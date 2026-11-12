<?php
/**
 * Reads over the activity log.
 *
 * One definition of a page, a search and a row, shared by the REST route
 * the Activity screen calls and the WP-CLI command an operator runs. Two
 * definitions would drift, and the terminal would then show a log the
 * dashboard could not reproduce.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Audit\Checks;
use BetterShield\Database\Schema;
use BetterShield\Hardening\Items;
use BetterShield\Support\Areas;
use BetterShield\Support\Ip;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * The plugin-owned events table, for which no core API exists, read without a
 * cache on purpose: an activity log served from a stale copy is a log that
 * omits the most recent thing that happened, which is the entry most likely to
 * matter.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Query {

	public const PER_PAGE = 40;

	/**
	 * Site names for a network read, memoized for the request.
	 *
	 * @var array<int, string>
	 */
	private static array $site_labels = array();

	/**
	 * The audit's check registry, read once per request for the finding rows
	 * on a page rather than once per row.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static ?array $checks = null;

	/**
	 * The hardening registry, read once per request for the same reason.
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static ?array $items = null;

	/**
	 * The scheduled tasks' names, an add-on's included, read once per request
	 * for the same reason.
	 *
	 * @var array<string, string>|null
	 */
	private static ?array $tasks = null;

	/**
	 * The login the log recorded for each account on the last page read that
	 * no longer exists, by id. Replaced on every read, never accumulated.
	 *
	 * @var array<int, string>
	 */
	private static array $recorded_logins = array();

	/**
	 * The event types that record an account's login. Every other row about
	 * an account holds only its id.
	 *
	 * On a network an account is created and deleted under the main site, so
	 * a subsite's own record of its login is the row its removal from that
	 * site left.
	 */
	private const LOGIN_RECORDS = array( 'user_created', 'user_deleted', 'user_removed_from_site' );

	/**
	 * Event types whose account object is the name somebody typed at the
	 * sign-in or reset form rather than an account's id. A typed "2" is not
	 * account 2.
	 */
	private const TYPED_NAMES = array( 'login_failed', 'password_reset_requested' );

	/**
	 * Newest first, one page at a time.
	 *
	 * Paged on `id` rather than on time. The column is monotonic with insertion
	 * and unique, so a page boundary cannot repeat or skip a row even when many
	 * events share a millisecond — which they routinely do, since a request
	 * flushes its whole buffer in one insert.
	 *
	 * @param array{cursor?: int, area?: string, search?: string, actor?: string, from?: string, to?: string, per_page?: int, network?: bool, sites?: int[]} $args
	 * @return array{events: array<int, array<string, mixed>>, next_cursor: ?int}
	 */
	public static function page( array $args = array() ): array {
		global $wpdb;

		$cursor   = isset( $args['cursor'] ) ? (int) $args['cursor'] : 0;
		$per_page = isset( $args['per_page'] ) ? max( 1, min( 500, (int) $args['per_page'] ) ) : self::PER_PAGE;
		$table    = self::read_table( $args );

		// One more than the page size, so the presence of a next page is known
		// without a second COUNT query over the whole table.
		$limit = $per_page + 1;

		$where  = array( self::scope( $args ) );
		$params = array( $table );

		/*
		 * The network's log by when things happened. Its ids stop following
		 * time once a site's earlier rows are carried into the shared table
		 * with new ids: a site moved late listed its whole history above what
		 * every other site did meanwhile, network policy changes pushed off
		 * the first page (#2134). The cursor stays the last row's id, and its
		 * time is read back to continue from.
		 */
		$by_time = self::is_network_read( $args );
		$at      = null;

		if ( $cursor > 0 && $by_time ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one row of the plugin's own table, by its key.
			$at = $wpdb->get_var( $wpdb->prepare( 'SELECT occurred_at FROM %i WHERE id = %d', $table, $cursor ) );
		}

		if ( $cursor > 0 && is_string( $at ) && '' !== $at ) {
			$where[]  = '(occurred_at < %s OR (occurred_at = %s AND id < %d))';
			$params[] = $at;
			$params[] = $at;
			$params[] = $cursor;
		} elseif ( $cursor > 0 ) {
			$where[]  = 'id < %d';
			$params[] = $cursor;
		}

		list( $filter_clauses, $filter_params ) = self::conditions( $args, true );

		$where  = array_merge( $where, $filter_clauses );
		$params = array_merge( $params, $filter_params );

		$params[] = $limit;

		$columns = array( 'id', 'occurred_at', 'event_type', 'severity', 'actor_type', 'actor_id', 'actor_label', 'object_type', 'object_id', 'context', 'ip_prefix', 'site_id' );

		/*
		 * The door column arrived with schema 3, and the writer already leaves it
		 * out of its INSERT until the upgrade has been verified and stamped. The
		 * read has to agree. One missing table anywhere in the schema withholds
		 * the stamp for every table, so a site can hold a perfectly good events
		 * table minus its newest column — and asking for it there errored, which
		 * this method turns into an empty array and the screen into an empty log
		 * with nothing said about why.
		 */
		if ( Schema::ready( 'entry_path' ) ) {
			$columns[] = 'entry_path';
		}

		/*
		 * Static analysis stops at the method boundary: it can see that every
		 * clause written above is a literal, and cannot see that the one arriving
		 * from search_clause() is too. Silenced here rather than by writing the
		 * search rule out a second time, which is the defect that method exists
		 * to prevent — and the placeholder count is genuinely unknowable up
		 * front, because the type list's length comes from the registry.
		 */
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT ' . implode( ', ', $columns ) . ' FROM %i WHERE ' . implode( ' AND ', $where ) . ( $by_time ? ' ORDER BY occurred_at DESC, id DESC' : ' ORDER BY id DESC' ) . ' LIMIT %d',
				$params
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$rows = is_array( $rows ) ? $rows : array();

		$has_more = count( $rows ) > $per_page;
		if ( $has_more ) {
			array_pop( $rows );
		}

		$across = self::is_network_read( $args );

		self::load_accounts( $rows, $table, self::scope( $args ) );

		$events = array();
		foreach ( $rows as $row ) {
			$events[] = self::shape( $row, $across );
		}

		return array(
			'events'      => $events,
			'next_cursor' => $has_more && array() !== $events ? end( $events )['id'] : null,
		);
	}

	/**
	 * This site's rows after an id, oldest first, as they are stored.
	 *
	 * For a reader that keeps its own place in the log and takes what came
	 * after it — the Hub link's sender — rather than a page a person turns.
	 * Paged on `id` for the reason `page()` is, read from the same table under
	 * the same site predicate, and shaped by the caller: what it sends is not
	 * what a screen shows.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function after( int $cursor, int $limit ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the scope is assembled by Schema::site_where() from integers; nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, occurred_at, event_type, severity, actor_type, actor_id, object_type, object_id, ip_prefix, context FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND id > %d ORDER BY id ASC LIMIT %d',
				Schema::table( 'events' ),
				max( 0, $cursor ),
				max( 1, min( 500, $limit ) )
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_array( $rows ) ? $rows : array();
	}

	/** The id of this site's newest row, or 0 while its log is empty. */
	public static function latest_id(): int {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the scope is assembled by Schema::site_where() from integers; nothing from a request reaches the string.
		$id = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM %i WHERE ' . Schema::site_where( 'events' ) . ' ORDER BY id DESC LIMIT 1',
				Schema::table( 'events' )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return (int) $id;
	}

	/**
	 * Whether these arguments ask for more than the current site's rows.
	 *
	 * A site filter alone never widens the read. The caller has to say so, so
	 * that no reader already passing filters through — the screen, the export,
	 * WP-CLI — can be handed a wider log than the one it asked for by a query
	 * string it does not control.
	 *
	 * @param array<string, mixed> $args
	 */
	private static function is_network_read( array $args ): bool {
		return is_multisite() && ! empty( $args['network'] );
	}

	/**
	 * The site predicate these arguments read under.
	 *
	 * @param array<string, mixed> $args
	 */
	private static function scope( array $args ): string {
		if ( ! self::is_network_read( $args ) ) {
			return Schema::site_where( 'events' );
		}

		$sites = isset( $args['sites'] ) && is_array( $args['sites'] ) ? $args['sites'] : array();

		return Schema::network_where( $sites );
	}

	/**
	 * Which table a read answers from.
	 *
	 * A network read is a read of the network table whatever the site serving
	 * it has been switched to — a subsite still writing to its own log has
	 * none of its neighbors' rows to offer.
	 *
	 * @param array<string, mixed> $args
	 */
	private static function read_table( array $args = array() ): string {
		return self::is_network_read( $args ) ? Schema::network_table( 'events' ) : Schema::table( 'events' );
	}

	/**
	 * A site's name, asked once per request however many rows carry its id.
	 *
	 * Rows arrive interleaved on a network read, so a lookup per row would be
	 * one query per row — over a page of forty, forty queries for at most a
	 * handful of distinct names.
	 */
	private static function site_label( int $site_id ): string {
		if ( $site_id <= 0 ) {
			$site_id = (int) get_main_site_id();
		}

		if ( isset( self::$site_labels[ $site_id ] ) ) {
			return self::$site_labels[ $site_id ];
		}

		$name = is_multisite() ? (string) get_blog_option( $site_id, 'blogname', '' ) : (string) get_option( 'blogname', '' );

		self::$site_labels[ $site_id ] = '' !== $name ? $name : sprintf(
			/* translators: %d: a numeric site identifier on a network. */
			__( 'Site %d', 'bettershield' ),
			$site_id
		);

		return self::$site_labels[ $site_id ];
	}

	/**
	 * How many events each area holds, across everything the read covers.
	 *
	 * Counted here rather than in the interface because the log is paged: a
	 * browser only ever holds one page, so a count taken there would describe
	 * the page rather than the record, and would change every time the reader
	 * asked for more.
	 *
	 * Narrowed by the search but never by the current area, which is the same
	 * rule the report's chips follow: a facet counts against the other filters
	 * and never against its own selection. Counting the area against itself
	 * would leave every chip reading either its total or nothing, and ignoring
	 * the search would advertise numbers the list cannot produce.
	 *
	 * @param array<string, mixed> $args
	 * @return array<string, int>
	 */
	public static function counts_by_area( array $args ): array {
		global $wpdb;

		// Every filter except the area itself, which is the facet these numbers
		// describe. One definition, shared with the listing.
		list( $filter_clauses, $filter_params ) = self::conditions( $args, false );

		$where  = array_merge( array( self::scope( $args ) ), $filter_clauses );
		$params = array_merge( array( self::read_table( $args ) ), $filter_params );

		// One grouped query, then folded into areas in PHP. The type-to-area
		// map stays in one place that way, rather than half of it living in a
		// CASE expression.
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- literal clauses, bound values, a search rule shared with the listing rather than duplicated.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT event_type, COUNT(*) AS total FROM %i WHERE ' . implode( ' AND ', $where ) . ' GROUP BY event_type',
				$params
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$areas  = Types::areas();
		$counts = array( 'all' => 0 );

		foreach ( array_keys( Areas::all() ) as $slug ) {
			$counts[ $slug ] = 0;
		}

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$total          = (int) $row->total;
			$counts['all'] += $total;

			// An event type with no area still counts in the total: it is in
			// the log, and saying otherwise would make the numbers disagree
			// with the list.
			$area = $areas[ (string) $row->event_type ] ?? null;
			if ( null !== $area ) {
				$counts[ $area ] += $total;
			}
		}

		return $counts;
	}

	/**
	 * Every filter except the cursor, as clauses and the values they bind.
	 *
	 * One definition, because three readers narrow the same log and they must
	 * agree: the listing, the per-area counts beside it, and the export. Two
	 * definitions would drift, and the chips would then advertise numbers the
	 * list could not produce.
	 *
	 * `$with_area` is what lets the counts leave the area out. A facet counts
	 * against the *other* filters and never against its own selection — count
	 * an area against itself and every chip reads either its full total or
	 * nothing, which is no information at all.
	 *
	 * @param array{area?: string, search?: string, actor?: string, from?: string, to?: string} $args
	 * @return array{0: string[], 1: array<int, mixed>}
	 */
	public static function conditions( array $args, bool $with_area ): array {
		if ( ! self::valid_filters( $args ) ) {
			return array( array( '1 = 0' ), array() );
		}
		$where  = array();
		$params = array();

		$area = isset( $args['area'] ) ? (string) $args['area'] : '';
		if ( $with_area && '' !== $area && 'all' !== $area ) {
			$types = Types::in_area( $area );
			if ( array() !== $types ) {
				// The only clause built by hand is this run of placeholders,
				// and its length comes from the type registry rather than from
				// anything a request supplied.
				$where[] = 'event_type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ')';
				$params  = array_merge( $params, $types );
			} else {
				$where[] = '1 = 0';
			}
		}

		list( $search_clause, $search_params ) = self::search_clause( isset( $args['search'] ) ? (string) $args['search'] : '', self::read_table( $args ), self::scope( $args ) );
		if ( '' !== $search_clause ) {
			$where[] = $search_clause;
			$params  = array_merge( $params, $search_params );
		}

		list( $actor_clause, $actor_params ) = self::actor_clause( isset( $args['actor'] ) ? (string) $args['actor'] : '' );
		if ( '' !== $actor_clause ) {
			$where[] = $actor_clause;
			$params  = array_merge( $params, $actor_params );
		}

		// One network, named by the label a row shows ("prefix", because
		// "network" already means reading every site of one). Only a stored
		// prefix is accepted, so nothing narrower than a /24 or a /64 is asked.
		$label = isset( $args['prefix'] ) ? trim( (string) $args['prefix'] ) : '';
		if ( '' !== $label ) {
			$prefix = Ip::from_label( $label );

			if ( null === $prefix ) {
				$where[] = '1 = 0';
			} else {
				$where[]  = 'ip_prefix = %s';
				$params[] = $prefix;
			}
		}

		// The retention window, applied to every read whatever was asked for:
		// rows older than the current retention allows are not returned even
		// while they are still on disk.
		$where[]  = 'occurred_at >= %s';
		$params[] = \BetterShield\Support\Tier::retention_floor();

		$from = self::boundary( isset( $args['from'] ) ? (string) $args['from'] : '', false );
		if ( null !== $from ) {
			$where[]  = 'occurred_at >= %s';
			$params[] = $from;
		}

		$to = self::boundary( isset( $args['to'] ) ? (string) $args['to'] : '', true );
		if ( null !== $to ) {
			$where[]  = 'occurred_at <= %s';
			$params[] = $to;
		}

		return array( $where, $params );
	}

	/** Shared by REST validation and internal readers, before sanitization. */
	public static function valid_filters( array $args ): bool {
		foreach ( array( 'area', 'from', 'to', 'prefix' ) as $key ) {
			if ( isset( $args[ $key ] ) && ! is_string( $args[ $key ] ) ) {
				return false;
			}
		}
		$area = $args['area'] ?? '';
		if ( '' !== $area && 'all' !== $area && ! Areas::exists( $area ) ) {
			return false;
		}
		$from = $args['from'] ?? '';
		$to   = $args['to'] ?? '';
		if ( ( '' !== $from && null === self::boundary( $from, false ) ) || ( '' !== $to && null === self::boundary( $to, true ) ) ) {
			return false;
		}
		$prefix = $args['prefix'] ?? '';
		if ( '' !== $prefix && null === Ip::from_label( $prefix ) ) {
			return false;
		}
		// Compared as the moments they stand for, because a day and an
		// instant can be given side by side and do not sort as text.
		return '' === $from || '' === $to || self::boundary( $from, false ) <= self::boundary( $to, true );
	}

	/**
	 * Whether a value is an actor token this class issues: `user:<id>` or
	 * `type:<kind>`. Anything else matches no row.
	 */
	public static function is_actor_token( string $actor ): bool {
		return 1 === preg_match( '/^(?:user:\d+|type:[a-z_]{1,16})$/', trim( $actor ) );
	}

	/**
	 * The actor half of a WHERE clause.
	 *
	 * The value is a token this class both produces and consumes — `user:12`
	 * or `type:system`, or `users:12,14` for an add-on reporting on several
	 * accounts at once — rather than a name typed by a reader. Two people can
	 * share a display name, and an account deleted last week still has one on
	 * its old rows; matching on the identifier where there is one keeps both
	 * cases honest, and the label is left to `search` where a fuzzy match is
	 * what the reader actually wants.
	 *
	 * @return array{0: string, 1: array<int, mixed>}
	 */
	public static function actor_clause( string $actor ): array {
		$actor = trim( $actor );

		if ( '' === $actor ) {
			return array( '', array() );
		}

		if ( 1 === preg_match( '/^user:(\d+)$/', $actor, $matches ) ) {
			return array( 'actor_id = %d', array( (int) $matches[1] ) );
		}

		// Several accounts at once, for a report about everyone holding one
		// role: up to a hundred, each a number. A longer or malformed list
		// is a token this class never issued, and matches nothing below.
		if ( 1 === preg_match( '/^users:(\d+(?:,\d+){0,99})$/', $actor, $matches ) ) {
			$ids = array_values( array_unique( array_map( 'intval', explode( ',', $matches[1] ) ) ) );

			return array( 'actor_id IN (' . implode( ', ', array_fill( 0, count( $ids ), '%d' ) ) . ')', $ids );
		}

		if ( 1 === preg_match( '/^type:([a-z_]{1,16})$/', $actor, $matches ) ) {
			// An actor type with no identifier behind it: the site itself, or
			// somebody signed out. Rows carrying an id are excluded so the
			// two kinds of token never overlap and double-count.
			return array( 'actor_type = %s AND actor_id IS NULL', array( $matches[1] ) );
		}

		// Anything else is not a token this class issued. Refused as a clause
		// that matches nothing, rather than ignored: silently widening a filter
		// back to everything shows the reader more than they asked for and
		// tells them nothing about why.
		return array( '1 = 0', array() );
	}

	/**
	 * One end of a date range, as a stored-column datetime.
	 *
	 * A calendar day is read in the site's own timezone; the column holds UTC.
	 * Converting here is what stops "yesterday" meaning a different span of
	 * hours to the log than it does to the person reading it.
	 *
	 * Or an exact instant in UTC, taken as given. The log screen files rows
	 * under the reader's own calendar day, which need not be the site's, so
	 * it sends the instants that day starts and ends at rather than a day the
	 * site would read in its own zone.
	 */
	private static function boundary( string $day, bool $end_of_day ): ?string {
		if ( 1 === preg_match( '/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/D', $day, $at ) ) {
			if ( ! checkdate( (int) $at[2], (int) $at[3], (int) $at[1] ) || (int) $at[4] > 23 || (int) $at[5] > 59 || (int) $at[6] > 59 ) {
				return null;
			}

			return sprintf( '%s-%s-%s %s:%s:%s.%s', $at[1], $at[2], $at[3], $at[4], $at[5], $at[6], str_pad( $at[7] ?? '', 3, '0' ) );
		}

		if ( 1 !== preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/D', $day, $parts ) || ! checkdate( (int) $parts[2], (int) $parts[3], (int) $parts[1] ) ) {
			return null;
		}

		try {
			$local = new \DateTimeImmutable(
				$day . ( $end_of_day ? ' 23:59:59.999' : ' 00:00:00.000' ),
				wp_timezone()
			);
		} catch ( \Exception $e ) {
			return null;
		}
		if ( $local->format( 'Y-m-d' ) !== $day ) {
			return null;
		}

		return $local->setTimezone( new \DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s.v' );
	}

	/**
	 * The search half of a WHERE clause, and the values it binds.
	 *
	 * Returned rather than applied so the listing and the counting share one
	 * definition of what a search matches. Two definitions would eventually
	 * disagree, and the chips would then advertise numbers the list could not
	 * produce.
	 *
	 * Searched columns are the ones a person would name: who did it, and what
	 * it was done to. Not the context blob — it holds machine detail nobody
	 * types, and matching inside JSON returns rows for reasons invisible on
	 * screen, which is the worst kind of search result. The one exception is
	 * the login an account's creation or deletion recorded, which is the name
	 * the screen shows for that account once it is gone.
	 *
	 * Event types are matched through their written names rather than their
	 * stored identifiers, so "sign-in" finds a failed login. The identifiers
	 * are frozen database values and nobody should have to learn them.
	 *
	 * @param string $search The term.
	 * @param string $table  The table the read answers from; the site's own when empty.
	 * @param string $scope  The site predicate it reads under; the site's own when empty.
	 * @return array{0: string, 1: array<int, string>}
	 */
	public static function search_clause( string $search, string $table = '', string $scope = '' ): array {
		global $wpdb;

		$search = trim( $search );

		if ( '' === $search ) {
			return array( '', array() );
		}

		$like   = '%' . $wpdb->esc_like( $search ) . '%';
		$clause = array( 'actor_label LIKE %s', 'object_id LIKE %s' );
		$params = array( $like, $like );

		// A failed sign-in's row names one tried name and lists the others
		// its burst tried, so a name followed from Login & Access finds every
		// row that tried it, not only the ones it opened (#1979).
		// Matched inside that list only, and as the log encodes it, so a
		// search for "attempts" or a digit does not find every burst.
		$encoded  = wp_json_encode( $search );
		$clause[] = "( event_type = 'login_failed' AND context LIKE %s )";
		$params[] = '%' . $wpdb->esc_like( '"unlogged_names":[' ) . '%' . $wpdb->esc_like( is_string( $encoded ) ? substr( $encoded, 1, -1 ) : $search ) . '%';

		/*
		 * The rows about an account store its id and the screen names it by
		 * its login, so a login searched for finds them too. The accounts are
		 * looked up first, a bounded number of them, because the users table is
		 * not this plugin's to join against: on a network it is shared by every
		 * site.
		 */
		$accounts = get_users(
			array(
				'blog_id'        => 0,
				'search'         => '*' . $search . '*',
				'search_columns' => array( 'user_login' ),
				'fields'         => 'ID',
				'number'         => 100,
			)
		);

		// An account deleted since is invisible to that lookup, and is found
		// by the login the log recorded for it instead.
		$accounts = array_values( array_unique( array_merge( array_map( 'intval', $accounts ), self::gone_accounts_named( $search, $table, $scope ) ) ) );

		if ( array() !== $accounts ) {
			$clause[] = "( object_type = 'user' AND event_type NOT IN (" . implode( ',', array_fill( 0, count( self::TYPED_NAMES ), '%s' ) ) . ')'
				. ' AND object_id IN (' . implode( ',', array_fill( 0, count( $accounts ), '%s' ) ) . ') )';
			$params   = array_merge( $params, self::TYPED_NAMES, array_map( 'strval', $accounts ) );
		}

		/*
		 * The subject a row shows is its object's label, a check's or a
		 * protection's title, not the key stored for it, so "XML-RPC" found
		 * nothing and only "xmlrpc" did (#2052). The labels are matched here
		 * and asked for by the ids they belong to, as logins are above.
		 */
		foreach ( self::labelled_ids( $search ) as $object_types => $ids ) {
			$types    = explode( ',', $object_types );
			$clause[] = '( object_type IN (' . implode( ',', array_fill( 0, count( $types ), '%s' ) ) . ')'
				. ' AND object_id IN (' . implode( ',', array_fill( 0, count( $ids ), '%s' ) ) . ') )';
			$params   = array_merge( $params, $types, $ids );
		}

		// An assistant application and a plugin are shown by the name their
		// row recorded, which only their id found (#2217).
		foreach ( self::context_named_ids( $search, $table, $scope ) as $object_type => $ids ) {
			$clause[] = '( object_type = %s AND object_id IN (' . implode( ',', array_fill( 0, count( $ids ), '%s' ) ) . ') )';
			$params   = array_merge( $params, array( $object_type ), $ids );
		}

		$matched = array();
		foreach ( Types::labels() as $type => $label ) {
			if ( false !== stripos( $label, $search ) ) {
				$matched[] = $type;
			}
		}

		if ( array() !== $matched ) {
			$clause[] = 'event_type IN (' . implode( ',', array_fill( 0, count( $matched ), '%s' ) ) . ')';
			$params   = array_merge( $params, $matched );
		}

		/*
		 * An address searched for is matched against the network it belongs to,
		 * not against text. The column holds the truncated form as binary, so a
		 * LIKE over it would never match what the screen displays — the search
		 * term is truncated the same way and compared exactly. Typing any
		 * address in a /24 therefore finds every row from that /24, which is
		 * the only question the stored value can answer.
		 */
		$network = Ip::truncated_binary( $search );

		if ( null !== $network ) {
			$clause[] = 'ip_prefix = %s';
			$params[] = $network;
		}

		return array( '(' . implode( ' OR ', $clause ) . ')', $params );
	}

	/**
	 * The object ids whose label, as object_label() gives it, contains the
	 * search, keyed by the object types (comma-joined) that label is given
	 * to. Only the labels that are fixed for an id: those read from a row's
	 * own context are not knowable before the row is.
	 *
	 * @return array<string, string[]>
	 */
	private static function labelled_ids( string $search ): array {
		if ( null === self::$checks ) {
			self::$checks = Checks::all();
		}

		if ( null === self::$items ) {
			self::$items = Items::all();
		}

		$labels = array(
			'finding'                  => array_map( static fn( array $check ): string => Checks::title_of( $check ), self::$checks ),
			'hardening,hardening_item' => array_map( static fn( array $item ): string => (string) ( $item['title'] ?? '' ), self::$items ),
			'alert'                    => array(
				'critical'           => __( 'Instant alert', 'bettershield' ),
				'digest'             => __( 'Weekly summary', 'bettershield' ),
				'recovery_readiness' => __( 'Recovery email check', 'bettershield' ),
			),
			'lockout'                  => array(
				'blocklist'  => __( 'Blocklist', 'bettershield' ),
				'email_link' => __( 'Emailed unlock link', 'bettershield' ),
				'all'        => __( 'Every form', 'bettershield' ),
			),
			'audit'                    => array( 'summary' => __( 'Open findings', 'bettershield' ) ),
			'task'                     => self::task_labels(),
		);

		$found = array();

		foreach ( $labels as $types => $by_id ) {
			$ids = array();

			foreach ( $by_id as $id => $label ) {
				if ( '' !== $label && false !== stripos( $label, $search ) ) {
					$ids[] = (string) $id;
				}
			}

			if ( array() !== $ids ) {
				$found[ $types ] = $ids;
			}
		}

		return $found;
	}

	/**
	 * The filtered log as CSV, for a spreadsheet or an auditor's file.
	 *
	 * Assembled by walking the same paged read the screen uses, in bounded
	 * batches under a wall-clock budget — the plugin's rule for every loop over
	 * its own tables. Falling short of the whole log is acceptable and is
	 * stated in the file; blocking the request that asked for it is not.
	 *
	 * @param array{area?: string, search?: string, actor?: string, from?: string, to?: string} $args
	 * @return array{csv: string, rows: int, complete: bool}
	 */
	public static function export( array $args = array(), int $max_rows = 10000, float $budget_seconds = 10.0 ): array {
		$start    = microtime( true );
		$cursor   = 0;
		$rows     = 0;
		$complete = true;

		// A read across the network carries rows from several sites, and a
		// file of them with no column naming the site cannot be told apart.
		// The table and the JSON already name it; so does the file.
		$across = ! empty( $args['network'] );
		// The columns the screen shows first, under readable names: the time
		// in the site's own zone beside UTC, the area the screen files the
		// row under, and who and what as the row says them. The raw record
		// follows for a script or an auditor, under its own field names.
		$header = array(
			__( 'Time (site)', 'bettershield' ),
			__( 'Time (UTC)', 'bettershield' ),
			__( 'Event', 'bettershield' ),
			__( 'Category', 'bettershield' ),
			__( 'Severity', 'bettershield' ),
			__( 'Who', 'bettershield' ),
			__( 'About', 'bettershield' ),
			__( 'Network', 'bettershield' ),
			'event_type',
			'actor_type',
			'object_type',
			'object_id',
			'entry_path',
			'context',
		);
		$areas      = \BetterShield\Support\Areas::all();
		// The severity words come from the one place that translates them,
		// led with a capital as a column's value.
		$severities = array_map( 'ucfirst', \BetterShield\Operator\Widget::severity_labels() );

		$lines = array(
			self::csv_row( $across ? array_merge( $header, array( 'site_id', 'site_label' ) ) : $header ),
		);

		do {
			$page = self::page(
				array_merge(
					$args,
					array(
						'cursor' => $cursor,
						// Never ask for more than the allowance has room for,
						// or a single page could overshoot the cap entirely and
						// the file would be larger than it promised to be.
						'per_page' => max( 1, min( 500, $max_rows - $rows ) ),
					)
				)
			);

			foreach ( $page['events'] as $event ) {
				$site = $across ? array( (string) ( $event['site_id'] ?? '' ), (string) ( $event['site_label'] ?? '' ) ) : array();

				$when = strtotime( (string) $event['occurred_at'] );

				$lines[] = self::csv_row(
					array_merge(
						array(
							false !== $when ? (string) wp_date( 'Y-m-d H:i:s T', $when ) : '',
							false !== $when ? gmdate( 'Y-m-d H:i:s', $when ) . ' UTC' : (string) $event['occurred_at'],
							(string) $event['label'],
							(string) ( $areas[ (string) $event['area'] ] ?? '' ),
							(string) ( $severities[ (string) $event['severity'] ] ?? $event['severity'] ),
							self::actor_words( $event ),
							self::about_words( $event ),
							null !== $event['network'] ? (string) $event['network'] : '',
							(string) $event['type'],
							(string) $event['actor_type'],
							null !== $event['object_type'] ? (string) $event['object_type'] : '',
							null !== $event['object_id'] ? (string) $event['object_id'] : '',
							(string) $event['entry_path'],
							null !== $event['context'] ? (string) wp_json_encode( $event['context'] ) : '',
						),
						$site
					)
				);

				++$rows;
			}

			$cursor = $page['next_cursor'];

			if ( null !== $cursor && ( $rows >= $max_rows || microtime( true ) - $start >= $budget_seconds ) ) {
				// Never a silent truncation: a file that stops early says so in
				// its own last line, where anyone reading it will meet it.
				$lines[]  = self::csv_row( array( '# truncated: more rows matched than this export carries. Narrow the date range and export again.' ) );
				$complete = false;
				break;
			}
		} while ( null !== $cursor );

		return array(
			'csv'      => implode( "\r\n", $lines ) . "\r\n",
			'rows'     => $rows,
			'complete' => $complete,
		);
	}

	/**
	 * One CSV line, quoted to RFC 4180 and safe to open in a spreadsheet.
	 *
	 * Written out rather than delegated to `fputcsv`, for two reasons that
	 * both matter here. That function needs a stream, and a security plugin
	 * reaching for direct filesystem calls is a thing a reviewer is right to
	 * stop at. And its escape-character behavior is not RFC 4180: it can emit
	 * backslashes that a spreadsheet reads back as part of the value.
	 *
	 * The second job is the one a security export must not get wrong. Several
	 * of these fields hold text a stranger chose — the login name someone typed
	 * at a sign-in form arrives here as an object id — and a spreadsheet treats
	 * a cell beginning with `=`, `+`, `-` or `@` as a formula to run. A log of
	 * an attack must not become the attack; `Text::csv_cell()` neutralizes
	 * those cells, here and in every other CSV this plugin writes.
	 *
	 * @param array<int, string> $fields
	 */
	private static function csv_row( array $fields ): string {
		$out = array();

		foreach ( $fields as $field ) {
			$field = Text::csv_cell( (string) $field );

			if ( 1 === preg_match( '/["\r\n,]/', $field ) ) {
				$field = '"' . str_replace( '"', '""', $field ) . '"';
			}

			$out[] = $field;
		}

		return implode( ',', $out );
	}

	/**
	 * How many people and processes appear in the log, however many the
	 * filter's list stops at.
	 *
	 * The same scope and window as `actors()`, and the same folding: an
	 * account is one actor under every label it has had, and a process is
	 * one per kind. Counted by the database rather than read.
	 *
	 * @param array<string, mixed> $args As for `actors()`.
	 */
	public static function actors_total( array $args = array() ): int {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the scope is assembled by Schema::site_where() or Schema::network_where() from integers and, on an unfiltered network read, core's own registry table name; nothing from a request reaches the string.
		$total = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT( DISTINCT CASE WHEN actor_id > 0 THEN CONCAT( 'user:', actor_id ) ELSE CONCAT( 'type:', actor_type ) END ) FROM %i WHERE " . self::scope( $args ) . ' AND occurred_at >= %s',
				self::read_table( $args ),
				\BetterShield\Support\Tier::retention_floor()
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return (int) $total;
	}

	/**
	 * Who appears in the log, as tokens the actor filter accepts.
	 *
	 * Derived from the log rather than from the user table, which is the whole
	 * point: an account deleted last week is still an actor in the record and
	 * has to remain selectable, and its name survives because the writer
	 * denormalizes the label at write time.
	 *
	 * Bounded and ordered by how much each actor did, so a busy site offers the
	 * people worth filtering to rather than an unusable list of everyone.
	 *
	 * Bounded by the retention window as well, like every other read of the log.
	 * Without it this grouped over every row on disk, so it offered names that
	 * selected an empty listing — with a count beside them saying otherwise —
	 * and paid for a temporary table over the whole log on every request the
	 * Activity screen makes.
	 *
	 * @param array<string, mixed> $args The same 'network' and 'sites' the
	 *                                   listing reads under, so the filter
	 *                                   offers the actors the list can show.
	 * @return array<int, array{token: string, label: string, count: int}>
	 */
	public static function actors( int $limit = 40, array $args = array() ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the scope is assembled by Schema::site_where() or Schema::network_where() from integers and, on an unfiltered network read, core's own registry table name; nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT actor_type, actor_id, actor_label, COUNT(*) AS total FROM %i WHERE ' . self::scope( $args ) . ' AND occurred_at >= %s GROUP BY actor_type, actor_id, actor_label ORDER BY total DESC LIMIT %d',
				self::read_table( $args ),
				\BetterShield\Support\Tier::retention_floor(),
				max( 1, min( 200, $limit ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$id    = null !== $row->actor_id ? (int) $row->actor_id : 0;
			$label = null !== $row->actor_label ? (string) $row->actor_label : '';

			if ( $id > 0 ) {
				$token = 'user:' . $id;
				$name  = '' !== $label ? $label : sprintf(
					/* translators: %d: a numeric account identifier. */
					__( 'Account %d', 'bettershield' ),
					$id
				);
			} else {
				$token = 'type:' . (string) $row->actor_type;
				$name  = self::actor_type_label( (string) $row->actor_type );
			}

			// Several rows can fold into one token — the same account under a
			// display name it has since changed, most often — so counts add
			// rather than overwrite.
			if ( isset( $out[ $token ] ) ) {
				$out[ $token ]['count'] += (int) $row->total;
				continue;
			}

			$out[ $token ] = array(
				'token' => $token,
				'label' => $name,
				'count' => (int) $row->total,
			);
		}

		$out = array_values( $out );

		usort(
			$out,
			static function ( array $a, array $b ): int {
				return $b['count'] <=> $a['count'];
			}
		);

		return $out;
	}

	/**
	 * An actor with no account behind it, said as a person would say it. The
	 * same words the Activity screen uses for the same thing.
	 */
	private static function actor_type_label( string $type ): string {
		switch ( $type ) {
			case 'system':
				return __( 'WordPress or the server', 'bettershield' );
			case 'agent':
				return __( 'Agent', 'bettershield' );
			case 'user':
				// A user row with no id: an account acting before its session
				// existed, or after it was torn down.
				return __( 'Signed-in account', 'bettershield' );
			default:
				return __( 'Signed-out visitor', 'bettershield' );
		}
	}

	/**
	 * The area one event type belongs to, or '' for a type with no area.
	 *
	 * The map is a literal the registry rebuilds on every call, and `shape()`
	 * runs once per row — so it is held for the length of the request rather
	 * than assembled two hundred times for one page.
	 *
	 * @param string $type The event type.
	 * @return string The area slug.
	 */
	private static function area_of( string $type ): string {
		static $areas = null;

		if ( null === $areas ) {
			$areas = Types::areas();
		}

		return isset( $areas[ $type ] ) ? (string) $areas[ $type ] : '';
	}

	/**
	 * Who did it, as the row on screen names them.
	 *
	 * @param array<string, mixed> $event
	 */
	private static function actor_words( array $event ): string {
		if ( null !== $event['actor_label'] && '' !== (string) $event['actor_label'] ) {
			return (string) $event['actor_label'];
		}

		if ( 'system' === $event['actor_type'] ) {
			return __( 'WordPress or the server', 'bettershield' );
		}

		return 'agent' === $event['actor_type'] ? __( 'Agent', 'bettershield' ) : __( 'Signed-out visitor', 'bettershield' );
	}

	/**
	 * What the row was about, as the screen names it: the object's label where
	 * it has one, its id where not, and nothing for an option's own name.
	 *
	 * @param array<string, mixed> $event
	 */
	private static function about_words( array $event ): string {
		if ( null !== $event['object_label'] && '' !== (string) $event['object_label'] ) {
			return (string) $event['object_label'];
		}

		$id = null !== $event['object_id'] ? (string) $event['object_id'] : '';

		return 0 === strpos( $id, 'bettershield_' ) ? '' : $id;
	}

	/**
	 * One stored row as the record every reader sees.
	 *
	 * @return array<string, mixed>
	 */
	private static function shape( object $row, bool $with_site = false ): array {
		$severities = array( 'info', 'low', 'medium', 'high', 'critical' );
		$context    = null !== $row->context ? json_decode( (string) $row->context, true ) : null;

		$shaped = array(
			'id'          => (int) $row->id,
			// Stored UTC without a zone marker; say so explicitly rather
			// than let the browser read it as local time.
			'occurred_at' => Time::utc_iso( (string) $row->occurred_at ),
			'type'        => (string) $row->event_type,
			'label'       => self::label_of( (string) $row->event_type, $context, $row->object_type ?? null ),
			/*
			 * Which part of the site this belongs to, in the same vocabulary
			 * the area filter uses. The map lives on the server because the
			 * filter's clause is built from it; without the slug on the row
			 * the screen could group and filter by area but never say, on a
			 * row, which area it was — the one place a reader scanning a
			 * mixed log actually wants it.
			 */
			'area'        => self::area_of( (string) $row->event_type ),
			'severity'    => $severities[ (int) $row->severity ] ?? 'info',
			'actor_type'  => (string) $row->actor_type,
			// Carried so a reader can narrow to the actor on a row they are
			// looking at. The label alone cannot do that: two people can share
			// a display name, and one person can change theirs.
			'actor_id'    => null !== $row->actor_id ? (int) $row->actor_id : null,
			'actor_label' => null !== $row->actor_label ? (string) $row->actor_label : null,
			'object_type' => null !== $row->object_type ? (string) $row->object_type : null,
			'object_id'   => null !== $row->object_id ? (string) $row->object_id : null,
			/*
			 * What the object is called, where the id is not something to show
			 * an owner. Null where there is no better name than the id, and the
			 * screen then shows the id.
			 */
			'object_label' => self::object_label( (string) $row->event_type, $row->object_type ?? null, $row->object_id ?? null, $context ),
			'context'     => $context,
			// Absent on a site whose schema-3 upgrade has not been stamped, where
			// the column is left out of the read above. 'unknown' is what the
			// column itself defaults to, so the two states read the same.
			'entry_path'  => isset( $row->entry_path ) ? (string) $row->entry_path : 'unknown',
			/*
			 * The network the request came from, never the address. Stored
			 * truncated — v4 to /24, v6 to /64 — and rendered the same way the
			 * read ability already renders it.
			 *
			 * It was written on every row and shown nowhere, which is data
			 * collected and never used: either it earns its place on the screen
			 * or it should not be stored. It answers the question the log could
			 * not — where a run of failed sign-ins came from — so it is shown.
			 */
			'network'     => Ip::prefix_label( $row->ip_prefix ?? null ),
			/*
			 * Which site the row belongs to. `0` is the main site's own
			 * convention for rows written before its log became the
			 * network's, so it is reported as the main site rather than as a
			 * site nobody can name.
			 */
			'site_id'     => isset( $row->site_id ) && (int) $row->site_id > 0 ? (int) $row->site_id : (int) self::main_site_id(),
		);

		// Only where a reader is looking at more than one site's rows. On a
		// single site's own log every row would carry the same name.
		if ( $with_site ) {
			$shaped['site_label'] = self::site_label( $shaped['site_id'] );
		}

		return $shaped;
	}

	/**
	 * What a row's object is called, where its stored id is not something to
	 * show an owner: a finding by its check's title, a hardening item by its
	 * title, an account by its login.
	 *
	 * Null where there is no better name than the id. A key the registry no
	 * longer knows, from a check or item since removed, has no title to give,
	 * and an account deleted since is named by the login the log recorded for
	 * it: on its own row, or on its creation or deletion, read by
	 * load_accounts(). Public so "Since you last looked" names an object the
	 * way the log does.
	 *
	 * An add-on names its own objects through `bettershield_event_object_label`,
	 * asked only where this plugin has no name: one this plugin gives keeps
	 * it, as an event type's label does.
	 *
	 * @param string      $event   The event type.
	 * @param string|null $type    The object type.
	 * @param string|null $id      The object id as stored.
	 * @param mixed       $context The row's decoded context.
	 */
	public static function object_label( string $event, ?string $type, ?string $id, $context = null ): ?string {
		if ( null === $id || '' === $id ) {
			return null;
		}

		$label = self::own_label( $event, $type, $id, $context );

		if ( null !== $label ) {
			return $label;
		}

		/**
		 * Names an object this plugin has no name for: an add-on's setting by
		 * what its screen calls it, rather than by the option that holds it,
		 * and what the save changed where the row records it. The activity
		 * log, the alert email and "Since you last looked" all show it.
		 *
		 * @param string|null $label   Null: this plugin has no name for it.
		 * @param string      $event   The event type.
		 * @param string|null $type    The object type.
		 * @param string      $id      The object id as stored.
		 * @param mixed       $context The row's decoded context.
		 */
		$named = apply_filters( 'bettershield_event_object_label', null, $event, $type, $id, $context );

		$named = is_string( $named ) ? trim( wp_strip_all_tags( $named ) ) : '';

		return '' !== $named ? $named : null;
	}

	/**
	 * A watched setting as its own screen names it, and what it changed from
	 * and to where the row records that. Null for a setting not on the list.
	 *
	 * @param string $type    `setting` or `network_setting`.
	 * @param string $id      The option's name.
	 * @param mixed  $context The row's decoded context.
	 */
	private static function setting_label( string $type, string $id, $context ): ?string {
		$names = 'network_setting' === $type
			? array(
				'registration'  => __( 'Allow new registrations', 'bettershield' ),
				'admin_email'   => __( 'Network admin email', 'bettershield' ),
				'add_new_users' => __( 'Add new users', 'bettershield' ),
				'site_admins'   => __( 'Network administrators', 'bettershield' ),
			)
			: array(
				'siteurl'             => __( 'WordPress address (URL)', 'bettershield' ),
				'home'                => __( 'Site address (URL)', 'bettershield' ),
				'admin_email'         => __( 'Administration email address', 'bettershield' ),
				'users_can_register'  => __( 'Anyone can register', 'bettershield' ),
				'default_role'        => __( 'New user default role', 'bettershield' ),
				'permalink_structure' => __( 'Permalink structure', 'bettershield' ),
				'blog_public'         => __( 'Search engine visibility', 'bettershield' ),
				'bettershield_store_account_tab' => __( 'Sign-in security on WooCommerce My Account', 'bettershield' ),
				'bettershield_account_page' => __( 'Sign-in security page', 'bettershield' ),
			);
		$name  = $names[ strtolower( $id ) ] ?? null;

		if ( null === $name || ! is_array( $context ) || ! isset( $context['before'], $context['after'] ) ) {
			return $name;
		}

		$say = static function ( $value ) use ( $id ): string {
			$value = (string) $value;

			if ( 'users_can_register' === $id ) {
				return '1' === $value ? __( 'on', 'bettershield' ) : __( 'off', 'bettershield' );
			}

			$roles = wp_roles()->get_names();

			return isset( $roles[ $value ] ) ? translate_user_role( $roles[ $value ] ) : $value;
		};

		return sprintf(
			/* translators: 1: a setting's name, e.g. "Anyone can register", 2: its earlier value, 3: its new value. */
			__( '%1$s (%2$s → %3$s)', 'bettershield' ),
			$name,
			$say( $context['before'] ),
			$say( $context['after'] )
		);
	}

	/**
	 * This plugin's own name for a row's object, where it has one.
	 *
	 * @param string      $event   The event type.
	 * @param string|null $type    The object type.
	 * @param string      $id      The object id as stored.
	 * @param mixed       $context The row's decoded context.
	 */
	private static function own_label( string $event, ?string $type, string $id, $context ): ?string {
		// A refused write to a takeover setting by the code that made it,
		// which is what tells the owner which plugin to update (#1977).
		if ( 'takeover_setting_refused' === $event && is_array( $context ) && '' !== (string) ( $context['name'] ?? '' ) ) {
			return sprintf(
				/* translators: 1: an option's name, e.g. default_role; 2: the plugin or theme that wrote it. */
				__( '%1$s, written by %2$s', 'bettershield' ),
				$id,
				(string) $context['name']
			);
		}

		// A watched setting by what its screen calls it, never its option's
		// name, with what changed where the row records it (#2489).
		$setting = 'setting' === $type || 'network_setting' === $type ? self::setting_label( $type, $id, $context ) : null;

		if ( null !== $setting ) {
			return $setting;
		}

		if ( 'finding' === $type ) {
			if ( null === self::$checks ) {
				self::$checks = Checks::all();
			}

			return isset( self::$checks[ $id ] ) ? Checks::title_of( self::$checks[ $id ] ) : null;
		}

		// An assistant's connection by its application's name, read now, and
		// by the platform it called from where it was one (#1880).
		if ( 'mcp_connection' === $type ) {
			$name     = \BetterShield\Mcp\Audit::connection_label( $id );
			$provider = is_array( $context ) && 'anthropic' === ( $context['provider'] ?? '' ) ? 'Anthropic' : '';

			/* translators: 1: an assistant application's name, 2: the platform whose published range the call came from. */
			return '' === $provider ? $name : sprintf( __( '%1$s, from %2$s’s range', 'bettershield' ), $name, $provider );
		}

		/*
		 * One of this plugin's own abilities by the name Agent Activity
		 * gives the same call, never its code name (#2826). Read from the
		 * registry, so a name is never kept past the ability; with nothing
		 * registered the row keeps the code name. Another plugin's ability
		 * keeps its code name: its label is that plugin's own say.
		 */
		if ( 'ability_used' === $event && ( 'ability' === $type || \BetterShield\Mcp\Audit::OBJECT_TYPE === $type ) && str_starts_with( $id, 'bettershield/' ) && function_exists( 'wp_has_ability' ) && function_exists( 'wp_get_ability' ) && wp_has_ability( $id ) ) {
			$ability = wp_get_ability( $id );
			$label   = is_object( $ability ) && method_exists( $ability, 'get_label' ) ? trim( (string) $ability->get_label() ) : '';

			return '' !== $label ? $label : null;
		}

		// Sessions by whose they are: a suggestion to end them read "2",
		// the account's ID (#2826).
		if ( 'sessions' === $type ) {
			if ( 'site' === $id ) {
				return __( 'Every session on this site', 'bettershield' );
			}

			return preg_match( '/^[1-9][0-9]*$/', $id )
				? sprintf(
					/* translators: %s: an account's name. */
					__( 'Sessions for %s', 'bettershield' ),
					\BetterShield\Abilities\ReadSurface::account_label( (int) $id )
				)
				: null;
		}

		// An alert by what it was, not by its kind's key (#1793).
		if ( 'alert' === $type ) {
			$kinds = array(
				'critical'           => __( 'Instant alert', 'bettershield' ),
				'digest'             => __( 'Weekly summary', 'bettershield' ),
				'recovery_readiness' => __( 'Recovery email check', 'bettershield' ),
			);

			return $kinds[ $id ] ?? null;
		}

		/*
		 * An incident by its number, as its own screen names it: "Incident
		 * response attempted · 1" was the bare id (#2242). A response says
		 * what it did as well, which is all its alert line can carry.
		 */
		if ( 'incident' === $type && preg_match( '/^[1-9][0-9]*$/', $id ) ) {
			/* translators: %d: an incident's own number. */
			$name = sprintf( __( 'Incident #%d', 'bettershield' ), (int) $id );

			// Opened, it says what started it: the number alone told the
			// email's reader nothing of what happened (#2486).
			if ( 'incident_opened' === $event && is_array( $context ) && '' !== (string) ( $context['source'] ?? '' ) ) {
				return sprintf(
					/* translators: 1: an incident's own number, 2: the kind of event that started it, e.g. "Failed sign-in". */
					__( 'Incident #%1$d (%2$s)', 'bettershield' ),
					(int) $id,
					\BetterShield\Events\Types::label( (string) $context['source'] )
				);
			}

			if ( 'incident_response_applied' !== $event || ! is_array( $context ) || ! isset( $context['applied'], $context['actions'] ) ) {
				return $name;
			}

			$kinds = array(
				'demote'     => __( 'site roles removed', 'bettershield' ),
				'sessions'   => __( 'sessions ended', 'bettershield' ),
				'passwords'  => __( 'application passwords revoked', 'bettershield' ),
				'reset'      => __( 'new password required', 'bettershield' ),
				'cron'       => __( 'scheduled event removed', 'bettershield' ),
				'restore'    => __( 'published copy restored', 'bettershield' ),
				'quarantine' => __( 'file quarantined', 'bettershield' ),
			);
			$done  = is_array( $context['done'] ?? null ) ? $context['done'] : array();
			$parts = array_values( array_filter( array_map( static fn( $kind ): ?string => is_string( $kind ) ? ( $kinds[ $kind ] ?? null ) : null, $done ) ) );

			if ( (int) ( $context['refused'] ?? 0 ) > 0 ) {
				/* translators: %d: how many response steps were refused. */
				$parts[] = sprintf( _n( '%d refused', '%d refused', (int) $context['refused'], 'bettershield' ), (int) $context['refused'] );
			}

			$counted = sprintf(
				/* translators: 1: an incident's name, e.g. "Incident #1", 2: steps applied, 3: steps selected. */
				_n( '%1$s, %2$d of %3$d action applied', '%1$s, %2$d of %3$d actions applied', (int) $context['actions'], 'bettershield' ),
				$name,
				(int) $context['applied'],
				(int) $context['actions']
			);

			return array() === $parts ? $counted : sprintf(
				/* translators: 1: what a response did in numbers, 2: the steps, comma-separated. */
				__( '%1$s (%2$s)', 'bettershield' ),
				$counted,
				implode( ', ', $parts )
			);
		}

		// A set of printed codes by how many, not by its key (#1916).
		if ( 'recovery' === $type && 'offline_codes' === $id ) {
			$count = is_array( $context ) ? (int) ( $context['count'] ?? 0 ) : 0;

			return $count > 0
				? sprintf(
					/* translators: %d: how many printed recovery codes were issued. */
					_n( '%d code', '%d codes', $count, 'bettershield' ),
					$count
				)
				: __( 'Printed recovery codes', 'bettershield' );
		}

		/*
		 * A lockout by the form it closed: its subject was its row's id
		 * ("Sign-in lockout started · 2"), which the row keeps because the
		 * lockout is looked up by it (#1932). The words it is recorded with
		 * otherwise are said too.
		 */
		if ( 'lockout' === $type ) {
			$forms = array(
				\BetterShield\Login\Surfaces::SIGNIN   => __( 'Sign-in form', 'bettershield' ),
				\BetterShield\Login\Surfaces::COMMENT  => __( 'Comment form', 'bettershield' ),
				\BetterShield\Login\Surfaces::RESET    => __( 'Password-reset form', 'bettershield' ),
				\BetterShield\Login\Surfaces::REGISTER => __( 'Sign-up form', 'bettershield' ),
				\BetterShield\Login\Surfaces::PROBE    => __( 'Missing pages', 'bettershield' ),
			);

			/*
			 * A release of some forms only is recorded as "all" with the forms
			 * it covered, and read "Every form" while the others' lockouts
			 * still stood. Those forms are named.
			 */
			if ( 'all' === $id && is_array( $context ) && is_array( $context['surfaces'] ?? null ) && array() !== array_diff( \BetterShield\Login\Surfaces::ALL, $context['surfaces'] ) ) {
				$named = array_values( array_filter( array_map( static fn( $surface ): ?string => is_string( $surface ) ? ( $forms[ $surface ] ?? null ) : null, $context['surfaces'] ) ) );

				if ( array() !== $named ) {
					return wp_sprintf( '%l', $named );
				}
			}

			$keys = array(
				'blocklist'  => __( 'Blocklist', 'bettershield' ),
				'email_link' => __( 'Emailed unlock link', 'bettershield' ),
				'all'        => __( 'Every form', 'bettershield' ),
			);

			if ( isset( $keys[ $id ] ) ) {
				return $keys[ $id ];
			}

			if ( ! preg_match( '/^[0-9]+$/', $id ) ) {
				return null;
			}
			// A sign-in lockout predates saying which form it was.
			$surface = is_array( $context ) && is_string( $context['surface'] ?? null ) ? $context['surface'] : \BetterShield\Login\Surfaces::SIGNIN;

			return $forms[ $surface ] ?? null;
		}

		/*
		 * A maintenance window by when it ends, not by its id: an alert said
		 * "Planned maintenance started: 1b09ec54-…" (#1958). The row keeps
		 * the id, which its summary is found by.
		 */
		if ( 'maintenance' === $type ) {
			// A booked window by when it starts: "until" alone did not say
			// when alerts would go quiet.
			$starts = is_array( $context ) ? strtotime( (string) ( $context['starts'] ?? '' ) ) : false;

			if ( false !== $starts && $starts > 0 ) {
				$ends = strtotime( (string) ( $context['until'] ?? '' ) );

				return false !== $ends && $ends > 0
					/* translators: 1: date and time a booked maintenance window starts, 2: when it ends. */
					? sprintf( __( 'from %1$s until %2$s', 'bettershield' ), \BetterShield\Support\Time::said( $starts ), \BetterShield\Support\Time::said( $ends ) )
					/* translators: %s: date and time a booked maintenance window was to start. */
					: sprintf( __( 'booked for %s', 'bettershield' ), \BetterShield\Support\Time::said( $starts ) );
			}

			$closed = \BetterShield\Alerts\Maintenance::CLOSED === $event;
			$at     = is_array( $context ) ? strtotime( (string) ( $closed ? ( $context['ended'] ?? '' ) : ( $context['until'] ?? '' ) ) ) : false;

			if ( false === $at || $at <= 0 ) {
				return __( 'Planned maintenance window', 'bettershield' );
			}

			// With its zone, as the email's own moment beside it is (#2486).
			$when = \BetterShield\Support\Time::said( $at );

			return $closed
				/* translators: %s: date and time a maintenance window ended. */
				? sprintf( __( 'ended %s', 'bettershield' ), $when )
				/* translators: %s: date and time a maintenance window ends. */
				: sprintf( __( 'until %s', 'bettershield' ), $when );
		}

		// A change to what roles may do by the roles it touched, not by the
		// option that holds them: an alert said "wp_user_roles" (#2080).
		if ( 'role' === $type ) {
			$roles = is_array( $context ) && is_array( $context['roles'] ?? null ) ? array_values( array_filter( array_map( 'strval', $context['roles'] ) ) ) : array();

			return array() === $roles ? null : wp_sprintf( '%l', $roles );
		}

		/*
		 * A switch by the name its screen gives it and the way it went: five
		 * turns of the agent switches read as five bare "Setting changed"
		 * rows, and turning changes on looked like turning them off (#2002).
		 */
		if ( 'setting' === $type ) {
			$switches = array(
				\BetterShield\Abilities\Registrar::OPTION       => __( 'Let AI assistants see security info', 'bettershield' ),
				\BetterShield\Abilities\Registrar::WRITE_OPTION => __( 'Let AI assistants fix things', 'bettershield' ),
				\BetterShield\Agents\Capture::OPTION            => __( 'Record what agents do on this site', 'bettershield' ),
				\BetterShield\Mcp\Manager::OPTION               => __( 'Allow AI assistant connections', 'bettershield' ),
			);

			if ( ! isset( $switches[ $id ] ) ) {
				return null;
			}

			if ( ! is_array( $context ) || ! array_key_exists( 'enabled', $context ) ) {
				return $switches[ $id ];
			}

			return sprintf(
				/* translators: 1: a switch's name, 2: on or off. */
				__( '%1$s: %2$s', 'bettershield' ),
				$switches[ $id ],
				$context['enabled'] ? __( 'on', 'bettershield' ) : __( 'off', 'bettershield' )
			);
		}

		// The whole audit, explained at once: what it covered, not a key.
		if ( 'audit' === $type && 'summary' === $id ) {
			return __( 'Open findings', 'bettershield' );
		}

		// A network's site by its address, and a change of its standing by
		// what changed (#1975).
		if ( 'site' === $type && is_array( $context ) && '' !== (string) ( $context['address'] ?? '' ) ) {
			$address = (string) $context['address'];
			$changed = 'site_status_changed' === $event && is_array( $context['changed'] ?? null ) ? $context['changed'] : array();
			$words   = array(
				'archived' => array( __( 'archived', 'bettershield' ), __( 'unarchived', 'bettershield' ) ),
				'deleted'  => array( __( 'deactivated', 'bettershield' ), __( 'reactivated', 'bettershield' ) ),
				'spam'     => array( __( 'marked as spam', 'bettershield' ), __( 'no longer spam', 'bettershield' ) ),
				'public'   => array( __( 'shown to search engines', 'bettershield' ), __( 'hidden from search engines', 'bettershield' ) ),
				'mature'   => array( __( 'marked mature', 'bettershield' ), __( 'no longer mature', 'bettershield' ) ),
			);
			$said    = array();

			foreach ( $changed as $flag => $on ) {
				if ( isset( $words[ $flag ] ) ) {
					$said[] = $words[ $flag ][ $on ? 0 : 1 ];
				}
			}

			return array() === $said ? $address : sprintf(
				/* translators: 1: a network site's address, e.g. example.com/shop/; 2: what changed, e.g. "archived, marked as spam". */
				__( '%1$s: %2$s', 'bettershield' ),
				$address,
				implode( wp_get_list_item_separator(), $said )
			);
		}

		// A file saved in the editor by its path inside the plugin or theme,
		// and the plugin or theme by name (#1974).
		if ( 'theme_plugin_file_edited' === $event && is_array( $context ) && '' !== (string) ( $context['file'] ?? '' ) ) {
			return sprintf(
				/* translators: 1: a file's path inside its plugin or theme, e.g. functions.php; 2: the plugin's or theme's name. */
				__( '%1$s in %2$s', 'bettershield' ),
				(string) $context['file'],
				'' !== trim( (string) ( $context['name'] ?? '' ) ) ? (string) $context['name'] : $id
			);
		}

		// The trap password by the name it was given, never its ID.
		if ( 'canary_used' === $event && 'app_password' === $type ) {
			return is_array( $context ) && '' !== trim( (string) ( $context['name'] ?? '' ) ) ? (string) $context['name'] : null;
		}

		// A plugin by the name its header gave when the row was written, as
		// the Plugins screen names it, not by its file (#2120).
		if ( 'plugin' === $type ) {
			return is_array( $context ) && isset( $context['name'] ) && '' !== trim( (string) $context['name'] ) ? (string) $context['name'] : null;
		}

		// An assistant application by the name it introduced itself with:
		// its client id told the owner nothing about which one was let in.
		if ( 'mcp_app' === $type ) {
			return is_array( $context ) && isset( $context['name'] ) && '' !== trim( (string) $context['name'] ) ? (string) $context['name'] : null;
		}

		// A scheduled task by its name on the Schedules screen, not its hook:
		// "Early run finished" named `bettershield_certificate_check`.
		if ( 'task' === $type ) {
			return self::task_labels()[ $id ] ?? null;
		}

		if ( 'hardening' === $type || 'hardening_item' === $type ) {
			if ( null === self::$items ) {
				self::$items = Items::all();
			}

			return isset( self::$items[ $id ]['title'] ) ? (string) self::$items[ $id ]['title'] : null;
		}

		if ( 'user' !== $type || in_array( $event, self::TYPED_NAMES, true ) || ! preg_match( '/^[1-9][0-9]*$/', $id ) ) {
			return null;
		}

		$login = self::account_login( (int) $id, $context );

		return null !== $login && 'login_lockout_emailed' === $event ? self::why_lockout_emailed( $login, $context ) : $login;
	}

	/**
	 * An account's login, read now, or as the log recorded it once it is gone.
	 *
	 * @param mixed $context The row's decoded context.
	 */
	private static function account_login( int $id, $context ): ?string {
		$user = get_userdata( $id );

		if ( $user instanceof \WP_User && '' !== (string) $user->user_login ) {
			return (string) $user->user_login;
		}

		if ( is_array( $context ) && isset( $context['login'] ) && '' !== (string) $context['login'] ) {
			return (string) $context['login'];
		}

		return self::$recorded_logins[ $id ] ?? null;
	}

	/**
	 * Who a lockout email went to, and why it went: the row records the
	 * reason as a code the screen would otherwise never show.
	 *
	 * @param mixed $context The row's decoded context.
	 */
	private static function why_lockout_emailed( string $login, $context ): string {
		switch ( is_array( $context ) ? (string) ( $context['why'] ?? '' ) : '' ) {
			case 'familiar':
				/* translators: %s: the account's username. */
				return sprintf( __( '%s, on a network the account has used', 'bettershield' ), $login );
			case 'requested':
				/* translators: %s: the account's username. */
				return sprintf( __( '%s, unlock link asked for on the sign-in screen', 'bettershield' ), $login );
			case 'password_right':
				/* translators: %s: the account's username. */
				return sprintf( __( '%s, correct password then wrong two-factor codes', 'bettershield' ), $login );
			default:
				return $login;
		}
	}

	/**
	 * Every scheduled task's name, by hook.
	 *
	 * @return array<string, string>
	 */
	private static function task_labels(): array {
		if ( null === self::$tasks ) {
			self::$tasks = \BetterShield\Cron\Labels::all();
		}

		return self::$tasks;
	}

	/**
	 * Reads every account a page names in one query, so naming them costs a
	 * read per page rather than one per row.
	 *
	 * An account deleted since has nothing left to read there, and only its
	 * creation and deletion recorded its login, so its other rows were named
	 * by id. The logins those two rows recorded are read once for the page,
	 * from the rows the reader can see, for the accounts that are gone.
	 *
	 * @param array<int, object> $rows  The page's rows as stored.
	 * @param string             $table The table they were read from; the site's own when empty.
	 * @param string             $scope The site predicate they were read under; the site's own when empty.
	 */
	public static function load_accounts( array $rows, string $table = '', string $scope = '' ): void {
		global $wpdb;

		self::$recorded_logins = array();

		$ids = array();

		foreach ( $rows as $row ) {
			if ( 'user' === ( $row->object_type ?? null ) && ! in_array( (string) $row->event_type, self::TYPED_NAMES, true ) && preg_match( '/^[1-9][0-9]*$/', (string) $row->object_id ) ) {
				$ids[ (int) $row->object_id ] = true;
			}
		}

		if ( array() === $ids ) {
			return;
		}

		cache_users( array_keys( $ids ) );

		$gone = self::gone( array_keys( $ids ) );

		if ( array() === $gone ) {
			return;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$records = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT object_id, context FROM %i WHERE ' . ( '' !== $scope ? $scope : Schema::site_where( 'events' ) )
					. ' AND event_type IN (' . implode( ',', array_fill( 0, count( self::LOGIN_RECORDS ), '%s' ) )
					. ") AND object_type = 'user' AND object_id IN (" . implode( ',', array_fill( 0, count( $gone ), '%s' ) ) . ') ORDER BY id DESC',
				array_merge( array( '' !== $table ? $table : Schema::table( 'events' ) ), self::LOGIN_RECORDS, array_map( 'strval', $gone ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( is_array( $records ) ? $records : array() as $record ) {
			$login = self::recorded_login( $record->context );

			// Newest first, so the login last recorded is the one kept.
			if ( '' !== $login && ! isset( self::$recorded_logins[ (int) $record->object_id ] ) ) {
				self::$recorded_logins[ (int) $record->object_id ] = $login;
			}
		}
	}

	/**
	 * Accounts deleted since whose login, as the log recorded it, contains the
	 * term. Only the rows that record a login are read, newest first and a
	 * bounded number of them, and the login is compared after decoding, so
	 * nothing else in the recorded detail can match.
	 *
	 * @param string $search The term.
	 * @param string $table  The table the read answers from; the site's own when empty.
	 * @param string $scope  The site predicate it reads under; the site's own when empty.
	 * @return array<int, int> Their ids.
	 */
	private static function gone_accounts_named( string $search, string $table, string $scope ): array {
		global $wpdb;

		// The term as the context column stores it, to narrow the read; the
		// decoded login decides.
		$encoded = substr( (string) wp_json_encode( $search ), 1, -1 );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$records = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT object_id, context FROM %i WHERE ' . ( '' !== $scope ? $scope : Schema::site_where( 'events' ) )
					. ' AND event_type IN (' . implode( ',', array_fill( 0, count( self::LOGIN_RECORDS ), '%s' ) )
					. ") AND object_type = 'user' AND context LIKE %s ORDER BY id DESC LIMIT 200",
				array_merge( array( '' !== $table ? $table : Schema::table( 'events' ) ), self::LOGIN_RECORDS, array( '%' . $wpdb->esc_like( $encoded ) . '%' ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$ids = array();

		foreach ( is_array( $records ) ? $records : array() as $record ) {
			$login = self::recorded_login( $record->context );

			if ( '' !== $login && false !== stripos( $login, $search ) && preg_match( '/^[1-9][0-9]*$/', (string) $record->object_id ) ) {
				$ids[ (int) $record->object_id ] = true;
			}
		}

		if ( array() === $ids ) {
			return array();
		}

		cache_users( array_keys( $ids ) );

		// An account that still exists is found by its login as it is now.
		return self::gone( array_keys( $ids ) );
	}

	/**
	 * The ids of the assistant applications and plugins whose recorded name,
	 * the one object_label() shows for their rows, contains the search,
	 * keyed by object type. A bounded read of the newest rows that could
	 * name one; the decoded name decides, as for a gone account's login.
	 *
	 * @return array<string, string[]>
	 */
	private static function context_named_ids( string $search, string $table, string $scope ): array {
		global $wpdb;

		$encoded = substr( (string) wp_json_encode( $search ), 1, -1 );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$records = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT object_type, object_id, context FROM %i WHERE ' . ( '' !== $scope ? $scope : Schema::site_where( 'events' ) )
					. " AND object_type IN ('mcp_app', 'plugin') AND context LIKE %s ORDER BY id DESC LIMIT 200",
				'' !== $table ? $table : Schema::table( 'events' ),
				'%' . $wpdb->esc_like( $encoded ) . '%'
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$ids = array();

		foreach ( is_array( $records ) ? $records : array() as $record ) {
			$context = json_decode( (string) $record->context, true );
			$name    = is_array( $context ) && is_string( $context['name'] ?? null ) ? $context['name'] : '';

			if ( '' !== trim( $name ) && false !== stripos( $name, $search ) && '' !== (string) $record->object_id ) {
				$ids[ (string) $record->object_type ][ (string) $record->object_id ] = true;
			}
		}

		return array_map( 'array_keys', $ids );
	}

	/**
	 * Of these account ids, the ones no account has any more. Read off the
	 * user cache, which cache_users() has just filled for every one that
	 * exists, so asking costs no query per id.
	 *
	 * @param array<int, int> $ids
	 * @return array<int, int>
	 */
	private static function gone( array $ids ): array {
		return array_values(
			array_filter(
				$ids,
				static function ( int $id ): bool {
					return false === wp_cache_get( $id, 'users' );
				}
			)
		);
	}

	/**
	 * The login a row's stored context recorded, or ''.
	 *
	 * @param mixed $context The context column as stored.
	 */
	private static function recorded_login( $context ): string {
		$decoded = is_string( $context ) ? json_decode( $context, true ) : null;

		return is_array( $decoded ) && isset( $decoded['login'] ) && is_scalar( $decoded['login'] ) ? (string) $decoded['login'] : '';
	}

	/**
	 * An event's written name, read off what the row recorded where one type
	 * stands for more than one thing. An alert is recorded whether or not
	 * WordPress accepted it for sending, and one it refused is not "Alert
	 * sent". An AI explanation is of a finding, of the whole audit or of an
	 * incident, and only the first is "Finding explained by AI".
	 *
	 * Public because every reader of the log names a row the same way: the
	 * screen through the listing here, an assistant through the abilities.
	 *
	 * @param string      $type        The event type.
	 * @param mixed       $context     The row's decoded context.
	 * @param string|null $object_type What the row is about, where it says.
	 */
	public static function label_of( string $type, $context, ?string $object_type = null ): string {
		if ( 'alert_sent' === $type && is_array( $context ) && array_key_exists( 'sent', $context ) && false === $context['sent'] ) {
			return __( 'Alert not accepted for sending', 'bettershield' );
		}

		/*
		 * An assistant's call that did not complete is not a query. The type
		 * stays one, so a filter on assistant calls still finds it; the row
		 * says what became of it.
		 */
		// The row is written whether or not the mail went, so a mail that
		// did not go is not said to have been emailed (#2826).
		if ( 'account_notice_sent' === $type && is_array( $context ) && false === ( $context['sent'] ?? null ) ) {
			return __( 'Sign-in change email to the account holder could not be sent', 'bettershield' );
		}

		// The same for a lockout email, which is recorded whether or not it went.
		if ( 'login_lockout_emailed' === $type && is_array( $context ) && false === ( $context['delivered'] ?? null ) ) {
			return __( 'Lockout email could not be sent', 'bettershield' );
		}

		if ( 'ability_used' === $type && is_array( $context ) && 'failed' === ( $context['outcome'] ?? null ) ) {
			return in_array( (string) ( $context['error'] ?? '' ), \BetterShield\Mcp\Audit::REFUSALS, true )
				? __( 'AI assistant call refused', 'bettershield' )
				: __( 'AI assistant call failed', 'bettershield' );
		}

		/*
		 * Lockouts cover the comment, sign-up and password-reset forms as
		 * well as sign-in, and every release read "Sign-in lockout cleared".
		 * A row that says which form is named by it; one that cleared more
		 * than one form, or that predates saying, is a lockout cleared.
		 */
		if ( 'login_lockout_cleared' === $type && is_array( $context ) ) {
			$surfaces = isset( $context['surfaces'] ) && is_array( $context['surfaces'] ) ? $context['surfaces'] : ( isset( $context['surface'] ) ? array( $context['surface'] ) : array() );

			if ( 1 === count( $surfaces ) ) {
				switch ( (string) reset( $surfaces ) ) {
					case \BetterShield\Login\Surfaces::SIGNIN:
						return __( 'Sign-in lockout cleared', 'bettershield' );
					case \BetterShield\Login\Surfaces::COMMENT:
						return __( 'Comment-form lockout cleared', 'bettershield' );
					case \BetterShield\Login\Surfaces::RESET:
						return __( 'Password-reset lockout cleared', 'bettershield' );
					case \BetterShield\Login\Surfaces::REGISTER:
						return __( 'Sign-up lockout cleared', 'bettershield' );
					case \BetterShield\Login\Surfaces::PROBE:
						return __( 'Missing-page lockout cleared', 'bettershield' );
				}
			}

			if ( count( $surfaces ) > 1 ) {
				return __( 'Lockouts cleared', 'bettershield' );
			}
		}

		// The probe surface is not a form, and "Form closed" misnamed it (#690).
		if ( 'surface_closed' === $type && is_array( $context ) && \BetterShield\Login\Surfaces::PROBE === ( $context['surface'] ?? null ) ) {
			return __( 'Missing pages closed to a network', 'bettershield' );
		}

		/*
		 * One type for every difference the file check records. A file that
		 * was added has no official copy, and one that is missing matches
		 * nothing, and every row said "File no longer matches the official
		 * copy" (#1832). Named by what the row recorded; altered code that
		 * no publisher ships was compared against what it was before.
		 */
		if ( 'file_changed' === $type && is_array( $context ) ) {
			$published = in_array( (string) ( $context['area'] ?? '' ), array( \BetterShield\Integrity\Manifest::CONTEXT_CORE, \BetterShield\Integrity\Manifest::CONTEXT_PLUGIN ), true );

			switch ( (string) ( $context['change'] ?? '' ) ) {
				case 'added':
					return __( 'Added file not in the official release', 'bettershield' );
				case 'removed':
					return __( 'Expected file is missing', 'bettershield' );
				case 'unreadable':
					return __( 'File could not be read', 'bettershield' );
				case 'modified':
					return $published
						? __( 'File no longer matches the official copy', 'bettershield' )
						: __( 'File changed since it was last checked', 'bettershield' );
			}
		}

		// A set of printed codes shares the link's type, and its row read as
		// the link made again, once per set (#1916).
		if ( 'recovery_link_generated' === $type && is_array( $context ) && 'offline_codes' === ( $context['kind'] ?? '' ) ) {
			return __( 'Printed recovery codes issued', 'bettershield' );
		}

		/*
		 * A response plan is recorded once, when its batch ends, and every row
		 * read "Incident response attempted" though each step had landed. It
		 * is an attempt only where none did (#2242); a row written before the
		 * counts were is named by its type.
		 */
		if ( 'incident_response_applied' === $type && is_array( $context ) && isset( $context['applied'] ) && 0 === (int) $context['applied'] ) {
			return __( 'Incident response attempted', 'bettershield' );
		}

		if ( 'ai_explanation_generated' === $type ) {
			switch ( $object_type ) {
				case 'finding':
					return __( 'Finding explained by AI', 'bettershield' );
				case 'audit':
					return __( 'Audit explained by AI', 'bettershield' );
				case 'incident':
					return __( 'Incident explained by AI', 'bettershield' );
			}
		}

		return Types::label( $type );
	}

	/**
	 * The site a row with no id of its own belongs to.
	 */
	private static function main_site_id(): int {
		return is_multisite() ? (int) get_main_site_id() : 0;
	}
}
