<?php
/**
 * Reads the agent invocation record.
 *
 * One definition of the filters, shared by the listing and by the counts
 * beside it, because two readers narrowing the same table would drift and
 * the chips would then advertise numbers the list could not produce.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Database\Schema;
use BetterShield\Support\Text;
use BetterShield\Support\Tier;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * A plugin-owned table with no core API, read without a cache: a record
 * served from a stale copy omits the most recent entry, which is the one most
 * likely to matter.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Invocations {

	public const PER_PAGE = 40;

	/**
	 * Newest first, one page at a time.
	 *
	 * Paged on `id` rather than on time, for the reason the activity log is:
	 * the column is monotonic with insertion and unique, so a page boundary
	 * cannot repeat or skip a row even when many invocations share a
	 * millisecond — which they routinely do, since one request writes its
	 * whole buffer in a single insert.
	 *
	 * @param array{cursor?: int, outcome?: string, ability?: string, namespace?: string, entry_path?: string, per_page?: int} $args
	 * @return array{invocations: array<int, array<string, mixed>>, next_cursor: ?int}
	 */
	public static function page( array $args = array() ): array {
		global $wpdb;

		if ( ! self::table_ready() ) {
			return array(
				'invocations' => array(),
				'next_cursor' => null,
			);
		}

		$cursor   = isset( $args['cursor'] ) ? (int) $args['cursor'] : 0;
		$per_page = isset( $args['per_page'] ) ? max( 1, min( 200, (int) $args['per_page'] ) ) : self::PER_PAGE;

		// One more than the page size, so the presence of a next page is
		// known without a second COUNT over the whole table.
		$limit = $per_page + 1;

		$where  = array( Schema::site_where( 'agent_invocations' ) );
		$params = array( Schema::table( 'agent_invocations' ) );

		if ( $cursor > 0 ) {
			$where[]  = 'id < %d';
			$params[] = $cursor;
		}

		list( $clauses, $filter_params ) = self::conditions( $args, true );

		$where    = array_merge( $where, $clauses );
		$params   = array_merge( $params, $filter_params );
		$params[] = $limit;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, invoked_at, ability_name, registering_plugin, entry_path, user_id, outcome, error_code, input_digest, duration_ms' . ( Schema::ready( 'invocation_connection' ) ? ', connection' : '' ) . ' FROM %i WHERE ' . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d',
				$params
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$rows = is_array( $rows ) ? $rows : array();

		$has_more = count( $rows ) > $per_page;
		if ( $has_more ) {
			array_pop( $rows );
		}

		$invocations = array();
		foreach ( $rows as $row ) {
			$invocations[] = self::shape( $row );
		}

		return array(
			'invocations' => $invocations,
			'next_cursor' => $has_more && array() !== $invocations ? end( $invocations )['id'] : null,
		);
	}

	/**
	 * The filtered record as CSV, for an auditor's file.
	 *
	 * Assembled by walking the same paged read the screen uses, in bounded
	 * batches under a wall-clock budget — the plugin's rule for every loop
	 * over its own tables. Falling short of the whole record is acceptable and
	 * is stated in the file; blocking the request that asked for it is not.
	 *
	 * This is the only way the agent record leaves a site, so it is the one
	 * read here that has to be the whole record rather than a page of it: a
	 * file that holds the newest forty rows and looks complete tells its
	 * reader something untrue about what an agent did.
	 *
	 * @param array{outcome?: string, ability?: string, namespace?: string, entry_path?: string} $args
	 * @return array{csv: string, rows: int, complete: bool}
	 */
	public static function export( array $args = array(), int $max_rows = 10000, float $budget_seconds = 10.0 ): array {
		$start    = microtime( true );
		$cursor   = 0;
		$rows     = 0;
		$complete = true;

		$lines = array(
			Text::csv_row( array( 'id', 'invoked_at_utc', 'ability', 'namespace', 'entry_path', 'user_id', 'user_label', 'outcome', 'error_code', 'input_digest', 'duration_ms', 'connection' ) ),
		);

		do {
			$page = self::page(
				array_merge(
					$args,
					array(
						'cursor' => $cursor,
						// Never ask for more than the allowance has room for,
						// or a single page could overshoot the cap entirely
						// and the file would be larger than it promised.
						'per_page' => max( 1, min( 200, $max_rows - $rows ) ),
					)
				)
			);

			foreach ( $page['invocations'] as $invocation ) {
				$lines[] = Text::csv_row(
					array(
						(string) $invocation['id'],
						(string) $invocation['invoked_at'],
						(string) $invocation['ability'],
						null !== $invocation['namespace'] ? (string) $invocation['namespace'] : '',
						(string) $invocation['entry_path'],
						(string) $invocation['user_id'],
						(string) $invocation['user_label'],
						(string) $invocation['outcome'],
						null !== $invocation['error_code'] ? (string) $invocation['error_code'] : '',
						null !== $invocation['input_digest'] ? (string) $invocation['input_digest'] : '',
						null !== $invocation['duration_ms'] ? (string) $invocation['duration_ms'] : '',
						null !== $invocation['connection'] ? (string) $invocation['connection_label'] . ' (' . (string) $invocation['connection'] . ')' : '',
					)
				);

				++$rows;
			}

			$cursor = $page['next_cursor'];

			if ( null !== $cursor && ( $rows >= $max_rows || microtime( true ) - $start >= $budget_seconds ) ) {
				// Never a silent truncation: a file that stops early says so
				// in its own last line, where anyone reading it will meet it.
				$lines[]  = Text::csv_row( array( '# truncated: more rows matched than this export carries. Narrow the filters and export again.' ) );
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
	 * Every filter except the cursor, as clauses and the values they bind.
	 *
	 * `$with_outcome` is what lets the counts leave the outcome out. A facet
	 * counts against the *other* filters and never against its own selection
	 * — count an outcome against itself and every chip reads either its full
	 * total or nothing, which is no information at all.
	 *
	 * @param array{outcome?: string, ability?: string, namespace?: string, entry_path?: string} $args
	 * @return array{0: string[], 1: array<int, mixed>}
	 */
	public static function conditions( array $args, bool $with_outcome ): array {
		$where  = array();
		$params = array();

		$outcome = isset( $args['outcome'] ) ? (string) $args['outcome'] : '';

		if ( $with_outcome && '' !== $outcome && in_array( $outcome, Capture::OUTCOMES, true ) ) {
			$where[]  = 'outcome = %s';
			$params[] = $outcome;
		}

		$ability = isset( $args['ability'] ) ? trim( (string) $args['ability'] ) : '';

		if ( '' !== $ability ) {
			$where[]  = 'ability_name = %s';
			$params[] = $ability;
		}

		$namespace = isset( $args['namespace'] ) ? trim( (string) $args['namespace'] ) : '';

		if ( '' !== $namespace ) {
			$where[]  = 'registering_plugin = %s';
			$params[] = $namespace;
		}

		// One account: the one the call ran as. No credential is stored per
		// call, so this is as close to "this agent" as the record goes.
		$user = isset( $args['user'] ) ? (int) $args['user'] : 0;

		if ( $user > 0 ) {
			$where[]  = 'user_id = %d';
			$params[] = $user;
		}

		$entry_path = isset( $args['entry_path'] ) ? trim( (string) $args['entry_path'] ) : '';

		if ( '' !== $entry_path ) {
			$where[]  = 'entry_path = %s';
			$params[] = $entry_path;
		}

		// One connection: which assistant made the call, where the account
		// alone cannot tell two of them apart (#2213).
		$connection = isset( $args['connection'] ) ? trim( (string) $args['connection'] ) : '';

		if ( '' !== $connection && ! Schema::ready( 'invocation_connection' ) ) {
			// No row names one yet, so none matches.
			$where[] = '1 = 0';
		} elseif ( '' !== $connection ) {
			$where[]  = 'connection = %s';
			$params[] = $connection;
		}

		// The retention window, applied to every read whatever was asked for:
		// rows older than the current retention allows are not returned even while
		// they are still on disk.
		$where[]  = 'invoked_at >= %s';
		$params[] = Tier::retention_floor();

		return array( $where, $params );
	}

	/**
	 * How many invocations each outcome accounts for, under the other
	 * filters. This is what puts a number on every chip, and what lets the
	 * screen answer its own question before anybody clicks: "Refused · 0" is
	 * the good news, and it is worth stating.
	 *
	 * @param array{ability?: string, namespace?: string, entry_path?: string} $args
	 * @return array<string, int>
	 */
	public static function counts( array $args = array() ): array {
		global $wpdb;

		$counts = array( 'all' => 0 );

		foreach ( Capture::OUTCOMES as $outcome ) {
			$counts[ $outcome ] = 0;
		}

		if ( ! self::table_ready() ) {
			return $counts;
		}

		list( $clauses, $params ) = self::conditions( $args, false );

		$where  = array_merge( array( Schema::site_where( 'agent_invocations' ) ), $clauses );
		$params = array_merge( array( Schema::table( 'agent_invocations' ) ), $params );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT outcome, COUNT(*) AS total FROM %i WHERE ' . implode( ' AND ', $where ) . ' GROUP BY outcome',
				$params
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$outcome = (string) $row->outcome;
			$total   = (int) $row->total;

			$counts['all'] += $total;

			// An outcome this version does not know about is still counted in
			// the total. Dropping it would make the chips add up to less than
			// the list shows, and the list is what is true.
			if ( isset( $counts[ $outcome ] ) ) {
				$counts[ $outcome ] = $total;
			}
		}

		return $counts;
	}

	/**
	 * The namespaces that have been seen, with a count each, newest activity
	 * first. Presented as namespaces rather than plugins on purpose: the
	 * platform exposes no accessor that maps an ability to the plugin behind
	 * it, so this is a naming convention and the screen says so.
	 *
	 * @return array<int, array{namespace: string, total: int}>
	 */
	public static function namespaces( int $limit = 40 ): array {
		global $wpdb;

		if ( ! self::table_ready() ) {
			return array();
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT registering_plugin, COUNT(*) AS total FROM %i WHERE ' . Schema::site_where( 'agent_invocations' ) . ' AND registering_plugin IS NOT NULL AND invoked_at >= %s GROUP BY registering_plugin ORDER BY total DESC LIMIT %d',
				Schema::table( 'agent_invocations' ),
				Tier::retention_floor(),
				max( 1, min( 200, $limit ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[] = array(
				'namespace' => (string) $row->registering_plugin,
				'total'     => (int) $row->total,
			);
		}

		return $out;
	}

	/**
	 * The connections that have made calls, with a count each and the label
	 * an owner reads, busiest first: what the screen's connection filter
	 * offers.
	 *
	 * @return array<int, array{connection: string, label: string, total: int}>
	 */
	public static function connections( int $limit = 40 ): array {
		global $wpdb;

		if ( ! self::table_ready() || ! Schema::ready( 'invocation_connection' ) ) {
			return array();
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT connection, COUNT(*) AS total FROM %i WHERE ' . Schema::site_where( 'agent_invocations' ) . ' AND connection IS NOT NULL AND invoked_at >= %s GROUP BY connection ORDER BY total DESC LIMIT %d',
				Schema::table( 'agent_invocations' ),
				Tier::retention_floor(),
				max( 1, min( 200, $limit ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[] = array(
				'connection' => (string) $row->connection,
				'label'      => \BetterShield\Mcp\Audit::connection_label( (string) $row->connection ),
				'total'      => (int) $row->total,
			);
		}

		return $out;
	}

	/**
	 * An ability's registered label, or null when nothing by that name is
	 * registered now. Read from the registry each time, so a label is never
	 * kept past the ability it names.
	 */
	private static function ability_label( string $name ): ?string {
		if ( '' === $name || ! function_exists( 'wp_has_ability' ) || ! function_exists( 'wp_get_ability' ) || ! wp_has_ability( $name ) ) {
			return null;
		}

		$ability = wp_get_ability( $name );
		$label   = is_object( $ability ) && method_exists( $ability, 'get_label' ) ? trim( (string) $ability->get_label() ) : '';

		return '' !== $label ? $label : null;
	}

	/**
	 * Whether the migration that creates this table has been verified and
	 * stamped. Reading before then is not an error — it is a site mid-upgrade
	 * — so it answers empty rather than raising.
	 */
	private static function table_ready(): bool {
		return Schema::ready( 'agent_invocations' );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function shape( object $row ): array {
		$user_id    = null === $row->user_id ? 0 : (int) $row->user_id;
		$connection = isset( $row->connection ) && '' !== (string) $row->connection ? (string) $row->connection : null;

		return array(
			'id'           => (int) $row->id,
			// Stored UTC without a zone marker; say so explicitly rather than
			// let the browser read it as local time.
			'invoked_at'   => Time::utc_iso( (string) $row->invoked_at ),
			'ability'      => (string) $row->ability_name,
			// What the owner reads in the row: the ability's own registered
			// label, or null where it is no longer registered (#2364).
			'ability_label' => self::ability_label( (string) $row->ability_name ),
			'namespace'    => null === $row->registering_plugin ? null : (string) $row->registering_plugin,
			'entry_path'   => (string) $row->entry_path,
			'user_id'      => $user_id,
			'user_label'   => self::user_label( $user_id ),
			'outcome'      => (string) $row->outcome,
			'error_code'   => null === $row->error_code ? null : (string) $row->error_code,
			'input_digest' => null === $row->input_digest ? null : (string) $row->input_digest,
			'duration_ms'  => null === $row->duration_ms ? null : (int) $row->duration_ms,
			// Which connection made the call, and what the owner calls it.
			// Null for a call from no connection, and for rows from before
			// the column existed.
			'connection'       => $connection,
			'connection_label' => null === $connection ? null : \BetterShield\Mcp\Audit::connection_label( $connection ),
		);
	}

	/**
	 * A display label for whoever made the call, resolved at read time rather
	 * than stored. Storing it would keep a name after the account is gone,
	 * and the rule here is an identifier plus a label, never a user record.
	 */
	private static function user_label( int $user_id ): string {
		if ( 0 === $user_id ) {
			return __( 'Not signed in', 'bettershield' );
		}

		$user = get_userdata( $user_id );

		if ( ! $user instanceof \WP_User ) {
			/* translators: %d: the numeric id of an account that no longer exists. */
			return sprintf( __( 'Deleted account (%d)', 'bettershield' ), $user_id );
		}

		return (string) $user->display_name;
	}
}
