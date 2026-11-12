<?php
/**
 * Database schema installer and upgrader.
 *
 * Custom tables instead of postmeta/options/CPTs: the write volume and
 * time-range query patterns need purpose-built compound indexes, and
 * retention pruning must never lock shared core tables.
 *
 * Migrations are forward-only and never destructive: no migration may
 * drop a table or column, because on a security plugin that would drop
 * evidence. New tables ship with the features that need them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Schema {

	/**
	 * Bump when a migration adds tables or columns, or when an update has a
	 * step to take once that cannot wait for somebody to open a screen.
	 * Never for removals.
	 *
	 * 2: login attempts and lockouts.
	 * 3: entry_path on events — which door an action came through.
	 * 4: the integrity baseline and its changes.
	 * 5: enrolled passkeys.
	 * 6: the passkey credential column narrowed to ASCII, so its unique index
	 *    fits the row-size limit older servers enforce. A changed column rather
	 *    than a new one, which is why it reads as a gap in this list.
	 * 7: claims — which request goes first, decided by a unique key.
	 * 8: agent invocations — what the Abilities API was asked to do.
	 * 9: the network data model — events, findings, agent invocations and
	 *    passkeys live once per network, carried over site by site by the
	 *    migration task; on a single site the version is a stamp and nothing
	 *    moves.
	 * 10: per-site correlated incidents and durable evidence.
	 * 11: indexed lookup of durable observed-change and incident response receipts.
	 * 12: write proposals — what an agent asked for, and the one confirmation
	 *     a person may mint against it.
	 * 13: which surface an attempt and a lockout belong to. Existing rows are
	 *     sign-ins, which is what they were, so the default carries them over
	 *     without a data migration.
	 * 14: no table changes. The update that brings the cloud-metadata block
	 *     switches it on, once, and this is where an update first runs.
	 * 15: whether each passkey has verified its holder; older rows remain unknown.
	 * 16: which connection made each agent call; older rows remain unknown.
	 * 17: whether each passkey can sign in without a username, as the browser
	 *     reported it at enrollment; older rows and silent browsers stay unknown.
	 * 18: whether a file change came under a version nothing confirms; older
	 *     rows keep the grade they were reported at.
	 * 19: the named signs of compromise an added file showed, as rule ids and
	 *     line numbers; older rows have none.
	 */
	public const VERSION = 19;

	private const OPTION = 'bettershield_schema_version';

	/**
	 * Which capabilities the migration proved, when each last changed, and
	 * what the database said about the ones it could not.
	 *
	 * Beside the version rather than instead of it: the version is what every
	 * existing reader means by "the schema is done", and it keeps that meaning.
	 * The map is what a single missing table may narrow, so that one absence
	 * stops the writer it belongs to and nothing else.
	 */
	private const READINESS_OPTION = 'bettershield_schema_readiness';

	/**
	 * The tables that live once per network, at the base prefix.
	 *
	 * What a network administrator reads across sites, or what belongs to the
	 * host rather than the site. Everything else stays per blog: its keys are
	 * global by design and its subject is one site's own mechanism.
	 *
	 * @var string[]
	 */
	public const NETWORK_TABLES = array( 'events', 'findings', 'agent_invocations', 'passkeys' );

	/** Readiness of the network tables, recorded once for the whole network. */
	private const NETWORK_OPTION = 'bettershield_network_schema';

	/**
	 * The version that first carried each capability a writer or reader gates
	 * on, for the per-blog tables. The network tables were created whole at 9.
	 */
	private const CAPABILITY_VERSION = array(
		'events'            => 1,
		'findings'          => 1,
		'entry_path'        => 3,
		'passkeys'          => 5,
		'passkey_verification' => 15,
		'invocation_connection' => 16,
		'passkey_discoverable' => 17,
		'claims'            => 7,
		'agent_invocations' => 8,
		'incidents' => 10,
		'observed_changes' => 11,
		'incident_evidence' => 10,
		'write_proposals'   => 12,
		'request_surfaces'  => 13,
	);

	/** Which table a capability lives in, where the name is not the table's. */
	private const CAPABILITY_TABLE = array(
		'entry_path' => 'events',
		'passkey_verification' => 'passkeys',
		'passkey_discoverable' => 'passkeys',
		'invocation_connection' => 'agent_invocations',
	);

	/**
	 * Fully-prefixed table name for a short name, e.g. table( 'events' ).
	 *
	 * A network-scoped table answers at the base prefix on a network, with one
	 * transitional rule: on a subsite whose rows have not yet been carried
	 * over, it still answers at the blog prefix, so a half-migrated network
	 * keeps every site's log whole. The main site of a network has always
	 * used the base prefix, so its tables are the network tables. On a single
	 * site the two prefixes are one and nothing changes.
	 */
	public static function table( string $name ): string {
		global $wpdb;

		if ( self::is_network_table_here( $name ) ) {
			return $wpdb->base_prefix . 'bettershield_' . $name;
		}

		// One file check for the shared code, whichever site asks.
		if ( in_array( $name, \BetterShield\Integrity\Shared::TABLES, true ) && \BetterShield\Integrity\Shared::applies() ) {
			return $wpdb->base_prefix . 'bettershield_' . $name;
		}

		return $wpdb->prefix . 'bettershield_' . $name;
	}

	/**
	 * The network table's name, whatever the current site's migration state.
	 */
	public static function network_table( string $name ): string {
		global $wpdb;

		return $wpdb->base_prefix . 'bettershield_' . $name;
	}

	/**
	 * Whether, on this site right now, the named table is the network's.
	 */
	public static function is_network_table_here( string $name ): bool {
		return is_multisite()
			&& in_array( $name, self::NETWORK_TABLES, true )
			&& NetworkMigration::uses_network_table( $name );
	}

	/**
	 * The `site_id` a row written now into the named table carries.
	 *
	 * `0` on a single site, forever, and on a subsite still writing to its own
	 * table; the blog id once the site's rows live in the network table. The
	 * main site of a network writes its id too — its rows from before the
	 * migration carry `0`, and site_where() reads both.
	 */
	public static function site_id( string $table ): int {
		if ( ! self::is_network_table_here( $table ) ) {
			return 0;
		}

		return (int) get_current_blog_id();
	}

	/**
	 * The prepared predicate for "this site's rows" in the named table.
	 *
	 * Every read of a network-scoped table goes through this rather than
	 * naming a value: the value depends on which table answers here, and the
	 * main site of a network reads two of them.
	 */
	public static function site_where( string $table, string $column = 'site_id' ): string {
		$column = preg_replace( '/[^a-z_]/', '', $column );

		if ( ! self::is_network_table_here( $table ) ) {
			return $column . ' = 0';
		}

		$blog = (int) get_current_blog_id();

		if ( is_main_site() ) {
			return $column . ' IN (0, ' . $blog . ')';
		}

		return $column . ' = ' . $blog;
	}

	/**
	 * The prepared predicate for a network read: the rows of the listed
	 * sites, or of every site of the current network when the list is empty.
	 * The main site's pre-migration rows are included with it.
	 *
	 * @param int[] $site_ids
	 */
	public static function network_where( array $site_ids, string $column = 'site_id' ): string {
		$column = preg_replace( '/[^a-z_]/', '', $column );
		$ids    = array_values( array_unique( array_map( 'intval', $site_ids ) ) );

		if ( array() === $ids ) {
			// No filter still has a boundary on a network. On a single site
			// the table holds that site's rows and nobody else's, so there
			// is nothing left to narrow to.
			return is_multisite() ? self::current_network_where( $column ) : '1 = 1';
		}

		if ( in_array( (int) get_main_site_id(), $ids, true ) && self::legacy_rows_are_here() ) {
			$ids[] = 0;
		}

		sort( $ids );

		return $column . ' IN (' . implode( ', ', $ids ) . ')';
	}

	/**
	 * Every site of the network serving this request, and no other.
	 *
	 * These tables sit at the base prefix, which is one value per WordPress
	 * *installation* — and an installation can carry more than one network.
	 * So "no site filter" cannot mean "no restriction": it has to name the
	 * network, or one network's dashboard reads another's history.
	 *
	 * Written as a subquery against the registry rather than as a list of
	 * ids, so the clause cannot be stale by the time it runs — a site added,
	 * moved or removed between assembling a list and reading under it is a
	 * site the read would get wrong.
	 */
	private static function current_network_where( string $column ): string {
		global $wpdb;

		/*
		 * The table name comes from this installation's own configuration and
		 * the network id is cast to an integer, so nothing a request can
		 * reach enters the string. It is assembled rather than bound because
		 * every caller splices it into a statement of its own and prepares
		 * that; the registry's own column is named in full because the outer
		 * table has a `site_id` of its own meaning something else entirely.
		 */
		$mine = $column . ' IN ( SELECT blog_id FROM ' . $wpdb->blogs . ' WHERE ' . $wpdb->blogs . '.site_id = ' . (int) get_current_network_id() . ' )';

		if ( ! self::legacy_rows_are_here() ) {
			return $mine;
		}

		return '( ' . $column . ' = 0 OR ' . $mine . ' )';
	}

	/**
	 * Whether `site_id = 0` names rows of *this* network's main site.
	 *
	 * Zero is what the site whose own tables are the base-prefix tables wrote
	 * before the network tables existed, and an installation has one such
	 * site. A second network's main site has an ordinary blog prefix and its
	 * history arrives carrying its blog id, so none of the zero rows is its —
	 * reading them under its predicate would hand it another network's log.
	 */
	private static function legacy_rows_are_here(): bool {
		global $wpdb;

		return $wpdb->get_blog_prefix( (int) get_main_site_id() ) === $wpdb->base_prefix;
	}

	/**
	 * Whether a capability's table and columns are there to be written to.
	 *
	 * Answers from the stamp that covers the table that answers here: the
	 * network's for a network table, this blog's for the rest. The first form
	 * of a per-capability readiness map; a stamp that outran the schema is
	 * the failure both stamps exist to prevent.
	 */
	public static function ready( string $capability ): bool {
		$state = self::readiness_for( $capability );

		if ( null !== $state ) {
			return $state['ready'];
		}

		// Nothing recorded: a site upgrading from a version that stamped only
		// an integer, until its first install runs. The version comparison is
		// what that site has, and answering "degraded" from an absent map
		// would stop every writer on the strength of a record nobody has
		// written yet.
		$table = self::CAPABILITY_TABLE[ $capability ] ?? $capability;

		if ( self::is_network_table_here( $table ) ) {
			return self::network_current() >= max( 9, self::CAPABILITY_VERSION[ $capability ] ?? 9 );
		}

		return self::current() >= ( self::CAPABILITY_VERSION[ $capability ] ?? self::VERSION );
	}

	/**
	 * The per-capability record for the tables at this site's own prefix.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function readiness(): array {
		$recorded = get_option( self::READINESS_OPTION, array() );

		return is_array( $recorded ) ? $recorded : array();
	}

	/**
	 * The same, for the tables the network shares. Empty off a network, where
	 * there is no second record to consult.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function network_readiness(): array {
		if ( ! is_multisite() ) {
			return array();
		}

		$capabilities = self::network_record()['capabilities'] ?? array();

		return is_array( $capabilities ) ? $capabilities : array();
	}

	/**
	 * What the map holds for one capability, read from whichever record covers
	 * the table that answers here, or null where nothing has been recorded.
	 *
	 * @return array{ready: bool, reason: string, stamped_at: string}|null
	 */
	public static function readiness_for( string $capability ): ?array {
		$table = self::CAPABILITY_TABLE[ $capability ] ?? $capability;
		$map   = self::is_network_table_here( $table ) ? self::network_readiness() : self::readiness();

		if ( ! isset( $map[ $capability ] ) || ! is_array( $map[ $capability ] ) ) {
			return null;
		}

		$state = $map[ $capability ];

		return array(
			'ready'      => (bool) ( $state['ready'] ?? false ),
			'reason'     => (string) ( $state['reason'] ?? '' ),
			'stamped_at' => (string) ( $state['stamped_at'] ?? '' ),
		);
	}

	/**
	 * Every capability the map covers, in the order the migration proves them.
	 *
	 * @return string[]
	 */
	public static function capabilities(): array {
		return array_keys( self::capability_proofs() );
	}

	/**
	 * The network option as last read, for the request.
	 *
	 * Sitemeta has no autoload flag, so this read is a row on the first ask of
	 * each request — and `ready()` is asked on the write path, once per writer.
	 * Held for the request so a network pays for it once, the way the state
	 * beside it is. The whole row rather than the version alone: the version
	 * and the readiness map are two readers of one option.
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $network_record = null;

	/**
	 * @return array<string, mixed>
	 */
	private static function network_record(): array {
		if ( null !== self::$network_record ) {
			return self::$network_record;
		}

		$recorded = get_site_option( self::NETWORK_OPTION, array() );

		self::$network_record = is_array( $recorded ) ? $recorded : array();

		return self::$network_record;
	}

	/**
	 * The recorded version of the network tables, for the whole network.
	 */
	public static function network_current(): int {
		if ( ! is_multisite() ) {
			return self::current();
		}

		return (int) ( self::network_record()['version'] ?? 0 );
	}

	/**
	 * Forget the request's copy of the network stamp, so the next read asks
	 * the database. For the installer, which has just changed it, and for a
	 * test that arranges a network mid-upgrade.
	 */
	public static function forget_network_stamp(): void {
		self::$network_record = null;
	}

	/**
	 * Create or update all tables. Safe to run repeatedly: dbDelta is
	 * additive and only applies missing pieces.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		foreach ( self::table_definitions( $wpdb->get_charset_collate() ) as $sql ) {
			dbDelta( $sql );
		}

		// On a network the four shared tables exist once, at the base prefix,
		// whichever site is installing: a subsite still writing to its own
		// table needs the network's to be there when its rows are carried
		// over. On the main site this names the tables just created.
		if ( is_multisite() ) {
			foreach ( self::table_definitions( $wpdb->get_charset_collate(), true ) as $sql ) {
				dbDelta( $sql );
			}

			$recorded                 = self::network_record();
			$recorded['capabilities'] = self::stamped(
				is_array( $recorded['capabilities'] ?? null ) ? $recorded['capabilities'] : array(),
				self::measure( true )
			);

			// The version still means what it always did — every shared table
			// is there — and is still withheld until it is. The map beside it
			// says which of them are, so one absent table narrows one writer.
			if ( self::network_tables_present() ) {
				$recorded['version']    = self::VERSION;
				$recorded['stamped_at'] = gmdate( 'Y-m-d H:i:s' );
			}

			update_site_option( self::NETWORK_OPTION, $recorded );
			self::forget_network_stamp();
		}

		self::narrow_credential_id();

		// Not schema, but it is a migration and this is where migrations run:
		// a row written before its option required autoload costs a query on
		// every front-end page view until something happens to rewrite it, and
		// an option a site never used costs one for being absent.
		\BetterShield\Support\HotOptions::seed();

		// The map is written whichever way the proofs went, because it is the
		// record of what a writer may still do while the stamp is withheld: a
		// migration that could not finish is exactly when something has to say
		// which parts of the product are still working.
		//
		// Tiny array read on every admin request, beside the version and for
		// the same reason: autoloading is correct here.
		update_option( self::READINESS_OPTION, self::stamped( self::readiness(), self::measure( false ) ), true );

		// The version is stamped only when the schema it names is really
		// there. dbDelta reports rather than throws, and an ALTER refused by
		// a locked table or a missing privilege would otherwise leave the
		// version claiming a column every INSERT then fails to find — every
		// event lost, silently, until someone noticed. Unstamped, the next
		// boot tries again, and the writer knows to leave the column out.
		if ( self::schema_is_present() ) {
			// Tiny integer read on every admin request: autoloading is correct here.
			update_option( self::OPTION, self::VERSION, true );

			/*
			 * Not schema either, and here for the reason the hot options are:
			 * an update reaches this before anybody opens a screen. The
			 * cloud-metadata block is on from the update that brings it, once,
			 * and only where its undo record has a table to go in. Applying an
			 * item reads its translated definition, which waits for init.
			 */
			if ( Pruner::updated_from_earlier_build() ) {
				if ( did_action( 'init' ) ) {
					\BetterShield\Hardening\Item\CloudMetadata::seed();
				} else {
					add_action( 'init', array( \BetterShield\Hardening\Item\CloudMetadata::class, 'seed' ), 20 );
				}
			}
		}
	}

	/**
	 * Run the migration again now, because somebody asked.
	 *
	 * The hourly back-off exists so a database that cannot create a table is
	 * not asked once per request; a person waiting in front of a button is not
	 * that, and an hour they cannot see is not an answer. Additive like every
	 * other run of the installer — dbDelta creates what is missing and leaves
	 * what is there — so there is nothing here to undo.
	 */
	public static function retry_migration(): void {
		delete_transient( 'bettershield_schema_retry' );
		self::forget_repair_state();
		self::install();
	}

	/**
	 * What each capability's readiness is proved by.
	 *
	 * The same proofs the version stamp has always been gated on, named one at
	 * a time instead of collapsed into a single answer. A capability that is a
	 * table of its own is proved by the table; one that arrived as a column or
	 * as an index on a table that already existed names that column or index,
	 * because a table present at the wrong shape loses every row an INSERT
	 * gives it just as completely as a table that is not there.
	 *
	 * Every migration adds its own proof here rather than trusting the last
	 * one.
	 *
	 * @return array<string, array{table: string, column?: string, index?: string, columns?: string[]}>
	 */
	private static function capability_proofs(): array {
		return array(
			'events'             => array( 'table' => 'events' ),
			'entry_path'         => array( 'table' => 'events', 'column' => 'entry_path' ),
			'findings'           => array( 'table' => 'findings' ),
			'login_attempts'     => array( 'table' => 'login_attempts' ),
			'lockouts'           => array( 'table' => 'lockouts' ),
			'undo'               => array( 'table' => 'undo' ),
			'observed_changes'   => array( 'table' => 'undo', 'index' => 'idx_action_id', 'columns' => array( 'action_key', 'id' ) ),
			'integrity_baseline' => array( 'table' => 'integrity_baseline' ),
			'integrity_changes'  => array( 'table' => 'integrity_changes' ),
			'passkeys'           => array( 'table' => 'passkeys' ),
			'passkey_verification' => array( 'table' => 'passkeys', 'column' => 'user_verified' ),
			'passkey_discoverable' => array( 'table' => 'passkeys', 'column' => 'discoverable' ),
			'claims'             => array( 'table' => 'claims' ),
			'agent_invocations'  => array( 'table' => 'agent_invocations' ),
			'invocation_connection' => array( 'table' => 'agent_invocations', 'column' => 'connection' ),
			'incidents'          => array( 'table' => 'incidents' ),
			'incident_evidence'  => array( 'table' => 'incident_evidence' ),
			'write_proposals'    => array( 'table' => 'write_proposals' ),
		);
	}

	/**
	 * Prove every capability that belongs to one of the two records, once.
	 *
	 * The network record covers the four tables a network shares, wherever the
	 * site asking happens to be in the carry-over; the site's own record covers
	 * everything that answers at its prefix, which is the same four until its
	 * rows have moved.
	 *
	 * @return array<string, array{ready: bool, reason: string}>
	 */
	private static function measure( bool $network ): array {
		$measured = array();

		foreach ( self::capability_proofs() as $capability => $proof ) {
			$shared = in_array( $proof['table'], self::NETWORK_TABLES, true );

			if ( $network ? ! $shared : self::is_network_table_here( $proof['table'] ) ) {
				continue;
			}

			$reason = self::prove( $proof, $network );

			$measured[ $capability ] = array(
				'ready'  => '' === $reason,
				'reason' => $reason,
			);
		}

		return $measured;
	}

	/**
	 * Prove one capability, and say why in plain words when it fails.
	 *
	 * The reason is what the database said wherever the database said anything
	 * — a refused privilege or a table it cannot open tells the owner far more
	 * than "missing" does — and a plain sentence naming what is not there
	 * otherwise. It is recorded untranslated because it is a quotation, and a
	 * translated copy would be frozen in whatever language the migration
	 * happened to run in.
	 *
	 * @param array{table: string, column?: string, index?: string, columns?: string[]} $proof
	 * @return string The reason it failed, or an empty string when it passed.
	 */
	private static function prove( array $proof, bool $network ): string {
		global $wpdb;

		$table = $network ? self::network_table( $proof['table'] ) : self::table( $proof['table'] );

		if ( ! self::table_exists( $table ) ) {
			return self::database_said() ?? 'Table ' . $table . ' is missing.';
		}

		if ( isset( $proof['column'] ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection at install time.
			$columns = (array) $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', $table ) );

			if ( ! in_array( $proof['column'], $columns, true ) ) {
				return self::database_said() ?? 'Column ' . $proof['column'] . ' is missing from table ' . $table . '.';
			}
		}

		if ( isset( $proof['index'] ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection at install time.
			$rows = $wpdb->get_results( $wpdb->prepare( 'SHOW INDEX FROM %i WHERE Key_name=%s', $table, $proof['index'] ), ARRAY_A );

			if ( ! is_array( $rows ) ) {
				return self::database_said() ?? 'Index ' . $proof['index'] . ' could not be read on table ' . $table . '.';
			}

			$said = self::database_said();

			if ( null !== $said ) {
				return $said;
			}

			usort( $rows, static fn( $a, $b ) => (int) $a['Seq_in_index'] <=> (int) $b['Seq_in_index'] );

			if ( array_column( $rows, 'Column_name' ) !== ( $proof['columns'] ?? array() ) ) {
				return 'Index ' . $proof['index'] . ' is missing from table ' . $table . '.';
			}
		}

		return '';
	}

	/** What the database said about the statement just run, where it said anything. */
	private static function database_said(): ?string {
		global $wpdb;

		$said = (string) $wpdb->last_error;

		return '' === $said ? null : $said;
	}

	/**
	 * Merge a measurement into the record, keeping the moment each capability
	 * entered the state it is in.
	 *
	 * `stamped_at` moves only when the answer changes, which is what makes it
	 * a "since". Rewritten on every proof, a capability that has been down for
	 * a week would read as having failed a moment ago on every boot, and
	 * nothing watching for one that stays down could ever see an hour pass.
	 *
	 * @param array<string, mixed>                             $recorded
	 * @param array<string, array{ready: bool, reason: string}> $measured
	 * @return array<string, array{ready: bool, reason: string, stamped_at: string}>
	 */
	private static function stamped( array $recorded, array $measured ): array {
		$now    = gmdate( 'Y-m-d H:i:s' );
		$record = array();

		foreach ( $measured as $capability => $state ) {
			$was     = isset( $recorded[ $capability ]['ready'] ) ? (bool) $recorded[ $capability ]['ready'] : null;
			$stamped = (string) ( $recorded[ $capability ]['stamped_at'] ?? '' );

			$record[ $capability ] = array(
				'ready'      => $state['ready'],
				'reason'     => $state['reason'],
				'stamped_at' => $was === $state['ready'] && '' !== $stamped ? $stamped : $now,
			);
		}

		return $record;
	}

	/**
	 * Whether the schema this version claims is really on disk.
	 *
	 * Every capability's proof, over the tables that answer at this site's
	 * prefix: the stamp says "version 4", and version 4 means the entry_path
	 * column *and* both integrity tables. A stamp that outruns the schema is
	 * the failure this exists to prevent — an INSERT naming a column the table
	 * does not have loses every row it was given, silently.
	 *
	 * One answer for the whole schema is still what the stamp needs, and it is
	 * still all it may say: which capabilities are usable while the stamp is
	 * withheld is the map's question, not this one's.
	 */
	private static function schema_is_present(): bool {
		foreach ( self::capability_proofs() as $proof ) {
			if ( '' !== self::prove( $proof, false ) ) {
				return false;
			}
		}

		return true;
	}

	private static function network_tables_present(): bool {
		foreach ( self::NETWORK_TABLES as $name ) {
			if ( ! self::table_exists( self::network_table( $name ) ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Bring an existing passkeys table's `credential_id` to ASCII.
	 *
	 * dbDelta compares column definitions without their character set, so it
	 * will not migrate a column whose only change is its charset — a table
	 * created before this was declared keeps utf8mb4 and its 1020-byte unique
	 * index. That is harmless where the table created at all (a modern server
	 * allows 3072), but it leaves the column comparing case-insensitively,
	 * which is wrong for a base64url credential id: two ids differing only in
	 * case are two credentials, and were being treated as one.
	 *
	 * Forward-only and non-destructive: ASCII is a subset of utf8mb4 and every
	 * value in this column is already base64url, so no byte changes.
	 */
	private static function narrow_credential_id(): void {
		global $wpdb;

		$table = self::table( 'passkeys' );

		if ( ! self::table_exists( $table ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection at install time.
		$collation = (string) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COLLATION_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s',
				$table,
				'credential_id'
			)
		);

		if ( 'ascii_bin' === $collation || '' === $collation ) {
			return;
		}

		/*
		 * `%i` is the identifier placeholder, so the table name goes through
		 * prepare() like every other query in this file rather than being
		 * concatenated. Nothing here is user-supplied — the name is built from
		 * `$wpdb->prefix` — but a static checker cannot see that, and neither
		 * can the next person reading it.
		 */
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- a schema migration is the one thing that must change a schema, on this plugin's own table, at install time.
		$wpdb->query(
			$wpdb->prepare( 'ALTER TABLE %i MODIFY `credential_id` varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL', $table )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
	}

	private static function table_exists( string $table ): bool {
		global $wpdb;

		// Escaped because `_` is a wildcard to LIKE: `wp_7_` also matches another
		// prefix's `wp67_`, and the first row answering was then the wrong table.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection at install time.
		return (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	/**
	 * The recorded schema version, as the writer and others reason about it.
	 */
	public static function current(): int {
		return (int) get_option( self::OPTION, 0 );
	}

	/**
	 * Cheap version gate, hooked on admin_init, so plugin updates migrate
	 * without requiring a re-activation.
	 */
	public static function maybe_upgrade(): void {
		if ( (int) get_option( self::OPTION, 0 ) >= self::VERSION ) {
			return;
		}

		// A migration that could not complete is retried hourly, not on every
		// request: dbDelta introspects every table each time it runs.
		if ( false !== get_transient( 'bettershield_schema_retry' ) ) {
			return;
		}

		self::install();

		if ( (int) get_option( self::OPTION, 0 ) < self::VERSION ) {
			set_transient( 'bettershield_schema_retry', '1', HOUR_IN_SECONDS );
		}
	}

	/**
	 * What this request has already tried to repair, and what it found.
	 *
	 * @var array<string, bool>
	 */
	private static array $repaired = array();

	/**
	 * Put a capability's table back when something reached for it and it was
	 * not there, and answer whether it is there now.
	 *
	 * A table can go missing after the migration as well as before it: a
	 * restore from a partial dump, a host moving a site, a table removed by
	 * hand. The caps that stand in front of a credential cannot do their work
	 * without one and refuse rather than admitting everybody, so waiting for
	 * the next admin page load means refusing sign-ins until somebody happens
	 * to open the dashboard.
	 *
	 * `install()` is additive — dbDelta creates what is missing and leaves
	 * what is there — so this is the same migration the boot runs, asked for
	 * early by whoever needed it. It is bounded twice. Once per request,
	 * because dbDelta introspects every table this plugin owns and one sign-in
	 * must not pay for that once per cap it consults. And once per ten minutes
	 * for the site, through the same back-off a migration that could not
	 * complete already sets, so a database that will not create tables is
	 * asked a few times an hour rather than on every request.
	 *
	 * Returning false is not a failure to report: the caller asked because its
	 * statement had already failed, and it is the caller that decides what to
	 * do about it.
	 */
	public static function repair( string $capability ): bool {
		$table = self::CAPABILITY_TABLE[ $capability ] ?? $capability;
		$name  = self::is_network_table_here( $table ) ? self::network_table( $table ) : self::table( $table );

		if ( self::ready( $capability ) && self::table_exists( $name ) ) {
			return true;
		}

		if ( isset( self::$repaired[ $capability ] ) ) {
			return self::$repaired[ $capability ];
		}

		// Recorded before the installer runs rather than after it, so a
		// migration that reaches back in here answers from the record instead
		// of starting a second one.
		self::$repaired[ $capability ] = false;

		if ( false !== get_transient( 'bettershield_schema_retry' ) ) {
			return false;
		}

		set_transient( 'bettershield_schema_retry', '1', 10 * MINUTE_IN_SECONDS );

		self::install();

		self::$repaired[ $capability ] = self::table_exists( $name );

		return self::$repaired[ $capability ];
	}

	/**
	 * Forget what this request already tried to repair. Production never needs
	 * this — the record lives and dies with the request — but the test process
	 * is many requests in one lifetime.
	 */
	public static function forget_repair_state(): void {
		self::$repaired = array();
	}

	/**
	 * CREATE TABLE statements in dbDelta's expected format.
	 *
	 * Conventions:
	 * - Integer columns carry a display width (`int(10) unsigned`,
	 *   `tinyint(3) unsigned`), the way core's own tables do. dbDelta decides
	 *   whether to rewrite a column by comparing the declared type with the
	 *   one the server reports, and MariaDB and MySQL before 8.0.17 report
	 *   the width; declared without one, every one of these columns was
	 *   rewritten on every install, on every such server.
	 * - datetime(3): explicit UTC written by the callers, millisecond
	 *   precision, no server-timezone conversion and no 2038 limit.
	 * - Structured payload columns (context, evidence, prior_state) hold
	 *   JSON encoded as longtext for broad database compatibility.
	 * - Anything worth filtering has its own indexed column; payload
	 *   columns are for display and forensics, never for queries.
	 *
	 * @return string[]
	 */
	private static function table_definitions( string $charset_collate, bool $network = false ): array {
		// With $network, the four shared tables are named at the base prefix
		// whatever this site's migration state, and only those four are
		// returned.
		$name = static function ( string $short ) use ( $network ): string {
			return $network ? self::network_table( $short ) : self::table( $short );
		};

		$events   = $name( 'events' );
		$findings = $name( 'findings' );
		$undo     = $name( 'undo' );
		$attempts = $name( 'login_attempts' );
		$lockouts = $name( 'lockouts' );
		$baseline = $name( 'integrity_baseline' );
		$changes  = $name( 'integrity_changes' );
		$passkeys = $name( 'passkeys' );
		$claims   = $name( 'claims' );
		$agents   = $name( 'agent_invocations' );
		$incidents = $name( 'incidents' );
		$evidence = $name( 'incident_evidence' );
		$proposals = $name( 'write_proposals' );

		$shared = array( $events, $findings, $passkeys, $agents );

		$definitions = array(
			"CREATE TABLE {$incidents} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				anchor_key char(64) NOT NULL,
				status varchar(16) NOT NULL DEFAULT 'new',
				opened_at datetime(3) NOT NULL,
				updated_at datetime(3) NOT NULL,
				resolved_at datetime(3) NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_anchor (anchor_key),
				KEY idx_status (status, updated_at)
			) {$charset_collate};",
			"CREATE TABLE {$evidence} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				source_key char(64) NOT NULL,
				subject_key char(64) NOT NULL DEFAULT '',
				incident_id bigint(20) unsigned NOT NULL DEFAULT 0,
				occurred_at datetime(3) NOT NULL,
				anchor varchar(16) NOT NULL DEFAULT '',
				actor_id bigint(20) unsigned NOT NULL DEFAULT 0,
				event_type varchar(64) NOT NULL,
				relation varchar(16) NOT NULL DEFAULT '',
				snapshot longtext NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_source (source_key),
				KEY idx_incident (incident_id, occurred_at, id),
				KEY idx_actor (actor_id, incident_id),
				KEY idx_subject (subject_key, incident_id)
			) {$charset_collate};",


			// Attempts, at full address precision without storing an address:
			// ip_hmac is a keyed digest that matches exactly and cannot be
			// reversed without the key, which is why an ended lockout's digest
			// is blanked; ip_prefix is the same truncated form the events
			// table stores, for display. Pruned aggressively — this is working
			// data for the lockout decision, not history; history is the
			// events table's job.
			//
			// `surface` is which form was being answered. It exists so that
			// counting is per surface and a flood on a public form can never
			// deepen a sign-in lockout — which is to say, can never cost the
			// owner their own dashboard. Rows written before it defaulted to
			// sign-ins because that is the only thing this table held.
			//
			// Deliberately no index carrying it. The filter runs after
			// (site_id, ip_hmac, occurred_at) has already narrowed to the
			// handful of rows one source wrote inside one window, so a fourth
			// column would buy nothing and be paid for on every write — and
			// these writes are on the sign-in path.
			"CREATE TABLE {$attempts} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				occurred_at datetime(3) NOT NULL,
				ip_hmac char(64) NOT NULL,
				ip_prefix varbinary(16) NULL,
				username varchar(60) NOT NULL DEFAULT '',
				outcome varchar(12) NOT NULL,
				method varchar(24) NOT NULL DEFAULT 'direct',
				surface varchar(16) NOT NULL DEFAULT 'signin',
				PRIMARY KEY  (id),
				KEY idx_ip_time (site_id, ip_hmac, occurred_at),
				KEY idx_time (site_id, occurred_at)
			) {$charset_collate};",

			// Lockouts, one row each, because a lockout is a thing the admin
			// screen shows and clears — not merely a count that emerges from
			// the attempts table. unlock_token_hash backs the emailed
			// unlock link; like the recovery token, only the hash is stored.
			"CREATE TABLE {$lockouts} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				ip_hmac char(64) NOT NULL,
				ip_prefix varbinary(16) NULL,
				started_at datetime(3) NOT NULL,
				expires_at datetime(3) NOT NULL,
				released_at datetime(3) NULL,
				release_reason varchar(32) NULL,
				attempts int(10) unsigned NOT NULL DEFAULT 0,
				last_username varchar(60) NOT NULL DEFAULT '',
				unlock_token_hash char(64) NULL,
				surface varchar(16) NOT NULL DEFAULT 'signin',
				PRIMARY KEY  (id),
				KEY idx_active (site_id, ip_hmac, expires_at),
				KEY idx_time (site_id, started_at, id)
			) {$charset_collate};",

			// Activity log. idx_time carries id as a tiebreaker so cursor
			// pagination stays stable when events share a millisecond.
			// actor_label is denormalized on write so the record survives
			// actor deletion. entry_path is which door the action came
			// through — the dashboard's REST calls, WP-CLI, or plain PHP such
			// as cron and hooks; rows written before the column existed read
			// 'unknown' rather than claiming a door.
			"CREATE TABLE {$events} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				occurred_at datetime(3) NOT NULL,
				event_type varchar(32) NOT NULL,
				severity tinyint(3) unsigned NOT NULL DEFAULT 0,
				actor_type varchar(16) NOT NULL,
				actor_id bigint(20) unsigned NULL,
				actor_label varchar(191) NULL,
				object_type varchar(32) NULL,
				object_id varchar(191) NULL,
				ip_prefix varbinary(16) NULL,
				context longtext NULL,
				entry_path varchar(16) NOT NULL DEFAULT 'unknown',
				PRIMARY KEY  (id),
				KEY idx_time (site_id, occurred_at, id),
				KEY idx_type_time (site_id, event_type, occurred_at),
				KEY idx_actor (site_id, actor_type, actor_id, occurred_at)
			) {$charset_collate};",

			// Audit findings with lifecycle, so scores are stable across
			// runs and "first seen" is meaningful. finding_key is a stable
			// string identifier, never a generated id.
			"CREATE TABLE {$findings} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				finding_key varchar(64) NOT NULL,
				severity tinyint(3) unsigned NOT NULL DEFAULT 0,
				status varchar(16) NOT NULL DEFAULT 'open',
				first_seen_at datetime(3) NOT NULL,
				last_seen_at datetime(3) NOT NULL,
				resolved_at datetime(3) NULL,
				evidence longtext NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_finding (site_id, finding_key)
			) {$charset_collate};",

			// Reversibility ledger. Rows are written before an action
			// executes so a crash mid-action still leaves a revert path.
			// prior_state captures enough to restore exactly. This table
			// is never pruned by retention: undo outlives log history.
			"CREATE TABLE {$undo} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				token char(32) NOT NULL,
				action_key varchar(64) NOT NULL,
				created_at datetime(3) NOT NULL,
				created_by bigint(20) unsigned NULL,
				prior_state longtext NOT NULL,
				applied_state longtext NOT NULL,
				reverted_at datetime(3) NULL,
				revert_failed_reason varchar(255) NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_token (token),
				KEY idx_action_id (action_key, id)
			) {$charset_collate};",

			/*
			 * What each file hashed to the last time it was checked, so a
			 * later run can tell a change from a first sighting.
			 *
			 * The path is indexed by its hash rather than directly: MySQL's
			 * index key length limit makes varchar(1024) unusable as a utf8mb4
			 * unique key, and paths are long.
			 *
			 * `algo` is a departure from the original design, forced by what
			 * WordPress actually publishes. Core checksums are MD5; plugin
			 * checksums carry SHA-256. Comparing a file means hashing it with
			 * whatever algorithm its source published, so the row has to say
			 * which one it used — a column of hashes that silently mixes two
			 * algorithms compares equal to nothing and unequal to everything.
			 */
			"CREATE TABLE {$baseline} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				path_hash char(64) NOT NULL,
				path varchar(1024) NOT NULL,
				context varchar(16) NOT NULL,
				slug varchar(191) NULL,
				version varchar(32) NULL,
				algo varchar(8) NOT NULL DEFAULT 'sha256',
				file_hash char(64) NOT NULL,
				file_size bigint(20) unsigned NOT NULL DEFAULT 0,
				recorded_at datetime(3) NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_path (site_id, path_hash),
				KEY idx_slug (site_id, context, slug)
			) {$charset_collate};",

			/*
			 * A file that no longer matches what its source published, or that
			 * is there when nothing published it, or gone when something did.
			 *
			 * Never the file's contents — this table holds paths, hashes and
			 * sizes, and a security record that copied the altered file into
			 * the database would become the thing worth stealing. `signals`
			 * holds which named signs of compromise an added file showed and
			 * on which line, never the bytes that matched.
			 */
			"CREATE TABLE {$changes} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				path_hash char(64) NOT NULL,
				path varchar(1024) NOT NULL,
				context varchar(16) NOT NULL,
				slug varchar(191) NULL,
				version varchar(32) NULL,
				detected_at datetime(3) NOT NULL,
				change_type varchar(16) NOT NULL,
				algo varchar(8) NOT NULL DEFAULT 'sha256',
				hash_before char(64) NULL,
				hash_after char(64) NULL,
				size_before bigint(20) unsigned NULL,
				size_after bigint(20) unsigned NULL,
				status varchar(16) NOT NULL DEFAULT 'new',
				unconfirmed_update tinyint(1) NOT NULL DEFAULT 0,
				signals varchar(255) NULL,
				PRIMARY KEY  (id),
				KEY idx_status_time (site_id, status, detected_at),
				KEY idx_path (site_id, path_hash)
			) {$charset_collate};",

			/*
			 * Enrolled passkeys, one row each.
			 *
			 * A table rather than user meta, because the lookup that matters
			 * runs the other way: a browser signing in without a username
			 * hands over a credential id and nothing else, and finding its
			 * owner has to be an indexed read rather than a scan of everyone's
			 * meta. `credential_id` is therefore unique and the entry point.
			 *
			 * `public_key` is exactly that — public. `sign_count` is the only
			 * mutable field, and it is what detects a cloned authenticator.
			 *
			 * `credential_id` is declared ASCII rather than inheriting the
			 * table's utf8mb4, for two reasons. A unique index over 255
			 * utf8mb4 characters needs 1020 bytes, which exceeds the 767-byte
			 * index limit on MySQL below 5.7.7 and MariaDB below 10.2 — still
			 * supported by the WordPress version this plugin requires, and
			 * common on budget hosts. There the table failed to create, the
			 * version stamp was never written because it is gated on that
			 * table existing, and every boot re-ran the whole schema install
			 * while passkeys stayed permanently unavailable.
			 *
			 * The value is base64url, so ASCII is not a compromise: 255 bytes
			 * fits everywhere. `ascii_bin` also compares exactly, where the
			 * table's default collation compares case-insensitively — two
			 * credential ids differing only in case are different credentials,
			 * and were being treated as the same one.
			 *
			 * `rp_id` records the relying party the credential was created
			 * under, because a credential cannot be re-scoped afterwards: the
			 * browser will only ever offer it for the domain it was made for.
			 * Where a host's credentials come to be shared across its sites,
			 * older rows and newer ones are two generations under two relying
			 * parties, and a check that compared one current value against
			 * both would either refuse the old or accept the wrong one. Rows
			 * written before the column read empty and are taken to belong to
			 * the host of the site they were enrolled on.
			 *
			 * The account leads the index rather than the site: a credential
			 * belongs to the account wherever it was enrolled, and the lookup
			 * that matters is "this account's credentials", with the site as a
			 * tiebreaker. An index named `idx_user` in the older column order
			 * may still be on disk — dbDelta only ever adds, so an index is
			 * redefined under a new name rather than rewritten in place, and
			 * this table drops nothing.
			 */
			"CREATE TABLE {$passkeys} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				user_id bigint(20) unsigned NOT NULL,
				credential_id varchar(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				public_key text NOT NULL,
				algorithm int(11) NOT NULL,
				sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
				user_verified tinyint(1) unsigned NULL DEFAULT NULL,
				discoverable tinyint(1) unsigned NULL DEFAULT NULL,
				transports varchar(191) NOT NULL DEFAULT '',
				label varchar(191) NOT NULL DEFAULT '',
				rp_id varchar(191) NOT NULL DEFAULT '',
				created_at datetime(3) NOT NULL,
				last_used_at datetime(3) NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_credential (credential_id),
				KEY idx_user_site (user_id, site_id)
			) {$charset_collate};",

			/*
			 * Claims: which request goes first. `uq_claim` is the whole point
			 * of the table — it is what refuses the second INSERT, and every
			 * guarantee `Support\Claim` offers rests on the database enforcing
			 * it rather than on any code here checking first.
			 *
			 * Keys are built by this plugin from slugs and hex digests, so
			 * ascii_bin is no compromise and compares exactly, where the
			 * table's own collation would make two keys differing in case the
			 * same key.
			 */
			"CREATE TABLE {$claims} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				claim_key varchar(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				count int(10) unsigned NOT NULL DEFAULT 1,
				created_at datetime(3) NOT NULL,
				expires_at datetime(3) NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_claim (claim_key),
				KEY idx_expiry (expires_at)
			) {$charset_collate};",

			/*
			 * What an agent asked to change, and the one confirmation a person
			 * may mint against it.
			 *
			 * Per site rather than per network, like the claims table above:
			 * the thing being proposed is one site's own protection, and the
			 * person who confirms it is confirming it here.
			 *
			 * `token_hash` is the SHA-256 of a confirmation shown once and
			 * stored never; `uq_token` is what makes spending it a single
			 * statement, so two requests carrying the same string cannot both
			 * find it unspent. `plan` holds exactly the object the proposal
			 * returned, so what is confirmed is what was read rather than a
			 * recomputation of it, and `state_digest` is what the execution
			 * compares against live state before anything changes.
			 *
			 * `proposed_correlation` and `spent_correlation` join the two
			 * halves of the story to the invocation record: which call asked,
			 * and which call carried the answer.
			 */
			"CREATE TABLE {$proposals} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				ability varchar(64) NOT NULL,
				target varchar(191) NOT NULL,
				target_type varchar(32) NOT NULL,
				plan longtext NOT NULL,
				state_digest char(64) NOT NULL,
				proposed_by bigint(20) unsigned NOT NULL DEFAULT 0,
				proposed_at datetime(3) NOT NULL,
				proposed_correlation varchar(64) NULL,
				expires_at datetime(3) NOT NULL,
				token_hash char(64) NULL,
				minted_by bigint(20) unsigned NULL,
				minted_at datetime(3) NULL,
				minted_with_sudo tinyint(1) NOT NULL DEFAULT 0,
				spent_at datetime(3) NULL,
				spent_correlation varchar(64) NULL,
				withdrawn_at datetime(3) NULL,
				outcome varchar(64) NULL,
				undo_token varchar(64) NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_token (token_hash),
				KEY idx_expiry (expires_at),
				KEY idx_proposed (proposed_at)
			) {$charset_collate};",

			/*
			 * What the Abilities API was asked to do on this site, by anyone,
			 * for any ability — not only ours.
			 *
			 * Its own table rather than a row in `events`: the volume profile
			 * is different and potentially far higher, the retention differs,
			 * and the columns worth an index here are ones the events table
			 * has no use for.
			 *
			 * `correlation_id` is written once, not updated. The lifecycle is
			 * followed in memory for the length of the request and the row is
			 * written when its outcome is known, so there is no `pending`
			 * state on disk to be updated later — one INSERT per request for
			 * every invocation in it. The unique key is what makes that safe:
			 * a buffer flushed twice writes the row once.
			 *
			 * `error_code` is a column of its own rather than part of
			 * `outcome`. Folding the code into the outcome would give the
			 * column unbounded cardinality and cost `idx_outcome` its whole
			 * purpose, which is answering "what was refused" quickly — the
			 * highest-value query in this table.
			 *
			 * `input_digest` is a keyed SHA-256 of the normalized input and
			 * never the input. Ability inputs may carry secrets, and an
			 * unkeyed hash over a small set of them reverses by guessing.
			 */
			"CREATE TABLE {$agents} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				site_id bigint(20) unsigned NOT NULL DEFAULT 0,
				invoked_at datetime(3) NOT NULL,
				correlation_id char(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
				ability_name varchar(191) NOT NULL,
				registering_plugin varchar(191) NULL,
				entry_path varchar(16) NOT NULL,
				user_id bigint(20) unsigned NULL,
				outcome varchar(24) NOT NULL DEFAULT 'unknown',
				error_code varchar(64) NULL,
				input_digest char(64) NULL,
				duration_ms int(10) unsigned NULL,
				connection varchar(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uq_correlation (correlation_id),
				KEY idx_time (site_id, invoked_at, id),
				KEY idx_ability (site_id, ability_name, invoked_at),
				KEY idx_outcome (site_id, outcome, invoked_at),
				KEY idx_connection (site_id, connection, invoked_at)
			) {$charset_collate};",
		);

		if ( ! $network ) {
			return $definitions;
		}

		return array_values(
			array_filter(
				$definitions,
				static function ( string $sql ) use ( $shared ): bool {
					return 1 === preg_match( '/CREATE TABLE (\S+)/', $sql, $m ) && in_array( $m[1], $shared, true );
				}
			)
		);
	}
}
