<?php
/**
 * Where each site of a network stands in the move to the shared tables.
 *
 * The state, and nothing else: which sites have been switched to the network
 * table for which table, and how far the copy has got. The task that does the
 * copying reads and writes this; every `Schema::table()` call reads it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Database;

use BetterShield\Events\Seal;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkMigration {

	/** The network option that carries the whole state. */
	public const OPTION = 'bettershield_network_migration';

	/**
	 * The scheduled task that runs the copy.
	 *
	 * The same word as the option above, which is a coincidence of subject
	 * rather than a link: one is a row in sitemeta, the other a hook name.
	 */
	public const TASK = 'bettershield_network_migration';

	public const STATUS_PENDING  = 'pending';
	public const STATUS_RUNNING  = 'running';
	public const STATUS_COMPLETE = 'complete';

	/** How many sites one page of the walk asks for. */
	private const SITES_PER_PAGE = 200;

	/** How many rows one copy statement moves. */
	private const BATCH = 1000;

	/**
	 * The shortest a tick may hold the copy for, in seconds.
	 *
	 * The key is given back in a `finally`, so this only governs a tick that
	 * did not come back at all — a worker recycled mid-deploy, a fatal. It
	 * is well short of the hourly cadence, so the next tick picks the copy up
	 * rather than waiting out a holder that no longer exists.
	 */
	private const CLAIM_FLOOR_SECONDS = 300;

	/**
	 * The tables whose unique keys reject a row that is already there, so a
	 * row already carried over — by a run the clock cut short between the copy
	 * and the cursor write — must be stepped over rather than reject the batch
	 * it traveled in.
	 *
	 * Two of those keys are global and one is per site: a finding is unique on
	 * the site and the finding's key together, which is exactly what a second
	 * copy of one site's rows collides on, so the key set is about what a
	 * repeat of *this* copy would hit rather than about the key's scope. The
	 * activity log has no such key at all and cannot be protected this way;
	 * what keeps a batch of it from arriving twice is the transaction the
	 * batch and its cursor travel in together.
	 *
	 * @var string[]
	 */
	private const IGNORE_DUPLICATES = array( 'findings', 'agent_invocations', 'passkeys' );

	/**
	 * The state as last read, for the request. One option read per request
	 * rather than one per table-name resolution.
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $memo = null;

	/**
	 * Whether the named table answers at the base prefix on this site.
	 *
	 * The main site's tables have always been the base-prefix tables, so it
	 * is switched by construction. A subsite is switched once its copy of
	 * that table has finished, and never before: until then its own table
	 * holds its log, and the network table holds none of it.
	 */
	public static function uses_network_table( string $table ): bool {
		if ( ! is_multisite() ) {
			return false;
		}

		if ( is_main_site() ) {
			return true;
		}

		$state = self::state();

		return ! empty( $state['switched'][ (string) get_current_blog_id() ][ $table ] );
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		if ( null !== self::$memo ) {
			return self::$memo;
		}

		$stored = is_multisite() ? get_site_option( self::OPTION, array() ) : array();

		self::$memo = is_array( $stored ) ? array_merge( self::defaults(), $stored ) : self::defaults();

		return self::$memo;
	}

	/**
	 * Record that a site's rows for a table now live in the network table.
	 *
	 * Written before the remaining rows are drained, on purpose: the next row
	 * the site writes goes to the network table, and the old table only ever
	 * stops growing from here.
	 */
	public static function mark_switched( int $blog_id, string $table ): void {
		$state = self::state();

		$state['switched'][ (string) $blog_id ][ $table ] = true;

		self::save( $state );
	}

	/**
	 * Whether every site has been switched for every network table.
	 */
	public static function is_complete(): bool {
		return self::STATUS_COMPLETE === ( self::state()['status'] ?? '' );
	}

	/** Queue a provisioned site before its first audit writes local history. */
	public static function enroll_current_site(): void {
		if ( ! is_multisite() || Schema::network_current() < 9 ) {
			return;
		}
		self::forget();
		if ( self::is_complete() && ! self::site_is_done( get_current_blog_id() ) ) {
			self::reopen();
		}
	}

	private static function reopen(): void {
		$state = self::state();
		$state['status'] = self::STATUS_PENDING;
		$state['finished_at'] = '';
		self::save( $state );
	}

	/**
	 * A deleted site leaves the copy's record.
	 *
	 * Its entries stayed behind, and every one still counted as a site
	 * carried over, so a network that had lost sites read "8 of 4". The total
	 * is counted again without it: this runs while the site is being
	 * removed, before its row is gone.
	 */
	public static function forget_site( int $blog_id ): void {
		if ( ! is_multisite() || $blog_id <= 0 ) {
			return;
		}

		self::forget();

		$state = self::state();

		foreach ( array( 'switched', 'resealed', 'verdict', 'failing' ) as $part ) {
			unset( $state[ $part ][ (string) $blog_id ] );
		}

		if ( (int) ( $state['current']['blog_id'] ?? 0 ) === $blog_id ) {
			$state['current'] = array();
		}

		self::save( $state );

		$state['sites_done'] = self::sites_switched();

		if ( (int) $state['sites_total'] > 0 ) {
			// A count rather than a walk, as the tick's: no site is read, so
			// there is nothing to page through and nothing that could be capped.
			$state['sites_total'] = (int) get_sites(
				array(
					'count'        => true,
					'network_id'   => get_current_network_id(),
					'site__not_in' => array( $blog_id ),
				)
			);
		}

		self::save( $state );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function save( array $state ): void {
		self::$memo = array_merge( self::defaults(), $state );

		if ( is_multisite() ) {
			update_site_option( self::OPTION, self::$memo );
		}
	}

	/**
	 * Forget the request's copy of the state, so the next read asks the
	 * database. For the copy task between batches, and for tests.
	 *
	 * The cached copy of the option is dropped with it, which is what makes
	 * "asks the database" true where a persistent object cache is installed.
	 * A batch writes its cursor into the option row directly, inside the
	 * transaction it shares with the rows, so on a request that died before
	 * the cache was brought back into line the cached copy names an earlier
	 * cursor than the one that was committed. Resuming from that copy would
	 * copy a batch that is already there.
	 */
	public static function forget(): void {
		self::$memo = null;

		if ( ! is_multisite() ) {
			return;
		}

		$network_id = get_current_network_id();

		wp_cache_delete( $network_id . ':' . self::OPTION, 'site-options' );
		wp_cache_delete( $network_id . ':notoptions', 'site-options' );
	}

	/**
	 * Whether this site is the one that keeps the copy's appointment.
	 *
	 * wp-cron stores a schedule per site. Registered on every site's boot,
	 * the hourly task was scheduled on every subsite as well, so any two
	 * subsites taking traffic in the same window each ran it — against one
	 * cursor, one network option and one set of shared tables. A network has
	 * exactly one main site, which is the one place to keep the appointment.
	 */
	public static function schedules_here(): bool {
		return is_multisite() && is_main_site();
	}

	/**
	 * Drop an appointment a subsite made for itself under an earlier version,
	 * where nothing answers the hook any more.
	 */
	public static function unschedule_here(): void {
		if ( false !== wp_next_scheduled( self::TASK ) ) {
			wp_clear_scheduled_hook( self::TASK );
		}
	}

	/**
	 * The key one tick holds while it is copying.
	 *
	 * Named for the network: what it guards is one network option and one set
	 * of base-prefix tables, and an installation can carry more than one
	 * network over the same prefix.
	 */
	public static function claim_key(): string {
		return 'network_migration_' . get_current_network_id();
	}

	/**
	 * Take the copy for this network, or answer that somebody else holds it.
	 *
	 * A claim is recorded in the claiming site's own table, so one taken on a
	 * subsite arbitrates nothing. Taken on the network's main site, every
	 * site of the network competes for the same row — the same reason the
	 * network's undo list is read there.
	 */
	private static function claim_tick( float $budget ): bool {
		switch_to_blog( (int) get_main_site_id() );

		try {
			return Claim::claim( self::claim_key(), max( self::CLAIM_FLOOR_SECONDS, (int) ceil( $budget ) * 2 ) );
		} finally {
			restore_current_blog();
		}
	}

	/** Give the copy back, from wherever the tick ended up. */
	private static function release_tick(): void {
		switch_to_blog( (int) get_main_site_id() );

		try {
			Claim::release( self::claim_key() );
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * One bounded tick of the copy.
	 *
	 * Nothing is dropped and nothing is rewritten: rows are copied into the
	 * network table with the blog id they belong to, the blog table keeps
	 * every row it had, and a tick that runs out of clock leaves a cursor for
	 * the next one. The task runner calls this hourly while it is incomplete.
	 *
	 * The order inside a site matters. A table is marked switched *before* the
	 * last rows are drained, so the site's next write goes to the network
	 * table and the blog table stops growing; draining then picks up whatever
	 * arrived in between. Marked the other way about, a row written between
	 * the final batch and the mark would be left behind in a table nothing
	 * reads any more.
	 *
	 * One tick at a time for the whole network, whatever reached this: the
	 * scheduler, the runner's loopback, the terminal. A second arrival while
	 * one is in flight stands down rather than copying the same range again.
	 *
	 * @return array<string, mixed> The state after the tick, plus what this
	 *                              tick did: `copied`, `sites_touched`, and
	 *                              `skipped` where it did nothing.
	 */
	public static function run( float $budget = 10.0 ): array {
		self::forget();

		if ( ! is_multisite() ) {
			// Version 9 is a stamp on a single site and nothing moves. Said
			// as an answer rather than left as silence, because the runner
			// records what each task returned.
			return array_merge( self::state(), array( 'copied' => 0, 'sites_touched' => 0, 'skipped' => 'single_site' ) );
		}

		if ( ! self::claim_tick( $budget ) ) {
			/*
			 * A tick is already inside the copy. The three other tables carry
			 * unique keys that reject a row already there; the activity log
			 * carries none, so two ticks reading one cursor insert the same
			 * range twice and the day's seal is then computed over the
			 * doubled rows. Standing down is the whole protection.
			 */
			return array_merge( self::state(), array( 'copied' => 0, 'sites_touched' => 0, 'skipped' => 'claimed' ) );
		}

		try {
			return self::tick( $budget );
		} finally {
			self::release_tick();
		}
	}

	/**
	 * The tick itself, with the key already held.
	 *
	 * @return array<string, mixed>
	 */
	private static function tick( float $budget ): array {
		$started = microtime( true );

		// Read after the key was taken, not before: a tick that committed a
		// cursor between this request arriving and winning the key has moved
		// the state this one is about to resume from.
		self::forget();

		if ( self::is_complete() ) {
			// Older versions never enrolled sites added after completion. The
			// scheduled check also recovers an enrollment missed by overlapping
			// provisioning requests, without discarding any local history.
			if ( self::every_site_is_done() ) {
				return array_merge( self::state(), array( 'copied' => 0, 'sites_touched' => 0, 'skipped' => 'complete' ) );
			}
			self::reopen();
		}

		if ( Schema::network_current() < 9 ) {
			// Nowhere to copy to yet. The main site's install stamps this, and
			// until it has, doing anything here would be inventing a table.
			return array_merge( self::state(), array( 'copied' => 0, 'sites_touched' => 0, 'skipped' => 'network_tables_not_ready' ) );
		}

		$state = self::state();
		$state['error'] = array();
		self::save( $state );

		if ( self::STATUS_PENDING === $state['status'] ) {
			$state['status']     = self::STATUS_RUNNING;
			$state['started_at'] = gmdate( 'Y-m-d H:i:s' );

			// A count rather than a walk: no site is read here, so there is
			// nothing to page through and nothing that could be capped. It is
			// the denominator the dashboard shows progress against, and it
			// counts this network's sites because the state it feeds is this
			// network's own option.
			$state['sites_total'] = (int) get_sites(
				array(
					'count'      => true,
					'network_id' => get_current_network_id(),
				)
			);

			self::save( $state );
		}

		$copied  = 0;
		$touched = 0;
		$offset  = 0;
		$ran_out = false;

		/*
		 * The walk restarts at the first page every tick rather than carrying
		 * an offset. A site already switched is stepped over on an in-memory
		 * check, so the cost of restarting is one id query per page, and an
		 * offset stored across ticks would walk past a site created since —
		 * the one site most likely still to need carrying over.
		 */
		while ( ! $ran_out ) {
			$ids = get_sites(
				array(
					'fields'     => 'ids',
					'number'     => self::SITES_PER_PAGE,
					'offset'     => $offset,
					'orderby'    => 'id',
					'order'      => 'ASC',
					'network_id' => get_current_network_id(),
				)
			);

			if ( array() === $ids ) {
				break;
			}

			$offset += self::SITES_PER_PAGE;

			foreach ( $ids as $id ) {
				$blog_id = (int) $id;

				if ( self::site_is_done( $blog_id ) ) {
					continue;
				}

				++$touched;

				switch_to_blog( $blog_id );

				try {
					$copied += self::carry_site( $blog_id, $started, $budget );
				} finally {
					restore_current_blog();
				}

				if ( ! empty( self::state()['error'] ) || microtime( true ) - $started >= $budget ) {
					$ran_out = true;
					break;
				}
			}
		}

		$state = self::state();

		$state['sites_done'] = self::sites_switched();

		if ( ! $ran_out && $state['sites_done'] >= $state['sites_total'] && self::every_site_is_done() ) {
			$state['status']      = self::STATUS_COMPLETE;
			$state['finished_at'] = gmdate( 'Y-m-d H:i:s' );
			$state['current']     = array();
		}

		self::save( $state );

		return array_merge( self::state(), array( 'copied' => $copied, 'sites_touched' => $touched ) );
	}

	/**
	 * Carry one site, table by table, for as long as the clock allows.
	 *
	 * Runs switched to the site, so every option it reads or writes — the
	 * seals above all — is that site's own.
	 *
	 * @return int Rows copied.
	 */
	private static function carry_site( int $blog_id, float $started, float $budget ): int {
		global $wpdb;

		$copied = 0;

		foreach ( Schema::NETWORK_TABLES as $table ) {
			if ( microtime( true ) - $started >= $budget ) {
				return $copied;
			}

			$state    = self::state();
			$switched = ! empty( $state['switched'][ (string) $blog_id ][ $table ] );
			$current  = $state['current'];
			$resuming = (int) ( $current['blog_id'] ?? 0 ) === $blog_id && ( $current['table'] ?? '' ) === $table;

			// A switch redirects new writes; a retained cursor means the old
			// table still has a final drain to finish, even across requests.
			if ( $switched && ! $resuming ) {
				continue;
			}

			$blog_table = $wpdb->prefix . 'bettershield_' . $table;
			$net_table  = Schema::network_table( $table );

			if ( $blog_table === $net_table ) {
				self::mark_switched( $blog_id, $table );
				continue;
			}

			$cursor = self::cursor_for( $blog_id, $table );
			self::remember_cursor( $blog_id, $table, $cursor );
			$exists = self::table_exists( $blog_table );
			if ( null === $exists ) {
				self::failed_batch( $blog_id, $table, $cursor, 'table_read' );
				return $copied;
			}
			if ( ! $exists ) {
				self::mark_switched( $blog_id, $table );
				self::forget_cursor( $blog_id, $table );
				continue;
			}

			if ( 'events' === $table && 0 === $cursor ) {
				self::record_prior_verdict( $blog_id );
			}

			$columns = self::shared_columns( $blog_table, $net_table );
			if ( array() === $columns ) {
				self::failed_batch( $blog_id, $table, $cursor, 'columns' );
				return $copied;
			}

			while ( microtime( true ) - $started < $budget ) {
				$batch = self::copy_batch( $blog_id, $table, $blog_table, $net_table, $columns, $cursor );
				if ( $batch['failed'] ) {
					return $copied;
				}

				$copied += $batch['copied'];
				$cursor  = $batch['cursor'];
				self::remember_cursor( $blog_id, $table, $cursor, $batch['copied'] );

				if ( ! $batch['at_end'] ) {
					continue;
				}
				if ( ! $switched ) {
					// Save the successful cursor before redirecting new writes.
					// The next iteration drains any rows arriving in that gap.
					self::mark_switched( $blog_id, $table );
					$switched = true;
					continue;
				}

				if ( 'events' === $table ) {
					self::reseal( $blog_id, (int) ( self::state()['current']['copied'] ?? 0 ) );
				}
				self::forget_cursor( $blog_id, $table );
				continue 2;
			}

			return $copied;
		}

		return $copied;
	}

	/**
	 * One batch, by ascending id, from the blog table into the network table.
	 *
	 * The rows and the cursor that says they have been carried travel in one
	 * transaction. Written as two independent statements, a tick killed
	 * between them — the wall clock, the memory limit, a worker recycled
	 * mid-deploy — leaves rows committed that the next tick has no record of
	 * and selects again: the activity log gains an exact copy of a batch of
	 * its own history, which nothing afterwards can tell apart from the
	 * original, and the seals are then recomputed over the doubled rows.
	 * Committed together, an interrupted tick leaves neither.
	 *
	 * On a storage engine that does not do transactions the two statements
	 * land independently and the pair behaves exactly as it did before.
	 *
	 * @param string[] $columns
	 * @return array{copied: int, cursor: int, at_end: bool, failed: bool}
	 */
	private static function copy_batch( int $blog_id, string $table, string $blog_table, string $net_table, array $columns, int $cursor ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a migration over the plugin's own tables; there is no core API and nothing to cache.
		$ids = (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT id FROM %i WHERE id > %d ORDER BY id ASC LIMIT %d',
				$blog_table,
				$cursor,
				self::BATCH
			)
		);

		if ( '' !== (string) $wpdb->last_error ) {
			return self::failed_batch( $blog_id, $table, $cursor, 'select' );
		}

		if ( array() === $ids ) {
			return array(
				'copied' => 0,
				'cursor' => $cursor,
				'at_end' => true,
				'failed' => false,
			);
		}

		$last = (int) end( $ids );

		$list   = implode( ', ', $columns );
		$ignore = in_array( $table, self::IGNORE_DUPLICATES, true ) ? 'IGNORE ' : '';

		$wpdb->query( 'START TRANSACTION' );

		/*
		 * The column list is introspected from these two tables and reduced to
		 * word characters, the ids are integers, and both table names are
		 * bound with %i. Assembled rather than written out because the two
		 * tables can legitimately differ — a site that never took a later
		 * migration has fewer columns than the network table — and naming the
		 * intersection is what lets its rows travel anyway.
		 */
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $ignore is one of two literals chosen above and $list is the introspected column intersection reduced to word characters; nothing from a request reaches the string, and every value is bound.
		$moved = $wpdb->query(
			$wpdb->prepare(
				'INSERT ' . $ignore . 'INTO %i (site_id, ' . $list . ') SELECT %d, ' . $list . ' FROM %i WHERE id > %d AND id <= %d ORDER BY id ASC',
				$net_table,
				$blog_id,
				$blog_table,
				$cursor,
				$last
			)
		);

		if ( false === $moved ) {
			$wpdb->query( 'ROLLBACK' );

			return self::failed_batch( $blog_id, $table, $cursor, 'insert' );
		}

		$moved   = max( 0, (int) $moved );
		$skipped = count( $ids ) - $moved;

		// Counted before the cursor is persisted, so the tally of rows stepped
		// over is committed with the batch that stepped over them.
		if ( $skipped > 0 && in_array( $table, self::IGNORE_DUPLICATES, true ) ) {
			self::count_ignored( $table, $skipped );
		}

		self::persist_cursor( $blog_id, $table, $last, $moved );

		$wpdb->query( 'COMMIT' );
		// One line rather than two: a second phpcs:enable directly under the
		// first is not honored, and the annotations further down this file
		// stop working.
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		return array(
			'copied' => $moved,
			'cursor' => $last,
			'at_end' => count( $ids ) < self::BATCH,
			'failed' => false,
		);
	}

	/**
	 * The columns both tables have, minus the two the copy decides itself.
	 *
	 * @return string[]
	 */
	private static function shared_columns( string $blog_table, string $net_table ): array {
		$blog = self::columns_of( $blog_table );
		$net  = self::columns_of( $net_table );

		$shared = array_values( array_intersect( $blog, $net ) );

		return array_values(
			array_filter(
				$shared,
				static function ( string $column ): bool {
					// `id` is assigned by the network table, `site_id` is
					// written as the blog the rows belong to.
					return 'id' !== $column && 'site_id' !== $column;
				}
			)
		);
	}

	/**
	 * @return string[]
	 */
	private static function columns_of( string $table ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection during a migration.
		$columns = (array) $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', $table ) );

		$safe = array();

		foreach ( $columns as $column ) {
			$name = preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $column ) );

			if ( '' !== $name ) {
				$safe[] = $name;
			}
		}

		return $safe;
	}

	/** A missing table is empty; an unreadable catalog is an error. */
	private static function table_exists( string $table ): ?bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- migration schema introspection.
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
		return '' !== (string) $wpdb->last_error ? null : $found === $table;
	}

	/**
	 * Persist a retryable failure without exposing SQL or counting it as a skip.
	 *
	 * @return array{copied: int, cursor: int, at_end: bool, failed: bool}
	 */
	private static function failed_batch( int $blog_id, string $table, int $cursor, string $operation ): array {
		$state = self::state();
		$state['error'] = array( 'blog_id' => $blog_id, 'table' => $table, 'operation' => $operation );
		self::save( $state );
		return array( 'copied' => 0, 'cursor' => $cursor, 'at_end' => false, 'failed' => true );
	}

	/**
	 * Recompute the site's seals over the rows in their new home, and say so
	 * in the site's own log.
	 *
	 * Runs switched to the site and after it has been marked, so the seal
	 * reads the network table through the same predicate every other read of
	 * this site's log uses.
	 */
	private static function reseal( int $blog_id, int $rows_copied ): void {
		$state = self::state();

		$verdict = $state['verdict'][ (string) $blog_id ] ?? array();

		// Every day is taken again over the renumbered rows, except a day
		// that had already failed: taken again, it would be sealed as genuine.
		$result = Seal::reseal_site( null, (array) ( $state['failing'][ (string) $blog_id ] ?? array() ), 'network_migration' );

		$state = self::state();

		$state['resealed'][ (string) $blog_id ] = $result['recomputed'];

		self::save( $state );

		Writer::instance()->record(
			'log_migrated',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'system',
				'object_type' => 'log',
				'object_id'   => (string) $blog_id,
				'context'     => array(
					'days_resealed' => (int) $result['recomputed'],
					// A reseal that could not finish here is finished by the
					// site's daily check, which checks nothing until it is.
					'reseal_owed'   => Seal::reseal_owed(),
					'rows_copied'   => $rows_copied,
					// What the seals said about themselves before the rows
					// moved. Recorded now because after the move the old
					// answer can never be asked for again.
					'seals_before'  => $verdict,
				),
			)
		);

		// Written while still switched to the site: this row belongs to the
		// site's log, not to whichever site the task happened to fire on.
		Writer::instance()->flush();
	}

	/**
	 * The verdict this site's seals held over its own table, taken before a
	 * single row moves.
	 */
	private static function record_prior_verdict( int $blog_id ): void {
		$state = self::state();

		if ( isset( $state['verdict'][ (string) $blog_id ] ) ) {
			return;
		}

		$result = Seal::verify();

		$state['verdict'][ (string) $blog_id ] = array(
			'checked'      => (int) $result['checked'],
			'intact'       => (int) $result['intact'],
			'broken'       => count( $result['broken'] ),
			'unverifiable' => (int) $result['unverifiable'],
		);

		// A day that could not be read now is not vouched for after the move
		// either.
		$state['failing'][ (string) $blog_id ] = array_values(
			array_unique(
				array_merge(
					array_map( 'strval', wp_list_pluck( $result['broken'], 'day' ) ),
					array_map( 'strval', (array) $result['unreadable'] )
				)
			)
		);

		self::save( $state );
	}

	private static function cursor_for( int $blog_id, string $table ): int {
		$current = self::state()['current'];

		if ( (int) ( $current['blog_id'] ?? 0 ) !== $blog_id || (string) ( $current['table'] ?? '' ) !== $table ) {
			return 0;
		}

		return (int) ( $current['cursor'] ?? 0 );
	}

	private static function remember_cursor( int $blog_id, string $table, int $cursor, int $copied = 0 ): void {
		self::save( self::cursor_state( $blog_id, $table, $cursor, $copied ) );
	}

	/**
	 * The state this request holds, with the cursor moved to `$cursor`.
	 *
	 * Computed rather than stored, and taken by both writers below, so the
	 * copy committed with a batch and the copy the request goes on reading
	 * cannot say two different things.
	 *
	 * @return array<string, mixed>
	 */
	private static function cursor_state( int $blog_id, string $table, int $cursor, int $copied ): array {
		$state = self::state();

		$previous = $state['current'];
		$total = (int) ( $previous['blog_id'] ?? 0 ) === $blog_id && ( $previous['table'] ?? '' ) === $table
			? (int) ( $previous['copied'] ?? 0 ) : 0;
		$state['current'] = array(
			'copied'  => $total + $copied,
			'blog_id' => $blog_id,
			'table'   => $table,
			'cursor'  => $cursor,
		);

		return $state;
	}

	/**
	 * Write the cursor into the option's own row, inside the batch's
	 * transaction.
	 *
	 * The option API is deliberately not used here. It writes the row and the
	 * caches around it in one step, and the cache write would survive a
	 * rollback; what has to be atomic with the copied rows is the row in the
	 * database, and nothing else. Neither the request's own copy of the state
	 * nor the option cache is touched, because the caller brings both into
	 * line once the batch has committed.
	 */
	private static function persist_cursor( int $blog_id, string $table, int $cursor, int $copied ): void {
		global $wpdb;

		$network_id = get_current_network_id();
		$value      = maybe_serialize( self::cursor_state( $blog_id, $table, $cursor, $copied ) );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- the state row of a migration in flight; the option API cannot write inside the transaction and its caches are the caller's to refresh. meta_key and meta_value name the columns written by id, not a meta query.
		$meta_id = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT meta_id FROM %i WHERE site_id = %d AND meta_key = %s LIMIT 1',
				$wpdb->sitemeta,
				$network_id,
				self::OPTION
			)
		);

		if ( null === $meta_id ) {
			// The first tick of a run saves the state before any batch, so the
			// row is normally there already. Inserted rather than assumed,
			// because a cursor with nowhere to land is a batch that would be
			// copied again.
			$wpdb->insert(
				$wpdb->sitemeta,
				array(
					'site_id'    => $network_id,
					'meta_key'   => self::OPTION,
					'meta_value' => $value,
				),
				array( '%d', '%s', '%s' )
			);
		} else {
			$wpdb->update(
				$wpdb->sitemeta,
				array( 'meta_value' => $value ),
				array( 'meta_id' => (int) $meta_id ),
				array( '%s' ),
				array( '%d' )
			);
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key, WordPress.DB.SlowDBQuery.slow_db_query_meta_value
	}

	private static function forget_cursor( int $blog_id, string $table ): void {
		$state = self::state();

		if ( (int) ( $state['current']['blog_id'] ?? 0 ) === $blog_id && (string) ( $state['current']['table'] ?? '' ) === $table ) {
			$state['current'] = array();
			self::save( $state );
		}
	}

	private static function count_ignored( string $table, int $rows ): void {
		$state = self::state();

		$state['ignored'][ $table ] = (int) ( $state['ignored'][ $table ] ?? 0 ) + $rows;

		self::save( $state );
	}

	/**
	 * Whether every network table of one site has been carried over.
	 */
	private static function site_is_done( int $blog_id ): bool {
		$state = self::state();
		if ( (int) ( $state['current']['blog_id'] ?? 0 ) === $blog_id ) {
			return false;
		}
		$switched = $state['switched'][ (string) $blog_id ] ?? array();

		foreach ( Schema::NETWORK_TABLES as $table ) {
			if ( empty( $switched[ $table ] ) ) {
				return false;
			}
		}

		return true;
	}

	private static function sites_switched(): int {
		$done = 0;

		foreach ( array_keys( self::state()['switched'] ) as $blog_id ) {
			// A site deleted before its entries were taken out is not a site
			// carried over: a record written before deletions forgot a site
			// still holds some, and they made the count outrun the total.
			$site = get_site( (int) $blog_id );

			if ( $site && (int) $site->network_id === get_current_network_id() && self::site_is_done( (int) $blog_id ) ) {
				++$done;
			}
		}

		return $done;
	}

	/**
	 * Whether the walk found nothing left to carry over.
	 *
	 * Asked over the sites themselves rather than over a count, because a site
	 * created while the migration was running raises the total after the count
	 * that started it was taken.
	 */
	private static function every_site_is_done(): bool {
		$offset = 0;

		do {
			$ids = get_sites(
				array(
					'fields'     => 'ids',
					'number'     => self::SITES_PER_PAGE,
					'offset'     => $offset,
					// The same network the walk above covered, or "nothing
					// left" would be answered over sites this state never
					// described.
					'network_id' => get_current_network_id(),
				)
			);

			foreach ( $ids as $id ) {
				if ( ! self::site_is_done( (int) $id ) ) {
					return false;
				}
			}

			$offset += self::SITES_PER_PAGE;
		} while ( count( $ids ) === self::SITES_PER_PAGE );

		return true;
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function defaults(): array {
		return array(
			'status'      => self::STATUS_PENDING,
			'started_at'  => '',
			'finished_at' => '',
			'sites_total' => 0,
			'sites_done'  => 0,
			'current'     => array(),
			'error'       => array(),
			'switched'    => array(),
			'ignored'     => array(),
			'resealed'    => array(),
			// What each site's seals said about themselves before its rows
			// moved, kept because after the move nothing can ask again.
			'verdict'     => array(),
			// And which days had failed then, which the reseal after the move
			// leaves failing rather than taking again over the moved rows.
			'failing'     => array(),
		);
	}
}
