<?php
/**
 * Retention pruner.
 *
 * Deletes expired activity events in bounded batches under a wall-clock
 * budget — never a single unbounded range delete, which would lock the
 * table exactly when a busy site can least afford it. Falling behind is
 * acceptable; blocking is not: the remainder is picked up next run.
 *
 * Scope: the events table, the login working data, the agent invocation
 * record, write proposals and closed file changes. The undo ledger is NEVER
 * pruned — undo must outlive log retention. Findings keep their own
 * lifecycle.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * A bounded DELETE against the plugin-owned events table. There is no core API
 * for it, and caching a delete is meaningless.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Pruner {

	/**
	 * Event retention in days, by default. A filter may widen it
	 * (`Support\Tier::retention_days()`), and every read of the log is
	 * clamped to the same window, so a widening that goes away shows thirty
	 * days whatever is still on disk. This pruner catches up thirty days
	 * later (`RetentionHold`), so a widening that comes back first finds its
	 * days still there.
	 *
	 * Thirty: the log is diagnosis and diagnosis is free, and it must also
	 * outlast the digest — a weekly summary reading a window its own
	 * retention had already pruned would silently under-report. A test pins
	 * that relationship.
	 */
	public const RETENTION_DAYS = 30;

	/**
	 * How long a closed file change is kept: one put back, or replaced by a
	 * newer row. The stated retention is "until resolved, then thirty days".
	 * The table records when a change was found and not when it closed, so
	 * the window runs from when it was found; an open change, and one the
	 * owner marked as expected, are never pruned.
	 */
	public const INTEGRITY_RETENTION_DAYS = 30;

	/**
	 * The latest cutoff the events pruner has applied, as the log stores a
	 * time.
	 *
	 * The live retention floor says what may be pruned from now on, not what
	 * already was: a site that moves to a longer retention has days behind the
	 * new floor that the shorter one emptied. Whatever reads a missing day as
	 * removal has to know how far this pruner actually went.
	 */
	public const PRUNED_THROUGH_OPTION = 'bettershield_events_pruned_through';

	/**
	 * Delete expired events. Returns the number of rows removed.
	 *
	 * Expired by the window the log is kept on disk for, which outlasts the
	 * one it is read in for a month after a longer retention goes quiet
	 * (`RetentionHold`). What the filter answers now is written down first.
	 */
	public static function prune_events( float $budget_seconds = 5.0, int $batch_size = 1000 ): int {
		global $wpdb;

		\BetterShield\Support\Tier::note_retention();

		$cutoff = \BetterShield\Support\Tier::kept_floor();

		// Never recorded on a site an earlier build pruned: the line that build
		// left is where this one starts, or a longer retention's first line
		// would land behind days already gone.
		$line = max( $cutoff, self::reached() );

		// Written before the first delete, so a run cut short still leaves
		// the line behind every row it may have taken.
		if ( $line > self::stored_cutoff() ) {
			update_option( self::PRUNED_THROUGH_OPTION, $line, false );
		}

		$start   = microtime( true );
		$removed = 0;

		do {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
			$deleted = $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at < %s ORDER BY id ASC LIMIT %d',
					Schema::table( 'events' ),
					$cutoff,
					$batch_size
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

			$removed += (int) $deleted;

			if ( (int) $deleted < $batch_size ) {
				break; // Nothing left below the cutoff.
			}
		} while ( microtime( true ) - $start < $budget_seconds );

		return $removed;
	}

	/**
	 * How far back the events pruner has reached: rows before this may be
	 * gone by its hand, whatever the retention is now. Empty until it has run.
	 *
	 * Never later than the shortest retention the log is kept for, so a stored
	 * value cannot move the line over days no retention would have touched.
	 */
	public static function pruned_through(): string {
		$stored = self::reached();

		if ( '' === $stored ) {
			return '';
		}

		$shortest = ( new \DateTimeImmutable( '-' . self::RETENTION_DAYS . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		return $stored < $shortest ? $stored : $shortest;
	}

	private static function stored_cutoff(): string {
		$stored = get_option( self::PRUNED_THROUGH_OPTION, '' );

		return is_string( $stored ) ? $stored : '';
	}

	/**
	 * How far the pruner is known to have reached: what it recorded, or, on a
	 * site updated from a build that recorded nothing, that build's line.
	 *
	 * Earlier builds pruned to the shortest retention every day and never
	 * wrote the option. Read as "never pruned", the days they emptied were
	 * judged by the live floor, and with a longer retention on, every one of
	 * them read as a day somebody had removed: a high seal finding that stayed
	 * open until the longer retention caught up, about two months later. A
	 * site installed on this build records its own line from its first run,
	 * so nothing is assumed for it.
	 */
	private static function reached(): string {
		$stored = self::stored_cutoff();

		if ( '' !== $stored || ! self::updated_from_earlier_build() ) {
			return $stored;
		}

		return ( new \DateTimeImmutable( '-' . self::RETENTION_DAYS . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}

	/**
	 * Whether this site ran an earlier build before this one: the update was
	 * noted, or the version on record is behind the one running and has not
	 * been noted yet (an update outside the dashboard, before any screen).
	 * The retention grace asks the same.
	 */
	public static function updated_from_earlier_build(): bool {
		if ( '' !== (string) get_option( \BetterShield\Onboarding\Release::CAME_FROM, '' ) ) {
			return true;
		}

		$stored = (string) get_option( 'bettershield_version', '' );

		return '' !== $stored && defined( 'BETTERSHIELD_VERSION' ) && version_compare( $stored, (string) BETTERSHIELD_VERSION, '<' );
	}

	/**
	 * Delete expired agent invocations. Same bounded shape and the same
	 * window as the activity log — the two records are read side by side and
	 * a reader should not find one reaching further back than the other.
	 */
	public static function prune_agent_invocations( float $budget_seconds = 5.0, int $batch_size = 1000 ): int {
		global $wpdb;

		if ( ! Schema::ready( 'agent_invocations' ) ) {
			return 0;
		}

		\BetterShield\Support\Tier::note_retention();

		$cutoff = \BetterShield\Support\Tier::kept_floor();

		$start   = microtime( true );
		$removed = 0;

		do {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
			$deleted = $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE ' . Schema::site_where( 'agent_invocations' ) . ' AND invoked_at < %s ORDER BY id ASC LIMIT %d',
					Schema::table( 'agent_invocations' ),
					$cutoff,
					$batch_size
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

			$removed += (int) $deleted;

			if ( (int) $deleted < $batch_size ) {
				break; // Nothing left below the cutoff.
			}
		} while ( microtime( true ) - $start < $budget_seconds );

		return $removed;
	}

	/**
	 * Delete write proposals older than a week.
	 *
	 * A proposal is live for fifteen minutes and readable afterwards as the
	 * record of what an agent asked for and what a person answered. Seven days
	 * is long enough for that reading and short enough that the table stays
	 * working data: the durable half of the story is the activity log and the
	 * undo ledger, and neither is pruned by this.
	 */
	public static function prune_write_proposals( float $budget_seconds = 5.0, int $batch_size = 1000 ): int {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return 0;
		}

		$cutoff = ( new \DateTimeImmutable( '-7 days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		$start   = microtime( true );
		$removed = 0;

		do {
			$deleted = $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE proposed_at < %s ORDER BY id ASC LIMIT %d',
					Schema::table( 'write_proposals' ),
					$cutoff,
					$batch_size
				)
			);

			$removed += (int) $deleted;

			if ( (int) $deleted < $batch_size ) {
				break; // Nothing left below the cutoff.
			}
		} while ( microtime( true ) - $start < $budget_seconds );

		// The menu reads a cached count of what is waiting, maintained by the
		// writes to this table. A delete is one of them.
		if ( $removed > 0 ) {
			\BetterShield\Abilities\Proposals::refresh_open_count();
		}

		return $removed;
	}

	/**
	 * Delete closed file changes past their window, in bounded batches.
	 *
	 * Closed rows only had their status moved, so the table grew for the
	 * life of the site. The one reader of a closed row is a restore being
	 * undone, which lists its change again; past the window the next check
	 * of the files lists it instead, as it lists any difference it finds.
	 */
	public static function prune_integrity_changes( float $budget_seconds = 5.0, int $batch_size = 1000 ): int {
		global $wpdb;

		if ( ! Schema::ready( 'integrity_changes' ) || \BetterShield\Integrity\Shared::elsewhere() ) {
			return 0;
		}

		$cutoff = ( new \DateTimeImmutable( '-' . self::INTEGRITY_RETENTION_DAYS . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		$start   = microtime( true );
		$removed = 0;

		/*
		 * Not one an incident on record still cites. The window counts from
		 * when the change was found, and a change put back long after that is
		 * what an incident's plan undoes and re-checks: pruned, both refused
		 * it as no longer on record. Evidence keys a change by these columns,
		 * as the incident engine writes them, and goes with its incident.
		 */
		// The change's columns named by its table: evidence has an id of its own.
		$changes = Schema::table( 'integrity_changes' );
		$cited   = Schema::ready( 'incident_evidence' )
			? $wpdb->prepare( " AND NOT EXISTS ( SELECT 1 FROM %i e WHERE e.source_key = SHA2( CONCAT( 'integrity:', %i.id, ':', %i.detected_at, ':', %i.path, ':', COALESCE( %i.hash_after, '' ) ), 256 ) )", Schema::table( 'incident_evidence' ), $changes, $changes, $changes, $changes )
			: '';

		do {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $cited is prepared just above, with the table name as its only value.
			$deleted = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM %i WHERE site_id = 0 AND status IN ('restored','superseded') AND detected_at < %s{$cited} ORDER BY id ASC LIMIT %d",
					$changes,
					$cutoff,
					$batch_size
				)
			);

			$removed += (int) $deleted;

			if ( (int) $deleted < $batch_size ) {
				break; // Nothing left past the window.
			}
		} while ( microtime( true ) - $start < $budget_seconds );

		return $removed;
	}

	/**
	 * Delete stale login-protection working data: attempts older than two
	 * days (the counting window is minutes; two days is generous forensics),
	 * and lockout rows a month past their end. Same bounded shape as events.
	 */
	public static function prune_login_data( float $budget_seconds = 5.0, int $batch_size = 1000 ): int {
		global $wpdb;

		// Each finished day's failed sign-ins, counted before the rows go:
		// the usual an unusual hour is measured against.
		\BetterShield\Events\Unusual::roll_up_signins();

		$start   = microtime( true );
		$removed = 0;

		$targets = array(
			array( Schema::table( 'login_attempts' ), 'occurred_at', '-2 days' ),
			array( Schema::table( 'lockouts' ), 'expires_at', '-30 days' ),
		);

		// A lockout that has ended no longer needs to be matched against a
		// connection, so its keyed digest is blanked: the row stays as history
		// (when, how many attempts, which network) with nothing left in it
		// that a holder of the key could turn back into an address. The unlock
		// token goes with it — it was the credential for this one lockout, and
		// the lockout is over.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET ip_hmac = '', unlock_token_hash = NULL WHERE site_id = 0 AND ip_hmac <> '' AND expires_at < %s LIMIT %d",
				Schema::table( 'lockouts' ),
				gmdate( 'Y-m-d H:i:s.v' ),
				$batch_size
			)
		);

		foreach ( $targets as $target ) {
			list( $table, $column, $age ) = $target;

			$cutoff = ( new \DateTimeImmutable( $age, new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

			do {
				$deleted = $wpdb->query(
					$wpdb->prepare(
						'DELETE FROM %i WHERE site_id = 0 AND %i < %s ORDER BY id ASC LIMIT %d',
						$table,
						$column,
						$cutoff,
						$batch_size
					)
				);

				$removed += (int) $deleted;

				if ( (int) $deleted < $batch_size ) {
					break;
				}
			} while ( microtime( true ) - $start < $budget_seconds );
		}

		return $removed;
	}
}
