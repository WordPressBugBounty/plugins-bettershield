<?php
/**
 * What a public form's numbers would have done, replayed over the attempts
 * the site still holds.
 *
 * An owner changing a form's threshold or window has had nothing to go on but
 * the number itself. This walks the attempts recorded against that form,
 * source by source in time order, the way the gate counts them — a count
 * inside the window that starts no earlier than the last closure, the attempt
 * that reaches the threshold held or refused along with the ones after it
 * until the pause ends — and says how many sources would have been closed out
 * and how many attempts caught.
 *
 * The reset and sign-up forms record an attempt made while they are closed,
 * and it counts toward the next closure, so a source that keeps going is
 * closed again the moment a pause ends. The comment form holds a comment
 * while it is closed without recording it, so for comments those count
 * toward nothing.
 *
 * Limits, said on the screen. The table keeps two days, and only while the
 * form is switched on. A comment held while the form was really closed was
 * never recorded, so it cannot be replayed. And a row does not record whether
 * its source could be verified, which is what spares an address several
 * people share, so every source is counted as though it could.
 *
 * Read-only. It writes nothing and runs nothing on a visitor's request.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Database\Schema;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Replay {

	/**
	 * How many attempts one replay reads. Enough for two days of a busy form;
	 * past it, the answer says it read the most recent share only.
	 */
	public const MAX_ROWS = 20000;

	/**
	 * Replay one form's attempts under the saved numbers and under the ones
	 * proposed.
	 *
	 * @param array{threshold: int, window_minutes: int, lockout_minutes: int} $proposed
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function run( string $surface, array $proposed ) {
		if ( ! in_array( $surface, Surfaces::GATED, true ) ) {
			/* translators: %s: the name of a form. */
			return new \WP_Error( 'bettershield_unknown_surface', sprintf( __( 'There is no form called %s to protect.', 'bettershield' ), $surface ), array( 'status' => 400 ) );
		}

		if ( ! Gate::surfaced() ) {
			return new \WP_Error( 'bettershield_replay_unavailable', __( 'Past attempts cannot be checked until the database upgrade finishes.', 'bettershield' ), array( 'status' => 409 ) );
		}

		global $wpdb;

		$since = Time::stamp( time() - 2 * DAY_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- a bounded read of this plugin's own table, for one screen.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_hmac, occurred_at FROM %i WHERE site_id = 0 AND surface = %s AND outcome = 'failed' AND occurred_at >= %s ORDER BY occurred_at DESC LIMIT %d",
				Schema::table( 'login_attempts' ),
				$surface,
				$since,
				self::MAX_ROWS + 1
			)
		);

		if ( '' !== $wpdb->last_error || ! is_array( $rows ) ) {
			return new \WP_Error( 'bettershield_replay_unreadable', __( 'The recorded attempts could not be read.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$truncated = count( $rows ) > self::MAX_ROWS;
		$rows      = array_slice( $rows, 0, self::MAX_ROWS );

		$sources = array();
		$oldest  = null;

		foreach ( $rows as $row ) {
			$time = strtotime( (string) $row->occurred_at . ' UTC' );

			if ( false === $time ) {
				continue;
			}

			$sources[ (string) $row->ip_hmac ][] = $time;
			$oldest                               = null === $oldest ? $time : min( $oldest, $time );
		}

		foreach ( $sources as &$times ) {
			sort( $times );
		}
		unset( $times );

		$saved = Protection::instance()->surface_policy( $surface );

		return array(
			'surface'   => $surface,
			'from'      => gmdate( 'c', null === $oldest ? time() - 2 * DAY_IN_SECONDS : $oldest ),
			'to'        => gmdate( 'c' ),
			'attempts'  => count( $rows ),
			'sources'   => count( $sources ),
			'truncated' => $truncated,
			'saved'     => self::simulate( $sources, $saved, Surfaces::COMMENT !== $surface ),
			'proposed'  => self::simulate( $sources, $proposed, Surfaces::COMMENT !== $surface ),
		);
	}

	/**
	 * Walk each source's attempts under one set of numbers, by the gate's own
	 * rules (`Gate::note_failure()`): every attempt the form records counts;
	 * the count is of recorded attempts after the later of one window ago and
	 * the last closure's start; the attempt that reaches the threshold closes
	 * the form and is caught; and every attempt while it is closed is caught.
	 *
	 * @param array<string, int[]>                                               $sources Attempt times per source, oldest first.
	 * @param array{threshold: int, window_minutes: int, lockout_minutes: int} $policy
	 * @param bool                                                              $records_while_closed Whether the form records an attempt made while it is closed: reset and sign-up do, comments do not.
	 * @return array{closed: int, closures: int, caught: int}
	 */
	public static function simulate( array $sources, array $policy, bool $records_while_closed = true ): array {
		$threshold = max( 1, (int) $policy['threshold'] );
		$window    = max( 1, (int) $policy['window_minutes'] ) * MINUTE_IN_SECONDS;
		$lockout   = max( 1, (int) $policy['lockout_minutes'] ) * MINUTE_IN_SECONDS;

		$closed   = 0;
		$closures = 0;
		$caught   = 0;

		foreach ( $sources as $times ) {
			$started  = null;
			$until    = 0;
			$recorded = array();
			$head     = 0;
			$shut     = false;

			foreach ( $times as $time ) {
				$closed_now = $time < $until;

				if ( $closed_now ) {
					++$caught;

					if ( ! $records_while_closed ) {
						continue;
					}
				}

				$recorded[] = $time;

				$since = $time - $window;

				if ( null !== $started && $started > $since ) {
					$since = $started;
				}

				// The times are in order and the lower bound only moves
				// forward, so what falls behind it is passed once: a flood
				// from one source costs one pass, not one per attempt.
				$last = count( $recorded );

				while ( $head < $last && $recorded[ $head ] <= $since ) {
					++$head;
				}

				$count = $last - $head;

				if ( ! $closed_now && $count >= $threshold ) {
					++$closures;
					++$caught;
					$shut    = true;
					$started = $time;
					$until   = $time + $lockout;
				}
			}

			$closed += $shut ? 1 : 0;
		}

		return array(
			'closed'   => $closed,
			'closures' => $closures,
			'caught'   => $caught,
		);
	}
}
