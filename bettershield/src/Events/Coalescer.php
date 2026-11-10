<?php
/**
 * One event now, the rest counted, and the count carried on the next one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The problem this solves is narrow and keeps recurring: an event worth
 * recording that an outsider can trigger as fast as they like. Writing every
 * one lets anyone grow the events table from outside, and a log nobody can read
 * is a log that failed. Writing only the first loses the number, which for a
 * guessing attempt is the entire signal.
 *
 * So: the first occurrence in a window is recorded at once, the rest are
 * counted, and the next recorded occurrence carries the count with it. Nothing
 * is silently dropped — the row that eventually lands says how many it stands
 * for.
 *
 * **This is not a third throttle.** `app_password_used` is throttled at its
 * listener because it is traffic, and `Events\Sampling` caps non-security types
 * at a per-hour threshold. Both of those may drop what they cover. This exists
 * for the security-relevant types neither may touch, where the count is the
 * thing worth keeping, and it was written once in the recovery path before
 * being needed a second time.
 *
 * State lives in a transient, so a site with a persistent object cache absorbs
 * a flood without touching the database at all, and a site without one spends a
 * fixed row rather than a growing table.
 *
 * **The count is a floor, not a tally.** Reading the state, adding to it and
 * writing it back is three steps, and a burst arriving in parallel is the case
 * this exists for: two requests can read the same figure and write back the
 * same increment, so occurrences that overlap under-report. The same gap at a
 * window boundary can let a second request open a window the first has already
 * opened, which spends one extra row.
 *
 * An atomic counter would close both, and it would be cheaper rather than
 * dearer: `Support\Claim` counts and reports in a single statement, while on a
 * site with no persistent object cache the transient here costs a read plus two
 * option writes for every suppressed occurrence. What it would cost instead is
 * the carry. A fixed counting window resets its total in the same statement
 * that opens the next window, so a burst's tail would be counted exactly and
 * then discarded, and the row that eventually lands would no longer say how
 * many it stands for — which is the entire signal for a guessing attempt. So
 * the floor stays, and what matters is that it is described as a floor rather
 * than left to be read as exact.
 *
 * The tail of a burst can be lost: if occurrences stop and nothing else happens
 * before the transient expires, the final count goes unreported. The event that
 * opened the window has already said what is happening, which is the part worth
 * knowing promptly.
 */
final class Coalescer {

	/** How many distinct names a window keeps for the row that reports it. */
	public const NAMES_KEPT = 10;

	/**
	 * Whether this occurrence should be recorded, and what it stands for.
	 *
	 * @param string $key    Transient key. Callers scope this themselves — one
	 *                       noisy source must not be able to mask another.
	 * @param int    $window Seconds during which occurrences are counted rather
	 *                       than written.
	 * @return int|null At least how many earlier occurrences this one speaks for
	 *                  (0 when it speaks only for itself), or null when this
	 *                  occurrence is counted rather than recorded. See the
	 *                  class note on parallel arrivals.
	 */
	public static function admit( string $key, int $window ): ?int {
		$admitted = self::admit_named( $key, $window, '' );

		return null === $admitted ? null : $admitted['count'];
	}

	/**
	 * admit(), keeping what each counted occurrence was about.
	 *
	 * A count alone hid which names a burst of failed sign-ins worked
	 * through, an administrator's among them (#2077). The names a window
	 * counted, up to NAMES_KEPT distinct ones, go with the count to the row
	 * that reports it.
	 *
	 * @param string $key    As admit().
	 * @param int    $window As admit().
	 * @param string $name   What this occurrence was about, as the log may keep it; '' for nothing.
	 * @return array{count: int, names: string[]}|null As admit(), with the names counted.
	 */
	public static function admit_named( string $key, int $window, string $name ): ?array {
		$window = max( 1, $window );

		$state    = get_transient( $key );
		$is_state = is_array( $state ) && isset( $state['opened_at'], $state['suppressed'] );

		// Held well past the window so a later occurrence can still report what
		// an earlier one suppressed.
		$retain = $window * 12;

		if ( $is_state && time() - (int) $state['opened_at'] < $window ) {
			$state['suppressed'] = (int) $state['suppressed'] + 1;

			$names = isset( $state['names'] ) && is_array( $state['names'] ) ? $state['names'] : array();

			if ( '' !== $name && ! in_array( $name, $names, true ) && count( $names ) < self::NAMES_KEPT ) {
				$names[] = $name;
			}

			$state['names'] = $names;

			set_transient( $key, $state, $retain );

			return null;
		}

		$suppressed = $is_state ? (int) $state['suppressed'] : 0;
		$names      = $is_state && isset( $state['names'] ) && is_array( $state['names'] ) ? array_values( array_map( 'strval', $state['names'] ) ) : array();

		set_transient(
			$key,
			array(
				'opened_at'  => time(),
				'suppressed' => 0,
				'names'      => array(),
			),
			$retain
		);

		return array(
			'count' => $suppressed,
			'names' => $names,
		);
	}
}
