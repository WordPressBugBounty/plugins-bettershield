<?php
/**
 * What a longer retention leaves behind: for thirty days after a filter last
 * answered a longer window than it answers now, the pruners keep to that one.
 *
 * Retention is read from two filters (`Support\Tier::retention_days()`,
 * `Incidents\Repository::history_days()`), thirty days unless something
 * answers them, and every read keeps to what they answer at that moment. The
 * pruners kept to it too, so a filter that went quiet for one night cost
 * every row it had kept past thirty days: an add-on switched off to look for
 * a conflict, across the hour the daily prune runs, came back to find two
 * months of activity and agent activity, five of handled incidents and the
 * score history gone for good (#1355).
 *
 * So each prune writes down the longest window the filters answer, and for
 * thirty days after they last answered it nothing inside it is deleted.
 * Reads are not widened: the screens show what the filters answer now, and
 * the older rows wait on disk rather than being shown, so a retention that
 * comes back within the month finds them where it left them. Nothing here
 * reads the tier. `RetentionGrace` keeps the same promise for the moment an
 * update brings.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Database;

use BetterShield\Incidents\Repository;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RetentionHold {

	/** For each record, the longest window last answered and when, as Unix time. */
	public const OPTION = 'bettershield_retention_hold';

	/** How long a longer window is kept to after the filters stop answering it, in days. */
	public const DAYS = 30;

	/**
	 * The days a record stays on disk: what the filters answer now, or a
	 * longer window they answered within the last thirty days. Only reads.
	 *
	 * @param string $record   'activity' or 'incidents'.
	 * @param int    $answered What the filters answer now, in days, held to range.
	 */
	public static function days( string $record, int $answered ): int {
		$held = self::held( $record );

		if ( $held['days'] > $answered && time() - $held['at'] < self::DAYS * DAY_IN_SECONDS ) {
			return $held['days'];
		}

		return $answered;
	}

	/**
	 * Write down what the filters answer, for a pruner about to delete by it.
	 *
	 * Only a window longer than the default is worth holding to. While one is
	 * answered it is written at most once a day, and a longer one still being
	 * held to is not written over by a shorter answer.
	 *
	 * @param string $record   'activity' or 'incidents'.
	 * @param int    $answered What the filters answer now, in days, held to range.
	 */
	public static function note( string $record, int $answered ): void {
		if ( $answered <= Pruner::RETENTION_DAYS || self::days( $record, $answered ) > $answered ) {
			return;
		}

		$held = self::held( $record );

		if ( $answered === $held['days'] && time() - $held['at'] < DAY_IN_SECONDS ) {
			return;
		}

		$stored            = self::stored();
		$stored[ $record ] = array(
			'days' => $answered,
			'at'   => time(),
		);

		update_option( self::OPTION, $stored, false );
	}

	/**
	 * What is written down for a record, held to the longest it may be kept
	 * and to a time that has already happened.
	 *
	 * @return array{days: int, at: int}
	 */
	private static function held( string $record ): array {
		$held    = self::stored()[ $record ] ?? null;
		$held    = is_array( $held ) ? $held : array();
		$longest = 'incidents' === $record ? Repository::HISTORY_DAYS_MAX : Tier::RETENTION_DAYS_MAX;

		return array(
			'days' => max( 0, min( $longest, (int) ( $held['days'] ?? 0 ) ) ),
			'at'   => min( time(), (int) ( $held['at'] ?? 0 ) ),
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function stored(): array {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}
}
