<?php
/**
 * The retention an update keeps for a while: the windows a site had on disk
 * when it updated, held for thirty days.
 *
 * Retention is read from two filters (`Support\Tier::retention_days()`,
 * `Incidents\Repository::history_days()`), thirty days unless something
 * answers them. Earlier builds widened it for a paid add-on, and an add-on
 * released before the filters answers none of them. On a site that gets this
 * build first, the next daily prune would delete everything past thirty days
 * that the add-on had kept: activity, agent activity, handled incidents and
 * the score history, none of it recoverable. The plugin updates on its own
 * schedule, and an add-on without a working key gets no update at all, so
 * releasing the add-on first does not prevent it (#1721).
 *
 * So once, on the first read after an update, the furthest reach of the
 * activity log and of the handled incidents on disk is written down, held to
 * the longest each may be kept. For thirty days neither window is shorter
 * than that, whatever the filters say; after that the filters alone decide
 * again. Nothing here reads the tier: the windows come from what is on disk.
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

/*
 * Two one-time reads of plugin-owned tables, for the oldest row in each.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class RetentionGrace {

	/** The windows written down at the update, and when they stop applying. */
	public const OPTION = 'bettershield_retention_grace';

	/** How long the windows are kept after the update, in days. */
	public const DAYS = 30;

	/**
	 * The days a record is kept for while the grace lasts: 0 when there is
	 * none, or it is over.
	 *
	 * @param string $record 'activity' or 'incidents'.
	 */
	public static function days( string $record ): int {
		$grace = self::grace();

		if ( time() >= $grace['until'] ) {
			return 0;
		}

		return 'incidents' === $record ? $grace['incidents'] : $grace['activity'];
	}

	/**
	 * The grace as written down, deciding it on the first read.
	 *
	 * @return array{activity: int, incidents: int, until: int}
	 */
	private static function grace(): array {
		$stored = get_option( self::OPTION, null );

		if ( is_array( $stored ) ) {
			return array(
				'activity'  => (int) ( $stored['activity'] ?? 0 ),
				'incidents' => (int) ( $stored['incidents'] ?? 0 ),
				'until'     => (int) ( $stored['until'] ?? 0 ),
			);
		}

		$none = array(
			'activity'  => 0,
			'incidents' => 0,
			'until'     => 0,
		);

		// A new install has nothing an earlier build kept, and is decided at
		// once. An update whose log cannot be read yet is asked again later,
		// rather than settled on no history.
		if ( ! Pruner::updated_from_earlier_build() ) {
			update_option( self::OPTION, $none, false );

			return $none;
		}

		if ( ! Schema::ready( 'events' ) ) {
			return $none;
		}

		$grace = array(
			'activity'  => self::reach( self::oldest_event(), Tier::RETENTION_DAYS_MAX ),
			'incidents' => Schema::ready( 'incidents' ) ? self::reach( self::oldest_handled_incident(), Repository::HISTORY_DAYS_MAX ) : 0,
			'until'     => time() + self::DAYS * DAY_IN_SECONDS,
		);

		update_option( self::OPTION, $grace, false );

		return $grace;
	}

	/**
	 * How many days back a row reaches, when that is more than the default
	 * window keeps; 0 otherwise. A site pruned daily to thirty days holds a
	 * day past it at most, and that is not history to keep.
	 *
	 * @param string $oldest When the oldest row was written, as the tables store it, or ''.
	 * @param int    $max    The longest the record may be kept.
	 */
	private static function reach( string $oldest, int $max ): int {
		$at = '' === $oldest ? false : strtotime( $oldest . ' UTC' );

		if ( false === $at ) {
			return 0;
		}

		$days = (int) ceil( ( time() - $at ) / DAY_IN_SECONDS );

		return $days > Pruner::RETENTION_DAYS + 1 ? min( $max, $days ) : 0;
	}

	private static function oldest_event(): string {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$oldest = $wpdb->get_var( $wpdb->prepare( 'SELECT MIN(occurred_at) FROM %i WHERE ' . Schema::site_where( 'events' ), Schema::table( 'events' ) ) );
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_string( $oldest ) ? $oldest : '';
	}

	private static function oldest_handled_incident(): string {
		global $wpdb;

		$oldest = $wpdb->get_var( $wpdb->prepare( "SELECT MIN(resolved_at) FROM %i WHERE status='resolved'", Schema::table( 'incidents' ) ) );

		return is_string( $oldest ) ? $oldest : '';
	}
}
