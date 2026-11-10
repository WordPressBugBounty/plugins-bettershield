<?php
/**
 * Three changes that together look like somebody taking an account over.
 *
 * Each is logged on its own — the email address changed, the password
 * changed, an application password added — and each on its own is ordinary
 * account upkeep. All three on one privileged account inside an hour is the
 * shape of a takeover: the address moved so a reset reaches somebody else,
 * the password moved so the owner is out, and a standing credential added so
 * the way in survives both being put back.
 *
 * Recorded once, as its own event, and worded as a question: an administrator
 * setting up a colleague's account makes the same three changes. It never
 * locks, blocks or responds by itself; the owner's instant alert and the
 * incident's response plan are what follow from it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Incidents;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Password\Policy;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Takeover {

	/** The event recorded when all three line up. */
	public const EVENT = 'account_takeover_sequence';

	/** The three changes, in no particular order. */
	public const TYPES = array( 'user_email_changed', 'password_changed', 'app_password_created' );

	/** How close together they have to be. */
	public const WINDOW = HOUR_IN_SECONDS;

	/**
	 * Accounts already recorded during this request, so a batch holding all
	 * three rows records the sequence once rather than once per row.
	 *
	 * @var array<int, true>
	 */
	private static array $recorded = array();

	/**
	 * Called for each of the three as the incident engine reads it: when this
	 * one completes the set for its account within the hour before it, and no
	 * sequence was recorded for that account inside the same hour, record one.
	 *
	 * @param array<string, mixed> $row The event row as stored.
	 */
	public static function observe( array $row ): bool {
		if ( ! in_array( (string) $row['event_type'], self::TYPES, true ) || 'user' !== ( $row['object_type'] ?? '' ) ) {
			return false;
		}

		$user = (int) ( $row['object_id'] ?? 0 );

		if ( $user <= 0 || isset( self::$recorded[ $user ] ) || ! Policy::instance()->user_is_privileged( $user ) ) {
			return false;
		}

		$at    = strtotime( (string) $row['occurred_at'] . ' UTC' );
		$since = Time::stamp( ( false === $at ? time() : $at ) - self::WINDOW );
		$until = Time::stamp( false === $at ? time() : $at );

		global $wpdb;

		// Once per account per hour: a sequence already recorded since an
		// hour before this row covers it.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- this plugin's own events, read fresh; the site predicate is integers from Schema::site_where(); every value bound.
		$already = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE ' . Schema::site_where( 'events' ) . " AND event_type = %s AND object_type = 'user' AND object_id = %s AND occurred_at >= %s LIMIT 1", Schema::table( 'events' ), self::EVENT, (string) $user, $since ) );

		if ( '' !== $wpdb->last_error || null !== $already ) {
			return false;
		}

		// The set has to be complete by this row: the other two in the hour
		// before it, whichever order they came in.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- as above.
		$before = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT DISTINCT event_type FROM %i WHERE ' . Schema::site_where( 'events' ) . " AND object_type = 'user' AND object_id = %s AND occurred_at >= %s AND occurred_at <= %s AND event_type IN (" . implode( ',', array_fill( 0, count( self::TYPES ), '%s' ) ) . ')',
				array_merge( array( Schema::table( 'events' ), (string) $user, $since, $until ), self::TYPES )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( '' !== $wpdb->last_error || ! is_array( $before ) || count( array_intersect( self::TYPES, $before ) ) < count( self::TYPES ) ) {
			return false;
		}

		self::$recorded[ $user ] = true;

		Writer::instance()->record(
			self::EVENT,
			Writer::SEVERITY_HIGH,
			array(
				'actor_type'  => 'system',
				'object_type' => 'user',
				'object_id'   => (string) $user,
				'context'     => array( 'window_minutes' => (int) ( self::WINDOW / MINUTE_IN_SECONDS ) ),
			)
		);

		return true;
	}

	/** Forget what this request recorded; for a long-running process and tests. */
	public static function reset(): void {
		self::$recorded = array();
	}
}
