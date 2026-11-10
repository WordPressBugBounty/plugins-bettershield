<?php
/**
 * A finding set aside for a set number of days.
 *
 * Marking a finding not applicable is for a finding that will never apply.
 * An owner with a known, temporary reason (an update waiting on a staging
 * test, a change booked for next week) had only that or a reminder every
 * day, and a finding that nags every day is the one that stops being read.
 *
 * A snoozed finding stays open, and it keeps counting against the score:
 * the problem is real until it is fixed, and the score describes the site.
 * What the snooze changes is where the finding is shown. It leaves the list
 * of what needs attention for its own list, and the summary does not name it
 * as the next thing to do. It comes back on its own when the time is up, at
 * once if the finding gets worse, and whenever the owner wakes it. Each of
 * those is a line in the activity log.
 *
 * Kept in one option rather than in the findings table, so the row itself,
 * its status and every reader of it stay exactly as they were.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Snooze {

	/** Where the snoozes are kept, by finding key. */
	public const OPTION = 'bettershield_finding_snoozes';

	/**
	 * Held around each read and write of the snoozes. They are one option,
	 * read whole and written whole, so two changes at once each wrote back
	 * what they had read and the second dropped the first.
	 */
	private const CLAIM = 'finding_snoozes';

	/** Long enough for one read and one write; a lapsed claim is taken over. */
	private const CLAIM_SECONDS = 15;

	/** The lengths a finding may be set aside for, in days. */
	public const DAYS = array( 7, 30 );

	/**
	 * Every snooze on record, whether or not it has run out.
	 *
	 * @return array<string, array{until: int, severity: int, at: int, days: int}>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );
		$out    = array();

		foreach ( is_array( $stored ) ? $stored : array() as $key => $entry ) {
			if ( ! is_string( $key ) || ! is_array( $entry ) || ! isset( $entry['until'] ) ) {
				continue;
			}

			$out[ $key ] = array(
				'until'    => (int) $entry['until'],
				'severity' => (int) ( $entry['severity'] ?? 0 ),
				'at'       => (int) ( $entry['at'] ?? 0 ),
				'days'     => (int) ( $entry['days'] ?? 0 ),
			);
		}

		return $out;
	}

	/**
	 * When a finding's snooze ends, as a timestamp, or null when it is not
	 * snoozed now. A snooze that has run out is over the moment it runs out,
	 * whether or not anything has cleared it yet.
	 */
	public static function until( string $key ): ?int {
		$entry = self::all()[ $key ] ?? null;

		return null !== $entry && $entry['until'] > time() ? $entry['until'] : null;
	}

	/**
	 * The same, as an ISO 8601 UTC time for the screens, or null.
	 */
	public static function until_iso( string $key ): ?string {
		$until = self::until( $key );

		return null === $until ? null : gmdate( 'c', $until );
	}

	/**
	 * Set an open finding aside for a number of days.
	 *
	 * @return true|\WP_Error
	 */
	public static function snooze( string $key, int $days ) {
		if ( ! isset( Checks::all()[ $key ] ) ) {
			return new \WP_Error( 'bettershield_unknown_finding', __( 'Unknown finding.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( ! in_array( $days, self::DAYS, true ) ) {
			return new \WP_Error(
				'bettershield_snooze_days',
				/* translators: %s: the lengths allowed, e.g. "7, 30". */
				sprintf( __( 'A finding can be snoozed for %s days.', 'bettershield' ), implode( ', ', self::DAYS ) ),
				array( 'status' => 400 )
			);
		}

		$severity = self::open_severity( $key );

		if ( null === $severity ) {
			return new \WP_Error(
				'bettershield_finding_not_in_state',
				__( 'Only an open finding can be snoozed.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( ! Claim::claim( self::CLAIM, self::CLAIM_SECONDS ) ) {
			return self::busy();
		}

		try {
			$snoozes         = self::fresh();
			$until           = time() + $days * DAY_IN_SECONDS;
			$snoozes[ $key ] = array(
				'until'    => $until,
				'severity' => $severity,
				'at'       => time(),
				'days'     => $days,
			);

			update_option( self::OPTION, $snoozes, false );
		} finally {
			Claim::release( self::CLAIM );
		}

		// At the weight of the finding set aside, as suppressing one is.
		Writer::instance()->record(
			'finding_snoozed',
			max( Writer::SEVERITY_LOW, $severity ),
			array(
				'object_type' => 'finding',
				'object_id'   => $key,
				'context'     => array(
					'days'  => $days,
					'until' => gmdate( 'c', $until ),
				),
			)
		);

		return true;
	}

	/**
	 * Bring a snoozed finding back now: the owner's undo.
	 *
	 * @return true|\WP_Error
	 */
	public static function wake( string $key ) {
		if ( null === self::until( $key ) ) {
			return new \WP_Error(
				'bettershield_finding_not_in_state',
				__( 'This finding is not snoozed.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$ended = self::end( $key, 'owner' );

		return is_wp_error( $ended ) ? $ended : true;
	}

	/**
	 * Take a snooze off a finding the owner has decided about more firmly,
	 * with nothing recorded: that decision is logged as itself. Left in place,
	 * a finding marked not applicable and then put back returned snoozed.
	 */
	public static function release( string $key ): void {
		self::end( $key, '' );
	}

	/**
	 * After an audit: end each snooze whose time is up, whose finding got
	 * worse, or whose finding is no longer open.
	 *
	 * A finding that closed simply loses its snooze, with nothing recorded:
	 * its closing is already in the log, and it is closing that matters.
	 */
	public static function review(): void {
		$snoozes = self::all();

		if ( array() === $snoozes ) {
			return;
		}

		foreach ( $snoozes as $key => $entry ) {
			$severity = self::open_severity( $key );

			if ( null === $severity ) {
				self::end( $key, '' );
				continue;
			}

			if ( $severity > $entry['severity'] ) {
				self::end( $key, 'worse' );
				continue;
			}

			if ( $entry['until'] <= time() ) {
				self::end( $key, 'expired' );
			}
		}
	}

	/**
	 * Take a snooze off the record, saying why unless there is nothing to say.
	 *
	 * Takes the claim itself, for each snooze it ends: the claim is not
	 * re-entrant, so the audit's review cannot hold it around its loop. A
	 * snooze it cannot end now is left for the next audit, or refused to
	 * the owner.
	 *
	 * @return true|\WP_Error
	 */
	private static function end( string $key, string $reason ) {
		if ( ! Claim::claim( self::CLAIM, self::CLAIM_SECONDS ) ) {
			return self::busy();
		}

		try {
			$snoozes = self::fresh();

			if ( ! isset( $snoozes[ $key ] ) ) {
				return true;
			}

			unset( $snoozes[ $key ] );
			update_option( self::OPTION, $snoozes, false );
		} finally {
			Claim::release( self::CLAIM );
		}

		if ( '' === $reason ) {
			return true;
		}

		Writer::instance()->record(
			'finding_woken',
			// A finding that got worse while set aside is news; one whose
			// time ran out, or that the owner woke, is housekeeping.
			'worse' === $reason ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_LOW,
			array(
				'object_type' => 'finding',
				'object_id'   => $key,
				'context'     => array( 'reason' => $reason ),
			)
		);

		return true;
	}

	/**
	 * The snoozes as stored now, past whatever this request has already
	 * read: another request may have changed them since.
	 *
	 * @return array<string, array{until: int, severity: int, at: int, days: int}>
	 */
	private static function fresh(): array {
		wp_cache_delete( self::OPTION, 'options' );

		$missing = wp_cache_get( 'notoptions', 'options' );

		if ( is_array( $missing ) && isset( $missing[ self::OPTION ] ) ) {
			unset( $missing[ self::OPTION ] );
			wp_cache_set( 'notoptions', $missing, 'options' );
		}

		return self::all();
	}

	/** Another change to the snoozes holds them. */
	private static function busy(): \WP_Error {
		return new \WP_Error(
			'bettershield_snooze_busy',
			__( 'Another change to the snoozed findings is being saved. Try again in a moment.', 'bettershield' ),
			array( 'status' => 409 )
		);
	}

	/**
	 * The stored severity of a finding while it is open, or null when it is
	 * not open.
	 */
	private static function open_severity( string $key ): ?int {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- read fresh from this plugin's own table; the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$severity = $wpdb->get_var(
			$wpdb->prepare( "SELECT severity FROM %i WHERE " . Schema::site_where( 'findings' ) . " AND finding_key = %s AND status = 'open'", Schema::table( 'findings' ), $key )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return null === $severity ? null : (int) $severity;
	}
}
