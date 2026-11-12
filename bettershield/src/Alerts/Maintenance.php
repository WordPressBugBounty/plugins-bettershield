<?php
/**
 * A bounded, owner-declared quiet window for routine maintenance alerts.
 * Logging and enforcement continue. Counts are persisted before either sender
 * may hold an event; a failed write leaves the ordinary alert path available.
 *
 * @package BetterShield
 */
declare( strict_types=1 );
namespace BetterShield\Alerts;

use BetterShield\Cron\Runner;
use BetterShield\Database\Schema;
use BetterShield\Events\Types;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class Maintenance {
	public const OPTION = 'bettershield_maintenance_window';
	public const TASK = 'bettershield_maintenance_close';
	/** A window booked ahead: when it opens, for how long, and who booked it. */
	public const BOOKING = 'bettershield_maintenance_booking';
	/** The scheduled opening of a booked window. */
	public const OPEN_TASK = 'bettershield_maintenance_open';
	/** The lengths a window may run for, booked or opened now. */
	public const LENGTHS = array( 30, 60, 120, 240 );
	/** How far ahead a window may be booked. */
	private const BOOK_AHEAD = 30 * DAY_IN_SECONDS;
	/** How soon a booked window may open, so a booking is never already late. */
	private const BOOK_LEAD = 5 * MINUTE_IN_SECONDS;
	public const CLOSED = 'maintenance_window_closed';
	private const LOCK = 'maintenance_window_write';
	// Deliberately excludes policy weakening, credentials, canaries, lockdown,
	// generic plugin settings and unknown future event types. Critical always pierces.
	private const EXPECTED = array( 'user_created', 'user_role_changed', 'user_role_granted', 'plugin_activated', 'plugin_deactivated', 'plugin_installed', 'plugin_updated', 'theme_installed', 'theme_updated', 'theme_changed', 'core_updated', 'file_changed' );
	private static array $held = array();
	private static bool $closing = false;
	private static bool $dispatch_after_close = false;

	public static function register(): void {
		add_action( 'bettershield_events_flushed', array( self::class, 'observe' ), 5, 2 );
		add_action( self::TASK, array( self::class, 'tick' ) );
		add_action( self::OPEN_TASK, array( self::class, 'tick' ) );
		Runner::instance()->register_task( 'bettershield_maintenance_retry', 'hourly', array( self::class, 'tick' ), false );
	}

	private static function state(): array {
		$value = get_option( self::OPTION, array() );
		return is_array( $value ) ? $value : array();
	}

	private static function fresh(): array {
		// The option is never autoloaded. A worker waiting for the lock must
		// not use the copy it read before another worker updated the counts.
		wp_cache_delete( self::OPTION, 'options' );
		return self::state();
	}

	public static function report(): array {
		$state   = self::state();
		$booking = self::booking();
		$by      = null !== $booking ? get_userdata( (int) $booking['by'] ) : false;
		return array(
			'active' => 'active' === ( $state['phase'] ?? '' ) && (int) ( $state['until'] ?? 0 ) > time(),
			'until' => isset( $state['until'] ) ? gmdate( 'c', (int) $state['until'] ) : null,
			'held' => (int) ( $state['held'] ?? 0 ),
			'total' => (int) ( $state['total'] ?? 0 ),
			'summary_pending' => array() !== $state && 'closed' !== ( $state['phase'] ?? '' ),
			// A window booked ahead, said with who booked it.
			'booked' => null === $booking ? null : array(
				'at'      => gmdate( 'c', (int) $booking['at'] ),
				'until'   => gmdate( 'c', (int) $booking['at'] + (int) $booking['minutes'] * MINUTE_IN_SECONDS ),
				'minutes' => (int) $booking['minutes'],
				'by'      => $by instanceof \WP_User ? $by->display_name : '',
				// What the form shows, on the site's clock.
				'local'   => wp_date( 'Y-m-d\TH:i', (int) $booking['at'] ),
			),
		);
	}

	/**
	 * The window booked ahead, or null.
	 *
	 * @return array{id: string, at: int, minutes: int, by: int, booked_at: int}|null
	 */
	public static function booking(): ?array {
		wp_cache_delete( self::BOOKING, 'options' );
		$value = get_option( self::BOOKING, array() );
		return is_array( $value ) && isset( $value['at'], $value['minutes'] ) ? $value : null;
	}

	/** Whether a window is open now, or its summary is still owed. */
	private static function open_or_pending(): bool {
		$state = self::fresh();
		return array() !== $state && 'closed' !== ( $state['phase'] ?? '' );
	}

	/**
	 * Book a window to open by itself later, or change the one booked. One
	 * window at a time, booked or open. Recorded at once and never held, with
	 * who booked it, when it opens and how long it runs.
	 *
	 * @param string $local When it opens, as `Y-m-d\TH:i` on the site's clock.
	 * @return true|\WP_Error
	 */
	public static function book( string $local, int $minutes ) {
		if ( ! in_array( $minutes, self::LENGTHS, true ) ) {
			return new \WP_Error( 'bettershield_maintenance_duration', __( 'Choose 30 minutes, 1 hour, 2 hours or 4 hours.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$at = \DateTimeImmutable::createFromFormat( '!Y-m-d\TH:i', $local, wp_timezone() );
		if ( false === $at ) {
			return new \WP_Error( 'bettershield_maintenance_when', __( 'Enter the date and time the window should start.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$at = $at->getTimestamp();
		if ( $at < time() + self::BOOK_LEAD || $at > time() + self::BOOK_AHEAD ) {
			return new \WP_Error( 'bettershield_maintenance_when', __( 'Book a start at least 5 minutes from now and no more than 30 days ahead.', 'bettershield' ), array( 'status' => 400 ) );
		}
		self::tick();
		if ( ! Claim::claim( self::LOCK, 10 ) ) { return self::busy(); }
		try {
			if ( self::open_or_pending() ) {
				return new \WP_Error( 'bettershield_maintenance_active', __( 'A maintenance window is open or its summary is pending. End it first.', 'bettershield' ), array( 'status' => 409 ) );
			}
			$before = self::booking();
			// Booking the same start and length again changes nothing, so it
			// records nothing and emails nobody.
			if ( null !== $before && $at === (int) $before['at'] && $minutes === (int) $before['minutes'] ) {
				return true;
			}
			$booking = array( 'id' => wp_generate_uuid4(), 'at' => $at, 'minutes' => $minutes, 'by' => get_current_user_id(), 'booked_at' => time() );
			if ( ! update_option( self::BOOKING, $booking, false ) ) { return self::busy(); }
			wp_clear_scheduled_hook( self::OPEN_TASK );
			wp_schedule_single_event( $at, self::OPEN_TASK );
			// Who booked it is the row's own actor. High, and never held: an
			// alert path that will go quiet is told the moment it is set up.
			Writer::instance()->record(
				'maintenance_window_booked',
				Writer::SEVERITY_HIGH,
				array(
					'object_type' => 'maintenance',
					'object_id'   => $booking['id'],
					'context'     => array(
						'starts'  => gmdate( 'c', $at ),
						'until'   => gmdate( 'c', $at + $minutes * MINUTE_IN_SECONDS ),
						'minutes' => $minutes,
						'change'  => null === $before ? 'booked' : 'changed',
					),
				)
			);
			return true;
		} finally { Claim::release( self::LOCK ); }
	}

	/** @return true|\WP_Error */
	public static function cancel_booking() {
		if ( ! Claim::claim( self::LOCK, 10 ) ) { return self::busy(); }
		try {
			$booking = self::booking();
			if ( null === $booking ) {
				return new \WP_Error( 'bettershield_maintenance_not_booked', __( 'No maintenance window is booked.', 'bettershield' ), array( 'status' => 404 ) );
			}
			if ( ! delete_option( self::BOOKING ) ) { return self::busy(); }
			wp_clear_scheduled_hook( self::OPEN_TASK );
			Writer::instance()->record(
				'maintenance_booking_canceled',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'maintenance',
					'object_id'   => (string) $booking['id'],
					'context'     => array( 'starts' => gmdate( 'c', (int) $booking['at'] ) ),
				)
			);
			return true;
		} finally { Claim::release( self::LOCK ); }
	}

	/**
	 * Open a booked window that is due. It closes at the booked end however
	 * late it opens; one whose whole window has passed opens nothing and is
	 * recorded as missed.
	 */
	private static function open_booked(): void {
		$booking = self::booking();
		if ( null === $booking || (int) $booking['at'] > time() || ! Claim::claim( self::LOCK, 10 ) ) { return; }
		try {
			$booking = self::booking();
			if ( null === $booking || (int) $booking['at'] > time() ) { return; }
			$until = (int) $booking['at'] + (int) $booking['minutes'] * MINUTE_IN_SECONDS;
			if ( ! delete_option( self::BOOKING ) ) { return; }
			if ( $until <= time() || self::open_or_pending() ) {
				Writer::instance()->record( 'maintenance_booking_missed', Writer::SEVERITY_INFO, array( 'actor_type' => 'system', 'object_type' => 'maintenance', 'object_id' => (string) $booking['id'], 'context' => array( 'starts' => gmdate( 'c', (int) $booking['at'] ) ) ) );
				return;
			}
			self::open(
				$until,
				array(
					'booked_by' => (int) $booking['by'],
					'booked_at' => gmdate( 'c', (int) $booking['booked_at'] ),
				),
				(string) $booking['id']
			);
		} finally { Claim::release( self::LOCK ); }
	}

	/** @return true|\WP_Error */
	public static function start( int $minutes ) {
		if ( ! in_array( $minutes, array( 30, 60, 120, 240 ), true ) ) {
			return new \WP_Error( 'bettershield_maintenance_duration', __( 'Choose 30 minutes, 1 hour, 2 hours or 4 hours.', 'bettershield' ), array( 'status' => 400 ) );
		}
		self::tick();
		if ( ! Claim::claim( self::LOCK, 10 ) ) { return self::busy(); }
		try {
			if ( self::open_or_pending() ) {
				return new \WP_Error( 'bettershield_maintenance_active', __( 'The last maintenance window is still open or its summary is pending. End it first.', 'bettershield' ), array( 'status' => 409 ) );
			}
			// One window at a time, booked or open.
			if ( null !== self::booking() ) {
				return new \WP_Error( 'bettershield_maintenance_booked', __( 'A maintenance window is booked. Cancel the booking first, or change its time.', 'bettershield' ), array( 'status' => 409 ) );
			}
			return self::open( time() + $minutes * MINUTE_IN_SECONDS ) ? true : self::busy();
		} finally { Claim::release( self::LOCK ); }
	}

	/**
	 * Open a window that closes at `$until`, under the claim the caller holds.
	 *
	 * @param array<string, mixed> $booked Who booked it and when, for one booked ahead.
	 */
	private static function open( int $until, array $booked = array(), string $id = '' ): bool {
		$state = array( 'id' => '' !== $id ? $id : wp_generate_uuid4(), 'phase' => 'active', 'started' => Time::stamp(), 'until' => $until, 'counts' => array(), 'total' => 0, 'held' => 0 );
		if ( ! update_option( self::OPTION, $state, false ) ) { return false; }
		// A booked window opens by itself, so the row is the site's, and it
		// names who booked it and when.
		Writer::instance()->record( 'maintenance_window_started', Writer::SEVERITY_HIGH, array( 'object_type' => 'maintenance', 'object_id' => $state['id'], 'context' => array( 'until' => gmdate( 'c', $state['until'] ) ) + $booked ) + ( array() !== $booked ? array( 'actor_type' => 'system' ) : array() ) );
		// A missing cron does not extend the quiet period: holds() expires
		// by the clock and the independent hourly task retries the summary.
		wp_schedule_single_event( $state['until'], self::TASK );
		return true;
	}

	/** Capture only the batch the writer actually persisted. */
	public static function observe( array $events, array $context ): void {
		self::$held = array();
		if ( self::$closing ) {
			self::$dispatch_after_close = ! $context['front_end_get'] && ! $context['checkout'];
		}
		$state = self::state();
		if ( 'active' !== ( $state['phase'] ?? '' ) || (int) ( $state['until'] ?? 0 ) <= time() || ! Claim::claim( self::LOCK, 10 ) ) { return; }
		try {
			$state = self::fresh();
			if ( 'active' !== ( $state['phase'] ?? '' ) || (int) $state['until'] <= time() ) { return; }
			$held = array();
			$changed = false;
			foreach ( $events as $event ) {
				$type = (string) $event['event_type'];
				if ( (int) ( $event['site_id'] ?? -1 ) !== Schema::site_id( 'events' ) || (string) $event['occurred_at'] < $state['started'] || str_starts_with( $type, 'maintenance_' ) || str_starts_with( $type, 'alert_' ) ) { continue; }
				$expected = in_array( $type, self::EXPECTED, true );
				$key = $expected ? $type : 'other';
				$state['counts'][ $key ] = (int) ( $state['counts'][ $key ] ?? 0 ) + 1;
				++$state['total'];
				$changed = true;
				// This plugin's own switch-off is never held: the summary it
				// would wait for is sent by the plugin that was switched off.
				if ( $expected && Writer::SEVERITY_HIGH === (int) $event['severity'] && ! self::is_this_plugin( $event ) ) {
					++$state['held'];
					$held[ self::fingerprint( $event ) ] = true;
				}
			}
			if ( $changed && update_option( self::OPTION, $state, false ) ) { self::$held = $held; }
		} finally { Claim::release( self::LOCK ); }
	}

	private static function fingerprint( array $event ): string {
		return hash( 'sha256', (string) wp_json_encode( $event ) );
	}

	/** Whether an event is about this plugin's own file. */
	private static function is_this_plugin( array $event ): bool {
		return 'plugin' === (string) ( $event['object_type'] ?? '' ) && plugin_basename( BETTERSHIELD_FILE ) === (string) ( $event['object_id'] ?? '' );
	}

	public static function holds( array $event ): bool {
		return isset( self::$held[ self::fingerprint( $event ) ] );
	}

	public static function tick(): void {
		$state = self::state();
		if ( array() !== $state && 'closed' !== ( $state['phase'] ?? '' ) && (int) $state['until'] <= time() ) { self::end(); }
		// A booked window that is due opens here too, so an opening the
		// scheduler missed is made by the hourly task, late but never long.
		self::open_booked();
	}

	/** @return true|\WP_Error */
	public static function end() {
		if ( ! Claim::claim( self::LOCK, 10 ) ) { return self::busy(); }
		self::$closing = true;
		self::$dispatch_after_close = false;
		try {
			$state = self::fresh();
			if ( array() === $state || 'closed' === ( $state['phase'] ?? '' ) ) { return true; }
			if ( 'ending' !== $state['phase'] ) {
				$state['phase'] = 'ending';
				$state['until'] = min( time(), (int) $state['until'] );
				if ( ! update_option( self::OPTION, $state, false ) ) { return self::busy(); }
			}
			// The summary remains in the activity log after this single working
			// option is replaced by the next window. Retry a failed event write;
			// do not duplicate a summary persisted before a worker stopped.
			if ( ! self::summary_exists( $state['id'] ) ) {
				Writer::instance()->record( self::CLOSED, Writer::SEVERITY_INFO, array( 'object_type' => 'maintenance', 'object_id' => $state['id'], 'context' => self::summary( $state ) ) );
				Writer::instance()->flush();
				if ( ! self::summary_exists( $state['id'] ) ) { return self::busy(); }
			}
			$state['phase'] = 'closed';
			if ( ! update_option( self::OPTION, $state, false ) ) { return self::busy(); }
			wp_clear_scheduled_hook( self::TASK );
			return true;
		} finally {
			Claim::release( self::LOCK );
			self::$closing = false;
			if ( self::$dispatch_after_close ) {
				// Delivery may wait on a remote server; it must not outlive the
				// short database claim that protects window transitions.
				do_action( 'bettershield_maintenance_summary_ready' );
			}
		}
	}

	public static function defers_delivery(): bool { return self::$closing; }

	private static function summary_exists( string $id ): bool {
		global $wpdb;
		$table = Schema::table( 'events' );
		$scope = Schema::site_where( 'events' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin table and internal site predicate; values are prepared.
		return null !== $wpdb->get_var( $wpdb->prepare( "SELECT id FROM `$table` WHERE $scope AND event_type = %s AND object_id = %s LIMIT 1", self::CLOSED, $id ) );
	}

	private static function summary( array $state ): array {
		return array( 'started' => $state['started'], 'ended' => gmdate( 'c', $state['until'] ), 'total' => $state['total'], 'held' => $state['held'], 'counts' => $state['counts'] );
	}

	/** Bounded, credential-free summary copied into the existing delivery queues. */
	public static function event_summary( array $event ): ?array {
		if ( self::CLOSED !== ( $event['event_type'] ?? '' ) ) { return null; }
		$context = json_decode( (string) ( $event['context'] ?? '' ), true );
		return is_array( $context ) && isset( $context['counts'], $context['total'], $context['held'] ) ? $context : null;
	}

	public static function summary_text( array $summary ): string {
		$total = (int) $summary['total'];
		$held  = (int) $summary['held'];
		// Each count in its own plural, since one sentence carries two.
		/* translators: %d: how many events were recorded during maintenance. */
		$events = sprintf( _n( '%d event', '%d events', $total, 'bettershield' ), $total );
		/* translators: %d: how many alert emails were not sent during maintenance. */
		$alerts = sprintf( _n( '%d alert email', '%d alert emails', $held, 'bettershield' ), $held );
		$digest = \BetterShield\Alerts\Settings::instance()->settings()['digest'];
		// With nothing held back, the "didn't send" clause is left out rather
		// than reading "didn't send 0 alert emails". The digest is named only
		// where there is one to keep them (#1840).
		if ( $held < 1 ) {
			$lead = $digest
				/* translators: %s: how many events, e.g. "3 events". */
				? sprintf( __( 'During maintenance, BetterShield logged %s. You can see every event in BetterShield › Activity and in your weekly summary.', 'bettershield' ), $events )
				/* translators: %s: how many events, e.g. "3 events". */
				: sprintf( __( 'During maintenance, BetterShield logged %s. You can see every event in BetterShield › Activity.', 'bettershield' ), $events );
		} else {
			$lead = $digest
				? sprintf( /* translators: 1: how many events, e.g. "3 events", 2: how many alerts were not sent, e.g. "1 alert email". */ __( 'During maintenance, BetterShield logged %1$s and didn’t send %2$s. You can see every event in BetterShield › Activity and in your weekly summary.', 'bettershield' ), $events, $alerts )
				: sprintf( /* translators: 1: how many events, e.g. "3 events", 2: how many alerts were not sent, e.g. "1 alert email". */ __( 'During maintenance, BetterShield logged %1$s and didn’t send %2$s. You can see every event in BetterShield › Activity.', 'bettershield' ), $events, $alerts );
		}
		$lines = array( $lead );
		foreach ( (array) $summary['counts'] as $type => $count ) {
			// Counted as the weekly summary counts, "File change found × 947".
			$lines[] = sprintf(
				/* translators: 1: what happened, 2: how many times. */
				__( '%1$s × %2$d', 'bettershield' ),
				'other' === $type ? __( 'Other activity', 'bettershield' ) : Types::label( $type ),
				(int) $count
			);
		}
		// Indented as every other line of the alert is.
		return '  ' . implode( "\n  ", $lines );
	}

	private static function busy(): \WP_Error {
		return new \WP_Error( 'bettershield_maintenance_busy', __( 'The maintenance window could not be saved. Try again. Ordinary alerts continue if a count cannot be saved.', 'bettershield' ), array( 'status' => 503 ) );
	}
}
