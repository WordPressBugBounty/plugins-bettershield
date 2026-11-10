<?php
/**
 * How the alerts this site sent were received.
 *
 * An alerting system nobody trusts is worse than none, and the only way to know
 * whether it is trusted is to let the reader say an alert was not worth
 * sending. This counts those answers against the alerts that were actually
 * delivered, and the result is shown to the owner on the same screen where they
 * can turn any of it off — a rate that is only ever read by the people who
 * built the thing is not a check on anything.
 *
 * Counted from the activity log rather than from a running total kept beside
 * it, so there is one source of truth and no counter to drift. The consequence
 * is that the window is the log's own retention, which is stated rather than
 * hidden: a rate over an unnamed period is a number that cannot be argued with.
 *
 * @package BetterShield
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
 * -- the plugin-owned events table, for which no core API exists.
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Support\Tier;
use BetterShield\Database\Schema;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Precision {

	/**
	 * Alerts sent and alerts called unhelpful over the window the log keeps,
	 * with the rate where there is enough to compute one.
	 *
	 * @return array{window_days: int, sent: int, unhelpful: int, rate: ?float}
	 */
	private static function since(): string {
		return ( new \DateTimeImmutable( '-' . Tier::retention_days() . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}

	public static function rate(): array {
		global $wpdb;
		$table = Schema::table( 'events' ); $scope = Schema::site_where( 'events' ); $since = self::since();
		// Count deliveries and distinct delivery opinions in one snapshot. Old
		// unbound finding feedback and failed/test sends cannot enter the ratio.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- aliases prefix a trusted site predicate; all values and identifiers are prepared.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS sent, COALESCE(SUM(EXISTS(SELECT 1 FROM %i f WHERE f.$scope AND f.event_type='alert_feedback' AND f.context LIKE %s AND f.object_id=CAST(s.id AS CHAR) AND f.occurred_at>%s)),0) AS unhelpful FROM %i s WHERE s.$scope AND s.event_type='alert_sent' AND s.occurred_at>%s AND s.context LIKE %s AND s.object_id<>'test'", $table, '%"delivery_bound":true%', $since, $table, $since, '%"sent":true%' ), ARRAY_A );
		$available = '' === $wpdb->last_error && is_array( $row );
		$sent = (int) ( $row['sent'] ?? 0 ); $unhelpful = (int) ( $row['unhelpful'] ?? 0 );
		return array( 'available' => $available, 'window_days' => Tier::retention_days(), 'sent' => $sent, 'unhelpful' => $unhelpful, 'rate' => $available && $sent > 0 ? round( $unhelpful / $sent, 3 ) : null );
	}

	/** One opinion per successfully delivered message, even across readers/reloads. */
	public static function feedback( string $delivery ) {
		if ( ! current_user_can( \BetterShield\Capabilities::MANAGE ) ) { return new \WP_Error( 'rest_forbidden', __( 'Not allowed.', 'bettershield' ), array( 'status' => 403 ) ); }
		if ( ! preg_match( '/\A[0-9a-f]{32}\z/D', $delivery ) ) { return self::missing(); }
		global $wpdb;
		$table = Schema::table( 'events' ); $scope = Schema::site_where( 'events' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- trusted site predicate and opaque receipt, no caller-supplied SQL.
		$id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM %i WHERE $scope AND event_type='alert_sent' AND occurred_at>%s AND object_id<>'test' AND context LIKE %s AND context LIKE %s ORDER BY id DESC LIMIT 1", $table, self::since(), '%"sent":true%', '%"delivery":"' . $wpdb->esc_like( $delivery ) . '"%' ) );
		if ( '' !== $wpdb->last_error ) { return self::unavailable(); }
		if ( ! $id ) { return self::missing(); }
		$key = 'alert_feedback:' . $id;
		if ( ! \BetterShield\Support\Claim::claim( $key, 30 ) ) { return self::unavailable(); }
		try {
			$recorded = self::recorded( (int) $id );
			if ( null === $recorded ) { return self::unavailable(); }
			if ( ! $recorded ) {
				\BetterShield\Events\Writer::instance()->record( 'alert_feedback', \BetterShield\Events\Writer::SEVERITY_INFO, array( 'object_type' => 'alert', 'object_id' => (string) $id, 'context' => array( 'helpful' => false, 'delivery_bound' => true ) ) );
				\BetterShield\Events\Writer::instance()->flush();
				if ( true !== self::recorded( (int) $id ) ) { return self::unavailable(); }
			}
			return array( 'recorded' => true, 'precision' => self::rate() );
		} finally { \BetterShield\Support\Claim::release( $key ); }
	}

	private static function recorded( int $id ): ?bool {
		global $wpdb;
		$scope = Schema::site_where( 'events' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- trusted site predicate; delivery row ID is server-derived.
		$found = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM %i WHERE $scope AND event_type='alert_feedback' AND context LIKE %s AND object_id=%s LIMIT 1", Schema::table( 'events' ), '%"delivery_bound":true%', (string) $id ) );
		return '' !== $wpdb->last_error ? null : (bool) $found;
	}
	private static function missing(): \WP_Error { return new \WP_Error( 'bettershield_alert_receipt_missing', __( 'This feedback needs a link from a delivered alert still in the activity history.', 'bettershield' ), array( 'status' => 400 ) ); }
	private static function unavailable(): \WP_Error { return new \WP_Error( 'bettershield_alert_feedback_unavailable', __( 'Feedback could not be recorded. Please try again.', 'bettershield' ), array( 'status' => 503 ) ); }
}
