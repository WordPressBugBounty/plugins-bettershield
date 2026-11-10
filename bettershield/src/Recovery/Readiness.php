<?php
/**
 * Scheduled recovery checks. Credentials are inspected, never exercised.
 * Mail acceptance is evidence about the sender, never proof of inbox delivery.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

use BetterShield\Alerts\Mailer;
use BetterShield\Alerts\Settings;
use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Readiness {
	public const MAIL_ENABLED = 'bettershield_recovery_test_mail';
	public const MAIL_RESULT  = 'bettershield_recovery_test_result';
	public const CHECKED_AT   = 'bettershield_recovery_checked_at';
	public const MAX_ADMINS   = 200;

	public static function mail_enabled(): bool {
		return (bool) get_option( self::MAIL_ENABLED, false );
	}

	public static function set_mail_enabled( bool $enabled ): bool {
		if ( $enabled === self::mail_enabled() ) {
			return true;
		}
		if ( ! update_option( self::MAIL_ENABLED, $enabled, false ) ) {
			return false;
		}
		Writer::instance()->record( 'setting_changed', Writer::SEVERITY_LOW, array(
			'object_type' => 'setting',
			'object_id'   => self::MAIL_ENABLED,
			'context'     => array( 'enabled' => $enabled ),
		) );
		return true;
	}

	/** Called on the schedule. */
	public static function run(): void {
		self::check( false );
	}

	/**
	 * Called by the person pressing Check now.
	 *
	 * A refused test is the one result the owner is told to go and fix, and
	 * this press is how they find out whether they did, so a refusal is sent
	 * again here rather than waiting out the week. So is a test that was for
	 * other recipients: the report stops counting it the moment they change,
	 * and the email path would read untested for the rest of the week. The
	 * route allows one press a minute and the send claim one attempt per five
	 * minutes; the schedule still waits the week, so mail that keeps failing
	 * is not retried daily.
	 */
	public static function run_now(): void {
		self::check( true );
	}

	private static function check( bool $on_demand ): void {
		// Destination changes invalidate the evidence, not the weekly cap of
		// the schedule; a person asking is told about the new destination.
		$previous = get_option( self::MAIL_RESULT, array() );
		$previous = is_array( $previous ) ? $previous : array();
		$due      = (int) ( $previous['at'] ?? 0 ) <= time() - WEEK_IN_SECONDS
			|| ( $on_demand && 'refused' === ( $previous['outcome'] ?? '' ) )
			|| ( $on_demand && ! hash_equals( self::destination(), (string) ( $previous['destination'] ?? '' ) ) );
		if ( self::mail_enabled() && $due ) {
			$settings = Settings::instance();
			$outcome = $settings->is_muted() ? 'muted' : ( array() === $settings->recipients() ? 'no_recipient' : '' );
			// Concurrent checks cannot send twice. Keep this short so a crashed
			// send can be retried by the next daily check; completed attempts
			// (including refusals) are limited to one per week by the result,
			// except that Check now sends a refused test again.
			if ( '' === $outcome && Claim::claim( 'recovery_readiness_mail', 5 * MINUTE_IN_SECONDS ) ) {
				// Written in each reader's language.
				$sent = Mailer::send(
					'recovery_readiness',
					static fn(): string => __( 'Weekly check: BetterShield emails reach you', 'bettershield' ),
					static fn(): string => __( 'BetterShield sends this once a week to make sure you’d get your recovery link and alerts by email. No action needed. It contains no sign-in details.', 'bettershield' )
				);
				$outcome = $sent ? 'accepted' : 'refused';
				update_option( self::MAIL_RESULT, array(
					'at' => time(), 'outcome' => $outcome,
					// Invalidate old acceptance when the destination changes.
					'destination' => self::destination(),
				), false );
			}
		}
		update_option( self::CHECKED_AT, time(), false );
		// Refresh findings in the same run, including resolution after repair.
		Auditor::run();
	}

	private static function destination(): string {
		$recipients = Settings::instance()->recipients();
		sort( $recipients );
		// The plugin's own key, not the salts: the keys fix moves the salts
		// (applied, rotated, undone), and every move threw the last result
		// away, so the email path read untested for up to a week.
		return hash_hmac( 'sha256', implode( "\n", $recipients ), \BetterShield\Support\ClientIp::signing_secret() );
	}

	private static function mail_result(): array {
		$result = get_option( self::MAIL_RESULT, array() );
		if ( ! is_array( $result ) || ! hash_equals( self::destination(), (string) ( $result['destination'] ?? '' ) ) ) {
			return array();
		}
		return $result;
	}

	/**
	 * Whether the recovery link works: `available`, or `missing`,
	 * `expired` or `refused` (the mailer turned it away). What the report
	 * and the preflight call a link, for screens that mention one.
	 */
	public static function link_state(): string {
		return ! RecoveryLink::link_exists() ? 'missing' : ( RecoveryLink::expired() ? 'expired' : ( false === Auditor::recovery_mail_result() ? 'refused' : 'available' ) );
	}

	/** Read-only report; no sends, credential consumption or unbounded scans. */
	public static function report(): array {
		$link = self::link_state();
		$codes = OfflineCodes::remaining();
		$roles = array();
		foreach ( wp_roles()->roles as $slug => $role ) {
			if ( ! empty( $role['capabilities']['manage_options'] ) ) {
				$roles[] = $slug;
			}
		}
		$query = new \WP_User_Query( array(
			// Query the current role inventory. Core's capability query calls
			// WP_Roles::for_site(), replacing request-local role definitions.
			'role__in' => $roles, 'include' => array() === $roles ? array( 0 ) : array(),
			'number' => self::MAX_ADMINS,
			'fields' => array( 'ID', 'user_email' ), 'count_total' => false,
			'orderby' => 'ID', 'order' => 'ASC',
		) );
		$admins = 0;
		foreach ( $query->get_results() as $user ) {
			if ( is_email( (string) $user->user_email ) ) {
				++$admins;
			}
		}
		$result = self::mail_result();
		$mail = ! self::mail_enabled() ? 'off' : ( Settings::instance()->is_muted() ? 'muted' : ( array() === Settings::instance()->recipients() ? 'no_recipient' : ( $result['outcome'] ?? 'untested' ) ) );
		if ( 'accepted' === $mail && (int) $result['at'] < time() - 8 * DAY_IN_SECONDS ) {
			$mail = 'stale';
		}
		$checked = (int) get_option( self::CHECKED_AT, 0 );
		$overdue = $checked <= time() - 2 * DAY_IN_SECONDS;
		// The way back is missing only with neither a working link nor a code
		// left, the rule the sign-in pre-flight refuses on: printed codes are
		// an addition to the link, and nobody holds any until they issue them,
		// so "no codes" alone flagged every new install with a good link.
		$no_way_back = 'available' !== $link && 0 === $codes;
		$report = array(
			'checked_at' => $checked > 0 ? gmdate( 'c', $checked ) : null,
			'overdue' => $overdue,
			'link' => $link,
			'link_expires_at' => null !== RecoveryLink::expires_at() ? gmdate( 'c', RecoveryLink::expires_at() ) : null,
			'link_mail' => Auditor::recovery_mail_result(),
			'offline_codes' => $codes,
			'offline_codes_issued' => OfflineCodes::ever_issued(),
			'administrators_with_email' => $admins,
			'admin_scan_limited' => count( $query->get_results() ) === self::MAX_ADMINS,
			'admin_scan_limit' => self::MAX_ADMINS,
			'email_tests' => self::mail_enabled(),
			'mail' => $mail,
			'mail_checked_at' => ! empty( $result['at'] ) ? gmdate( 'c', (int) $result['at'] ) : null,
			'needs_attention' => $overdue || $no_way_back || 0 === $admins || in_array( $mail, array( 'refused', 'muted', 'no_recipient', 'stale', 'untested' ), true ),
		);
		// Each way back in judged once, here, rather than by every reader.
		return $report + self::checks( $report );
	}

	/**
	 * Whether each way back in would work today, judged here so every reader
	 * of the report shows the site's answer: the recovery link, printed codes,
	 * an administrator with an email address, and the weekly email check. That
	 * last one is optional and off by default, so while it is off it is left
	 * out rather than counted against an owner with nothing to fix; untested
	 * is counted, as the report counts it as needing attention.
	 *
	 * @param array<string, mixed> $report What report() found.
	 * @return array{checks: array<int, array{key: string, ok: bool}>, ready: int, total: int}
	 */
	public static function checks( array $report ): array {
		$checks = array(
			array( 'key' => 'link', 'ok' => 'available' === ( $report['link'] ?? '' ) ),
			array( 'key' => 'codes', 'ok' => (int) ( $report['offline_codes'] ?? 0 ) > 0 ),
			array( 'key' => 'admin_address', 'ok' => (int) ( $report['administrators_with_email'] ?? 0 ) > 0 ),
		);
		if ( 'off' !== ( $report['mail'] ?? 'off' ) ) {
			$checks[] = array( 'key' => 'email_path', 'ok' => 'accepted' === $report['mail'] );
		}
		return array( 'checks' => $checks, 'ready' => count( array_filter( array_column( $checks, 'ok' ) ) ), 'total' => count( $checks ) );
	}

	public static function finding(): ?array {
		$report = self::report();
		if ( ! $report['needs_attention'] ) {
			return null;
		}
		return array(
			'link' => $report['link'], 'offline_codes' => $report['offline_codes'],
			'administrators_with_email' => $report['administrators_with_email'],
			'email_check' => $report['mail'], 'check_overdue' => $report['overdue'],
		);
	}
}
