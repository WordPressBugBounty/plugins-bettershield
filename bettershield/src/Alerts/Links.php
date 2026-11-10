<?php
/**
 * The addresses an alert points at.
 *
 * A link in an email outlives the release that wrote it: it sits in an inbox
 * for months and is followed long after the screen it names has been rebuilt.
 * So every one of them is an ordinary admin URL — built server-side, resolved
 * by the server, valid with JavaScript switched off, and surviving the sign-in
 * redirect on the way. A section address without a tab resolves to that
 * section's default tab without rewriting itself, which is what makes the short
 * form safe to send.
 *
 * Kept in one class because the shapes must not drift. A link that lands on a
 * dashboard instead of the finding it promised is a support ticket, and one
 * that 404s is worse.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Links {

	/**
	 * Marks a visit as having arrived from an alert, which is what lets the
	 * screen ask whether the alert was worth sending. Nothing is recorded by
	 * the parameter's presence alone.
	 */
	public const FROM_ALERT = 'from=alert';

	/**
	 * One specific finding, opened and scrolled to — never the report it lives
	 * in and never the dashboard.
	 */
	public static function finding( string $key ): string {
		return admin_url(
			'admin.php?page=bettershield-findings&finding=' . rawurlencode( $key ) . '&' . self::FROM_ALERT
		);
	}

	/**
	 * The findings report, opened on one of its statuses where one is named:
	 * the snoozed list, which its default Open view leaves out.
	 */
	public static function findings( string $status = '' ): string {
		return admin_url( 'admin.php?page=bettershield-findings' . ( '' !== $status ? '&status=' . rawurlencode( $status ) : '' ) . '&' . self::FROM_ALERT );
	}

	/**
	 * The incidents, where an incident's timeline and response plan are,
	 * rather than the unfiltered log (#2246).
	 */
	public static function incidents(): string {
		return admin_url( 'admin.php?page=bettershield-activity&tab=incidents&' . self::FROM_ALERT );
	}

	/**
	 * One assistant connection's calls, newest first: its timeline (#1880).
	 */
	public static function agent_timeline( string $connection ): string {
		return admin_url( 'admin.php?page=bettershield-activity&tab=agents&connection=' . rawurlencode( $connection ) . '&' . self::FROM_ALERT );
	}

	/** Agents › Connect, where a connected application is revoked. */
	public static function agent_connections(): string {
		return admin_url( 'admin.php?page=bettershield-agents&tab=connect&' . self::FROM_ALERT );
	}

	public static function activity(): string {
		return admin_url( 'admin.php?page=bettershield-activity&' . self::FROM_ALERT );
	}

	/**
	 * Where the owner turns any of this off. Named in every message, because a
	 * message that cannot be stopped from inside itself is the pattern this
	 * product exists not to repeat.
	 */
	public static function alert_settings(): string {
		return admin_url( 'admin.php?page=bettershield-settings&tab=alerts' );
	}
}
