<?php
/**
 * One check before a change to how people sign in: is there a way back in,
 * and was it looked at within the last day.
 *
 * A person on the dashboard or the command line changing the sign-in address,
 * the dashboard gate or a two-factor requirement met no recovery check at all,
 * while an agent making the same change met one. This is the check they share.
 * It refuses with the reason and where it is fixed, and a person may go ahead
 * anyway with a second, explicit confirmation, which is recorded with the
 * check that failed.
 *
 * Kept out of the settings writers themselves: an undo and a settings import
 * call those, and putting a change back must never be refused.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Preflight {

	/** No recovery link that works and no printed code left. */
	public const NO_WAY_BACK = 'no_way_back';

	/** The recovery options were not checked within the last day. */
	public const STALE = 'stale';

	/**
	 * Null when a sign-in change may go ahead; otherwise the first check that
	 * failed, what it means, where it is fixed, and whether pressing Check
	 * now could clear it.
	 *
	 * The way back is the recovery link that is live and was not refused by
	 * the mailer, or a printed code not yet used — either is enough. Backup
	 * visibility is deliberately not a check: a host's backups are never
	 * visible to a plugin, so refusing on it would refuse almost every site.
	 *
	 * @return array{check: string, message: string, url: string, can_check_now: bool}|null
	 */
	public static function failure(): ?array {
		$report = Readiness::report();
		$url    = admin_url( 'admin.php?page=bettershield-protect&tab=recovery' );

		if ( 'available' !== ( $report['link'] ?? '' ) && (int) ( $report['offline_codes'] ?? 0 ) < 1 ) {
			return array(
				'check'         => self::NO_WAY_BACK,
				'message'       => __( 'You have no working recovery link or recovery codes. Set one up under Protection → Recovery before changing sign-in settings.', 'bettershield' ),
				'url'           => $url,
				'can_check_now' => false,
			);
		}

		$checked = null === ( $report['checked_at'] ?? null ) ? 0 : (int) strtotime( (string) $report['checked_at'] );

		if ( $checked <= time() - DAY_IN_SECONDS ) {
			return array(
				'check'         => self::STALE,
				'message'       => 0 === $checked
					? __( 'Recovery options were never checked. Check them before changing sign-in settings.', 'bettershield' )
					: __( 'Recovery options were last checked over a day ago. Check them before changing sign-in settings.', 'bettershield' ),
				'url'           => $url,
				'can_check_now' => true,
			);
		}

		return null;
	}

	/**
	 * The refusal a route answers with. The failure travels in the error's
	 * data so a screen can offer Check now and the second confirmation.
	 *
	 * @param array{check: string, message: string, url: string, can_check_now: bool} $failure
	 */
	public static function refusal( array $failure ): \WP_Error {
		// The code a screen recognizes to offer Check now and Go ahead anyway.
		return new \WP_Error(
			'bettershield_recovery_preflight',
			$failure['message'],
			array(
				'status'    => 409,
				'preflight' => $failure,
			)
		);
	}

	/**
	 * Record that a person went ahead anyway, naming the check that failed,
	 * the change it was for and where it was made.
	 *
	 * @param array{check: string} $failure
	 * @param string               $change The hardening item or setting changed.
	 * @param string               $via    'dashboard' or 'cli'.
	 */
	public static function overridden( array $failure, string $change, string $via ): void {
		Writer::instance()->record(
			'recovery_preflight_overridden',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => $change,
				'context'     => array(
					'check' => $failure['check'],
					'via'   => $via,
				),
			)
		);
	}
}
