<?php
/**
 * How to fix the findings whose cause is outside this plugin (#2430): the
 * server, the host, the domain's certificate, or a choice only a person can
 * make. Nothing here changes the site. The panel says what is wrong, who
 * usually fixes it and how, and Check again asks the check once more.
 *
 * Most of these checks read the site as it is, so asking again is an audit
 * run now. The certificate is read by a daily task that opens a connection,
 * which never happens in a request somebody is waiting on, so its Check
 * again queues that task; the audit after it decides. Undelivered alerts
 * close only when a message is accepted, so theirs sends the test alert.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Alerts\Mailer;
use BetterShield\Audit\Auditor;
use BetterShield\Cron\Runner;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Guidance {

	/** The findings answered with guidance and Check again. */
	public const KEYS = array(
		'certificate_expiring',
		'disk_space_low',
		'php_end_of_life',
		'default_table_prefix',
		'admin_user_id_one',
		'backup_plugin_not_visible',
		'plugins_directory_unclaimed',
		'alerts_undeliverable',
		'network_passkey_no_way_back',
		// Only for the person asking: their own password, changed on
		// their profile, is checked again from the panel.
		'passwords_below_policy',
	);

	/** The daily task that reads the certificate. */
	public const CERTIFICATE_TASK = 'bettershield_certificate_check';

	/** How often one finding may be asked again. */
	private const PACE_SECONDS = 10;

	/**
	 * What the panel needs beside the finding: the site's address, for the
	 * message to the host, and whether a look asked for is still running.
	 *
	 * @return array{address: string, checking: bool}
	 */
	public static function state( string $key ): array {
		$pending = Runner::pending_request();

		return array(
			'address'  => (string) wp_parse_url( home_url(), PHP_URL_HOST ),
			'checking' => 'certificate_expiring' === $key && is_array( $pending ) && self::CERTIFICATE_TASK === ( $pending['hook'] ?? '' ),
		);
	}

	/**
	 * Ask the finding's check again.
	 *
	 * @return array{open: bool, queued: bool, test: ?string}|\WP_Error
	 */
	public static function check_again( string $key, int $user_id ) {
		if ( ! in_array( $key, self::KEYS, true ) ) {
			return new \WP_Error( 'bettershield_guidance_unknown', __( 'This finding has no Check again.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( ! Claim::claim( 'finding_check_again_' . $key, self::PACE_SECONDS ) ) {
			return new \WP_Error( 'bettershield_guidance_paced', __( 'This was checked a moment ago. Try again in a few seconds.', 'bettershield' ), array( 'status' => 429 ) );
		}

		if ( 'certificate_expiring' === $key ) {
			$queued = Runner::instance()->request_run( self::CERTIFICATE_TASK, $user_id );

			if ( is_wp_error( $queued ) ) {
				return $queued;
			}

			return array(
				'open'   => Auditor::is_open( $key ),
				'queued' => true,
				'test'   => null,
			);
		}

		// Sent the way a live alert is; an accepted one clears the refusal.
		$test = 'alerts_undeliverable' === $key ? (string) Mailer::test()['outcome'] : null;

		Auditor::run();

		return array(
			'open'   => Auditor::is_open( $key ),
			'queued' => false,
			'test'   => $test,
		);
	}
}
