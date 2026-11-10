<?php
/**
 * The site's first file check and first probes, as the score's screens see them.
 *
 * Both can open findings no audit could know about yet, so any score shown
 * before they end could fall afterwards. They start when the Quick Setup opens,
 * and while they run, screens say so in place of a score that is about to
 * change, so the setup and the Overview never show two figures. What has been
 * found so far stays on screen: only the figure waits.
 *
 * The wait is bounded. A check that cannot finish, on a site whose scheduler
 * does not run, must not keep the score away for good, and past the wait the
 * score comes back with "files have not been checked" among its findings.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FirstScan {

	/** When the wait began. */
	public const OPTION = 'bettershield_first_scan';

	/**
	 * The scheduled tasks whose answers audits read. Until a task has answered,
	 * its findings cost nothing, so its first answer can lower the score.
	 */
	private const PROBES = array(
		'bettershield_artifact_probe',
		'bettershield_cross_origin_probe',
		\BetterShield\Audit\XmlRpc::TASK,
		'bettershield_folder_listing_probe',
		'bettershield_csp_reach',
		'bettershield_sign_in_cache_probe',
		'bettershield_domain_records',
		'bettershield_mixed_content',
		'bettershield_rest_surface',
		'bettershield_server_headers',
		'bettershield_certificate_check',
		'bettershield_directory_status',
		'bettershield_recovery_readiness',
	);

	/** How long the score waits for the check. */
	public const WAIT_SECONDS = 30 * MINUTE_IN_SECONDS;

	/**
	 * Start waiting, where this site has never finished a check, or on the
	 * setup's own opening, where a finished check may still leave probes owed.
	 *
	 * @param bool $setup_opening Whether the Quick Setup is opening.
	 */
	public static function begin( bool $setup_opening = false ): void {
		if ( array() !== self::stored() || ( ! $setup_opening && self::checked() ) ) {
			return;
		}

		update_option(
			self::OPTION,
			array(
				'at'     => time(),
				'probes' => self::PROBES,
			),
			false
		);
	}

	/**
	 * Whether the score is waiting for the check, and whether this reader may
	 * carry the check on from a screen.
	 *
	 * @return array{running: bool, drive: bool}
	 */
	public static function report(): array {
		$stored  = self::stored();
		$running = array() !== $stored
			&& ( ! self::checked() || array() !== ( $stored['probes'] ?? array() ) )
			&& time() - (int) $stored['at'] < self::WAIT_SECONDS;

		return array(
			'running' => $running,
			'drive'   => $running && current_user_can( Capabilities::MANAGE ),
		);
	}

	/**
	 * Run the next probe owed, once the check has finished, then audit after the
	 * last. One per request, so a screen can carry them on without a long wait.
	 *
	 * @return bool Whether a probe was run: the check itself is not to be started.
	 */
	public static function carry_on(): bool {
		$stored = self::stored();

		if ( ! self::report()['running'] || ! self::checked() || array() === ( $stored['probes'] ?? array() ) ) {
			return false;
		}

		$probe            = array_shift( $stored['probes'] );
		$stored['probes'] = array_values( $stored['probes'] );

		// Written first, so a probe that fails is not asked again by the next slice.
		update_option( self::OPTION, $stored, false );

		do_action( (string) $probe );

		if ( array() === $stored['probes'] ) {
			\BetterShield\Audit\Auditor::run();
		}

		return true;
	}

	/**
	 * Runs the site checks again, after the Quick Setup switched another
	 * security plugin off. Its headers, limits and other changes left with
	 * it, so the score waits for these checks again, as it does on a site
	 * that had no other plugin.
	 */
	public static function again(): void {
		update_option(
			self::OPTION,
			array(
				'at'     => time(),
				'probes' => self::PROBES,
			),
			false
		);
	}

	/**
	 * Whether the file check this site's score waits for has finished. A
	 * subsite of a network reads the main site's check rather than running
	 * one, so it has nothing to wait for; its own probes still run.
	 */
	private static function checked(): bool {
		return Shared::elsewhere() || null !== Scanner::last_result();
	}

	/**
	 * @return array{at?: int, probes?: string[]}
	 */
	private static function stored(): array {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) && is_int( $stored['at'] ?? null ) ? $stored : array();
	}
}
