<?php
/**
 * Safe mode: pauses ALL plugin enforcement without deactivating the
 * plugin or losing any configuration.
 *
 * Time-limited by default and self-expiring, so a recovery action never
 * silently leaves a site unprotected forever. Entry and exit are always
 * logged.
 *
 * On a network there are two of them, and every reader answers to either.
 * A site's own recovery credential raises the site's mode and nothing else:
 * one site's operator does not decide what the sites beside it enforce. The
 * network's own credential raises the network's mode, which every site reads
 * beside its own — because a policy set above a site cannot be stood down by
 * that site's link, and a protection nobody can stand down is a way to be
 * locked out.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

use BetterShield\Events\Writer;
use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SafeMode {

	private const OPTION = 'bettershield_safe_mode_until';

	/**
	 * The network's own mode, in the network's options.
	 *
	 * A network option is a row read on the first ask of each request on a
	 * host with no persistent object cache — there is no autoload flag for
	 * sitemeta, so seeding it buys presence rather than a free read. That
	 * cost is why nothing here reads it on a single site, and why it is read
	 * after the site's own answer rather than before: a site already in safe
	 * mode never asks.
	 */
	public const NETWORK_OPTION = 'bettershield_network_safe_mode_until';

	public static function is_active(): bool {
		if ( (int) get_option( self::OPTION, 0 ) > time() ) {
			return true;
		}

		return self::is_network_active();
	}

	/**
	 * Whether this site's own pause is running, as against the network's.
	 * The two are ended from different places: a site ends its own, and only
	 * the network ends the network's.
	 */
	public static function is_site_active(): bool {
		return (int) get_option( self::OPTION, 0 ) > time();
	}

	/**
	 * Whether the network as a whole is stood down.
	 */
	public static function is_network_active(): bool {
		return self::network_until() > time();
	}

	/**
	 * Expiry timestamp while active, null otherwise.
	 *
	 * The later of the two on a network, because it is what a reader is told
	 * enforcement comes back at, and coming back while the other mode is
	 * still running would be untrue.
	 */
	public static function until(): ?int {
		$until = max( (int) get_option( self::OPTION, 0 ), self::network_until() );

		return $until > time() ? $until : null;
	}

	/**
	 * The network's expiry stamp, or zero on a single site.
	 */
	private static function network_until(): int {
		if ( ! is_multisite() ) {
			return 0;
		}

		return (int) get_network_option( null, self::NETWORK_OPTION, 0 );
	}

	/**
	 * Enter safe mode, and record the one entry.
	 *
	 * The door records nothing of its own: whatever it wants beside the
	 * entry — the codes it has left, say — travels here, so that one act is
	 * one row however it was reached.
	 *
	 * @param array<string, mixed> $context What the door adds to the record.
	 */
	public static function enter( int $duration_seconds, string $via, array $context = array() ): void {
		update_option( self::OPTION, time() + $duration_seconds, true );

		// Take effect in this request too, not only the next one.
		Manager::instance()->unenforce_all();

		// Locked out may mean the HTTPS address is why: a switch still
		// waiting, or one reached over plain HTTP, goes back (#1289).
		if ( in_array( $via, array( 'recovery_link', 'recovery_code' ), true ) ) {
			\BetterShield\Hardening\Item\HttpsAddress::stand_down();
		}

		Writer::instance()->record(
			'safe_mode_entered',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'safe_mode',
				'context'     => array_merge(
					$context,
					array(
						'duration_seconds' => $duration_seconds,
						'via'              => $via,
					)
				),
			)
		);
	}

	public static function end( string $reason ): void {
		if ( 0 === (int) get_option( self::OPTION, 0 ) ) {
			return;
		}

		delete_option( self::OPTION );

		// Re-arm active enforcement immediately.
		Manager::instance()->enforce();

		Writer::instance()->record(
			'safe_mode_exited',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'safe_mode',
				'context'     => array( 'reason' => $reason ),
			)
		);
	}

	/**
	 * Raise the mode for every site of the network.
	 *
	 * Reached only from the network's own recovery credential and the network
	 * dashboard, never from a site: a site's link stands down the site it was
	 * issued for, which is the boundary that keeps one operator out of another
	 * operator's posture.
	 *
	 * Enforcement on THIS site is dropped for the rest of the request the way
	 * the per-site entry does it. Every other site of the network reads the
	 * option on its own next request; there is no way to reach into a request
	 * that is not happening.
	 */
	public static function enter_network( int $duration_seconds, string $via ): void {
		update_network_option( null, self::NETWORK_OPTION, time() + $duration_seconds );

		Manager::instance()->unenforce_all();

		self::record_for_network(
			'network_safe_mode_entered',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'safe_mode',
				'context'     => array(
					'duration_seconds' => $duration_seconds,
					'via'              => $via,
				),
			)
		);
	}

	/**
	 * Record a network-wide act against the network, which is its main site,
	 * whichever site's address or URL served the request.
	 *
	 * Recorded against the serving subsite, the pause of every site went to
	 * that subsite's alert recipients only, and deleting the subsite took the
	 * network's only record of it with its rows (#2135). Flushed while
	 * switched, so the alert is the main site's too; what this request had
	 * already recorded is flushed first, under the site it belongs to.
	 *
	 * @param array<string, mixed> $args
	 */
	public static function record_for_network( string $type, int $severity, array $args ): void {
		if ( ! is_multisite() || is_main_site() ) {
			Writer::instance()->record( $type, $severity, $args );

			return;
		}

		Writer::instance()->flush();
		switch_to_blog( get_main_site_id() );

		try {
			Writer::instance()->record( $type, $severity, $args );
			Writer::instance()->flush();
		} finally {
			restore_current_blog();
		}
	}

	public static function end_network( string $reason ): void {
		if ( 0 === self::network_until() ) {
			return;
		}

		delete_network_option( null, self::NETWORK_OPTION );

		// Only where this site is not standing itself down as well; re-arming
		// under the site's own mode would undo what its own link just did.
		if ( ! self::is_active() ) {
			Manager::instance()->enforce();
		}

		self::record_for_network(
			'network_safe_mode_exited',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'safe_mode',
				'context'     => array( 'reason' => $reason ),
			)
		);
	}

	/**
	 * Self-expiry: called at boot; logs the exit exactly once.
	 *
	 * Both modes, because a network mode that lapsed with nothing said would
	 * leave the log claiming every site was stood down for as long as nobody
	 * looked. The network row is cleared by whichever site's request notices
	 * first, and the event lands on that site — one row for the network,
	 * rather than one per site per lapse.
	 */
	public static function maybe_expire(): void {
		$until = (int) get_option( self::OPTION, 0 );

		if ( $until > 0 && $until <= time() ) {
			delete_option( self::OPTION );

			Writer::instance()->record(
				'safe_mode_exited',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'safe_mode',
					'context'     => array( 'reason' => 'expired' ),
				)
			);
		}

		$network = self::network_until();

		if ( $network > 0 && $network <= time() ) {
			delete_network_option( null, self::NETWORK_OPTION );

			self::record_for_network(
				'network_safe_mode_exited',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'safe_mode',
					'context'     => array( 'reason' => 'expired' ),
				)
			);
		}
	}
}
