<?php
/**
 * Fix for "The site address is not HTTPS" (#1289).
 *
 * The panel checks the certificate the way Site Health does, switches both
 * addresses through the https_address item after the recovery pre-flight,
 * and then waits: the switch goes back on its own after five minutes unless
 * Keep HTTPS is pressed on this screen opened over HTTPS, which is the proof
 * the new address works for a browser.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Hardening\Item\HttpsAddress as Item;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\Preflight;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HttpsAddress {

	/**
	 * What the panel shows: where the site is, whether the switch can be
	 * offered here and why not, and the pending period while it runs.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$manager      = Manager::instance();
		$availability = Item::availability();
		$until        = Item::pending_until();

		return array(
			'address'       => (string) get_option( 'home' ),
			'https'         => Item::is_https(),
			// Switched by this item, and so undone by it.
			'switched'      => $manager->is_active( Item::ITEM ),
			'available'     => (bool) $availability['available'],
			'note'          => (string) ( $availability['note'] ?? '' ),
			'pending_until' => null === $until ? null : gmdate( 'c', $until ),
			// Asked on every read: Keep HTTPS works only on a request that
			// came over HTTPS, and the panel says so before it is pressed.
			'over_https'    => is_ssl(),
		);
	}

	/**
	 * Ask the site for its own front page over HTTPS, checking the
	 * certificate, and say what was found.
	 *
	 * @return array{ready: bool, problems: string[]}
	 */
	public static function check(): array {
		$problems = Item::problems();

		return array(
			'ready'    => array() === $problems,
			'problems' => $problems,
		);
	}

	/**
	 * Switch to HTTPS, after the recovery pre-flight.
	 *
	 * @param bool $override Whether the person went ahead past a failed pre-flight.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function apply( bool $override ) {
		$failure = Preflight::failure();

		if ( null !== $failure && ! $override ) {
			return Preflight::refusal( $failure );
		}

		$done = Manager::instance()->apply( Item::ITEM );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( null !== $failure ) {
			Preflight::overridden( $failure, Item::ITEM, 'dashboard' );
		}

		Auditor::run();

		return array(
			'notes' => $done['notes'],
			'state' => self::state(),
		);
	}

	/**
	 * Keep HTTPS: end the pending period, from a request over HTTPS.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function keep() {
		$done = Manager::instance()->act( Item::ITEM, 'keep' );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		// Kept, the address is settled, and the finding closes.
		Auditor::run();

		return array( 'state' => self::state() );
	}

	/**
	 * Put both addresses back now.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function undo() {
		$done = Manager::instance()->revert( Item::ITEM );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		Auditor::run();

		return array( 'state' => self::state() );
	}
}
