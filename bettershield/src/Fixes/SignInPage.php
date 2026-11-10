<?php
/**
 * Fix for "The sign-in page is served from a page cache" (#2430).
 *
 * Applies the protection that keeps the sign-in page out of page caches,
 * through the hardening manager so it has the same Undo as every other
 * protection, then asks the sign-in page again, twice, as the check does,
 * and audits. A cache that still answers with a stored copy is named, so
 * the owner knows which one needs its own exclusion or purge.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\SignInCache;
use BetterShield\Hardening\Item\SignInNoCache;
use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SignInPage {

	/**
	 * What the panel shows: whether the protection is on, what the last
	 * check saw, and the caches that may still need their own exclusion.
	 *
	 * @return array{active: bool, address: string, cached: bool, reliable: bool, headers: string[], caches: string[], checked_at: string}
	 */
	public static function state(): array {
		$last    = SignInCache::last() ?? array();
		$signals = (array) ( $last['signals'] ?? array() );
		$headers = array();

		foreach ( $signals as $signal ) {
			$headers[] = (string) ( $signal['header'] ?? '' ) . ': ' . (string) ( $signal['value'] ?? '' );
		}

		return array(
			'active'     => Manager::instance()->is_active( SignInNoCache::ITEM ),
			'address'    => (string) ( $last['address'] ?? '' ),
			'cached'     => ! empty( $last['cached'] ),
			'reliable'   => ! empty( $last['reliable'] ),
			'headers'    => $headers,
			'caches'     => SignInNoCache::caches_to_exclude( $signals ),
			'checked_at' => (string) ( $last['checked_at'] ?? '' ),
		);
	}

	/**
	 * Switch the protection on, where it is not yet, and check again.
	 *
	 * @return array<string, mixed>|\WP_Error The panel's state after the check.
	 */
	public static function apply() {
		$manager = Manager::instance();

		if ( ! $manager->is_active( SignInNoCache::ITEM ) ) {
			$done = $manager->apply( SignInNoCache::ITEM );

			if ( is_wp_error( $done ) ) {
				return $done;
			}
		}

		return self::check();
	}

	/**
	 * Ask the sign-in page again and audit, so the finding follows.
	 *
	 * @return array<string, mixed>
	 */
	public static function check(): array {
		SignInCache::probe();
		Auditor::run();

		return self::state();
	}
}
