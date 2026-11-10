<?php
/**
 * How many protections are on, worked out once for every screen that says so.
 *
 * Each screen used to count for itself: the Overview's tile, its card, the
 * Hardening strip and Login & Access all gave different numbers for one site
 * (#2716). Every protection sits on one tab, so the two tabs' counts add up to
 * the whole.
 *
 * A protection the server or another plugin already provides counts as on,
 * because it is. Sign-in limits count only while they can run: with visitors'
 * addresses unreadable, turned on is not the same as working.
 *
 * Read on the Overview and Protection screens, so only the answers that take no
 * request of their own are asked for here.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

use BetterShield\Login\Protection;
use BetterShield\Onboarding\SafeFixes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProtectionCount {

	/**
	 * @return array{on: int, total: int, screens: array{hardening: array{on: int, total: int}, login: array{on: int, total: int}}}
	 */
	public static function all(): array {
		$screens = array(
			'hardening' => array( 'on' => 0, 'total' => 0 ),
			'login'     => array( 'on' => 0, 'total' => 0 ),
		);

		$definitions = Items::all();
		$groups      = Items::groups();
		$manager     = Manager::instance();

		foreach ( Items::ids() as $id ) {
			$group  = (string) ( $definitions[ $id ]['group'] ?? '' );
			$screen = 'login' === ( $groups[ $group ]['screen'] ?? '' ) ? 'login' : 'hardening';

			++$screens[ $screen ]['total'];

			if ( $manager->is_active( $id ) || SafeFixes::enforced_without_us( $id ) ) {
				++$screens[ $screen ]['on'];
			}
		}

		foreach ( self::sign_in_switches() as $on ) {
			++$screens['login']['total'];

			if ( $on ) {
				++$screens['login']['on'];
			}
		}

		return array(
			'on'      => $screens['hardening']['on'] + $screens['login']['on'],
			'total'   => $screens['hardening']['total'] + $screens['login']['total'],
			'screens' => $screens,
		);
	}

	/**
	 * The settings on Login & Access that aren't hardening items.
	 *
	 * @return bool[]
	 */
	private static function sign_in_switches(): array {
		$protection = Protection::instance();
		$settings   = $protection->settings();

		$switches = array(
			! empty( $settings['attempt_limit'] ) && ! empty( $protection->resolution_report()['confident'] ),
			! empty( $settings['honeypot'] ),
			! empty( $settings['proof_of_work'] ),
			! empty( $settings['new_location_notice'] ),
		);

		foreach ( $settings['surfaces'] as $policy ) {
			$switches[] = ! empty( $policy['enabled'] );
		}

		return $switches;
	}
}
