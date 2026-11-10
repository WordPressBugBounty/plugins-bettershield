<?php
/**
 * Fixes for three findings that answer to one of this plugin's own settings
 * (#2564): common usernames not refused, no proof of work at sign-in, and
 * pingbacks still open.
 *
 * Each makes the same change its screen would, through that screen's own
 * save, so the change has the same checks, the same activity row and the
 * same way back:
 *
 * - Common usernames: the Quick Setup's refusal of the names on offer,
 *   which never offers a name an account here holds. Saved through login
 *   protection's settings, so the settings ledger can put the list back.
 * - Proof of work: login protection's switch, only while sign-in protection
 *   is on, since the check needs both. Undone through the settings ledger.
 * - Pingbacks: the XML-RPC protection with pingbacks only, through the
 *   hardening manager, whose revert is its Undo. For sites that keep the
 *   rest of XML-RPC for an app or a connected service.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Hardening\Item\XmlRpc;
use BetterShield\Hardening\Manager;
use BetterShield\Login\Protection;
use BetterShield\Onboarding\QuickSetup;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SignInExtras {

	/** The settings surface the two sign-in fixes save through. */
	private const SURFACE = 'login_protection';

	/**
	 * What the common-usernames panel shows: the names it would refuse, how
	 * long one try of them pauses the connection, and whether the way back
	 * in is ready, which refusing them waits for.
	 *
	 * @return array{names: string[], minutes: int, recovery_ready: bool, recovery_receipt: string}
	 */
	public static function names_state(): array {
		$names = QuickSetup::common_names();

		return array(
			'names'            => array_values( $names['offered'] ),
			'minutes'          => (int) $names['minutes'],
			'recovery_ready'   => QuickSetup::recovery_ready(),
			// 'pending' when the recovery email is the way back and only the
			// owner's word that it arrived is missing.
			'recovery_receipt' => QuickSetup::recovery_receipt(),
		);
	}

	/**
	 * Refuse the common names on offer, as the Quick Setup does.
	 *
	 * @return array{names: string[], undo: string}|\WP_Error What was refused and the settings record that puts it back.
	 */
	public static function block_names() {
		$offered = QuickSetup::common_names()['offered'];

		if ( array() === $offered ) {
			return new \WP_Error( 'bettershield_nothing_to_block', __( 'Every common name is refused already, or an account here holds it. Nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$before = self::last_token();
		$done   = QuickSetup::block_common_names( array(), 'findings' );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		return array(
			'names' => array_values( $offered ),
			'undo'  => self::token_since( $before ),
		);
	}

	/**
	 * What the proof-of-work panel shows: whether sign-in protection is on,
	 * which the check needs as well.
	 *
	 * @return array{protection_on: bool, active: bool}
	 */
	public static function proof_state(): array {
		$settings = Protection::instance()->settings();

		return array(
			'protection_on' => ! empty( $settings['enabled'] ),
			'active'        => ! empty( $settings['enabled'] ) && ! empty( $settings['proof_of_work'] ),
		);
	}

	/**
	 * Ask for proof of work after wrong passwords: login protection's own
	 * switch, through its own save.
	 *
	 * @return array{undo: string}|\WP_Error The settings record that turns it off again.
	 */
	public static function turn_on_proof() {
		$settings = Protection::instance()->settings();

		// Turning protection itself on is a bigger change than this finding
		// asks for, and its screen says what it does.
		if ( empty( $settings['enabled'] ) ) {
			return new \WP_Error( 'bettershield_protection_off', __( 'Sign-in protection is off. Turn it on in Login & Access first.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! empty( $settings['proof_of_work'] ) ) {
			return new \WP_Error( 'bettershield_already_on', __( 'Proof of work is on already. Nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$before = self::last_token();
		$done   = Protection::instance()->update_settings( array( 'proof_of_work' => true ) );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		return array( 'undo' => self::token_since( $before ) );
	}

	/**
	 * Block pingbacks only: the XML-RPC protection with that scope, so the
	 * rest of XML-RPC keeps answering. Its Undo is the protection's revert.
	 *
	 * @return array{item: string}|\WP_Error
	 */
	public static function block_pingbacks() {
		$manager = Manager::instance();

		// Already on in any scope closes the finding; changing the scope is
		// the Hardening screen's choice, not this one's.
		if ( $manager->is_active( 'xmlrpc' ) ) {
			return new \WP_Error( 'bettershield_already_on', __( 'The XML-RPC protection is on already. Change what it blocks on the Hardening screen.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$done = $manager->apply( 'xmlrpc', array( 'scope' => XmlRpc::SCOPE_PINGBACKS ) );

		return is_wp_error( $done ) ? $done : array( 'item' => 'xmlrpc' );
	}

	/**
	 * The newest login-protection record still open, or ''.
	 */
	private static function last_token(): string {
		foreach ( SettingsLedger::recent( 1, SettingsLedger::SCOPE_SITE ) as $row ) {
			if ( self::SURFACE === $row['surface'] ) {
				return (string) $row['token'];
			}
		}

		return '';
	}

	/**
	 * The record the save just wrote: the newest one, where it is not the one
	 * that was newest before. '' when the save had nothing to record.
	 */
	private static function token_since( string $before ): string {
		$after = self::last_token();

		return $after !== $before ? $after : '';
	}
}
