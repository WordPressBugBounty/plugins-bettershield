<?php
/**
 * Hardening item: keep BetterShield up to date by itself.
 *
 * The same switch as "Enable auto-updates" on BetterShield's row under
 * Plugins: this plugin's file added to the `auto_update_plugins` list core
 * keeps, the write core's own link makes. Undo takes it off the list again,
 * if it is still there.
 *
 * Not offered where the switch is not the owner's to flip: automatic
 * updates off for the site, file changes not allowed, plugin auto-updates
 * switched off, or a filter deciding it either way. On a network the list
 * is the network's, so it is offered on the main site to a network
 * administrator, who may set it there with the same undo (#2568).
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Audit\Checks;
use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OwnAutoUpdates {

	public const ITEM = 'own_auto_updates';

	/**
	 * @return array{available: bool, reason?: string, url?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( is_multisite() && ( ! is_main_site() || ! current_user_can( 'manage_network_plugins' ) ) ) {
			return array(
				'available' => false,
				'reason'    => 'network_admin',
				'note'      => __( 'On a network, a network administrator sets plugin auto-updates from the main site.', 'bettershield' ),
			);
		}

		if ( Manager::instance()->is_active( self::ITEM ) ) {
			return array(
				'available' => true,
				'note'      => null,
			);
		}

		switch ( Checks::own_auto_updates_decided() ) {
			case 'disabled':
				return array(
					'available' => false,
					'note'      => __( 'Automatic updates are off on this site, so this switch would do nothing.', 'bettershield' ),
				);
			case 'no_switch':
				return array(
					'available' => false,
					'note'      => __( 'Plugin auto-updates are switched off on this site, so there is no switch to turn on.', 'bettershield' ),
				);
			case 'forced':
				return array(
					'available' => false,
					'note'      => __( 'Code on this site already decides whether BetterShield updates itself.', 'bettershield' ),
				);
		}

		if ( self::listed() ) {
			return array(
				'available' => false,
				'note'      => __( 'BetterShield already updates itself.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		unset( $options );

		$list   = self::list();
		$list[] = plugin_basename( BETTERSHIELD_FILE );

		update_site_option( 'auto_update_plugins', array_values( array_unique( $list ) ) );

		if ( ! self::listed() ) {
			return new \WP_Error( 'bettershield_auto_update_not_saved', __( 'WordPress did not save the switch, so nothing was changed.', 'bettershield' ) );
		}

		return array(
			'tokens' => array(),
			'notes'  => array(),
		);
	}

	/**
	 * On a network the list is the network's: an administrator who may not
	 * set it may not empty it either, the same gate as availability and
	 * apply. Nobody signed in (a scheduled check, the command line) is the
	 * server's own undo and goes ahead.
	 *
	 * @return \WP_Error|null
	 */
	public static function refuse_revert(): ?\WP_Error {
		if ( ! is_multisite() || 0 === get_current_user_id() || current_user_can( 'manage_network_plugins' ) ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_network_admin_only',
			__( 'On a network, only a network administrator can turn BetterShield’s auto-updates off.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Take this plugin off the list, if it is still there.
	 *
	 * @param array<string, mixed> $state Unused.
	 * @return array{notes: string[]}
	 */
	public static function revert( array $state ): array {
		unset( $state );

		if ( ! self::listed() ) {
			return array( 'notes' => array( __( 'BetterShield’s auto-updates were already switched off, so nothing else changed.', 'bettershield' ) ) );
		}

		$file = plugin_basename( BETTERSHIELD_FILE );

		update_site_option( 'auto_update_plugins', array_values( array_diff( self::list(), array( $file ) ) ) );

		// The finding it closed opens again on the next screen.
		\BetterShield\Plugin::owe_audit();

		return array( 'notes' => array() );
	}

	/**
	 * Nothing to hook: the item is the stored switch itself.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );
	}

	/**
	 * Whether the switch is still on: switching it off under Plugins leaves
	 * the item reading on with nothing in force.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return self::listed();
	}

	private static function listed(): bool {
		return in_array( plugin_basename( BETTERSHIELD_FILE ), self::list(), true );
	}

	/**
	 * @return string[]
	 */
	private static function list(): array {
		return array_map( 'strval', (array) get_site_option( 'auto_update_plugins', array() ) );
	}
}
