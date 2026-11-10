<?php
/**
 * Hardening item: keep PHP errors off the page.
 *
 * A PHP warning printed into a page shows file paths, and sometimes a query
 * or a credential, to whoever loaded it. The usual fix is a line in
 * wp-config.php or the server's PHP settings; this turns PHP's
 * `display_errors` off from the plugin instead, as soon as it loads, on
 * every request, and touches no file. Logging is a separate setting and
 * carries on.
 *
 * What runs before this plugin loads (wp-config.php itself, must-use
 * plugins, plugins loaded earlier) can still print, and the finding's note
 * keeps the wp-config.php line for that. A server that does not let a
 * plugin change the setting is found out at apply, by reading it back.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Audit\Checks;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PhpErrorDisplay {

	public const ITEM = 'php_error_display';

	/** What display_errors was before this request turned it off. */
	private static ?string $before = null;

	/**
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( ! self::can_set() ) {
			return array(
				'available' => false,
				'reason'    => 'server_config',
				'note'      => __( 'This server does not let plugins change PHP settings. Set WP_DEBUG_DISPLAY to false in wp-config.php, or ask your host.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * Turn it off once to see that the server takes it, and put it back:
	 * enforcement turns it off for good once the item is saved.
	 *
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		unset( $options );

		$before = (string) ini_get( 'display_errors' );
		$took   = false !== ini_set( 'display_errors', '0' ) && ! Checks::display_errors_prints( (string) ini_get( 'display_errors' ) ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- turning it off is the item.

		ini_set( 'display_errors', $before ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- put back until the item is saved.

		if ( ! $took ) {
			return new \WP_Error( 'bettershield_ini_refused', __( 'This server did not let the plugin turn display_errors off, so nothing was changed. Set WP_DEBUG_DISPLAY to false in wp-config.php, or ask your host.', 'bettershield' ) );
		}

		return array(
			'tokens' => array(),
			'notes'  => array(),
		);
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		self::turn_off();

		// Again once every plugin has loaded, in case one turned it back on.
		add_action( 'plugins_loaded', array( self::class, 'turn_off' ), PHP_INT_MAX );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_action( 'plugins_loaded', array( self::class, 'turn_off' ), PHP_INT_MAX );

		if ( null !== self::$before ) {
			ini_set( 'display_errors', self::$before ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- what this request had before the item.
			self::$before = null;
		}
	}

	public static function turn_off(): void {
		if ( ! self::can_set() ) {
			return;
		}

		if ( null === self::$before ) {
			self::$before = (string) ini_get( 'display_errors' );
		}

		ini_set( 'display_errors', '0' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- turning it off is the item.
	}

	/**
	 * Whether pages are served without PHP errors in them, as far as this
	 * request can tell.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return ! Checks::display_errors_prints( (string) ini_get( 'display_errors' ) );
	}

	private static function can_set(): bool {
		if ( ! function_exists( 'ini_set' ) ) {
			return false;
		}

		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );

		return ! in_array( 'ini_set', $disabled, true );
	}
}
