<?php
/**
 * PSR-4 autoloader for the BetterShield namespace.
 *
 * Deliberately dependency-free: no Composer runtime, no vendor directory
 * in the distributed plugin.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Autoloader {

	/**
	 * Register the autoloader for the BetterShield\ prefix, mapped to src/.
	 */
	public static function register(): void {
		spl_autoload_register(
			static function ( string $class ): void {
				$prefix = __NAMESPACE__ . '\\';

				if ( ! str_starts_with( $class, $prefix ) ) {
					return;
				}

				$relative = substr( $class, strlen( $prefix ) );
				$path     = __DIR__ . '/' . str_replace( '\\', '/', $relative ) . '.php';

				if ( is_file( $path ) ) {
					require $path;
				}
			}
		);
	}
}
