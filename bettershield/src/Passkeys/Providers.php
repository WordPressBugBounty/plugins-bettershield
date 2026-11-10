<?php
/** Display names for passkey providers; never an authentication or trust decision. @package BetterShield */
declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class Providers {

	/** A browser may hide or change its AAGUID. Unknown providers keep a neutral name. */
	public static function name( string $bytes ): string {
		if ( 16 !== strlen( $bytes ) || str_repeat( "\0", 16 ) === $bytes ) { return __( 'Passkey', 'bettershield' ); }
		$hex = bin2hex( $bytes );
		$id = substr( $hex, 0, 8 ) . '-' . substr( $hex, 8, 4 ) . '-' . substr( $hex, 12, 4 ) . '-' . substr( $hex, 16, 4 ) . '-' . substr( $hex, 20 );
		$path = __DIR__ . '/provider-names.json';
		$names = json_decode( (string) @file_get_contents( $path, false, null, 0, 65536 ), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- A missing bundled file falls back to the neutral name.
		return is_array( $names ) && isset( $names[ $id ] ) && is_string( $names[ $id ] ) ? $names[ $id ] : __( 'Passkey', 'bettershield' );
	}
}
