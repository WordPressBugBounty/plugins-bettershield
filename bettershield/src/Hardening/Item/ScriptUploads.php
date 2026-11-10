<?php
/**
 * Hardening item: keep script-carrying uploads to administrators.
 *
 * An SVG, HTML or JavaScript file uploaded to the media library is served
 * from the site's own address, so the script in it runs as part of the site
 * in whoever opens it. A PHP-type file can run on the server. A plugin that
 * adds one of these types to the upload list usually means administrators,
 * and the list it changes is everybody's.
 *
 * This takes the same types the finding looks for off the list for every
 * account below administrator, at the last priority so a plugin adding them
 * is answered after it. For an account that may publish unfiltered HTML,
 * HTML and JavaScript are WordPress's own answer, and only SVG and PHP types
 * go, matching the finding.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Audit\Checks;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScriptUploads {

	public const ITEM = 'script_uploads';

	/**
	 * Who widened the list, so the card can say whose feature stops working
	 * for editors and authors.
	 */
	public static function conflict(): ?string {
		$names = \BetterShield\Audit\CrossOrigin::owner_names( 'upload_mimes' );

		if ( array() === $names ) {
			return null;
		}

		return sprintf(
			/* translators: %s: a list of plugin or theme names. */
			__( 'Upload types are changed by: %s. Accounts below administrator lose any SVG, HTML, JavaScript or PHP type added there; administrators keep them.', 'bettershield' ),
			implode( ', ', $names )
		);
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		add_filter( 'upload_mimes', array( self::class, 'narrow' ), PHP_INT_MAX, 2 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'upload_mimes', array( self::class, 'narrow' ), PHP_INT_MAX );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_filter( 'upload_mimes', array( self::class, 'narrow' ) );
	}

	/**
	 * The upload list without the script-carrying types, for an account
	 * below administrator.
	 *
	 * @param array<string, string>  $types Extension pattern => MIME type.
	 * @param int|\WP_User|null|mixed $user  Whose list it is; the signed-in account when none is named.
	 * @return array<string, string>
	 */
	public static function narrow( $types, $user = null ): array {
		$types = (array) $types;

		if ( $user instanceof \WP_User ) {
			$account = $user;
		} elseif ( is_numeric( $user ) && (int) $user > 0 ) {
			$account = get_userdata( (int) $user );
		} else {
			$account = wp_get_current_user();
		}

		if ( ! $account instanceof \WP_User || user_can( $account, 'manage_options' ) ) {
			return $types;
		}

		$risky = array_merge( user_can( $account, 'unfiltered_html' ) ? array( 'svg', 'svgz' ) : Checks::SCRIPT_TYPES, Checks::PHP_TYPES );
		$out   = array();

		foreach ( $types as $pattern => $mime ) {
			$all  = explode( '|', strtolower( (string) $pattern ) );
			$kept = array_values( array_diff( $all, $risky ) );

			if ( count( $kept ) === count( $all ) ) {
				$out[ $pattern ] = $mime;
			} elseif ( array() !== $kept ) {
				$out[ implode( '|', $kept ) ] = $mime;
			}
		}

		return $out;
	}
}
