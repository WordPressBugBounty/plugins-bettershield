<?php
/**
 * Hardening item: stop publishing the WordPress version.
 *
 * WordPress prints its version into every page's <head>, into feeds, and
 * onto every core script and stylesheet URL as `?ver=`, including the
 * combined ones the sign-in page loads. None of that is a
 * vulnerability on its own; all of it tells an automated scanner exactly
 * which exploits to try first.
 *
 * The asset version is replaced, not removed. Dropping `?ver=` would leave
 * browsers and CDNs holding stale core CSS across a core update; a keyed hash
 * of the version busts caches the same way and says nothing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VersionDisclosure {

	/**
	 * Core builds every generator tag — the page head's and each feed's —
	 * through a per-type filter; all of them are covered or the version keeps
	 * leaking through whichever was forgotten.
	 */
	private const GENERATOR_TYPES = array( 'html', 'xhtml', 'atom', 'rss2', 'rdf', 'comment', 'export' );

	/**
	 * Core's own tag is blanked first, before anything else on the same
	 * filter runs. A plugin that adds its own generator tag (WooCommerce
	 * appends one to the page head's) does it later on that filter, so its
	 * tag still prints: only the WordPress version is ours to remove.
	 * Blanking the combined `the_generator` output instead took those tags
	 * with it.
	 */
	private const GENERATOR_PRIORITY = PHP_INT_MIN;

	/**
	 * @param array<string, mixed> $state Unused; runtime-only.
	 */
	public static function enforce( array $state ): void {
		foreach ( self::GENERATOR_TYPES as $type ) {
			add_filter( 'get_the_generator_' . $type, array( self::class, 'blank_generator' ), self::GENERATOR_PRIORITY );
		}
		add_filter( 'script_loader_src', array( self::class, 'mask_core_version' ), 20 );
		add_filter( 'style_loader_src', array( self::class, 'mask_core_version' ), 20 );
		// A script module registered without a version of its own is served
		// with the WordPress version, through a filter of its own.
		add_filter( 'script_module_loader_src', array( self::class, 'mask_core_version' ), 20 );
		add_action( 'login_init', array( self::class, 'print_assets_one_by_one' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		foreach ( self::GENERATOR_TYPES as $type ) {
			remove_filter( 'get_the_generator_' . $type, array( self::class, 'blank_generator' ), self::GENERATOR_PRIORITY );
		}
		remove_filter( 'script_loader_src', array( self::class, 'mask_core_version' ), 20 );
		remove_filter( 'style_loader_src', array( self::class, 'mask_core_version' ), 20 );
		remove_filter( 'script_module_loader_src', array( self::class, 'mask_core_version' ), 20 );
		remove_action( 'login_init', array( self::class, 'print_assets_one_by_one' ) );
	}

	/**
	 * The sign-in page combines core's assets into one `load-styles.php` and
	 * one `load-scripts.php` address, and core builds those with the version
	 * and without the two filters above. It is the one public page that
	 * combines, so there each asset is printed on its own, through them —
	 * as on every other page a visitor can reach.
	 */
	public static function print_assets_one_by_one(): void {
		$GLOBALS['concatenate_scripts'] = false; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- core's own switch, which it settles only while unset; false is its value on every other public page.
	}

	/**
	 * The empty generator tag, as a method rather than `__return_empty_string`.
	 *
	 * Core keys a filter on the callback, and a plain function name is its own
	 * key — so every plugin registering `__return_empty_string` on these seven
	 * hooks at the same priority shares one slot with us, and our undo would
	 * remove theirs. A class method is a name nobody else registers.
	 */
	public static function blank_generator(): string {
		return '';
	}

	/**
	 * Whether printed generator output names the WordPress version.
	 *
	 * Not whether it is empty: with the item applied, another plugin's own
	 * generator tag still prints, and that is not the WordPress version.
	 * Every tag core builds names WordPress (or wordpress.org) beside the
	 * version.
	 */
	public static function names_core_version( string $printed ): bool {
		$version = (string) get_bloginfo( 'version' );

		return '' !== $version && false !== stripos( $printed, 'wordpress' ) && str_contains( $printed, $version );
	}

	/**
	 * Replace a `?ver=` that equals the WordPress version with a keyed hash of
	 * it. Only the core version is touched: a plugin's own version string is
	 * that plugin's business, and often not the WordPress version at all.
	 */
	public static function mask_core_version( string $src ): string {
		if ( '' === $src || ! str_contains( $src, 'ver=' ) ) {
			return $src;
		}

		$query = (string) wp_parse_url( $src, PHP_URL_QUERY );
		parse_str( $query, $args );

		if ( ! isset( $args['ver'] ) || (string) $args['ver'] !== self::core_version() ) {
			return $src;
		}

		return add_query_arg( 'ver', self::masked_version(), $src );
	}

	/**
	 * The version and its mask, held for the request.
	 *
	 * These two filters run once per enqueued asset, so a page with sixty of
	 * them asked sixty times — and each match then derived a key, because
	 * wp_salt() re-applies its filters on every call even from its own cache.
	 * This is a front-end path, and nothing on a front-end path recomputes a
	 * constant per asset.
	 */
	private static string $core_version = '';

	private static string $masked = '';

	private static function core_version(): string {
		if ( '' === self::$core_version ) {
			self::$core_version = (string) get_bloginfo( 'version' );
		}

		return self::$core_version;
	}

	/**
	 * Stable for a given core version and site, unrecognizable as a version.
	 */
	public static function masked_version(): string {
		if ( '' === self::$masked ) {
			self::$masked = substr( hash_hmac( 'sha256', self::core_version(), wp_salt( 'nonce' ) ), 0, 10 );
		}

		return self::$masked;
	}
}
