<?php
/**
 * Hardening item: keep the sign-in page out of page caches.
 *
 * WordPress already asks browsers not to keep the sign-in page. A page cache
 * or CDN in front of it may not listen to that header alone, and then hands
 * every visitor one stored copy of a form built for somebody else. This adds
 * the signals those caches read on the sign-in page itself, wherever it has
 * been moved to: the `DONOTCACHEPAGE` constant most caching plugins honor,
 * `no-store` and `private` in Cache-Control, and the headers LiteSpeed, nginx
 * and CDNs read for their own caches. Nothing else is sent, and no other
 * page changes.
 *
 * A copy a cache already holds is not taken back by this; the cache's own
 * purge or exclusion does that.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SignInNoCache {

	public const ITEM = 'sign_in_no_cache';

	/**
	 * The headers sent, by name. `Cache-Control` replaces core's; the rest
	 * are each read by one kind of cache and ignored by everything else.
	 */
	public const HEADERS = array(
		'Cache-Control'             => 'no-store, no-cache, must-revalidate, max-age=0, private',
		'Pragma'                    => 'no-cache',
		'X-LiteSpeed-Cache-Control' => 'no-cache',
		'X-Accel-Expires'           => '0',
		'Surrogate-Control'         => 'no-store',
		'CDN-Cache-Control'         => 'no-store',
	);

	/**
	 * Caching plugins that keep a copy of pages, by main file, with the name
	 * a person knows them by. Each honors `DONOTCACHEPAGE`, and each also
	 * has an exclusion list of its own, which is what a copy already stored
	 * needs.
	 */
	private const CACHE_PLUGINS = array(
		'wp-super-cache/wp-cache.php'               => 'WP Super Cache',
		'w3-total-cache/w3-total-cache.php'         => 'W3 Total Cache',
		'wp-rocket/wp-rocket.php'                   => 'WP Rocket',
		'litespeed-cache/litespeed-cache.php'       => 'LiteSpeed Cache',
		'wp-fastest-cache/wpFastestCache.php'       => 'WP Fastest Cache',
		'cache-enabler/cache-enabler.php'           => 'Cache Enabler',
		'sg-cachepress/sg-cachepress.php'           => 'Speed Optimizer',
		'breeze/breeze.php'                         => 'Breeze',
		'hummingbird-performance/wp-hummingbird.php' => 'Hummingbird',
		'nginx-helper/nginx-helper.php'             => 'Nginx Helper',
		'wp-optimize/wp-optimize.php'               => 'WP-Optimize',
		'comet-cache/comet-cache.php'               => 'Comet Cache',
		'swift-performance-lite/performance.php'    => 'Swift Performance',
	);

	/**
	 * The CDNs a probe header names, by the header's lowercase name.
	 */
	private const CDN_HEADERS = array(
		'cf-cache-status'      => 'Cloudflare',
		'x-sucuri-cache'       => 'Sucuri',
		'x-kinsta-cache'       => 'Kinsta',
		'x-hcdn-cache-status'  => 'Hostinger CDN',
		'x-litespeed-cache'    => 'LiteSpeed',
		'x-varnish'            => 'Varnish',
		'x-fastcgi-cache'      => 'nginx',
		'x-nginx-cache'        => 'nginx',
	);

	/**
	 * @param array<string, mixed> $state Unused; runtime-only.
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		// Fires on the sign-in page wherever it answers, before any output.
		add_action( 'login_init', array( self::class, 'send' ), 0 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_action( 'login_init', array( self::class, 'send' ), 0 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'login_init', array( self::class, 'send' ) );
	}

	/**
	 * Say "do not keep this" in every way a cache in front of the sign-in
	 * page reads it.
	 */
	public static function send(): void {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- the name caching plugins read.
		}

		if ( headers_sent() ) {
			return;
		}

		foreach ( self::HEADERS as $name => $value ) {
			header( $name . ': ' . $value );
		}
	}

	/**
	 * The caching plugins active here, and the CDN or server cache the last
	 * check saw answering for the sign-in page: each may hold a copy made
	 * before this was applied, and needs its own exclusion or purge.
	 *
	 * @param array<int, array{header?: string}> $signals What the last check saw.
	 * @return string[] Names a person knows them by.
	 */
	public static function caches_to_exclude( array $signals = array() ): array {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$names = array();

		foreach ( self::CACHE_PLUGINS as $file => $name ) {
			if ( is_plugin_active( $file ) ) {
				$names[] = $name;
			}
		}

		foreach ( $signals as $signal ) {
			$header = strtolower( (string) ( $signal['header'] ?? '' ) );

			if ( isset( self::CDN_HEADERS[ $header ] ) ) {
				$names[] = self::CDN_HEADERS[ $header ];
			}
		}

		return array_values( array_unique( $names ) );
	}
}
