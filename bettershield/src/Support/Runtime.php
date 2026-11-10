<?php
/**
 * The bundled abilities runtime, trimmed to the API and nothing else.
 *
 * This plugin carries the Abilities API for sites below the WordPress release
 * that ships it. The package it carries was written to run as a plugin of its
 * own, and when it loads it arms more than the API: a script on every admin
 * page, REST routes listing every ability, and the platform's own sample
 * abilities. None of that is what this plugin asked for, and two of the three
 * are wrong on any site — a script this plugin did not write, on screens that
 * are not its own, and routes a current platform already serves itself.
 *
 * So the runtime is loaded, and then what it armed beyond the API is taken
 * back down:
 *
 * - The admin script, always. This plugin enqueues on its own screens only.
 * - The REST routes, on a platform that already has the API — it registers
 *   its own — and, below that platform, unless the owner has opted into agent
 *   access. Abilities register only when the owner says so, and a route that
 *   lists them is part of the same surface.
 * - The platform's sample abilities, below that platform, on the same opt-in:
 *   with the switch on, the site behaves like the platform it would have if it
 *   were current; with it off, like nothing was added. On a current platform
 *   these hooks are the platform's own and are left alone.
 *
 * Done twice: as soon as the runtime is included, and again once every plugin
 * has loaded, because the autoloader the runtime ships with can defer to a
 * newer copy carried by another plugin and load the files then instead.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Abilities\Registrar;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Runtime {

	/** The WordPress release that provides the Abilities API itself. */
	public const PLATFORM_VERSION = '6.9';

	/** What the runtime hooks that this plugin takes down again. */
	private const ASSETS_REGISTER = array( 'WP_Abilities_Assets_Init', 'register_assets' );
	private const ASSETS_ENQUEUE  = array( 'WP_Abilities_Assets_Init', 'admin_enqueue_scripts' );
	private const REST_ROUTES     = array( 'WP_REST_Abilities_Init', 'register_routes' );
	private const CORE_CATEGORIES = 'wp_register_core_ability_categories';
	private const CORE_ABILITIES  = 'wp_register_core_abilities';

	/**
	 * Whether WordPress itself provides the Abilities API.
	 *
	 * A fact about the platform, so it is asked of the platform.
	 * `function_exists( 'wp_register_ability' )` cannot answer it: the bundle
	 * loads under a shared autoloader that several plugins may carry, that
	 * autoloader caches the list of participants and any of them may load
	 * first, and the function then exists because of the bundle rather than
	 * because of WordPress. Answering that question wrongly on a 6.7 or 6.8
	 * site leaves the platform's own sample abilities registered with the
	 * owner's opt-in off, and strips the abilities REST routes from a site
	 * that opted in and has nothing else to serve them.
	 *
	 * @param string|null $version The version to judge; the running one by default.
	 */
	public static function platform_has_api( ?string $version = null ): bool {
		$version = null === $version ? (string) ( $GLOBALS['wp_version'] ?? '' ) : $version;

		return '' !== $version && version_compare( $version, self::PLATFORM_VERSION, '>=' );
	}

	/**
	 * Take down what the runtime armed, now and again after every plugin has
	 * loaded.
	 *
	 * @param bool $platform_had_api Whether the API existed before the runtime
	 *                               was included — that is, whether the platform
	 *                               itself provides it.
	 */
	public static function arm( bool $platform_had_api ): void {
		$trim = static function () use ( $platform_had_api ): void {
			self::trim( $platform_had_api, Registrar::is_enabled() );
		};

		$trim();

		// After the autoloader's own conflict check, which runs at priority 1
		// and may be what actually loads the files.
		add_action( 'plugins_loaded', $trim, 2 );
	}

	/**
	 * The removals themselves, decided by two facts and nothing else.
	 *
	 * Pure so it can be exercised: a test arms the hooks and asks what is
	 * left. Removing a hook that was never added is a no-op, so this is safe
	 * to run on a site with no runtime at all.
	 *
	 * @param bool $platform_had_api Whether the platform provides the API itself.
	 * @param bool $opted_in         Whether the owner has turned agent access on.
	 */
	public static function trim( bool $platform_had_api, bool $opted_in ): void {
		remove_action( 'init', self::ASSETS_REGISTER );
		remove_action( 'admin_enqueue_scripts', self::ASSETS_ENQUEUE );

		if ( $platform_had_api ) {
			// The platform registers its own routes through its own classes;
			// the runtime's registration would only re-register the same ones.
			// Its sample abilities are hooked by the platform under the same
			// names, so those stay: removing them here would remove the
			// platform's own.
			remove_action( 'rest_api_init', self::REST_ROUTES, 11 );

			return;
		}

		if ( $opted_in ) {
			return;
		}

		remove_action( 'rest_api_init', self::REST_ROUTES, 11 );
		remove_action( 'wp_abilities_api_categories_init', self::CORE_CATEGORIES );
		remove_action( 'wp_abilities_api_init', self::CORE_ABILITIES );
	}
}
