<?php
/**
 * Plugin Name:       BetterShield
 * Plugin URI:        https://bettershield.ai
 * Description:       Security audit in plain language, 30 hardening fixes you can undo, two-factor authentication (2FA), passkeys, login protection and an activity log.
 * Version:           1.1.8
 * Requires at least: 6.7
 * Requires PHP:      8.0
 * Author:            WPDeveloper
 * Author URI:        https://wpdeveloper.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bettershield
 * Domain Path:       /languages
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * The floor, before a single file of this plugin is loaded.
 *
 * `Requires PHP` in the header is enforced by WordPress on activation and on
 * update, and nowhere else. An install that arrives any other way — a host
 * rolling PHP back, a MultiPHP switch, a staging copy restored on an older
 * stack, a folder uploaded over FTP or synced by a deploy tool — keeps
 * running against whatever PHP it lands on. This file parses everywhere; most
 * of `src/` does not, so without this the first PHP 8.0 signature the boot
 * reaches ends every request on the site with a parse error, and the screen
 * that could deactivate the plugin is one of them.
 *
 * WordPress itself serves on 7.4, so standing down leaves a working site.
 */
if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html(
				sprintf(
					/* translators: 1: the PHP version this site runs. 2: the version BetterShield needs. */
					__( 'BetterShield is not running: it needs PHP %2$s or newer, not %1$s. Nothing else is affected.', 'bettershield' ),
					PHP_VERSION,
					'8.0'
				)
			);
			echo '</p></div>';
		}
	);

	return;
}

define( 'BETTERSHIELD_VERSION', '1.1.8' );
define( 'BETTERSHIELD_FILE', __FILE__ );
define( 'BETTERSHIELD_PATH', __DIR__ );

require_once __DIR__ . '/src/Autoloader.php';

Autoloader::register();

/*
 * The abilities runtime, bundled and loaded through an autoloader that lets
 * several plugins ship the same package without colliding — the newest copy
 * wins and loads once. Required here, before anything registers an ability,
 * because registration happens on a hook this file arms.
 *
 * WordPress gained this API in 6.9 and the supported floor is older, so a site
 * below it gets the bundled copy and a site at or above it never loads the
 * bundle at all: the platform has the API, and twenty files of somebody else's
 * package on every request buy nothing. A site whose neighbor already loaded
 * the same package does not load it twice either. The readable check is what
 * makes a checkout with no build behave like a plugin without the feature
 * rather than a fatal error: nothing registers, the endpoint offers nothing,
 * and the connection screen says so.
 */
$bettershield_runtime = __DIR__ . '/dependencies/vendor/autoload_packages.php';

/*
 * Whether the platform provides the API decides what the bundle is allowed to
 * add beyond it. Asked of WordPress rather than of the symbol table: the
 * bundle loads under an autoloader several plugins may carry, so another one
 * can have loaded it before this file runs — and `function_exists` would then
 * answer for the bundle rather than for the platform.
 */
$bettershield_platform_had_api = Support\Runtime::platform_has_api();

if ( ! $bettershield_platform_had_api && ! defined( 'WP_ABILITIES_API_VERSION' ) && is_readable( $bettershield_runtime ) ) {
	require_once $bettershield_runtime;
}

/*
 * Outside the guard above, because the bundle may be loaded whether or not
 * this file loaded it. The package was written to run as a plugin of its own
 * and arms more than the API: an admin script on every screen, REST routes,
 * and sample abilities. Only the API was asked for; the rest comes back down,
 * and removing a hook nothing added costs nothing.
 */
Support\Runtime::arm( $bettershield_platform_had_api );

unset( $bettershield_runtime, $bettershield_platform_had_api );

/*
 * On one front-end page view in twenty, measure what this plugin costs that
 * visitor and report the answer on the dashboard. Armed here rather than on a
 * hook because the read it most needs to see is the next statement, which is
 * deliberately earlier than any hook. On the other nineteen it costs the checks
 * that decide not to measure — the request's method and address, and one random
 * draw — and nothing is hooked.
 */
Support\Cost::begin( microtime( true ) );

/*
 * Before anything else, and deliberately not on a hook: a sign-in key has to
 * be in place before the first thing that asks for one, and a drop-in or an
 * early plugin can ask before plugins_loaded. Reads one autoloaded option and
 * returns when the item is off.
 */
\BetterShield\Hardening\Item\AuthKeys::register_early();

register_activation_hook( __FILE__, array( Lifecycle::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Lifecycle::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( Plugin::class, 'boot' ) );

// Stop before WordPress loads other plugins; registration is timed separately.
Support\Cost::booted();
