<?php
/**
 * Our screens carry our notices, and nobody else's.
 *
 * WordPress prints every plugin's admin notices on every admin screen, above
 * whatever the screen draws. On these screens that put other plugins' sales
 * banners, review requests and setup nags above a security report — and left
 * the reader to work out which of the boxes over the report were about the
 * report. A notice about this site's security belongs to this plugin, and is
 * kept; the rest are left for the screens they were written for.
 *
 * Only notice hooks are touched, only on our own screens, and only for the
 * request being drawn: nothing is unregistered from any other screen.
 *
 * @package BetterShield
 */

namespace BetterShield\Admin;

defined( 'ABSPATH' ) || exit;

/**
 * Removes other code's admin notices from the screens this plugin draws.
 */
final class Quiet {

	/**
	 * The hooks WordPress prints notices from, per admin area.
	 */
	private const NOTICE_HOOKS = array(
		'admin_notices',
		'all_admin_notices',
		'network_admin_notices',
		'user_admin_notices',
	);

	/**
	 * Namespaces whose notices stay: this plugin's and its add-on's.
	 *
	 * Matched as a prefix, so `BetterShieldUltra\` is covered by the second
	 * entry and nothing that merely contains the name is.
	 */
	private const OURS = array( 'BetterShield\\', 'BetterShieldUltra\\' );

	/**
	 * Hook suffixes of the screens this plugin draws.
	 *
	 * @var array<string, true>
	 */
	private static array $screens = array();

	private static bool $registered = false;

	/**
	 * Listen for our screens being drawn. Safe to call more than once.
	 */
	public static function register(): void {
		if ( self::$registered ) {
			return;
		}

		self::$registered = true;

		/*
		 * `in_admin_header` is the last action before the notice hooks fire
		 * in admin-header.php, and it fires only when a screen is actually
		 * being drawn — so everything registered by then, from any plugin at
		 * any priority, is already in place to be taken out.
		 */
		add_action( 'in_admin_header', array( self::class, 'silence' ), PHP_INT_MAX );
	}

	/**
	 * Mark a screen as one of ours, by the hook suffix its registration returned.
	 *
	 * @param string $hook The page hook suffix.
	 */
	public static function claim( string $hook ): void {
		if ( '' !== $hook ) {
			self::$screens[ $hook ] = true;
		}
	}

	/**
	 * Take every notice that is not ours off the screen being drawn, if it is ours.
	 */
	public static function silence(): void {
		global $hook_suffix, $wp_filter;

		if ( ! is_string( $hook_suffix ) || ! isset( self::$screens[ $hook_suffix ] ) ) {
			return;
		}

		foreach ( self::NOTICE_HOOKS as $name ) {
			if ( ! isset( $wp_filter[ $name ] ) || ! $wp_filter[ $name ] instanceof \WP_Hook ) {
				continue;
			}

			foreach ( $wp_filter[ $name ]->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $callback ) {
					if ( ! self::is_ours( $callback['function'] ) ) {
						remove_action( $name, $callback['function'], $priority );
					}
				}
			}
		}
	}

	/**
	 * Whether a callback belongs to this plugin or its add-on.
	 *
	 * Decided by the namespace the callback was written in, which is the one
	 * fact every shape of callback carries: a method's class, a namespaced
	 * function's name, a closure's declaring scope.
	 *
	 * @param mixed $callback A registered callback.
	 */
	public static function is_ours( $callback ): bool {
		$name = self::name_of( $callback );

		foreach ( self::OURS as $prefix ) {
			if ( 0 === strpos( $name, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The fully qualified name a callback was declared under, or ''.
	 *
	 * @param mixed $callback A registered callback.
	 */
	private static function name_of( $callback ): string {
		if ( is_array( $callback ) && isset( $callback[0] ) ) {
			return is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0];
		}

		if ( is_string( $callback ) ) {
			return ltrim( $callback, '\\' );
		}

		if ( $callback instanceof \Closure ) {
			try {
				$reflection = new \ReflectionFunction( $callback );
				$scope      = $reflection->getClosureScopeClass();

				return $scope ? $scope->getName() : $reflection->getNamespaceName() . '\\';
			} catch ( \ReflectionException $error ) {
				return '';
			}
		}

		if ( is_object( $callback ) ) {
			return get_class( $callback );
		}

		return '';
	}
}
