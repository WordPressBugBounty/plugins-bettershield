<?php
/**
 * The forms this plugin can put a bot check on.
 *
 * Every sign-in protection here is decided on `authenticate`, which fires for
 * every credential path there is, and rendered on `login_form`, which fires for
 * one. That mismatch is not a detail — it is the difference between a check and
 * a lockout. A store that has moved its customers to My Account, which is the
 * WooCommerce default, fires `woocommerce_login_form` instead: the honeypot was
 * never rendered there and so protected nothing customer-facing, and proof of
 * work was enforced there anyway and refused customers who had typed the right
 * password, pointing them at a puzzle the page did not contain.
 *
 * So the surfaces are listed in one place, both checks read the same list, and
 * a site running a login form neither WordPress nor WooCommerce renders can add
 * its own hook to it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginForms {

	/**
	 * Hooks that fire while a sign-in form is being rendered.
	 *
	 * WooCommerce is named rather than detected: the hook simply never fires
	 * on a site without it, so listing it costs a site that has no store
	 * nothing at all, and detecting it would mean asking a question with an
	 * answer that changes mid-request.
	 *
	 * @return string[]
	 */
	public static function sign_in_hooks(): array {
		/**
		 * Filters where a sign-in form's bot checks are rendered.
		 *
		 * A theme or plugin that renders its own sign-in form can add the hook
		 * it fires, and the checks appear on it. Without that, a custom form is
		 * a form this plugin cannot reach — which it treats as a reason not to
		 * enforce, rather than a reason to refuse.
		 *
		 * @param string[] $hooks Action hooks fired while a sign-in form renders.
		 */
		return array_values( array_unique( array_filter( array_map(
			'strval',
			(array) apply_filters(
				'bettershield_sign_in_form_hooks',
				array( 'login_form', 'woocommerce_login_form' )
			)
		) ) ) );
	}

	/**
	 * Hooks that fire while a registration form is being rendered.
	 *
	 * @return string[]
	 */
	public static function registration_hooks(): array {
		/**
		 * Filters where a registration form's bot checks are rendered.
		 *
		 * @param string[] $hooks Action hooks fired while a registration form renders.
		 */
		return array_values( array_unique( array_filter( array_map(
			'strval',
			(array) apply_filters(
				'bettershield_registration_form_hooks',
				array( 'register_form', 'woocommerce_register_form' )
			)
		) ) ) );
	}

	/**
	 * Whether this request is a submission to the sign-in page WordPress ships.
	 *
	 * Used to tell a form this plugin rendered on from one it could not reach.
	 * `wp-login.php` is the one surface always covered, so a submission that
	 * arrives there without the field we put on it is a submission that skipped
	 * the field rather than one that never had it.
	 */
	public static function is_core_sign_in_request(): bool {
		if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
			return true;
		}

		// `$pagenow` is set by core for wp-login.php, but a custom sign-in
		// address rewrites to it and the global follows the rewrite rather
		// than the request. The script actually running is the fact.
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? (string) wp_unslash( $_SERVER['SCRIPT_NAME'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared as a path, never stored or echoed.

		return 'wp-login.php' === basename( $script );
	}
}
