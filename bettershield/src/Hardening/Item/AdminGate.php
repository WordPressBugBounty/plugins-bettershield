<?php
/**
 * Hardening item: answer signed-out requests to /wp-admin/ with 404.
 *
 * WordPress sends a signed-out visitor who asks for /wp-admin/ to the login
 * form, which confirms two things at once — that this is WordPress, and where
 * to log in. A 404 confirms neither. This is not a rename of the directory,
 * which plugins hardcode paths into and which would be a permanent support
 * burden; it is a refusal to redirect.
 *
 * Front-end code reaches admin-post.php while signed out by design, so that
 * keeps working. The rest of what a signed-out request legitimately asks for
 * never gets this far: admin-ajax.php is answered by the AJAX check below,
 * the asset loaders do not boot plugins at all, and the install, upgrade and
 * setup scripts define WP_INSTALLING, which stops core loading site-active
 * plugins. A network-active one still loads on them, outside this gate.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminGate {

	/**
	 * Admin scripts a signed-out request may legitimately reach.
	 *
	 * One entry, because one entry is all that reaches this list. Everything
	 * else a signed-out visitor legitimately asks for is answered before the
	 * comparison happens — see the class docblock for which and by what.
	 */
	private const OPEN = array( 'admin-post.php' );

	/** Where signed-out visitors are sent, set at boot; empty for the plain 404. */
	private static string $destination = '';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'          => 'destination',
				'label'        => __( 'Send signed-out visitors to', 'bettershield' ),
				'description'  => __( 'Leave this empty to show “page not found”. Or enter an address on this site, without the domain.', 'bettershield' ),
				'placeholder'  => 'page-not-found',
				'required'     => false,
				'pattern'      => LoginUrl::SLUG_PATTERN,
				'lowercase'    => true,
				'pattern_note' => LoginUrl::slug_rule(),
			),
		);
	}

	/**
	 * @param array<string, mixed> $options
	 * @return array<string, string>|\WP_Error
	 */
	public static function validate( array $options ) {
		$to = isset( $options['destination'] ) ? strtolower( trim( (string) $options['destination'] ) ) : '';

		if ( '' === $to ) {
			return array();
		}

		if ( 1 !== preg_match( '/' . LoginUrl::SLUG_PATTERN . '/', $to ) ) {
			return new \WP_Error( 'bettershield_bad_destination', LoginUrl::slug_rule() );
		}

		if ( LoginUrl::is_reserved_name( $to ) ) {
			return new \WP_Error( 'bettershield_reserved_destination', __( 'That address is already part of WordPress. Choose another.', 'bettershield' ) );
		}

		if ( self::sign_in_slug() === $to ) {
			return new \WP_Error( 'bettershield_destination_is_sign_in', __( 'That is your sign-in address, which this keeps private. Choose another.', 'bettershield' ) );
		}

		return array( 'destination' => $to );
	}

	/**
	 * What the row says while this is on, when it sends visitors somewhere.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$to = isset( $state['options']['destination'] ) ? (string) $state['options']['destination'] : '';

		if ( empty( $state['active'] ) || '' === $to ) {
			return null;
		}

		return home_url( '/' . $to . '/' );
	}

	/** The sign-in address in force, or empty. */
	private static function sign_in_slug(): string {
		$state = Manager::instance()->item_state( 'login_url' );

		return empty( $state['active'] ) ? '' : (string) ( $state['options']['slug'] ?? '' );
	}

	/**
	 * Where a signed-out visitor is sent, or null for the plain 404. Asked
	 * on every refusal, because the sign-in address can move to this name
	 * after it was saved, and a redirect there would hand it out.
	 */
	public static function destination_url(): ?string {
		if ( '' === self::$destination || self::sign_in_slug() === self::$destination ) {
			return null;
		}

		return home_url( '/' . self::$destination . '/' );
	}

	/**
	 * A plugin that moves the sign-in page usually also intercepts /wp-admin/
	 * for signed-out visitors, and the two interceptions can disagree about
	 * what a visitor gets.
	 */
	public static function conflict(): ?string {
		$competing = LoginUrl::competing_plugin();

		if ( null === $competing ) {
			return null;
		}

		return sprintf(
			/* translators: %s: plugin name. */
			__( '%s also decides what signed-out visitors see at /wp-admin/. After applying, check its sign-in address still works.', 'bettershield' ),
			$competing
		);
	}

	/**
	 * @param array<string, mixed> $state Where visitors go, if anywhere; nothing is written.
	 */
	public static function enforce( array $state ): void {
		self::$destination = isset( $state['options']['destination'] ) ? (string) $state['options']['destination'] : '';

		// Priority 0 on init: before auth_redirect() in wp-admin/admin.php gets
		// its chance to send the visitor to the login form.
		add_action( 'init', array( self::class, 'gate' ), 0 );

		// Core sends signed-out visitors to sign in from other moments too:
		// the Customizer on setup_theme, before init, and pages such as the
		// Font Library on admin_init, which admin-post.php fires signed out.
		// All of them go through auth_redirect(), the one caller that asks
		// for a re-authenticating sign-in address, so that is refused too.
		add_filter( 'login_url', array( self::class, 'gate_sign_in_redirect' ), PHP_INT_MAX, 3 );
	}

	/**
	 * Whether what enforce() attaches is still attached on this request.
	 * Switched on is not the same as working: another plugin's
	 * remove_filter() leaves the item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'init', array( self::class, 'gate' ) )
			&& false !== has_filter( 'login_url', array( self::class, 'gate_sign_in_redirect' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		self::$destination = '';

		remove_action( 'init', array( self::class, 'gate' ), 0 );
		remove_filter( 'login_url', array( self::class, 'gate_sign_in_redirect' ), PHP_INT_MAX );
	}

	public static function gate(): void {
		if ( ! self::should_refuse() ) {
			return;
		}

		$again = self::sign_in_again_url();

		if ( null !== $again ) {
			wp_safe_redirect( $again );
			exit;
		}

		self::refuse();
	}

	/**
	 * Where someone whose own session just ended goes instead of the 404.
	 *
	 * The idle timeout or the session limit signs people out while they work
	 * in the dashboard, and their next click met the page meant for
	 * strangers, with no reason and no way back. Only a session this site
	 * provably issued is told where to sign in: one the timeout ended on
	 * this request, a cookie whose signature still checks out, or a valid
	 * front-end cookie with no dashboard one, whose holder the sign-in
	 * address sends here and who has to be able to reach the form. Null for
	 * everyone else.
	 */
	public static function sign_in_again_url(): ?string {
		$why = \BetterShield\Login\Sessions::instance()->ended_why();

		if ( '' === $why && ! self::holds_a_front_end_session() ) {
			return null;
		}

		$back = set_url_scheme( 'http://' . ( isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '' ) . ( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) );
		$url  = wp_login_url( wp_validate_redirect( $back, admin_url() ) );

		// Added here rather than by asking wp_login_url() to force it: that
		// is the request gate_sign_in_redirect() refuses, and this answers it.
		return '' === $why ? add_query_arg( 'reauth', '1', $url ) : add_query_arg( \BetterShield\Login\Sessions::SIGNED_OUT, $why, $url );
	}

	/** Whether this request carries a valid front-end sign-in cookie of this site. */
	private static function holds_a_front_end_session(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- handed to core's own check, which verifies its signature.
		$cookie = isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ? $_COOKIE[ LOGGED_IN_COOKIE ] : '';

		return is_string( $cookie ) && '' !== $cookie && false !== wp_validate_auth_cookie( $cookie, 'logged_in' );
	}

	/**
	 * Refuses a signed-out dashboard request that is about to be sent to
	 * sign in, from whichever admin script asked. The address would name a
	 * moved sign-in page, which a 404 everywhere else keeps to itself.
	 *
	 * On the open scripts only admin_init is refused: core renders pages
	 * there that admin-post.php reaches signed out, while a front-end
	 * feature's own handler, which runs after it, may still send its
	 * visitor to sign in.
	 *
	 * @param string $login_url    The sign-in address.
	 * @param string $redirect     Where to return after signing in.
	 * @param bool   $force_reauth Whether auth_redirect() asked for it.
	 */
	public static function gate_sign_in_redirect( $login_url, $redirect = '', $force_reauth = false ) {
		global $pagenow;

		if ( ! $force_reauth || ! self::signed_out_dashboard() ) {
			return $login_url;
		}

		if ( ! in_array( (string) $pagenow, self::OPEN, true ) || doing_action( 'admin_init' ) ) {
			// Someone whose own session just ended is told where to sign in
			// here too, as the init gate tells them.
			$again = self::sign_in_again_url();

			if ( null !== $again ) {
				return $again;
			}

			self::refuse();
		}

		return $login_url;
	}

	/**
	 * Whether the current request is a signed-out visit to a gated admin
	 * script. Public so the decision can be tested without a request.
	 */
	public static function should_refuse(): bool {
		global $pagenow;

		return self::signed_out_dashboard() && ! in_array( (string) $pagenow, self::OPEN, true );
	}

	/**
	 * A signed-out request to an admin script, other than the AJAX, cron
	 * and REST requests that answer signed-out callers by their own rules.
	 */
	private static function signed_out_dashboard(): bool {
		if ( ! is_admin() || is_user_logged_in() ) {
			return false;
		}

		return ! ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) );
	}

	/**
	 * The chosen address, or a plain 404, ending the request. Separate from
	 * the decision so it can be exercised on its own.
	 */
	public static function refuse(): void {
		$to = self::destination_url();

		if ( null !== $to ) {
			nocache_headers();
			wp_safe_redirect( $to );
			exit;
		}

		status_header( 404 );
		nocache_headers();

		// The Customizer asks before translations may load (setup_theme).
		$early = ! did_action( 'after_setup_theme' );

		wp_die(
			$early ? 'This page is not available.' : esc_html__( 'This page is not available.', 'bettershield' ),
			$early ? 'Not found' : esc_html__( 'Not found', 'bettershield' ),
			array( 'response' => 404 )
		);
	}
}
