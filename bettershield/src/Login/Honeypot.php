<?php
/**
 * Honeypot bot protection: an invisible field and a clock, no puzzle.
 *
 * Two observations about unsophisticated automation, each turned into a
 * check. Bots fill in every field they find, so a field a person never sees
 * comes back non-empty exactly when a script filled it. And bots submit
 * instantly, so a form that comes back within two seconds of being rendered
 * was not filled in by hands. People see nothing, solve nothing, and prove
 * nothing — which is the point: a visual challenge would need an outside
 * service, and this plugin makes no external calls.
 *
 * Forms this plugin did not render are exempt by architecture: the check
 * only runs when its own fields are present in the submission, so a custom
 * login form, an app password or an XML-RPC client is never rejected for
 * lacking a field nobody gave it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Checkout;
use BetterShield\Support\ClientIp;
use BetterShield\Support\LoginForms;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Honeypot {

	/**
	 * The trap field. A name autofill has no interest in: browsers and
	 * password managers fill fields they recognize, and rejecting a person
	 * because their browser helpfully filled "website" would be a false
	 * positive of our own construction.
	 */
	private const FIELD = 'bettershield_hp_check';

	/**
	 * The clock field, carrying "timestamp.signature".
	 */
	private const STAMP = 'bettershield_hp_time';

	/**
	 * Faster than this, in seconds, is not typing.
	 */
	private const MIN_SECONDS = 2;

	/** Whether the last check caught only the clock: sent too soon, nothing else wrong. */
	private bool $too_fast = false;

	private static ?Honeypot $instance = null;

	public static function instance(): Honeypot {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Every sign-in and registration form this plugin can reach, not only
		// the two WordPress renders itself. A store that has moved its
		// customers to My Account — the WooCommerce default — fires its own
		// hooks, and while only core's were listed the trap was never on the
		// form the site's actual customers use.
		foreach ( array_merge( LoginForms::sign_in_hooks(), LoginForms::registration_hooks() ) as $hook ) {
			add_action( $hook, array( $this, 'render' ) );
		}

		add_action( 'comment_form', array( $this, 'render' ) );

		// Priority 25: after core has resolved credentials (20), before
		// anything acts on the signed-in user. A wrong password fails on its
		// own; this only turns a would-be success by a bot into a refusal.
		add_filter( 'authenticate', array( $this, 'check_login' ), 25, 1 );
		add_filter( 'registration_errors', array( $this, 'check_registration' ), 10, 3 );
		// WooCommerce's own sign-up form does not run core's registration
		// filter, and the field is drawn on it — so on a store the trap was
		// laid and never looked at. Same callback: the filter passes a
		// WP_Error first, as core's does.
		add_filter( 'woocommerce_registration_errors', array( $this, 'check_registration' ), 10, 3 );
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 5, 1 );
	}

	private function enabled(): bool {
		return Protection::instance()->settings()['honeypot'] && ! SafeMode::is_active();
	}

	/**
	 * Whether this request is the store's own checkout, where the trap is
	 * not read. A field that was never rendered must not be judged: on the
	 * checkout the account creation carries no trap, so an absent one is the
	 * ordinary state rather than evidence of anything.
	 *
	 * Judged by what the request is doing, not by a `wc-ajax` parameter on
	 * its address: that one anybody can append to a sign-in or sign-up that
	 * did carry the trap, and a filled trap was then never read.
	 */
	private function on_store_path(): bool {
		return Checkout::is_checkout_request();
	}

	/* ---- render ------------------------------------------------------------- */

	public function render(): void {
		if ( ! $this->enabled() ) {
			return;
		}

		/*
		 * Nothing is added to the cart or the checkout. WooCommerce fires its
		 * sign-in form hook inside the checkout page when the store lets
		 * customers log in there, so the trap was being drawn into a page the
		 * readme promises is left alone — and into a page a full-page cache
		 * hands to every shopper.
		 */
		if ( Checkout::is_store_path() ) {
			return;
		}

		$time = (string) time();

		// aria-hidden plus tabindex -1 plus a box clipped to nothing: invisible
		// to people, absent from tab order and screen readers, present in the
		// DOM for anything that parses fields mechanically. Clipped where it
		// stands rather than pushed off the page, because an offset to the left
		// is where a right-to-left page scrolls to.
		printf(
			'<div style="position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0,0,0,0);clip-path:inset(50%%);white-space:nowrap;" aria-hidden="true"><label>%1$s<input type="text" name="%2$s" value="" tabindex="-1" autocomplete="off"></label></div><input type="hidden" name="%3$s" value="%4$s">',
			esc_html__( 'Leave this field empty', 'bettershield' ),
			esc_attr( self::FIELD ),
			esc_attr( self::STAMP ),
			esc_attr( $time . '.' . $this->sign( $time ) )
		);
	}

	/* ---- checks -------------------------------------------------------------- */

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function check_login( $user ) {
		if ( ! $user instanceof \WP_User || ! $this->submitted() || ! $this->enabled() || $this->on_store_path() ) {
			return $user;
		}

		if ( $this->caught() ) {
			$this->record( 'login' );

			/*
			 * Right credentials, sent sooner than a person types: a password
			 * manager that fills and submits as the page loads, or a quick
			 * hand. Told to wait rather than left with no reason. Anything
			 * else caught keeps the plain answer.
			 */
			return new \WP_Error(
				'bettershield_honeypot',
				$this->too_fast
					? __( 'That was sent too soon after the page opened. Wait a second, then sign in again.', 'bettershield' )
					: __( 'That did not go through. Please try signing in again.', 'bettershield' )
			);
		}

		return $user;
	}

	/**
	 * @param string $username Unused; the filters pass it before the address.
	 * @param string $email    The address the account is being created for.
	 */
	public function check_registration( \WP_Error $errors, $username = '', $email = '' ): \WP_Error {
		// The checkout's own account only, as the sign-up throttle reads it.
		if ( $this->submitted() && $this->enabled() && ! Checkout::is_checkout_account( (string) $email ) && $this->caught() ) {
			$this->record( 'registration' );
			$errors->add( 'bettershield_honeypot', __( 'That did not go through. Please try again.', 'bettershield' ) );
		}

		return $errors;
	}

	/**
	 * @param array<string, mixed> $comment
	 * @return array<string, mixed>
	 */
	public function check_comment( $comment ) {
		if ( is_user_logged_in() || ! $this->submitted() || ! $this->enabled() || ! $this->caught() ) {
			return $comment;
		}

		$this->record( 'comment' );

		wp_die(
			esc_html__( 'That did not go through. Go back and try again.', 'bettershield' ),
			esc_html__( 'Comment not posted', 'bettershield' ),
			array(
				'response'  => 400,
				'back_link' => true,
			)
		);
	}

	/* ---- internals ------------------------------------------------------------- */

	/**
	 * Whether this submission carries our fields at all — the architecture
	 * exemption for forms we never rendered.
	 */
	private function submitted(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence check only; each consuming flow verifies its own credentials.
		return isset( $_POST[ self::STAMP ] );
	}

	private function caught(): bool {
		$this->too_fast = false;

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- these fields are this plugin's own bot check; the surrounding flow (login, registration, comment) carries its own verification.
		$trap  = isset( $_POST[ self::FIELD ] ) ? (string) wp_unslash( $_POST[ self::FIELD ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared to empty, never stored.
		$stamp = isset( $_POST[ self::STAMP ] ) ? sanitize_text_field( (string) wp_unslash( $_POST[ self::STAMP ] ) ) : '';
		// phpcs:enable

		if ( '' !== $trap ) {
			return true;
		}

		$parts = explode( '.', $stamp, 2 );

		if ( 2 !== count( $parts ) || ! hash_equals( $this->sign( $parts[0] ), $parts[1] ) ) {
			// A forged or mangled clock is its own answer.
			return true;
		}

		$age = time() - (int) $parts[0];

		// Too fast is a script. Old is fine: a cached page renders an old
		// clock, and a person who left the tab open for an hour is still a
		// person. Negative is a forged clock from the future.
		$this->too_fast = $age >= 0 && $age < self::MIN_SECONDS;

		return $age < self::MIN_SECONDS;
	}

	/**
	 * Signed with a key this plugin owns rather than with `wp_salt()`.
	 *
	 * The `auth_keys` hardening item rotates the salts — that is what it is
	 * for — and every stamp already rendered into a page then failed to
	 * verify, so the submission was refused as a bot. That undid the age
	 * tolerance deliberately built two methods up, at exactly the moment it
	 * was most needed: a cached page keeps serving stale forms for the length
	 * of its TTL, and an anonymous commenter on one has no session to lose and
	 * no idea why they were turned away.
	 *
	 * `ClientIp::hmac()` already makes this argument for its own secret —
	 * lockouts must not evaporate when keys rotate — and the same requirement
	 * applies here. Reusing that key rather than adding a sibling: both are
	 * plugin-held, neither leaves the site, and one fewer option is one fewer
	 * thing to keep in step.
	 */
	private function sign( string $time ): string {
		return hash_hmac( 'sha256', 'bettershield-hp|' . $time, ClientIp::signing_secret() );
	}

	private function record( string $surface ): void {
		Writer::instance()->record(
			'honeypot_rejected',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'honeypot',
				'object_id'   => $surface,
			)
		);
	}
}
