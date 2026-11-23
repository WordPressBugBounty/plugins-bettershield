<?php
/**
 * Refusals of a right password, answered on this plugin's own screen.
 *
 * Passkey-only, a password hold and a lockdown each refuse a sign-in whose
 * password was correct. Returned into the `authenticate` chain as an error,
 * core reports them on `wp_login_failed` like a wrong password, and every
 * other limiter listening there counts them: a few habit-typed passwords then
 * lock the owner out, passkey included, and a limiter that rewrites failure
 * messages hides the explanation behind "incorrect password".
 *
 * So a person at a browser is sent to the sign-in page with the explanation
 * instead, once the whole chain has answered — the way the two-factor gate
 * sends a sign-in that owes a code to its screen. Core never sees a failure,
 * and any check later in the chain (another plugin's lockout among them) has
 * already had its say and replaced the refusal if it refuses too. Clients that
 * are not a person at a browser keep the error, which is all they can read,
 * and so does the store's checkout, where nothing is added to the request.
 *
 * The screen reads one fixed message per key, never text from the address.
 * An add-on's own refusal of a right password (one it names through
 * `bettershield_own_refusals`, as Ultra's sign-in hours do) is sent the same
 * way: its explanation is kept on the site for a few minutes under a random
 * note the address carries, and shown once as plain text (#3055).
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Capabilities;
use BetterShield\Remediation\PasswordHold;
use BetterShield\Support\Checkout;
use BetterShield\Support\OneTimeNote;
use BetterShield\TwoFactor\LoginStep;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RightPasswordRefusals {

	/** The query key the sign-in page reads the explanation from. */
	public const KEY = 'bettershield_refused';

	/** Each refusal of a right password, and the key its explanation goes by. */
	private const CODES = array(
		'bettershield_passkey_only' => 'passkey',
		PasswordHold::REFUSAL       => 'new_password',
		'bettershield_lockdown'     => 'lockdown',
	);

	/** The key an add-on's refusal is explained by, from its note. */
	private const NOTE = 'note';

	/** The query key that names the note. */
	public const NOTE_KEY = 'bettershield_refused_note';

	private static ?RightPasswordRefusals $instance = null;

	public static function instance(): RightPasswordRefusals {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		/*
		 * Added as a sign-in begins rather than at boot, so it is the last
		 * thing on the chain whatever priority another plugin chose: a check
		 * that refuses after ours must still be the answer. `wp_authenticate`
		 * fires from wp_signon() only, which is where a browser signs in.
		 */
		add_action( 'wp_authenticate', array( $this, 'listen' ) );
		add_filter( 'wp_login_errors', array( $this, 'explain' ) );
	}

	public function listen(): void {
		add_filter( 'authenticate', array( $this, 'divert' ), PHP_INT_MAX, 2 );
	}

	/**
	 * Send a browser whose right password was refused to the explanation.
	 * Does not return when it sends; anything else passes through untouched.
	 *
	 * @param mixed $user
	 * @param mixed $username
	 * @return mixed
	 */
	public function divert( $user, $username = '' ) {
		$to = $this->destination( $user, is_string( $username ) ? $username : '' );

		// Once the response has started, a redirect cannot happen; the
		// refusal is all that is left to give.
		if ( null === $to || headers_sent() ) {
			return $user;
		}

		// The sign-in page of this site; nothing to guard against, and
		// wp_safe_redirect() refuses it where the site and home hosts differ.
		wp_redirect( $to ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- see above.
		exit;
	}

	/**
	 * Where a refused sign-in is sent instead of failing, or null when it is
	 * left to fail as it is.
	 *
	 * @param mixed $user What the authenticate chain answered.
	 */
	public function destination( $user, string $username ): ?string {
		if ( ! $user instanceof \WP_Error ) {
			return null;
		}

		$code  = (string) $user->get_error_code();
		$added = ! isset( self::CODES[ $code ] ) && in_array( $code, self::added_codes(), true );

		if ( ! isset( self::CODES[ $code ] ) && ! $added ) {
			return null;
		}

		if ( ! LoginStep::interactive() || Checkout::is_checkout_request() ) {
			return null;
		}

		$key = $added ? self::NOTE : self::CODES[ $code ];

		if ( 'passkey' === $key ) {
			$account = self::account( $username );
			$key     = null !== $account && user_can( $account, Capabilities::MANAGE ) ? 'passkey_owner' : 'passkey';
		}

		$args = array( self::KEY => $key );

		if ( $added ) {
			$note = OneTimeNote::keep( $user->get_error_message() );

			if ( '' !== $note ) {
				$args[ self::NOTE_KEY ] = $note;
			}
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- carried to the sign-in page as core carries them; only an address on this site is kept, and core escapes it where it prints it.
		$redirect = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), '' ) : '';

		if ( '' !== $redirect ) {
			$args['redirect_to'] = rawurlencode( $redirect );
		}

		if ( isset( $_REQUEST['interim-login'] ) ) {
			$args['interim-login'] = '1';
		}
		// phpcs:enable

		return add_query_arg( $args, site_url( 'wp-login.php', 'login' ) );
	}

	/**
	 * The explanation, on the sign-in page the refusal sent the person to.
	 *
	 * @param mixed $errors
	 * @return mixed
	 */
	public function explain( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- picks one of a few fixed messages; nothing is acted on.
		$key     = isset( $_GET[ self::KEY ] ) && is_string( $_GET[ self::KEY ] ) ? sanitize_key( wp_unslash( $_GET[ self::KEY ] ) ) : '';
		$message = self::NOTE === $key ? self::take_note() : self::message( $key );

		if ( ! $errors instanceof \WP_Error || '' === $message ) {
			return $errors;
		}

		$errors->add( 'bettershield_refused', $message );

		return $errors;
	}

	/** The fixed explanation for a key, or an empty string for any other. */
	public static function message( string $key ): string {
		switch ( $key ) {
			case 'passkey_owner':
				return __( 'This account needs a passkey. Use the passkey button. If you cannot, use your recovery link or a recovery code.', 'bettershield' );
			case 'passkey':
				return __( 'This account needs a passkey. Use the passkey button. If you cannot, ask an administrator to remove your passkeys so your password works again.', 'bettershield' );
			case 'new_password':
				return PasswordHold::error()->get_error_message();
			case 'lockdown':
				return __( 'Sign-in is paused for now. Try again later.', 'bettershield' );
		}

		return '';
	}

	/**
	 * The codes an add-on returns on the sign-in chain for a right
	 * credential, read the way the lockout reads them. Only strings, and
	 * never one of this plugin's own: those have their fixed messages.
	 *
	 * @return string[]
	 */
	private static function added_codes(): array {
		$added = apply_filters( 'bettershield_own_refusals', array() );

		return array_values( array_filter( is_array( $added ) ? $added : array(), static fn( $code ): bool => is_string( $code ) && '' !== $code ) );
	}

	/**
	 * The explanation a note holds, escaped, said once; a note that is gone
	 * (or never was) still says why, in general words.
	 */
	private static function take_note(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a note this site wrote, looked up by its name; the text is shown escaped and nothing is acted on.
		$text = OneTimeNote::take( isset( $_GET[ self::NOTE_KEY ] ) ? wp_unslash( $_GET[ self::NOTE_KEY ] ) : null );

		return null !== $text ? esc_html( $text ) : esc_html__( 'This account can’t sign in right now. Ask the site’s administrator.', 'bettershield' );
	}

	/** The account a sign-in named, found the way core's own check finds it. */
	private static function account( string $username ): ?\WP_User {
		$username = trim( $username );

		if ( '' === $username ) {
			return null;
		}

		$user = get_user_by( 'login', $username );

		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}

		return $user instanceof \WP_User ? $user : null;
	}
}
