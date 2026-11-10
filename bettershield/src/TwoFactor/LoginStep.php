<?php
/**
 * The second screen of a two-factor sign-in.
 *
 * The password form is WordPress's own and carries nothing of this plugin's.
 * When the password is right and the account has a second factor armed, the
 * sign-in is parked — no cookie that signs anybody in has been set — and the
 * browser is sent here, to a screen that asks for the code and nothing else.
 * Only an account with two-factor on ever sees it, and only after its
 * password was right, so the ordinary sign-in page stays exactly what
 * WordPress ships and tells a visitor nothing about who has a second factor.
 *
 * The parked sign-in is a random token in a short-lived, HttpOnly, SameSite
 * cookie, matched to a server-side record — stored under the token's hash,
 * never the token — of which account it is and whether to remember it. It
 * signs nobody in on its own, it dies in ten minutes, it is spent the moment
 * a code is accepted, and each account holds one at a time: parking again
 * retires the last, so nobody can fill the database by resubmitting a
 * password they hold.
 *
 * Wrong codes count toward the same lockout as wrong passwords; a source
 * that is locked out is refused here too; and an account allows ten wrong
 * codes an hour before it stops checking, so a stolen password does not buy
 * unlimited guessing from unlimited addresses.
 *
 * When the code is right the sign-in finishes exactly as core would have
 * finished it: the rest of the `authenticate` chain gets its say (a spam
 * flag on a network, a third-party refusal), then the cookie is set, then
 * core's own routing decides where the person lands.
 *
 * Sign-ins that are not a person at a browser — REST, XML-RPC, AJAX, cron,
 * the command line, a JSON client, or a page that already started printing
 * before it authenticated — cannot be sent to a second screen. They get a
 * refusal that says what to do instead.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginStep {

	public const ACTION = 'bettershield_2fa';
	public const COOKIE = 'bettershield_2fa_pending';
	public const TTL    = 10 * MINUTE_IN_SECONDS;

	private const FIELD     = 'bettershield_2fa_code';
	private const META_PARK = 'bettershield_2fa_park';

	private static ?LoginStep $instance = null;

	/**
	 * What the caller of wp_signon() asked about remembering the session,
	 * captured on its way past. Null until this request has seen a sign-in.
	 */
	private ?bool $remember = null;

	public static function instance(): LoginStep {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// wp-login.php keeps an action it has no handler for only when
		// something is hooked to it; this hook is what makes the screen exist.
		add_action( 'login_form_' . self::ACTION, array( $this, 'screen' ) );

		// wp_signon() runs this filter with the credentials it was actually
		// given — the only place a plugin's own "remember me" is visible.
		add_filter( 'secure_signon_cookie', array( $this, 'note_remember' ), 10, 2 );
	}

	/**
	 * @param mixed $secure
	 * @param mixed $credentials
	 * @return mixed
	 */
	public function note_remember( $secure, $credentials ) {
		$this->remember = is_array( $credentials ) && ! empty( $credentials['remember'] );

		return $secure;
	}

	/** What was noted, if anything: null when no sign-in has passed this request. */
	public function remembered(): ?bool {
		return $this->remember;
	}

	/** Test seam: a new request, as far as the remembered choice goes. */
	public function reset_request_state(): void {
		$this->remember = null;
	}

	/* ---- the hand-off from the password step ----------------------------- */

	/**
	 * Whether this request is a person at a browser, who can be sent on to a
	 * second screen. Everything else gets a refusal it can read.
	 */
	public static function interactive(): bool {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}

		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}

		// A client that asked for JSON or XML will not render an HTML page.
		if ( wp_is_json_request() || wp_is_jsonp_request() || wp_is_xml_request() ) {
			return false;
		}

		// A REST request whose authentication ran before core defined
		// REST_REQUEST — a plugin calling wp_authenticate() from
		// determine_current_user at init — is still a REST request.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read to classify the request, never to act on; only the path is compared, and nothing is stored or printed.
		$path = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( (string) wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';

		if ( isset( $_GET['rest_route'] ) || str_contains( $path, '/' . rest_get_url_prefix() . '/' ) ) {
			return false;
		}
		// phpcs:enable

		return true;
	}

	/**
	 * Park the sign-in and send the browser to the code screen. Does not
	 * return — except when the response has already started, in which case
	 * neither the cookie nor the redirect can happen, and the caller gets a
	 * refusal to show instead of a blank page.
	 *
	 * @return \WP_Error
	 */
	public function begin( \WP_User $user ) {
		if ( headers_sent() ) {
			return new \WP_Error(
				'bettershield_2fa_required',
				__( 'The two-factor code screen could not open here. Sign in from the site’s own sign-in page.', 'bettershield' )
			);
		}

		// The address is this plugin's own, on this site; wp_safe_redirect()
		// would refuse it on an install whose site address is on a different
		// host from its home address, and there is nothing to guard against.
		wp_redirect( $this->hand_off_from_request( $user ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- see above.
		exit;
	}

	/**
	 * Park the sign-in with what the form asked for, and answer with the
	 * address of the code screen.
	 */
	private function hand_off_from_request( \WP_User $user ): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read from core's own sign-in request, which core owns the verification of; nothing here acts on these values beyond carrying them to the next screen. redirect_to is carried as core carries it: escaped where it is printed and followed only through wp_safe_redirect().
		$remember    = null !== $this->remembered() ? (bool) $this->remembered() : ! empty( $_POST['rememberme'] );
		$redirect_to = self::requested_redirect();
		$interim     = isset( $_REQUEST['interim-login'] );
		$customize   = isset( $_REQUEST['customize-login'] );
		// phpcs:enable

		return $this->hand_off( $user, $remember, $redirect_to, $interim, $customize );
	}

	/**
	 * Where the sign-in form asked to go next.
	 *
	 * Core's form names it `redirect_to`. A store's own sign-in form, the one
	 * on its checkout among them, names it `redirect`, so a customer signing
	 * in to pay was sent to My Account instead of back to checkout, mid-order.
	 * The store's field is read only from the store's form, and only an
	 * address on this site is carried.
	 */
	private static function requested_redirect(): string {
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read as in begin(): carried to the next screen, escaped where printed and followed only through wp_safe_redirect(); the store verifies its own form's nonce before it signs anybody in.
		if ( isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) && '' !== $_REQUEST['redirect_to'] ) {
			return wp_unslash( $_REQUEST['redirect_to'] );
		}

		if ( isset( $_POST['woocommerce-login-nonce'], $_POST['redirect'] ) && is_string( $_POST['redirect'] ) ) {
			return wp_validate_redirect( wp_unslash( $_POST['redirect'] ), '' );
		}
		// phpcs:enable

		return '';
	}

	/**
	 * Park the sign-in, hand the browser the cookie that names it, and answer
	 * with the screen's address — for whoever is about to send the browser
	 * there: the gate with a redirect, the passkey route with a JSON reply.
	 */
	public function hand_off( \WP_User $user, bool $remember, string $redirect_to, bool $interim = false, bool $customize = false, string $action = self::ACTION, string $via = 'password' ): string {
		$token = self::park( $user, $remember, $via );
		$this->set_cookie( $token, time() + self::TTL );

		return self::url( $redirect_to, $interim, $customize, $action );
	}

	/**
	 * The parked sign-in this browser holds, if any — for a screen an add-on
	 * draws between the password and the code (enrollment, say), which needs
	 * to know who it is drawing for without ever seeing the token's record.
	 *
	 * @return array{user_id: int, remember: bool}|null
	 */
	public static function pending_for_request(): ?array {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the cookie is read, not acted on; whatever reads it decides, and pending() refuses anything but the exact shape this plugin issues.
		return self::pending( isset( $_COOKIE[ self::COOKIE ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE ] ) : '' );
	}

	/**
	 * Whether a sign-in that has proved one factor still owes the second.
	 * True for a two-factor account outside safe mode, unless the way in
	 * already carried a second factor — a passkey the person unlocked with a
	 * fingerprint, a face or a PIN is exactly that.
	 *
	 * The filter is the seam a paid add-on uses for a device the owner chose
	 * to trust for a while. The free plugin itself never answers false here.
	 *
	 * @param string $proof How the first factor was proved: 'password', or 'passkey'.
	 */
	public static function second_factor_required( \WP_User $user, string $proof, bool $second_factor_carried = false ): bool {
		$required = Manager::instance()->enabled( (int) $user->ID ) && ! SafeMode::is_active() && ! $second_factor_carried;

		/**
		 * Whether this sign-in must still pass the second screen.
		 *
		 * @param bool     $required Whether the second factor is owed.
		 * @param \WP_User $user     The account signing in.
		 * @param string   $proof    'password' or 'passkey'.
		 */
		return (bool) apply_filters( 'bettershield_second_factor_required', $required, $user, $proof );
	}

	/**
	 * The refusal for a sign-in that cannot be sent to the second screen.
	 *
	 * A sign-in form on a page that posts in the background — a theme's
	 * pop-up, a JSON form — is a person. Given the account whose password was
	 * right, the sign-in is parked and the answer links to the code screen,
	 * so the password isn't typed twice; nothing signs anybody in until the
	 * code is right. The address also travels in the error's data, as
	 * `continue`, for a form that would rather redirect.
	 *
	 * Without an account to park, or with the response already started, the
	 * person is told where the sign-in page is: with the address moved and
	 * the dashboard hidden there is nowhere else to find it, and an
	 * application password does not work on a sign-in form. A client of the
	 * API is told about the application password, which is what works there.
	 */
	public static function refusal( ?\WP_User $user = null ): \WP_Error {
		if ( self::from_a_page() ) {
			if ( null !== $user && ! headers_sent() ) {
				$continue = self::instance()->hand_off_from_request( $user );

				return new \WP_Error(
					'bettershield_2fa_required',
					sprintf(
						/* translators: %s: the address of the two-factor code screen. */
						__( 'This account uses two-factor authentication. <a href="%s">Enter your code to finish signing in.</a>', 'bettershield' ),
						esc_url( $continue )
					),
					array( 'continue' => $continue )
				);
			}

			return new \WP_Error(
				'bettershield_2fa_required',
				sprintf(
					/* translators: %s: the address of the site's sign-in page. */
					__( 'This account uses two-factor authentication. Sign in on <a href="%s">the site’s sign-in page</a>.', 'bettershield' ),
					esc_url( site_url( 'wp-login.php', 'login' ) )
				)
			);
		}

		return new \WP_Error(
			'bettershield_2fa_required',
			__( 'This account uses two-factor authentication. Use the site’s sign-in page or an application password.', 'bettershield' )
		);
	}

	/**
	 * Whether a sign-in that is not a browser page was still sent by a form
	 * on one, rather than by a client of the API or the command line.
	 */
	private static function from_a_page(): bool {
		if ( self::from_an_api_client() ) {
			return false;
		}

		return wp_doing_ajax() || wp_is_json_request() || wp_is_jsonp_request();
	}

	/**
	 * Whether a sign-in came from a client of the API or the command line:
	 * the REST API, XML-RPC or WP-CLI, where an application password is what
	 * works and a link to a page is nothing to follow.
	 */
	public static function from_an_api_client(): bool {
		if ( ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return true;
		}

		// The same reading interactive() makes of a REST request whose
		// authentication ran before core said so.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read to classify the request, never to act on; only the path is compared, and nothing is stored or printed.
		$path = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( (string) wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) : '';

		return isset( $_GET['rest_route'] ) || str_contains( $path, '/' . rest_get_url_prefix() . '/' );
		// phpcs:enable
	}

	/**
	 * Record a parked sign-in and return the token that names it. The store
	 * holds the token's hash, so a read of the database yields nothing that
	 * opens the second screen. One park per account: the previous one, if
	 * any, is retired first.
	 *
	 * It keeps what the sign-in began with, `password` or `passkey`, because a
	 * protection placed while it waits for its code may refuse one and not
	 * the other.
	 */
	public static function park( \WP_User $user, bool $remember = false, string $via = 'password' ): string {
		$key      = self::park_key();
		$previous = (string) get_user_meta( (int) $user->ID, $key, true );

		if ( '' !== $previous ) {
			delete_transient( 'bettershield_2fa_step_' . $previous );
		}

		$token = bin2hex( random_bytes( 32 ) );
		$hash  = hash( 'sha256', $token );

		set_transient(
			'bettershield_2fa_step_' . $hash,
			array(
				'user_id'  => (int) $user->ID,
				'remember' => $remember,
				'via'      => 'passkey' === $via ? 'passkey' : 'password',
			),
			self::TTL
		);
		update_user_meta( (int) $user->ID, $key, $hash );

		return $token;
	}

	/**
	 * Where an account's parked sign-in is pointed to from.
	 *
	 * The record itself is a transient, which on a network lives in the site's
	 * own option table; the pointer was network-global user meta. So parking on
	 * one subsite deleted a key that only exists in another's options — the
	 * earlier park stayed answerable for its full ten minutes while the pointer
	 * named the newer one, and "each account holds one at a time" was untrue on
	 * a network. Scoped per site so the pointer belongs to the site whose
	 * transient it names, the same split `Policy::since_key()` closes. The
	 * plain key stays on a single site, where there is nothing to tell apart,
	 * so no existing park is disturbed.
	 */
	private static function park_key(): string {
		return is_multisite() ? self::META_PARK . '_' . get_current_blog_id() : self::META_PARK;
	}

	/**
	 * `password` is true unless the sign-in is on record as a passkey's: one
	 * parked before the record said is read as the stricter of the two.
	 *
	 * @return array{user_id: int, remember: bool, password: bool}|null
	 */
	public static function pending( string $token ): ?array {
		if ( ! preg_match( '/^[0-9a-f]{64}$/', $token ) ) {
			return null;
		}

		$record = get_transient( self::key( $token ) );

		if ( ! is_array( $record ) || empty( $record['user_id'] ) ) {
			return null;
		}

		return array(
			'user_id'  => (int) $record['user_id'],
			'remember' => ! empty( $record['remember'] ),
			'password' => 'passkey' !== ( $record['via'] ?? '' ),
		);
	}

	private static function forget( string $token ): void {
		delete_transient( self::key( $token ) );
	}

	/**
	 * Retire whatever park an account holds — the support path that turns
	 * two-factor off for somebody calls this, so nothing half-done survives.
	 */
	public static function forget_for( int $user_id ): void {
		$key  = self::park_key();
		$hash = (string) get_user_meta( $user_id, $key, true );

		if ( '' !== $hash ) {
			delete_transient( 'bettershield_2fa_step_' . $hash );
		}

		delete_user_meta( $user_id, $key );
	}

	/**
	 * Check a code against a parked sign-in. On success the parking is spent
	 * and the account comes back; nothing here sets a cookie — that is the
	 * screen's job, so this can be exercised without a browser.
	 *
	 * @return \WP_User|\WP_Error
	 */
	public function attempt( string $token, string $code ) {
		$pending = self::pending( $token );
		$user    = null === $pending ? false : get_user_by( 'id', $pending['user_id'] );

		if ( ! $user instanceof \WP_User ) {
			return self::expired();
		}

		if ( \BetterShield\Remediation\Suspension::blocks( (int) $user->ID ) ) { return \BetterShield\Remediation\Suspension::error(); }

		// The factor was turned off — by the person elsewhere, or by an
		// administrator on their behalf — or safe mode paused it, since this
		// sign-in was parked. The password was right and nothing more is owed.
		if ( ! Manager::instance()->enabled( (int) $user->ID ) || SafeMode::is_active() ) {
			self::forget( $token );

			return $this->finish( $user, $pending['password'] );
		}

		// The same lockout and blocklist the password step applies. A source
		// that was locked out between the two steps is refused here as well,
		// and the knock is announced the way core announces it, so the log
		// shows a locked door being tried.
		$allowed = Protection::instance()->enforce( $user );

		if ( is_wp_error( $allowed ) ) {
			do_action( 'wp_login_failed', $user->user_login, $allowed ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

			return $allowed;
		}

		if ( '' === trim( $code ) ) {
			return new \WP_Error(
				'bettershield_2fa_empty',
				__( 'Enter the six-digit code from your authenticator app, or an unused backup code.', 'bettershield' )
			);
		}

		// Whether there was room is read before the check takes from it, so the
		// count this attempt makes is not the count that reports the cap.
		$room = self::guess_allowed( (int) $user->ID );

		// The check is the only thing that tells a spent hour from records
		// that could not be read at all: both leave no room, and only one of
		// them is answered by waiting.
		$checked = Manager::instance()->check_code( (int) $user->ID, $code );

		if ( is_wp_error( $checked ) ) {
			// Recorded where it was decided, at the severity it deserves;
			// counting it again here would put one refusal in the log twice.
			return $checked;
		}

		if ( ! $room ) {
			return new \WP_Error(
				'bettershield_2fa_capped',
				__( 'Too many wrong codes in the last hour, so codes are paused for this account. Locked out? Use your recovery link.', 'bettershield' )
			);
		}

		if ( true !== $checked ) {
			Writer::instance()->record(
				'two_factor_failed',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'user',
					'object_id'   => (string) $user->ID,
				)
			);

			// Refused either way, and under the one code a wrong credential
			// carries; only the reason given differs (#2076).
			$error = new \WP_Error(
				'bettershield_2fa_wrong',
				Manager::instance()->was_just_used( (int) $user->ID, $code )
					? __( 'That code was just used. Wait for your app to show a new one, or use an unused backup code.', 'bettershield' )
					// The sign-in screen takes a backup code too, and someone without
					// their phone needs to hear that here.
					: __( 'That code does not match. Try the code your app shows right now, or an unused backup code.', 'bettershield' )
			);

			// A wrong code is a wrong credential: it counts toward the lockout
			// exactly as a wrong password does.
			do_action( 'wp_login_failed', $user->user_login, $error ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

			return $error;
		}

		self::forget( $token );

		return $this->finish( $user, $pending['password'] );
	}

	/**
	 * Finish a parked sign-in whose person has just set two-factor up within
	 * it. The code proved seconds ago is spent, so asking for it again could
	 * only refuse it. Does not return when the sign-in goes through.
	 *
	 * @return \WP_Error|null Why the rest of the chain refused it, or null when
	 *                        this browser holds no sign-in of this account's
	 *                        with two-factor on, which is the code screen's to answer.
	 */
	public function finish_after_setup( \WP_User $user, string $redirect_to ): ?\WP_Error {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared as a hash and never output.
		$token   = isset( $_COOKIE[ self::COOKIE ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE ] ) : '';
		$pending = self::pending( $token );

		if ( null === $pending || (int) $pending['user_id'] !== (int) $user->ID || ! Manager::instance()->enabled( (int) $user->ID ) ) {
			return null;
		}

		self::forget( $token );

		$result = $this->finish( $user, $pending['password'] );

		if ( $result instanceof \WP_Error ) {
			return $result;
		}

		$this->complete( $result, $pending['remember'], $redirect_to, false, false, ! $pending['password'] );

		return null;
	}

	/**
	 * The code was right (or no longer needed): give the rest of the
	 * `authenticate` chain its say before anybody is signed in. Handing over
	 * to this screen left that chain at this plugin's own step; core's spam
	 * check on a network and any third-party gate come after it, and a
	 * refusal from them is a refusal.
	 *
	 * @return \WP_User|\WP_Error
	 */
	private function finish( \WP_User $user, bool $password = true ) {
		// Started from the account rather than from credentials, through the
		// marked re-entry so the plugin's own gate stands aside by name;
		// core's password handlers pass it straight through and everything
		// hooked after runs exactly as it would have. It carries whether the
		// sign-in began with a password, for a protection about passwords.
		$verdict = Manager::instance()->reenter_chain( $user, $password );

		if ( $verdict instanceof \WP_User && (int) $verdict->ID === (int) $user->ID ) {
			return $verdict;
		}

		$error = $verdict instanceof \WP_Error ? $verdict : new \WP_Error( 'bettershield_2fa_refused', __( 'Sign-in was refused after the code was accepted.', 'bettershield' ) );

		do_action( 'wp_login_failed', $user->user_login, $error ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

		return $error;
	}

	/* ---- the screen ------------------------------------------------------- */

	/**
	 * Runs inside wp-login.php for `?action=bettershield_2fa`, where core's
	 * own login_header() and login_footer() are available — the screen is
	 * drawn with the same chrome as the password form, so a moved sign-in
	 * address, a custom logo and every login-page style apply here too.
	 */
	public function screen(): void {
		global $interim_login;

		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the parked-sign-in cookie is the proof this request belongs to someone who just gave the right password; it is HttpOnly and SameSite=Lax, so a cross-site POST cannot carry it. Core's own sign-in form uses no nonce for the same reason. redirect_to is carried as in begin(), and pending() refuses any token but the exact shape this plugin issues.
		$interim_login = isset( $_REQUEST['interim-login'] ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- login_header() and login_footer() read this global to draw the modal variant; the hook fires before core sets it.
		$customize     = isset( $_REQUEST['customize-login'] );
		$redirect_to   = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '';
		$token         = isset( $_COOKIE[ self::COOKIE ] ) ? (string) wp_unslash( $_COOKIE[ self::COOKIE ] ) : '';
		$pending       = self::pending( $token );
		$submitted     = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST[ self::FIELD ] );
		$code          = $submitted ? sanitize_text_field( wp_unslash( (string) $_POST[ self::FIELD ] ) ) : '';
		// phpcs:enable

		if ( $customize ) {
			wp_enqueue_script( 'customize-base' );
		}

		$errors = new \WP_Error();

		if ( null !== $pending && $submitted ) {
			$result = $this->attempt( $token, $code );

			if ( $result instanceof \WP_User ) {
				$this->complete( $result, $pending['remember'], $redirect_to, (bool) $interim_login, $customize, ! $pending['password'] );
			}

			$errors = $result;
		}

		if ( null === $pending || 'bettershield_2fa_expired' === $errors->get_error_code() ) {
			$this->render_expired( $redirect_to );
			exit;
		}

		$this->render_form( $errors, $redirect_to, (bool) $interim_login, $customize, (int) $pending['user_id'] );
		exit;
	}

	/**
	 * Sign in exactly as core would have after the password, then go where
	 * core would have gone.
	 */
	private function complete( \WP_User $user, bool $remember, string $redirect_to, bool $interim, bool $customize, bool $passkey = false ): void {
		$this->set_cookie( '', time() - YEAR_IN_SECONDS );

		/**
		 * Fires when the second screen accepted this sign-in, before any
		 * cookie is set — the moment an add-on may note that this browser
		 * passed the second factor.
		 *
		 * @param \WP_User $user The account signing in.
		 */
		do_action( 'bettershield_2fa_passed', $user );

		// A sign-in a passkey began is a passkey's, its code notwithstanding.
		if ( $passkey ) {
			\BetterShield\Login\Sessions::opening_by( 'passkey' );
		}

		// '' for secure: decided from the connection, as core does.
		wp_set_auth_cookie( (int) $user->ID, $remember, '' );

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

		$requested = $redirect_to;
		$target    = '' !== $redirect_to ? $redirect_to : admin_url();

		/** This filter is documented in wp-login.php */
		$target = apply_filters( 'login_redirect', $target, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter.

		if ( $interim ) {
			self::interim_success( $customize );
		}

		$destination = self::destination( $user, $target );

		if ( $destination['own'] ) {
			// A destination this code chose, on this site: core sends it with
			// wp_redirect() for the same reason.
			wp_redirect( $destination['url'] ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- see above.
			exit;
		}

		wp_safe_redirect( $destination['url'] );
		exit;
	}

	/**
	 * The page that ends a sign-in in the window that renews an expired
	 * session: core's own success page, so the parent window closes it the
	 * same way — and the Customizer's messenger, so it resumes rather than
	 * waits. Does not return.
	 */
	public static function interim_success( bool $customize ): void {
		global $interim_login;

		$interim_login = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- read by login_header() to draw the success variant.
		login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'bettershield' ) . '</p>' );
		echo '</div>';
		/** This action is documented in wp-login.php */
		do_action( 'login_footer' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

		if ( $customize ) {
			wp_print_inline_script_tag(
				"setTimeout( function(){ new wp.customize.Messenger({ url: '" . esc_url_raw( wp_customize_url() ) . "', channel: 'login' }).send('login') }, 1000 );"
			);
		}

		echo '</body></html>';
		exit;
	}

	/**
	 * Where a sign-in lands: core's rules from wp-login.php, in core's order.
	 * An administrator overdue to confirm the site email sees that screen
	 * first; a person with nowhere on this site to go, or no reason to see
	 * the dashboard, goes where core would send them.
	 *
	 * @return array{url: string, own: bool}
	 */
	public static function destination( \WP_User $user, string $redirect_to ): array {
		if ( $user->exists() && $user->has_cap( 'manage_options' ) ) {
			/** This filter is documented in wp-login.php */
			$interval = (int) apply_filters( 'admin_email_check_interval', 6 * MONTH_IN_SECONDS ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter.

			if ( $interval > 0 && time() > (int) get_option( 'admin_email_lifespan' ) ) {
				return array(
					'url' => add_query_arg(
						array(
							'action'  => 'confirm_admin_email',
							'wp_lang' => get_user_locale( $user ),
						),
						wp_login_url( $redirect_to )
					),
					'own' => true,
				);
			}
		}

		if ( '' === $redirect_to || 'wp-admin/' === $redirect_to || admin_url() === $redirect_to ) {
			if ( is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ) {
				$redirect_to = user_admin_url();
			} elseif ( is_multisite() && ! $user->has_cap( 'read' ) ) {
				$redirect_to = get_dashboard_url( $user->ID );
			} elseif ( ! $user->has_cap( 'edit_posts' ) ) {
				$redirect_to = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
			}

			return array(
				'url' => '' !== $redirect_to ? $redirect_to : admin_url(),
				'own' => true,
			);
		}

		return array(
			'url' => $redirect_to,
			'own' => false,
		);
	}

	private function render_form( \WP_Error $errors, string $redirect_to, bool $interim, bool $customize, int $user_id ): void {
		login_header( __( 'Authenticator app code or backup code', 'bettershield' ), '', $errors->has_errors() ? $errors : null );

		/**
		 * Fires on the code screen, before the form. The seam for anything
		 * that dresses this plugin's own sign-in screens.
		 *
		 * @param int $user_id The account the parked sign-in belongs to.
		 */
		do_action( 'bettershield_2fa_screen_before_form', $user_id );
		?>
		<form name="bettershield-2fa" id="loginform" action="<?php echo esc_url( self::url( $redirect_to, $interim, $customize ) ); ?>" method="post">
			<p class="bettershield-2fa-lead" style="margin:0 0 16px"><?php esc_html_e( 'Enter the six-digit code from your authenticator app, or an unused backup code.', 'bettershield' ); ?></p>
			<p>
				<label for="<?php echo esc_attr( self::FIELD ); ?>"><?php esc_html_e( 'Authenticator app code or backup code', 'bettershield' ); ?></label>
				<input type="text" name="<?php echo esc_attr( self::FIELD ); ?>" id="<?php echo esc_attr( self::FIELD ); ?>" class="input" value="" size="20" autocomplete="one-time-code" inputmode="<?php echo BackupCodes::holds_imported( $user_id ) ? 'text' : 'numeric'; ?>" autocapitalize="off" spellcheck="false" />
			</p>
			<?php
			/**
			 * Fires inside the code form, before its submit row — for a field
			 * an add-on wants answered along with the code.
			 *
			 * @param int $user_id The account the parked sign-in belongs to.
			 */
			do_action( 'bettershield_2fa_screen_form_fields', $user_id );
			?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Continue', 'bettershield' ); ?>" />
			</p>
		</form>
		<p id="nav">
			<a href="<?php echo esc_url( wp_login_url( $redirect_to ) ); ?>"><?php esc_html_e( 'Start again', 'bettershield' ); ?></a>
		</p>
		<?php
		/**
		 * Fires on the code screen, after the form and its links.
		 *
		 * @param int $user_id The account the parked sign-in belongs to.
		 */
		do_action( 'bettershield_2fa_screen_after_form', $user_id );

		login_footer( self::FIELD );
	}

	private function render_expired( string $redirect_to ): void {
		login_header( __( 'Authenticator app code or backup code', 'bettershield' ), '', self::expired() );
		?>
		<p id="nav">
			<a href="<?php echo esc_url( wp_login_url( $redirect_to ) ); ?>"><?php esc_html_e( 'Sign in again', 'bettershield' ); ?></a>
		</p>
		<?php
		login_footer();
	}

	/* ---- helpers ------------------------------------------------------------ */

	private static function expired(): \WP_Error {
		return new \WP_Error(
			'bettershield_2fa_expired',
			__( 'That sign-in took too long or was already used. Sign in again.', 'bettershield' )
		);
	}

	private static function key( string $token ): string {
		return 'bettershield_2fa_step_' . hash( 'sha256', $token );
	}

	/**
	 * Ten wrong codes an hour for one account is a person who has lost the
	 * plot, or a script that has the password and is working through the
	 * code space from as many addresses as it likes. After that the account
	 * stops checking codes for the hour.
	 *
	 * Asked here only so the screen can say so. The count itself is kept by
	 * the manager, beside the check it bounds, because this screen is not the
	 * only thing that checks a code.
	 */
	private static function guess_allowed( int $user_id ): bool {
		return Manager::instance()->guess_allowed( $user_id );
	}

	/**
	 * The screen's address. Built on the sign-in script itself, not on
	 * wp_login_url(): plugins that put a sign-in form on a front-end page
	 * point wp_login_url() there, and that page never runs this action. A
	 * moved sign-in address still applies, because it rewrites site_url().
	 */
	public static function url( string $redirect_to, bool $interim = false, bool $customize = false, string $action = self::ACTION ): string {
		$args = array( 'action' => '' !== $action ? $action : self::ACTION );

		if ( '' !== $redirect_to ) {
			$args['redirect_to'] = rawurlencode( $redirect_to );
		}

		if ( $interim ) {
			$args['interim-login'] = '1';
		}

		if ( $customize ) {
			$args['customize-login'] = '1';
		}

		return add_query_arg( $args, site_url( 'wp-login.php', 'login' ) );
	}

	/**
	 * Where the cookie has to be readable: the sign-in script's own path and
	 * the site's home path, which differ on an install that keeps WordPress
	 * in its own directory — core sets its sign-in cookies on both too.
	 *
	 * @return string[]
	 */
	public static function cookie_paths(): array {
		$paths = array();

		foreach ( array( 'COOKIEPATH', 'SITECOOKIEPATH' ) as $constant ) {
			$path = defined( $constant ) ? (string) constant( $constant ) : '';

			$paths[] = '' !== $path ? $path : '/';
		}

		return array_values( array_unique( $paths ) );
	}

	private function set_cookie( string $value, int $expires ): void {
		if ( headers_sent() ) {
			return;
		}

		foreach ( self::cookie_paths() as $path ) {
			setcookie(
				self::COOKIE,
				$value,
				array(
					'expires'  => $expires,
					'path'     => $path,
					'domain'   => defined( 'COOKIE_DOMAIN' ) && is_string( COOKIE_DOMAIN ) ? COOKIE_DOMAIN : '',
					// The connection, not the address: a Secure cookie set on a
					// request that reached PHP over plain HTTP is a cookie the
					// browser never sends back, which parks a sign-in nothing
					// can finish. Where TLS ends at a proxy the site is https
					// and this request is not, and the browser is the one that
					// has to be believed here.
					'secure'   => Server::connection_is_https(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}
}
