<?php
/**
 * The passkey button on the sign-in form.
 *
 * Added below the password form rather than in place of it, and that ordering
 * is the safety property: if every line of this failed to load, the sign-in
 * page would be exactly the page WordPress ships. Nothing here removes,
 * replaces or gates the password field, so no failure mode of this file can
 * keep anybody out.
 *
 * The script is small and inline for the same reason — the sign-in page is the
 * one page that has to work when everything else is broken, and a build
 * artifact that 404s after a bad deploy would take the button with it but
 * leave the form intact.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginForm {

	/**
	 * The sign-in screen action a passkey sign-in ends on in the window that
	 * renews an expired session.
	 */
	public const DONE = 'bettershield_passkey_done';

	/**
	 * The sign-in screen actions the button posts to: the challenge, then the
	 * signed answer. Sign-in screen actions rather than REST routes, as the
	 * two-factor code step is: a site that closes REST to signed-out visitors
	 * cannot close wp-login.php without closing password sign-in too, and the
	 * REST routes left the button failing there, and its passkey-only
	 * accounts with no way in but the recovery link (#2462).
	 */
	public const OPTIONS = 'bettershield_passkey_options';
	public const SIGN_IN = 'bettershield_passkey';

	/** The assertion's fields: base64url text, all of them. */
	private const TEXT_FIELDS = array( 'handle', 'id', 'clientDataJSON', 'authenticatorData', 'signature', 'redirect_to' );

	/** The most a sign-in body is read to: an assertion is a few kilobytes. */
	private const MAX_BODY_BYTES = 65536;

	/** Where to land, as the password form carries it. */
	private const FLAGS = array( 'remember', 'interim', 'customize' );

	/** Whether the button was drawn on this page, so the script knows to run. */
	private bool $rendered = false;

	public function register(): void {
		add_action( 'login_form', array( $this, 'render' ) );
		add_action( 'login_form_' . self::DONE, array( $this, 'done' ) );
		add_action( 'login_form_' . self::OPTIONS, array( $this, 'serve_options' ) );
		add_action( 'login_form_' . self::SIGN_IN, array( $this, 'serve_sign_in' ) );

		// The script runs from the footer, when the whole form exists: it can
		// then place the button below the Log In row in one synchronous step,
		// with no listener and no moment where the button sits elsewhere.
		add_action( 'login_footer', array( $this, 'script' ) );
	}

	public function render(): void {
		if ( ! Manager::availability()['available'] ) {
			return;
		}

		// Nothing to sign in with yet: a button that can only fail is worse
		// than no button.
		if ( ! self::any_enrolled() ) {
			return;
		}

		$this->rendered = true;

		?>
		<div class="bettershield-passkey" id="bettershield-passkey" style="clear:both;padding-top:20px;text-align:center">
			<button type="button" class="button button-secondary" id="bettershield-passkey-button" style="width:100%">
				<?php esc_html_e( 'Log In With a Passkey', 'bettershield' ); ?>
			</button>
			<p id="bettershield-passkey-note" style="margin:8px 0 0;font-size:12px" role="status"></p>
		</div>
		<?php
	}

	/**
	 * Core's own success page, which is what closes the window that renews
	 * an expired session; the passkey route has already set the cookie. A
	 * browser that arrives here signed out is sent to sign in again in the
	 * same window, rather than told it succeeded.
	 */
	public function done(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- carried from the sign-in form to this page, which changes nothing.
		$customize = isset( $_REQUEST['customize-login'] );

		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( add_query_arg( 'interim-login', '1', wp_login_url() ) );
			exit;
		}

		if ( $customize ) {
			wp_enqueue_script( 'customize-base' );
		}

		\BetterShield\TwoFactor\LoginStep::interim_success( $customize );
	}

	/** The challenge, from the sign-in screen. */
	public function serve_options(): void {
		self::send( self::options_answer() );
	}

	/** The signed answer, from the sign-in screen. */
	public function serve_sign_in(): void {
		// Bounded and quiet: an assertion is a few kilobytes, and an anonymous
		// endpoint must not be a lever on memory or the error log. A body cut
		// short does not decode, and is refused as bad input below.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the request body, read once with a ceiling.
		$raw  = (string) @file_get_contents( 'php://input', false, null, 0, self::MAX_BODY_BYTES );
		$body = json_decode( $raw, true );

		self::send( self::sign_in_answer( is_array( $body ) ? $body : array() ) );
	}

	/**
	 * What the challenge action answers: the options, or a refusal.
	 *
	 * @return array{status: int, body: array<string, mixed>}
	 */
	public static function options_answer(): array {
		if ( ! self::is_post() ) {
			return self::refusal( self::wrong_method() );
		}

		$options = Manager::login_options();

		return is_wp_error( $options ) ? self::refusal( $options ) : array(
			'status' => 200,
			'body'   => $options,
		);
	}

	/**
	 * What the sign-in action answers: where to go next, or why not.
	 *
	 * The body is checked for shape before anything reads it, as the REST
	 * route's declared arguments checked it: every assertion field and the
	 * address is text, and the landing flags are yes or no. An array where
	 * text belongs was a warning an anonymous caller could write to the log.
	 * What runs after is the sign-in exactly as the route ran it
	 * (Rest\PasskeyController::complete_login()): the lockout and every
	 * other sign-in gate, the second-factor hand-off, the touch-only refusal,
	 * and the record of the sign-in.
	 *
	 * @param array<string, mixed> $body The posted JSON.
	 * @return array{status: int, body: array<string, mixed>}
	 */
	public static function sign_in_answer( array $body ): array {
		if ( ! self::is_post() ) {
			return self::refusal( self::wrong_method() );
		}

		foreach ( self::TEXT_FIELDS as $field ) {
			if ( isset( $body[ $field ] ) && ! is_string( $body[ $field ] ) ) {
				return self::refusal( new \WP_Error( 'bettershield_passkey_malformed', __( 'That did not work. Try again, or use another way to sign in.', 'bettershield' ), array( 'status' => 400 ) ) );
			}
		}

		foreach ( self::FLAGS as $flag ) {
			$body[ $flag ] = isset( $body[ $flag ] ) && rest_sanitize_boolean( $body[ $flag ] );
		}

		if ( isset( $body['handle'] ) ) {
			$body['handle'] = sanitize_text_field( (string) $body['handle'] );
		}

		$result = \BetterShield\Rest\PasskeyController::complete_login( $body );

		return is_wp_error( $result ) ? self::refusal( $result ) : array(
			'status' => 200,
			'body'   => $result,
		);
	}

	/** Both actions take a POST only: a link must never start a sign-in. */
	private static function is_post(): bool {
		return isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( sanitize_key( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) );
	}

	private static function wrong_method(): \WP_Error {
		return new \WP_Error( 'bettershield_passkey_method', __( 'Use the passkey button on the sign-in form.', 'bettershield' ), array( 'status' => 405 ) );
	}

	/**
	 * A refusal in the shape a REST error had: code, message and status, so
	 * the script reads it as it read the route's.
	 *
	 * @return array{status: int, body: array<string, mixed>}
	 */
	private static function refusal( \WP_Error $error ): array {
		$data   = $error->get_error_data();
		$status = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 400;

		return array(
			'status' => $status,
			'body'   => array(
				'code'    => (string) $error->get_error_code(),
				'message' => $error->get_error_message(),
				'data'    => array( 'status' => $status ),
			),
		);
	}

	/**
	 * @param array{status: int, body: array<string, mixed>} $answer
	 */
	private static function send( array $answer ): void {
		nocache_headers();
		wp_send_json( $answer['body'], $answer['status'] );
	}

	public function script(): void {
		if ( ! $this->rendered ) {
			return;
		}

		$config = array(
			// The sign-in screen's own address, moved where the site moved it.
			'options' => esc_url_raw( site_url( 'wp-login.php?action=' . self::OPTIONS, 'login_post' ) ),
			'verify'  => esc_url_raw( site_url( 'wp-login.php?action=' . self::SIGN_IN, 'login_post' ) ),
			// Whether the username field's own list offers a saved passkey
			// too. Only where the browser can; the button stays either way.
			'autofill' => Policy::instance()->settings()['autofill'],
			'working' => __( 'Waiting for your device…', 'bettershield' ),
			'hint'    => __( 'Still waiting. A password manager may be asking at the top of the screen. Otherwise, use your password.', 'bettershield' ),
			'stop'    => __( 'Stop Waiting', 'bettershield' ),
			// Neutral about the password, as the lines below are.
			'stopped' => __( 'Stopped. Try again when your device is ready, or use another way to sign in.', 'bettershield' ),
			// Neutral: under passkey-only the password is refused, so this
			// line cannot promise it (#2469).
			'failed'  => __( 'That did not work. Try again, or use another way to sign in.', 'bettershield' ),
			// The browser reports a device with no passkey here and a prompt
			// the person closed as one error, on purpose, so this covers both.
			// Neutral about the password for the same reason as above.
			'none'    => __( 'No passkey was used. If this device doesn’t have one for this site, sign in another way, then add one from your profile.', 'bettershield' ),
			// The sign-in answered with a page rather than with this plugin's
			// answer: another plugin took the sign-in over to ask for its own
			// code, and the browser ends signed out. Said plainly, without
			// naming it (#2465).
			'elsewhere' => __( 'Another security plugin here stepped in to ask for its own code. Sign in with your password and its code, or ask your administrator to choose one plugin.', 'bettershield' ),
		);

		/*
		 * Printed through core's inline-script tag, so the page's script
		 * attributes and any CSP nonce a site adds apply to it. Inline rather
		 * than enqueued: one file request before a form somebody is already
		 * waiting at, for a few lines, is not worth it.
		 */
		ob_start();
		?>
		( function () {
			var cfg = <?php echo wp_json_encode( $config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JSON_HEX flags escape script delimiters and quotes while preserving valid JavaScript values. ?>;
			var wrapper = document.getElementById( 'bettershield-passkey' );
			var button = document.getElementById( 'bettershield-passkey-button' );
			var note = document.getElementById( 'bettershield-passkey-note' );

			if ( ! wrapper || ! button || ! note ) {
				return;
			}

			/* No WebAuthn in this browser: take the button away rather than
			   leave one that cannot work. The password form is untouched. */
			if ( ! window.PublicKeyCredential ) {
				wrapper.style.display = 'none';
				return;
			}

			/* The hook that draws the button sits above the Log In row. Below
			   it is where a second way in belongs, so it does not compete
			   with the first. The form is complete by now, so this is one
			   synchronous move. */
			var submit = wrapper.parentNode && wrapper.parentNode.querySelector( 'p.submit' );
			if ( submit && submit.parentNode === wrapper.parentNode ) {
				submit.insertAdjacentElement( 'afterend', wrapper );
			}

			/* What the password form would have carried: where to go, for
			   how long, and whether this is the window that renews an
			   expired session. */
			var form = document.getElementById( 'loginform' );
			function field( name ) {
				return form && form.elements ? form.elements.namedItem( name ) : null;
			}
			function landing() {
				var redirect = field( 'redirect_to' );
				var remember = field( 'rememberme' );
				return {
					redirect_to: redirect && 'string' === typeof redirect.value ? redirect.value : '',
					remember: !! ( remember && remember.checked ),
					interim: !! field( 'interim-login' ),
					customize: !! field( 'customize-login' )
				};
			}

			function fromBase64Url( value ) {
				var padded = value.replace( /-/g, '+' ).replace( /_/g, '/' );
				var raw = window.atob( padded );
				var bytes = new Uint8Array( raw.length );
				for ( var i = 0; i < raw.length; i++ ) { bytes[ i ] = raw.charCodeAt( i ); }
				return bytes;
			}

			function toBase64Url( buffer ) {
				var bytes = new Uint8Array( buffer );
				var binary = '';
				for ( var i = 0; i < bytes.length; i++ ) { binary += String.fromCharCode( bytes[ i ] ); }
				return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
			}

			/* The server's own reason for a refusal (locked out, paused,
			   a passkey that cannot sign this account in here) is the one
			   worth reading. Only this plugin's own: a refusal another
			   plugin or a firewall answers with is not ours to word, and
			   gets the general line, as a failure that gives none does. */
			function refused( answer ) {
				var error = new Error( 'refused' );
				var ours = answer && 'string' === typeof answer.code && 0 === answer.code.indexOf( 'bettershield_' );
				error.reason = ours && 'string' === typeof answer.message ? answer.message : '';
				return error;
			}

			/* The device's signed answer, sent as the password form would be,
			   and the next page followed. The same for the button and for a
			   passkey picked from the username field's list. */
			function verify( options, credential ) {
				return window.fetch( cfg.verify, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify( Object.assign( landing(), {
						handle: options.handle,
						id: credential.id,
						clientDataJSON: toBase64Url( credential.response.clientDataJSON ),
						authenticatorData: toBase64Url( credential.response.authenticatorData ),
						signature: toBase64Url( credential.response.signature )
					} ) )
				} )
					/* This plugin answers in JSON. A page in its place is
					   another plugin that took the sign-in over. */
					.then( function ( r ) {
						return r.text().then( function ( text ) {
							try {
								return JSON.parse( text );
							} catch ( e ) {
								var other = new Error( 'elsewhere' );
								other.reason = cfg.elsewhere;
								throw other;
							}
						} );
					} )
					.then( function ( result ) {
						if ( result && result.redirect ) {
							window.location.assign( result.redirect );
							return;
						}
						throw refused( result );
					} );
			}

			/* A passkey offered in the username field's own list, beside the
			   saved passwords, where most people look. The request waits
			   quietly until one is picked; the button below cancels it, as a
			   browser holds one passkey request at a time. */
			var quiet = null;
			/* Refused picks from the list on this page. An authenticator that
			   answers without asking would otherwise be offered again, and
			   refused again, with no end. */
			var refusals = 0;

			function listen() {
				var user = document.getElementById( 'user_login' );
				if ( ! cfg.autofill || ! user || 'function' !== typeof window.PublicKeyCredential.isConditionalMediationAvailable ) {
					return;
				}

				window.PublicKeyCredential.isConditionalMediationAvailable().then( function ( available ) {
					if ( ! available || quiet ) {
						return;
					}

					var tokens = ( user.getAttribute( 'autocomplete' ) || 'username' ).split( /\s+/ );
					if ( -1 === tokens.indexOf( 'webauthn' ) ) {
						tokens.push( 'webauthn' );
						user.setAttribute( 'autocomplete', tokens.join( ' ' ) );
					}

					var mine = new window.AbortController();
					var lapse = null;
					var picked = false;
					quiet = mine;

					window.fetch( cfg.options, { method: 'POST', credentials: 'same-origin', signal: mine.signal } )
						.then( function ( r ) { return r.json(); } )
						.then( function ( options ) {
							/* No challenge (passkeys paused, too many tries):
							   the list offers passwords only, as before, and
							   the button still says why if it is pressed. */
							if ( ! options || ! options.challenge ) {
								quiet = null;
								return;
							}
							/* A challenge lasts five minutes. Ask for a fresh
							   one before it lapses, so a passkey picked after
							   a long wait still works. */
							lapse = window.setTimeout( function () {
								if ( quiet === mine ) {
									quiet = null;
									mine.abort();
									listen();
								}
							}, 270000 );
							return navigator.credentials.get( {
								mediation: 'conditional',
								publicKey: {
									challenge: fromBase64Url( options.challenge ),
									rpId: options.rpId,
									userVerification: 'preferred'
								},
								signal: mine.signal
							} ).then( function ( credential ) {
								window.clearTimeout( lapse );
								quiet = null;
								picked = true;
								button.disabled = true;
								note.textContent = cfg.working;
								return verify( options, credential );
							} );
						} )
						.catch( function ( error ) {
							window.clearTimeout( lapse );
							/* Canceled for the button or for a fresh
							   challenge: nothing went wrong. */
							if ( mine.signal.aborted ) {
								return;
							}
							quiet = null;
							/* Only a passkey that was picked and then refused
							   has something to say, and the list offers one
							   again for the next try. Anything before that
							   (no challenge, an answer that is not ours)
							   leaves the list to passwords, as before, and is
							   not asked again: a request that keeps failing
							   must not repeat on its own. */
							if ( ! picked ) {
								return;
							}
							button.disabled = false;
							note.textContent = ( error && error.reason ) || cfg.failed;
							/* Three refused picks and the list goes back to
							   passwords; the button still works. */
							refusals += 1;
							if ( refusals < 3 ) {
								listen();
							}
						} );
				} );
			}

			listen();

			button.addEventListener( 'click', function () {
				button.disabled = true;
				note.textContent = cfg.working;

				if ( quiet ) {
					var waiting = quiet;
					quiet = null;
					waiting.abort();
				}

				/* The request's own timeout doesn't close a prompt hidden behind
				   another window, so this does, and the person can too. */
				var controller = new window.AbortController();
				var stopped = false;
				var deadline = window.setTimeout( function () { controller.abort(); }, 120000 );
				var stop = document.createElement( 'button' );
				stop.type = 'button';
				stop.className = 'button';
				stop.style.width = '100%';
				stop.style.marginTop = '8px';
				stop.textContent = cfg.stop;
				stop.addEventListener( 'click', function () {
					stopped = true;
					controller.abort();
				} );

				/* A prompt that never comes looks like one that is slow. Say
				   so after a while; the password form is right there. */
				var hint = window.setTimeout( function () {
					note.textContent = cfg.hint;
					button.parentNode.insertBefore( stop, button.nextSibling );
				}, 15000 );

				function settled() {
					window.clearTimeout( hint );
					window.clearTimeout( deadline );
					if ( stop.parentNode ) { stop.parentNode.removeChild( stop ); }
				}

				window.fetch( cfg.options, { method: 'POST', credentials: 'same-origin', signal: controller.signal } )
					.then( function ( r ) { return r.json(); } )
					.then( function ( options ) {
						if ( ! options || ! options.challenge ) {
							throw refused( options );
						}
						return navigator.credentials.get( {
							publicKey: {
								challenge: fromBase64Url( options.challenge ),
								rpId: options.rpId,
								userVerification: 'preferred',
								timeout: 120000
							},
							signal: controller.signal
						} ).then( function ( credential ) {
							/* The device answered, so there is no more waiting to stop. */
							settled();
							return verify( options, credential );
						} );
					} )
					.catch( function ( error ) {
						settled();
						button.disabled = false;
						note.textContent = stopped ? cfg.stopped : ( error && error.reason ) || ( error && ( 'NotAllowedError' === error.name || 'AbortError' === error.name ) ? cfg.none : cfg.failed );
						/* Back where the person was, so the next try or the
						   way past it is one key away. */
						button.focus();
						/* And the username field's list offers a passkey
						   again. */
						listen();
					} );
			} );
		}() );
		<?php
		wp_print_inline_script_tag( (string) ob_get_clean() );
	}

	/**
	 * Whether anybody has a passkey a browser here would offer.
	 *
	 * Asked before the button is drawn, and deliberately not per-account: the
	 * sign-in form does not know who is standing in front of it, and asking
	 * would mean telling an anonymous visitor which accounts have one.
	 *
	 * Only credentials of the relying party this site asks for. One made for
	 * a different domain is never presented however many are on record, so a
	 * button drawn on the strength of it is a button that can only fail.
	 */
	private static function any_enrolled(): bool {
		return Store::any_enrolled();
	}
}
