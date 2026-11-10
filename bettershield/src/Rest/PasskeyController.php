<?php
/**
 * REST surface for passkeys.
 *
 * Two of these routes are open to anyone, and that is deliberate: signing in
 * happens before there is anybody to check. They are written to give an
 * anonymous caller nothing — the options route names no accounts, and every
 * failure answers with the same refusal so the endpoint cannot be used to
 * learn who has a passkey.
 *
 * Listing keys needs a signed-in user. Adding or removing one needs a signed-in
 * browser session, and touches that user's own, with one exception: an
 * administrator may remove every passkey of another account they can edit,
 * after confirming their password, which is how somebody who lost theirs
 * under a passkey-only policy is let back in to sign in with a password.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Events\Writer;
use BetterShield\Passkeys\Manager;
use BetterShield\Passkeys\Policy;
use BetterShield\Passkeys\Store;
use BetterShield\Recovery\SafeMode;
use BetterShield\TwoFactor\LoginStep;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasskeyController {

	/** Each request's answer to whether the holder proved it is them. */
	private static ?\WeakMap $proved = null;

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		$signed_in = static function (): bool {
			return is_user_logged_in();
		};

		// A passkey is a sign-in credential, so adding or removing one is a
		// change to how this account signs in. An application password is
		// exempt from the sign-in gate and must not be able to enroll a
		// credential of its own choosing, or strip the ones already there.
		$interactive = static function () {
			return Permissions::interactive();
		};

		/*
		 * And proof that this is the account holder rather than somebody at an
		 * unlocked screen. A passkey that verifies its holder signs this
		 * account in without its second factor, and outlives a new password,
		 * so adding one adds a way in and removing one takes a way in away.
		 * Finishing a registration needs the challenge only this step issues,
		 * so asking here covers it.
		 */
		$holder = static function ( \WP_REST_Request $request ) use ( $interactive ) {
			$session = $interactive();

			if ( true !== $session ) {
				return $session;
			}

			/*
			 * Core asks a route's permission again to answer its Allow header,
			 * after the route has run. A code is spent by being checked, so the
			 * answer is kept for this request rather than asked for twice.
			 */
			self::$proved ??= new \WeakMap();

			if ( ! isset( self::$proved[ $request ] ) ) {
				self::$proved[ $request ] = self::holder_proved( wp_get_current_user(), (string) $request->get_param( 'code' ) );
			}

			return self::$proved[ $request ];
		};

		/*
		 * What the browser sends back from an assertion: base64url text, all of
		 * it. Declared so core refuses a body of the wrong shape before the
		 * callback runs — casting an array to a string emits a warning, so a
		 * caller sending `{"id":[1]}` was a lever on the error log and, with
		 * display on, on the JSON body it printed ahead of. The sign-in page's
		 * own actions check the same shape themselves (Passkeys\LoginForm).
		 *
		 * Both callbacks are named on every field. Core runs a validator only
		 * where the argument names one, and it falls back to its own combined
		 * parser only for an argument that names no sanitizer either — so a
		 * hand-rolled sanitizer with no validator beside it is the one shape
		 * that gets no type check at all, which is what `handle` was.
		 */
		$text = array(
			'type'              => 'string',
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'rest_sanitize_request_arg',
		);

		$assertion = array(
			// The one field that is read back out as text rather than decoded
			// as base64url, so it keeps the stricter sanitizer.
			'handle'            => array(
				'type'              => 'string',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_text_field',
			),
			'id'                => $text,
			'clientDataJSON'    => $text,
			'authenticatorData' => $text,
			'signature'         => $text,
		);

		/*
		 * Signing in with a passkey is not here. It runs as two sign-in page
		 * actions (Passkeys\LoginForm), as the two-factor code step does: a
		 * site that closes REST to signed-out visitors closed the passkey
		 * button with it, and its passkey-only accounts had no way in but
		 * the recovery link (#2462).
		 */

		register_rest_route(
			'bettershield/v1',
			'/passkeys',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( self::payload() );
					},
					'permission_callback' => $signed_in,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/passkeys/register-options',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$options = Manager::registration_options( wp_get_current_user() );

					return is_wp_error( $options ) ? $options : rest_ensure_response( $options );
				},
				'permission_callback' => $holder,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/passkeys/register',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body   = $request->get_json_params();
					$result = Manager::register( wp_get_current_user(), is_array( $body ) ? $body : array() );

					return is_wp_error( $result ) ? $result : rest_ensure_response( self::payload() );
				},
				'permission_callback' => $interactive,
			)
		);

		/*
		 * Proof for an account with nothing else to give it with: one of its
		 * own passkeys answers a challenge issued to it in this session, and
		 * the answer stands for a short while, as a password typed again does.
		 */
		register_rest_route(
			'bettershield/v1',
			'/passkeys/confirm-options',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$options = Manager::confirmation_options( wp_get_current_user() );

					return is_wp_error( $options ) ? $options : rest_ensure_response( $options );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/passkeys/confirm',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body      = $request->get_json_params();
					$confirmed = Sudo::confirm_passkey( is_array( $body ) ? $body : array() );

					return is_wp_error( $confirmed ) ? $confirmed : rest_ensure_response( $confirmed );
				},
				'permission_callback' => $interactive,
				'args'                => $assertion,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/passkeys/(?P<id>\d+)',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'remove' ),
				'permission_callback' => $holder,
			)
		);

		/*
		 * Somebody else's passkeys, removed by whoever manages the site: the
		 * support path for a lost device. Under passkey-only that account's
		 * password is refused while it holds one, and its holder has neither
		 * the recovery link nor printed codes. Removing them is what lets the
		 * password back in. Remove only: a passkey is made by the device in
		 * front of its holder, never by an administrator for them.
		 */
		register_rest_route(
			'bettershield/v1',
			'/passkeys/users/(?P<id>[0-9]+)/remove',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$user_id = (int) $request['id'];

					// On a network, "no such account" covers accounts of other
					// sites too: a site's administrator manages that site's
					// members, not the network's.
					if ( ! get_userdata( $user_id ) instanceof \WP_User || ( is_multisite() && ! is_super_admin() && ! is_user_member_of_blog( $user_id ) ) ) {
						return new \WP_Error( 'bettershield_no_user', __( 'No such account.', 'bettershield' ), array( 'status' => 404 ) );
					}

					// Your own come off one at a time on your own profile,
					// which asks you to prove you hold the account.
					if ( get_current_user_id() === $user_id ) {
						return new \WP_Error( 'bettershield_own_passkeys', __( 'Remove your own passkeys one at a time on your profile.', 'bettershield' ), array( 'status' => 403 ) );
					}

					// Managing this plugin is not the same as having any say
					// over this account. The account's own editor does.
					if ( ! current_user_can( 'edit_user', $user_id ) ) {
						return new \WP_Error( 'bettershield_cannot_edit_user', __( 'You cannot change this account.', 'bettershield' ), array( 'status' => 403 ) );
					}

					// Where a network keeps one table of passkeys for every
					// site, an account's are removed from all of them at once,
					// which is the network's decision rather than one site's.
					if ( ! self::may_remove_across_sites() ) {
						return new \WP_Error( 'bettershield_network_passkeys', __( 'Passkeys work on every site in this network, so only a network administrator can remove them.', 'bettershield' ), array( 'status' => 403 ) );
					}

					// Nothing to remove is not a factor removed: no event, and
					// nobody signed out for a passkey they never had.
					if ( 0 === Store::count_for_user( $user_id ) ) {
						return new \WP_Error( 'bettershield_no_passkeys', __( 'This account has no passkeys.', 'bettershield' ), array( 'status' => 409 ) );
					}

					$removed = Store::forget_user( $user_id );

					// What may have been opened with them does not outlive them.
					\BetterShield\Login\SessionReset::credential_changed( $user_id, 'passkey' );

					$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( get_userdata( $user_id ) );

					Writer::instance()->record(
						'passkey_removed',
						$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
						array(
							'object_type' => 'user',
							'object_id'   => (string) $user_id,
							'context'     => array(
								'by'    => 'admin',
								'count' => $removed,
							),
						)
					);

					return rest_ensure_response( array( 'removed' => $removed ) );
				},
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
			)
		);
	}

	/**
	 * Whether the signed-in account may remove somebody's passkeys from every
	 * site that shares them: anybody off a network, or where each site keeps
	 * its own; only a network administrator where one table holds them all.
	 */
	public static function may_remove_across_sites(): bool {
		return ! is_multisite() || ! \BetterShield\Database\Schema::is_network_table_here( 'passkeys' ) || is_super_admin();
	}

	/**
	 * Whether the person changing this account's passkeys proved they hold it.
	 *
	 * An account with two-factor proves it with a current app code or an
	 * unused backup code, as turning two-factor off does. An account with a
	 * password the site accepts types it again, whatever the site's own
	 * setting for asking it elsewhere. An account that signs in by passkey
	 * alone answers with one of those passkeys, asked for again in this
	 * session. Safe mode, the way back in, asks for nothing, and an account
	 * holding none of the three has nothing it could be asked for.
	 *
	 * @return true|\WP_Error
	 */
	public static function holder_proved( \WP_User $user, string $code ) {
		if ( SafeMode::is_active() ) {
			return true;
		}

		$two_factor = \BetterShield\TwoFactor\Manager::instance();

		if ( $two_factor->enabled( $user->ID ) ) {
			if ( '' === trim( $code ) ) {
				return new \WP_Error( 'bettershield_current_code_required', __( 'Enter a current authenticator code or unused backup code to change passkeys.', 'bettershield' ), array( 'status' => 403 ) );
			}

			// Only something shaped like a code is checked, so typing anything
			// else spends none of the account's guesses.
			$digits  = (string) preg_replace( '/[^0-9]/', '', $code );
			$checked = in_array( strlen( $digits ), array( 6, 8 ), true ) ? $two_factor->check_code( $user->ID, $code ) : false;

			if ( is_wp_error( $checked ) ) {
				return $checked;
			}

			return true === $checked ? true : new \WP_Error( 'bettershield_wrong_code', $two_factor->wrong_code_message( (int) $user->ID, $code, __( 'That code does not match. Enter a current app code or an unused backup code.', 'bettershield' ) ), array( 'status' => 403 ) );
		}

		/*
		 * A password the site has asked this account to replace proves
		 * nothing: whoever holds it may be the reason for the hold.
		 */
		if ( \BetterShield\Remediation\PasswordHold::blocks( (int) $user->ID ) ) {
			return new \WP_Error( 'bettershield_new_password_required', __( 'Set a new password with “Lost your password?” before changing passkeys.', 'bettershield' ), array( 'status' => 403 ) );
		}

		$has_password = '' !== (string) $user->user_pass && ! Policy::instance()->refuses_password( $user );

		if ( $has_password && ! Sudo::password_confirmed_recently( (int) $user->ID ) ) {
			return new \WP_Error( 'bettershield_confirm_password', __( 'Confirm your password to add or remove a passkey.', 'bettershield' ), array( 'status' => 403 ) );
		}

		/*
		 * No password the site accepts and no second factor: one of the
		 * account's own passkeys is what is left, asked for again in this
		 * session. Without it, whoever held the session added a passkey of
		 * their own, and it went on signing in after the session ended.
		 */
		if ( ! $has_password && Store::count_usable_for_user( (int) $user->ID ) > 0 && ! Sudo::passkey_confirmed_recently( (int) $user->ID ) ) {
			return new \WP_Error( 'bettershield_confirm_passkey', __( 'Confirm with one of your passkeys before adding or removing one.', 'bettershield' ), array( 'status' => 403 ) );
		}

		return true;
	}

	/**
	 * Verify an assertion and start a session — or, when the passkey proved
	 * only that a device was touched and the account has a second factor,
	 * send the person to the code screen with the passkey standing in for
	 * the password.
	 *
	 * Called from the sign-in page's own action (Passkeys\LoginForm), with
	 * the body already checked there for shape (#2462).
	 *
	 * @param array<string, mixed> $body The assertion, and where to land: `redirect_to`, `remember`, `interim`, `customize`.
	 * @return array{redirect: string}|\WP_Error
	 */
	public static function complete_login( array $body ) {
		$user_verified = false;
		$user          = Manager::verify_login( $body, $user_verified );
		$redirect_to   = is_string( $body['redirect_to'] ?? null ) ? (string) $body['redirect_to'] : '';
		$remember      = ! empty( $body['remember'] );
		$interim       = ! empty( $body['interim'] );
		$customize     = ! empty( $body['customize'] );

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		/*
		 * Another security plugin has two-factor set up for this account. It
		 * asks for its own code after any sign-in, this one included, and
		 * takes the sign-in over to do it: the browser ended signed out with
		 * a general failure, or that plugin's raw refusal (#2465). Said
		 * plainly instead, before anything starts, and its check is left to
		 * stand: the account signs in with its password and that code.
		 */
		if ( '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user ) ) {
			return new \WP_Error(
				'bettershield_passkey_two_factor_elsewhere',
				__( 'Another security plugin here also asks for a code for your account. Sign in with your password and its code, or ask your administrator to choose one plugin.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		/*
		 * Everything that guards a sign-in still applies. A passkey proves who
		 * is holding the device; it does not exempt the account from the
		 * site's own rules — the lockout, a spam flag on a network, a
		 * third-party gate — and skipping them would make this the softest
		 * way in rather than the strongest. The chain is run from the account
		 * through the marked re-entry, so core's password handlers pass it
		 * through and this plugin's own gate stands aside by name — the
		 * passkey factor rule is applied just below, not by the gate.
		 */
		$verdict = \BetterShield\TwoFactor\Manager::instance()->reenter_chain( $user );

		if ( ! $verdict instanceof \WP_User || (int) $verdict->ID !== (int) $user->ID ) {
			$error = $verdict instanceof \WP_Error ? $verdict : new \WP_Error( 'bettershield_passkey_rejected', __( 'That passkey could not be used to sign in.', 'bettershield' ) );
			$error->add_data( array( 'status' => 403 ) );

			return $error;
		}

		/*
		 * A passkey the person unlocked with a fingerprint, a face or a PIN
		 * carries the second factor with it. One that only asked for a touch
		 * proves possession alone, and a two-factor account still owes its
		 * code — so that sign-in is parked and continues on the code screen,
		 * exactly as it would after a password.
		 */
		if ( LoginStep::second_factor_required( $user, 'passkey', $user_verified ) ) {
			self::record_use( $user, false );

			return array(
				'redirect' => LoginStep::instance()->hand_off( $user, $remember, $redirect_to, $interim, $customize, LoginStep::ACTION, 'passkey' ),
			);
		}

		/*
		 * Nothing further will be asked, so this passkey is the whole sign-in
		 * — and a whole sign-in has to prove the person, not just that
		 * somebody was standing there. A key that only asked for a touch
		 * proves possession: enough as one factor of two, not enough on its
		 * own. A security key with no PIN set, lost or shared on a kiosk, is
		 * the case this refuses.
		 *
		 * The browser is still asked for verification as "preferred" rather
		 * than "required", deliberately: a touch-only key is a supported
		 * second factor for an account that has a code, and asking the browser
		 * to require verification would refuse that key before this site ever
		 * saw it. The rule belongs here, where what the key is being used for
		 * is known.
		 *
		 * Safe mode is exempt, as it is everywhere else: it exists for the
		 * owner who is already locked out.
		 */
		if ( ! $user_verified && ! SafeMode::is_active() ) {
			self::record_use( $user, false );

			/*
			 * What to try instead depends on whether a password would work for
			 * this account, which is a narrower question than whether the
			 * policy names one of its roles: an account holding no passkey
			 * keeps its password however many roles are named. Sending a
			 * reader whose password IS refused to that password leaves them
			 * with two shut doors and an instruction pointing at one of them.
			 */
			// And the way back named is one this account holds: the link and
			// the printed codes are the owner's, not an editor's.
			if ( ! Policy::instance()->armed_for( $user ) ) {
				$instead = __( 'This key needs your fingerprint, face or PIN, not just a touch. Your password also works.', 'bettershield' );
			} elseif ( user_can( $user, \BetterShield\Capabilities::MANAGE ) ) {
				$instead = __( 'This key needs your fingerprint, face or PIN, not just a touch. If it cannot, use your recovery link or a recovery code.', 'bettershield' );
			} else {
				$instead = __( 'This key needs your fingerprint, face or PIN, not just a touch. If it cannot, ask an administrator to remove your passkeys so your password works again.', 'bettershield' );
			}

			return new \WP_Error(
				'bettershield_passkey_verification_required',
				$instead,
				array( 'status' => 403 )
			);
		}

		wp_set_current_user( $user->ID );
		// Said before the cookie, so the session's record carries it: on a
		// network, a site that asks for a passkey takes a session a passkey
		// opened elsewhere, and not one a password opened.
		\BetterShield\Login\Sessions::opening_by( 'passkey' );
		wp_set_auth_cookie( $user->ID, $remember );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own action.

		self::record_use( $user, true );

		return array(
			'redirect' => self::landing( $user, $redirect_to, $interim, $customize ),
		);
	}

	/**
	 * Where a whole passkey sign-in sends the browser: where core would after
	 * a password. The script follows the answer without asking, so an
	 * address this code did not choose is held to this site, as
	 * wp_safe_redirect() would hold it.
	 */
	private static function landing( \WP_User $user, string $redirect_to, bool $interim, bool $customize ): string {
		if ( $interim ) {
			return LoginStep::url( '', true, $customize, \BetterShield\Passkeys\LoginForm::DONE );
		}

		$target = '' !== $redirect_to ? $redirect_to : admin_url();

		/** This filter is documented in wp-login.php */
		$target      = (string) apply_filters( 'login_redirect', $target, $redirect_to, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter.
		$destination = LoginStep::destination( $user, $target );

		return $destination['own'] ? $destination['url'] : wp_validate_redirect( $destination['url'], admin_url() );
	}

	private static function record_use( \WP_User $user, bool $completed ): void {
		Writer::instance()->record(
			'passkey_used',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => (int) $user->ID,
				'actor_label' => $user->user_login,
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array( 'completed' => $completed ),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function remove( \WP_REST_Request $request ) {
		$user = wp_get_current_user();
		$id   = (int) $request->get_param( 'id' );


		$removed = Store::remove_checked( (int) $user->ID, $id );
		if ( is_wp_error( $removed ) ) { return $removed; }

		// Removing a passkey is what someone does when they suspect it — the
		// sessions it may have opened should not outlive it. The device this
		// was asked from stays signed in.
		\BetterShield\Login\SessionReset::credential_changed( (int) $user->ID, 'passkey' );

		// A factor coming off a privileged account goes out ahead of the
		// digest, the way the second factor does. On an ordinary account it
		// stays the quiet event it was.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( $user );

		Writer::instance()->record(
			'passkey_removed',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
			)
		);

		return rest_ensure_response( self::payload() );
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function payload(): array {
		$availability = Manager::availability();

		return array(
			'available' => $availability['available'],
			'reason'    => $availability['reason'],
			'label'     => $availability['label'],
			'intro'     => \BetterShield\Passkeys\ProfilePanel::instance()->intro_for( wp_get_current_user() ),
			'passkeys'  => Store::for_user( (int) wp_get_current_user()->ID ),
			'max'       => Store::MAX_PER_USER,
			// Changing passkeys asks this account for a current code, so the
			// screen asks with the press rather than after a refusal (#2147).
			// Not in safe mode, the way back in, where nothing is asked.
			'needs_code' => ! SafeMode::is_active() && \BetterShield\TwoFactor\Manager::instance()->enabled( (int) wp_get_current_user()->ID ),
			// Another security plugin has two-factor set up for this account,
			// so no passkey is offered to it (#2465).
			'elsewhere'  => '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( wp_get_current_user() ),
			// For whoever manages the site: two plugins handle two-factor,
			// and how many accounts a passkey cannot sign in because of it.
			'shared'     => current_user_can( \BetterShield\Capabilities::MANAGE ) ? \BetterShield\Onboarding\Coexistence::two_factor_accounts_elsewhere() : null,
		);
	}
}
