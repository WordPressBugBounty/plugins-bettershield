<?php
/**
 * Enrolling a passkey, and checking one at sign-in.
 *
 * A passkey is a key pair the device keeps and the site never sees the private
 * half of. There is no shared secret to steal from this database, nothing to
 * phish — the browser will only sign for the origin the key was made for — and
 * nothing to type. That is the whole reason to build it.
 *
 * **This is purely additive, and the lockout invariant holds by construction.**
 * A passkey is another way in, never the only one: passwords, backup codes,
 * two-factor and the recovery link all keep working exactly as before. Nothing
 * here can lock anybody out of anything, which is why it needs no arming
 * sequence of the kind two-factor has.
 *
 * Every check below refuses rather than assumes. A verification step that
 * cannot be completed is a failed verification, never a passed one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

use BetterShield\Events\Writer;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Manager {

	public const PURPOSE_REGISTER = 'register';
	public const PURPOSE_LOGIN    = 'login';
	public const PURPOSE_CONFIRM  = 'confirm';

	/**
	 * Whether this site can do passkeys at all.
	 *
	 * WebAuthn requires a secure context. On plain HTTP the browser refuses
	 * outright, so the feature says so rather than offering a button that
	 * fails — except on localhost, which browsers treat as secure.
	 *
	 * Everything that can refuse a password in favor of a passkey asks this
	 * first, so it is the one place that decides whether the feature exists on
	 * this site at all.
	 *
	 * @return array{available: bool, reason: string, label: string}
	 */
	public static function availability(): array {
		$answer = array(
			'available' => true,
			'reason'    => '',
			'label'     => '',
		);

		// `label` is the short status a screen shows; `reason` the sentence
		// with the next step (#2235).
		if ( ! extension_loaded( 'openssl' ) ) {
			$answer = array(
				'available' => false,
				'reason'    => __( 'Passkeys are not available on this site yet. Site owner: ask your host to turn on PHP’s OpenSSL extension.', 'bettershield' ),
				'label'     => __( 'Requires PHP OpenSSL', 'bettershield' ),
			);
		} elseif ( ! self::is_secure_context() ) {
			$answer = array(
				'available' => false,
				'label'     => __( 'Requires HTTPS', 'bettershield' ),
				// Not "until the site has a certificate": a site behind a proxy
				// that ends TLS has one, and is offered passkeys below on the
				// strength of the address rather than the connection.
				'reason'    => __( 'Passkeys work only when this site uses a secure https:// address. Turn on HTTPS, then add a passkey.', 'bettershield' ),
			);
		}

		/**
		 * Whether this site can do passkeys, and why not when it cannot.
		 *
		 * The checks above cover what this code can see. A host that has taken
		 * the API away in some other way answers here, and everything that
		 * offers or requires a passkey follows the answer.
		 *
		 * @param array{available: bool, reason: string, label: string} $answer What the checks above decided.
		 */
		$filtered = apply_filters( 'bettershield_passkey_availability', $answer );

		if ( ! is_array( $filtered ) || ! isset( $filtered['available'] ) ) {
			return $answer;
		}

		$available = (bool) $filtered['available'];
		$label     = (string) ( $filtered['label'] ?? '' );

		return array(
			'available' => $available,
			'reason'    => (string) ( $filtered['reason'] ?? '' ),
			// A filter that names no status of its own reads as plainly unavailable.
			'label'     => $available ? '' : ( '' !== $label ? $label : __( 'Unavailable', 'bettershield' ) ),
		);
	}

	/**
	 * Whether this site can do passkeys, as a yes or no and with no sentence
	 * built: the same checks and filter as availability().
	 *
	 * For the sign-in path. A translated string there loads the text domain
	 * just in time, which asks for the current user while the auth cookie is
	 * still being checked, and that check runs again: on a network served
	 * over http:// every subsite request ran out of memory (#2628).
	 */
	public static function is_available(): bool {
		$answer = array(
			'available' => extension_loaded( 'openssl' ) && self::is_secure_context(),
			'reason'    => '',
			'label'     => '',
		);

		/** This filter is documented in src/Passkeys/Manager.php */
		$filtered = apply_filters( 'bettershield_passkey_availability', $answer );

		return is_array( $filtered ) && isset( $filtered['available'] ) ? (bool) $filtered['available'] : $answer['available'];
	}

	/**
	 * The relying party: the domain a passkey is bound to.
	 *
	 * Bare host, never a scheme or a port. A key made for one domain cannot be
	 * used on another, and that binding is what makes passkeys unphishable —
	 * so this value is derived from the site rather than configurable.
	 *
	 * Where several sites share one host, the shared domain is the relying
	 * party and every site of it asks for the same credentials. That is only
	 * allowed to move up: the spec permits a relying party that is a
	 * registrable suffix of the origin's host and nothing else, so this
	 * answers the shared domain when this site's host is that domain or sits
	 * under it, and the site's own host in every other case — including a site
	 * addressed at a domain of its own, whose credentials stay its own.
	 *
	 * Sites addressed at one host by path are unaffected: their host already
	 * is the shared domain, and their existing credentials keep working.
	 */
	public static function rp_id(): string {
		$host = self::host_of( (string) home_url() );

		if ( ! is_multisite() ) {
			return $host;
		}

		// The shared domain without a port: the relying party is a bare host,
		// and a development address carries one where a live one does not.
		$network = get_network();
		$shared  = $network instanceof \WP_Network ? strtolower( explode( ':', (string) $network->domain )[0] ) : '';

		if ( '' === $shared ) {
			return $host;
		}

		return $host === $shared || str_ends_with( $host, '.' . $shared ) ? $shared : $host;
	}

	private static function host_of( string $url ): string {
		$host = '' !== $url ? wp_parse_url( $url, PHP_URL_HOST ) : null;

		return is_string( $host ) && '' !== $host ? strtolower( $host ) : 'localhost';
	}

	/**
	 * What the browser will report as the origin, for comparison.
	 *
	 * The host and port are the site's. The scheme follows the connection:
	 * home_url() already answers with https on a request that arrived over
	 * https, whatever the stored site address says, so a site whose address
	 * still reads http but which is served over https is compared at the
	 * https origin — the one the browser signs for.
	 */
	public static function origin(): string {
		$parts  = wp_parse_url( home_url() );
		$scheme = isset( $parts['scheme'] ) ? (string) $parts['scheme'] : 'https';
		$host   = isset( $parts['host'] ) ? (string) $parts['host'] : '';
		$port   = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';

		return $scheme . '://' . $host . $port;
	}

	/**
	 * What an account another security plugin covers is told about passkeys,
	 * without naming that plugin: the account holder may not know it, and
	 * the choice of one plugin for two-factor is the administrator's (#2465).
	 */
	public static function elsewhere_words(): string {
		return __( 'Another security plugin handles two-factor for your account here, so a passkey cannot sign you in. Use your password and its code, or ask your administrator.', 'bettershield' );
	}

	/* ---- registration --------------------------------------------------- */

	/**
	 * The options a browser needs to create a passkey for this account.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function registration_options( \WP_User $user ) {
		$availability = self::availability();

		if ( ! $availability['available'] ) {
			return new \WP_Error( 'bettershield_passkey_unavailable', $availability['reason'], array( 'status' => 409 ) );
		}

		// Another plugin's code would still be asked after it, so it could
		// never sign this account in (#2465).
		if ( '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user ) ) {
			return new \WP_Error( 'bettershield_passkey_two_factor_elsewhere', self::elsewhere_words(), array( 'status' => 409 ) );
		}

		$issued = Store::issue_challenge( self::PURPOSE_REGISTER, (int) $user->ID );

		if ( is_wp_error( $issued ) ) {
			return $issued;
		}

		return array(
			'challenge' => self::b64url( $issued['challenge'] ),
			'handle'    => $issued['handle'],
			'rp'        => array(
				'id'   => self::rp_id(),
				'name' => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
			),
			'user'      => array(
				// A per-account identifier that is not the login name and not
				// the email: it goes onto the device and there is no reason for
				// it to carry anything about the person.
				'id'          => self::b64url( self::user_handle( $user ) ),
				'name'        => $user->user_login,
				'displayName' => '' !== $user->display_name ? $user->display_name : $user->user_login,
			),
			'algorithms' => CoseKey::supported(),
			/*
			 * Devices this account already enrolled. The browser uses these to
			 * decline a second registration of the same authenticator rather
			 * than making one the unique index would then reject — the same
			 * outcome, reached without an error the person has to read.
			 */
			'registered' => Store::credential_ids_for_user( (int) $user->ID ),
			/*
			 * How hard the browser is told to ask.
			 *
			 * Preferred everywhere else, deliberately: a key that only does a
			 * touch is a fine second factor for an account that also has a
			 * code, and demanding verification would refuse it before this
			 * site ever saw it.
			 *
			 * Required for the one case where it strands somebody. Under
			 * passkey-only the password is refused, so an account whose single
			 * key asks for a touch and nothing more can sign in through
			 * neither — the key is turned away at the door and the password is
			 * too, and recovery is the only way left. Asked at enrollment,
			 * that is a device the person can swap while they are standing
			 * there. Asked at sign-in it is a lockout.
			 */
			'verification' => self::verification_for( $user ),
			/*
			 * The sign-in form has no username step: it asks the browser for
			 * any key it holds for this site. A key that keeps nothing on the
			 * device is never offered there, so it is asked for here and
			 * refused below when the browser says it was not given one (#2469).
			 */
			'residentKey'  => 'required',
		);
	}

	/**
	 * What the browser said about whether the new key can sign in without a
	 * username: its `credProps.rk`, sent on as `discoverable`. Null where it
	 * said nothing, which older browsers do.
	 *
	 * @param array<string, mixed> $response
	 */
	private static function reported_discoverable( array $response ): ?bool {
		if ( ! array_key_exists( 'discoverable', $response ) ) {
			return null;
		}

		$value = $response['discoverable'];

		if ( is_bool( $value ) ) {
			return $value;
		}

		if ( is_int( $value ) || is_string( $value ) ) {
			$value = strtolower( trim( (string) $value ) );

			if ( in_array( $value, array( '1', 'true' ), true ) ) {
				return true;
			}

			if ( in_array( $value, array( '0', 'false' ), true ) ) {
				return false;
			}
		}

		return null;
	}

	/**
	 * Whether this enrollment has to produce a key that verifies its holder.
	 *
	 * Required while the policy names this role and no usable credential has
	 * proved verification. An older credential with no recorded verification
	 * is not evidence that a new touch-only key would leave a working way in.
	 */
	private static function verification_for( \WP_User $user ): string {
		if ( ! Policy::instance()->applies_to( $user ) ) {
			return 'preferred';
		}

		// The ones a browser here would actually offer. An account holding
		// only credentials of an older relying party has nothing to sign in
		// with, so this enrollment is the first that counts.
		return 0 === Store::count_verified_for_user( (int) $user->ID ) ? 'required' : 'preferred';
	}

	/**
	 * Check what the browser produced, and enroll it.
	 *
	 * @param array<string, mixed> $response
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function register( \WP_User $user, array $response ) {
		$challenge = Store::consume_challenge( (string) ( $response['handle'] ?? '' ), self::PURPOSE_REGISTER, (int) $user->ID );

		if ( null === $challenge ) {
			return new \WP_Error(
				'bettershield_passkey_challenge',
				__( 'That registration took too long or was already used. Start again.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$client_data = self::check_client_data( (string) ( $response['clientDataJSON'] ?? '' ), $challenge, 'webauthn.create' );

		if ( is_wp_error( $client_data ) ) {
			return $client_data;
		}

		$attestation = self::b64url_decode( (string) ( $response['attestationObject'] ?? '' ) );

		try {
			$decoded = Cbor::decode( $attestation );
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'bettershield_passkey_attestation', __( 'That security key sent something this site could not read.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( ! is_array( $decoded ) || ! isset( $decoded['authData'] ) || ! is_string( $decoded['authData'] ) ) {
			return new \WP_Error( 'bettershield_passkey_attestation', __( 'That security key sent an incomplete registration.', 'bettershield' ), array( 'status' => 400 ) );
		}

		// A registration is checked against the relying party this site asked
		// for, which is also the one the row about to be written records.
		$parsed = self::parse_authenticator_data( (string) $decoded['authData'], true, self::rp_id() );

		if ( is_wp_error( $parsed ) ) {
			return $parsed;
		}

		/*
		 * A key the browser says it could not store on the device. Saved, it
		 * would be listed and never sign in, and under passkey-only it would
		 * be the one key the password was refused for (#2469).
		 */
		$discoverable = self::reported_discoverable( $response );

		if ( false === $discoverable ) {
			return new \WP_Error(
				'bettershield_passkey_not_discoverable',
				__( 'This key can’t sign you in without a username. Use a passkey saved on your phone, computer or password manager, or a security key with a PIN.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		/*
		 * Asked of the browser in the options, and checked here, because the
		 * request is only a request: a client that ignores it sends a
		 * touch-only key, and stored, that key is the one thing this account
		 * may sign in with and the one thing the sign-in turns away. Read
		 * against the same answer the options gave, so a second key and an
		 * account outside the policy are not held to it.
		 */
		if ( 'required' === self::verification_for( $user ) && ! $parsed['user_verified'] ) {
			return new \WP_Error(
				'bettershield_passkey_verification_needed',
				__( 'Your role needs a passkey that checks your fingerprint, face or PIN. Set a PIN on this key or use another.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		$key = CoseKey::to_pem( $parsed['cose'] );

		if ( is_wp_error( $key ) ) {
			return $key;
		}

		$label = sanitize_text_field( (string) ( $response['label'] ?? '' ) );
		if ( '' === $label ) { $label = Providers::name( $parsed['aaguid'] ); }

		$added = Store::add(
			(int) $user->ID,
			self::b64url( $parsed['credential_id'] ),
			$key['pem'],
			$key['alg'],
			$parsed['sign_count'],
			sanitize_text_field( (string) ( $response['transports'] ?? '' ) ),
			$label,
			$parsed['user_verified'],
			$discoverable
		);

		if ( is_wp_error( $added ) ) {
			return $added;
		}

		// A credential on a privileged account is a standing way into the
		// site, and it goes out ahead of the digest. On an ordinary account
		// it stays the quiet event it was.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( $user );

		Writer::instance()->record(
			'passkey_registered',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array( 'label' => $label ),
			)
		);

		return array( 'passkeys' => Store::for_user( (int) $user->ID ) );
	}

	/* ---- signing in ------------------------------------------------------ */

	/**
	 * The options a browser needs to sign in with a passkey.
	 *
	 * No credential list is sent. The browser offers whatever it holds for
	 * this domain and the site works out who that is afterwards — which is
	 * what lets somebody sign in without typing a username, and means this
	 * endpoint tells an anonymous caller nothing about who has an account.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function login_options() {
		$availability = self::availability();

		if ( ! $availability['available'] ) {
			return new \WP_Error( 'bettershield_passkey_unavailable', $availability['reason'], array( 'status' => 409 ) );
		}

		$issued = Store::issue_challenge( self::PURPOSE_LOGIN );

		if ( is_wp_error( $issued ) ) {
			return $issued;
		}

		return array(
			'challenge' => self::b64url( $issued['challenge'] ),
			'handle'    => $issued['handle'],
			'rpId'      => self::rp_id(),
		);
	}

	/**
	 * Verify an assertion and answer with the account it belongs to.
	 *
	 * Whether the authenticator verified the *person* — a fingerprint, a face,
	 * a PIN — and not merely their presence (a touch on a key) is reported
	 * beside the account, because it decides whether this sign-in already
	 * carries a second factor or still owes one.
	 *
	 * @param array<string, mixed> $response
	 * @param bool|null            $user_verified Set to whether the authenticator verified the person.
	 * @return \WP_User|\WP_Error
	 */
	public static function verify_login( array $response, ?bool &$user_verified = null ) {
		$user_verified = false;

		// One answer for every refusal below, so this open route cannot be used
		// to learn which keys exist. It names the likely cause without saying
		// that it is the cause here.
		$generic = new \WP_Error(
			'bettershield_passkey_rejected',
			__( 'That passkey could not be used to sign in. It may have been removed from this site. Sign in another way, then add it again.', 'bettershield' ),
			array( 'status' => 400 )
		);

		/*
		 * Counted against the same cap as asking for a challenge, before
		 * anything is looked up. This route is open to anybody and needs no
		 * challenge to reach — the handle is a string in the body — so
		 * without a count of its own it was the one sign-in request a
		 * connection could make without limit.
		 */
		$refused = Store::source_refusal( self::PURPOSE_LOGIN );

		if ( null !== $refused ) {
			return $refused;
		}

		$challenge = Store::consume_challenge( (string) ( $response['handle'] ?? '' ), self::PURPOSE_LOGIN );

		if ( null === $challenge ) {
			return $generic;
		}

		$credential_id = (string) ( $response['id'] ?? '' );
		$stored        = '' !== $credential_id ? Store::find( $credential_id ) : null;

		if ( null === $stored ) {
			return $generic;
		}

		$user = get_user_by( 'id', $stored['user_id'] );
		if ( $user instanceof \WP_User && \BetterShield\Remediation\Suspension::blocks( (int) $user->ID ) ) { return $generic; }

		if ( ! $user instanceof \WP_User ) {
			return $generic;
		}

		$checked = self::check_assertion( $response, $challenge, $stored, $user );

		// A counter that went backwards says so; every other refusal is the
		// one answer this route gives an anonymous caller.
		if ( is_wp_error( $checked ) ) {
			return 'bettershield_passkey_counter' === $checked->get_error_code() ? $checked : $generic;
		}

		$user_verified = $checked;

		return $user;
	}

	/**
	 * The checks every assertion answers to, whatever it is for: the
	 * browser's account of the request, the relying party, the signature and
	 * the counter. Which challenge it answers, and whose credential may answer
	 * it, are the caller's to settle first, because that is the part a
	 * sign-in and a confirmation do not share.
	 *
	 * @param array<string, mixed> $response
	 * @param array<string, mixed> $stored   The credential, as `Store::find()` returns it.
	 * @return bool|\WP_Error Whether the authenticator verified the person, or the refusal.
	 */
	private static function check_assertion( array $response, string $challenge, array $stored, \WP_User $user ) {
		$generic = new \WP_Error(
			'bettershield_passkey_rejected',
			__( 'That passkey could not be used to sign in.', 'bettershield' ),
			array( 'status' => 400 )
		);

		$client_data = self::check_client_data( (string) ( $response['clientDataJSON'] ?? '' ), $challenge, 'webauthn.get' );

		if ( is_wp_error( $client_data ) ) {
			return $generic;
		}

		$authenticator_data = self::b64url_decode( (string) ( $response['authenticatorData'] ?? '' ) );
		$signature          = self::b64url_decode( (string) ( $response['signature'] ?? '' ) );

		/*
		 * Checked against the relying party this credential was created
		 * under, not against the one this site would ask for today. A host
		 * whose credentials came to be shared holds two generations at once,
		 * and a single current value would refuse one of them outright. What
		 * keeps that safe is the origin check above, which is exact and which
		 * a credential of the wrong generation cannot pass: the browser
		 * reports the address it is really at.
		 */
		$parsed = self::parse_authenticator_data( $authenticator_data, false, Store::rp_id_of( $stored['site_id'], $stored['rp_id'] ) );

		if ( is_wp_error( $parsed ) ) {
			return $generic;
		}

		// What the authenticator actually signed: its own data, then the hash
		// of the client data. Reassembled here rather than trusted from the
		// browser, which is the point of the exercise.
		$signed = $authenticator_data . hash( 'sha256', self::b64url_decode( (string) $response['clientDataJSON'] ), true );

		if ( ! CoseKey::verify( $stored['public_key'], $stored['algorithm'], $signed, $signature ) ) {
			self::record_refusal( $user, 'signature' );

			return $generic;
		}

		/*
		 * The counter is how a cloned authenticator gives itself away: a real
		 * one only ever counts up. Many authenticators — including most
		 * phones, and synced platform credentials exercised from a second
		 * device — report zero always, so a zero says nothing and is let
		 * through; refusing it bricked exactly those credentials. What keeps
		 * an accepted zero from disarming this check is the write below:
		 * mark_used() is monotonic, so the stored number never goes
		 * backwards whatever arrives.
		 */
		if ( $stored['sign_count'] > 0 && $parsed['sign_count'] > 0 && $parsed['sign_count'] <= $stored['sign_count'] ) {
			self::record_refusal( $user, 'counter' );

			/*
			 * "Sign in another way" was all it said, and an account whose
			 * password no longer signs it in has no other way: the one that
			 * works is an administrator removing its passkeys, which is
			 * what the password refusal beside it says too (#2221).
			 */
			return new \WP_Error(
				'bettershield_passkey_counter',
				Policy::instance()->refuses_password( $user )
					? __( 'That passkey was refused: it may have been copied. Ask an administrator to remove your passkeys so you can sign in with your password and add a new one.', 'bettershield' )
					: __( 'That passkey was refused: it may have been copied. Sign in another way and remove it from your profile.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		Store::mark_used( $stored['id'], $parsed['sign_count'], $parsed['user_verified'] );

		return (bool) $parsed['user_verified'];
	}

	/* ---- confirming the holder ------------------------------------------ */

	/**
	 * The options a browser needs to prove, with one of this account's own
	 * passkeys, that the person at this session holds the account: what an
	 * account with no password the site accepts and no second factor gives
	 * before its passkeys change. Only this account's credentials are
	 * offered, and the challenge belongs to this account and this session.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function confirmation_options( \WP_User $user ) {
		$availability = self::availability();

		if ( ! $availability['available'] ) {
			return new \WP_Error( 'bettershield_passkey_unavailable', $availability['reason'], array( 'status' => 409 ) );
		}

		$issued = Store::issue_challenge( self::PURPOSE_CONFIRM, (int) $user->ID );

		if ( is_wp_error( $issued ) ) {
			return $issued;
		}

		return array(
			'challenge' => self::b64url( $issued['challenge'] ),
			'handle'    => $issued['handle'],
			'rpId'      => self::rp_id(),
			'allow'     => Store::credential_ids_for_user( (int) $user->ID ),
		);
	}

	/**
	 * Check that the person at this session holds this account, by one of its
	 * own passkeys answering a challenge issued to it in this session.
	 *
	 * The same checks as a sign-in, and three more: the challenge was issued
	 * to this account in this session, the credential is this account's, and
	 * the authenticator verified the person rather than a touch. This stands
	 * in for a password the account does not have, and a touch proves only
	 * that a key is plugged in.
	 *
	 * @param array<string, mixed> $response
	 * @return true|\WP_Error
	 */
	public static function verify_confirmation( \WP_User $user, array $response ) {
		$refused = new \WP_Error(
			'bettershield_passkey_not_confirmed',
			__( 'That passkey did not confirm it is you. Try one of this account’s passkeys.', 'bettershield' ),
			array( 'status' => 403 )
		);

		$challenge = Store::consume_challenge( (string) ( $response['handle'] ?? '' ), self::PURPOSE_CONFIRM, (int) $user->ID );

		if ( null === $challenge ) {
			return $refused;
		}

		$stored = Store::find( (string) ( $response['id'] ?? '' ) );

		if ( null === $stored || (int) $stored['user_id'] !== (int) $user->ID ) {
			return $refused;
		}

		$checked = self::check_assertion( $response, $challenge, $stored, $user );

		if ( is_wp_error( $checked ) ) {
			return 'bettershield_passkey_counter' === $checked->get_error_code() ? $checked : $refused;
		}

		if ( true !== $checked ) {
			return new \WP_Error(
				'bettershield_passkey_verification_required',
				__( 'That key asked only for a touch. Use your fingerprint, face or PIN to confirm it is you.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/* ---- the parts every check shares ------------------------------------ */

	/**
	 * The browser's account of what it was asked to do.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function check_client_data( string $encoded, string $challenge, string $expected_type ) {
		$json = self::b64url_decode( $encoded );
		$data = json_decode( $json, true );

		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'bettershield_passkey_client_data', __( 'The browser sent something this site could not read.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( ( $data['type'] ?? '' ) !== $expected_type ) {
			return new \WP_Error( 'bettershield_passkey_type', __( 'That response was for a different kind of request.', 'bettershield' ), array( 'status' => 400 ) );
		}

		// This relying party supports first-party ceremonies only. Older
		// clients omit this member; when present it must be the boolean false.
		if ( array_key_exists( 'crossOrigin', $data ) && false !== $data['crossOrigin'] ) {
			return new \WP_Error( 'bettershield_passkey_cross_origin', __( 'Open this site directly to use a passkey.', 'bettershield' ), array( 'status' => 403 ) );
		}

		// hash_equals, because this is a comparison an attacker gets to repeat.
		$presented = self::b64url_decode( (string) ( $data['challenge'] ?? '' ) );

		if ( '' === $presented || ! hash_equals( $challenge, $presented ) ) {
			return new \WP_Error( 'bettershield_passkey_challenge', __( 'That response answered a different request.', 'bettershield' ), array( 'status' => 409 ) );
		}

		/*
		 * The origin check is the anti-phishing property, and it is exact. A
		 * look-alike domain produces a different origin, the browser reports
		 * it honestly, and this refuses — which is the whole reason a passkey
		 * cannot be handed to the wrong site the way a password can.
		 */
		if ( ! hash_equals( self::origin(), (string) ( $data['origin'] ?? '' ) ) ) {
			return new \WP_Error( 'bettershield_passkey_origin', __( 'That response came from a different address than this site.', 'bettershield' ), array( 'status' => 400 ) );
		}

		return $data;
	}

	/**
	 * Authenticator data: the domain hash, the flags, the counter, and — at
	 * registration — the new credential and its public key.
	 *
	 * @param string $expected_rp_id The relying party this response has to name.
	 * @return array{sign_count: int, user_verified: bool, credential_id: string, cose: array<int|string, mixed>}|\WP_Error
	 */
	private static function parse_authenticator_data( string $data, bool $expect_credential, string $expected_rp_id ) {
		if ( strlen( $data ) < 37 ) {
			return new \WP_Error( 'bettershield_passkey_authdata', __( 'The security key sent too little data.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$rp_id_hash = substr( $data, 0, 32 );
		$flags      = ord( $data[32] );
		$sign_count = unpack( 'N', substr( $data, 33, 4 ) )[1];

		if ( ! hash_equals( hash( 'sha256', $expected_rp_id, true ), $rp_id_hash ) ) {
			return new \WP_Error( 'bettershield_passkey_rp', __( 'That passkey belongs to a different site.', 'bettershield' ), array( 'status' => 400 ) );
		}

		// Bit 0 is user-present. Without it nobody touched the device, and a
		// signature nobody asked for is not a sign-in.
		if ( 0 === ( $flags & 0x01 ) ) {
			return new \WP_Error( 'bettershield_passkey_presence', __( 'The security key did not confirm somebody was there.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$result = array(
			'sign_count'    => (int) $sign_count,
			// Bit 2 is user-verified: the person, not just their presence.
			'user_verified' => 0 !== ( $flags & 0x04 ),
			'credential_id' => '',
			'cose'          => array(),
		);

		if ( ! $expect_credential ) {
			return $result;
		}

		// Bit 6 says a credential is attached, which registration requires.
		if ( 0 === ( $flags & 0x40 ) || strlen( $data ) < 55 ) {
			return new \WP_Error( 'bettershield_passkey_credential', __( 'The registration did not include a key.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$length = unpack( 'n', substr( $data, 53, 2 ) )[1];

		if ( $length < 16 || $length > 1023 || strlen( $data ) < 55 + $length ) {
			return new \WP_Error( 'bettershield_passkey_credential', __( 'The registration named a key of an implausible size.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$result['credential_id'] = substr( $data, 55, $length );
		$result['aaguid'] = substr( $data, 37, 16 );

		try {
			list( $cose, ) = Cbor::decode_first( substr( $data, 55 + $length ) );
		} catch ( \Throwable $e ) {
			return new \WP_Error( 'bettershield_passkey_cose', __( 'The public key could not be read.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( ! is_array( $cose ) ) {
			return new \WP_Error( 'bettershield_passkey_cose', __( 'The public key could not be read.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$result['cose'] = $cose;

		return $result;
	}

	/**
	 * A device-facing account identifier that says nothing about the person.
	 *
	 * Never read back. WebAuthn requires a `user.id` in the registration
	 * options and the device keeps it, but this site resolves an account from
	 * the credential id at sign-in and ignores the `userHandle` the browser
	 * returns — so the value must exist and stay stable, and nothing here
	 * consults it. Said plainly because a helper whose result is never read
	 * looks like something to delete.
	 *
	 * Derived from the relying party rather than from the site address, so
	 * that one account is one account to every device across a shared domain.
	 * Nothing reads it back, which is what makes that safe to change.
	 */
	private static function user_handle( \WP_User $user ): string {
		$anchor = is_multisite() ? self::rp_id() : home_url();

		return hash( 'sha256', 'bettershield-user|' . $anchor . '|' . $user->ID, true );
	}

	private static function record_refusal( \WP_User $user, string $why ): void {
		Writer::instance()->record(
			'passkey_refused',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array( 'reason' => $why ),
			)
		);
	}

	/**
	 * Whether a browser on this site is in a context WebAuthn will work in.
	 *
	 * The question is about the address the browser is at, not about the
	 * connection this process received. Where TLS ends at a proxy — a load
	 * balancer, a CDN, a reverse proxy in front of PHP — `is_ssl()` is false
	 * on every request while every visitor is on https, and judging by the
	 * connection alone switched the feature off for a site where it works
	 * perfectly. The stored address is what the browser is looking at, and it
	 * is also what `origin()` compares against, so the two agree.
	 *
	 * Offering it on a genuinely plain-http page costs nothing:
	 * `window.PublicKeyCredential` is undefined there and the sign-in form's
	 * own script hides the button on that.
	 */
	private static function is_secure_context(): bool {
		if ( Server::connection_is_https() || Server::address_is_https() ) {
			return true;
		}

		// Browsers treat localhost as secure, which is what makes local
		// development possible at all. The site's own host, not the relying
		// party: what the browser judges is the address it is at.
		$host = self::host_of( (string) home_url() );

		return 'localhost' === $host || '127.0.0.1' === $host || str_ends_with( $host, '.localhost' );
	}

	public static function b64url( string $raw ): string {
		return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
	}

	public static function b64url_decode( string $encoded ): string {
		$decoded = base64_decode( strtr( $encoded, '-_', '+/' ), false );

		return is_string( $decoded ) ? $decoded : '';
	}
}
