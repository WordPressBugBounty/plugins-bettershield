<?php
/**
 * The browser sign-in path: an OAuth 2.1 authorization server for one endpoint.
 *
 * The pairing token covers clients with a field to paste a secret into. This
 * covers the ones that take a URL and nothing else: they read the discovery
 * documents, register themselves, send an administrator to a consent page in
 * their own browser, and come back with a code they exchange for tokens.
 *
 * What holds it together:
 *
 * - **PKCE with S256 is required.** These are public clients with no secret
 *   of their own, so the proof that the client redeeming a code is the client
 *   that asked for it is the verifier. A plain challenge is refused rather
 *   than downgraded to.
 * - **Codes are single-use, and the database is what says so.** A code is
 *   claimed before it is read, in one statement whose outcome the database
 *   decides, so two requests presenting the same code cannot both be the first.
 *   Read-modify-write over a shared option cannot make that promise: both
 *   readers see an unspent code, and both mint.
 * - **Refresh tokens rotate, and a spent one is remembered.** Presenting a
 *   refresh token that has already been rotated away revokes the whole family
 *   it belongs to, which is what OAuth 2.1 asks for and the only way a copied
 *   token becomes visible rather than merely useless.
 * - **Tokens are bound to this endpoint.** A client that names a resource must
 *   name this one, and every token records the resource it was issued for.
 * - **Nothing secret is stored.** Access and refresh tokens exist in the
 *   token response and as SHA-256 digests here, and in no log anywhere.
 * - **Every write is serialized.** One claim stands in front of the whole
 *   read-modify-write, so a registration arriving beside a token mint cannot
 *   quietly discard either.
 *
 * The issuer carries a path — `https://example.com/bettershield/mcp` — which
 * RFC 8414 permits and which matters for coexistence: discovery documents are
 * then served at path-suffixed well-known URLs specific to this endpoint, so
 * another plugin serving its own assistant endpoint on the same site does not
 * collide with this one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Events\Writer;
use BetterShield\Support\Claim;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OAuth {

	/** Where every client, code and token digest is kept. */
	public const OPTION = 'bettershield_mcp_oauth';

	/** How long an authorization code lives. Deliberately short. */
	private const CODE_TTL = 60;

	/** How long an access token lives before it has to be refreshed. */
	private const ACCESS_TTL = 3600;

	/** How long a refresh token lives. */
	private const REFRESH_TTL = 2592000;

	/** At most one write a minute recording that a client was seen. */
	private const LAST_USED_THROTTLE = 60;

	/**
	 * How many client registrations are kept.
	 *
	 * A client has to register before it can hold anything, so without a
	 * ceiling the option grows without bound and every read of it pays. A
	 * client holding a live grant is never evicted, so the ceiling only
	 * discards registrations nobody finished.
	 */
	private const MAX_CLIENTS = 50;

	/** How long an unused registration survives. */
	private const CLIENT_TTL = 86400;

	/**
	 * How many return addresses one application may register.
	 *
	 * RFC 7591 clients register one or two: the callback and, sometimes, a
	 * loopback address for a desktop build. Five is generous.
	 */
	private const MAX_REDIRECT_URIS = 5;

	/** How long any one of them may be. */
	private const MAX_REDIRECT_URI_BYTES = 512;

	/**
	 * How many rotated-away refresh digests are remembered per family.
	 *
	 * Reuse detection needs the digests a client could plausibly still be
	 * holding, which is the last few in a family rather than every one issued
	 * inside a refresh token's whole life. Without a ceiling the bucket grows
	 * at whatever rate a client rotates, in an option every authenticated call
	 * reads and every write rewrites in full.
	 */
	private const MAX_SPENT_PER_FAMILY = 8;

	/**
	 * The name the round-trip check's own credential is filed under.
	 *
	 * Not a registered application and never one: it exists so the listing of
	 * connected applications, which is keyed on registrations, does not report
	 * a check as somebody's assistant.
	 */
	private const PROBE_CLIENT = 'self-test';

	/** The claim every write to the option above is taken behind. */
	private const LOCK_KEY = 'mcp_oauth_write';

	/** How long that claim is held for, if the holder never gives it back. */
	private const LOCK_TTL = 5;

	/** How many times a writer asks for it before going ahead regardless. */
	private const LOCK_TRIES = 10;

	/** How long it waits between asks, in microseconds. */
	private const LOCK_WAIT = 20000;

	/** The claim namespace one authorization code is spent under. */
	private const CODE_CLAIM = 'mcp_code_';

	/** The claim namespace one refresh token is rotated under. */
	private const REFRESH_CLAIM = 'mcp_refresh_';

	/**
	 * The state as this request has already read it.
	 *
	 * One authenticated call used to read, normalize and prune this whole
	 * option several times: once to validate the token, once to find the
	 * client, once to list what is connected. It is read once now and dropped
	 * the moment anything writes.
	 *
	 * @var array<string, mixed>|null
	 */
	private static ?array $memo = null;

	/**
	 * Clients this request has already queued a last-used write for.
	 *
	 * @var array<string, true>
	 */
	private static array $touched = array();

	/* ---- identity ------------------------------------------------------------- */

	/**
	 * The issuer, which is the endpoint's own address.
	 */
	public static function issuer(): string {
		return untrailingslashit( home_url( '/' . Pairing::ENDPOINT_PATH ) );
	}

	/** The protected resource: the endpoint clients call. */
	public static function resource(): string {
		return Pairing::endpoint();
	}

	/**
	 * Where a person is sent to approve a connection.
	 *
	 * A front-end URL rather than a REST route, and that is load-bearing: a
	 * browser arriving from the sign-in screen carries a cookie and no REST
	 * nonce, so a REST route would read it as signed out and bounce it back
	 * to sign in forever.
	 */
	public static function authorize_url(): string {
		return home_url( '/bettershield/authorize' );
	}

	public static function token_url(): string {
		return rest_url( 'bettershield/v1/mcp/oauth/token' );
	}

	public static function register_url(): string {
		return rest_url( 'bettershield/v1/mcp/oauth/register' );
	}

	/** Where an application hands back a grant it no longer wants (RFC 7009). */
	public static function revocation_url(): string {
		return rest_url( 'bettershield/v1/mcp/oauth/revoke' );
	}

	/**
	 * Where a client is told to look for the metadata about this resource.
	 *
	 * The well-known address is a rewrite, and a site with plain permalinks
	 * has none: every unknown path there answers with the front page. That
	 * address goes into the `WWW-Authenticate` header on every refusal, which
	 * is the whole of what a client holding nothing has to go on — so where
	 * the rewrite is not routed, the header names the REST route instead,
	 * which is always served.
	 */
	public static function resource_metadata_url(): string {
		return Pairing::pretty_routed()
			? home_url( '/.well-known/oauth-protected-resource/' . Pairing::ENDPOINT_PATH )
			: rest_url( 'bettershield/v1/mcp/protected-resource' );
	}

	/* ---- discovery ------------------------------------------------------------ */

	/**
	 * What protects this endpoint, for a client that has just been refused.
	 *
	 * @return array<string, mixed>
	 */
	public static function protected_resource_metadata(): array {
		$document = array(
			'resource'                 => self::resource(),
			'authorization_servers'    => array( self::issuer() ),
			'scopes_supported'         => Scopes::supported(),
			'bearer_methods_supported' => array( 'header' ),
		);

		if ( Pairing::pretty_routed() ) {
			return $document;
		}

		/*
		 * The sign-in flow is rewrites all the way down — the authorization
		 * endpoint and the server metadata both — so on a site with plain
		 * permalinks there is nothing behind the address this document would
		 * name. Naming it anyway sends a client to fetch a page of HTML and
		 * report that this server's sign-in flow is broken. Saying so instead
		 * is the honest answer, and it names the way in that does work.
		 */
		unset( $document['authorization_servers'] );

		$document['bettershield_sign_in_note'] = __( 'Signing in through the browser needs the pretty addresses this site does not route. Switch its permalinks away from plain, or paste the connection token from the site’s Agents screen as a bearer credential.', 'bettershield' );

		return $document;
	}

	/**
	 * The endpoint map, and only the grants actually implemented here.
	 *
	 * @return array<string, mixed>
	 */
	public static function authorization_server_metadata(): array {
		return array(
			'issuer'                                     => self::issuer(),
			'authorization_endpoint'                     => self::authorize_url(),
			'token_endpoint'                             => self::token_url(),
			'registration_endpoint'                      => self::register_url(),
			// RFC 7009: an application that lets go of this site hands its
			// grant back here, so letting go on its side ends the access on
			// this one rather than leaving it to expire.
			'revocation_endpoint'                        => self::revocation_url(),
			'revocation_endpoint_auth_methods_supported' => array( 'none' ),
			'scopes_supported'                           => Scopes::supported(),
			'response_types_supported'                   => array( 'code' ),
			'grant_types_supported'                      => array( 'authorization_code', 'refresh_token' ),
			'code_challenge_methods_supported'           => array( 'S256' ),
			'token_endpoint_auth_methods_supported'      => array( 'none' ),
			// RFC 8707: a client may name the resource it wants a token for,
			// and this server has exactly one to name.
			'resource_indicators_supported'              => true,
		);
	}

	/* ---- registration --------------------------------------------------------- */

	/**
	 * Register a public client, which is a name and where to send it back to.
	 *
	 * No secret is issued: a client that runs on somebody's laptop cannot keep
	 * one, and pretending otherwise is what PKCE exists to replace.
	 *
	 * Registration is unauthenticated by design — a client has to be able to
	 * introduce itself before anybody has approved anything — so the switch is
	 * what decides whether this site introduces itself at all. While it is on,
	 * what bounds the door is everything around it: the per-network throttle
	 * in front of this, the ceiling on how many registrations are kept, and
	 * the consent page, where an administrator sees the host a code would go
	 * back to and whether anybody has approved this application before.
	 * Registering is never connecting.
	 *
	 * @param array<string, mixed> $body The parsed registration request.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function register_client( array $body ) {
		if ( ! Manager::is_enabled() ) {
			return self::registration_error(
				'access_denied',
				__( 'This site is not accepting assistant connections. An administrator turns the connection on under Agents.', 'bettershield' ),
				403
			);
		}

		$requested = isset( $body['redirect_uris'] ) && is_array( $body['redirect_uris'] ) ? $body['redirect_uris'] : array();

		/*
		 * Bounded before anything is kept, and refused rather than trimmed:
		 * this list is stored in an option every authenticated call reads and
		 * every write rewrites in full, and it is walked in constant time on
		 * every authorize request. A client that registers more addresses than
		 * this, or a longer one, has to hear about it — silently keeping the
		 * first few would leave it redirecting to an address the site never
		 * accepted.
		 */
		if ( count( $requested ) > self::MAX_REDIRECT_URIS ) {
			return self::registration_error(
				'invalid_redirect_uri',
				sprintf(
					/* translators: %d: how many return addresses one application may register. */
					__( 'This site registers at most %d return addresses for one application.', 'bettershield' ),
					self::MAX_REDIRECT_URIS
				),
				400
			);
		}

		foreach ( $requested as $candidate ) {
			if ( is_scalar( $candidate ) && strlen( (string) $candidate ) > self::MAX_REDIRECT_URI_BYTES ) {
				return self::registration_error(
					'invalid_redirect_uri',
					sprintf(
						/* translators: %d: how long a return address may be, in bytes. */
						__( 'A return address may be at most %d bytes long.', 'bettershield' ),
						self::MAX_REDIRECT_URI_BYTES
					),
					400
				);
			}
		}

		$uris = array_values(
			array_unique(
				array_filter(
					array_map( 'strval', $requested ),
					static function ( string $uri ): bool {
						return self::is_valid_redirect_uri( $uri );
					}
				)
			)
		);

		if ( array() === $uris ) {
			return self::registration_error(
				'invalid_redirect_uri',
				__( 'At least one usable return address is required. This site accepts an https address, a loopback http address, or an application’s own reverse-domain scheme.', 'bettershield' ),
				400
			);
		}

		$name      = isset( $body['client_name'] ) ? sanitize_text_field( (string) $body['client_name'] ) : '';
		$name      = '' === $name ? __( 'An assistant', 'bettershield' ) : Text::clip( $name, 120 );
		$client_id = 'bs_' . bin2hex( random_bytes( 16 ) );
		$now       = time();

		self::mutate(
			static function ( array &$state ) use ( $client_id, $uris, $name, $now ): void {
				$state['clients'][ $client_id ] = array(
					'redirect_uris' => $uris,
					'name'          => $name,
					'created'       => $now,
					'last_used'     => 0,
					'granted_by'    => 0,
				);

				$state['clients'] = self::prune_clients( $state );
			}
		);

		return array(
			'client_id'                  => $client_id,
			'client_id_issued_at'        => $now,
			'redirect_uris'              => $uris,
			'client_name'                => $name,
			'token_endpoint_auth_method' => 'none',
			'grant_types'                => array( 'authorization_code', 'refresh_token' ),
			'response_types'             => array( 'code' ),
			'scope'                      => implode( ' ', Scopes::supported() ),
		);
	}

	/* ---- authorization -------------------------------------------------------- */

	/**
	 * Check an authorization request without issuing anything.
	 *
	 * The order is the security property, and it is this:
	 *
	 * 1. Every parameter is checked against its own allow-list, before
	 *    anything is looked up. Nothing here is run through a text sanitizer —
	 *    that one strips `%XX` from every value it touches, which silently
	 *    corrupts a double-encoded callback and a percent-bearing `state`.
	 * 2. The client and its registered return address are matched. A failure
	 *    before this point is answered on this site's own page, never by
	 *    redirecting, or a mistyped request becomes a redirector for whoever
	 *    made it.
	 * 3. Only then is a parameter failure the client is entitled to hear about
	 *    handed back for the caller to redirect with.
	 *
	 * @param array<string, string> $params The request's own parameters.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate_authorize_request( array $params ) {
		$client_id    = (string) ( $params['client_id'] ?? '' );
		$redirect_uri = (string) ( $params['redirect_uri'] ?? '' );

		// The two that decide where an answer may be sent. A failure in either
		// is answered here and nowhere else.
		if ( 1 !== preg_match( '/^bs_[a-f0-9]{32}$/', $client_id ) ) {
			return self::authorize_error( 'invalid_request', __( 'That application identifier is not one this site issues.', 'bettershield' ), false );
		}

		if ( '' === $redirect_uri || ! self::is_valid_redirect_uri( $redirect_uri ) ) {
			return self::authorize_error( 'invalid_request', __( 'That return address is not one this site can send an answer to.', 'bettershield' ), false );
		}

		$state = (string) ( $params['state'] ?? '' );

		if ( strlen( $state ) > 512 || 1 !== preg_match( '/^[\x20-\x7E]*$/', $state ) ) {
			return self::authorize_error( 'invalid_request', __( 'That request carried a state value this site cannot return unchanged.', 'bettershield' ), false );
		}

		// Everything else is the client's own mistake to hear about, once the
		// address it would be sent to has been proved to belong to it.
		$deferred = self::check_authorize_shape( $params );

		$client = self::client( $client_id );

		if ( null === $client ) {
			return self::authorize_error( 'invalid_client', __( 'That application is not registered here.', 'bettershield' ), false );
		}

		if ( ! self::exactly_one_of( $redirect_uri, $client['redirect_uris'] ) ) {
			return self::authorize_error(
				'invalid_redirect_uri',
				__( 'That return address is not one this application registered.', 'bettershield' ),
				false
			);
		}

		if ( null !== $deferred ) {
			return $deferred;
		}

		$requested = (string) ( $params['scope'] ?? '' );

		return array(
			'client_id'      => $client_id,
			'client_name'    => $client['name'],
			'redirect_uri'   => $redirect_uri,
			'code_challenge' => (string) $params['code_challenge'],
			// What the client asked for, narrowed to what this server issues.
			// What it is granted is decided by the person on the consent page.
			'scope'          => '' === trim( $requested ) ? Scopes::READ_WRITE : Scopes::normalize( $requested ),
			'state'          => $state,
			'resource'       => self::resource(),
			// For the consent page: how old this registration is, and whether
			// anybody has ever approved it before.
			'client_created' => $client['created'],
			'first_seen'     => 0 === $client['granted_by'],
		);
	}

	/**
	 * Every parameter that is the client's to get wrong, each against its own
	 * allow-list.
	 *
	 * Returned rather than thrown so the caller can hold it until the return
	 * address has been proved. Nothing here reads or writes stored state.
	 *
	 * @param array<string, string> $params
	 */
	private static function check_authorize_shape( array $params ): ?\WP_Error {
		if ( 'code' !== (string) ( $params['response_type'] ?? '' ) ) {
			return self::authorize_error(
				'unsupported_response_type',
				__( 'This server issues authorization codes and nothing else.', 'bettershield' ),
				true
			);
		}

		if ( 'S256' !== (string) ( $params['code_challenge_method'] ?? '' ) ) {
			return self::authorize_error( 'invalid_request', __( 'A code challenge using S256 is required.', 'bettershield' ), true );
		}

		// RFC 7636 §4.1: 43 to 128 characters of the unreserved set.
		if ( 1 !== preg_match( '/^[A-Za-z0-9._~\-]{43,128}$/', (string) ( $params['code_challenge'] ?? '' ) ) ) {
			return self::authorize_error( 'invalid_request', __( 'That code challenge is not a well-formed S256 challenge.', 'bettershield' ), true );
		}

		if ( ! Scopes::are_supported( (string) ( $params['scope'] ?? '' ) ) ) {
			return self::authorize_error( 'invalid_request', __( 'This server issues the read and write scopes and no others.', 'bettershield' ), true );
		}

		$resource = (string) ( $params['resource'] ?? '' );

		if ( '' !== $resource && ! self::names_this_resource( $resource ) ) {
			return self::authorize_error( 'invalid_target', __( 'That request asked for a token for a different address than this one.', 'bettershield' ), true );
		}

		return null;
	}

	/**
	 * Issue the code a person's approval produced.
	 *
	 * @param array<string, mixed> $request The checked request.
	 */
	public static function issue_code( array $request, int $user_id ): string {
		$code   = bin2hex( random_bytes( 32 ) );
		$digest = self::digest( $code );
		$grant  = WriteGrants::issue( (string) ( $request['scope'] ?? '' ) );
		$entry  = array(
			'client_id'    => (string) $request['client_id'],
			'redirect_uri' => (string) $request['redirect_uri'],
			'challenge'    => (string) $request['code_challenge'],
			'scope'        => $grant['scope'],
			'write_generation' => $grant['write_generation'],
			'resource'     => (string) ( $request['resource'] ?? self::resource() ),
			'user_id'      => $user_id,
			'expires'      => time() + self::CODE_TTL,
		);

		// A hub connection's ticket travels with its code as a digest, so the
		// exchange can insist on the same one and spend it there.
		if ( '' !== (string) ( $request['hub_ticket'] ?? '' ) ) {
			$entry['hub_ticket'] = Hub::digest( (string) $request['hub_ticket'] );

			// And whether the person approving it also turned the Hub link on,
			// which happens only once the hub has its grant.
			if ( ! empty( $request['hub_link'] ) ) {
				$entry['hub_link'] = true;
			}
		}

		self::mutate(
			static function ( array &$state ) use ( $digest, $entry, $user_id ): void {
				$state['codes'][ $digest ] = $entry;

				if ( isset( $state['clients'][ $entry['client_id'] ] ) ) {
					$state['clients'][ $entry['client_id'] ]['granted_by'] = $user_id;
					$state['clients'][ $entry['client_id'] ]['granted_at'] = time();
				}
			}
		);

		return $code;
	}

	/* ---- token ---------------------------------------------------------------- */

	/**
	 * Exchange a code, or a refresh token, for a fresh pair.
	 *
	 * @param array<string, string> $body The token request.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function exchange_token( array $body ) {
		$resource = (string) ( $body['resource'] ?? '' );

		if ( '' !== $resource && ! self::names_this_resource( $resource ) ) {
			return self::error( 'invalid_target', __( 'That request asked for a token for a different address than this one.', 'bettershield' ) );
		}

		$grant = (string) ( $body['grant_type'] ?? '' );

		if ( 'authorization_code' === $grant ) {
			return self::grant_code( $body );
		}

		if ( 'refresh_token' === $grant ) {
			return self::grant_refresh( $body );
		}

		return self::error( 'unsupported_grant_type', __( 'That grant type is not supported here.', 'bettershield' ) );
	}

	/**
	 * @param array<string, string> $body
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function grant_code( array $body ) {
		$code = (string) ( $body['code'] ?? '' );

		if ( '' === $code ) {
			return self::error( 'invalid_grant', __( 'That authorization code is not one this site issued, or it has expired.', 'bettershield' ) );
		}

		$key = self::digest( $code );

		/*
		 * The database decides who spends this code, in one statement, before
		 * anything is read. Two requests presenting the same code both find it
		 * unspent in the option — that is the shape of the race, not a way out
		 * of it — and only one of them takes the claim. A claim that cannot be
		 * taken at all is a loss too: a code redemption that cannot be
		 * arbitrated must not be allowed to happen twice.
		 */
		if ( ! Claim::claim( self::CODE_CLAIM . $key, self::CODE_TTL ) ) {
			return self::error( 'invalid_grant', __( 'That authorization code has already been used.', 'bettershield' ) );
		}

		$entry = self::mutate(
			static function ( array &$state ) use ( $key ) {
				if ( ! isset( $state['codes'][ $key ] ) ) {
					return null;
				}

				$found = $state['codes'][ $key ];

				// Single use, whichever way the checks below go: a code that
				// has been presented once is spent even if presenting it
				// failed.
				unset( $state['codes'][ $key ] );

				return $found;
			}
		);

		if ( ! is_array( $entry ) ) {
			return self::error( 'invalid_grant', __( 'That authorization code is not one this site issued, or it has expired.', 'bettershield' ) );
		}

		if ( (int) $entry['expires'] < time() ) {
			return self::error( 'invalid_grant', __( 'That authorization code has expired.', 'bettershield' ) );
		}

		if ( ! hash_equals( (string) $entry['client_id'], (string) ( $body['client_id'] ?? '' ) ) ) {
			return self::error( 'invalid_grant', __( 'That authorization code belongs to a different application.', 'bettershield' ) );
		}

		if ( ! hash_equals( (string) $entry['redirect_uri'], (string) ( $body['redirect_uri'] ?? '' ) ) ) {
			return self::error( 'invalid_grant', __( 'That authorization code was issued for a different return address.', 'bettershield' ) );
		}

		$verifier = (string) ( $body['code_verifier'] ?? '' );

		if ( '' === $verifier || ! hash_equals( (string) $entry['challenge'], self::s256( $verifier ) ) ) {
			return self::error( 'invalid_grant', __( 'The code verifier does not match the challenge this code was issued against.', 'bettershield' ) );
		}

		$hub_ticket = (string) ( $entry['hub_ticket'] ?? '' );

		if ( '' !== $hub_ticket ) {
			$presented = (string) ( $body['hub_ticket'] ?? '' );

			// The ticket this code was approved against, and still
			// outstanding: spending it here is what makes it single use.
			if ( '' === $presented || ! hash_equals( $hub_ticket, Hub::digest( $presented ) ) || ! Hub::spend_ticket( $presented ) ) {
				return self::error( 'invalid_grant', __( 'That connection was not started from this site’s dashboard, or it has already been completed. Start it again from BetterShield › Hub.', 'bettershield' ) );
			}
		}

		// What the hub holds now, read before the new grant joins it.
		$replaced = '' !== $hub_ticket ? Hub::apps() : array();

		$minted = self::mint(
			(string) $entry['client_id'],
			(string) $entry['scope'],
			(int) $entry['user_id'],
			'',
			// The hub this grant was approved for, from the return address the
			// code was issued against, so the grant stays that hub's whatever
			// the address setting says later.
			'' !== $hub_ticket ? Hub::host_of( (string) $entry['redirect_uri'] ) : '',
			'',
			(string) ( $entry['write_generation'] ?? '' )
		);

		// A new grant renews nothing, so no ended grant can meet it here; the
		// answer is still checked rather than assumed.
		if ( null === $minted ) {
			return self::error( 'invalid_grant', __( 'That authorization code is not one this site issued, or it has expired.', 'bettershield' ) );
		}

		if ( '' !== $hub_ticket ) {
			self::replace_hub_grants( $replaced, (string) $minted['access_token'] );

			$minted['bettershield_site'] = Hub::site_facts();

			// Turned on now that the grant it rides on exists, so the hub's
			// first read of the site finds its key. A link that cannot be on
			// here does not hold up the connection: the Hub card says why.
			// On a link already on, the rest of the log it sends is kept: the
			// connection adds the link, and takes nothing from it.
			if ( ! empty( $entry['hub_link'] ) ) {
				$record = \BetterShield\Hub\Link\Link::record();

				\BetterShield\Hub\Link\Link::enable( true, $record['enabled'] && $record['full_log'], (int) $entry['user_id'] );
			}
		}

		return $minted;
	}

	/**
	 * Connecting the hub again replaces what it held. The Hub card describes
	 * one grant, and an earlier one left in place went on working with
	 * whatever it was approved for: a write grant outlived a reconnect for
	 * reading only while the card said the hub could change nothing.
	 *
	 * Every grant the hub held before this exchange ends, the new one's own
	 * line excepted, and each ending is on the record as Disconnect's is.
	 *
	 * @param array<int, array{id: string}> $replaced The hub's grants before the exchange.
	 * @param string                        $access   The access token just minted.
	 */
	private static function replace_hub_grants( array $replaced, string $access ): void {
		if ( array() === $replaced ) {
			return;
		}

		$clients = array_map( 'strval', array_column( $replaced, 'id' ) );
		$key     = self::digest( $access );

		self::mutate(
			static function ( array &$state ) use ( $clients, $key ): void {
				$keep     = (string) ( $state['tokens'][ $key ]['family'] ?? '' );
				$families = array();

				foreach ( array( 'tokens', 'refresh' ) as $bucket ) {
					foreach ( (array) ( $state[ $bucket ] ?? array() ) as $entry ) {
						$family = is_array( $entry ) ? (string) ( $entry['family'] ?? '' ) : '';

						if ( '' !== $family && $keep !== $family && in_array( (string) ( $entry['client_id'] ?? '' ), $clients, true ) ) {
							$families[ $family ] = true;
						}
					}
				}

				foreach ( array_keys( $families ) as $family ) {
					self::drop_family( $state, (string) $family );
				}
			}
		);

		foreach ( $replaced as $app ) {
			Writer::instance()->record(
				'mcp_app_revoked',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'mcp_app',
					'object_id'   => (string) $app['id'],
					'context'     => array( 'replaced_by_reconnect' => true ),
				)
			);
		}
	}

	/**
	 * @param array<string, string> $body
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function grant_refresh( array $body ) {
		$presented = (string) ( $body['refresh_token'] ?? '' );
		$client_id = (string) ( $body['client_id'] ?? '' );

		if ( '' === $presented ) {
			return self::error( 'invalid_grant', __( 'That refresh token is not one this site issued, or it has already been used.', 'bettershield' ) );
		}

		/*
		 * Required, not optional. Without it a refresh token lifted from one
		 * client's storage is redeemable by anything that can reach this
		 * endpoint, and the binding the rest of this file maintains says
		 * nothing.
		 */
		if ( 1 !== preg_match( '/^bs_[a-f0-9]{32}$/', $client_id ) ) {
			return self::error( 'invalid_request', __( 'A refresh request has to name the application it belongs to.', 'bettershield' ) );
		}

		$key = self::digest( $presented );

		if ( ! Claim::claim( self::REFRESH_CLAIM . $key, self::LOCK_TTL ) ) {
			return self::error( 'invalid_grant', __( 'That refresh token is being used by another request.', 'bettershield' ) );
		}

		$outcome = self::mutate(
			static function ( array &$state ) use ( $key, $client_id ) {
				/*
				 * Already spent. This is the case rotation exists to make
				 * visible: the real client rotated, so a second presentation
				 * of the same token is a copy of it being used. Everything
				 * descended from that grant goes, and the refusal is recorded.
				 *
				 * Whichever application the request names: the token is the
				 * evidence, and a client id is no secret, so the holder of a
				 * copy could name the right one anyway. For the same reason
				 * the record names the application the token was issued to,
				 * never the one in the request.
				 */
				if ( isset( $state['spent'][ $key ] ) ) {
					$owner = (string) ( $state['spent'][ $key ]['client_id'] ?? '' );

					self::drop_family( $state, (string) ( $state['spent'][ $key ]['family'] ?? '' ) );

					return array(
						'reuse' => true,
						'owner' => $owner,
						'last'  => ! self::holds_grant( $state, $owner ),
					);
				}

				if ( ! isset( $state['refresh'][ $key ] ) ) {
					return null;
				}

				$entry = $state['refresh'][ $key ];

				if ( ! hash_equals( (string) $entry['client_id'], $client_id ) ) {
					return array( 'wrong_client' => true );
				}

				// Rotation: the presented token and the access token it minted
				// both stop working here, before the new pair exists, and the
				// digest is remembered so presenting it again is answerable.
				unset( $state['refresh'][ $key ] );

				if ( isset( $entry['access'] ) ) {
					unset( $state['tokens'][ (string) $entry['access'] ] );
				}

				$state['spent'][ $key ] = array(
					'family'    => (string) ( $entry['family'] ?? '' ),
					'client_id' => (string) $entry['client_id'],
					'expires'   => time() + self::REFRESH_TTL,
				);

				return array( 'entry' => $entry );
			}
		);

		Claim::release( self::REFRESH_CLAIM . $key );

		if ( is_array( $outcome ) && ! empty( $outcome['reuse'] ) ) {
			self::note_refresh_reuse( (string) $outcome['owner'], ! empty( $outcome['last'] ) );

			return self::error( 'invalid_grant', __( 'That refresh token has already been replaced. Every token from that connection has been withdrawn; connect the application again.', 'bettershield' ) );
		}

		if ( is_array( $outcome ) && ! empty( $outcome['wrong_client'] ) ) {
			return self::error( 'invalid_grant', __( 'That refresh token belongs to a different application.', 'bettershield' ) );
		}

		if ( ! is_array( $outcome ) || ! isset( $outcome['entry'] ) ) {
			return self::error( 'invalid_grant', __( 'That refresh token is not one this site issued, or it has already been used.', 'bettershield' ) );
		}

		$entry = (array) $outcome['entry'];
		$hub   = (string) ( $entry['hub'] ?? '' );

		// A grant approved before grants carried their hub is marked the
		// first time it is recognized, so it stays the hub's when the address
		// moves later.
		if ( '' === $hub ) {
			$hub = Hub::unmarked_host( (string) $entry['client_id'] );
		}

		$minted = self::mint(
			(string) $entry['client_id'],
			(string) $entry['scope'],
			(int) $entry['user_id'],
			(string) ( $entry['family'] ?? '' ),
			$hub,
			$key,
			(string) ( $entry['write_generation'] ?? '' )
		);

		// The grant this refresh renews was ended while the refresh was on its
		// way, by a revocation, a Remove or a Disconnect: it stays ended.
		if ( null === $minted ) {
			return self::error( 'invalid_grant', __( 'The access this refresh token belonged to was ended while it was being renewed. Connect the application again.', 'bettershield' ) );
		}

		return $minted;
	}

	/**
	 * Mark one client's live grants as the hub's, where they carry no mark.
	 *
	 * For grants approved before grants carried the hub they were approved
	 * for: recognized by a return address at the hub this site points at
	 * now, which stops being true the moment that address moves.
	 *
	 * @return bool Whether anything was marked.
	 */
	public static function mark_hub( string $client_id, string $hub ): bool {
		if ( '' === $client_id || '' === $hub ) {
			return false;
		}

		$marked = false;

		self::mutate(
			static function ( array &$state ) use ( $client_id, $hub, &$marked ): void {
				foreach ( array( 'tokens', 'refresh' ) as $bucket ) {
					foreach ( (array) ( $state[ $bucket ] ?? array() ) as $key => $entry ) {
						if ( is_array( $entry ) && $client_id === (string) ( $entry['client_id'] ?? '' ) && '' === (string) ( $entry['hub'] ?? '' ) ) {
							$state[ $bucket ][ $key ]['hub'] = $hub;
							$marked                           = true;
						}
					}
				}
			}
		);

		return $marked;
	}

	/**
	 * Say, once per application per hour, that a spent refresh token came
	 * back, and that the access it belonged to was ended for it.
	 *
	 * A second presentation of a rotated token is a copy of the credential in
	 * somebody else's hands, so it is its own high row, which alerts, rather
	 * than a quiet refusal that read like a mistyped token. Still once an
	 * hour per application, so a client stuck in a retry loop cannot fill the
	 * log with the one row an owner most needs to find.
	 *
	 * The application's removal is recorded beside it when that line was the
	 * last grant the application held, and outside the hourly hold: an
	 * application loses its last grant once per approval, so nothing can
	 * repeat it, and an application still connected through another grant
	 * has not been removed.
	 *
	 * @param string $client_id The application the spent token was issued to.
	 * @param bool   $removed   Whether that application holds no grant now.
	 */
	private static function note_refresh_reuse( string $client_id, bool $removed ): void {
		$client = self::state()['clients'][ $client_id ] ?? array();
		$name   = is_array( $client ) ? (string) ( $client['name'] ?? '' ) : '';
		$args   = array(
			'object_type' => 'mcp_app',
			'object_id'   => Text::clip( $client_id, 191 ),
		);

		if ( Claim::claim( 'mcp_refresh_reused_' . md5( $client_id ), HOUR_IN_SECONDS ) ) {
			Writer::instance()->record( 'mcp_refresh_reused', Writer::SEVERITY_HIGH, $args + array( 'context' => array( 'name' => $name ) ) );
		}

		if ( ! $removed ) {
			return;
		}

		Writer::instance()->record(
			'mcp_app_revoked',
			Writer::SEVERITY_LOW,
			$args + array(
				'context' => array(
					'name'   => $name,
					'reason' => 'refresh_reused',
				),
			)
		);
	}

	/**
	 * Whether an application still holds a live grant: what makes it one of
	 * the connected applications.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function holds_grant( array $state, string $client_id ): bool {
		foreach ( array( 'tokens', 'refresh' ) as $bucket ) {
			foreach ( (array) ( $state[ $bucket ] ?? array() ) as $entry ) {
				if ( is_array( $entry ) && $client_id === (string) ( $entry['client_id'] ?? '' ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Everything descended from one grant, gone.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function drop_family( array &$state, string $family ): void {
		if ( '' === $family ) {
			return;
		}

		foreach ( array( 'tokens', 'refresh', 'codes', 'spent' ) as $bucket ) {
			if ( ! isset( $state[ $bucket ] ) || ! is_array( $state[ $bucket ] ) ) {
				continue;
			}

			foreach ( $state[ $bucket ] as $key => $entry ) {
				if ( is_array( $entry ) && $family === (string) ( $entry['family'] ?? '' ) ) {
					unset( $state[ $bucket ][ $key ] );
				}
			}
		}
	}

	/**
	 * Mint a pair, store the digests, and hand back the only copy.
	 *
	 * @param string $hub     The hub host a hub grant was approved for; empty
	 *                        for every other grant.
	 * @param string $rotated For a refresh, the digest of the refresh token
	 *                        this pair replaces; empty for a new grant.
	 * @return array<string, mixed>|null Null when the grant a refresh renews
	 *                                   was ended while it was being renewed.
	 */
	private static function mint( string $client_id, string $scope, int $user_id, string $family, string $hub = '', string $rotated = '', string $generation = '' ): ?array {
		$access  = bin2hex( random_bytes( 32 ) );
		$refresh = bin2hex( random_bytes( 32 ) );
		$akey    = self::digest( $access );
		$rkey    = self::digest( $refresh );
		$scope   = Scopes::normalize( $scope );

		// The grant a refresh renews, as the token it rotated away recorded it.
		$renewing = $family;

		// One identifier for everything a single approval ever produces, so a
		// token that turns up after it should have been replaced can take the
		// whole line with it.
		$family = '' === $family ? bin2hex( random_bytes( 16 ) ) : $family;

		$resource = self::resource();

		$stored = self::mutate(
			static function ( array &$state ) use ( $akey, $rkey, $client_id, &$scope, $user_id, $family, $resource, $hub, $rotated, $renewing, $generation ): bool {
				/*
				 * A refresh rotates the old pair away in one write and stores
				 * this one in the next. A grant ended between the two, handed
				 * back or removed or disconnected, took the rotated token's
				 * record with it, and storing this pair would bring the grant
				 * back with tokens nobody agreed to keep.
				 */
				if ( '' !== $rotated && ( ! isset( $state['spent'][ $rotated ] ) || $renewing !== (string) ( $state['spent'][ $rotated ]['family'] ?? '' ) ) ) {
					return false;
				}

				$scope = WriteGrants::scope( array( 'scope' => $scope, 'write_generation' => $generation ) );
				$state['tokens'][ $akey ] = array(
					'client_id' => $client_id,
					'scope'     => $scope,
					'write_generation' => $generation,
					'user_id'   => $user_id,
					'family'    => $family,
					'resource'  => $resource,
					'expires'   => time() + self::ACCESS_TTL,
					'refresh'   => $rkey,
				);

				$state['refresh'][ $rkey ] = array(
					'access'    => $akey,
					'client_id' => $client_id,
					'scope'     => $scope,
					'write_generation' => $generation,
					'user_id'   => $user_id,
					'family'    => $family,
					'resource'  => $resource,
					'expires'   => time() + self::REFRESH_TTL,
				);

				if ( '' !== $hub ) {
					$state['tokens'][ $akey ]['hub']  = $hub;
					$state['refresh'][ $rkey ]['hub'] = $hub;
				}

				return true;
			}
		);

		if ( true !== $stored ) {
			return null;
		}

		return array(
			'access_token'  => $access,
			'token_type'    => 'Bearer',
			'expires_in'    => self::ACCESS_TTL,
			'refresh_token' => $refresh,
			'scope'         => $scope,
		);
	}

	/* ---- use ------------------------------------------------------------------ */

	/**
	 * The grant behind a presented access token, or null.
	 *
	 * Looked up by digest, so nothing here compares a secret against a stored
	 * secret and there is no stored secret to compare against.
	 *
	 * @return array{client_id: string, scope: string, user_id: int}|null
	 */
	public static function validate_token( string $presented ): ?array {
		if ( '' === $presented ) {
			return null;
		}

		$state = self::state();
		$key   = self::digest( $presented );

		if ( ! isset( $state['tokens'][ $key ] ) ) {
			return null;
		}

		$entry = $state['tokens'][ $key ];

		if ( (int) $entry['expires'] < time() ) {
			return null;
		}

		$client_id = (string) $entry['client_id'];

		/*
		 * A staging copy carries the live site's grants with its database.
		 * The hub is refused on one while it is marked staging, so the hub
		 * goes on seeing one site rather than two; the grant itself is kept,
		 * and the undo lets it in again.
		 */
		if ( \BetterShield\Onboarding\SiteIdentity::is_staging() && Hub::is_hub_client( $client_id ) ) {
			return null;
		}

		// Recorded against the client rather than the token, so the answer
		// survives the rotation that replaces the token every hour.
		if ( isset( $state['clients'][ $client_id ] ) && is_array( $state['clients'][ $client_id ] ) ) {
			$last = (int) ( $state['clients'][ $client_id ]['last_used'] ?? 0 );

			if ( time() - $last >= self::LAST_USED_THROTTLE ) {
				self::touch_client( $client_id );
			}
		}

		return array(
			'client_id' => $client_id,
			'scope'     => WriteGrants::scope( $entry ),
			'user_id'   => (int) $entry['user_id'],
		);
	}

	/**
	 * Record that a client was seen, after the answer has gone.
	 *
	 * This is a full rewrite of a growing option, and the request it would
	 * otherwise happen on is one an assistant is waiting for. Nothing depends
	 * on it having landed by the time the response is written, so it lands at
	 * shutdown instead — ahead of the invocation writer and the activity log,
	 * both of which are doing the same thing for better reasons.
	 *
	 * Once per client per request. Two calls on one connection would otherwise
	 * both find the stamp stale and both queue a write.
	 */
	private static function touch_client( string $client_id ): void {
		if ( isset( self::$touched[ $client_id ] ) ) {
			return;
		}

		self::$touched[ $client_id ] = true;

		add_action(
			'shutdown',
			static function () use ( $client_id ): void {
				self::mutate(
					static function ( array &$state ) use ( $client_id ): void {
						if ( isset( $state['clients'][ $client_id ] ) ) {
							$state['clients'][ $client_id ]['last_used'] = time();
						}
					}
				);
			},
			85
		);
	}

	/**
	 * A credential the site mints for its own round-trip check.
	 *
	 * An access token and nothing else: no refresh token, a life measured in
	 * a couple of minutes, and no client registration behind it, so it cannot
	 * outlive the check or be refreshed into something durable. It is
	 * withdrawn as soon as the answer is read, and the short life is the
	 * backstop for the request that dies before it gets there.
	 */
	public static function issue_probe_token( int $user_id, int $seconds, string $scope = Scopes::READ_WRITE ): string {
		$token    = bin2hex( random_bytes( 32 ) );
		$key      = self::digest( $token );
		$grant    = WriteGrants::issue( $scope );
		$resource = self::resource();

		self::mutate(
			static function ( array &$state ) use ( $key, $user_id, $seconds, $grant, $resource ): void {
				$state['tokens'][ $key ] = array(
					'client_id' => self::PROBE_CLIENT,
					'scope'     => WriteGrants::scope( $grant ),
					'write_generation' => $grant['write_generation'],
					'user_id'   => $user_id,
					'family'    => '',
					'resource'  => $resource,
					'expires'   => time() + max( 1, $seconds ),
					'refresh'   => '',
				);
			}
		);

		return $token;
	}

	/** Take the round-trip credential back. */
	public static function withdraw_probe_token( string $token ): void {
		$key = self::digest( $token );

		self::mutate(
			static function ( array &$state ) use ( $key ): void {
				unset( $state['tokens'][ $key ] );
			}
		);
	}

	/**
	 * The applications holding a live grant, newest first.
	 *
	 * A client that registered and never finished is not one of these: what
	 * makes an application connected is a token, not a registration.
	 *
	 * `hub` is the hub host a hub grant was approved for, and empty for every
	 * other grant.
	 *
	 * @return array<int, array{id: string, name: string, granted_at: int, granted_by: int, last_used: int, scope: string, hub: string}>
	 */
	public static function connected_apps(): array {
		$state  = self::state();
		$current = WriteGrants::current();
		$live   = array();
		$output = array();

		foreach ( array( 'refresh', 'tokens' ) as $bucket ) {
			foreach ( $state[ $bucket ] as $entry ) {
				$id = isset( $entry['client_id'] ) ? (string) $entry['client_id'] : '';

				if ( '' === $id || self::PROBE_CLIENT === $id ) {
					continue;
				}

				$hub = isset( $entry['hub'] ) ? (string) $entry['hub'] : '';

				if ( isset( $live[ $id ] ) ) {
					// Any one of a client's tokens naming its hub is enough.
					if ( '' === $live[ $id ]['hub'] ) {
						$live[ $id ]['hub'] = $hub;
					}

					continue;
				}

				$live[ $id ] = array(
					'user_id' => isset( $entry['user_id'] ) ? (int) $entry['user_id'] : 0,
					'scope'   => WriteGrants::scope( $entry, $current ),
					'hub'     => $hub,
				);
			}
		}

		foreach ( $live as $id => $grant ) {
			$client = isset( $state['clients'][ $id ] ) && is_array( $state['clients'][ $id ] ) ? $state['clients'][ $id ] : array();

			$output[] = array(
				'id'         => (string) $id,
				'name'       => isset( $client['name'] ) ? (string) $client['name'] : __( 'An assistant', 'bettershield' ),
				'granted_at' => (int) ( $client['granted_at'] ?? $client['created'] ?? 0 ),
				'granted_by' => $grant['user_id'] > 0 ? $grant['user_id'] : (int) ( $client['granted_by'] ?? 0 ),
				'last_used'  => (int) ( $client['last_used'] ?? 0 ),
				'scope'      => $grant['scope'],
				'hub'        => $grant['hub'],
			);
		}

		usort(
			$output,
			static function ( array $a, array $b ): int {
				return $b['granted_at'] <=> $a['granted_at'];
			}
		);

		return $output;
	}

	/**
	 * The name an application registered under, or null for one this site
	 * no longer knows.
	 */
	public static function client_name( string $client_id ): ?string {
		$clients = '' === $client_id ? array() : self::state()['clients'];
		$name    = isset( $clients[ $client_id ]['name'] ) ? trim( (string) $clients[ $client_id ]['name'] ) : '';

		return '' === $name ? null : $name;
	}

	/**
	 * The return addresses one registered application named.
	 *
	 * @return string[]
	 */
	public static function redirect_uris_of( string $client_id ): array {
		$client = self::client( $client_id );

		return null === $client ? array() : array_values( array_map( 'strval', (array) $client['redirect_uris'] ) );
	}

	/** A grant's identity, excluding routine access and refresh-token rotation. Never exposes credentials. */
	public static function client_grants_digest( string $client_id ): string {
		return self::grants_digest( self::state(), $client_id );
	}

	private static function grants_digest( array $state, string $client_id ): string {
		$families = array();
		foreach ( array( 'tokens', 'refresh', 'codes' ) as $bucket ) {
			foreach ( $state[ $bucket ] as $key => $entry ) {
				if ( ( $entry['client_id'] ?? '' ) !== $client_id ) { continue; }
				$family = 'codes' === $bucket ? 'code:' . $key : (string) ( $entry['family'] ?? '' );
				$families[ $family ] = array( 'user' => (int) ( $entry['user_id'] ?? 0 ), 'scope' => (string) ( $entry['scope'] ?? '' ) );
			}
		}
		ksort( $families );
		return (string) \BetterShield\Agents\Capture::digest( $families );
	}

	/**
	 * Cut one application off, leaving every other connection alone.
	 *
	 * The registration itself is kept on purpose. Clients cache the id they
	 * were issued and reuse it when somebody reconnects them, so deleting it
	 * turns a reconnection into an unexplained failure. Keeping it costs
	 * nothing: reconnecting still needs a person's approval and still mints
	 * entirely new tokens.
	 */
	public static function revoke_client( string $client_id, ?string $expected_grants = null ): bool {
		if ( '' === $client_id ) {
			return false;
		}

		$removed = (bool) self::mutate(
			static function ( array &$state ) use ( $client_id, $expected_grants ): bool {
				if ( null !== $expected_grants && ! hash_equals( $expected_grants, self::grants_digest( $state, $client_id ) ) ) { return false; }
				$removed = false;

				foreach ( array( 'tokens', 'refresh', 'codes', 'spent' ) as $bucket ) {
					foreach ( $state[ $bucket ] as $key => $entry ) {
						if ( isset( $entry['client_id'] ) && (string) $entry['client_id'] === $client_id ) {
							unset( $state[ $bucket ][ $key ] );
							$removed = true;
						}
					}
				}

				return $removed;
			}
		);

		if ( $removed ) {
			AppTools::forget( $client_id );
			Networks::forget( Audit::APP . ':' . $client_id );
			self::end_link_without_the_hub();
		}

		return $removed;
	}

	/**
	 * End the grant a presented token belongs to, for the application it was
	 * issued to: RFC 7009 revocation.
	 *
	 * What ends is the grant rather than the one token: everything a single
	 * approval produced, access and refresh tokens alike. The application's
	 * other grants, and every other application's, are left alone.
	 *
	 * The answer is the same whether or not anything ended. A token this site
	 * never issued, one that has expired and one issued to another application
	 * all end nothing and say nothing, so the route cannot be used to learn
	 * which tokens are live, and nothing is written for any of them: the
	 * stored state is read first, and rewritten only once there is a grant to
	 * end.
	 *
	 * A refresh token rotated away moments ago still names its grant. At the
	 * token endpoint the same token is evidence of a copy and ends the grant
	 * there; here it is a request to end that grant, which is what presenting
	 * it there would have done, and it lets an application that hands back
	 * the token it held while a refresh replaced it end the access it meant
	 * to end.
	 *
	 * @param array<string, string> $body The revocation request.
	 * @return array{ended: bool}|\WP_Error
	 */
	public static function revoke_token( array $body ) {
		$presented = (string) ( $body['token'] ?? '' );
		$client_id = (string) ( $body['client_id'] ?? '' );

		if ( '' === $presented ) {
			return self::error( 'invalid_request', __( 'A revocation request has to carry the token it hands back.', 'bettershield' ) );
		}

		// Required, as a refresh requires it: these are public clients, so the
		// identifier is the whole of what says who is asking, and the token has
		// to have been issued to the application that names itself.
		if ( 1 !== preg_match( '/^bs_[a-f0-9]{32}$/', $client_id ) ) {
			return self::error( 'invalid_request', __( 'A revocation request has to name the application the token belongs to.', 'bettershield' ) );
		}

		$key  = self::digest( $presented );
		$hint = (string) ( $body['token_type_hint'] ?? '' );

		if ( '' === self::grant_family( self::state(), $key, $client_id, $hint ) ) {
			return array( 'ended' => false );
		}

		$last = self::mutate(
			static function ( array &$state ) use ( $key, $client_id, $hint ): ?bool {
				$family = self::grant_family( $state, $key, $client_id, $hint );

				// Ended by another request between the read and the claim.
				if ( '' === $family ) {
					return null;
				}

				self::drop_family( $state, $family );

				return ! self::holds_grant( $state, $client_id );
			}
		);

		if ( null === $last ) {
			return array( 'ended' => false );
		}

		// On the record as a Remove under Agents is, once the application holds
		// nothing; one still connected through another approval was not removed.
		if ( true === $last ) {
			$client = self::state()['clients'][ $client_id ] ?? array();

			Writer::instance()->record(
				'mcp_app_revoked',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'mcp_app',
					'object_id'   => $client_id,
					'context'     => array(
						'name'   => is_array( $client ) ? (string) ( $client['name'] ?? '' ) : '',
						'reason' => 'revoked_by_app',
					),
				)
			);
		}

		/*
		 * The Hub link sends only while this site holds the hub's grant. The
		 * hub handing that grant back ends the link now, key and all, as a
		 * Disconnect here does, rather than at the link's next run.
		 */
		if ( \BetterShield\Hub\Link\Link::is_on() && \BetterShield\Hub\Link\Link::NOT_HUB === \BetterShield\Hub\Link\Link::standing() ) {
			\BetterShield\Hub\Link\Link::disable( 'disconnected' );
		}

		return array( 'ended' => true );
	}

	/**
	 * The grant a token's digest belongs to, when the token was issued to this
	 * application and its grant is still on record: as an access token, a
	 * refresh token, or a refresh token already rotated away. Looked for where
	 * the hint points first, then everywhere else, as RFC 7009 asks. Empty for
	 * anything else, a token of another application included.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function grant_family( array $state, string $key, string $client_id, string $hint ): string {
		$buckets = 'refresh_token' === $hint ? array( 'refresh', 'tokens', 'spent' ) : array( 'tokens', 'refresh', 'spent' );

		foreach ( $buckets as $bucket ) {
			$entry = $state[ $bucket ][ $key ] ?? null;

			if ( is_array( $entry ) ) {
				return hash_equals( (string) ( $entry['client_id'] ?? '' ), $client_id ) ? (string) ( $entry['family'] ?? '' ) : '';
			}
		}

		return '';
	}


	/** Everything, gone. Called by disconnect. */
	public static function revoke_all(): void {
		delete_option( self::OPTION );
		AppTools::forget_all();
		Networks::forget_all();

		self::$memo = null;

		self::end_link_without_the_hub();
	}

	/**
	 * The Hub link sends only while the site holds the hub's grant, and its
	 * signing key is no use once it does not. Ended here, in the request that
	 * ended the grant, and by the person who ended it: from Agents › Connect
	 * or Connected apps the key and the switch stayed until the link's next
	 * scheduled run, indefinitely where the schedule does not run, and the
	 * Hub page had no link left to turn off (#1823).
	 */
	private static function end_link_without_the_hub(): void {
		if ( ! class_exists( \BetterShield\Hub\Link\Link::class ) || array() !== \BetterShield\Mcp\Hub::apps() ) {
			return;
		}

		\BetterShield\Hub\Link\Link::disable( 'disconnected' );
	}

	/** A write opt-out preserves read access and registrations, including pending approvals and rotations. */
	public static function narrow_write_scopes(): void {
		self::mutate( static function ( array &$state ): void {
			foreach ( array( 'tokens', 'refresh', 'codes' ) as $bucket ) {
				foreach ( $state[ $bucket ] as &$entry ) { $entry['scope'] = Scopes::READ_ONLY; }
				unset( $entry );
			}
		} );
	}

	/* ---- state ---------------------------------------------------------------- */

	/**
	 * The stored state, with everything expired already dropped.
	 *
	 * Pruned on the way out rather than on a schedule: this option is read on
	 * every authenticated call, so the read is the natural place to keep it
	 * from growing, and nothing else has to remember. Held for the request
	 * afterwards, because one call used to do all of this three times.
	 *
	 * @return array<string, mixed>
	 */
	private static function state(): array {
		if ( null !== self::$memo ) {
			return self::$memo;
		}

		self::$memo = self::normalize( get_option( self::OPTION, array() ) );

		return self::$memo;
	}

	/**
	 * Forget what this request has read. Production never needs this; a test
	 * process is many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::forget_state();

		self::$touched = array();
	}

	/**
	 * Drop the held copy and nothing else.
	 *
	 * What a write invalidates is the read, not the request's memory of what
	 * it has already queued: clearing that too would let one connection queue
	 * the same last-used write twice because something else saved in between.
	 */
	public static function forget_state(): void {
		self::$memo = null;
	}

	/**
	 * @param mixed $stored
	 * @return array<string, mixed>
	 */
	private static function normalize( $stored ): array {
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$state = array(
			'clients' => isset( $stored['clients'] ) && is_array( $stored['clients'] ) ? $stored['clients'] : array(),
			'codes'   => isset( $stored['codes'] ) && is_array( $stored['codes'] ) ? $stored['codes'] : array(),
			'tokens'  => isset( $stored['tokens'] ) && is_array( $stored['tokens'] ) ? $stored['tokens'] : array(),
			'refresh' => isset( $stored['refresh'] ) && is_array( $stored['refresh'] ) ? $stored['refresh'] : array(),
			// The digests of refresh tokens that have already been rotated
			// away, kept for as long as one could have lived so that presenting
			// one is answerable rather than merely useless.
			'spent'   => isset( $stored['spent'] ) && is_array( $stored['spent'] ) ? $stored['spent'] : array(),
		);

		$now = time();

		foreach ( array( 'codes', 'tokens', 'refresh', 'spent' ) as $bucket ) {
			foreach ( $state[ $bucket ] as $key => $entry ) {
				if ( ! is_array( $entry ) || ! isset( $entry['expires'] ) || (int) $entry['expires'] < $now ) {
					unset( $state[ $bucket ][ $key ] );
				}
			}
		}

		$state['spent'] = self::cap_spent( $state['spent'] );

		return $state;
	}

	/**
	 * Keep the memory of rotated-away refresh tokens bounded.
	 *
	 * Expiry alone does not bound it: nothing stops a client holding a live
	 * grant from rotating as fast as it can post, and every rotation adds an
	 * entry with a fresh thirty-day life. The newest few in each family are
	 * the ones a copied token could still be among; anything older is answered
	 * as a token this site did not issue, which is a weaker sentence about a
	 * case nobody reaches.
	 *
	 * @param array<string, mixed> $spent
	 * @return array<string, mixed>
	 */
	private static function cap_spent( array $spent ): array {
		$families = array();

		/*
		 * Walked backwards, so the newest entry of each family is seen first.
		 * Two rotations inside one second carry the same expiry, and the sort
		 * below is stable — without this the tie would be broken in favor of
		 * the oldest, which is precisely the wrong half to keep.
		 */
		foreach ( array_reverse( $spent, true ) as $key => $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			$families[ (string) ( $entry['family'] ?? '' ) ][ $key ] = (int) ( $entry['expires'] ?? 0 );
		}

		foreach ( $families as $keys ) {
			if ( count( $keys ) <= self::MAX_SPENT_PER_FAMILY ) {
				continue;
			}

			// Newest first: an entry's expiry is its own rotation stamped
			// forward by one refresh token's life, so it orders them.
			arsort( $keys );

			foreach ( array_slice( array_keys( $keys ), self::MAX_SPENT_PER_FAMILY ) as $key ) {
				unset( $spent[ $key ] );
			}
		}

		return $spent;
	}

	/**
	 * Read, change and write the state with nobody else in between.
	 *
	 * Every write goes through here. The claim is what makes a registration
	 * arriving beside a token mint two writes rather than one write and one
	 * silent loss; the cache drop is what makes the read inside the claim a
	 * read of what is actually stored rather than of what this request read
	 * before it waited.
	 *
	 * A claim that cannot be taken does not stop the write. This lock exists to
	 * order two writers, not to authorize either — refusing to write would turn
	 * a busy moment into a connection that cannot be made, which is worse than
	 * the rare interleaving it would prevent.
	 *
	 * @param callable $change Receives the state by reference; may return anything.
	 * @return mixed Whatever the callable returned.
	 */
	private static function mutate( callable $change ) {
		$held = false;

		for ( $attempt = 0; $attempt < self::LOCK_TRIES; $attempt++ ) {
			if ( Claim::claim( self::LOCK_KEY, self::LOCK_TTL ) ) {
				$held = true;
				break;
			}

			usleep( self::LOCK_WAIT );
		}

		try {
			// The read below has to be a read of what is stored, not of what
			// this request cached before it waited for the claim.
			wp_cache_delete( self::OPTION, 'options' );

			self::$memo = null;

			$stored = get_option( self::OPTION, null );

			if ( null === $stored ) {
				/*
				 * Absent — which may be this site's own record that it is
				 * absent, cached before another request wrote the first
				 * client. `notoptions` is one entry shared by every absent
				 * option on the site, so it is dropped only here, where
				 * whether the answer is right is the whole question, and never
				 * on a write to an option that already exists.
				 */
				wp_cache_delete( 'notoptions', 'options' );

				$stored = get_option( self::OPTION, null );
			}

			$state  = self::normalize( $stored );
			$result = $change( $state );

			self::save( $state );

			return $result;
		} finally {
			if ( $held ) {
				Claim::release( self::LOCK_KEY );
			}
		}
	}

	/**
	 * @param array<string, mixed> $state
	 */
	private static function save( array $state ): void {
		$current = WriteGrants::current();
		foreach ( array( 'tokens', 'refresh', 'codes' ) as $bucket ) {
			foreach ( $state[ $bucket ] as &$entry ) { $entry['scope'] = WriteGrants::scope( $entry, $current ); }
			unset( $entry );
		}
		update_option( self::OPTION, $state, false );

		self::$memo = null;
	}

	/**
	 * @return array{redirect_uris: string[], name: string, created: int, granted_by: int}|null
	 */
	private static function client( string $client_id ): ?array {
		if ( '' === $client_id ) {
			return null;
		}

		$clients = self::state()['clients'];

		if ( ! isset( $clients[ $client_id ] ) || ! is_array( $clients[ $client_id ] ) ) {
			return null;
		}

		$client = $clients[ $client_id ];

		return array(
			'redirect_uris' => isset( $client['redirect_uris'] ) && is_array( $client['redirect_uris'] )
				? array_map( 'strval', $client['redirect_uris'] )
				: array(),
			'name'          => isset( $client['name'] ) ? (string) $client['name'] : '',
			'created'       => (int) ( $client['created'] ?? 0 ),
			'granted_by'    => (int) ( $client['granted_by'] ?? 0 ),
		);
	}

	/**
	 * Keep the registration list bounded.
	 *
	 * Abandoned registrations go first, oldest of the rest after that, and a
	 * client referenced by a live code or token is never dropped — evicting
	 * one would break a working connection, so a site legitimately holding
	 * more than the ceiling keeps them all.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, array<string, mixed>>
	 */
	private static function prune_clients( array $state ): array {
		$clients = $state['clients'];
		$in_use  = array();

		foreach ( array( 'codes', 'tokens', 'refresh' ) as $bucket ) {
			foreach ( $state[ $bucket ] as $entry ) {
				if ( is_array( $entry ) && isset( $entry['client_id'] ) ) {
					$in_use[ (string) $entry['client_id'] ] = true;
				}
			}
		}

		$now = time();

		foreach ( $clients as $id => $client ) {
			$created = (int) ( $client['created'] ?? 0 );

			if ( ! isset( $in_use[ $id ] ) && $created + self::CLIENT_TTL < $now ) {
				unset( $clients[ $id ] );
			}
		}

		if ( count( $clients ) <= self::MAX_CLIENTS ) {
			return $clients;
		}

		$evictable = array_filter(
			$clients,
			static function ( $id ) use ( $in_use ): bool {
				return ! isset( $in_use[ $id ] );
			},
			ARRAY_FILTER_USE_KEY
		);

		uasort(
			$evictable,
			static function ( array $a, array $b ): int {
				return (int) ( $a['created'] ?? 0 ) <=> (int) ( $b['created'] ?? 0 );
			}
		);

		foreach ( array_keys( $evictable ) as $id ) {
			if ( count( $clients ) <= self::MAX_CLIENTS ) {
				break;
			}

			unset( $clients[ $id ] );
		}

		return $clients;
	}

	/* ---- helpers -------------------------------------------------------------- */

	/** How every secret here is stored, and the only form any of them is kept in. */
	private static function digest( string $value ): string {
		return hash( 'sha256', $value );
	}

	/**
	 * The S256 transformation: the base64url of the verifier's SHA-256.
	 */
	private static function s256( string $verifier ): string {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- the challenge encoding RFC 7636 defines; not obfuscation.
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Whether a return address is exactly one the client registered.
	 *
	 * Compared byte for byte and in constant time. A registered address is not
	 * a pattern and is never treated as one: no prefix, no wildcard, no
	 * normalization that could make two different addresses look like one.
	 *
	 * @param string[] $registered
	 */
	private static function exactly_one_of( string $presented, array $registered ): bool {
		foreach ( $registered as $candidate ) {
			if ( hash_equals( $candidate, $presented ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a resource indicator names this endpoint.
	 *
	 * Compared by parts rather than as a string, because a client that appends
	 * a slash or spells the host in a different case has still named this
	 * address, and refusing it would be a refusal nobody could act on.
	 */
	private static function names_this_resource( string $given ): bool {
		$asked = wp_parse_url( trim( $given ) );
		$ours  = wp_parse_url( self::resource() );

		if ( ! is_array( $asked ) || ! is_array( $ours ) ) {
			return false;
		}

		return strtolower( (string) ( $asked['scheme'] ?? '' ) ) === strtolower( (string) ( $ours['scheme'] ?? '' ) )
			&& strtolower( (string) ( $asked['host'] ?? '' ) ) === strtolower( (string) ( $ours['host'] ?? '' ) )
			&& self::port_of( $asked ) === self::port_of( $ours )
			&& untrailingslashit( (string) ( $asked['path'] ?? '' ) ) === untrailingslashit( (string) ( $ours['path'] ?? '' ) );
	}

	/**
	 * The port an address is on, spelled or implied.
	 *
	 * A client that writes the port its scheme already implies has named the
	 * same address, and refusing that is a refusal nobody can act on — which
	 * is exactly the class of difference the comparison above exists to see
	 * past.
	 *
	 * @param array<string, mixed> $parts
	 */
	private static function port_of( array $parts ): int {
		if ( isset( $parts['port'] ) ) {
			return (int) $parts['port'];
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );

		if ( 'https' === $scheme ) {
			return 443;
		}

		return 'http' === $scheme ? 80 : 0;
	}

	/**
	 * Whether a return address is one this server will ever send a code to.
	 *
	 * An allow-list rather than a shape check. `https` with a host is the
	 * hosted client; loopback `http` is the one running on the person's own
	 * machine; a private-use scheme in reverse-domain form is the desktop
	 * application registering its own handler. A fragment is refused outright —
	 * the specification forbids one on a redirection endpoint, and it is where
	 * an appended parameter would go unseen — and so is anything carrying a
	 * wildcard, along with the four schemes a browser treats as executable.
	 */
	private static function is_valid_redirect_uri( string $uri ): bool {
		$uri = trim( $uri );

		if ( '' === $uri || false !== strpos( $uri, '*' ) || false !== strpos( $uri, '#' ) ) {
			return false;
		}

		$parts = wp_parse_url( $uri );

		if ( ! is_array( $parts ) || isset( $parts['fragment'] ) ) {
			return false;
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = strtolower( (string) ( $parts['host'] ?? '' ) );

		if ( '' === $scheme ) {
			return false;
		}

		if ( 'https' === $scheme ) {
			return '' !== $host && self::is_plain_address( $uri, $host );
		}

		if ( 'http' === $scheme ) {
			return in_array( $host, array( 'localhost', '127.0.0.1', '[::1]', '::1' ), true );
		}

		if ( in_array( $scheme, array( 'javascript', 'data', 'file', 'vbscript' ), true ) ) {
			return false;
		}

		// A private-use scheme, which RFC 8252 §7.1 says should be a domain
		// name the application controls, written backwards. The dot is the
		// whole of what distinguishes one from a scheme anybody could claim.
		return false !== strpos( $scheme, '.' );
	}

	/**
	 * Whether an address is written the one way a browser cannot read as
	 * another host.
	 *
	 * The host compared — with the hub's, above all, which decides whether a
	 * ticket is asked for — has to be the host the browser reaches. A browser
	 * decodes an escaped host and reads another script's full stops as dots,
	 * and the redirect strips characters it does not send, so any of those
	 * reached the hub while reading as somewhere else here. So the host is
	 * plain ASCII letters, digits, hyphens and dots (an international name
	 * registers its xn-- form) or an address literal, and the address is one
	 * the redirect sends exactly as written.
	 */
	private static function is_plain_address( string $uri, string $host ): bool {
		if ( 1 !== preg_match( '/^(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.?|\[[0-9a-f:.]+\])$/', $host ) ) {
			return false;
		}

		return wp_sanitize_redirect( $uri ) === $uri;
	}

	/**
	 * An error the consent page may or may not be allowed to redirect with.
	 */
	private static function authorize_error( string $code, string $message, bool $redirectable ): \WP_Error {
		$data = array( 'status' => 400 );

		if ( $redirectable ) {
			$data['redirectable'] = true;
		}

		return new \WP_Error( $code, $message, $data );
	}

	/**
	 * An error the registration endpoint renders in RFC 7591's own shape.
	 */
	private static function registration_error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error(
			$code,
			$message,
			array(
				'status'            => $status,
				'error'             => $code,
				'error_description' => $message,
			)
		);
	}

	/**
	 * An error carrying the code the token endpoint has to render.
	 */
	private static function error( string $code, string $message ): \WP_Error {
		return new \WP_Error(
			$code,
			$message,
			array(
				'status'            => 400,
				'error'             => $code,
				'error_description' => $message,
			)
		);
	}
}
