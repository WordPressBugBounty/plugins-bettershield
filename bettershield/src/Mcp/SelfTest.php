<?php
/**
 * One real round trip to this site's own assistant endpoint, and the first
 * thing that went wrong.
 *
 * Everything else on the connection screen is read out of this site's own
 * state, which cannot see the two failures people actually hit: a certificate
 * the server will not verify, and an address that redirects. Both look
 * perfectly healthy from inside and refuse every assistant from outside. So
 * this makes the call an assistant would make and names the step it stopped
 * at, in order:
 *
 * `disabled` → `not_connected` → `unreachable` → `tls` → `redirect` →
 * `not_routed` → `auth` → `no_tools` → `ok`.
 *
 * The credential it uses is its own: a token good for two minutes, minted for
 * the account the connection runs as and withdrawn the moment the answer is
 * read. The pairing token is stored as a digest and cannot be presented by
 * anything, this included — which is the point of storing it that way, and
 * means a self-test can never be the thing that leaks it.
 *
 * A request a site makes to itself never leaves the server, so it goes
 * through the same-site path in the one class allowed to open a connection.
 *
 * **One request, and nothing read out of the answer is ever fetched.** The
 * addresses this endpoint publishes are computed here from this site's own
 * options; a URL that arrived in a response header is a URL somebody else
 * chose, and following one would turn a diagnostic into a request this site
 * makes wherever it is pointed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SelfTest {

	/** How long the probe credential lives, whatever happens to it. */
	public const PROBE_SECONDS = 120;

	/**
	 * Run the round trip.
	 *
	 * @return array{step: string, message: string, tools: int}
	 */
	public static function run(): array {
		if ( ! Manager::is_enabled() ) {
			// The screen says this step in its own words, and a second line
			// from here said the same thing again.
			return self::answer( 'disabled', '' );
		}

		/*
		 * Nothing to test with only when nothing holds access. An application
		 * that signed in through the browser holds a grant and no pairing, and
		 * so does every site connected through the hub; the probe mints its
		 * own credential either way.
		 */
		$apps = OAuth::connected_apps();

		if ( ! Pairing::is_connected() && array() === $apps ) {
			// The screen says this step in its own words, and a second line
			// from here said the same thing again.
			return self::answer( 'not_connected', '' );
		}

		/*
		 * Asked as the account the credential runs as, not whoever pressed
		 * the button. A paired account that has since lost the capability is
		 * refused at the door, and a probe minted for somebody else answered
		 * "ok" over it. With nothing paired, the newest app whose account can
		 * still act.
		 */
		$holder = Pairing::is_connected() ? Pairing::user_id() : 0;

		if ( Pairing::is_connected() && ! Server::may_act_as( $holder ) ) {
			$user = get_userdata( $holder );

			return self::answer(
				'auth',
				$user
					? sprintf(
						/* translators: %s: the name of the account that connected the assistant. */
						__( '%s connected this assistant and can no longer hold its credential, so the endpoint refuses it. Connect it again from an account that manages BetterShield.', 'bettershield' ),
						$user->display_name
					)
					: __( 'The account that connected this assistant is gone, so the endpoint refuses its credential. Connect it again from an account that manages BetterShield.', 'bettershield' )
			);
		}

		if ( ! Pairing::is_connected() ) {
			foreach ( $apps as $app ) {
				if ( Server::may_act_as( (int) $app['granted_by'] ) ) {
					$holder = (int) $app['granted_by'];

					break;
				}
			}

			if ( 0 === $holder ) {
				return self::answer(
					'auth',
					__( 'No account that approved the connected apps can still hold their access, so the endpoint refuses them. Connect them again from an account that manages BetterShield.', 'bettershield' )
				);
			}
		}

		// The address a person is handed, which on a site with plain permalinks
		// is the REST one: probing the pretty address there would report a
		// failure the screen never offered anybody.
		$endpoint = Pairing::address();
		$home     = home_url( '/' );
		$path     = 0 === strpos( $endpoint, $home ) ? '/' . substr( $endpoint, strlen( $home ) ) : '/' . Pairing::ENDPOINT_PATH;

		// The widest reach anything here holds, so the catalog this counts is
		// one a credential would actually be offered rather than a larger one
		// nobody can call.
		$token = OAuth::issue_probe_token( $holder, self::PROBE_SECONDS, self::reach( $apps ) );

		try {
			$response = Http::same_site_post(
				$path,
				array(
					'headers' => array(
						'Authorization' => 'Bearer ' . $token,
						'Content-Type'  => 'application/json',
						'Accept'        => 'application/json',
					),
					'body'    => (string) wp_json_encode(
						array(
							'jsonrpc' => '2.0',
							'id'      => 1,
							'method'  => 'tools/list',
						)
					),
				)
			);
		} finally {
			OAuth::withdraw_probe_token( $token );
		}

		return self::read( $response, $endpoint );
	}

	/**
	 * Read and write when the pairing or any live grant may change the site,
	 * read otherwise.
	 *
	 * @param array<int, array{scope: string}> $apps
	 */
	private static function reach( array $apps ): string {
		$scopes = array_column( $apps, 'scope' );

		if ( Pairing::is_connected() ) {
			$scopes[] = Pairing::scope();
		}

		foreach ( $scopes as $scope ) {
			if ( Scopes::allows_write( (string) $scope ) ) {
				return Scopes::READ_WRITE;
			}
		}

		return Scopes::READ_ONLY;
	}

	/**
	 * What the answer says, in the vocabulary above.
	 *
	 * @param array<string, mixed>|\WP_Error $response
	 * @return array{step: string, message: string, tools: int}
	 */
	private static function read( $response, string $endpoint ): array {
		if ( is_wp_error( $response ) ) {
			$reason = $response->get_error_message();

			// A certificate this server will not verify is its own answer:
			// the address is reachable and the connection is refused, which
			// is the commonest state on a local or staging site and needs a
			// different sentence from "nothing answered".
			$certificate = false !== stripos( $reason, 'ssl' ) || false !== stripos( $reason, 'certificate' );

			return self::answer(
				$certificate ? 'tls' : 'unreachable',
				$certificate
					? sprintf(
						/* translators: 1: the endpoint URL, 2: what the connection said. */
						__( '%1$s could not be reached over a verified connection: %2$s. On a local or staging site this is usually a certificate nothing outside it trusts.', 'bettershield' ),
						$endpoint,
						$reason
					)
					: sprintf(
						/* translators: 1: the endpoint URL, 2: what the connection said. */
						__( '%1$s could not be reached: %2$s.', 'bettershield' ),
						$endpoint,
						$reason
					)
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $response );

		if ( in_array( $status, array( 301, 302, 307, 308 ), true ) ) {
			return self::answer(
				'redirect',
				sprintf(
					/* translators: %s: the endpoint URL. */
					__( '%s redirected instead of answering. That usually means the site address and the WordPress address disagree about the scheme, and an assistant follows the redirect without the credential.', 'bettershield' ),
					$endpoint
				)
			);
		}

		if ( 404 === $status ) {
			return self::answer(
				'unreachable',
				sprintf(
					/* translators: 1: the endpoint URL, 2: the fallback endpoint URL. */
					__( '%1$s is not a URL this site knows. Save the permalink settings again to rebuild the rules; until then, give your assistant %2$s instead.', 'bettershield' ),
					$endpoint,
					Pairing::fallback_endpoint()
				)
			);
		}

		if ( in_array( $status, array( 401, 403, 429 ), true ) ) {
			return self::answer(
				'auth',
				sprintf(
					/* translators: %s: the endpoint URL. */
					__( '%s answered, and refused the credential. Rotate the connection token and pair the assistant again.', 'bettershield' ),
					$endpoint
				)
			);
		}

		$body  = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$tools = is_array( $body ) && isset( $body['result']['tools'] ) && is_array( $body['result']['tools'] )
			? $body['result']['tools']
			: null;

		// A 200 that is not a protocol answer is a page: a site with no rewrite
		// rules answers every unknown path with its front page, and so does a
		// rule in front of WordPress that catches the address first. Naming
		// that is what stops it reading as "the endpoint offered nothing".
		if ( 200 === $status && ( ! is_array( $body ) || ! isset( $body['jsonrpc'] ) ) ) {
			return self::answer(
				'not_routed',
				$endpoint === Pairing::fallback_endpoint()
					? sprintf(
						/* translators: %s: the endpoint URL. */
						__( '%s answered with a page instead of the endpoint. Something in front of WordPress is answering that address before this plugin can.', 'bettershield' ),
						$endpoint
					)
					: sprintf(
						/* translators: 1: the endpoint URL, 2: the fallback endpoint URL. */
						__( '%1$s answered with a page instead of the endpoint, so that address is not routed to this plugin. Save the permalink settings again to rebuild the rules; until then, give your assistant %2$s instead.', 'bettershield' ),
						$endpoint,
						Pairing::fallback_endpoint()
					)
			);
		}

		// An empty catalog is a failure rather than a pass. It is the exact
		// shape of a connection an assistant calls healthy and cannot use.
		if ( 200 !== $status || null === $tools || array() === $tools ) {
			return self::answer(
				'no_tools',
				sprintf(
					/* translators: %s: the endpoint URL. */
					__( '%s answered and offered no tools. Check that agent access is turned on and that this installation carries the abilities runtime.', 'bettershield' ),
					$endpoint
				)
			);
		}

		return self::answer(
			'ok',
			sprintf(
				/* translators: %d: how many tools the endpoint offered. */
				_n(
					'The endpoint answered, accepted the credential and offered %d tool.',
					'The endpoint answered, accepted the credential and offered %d tools.',
					count( $tools ),
					'bettershield'
				),
				count( $tools )
			),
			count( $tools )
		);
	}

	/**
	 * @return array{step: string, message: string, tools: int}
	 */
	private static function answer( string $step, string $message, int $tools = 0 ): array {
		return array(
			'step'    => $step,
			'message' => $message,
			'tools'   => $tools,
		);
	}
}
