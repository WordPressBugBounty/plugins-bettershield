<?php
/**
 * Whether the web server refuses xmlrpc.php before WordPress can answer.
 *
 * The XML-RPC finding read WordPress's own filter, which says whether
 * WordPress would serve the endpoint. Many hosts refuse the file at the web
 * server instead, and there the finding was reported at medium, and took
 * points off the score, for an endpoint nobody can reach.
 *
 * **This asks rather than guesses.** It sends one `system.listMethods` call
 * to the address the endpoint lives at. An answer from WordPress carries a
 * `<methodResponse>`, whether the call succeeded or WordPress refused it; a
 * refusal from the web server carries none.
 *
 * **A refusal counts only when the server answers this server otherwise.** A
 * firewall that blocks the site's own address refuses every request from
 * here, while visitors still reach the endpoint. So a refusal of xmlrpc.php
 * is believed only when a control request to the REST API, a WordPress
 * address any visitor may ask for, is answered normally. Anything this
 * cannot tell leaves the finding to the filter, as before, and never closes
 * it.
 *
 * A request a site makes to itself never leaves the server, so this reaches
 * no third party. The call lists method names and signs nobody in.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class XmlRpc {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_xmlrpc_probe';

	/** The background task that runs the probe. */
	public const TASK = 'bettershield_xmlrpc_probe';

	/** The statuses a web server refuses a file with. */
	private const REFUSALS = array( 403, 404, 405, 410 );

	/**
	 * Ask the endpoint, and remember the answer.
	 *
	 * @return array{checked_at: string, reliable: bool, blocked: bool, reason?: string, code?: int}
	 */
	public static function probe(): array {
		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'reliable'   => true,
			'blocked'    => false,
		);

		$path    = self::relative_to_home( site_url( 'xmlrpc.php' ) );
		$control = self::relative_to_home( rest_url() );

		if ( null === $path || null === $control ) {
			return self::unreliable( $answer, 'elsewhere' );
		}

		$response = Http::same_site_post(
			$path,
			array(
				'headers' => array( 'Content-Type' => 'text/xml' ),
				'body'    => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
			)
		);

		if ( is_wp_error( $response ) ) {
			return self::unreliable( $answer, 'unreachable' );
		}

		$code           = (int) wp_remote_retrieve_response_code( $response );
		$answer['code'] = $code;

		// WordPress answered, so the endpoint is served. Whether WordPress
		// itself refuses the calls is the filter's to say, and the check
		// reads it.
		if ( false !== stripos( (string) wp_remote_retrieve_body( $response ), '<methodResponse' ) ) {
			update_option( self::OPTION, $answer, false );

			return $answer;
		}

		// This plugin's own refusal ("Disable XML-RPC") comes from inside
		// WordPress, so the endpoint is served, and the item says the rest.
		// Taken for the web server's block, it outlived the item.
		if ( 'xmlrpc' === (string) wp_remote_retrieve_header( $response, strtolower( \BetterShield\Hardening\Item\XmlRpc::REFUSED_HEADER ) ) ) {
			update_option( self::OPTION, $answer, false );

			return $answer;
		}

		if ( $code >= 300 && $code < 400 ) {
			return self::unreliable( $answer, 'redirected' );
		}

		// A sign-in prompt, a rate limit or a maintenance page is somebody
		// standing in front of the whole site, not a rule about this file.
		if ( ! in_array( $code, self::REFUSALS, true ) ) {
			return self::unreliable( $answer, 'refused' );
		}

		$check = Http::same_site( $control, array( 'headers' => array( 'Accept' => 'application/json' ) ) );

		if ( is_wp_error( $check ) || 200 !== (int) wp_remote_retrieve_response_code( $check ) ) {
			return self::unreliable( $answer, 'refused' );
		}

		$answer['blocked'] = true;

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * The last answer, or nothing if this has never run.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['checked_at'] ) ? $stored : null;
	}

	/**
	 * Whether the last answer was a refusal this can stand behind.
	 */
	public static function blocked(): bool {
		$last = self::last();

		return null !== $last && ! empty( $last['reliable'] ) && ! empty( $last['blocked'] );
	}

	/**
	 * Record a run that could not tell, and answer with it.
	 *
	 * @param array<string, mixed> $answer
	 * @return array<string, mixed>
	 */
	private static function unreliable( array $answer, string $reason ): array {
		// A request that failed says nothing about a rule the host answered
		// with lately, so that answer stands, for as long as a server's answer
		// is trusted without being asked again. Its date doesn't move, and any
		// other reason is news about the site itself.
		$last = self::last();

		if ( null !== $last && in_array( $reason, array( 'unreachable', 'refused', 'redirected' ), true ) && self::blocked() && time() - (int) strtotime( (string) $last['checked_at'] ) < \BetterShield\Hardening\ServerRules::FRESH_FOR ) {
			return $last;
		}

		$answer['reliable'] = false;
		$answer['reason']   = $reason;
		$answer['blocked']  = false;

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * An address as a path below the home address, or null where it is on
	 * another host or outside the home path. Public for the quarantine
	 * folder's question to the server, which makes the same control request.
	 */
	public static function relative_to_home( string $url ): ?string {
		$home      = home_url( '/' );
		$host      = wp_parse_url( $url, PHP_URL_HOST );
		$home_host = wp_parse_url( $home, PHP_URL_HOST );

		if ( ! is_string( $host ) || ! is_string( $home_host ) || strtolower( $host ) !== strtolower( $home_host ) ) {
			return null;
		}

		$path      = trim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
		$home_path = trim( (string) wp_parse_url( $home, PHP_URL_PATH ), '/' );
		$query     = (string) wp_parse_url( $url, PHP_URL_QUERY );

		if ( '' !== $home_path ) {
			if ( $path !== $home_path && 0 !== strpos( $path, $home_path . '/' ) ) {
				return null;
			}

			$path = trim( substr( $path, strlen( $home_path ) ), '/' );
		}

		// Plain permalinks put the REST API behind a query string.
		return '' === $query ? $path : $path . '?' . $query;
	}
}
