<?php
/**
 * Whether the sign-in page is answered from a page cache or a CDN.
 *
 * A cached sign-in page hands every visitor the same copy: a form built for
 * somebody else, with whatever that request was told. Sign-in forms carry
 * per-request values, and a lockout answer is about one visitor, so a copy
 * served to the next one is wrong twice: the form can fail for reasons the
 * visitor cannot see, and one visitor's answer is shown to others.
 *
 * **This asks rather than guesses.** It requests the sign-in address the
 * site actually uses, twice, as a visitor with no cookies (following a
 * redirect to a custom login page on this site when that is where the
 * form really is), and reads the
 * headers caches add to what they serve: a status naming a hit, or an `Age`
 * above zero. The second request is the one that counts, because the first
 * may be what fills the cache. Only a hit is reported, never a guess from
 * the host.
 *
 * A request a site makes to itself never leaves the server, so this reaches
 * no third party. It is a plain GET of a page any visitor may open: nothing
 * is submitted and no attempt is counted.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SignInCache {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_sign_in_cache';

	/**
	 * Headers whose value names what a cache did with the response, by the
	 * header's lowercase name.
	 */
	private const STATUS_HEADERS = array(
		'cf-cache-status',
		'x-cache',
		'x-cache-status',
		'x-litespeed-cache',
		'x-proxy-cache',
		'x-nginx-cache',
		'x-fastcgi-cache',
		'x-srcache-fetch-status',
		'x-sucuri-cache',
		'x-kinsta-cache',
		'x-hcdn-cache-status',
		'x-rocket-nginx-serving-static',
	);

	/**
	 * Values that mean the response came out of a cache rather than from
	 * WordPress: a hit, and the states a cache answers with while it
	 * refreshes a copy it already served. A word boundary was not enough:
	 * it does not fall after an underscore, so "TCP_HIT" from one CDN read
	 * as a miss, and another CDN joins its word on ("RefreshHit").
	 */
	private const HIT_PATTERN = '/(?:^|[^a-z])(?:hit|stale|updating|revalidated)(?![a-z])|refreshhit/i';

	/**
	 * Ask twice, and remember the answer.
	 *
	 * @return array{checked_at: string, reliable: bool, reason?: string, path?: string, cached: bool, signals: array<int, array{header: string, value: string}>}
	 */
	public static function probe(): array {
		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'reliable'   => true,
			'cached'     => false,
			'signals'    => array(),
		);

		$path = self::sign_in_path();

		if ( null === $path ) {
			return self::unreliable( $answer, 'elsewhere' );
		}

		$answer['path'] = $path;
		$response       = null;

		/*
		 * The address as it is asked for, home path included. The path is
		 * kept below the home address for the request, and named alone it
		 * read /wp-login.php on a site under /blog, or the main site's page
		 * on a subdirectory network, rather than the page found cached.
		 */
		$asked             = home_url( '/' ) . ltrim( $path, '/' );
		$query             = (string) wp_parse_url( $asked, PHP_URL_QUERY );
		$answer['address'] = (string) wp_parse_url( $asked, PHP_URL_PATH ) . ( '' === $query ? '' : '?' . $query );

		$args     = array( 'headers' => array( 'Accept' => 'text/html' ) );
		$response = Http::same_site( $path, $args );

		if ( is_wp_error( $response ) ) {
			return self::unreliable( $answer + array( 'failure' => SelfRequest::failure( $response ) ), 'unreachable' );
		}

		/*
		 * A custom login page often leaves the sign-in address alone and
		 * sends /wp-login.php on to its own page. Followed by hand, at most
		 * two hops and only on this site. The page it lands on counts only
		 * if it has a password field: plenty of setups send /wp-login.php to
		 * the home page, and reading that page's cache headers would report
		 * the sign-in page as cached on nearly every cached site.
		 */
		$landed = null;

		if ( self::is_redirect( $response ) ) {
			$landed = self::follow( $response, $asked );

			if ( null === $landed ) {
				$answer['code'] = (int) wp_remote_retrieve_response_code( $response );

				return self::unreliable( $answer, 'redirected' );
			}

			$query             = (string) wp_parse_url( $landed, PHP_URL_QUERY );
			$answer['address'] = (string) wp_parse_url( $landed, PHP_URL_PATH ) . ( '' === $query ? '' : '?' . $query );
			// Kept below the home address, as the sign-in path is.
			$home_path      = trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
			$answer['path'] = ltrim( $answer['address'], '/' );
			$answer['path'] = '' !== $home_path && 0 === strpos( $answer['path'], $home_path . '/' ) ? substr( $answer['path'], strlen( $home_path ) + 1 ) : $answer['path'];
		}

		// The first may be what fills the cache; the second is what the next
		// visitor gets. A redirect's landing page is asked twice of its own.
		for ( $i = null === $landed ? 1 : 0; $i < 2; $i++ ) {
			$response = null === $landed ? Http::same_site( $path, $args ) : Http::same_site_at( $landed, $args );

			if ( is_wp_error( $response ) ) {
				return self::unreliable( $answer + array( 'failure' => SelfRequest::failure( $response ) ), 'unreachable' );
			}
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		/*
		 * Only the page itself says anything about how the page is served. A
		 * redirect is an answer about another address, and a refusal is the
		 * host keeping the page from this server; neither is "not cached".
		 */
		if ( 200 !== $code ) {
			$answer['code'] = $code;

			// A redirect is its own answer, and its own sentence.
			if ( $code < 300 || $code >= 400 ) {
				$answer['failure'] = SelfRequest::failure( $response );
			}

			return self::unreliable( $answer, 0 === $code ? 'unreachable' : ( $code >= 300 && $code < 400 ? 'redirected' : 'refused' ) );
		}

		$answer['signals'] = self::signals( $response );
		$answer['cached']  = array() !== $answer['signals'];

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
	 * The headers on a response that say a cache served it.
	 *
	 * @param array<string, mixed> $response
	 * @return array<int, array{header: string, value: string}>
	 */
	public static function signals( array $response ): array {
		$signals = array();

		foreach ( self::STATUS_HEADERS as $name ) {
			foreach ( (array) wp_remote_retrieve_header( $response, $name ) as $value ) {
				$value = trim( (string) $value );

				if ( '' !== $value && 1 === preg_match( self::HIT_PATTERN, $value ) ) {
					$signals[] = array(
						'header' => $name,
						'value'  => substr( $value, 0, 80 ),
					);
				}
			}
		}

		// Two request ids is how this cache says the second answered from the
		// first.
		foreach ( (array) wp_remote_retrieve_header( $response, 'x-varnish' ) as $value ) {
			if ( 1 === preg_match( '/^\s*\d+\s+\d+\s*$/', (string) $value ) ) {
				$signals[] = array(
					'header' => 'x-varnish',
					'value'  => trim( (string) $value ),
				);
			}
		}

		foreach ( (array) wp_remote_retrieve_header( $response, 'age' ) as $value ) {
			if ( is_numeric( trim( (string) $value ) ) && (int) $value > 0 ) {
				$signals[] = array(
					'header' => 'age',
					'value'  => (string) (int) $value,
				);
			}
		}

		return $signals;
	}

	/**
	 * The sign-in address as a path below the home address, wherever it has
	 * been moved to, or null where it is on another host.
	 */
	public static function sign_in_path(): ?string {
		$url       = wp_login_url();
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

		return '' === $query ? $path : $path . '?' . $query;
	}

	/** Redirect statuses a sign-in address is followed through. */
	private const REDIRECTS = array( 301, 302, 303, 307, 308 );

	/** Hops followed before giving up. */
	private const MAX_HOPS = 2;

	/**
	 * Bytes of a redirect's landing page read to find the password field.
	 * More than the usual self-request cap: a theme's header can easily
	 * fill that before the form starts.
	 */
	private const LANDING_BYTES = 262144;

	/**
	 * @param array<string, mixed> $response
	 */
	private static function is_redirect( array $response ): bool {
		return in_array( (int) wp_remote_retrieve_response_code( $response ), self::REDIRECTS, true );
	}

	/**
	 * Where a redirect from the sign-in address ends up, when that is a
	 * sign-in form on this site; null for anything else.
	 *
	 * @param array<string, mixed> $response The redirect.
	 * @param string               $from     The address that answered with it.
	 */
	private static function follow( array $response, string $from ): ?string {
		for ( $hop = 0; $hop < self::MAX_HOPS; $hop++ ) {
			$to = self::resolve( (string) wp_remote_retrieve_header( $response, 'location' ), $from );

			if ( null === $to ) {
				return null;
			}

			$response = Http::same_site_at(
				$to,
				array(
					'headers'             => array( 'Accept' => 'text/html' ),
					'limit_response_size' => self::LANDING_BYTES,
				)
			);

			if ( is_wp_error( $response ) ) {
				return null;
			}

			if ( 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				return 1 === preg_match( '/<input\b[^>]*\btype\s*=\s*["\']?password\b/i', (string) wp_remote_retrieve_body( $response ) ) ? $to : null;
			}

			if ( ! self::is_redirect( $response ) ) {
				return null;
			}

			$from = $to;
		}

		return null;
	}

	/**
	 * A Location header as a full address, relative ones resolved against the
	 * address that sent it. Null when it is empty or leaves this site; the
	 * request itself holds the host to this site's again.
	 */
	private static function resolve( string $location, string $from ): ?string {
		$location = trim( $location );

		if ( '' === $location ) {
			return null;
		}

		if ( 0 === strpos( $location, '//' ) ) {
			$location = (string) wp_parse_url( $from, PHP_URL_SCHEME ) . ':' . $location;
		} elseif ( null === wp_parse_url( $location, PHP_URL_SCHEME ) ) {
			$origin = (string) wp_parse_url( $from, PHP_URL_SCHEME ) . '://' . (string) wp_parse_url( $from, PHP_URL_HOST );
			$port   = wp_parse_url( $from, PHP_URL_PORT );
			$origin = null === $port ? $origin : $origin . ':' . (int) $port;

			if ( '/' !== $location[0] ) {
				$dir      = (string) wp_parse_url( $from, PHP_URL_PATH );
				$dir      = '' === $dir ? '/' : substr( $dir, 0, (int) strrpos( $dir, '/' ) + 1 );
				$location = $dir . $location;
			}

			$location = $origin . $location;
		}

		$host = wp_parse_url( $location, PHP_URL_HOST );
		$home = wp_parse_url( home_url( '/' ), PHP_URL_HOST );

		return is_string( $host ) && is_string( $home ) && strtolower( $host ) === strtolower( $home ) ? $location : null;
	}

	/**
	 * Record a run that could not tell, and answer with it.
	 *
	 * @param array<string, mixed> $answer
	 * @return array<string, mixed>
	 */
	private static function unreliable( array $answer, string $reason ): array {
		$answer['reliable'] = false;
		$answer['reason']   = $reason;
		$answer['cached']   = false;
		$answer['signals']  = array();

		update_option( self::OPTION, $answer, false );

		return $answer;
	}
}
