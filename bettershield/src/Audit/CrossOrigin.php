<?php
/**
 * Whether another website can make signed-in requests to this one and read
 * the answers.
 *
 * A browser shares a response with another site only when the response says
 * so: `Access-Control-Allow-Origin` naming that site, and, for a request that
 * carries the visitor's cookies, `Access-Control-Allow-Credentials: true`.
 * A policy that names whichever site asked, with credentials, lets any page
 * the visitor opens call this site as them and read what comes back.
 *
 * **This asks rather than guesses.** It sends one request to each of the two
 * places a browser reaches with cookies, naming an origin nobody can own, and
 * reads the two headers that decide it. A request a site makes to itself
 * never leaves the server, so this reaches no third party.
 *
 * **What is not reported, and why.**
 *
 * - The REST API's own policy. WordPress answers every origin there, with
 *   credentials, on purpose: a cookie reaches the REST API as the visitor
 *   only with the nonce WordPress prints on its own pages, and without it the
 *   request is answered as a stranger's. The answer is recorded, and a
 *   finding opens only when code has replaced that policy and the request is
 *   answered as the visitor anyway, which this cannot see from outside, so it
 *   is never claimed.
 * - A wildcard with credentials. A browser refuses to share a signed-in
 *   answer under `*`, so it is a careless header rather than an open door.
 *
 * What is reported is admin-ajax answering a site it does not know, with
 * credentials. WordPress allows only the site's own addresses there, so a
 * foreign one named back means the allowed list was widened, by code or by
 * the web server, and every action on it that does not check a nonce answers
 * to any website.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CrossOrigin {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_cross_origin';

	/**
	 * An origin nobody can own: `.invalid` is reserved and never resolves, so
	 * a policy that names it back was not written for anybody real.
	 */
	public const FOREIGN = 'https://cross-origin-check.invalid';

	/**
	 * Where the probe's own admin-ajax request records what WordPress decided
	 * about the probe's origin: the token it expects, then the answer.
	 */
	public const WITNESS_OPTION = 'bettershield_cross_origin_witness';

	/** The header that carries the probe's one-time token to admin-ajax. */
	public const WITNESS_HEADER = 'X-BetterShield-Probe';

	/**
	 * Ask each endpoint, and remember the answer.
	 *
	 * @return array{checked_at: string, reliable: bool, reason?: string, endpoints: array<string, array<string, mixed>>, open: array<int, array<string, mixed>>}
	 */
	public static function probe(): array {
		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'reliable'   => true,
			'endpoints'  => array(),
			'open'       => array(),
		);

		$endpoints = self::endpoints();

		/*
		 * Only admin-ajax can open the finding, so where it cannot be asked
		 * from here (the WordPress address on another host, or outside the
		 * site address) the answer is "could not tell". Skipped, it stored a
		 * pass, and an open finding was closed as fixed while admin-ajax
		 * still named the foreign origin back.
		 */
		if ( null === $endpoints['admin_ajax'] ) {
			$answer['reliable'] = false;
			$answer['reason']   = 'elsewhere';

			update_option( self::OPTION, $answer, false );

			return $answer;
		}

		foreach ( $endpoints as $endpoint => $path ) {
			if ( null === $path ) {
				continue;
			}

			$headers = array(
				'Accept' => '*/*',
				'Origin' => self::FOREIGN,
			);

			// A token admin-ajax can record its own decision against: it is
			// where WordPress decides the header, and a widening that depends
			// on the request (only on AJAX, or for whichever site asks) is
			// not visible from this run.
			if ( 'admin_ajax' === $endpoint ) {
				$token = wp_generate_password( 32, false );
				update_option( self::WITNESS_OPTION, array( 'expect' => hash( 'sha256', $token ) ), false );
				$headers[ self::WITNESS_HEADER ] = $token;
			}

			$response  = Http::same_site( $path, array( 'headers' => $headers ) );
			$witnessed = 'admin_ajax' === $endpoint ? self::witnessed() : null;

			$code = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );

			/*
			 * A request that never arrived, or one sent somewhere else, says
			 * nothing about the policy on the address asked: a redirect to
			 * https or www carries the redirect's headers, not the
			 * endpoint's. Either is a stated "could not tell", never a pass.
			 */
			/*
			 * And WordPress answers a no-action request to admin-ajax with 400
			 * or 200, after it has written its cross-origin headers. Anything
			 * else is somebody in front of WordPress: a sign-in prompt, a
			 * firewall refusing the server's own address, a rate limit, a
			 * maintenance page. It carries none of those headers, so reading
			 * it as a policy stored a pass while browsers still got the real
			 * one. The REST API's answer only ever records its own policy and
			 * never opens this finding, so a refusal there is left recorded.
			 */
			$refused = 'admin_ajax' === $endpoint && 200 !== $code && 400 !== $code;

			if ( 0 === $code || ( $code >= 300 && $code < 400 ) || $refused ) {
				$answer['reliable']  = false;
				$answer['reason']    = 0 === $code ? 'unreachable' : ( $code >= 300 && $code < 400 ? 'redirected' : 'refused' );
				$answer['endpoints'] = array();
				$answer['open']      = array();

				if ( 'refused' === $answer['reason'] ) {
					$answer['code'] = $code;
				}

				if ( 'redirected' !== $answer['reason'] ) {
					$answer['failure'] = SelfRequest::failure( $response );
				}

				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			$policy      = self::policy( $response );
			$credentials = self::credentials( $response );

			$answer['endpoints'][ $endpoint ] = array(
				'policy'      => $policy,
				'credentials' => $credentials,
			);

			if ( 'admin_ajax' !== $endpoint || 'reflected' !== $policy || ! $credentials ) {
				continue;
			}

			$answer['open'][] = array(
				'endpoint' => $endpoint,
				'policy'   => $policy,
				'source'   => self::ajax_source( $witnessed ),
			);
		}

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
	 * The two places a browser reaches with the visitor's cookies, as paths
	 * below the home address, or null where one is on another host.
	 *
	 * @return array<string, ?string>
	 */
	public static function endpoints(): array {
		return array(
			'rest'       => self::relative_to_home( rest_url() ),
			'admin_ajax' => self::relative_to_home( admin_url( 'admin-ajax.php' ) ),
		);
	}

	/**
	 * What an endpoint answered about origins: the foreign one named back,
	 * any origin at all, or neither.
	 *
	 * @param array<string, mixed> $response
	 */
	private static function policy( array $response ): string {
		$values = self::header_values( $response, 'access-control-allow-origin' );

		foreach ( $values as $value ) {
			if ( self::FOREIGN === rtrim( $value, '/' ) ) {
				return 'reflected';
			}
		}

		return in_array( '*', $values, true ) ? 'wildcard' : 'none';
	}

	/** @param array<string, mixed> $response */
	private static function credentials( array $response ): bool {
		return in_array( 'true', array_map( 'strtolower', self::header_values( $response, 'access-control-allow-credentials' ) ), true );
	}

	/**
	 * Every value a header was sent with. The web server and WordPress can
	 * each send one, and a response carrying two is answered by both.
	 *
	 * @param array<string, mixed> $response
	 * @return string[]
	 */
	private static function header_values( array $response, string $name ): array {
		$raw    = wp_remote_retrieve_header( $response, $name );
		$values = array();

		foreach ( (array) $raw as $value ) {
			foreach ( explode( ',', (string) $value ) as $part ) {
				$part = trim( $part );

				if ( '' !== $part ) {
					$values[] = $part;
				}
			}
		}

		return $values;
	}

	/**
	 * Listen on the probe's own admin-ajax request, and on no other.
	 *
	 * Registered only on an admin-ajax request that carries the probe's
	 * header, so every other request pays for nothing but the check.
	 */
	public static function listen(): void {
		if ( ! wp_doing_ajax() || empty( $_SERVER['HTTP_X_BETTERSHIELD_PROBE'] ) ) {
			return;
		}

		add_filter( 'allowed_http_origin', array( self::class, 'witness' ), PHP_INT_MAX, 2 );
	}

	/**
	 * What WordPress decided about the probe's origin, recorded on the
	 * request it decided it for, with the code on the two filters that
	 * decide it. Only for the token the probe is waiting on, and only once.
	 *
	 * @param mixed $allowed The origin WordPress allows, or ''.
	 * @param mixed $origin  The origin it was asked about.
	 * @return mixed What WordPress decided, unchanged.
	 */
	public static function witness( $allowed, $origin = '' ) {
		if ( self::FOREIGN !== (string) $origin ) {
			return $allowed;
		}

		$token = sanitize_text_field( wp_unslash( (string) ( $_SERVER['HTTP_X_BETTERSHIELD_PROBE'] ?? '' ) ) );

		wp_cache_delete( self::WITNESS_OPTION, 'options' );
		$pending = get_option( self::WITNESS_OPTION );

		if ( '' === $token || ! is_array( $pending ) || isset( $pending['allowed'] ) || ! hash_equals( (string) ( $pending['expect'] ?? '' ), hash( 'sha256', $token ) ) ) {
			return $allowed;
		}

		update_option(
			self::WITNESS_OPTION,
			array(
				'expect'  => (string) $pending['expect'],
				'allowed' => '' !== (string) $allowed,
				'owners'  => array_values( array_unique( array_merge( self::owners( 'allowed_http_origins' ), self::owners( 'allowed_http_origin' ) ) ) ),
			),
			false
		);

		return $allowed;
	}

	/**
	 * What admin-ajax recorded about the probe's request, once, or null
	 * where it recorded nothing: a cache answered, or the server did before
	 * WordPress ran.
	 *
	 * @return array{allowed: bool, owners: string[]}|null
	 */
	private static function witnessed(): ?array {
		wp_cache_delete( self::WITNESS_OPTION, 'options' );
		$seen = get_option( self::WITNESS_OPTION );
		delete_option( self::WITNESS_OPTION );

		return is_array( $seen ) && isset( $seen['allowed'] )
			? array(
				'allowed' => (bool) $seen['allowed'],
				'owners'  => array_map( 'strval', (array) ( $seen['owners'] ?? array() ) ),
			)
			: null;
	}

	/**
	 * Who widened admin-ajax's allowed origins, as far as can be told.
	 *
	 * Decided on admin-ajax's own answer to the probe, where WordPress
	 * decides the header: if its list allowed an origin nobody can own, code
	 * widened it, and the callbacks on the two filters that decide it are
	 * named by where they live; if it did not, the header came from somewhere
	 * that bypasses the list, the web server or code sending its own headers.
	 *
	 * Where admin-ajax recorded nothing, the list is asked here instead. A
	 * widening it finds is still a widening; one it does not find may depend
	 * on the request, so it is not said to come from the server.
	 *
	 * @param array{allowed: bool, owners: string[]}|null $witnessed What admin-ajax recorded.
	 * @return array{kind: string, owners: string[]}
	 */
	public static function ajax_source( ?array $witnessed = null ): array {
		if ( null !== $witnessed ) {
			return $witnessed['allowed']
				? array(
					'kind'   => 'filter',
					'owners' => $witnessed['owners'],
				)
				: array(
					'kind'   => 'server',
					'owners' => array(),
				);
		}

		if ( ! is_allowed_http_origin( self::FOREIGN ) ) {
			return array(
				'kind'   => 'unknown',
				'owners' => array(),
			);
		}

		return array(
			'kind'   => 'filter',
			'owners' => array_values( array_unique( array_merge( self::owners( 'allowed_http_origins' ), self::owners( 'allowed_http_origin' ) ) ) ),
		);
	}

	/**
	 * Where the widened policy comes from, in the finding's words.
	 *
	 * @param array<string, mixed> $source As `ajax_source()` answered it.
	 */
	public static function describe_source( array $source ): string {
		if ( 'unknown' === ( $source['kind'] ?? '' ) ) {
			return __( 'Code on this site or the web server. BetterShield could not tell which.', 'bettershield' );
		}

		if ( 'filter' !== ( $source['kind'] ?? '' ) ) {
			return __( 'The web server, or code sending its own headers. WordPress’s allowed-origins list does not include it.', 'bettershield' );
		}

		$names = array();

		foreach ( (array) ( $source['owners'] ?? array() ) as $owner ) {
			$names[] = self::owner_name( (string) $owner );
		}

		if ( array() === $names ) {
			return __( 'Code on this site widens WordPress’s list of allowed origins.', 'bettershield' );
		}

		return sprintf(
			/* translators: %s: a list of plugin or theme names. */
			__( 'WordPress’s list of allowed origins is widened by: %s.', 'bettershield' ),
			implode( ', ', array_unique( $names ) )
		);
	}

	/**
	 * The plugins and themes with a callback on a hook, as the Plugins screen
	 * names them, leaving out WordPress and this plugin.
	 *
	 * @return string[]
	 */
	public static function owner_names( string $hook ): array {
		$names = array();

		foreach ( self::owners( $hook ) as $owner ) {
			if ( dirname( plugin_basename( BETTERSHIELD_FILE ) ) !== $owner ) {
				$names[] = self::owner_name( $owner );
			}
		}

		return array_values( array_unique( $names ) );
	}

	/**
	 * An owner as the Plugins screen names it, or as near as can be told.
	 */
	private static function owner_name( string $owner ): string {
		if ( 'mu-plugin' === $owner ) {
			return __( 'a must-use plugin', 'bettershield' );
		}

		if ( str_starts_with( $owner, 'theme:' ) ) {
			$theme = wp_get_theme( substr( $owner, 6 ) );

			return $theme->exists() ? wp_strip_all_tags( (string) $theme->get( 'Name' ) ) : substr( $owner, 6 );
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( get_plugins() as $file => $plugin ) {
			if ( $owner === dirname( (string) $file ) || $owner . '.php' === (string) $file ) {
				return wp_strip_all_tags( (string) $plugin['Name'] );
			}
		}

		return $owner;
	}

	/**
	 * The plugins, themes or must-use code with a callback on a hook, by
	 * directory. A heuristic, read from where each callback is defined; no
	 * callback is ever run.
	 *
	 * @return string[]
	 */
	private static function owners( string $hook ): array {
		global $wp_filter;

		if ( ! isset( $wp_filter[ $hook ] ) || ! is_object( $wp_filter[ $hook ] ) ) {
			return array();
		}

		$owners = array();

		foreach ( (array) $wp_filter[ $hook ]->callbacks as $callbacks ) {
			foreach ( (array) $callbacks as $entry ) {
				// The witness only listens; it widens nothing.
				if ( array( self::class, 'witness' ) === ( $entry['function'] ?? null ) ) {
					continue;
				}

				$owner = self::owner_of( $entry['function'] ?? null );

				if ( '' !== $owner && 'wordpress' !== $owner ) {
					$owners[] = $owner;
				}
			}
		}

		return $owners;
	}

	/** @param mixed $callback */
	private static function owner_of( $callback ): string {
		try {
			if ( is_array( $callback ) && isset( $callback[0], $callback[1] ) ) {
				$reflection = new \ReflectionMethod( is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0], (string) $callback[1] );
			} elseif ( $callback instanceof \Closure || ( is_string( $callback ) && function_exists( $callback ) ) ) {
				$reflection = new \ReflectionFunction( $callback );
			} else {
				return '';
			}
		} catch ( \Throwable $e ) {
			return '';
		}

		$file = (string) $reflection->getFileName();

		if ( '' === $file ) {
			return '';
		}

		$file  = wp_normalize_path( $file );
		$theme = wp_normalize_path( get_theme_root() );

		if ( str_starts_with( $file, trailingslashit( $theme ) ) ) {
			return 'theme:' . strtok( substr( $file, strlen( trailingslashit( $theme ) ) ), '/' );
		}

		$source = \BetterShield\Abilities\AgentSurface::source_path( $file );

		return 'unknown' === $source ? '' : $source;
	}

	/**
	 * One of this site's own addresses as a path below the home address, or
	 * null where it is not below it at all.
	 */
	private static function relative_to_home( string $url ): ?string {
		$home = home_url( '/' );

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
