<?php
/**
 * Every other MCP endpoint on the site, who owns it, and whether it answers
 * without signing in (#1877).
 *
 * AI plugins ship their own MCP servers outside the Abilities registry, as
 * REST routes of their own, and those have had the worst flaws in the field:
 * an endpoint that let a subscriber become an administrator, a URL mode that
 * took no credential at all. Agents › Surface listed the registry and the
 * application passwords, and none of these.
 *
 * The REST routes are walked for the shapes an MCP server takes (a path
 * segment named mcp, a streamable or SSE transport beside one, a
 * protected-resource document), and each is attributed to the plugin its
 * callback lives in. A route whose permission callback is missing,
 * `__return_true`, or answers yes to a caller nobody signed in as is then
 * asked itself over a request this site makes to itself, with no cookie and
 * a short timeout, for `initialize` (and `tools/list` only when that came
 * back as a JSON-RPC error), both read-only: many servers let the permission callback through and
 * refuse in the handler, where they send the 401 and WWW-Authenticate
 * challenge MCP clients start OAuth from. Only a route that gives that
 * caller a JSON-RPC result is said to accept calls without signing in.
 * OAuth discovery and sign-in routes are public by design and are listed as
 * sign-in routes, never as open. Core's own routes are never called.
 * Where vulnerability checks have data, the owner's known advisories are
 * named. This plugin's own endpoint is left out: it has its own card.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class McpEndpoints {

	/**
	 * A path segment an MCP server's route carries: the protocol's own name,
	 * its long form, or the protected-resource document an OAuth-guarded
	 * server publishes.
	 */
	private const SHAPE = '#(?:^|/)(?:mcp|model-context-protocol|oauth-protected-resource)(?:[/_-]|$)#i';

	/**
	 * A route that has to answer a stranger: the protected-resource or
	 * authorization-server document, or an OAuth step a client takes before
	 * it holds a token.
	 */
	private const SIGN_IN = '#(?:^|/)(?:(?:oauth-)?protected-resource|oauth-authorization-server|openid-configuration)(?:/|$)|(?:^|/)oauth2?(?:/[^/]+)*/(?:authorize|token|register|revoke|device)(?:/|$)#i';

	/** Where each route's answer is kept between checks. */
	public const CACHE = 'bettershield_mcp_route_answers';

	/** How long a clear answer is kept: a plugin update or switch clears it sooner. */
	private const KEEP = 12 * HOUR_IN_SECONDS;

	/** How long a route that couldn't be asked is left before asking again. */
	private const KEEP_UNCHECKED = HOUR_IN_SECONDS;

	/** Seconds one call to another plugin's route may take. */
	private const TIMEOUT = 3;

	/** Seconds all of one report's calls may take together. */
	private const BUDGET = 9.0;

	/** Seconds this request has spent calling routes so far. */
	private static float $spent = 0.0;

	/**
	 * @return array<int, array{route: string, owner: string, owner_label: string, open: bool, sign_in: bool, advisory: bool}>
	 */
	public static function report(): array {
		$server = rest_get_server();
		$found  = array();

		foreach ( $server->get_routes() as $route => $handlers ) {
			$route = (string) $route;

			if ( 1 !== preg_match( self::SHAPE, $route ) || str_starts_with( ltrim( $route, '/' ), 'bettershield/' ) ) {
				continue;
			}

			$found_row = self::row( $route, (array) $handlers );

			if ( null !== $found_row ) {
				$found[] = $found_row;
			}
		}

		usort(
			$found,
			static fn( array $a, array $b ): int => array( (int) ! $a['open'], $a['route'] ) <=> array( (int) ! $b['open'], $b['route'] )
		);

		return $found;
	}

	/**
	 * One matched route as the report lists it, or null for core's own.
	 *
	 * @param array<int|string, mixed> $handlers
	 * @return array{route: string, owner: string, owner_label: string, open: bool, sign_in: bool, advisory: bool}|null
	 */
	public static function row( string $route, array $handlers ): ?array {
		$owner   = '';
		$through = false;

		foreach ( $handlers as $handler ) {
			if ( ! is_array( $handler ) ) {
				continue;
			}

			if ( '' === $owner ) {
				$owner = self::owner_of( $handler['callback'] ?? null );
			}

			$through = $through || self::answers_anyone( $handler, $route );
		}

		// Core's own routes are not another plugin's door, and never called.
		if ( 'wordpress' === $owner ) {
			return null;
		}

		$sign_in = 1 === preg_match( self::SIGN_IN, $route );
		$refused = false;
		$open    = ! $sign_in && $through && self::serves_stranger( $route, $refused );

		return array(
			'route'       => $route,
			'owner'       => $owner,
			'owner_label' => '' === $owner ? __( 'Unknown source', 'bettershield' ) : AgentSurface::source_label( $owner ),
			// Public by design is not open; past the permission callback,
			// only a real answer to a stranger is.
			'open'        => $open,
			'sign_in'     => $sign_in,
			// Let through, called, and neither refused nor answered as MCP:
			// it doesn't ask for a sign-in, it just isn't an AI connection.
			'not_mcp'     => ! $open && ! $sign_in && $through && ! $refused,
			'advisory'    => '' !== $owner && self::has_advisory( $owner ),
		);
	}

	/**
	 * Whether the route gives a caller nobody signed in as a JSON-RPC result.
	 *
	 * It is asked over a request this site makes to itself, with no cookie,
	 * so the route answers exactly what a stranger gets, and runs in its own
	 * request: what it prints, the headers it sends, a sleep or an `exit`
	 * stay there, and the timeout bounds what it can cost this one. The
	 * answer is kept, so a route with side effects is not called again on
	 * every Agent surface load or audit, and `initialize` is sent alone
	 * unless it came back as a JSON-RPC error. A refusal (401, 403, a
	 * WWW-Authenticate challenge, an error) is not open, and sets
	 * `$refused`. A route that couldn't be asked (loopback blocked, timed
	 * out, or past this report's time budget) reads as its permission
	 * callback says: open, as before it was asked.
	 *
	 * @param bool $refused Set when the route asked the caller to sign in.
	 */
	private static function serves_stranger( string $route, bool &$refused = false ): bool {
		// A route with a parameter in its path can't be called as listed.
		if ( str_contains( $route, '(?P<' ) || str_contains( $route, '(' ) ) {
			return true;
		}

		$kept = get_transient( self::CACHE );
		$kept = is_array( $kept ) ? $kept : array();
		$key  = md5( $route );

		if ( isset( $kept[ $key ] ) && is_array( $kept[ $key ] ) && (int) ( $kept[ $key ]['until'] ?? 0 ) > time() ) {
			$refused = ! empty( $kept[ $key ]['refused'] );

			return ! empty( $kept[ $key ]['open'] );
		}

		$answer = self::ask( $route );

		// Past this report's time budget: not the route's doing, so nothing
		// is kept, and it is asked on the next load.
		if ( false === $answer ) {
			return true;
		}

		if ( null === $answer ) {
			$kept[ $key ] = array(
				'open'    => true,
				'refused' => false,
				'until'   => time() + self::KEEP_UNCHECKED,
			);
		} else {
			$kept[ $key ] = $answer + array( 'until' => time() + self::KEEP );
		}

		set_transient( self::CACHE, $kept, self::KEEP );

		$refused = ! empty( $kept[ $key ]['refused'] );

		return ! empty( $kept[ $key ]['open'] );
	}

	/**
	 * What a stranger gets from the route, null when it couldn't be asked,
	 * or false when this report's time budget ran out first.
	 *
	 * @return array{open: bool, refused: bool}|null|false
	 */
	private static function ask( string $route ) {
		$path = self::path_of( $route );

		if ( null === $path ) {
			return null;
		}

		foreach ( array( 'initialize', 'tools/list' ) as $index => $method ) {
			$left = self::BUDGET - self::$spent;

			if ( $left < 1 ) {
				return 0 === $index ? false : null;
			}

			$began    = microtime( true );
			$response = \BetterShield\Support\Http::same_site_post(
				$path,
				array(
					'timeout' => (int) min( self::TIMEOUT, floor( $left ) ),
					'headers' => array(
						'Content-Type' => 'application/json',
						'Accept'       => 'application/json, text/event-stream',
					),
					'body'    => (string) wp_json_encode(
						array(
							'jsonrpc' => '2.0',
							'id'      => $index + 1,
							'method'  => $method,
							'params'  => 'initialize' === $method ? array(
								'protocolVersion' => '2025-06-18',
								'capabilities'    => new \stdClass(),
								'clientInfo'      => array(
									'name'    => 'bettershield-audit',
									'version' => '1',
								),
							) : new \stdClass(),
						)
					),
				)
			);

			self::$spent += microtime( true ) - $began;

			if ( is_wp_error( $response ) ) {
				return null;
			}

			$status  = (int) wp_remote_retrieve_response_code( $response );
			$headers = array();

			// Requests' header dictionary is iterable, not an array to cast.
			foreach ( wp_remote_retrieve_headers( $response ) as $name => $value ) {
				$headers[ strtolower( (string) $name ) ] = $value;
			}

			$body    = (string) wp_remote_retrieve_body( $response );

			if ( self::is_refusal( $status, $headers ) ) {
				return array(
					'open'    => false,
					'refused' => true,
				);
			}

			if ( self::is_result( $body ) ) {
				return array(
					'open'    => true,
					'refused' => false,
				);
			}

			// `tools/list` is worth asking only of a route that answered as
			// JSON-RPC but not with a result (a server that skips
			// `initialize`). Anything else is not an AI connection, and is
			// not called again.
			if ( ! self::is_rpc_error( $body ) ) {
				break;
			}
		}

		return array(
			'open'    => false,
			'refused' => false,
		);
	}

	/**
	 * The route as a path on this site, the way `rest_url()` spells it for
	 * the site's permalinks, or null when that isn't under the site's home.
	 */
	private static function path_of( string $route ): ?string {
		$home = home_url( '/' );
		$url  = rest_url( ltrim( $route, '/' ) );

		if ( ! str_starts_with( $url, $home ) ) {
			return null;
		}

		return '/' . ltrim( substr( $url, strlen( $home ) ), '/' );
	}

	/**
	 * Forgets every route's kept answer: a plugin switched on, off or
	 * updated may answer differently now.
	 */
	public static function forget(): void {
		delete_transient( self::CACHE );
	}

	/**
	 * Whether an answer's body is a JSON-RPC result.
	 */
	private static function is_result( string $data ): bool {
		if ( self::is_result_message( json_decode( $data, true ) ) ) {
			return true;
		}

		// Streamable HTTP may answer as a stream of events, each message on
		// a `data:` line: asked with text/event-stream accepted, that is as
		// real an answer as plain JSON (#2939).
		foreach ( preg_split( '/\r\n|\r|\n/', $data ) as $line ) {
			if ( str_starts_with( $line, 'data:' ) && self::is_result_message( json_decode( trim( substr( $line, 5 ) ), true ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an answer's body is a JSON-RPC error, as plain JSON or on an
	 * event stream's `data:` line.
	 */
	private static function is_rpc_error( string $data ): bool {
		$lines = array_merge( array( $data ), preg_split( '/\r\n|\r|\n/', $data ) );

		foreach ( $lines as $line ) {
			$line    = str_starts_with( $line, 'data:' ) ? trim( substr( $line, 5 ) ) : $line;
			$message = json_decode( $line, true );

			if ( is_array( $message ) && array_key_exists( 'error', $message ) && isset( $message['jsonrpc'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an answer refuses the caller: an error status, or a
	 * WWW-Authenticate challenge.
	 *
	 * @param array<string, mixed> $headers Lowercased names.
	 */
	private static function is_refusal( int $status, array $headers ): bool {
		return $status >= 400 || array_key_exists( 'www-authenticate', $headers );
	}

	/**
	 * Whether one decoded JSON-RPC message is a result, not an error.
	 *
	 * @param mixed $message
	 */
	private static function is_result_message( $message ): bool {
		return is_array( $message ) && array_key_exists( 'result', $message ) && ! array_key_exists( 'error', $message );
	}

	/**
	 * The endpoints that accept calls without signing in, by route.
	 *
	 * @return string[]
	 */
	public static function open_routes(): array {
		return array_values( array_column( array_filter( self::report(), static fn( array $row ): bool => $row['open'] ), 'route' ) );
	}

	/**
	 * Whether a handler lets anyone call it: no permission callback at all
	 * (core then lets the request through, and says so only in a notice), or
	 * one that answers yes to everybody. A closure that returns true is as
	 * open as `__return_true`, so the callback is asked as nobody signed in,
	 * with a request of the route's own method, as core would ask it.
	 *
	 * @param array<string, mixed> $handler
	 */
	private static function answers_anyone( array $handler, string $route ): bool {
		$check = $handler['permission_callback'] ?? null;

		if ( null === $check || '__return_true' === $check ) {
			return true;
		}

		if ( ! is_callable( $check ) ) {
			return false;
		}

		$methods = array_keys( array_filter( (array) ( $handler['methods'] ?? array() ) ) );
		$request = new \WP_REST_Request( (string) ( $methods[0] ?? 'POST' ), $route );
		$was     = get_current_user_id();

		wp_set_current_user( 0 );

		try {
			return true === call_user_func( $check, $request );
		} catch ( \Throwable $e ) {
			return false;
		} finally {
			wp_set_current_user( $was );
		}
	}

	/**
	 * The plugin, theme or must-use code a callback lives in.
	 *
	 * @param mixed $callback
	 */
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

		$source = AgentSurface::source_path( $file );

		return 'unknown' === $source ? '' : $source;
	}

	/**
	 * Whether the vulnerability checks hold an advisory for this plugin.
	 * Nothing is fetched here: where the checks are off or have no data,
	 * the answer is no rather than a guess.
	 */
	private static function has_advisory( string $slug ): bool {
		$state = \BetterShield\Vulnerabilities\State::get();

		foreach ( (array) ( $state['affected'] ?? array() ) as $item ) {
			if ( is_array( $item ) && 'plugin' === ( $item['type'] ?? '' ) && $slug === ( $item['slug'] ?? '' ) ) {
				return true;
			}
		}

		return false;
	}
}
