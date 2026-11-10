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
 * Read, never called: the REST routes are walked for the shapes an MCP
 * server takes (a path segment named mcp, a streamable or SSE transport
 * beside one, a protected-resource document), each is attributed to the
 * plugin its callback lives in, and a route whose permission callback is
 * missing, `__return_true`, or answers yes to a caller nobody signed in as
 * is said to accept calls without signing in. The permission callback is
 * asked, as core asks it on every request; the endpoint itself never is.
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
	 * @return array<int, array{route: string, owner: string, owner_label: string, open: bool, advisory: bool}>
	 */
	public static function report(): array {
		$server = rest_get_server();
		$found  = array();

		foreach ( $server->get_routes() as $route => $handlers ) {
			$route = (string) $route;

			if ( 1 !== preg_match( self::SHAPE, $route ) || str_starts_with( ltrim( $route, '/' ), 'bettershield/' ) ) {
				continue;
			}

			$owner = '';
			$open  = false;

			foreach ( (array) $handlers as $handler ) {
				if ( ! is_array( $handler ) ) {
					continue;
				}

				if ( '' === $owner ) {
					$owner = self::owner_of( $handler['callback'] ?? null );
				}

				$open = $open || self::answers_anyone( $handler, $route );
			}

			// Core's own routes are not another plugin's door.
			if ( 'wordpress' === $owner ) {
				continue;
			}

			$found[] = array(
				'route'       => $route,
				'owner'       => $owner,
				'owner_label' => '' === $owner ? __( 'Unknown source', 'bettershield' ) : AgentSurface::source_label( $owner ),
				'open'        => $open,
				'advisory'    => '' !== $owner && self::has_advisory( $owner ),
			);
		}

		usort(
			$found,
			static fn( array $a, array $b ): int => array( (int) ! $a['open'], $a['route'] ) <=> array( (int) ! $b['open'], $b['route'] )
		);

		return $found;
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
