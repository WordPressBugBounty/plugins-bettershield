<?php
/**
 * What this site's REST API answers to somebody who is not signed in.
 *
 * User enumeration is the best-known leak and it is one route out of many. A
 * typical install answers an anonymous caller with posts, pages, media,
 * comments, taxonomies, settings for some plugins, and whatever every other
 * installed plugin registered without thinking about who could read it — and
 * nothing anywhere tells the owner which those are.
 *
 * **This reports; it does not close.** Most of what is open is open on
 * purpose: a headless front end, an app, a block editor. Closing routes on a
 * guess would break sites, so this names what answers and leaves the judgment
 * with the person who knows what their site is for. A route the owner picks
 * is closed by `Fixes\RestRoutes`, after a week of watching who reads it
 * (#1870); nothing here closes anything.
 *
 * The probe asks each route's own `permission_callback` with nobody signed in,
 * building the request the way `WP_REST_Server::dispatch()` builds it so the
 * callback is asked the same question the server asks. It never dispatches the
 * route, so nothing is created, changed or counted by looking.
 *
 * A route whose path carries a value — a post id, a term slug — has no honest
 * request to build, so it is reported as a third state rather than guessed at.
 *
 * **Asked once a day, never on a request.** Surveying the whole installation
 * means running every other plugin's permission callback and swapping the
 * signed-in user out and back to do it, which fires `set_current_user` twice
 * for every listener on the site. That is not work a dashboard request may ask
 * for, so the answer is stored with the day it was taken and every reader gets
 * that — the same shape the certificate and the exposed-artifact probe use.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RestSurface {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_rest_surface';

	/**
	 * Namespaces whose openness is a WordPress fact rather than this site's
	 * decision, and which say nothing an owner can act on.
	 */
	private const UNINTERESTING = array( 'oembed/1.0' );

	private const OPEN         = 'open';
	private const CLOSED       = 'closed';
	private const UNDETERMINED = 'undetermined';

	/**
	 * Look now, and store what was found. Called by the daily task.
	 *
	 * Only what the finding reads is kept. The per-namespace counters the
	 * report computes are how the probe proves it kept measurement and
	 * assumption apart; they are not what an owner is shown, and storing them
	 * would be a second copy of a number nothing reads.
	 *
	 * @return array{checked_at: string, namespaces: array<string, array{open: int, notable: string[]}>}
	 */
	public static function refresh(): array {
		$kept = array();

		foreach ( self::report()['namespaces'] as $namespace => $counts ) {
			$kept[ (string) $namespace ] = array(
				'open'    => (int) $counts['open'],
				'notable' => (array) $counts['notable'],
			);
		}

		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'namespaces' => $kept,
		);

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
	 * Whether a stranger's read of this registered route is let through now:
	 * asked of its own read handlers as nobody, as the daily survey asks. A
	 * route whose path carries a value is not knowable, and not open here.
	 */
	public static function answers_anyone( string $route ): bool {
		$handlers = rest_get_server()->get_routes()[ $route ] ?? null;

		if ( ! is_array( $handlers ) ) {
			return false;
		}

		$was = get_current_user_id();
		wp_set_current_user( 0 );

		try {
			foreach ( $handlers as $handler ) {
				$methods = array_keys( array_filter( (array) ( $handler['methods'] ?? array() ) ) );

				if ( in_array( 'GET', $methods, true ) && self::OPEN === self::verdict_for( $route, (array) $handler ) ) {
					return true;
				}
			}
		} finally {
			wp_set_current_user( $was );
		}

		return false;
	}

	/**
	 * What a stranger can read, grouped by namespace.
	 *
	 * `total` counts the routes this could answer for, and `open` is how many
	 * of those answer a stranger. Routes it could not answer for are counted
	 * separately as `undetermined` and left out of both, so the ratio stays a
	 * measurement rather than a mix of what was read and what was assumed.
	 *
	 * @return array{namespaces: array<string, array{open: int, total: int, undetermined: int, notable: string[]}>}
	 */
	public static function report(): array {
		$server = rest_get_server();
		$routes = $server->get_routes();

		$namespaces = array();

		// Whoever is signed in must not change what this reports, so the
		// probe runs as nobody and the previous user is put back after.
		$was = get_current_user_id();
		wp_set_current_user( 0 );

		try {
			foreach ( $routes as $route => $handlers ) {
				$namespace = self::namespace_of( (string) $route );

				if ( '' === $namespace || in_array( $namespace, self::UNINTERESTING, true ) ) {
					continue;
				}

				/*
				 * The namespace index itself. Core registers one for every
				 * namespace, open to anybody, and it lists routes rather than
				 * answering with anything from the site. Counting it would put
				 * one unavoidable "open" against every plugin on the site and
				 * teach the reader to ignore the number.
				 */
				if ( trim( (string) $route, '/' ) === $namespace ) {
					continue;
				}

				foreach ( $handlers as $handler ) {
					$methods = array_keys( array_filter( (array) ( $handler['methods'] ?? array() ) ) );

					// Reads only. A write open to anonymous callers is a
					// different and much louder problem, and it is the agent
					// surface report's subject rather than this one's.
					if ( ! in_array( 'GET', $methods, true ) ) {
						continue;
					}

					if ( ! isset( $namespaces[ $namespace ] ) ) {
						$namespaces[ $namespace ] = array(
							'open'         => 0,
							'total'        => 0,
							'undetermined' => 0,
							'notable'      => array(),
						);
					}

					$verdict = self::verdict_for( (string) $route, (array) $handler );

					if ( self::UNDETERMINED === $verdict ) {
						++$namespaces[ $namespace ]['undetermined'];

						continue;
					}

					++$namespaces[ $namespace ]['total'];

					if ( self::OPEN !== $verdict ) {
						continue;
					}

					++$namespaces[ $namespace ]['open'];

					// A handful of names, not the whole list: this is a report
					// somebody reads, not a schema dump.
					if ( count( $namespaces[ $namespace ]['notable'] ) < 5 ) {
						$namespaces[ $namespace ]['notable'][] = (string) $route;
					}
				}
			}
		} finally {
			wp_set_current_user( $was );
		}

		ksort( $namespaces );

		return array( 'namespaces' => $namespaces );
	}

	/**
	 * What one handler would answer a stranger: open, closed, or not knowable.
	 *
	 * Asked of the route's own callback, never by dispatching it, so nothing is
	 * created, changed or counted by looking. Three things make this the same
	 * question the REST server asks rather than a near miss:
	 *
	 * - The request carries the route it belongs to and the handler's own
	 *   attributes, because a callback that reads a parameter has to find in
	 *   the request what a real caller's request would hold.
	 * - Registered defaults are applied before asking, exactly as `dispatch()`
	 *   does. Core's comments controller refuses an anonymous caller unless
	 *   `status` is `approve` — which is that argument's default. A probe that
	 *   skipped defaults saw `null` there, was refused, and reported the
	 *   collection closed while it answered every stranger with 200.
	 * - The answer is read the way the server reads it: `false`, `null` and a
	 *   `WP_Error` are refusals, and anything else lets the caller through.
	 *
	 * A route whose path carries a value has no honest request to build: there
	 * is no id to put in it that is not a guess about this site's content, and
	 * a single-item callback resolves that id before anything else. Asking with
	 * a hole where the id goes is what reported every single-item route closed,
	 * including ones any visitor can read. Those are undetermined instead, and
	 * left out of the counts.
	 *
	 * A callback that throws is reported closed: a route this cannot reason
	 * about must not be announced as a hole on a guess.
	 *
	 * @param array<string, mixed> $handler
	 * @return self::OPEN|self::CLOSED|self::UNDETERMINED
	 */
	private static function verdict_for( string $route, array $handler ): string {
		$callback = $handler['permission_callback'] ?? null;

		/*
		 * No callback at all is core's "everyone", and it warns about it too.
		 * Neither this nor `__return_true` looks at the request, so both are
		 * answered before a missing path value could matter — which keeps the
		 * commonest genuinely open plugin route out of the undetermined pile.
		 */
		if ( null === $callback || '__return_true' === $callback ) {
			return self::OPEN;
		}

		if ( ! is_callable( $callback ) ) {
			return self::CLOSED;
		}

		if ( self::takes_a_value_from_the_path( $route ) ) {
			return self::UNDETERMINED;
		}

		try {
			$verdict = call_user_func( $callback, self::request_for( $route, $handler ) );
		} catch ( \Throwable $e ) {
			return self::CLOSED;
		}

		if ( false === $verdict || null === $verdict || is_wp_error( $verdict ) ) {
			return self::CLOSED;
		}

		return self::OPEN;
	}

	/**
	 * The request the REST server would have built before asking.
	 *
	 * `set_attributes()` alone does not apply defaults: `dispatch()` reads them
	 * out of the handler's `args` and sets them in a separate step, and this
	 * mirrors that step rather than calling `sanitize_params()` — which would
	 * run every registered sanitize callback on a site the report is only
	 * supposed to be looking at.
	 *
	 * @param array<string, mixed> $handler
	 */
	private static function request_for( string $route, array $handler ): \WP_REST_Request {
		$request = new \WP_REST_Request( 'GET', $route );
		$request->set_attributes( $handler );

		$defaults = array();
		$args     = isset( $handler['args'] ) && is_array( $handler['args'] ) ? $handler['args'] : array();

		foreach ( $args as $name => $options ) {
			// `isset` rather than `array_key_exists`, because that is what the
			// server uses — an argument declared with a null default gets no
			// default there either.
			if ( is_array( $options ) && isset( $options['default'] ) ) {
				$defaults[ (string) $name ] = $options['default'];
			}
		}

		$request->set_default_params( $defaults );

		return $request;
	}

	/**
	 * Whether the route's path holds a value rather than being a fixed address.
	 *
	 * Routes are stored as the regular expression the server matches a URL
	 * against, so a capture group anywhere in one means part of the path is
	 * filled in by the caller — `/wp/v2/posts/(?P<id>[\d]+)`.
	 */
	private static function takes_a_value_from_the_path( string $route ): bool {
		return false !== strpos( $route, '(' );
	}

	private static function namespace_of( string $route ): string {
		$parts = array_values( array_filter( explode( '/', $route ) ) );

		if ( count( $parts ) < 2 ) {
			return '';
		}

		return $parts[0] . '/' . $parts[1];
	}
}
