<?php
/**
 * Fix for "Some plugin data can be read by anyone without signing in"
 * (#1870): require sign-in for a route the owner picks.
 *
 * Nothing is closed by default, and nothing is closed on a guess. A route the
 * owner picks is watched first, for a week: how many requests reach it from
 * somebody not signed in, and from which sites (the host of the page that
 * asked, never the visitor). Then the owner closes it, or reopens it. Closed,
 * a caller who is not signed in gets WordPress's own refusal, `rest_forbidden`
 * with 401, on that route and nothing else; signed-in callers are not touched.
 *
 * Only a route the survey finds answering anybody can be picked, and never
 * WordPress's own, the store's checkout routes, or this plugin's: those are
 * open because the front end, a shopper or a caller holding nothing has to
 * reach them. Each picked route has its own undo record, written before
 * anything changes, and every change is in the activity log.
 *
 * Closing is a protection like any other, so it pauses under safe mode.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\RestSurface;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RestRoutes {

	/** autoload=false: read on REST requests and this plugin's screens only. */
	public const OPTION = 'bettershield_rest_routes';

	public const ACTION = 'rest_route_guarded';

	/** How long a route is watched before it may be closed. */
	public const WATCH_FOR = 7 * DAY_IN_SECONDS;

	/** At most this many sites are kept per route; the rest count as one. */
	private const ORIGINS = 10;

	/**
	 * Namespaces never offered: WordPress's own (its `wp-*` namespaces and
	 * batch among them), the store's checkout, and this plugin's and its
	 * add-on's, each open on purpose. The index itself is never offered.
	 */
	private const NEVER = array( 'wp/', 'wp-', 'batch/', 'wc/store', 'bettershield/', 'bettershield-ultra/', 'oembed/' );

	/**
	 * Requests seen on this request, counted when it ends: one write for the
	 * request, not one per route matched.
	 *
	 * @var array<string, string>
	 */
	private static array $seen = array();

	public static function register(): void {
		add_filter( 'rest_pre_dispatch', array( self::class, 'gate' ), 5, 3 );
	}

	/**
	 * The routes picked, by route.
	 *
	 * @return array<string, array{state: string, since: int, requests: int, origins: array<string, int>, undo: string}>
	 */
	public static function picked(): array {
		$stored = get_option( self::OPTION, array() );
		$out    = array();

		foreach ( is_array( $stored ) ? $stored : array() as $route => $entry ) {
			if ( ! is_string( $route ) || ! is_array( $entry ) || ! in_array( $entry['state'] ?? '', array( 'watching', 'closed' ), true ) ) {
				continue;
			}

			$out[ $route ] = array(
				'state'    => (string) $entry['state'],
				'since'    => (int) ( $entry['since'] ?? 0 ),
				'requests' => (int) ( $entry['requests'] ?? 0 ),
				'origins'  => array_map( 'intval', array_filter( (array) ( $entry['origins'] ?? array() ), 'is_numeric' ) ),
				'undo'     => (string) ( $entry['undo'] ?? '' ),
			);
		}

		return $out;
	}

	/**
	 * What the finding's panel shows: each route it names, with what was
	 * seen on it and whether it may be closed yet.
	 *
	 * @param string[] $routes The routes the finding names.
	 * @return array<int, array{route: string, state: string, requests: int, origins: array<string, int>, closable_at: string, undo: string, offered: bool}>
	 */
	public static function describe( array $routes ): array {
		$picked = self::picked();
		$out    = array();

		foreach ( array_values( array_unique( array_merge( array_map( 'strval', $routes ), array_keys( $picked ) ) ) ) as $route ) {
			$entry = $picked[ $route ] ?? null;

			$out[] = array(
				'route'       => $route,
				'state'       => null === $entry ? 'open' : $entry['state'],
				'requests'    => null === $entry ? 0 : $entry['requests'],
				'origins'     => null === $entry ? array() : $entry['origins'],
				'closable_at' => null === $entry ? '' : gmdate( 'c', $entry['since'] + self::WATCH_FOR ),
				'undo'        => null === $entry ? '' : $entry['undo'],
				'offered'     => self::offerable( $route ),
			);
		}

		return $out;
	}

	/** Whether a route is one this may watch and close at all. */
	private static function offerable( string $route ): bool {
		$path = ltrim( $route, '/' );

		if ( '' === $path ) {
			return false;
		}

		foreach ( self::NEVER as $prefix ) {
			if ( str_starts_with( $path, $prefix ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Start watching a route, its undo record first.
	 *
	 * @return array{route: string, undo: string}|\WP_Error
	 */
	public static function watch( string $route ) {
		if ( isset( self::picked()[ $route ] ) ) {
			return new \WP_Error( 'bettershield_route_picked', __( 'That address is already being watched or closed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! self::offerable( $route ) || ! RestSurface::answers_anyone( $route ) ) {
			return new \WP_Error( 'bettershield_route_not_offered', __( 'That address does not answer anyone who asks, or is one BetterShield leaves open, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$token = Ledger::open( self::ACTION, array( 'route' => $route, 'state' => 'open' ), array( 'route' => $route ) );

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::put(
			$route,
			array(
				'state'    => 'watching',
				'since'    => time(),
				'requests' => 0,
				'origins'  => array(),
				'undo'     => $token,
			)
		);

		self::record( 'rest_route_watched', $route );

		return array(
			'route' => $route,
			'undo'  => $token,
		);
	}

	/**
	 * Require sign-in for a watched route, once it has been watched a week.
	 *
	 * @return array{route: string}|\WP_Error
	 */
	public static function close( string $route ) {
		$entry = self::picked()[ $route ] ?? null;

		if ( null === $entry || 'watching' !== $entry['state'] ) {
			return new \WP_Error( 'bettershield_route_not_watched', __( 'That address is not being watched, so it cannot be closed yet.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( time() < $entry['since'] + self::WATCH_FOR ) {
			return new \WP_Error( 'bettershield_route_watching', __( 'That address is watched for a week before it can be closed, so you can see who reads it first.', 'bettershield' ), array( 'status' => 409 ) );
		}

		self::put( $route, array( 'state' => 'closed' ) + $entry );
		self::record( 'rest_route_closed', $route );
		// The check reads the closed routes, so the finding follows now.
		Auditor::run();

		return array( 'route' => $route );
	}

	/**
	 * Open a watched or closed route again, by its undo record.
	 *
	 * @return array{route: string}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$route  = (string) ( ( is_array( $entry->prior_state ) ? $entry->prior_state : array() )['route'] ?? '' );
		$picked = self::picked();

		if ( '' === $route || ! isset( $picked[ $route ] ) || $picked[ $route ]['undo'] !== $token ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		unset( $picked[ $route ] );
		update_option( self::OPTION, $picked, false );
		Ledger::mark_reverted( $token );

		self::record( 'rest_route_reopened', $route );
		Auditor::run();

		return array( 'route' => $route );
	}

	/** The routes closed now. @return string[] */
	public static function closed(): array {
		return array_keys( array_filter( self::picked(), static fn( array $entry ): bool => 'closed' === $entry['state'] ) );
	}

	/**
	 * The routes the finding names now, as its check reads the last survey.
	 *
	 * @return string[]
	 */
	public static function named(): array {
		$finding = \BetterShield\Audit\Checks::all()['rest_surface_unreviewed']['test']();
		$routes  = array();

		foreach ( is_array( $finding ) ? (array) ( $finding['namespaces'] ?? array() ) : array() as $namespace ) {
			$routes = array_merge( $routes, array_map( 'strval', (array) ( $namespace['routes'] ?? array() ) ) );
		}

		return $routes;
	}

	/**
	 * The routes still watched or closed, for the list of fixes that outlive
	 * their finding.
	 *
	 * @return array<int, array{route: string, state: string, undo: string}>
	 */
	public static function open_changes(): array {
		$out = array();

		foreach ( self::picked() as $route => $entry ) {
			$out[] = array(
				'route' => $route,
				'state' => $entry['state'],
				'undo'  => $entry['undo'],
			);
		}

		return $out;
	}

	/**
	 * Before WordPress answers a REST request: count a request to a watched
	 * route from somebody not signed in, and refuse one to a closed route.
	 *
	 * @param mixed            $result  What answers instead, if anything has.
	 * @param \WP_REST_Server  $server  The server.
	 * @param \WP_REST_Request $request The request.
	 * @return mixed
	 */
	public static function gate( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof \WP_REST_Request ) {
			return $result;
		}

		$picked = self::picked();

		if ( array() === $picked || is_user_logged_in() || \BetterShield\Recovery\SafeMode::is_active() ) {
			return $result;
		}

		$path = (string) $request->get_route();

		foreach ( $picked as $route => $entry ) {
			if ( 1 !== preg_match( '@^' . $route . '$@i', $path ) ) {
				continue;
			}

			if ( 'closed' === $entry['state'] ) {
				// A response, not the error itself: inside a batch, core hands
				// what this returns to filters that take only a response.
				return rest_convert_error_to_response( new \WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to do that.', 'bettershield' ), array( 'status' => rest_authorization_required_code() ) ) );
			}

			if ( array() === self::$seen ) {
				add_action( 'shutdown', array( self::class, 'count' ) );
			}

			self::$seen[ $route ] = self::origin_of( $request );
		}

		return $result;
	}

	/**
	 * The site a request was made from: the host of its Origin, or of its
	 * Referer, or '' for a request that names neither.
	 */
	private static function origin_of( \WP_REST_Request $request ): string {
		foreach ( array( 'origin', 'referer' ) as $header ) {
			$host = wp_parse_url( (string) $request->get_header( $header ), PHP_URL_HOST );

			if ( is_string( $host ) && '' !== $host ) {
				return strtolower( $host );
			}
		}

		return '';
	}

	/** At the end of the request, what was seen on it, in one write. */
	public static function count(): void {
		$picked = self::picked();

		foreach ( self::$seen as $route => $origin ) {
			if ( ! isset( $picked[ $route ] ) || 'watching' !== $picked[ $route ]['state'] ) {
				continue;
			}

			++$picked[ $route ]['requests'];

			$key     = '' === $origin ? __( 'No site named', 'bettershield' ) : $origin;
			$origins = $picked[ $route ]['origins'];

			if ( ! isset( $origins[ $key ] ) && count( $origins ) >= self::ORIGINS ) {
				$key = __( 'Other sites', 'bettershield' );
			}

			$origins[ $key ]              = ( $origins[ $key ] ?? 0 ) + 1;
			$picked[ $route ]['origins'] = $origins;
		}

		self::$seen = array();
		update_option( self::OPTION, $picked, false );
	}

	/**
	 * @param array<string, mixed> $entry
	 */
	private static function put( string $route, array $entry ): void {
		$picked           = self::picked();
		$picked[ $route ] = $entry;

		update_option( self::OPTION, $picked, false );
	}

	private static function record( string $type, string $route ): void {
		Writer::instance()->record(
			$type,
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'rest_route',
				'object_id'   => $route,
			)
		);
	}
}
