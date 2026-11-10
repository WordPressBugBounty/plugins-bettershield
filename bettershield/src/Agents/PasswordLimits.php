<?php
/**
 * An application password held to the routes and the addresses it is for.
 *
 * WordPress lets an application password do everything its account can, from
 * anywhere. As assistants and integrations sign in with them, one that leaks
 * is the whole account. The owner can bind one to the REST routes it is used
 * for, to the network it is used from, or both, and a request outside either
 * is refused with a sentence that says why, and recorded.
 *
 * Held against the password's own id, on its account, so the limit goes with
 * the password: revoked, it is gone; renamed, it stands. Every change is
 * written to the undo ledger first, and the undo puts back exactly what was
 * there. The recovery link and signing in with a password are untouched,
 * because application passwords are not how anybody gets back in.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Events\Coalescer;
use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Support\ClientIp;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasswordLimits {

	/** Where each account keeps its passwords' limits, by password id. */
	public const META = 'bettershield_app_password_limits';

	/** The undo record a change to a limit writes. */
	public const UNDO = 'app_password_limit';

	/** How many route prefixes one password may be held to. */
	public const MAX_ROUTES = 10;

	/** The code a refused request carries. */
	public const REFUSED = 'bettershield_app_password_limited';

	/** This request's refusal, to answer it with once the route is known. */
	private static ?\WP_Error $refusal = null;

	public function register(): void {
		add_filter( 'wp_authenticate_application_password_errors', array( $this, 'check' ), 10, 3 );
		add_action( 'wp_delete_application_password', array( $this, 'forget' ), 10, 2 );
	}

	/**
	 * A revoked password's limit goes with it: there is nothing left for it
	 * to hold, and a new password must not inherit it by accident.
	 *
	 * @param mixed $user_id
	 * @param mixed $item
	 */
	public function forget( $user_id, $item = array() ): void {
		$uuid   = is_array( $item ) ? (string) ( $item['uuid'] ?? '' ) : '';
		$stored = get_user_meta( (int) $user_id, self::META, true );

		if ( '' === $uuid || ! is_array( $stored ) || ! isset( $stored[ $uuid ] ) ) {
			return;
		}

		unset( $stored[ $uuid ] );
		self::store( (int) $user_id, $stored );
	}

	/**
	 * Refuse a request outside the password's limit, before it is signed in.
	 *
	 * @param mixed                $errors What the check has found so far.
	 * @param mixed                $user   The account the password belongs to.
	 * @param array<string, mixed> $item   The password, as core stores it.
	 * @return mixed
	 */
	public function check( $errors, $user = null, $item = array() ) {
		if ( ! $errors instanceof \WP_Error || ! $user instanceof \WP_User || ! is_array( $item ) ) {
			return $errors;
		}

		/*
		 * Never the decoy. Its alarm runs on application_password_did_authenticate,
		 * which core fires only when the errors collected here are empty, so a
		 * refusal here was a use of the decoy nobody was told about. Any use
		 * of it is the alarm, from anywhere, including under a limit saved
		 * before set() refused one.
		 */
		if ( Canary::is_decoy( $item, (int) $user->ID ) ) {
			return $errors;
		}

		$limit = self::get( (int) $user->ID, (string) ( $item['uuid'] ?? '' ) );

		if ( null === $limit ) {
			return $errors;
		}

		$route    = self::current_route();
		$settings = Protection::instance()->settings();
		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );
		$reason   = '';

		if ( array() !== $limit['routes'] && ! self::route_allowed( $route, $limit['routes'] ) ) {
			$reason = 'route';
		} elseif ( '' !== $limit['range'] && ( '' === $resolved['ip'] || ! ClientIp::in_ranges( $resolved['ip'], array( $limit['range'] ) ) ) ) {
			$reason = 'address';
		}

		if ( '' === $reason ) {
			return $errors;
		}

		$message = 'route' === $reason
			? __( 'This application password is limited to other REST API routes, so this request was refused.', 'bettershield' )
			: __( 'This application password is limited to another network, so this request was refused.', 'bettershield' );

		$errors->add( self::REFUSED, $message, array( 'status' => 403 ) );

		/*
		 * Asked before WordPress has parsed the request. A plugin that lets
		 * application passwords sign in to more than the API makes core ask
		 * while it starts up, when no route is known yet. Nothing is allowed
		 * on a route nobody knows, but nothing is decided either: core
		 * forgets that early "nobody" before it serves a REST request and
		 * asks again with the route parsed, and that answer is the one given
		 * and recorded. XML-RPC signs in through authenticate and never
		 * parses a request, so it is decided here as it is.
		 */
		if ( 'route' === $reason && '' === $route && ! did_action( 'parse_request' ) && ! doing_filter( 'authenticate' ) && ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			add_action( 'parse_request', array( self::class, 'forget_early_refusal' ), 9 );

			return $errors;
		}

		/*
		 * The request is answered with this sentence rather than as a
		 * stranger's. WordPress settles who a REST request is lazily, often
		 * after it has looked for authentication errors, so the refusal is
		 * kept and given as the answer before the route runs.
		 */
		self::$refusal = new \WP_Error( self::REFUSED, $message, array( 'status' => 403 ) );
		add_filter( 'rest_pre_dispatch', array( self::class, 'answer' ), 1 );

		/*
		 * Every request is refused; the row is written once an hour per
		 * password and network, and the next one says how many it stands for.
		 * Somebody holding a leaked, limited password could otherwise fill the
		 * log with the same row and push real events out of "Since you last
		 * looked". Keyed on the connection, as a failed sign-in is.
		 */
		$suppressed = Coalescer::admit( 'bettershield_pwlimit_' . md5( (string) ( $item['uuid'] ?? '' ) . '|' . ClientIp::hmac( ClientIp::volume_source( $resolved ) ) ), HOUR_IN_SECONDS );

		if ( null === $suppressed ) {
			return $errors;
		}

		Writer::instance()->record(
			'app_password_refused',
			Writer::SEVERITY_MEDIUM,
			array(
				/*
				 * Named rather than looked up. This runs while WordPress is
				 * still deciding who the request is, and asking it would
				 * ask for this same check again, and again.
				 */
				'actor_type'  => 'system',
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array(
					'password' => (string) ( $item['name'] ?? '' ),
					'reason'   => $reason,
					'route'    => substr( $route, 0, 120 ),
				) + ( $suppressed > 0 ? array( 'unlogged_attempts' => $suppressed ) : array() ),
			)
		);

		return $errors;
	}

	/**
	 * Forget a refusal given before the route was known, once it is.
	 *
	 * Core keeps the first answer an application password got and gives it
	 * to a REST request before it asks again, so the early refusal would
	 * stand for a route the password may use. Forgotten only where nothing
	 * on this request was decided, and before the REST API is served.
	 */
	public static function forget_early_refusal(): void {
		$status = $GLOBALS['wp_rest_application_password_status'] ?? null;

		if ( null === self::$refusal && $status instanceof \WP_Error && self::REFUSED === $status->get_error_code() ) {
			$GLOBALS['wp_rest_application_password_status'] = null; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- core's own global, reset on purpose.
			$GLOBALS['wp_rest_application_password_uuid']   = null; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- core's own global, reset on purpose.
		}
	}

	/**
	 * Answer a refused request with its refusal, whatever else was going to
	 * answer it.
	 *
	 * @param mixed $result
	 * @return mixed
	 */
	public static function answer( $result ) {
		return null !== self::$refusal ? self::$refusal : $result;
	}

	/**
	 * One password's limit, or null when it has none.
	 *
	 * @return array{routes: string[], range: string, set_at: int}|null
	 */
	public static function get( int $user_id, string $uuid ): ?array {
		$all = self::all_for( $user_id );

		return $all[ $uuid ] ?? null;
	}

	/**
	 * Every limit on one account's passwords, by password id.
	 *
	 * @return array<string, array{routes: string[], range: string, set_at: int}>
	 */
	public static function all_for( int $user_id ): array {
		$stored = get_user_meta( $user_id, self::META, true );
		$out    = array();

		foreach ( is_array( $stored ) ? $stored : array() as $uuid => $limit ) {
			if ( ! is_string( $uuid ) || ! is_array( $limit ) ) {
				continue;
			}

			$routes = array_values( array_filter( array_map( 'strval', (array) ( $limit['routes'] ?? array() ) ) ) );
			$range  = (string) ( $limit['range'] ?? '' );

			if ( array() === $routes && '' === $range ) {
				continue;
			}

			$out[ $uuid ] = array(
				'routes' => $routes,
				'range'  => $range,
				'set_at' => (int) ( $limit['set_at'] ?? 0 ),
			);
		}

		return $out;
	}

	/**
	 * Hold a password to route prefixes, a range, or both.
	 *
	 * @param mixed $routes Route prefixes, as a list or one string of them.
	 * @return array{limit: array<string, mixed>, undo: string}|\WP_Error
	 */
	public static function set( int $user_id, string $uuid, $routes, string $range ) {
		$exists = self::password( $user_id, $uuid );

		if ( is_wp_error( $exists ) ) {
			return $exists;
		}

		if ( Canary::is_decoy( $exists, $user_id ) ) {
			return new \WP_Error(
				'bettershield_decoy_unlimited',
				__( 'The decoy cannot be limited: every use must trigger an alert.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$clean = self::clean( $routes, $range );

		if ( is_wp_error( $clean ) ) {
			return $clean;
		}

		$wider = self::widens( $user_id, $uuid, $clean['routes'], $clean['range'] );
		$limit = array_merge( $clean, array( 'set_at' => time() ) );
		$undo  = self::write( $user_id, $uuid, $limit );

		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		Writer::instance()->record(
			'app_password_limited',
			// Widening one lets it reach what it was kept from, as removing it does.
			$wider ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_LOW,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'password' => (string) ( $exists['name'] ?? '' ),
					'routes'   => $clean['routes'],
					'range'    => $clean['range'],
					'widened'  => $wider,
					'undo'     => $undo,
				),
			)
		);

		return array(
			'limit' => $limit,
			'undo'  => $undo,
		);
	}

	/**
	 * Take a password's limit away.
	 *
	 * @return array{undo: string}|\WP_Error
	 */
	public static function remove( int $user_id, string $uuid ) {
		if ( null === self::get( $user_id, $uuid ) ) {
			return new \WP_Error( 'bettershield_no_limit', __( 'That application password has no limit to take away.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$exists = self::password( $user_id, $uuid );
		$undo   = self::write( $user_id, $uuid, null );

		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		Writer::instance()->record(
			'app_password_unlimited',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'password' => is_array( $exists ) ? (string) ( $exists['name'] ?? '' ) : '',
					'undo'     => $undo,
				),
			)
		);

		return array( 'undo' => $undo );
	}

	/**
	 * The account a recorded change to a limit was made on, or 0 where there
	 * is no such change on record.
	 */
	public static function undo_account( string $token ): int {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::UNDO !== (string) $entry->action_key ) {
			return 0;
		}

		$prior = is_array( $entry->prior_state ) ? $entry->prior_state : array();

		return (int) ( $prior['user_id'] ?? 0 );
	}

	/**
	 * Put a password's limit back exactly as it was before a change.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::UNDO !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'There is no such change on record.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$user_id = (int) ( $prior['user_id'] ?? 0 );
		$uuid    = (string) ( $prior['uuid'] ?? '' );
		$stored  = get_user_meta( $user_id, self::META, true );
		$stored  = is_array( $stored ) ? $stored : array();

		if ( is_array( $prior['limit'] ?? null ) ) {
			$stored[ $uuid ] = $prior['limit'];
		} else {
			unset( $stored[ $uuid ] );
		}

		self::store( $user_id, $stored );
		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			is_array( $prior['limit'] ?? null ) ? 'app_password_limited' : 'app_password_unlimited',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array( 'undone' => $token ),
			)
		);

		return true;
	}

	/**
	 * Route prefixes and a range as they are kept, or the reason they cannot
	 * be.
	 *
	 * A prefix is a REST route as the API names it, starting with a slash; one
	 * written with the API's own address in front (`/wp-json/...`) is taken
	 * as the route it names. A range is an address or a CIDR range no wider
	 * than the allowlist accepts.
	 *
	 * @param mixed $routes
	 * @return array{routes: string[], range: string}|\WP_Error
	 */
	public static function clean( $routes, string $range ) {
		$list = is_array( $routes ) ? $routes : preg_split( '/[\s,]+/', (string) $routes );
		$out  = array();
		$api  = '/' . trim( rest_get_url_prefix(), '/' ) . '/';

		foreach ( (array) $list as $route ) {
			$route = trim( (string) $route );

			if ( '' === $route ) {
				continue;
			}

			if ( 0 === strpos( $route, $api ) ) {
				$route = '/' . substr( $route, strlen( $api ) );
			}

			if ( 1 !== preg_match( '#^/[A-Za-z0-9_\-./]*$#', $route ) || str_contains( $route, '..' ) ) {
				return new \WP_Error(
					'bettershield_bad_route',
					/* translators: %s: what was typed. */
					sprintf( __( '"%s" is not a REST route. Start with a slash, like /bettershield/v1/.', 'bettershield' ), $route ),
					array( 'status' => 400 )
				);
			}

			// Prefixes match from the start, so "/" (or the API's own root)
			// matches every route and limits nothing, as an unrestricted
			// range would (#2662).
			if ( '' === trim( $route, '/.' ) ) {
				return new \WP_Error(
					'bettershield_route_everything',
					__( 'A limit to "/" allows every route. Name a route, like /wp/v2/posts/.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$out[] = $route;
		}

		$out   = array_values( array_unique( $out ) );
		$range = trim( $range );

		if ( count( $out ) > self::MAX_ROUTES ) {
			/* translators: %d: the most route prefixes allowed. */
			return new \WP_Error( 'bettershield_too_many_routes', sprintf( __( 'Up to %d route prefixes can be set.', 'bettershield' ), self::MAX_ROUTES ), array( 'status' => 400 ) );
		}

		if ( '' !== $range ) {
			$wide = str_contains( $range, '/' ) && (int) substr( $range, strpos( $range, '/' ) + 1 ) < ( str_contains( $range, ':' ) ? 32 : 8 );

			// Well formed but too wide to limit anything: said as such,
			// not as a range that could not be read (#2662).
			if ( ClientIp::valid_range( $range ) && $wide ) {
				return new \WP_Error(
					'bettershield_wide_range',
					/* translators: %s: what was typed. */
					sprintf( __( '"%s" is wider than a limit can use. The widest is /8 for IPv4 and /32 for IPv6.', 'bettershield' ), $range ),
					array( 'status' => 400 )
				);
			}

			if ( ! ClientIp::valid_range( $range ) ) {
				return new \WP_Error(
					'bettershield_bad_range',
					/* translators: %s: what was typed. */
					sprintf( __( '"%s" cannot be used. Use one address, or a range like 203.0.113.0/24.', 'bettershield' ), $range ),
					array( 'status' => 400 )
				);
			}
		}

		if ( array() === $out && '' === $range ) {
			return new \WP_Error( 'bettershield_empty_limit', __( 'Name at least one route prefix or address range, or remove the limit.', 'bettershield' ), array( 'status' => 400 ) );
		}

		return array(
			'routes' => $out,
			'range'  => $range,
		);
	}

	/**
	 * Whether holding a password to these would let it reach anything its
	 * limit now keeps it from.
	 *
	 * That is taking a protection away, the same as removing the limit, so it
	 * is a person's to do rather than a token's. A password with no limit
	 * reaches everything, so a first limit only narrows it. What cannot be
	 * read as a limit is taken as widening.
	 *
	 * @param mixed $routes Route prefixes, as a list or one string of them.
	 */
	public static function widens( int $user_id, string $uuid, $routes, string $range ): bool {
		$held = self::get( $user_id, $uuid );

		if ( null === $held ) {
			return false;
		}

		$asked = self::clean( $routes, $range );

		if ( is_wp_error( $asked ) ) {
			return true;
		}

		return ! self::routes_within( $asked['routes'], $held['routes'] ) || ! self::range_within( $asked['range'], $held['range'] );
	}

	/**
	 * Whether every route the inner prefixes allow, the outer ones allow too.
	 * No prefixes at all allow every route.
	 *
	 * @param string[] $inner
	 * @param string[] $outer
	 */
	private static function routes_within( array $inner, array $outer ): bool {
		if ( array() === $outer ) {
			return true;
		}

		if ( array() === $inner ) {
			return false;
		}

		foreach ( $inner as $prefix ) {
			if ( ! self::route_allowed( $prefix, $outer ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether every address the inner range holds, the outer one holds too.
	 * No range at all holds every address.
	 *
	 * Compared as written, family by family: a range in one family is never
	 * inside one in the other, even where an address in it can be read as an
	 * address in the other. That only ever reads a narrowing as a widening.
	 */
	private static function range_within( string $inner, string $outer ): bool {
		if ( '' === $outer ) {
			return true;
		}

		$in  = self::span( $inner );
		$out = self::span( $outer );

		return null !== $in
			&& null !== $out
			&& $in['bytes'] === $out['bytes']
			&& $in['bits'] >= $out['bits']
			&& ClientIp::in_ranges( $in['base'], array( $outer ) );
	}

	/**
	 * A range's first address, its family's width in bytes, and how many of
	 * its leading bits are fixed; a bare address fixes all of them.
	 *
	 * @return array{base: string, bytes: int, bits: int}|null
	 */
	private static function span( string $range ): ?array {
		$parts  = explode( '/', trim( $range ), 2 );
		$packed = '' === $parts[0] ? false : @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input answers null, not a warning.

		if ( false === $packed ) {
			return null;
		}

		return array(
			'base'  => $parts[0],
			'bytes' => strlen( $packed ),
			'bits'  => isset( $parts[1] ) ? (int) $parts[1] : strlen( $packed ) * 8,
		);
	}

	/**
	 * Whether a route falls under one of the prefixes.
	 *
	 * @param string[] $prefixes
	 */
	public static function route_allowed( string $route, array $prefixes ): bool {
		if ( '' === $route ) {
			return false;
		}

		foreach ( $prefixes as $prefix ) {
			if ( 0 === strpos( $route, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The REST route this request is for, or '' where it is not a REST
	 * request at all, which no route prefix covers.
	 *
	 * Read only where core reads the route it serves: the parsed `rest_route`,
	 * which it requires to be a string before it defines REST_REQUEST. Never
	 * from the query string or the address as written. XML-RPC never parses
	 * a request and ignores both, and an address the server resolves to
	 * another file keeps its raw spelling there, so either would name a route
	 * nothing is going to run.
	 */
	public static function current_route(): string {
		global $wp;

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return '';
		}

		$route = isset( $wp ) && is_object( $wp ) ? ( $wp->query_vars['rest_route'] ?? '' ) : '';

		return is_string( $route ) && '' !== $route ? '/' . ltrim( $route, '/' ) : '';
	}

	/**
	 * The password, as core keeps it, or a refusal where the account holds
	 * no such password.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function password( int $user_id, string $uuid ) {
		$item = class_exists( 'WP_Application_Passwords' ) ? \WP_Application_Passwords::get_user_application_password( $user_id, $uuid ) : null;

		return is_array( $item ) ? $item : new \WP_Error( 'bettershield_unknown_password', __( 'That account holds no such application password.', 'bettershield' ), array( 'status' => 404 ) );
	}

	/**
	 * Change one password's limit, with the undo record written first.
	 *
	 * @param array<string, mixed>|null $limit
	 * @return string|\WP_Error The undo token.
	 */
	private static function write( int $user_id, string $uuid, ?array $limit ) {
		$stored = get_user_meta( $user_id, self::META, true );
		$stored = is_array( $stored ) ? $stored : array();

		$token = Ledger::open(
			self::UNDO,
			array(
				'user_id' => $user_id,
				'uuid'    => $uuid,
				'limit'   => $stored[ $uuid ] ?? null,
			),
			array(
				'user_id' => $user_id,
				'uuid'    => $uuid,
				'limit'   => $limit,
			)
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		if ( null === $limit ) {
			unset( $stored[ $uuid ] );
		} else {
			$stored[ $uuid ] = $limit;
		}

		self::store( $user_id, $stored );

		return $token;
	}

	/** @param array<string, mixed> $stored */
	private static function store( int $user_id, array $stored ): void {
		if ( array() === $stored ) {
			delete_user_meta( $user_id, self::META );
		} else {
			update_user_meta( $user_id, self::META, $stored );
		}
	}
}
