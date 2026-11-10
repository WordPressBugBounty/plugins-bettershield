<?php
/**
 * Which accounts a REST request sets a password for, and the passwords.
 *
 * Core's users route and the store's customers route both set passwords
 * through `rest_dispatch_request`, which is where the password checks read
 * them. The store's route also takes a batch, `create` and `update` lists
 * whose passwords sit one level down, one per item, and whose items the
 * store then creates or updates without dispatching again, so this filter
 * is the only chance to see them. Read in one place so that every check
 * covers the same routes the same way.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Password;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RestAccounts {
	/** `/wp/v2/users`, `/wp/v2/users/<id>` and `/wp/v2/users/me`. */
	private const USERS = '#^/wp/v2/users(/|$)#i';

	/** The store's twin of it: `/wc/vN/customers`, `/…/<id>` and `/…/batch`. */
	private const CUSTOMERS = '#^/wc/v[0-9]+/customers(/|$)#i';

	/** The store's batch route, whose items each carry their own password. */
	private const BATCH = '#^/wc/v[0-9]+/customers/batch/?$#i';

	/** Whether a route sets account passwords. */
	public static function covers( string $route ): bool {
		return 1 === preg_match( self::USERS, $route ) || self::is_store_route( $route );
	}

	/** Whether a route is the store's customers route, in any of its forms. */
	public static function is_store_route( string $route ): bool {
		return 1 === preg_match( self::CUSTOMERS, $route );
	}

	/**
	 * Every password the request sets, one entry per account.
	 *
	 * `fields` is where the rest of that account's details are read from: the
	 * request's parameters, or the batch item as the store will read it.
	 * `account` is the existing account the password is for, 0 for one being
	 * created. `item` names the batch item, and is empty outside a batch.
	 *
	 * @return array<int, array{password: string, fields: array<string, mixed>, account: int, item: string}>
	 */
	public static function passwords( \WP_REST_Request $request ): array {
		$route = (string) $request->get_route();

		if ( 1 !== preg_match( self::BATCH, $route ) ) {
			$password = self::password( $request['password'] );

			if ( '' === $password ) {
				return array();
			}

			return array(
				array(
					'password' => $password,
					'fields'   => $request->get_params(),
					'account'  => self::account( $request ),
					'item'     => '',
				),
			);
		}

		/*
		 * The store builds each item it creates as a request of its own: the
		 * item, whatever it is, as the body, and the batch address's
		 * parameters as the query. Read through a request built the same way,
		 * an item's field wins unless it is null, and an item that is not a
		 * set of fields has none, so a `password` in the address is the
		 * password of every created item that does not carry its own, and its
		 * username and email arrive the same way. An update is built from the
		 * item alone.
		 */
		$query = (array) $request->get_query_params();
		$found = array();

		foreach ( array( 'create', 'update' ) as $action ) {
			$items = $request[ $action ];

			if ( ! is_array( $items ) ) {
				continue;
			}

			foreach ( $items as $index => $item ) {
				if ( 'create' === $action ) {
					$item = self::as_created( $route, $item, $query );
				} elseif ( ! is_array( $item ) ) {
					continue;
				}

				$password = self::password( $item['password'] ?? '' );

				if ( '' === $password ) {
					continue;
				}

				$found[] = array(
					'password' => $password,
					'fields'   => $item,
					'account'  => 'update' === $action ? absint( self::text( $item['id'] ?? 0 ) ) : 0,
					'item'     => $action . '[' . $index . ']',
				);
			}
		}

		return $found;
	}

	/**
	 * The fields of a created batch item as the store's sub-request reads
	 * them.
	 *
	 * @param mixed                $item  The item as the batch carried it.
	 * @param array<string, mixed> $query The batch address's parameters.
	 * @return array<string, mixed>
	 */
	private static function as_created( string $route, $item, array $query ): array {
		$created = new \WP_REST_Request( 'POST', $route );
		$created->set_body_params( $item );
		$created->set_query_params( $query );

		$fields = array();

		foreach ( array_keys( $query + ( is_array( $item ) ? $item : array() ) ) as $key ) {
			$value = $created->get_param( (string) $key );

			if ( null !== $value ) {
				$fields[ $key ] = $value;
			}
		}

		return $fields;
	}

	/**
	 * A password as the account will be given it. The store creates and
	 * updates a batch item without the route's schema and hands `true` on to
	 * WordPress, which stores it as "1"; `false`, null and an empty value set
	 * no password there, and an array stops WordPress's hasher before
	 * anything is written.
	 *
	 * @param mixed $value
	 */
	private static function password( $value ): string {
		return true === $value ? '1' : self::text( $value );
	}

	/**
	 * A request value as text, or empty where it is not one. An array cast
	 * to a string is a warning and the word "Array", never a password.
	 *
	 * @param mixed $value
	 */
	public static function text( $value ): string {
		return is_string( $value ) || is_int( $value ) || is_float( $value ) ? (string) $value : '';
	}

	/**
	 * The existing account a single-account request is about, or 0. `me` is
	 * the caller. The store's route names the account in the path rather than
	 * as a parameter, so an update there would otherwise read as a creation.
	 */
	private static function account( \WP_REST_Request $request ): int {
		$route = (string) $request->get_route();

		if ( 1 === preg_match( '#^/wp/v2/users/me$#i', $route ) ) {
			return get_current_user_id();
		}

		$id = absint( self::text( $request['id'] ) );

		if ( 0 === $id && 1 === preg_match( '#^/wc/v[0-9]+/customers/([0-9]+)$#i', $route, $matched ) ) {
			$id = (int) $matched[1];
		}

		return $id;
	}
}
