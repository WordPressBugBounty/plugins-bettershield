<?php
/**
 * Lists of accounts named in a sign-in requirement, beside its roles: who is
 * asked whatever their role, and who this site's roles leave alone.
 *
 * Shared by the two-factor and passkey-only requirements so the two read,
 * refuse and describe a named account the same way.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NamedAccounts {

	/**
	 * The most accounts either list holds. A list is for the handful a role
	 * cannot describe; a site with more than this many exceptions wants a role.
	 */
	public const MAX = 200;

	/**
	 * Account ids from a stored list: whole, positive, each once.
	 *
	 * @param mixed $list
	 * @return int[]
	 */
	public static function ids( $list ): array {
		$ids = array();

		foreach ( (array) $list as $id ) {
			if ( is_int( $id ) || ( is_string( $id ) && ctype_digit( $id ) ) ) {
				$ids[] = (int) $id;
			}
		}

		return array_values( array_unique( array_filter( $ids ) ) );
	}

	/**
	 * Whether an account can be named on this site: it exists and, on a
	 * network, belongs to this site.
	 */
	public static function nameable( int $id ): bool {
		$user = get_userdata( $id );

		return $user instanceof \WP_User && ( ! is_multisite() || is_user_member_of_blog( $id ) );
	}

	/**
	 * Both lists as a save would store them, or the refusal it earns. A list
	 * missing from the input keeps what is stored. One already stored that
	 * has since gone, or left this site, is dropped quietly, so a deleted
	 * account never blocks the next save.
	 *
	 * @param array<string, mixed>               $input
	 * @param array{users: int[], excluded: int[]} $current
	 * @return array{users: int[], excluded: int[]}|\WP_Error
	 */
	public static function clean( array $input, array $current ) {
		$people = array();

		foreach ( array( 'users', 'excluded' ) as $list ) {
			if ( ! isset( $input[ $list ] ) ) {
				$people[ $list ] = array_values( array_filter( $current[ $list ], array( self::class, 'nameable' ) ) );
				continue;
			}

			if ( ! is_array( $input[ $list ] ) || count( $input[ $list ] ) > self::MAX ) {
				return new \WP_Error(
					'bettershield_bad_people',
					sprintf(
						/* translators: %d: the most accounts the list can hold. */
						__( 'Name at most %d accounts. For more, require a role instead.', 'bettershield' ),
						self::MAX
					),
					array( 'status' => 400 )
				);
			}

			$people[ $list ] = array();

			foreach ( $input[ $list ] as $id ) {
				if ( ! is_int( $id ) && ! ( is_string( $id ) && ctype_digit( $id ) ) ) {
					return self::unknown();
				}

				$id = (int) $id;

				if ( self::nameable( $id ) ) {
					$people[ $list ][] = $id;
				} elseif ( ! in_array( $id, $current[ $list ], true ) ) {
					return self::unknown();
				}
			}

			$people[ $list ] = array_values( array_unique( $people[ $list ] ) );
		}

		if ( array() !== array_intersect( $people['users'], $people['excluded'] ) ) {
			return new \WP_Error( 'bettershield_people_both', __( 'An account can’t be both required and left out. Remove it from one of the lists.', 'bettershield' ), array( 'status' => 400 ) );
		}

		return $people;
	}

	/**
	 * Each named account as a screen shows it, skipping any gone since.
	 *
	 * @param int[] $ids
	 * @return array<int, array{id: int, name: string, login: string}>
	 */
	public static function describe( array $ids ): array {
		$out = array();

		foreach ( $ids as $id ) {
			$user = get_userdata( (int) $id );

			if ( $user instanceof \WP_User ) {
				$out[] = array(
					'id'    => (int) $user->ID,
					'name'  => (string) $user->display_name,
					'login' => (string) $user->user_login,
				);
			}
		}

		return $out;
	}

	private static function unknown(): \WP_Error {
		return new \WP_Error( 'bettershield_unknown_account', __( 'That is not an account on this site.', 'bettershield' ), array( 'status' => 400 ) );
	}
}
