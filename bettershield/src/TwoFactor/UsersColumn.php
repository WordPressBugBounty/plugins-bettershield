<?php
/**
 * A "Two-factor" column on the Users screen.
 *
 * Whether an account signs in with a code was readable only by its holder,
 * on their own screen: an administrator could not tell which accounts were
 * covered, including those brought over from another plugin. The column
 * says it per row, to whoever manages this plugin, and nothing else: no
 * secret, no code count.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Onboarding\Coexistence;
use BetterShield\Rest\Permissions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UsersColumn {

	public const COLUMN = 'bettershield_two_factor';

	public static function register(): void {
		if ( ! is_admin() ) {
			return;
		}

		add_filter( 'manage_users_columns', array( self::class, 'columns' ) );
		add_filter( 'manage_users_custom_column', array( self::class, 'cell' ), 10, 3 );
		add_filter( 'manage_users-network_columns', array( self::class, 'columns' ) );
	}

	/**
	 * @param array<string, string> $columns
	 * @return array<string, string>
	 */
	public static function columns( $columns ): array {
		$columns = is_array( $columns ) ? $columns : array();

		if ( ! Permissions::manage() ) {
			return $columns;
		}

		$columns[ self::COLUMN ] = __( 'Two-factor', 'bettershield' );

		return $columns;
	}

	/**
	 * @param string $output
	 * @param string $column
	 * @param int    $user_id
	 */
	public static function cell( $output, $column, $user_id ): string {
		if ( self::COLUMN !== $column ) {
			return (string) $output;
		}

		return self::label_for( (int) $user_id );
	}

	/** The cell's markup for one account. */
	public static function label_for( int $user_id ): string {
		if ( Manager::instance()->enabled( $user_id ) ) {
			return esc_html__( 'On', 'bettershield' );
		}

		$user      = get_userdata( $user_id );
		$elsewhere = $user instanceof \WP_User ? Coexistence::two_factor_for_user( $user ) : '';

		if ( '' !== $elsewhere ) {
			return esc_html(
				sprintf(
					/* translators: %s: the name of another security plugin. */
					__( 'In %s', 'bettershield' ),
					$elsewhere
				)
			);
		}

		return '<span aria-hidden="true">—</span><span class="screen-reader-text">' . esc_html__( 'Off', 'bettershield' ) . '</span>';
	}
}
