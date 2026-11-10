<?php
/**
 * Hardening item: keep unfiltered code to administrators.
 *
 * `unfiltered_html` lets an account publish script in a post, and
 * `unfiltered_upload` lets it upload a file of any type. Both run in the
 * browsers of whoever views the result, administrators included, so held
 * below administrator they are a way up.
 *
 * Applied as runtime filters, with no role edited in the database: every
 * account and role below `manage_options` is answered as not holding them,
 * and undo is the filters coming off. Editors keep `unfiltered_html`, which
 * core gives them and the finding does not count.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UnfilteredCode {

	public const ITEM = 'unfiltered_code';

	private const CAPS = array( 'unfiltered_html', 'unfiltered_upload' );

	/**
	 * On a network only super admins hold these, and the finding is not
	 * asked there.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( is_multisite() ) {
			return array(
				'available' => false,
				'reason'    => 'network_admin',
				'note'      => __( 'On a network, only network administrators can publish unfiltered code, so there is nothing to take back here.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * The roles that lose something while it is on, read from what each role
	 * stores rather than through the filter this item adds.
	 */
	public static function conflict(): ?string {
		$names = array();

		foreach ( wp_roles()->roles as $slug => $role ) {
			$caps = (array) ( $role['capabilities'] ?? array() );

			if ( ! empty( $caps['manage_options'] ) ) {
				continue;
			}

			if ( ( 'editor' !== $slug && ! empty( $caps['unfiltered_html'] ) ) || ! empty( $caps['unfiltered_upload'] ) ) {
				$names[] = translate_user_role( (string) $role['name'] );
			}
		}

		if ( array() === $names ) {
			return null;
		}

		return sprintf(
			/* translators: %s: a list of role names, such as Author, Shop manager. */
			__( 'These roles can’t add scripts while this is on: %s. If a plugin gave them that on purpose, it may stop working for them.', 'bettershield' ),
			implode( ', ', $names )
		);
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		// Last, so a plugin granting either of these is answered after it.
		add_filter( 'user_has_cap', array( self::class, 'user_caps' ), PHP_INT_MAX, 4 );
		add_filter( 'role_has_cap', array( self::class, 'role_caps' ), PHP_INT_MAX, 3 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'user_has_cap', array( self::class, 'user_caps' ), PHP_INT_MAX );
		remove_filter( 'role_has_cap', array( self::class, 'role_caps' ), PHP_INT_MAX );
	}

	/**
	 * Whether both filters are still attached: another plugin removing one
	 * leaves the item reading on with the capability back.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_filter( 'user_has_cap', array( self::class, 'user_caps' ) )
			&& false !== has_filter( 'role_has_cap', array( self::class, 'role_caps' ) );
	}

	/**
	 * An account below administrator is answered without the two
	 * capabilities, except an Editor's unfiltered HTML.
	 *
	 * @param array<string, bool> $allcaps
	 * @param string[]            $caps
	 * @param array<int, mixed>   $args
	 * @param \WP_User|null       $user
	 * @return array<string, bool>
	 */
	public static function user_caps( $allcaps, $caps = array(), $args = array(), $user = null ): array {
		$allcaps = (array) $allcaps;

		if ( ! empty( $allcaps['manage_options'] ) ) {
			return $allcaps;
		}

		$editor = $user instanceof \WP_User && in_array( 'editor', (array) $user->roles, true );

		foreach ( self::CAPS as $cap ) {
			if ( ! ( 'unfiltered_html' === $cap && $editor ) ) {
				unset( $allcaps[ $cap ] );
			}
		}

		return $allcaps;
	}

	/**
	 * The same answer for a role, so what the finding asks of each role
	 * reads the item as on.
	 *
	 * @param array<string, bool> $capabilities
	 * @return array<string, bool>
	 */
	public static function role_caps( $capabilities, $cap = '', $name = '' ): array {
		$capabilities = (array) $capabilities;

		if ( ! in_array( $cap, self::CAPS, true ) || ! empty( $capabilities['manage_options'] ) ) {
			return $capabilities;
		}

		if ( 'unfiltered_html' === $cap && 'editor' === $name ) {
			return $capabilities;
		}

		unset( $capabilities[ $cap ] );

		return $capabilities;
	}
}
