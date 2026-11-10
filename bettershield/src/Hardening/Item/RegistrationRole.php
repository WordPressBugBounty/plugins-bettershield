<?php
/**
 * Hardening item: new accounts start as Subscriber.
 *
 * With registration open, the role WordPress gives a new account is the
 * whole of what a stranger gets by signing up. Set to a role that can write,
 * every sign-up is a working author or editor account nobody had to guess a
 * password for.
 *
 * This sets that one setting, `default_role`, to Subscriber and keeps the
 * role it replaced, so undo can put it back. Undo leaves a role somebody
 * chose in the meantime alone: putting the old one back over a newer
 * decision would be undo changing something it never changed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RegistrationRole {

	public const ITEM = 'registration_role';

	/** The role it replaced, kept while the item is on. */
	public const OPTION = 'bettershield_registration_role';

	private const ROLE = 'subscriber';

	/**
	 * On a network the sign-up is the network's, and the account it makes
	 * gets no role on any site, so a site's default role is not what a
	 * stranger arrives with.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( is_multisite() ) {
			return array(
				'available' => false,
				'reason'    => 'network_admin',
				'note'      => __( 'On a network, registration is the network’s setting, and new accounts get no role on this site.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * A guest-posting site opens registration to writers on purpose.
	 */
	public static function conflict(): ?string {
		$role = get_role( (string) get_option( 'default_role', self::ROLE ) );

		if ( (bool) get_option( 'users_can_register' ) && $role instanceof \WP_Role && ! empty( $role->capabilities['edit_posts'] ) ) {
			return __( 'If people sign up here to write posts, they will need a role given by hand afterwards.', 'bettershield' );
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		unset( $options );

		$previous = (string) get_option( 'default_role', self::ROLE );

		if ( ! update_option( self::OPTION, array( 'previous' => $previous ), false ) && get_option( self::OPTION ) !== array( 'previous' => $previous ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'Nothing was changed: the role to come back to could not be stored.', 'bettershield' ) );
		}

		if ( self::ROLE !== $previous ) {
			self::write( self::ROLE );
		}

		if ( self::ROLE !== (string) get_option( 'default_role' ) ) {
			delete_option( self::OPTION );

			return new \WP_Error( 'bettershield_role_not_set', __( 'WordPress did not take the new role, so nothing was changed.', 'bettershield' ) );
		}

		return array(
			'tokens' => array(),
			'notes'  => self::ROLE === $previous ? array( __( 'New accounts already started as Subscriber. Undo leaves it that way.', 'bettershield' ) ) : array(),
		);
	}

	/**
	 * Writes the role as BetterShield's own change, which the takeover
	 * guard lets through: Monitor first and the Hub apply and undo this
	 * with nobody signed in, and an undo the guard refused would leave the
	 * role unchanged without saying so.
	 */
	private static function write( string $role ): void {
		TakeoverSettings::as_bettershield(
			static function () use ( $role ): void {
				update_option( 'default_role', $role );
			}
		);
	}

	/**
	 * Put the replaced role back, unless the setting was changed since or
	 * that role no longer exists. Either way the item comes off and says
	 * what it left.
	 *
	 * @param array<string, mixed> $state Unused; the role is read from its option.
	 * @return array{notes: string[]}
	 */
	public static function revert( array $state ): array {
		unset( $state );

		$kept     = get_option( self::OPTION );
		$previous = is_array( $kept ) ? (string) ( $kept['previous'] ?? '' ) : '';
		$current  = (string) get_option( 'default_role', self::ROLE );
		$notes    = array();

		delete_option( self::OPTION );

		if ( self::ROLE !== $current ) {
			$notes[] = sprintf(
				/* translators: %s: a role name, such as Author. */
				__( 'The role for new accounts was changed to %s since, so it was left as it is.', 'bettershield' ),
				self::role_name( $current )
			);
		} elseif ( '' === $previous ) {
			$notes[] = __( 'The role to come back to was not found, so new accounts still start as Subscriber. Change it under Settings › General.', 'bettershield' );
		} elseif ( ! get_role( $previous ) instanceof \WP_Role ) {
			$notes[] = __( 'The role new accounts got before no longer exists, so they still start as Subscriber.', 'bettershield' );
		} elseif ( self::ROLE !== $previous ) {
			self::write( $previous );
		}

		// The finding it closed opens again on the next screen.
		\BetterShield\Plugin::owe_audit();

		return array( 'notes' => $notes );
	}

	/**
	 * Nothing to hook: the item is the stored setting itself.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );
	}

	/**
	 * What undo would put back, while the item is on.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$kept     = get_option( self::OPTION );
		$previous = is_array( $kept ) ? (string) ( $kept['previous'] ?? '' ) : '';

		if ( empty( $state['active'] ) || '' === $previous || self::ROLE === $previous ) {
			return null;
		}

		return sprintf(
			/* translators: %s: a role name, such as Author. */
			__( 'Undo gives new accounts %s again.', 'bettershield' ),
			self::role_name( $previous )
		);
	}

	private static function role_name( string $slug ): string {
		$roles = wp_roles()->roles;

		return isset( $roles[ $slug ]['name'] ) ? translate_user_role( (string) $roles[ $slug ]['name'] ) : $slug;
	}
}
