<?php
/**
 * Hardening item: keep site-changing abilities to administrators.
 *
 * Another plugin's ability that changes the site, is reachable over the REST
 * API and lets a subscriber through its own permission check can be run by
 * any signed-in account, or by an agent using one. The fix belongs to that
 * plugin; until it ships, this narrows the abilities the finding listed, as
 * they were when the item was applied, to accounts that can manage the site.
 *
 * WordPress 7.1 filters every permission check (`wp_ability_permission_result`),
 * so there the answer is refused on every check. Before 7.1 the only place to
 * reach an ability's gate is as it registers (`wp_register_ability_args`):
 * its permission callback is wrapped, which covers what registers after this
 * plugin loads and nothing registered earlier. Those stay open and stay
 * reported, rather than claimed fixed. A denial is a plain false, which the
 * finding's own probe reads as refused.
 *
 * An ability registered after the item was applied is not covered until it
 * is applied again.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Abilities\AgentSurface;
use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AbilityAccess {

	public const ITEM = 'ability_access';

	/**
	 * @return array{available: bool, note: ?string, reason?: string}
	 */
	public static function availability(): array {
		if ( ! \BetterShield\Abilities\Registrar::is_available() ) {
			return array(
				'available' => false,
				'note'      => __( 'Needs WordPress 6.9 or newer.', 'bettershield' ),
			);
		}

		// Nothing to keep is something this site cannot offer, not a refusal.
		if ( ! Manager::instance()->is_active( self::ITEM ) && array() === AgentSurface::low_privilege_writes() ) {
			return array(
				'available' => false,
				// Good news, not a fault: the screen says so without a warning (#2523).
				'reason'    => 'not_needed',
				'note'      => self::nothing_open(),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * The abilities to cover are read here, at apply, from the same probe
	 * the finding runs. Whatever was passed is not a list anybody may hand
	 * this item.
	 *
	 * @param array<string, mixed> $options Ignored.
	 * @return array{abilities: string[]}|\WP_Error
	 */
	public static function validate( array $options ) {
		unset( $options );

		$open = AgentSurface::low_privilege_writes();

		if ( array() === $open ) {
			return new \WP_Error( 'bettershield_no_open_abilities', self::nothing_open() );
		}

		return array( 'abilities' => array_values( $open ) );
	}

	/**
	 * Each ability the item would cover, with the plugin it belongs to, so
	 * the card says whose feature changes for other roles.
	 */
	public static function conflict(): ?string {
		if ( Manager::instance()->is_active( self::ITEM ) || ! \BetterShield\Abilities\Registrar::is_available() ) {
			return null;
		}

		$named = self::named( AgentSurface::low_privilege_writes() );

		if ( array() === $named ) {
			return null;
		}

		return sprintf(
			/* translators: %s: a list of abilities, each with the plugin that added it, such as "shop/refund (Shop)". */
			__( 'Roles below administrator lose these, through an agent too: %s.', 'bettershield' ),
			implode( ', ', $named )
		);
	}

	/**
	 * What the item covers, while it is on.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$covered = self::covered( $state );

		if ( empty( $state['active'] ) || array() === $covered ) {
			return null;
		}

		$line = sprintf(
			/* translators: %s: a list of abilities, each with the plugin that added it. */
			__( 'Kept to administrators: %s.', 'bettershield' ),
			implode( ', ', self::named( $covered ) )
		);

		// Before 7.1 only what registers after this plugin loads is reached.
		if ( ! self::filters_every_check() ) {
			$line .= ' ' . __( 'On this WordPress version, any of these registered before BetterShield loads stays open, and the finding keeps saying so.', 'bettershield' );
		}

		return $line;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		if ( self::filters_every_check() ) {
			add_filter( 'wp_ability_permission_result', array( self::class, 'refuse' ), PHP_INT_MAX, 2 );

			return;
		}

		add_filter( 'wp_register_ability_args', array( self::class, 'wrap' ), PHP_INT_MAX, 2 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'wp_ability_permission_result', array( self::class, 'refuse' ), PHP_INT_MAX );
		remove_filter( 'wp_register_ability_args', array( self::class, 'wrap' ), PHP_INT_MAX );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return self::filters_every_check()
			? false !== has_filter( 'wp_ability_permission_result', array( self::class, 'refuse' ) )
			: false !== has_filter( 'wp_register_ability_args', array( self::class, 'wrap' ) );
	}

	/**
	 * A covered ability, asked by an account that cannot manage the site.
	 *
	 * @param bool|\WP_Error|mixed $permission What the ability's own check answered.
	 * @param mixed                $name       The ability.
	 * @return bool|\WP_Error|mixed
	 */
	public static function refuse( $permission, $name = '' ) {
		if ( self::is_covered( (string) $name ) && ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		return $permission;
	}

	/**
	 * A covered ability's own permission callback, asked only of an account
	 * that can manage the site.
	 *
	 * @param array<string, mixed>|mixed $args The registration arguments.
	 * @param mixed                      $name The ability.
	 * @return array<string, mixed>|mixed
	 */
	public static function wrap( $args, $name = '' ) {
		if ( ! is_array( $args ) || ! self::is_covered( (string) $name ) || ! isset( $args['permission_callback'] ) || ! is_callable( $args['permission_callback'] ) ) {
			return $args;
		}

		$own = $args['permission_callback'];

		$args['permission_callback'] = static function ( ...$input ) use ( $own ) {
			return current_user_can( 'manage_options' ) ? $own( ...$input ) : false;
		};

		return $args;
	}

	private static function is_covered( string $name ): bool {
		return '' !== $name && in_array( $name, self::covered( Manager::instance()->item_state( self::ITEM ) ), true );
	}

	/**
	 * @param array<string, mixed> $state
	 * @return string[]
	 */
	private static function covered( array $state ): array {
		return isset( $state['options']['abilities'] ) ? array_map( 'strval', (array) $state['options']['abilities'] ) : array();
	}

	/**
	 * Each ability with the plugin that added it.
	 *
	 * @param string[] $abilities
	 * @return string[]
	 */
	private static function named( array $abilities ): array {
		$sources = array();

		foreach ( AgentSurface::abilities() as $row ) {
			$sources[ $row['name'] ] = (string) $row['registering_source_label'];
		}

		$out = array();

		foreach ( $abilities as $ability ) {
			$out[] = isset( $sources[ $ability ] ) && '' !== $sources[ $ability ] ? $ability . ' (' . $sources[ $ability ] . ')' : $ability;
		}

		return $out;
	}

	private static function nothing_open(): string {
		return __( 'No plugin here lets non-admins change the site this way, so there’s nothing to limit.', 'bettershield' );
	}

	private static function filters_every_check(): bool {
		return version_compare( (string) get_bloginfo( 'version' ), '7.1-alpha', '>=' );
	}
}
