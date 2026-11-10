<?php
/**
 * Plugin capabilities.
 *
 * Distinct capabilities instead of manage_options everywhere, so that
 * site owners can later grant read-only access to a role without handing
 * over full administration.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Capabilities {

	public const READ_POSTURE  = 'bettershield_read_posture';
	public const MANAGE        = 'bettershield_manage';
	public const READ_ACTIVITY = 'bettershield_read_activity';

	/**
	 * What lets a credential change this site's protections rather than read
	 * them.
	 *
	 * Deliberately outside ALL, so activation never grants it and an update
	 * never puts it back: it exists only while the owner has the write opt-in
	 * on, and the switch that turns that on is the one place it is granted.
	 * An administrator therefore holds it because somebody decided to, which
	 * is the whole difference between this capability and the three above.
	 */
	public const WRITE_POSTURE = 'bettershield_write_posture';

	private const ALL = array( self::READ_POSTURE, self::MANAGE, self::READ_ACTIVITY );

	/**
	 * Grant all plugin capabilities to administrators.
	 *
	 * Idempotent and write-free when already granted, so it is safe both
	 * on activation and on the admin_init gate that covers plugin updates
	 * (updates never re-run activation).
	 */
	public static function map(): void {
		$role = get_role( 'administrator' );

		if ( null === $role ) {
			return;
		}

		foreach ( self::ALL as $capability ) {
			if ( ! $role->has_cap( $capability ) ) {
				$role->add_cap( $capability );
			}
		}
	}

	/**
	 * The admin_init form: grant once per plugin version, not on every page
	 * load. An owner who deliberately takes a capability away from
	 * administrators with a role editor has made a decision, and a plugin
	 * that puts it back on the next request has overruled them silently.
	 * Activation and updates re-grant; nothing else does.
	 */
	public static function map_once(): void {
		$version = defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '0';

		if ( get_option( 'bettershield_caps_version' ) === $version ) {
			return;
		}

		self::map();
		update_option( 'bettershield_caps_version', $version, true );
	}
}
