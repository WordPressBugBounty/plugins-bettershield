<?php
/**
 * The permission rules shared by more than one controller.
 *
 * The interactive rule started life inside the two-factor controller and was
 * right there and missing one file over, which is what a rule kept in one
 * place does for the file it is not in. It lives here now so every caller
 * asks the same question of the same code.
 *
 * The rule these methods encode is asymmetric, and deliberately so: a
 * credential may make this site safer, and only a person may make it weaker.
 * Reading is open to anything holding the capability. So is applying a
 * protection — a provisioning script that hardens a site on the way up is
 * doing the thing this plugin exists for. Taking a protection away asks for
 * the session a person is actually sitting in front of.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Hardening\Items;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Permissions {

	/**
	 * The capability alone: reads, and the changes that only add protection.
	 */
	public static function manage(): bool {
		return current_user_can( Capabilities::MANAGE );
	}

	/**
	 * A signed-in browser session rather than a token.
	 *
	 * An application password is itself a second factor — generated, scoped to
	 * one integration, revocable on its own — and it is deliberately exempt
	 * from the sign-in gate. A credential that is exempt from a protection
	 * must not be able to remove it, so anything that changes how signing in
	 * works asks for the session that a person is actually sitting in front of.
	 *
	 * @return bool|\WP_Error
	 */
	public static function interactive() {
		if ( ! is_user_logged_in() ) {
			return false;
		}

		return self::not_an_application_password();
	}

	/**
	 * The same, and holding the capability that manages this plugin.
	 *
	 * This is the guard on every route that can lower the site's defenses:
	 * reverting a protection, importing a settings document, changing login
	 * protection, ending sessions, suppressing a finding, disabling another
	 * account's second factor, or turning a check off.
	 *
	 * @return bool|\WP_Error
	 */
	public static function interactive_manage() {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		$session = self::not_an_application_password();

		if ( true !== $session ) {
			return $session;
		}

		/*
		 * And, where the owner asked for it, the password again. This is the
		 * same set of routes — the ones that take a protection away — so the
		 * two questions are asked in one place rather than being kept in step
		 * by hand across a dozen controllers.
		 */
		return Sudo::confirmed();
	}

	/**
	 * A route that adds protection with one request and removes it with
	 * another: a person's own session either way, and the password again only
	 * for the request that removes it.
	 *
	 * The password gate promises to ask before a protection comes down and
	 * never before one goes up, and a route that both adds and removes cannot
	 * keep that promise on its permission alone. So the route works out which
	 * way this request goes — a role taken off a requirement, alerts turned
	 * down, a published contact withdrawn — and passes that here. Adding a
	 * role, an address or a check is not asked about.
	 *
	 * @param bool $removes Whether this request takes a protection away.
	 * @return bool|\WP_Error
	 */
	public static function interactive_manage_if( bool $removes ) {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		$session = self::not_an_application_password();

		if ( true !== $session ) {
			return $session;
		}

		return $removes ? Sudo::confirmed() : true;
	}

	/**
	 * A route that takes an assistant's access away, or turns agent access
	 * on and off. Ending access is the safe direction, so it is never asked
	 * for the password, and an owner cutting off an assistant they no longer
	 * trust is not told they are removing a protection (#1820); widening it
	 * is asked, as minting a credential is.
	 *
	 * @param bool $widens Whether this request gives an assistant more than it had.
	 * @return bool|\WP_Error
	 */
	public static function interactive_manage_access( bool $widens ) {
		return self::interactive_manage_if( $widens );
	}

	/**
	 * Changing a file in the site's own code: the web root, core, a plugin or
	 * a theme. On a network that code belongs to every site, so the say over
	 * it is the network's, whatever one site's administrator may manage here;
	 * the record of the change would sit in one site's log and undo list,
	 * where the network's own administrator never sees it.
	 *
	 * `$update_rights` asks as well for the capability to update the code at
	 * all, which a change to it is.
	 *
	 * @return bool|\WP_Error
	 */
	public static function shared_code( bool $update_rights = true ) {
		if ( ( ! $update_rights || current_user_can( 'update_plugins' ) ) && ( ! is_multisite() || current_user_can( 'manage_network' ) ) ) {
			return true;
		}

		return new \WP_Error(
			'bettershield_shared_code',
			// Who can, where a network is the reason (#2639).
			is_multisite() && ! current_user_can( 'manage_network' )
				? __( 'Only a network administrator can change the files every site on this network shares. Ask one to review this change.', 'bettershield' )
				: __( 'Changing these files needs permission to update plugins. Ask an administrator to review this change.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Reading something that belongs to the network rather than to a site.
	 *
	 * `manage_network` is what the network screens have always asked for, and
	 * it is the capability a network administrator actually holds. On a single
	 * site there is no network to read and this is false — the routes are not
	 * registered there either, so this is the second of two answers rather
	 * than the only one.
	 */
	public static function network_read(): bool {
		return is_multisite() && current_user_can( 'manage_network' );
	}

	/**
	 * Changing something that belongs to the network.
	 *
	 * The narrower capability, deliberately: `manage_network` covers reading
	 * the estate, and `manage_network_options` is the one about settings. The
	 * other two legs are the same rule every weakening route here follows —
	 * a person's own session rather than a token, and the password again where
	 * the owner asked for it.
	 *
	 * That last leg is read from the main site. The switch is a per-site
	 * option and a network request lands on whichever site answered it, so
	 * without this the gate would be on or off depending on which site's
	 * dashboard the administrator happened to come from.
	 *
	 * @return bool|\WP_Error
	 */
	public static function network_manage() {
		if ( ! is_multisite() || ! current_user_can( 'manage_network_options' ) ) {
			return false;
		}

		$session = self::not_an_application_password();

		if ( true !== $session ) {
			return $session;
		}

		return Sudo::confirmed( true );
	}

	/**
	 * Applying a hardening item.
	 *
	 * Applying adds protection, so a token may do it — except for the items
	 * that change how signing in works. Rotating the sign-in keys signs every
	 * account out, and renaming the sign-in address or gating wp-admin moves
	 * the door a person has to find; each of those is disruptive enough in its
	 * own right that it asks for a session even though the direction is safe.
	 *
	 * The registry already knows which items those are: they are the ones in
	 * the `sign_in` group, so this reads the answer rather than restating it.
	 *
	 * @return bool|\WP_Error
	 */
	public static function apply_hardening_item( \WP_REST_Request $request ) {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		return self::needs_way_back( (string) $request['item'] )
			? self::not_an_application_password()
			: true;
	}

	/**
	 * Whether an item id belongs to the group that changes how signing in
	 * works, and is not one of its items that only adds a check (leaked
	 * passwords, shorter reset links), which can't lock anyone out. An
	 * unknown id is treated as though it did: the route answers
	 * "no such item" further in, and until it does, the guarded reading is
	 * the right one.
	 */
	public static function changes_signing_in( string $item ): bool {
		$items = Items::all();

		if ( ! isset( $items[ $item ] ) ) {
			return true;
		}

		// An item in the group that can't lock anyone out says so with
		// 'way_back' => false (#2497).
		return 'sign_in' === ( $items[ $item ]['group'] ?? '' ) && false !== ( $items[ $item ]['way_back'] ?? true );
	}

	/**
	 * Whether applying an item waits for a proved way back in: one that
	 * changes how people sign in, or one that changes the site's own
	 * address, which a failing certificate turns into a lockout (#1289).
	 */
	public static function needs_way_back( string $item ): bool {
		return self::changes_signing_in( $item ) || in_array( $item, Items::ADDRESS_ITEMS, true );
	}

	/**
	 * @return bool|\WP_Error
	 */
	private static function not_an_application_password() {
		if ( ! function_exists( 'rest_get_authenticated_app_password' ) || null === rest_get_authenticated_app_password() ) {
			return true;
		}

		return new \WP_Error(
			'bettershield_interactive_only',
			__( 'Change this from a signed-in browser, not an application password.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}
}
