<?php
/**
 * REST surface for passkey-only sign-in.
 *
 * The write is interactive: this is the control that decides whether a
 * password opens an account, and a credential that is itself exempt from a
 * protection must not be able to change it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Passkeys\Manager;
use BetterShield\Passkeys\Policy;
use BetterShield\Passkeys\Store;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasskeyPolicyController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/passkeys/policy',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'read' ),
					'permission_callback' => static function (): bool {
						return current_user_can( Capabilities::MANAGE );
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body   = $request->get_json_params();
						$result = Policy::instance()->update_settings( is_array( $body ) ? $body : array() );

						return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'policy' => $result ) );
					},
					// Naming a role here decides whether a password opens those
					// accounts. Both directions are consequential and neither
					// belongs to a token. Taking a role off gives those
					// accounts their password back, so only that asks for the
					// password again.
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( Policy::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);
	}

	public function read(): \WP_REST_Response {
		$policy       = Policy::instance();
		$availability = Manager::availability();

		return rest_ensure_response(
			array(
				'policy'    => $policy->settings(),
				/*
				 * Whether the policy can take effect here at all. Where
				 * passkeys are off the gate stands aside, so a saved role is
				 * not in effect, and the screen has to say so rather than
				 * count it as covered.
				 */
				'available' => $availability['available'],
				'reason'    => $availability['reason'],
				'roles'     => self::roles(),
				/*
				 * The part of this policy the site did not set and cannot take
				 * away. Sent whether or not there is one, so the screen draws
				 * the same shape either way rather than guessing from a
				 * missing key.
				 */
				'network'   => array(
					'roles'    => NetworkPolicies::passkey()['roles'],
					'set'      => NetworkPolicies::passkey_is_set(),
					'can_edit' => true === Permissions::network_manage(),
				),
				/*
				 * How each named role currently stands, which is the only
				 * honest way to present this control. "Editors are
				 * passwordless" is a statement about a setting; "four editors,
				 * one of whom has a passkey" is a statement about the site,
				 * and it is the one that tells an owner whether the policy is
				 * doing anything yet.
				 */
				'coverage'  => self::coverage( $policy ),
			)
		);
	}

	/**
	 * @return array<int, array{slug: string, label: string, store_only: bool}>
	 */
	private static function roles(): array {
		$out = array();

		foreach ( wp_roles()->roles as $slug => $role ) {
			$out[] = array(
				'slug'       => (string) $slug,
				'label'      => isset( $role['name'] ) ? translate_user_role( (string) $role['name'] ) : (string) $slug,
				'store_only' => \BetterShield\Login\StoreAccount::role_kept_out( (string) $slug ),
			);
		}

		return $out;
	}

	/**
	 * Per named role: how many accounts hold it, and how many of those have a
	 * passkey and are therefore actually signing in without a password.
	 *
	 * Bounded rather than exhaustive. This runs on a settings screen, and a
	 * site with fifty thousand subscribers must not pay a full user walk to
	 * draw one panel — so the count is capped and says when it stopped
	 * counting, which is the same rule the rest of this plugin follows.
	 *
	 * @return array<int, array{role: string, accounts: int, enrolled: int, capped: bool}>
	 */
	private static function coverage( Policy $policy ): array {
		$out = array();
		$cap = 200;

		// The roles this site enforces, its own and the network's, so a role
		// the network requires gets its line too.
		foreach ( NetworkPolicies::effective_passkey_roles( $policy->settings()['roles'] ) as $role ) {
			$users = get_users(
				array(
					'role'   => $role,
					'number' => $cap + 1,
					'fields' => array( 'ID' ),
				)
			);

			$capped = count( $users ) > $cap;

			if ( $capped ) {
				array_pop( $users );
			}

			$ids = array_map( static fn( $user ): int => (int) $user->ID, $users );

			$out[] = array(
				'role'     => (string) $role,
				'accounts' => count( $ids ),
				/*
				 * One query for the whole role rather than one per account.
				 * Asking per account cost up to two hundred COUNT queries per
				 * named role every time this screen was drawn — six hundred to
				 * put three lines of text on a settings page.
				 */
				'enrolled' => Store::count_enrolled_among( $ids ),
				'capped'   => $capped,
			);
		}

		return $out;
	}
}
