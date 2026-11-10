<?php
/**
 * REST surface for two-factor enrollment.
 *
 * The enrollment routes are self-service: they act on the signed-in user and
 * ask only that someone IS signed in — a subscriber protecting their own
 * account needs no plugin capability to do it. The one administrative route,
 * disabling another user's second factor, is the support path and carries
 * both the manage capability and an event trail.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Recovery\Preflight;
use BetterShield\TwoFactor\Manager;
use BetterShield\TwoFactor\Policy;
use BetterShield\Rest\Sudo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TwoFactorController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		$signed_in = static function (): bool {
			return is_user_logged_in();
		};

		// Managing the factor is interactive: a request that signed in with
		// an application password — itself exempt from the factor — may read
		// the status but may not enroll, re-enroll, or turn it off.
		$interactive = static function () {
			return Permissions::interactive();
		};

		// Turning the factor off for somebody else is the same act as turning
		// it off for yourself, so it asks for the same session — and for the
		// capability to edit the account it is aimed at, which managing this
		// plugin does not by itself confer.
		$interactive_manage = static function () {
			return Permissions::interactive_manage();
		};

		/*
		 * The one field each of these routes reads, declared so core refuses a
		 * body of the wrong shape before the callback runs — the reason the
		 * passkey routes declare theirs. Cast by hand, an array arrived as the
		 * word "Array" with a PHP warning ahead of it: log noise and, with
		 * display on, a broken JSON answer; on the password route, a wrong
		 * password attempt as well. A code may come as a number from a script.
		 */
		$code = array(
			'code' => array(
				'type'              => array( 'string', 'integer' ),
				'required'          => false,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/status',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response(
						Manager::instance()->status( get_current_user_id() ) + array(
							// Whether this account's application passwords sign
							// in at all here: refused by a hardening item or a
							// lockdown, the card's promise that they keep working
							// was untrue (#1847).
							'app_passwords_work' => wp_is_application_passwords_available_for_user( wp_get_current_user() ),
						)
					);
				},
				'permission_callback' => $signed_in,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/start',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => $code,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					// The secret appears in this response and is never shown
					// again; the screen renders it as a QR code and as text.
					$result = Manager::instance()->start( wp_get_current_user(), is_array( $body ) ? (string) ( $body['code'] ?? '' ) : '' );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/confirm',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => $code,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body   = $request->get_json_params();
					$result = Manager::instance()->confirm( wp_get_current_user(), is_array( $body ) ? (string) ( $body['code'] ?? '' ) : '' );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/acknowledge',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$result = Manager::instance()->acknowledge( wp_get_current_user() );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/discard',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( Manager::instance()->discard( wp_get_current_user() ) );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/disable',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				// A code, as everywhere; or, while safe mode is on, the
				// account's own password instead.
				'args'                => $code + array(
					'password' => array(
						'type'              => 'string',
						'required'          => false,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body     = $request->get_json_params();
					$body     = is_array( $body ) ? $body : array();
					$code     = (string) ( $body['code'] ?? '' );
					$password = (string) ( $body['password'] ?? '' );

					$result = '' === trim( $code ) && '' !== $password
						? Manager::instance()->disable_in_safe_mode( wp_get_current_user(), $password )
						: Manager::instance()->disable( wp_get_current_user(), $code );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/backup-codes',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => $code,
				/*
				 * A fresh set for an account already enrolled. Ten codes were
				 * minted once at enrollment and from then on only decreased,
				 * so the panel counted down toward a dead end on the one screen
				 * the affected roles can open.
				 *
				 * Guarded by the same proof `/two-factor/disable` demands, and
				 * that guard is the point rather than a formality: a route that
				 * hands out ten long-lived credentials to whoever holds the
				 * session would leave a hijacked session better off than it
				 * started.
				 */
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body   = $request->get_json_params();
					$result = Manager::instance()->reissue_backup_codes(
						wp_get_current_user(),
						is_array( $body ) ? (string) ( $body['code'] ?? '' ) : ''
					);

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $interactive,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/confirm-password',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'password' => array(
						'type'              => 'string',
						'required'          => false,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body   = $request->get_json_params();
					$result = Sudo::confirm( is_array( $body ) ? (string) ( $body['password'] ?? '' ) : '' );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				/*
				 * The session rule, and deliberately not the sudo layer that
				 * sits on top of it — this is the route that satisfies that
				 * layer, and gating it behind itself would make every guarded
				 * action permanently unreachable.
				 *
				 * Any signed-in account, not only one that manages this
				 * plugin: an account without two-factor proves a change to its
				 * own passkeys with this password, and an author refused here
				 * could never add one or remove a lost one. The window opens
				 * nothing else for it, since every other route that reads the
				 * window asks for the capability first.
				 */
				'permission_callback' => static function () {
					return Permissions::interactive();
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/policy',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						$roles = array();

						foreach ( wp_roles()->roles as $slug => $role ) {
							$roles[] = array(
								'slug'       => (string) $slug,
								'label'      => translate_user_role( (string) $role['name'] ),
								// Sent to My Account rather than the dashboard,
								// where this requirement is asked.
								'store_only' => \BetterShield\Login\StoreAccount::role_kept_out( (string) $slug ),
							);
						}

						$network = \BetterShield\Network\Policies::two_factor();

						return rest_ensure_response(
							array_merge(
								Policy::instance()->settings(),
								array(
									'available_roles' => $roles,
									// Whether there is a My Account page for
									// the tab's switch to be about.
									'store_active'    => \BetterShield\Login\StoreAccount::available(),
									// The pages the account page can be.
									'account_pages'   => \BetterShield\Login\AccountPage::choices(),
									// Another plugin kept for two-factor in
									// Quick Setup, or ''.
									'handled_by'      => \BetterShield\Onboarding\Coexistence::two_factor_handled_by(),
									/*
									 * The part of this policy the site did not
									 * set and cannot take away. Sent whether or
									 * not there is one, so the screen draws the
									 * same shape either way rather than
									 * guessing from a missing key.
									 */
									'network'         => array(
										'roles'      => $network['roles'],
										'grace_days' => $network['grace_days'],
										'set'        => \BetterShield\Network\Policies::two_factor_is_set(),
										'can_edit'   => true === Permissions::network_manage(),
									),
									// Roles an add-on asks two-factor of under
									// its own rules, so the count says everyone
									// who is asked. Not this policy's to edit.
									'elsewhere'       => array(
										'roles' => self::roles_required_elsewhere(),
									),
								)
							)
						);
					},
					'permission_callback' => static function () {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					// Declared, as the code routes above are, so a body of the
					// wrong shape is refused before anything casts it: a role
					// sent as a list was "Array" with a PHP warning ahead of it.
					'args'                => array(
						'roles'      => array(
							'type'              => 'array',
							'items'             => array( 'type' => 'string' ),
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'grace_days' => array(
							'type'              => 'integer',
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'store_tab'  => array(
							'type'              => 'boolean',
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'account_page' => array(
							'type'              => 'integer',
							'minimum'           => 0,
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
					),
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body     = $request->get_json_params();
						$body     = is_array( $body ) ? $body : array();
						$override = true === ( $body['override_preflight'] ?? false );
						unset( $body['override_preflight'] );

						/*
						 * Requiring a factor of a role that did not need one
						 * changes how its accounts sign in, so it waits for a
						 * proved way back in, as a sign-in hardening item does.
						 * Narrowing or keeping the roles is never held up.
						 */
						$current = Policy::instance()->settings()['roles'];
						$widened = array() !== array_diff( array_map( 'strval', array_filter( (array) ( $body['roles'] ?? $current ), 'is_scalar' ) ), $current );
						$failure = $widened ? Preflight::failure() : null;

						if ( null !== $failure && ! $override ) {
							return Preflight::refusal( $failure );
						}

						$result = Policy::instance()->update_settings( $body );

						if ( ! is_wp_error( $result ) && null !== $failure ) {
							Preflight::overridden( $failure, 'two_factor_policy', 'dashboard' );
						}

						return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
					},
					/*
					 * Requiring a factor strengthens the site, but *removing*
					 * the requirement weakens it and the two share one route —
					 * so the whole route asks for the session, on the rule this
					 * plugin applies everywhere else. The password again only
					 * where a role comes off or the grace grows.
					 */
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( Policy::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);

		/*
		 * Take back the two-factor brought over from another plugin as it was
		 * switched off. Each account it reaches goes back to signing in with
		 * a password alone here, so it asks for the password, as every route
		 * that takes a protection away does.
		 */
		register_rest_route(
			'bettershield/v1',
			'/two-factor/import/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = \BetterShield\TwoFactor\Import::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => static function () {
					return Permissions::interactive_manage_if( true );
				},
				'args'                => array(
					'undo' => array(
						'type'              => 'string',
						'required'          => false,
						'default'           => '',
						'pattern'           => '^([a-f0-9]{32})?$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/two-factor/users/(?P<id>[0-9]+)/disable',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$user_id = (int) $request['id'];

					// On a network, "no such account" covers accounts of other
					// sites too: a site's administrator manages that site's
					// members, not the network's.
					if ( null === get_userdata( $user_id ) || ( is_multisite() && ! is_super_admin() && ! is_user_member_of_blog( $user_id ) ) ) {
						return new \WP_Error( 'bettershield_no_user', __( 'No such account.', 'bettershield' ), array( 'status' => 404 ) );
					}

					// The support path is for somebody else's account. Your own
					// comes off through the route that asks for a current code,
					// so nobody at an unlocked screen can remove it.
					if ( get_current_user_id() === $user_id ) {
						return new \WP_Error( 'bettershield_own_two_factor', __( 'To turn off your own two-factor, use Turn off in your two-factor settings.', 'bettershield' ), array( 'status' => 403 ) );
					}

					// Managing this plugin is not the same as having any say
					// over this account. The account's own editor does.
					if ( ! current_user_can( 'edit_user', $user_id ) ) {
						return new \WP_Error( 'bettershield_cannot_edit_user', __( 'You cannot change this account.', 'bettershield' ), array( 'status' => 403 ) );
					}

					// Nothing to turn off is not a factor removed: no event, and
					// nobody signed out for a factor they never had.
					if ( ! Manager::instance()->enabled( $user_id ) ) {
						return new \WP_Error( 'bettershield_not_enabled', __( 'Two-factor is not on for this account.', 'bettershield' ), array( 'status' => 409 ) );
					}

					// The support path: their phone is gone, their codes are
					// gone, an administrator lets them start over.
					return rest_ensure_response( Manager::instance()->disable_for( $user_id, 'admin' ) );
				},
				'permission_callback' => $interactive_manage,
			)
		);
	}

	/**
	 * The roles an add-on asks two-factor of under rules of its own, as role
	 * slugs this site has. Read only to be counted; never saved into this
	 * policy.
	 *
	 * @return string[]
	 */
	private static function roles_required_elsewhere(): array {
		/**
		 * Filters the roles an add-on requires two-factor of outside this
		 * plugin's own policy.
		 *
		 * @param string[] $roles Role slugs.
		 */
		$roles = apply_filters( 'bettershield_two_factor_roles_required_elsewhere', array() );
		$known = array_keys( wp_roles()->roles );

		return array_values( array_intersect( $known, array_map( 'strval', is_array( $roles ) ? $roles : array() ) ) );
	}
}
