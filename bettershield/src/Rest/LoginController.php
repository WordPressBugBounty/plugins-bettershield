<?php
/**
 * REST surface for login protection: settings, lockouts, sessions.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Login\Attempts;
use BetterShield\Login\Protection;
use BetterShield\Login\Replay;
use BetterShield\Login\Surfaces;
use BetterShield\Login\Sessions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		$manage = static function (): bool {
			return current_user_can( Capabilities::MANAGE );
		};

		// Every route below that can lower this site's defenses asks for a
		// signed-in browser session. A credential exempt from the sign-in gate
		// may read, and may add protection, but may not take any away.
		$interactive_manage = static function () {
			return Permissions::interactive_manage();
		};

		register_rest_route(
			'bettershield/v1',
			'/login-protection',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response(
							array(
								'settings'   => Protection::instance()->settings(),
								'proof_of_work_available' => \BetterShield\Login\ProofOfWork::available(),
								// Whether this server can take the auth-log line,
								// and whether its host has already decided it.
								'host_ban_line' => \BetterShield\Support\AuthLog::status(),
								// What this plugin recommends, so a number
								// somebody changed has a way back to it.
								'defaults'   => Protection::instance()->defaults(),
								// How THIS request resolved: the live answer to
								// "which detection method is in use", and what the
								// screen warns from.
								'resolution' => Protection::instance()->resolution_report(),
								'lockouts'   => Protection::instance()->lockouts(),
								// How many there are in all, so a list cut at
								// its length can say so.
								'lockouts_total' => Protection::instance()->lockout_total(),
								// How many are running, which the screen
								// counts from rather than from the list.
								'lockouts_active' => Protection::instance()->lockout_running(),
								// What the counter covers, when that is less
								// than the account it is protecting.
								'scope_note' => Protection::instance()->counting_scope(),
								// The same, for the three forms below it: they
								// count on the same per-site tables.
								'scope_note_public' => Protection::instance()->counting_scope_public(),
								// Other active plugins that limit sign-in
								// attempts too, and where the choice between
								// them is made.
								'also_limiting'     => \BetterShield\Onboarding\Coexistence::doing( 'login_limits' ),
								'coexistence_url'   => \BetterShield\Onboarding\QuickSetup::url(),
							)
						);
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();
						$body = is_array( $body ) ? $body : array();

						/*
						 * A body naming none of the settings changes nothing, so
						 * it is refused rather than answered 200 and logged as a
						 * change, as the other settings routes refuse theirs
						 * (#2176). Checked in the callback, after the permission
						 * check, so a caller with no business here hears no.
						 */
						if ( array() === array_intersect_key( $body, Protection::instance()->settings() ) ) {
							return new \WP_Error(
								'bettershield_no_known_setting',
								__( 'Name at least one login protection setting to change.', 'bettershield' ),
								array( 'status' => 400 )
							);
						}

						// A block on the saver's own connection locks them out on
						// their next sign-in, as blocking their own name would.
						$self = Protection::instance()->refuses_the_saver( $body );

						if ( null !== $self ) {
							return $self;
						}

						// A change to the host-ban line from a network's
						// subsite is said to be the main site's, rather than
						// silently not made.
						$network = Protection::instance()->refuses_a_network_switch( $body );

						if ( null !== $network ) {
							return $network;
						}

						$result = Protection::instance()->update_settings( $body );

						if ( is_wp_error( $result ) ) {
							return $result;
						}

						// Several checks read these settings, so the answer
						// carries the audit they now produce.
						return rest_ensure_response( array_merge( array( 'settings' => $result ), OverviewController::reaudited() ) );
					},
					// A session either way; the password again only when the
					// save takes protection away.
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( Protection::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);

		/*
		 * What proposed numbers for one public form would have done over the
		 * attempts still recorded, beside what the saved ones did. A read: it
		 * changes nothing, so it asks what reading the settings asks.
		 */
		$number = static fn( int $min, int $max ): array => array(
			'type'              => 'integer',
			'required'          => true,
			'minimum'           => $min,
			'maximum'           => $max,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'rest_sanitize_request_arg',
		);

		register_rest_route(
			'bettershield/v1',
			'/login-protection/replay',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Replay::run(
						(string) $request->get_param( 'surface' ),
						array(
							'threshold'       => (int) $request->get_param( 'threshold' ),
							'window_minutes'  => (int) $request->get_param( 'window_minutes' ),
							'lockout_minutes' => (int) $request->get_param( 'lockout_minutes' ),
						)
					);

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => $manage,
				'args'                => array(
					'surface'         => array(
						'type'              => 'string',
						'required'          => true,
						'enum'              => Surfaces::GATED,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
					'threshold'       => $number( 3, 100 ),
					'window_minutes'  => $number( 1, 1440 ),
					'lockout_minutes' => $number( 1, 1440 ),
				),
			)
		);

		// The networks failed sign-ins came from and the names they tried
		// (#1979). Whether a name is an account, and the offer to block one
		// that is not, only for someone who may list the users.
		register_rest_route(
			'bettershield/v1',
			'/login-protection/attempts',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					return rest_ensure_response( Attempts::summary( (int) $request->get_param( 'days' ), current_user_can( 'list_users' ) ) );
				},
				'permission_callback' => $manage,
				'args'                => array(
					'days' => array(
						'type'              => 'integer',
						'enum'              => Attempts::SPANS,
						'default'           => Attempts::SPANS[0],
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/login-protection/lockouts/(?P<id>[0-9]+)/release',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Protection::instance()->release( (int) $request['id'] );

					if ( is_wp_error( $result ) ) {
						return $result;
					}

					return rest_ensure_response(
						array(
							'lockouts'        => Protection::instance()->lockouts(),
							'lockouts_total'  => Protection::instance()->lockout_total(),
							'lockouts_active' => Protection::instance()->lockout_running(),
						)
					);
				},
				'permission_callback' => $interactive_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/login-protection/sessions',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'args'                => array(
					'offset' => array(
						'type'              => 'integer',
						'minimum'           => 0,
						'default'           => 0,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					// One page of the list, and what a site-wide end would
					// actually reach from where this caller is standing — so the
					// screen can say so before the button is pressed rather than
					// after. Every account's sessions are counted once, and the
					// total and the reach come from that count; only the
					// accounts on the page are read.
					$sessions = Sessions::instance();
					$live     = $sessions->live_counts();

					return rest_ensure_response(
						array(
							'sessions'      => $sessions->active( (int) $request['offset'], Sessions::LISTED, $live ),
							'total'         => count( $live ),
							'reach'         => $sessions->site_wide_reach( $live ),
							// Whether a concurrent-session limit can be kept here at
							// all. A site that swapped the session manager has no
							// meta to remove entries from, and the setting was a
							// silent no-op there while the screen showed a limit.
							'cap_supported' => $sessions->cap_supported(),
						)
					);
				},
				'permission_callback' => $manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/login-protection/sessions/end',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					if ( is_array( $body ) && isset( $body['user_id'] ) ) {
						$user_id = (int) $body['user_id'];

						// On a network a site's administrator reaches that site's
						// members, not every account the network holds.
						if ( null === get_userdata( $user_id ) || ( is_multisite() && ! is_super_admin() && ! is_user_member_of_blog( $user_id ) ) ) {
							return new \WP_Error( 'bettershield_no_user', __( 'No such account.', 'bettershield' ), array( 'status' => 404 ) );
						}

						// Managing this plugin is not the same as having any say
						// over this account. The account's own editor does — the
						// same check its sibling on the two-factor controller
						// makes, and for the same reason: signing somebody out
						// is something done to them, not to the site.
						if ( ! current_user_can( 'edit_user', $user_id ) ) {
							return new \WP_Error( 'bettershield_cannot_edit_user', __( 'You cannot change this account.', 'bettershield' ), array( 'status' => 403 ) );
						}

						$result = Sessions::instance()->end_for_user( $user_id );
					} elseif ( is_array( $body ) && ( $body['scope'] ?? '' ) === 'site' ) {
						$result = Sessions::instance()->end_all();
					} else {
						return new \WP_Error( 'bettershield_bad_scope', __( 'Say whose sessions to end: a user, or the whole site.', 'bettershield' ), array( 'status' => 400 ) );
					}

					// The acting administrator's own session may be among the ended
					// ones; the address to sign back in at travels with the answer,
					// so the screen can go straight there rather than leave a dead
					// dashboard behind. wp_login_url() honors the moved address.
					$sessions = Sessions::instance();
					$live     = $sessions->live_counts();

					return rest_ensure_response(
						array_merge(
							$result,
							array(
								'sessions'      => $sessions->active( 0, Sessions::LISTED, $live ),
								'total'         => count( $live ),
								'reach'         => $sessions->site_wide_reach( $live ),
								'cap_supported' => $sessions->cap_supported(),
								'login_url'     => wp_login_url(),
							)
						)
					);
				},
				'permission_callback' => $interactive_manage,
			)
		);
	}
}
