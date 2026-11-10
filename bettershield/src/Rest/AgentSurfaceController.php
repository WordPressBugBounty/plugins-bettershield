<?php
/**
 * REST surface for the Agent surface screen.
 *
 * Distinct from the ability of the same name: this route serves the owner's
 * own screen, carries the manage capability like every Protect surface, and
 * is the one place per-password names appear. The ability serves agents,
 * follows the opt-in, and never carries names.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Abilities\AgentSurface;
use BetterShield\Abilities\Registrar;
use BetterShield\Agents\Canary;
use BetterShield\Agents\Connectors;
use BetterShield\Agents\Expiry;
use BetterShield\Agents\PasswordLimits;
use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AgentSurfaceController {

	/**
	 * What the credential this site holds was issued for.
	 *
	 * A site with nothing paired has no scope, and counting the tools a
	 * read-only catalog would offer there would understate what an assistant
	 * is about to be given. Unpaired therefore counts the whole catalog, which
	 * is what the first credential minted here will reach.
	 */
	private static function paired_scope(): string {
		$scope = \BetterShield\Mcp\Pairing::scope();

		return '' === $scope ? \BetterShield\Mcp\Scopes::READ_WRITE : $scope;
	}

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/agent-surface',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					$canary = Canary::planted();

					return rest_ensure_response(
						array(
							'abilities_api_available' => Registrar::is_available(),
							'abilities_enabled'       => Registrar::is_enabled(),
							// The second opt-in, the capability it carries and
							// whether this site asks for the password again.
							// Here beside the first so the screen draws the
							// whole state on its first read rather than
							// starting on a guess and correcting itself.
							'write_enabled'           => Registrar::write_enabled(),
							'capability_granted'      => Registrar::write_capability_held(),
							'sudo_required'           => Sudo::required(),
							'password_reason'         => Sudo::required() ? null : Registrar::password_reason(),
							// How many requests are waiting for an answer, from
							// the same cached count the menu's bubble reads, so
							// the two can never disagree.
							'open_requests'           => \BetterShield\Abilities\Proposals::open_count(),
							// The ceilings an agent works under, read through
							// the filters that set them rather than written
							// into a sentence: a site that raised one is told
							// the number it actually has.
							// Each is per connection; the site as a whole
							// allows a few connections' worth.
							'limits'                  => array(
								'writes_per_hour' => max( 1, (int) apply_filters( 'bettershield_agent_write_limit', Registrar::WRITE_LIMIT_PER_HOUR ) ),
								'plans_per_hour'  => max( 1, (int) apply_filters( 'bettershield_agent_propose_limit', Registrar::PROPOSE_LIMIT_PER_HOUR ) ),
								'site_factor'     => Registrar::SITE_LIMIT_FACTOR,
							),
							'abilities'               => AgentSurface::abilities(),
							// What an update added or opened wider, waiting for
							// the owner to accept it (#1878).
							'ability_changes'         => \BetterShield\Abilities\Baseline::described(),
							'application_passwords'   => AgentSurface::application_passwords( true ),
							// Other plugins' MCP servers, read from the REST
							// routes: who owns each and whether it signs anyone in.
							'mcp_endpoints'           => \BetterShield\Abilities\McpEndpoints::report(),
							// The policy for retiring the ones nobody uses.
							'expiry'                  => ( new Expiry() )->settings(),
							'expiry_min_days'         => Expiry::MIN_DAYS,
							// The decoy, if one is planted, and when it was
							// last used, if it has been.
							'canary'                  => $canary,
							'canary_use'              => null === $canary ? null : Canary::last_use( $canary['uuid'] ),
							'canary_name'             => Canary::NAME,
							'decoy_page'              => \BetterShield\Agents\DecoyPage::described(),
							// Which credentials this site keeps for AI
							// connectors, and who can read them. Absent below
							// the version that has connectors at all, rather
							// than a placeholder promising a later one.
							'connectors'              => Connectors::report(),
							'connectors_reference'    => Connectors::reference_url(),
							// Whether this site answers an assistant directly,
							// whether anything is paired with it or signed in
							// to it, and how much a paired one would reach.
							// Facts rather than the connection itself: the
							// screen that draws it reads its own route, and
							// this is the summary every other screen needs.
							'mcp'                     => array(
								'enabled'   => \BetterShield\Mcp\Manager::is_enabled(),
								'connected' => \BetterShield\Mcp\Pairing::is_connected(),
								// Whether an assistant has used that credential:
								// issued and waiting is not connected (#2062).
								'used'      => \BetterShield\Mcp\Pairing::is_connected() && \BetterShield\Mcp\Pairing::state()['last_used'] > 0,
								// The applications holding a grant of their own.
								// One that signed in through the consent page,
								// the hub among them, needs no credential, so
								// "nothing paired" is not "nothing has access".
								'apps'      => count( \BetterShield\Mcp\OAuth::connected_apps() ),
								// The catalog the credential in hand would be
								// offered, which on a read-only pairing is
								// smaller than the one that exists.
								'tools'     => \BetterShield\Mcp\Manager::is_enabled() ? count( \BetterShield\Mcp\Tools::catalog( self::paired_scope() ) ) : 0,
							),
						)
					);
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::MANAGE );
				},
			)
		);

		// Taking the abilities as they are now as the baseline: the owner
		// saying an update's changes are expected, which asks for the session
		// as marking a file change expected does.
		register_rest_route( 'bettershield/v1', '/agent-surface/abilities/accept', array(
			'methods'             => \WP_REST_Server::CREATABLE,
			'permission_callback' => static function () {
				return Permissions::interactive_manage();
			},
			'callback'            => static function () {
				$accepted = \BetterShield\Abilities\Baseline::accept();

				if ( is_wp_error( $accepted ) ) {
					return $accepted;
				}

				return rest_ensure_response(
					array(
						'ability_changes' => \BetterShield\Abilities\Baseline::described(),
						'undo'            => $accepted['undo'],
					)
				);
			},
		) );

		// Bringing accepted changes back to wait for the owner again only
		// adds warnings, so the password is not asked.
		register_rest_route( 'bettershield/v1', '/agent-surface/abilities/accept/undo', array(
			'methods'             => \WP_REST_Server::CREATABLE,
			'permission_callback' => static function () {
				return Permissions::interactive_manage_if( false );
			},
			'args'                => array(
				'undo' => array( 'required' => true, 'type' => 'string', 'pattern' => '^[a-f0-9]{32}$', 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ),
			),
			'callback'            => static function ( \WP_REST_Request $request ) {
				$undone = \BetterShield\Abilities\Baseline::undo_accept( (string) $request['undo'] );

				if ( is_wp_error( $undone ) ) {
					return $undone;
				}

				return rest_ensure_response( array( 'ability_changes' => \BetterShield\Abilities\Baseline::described() ) );
			},
		) );

		register_rest_route( 'bettershield/v1', '/agent-surface/decoy-page', array(
			'methods' => \WP_REST_Server::CREATABLE,
			// Putting the page up adds a tripwire. Taking it down, or moving
			// it off the address it was at, takes one away, so only those
			// ask for the password again.
			'permission_callback' => static function ( \WP_REST_Request $request ) {
				$before = \BetterShield\Agents\DecoyPage::report();

				return Permissions::interactive_manage_if( $before['enabled'] && ( ! (bool) $request['enabled'] || $before['slug'] !== (string) $request['slug'] ) );
			},
			'args' => array(
				'enabled' => array( 'required' => true, 'type' => 'boolean', 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ),
				// Generous here, so a long path is answered with the length
				// rule rather than the generic "Invalid parameter(s)" (#2664).
				'slug' => array( 'default' => '', 'type' => 'string', 'maxLength' => 200, 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ),
			),
			'callback' => static function ( \WP_REST_Request $request ) {
				$result = \BetterShield\Agents\DecoyPage::save( (bool) $request['enabled'], (string) $request['slug'] );
				return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'decoy_page' => \BetterShield\Agents\DecoyPage::described() ) );
			},
		) );
		register_rest_route( 'bettershield/v1', '/agent-surface/decoy-page/test', array(
			'methods' => \WP_REST_Server::CREATABLE,
			// A check changes no protection, so the password is never asked.
			'permission_callback' => static function () {
				return Permissions::interactive_manage_if( false );
			},
			'callback' => static function () { return rest_ensure_response( \BetterShield\Agents\DecoyPage::test() ); },
		) );

		register_rest_route(
			'bettershield/v1',
			'/agent-surface/canary',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				/*
				 * Read from the body rather than declared as a required
				 * argument: core validates registered arguments *before* the
				 * permission callback, so a required one here would answer a
				 * caller with no business on this route with "you left out a
				 * field" instead of "no".
				 */
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					// A yes or a no: cast, the word "false" planted a decoy.
					if ( ! is_array( $body ) || ! is_bool( $body['plant'] ?? null ) ) {
						return new \WP_Error(
							'bettershield_missing_plant',
							__( 'Say whether to plant the decoy or remove it.', 'bettershield' ),
							array( 'status' => 400 )
						);
					}

					if ( ! $body['plant'] ) {
						Canary::remove();

						return rest_ensure_response( array( 'canary' => null ) );
					}

					$planted = Canary::plant( get_current_user_id() );

					return is_wp_error( $planted ) ? $planted : rest_ensure_response( array( 'canary' => Canary::planted() ) );
				},
				// Planting the decoy adds a tripwire, and planting it again
				// replaces it with a fresh one. Removing the one that is there
				// takes it away, so only that asks for the password again.
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					return Permissions::interactive_manage_if( is_array( $body ) && false === ( $body['plant'] ?? null ) && null !== Canary::planted() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agent-surface/expiry',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body   = $request->get_json_params();
					$result = ( new Expiry() )->update_settings( is_array( $body ) ? $body : array() );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'expiry' => $result ) );
				},
				// Interactive: switching this on starts revoking credentials,
				// and revoking one cannot be undone.
				'permission_callback' => static function () {
					return \BetterShield\Rest\Permissions::interactive_manage();
				},
			)
		);

		/*
		 * Holding an application password to what it is for, and taking that
		 * hold away. Adding a limit, or narrowing one, only narrows what a
		 * credential can reach, so it takes the capability. Changing one so it
		 * reaches more, removing one, or undoing a change widens it again, so
		 * those ask for the session and the password again, as taking any
		 * protection away does. A limited password can't lift its own.
		 *
		 * And whichever way it goes, a password and its limit belong to its
		 * account across the whole network, so managing this plugin is not
		 * the same as having any say over them. The account's own editor
		 * does, as core's routes for these passwords ask; on a network a
		 * site's administrator reaches that site's members, not every account
		 * the network holds. Asked after the capability, so a caller with no
		 * business here learns nothing about which accounts exist, and before
		 * the password again, so nobody types it to be refused.
		 */
		$password = '/agent-surface/app-passwords/(?P<user>\d+)/(?P<uuid>[a-f0-9-]{36})/limit';
		$account  = static function ( int $user_id ) {
			if ( ! Permissions::manage() ) {
				return false;
			}

			if ( ! get_userdata( $user_id ) instanceof \WP_User || ( is_multisite() && ! is_super_admin() && ! is_user_member_of_blog( $user_id ) ) ) {
				return new \WP_Error( 'bettershield_no_user', __( 'No such account.', 'bettershield' ), array( 'status' => 404 ) );
			}

			if ( ! current_user_can( 'edit_user', $user_id ) ) {
				return new \WP_Error( 'bettershield_cannot_edit_user', __( 'You cannot change this account.', 'bettershield' ), array( 'status' => 403 ) );
			}

			return true;
		};
		$answer   = static function ( $result ) {
			return is_wp_error( $result ) ? $result : rest_ensure_response(
				array_merge(
					(array) $result,
					array( 'application_passwords' => AgentSurface::application_passwords( true ) )
				)
			);
		};

		register_rest_route(
			'bettershield/v1',
			$password,
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) use ( $answer ) {
						return $answer( PasswordLimits::set( (int) $request['user'], (string) $request['uuid'], $request['routes'], (string) $request['range'] ) );
					},
					'permission_callback' => static function ( \WP_REST_Request $request ) use ( $account ) {
						$theirs = $account( (int) $request['user'] );

						if ( true !== $theirs ) {
							return $theirs;
						}

						return PasswordLimits::widens( (int) $request['user'], (string) $request['uuid'], $request['routes'], (string) $request['range'] )
							? Permissions::interactive_manage()
							: true;
					},
					'args'                => array(
						'routes' => array(
							'type'              => array( 'array', 'string' ),
							'items'             => array( 'type' => 'string' ),
							'default'           => array(),
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'range'  => array(
							'type'              => 'string',
							'default'           => '',
							'maxLength'         => 64,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
				array(
					'methods'             => \WP_REST_Server::DELETABLE,
					'callback'            => static function ( \WP_REST_Request $request ) use ( $answer ) {
						return $answer( PasswordLimits::remove( (int) $request['user'], (string) $request['uuid'] ) );
					},
					'permission_callback' => static function ( \WP_REST_Request $request ) use ( $account ) {
						$theirs = $account( (int) $request['user'] );

						return true === $theirs ? Permissions::interactive_manage() : $theirs;
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agent-surface/app-passwords/limit-undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $answer ) {
					$result = PasswordLimits::undo( (string) $request['token'] );

					return $answer( is_wp_error( $result ) ? $result : array( 'undone' => true ) );
				},
				// Asked of the account the change was made on. A record that
				// is not there is answered as one by the route itself.
				'permission_callback' => static function ( \WP_REST_Request $request ) use ( $account ) {
					$user   = PasswordLimits::undo_account( (string) $request['token'] );
					$theirs = 0 === $user ? Permissions::manage() : $account( $user );

					return true === $theirs ? Permissions::interactive_manage() : $theirs;
				},
				'args'                => array(
					'token' => array(
						'type'              => 'string',
						'required'          => true,
						'maxLength'         => 64,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}
}
