<?php
/**
 * REST surface for the password policy, the uninstall choice, and the
 * agent-abilities opt-in.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Disclosure\SecurityTxt;
use BetterShield\Password\Policy;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasswordPolicyController {

	/** How many of each settings area's changes the undo list holds until a wider window is asked for. */
	private const UNDO_WINDOW = 20;

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
			'/settings/password-policy',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response(
							array_merge(
								Policy::instance()->settings(),
								// What the plugin recommends, so a number
								// somebody changed has a way back to it. Under
								// its own key rather than beside the values, so
								// nothing here can be mistaken for a setting.
								array( 'defaults' => Policy::instance()->defaults() )
							)
						);
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						$result = Policy::instance()->update_settings( is_array( $body ) ? $body : array() );

						// A check reads the policy: audit with it now, and the
						// screen reads the findings again.
						if ( ! is_wp_error( $result ) ) {
							\BetterShield\Audit\Auditor::run();
						}

						// Answered with the defaults as the read is: the screen
						// keeps what a save answers with, and without them every
						// "Default: … / Use it" hint went until a reload.
						return is_wp_error( $result ) ? $result : rest_ensure_response( array_merge( $result, array( 'defaults' => Policy::instance()->defaults() ) ) );
					},
					// A session either way; the password again only when the
					// save lowers the bar.
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( Policy::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/security-txt',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( SecurityTxt::instance()->settings() );
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body   = $request->get_json_params();
						$result = SecurityTxt::instance()->update_settings( is_array( $body ) ? $body : array() );

						// A check reads when the published contact lapses.
						if ( ! is_wp_error( $result ) ) {
							\BetterShield\Audit\Auditor::run();
						}

						return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
					},
					/*
					 * Publishing a contact adds something; withdrawing one takes
					 * away the only way a finder knows where to send what they
					 * found. One route does both: a session either way, and the
					 * password again only for withdrawing it, or for replacing
					 * the address a finder would write to.
					 */
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( SecurityTxt::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/uninstall',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( \BetterShield\Support\UninstallChoice::state() );
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					/*
					 * Declared, so core refuses a shape this cannot read
					 * rather than casting it. An array cast to a string is
					 * "Array", which `normalize()` does not recognize and
					 * therefore reads as keeping everything — so a client
					 * sending the wrong shape moved the owner's setting to
					 * the opposite end of the choice and got a 200 for it.
					 */
					'args'                => array(
						'choice'      => array(
							'type'              => 'string',
							'enum'              => array(
								\BetterShield\Support\UninstallChoice::KEEP,
								\BetterShield\Support\UninstallChoice::REMOVE,
								\BetterShield\Support\UninstallChoice::PACKAGE,
							),
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
						'remove_data' => array(
							'type'              => 'boolean',
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_request_arg',
						),
					),
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();
						$body = is_array( $body ) ? $body : array();

						/*
						 * Three answers now, sent by name. A body carrying only
						 * the boolean is still the two answers it always was,
						 * which is what keeps a client written against the
						 * earlier shape saying what it meant.
						 */
						if ( is_string( $body['choice'] ?? null ) ) {
							$saved = \BetterShield\Support\UninstallChoice::set_choice( $body['choice'] );
						} else {
							$saved = \BetterShield\Support\UninstallChoice::set_remove_data( rest_sanitize_boolean( $body['remove_data'] ?? false ) );
						}

						return is_wp_error( $saved ) ? $saved : rest_ensure_response( \BetterShield\Support\UninstallChoice::state() );
					},
					'permission_callback' => $interactive_manage,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/sudo',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( array( 'enabled' => Sudo::enabled() ) );
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						/*
						 * A yes or a no, and nothing else. Read as a no, a body that
						 * named nothing, or misspelled the key, switched the gate off
						 * and answered 200: the one direction a typo must never move
						 * it. Checked here rather than declared as an argument, as
						 * the capture and decoy routes do, because core checks
						 * declared arguments before the permission callback, and a
						 * caller with no business here should hear no, not which
						 * field it left out.
						 */
						if ( ! is_array( $body ) || ! is_bool( $body['enabled'] ?? null ) ) {
							return new \WP_Error(
								'bettershield_missing_enabled',
								__( 'Say whether to ask for the password before removing a protection.', 'bettershield' ),
								array( 'status' => 400 )
							);
						}

						$saved = Sudo::set_enabled( $body['enabled'] );

						return is_wp_error( $saved ) ? $saved : rest_ensure_response( array( 'enabled' => Sudo::enabled() ) );
					},
					// One route both arms the gate and stands it down, so it
					// takes the stricter rule: standing it down is weakening.
					'permission_callback' => $interactive_manage,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/abilities',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response(
							array(
								'enabled'           => \BetterShield\Abilities\Registrar::is_enabled(),
								// Below WordPress 6.9 there is no Abilities API;
								// the screen shows the calm requires-notice
								// instead of a toggle that could do nothing.
								'available'         => \BetterShield\Abilities\Registrar::is_available(),
								/*
								 * Recording what agents do is a separate
								 * decision from letting them read this site,
								 * and the two are separate toggles because
								 * they answer different questions. A site can
								 * refuse every agent and still want the record
								 * of what tried.
								 */
								'capture_enabled'   => \BetterShield\Agents\Capture::is_enabled(),
								'capture_available' => \BetterShield\Agents\Capture::is_available(),
								'capture_requires'  => \BetterShield\Agents\Capture::REQUIRES_WP,
							)
						);
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						// A yes or a no, as the password gate above reads it: an
						// empty body took agent reading away, and agent changes
						// with it, and answered 200.
						if ( ! is_array( $body ) || ! is_bool( $body['enabled'] ?? null ) ) {
							return new \WP_Error(
								'bettershield_missing_enabled',
								__( 'Say whether an agent may read this site’s security information.', 'bettershield' ),
								array( 'status' => 400 )
							);
						}

						$enabled = $body['enabled'];

						$saved = \BetterShield\Abilities\Registrar::set_enabled( $enabled );

						if ( is_wp_error( $saved ) ) {
							return $saved;
						}

						return rest_ensure_response(
							array(
								'enabled'           => $enabled,
								'available'         => \BetterShield\Abilities\Registrar::is_available(),
								'capture_enabled'   => \BetterShield\Agents\Capture::is_enabled(),
								'capture_available' => \BetterShield\Agents\Capture::is_available(),
								'capture_requires'  => \BetterShield\Agents\Capture::REQUIRES_WP,
							)
						);
					},
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						// Agent reading off, which takes changes with it, is
						// never asked for the password; on is (#1820).
						$body = $request->get_json_params();

						return Permissions::interactive_manage_access( ! ( is_array( $body ) && false === ( $body['enabled'] ?? null ) ) );
					},
				),
			)
		);

		/*
		 * The settings undo list, and putting one back.
		 *
		 * Reading is a read. Putting a change back is a change like any other
		 * — it can take a protection away as easily as restore one, since what
		 * it restores is whatever was there before — so it sits on the same
		 * side of the interactive line as the saves it reverses.
		 *
		 * Both are this site's own history and nothing else. The policies a
		 * network sets for every site under it are recorded in the main site's
		 * table, so on the main site the two lists share one table; the scope
		 * is named here so this pair reaches a site's records and never the
		 * network's, whose own screen has the capability for them.
		 */
		$window = array(
			'description'       => __( 'How many of each settings area’s changes to list, newest first.', 'bettershield' ),
			'type'              => 'integer',
			'default'           => self::UNDO_WINDOW,
			'minimum'           => 1,
			'maximum'           => SettingsLedger::MOST_LISTED,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'rest_sanitize_request_arg',
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/undo',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn( \WP_REST_Request $request ): \WP_REST_Response => rest_ensure_response( self::undo_list( (int) $request['limit'] ) ),
				'permission_callback' => $manage,
				'args'                => array( 'limit' => $window ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/undo/(?P<token>[a-f0-9]{32})',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$done = SettingsLedger::revert( (string) $request['token'], SettingsLedger::SCOPE_SITE );

					if ( is_wp_error( $done ) ) {
						return $done;
					}

					// The setting put back may be one a check reads.
					\BetterShield\Audit\Auditor::run();

					return rest_ensure_response( self::undo_list( (int) $request['limit'] ) );
				},
				'permission_callback' => $interactive_manage,
				'args'                => array( 'limit' => $window ),
			)
		);
	}

	/**
	 * The undo list in a window, and how many changes there are in all, so a
	 * screen showing some can say how many more there are and ask for them,
	 * and whether the window is already the widest this route reads.
	 *
	 * @param int $limit How many of each settings area's changes to list.
	 * @return array{changes: array<int, array<string, mixed>>, total: int, widest: bool}
	 */
	private static function undo_list( int $limit ): array {
		$limit = $limit > 0 ? $limit : self::UNDO_WINDOW;

		return array(
			'changes' => SettingsLedger::recent( $limit, SettingsLedger::SCOPE_SITE ),
			'total'   => SettingsLedger::revertible_total( SettingsLedger::SCOPE_SITE ),
			'widest'  => $limit >= SettingsLedger::MOST_LISTED,
		);
	}
}
