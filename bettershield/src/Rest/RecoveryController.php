<?php
/**
 * REST surface for safe mode and the recovery link.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RecoveryController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		// All three of the routes below are interactive acts, and an
		// application password — itself exempt from the sign-in gate — may
		// reach none of them. Minting a link or a set of codes hands out a
		// credential that pauses every protection on the site for an hour.
		// Ending safe mode closes the window an owner is in because they were
		// locked out, so only a person at a browser may do that, the same as
		// every other act that changes how the site is defended.
		$interactive_manage = static function () {
			return Permissions::interactive_manage();
		};

		register_rest_route( 'bettershield/v1', '/recovery/readiness', array(
			'methods' => \WP_REST_Server::CREATABLE,
			// Turning the weekly email check off is the one direction that
			// takes something away, so only that asks for the password again.
			'permission_callback' => static function ( \WP_REST_Request $request ) {
				$body = $request->get_json_params();

				return Permissions::interactive_manage_if( is_array( $body ) && false === ( $body['email_tests'] ?? null ) && \BetterShield\Recovery\Readiness::mail_enabled() );
			},
			'callback' => static function ( \WP_REST_Request $request ) {
				$body = $request->get_json_params();
				if ( ! is_array( $body ) || ! isset( $body['email_tests'] ) || ! is_bool( $body['email_tests'] ) ) {
					return new \WP_Error( 'bettershield_readiness_input', __( 'Say whether to enable weekly recovery email checks.', 'bettershield' ), array( 'status' => 400 ) );
				}
				if ( ! \BetterShield\Recovery\Readiness::set_mail_enabled( $body['email_tests'] ) ) {
					return new \WP_Error( 'bettershield_readiness_save', __( 'The email-check preference could not be saved. Try again.', 'bettershield' ), array( 'status' => 500 ) );
				}
				return rest_ensure_response( array( 'overview' => OverviewController::screen_payload() ) );
			},
		) );
		register_rest_route( 'bettershield/v1', '/recovery/readiness/check', array(
			'methods' => \WP_REST_Server::CREATABLE,
			// A check changes no protection, so the password is never asked.
			'permission_callback' => static function () {
				return Permissions::interactive_manage_if( false );
			},
			'callback' => static function () {
				if ( ! \BetterShield\Support\Claim::claim( 'recovery_readiness_check', MINUTE_IN_SECONDS ) ) {
					return new \WP_Error( 'bettershield_readiness_paced', __( 'Recovery was checked recently. Wait a minute before checking again.', 'bettershield' ), array( 'status' => 429 ) );
				}
				\BetterShield\Recovery\Readiness::run_now();
				return rest_ensure_response( array( 'overview' => OverviewController::screen_payload() ) );
			},
		) );

		register_rest_route(
			'bettershield/v1',
			'/recovery/regenerate',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					// The URL appears in this response exactly once; only
					// its hash persists server-side.
					$url = RecoveryLink::generate();

					// A link whose hash did not land opens nothing, so none
					// is shown: the previous link is still the one on record.
					if ( null === $url ) {
						return new \WP_Error(
							'bettershield_recovery_link_failed',
							__( 'The recovery link could not be stored, so none was issued. Try again.', 'bettershield' ),
							array( 'status' => 503 )
						);
					}

					// The overview travels back with it because generating
					// moves recovery_link_exists. A screen left saying no
					// link exists would invite the owner to generate a
					// second one, silently retiring the link they just
					// stored.
					return rest_ensure_response(
						array(
							'url'      => $url,
							'overview' => OverviewController::screen_payload(),
						)
					);
				},
				'permission_callback' => $interactive_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/recovery/codes',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					// The codes appear in this response exactly once; only
					// their hashes persist. Issuing a set replaces whatever
					// was there, which the screen says before it is pressed.
					$codes = OfflineCodes::issue();

					if ( array() === $codes ) {
						return new \WP_Error(
							'bettershield_offline_codes_failed',
							__( 'The codes could not be stored, so none were issued. Try again.', 'bettershield' ),
							array( 'status' => 503 )
						);
					}

					return rest_ensure_response(
						array(
							'codes'        => $codes,
							// Where a code is used, so the printed sheet says it
							// beside them: paper kept off the site has to carry
							// the address it is for.
							'code_address' => \BetterShield\Recovery\RecoveryLink::code_address(),
							'overview'     => OverviewController::screen_payload(),
						)
					);
				},
				'permission_callback' => $interactive_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/safe-mode/end',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					/*
					 * Only the network's pause running: this site cannot end
					 * it, and answering that it had ended left every site
					 * paused for the hour behind a control that said it was
					 * over.
					 */
					if ( ! SafeMode::is_site_active() && SafeMode::is_network_active() ) {
						return new \WP_Error(
							'bettershield_network_safe_mode',
							__( 'Protection is paused network-wide, so it can only be ended in Network Admin › BetterShield. It also resumes on its own.', 'bettershield' ),
							array( 'status' => 409 )
						);
					}

					SafeMode::end( 'manual' );

					return rest_ensure_response(
						array(
							'ended'           => true,
							// The network's pause can be running as well.
							'network_paused'  => SafeMode::is_network_active(),
						)
					);
				},
				// Ending safe mode slams the recovery window shut — the state
				// an owner is in because they were locked out. Only a person
				// at a browser may do that, same as every other weakening act.
				'permission_callback' => $interactive_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/lockdown',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( array( 'lockdown' => self::lockdown_for_screen( \BetterShield\Recovery\Lockdown::state() ) ) );
					},
					'permission_callback' => static function (): bool {
						return current_user_can( \BetterShield\Capabilities::MANAGE );
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						// A yes or a no: cast, the word "false" locked the site
						// down and signed everybody else out, and "0" lifted it.
						if ( ! is_array( $body ) || ! is_bool( $body['active'] ?? null ) ) {
							return new \WP_Error(
								'bettershield_missing_active',
								__( 'Say whether to lock the site down or lift the lockdown.', 'bettershield' ),
								array( 'status' => 400 )
							);
						}

						if ( ! $body['active'] ) {
							$left = \BetterShield\Recovery\Lockdown::leave( 'manual' );

							return is_wp_error( $left ) ? $left : rest_ensure_response( array( 'lockdown' => self::lockdown_for_screen( $left ) ) );
						}

						$entered = \BetterShield\Recovery\Lockdown::enter( get_current_user_id() );

						return is_wp_error( $entered ) ? $entered : rest_ensure_response( array( 'lockdown' => self::lockdown_for_screen( $entered ) ) );
					},
					/*
					 * Both directions are a person's act. Throwing it signs
					 * everybody else out and closes the site; lifting it opens
					 * a site somebody closed because it was under attack, and
					 * a credential that could do the second is a credential
					 * that could undo the response to its own theft.
					 *
					 * Both directions ask for the password again. Lifting it
					 * takes a protection away; throwing it ends every other
					 * dashboard session, which is what "Sign Out Everyone"
					 * does, and that asks. A lockdown that did not would be
					 * the way around it.
					 */
					'permission_callback' => $interactive_manage,
				),
			)
		);
	}

	/**
	 * The lockdown, and whether its sign-out stops at this site's own accounts
	 * for the person asking, so the screen says so before it is pressed.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>
	 */
	private static function lockdown_for_screen( array $state ): array {
		return $state + array( 'site_accounts_only' => is_multisite() && ! current_user_can( 'manage_network_users' ) );
	}
}
