<?php
/**
 * REST surface for alerting: the settings, a deliberate send, and the signal
 * that says an alert was not worth sending.
 *
 * The feedback route is the one worth explaining. An alert email could carry a
 * one-click "not helpful" link straight back to the site, and that link would
 * have to work for someone who is not signed in — which means a token in an
 * inbox that mutates state, and a way to record feedback for a site by guessing
 * a URL. Instead the mail links to the finding, and the control lives on the
 * screen the reader lands on, behind the same capability as everything else.
 * The measurement survives; the login-free write does not.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Alerts\Mailer;
use BetterShield\Alerts\Maintenance;
use BetterShield\Alerts\Notifier;
use BetterShield\Alerts\Precision;
use BetterShield\Alerts\Settings;
use BetterShield\Capabilities;
use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AlertsController {

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
			'/settings/alerts',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( self::payload() );
					},
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						$result = Settings::instance()->update_settings( is_array( $body ) ? $body : array() );

						if ( is_wp_error( $result ) ) {
							return $result;
						}

						// Muting is what the delivery check reads; the other
						// switches here change no check's answer.
						if ( is_array( $body ) && array_key_exists( 'muted', $body ) ) {
							\BetterShield\Audit\Auditor::run();
						}

						return rest_ensure_response( self::payload() );
					},
					// A session either way; the password again only when the
					// save makes the site quieter — muted, a summary or the
					// instant alert off, or somebody no longer told.
					'permission_callback' => static function ( \WP_REST_Request $request ) {
						$body = $request->get_json_params();

						return Permissions::interactive_manage_if( Settings::instance()->weakens( is_array( $body ) ? $body : array() ) );
					},
				),
			)
		);

		register_rest_route( 'bettershield/v1', '/alerts/maintenance', array(
			'methods' => \WP_REST_Server::CREATABLE,
			'permission_callback' => $interactive_manage,
			'args' => array( 'minutes' => array( 'type' => 'integer', 'enum' => array( 30, 60, 120, 240 ), 'required' => true, 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ) ),
			'callback' => static function ( \WP_REST_Request $request ) {
				$result = Maintenance::start( (int) $request['minutes'] );
				return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'alerts' => self::payload() ) );
			},
		) );
		register_rest_route( 'bettershield/v1', '/alerts/maintenance/end', array(
			'methods' => \WP_REST_Server::CREATABLE,
			'permission_callback' => $interactive_manage,
			'callback' => static function () {
				$result = Maintenance::end();
				return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'alerts' => self::payload() ) );
			},
		) );

		register_rest_route(
			'bettershield/v1',
			'/alerts/digest',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function (): \WP_REST_Response {
						$outcome = Notifier::digest_now();

						return rest_ensure_response(
							array(
								'sent'    => 'sent' === $outcome,
								// What became of the press: sent, refused,
								// too_soon, just_tried, muted, no_recipient or
								// no_digest_recipient. A send
								// declined because one just went out is not a
								// mail server refusing it.
								'outcome' => $outcome,
								'alerts'  => self::payload(),
							)
						);
					},
					// The same capability as changing the settings: sending mail
					// from someone else's site is a change, whatever it is called.
					'permission_callback' => $manage,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/alerts/feedback',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback' => static function ( \WP_REST_Request $request ) {
						$result = Precision::feedback( (string) $request['delivery'] );
						return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
					},
					'args' => array( 'delivery' => array( 'type' => 'string', 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg', 'required' => true, 'pattern' => '^[0-9a-f]{32}$' ) ),
					'permission_callback' => $manage,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/alerts/test',
			array(
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function (): \WP_REST_Response {
						// The exact path a live alert takes, and the honest
						// three-way answer: sent, refused by the mail server,
						// muted, or nowhere to send. Changes nothing.
						return rest_ensure_response( Mailer::test() );
					},
					'permission_callback' => $manage,
				),
			)
		);
	}

	/**
	 * The settings, plus the two things the screen needs to tell the truth
	 * about them: where messages actually go when nobody has named an address,
	 * and how the alerts sent so far have been received.
	 *
	 * @return array<string, mixed>
	 */
	private static function payload(): array {
		$settings = Settings::instance();

		return array_merge(
			$settings->settings(),
			array(
				/*
				 * Whether alerts are muted here, not whether the switch was
				 * last saved on: a mute a staging answer set stops applying on
				 * the copy's new address, and alerts are sent there while the
				 * stored switch still read on. Saving writes what is shown.
				 */
				'muted'                => $settings->is_muted(),
				'staging_mute_lapsed'  => $settings->settings()['muted'] && ! $settings->is_muted(),
				'effective_recipients' => $settings->recipients(),
				'precision'            => Precision::rate(),
				'maintenance'          => Maintenance::report(),
				// So the field can stop at the limit rather than learn it
				// from a refusal.
				'max'                  => Settings::MAX_RECIPIENTS,
				// The types that have sent an instant email here, to choose
				// which of them wait for the weekly summary instead.
				'instant_types'        => $settings->instant_types(),
			)
		);
	}
}
