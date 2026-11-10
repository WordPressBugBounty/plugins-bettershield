<?php
/**
 * REST surface for the agent activity record.
 *
 * Gated on the activity capability rather than the manage one, for the same
 * reason the activity log is: reading the record is a different privilege
 * from changing the site, and separating them is what lets an owner hand
 * somebody the record without handing them the controls.
 *
 * The one route that writes — the capture switch — takes the interactive
 * guard instead. Turning the record off is a protection being taken away,
 * and a token may not do it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Agents\Capture;
use BetterShield\Agents\Invocations;
use BetterShield\Capabilities;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AgentActivityController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * The filters, shared by the listing and the counts so one cannot narrow
	 * the record differently from the other.
	 *
	 * Every one names a validator as well as a sanitizer: core runs a
	 * validator only where the argument names one, so a schema written with a
	 * hand-rolled sanitizer alone describes a shape and enforces none of it.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function filter_args(): array {
		$key = array(
			'type'              => 'string',
			'required'          => false,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'sanitize_key',
		);

		$text = array(
			'type'              => 'string',
			'required'          => false,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'sanitize_text_field',
		);

		return array(
			// One of the outcomes the record can hold, as the ability that
			// reads the same rows already requires. Anything else is the
			// request being wrong rather than a filter quietly dropped.
			'outcome'    => array_merge( $key, array( 'enum' => array_merge( array( '' ), Capture::OUTCOMES ) ) ),
			'ability'    => $text,
			'namespace'  => $text,
			// One of the doors a row can name, for the same reason.
			'entry_path' => array_merge( $key, array( 'enum' => array_merge( array( '' ), \BetterShield\Events\Writer::ENTRIES ) ) ),
			// The connection a call came in on (#2213).
			'connection' => $text,
			// The account a call ran as.
			'user'       => array(
				'type'              => 'integer',
				'required'          => false,
				'minimum'           => 1,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'absint',
			),
		);
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/agent-activity',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'list_invocations' ),
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_ACTIVITY );
				},
				'args'                => array_merge(
					array(
						// A row id, so anything that is not a number is the
						// request being wrong rather than a silent zero that
						// quietly hands back the first page again.
						'cursor' => array(
							'type'              => 'integer',
							'required'          => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'absint',
						),
					),
					self::filter_args()
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/agent-activity/capture',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				/*
				 * Read from the body rather than declared as a required
				 * argument: core validates registered arguments before the
				 * permission callback, so a required one here would answer a
				 * caller with no business on this route with "you left out a
				 * field" instead of "no".
				 *
				 * A yes or a no, and nothing else: cast, the word "false" was
				 * a yes and switched recording on, while "0" switched it off.
				 */
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					if ( ! is_array( $body ) || ! is_bool( $body['enabled'] ?? null ) ) {
						return new \WP_Error(
							'bettershield_missing_enabled',
							__( 'Say whether to record agent activity or stop recording it.', 'bettershield' ),
							array( 'status' => 400 )
						);
					}

					$saved = Capture::set_enabled( $body['enabled'] );

					if ( is_wp_error( $saved ) ) {
						return $saved;
					}

					return rest_ensure_response( array( 'capture_enabled' => Capture::is_enabled() ) );
				},
				// Switching the record off is a protection coming down, and
				// only that asks for the password again.
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					return Permissions::interactive_manage_if( is_array( $body ) && false === ( $body['enabled'] ?? null ) && Capture::is_enabled() );
				},
			)
		);
	}

	public function list_invocations( \WP_REST_Request $request ): \WP_REST_Response {
		$filters = array(
			'outcome'    => (string) $request->get_param( 'outcome' ),
			'ability'    => (string) $request->get_param( 'ability' ),
			'namespace'  => (string) $request->get_param( 'namespace' ),
			'entry_path' => (string) $request->get_param( 'entry_path' ),
			'user'       => (int) $request->get_param( 'user' ),
			'connection' => (string) $request->get_param( 'connection' ),
		);

		$page = Invocations::page(
			array_merge(
				$filters,
				array( 'cursor' => (int) $request->get_param( 'cursor' ) )
			)
		);

		return rest_ensure_response(
			array(
				'invocations'      => $page['invocations'],
				'next_cursor'      => $page['next_cursor'],
				// The outcome facet counts against the other filters, never
				// against itself.
				'counts'           => Invocations::counts( $filters ),
				'namespaces'       => Invocations::namespaces(),
				'connections'      => Invocations::connections(),
				'capture_available' => Capture::is_available(),
				'capture_enabled'  => Capture::is_enabled(),
				'requires_wp'      => Capture::REQUIRES_WP,
				'retention_days'   => Tier::retention_days(),
			)
		);
	}
}
