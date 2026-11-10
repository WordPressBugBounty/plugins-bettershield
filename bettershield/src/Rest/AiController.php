<?php
/**
 * REST surface for AI explanations.
 *
 * Both routes take the manage capability rather than the posture-reading one.
 * Asking for an explanation spends the owner's own AI credit at their own
 * provider, and spending somebody's money is not a read.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Ai\Explainer;
use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AiController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		// Drafting a write-up removes no protection: a person's own session,
		// never the password again.
		register_rest_route( 'bettershield/v1', '/ai/incidents/(?P<id>\d+)', array(
			array( 'methods' => 'GET', 'permission_callback' => array( Permissions::class, 'manage' ), 'args' => array( 'id' => array( 'type' => 'integer', 'minimum' => 1, 'sanitize_callback' => 'rest_sanitize_request_arg', 'validate_callback' => 'rest_validate_request_arg' ) ), 'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Ai\Incident::preview( $r['id'] ) ),
			array( 'methods' => 'POST', 'permission_callback' => static fn() => Permissions::interactive_manage_if( false ), 'args' => array( 'id' => array( 'type' => 'integer', 'minimum' => 1, 'sanitize_callback' => 'rest_sanitize_request_arg', 'validate_callback' => 'rest_validate_request_arg' ), 'evidence_hash' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'required' => true, 'sanitize_callback' => 'rest_sanitize_request_arg', 'validate_callback' => 'rest_validate_request_arg' ), 'client' => array( 'type' => 'boolean', 'default' => false, 'sanitize_callback' => 'rest_sanitize_request_arg', 'validate_callback' => 'rest_validate_request_arg' ) ), 'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Ai\Incident::explain( $r['id'], $r['client'], $r['evidence_hash'] ) ),
		) );
		$manage = static function (): bool {
			return current_user_can( Capabilities::MANAGE );
		};

		register_rest_route(
			'bettershield/v1',
			'/ai/status',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					$status = Explainer::availability();

					// Whether the feature works here, and what it has cost so
					// far this month. The screen shows the second beside the
					// first, because a feature that spends the owner's own
					// credit should say how much of it has gone.
					$status['usage'] = Explainer::usage();

					// Where a provider is set up, for somebody who may open
					// that screen: the notice names it, and the row links it.
					$status['connectors_url'] = Explainer::REASON_NO_PROVIDER === $status['reason'] && current_user_can( 'manage_options' )
						? admin_url( 'options-connectors.php' )
						: '';

					// And what one account may ask for in an hour, so the card
					// can name the cap rather than leaving somebody to meet it
					// in a refusal. Null where nothing caps it: zero would
					// read as a cap of none.
					$per_hour = Explainer::budget_per_hour();

					$status['budget'] = array(
						'per_hour' => 0 === $per_hour ? null : $per_hour,
					);

					return rest_ensure_response( $status );
				},
				'permission_callback' => $manage,
			)
		);

		// The open findings explained together, as one ask against the same
		// hourly allowance; a kept answer when the findings have not moved.
		register_rest_route(
			'bettershield/v1',
			'/ai/summary',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$result = \BetterShield\Ai\Summary::explain();

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/ai/explain/(?P<finding>[a-z0-9_]+)',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Explainer::explain( sanitize_key( (string) $request->get_param( 'finding' ) ) );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
			)
		);
	}
}
