<?php
/**
 * The release notes an account has read.
 *
 * The first-run panel this controller also served is gone; the Quick Setup
 * that replaced it has routes of its own.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Onboarding\Release;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OnboardingController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/release/seen',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					/*
					 * A version, and nothing else. The value is stored against
					 * the account, and core's default sanitizer for a plain
					 * string is a cast — so without a shape and a length this
					 * is an unbounded value from a request landing in a
					 * longtext column, on the lowest capability this plugin
					 * grants. Both keywords are inside the subset core's
					 * schema validator implements.
					 *
					 * The validator is named rather than assumed: a route
					 * registered directly gets no callback of its own, so a
					 * schema written without one describes the parameter and
					 * enforces nothing about it.
					 */
					'version' => array(
						'type'              => 'string',
						'required'          => true,
						'pattern'           => '^[0-9]+(\\.[0-9]+){0,3}$',
						'maxLength'         => 20,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					Release::dismiss( (string) $request->get_param( 'version' ) );

					return rest_ensure_response( array( 'dismissed' => true ) );
				},
				// Per person rather than per site: dismissing this says "I have
				// read it", which is not a thing one administrator can say on
				// another's behalf. It changes nothing about the site, so it
				// asks only for the capability that reaches the screen.
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
			)
		);
	}
}
