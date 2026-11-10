<?php
/**
 * REST surface for the vulnerability check: its state, the owner's consent
 * to the one outside call it makes, and a check on demand.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Vulnerabilities\Scanner;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnerabilitiesController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'routes' ) );
	}

	public function routes(): void {
		$read = static function (): bool {
			return current_user_can( Capabilities::READ_POSTURE );
		};
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
			'/vulnerabilities',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( Scanner::summary() );
				},
				'permission_callback' => $read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/vulnerabilities/consent',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();
					if ( ! is_array( $body ) || ! is_bool( $body['enabled'] ?? null ) || array_diff( array_keys( $body ), array( 'enabled' ) ) ) {
						return new \WP_Error( 'invalid_consent', __( 'Choose whether to enable vulnerability checks.', 'bettershield' ), array( 'status' => 400 ) );
					}
					Scanner::set_consent( $body['enabled'] );

					// A change here changes what the findings may say; refresh
					// them so the screen never shows a state the owner just left.
					Auditor::run();

					return rest_ensure_response( Scanner::summary() );
				},
				'permission_callback' => $interactive_manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/vulnerabilities/check',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					$result = Scanner::run();
					Auditor::run();

					return rest_ensure_response( array( 'result' => $result ) + Scanner::summary() );
				},
				'permission_callback' => $manage,
			)
		);
	}
}
