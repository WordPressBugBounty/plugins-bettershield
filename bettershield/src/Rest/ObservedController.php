<?php
/** Interactive observed-change review and response. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Rest;
use BetterShield\Remediation\Observed;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class ObservedController {
	public function register(): void { add_action( 'rest_api_init', array( $this, 'routes' ) ); }
	private static function arg( array $schema ): array { return $schema + array( 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ); }
	public function routes(): void {
		register_rest_route( 'bettershield/v1', '/observed-changes', array(
			array( 'methods' => \WP_REST_Server::READABLE, 'permission_callback' => array( Permissions::class, 'manage' ), 'callback' => static fn( \WP_REST_Request $r ) => rest_ensure_response( Observed::listing( $r['cursor'] ?? PHP_INT_MAX ) ), 'args' => array( 'cursor' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ) ) ),
			array( 'methods' => \WP_REST_Server::CREATABLE, 'permission_callback' => array( Permissions::class, 'interactive_manage' ), 'callback' => static fn( \WP_REST_Request $r ) => rest_ensure_response( Observed::settings( $r['enabled'] ) ), 'args' => array( 'enabled' => self::arg( array( 'type' => 'boolean', 'required' => true ) ) ) ),
		) );
		register_rest_route( 'bettershield/v1', '/observed-changes/(?P<token>[a-f0-9]{32})', array(
			array( 'methods' => \WP_REST_Server::READABLE, 'permission_callback' => array( Permissions::class, 'manage' ), 'callback' => static fn( \WP_REST_Request $r ) => rest_ensure_response( Observed::view( (string) $r['token'] ) ) ),
			array( 'methods' => \WP_REST_Server::CREATABLE, 'permission_callback' => array( Permissions::class, 'interactive_manage' ), 'callback' => static fn( \WP_REST_Request $r ) => rest_ensure_response( Observed::act( (string) $r['token'], $r['action'], $r['revision'] ) ), 'args' => array( 'action' => self::arg( array( 'type' => 'string', 'enum' => array( 'apply', 'undo' ), 'required' => true ) ), 'revision' => self::arg( array( 'type' => 'string', 'pattern' => '^[a-f0-9]{64}$', 'required' => true ) ) ) ),
		) );
	}
}
