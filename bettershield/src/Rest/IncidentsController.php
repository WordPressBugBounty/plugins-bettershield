<?php
/** Owner incident inventory and explicit lifecycle changes. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Rest;
use BetterShield\Incidents\Engine;
use BetterShield\Incidents\Repository;
use BetterShield\Capabilities;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class IncidentsController {
	public function register(): void { add_action( 'rest_api_init', array( $this, 'register_routes' ) ); }
	private static function arg( array $schema ): array { return $schema + array( 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ); }
	public function register_routes(): void {
		/*
		 * Preparing a plan, changing an incident's status and refreshing its
		 * evidence read, label or recorrelate; none removes a protection. They
		 * ask for a person's own session and never for the password again,
		 * which stays on applying and undoing a plan.
		 */
		$labels = static fn() => Permissions::interactive_manage_if( false );
		if ( is_multisite() ) {
			register_rest_route( 'bettershield/v1', '/network/incidents', array(
				'methods' => 'GET',
				'permission_callback' => static fn(): bool => Permissions::network_read(),
				'args' => array( 'cursor' => self::arg( array( 'type' => 'integer', 'minimum' => 0, 'default' => 0 ) ) ),
				'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Network::page( $r['cursor'] ),
			) );
		}

		register_rest_route( 'bettershield/v1', '/incidents/(?P<id>\d+)/response', array(
			'methods' => 'POST', 'permission_callback' => $labels,
			'args' => array( 'id' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ) ),
			'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::prepare( $r['id'] ),
		) );
		register_rest_route( 'bettershield/v1', '/incidents/(?P<id>\d+)/response', array(
			'methods' => 'GET', 'permission_callback' => array( Permissions::class, 'manage' ),
			'args' => array( 'id' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ) ),
			'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::latest( $r['id'] ),
		) );
		register_rest_route( 'bettershield/v1', '/incidents/(?P<id>\d+)/response/history', array(
			'methods' => 'GET', 'permission_callback' => array( Permissions::class, 'manage' ),
			'args' => array( 'id' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ), 'cursor' => self::arg( array( 'type' => 'integer', 'minimum' => 0, 'default' => 0 ) ) ),
			'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::history( $r['id'], $r['cursor'] ),
		) );

		$token = self::arg( array( 'type' => 'string', 'pattern' => '^[a-f0-9]{32}$' ) );
		register_rest_route( 'bettershield/v1', '/incident-response/(?P<token>[a-f0-9]{32})', array(
			array( 'methods' => 'GET', 'permission_callback' => array( Permissions::class, 'manage' ), 'args' => array( 'token' => $token ), 'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::view( $r['token'] ) ),
			array( 'methods' => 'POST', 'permission_callback' => array( Permissions::class, 'interactive_manage' ), 'args' => array( 'token' => $token, 'selected' => self::arg( array( 'type' => 'array', 'items' => array( 'type' => 'string', 'maxLength' => 80 ), 'minItems' => 1, 'maxItems' => 20, 'required' => true ) ) ), 'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::apply( $r['token'], $r['selected'] ) ),
		) );
		// A second look after a plan ran: the audit, one bounded piece of the
		// file check, and each target read against its state before. It
		// changes nothing on the site, so it asks what running an audit asks.
		register_rest_route( 'bettershield/v1', '/incident-response/(?P<token>[a-f0-9]{32})/recheck', array(
			'methods' => 'POST', 'permission_callback' => array( Permissions::class, 'manage' ),
			'args' => array( 'token' => $token ),
			'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Recheck::run( $r['token'] ),
		) );
		register_rest_route( 'bettershield/v1', '/incident-response/(?P<token>[a-f0-9]{32})/undo', array(
			'methods' => 'POST', 'permission_callback' => array( Permissions::class, 'interactive_manage' ),
			'args' => array( 'token' => $token, 'item' => self::arg( array( 'type' => 'string', 'maxLength' => 80, 'required' => true ) ) ),
			'callback' => static fn( \WP_REST_Request $r ) => \BetterShield\Incidents\Response::undo( $r['token'], $r['item'] ),
		) );
		$read = static fn(): bool => current_user_can( Capabilities::READ_ACTIVITY );
		register_rest_route( 'bettershield/v1', '/incidents', array(
			'methods' => 'GET', 'permission_callback' => $read,
			'args' => array( 'status' => self::arg( array( 'type' => 'string', 'enum' => array( 'open', 'resolved' ), 'default' => 'open' ) ), 'cursor' => self::arg( array( 'type' => 'integer', 'minimum' => 0, 'default' => 0 ) ) ),
			'callback' => static function ( \WP_REST_Request $r ) {
				$result = Repository::page( $r['status'], $r['cursor'] );
				return is_wp_error( $result ) ? $result : rest_ensure_response( $result + array( 'counts' => Repository::status_counts(), 'engine' => Engine::report(), 'can_manage' => current_user_can( Capabilities::MANAGE ) ) );
			},
		) );
		register_rest_route( 'bettershield/v1', '/incidents/(?P<id>\d+)', array(
			'methods' => 'GET', 'permission_callback' => $read,
			'args' => array( 'id' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ), 'cursor' => self::arg( array( 'type' => 'integer', 'minimum' => 0, 'default' => 0 ) ) ),
			'callback' => static function ( \WP_REST_Request $r ) {
				$result = Repository::detail( $r['id'], $r['cursor'] );
				if ( ! is_wp_error( $result ) ) {
					$history = Repository::history( $r['id'] );
					if ( is_wp_error( $history ) ) { return $history; }
					$result['history'] = $history;
				}
				return $result;
			},
		) );
		register_rest_route( 'bettershield/v1', '/incidents/(?P<id>\d+)/status', array(
			'methods' => 'POST', 'permission_callback' => $labels,
			'args' => array( 'id' => self::arg( array( 'type' => 'integer', 'minimum' => 1 ) ), 'status' => self::arg( array( 'type' => 'string', 'enum' => array( 'acknowledged', 'resolved' ), 'required' => true ) ) ),
			'callback' => static fn( \WP_REST_Request $r ) => Repository::status( $r['id'], $r['status'] ),
		) );
		register_rest_route( 'bettershield/v1', '/incidents/refresh', array(
			'methods' => 'POST', 'permission_callback' => $labels,
			'callback' => static fn() => Engine::tick() ? array( 'engine' => Engine::report() ) : Repository::error(),
		) );
	}
}
