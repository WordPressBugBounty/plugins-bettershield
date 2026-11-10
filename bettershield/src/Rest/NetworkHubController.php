<?php
/**
 * Prepare one ordinary site connection at a time from Network Admin.
 *
 * @package BetterShield
 */
declare( strict_types=1 );
namespace BetterShield\Rest;

use BetterShield\Events\Writer;
use BetterShield\Mcp\Hub;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkHubController {
	public function register(): void {
		if ( is_multisite() ) {
			add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		}
	}
	public function register_routes(): void {
		register_rest_route( 'bettershield/v1', '/network/hub/status', array(
			'methods' => 'GET', 'callback' => array( $this, 'status' ), 'permission_callback' => array( Permissions::class, 'network_read' ),
			'args' => array( 'sites' => array( 'type' => 'array', 'items' => array( 'type' => 'integer', 'minimum' => 1 ), 'maxItems' => 10, 'minItems' => 1, 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ) ),
		) );
		register_rest_route( 'bettershield/v1', '/network/hub/connect', array(
			'methods' => 'POST', 'callback' => array( $this, 'connect' ), 'permission_callback' => array( Permissions::class, 'network_manage' ),
		) );
	}
	private static function denied(): \WP_Error {
		return new \WP_Error( 'bettershield_network_hub_denied', __( 'A network administrator must prepare this connection from their signed-in browser.', 'bettershield' ), array( 'status' => 403 ) );
	}
	/** Check global IDs against this network before switching any context. */
	private static function target( $id ) {
		if ( ! is_int( $id ) || $id < 1 ) {
			return new \WP_Error( 'bettershield_network_hub_site', __( 'Choose an available site on this network.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$site = get_site( $id );
		if ( ! $site || (int) $site->network_id !== get_current_network_id() || $site->deleted || $site->spam || $site->archived || ! wp_is_site_initialized( $id ) ) {
			return new \WP_Error( 'bettershield_network_hub_site', __( 'Choose an available site on this network.', 'bettershield' ), array( 'status' => 400 ) );
		}
		return true;
	}
	private static function on_site( int $id, callable $run ) {
		Writer::instance()->flush();
		switch_to_blog( $id );
		try {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
			if ( ! is_plugin_active( plugin_basename( BETTERSHIELD_FILE ) ) ) {
				return new \WP_Error( 'bettershield_network_hub_inactive', __( 'Activate BetterShield on this site before connecting it.', 'bettershield' ), array( 'status' => 409 ) );
			}
			return $run();
		} finally {
			Writer::instance()->flush();
			restore_current_blog();
		}
	}
	private static function connected(): bool {
		foreach ( Hub::apps() as $app ) {
			if ( $app['hub'] === Hub::host() ) { return true; }
		}
		return false;
	}
	public function status( \WP_REST_Request $request ) {
		if ( ! Permissions::network_read() ) { return self::denied(); }
		$ids = $request['sites'];
		if ( ! is_array( $ids ) || count( $ids ) < 1 || count( $ids ) > 10 ) {
			return new \WP_Error( 'bettershield_network_hub_sites', __( 'Choose between one and ten sites.', 'bettershield' ), array( 'status' => 400 ) );
		}
		foreach ( $ids as $id ) { $valid = self::target( $id ); if ( is_wp_error( $valid ) ) { return $valid; } }
		$sites = array();
		foreach ( array_unique( $ids ) as $id ) {
			$result = self::on_site( $id, static function () { return array( 'connected' => self::connected(), 'host' => Hub::host() ); } );
			$sites[] = array_merge( array( 'id' => $id ), is_wp_error( $result ) ? array( 'connected' => false, 'error' => $result->get_error_message() ) : $result );
		}
		return rest_ensure_response( array( 'sites' => $sites ) );
	}
	public function connect( \WP_REST_Request $request ) {
		$permission = Permissions::network_manage();
		if ( true !== $permission ) { return is_wp_error( $permission ) ? $permission : self::denied(); }
		$body = $request->get_json_params();
		if ( ! is_array( $body ) || true !== ( $body['confirmed'] ?? null ) ) {
			return new \WP_Error( 'bettershield_network_hub_confirm', __( 'Confirm the connection for this site before continuing.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$id = $body['site_id'] ?? null;
		$valid = self::target( $id );
		if ( is_wp_error( $valid ) ) { return $valid; }
		return self::on_site( $id, static function () use ( $body ) {
			$permission = Permissions::interactive_manage();
			if ( true !== $permission ) { return is_wp_error( $permission ) ? $permission : self::denied(); }
			if ( self::connected() ) { return rest_ensure_response( array( 'connected' => true ) ); }
			$inner = new \WP_REST_Request( 'POST' );
			return ( new HubController() )->connect( $inner );
		} );
	}
}
