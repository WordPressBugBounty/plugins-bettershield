<?php
/**
 * REST surface for the network's own way back in.
 *
 * Two things live here, and they are the two acts that belong to a network
 * rather than to any of its sites.
 *
 * The first is the network's recovery link: one for the whole network, issued
 * here and shown once, answered at any site's reserved address, and standing
 * every site down when it is opened. A site's own link opens that site, which
 * is right — one site's operator does not decide what the sites beside it
 * enforce — but it leaves a network administrator locked out above the sites
 * with nothing that reaches the policies set above them. This is that thing.
 *
 * The second is rotating the sign-in key. On a network one sign-in covers
 * every site, so the key that signs it is shared, and replacing it ends every
 * session on every site at once. That is not a switch to leave on one site's
 * hardening screen, so the item refuses there and says to come here.
 *
 * Registered only on a network, for the reason every network route is: a route
 * that exists in order to refuse is a route somebody has to read the refusal
 * of.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Hardening\Manager;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkRecoveryController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/network/recovery/link',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'read' ),
					// A read of what is on record, open to the capability that
					// reads the rest of the network. The link itself is not in
					// the answer; only its hash is ever stored, so there is
					// nothing here to disclose.
					'permission_callback' => static function (): bool {
						return Permissions::network_read();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'generate' ),
					/*
					 * Issuing one silently retires the link somebody may be
					 * holding, and the link it hands back pauses every
					 * protection on every site of the network for an hour. A
					 * stored credential must not be able to mint that.
					 */
					'permission_callback' => static function () {
						return Permissions::network_manage();
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/safe-mode/end',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'end_pause' ),
				// Ending it re-arms every protection on every site at once;
				// the network's own administrator, at a browser, decides that.
				'permission_callback' => static function () {
					return Permissions::network_manage();
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/network/recovery/rotate-keys',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'rotate' ),
				'permission_callback' => static function () {
					return Permissions::network_manage();
				},
				'args'                => array(
					// Whether the session being handed over was a remembered
					// one, so the replacement lasts as long as the one it
					// replaces rather than quietly becoming shorter.
					'remember' => array(
						'type'              => 'boolean',
						'required'          => false,
						'default'           => false,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);
	}

	/**
	 * What the dashboard shows about the link on record.
	 */
	public function read(): \WP_REST_Response {
		return rest_ensure_response(
			array(
				'link'      => RecoveryLink::network_state(),
				'safe_mode' => array(
					'active' => SafeMode::is_network_active(),
					'until'  => SafeMode::is_network_active() ? SafeMode::until() : null,
				),
			)
		);
	}

	/**
	 * End the pause the network's link raised, on every site, and answer
	 * with what is on record now.
	 */
	public function end_pause(): \WP_REST_Response {
		SafeMode::end_network( 'manual' );

		return $this->read();
	}

	/**
	 * Issue a link. The URL appears in this response exactly once.
	 */
	public function generate() {
		$url = RecoveryLink::generate_network();

		if ( null === $url ) {
			return new \WP_Error(
				'bettershield_recovery_link_failed',
				__( 'The recovery link could not be stored, so none was issued. Try again.', 'bettershield' ),
				array( 'status' => 503 )
			);
		}

		return rest_ensure_response(
			array(
				'url'  => $url,
				'link' => RecoveryLink::network_state(),
			)
		);
	}

	/**
	 * Rotate the key every site of the network signs with.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function rotate( \WP_REST_Request $request ) {
		$rotated = Manager::instance()->rotate_network_keys(
			get_current_user_id(),
			(bool) $request['remember']
		);

		return is_wp_error( $rotated ) ? $rotated : rest_ensure_response( $rotated );
	}
}
