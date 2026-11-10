<?php
/**
 * REST surface for the two policies a network sets once for every site.
 *
 * Registered only on a network. On a single site there is nothing for these
 * routes to answer about, and a route that exists in order to refuse is a
 * route somebody has to read the refusal of.
 *
 * The read is deliberately cheap: two network options and a role list. What it
 * does not do is walk the network — whether every site has a way back is a
 * question with two hundred site switches in it, and it is asked at the one
 * moment its answer decides something, which is a widening of the passkey
 * policy. The sites table on the dashboard is where a network administrator
 * sees which sites are short.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Network\Policies;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NetworkPoliciesController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/network/policies',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => array( $this, 'read' ),
					'permission_callback' => static function (): bool {
						return Permissions::network_read();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'write' ),
					/*
					 * Both directions are consequential and neither belongs to
					 * a stored credential: naming a role here decides whether
					 * a password opens accounts on every site of the network,
					 * and taking one away hands the password back to all of
					 * them.
					 */
					'permission_callback' => static function () {
						return Permissions::network_manage();
					},
					'args'                => self::args(),
				),
			)
		);
	}

	/**
	 * The two sections a request may carry, each optional: a save that names
	 * one leaves the other exactly as it was.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function args(): array {
		$roles = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);

		return array(
			'two_factor' => array(
				'type'              => 'object',
				'required'          => false,
				'properties'        => array(
					'roles'      => $roles,
					'grace_days' => array(
						'type'    => 'integer',
						'minimum' => 0,
						'maximum' => 90,
					),
				),
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
			'passkey'    => array(
				'type'              => 'object',
				'required'          => false,
				'properties'        => array( 'roles' => $roles ),
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
		);
	}

	public function read(): \WP_REST_Response {
		return rest_ensure_response(
			array(
				'two_factor' => array_merge( Policies::two_factor(), array( 'set' => Policies::two_factor_is_set() ) ),
				'passkey'    => array_merge( Policies::passkey(), array( 'set' => Policies::passkey_is_set() ) ),
				'roles'      => Policies::available_roles(),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function write( \WP_REST_Request $request ) {
		/*
		 * Every section named is checked before either is saved. Saved one
		 * after the other, a body naming both wrote the two-factor policy for
		 * every site — with its event and its undo row — and then answered the
		 * passkey section's refusal, so a client reading the 4xx as "nothing
		 * changed" had changed the whole network.
		 */
		$checks = array(
			'two_factor' => array( Policies::class, 'validate_two_factor' ),
			'passkey'    => array( Policies::class, 'validate_passkey' ),
		);

		foreach ( $checks as $section => $validate ) {
			if ( ! is_array( $request[ $section ] ) ) {
				continue;
			}

			$checked = call_user_func( $validate, $request[ $section ] );

			if ( is_wp_error( $checked ) ) {
				return $checked;
			}
		}

		$wanted = 0;

		if ( is_array( $request['two_factor'] ) ) {
			$saved = Policies::update_two_factor( $request['two_factor'] );

			if ( is_wp_error( $saved ) ) {
				return $saved;
			}

			++$wanted;
		}

		if ( is_array( $request['passkey'] ) ) {
			$saved = Policies::update_passkey( $request['passkey'] );

			if ( is_wp_error( $saved ) ) {
				return $saved;
			}

			++$wanted;
		}

		if ( 0 === $wanted ) {
			return new \WP_Error(
				'bettershield_nothing_to_save',
				__( 'Name a policy to change.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		return $this->read();
	}
}
