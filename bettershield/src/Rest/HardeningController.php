<?php
/**
 * REST surface for hardening items.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Audit\Auditor;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\Preflight;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HardeningController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	private static function arg( array $schema ): array { return $schema + array( 'validate_callback' => 'rest_validate_request_arg', 'sanitize_callback' => 'rest_sanitize_request_arg' ); }

	public function register_routes(): void {
		$manage = static function (): bool {
			return Permissions::manage();
		};

		$interactive_manage = static function () {
			return Permissions::interactive_manage();
		};

		register_rest_route( 'bettershield/v1', '/hardening/(?P<item>[a-z_]+)/monitor', array(
			'methods' => \WP_REST_Server::CREATABLE,
			// Starting or ending a watch changes no protection, and enforcing
			// puts one on: the password gate asks before a protection comes
			// down, never before one goes up. Still a person's browser session.
			'permission_callback' => static fn() => Permissions::interactive_manage_if( false ),
			'callback' => static fn( \WP_REST_Request $r ) => rest_ensure_response( \BetterShield\Hardening\Monitor::change( (string) $r['item'], $r['action'], (array) $r['options'], $r['seconds'], $r['threshold'], $r['id'], true === $r['override_preflight'] ) ),
			'args' => array(
				'action' => self::arg( array( 'type' => 'string', 'enum' => array( 'start', 'stop', 'enforce' ), 'required' => true ) ),
				// The second confirmation the recovery pre-flight asks for.
				'override_preflight' => self::arg( array( 'type' => 'boolean', 'default' => false ) ),
				'id' => self::arg( array( 'type' => 'string', 'default' => '', 'maxLength' => 36 ) ),
				'seconds' => self::arg( array( 'type' => 'integer', 'enum' => array( 3600, 86400, 604800 ), 'default' => 86400 ) ),
				'threshold' => self::arg( array( 'type' => 'integer', 'enum' => array( 0, 1, 5, 10 ), 'default' => 0 ) ),
				'options' => self::arg( array( 'type' => 'object', 'default' => array(), 'additionalProperties' => false, 'properties' => array(
					'roles' => array( 'type' => array( 'string', 'array' ), 'items' => array( 'type' => 'string' ) ),
					'mode' => array( 'type' => 'string' ), 'slug' => array( 'type' => 'string' ), 'scope' => array( 'type' => 'string', 'enum' => array( 'all', 'jetpack', 'pingbacks' ) ),
					// Sent by the row with the address; the item's validator drops it, so a watch never turns the gate on.
					'admin_visitors' => array( 'type' => 'string' ),
					'destination' => array( 'type' => 'string' ),
				) ) ),
			),
		) );

		register_rest_route(
			'bettershield/v1',
			'/hardening',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( self::listed() ),
				'permission_callback' => $manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/hardening/(?P<item>[a-z_]+)/dry-run',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					return rest_ensure_response(
						Manager::instance()->dry_run(
							(string) $request['item'],
							is_array( $body ) && isset( $body['options'] ) && is_array( $body['options'] ) ? $body['options'] : array()
						)
					);
				},
				'permission_callback' => $manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/hardening/(?P<item>[a-z_]+)/apply',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'apply' ),
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					return Permissions::apply_hardening_item( $request );
				},
			)
		);

		// Reverting takes a protection away, so it asks for the session
		// regardless of which item it is.
		register_rest_route(
			'bettershield/v1',
			'/hardening/(?P<item>[a-z_]+)/revert',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'revert' ),
				'permission_callback' => $interactive_manage,
			)
		);

		// An action is neither an apply nor a revert, so it is gated by its
		// direction, as its item answers. Rotating the sign-in keys signs
		// every account out, and taking the content policy back to watching,
		// widening it or clearing what it reported removes protection: those
		// get the stricter rule. Starting to enforce the policy, taking a
		// source back off it or putting its reports back adds protection, and
		// the password gate never asks before that.
		register_rest_route(
			'bettershield/v1',
			'/hardening/(?P<item>[a-z_]+)/action/(?P<action>[a-z_]+)',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'act' ),
				// What an action is about, for the ones that take something:
				// the directive and the source a report named.
				'args'                => array(
					'directive' => self::arg( array( 'type' => 'string', 'maxLength' => 40 ) ),
					'source'    => self::arg( array( 'type' => 'string', 'maxLength' => 300 ) ),
				),
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					return Permissions::interactive_manage_if( ! Items::adds_protection( (string) $request['item'], (string) $request['action'] ) );
				},
			)
		);
	}

	/**
	 * The item list as the Hardening screens read it.
	 *
	 * The groups travel with the items so the screens cannot disagree with
	 * the registry about what a group is called or which screen shows it.
	 * `describe_all()` still answers a flat list for the CLI and the
	 * diagnostics report.
	 *
	 * @return array{items: array<int, array<string, mixed>>, groups: array<string, mixed>}
	 */
	private static function listed(): array {
		return array(
			'items'  => Manager::instance()->describe_all(),
			'groups' => Items::groups(),
			'count'  => \BetterShield\Hardening\ProtectionCount::all(),
		);
	}

	/**
	 * What an apply or a revert answers with: its own result, and every
	 * surface the change moves, read after the audit that follows it.
	 *
	 * The item list and the findings came back only as a second and a third
	 * request, after this one had already waited on the audit, so a switch
	 * did not move until both had answered. Carried here, the screen takes
	 * them from the first answer.
	 *
	 * @param array<string, mixed> $result
	 */
	private static function changed( array $result ): \WP_REST_Response {
		return rest_ensure_response(
			array_merge(
				$result,
				array(
					'overview'  => OverviewController::screen_payload(),
					'hardening' => self::listed(),
					'findings'  => Auditor::findings_for_reader(),
				)
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function apply( \WP_REST_Request $request ) {
		$body    = $request->get_json_params();
		$item    = (string) $request['item'];
		$options = isset( $body['options'] ) && is_array( $body['options'] ) ? $body['options'] : array();

		/*
		 * A change to how people sign in waits for a proved way back in. The
		 * person may go ahead anyway by saying so a second time, and that is
		 * recorded once the change has been made, with the check that failed.
		 */
		$failure = Permissions::needs_way_back( $item ) ? Preflight::failure() : null;

		if ( null !== $failure && true !== ( $body['override_preflight'] ?? false ) ) {
			return Preflight::refusal( $failure );
		}

		$result = Manager::instance()->apply_from_screen( $item, $options );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		if ( null !== $failure ) {
			Preflight::overridden( $failure, $item, 'dashboard' );
		}

		// Refresh findings so the response reflects the change.
		Auditor::run();

		return self::changed( $result );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function revert( \WP_REST_Request $request ) {
		$result = Manager::instance()->revert( (string) $request['item'], Manager::CAUSE_MANUAL );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		Auditor::run();

		return self::changed( $result );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function act( \WP_REST_Request $request ) {
		$args = array();

		foreach ( array( 'directive', 'source' ) as $key ) {
			if ( is_string( $request[ $key ] ) ) {
				$args[ $key ] = $request[ $key ];
			}
		}

		$result = Manager::instance()->act( (string) $request['item'], (string) $request['action'], $args );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response( $result );
	}
}
