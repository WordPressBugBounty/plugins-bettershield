<?php
/**
 * REST surface for the operator tools: settings export and import, the
 * report-a-problem block, and the security report. The first three are behind
 * the manage capability — an export describes the site's defenses, an import
 * changes them, and the diagnostics say how they are set up. The security
 * report is a read for whoever may read the posture, and carries only the
 * sections that reader may see.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Operator\Diagnostics;
use BetterShield\Operator\Report;
use BetterShield\Operator\SettingsDocument;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OperatorController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		$manage = static function (): bool {
			return current_user_can( Capabilities::MANAGE );
		};

		register_rest_route(
			'bettershield/v1',
			'/settings/export',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( SettingsDocument::export() );
				},
				'permission_callback' => $manage,
			)
		);

		/*
		 * Settings another security plugin left on this site, each read as a
		 * settings document for the import below to plan and apply, with what
		 * could not be carried. A read: nothing is written to either plugin.
		 */
		register_rest_route(
			'bettershield/v1',
			'/settings/import/sources',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( array( 'sources' => \BetterShield\Operator\Migrate::sources() ) );
				},
				'permission_callback' => $manage,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/settings/import',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$body     = $request->get_json_params();
					$document = is_array( $body ) && isset( $body['document'] ) && is_array( $body['document'] ) ? $body['document'] : null;

					if ( null === $document ) {
						return new \WP_Error( 'bettershield_bad_document', __( 'This is not a BetterShield settings document.', 'bettershield' ), array( 'status' => 400 ) );
					}

					// The plan is the default. Applying is the explicit second
					// step, so the screen shows what will happen before it does.
					$apply    = is_array( $body ) && rest_sanitize_boolean( $body['apply'] ?? false );
					$override = is_array( $body ) && true === ( $body['override_preflight'] ?? false );
					$result   = $apply ? SettingsDocument::apply( $document, $override, 'dashboard' ) : SettingsDocument::plan( $document );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				/*
				 * A document can revert every protection on the site in one
				 * request, so applying one asks for the session. Planning is a
				 * read of what would happen and stays on the capability —
				 * which keeps the plan-before-apply pair usable by a script
				 * that wants to check a site against a document without
				 * being able to change it.
				 */
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					$body = $request->get_json_params();

					if ( ! is_array( $body ) || ! rest_sanitize_boolean( $body['apply'] ?? false ) ) {
						return Permissions::manage();
					}

					return Permissions::interactive_manage();
				},
			)
		);

		/*
		 * The security report, on demand: one self-contained page to keep or
		 * print, with only the sections this reader may read on screen. A
		 * read, built from what the weekly summary reports; nothing is sent
		 * anywhere and nothing is stored.
		 */
		register_rest_route(
			'bettershield/v1',
			'/report',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$report = Report::build( (int) $request->get_param( 'days' ) );

					return rest_ensure_response(
						array(
							'html'     => Report::render( $report ),
							'filename' => Report::filename(),
							'days'     => $report['days'],
							'since'    => $report['since'],
						)
					);
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
				'args'                => array(
					'days' => array(
						'type'              => 'integer',
						'default'           => Report::DEFAULT_DAYS,
						'minimum'           => 1,
						'maximum'           => 366,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/diagnostics',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response(
						array(
							'text'        => Diagnostics::render(),
							'support_url' => Diagnostics::SUPPORT_URL,
						)
					);
				},
				'permission_callback' => $manage,
			)
		);
	}
}
