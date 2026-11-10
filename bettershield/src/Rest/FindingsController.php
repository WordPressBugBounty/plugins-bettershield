<?php
/**
 * REST surface for the full findings report.
 *
 * Reading the report needs only the posture capability: the diagnosis is
 * never withheld. Changing a finding's status needs the manage capability.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Fixes\AdminUsername;
use BetterShield\Fixes\ConfigMode;
use BetterShield\Fixes\ContentLinks;
use BetterShield\Fixes\DormantAccounts;
use BetterShield\Fixes\DomainMailRecords;
use BetterShield\Fixes\Guidance;
use BetterShield\Fixes\HttpsAddress;
use BetterShield\Fixes\InactiveExtensions;
use BetterShield\Fixes\LoginAddress;
use BetterShield\Fixes\ProxySetup;
use BetterShield\Fixes\QuarantineSeal;
use BetterShield\Fixes\LoginLimits;
use BetterShield\Fixes\PluginUpdates;
use BetterShield\Fixes\ProtectionRepair;
use BetterShield\Fixes\RestRoutes;
use BetterShield\Fixes\ScheduledEvents;
use BetterShield\Fixes\ScheduledWork;
use BetterShield\Fixes\SignInExtras;
use BetterShield\Fixes\SignInPage;
use BetterShield\Fixes\StalePasswords;
use BetterShield\Fixes\WeakPasswords;
use BetterShield\Fixes\WorldWritable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FindingsController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( Auditor::findings_for_reader() );
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
			)
		);

		foreach ( array( 'suppress', 'unsuppress' ) as $action ) {
			register_rest_route(
				'bettershield/v1',
				'/findings/(?P<key>[a-z0-9_]+)/' . $action,
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => function ( \WP_REST_Request $request ) use ( $action ) {
						return $this->change_status( (string) $request['key'], $action );
					},
					/*
					 * Suppressing hides a finding the audit is still raising,
					 * which is the one direction here that lowers what this
					 * site reports about itself — so it asks for the session.
					 * Putting a finding back is the safe direction and stays
					 * on the capability.
					 */
					'permission_callback' => static function () use ( $action ) {
						return 'suppress' === $action
							? Permissions::interactive_manage()
							: Permissions::manage();
					},
					/*
					 * The route keeps no note, but a caller that sends a
					 * reason gets it type-checked like snooze's days, so a
					 * malformed body is refused rather than acted on (#2177).
					 */
					'args'                => array(
						'reason' => array(
							'type'              => 'string',
							'maxLength'         => 255,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				)
			);
		}

		register_rest_route(
			'bettershield/v1',
			'/findings/(?P<key>[a-z0-9_]+)/snooze',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => function ( \WP_REST_Request $request ) {
					return $this->answer( \BetterShield\Audit\Snooze::snooze( (string) $request['key'], (int) $request['days'] ) );
				},
				// Setting a finding aside lowers what the report leads with,
				// so it asks for the session, as marking one not applicable
				// does.
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
				'args'                => array(
					'days' => array(
						'type'              => 'integer',
						'required'          => true,
						'enum'              => \BetterShield\Audit\Snooze::DAYS,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/(?P<key>[a-z0-9_]+)/wake',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => function ( \WP_REST_Request $request ) {
					return $this->answer( \BetterShield\Audit\Snooze::wake( (string) $request['key'] ) );
				},
				// Bringing one back is the safe direction.
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/leftover_tools_reachable/quarantine',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => function ( \WP_REST_Request $request ) {
					return $this->quarantine_tool( (string) $request['path'] );
				},
				// Replaces a file in the site's own code, so it takes the
				// manage capability and the say over that code; the undo is on
				// the Files screen's quarantine list.
				'permission_callback' => static function () {
					return Permissions::manage() ? Permissions::shared_code() : false;
				},
				'args'                => array(
					'path' => array(
						'type'              => 'string',
						'required'          => true,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		// The same move for a downloadable backup, dump or log, offered where
		// the rule that hides them cannot apply on this server.
		register_rest_route(
			'bettershield/v1',
			'/findings/artifacts_downloadable/quarantine',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => function ( \WP_REST_Request $request ) {
					return $this->quarantine_artifact( (string) $request['path'] );
				},
				'permission_callback' => static function () {
					return Permissions::manage() ? Permissions::shared_code() : false;
				},
				'args'                => array(
					'path' => array(
						'type'              => 'string',
						'required'          => true,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		$this->register_login_limits();
		$this->register_sign_in_extras();
		$this->register_scheduled_events();
		$this->register_rest_routes();
		$this->register_quarantine_seal();
		$this->register_content_folders();
		$this->register_domain_records();
		$this->register_login_address();
		$this->register_content_links();
		$this->register_https_address();
		$this->register_scheduled_work();
		$this->register_account_fixes();
		$this->register_extension_and_site_fixes();
		$this->register_guidance();

		// The lockouts' proxy Fix (#2205): what the panel shows. Its save is
		// login protection's own route, with its validation and password.
		register_rest_route(
			'bettershield/v1',
			'/findings/lockouts_not_running/proxy',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( ProxySetup::state() );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);
	}

	/**
	 * The one-press fixes on extension and site findings (#2430): plugin
	 * updates, unused plugins and themes moved into quarantine, the sign-in
	 * page kept out of page caches, wp-config.php's permissions, and
	 * protections applied again. Each change that adds protection takes the
	 * capability; each way back that takes it away again asks for the
	 * session. A change to code or a file every site of a network shares
	 * takes the say over that code as well.
	 */
	private function register_extension_and_site_fixes(): void {
		$undo_arg = array(
			'undo' => array(
				'type'              => 'string',
				'required'          => false,
				'default'           => '',
				'pattern'           => '^([a-f0-9]{32})?$',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_text_field',
			),
		);

		$shared = static function () {
			return Permissions::manage() ? Permissions::shared_code() : false;
		};

		$shared_session = static function () {
			$allowed = Permissions::interactive_manage();

			return true === $allowed ? Permissions::shared_code() : $allowed;
		};

		// The same Update now for both findings that name a plugin to update.
		foreach ( PluginUpdates::FINDINGS as $key ) {
			register_rest_route(
				'bettershield/v1',
				'/findings/' . $key . '/updates',
				array(
					array(
						'methods'             => \WP_REST_Server::READABLE,
						'callback'            => static function () use ( $key ): \WP_REST_Response {
							return rest_ensure_response( PluginUpdates::state( $key ) );
						},
						'permission_callback' => static function (): bool {
							return Permissions::manage();
						},
					),
					array(
						'methods'             => \WP_REST_Server::CREATABLE,
						'callback'            => static function ( \WP_REST_Request $request ) use ( $key ) {
							$result = PluginUpdates::update( (string) $request['plugin'] );

							return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => PluginUpdates::state( $key ) ) );
						},
						// Installs code the directory published: adds protection,
						// and writes code a network's every site runs.
						'permission_callback' => $shared,
						'args'                => array(
							// A plugin file the update cache offers; anything else is
							// refused by name in the call.
							'plugin' => array(
								'type'              => 'string',
								'required'          => true,
								'maxLength'         => 255,
								'validate_callback' => 'rest_validate_request_arg',
								'sanitize_callback' => 'sanitize_text_field',
							),
						),
					),
				)
			);

			register_rest_route(
				'bettershield/v1',
				'/findings/' . $key . '/updates/undo',
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) use ( $key ) {
						$result = PluginUpdates::undo( (string) $request['undo'] );

						return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => PluginUpdates::state( $key ) ) );
					},
					// Puts back a version the update replaced, which may be the
					// one an advisory names.
					'permission_callback' => $shared_session,
					'args'                => $undo_arg,
				)
			);
		}

		register_rest_route(
			'bettershield/v1',
			'/findings/inactive_extensions/extensions',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( InactiveExtensions::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = InactiveExtensions::move( (string) $request['kind'], (string) $request['id'] );

						return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => InactiveExtensions::state() ) );
					},
					// Takes code nothing runs out of reach: adds protection.
					'permission_callback' => $shared,
					'args'                => array(
						'kind' => array(
							'type'              => 'string',
							'required'          => true,
							'enum'              => array( 'plugin', 'theme' ),
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_key',
						),
						// A plugin file or theme folder the finding counts;
						// anything else is refused by name in the call.
						'id'   => array(
							'type'              => 'string',
							'required'          => true,
							'maxLength'         => 255,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/inactive_extensions/extensions/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = InactiveExtensions::put_back( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => InactiveExtensions::state() ) );
				},
				// Puts code back where visitors can reach it.
				'permission_callback' => $shared_session,
				'args'                => $undo_arg,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/sign_in_page_cached/no-cache',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( SignInPage::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function () {
						$result = SignInPage::apply();

						return is_wp_error( $result ) ? $result : self::scored( $result );
					},
					// Adds protection, as applying a hardening item does. Its
					// way back is that item's own revert, which asks for the
					// session.
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/sign_in_page_cached/no-cache/check',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					return self::scored( SignInPage::check() );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/config_world_writable/mode',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( ConfigMode::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function () {
						$result = ConfigMode::apply();

						return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => ConfigMode::state() ) );
					},
					// Narrows who may write the file every site of a network
					// reads; adds protection.
					'permission_callback' => $shared,
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/config_world_writable/mode/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = ConfigMode::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( array( 'state' => ConfigMode::state() ) );
				},
				// Widens who may write it again.
				'permission_callback' => $shared_session,
				'args'                => $undo_arg,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/hardening_not_working/protections',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( ProtectionRepair::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = ProtectionRepair::reapply( (string) $request['item'], true === $request['override_preflight'] );

						return is_wp_error( $result ) ? $result : self::scored( $result );
					},
					// As applying the item does: the capability, and the
					// session for one that changes how people sign in.
					'permission_callback' => array( Permissions::class, 'apply_hardening_item' ),
					'args'                => array(
						'item'               => array(
							'type'              => 'string',
							'required'          => true,
							'enum'              => \BetterShield\Hardening\Items::ids(),
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_key',
						),
						// The second confirmation the recovery pre-flight asks for.
						'override_preflight' => array(
							'type'              => 'boolean',
							'default'           => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_boolean',
						),
					),
				),
			)
		);
	}

	/**
	 * The plain-HTTP content's Fix (#1291): how many published posts carry
	 * this site's own http:// address, and the rewrite and its undo, a batch
	 * per request. Each changes published content, so each asks for the
	 * person's own session.
	 */
	private function register_content_links(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/mixed_content_published/links',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( ContentLinks::state() );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);

		foreach ( array( 'rewrite', 'undo' ) as $step ) {
			register_rest_route(
				'bettershield/v1',
				'/findings/mixed_content_published/links/' . $step,
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function () use ( $step ) {
						$result = 'rewrite' === $step ? ContentLinks::rewrite() : ContentLinks::undo();

						return is_wp_error( $result ) ? $result : self::scored( $result );
					},
					'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				)
			);
		}
	}

	/**
	 * The plain-HTTP address's Fix (#1289): where the site is, the
	 * certificate check, the switch, Keep HTTPS and the way back. The check
	 * changes nothing but asks the site for a page, so it is a POST; the
	 * switch, keeping it and undoing it each ask for the person's own
	 * session, and the switch the recovery pre-flight first.
	 */
	private function register_https_address(): void {
		$base = '/findings/site_not_https/address';

		register_rest_route(
			'bettershield/v1',
			$base,
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( HttpsAddress::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = HttpsAddress::apply( true === $request['override_preflight'] );

						return is_wp_error( $result ) ? $result : self::scored( $result );
					},
					'permission_callback' => array( Permissions::class, 'interactive_manage' ),
					'args'                => array(
						// The second confirmation the recovery pre-flight asks for.
						'override_preflight' => array(
							'type'              => 'boolean',
							'default'           => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_boolean',
						),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			$base . '/check',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( HttpsAddress::check() );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			$base . '/keep',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$result = HttpsAddress::keep();

					return is_wp_error( $result ) ? $result : self::scored( $result );
				},
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			$base . '/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$result = HttpsAddress::undo();

					return is_wp_error( $result ) ? $result : self::scored( $result );
				},
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
			)
		);
	}

	/**
	 * The hidden content's Fix (#2210): the sign-in address now and what it
	 * hides, and moving it again. Moving it changes how people sign in, so
	 * it asks for the person's own session and, where asked for, the
	 * password; the recovery pre-flight comes first, as on the item.
	 */
	private function register_login_address(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/login_url_shadows_content/address',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( LoginAddress::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$result = LoginAddress::change( (string) $request['slug'], true === $request['override_preflight'] );

						return is_wp_error( $result ) ? $result : self::scored( $result );
					},
					'permission_callback' => array( Permissions::class, 'interactive_manage' ),
					'args'                => array(
						// Not required: the item's own rule refuses an empty one,
						// in its own words.
						'slug'               => array(
							'type'              => 'string',
							'default'           => '',
							'maxLength'         => 40,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'sanitize_text_field',
						),
						// The second confirmation the recovery pre-flight asks for.
						'override_preflight' => array(
							'type'              => 'boolean',
							'default'           => false,
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => 'rest_sanitize_boolean',
						),
					),
				),
			)
		);
	}

	/**
	 * The two-limiters Fix (#1945): leave sign-in limits to the other plugin,
	 * as the Quick Setup's step does. It switches BetterShield's own limit
	 * off, so it asks for the session a weakening asks for.
	 */
	private function register_login_limits(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/login_limits_overlap/leave',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$done = LoginLimits::leave_to_other();

					if ( is_wp_error( $done ) ) {
						return $done;
					}

					Auditor::run();

					return rest_ensure_response(
						array(
							'findings' => Auditor::findings_for_reader(),
							'overview' => OverviewController::screen_payload(),
						)
					);
				},
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
			)
		);
	}

	/**
	 * The fixes for three findings that answer to one of this plugin's own
	 * settings (#2564): refuse the common usernames, ask for proof of work,
	 * block pingbacks only.
	 *
	 * The two sign-in changes save through login protection, whose own route
	 * asks for the session, so these do too; each answers with the settings
	 * record its Undo puts back. Blocking pingbacks only is the XML-RPC
	 * protection, gated as applying it from the Hardening screen is, and its
	 * Undo is that protection's revert.
	 *
	 * Each runs the audit and answers with the score, leaving the report out,
	 * so the row and its Undo stay on screen until the report is read again.
	 */
	private function register_sign_in_extras(): void {
		$read = static function (): bool {
			return Permissions::manage();
		};

		$answer = static function ( $result ) {
			if ( is_wp_error( $result ) ) {
				return $result;
			}

			Auditor::run();

			return self::scored( $result );
		};

		register_rest_route(
			'bettershield/v1',
			'/findings/common_usernames_allowed/names',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( SignInExtras::names_state() ),
					'permission_callback' => $read,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static fn() => $answer( SignInExtras::block_names() ),
					'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/proof_of_work_off/proof',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( SignInExtras::proof_state() ),
					'permission_callback' => $read,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static fn() => $answer( SignInExtras::turn_on_proof() ),
					'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/pingbacks_open/block',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn() => $answer( SignInExtras::block_pingbacks() ),
				'permission_callback' => static function () {
					$item = new \WP_REST_Request( 'POST', '/bettershield/v1/hardening/xmlrpc/apply' );
					$item->set_param( 'item', 'xmlrpc' );

					return Permissions::apply_hardening_item( $item );
				},
			)
		);
	}

	/**
	 * The unanswered scheduled events' Fix (#1952): remove the hooks the
	 * finding names, each kept first, and the undo that schedules them
	 * again. Removing takes away something that could run; putting it back
	 * is the other direction, and asks for the session.
	 */
	private function register_scheduled_events(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/cron_events_unanswered/remove',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					// Without the report: taken in, it would close the finding and
					// take the row, and its Undo, off the screen.
					$result = ScheduledEvents::remove( (array) $request['hooks'] );

					if ( is_wp_error( $result ) ) {
						return $result;
					}

					// The score moves now; the row waits for the next read.
					Auditor::run();

					return rest_ensure_response( is_array( $result ) ? $result + array( 'overview' => OverviewController::screen_payload() ) : $result );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
				'args'                => array(
					// Hook names the finding shows; anything else is refused
					// by name in the call.
					'hooks' => array(
						'type'              => 'array',
						'items'             => array( 'type' => 'string' ),
						'required'          => true,
						'maxItems'          => \BetterShield\Audit\Cron::MAX_NAMED,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => static fn( $value ): array => array_map( 'sanitize_text_field', (array) $value ),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/cron_events_unanswered/remove/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = ScheduledEvents::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( $result + array( 'findings' => Auditor::findings_for_reader() ) );
				},
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
				'args'                => array(
					'undo' => array(
						'type'              => 'string',
						'required'          => false,
						'default'           => '',
						'pattern'           => '^([a-f0-9]{32})?$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * The open REST routes' Fix (#1870): the routes the finding names with
	 * what was seen on each, and watching, closing and opening one again.
	 * Watching changes nothing and closing takes something away, so both are
	 * the manager's; opening again is the other direction, and asks for the
	 * session.
	 */
	private function register_rest_routes(): void {
		$route_arg = array(
			'route' => array(
				'type'              => 'string',
				'required'          => true,
				'maxLength'         => 512,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => static fn( $value ): string => wp_check_invalid_utf8( (string) $value ),
			),
		);
		$listing   = static fn(): array => array( 'routes' => RestRoutes::describe( RestRoutes::named() ) );

		register_rest_route(
			'bettershield/v1',
			'/findings/rest_surface_unreviewed/routes',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( $listing() ),
				'permission_callback' => static fn(): bool => Permissions::manage(),
			)
		);

		foreach ( array( 'watch', 'close' ) as $verb ) {
			register_rest_route(
				'bettershield/v1',
				'/findings/rest_surface_unreviewed/routes/' . $verb,
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) use ( $verb, $listing ) {
						$result = 'watch' === $verb ? RestRoutes::watch( (string) $request['route'] ) : RestRoutes::close( (string) $request['route'] );

						return is_wp_error( $result ) ? $result : self::scored( $listing() );
					},
					'permission_callback' => static fn(): bool => Permissions::manage(),
					'args'                => $route_arg,
				)
			);
		}

		register_rest_route(
			'bettershield/v1',
			'/findings/rest_surface_unreviewed/routes/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) use ( $listing ) {
					$result = RestRoutes::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( $listing() + array( 'findings' => Auditor::findings_for_reader() ) );
				},
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
				'args'                => array(
					'undo' => array(
						'type'              => 'string',
						'required'          => false,
						'default'           => '',
						'pattern'           => '^([a-f0-9]{32})?$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * The stalled schedule's Fix (#2209): how far behind it is and how a host
	 * would run it, and Try now, which only spawns the site's own run inside
	 * the runner's five-minute claim. Asking the site to catch up on work it
	 * already owed takes nothing away, so the session is not asked for.
	 */
	private function register_scheduled_work(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/cron_schedule_stalled/schedule',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( ScheduledWork::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( ScheduledWork::try_now() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
			)
		);
	}

	/**
	 * The account findings' Fixes (#2430): the account named "admin"
	 * renamed, stale application passwords revoked, dormant accounts
	 * suspended, and weak passwords asked to change. Each list is read with
	 * the capability; each change touches an account, so it and its undo ask
	 * for the person's own session and, where asked for, the password.
	 */
	private function register_account_fixes(): void {
		$read   = static function (): bool {
			return Permissions::manage();
		};
		/*
		 * Each of these changes what its check reads, so the audit runs and
		 * the score in the answer is the one the change produced. The report
		 * is left out on purpose: taken in, it would close the finding and
		 * take the row, and the Undo beside it, off the screen. The row reads
		 * as fixed the next time the findings are read.
		 */
		$answer = static function ( $result ) {
			if ( is_wp_error( $result ) ) {
				return $result;
			}

			Auditor::run();

			return rest_ensure_response( is_array( $result ) ? $result + array( 'overview' => OverviewController::screen_payload() ) : $result );
		};
		$undo   = array(
			'undo' => array(
				'type'              => 'string',
				'required'          => false,
				'default'           => '',
				'pattern'           => '^([a-f0-9]{32})?$',
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'sanitize_text_field',
			),
		);
		$ids    = static function ( int $max ): array {
			return array(
				'type'              => 'array',
				'items'             => array( 'type' => 'integer' ),
				'required'          => true,
				'maxItems'          => $max,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => static fn( $value ): array => array_map( 'absint', (array) $value ),
			);
		};

		register_rest_route(
			'bettershield/v1',
			'/findings/admin_username_exists/account',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( AdminUsername::state() ),
				'permission_callback' => $read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/admin_username_exists/rename',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( AdminUsername::rename( (string) $request['username'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array(
					// Checked against core's rules in the call, so a refusal
					// names what is wrong rather than the field.
					'username' => array(
						'type'              => 'string',
						'required'          => true,
						'maxLength'         => 60,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => static fn( $value ): string => trim( (string) $value ),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/admin_username_exists/rename/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( AdminUsername::undo( (string) $request['undo'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => $undo,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/application_passwords_stale/passwords',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( StalePasswords::state() ),
				'permission_callback' => $read,
			)
		);

		// A revoked application password cannot be put back, so there is
		// no undo route; core's hook records each revoke.
		register_rest_route(
			'bettershield/v1',
			'/findings/application_passwords_stale/revoke',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( StalePasswords::revoke( (array) $request['passwords'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array(
					// "account id:password uuid", as the list gives them.
					'passwords' => array(
						'type'              => 'array',
						'items'             => array(
							'type'    => 'string',
							'pattern' => '^[0-9]+:[a-f0-9-]{36}$',
						),
						'required'          => true,
						'maxItems'          => StalePasswords::MAX_LISTED,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => static fn( $value ): array => array_map( 'sanitize_text_field', (array) $value ),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/privileged_account_dormant/accounts',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( DormantAccounts::state() ),
				'permission_callback' => $read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/privileged_account_dormant/suspend',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( DormantAccounts::suspend( (array) $request['accounts'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array( 'accounts' => $ids( DormantAccounts::MAX_LISTED ) ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/privileged_account_dormant/suspend/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( DormantAccounts::lift( (string) $request['undo'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => $undo,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/passwords_below_policy/accounts',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( WeakPasswords::state() ),
				'permission_callback' => $read,
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/passwords_below_policy/hold',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( WeakPasswords::hold( (array) $request['accounts'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array( 'accounts' => $ids( WeakPasswords::MAX_LISTED ) ),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/passwords_below_policy/hold/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => $answer( WeakPasswords::undo( (string) $request['undo'] ) ),
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => $undo,
			)
		);
	}

	/**
	 * The world-writable folders' Fix (#2211): the folders the finding
	 * names, the world-write bit taken from the ones chosen, and its undo.
	 * The folders hold code every site of a network runs, so each also takes
	 * the say over that code.
	 */
	private function register_content_folders(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/content_dirs_world_writable/folders',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( WorldWritable::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
						return self::scored( WorldWritable::apply( (array) $request['folders'] ) + array( 'state' => WorldWritable::state() ) );
					},
					// Narrows who may write; adds protection.
					'permission_callback' => static function () {
						return Permissions::manage() ? Permissions::shared_code() : false;
					},
					'args'                => array(
						// Names the finding shows, never paths: anything else
						// is refused by name in the call.
						'folders' => array(
							'type'              => 'array',
							'items'             => array( 'type' => 'string' ),
							'maxItems'          => 10,
							'default'           => array(),
							'validate_callback' => 'rest_validate_request_arg',
							'sanitize_callback' => static fn( $value ): array => array_map( 'sanitize_text_field', (array) $value ),
						),
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/content_dirs_world_writable/folders/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = WorldWritable::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( array( 'state' => WorldWritable::state() ) );
				},
				// Widens who may write again: the session, and the say over
				// the code.
				'permission_callback' => static function () {
					$allowed = Permissions::interactive_manage();

					return true === $allowed ? Permissions::shared_code() : $allowed;
				},
				'args'                => array(
					'undo' => array(
						'type'              => 'string',
						'required'          => false,
						'default'           => '',
						'pattern'           => '^([a-f0-9]{32})?$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * The domain's mail and certificate records' Fix (#2203): the records to
	 * publish, for anybody who may read the findings, and Check again, which
	 * only queues the daily lookup, for somebody who may manage the site.
	 */
	private function register_domain_records(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/domain_mail_records/records',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( DomainMailRecords::state() );
				},
				'permission_callback' => static function (): bool {
					return current_user_can( Capabilities::READ_POSTURE );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/domain_mail_records/check',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$queued = DomainMailRecords::check_again( get_current_user_id() );

					return is_wp_error( $queued ) ? $queued : rest_ensure_response( array( 'state' => DomainMailRecords::state() ) );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);
	}

	/**
	 * How to fix the findings whose cause is outside this plugin (#2430):
	 * the site's address for the message to the host, and Check again, which
	 * asks the check once more and changes nothing.
	 */
	private function register_guidance(): void {
		$key = array(
			'type'              => 'string',
			'required'          => true,
			'enum'              => Guidance::KEYS,
			'validate_callback' => 'rest_validate_request_arg',
			'sanitize_callback' => 'sanitize_key',
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/(?P<key>[a-z0-9_]+)/guidance',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
						return rest_ensure_response( Guidance::state( (string) $request['key'] ) );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
					'args'                => array( 'key' => $key ),
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function ( \WP_REST_Request $request ) {
						$answer = Guidance::check_again( (string) $request['key'], get_current_user_id() );

						if ( is_wp_error( $answer ) ) {
							return $answer;
						}

						$findings = Auditor::findings_for_reader();
						$row      = array_values( wp_list_filter( $findings, array( 'id' => (string) $request['key'] ) ) );

						return rest_ensure_response(
							$answer + array(
								// What the check saw just now, as the row shows it, so the
								// panel can say it rather than "the same thing".
								'evidence' => $row && 'open' === $row[0]['status'] && is_array( $row[0]['evidence'] ) ? $row[0]['evidence'] : array(),
								'state'    => Guidance::state( (string) $request['key'] ),
								'findings' => $findings,
								'overview' => OverviewController::screen_payload(),
							)
						);
					},
					// Asking again changes nothing, as the audit does not.
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
					'args'                => array( 'key' => $key ),
				),
			)
		);
	}

	/**
	 * The quarantine folder's Fix (#2207): what the panel offers, the seal
	 * written where the server reads it, its undo, and asking the server
	 * again in the background.
	 */
	private function register_quarantine_seal(): void {
		register_rest_route(
			'bettershield/v1',
			'/findings/quarantine_unsealed/seal',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static function (): \WP_REST_Response {
						return rest_ensure_response( QuarantineSeal::state() );
					},
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'callback'            => static function () {
						$result = QuarantineSeal::repair();

						return is_wp_error( $result ) ? $result : self::scored( $result + array( 'state' => QuarantineSeal::state() ) );
					},
					// Adds protection, as a hardening item's apply does.
					'permission_callback' => static function (): bool {
						return Permissions::manage();
					},
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/quarantine_unsealed/seal/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = QuarantineSeal::undo( (string) $request['undo'] );

					return is_wp_error( $result ) ? $result : self::scored( array( 'state' => QuarantineSeal::state() ) );
				},
				// Taking the seal away lowers a protection, so it asks for
				// the signed-in session, as every undo here does.
				'permission_callback' => static function () {
					return Permissions::interactive_manage();
				},
				'args'                => array(
					// Checked in the call rather than required here, so a
					// caller without the session is refused for that first.
					'undo' => array(
						'type'              => 'string',
						'required'          => false,
						'default'           => '',
						'pattern'           => '^([a-f0-9]{32})?$',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/findings/quarantine_unsealed/check',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$queued = QuarantineSeal::check_again( get_current_user_id() );

					return is_wp_error( $queued ) ? $queued : rest_ensure_response( array( 'state' => QuarantineSeal::state() ) );
				},
				'permission_callback' => static function (): bool {
					return Permissions::manage();
				},
			)
		);
	}

	/**
	 * The report and the score as they stand after a change, or the refusal.
	 *
	 * @param true|\WP_Error $result
	 * @return \WP_REST_Response|\WP_Error
	 */
	private function answer( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return rest_ensure_response(
			array(
				'findings' => Auditor::findings_for_reader(),
				'overview' => OverviewController::screen_payload(),
			)
		);
	}

	/**
	 * A Fix's answer with the score its change produced. Each of these fixes
	 * has audited by the time it answers; the report is left out, as for the
	 * account fixes, so the row and the Undo beside it stay on the screen.
	 *
	 * @param array<string, mixed> $body What the panel reads.
	 */
	private static function scored( array $body ): \WP_REST_Response {
		return rest_ensure_response( $body + array( 'overview' => OverviewController::screen_payload() ) );
	}

	/**
	 * Move one leftover tool the last probe found into quarantine, and answer
	 * with the report and the score as they now stand.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	private function quarantine_tool( string $path ) {
		$result = \BetterShield\Audit\ExposedArtifacts::quarantine_tool( $path );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		Auditor::run();

		return rest_ensure_response(
			array(
				'quarantined' => $result,
				'findings'    => Auditor::findings_for_reader(),
				'overview'    => OverviewController::screen_payload(),
			)
		);
	}

	/**
	 * Move one downloadable file the last probe found into quarantine, and
	 * answer with the report and the score as they now stand.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	private function quarantine_artifact( string $path ) {
		$result = \BetterShield\Audit\ExposedArtifacts::quarantine_artifact( $path );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		Auditor::run();

		return rest_ensure_response(
			array(
				'quarantined' => $result,
				'findings'    => Auditor::findings_for_reader(),
				'overview'    => OverviewController::screen_payload(),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	private function change_status( string $key, string $action ) {
		$result = 'suppress' === $action
			? Auditor::suppress( $key )
			: Auditor::unsuppress( $key );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// The score moves when a finding stops or starts counting, so the
		// caller gets both surfaces back and never renders a stale total.
		return rest_ensure_response(
			array(
				'findings' => Auditor::findings_for_reader(),
				'overview' => OverviewController::screen_payload(),
			)
		);
	}
}
