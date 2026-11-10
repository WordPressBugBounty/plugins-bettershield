<?php
/**
 * The owner's side of the optional hub connection.
 *
 * Reading where the hub is and what it holds, changing where it is, starting
 * a connection and ending one, and turning the Hub link on or off, which is a
 * choice of its own that connecting alone never makes. Starting a connection
 * turns on the switches it needs — reading, changing where the owner chose
 * it, and the connection itself — each through the setter every other screen
 * uses, so each flip is on the record the same way. It never turns one off:
 * the owner's other assistants may rely on them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Abilities\Registrar;
use BetterShield\Events\Writer;
use BetterShield\Hub\Link\Link;
use BetterShield\Mcp\Hub;
use BetterShield\Mcp\Manager;
use BetterShield\Mcp\Pairing;
use BetterShield\Recovery\Lockdown;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HubController {

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/hub',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'permission_callback' => array( Permissions::class, 'manage' ),
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( self::state() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/hub/connect',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array(
					// Pressed on the Quick Setup's hub step, which the hub
					// sends the owner back to (#2297).
					'from'   => array(
						'required'          => false,
						'type'              => 'string',
						'enum'              => array( '', 'setup' ),
						'default'           => '',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => array( $this, 'connect' ),
			)
		);

		/*
		 * The Hub link: on with the classes it sends, or off. Off deletes its
		 * key; on makes a new one.
		 */
		register_rest_route(
			'bettershield/v1',
			'/hub/link',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					// Turning the link on adds monitoring and is not asked for
					// the password; turning it off takes it away and is (#1785),
					// and so is turning off a class it sends while it stays on.
					// The classes are read as the callback below reads them.
					if ( false === rest_sanitize_boolean( $request['on'] ?? false ) ) {
						return Permissions::interactive_manage_if( true );
					}

					$record = Link::record();

					return Permissions::interactive_manage_if(
						Link::narrows(
							null === $request['posture'] ? $record['posture'] : rest_sanitize_boolean( $request['posture'] ),
							null === $request['full_log'] ? $record['full_log'] : rest_sanitize_boolean( $request['full_log'] )
						)
					);
				},
				'args'                => array(
					'on'       => array(
						'required'          => true,
						'type'              => 'boolean',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
					'posture'  => array(
						'required'          => false,
						'type'              => 'boolean',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
					'full_log' => array(
						'required'          => false,
						'type'              => 'boolean',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					if ( ! $request['on'] ) {
						Link::disable( 'owner' );

						return rest_ensure_response( self::state() );
					}

					$record   = Link::record();
					$posture  = null === $request['posture'] ? $record['posture'] : (bool) $request['posture'];
					$full_log = null === $request['full_log'] ? $record['full_log'] : (bool) $request['full_log'];
					$on       = Link::enable( $posture, $full_log );

					if ( is_wp_error( $on ) ) {
						return $on;
					}

					return rest_ensure_response( self::state() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/hub/disconnect',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function () {
					// Taking the hub's access away: never asked (#1820).
					return Permissions::interactive_manage_access( false );
				},
				'callback'            => static function (): \WP_REST_Response {
					foreach ( Hub::apps() as $app ) {
						Writer::instance()->record(
							'mcp_app_revoked',
							Writer::SEVERITY_LOW,
							array(
								'object_type' => 'mcp_app',
								'object_id'   => (string) $app['id'],
							)
						);
					}

					Hub::disconnect();

					return rest_ensure_response( self::state() );
				},
			)
		);
	}

	/**
	 * Turn on what the connection needs, mint its ticket, and say where the
	 * browser goes next.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function connect( \WP_REST_Request $request ) {
		if ( ! Manager::is_available() ) {
			return new \WP_Error(
				'bettershield_hub_unavailable',
				__( 'Connecting to the hub needs WordPress 6.9 or later.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// Refused before anything is switched on: there is no hub to send
		// the browser to, and the default is not one the host would accept.
		if ( Hub::pin_is_invalid() ) {
			return new \WP_Error(
				'bettershield_hub_pin_invalid',
				__( 'BETTERSHIELD_HUB_URL in wp-config.php is not a usable https address, so this site cannot connect.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// Refused before anything is switched on: the hub signs in through
		// this site's pretty addresses, and with plain permalinks there are
		// none, so it would refuse the site and leave the switches on.
		if ( ! Pairing::pretty_routed() ) {
			return new \WP_Error(
				'bettershield_hub_plain_permalinks',
				__( 'Connecting needs pretty permalinks. Choose any structure except Plain under Settings → Permalinks, then come back.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// Refused before anything is switched on: a lockdown pauses every
		// connected app, and the exchange would refuse the hub's code.
		if ( Lockdown::is_active() ) {
			return new \WP_Error(
				'bettershield_hub_lockdown',
				__( 'This site is locked down, which pauses connected apps. Connect once the lockdown ends.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// Refused before anything is switched on: a copy marked as staging
		// refuses the hub, which would be turned away the moment it arrived,
		// with agent access left on behind it (#2151).
		if ( \BetterShield\Onboarding\SiteIdentity::is_staging() ) {
			return new \WP_Error(
				'bettershield_hub_staging',
				__( 'This copy is marked as staging, which refuses the hub. Undo that on the Overview to connect.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// A connection always reads and makes fixes that can be undone; what
		// agents may do is changed under Agents afterwards.
		$access = Hub::ACCESS_WRITE;

		if ( ! Registrar::is_enabled() ) {
			$read = Registrar::set_enabled( true );

			if ( is_wp_error( $read ) ) {
				return $read;
			}
		}

		if ( Hub::ACCESS_WRITE === $access && ! Registrar::write_enabled() ) {
			$written = Registrar::set_write_enabled( true );

			if ( is_wp_error( $written ) ) {
				return $written;
			}
		}

		if ( ! Manager::is_enabled() ) {
			Manager::set_enabled( true );
		}

		$ticket = Hub::mint_ticket( get_current_user_id(), $access );
		$from   = 'setup' === (string) $request['from'] ? 'setup' : '';

		if ( 'setup' === $from ) {
			\BetterShield\Onboarding\QuickSetup::await_hub();
		}

		Writer::instance()->flush();

		return rest_ensure_response(
			array(
				'redirect' => Hub::connect_url( $ticket, $access, $from ),
				'expires'  => gmdate( 'c', time() + Hub::TICKET_TTL ),
				'hub'      => self::state(),
			)
		);
	}

	/**
	 * Where the hub is and what it holds, as the screen reads it.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$apps = array_map(
			static function ( array $app ): array {
				return array(
					'id'         => (string) $app['id'],
					'name'       => (string) $app['name'],
					// The hub this grant was approved for, which is not the
					// configured one when the address moved underneath it.
					'host'       => '' !== $app['hub'] ? (string) $app['hub'] : Hub::host(),
					'scope'      => (string) $app['scope'],
					'granted_at' => $app['granted_at'] > 0 ? gmdate( 'c', (int) $app['granted_at'] ) : null,
					'last_used'  => $app['last_used'] > 0 ? gmdate( 'c', (int) $app['last_used'] ) : null,
				);
			},
			Hub::apps()
		);

		$refused_by = Hub::refused_by();

		return array(
			'url'           => Hub::url(),
			'host'          => Hub::host(),
			'pin_invalid'   => Hub::pin_is_invalid(),
			'available'     => Manager::is_available(),
			'pretty_routed' => Pairing::pretty_routed(),
			'connected'     => array() !== $apps,
			/*
			 * A grant is not access. What the site does with a hub call is
			 * decided by its own switches, and the card says that rather
			 * than what the grant was once approved for.
			 */
			'reachable'     => array() === $refused_by,
			'refused_by'    => $refused_by,
			'writes'        => Registrar::write_enabled(),
			'agents_url'    => admin_url( 'admin.php?page=' . \BetterShield\Admin\Sections::AGENTS . '&tab=connect' ),
			'overview_url'  => admin_url( 'admin.php?page=' . \BetterShield\Admin\Sections::ROOT ),
			'recovery_url'  => admin_url( 'admin.php?page=bettershield-protect&tab=recovery' ),
			'apps'          => $apps,
			'link'          => Link::state(),
		);
	}
}
