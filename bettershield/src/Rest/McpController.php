<?php
/**
 * The owner's side of the assistant endpoint.
 *
 * Everything an administrator does about the connection happens here: turning
 * the endpoint on, minting a credential and choosing how far it reaches,
 * replacing one, opening the short window in which an application may register
 * itself, ending everything, and seeing which applications hold a grant. The
 * endpoint an assistant actually talks to is elsewhere and authenticates
 * itself; these routes carry the plugin's own capability like every other
 * screen.
 *
 * The credential appears in exactly two answers — the one that mints it and
 * the one that replaces it — and in no read, no listing and no log. A screen
 * that could ask for it again would be a screen an attacker could ask for it
 * from.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Abilities\Registrar;
use BetterShield\Events\Writer;
use BetterShield\Hub\Link\Link;
use BetterShield\Mcp\AppTools;
use BetterShield\Mcp\Hub;
use BetterShield\Mcp\Manager;
use BetterShield\Mcp\OAuth;
use BetterShield\Mcp\Pairing;
use BetterShield\Mcp\Scopes;
use BetterShield\Mcp\SelfTest;
use BetterShield\Mcp\Server;
use BetterShield\Mcp\Tools;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class McpController {

	/** What an owner may ask a credential to be allowed to do. */
	private const SCOPE_ARG = array(
		'required'          => false,
		'type'              => 'string',
		'enum'              => array( Scopes::READ_ONLY, Scopes::READ_WRITE ),
		'default'           => Scopes::READ_WRITE,
		'validate_callback' => 'rest_validate_request_arg',
		'sanitize_callback' => 'rest_sanitize_request_arg',
	);

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_filter( 'rest_pre_serve_request', array( $this, 'serve_stream' ), 10, 3 );
	}

	/**
	 * An answer the endpoint built as an event stream goes out as one.
	 *
	 * The REST server would encode the stream's text as a JSON string; the
	 * headers it already sent name the content type, so the body is written
	 * as it is and the server is told it has been served. The stream is told
	 * from a JSON answer by what it holds, never by reading headers back.
	 *
	 * @param mixed $served
	 * @param mixed $result
	 * @param mixed $request
	 * @return mixed
	 */
	public function serve_stream( $served, $result, $request ) {
		if ( $served || ! $result instanceof \WP_REST_Response || ! $result->get_data() instanceof \BetterShield\Mcp\EventStream ) {
			return $served;
		}

		echo $result->get_data()->body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- an event stream of JSON this endpoint encoded itself; the content type was sent with the headers.

		return true;
	}

	public function register_routes(): void {
		register_rest_route(
			'bettershield/v1',
			'/mcp/connection',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'permission_callback' => array( Permissions::class, 'manage' ),
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( self::connection() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/enable',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					// Off is never asked for the password; on is (#1820).
					return Permissions::interactive_manage_access( false !== rest_sanitize_boolean( $request['enabled'] ?? true ) );
				},
				'args'                => array(
					'enabled' => array(
						'required'          => true,
						'type'              => 'boolean',
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$enabled = (bool) $request['enabled'];

					$saved = Manager::set_enabled( $enabled );

					if ( is_wp_error( $saved ) ) {
						return $saved;
					}

					return rest_ensure_response( array( 'enabled' => $enabled ) );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/connect',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array( 'scope' => self::SCOPE_ARG ),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					return rest_ensure_response( self::mint( 'mcp_connected', (string) $request['scope'] ) );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/rotate',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( Permissions::class, 'interactive_manage' ),
				'args'                => array( 'scope' => self::SCOPE_ARG ),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					return rest_ensure_response( self::mint( 'mcp_rotated', (string) $request['scope'] ) );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/disconnect',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function () {
					// Taking access away: the safe direction, never asked (#1820).
					return Permissions::interactive_manage_access( false );
				},
				'callback'            => static function (): \WP_REST_Response {
					/*
					 * Forgetting the pairing ends every app's grant and the
					 * hub's too, and only the pairing used to be written down.
					 * Each grant ended is on the record, as a hub disconnect
					 * already records its own.
					 */
					$ended = OAuth::connected_apps();

					Pairing::forget();

					Writer::instance()->record(
						'mcp_disconnected',
						Writer::SEVERITY_LOW,
						array(
							'object_type' => 'mcp',
							'object_id'   => 'pairing',
						)
					);

					foreach ( $ended as $app ) {
						Writer::instance()->record(
							'mcp_app_revoked',
							Writer::SEVERITY_LOW,
							array(
								'object_type' => 'mcp_app',
								'object_id'   => (string) $app['id'],
								'context'     => array(
									'name'   => Text::clip( (string) $app['name'], 120 ),
									'reason' => 'disconnected',
								),
							)
						);
					}

					return rest_ensure_response( array( 'connection' => self::connection() ) );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/self-test',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => array( Permissions::class, 'manage' ),
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( SelfTest::run() );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/apps',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'permission_callback' => array( Permissions::class, 'manage' ),
				'callback'            => static function (): \WP_REST_Response {
					return rest_ensure_response( array( 'apps' => self::apps() ) );
				},
			)
		);

		// The tools one application may use, narrowed from what its scope
		// allows (#1879). Unticking is never asked; allowing one back is.
		register_rest_route(
			'bettershield/v1',
			'/mcp/apps/(?P<id>[A-Za-z0-9_.-]{1,64})/tools',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'permission_callback' => static function ( \WP_REST_Request $request ) {
					return Permissions::interactive_manage_access( AppTools::widens( (string) $request['id'], (array) $request->get_param( 'tools_denied' ) ) );
				},
				'args'                => array(
					'tools_denied' => array(
						'type'              => 'array',
						'items'             => array( 'type' => 'string' ),
						'maxItems'          => 200,
						'required'          => true,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					$id = (string) $request['id'];

					if ( ! in_array( $id, array_column( OAuth::connected_apps(), 'id' ), true ) ) {
						return new \WP_Error( 'bettershield_no_such_app', __( 'No connected app has that id, so nothing was changed.', 'bettershield' ), array( 'status' => 404 ) );
					}

					$saved = AppTools::set( $id, (array) $request->get_param( 'tools_denied' ) );

					if ( is_wp_error( $saved ) ) {
						return $saved;
					}

					return rest_ensure_response( array( 'apps' => self::apps() ) );
				},
			)
		);

		register_rest_route(
			'bettershield/v1',
			'/mcp/apps/(?P<id>[A-Za-z0-9_.-]{1,64})',
			array(
				'methods'             => \WP_REST_Server::DELETABLE,
				'permission_callback' => static function () {
					// Taking access away: the safe direction, never asked (#1820).
					return Permissions::interactive_manage_access( false );
				},
				'callback'            => static function ( \WP_REST_Request $request ) {
					$id = (string) $request['id'];

					// An id that held nothing removed nothing, and is not
					// recorded as though it had.
					if ( ! OAuth::revoke_client( $id ) ) {
						return new \WP_Error( 'bettershield_no_such_app', __( 'No connected app has that id, so nothing was removed.', 'bettershield' ), array( 'status' => 404 ) );
					}

					Writer::instance()->record(
						'mcp_app_revoked',
						Writer::SEVERITY_LOW,
						array(
							'object_type' => 'mcp_app',
							'object_id'   => $id,
						)
					);

					return rest_ensure_response( array( 'apps' => self::apps() ) );
				},
			)
		);
	}

	/**
	 * Mint a credential and hand it back once.
	 *
	 * Connecting and rotating are the same act with different reasons behind
	 * them, so they are one function: whatever was there stops working, a new
	 * one exists, and the plaintext is in this answer and nowhere else.
	 *
	 * Rotating is also how an owner narrows or widens a connection, which is
	 * why the scope is chosen here rather than on a separate switch: changing
	 * what a credential may do and replacing the credential are the same act,
	 * and a scope that could be widened without replacing the token would let
	 * a copied one grow without anybody reconnecting anything.
	 *
	 * Which is also why a site that forbids changes mints read only whatever
	 * was asked for. Execution re-checks the write opt-in, so a wide scope
	 * stored while it is off has no teeth today — and gets them the moment the
	 * opt-in is turned on for some unrelated one-off task, with no reconnect
	 * and nobody choosing again. The credential carries what the site can
	 * currently allow, and widening it is a fresh credential like any other.
	 *
	 * The grant is recorded high rather than medium: a pairing token is a
	 * standing bearer credential that runs as the administrator who minted it,
	 * and it outlives the password change an owner makes on suspecting
	 * compromise. Ending one stays low — taking access back is the safe
	 * direction.
	 *
	 * @return array{token: string, connection: array<string, mixed>}
	 */
	private static function mint( string $event, string $scope ): array {
		// What this account can do through an agent, not what the site
		// allows somebody to: a credential runs as the account that minted it.
		$scope = Registrar::can_write() ? Scopes::normalize( $scope ) : Scopes::READ_ONLY;
		$token = Pairing::mint( get_current_user_id(), $scope );

		Writer::instance()->record(
			$event,
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'mcp',
				'object_id'   => 'pairing',
				'context'     => array(
					// The last four characters, which is what the screen shows
					// and all that ever leaves the pairing record.
					'hint'  => Pairing::hint(),
					'scope' => $scope,
				),
			)
		);

		return array(
			'token'      => $token,
			'connection' => self::connection(),
		);
	}

	/**
	 * Everything a screen needs to describe the connection, and no credential.
	 *
	 * @return array<string, mixed>
	 */
	public static function connection(): array {
		$state = Pairing::state();

		return array(
			'enabled'           => Manager::is_enabled(),
			'available'         => Manager::is_available(),
			'connected'         => Pairing::is_connected(),
			'connected_at'      => $state['connected_at'] > 0 ? gmdate( 'c', $state['connected_at'] ) : null,
			'connected_by'      => Pairing::granted_by(),
			// When an assistant last used the credential, or null where none
			// has yet: issued is not connected, and the card said "Connected"
			// for a credential nobody had pasted anywhere (#2062).
			'last_used'         => Pairing::is_connected() && $state['last_used'] > 0 ? gmdate( 'c', $state['last_used'] ) : null,
			// Whether that account can still hold the credential. One that has
			// lost the capability is refused at the door, and the card used to
			// read as healthy over it. Null when nothing is paired.
			'holder_can_act'    => Pairing::is_connected() ? Server::may_act_as( Pairing::user_id() ) : null,
			'token_hint'        => $state['hint'],
			// What the paired credential may do. An empty string rather than a
			// default, so a screen can tell "read only" from "nothing here".
			'scope'             => Pairing::scope(),
			// How many applications hold a grant, with or without a credential
			// minted here. One that signed in through the consent page needs
			// none, and Disconnect ends it all the same.
			'apps'              => count( OAuth::connected_apps() ),
			'endpoint'          => Pairing::address(),
			'fallback_endpoint' => Pairing::fallback_endpoint(),
			'oauth'             => array(
				'issuer'                => OAuth::issuer(),
				'resource_metadata_url' => OAuth::resource_metadata_url(),
				'authorize_url'         => OAuth::authorize_url(),
				'scopes_supported'      => Scopes::supported(),
			),
			'snippets'          => Pairing::snippets(),
			'prompt'            => Pairing::prompt(),
			'health'            => self::health(),
			// The clock every moment in this document was written against, so
			// a screen reads them against it rather than against the browser's.
			'now'               => gmdate( 'c' ),
		);
	}

	/**
	 * What can be answered about the connection without making a request.
	 *
	 * Deliberately separate from the round trip: this is free and always
	 * available, and it tells the two commonest failures apart before anybody
	 * presses a button. A site reachable only over plain HTTP, or whose two
	 * addresses disagree about the scheme, refuses every assistant while
	 * looking healthy from the dashboard.
	 *
	 * @return array<string, mixed>
	 */
	public static function health(): array {
		$home = (string) wp_parse_url( home_url(), PHP_URL_SCHEME );
		$site = (string) wp_parse_url( site_url(), PHP_URL_SCHEME );
		$rest = (string) wp_parse_url( rest_url(), PHP_URL_SCHEME );

		/*
		 * The catalog this credential would actually be offered, not the
		 * larger one nobody can call. The round-trip check counts the same
		 * thing, and the two numbers used to land side by side on one screen
		 * disagreeing about a read-only connection.
		 */
		$scope = Pairing::scope();

		$names = array_map(
			static function ( array $tool ): string {
				return (string) $tool['name'];
			},
			Tools::catalog( '' === $scope ? Scopes::READ_WRITE : $scope )
		);

		return array(
			'https'              => 'https' === $home,
			'scheme_agreement'   => $home === $site && $home === $rest,
			'pretty_routed'      => Pairing::pretty_routed(),
			'tools'              => count( $names ),
			'tool_names'         => $names,
			'read_enabled'       => Registrar::is_enabled(),
			'write_enabled'      => Registrar::write_enabled(),
			'capability_granted' => Registrar::write_capability_held(),
		);
	}

	/**
	 * The applications holding a grant, with the person who approved each one
	 * named rather than numbered, and what each was allowed to do.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function apps(): array {
		$apps  = array();
		$tools = array();

		foreach ( OAuth::connected_apps() as $app ) {
			$user = $app['granted_by'] > 0 ? get_userdata( $app['granted_by'] ) : false;

			$apps[] = array(
				'id'             => $app['id'],
				'name'           => Text::clip( $app['name'], 120 ),
				'scope'          => $app['scope'],
				'granted_at'     => $app['granted_at'] > 0 ? gmdate( 'c', $app['granted_at'] ) : null,
				'granted_by'     => $user
					? array(
						'id'           => (int) $user->ID,
						'display_name' => Text::clip( (string) $user->display_name, 191 ),
					)
					: null,
				'last_used_at'   => $app['last_used'] > 0 ? gmdate( 'c', $app['last_used'] ) : null,
				// The same question for the account that approved it.
				'holder_can_act' => Server::may_act_as( (int) $app['granted_by'] ),
				// The tools its scope allows, and those the owner unticked (#1879).
				'tools'          => $tools[ $app['scope'] ] ??= array_map(
					static fn( array $tool ): array => array(
						'name'   => (string) $tool['name'],
						'title'  => (string) ( $tool['annotations']['title'] ?? $tool['name'] ),
						'writes' => empty( $tool['annotations']['readOnlyHint'] ),
					),
					Tools::catalog( (string) $app['scope'] )
				),
				'tools_denied'   => AppTools::denied( (string) $app['id'] ),
				// So the tools panel can say what unticking the hub's reads costs.
				'is_hub'         => Hub::is_hub_client( (string) $app['id'] ),
				'hub_link_on'    => Link::is_on(),
			);
		}

		return $apps;
	}
}
