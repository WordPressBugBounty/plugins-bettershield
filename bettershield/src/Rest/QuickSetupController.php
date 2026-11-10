<?php
/**
 * The Quick Setup's routes.
 *
 * Every write answers with the whole setup, read back from the site after the
 * write, so the screen always draws what is true rather than what it sent.
 *
 * Every write also asks for a person's own session. The setup is somebody
 * sitting in front of the site answering questions about it, and several of
 * its answers take something away — trusting a proxy, handing sign-in limits
 * to another plugin, undoing a fix — so the routes that can do that ask what
 * every such route here asks, the password again included where the owner
 * turned that on. The rest refuse a token and ask nothing more of a person.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Capabilities;
use BetterShield\Login\Protection;
use BetterShield\Onboarding\Coexistence;
use BetterShield\Onboarding\DeactivationFeedback;
use BetterShield\Onboarding\Ecosystem;
use BetterShield\Onboarding\QuickSetup;
use BetterShield\Onboarding\SafeFixes;
use BetterShield\Onboarding\Usage;
use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class QuickSetupController {

	private const NS = 'bettershield/v1';

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_filter( 'rest_post_dispatch', array( self::class, 'drop_queued_redirect' ), 10, 3 );
	}

	/**
	 * Whether a route is one of the setup's own.
	 */
	public static function is_setup_route( string $route ): bool {
		return 0 === strpos( $route . '/', '/' . self::NS . '/quick-setup/' );
	}

	/**
	 * Keep the setup's answers JSON when another plugin has asked to redirect.
	 *
	 * A plugin the Ecosystem step has just switched on can queue a redirect
	 * to its own welcome screen for the next request, from `plugins_loaded`
	 * or `wp_loaded`, and REST requests run both. That next request is the
	 * setup's own, either the next card's install or the step after it. The
	 * web server turns a `Location` header on a 200 into a 302, so the screen
	 * followed it to an admin page and reported a response that was not JSON,
	 * for a plugin that had in fact been installed. None of these routes
	 * redirects, so a `Location` header here was set by something else, and
	 * it is removed before the response's own headers go out.
	 *
	 * @param mixed $result
	 * @param mixed $server
	 * @param mixed $request
	 * @return mixed
	 */
	public static function drop_queued_redirect( $result, $server, $request ) {
		if ( $request instanceof \WP_REST_Request && self::is_setup_route( $request->get_route() ) && ! headers_sent() ) {
			header_remove( 'Location' );
		}

		return $result;
	}

	/**
	 * The capability and a person's own session, without asking for the
	 * password again: for the writes that take nothing away.
	 *
	 * @return bool|\WP_Error
	 */
	public static function session_manage() {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		return Permissions::interactive();
	}

	/**
	 * The usage-data answer: a person's session, and on a network a super
	 * admin's. The report describes the whole network, so a site
	 * administrator's yes would share what is not theirs to share.
	 *
	 * @return bool|\WP_Error
	 */
	public static function session_answer() {
		$session = self::session_manage();

		if ( true !== $session ) {
			return $session;
		}

		if ( ! Usage::may_answer() ) {
			return new \WP_Error(
				'bettershield_network_decides',
				__( 'On a network, a network administrator decides usage sharing once for every site.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/**
	 * Reading the report this site would send: the capability, and on a
	 * network a super admin's, because the report is the network's (its
	 * address, name and administrator, and the main site's theme and plugins).
	 *
	 * @return bool|\WP_Error
	 */
	public static function reads_report() {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return false;
		}

		if ( ! Usage::may_answer() ) {
			return new \WP_Error( 'bettershield_network_report', __( 'On a network, only a network administrator can read the usage report.', 'bettershield' ), array( 'status' => 403 ) );
		}

		return true;
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function arg( string $type, bool $required = true, array $extra = array() ): array {
		return array_merge(
			array(
				'type'              => $type,
				'required'          => $required,
				'validate_callback' => 'rest_validate_request_arg',
				'sanitize_callback' => 'rest_sanitize_request_arg',
			),
			$extra
		);
	}

	/**
	 * The setup as it stands, as a response.
	 */
	private static function state( bool $with_summary = false, array $extra = array() ): \WP_REST_Response {
		return rest_ensure_response( array_merge( $extra, array( 'state' => QuickSetup::payload( $with_summary ) ) ) );
	}

	/**
	 * @param callable(): (true|\WP_Error) $write
	 * @return \WP_REST_Response|\WP_Error
	 */
	private static function then_state( callable $write, bool $with_summary = false ) {
		$result = $write();

		return is_wp_error( $result ) ? $result : self::state( $with_summary );
	}

	public function register_routes(): void {
		$manage   = array( Permissions::class, 'manage' );
		$session  = array( self::class, 'session_manage' );
		$answers  = array( self::class, 'session_answer' );
		$weakens  = array( Permissions::class, 'interactive_manage' );

		register_rest_route(
			self::NS,
			'/quick-setup',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => self::state( QuickSetup::is_done() && 'ready' === QuickSetup::state()['step'] ),
				'permission_callback' => $manage,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/step',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'step'    => self::arg( 'string', true, array( 'enum' => QuickSetup::STEPS ) ),
					// The step left behind, and whether by Skip.
					'passed'  => self::arg( 'string', false, array( 'enum' => QuickSetup::STEPS ) ),
					'skipped' => self::arg( 'boolean', false ),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					QuickSetup::set_step( (string) $request->get_param( 'step' ), (string) $request->get_param( 'passed' ), (bool) $request->get_param( 'skipped' ) );

					return rest_ensure_response( array( 'step' => QuickSetup::state()['step'] ) );
				},
				'permission_callback' => $session,
			)
		);

		/*
		 * The usage-data question. A person's session and nothing less: the
		 * yes is what lets something about the site leave it, and a credential
		 * that could give it would be a credential that could send the report.
		 */
		register_rest_route(
			self::NS,
			'/quick-setup/consent',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'answer' => self::arg( 'string', true, array( 'enum' => array( 'yes', 'skip', 'no' ) ) ),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$answer = (string) $request->get_param( 'answer' );

					if ( 'skip' === $answer ) {
						Usage::skip();
					} else {
						Usage::answer( 'yes' === $answer );
					}

					return self::state();
				},
				'permission_callback' => $answers,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/coexistence',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'choices' => self::arg( 'object', true ),
					// The other plugins' settings to bring over, by source.
					'import'  => self::arg(
						'array',
						false,
						array(
							'items'    => array(
								'type'      => 'string',
								'maxLength' => 32,
							),
							'maxItems' => 10,
						)
					),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => QuickSetup::save_coexistence( $request->get_param( 'choices' ), $request->get_param( 'import' ) )
				),
				'permission_callback' => $weakens,
			)
		);

		/*
		 * Switch off another security plugin the coexistence check found, at
		 * the owner's press, so choosing BetterShield for a job does not mean
		 * leaving the setup for the Plugins screen. It switches a protection
		 * off, so it asks for the password; only a plugin the check names.
		 */
		register_rest_route(
			self::NS,
			'/quick-setup/coexistence/deactivate',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'plugin'  => self::arg( 'string', true, array( 'maxLength' => 255 ) ),
					// The choices on screen, saved or not: the plugin is
					// switched off only once each of its jobs is BetterShield's.
					'choices' => self::arg( 'object', false ),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => Coexistence::deactivate(
						(string) $request->get_param( 'plugin' ),
						is_array( $request->get_param( 'choices' ) ) ? $request->get_param( 'choices' ) : null
					)
				),
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/site',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'team'       => self::arg( 'string', true, array( 'enum' => array( 'solo', 'team' ) ) ),
					'proxy'      => self::arg( 'string', true, array( 'enum' => array( 'direct', 'cloudflare', 'other' ) ) ),
					'recipients' => self::arg(
						'array',
						true,
						array(
							// Checked by the alert settings, which say which
							// address is wrong and why; the schema's own
							// check answered only "Invalid parameter(s)".
							'items'    => array(
								'type' => 'string',
							),
							'maxItems' => 5,
						)
					),
					'digest'     => self::arg( 'boolean', true ),
					'instant'    => self::arg( 'boolean', true ),
					// Named here rather than on Login & Access; left out, the
					// list stays as it is. Checked by Login & Access's save.
					'trusted_proxies' => self::arg(
						'array',
						false,
						array(
							'items'    => array( 'type' => 'string' ),
							'maxItems' => Protection::MAX_LIST_ENTRIES,
						)
					),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => QuickSetup::save_site(
						array(
							'team'       => $request->get_param( 'team' ),
							'proxy'      => $request->get_param( 'proxy' ),
							'recipients' => (array) $request->get_param( 'recipients' ),
							'digest'     => (bool) $request->get_param( 'digest' ),
							'instant'    => (bool) $request->get_param( 'instant' ),
						) + ( null === $request->get_param( 'trusted_proxies' ) ? array() : array( 'trusted_proxies' => (array) $request->get_param( 'trusted_proxies' ) ) )
					)
				),
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/recovery/received',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'received' => self::arg( 'boolean', true ),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => QuickSetup::confirm_received( (bool) $request->get_param( 'received' ) )
				),
				'permission_callback' => $session,
			)
		);

		// Issuing a new link retires the one on record, which is why this
		// asks what the Recovery tab's own regenerate asks.
		register_rest_route(
			self::NS,
			'/quick-setup/recovery/resend',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$url  = null;
					$sent = RecoveryLink::issue_and_mail( $url );

					if ( null === $sent ) {
						return new \WP_Error(
							'bettershield_recovery_not_issued',
							__( 'A new recovery link could not be saved, so nothing was sent. The link you had still works.', 'bettershield' ),
							array( 'status' => 503 )
						);
					}

					// A mail that was not accepted has still retired the link
					// the owner had, so the new one comes back to be shown
					// once. One that was accepted is in their inbox, and stays
					// off the screen.
					return self::state( false, $sent ? array( 'sent' => true ) : array( 'sent' => false, 'url' => (string) $url ) );
				},
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/recovery/codes',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$codes = OfflineCodes::issue();

					if ( array() === $codes ) {
						return new \WP_Error(
							'bettershield_codes_not_issued',
							__( 'The codes could not be stored, so none were issued. Try again.', 'bettershield' ),
							array( 'status' => 503 )
						);
					}

					return self::state( false, array( 'codes' => $codes ) );
				},
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/two-factor/require',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'required' => self::arg( 'boolean', true ),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => QuickSetup::require_for_admins( (bool) $request->get_param( 'required' ) )
				),
				'permission_callback' => $weakens,
			)
		);

		// Adds blocks and lifts none, so the person's session is enough.
		register_rest_route(
			self::NS,
			'/quick-setup/common-names',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state( static fn() => QuickSetup::block_common_names( (array) ( $request['names'] ?? array() ) ) ),
				'permission_callback' => $session,
				'args'                => array(
					// The owner's own names to refuse with the common ones (#1965).
					'names' => array(
						'type'              => 'array',
						'required'          => false,
						'default'           => array(),
						'maxItems'          => 20,
						'items'             => array(
							'type'      => 'string',
							'maxLength' => 60,
						),
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'rest_sanitize_request_arg',
					),
				),
			)
		);

		// Lifts a block, so it asks for the password as Login & access does.
		register_rest_route(
			self::NS,
			'/quick-setup/common-names/unblock',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					// A common name, or one of the owner's own the setup refused
					// (#2456); which, is checked where it is lifted.
					'name' => self::arg( 'string', true, array( 'maxLength' => 60 ) ),
				),
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state( static fn() => QuickSetup::unblock_common_name( (string) $request->get_param( 'name' ) ) ),
				'permission_callback' => $weakens,
			)
		);

		// Lifts every block this setup made, so it asks as one lift does (#2457).
		register_rest_route(
			self::NS,
			'/quick-setup/common-names/unblock-all',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn() => self::then_state( static fn() => QuickSetup::unblock_all_names() ),
				'permission_callback' => $weakens,
			)
		);

		// Gives back what muting took away, so the person's session is enough.
		register_rest_route(
			self::NS,
			'/quick-setup/alerts/unmute',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn() => self::then_state( static fn() => QuickSetup::unmute_alerts() ),
				'permission_callback' => $session,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/fixes',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'items' => self::arg(
						'array',
						true,
						array(
							'items'    => array(
								'type' => 'string',
								'enum' => SafeFixes::ids(),
							),
							'maxItems' => count( SafeFixes::ids() ),
						)
					),
					// The ticked fixes whose conflict warning the screen showed.
					// Any other fix with a warning is held, however it was ticked.
					'confirm' => self::arg(
						'array',
						false,
						array(
							'items'    => array(
								'type' => 'string',
								'enum' => SafeFixes::ids(),
							),
							'maxItems' => count( SafeFixes::ids() ),
							'default'  => array(),
						)
					),
					// The Ready step's switch putting back a fix it switched off.
					'rejoin'  => self::arg( 'boolean', false, array( 'default' => false ) ),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$rejoin = (bool) $request->get_param( 'rejoin' );
					$result = SafeFixes::apply( (array) $request->get_param( 'items' ), (array) $request->get_param( 'confirm' ), $rejoin );

					// The Ready step's switch is answered with the summary that
					// step draws: an answer without it would replace the step's
					// state and take the list of fixes off the screen.
					return self::state( $rejoin, $result );
				},
				'permission_callback' => $session,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/fixes/preview',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( array( 'preview' => SafeFixes::preview() ) ),
				'permission_callback' => $manage,
			)
		);

		// Taking the set away weakens the site, so it asks for what the
		// per-fix undo asks for.
		register_rest_route(
			self::NS,
			'/quick-setup/fixes/undo-set',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function () {
					$result = SafeFixes::undo_set();

					return is_wp_error( $result ) ? $result : self::state( true, $result );
				},
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/fixes/(?P<item>[a-z_]+)/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static fn( \WP_REST_Request $request ) => self::then_state(
					static fn() => SafeFixes::undo( (string) $request->get_param( 'item' ) ),
					true
				),
				'permission_callback' => $weakens,
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/ecosystem/install',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'slug' => self::arg( 'string', true, array( 'enum' => array_keys( Ecosystem::catalog() ) ) ),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = Ecosystem::install( (string) $request->get_param( 'slug' ) );

					return is_wp_error( $result ) ? $result : rest_ensure_response( $result );
				},
				// The person first, then whether they may install here: a
				// credential is refused as a credential whatever it could do.
				'permission_callback' => static function () {
					$session = self::session_manage();

					if ( true !== $session ) {
						return $session;
					}

					return Ecosystem::available();
				},
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/complete',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'skipped' => self::arg( 'boolean', true ),
				),
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					$skipped = (bool) $request->get_param( 'skipped' );

					// Skipping the whole setup before answering the first
					// question is a skip of that question too: nothing is
					// sent, and the one reminder is owed.
					if ( $skipped ) {
						Usage::skip();
					}

					QuickSetup::complete( $skipped );

					return self::state( ! $skipped );
				},
				'permission_callback' => $session,
			)
		);

		// Settings' "Run Quick Setup Again": a finished setup is closed to its
		// URL until the owner asks for it here.
		register_rest_route(
			self::NS,
			'/quick-setup/reopen',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
					QuickSetup::reopen( (string) $request['step'] );

					return rest_ensure_response( array( 'url' => QuickSetup::url() ) );
				},
				'permission_callback' => $session,
				'args'                => array(
					// Where the choice the screen pointed at is made.
					'step' => array(
						'type'              => 'string',
						'required'          => false,
						'enum'              => QuickSetup::STEPS,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);

		/*
		 * The answer to "is this a staging copy or a move?", and its undo.
		 * Both ask for the session. Marking a copy staging mutes every alert,
		 * refuses the hub and stops usage reports — what muting alerts on
		 * their own screen asks the password for — so that answer asks for it
		 * too, as does an undo that would put the same quiet back. A move, and
		 * an undo that hears the alerts again, take nothing away.
		 */
		register_rest_route(
			self::NS,
			'/site-identity/answer',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = \BetterShield\Onboarding\SiteIdentity::answer( (string) $request['answer'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array_merge( $result, array( 'site_identity' => \BetterShield\Onboarding\SiteIdentity::overview() ) ) );
				},
				'permission_callback' => static function ( \WP_REST_Request $request ) use ( $session, $weakens ) {
					return \BetterShield\Onboarding\SiteIdentity::STAGING === (string) $request['answer'] ? $weakens() : $session();
				},
				'args'                => array(
					'answer' => array(
						'type'              => 'string',
						'required'          => true,
						'enum'              => array( 'staging', 'moved' ),
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_key',
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/site-identity/undo',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = \BetterShield\Onboarding\SiteIdentity::undo( (string) $request['token'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'site_identity' => \BetterShield\Onboarding\SiteIdentity::overview() ) );
				},
				'permission_callback' => static function ( \WP_REST_Request $request ) use ( $session, $weakens ) {
					return \BetterShield\Onboarding\SiteIdentity::undo_quietens( (string) $request['token'] ) ? $weakens() : $session();
				},
				'args'                => array(
					'token' => array(
						'type'              => 'string',
						'required'          => true,
						'maxLength'         => 64,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		// Done with the card left after a move: it goes, and its undo stays.
		register_rest_route(
			self::NS,
			'/site-identity/done',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function ( \WP_REST_Request $request ) {
					$result = \BetterShield\Onboarding\SiteIdentity::done( (string) $request['token'] );

					return is_wp_error( $result ) ? $result : rest_ensure_response( array( 'site_identity' => \BetterShield\Onboarding\SiteIdentity::overview() ) );
				},
				'permission_callback' => $session,
				'args'                => array(
					'token' => array(
						'type'              => 'string',
						'required'          => true,
						'maxLength'         => 64,
						'validate_callback' => 'rest_validate_request_arg',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/quick-setup/offer/dismiss',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					QuickSetup::dismiss_offer();

					return rest_ensure_response( array( 'dismissed' => true ) );
				},
				'permission_callback' => $session,
			)
		);

		/*
		 * The same answer from Settings, where it can be changed at any time,
		 * and from the one reminder a skipped question earns.
		 */
		register_rest_route(
			self::NS,
			'/settings/usage',
			array(
				array(
					'methods'             => \WP_REST_Server::READABLE,
					'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( Usage::for_screen() ),
					'permission_callback' => $manage,
				),
				array(
					'methods'             => \WP_REST_Server::CREATABLE,
					'args'                => array(
						'allowed' => self::arg( 'boolean', true ),
					),
					'callback'            => static function ( \WP_REST_Request $request ): \WP_REST_Response {
						Usage::answer( (bool) $request->get_param( 'allowed' ) );

						return rest_ensure_response( Usage::for_screen() );
					},
					'permission_callback' => $answers,
				),
			)
		);

		/*
		 * The report this site would send, read and sent nowhere. A read: it
		 * builds the report the way sending does, records nothing and
		 * schedules nothing.
		 */
		register_rest_route(
			self::NS,
			'/settings/usage/preview',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => static fn(): \WP_REST_Response => rest_ensure_response( Usage::preview() ),
				'permission_callback' => array( self::class, 'reads_report' ),
			)
		);

		register_rest_route(
			self::NS,
			'/usage/reminder/dismiss',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => static function (): \WP_REST_Response {
					Usage::dismiss_reminder();

					return rest_ensure_response( Usage::for_screen() );
				},
				'permission_callback' => $answers,
			)
		);

		/*
		 * Why the plugin is being switched off, from the question its
		 * Deactivate link asks on the Plugins screen. Kept for the one report
		 * deactivating sends, and refused where that report does not go, so
		 * an answer never waits for a send that will not happen.
		 */
		register_rest_route(
			self::NS,
			'/usage/deactivation-reason',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'args'                => array(
					'reason'  => self::arg( 'string', true, array( 'enum' => array_keys( DeactivationFeedback::REASONS ) ) ),
					'details' => self::arg( 'string', false, array( 'maxLength' => DeactivationFeedback::DETAILS_MAX ) ),
				),
				'callback'            => static function ( \WP_REST_Request $request ) {
					if ( ! Usage::sends_on_deactivation() ) {
						return new \WP_Error( 'bettershield_usage_not_shared', __( 'This site does not share usage data, so there is nowhere to send a reason.', 'bettershield' ), array( 'status' => 409 ) );
					}

					if ( ! DeactivationFeedback::store( (string) $request->get_param( 'reason' ), (string) $request->get_param( 'details' ) ) ) {
						return new \WP_Error( 'bettershield_reason_not_saved', __( 'The reason could not be saved. Deactivate without it.', 'bettershield' ), array( 'status' => 500 ) );
					}

					return rest_ensure_response( array( 'saved' => true ) );
				},
				// The person at the Plugins screen, holding what deactivating
				// takes there: activate_plugins on a site, the network's own
				// plugin capability on a network, where the report is the
				// network's. Never a stored credential.
				'permission_callback' => static function () {
					$interactive = Permissions::interactive();

					if ( true !== $interactive ) {
						return $interactive;
					}

					return current_user_can( is_multisite() ? 'manage_network_plugins' : 'activate_plugins' );
				},
			)
		);
	}
}
