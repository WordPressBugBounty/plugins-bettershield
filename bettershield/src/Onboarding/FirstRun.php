<?php
/**
 * The plugin's first minute.
 *
 * Activation already does the useful work — the baseline audit runs and the
 * recovery link is created and mailed. What was missing is the owner being
 * told any of it. This holds whether that account is still owed, and the
 * redirect that takes the owner to the Quick Setup once.
 *
 * Nothing here blocks the dashboard, gates a screen, or has to be finished
 * before the plugin works. Every step of the setup has its own Skip, and a
 * setup left part way is offered again on the Overview rather than required.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Events\Writer;
use BetterShield\Recovery\RecoveryLink;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FirstRun {

	/** autoload=false: read on our screens, never on every request. */
	public const OPTION = 'bettershield_first_run';

	/**
	 * Set at activation, consumed by the first admin page load. A transient
	 * rather than an option because an unconsumed redirect must expire: an
	 * owner who activates and never returns should not be redirected days
	 * later from an unrelated screen.
	 */
	private const REDIRECT_TRANSIENT = 'bettershield_first_run_redirect';

	private const REDIRECT_TTL = 60;

	public function register(): void {
		add_action( 'admin_init', array( $this, 'maybe_redirect' ) );
	}

	/**
	 * Called from activation. Records that the setup is owed and arms the
	 * one-time redirect.
	 *
	 * Re-activation of a site that already answered does not ask again — the
	 * option survives deactivation, and being shown the welcome a second time
	 * reads as the plugin having forgotten the site. A site that never answered
	 * is still owed the setup, so its re-activation arms the redirect again. A site
	 * from before the setup existed is offered it on the Overview instead.
	 *
	 * The redirect is armed only when a person pressed Activate on the Plugins
	 * screen. An activation from the terminal has nobody to send anywhere, and
	 * one made by another plugin's installer through a background request is
	 * somebody in the middle of that plugin's own setup: sending them here
	 * afterwards would take them out of it. Both are offered the setup on the
	 * Overview instead.
	 */
	public static function begin(): void {
		if ( false === get_option( self::OPTION ) ) {
			update_option(
				self::OPTION,
				array(
					'status'     => 'pending',
					'started_at' => gmdate( 'c' ),
				),
				false
			);

			QuickSetup::begin();
		}

		if ( ! self::is_pending() || 'pending' !== QuickSetup::state()['status'] ) {
			return;
		}

		// However it was activated, the first visit to the plugin opens the
		// setup once; a bulk or background activation is never redirected.
		QuickSetup::owe_visit();

		if ( self::activated_in_the_background() ) {
			return;
		}

		set_transient( self::REDIRECT_TRANSIENT, 1, self::REDIRECT_TTL );
	}

	/**
	 * Whether this activation came from something other than a person on the
	 * Plugins screen: the terminal, or a request made by a script.
	 */
	private static function activated_in_the_background(): bool {
		return wp_doing_ajax()
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'WP_CLI' ) && WP_CLI );
	}

	public static function is_pending(): bool {
		$state = get_option( self::OPTION );

		return is_array( $state ) && 'pending' === ( $state['status'] ?? '' );
	}

	/**
	 * The owner is done with the first run — either having worked through the
	 * setup or having skipped it. Both mean "stop offering me this".
	 *
	 * @param bool $record Whether to write the event. The Quick Setup records
	 *                     its own, which says which of the two it was.
	 */
	public static function complete( bool $record = true ): void {
		if ( ! self::is_pending() ) {
			return;
		}

		$state = get_option( self::OPTION );

		update_option(
			self::OPTION,
			array(
				'status'       => 'done',
				'started_at'   => is_array( $state ) ? ( $state['started_at'] ?? null ) : null,
				'completed_at' => gmdate( 'c' ),
			),
			false
		);

		if ( $record ) {
			Writer::instance()->record( 'first_run_completed' );
		}
	}

	/**
	 * What the panel needs to draw itself, and what the Overview payload
	 * carries so the screen never has to ask a second endpoint.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$login = \BetterShield\Login\Protection::instance()->settings();

		return array(
			'pending'  => self::is_pending(),
			// Sign-in protection as the owner means it: attempts are counted
			// and a connection that keeps failing is paused.
			'login_protection_enabled' => $login['enabled'] && $login['attempt_limit'],
			// As enforced here: a network's floor counts as much as the site's own (#1784).
			'two_factor_required' => array() !== \BetterShield\Network\Policies::effective_two_factor_roles( \BetterShield\TwoFactor\Policy::instance()->settings()['roles'] ),
			'recovery' => array(
				// Whether a link exists, and whether the activation mail was
				// accepted for delivery. Acceptance is not proof of arrival, so
				// the screen offers to send it again either way.
				// Tri-state, read through the one function that owns this
				// option: null means no attempt was ever recorded — a link
				// generated from the dashboard is read on screen and never
				// mailed. Collapsing that into false told the owner the email
				// had failed when none was sent, which pushes them to
				// regenerate, which silently retires the link they hold.
				'exists' => RecoveryLink::link_exists(),
				'mailed' => Auditor::recovery_mail_result(),
			),
		);
	}

	/**
	 * Send the owner to the Quick Setup once, on the first admin page they
	 * load after activating.
	 *
	 * Deliberately silent when it cannot be the right thing to do: during bulk
	 * or network activation the owner is mid-task on the plugins screen and
	 * being thrown elsewhere loses the rest of their selection; under WP-CLI
	 * and during AJAX there is nobody to redirect; and a user without the
	 * capability has nothing to land on.
	 */
	public function maybe_redirect(): void {
		// Before the transient is read, so the requests that never redirect
		// (admin-ajax.php above all, which a store's queue runner reaches
		// about once a minute) do not pay for the lookup.
		if ( wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) || is_network_admin() ) {
			return;
		}

		if ( ! get_transient( self::REDIRECT_TRANSIENT ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading, not acting: core's own bulk-activation marker.
		if ( isset( $_GET['activate-multi'] ) ) {
			delete_transient( self::REDIRECT_TRANSIENT );

			return;
		}

		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			return;
		}

		delete_transient( self::REDIRECT_TRANSIENT );

		wp_safe_redirect( QuickSetup::url() );
		exit;
	}
}
