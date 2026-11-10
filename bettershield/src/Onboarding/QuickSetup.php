<?php
/**
 * The Quick Setup: where it stands, and what each step saves.
 *
 * Seven steps at most, and none of them required. Skipping a step changes
 * nothing, skipping the whole setup counts as finishing it, and the dashboard
 * works fully either way — the setup only puts in front of the owner, in a
 * safe order, choices that already live on other screens.
 *
 * Every write goes through the class that owns the setting, with its own
 * ledger row and its own activity record, so the setup never becomes a second
 * way of changing the site. And everything the setup shows is read back from
 * the site after the write, never from what the setup believes it did: the
 * Ready step summarizes what is true.
 *
 * The one thing kept here is the setup's own progress — the step to resume
 * at, the owner's answers that belong to no other setting, and whether the
 * card offering the setup has been dismissed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Alerts\Settings as AlertSettings;
use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Integrity\FirstScan;
use BetterShield\Login\Protection;
use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Support\ClientIp;
use BetterShield\TwoFactor\Manager as TwoFactor;
use BetterShield\TwoFactor\Policy as TwoFactorPolicy;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class QuickSetup {

	/** autoload=false: read on this plugin's screens only. */
	public const OPTION = 'bettershield_quick_setup';

	/** The admin page the setup is drawn on. */
	public const PAGE = 'bettershield-setup';

	/** The answers the proxy question takes. */
	private const PROXY_ANSWERS = array( 'direct', 'cloudflare', 'other' );

	/** Every step, in order. The screen decides nothing about which exist. */
	public const STEPS = array( 'welcome', 'coexistence', 'protect', 'ready', 'hub' );

	/**
	 * The steps Protect took over, each of which a setup left part way may
	 * still have saved: it resumes on Protect (#2297).
	 */
	private const MERGED_STEPS = array( 'site', 'recovery', 'fixes', 'ecosystem' );

	/**
	 * How long the setup stays open for the owner to come back to it from
	 * the hub: longer than a connection ticket and the hub's own sign-in.
	 */
	public const HUB_RETURN_FOR = 30 * MINUTE_IN_SECONDS;

	/**
	 * How long the setup's last two steps stay open after Protect finished
	 * it: the owner is still on them, and a reload sent them to the Overview
	 * with the Ecosystem and Hub steps out of reach (#2512).
	 */
	public const FINISHING_FOR = 30 * MINUTE_IN_SECONDS;

	/** How long a finished setup stays open after the owner asks to run it again. */
	public const REOPEN_FOR = DAY_IN_SECONDS;

	/** The grace period offered with the administrator requirement, in days. */
	public const GRACE_DAYS = 14;

	/**
	 * The setup items the Protect step can earn, by the names the score
	 * gives them (Auditor::SETUP_POINTS), in the order the step lists them.
	 */
	private const PROTECT_ITEMS = array( 'sign_in_limits', 'file_editor', 'username_discovery', 'security_headers', 'directory_browsing', 'version_hidden' );

	/**
	 * Checks whose answer can change after the last audit, without the setup
	 * doing anything: what the owner's own request showed about how visits
	 * arrive, WordPress's update check, and a password the owner just signed in
	 * with. Apply's audit reads them, so the setup's score has to as well, or
	 * Apply looks like it cost the points they take.
	 */
	private const AUDIT_READS_AGAIN = array( 'lockouts_not_running', 'core_update_available', 'passwords_below_policy' );

	/** The setup item each safe fix earns, by fix. */
	private const FIX_ITEMS = array(
		'file_editor'        => 'file_editor',
		'version_disclosure' => 'version_hidden',
		'directory_browsing' => 'directory_browsing',
		'user_enumeration'   => 'username_discovery',
		'security_headers'   => 'security_headers',
	);

	/**
	 * The stored progress, with every key present.
	 *
	 * @return array{status: string, step: string, skipped_steps: string[], score_before: int, started_at: int, completed_at: int, skipped: bool, offer: string, opened: bool, team: string, proxy: string, coexistence: array<string, string>, coexistence_saved: bool, coexistence_limiters: string[]|null, recovery_received: int, reopened_at: int, hub_until: int, installed: string[], imported: array<int, array{name: string, count: int}>, deactivated: array<int, array{file: string, name: string}>}
	 */
	public static function state(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$status   = is_string( $stored['status'] ?? null ) ? $stored['status'] : '';
		$limiters = $stored['coexistence_limiters'] ?? null;
		$step     = self::current_step( $stored['step'] ?? '' );
		$skipped  = array_map( array( self::class, 'current_step' ), array_filter( (array) ( $stored['skipped_steps'] ?? array() ), 'is_string' ) );

		return array(
			// '' never begun, 'pending' begun or owed, 'done' finished or skipped.
			'status'               => in_array( $status, array( 'pending', 'done' ), true ) ? $status : '',
			'step'                 => $step,
			// The steps passed by Skip rather than finished, which the stepper
			// draws apart from the finished ones.
			'skipped_steps'        => array_values( array_intersect( self::STEPS, $skipped ) ),
			'started_at'           => (int) ( $stored['started_at'] ?? 0 ),
			// The score as this run of the setup found it, for Ready to show
			// the move; -1 until the run has read it.
			'score_before'         => isset( $stored['score_before'] ) && is_int( $stored['score_before'] ) ? max( -1, min( 100, $stored['score_before'] ) ) : -1,
			// Whether that was read while the first file check still ran, so
			// the check can move it and it cannot be shown as a before.
			'score_unscanned'      => ! empty( $stored['score_unscanned'] ),
			// The first of those, before Coexistence switched anything off.
			'score_found'          => isset( $stored['score_found'] ) && is_int( $stored['score_found'] ) ? max( -1, min( 100, $stored['score_found'] ) ) : -1,
			'completed_at'         => (int) ( $stored['completed_at'] ?? 0 ),
			'skipped'              => ! empty( $stored['skipped'] ),
			'offer'                => 'dismissed' === ( $stored['offer'] ?? '' ) ? 'dismissed' : '',
			'opened'               => ! empty( $stored['opened'] ),
			'team'                 => in_array( $stored['team'] ?? '', array( 'solo', 'team' ), true ) ? (string) $stored['team'] : '',
			// The proxy answer as the owner gave it; '' when never answered.
			'proxy'                => in_array( $stored['proxy'] ?? '', self::PROXY_ANSWERS, true ) ? (string) $stored['proxy'] : '',
			'coexistence'          => Coexistence::clean( $stored['coexistence'] ?? array() ),
			'coexistence_saved'    => ! empty( $stored['coexistence_saved'] ),
			// The plugins limiting sign-ins when those choices were saved;
			// null for choices saved before they were stored with them.
			'coexistence_limiters' => is_array( $limiters ) ? array_values( array_filter( $limiters, 'is_string' ) ) : null,
			'recovery_received'    => (int) ( $stored['recovery_received'] ?? 0 ),
			// When the owner asked to run a finished setup again; 0 when not.
			'reopened_at'          => (int) ( $stored['reopened_at'] ?? 0 ),
			// Until when the setup waits for the owner to come back from
			// connecting to the hub; 0 when it does not.
			'hub_until'            => (int) ( $stored['hub_until'] ?? 0 ),
			// Until when a setup just finished stays on its last two steps;
			// 0 when it does not.
			'finishing_until'      => (int) ( $stored['finishing_until'] ?? 0 ),
			// A finished run reopened by Back from its last steps; finishing
			// it again records nothing new (#2758).
			'resumed'              => ! empty( $stored['resumed'] ),
			// The plugins the Ecosystem step installed and activated, by
			// directory slug, for Ready to name (#2117).
			'installed'            => array_values( array_filter( (array) ( $stored['installed'] ?? array() ), 'is_string' ) ),
			// What the Coexistence step brought over from another plugin, and
			// the plugins switched off from its link, for Ready to name (#1964).
			'imported'             => array_values(
				array_filter(
					(array) ( $stored['imported'] ?? array() ),
					static fn( $row ): bool => is_array( $row ) && is_string( $row['name'] ?? null ) && is_int( $row['count'] ?? null )
				)
			),
			'deactivated'          => array_values(
				array_filter(
					(array) ( $stored['deactivated'] ?? array() ),
					static fn( $row ): bool => is_array( $row ) && is_string( $row['file'] ?? null ) && is_string( $row['name'] ?? null )
				)
			),
		);
	}

	/**
	 * A saved step as a step this setup has: one Protect took over is
	 * Protect, and anything else not a step is none.
	 *
	 * @param mixed $step
	 */
	private static function current_step( $step ): string {
		$step = is_string( $step ) ? $step : '';

		if ( in_array( $step, self::MERGED_STEPS, true ) ) {
			return 'protect';
		}

		return in_array( $step, self::STEPS, true ) ? $step : '';
	}

	/**
	 * @param array<string, mixed> $changes
	 */
	private static function save( array $changes ): void {
		update_option( self::OPTION, array_merge( self::state(), $changes ), false );
	}

	/** Note a plugin the Ecosystem step installed and activated. */
	public static function note_installed( string $slug ): void {
		$installed = self::state()['installed'];

		if ( ! in_array( $slug, $installed, true ) ) {
			$installed[] = $slug;
			self::save( array( 'installed' => $installed ) );
		}
	}

	/**
	 * Note a plugin the owner switched off from the Coexistence step's link,
	 * once WordPress has switched it off.
	 */
	public static function note_deactivated( string $file, string $name ): void {
		$deactivated = array_values( array_filter( self::state()['deactivated'], static fn( array $row ): bool => $row['file'] !== $file ) );

		$deactivated[] = array(
			'file' => $file,
			'name' => $name,
		);

		self::save( array( 'deactivated' => $deactivated ) );
	}

	/** A plugin noted as switched off from the setup was turned back on. */
	public static function forget_deactivated( string $file ): void {
		$deactivated = self::state()['deactivated'];
		$kept        = array_values( array_filter( $deactivated, static fn( array $row ): bool => $row['file'] !== $file ) );

		if ( count( $kept ) !== count( $deactivated ) ) {
			self::save( array( 'deactivated' => $kept ) );
		}
	}

	/**
	 * The two-factor answer, once the plugin it was taken from is back on:
	 * left on BetterShield, an account would be asked for both codes.
	 */
	public static function keep_two_factor_elsewhere(): void {
		self::keep_elsewhere( 'two_factor' );
	}

	/**
	 * The sign-in limits answer, once a plugin that limits sign-ins is back
	 * on: left on BetterShield, the Overview no longer named that plugin,
	 * though both now limit sign-ins and can lock people out twice.
	 * BetterShield's own limit is left as it is.
	 */
	public static function keep_login_limits_elsewhere(): void {
		self::keep_elsewhere( 'login_limits' );
	}

	/** A saved "Use BetterShield" for one job, put back to the other plugin's. */
	private static function keep_elsewhere( string $job ): void {
		$state = self::state();

		if ( $state['coexistence_saved'] && 'bettershield' === ( $state['coexistence'][ $job ] ?? '' ) ) {
			self::save( array( 'coexistence' => array_merge( $state['coexistence'], array( $job => 'keep' ) ) ) );
		}
	}

	public static function url(): string {
		return admin_url( 'admin.php?page=' . self::PAGE );
	}

	/**
	 * Called from activation: the setup is owed.
	 *
	 * Only on a site that has never had it; re-activation leaves whatever the
	 * owner already did alone.
	 */
	public static function begin(): void {
		if ( '' !== self::state()['status'] ) {
			return;
		}

		self::save(
			array(
				'status'     => 'pending',
				'started_at' => time(),
			)
		);
	}

	public static function is_done(): bool {
		return 'done' === self::state()['status'];
	}

	/**
	 * Whether the setup's page may be drawn.
	 *
	 * Always until it is finished. After that only when the owner has asked
	 * to run it again from Settings, and only until they finish it again or a
	 * day has passed: a finished setup reached by a bookmark, a copied link or
	 * the Back button goes to the dashboard instead.
	 */
	public static function is_open(): bool {
		$state = self::state();

		if ( 'done' !== $state['status'] || self::awaiting_hub() || self::finishing() ) {
			return true;
		}

		return $state['reopened_at'] > 0 && time() - $state['reopened_at'] < self::REOPEN_FOR;
	}

	/**
	 * Whether the owner left for the hub from the setup's last step, within
	 * the time it waits: coming back, the page opens on that step, which
	 * says whether the site is connected (#2297).
	 */
	public static function awaiting_hub(): bool {
		return self::state()['hub_until'] > time();
	}

	/**
	 * Whether the setup was finished moments ago and the owner is still on
	 * its last two steps: a reload opens on the one they were on.
	 */
	public static function finishing(): bool {
		$state = self::state();

		return 'done' === $state['status'] && in_array( $state['step'], array( 'ready', 'hub' ), true ) && $state['finishing_until'] > time();
	}

	/**
	 * The owner pressed Connect on the setup's hub step: keep the page open
	 * for the way back, on that step.
	 */
	public static function await_hub(): void {
		self::save(
			array(
				'hub_until' => time() + self::HUB_RETURN_FOR,
				'step'      => 'hub',
			)
		);
	}

	/**
	 * Why this site cannot connect to the hub now, in the words the Hub
	 * screen uses, or '' where it can (or already is connected).
	 */
	private static function hub_blocked(): string {
		if ( ! \BetterShield\Mcp\Manager::is_available() ) {
			return __( 'Connecting needs WordPress 6.9 or later.', 'bettershield' );
		}

		if ( \BetterShield\Mcp\Hub::pin_is_invalid() ) {
			return __( 'BETTERSHIELD_HUB_URL in wp-config.php is not a usable https address, so this site cannot connect.', 'bettershield' );
		}

		if ( ! \BetterShield\Mcp\Pairing::pretty_routed() ) {
			return __( 'Connecting needs readable page addresses. Under Settings › Permalinks, choose any option except Plain.', 'bettershield' );
		}

		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			return __( 'This site is locked down, which pauses connected apps. Connect once the lockdown ends.', 'bettershield' );
		}

		if ( \BetterShield\Onboarding\SiteIdentity::is_staging() ) {
			return __( 'This site is marked as a test (staging) copy, so it can’t connect. Change that on the Overview.', 'bettershield' );
		}

		return '';
	}

	/**
	 * The owner asked to run the finished setup again, or to go to one of
	 * its steps: a screen that says where a choice is made opens the setup
	 * on that step rather than on its welcome.
	 *
	 * @param string $step The step to open on, or '' for where it stands.
	 */
	public static function reopen( string $step = '' ): void {
		$changes = in_array( $step, self::STEPS, true ) ? array( 'step' => $step ) : array();

		if ( self::is_done() ) {
			$changes['reopened_at']     = time();
			$changes['finishing_until'] = 0;
			// A run again names only what it installs itself, and starts
			// from the score as it finds it, whichever step it opens on.
			$changes['installed']    = array();
			$changes['score_before'] = self::starting_score();
			$changes['score_found']  = $changes['score_before'];
			$changes['score_unscanned'] = FirstScan::report()['running'];
		}

		if ( array() !== $changes ) {
			self::save( $changes );
		}
	}

	/**
	 * Whether this site had the plugin before the setup existed.
	 *
	 * Those sites were never sent to it, so they are offered it once instead.
	 */
	private static function predates_setup(): bool {
		return '' === self::state()['status'] && false !== get_option( FirstRun::OPTION );
	}

	/**
	 * Whether the Overview should carry the card that offers the setup.
	 *
	 * Offered until it is finished or the card is dismissed, which covers
	 * every site the setup did not open by itself: an update from a version
	 * without it, an install started from another plugin, a bulk or terminal
	 * activation, and a setup somebody left part way.
	 */
	public static function offer_due(): bool {
		$state = self::state();

		if ( 'dismissed' === $state['offer'] || 'done' === $state['status'] ) {
			return false;
		}

		return 'pending' === $state['status'] || self::predates_setup();
	}

	public static function dismiss_offer(): void {
		self::save( array( 'offer' => 'dismissed' ) );
	}

	/**
	 * Whether a network's site should be taken to the setup the first time
	 * its administrator opens this plugin — which is how each site of a
	 * network gets its own, with nobody redirected on activation.
	 */
	public static function opens_on_first_visit(): bool {
		$state = self::state();

		return is_multisite() && 'pending' === $state['status'] && ! $state['opened'] && '' === $state['offer'];
	}

	public static function mark_opened(): void {
		if ( ! self::state()['opened'] ) {
			self::save( array( 'opened' => true ) );
		}
	}

	/**
	 * Remember where the owner is, so leaving part way resumes there, and
	 * how they left the step they came from: by Skip, or by finishing it.
	 *
	 * @param string $step    The step the owner is on now.
	 * @param string $passed  The step they came from, when they moved forward.
	 * @param bool   $skipped Whether they left it by Skip.
	 */
	public static function set_step( string $step, string $passed = '', bool $skipped = false ): void {
		if ( ! in_array( $step, self::STEPS, true ) ) {
			return;
		}

		$state   = self::state();
		$changes = array(
			'step'   => $step,
			'opened' => true,
		);

		if ( in_array( $passed, self::STEPS, true ) ) {
			$changes['skipped_steps'] = array_values( array_diff( $state['skipped_steps'], array( $passed ) ) );

			if ( $skipped ) {
				$changes['skipped_steps'][] = $passed;
			}
		}

		// A site that predates the setup starts it by opening it.
		if ( '' === $state['status'] ) {
			$changes['status']     = 'pending';
			$changes['started_at'] = time();
		}

		/*
		 * Back from the last two steps moments after Protect finished the
		 * run: it is not finished any more, so it is owed again and stays
		 * open. Left done on Protect, a reload went to the Overview and the
		 * Hub step was out of reach (#2758). Going forward finishes it again.
		 */
		if ( self::finishing() && ! in_array( $step, array( 'ready', 'hub' ), true ) ) {
			$changes['status']          = 'pending';
			$changes['finishing_until'] = 0;
			// Finishing again closes the same run: its start was recorded
			// and its first scan begun the first time.
			$changes['resumed'] = true;
		}

		// The score before anything this run changes, read once, as the run
		// leaves its first step.
		if ( $state['score_before'] < 0 && 'welcome' !== $step ) {
			$changes['score_before'] = self::starting_score();
			$changes['score_found']  = $changes['score_before'];
			$changes['score_unscanned'] = FirstScan::report()['running'];
		}

		/*
		 * Leaving Coexistence after it switched another plugin off: that
		 * plugin's protections went with it, so the score is read again
		 * from a fresh audit. Read before, the summary showed the setup
		 * taking points away (#2610).
		 */
		if ( 'coexistence' === $passed && ( array() !== $state['deactivated'] || $state['coexistence_saved'] ) ) {
			Auditor::run();
			$changes['score_before'] = self::starting_score();
			$changes['score_unscanned'] = FirstScan::report()['running'];
		}

		self::save( $changes );
	}

	/**
	 * Finish, whether by reaching the end or by skipping the rest.
	 *
	 * The two are recorded differently because they are different facts, but
	 * they leave the site in the same place: nothing further is applied, the
	 * card offering the setup goes, and the menu still reaches it.
	 */
	public static function complete( bool $skipped ): void {
		$state   = self::state();
		$resumed = $state['resumed'];

		self::save(
			array(
				'resumed'         => false,
				'status'          => 'done',
				'step'            => $skipped ? $state['step'] : 'ready',
				'completed_at'    => time(),
				'skipped'         => $skipped,
				'opened'          => true,
				// Finished again, so the page closes again, once the owner
				// has had time to finish its last two steps.
				'reopened_at'     => 0,
				'finishing_until' => $skipped ? 0 : time() + self::FINISHING_FOR,
			)
		);

		// The welcome panel this setup replaces is owed no longer either.
		FirstRun::complete( false );

		// Finished again after Back from its last steps: the same run, whose
		// first scan began and whose end was recorded the first time.
		if ( $resumed ) {
			return;
		}

		// A setup skipped past its page still waits for the check.
		FirstScan::begin();

		Writer::instance()->record( $skipped ? 'quick_setup_skipped' : 'quick_setup_completed' );
	}

	/* ---- the way back in ---------------------------------------------- */

	/**
	 * Whether the owner has a way back in they have confirmed holding.
	 *
	 * Either of two things: printed recovery codes are on file, or the owner
	 * said the recovery email arrived — for the link on record now, which is
	 * still one they could open. The email alone is not enough, because an
	 * email that was accepted for sending may still never have arrived; the
	 * owner saying so is.
	 */
	public static function recovery_ready(): bool {
		if ( OfflineCodes::exist() ) {
			return true;
		}

		$received = self::state()['recovery_received'];

		return $received > 0 && RecoveryLink::usable() && RecoveryLink::issued_at() === $received;
	}

	/**
	 * Where the owner's word on the recovery email stands, for the screens
	 * that ask for it: 'confirmed' for the link on record now, 'pending'
	 * while that link is usable and not yet confirmed, '' with no link.
	 */
	public static function recovery_receipt(): string {
		if ( ! RecoveryLink::usable() ) {
			return '';
		}

		return self::state()['recovery_received'] === RecoveryLink::issued_at() ? 'confirmed' : 'pending';
	}

	/**
	 * The owner confirmed the recovery email arrived, or took that back.
	 * Either moves the "No way back in" finding, so the audit runs again.
	 *
	 * @return true|\WP_Error
	 */
	public static function confirm_received( bool $received ) {
		if ( ! $received ) {
			// Logged as ticking is: it takes readiness back, and the names
			// refusal setup offers with it. Only when there was one to take.
			if ( ! empty( self::state()['recovery_received'] ) ) {
				self::save( array( 'recovery_received' => 0 ) );
				Writer::instance()->record( 'recovery_receipt_withdrawn', Writer::SEVERITY_INFO, array( 'object_type' => 'recovery_link' ) );
				Auditor::run();
			}

			return true;
		}

		if ( ! RecoveryLink::usable() ) {
			return new \WP_Error(
				'bettershield_no_link_to_confirm',
				__( 'There is no recovery email to confirm. Send one, or download the recovery codes.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$issued = RecoveryLink::issued_at();

		if ( self::state()['recovery_received'] !== $issued ) {
			self::save( array( 'recovery_received' => $issued ) );
			Writer::instance()->record( 'recovery_receipt_confirmed', Writer::SEVERITY_INFO, array( 'object_type' => 'recovery_link' ) );
			Auditor::run();
		}

		return true;
	}

	/**
	 * Where the recovery email stands: sent, failed, or never sent from here.
	 */
	private static function recovery_mail(): string {
		if ( ! RecoveryLink::link_exists() ) {
			return 'not_sent';
		}

		$mailed = Auditor::recovery_mail_result();

		if ( true === $mailed ) {
			return 'sent';
		}

		return false === $mailed ? 'failed' : 'not_sent';
	}

	/* ---- your site ---------------------------------------------------- */

	/**
	 * What this request suggests about a proxy in front of the site.
	 *
	 * Read from the owner's own request to this page, which travels the same
	 * way a visitor's does. A suggestion and nothing more: trusting Cloudflare
	 * is always the owner's own statement.
	 */
	private static function detected_proxy(): string {
		$report = Protection::instance()->resolution_report();

		if ( in_array( $report['method'], array( ClientIp::METHOD_CLOUDFLARE, ClientIp::METHOD_CLOUDFLARE_UNCONFIRMED ), true ) ) {
			return 'cloudflare';
		}

		if ( ClientIp::METHOD_PROXY === $report['method'] || ! empty( $report['ignored_headers'] ) ) {
			return 'proxy';
		}

		/*
		 * A private connecting address nothing names: the test the "Sign-in
		 * lockouts are not running" finding makes, so the step no longer
		 * says visits arrive directly minutes before the finding says they
		 * do not (#2199).
		 */
		if ( empty( $report['confident'] ) && '' !== $report['connecting'] ) {
			return 'private';
		}

		return '';
	}

	/**
	 * The proxy answer to show: the one the owner gave, while the settings
	 * still agree with it, and otherwise what the settings say.
	 *
	 * Three answers land on two independent settings, so the settings alone
	 * cannot say which was given: "another proxy" writes nothing, and "no,
	 * direct" leaves a trusted-proxy list where it was. Read back from the
	 * settings only, the step showed an answer other than the one saved.
	 * Read back from the answer only, it could show a Cloudflare trust that
	 * was switched off in Login & Access since.
	 */
	private static function proxy_choice(): string {
		$settings = Protection::instance()->settings();
		$answer   = self::state()['proxy'];

		if ( 'other' === $answer
			|| ( 'cloudflare' === $answer && ! empty( $settings['cloudflare'] ) )
			|| ( 'direct' === $answer && empty( $settings['cloudflare'] ) ) ) {
			return $answer;
		}

		if ( ! empty( $settings['cloudflare'] ) ) {
			return 'cloudflare';
		}

		if ( ! empty( $settings['trusted_proxies'] ) ) {
			return 'other';
		}

		return 'direct';
	}

	private static function team(): string {
		$saved = self::state()['team'];

		if ( '' !== $saved ) {
			return $saved;
		}

		if ( in_array( 'administrator', TwoFactorPolicy::instance()->settings()['roles'], true ) ) {
			return 'team';
		}

		// More than one person who can sign in to the dashboard to manage the
		// site — administrators and editors — is a team, whatever was never
		// answered: "Just me" on a site with two administrators was wrong.
		$people = get_users(
			array(
				'role__in' => array( 'administrator', 'editor' ),
				'number'   => 2,
				'fields'   => 'ID',
			)
		);

		return count( $people ) > 1 ? 'team' : 'solo';
	}

	/**
	 * Save the Your Site step: who signs in, the proxy, and where alerts go.
	 *
	 * Only what changed is written. A re-run that leaves a field as it was
	 * leaves its setting untouched — no ledger row, no activity line.
	 *
	 * @param array<string, mixed> $input team, proxy, recipients, digest, instant.
	 * @return true|\WP_Error
	 */
	public static function save_site( array $input ) {
		/*
		 * Every part is checked before any is written (#2115). The team and
		 * proxy answers were stored first, so a refused proxy address or
		 * alert recipient left them saved: the step reopened on answers the
		 * owner never confirmed, and Skip kept half of a refused save.
		 */
		$team  = $input['team'] ?? '';
		$proxy = $input['proxy'] ?? '';
		$login = array();

		if ( in_array( $proxy, self::PROXY_ANSWERS, true ) ) {
			$trusted = (bool) Protection::instance()->settings()['cloudflare'];

			/*
			 * "Another proxy" says nothing about Cloudflare, so it leaves that
			 * trust as it is; switching it off on that answer took a working
			 * Cloudflare setup down and then showed "No, direct". The other
			 * two answers are about Cloudflare, and say which way.
			 */
			$trust = 'other' === $proxy ? $trusted : 'cloudflare' === $proxy;

			if ( $trusted !== $trust ) {
				$login['cloudflare'] = $trust;
			}
		}

		/*
		 * The trusted proxies, named here rather than on Login & Access: the
		 * proxy's addresses with "another proxy", or none with "direct" when
		 * the owner chose to clear the ones still named. Through Login &
		 * Access's own save, so its checks, its undo record and its activity
		 * row are the same from either place.
		 */
		if ( isset( $input['trusted_proxies'] ) && is_array( $input['trusted_proxies'] ) && in_array( $proxy, array( 'direct', 'other' ), true ) ) {
			$proxies = array_values( array_filter( array_map( static fn( $range ): string => trim( is_string( $range ) ? $range : '' ), $input['trusted_proxies'] ), 'strlen' ) );

			if ( 'direct' === $proxy && array() !== $proxies ) {
				return new \WP_Error( 'bettershield_direct_proxies', __( 'A site with no service in front of it has no addresses to add. Choose “Yes, another service” to add one.', 'bettershield' ), array( 'status' => 400 ) );
			}

			if ( $proxies !== Protection::instance()->settings()['trusted_proxies'] ) {
				$login['trusted_proxies'] = $proxies;
			}
		}

		$alerts  = AlertSettings::instance();
		$current = $alerts->settings();
		$changes = array();

		if ( isset( $input['recipients'] ) && is_array( $input['recipients'] ) ) {
			$list = array();

			foreach ( $input['recipients'] as $address ) {
				// As typed: the alert settings refuse an address that cleaning
				// would change, and cleaning it here first saved the changed
				// one instead.
				$address = trim( is_string( $address ) ? $address : '' );

				if ( '' !== $address && ! in_array( strtolower( $address ), array_map( 'strtolower', $list ), true ) ) {
					$list[] = $address;
				}
			}

			if ( array_map( 'strtolower', $list ) !== array_map( 'strtolower', $alerts->recipients() ) ) {
				$changes['recipients'] = $list;
			}
		}

		if ( isset( $input['digest'] ) && is_bool( $input['digest'] ) && $input['digest'] !== (bool) $current['digest'] ) {
			$changes['digest'] = $input['digest'];
		}

		if ( isset( $input['instant'] ) && is_bool( $input['instant'] ) && $input['instant'] !== (bool) $current['instant_critical'] ) {
			$changes['instant_critical'] = $input['instant'];
		}

		// Checked, both, before anything is written.
		foreach ( array( array( Protection::instance(), $login ), array( $alerts, $changes ) ) as list( $owner, $next ) ) {
			if ( array() !== $next ) {
				$checked = $owner->validate( $next );

				if ( is_wp_error( $checked ) ) {
					return $checked;
				}
			}
		}

		if ( array() !== $login ) {
			$result = Protection::instance()->update_settings( $login );

			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		if ( array() !== $changes ) {
			$result = $alerts->update_settings( $changes );

			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		if ( in_array( $team, array( 'solo', 'team' ), true ) ) {
			self::save( array( 'team' => $team ) );
		}

		if ( in_array( $proxy, self::PROXY_ANSWERS, true ) ) {
			self::save( array( 'proxy' => $proxy ) );
		}

		return true;
	}

	/* ---- two-factor --------------------------------------------------- */

	/**
	 * Require two-factor for administrators, or stop requiring it.
	 *
	 * Refused while the owner has no way back in they have confirmed, because
	 * this is the one choice in the setup that can hold back somebody's
	 * dashboard. It never holds back a sign-in, and the grace period starts
	 * for each account when it first meets the rule.
	 *
	 * Only the administrator role is added or taken away; any other role the
	 * policy already names stays as it was, and so does a grace period chosen
	 * before.
	 *
	 * @return true|\WP_Error
	 */
	public static function require_for_admins( bool $required ) {
		$policy   = TwoFactorPolicy::instance();
		$settings = $policy->settings();
		$roles    = $settings['roles'];
		$has      = in_array( 'administrator', $roles, true );

		if ( $required === $has ) {
			return true;
		}

		if ( $required && ! self::recovery_ready() ) {
			return new \WP_Error(
				'bettershield_recovery_first',
				__( 'Confirm your recovery options first: check “I received the recovery email”, or download the recovery codes.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$next = array( 'roles' => $required ? array_values( array_merge( $roles, array( 'administrator' ) ) ) : array_values( array_diff( $roles, array( 'administrator' ) ) ) );

		// A policy that named nobody had no grace period anybody chose.
		if ( $required && array() === $roles ) {
			$next['grace_days'] = self::GRACE_DAYS;
		}

		$result = $policy->update_settings( $next );

		return is_wp_error( $result ) ? $result : true;
	}

	/* ---- common usernames ---------------------------------------------- */

	/**
	 * The names bots try first on any WordPress site. Short and obvious on
	 * purpose: one try of a blocked name pauses a verified network, the
	 * owner's own office included, so nothing here may be a name a person
	 * plausibly signs in with.
	 */
	public const COMMON_NAMES = array( 'admin', 'administrator', 'root', 'test' );

	/**
	 * The common names this site could refuse, the ones it already refuses
	 * everywhere, and the ones an account here holds.
	 *
	 * A name an account here holds is never offered: refusing it would
	 * refuse that person, and that belongs on the blocklist as a decision
	 * about them, never as a default. It is named, so the card can say
	 * plainly whether any were found (#2323).
	 *
	 * With them, the owner's own names this setup refused, so the card that
	 * took them can show them again and let each one through (#2456).
	 *
	 * @return array{offered: string[], blocked: string[], own: string[], in_use: string[], minutes: int}
	 */
	public static function common_names(): array {
		$everywhere = array();

		foreach ( Protection::instance()->settings()['blocklist'] as $entry ) {
			if ( '' !== (string) ( $entry['username'] ?? '' ) && '' === (string) ( $entry['range'] ?? '' ) && '' === (string) ( $entry['ua'] ?? '' ) ) {
				$everywhere[] = strtolower( (string) $entry['username'] );
			}
		}

		$offered = array();
		$blocked = array();
		$in_use  = array();

		foreach ( self::COMMON_NAMES as $name ) {
			if ( in_array( $name, $everywhere, true ) ) {
				$blocked[] = $name;
			} elseif ( false === username_exists( $name ) ) {
				$offered[] = $name;
			} else {
				$in_use[] = $name;
			}
		}

		return array(
			'offered' => $offered,
			'blocked' => $blocked,
			'own'     => self::own_names_blocked(),
			'in_use'  => $in_use,
			// How long a try on one pauses its source, said beside the box.
			'minutes' => (int) Protection::instance()->settings()['lockout_minutes'],
		);
	}

	/**
	 * The owner's own names this setup refused everywhere: blocklist entries
	 * by name alone that carry the setup's own note.
	 *
	 * @return string[]
	 */
	public static function own_names_blocked(): array {
		$names = array();

		foreach ( Protection::instance()->settings()['blocklist'] as $entry ) {
			$name = strtolower( (string) ( $entry['username'] ?? '' ) );

			if ( '' !== $name && '' === (string) ( $entry['range'] ?? '' ) && '' === (string) ( $entry['ua'] ?? '' ) && __( 'Added in Quick Setup.', 'bettershield' ) === (string) ( $entry['note'] ?? '' ) && ! in_array( $name, self::COMMON_NAMES, true ) ) {
				$names[] = $name;
			}
		}

		return $names;
	}

	/**
	 * Refuse the common names on offer, through the blocklist's own save:
	 * its checks, its undo record and its activity row.
	 *
	 * Only once the way back in is ready, as the two-factor requirement is:
	 * a name block can pause the owner's own network on one mistyped try.
	 *
	 * With them, any names of the owner's own, which could otherwise only be
	 * added on Login & access (#1965). A name an account here holds is
	 * refused, as it is never offered: that is a decision about a person.
	 *
	 * @param array<int, mixed> $extra The owner's own names.
	 * @param string            $from  Where the names were added: 'setup', or 'findings' for a finding's Fix.
	 * @return true|\WP_Error
	 */
	public static function block_common_names( array $extra = array(), string $from = 'setup' ) {
		$names   = self::common_names();
		$offered = $names['offered'];
		$own     = array();

		foreach ( $extra as $typed ) {
			$given = trim( (string) $typed );
			$name  = strtolower( sanitize_user( $given, true ) );

			/*
			 * The name as typed, or a refusal, as the blocklist's own save
			 * answers: cleaned without a word, "jo<b>" blocked "jo", a name
			 * nobody typed that a real account may hold (#1800).
			 */
			if ( '' !== $given && 0 !== strcasecmp( $name, $given ) ) {
				return new \WP_Error(
					'bettershield_bad_username',
					'' === $name
						? __( 'WordPress does not allow that username, so it was not added.', 'bettershield' )
						/* translators: %s: the name as WordPress would store it. */
						: sprintf( __( 'WordPress does not allow that username and would store it as "%s". Enter the account’s exact username.', 'bettershield' ), $name ),
					array( 'status' => 400 )
				);
			}

			if ( '' !== $name && ! in_array( $name, $offered, true ) && ! in_array( $name, $names['blocked'], true ) && ! in_array( $name, $own, true ) ) {
				$own[] = $name;
			}
		}

		// Nothing on offer is not a reason to drop names of the owner's own.
		if ( array() === $offered && array() === $own ) {
			return true;
		}

		$held = array_values( array_filter( $own, static fn( string $name ): bool => false !== username_exists( $name ) ) );

		if ( array() !== $held ) {
			return new \WP_Error(
				'bettershield_name_in_use',
				sprintf(
					/* translators: %s: one or more usernames. */
					_n(
						'%s is an account name, so it was not blocked. To block it anyway, use Login & Access.',
						'%s are account names, so they were not blocked. To block them anyway, use Login & Access.',
						count( $held ),
						'bettershield'
					),
					implode( ', ', $held )
				),
				array( 'status' => 409 )
			);
		}

		if ( ! self::recovery_ready() ) {
			return new \WP_Error(
				'bettershield_recovery_first',
				__( 'Confirm your recovery options first: check “I received the recovery email”, or download the recovery codes.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$list = Protection::instance()->settings()['blocklist'];

		foreach ( $offered as $name ) {
			$list[] = array(
				'username' => $name,
				'note'     => 'findings' === $from ? __( 'A name bots try first. Added from Findings.', 'bettershield' ) : __( 'A name bots try first. Added in Quick Setup.', 'bettershield' ),
			);
		}

		foreach ( $own as $name ) {
			$list[] = array(
				'username' => $name,
				'note'     => __( 'Added in Quick Setup.', 'bettershield' ),
			);
		}

		$result = Protection::instance()->update_settings( array( 'blocklist' => $list ) );

		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Stop refusing one of the common names, from the setup rather than
	 * Login & access: only a name the setup offers, and only its block
	 * everywhere, by name alone. A block that also names an address or a
	 * browser is a decision about somebody, and stays where it was made.
	 *
	 * @return true|\WP_Error
	 */
	public static function unblock_common_name( string $name ) {
		$name  = strtolower( trim( $name ) );
		$names = self::common_names();

		if ( ! in_array( $name, $names['blocked'], true ) && ! in_array( $name, $names['own'], true ) ) {
			return new \WP_Error( 'bettershield_not_blocked', __( 'That name is not one this site refuses from here, so nothing was changed.', 'bettershield' ), array( 'status' => 404 ) );
		}

		return self::lift_names( array( $name ) );
	}

	/**
	 * Stop refusing every name this setup refuses, in one save: the common
	 * names and the owner's own. One press for what took four, each with its
	 * own confirmation and its own save (#2457). The same rule as one name:
	 * blocks by name alone, and of an owner's name only the setup's entry.
	 *
	 * @return true|\WP_Error
	 */
	public static function unblock_all_names() {
		$names = self::common_names();
		$all   = array_values( array_unique( array_merge( $names['blocked'], $names['own'] ) ) );

		if ( array() === $all ) {
			return new \WP_Error( 'bettershield_not_blocked', __( 'No name is refused from here, so nothing was changed.', 'bettershield' ), array( 'status' => 404 ) );
		}

		return self::lift_names( $all );
	}

	/**
	 * Take a set of the setup's name blocks off the blocklist in one save.
	 *
	 * A common name loses its block by name alone, as before. An owner's own
	 * name loses only the entry this setup added, the one carrying its note:
	 * a block of the same name made on Login & access is a decision taken
	 * there, and stays there (#2456).
	 *
	 * @param string[] $names Lower-case names.
	 * @return true|\WP_Error
	 */
	private static function lift_names( array $names ) {
		$note = __( 'Added in Quick Setup.', 'bettershield' );

		$list = array_values(
			array_filter(
				Protection::instance()->settings()['blocklist'],
				static function ( array $entry ) use ( $names, $note ): bool {
					$name = strtolower( (string) ( $entry['username'] ?? '' ) );

					if ( ! in_array( $name, $names, true ) || '' !== (string) ( $entry['range'] ?? '' ) || '' !== (string) ( $entry['ua'] ?? '' ) ) {
						return true;
					}

					return ! in_array( $name, self::COMMON_NAMES, true ) && $note !== (string) ( $entry['note'] ?? '' );
				}
			)
		);

		$result = Protection::instance()->update_settings( array( 'blocklist' => $list ) );

		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Hear alerts again, from the setup's alert card. Muting asks for the
	 * password; this gives back what muting took away, so it does not.
	 *
	 * @return true|\WP_Error
	 */
	public static function unmute_alerts() {
		$result = AlertSettings::instance()->update_settings( array( 'muted' => false ) );

		return is_wp_error( $result ) ? $result : true;
	}

	/* ---- coexistence -------------------------------------------------- */

	/**
	 * Save the coexistence choices and put them into effect, then bring over
	 * the other plugins' settings the owner left ticked.
	 *
	 * The choices are saved first: a sign-in limit handed to BetterShield is
	 * what lets the import carry the other plugin's attempt numbers.
	 *
	 * @param mixed $input  Job => choice.
	 * @param mixed $import The import sources to bring over, by key; null for none.
	 * @return true|\WP_Error
	 */
	public static function save_coexistence( $input, $import = null ) {
		$choices = Coexistence::clean( $input );
		$result  = Coexistence::apply( $choices );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$before = self::state();

		/*
		 * Which plugins limit sign-ins as the choice is made, kept with it:
		 * the audit stays quiet about the ones the owner chose over, and
		 * speaks up about one activated afterwards. The same choices saved
		 * over a different set of them are a new decision, and recorded.
		 */
		$limiters = Coexistence::limiter_files();

		self::save(
			array(
				'coexistence'          => $choices,
				'coexistence_saved'    => true,
				'coexistence_limiters' => $limiters,
			)
		);

		if ( ! $before['coexistence_saved'] || $before['coexistence'] !== $choices || $before['coexistence_limiters'] !== $limiters ) {
			Writer::instance()->record(
				'coexistence_choices_saved',
				Writer::SEVERITY_INFO,
				array( 'context' => array( 'choices' => $choices ) )
			);
		}

		$keys = is_array( $import ) ? array_values( array_filter( $import, 'is_string' ) ) : array();

		if ( array() === $keys ) {
			return true;
		}

		$done = Coexistence::import( $keys );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		// Added to what an earlier save brought over, by plugin.
		$imported = array_column( self::state()['imported'], 'count', 'name' );

		foreach ( $done as $row ) {
			$imported[ $row['name'] ] = (int) ( $imported[ $row['name'] ] ?? 0 ) + $row['count'];
		}

		if ( array() !== $done ) {
			self::save(
				array(
					'imported' => array_map(
						static fn( string $name, int $count ): array => array(
							'name'  => $name,
							'count' => $count,
						),
						array_keys( $imported ),
						array_values( $imported )
					),
				)
			);
		}

		return true;
	}

	/* ---- what the screen draws ---------------------------------------- */

	/**
	 * The steps this site gets.
	 *
	 * @return string[]
	 */
	public static function steps(): array {
		$steps = array( 'welcome' );

		if ( Coexistence::applies() ) {
			$steps[] = 'coexistence';
		}

		// The site's answers and the safe fixes, on one screen with one
		// Apply (recovery, two-factor and the usernames are pointed to from
		// Ready, the Ecosystem step); the recommended plugins are offered on
		// Ready, and the hub has the last step of its own (#2297), on every
		// site: where it cannot connect yet, the step says why.
		array_push( $steps, 'protect', 'ready', 'hub' );

		return $steps;
	}

	/**
	 * Everything the setup draws, read from the site as it is now.
	 *
	 * @param bool $with_summary Whether to include the Ready summary, which
	 *                           reads the audit and is only wanted at the end.
	 * @return array<string, mixed>
	 */
	public static function payload( bool $with_summary = false ): array {
		self::settle_score_before();

		$state    = self::state();
		$user     = wp_get_current_user();
		$alerts   = AlertSettings::instance()->settings();
		$require  = self::admin_requirement();
		$factor   = TwoFactor::instance()->status( (int) $user->ID );
		$lists    = Ecosystem::available() ? Ecosystem::lists() : array(
			'recommended' => array(),
			'more'        => array(),
		);

		// A finished setup opened again starts from the beginning, with every
		// answer filled in from what is set now.
		$step      = $state['step'];
		$returning = self::awaiting_hub();
		$finishing = self::finishing();

		if ( '' === $step || ( 'done' === $state['status'] && ! $finishing && ( 'ready' === $step || ( 'hub' === $step && ! $returning ) ) ) ) {
			$step = 'welcome';
		}

		$payload = array(
			// The file check that runs while the setup is open.
			'first_scan'  => FirstScan::report(),
			'status'      => '' === $state['status'] ? 'pending' : $state['status'],
			// Coming back from the hub, or reloading the last two steps, is
			// the same run, not a second one.
			'rerun'       => 'done' === $state['status'] && ! $returning && ! $finishing,
			'step'        => $step,
			'skipped_steps' => $state['skipped_steps'],
			'steps'       => self::steps(),
			'consent'     => Usage::for_screen(),
			'coexistence' => array(
				'rows'       => Coexistence::rows( $state['coexistence'] ),
				'saved'      => $state['coexistence_saved'],
				// What the step can bring over from each other plugin, read
				// only where it has another plugin to share a job with.
				'imports'    => Coexistence::applies() ? Coexistence::imports() : array(),
				// What stops with each plugin because it cannot come over.
				'not_carried' => Coexistence::applies() ? Coexistence::not_carried() : array(),
				// What a save here already brought over, by plugin, so a
				// Deactivate that takes the import card away still says so.
				'imported'   => $state['imported'],
				// Whether the step may switch the other plugin off itself;
				// off, as by default, it points to the Plugins screen instead.
				'deactivation' => Coexistence::deactivation_enabled(),
				// For each plugin whose two-factor comes over as it is switched
				// off: how many accounts keep their app, and who cannot come.
				'two_factor_move' => Coexistence::applies() ? Coexistence::two_factor_moves() : array(),
				// Whether BetterShield's own vulnerability check is on, so the
				// card says what it does rather than that it leaves the job
				// to the other plugin (#2233).
				'vulnerability_checks' => \BetterShield\Vulnerabilities\Scanner::consented() && null !== \BetterShield\Vulnerabilities\Scanner::feed(),
				// Where the sign-in page goes back to once a plugin moving it
				// is off: WordPress's own, under any folder it is installed in.
				'sign_in_default' => Coexistence::default_sign_in_path(),
			),
			'site'        => array(
				'team'   => self::team(),
				// How many failed sign-ins pause a visitor, and over how long,
				// for the one line under Protect's sign-in limits row.
				'limits' => array(
					'tries'   => (int) Protection::instance()->settings()['threshold'],
					'minutes' => (int) Protection::instance()->settings()['window_minutes'],
				),
				'proxy'  => array(
					'choice'   => self::proxy_choice(),
					'detected' => self::detected_proxy(),
					// Whether the owner has answered, so a detection only
					// pre-selects an answer nobody has given.
					'answered' => '' !== self::state()['proxy'],
					// How many trusted proxies Login & Access names, which
					// "No, direct" leaves where they are and says so.
					'trusted'  => count( (array) Protection::instance()->settings()['trusted_proxies'] ),
					// And which, for the field "another proxy" names them in.
					'list'     => array_values( array_map( 'strval', (array) Protection::instance()->settings()['trusted_proxies'] ) ),
				),
				'alerts' => array(
					'admin_email' => (string) get_option( 'admin_email' ),
					'recipients'  => AlertSettings::instance()->recipients(),
					'max'         => 5,
					'digest'      => (bool) $alerts['digest'],
					'digest_day'  => self::weekday( (int) $alerts['digest_day'] ),
					'instant'     => (bool) $alerts['instant_critical'],
					'muted'       => AlertSettings::instance()->is_muted(),
				),
			),
			'recovery'    => array(
				'mail'        => self::recovery_mail(),
				'link'        => RecoveryLink::link_exists(),
				'usable'      => RecoveryLink::usable(),
				'received'    => $state['recovery_received'] > 0 && RecoveryLink::issued_at() === $state['recovery_received'],
				'codes_left'  => OfflineCodes::remaining(),
				'code_address' => RecoveryLink::code_address(),
				'ready'       => self::recovery_ready(),
				'admin_email' => (string) get_option( 'admin_email' ),
				// Where the link on record actually went, which the admin
				// email may no longer be (#2114).
				'mailed_to'   => RecoveryLink::mailed_to(),
			),
			'two_factor'  => array(
				'handled_by' => Coexistence::two_factor_elsewhere( $state['coexistence'] ),
				'enrolled'   => ! empty( $factor['enabled'] ),
				'pending'    => ! empty( $factor['pending'] ),
				// A code verified and the backup codes never kept: the phone
				// holds an entry, yet sign-in asks for nothing (#2137).
				'unfinished' => empty( $factor['enabled'] ) && ! empty( $factor['confirmed'] ),
				'required'   => $require['required'],
				'by_network' => $require['by_network'],
				'grace_days' => $require['grace_days'],
				'is_admin'   => in_array( 'administrator', (array) $user->roles, true ),
			),
			'common_names' => self::common_names(),
			'fixes'       => SafeFixes::describe(),
			// The score now and what Protect's choices would make it.
			'score'       => self::score_preview(),
			// Offered on Protect beside the fixes: off by default, and saved
			// only through its own consent route (#2297).
			'vulnerabilities' => self::vulnerability_checks(),
			'ecosystem'   => $lists,
			'hub'         => array(
				'offerable' => \BetterShield\Mcp\Hub::offerable(),
				'connected' => array() !== \BetterShield\Mcp\Hub::apps(),
				// Why Connect cannot work here now; '' where it can.
				'blocked'   => self::hub_blocked(),
				'url'       => \BetterShield\Mcp\Hub::url(),
				'returning' => $returning,
			),
		);

		if ( $with_summary ) {
			$payload['summary'] = self::summary();
		}

		return $payload;
	}

	/**
	 * The score as it stands, and what each set of Protect's choices would
	 * make it, so the step can say where Apply takes the grade without doing
	 * any arithmetic of its own.
	 *
	 * `choices` are the choices Apply can close a setup item with that are
	 * open now: a safe fix by its id, `common_usernames`, and `two_factor`
	 * where requiring it of administrators covers every account it names.
	 * `projected` holds one score per set of them, indexed by the bits of
	 * `choices` in order, each the one calculation (Auditor::score_of) run on
	 * the findings that set would leave, never points added back to a total.
	 *
	 * @return array{score: int, grade: string, points: array<string, int>, open: array<string, bool>, lockouts: bool, choices: string[], projected: array<int, array{score: int, grade: string}>}
	 */
	public static function score_preview(): array {
		/*
		 * The score now and every projection start from the open set the
		 * audit after Apply will see. Read from the last audit instead, a
		 * finding it had not raised yet was missing from the starting score,
		 * and Apply looked like it took those points away (#2702). Only the
		 * proxy answer itself can still change this, which `uncertain` says.
		 */
		$open = Auditor::open_levels_reading( self::AUDIT_READS_AGAIN );
		$now  = Auditor::score_of( $open )['score'];

		$keys  = self::item_keys();
		$state = self::item_states( self::PROTECT_ITEMS, $open );
		$points = $state['points'];
		$items  = $state['open'];

		// Each choice, and the setup item it closes.
		$closes = array();

		foreach ( self::FIX_ITEMS as $fix => $item ) {
			if ( $items[ $item ] ) {
				$closes[ $fix ] = $item;
			}
		}

		// Recovery, two-factor and the usernames are not Protect's choices any
		// more (Ecosystem points to them), so no projection counts them.

		$choices   = array_keys( $closes );
		$projected = array();

		for ( $set = 0; $set < 1 << count( $choices ); $set++ ) {
			$left = $open;

			foreach ( $choices as $bit => $choice ) {
				if ( $set & ( 1 << $bit ) ) {
					$left = array_diff_key( $left, array_flip( $keys[ $closes[ $choice ] ] ) );
				}
			}

			$score       = Auditor::score_of( $left )['score'];
			$projected[] = array(
				'score' => $score,
				'grade' => Auditor::grade( $score ),
			);
		}

		return array(
			'score'     => $now,
			'grade'     => Auditor::grade( $now ),
			'points'    => $points,
			'open'      => $items,
			// Whether lockouts cannot run here, which the proxy answer can
			// decide: the step asks it up front while they cannot.
			'lockouts'  => isset( $open['lockouts_not_running'] ),
			// Whether the projections can be off: the proxy answer may let
			// lockouts run, which only a request after Apply can show.
			'uncertain' => isset( $open['lockouts_not_running'] ),
			'choices'   => $choices,
			'projected' => $projected,
		);
	}

	/**
	 * Read the starting score again once the first file check has finished, so
	 * what the check found is in the before as well as the after. Only while
	 * nothing has been applied: past Protect the score already holds the
	 * setup's own changes, and the summary then shows no before at all.
	 */
	private static function settle_score_before(): void {
		$state = self::state();

		if ( ! $state['score_unscanned'] || FirstScan::report()['running'] || 'pending' !== $state['status'] || ! in_array( $state['step'], array( 'welcome', 'coexistence', 'protect' ), true ) ) {
			return;
		}

		$score = self::starting_score();

		self::save(
			array(
				'score_before'    => $score,
				'score_found'     => $score,
				'score_unscanned' => false,
			)
		);
	}

	/** The score this run of the setup starts from. */
	private static function starting_score(): int {
		return Auditor::score_of( Auditor::open_levels_reading( self::AUDIT_READS_AGAIN ) )['score'];
	}

	/**
	 * The finding keys behind each setup item.
	 *
	 * @return array<string, string[]>
	 */
	private static function item_keys(): array {
		$keys = array();

		foreach ( Auditor::SETUP_POINTS as $key => $setup ) {
			$keys[ $setup[0] ][] = $key;
		}

		return $keys;
	}

	/**
	 * What each setup item is worth and whether it is still open.
	 *
	 * @param string[]                $items The setup items.
	 * @param array<string, int>|null $open  The open findings, read now when not given.
	 * @return array{points: array<string, int>, open: array<string, bool>}
	 */
	private static function item_states( array $items, ?array $open = null ): array {
		$open   = $open ?? Auditor::open_levels();
		$keys   = self::item_keys();
		$points = array();
		$state  = array();

		foreach ( $items as $item ) {
			$points[ $item ] = 0;

			foreach ( $keys[ $item ] ?? array() as $key ) {
				$points[ $item ] = (int) Auditor::SETUP_POINTS[ $key ][1];
			}

			$state[ $item ] = array() !== array_intersect_key( $open, array_flip( $keys[ $item ] ?? array() ) );
		}

		return array(
			'points' => $points,
			'open'   => $state,
		);
	}

	/**
	 * The vulnerability checks as the Protect step offers them: whether they
	 * are on, and the source and the words Settings › General says them in.
	 * Not offered where no source is bound to the site.
	 *
	 * @return array{available: bool, on: bool, label: string}
	 */
	private static function vulnerability_checks(): array {
		$summary = \BetterShield\Vulnerabilities\Scanner::summary();

		return array(
			'available' => ! empty( $summary['feed_bound'] ),
			'on'        => \BetterShield\Vulnerabilities\Scanner::consented(),
			'label'     => (string) ( $summary['feed_label'] ?? '' ),
		);
	}

	/**
	 * The two-factor requirement for administrators as this site enforces it:
	 * its own policy with the network's beneath it, read the way enforcement
	 * reads it. A network that requires administrators requires them here
	 * whatever this site's own list says, and its window is the shorter of
	 * the two — so the setup says what will happen at the next sign-in.
	 *
	 * @return array{required: bool, by_network: bool, grace_days: int}
	 */
	private static function admin_requirement(): array {
		$policy = TwoFactorPolicy::instance()->settings();
		$roles  = NetworkPolicies::effective_two_factor_roles( $policy['roles'] );

		return array(
			'required'   => in_array( 'administrator', $roles, true ),
			'by_network' => in_array( 'administrator', NetworkPolicies::two_factor()['roles'], true ),
			// A policy that names nobody has no window anybody chose: this is
			// the one requiring it here would start.
			'grace_days' => array() === $roles ? self::GRACE_DAYS : NetworkPolicies::effective_grace( (int) $policy['grace_days'] ),
		);
	}

	private static function weekday( int $day ): string {
		global $wp_locale;

		$day = max( 0, min( 6, $day ) );

		return $wp_locale instanceof \WP_Locale ? (string) $wp_locale->get_weekday( $day ) : (string) $day;
	}

	/**
	 * The Ready step: what is true on this site now.
	 *
	 * Every line is read from the setting it describes, never from anything
	 * this setup remembers doing. A summary of intentions is how a screen
	 * comes to report a protection that is not there.
	 *
	 * @return array<string, mixed>
	 */
	public static function summary(): array {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$state    = self::state();
		$overview = Auditor::overview();
		$user     = wp_get_current_user();
		$require  = self::admin_requirement();
		$alerts   = AlertSettings::instance()->settings();
		$fixes    = SafeFixes::describe();

		return array(
			'grade'       => (string) $overview['grade'],
			'score'       => (int) $overview['score'],
			// Where this run of the setup found it, or null where it never read it.
			'before'      => $state['score_before'] >= 0 && ! $state['score_unscanned'] ? array(
				'score' => $state['score_before'],
				'grade' => Auditor::grade( $state['score_before'] ),
			) : null,
			// What the score was before Coexistence switched another plugin
			// off, where that lowered it; null where it did not.
			'found'       => array() !== $state['deactivated'] && ! $state['score_unscanned'] && $state['score_found'] > $state['score_before'] ? $state['score_found'] : null,
			'first_scan'  => FirstScan::report(),
			'audited_at'  => $overview['generated_at'] ?? null,
			'usage'       => Usage::is_allowed(),
			'coexistence' => $state['coexistence_saved'] ? Coexistence::rows( $state['coexistence'] ) : array(),
			'recovery'    => self::recovery_ready(),
			// The names bots try first, refused at sign-in on the Way Back In
			// step: the one choice that can pause the owner on a mistyped name.
			// With the owner's own names this setup blocked beside them (#2116).
			'common_names' => array_values( array_unique( array_merge( self::common_names()['blocked'], self::own_names_blocked() ) ) ),
			// What the Ecosystem step installed and activated, by name.
			'installed'    => array_values( array_filter( array_map( static fn( string $slug ): string => (string) ( Ecosystem::catalog()[ $slug ]['name'] ?? '' ), $state['installed'] ) ) ),
			// What the Coexistence step brought over, and the plugins switched
			// off from its link that are still off (#1964).
			'imported'     => $state['imported'],
			'deactivated'  => array_values( array_map( static fn( array $row ): string => $row['name'], array_filter( $state['deactivated'], static fn( array $row ): bool => ! is_plugin_active( $row['file'] ) ) ) ),
			// The same plugins, each with WordPress's own Activate, for its
			// Turn It Back On ('' where this account may not use it).
			'reactivate'   => array_values(
				array_map(
					static fn( array $row ): array => array(
						'file'         => $row['file'],
						'name'         => $row['name'],
						'activate_url' => Coexistence::activate_url( $row['file'] ),
					),
					array_filter( $state['deactivated'], static fn( array $row ): bool => ! is_plugin_active( $row['file'] ) )
				)
			),
			'two_factor'  => array(
				'enrolled'   => TwoFactor::instance()->enabled( (int) $user->ID ),
				'unfinished' => ! TwoFactor::instance()->enabled( (int) $user->ID ) && ! empty( TwoFactor::instance()->status( (int) $user->ID )['confirmed'] ),
				'handled_by' => Coexistence::two_factor_elsewhere( $state['coexistence'] ),
				'required'   => $require['required'],
				'grace_days' => $require['grace_days'],
			),
			'fixes'       => array(
				'on'      => count( array_filter( $fixes, static fn( array $fix ): bool => (bool) $fix['on'] ) ),
				'total'   => count( $fixes ),
				'items'   => $fixes,
				// The fixes the last applied set can still take back together.
				'set'     => SafeFixes::set_items(),
				// The fixes setup turned on, the Ready step's switches
				// included; any other fix on was on before it ran (#2248).
				'applied' => SafeFixes::applied_items(),
			),
			'alerts'      => array(
				'recipients' => AlertSettings::instance()->recipients(),
				'digest'     => (bool) $alerts['digest'],
				'digest_day' => self::weekday( (int) $alerts['digest_day'] ),
				'instant'    => (bool) $alerts['instant_critical'],
				'muted'      => AlertSettings::instance()->is_muted(),
			),
		);
	}
}
