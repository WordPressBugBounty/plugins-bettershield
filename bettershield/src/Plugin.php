<?php
/**
 * Plugin bootstrap.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {

	private static ?Plugin $instance = null;

	/**
	 * Boot the plugin on plugins_loaded. Idempotent.
	 */
	public static function boot(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
			// The main-file timer stops before other plugins load. Only our
			// registration work belongs in this later plugins_loaded window.
			Support\Cost::around( static function (): void {
				self::$instance->register_hooks();
			} );
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Bring the schema up to date, without doing it while somebody waits.
	 *
	 * The migration is eleven `CREATE TABLE` statements through `dbDelta`, plus
	 * a `DESCRIBE` and a `SHOW INDEX` per table. It runs once per version bump,
	 * on whichever request arrives first — and that request used to be able to
	 * be a Store API checkout POST, because this is called before any gate.
	 *
	 * So: never on the store path, at all, not even at that request's shutdown,
	 * which is still the buyer's request. Inline where something is about to
	 * read or write and cannot wait — an admin screen, a cron run, a WP-CLI
	 * call. Otherwise at shutdown, where the response has already gone and the
	 * migration still lands ahead of the buffered writer's own flush, which
	 * runs last on purpose.
	 */
	public static function catch_up_schema(): void {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a structural test; never stored, never echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		if ( Support\Checkout::is_store_uri( $uri ) ) {
			return;
		}

		if ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			Database\Schema::maybe_upgrade();

			return;
		}

		add_action( 'shutdown', array( Database\Schema::class, 'maybe_upgrade' ), 0 );
	}

	/**
	 * The two records a screen owes: which version this site is on, and the
	 * facts only a web request can see.
	 *
	 * Neither option is autoloaded, because nothing but a panel ever reads
	 * them — which is the whole reason they must not be read anywhere else.
	 * `bettershield_version` was written only on activation, which an update
	 * does not call, so a site running a new version still reported the old one
	 * and there was no "came from" for anything to compare against.
	 */
	public static function catch_up_on_screen(): void {
		// A version this site has not run before is a version whose checks
		// have not run either, and so is a copy the upgrader has just put in
		// place (below). The audit reads only and takes under a second, and a
		// score carried over from the previous code is the one thing a screen
		// must not show as current.
		$fresh   = Onboarding\Release::note_version();
		$pending = '1' === get_option( self::AUDIT_PENDING_OPTION );

		// The hub's address is no longer a setting; the one older versions
		// saved is retired with the version that stopped reading it.
		if ( $fresh ) {
			Mcp\Hub::retire_saved_address();
		}

		/*
		 * A change no hook sees — wp-config.php edited, a file put back over
		 * FTP — reaches the findings only through an audit. A BetterShield
		 * screen opened when the last one is older than the threshold below
		 * runs it again; any other screen leaves it to the schedule.
		 */
		$stale = ! $fresh && ! $pending && self::on_own_screen() && Audit\Auditor::last_run_older_than( self::STALE_AUDIT_SECONDS );

		if ( $fresh || $pending || $stale ) {
			/*
			 * One audit at a time across requests: two screens opened together
			 * would otherwise both pay it, and some checks reach the network.
			 * The claim is short and given back once the run ends, so a run
			 * that died holds nobody up for long. A version change is still
			 * paid by this request whatever another is doing.
			 */
			if ( $fresh || Support\Claim::claim( self::AUDIT_CLAIM, self::AUDIT_CLAIM_SECONDS ) ) {
				delete_option( self::AUDIT_PENDING_OPTION );

				try {
					if ( $fresh || $pending ) {
						// The update cleared core's update cache (#2146).
						Audit\Checks::refill_update_cache();
					}

					Audit\Auditor::run();
				} finally {
					Support\Claim::release( self::AUDIT_CLAIM );
				}
			}
		}

		Support\Observed::record();
	}

	/**
	 * How old the last audit may be when a BetterShield screen opens before
	 * that screen runs it again: five minutes. Long enough that moving
	 * between sections does not audit on every click, short enough that a
	 * change made outside WordPress shows on the next visit.
	 */
	public const STALE_AUDIT_SECONDS = 5 * MINUTE_IN_SECONDS;

	/** Held while a screen runs the audit, so a second screen does not. */
	private const AUDIT_CLAIM = 'audit_on_screen';

	/** Longer than an audit takes, short enough that a crashed run lapses. */
	private const AUDIT_CLAIM_SECONDS = 120;

	/**
	 * Whether the screen being drawn is one of this plugin's own. Read from
	 * the request because `admin_menu` fires before WordPress names the page.
	 */
	private static function on_own_screen(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen is open, not acting on a submission.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';

		return '' !== $page && 0 === strpos( $page, Admin\Sections::ROOT ) && current_user_can( Capabilities::READ_POSTURE );
	}

	/**
	 * Note that something an audit check reads has changed outside this
	 * plugin — an account, a role, a watched setting, a plugin, a theme, the
	 * core version — so the next screen audits again.
	 *
	 * Only a flag is written, and only when it is not already set, so a
	 * request carrying a hundred events writes it once; the audit itself is
	 * left to that screen, which runs it once and clears the flag. A visitor's request writes
	 * nothing at all: a sign-up or a checkout creating an account is not an
	 * operator changing the site, and anything it does change is read again
	 * by the stale-audit rule above when the owner next looks.
	 */
	public static function owe_audit_for_change(): void {
		// Asked only once WordPress has settled who is signed in: asking
		// earlier would decide it before the plugins that answer it load.
		$operator = ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || ( did_action( 'set_current_user' ) && current_user_can( 'manage_options' ) );

		if ( ! $operator ) {
			return;
		}

		// Already owed: nothing to write. The option is autoloaded, so the
		// read costs nothing.
		if ( '1' !== get_option( self::AUDIT_PENDING_OPTION ) ) {
			self::owe_audit();
		}
	}

	/**
	 * Called at the start of every audit run: whatever was owed before it
	 * began is paid by it.
	 */
	public static function audit_paid(): void {
		if ( '1' === get_option( self::AUDIT_PENDING_OPTION ) ) {
			delete_option( self::AUDIT_PENDING_OPTION );
		}
	}

	/**
	 * Set by the upgrade listener, consumed by the first screen drawn after
	 * it. Autoloaded so the check above costs the screen nothing; deleted
	 * the moment it is read, so it exists only between an install and the
	 * next screen.
	 */
	private const AUDIT_PENDING_OPTION = 'bettershield_audit_pending';

	/**
	 * Have the first screen drawn from now on run the audit: for a change
	 * made where running it inline would cost a visitor, such as the HTTPS
	 * switch going back on its own (#1289).
	 */
	public static function owe_audit(): void {
		update_option( self::AUDIT_PENDING_OPTION, '1', true );
	}

	/**
	 * Audit again once this plugin has been updated or reinstalled in place.
	 *
	 * Neither path runs activation, and a forced reinstall of the same
	 * version changes no version marker, so without this the findings and the
	 * score stayed whatever the previous copy last computed. Only this
	 * plugin's own completion is answered; every other plugin's update is
	 * somebody else's business.
	 *
	 * The action fires from the code that was running before the swap, so
	 * the first install to carry this listener is not the one it answers:
	 * the copy being replaced had no such hook, and the audit that time comes
	 * from the schedule.
	 *
	 * And for the same reason the audit is not run here. The process serving
	 * this action holds the old copy's classes while the files on disk are
	 * the new copy's, so any class the audit loads for the first time comes
	 * from the new code and meets the old — which was a fatal error inside
	 * the install command the first time a build changed a class the audit
	 * reaches. The listener notes that an audit is owed; the first screen
	 * drawn afterwards, by a process that loaded one copy, pays it.
	 *
	 * @param mixed                $upgrader The upgrader that just finished.
	 * @param array<string, mixed> $options  What it did, in core's own shape.
	 */
	public static function after_upgrade( $upgrader, $options ): void {
		if ( ! is_array( $options ) || 'plugin' !== ( $options['type'] ?? '' ) ) {
			return;
		}

		$basename  = plugin_basename( BETTERSHIELD_FILE );
		$directory = dirname( $basename );
		$updated   = isset( $options['plugins'] ) && is_array( $options['plugins'] ) && in_array( $basename, $options['plugins'], true );

		// An install over an existing copy names the destination, not the
		// plugin: WordPress does not know a reinstall from a first install.
		$result    = is_object( $upgrader ) && isset( $upgrader->result ) && is_array( $upgrader->result ) ? $upgrader->result : array();
		$installed = 'install' === ( $options['action'] ?? '' ) && $directory === (string) ( $result['destination_name'] ?? '' );

		if ( ! $updated && ! $installed ) {
			return;
		}

		Onboarding\Release::note_version();
		update_option( self::AUDIT_PENDING_OPTION, '1', true );
	}

	/**
	 * Wire up services.
	 *
	 * Services that write to the database go through the buffered event writer
	 * and the undo ledger — nothing writes directly.
	 */
	private function register_hooks(): void {
		// Plugin updates do not re-run activation, so the schema catches up on
		// every boot: one autoloaded option read when current.
		self::catch_up_schema();

		// The decoy credential, when one is planted. Registered on every
		// request because the thing it watches for is an authentication, and
		// those arrive wherever they like.
		Agents\Canary::register();
		// Consulted only when an application password signs a request in.
		( new Agents\PasswordLimits() )->register();
		Agents\DecoyPage::register();
		Incidents\Engine::register();

		/*
		 * The two records that exist for a panel on a screen, taken where a
		 * screen is actually being drawn. `is_admin()` was the gate and is not
		 * one: admin-ajax.php and admin-post.php both define WP_ADMIN, and the
		 * second answers unauthenticated requests — so a front end that uses
		 * either was paying two uncached option reads per request for facts
		 * nothing on that request would ever read. Neither entry point loads
		 * wp-admin/menu.php, so these hooks fire on a real screen and nowhere
		 * else.
		 */
		add_action( 'admin_menu', array( self::class, 'catch_up_on_screen' ) );
		add_action( 'upgrader_process_complete', array( self::class, 'after_upgrade' ), 10, 2 );
		add_action( 'network_admin_menu', array( self::class, 'catch_up_on_screen' ) );

		/*
		 * A subsite created after network activation has nothing of its own
		 * until somebody opens its dashboard, and until then every request
		 * against it errors and the audit answers a confident 100 — a false
		 * all-clear on a site nothing has ever checked. Core hands us the new
		 * site here, and it is provisioned in its context exactly as a site
		 * present at activation was: tables, capabilities, a baseline audit
		 * and, above all, its own recovery link. Creating the tables alone
		 * left a site with no way back in.
		 */
		if ( is_multisite() ) {
			add_action(
				'wp_initialize_site',
				static function ( $site, $args = array() ): void {
					if ( ! is_object( $site ) || ! isset( $site->blog_id ) ) {
						return;
					}

					/*
					 * Only where the plugin runs on every site. Active on one
					 * site alone, it still loads in Network Admin, which runs
					 * as the main site, so a site created there was provisioned
					 * and its owner mailed a recovery link for a plugin that
					 * never loads on it; activating it there later then found
					 * the link issued and mailed nobody. That case is the one
					 * where the creating site lists the plugin as its own.
					 * Network-active, or loaded with the must-use plugins (in
					 * neither list), it runs on the new site too.
					 */
					if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
						require_once ABSPATH . 'wp-admin/includes/plugin.php';
					}

					$basename = plugin_basename( BETTERSHIELD_FILE );

					if ( ! is_plugin_active_for_network( $basename ) && in_array( $basename, (array) get_option( 'active_plugins', array() ), true ) ) {
						return;
					}

					switch_to_blog( (int) $site->blog_id );

					// Provisioning creates tables and runs an audit, either of
					// which can throw; the restore has to happen anyway, or the
					// request that created the site spends the rest of its life
					// answering for it.
					try {
						Lifecycle::activate_site();

						// What WordPress wrote while making it — its roles and
						// first administrator — is this one row (#2184).
						Events\Writer::instance()->record(
							'site_created',
							Events\Writer::SEVERITY_INFO,
							array(
								'object_type' => 'site',
								'object_id'   => (string) (int) $site->blog_id,
								// And who it was handed to: that grant is the
								// one the rows this replaces would have named.
								'context'     => array(
									'path'          => (string) ( $site->path ?? '' ),
									// Named as its later rows name it (#1975).
									'address'       => $site instanceof \WP_Site ? Events\Listeners::site_address( $site ) : '',
									'administrator' => is_array( $args ) ? (int) ( $args['user_id'] ?? 0 ) : 0,
								),
							)
						);
					} finally {
						restore_current_blog();

						/*
						 * And onto the network screen at once. Its pages are
						 * cached for an hour, so the new site was counted as
						 * carried over but missing from the table until they
						 * expired (#1828).
						 */
						Admin\Network::forget_rollup();
					}
				},
				20,
				2
			);

			/*
			 * And the other end of the same life. A deleted subsite's own
			 * tables are dropped by core only if a plugin names them, so
			 * without this every table this plugin made for that site stayed
			 * — the activity log with its usernames and truncated networks,
			 * the sign-in tables, the passkey records, the undo history — on
			 * a site that no longer exists, where retention and pruning run
			 * per site and so never run again. The stated ninety days stops
			 * being true for exactly the data nobody can reach any more.
			 */
			add_filter(
				'wpmu_drop_tables',
				static function ( $tables, $blog_id = 0 ) {
					return array_values( array_unique( array_merge( (array) $tables, Lifecycle::site_tables( (int) $blog_id ) ) ) );
				},
				10,
				2
			);

			/*
			 * And what that filter cannot express. It names whole tables, so
			 * it reaches neither the per-site judgments kept in the network's
			 * single usermeta table under names carrying the site's id, nor —
			 * on a migrated network — the site's own rows inside the four
			 * network tables, which are one shared copy at the base prefix.
			 * Before core's own drop, so a failure here cannot leave the
			 * tables gone and the rows pointing at them behind.
			 */
			add_action(
				'wp_uninitialize_site',
				static function ( $site ): void {
					$blog_id = $site instanceof \WP_Site ? (int) $site->blog_id : (int) $site;

					// A site somebody asked to remove is removed; nothing this
					// sweep runs into may hold up the deletion itself.
					try {
						Lifecycle::forget_site( $blog_id );
					} catch ( \Throwable $sweep_failed ) {
						unset( $sweep_failed );
					}
				},
				5,
				1
			);
		}

		add_action( 'admin_init', array( Capabilities::class, 'map_once' ) );

		Events\Writer::instance()->register();

		// A place for an account holder to ask what this plugin knows about
		// them, and to ask for it to go. Registered unconditionally: a plugin
		// that keeps something and registers nothing is not refusing, it is
		// absent — the owner sends an export missing whatever this holds and
		// neither of them finds out.
		Privacy\PersonalData::register();

		// The last moment before an update becomes the site. Reports; never
		// interrupts — see the class docblock.
		Integrity\IncomingPackage::register();

		// A plugin or theme deleted through WordPress takes its open file
		// changes with it.
		Integrity\Scanner::register();

		// Capture before anything else registers: a listener added after the
		// action it watches has already fired records nothing.
		Events\Listeners::instance()->register();

		// Recovery first: safe-mode expiry is settled before enforcement
		// decides whether to arm, and the recovery link handler outranks
		// everything else on init.
		Recovery\SafeMode::maybe_expire();
		Recovery\RecoveryLink::register();

		// The owner's own emergency switch. Registers nothing at all when it is
		// off, and stands down under safe mode — the recovery link has to
		// outrank the one protection here that refuses sign-ins on purpose.
		Recovery\Lockdown::instance()->register();

		Hardening\Manager::instance()->enforce();
		Hardening\Monitor::register();
		// The HTTPS switch's way back, on every request and under safe mode
		// too: enforcement pausing must not pause the revert.
		Hardening\Item\HttpsAddress::register_early();
		Hardening\Item\HttpsRedirect::register_early();
		// The upload check's loopback, which has to be its account before
		// anything asks who is signed in.
		Audit\UploadTypes::register_early();
		Remediation\Suspension::register();
		Remediation\PasswordHold::register();
		// Where a dormant account suspended from its finding is let back in.
		Fixes\DormantAccounts::register();
		// REST routes the owner picked: watched for a week, then closed to
		// anybody not signed in (#1870).
		Fixes\RestRoutes::register();

		// Password policy: enforcement at the choosing moments, observation
		// at sign-in, never anything retroactive.
		Password\Policy::instance()->register();

		// Login protection: lockouts on verified addresses only, sessions,
		// and the honeypot. All of it pauses under safe mode.
		Login\Protection::instance()->register();
		Login\Sessions::instance()->register();
		Login\Honeypot::instance()->register();
		Login\Requests::instance()->register();
		// Missing pages and scanner paths, per source; off until the owner
		// turns it on (#690).
		Login\Probes::instance()->register();
		// Which account the store's checkout is creating, for the two above.
		Support\Checkout::register();
		Hardening\Item\EmailChange::register();

		// A cost between a wrong password and a lockout, paid by the machine
		// doing the guessing. No third party, so no disclosure.
		Login\ProofOfWork::instance()->register();

		// Tells an account holder — not the site's alert list — when their own
		// account signs in from a network it has not used before. Blocks nothing.
		Login\NewLocation::instance()->register();

		// A person's own sign-ins, on their own profile screen — the one place
		// an author or a subscriber can reach, and exactly the accounts that
		// most need to see this.
		Login\MySessions::instance()->register();
		Login\StoreAccount::instance()->register();
		Login\AccountPage::instance()->register();

		// A revoked credential takes its sessions with it: password changes,
		// role changes, and the second-factor and passkey removals wired at
		// their own sites all end what the old credential vouched for.
		Login\SessionReset::register();

		// Two-factor enrollment on the same screen, for the same reason: the
		// roles a two-factor policy targets cannot open any screen this
		// plugin draws, and an account held as overdue must be sent
		// somewhere it can comply.
		TwoFactor\ProfilePanel::instance()->register();

		// And passkeys beside it, for the same reason again: the passkey-only
		// policy can name any role on the site, and a role told its password
		// is about to stop working needs somewhere to enroll the credential
		// that replaces it.
		Passkeys\ProfilePanel::instance()->register();

		// One stamp per sign-in, so the audit can eventually say which
		// privileged accounts nobody uses.
		Audit\Dormant::register();

		// Every site's posture, the shared tables' progress and the network's
		// own log, on one screen in Network Admin.
		Admin\Network::register();

		// Two-factor: armed only by the full enrollment sequence, paused by
		// safe mode, never applied to application-password requests.
		TwoFactor\Manager::instance()->register();

		// Another plugin's authenticator-app enrollments, brought over as it
		// is switched off once two-factor is handed to BetterShield.
		TwoFactor\Import::register();

		// Requiring the factor of a role. Enforced in the dashboard rather than
		// at the sign-in, so a bug here is a form somebody can fill in rather
		// than a door that refuses them.
		TwoFactor\Policy::instance()->register();

		// Signing out or resetting a password ends any standing confirmation.
		Rest\Sudo::register();

		// Passkeys: purely additive. The button appears below the password
		// form and nothing here removes, replaces or gates that form, so no
		// failure of it can keep anybody out.
		( new Passkeys\LoginForm() )->register();

		// Passkey-only sign-in, which is the one thing here that DOES refuse a
		// password — and only for an account that already holds a passkey, so
		// nobody is ever refused without another way in. Stands down under
		// safe mode, which is what makes the recovery link the way back.
		Passkeys\Policy::instance()->register();

		// Read abilities: registered only when the owner opted in, and only
		// where the platform has the API (6.9+) — inert everywhere else.
		Abilities\Registrar::instance()->register();

		// The endpoint an assistant connects to, and the URLs it discovers
		// this site through. Registered on every request because the pretty
		// paths are rewrite rules and a rule has to exist before the request
		// that uses it; the master switch is off by default and every surface
		// here answers 404 or refuses while it is.
		( new Mcp\Manager() )->register();

		// The record of what the Abilities API was asked to do — by anyone,
		// for any ability, ours or another plugin's. Needs the lifecycle
		// filters (7.1+) and is inert below that. Deliberately not behind the
		// ability opt-in: that gate decides whether agents may read this
		// site, and this is the owner's own record of what they did.
		Agents\Capture::instance()->register();

		// Verification: confirms applied protections from the one request that
		// can see them — a visitor's page view — at shutdown, after the
		// response has gone, one item per request, never on the checkout.
		Verify\Sampler::instance()->register();

		// Alerting: watches what the event writer actually persisted, and
		// sends only from requests no visitor is waiting on.
		// Says where to report a vulnerability, at the address RFC 9116
		// reserves. Served rather than written, so it turns off cleanly and
		// works on nginx exactly as on Apache.
		Disclosure\SecurityTxt::instance()->register();

		Alerts\Notifier::instance()->register();
		Alerts\AccountNotices::register();

		$runner = Cron\Runner::instance();
		$runner->register();
		Alerts\Maintenance::register();
		$runner->register_task( Hardening\Monitor::TASK, 'hourly', array( Hardening\Monitor::class, 'tick' ), false );
		$runner->register_task( 'bettershield_incidents_refresh', 'hourly', array( Incidents\Engine::class, 'tick' ), false );
		$runner->register_task( Events\Unusual::TASK, 'hourly', array( Events\Unusual::class, 'check_signins' ), false );
		$runner->register_task( 'bettershield_incidents_prune', 'daily', array( Incidents\Repository::class, 'prune' ) );
		$runner->register_task(
			'bettershield_prune_events',
			'daily',
			array( Database\Pruner::class, 'prune_events' )
		);
		$runner->register_task(
			'bettershield_prune_agent_invocations',
			'daily',
			array( Database\Pruner::class, 'prune_agent_invocations' )
		);
		$runner->register_task(
			'bettershield_recovery_readiness',
			'daily',
			array( Recovery\Readiness::class, 'run' ),
			false
		);

		/*
		 * One email before a two-factor deadline, to the account it is about.
		 * Mail: never inside a page view.
		 */
		$runner->register_task( TwoFactor\Reminder::TASK, 'daily', array( TwoFactor\Reminder::class, 'run' ), false );

		$runner->register_task(
			'bettershield_daily_audit',
			'daily',
			array( Audit\Auditor::class, 'run' )
		);

		/*
		 * The usage report, which sends nothing unless the owner said yes —
		 * the task reads the answer every time it runs, so turning sharing off
		 * stops it at once. An outbound request: never inside a page view.
		 */
		$runner->register_task( Onboarding\Usage::TASK, 'daily', array( Onboarding\Usage::class, 'run' ), false );
		Onboarding\Usage::register();

		/*
		 * The Hub link, which sends nothing unless the owner turned it on. Its
		 * task is on the schedule exactly while it is on, so the schedule says
		 * whether to run it, and a site that never turned it on reads nothing
		 * of it on a visitor's request. An outbound request: never inside a
		 * page view. A run left on the schedule while it is off ends itself.
		 */
		Hub\Link\Push::register();

		if ( Hub\Link\Push::scheduled() ) {
			$runner->register_task( Hub\Link\Push::TASK, Hub\Link\Push::RECURRENCE, array( Hub\Link\Push::class, 'run' ), false );
		} else {
			add_action( Hub\Link\Push::TASK, array( Hub\Link\Push::class, 'run' ) );
		}
		// Opening a socket takes as long as it takes, so the certificate is
		// read here and nowhere else; every reader gets the stored answer.
		// Opens a TLS connection: never inside somebody's page view.
		$runner->register_task(
			'bettershield_certificate_check',
			'daily',
			static function ( ...$asked ): void {
				Audit\Certificate::check();

				// Run early because a person pressed Check again (#2430): the
				// finding follows the certificate just read.
				if ( array() !== $asked ) {
					Audit\Auditor::run();
				}
			},
			false
		);
		// Seals yesterday and anything older that is still unsealed. Never
		// today: rows are still arriving, and a seal that has to be revised is
		// not a seal.
		$runner->register_task(
			'bettershield_seal_log',
			'daily',
			array( Events\Seal::class, 'run_and_check' )
		);
		// On an unusually large uploads tree the directory-browsing item caps
		// one pass at five hundred guards; this continues until every bare
		// directory has one. A no-op everywhere else.
		$runner->register_task(
			'bettershield_guard_top_up',
			'daily',
			array( Hardening\Item\DirectoryBrowsing::class, 'top_up' )
		);
		$runner->register_task(
			'bettershield_prune_login_data',
			'daily',
			array( Database\Pruner::class, 'prune_login_data' )
		);
		// Write proposals past their reading life. The change itself and its
		// undo are recorded elsewhere and outlive this by design.
		$runner->register_task(
			'bettershield_prune_write_proposals',
			'daily',
			array( Database\Pruner::class, 'prune_write_proposals' )
		);
		// Closed file changes past their window. Open ones and the owner's
		// own markings stay; only the status of a closed one ever moved.
		$runner->register_task(
			'bettershield_prune_integrity_changes',
			'daily',
			array( Database\Pruner::class, 'prune_integrity_changes' )
		);
		// Lapsed claims. They are working state with an expiry already on
		// them, so nothing reads a row this removes; the sweep is only to
		// stop the table growing without bound.
		$runner->register_task(
			'bettershield_prune_claims',
			'daily',
			array( Support\Claim::class, 'prune' )
		);
		// What an update or an activation changed about the abilities agents
		// can call, compared on a later request, once the new code loads.
		Abilities\Baseline::register();
		$runner->register_task( Abilities\Baseline::TASK, 'daily', array( Abilities\Baseline::class, 'review' ), false );
		add_action( 'upgrader_process_complete', array( Vulnerabilities\Scanner::class, 'after_upgrade' ), 10, 2 );
		add_action( 'deleted_plugin', array( Vulnerabilities\Scanner::class, 'on_deleted' ) );
		add_action( 'deleted_theme', array( Vulnerabilities\Scanner::class, 'on_deleted' ) );
		add_action( 'bettershield_inventory_recheck', array( Vulnerabilities\Scanner::class, 'recheck' ) );

		// The vulnerability check: runs only when a feed is bound and the
		// owner turned it on; otherwise it returns at once, recording nothing.
		$runner->register_task(
			Vulnerabilities\Scanner::TASK,
			'daily',
			array( Vulnerabilities\Scanner::class, 'run' ),
			false
		);
		// Ticks daily; the sender decides whether today is the owner's chosen
		// day and whether a week has passed. wp-cron cannot move an existing
		// weekly schedule to a different weekday, and a daily tick is also what
		// gives this the runner's overdue fallback on a site whose cron stopped.
		$runner->register_task(
			'bettershield_digest',
			'daily',
			array( Alerts\Notifier::class, 'digest_tick' )
		);
		// The safety net under instant alerts: a burst held through the
		// coalescing window still goes out on a site with no admin traffic.
		$runner->register_task(
			'bettershield_alerts_dispatch',
			'hourly',
			array( Alerts\Notifier::instance(), 'dispatch' )
		);
		/*
		 * File integrity, hourly rather than daily — because one tick is not
		 * one check. A tick does as much as its budget allows and saves where
		 * it got to; a big site takes several to get through a run. Hourly
		 * ticks mean a run that needs twenty of them still finishes inside a
		 * day, and on a small site the ticks after the run completes cost a
		 * single option read each.
		 *
		 * Never inline in an administrator's page load: a tick is a walk of
		 * the install that hashes files and closes the changes it settles,
		 * the very kind of work the fallback keeps off a page someone is
		 * waiting for. Cron and the loopback run it.
		 */
		$runner->register_task(
			'bettershield_integrity_scan',
			'hourly',
			array( Integrity\Scanner::class, 'tick' ),
			false
		);

		/*
		 * Whether the directory still lists the plugins this site installed
		 * from it. Daily, and asking about a handful each time — a site with
		 * sixty plugins works through its list over a week rather than making
		 * sixty requests at once, and after that only what expired.
		 *
		 * Its own task rather than part of the audit: the audit is what the
		 * dashboard button runs, and a button that makes eight HTTP requests
		 * before it answers is a button people stop pressing. The audit check
		 * reads only what this has already learned.
		 */
		/*
		 * Whether the site hands a stranger its own leftovers. Weekly, because
		 * the answer changes when somebody deploys rather than by the hour,
		 * and it is a request per path against the site's own web server. Its
		 * own task for the same reason the directory check is: the audit is
		 * what the dashboard button runs, and the check reads only what this
		 * has already learned.
		 */
		/*
		 * Retiring application passwords nobody has used, when the owner has
		 * asked for it. Off until they do — this revokes credentials, and it
		 * is the one thing here that cannot be undone.
		 */
		$runner->register_task(
			'bettershield_app_password_sweep',
			'daily',
			static function (): void {
				( new Agents\Expiry() )->sweep();
			}
		);

		// A few dozen requests to this site's own server, inside a twenty-second
		// budget: the files a stranger could download and the leftover tools a
		// stranger could run. Cron and loopback only.
		$runner->register_task(
			'bettershield_artifact_probe',
			'weekly',
			static function ( ...$asked ): void {
				Audit\ExposedArtifacts::probe();

				// The same week's question about the quarantine folder, so a
				// server that denies it keeps that answer between audits.
				Files\Quarantine::ask_the_server();

				// And whether it already refuses what two .htaccess items
				// cannot write on it.
				Hardening\ServerRules::ask();

				// Run early because a person pressed Check again (#2207):
				// the findings take the answer now rather than at the next
				// daily audit. A requested run arrives with an argument.
				if ( array() !== $asked ) {
					Audit\Auditor::run();
				}
			},
			false
		);

		// Two requests to this site's own server, each naming an origin
		// nobody can own, to read the cross-origin policy that comes back.
		// Cron and loopback only.
		$runner->register_task(
			'bettershield_cross_origin_probe',
			'daily',
			array( Audit\CrossOrigin::class, 'probe' ),
			false
		);

		// And on the probe's own admin-ajax request, a record of what
		// WordPress decided there. Nothing on any other request.
		Audit\CrossOrigin::listen();

		// One XML-RPC call to this site's own server, and a control request
		// to the REST API, to learn whether the web server refuses
		// xmlrpc.php before WordPress answers. Cron and loopback only.
		$runner->register_task(
			Audit\XmlRpc::TASK,
			'daily',
			array( Audit\XmlRpc::class, 'probe' ),
			false
		);

		// One request for an uploads folder without an index file, and a
		// control request to the REST API, to learn whether the web server
		// lists it. Cron and loopback only.
		$runner->register_task(
			'bettershield_folder_listing_probe',
			'daily',
			array( Audit\FolderListing::class, 'probe' ),
			false
		);

		// One post to the content policy's report address, as a visitor's
		// browser sends it, to learn whether reports can arrive at all.
		// Cron and loopback only.
		$runner->register_task(
			'bettershield_csp_reach',
			'daily',
			array( Hardening\Item\ContentSecurityPolicy::class, 'probe_reach' ),
			false
		);

		// Two plain GETs of the sign-in page, as a visitor with no cookies,
		// to read whether a cache answered the second. Cron and loopback
		// only.
		$runner->register_task(
			'bettershield_sign_in_cache_probe',
			'daily',
			array( Audit\SignInCache::class, 'probe' ),
			false
		);

		// The site domain's SPF, DMARC and CAA records, asked of the server's
		// own resolver. A lookup can wait on a slow resolver, so cron and
		// loopback only.
		$runner->register_task(
			'bettershield_domain_records',
			'daily',
			static function ( ...$asked ): void {
				$answer = Audit\DomainRecords::lookup();

				// Run early because a person pressed Check again (#2203): the
				// finding takes a reliable answer now. One that could not tell
				// leaves the finding as it was, never fixed.
				if ( array() !== $asked && ! empty( $answer['reliable'] ) ) {
					Audit\Auditor::run();
				}
			},
			false
		);

		/*
		 * Whether anything published still points at plain HTTP. No index can
		 * serve a leading wildcard, so this reads every published post's
		 * content in full — its own task for the same reason the two above
		 * are: the audit is what the dashboard button runs, and the check
		 * reads only what this has already learned.
		 */
		$runner->register_task(
			'bettershield_mixed_content',
			'daily',
			array( Audit\MixedContent::class, 'refresh' )
		);

		/*
		 * Which namespaces answer a stranger. Surveying that means running
		 * every registered permission callback on the site and swapping the
		 * signed-in user out and back to do it, so it happens here and the
		 * check reads the answer.
		 */
		$runner->register_task(
			'bettershield_rest_surface',
			'daily',
			array( Audit\RestSurface::class, 'refresh' )
		);

		/*
		 * Which of the four security headers the web server already sends on
		 * its own. Daily and one request, to this site's own front page, with
		 * a token this plugin's send path stands aside for; what comes back
		 * is kept on the headers item's state, and the item leaves those
		 * headers to the server. Off the inline path like every other request
		 * to the site's own web server: its length is the server's, not a
		 * page view's.
		 */
		$runner->register_task(
			'bettershield_server_headers',
			'daily',
			array( Hardening\Manager::instance(), 'learn_server_headers' ),
			false
		);

		/*
		 * Carries a network's per-site logs into the tables the network
		 * shares, one bounded tick at a time. Keep discovery scheduled after
		 * completion so a newly provisioned or previously missed site joins.
		 *
		 * On the network's main site alone: wp-cron keeps a schedule per
		 * site, so registering this everywhere gave every subsite its own
		 * hourly appointment with one shared cursor.
		 *
		 * Never inline: it copies rows and
		 * recomputes seals, which is not work to spend somebody's page view
		 * on — the scheduler and the runner's own loopback are where it
		 * belongs, and the overdue fallback is what reaches a network whose
		 * scheduler has stopped.
		 *
		 * Deliberately not started from the schema catch-up beside it either,
		 * even though that is where a network first learns it has tables to
		 * move into. That path runs on an admin screen, and the two mechanisms
		 * above already reach a site whose cron never fires; starting a copy
		 * there would put the one piece of work that must never be inline on
		 * exactly the request that must never wait for it.
		 */
		if ( Database\NetworkMigration::schedules_here() ) {
			$runner->register_task(
				Database\NetworkMigration::TASK,
				'hourly',
				array( Database\NetworkMigration::class, 'run' ),
				false
			);
		} elseif ( is_multisite() ) {
			// A subsite that scheduled this for itself under an earlier
			// version keeps an appointment nothing answers here any more.
			// Cleared on init, where the cron array is already in memory and
			// finding nothing costs a lookup.
			add_action( 'init', array( Database\NetworkMigration::class, 'unschedule_here' ) );
		}

		// Asks the plugin and theme directories over HTTP: cron and
		// loopback only.
		$runner->register_task(
			'bettershield_directory_status',
			'daily',
			static function (): void {
				$items = Vulnerabilities\Inventory::collect();

				Vulnerabilities\Directory::refresh( $items );
				Vulnerabilities\ThemeDirectory::refresh( $items );
			},
			false
		);

		// Reads the store's posts, options and snippets for scripts that may
		// be reading card details: resumable chunks under a budget, cron and
		// loopback only.
		$runner->register_task(
			Audit\StoreScripts::TASK,
			'hourly',
			array( Audit\StoreScripts::class, 'run' ),
			false
		);

		( new Rest\OverviewController() )->register();
		( new Rest\FindingsController() )->register();
		( new Rest\HardeningController() )->register();
		( new Rest\RecoveryController() )->register();
		( new Rest\ActivityController() )->register();
		( new Rest\IncidentsController() )->register();
		( new Rest\ObservedController() )->register();
		( new Rest\PasswordPolicyController() )->register();
		( new Rest\AlertsController() )->register();
		( new Rest\IntegrityController() )->register();
		( new Rest\AiController() )->register();
		( new Rest\PasskeyController() )->register();
		( new Rest\LoginController() )->register();
		( new Rest\TwoFactorController() )->register();
		( new Rest\VulnerabilitiesController() )->register();
		( new Rest\AgentSurfaceController() )->register();
		( new Rest\AgentActivityController() )->register();
		( new Rest\AgentWriteController() )->register();
		( new Rest\McpController() )->register();
		( new Rest\HubController() )->register();
		( new Rest\PasskeyPolicyController() )->register();

		// Only where there is a network to set a policy for. A route that
		// exists in order to refuse is one somebody has to read the refusal of.
		if ( is_multisite() ) {
			( new Rest\NetworkPoliciesController() )->register();
			( new Rest\NetworkRecoveryController() )->register();
		}

		( new Rest\OperatorController() )->register();
		( new Rest\OnboardingController() )->register();
		( new Rest\QuickSetupController() )->register();

		// The network's own reads. Registers nothing on a single site, where
		// there is no network to read and no capability that would answer.
		( new Rest\NetworkController() )->register();
		( new Rest\NetworkHubController() )->register();

		// Operator tooling: the same services, reached from Site Health, the
		// dashboard and the terminal.
		( new Operator\SiteHealth() )->register();
		Cli\Command::register();

		if ( is_admin() ) {
			( new Admin\Menu() )->register();
			( new Operator\Widget() )->register();
			( new Onboarding\FirstRun() )->register();
			// Back to the setup after its link switches a plugin off (#1964).
			add_action( 'load-plugins.php', array( Onboarding\Coexistence::class, 'watch_deactivate_link' ) );
			( new Admin\QuickSetupPage() )->register();
			// Core's Plugins and Updates screens: which waiting update fixes a
			// known vulnerability, read from what the last check stored.
			( new Vulnerabilities\UpdateNotes() )->register();
			// The address and folder this site is known by, remembered once,
			// so a copy or a move can be noticed later.
			add_action( 'admin_init', array( Onboarding\SiteIdentity::class, 'remember_first' ) );
			add_action( 'admin_notices', array( Onboarding\SiteIdentity::class, 'notice' ) );
			// Plugins, Add New: what is already known about a plugin, beside
			// its Install button.
			( new Vulnerabilities\InstallNotes() )->register();
			// Plugins: switching this one off with a rotated key in force
			// signs everybody else out, said before the click.
			add_filter( 'plugin_row_meta', array( Hardening\Item\AuthKeys::class, 'row_meta' ), 10, 2 );
			// Plugins: why this one is being switched off, asked only where
			// the deactivation report the owner agreed to share will carry it.
			( new Onboarding\DeactivationFeedback() )->register();
		}
	}
}
