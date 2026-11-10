<?php
/**
 * Lockdown: one switch a person throws when the site is under attack.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BetterShield\Capabilities;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;
use BetterShield\Undo\SettingsLedger;

/**
 * Beside safe mode because these are the site's only two whole-site modes, and
 * each has to know about the other. Safe mode outranks this one: it exists so
 * a locked-out owner can get back in, and a lockdown that survived it would be
 * the one protection here capable of defeating the recovery promise. So
 * `is_active()` answers false under safe mode, and the recovery link therefore
 * pauses a lockdown for as long as safe mode lasts, the same way it pauses
 * everything else. It does not end it: the lockdown is back when safe mode
 * ends, unless somebody lifted it in the meantime.
 *
 * **This is not the automatic response policy, and the difference is the whole
 * risk profile.** That decides things on the owner's behalf from rules; this
 * is one switch a person throws and can throw back, so nothing here waits on
 * an outside ruling and nothing here acts on its own.
 *
 * **It does not expire, and that is deliberate.** Safe mode expires because
 * running out re-arms protections, which is the safe direction. Running out of
 * a lockdown would quietly unlock a site somebody locked because it was being
 * attacked — the unsafe direction, and at the worst possible moment. It stays
 * until a person ends it, and `notice()` says so on every dashboard screen for
 * as long as it is on.
 *
 * **The front end is untouched, and the checkout most of all.** A shop under
 * attack still has customers mid-purchase, and a security switch that empties
 * a cart has done more damage than most attacks would. Nothing here runs on a
 * front-end request: the surfaces it closes are the administrative ones, plus
 * the two credential paths that do not belong to a browser.
 */
final class Lockdown {

	/** How many accounts the last selection left out as beyond reach. See within_reach(). */
	private static int $beyond_reach = 0;

	public const OPTION = 'bettershield_lockdown';

	/**
	 * How many dashboard-capable accounts one throw of the switch evicts.
	 *
	 * An emergency control has to finish. Past this the surplus is counted and
	 * reported rather than attempted, because a request that times out part
	 * way leaves some sessions ended and others not with nothing saying which.
	 */
	public const MAX_EVICTIONS = 500;

	/**
	 * The key that decides which request throws the switch.
	 *
	 * Both transitions are read-decide-write, and between the read and the
	 * write the state is still what it was: a double-click, or two open tabs,
	 * produced two undo rows for one change, two records of one emergency, and
	 * the eviction sweep run twice over the same accounts. Short, because it
	 * only has to cover the one request, and released on every path out so a
	 * genuine retry a moment later is not held off by a window it cannot see.
	 */
	private const TRANSITION_CLAIM = 'lockdown_transition';

	private const TRANSITION_SECONDS = 30;

	/**
	 * The capabilities that put NEW code on this site, or change code already
	 * on it.
	 *
	 * Refused for everybody while a lockdown is on, including administrators
	 * and including whoever threw it: the likeliest way an attacker with a
	 * foothold keeps it is by installing or editing something, and a switch
	 * that exempted administrators would exempt exactly the account they are
	 * most likely to be holding.
	 *
	 * **Deactivating and deleting are deliberately NOT here, and the first
	 * draft had them.** WordPress governs activation and deactivation with the
	 * same `activate_plugins` capability, so freezing it took away the one
	 * action an owner most needs during the incident this switch is for:
	 * turning off the backdoor they just found. It left them choosing between
	 * a locked-down site with the backdoor still running and lifting the
	 * lockdown to remove it. Adding code is what a lockdown stops; taking it
	 * away is the remediation the lockdown exists to make room for.
	 *
	 * WordPress's background updates ask for no capability and keep running:
	 * they are how security releases arrive, and scheduled work runs as no
	 * user by design. So the freeze is said as the dashboard's, never as
	 * "nothing can be updated".
	 */
	private const FROZEN_CAPS = array(
		'install_plugins',
		'update_plugins',
		'install_themes',
		'update_themes',
		'update_core',
		'edit_plugins',
		'edit_themes',
		'edit_files',
	);

	private static ?Lockdown $instance = null;

	public static function instance(): Lockdown {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/* ---- state ----------------------------------------------------------------- */

	/**
	 * @return array{active: bool, since: ?int, by: int}
	 */
	public static function state(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'active' => ! empty( $stored['active'] ),
			'since'  => isset( $stored['since'] ) ? (int) $stored['since'] : null,
			'by'     => isset( $stored['by'] ) ? (int) $stored['by'] : 0,
		);
	}

	/**
	 * Whether a lockdown is being enforced right now.
	 *
	 * Safe mode wins. The recovery link exists so somebody who cannot get in
	 * can get in, and it has to outrank every protection this plugin has —
	 * including the one that refuses sign-ins by design.
	 */
	public static function is_active(): bool {
		if ( SafeMode::is_active() ) {
			return false;
		}

		return self::state()['active'];
	}

	/**
	 * Whether this site refuses a session presented to it while it is locked
	 * down.
	 *
	 * The gate below is kept at this site's sign-in form. On a network every
	 * site's form signs an account in, and the cookie it sets is good on every
	 * site that shares its path or its domain, so an account refused here could
	 * sign in at the next site and walk in. A session opened after the lockdown
	 * began, anywhere but here, for an account the gate would refuse, is nobody
	 * on this site. One opened before it was the eviction's to end, and the
	 * customers it leaves signed in stay signed in; one opened here passed the
	 * gate or came through the checkout, which a lockdown leaves alone. A
	 * record that does not say where it was opened is read as the stricter of
	 * the two.
	 *
	 * @param array<string, mixed> $session Core's record of the session.
	 */
	public static function refuses_session( \WP_User $user, array $session ): bool {
		if ( ! is_multisite() || ! self::is_active() ) {
			return false;
		}

		$since = self::state()['since'];

		if ( null === $since || (int) ( $session['login'] ?? 0 ) < $since ) {
			return false;
		}

		if ( false === \BetterShield\Login\Sessions::opened_elsewhere( $session ) ) {
			return false;
		}

		return ! self::manages_here( $user );
	}

	/**
	 * Whether an account is one the gate lets in, read from the capabilities
	 * its roles give it here.
	 *
	 * Not through `user_can()`, as the gate asks: this is also asked while
	 * WordPress is still working out who the request is, and a capability
	 * filter that asks who the current user is would ask the question being
	 * answered.
	 */
	private static function manages_here( \WP_User $user ): bool {
		return is_super_admin( $user->ID ) || ! empty( $user->allcaps[ Capabilities::MANAGE ] ) || ! empty( $user->allcaps['manage_options'] );
	}

	/**
	 * Throw the switch.
	 *
	 * @return array{active: bool, since: ?int, by: int}|\WP_Error
	 */
	public static function enter( int $by, bool $end_sessions = true ) {
		if ( self::state()['active'] ) {
			return self::state();
		}

		// A caller that loses reads the state rather than an error: a second
		// press of the same button means "already done", not "something went
		// wrong".
		if ( ! Claim::claim( self::TRANSITION_CLAIM, self::TRANSITION_SECONDS ) ) {
			return self::state();
		}

		$token = SettingsLedger::record( 'lockdown', array( 'active' => false ), array( 'active' => true ) );

		/*
		 * False is the one answer that stops this: the prior state existed and
		 * could not be written down, so the switch would close the site with
		 * nothing in the list to open it again. Null is not that — it is a
		 * revert applying its own recorded state, which is never ledgered a
		 * second time, and it carries on.
		 */
		if ( false === $token ) {
			Claim::release( self::TRANSITION_CLAIM );

			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'The site was not locked down: its undo record could not be saved. Nothing changed.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$next = array(
			'active' => true,
			'since'  => time(),
			'by'     => $by,
		);

		if ( ! update_option( self::OPTION, $next, true ) ) {
			/*
			 * The change never took effect, so its undo record closes at once
			 * rather than sitting in the list offering to put back something
			 * that never happened. `Hardening\Manager` does the same on a
			 * failed apply, and for the same reason: a ledger that lies about
			 * what occurred is worse than no ledger.
			 */
			if ( is_string( $token ) ) {
				\BetterShield\Undo\Ledger::mark_reverted( $token );
			}

			Claim::release( self::TRANSITION_CLAIM );

			return new \WP_Error(
				'bettershield_lockdown_failed',
				__( 'The site was not locked down: the setting could not be saved. Nothing changed.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		/*
		 * Ending every other session is the point rather than a side effect:
		 * a lockdown that left an intruder's existing session working would
		 * close the door they came through and leave them inside. The session
		 * of whoever threw the switch is spared, because being signed out by
		 * one's own emergency control is how somebody ends up locked out of a
		 * site they are trying to defend.
		 */
		$evicted = array(
			'ended'    => 0,
			'accounts' => 0,
			'beyond'   => 0,
			'skipped' => 0,
		);

		if ( $end_sessions ) {
			$evicted = self::end_other_sessions( $by, (string) wp_get_session_token() );
		}

		Writer::instance()->record(
			'lockdown_entered',
			Writer::SEVERITY_CRITICAL,
			array(
				'actor_type'  => 'user',
				'actor_id'    => $by,
				'object_type' => 'site',
				'context'     => array(
					'sessions_ended'   => $evicted['ended'],
					'accounts_swept'   => $evicted['accounts'],
					// Stated rather than left out: a bounded sweep that does
					// not say what it skipped reads as one that finished.
					'accounts_skipped' => $evicted['skipped'],
					// The same for those this account may not sign out.
					'accounts_beyond_reach' => $evicted['beyond'],
				),
			)
		);

		Claim::release( self::TRANSITION_CLAIM );

		return self::state();
	}

	/**
	 * Throw it back.
	 *
	 * @return array{active: bool, since: ?int, by: int}|\WP_Error
	 */
	public static function leave( string $reason = 'manual' ) {
		$before = self::state();

		if ( ! $before['active'] ) {
			return $before;
		}

		if ( ! Claim::claim( self::TRANSITION_CLAIM, self::TRANSITION_SECONDS ) ) {
			return $before;
		}

		$token = SettingsLedger::record( 'lockdown', array( 'active' => true ), array( 'active' => false ) );

		/*
		 * Read exactly as on the way in, and refused for the same reason: an
		 * unrecordable change is one nobody can put back. The site staying
		 * closed is the safe half of that trade, and the recovery link
		 * outranks a lockdown, so nobody is stranded by it.
		 */
		if ( false === $token ) {
			Claim::release( self::TRANSITION_CLAIM );

			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'The lockdown was not lifted: its undo record could not be saved. The site is still closed, and your recovery link still works.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$stored = update_option(
			self::OPTION,
			array(
				'active' => false,
				'since'  => null,
				'by'     => 0,
			),
			true
		);

		/*
		 * The same care the entry path takes, for the same reason. The site is
		 * still closed, and what would outlive this request otherwise is a
		 * record saying it had been reopened and an undo row offering to close
		 * it again — a ledger that lies about what occurred is worse than no
		 * ledger, in both directions. The early return above means a false
		 * here is a failed write rather than a write that changed nothing.
		 */
		if ( ! $stored ) {
			if ( is_string( $token ) ) {
				\BetterShield\Undo\Ledger::mark_reverted( $token );
			}

			Claim::release( self::TRANSITION_CLAIM );

			return new \WP_Error(
				'bettershield_lockdown_lift_failed',
				__( 'The lockdown was not lifted: the setting could not be saved. The site is still closed.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		Writer::instance()->record(
			'lockdown_left',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'site',
				'context'     => array(
					'reason'  => $reason,
					'held_for' => null === $before['since'] ? null : ( time() - $before['since'] ),
				),
			)
		);

		Claim::release( self::TRANSITION_CLAIM );

		return self::state();
	}

	/**
	 * Whether the account throwing the switch may end this account's sessions.
	 *
	 * A session is the whole network's, so ending one here signs the account
	 * out of every site it belongs to. A site's administrator doesn't get to
	 * do that to a network's accounts, the same rule "Sign out everyone" keeps.
	 * Their reach is their own account and those that belong to this site
	 * alone. Someone who may manage the network's users, or a command run
	 * with no account behind it, reaches everyone.
	 */
	private static function within_reach( int $id, int $by ): bool {
		if ( ! is_multisite() || $by <= 0 || $id === $by || user_can( $by, 'manage_network_users' ) ) {
			return true;
		}

		if ( is_super_admin( $id ) ) {
			return false;
		}

		return array() === array_diff( array_map( 'intval', array_keys( get_blogs_of_user( $id ) ) ), array( (int) get_current_blog_id() ) );
	}

	/** The same capped candidate selection used by the eviction itself. */
	private static function eviction_ids( int $keep ): array {
		$ids    = array();
		$beyond = array();

		/*
		 * The network's own administrators first of all. A capability read is
		 * answered from this site's capabilities meta, and an account with no
		 * role here has no such row, which is the ordinary state of the
		 * accounts with the run of every site. Appended after the local read
		 * they fell where the bound cuts, so on a busy site the panic switch
		 * spared the one account it most needed to reach.
		 */
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$super = get_user_by( 'login', (string) $login );

				if ( $super instanceof \WP_User ) {
					if ( self::within_reach( (int) $super->ID, $keep ) ) {
						$ids[] = (int) $super->ID;
					} else {
						$beyond[] = (int) $super->ID;
					}
				}
			}
		}

		// Then the account throwing the switch, which loses its other sessions.
		if ( $keep > 0 ) {
			$ids[] = $keep;
		}

		/*
		 * Then the accounts that can reach the dashboard, those that can
		 * change most first: administrators, editors, then the rest. A
		 * customer's session opens a customer account and nothing else, and
		 * clearing those is what would empty a shop's carts. Only accounts
		 * holding a session are read, so dormant ones spend none of the
		 * bound, and with no order a read answers by login, which an intruder
		 * picks. Each pass asks for what is left of the bound and excludes
		 * what is held, so the total stops one past it and a surplus means
		 * what it says.
		 */
		/*
		 * A session is a row of user meta only where core keeps sessions. A
		 * site that keeps them elsewhere has no such rows to read by, so there
		 * every capable account is read and the session manager asked.
		 */
		$in_meta = 'WP_User_Meta_Session_Tokens' === apply_filters( 'session_token_manager', 'WP_User_Meta_Session_Tokens' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter, asked the way core asks it.

		// The first pass takes whoever may run this plugin too: they can
		// still sign in during a lockdown, whatever else their role can do.
		foreach ( array( array( 'manage_options', Capabilities::MANAGE ), array( 'edit_others_posts' ), array( 'edit_posts' ) ) as $capabilities ) {
			$ids = array_values( array_unique( $ids ) );

			if ( count( $ids ) > self::MAX_EVICTIONS ) {
				break;
			}

			$query = array(
				'fields'         => 'ID',
				'number'         => self::MAX_EVICTIONS + 1 - count( $ids ),
				'capability__in' => $capabilities,
				'exclude'        => array_merge( $ids, $beyond ), // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- at most MAX_EVICTIONS ids; the owner's emergency switch, never a front-end path.
			);

			if ( $in_meta ) {
				$query['meta_key']     = 'session_tokens'; // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- bounded above; the owner's emergency switch, never a front-end path.
				$query['meta_compare'] = 'EXISTS';
			}

			$found = get_users( $query );

			foreach ( $found as $id ) {
				if ( self::within_reach( (int) $id, $keep ) ) {
					$ids[] = (int) $id;
				} else {
					$beyond[] = (int) $id;
				}
			}
		}

		$ids = array_values( array_unique( $ids ) );

		self::$beyond_reach = count( array_unique( $beyond ) );

		return $ids;
	}

	/** Counts for a machine-initiated lockdown, which has no browser session to keep. */
	public static function eviction_preview( int $by ): array {
		$ids = self::eviction_ids( $by ); $accounts = array();
		foreach ( array_slice( $ids, 0, self::MAX_EVICTIONS ) as $id ) {
			$accounts[ $id ] = count( \WP_Session_Tokens::get_instance( $id )->get_all() );
		}
		return array( 'accounts' => $accounts, 'skipped' => max( 0, count( $ids ) - self::MAX_EVICTIONS ) );
	}

	/**
	 * End every session except the one belonging to the person who threw the
	 * switch. Returns how many accounts were signed out.
	 */
	private static function end_other_sessions( int $keep, string $keep_token ): array {
		$ended = 0; $swept = 0; $skipped = 0;
		$ids = self::eviction_ids( $keep );

		/*
		 * Bounded, because an emergency control that times out halfway through
		 * leaves some sessions ended and others not with nothing recording
		 * which. What is NOT bounded is the honesty about it: the surplus is
		 * counted and goes into the event, so a log saying the site was
		 * evicted never means less than it says.
		 */
		if ( count( $ids ) > self::MAX_EVICTIONS ) {
			$skipped = count( $ids ) - self::MAX_EVICTIONS;
			$ids     = array_slice( $ids, 0, self::MAX_EVICTIONS );
		}

		foreach ( $ids as $id ) {
			$manager = \WP_Session_Tokens::get_instance( $id );

			/*
			 * The account throwing the switch keeps THIS session and loses its
			 * others, rather than keeping all of them.
			 *
			 * Skipping the whole account was the first draft and it had the
			 * defect that mattered most: the case this feature exists for is a
			 * credential somebody else is holding, and if that credential is
			 * the administrator's own then an intruder signed in as them
			 * survived the eviction untouched. Being signed out by one's own
			 * emergency control is what has to be avoided — not sparing every
			 * device that account has ever used.
			 */
			if ( $id === $keep ) {
				if ( '' !== $keep_token ) {
					// Everything this account holds except the one being kept.
					$others = max( 0, count( $manager->get_all() ) - 1 );

					$manager->destroy_others( $keep_token );

					$ended += $others;
					++$swept;

					continue;
				}

				// No session token to keep: this was not a browser, so there
				// is nothing to spare and the account is evicted like the rest.
			}

			/*
			 * Counted before they are destroyed, and counted as sessions.
			 * This was incrementing once per account, so the row said "3
			 * sessions ended" for three accounts holding a dozen devices
			 * between them — and, worse, said one for an account that was
			 * signed in nowhere at all. A number in an emergency record is
			 * either the number or it is noise.
			 */
			$ended += count( $manager->get_all() );

			$manager->destroy_all();

			++$swept;
		}

		return array(
			'ended'    => $ended,
			'accounts' => $swept,
			'beyond'   => self::$beyond_reach,
			'skipped' => $skipped,
		);
	}

	/* ---- enforcement ----------------------------------------------------------- */

	public function register(): void {
		if ( ! self::is_active() ) {
			return;
		}

		/*
		 * Priority 32: after the lockout gate (30) has had its say, and before
		 * the passkey-only gate (35) and the second-factor gate (40). An
		 * account refused here has no business being sent on to a code screen
		 * whose answer cannot help it.
		 */
		add_filter( 'authenticate', array( $this, 'gate' ), 32, 3 );

		// The two credential paths that are not a person at a browser. Both are
		// how a stolen credential is used without touching the sign-in form.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'wp_is_application_passwords_available', '__return_false' );

		/*
		 * Nobody new arrives during a lockdown. Both the single-site option and
		 * the network one, because they are different settings: on a network
		 * `users_can_register` governs nothing and signups go through
		 * wp-signup.php, which reads the site option — so filtering only the
		 * first would have promised something the code did not do on exactly
		 * the installs with the most accounts.
		 */
		add_filter( 'option_users_can_register', '__return_zero' );
		add_filter( 'pre_option_users_can_register', '__return_zero' );
		add_filter( 'pre_site_option_registration', array( $this, 'no_registration' ) );

		/*
		 * WooCommerce's My Account form keeps its own registration setting
		 * and signs the new customer in itself, never through authenticate,
		 * so neither of the above reaches it. The form is not offered, a post
		 * it would have sent is refused, and nobody new is signed in. All
		 * three run on that form only: an account made at checkout is left
		 * alone, as the checkout always is.
		 */
		add_filter( 'pre_option_woocommerce_enable_myaccount_registration', array( $this, 'no_shop_registration' ) );
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'refuse_shop_registration' ) );
		add_filter( 'woocommerce_registration_auth_new_customer', array( $this, 'no_new_customer_session' ) );

		// And nothing that runs on this site changes while it is on.
		add_filter( 'map_meta_cap', array( $this, 'freeze_caps' ), 10, 2 );

		// On every dashboard screen, not only the one with the switch.
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	/**
	 * Say on every screen that the site is closed.
	 *
	 * The class used to claim this and only the Recovery panel did it, so an
	 * owner could work for an hour on other screens with no sign that their
	 * customers were being turned away. A mode this consequential has to be
	 * visible from wherever somebody happens to be standing.
	 */
	public function notice(): void {
		$state = self::state();

		if ( ! self::is_active() || null === $state['since'] ) {
			return;
		}

		// Where it is ended, for somebody who may end it (#2406).
		$end = current_user_can( \BetterShield\Capabilities::MANAGE )
			? sprintf(
				' <a href="%s">%s</a> (%s)',
				esc_url( admin_url( 'admin.php?page=bettershield-protect&tab=recovery' ) ),
				esc_html__( 'End lockdown', 'bettershield' ),
				esc_html__( 'BetterShield › Protection › Recovery', 'bettershield' )
			)
			: '';

		printf(
			'<div class="notice bs-notice notice-error"><p><strong>%s</strong> %s%s</p></div>',
			esc_html__( 'This site is in lockdown.', 'bettershield' ),
			esc_html(
				sprintf(
					/* translators: %s: how long ago, e.g. "2 hours". */
					__( 'Only administrators can sign in, and plugins, themes and code can’t be changed from the dashboard. On for %s.', 'bettershield' ),
					human_time_diff( $state['since'] )
				)
			),
			$end // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped where it is built.
		);
	}

	/**
	 * Only accounts that manage this site may sign in.
	 *
	 * Everybody else is refused — which on a membership site or a shop is most
	 * accounts, and is the cost the owner is choosing when they throw this. It
	 * is stated where the switch is rather than discovered afterwards.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function gate( $user, $username = '', $password = '' ) {
		/*
		 * Re-checked rather than trusted from having been hooked. Hooking
		 * happens once at boot, and safe mode can begin part-way through a
		 * request — the recovery link is exactly that request — so a gate that
		 * only consulted the boot-time answer would go on refusing sign-ins
		 * inside the very request that exists to stop it.
		 */
		if ( ! $user instanceof \WP_User || ! self::is_active() ) {
			return $user;
		}

		if ( user_can( $user, Capabilities::MANAGE ) || user_can( $user, 'manage_options' ) ) {
			return $user;
		}

		/*
		 * One of this plugin's own refusals, so it does not count as a wrong
		 * password toward a lockout: the credential was correct and the site
		 * is simply closed. Counting it would lock accounts out past the end
		 * of the lockdown, which is damage that outlasts the emergency.
		 */
		return new \WP_Error(
			'bettershield_lockdown',
			__( 'Sign-in is paused for now. Try again later.', 'bettershield' )
		);
	}

	/**
	 * The network's registration setting, answered as closed.
	 *
	 * @param mixed $value
	 * @return string
	 */
	public function no_registration( $value ): string {
		return self::is_active() ? 'none' : (string) $value;
	}

	/**
	 * The shop's My Account registration setting, answered as closed on the
	 * front end. In the dashboard it reads as stored: answered there, saving
	 * the shop's settings during a lockdown would write the closure in for
	 * good.
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	public function no_shop_registration( $value ) {
		return self::is_active() && ! is_admin() ? 'no' : $value;
	}

	/**
	 * Refuse the My Account registration form's post, which a page opened
	 * before the lockdown can still send.
	 *
	 * @param mixed $errors
	 * @return mixed
	 */
	public function refuse_shop_registration( $errors ) {
		if ( ! self::is_active() || ! $errors instanceof \WP_Error ) {
			return $errors;
		}

		$errors->add( 'bettershield_lockdown', __( 'Sign-up is paused for now. Try again later.', 'bettershield' ) );

		return $errors;
	}

	/**
	 * Nobody new is signed in from the My Account form.
	 *
	 * @param mixed $sign_in
	 * @return mixed
	 */
	public function no_new_customer_session( $sign_in ) {
		return self::is_active() ? false : $sign_in;
	}

	/**
	 * @param array<int, string> $caps
	 * @return array<int, string>
	 */
	public function freeze_caps( array $caps, string $cap ): array {
		if ( ! self::is_active() ) {
			return $caps;
		}

		if ( in_array( $cap, self::FROZEN_CAPS, true ) ) {
			return array( 'do_not_allow' );
		}

		return $caps;
	}
}
