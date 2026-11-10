<?php
/**
 * Passkey-only sign-in: the password stops opening an account that has a
 * passkey.
 *
 * The design and the safety argument are on the class below — kept there
 * rather than here because the direct-access guard has to sit inside the first
 * fifty lines, which is as far as the plugin checker reads for it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BetterShield\Events\Writer;
use BetterShield\Login\Sessions;
use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Recovery\OfflineCodes;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;
use BetterShield\Support\LoginForms;
use BetterShield\TwoFactor\Manager as TwoFactorManager;
use BetterShield\Undo\SettingsLedger;

/**
 * A passkey cannot be phished — the browser will not present it to a domain it
 * was not registered for, and there is no secret for anybody to repeat. A
 * password sitting behind it is the leg that undoes all of that: a credential
 * that can be read out of a breach, guessed, or typed into a convincing copy
 * of the sign-in page. This is the switch that removes it.
 *
 * **This gate refuses at the sign-in, which `TwoFactor\Policy` deliberately
 * does not, and the difference is worth stating rather than discovering.**
 * That policy withholds the *dashboard* instead of the sign-in, because
 * parking a sign-in behind a requirement is a new way to be locked out and a
 * bug there is somebody staring at a page that refuses them. The same trade is
 * not available here: the whole value of this feature is that a stolen
 * password does not sign anybody in, and a version that let the password
 * through and withheld the dashboard would deliver none of it.
 *
 * So the safety is built somewhere else, and it is built out of one rule:
 * **an account is never refused unless it already holds a working passkey.**
 * A role can be named here for people who have not enrolled and nothing
 * happens to them — they keep their password indefinitely, and are asked
 * rather than cut off. Enforcement begins for one account at the moment that
 * account registers a passkey, which is the moment it has another way in. The
 * dashboard notice says so plainly before anybody enrolls.
 *
 * That is also why there is no grace window here. `TwoFactor\Policy` has one
 * because it has a deadline after which something is withheld; this has no
 * deadline at all, and a countdown to a date on which nothing happens would be
 * theater.
 *
 * **The way back is the recovery link — or a printed code, which opens the
 * same door — and it works by construction rather than by being remembered.**
 * Either credential puts the site into safe mode, this gate stands down under
 * safe mode exactly as every other protection does, and the password signs its
 * owner in again. Nothing here has to know about recovery for recovery to
 * work, which is the property worth keeping.
 *
 * Arming it is the one place that does have to know, and it asks a harder
 * question than whether something is on record: see `update_settings()`.
 */
final class Policy {

	public const OPTION = 'bettershield_passkey_policy';

	/**
	 * How many refusals of one account inside the window raise the louder
	 * event.
	 *
	 * One refusal is somebody typing a password out of habit, or a password
	 * that has leaked — worth a row either way, and the first of each window
	 * gets one. What is not routine is the same account refused over and over,
	 * and that is a single row saying how many rather than a row per attempt:
	 * this refusal accrues to no lockout, and it is one of the types the writer
	 * keeps when everything else is shed, so nothing else bounds it.
	 */
	public const REPEAT_THRESHOLD = 10;

	/** The window the threshold is counted in, in minutes. */
	public const REPEAT_WINDOW_MINUTES = 60;

	private static ?Policy $instance = null;

	public static function instance(): Policy {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		/*
		 * Priority 35: after the password (20), the honeypot (25) and the
		 * lockout gate (30), and before the second-factor gate (40). Refusing
		 * the password outright before that gate parks the sign-in at a code
		 * screen saves sending somebody to a screen whose answer cannot help
		 * them.
		 */
		add_filter( 'authenticate', array( $this, 'gate' ), 35, 3 );

		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	/* ---- settings -------------------------------------------------------------- */

	/**
	 * @return array{roles: string[]}
	 */
	public function settings(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'roles' => array_values( array_filter( array_map( 'strval', (array) ( $stored['roles'] ?? array() ) ) ) ),
		);
	}

	/**
	 * The stored value apart from the defaults, so the per-field reset, the
	 * release panel's honesty test and a settings import all read the same
	 * shape.
	 *
	 * @return array{roles: string[]}
	 */
	public function defaults(): array {
		return array( 'roles' => array() );
	}

	/**
	 * What this input would become, or the refusal it earns.
	 *
	 * Separate from the write so a dry run can ask the same question the save
	 * will. Both refusals belong here, including the one that depends on the
	 * site's state rather than on the input: whether there is a way back is
	 * exactly what an operator planning an import needs to be told, and a
	 * fresh site is the likeliest one to have none.
	 *
	 * @param array<string, mixed> $input
	 * @return array{roles: string[]}|\WP_Error
	 */
	public function validate( array $input ) {
		$current = $this->settings();
		$roles   = isset( $input['roles'] ) ? (array) $input['roles'] : $current['roles'];
		$known   = array_keys( wp_roles()->roles );

		$clean = array();

		foreach ( $roles as $role ) {
			$role = sanitize_key( (string) $role );

			if ( '' === $role ) {
				continue;
			}

			if ( ! in_array( $role, $known, true ) ) {
				return new \WP_Error(
					'bettershield_unknown_role',
					__( 'That is not a role on this site.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$clean[] = $role;
		}

		$next = array( 'roles' => array_values( array_unique( $clean ) ) );

		/*
		 * Naming a role here is the only thing in this plugin that takes an
		 * account's password away, and the way back from a lost passkey is the
		 * recovery link or a printed code. Arming it on a site that has
		 * neither would be promising a door that is not there — so this
		 * refuses, the way the HSTS item refuses without HTTPS rather than
		 * trusting the owner to have checked.
		 *
		 * Widening is what is refused, and widening is a question about
		 * membership rather than about size: swapping one role for another
		 * leaves the count exactly where it was while arming the policy for
		 * accounts it did not cover a moment ago. So the test is what the
		 * change adds. Narrowing, reordering and saving the same roles again
		 * all stay open, because a site that has lost its way back has to be
		 * able to take roles out — a refusal that trapped it would be the
		 * state this one exists to prevent.
		 *
		 * And what counts as a way back is a credential the owner is holding,
		 * not a row in the options table. Only the link's hash is stored here,
		 * so a link past its life opens nothing and a link whose mail was
		 * refused for sending is one nobody ever received; neither can be
		 * produced again from this site. Printed codes have no such dependency
		 * and never expire, which is why they count on their own.
		 */
		/*
		 * A role the network requires cannot be unchecked here. It would still
		 * be required — the network's list sits beneath this one — and this
		 * screen would show a role missing from a site that goes on enforcing
		 * it. Refusing says where the requirement was set.
		 */
		$blocked = NetworkPolicies::network_roles_removed( $current['roles'], $next['roles'], NetworkPolicies::passkey()['roles'] );

		if ( array() !== $blocked ) {
			return new \WP_Error(
				'bettershield_network_role',
				sprintf(
					/* translators: %s: a comma-separated list of role names. */
					__( 'The network requires a passkey for these roles, so only a network administrator can remove them: %s.', 'bettershield' ),
					implode( ', ', $blocked )
				),
				array( 'status' => 409 )
			);
		}

		$widened = array_diff( $next['roles'], $current['roles'] );

		/*
		 * A site that cannot create or check a passkey cannot meet this
		 * requirement for anybody. The gate stands aside there, so a role
		 * named now would change nothing at sign-in while its accounts were
		 * asked, on every dashboard page, for a passkey the site cannot make.
		 * Widening is refused with the reason; narrowing stays open, because a
		 * policy saved while the site was on HTTPS has to stay removable after
		 * it moves.
		 */
		$availability = Manager::availability();

		if ( array() !== $widened && ! $availability['available'] ) {
			return new \WP_Error(
				'bettershield_passkeys_unavailable',
				trim(
					sprintf(
						/* translators: %s: why passkeys cannot be used on this site. */
						__( 'Passkeys are off on this site, so no role can be asked to use them. %s', 'bettershield' ),
						$availability['reason']
					)
				),
				array( 'status' => 409 )
			);
		}

		if ( array() !== $widened && ! RecoveryLink::usable() && ! OfflineCodes::exist() ) {
			return new \WP_Error(
				'bettershield_no_way_back',
				__( 'Passwords stop working for these roles, so first generate a new recovery link or issue recovery codes. An expired or undelivered link does not count.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return $next;
	}

	/**
	 * Whether saving this input would take protection away: a role whose
	 * accounts would sign in with a password again. Input the save would
	 * refuse takes nothing away, since nothing is written.
	 *
	 * @param array<string, mixed> $input
	 */
	public function weakens( array $input ): bool {
		$next = $this->validate( $input );

		return ! is_wp_error( $next ) && array() !== array_diff( $this->settings()['roles'], $next['roles'] );
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{roles: string[]}|\WP_Error
	 */
	public function update_settings( array $input ) {
		$current = $this->settings();
		$next    = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		// The same roles in another order are what is stored already. Saving
		// them wrote a high event, which alerts, for a change nobody made.
		if ( array() === array_diff( $current['roles'], $next['roles'] ) && array() === array_diff( $next['roles'], $current['roles'] ) ) {
			return $current;
		}

		// Before the write, so the way back exists whether or not it succeeds.
		// This is the setting that decides whether a password opens an
		// account, so arming it with no record to lift it by is the one state
		// the refusal above exists to keep a site out of.
		if ( false === SettingsLedger::record( 'passkey_policy', $current, $next ) ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		update_option( self::OPTION, $next, true );

		Writer::instance()->record(
			'passkey_policy_changed',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array( 'roles' => $next['roles'], 'weakened' => array_values( array_diff( $current['roles'], $next['roles'] ) ) ),
			)
		);

		return $next;
	}

	/* ---- who it covers --------------------------------------------------------- */

	/**
	 * Whether the policy names one of this account's roles.
	 *
	 * Read per request rather than stamped on the account, so a role granted
	 * or removed today changes the answer today.
	 */
	public function applies_to( \WP_User $user ): bool {
		/*
		 * This site's roles with the network's beneath them. A network may
		 * name a role for every site under it; a site may add to that and may
		 * never take it away, so the two lists compose rather than one
		 * replacing the other.
		 */
		$roles = NetworkPolicies::effective_passkey_roles( $this->settings()['roles'] );

		if ( array() === $roles ) {
			return false;
		}

		return array() !== array_intersect( $roles, array_map( 'strval', (array) $user->roles ) );
	}

	/**
	 * Whether the password is actually refused for this account right now.
	 *
	 * The passkey count is the whole safety property of this feature: an
	 * account with none is never refused, however many roles the policy names.
	 *
	 * Asked live rather than cached for the request, deliberately. A cache was
	 * tried and reverted: it went stale the moment somebody removed their last
	 * passkey, which is exactly the moment the password has to start working
	 * again, and the query it saved is not on the path it looked like. The
	 * lockout gate runs first and hands a WP_Error down the chain, so a
	 * credential-stuffing run is refused before this is ever reached — the
	 * count only costs a query on an attempt that already looks genuine.
	 */
	public function armed_for( \WP_User $user ): bool {
		return $this->applies_to( $user ) && Store::count_usable_for_user( (int) $user->ID ) > 0;
	}

	/**
	 * Whether this account's password is refused at sign-in on this site:
	 * the policy is armed for it, and a passkey can be created and checked
	 * here at all.
	 *
	 * A site where a passkey cannot be created or checked at all — no OpenSSL
	 * to verify a signature with, an address the browser will not offer a
	 * credential at. The whole safety argument above rests on the refused
	 * account holding a working passkey, and here it holds one that nothing
	 * on this site can use: refusing the password would leave two shut doors
	 * and the recovery link. A mechanism that cannot work where it is
	 * installed says so rather than reporting success.
	 *
	 * Asked by the gate below and by the password confirmation, which spares
	 * exactly these accounts, so the two cannot disagree about who signs in
	 * by a passkey alone.
	 *
	 * Nor where another security plugin has two-factor set up for the account:
	 * it asks for its own code after a passkey too, so the passkey never
	 * completes a sign-in here, and its password, behind that plugin's code,
	 * is the account's way in (#2465).
	 */
	public function refuses_password( \WP_User $user ): bool {
		return Manager::is_available() && $this->armed_for( $user ) && '' === \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user );
	}

	/**
	 * Whether this site refuses a session presented to it because it was
	 * opened on another site of the network, without a passkey, for an
	 * account this site holds to one.
	 *
	 * The gate below is kept at this site's sign-in form, against the roles
	 * the account holds here. On a network every site's form signs an account
	 * in, and the cookie it sets is good on every site that shares its path or
	 * its domain, so a password typed at a site that names none of the
	 * account's roles there opened this one. A session opened here, by a
	 * passkey anywhere, or recorded before sessions said where they were
	 * opened, is left as it is: refusing those would sign out somebody who
	 * just enrolled the passkey that armed the policy for them.
	 *
	 * @param array<string, mixed> $session Core's record of the session.
	 */
	public function refuses_session( \WP_User $user, array $session ): bool {
		if ( ! is_multisite() || SafeMode::is_active() ) {
			return false;
		}

		if ( true !== Sessions::opened_elsewhere( $session ) || Sessions::opened_by_passkey( $session ) ) {
			return false;
		}

		return $this->refuses_password( $user );
	}

	/**
	 * Accounts the policy is waiting on: named by a role, holding no passkey,
	 * and therefore still signing in with a password.
	 */
	public function awaiting( \WP_User $user ): bool {
		return $this->applies_to( $user ) && 0 === Store::count_usable_for_user( (int) $user->ID );
	}

	/* ---- the gate -------------------------------------------------------------- */

	/**
	 * After the password: refuse it, or leave the chain alone.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function gate( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || SafeMode::is_active() ) {
			return $user;
		}

		if ( ! $this->refuses_password( $user ) ) {
			return $user;
		}

		// The three cases no password gate owes anything, decided in one place
		// so this gate and the second-factor gate cannot come to disagree
		// about who is exempt. The first of them is what lets a real passkey
		// sign-in through: it re-runs this chain from an account it has
		// already verified, and is named by a marker rather than inferred.
		// Except a password sign-in parked for its code before this account
		// came to sign in by passkey: that is a password, finishing.
		if ( TwoFactorManager::instance()->password_path_exempt( $user, (string) $password ) && ! TwoFactorManager::instance()->finishing_a_password( (int) $user->ID ) ) {
			return $user;
		}

		// Password-only XML-RPC would walk around this the way it would walk
		// around the second factor; refuse it with the fix named.
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return new \WP_Error(
				'bettershield_passkey_only_xmlrpc',
				__( 'This account signs in with a passkey, so XML-RPC needs an application password.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		$this->record_refusal( $user );

		/*
		 * A refusal of this plugin's own, which does not count as a wrong
		 * password toward a lockout: the password was right, and locking the
		 * account for using it correctly would punish exactly the person this
		 * feature is protecting.
		 *
		 * The message says what to do instead and names the way back, because
		 * the reader of it is somebody who just typed a password they know is
		 * correct and had it refused — the one moment where an unexplained
		 * refusal reads as a broken site.
		 *
		 * The button is drawn on the sign-in page WordPress ships and nowhere
		 * else, so only there can the message point at it. A store's My
		 * Account or checkout form, or any other form, is sent to that page:
		 * the sign-in script itself, not wp_login_url(), which a plugin may
		 * point at a front-end form that draws no button either.
		 */
		/*
		 * The way back named is one this account holds. The recovery link is
		 * mailed to the site's owner and printed codes are issued to whoever
		 * manages it, so an editor told about either was pointed at nothing;
		 * an administrator can remove their passkeys, which is what restores
		 * their password. Decided by the capability, not the role: an owner
		 * under any role keeps the ways back an owner holds.
		 */
		$owner = user_can( $user, \BetterShield\Capabilities::MANAGE );

		if ( \BetterShield\TwoFactor\LoginStep::from_an_api_client() ) {
			/*
			 * A client of the API or the command line follows no link and
			 * presses no button; an application password is what works for
			 * it, as the second-factor refusal already says (#1783).
			 */
			$message = __( 'This account signs in with a passkey, so this client needs an application password.', 'bettershield' );
		} elseif ( LoginForms::is_core_sign_in_request() ) {
			$message = $owner
				? __( 'This account needs a passkey. Use the passkey button. If you cannot, use your recovery link or a recovery code.', 'bettershield' )
				: __( 'This account needs a passkey. Use the passkey button. If you cannot, ask an administrator to remove your passkeys so your password works again.', 'bettershield' );
		} else {
			$message = sprintf(
				$owner
					/* translators: %s: the address of the site's sign-in page. */
					? __( 'This account needs a passkey. Sign in on <a href="%s">the site’s sign-in page</a>. If you cannot, use your recovery link or a recovery code.', 'bettershield' )
					/* translators: %s: the address of the site's sign-in page. */
					: __( 'This account needs a passkey. Sign in on <a href="%s">the site’s sign-in page</a>. If you cannot, ask an administrator to remove your passkeys so your password works again.', 'bettershield' ),
				esc_url( site_url( 'wp-login.php', 'login' ) )
			);
		}

		return new \WP_Error( 'bettershield_passkey_only', $message, array( 'status' => 403 ) );
	}

	/**
	 * The refusal, written once per account per window and then again as one
	 * louder row when the repeats cross a threshold.
	 *
	 * A refusal on its own is the credential having leaked, which is worth
	 * knowing about — so the first one is recorded exactly as it was. But this
	 * refusal deliberately accrues to no lockout, and it is one of the types
	 * the writer keeps when everything else is shed under load, so a script
	 * working through a leaked password wrote a row per attempt into the
	 * history that must not thin. Coalesced, a flood reads as one escalation
	 * carrying how many and over how long, which is the shape the agent
	 * refusals already use.
	 */
	private function record_refusal( \WP_User $user ): void {
		$count = Claim::bump( 'pkrefuse_' . (int) $user->ID, self::REPEAT_WINDOW_MINUTES * MINUTE_IN_SECONDS );

		if ( 1 === $count ) {
			Writer::instance()->record(
				'password_refused_passkey_only',
				Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'user',
					'actor_id'    => (int) $user->ID,
					'object_type' => 'user',
					'object_id'   => (string) $user->ID,
				)
			);

			return;
		}

		/**
		 * How many refusals inside the window raise the louder event. Zero or
		 * less switches the escalation off and leaves the first refusal of each
		 * window as the only record.
		 *
		 * @param int $threshold The default, self::REPEAT_THRESHOLD.
		 */
		$threshold = (int) apply_filters( 'bettershield_passkey_refusal_threshold', self::REPEAT_THRESHOLD );

		// Exactly at the threshold, so one crossing writes one row however far
		// past it the flood goes.
		if ( $threshold < 1 || $count !== $threshold ) {
			return;
		}

		Writer::instance()->record(
			'password_refused_repeated',
			Writer::SEVERITY_HIGH,
			array(
				'actor_type'  => 'user',
				'actor_id'    => (int) $user->ID,
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array(
					'requests'       => $count,
					'window_minutes' => self::REPEAT_WINDOW_MINUTES,
				),
			)
		);
	}

	/* ---- the nudge ------------------------------------------------------------- */

	/**
	 * Told before it applies, not after.
	 *
	 * The one genuinely surprising thing about this feature is that
	 * registering a passkey is what switches the password off, so an account
	 * the policy is waiting on is told exactly that while it still has a
	 * password to sign in with.
	 *
	 * Not on a site where passkeys are off: the link would land on a card
	 * saying none can be added here, and the password would go on signing the
	 * account in whatever it did.
	 */
	public function notice(): void {
		$user = wp_get_current_user();

		if ( ! $user instanceof \WP_User || 0 === $user->ID || ! $this->awaiting( $user ) ) {
			return;
		}

		if ( ! Manager::availability()['available'] ) {
			return;
		}

		printf(
			'<div class="notice bs-notice notice-info"><p>%s</p><p><a href="%s">%s</a></p></div>',
			esc_html__( 'This site asks you to add a passkey. Once you do, your password no longer signs you in.', 'bettershield' ),
			esc_url( $this->enrollment_url() ),
			esc_html__( 'Add a passkey', 'bettershield' )
		);
	}

	/**
	 * Where this account can actually add one.
	 *
	 * The plugin's own screen needs a capability most of the roles this policy
	 * can name do not have, so `get_edit_profile_url()` was sending everybody
	 * — administrators included — to a screen that had no passkey control on
	 * it at all. The panel on the profile screen is the answer for everyone
	 * without the capability, and the anchor is what makes the link land on
	 * the control rather than at the top of a long page.
	 *
	 * The same branch `TwoFactor\Policy::enrollment_url()` takes, for the same
	 * reason.
	 */
	public function enrollment_url(): string {
		if ( current_user_can( \BetterShield\Capabilities::MANAGE ) ) {
			return admin_url( 'admin.php?page=bettershield-protect&tab=two-factor#bettershield-passkeys' );
		}

		return \BetterShield\Login\AccountPage::front_end_url( wp_get_current_user(), 'bettershield-passkeys' ) ?? admin_url( 'profile.php#bettershield-passkeys' );
	}
}
