<?php
/**
 * Requiring the second factor of a role, without ever locking anybody out.
 *
 * Two-factor here has always been self-serve: an account has it because
 * somebody chose to turn it on. That is the right default and it is not a
 * policy — an agency running a client site cannot ask for the one thing that
 * would most reduce its risk, which is that the editors actually use it.
 *
 * **The enforcement point is deliberately not the sign-in.** The obvious
 * implementation parks the sign-in at an enrollment screen, and it is what the
 * request asked for. It is also a new way to be locked out of your own site,
 * added to the plugin whose first principle is that the owner can always get
 * back in. So the password still signs you in, and what the policy withholds
 * is the *admin screens*: an account past its grace window lands on the
 * enrollment screen and on no other.
 *
 * **What stays open is as deliberate as what is withheld.** Its own profile
 * screen — where its password, its second factor and its signed-in devices are
 * — `admin-post.php`, `admin-ajax.php`, the REST API and the whole front end
 * all keep working. This is a nudge with teeth, not a fence: a version that
 * fenced those would break the front end for exactly the accounts it
 * restricts, and would be the lockout the paragraph above rules out.
 *
 * The difference matters in every failure mode. A bug here is an
 * administrator looking at an enrollment form they can complete, not one
 * staring at a sign-in page that refuses them. The recovery link, safe mode
 * and every front-end path are untouched, and no session is ever refused.
 *
 * **Grace is counted from when the account first met the policy**, not from
 * when it was created. Switching this on gives everybody the full window from
 * that moment, including accounts that have existed for years — which is what
 * makes it safe for an owner to try.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Events\Writer;
use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Recovery\SafeMode;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy {

	public const OPTION = 'bettershield_two_factor_policy';

	/** When this account first met the policy, as a Unix timestamp. */
	private const META_SINCE = 'bettershield_2fa_required_since';

	/**
	 * When each role on this site's list was last added to it, by role.
	 *
	 * An account's clock starts the first time the policy sees it, and it was
	 * kept through the end of that spell of the requirement. Required again,
	 * the account was overdue at once, with none of the window the screen
	 * promises. A clock older than the spell its account is covered by now
	 * belongs to an earlier one, and starts again.
	 */
	public const ROLES_SINCE = 'bettershield_two_factor_roles_since';

	/**
	 * The key that holds this account's clock for the site it is on.
	 *
	 * The policy is a per-site option and its grace window is a per-site
	 * promise, but the clock was one network-global value written once and
	 * never reset. So a second subsite switching the policy on judged its
	 * members against the clock the *first* one started — usually long past —
	 * and redirected them to enrollment with none of the window the feature
	 * says they get, on a site whose policy was new to them that morning.
	 *
	 * Scoped per site on a network, so each subsite's window runs from the
	 * first time that subsite saw the account. The plain key stays on a single
	 * site, where there is exactly one policy and nothing to tell apart, so no
	 * existing clock is disturbed.
	 *
	 * This is not enforcement reaching across a network — it is the opposite.
	 * It is what stops one site's policy deciding another site's deadline.
	 */
	private function since_key(): string {
		return is_multisite() ? self::META_SINCE . '_' . get_current_blog_id() : self::META_SINCE;
	}

	/**
	 * Forget one account's clock on this site.
	 *
	 * A stored judgment about a person, and the value that decides their
	 * deadline — so an erasure takes it, and a fresh one starts from the next
	 * time this site sees them rather than from a date they can no longer see.
	 */
	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::instance()->since_key() );
	}

	/** Not required · inside the grace window · owed now. */
	public const NOT_REQUIRED = 'not_required';
	public const IN_GRACE     = 'in_grace';
	public const OVERDUE      = 'overdue';

	private static ?Policy $instance = null;

	public static function instance(): Policy {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Late, so anything that legitimately redirects earlier still wins,
		// and so the capability map is in place.
		add_action( 'admin_init', array( $this, 'enforce' ), 20 );
		add_action( 'admin_notices', array( $this, 'countdown' ) );

		// Every way the list is written, undo and import included, so a role
		// added by any of them starts its spell.
		add_action( 'add_option_' . self::OPTION, array( $this, 'list_added' ), 10, 2 );
		add_action( 'update_option_' . self::OPTION, array( $this, 'list_changed' ), 10, 2 );
		add_action( 'delete_option_' . self::OPTION, array( $this, 'list_deleted' ) );

		// And the network's list, which a site's own roles-since cannot see.
		add_action( 'add_site_option_' . NetworkPolicies::OPTION_TWO_FACTOR, array( NetworkPolicies::class, 'two_factor_list_added' ), 10, 2 );
		add_action( 'update_site_option_' . NetworkPolicies::OPTION_TWO_FACTOR, array( NetworkPolicies::class, 'two_factor_list_changed' ), 10, 3 );
		add_action( 'delete_site_option_' . NetworkPolicies::OPTION_TWO_FACTOR, array( NetworkPolicies::class, 'two_factor_list_deleted' ) );

		// An account that leaves the covered roles leaves its clock behind.
		// set_user_role fires only when the whole set is replaced, so a role
		// taken away on its own is listened for too.
		add_action( 'set_user_role', array( $this, 'role_moved' ) );
		add_action( 'remove_user_role', array( $this, 'role_moved' ) );

		add_filter( 'bettershield_two_factor_self_disable_allowed', array( $this, 'may_self_disable' ), 10, 2 );
	}

	/**
	 * Whether a covered account may turn its own second factor off.
	 *
	 * Only an add-on answered this, so with this plugin alone a required
	 * account could switch two-factor off with a code of its own, and the
	 * dashboard then gave it the whole grace window again, since an enrolled
	 * account never starts its clock. What the role requires is kept, and
	 * an administrator's disable for the account is not asked.
	 *
	 * @param mixed $allowed
	 * @param mixed $user
	 * @return mixed
	 */
	public function may_self_disable( $allowed, $user ) {
		if ( ! $user instanceof \WP_User || SafeMode::is_active() ) {
			return $allowed;
		}

		$roles = NetworkPolicies::effective_two_factor_roles( $this->settings()['roles'] );

		if ( array() !== array_intersect( (array) $user->roles, $roles ) ) {
			return false;
		}

		return is_multisite() && $this->required_elsewhere( $user ) ? false : $allowed;
	}

	/**
	 * Whether another site of this network requires a second factor of the
	 * account. The factor is one for the account and turning it off removes
	 * it everywhere, while the roles above are this site's: an editor where
	 * editors are covered turned it off from a site where they were a
	 * subscriber, and the covering site then gave a fresh grace window.
	 */
	private function required_elsewhere( \WP_User $user ): bool {
		$here    = (int) get_current_blog_id();
		$network = (int) get_current_network_id();

		foreach ( get_blogs_of_user( (int) $user->ID ) as $site_id => $site ) {
			if ( (int) $site_id === $here || (int) ( $site->site_id ?? $network ) !== $network ) {
				continue;
			}

			switch_to_blog( (int) $site_id );

			try {
				$covered = NetworkPolicies::effective_two_factor_roles( $this->settings()['roles'] );
				$there   = ( new \WP_User( (int) $user->ID, '', (int) $site_id ) )->roles;

				if ( array() !== array_intersect( (array) $there, $covered ) ) {
					return true;
				}
			} finally {
				restore_current_blog();
			}
		}

		return false;
	}

	/**
	 * @param mixed $option
	 * @param mixed $value
	 */
	public function list_added( $option, $value ): void {
		$this->list_changed( array(), $value );
	}

	/**
	 * Start the spell of each role the list gained, and forget the roles it
	 * lost.
	 *
	 * @param mixed $old
	 * @param mixed $value
	 */
	public function list_changed( $old, $value ): void {
		$before  = is_array( $old ) ? array_map( 'strval', (array) ( $old['roles'] ?? array() ) ) : array();
		$after   = is_array( $value ) ? array_map( 'strval', (array) ( $value['roles'] ?? array() ) ) : array();
		$since   = $this->roles_since();
		$network = NetworkPolicies::two_factor()['roles'];
		$started = NetworkPolicies::two_factor_roles_since();

		foreach ( array_diff( $after, $before ) as $role ) {
			/*
			 * A role the network already requires was never uncovered, so
			 * adding it here starts no new spell: it carries the network's
			 * start. Stamped with the time, a site administrator could add the
			 * role, or take it off and add it back, to give every overdue
			 * account the whole window again.
			 */
			$since[ $role ] = in_array( $role, $network, true ) ? ( $started[ $role ] ?? 0 ) : time();
		}

		update_option( self::ROLES_SINCE, array_intersect_key( $since, array_flip( $after ) ), false );
	}

	public function list_deleted(): void {
		delete_option( self::ROLES_SINCE );
	}

	/**
	 * @return array<string, int>
	 */
	private function roles_since(): array {
		$stored = get_option( self::ROLES_SINCE, array() );

		return is_array( $stored ) ? array_map( 'intval', $stored ) : array();
	}

	/**
	 * When the spell of the requirement this account is under began: the
	 * earliest start among its covered roles. A role's start is the earlier
	 * of the lists that require it now, this site's and the network's, each
	 * from when the role joined it. A role a list has no start for has been
	 * on it for as long as anybody knows, which is zero.
	 *
	 * @param string[] $roles The roles required here.
	 */
	private function spell_began( \WP_User $user, array $roles ): int {
		$since   = $this->roles_since();
		$network = NetworkPolicies::two_factor_roles_since();
		$own     = array_map( 'strval', $this->settings()['roles'] );
		$net     = NetworkPolicies::two_factor()['roles'];
		$began   = null;

		foreach ( array_intersect( (array) $user->roles, $roles ) as $role ) {
			$starts = array();

			if ( in_array( $role, $own, true ) ) {
				$starts[] = $since[ $role ] ?? 0;
			}

			if ( in_array( $role, $net, true ) ) {
				$starts[] = $network[ $role ] ?? 0;
			}

			$start = array() === $starts ? 0 : min( $starts );
			$began = null === $began ? $start : min( $began, $start );
		}

		return (int) $began;
	}

	/**
	 * Forget the clock of an account that no longer holds a covered role, so
	 * coming back to one is a fresh window rather than an old deadline.
	 *
	 * @param mixed $user_id
	 */
	public function role_moved( $user_id ): void {
		$user = get_userdata( (int) $user_id );

		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$roles = NetworkPolicies::effective_two_factor_roles( $this->settings()['roles'] );

		if ( array() === array_intersect( (array) $user->roles, $roles ) ) {
			self::forget( (int) $user->ID );
		}
	}

	/**
	 * @return array{roles: string[], grace_days: int, store_tab: bool, account_page: int}
	 */
	public function settings(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'roles'        => array_values( array_filter( array_map( 'strval', (array) ( $stored['roles'] ?? array() ) ) ) ),
			// Long enough that somebody on holiday is not shut out of their own
			// dashboard on their first day back.
			'grace_days'   => max( 0, min( 90, (int) ( $stored['grace_days'] ?? 14 ) ) ),
			// Whether a store's My Account page offers the Sign-in security
			// tab to accounts nothing asks it of. On until an owner says not.
			'store_tab'    => false !== ( $stored['store_tab'] ?? true ),
			// The page members kept out of wp-admin set this up on; 0 is none.
			'account_page' => max( 0, (int) ( $stored['account_page'] ?? 0 ) ),
		);
	}

	/**
	 * What this input would become, or the refusal it earns.
	 *
	 * Separate from the write so a dry run can ask the same question the save
	 * will: a settings import plans every section through its own validator,
	 * and a section without one could only be planned by guessing.
	 *
	 * @param array<string, mixed> $input
	 * @return array{roles: string[], grace_days: int, store_tab: bool, account_page: int}|\WP_Error
	 */
	public function validate( array $input ) {
		$current = $this->settings();
		$roles   = isset( $input['roles'] ) ? (array) $input['roles'] : $current['roles'];
		$known   = array_keys( wp_roles()->roles );

		foreach ( $roles as $role ) {
			// A list or an object is no role name, and casting one is a PHP
			// warning before the refusal.
			if ( ! is_scalar( $role ) || ! in_array( (string) $role, $known, true ) ) {
				return new \WP_Error( 'bettershield_unknown_role', __( 'That is not a role on this site.', 'bettershield' ), array( 'status' => 400 ) );
			}
		}

		// An empty or non-numeric value is refused rather than cast: (int) ''
		// is 0, and a grace of zero sends every covered account without a
		// second factor to enrollment on its next admin page.
		if ( isset( $input['grace_days'] ) && ! is_numeric( $input['grace_days'] ) ) {
			return new \WP_Error( 'bettershield_bad_grace', __( 'The grace period needs to be between 0 and 90 days.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$days = isset( $input['grace_days'] ) ? (int) $input['grace_days'] : $current['grace_days'];

		if ( $days < 0 || $days > 90 ) {
			return new \WP_Error( 'bettershield_bad_grace', __( 'The grace period needs to be between 0 and 90 days.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$next = array_values( array_unique( array_map( 'strval', $roles ) ) );

		/*
		 * A role the network requires cannot be unchecked here. It would still
		 * be required — the network's list sits beneath this one — and the
		 * screen would show a role missing from a site that goes on enforcing
		 * it. Refusing says where the requirement was set, which is the one
		 * thing an administrator looking at a checkbox that will not stay off
		 * needs to know.
		 */
		$blocked = NetworkPolicies::network_roles_removed( $current['roles'], $next, NetworkPolicies::two_factor()['roles'] );

		if ( array() !== $blocked ) {
			return new \WP_Error(
				'bettershield_network_role',
				sprintf(
					/* translators: %s: a comma-separated list of role names. */
					__( 'The network requires two-factor for these roles, so only a network administrator can remove them: %s.', 'bettershield' ),
					implode( ', ', $blocked )
				),
				array( 'status' => 409 )
			);
		}

		if ( isset( $input['store_tab'] ) && ! is_scalar( $input['store_tab'] ) ) {
			return new \WP_Error( 'bettershield_bad_store_tab', __( 'The My Account setting needs to be on or off.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$page = $input['account_page'] ?? $current['account_page'];

		if ( ! is_numeric( $page ) || ( 0 !== (int) $page && $page !== $current['account_page'] && ! \BetterShield\Login\AccountPage::usable( get_post( (int) $page ) ) ) ) {
			return new \WP_Error( 'bettershield_bad_account_page', __( 'Choose a published page that needs no password.', 'bettershield' ), array( 'status' => 400 ) );
		}

		return array(
			'roles'        => $next,
			'grace_days'   => $days,
			'store_tab'    => isset( $input['store_tab'] ) ? rest_sanitize_boolean( $input['store_tab'] ) : $current['store_tab'],
			'account_page' => (int) $page,
		);
	}

	/**
	 * Whether saving this input would take protection away: a role no longer
	 * required, or a longer wait before an account without a second factor is
	 * sent to enrollment. Input the save would refuse takes nothing away,
	 * since nothing is written.
	 *
	 * @param array<string, mixed> $input
	 */
	public function weakens( array $input ): bool {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return false;
		}

		$current = $this->settings();

		return array() !== array_diff( $current['roles'], $next['roles'] ) || $next['grace_days'] > $current['grace_days'];
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{roles: string[], grace_days: int, store_tab: bool, account_page: int}|\WP_Error
	 */
	public function update_settings( array $input ) {
		$current = $this->settings();
		$next    = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		// The same roles in another order and the same window are what is
		// stored already: no undo row, no write and no event for nothing.
		$same_requirement = array() === array_diff( $current['roles'], $next['roles'] ) && array() === array_diff( $next['roles'], $current['roles'] ) && $current['grace_days'] === $next['grace_days'];

		if ( $same_requirement && $current['store_tab'] === $next['store_tab'] && $current['account_page'] === $next['account_page'] ) {
			return $current;
		}

		// Before the write, so the way back exists whether or not it succeeds.
		// A prior state that could not be recorded is a change with no way
		// back, and this one decides whether accounts keep their dashboards.
		if ( false === SettingsLedger::record( 'two_factor_policy', $current, $next ) ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		update_option( self::OPTION, $next, false );

		// What a menu shows is not what the site requires, and the requirement's
		// own row feeds the incident engine.
		if ( $current['store_tab'] !== $next['store_tab'] ) {
			Writer::instance()->record(
				'setting_changed',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'setting',
					'object_id'   => 'bettershield_store_account_tab',
					'context'     => array( 'enabled' => $next['store_tab'] ),
				)
			);
		}

		if ( $current['account_page'] !== $next['account_page'] ) {
			Writer::instance()->record(
				'setting_changed',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'setting',
					'object_id'   => 'bettershield_account_page',
					'context'     => array( 'enabled' => $next['account_page'] > 0 ),
				)
			);
		}

		if ( $same_requirement ) {
			return $next;
		}

		/*
		 * A row that reads the same whether the requirement was extended or
		 * taken away answers none of the questions it is kept for. The changes
		 * that leave an account without a second factor are named, and the row
		 * carries the severity of the weakest thing in it — removing the
		 * requirement from every administrator cannot be quieter than removing
		 * it from one of them.
		 *
		 * Roles are compared by identity rather than by count: swapping the
		 * administrators for the editors covers the same number of roles and
		 * leaves the administrators with nothing required of them.
		 */
		$weakened = array();

		if ( array() !== array_diff( $current['roles'], $next['roles'] ) ) {
			$weakened[] = 'roles no longer required';
		}

		if ( $next['grace_days'] > $current['grace_days'] ) {
			$weakened[] = 'grace period lengthened';
		}

		Writer::instance()->record(
			'two_factor_policy_changed',
			array() === $weakened ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'policy',
				'context'     => array(
					'roles'      => $next['roles'],
					'grace_days' => $next['grace_days'],
					'weakened'   => $weakened,
				),
			)
		);

		return $next;
	}

	/**
	 * Whether this account is covered, and if so how long it has. Asked for
	 * a page the account is looking at, so meeting it starts its clock.
	 *
	 * @return array{status: string, due_at: ?int, days_left: ?int}
	 */
	public function state_for( \WP_User $user ): array {
		return $this->state( $user, true );
	}

	/**
	 * The same answer, read without starting a clock.
	 *
	 * For a reader nobody is in front of: a task walking a role must not be
	 * what starts the window of people it has told nothing. An account this
	 * site has not met yet reads as not required here, because it has no
	 * deadline yet.
	 *
	 * @return array{status: string, due_at: ?int, days_left: ?int}
	 */
	public function peek( \WP_User $user ): array {
		return $this->state( $user, false );
	}

	/**
	 * @param bool $start_clock Whether meeting the account starts its clock.
	 * @return array{status: string, due_at: ?int, days_left: ?int}
	 */
	private function state( \WP_User $user, bool $start_clock ): array {
		/*
		 * Asked two or three times in one admin request — enforce() on
		 * admin_init, countdown() on admin_notices, and the profile panel — and
		 * deliberately not memoized for it. Everything underneath already sits
		 * in WordPress's own request caches: safe mode is an autoloaded option,
		 * the settings are one option read cached after the first, and both
		 * user meta reads are cached too. So a memo would save arithmetic and
		 * no queries, while introducing an answer that can be wrong within a
		 * request — this is the state that changes the moment somebody
		 * enrolls, which is exactly when the next caller must see the new one.
		 * The same cache was tried on the passkey policy's `armed_for()` and
		 * reverted for the same reason.
		 */
		$none = array(
			'status'    => self::NOT_REQUIRED,
			'due_at'    => null,
			'days_left' => null,
		);

		/*
		 * Safe mode answers here rather than at the enforcement point, so that
		 * everything reading this state — the countdown, the screens, whatever
		 * asks next — agrees that nothing is being required right now. A guard
		 * that lives only at the point of use is a guard the next caller does
		 * not get, which is how the sign-in routes ended up with five holes.
		 */
		if ( SafeMode::is_active() ) {
			return $none;
		}

		$settings = $this->settings();

		/*
		 * What this site enforces is its own answer with the network's beneath
		 * it: the roles are both lists together, and the window is the shorter
		 * of the two where a network set one. A site may add to what is
		 * required of it and may never take the network's part away.
		 *
		 * The clock is not composed, and that is the point of leaving it here:
		 * `since_key()` runs each site's window from the first time that site
		 * saw the account, so a policy set for a whole network still gives
		 * every site's members their full window on the site they are on.
		 */
		$roles = NetworkPolicies::effective_two_factor_roles( $settings['roles'] );
		$grace = NetworkPolicies::effective_grace( $settings['grace_days'] );

		if ( array() === $roles || array() === array_intersect( (array) $user->roles, $roles ) ) {
			return $none;
		}

		// Already done, and nothing more is owed.
		if ( Manager::instance()->enabled( (int) $user->ID ) ) {
			return $none;
		}

		$key   = $this->since_key();
		$since = (int) get_user_meta( $user->ID, $key, true );

		// A clock from an earlier spell of the requirement is not this one's.
		if ( 0 !== $since && $since < $this->spell_began( $user, $roles ) ) {
			$since = 0;
		}

		if ( 0 === $since ) {
			// Not met yet, and this reader may not be the one to meet it:
			// there is no deadline until a page the account sees asks.
			if ( ! $start_clock ) {
				return $none;
			}

			// First sight. The clock starts now rather than at account
			// creation, so switching the policy on does not immediately shut
			// out everybody who was already here.
			$since = time();
			update_user_meta( $user->ID, $key, $since );
		}

		$due       = $since + ( $grace * DAY_IN_SECONDS );
		$remaining = $due - time();

		return array(
			'status'    => $remaining > 0 ? self::IN_GRACE : self::OVERDUE,
			'due_at'    => $due,
			'days_left' => $remaining > 0 ? (int) ceil( $remaining / DAY_IN_SECONDS ) : 0,
		);
	}

	/**
	 * Send an overdue account to the enrollment screen, and nowhere else.
	 */
	public function enforce(): void {
		if ( ! is_user_logged_in() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$user = wp_get_current_user();

		if ( self::OVERDUE !== $this->state_for( $user )['status'] ) {
			return;
		}

		if ( $this->is_enrollment_screen() || $this->is_always_reachable() ) {
			return;
		}

		wp_safe_redirect( $this->enrollment_url() );
		exit;
	}

	/**
	 * The countdown, on every admin page, while the window is still open.
	 */
	public function countdown(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$state = $this->state_for( wp_get_current_user() );

		if ( self::IN_GRACE !== $state['status'] || $this->is_enrollment_screen() ) {
			return;
		}

		printf(
			'<div class="notice bs-notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
			esc_html(
				sprintf(
					/* translators: %d: number of days. */
					_n(
						'Set up two-factor sign-in within %d day to keep using the dashboard.',
						'Set up two-factor sign-in within %d days to keep using the dashboard.',
						(int) $state['days_left'],
						'bettershield'
					),
					(int) $state['days_left']
				)
			),
			esc_url( $this->enrollment_url() ),
			esc_html__( 'Set it up now', 'bettershield' )
		);
	}

	/**
	 * Where this account can actually enroll. The plugin's own screen needs a
	 * capability most policy targets lack — sending an editor there is a
	 * "you are not allowed" wall with no way to comply. Everyone else gets
	 * the panel on their own profile screen, which needs nothing beyond
	 * being signed in and is already on the always-reachable list.
	 */
	public function enrollment_url(): string {
		return $this->enrollment_url_for( wp_get_current_user() );
	}

	/**
	 * The same place for a given account, for a message written to it from a
	 * request it is not signed in to.
	 */
	public function enrollment_url_for( \WP_User $user ): string {
		if ( user_can( $user, \BetterShield\Capabilities::MANAGE ) ) {
			return admin_url( 'admin.php?page=bettershield-protect&tab=two-factor' );
		}

		// An account kept out of wp-admin never reaches profile.php; its own
		// sign-in settings are on My Account or the page the owner chose.
		return \BetterShield\Login\AccountPage::front_end_url( $user, 'bettershield-two-factor' ) ?? admin_url( 'profile.php#bettershield-two-factor' );
	}

	/**
	 * The window this site gives before a covered account is sent to
	 * enrollment, with the network's beneath it: what a deadline is counted
	 * with.
	 */
	public function grace_days(): int {
		return NetworkPolicies::effective_grace( $this->settings()['grace_days'] );
	}

	/**
	 * When each clock on this site started, for the covered accounts whose
	 * clock started inside a span: oldest first, and at most a page of them.
	 * Read under this site's own key, so another site's clocks are not.
	 *
	 * @param int $after   Clocks that started after this moment…
	 * @param int $through …and no later than this one.
	 * @param int $limit   The most to read.
	 * @return array<int, int> When each clock started, by account id.
	 */
	public function clocks_started_between( int $after, int $through, int $limit ): array {
		$roles = NetworkPolicies::effective_two_factor_roles( $this->settings()['roles'] );

		if ( array() === $roles || $through <= $after || $limit < 1 ) {
			return array();
		}

		$query = new \WP_User_Query(
			array(
				'number'      => $limit,
				'fields'      => 'ids',
				'count_total' => false,
				'role__in'    => $roles,
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- a daily task's bounded page, never a front-end request.
				'meta_query'  => array(
					'clock' => array(
						'key'     => $this->since_key(),
						'value'   => array( $after + 1, $through ),
						'compare' => 'BETWEEN',
						'type'    => 'NUMERIC',
					),
				),
				'orderby'     => 'clock',
				'order'       => 'ASC',
			)
		);

		$ids = array_map( 'intval', (array) $query->get_results() );

		// One read for the page's accounts and their meta together.
		if ( array() !== $ids ) {
			cache_users( $ids );
		}

		$clocks = array();

		foreach ( $ids as $id ) {
			$clocks[ $id ] = (int) get_user_meta( $id, $this->since_key(), true );
		}

		return $clocks;
	}

	private function is_enrollment_screen(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen is being drawn, never acting on it.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';

		return 'bettershield-protect' === $page;
	}

	/**
	 * Screens an account must keep whatever else is withheld.
	 *
	 * Signing out has to work — an account that cannot enroll and cannot leave
	 * is trapped — and so do the endpoints the enrollment screen itself calls.
	 * `profile.php` is where the enrollment panel lives for every role without
	 * this plugin's capability, so withholding it would withhold the only place
	 * the policy can be complied with.
	 *
	 * This list covers the admin screens and nothing else, which is the whole
	 * of what this policy reaches: the REST API and the front end are out of
	 * scope by design and are never consulted here. See the class docblock for
	 * why extending it to them would be the lockout this design avoids.
	 */
	private function is_always_reachable(): bool {
		global $pagenow;

		// `admin-ajax.php` is already answered by the wp_doing_ajax() guard
		// above; named here so the list reads as what it is — the screens this
		// may never withhold — rather than as whatever happens to be left over.
		if ( in_array( (string) $pagenow, array( 'admin-post.php', 'admin-ajax.php', 'profile.php' ), true ) ) {
			return true;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading the action being performed, never acting on it.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( (string) $_REQUEST['action'] ) ) : '';

		return 'logout' === $action;
	}
}
