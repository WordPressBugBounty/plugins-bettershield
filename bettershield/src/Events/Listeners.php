<?php
/**
 * Site activity capture.
 *
 * The single place that owns the mapping from a WordPress hook to an activity
 * event. Everything here is a listener: it observes, records through the
 * buffered writer, and changes nothing. No listener may alter a value it is
 * passed, and none may perform a query of its own on a front-end request.
 *
 * What is deliberately never recorded: password hashes, reset keys, nonces,
 * option values, or anything else whose disclosure would make the log itself
 * worth stealing. Events name what changed and who changed it. The value is
 * visible in the site's own settings to anyone entitled to see it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Listeners {

	/**
	 * The settings a takeover changes first, named once: the event they are
	 * recorded under, how loud it is, and the hardening item that keeps them
	 * to administrators all read this list.
	 */
	public const TAKEOVER_SETTINGS = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role' );


	/*
	 * A singleton for the same reason the writer is one: WordPress deduplicates
	 * identical callbacks by object identity, so one shared instance makes a
	 * second register() harmless. Two instances would each attach, and every
	 * event would be recorded twice.
	 */
	private static ?Listeners $instance = null;

	/**
	 * The file the theme or plugin editor is saving on this request, and its
	 * hash before core wrote it; see note_editor_save().
	 *
	 * @var array{type: string, id: string, file: string, name: string, path: string, hash: string}|null
	 */
	private ?array $editor_save = null;

	/** Whether core is granting or revoking a super admin right now; see note_super_admin_change(). */
	private bool $super_admin_changing = false;

	/**
	 * What the role map went through on this request, per site, until the
	 * writer drains: the map before the first change, the one after the
	 * last, and every grant and revocation on the way, so a capability
	 * granted and taken back again is still said.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $roles_pending = array();

	/**
	 * The plugins activated on this request, which is what usually rewrites
	 * the role map.
	 *
	 * @var string[]
	 */
	private array $activating = array();

	public static function instance(): Listeners {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Options worth an event, and nothing else.
	 *
	 * An unfiltered `updated_option` listener is both a performance fault and a
	 * noise fault: WordPress writes options constantly — transients, cron, rate
	 * limiters — and almost none of that describes a site changing. These are
	 * the ones that do.
	 *
	 * @return string[]
	 */
	public static function watched_options(): array {
		global $wpdb;

		return array(
			'siteurl',
			'home',
			'admin_email',
			'users_can_register',
			'default_role',
			'permalink_structure',
			'blog_public',
			/*
			 * What each role is allowed to do, which is a different question
			 * from which role an account holds. Granting `manage_options` to
			 * subscriber escalates every subscriber at once and touches no
			 * user record at all, so the per-user listeners cannot see it.
			 *
			 * The name carries the table prefix, so it is read rather than
			 * written out: on a site with a non-default prefix a literal
			 * `wp_user_roles` would watch an option that does not exist.
			 */
			$wpdb->get_blog_prefix() . 'user_roles',
		);
	}

	public function register(): void {
		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_logout', array( $this, 'on_logout' ), 10, 1 );
		add_action( 'retrieve_password', array( $this, 'on_password_reset_requested' ), 10, 1 );

		// Before the row exists, so the role hooks core fires during creation
		// can be told apart from the same hooks on an account that already
		// exists. Cleared on `user_register`, which core fires afterwards.
		add_filter( 'wp_pre_insert_user_data', array( $this, 'note_account_creation' ), 10, 2 );
		add_action( 'user_register', array( $this, 'on_user_register' ), 10, 1 );
		add_action( 'deleted_user', array( $this, 'on_user_deleted' ), 10, 3 );
		/*
		 * On a network, taking somebody off a site is what deleting an account
		 * looks like from that site: their permissions here are gone, and
		 * nothing said so or cleared what this plugin kept about them here.
		 * Core deletes nothing on this path — `wp_delete_user()` removes a
		 * membership rather than an account — so a site that let a contractor
		 * go kept that person's two-factor clock, their parked sign-in and
		 * their reading position for as long as the site existed.
		 */
		add_action( 'remove_user_from_blog', array( $this, 'on_user_removed_from_site' ), 10, 3 );
		add_action( 'set_user_role', array( $this, 'on_role_changed' ), 10, 3 );
		// set_user_role fires only when the whole set is replaced. A role added
		// alongside existing ones — the shape privilege escalation usually
		// takes — arrives on these two instead.
		add_action( 'add_user_role', array( $this, 'on_role_added' ), 10, 2 );
		add_action( 'remove_user_role', array( $this, 'on_role_removed' ), 10, 2 );
		// The highest privilege a network has, and neither hook was listened
		// to at all: a super admin can reach every site on the network, so a
		// grant here outranks any per-site role change beside it.
		add_action( 'granted_super_admin', array( $this, 'on_super_admin_granted' ), 10, 1 );
		add_action( 'revoked_super_admin', array( $this, 'on_super_admin_revoked' ), 10, 1 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ), 10, 1 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 3 );

		// The credential agents and connected tools actually authenticate
		// with. Its creation is the moment access is granted.
		add_action( 'wp_create_application_password', array( $this, 'on_app_password_created' ), 10, 4 );
		add_action( 'wp_delete_application_password', array( $this, 'on_app_password_deleted' ), 10, 2 );
		add_action( 'application_password_did_authenticate', array( $this, 'on_app_password_used' ), 10, 2 );
		/*
		 * XML-RPC being used at all, which nothing recorded. That absence is
		 * why the hardening preview for it could say nothing about whether
		 * turning it off would break anything — the one item with no
		 * capability holders to count, and therefore the one where evidence is
		 * the only possible answer. Throttled the way application-password use
		 * is: this is traffic, and a Jetpack sync or an app polling produces it
		 * in bursts.
		 */
		add_action( 'xmlrpc_call', array( $this, 'on_xmlrpc_used' ), 10, 1 );

		add_action( 'activate_plugin', array( $this, 'note_activating' ), 10, 1 );
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 2 );
		// What a role may do, said once per request rather than once per
		// add_cap() (#2080).
		add_action( 'bettershield_events_before_flush', array( $this, 'record_role_changes' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 1 );
		// Its name read while its files are still there (#2120).
		add_action( 'delete_plugin', array( $this, 'before_plugin_deleted' ), 10, 1 );
		add_action( 'deleted_plugin', array( $this, 'on_plugin_deleted' ), 10, 2 );
		// What was installed before a run, so a package laid over a plugin is
		// recorded as the update it is, with the versions it moved between (#2344).
		add_filter( 'upgrader_pre_download', array( $this, 'on_upgrade_run' ), 10, 3 );
		add_filter( 'upgrader_pre_install', array( $this, 'before_upgrade' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrade_complete' ), 10, 2 );

		add_action( 'switch_theme', array( $this, 'on_theme_changed' ), 10, 1 );
		add_action( 'deleted_theme', array( $this, 'on_theme_deleted' ), 10, 2 );

		// A save in the theme or plugin file editor, which fires no hook of
		// its own: the file is read as the request starts and again as it
		// ends, before the writer flushes (#1974).
		add_action( 'admin_init', array( $this, 'note_editor_save' ) );

		// Core's own upgrade path does not go through the upgrader hook with a
		// type we can read, so it has its own.
		add_action( '_core_updated_successfully', array( $this, 'on_core_updated' ), 10, 1 );

		add_action( 'updated_option', array( $this, 'on_option_updated' ), 10, 3 );
		/*
		 * A watched setting written where there was none. Neither hook covers
		 * the other: core routes an update whose current value reads as absent
		 * through `add_option()`, which fires only this one. On a network that
		 * is the ordinary case for the registration switch — core answers it
		 * from the network's own option and never reads the site row — so the
		 * one setting on this list that decides whether strangers may open
		 * accounts was changing there with nothing recorded.
		 */
		add_action( 'added_option', array( $this, 'on_option_added' ), 10, 2 );

		/*
		 * On a network the switches a takeover reaches for first are the
		 * network's own: whether strangers may register (the site's
		 * `users_can_register` governs nothing there), where network notices
		 * go, and whether site administrators may add accounts. Written
		 * through the network-option API, which neither hook above hears; core
		 * announces those writes under the old "site option" names.
		 */
		if ( is_multisite() ) {
			add_action( 'update_site_option', array( $this, 'on_network_option_updated' ), 10, 3 );
			add_action( 'add_site_option', array( $this, 'on_network_option_added' ), 10, 2 );
			// The super-admin list is written inside these two, between hooks
			// that record the grant themselves.
			add_action( 'grant_super_admin', array( $this, 'note_super_admin_change' ) );
			add_action( 'revoke_super_admin', array( $this, 'note_super_admin_change' ) );
			// The network's sites themselves: one deleted, and one archived,
			// deactivated, marked as spam or mature, or hidden from search
			// engines. A site's creation is recorded where it is provisioned
			// (`Plugin`, #2184), so the three together are its history (#1975).
			add_action( 'wp_update_site', array( $this, 'on_site_updated' ), 10, 2 );
			add_action( 'wp_delete_site', array( $this, 'on_site_deleted' ), 10, 1 );
		}
	}

	/* ---- authentication -------------------------------------------- */

	/**
	 * @param mixed $user WP_User for the account that signed in.
	 */
	public function on_login( string $user_login, $user = null ): void {
		Writer::instance()->record(
			'login',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => $user instanceof \WP_User ? (int) $user->ID : null,
				'actor_label' => $user_login,
				'object_type' => 'user',
				'object_id'   => $user instanceof \WP_User ? (string) $user->ID : null,
			)
		);
	}

	/**
	 * The attempted name is the field that makes this record useful: it is what
	 * separates one person mistyping their own password from a list of names
	 * being worked through. It is a login identifier, never a credential.
	 */
	public function on_login_failed( string $username ): void {
		/**
		 * Filters how long failed sign-ins from one source are coalesced into
		 * one logged event.
		 *
		 * @param int $seconds Window length in seconds.
		 */
		$window = (int) apply_filters( 'bettershield_login_failure_window', 5 * MINUTE_IN_SECONDS );

		/*
		 * Keyed per source, so a flood from one address cannot hide a single
		 * quiet attempt from another — which is the failure mode a global
		 * window would introduce while fixing the row count.
		 *
		 * A lockout stops the sign-in but never stopped the logging, and from an
		 * address the lockout deliberately never blocks — an unconfident one,
		 * which is now the correct answer more often — every attempt wrote a
		 * row. Anyone could grow the table from outside, inside the retention
		 * window, and a log too big to read is a log that failed.
		 */
		$resolved = ClientIp::resolve( \BetterShield\Login\Protection::trusted_proxies(), \BetterShield\Login\Protection::cloudflare() );
		// Keyed on the connection the failures arrived on: under an edge the
		// owner has not vouched for, the claimed address is the request's to
		// choose, and a window keyed on it coalesces nothing.
		$key = 'bettershield_lfail_' . md5( ClientIp::hmac( ClientIp::volume_source( $resolved ) ) );

		/*
		 * A name that is an account here gets a window of its own. Folded
		 * into the connection's, a wrong password on the real administrator
		 * was hidden behind a guess at a name that does not exist, and showed
		 * nowhere in the log (#2077). The rows this can add are bounded by
		 * the accounts the site has, not by what is typed.
		 */
		$account = get_user_by( 'login', $username );

		if ( ! $account instanceof \WP_User && is_email( $username ) ) {
			$account = get_user_by( 'email', $username );
		}

		if ( $account instanceof \WP_User ) {
			$key = 'bettershield_lfail_' . md5( ClientIp::hmac( ClientIp::volume_source( $resolved ) ) . '|' . $account->ID );
		}

		// The typed name as the log may keep it: an account's login where it
		// names one, a masked shape where it was an email that names none,
		// never a password pasted into the wrong field.
		$name     = \BetterShield\Login\Protection::loggable_identifier( $username );
		$admitted = Coalescer::admit_named( $key, $window, (string) $name );

		if ( null === $admitted ) {
			return;
		}

		$context = array();

		// The row says how many it stands for, so a burst is never silently
		// smaller than it was, and which names they tried, so the burst can
		// be searched for and read.
		if ( $admitted['count'] > 0 ) {
			$context['unlogged_attempts'] = $admitted['count'];

			if ( array() !== $admitted['names'] ) {
				$context['unlogged_names'] = $admitted['names'];
			}
		}

		Writer::instance()->record(
			'login_failed',
			Writer::SEVERITY_LOW,
			array(
				'actor_type'  => 'anonymous',
				'object_type' => 'user',
				'object_id'   => $name,
				'context'     => $context,
			)
		);
	}

	public function on_logout( int $user_id = 0 ): void {
		$user = $user_id > 0 ? get_user_by( 'id', $user_id ) : false;

		Writer::instance()->record(
			'logout',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => $user_id > 0 ? $user_id : null,
				'actor_label' => $user instanceof \WP_User ? $user->user_login : null,
				'object_type' => 'user',
				'object_id'   => $user_id > 0 ? (string) $user_id : null,
			)
		);
	}

	/**
	 * Someone asked for a reset link for an account.
	 *
	 * Recorded separately from the reset completing, because the request is
	 * the half an attacker can make happen and the completion is the half they
	 * usually cannot. A burst of these against one administrator is a signal
	 * on its own, and it is invisible if only completions are kept.
	 */
	public function on_password_reset_requested( string $user_login ): void {
		/*
		 * Not a request anybody made: core mints a reset key for an account
		 * created in this same request, for its "set your password" email,
		 * as a store's checkout or the new-user notice does. Recorded, it
		 * read as a signed-out visitor asking to reset the new customer's
		 * password, and the burst window wrote its state on the checkout
		 * request (#1790). The account's creation is already recorded.
		 */
		// Looked up only when some account was created in this request.
		$account = array() === $this->created_now ? false : get_user_by( 'login', $user_login );

		if ( $account instanceof \WP_User && isset( $this->created_now[ (int) $account->ID ] ) ) {
			return;
		}

		$resolved = ClientIp::resolve( \BetterShield\Login\Protection::trusted_proxies(), \BetterShield\Login\Protection::cloudflare() );
		$key = 'bettershield_reset_' . md5( ClientIp::hmac( ClientIp::volume_source( $resolved ) ) );
		$suppressed = Coalescer::admit( $key, 5 * MINUTE_IN_SECONDS );
		if ( null === $suppressed ) { return; }

		Writer::instance()->record(
			'password_reset_requested',
			Writer::SEVERITY_LOW,
			array(
				'actor_type'  => 'anonymous',
				'object_type' => 'user',
				'object_id'   => \BetterShield\Login\Protection::loggable_identifier( $user_login ),
				'context'     => $suppressed > 0 ? array( 'unlogged_attempts' => $suppressed ) : array(),
			)
		);
	}

	/* ---- users and roles ------------------------------------------- */

	/**
	 * Whether an account is being created right now.
	 *
	 * A role arriving on an account with no prior role is either the account
	 * being created — which `user_created` already records alongside its roles
	 * — or an existing role-less account being given one, which is a privilege
	 * grant and recorded nothing at all. The hook arguments cannot tell them
	 * apart, so the creation is what gets marked.
	 *
	 * Marked from the filter that runs before the row is inserted rather than
	 * from `user_register`: core sets the role between those two points, so a
	 * flag raised on registration is raised after the hooks it exists to
	 * silence have already fired.
	 */
	private bool $creating_account = false;

	/**
	 * The accounts created in this request, by id.
	 *
	 * @var array<int, true>
	 */
	private array $created_now = array();

	/** Test seam: a new request, as far as this request's memory goes. */
	public function reset_request_state(): void {
		$this->creating_account = false;
		$this->created_now      = array();
	}

	/**
	 * @param mixed $data
	 * @param mixed $update
	 * @return mixed
	 */
	public function note_account_creation( $data, $update = null ) {
		if ( ! $update ) {
			$this->creating_account = true;
		}

		return $data;
	}

	public function on_user_register( int $user_id ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$this->creating_account        = false;
		$this->created_now[ $user_id ] = true;

		$user = get_user_by( 'id', $user_id );

		// An account arriving with a privileged role is the event most worth
		// hearing about ahead of the digest: it is the first thing an
		// intruder with a foothold creates. High, so the instant alert path
		// carries it; an ordinary account stays medium.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( $user );

		$context = array( 'login' => $user instanceof \WP_User ? $user->user_login : '', 'roles' => $user instanceof \WP_User ? implode( ',', $user->roles ) : '' );
		$token = \BetterShield\Remediation\Observed::account( $user_id ); if ( $token ) { $context['change_token'] = $token; }

		Writer::instance()->record(
			'user_created',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => $context,
			)
		);
	}

	/**
	 * @param mixed $reassign User ID content was reassigned to, or null.
	 * @param mixed $user     The WP_User being removed.
	 */
	public function on_user_deleted( int $user_id, $reassign = null, $user = null ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		// Removing a privileged account is worth hearing about at once;
		// clearing fifty spam subscribers is Tuesday. The instant-alert path
		// starts at high, so the privilege carries the severity.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( $user );

		Writer::instance()->record(
			'user_deleted',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					// The name is captured here because after this request there
					// is nowhere left to read it from.
					'login'      => $user instanceof \WP_User ? $user->user_login : '',
					'reassigned' => null === $reassign ? 0 : (int) $reassign,
				),
			)
		);

		/*
		 * And everything kept about the person rather than about the site.
		 * The per-site records go through the same path a removed membership
		 * takes; the rest is network-global, held once for the account however
		 * many sites it belonged to, and it is exactly what the erasure
		 * request removes — so an account deleted outright is left in the same
		 * state as an account that asked to be forgotten.
		 */
		$this->forget_site_records( $user_id );

		\BetterShield\Rest\Sudo::forget( $user_id );
		\BetterShield\Password\Policy::forget_everywhere( $user_id );
		\BetterShield\Onboarding\Release::forget( $user_id );

		// A credential bound to an account that no longer exists is a row that
		// can never be used and never be removed by its owner. On a network the
		// table holding it is the network's, so this is the only moment it goes.
		\BetterShield\Passkeys\Store::forget_user( $user_id );
	}

	/**
	 * Somebody taken off this site.
	 *
	 * Core fires this with the site being left switched to, so everything
	 * below acts on that site's own record of the account: the two-factor
	 * clock this site started, the pointer to a sign-in parked here, where
	 * they had read up to, and whether their password is below this site's
	 * policy. All four are scoped per site on a network, so this removes this
	 * site's and leaves every other site's alone.
	 *
	 * Sessions are the exception, because there is no such thing as a per-site
	 * session: tokens are user meta and user meta is one table for the whole
	 * network. Ending them is therefore reserved for the account that has just
	 * lost its last membership — and never for a network administrator, whose
	 * standing does not come from a membership at all.
	 *
	 * @param mixed $reassign User ID content was reassigned to, or 0.
	 */
	public function on_user_removed_from_site( int $user_id, int $blog_id = 0, $reassign = 0 ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$user = get_user_by( 'id', $user_id );

		$this->forget_site_records( $user_id );

		$ended = false;

		if ( ! is_super_admin( $user_id ) && count( (array) get_blogs_of_user( $user_id ) ) <= 1 ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			\BetterShield\Rest\Sudo::forget( $user_id );

			$ended = true;
		}

		// The site's own deletion removing its members is not a membership
		// ended by somebody: the site and its log go with it, and a row here
		// would outlive the sweep that took the rest.
		if ( \BetterShield\Lifecycle::is_being_deleted( $blog_id ) ) {
			return;
		}

		Writer::instance()->record(
			'user_removed_from_site',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					// Captured here because the account keeps existing while
					// its membership here does not, and a row naming only an
					// id is a row nobody can read a year later.
					'login'          => $user instanceof \WP_User ? $user->user_login : '',
					'reassigned'     => (int) $reassign,
					'sessions_ended' => $ended,
				),
			)
		);
	}

	/**
	 * What this site keeps about one person, forgotten.
	 *
	 * Each class is forgotten by the code that owns it, so the keys that are
	 * scoped per site on a network are scoped the same way here as they are
	 * written. Nothing here touches the account itself.
	 */
	private function forget_site_records( int $user_id ): void {
		\BetterShield\TwoFactor\Policy::forget( $user_id );
		\BetterShield\TwoFactor\LoginStep::forget_for( $user_id );
		\BetterShield\Events\SinceLastVisit::forget( $user_id );
		\BetterShield\Password\Policy::forget( $user_id );
	}

	/**
	 * @param string[] $old_roles Roles held before the change.
	 */
	public function on_role_changed( int $user_id, string $role, array $old_roles = array() ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		/*
		 * An empty prior set means one of two things, and only one of them is
		 * already recorded. During account creation `user_created` carries the
		 * roles, so a second row would say the same thing twice. On an account
		 * that exists and holds no role — the stock "— No role for this site —"
		 * state, and what adding a network user to a subsite produces — the
		 * same hook is a privilege grant, and it was recording nothing.
		 */
		if ( array() === $old_roles && $this->creating_account ) {
			return;
		}

		// A site being created is handed its first administrator: that is
		// the site coming into being, recorded once as such (#2184).
		if ( self::initializing_site() ) {
			return;
		}

		/*
		 * Read the account rather than trust the argument. Core's REST users
		 * controller fires this hook with an empty $role — the classic
		 * profile screen and WP-CLI pass a real one — so a promotion driven
		 * by automation logged "to: " and nothing else, which is the half of
		 * the record that matters. Reading the account answers correctly
		 * whichever path called.
		 */
		$user = get_user_by( 'id', $user_id );
		$now  = $user instanceof \WP_User ? array_values( (array) $user->roles ) : array_filter( array( $role ) );

		// A change that touches a privileged role — gained or lost — is the
		// escalation the instant path exists for. A membership site moving
		// people between ordinary roles on every purchase is routine, and
		// instant-emailing the owner per sale is how alerts get muted.
		$policy     = \BetterShield\Password\Policy::instance();
		$privileged = $policy->roles_are_privileged( $now ) || $policy->roles_are_privileged( $old_roles );

		Writer::instance()->record(
			'user_role_changed',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'from' => implode( ',', $old_roles ),
					'to'   => implode( ',', $now ),
				),
			)
		);
	}

	/**
	 * @param mixed $user The WP_User whose password was reset.
	 */
	public function on_password_reset( $user = null ): void {
		$this->record_password_change( $user instanceof \WP_User ? (int) $user->ID : 0, 'reset' );
	}

	/**
	 * @param mixed $old_user_data WP_User as it was before the update.
	 * @param mixed $userdata      The submitted field values.
	 */
	public function on_profile_update( int $user_id, $old_user_data = null, $userdata = array() ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		if ( ! $old_user_data instanceof \WP_User || ! is_array( $userdata ) ) {
			return;
		}

		if ( isset( $userdata['user_pass'] ) ) {
			// Two hashes compared to answer one yes-or-no question. Neither is
			// recorded, and neither leaves this method.
			if ( (string) $userdata['user_pass'] !== (string) $old_user_data->user_pass ) {
				$this->record_password_change( $user_id, 'profile' );
			}
		}

		/*
		 * The address change is the one that has to be here.
		 *
		 * Taking an account by changing its email and then asking for a reset
		 * is the ordinary shape of the attack, and the reset that follows looks
		 * entirely legitimate on its own. Without this, the log records the
		 * takeover's second half and misses the first.
		 *
		 * Neither address is stored — the log has no reason to accumulate
		 * people's email, and the current one is on the user's own profile for
		 * anyone entitled to see it. That it changed, and who changed it, is
		 * the security signal.
		 */
		if ( isset( $userdata['user_email'] ) && (string) $userdata['user_email'] !== (string) $old_user_data->user_email ) {
			// Changing the address on a privileged account is how it is
			// taken; a customer editing their own is account upkeep. The
			// privilege carries the severity, and with it the instant path.
			Writer::instance()->record(
				'user_email_changed',
				\BetterShield\Password\Policy::instance()->user_is_privileged( $user_id ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'user',
					'object_id'   => (string) $user_id,
					'context'     => array( 'login' => $old_user_data->user_login ),
				)
			);
		}
	}

	/**
	 * A role gained without the rest of the set being replaced.
	 *
	 * @param mixed $role The role name added.
	 */
	public function on_role_added( int $user_id, $role = '' ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		/*
		 * Suppressed only for the role an account is created with, which
		 * `user_created` already records alongside it. Both signals are needed
		 * and neither is enough alone: counting roles cannot tell that from
		 * `add_role()` on an existing account holding none, because core fires
		 * this after the write and the freshly read user holds exactly one
		 * role either way — which is how granting administrator to a role-less
		 * account recorded nothing. And the creation flag alone would suppress
		 * a genuine second role added in the same request that made the
		 * account.
		 */
		if ( $this->creating_account || self::initializing_site() ) {
			return;
		}

		$this->record_role_change( 'user_role_granted', $user_id, (string) $role );
	}

	/**
	 * Whether WordPress is filling in a new site of a network.
	 *
	 * Its default roles and its first administrator are written then, before
	 * anybody has done anything on it, and every new site began with "What a
	 * role may do changed", an administrator grant and a critical alert to
	 * its administrator (#2184). The site's creation is recorded once
	 * instead, as activation on an existing site is.
	 */
	private static function initializing_site(): bool {
		return is_multisite() && doing_action( 'wp_initialize_site' );
	}

	/**
	 * What network-wide control is called in the log.
	 *
	 * WordPress keeps it as a flag on the network rather than as a role, so
	 * this slug names no registered role and no role object holds its
	 * capabilities. Anything that grades privilege by looking a role up has
	 * to be told about it by name.
	 */
	private const SUPER_ADMIN_ROLE = 'super-admin';

	public function on_super_admin_granted( int $user_id ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$this->super_admin_changing = false;
		$this->record_role_change( 'user_role_granted', $user_id, self::SUPER_ADMIN_ROLE );
	}

	public function on_super_admin_revoked( int $user_id ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$this->super_admin_changing = false;
		$this->record_role_change( 'user_role_revoked', $user_id, self::SUPER_ADMIN_ROLE );
	}

	/**
	 * A grant or revoke through core's own functions is under way. Its write
	 * to the super-admin list is recorded by the hooks above, so the list's
	 * own change is not a second row; a write that skips them is.
	 */
	public function note_super_admin_change(): void {
		$this->super_admin_changing = true;
	}

	/* ---- a network's sites ------------------------------------------ */

	/**
	 * The flags on a network's site that change what it is: archived,
	 * deactivated (core's `deleted`), spam, mature, and whether search engines
	 * are asked to stay away (`public`).
	 */
	public const SITE_FLAGS = array( 'archived', 'deleted', 'spam', 'public', 'mature' );

	/**
	 * A site's standing changed: one row naming the flags that moved, in that
	 * site's own log beside the row of its creation, so its history reads in
	 * one place. Any other update to the site row, such as core touching its
	 * last-updated time on every post, changes no flag and records nothing.
	 *
	 * @param mixed $new_site The site as it is now.
	 * @param mixed $old_site The site as it was.
	 */
	public function on_site_updated( $new_site = null, $old_site = null ): void {
		if ( ! $new_site instanceof \WP_Site || ! $old_site instanceof \WP_Site ) {
			return;
		}

		$changed = array();

		foreach ( self::SITE_FLAGS as $flag ) {
			if ( (int) $new_site->$flag !== (int) $old_site->$flag ) {
				$changed[ $flag ] = 1 === (int) $new_site->$flag;
			}
		}

		if ( array() === $changed ) {
			return;
		}

		$blog_id = (int) $new_site->blog_id;

		// Its own log where this plugin runs on it; where it does not, the
		// site's tables are not this plugin's to write, and the network
		// screen doing the change keeps the row.
		$switch = $blog_id !== get_current_blog_id() && self::runs_on_every_site();

		if ( $switch ) {
			switch_to_blog( $blog_id );
		}

		try {
			Writer::instance()->record(
				'site_status_changed',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'site',
					'object_id'   => (string) $blog_id,
					'context'     => array(
						'address' => self::site_address( $new_site ),
						'changed' => $changed,
					),
				)
			);
		} finally {
			if ( $switch ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * A site removed from the network, named from the site core passes,
	 * since there is nothing left to read afterwards. Its own log goes with
	 * it, so the row is the main site's, where the network's other history is.
	 *
	 * @param mixed $old_site The site that was deleted.
	 */
	public function on_site_deleted( $old_site = null ): void {
		if ( ! $old_site instanceof \WP_Site ) {
			return;
		}

		$main   = (int) get_main_site_id();
		$switch = $main !== get_current_blog_id();

		if ( $switch ) {
			switch_to_blog( $main );
		}

		try {
			Writer::instance()->record(
				'site_deleted',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'site',
					'object_id'   => (string) (int) $old_site->blog_id,
					'context'     => array( 'address' => self::site_address( $old_site ) ),
				)
			);
		} finally {
			if ( $switch ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * A network's site by the address people reach it at: its domain and path.
	 */
	public static function site_address( \WP_Site $site ): string {
		return (string) $site->domain . (string) $site->path;
	}

	/**
	 * Whether this plugin runs on every site of the network: active for the
	 * whole network, or loaded with the must-use plugins (in neither list).
	 * Active on one site alone, it still loads in Network Admin as that site.
	 */
	private static function runs_on_every_site(): bool {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$basename = plugin_basename( BETTERSHIELD_FILE );

		return is_plugin_active_for_network( $basename ) || ! in_array( $basename, (array) get_option( 'active_plugins', array() ), true );
	}

	/**
	 * @param mixed $role The role name removed.
	 */
	public function on_role_removed( int $user_id, $role = '' ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$this->record_role_change( 'user_role_revoked', $user_id, (string) $role );
	}

	private function record_role_change( string $event, int $user_id, string $role ): void {
		if ( $user_id <= 0 || '' === $role ) {
			return;
		}

		// A privileged role moving is the quiet escalation; an ordinary one
		// is membership churn, which must not ride the instant path.
		//
		// Super admin is named before the lookup rather than left to it: it
		// has no role object to read capabilities from, so the lookup answers
		// no and network-wide control would be recorded more quietly than a
		// single site's administrator — the other way around from the truth.
		$privileged = self::SUPER_ADMIN_ROLE === $role
			|| \BetterShield\Password\Policy::instance()->roles_are_privileged( array( $role ) );

		Writer::instance()->record(
			$event,
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array( 'role' => $role ),
			)
		);
	}

	/* ---- application passwords ------------------------------------- */

	/**
	 * @param mixed $user_id The account the password belongs to.
	 * @param mixed $item    The stored record: uuid, name, created.
	 */
	public function on_app_password_created( $user_id = 0, $item = array() ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		// The decoy being planted records its own creation, said as the decoy.
		if ( \BetterShield\Agents\Canary::planting() ) {
			return;
		}

		// A standing credential on a privileged account is worth hearing
		// about at once; on an ordinary account it is an integration being
		// set up. The privilege carries the severity.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( (int) $user_id );

		Writer::instance()->record(
			'app_password_created',
			$privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) (int) $user_id,
				'context'     => array(
					// The name the person typed and the identifier, never the
					// password itself, which this hook also carries.
					'name' => is_array( $item ) && isset( $item['name'] ) ? \BetterShield\Support\Text::clip( (string) $item['name'], 100 ) : '',
					'uuid' => is_array( $item ) && isset( $item['uuid'] ) ? (string) $item['uuid'] : '',
				),
			)
		);
	}

	/**
	 * @param mixed $user_id The account the password belonged to.
	 * @param mixed $item    The record as it was.
	 */
	public function on_app_password_deleted( $user_id = 0, $item = array() ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		Writer::instance()->record(
			'app_password_revoked',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) (int) $user_id,
				'context'     => array(
					'name' => is_array( $item ) && isset( $item['name'] ) ? \BetterShield\Support\Text::clip( (string) $item['name'], 100 ) : '',
					'uuid' => is_array( $item ) && isset( $item['uuid'] ) ? (string) $item['uuid'] : '',
				),
			)
		);
	}

	/**
	 * Something reached this site over XML-RPC.
	 *
	 * One row an hour, whatever the volume — the row stands for a period of
	 * use rather than for a request, and it exists so the preview for turning
	 * XML-RPC off can answer the question somebody actually opens it to ask.
	 * The method name travels because "something used XML-RPC" and "something
	 * called pingback.ping" are different facts to whoever is deciding, and it
	 * is the name of a public API rather than anything about the caller.
	 *
	 * @param mixed $method The XML-RPC method called.
	 */
	public function on_xmlrpc_used( $method = '' ): void {
		if ( ! Claim::claim( 'xmlrpc_use', HOUR_IN_SECONDS ) ) {
			return;
		}

		Writer::instance()->record(
			'xmlrpc_used',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'system',
				'object_type' => 'endpoint',
				'object_id'   => 'xmlrpc.php',
				'context'     => array(
					'method'   => \BetterShield\Support\Text::clip( (string) $method, 60 ),
					'first_in' => 'hour',
				),
			)
		);
	}

	/**
	 * A connected tool signed in with an application password.
	 *
	 * Deliberately not one event per request. A connector polling every minute
	 * would otherwise write fourteen hundred rows a day and bury everything
	 * else in the log — the answer worth having is "this key was in use today",
	 * not a transcript of its traffic. One row per credential per hour gives
	 * that, and the failures are already recorded unthrottled by login
	 * protection, because those are the ones that are rare and mean something.
	 *
	 * @param mixed $user The account that authenticated.
	 * @param mixed $item The application password record used.
	 */
	public function on_app_password_used( $user = null, $item = array() ): void {
		$uuid = is_array( $item ) && isset( $item['uuid'] ) ? (string) $item['uuid'] : '';

		if ( '' === $uuid ) {
			return;
		}

		// Taking the hour is what decides whether this row is written, so it
		// is one statement rather than a read and a write: this is traffic,
		// and two requests arriving together is the normal case here.
		if ( ! Claim::claim( 'apuse_' . md5( $uuid ), HOUR_IN_SECONDS ) ) {
			return;
		}

		Writer::instance()->record(
			'app_password_used',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => $user instanceof \WP_User ? (int) $user->ID : null,
				'actor_label' => $user instanceof \WP_User ? $user->user_login : null,
				'object_type' => 'app_password',
				'object_id'   => $uuid,
				'context'     => array(
					'name'    => is_array( $item ) && isset( $item['name'] ) ? \BetterShield\Support\Text::clip( (string) $item['name'], 100 ) : '',
					// So a reader knows this row stands for a period of use
					// rather than for one request.
					'first_in' => 'hour',
				),
			)
		);
	}

	private function record_password_change( int $user_id, string $via ): void {
		if ( $user_id <= 0 ) {
			return;
		}

		Writer::instance()->record(
			'password_changed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array( 'via' => $via ),
			)
		);
	}

	/* ---- plugins and themes ---------------------------------------- */

	public function on_plugin_activated( string $plugin, ?bool $network = false ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$token   = \BetterShield\Remediation\Observed::plugin( $plugin, $network ?? false );
		$context = array_filter( array( 'change_token' => $token, 'name' => self::plugin_name( $plugin ) ) );
		Writer::instance()->record( 'plugin_activated', $this->activation_severity(), array( 'object_type' => 'plugin', 'object_id' => $plugin, 'context' => $context ) );
	}

	/**
	 * A plugin's name as its header gives it, read while its file is there,
	 * so the row can say "WP 2FA" rather than "wp-2fa/wp-2fa.php" and keep
	 * saying it after the plugin is gone (#2120); '' when it cannot be read.
	 */
	private static function plugin_name( string $plugin ): string {
		$path = WP_PLUGIN_DIR . '/' . $plugin;

		if ( '' === $plugin || ! is_readable( $path ) ) {
			return '';
		}

		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$data = get_plugin_data( $path, false, false );

		return \BetterShield\Support\Text::clip( (string) ( $data['Name'] ?? '' ), 100 );
	}

	/**
	 * Switching off this plugin or its add-on takes every protection, alert
	 * and record down with it, and the request that does it is the last one
	 * this plugin can speak from: once it is off there is no weekly summary
	 * to carry a quieter row. So it goes out at once, whoever does it.
	 * Anybody else's plugin stays routine.
	 *
	 * "At once" includes when an earlier alert's five-minute hold is still
	 * running: the follow-up that would have sent it after the hold belongs
	 * to the plugin being switched off, so it is sent before this request
	 * ends instead, along with anything else queued (#2470). From the
	 * Plugins screen, the network's, or WP-CLI alike: all arrive here.
	 */
	public function on_plugin_deactivated( string $plugin ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		$own = self::is_bettershield( $plugin );

		$this->record_plugin( 'plugin_deactivated', $plugin, $own ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM );

		if ( $own ) {
			\BetterShield\Alerts\Notifier::instance()->send_before_switch_off();
		}
	}

	/**
	 * The names of plugins about to be deleted, read before core removes
	 * their files: `deleted_plugin` fires after, when the header is gone.
	 *
	 * @var array<string, string>
	 */
	private static array $deleting = array();

	/**
	 * The plugins installed when the current upgrader run began, by file, with
	 * the version each was at. Null until a run begins.
	 *
	 * @var array<string, string>|null
	 */
	private static ?array $before_upgrade = null;

	/**
	 * The upgrader whose run took the snapshot above, held weakly so a run
	 * that has ended is not kept alive by it.
	 *
	 * @var \WeakReference<object>|null
	 */
	private static ?\WeakReference $upgrade_run = null;

	/**
	 * Start each upgrader's run from a clean snapshot.
	 *
	 * The snapshot is normally cleared when the run completes, but a run can
	 * stop short of its completion hook, and the next run then reported the
	 * versions noted before the earlier one. This filter fires as every item
	 * starts and is the first to name the upgrader: a different upgrader is a
	 * new run, while the items of one bulk run share theirs and keep the
	 * snapshot the first item took. What it was given goes back unchanged.
	 *
	 * @param mixed $reply    Passed through.
	 * @param mixed $package  The package being fetched, unused.
	 * @param mixed $upgrader The upgrader running.
	 * @return mixed
	 */
	public function on_upgrade_run( $reply = false, $package = '', $upgrader = null ) {
		if ( ! is_object( $upgrader ) ) {
			return $reply;
		}

		if ( null === self::$upgrade_run || self::$upgrade_run->get() !== $upgrader ) {
			self::$before_upgrade = null;
			self::$upgrade_run    = \WeakReference::create( $upgrader );
		}

		return $reply;
	}

	/**
	 * Note the installed plugins' versions as an upgrader run starts.
	 *
	 * A filter only so the hook fires before the package lands; what it was
	 * given goes back unchanged. A bulk run fires it per item, and the first
	 * snapshot stands for the whole run.
	 *
	 * A bulk update describes each item by its plugin file alone, with no
	 * type, so a plugin file in the description counts as a plugin run too.
	 *
	 * @param mixed $response   Passed through.
	 * @param mixed $hook_extra The run's own description.
	 * @return mixed
	 */
	public function before_upgrade( $response = true, $hook_extra = array() ) {
		if ( null === self::$before_upgrade && is_array( $hook_extra ) && ( 'plugin' === ( $hook_extra['type'] ?? '' ) || isset( $hook_extra['plugin'] ) ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}

			self::$before_upgrade = array();

			foreach ( get_plugins() as $file => $data ) {
				self::$before_upgrade[ (string) $file ] = (string) ( $data['Version'] ?? '' );
			}
		}

		if ( null === self::$before_upgrade && is_array( $hook_extra ) && ( 'theme' === ( $hook_extra['type'] ?? '' ) || isset( $hook_extra['theme'] ) ) ) {
			self::$before_upgrade = array();

			foreach ( wp_get_themes() as $stylesheet => $theme ) {
				self::$before_upgrade[ (string) $stylesheet ] = (string) $theme->get( 'Version' );
			}
		}

		return $response;
	}

	public function before_plugin_deleted( string $plugin ): void {
		self::$deleting[ $plugin ] = self::plugin_name( $plugin );
	}

	/**
	 * @param mixed $deleted Whether the removal actually succeeded.
	 */
	public function on_plugin_deleted( string $plugin, $deleted = true ): void {
		if ( ! $deleted ) {
			return; // A failed deletion is not a deletion.
		}

		\BetterShield\Plugin::owe_audit_for_change();

		$this->record_plugin( 'plugin_deleted', $plugin, self::is_bettershield( $plugin ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM );
	}

	/**
	 * Installs and updates, for plugins and themes alike, arrive on one hook.
	 *
	 * Themes were skipped here on the grounds that the theme switch covers
	 * them. It does not: `switch_theme` fires when a theme is *activated*, and
	 * says nothing about one being installed or updated. A theme is executable
	 * code on the site like a plugin is, so it is recorded like one.
	 *
	 * An install names nothing in `$hook_extra`: WordPress does not know the
	 * plugin file or the stylesheet until the package is unpacked, so the
	 * bulk and single keys that an update carries are both absent, and the
	 * row for the highest-severity extension event this log records went out
	 * with an empty object. The upgrader is what knows — its result names
	 * the destination and its own info method reads the file inside it — so
	 * an install is named from there.
	 *
	 * @param mixed $upgrader   The upgrader instance, which names an install.
	 * @param mixed $hook_extra What was installed or updated.
	 */
	public function on_upgrade_complete( $upgrader = null, $hook_extra = array() ): void {
		// Taken once per run, whatever happens below, so a run that returns
		// early never leaves its snapshot for the next one.
		$before               = (array) self::$before_upgrade;
		self::$before_upgrade = null;

		if ( ! is_array( $hook_extra ) ) {
			return;
		}

		$type   = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';
		$action = isset( $hook_extra['action'] ) ? (string) $hook_extra['action'] : '';

		// Core has its own hook, which fires with the version it landed on.
		if ( 'plugin' !== $type && 'theme' !== $type ) {
			return;
		}

		// What was installed or updated may be what a check reads.
		\BetterShield\Plugin::owe_audit_for_change();

		// The hook fires for a run that failed too: an upload refused because
		// the folder already exists (the first pass of Replace), a package a
		// filter rejected, an update rolled back. Nothing landed, so nothing is
		// recorded. A bulk run fires once for all its items and its upgrader
		// holds only the last one's result, so that result is not read.
		if ( empty( $hook_extra['bulk'] ) && self::run_failed( $upgrader ) ) {
			return;
		}

		// A bulk update reports an array; a single one reports a string.
		$plural  = 'plugin' === $type ? 'plugins' : 'themes';
		$targets = array();
		if ( isset( $hook_extra[ $plural ] ) && is_array( $hook_extra[ $plural ] ) ) {
			$targets = $hook_extra[ $plural ];
		} elseif ( isset( $hook_extra[ $type ] ) ) {
			$targets = array( (string) $hook_extra[ $type ] );
		}

		if ( 'plugin' === $type ) {
			$event    = 'install' === $action ? 'plugin_installed' : 'plugin_updated';
			$severity = 'install' === $action ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_INFO;
		} else {
			$event    = 'install' === $action ? 'theme_installed' : 'theme_updated';
			$severity = 'install' === $action ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_INFO;
		}

		$object = 'plugin' === $type ? 'plugin' : 'theme';

		if ( array() === $targets ) {
			$targets = array( self::installed_target( $upgrader, $type ) );
		}

		foreach ( $targets as $target ) {
			$target = (string) $target;
			$from   = $before[ $target ] ?? null;
			$to     = 'plugin' === $type ? self::plugin_version( $target ) : self::theme_version( $target );

			// A bulk run holds no result per item, so the versions answer for
			// each one: an item that never reached the install step, or kept its
			// version, didn't land. Its row would vouch for what comes after.
			if ( ! empty( $hook_extra['bulk'] ) && ( null === $from || $from === $to ) ) {
				continue;
			}

			if ( 'plugin' !== $type ) {
				$this->record_extension( $event, $object, $target, $severity, null !== $from && '' !== $from && '' !== $to ? array( 'from' => $from, 'to' => $to ) : array() );
				continue;
			}

			// A package uploaded over a plugin that was already here, or
			// installed with --force, is an update: said so, with the
			// versions it moved between. It keeps the install's grade, since
			// somebody chose to lay a package over code that was running.
			$this->record_extension(
				null !== $from ? 'plugin_updated' : $event,
				$object,
				$target,
				$severity,
				null !== $from && '' !== $from && '' !== $to ? array( 'from' => $from, 'to' => $to ) : array()
			);
		}
	}

	/** The version a plugin's header gives now, read past the plugins cache. */
	private static function plugin_version( string $plugin ): string {
		$path = WP_PLUGIN_DIR . '/' . $plugin;

		if ( '' === $plugin || ! is_readable( $path ) ) {
			return '';
		}

		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return \BetterShield\Support\Text::clip( (string) ( get_plugin_data( $path, false, false )['Version'] ?? '' ), 32 );
	}

	/** The version a theme's header gives now, read past the themes cache. */
	private static function theme_version( string $stylesheet ): string {
		$path = get_theme_root( $stylesheet ) . '/' . $stylesheet . '/style.css';

		if ( '' === $stylesheet || ! is_readable( $path ) ) {
			return '';
		}

		return \BetterShield\Support\Text::clip( (string) ( get_file_data( $path, array( 'version' => 'Version' ) )['version'] ?? '' ), 32 );
	}

	/**
	 * WordPress itself moved to a new version.
	 *
	 * One of the most security-relevant things that can happen to a site, and
	 * it left no trace at all until this: core does not travel through the
	 * upgrader hook with a type this plugin can read.
	 *
	 * @param mixed $wp_version The version core landed on.
	 */
	public function on_core_updated( $wp_version = '' ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		Writer::instance()->record(
			'core_updated',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'core',
				'object_id'   => substr( (string) $wp_version, 0, 32 ),
			)
		);
	}

	/**
	 * @param mixed $stylesheet The theme directory removed.
	 * @param mixed $deleted    Whether the removal actually succeeded.
	 */
	public function on_theme_deleted( $stylesheet = '', $deleted = true ): void {
		if ( ! $deleted ) {
			return; // A failed deletion is not a deletion.
		}

		\BetterShield\Plugin::owe_audit_for_change();

		$this->record_extension( 'theme_deleted', 'theme', (string) $stylesheet, Writer::SEVERITY_MEDIUM );
	}

	/**
	 * A save in the theme or plugin file editor, noted before core makes it.
	 *
	 * Core writes the file in `wp_edit_theme_plugin_file()`, reached from the
	 * editor's AJAX action and from the no-JavaScript form on both editor
	 * screens, and announces nothing. So the file it will write is found the
	 * way core finds it, hashed now, and hashed again at shutdown. A save core
	 * refused, or wrote and then rolled back because the site broke, leaves
	 * the hash as it was and is not recorded. Who saved it and which file, never
	 * the contents.
	 */
	public function note_editor_save(): void {
		global $pagenow;

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- read only to find the file; core checks the nonce and the capability before it writes, and a refused save changes nothing to record.
		$ajax = wp_doing_ajax() && isset( $_POST['action'] ) && 'edit-theme-plugin-file' === $_POST['action'];
		$form = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] && in_array( (string) $pagenow, array( 'plugin-editor.php', 'theme-editor.php' ), true );

		if ( ( ! $ajax && ! $form ) || null !== $this->editor_save ) {
			return;
		}

		// Only someone core would let save: a visitor posting the action to
		// admin-ajax.php must not make this request read and hash files.
		if ( ! current_user_can( empty( $_POST['plugin'] ) ? 'edit_themes' : 'edit_plugins' ) ) {
			return;
		}

		$target = self::editor_target( wp_unslash( $_POST ) );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( null === $target ) {
			return;
		}

		$hash = @hash_file( 'sha256', $target['path'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is not a save to record.

		if ( false === $hash ) {
			return;
		}

		$this->editor_save = $target + array( 'hash' => $hash );

		// Before the writer's flush at 100, so the row is in this request's batch.
		add_action( 'shutdown', array( $this, 'on_editor_saved' ), 10 );
	}

	/**
	 * The save, recorded if the file it named now reads differently.
	 */
	public function on_editor_saved(): void {
		$save              = $this->editor_save;
		$this->editor_save = null;

		if ( null === $save ) {
			return;
		}

		clearstatcache( true, $save['path'] );

		$hash = is_file( $save['path'] ) ? @hash_file( 'sha256', $save['path'] ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the same: unreadable is nothing to record.

		if ( false === $hash || hash_equals( $save['hash'], $hash ) ) {
			return;
		}

		\BetterShield\Plugin::owe_audit_for_change();

		Writer::instance()->record(
			'theme_plugin_file_edited',
			// Writing PHP from the dashboard is the first thing a stolen
			// administrator session does, so this reaches the instant alert.
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => $save['type'],
				'object_id'   => $save['id'],
				'context'     => array(
					'name' => $save['name'],
					'file' => $save['file'],
				),
			)
		);
	}

	/**
	 * The file an editor save names, found the way core finds it and kept
	 * inside its own plugin's or theme's folder. Null for anything core would
	 * refuse before writing.
	 *
	 * @param mixed $args The posted fields: `plugin` or `theme`, and `file`.
	 * @return array{type: string, id: string, file: string, name: string, path: string}|null
	 */
	public static function editor_target( $args ): ?array {
		if ( ! is_array( $args ) || ! isset( $args['file'] ) || ! is_string( $args['file'] ) || '' === $args['file'] || 0 !== validate_file( $args['file'] ) ) {
			return null;
		}

		$file = $args['file'];

		if ( isset( $args['plugin'] ) && is_string( $args['plugin'] ) && '' !== $args['plugin'] ) {
			$plugin = $args['plugin'];

			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}

			$plugins = get_plugins();

			if ( ! isset( $plugins[ $plugin ] ) ) {
				return null;
			}

			// A plugin in a folder may have any of its own files edited; a
			// single-file plugin only itself.
			$folder = dirname( $plugin );

			if ( '.' === $folder ? $file !== $plugin : 0 !== strpos( $file, $folder . '/' ) ) {
				return null;
			}

			$path = WP_PLUGIN_DIR . '/' . $file;

			return is_file( $path ) ? array(
				'type' => 'plugin',
				'id'   => $plugin,
				'file' => '.' === $folder ? $file : substr( $file, strlen( $folder ) + 1 ),
				'name' => (string) ( $plugins[ $plugin ]['Name'] ?? '' ),
				'path' => $path,
			) : null;
		}

		if ( isset( $args['theme'] ) && is_string( $args['theme'] ) && '' !== $args['theme'] && 0 === validate_file( $args['theme'] ) ) {
			$theme = wp_get_theme( $args['theme'] );

			if ( ! $theme->exists() ) {
				return null;
			}

			$path = $theme->get_stylesheet_directory() . '/' . $file;

			return is_file( $path ) ? array(
				'type' => 'theme',
				'id'   => $args['theme'],
				'file' => $file,
				'name' => (string) $theme->get( 'Name' ),
				'path' => $path,
			) : null;
		}

		return null;
	}

	/**
	 * What an upgrader just put in place, read off the upgrader.
	 *
	 * The plugin file (`dir/file.php`) or the stylesheet where the upgrader
	 * can say, and the destination directory where only the result is there
	 * to read; the empty string when neither is, which is what this row
	 * carried for every install before.
	 *
	 * @param mixed $upgrader The upgrader instance.
	 */
	private static function installed_target( $upgrader, string $type ): string {
		if ( ! is_object( $upgrader ) ) {
			return '';
		}

		if ( 'plugin' === $type && method_exists( $upgrader, 'plugin_info' ) ) {
			$file = $upgrader->plugin_info();

			if ( is_string( $file ) && '' !== $file ) {
				return $file;
			}
		}

		if ( 'theme' === $type && method_exists( $upgrader, 'theme_info' ) ) {
			$theme = $upgrader->theme_info();

			if ( $theme instanceof \WP_Theme ) {
				return (string) $theme->get_stylesheet();
			}
		}

		$result = isset( $upgrader->result ) && is_array( $upgrader->result ) ? $upgrader->result : array();

		return isset( $result['destination_name'] ) ? (string) $result['destination_name'] : '';
	}

	/**
	 * Whether a single upgrader run ended in an error.
	 *
	 * Core hands the run's outcome to the skin before the hook fires. The
	 * upgrader's own result is written only once the package is in place, so
	 * a refusal before that leaves it empty, and a failed post-install step
	 * replaces it with the error.
	 *
	 * @param mixed $upgrader The upgrader the hook passed.
	 */
	private static function run_failed( $upgrader ): bool {
		if ( ! is_object( $upgrader ) ) {
			return false;
		}

		if ( isset( $upgrader->skin ) && is_object( $upgrader->skin ) && isset( $upgrader->skin->result ) && is_wp_error( $upgrader->skin->result ) ) {
			return true;
		}

		return isset( $upgrader->result ) && ( false === $upgrader->result || is_wp_error( $upgrader->result ) );
	}

	/**
	 * @param array<string, string> $versions `from` and `to`, where known.
	 */
	private function record_extension( string $event, string $object_type, string $id, int $severity, array $versions = array() ): void {
		// A plugin by the name its header gives, as its activation row names
		// it: an install said "hello-dolly/hello.php" beside "Hello Dolly" (#2408).
		$name = 'plugin' === $object_type ? self::plugin_name( $id ) : '';

		Writer::instance()->record(
			$event,
			$severity,
			array(
				'object_type' => $object_type,
				'object_id'   => $id,
				'context'     => ( '' !== $name ? array( 'name' => $name ) : array() ) + $versions,
			)
		);
	}

	private function record_plugin( string $event, string $plugin, int $severity ): void {
		$name = self::plugin_name( $plugin );

		if ( '' === $name && isset( self::$deleting[ $plugin ] ) ) {
			$name = self::$deleting[ $plugin ];
		}

		unset( self::$deleting[ $plugin ] );

		Writer::instance()->record(
			$event,
			$severity,
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
				'context'     => '' !== $name ? array( 'name' => $name ) : array(),
			)
		);
	}

	/**
	 * Whether a plugin file is this plugin or its add-on. Known by the file
	 * each was loaded from, and the add-on also by its own file name: only a
	 * plugin that is off can be deleted, so it is not loaded then.
	 */
	private static function is_bettershield( string $plugin ): bool {
		if ( plugin_basename( BETTERSHIELD_FILE ) === $plugin || 'bettershield-ultra.php' === wp_basename( $plugin ) ) {
			return true;
		}

		return defined( 'BETTERSHIELD_ULTRA_FILE' ) && plugin_basename( (string) constant( 'BETTERSHIELD_ULTRA_FILE' ) ) === $plugin;
	}

	/**
	 * How loudly to record somebody else's code being switched on.
	 *
	 * Activating a plugin or a theme runs code the site did not run a moment
	 * ago, and it is also the commonest deliberate thing an administrator
	 * does: recording all of it high would interrupt routine work, which is
	 * the opposite of what an alert is for. Code switched on by nobody is the
	 * shape worth interrupting for — no signed-in account behind it, and not
	 * the command line either.
	 *
	 * Resolved here rather than read back from the stored row, because the
	 * severity is chosen before the writer builds one. The two answers have
	 * to agree, so this asks the same questions in the same order the writer
	 * asks them when it names the actor.
	 */
	private function activation_severity(): int {
		$user = wp_get_current_user();

		if ( $user instanceof \WP_User && $user->exists() ) {
			return Writer::SEVERITY_MEDIUM;
		}

		// The command line signs nobody in and is still somebody: it is the
		// system, not an unnamed actor.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return Writer::SEVERITY_MEDIUM;
		}

		return Writer::SEVERITY_HIGH;
	}

	public function on_theme_changed( string $new_name ): void {
		// A check may read what this changed.
		\BetterShield\Plugin::owe_audit_for_change();

		Writer::instance()->record(
			'theme_changed',
			$this->activation_severity(),
			array(
				'object_type' => 'theme',
				'object_id'   => $new_name,
			)
		);
	}

	/* ---- settings --------------------------------------------------- */

	/**
	 * The option name only, never its value — with one stated exception.
	 *
	 * Two of the watched options carry personal or structural data, and a log
	 * that copies them becomes a thing worth stealing in its own right. That a
	 * setting changed, and who changed it, is the security signal; what it
	 * changed to is on the settings screen for anyone entitled to see it.
	 *
	 * The exception is the role map, which has no such screen. See below.
	 *
	 * @param mixed $old
	 * @param mixed $new
	 */
	public function on_option_updated( string $option, $old = null, $new = null ): void {
		// MySQL matches option names without regard to case, so a write to
		// DEFAULT_ROLE changed default_role and went unrecorded. Read as the
		// watched name it wrote.
		$watched = array_change_key_case( array_combine( self::watched_options(), self::watched_options() ) );
		$option  = $watched[ strtolower( trim( $option ) ) ] ?? '';

		if ( '' === $option ) {
			return;
		}

		// Checks read these settings and the role map. On a network the
		// write lands in the site being changed, and so does the flag.
		\BetterShield\Plugin::owe_audit_for_change();

		global $wpdb;

		// What a role may do is a privilege change, not a setting change, and
		// it is rated to match: nothing else on this list can quietly promote
		// every account that holds a role.
		$is_roles = ( $wpdb->get_blog_prefix() . 'user_roles' ) === $option;

		$context = array();

		if ( $is_roles && self::initializing_site() ) {
			return;
		}

		if ( $is_roles ) {
			/*
			 * Each add_cap() rewrites the whole map, and a plugin that adds a
			 * hundred capabilities on activation wrote a hundred high rows in
			 * one second (#2080). The change is gathered here and recorded
			 * once, before the writer drains: record_role_changes().
			 */
			$this->note_role_change( $option, is_array( $old ) ? $old : array(), is_array( $new ) ? $new : array() );

			return;
		}

		/*
		 * Three types rather than two. The settings a takeover changes first
		 * carry one of their own because severity alone does not keep a row:
		 * the generic setting event may thin when the log is under load, and
		 * a takeover through a front-end exploit is exactly the request it
		 * would have thinned on.
		 */
		if ( self::is_takeover_setting( $option ) ) {
			$type = 'site_setting_changed';
		} else {
			$type = 'setting_changed';
		}

		$token = \BetterShield\Remediation\Observed::option( $option, $old, $new ); if ( $token ) { $context['change_token'] = $token; }

		// What changed, for the settings whose value says nothing about
		// anyone: a switch and a role. The alert and the timeline say it. On
		// a network the site's switch is read as the network's, so its values
		// here say nothing about who may register.
		if ( in_array( $option, array( 'users_can_register', 'default_role' ), true ) && ! ( 'users_can_register' === $option && is_multisite() ) && is_scalar( $old ) && is_scalar( $new ) && strlen( (string) $old ) <= 64 && strlen( (string) $new ) <= 64 ) {
			$context['before'] = (string) $old;
			$context['after']  = (string) $new;
		}

		Writer::instance()->record(
			$type,
			self::setting_severity( $option ),
			array(
				'object_type' => 'setting',
				'object_id'   => $option,
				'context'     => $context,
			)
		);

		// Where alerts go follows this address while nobody is named.
		if ( 'admin_email' === $option ) {
			\BetterShield\Alerts\Settings::instance()->admin_email_changed( $old, $new );
		}
	}

	/**
	 * A plugin is about to be activated on this request: its activation hook
	 * is what adds roles and capabilities, before `activated_plugin` fires.
	 */
	public function note_activating( string $plugin ): void {
		$this->activating[] = $plugin;
	}

	/**
	 * Drop what was gathered for the next drain without recording it. The
	 * writer's test seam, beside its own buffer.
	 */
	public function forget_pending(): void {
		$this->roles_pending = array();
		$this->activating    = array();
	}

	/**
	 * One change to the role map, gathered for record_role_changes().
	 *
	 * @param array<string, mixed> $old
	 * @param array<string, mixed> $new
	 */
	private function note_role_change( string $option, array $old, array $new ): void {
		$site = get_current_blog_id();
		$diff = self::role_diff( $old, $new );

		if ( ! isset( $this->roles_pending[ $site ] ) ) {
			$this->roles_pending[ $site ] = array(
				'option'        => $option,
				'before'        => $old,
				'granted'       => array(),
				'revoked'       => array(),
				'roles_added'   => array(),
				'roles_removed' => array(),
				'renamed'       => array(),
				'tokens'        => array(),
				// Who made it, as it was when it happened: recorded later,
				// the current account could be a different one, or a task's
				// "system" could have become whoever's request ran it.
				'actor'         => self::actor_now(),
			);
		}

		$pending          = $this->roles_pending[ $site ];
		$pending['after'] = $new;

		// Captured as it happens, as every other observed change is: what
		// the role was is only known now.
		$token = \BetterShield\Remediation\Observed::option( $option, $old, $new );

		if ( '' !== $token ) {
			$pending['tokens'][] = $token;
		}

		foreach ( array( 'granted', 'revoked', 'roles_added', 'roles_removed', 'renamed' ) as $key ) {
			$pending[ $key ] = array_values( array_unique( array_merge( $pending[ $key ], $diff[ $key ] ) ) );
		}

		$this->roles_pending[ $site ] = $pending;
	}

	/**
	 * What the role map went through on this request, as one row per site.
	 *
	 * The quietest privilege change there is, and the row has to answer what
	 * an investigator asks of it: WordPress ships no screen that displays a
	 * role's capability map, so "wp_user_roles changed" was a row nobody
	 * could do anything with. Names only, on both sides: which role, and
	 * which capability. A capability name is not secret, and it is the whole
	 * of what an investigator needs. With them, the roles by the names the
	 * screens give them, and the plugin activated on the same request, which
	 * is what rewrites the map most of the time.
	 */
	public function record_role_changes(): void {
		$pending             = $this->roles_pending;
		$activating          = $this->activating;
		$this->roles_pending = array();
		$this->activating    = array();

		foreach ( $pending as $site => $change ) {
			$switched = is_multisite() && (int) $site !== get_current_blog_id();

			if ( $switched ) {
				switch_to_blog( (int) $site );
			}

			try {
				$context = $this->role_changes( $change, $activating );

				if ( null === $context ) {
					continue;
				}

				// The row links the way back where it stands for one change
				// that has one; the rest are listed where observed changes are.
				if ( 1 === count( $change['tokens'] ) ) {
					$context['change_token'] = $change['tokens'][0];
				}

				Writer::instance()->record(
					'role_capabilities_changed',
					self::role_change_severity( $change ),
					array_merge(
						(array) $change['actor'],
						array(
							'object_type' => 'role',
							'object_id'   => (string) $change['option'],
							'context'     => $context,
						)
					)
				);
			} finally {
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}
	}

	/**
	 * How loud a change to what a role may do is.
	 *
	 * High where an account already holding a role can now do something it
	 * could not: a role that existed before this request, other than the
	 * administrator, gaining a capability. That escalates every account that
	 * holds it, and nothing else on the watched list can.
	 *
	 * Not where a plugin only sets itself up (#2080): its new roles taking
	 * their capabilities, and the administrator, which already runs the site,
	 * taking the plugin's own. Rated high, one store's activation went out as
	 * an instant alert about an escalation. Medium keeps the row and the
	 * digest and drops the interruption.
	 *
	 * Taking a capability away is high as before, except this plugin's own
	 * on the administrator role: the write opt-in is a capability held while
	 * that switch is on, and each turn of it was an alert to the person who
	 * had just turned it. A role removed is high.
	 *
	 * Read from every change the request made, never from the bounded list
	 * the row names.
	 *
	 * @param array<string, mixed> $change What note_role_change() gathered.
	 */
	private static function role_change_severity( array $change ): int {
		// A role removed, or one renamed, so that the Users screen calls the
		// administrators something harmless.
		if ( array() !== (array) $change['roles_removed'] || array() !== (array) $change['renamed'] ) {
			return Writer::SEVERITY_HIGH;
		}

		$new_roles = (array) $change['roles_added'];

		foreach ( (array) $change['granted'] as $entry ) {
			$role = strstr( (string) $entry, ':', true );

			if ( 'administrator' !== $role && ! in_array( $role, $new_roles, true ) ) {
				return Writer::SEVERITY_HIGH;
			}
		}

		foreach ( (array) $change['revoked'] as $entry ) {
			if ( 0 !== strpos( (string) $entry, 'administrator:bettershield_' ) ) {
				return Writer::SEVERITY_HIGH;
			}
		}

		return Writer::SEVERITY_MEDIUM;
	}

	/**
	 * The settings a takeover changes first.
	 *
	 * The site's address, where the administrator's mail goes, whether
	 * strangers may register and as what. Named once, because the answer
	 * decides two separate things: which type the change is recorded under,
	 * which is what keeps the row when the log is under load, and how loud it
	 * is, which is what reaches the instant alert.
	 */
	private static function is_takeover_setting( string $option ): bool {
		// MySQL matches option names without regard to case: DEFAULT_ROLE
		// writes default_role.
		return in_array( strtolower( trim( $option ) ), self::TAKEOVER_SETTINGS, true );
	}

	/**
	 * How loud a change to a watched setting is.
	 *
	 * The five above are rated high, which is where the instant alert starts.
	 * A permalink or visibility change is worth a row and no more.
	 */
	private static function setting_severity( string $option ): int {
		return self::is_takeover_setting( $option ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM;
	}

	/**
	 * Network options worth an event. The four a takeover of a network
	 * reaches for, and nothing else: a network writes its own options as
	 * constantly as a site does.
	 *
	 * @return string[]
	 */
	public static function watched_network_options(): array {
		return array( 'registration', 'admin_email', 'add_new_users', 'site_admins' );
	}

	/**
	 * A watched network setting changed. Recorded once, on the main site:
	 * the network's screen and the main site's Activity are where the
	 * network's owner reads, whichever site the write happened to come from.
	 * As loud as the single-site equivalents, which reach the instant alert.
	 *
	 * @param mixed $value
	 * @param mixed $old_value
	 */
	public function on_network_option_updated( string $option, $value = null, $old_value = null ): void {
		unset( $value, $old_value );

		if ( ! in_array( $option, self::watched_network_options(), true ) ) {
			return;
		}

		\BetterShield\Plugin::owe_audit_for_change();

		if ( 'site_admins' === $option && $this->super_admin_changing ) {
			return;
		}

		$main     = (int) get_main_site_id();
		$switched = get_current_blog_id() !== $main;

		if ( $switched ) {
			switch_to_blog( $main );
		}

		try {
			Writer::instance()->record(
				'site_setting_changed',
				Writer::SEVERITY_HIGH,
				array(
					'object_type' => 'network_setting',
					'object_id'   => $option,
				)
			);
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * The same, for a network setting written where there was none.
	 *
	 * @param mixed $value
	 */
	public function on_network_option_added( string $option, $value = null ): void {
		$this->on_network_option_updated( $option, $value );
	}

	/**
	 * The same, for a watched setting that did not exist a moment ago.
	 *
	 * An empty prior is the honest one here: there was nothing, so a role map
	 * arriving this way reads as every capability in it granted at once, which
	 * is what happened.
	 *
	 * @param mixed $value
	 */
	public function on_option_added( string $option, $value = null ): void {
		$this->on_option_updated( $option, array(), $value );
	}

	/**
	 * What a request's changes to the role map come to, as the row says it,
	 * or null where they came to nothing at all.
	 *
	 * Bounded, because this is written from a hook anybody's code can trigger
	 * and a plugin that rewrites every role on activation would otherwise put
	 * its entire capability table in one log row. Past the cap the count is
	 * kept, so the row says it is a summary rather than pretending to be a
	 * complete list.
	 *
	 * @param array<string, mixed> $change What note_role_change() gathered.
	 * @return array<string, mixed>|null
	 */
	private function role_changes( array $change, array $activating ): ?array {
		if ( array() === array_merge( (array) $change['granted'], (array) $change['revoked'], (array) $change['roles_added'], (array) $change['roles_removed'], (array) $change['renamed'] ) ) {
			return null;
		}

		$context = array(
			'roles_added'   => (array) $change['roles_added'],
			'roles_removed' => (array) $change['roles_removed'],
		);

		if ( array() !== (array) $change['renamed'] ) {
			$context['renamed'] = (array) $change['renamed'];
		}

		foreach ( array( 'granted', 'revoked' ) as $key ) {
			$list            = (array) $change[ $key ];
			$context[ $key ] = array_slice( $list, 0, self::ROLE_CHANGES_LOGGED );

			if ( count( $list ) > self::ROLE_CHANGES_LOGGED ) {
				$context[ $key . '_total' ] = count( $list );
			}
		}

		// The roles touched, by the names the screens give them, which is
		// what the row and the alert are about rather than the option.
		$touched = array();

		foreach ( array_merge( (array) $change['granted'], (array) $change['revoked'] ) as $entry ) {
			$touched[] = (string) strstr( (string) $entry, ':', true );
		}

		$maps  = array( (array) ( $change['after'] ?? array() ), (array) $change['before'] );
		$names = array();

		foreach ( array_unique( array_merge( $touched, (array) $change['roles_added'], (array) $change['roles_removed'], (array) $change['renamed'] ) ) as $slug ) {
			$name = $slug;

			foreach ( $maps as $map ) {
				if ( isset( $map[ $slug ]['name'] ) && '' !== (string) $map[ $slug ]['name'] ) {
					$name = translate_user_role( (string) $map[ $slug ]['name'] );
					break;
				}
			}

			$names[] = $name;
		}

		$context['roles'] = array_slice( $names, 0, self::ROLE_CHANGES_LOGGED );

		if ( array() !== $activating ) {
			$context['activated'] = array_values( array_unique( $activating ) );
		}

		return $context;
	}

	/**
	 * Who is acting right now, as the writer would name them: the site for a
	 * scheduled task, the signed-in account otherwise. Empty where the writer
	 * is better placed to say (nobody signed in).
	 *
	 * @return array<string, mixed>
	 */
	private static function actor_now(): array {
		if ( \BetterShield\Cron\Runner::in_task() ) {
			return array( 'actor_type' => 'system' );
		}

		$user = wp_get_current_user();

		return $user instanceof \WP_User && $user->exists()
			? array(
				'actor_type' => 'user',
				'actor_id'   => (int) $user->ID,
			)
			: array();
	}

	/**
	 * What changed between two role maps, as names, in full.
	 *
	 * @param array<string, mixed> $old
	 * @param array<string, mixed> $new
	 * @return array{renamed: string[], granted: string[], revoked: string[], roles_added: string[], roles_removed: string[]}
	 */
	private static function role_diff( array $old, array $new ): array {
		$granted = array();
		$revoked = array();

		$caps = static function ( $role ): array {
			return isset( $role['capabilities'] ) && is_array( $role['capabilities'] )
				? array_keys( array_filter( $role['capabilities'] ) )
				: array();
		};

		foreach ( $new as $slug => $role ) {
			if ( ! is_array( $role ) ) {
				continue;
			}

			$before = isset( $old[ $slug ] ) && is_array( $old[ $slug ] ) ? $caps( $old[ $slug ] ) : array();
			$after  = $caps( $role );

			foreach ( array_diff( $after, $before ) as $capability ) {
				$granted[] = $slug . ':' . $capability;
			}

			foreach ( array_diff( $before, $after ) as $capability ) {
				$revoked[] = $slug . ':' . $capability;
			}
		}

		// A role whose display name changed and nothing else still changed
		// what the screens call everyone holding it.
		$renamed = array();

		foreach ( $new as $slug => $role ) {
			if ( is_array( $role ) && isset( $old[ $slug ] ) && is_array( $old[ $slug ] ) && (string) ( $old[ $slug ]['name'] ?? '' ) !== (string) ( $role['name'] ?? '' ) ) {
				$renamed[] = (string) $slug;
			}
		}

		return array(
			'renamed'       => $renamed,
			'granted'       => $granted,
			'revoked'       => $revoked,
			'roles_added'   => array_values( array_map( 'strval', array_diff( array_keys( $new ), array_keys( $old ) ) ) ),
			'roles_removed' => array_values( array_map( 'strval', array_diff( array_keys( $old ), array_keys( $new ) ) ) ),
		);
	}

	/** How many capability changes one row names before it summarizes instead. */
	private const ROLE_CHANGES_LOGGED = 25;
}
