<?php
/**
 * Read abilities: the security surface an owner's agent may query.
 *
 * Two decisions define this file. First, the opt-in gates REGISTRATION, not
 * permission: when the owner has not turned the surface on, nothing exists
 * to discover — a registered-but-denied ability still advertises that the
 * capability is there, which is information nobody needed. The category is
 * gated with the abilities, for the same reason. Second, everything is
 * read-only by declaration AND by construction: no callback here mutates
 * anything except the activity log entry that records the query itself.
 *
 * Schemas hold to the subset of JSON Schema Draft-04 that core's validator
 * implements: no $ref, no oneOf/anyOf/allOf, no patternProperties, no
 * dependencies, no additionalProperties. The test suite validates through
 * core's own execution path, not a generic validator.
 *
 * On WordPress below 6.9 the registration hooks never fire and this class
 * is inert, which is the feature gate doing its job silently.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

use BetterShield\Agents\Capture;
use BetterShield\Agents\Connectors;
use BetterShield\Agents\Invocations;
use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Database\Schema;
use BetterShield\Events\Query;
use BetterShield\Events\Types;
use BetterShield\Events\Writer;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Integrity\Manifest;
use BetterShield\Integrity\Restore;
use BetterShield\Integrity\Unpublished;
use BetterShield\Recovery\Readiness;
use BetterShield\Rest\Permissions;
use BetterShield\Support\Claim;
use BetterShield\Support\Ip;
use BetterShield\Undo\Ledger;
use BetterShield\Vulnerabilities\State;
use BetterShield\Vulnerabilities\Source;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Registrar {

	public const OPTION = 'bettershield_abilities_enabled';

	/**
	 * The second opt-in, for the surface that changes things.
	 *
	 * Separate from the read switch and never implied by it: a site owner who
	 * lets an agent read this site's posture has not thereby let it move any
	 * part of it. Turning the read switch off turns this off with it, and
	 * never the reverse.
	 */
	public const WRITE_OPTION = 'bettershield_abilities_write_enabled';

	/**
	 * How many write invocations of one ability are allowed in an hour before
	 * the rest are refused. Low on purpose, and the owner's to raise.
	 */
	public const WRITE_LIMIT_PER_HOUR = 5;

	/**
	 * How many plans for one kind of change are prepared in an hour before the
	 * rest are refused.
	 *
	 * Higher than the ceiling on changing the site, because preparing a plan
	 * changes nothing and an agent reading through a site's protections asks
	 * for more of these than it ever acts on. Still a ceiling: every plan is a
	 * row, and a plan is offered to a connection that may do nothing else.
	 */
	public const PROPOSE_LIMIT_PER_HOUR = 30;

	/**
	 * How many connections' worth of a ceiling the site allows in an hour.
	 *
	 * Each ceiling is counted per credential, so the hub and the owner's own
	 * assistant do not use up each other's. This is the outer cap, so that
	 * adding connections cannot multiply what the site allows without end.
	 */
	public const SITE_LIMIT_FACTOR = 3;

	/**
	 * Items whose apply writes through the guarded file writer.
	 *
	 * A rule block in a shared file at the root of the site, or in the uploads
	 * directory: the blast radius is the whole site, and it stays the owner's
	 * own switch. These are not applied by an agent and they are not described
	 * to one either — a plan for weakening something is most of the way to
	 * asking for it.
	 *
	 * @var string[]
	 */
	public const HUMAN_ONLY_ITEMS = array( 'uploads_php', 'directory_browsing', 'sensitive_files' );

	/** The ledger key a plugin deactivation made through an ability records under. */
	private const DEACTIVATION_KEY = 'agent_deactivate_plugin';

	/**
	 * The abstract event vocabulary the ability speaks, mapped to the
	 * concrete types the log stores. Agents get a stable, small enum;
	 * renaming or adding internal types never breaks a caller.
	 */
	private const EVENT_GROUPS = array(
		'login'            => array( 'login', 'logout', 'login_lockout_started', 'login_lockout_emailed', 'login_unlock_requested', 'surface_closed', 'comment_held', 'password_reset_throttled', 'registration_refused', 'turnstile_refused', 'turnstile_unreachable', 'login_lockout_cleared', 'sessions_ended', 'sessions_reset', 'session_ended_by_owner', 'session_reported_by_owner', 'login_new_network', 'email_change_held', 'email_change_confirmed', 'sudo_refused', 'sudo_confirmed', 'app_password_used', 'xmlrpc_used', 'passkey_used' ),
		'login_failed'     => array( 'login_failed', 'login_blocked', 'honeypot_rejected' ),
		/*
		 * Every way an account or its privileges can change. The three that
		 * were missing are the ones an escalation actually looks like: a role
		 * added alongside the others, a change to what a role may do at all,
		 * and the address swap that makes the reset which follows look
		 * legitimate. An agent watching for privilege escalation through this
		 * filter was watching without them.
		 */
		'user_change'      => array( 'user_created', 'user_deleted', 'user_removed_from_site', 'user_role_changed', 'user_role_granted', 'user_role_revoked', 'temporary_access_end_refused', 'account_suspended', 'account_suspension_lifted', 'handover_completed', 'role_capabilities_changed', 'user_email_changed', 'username_changed', 'password_changed', 'password_reset_requested', 'password_reset_unsent', 'app_password_created', 'app_password_limited', 'app_password_unlimited', 'app_password_refused', 'account_takeover_sequence', 'app_password_revoked', 'password_refused_breached', 'canary_used', 'canary_disarmed', 'canary_page_touched', 'incident_status_changed', 'incident_opened', 'dormant_privileged_login', 'incident_code_added', 'incident_cron_unanswered', 'incident_account_demoted', 'incident_password_held', 'password_hold_lifted' ),
		'plugin_change'    => array( 'plugin_activated', 'plugin_deactivated', 'plugin_installed', 'plugin_updated', 'update_code_changed', 'plugin_deleted', 'package_unverified', 'package_partly_checked', 'package_adopted', 'package_adoption_undone', 'response_taken', 'response_undone', 'response_rolled_back', 'plugin_update_applied', 'plugin_update_undone', 'extension_quarantined', 'extension_put_back' ),
		'theme_change'     => array( 'theme_changed', 'theme_installed', 'theme_updated', 'theme_deleted', 'theme_plugin_file_edited' ),
		'setting_change'   => array( 'site_created', 'site_status_changed', 'site_deleted', 'cron_events_removed', 'cron_events_restored', 'rest_route_watched', 'rest_route_closed', 'rest_route_reopened', 'canary_page_changed', 'canary_page_tested', 'setting_changed', 'site_setting_changed', 'takeover_setting_refused', 'password_policy_updated', 'login_protection_updated', 'two_factor_policy_changed', 'alerts_updated', 'uninstall_choice_changed', 'settings_imported', 'settings_exported', 'keys_rotated', 'usage_tracking_enabled', 'usage_tracking_disabled', 'hub_link_enabled', 'hub_link_disabled', 'coexistence_choices_saved' ),
		/*
		 * A change to a file, and every way the record of one is undone or
		 * taken away: a restore reversed, a change told to stop being
		 * reported, and the quarantined copy retrieved or destroyed. An agent
		 * watching this filter for an intrusion and its handling was seeing
		 * only the first half of the story.
		 */
		'file_change'      => array( 'file_changed', 'file_restored', 'file_restore_undone', 'file_change_suppressed', 'file_change_unsuppressed', 'file_expected', 'file_expected_undone', 'file_changes_expected', 'file_changes_unexpected', 'file_selection_expected', 'file_package_rechecked', 'file_quarantined', 'leftover_tool_quarantined', 'exposed_file_quarantined', 'quarantine_downloaded', 'quarantine_deleted', 'quarantine_sealed', 'quarantine_seal_undone', 'content_links_rewritten', 'content_links_restored', 'folder_mode_tightened', 'folder_mode_restored', 'config_mode_tightened', 'config_mode_restored', 'vulnerability_found', 'vulnerability_resolved', 'core_updated', 'incident_code_modified' ),
		'two_factor'       => array( 'two_factor_enabled', 'two_factor_disabled', 'two_factor_failed', 'two_factor_skipped', 'two_factor_backup_used', 'two_factor_backup_reissued', 'two_factor_imported', 'two_factor_import_failed', 'two_factor_import_undone', 'two_factor_moved', 'two_factor_not_moved', 'passkey_registered', 'passkey_removed', 'passkey_refused', 'passkey_policy_changed', 'password_refused_passkey_only', 'password_refused_repeated' ),
		'protection'       => array( 'hardening_applied', 'hardening_reverted', 'hardening_failed', 'hardening_revert_failed', 'hardening_verified', 'finding_opened', 'finding_resolved', 'finding_suppressed', 'finding_unsuppressed', 'finding_snoozed', 'finding_woken', 'site_marked_staging', 'site_marked_moved', 'site_identity_undone', 'safe_mode_entered', 'safe_mode_exited', 'network_safe_mode_entered', 'network_safe_mode_exited', 'network_2fa_policy_changed', 'network_passkey_policy_changed', 'recovery_link_generated', 'recovery_link_failed', 'recovery_preflight_overridden', 'recovery_receipt_confirmed', 'recovery_receipt_withdrawn', 'csp_enforced', 'csp_report_only_restored', 'lockdown_entered', 'lockdown_left', 'incident_response_applied', 'incident_cron_unscheduled', 'observed_change_response', 'cloudflare_action_taken', 'cloudflare_action_undone', 'cloudflare_block_refused', 'cloudflare_block_failed', 'log_resealed', 'log_reseal_refused', 'csp_source_allowed', 'csp_source_removed', 'csp_reports_cleared', 'csp_reports_restored', 'outbound_refused', 'outbound_internal' ),
		/*
		 * Was declared and left empty, so it answered "no agent activity" to
		 * a site full of it — indistinguishable from the truth. The three
		 * that join `ability_used` here are the ones an agent watching this
		 * filter actually needs: an ability refused to whoever asked, the
		 * recording being stopped, and the recording falling short. A filter
		 * that returned only our own queries would report a quiet site while
		 * something was being turned away from it repeatedly.
		 */
		'agent_invocation' => array( 'ability_used', 'ability_added', 'ability_widened', 'ability_changes_accepted', 'ability_changes_accept_undone', 'agent_new_network', 'agent_check_requested', 'agent_triage_requested', 'agent_permission_denied', 'agent_refusals_repeated', 'agent_capture_removed', 'agent_capture_truncated', 'agent_proposal_made', 'write_confirmation_minted', 'write_confirmation_withdrawn', 'agent_proposal_declined', 'agent_write_applied', 'agent_write_applied_direct', 'agent_write_reverted', 'agent_write_refused', 'mcp_connected', 'mcp_rotated', 'mcp_disconnected', 'mcp_app_granted', 'mcp_app_revoked', 'mcp_auth_refused', 'mcp_locked_out', 'mcp_refresh_reused' ),
		'operations'      => array( 'activity_unusual', 'first_run_completed', 'quick_setup_completed', 'quick_setup_skipped', 'scan_completed', 'integrity_scan_completed', 'unpublished_watch_ran', 'task_run_requested', 'task_run_finished', 'task_run_failed', 'vulnerability_check_failed', 'breach_check_unavailable', 'security_txt_published', 'security_txt_withdrawn', 'buffer_overflow', 'events_sampled', 'log_migrated', 'schema_repaired', 'schema_repair_failed' ),
		'alerts'          => array( 'maintenance_window_started', 'maintenance_window_closed', 'alert_sent', 'account_notice_sent', 'alert_delivery_failed', 'alert_feedback' ),
		'ai'              => array( 'ai_explanation_generated' ),
	);

	private static ?Registrar $instance = null;

	private ?Source $vulnerability_source = null;

	public static function instance(): Registrar {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'wp_abilities_api_categories_init', array( $this, 'register_category' ) );
		add_action( 'wp_abilities_api_init', array( $this, 'register_abilities' ) );

		/*
		 * Once per admin page load, and deliberately not on every request.
		 * The opt-in and the capability it grants are two stores that can
		 * disagree, and a person opening the dashboard is the moment to put
		 * them back in step; doing it on every request would also overrule an
		 * owner who took the capability away with a role editor before they
		 * had finished the sentence.
		 */
		add_action( 'admin_init', array( self::class, 'reconcile_write_capability' ) );
	}

	/**
	 * The vulnerability source the ability reads.
	 *
	 * Swapped through the `bettershield_vulnerability_feed` filter rather than
	 * through a setter here: a public mutator on a singleton lets any other
	 * plugin on the site replace what this answers about vulnerabilities, and
	 * a filter is both the house pattern and something an audit can see.
	 */
	public function vulnerability_source(): Source {
		if ( null === $this->vulnerability_source ) {
			$this->vulnerability_source = new State();
		}

		return $this->vulnerability_source;
	}

	/* ---- the gate ----------------------------------------------------------- */

	public static function is_enabled(): bool {
		return '1' === get_option( self::OPTION );
	}

	/**
	 * Flip the opt-in. One path for the screen, the terminal and a settings
	 * import, so every flip is on the record the same way, its way back
	 * written first.
	 *
	 * @return true|\WP_Error
	 */
	public static function set_enabled( bool $enabled ) {
		$undo = \BetterShield\Undo\SettingsLedger::record( 'abilities', array( 'enabled' => self::is_enabled() ), array( 'enabled' => $enabled ) );

		if ( false === $undo ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $enabled ? '1' : '0', true );

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array( 'enabled' => $enabled ),
			)
		);

		// Reading is the floor the write surface stands on. Taking the floor
		// away takes the surface with it, in the same act, so there is never a
		// moment where writes are on and reads are off.
		if ( ! $enabled ) {
			return self::set_write_enabled( false );
		}

		return true;
	}

	/* ---- the second gate ----------------------------------------------------- */

	public static function write_enabled(): bool {
		return '1' === get_option( self::WRITE_OPTION );
	}

	/**
	 * Flip the write opt-in, and grant or take back the capability with it.
	 *
	 * The capability is granted here and nowhere else. Activation never maps
	 * it and an update never puts it back, so an administrator holds it
	 * because this switch was turned on and stops holding it the moment it is
	 * turned off.
	 *
	 * @return true|\WP_Error
	 */
	public static function set_write_enabled( bool $enabled ) {
		if ( $enabled && ! self::is_enabled() ) {
			return new \WP_Error(
				'bettershield_read_abilities_off',
				__( 'Turn on agent access first. Changing this site through an ability needs the read surface it is built on.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// A new opt-in never widens grants from before changes were turned off.
		// Rotate again before enabling, so a failed withdrawal cannot be bypassed.
		if ( $enabled && ! self::write_enabled() && ! \BetterShield\Mcp\WriteGrants::withdraw() ) {
			return new \WP_Error( 'bettershield_grants_not_narrowed', __( 'Existing assistant access could not be narrowed. Agent changes stay off; try again before reconnecting an assistant.', 'bettershield' ), array( 'status' => 503 ) );
		}
		// Its way back first, as the read switch's (#1824).
		if ( false === \BetterShield\Undo\SettingsLedger::record( 'agent_writes', array( 'enabled' => self::write_enabled() ), array( 'enabled' => $enabled ) ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::WRITE_OPTION, $enabled ? '1' : '0', true );
		$saved = \BetterShield\Mcp\WriteGrants::current();
		if ( ! $saved['valid'] || $saved['enabled'] !== $enabled ) {
			return new \WP_Error( 'bettershield_write_access_not_saved', __( 'Agent access could not be saved. Refresh the page and try again.', 'bettershield' ), array( 'status' => 503 ) );
		}

		$role = get_role( 'administrator' );

		if ( null !== $role ) {
			if ( $enabled ) {
				$role->add_cap( Capabilities::WRITE_POSTURE );
			} else {
				$role->remove_cap( Capabilities::WRITE_POSTURE );
			}

			self::refresh_current_capabilities();
		}

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => self::WRITE_OPTION,
				'context'     => array( 'enabled' => $enabled ),
			)
		);

		if ( ! $enabled && ! \BetterShield\Mcp\WriteGrants::withdraw() ) {
			return new \WP_Error( 'bettershield_grants_not_narrowed', __( 'Agent changes are off, but existing assistant access could not be narrowed. Try turning changes off again before reconnecting an assistant.', 'bettershield' ), array( 'status' => 503 ) );
		}
		return true;
	}

	/**
	 * The abilities that exist only while the write opt-in is on.
	 *
	 * Read off the definitions rather than restated, so a surface that names
	 * what is behind the second switch cannot fall out of step with what is
	 * actually behind it.
	 *
	 * @return string[]
	 */
	public static function write_ability_names(): array {
		return array_keys( self::instance()->write_definitions() );
	}

	/**
	 * Whether the administrator role currently holds the write capability:
	 * what the switch actually did, and whether the stores have drifted.
	 */
	public static function write_capability_granted(): bool {
		$role = get_role( 'administrator' );

		return null !== $role && $role->has_cap( Capabilities::WRITE_POSTURE );
	}

	/**
	 * Whether the account reading a screen holds it: what its own screens
	 * say, and what a credential it mints may carry. The role holding it is
	 * not this account holding it — a delegated manager runs this plugin and
	 * was told it held the permission for agent changes because the
	 * administrator role did. Asked of both, so a super admin, who passes any
	 * capability check, is not told it holds one the switch never granted.
	 */
	public static function write_capability_held(): bool {
		return self::write_capability_granted() && current_user_can( Capabilities::WRITE_POSTURE );
	}

	/**
	 * Put the capability back in step with the opt-in.
	 *
	 * Two stores hold one decision: an option the owner set, and a capability
	 * on the administrator role that the option is supposed to carry. They can
	 * come apart — a role editor, a partial restore, a migration that copied
	 * options and not roles — and while they do, `write_enabled()` says yes
	 * and `can_write()` says no.
	 *
	 * The option wins, because it is the decision and the capability is its
	 * consequence. Nothing is logged here directly: changing what a role may
	 * do rewrites the roles option, and the activity log already records that
	 * as a capability change with the names on both sides.
	 */
	public static function reconcile_write_capability(): void {
		// `admin_init` also fires on admin-ajax.php and admin-post.php with
		// nobody signed in, which a store's queue runner reaches about once a
		// minute. The moment this waits for is somebody opening the
		// dashboard, so a request that is not one reads nothing.
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		$role = get_role( 'administrator' );

		if ( null === $role ) {
			return;
		}

		$wanted = self::write_enabled();
		$held   = $role->has_cap( Capabilities::WRITE_POSTURE );

		if ( $wanted === $held ) {
			return;
		}

		if ( $wanted ) {
			$role->add_cap( Capabilities::WRITE_POSTURE );
		} else {
			$role->remove_cap( Capabilities::WRITE_POSTURE );
		}

		self::refresh_current_capabilities();
	}

	/**
	 * The signed-in account's capabilities read again from its roles.
	 *
	 * An account's capabilities are worked out once, when it is loaded, so a
	 * role changed later in the same request is not what it reports — and the
	 * screen that answers with what this account holds, right after the switch
	 * moved it, answered with what it held before.
	 */
	private static function refresh_current_capabilities(): void {
		$user = wp_get_current_user();

		if ( $user->exists() ) {
			$user->get_role_caps();
		}
	}

	/**
	 * The gate on every write ability, re-checked inside every callback.
	 *
	 * Four conditions, each independent: the read opt-in, the write opt-in,
	 * the capability that manages this plugin, and the capability that exists
	 * only while the owner has asked for a write surface at all.
	 */
	public static function can_write(): bool {
		return self::is_enabled()
			&& self::write_enabled()
			&& current_user_can( Capabilities::MANAGE )
			&& current_user_can( Capabilities::WRITE_POSTURE );
	}

	/**
	 * Whether deactivating another plugin is offered at all.
	 *
	 * Built, tested and off. wordpress.org's guidance on a plugin changing
	 * another plugin's activation status is what keeps it off, and the filter
	 * is what an owner running their own build turns it on with.
	 */
	public static function deactivation_enabled(): bool {
		return (bool) apply_filters(
			'bettershield_write_deactivation_enabled',
			defined( 'BETTERSHIELD_WRITE_DEACTIVATION' ) && BETTERSHIELD_WRITE_DEACTIVATION
		);
	}

	/**
	 * Whether the way back in was proved recently enough to allow a change to
	 * how people sign in.
	 *
	 * Two conditions, and both are about the link rather than about this
	 * feature: it has to exist and be usable, and the daily check has to have
	 * looked within the last day. An older answer is an answer about a site
	 * that may have moved since.
	 *
	 * @param array<string, mixed>|null $report The readiness report already read, or null to read it.
	 */
	public static function recovery_ready( ?array $report = null ): bool {
		$report = $report ?? Readiness::report();

		if ( 'available' !== ( $report['link'] ?? '' ) ) {
			return false;
		}

		$checked = null === ( $report['checked_at'] ?? null ) ? 0 : (int) strtotime( (string) $report['checked_at'] );

		return $checked > 0 && $checked > time() - DAY_IN_SECONDS;
	}

	/**
	 * Whether the platform can register abilities at all (WordPress 6.9+).
	 */
	public static function is_available(): bool {
		return function_exists( 'wp_register_ability' );
	}

	/**
	 * The shared permission callback: two independent gates. The opt-in is
	 * re-checked here even though registration already required it — a
	 * toggle turned off between requests must deny on the very next call,
	 * whatever a registry cache thinks.
	 */
	public static function can_read(): bool {
		return self::is_enabled() && current_user_can( Capabilities::READ_POSTURE );
	}

	/**
	 * The activity log's own gate: reading the record is a different
	 * privilege from reading the posture, on the screen and here alike.
	 */
	public static function can_read_activity(): bool {
		return self::is_enabled() && current_user_can( Capabilities::READ_ACTIVITY );
	}

	/**
	 * The gate for what only an administrator of this plugin may read. The
	 * connector report is the one: it carries where each credential is kept
	 * and the last four characters of it, which the owner's own route serves
	 * to `manage` alone. An ability gated lower would hand an agent what the
	 * same person is refused on screen.
	 */
	public static function can_manage(): bool {
		return self::is_enabled() && current_user_can( Capabilities::MANAGE );
	}

	/**
	 * Whether this process already registered the category. Categories have
	 * no unregister path, and re-registering warns; per-request in
	 * production this is one call, but a test process fires the action many
	 * times.
	 */
	private static bool $category_registered = false;

	public function register_category(): void {
		if ( ! self::is_enabled() || ! function_exists( 'wp_register_ability_category' ) || self::$category_registered ) {
			return;
		}

		wp_register_ability_category(
			'bettershield',
			array(
				'label'       => __( 'BetterShield', 'bettershield' ),
				'description' => __( 'Security posture, activity and integrity for this site. Reading is always offered. Changing the site is offered only where the owner has turned that on, and a change is then either one the undo record can take back exactly or one a person has to allow first.', 'bettershield' ),
			)
		);

		self::$category_registered = true;
	}

	public function register_abilities(): void {
		if ( ! self::is_enabled() || ! self::is_available() ) {
			return; // Owner has not opted in: register nothing at all.
		}

		foreach ( $this->definitions() as $name => $args ) {
			// A network's own read exists only on a network: registered on a
			// single site it was offered to every connection and refused
			// every call (#1825).
			if ( ! is_multisite() && in_array( $name, ReadSurface::NETWORK_READS, true ) ) {
				continue;
			}

			wp_register_ability( $name, self::with_input_default( $args ) );
		}

		/*
		 * Both halves of the second opt-in, not just the option. Registration
		 * is the tool catalog a paired assistant reads, so a site whose stores
		 * have drifted apart would otherwise advertise four write tools and
		 * refuse every call to them — registering and denying, which is the
		 * pattern the read half of this surface exists to avoid. The repair
		 * runs on the next admin page load; until it does, nothing is on the
		 * wire.
		 */
		if ( ! self::write_enabled() || ! self::write_capability_granted() ) {
			return; // The second opt-in is off, or incomplete: the write surface does not exist to be found.
		}

		foreach ( $this->write_definitions() as $name => $args ) {
			wp_register_ability( $name, self::with_input_default( $args ) );
		}
	}

	/**
	 * An ability whose input is all optional may be run with none at all.
	 *
	 * Core validates a missing input as null against the schema, and a schema
	 * of type object with no default refused it: "input is not of type
	 * object", through core's REST endpoint and `execute()` alike, wherever
	 * a client sent nothing (#1788). This plugin's own server always sends an
	 * object, so only other clients met it. Core's own abilities say
	 * `default: []`; so do these.
	 *
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>
	 */
	private static function with_input_default( array $args ): array {
		$schema = $args['input_schema'] ?? null;

		if ( ! is_array( $schema ) || 'object' !== ( $schema['type'] ?? null ) || array_key_exists( 'default', $schema ) || array() !== ( $schema['required'] ?? array() ) ) {
			return $args;
		}

		$args['input_schema']['default'] = array();

		return $args;
	}

	/* ---- definitions --------------------------------------------------------- */

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private function definitions(): array {
		$read_meta = array(
			'category'            => 'bettershield',
			'permission_callback' => array( self::class, 'can_read' ),
			// Annotations are hints with no runtime enforcement — the
			// permission callback above is the only real gate — but they are
			// declared anyway, explicitly, because `destructive` DEFAULTS TO
			// TRUE and an undeclared read ability advertises itself as
			// dangerous.
			'meta'                => array(
				'annotations'  => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
				'show_in_rest' => true,
			),
		);

		$definitions = array(

			'bettershield/get-security-posture'   => $read_meta + array(
				'label'            => __( 'Get the security score', 'bettershield' ),
				'description'      => __( 'The security score, grade, and open findings for this site, each with a plain-language explanation.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'include_resolved' => array(
							'type'        => 'boolean',
							'default'     => false,
							'description' => 'Also include findings that are fixed or marked not applicable.',
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'score'          => array(
							'type'    => 'integer',
							'minimum' => 0,
							'maximum' => 100,
						),
						'grade'          => array(
							'type' => 'string',
							'enum' => array( 'A', 'B', 'C', 'D', 'F' ),
						),
						'generated_at'   => array( 'type' => 'string' ),
						'findings_count' => array(
							'type'    => 'integer',
							'minimum' => 0,
						),
						'findings'       => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'          => array( 'type' => 'string' ),
									'severity'    => array(
										'type' => 'string',
										'enum' => array( 'critical', 'high', 'medium', 'low', 'info' ),
									),
									'status'      => array( 'type' => 'string' ),
									'title'       => array( 'type' => 'string' ),
									'explanation' => array( 'type' => 'string' ),
									'remediable'  => array( 'type' => 'boolean' ),
									'hardening_item' => array( 'type' => 'string' ),
									'applied'     => array( 'type' => 'boolean' ),
									'reversible'  => array( 'type' => 'boolean' ),
									'snoozed_until' => array(
										'type'        => 'string',
										'description' => 'ISO 8601 UTC. Present only while the owner has snoozed this open finding: it stays open and counted in the score, and is left out of what needs attention until then.',
									),
								),
								'required'   => array( 'id', 'severity', 'title', 'remediable' ),
							),
						),
						'checks_unknown' => array(
							'type'        => 'array',
							'description' => 'Checks that could not be evaluated on the last run, each with the reason. An empty list means every check answered.',
							'items'       => array(
								'type'       => 'object',
								'properties' => array(
									'check'            => array( 'type' => 'string' ),
									'title'            => array( 'type' => 'string' ),
									'reason_code'      => array( 'type' => 'string' ),
									'reason'           => array( 'type' => 'string' ),
									'last_answered_at' => array( 'type' => 'string' ),
								),
								'required'   => array( 'check', 'title' ),
							),
						),
					),
					'required'   => array( 'score', 'grade', 'generated_at', 'findings_count', 'findings', 'checks_unknown' ),
				),
				'execute_callback' => array( $this, 'get_security_posture' ),
			),

			// The log's gate, not the posture's: `+` keeps the left operand's
			// keys, so the override has to come first.
			'bettershield/query-activity'         => array( 'permission_callback' => array( self::class, 'can_read_activity' ) ) + $read_meta + array(
				'label'            => __( 'Query activity', 'bettershield' ),
				'description'      => __( 'A bounded, paginated window over the activity log. Retention limits are applied silently and reported in the response.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'since'      => array(
							'type'        => 'string',
							'description' => 'ISO 8601 UTC. Clamped to the retention limit.',
						),
						'until'      => array(
							'type'        => 'string',
							'description' => 'ISO 8601 UTC.',
						),
						'event_type' => array(
							'type' => 'string',
							// Named from the map itself, so the two cannot
							// disagree about what a caller may ask for.
							'enum' => array_keys( self::EVENT_GROUPS ),
						),
						'limit'      => array(
							'type'    => 'integer',
							'minimum' => 1,
							'maximum' => 200,
							'default' => 50,
						),
						'cursor'     => array(
							'type'        => 'string',
							// Empty is the first page, as it always was.
							'pattern'     => '^[0-9]*$',
							'description' => 'Opaque cursor from a previous response.',
						),
						'sites'      => array(
							'type'        => 'array',
							'items'       => array( 'type' => 'integer' ),
							'description' => 'Site ids on a network. Honored only for a caller who may read the whole network; otherwise the call answers for the current site.',
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'events'                  => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'           => array( 'type' => 'integer' ),
									'occurred_at'  => array( 'type' => 'string' ),
									'type'         => array( 'type' => 'string' ),
									'actor_type'   => array( 'type' => 'string' ),
									'actor_label'  => array( 'type' => 'string' ),
									'object_type'  => array( 'type' => 'string' ),
									'object_id'    => array( 'type' => 'string' ),
									'summary'      => array( 'type' => 'string' ),
									'ip_truncated' => array( 'type' => 'string' ),
									'site_id'      => array( 'type' => 'integer' ),
								),
								'required'   => array( 'id', 'occurred_at', 'type' ),
							),
						),
						'cursor'                  => array( 'type' => 'string' ),
						'has_more'                => array( 'type' => 'boolean' ),
						'truncated_by_retention'  => array( 'type' => 'boolean' ),
					),
					'required'   => array( 'events', 'has_more', 'truncated_by_retention' ),
				),
				'execute_callback' => array( $this, 'query_activity' ),
			),

			'bettershield/get-integrity-status'   => $read_meta + array(
				'label'            => __( 'Get file check results', 'bettershield' ),
				'description'      => __( 'File integrity state against wordpress.org checksums: hashes and paths only, never file contents. The open changes, or with list set to expected the accepted ones; whether a check is running and how far it has got; and how many are accepted.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'cursor' => array(
							'type'        => 'string',
							'description' => 'The next_cursor from a previous response, to read the changes past the ones it carried.',
						),
						'list'   => array(
							'type'        => 'string',
							'enum'        => array( 'open', 'expected' ),
							'description' => 'Which changes to list: the open ones (the default), or the accepted ones (expected). A cursor belongs to the list that gave it.',
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'monitoring_active' => array(
							'type'        => 'boolean',
							'description' => 'True when a file check has finished within two of its own scheduled intervals; false on a site whose checks have stopped.',
						),
						'status_note'       => array( 'type' => 'string' ),
						'last_check_at'     => array( 'type' => 'string' ),
						'next_check_at'     => array(
							'type'        => 'string',
							'description' => 'The next scheduled check, or empty when the appointment on record has already passed.',
						),
						'missed_check_at'   => array(
							'type'        => 'string',
							'description' => 'The appointment that has passed without being kept, or empty. Empty in both fields means no check is scheduled.',
						),
						'files_checked'     => array(
							'type'    => 'integer',
							'minimum' => 0,
						),
						'open_changes'      => array(
							'type'    => 'integer',
							'minimum' => 0,
						),
						'unverifiable'      => array(
							'type'    => 'integer',
							'minimum' => 0,
						),
						'changes'           => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'            => array(
										'type'        => 'integer',
										'minimum'     => 1,
										'description' => 'The change_id propose-file-restore takes.',
									),
									'path'          => array( 'type' => 'string' ),
									'change_type'   => array(
										'type' => 'string',
										'enum' => array( 'added', 'modified', 'removed', 'unreadable', 'package_mismatch' ),
									),
									'context'       => array(
										'type' => 'string',
										'enum' => array( Manifest::CONTEXT_CORE, Manifest::CONTEXT_PLUGIN, Manifest::CONTEXT_EXTRA, Unpublished::CONTEXT_THEME, Unpublished::CONTEXT_DROPIN, Unpublished::CONTEXT_MUPLUGIN, Unpublished::CONTEXT_CONFIG, Unpublished::CONTEXT_UNLISTED ),
									),
									'slug'          => array( 'type' => 'string' ),
									'first_seen_at' => array( 'type' => 'string' ),
									'hash_before'   => array( 'type' => 'string' ),
									'hash_after'    => array( 'type' => 'string' ),
								),
								'required'   => array( 'id', 'path', 'change_type' ),
							),
						),
						/*
						 * The list above is capped and `open_changes` is not,
						 * so this is what tells a caller which of the two it is
						 * reading. Required, so its absence cannot be read as
						 * false by a client talking to an older release.
						 */
						'changes_truncated' => array(
							'type'        => 'boolean',
							'description' => 'True when open_changes exceeds what this list carries.',
						),
						/*
						 * Saying the list is short is half an answer. This is
						 * the other half: what to pass back as `cursor` to read
						 * the rest, and empty when there is no rest.
						 */
						'next_cursor'       => array(
							'type'        => 'string',
							'description' => 'Pass back as cursor to read the next page of changes. Empty when this page is the last.',
						),
						/*
						 * And the third answer, which is neither. A cursor
						 * that cannot be resolved is not the end of the list,
						 * and folding it into `changes_truncated` handed a
						 * caller "there is more" with nothing to fetch it
						 * with and no way to tell that apart from an ordinary
						 * end. The REST controller and the CLI both branch on
						 * this; the ability had nowhere to put it.
						 */
						'changes_error'     => array(
							'type'        => 'string',
							'description' => 'Why the change list could not be read. Empty when it was read. When set, changes is what could be gathered and changes_truncated says nothing about paging.',
						),
						'running'           => array( 'type' => 'boolean' ),
						'progress'          => array(
							'type'        => 'object',
							'description' => 'How far a running check has got: which target of how many, the pass it is on, files compared so far and what is being checked now. Zeros when none is running.',
							'properties'  => array(
								'target'  => array( 'type' => 'integer' ),
								'targets' => array( 'type' => 'integer' ),
								'phase'   => array( 'type' => 'string' ),
								'checked' => array( 'type' => 'integer' ),
								'label'   => array( 'type' => 'string' ),
							),
							'required'    => array( 'target', 'targets', 'phase', 'checked', 'label' ),
						),
						'expected_total'    => array(
							'type'    => 'integer',
							'minimum' => 0,
						),
					),
					'required'   => array( 'monitoring_active', 'files_checked', 'changes', 'changes_truncated', 'running', 'progress', 'expected_total' ),
				),
				'execute_callback' => array( $this, 'get_integrity_status' ),
			),

			'bettershield/get-agent-surface'      => $read_meta + array(
				'label'            => __( 'See what AI tools other plugins offer', 'bettershield' ),
				'description'      => __( 'What agents can do on this site: every registered ability with its declared annotations, REST exposure and low-privilege reachability, and application-password holdings as counts and ages, never names.', 'bettershield' ),
				'input_schema'     => array( 'type' => 'object' ),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'abilities_api_available' => array( 'type' => 'boolean' ),
						'abilities'               => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'name'                  => array( 'type' => 'string' ),
									'registering_source'    => array( 'type' => 'string' ),
									'registering_source_label' => array( 'type' => 'string' ),
									'annotated_readonly'    => array( 'type' => 'boolean' ),
									'annotated_destructive' => array( 'type' => 'boolean' ),
									'exposed_in_rest'       => array( 'type' => 'boolean' ),
									'low_privilege_access'  => array(
										'type' => 'string',
										'enum' => array( 'denied', 'allowed', 'unknown' ),
									),
								),
								'required'   => array( 'name', 'low_privilege_access' ),
							),
						),
						'application_passwords'   => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'user_id'            => array( 'type' => 'integer' ),
									'role'               => array( 'type' => 'string' ),
									'count'              => array(
										'type'    => 'integer',
										'minimum' => 0,
									),
									'oldest_unused_days' => array(
										'type'    => 'integer',
										'minimum' => 0,
									),
								),
								'required'   => array( 'user_id', 'count' ),
							),
						),
					),
					'required'   => array( 'abilities_api_available', 'abilities', 'application_passwords' ),
				),
				'execute_callback' => array( $this, 'get_agent_surface' ),
			),

			'bettershield/get-vulnerability-state' => $read_meta + array(
				'label'            => __( 'Get vulnerability state', 'bettershield' ),
				'description'      => __( 'Known vulnerabilities affecting what this site runs. States plainly when no data source is configured, since an empty answer is not a clean bill of health.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'severity_min' => array(
							'type'    => 'string',
							'enum'    => array( 'critical', 'high', 'medium', 'low', 'info' ),
							'default' => 'info',
						),
						'limit'        => array(
							'type'    => 'integer',
							'minimum' => 1,
							'maximum' => 1000,
							'default' => 50,
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'source_available' => array( 'type' => 'boolean' ),
						'complete'         => array( 'type' => 'boolean' ),
						'stale'            => array( 'type' => 'boolean' ),
						'error'            => array( 'type' => 'string' ),
						'status_note'      => array( 'type' => 'string' ),
						'last_updated_at'  => array( 'type' => 'string' ),
						// How many match the severity asked for, and whether the
						// list below stopped at the limit before them all.
						'total'            => array( 'type' => 'integer' ),
						'truncated'        => array( 'type' => 'boolean' ),
						'affected'         => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'type'              => array( 'type' => 'string' ),
									'match_status'      => array( 'type' => 'string' ),
									'advisory_ids'      => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
									'exploited'         => array( 'type' => array( 'boolean', 'null' ) ),
									'advisories'        => array( 'type' => 'array', 'items' => array( 'type' => 'object' ) ),
									'slug'              => array( 'type' => 'string' ),
									'name'              => array( 'type' => 'string' ),
									'installed_version' => array( 'type' => 'string' ),
									'vulnerable'        => array( 'type' => 'boolean' ),
									'severity'          => array( 'type' => array( 'string', 'null' ) ),
									'severity_known'    => array( 'type' => 'boolean' ),
									'cve_ids'           => array(
										'type'  => 'array',
										'items' => array( 'type' => 'string' ),
									),
									'fixed_in'          => array( 'type' => 'string' ),
									'patch_available'   => array( 'type' => 'boolean' ),
									'disclosed_at'      => array( 'type' => 'string' ),
								),
								'required'   => array( 'slug', 'vulnerable' ),
							),
						),
					),
					'required'   => array( 'source_available', 'affected' ),
				),
				'execute_callback' => array( $this, 'get_vulnerability_state' ),
			),

			/*
			 * What ran on this site, and what was refused. Gated on the
			 * activity capability rather than the posture one, like the log
			 * it sits beside: this is a record of what happened, not a
			 * statement of how the site is configured.
			 */
			'bettershield/query-agent-activity'   => array( 'permission_callback' => array( self::class, 'can_read_activity' ) ) + $read_meta + array(
				'label'            => __( 'Query agent activity', 'bettershield' ),
				'description'      => __( 'A bounded, paginated window over Abilities API invocations on this site, whoever registered the ability. Inputs are recorded as digests and never returned. Retention limits are applied silently and reported in the response.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'outcome'    => array(
							'type'        => 'string',
							// Named from the capture layer itself, so the two
							// cannot disagree about what a caller may ask for.
							'enum'        => Capture::OUTCOMES,
							'description' => 'Narrow to one outcome. permission_denied is the one worth watching.',
						),
						'ability'    => array(
							'type'        => 'string',
							'description' => 'An exact ability name.',
						),
						'namespace'  => array(
							'type'        => 'string',
							'description' => "The ability name's namespace prefix. This is a naming convention, not an enforced link to the plugin that registered it.",
						),
						'entry_path' => array(
							'type' => 'string',
							// The doors the writer can name, from the writer,
							// so the two cannot disagree. A value it never
							// writes would be a filter that matches nothing,
							// which reads as "none of those"; one it writes
							// and this refuses hides an assistant's own calls.
							'enum' => Writer::ENTRIES,
						),
						'limit'      => array(
							'type'    => 'integer',
							'minimum' => 1,
							'maximum' => 200,
							'default' => 50,
						),
						'cursor'     => array(
							'type'        => 'string',
							'description' => 'Opaque cursor from a previous response.',
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'capture_available' => array( 'type' => 'boolean' ),
						'capture_enabled'   => array( 'type' => 'boolean' ),
						'status_note'       => array( 'type' => 'string' ),
						'invocations'       => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'           => array( 'type' => 'integer' ),
									'invoked_at'   => array( 'type' => 'string' ),
									'ability'      => array( 'type' => 'string' ),
									'namespace'    => array( 'type' => 'string' ),
									'entry_path'   => array( 'type' => 'string' ),
									'user_id'      => array( 'type' => 'integer' ),
									'user_label'   => array(
										'type'        => 'string',
										'description' => 'A display label for the account, resolved when the row is read. Never a stored user record.',
									),
									'outcome'      => array( 'type' => 'string' ),
									'error_code'   => array( 'type' => 'string' ),
									'input_digest' => array(
										'type'        => 'string',
										'description' => 'A keyed SHA-256 of the normalized input. Never the input itself.',
									),
									'duration_ms'  => array( 'type' => 'integer' ),
								),
								'required'   => array( 'id', 'invoked_at', 'ability', 'outcome' ),
							),
						),
						'counts'            => array( 'type' => 'object' ),
						'cursor'            => array( 'type' => 'string' ),
						'has_more'          => array( 'type' => 'boolean' ),
					),
					'required'   => array( 'capture_available', 'capture_enabled', 'invocations', 'has_more' ),
				),
				'execute_callback' => array( $this, 'query_agent_activity' ),
			),

			/*
			 * Which connector credentials this site keeps and who can read
			 * them. No credential bytes or suffixes leave through an ability.
			 */
			'bettershield/get-credential-exposure' => array( 'permission_callback' => array( self::class, 'can_manage' ) ) + $read_meta + array(
				'label'            => __( 'Check app passwords and stored keys', 'bettershield' ),
				'description'      => __( 'Which AI connector credentials this site holds, where each is stored, and how many plugins can read them. Never returns credential values or key hints.', 'bettershield' ),
				'input_schema'     => array( 'type' => 'object' ),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'available'                => array( 'type' => 'boolean' ),
						'configured_count'         => array( 'type' => 'integer' ),
						'readable_by_plugin_count' => array( 'type' => 'integer' ),
						'advisory'                 => array( 'type' => 'string' ),
						'reference_url'            => array( 'type' => 'string' ),
						'connectors'               => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'              => array( 'type' => 'string' ),
									'label'           => array( 'type' => 'string' ),
									'type'            => array( 'type' => 'string' ),
									'method'          => array( 'type' => 'string' ),
									'configured'      => array( 'type' => 'boolean' ),
									'storage_source'  => array(
										'type' => 'string',
										'enum' => array( 'env', 'constant', 'database', 'none' ),
									),
									'encryption'      => array(
										'type' => 'string',
										'enum' => array( 'not_encrypted', 'outside_the_database', 'not_configured' ),
									),
									'rest_registered' => array( 'type' => 'boolean' ),
									'rest_value'      => array( 'type' => 'string' ),
								),
								'required'   => array( 'id', 'configured', 'storage_source' ),
							),
						),
					),
					'required'   => array( 'available', 'connectors', 'advisory' ),
				),
				'execute_callback' => array( $this, 'get_credential_exposure' ),
			),

			/*
			 * Whether the way back in is ready, as the sign-in write gate
			 * sees it (#1881): an assistant learned this only from a refusal.
			 * States and counts, never the link or a code.
			 */
			'bettershield/get-recovery-readiness' => array( 'permission_callback' => array( self::class, 'can_manage' ) ) + $read_meta + array(
				'label'            => __( 'Get recovery readiness', 'bettershield' ),
				'description'      => __( 'Whether each way back in works today, and whether a change to how people sign in would be allowed now. Never returns the recovery link or a code.', 'bettershield' ),
				'input_schema'     => array( 'type' => 'object' ),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'recovery_ready'  => array( 'type' => 'boolean' ),
						'checks'          => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'key' => array(
										'type' => 'string',
										'enum' => array( 'link', 'codes', 'admin_address', 'email_path' ),
									),
									'ok'  => array( 'type' => 'boolean' ),
								),
								'required'   => array( 'key', 'ok' ),
							),
						),
						'ready'           => array( 'type' => 'integer' ),
						'total'           => array( 'type' => 'integer' ),
						'checked_at'      => array( 'type' => 'string' ),
						'overdue'         => array( 'type' => 'boolean' ),
						'link'            => array(
							'type' => 'string',
							'enum' => array( 'available', 'missing', 'expired', 'refused' ),
						),
						'link_expires_at' => array( 'type' => 'string' ),
						'offline_codes'   => array( 'type' => 'integer' ),
						'mail'            => array( 'type' => 'string' ),
						'mail_checked_at' => array( 'type' => 'string' ),
						'lockdown'        => array( 'type' => 'boolean' ),
						'safe_mode'       => array( 'type' => 'boolean' ),
					),
					'required'   => array( 'recovery_ready', 'checks', 'overdue', 'link', 'offline_codes', 'mail', 'lockdown', 'safe_mode' ),
				),
				'execute_callback' => array( $this, 'get_recovery_readiness' ),
			),
		) + ReadSurface::definitions( $read_meta, function ( string $name, $input ): void { $this->self_audit( $name, $input ); } )
			+ WriteFixes::read_definition( $read_meta, function ( string $name, $input ): void { $this->self_audit( $name, $input ); } );

		// What an add-on reads, built here with the same gates, annotations
		// and record as everything above, and never under a name above — nor
		// under a write's. The writes exist only while their own switch is on,
		// so a read registered under one of their names while it is off would
		// be answering to that name the day it is switched on.
		return $definitions + ReadSurface::extensions( $read_meta, function ( string $name, $input ): void { $this->self_audit( $name, $input ); }, array_merge( array_keys( $definitions ), self::write_ability_names() ) );
	}

	/* ---- the write surface ------------------------------------------------------ */

	/**
	 * The abilities that propose a change and the ones that carry it out.
	 *
	 * The pair is deliberate. A proposal is a read with a plan attached: it
	 * says exactly what would change, what it would cost, and what putting it
	 * back looks like, and it changes nothing. Carrying it out needs a
	 * confirmation a person minted against that one plan, and the plan is
	 * checked against live state again before anything moves.
	 *
	 * Annotations are declared explicitly on both halves. They are discovery
	 * hints with no runtime enforcement — the permission callback and the
	 * confirmation are the real gates — but `destructive` defaults to true and
	 * a proposal that advertises itself as dangerous is a proposal nothing
	 * will ask for.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function write_definitions(): array {
		$string  = array( 'type' => 'string' );
		$boolean = array( 'type' => 'boolean' );
		$integer = array( 'type' => 'integer' );
		$lines   = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);

		$plan_meta = array(
			'category'            => 'bettershield',
			'permission_callback' => array( self::class, 'can_write' ),
			'meta'                => array(
				'annotations'  => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
				'show_in_rest' => true,
			),
		);

		$act_meta = array(
			'category'            => 'bettershield',
			'permission_callback' => array( self::class, 'can_write' ),
			'meta'                => array(
				'annotations'  => array(
					'readonly'    => false,
					'destructive' => true,
					// Applying twice is applying once: the second call finds
					// the confirmation spent and the item already in place.
					'idempotent'  => true,
				),
				'show_in_rest' => true,
			),
		);

		// Fields every plan carries, so an agent reads one shape whichever
		// kind of change it asked about.
		$plan_fields = array(
			'proposal_id'           => $integer,
			'target_type'           => $string,
			'effect'                => $lines,
			'changes_signing_in'    => $boolean,
			'recovery_ready'        => $boolean,
			'reversible'            => $boolean,
			'state_digest'          => $string,
			'undo_token'            => $string,
			'expires_at'            => $string,
			'confirmation_required' => $boolean,
			'confirm_by'            => array(
				'type'        => 'string',
				'enum'        => array( 'conversation', 'dashboard' ),
				'description' => 'Where the person agrees. "conversation": this connection may change the site, the confirmation is in this answer, and the apply follows once the person has agreed to the plan shown to them. "dashboard": a caller outside the connected assistant; a person allows the plan under Agents › Requests and hands over the confirmation.',
			),
			'confirmation'          => array(
				'type'        => 'string',
				'description' => 'The single-use confirmation apply takes, present only when confirm_by is "conversation". Show the plan to the person and send this only after they agree; it expires with the plan.',
			),
		);

		$plan_required = array( 'proposal_id', 'target_type', 'effect', 'changes_signing_in', 'recovery_ready', 'reversible', 'state_digest', 'expires_at', 'confirmation_required', 'confirm_by' );

		$definitions = array(

			'bettershield/propose-hardening'   => $plan_meta + array(
				'label'            => __( 'Suggest turning a protection on or off', 'bettershield' ),
				'description'      => __( 'Describes exactly what applying one protection would do to this site (or what taking one off would do, with action set to "revert"), and records the plan so a person can allow it. Changes nothing either way. When this connection may change the site, the answer carries the confirmation the act takes: show the plan to the person and act once they agree. Otherwise the plan is allowed from the dashboard. Taking a protection off always needs one of these plans: apply-hardening puts a reversible protection on by itself, and nothing takes one off by itself.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'item_id' => array(
							'type' => 'string',
							'enum' => Items::ids(),
						),
						'action'  => array(
							'type'        => 'string',
							'enum'        => array( 'apply', 'revert' ),
							'description' => 'Which direction to plan. "apply" is the default and describes putting the protection on. "revert" describes taking it off again, and is refused unless that protection is on now and this site has the record that puts it back.',
						),
						'options' => array(
							'type'        => 'object',
							'description' => 'The item’s own fields, where it takes any. Ignored when planning a revert.',
						),
					),
					'required'   => array( 'item_id' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => $plan_fields + array(
						'item_id'  => $string,
						'title'    => $string,
						'group'    => $string,
						'action'   => array(
							'type' => 'string',
							'enum' => array( 'apply', 'revert' ),
						),
						'conflict' => $string,
						'preview'  => $lines,
						// The options the plan was computed with, returned so
						// the digest the apply recomputes is over what a
						// person actually read.
						'options'  => array( 'type' => 'object' ),
					),
					'required'   => array_merge( $plan_required, array( 'item_id', 'title', 'group' ) ),
				),
				'execute_callback' => array( $this, 'propose_hardening' ),
			),

			'bettershield/propose-file-restore' => $plan_meta + array(
				'label'            => __( 'Suggest putting a file back', 'bettershield' ),
				'description'      => __( 'Describes what replacing one changed file with its published copy would do, including how much differs and the checksum it would be restored to. Changes nothing.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'change_id' => array(
							'type'    => 'integer',
							'minimum' => 1,
						),
					),
					'required'   => array( 'change_id' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => $plan_fields + array(
						'change_id'          => $integer,
						'path'               => $string,
						'change_type'        => $string,
						'published_checksum' => $string,
						'checksum_algorithm' => $string,
						'current_checksum'   => $string,
						'quarantine'         => $boolean,
						'differs'            => array(
							'type'       => 'object',
							'properties' => array(
								'lines_added'   => $integer,
								'lines_removed' => $integer,
								'comparable'    => $boolean,
							),
						),
					),
					'required'   => array_merge( $plan_required, array( 'change_id', 'path', 'quarantine' ) ),
				),
				'execute_callback' => array( $this, 'propose_file_restore' ),
			),

			'bettershield/restore-file'        => $act_meta + array(
				'label'            => __( 'Put a file back', 'bettershield' ),
				'description'      => __( 'Puts the published copy of one changed file back, once, with the confirmation for the plan propose-file-restore returned. The file as it is now goes to quarantine first, the published copy is checked against its checksum before it is used, and the answer carries the handle revert-hardening takes to put the current file back. That way back is best effort, not guaranteed, which is why this waits for the person’s agreement.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'proposal_id'  => array(
							'type'    => 'integer',
							'minimum' => 1,
						),
						'confirmation' => $string,
					),
					'required'   => array( 'proposal_id', 'confirmation' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'restored'   => $boolean,
						'change_id'  => $integer,
						'path'       => $string,
						'undo_token' => $string,
					),
					'required'   => array( 'restored', 'change_id', 'path', 'undo_token' ),
				),
				'execute_callback' => array( $this, 'restore_file' ),
			),

			'bettershield/apply-hardening'     => $act_meta + array(
				'label'            => __( 'Apply a protection', 'bettershield' ),
				'description'      => __( 'Applies one protection. A reversible protection is applied directly and the answer carries the handle that puts it back. A protection that changes how people sign in is refused here and named a proposal: a connection a person has allowed to change the site gets the confirmation back with the plan and applies it once the person agrees in the conversation; callers outside the connected assistant use the dashboard to allow a plan.', 'bettershield' ),
				/*
				 * Two ways in, and no way to say so in a schema: core's
				 * validator implements no `oneOf`, so every property is
				 * optional here and the callback decides which shape it was
				 * handed. A required field would refuse the other shape before
				 * anything of ours ran.
				 */
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'item_id'      => array(
							'type' => 'string',
							'enum' => Items::ids(),
						),
						'options'      => array(
							'type'        => 'object',
							'description' => 'The item’s own fields, where it takes any.',
						),
						'proposal_id'  => array(
							'type'    => 'integer',
							'minimum' => 1,
						),
						// The state the plan was computed from, handed back so
						// the action can refuse a site that moved underneath
						// it. Optional, so a bare {item_id} call still works;
						// checked whenever it is supplied.
						'state_digest' => $string,
						'confirmation' => array(
							'type'        => 'string',
							'description' => 'The single-use confirmation a person minted for a proposal. Required only for a protection whose way back is not guaranteed by the undo ledger alone.',
						),
					),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'applied'          => $boolean,
						'item_id'          => $string,
						'undo_token'       => $string,
						'notes'            => $lines,
						// What the dry run warned about, where it warned about
						// anything. An item with no apply routine of its own
						// leaves `notes` empty, so without this the warning the
						// screen shows beside the toggle reached a caller here
						// through no channel at all.
						'conflict_warning' => $string,
					),
					'required'   => array( 'applied', 'item_id', 'undo_token' ),
				),
				'execute_callback' => array( $this, 'apply_hardening' ),
			),

			'bettershield/revert-hardening'    => $act_meta + array(
				'label'            => __( 'Undo a change', 'bettershield' ),
				'description'      => __( 'Restores what a change made through these abilities replaced, using the handle it returned. A plugin switched back on and a restored file put back are the safe direction and ask for nothing more. Taking a protection off is not the safe direction, whatever put it there: for that, ask propose-hardening with action "revert", show the person the plan, and send the confirmation it carries. A finding fix’s handle (scheduled events, a REST route, a folder, a plugin update or quarantine, an account change) takes its plan from propose-fix-undo the same way.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'undo_token'   => $string,
						'confirmation' => array(
							'type'        => 'string',
							'description' => 'The single-use confirmation a person minted for a revert plan. Required when the handle names a protection; ignored for a plugin switched back on or a file put back.',
						),
					),
					'required'   => array( 'undo_token' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'reverted'    => $boolean,
						'target'      => $string,
						'target_type' => $string,
						'notes'       => $lines,
					),
					'required'   => array( 'reverted', 'target', 'target_type' ),
				),
				'execute_callback' => array( $this, 'revert_hardening' ),
			),
		);

		$definitions += WriteChecks::definitions( array( $this, 'run_check' ) );
		$definitions += WriteTriage::definitions( array( $this, 'run_triage' ), $plan_meta, $act_meta, $plan_fields, $plan_required );
		$definitions += WriteAccess::definitions( array( $this, 'run_access' ), $plan_meta, $act_meta, $plan_fields, $plan_required );
		$definitions += WriteFixes::definitions( array( $this, 'run_fix' ) );
		$definitions += WriteExtensions::definitions( array( $this, 'run_extension' ), $plan_meta, $act_meta, $plan_fields, $plan_required );

		if ( ! self::deactivation_enabled() ) {
			return $definitions;
		}

		return $definitions + array(

			'bettershield/propose-plugin-deactivation' => $plan_meta + array(
				'label'            => __( 'Suggest switching a plugin off', 'bettershield' ),
				'description'      => __( 'Describes what switching one plugin off would do to this site, and records the plan so a person can allow it. Changes nothing.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'plugin' => array(
							'type'        => 'string',
							'description' => 'The plugin file, as WordPress names it: directory/file.php.',
						),
					),
					'required'   => array( 'plugin' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => $plan_fields + array(
						'plugin'  => $string,
						'name'    => $string,
						'active'  => $boolean,
						'network' => $boolean,
					),
					'required'   => array_merge( $plan_required, array( 'plugin', 'name', 'active' ) ),
				),
				'execute_callback' => array( $this, 'propose_plugin_deactivation' ),
			),

			'bettershield/deactivate-plugin'           => $act_meta + array(
				'label'            => __( 'Switch off a confirmed plugin', 'bettershield' ),
				'description'      => __( 'Switches off the plugin a person allowed, once, using the confirmation they minted. The prior state is recorded first, so it can be switched back on.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array(
						'proposal_id'  => array(
							'type'    => 'integer',
							'minimum' => 1,
						),
						'confirmation' => $string,
					),
					'required'   => array( 'proposal_id', 'confirmation' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'deactivated' => $boolean,
						'plugin'      => $string,
						'undo_token'  => $string,
					),
					'required'   => array( 'deactivated', 'plugin', 'undo_token' ),
				),
				'execute_callback' => array( $this, 'deactivate_plugin' ),
			),
		);
	}

	/* ---- the write callbacks ---------------------------------------------------- */

	/** Every add-on action uses Free's native write gate and single-use plan contract. */
	public function run_extension( string $short, $raw, bool $undo = false ) {
		$spec = WriteExtensions::named( $short );
		$ability = $undo ? 'bettershield/revert-hardening' : 'bettershield/' . $short;
		if ( ! $undo ) { $this->self_audit( $ability, $raw ); }
		$input = is_array( $raw ) ? $raw : array();
		$plan = null !== $spec && $short === $spec['propose'];
		$type = $spec['target_type'] ?? 'addon';
		$refused = self::write_gate();
		if ( null === $refused && ( null === $spec || ! WriteExtensions::valid_input( $input, $spec, $plan, $undo ) ) ) {
			$refused = WriteTriage::error( 'bettershield_extension_input', __( 'Choose the action the site offers. Execution needs its proposal and single-use confirmation, with no replacement target.', 'bettershield' ), 400 );
		}
		if ( null === $refused ) { $refused = $plan ? self::propose_rate_limit( $short ) : self::rate_limit( $undo ? 'revert-hardening' : $short ); }
		if ( null !== $refused ) { return self::refuse_early( $ability, $type, '', $refused ); }
		$undo = $undo || ( $plan && ( 'revert' === ( $input['action'] ?? '' ) || ! empty( $spec['undo_only'] ) ) );
		if ( $undo && ! isset( $spec['undo_key'] ) ) { return WriteTriage::moved(); }
		$proposal = null;
		if ( ! $plan ) {
			$proposal = Proposals::spend( $input['confirmation'], $ability );
			if ( is_wp_error( $proposal ) ) { return self::refuse_early( $ability, $type, '', $proposal ); }
			if ( isset( $input['proposal_id'] ) && (int) $proposal->id !== $input['proposal_id'] ) { return self::refuse( $proposal, WriteTriage::moved() ); }
			$input = $proposal->plan + ( $undo ? array( 'undo_token' => $input['undo_token'] ) : array() );
			// Neither an add-on nor another revert family may spend this one's plan.
			if ( $proposal->target_type !== $type || ( $undo && 'revert' !== ( $input['action'] ?? '' ) ) ) { return self::refuse( $proposal, WriteTriage::moved() ); }
		}
		$live = call_user_func( $spec[ $undo ? 'undo_snapshot' : 'snapshot' ], $input );
		if ( is_wp_error( $live ) ) { return null === $proposal ? $live : self::refuse( $proposal, $live ); }
		if ( $plan ) {
			$body = array( 'target_type' => $type, 'effect' => $live['effect'], 'changes_signing_in' => $live['changes_signing_in'] ?? false, 'recovery_ready' => self::recovery_ready(), 'reversible' => $live['reversible'], 'state_digest' => $live['digest'], 'expires_at' => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ), 'confirmation_required' => true, 'action' => $undo ? 'revert' : 'apply' ) + $live['target'];
			return self::record_proposal( $undo ? 'bettershield/revert-hardening' : 'bettershield/' . $spec['act'], $live['object_id'], $type, $body, $live['digest'] );
		}
		if ( $proposal->target !== $live['object_id'] || ! hash_equals( (string) $proposal->state_digest, $live['digest'] ) ) { return self::refuse( $proposal, WriteTriage::moved() ); }
		// A change to how somebody signs in is spent only behind proven recovery and a person's confirmed password, as lockdown is.
		if ( ! empty( $live['changes_signing_in'] ) && ( ! self::recovery_ready() || 1 !== (int) $proposal->minted_with_sudo ) ) { return self::refuse( $proposal, WriteTriage::error( 'bettershield_recovery_unverified', self::unverified_reason(), 409 ) ); }
		$intent = WriteTriage::intent( $ability );
		if ( null !== $intent ) { return self::refuse( $proposal, $intent ); }
		$result = call_user_func( $spec[ $undo ? 'undo_execute' : 'execute' ], $live );
		if ( is_wp_error( $result ) ) { return self::refuse( $proposal, $result ); }
		$known = true === ( $result[ $undo ? 'reverted' : 'applied' ] ?? false );
		Proposals::record_outcome( (int) $proposal->id, $known ? ( $undo ? 'reverted' : 'applied' ) : 'unknown', $result['undo_token'] ?? null );
		Writer::instance()->record( $known ? ( $undo ? 'agent_write_reverted' : 'agent_write_applied' ) : 'agent_write_refused', Writer::SEVERITY_MEDIUM, array( 'object_type' => $type, 'object_id' => $live['object_id'], 'context' => array( 'ability' => $ability, 'proposal_id' => (int) $proposal->id, 'outcome' => $known ? 'completed' : 'unknown' ) ) );
		return $result;
	}

	/**
	 * A finding fix that only adds protection: applied directly, as a
	 * reversible hardening item is. Every gate is asked again here, the
	 * intent is on disk before the fix runs, and the fix class writes its own
	 * undo row before it changes anything.
	 */
	public function run_fix( string $short, $raw ) {
		$ability = 'bettershield/' . $short;
		$this->self_audit( $ability, $raw );
		$input   = is_array( $raw ) ? $raw : array();
		$refused = self::write_gate() ?? WriteFixes::gate() ?? ( WriteFixes::shared_code( $short ) ? WriteFixes::code_gate() : null ) ?? WriteFixes::validate( $short, $input ) ?? self::rate_limit( $short );
		if ( null !== $refused ) { return self::refuse_early( $ability, 'finding_fix', $short, $refused ); }
		$intent = WriteTriage::intent( $ability );
		if ( null !== $intent ) { return self::refuse_early( $ability, 'finding_fix', $short, $intent ); }
		$result = WriteFixes::apply( $short, $input );
		if ( is_wp_error( $result ) ) { return self::refuse_early( $ability, 'finding_fix', $short, $result ); }
		// Nobody was in the loop, so it is the loud row.
		Writer::instance()->record( 'agent_write_applied_direct', Writer::SEVERITY_HIGH, array( 'object_type' => 'finding_fix', 'object_id' => $short, 'context' => self::without_nulls( array( 'ability' => $ability, 'correlation' => Capture::instance()->current_correlation() ) ) ) );
		return $result;
	}

	/** Irreversible access actions have no direct path and use the site's single-use confirmation. */
	public function run_access( string $short, $raw ) {
		$ability = 'bettershield/' . $short; $this->self_audit( $ability, $raw );
		$input = is_array( $raw ) ? $raw : array(); $is_plan = isset( WriteAccess::PAIRS[ $short ] );
		$act = $is_plan ? WriteAccess::PAIRS[ $short ] : $short;
		$type = 'end-sessions' === $act ? 'sessions' : ( 'revoke-app' === $act ? 'mcp_app' : 'lockdown' );
		$refused = self::write_gate();
		if ( null === $refused && ! WriteAccess::valid_input( $short, $input ) ) { $refused = WriteTriage::error( 'bettershield_access_input', __( 'Choose one access action. Execution needs its proposal and single-use confirmation, with no replacement target.', 'bettershield' ), 400 ); }
		if ( null === $refused ) { $refused = $is_plan ? self::propose_rate_limit( $short ) : self::rate_limit( $short ); }
		if ( null !== $refused ) { return self::refuse_early( $ability, $type, '', $refused ); }
		$proposal = null;
		if ( ! $is_plan ) {
			$proposal = Proposals::spend( $input['confirmation'], $ability );
			if ( is_wp_error( $proposal ) ) { return self::refuse_early( $ability, $type, '', $proposal ); }
			if ( (int) $proposal->id !== $input['proposal_id'] ) { return self::refuse( $proposal, WriteTriage::moved() ); }
			$input = $proposal->plan;
		}
		$live = WriteAccess::snapshot( $act, $input );
		if ( is_wp_error( $live ) ) { return null !== $proposal ? self::refuse( $proposal, $live ) : $live; }
		$target = (string) ( $live['target']['user_id'] ?? $live['target']['app_id'] ?? 'site' );
		if ( $is_plan ) {
			$plan = $live['target'] + array( 'target_type' => $type, 'effect' => $live['effect'], 'changes_signing_in' => 'enter-lockdown' === $act, 'recovery_ready' => self::recovery_ready(), 'reversible' => false, 'state_digest' => $live['digest'], 'expires_at' => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ), 'confirmation_required' => true );
			return self::record_proposal( 'bettershield/' . $act, $target, $type, $plan, $live['digest'] );
		}
		if ( ! hash_equals( (string) $proposal->state_digest, $live['digest'] ) ) { return self::refuse( $proposal, WriteTriage::moved() ); }
		if ( 'enter-lockdown' === $act && ( ! self::recovery_ready() || 1 !== (int) $proposal->minted_with_sudo ) ) { return self::refuse( $proposal, WriteTriage::error( 'bettershield_recovery_unverified', self::unverified_reason(), 409 ) ); }
		$intent = WriteTriage::intent( $ability );
		if ( null !== $intent ) { return self::refuse( $proposal, $intent ); }
		$result = WriteAccess::execute( $act, $live['target'], $live['grants'] );
		if ( is_wp_error( $result ) ) { return self::refuse( $proposal, $result ); }
		Proposals::record_outcome( (int) $proposal->id, 'applied', null );
		Writer::instance()->record( 'agent_write_applied', Writer::SEVERITY_MEDIUM, array( 'object_type' => $type, 'object_id' => $target, 'context' => array( 'ability' => $ability ) ) );
		return $result;
	}

	/** Triage uses the same permission, rate, proposal and confirmation contracts as protection writes. */
	public function run_triage( string $short, $raw ) {
		$ability = 'bettershield/' . $short; $this->self_audit( $ability, $raw );
		$input = is_array( $raw ) ? $raw : array(); $file = str_contains( $short, 'file' );
		$type = $file ? 'file_change' : 'incident';
		$refused = self::write_gate() ?? ( $file ? self::shared_code_gate() : null ) ?? WriteTriage::input( $short, $input );
		if ( null !== $refused ) { return self::refuse_early( $ability, $type, '', $refused ); }
		$is_plan = str_starts_with( $short, 'propose-' );
		$limited = $is_plan ? self::propose_rate_limit( $short ) : self::rate_limit( $short );
		if ( null !== $limited ) { return self::refuse_early( $ability, $type, '', $limited ); }
		$proposal = null;
		if ( ! $is_plan && isset( $input['proposal_id'] ) ) {
			$proposal = Proposals::spend( $input['confirmation'], $ability );
			if ( is_wp_error( $proposal ) ) { return self::refuse_early( $ability, $type, '', $proposal ); }
			if ( (int) $proposal->id !== $input['proposal_id'] ) { return self::refuse( $proposal, WriteTriage::error( 'bettershield_confirmation_unknown', __( 'That confirmation belongs to a different change.', 'bettershield' ), 403 ) ); }
			foreach ( array( 'change_id', 'incident_id', 'status' ) as $key ) {
				if ( isset( $input[ $key ] ) && $input[ $key ] !== ( $proposal->plan[ $key ] ?? null ) ) { return self::refuse( $proposal, WriteTriage::moved() ); }
			}
			$input = $proposal->plan;
		}
		$id = (int) ( $input[ $file ? 'change_id' : 'incident_id' ] ?? 0 );
		$record = $file ? WriteTriage::file( $id ) : \BetterShield\Incidents\Repository::detail( $id );
		if ( is_wp_error( $record ) ) { return null !== $proposal ? self::refuse( $proposal, $record ) : $record; }
		$digest = $file ? WriteTriage::file_digest( $record ) : \BetterShield\Incidents\Repository::status_digest( $record );
		if ( null !== $proposal && ! hash_equals( (string) $proposal->state_digest, $digest ) ) { return self::refuse( $proposal, WriteTriage::moved() ); }
		if ( $is_plan ) {
			if ( $file && ! in_array( $record->status, array( 'new', 'acknowledged' ), true ) ) { return WriteTriage::error( 'bettershield_change_not_open', __( 'That file change has already been dealt with.', 'bettershield' ), 409 ); }
			if ( ! $file && $record['status'] === $input['status'] ) { return WriteTriage::error( 'bettershield_status_unchanged', __( 'That incident already has this status.', 'bettershield' ), 409 ); }
			$plan = array(
				'target_type' => $type, 'changes_signing_in' => false, 'recovery_ready' => self::recovery_ready(),
				'reversible' => true, 'state_digest' => $digest, 'expires_at' => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ),
				'confirmation_required' => $file || 'resolved' === $input['status'],
				'effect' => array( $file ? __( 'Accepts this file change, so it no longer appears among open changes. Does not edit the file. Undo reports the change again.', 'bettershield' ) : ( 'resolved' === $input['status'] ? __( 'Marks this incident handled and stops collecting new evidence for it. Undo reopens it as acknowledged and resumes collection.', 'bettershield' ) : __( 'Labels this incident acknowledged. Evidence collection continues and no protection changes.', 'bettershield' ) ) ),
			) + ( $file ? array( 'change_id' => $id, 'path' => $record->path ) : array( 'incident_id' => $id, 'status' => $input['status'] ) );
			return self::record_proposal( $file ? 'bettershield/mark-file-expected' : 'bettershield/set-incident-status', $file ? $record->path : (string) $id, $type, $plan, $digest );
		}
		$intent = WriteTriage::intent( $ability );
		if ( null !== $intent ) { return null !== $proposal ? self::refuse( $proposal, $intent ) : $intent; }
		if ( $file ) {
			$result = 'mark-file-expected' === $short ? Restore::suppress( $id, $digest ) : Restore::unsuppress( $id );
			$answer = array( 'applied' => true, 'change_id' => $id, 'path' => (string) $record->path );
			if ( is_array( $result ) && isset( $result['undo'] ) ) { $answer['undo_token'] = $result['undo']; }
		} else {
			$result = \BetterShield\Incidents\Repository::status( $id, $input['status'], $digest, 'resolved' === $input['status'] );
			$answer = array( 'applied' => true, 'incident_id' => $id, 'status' => $input['status'] );
			if ( is_array( $result ) && isset( $result['undo_token'] ) ) { $answer['undo_token'] = $result['undo_token']; }
		}
		if ( is_wp_error( $result ) ) { return null !== $proposal ? self::refuse( $proposal, $result ) : self::refuse_early( $ability, $type, (string) $id, $result ); }
		if ( null !== $proposal ) { Proposals::record_outcome( (int) $proposal->id, 'applied', $answer['undo_token'] ?? null ); }
		Writer::instance()->record( null !== $proposal ? 'agent_write_applied' : 'agent_write_applied_direct', null !== $proposal ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_HIGH, array( 'object_type' => $type, 'object_id' => (string) $id, 'context' => array( 'ability' => $ability ) ) );
		return $answer;
	}

	/** Reopening evidence is the safe direction; it still needs the write and shared-code gates. */
	private static function undo_triage( object $entry, string $token ) {
		$file = Restore::SUPPRESS_UNDO === (string) $entry->action_key;
		$refused = ( $file ? self::shared_code_gate() : null ) ?? WriteTriage::intent( 'bettershield/revert-hardening' );
		if ( null !== $refused ) { return $refused; }
		$result = $file ? Restore::revert_suppression( $token ) : \BetterShield\Incidents\Repository::undo_status( $token );
		if ( is_wp_error( $result ) ) { return $result; }
		$target = (string) ( $entry->applied_state[ $file ? 'change' : 'incident_id' ] ?? '' );
		Writer::instance()->record( 'agent_write_reverted', Writer::SEVERITY_MEDIUM, array( 'object_type' => $file ? 'file_change' : 'incident', 'object_id' => $target, 'context' => array( 'ability' => 'bettershield/revert-hardening' ) ) );
		return array( 'reverted' => true, 'target' => $target, 'target_type' => $file ? 'file_expected' : 'incident', 'notes' => array() );
	}

	/** A write-scoped check or observation, with no protection change to confirm. */
	public function run_check( string $short, $input ) {
		$ability = 'bettershield/' . $short;
		$this->self_audit( $ability, $input );
		$input = is_array( $input ) ? $input : array();
		$limit = WriteChecks::continues_a_file_check( $short )
			? static fn(): ?\WP_Error => self::rate_limit( $ability . '#continue', WriteChecks::FILE_CHECK_SLICES_PER_HOUR )
			: static fn(): ?\WP_Error => self::rate_limit( $ability );
		// Running overdue work is the one check that sets other code going, so it waits out lockdown and safe mode.
		$refused = self::write_gate() ?? ( 'run-scheduled-work' === $short ? WriteFixes::gate() : null ) ?? WriteChecks::validate( $short, $input ) ?? $limit();
		if ( null !== $refused ) { return self::refuse_early( $ability, 'check', $short, $refused ); }
		Writer::instance()->record( 'agent_check_requested', Writer::SEVERITY_INFO, array( 'object_type' => 'ability', 'object_id' => $ability ) );
		Writer::instance()->flush();
		return WriteChecks::run( $short, $input );
	}

	/**
	 * A plan for one protection, and the row a person confirms against.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function propose_hardening( $input ) {
		$this->self_audit( 'bettershield/propose-hardening', $input );

		$refused = self::write_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input   = is_array( $input ) ? $input : array();
		$item    = (string) ( $input['item_id'] ?? '' );
		$action  = (string) ( $input['action'] ?? 'apply' );
		$options = isset( $input['options'] ) && is_array( $input['options'] ) ? $input['options'] : array();

		if ( ! isset( Items::all()[ $item ] ) ) {
			return new \WP_Error( 'bettershield_unknown_item', __( 'There is no such protection.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( 'apply' !== $action && 'revert' !== $action ) {
			return new \WP_Error(
				'bettershield_unknown_action',
				__( 'A plan is for putting a protection on or for taking it off. Name one of those as the action, or leave it out to plan putting it on.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		if ( in_array( $item, self::HUMAN_ONLY_ITEMS, true ) ) {
			return new \WP_Error(
				'bettershield_human_only',
				__( 'This protection writes a rule block into a shared configuration file, which stays the site owner’s own switch. It is not described or applied through an ability.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		// Shape before the hour's slot, as in apply_hardening().
		$limited = self::propose_rate_limit( 'propose-hardening' );

		if ( null !== $limited ) {
			return $limited;
		}

		if ( 'revert' === $action ) {
			return $this->propose_hardening_revert( $item );
		}

		$dry = Manager::instance()->dry_run( $item, $options );

		if ( is_wp_error( $dry ) ) {
			return $dry;
		}

		/*
		 * A plan for a change that cannot be made is not a plan. The dry run
		 * already knows both ways it cannot: options the item itself rejects,
		 * and a mechanism this installation cannot offer at all. Recording
		 * either as a proposal puts a plan in front of a person that the apply
		 * will refuse whatever they answer — and, on the options half, a plan
		 * whose preview is empty because the preview never ran.
		 */
		if ( null !== $dry['refusal'] ) {
			return new \WP_Error( 'bettershield_bad_options', (string) $dry['refusal'], array( 'status' => 400 ) );
		}

		if ( ! $dry['available'] ) {
			return new \WP_Error(
				'bettershield_unavailable',
				null === $dry['availability_note']
					? __( 'This protection is not offered on this installation.', 'bettershield' )
					: (string) $dry['availability_note'],
				array(
					'status' => 409,
					'reason' => (string) ( $dry['availability_reason'] ?? '' ),
				)
			);
		}

		$definition = Items::all()[ $item ];
		$handler    = Items::handlers()[ $item ] ?? null;

		$preview = array();

		if ( array() !== $options && null !== $handler && method_exists( $handler, 'preview' ) ) {
			$preview = array_values( array_map( 'strval', (array) $handler::preview( $options ) ) );
		}

		$digest = self::hardening_digest( $item, $options, $dry );
		$effect = array_values( array_map( 'strval', (array) $dry['effect'] ) );

		/*
		 * A plan that changes how people sign in names the lockout risk
		 * before anything else it says. The person allowing it is choosing
		 * to risk their own way in, and that sentence is the thing they are
		 * agreeing to; the item's own effect lines describe the mechanism
		 * and come after it.
		 */
		if ( Permissions::changes_signing_in( $item ) ) {
			array_unshift(
				$effect,
				__( 'Changes how people sign in. If it goes wrong, the way back in is the recovery link: this site verifies it daily, it must have been verified within the last day for the change to be allowed, and pressing the button on the page it opens puts the site in safe mode with every protection relaxed.', 'bettershield' )
			);
		}

		$plan = self::without_nulls(
			array(
				'item_id'               => $item,
				'title'                 => (string) $definition['title'],
				'group'                 => (string) $definition['group'],
				'target_type'           => 'hardening_item',
				'action'                => 'apply',
				'options'               => $options,
				'effect'                => $effect,
				'conflict'              => null === $dry['conflict_warning'] ? null : (string) $dry['conflict_warning'],
				'changes_signing_in'    => Permissions::changes_signing_in( $item ),
				'recovery_ready'        => self::recovery_ready(),
				'preview'               => $preview,
				// The item's own answer, not this file's. A protection whose
				// undo reaches everything it changed is put back exactly by
				// the handle the apply returns; one that says otherwise says
				// so here rather than being described with a promise it cannot
				// keep, and is refused on the direct path for the same reason.
				'reversible'            => self::item_is_reversible( $item, $options ),
				'state_digest'          => $digest,
				'expires_at'            => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ),
				'confirmation_required' => true,
			)
		);

		return self::record_proposal( 'bettershield/apply-hardening', $item, 'hardening_item', $plan, $digest );
	}

	/**
	 * A plan for taking one protection off, and the row a person confirms
	 * against.
	 *
	 * Putting a protection on and taking it off are opposite directions, and
	 * only one of them is safe. The undo ledger makes an apply reversible by
	 * construction, which is what lets a credential make one on its own; there
	 * is no equivalent warrant for a revert, because protected to unprotected
	 * re-opens exactly what the item was holding off. So a revert takes the
	 * ladder a sign-in change takes: a plan, a confirmation minted against it,
	 * one spend.
	 *
	 * Two conditions, and both are about the protection rather than about who
	 * is asking. It has to be on now, and this site has to hold the record
	 * that puts it back — the same record the act will be handed, so a plan is
	 * never made for a revert the act would refuse.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private function propose_hardening_revert( string $item ) {
		$manager = Manager::instance();

		if ( ! $manager->is_active( $item ) ) {
			return new \WP_Error(
				'bettershield_not_applied',
				__( 'This protection is not on, so there is nothing here to take off.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$token = (string) ( $manager->item_state( $item )['token'] ?? '' );
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || 'harden_' . $item !== (string) $entry->action_key || null !== $entry->reverted_at ) {
			return new \WP_Error(
				'bettershield_unknown_undo',
				__( 'There is no record on this site of what this protection replaced, so taking it off stays the site owner’s own switch rather than something described or carried out here.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$dry = $manager->dry_run( $item );

		if ( is_wp_error( $dry ) ) {
			return $dry;
		}

		$definition = Items::all()[ $item ];
		$digest     = self::revert_digest( $item, $token );

		// What taking it off does, told in that direction. The item's apply
		// effect read here said the plan would add what it was about to stop.
		$effect = array_merge(
			array( __( 'Takes this protection off the site and puts back what the undo record kept from before it. Until it is put on again:', 'bettershield' ) ),
			Items::reverts( $item, (array) ( $manager->item_state( $item )['options'] ?? array() ) )
		);

		/*
		 * The sentence a sign-in item's plan leads with, told in the direction
		 * a revert actually runs. Applying one of these risks the way in, which
		 * is why the apply path asks for proven recovery; taking one off puts
		 * the way in back to the one WordPress ships, and the person agreeing
		 * needs to know that anybody relying on the moved one loses it.
		 */
		if ( Permissions::changes_signing_in( $item ) ) {
			array_unshift(
				$effect,
				__( 'Changes how people sign in: the way in goes back to the one WordPress ships. Anybody using the address or the gate this protection put in place will need the original one again.', 'bettershield' )
			);
		}

		$plan = self::without_nulls(
			array(
				'item_id'               => $item,
				'title'                 => (string) $definition['title'],
				'group'                 => (string) $definition['group'],
				'target_type'           => 'hardening_item',
				'action'                => 'revert',
				'effect'                => $effect,
				'changes_signing_in'    => Permissions::changes_signing_in( $item ),
				'recovery_ready'        => self::recovery_ready(),
				// Putting the protection on again is what puts this back, and
				// it is offered for every item that is on now.
				'reversible'            => true,
				// The handle revert-hardening takes, so the plan and the act
				// name the same application of this protection.
				'undo_token'            => $token,
				'state_digest'          => $digest,
				'expires_at'            => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ),
				'confirmation_required' => true,
			)
		);

		return self::record_proposal( 'bettershield/revert-hardening', $item, 'hardening_item', $plan, $digest );
	}

	/**
	 * The digest a revert plan is pinned to.
	 *
	 * The handle names one application of one protection, so it is the whole
	 * of what the plan was about. A protection taken off and put on again
	 * carries a new handle, and the plan made before that stops describing the
	 * site — which is what the spend compares rather than assumes.
	 */
	private static function revert_digest( string $item, string $token ): string {
		return (string) Capture::digest(
			array(
				'item'   => $item,
				'action' => 'revert',
				'token'  => $token,
			)
		);
	}

	/**
	 * A plan for putting one changed file back.
	 *
	 * The comparison is summarized rather than carried: how many lines differ
	 * is the fact worth having, and the lines themselves are the contents of a
	 * file this plugin never hands to anything.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function propose_file_restore( $input ) {
		$this->self_audit( 'bettershield/propose-file-restore', $input );

		$refused = self::write_gate() ?? self::shared_code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input     = is_array( $input ) ? $input : array();
		$change_id = (int) ( $input['change_id'] ?? 0 );
		$unknown   = new \WP_Error( 'bettershield_unknown_change', __( 'There is no such file change on record.', 'bettershield' ), array( 'status' => 404 ) );

		// Shape before the hour's slot, as in apply_hardening().
		if ( $change_id <= 0 ) {
			return $unknown;
		}

		$limited = self::propose_rate_limit( 'propose-file-restore' );

		if ( null !== $limited ) {
			return $limited;
		}

		$row = self::change_row( $change_id );

		if ( null === $row ) {
			return $unknown;
		}

		$preview = Restore::preview( $change_id );

		if ( is_wp_error( $preview ) ) {
			return $preview;
		}

		$path    = (string) $row->path;
		$current = null === $row->hash_after ? '' : (string) $row->hash_after;
		$digest  = (string) Capture::digest(
			array(
				'change_id' => $change_id,
				'path'      => $path,
				'hash'      => $current,
			)
		);

		$plan = self::without_nulls(
			array(
				'change_id'          => $change_id,
				'path'               => $path,
				'change_type'        => (string) $row->change_type,
				'target_type'        => 'file_change',
				'effect'             => array(
					__( 'Takes a copy of the file as it is now into quarantine before anything is written.', 'bettershield' ),
					__( 'Fetches the published copy for this exact version and checks it against the published checksum before it is used.', 'bettershield' ),
					__( 'Writes that copy over the file on disk, and records the prior state in the undo ledger first. That way back is best effort, not guaranteed, since the file, its path or the quarantined copy may have moved by the time it is asked for, which is why this change waits for a person.', 'bettershield' ),
				),
				'published_checksum' => null === $row->hash_before ? null : (string) $row->hash_before,
				'checksum_algorithm' => (string) $row->algo,
				'current_checksum'   => '' === $current ? null : $current,
				'quarantine'         => true,
				'differs'            => self::difference_summary( (string) $preview['diff'] ),
				'changes_signing_in' => false,
				'recovery_ready'     => self::recovery_ready(),
				/*
				 * A restore's undo is conditional rather than guaranteed: the
				 * original path, the contents on disk and the quarantined copy
				 * may all have moved by the time anybody asks for it back. The
				 * copy taken before the write is a good-faith way back, not a
				 * promise, and this field is where the difference is stated.
				 */
				'reversible'         => false,
				'state_digest'       => $digest,
				'expires_at'         => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ),
				'confirmation_required' => true,
			)
		);

		return self::record_proposal( 'bettershield/restore-file', $path, 'file_change', $plan, $digest );
	}

	/**
	 * Put the published copy of one changed file back, with the confirmation
	 * a person agreed to.
	 *
	 * The plan carried the file's checksum as it stood; the write refuses a
	 * file that has moved since, quarantines what is there first and checks
	 * the published copy against its checksum before using it — all of it
	 * inside Integrity\Restore, which the dashboard's own Restore button
	 * runs. The undo is the ledger row that write leaves, and
	 * revert-hardening takes its handle.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function restore_file( $input ) {
		$this->self_audit( 'bettershield/restore-file', $input );

		$refused = self::write_gate() ?? self::shared_code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input        = is_array( $input ) ? $input : array();
		$confirmation = (string) ( $input['confirmation'] ?? '' );
		$proposal_id  = (int) ( $input['proposal_id'] ?? 0 );

		// Shape before the hour's slot, as in apply_hardening().
		if ( '' === $confirmation || $proposal_id <= 0 ) {
			return new \WP_Error(
				'bettershield_confirmation_unknown',
				__( 'That confirmation does not match a change waiting to be made.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		$limited = self::rate_limit( 'restore-file' );

		if ( null !== $limited ) {
			return self::refuse_early( 'bettershield/restore-file', 'file_change', '', $limited );
		}

		$proposal = Proposals::spend( $confirmation, 'bettershield/restore-file' );

		if ( is_wp_error( $proposal ) ) {
			return self::refuse_early( 'bettershield/restore-file', 'file_change', '', $proposal );
		}

		if ( (int) $proposal->id !== $proposal_id ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_confirmation_unknown', __( 'That confirmation belongs to a different change.', 'bettershield' ), array( 'status' => 403 ) )
			);
		}

		$plan      = is_array( $proposal->plan ) ? $proposal->plan : array();
		$change_id = (int) ( $plan['change_id'] ?? 0 );
		$row       = self::change_row( $change_id );

		if ( null === $row ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_unknown_change', __( 'There is no such file change on record.', 'bettershield' ), array( 'status' => 404 ) )
			);
		}

		// The state the plan was made from, against the record now.
		$current = null === $row->hash_after ? '' : (string) $row->hash_after;
		$digest  = (string) Capture::digest(
			array(
				'change_id' => $change_id,
				'path'      => (string) $row->path,
				'hash'      => $current,
			)
		);

		if ( ! hash_equals( (string) $proposal->state_digest, $digest ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error(
					'bettershield_state_moved',
					__( 'This file is not in the state the plan described, so the plan no longer describes it. Ask for the change again.', 'bettershield' ),
					array( 'status' => 409 )
				)
			);
		}

		// And the file on disk against the plan's checksum, inside the write.
		// The record's checksum, compared the way it was taken: MD5 for core.
		$restored = Restore::apply( $change_id, '' === $current ? null : $current, (string) $row->algo );

		if ( is_wp_error( $restored ) ) {
			return self::refuse( $proposal, $restored );
		}

		Writer::instance()->record(
			'agent_write_applied',
			// Medium: a person agreed to this change and the row that minted
			// the confirmation names them.
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file_change',
				'object_id'   => (string) $restored['path'],
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/restore-file',
						'proposal_id' => (int) $proposal->id,
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		Proposals::record_outcome( (int) $proposal->id, 'restored', (string) $restored['undo'] );

		return array(
			'restored'   => true,
			'change_id'  => $change_id,
			'path'       => (string) $restored['path'],
			'undo_token' => (string) $restored['undo'],
		);
	}

	/**
	 * Put the displaced file back from quarantine: the way back a restore
	 * keeps in good faith, refused with the reasons Guarded::restore() gives
	 * when the kept copy or the path has moved. Only a restore these
	 * abilities made: a restore's undo puts an altered file back, and an
	 * assistant takes back only what an assistant did.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function undo_restore( object $entry, string $token ) {
		$refused = self::shared_code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		if ( null === Proposals::by_undo_token( $token ) ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'That change is not one these abilities made.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$done = \BetterShield\Files\Guarded::restore( $token );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		$prior = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$path  = ltrim( str_replace( ABSPATH, '', (string) ( $prior['path'] ?? '' ) ), '/' );

		// The difference is back on disk, so the change the restore closed is
		// listed again, as it is when the owner puts the file back.
		\BetterShield\Integrity\Restore::reopen_put_back( (string) ( $prior['path'] ?? '' ), (string) ( $prior['sha256'] ?? '' ) );

		Writer::instance()->record(
			'agent_write_reverted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file_change',
				'object_id'   => $path,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/revert-hardening',
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		return array(
			'reverted'    => true,
			'target'      => $path,
			'target_type' => 'file_change',
			'notes'       => array( __( 'The file as it was before the restore is back from quarantine, byte for byte.', 'bettershield' ) ),
		);
	}

	/**
	 * Apply one protection.
	 *
	 * Two paths, and which one a call takes is decided by the protection
	 * rather than by the caller. A reversible protection is applied directly:
	 * the credential asking already holds the capability that manages this
	 * site and the one that exists only while the owner has asked for a write
	 * surface, the change is recorded before it happens, and the way back is
	 * written to the ledger before anything moves — so the guarantee is made
	 * by construction rather than by asking somebody first.
	 *
	 * A protection that changes how people sign in is not. That one is
	 * refused here and answered with the name of the proposal path, because
	 * the failure mode is somebody locked out of their own site and the way
	 * back has to be proved by a person before it is risked.
	 *
	 * The order is the contract either way, and every step of it is
	 * load-bearing: the gate again, the rate limit, the confirmation spent in
	 * one statement where there is one, the state compared against the plan,
	 * the record written, and only then the change.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function apply_hardening( $input ) {
		$this->self_audit( 'bettershield/apply-hardening', $input );

		$refused = self::write_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input        = is_array( $input ) ? $input : array();
		$confirmation = (string) ( $input['confirmation'] ?? '' );
		$proposal_id  = (int) ( $input['proposal_id'] ?? 0 );

		/*
		 * Which of the two shapes this is, decided before anything is spent.
		 * A caller naming a plan means the confirmed path, and used to be sent
		 * down the direct one instead: the change happened, the row stayed
		 * open, and the owner's screen showed a plan waiting to be allowed for
		 * something that had already been done.
		 */
		if ( '' === $confirmation && $proposal_id > 0 ) {
			return new \WP_Error(
				'bettershield_confirmation_required',
				__( 'This names a plan, so it needs the confirmation a person minted for that plan. Send the confirmation, or leave the proposal out to apply a protection directly.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		/*
		 * And the field the confirmed path needs, asked for before the
		 * confirmation is taken. A confirmation is single use, so spending one
		 * to tell the caller which field they left out costs a person a second
		 * trip to the dashboard for a mistake nothing had to make.
		 */
		if ( '' !== $confirmation && $proposal_id <= 0 ) {
			return new \WP_Error(
				'bettershield_proposal_required',
				__( 'Name the plan this confirmation was minted for, as proposal_id. Nothing was changed and the confirmation still stands.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		// The direct path's own refusals, read off the item's definition
		// alone, and asked here for the same reason.
		if ( '' === $confirmation ) {
			$refused = self::direct_refusal(
				(string) ( $input['item_id'] ?? '' ),
				isset( $input['options'] ) && is_array( $input['options'] ) ? $input['options'] : array()
			);

			if ( null !== $refused ) {
				return $refused;
			}
		}

		/*
		 * The hour's slot is taken only now, once the call has been read as
		 * well-formed. Every refusal above is one the caller fixes by reading
		 * the schema again, and a limiter that counted those spent the few
		 * changes an hour allows on calls that changed nothing: an agent that
		 * mis-shaped a handful was then refused the one it had got right, and
		 * told to wait an hour. The refusals past this line are about the
		 * site's state, and those are what the ceiling is for.
		 */
		$limited = self::rate_limit( 'apply-hardening' );

		if ( null !== $limited ) {
			return self::refuse_early( 'bettershield/apply-hardening', 'hardening_item', (string) ( $input['item_id'] ?? '' ), $limited );
		}

		if ( '' === $confirmation ) {
			return $this->apply_directly(
				(string) ( $input['item_id'] ?? '' ),
				isset( $input['options'] ) && is_array( $input['options'] ) ? $input['options'] : array(),
				(string) ( $input['state_digest'] ?? '' )
			);
		}

		$proposal = Proposals::spend( $confirmation, 'bettershield/apply-hardening' );

		if ( is_wp_error( $proposal ) ) {
			return self::refuse_early( 'bettershield/apply-hardening', 'hardening_item', '', $proposal );
		}

		$item    = (string) ( $proposal->plan['item_id'] ?? '' );
		$options = isset( $proposal->plan['options'] ) && is_array( $proposal->plan['options'] ) ? $proposal->plan['options'] : array();

		if ( in_array( $item, self::HUMAN_ONLY_ITEMS, true ) || ! isset( Items::all()[ $item ] ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_human_only', __( 'This protection is not applied through an ability.', 'bettershield' ), array( 'status' => 403 ) )
			);
		}

		$dry = Manager::instance()->dry_run( $item, $options );

		if ( is_wp_error( $dry ) ) {
			return self::refuse( $proposal, $dry );
		}

		$now = self::hardening_digest( $item, $options, $dry );

		if ( ! hash_equals( (string) $proposal->state_digest, $now ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error(
					'bettershield_state_moved',
					sprintf(
						/* translators: %s: what the site says about this protection now. */
						__( 'This site has changed since that plan was made, so the plan no longer describes it: %s. Ask for the change again.', 'bettershield' ),
						self::what_moved( $item, $options, $dry, (string) $proposal->state_digest )
					),
					array( 'status' => 409 )
				)
			);
		}

		if ( Permissions::needs_way_back( $item ) && ( ! self::recovery_ready() || 1 !== (int) $proposal->minted_with_sudo ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_recovery_unverified', self::unverified_reason(), array( 'status' => 409 ) )
			);
		}

		/*
		 * The record of what is about to happen, written and flushed before it
		 * happens. A change that dies halfway leaves this row behind, which is
		 * the half an owner reading the log afterwards actually needs.
		 */
		Writer::instance()->record(
			'agent_write_applied',
			// Medium: a person allowed this change minutes ago and the row that
			// minted the confirmation names them. The direct path, with nobody
			// in the loop, is the one recorded high.
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/apply-hardening',
						'proposal_id' => (int) $proposal->id,
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);
		Writer::instance()->flush();

		$applied = Manager::instance()->apply( $item, $options );

		if ( is_wp_error( $applied ) ) {
			return self::refuse( $proposal, $applied );
		}

		Proposals::record_outcome( (int) $proposal->id, 'applied', (string) $applied['undo_token'] );

		return self::applied_answer( $item, $applied );
	}

	/**
	 * The refusals the direct path gives from the item's definition alone.
	 *
	 * Nothing here reads the site or spends anything, which is why the
	 * caller asks them before the hour's slot is taken.
	 */
	private static function direct_refusal( string $item, array $options = array() ): ?\WP_Error {
		// Neither shape of the call: input the schema cannot refuse, since
		// both shapes leave every field optional. Filed as input, not as a
		// protection that does not exist (#2216).
		if ( '' === $item ) {
			return new \WP_Error(
				'bettershield_item_missing',
				__( 'Name the protection to apply.', 'bettershield' ),
				array(
					'status'        => 400,
					'input_invalid' => true,
				)
			);
		}

		if ( ! isset( Items::all()[ $item ] ) ) {
			return new \WP_Error(
				'bettershield_unknown_item',
				__( 'Name the protection to apply.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		if ( in_array( $item, self::HUMAN_ONLY_ITEMS, true ) ) {
			return new \WP_Error(
				'bettershield_human_only',
				__( 'This protection writes a rule block into a shared configuration file, which stays the site owner’s own switch. It is not described or applied through an ability.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		/*
		 * Two reasons a protection waits for a person, asked as one question.
		 * The direct path is warranted by the ledger row alone — the way back
		 * is written before the change, so it is guaranteed by construction —
		 * and a protection the item itself says is not reversible has no such
		 * warrant, whatever else is true of it. The sign-in door is the other
		 * reason, and it is one arm of the answer rather than the whole rule.
		 */
		/*
		 * Each refusal below carries a code of its own, because the agent
		 * audit keeps the code and nothing else. An agent that keeps asking
		 * to change how people sign in and one that asked for something that
		 * cannot be undone are different stories, and under one shared code
		 * they read as the same five rows.
		 */
		if ( Permissions::changes_signing_in( $item ) ) {
			return new \WP_Error(
				'bettershield_signin_change_refused',
				__( 'This protection changes how people sign in, so it is not applied directly. Ask for it with propose-hardening: the plan comes back with the confirmation the apply takes, for the person to agree to first.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// The site's own address: a certificate that fails afterwards takes
		// the dashboard with it, so a person agrees first (#1289).
		if ( in_array( $item, Items::ADDRESS_ITEMS, true ) ) {
			return new \WP_Error(
				'bettershield_address_change_refused',
				__( 'This protection changes the site’s own address, so it is not applied directly. Ask for it with propose-hardening: the plan comes back with the confirmation the apply takes, for the person to agree to first.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( ! self::item_is_reversible( $item, $options ) ) {
			return new \WP_Error(
				'bettershield_irreversible_refused',
				__( 'Undoing this protection with these options does not reach everything it changes, so it is not applied directly. Ask for it with propose-hardening: the plan comes back with the confirmation the apply takes, for the person to agree to first.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return null;
	}

	/**
	 * Apply a reversible protection with no proposal in front of it.
	 *
	 * Everything that made the confirmed path safe is still here except the
	 * confirmation: the same human-only list, the same refusal for an item
	 * this installation cannot offer, the same activity row and the same
	 * ledger row written before the change, and the same handle in the answer.
	 * What is gone is the round trip through a person, which for a change that
	 * can be undone exactly was ceremony rather than protection.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	private function apply_directly( string $item, array $options, string $state_digest = '' ) {
		$refused = self::direct_refusal( $item, $options );

		if ( null !== $refused ) {
			return $refused;
		}

		$dry = Manager::instance()->dry_run( $item, $options );

		if ( is_wp_error( $dry ) ) {
			return $dry;
		}

		/*
		 * The state the caller says the plan was computed from, compared
		 * against the state there is now. Optional, so a bare {item_id} call
		 * still works; when it is supplied it is checked, because a digest
		 * accepted and discarded is worse than one nobody sent — it is a check
		 * a client believes it has.
		 */
		if ( '' !== $state_digest && ! hash_equals( self::hardening_digest( $item, $options, $dry ), $state_digest ) ) {
			return new \WP_Error(
				'bettershield_state_moved',
				sprintf(
					/* translators: %s: what the site says about this protection now. */
					__( 'This site has changed since that plan was made, so the plan no longer describes it: %s. Ask for the change again.', 'bettershield' ),
					self::what_moved( $item, $options, $dry, $state_digest )
				),
				array( 'status' => 409 )
			);
		}

		/*
		 * The record of what is about to happen, written and flushed before it
		 * happens. A change that dies halfway leaves this row behind, which is
		 * the half an owner reading the log afterwards actually needs.
		 */
		Writer::instance()->record(
			// Its own type rather than the confirmed one with a flag beside
			// it. The log's readable name is derived from the type alone, so
			// under the shared type a change nobody was in the loop for was
			// described to the owner in the words of one they had allowed —
			// and that word invites the reader to assume they did.
			'agent_write_applied_direct',
			// High, and deliberately: nobody was in the loop, and a leaked
			// credential looks exactly like this.
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/apply-hardening',
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);
		Writer::instance()->flush();

		$applied = Manager::instance()->apply( $item, $options );

		if ( is_wp_error( $applied ) ) {
			Writer::instance()->record(
				'agent_write_refused',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'hardening_item',
					'object_id'   => $item,
					'context'     => self::without_nulls(
						array(
							'ability'     => 'bettershield/apply-hardening',
							'reason'      => $applied->get_error_code(),
							'correlation' => Capture::instance()->current_correlation(),
						)
					),
				)
			);

			return $applied;
		}

		return self::applied_answer( $item, $applied );
	}

	/**
	 * Put back what one of these abilities changed.
	 *
	 * A credential may make this site safer or return it to where it was, and
	 * only a person may make it weaker. Which of those a revert is depends
	 * entirely on what is being reverted, and the three cases divide cleanly.
	 * Switching a plugin back on and putting a restored file back return the
	 * site to where it was, so they ask for nothing beyond the gate and the
	 * ceiling. Taking a protection off does not: protected to unprotected
	 * re-opens whatever the item was holding off — the file editor, XML-RPC, a
	 * moved sign-in door — so it is a weakening, and it takes the same
	 * confirmation contract the apply of an irreversible item takes.
	 *
	 * The rate limit and the gate apply to all three, because a loop is a loop
	 * whichever way it runs.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function revert_hardening( $input ) {
		$this->self_audit( 'bettershield/revert-hardening', $input );

		$refused = self::write_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input        = is_array( $input ) ? $input : array();
		$token        = (string) ( $input['undo_token'] ?? '' );
		$confirmation = (string) ( $input['confirmation'] ?? '' );
		$unknown      = new \WP_Error( 'bettershield_unknown_undo', __( 'That change is not one this site recorded.', 'bettershield' ), array( 'status' => 404 ) );

		/*
		 * Every refusal the caller fixes by reading the answer comes before
		 * the hour's slot, as in apply_hardening(): a handle this site never
		 * issued, and a protection taken off without a confirmation. The
		 * second is how the tool tells a caller to ask for a plan, and counted,
		 * it spent the slot the confirmed call then needed. A handle is
		 * 128 random bits, so answering an unknown one first opens nothing to
		 * guessing; a wrong or spent confirmation still counts.
		 */
		if ( '' === $token ) {
			return $unknown;
		}

		$entry = Ledger::find( $token );

		if ( null === $entry ) {
			return $unknown;
		}

		$key  = (string) $entry->action_key;
		$item = '';
		$extension = WriteExtensions::undo( $key );
		if ( null !== $extension ) {
			// Named before the hour's slot, as a protection taken off without its plan is below.
			if ( '' === $confirmation ) {
				return self::refuse_early( 'bettershield/revert-hardening', (string) $extension['target_type'], '', new \WP_Error( 'bettershield_confirmation_required', sprintf( /* translators: %s: the ability that plans the way back. */ __( 'Taking this back asks for a person. Ask for the plan with %s and this handle, show it to them, and send the confirmation it carries.', 'bettershield' ), (string) $extension['propose'] ), array( 'status' => 403 ) ) );
			}
			return $this->run_extension( $extension['act'], $input, true );
		}

		if ( ! in_array( $key, array( self::DEACTIVATION_KEY, 'integrity_restore', Restore::SUPPRESS_UNDO, \BetterShield\Incidents\Repository::STATUS_UNDO ), true ) ) {
			if ( 0 !== strpos( $key, 'harden_' ) ) {
				return new \WP_Error( 'bettershield_unknown_undo', __( 'That change is not one these abilities made.', 'bettershield' ), array( 'status' => 404 ) );
			}

			$item = substr( $key, strlen( 'harden_' ) );

			/*
			 * From here the direction is unsafe, so the contract is the
			 * apply's. Asked before the confirmation is taken and recorded as a
			 * refusal: a credential trying to strip a protection unattended is
			 * the one thing on this surface an owner most needs the log to show.
			 */
			if ( '' === $confirmation ) {
				return self::refuse_early(
					'bettershield/revert-hardening',
					'hardening_item',
					$item,
					new \WP_Error(
						'bettershield_confirmation_required',
						__( 'Taking a protection off asks for a person. Ask for the plan with propose-hardening and the action "revert", show it to them, and send the confirmation it carries.', 'bettershield' ),
						array( 'status' => 403 )
					)
				);
			}
		}

		$limited = self::rate_limit( 'revert-hardening' );

		if ( null !== $limited ) {
			return self::refuse_early( 'bettershield/revert-hardening', 'hardening_item', $item, $limited );
		}

		if ( in_array( $key, array( Restore::SUPPRESS_UNDO, \BetterShield\Incidents\Repository::STATUS_UNDO ), true ) ) { return self::undo_triage( $entry, $token ); }

		if ( self::DEACTIVATION_KEY === $key ) {
			return self::reactivate_plugin( $entry, $token );
		}

		if ( 'integrity_restore' === $key ) {
			return self::undo_restore( $entry, $token );
		}

		$proposal = Proposals::spend( $confirmation, 'bettershield/revert-hardening' );

		if ( is_wp_error( $proposal ) ) {
			return self::refuse_early( 'bettershield/revert-hardening', 'hardening_item', $item, $proposal );
		}

		// The plan named a protection, and this is a handle to one. A
		// confirmation that opened whichever protection the caller happened to
		// hold a handle for would be a confirmation for the ability rather
		// than for the change.
		if ( (string) $proposal->target !== $item ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_confirmation_unknown', __( 'That confirmation belongs to a different change.', 'bettershield' ), array( 'status' => 403 ) )
			);
		}

		if ( ! hash_equals( (string) $proposal->state_digest, self::revert_digest( $item, $token ) ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error(
					'bettershield_state_moved',
					__( 'This protection is not the one the plan described, so the plan no longer describes it. Ask for the change again.', 'bettershield' ),
					array( 'status' => 409 )
				)
			);
		}

		$reverted = Manager::instance()->revert_if_token( $item, $token, Manager::CAUSE_API );

		if ( is_wp_error( $reverted ) ) {
			return self::refuse( $proposal, $reverted );
		}

		Writer::instance()->record(
			'agent_write_reverted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'hardening',
				'object_id'   => $item,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/revert-hardening',
						'proposal_id' => (int) $proposal->id,
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		Proposals::record_outcome( (int) $proposal->id, 'reverted', null );

		return array(
			'reverted'    => true,
			'target'      => $item,
			'target_type' => 'hardening_item',
			'notes'       => array_values( array_map( 'strval', (array) ( $reverted['notes'] ?? array() ) ) ),
		);
	}

	/**
	 * A plan for switching one plugin off.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function propose_plugin_deactivation( $input ) {
		$this->self_audit( 'bettershield/propose-plugin-deactivation', $input );

		$refused = self::write_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input  = is_array( $input ) ? $input : array();
		$plugin = self::plugin_file( (string) ( $input['plugin'] ?? '' ) );

		// Shape before the hour's slot, as in apply_hardening(): the plugin
		// named has to be one this site has and is allowed to switch off.
		if ( is_wp_error( $plugin ) ) {
			return $plugin;
		}

		$limited = self::propose_rate_limit( 'propose-plugin-deactivation' );

		if ( null !== $limited ) {
			return $limited;
		}

		$data    = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
		$network = is_multisite() && is_plugin_active_for_network( $plugin );
		$active  = is_plugin_active( $plugin );
		$digest  = self::plugin_digest( $plugin, $active, $network );

		$network_only = self::network_plugin_gate( $network );

		if ( null !== $network_only ) {
			return $network_only;
		}

		$plan = array(
			'plugin'                => $plugin,
			'name'                  => (string) ( $data['Name'] ?? $plugin ),
			'target_type'           => 'plugin',
			'active'                => $active,
			'network'               => $network,
			'effect'                => self::deactivation_effect( $plugin, $network ),
			'changes_signing_in'    => false,
			'recovery_ready'        => self::recovery_ready(),
			/*
			 * Switching a plugin back on runs its activation routine again;
			 * it does not restore the state the site was in before. What the
			 * ledger row buys here is a record of what was on, which is a good
			 * way back rather than a guaranteed one — so this stays on the
			 * confirmed path and says so in the field that carries the answer.
			 */
			'reversible'            => false,
			'state_digest'          => $digest,
			'expires_at'            => gmdate( 'c', time() + Proposals::WINDOW_SECONDS ),
			'confirmation_required' => true,
		);

		return self::record_proposal( 'bettershield/deactivate-plugin', $plugin, 'plugin', $plan, $digest );
	}

	/**
	 * Switch off the plugin a person allowed.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function deactivate_plugin( $input ) {
		$this->self_audit( 'bettershield/deactivate-plugin', $input );

		$refused = self::write_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$input        = is_array( $input ) ? $input : array();
		$confirmation = (string) ( $input['confirmation'] ?? '' );
		$proposal_id  = (int) ( $input['proposal_id'] ?? 0 );

		// Shape before the hour's slot, as in apply_hardening(): a call
		// missing either field is answered as the spend below would answer
		// it, before it is counted.
		if ( '' === $confirmation || $proposal_id <= 0 ) {
			return new \WP_Error(
				'bettershield_confirmation_unknown',
				__( 'That confirmation does not match a change waiting to be made.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		$limited = self::rate_limit( 'deactivate-plugin' );

		if ( null !== $limited ) {
			return self::refuse_early( 'bettershield/deactivate-plugin', 'plugin', '', $limited );
		}

		/*
		 * The two refusals that can be seen coming, asked before the
		 * confirmation is taken: a plugin the caller may not switch off, and a
		 * plugin that is not running in the first place. Both are read off the
		 * plan the caller named rather than off the row the confirmation
		 * spends, so a person does not lose their one confirmation to an
		 * answer that was knowable without it. Both are asked again below, of
		 * the row that was actually spent, because that row is the authority
		 * on what is being switched off.
		 */
		$foreseen = self::plugin_deactivation_gate( $proposal_id );

		if ( null !== $foreseen ) {
			return $foreseen;
		}

		$proposal = Proposals::spend( $confirmation, 'bettershield/deactivate-plugin' );

		if ( is_wp_error( $proposal ) ) {
			return self::refuse_early( 'bettershield/deactivate-plugin', 'plugin', '', $proposal );
		}

		if ( (int) $proposal->id !== $proposal_id ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_confirmation_unknown', __( 'That confirmation belongs to a different change.', 'bettershield' ), array( 'status' => 403 ) )
			);
		}

		$plugin = self::plugin_file( (string) ( $proposal->plan['plugin'] ?? '' ) );

		if ( is_wp_error( $plugin ) ) {
			return self::refuse( $proposal, $plugin );
		}

		$network = is_multisite() && is_plugin_active_for_network( $plugin );
		$active  = is_plugin_active( $plugin );

		$network_only = self::network_plugin_gate( $network );

		if ( null !== $network_only ) {
			return self::refuse( $proposal, $network_only );
		}

		/*
		 * A plugin that is not running cannot be switched off, and answering
		 * `deactivated: true` for one leaves a ledger row whose undo would
		 * switch on something the owner never had running.
		 */
		if ( ! $active ) {
			return self::refuse(
				$proposal,
				new \WP_Error(
					'bettershield_plugin_not_active',
					__( 'That plugin is not running, so there is nothing here to switch off.', 'bettershield' ),
					array( 'status' => 409 )
				)
			);
		}

		if ( ! hash_equals( (string) $proposal->state_digest, self::plugin_digest( $plugin, $active, $network ) ) ) {
			return self::refuse(
				$proposal,
				new \WP_Error(
					'bettershield_state_moved',
					__( 'This plugin is not in the state the plan described, so the plan no longer describes it. Ask for the change again.', 'bettershield' ),
					array( 'status' => 409 )
				)
			);
		}

		// Ledger first: if the way back cannot be written down, nothing moves.
		$token = Ledger::open(
			self::DEACTIVATION_KEY,
			array(
				'plugin'  => $plugin,
				'active'  => $active,
				'network' => $network,
			),
			array( 'active' => false )
		);

		if ( null === $token ) {
			return self::refuse(
				$proposal,
				new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed, because the way back could not be recorded.', 'bettershield' ), array( 'status' => 500 ) )
			);
		}

		Writer::instance()->record(
			'agent_write_applied',
			// Medium: a person allowed this change minutes ago and the row that
			// minted the confirmation names them. The direct path, with nobody
			// in the loop, is the one recorded high.
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/deactivate-plugin',
						'proposal_id' => (int) $proposal->id,
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);
		Writer::instance()->flush();

		deactivate_plugins( array( $plugin ), false, $network );

		Proposals::record_outcome( (int) $proposal->id, 'deactivated', $token );

		return array(
			'deactivated' => true,
			'plugin'      => $plugin,
			'undo_token'  => $token,
		);
	}

	/* ---- write helpers ----------------------------------------------------------- */

	/**
	 * The gate, asked again inside the callback.
	 *
	 * The permission callback already asked, and both opt-ins can be turned
	 * off between a registry being built and a callback running. A registered
	 * ability that kept working after the owner withdrew consent would make
	 * the switch a suggestion.
	 */
	private static function write_gate(): ?\WP_Error {
		if ( self::can_write() ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_write_denied',
			__( 'Agents are not allowed to change this site.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * The gate the dashboard's own file routes carry: a file in the code a
	 * network shares is the network's to write, not one site's, whoever's
	 * assistant is asking.
	 */
	private static function shared_code_gate(): ?\WP_Error {
		$allowed = Permissions::shared_code( false );

		return true === $allowed ? null : $allowed;
	}

	/**
	 * How many changes of one kind an hour, counted where two requests cannot
	 * both find the window clear.
	 *
	 * Counted for the credential asking, so one connection's changes never
	 * spend another's, and for the site as a whole under a cap a few times
	 * higher. The credential's count is taken first: a call it refuses
	 * leaves the site's count alone.
	 *
	 * A counter that cannot be read is not a ceiling with room under it: a
	 * null answer refuses, exactly as the sign-in counters do.
	 */
	private static function rate_limit( string $ability, ?int $ceiling = null ): ?\WP_Error {
		$ceiling = max( 1, null === $ceiling ? (int) apply_filters( 'bettershield_agent_write_limit', self::WRITE_LIMIT_PER_HOUR ) : $ceiling );
		$mine    = Claim::bump_or_fail( 'agent_write_' . $ability . '@' . substr( hash( 'sha256', self::caller() ), 0, 16 ), HOUR_IN_SECONDS );
		$site    = null !== $mine && $mine <= $ceiling ? Claim::bump_or_fail( 'agent_write_' . $ability, HOUR_IN_SECONDS ) : null;

		if ( null !== $site && $site <= $ceiling * self::SITE_LIMIT_FACTOR ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_rate_limited',
			__( 'There were too many requests in the last hour. Try again later.', 'bettershield' ),
			array( 'status' => 429 )
		);
	}

	/**
	 * Who is asking, as the hourly ceilings count it: the connection an
	 * assistant came in on, the application password a REST caller signed
	 * in with, or otherwise the account itself.
	 */
	private static function caller(): string {
		$connection = \BetterShield\Mcp\Server::current_credential();

		if ( null !== $connection ) {
			return $connection;
		}

		$password = function_exists( 'rest_get_authenticated_app_password' ) ? rest_get_authenticated_app_password() : null;

		if ( is_string( $password ) && '' !== $password ) {
			return 'app_password:' . $password;
		}

		return 'user:' . get_current_user_id();
	}

	/**
	 * The ceiling on preparing a plan.
	 *
	 * Higher than the one on changing the site, because a plan changes
	 * nothing and an agent working through a site's protections reads more
	 * than it writes. Not absent, though: a plan is declared read-only and is
	 * therefore offered to a connection whose owner chose "look, do not
	 * touch", and every plan writes a row. An unbounded loop over this is a
	 * table growing on a credential that was never allowed to change anything.
	 */
	private static function propose_rate_limit( string $ability ): ?\WP_Error {
		return self::rate_limit( $ability, (int) apply_filters( 'bettershield_agent_propose_limit', self::PROPOSE_LIMIT_PER_HOUR ) );
	}

	/**
	 * Whether the item's own contract says undoing it puts the site back.
	 *
	 * Read off the item rather than off a list kept here: the line between
	 * what an agent applies on its own and what waits for a person is exactly
	 * reversibility, and an item added later has to answer for itself. An item
	 * that somehow says nothing is treated as reversible, which is what every
	 * item here was before any of them said anything — the declaration is
	 * required by the definitions and asserted by the suite.
	 */
	public static function item_is_reversible( string $item, array $options = array() ): bool {
		return Items::is_reversible( $item, $options );
	}

	/**
	 * The answer both apply paths give.
	 *
	 * @param array<string, mixed> $applied
	 * @return array<string, mixed>
	 */
	private static function applied_answer( string $item, array $applied ): array {
		return self::without_nulls(
			array(
				'applied'          => true,
				'item_id'          => $item,
				'undo_token'       => (string) $applied['undo_token'],
				'notes'            => array_values( array_map( 'strval', (array) ( $applied['notes'] ?? array() ) ) ),
				'conflict_warning' => null === ( $applied['conflict_warning'] ?? null ) ? null : (string) $applied['conflict_warning'],
			)
		);
	}

	/**
	 * Why a sign-in protection was not applied, in terms the person reading it
	 * can act on.
	 *
	 * Three causes, not two. The way back in was not checked recently enough;
	 * the site asks for the password again and nobody gave it; or the site
	 * asks and the account that allowed the change has no password to give —
	 * an account signed in by a passkey alone. Telling that last person to
	 * turn on a setting that is already on sends them nowhere.
	 */
	private static function unverified_reason(): string {
		if ( ! self::recovery_ready() ) {
			return __( 'This protection changes how people sign in, so the way back in has to have been checked within the last day. Check recovery, then ask for the change again.', 'bettershield' );
		}

		return self::password_reason();
	}

	/**
	 * Why a change to how people sign in cannot be allowed without a password
	 * re-entered: the switch that asks for one is off, or this account has
	 * none to give. The allow refuses with this before minting anything.
	 */
	public static function password_reason(): string {
		if ( \BetterShield\Rest\Sudo::enabled() ) {
			return __( 'This protection changes how people sign in, so the person allowing it has to confirm their password. It has to be allowed by an account that has one, or applied from the protection’s own screen.', 'bettershield' );
		}

		return __( 'This protection changes how people sign in, so the person allowing it has to confirm their password. Turn the password confirmation on and allow the change again.', 'bettershield' );
	}

	/**
	 * A plugin the whole network runs is the network's to switch off.
	 *
	 * Every other gate on this path is per site — the opt-in, the capability,
	 * the write capability — and a site administrator holding all three is
	 * still an administrator of one site. Removing a plugin from
	 * `active_sitewide_plugins` removes it from every other site on the
	 * network, including sites they have no standing on at all.
	 */
	private static function network_plugin_gate( bool $network ): ?\WP_Error {
		if ( ! $network || current_user_can( 'manage_network_plugins' ) ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_network_only',
			__( 'This plugin is active for the whole network, so switching it off is a network administrator’s to do.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * The refusals a deactivation can be given before its confirmation is
	 * spent, read off the plan the caller named.
	 *
	 * Answers null when there is no plan under that id: the spend that follows
	 * is what says so, with the code it has always used.
	 */
	private static function plugin_deactivation_gate( int $proposal_id ): ?\WP_Error {
		$proposal = $proposal_id > 0 ? Proposals::find( $proposal_id ) : null;

		if ( null === $proposal || 'bettershield/deactivate-plugin' !== (string) $proposal->ability ) {
			return null;
		}

		$plugin = self::plugin_file( (string) ( $proposal->plan['plugin'] ?? '' ) );

		if ( is_wp_error( $plugin ) ) {
			return $plugin;
		}

		$network_only = self::network_plugin_gate( is_multisite() && is_plugin_active_for_network( $plugin ) );

		if ( null !== $network_only ) {
			return $network_only;
		}

		if ( ! is_plugin_active( $plugin ) ) {
			return new \WP_Error(
				'bettershield_plugin_not_active',
				__( 'That plugin is not running, so there is nothing here to switch off.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return null;
	}

	/**
	 * Write the proposal row, and answer with the plan it holds.
	 *
	 * A plan with no row behind it is a plan nothing can confirm, so a row
	 * that could not be written is a refusal rather than an answer.
	 *
	 * @param array<string, mixed> $plan
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function record_proposal( string $ability, string $target, string $target_type, array $plan, string $digest ) {
		$id = Proposals::open( $ability, $target, $target_type, $plan, $digest );

		if ( null === $id ) {
			return new \WP_Error(
				'bettershield_proposal_failed',
				__( 'The plan could not be recorded, so there is nothing for anybody to confirm. Nothing was changed.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$confirmation = self::confirms_in_conversation() ? Proposals::mint( $id, get_current_user_id(), true ) : null;
		$confirm_by   = null === $confirmation ? 'dashboard' : 'conversation';

		Writer::instance()->record(
			'agent_proposal_made',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => $target_type,
				'object_id'   => $target,
				'context'     => self::without_nulls(
					array(
						'ability'     => $ability,
						'proposal_id' => $id,
						'confirm_by'  => $confirm_by,
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		if ( null !== $confirmation ) {
			// The same row the dashboard's Allow once writes, so the log
			// reads the same whichever way a plan was confirmed.
			Writer::instance()->record(
				'write_confirmation_minted',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => $target_type,
					'object_id'   => $target,
					'context'     => array(
						'ability'     => $ability,
						'proposal_id' => $id,
						'confirmed'   => true,
						'confirm_by'  => 'conversation',
					),
				)
			);
		}

		return array( 'proposal_id' => $id ) + $plan + array( 'confirm_by' => $confirm_by ) + ( null === $confirmation ? array() : array( 'confirmation' => $confirmation ) );
	}

	/**
	 * Whether the connection behind this call confirms in the conversation.
	 *
	 * A person who allowed an assistant to change the site made the decision
	 * the dashboard's Allow once then asked them for a second time, on a
	 * screen they had to go to. So a plan proposed over a connection with
	 * write scope comes back with its own confirmation — single-use, expiring
	 * and checked against the site's state exactly as before — and the
	 * assistant shows the plan and applies once the person agrees. The
	 * confirmation counts as the person's own, which is what the sign-in
	 * gate reads: the recovery link verified within the day still decides.
	 * A caller outside the endpoint uses the dashboard to allow a plan.
	 * Read-only connections cannot prepare proposals.
	 */
	private static function confirms_in_conversation(): bool {
		$scope = \BetterShield\Mcp\Server::current_scope();

		return null !== $scope && \BetterShield\Mcp\Scopes::allows_write( $scope ) && self::can_write();
	}

	/**
	 * Record a refusal that happened before anything was spent.
	 *
	 * `refuse()` below has a proposal row to name because the confirmation was
	 * taken; this one has only what was asked for and what stopped it. Both
	 * write the same type, so an owner reading the log sees one account of
	 * changes that did not happen rather than two halves with a gap between
	 * them.
	 *
	 * Refusals about shape are deliberately not recorded here: a field left
	 * out is fixed by reading the schema again, and it is not counted against
	 * the hour's allowance either. What is recorded is the same class the
	 * ceiling exists for — the caller's budget, and every way a confirmation
	 * can fail to be one.
	 *
	 * @param string $target What the change was about, where that is known
	 *                       without reading the plan the caller could not spend.
	 */
	private static function refuse_early( string $ability, string $target_type, string $target, \WP_Error $error ): \WP_Error {
		$row = array(
			'object_type' => $target_type,
			'context'     => self::without_nulls(
				array(
					'ability'     => $ability,
					'reason'      => $error->get_error_code(),
					'correlation' => Capture::instance()->current_correlation(),
				)
			),
		);

		if ( '' !== $target ) {
			$row['object_id'] = $target;
		}

		Writer::instance()->record( 'agent_write_refused', Writer::SEVERITY_MEDIUM, $row );

		return $error;
	}

	/**
	 * Record a refusal that happened after the confirmation was spent.
	 *
	 * The confirmation is gone either way — that is what single use means —
	 * so the row says what was asked for and what stopped it, and the log
	 * carries the same answer for somebody reading it later.
	 *
	 * @return \WP_Error
	 */
	private static function refuse( object $proposal, \WP_Error $error ): \WP_Error {
		Proposals::record_outcome( (int) $proposal->id, $error->get_error_code(), null );

		Writer::instance()->record(
			'agent_write_refused',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => (string) $proposal->target_type,
				'object_id'   => (string) $proposal->target,
				'context'     => self::without_nulls(
					array(
						'ability'     => (string) $proposal->ability,
						'proposal_id' => (int) $proposal->id,
						'reason'      => $error->get_error_code(),
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		return $error;
	}

	/**
	 * The digest a plan is pinned to: the item, what the site says about it
	 * now, and the options the plan was computed with.
	 *
	 * Read from the dry run rather than recomputed, so the thing compared at
	 * execution is the thing the plan described.
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $dry
	 */
	private static function hardening_digest( string $item, array $options, array $dry ): string {
		return (string) Capture::digest(
			array(
				'item'      => $item,
				'active'    => (bool) $dry['already_active'],
				'available' => (bool) $dry['available'],
				'options'   => $options,
			)
		);
	}

	/**
	 * What actually moved, in one clause, for the refusal that says the plan
	 * no longer fits.
	 *
	 * Named by comparing the two states rather than by reading the live one.
	 * Reading the live state alone tested one condition for truth and the
	 * other for falsity, so the two opposite transitions — an owner reverting
	 * an item by hand, and an installation that can offer a protection it
	 * could not before — both fell through to a catch-all blaming the caller's
	 * options, which is a sentence that sends somebody to look in the wrong
	 * place.
	 *
	 * The plan's own state is recovered from the digest it was pinned to:
	 * there are four combinations of the two booleans, so the one the digest
	 * was computed over identifies itself. Where it does not — a digest from
	 * a different item or different options — the catch-all is true again.
	 *
	 * @param array<string, mixed> $options
	 * @param array<string, mixed> $dry
	 */
	private static function what_moved( string $item, array $options, array $dry, string $planned_digest ): string {
		$now_active    = ! empty( $dry['already_active'] );
		$now_available = ! empty( $dry['available'] );

		foreach ( array( true, false ) as $was_active ) {
			foreach ( array( true, false ) as $was_available ) {
				$candidate = self::hardening_digest(
					$item,
					$options,
					array(
						'already_active' => $was_active,
						'available'      => $was_available,
					)
				);

				if ( ! hash_equals( $candidate, $planned_digest ) ) {
					continue;
				}

				if ( $was_active !== $now_active ) {
					return $now_active
						? __( 'it is already applied', 'bettershield' )
						: __( 'it is no longer applied', 'bettershield' );
				}

				if ( $was_available !== $now_available ) {
					return $now_available
						? __( 'this installation can offer it now', 'bettershield' )
						: __( 'this installation cannot offer it', 'bettershield' );
				}

				break 2;
			}
		}

		return __( 'what this site says about it is not what the plan was computed from', 'bettershield' );
	}

	/**
	 * The state a plugin plan is pinned to.
	 */
	private static function plugin_digest( string $plugin, bool $active, bool $network ): string {
		return (string) Capture::digest(
			array(
				'plugin'  => $plugin,
				'active'  => $active,
				'network' => $network,
			)
		);
	}

	/**
	 * What switching one plugin off does to this site, in the item vocabulary.
	 *
	 * @return string[]
	 */
	private static function deactivation_effect( string $plugin, bool $network ): array {
		$lines = array(
			__( 'Stops this plugin loading on the next request. Its files, settings and data are left exactly as they are.', 'bettershield' ),
			__( 'Runs the plugin’s own deactivation routine, which is code this plugin does not control.', 'bettershield' ),
			__( 'Records the prior state in the undo ledger before anything changes, so it can be switched back on.', 'bettershield' ),
		);

		if ( $network ) {
			$lines[] = __( 'This plugin is active across the whole network, so switching it off here switches it off for every site.', 'bettershield' );
		}

		return $lines;
	}

	/**
	 * A plugin file that names a plugin on this site, and is not this one.
	 *
	 * This plugin and anything extending it are refused outright: an ability
	 * that can switch off the thing enforcing the site's protections — the
	 * confirmation contract included — is a way around every other rule here.
	 *
	 * @return string|\WP_Error
	 */
	private static function plugin_file( string $plugin ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugin  = plugin_basename( trim( $plugin ) );
		$unknown = new \WP_Error( 'bettershield_unknown_plugin', __( 'There is no such plugin on this site.', 'bettershield' ), array( 'status' => 404 ) );

		if ( '' === $plugin || 0 !== validate_file( $plugin ) || ! isset( get_plugins()[ $plugin ] ) ) {
			return $unknown;
		}

		$directory = strtok( $plugin, '/' );

		if ( plugin_basename( BETTERSHIELD_FILE ) === $plugin || 'bettershield' === $directory || 0 === strpos( (string) $directory, 'bettershield-' ) ) {
			return new \WP_Error(
				'bettershield_human_only',
				__( 'This plugin and its extensions are not switched off through an ability.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		return $plugin;
	}

	/**
	 * Switch a plugin back on from the state its ledger row recorded.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function reactivate_plugin( object $entry, string $token ) {
		/*
		 * Under a mutex for the length of it, which is the shape every other
		 * undo here has and this one did not. Reading `reverted_at`, running
		 * the plugin's own activation routine — code this plugin does not
		 * control and cannot assume is idempotent — and only then marking the
		 * row is three statements with the change in the middle: two callers
		 * arriving together both read null, both activate, and one loses the
		 * row afterwards. The mutex is per change rather than shared, so one
		 * slow activation does not hold up an unrelated undo.
		 */
		if ( ! Claim::claim( 'agent_plugin_revert_' . $token, MINUTE_IN_SECONDS ) ) {
			return new \WP_Error(
				'bettershield_revert_busy',
				__( 'That change is already being put back. Try again in a moment.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		try {
			return self::reactivate_plugin_claimed( $entry, $token );
		} finally {
			Claim::release( 'agent_plugin_revert_' . $token );
		}
	}

	/**
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function reactivate_plugin_claimed( object $entry, string $token ) {
		/*
		 * Read again, inside the mutex. The row the caller arrived with was
		 * fetched before anything was claimed, so on a real race it is the
		 * state as it was before the other caller finished — which is exactly
		 * the reading that would send this one into a second activation.
		 */
		$entry = Ledger::find( $token ) ?? $entry;

		$prior  = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$plugin = self::plugin_file( (string) ( $prior['plugin'] ?? '' ) );

		if ( is_wp_error( $plugin ) ) {
			return $plugin;
		}

		// Putting a plugin back for the whole network is the same act as
		// taking it away from the whole network, and asks for the same standing.
		$network_only = self::network_plugin_gate( ! empty( $prior['network'] ) );

		if ( null !== $network_only ) {
			return $network_only;
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$notes = array();

		/*
		 * A plugin that was not running when it was "switched off" is put back
		 * by leaving it alone. An undo that made a change of its own would be
		 * a second change, and this one would start a plugin the owner had
		 * never had running.
		 */
		if ( empty( $prior['active'] ) ) {
			$notes[] = __( 'That plugin was not running before the change, so it has been left as it was.', 'bettershield' );
		} else {
			$activated = activate_plugin( $plugin, '', ! empty( $prior['network'] ) );

			if ( is_wp_error( $activated ) ) {
				Ledger::mark_revert_failed( $token, $activated->get_error_message() );

				return $activated;
			}
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'agent_write_reverted',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'plugin',
				'object_id'   => $plugin,
				'context'     => self::without_nulls(
					array(
						'ability'     => 'bettershield/revert-hardening',
						'correlation' => Capture::instance()->current_correlation(),
					)
				),
			)
		);

		return array(
			'reverted'    => true,
			'target'      => $plugin,
			'target_type' => 'plugin',
			'notes'       => $notes,
		);
	}

	/**
	 * One recorded file change, read for the plan that describes it.
	 */
	private static function change_row( int $change_id ): ?object {
		global $wpdb;

		if ( $change_id <= 0 || ! Schema::ready( 'integrity_changes' ) ) {
			return null;
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE ' . Schema::site_where( 'integrity_changes' ) . ' AND id = %d',
				Schema::table( 'integrity_changes' ),
				$change_id
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return null === $row ? null : $row;
	}

	/**
	 * How much of a file differs, counted from the rendered comparison.
	 *
	 * Counts only: the lines themselves are the contents of a file, and a
	 * security plugin that hands file contents to an agent is a worse problem
	 * than the one it was asked about.
	 *
	 * @return array{lines_added: int, lines_removed: int, comparable: bool}
	 */
	private static function difference_summary( string $rendered ): array {
		$added   = substr_count( $rendered, 'diff-addedline' );
		$removed = substr_count( $rendered, 'diff-deletedline' );

		return array(
			'lines_added'   => $added,
			'lines_removed' => $removed,
			// A binary file, one past the comparison budget, or one that is
			// simply gone: the hashes still differ and the lines cannot be
			// counted, which is a state rather than a zero.
			'comparable'    => $added > 0 || $removed > 0,
		);
	}

	/* ---- callbacks -------------------------------------------------------------- */

	/**
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_security_posture( $input ): array {
		$this->self_audit( 'bettershield/get-security-posture', $input );

		$include_resolved = is_array( $input ) && ! empty( $input['include_resolved'] );

		$overview = Auditor::overview();
		$findings = array();

		foreach ( Auditor::findings() as $finding ) {
			if ( ! $include_resolved && 'open' !== $finding['status'] ) {
				continue;
			}

			$findings[] = array(
				'id'          => (string) $finding['id'],
				'severity'    => (string) $finding['severity'],
				'status'      => (string) $finding['status'],
				'title'       => (string) $finding['title'],
				'explanation' => (string) ( $finding['why'] ?? '' ),
				'remediable'  => (bool) ( $finding['remediable'] ?? false ),
				// Set to applied already: nothing here to apply, and an open
				// finding beside it means nothing is enforcing it right now
				// (safe mode pauses every protection), which is not a thing
				// applying again can change.
				'applied'     => (bool) ( $finding['hardening_active'] ?? false ),
				'reversible'  => null !== ( $finding['hardening_item'] ?? null ),
			);

			// The protection that fixes it, by the id propose-hardening and
			// apply-hardening take, so a caller can act on a finding without
			// keeping its own map of which item answers which. Left out, not
			// null, where no protection answers it.
			if ( null !== ( $finding['hardening_item'] ?? null ) ) {
				$findings[ count( $findings ) - 1 ]['hardening_item'] = (string) $finding['hardening_item'];
			}

			// Set aside by the owner until then: still open and still counted
			// in the score, and left out of what needs attention, as the
			// Overview and the weekly summary leave it out. Left out, not
			// null, when it is not snoozed.
			if ( null !== ( $finding['snoozed_until'] ?? null ) ) {
				$findings[ count( $findings ) - 1 ]['snoozed_until'] = (string) $finding['snoozed_until'];
			}
		}

		$unknown = array();

		foreach ( (array) ( $overview['checks_unknown'] ?? array() ) as $check ) {
			$unknown[] = array(
				'check'            => (string) ( $check['key'] ?? '' ),
				'title'            => (string) ( $check['title'] ?? '' ),
				'reason_code'      => (string) ( $check['code'] ?? '' ),
				'reason'           => (string) ( $check['reason'] ?? '' ),
				'last_answered_at' => (string) ( $check['last_answered_at'] ?? '' ),
			);
		}

		return array(
			'score'          => (int) $overview['score'],
			'grade'          => (string) $overview['grade'],
			'generated_at'   => (string) $overview['generated_at'],
			'findings_count' => count( $findings ),
			'findings'       => $findings,
			// What this posture does not cover, named. A caller that cannot
			// tell a check that passed from one that never ran will read the
			// first as the second.
			'checks_unknown' => $unknown,
		);
	}

	/**
	 * The sites a caller may read across, from the ones they asked for.
	 *
	 * Empty unless this is a network, the caller named sites, and they hold
	 * the network read permission — so an ordinary administrator naming a
	 * neighbor's id is answered with their own site's log rather than an
	 * error, and never with somebody else's rows. Ids that are not on the
	 * network are dropped: a super administrator cannot read a blog that does
	 * not exist here either.
	 *
	 * @param array<string, mixed> $input
	 * @return int[]
	 */
	private function requested_sites( array $input ): array {
		if ( ! is_multisite() || ! isset( $input['sites'] ) || ! is_array( $input['sites'] ) || array() === $input['sites'] ) {
			return array();
		}

		if ( ! \BetterShield\Rest\Permissions::network_read() ) {
			return array();
		}

		$real = array();

		// Each id asked about, rather than a listing of the network: a caller
		// naming three sites should cost three lookups and not a walk of ten
		// thousand. The lookup is global — it finds a site on any network in
		// the database — so membership of this one is checked as well.
		foreach ( array_map( 'intval', $input['sites'] ) as $blog_id ) {
			$site = $blog_id > 0 ? get_site( $blog_id ) : null;

			if ( $site instanceof \WP_Site && (int) $site->network_id === get_current_network_id() ) {
				$real[] = $blog_id;
			}
		}

		return array_values( array_unique( $real ) );
	}

	/**
	 * The site predicate this call reads under.
	 *
	 * @param array<string, mixed> $input
	 */
	private function activity_scope( array $input ): string {
		$sites = $this->requested_sites( $input );

		return array() === $sites ? Schema::site_where( 'events' ) : Schema::network_where( $sites );
	}

	/**
	 * Which table answers. A read across sites is a read of the network
	 * table whatever the site serving the call has been switched to.
	 *
	 * @param array<string, mixed> $input
	 */
	private function activity_table( array $input ): string {
		return array() === $this->requested_sites( $input ) ? Schema::table( 'events' ) : Schema::network_table( 'events' );
	}

	/**
	 * An unknown group is refused rather than answered with an empty page,
	 * which would read as "nothing happened" for a filter that names nothing.
	 * Declared in the signature because a WP_Error out of a method typed
	 * `array` is a TypeError under strict_types, on the one input a caller is
	 * most likely to get wrong.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function query_activity( $input ): array|\WP_Error {
		$this->self_audit( 'bettershield/query-activity', $input );

		global $wpdb;

		$input = is_array( $input ) ? $input : array();
		$limit = min( 200, max( 1, (int) ( $input['limit'] ?? 50 ) ) );

		/*
		 * A bound that cannot be read is refused, for the reason an unknown
		 * group is: an unreadable `since` used to be no bound at all, so the
		 * whole log came back, and a cursor cast to 0 answered "nothing".
		 * Empty still means not given.
		 */
		foreach ( array( 'since', 'until' ) as $bound ) {
			if ( isset( $input[ $bound ] ) && ( ! is_scalar( $input[ $bound ] ) || ( '' !== (string) $input[ $bound ] && null === $this->to_mysql( (string) $input[ $bound ] ) ) ) ) {
				return new \WP_Error(
					'bettershield_bad_time',
					/* translators: %s: since or until, the input's name. */
					sprintf( __( 'This ability cannot read the time given as %s. Send it as ISO 8601 UTC, for example 2026-10-01T00:00:00Z.', 'bettershield' ), $bound ),
					array( 'status' => 400 )
				);
			}
		}

		if ( isset( $input['cursor'] ) && ( ! is_scalar( $input['cursor'] ) || 1 !== preg_match( '/^[0-9]*$/', (string) $input['cursor'] ) ) ) {
			return new \WP_Error(
				'bettershield_bad_cursor',
				__( 'That is not a cursor this ability gave out. Send the cursor from the previous answer, or none for the first page.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		// Retention clamping: silent, flagged, never an error, never a pitch.
		$floor     = \BetterShield\Support\Tier::retention_floor();
		$since     = isset( $input['since'] ) ? $this->to_mysql( (string) $input['since'] ) : null;
		// Clamped, not truncated: a caller who named no window had none cut
		// short, and the flag means "less than you asked for" — which reads to
		// an agent as "you are not seeing everything".
		$truncated = null !== $since && $since < $floor;
		$since     = ( null === $since || $since < $floor ) ? $floor : $since;

		$where  = array( $this->activity_scope( $input ), 'occurred_at >= %s' );
		$params = array( $since );

		if ( isset( $input['until'] ) ) {
			$until = $this->to_mysql( (string) $input['until'] );
			if ( null !== $until ) {
				$where[]  = 'occurred_at <= %s';
				$params[] = $until;
			}
		}

		if ( isset( $input['event_type'] ) ) {
			$group = (string) $input['event_type'];

			/*
			 * An unrecognized group used to fall through to no filter at all,
			 * so a caller asking for one thing was handed everything and had
			 * no way to tell. Core's schema refuses an unknown value before
			 * this runs; a direct caller gets the same answer here rather
			 * than a silently different one.
			 */
			if ( ! isset( self::EVENT_GROUPS[ $group ] ) ) {
				return new \WP_Error(
					'bettershield_unknown_event_type',
					__( 'That is not an event type this ability knows.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$concrete = self::EVENT_GROUPS[ $group ];

			if ( array() === $concrete ) {
				// A group with no producers yet answers empty, honestly.
				return array(
					'events'                 => array(),
					'has_more'               => false,
					'truncated_by_retention' => $truncated,
				);
			}

			$where[] = 'event_type IN (' . implode( ',', array_fill( 0, count( $concrete ), '%s' ) ) . ')';
			$params  = array_merge( $params, $concrete );
		}

		// Cursor pagination on id, descending: newest first, and a boundary
		// can neither repeat nor skip a row however many events share a
		// millisecond.
		if ( isset( $input['cursor'] ) && '' !== (string) $input['cursor'] ) {
			$where[]  = 'id < %d';
			$params[] = (int) $input['cursor'];
		}

		$sql  = 'SELECT id, occurred_at, event_type, actor_type, actor_id, actor_label, object_type, object_id, ip_prefix, site_id, context FROM %i WHERE ' . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d';
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- $sql is built from literal fragments and placeholders above; every value travels through prepare(). A plugin-owned table with no core API, deliberately uncached.
		$rows = $wpdb->get_results(
			$wpdb->prepare( $sql, array_merge( array( $this->activity_table( $input ) ), $params, array( $limit + 1 ) ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

		$has_more = count( $rows ) > $limit;
		$rows     = array_slice( $rows, 0, $limit );

		$events = array();
		foreach ( $rows as $row ) {
			$events[] = array(
				'id'           => (int) $row->id,
				// ISO 8601 in UTC, as query-agent-activity and the rest of the
				// API say a time: the stored value, with no zone, was read by a
				// client in its own zone, hours off (#1787).
				'occurred_at'  => \BetterShield\Support\Time::utc_iso( (string) $row->occurred_at ),
				'type'         => (string) $row->event_type,
				'actor_type'   => (string) $row->actor_type,
				// An account as list-users-and-roles names it, never by the
				// login the log stored for the screen (#1822).
				'actor_label'  => 'user' === (string) $row->actor_type && (int) ( $row->actor_id ?? 0 ) > 0 ? ReadSurface::account_label( (int) $row->actor_id ) : (string) ( $row->actor_label ?? '' ),
				'object_type'  => (string) ( $row->object_type ?? '' ),
				'object_id'    => (string) ( $row->object_id ?? '' ),
				// Named as the log names it. The context is read for that
				// and nothing else: it is not part of what an ability returns.
				'summary'      => Query::label_of( (string) $row->event_type, null !== $row->context ? json_decode( (string) $row->context, true ) : null, $row->object_type ?? null ),
				'ip_truncated' => (string) ( Ip::prefix_label( $row->ip_prefix ) ?? '' ),
				// Which site the row belongs to. `0` is the main site's own
				// convention for rows written before its log became the
				// network's, so it is reported as the main site rather than
				// as a site nobody can name.
				'site_id'      => isset( $row->site_id ) && (int) $row->site_id > 0 ? (int) $row->site_id : ( is_multisite() ? (int) get_main_site_id() : 0 ),
			);
		}

		$out = array(
			'events'                 => $events,
			'has_more'               => $has_more,
			'truncated_by_retention' => $truncated,
		);

		if ( $has_more && array() !== $events ) {
			$out['cursor'] = (string) end( $events )['id'];
		}

		return $out;
	}

	/**
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_integrity_status( $input ): array {
		$this->self_audit( 'bettershield/get-integrity-status', $input );

		/*
		 * Read from the same place every other consumer reads — the screen,
		 * the audit checks and the CLI all answer from Report::all(). This
		 * callback kept a placeholder written before the check shipped, so
		 * an agent asking about a site with open critical findings was told
		 * monitoring was inactive and nothing had been checked. The
		 * distinction that matters is preserved: never checked is not the
		 * same claim as checked and clean.
		 */
		$cursor   = is_array( $input ) ? (string) ( $input['cursor'] ?? '' ) : '';
		$expected = is_array( $input ) && 'expected' === ( $input['list'] ?? '' );

		// Each list pages with a cursor of its own shape, so the one asked for gets it.
		$report = \BetterShield\Integrity\Report::all( $expected ? '' : $cursor );

		if ( $expected ) {
			$page                    = \BetterShield\Integrity\Report::suppressed_page( $cursor );
			$report['changes']       = is_wp_error( $page ) ? array() : $page['changes'];
			$report['changes_error'] = is_wp_error( $page ) ? $page->get_error_message() : null;
			$report['next_cursor']   = is_wp_error( $page ) ? null : $page['next_cursor'];
		}

		$progress = is_array( $report['progress'] ?? null ) ? $report['progress'] : array();
		$open   = \BetterShield\Integrity\Report::open_count();
		$stats  = is_array( $report['stats'] ?? null ) ? $report['stats'] : array();

		$changes = array();

		foreach ( (array) ( $report['changes'] ?? array() ) as $change ) {
			// Paths and kinds, never contents and never hashes an agent has
			// no use for: this answers "what is wrong", not "what is in it".
			// And the id, which is what a restore plan is asked for: without
			// it every change was visible and none could be acted on.
			$changes[] = array(
				'id'            => (int) ( $change['id'] ?? 0 ),
				'path'          => (string) ( $change['path'] ?? '' ),
				'change_type'   => (string) ( $change['change_type'] ?? '' ),
				'context'       => (string) ( $change['context'] ?? '' ),
				'slug'          => (string) ( $change['slug'] ?? '' ),
				'first_seen_at' => (string) ( $change['detected_at'] ?? '' ),
			);
		}

		return array(
			// Configured is not running. A check that finished once and never
			// again is a site nobody is watching, and this said it was.
			'monitoring_active' => (bool) ( $report['ever_run'] ?? false ) && \BetterShield\Integrity\Report::on_schedule(),
			'status_note'       => empty( $report['ever_run'] )
				? __( 'No file check has finished on this site yet. Until one does, this says nothing about whether any file has changed.', 'bettershield' )
				: __( 'Files were compared against the copies their publishers shipped. Anything that could not be checked is listed rather than counted as clean.', 'bettershield' ),
			'last_check_at'     => (string) ( $report['last_run_at'] ?? '' ),
			'next_check_at'     => (string) ( $report['next_run_at'] ?? '' ),
			'missed_check_at'   => (string) ( $report['missed_run_at'] ?? '' ),
			'files_checked'     => (int) ( $stats['checked'] ?? 0 ),
			'open_changes'      => (int) ( $open['total'] ?? 0 ),
			'unverifiable'      => count( (array) ( $report['unverifiable'] ?? array() ) ),
			'changes'           => $changes,
			// An omission that is not stated is a record that lies by looking
			// complete. And an omission nobody can ask for is the same record
			// one page later, so the continuation the data layer already
			// returns is handed on rather than dropped.
			'changes_truncated' => null !== ( $report['next_cursor'] ?? null ),
			'next_cursor'       => (string) ( $report['next_cursor'] ?? '' ),
			// Kept apart from the flag above: "there is another page" and
			// "this could not be read" are opposite answers, and the second
			// arrived with an empty cursor that said the first was over.
			'changes_error'     => (string) ( $report['changes_error'] ?? '' ),
			'running'           => ! empty( $report['running'] ),
			'progress'          => array(
				'target'  => (int) ( $progress['target'] ?? 0 ),
				'targets' => (int) ( $progress['targets'] ?? 0 ),
				'phase'   => (string) ( $progress['phase'] ?? '' ),
				'checked' => (int) ( $progress['checked'] ?? 0 ),
				'label'   => (string) ( $progress['label'] ?? '' ),
			),
			'expected_total'    => \BetterShield\Integrity\Report::suppressed_total(),
		);
	}

	/**
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_agent_surface( $input ): array {
		$this->self_audit( 'bettershield/get-agent-surface', $input );

		// The abilities as agent-facing data: no per-password names — the
		// counts and ages are the finding; the names are for the owner's
		// screen. Fields the screen adds (login) are stripped here too.
		$passwords = array();
		foreach ( AgentSurface::application_passwords( false ) as $holder ) {
			$passwords[] = array(
				'user_id'            => (int) $holder['user_id'],
				'role'               => (string) $holder['role'],
				'count'              => (int) $holder['count'],
				'oldest_unused_days' => (int) $holder['oldest_unused_days'],
			);
		}

		return array(
			'abilities_api_available' => self::is_available(),
			'abilities'               => AgentSurface::abilities(),
			'application_passwords'   => $passwords,
		);
	}

	/**
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_vulnerability_state( $input ): array {
		$this->self_audit( 'bettershield/get-vulnerability-state', $input );

		$input  = is_array( $input ) ? $input : array();
		$source = $this->vulnerability_source();

		if ( ! $source->available() ) {
			return array(
				'source_available' => false,
				'complete' => false,
				'truncated' => false,
				'status_note'      => \BetterShield\Vulnerabilities\Scanner::feed() === null
					? __( 'No vulnerability data source is configured in this version, and no external calls are made. An empty list here means nothing was checked, not that nothing is vulnerable.', 'bettershield' )
					: __( 'The vulnerability check has not run yet, or is turned off. An empty list here means nothing was checked, not that nothing is vulnerable.', 'bettershield' ),
				'affected'         => array(),
			);
		}

		$severity = (string) ( $input['severity_min'] ?? 'info' );
		$limit    = min( 1000, max( 1, (int) ( $input['limit'] ?? 50 ) ) );
		$affected = $source->state( $severity, $limit );
		// The list stops at the limit, worst first, and said nothing of the
		// rest: an assistant asked about seventy affected plugins was handed
		// fifty with nothing to say more existed.
		$total = count( $source->state( $severity, PHP_INT_MAX ) );

		$out = array(
			'source_available' => true,
			'total'            => $total,
			'truncated'        => $total > count( $affected ),
			'affected'         => $affected,
		);

		if ( $source instanceof \BetterShield\Vulnerabilities\State ) {
			$out['stale'] = \BetterShield\Vulnerabilities\State::is_stale();
			$out['error'] = \BetterShield\Vulnerabilities\State::get()['error'];
			if ( $out['stale'] || '' !== $out['error'] ) { $out['status_note'] = __( 'This is the last successful result. It may not include newer advisories.', 'bettershield' ); }
		}

		$out['complete'] = ! $out['truncated'] && empty( $out['stale'] ) && empty( $out['error'] );

		$updated = $source->last_updated();
		if ( null !== $updated ) {
			$out['last_updated_at'] = $updated;
		}

		return $out;
	}

	/* ---- internals ----------------------------------------------------------------- */

	/**
	 * Every query is itself an activity-log event: the owner can always see
	 * what their agents asked. Inputs are recorded as digests, never raw —
	 * inputs may carry anything.
	 *
	 * @param mixed $input
	 */
	private function self_audit( string $ability, $input ): void {
		// A call that arrived through the assistant endpoint is recorded by
		// that endpoint, with the credential that made it and the outcome; a
		// second row here would say less about the same call.
		if ( Writer::ENTRY_MCP === Writer::entry_path() ) {
			return;
		}

		// The same digest the invocation record keeps, from the same helper:
		// two ways of computing one column is two answers about the same call.
		// A null answer means there was nothing to digest, and the key is left
		// out rather than filled with the digest of an empty string.
		$digest = Capture::digest( $input );

		Writer::instance()->record(
			'ability_used',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'ability',
				'object_id'   => $ability,
				'context'     => null === $digest ? array() : array( 'input_digest' => $digest ),
			)
		);
	}

	/**
	 * What ran on this site, and what was refused.
	 *
	 * Answers honestly on a platform that cannot capture: `capture_available`
	 * false with an empty list is a different statement from "nothing
	 * happened", and a caller has to be able to tell them apart. Same for the
	 * owner having switched recording off.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function query_agent_activity( $input ): array {
		$this->self_audit( 'bettershield/query-agent-activity', $input );

		$input = is_array( $input ) ? $input : array();
		$limit = min( 200, max( 1, (int) ( $input['limit'] ?? 50 ) ) );

		$available = Capture::is_available();
		$enabled   = Capture::is_enabled();

		if ( ! $available ) {
			return array(
				'capture_available' => false,
				'capture_enabled'   => $enabled,
				/* translators: %s: a WordPress version number. */
				'status_note'       => sprintf( __( 'Recording agent activity needs WordPress %s. Nothing has been recorded on this site.', 'bettershield' ), Capture::REQUIRES_WP ),
				'invocations'       => array(),
				'counts'            => array(),
				'has_more'          => false,
			);
		}

		$filters = array(
			'outcome'    => isset( $input['outcome'] ) ? (string) $input['outcome'] : '',
			'ability'    => isset( $input['ability'] ) ? (string) $input['ability'] : '',
			'namespace'  => isset( $input['namespace'] ) ? (string) $input['namespace'] : '',
			'entry_path' => isset( $input['entry_path'] ) ? (string) $input['entry_path'] : '',
		);

		$page = Invocations::page(
			array_merge(
				$filters,
				array(
					'cursor'   => isset( $input['cursor'] ) ? (int) $input['cursor'] : 0,
					'per_page' => $limit,
				)
			)
		);

		$note = '';

		if ( ! $enabled ) {
			// An empty list because nobody is listening is not the same fact
			// as an empty list because nothing happened.
			$note = __( 'Recording agent activity is switched off on this site. What is listed here was recorded before it was switched off.', 'bettershield' );
		}

		$out = array(
			'capture_available' => true,
			'capture_enabled'   => $enabled,
			'invocations'       => array_map(
				static function ( array $invocation ): array {
					// Named as every other read names an account (#1822).
					if ( (int) ( $invocation['user_id'] ?? 0 ) > 0 ) {
						$invocation['user_label'] = ReadSurface::account_label( (int) $invocation['user_id'] );
					}

					return self::without_nulls( $invocation );
				},
				$page['invocations']
			),
			'has_more'          => null !== $page['next_cursor'],
		);

		/*
		 * The totals describe the filtered set, not the page — so a caller
		 * paging through one answer was paying for the same aggregate again
		 * on every page. Computed with the first page, where it is asked.
		 */
		if ( 0 === (int) ( $input['cursor'] ?? 0 ) ) {
			$out['counts'] = Invocations::counts( $filters );
		}

		if ( '' !== $note ) {
			$out['status_note'] = $note;
		}

		if ( null !== $page['next_cursor'] ) {
			$out['cursor'] = (string) $page['next_cursor'];
		}

		return $out;
	}

	/**
	 * Which connector credentials this site holds, and who can read them.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_credential_exposure( $input ): array {
		$this->self_audit( 'bettershield/get-credential-exposure', $input );

		$report = Connectors::report( false );

		return array(
			'available'                => $report['available'],
			'configured_count'         => $report['configured_count'],
			'readable_by_plugin_count' => $report['readable_by_plugin_count'],
			'advisory'                 => $report['advisory'],
			'reference_url'            => Connectors::reference_url(),
			'connectors'               => array_map( array( self::class, 'without_nulls' ), $report['connectors'] ),
		);
	}

	/**
	 * The recovery readiness report's non-secret fields, and the write
	 * gate's answer from that same report.
	 *
	 * @param mixed $input
	 * @return array<string, mixed>
	 */
	public function get_recovery_readiness( $input ): array {
		$this->self_audit( 'bettershield/get-recovery-readiness', $input );

		$report = Readiness::report();

		return self::without_nulls(
			array(
				'recovery_ready'  => self::recovery_ready( $report ),
				'checks'          => array_values( (array) $report['checks'] ),
				'ready'           => (int) $report['ready'],
				'total'           => (int) $report['total'],
				'checked_at'      => $report['checked_at'],
				'overdue'         => (bool) $report['overdue'],
				'link'            => (string) $report['link'],
				'link_expires_at' => $report['link_expires_at'],
				'offline_codes'   => (int) $report['offline_codes'],
				'mail'            => (string) $report['mail'],
				'mail_checked_at' => $report['mail_checked_at'],
				'lockdown'        => \BetterShield\Recovery\Lockdown::is_active(),
				'safe_mode'       => \BetterShield\Recovery\SafeMode::is_active(),
			)
		);
	}

	/**
	 * Drop the keys whose value is null.
	 *
	 * Core validates ability output against a subset of JSON Schema Draft-04
	 * with no `oneOf`, `anyOf` or nullable types, so a field that is
	 * sometimes absent cannot be declared as "string or null" — and a null
	 * against `type: string` fails the whole output, which core then returns
	 * as an error instead of the answer. Neither of the two ways out is
	 * neutral: an empty string invents a value the record does not hold, and
	 * omitting the key says exactly what is true, which is that nothing was
	 * recorded there. Every such field is optional in the schemas above for
	 * this reason.
	 *
	 * @param array<string, mixed> $row
	 * @return array<string, mixed>
	 */
	private static function without_nulls( array $row ): array {
		return array_filter(
			$row,
			static function ( $value ): bool {
				return null !== $value;
			}
		);
	}

	/**
	 * ISO 8601 (or anything strtotime reads) to the stored format, UTC.
	 */
	private function to_mysql( string $time ): ?string {
		$timestamp = strtotime( $time );

		return false === $timestamp ? null : gmdate( 'Y-m-d H:i:s.v', $timestamp );
	}
}
