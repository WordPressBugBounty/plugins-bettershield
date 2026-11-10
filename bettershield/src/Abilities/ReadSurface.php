<?php
/**
 * Bounded projections of existing security state for the owner's agent.
 * These callbacks never run an audit or enforcement action. The overview
 * reconciles live findings through the same read used by the dashboard.
 *
 * @package BetterShield
 */
declare( strict_types=1 );
namespace BetterShield\Abilities;

use BetterShield\Audit;
use BetterShield\Hardening;
use BetterShield\Login;
use BetterShield\Network\Policies;
use BetterShield\Passkeys;
use BetterShield\Support\Text;
use BetterShield\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class ReadSurface {
	/** All schemas use only the subset enforced by WordPress's validator. */
	private static function object( array $properties ): array {
		return array( 'type' => 'object', 'properties' => $properties, 'required' => array_keys( $properties ) );
	}
	private static function rows( array $properties ): array {
		return array( 'type' => 'array', 'items' => self::object( $properties ) );
	}
	private static function strings(): array { return array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ); }

	/** @return array<string, array<string, mixed>> */
	public static function definitions( array $meta, callable $audit ): array {
		$string = array( 'type' => 'string' );
		$integer = array( 'type' => 'integer' );
		$boolean = array( 'type' => 'boolean' );
		$number = array( 'type' => 'number' );
		$strings = self::strings();
		$factor = self::object( array( 'two_factor_roles' => $strings, 'grace_days' => $integer, 'passkey_roles' => $strings ) );
		$surface = self::object( array( 'enabled' => $boolean, 'threshold' => $integer, 'window_minutes' => $integer, 'lockout_minutes' => $integer, 'action' => $string ) );
		$person = self::object( array( 'id' => $integer, 'display_name' => $string ) );
		$incident = array( 'id' => $integer, 'status' => $string, 'opened_at' => $string, 'updated_at' => $string, 'resolved_at' => $string, 'confidence' => $string, 'evidence_count' => $integer, 'anchor_count' => $integer );
		$by_severity = self::object( array( 'critical' => $integer, 'high' => $integer, 'medium' => $integer, 'low' => $integer, 'info' => $integer ) );
		$overview_finding = array( 'id' => $string, 'group' => $string, 'severity' => $string, 'severity_level' => $integer, 'deduction' => $integer, 'status' => $string, 'title' => $string, 'why' => $string, 'break_note' => $string, 'stale' => $boolean, 'first_seen_at' => $string, 'last_seen_at' => $string, 'resolved_at' => $string, 'snoozed_until' => $string, 'evidence_available' => $boolean, 'fix' => self::object( array( 'kind' => $string, 'item_id' => $string, 'item_active' => $boolean, 'path' => $string, 'reversible' => $boolean, 'control' => self::object( array( 'label' => $string, 'url' => $string ) ) ) ) );
		$specs = array(
			'get-security-overview' => array(
				'label' => __( 'Get the security overview', 'bettershield' ),
				'description' => __( 'This site’s Overview as data, from the payload its Overview screen draws: the score and grade and what the one-click fixes would make them, the last 30 recorded days, open findings by severity with the snoozed ones counted apart, and how many are marked not applicable; each open and not-applicable finding with its area, points, status, first and last seen, snooze, whether the last audit could check it, and its fix (the protection that answers it, whether it is on and how a connection may apply it, or where the setting is); the last audit’s time and the checks it could not run; this week’s receipts and what the plugin costs a page view; safe mode, which pauses protections and never changes the score; and whether each way back in would work today. Fixed findings only with include_fixed. No evidence payloads.', 'bettershield' ),
				'permission' => 'can_read', 'method' => 'overview',
				'input' => array( 'include_fixed' => array( 'type' => 'boolean', 'description' => 'Also include findings that have been fixed.' ) ),
				'output' => array(
					'schema' => $string, 'plugin_version' => $string,
					'score' => $integer, 'grade' => $string, 'projected_score' => $integer, 'projected_grade' => $string,
					'history' => self::rows( array( 'at' => $string, 'score' => $integer ) ),
					'counts' => self::object( array( 'open' => $by_severity, 'snoozed' => $by_severity, 'suppressed' => $integer ) ),
					'findings' => self::rows( $overview_finding ),
					'audit' => self::object( array( 'generated_at' => $string, 'duration_ms' => $integer, 'checks_total' => $integer, 'checks_ran' => $integer, 'checks_unknown' => self::rows( array( 'check' => $string, 'title' => $string, 'reason_code' => $string, 'reason' => $string, 'last_answered_at' => $string ) ), 'next_check_at' => $string ) ),
					'receipts' => self::object( array( 'audits_week' => $integer, 'hardening_active' => $integer, 'events_week' => $integer, 'last_change_at' => $string ) ),
					'front_end_cost' => self::object( array( 'measured' => $boolean, 'pages' => $integer, 'ms' => $number, 'queries' => $number, 'samples' => $integer, 'one_in' => $integer, 'since' => $string ) ),
					'safe_mode' => self::object( array( 'active' => $boolean, 'until' => $string, 'by_network' => $boolean ) ),
					'lockdown' => self::object( array( 'active' => $boolean ) ),
					'alerts_muted' => $boolean,
					'recovery' => self::object( array( 'link' => $string, 'link_expires_at' => $string, 'link_mail' => $string, 'offline_codes' => $integer, 'administrators_with_email' => $integer, 'email_tests' => $boolean, 'mail' => $string, 'mail_checked_at' => $string, 'checked_at' => $string, 'overdue' => $boolean, 'needs_attention' => $boolean, 'checks' => self::rows( array( 'key' => $string, 'ok' => $boolean ) ), 'ready' => $integer, 'total' => $integer, 'ready_for_sign_in_changes' => $boolean ) ),
				),
			),
			'list-incidents' => array(
				'label' => __( 'List this site’s incidents', 'bettershield' ),
				'description' => __( 'Up to 20 stored incidents with confidence and evidence counts. Open incidents do not expire; handled history follows retention. No correlation work or response action runs.', 'bettershield' ),
				'permission' => 'can_read_activity', 'method' => 'incidents',
				'input' => array( 'status' => array( 'type' => 'string', 'enum' => array( 'open', 'resolved' ) ), 'before_id' => array( 'type' => 'integer', 'minimum' => 0 ) ),
				'output' => array( 'incidents' => self::rows( $incident ), 'next_cursor' => $integer, 'engine' => self::object( array( 'last_checked_at' => $string, 'pending' => $boolean, 'failed' => $boolean ) ) ),
			),
			'get-incident' => array(
				'label' => __( 'Get an incident’s timeline', 'bettershield' ),
				'description' => __( 'Up to 100 evidence records after a stable evidence ID. Explicit time links, recorded account IDs, paths and bounded summaries; no credentials, full addresses or response handles. Does not prove malicious intent.', 'bettershield' ),
				'permission' => 'can_read_activity', 'method' => 'incident',
				'input' => array( 'incident_id' => array( 'type' => 'integer', 'minimum' => 1 ), 'after_id' => array( 'type' => 'integer', 'minimum' => 0 ) ), 'required' => array( 'incident_id' ),
				'output' => $incident + array( 'evidence' => self::rows( array( 'id' => $integer, 'occurred_at' => $string, 'actor_id' => $integer, 'anchor' => $string, 'type' => $string, 'label' => $string, 'relation' => $string, 'snapshot' => self::object( array( 'source' => $string, 'source_id' => $integer, 'object_type' => $string, 'object_id' => $string, 'target_user' => $integer, 'details' => array( 'type' => 'object' ) ) ) ) ), 'next_cursor' => $integer ),
			),
			'get-hardening-state' => array(
				'label' => __( 'See which hardening switches are on', 'bettershield' ),
				'description' => __( 'Saved control states and observation support, with each control’s group, how a connection may apply it (directly, after a person confirms, or never), whether it can be undone, whether it can work on this server and why not, what else already does its job, a failed undo, how far it reaches on a network, the strict transport and content policy settings in force, and what a watch window has seen. Omits control options, hidden login paths and undo handles; does not apply controls or probe the site.', 'bettershield' ),
				'permission' => 'can_read', 'method' => 'hardening',
				'output' => array( 'items' => self::rows( array( 'id' => $string, 'title' => $string, 'group' => $string, 'group_title' => $string, 'active' => $boolean, 'applied_at' => $string, 'observable' => $boolean, 'path' => $string, 'reversible' => $boolean, 'available' => $boolean, 'availability_note' => $string, 'conflict_warning' => $string, 'revert_failed' => $string, 'scope' => $string, 'detail' => array( 'type' => 'object' ), 'monitor' => self::object( array( 'id' => $string, 'supported' => $boolean, 'phase' => $string, 'started' => $string, 'ends' => $string, 'observed' => $integer, 'matched' => $integer, 'denied' => $integer ) ) ) ) ),
			),
			'get-login-protection' => array(
				'label' => __( 'Get login protection settings', 'bettershield' ),
				'description' => __( 'Login thresholds, enabled mechanisms and address-list counts; the comment, password reset and registration forms’ own limits and what each does when one is reached; the recommended limits; how this request’s client address was worked out; how many lockouts there are and how many are running; whether a session limit can be kept here; and how many accounts are signed in. No trusted address values, source addresses or unlock credentials.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'login',
				'output' => array( 'enabled' => $boolean, 'attempt_limit' => $boolean, 'threshold' => $integer, 'window_minutes' => $integer, 'lockout_minutes' => $integer, 'honeypot' => $boolean, 'proof_of_work' => $boolean, 'cloudflare' => $boolean, 'idle_minutes' => $integer, 'session_cap' => $integer, 'new_location_notice' => $boolean, 'host_ban_line' => $boolean, 'allowlist_count' => $integer, 'blocklist_count' => $integer, 'trusted_proxies_count' => $integer, 'surfaces' => self::object( array( 'comment' => $surface, 'reset' => $surface, 'register' => $surface ) ), 'defaults' => self::object( array( 'threshold' => $integer, 'window_minutes' => $integer, 'lockout_minutes' => $integer ) ), 'connection' => self::object( array( 'method' => $string, 'confident' => $boolean, 'ignored_headers' => $boolean ) ), 'lockouts_active' => $integer, 'lockouts_total' => $integer, 'session_cap_supported' => $boolean, 'signed_in_accounts' => $integer ),
			),
			'get-factor-policies' => array(
				'label' => __( 'See two-factor and passkey rules', 'bettershield' ),
				'description' => __( 'Site and effective two-factor/passkey role requirements, including the network minimum. Reading does not start anyone’s enrollment grace period.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'factors',
				'output' => array( 'site' => $factor, 'effective' => $factor, 'safe_mode' => $boolean, 'network_two_factor_set' => $boolean, 'network_passkey_set' => $boolean, 'network' => self::object( array( 'two_factor' => self::object( array( 'roles' => $strings, 'grace_days' => $integer, 'set' => $boolean ) ), 'passkey' => self::object( array( 'roles' => $strings, 'set' => $boolean ) ) ) ), 'safe_mode_source' => $string ),
			),
			'list-users-and-roles' => array(
				'label' => __( 'List this site’s users and roles', 'bettershield' ),
				'description' => __( 'Up to 50 current-site members after a user ID, plus a bounded role inventory. No email addresses, login names, credentials or per-user private metadata.', 'bettershield' ),
				'permission' => 'can_list_users', 'method' => 'users',
				'input' => array( 'after_id' => array( 'type' => 'integer', 'minimum' => 0 ), 'limit' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 50 ) ),
				'output' => array( 'users' => self::rows( array( 'id' => $integer, 'label' => $string, 'roles' => $strings ) ), 'roles' => self::rows( array( 'id' => $string, 'label' => $string, 'granted' => $strings, 'denied' => $strings, 'capabilities_truncated' => $boolean ) ), 'roles_truncated' => $boolean, 'next_after_id' => $integer, 'has_more' => $boolean ),
			),
			'get-active-sessions' => array(
				'label' => __( 'See when a user was last active', 'bettershield' ),
				'description' => __( 'Up to 20 live sessions for one current-site member, defaulting to the caller. Session tokens, hashes, IP addresses and browser strings are never returned. On multisite these are account sessions shared across the network.', 'bettershield' ),
				'permission' => 'can_list_users', 'method' => 'sessions',
				'input' => array( 'user_id' => array( 'type' => 'integer', 'minimum' => 1 ) ),
				'output' => array( 'user_id' => $integer, 'network_shared' => $boolean, 'sessions' => self::rows( array( 'signed_in_at' => $string, 'last_seen_at' => $string, 'expires_at' => $string ) ), 'active_count' => $integer, 'has_more' => $boolean ),
			),
			'list-quarantine' => array(
				'label' => __( 'List quarantined files', 'bettershield' ),
				'description' => __( 'Metadata from matching ledger entries, newest first, up to 200 a page: original relative path, size, digest and availability. Pass before_id from a previous answer to read older entries. No file contents, storage paths, download links or undo tokens.', 'bettershield' ),
				'permission' => 'can_read_activity', 'method' => 'quarantine',
				'input' => array( 'before_id' => array( 'type' => 'integer', 'minimum' => 1 ) ),
				'output' => array( 'items' => self::rows( array( 'id' => $integer, 'action' => $string, 'path' => $string, 'size' => $integer, 'sha256' => $string, 'at' => $string, 'restored' => $boolean, 'present' => $boolean ) ), 'ledger_limit' => $integer, 'next_before_id' => $integer, 'has_more' => $boolean ),
			),
			'get-cron-health' => array(
				'label' => __( 'Check background tasks are running', 'bettershield' ),
				'description' => __( 'The current request’s bounded cron audit: unanswered third-party hooks and counts, and whether the schedule itself is being run (how far this plugin’s own hooks are overdue, and whether that counts as stalled). Hook arguments are never returned and no task runs. Unanswered does not mean malicious.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'cron',
				'output' => array( 'events' => self::rows( array( 'hook' => $string, 'next_run' => $string, 'schedule' => $string, 'scheduled' => $integer ) ), 'total' => $integer, 'unanswered' => $integer, 'readable' => $boolean, 'legacy_schedule' => $boolean, 'schedule' => self::object( array( 'behind_seconds' => $integer, 'overdue' => $integer, 'stalled' => $boolean ) ) ),
			),
			'get-audit-check' => array(
				'label' => __( 'Get one check’s result', 'bettershield' ),
				'description' => __( 'One check’s explanation, risk guidance and last recorded status. Does not rerun the check or return its raw evidence payload.', 'bettershield' ),
				'permission' => 'can_read', 'method' => 'check',
				'input' => array( 'check_id' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 128 ) ), 'required' => array( 'check_id' ),
				'output' => array( 'id' => $string, 'title' => $string, 'group' => $string, 'severity' => $string, 'explanation' => $string, 'risk_note' => $string, 'status' => $string, 'last_seen_at' => $string, 'evidence_available' => $boolean ),
			),
			'get-backup-visibility' => array(
				'label' => __( 'See which backup plugin is installed', 'bettershield' ),
				'description' => __( 'Recognized active and inactive backup plugins. Host backups, backup age and restore testing remain unknown; plugin presence is not proof of a usable backup.', 'bettershield' ),
				'permission' => 'can_read', 'method' => 'backups',
				'output' => array( 'active_plugins' => $strings, 'inactive_plugins' => $strings, 'host_backups' => $string, 'last_backup' => $string, 'restore_test' => $string, 'lists_truncated' => $boolean ),
			),
			'get-site-settings' => array(
				'label' => __( 'Get this site’s own settings', 'bettershield' ),
				'description' => __( 'How the site’s own email alerts are set, with recipients counted and never named, and how many were sent in the window the log keeps; the password policy; whether a security contact file is published and until when; whether usage data is shared; and what uninstalling removes. No addresses, contact details or reasons. Changes nothing.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'settings',
				'output' => array(
					'alerts' => self::object( array( 'muted' => $boolean, 'transport' => $string, 'recipients' => $integer, 'uses_admin_address' => $boolean, 'digest' => $boolean, 'digest_day' => $integer, 'instant' => $boolean, 'sent' => self::object( array( 'count' => $integer, 'window_days' => $integer ) ), 'maintenance' => self::object( array( 'active' => $boolean, 'until' => $string ) ) ) ),
					'password_policy' => self::object( array( 'enabled' => $boolean, 'min_length' => $integer, 'min_length_privileged' => $integer, 'min_length_single_factor' => $integer ) ),
					'security_contact' => self::object( array( 'enabled' => $boolean, 'expires' => $string ) ),
					'usage' => self::object( array( 'allowed' => $boolean, 'last_sent' => $string ) ),
					'uninstall' => self::object( array( 'choice' => $string, 'remove_data' => $boolean ) ),
				),
			),
			'list-recent-changes' => array(
				'label' => __( 'List changes since a given time', 'bettershield' ),
				'description' => __( 'This site’s own list of what changed since the time given, as its Overview lists what changed since a person last looked: up to eight, the ones worth leading with first, with whether there were more and whether the log no longer reaches back that far. Reading it moves nobody’s last visit.', 'bettershield' ),
				'permission' => 'can_read_activity', 'method' => 'recent_changes',
				'input' => array( 'since' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 40 ) ), 'required' => array( 'since' ),
				'output' => array( 'since' => $string, 'clamped' => $boolean, 'more' => $boolean, 'changes' => self::rows( array( 'id' => $integer, 'occurred_at' => $string, 'type' => $string, 'label' => $string, 'severity' => $integer, 'actor' => $string, 'subject' => $string ) ) ),
			),
			'get-agent-connections' => array(
				'label' => __( 'Get this site’s agent connections', 'bettershield' ),
				'description' => __( 'Whether the MCP server is on; the paired credential (whether one is paired, since when, who holds it and what it may do); each application holding a grant, with its name, what it may do, who approved it and when, when it was last used and whether it is the hub; the hub connection’s host and when it was granted; the connection’s health; how many requests wait for a person; whether agent activity is recorded and the hourly limits on changes and plans; and whether unused application passwords are retired, a decoy credential is armed and when it was last used, and a decoy address is armed. No credential, token hint, decoy name, path or address.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'agent_connections',
				'output' => array(
					'mcp_enabled' => $boolean,
					'pairing' => self::object( array( 'connected' => $boolean, 'connected_at' => $string, 'connected_by' => $person, 'scope' => $string ) ),
					'apps' => self::rows( array( 'id' => $string, 'name' => $string, 'scope' => $string, 'granted_at' => $string, 'granted_by' => $person, 'last_used_at' => $string, 'is_hub' => $boolean ) ),
					'hub' => self::object( array( 'connected' => $boolean, 'host' => $string, 'granted_at' => $string ) ),
					'health' => self::object( array( 'https' => $boolean, 'scheme_agreement' => $boolean, 'pretty_routed' => $boolean, 'tools' => $integer, 'read_enabled' => $boolean, 'write_enabled' => $boolean, 'capability_granted' => $boolean ) ),
					'open_requests' => $integer,
					'rules' => self::object( array( 'sudo_enabled' => $boolean, 'recovery_ready_for_sign_in_changes' => $boolean, 'recording' => $boolean, 'write_limit_per_hour' => $integer, 'propose_limit_per_hour' => $integer ) ),
					'surface' => self::object( array( 'retire_unused_app_passwords' => self::object( array( 'enabled' => $boolean, 'days' => $integer ) ), 'decoy_credential' => self::object( array( 'armed' => $boolean, 'used_at' => $string ) ), 'decoy_url' => self::object( array( 'armed' => $boolean ) ) ) ),
				),
			),
			'list-network-sites' => array(
				'label' => __( 'List the network’s sites', 'bettershield' ),
				'description' => __( 'On a network, for a super administrator: each site’s name and address, whether this plugin is installed there, whether its MCP server and read abilities are on and whether it is connected to the hub, and its last score, grade, open findings and audit time (0, empty and 0 until it has been audited), from the roll-up the Network screen reads. Pass next_cursor back as cursor for the next page; an empty one is the last. Changes nothing on any site.', 'bettershield' ),
				'permission' => 'can_read_network', 'method' => 'network_sites',
				'input' => array( 'cursor' => array( 'type' => 'string', 'maxLength' => 20 ) ),
				'output' => array( 'sites' => self::rows( array( 'site_id' => $integer, 'name' => $string, 'home_url' => $string, 'installed' => $boolean, 'mcp_enabled' => $boolean, 'abilities_enabled' => $boolean, 'hub_connected' => $boolean, 'score' => $integer, 'grade' => $string, 'open_findings' => $integer, 'audited_at' => $string ) ), 'total' => $integer, 'next_cursor' => $string, 'built_at' => $string ),
			),
			'get-hub-link' => array(
				'label' => __( 'Get this site’s Hub link', 'bettershield' ),
				'description' => __( 'Whether this site sends its security events and a heartbeat to BetterShield Hub, signed: the public key the hub checks them against, the id the site signs as, and which kinds of events it sends. Off, the key and the id are empty: the link is off, or this is a copy at another address or a staging copy, or the site is not connected to hub.bettershield.ai. Pass the hub’s nonce (32 bytes, base64url) as challenge to get proof: the key’s Ed25519 signature, base64url, over five lines joined by a newline: “bettershield hub link proof v1”, https://hub.bettershield.ai, this site’s home URL without a trailing slash, the site id and the challenge. Empty without a challenge or while the link is off. Never the secret key.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'hub_link',
				'input' => array( 'challenge' => array( 'type' => 'string', 'minLength' => 43, 'maxLength' => 43, 'pattern' => '^[A-Za-z0-9_-]{43}$' ) ),
				'output' => array( 'enabled' => $boolean, 'public_key' => $string, 'site' => $string, 'classes' => self::object( array( 'alerting' => $boolean, 'posture' => $boolean, 'full_log' => $boolean ) ), 'proof' => $string ),
			),
			'list-lockouts' => array(
				'label' => __( 'List this site’s lockouts', 'bettershield' ),
				'description' => __( 'Up to 100 lockouts a page, newest first: each one’s form, the network it came from as a /24 or /64, when it started and ends, whether it is running and how many attempts set it off, with how many there are and how many are running. Pass next_cursor back as cursor for older ones; an empty one is the last page. No username, full address or way to lift one.', 'bettershield' ),
				'permission' => 'can_manage', 'method' => 'lockout_list',
				'input' => array( 'surface' => array( 'type' => 'string', 'enum' => Login\Surfaces::ALL ), 'limit' => array( 'type' => 'integer', 'minimum' => 1, 'maximum' => 100 ), 'cursor' => array( 'type' => 'string', 'maxLength' => 20 ) ),
				'output' => array( 'lockouts' => self::rows( array( 'id' => $integer, 'surface' => $string, 'address_prefix' => $string, 'started_at' => $string, 'expires_at' => $string, 'active' => $boolean, 'attempts' => $integer ) ), 'total' => $integer, 'active' => $integer, 'next_cursor' => $string ),
			),
			'get-site-environment' => array(
				'label' => __( 'Get this site’s software versions', 'bettershield' ),
				'description' => __( 'The WordPress and PHP versions, the active theme, how many plugins are installed and active, and how many updates WordPress already knows are waiting, with when it last looked. Also this plugin’s version, whether BetterShield Ultra is loaded and its version, on a network which site this is, and the address of this site’s dashboard. Counts and versions only: no plugin is named, and nothing is asked of WordPress.org.', 'bettershield' ),
				'permission' => 'can_read', 'method' => 'environment',
				'output' => array(
					'wordpress' => $string, 'php' => $string,
					'theme' => self::object( array( 'name' => $string, 'version' => $string ) ),
					'plugins' => self::object( array( 'active' => $integer, 'installed' => $integer ) ),
					'updates' => self::object( array( 'core' => $integer, 'plugins' => $integer, 'themes' => $integer, 'checked_at' => $string ) ),
					'bettershield' => self::object( array( 'version' => $string ) ),
					'ultra' => self::object( array( 'active' => $boolean, 'version' => $string ) ),
					'multisite' => self::object( array( 'enabled' => $boolean, 'network_id' => $integer, 'site_id' => $integer, 'main_site_id' => $integer, 'main_site_url' => $string, 'subdomain_install' => $boolean, 'network_active' => $boolean ) ),
					'admin_url' => $string,
				),
			),
		);
		$out = array();
		foreach ( $specs as $short => $spec ) {
			$name = 'bettershield/' . $short;
			$permission = in_array( $spec['permission'], array( 'can_list_users', 'can_read_network' ), true ) ? array( self::class, $spec['permission'] ) : array( Registrar::class, $spec['permission'] );
			$method = $spec['method'];
			$out[ $name ] = array( 'permission_callback' => $permission ) + $meta + array(
				'label' => $spec['label'], 'description' => $spec['description'],
				'input_schema' => array( 'type' => 'object', 'properties' => $spec['input'] ?? array(), 'required' => $spec['required'] ?? array() ),
				'output_schema' => self::object( array( 'site_id' => $integer, 'generated_at' => $string ) + $spec['output'] ),
				'execute_callback' => static function ( $input ) use ( $name, $method, $audit ) {
					$audit( $name, $input );
					$result = self::$method( is_array( $input ) ? $input : array() );
					return is_wp_error( $result ) ? $result : array( 'site_id' => get_current_blog_id(), 'generated_at' => gmdate( 'c' ) ) + $result;
				},
			);
		}
		return $out;
	}

	/**
	 * Read abilities an add-on adds to this set.
	 *
	 * An add-on describes each read; this plugin builds the ability, so every
	 * one inherits what makes a read safe here rather than being trusted to
	 * restate it: it registers only while the owner's read opt-in is on, it
	 * is gated by one of this plugin's own permission checks, it is annotated
	 * read-only, non-destructive and idempotent, every call is recorded as an
	 * `ability_used` row with its input as a digest, and its answer is
	 * stamped with the site and the time like every read here. A name this
	 * plugin already uses is never replaced, and nothing that is not a read
	 * can be added this way.
	 *
	 * @param array<string, mixed> $meta  The read defaults: category, gate and annotations.
	 * @param callable             $audit Records one call.
	 * @param string[]             $taken The names already defined.
	 * @return array<string, array<string, mixed>>
	 */
	public static function extensions( array $meta, callable $audit, array $taken ): array {
		/**
		 * Filters the read-only abilities an add-on adds under `bettershield/`.
		 *
		 * Each is `short-name => array( 'label', 'description', 'callback',
		 * 'output', 'input', 'required', 'permission' )`:
		 *
		 * - `short-name`: lowercase letters, digits and hyphens; registered as
		 *   `bettershield/<short-name>`.
		 * - `label`, `description`: what it reads, and — in the description —
		 *   what it deliberately leaves out.
		 * - `callback`: takes the input array and returns an array matching
		 *   `output`, or a `WP_Error`. It must change nothing.
		 * - `output`: the answer's properties, as JSON Schema (the subset core
		 *   validates). `site_id` and `generated_at` are added.
		 * - `input`, `required`: optional input properties.
		 * - `permission`: `can_read`, `can_read_activity` or `can_manage`
		 *   (the default).
		 *
		 * @param array<string, array<string, mixed>> $reads Reads added so far.
		 */
		$reads = apply_filters( 'bettershield_read_abilities', array() );
		$gates = array( 'can_read', 'can_read_activity', 'can_manage' );
		$out   = array();

		foreach ( is_array( $reads ) ? $reads : array() as $short => $spec ) {
			$short = is_string( $short ) ? $short : '';
			$name  = 'bettershield/' . $short;

			if ( 1 !== preg_match( '/^[a-z][a-z0-9-]{2,62}$/', $short ) || in_array( $name, $taken, true ) || isset( $out[ $name ] ) || ! is_array( $spec ) ) {
				continue;
			}

			$label       = is_string( $spec['label'] ?? null ) ? trim( $spec['label'] ) : '';
			$description = is_string( $spec['description'] ?? null ) ? trim( $spec['description'] ) : '';
			$callback    = $spec['callback'] ?? null;
			$output      = $spec['output'] ?? null;

			if ( '' === $label || '' === $description || ! is_callable( $callback ) || ! is_array( $output ) || array() === $output ) {
				continue;
			}

			$gate = in_array( $spec['permission'] ?? '', $gates, true ) ? $spec['permission'] : 'can_manage';

			// The gate and the annotations come from here, after the add-on's
			// own keys, so a description cannot loosen either.
			$out[ $name ] = array( 'permission_callback' => array( Registrar::class, $gate ) ) + $meta + array(
				'label'            => $label,
				'description'      => $description,
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => is_array( $spec['input'] ?? null ) ? $spec['input'] : array(),
					'required'   => is_array( $spec['required'] ?? null ) ? array_values( $spec['required'] ) : array(),
				),
				'output_schema'    => self::object( array( 'site_id' => array( 'type' => 'integer' ), 'generated_at' => array( 'type' => 'string' ) ) + $output ),
				'execute_callback' => static function ( $input ) use ( $name, $callback, $audit ) {
					$audit( $name, $input );
					$result = $callback( is_array( $input ) ? $input : array() );

					if ( is_wp_error( $result ) ) {
						return $result;
					}

					return array( 'site_id' => get_current_blog_id(), 'generated_at' => gmdate( 'c' ) ) + ( is_array( $result ) ? $result : array() );
				},
			);
		}

		return $out;
	}

	public static function can_list_users(): bool {
		return Registrar::can_manage() && current_user_can( 'list_users' );
	}

	/** The reads only a network's super administrator may make. */
	public const NETWORK_READS = array( 'bettershield/list-network-sites' );

	/**
	 * Set only while the release's manifest is built. The manifest describes
	 * what a site's own connection is offered, which is the same on a single
	 * site and on a network; a network's reads are offered beyond it, to a
	 * super administrator's connection only. A live request never sets it.
	 *
	 * @var bool
	 */
	public static $describing_release = false;

	/** A network's estate is read by a super administrator only, as its own screen is. */
	public static function can_read_network(): bool {
		return Registrar::can_read() && \BetterShield\Rest\Permissions::network_read();
	}

	private static function hardening( array $input ): array {
		$groups  = Hardening\Items::groups();
		$manager = Hardening\Manager::instance();
		$out     = array();
		foreach ( Hardening\Items::all() as $id => $item ) {
			$state      = $manager->item_state( $id );
			$options    = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();
			$standing   = $manager->standing( $id );
			$reversible = Registrar::item_is_reversible( $id, $options );
			$monitor    = Hardening\Monitor::describe( $id );
			// The window's counts and times only: its options can carry a hidden sign-in path.
			$watch = is_array( $monitor['state'] ?? null ) ? $monitor['state'] : array();
			$out[] = array(
				'id' => $id, 'title' => $item['title'], 'group' => $item['group'], 'group_title' => (string) ( $groups[ $item['group'] ]['title'] ?? '' ),
				'active' => ! empty( $state['active'] ), 'applied_at' => (string) ( $state['applied_at'] ?? '' ), 'observable' => \BetterShield\Verify\Checks::is_observable( $id ),
				'path' => self::path( $id, $reversible ), 'reversible' => $reversible,
				'available' => $standing['available'], 'availability_note' => (string) ( $standing['availability_note'] ?? '' ), 'conflict_warning' => (string) ( $standing['conflict_warning'] ?? '' ), 'revert_failed' => (string) ( $state['revert_failed'] ?? '' ),
				'scope' => self::scope( $id ), 'detail' => self::detail( $id, $state, $options ),
				'monitor' => array( 'id' => (string) ( $watch['id'] ?? '' ), 'supported' => (bool) $monitor['supported'], 'phase' => (string) ( $watch['phase'] ?? '' ), 'started' => (string) ( $watch['started'] ?? '' ), 'ends' => (string) ( $watch['ends'] ?? '' ), 'observed' => (int) ( $watch['observed'] ?? 0 ), 'matched' => (int) ( $watch['matched'] ?? 0 ), 'denied' => (int) ( $watch['denied'] ?? 0 ) ),
			);
		}
		return array( 'items' => $out );
	}

	/**
	 * How a connection may apply an item: never, for the items that write a
	 * rule block into a shared configuration file; after a person confirms,
	 * for anything that changes how people sign in or cannot be undone as
	 * applied; otherwise directly.
	 */
	private static function path( string $id, bool $reversible ): string {
		if ( in_array( $id, Registrar::HUMAN_ONLY_ITEMS, true ) ) { return 'human_only'; }
		return \BetterShield\Rest\Permissions::needs_way_back( $id ) || ! $reversible ? 'confirmed' : 'direct';
	}

	/**
	 * How far applying an item from this site reaches on a network. The
	 * sign-in keys are the network's own. The uploads rule placed in the main
	 * site's uploads directory reaches every site's, which sit inside it. The
	 * root .htaccess serves every site, so its rules are applied from the
	 * main site alone. Everything else is this site's.
	 */
	private static function scope( string $id ): string {
		if ( ! is_multisite() ) { return 'site'; }
		if ( 'auth_keys' === $id ) { return 'network'; }
		if ( 'uploads_php' === $id ) { return is_main_site() ? 'network' : 'site'; }
		if ( 'sensitive_files' === $id ) { return is_main_site() ? 'network' : 'main_site'; }
		return 'site';
	}

	/**
	 * The settings in force for the two items whose choice matters to a
	 * reader: how long browsers are told to refuse plain HTTP, and where the
	 * content policy stands on its way to enforcing. Every other item, and
	 * one that is off, has none.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\stdClass
	 */
	private static function detail( string $id, array $state, array $options ) {
		if ( empty( $state['active'] ) ) { return new \stdClass(); }
		if ( 'hsts' === $id ) {
			// Preload is never offered: it is a submission to a list built into browsers.
			return array( 'max_age' => Hardening\Item\Hsts::MODE_LONG === ( $options['mode'] ?? '' ) ? Hardening\Item\Hsts::LONG : Hardening\Item\Hsts::SHORT, 'include_subdomains' => 'yes' === ( $options['subdomains'] ?? '' ), 'preload' => false );
		}
		if ( 'csp_report_only' === $id ) {
			$policy = Hardening\Item\ContentSecurityPolicy::class;
			$ready  = $policy::promotable( false );
			return array( 'mode' => $policy::mode( $state ), 'report_kinds' => count( $policy::reports() ), 'ready_to_enforce' => (bool) $ready['ready'], 'quiet_days' => (int) $ready['quiet_days'], 'needed_days' => (int) $ready['needed'] );
		}
		return new \stdClass();
	}

	private static function login( array $input ): array {
		$settings = array_intersect_key( Login\Protection::instance()->settings(), array_fill_keys( array( 'enabled', 'attempt_limit', 'threshold', 'window_minutes', 'lockout_minutes', 'honeypot', 'proof_of_work', 'cloudflare', 'idle_minutes', 'session_cap', 'new_location_notice', 'allowlist', 'blocklist', 'trusted_proxies' ), true ) );
		// As enforced: the host's filter decides over the switch.
		$settings['host_ban_line'] = \BetterShield\Support\AuthLog::on();
		foreach ( array( 'allowlist', 'blocklist', 'trusted_proxies' ) as $name ) {
			$settings[ $name . '_count' ] = count( $settings[ $name ] );
			unset( $settings[ $name ] );
		}
		$protection = Login\Protection::instance();
		foreach ( Login\Surfaces::GATED as $surface ) {
			$settings['surfaces'][ $surface ] = $protection->surface_policy( $surface );
		}
		$defaults = $protection->defaults();
		$settings['defaults'] = array( 'threshold' => (int) $defaults['threshold'], 'window_minutes' => (int) $defaults['window_minutes'], 'lockout_minutes' => (int) $defaults['lockout_minutes'] );
		// How the address was worked out, never the address: over a connection it is the caller's own.
		$resolved = $protection->resolution_report();
		$settings['connection'] = array( 'method' => (string) $resolved['method'], 'confident' => (bool) $resolved['confident'], 'ignored_headers' => (bool) $resolved['ignored_headers'] );
		$settings['lockouts_active'] = $protection->lockout_running();
		$settings['lockouts_total'] = $protection->lockout_total();
		$settings['session_cap_supported'] = Login\Sessions::instance()->cap_supported();
		$settings['signed_in_accounts'] = count( Login\Sessions::instance()->live_counts() );
		return $settings;
	}

	private static function agent_connections( array $input ): array {
		$state    = \BetterShield\Mcp\Pairing::state();
		$paired   = \BetterShield\Mcp\Pairing::is_connected();
		$hub_apps = \BetterShield\Mcp\Hub::apps();
		$hub_ids  = array_map( 'strval', array_column( $hub_apps, 'id' ) );
		$stamp    = static fn( $at ): string => (int) $at > 0 ? gmdate( 'c', (int) $at ) : '';
		$apps     = array();
		foreach ( \BetterShield\Mcp\OAuth::connected_apps() as $app ) {
			$apps[] = array( 'id' => (string) $app['id'], 'name' => Text::clip( (string) $app['name'], 120 ), 'scope' => (string) $app['scope'], 'granted_at' => $stamp( $app['granted_at'] ), 'granted_by' => self::person( (int) $app['granted_by'] ), 'last_used_at' => $stamp( $app['last_used'] ), 'is_hub' => in_array( (string) $app['id'], $hub_ids, true ) );
		}
		// Armed or not, and when last used: never the decoy's name, its id or its path, which would disarm it.
		$canary = \BetterShield\Agents\Canary::planted();
		$used   = null === $canary ? null : \BetterShield\Agents\Canary::last_use( $canary['uuid'] );
		$expiry = ( new \BetterShield\Agents\Expiry() )->settings();
		return array(
			'mcp_enabled' => \BetterShield\Mcp\Manager::is_enabled(),
			'pairing' => array( 'connected' => $paired, 'connected_at' => $paired ? $stamp( $state['connected_at'] ) : '', 'connected_by' => self::person( $paired ? \BetterShield\Mcp\Pairing::user_id() : 0 ), 'scope' => \BetterShield\Mcp\Pairing::scope() ),
			'apps' => $apps,
			'hub' => array( 'connected' => array() !== $hub_apps, 'host' => \BetterShield\Mcp\Hub::host(), 'granted_at' => $stamp( $hub_apps[0]['granted_at'] ?? 0 ) ),
			'health' => array_diff_key( \BetterShield\Rest\McpController::health(), array( 'tool_names' => true ) ),
			'open_requests' => Proposals::open_count(),
			// Read through their filters: a site can set its own ceilings.
			'rules' => array( 'sudo_enabled' => \BetterShield\Rest\Sudo::enabled(), 'recovery_ready_for_sign_in_changes' => Registrar::recovery_ready(), 'recording' => \BetterShield\Agents\Capture::is_enabled(), 'write_limit_per_hour' => max( 1, (int) apply_filters( 'bettershield_agent_write_limit', Registrar::WRITE_LIMIT_PER_HOUR ) ), 'propose_limit_per_hour' => max( 1, (int) apply_filters( 'bettershield_agent_propose_limit', Registrar::PROPOSE_LIMIT_PER_HOUR ) ) ),
			'surface' => array( 'retire_unused_app_passwords' => array( 'enabled' => (bool) $expiry['enabled'], 'days' => (int) $expiry['days'] ), 'decoy_credential' => array( 'armed' => null !== $canary, 'used_at' => null === $used ? '' : (string) $used['at'] ), 'decoy_url' => array( 'armed' => (bool) \BetterShield\Agents\DecoyPage::report()['enabled'] ) ),
		);
	}

	/**
	 * An account named the way this read names every account: by its display
	 * name unless that is its login, and by number otherwise.
	 *
	 * @return array{id: int, display_name: string}
	 */
	private static function person( int $id ): array {
		$user = $id > 0 ? get_userdata( $id ) : false;
		return $user ? array( 'id' => (int) $user->ID, 'display_name' => self::user_label( $user->data ) ) : array( 'id' => 0, 'display_name' => '' );
	}

	/** The Hub link as the hub reads it to learn its key, with a proof when the hub sends a challenge; never the secret half. */
	private static function hub_link( array $input ): array {
		return \BetterShield\Hub\Link\Link::read( (string) ( $input['challenge'] ?? '' ) );
	}

	/**
	 * The Overview as data: Auditor::overview(), the payload the Overview
	 * screen draws, with each finding's record beside it and the judgments the
	 * screen makes made here. Open findings in the order the Overview lists
	 * them, then the ones marked not applicable, then, when asked, fixed ones.
	 *
	 * @return array<string, mixed>
	 */
	private static function overview( array $input ): array {
		$overview = Audit\Auditor::overview();
		$records  = array();
		foreach ( Audit\Auditor::findings() as $record ) {
			$records[ (string) $record['id'] ] = $record;
		}
		$manager  = Hardening\Manager::instance();
		$open     = array_fill_keys( array( 'critical', 'high', 'medium', 'low', 'info' ), 0 );
		$snoozed  = $open;
		$aside    = 0;
		$findings = array();
		foreach ( (array) $overview['findings'] as $finding ) {
			$findings[] = self::overview_row( $finding, $records[ (string) $finding['id'] ] ?? array(), $manager );
			$severity   = (string) $finding['severity'];
			if ( isset( $open[ $severity ] ) ) {
				++$open[ $severity ];
				$snoozed[ $severity ] += empty( $finding['snoozed_until'] ) ? 0 : 1;
			}
		}
		foreach ( $records as $record ) {
			$status = (string) $record['status'];
			$aside += 'suppressed' === $status ? 1 : 0;
			if ( 'suppressed' === $status || ( 'fixed' === $status && ! empty( $input['include_fixed'] ) ) ) {
				$findings[] = self::overview_row( $record, $record, $manager );
			}
		}
		$unknown = array();
		foreach ( (array) $overview['checks_unknown'] as $check ) {
			$unknown[] = array( 'check' => (string) $check['key'], 'title' => (string) $check['title'], 'reason_code' => (string) $check['code'], 'reason' => (string) $check['reason'], 'last_answered_at' => (string) $check['last_answered_at'] );
		}
		$cost   = is_array( $overview['front_end_cost'] ) ? $overview['front_end_cost'] : null;
		$report = (array) $overview['recovery_readiness'];
		$mailed = $report['link_mail'] ?? null;
		return array(
			'schema' => 'bettershield.overview/1', 'plugin_version' => BETTERSHIELD_VERSION,
			'score' => (int) $overview['score'], 'grade' => (string) $overview['grade'],
			'projected_score' => (int) $overview['projected_score'], 'projected_grade' => (string) $overview['projected_grade'],
			'history' => array_map( static fn( array $point ): array => array( 'at' => (string) $point['at'], 'score' => (int) $point['score'] ), (array) $overview['history'] ),
			'counts' => array( 'open' => $open, 'snoozed' => $snoozed, 'suppressed' => $aside ),
			'findings' => $findings,
			'audit' => array( 'generated_at' => (string) ( $overview['generated_at'] ?? '' ), 'duration_ms' => (int) ( $overview['duration_ms'] ?? 0 ), 'checks_total' => (int) $overview['checks_count'], 'checks_ran' => (int) $overview['checks_ran'], 'checks_unknown' => $unknown, 'next_check_at' => (string) ( $overview['next_check_at'] ?? '' ) ),
			'receipts' => array( 'audits_week' => (int) $overview['receipts']['audits_week'], 'hardening_active' => (int) $overview['receipts']['hardening_active'], 'events_week' => (int) $overview['receipts']['events_week'], 'last_change_at' => (string) ( $overview['receipts']['last_change_at'] ?? '' ) ),
			// Nothing until enough page views have been sampled to say anything, as on the Overview.
			'front_end_cost' => null === $cost
				? array( 'measured' => false, 'pages' => 0, 'ms' => 0, 'queries' => 0, 'samples' => 0, 'one_in' => 0, 'since' => '' )
				: array( 'measured' => true, 'pages' => (int) $cost['pages'], 'ms' => (float) $cost['ms'], 'queries' => (float) $cost['queries'], 'samples' => (int) $cost['samples'], 'one_in' => (int) $cost['one_in'], 'since' => (string) $cost['since'] ),
			// Beside the score and never folded into it: the score is what the site is set up to do.
			'safe_mode' => array( 'active' => (bool) $overview['safe_mode']['active'], 'until' => (string) ( $overview['safe_mode']['until'] ?? '' ), 'by_network' => (bool) $overview['safe_mode']['by_network'] ),
			// Never true over the MCP endpoint, which a lockdown closes before any tool runs; said for every other way in.
			'lockdown' => array( 'active' => \BetterShield\Recovery\Lockdown::is_active() ),
			'alerts_muted' => (bool) $overview['alerts_muted'],
			'recovery' => array(
				'link' => (string) ( $report['link'] ?? 'missing' ), 'link_expires_at' => (string) ( $report['link_expires_at'] ?? '' ),
				// Three states on the site: a link read on screen was never mailed, which is not a refusal.
				'link_mail' => null === $mailed ? 'not_mailed' : ( $mailed ? 'accepted' : 'refused' ),
				'offline_codes' => (int) ( $report['offline_codes'] ?? 0 ), 'administrators_with_email' => (int) ( $report['administrators_with_email'] ?? 0 ),
				'email_tests' => (bool) ( $report['email_tests'] ?? false ), 'mail' => (string) ( $report['mail'] ?? '' ), 'mail_checked_at' => (string) ( $report['mail_checked_at'] ?? '' ),
				'checked_at' => (string) ( $report['checked_at'] ?? '' ), 'overdue' => (bool) ( $report['overdue'] ?? false ), 'needs_attention' => (bool) ( $report['needs_attention'] ?? false ),
				'checks' => (array) ( $report['checks'] ?? array() ), 'ready' => (int) ( $report['ready'] ?? 0 ), 'total' => (int) ( $report['total'] ?? 0 ),
				'ready_for_sign_in_changes' => Registrar::recovery_ready( $report ),
			),
		);
	}

	/**
	 * One finding as the overview read gives it.
	 *
	 * @param array<string, mixed> $finding As the Overview lists it, or its record where the Overview does not list it.
	 * @param array<string, mixed> $record  Its record: the status and the times.
	 * @return array<string, mixed>
	 */
	private static function overview_row( array $finding, array $record, Hardening\Manager $manager ): array {
		$item    = (string) ( $finding['hardening_item'] ?? '' );
		$control = is_array( $finding['control'] ?? null ) ? $finding['control'] : array();
		$fix     = array( 'kind' => 'none', 'item_id' => '', 'item_active' => false, 'path' => '', 'reversible' => false, 'control' => array( 'label' => (string) ( $control['label'] ?? '' ), 'url' => (string) ( $control['url'] ?? '' ) ) );
		if ( '' !== $item ) {
			// Reversible as the item answers for the options it is set to, which is how its plan answers.
			$state      = $manager->item_state( $item );
			$reversible = Registrar::item_is_reversible( $item, is_array( $state['options'] ?? null ) ? $state['options'] : array() );
			$fix        = array( 'kind' => 'item', 'item_id' => $item, 'item_active' => ! empty( $finding['hardening_active'] ), 'path' => self::path( $item, $reversible ), 'reversible' => $reversible ) + $fix;
		} elseif ( '' !== $fix['control']['url'] ) {
			$fix['kind'] = 'control';
		}
		return array(
			'id' => (string) $finding['id'], 'group' => (string) $finding['group'], 'severity' => (string) $finding['severity'],
			'severity_level' => (int) $finding['severity_level'], 'deduction' => (int) $finding['deduction'],
			'status' => (string) ( $record['status'] ?? $finding['status'] ), 'title' => (string) $finding['title'],
			'why' => (string) $finding['why'], 'break_note' => (string) $finding['break_note'], 'stale' => ! empty( $finding['stale'] ),
			'first_seen_at' => (string) ( $record['first_seen_at'] ?? '' ), 'last_seen_at' => (string) ( $record['last_seen_at'] ?? '' ), 'resolved_at' => (string) ( $record['resolved_at'] ?? '' ),
			'snoozed_until' => (string) ( $finding['snoozed_until'] ?? '' ), 'evidence_available' => ! empty( $record['evidence'] ),
			'fix' => $fix,
		);
	}

	/** @return array|\WP_Error */
	private static function network_sites( array $input ) {
		$cursor = (string) ( $input['cursor'] ?? '' );
		if ( '' !== $cursor && ! ctype_digit( $cursor ) ) {
			return new \WP_Error( 'bettershield_cursor_invalid', __( 'That cursor is not one this read gave.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$page  = \BetterShield\Admin\Network::rollup( false, (int) $cursor );
		$sites = array();
		foreach ( (array) $page['sites'] as $site ) {
			$id        = (int) $site['id'];
			$installed = ! empty( $site['installed'] );
			$switches  = array( false, false, false );
			// A site without this plugin's tables has no switches to read.
			if ( $installed ) {
				switch_to_blog( $id );
				try {
					$switches = array( \BetterShield\Mcp\Manager::is_enabled(), Registrar::is_enabled(), array() !== \BetterShield\Mcp\Hub::apps() );
				} finally {
					restore_current_blog();
				}
			}
			$audited = null !== ( $site['audited_at'] ?? null );
			$sites[] = array( 'site_id' => $id, 'name' => Text::clip( (string) $site['name'], 191 ), 'home_url' => untrailingslashit( (string) $site['url'] ), 'installed' => $installed, 'mcp_enabled' => $switches[0], 'abilities_enabled' => $switches[1], 'hub_connected' => $switches[2], 'score' => $audited ? (int) $site['score'] : 0, 'grade' => $audited ? (string) $site['grade'] : '', 'open_findings' => $audited ? (int) $site['open_findings'] : 0, 'audited_at' => $audited ? (string) $site['audited_at'] : '' );
		}
		return array( 'sites' => $sites, 'total' => (int) $page['total'], 'next_cursor' => (int) $page['next_cursor'] > 0 ? (string) (int) $page['next_cursor'] : '', 'built_at' => gmdate( 'c', (int) $page['built_at'] ) );
	}

	/** @return array|\WP_Error */
	private static function lockout_list( array $input ) {
		$cursor = (string) ( $input['cursor'] ?? '' );
		if ( '' !== $cursor && ! ctype_digit( $cursor ) ) {
			return new \WP_Error( 'bettershield_cursor_invalid', __( 'That cursor is not one this read gave.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$surfaces   = isset( $input['surface'] ) ? array( (string) $input['surface'] ) : array();
		$protection = Login\Protection::instance();
		$page       = $protection->lockout_page( $surfaces, (int) $cursor, (int) ( $input['limit'] ?? 50 ) );
		if ( is_wp_error( $page ) ) { return $page; }
		$rows = $page['lockouts'];
		return array( 'lockouts' => $rows, 'total' => $protection->lockout_total( $surfaces ), 'active' => $protection->lockout_running( $surfaces ), 'next_cursor' => $page['has_more'] && array() !== $rows ? (string) $rows[ count( $rows ) - 1 ]['id'] : '' );
	}

	private static function factors( array $input ): array {
		$two = TwoFactor\Policy::instance()->settings();
		$passkey = Passkeys\Policy::instance()->settings();
		return array(
			'site' => array( 'two_factor_roles' => $two['roles'], 'grace_days' => $two['grace_days'], 'passkey_roles' => $passkey['roles'] ),
			'effective' => array( 'two_factor_roles' => Policies::effective_two_factor_roles( $two['roles'] ), 'grace_days' => Policies::effective_grace( $two['grace_days'] ), 'passkey_roles' => Policies::effective_passkey_roles( $passkey['roles'] ) ),
			'safe_mode' => \BetterShield\Recovery\SafeMode::is_active(),
			'network_two_factor_set' => Policies::two_factor_is_set(), 'network_passkey_set' => Policies::passkey_is_set(),
			// The network's floor as set, which a site's own policy can raise and never lower.
			'network' => array(
				'two_factor' => Policies::two_factor() + array( 'set' => Policies::two_factor_is_set() ),
				'passkey'    => Policies::passkey() + array( 'set' => Policies::passkey_is_set() ),
			),
			'safe_mode_source' => \BetterShield\Recovery\SafeMode::is_site_active() ? 'site' : ( \BetterShield\Recovery\SafeMode::is_network_active() ? 'network' : '' ),
		);
	}

	/** @return array|\WP_Error */
	private static function users( array $input ) {
		global $wpdb;
		$limit = max( 1, min( 50, (int) ( $input['limit'] ?? 50 ) ) );
		$after = max( 0, (int) ( $input['after_id'] ?? 0 ) );
		$query = new \WP_User_Query();
		$where = static function ( $candidate ) use ( $query, $after, $wpdb ) {
			if ( $candidate === $query ) { $candidate->query_where .= $wpdb->prepare( ' AND ID > %d', $after ); }
		};
		add_action( 'pre_user_query', $where );
		try {
			$query->prepare_query( array( 'blog_id' => get_current_blog_id(), 'number' => $limit + 1, 'orderby' => 'ID', 'order' => 'ASC', 'count_total' => false, 'fields' => array( 'ID', 'display_name', 'user_login', 'user_nicename' ) ) );
			$query->query();
			$failed = '' !== $wpdb->last_error;
		} finally { remove_action( 'pre_user_query', $where ); }
		if ( $failed ) { return new \WP_Error( 'bettershield_users_unreadable', __( 'The user inventory could not be read.', 'bettershield' ), array( 'status' => 503 ) ); }
		$found = $query->get_results();
		$users = array();
		foreach ( array_slice( $found, 0, $limit ) as $row ) {
			$user = new \WP_User( (int) $row->ID, '', get_current_blog_id() );
			$users[] = array( 'id' => (int) $row->ID, 'label' => self::user_label( $row ), 'roles' => array_values( $user->roles ) );
		}
		$roles = array();
		foreach ( array_slice( wp_roles()->roles, 0, 50, true ) as $id => $role ) {
			$caps = (array) ( $role['capabilities'] ?? array() );
			$bounded = array_slice( $caps, 0, 200, true );
			$roles[] = array( 'id' => (string) $id, 'label' => Text::clip( sanitize_text_field( $role['name'] ?? $id ), 120 ), 'granted' => array_keys( array_filter( $bounded ) ), 'denied' => array_keys( array_filter( $bounded, static fn( $value ) => ! $value ) ), 'capabilities_truncated' => count( $caps ) > 200 );
		}
		return array( 'users' => $users, 'roles' => $roles, 'roles_truncated' => count( wp_roles()->roles ) > 50, 'has_more' => count( $found ) > $limit, 'next_after_id' => array() === $users ? $after : $users[ count( $users ) - 1 ]['id'] );
	}

	/**
	 * An account as an assistant may read it: its display name, or "Account
	 * #N" where that name is its login, half a credential an assistant's
	 * transcript does not need. The same rule for every read that names an
	 * account, so one cannot be used to learn what another withholds (#1822).
	 */
	public static function account_label( int $user_id ): string {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;

		if ( ! $user instanceof \WP_User ) {
			/* translators: %d: an account's ID. */
			return sprintf( __( 'Account #%d', 'bettershield' ), $user_id );
		}

		return self::user_label( $user->data );
	}

	/**
	 * A member's name as this answer gives it, which is never their login.
	 *
	 * WordPress sets the display name to the login when an account is made
	 * without a first and last name, which is most accounts: the installer's
	 * administrator, and most made from Users, Add New. Given as it was, the
	 * answer that promises no login names was a list of them, roles beside.
	 * A display name that is the login or its URL form is not given.
	 *
	 * @param object $row The member's row.
	 */
	private static function user_label( $row ): string {
		$name = trim( (string) $row->display_name );

		if ( '' === $name || 0 === strcasecmp( $name, (string) $row->user_login ) || 0 === strcasecmp( $name, (string) $row->user_nicename ) ) {
			/* translators: %d: an account's ID. */
			return sprintf( __( 'Account #%d', 'bettershield' ), (int) $row->ID );
		}

		return Text::clip( sanitize_text_field( $name ), 120 );
	}

	/** @return array|\WP_Error */
	private static function sessions( array $input ) {
		$id = (int) ( $input['user_id'] ?? get_current_user_id() );
		if ( ! get_user_by( 'id', $id ) || ( is_multisite() && ! is_user_member_of_blog( $id, get_current_blog_id() ) ) ) {
			return new \WP_Error( 'bettershield_member_not_found', __( 'That account is not a member of this site.', 'bettershield' ), array( 'status' => 404 ) );
		}
		$stored = get_user_meta( $id, 'session_tokens', true );
		$out = array(); $count = 0;
		foreach ( is_array( $stored ) ? $stored : array() as $session ) {
			if ( ! is_array( $session ) || (int) ( $session['expiration'] ?? 0 ) <= time() ) { continue; }
			++$count;
			if ( count( $out ) >= 20 ) { continue; }
			$stamp = static fn( $value ): string => (int) $value > 0 ? gmdate( 'c', (int) $value ) : '';
			$out[] = array( 'signed_in_at' => $stamp( $session['login'] ?? 0 ), 'last_seen_at' => $stamp( Login\Sessions::last_seen( $session ) ), 'expires_at' => $stamp( $session['expiration'] ) );
		}
		return array( 'user_id' => $id, 'network_shared' => is_multisite(), 'sessions' => $out, 'active_count' => $count, 'has_more' => $count > count( $out ) );
	}

	private static function quarantine( array $input ) {
		global $wpdb;
		$page  = \BetterShield\Files\Quarantine::page( max( 0, (int) ( $input['before_id'] ?? 0 ) ) );
		$items = $page['items'];
		if ( '' !== $wpdb->last_error ) { return new \WP_Error( 'bettershield_quarantine_unreadable', __( 'The quarantine inventory could not be read.', 'bettershield' ), array( 'status' => 503 ) ); }
		// The ledger row id is the only field of the row that leaves here
		// beyond the metadata: it is what a caller passes back as before_id,
		// and it names no path and unlocks nothing.
		foreach ( $items as &$item ) {
			$item['id'] = (int) ( $item['ledger_id'] ?? 0 );
			$item       = array_intersect_key( $item, array_fill_keys( array( 'id', 'action', 'path', 'size', 'sha256', 'at', 'restored', 'present' ), true ) );
		}
		unset( $item );
		return array( 'items' => $items, 'ledger_limit' => \BetterShield\Files\Quarantine::MAX_ITEMS, 'next_before_id' => (int) $page['next_before_id'], 'has_more' => (bool) $page['has_more'] );
	}

	private static function cron( array $input ): array {
		$stored = get_option( 'cron' );
		$legacy = is_array( $stored ) && 2 !== ( $stored['version'] ?? null );
		// Core's legacy cron reader upgrades and writes the option. This read
		// reports the unsupported shape instead of triggering that mutation.
		$report = $legacy ? array( 'events' => array(), 'total' => 0, 'unanswered' => 0, 'readable' => false, 'schedule' => Audit\Cron::schedule() ) : Audit\Cron::report();
		return $report + array( 'legacy_schedule' => $legacy );
	}

	/** @return array|\WP_Error */
	private static function check( array $input ) {
		global $wpdb;
		$id = (string) ( $input['check_id'] ?? '' );
		$check = Audit\Checks::all()[ $id ] ?? null;
		if ( null === $check ) { return new \WP_Error( 'bettershield_check_unknown', __( 'That audit check is not registered.', 'bettershield' ), array( 'status' => 404 ) ); }
		$record = array();
		$findings = Audit\Auditor::findings();
		if ( '' !== $wpdb->last_error ) { return new \WP_Error( 'bettershield_check_unreadable', __( 'The saved audit check could not be read.', 'bettershield' ), array( 'status' => 503 ) ); }
		foreach ( $findings as $finding ) { if ( $id === $finding['id'] ) { $record = $finding; break; } }
		return array( 'id' => $id, 'title' => Audit\Checks::title_of( $check, isset( $record['severity'] ) ? (string) $record['severity'] : null ), 'group' => $check['group'], 'severity' => $record['severity'] ?? Audit\Checks::severity_of( $check ), 'explanation' => $check['why'], 'risk_note' => $check['break_note'], 'status' => $record['status'] ?? 'not_recorded', 'last_seen_at' => (string) ( $record['last_seen_at'] ?? '' ), 'evidence_available' => ! empty( $record['evidence'] ) );
	}

	/**
	 * The site's own settings as they stand. Alert recipients are counted:
	 * an address is where an alert can be sent, and nobody reading this needs
	 * one. The security contact file is reported published or not, never
	 * what it says.
	 *
	 * @return array|\WP_Error
	 */
	private static function settings( array $input ) {
		$alerts = \BetterShield\Alerts\Settings::instance();
		$saved  = $alerts->settings();
		$sent   = \BetterShield\Alerts\Precision::rate();
		if ( ! $sent['available'] ) { return new \WP_Error( 'bettershield_settings_unreadable', __( 'The alerts sent could not be counted.', 'bettershield' ), array( 'status' => 503 ) ); }
		$window   = \BetterShield\Alerts\Maintenance::report();
		$password = \BetterShield\Password\Policy::instance()->settings();
		$contact  = \BetterShield\Disclosure\SecurityTxt::instance()->settings();
		$usage    = \BetterShield\Onboarding\Usage::state();
		return array(
			'alerts' => array(
				// Every alert goes through WordPress's own mailer.
				'muted' => $alerts->is_muted(), 'transport' => 'wp_mail',
				'recipients' => count( $alerts->recipients() ), 'uses_admin_address' => array() === $saved['recipients'],
				'digest' => $saved['digest'], 'digest_day' => $saved['digest_day'], 'instant' => $saved['instant_critical'],
				'sent' => array( 'count' => $sent['sent'], 'window_days' => $sent['window_days'] ),
				'maintenance' => array( 'active' => $window['active'], 'until' => $window['active'] ? (string) $window['until'] : '' ),
			),
			'password_policy' => array( 'enabled' => $password['enabled'], 'min_length' => $password['min_length'], 'min_length_privileged' => $password['min_length_privileged'], 'min_length_single_factor' => $password['min_length_single_factor'] ),
			'security_contact' => array( 'enabled' => $contact['enabled'], 'expires' => $contact['enabled'] ? $contact['expires'] : '' ),
			'usage' => array( 'allowed' => $usage['allowed'], 'last_sent' => $usage['last_sent'] > 0 ? gmdate( 'c', $usage['last_sent'] ) : '' ),
			'uninstall' => array( 'choice' => \BetterShield\Support\UninstallChoice::choice(), 'remove_data' => \BetterShield\Support\UninstallChoice::remove_data() ),
		);
	}

	/**
	 * Versions and counts, from what WordPress already holds: the update
	 * counts come from the transients its own checks leave, so a read never
	 * makes a request of its own. `checked_at` is the oldest of the three
	 * checks, the time every count is at least as fresh as.
	 */
	private static function environment( array $input ): array {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$theme   = wp_get_theme();
		$active  = (array) get_option( 'active_plugins', array() );
		$network = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$core    = array_filter( (array) get_core_updates( array( 'dismissed' => false ) ), static fn( $offer ): bool => is_object( $offer ) && 'upgrade' === ( $offer->response ?? '' ) );
		$checked = array();
		foreach ( array( 'update_core', 'update_plugins', 'update_themes' ) as $transient ) {
			$stored = get_site_transient( $transient );
			if ( is_object( $stored ) && ! empty( $stored->last_checked ) ) { $checked[] = (int) $stored->last_checked; }
		}
		return array(
			'wordpress' => (string) get_bloginfo( 'version' ), 'php' => PHP_VERSION,
			'theme' => array( 'name' => Text::clip( sanitize_text_field( (string) $theme->get( 'Name' ) ), 120 ), 'version' => Text::clip( sanitize_text_field( (string) $theme->get( 'Version' ) ), 40 ) ),
			'plugins' => array( 'active' => count( array_unique( array_merge( $active, $network ) ) ), 'installed' => count( get_plugins() ) ),
			'updates' => array( 'core' => count( $core ), 'plugins' => count( get_plugin_updates() ), 'themes' => count( get_theme_updates() ), 'checked_at' => array() === $checked ? '' : gmdate( 'c', min( $checked ) ) ),
			'bettershield' => array( 'version' => BETTERSHIELD_VERSION ),
			'ultra' => array( 'active' => defined( 'BETTERSHIELD_ULTRA_VERSION' ), 'version' => defined( 'BETTERSHIELD_ULTRA_VERSION' ) ? (string) constant( 'BETTERSHIELD_ULTRA_VERSION' ) : '' ),
			'multisite' => \BetterShield\Mcp\Hub::network_identity(),
			// Where this site's dashboard is, which follows the WordPress address rather than the home address, so a
			// hub links into it right when WordPress lives in a subfolder (WPDevelopers/bettershield-hub#615).
			'admin_url' => untrailingslashit( admin_url() ),
		);
	}

	private static function incidents( array $input ) {
		$page = \BetterShield\Incidents\Repository::page( (string) ( $input['status'] ?? 'open' ), (int) ( $input['before_id'] ?? 0 ) );
		// When correlation last ran, and whether it has more to do or failed: a quiet list from a stalled engine is not a quiet site.
		return is_wp_error( $page ) ? $page : $page + array( 'engine' => \BetterShield\Incidents\Engine::report() );
	}

	/** @return array|\WP_Error */
	private static function recent_changes( array $input ) {
		$since = strtotime( (string) ( $input['since'] ?? '' ) );
		if ( false === $since || $since <= 0 || $since > time() ) {
			return new \WP_Error( 'bettershield_since_invalid', __( 'Give since as a time in the past, such as 2026-10-07T07:53:00Z.', 'bettershield' ), array( 'status' => 400 ) );
		}
		$list    = \BetterShield\Events\SinceLastVisit::changes_from( $since );
		$changes = array();
		foreach ( $list['changes'] as $change ) {
			// An account as list-users-and-roles names it, never by the login
			// the log stored for the dashboard's panel (#1822).
			$actor     = (int) ( $change['actor_id'] ?? 0 ) > 0 ? self::account_label( (int) $change['actor_id'] ) : (string) $change['actor'];
			$subject   = (int) ( $change['subject_user'] ?? 0 ) > 0 ? self::account_label( (int) $change['subject_user'] ) : (string) ( $change['subject'] ?? '' );
			$changes[] = array( 'id' => (int) $change['id'], 'occurred_at' => (string) $change['occurred_at'], 'type' => (string) $change['type'], 'label' => (string) $change['label'], 'severity' => (int) $change['severity'], 'actor' => $actor, 'subject' => $subject );
		}
		return array( 'since' => (string) $list['since'], 'clamped' => (bool) $list['clamped'], 'more' => (bool) $list['more'], 'changes' => $changes );
	}
	private static function incident( array $input ) {
		return \BetterShield\Incidents\Repository::detail( (int) $input['incident_id'], (int) ( $input['after_id'] ?? 0 ) );
	}
	private static function backups( array $input ): array {
		$report = Audit\BackupVisibility::report();
		$report['lists_truncated'] = count( $report['active_plugins'] ) > 50 || count( $report['inactive_plugins'] ) > 50;
		$report['active_plugins'] = array_slice( $report['active_plugins'], 0, 50 );
		$report['inactive_plugins'] = array_slice( $report['inactive_plugins'], 0, 50 );
		return $report;
	}
}
