<?php
/**
 * Human names for event types.
 *
 * The stored `event_type` string is an identifier and never changes, because
 * old rows keep the old value and renaming one rewrites history. What a reader
 * sees is decided here instead, in one place, so a wording change is a wording
 * change and not a migration.
 *
 * Kept in PHP rather than the interface so the names are translatable through
 * the same catalog as everything else.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Support\Areas;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Types {

	/**
	 * The map as it stands in the language currently in force, or null when it
	 * has not been built yet. See labels().
	 *
	 * @var array<string, string>|null
	 */
	private static ?array $labels = null;

	/**
	 * What other plugins registered on `bettershield_event_types`, checked,
	 * or null when it has not been asked for yet. See registered().
	 *
	 * @var array<string, array{label: string, area: string}>|null
	 */
	private static ?array $registered = null;

	/**
	 * The longest slug the log stores. `Writer` cuts a longer one to this, and
	 * a cut slug matches no registration, so a longer one is refused here
	 * rather than accepted and then never found.
	 */
	public const MAX_SLUG = 32;

	/**
	 * Written as plain statements of what happened, in the past tense, with no
	 * adjectives. The severity carries the alarm, if there is any to carry.
	 *
	 * Built once and held. `label()` is called inside the per-row shaping that
	 * the listing, the export and the Overview all share, so rebuilding a
	 * hundred-odd translated strings for each row was most of what those loops
	 * spent — and an export walks up to ten thousand rows under a wall-clock
	 * budget, so it was time taken from the end of the file.
	 *
	 * @return array<string, string>
	 */
	public static function labels(): array {
		if ( null !== self::$labels ) {
			return self::$labels;
		}

		$labels = array(
			'login'                   => __( 'Signed in', 'bettershield' ),
			'login_failed'            => __( 'Sign-in failed', 'bettershield' ),
			'logout'                  => __( 'Signed out', 'bettershield' ),
			'user_created'            => __( 'User created', 'bettershield' ),
			'user_deleted'            => __( 'User deleted', 'bettershield' ),
			'user_removed_from_site'  => __( 'User removed from this site', 'bettershield' ),
			'user_role_changed'       => __( 'Role changed', 'bettershield' ),
			'user_role_granted'       => __( 'Role granted', 'bettershield' ),
			'user_role_revoked'       => __( 'Role removed', 'bettershield' ),
			'temporary_access_end_refused' => __( 'Temporary access could not be ended', 'bettershield' ),
			/*
			 * An agency's access taken away in one previewed flow, and the
			 * two halves of the one step in it that can be put back: an
			 * account kept from signing in, with its role and data intact.
			 * The add-on's handover records them, and so does suspending a
			 * dormant account from its finding.
			 */
			'account_suspended'       => __( 'Account suspended', 'bettershield' ),
			'account_suspension_lifted' => __( 'Account suspension lifted', 'bettershield' ),
			'handover_completed'      => __( 'Agency handover completed', 'bettershield' ),
			'role_capabilities_changed' => __( 'Role permissions changed', 'bettershield' ),
			'user_email_changed'      => __( 'Email address changed', 'bettershield' ),
			'username_changed'        => __( 'Username changed', 'bettershield' ),
			'password_changed'        => __( 'Password changed', 'bettershield' ),
			'password_reset_requested' => __( 'Password reset requested', 'bettershield' ),
			'app_password_created'    => __( 'Application password created', 'bettershield' ),
			'app_password_limited'    => __( 'Application password restricted to certain uses or networks', 'bettershield' ),
			'app_password_unlimited'  => __( 'Application password restrictions removed', 'bettershield' ),
			'app_password_refused'    => __( 'Application password refused: used outside its restrictions', 'bettershield' ),
			'account_takeover_sequence' => __( 'Email, password and an application password changed within an hour', 'bettershield' ),
			'app_password_revoked'    => __( 'Application password revoked', 'bettershield' ),
			'app_password_used'       => __( 'Application password used', 'bettershield' ),
			'xmlrpc_used'             => __( 'Remote publishing (XML-RPC) used', 'bettershield' ),
			'canary_used'             => __( 'Trap password used: someone copied it from your database or a backup', 'bettershield' ),
			'incident_code_added' => __( 'New code file appeared', 'bettershield' ),
			'incident_code_modified' => __( 'Code file changed', 'bettershield' ),
			'observed_change_response' => __( 'Action taken on an observed change', 'bettershield' ),
			'incident_response_applied' => __( 'Incident response step taken', 'bettershield' ),
			'incident_cron_unanswered' => __( 'A scheduled task ran with no code to handle it', 'bettershield' ),
			/*
			 * The two response actions that leave no trace of their own
			 * anywhere else. Quarantine and the checksum-verified restore are
			 * recorded by the code that performs them, ending sessions and
			 * revoking credentials by the listeners that see them happen —
			 * these two change a capability map and the schedule directly, and
			 * nothing was watching either.
			 */
			'incident_account_demoted' => __( 'Account roles and capabilities removed', 'bettershield' ),
			'incident_cron_unscheduled' => __( 'Scheduled task removed', 'bettershield' ),
			'incident_password_held' => __( 'Account must set a new password before signing in', 'bettershield' ),
			'password_hold_lifted' => __( 'Account no longer has to set a new password', 'bettershield' ),
			'update_code_changed' => __( 'An update changed code in a plugin not from WordPress.org', 'bettershield' ),
			'incident_status_changed' => __( 'Incident status changed', 'bettershield' ),
			'incident_opened'         => __( 'Incident opened', 'bettershield' ),
			'dormant_privileged_login' => __( 'Admin account unused for a long time signed in', 'bettershield' ),
			'canary_page_touched' => __( 'Trap page visited', 'bettershield' ),
			'canary_page_changed' => __( 'Trap page address changed', 'bettershield' ),
			'canary_page_tested' => __( 'Trap page tested', 'bettershield' ),
			'canary_disarmed'         => __( 'Trap password turned off', 'bettershield' ),
			'plugin_activated'        => __( 'Plugin activated', 'bettershield' ),
			'plugin_deactivated'      => __( 'Plugin deactivated', 'bettershield' ),
			'plugin_installed'        => __( 'Plugin installed', 'bettershield' ),
			'plugin_updated'          => __( 'Plugin updated', 'bettershield' ),
			'package_unverified'      => __( 'Updated plugin’s files differ from the official copy', 'bettershield' ),
			/*
			 * Its own type rather than a second reason on the one above,
			 * because this label is what a summary email and an instant alert
			 * are built from and neither has the row's context to qualify it.
			 * The two most-installed plugins in the directory both ship more
			 * files than one inspection may hash, so "it did not match" would
			 * be said about an ordinary update of ordinary software.
			 */
			'package_partly_checked'  => __( 'Updated plugin only partly compared with the official copy', 'bettershield' ),
			/*
			 * The owner's answer to the two above, and the withdrawal of it.
			 * Recorded at info because neither is a finding: one says a
			 * difference was expected, and the other says that judgment was
			 * taken back. The difference itself keeps its own severity.
			 */
			'package_adopted'         => __( 'Modified plugin version trusted', 'bettershield' ),
			'package_adoption_undone' => __( 'Trust in a modified plugin version undone', 'bettershield' ),
			'plugin_deleted'          => __( 'Plugin deleted', 'bettershield' ),
			/*
			 * A response the site took on its own, and one it put back. The
			 * plugin change itself is recorded above by the listener that
			 * watches for any of them; these say why it happened and that
			 * there is a way back — which is the half the bare fact cannot
			 * carry, and the half somebody reading the log a week later needs.
			 *
			 * Nothing in this plugin records them. They are named here because
			 * this registry is what the whole product records through, add-on
			 * included: a type nobody registered lands in the log as its own
			 * slug, and the screens then show a reader a name meant for code.
			 */
			'response_taken'          => __( 'Automatic action taken on a plugin with a known vulnerability', 'bettershield' ),
			'response_undone'         => __( 'Automatic action undone', 'bettershield' ),
			'response_rolled_back'    => __( 'Automatic update rolled back', 'bettershield' ),
			/*
			 * A change made to the network in front of this site, and the same
			 * change taken back. Nothing in this plugin records them either;
			 * they are named here for the same reason as the pair above.
			 */
			'cloudflare_action_taken' => __( 'Cloudflare setting changed', 'bettershield' ),
			'cloudflare_action_undone' => __( 'Cloudflare setting change undone', 'bettershield' ),
			/*
			 * Two different refusals, and which of them happened is the whole
			 * value of the row: the first is this site declining to ask — safe
			 * mode is on, or the network belongs to an administrator — and the
			 * second is the service turning the request down. Named apart so a
			 * log reader can tell "we did not ask" from "we asked and were
			 * told no" without opening the row.
			 */
			'cloudflare_block_refused' => __( 'Cloudflare block not sent (safe mode is on, or the address belongs to an administrator)', 'bettershield' ),
			'turnstile_refused'       => __( 'Bot check not passed', 'bettershield' ),
			'turnstile_unreachable'   => __( 'Bot check could not be completed', 'bettershield' ),
			'cloudflare_block_failed'  => __( 'Cloudflare refused the block', 'bettershield' ),
			'theme_changed'           => __( 'Theme activated', 'bettershield' ),
			'theme_installed'         => __( 'Theme installed', 'bettershield' ),
			'theme_updated'           => __( 'Theme updated', 'bettershield' ),
			'theme_deleted'           => __( 'Theme deleted', 'bettershield' ),
			'theme_plugin_file_edited' => __( 'File edited in the file editor', 'bettershield' ),
			'core_updated'            => __( 'WordPress updated', 'bettershield' ),
			'setting_changed'         => __( 'Setting changed', 'bettershield' ),
			// Told apart from the row above because the settings a takeover
			// changes first are kept when the log is under load and the
			// generic row is not.
			'site_setting_changed'    => __( 'Sensitive site setting changed', 'bettershield' ),
			'takeover_setting_refused' => __( 'Change to a sensitive site setting blocked', 'bettershield' ),
			'first_run_completed'     => __( 'BetterShield first setup finished', 'bettershield' ),
			'quick_setup_completed'   => __( 'Quick Setup finished', 'bettershield' ),
			'quick_setup_skipped'     => __( 'Quick Setup skipped', 'bettershield' ),
			'coexistence_choices_saved' => __( 'Choices saved for features another security plugin also has', 'bettershield' ),
			'recovery_receipt_confirmed' => __( 'Recovery email confirmed as received', 'bettershield' ),
			'recovery_receipt_withdrawn' => __( 'Recovery email confirmation undone', 'bettershield' ),
			// The identifiers are the ones the earlier reporting wrote, so its
			// history and the current answer read as one record.
			'usage_tracking_enabled'  => __( 'Usage data sharing turned on', 'bettershield' ),
			'usage_tracking_disabled' => __( 'Usage data sharing turned off', 'bettershield' ),
			'hub_link_enabled'        => __( 'Instant alerts to BetterShield Hub turned on', 'bettershield' ),
			'hub_link_disabled'       => __( 'Instant alerts to BetterShield Hub turned off', 'bettershield' ),
			'settings_exported'       => __( 'Settings exported', 'bettershield' ),
			'settings_imported'       => __( 'Settings imported', 'bettershield' ),
			'hardening_applied'       => __( 'Hardening applied', 'bettershield' ),
			'hardening_reverted'      => __( 'Hardening undone', 'bettershield' ),
			'hardening_failed'        => __( 'Hardening could not be applied', 'bettershield' ),
			'hardening_revert_failed' => __( 'Hardening could not be undone', 'bettershield' ),
			'keys_rotated'            => __( 'Sign-in security keys replaced, everyone signed out', 'bettershield' ),
			'password_policy_updated' => __( 'Password policy changed', 'bettershield' ),
			'login_protection_updated' => __( 'Login protection changed', 'bettershield' ),
			'login_lockout_started'   => __( 'Sign-in lockout started', 'bettershield' ),
			'surface_closed'          => __( 'Form blocked for a network after repeated failures', 'bettershield' ),
			'comment_held'            => __( 'Comment held for moderation', 'bettershield' ),
			'password_reset_throttled' => __( 'Password reset requests slowed', 'bettershield' ),
			'password_reset_unsent'   => __( 'Password reset link could not be sent', 'bettershield' ),
			'registration_refused'    => __( 'Sign-up refused', 'bettershield' ),
			// Any form's: each row names its own, see Query::label_of().
			'login_lockout_cleared'   => __( 'Lockout cleared', 'bettershield' ),
			'login_lockout_emailed'   => __( 'Lockout email sent', 'bettershield' ),
			'login_unlock_requested'  => __( 'Unlock link requested', 'bettershield' ),
			'login_blocked'           => __( 'Sign-in refused by blocklist', 'bettershield' ),
			'sessions_ended'          => __( 'Sessions signed out', 'bettershield' ),
			'honeypot_rejected'       => __( 'Automated submission refused', 'bettershield' ),
			'two_factor_enabled'      => __( 'Two-factor turned on', 'bettershield' ),
			'two_factor_disabled'     => __( 'Two-factor turned off', 'bettershield' ),
			'two_factor_failed'       => __( 'Two-factor code rejected', 'bettershield' ),
			'two_factor_skipped'      => __( 'Signed in without a two-factor code', 'bettershield' ),
			'two_factor_backup_used'  => __( 'Backup code used', 'bettershield' ),
			'two_factor_backup_reissued' => __( 'New backup codes issued', 'bettershield' ),
			'two_factor_imported'     => __( 'Two-factor brought over from another plugin', 'bettershield' ),
			'two_factor_import_failed' => __( 'Two-factor could not be brought over', 'bettershield' ),
			'two_factor_import_undone' => __( 'Two-factor brought over was undone', 'bettershield' ),
			'two_factor_moved'        => __( 'Two-factor brought over for an account', 'bettershield' ),
			'two_factor_not_moved'    => __( 'Two-factor not brought over for an account', 'bettershield' ),
			'passkey_registered'      => __( 'Passkey added', 'bettershield' ),
			'passkey_removed'         => __( 'Passkey removed', 'bettershield' ),
			'passkey_used'            => __( 'Signed in with a passkey', 'bettershield' ),
			'passkey_refused'         => __( 'Passkey refused', 'bettershield' ),
			'passkey_policy_changed'  => __( 'Passkey-only requirement changed', 'bettershield' ),
			'lockdown_entered'        => __( 'Site locked down', 'bettershield' ),
			'lockdown_left'           => __( 'Site lockdown lifted', 'bettershield' ),
			'csp_enforced'            => __( 'Content Security Policy now blocks what it does not allow', 'bettershield' ),
			'csp_report_only_restored' => __( 'Content Security Policy back to reporting only', 'bettershield' ),
			'csp_source_allowed'      => __( 'Content Security Policy now allows a new source', 'bettershield' ),
			'csp_source_removed'      => __( 'Content Security Policy no longer allows a source', 'bettershield' ),
			'csp_reports_cleared'     => __( 'Content Security Policy reports cleared', 'bettershield' ),
			'csp_reports_restored'    => __( 'Cleared content policy reports put back', 'bettershield' ),
			'outbound_refused'        => __( 'Blocked a request to the server’s private cloud settings', 'bettershield' ),
			'outbound_internal'       => __( 'Site made a request into its own server network', 'bettershield' ),
			'password_refused_passkey_only' => __( 'Password refused: this account uses a passkey', 'bettershield' ),
			'password_refused_repeated' => __( 'Password refused repeatedly: this account uses a passkey', 'bettershield' ),
			/*
			 * A password turned down as it was being chosen, and the check
			 * that could not be made. The second is its own type rather than
			 * a quieter version of the first: "we did not ask" and "we asked
			 * and it was clean" are different answers, and a log that carried
			 * only the refusals would read as a clean bill of health for
			 * every hour the service was unreachable.
			 */
			'password_refused_breached' => __( 'Password refused: it appears in a published breach', 'bettershield' ),
			'breach_check_unavailable' => __( 'Leaked-password check could not run', 'bettershield' ),
			'ability_used'            => __( 'AI assistant used an action on this site', 'bettershield' ),
			'ability_added'           => __( 'New action available to AI assistants', 'bettershield' ),
			'ability_widened'         => __( 'AI assistant action given wider access', 'bettershield' ),
			'agent_new_network'       => __( 'AI assistant connected from a new network', 'bettershield' ),
			'ability_changes_accepted' => __( 'Changes to AI assistant actions approved', 'bettershield' ),
			'ability_changes_accept_undone' => __( 'Approval of AI assistant action changes undone', 'bettershield' ),
			'agent_triage_requested'  => __( 'AI assistant asked to review files or an incident', 'bettershield' ),
			'agent_check_requested'   => __( 'AI assistant asked for a check to run', 'bettershield' ),
			/*
			 * The write ladder, in the order it happens: an agent describes a
			 * change, a person allows exactly that one, the change is made,
			 * and either it is put back or it was refused on the way. Written
			 * as statements of fact, because the severity carries whatever
			 * weight there is and a log that editorializes is a log people
			 * stop reading.
			 */
			'agent_proposal_made'     => __( 'AI assistant suggested a change for your approval', 'bettershield' ),
			'write_confirmation_minted' => __( 'You approved one AI assistant change', 'bettershield' ),
			'write_confirmation_withdrawn' => __( 'Approval for an AI assistant change withdrawn', 'bettershield' ),
			'agent_proposal_declined' => __( 'AI assistant’s suggested change declined', 'bettershield' ),
			'agent_write_applied'     => __( 'AI assistant applied an approved change', 'bettershield' ),
			/*
			 * And the same change with nobody in the loop. Its own type rather
			 * than a flag on the one above, because the label is what an
			 * activity row, a summary email and an instant alert all show: a
			 * change no person confirmed described as confirmed invites the
			 * one dismissal this distinction exists to prevent.
			 */
			'agent_write_applied_direct' => __( 'AI assistant applied a change on its own', 'bettershield' ),
			'agent_write_reverted'    => __( 'AI assistant undid a change', 'bettershield' ),
			'agent_write_refused'     => __( 'AI assistant change refused', 'bettershield' ),
			'agent_permission_denied' => __( 'AI assistant action refused', 'bettershield' ),
			'agent_refusals_repeated' => __( 'AI assistant actions refused several times', 'bettershield' ),
			'agent_capture_removed'   => __( 'Agent activity recording stopped', 'bettershield' ),
			'agent_capture_truncated' => __( 'Agent activity partly recorded', 'bettershield' ),
			/*
			 * The assistant endpoint. A credential being minted or replaced
			 * and an application being allowed are grants of access; the rows
			 * either side of them are the same access being taken back or
			 * refused at the door.
			 */
			// Issued, which is all pressing Connect does: no assistant has
			// connected until one uses it (#2073).
			'mcp_connected'           => __( 'AI assistant connection key created', 'bettershield' ),
			'mcp_rotated'             => __( 'AI assistant connection key replaced', 'bettershield' ),
			'mcp_disconnected'        => __( 'AI assistant connection ended', 'bettershield' ),
			'mcp_app_granted'         => __( 'AI assistant app allowed', 'bettershield' ),
			'mcp_app_revoked'         => __( 'AI assistant app removed', 'bettershield' ),
			'mcp_auth_refused'        => __( 'AI assistant connection key refused', 'bettershield' ),
			'mcp_locked_out'          => __( 'AI assistant connection blocked for a network after repeated failures', 'bettershield' ),
			'mcp_refresh_reused'      => __( 'AI assistant connection key reused, so it was turned off for safety', 'bettershield' ),
			'ai_explanation_generated' => __( 'AI explanation written for an incident or the audit summary', 'bettershield' ),
			'alerts_updated'          => __( 'Alert settings changed', 'bettershield' ),
			'uninstall_choice_changed' => __( 'Uninstall choice changed', 'bettershield' ),
			'maintenance_window_started' => __( 'Planned maintenance started', 'bettershield' ),
			'maintenance_window_closed' => __( 'Planned maintenance ended', 'bettershield' ),
			'alert_sent'              => __( 'Alert sent', 'bettershield' ),
			'account_notice_sent'     => __( 'Sign-in change emailed to the account holder', 'bettershield' ),
			'alert_delivery_failed'   => __( 'Alert could not be delivered', 'bettershield' ),
			'quarantine_downloaded'   => __( 'Quarantined file downloaded', 'bettershield' ),
			'quarantine_deleted'      => __( 'Quarantined file deleted', 'bettershield' ),
			'quarantine_sealed'       => __( 'Quarantine folder blocked from web access', 'bettershield' ),
			'content_links_rewritten' => __( 'Site links changed from http:// to https://', 'bettershield' ),
			'content_links_restored'  => __( 'Rewritten links put back', 'bettershield' ),
			'quarantine_seal_undone'  => __( 'Quarantine folder web block removed', 'bettershield' ),
			'folder_mode_tightened'   => __( 'Folder permissions tightened', 'bettershield' ),
			'folder_mode_restored'    => __( 'Folder permissions put back', 'bettershield' ),
			'config_mode_tightened'   => __( 'wp-config.php no longer writable by other accounts', 'bettershield' ),
			'config_mode_restored'    => __( 'wp-config.php permissions put back', 'bettershield' ),
			'plugin_update_applied'   => __( 'Plugin updated from its finding', 'bettershield' ),
			'plugin_update_undone'    => __( 'Plugin update undone, earlier version put back', 'bettershield' ),
			'extension_quarantined'   => __( 'Unused plugin or theme moved to quarantine', 'bettershield' ),
			'extension_put_back'      => __( 'Plugin or theme put back from quarantine', 'bettershield' ),
			'cron_events_removed'     => __( 'Scheduled events removed', 'bettershield' ),
			'cron_events_restored'    => __( 'Removed scheduled events put back', 'bettershield' ),
			'rest_route_watched'      => __( 'REST address watched before closing', 'bettershield' ),
			'rest_route_closed'       => __( 'REST address closed to visitors not signed in', 'bettershield' ),
			'rest_route_reopened'     => __( 'Closed REST address opened again', 'bettershield' ),
			'hardening_verified'      => __( 'Protection checked against a live page', 'bettershield' ),
			'login_new_network'       => __( 'Signed in from a new network', 'bettershield' ),
			'email_change_held'       => __( 'Email address change held for confirmation', 'bettershield' ),
			'email_change_confirmed'  => __( 'Email address change confirmed', 'bettershield' ),
			'two_factor_policy_changed' => __( 'Two-factor requirement changed', 'bettershield' ),
			// Abbreviated because the stored type is a varchar(32) and the
			// unabbreviated name is one character past it; a truncated type
			// would find no label and print its own identifier at the reader.
			'network_2fa_policy_changed' => __( 'Two-factor requirement changed for the network', 'bettershield' ),
			'network_passkey_policy_changed' => __( 'Passkey-only requirement changed for the network', 'bettershield' ),
			'security_txt_published'  => __( 'Security contact file (security.txt) published', 'bettershield' ),
			'security_txt_withdrawn'  => __( 'Disclosure contact withdrawn', 'bettershield' ),
			'session_ended_by_owner'  => __( 'Signed out of a device', 'bettershield' ),
			'session_reported_by_owner' => __( 'Account owner reported a sign-in as not theirs', 'bettershield' ),
			'sessions_reset'          => __( 'Sessions ended after a credential change', 'bettershield' ),
			'sudo_confirmed'          => __( 'Identity confirmed for a protected change', 'bettershield' ),
			'sudo_refused'            => __( 'Password confirmation failed', 'bettershield' ),
			'alert_feedback'          => __( 'Alert marked unhelpful', 'bettershield' ),
			'scan_completed'          => __( 'Audit ran', 'bettershield' ),
			'integrity_scan_completed' => __( 'File check ran', 'bettershield' ),
			/*
			 * The shorter cycle over the locations no publisher answers for —
			 * drop-ins, must-use plugins, the theme, the configuration
			 * files and the plugins the directory has no list for. Its own
			 * type rather than the one above, because a reader scanning the
			 * log needs to tell "the whole site was checked against what its
			 * publishers shipped" from "the code nobody publishes for was
			 * checked against what it was". Nothing in this plugin records it;
			 * it is named here because this registry is what the whole product
			 * records through, and a type nobody registered lands in the log
			 * as its own slug.
			 */
			'unpublished_watch_ran'   => __( 'Custom code checked for changes', 'bettershield' ),
			// Said of every kind of difference the file check records, since a
			// count of them groups added, altered and missing files together;
			// each row says which it is, see Query::label_of() (#1832).
			'file_changed'            => __( 'File change found', 'bettershield' ),
			'vulnerability_found'     => __( 'Known vulnerability affects an installed version', 'bettershield' ),
			'vulnerability_resolved'  => __( 'Known vulnerability no longer applies', 'bettershield' ),
			'vulnerability_check_failed' => __( 'Vulnerability check could not download the latest list', 'bettershield' ),
			'file_restored'           => __( 'File restored to its official version', 'bettershield' ),
			'file_restore_undone'     => __( 'File restore undone', 'bettershield' ),
			'file_quarantined'        => __( 'File moved to quarantine', 'bettershield' ),
			'leftover_tool_quarantined' => __( 'Leftover installer or debug file moved to quarantine', 'bettershield' ),
			'exposed_file_quarantined' => __( 'Downloadable file moved to quarantine', 'bettershield' ),
			'file_changes_expected'   => __( 'All file changes in a plugin accepted', 'bettershield' ),
			'file_changes_unexpected' => __( 'Accepted file changes in a plugin shown again', 'bettershield' ),
			'file_selection_expected' => __( 'Selected file changes accepted', 'bettershield' ),
			'file_package_rechecked'  => __( 'A plugin’s changed files checked again', 'bettershield' ),
			'file_change_suppressed'  => __( 'File change accepted', 'bettershield' ),
			'file_change_unsuppressed' => __( 'File change acceptance undone', 'bettershield' ),
			'file_expected'           => __( 'File recorded as expected', 'bettershield' ),
			'file_expected_undone'    => __( 'File recorded as expected, undone', 'bettershield' ),
			'finding_opened'          => __( 'Finding opened', 'bettershield' ),
			'finding_resolved'        => __( 'Finding resolved', 'bettershield' ),
			'finding_suppressed'      => __( 'Finding marked not applicable', 'bettershield' ),
			'finding_unsuppressed'    => __( 'Finding put back in the report', 'bettershield' ),
			'finding_snoozed'         => __( 'Finding snoozed', 'bettershield' ),
			'site_marked_staging'     => __( 'Site marked as a staging copy', 'bettershield' ),
			'site_marked_moved'       => __( 'Site marked as moved to a new address', 'bettershield' ),
			'site_identity_undone'    => __( 'Staging or move answer taken back', 'bettershield' ),
			'site_created'            => __( 'Site created', 'bettershield' ),
			'site_status_changed'     => __( 'Site status changed', 'bettershield' ),
			'site_deleted'            => __( 'Site deleted', 'bettershield' ),
			'finding_woken'           => __( 'Snoozed finding back in the report', 'bettershield' ),
			'safe_mode_entered'       => __( 'Safe mode started', 'bettershield' ),
			'safe_mode_exited'        => __( 'Safe mode ended', 'bettershield' ),
			'network_safe_mode_entered' => __( 'Safe mode started for the network', 'bettershield' ),
			'network_safe_mode_exited' => __( 'Safe mode ended for the network', 'bettershield' ),
			'recovery_link_generated' => __( 'Recovery link generated', 'bettershield' ),
			'recovery_link_failed'    => __( 'Recovery link rejected', 'bettershield' ),
			'recovery_preflight_overridden' => __( 'Sign-in setting changed without testing the recovery link first', 'bettershield' ),
			'activity_unusual'        => __( 'Unusual activity noticed', 'bettershield' ),
			'buffer_overflow'         => __( 'Some events not recorded during a busy period', 'bettershield' ),
			'events_sampled'          => __( 'Repeated events counted rather than listed', 'bettershield' ),
			'log_migrated'            => __( 'Activity log moved to new storage and re-checked', 'bettershield' ),
			// The daily seals taken again because this plugin changed rows
			// under them, and a reseal on record that this plugin did not
			// write, which is refused and its days checked as they stand.
			'log_resealed'            => __( 'Activity log sealed again', 'bettershield' ),
			'log_reseal_refused'      => __( 'Unexpected change to the log’s check record refused', 'bettershield' ),
			/*
			 * The migration run again because somebody asked, and the answer
			 * either way. Two types rather than one with an outcome: the
			 * failure is the one a reader scanning a week of log has to find,
			 * and a row that has to be opened to learn which of the two it was
			 * is a row that gets skipped.
			 */
			'schema_repaired'         => __( 'BetterShield database tables repaired', 'bettershield' ),
			'schema_repair_failed'    => __( 'Storage could not be repaired', 'bettershield' ),
			/*
			 * An early run somebody asked for, and how it ended: the receipt that the
			 * work they asked for happened, or did not.
			 */
			'task_run_requested'      => __( 'Scheduled task run on request', 'bettershield' ),
			'task_run_finished'       => __( 'Scheduled task run on request finished', 'bettershield' ),
			'task_run_failed'         => __( 'Scheduled task run on request did not finish', 'bettershield' ),
		);

		// Another plugin's types after this plugin's own, which win where a
		// slug is named twice: a registration cannot rename what is already
		// in the record under a name.
		foreach ( self::registered() as $type => $registration ) {
			if ( ! isset( $labels[ $type ] ) ) {
				$labels[ $type ] = $registration['label'];
			}
		}

		/*
		 * Not held before `init`. Translations load on first use from there on,
		 * so a map built earlier would be in the wrong language for the whole
		 * request rather than for one call. Nothing reads this that early; the
		 * guard is so that a reader added later cannot silently untranslate a
		 * screen.
		 */
		if ( ! did_action( 'init' ) ) {
			return $labels;
		}

		// One process can render this map in more than one language: the digest
		// switches locale per recipient before writing to them. `change_locale`
		// covers a restore as well as a switch.
		add_action( 'switch_locale', array( self::class, 'forget_labels' ) );
		add_action( 'change_locale', array( self::class, 'forget_labels' ) );

		self::$labels = $labels;

		return $labels;
	}

	/**
	 * Drop the built map, so the next reader gets it in the language in force
	 * by then. Public because it is a hook callback.
	 */
	public static function forget_labels(): void {
		self::$labels     = null;
		self::$registered = null;
	}

	/**
	 * The event types other plugins record through this log.
	 *
	 * A type this registry does not name lands in the log as its own slug,
	 * belongs to no area, and so is missing from every filtered view and from
	 * every destination that asked for a class. A plugin recording its own
	 * activity through `Writer::record()` names its types here instead.
	 *
	 * Each registration is checked rather than trusted: the slug is what the
	 * log stores, so it is lowercase letters, digits and underscores and fits
	 * the column; the label is plain text; the area is one of the areas this
	 * plugin already has, because the set is closed and a filter offering an
	 * area nothing else knows would be a chip nobody can explain. One that
	 * fails any of those is left out, and a slug this plugin already names
	 * keeps this plugin's name and area.
	 *
	 * Asked once and held from `init` on, for the reason the label map is:
	 * the labels are translated, and a map built before translations load is
	 * in the wrong language for the rest of the request.
	 *
	 * @return array<string, array{label: string, area: string}>
	 */
	public static function registered(): array {
		if ( null !== self::$registered ) {
			return self::$registered;
		}

		/**
		 * Filters the event types other plugins record through this plugin's
		 * activity log.
		 *
		 * Add each type as `slug => array( 'label' => ..., 'area' => ... )`:
		 *
		 * - `slug`: lowercase letters, digits and underscores, at most 32
		 *   characters — the column the log stores it in. Pass the same
		 *   string to `Writer::record()`.
		 * - `label`: what happened, in the past tense, translated in your own
		 *   text domain. Plain text.
		 * - `area`: one of `access`, `exposure`, `server`, `configuration`,
		 *   `extensions`. (`plugin` is this plugin's own doing.)
		 *
		 * A slug this plugin already uses keeps its own name and area. Add the
		 * filter when your plugin loads: the map is read when first needed and
		 * held for the rest of the request, so a type added later in the
		 * request is seen from the next one. Once a type has been recorded its
		 * slug and area are part of the record, so treat both as permanent.
		 *
		 * @param array<string, array{label: string, area: string}> $types Types registered so far.
		 */
		$raw = apply_filters( 'bettershield_event_types', array() );
		$out = array();

		foreach ( is_array( $raw ) ? $raw : array() as $slug => $registration ) {
			$slug = is_string( $slug ) ? $slug : '';

			if ( 1 !== preg_match( '/^[a-z][a-z0-9_]*$/', $slug ) || strlen( $slug ) > self::MAX_SLUG || ! is_array( $registration ) ) {
				continue;
			}

			$label = is_string( $registration['label'] ?? null ) ? trim( wp_strip_all_tags( $registration['label'] ) ) : '';
			$area  = is_string( $registration['area'] ?? null ) ? $registration['area'] : '';

			if ( '' === $label || ! in_array( $area, self::AREAS, true ) ) {
				continue;
			}

			$out[ $slug ] = array(
				'label' => $label,
				'area'  => $area,
			);
		}

		if ( did_action( 'init' ) ) {
			self::$registered = $out;
		}

		return $out;
	}

	/**
	 * The areas another plugin's event may be filed under: every area but this
	 * plugin's own, which says the row is BetterShield's own doing and is not
	 * a claim another plugin may make. Written out rather than read from
	 * `Areas::all()`, which is translated and so not for before `init`.
	 */
	private const AREAS = array( Areas::ACCESS, Areas::EXPOSURE, Areas::SERVER, Areas::CONFIGURATION, Areas::EXTENSIONS );

	/**
	 * The stored identifier is the fallback, never a blank or a guess: an event
	 * this build does not have a name for is still an event that happened.
	 */
	public static function label( string $type ): string {
		$labels = self::labels();

		return $labels[ $type ] ?? $type;
	}

	/**
	 * Which area of the site each event is about.
	 *
	 * The same vocabulary the audit uses, so Access means one thing across the
	 * plugin. Two areas an audit produces — exposure and server — have no
	 * events, and one only events produce: this plugin's own actions, which an
	 * audit has no business reporting on.
	 *
	 * @return array<string, string>
	 */
	public static function areas(): array {
		$areas = array(
			'login'                   => Areas::ACCESS,
			'login_failed'            => Areas::ACCESS,
			'logout'                  => Areas::ACCESS,
			'user_created'            => Areas::ACCESS,
			'user_deleted'            => Areas::ACCESS,
			'user_removed_from_site'  => Areas::ACCESS,
			'user_role_changed'       => Areas::ACCESS,
			'user_role_granted'       => Areas::ACCESS,
			'user_role_revoked'       => Areas::ACCESS,
			'temporary_access_end_refused' => Areas::ACCESS,
			'account_suspended'       => Areas::ACCESS,
			'account_suspension_lifted' => Areas::ACCESS,
			'handover_completed'      => Areas::ACCESS,
			'role_capabilities_changed' => Areas::ACCESS,
			'user_email_changed'      => Areas::ACCESS,
			'username_changed'        => Areas::ACCESS,
			'password_changed'        => Areas::ACCESS,
			'password_reset_requested' => Areas::ACCESS,
			'app_password_created'    => Areas::ACCESS,
			'app_password_limited'    => Areas::ACCESS,
			'app_password_unlimited'  => Areas::ACCESS,
			'app_password_refused'    => Areas::ACCESS,
			'account_takeover_sequence' => Areas::ACCESS,
			'app_password_revoked'    => Areas::ACCESS,
			'app_password_used'       => Areas::ACCESS,
			'xmlrpc_used'             => Areas::EXPOSURE,
			'canary_used'             => Areas::ACCESS,
			'canary_page_touched' => Areas::ACCESS,
			'incident_code_added' => Areas::EXPOSURE,
			'incident_code_modified' => Areas::EXPOSURE,
			// BetterShield's own incident record, not a site setting (#2616).
			'incident_response_applied' => Areas::PLUGIN,
			'observed_change_response' => Areas::CONFIGURATION,
			'incident_cron_unanswered' => Areas::EXPOSURE,
			'incident_account_demoted' => Areas::ACCESS,
			'incident_cron_unscheduled' => Areas::EXPOSURE,
			'incident_password_held' => Areas::ACCESS,
			'password_hold_lifted' => Areas::ACCESS,
			'update_code_changed' => Areas::EXTENSIONS,
			'incident_status_changed' => Areas::PLUGIN,
			'incident_opened'         => Areas::PLUGIN,
			'dormant_privileged_login' => Areas::ACCESS,
			'canary_page_changed' => Areas::CONFIGURATION,
			'canary_page_tested' => Areas::CONFIGURATION,
			'canary_disarmed'         => Areas::ACCESS,

			'plugin_activated'        => Areas::EXTENSIONS,
			'plugin_deactivated'      => Areas::EXTENSIONS,
			'plugin_installed'        => Areas::EXTENSIONS,
			'plugin_updated'          => Areas::EXTENSIONS,
			'package_unverified'      => Areas::EXTENSIONS,
			'package_partly_checked'  => Areas::EXTENSIONS,
			'package_adopted'         => Areas::EXTENSIONS,
			'package_adoption_undone' => Areas::EXTENSIONS,
			'plugin_deleted'          => Areas::EXTENSIONS,
			'response_taken'          => Areas::EXTENSIONS,
			'response_undone'         => Areas::EXTENSIONS,
			'response_rolled_back'    => Areas::EXTENSIONS,
			'cloudflare_action_taken' => Areas::EXPOSURE,
			'cloudflare_action_undone' => Areas::EXPOSURE,
			'cloudflare_block_refused' => Areas::EXPOSURE,
			'turnstile_refused'       => Areas::ACCESS,
			'turnstile_unreachable'   => Areas::ACCESS,
			'cloudflare_block_failed'  => Areas::EXPOSURE,
			'theme_changed'           => Areas::EXTENSIONS,
			'theme_installed'         => Areas::EXTENSIONS,
			'theme_updated'           => Areas::EXTENSIONS,
			'theme_deleted'           => Areas::EXTENSIONS,
			'theme_plugin_file_edited' => Areas::EXTENSIONS,
			'core_updated'            => Areas::EXTENSIONS,

			'setting_changed'         => Areas::CONFIGURATION,
			'site_setting_changed'    => Areas::CONFIGURATION,
			'takeover_setting_refused' => Areas::CONFIGURATION,
			'first_run_completed'     => Areas::PLUGIN,
			'quick_setup_completed'   => Areas::PLUGIN,
			'quick_setup_skipped'     => Areas::PLUGIN,
			'coexistence_choices_saved' => Areas::PLUGIN,
			'recovery_receipt_confirmed' => Areas::ACCESS,
			'recovery_receipt_withdrawn' => Areas::ACCESS,
			'usage_tracking_enabled'  => Areas::PLUGIN,
			'usage_tracking_disabled' => Areas::PLUGIN,
			'hub_link_enabled'        => Areas::PLUGIN,
			'hub_link_disabled'       => Areas::PLUGIN,
			'settings_exported'       => Areas::PLUGIN,
			'settings_imported'       => Areas::PLUGIN,

			'scan_completed'          => Areas::PLUGIN,
			'integrity_scan_completed' => Areas::PLUGIN,
			// The check running is a fact about this plugin's own work, the
			// same as the run above; what it finds is filed under the code it
			// found it in, by `file_changed`.
			'unpublished_watch_ran'   => Areas::PLUGIN,
			// A file that no longer matches what shipped is a fact about the
			// code on the site, which is the area that covers where code came
			// from and whether it is what it claims to be.
			'file_changed'            => Areas::EXTENSIONS,
			'vulnerability_found'     => Areas::EXTENSIONS,
			'vulnerability_resolved'  => Areas::EXTENSIONS,
			'vulnerability_check_failed' => Areas::PLUGIN,
			'file_restored'           => Areas::EXTENSIONS,
			'file_restore_undone'     => Areas::EXTENSIONS,
			'file_quarantined'        => Areas::EXTENSIONS,
			'leftover_tool_quarantined' => Areas::EXPOSURE,
			'exposed_file_quarantined' => Areas::EXPOSURE,
			'file_changes_expected'   => Areas::EXTENSIONS,
			'file_changes_unexpected' => Areas::EXTENSIONS,
			'file_selection_expected' => Areas::EXTENSIONS,
			'file_package_rechecked'  => Areas::EXTENSIONS,
			'file_change_suppressed'  => Areas::PLUGIN,
			'file_change_unsuppressed' => Areas::PLUGIN,
			'file_expected'           => Areas::PLUGIN,
			'file_expected_undone'    => Areas::PLUGIN,
			'finding_opened'          => Areas::PLUGIN,
			'finding_resolved'        => Areas::PLUGIN,
			'finding_suppressed'      => Areas::PLUGIN,
			'finding_unsuppressed'    => Areas::PLUGIN,
			'finding_snoozed'         => Areas::PLUGIN,
			'site_marked_staging'     => Areas::PLUGIN,
			'site_marked_moved'       => Areas::PLUGIN,
			'site_identity_undone'    => Areas::PLUGIN,
			'site_created'            => Areas::CONFIGURATION,
			'site_status_changed'     => Areas::CONFIGURATION,
			'site_deleted'            => Areas::CONFIGURATION,
			'finding_woken'           => Areas::PLUGIN,
			'hardening_applied'       => Areas::PLUGIN,
			'hardening_reverted'      => Areas::PLUGIN,
			'hardening_failed'        => Areas::PLUGIN,
			'hardening_revert_failed' => Areas::PLUGIN,
			'keys_rotated'            => Areas::ACCESS,
			'password_policy_updated' => Areas::ACCESS,
			'login_protection_updated' => Areas::ACCESS,
			'login_lockout_started'   => Areas::ACCESS,
			'surface_closed'          => Areas::ACCESS,
			'comment_held'            => Areas::ACCESS,
			'password_reset_throttled' => Areas::ACCESS,
			'password_reset_unsent'   => Areas::ACCESS,
			'registration_refused'    => Areas::ACCESS,
			'login_lockout_cleared'   => Areas::ACCESS,
			'login_lockout_emailed'   => Areas::ACCESS,
			'login_unlock_requested'  => Areas::ACCESS,
			'login_blocked'           => Areas::ACCESS,
			'sessions_ended'          => Areas::ACCESS,
			'honeypot_rejected'       => Areas::ACCESS,
			'two_factor_enabled'      => Areas::ACCESS,
			'two_factor_disabled'     => Areas::ACCESS,
			'two_factor_skipped'      => Areas::ACCESS,
			'two_factor_failed'       => Areas::ACCESS,
			'two_factor_backup_used'  => Areas::ACCESS,
			'two_factor_backup_reissued' => Areas::ACCESS,
			'two_factor_imported'     => Areas::ACCESS,
			'two_factor_import_failed' => Areas::ACCESS,
			'two_factor_import_undone' => Areas::ACCESS,
			'two_factor_moved'        => Areas::ACCESS,
			'two_factor_not_moved'    => Areas::ACCESS,
			'passkey_registered'      => Areas::ACCESS,
			'passkey_removed'         => Areas::ACCESS,
			'passkey_used'            => Areas::ACCESS,
			'passkey_refused'         => Areas::ACCESS,
			'passkey_policy_changed'  => Areas::ACCESS,
			'lockdown_entered'        => Areas::PLUGIN,
			'lockdown_left'           => Areas::PLUGIN,
			'csp_enforced'            => Areas::EXPOSURE,
			'csp_report_only_restored' => Areas::EXPOSURE,
			'csp_source_allowed'      => Areas::EXPOSURE,
			'csp_source_removed'      => Areas::EXPOSURE,
			'csp_reports_cleared'     => Areas::EXPOSURE,
			'csp_reports_restored'    => Areas::EXPOSURE,
			'outbound_refused'        => Areas::EXPOSURE,
			'outbound_internal'       => Areas::EXPOSURE,
			'password_refused_passkey_only' => Areas::ACCESS,
			'password_refused_repeated' => Areas::ACCESS,
			'password_refused_breached' => Areas::ACCESS,
			// The check failing is a fact about this plugin's own work, in the
			// same way a scan that could not reach its data is.
			'breach_check_unavailable' => Areas::PLUGIN,
			'ability_used'            => Areas::PLUGIN,
			'ability_added'           => Areas::EXPOSURE,
			'ability_widened'         => Areas::EXPOSURE,
			'agent_new_network'       => Areas::ACCESS,
			'ability_changes_accepted' => Areas::EXPOSURE,
			'ability_changes_accept_undone' => Areas::EXPOSURE,
			'agent_check_requested'   => Areas::PLUGIN,
			'agent_triage_requested'  => Areas::PLUGIN,
			'agent_proposal_made'     => Areas::PLUGIN,
			'write_confirmation_minted' => Areas::PLUGIN,
			'write_confirmation_withdrawn' => Areas::PLUGIN,
			'agent_proposal_declined' => Areas::PLUGIN,
			'agent_write_applied'     => Areas::PLUGIN,
			'agent_write_applied_direct' => Areas::PLUGIN,
			'agent_write_reverted'    => Areas::PLUGIN,
			'agent_write_refused'     => Areas::PLUGIN,
			'agent_permission_denied' => Areas::PLUGIN,
			'agent_refusals_repeated' => Areas::PLUGIN,
			'agent_capture_removed'   => Areas::PLUGIN,
			'agent_capture_truncated' => Areas::PLUGIN,
			'mcp_connected'           => Areas::PLUGIN,
			'mcp_rotated'             => Areas::PLUGIN,
			'mcp_disconnected'        => Areas::PLUGIN,
			'mcp_app_granted'         => Areas::PLUGIN,
			'mcp_app_revoked'         => Areas::PLUGIN,
			'mcp_auth_refused'        => Areas::PLUGIN,
			'mcp_locked_out'          => Areas::PLUGIN,
			'mcp_refresh_reused'      => Areas::PLUGIN,
			'ai_explanation_generated' => Areas::PLUGIN,
			'alerts_updated'          => Areas::PLUGIN,
			'uninstall_choice_changed' => Areas::PLUGIN,
			'maintenance_window_started' => Areas::CONFIGURATION,
			'maintenance_window_closed' => Areas::CONFIGURATION,
			'alert_sent'              => Areas::PLUGIN,
			'account_notice_sent'     => Areas::PLUGIN,
			'alert_delivery_failed'   => Areas::PLUGIN,
			'quarantine_downloaded'   => Areas::EXTENSIONS,
			'quarantine_deleted'      => Areas::EXTENSIONS,
			'quarantine_sealed'       => Areas::EXTENSIONS,
			'content_links_rewritten' => Areas::EXPOSURE,
			'content_links_restored'  => Areas::EXPOSURE,
			'quarantine_seal_undone'  => Areas::EXTENSIONS,
			'folder_mode_tightened'   => Areas::CONFIGURATION,
			'folder_mode_restored'    => Areas::CONFIGURATION,
			'config_mode_tightened'   => Areas::CONFIGURATION,
			'config_mode_restored'    => Areas::CONFIGURATION,
			'plugin_update_applied'   => Areas::EXTENSIONS,
			'plugin_update_undone'    => Areas::EXTENSIONS,
			'extension_quarantined'   => Areas::EXTENSIONS,
			'extension_put_back'      => Areas::EXTENSIONS,
			'cron_events_removed'     => Areas::EXPOSURE,
			'cron_events_restored'    => Areas::EXPOSURE,
			'rest_route_watched'      => Areas::EXPOSURE,
			'rest_route_closed'       => Areas::EXPOSURE,
			'rest_route_reopened'     => Areas::EXPOSURE,
			'hardening_verified'      => Areas::PLUGIN,
			'login_new_network'       => Areas::ACCESS,
			'email_change_held'       => Areas::ACCESS,
			'email_change_confirmed'  => Areas::ACCESS,
			'two_factor_policy_changed' => Areas::ACCESS,
			'network_2fa_policy_changed' => Areas::ACCESS,
			'network_passkey_policy_changed' => Areas::ACCESS,
			'security_txt_published'  => Areas::EXPOSURE,
			'security_txt_withdrawn'  => Areas::EXPOSURE,
			'session_ended_by_owner'  => Areas::ACCESS,
			'session_reported_by_owner' => Areas::ACCESS,
			'sessions_reset'          => Areas::ACCESS,
			'sudo_confirmed'          => Areas::ACCESS,
			'sudo_refused'            => Areas::ACCESS,
			'alert_feedback'          => Areas::PLUGIN,
			'safe_mode_entered'       => Areas::PLUGIN,
			'safe_mode_exited'        => Areas::PLUGIN,
			'network_safe_mode_entered' => Areas::PLUGIN,
			'network_safe_mode_exited' => Areas::PLUGIN,
			'recovery_link_generated' => Areas::PLUGIN,
			'recovery_link_failed'    => Areas::PLUGIN,
			'recovery_preflight_overridden' => Areas::PLUGIN,
			'activity_unusual'        => Areas::PLUGIN,
			'buffer_overflow'         => Areas::PLUGIN,
			'events_sampled'          => Areas::PLUGIN,
			'log_migrated'            => Areas::PLUGIN,
			'log_resealed'            => Areas::PLUGIN,
			'log_reseal_refused'      => Areas::PLUGIN,
			'schema_repaired'         => Areas::PLUGIN,
			'schema_repair_failed'    => Areas::PLUGIN,
			'task_run_requested'      => Areas::PLUGIN,
			'task_run_finished'       => Areas::PLUGIN,
			'task_run_failed'         => Areas::PLUGIN,
		);

		// Another plugin's types, filed where it said; this plugin's own win.
		foreach ( self::registered() as $type => $registration ) {
			if ( ! isset( $areas[ $type ] ) ) {
				$areas[ $type ] = $registration['area'];
			}
		}

		return $areas;
	}

	/**
	 * The event types belonging to one area, which is what a filter turns into
	 * a WHERE clause.
	 *
	 * @return string[]
	 */
	public static function in_area( string $area ): array {
		return array_keys( array_filter( self::areas(), static function ( string $slug ) use ( $area ): bool {
			return $slug === $area;
		} ) );
	}
}
