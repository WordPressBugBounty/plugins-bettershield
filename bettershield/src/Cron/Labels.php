<?php
/**
 * What each scheduled task is called where a person reads it.
 *
 * A hook is an identifier and a schedule screen is read by somebody asking
 * "what does this site do on its own, and when" — so each task this plugin
 * schedules has a name here, in one place, the way event types have theirs in
 * `Events\Types`. An add-on names its own through `bettershield_task_labels`.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Cron;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Labels {

	/**
	 * Every task this plugin schedules, named. Translated, so not before
	 * `init`; a schedule screen is read long after.
	 *
	 * @return array<string, string>
	 */
	public static function all(): array {
		$labels = array(
			'bettershield_daily_audit'               => __( 'Security audit', 'bettershield' ),
			'bettershield_integrity_scan'            => __( 'File check', 'bettershield' ),
			'bettershield_vulnerability_check'       => __( 'Vulnerability check', 'bettershield' ),
			'bettershield_ability_review'            => __( 'Check AI assistant permissions', 'bettershield' ),
			'bettershield_certificate_check'         => __( 'Certificate check', 'bettershield' ),
			'bettershield_digest'                    => __( 'Weekly summary', 'bettershield' ),
			'bettershield_alerts_dispatch'           => __( 'Grouped alerts sent', 'bettershield' ),
			'bettershield_maintenance_retry'         => __( 'Maintenance period summary email', 'bettershield' ),
			'bettershield_maintenance_close'         => __( 'Maintenance period ending', 'bettershield' ),
			'bettershield_maintenance_open'          => __( 'Booked maintenance period starting', 'bettershield' ),
			'bettershield_seal_log'                  => __( 'Daily log fingerprint', 'bettershield' ),
			'bettershield_unusual_check'             => __( 'Unusual activity check', 'bettershield' ),
			'bettershield_incident_tick'             => __( 'Group related events into incidents', 'bettershield' ),
			'bettershield_incidents_refresh'         => __( 'Update open incidents', 'bettershield' ),
			'bettershield_incidents_prune'           => __( 'Remove old incidents', 'bettershield' ),
			'bettershield_hardening_monitor_review'  => __( 'Check applied fixes still work', 'bettershield' ),
			'bettershield_recovery_readiness'        => __( 'Recovery readiness check', 'bettershield' ),
			'bettershield_account_notice'            => __( 'Sign-in change email to an account holder', 'bettershield' ),
			'bettershield_two_factor_reminders'      => __( 'Two-factor deadline reminders', 'bettershield' ),
			'bettershield_recheck_landed_plugin'     => __( 'Installed plugin files checked again', 'bettershield' ),
			'bettershield_guard_top_up'              => __( 'Restore folder protection files', 'bettershield' ),
			'bettershield_app_password_sweep'        => __( 'Remove unused app passwords', 'bettershield' ),
			'bettershield_artifact_probe'            => __( 'Leftover files check', 'bettershield' ),
			'bettershield_cross_origin_probe'        => __( 'Cross-site access check', 'bettershield' ),
			'bettershield_xmlrpc_probe'              => __( 'XML-RPC check', 'bettershield' ),
			'bettershield_folder_listing_probe'      => __( 'Folder listing check', 'bettershield' ),
			'bettershield_csp_reach'                 => __( 'Browser security policy check', 'bettershield' ),
			'bettershield_sign_in_cache_probe'       => __( 'Sign-in page caching check', 'bettershield' ),
			'bettershield_domain_records'            => __( 'Domain records check', 'bettershield' ),
			'bettershield_mixed_content'             => __( 'Mixed content check', 'bettershield' ),
			'bettershield_rest_surface'              => __( 'REST API exposure check', 'bettershield' ),
			'bettershield_server_headers'            => __( 'Server headers check', 'bettershield' ),
			'bettershield_store_scripts'             => __( 'Store scripts check', 'bettershield' ),
			'bettershield_directory_status'          => __( 'WordPress.org plugin and theme status check', 'bettershield' ),
			'bettershield_prune_events'              => __( 'Remove old activity', 'bettershield' ),
			'bettershield_prune_agent_invocations'   => __( 'Remove old AI assistant activity', 'bettershield' ),
			'bettershield_prune_login_data'          => __( 'Remove old sign-in records', 'bettershield' ),
			'bettershield_prune_write_proposals'     => __( 'Remove expired AI change requests', 'bettershield' ),
			'bettershield_prune_integrity_changes'   => __( 'Remove old file changes', 'bettershield' ),
			'bettershield_prune_claims'              => __( 'Clean up stuck tasks', 'bettershield' ),
			'bettershield_usage_report'              => __( 'Usage report (sent only if you allowed it)', 'bettershield' ),
			'bettershield_hub_link_send'             => __( 'Send updates to BetterShield Hub', 'bettershield' ),
			'bettershield_network_migration'         => __( 'Network database update', 'bettershield' ),
		);

		/**
		 * Names an add-on's scheduled tasks, by hook.
		 *
		 * A hook this plugin already names keeps its name.
		 *
		 * @param array<string, string> $extra Task hook => what it is called.
		 */
		$extra = apply_filters( 'bettershield_task_labels', array() );

		foreach ( is_array( $extra ) ? $extra : array() as $hook => $label ) {
			if ( is_string( $hook ) && is_string( $label ) && '' !== trim( $label ) && ! isset( $labels[ $hook ] ) ) {
				$labels[ $hook ] = wp_strip_all_tags( $label );
			}
		}

		return $labels;
	}
}
