<?php
/**
 * Uninstall: keep everything, unless the owner said otherwise beforehand.
 *
 * By default, deleting this plugin removes none of its data. The activity
 * log is a record of what happened to the site, the undo ledger is what
 * makes past changes reversible, and people uninstall for many reasons —
 * a conflict hunt, a migration, a trial — none of which should quietly
 * destroy a security record.
 *
 * The exception is a choice the owner made while the plugin still had a
 * screen to ask on: the "when this plugin is deleted" setting, which answers
 * keep, remove, or package the quarantined copies and then remove. This
 * script cannot ask anyone anything — it runs after the plugin is already
 * gone from the interface — so it only honors the answer that was stored in
 * advance.
 *
 * Self-contained by design: nothing here depends on the plugin having
 * booted, so table names and option lists are written out literally, and a
 * test asserts they match the plugin. The one thing borrowed from the plugin
 * is its own file-revert code, loaded on purpose while the files are still
 * on disk, because rules left in .htaccess with their undo records dropped
 * would outlive every way of removing them — and, for the third answer, its
 * quarantine code, which needs the same ledger to name the copies it packages.
 *
 * @package BetterShield
 */

// Direct access serves nothing; WordPress defines this constant when it
// runs the file as part of deleting the plugin.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/*
 * Stop the buffered writers flushing at shutdown. Deletion runs inside a live
 * request: the plugin booted and registered that flush, and its files are
 * removed a moment later — so shutdown would fire against classes the
 * autoloader can no longer find, ending a documented workflow
 * (`wp plugin uninstall --deactivate`) in a fatal after the uninstall itself
 * had succeeded. Guarded by class_exists because this script is deliberately
 * self-contained and must run whether or not the plugin booted.
 *
 * What the request already recorded is written first, while the files are
 * still here. That workflow switches the plugin off in this same request, and
 * dropping the buffer dropped the record of the switch-off and the alert it
 * sends: the last thing this plugin can say before it is gone.
 */
if ( class_exists( '\\BetterShield\\Agents\\InvocationWriter' ) ) {
	\BetterShield\Agents\InvocationWriter::instance()->stand_down();
}
if ( class_exists( '\\BetterShield\\Events\\Writer' ) ) {
	try {
		\BetterShield\Events\Writer::instance()->flush();
	} catch ( \Throwable $bettershield_unwritten ) {
		// A row that cannot be written is no reason for the deletion to stop.
		unset( $bettershield_unwritten );
	}
	\BetterShield\Events\Writer::instance()->stand_down();
}

if ( ! function_exists( 'bettershield_uninstall_opted_in' ) ) {
	/**
	 * Whether a site of this network asked for its data to go.
	 *
	 * A site's answer is written down before its own sweep deletes the option
	 * that holds it, so a site walked later still learns what one walked
	 * earlier said.
	 *
	 * @param int       $blog_id The site.
	 * @param bool|null $answer  This site's own answer, to remember; null to ask.
	 */
	function bettershield_uninstall_opted_in( int $blog_id, ?bool $answer = null ): bool {
		static $answers = array();

		if ( null !== $answer ) {
			$answers[ $blog_id ] = $answer;
		}

		if ( ! isset( $answers[ $blog_id ] ) ) {
			$choice = (string) get_blog_option( $blog_id, 'bettershield_remove_data_on_uninstall' );

			$answers[ $blog_id ] = '1' === $choice || 'package' === $choice;
		}

		return $answers[ $blog_id ];
	}
}

if ( ! function_exists( 'bettershield_uninstall_site' ) ) {
	/**
	 * Remove this plugin's data from the current site: tables, options,
	 * transients, capabilities, and per-user flags.
	 *
	 * Declared conditionally so the test suite can run this file more than
	 * once in a process; WordPress itself runs it exactly once.
	 *
	 * @return bool Whether this site had opted in. The network block below
	 *              needs to know: four tables are shared, and they may only be
	 *              dropped where every site asked for its data to go.
	 */
	function bettershield_uninstall_site(): bool {
		global $wpdb;

		/*
		 * Every scheduled event of this plugin, kept data or not: a task that
		 * fires into a plugin that is gone runs nothing. Deactivation clears
		 * them, but deleting without deactivating (`wp plugin delete`) skips
		 * it, and a list of names here fell behind the tasks the plugin
		 * schedules. So the schedule itself is read, by the prefix every one
		 * of them carries, and each hook goes with all of its events, those
		 * scheduled with arguments included. The add-on's own are left: it is
		 * a separate plugin and clears them itself.
		 */
		foreach ( (array) _get_cron_array() as $bettershield_events ) {
			foreach ( array_keys( (array) $bettershield_events ) as $bettershield_hook ) {
				$bettershield_hook = (string) $bettershield_hook;

				if ( 0 === strpos( $bettershield_hook, 'bettershield_' ) && 0 !== strpos( $bettershield_hook, 'bettershield_ultra_' ) ) {
					wp_unschedule_hook( $bettershield_hook );
				}
			}
		}

		/*
		 * The rewrite rules that served the assistant endpoint. Before the
		 * opt-in check and not inside it: a stored rule routing a URL into a
		 * plugin that is being deleted is not data the owner asked to keep, it
		 * is a path to nothing.
		 *
		 * Emptied rather than flushed. On a network this function runs once
		 * per site, inside a blog switch, and a switch swaps the database
		 * handle and the object cache and nothing else: `$wp_rewrite` still
		 * holds the permalink structure and the rules of whichever site was
		 * current when it was built, so a flush here writes that site's table
		 * over every other site's. An empty row is the one WordPress
		 * regenerates from the site's own structure on its next request, which
		 * is exactly what is wanted and is correct on single site too.
		 */
		delete_option( 'rewrite_rules' );

		/*
		 * Only when the owner opted in, on this specific site. Two of the three
		 * answers remove; written out literally here, as every other name in
		 * this file is, because the class that stores them may not be loadable
		 * by the time this runs. `1` is what the answer was stored as when it
		 * was a toggle, and still means remove.
		 */
		$bettershield_choice = (string) get_option( 'bettershield_remove_data_on_uninstall' );

		if ( is_multisite() ) {
			bettershield_uninstall_opted_in( (int) get_current_blog_id(), '1' === $bettershield_choice || 'package' === $bettershield_choice );
		}

		if ( '1' !== $bettershield_choice && 'package' !== $bettershield_choice ) {
			return false;
		}

		// Files first, while the undo records that describe them still exist.
		// The plugin's own files are still on disk at this point — WordPress
		// runs this script before deleting them — so its own revert code is
		// the right tool: every marked block and every guard file this site's
		// hardening placed comes out through the same path a click would use.
		// If anything cannot be put back, its undo record and the item's state
		// are KEPT rather than dropped: a rule left in a file with no record
		// of it would outlive every way of removing it.
		$keep_undo = false;
		if ( is_file( __DIR__ . '/src/Autoloader.php' ) && ! class_exists( 'BetterShield\\Autoloader' ) ) {
			require_once __DIR__ . '/src/Autoloader.php';
			BetterShield\Autoloader::register();
		}
		if ( class_exists( 'BetterShield\\Hardening\\Manager' ) ) {
			try {
				$manager = BetterShield\Hardening\Manager::instance();
				foreach ( BetterShield\Hardening\Items::ids() as $item ) {
					if ( $manager->is_active( $item ) && is_wp_error( $manager->revert( $item ) ) ) {
						$keep_undo = true;
					}
				}
			} catch ( \Throwable $e ) {
				$keep_undo = true;
			}
		}

		/*
		 * The third answer: hand the quarantined copies back before the folder
		 * goes. It runs here, after the revert and before the tables are
		 * dropped, because the ledger is what knows where each copy came from
		 * — and an archive of files named only by their quarantine names is an
		 * archive nobody can read.
		 *
		 * The folder is removed only when an archive was actually written. If
		 * packaging fails for any reason the copies stay exactly where they
		 * are: "quarantine, never delete" is not conditional on the rest of
		 * this routine succeeding, and a displaced file may be the only
		 * remaining copy of what was put on the site.
		 */
		if ( 'package' === $bettershield_choice ) {
			bettershield_uninstall_hand_back_quarantine();
		}

		$tables = array( 'events', 'findings', 'login_attempts', 'lockouts', 'integrity_baseline', 'integrity_changes', 'passkeys', 'claims', 'agent_invocations', 'incidents', 'incident_evidence', 'write_proposals' );
		if ( ! $keep_undo ) {
			$tables[] = 'undo';
		}

		/*
		 * Four of these live once per network at the base prefix. This site
		 * owns its rows in them and nothing else, so it takes its rows and
		 * leaves the tables standing: dropping one here would take every other
		 * site's log with it, including sites whose owners answered no. The
		 * network block at the foot of this file drops them, and only where
		 * every site asked.
		 *
		 * Everything at this site's own prefix goes, network table names
		 * included: a subsite part-way through the move still holds its own
		 * copy of the rows it has not carried over yet.
		 */
		$shared = array( 'events', 'findings', 'agent_invocations', 'passkeys' );

		foreach ( $tables as $table ) {
			$own = $wpdb->prefix . 'bettershield_' . $table;

			if ( is_multisite() && in_array( $table, $shared, true ) && $own === $wpdb->base_prefix . 'bettershield_' . $table ) {
				continue;
			}

			$wpdb->query( 'DROP TABLE IF EXISTS `' . $own . '`' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- literal plugin-owned table names, built from the table prefix and a fixed list above; the owner opted into removal.
		}

		if ( is_multisite() ) {
			/*
			 * This site's rows in the shared tables. The main site's rows from
			 * before its log became the network's carry `0` rather than its id
			 * and are its own, so it names both; every other site names one.
			 */
			$bettershield_own_rows = array( (int) get_current_blog_id() );

			if ( is_main_site() ) {
				$bettershield_own_rows[] = 0;
			}

			$bettershield_in = implode( ', ', array_map( 'intval', $bettershield_own_rows ) );

			foreach ( $shared as $table ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- a literal plugin-owned table name and a list of integers; the owner opted into removal.
				$wpdb->query( 'DELETE FROM `' . $wpdb->base_prefix . 'bettershield_' . $table . '` WHERE site_id IN (' . $bettershield_in . ')' );
			}
		}

		$options = array(
			'bettershield_abilities_enabled',
			'bettershield_abilities_write_enabled',
			// The assistant endpoint: the switch, the pairing record, and the
			// applications that were allowed to connect. The rewrite rules
			// that served it are rebuilt below, outside this list, because a
			// URL this plugin no longer answers must stop being routed to it
			// whether or not the owner opted into removing data.
			'bettershield_mcp_enabled',
			'bettershield_mcp_tools_seen',
			'bettershield_mcp_pairing',
			'bettershield_mcp_oauth',
			'bettershield_mcp_app_tools',
			'bettershield_mcp_write_generation',
			// The optional hub: the address older versions saved, and any
			// connect tickets still outstanding.
			'bettershield_hub',
			'bettershield_hub_tickets',
			// The Hub link: the owner's choice, its secret key, its place in
			// the log and the flag a visitor's request leaves for it.
			'bettershield_hub_link',
			'bettershield_hub_link_key',
			'bettershield_hub_link_state',
			'bettershield_hub_link_urgent',
			// The fingerprint of the rule set the endpoint last had written,
			// which is what keeps it from rebuilding the table on every
			// request. The rules themselves are rebuilt below.
			'bettershield_mcp_rules',
			'bettershield_agent_capture',
			'bettershield_ai_explanations',
			'bettershield_ai_incidents',
			'bettershield_ai_summaries',
			'bettershield_ai_calls',
			'bettershield_passkey_policy',
			'bettershield_csp_observing_since',
			'bettershield_lockdown',
			'bettershield_activated_at',
			'bettershield_upload_types_answered',
			'bettershield_claims_failed',
			'bettershield_vulnerability_state',
			'bettershield_vulnerability_checks',
			'bettershield_alerts',
			'bettershield_alerts_pending',
			'bettershield_verification',
			'bettershield_two_factor_policy',
			'bettershield_two_factor_not_moved_told',
			'bettershield_two_factor_roles_since',
			'bettershield_two_factor_reminded_through',
			'bettershield_network_two_factor_roles_since',
			'bettershield_security_txt',
			'bettershield_certificate',
			'bettershield_sudo',
			'bettershield_csp_reports',
			'bettershield_csp_reach',
			'bettershield_log_seals',
			'bettershield_log_seal_verdict',
			'bettershield_log_reseal_owed',
			'bettershield_alerts_previous_recipient',
			'bettershield_https_address',
			'bettershield_registration_role',
			'bettershield_ability_baseline',
			'bettershield_ability_changes',
			'bettershield_agent_networks',
			'bettershield_alert_refused',
			'bettershield_content_links',
			'bettershield_log_reseal_carried',
			'bettershield_events_pruned_through',
			'bettershield_retention_grace',
			'bettershield_retention_hold',
			'bettershield_cloud_metadata_seeded',
			'bettershield_audit_meta',
			'bettershield_audit_pending',
			'bettershield_score_history',
			'bettershield_directory_status',
			'bettershield_theme_directory_status',
			'bettershield_store_scripts',
			'bettershield_previous_version',
			'bettershield_exposed_artifacts',
			'bettershield_quarantine_served',
			'bettershield_server_rules',
			'bettershield_cross_origin',
			'bettershield_cross_origin_witness',
			'bettershield_sign_in_cache',
			'bettershield_xmlrpc_probe',
			'bettershield_folder_listing',
			'bettershield_server_headers',
			'bettershield_domain_records',
			'bettershield_domain_records_asked',
			'bettershield_finding_snoozes',
			'bettershield_site_identity',
			'bettershield_site_identity_done',
			'bettershield_mixed_content',
			'bettershield_rest_surface',
			'bettershield_rest_routes',
			'bettershield_app_password_expiry',
			'bettershield_recovery_codes',
			'bettershield_canary',
			'bettershield_decoy_page',
			'bettershield_incident_cursor',
			// A single site keeps the decoy roster in its own options; a
			// network keeps it in sitemeta, and the block at the foot of this
			// file removes that one.
			'bettershield_canary_sites',
			'bettershield_auth_secret',
			'bettershield_caps_version',
			'bettershield_digest_last_sent',
			'bettershield_digest_last_scheduled',
			'bettershield_event_rates',
			'bettershield_first_run',
			'bettershield_first_scan',
			'bettershield_quick_setup',
			'bettershield_setup_fix_set',
			'bettershield_setup_fix_applied',
			'bettershield_activity_baseline',
			'bettershield_deactivated_at',
			// The usage-data answer, the reference the service filed this
			// site's reports under, and when the last one went.
			'bettershield_usage',
			// A deactivation reason waiting for the report it rides on.
			'bettershield_deactivation_reason',
			'bettershield_front_end_cost',
			'bettershield_observed',
			// What the owner said is their own copy of a plugin, and the open
			// difference each one answers.
			'bettershield_adopted_packages',
			'bettershield_integrity_taken_back',
			'bettershield_package_mismatches',
			'bettershield_integrity_result',
			'bettershield_integrity_result_summary',
			'bettershield_integrity_run',
			'bettershield_integrity_run_paths',
			'bettershield_integrity_run_unpublished',
			'bettershield_integrity_dependencies_seen',
			'bettershield_integrity_names_seen',
			'bettershield_integrity_config_shape',
			'bettershield_integrity_version_taken',
			'bettershield_integrity_unconfirmed_checked',
			'bettershield_integrity_quiet_hold',
			'bettershield_idle_since',
			'bettershield_ip_secret',
			'bettershield_login_protection',
			'bettershield_password_policy',
			'bettershield_recovery_mailed',
			'bettershield_recovery_mailed_to',
			'bettershield_recovery_test_mail',
			'bettershield_recovery_test_result',
			'bettershield_recovery_checked_at',
			'bettershield_maintenance_window',
			'bettershield_maintenance_booking',
			'bettershield_recovery_token_hash',
			'bettershield_recovery_token_issued',
			'bettershield_recovery_spent',
			'bettershield_remove_data_on_uninstall',
			'bettershield_hardening_monitors',
			'bettershield_observed_changes',
			'bettershield_open_proposals',
			'bettershield_account_suspensions',
			'bettershield_password_holds',
			'bettershield_store_endpoint',
			'bettershield_safe_mode_until',
			'bettershield_schema_readiness',
			'bettershield_schema_version',
			'bettershield_task_requested',
			'bettershield_version',
		);

		// The hardening state goes with the undo table, and stays with it: an
		// item whose files could not be put back keeps saying so on reinstall.
		if ( ! $keep_undo ) {
			$options[] = 'bettershield_hardening';
		}

		foreach ( $options as $option ) {
			delete_option( $option );
		}

		// The originals the content-link rewrite kept for its undo (#1291).
		delete_post_meta_by_key( '_bettershield_http_original' );

		// The task runner records when each task last started and how it last
		// ended, one option each per task; match by prefix.
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'bettershield\\_last\\_run\\_%' OR option_name LIKE 'bettershield\\_task\\_done\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no API lists options by prefix.

		/*
		 * Named one at a time, and only names this plugin still writes. The
		 * fallback lock and the alert hold became rows in the claims table,
		 * which the table drop above takes with it, and the lines that named
		 * them as transients went on running against nothing and reporting
		 * success — which is how they survived the move. A test now holds
		 * every name here to something the source can still write.
		 */
		delete_transient( 'bettershield_recovery_failures' );
		delete_transient( 'bettershield_observed_recent' );
		delete_transient( 'bettershield_schema_retry' );
		delete_transient( 'bettershield_https_redirect_probe' );
		delete_transient( 'bettershield_intelligence_retry' );
		delete_transient( 'bettershield_first_run_redirect' );
		delete_transient( 'bettershield_guards_complete' );
		// Per-account throttles are transients named by user ID; match by prefix.
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_bettershield\_reset\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_reset\_%' OR option_name LIKE '\_transient\_bettershield\_lfail\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_lfail\_%' OR option_name LIKE '\_transient\_bettershield\_manifest\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_manifest\_%' OR option_name LIKE '\_transient\_bettershield\_2fa\_skipped\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_2fa\_skipped\_%' OR option_name LIKE '\_transient\_bettershield\_2fa\_step\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_2fa\_step\_%' OR option_name LIKE '\_transient\_bettershield\_pkchal\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_pkchal\_%' OR option_name LIKE '\_transient\_bettershield\_pwrange\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_pwrange\_%' OR option_name LIKE '\_transient\_bettershield\_unusual\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_unusual\_%' OR option_name LIKE '\_transient\_bettershield\_pwlimit\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_pwlimit\_%' OR option_name LIKE '\_transient\_bettershield\_upload\_types\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_upload\_types\_%' OR option_name LIKE '\_site\_transient\_bettershield\_unlock\_alias\_%' OR option_name LIKE '\_site\_transient\_timeout\_bettershield\_unlock\_alias\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no API lists transients by prefix. The unlock aliases are site transients, which a single site keeps among its options.

		// Every raw delete above bypassed the options cache, so the drop comes
		// after the last of them: below the transient sweep rather than above
		// it, or the rows it removed would outlive their own deletion in a
		// persistent object cache.
		wp_cache_flush();

		// Per-user records: the password-policy flag and the two-factor set.
		$meta_keys = array( 'bettershield_password_below_policy', 'bettershield_totp_secret', 'bettershield_totp_pending', 'bettershield_totp_confirmed', 'bettershield_totp_last_step', 'bettershield_backup_codes', 'bettershield_backup_codes_pending', 'bettershield_2fa_park', 'bettershield_2fa_required_since', 'bettershield_sudo_until', 'bettershield_passkey_confirmed_until', 'bettershield_last_login', 'bettershield_release_seen', 'bettershield_last_overview_visit', 'bettershield_overview_visit_window', 'bettershield_app_password_limits', 'bettershield_account_notice_queue' );

		/*
		 * On a network the two-factor grace clock is kept per site, because a
		 * per-site policy owes a per-site window, and so is the pointer to a
		 * parked sign-in, because the record it names is this site's own
		 * transient. This site removes its own, and leaves every other site's
		 * alone — the same rule the loop below follows for the rest of this
		 * list.
		 */
		$own_keys = array();

		if ( is_multisite() ) {
			$own_keys = array(
				'bettershield_2fa_park_' . get_current_blog_id(),
				'bettershield_password_below_policy_' . get_current_blog_id(),
				'bettershield_2fa_required_since_' . get_current_blog_id(),
				'bettershield_last_overview_visit_' . get_current_blog_id(),
				'bettershield_overview_visit_window_' . get_current_blog_id(),
			);
		}

		if ( is_multisite() ) {
			/*
			 * User metadata is network-global: one table for the whole network,
			 * while this function runs once per site. Deleting across all of it
			 * would answer this site's toggle by destroying the two-factor
			 * enrollment and backup codes of every account on every other site,
			 * including the sites that explicitly chose to keep their data — a
			 * silent, unrecoverable loss on sites that were never asked.
			 *
			 * Scoped to this site's own members instead, in bounded pages. What
			 * this site keeps of an account under its own suffix goes with it.
			 * The rest of the list is the account's, one set for the network —
			 * its second factor, its backup codes, the limits on its
			 * application passwords — so it goes only once every site the
			 * account belongs to has asked. Cleared at the first site to opt
			 * in, it went for the administrator of a site that chose to keep it.
			 */
			$page = 1;

			do {
				$members = get_users(
					array(
						'blog_id' => get_current_blog_id(),
						'fields'  => 'ID',
						'number'  => 500,
						'paged'   => $page,
					)
				);

				foreach ( $members as $member_id ) {
					$every_site_asked = true;

					foreach ( array_keys( get_blogs_of_user( (int) $member_id ) ) as $member_site ) {
						if ( ! bettershield_uninstall_opted_in( (int) $member_site ) ) {
							$every_site_asked = false;
							break;
						}
					}

					foreach ( $every_site_asked ? array_merge( $meta_keys, $own_keys ) : $own_keys as $meta_key ) {
						delete_user_meta( (int) $member_id, $meta_key );
					}
				}

				++$page;
			} while ( count( $members ) === 500 );
		} else {
			foreach ( $meta_keys as $meta_key ) {
				delete_metadata( 'user', 0, $meta_key, '', true );
			}
		}

		// The three capabilities, from every role that holds one.
		$roles = wp_roles();
		foreach ( array_keys( $roles->roles ) as $role_name ) {
			$role = $roles->get_role( $role_name );

			if ( null === $role ) {
				continue;
			}

			foreach ( array( 'bettershield_read_posture', 'bettershield_manage', 'bettershield_read_activity', 'bettershield_write_posture' ) as $capability ) {
				$role->remove_cap( $capability );
			}
		}

		return true;
	}
}

if ( ! function_exists( 'bettershield_uninstall_hand_back_quarantine' ) ) {
	/**
	 * Package the quarantined copies for the owner, then remove the folder.
	 *
	 * The third answer to "when this plugin is deleted", and the only one that
	 * touches the folder at all. The order is the whole of it: the archive is
	 * written first, and the folder is removed only once there is one. A
	 * failure of any kind — no zip writer, no room, a copy that vanished
	 * mid-write — leaves every copy where it is, which is the same answer the
	 * plugin gives everywhere else about files it did not create.
	 *
	 * Borrowed from the plugin like the revert above it, and for the same
	 * reason: the copies are named by an undo ledger this routine is about to
	 * drop, and nothing outside the plugin can read it.
	 *
	 * Declared conditionally so the test suite can run this file more than
	 * once in a process; WordPress itself runs it exactly once.
	 *
	 * @return bool Whether the folder was removed.
	 */
	function bettershield_uninstall_hand_back_quarantine(): bool {
		if ( ! class_exists( 'BetterShield\\Files\\Quarantine' ) ) {
			return false;
		}

		try {
			$folder = BetterShield\Files\Quarantine::folder();

			if ( '' === $folder || ! is_dir( $folder ) ) {
				return false;
			}

			/*
			 * One archive takes a page of copies, and the ledger that says
			 * where each came from is dropped after this. So archives are
			 * written until the folder has nothing left to hand back, while
			 * the ledger can still name them; a folder bigger than the bound
			 * below keeps the rest, as one that failed to package does.
			 */
			$bettershield_rounds = 0;

			do {
				$packaged = BetterShield\Files\Quarantine::package();

				if ( is_wp_error( $packaged ) ) {
					break;
				}

				/*
				 * Exactly the copies the archive holds, and nothing else that
				 * is data. Removing what was never handed back is the one
				 * outcome this whole path exists to avoid.
				 */
				foreach ( $packaged['packaged'] as $bettershield_path ) {
					// A link is unlinked, never followed: unlink acts on the
					// link itself, so whatever it pointed at is left alone.
					if ( is_link( $bettershield_path ) || is_file( $bettershield_path ) ) {
						@unlink( $bettershield_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- a folder this plugin created, emptied at the owner's explicit request and only after its contents were packaged; what will not go leaves the folder standing, which is the report.
					}
				}

				++$bettershield_rounds;
			} while ( $packaged['count'] >= BetterShield\Files\Quarantine::MAX_ITEMS && $bettershield_rounds < 50 );

			if ( 0 === $bettershield_rounds ) {
				return false;
			}
		} catch ( \Throwable $e ) {
			return false;
		}

		/*
		 * The seals go last, and only when nothing else is left. A folder
		 * that keeps a copy the archive could not take keeps its index files
		 * and its rule block with it, or the one thing left in it would be
		 * the one thing now listable — the seals were unlinked before the
		 * folder was known to survive, which is the wrong order.
		 */
		$bettershield_entries = @scandir( $folder ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the folder was found above; one that vanished since is a result, not a defect, and a false answer keeps the seals and the folder both.
		$bettershield_left    = array_diff(
			false === $bettershield_entries ? array() : $bettershield_entries,
			array_merge( array( '.', '..' ), BetterShield\Files\Quarantine::SEALS )
		);

		if ( array() !== $bettershield_left ) {
			return false;
		}

		foreach ( BetterShield\Files\Quarantine::SEALS as $bettershield_seal ) {
			$bettershield_path = $folder . '/' . $bettershield_seal;

			if ( is_link( $bettershield_path ) || is_file( $bettershield_path ) ) {
				@unlink( $bettershield_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- as above.
			}
		}

		@rmdir( $folder ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- as above; a folder that still holds something stays, and says so by still being there.

		return ! is_dir( $folder );
	}
}

if ( is_multisite() ) {
	global $wpdb;
	// Declared again here: this file is included from inside core's
	// uninstall_plugin(), whose scope holds no $wpdb, and the declaration
	// inside the per-site function above does not reach out to this one.

	/*
	 * Every site answered the toggle for itself (or left it off); honor each
	 * answer where it was given. Read in pages rather than in one large call:
	 * a single number is a silent cut-off, and a site past it would keep data
	 * whose owner asked for it to go, with nothing left installed to ask again.
	 * The whole network is walked, a page at a time, however large it is —
	 * uninstall is the one walk with no page to return to.
	 */
	$bettershield_offset = 0;

	/*
	 * Whether every site asked for its data to go. Four tables are the
	 * network's rather than any one site's, so one site's answer cannot
	 * decide their fate: they are dropped only where nobody is left who
	 * wanted anything kept, and otherwise stay with the rows of the sites
	 * that said no.
	 */
	$bettershield_all_opted_in = true;

	do {
		$bettershield_site_ids = get_sites(
			array(
				'fields'     => 'ids',
				'number'     => 200,
				'offset'     => $bettershield_offset,
				// The uninstall is the current network's: another network
				// sharing this installation keeps its rows and its say.
				'network_id' => get_current_network_id(),
			)
		);

		foreach ( $bettershield_site_ids as $bettershield_site_id ) {
			switch_to_blog( (int) $bettershield_site_id );
			$bettershield_all_opted_in = bettershield_uninstall_site() && $bettershield_all_opted_in;
			restore_current_blog();
		}

		$bettershield_offset += 200;
	} while ( count( $bettershield_site_ids ) === 200 );

	if ( $bettershield_all_opted_in ) {
		foreach ( array( 'events', 'findings', 'agent_invocations', 'passkeys' ) as $bettershield_shared_table ) {
			$wpdb->query( 'DROP TABLE IF EXISTS `' . $wpdb->base_prefix . 'bettershield_' . $bettershield_shared_table . '`' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- literal plugin-owned table names, dropped only where every site on the network opted in.
		}

		/*
		 * The network tables' readiness stamp and the record of which site's
		 * rows were carried into them go with the tables, and only with them.
		 * Kept tables keep the record too: the move copies and never removes,
		 * so a kept site still holds its old rows in its own tables, and a
		 * reinstall that found no record would carry every one of them into
		 * the shared log a second time.
		 */
		delete_site_option( 'bettershield_network_schema' );
		delete_site_option( 'bettershield_network_migration' );
	}

	/*
	 * The network rollup, which lives in sitemeta rather than in any site's
	 * options — so the per-site sweep above cannot reach it, and neither could
	 * the delete_option() it used to be listed for. Removed once for the
	 * network and without consulting the per-site toggle, because it is not
	 * anybody's data: it is a cache this plugin derived from the per-site
	 * scores, and the code that would ever read it again is being removed in
	 * the same breath.
	 */
	delete_site_transient( 'bettershield_network_rollup' );

	// And its pages, each its own entry named under a generation, so swept
	// by prefix as the manifests are below.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no API lists site transients by prefix.
	$wpdb->query(
		"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\_site\_transient\_bettershield\_network\_rollup\_%' OR meta_key LIKE '\_site\_transient\_timeout\_bettershield\_network\_rollup\_%'"
	);

	/*
	 * And the decoy roster, which is in sitemeta for the same reason and is
	 * likewise derived: it names the sites that planted one, and the decoys
	 * themselves are application passwords each site's own sweep leaves alone.
	 */
	delete_site_option( 'bettershield_canary_sites' );

	/*
	 * And the list of sites that handed two-factor to this plugin in their
	 * setup, kept in sitemeta so a network deactivation reads one value. It
	 * is derived from each site's own setup answer.
	 */
	delete_site_option( 'bettershield_two_factor_handed_sites' );

	/*
	 * The network's own settings, which no site wrote and no one site's
	 * answer can decide: they go only where every site asked for its data to
	 * go, as the shared tables do. "Keep everything" kept each site's data and
	 * took the network's two-factor and passkey floors, its recovery link,
	 * its usage answer and its signing key anyway, so a reinstall came back
	 * without them (#1826).
	 */
	if ( $bettershield_all_opted_in ) {
		/*
		 * The two policies a network set once for every site under it. They belong
		 * to the network rather than to any one site, so the per-site sweep above
		 * cannot reach them.
		 */
		delete_site_option( 'bettershield_network_two_factor_policy' );
		delete_site_option( 'bettershield_network_two_factor_roles_since' );
		delete_site_option( 'bettershield_network_passkey_policy' );

		// The usage-data answer, which a network gives once for all of its sites.
		delete_site_option( 'bettershield_usage' );
		delete_site_option( 'bettershield_deactivation_reason' );

		/*
		 * The network's own way back in, and the key its sites signed with. The
		 * link's hash and the shared secret belong to the network for the same
		 * reason the policies above do. Removing the secret is the last thing this plugin
		 * does to a network's sign-in: with the code gone, nothing would mix it
		 * into a salt again, so leaving the row would be leaving a key nobody can
		 * use and nobody can find.
		 */
		delete_site_option( 'bettershield_network_recovery_token_hash' );
		delete_site_option( 'bettershield_network_recovery_token_issued' );
		delete_site_option( 'bettershield_network_recovery_mailed' );
		delete_site_option( 'bettershield_network_recovery_spent' );
		delete_site_option( 'bettershield_auth_secret' );

		/*
		 * The new-password holds an incident response placed. A password belongs
		 * to the network, so its hold does too; with the gate that reads them
		 * gone, each account signs in with its password as before.
		 */
		delete_site_option( 'bettershield_password_holds' );
	}

	/*
	 * A network-wide pause of every protection is not a setting anybody
	 * kept: with nothing installed to end it on time, it goes either way.
	 */
	delete_site_option( 'bettershield_network_safe_mode_until' );

	/*
	 * And the published manifests, which a network holds once in sitemeta
	 * rather than once per site — the same list of files and checksums every
	 * subsite would otherwise fetch for itself. Swept by prefix because the
	 * key carries a hash of the version it describes, so a manifest for a
	 * version since updated cannot be named any more.
	 */
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no API lists site transients by prefix.
	$wpdb->query(
		"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\_site\_transient\_bettershield\_manifest\_%' OR meta_key LIKE '\_site\_transient\_timeout\_bettershield\_manifest\_%'"
	);

	/*
	 * And an earlier unlock link's pointer at its lockout's newer one, held
	 * for the network as the lockouts are. Named by a hash, so swept by prefix.
	 */
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- no API lists site transients by prefix.
	$wpdb->query(
		"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\_site\_transient\_bettershield\_unlock\_alias\_%' OR meta_key LIKE '\_site\_transient\_timeout\_bettershield\_unlock\_alias\_%'"
	);
} else {
	bettershield_uninstall_site();
}
