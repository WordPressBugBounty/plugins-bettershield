<?php
/**
 * Activation and deactivation handlers.
 *
 * No capability checks here: WordPress already gates who can reach
 * activation, and a guard would silently break WP-CLI activation,
 * which runs without a logged-in user.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Lifecycle {

	/** Rows of one gone site cleared per statement, and how many statements. */
	private const FORGET_PER_PASS = 1000;
	private const FORGET_PASSES   = 50;

	/**
	 * Runs on plugin activation.
	 *
	 * Activation must be safe to run repeatedly (updates re-trigger it) and
	 * changes no setting and applies no hardening item by itself: those wait
	 * for the owner. Two protections do run from activation, and the
	 * readme names them — the sign-in gate and the public-form gate —
	 * because a default that acts has to be stated rather than discovered.
	 *
	 * Future services hook in here in dependency order: schema install,
	 * capability mapping, recovery-token generation.
	 */
	public static function activate( ?bool $network_wide = false ): void {
		// WP-CLI 2.8 passes null when --network is absent. Core forwards it
		// to this hook unchanged; null has the same single-site scope as false.
		if ( $network_wide && is_multisite() ) {
			// Activated for the whole network: every site gets what a single
			// site gets — its own tables, its own baseline audit, its own
			// recovery link to its own admin address.
			self::walk_network( array( self::class, 'activate_site' ) );

			// A key rotated before the switch applies again from the next
			// request: the presser is carried over to it.
			Hardening\Item\AuthKeys::hand_off_for_switch( true );

			return;
		}

		self::activate_site();

		if ( ! is_multisite() ) {
			Hardening\Item\AuthKeys::hand_off_for_switch( true );
		}
	}

	/**
	 * How many sites one page of a network walk holds.
	 *
	 * A page, not a bound. What was here before was a single `'number' => 500`,
	 * and a network past it was cut off silently: those sites were never
	 * provisioned on activation and never cleared on deactivation, while their
	 * own first request scheduled everything regardless.
	 */
	private const SITES_PER_PAGE = 200;

	/**
	 * How long an activation's network walk runs before it stops.
	 *
	 * Activation is somebody's click, and a very large network must not turn
	 * one into a request that never comes back. A site the clock stops short
	 * of is left exactly as a site past the old bound was — provisioning
	 * itself on its own first request — which is why stopping is safe there.
	 *
	 * Not for deactivation. Once the plugin is off, nothing of it runs on a
	 * site again, so a site the clock stopped short of kept every one of its
	 * scheduled events for good, rescheduled by wp-cron with nothing to
	 * answer them. Deactivation walks the whole network.
	 */
	private const WALK_BUDGET_SECONDS = 20.0;

	/**
	 * The two above as the walk reads them: properties, so a test can make a
	 * walk run out of time without building two hundred sites.
	 */
	private static int $sites_per_page = self::SITES_PER_PAGE;

	private static float $walk_budget = self::WALK_BUDGET_SECONDS;

	/**
	 * Run the same work inside every site of a network, in pages.
	 *
	 * The restore is in a `finally` because the work is somebody else's: a
	 * throw from one site that skipped it would leave the rest of the request
	 * — every remaining site of the walk included — reading and writing that
	 * one site's tables.
	 *
	 * @param callable $work    Called with that site switched to.
	 * @param bool     $bounded Whether the walk stops at its time budget; a
	 *                          deactivation's does not (see WALK_BUDGET_SECONDS).
	 */
	private static function walk_network( callable $work, bool $bounded = true ): void {
		$started = microtime( true );
		$offset  = 0;

		do {
			$site_ids = get_sites(
				array(
					'fields'     => 'ids',
					'number'     => self::$sites_per_page,
					'offset'     => $offset,
					// A network activation is one network's, never every
					// network sharing the installation's database.
					'network_id' => get_current_network_id(),
				)
			);

			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );

				try {
					$work();
				} finally {
					restore_current_blog();
				}
			}

			$offset += self::$sites_per_page;
		} while ( count( $site_ids ) === self::$sites_per_page && ( ! $bounded || microtime( true ) - $started < self::$walk_budget ) );
	}

	/**
	 * What a deleted subsite leaves behind in the network's own stores.
	 *
	 * Dropping the site's tables is the other half of this and core does it
	 * from `wpmu_drop_tables`. Two things sit outside those tables and so
	 * outlive them:
	 *
	 * The per-site judgments about a person — the 2FA deadline clock, the
	 * park pointer, the since-last-visit stamp and its window — live in the
	 * network's single `usermeta` table under names carrying the site's id.
	 * The eraser walks the sites an account still belongs to, and a deleted
	 * one is not among them, so nothing else ever reaches them again.
	 *
	 * And on a migrated network the four network tables hold one copy at the
	 * base prefix with every site's rows keyed by `site_id`. The blog-prefixed
	 * names `site_tables()` produces are the stale pre-migration copies, so
	 * core's drop is a no-op for them while the live rows — usernames,
	 * truncated networks, ability-input digests, passkey credentials — stay.
	 * Retention and pruning run per live site and never run for a gone one.
	 *
	 * Nothing here may stop the deletion: a site somebody asked to remove is
	 * removed.
	 */
	public static function forget_site( int $blog_id ): void {
		if ( $blog_id <= 0 || ! is_multisite() ) {
			return;
		}

		self::$deleting[ $blog_id ] = true;

		global $wpdb;

		foreach ( Privacy\PersonalData::site_scoped_meta() as $key ) {
			try {
				delete_metadata( 'user', 0, $key . '_' . $blog_id, '', true );
			} catch ( \Throwable $meta_failed ) {
				unset( $meta_failed );
			}
		}

		foreach ( Database\Schema::NETWORK_TABLES as $name ) {
			$table = Database\Schema::network_table( $name );

			// The migrated copy is the only one keyed this way; on a network
			// that never migrated there is no such table and nothing to do.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- schema introspection while the site is deleted.
			if ( $table !== $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) ) {
				continue;
			}

			/*
			 * Batched and bounded: a busy subsite's log can be large, and a
			 * single unbounded DELETE inside the request that removes the site
			 * is how that request dies part way through with the site half
			 * gone. The loop stops when a pass clears less than it asked for.
			 */
			for ( $pass = 0; $pass < self::FORGET_PASSES; $pass++ ) {
				/*
				 * A passkey is the account's on the whole network, and its
				 * site_id says only where it was enrolled: deleting that site
				 * took it away on every other site, with nothing to say so.
				 * The account's own deletion removes its passkeys, so here only
				 * those of an account that is already gone go with the site.
				 */
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a bounded delete of this plugin's own rows.
				$removed = 'passkeys' === $name
					? $wpdb->query(
						$wpdb->prepare(
							'DELETE FROM %i WHERE site_id = %d AND user_id NOT IN ( SELECT ID FROM %i ) LIMIT %d',
							$table,
							$blog_id,
							$wpdb->users,
							self::FORGET_PER_PASS
						)
					)
					: $wpdb->query(
						$wpdb->prepare(
							'DELETE FROM %i WHERE site_id = %d LIMIT %d',
							$table,
							$blog_id,
							self::FORGET_PER_PASS
						)
					);

				if ( ! is_int( $removed ) || $removed < self::FORGET_PER_PASS ) {
					break;
				}
			}
		}

		// Off the network screen and out of the copy's counts with it.
		Database\NetworkMigration::forget_site( $blog_id );
		Admin\Network::forget_rollup();
	}

	/**
	 * The sites being deleted in this request, by id.
	 *
	 * @var array<int, true>
	 */
	private static array $deleting = array();

	/**
	 * Whether this request is deleting the site. Core removes a deleted
	 * site's members after the sweep above has run, and each removal used to
	 * be recorded as a row keyed to the site, written at shutdown after the
	 * sweep and pruned by no site that is left.
	 */
	public static function is_being_deleted( int $blog_id ): bool {
		return isset( self::$deleting[ $blog_id ] );
	}

	/**
	 * Every table this plugin owns at one site's own prefix.
	 *
	 * Named for core's `wpmu_drop_tables`, which is the only way a deleted
	 * subsite's extra tables go with it. The four that live once per network
	 * are excluded when they resolve to the network's own copy: dropping one
	 * of those would take every other site's log with it.
	 *
	 * @return string[]
	 */
	public static function site_tables( int $blog_id = 0 ): array {
		global $wpdb;

		$prefix = $blog_id > 0 ? $wpdb->get_blog_prefix( $blog_id ) : $wpdb->prefix;
		$shared = array( 'events', 'findings', 'agent_invocations', 'passkeys' );

		$names = array(
			'events',
			'findings',
			'login_attempts',
			'lockouts',
			'integrity_baseline',
			'integrity_changes',
			'passkeys',
			'claims',
			'agent_invocations',
			'incidents',
			'incident_evidence',
			'write_proposals',
			'undo',
		);

		$tables = array();

		foreach ( $names as $name ) {
			$table = $prefix . 'bettershield_' . $name;

			if ( in_array( $name, $shared, true ) && $table === $wpdb->base_prefix . 'bettershield_' . $name ) {
				continue;
			}

			$tables[] = $table;
		}

		return $tables;
	}

	/**
	 * Everything one site gets: its tables, its capabilities, its baseline
	 * audit, its recovery link, and the panel that accounts for all of it.
	 *
	 * Public because a site created after a network activation is provisioned
	 * through the same path — core hands that site over on `wp_initialize_site`
	 * and it is owed what every other site got, the recovery link above all.
	 * Safe to run repeatedly: each step here is idempotent by itself.
	 */
	public static function activate_site(): void {
		Database\Schema::install();
		Database\NetworkMigration::enroll_current_site();
		Capabilities::map();

		// Options read on every request are seeded so a site that has never
		// touched them does not pay a query for their absence on each page
		// view. Declared in one place rather than listed here, because the
		// list was incomplete twice and neither gap was visible from this
		// function — see Support\HotOptions.
		Support\HotOptions::seed();

		// autoload=false: never add to the options loaded on every request.
		update_option( 'bettershield_version', BETTERSHIELD_VERSION, false );

		if ( false === get_option( 'bettershield_activated_at' ) ) {
			update_option( 'bettershield_activated_at', gmdate( 'Y-m-d H:i:s' ), false );
			Alerts\Settings::start_off();
		}

		/*
		 * The pretty addresses the assistant endpoint answers on. Done here
		 * rather than left to the fingerprint on the next `init`, because that
		 * comparison only rebuilds where a rebuild is allowed to happen — an
		 * administrator's page, a cron run or the terminal — and never on a
		 * request somebody is waiting for. Activation is all three of the
		 * first kind by definition.
		 */
		Mcp\Manager::rebuild_rules();

		// Re-apply whatever hardening this site already had before auditing it.
		// Activation is not a normal request: the plugin's own boot has not run
		// for the copy being activated, so nothing it enforces is in place yet.
		// Auditing first therefore looked at a site with every protection
		// switched off and reported items as re-exposed that were configured
		// all along — a scare on reactivation that corrected itself on the next
		// page load, which is worse than either being wrong or being right.
		Hardening\Manager::instance()->enforce();

		// One protection is on from the start: refusing other plugins'
		// requests to the address a cloud server keeps its credentials on.
		// Once in a site's life, so an owner who switched it off is not
		// overruled by a reactivation.
		Hardening\Item\CloudMetadata::seed();

		// Baseline audit: read-only checks, sub-second, so the dashboard
		// has real findings on first open. Modifies nothing.
		Audit\Auditor::run();

		// The recovery link is created once and mailed to the site owner,
		// so a lockout can be undone without logging in. Re-activation
		// never invalidates an existing link.
		$recovery_url = Recovery\RecoveryLink::ensure();
		if ( is_string( $recovery_url ) ) {
			// Whether the mail was accepted is recorded, because a link the
			// owner never received is the same as no link at all — and the
			// dashboard would otherwise tell them one is waiting in their
			// inbox. A true here is acceptance for delivery, never proof of
			// delivery, so only the failure is ever surfaced.
			Recovery\RecoveryLink::record_mailed( self::send_recovery_email( $recovery_url ), (string) get_option( 'admin_email' ) );
		}

		// The owner is owed an account of all of the above — the audit that just
		// ran, the link that was just mailed, and what is deliberately still
		// off. Records that the panel is due and arms the one-time redirect.
		Onboarding\FirstRun::begin();

		// Activation runs after plugins_loaded, so Plugin::boot() has not
		// executed on this request and nothing registered the shutdown flush.
		// Without this the baseline audit and the recovery link creation would
		// be buffered and then discarded, leaving activation off the record.
		Events\Writer::instance()->flush();
	}

	private static function send_recovery_email( string $url ): bool {
		// By its name in the subject, as every other BetterShield mail, and by
		// its address with the path in the body: by host alone, every subsite
		// of a subdirectory network sent the same subject and first line.
		$site = \BetterShield\Recovery\RecoveryLink::address( home_url() );

		// One layout for every recovery email (#1963).
		return \BetterShield\Recovery\RecoveryMail::send(
			(string) get_option( 'admin_email' ),
			\BetterShield\Recovery\RecoveryLink::keep_subject(),
			\BetterShield\Recovery\RecoveryLink::keep_heading(),
			sprintf(
				/* translators: %s: the site's home address without its scheme. */
				__( 'BetterShield was activated on %s.', 'bettershield' ),
				$site
			),
			$url,
			array(
				\BetterShield\Recovery\RecoveryLink::pauses_line(),
				\BetterShield\Recovery\RecoveryLink::works_once_line(),
				\BetterShield\Recovery\RecoveryLink::expiry_sentence( \BetterShield\Recovery\RecoveryLink::expires_at() ),
				__( 'Making a new link from the dashboard stops this one working.', 'bettershield' ),
			),
			\BetterShield\Recovery\RecoveryLink::not_asked_line()
		);
	}

	/**
	 * Runs on plugin deactivation.
	 *
	 * Never destructive: configuration, history, findings and undo records
	 * are all kept. Deactivation only stops behavior, it deletes nothing.
	 */
	public static function deactivate( ?bool $network_wide = false ): void {
		/*
		 * Cron is per-site on a network, and a network activation provisions
		 * every site, so clearing only the current one left this plugin's
		 * schedule running on every other: the events fired with no callback
		 * registered and wp-cron rescheduled them, indefinitely.
		 *
		 * Mirrors the activation branch exactly, scope included. Deactivating
		 * on one subsite of a network is that subsite's decision and stops
		 * there — clearing the whole network's schedules from it would restart
		 * every other site's clock, firing every daily and hourly task at once
		 * a minute later on sites nobody touched.
		 */
		if ( $network_wide && is_multisite() ) {
			/*
			 * Every site, however long it takes: nothing of this plugin runs
			 * on a site again once it is off, so one the walk missed would
			 * keep its schedule for good. A slow request is the lesser harm,
			 * so the time limit is lifted where the host allows it and a
			 * closed tab does not stop the walk part-way.
			 */
			if ( function_exists( 'set_time_limit' ) ) {
				@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a host that forbids it keeps its own limit, which is the answer.
			}

			if ( function_exists( 'ignore_user_abort' ) ) {
				ignore_user_abort( true );
			}

			/*
			 * The network's own hand-offs first: a host that ends a long
			 * request regardless of the time limit stops the walk part-way,
			 * and these are once for the network, not once per site.
			 */

			// Once, for the network the usage answer belongs to — not once for
			// every site the walk passed through.
			Onboarding\Usage::deactivated();

			// A rotated key stops applying with the plugin: the presser is
			// carried over to the plain one, as a rotation carries them.
			Hardening\Item\AuthKeys::hand_off_for_switch( false );

			self::walk_network( array( self::class, 'deactivate_site' ), false );

			return;
		}

		self::deactivate_site();

		// On a network the usage answer is the network's, and one site
		// switching the plugin off is not the network doing so.
		if ( ! is_multisite() ) {
			Onboarding\Usage::deactivated();
			Hardening\Item\AuthKeys::hand_off_for_switch( false );
		}
	}

	private static function deactivate_site(): void {
		Cron\Runner::instance()->unschedule_all();
		// So the first run back measures nothing across the time it was off.
		update_option( Events\Unusual::DEACTIVATED, time(), false );
		wp_clear_scheduled_hook( Alerts\Maintenance::TASK );
		wp_clear_scheduled_hook( Incidents\Engine::TASK );
		// The first usage report's retry is a one-off event of its own,
		// outside the runner's list: a deactivated plugin sends nothing more.
		// Saying once that it has switched off is `deactivate()`'s to do.
		wp_clear_scheduled_hook( Onboarding\Usage::FIRST_TASK );
		// A plugin's files still being compared after it was installed:
		// each pass is scheduled with where it stopped, so every one goes.
		wp_unschedule_hook( Integrity\IncomingPackage::RECHECK_HOOK );
	}
}
