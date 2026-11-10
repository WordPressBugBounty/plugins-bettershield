<?php
/**
 * Audit engine: runs the checks, maintains finding lifecycle, scores.
 *
 * The audit never modifies the site. It writes only to plugin-owned
 * records: the findings table, one meta option, and the activity log.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Database\Schema;
use BetterShield\Events\Listeners;
use BetterShield\Events\Writer;
use BetterShield\Hardening\Manager;
use BetterShield\Support\Tier;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Every query below targets the plugin-owned findings and events tables, for
 * which no core API exists. They are not cached on purpose: the posture a site
 * owner is shown must be the posture currently recorded, never a cached copy
 * of an earlier one.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Auditor {

	private const META_OPTION = 'bettershield_audit_meta';

	/** How long after closing a finding that comes back is still the same news. */
	private const REPEAT_DAYS = 14;

	private const SEVERITY_LEVELS = array(
		'info'     => 0,
		'low'      => 1,
		'medium'   => 2,
		'high'     => 3,
		'critical' => 4,
	);

	/**
	 * The score is two parts. Setup essentials are worth 60 points, one item
	 * each, and an open item costs its points; site health is worth 40, and
	 * every other open finding takes from it by severity, down to 0. While
	 * any critical finding is open the sum stops at CRITICAL_CAP, so a site
	 * with a critical problem never shows an A or a B.
	 *
	 * Every finding carries its own resolved deduction in the payload, so the
	 * numbers themselves stay server-side.
	 */
	public const SETUP_TOTAL  = 60;
	public const HEALTH_TOTAL = 40;
	public const CRITICAL_CAP = 74;

	/** Site-health deduction per open finding, by severity level. */
	public const DEDUCTIONS = array( 0, 1, 2, 5, 10 );

	/**
	 * The setup essentials: each check's item and what the item is worth.
	 * Two checks that answer the same item (sign-in limits) share it, and
	 * the item costs its points once however many of them are open.
	 *
	 * @var array<string, array{0: string, 1: int}>
	 */
	public const SETUP_POINTS = array(
		'privileged_password_only'      => array( 'two_factor', 10 ),
		'lockouts_not_running'          => array( 'sign_in_limits', 8 ),
		'login_attempts_unlimited'      => array( 'sign_in_limits', 8 ),
		'recovery_unconfirmed'          => array( 'way_back_in', 6 ),
		'file_editor_enabled'           => array( 'file_editor', 5 ),
		'user_listing_public'           => array( 'username_discovery', 5 ),
		'security_headers_missing'      => array( 'security_headers', 3 ),
		'common_usernames_allowed'      => array( 'common_usernames', 3 ),
		'directory_browsing_open'       => array( 'directory_browsing', 2 ),
		'version_disclosed'             => array( 'version_hidden', 2 ),
		'reset_form_unprotected'        => array( 'reset_form', 3 ),
		'comment_form_unprotected'      => array( 'comment_form', 3 ),
		'registration_form_unprotected' => array( 'registration_form', 3 ),
		'form_bot_check_off'            => array( 'bot_check', 3 ),
		'pingbacks_open'                => array( 'pingbacks', 2 ),
		'proof_of_work_off'             => array( 'proof_of_work', 1 ),
		'ai_bots_unblocked'             => array( 'ai_bots', 1 ),
	);

	/**
	 * Findings outside the setup essentials that another plugin or the host
	 * can also answer, so the owner may say the job is covered.
	 *
	 * @var string[]
	 */
	private const SELF_MANAGED_EXTRA = array( 'xmlrpc_enabled', 'backup_plugin_not_visible' );

	/**
	 * Whether this finding is a job another plugin or the host can do, which
	 * the screens offer as "I manage this myself". It is the owner's word and
	 * nothing checks it: the finding is suppressed like any other.
	 */
	public static function is_self_managed( string $key ): bool {
		return isset( self::SETUP_POINTS[ $key ] ) || in_array( $key, self::SELF_MANAGED_EXTRA, true );
	}

	/**
	 * What one open finding costs: its setup item's points, or its severity's
	 * site-health deduction.
	 */
	public static function deduction_of( string $key, int $level ): int {
		if ( isset( self::SETUP_POINTS[ $key ] ) ) {
			return self::SETUP_POINTS[ $key ][1];
		}

		return self::DEDUCTIONS[ max( 0, min( 4, $level ) ) ] ?? 0;
	}

	/**
	 * The setup item an open finding costs, or null where it takes from site
	 * health instead. Two findings that share an item cost it once, so a
	 * screen adding up their points needs to know which they share (#2512).
	 */
	public static function score_item_of( string $key ): ?string {
		return self::SETUP_POINTS[ $key ][0] ?? null;
	}

	/**
	 * The score for a set of open findings, and how it was reached. The one
	 * calculation behind the score, the projected score and the history:
	 * a projection is this run on the findings a fix would leave, never
	 * points added back to a total.
	 *
	 * @param array<string, int> $open Severity level by finding key.
	 * @return array{score: int, setup: int, health: int, capped: bool}
	 */
	public static function score_of( array $open ): array {
		$items    = array();
		$health   = 0;
		$critical = false;

		foreach ( $open as $key => $level ) {
			$level    = max( 0, min( 4, (int) $level ) );
			$critical = $critical || 4 === $level;

			if ( isset( self::SETUP_POINTS[ $key ] ) ) {
				$items[ self::SETUP_POINTS[ $key ][0] ] = self::SETUP_POINTS[ $key ][1];
				continue;
			}

			$health += self::DEDUCTIONS[ $level ] ?? 0;
		}

		$setup  = max( 0, self::SETUP_TOTAL - array_sum( $items ) );
		$health = max( 0, self::HEALTH_TOTAL - $health );
		$score  = $setup + $health;
		$capped = $critical && $score > self::CRITICAL_CAP;

		return array(
			'score'  => $capped ? self::CRITICAL_CAP : $score,
			'setup'  => $setup,
			'health' => $health,
			'capped' => $capped,
		);
	}

	/**
	 * The open findings the score reads, severity level by finding key, with
	 * the answers that change outside an audit run read again first, as the
	 * Overview reads them. A finding from a check that no longer exists is
	 * left out, as the Overview leaves it out of the score.
	 *
	 * @return array<string, int>
	 */
	public static function open_levels(): array {
		self::refresh_live();

		$checks   = Checks::all();
		$statuses = self::statuses( $levels );
		$open     = array();

		foreach ( $statuses as $key => $status ) {
			if ( 'open' === $status && isset( $checks[ $key ] ) ) {
				$open[ $key ] = (int) ( $levels[ $key ] ?? 0 );
			}
		}

		return $open;
	}

	/**
	 * Run every check and update finding lifecycle rows.
	 */
	public static function run(): void {
		global $wpdb;
		$start = microtime( true );

		// Whatever a change outside this plugin left owed is paid by this run,
		// so the next screen does not run it a second time.
		\BetterShield\Plugin::audit_paid();
		$now   = ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		$open       = 0;
		$suppressed = 0;

		/*
		 * A check whose evidence could not be gathered keeps its existing row
		 * rather than having it overwritten with a false negative. That makes
		 * the run partial, and a run that stamped itself complete anyway
		 * presented last week's answer as this minute's on the one line the
		 * dashboard is read for. Both numbers are recorded, and the rows that
		 * were kept are named so the report can mark them.
		 */
		$ran     = 0;
		$stale   = array();
		$unknown = array();
		// Checks with nothing to read on this site: neither run nor unknown.
		$inapplicable = array();

		/*
		 * The first audit on a site is a baseline, not news. Everything it
		 * opens was already true before the plugin arrived, and a site with a
		 * dozen of them would otherwise mail its owner about the site they
		 * just installed on — in the same minute as the Quick Setup that
		 * exists to say the same thing calmly. The report, the score and the
		 * first summary all still carry every one of them.
		 */
		$baseline = false === get_option( self::META_OPTION, false );
		$checks   = Checks::all();

		/*
		 * When each check last returned a result, pass or fail. The findings
		 * row cannot say it: its last-seen time moves only when a check fails,
		 * and most passing checks have no row at all, so "last answered" for a
		 * check that went dark read blank, or as the day it was last fixed.
		 * Carried forward for a check that cannot answer this time.
		 */
		$previous = get_option( self::META_OPTION, array() );
		$was      = is_array( $previous ) && isset( $previous['checks_answered'] ) && is_array( $previous['checks_answered'] ) ? $previous['checks_answered'] : array();
		$answered = array();

		foreach ( $checks as $key => $check ) {
			/*
			 * A check that throws is one that could not answer. Uncaught, one
			 * failing check (a filter's value, say) ended the whole run: the
			 * checks after it never ran, and neither the score nor this
			 * record was written, at activation and after every hardening
			 * switch as well as on the audit itself.
			 */
			try {
				$evidence = ( $check['test'] )();
			} catch ( \Throwable $failure ) {
				$evidence = new \WP_Error( 'bettershield_check_failed', __( 'This check stopped with an error this time.', 'bettershield' ) );
			}

			/*
			 * Not applicable here is not a question left open: the thing the
			 * check reads does not exist for this site (a domain nobody
			 * answers for has no mail records to miss), or only the network
			 * can act on it (#2182). A finding opened before is closed rather
			 * than kept, and the check is named apart from the ones that
			 * could not answer: counted among them, every subsite read "could
			 * not be checked" for two checks that had answered.
			 */
			if ( is_wp_error( $evidence ) && 'bettershield_audit_not_applicable' === $evidence->get_error_code() ) {
				self::mark_resolved( $key, $now );

				$inapplicable[ $key ] = array(
					'title'  => Checks::title_of( $check ),
					'reason' => (string) $evidence->get_error_message(),
				);

				continue;
			}

			// Unknown is neither new evidence nor proof of resolution. Preserve
			// the row (including suppression, severity and last-seen timestamp).
			if ( is_wp_error( $evidence ) ) {
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate contains only a fixed column and integer site IDs from Schema::site_where(); the finding key and table use placeholders.
				$kept   = $wpdb->get_row( $wpdb->prepare( 'SELECT status, severity FROM %i WHERE ' . Schema::site_where( 'findings' ) . ' AND finding_key=%s', Schema::table( 'findings' ), $key ) );
				$status = null !== $kept ? (string) $kept->status : null;

				// A result the check itself says can't be trusted any more is
				// not kept. It stays listed below as a check that couldn't run.
				if ( 'open' === $status && isset( $check['unknown_closes'] ) && ( $check['unknown_closes'] )() ) {
					self::mark_resolved( $key, $now );
					$status = 'fixed';
				}

				$open += 'open' === $status ? 1 : 0;
				$suppressed += 'suppressed' === $status ? 1 : 0;

				// Only where there was a row to keep. A check that has never
				// produced one carries nothing forward, so there is nothing
				// on the report to mark as older than the run.
				if ( null !== $status && 'fixed' !== $status ) {
					$stale[] = $key;
				}

				/*
				 * Which check, and why in the check's own words. A bare count
				 * tells an owner something is unknown and not what, which is
				 * the difference between ignoring it and fixing the firewall
				 * rule that caused it. Recorded for every check that could not
				 * answer, including the ones carrying no row yet — those are
				 * not stale, because there is nothing on the report to mark,
				 * but they are still unanswered.
				 */
				$unknown[ $key ] = array(
					// Named for the row it keeps, where it keeps one.
					'title'  => Checks::title_of( $check, null !== $kept ? ( array_flip( self::SEVERITY_LEVELS )[ (int) $kept->severity ] ?? null ) : null ),
					'code'   => (string) $evidence->get_error_code(),
					'reason' => (string) $evidence->get_error_message(),
				);

				if ( isset( $was[ $key ] ) && is_string( $was[ $key ] ) ) {
					$answered[ $key ] = $was[ $key ];
				}

				continue;
			}

			++$ran;
			$answered[ $key ] = (string) Time::utc_iso( $now );

			if ( null === $evidence ) {
				self::mark_resolved( $key, $now );
				continue;
			}

			/*
			 * A failing check is not the same as an open finding: one the owner
			 * suppressed stays suppressed, and counting it here made the
			 * activity log disagree with the dashboard about the same audit.
			 * The log is where an owner goes to audit their own decisions, so
			 * it is the worst place for that number to be wrong — and both
			 * counts are recorded rather than the difference being dropped.
			 */
			if ( 'suppressed' === self::mark_open( $key, self::SEVERITY_LEVELS[ Checks::severity_of( $check ) ], $evidence, $now, $baseline ) ) {
				++$suppressed;
				continue;
			}

			++$open;
		}

		update_option(
			self::META_OPTION,
			array(
				'generated_at' => gmdate( 'c' ),
				'duration_ms'  => (int) round( ( microtime( true ) - $start ) * 1000 ),
				'checks_total' => count( $checks ) - count( $inapplicable ),
				'checks_ran'   => $ran,
				'checks_stale' => $stale,
				// Named, with the reason each one gave.
				'checks_unknown' => $unknown,
				'checks_not_applicable' => $inapplicable,
				'checks_answered' => $answered,
			),
			false
		);

		self::remember_score( $checks );

		// With every row as this run left it: a snooze whose finding closed,
		// got worse or ran out of time ends here.
		Snooze::review();

		Writer::instance()->record(
			'scan_completed',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'audit',
				'context'     => array(
					'open_findings'       => $open,
					'suppressed_findings' => $suppressed,
				),
			)
		);
	}

	/**
	 * Whether the last completed run is older than the given age, or there
	 * has not been one.
	 */
	public static function last_run_older_than( int $seconds ): bool {
		$meta = get_option( self::META_OPTION, array() );
		$at   = is_array( $meta ) && is_string( $meta['generated_at'] ?? null ) ? strtotime( $meta['generated_at'] ) : false;

		return false === $at || ( time() - $at ) >= $seconds;
	}

	/** Where the score's own history is kept, and how much of it. */
	private const HISTORY_OPTION = 'bettershield_score_history';

	/**
	 * The events that record a change to what this plugin controls: its
	 * hardening, and its own settings and policies. "Last change made" is the
	 * newest of them. Counted from hardening alone, turning off sign-in
	 * protection or the two-factor requirement never moved it, and those are
	 * the changes an owner most needs that line to show.
	 *
	 * An incident response and what it did, a file put back from its
	 * official copy or from quarantine, and a kept copy deleted are changes
	 * made through this plugin too, and its most drastic: the line read "12
	 * minutes ago" for an activation hardening, minutes after a response had
	 * stripped an administrator and rewritten a core file (#2245).
	 *
	 * `setting_changed` is counted apart, and only for this plugin's own
	 * settings: the activity log writes the same type for the core options it
	 * watches and for a personal-data erasure, and neither is a change made
	 * through this plugin.
	 */
	private const CHANGES_MADE = array(
		'hardening_applied',
		'hardening_reverted',
		'settings_imported',
		'login_protection_updated',
		'password_policy_updated',
		'two_factor_policy_changed',
		'passkey_policy_changed',
		'alerts_updated',
		'canary_page_changed',
		'uninstall_choice_changed',
		'incident_response_applied',
		'incident_account_demoted',
		'incident_cron_unscheduled',
		'incident_password_held',
		'file_restored',
		'file_restore_undone',
		'file_quarantined',
		'quarantine_deleted',
	);

	/**
	 * The last 30 recorded UTC days: what the dashboard draws. Enough to see a
	 * direction, small enough that the whole series is one small option and
	 * never a table.
	 */
	private const HISTORY_POINTS = 30;

	/**
	 * How many recorded days are read: the log's retention window, and never
	 * fewer than the dashboard draws.
	 */
	private static function history_days(): int {
		return max( self::HISTORY_POINTS, Tier::retention_days() );
	}

	/**
	 * How many recorded days stay on disk: the days read, or the longer
	 * window the pruners are still holding the log to, so a retention that
	 * comes back finds its days where it left them.
	 */
	private static function kept_days(): int {
		return max( self::history_days(), Tier::kept_days() );
	}

	/**
	 * Add this audit's score, and the state of every check that did not pass,
	 * to the series behind the dashboard.
	 *
	 * "Are we getting safer" is the question an owner actually asks, and a
	 * single number cannot answer it — it says where the site is, never
	 * whether the work of the last fortnight moved anything. The check-level
	 * state is what answers the next question, "what moved": only the checks
	 * that did not pass are kept, as key and severity, so a day stays a few
	 * hundred bytes and a past day can be compared with today.
	 *
	 * Written here, at the end of a run, rather than where the score is
	 * displayed: the dashboard is a read, and a read that writes is a surprise
	 * for whoever debugs it next. One point per UTC day, updated after each audit so
	 * repeated manual runs cannot evict earlier days.
	 *
	 * @param array<string, array<string, mixed>> $checks The map the run
	 *                                                    already built.
	 */
	private static function remember_score( array $checks ): void {
		$series = array_values( array_filter( self::history_points( self::kept_days() ), static fn( $point ) => substr( $point['at'], 0, 10 ) !== gmdate( 'Y-m-d' ) ) );
		$state  = self::current_state( $checks );

		$series[] = array(
			'at'         => gmdate( 'c' ),
			'score'      => $state['score'],
			'open'       => $state['open'],
			'suppressed' => $state['suppressed'],
		);

		update_option(
			self::HISTORY_OPTION,
			array_values( array_slice( $series, -self::kept_days() ) ),
			false
		);
	}

	/**
	 * The latest score on each recorded UTC day, oldest first.
	 *
	 * @return array<int, array{at: string, score: int}>
	 */
	public static function score_history(): array {
		$series = array_map(
			static fn( array $point ): array => array(
				'at'    => $point['at'],
				'score' => $point['score'],
			),
			self::history_points()
		);

		return array_values( array_slice( $series, -self::HISTORY_POINTS ) );
	}

	/**
	 * Every kept day, oldest first: the latest point of each UTC day, with
	 * the checks that did not pass where the day recorded them. Days written
	 * before that was kept carry the score alone.
	 *
	 * @param int|null $days How many days to return; the days read when null.
	 * @return array<int, array{at: string, score: int, open?: array<string, int>, suppressed?: string[]}>
	 */
	private static function history_points( ?int $days = null ): array {
		$stored = get_option( self::HISTORY_OPTION, array() );
		$series = array();

		foreach ( is_array( $stored ) ? $stored : array() as $point ) {
			if ( ! is_array( $point ) || ! isset( $point['at'], $point['score'] ) || ! is_string( $point['at'] ) || ! is_numeric( $point['score'] ) ) { continue; }
			$time = strtotime( $point['at'] );
			if ( false === $time || $time > time() ) { continue; }
			$day = gmdate( 'Y-m-d', $time );
			// Normalize old per-run histories without inventing discarded days.
			if ( isset( $series[ $day ] ) && strtotime( $series[ $day ]['at'] ) > $time ) { continue; }

			$entry = array( 'at' => gmdate( 'c', $time ), 'score' => max( 0, min( 100, (int) $point['score'] ) ) );

			if ( isset( $point['open'] ) && is_array( $point['open'] ) ) {
				$open = array();

				foreach ( $point['open'] as $key => $level ) {
					if ( is_string( $key ) && is_numeric( $level ) ) {
						$open[ $key ] = max( 0, min( 4, (int) $level ) );
					}
				}

				$entry['open']       = $open;
				$entry['suppressed'] = array_values( array_filter( (array) ( $point['suppressed'] ?? array() ), 'is_string' ) );
			}

			$series[ $day ] = $entry;
		}

		ksort( $series );

		return array_values( array_slice( $series, -( $days ?? self::history_days() ) ) );
	}

	/**
	 * The recorded days a comparison can start from, oldest first: the ones
	 * that kept their checks, and never today, which is what they are
	 * compared with.
	 *
	 * @return array<int, array{day: string, score: int}>
	 */
	public static function posture_days(): array {
		$days  = array();
		$today = gmdate( 'Y-m-d' );

		foreach ( self::history_points() as $point ) {
			$day = substr( $point['at'], 0, 10 );

			if ( isset( $point['open'] ) && $day !== $today ) {
				$days[] = array(
					'day'   => $day,
					'score' => $point['score'],
				);
			}
		}

		return $days;
	}

	/**
	 * What changed between a recorded day and the findings as they stand:
	 * the checks that opened since, the ones that passed since, the ones the
	 * owner marked not applicable since, the ones the owner put back since,
	 * and the ones whose severity moved.
	 *
	 * The comparison is with the findings table rather than with today's
	 * point, because that is what the report shows; the two agree after any
	 * audit. A day that kept only its score has nothing to compare, and says
	 * so rather than reporting every open finding as new.
	 *
	 * @return array{since: array{day: string, score: int}, now: array{score: int}, opened: array<int, array{id: string, title: string, severity: string}>, resolved: array<int, array{id: string, title: string, severity: string}>, set_aside: array<int, array{id: string, title: string, severity: string}>, put_back: array<int, array{id: string, title: string, severity: string}>, changed: array<int, array{id: string, title: string, from: string, to: string}>}|\WP_Error
	 */
	public static function posture_since( string $day ): array|\WP_Error {
		$then = null;

		foreach ( self::history_points() as $point ) {
			if ( isset( $point['open'] ) && substr( $point['at'], 0, 10 ) === $day ) {
				$then = $point;
			}
		}

		if ( null === $then || gmdate( 'Y-m-d' ) === $day ) {
			return new \WP_Error( 'bettershield_posture_day_unknown', __( 'There is no record of the checks for that day.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$checks = Checks::all();
		$now    = self::current_state( $checks );
		$names  = array_flip( self::SEVERITY_LEVELS );

		$row = static function ( string $key, int $level ) use ( $checks, $names ): array {
			return array(
				'id'       => $key,
				'title'    => isset( $checks[ $key ] ) ? Checks::title_of( $checks[ $key ], $names[ $level ] ?? null ) : $key,
				'severity' => $names[ $level ] ?? 'info',
			);
		};

		$diff = array(
			'since'     => array(
				'day'   => $day,
				'score' => $then['score'],
			),
			'now'       => array( 'score' => $now['score'] ),
			'opened'    => array(),
			'resolved'  => array(),
			'set_aside' => array(),
			'put_back'  => array(),
			'changed'   => array(),
		);

		$then_aside = (array) ( $then['suppressed'] ?? array() );

		foreach ( $now['open'] as $key => $level ) {
			if ( ! isset( $then['open'][ $key ] ) ) {
				// Marked not applicable on that day and put back since is the
				// owner's call undone, not a check that started failing: the
				// mirror of a finding set aside since.
				$diff[ in_array( $key, $then_aside, true ) ? 'put_back' : 'opened' ][] = $row( $key, $level );
			} elseif ( $then['open'][ $key ] !== $level ) {
				$diff['changed'][] = array(
					'id'    => $key,
					'title' => $row( $key, $level )['title'],
					'from'  => $names[ $then['open'][ $key ] ] ?? 'info',
					'to'    => $names[ $level ] ?? 'info',
				);
			}
		}

		foreach ( $then['open'] as $key => $level ) {
			if ( isset( $now['open'][ $key ] ) ) {
				continue;
			}

			// Marked not applicable is the owner's call, not the site getting
			// better, so it is not counted among the checks that passed.
			$diff[ in_array( $key, $now['suppressed'], true ) ? 'set_aside' : 'resolved' ][] = $row( $key, $level );
		}

		return $diff;
	}

	/**
	 * The score as it stands, computed the way the dashboard computes it, with
	 * the checks behind it: every open finding's severity level, and the keys
	 * the owner marked not applicable.
	 *
	 * Deliberately not `overview()['score']`: that builds the whole payload,
	 * including two counting queries and the hardening state, for one number
	 * at the end of a run that has already done the expensive part.
	 *
	 * @param array<string, array<string, mixed>> $checks The map the run
	 *                                                    already built.
	 * @return array{score: int, open: array<string, int>, suppressed: string[]}
	 */
	private static function current_state( array $checks ): array {
		global $wpdb;

		$open       = array();
		$suppressed = array();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT finding_key, severity, status FROM %i WHERE " . Schema::site_where( 'findings' ) . " AND status IN ('open', 'suppressed')", Schema::table( 'findings' ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			if ( ! isset( $checks[ $row->finding_key ] ) ) {
				continue;
			}

			if ( 'suppressed' === $row->status ) {
				$suppressed[] = (string) $row->finding_key;
				continue;
			}

			$open[ (string) $row->finding_key ] = max( 0, min( 4, (int) $row->severity ) );
		}

		ksort( $open );
		sort( $suppressed );

		return array(
			'score'      => self::score_of( $open )['score'],
			'open'       => $open,
			'suppressed' => $suppressed,
		);
	}

	/**
	 * Overview payload for the dashboard.
	 *
	 * @return array<string, mixed>
	 */
	public static function overview(): array {
		global $wpdb;

		self::refresh_live();

		$meta   = get_option( self::META_OPTION, array() );
		$checks = Checks::all();

		/*
		 * `checks_count` is what this option called the total before a partial
		 * run could be told from a complete one. A site that has not audited
		 * since the upgrade still holds only that name, and reading it keeps
		 * its dashboard honest until the next run rewrites the option.
		 */
		$checks_total = (int) ( $meta['checks_total'] ?? $meta['checks_count'] ?? count( $checks ) );
		$checks_ran   = (int) ( $meta['checks_ran'] ?? $checks_total );
		$stale        = self::kept_stale();
		$manager      = Manager::instance();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT finding_key, severity, status FROM %i WHERE " . Schema::site_where( 'findings' ) . " AND status IN ('open', 'suppressed')", Schema::table( 'findings' ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		// get_results() answers null on a falsy query, and prepare() answers
		// null on a placeholder mismatch. Both queries are well-formed today,
		// so this guards the next edit rather than a live fault — on the
		// most-requested endpoint in the plugin, where a foreach over null
		// prints a warning wherever the site shows them.
		$rows = is_array( $rows ) ? $rows : array();

		$open            = array();
		$left            = array();
		$serious_left    = array();
		$findings        = array();
		$marked          = 0;
		$severity_labels = array_flip( self::SEVERITY_LEVELS );

		foreach ( $rows as $row ) {
			if ( ! isset( $checks[ $row->finding_key ] ) ) {
				continue; // A finding from a removed check: ignore in scoring.
			}

			if ( 'suppressed' === $row->status ) {
				++$marked;
				continue;
			}

			$check     = $checks[ $row->finding_key ];
			$level     = (int) $row->severity;
			$deduction = self::deduction_of( (string) $row->finding_key, $level );

			$open[ (string) $row->finding_key ] = $level;

			$remediable = self::remediable( $check['hardening_item'] );
			$active     = $remediable && $manager->is_active( (string) $check['hardening_item'] );
			$snoozed    = Snooze::until_iso( (string) $row->finding_key );

			/*
			 * What the lists offer, and so what the projections take away: a
			 * one-click fix not already on, and a critical or high finding,
			 * neither of them snoozed. A snoozed one still counts in the
			 * score, so it stays in both.
			 */
			if ( ! ( $remediable && ! $active && null === $snoozed ) ) {
				$left[ (string) $row->finding_key ] = $level;
			}

			if ( ! ( $level >= 3 && null === $snoozed ) ) {
				$serious_left[ (string) $row->finding_key ] = $level;
			}

			$findings[] = array(
				'id'               => $row->finding_key,
				'group'            => $check['group'],
				'severity'         => $severity_labels[ $level ] ?? 'info',
				'severity_level'   => $level,
				'status'           => 'open',
				'title'            => Checks::title_of( $check, $severity_labels[ $level ] ?? null ),
				'why'              => $check['why'],
				'break_note'       => $check['break_note'],
				'remediable'       => $remediable,
				'hardening_item'   => $check['hardening_item'],
				/*
				 * What the item is configured as, beside what the check just
				 * measured. The two disagree while nothing is enforcing an
				 * applied item, and the apply endpoint answers a press on one
				 * of those with a refusal and nothing else — so the screen has
				 * to know before it offers the control.
				 */
				'hardening_active' => $active,
				// Whether the last run could evaluate this check at all. False
				// on everything the run confirmed, including what it resolved.
				'stale'            => in_array( (string) $row->finding_key, $stale, true ),
				'stale_reason'     => self::unknown_reason( (string) $row->finding_key ),
				// Where the control is, for a finding whose answer is not a
				// one-click fix. Null where there genuinely is nowhere to send
				// anybody, which is several of them.
				'control'          => Checks::control_for( (string) $row->finding_key ) ?? Checks::control_when_applied( (string) $row->finding_key, $active ),
				'deduction'        => $deduction,
				'score_item'       => self::score_item_of( (string) $row->finding_key ),
				'self_managed'     => self::is_self_managed( (string) $row->finding_key ),
				// Partly answered already: listed and counted, not worth doing first.
				'partly_handled'   => Checks::partly_handled( (string) $row->finding_key ),
				// Set aside by the owner until then: still open and still
				// counted, shown apart from what needs attention.
				'snoozed_until'    => $snoozed,
			);
		}

		// Highest severity first; one-click fixes before guidance-only.
		usort(
			$findings,
			static function ( array $a, array $b ): int {
				if ( $a['severity_level'] !== $b['severity_level'] ) {
					return $b['severity_level'] <=> $a['severity_level'];
				}

				return (int) $b['remediable'] <=> (int) $a['remediable'];
			}
		);

		$scored = self::score_of( $open );
		$score  = $scored['score'];

		/*
		 * The same calculation on what the one-click fixes would leave, never
		 * the fixes' points added back: either bucket can already sit at its
		 * floor, and the cap still holds while a critical finding has no
		 * one-click fix, so adding points back promised a grade that fixing
		 * everything could not reach.
		 */
		$projected = self::score_of( $left )['score'];
		$serious   = self::score_of( $serious_left )['score'];

		// The count, not the items: the hardening endpoint already serves those
		// with live state, and a second copy here would be a second source of
		// truth for the same thing. describe_all() would also run every item's
		// conflict probe on the most-requested endpoint in the plugin.
		$hardening_active = $manager->active_count();

		$week_ago = ( new \DateTimeImmutable( '-7 days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		$events_table = Schema::table( 'events' );

		/*
		 * Every one of these three names the site. They are the numbers the
		 * roll-up shows per site, and the log they read is shared across a
		 * network: without the predicate a quiet site would report its
		 * neighbors’ week as its own.
		 */
		$site = Schema::site_where( 'events' );

		/*
		 * A `setting_changed` row is one of this plugin's settings when it
		 * names a setting or a hardening monitor, and not one of the core
		 * options the log watches (search engine visibility, the permalink
		 * structure). A personal-data erasure names a user.
		 */
		$core_options = Listeners::watched_options();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $site is the predicate above, integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$audits_week = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE " . $site . " AND event_type = 'scan_completed' AND occurred_at > %s", $events_table, $week_ago ) );
		$events_week = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE ' . $site . ' AND occurred_at > %s', $events_table, $week_ago ) );
		// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- one placeholder per listed type and per watched option, counted from the same arrays.
		$last_change = $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(occurred_at) FROM %i WHERE ' . $site . ' AND ( event_type IN (' . implode( ',', array_fill( 0, count( self::CHANGES_MADE ), '%s' ) ) . ") OR ( event_type = 'setting_changed' AND object_type IN ('setting','hardening') AND COALESCE(object_id, '') NOT IN (" . implode( ',', array_fill( 0, count( $core_options ), '%s' ) ) . ') ) )', array_merge( array( $events_table ), self::CHANGES_MADE, $core_options ) ) );
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$next_run = wp_next_scheduled( 'bettershield_daily_audit' );

		return array(
			'score'            => $score,
			'grade'            => self::grade( $score ),
			// Where it has been, so the ring can say whether the work moved
			// anything rather than only where the site stands today.
			'history'          => self::score_history(),
			// The two parts of the score and whether the critical cap held it
			// down, so the ring can show how it was reached.
			'buckets'          => array(
				'setup'  => array(
					'earned' => $scored['setup'],
					'of'     => self::SETUP_TOTAL,
				),
				'health' => array(
					'earned' => $scored['health'],
					'of'     => self::HEALTH_TOTAL,
				),
				'capped' => $scored['capped'],
				'cap'    => self::CRITICAL_CAP,
			),
			'projected_score'  => $projected,
			'projected_grade'  => self::grade( $projected ),
			// The score with the critical and high findings fixed, from the
			// same calculation, for the line that asks for them first.
			'serious_fixed_score' => $serious,
			'generated_at'     => $meta['generated_at'] ?? null,
			'duration_ms'      => $meta['duration_ms'] ?? null,
			'checks_count'     => $checks_total,
			// How many of them actually answered. Fewer than the total means
			// the rest kept whatever they reported last, so no line built on
			// this payload may call the run complete.
			'checks_ran'       => $checks_ran,
			// And which ones did not, with the reason each gave. A count says
			// something is unknown; this says what, which is the difference
			// between ignoring it and fixing the rule that caused it.
			'checks_unknown'   => self::unanswered(),
			'open_findings'    => count( $findings ),
			// Of those, how many the owner has snoozed. They still count in
			// the score and in the number above.
			'snoozed_findings' => count( array_filter( array_column( $findings, 'snoozed_until' ) ) ),
			// What the owner took out of the score on their own word, which
			// the Not applicable tab lists: the score says so beside itself.
			'marked_findings'  => $marked,
			'findings'         => $findings,
			'receipts'         => array(
				'audits_week'      => $audits_week,
				'hardening_active' => $hardening_active,
				'events_week'      => $events_week,
				// Read straight out of a column, so it carries no zone marker
				// until it is given one.
				'last_change_at'   => Time::utc_iso( null !== $last_change ? (string) $last_change : null ),
			),
			'next_check_at'    => false !== $next_run ? gmdate( 'c', $next_run ) : null,
			// Whether each part of this plugin's own record keeping is
			// working. One option read: a screen that reports a table it
			// cannot reach must not need that table to say so.
			'readiness'        => \BetterShield\Database\Readiness::report(),
			'first_run'        => \BetterShield\Onboarding\FirstRun::state(),
			'safe_mode'        => array(
				'active'     => \BetterShield\Recovery\SafeMode::is_active(),
				'until'      => null !== \BetterShield\Recovery\SafeMode::until()
					? gmdate( 'c', \BetterShield\Recovery\SafeMode::until() )
					: null,
				// Only the network's pause running, which this site cannot end.
				'by_network' => ! \BetterShield\Recovery\SafeMode::is_site_active() && \BetterShield\Recovery\SafeMode::is_network_active(),
			),
			// Muting is the one alert setting that belongs on a posture payload:
			// a site that has been silenced looks identical to a quiet one from
			// the outside, and the difference is the owner's to see.
			'alerts_muted'     => \BetterShield\Alerts\Settings::instance()->is_muted(),
			'recovery_link_exists' => \BetterShield\Recovery\RecoveryLink::link_exists(),
			// The way back that does not need email to arrive.
			'recovery_codes_left'  => \BetterShield\Recovery\OfflineCodes::remaining(),
			'recovery_codes_issued' => \BetterShield\Recovery\OfflineCodes::ever_issued(),
			'recovery_readiness'   => \BetterShield\Recovery\Readiness::report(),
			// Tri-state on purpose: null means nothing was ever recorded — a
			// link generated from the dashboard is read on screen and never
			// mailed — and only an outright false is worth telling the owner
			// about.
			'recovery_link_mailed' => self::recovery_mail_result(),
			// Whether the owner said the recovery email arrived ('confirmed',
			// 'pending', or '' with no usable link), and whether any way back
			// in is confirmed: what the "No way back in" finding reads.
			'recovery_receipt'     => \BetterShield\Onboarding\QuickSetup::recovery_receipt(),
			'recovery_confirmed'   => \BetterShield\Onboarding\QuickSetup::recovery_ready(),
			// What this plugin cost the visitors of this site, from this site's
			// own traffic. Null until enough page views have been sampled to
			// say anything — a figure drawn from three of them would be argued
			// with for the rest of the version's life.
			'front_end_cost'       => \BetterShield\Support\Cost::published(),
		);
	}

	/**
	 * Whether the mail carrying the recovery link on record was accepted for sending for
	 * sending, or null where no attempt was ever recorded.
	 *
	 * Public because the first-run state and the Quick Setup read the same
	 * option, and read it differently: one reader for one option, or two
	 * screens disagree about whether a mail failed or was never attempted.
	 *
	 * `Recovery\RecoveryLink::usable()` is the third reader, and it is the
	 * reason the three states must stay three. Only a recorded failure means
	 * nobody received a link; null means no send was ever attempted, which is
	 * a link read on screen and the strongest way back there is. Collapse null
	 * into false and the setting that takes a password away starts refusing
	 * the sites best placed to arm it.
	 */
	public static function recovery_mail_result(): ?bool {
		$recorded = get_option( 'bettershield_recovery_mailed', null );

		return null === $recorded ? null : '1' === $recorded;
	}

	/**
	 * Evaluate the checks that are read live, and reconcile their findings.
	 *
	 * The audit publishes findings from a scheduled task. For most checks
	 * that is the right cadence; for a check about whether scheduled tasks
	 * run at all it is the wrong channel — the audit that would raise it is
	 * stalled with everything else, and once the schedule catches up the
	 * finding stays open until the next daily run. A check declared `live`
	 * is asked again whenever the posture is read, and its row is opened or
	 * resolved on the spot. Cheap by construction: the one such check reads
	 * an autoloaded option and nothing else.
	 */
	private static function refresh_live(): void {
		if ( ! Schema::ready( 'findings' ) ) {
			return;
		}

		$now      = ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
		$manager  = Manager::instance();
		$statuses = self::statuses( $levels );

		foreach ( Checks::all() as $key => $check ) {
			if ( ! empty( $check['live'] ) ) {
				$evidence = ( $check['test'] )();

				if ( is_wp_error( $evidence ) ) {
					continue;
				}

				if ( null === $evidence ) {
					self::mark_resolved( $key, $now );
					continue;
				}

				self::mark_open( $key, self::SEVERITY_LEVELS[ Checks::severity_of( $check ) ], $evidence, $now, false );
				continue;
			}

			/*
			 * A setup essential whose answer changes outside an audit run — a
			 * two-factor requirement saved, the recovery email confirmed, a
			 * common name refused — is re-read here so the score moves at
			 * once. Only a flip, or a change of weight, is written: this is the most-requested
			 * endpoint, and a write per read would churn every open row's
			 * freshness. A check the audit has never met is left to it.
			 */
			if ( ! empty( $check['reread'] ) ) {
				$status = $statuses[ $key ] ?? null;

				if ( null === $status || 'suppressed' === $status ) {
					continue;
				}

				$evidence = ( $check['test'] )();

				if ( is_wp_error( $evidence ) ) {
					continue;
				}

				$level = self::SEVERITY_LEVELS[ Checks::severity_of( $check ) ];

				if ( null === $evidence && 'open' === $status ) {
					self::mark_resolved( $key, $now );
				} elseif ( null !== $evidence && 'fixed' === $status ) {
					self::mark_open( $key, $level, $evidence, $now, false );
				} elseif ( null !== $evidence && 'open' === $status && $level !== ( $levels[ $key ] ?? $level ) ) {
					// Still open at another weight, as XML-RPC is once its
					// pingbacks are blocked: the row moves, and the score with it.
					self::mark_open( $key, $level, $evidence, $now, false );
				}

				continue;
			}

			/*
			 * A check tied to a protection is re-read where its row and the
			 * protection disagree: an open row for an item that is applied,
			 * or a closed row for one that is not. The dashboard's apply and
			 * revert run the audit afterwards; an assistant's do not, and a
			 * fix it applied a moment ago answered as still open — or, worse,
			 * as applied and not enforced, which is the reading safe mode
			 * earns. Only a flip is written, so a protection that is paused
			 * keeps its open row without a write per read, and a suppressed
			 * row is never touched.
			 */
			$item = $check['hardening_item'] ?? null;

			if ( null === $item ) {
				continue;
			}

			$status = $statuses[ $key ] ?? null;

			if ( 'suppressed' === $status ) {
				continue;
			}

			$active = $manager->is_active( (string) $item );

			if ( ( $active && 'open' !== $status ) || ( ! $active && 'fixed' !== $status ) ) {
				continue;
			}

			$evidence = ( $check['test'] )();

			if ( is_wp_error( $evidence ) ) {
				continue;
			}

			if ( null === $evidence && 'open' === $status ) {
				self::mark_resolved( $key, $now );
			} elseif ( null !== $evidence && 'fixed' === $status ) {
				self::mark_open( $key, self::SEVERITY_LEVELS[ Checks::severity_of( $check ) ], $evidence, $now, false );
			}
		}
	}

	/**
	 * Every finding row's status on this site, keyed by finding.
	 *
	 * @param array<string, int>|null $levels Filled with each row's recorded severity, keyed the same.
	 * @return array<string, string>
	 */
	private static function statuses( ?array &$levels = null ): array {
		global $wpdb;

		$levels = array();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT finding_key, status, severity FROM %i WHERE ' . Schema::site_where( 'findings' ), Schema::table( 'findings' ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$statuses = array();

		foreach ( (array) $rows as $row ) {
			$statuses[ (string) $row->finding_key ] = (string) $row->status;
			$levels[ (string) $row->finding_key ]   = (int) $row->severity;
		}

		return $statuses;
	}

	/** Why a check could not answer on the last run, or '' when it did. */
	private static function unknown_reason( string $key ): string {
		$meta = get_option( self::META_OPTION, array() );

		return (string) ( is_array( $meta ) ? ( $meta['checks_unknown'][ $key ]['reason'] ?? '' ) : '' );
	}

	/**
	 * The checks that could not answer on the last run, each with the reason
	 * it gave and when it last did answer.
	 *
	 * @return array<int, array{key: string, title: string, code: string, reason: string, last_answered_at: string}>
	 */
	public static function unanswered(): array {
		$meta    = get_option( self::META_OPTION, array() );
		$unknown = is_array( $meta ) && isset( $meta['checks_unknown'] ) && is_array( $meta['checks_unknown'] ) ? $meta['checks_unknown'] : array();
		$out     = array();

		foreach ( $unknown as $key => $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			$out[] = array(
				'key'              => (string) $key,
				'title'            => (string) ( $entry['title'] ?? $key ),
				'code'             => (string) ( $entry['code'] ?? '' ),
				'reason'           => (string) ( $entry['reason'] ?? '' ),
				'last_answered_at' => (string) self::last_answered_at( (string) $key ),
			);
		}

		return $out;
	}

	/**
	 * When a check last produced an answer, pass or fail, in UTC and marked
	 * as such, or '' when that is not known.
	 *
	 * Recorded by each run. Where no run has recorded it yet, only the
	 * findings row is left, and its last-seen time is the last answer only
	 * while the row is open: a failing check that is still failing updates it
	 * on every run, and one that has since passed or been suppressed does not.
	 */
	private static function last_answered_at( string $key ): string {
		global $wpdb;

		$meta = get_option( self::META_OPTION, array() );

		if ( is_array( $meta ) && isset( $meta['checks_answered'][ $key ] ) && is_string( $meta['checks_answered'][ $key ] ) ) {
			return $meta['checks_answered'][ $key ];
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers from Schema::site_where(); the key and the table are bound.
		$at = $wpdb->get_var( $wpdb->prepare( "SELECT last_seen_at FROM %i WHERE " . Schema::site_where( 'findings' ) . " AND finding_key=%s AND status = 'open'", Schema::table( 'findings' ), $key ) );
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_string( $at ) ? (string) Time::utc_iso( $at ) : '';
	}

	/**
	 * The checks the last run could not evaluate, whose rows it kept rather
	 * than overwriting with a false negative.
	 *
	 * Empty for every run in which every check answered, and empty on a site
	 * whose last run predates the option carrying the list — which reads as
	 * "nothing known to be stale" rather than as a claim that nothing is.
	 *
	 * @return array<int, string>
	 */
	private static function kept_stale(): array {
		$meta = get_option( self::META_OPTION, array() );
		$kept = is_array( $meta ) && isset( $meta['checks_stale'] ) && is_array( $meta['checks_stale'] )
			? $meta['checks_stale']
			: array();

		return array_values( array_filter( $kept, 'is_string' ) );
	}

	/**
	 * Whether a finding's one-click fix can be applied here: it names an
	 * item, and that item is on already or can work on this server. An item
	 * that cannot (an .htaccess rule on nginx) would show Apply fix and fail,
	 * so the finding is not counted as fixable in one click.
	 */
	public static function remediable( ?string $item ): bool {
		if ( null === $item ) {
			return false;
		}

		$manager = \BetterShield\Hardening\Manager::instance();

		return $manager->is_active( $item ) || $manager->available( $item );
	}

	/**
	 * The full report as the plugin's own screens show it: the same rows,
	 * with each open finding's evidence as this reader may see it. Only for
	 * the screens — an assistant, a provider, the hub and the digest read
	 * `findings()`, which never carries more than the row stored.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function findings_for_reader(): array {
		return array_map(
			static function ( array $finding ): array {
				if ( 'open' === $finding['status'] ) {
					$finding['evidence'] = Checks::evidence_for_reader( (string) $finding['id'], $finding['evidence'] );
				}

				return $finding;
			},
			self::findings()
		);
	}

	/**
	 * Every finding on record, whatever its status — the full report the
	 * Findings screen shows. Nothing here is withheld or summarized.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function findings(): array {
		global $wpdb;

		self::refresh_live();

		$checks          = Checks::all();
		$severity_labels = array_flip( self::SEVERITY_LEVELS );
		$stale           = self::kept_stale();
		$manager         = Manager::instance();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare( 'SELECT finding_key, severity, status, first_seen_at, last_seen_at, resolved_at, evidence FROM %i WHERE ' . Schema::site_where( 'findings' ), Schema::table( 'findings' ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		// Same guard as overview(), for the same reason.
		$rows = is_array( $rows ) ? $rows : array();

		$out = array();

		foreach ( $rows as $row ) {
			if ( ! isset( $checks[ $row->finding_key ] ) ) {
				continue; // A finding left behind by a removed check.
			}

			$check  = $checks[ $row->finding_key ];
			$level  = (int) $row->severity;
			$active = null !== $check['hardening_item'] && $manager->is_active( (string) $check['hardening_item'] );

			$out[] = array(
				'id'               => $row->finding_key,
				'group'            => $check['group'],
				'severity'         => $severity_labels[ $level ] ?? 'info',
				'severity_level'   => $level,
				'status'           => (string) $row->status,
				'title'            => Checks::title_of( $check, $severity_labels[ $level ] ?? null ),
				'why'              => $check['why'],
				'break_note'       => $check['break_note'],
				'remediable'       => self::remediable( $check['hardening_item'] ),
				'hardening_item'   => $check['hardening_item'],
				// Configured state beside measured state, for the same reason
				// the overview payload carries it: an item that is applied and
				// not enforcing has no press the endpoint can accept.
				'hardening_active' => $active,
				// Standing on evidence the last run could not confirm.
				'stale'            => in_array( (string) $row->finding_key, $stale, true ),
				'stale_reason'     => self::unknown_reason( (string) $row->finding_key ),
				'control'          => Checks::control_for( (string) $row->finding_key ) ?? Checks::control_when_applied( (string) $row->finding_key, $active ),
				'deduction'        => self::deduction_of( (string) $row->finding_key, $level ),
				'score_item'       => self::score_item_of( (string) $row->finding_key ),
				'self_managed'     => self::is_self_managed( (string) $row->finding_key ),
				'partly_handled'   => 'open' === (string) $row->status && Checks::partly_handled( (string) $row->finding_key ),
				// Column values, marked as UTC before they leave: unmarked, a
				// browser reads them as local time and every "first seen" on the
				// report is displaced by the reader's own offset.
				'first_seen_at'    => Time::utc_iso( (string) $row->first_seen_at ),
				'last_seen_at'     => Time::utc_iso( (string) $row->last_seen_at ),
				'resolved_at'      => Time::utc_iso( null !== $row->resolved_at ? (string) $row->resolved_at : null ),
				'evidence'         => json_decode( (string) $row->evidence, true ),
				'snoozed_until'    => 'open' === (string) $row->status ? Snooze::until_iso( (string) $row->finding_key ) : null,
			);
		}

		// Open first, then suppressed, then fixed; highest severity within each.
		$rank = array(
			'open'       => 0,
			'suppressed' => 1,
			'fixed'      => 2,
		);

		usort(
			$out,
			static function ( array $a, array $b ) use ( $rank ): int {
				$a_rank = $rank[ $a['status'] ] ?? 3;
				$b_rank = $rank[ $b['status'] ] ?? 3;

				if ( $a_rank !== $b_rank ) {
					return $a_rank <=> $b_rank;
				}

				if ( $a['severity_level'] !== $b['severity_level'] ) {
					return $b['severity_level'] <=> $a['severity_level'];
				}

				return (int) $b['remediable'] <=> (int) $a['remediable'];
			}
		);

		return $out;
	}

	/**
	 * Mark a finding not applicable to this site. It stops scoring and stops
	 * reappearing, and the decision is logged.
	 *
	 * @return true|\WP_Error
	 */
	public static function suppress( string $key ) {
		$result = self::set_status( $key, 'suppressed', 'open' );

		// The stronger decision replaces a snooze, so the finding put back
		// later returns open rather than still set aside.
		if ( true === $result ) {
			Snooze::release( $key );
		}

		return $result;
	}

	/**
	 * Return a suppressed finding to the report. The status goes back to open
	 * and the checks re-run immediately, so a finding that was fixed while it
	 * was suppressed is shown as fixed rather than resurfacing as a problem.
	 *
	 * @return true|\WP_Error
	 */
	public static function unsuppress( string $key ) {
		$result = self::set_status( $key, 'open', 'suppressed' );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		self::run();

		return true;
	}

	/**
	 * @return true|\WP_Error
	 */
	private static function set_status( string $key, string $to, string $from ) {
		global $wpdb;

		if ( ! isset( Checks::all()[ $key ] ) ) {
			return new \WP_Error( 'bettershield_unknown_finding', __( 'Unknown finding.', 'bettershield' ), array( 'status' => 404 ) );
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- read fresh from this plugin's own table; the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$severity = (int) $wpdb->get_var(
			$wpdb->prepare( 'SELECT severity FROM %i WHERE ' . Schema::site_where( 'findings' ) . ' AND finding_key = %s AND status = %s', Schema::table( 'findings' ), $key, $from )
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$updated = $wpdb->update(
			Schema::table( 'findings' ),
			array( 'status' => $to ),
			array(
				'site_id'     => Schema::site_id( 'findings' ),
				'finding_key' => $key,
				'status'      => $from,
			),
			array( '%s' ),
			array( '%d', '%s', '%s' )
		);

		if ( 1 !== $updated ) {
			return new \WP_Error(
				'bettershield_finding_not_in_state',
				__( 'This finding’s status does not allow that change.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		/*
		 * Setting a finding aside is said at the weight of the finding, as its
		 * opening was: a critical one hidden from the report reaches the
		 * instant path, whoever hid it, and an info one stays at the floor.
		 * Bringing one back takes nothing away, so it stays quiet.
		 */
		Writer::instance()->record(
			'suppressed' === $to ? 'finding_suppressed' : 'finding_unsuppressed',
			'suppressed' === $to ? max( Writer::SEVERITY_LOW, $severity ) : Writer::SEVERITY_LOW,
			array(
				'object_type' => 'finding',
				'object_id'   => $key,
			)
		);

		return true;
	}

	public static function grade( int $score ): string {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 75 ) {
			return 'B';
		}
		if ( $score >= 60 ) {
			return 'C';
		}
		if ( $score >= 45 ) {
			return 'D';
		}

		return 'F';
	}

	/* ---- finding lifecycle ----------------------------------------- */

	/**
	 * Whether a check answered on the last run and found nothing: it ran, it
	 * wasn't one that couldn't tell, and its finding isn't open. Read from what
	 * the run stored, so asking costs no request.
	 */
	public static function passed_last_run( string $key ): bool {
		$meta = get_option( self::META_OPTION, array() );

		if ( ! is_array( $meta ) || ! isset( $meta['checks_answered'][ $key ] ) || isset( $meta['checks_unknown'][ $key ] ) ) {
			return false;
		}

		return ! self::is_open( $key );
	}

	/**
	 * Drop a check's answer from the last run, when what it answered about
	 * has just changed and the next run hasn't asked again.
	 */
	public static function forget_answer( string $key ): void {
		$meta = get_option( self::META_OPTION, array() );

		if ( is_array( $meta ) && isset( $meta['checks_answered'][ $key ] ) ) {
			unset( $meta['checks_answered'][ $key ] );
			update_option( self::META_OPTION, $meta, false );
		}
	}

	/**
	 * Whether a finding is open now, read from its row.
	 */
	public static function is_open( string $key ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$status = $wpdb->get_var( $wpdb->prepare( 'SELECT status FROM %i WHERE ' . Schema::site_where( 'findings' ) . ' AND finding_key = %s', Schema::table( 'findings' ), $key ) );

		return 'open' === $status;
	}

	/**
	 * The severity level a check's finding is opened at, or -1 for no such check.
	 */
	public static function level_for( string $key ): int {
		$checks = Checks::all();

		return isset( $checks[ $key ] ) ? self::SEVERITY_LEVELS[ Checks::severity_of( $checks[ $key ] ) ] : -1;
	}

	/**
	 * The open findings as the next audit would leave them for these checks.
	 *
	 * Each is read again, and nothing is written. A check that cannot answer
	 * keeps what its row says, and one the owner set aside stays set aside, as
	 * they do in a real run.
	 *
	 * @param string[] $keys The checks to read again.
	 * @return array<string, int> Severity level by finding key.
	 */
	public static function open_levels_reading( array $keys ): array {
		$open     = self::open_levels();
		$checks   = Checks::all();
		$statuses = self::statuses();

		foreach ( $keys as $key ) {
			if ( ! isset( $checks[ $key ]['test'] ) || 'suppressed' === ( $statuses[ $key ] ?? '' ) ) {
				continue;
			}

			$evidence = ( $checks[ $key ]['test'] )();

			if ( is_wp_error( $evidence ) ) {
				continue;
			}

			if ( null === $evidence ) {
				unset( $open[ $key ] );
			} else {
				$open[ $key ] = self::level_for( $key );
			}
		}

		return $open;
	}

	/**
	 * Open one finding now, without running an audit.
	 *
	 * Almost everything an audit reports was already true yesterday and will
	 * still be true tomorrow, so the daily run is the right moment to notice
	 * it. A few things are not like that: a mechanism this plugin is refusing
	 * requests on behalf of, discovered by the request it refused. Waiting for
	 * the next scheduled run would leave the owner with a site behaving
	 * strangely and nothing on any screen saying why.
	 *
	 * The finding is otherwise ordinary — same row, same severity ladder, same
	 * `finding_opened` event at its own weight — so the next audit closes it
	 * the way it closes any other, when the check that owns it stops finding
	 * anything.
	 *
	 * @param array<string, mixed> $evidence
	 * @return bool Whether the finding is now open. False for a key no check
	 *              owns, and for one the owner has suppressed.
	 */
	public static function open_now( string $key, array $evidence = array() ): bool {
		$checks = Checks::all();

		if ( ! isset( $checks[ $key ] ) ) {
			return false;
		}

		return 'open' === self::mark_open(
			$key,
			self::SEVERITY_LEVELS[ Checks::severity_of( $checks[ $key ] ) ],
			$evidence,
			( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' )
		);
	}

	/**
	 * @param bool $baseline Whether this is the site's first audit, on which
	 *                       nothing that opens is news.
	 * @return string The status the finding was left in: `open` or `suppressed`.
	 */
	private static function mark_open( string $key, int $severity, array $evidence, string $now, bool $baseline = false ): string {
		global $wpdb;

		$table    = Schema::table( 'findings' );
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$existing = $wpdb->get_row(
			$wpdb->prepare( 'SELECT id, status, severity, resolved_at, evidence FROM %i WHERE ' . Schema::site_where( 'findings' ) . ' AND finding_key = %s', $table, $key )
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$encoded = (string) wp_json_encode( $evidence );

		if ( null === $existing ) {
			$wpdb->insert(
				$table,
				array(
					'site_id'       => Schema::site_id( 'findings' ),
					'finding_key'   => $key,
					'severity'      => $severity,
					'status'        => 'open',
					'first_seen_at' => $now,
					'last_seen_at'  => $now,
					'evidence'      => $encoded,
				),
				array( '%d', '%s', '%d', '%s', '%s', '%s', '%s' )
			);

			self::record_opened( $key, $severity, $baseline );

			return 'open';
		}

		// A suppressed finding stays suppressed; it never resurfaces on
		// its own, only its freshness updates.
		$status = 'suppressed' === $existing->status ? 'suppressed' : 'open';

		$wpdb->update(
			$table,
			array(
				'severity'     => $severity,
				'status'       => $status,
				'last_seen_at' => $now,
				'resolved_at'  => null,
				'evidence'     => $encoded,
			),
			array( 'id' => $existing->id )
		);

		// A finding that had been closed and is back is the same news as one
		// arriving for the first time: something that was working has stopped.
		// The row itself cannot say so — nothing on it is new — which is why
		// this is the only place it gets said.
		if ( 'fixed' === $existing->status && 'open' === $status ) {
			self::record_opened( $key, $severity, $baseline, self::is_repeat( $key, $existing, $severity, $evidence ) );
		}

		return $status;
	}

	/**
	 * Say that a finding is now open, at the weight the finding itself carries.
	 *
	 * The severity ladder here is the writer's ladder — both run info through
	 * critical over the same five values — so a critical finding reaches the
	 * instant path and a low one waits for the summary, which is the whole
	 * point of recording it at its own level rather than at a fixed one.
	 */
	private static function record_opened( string $key, int $severity, bool $baseline, bool $repeat = false ): void {
		if ( $baseline ) {
			return;
		}

		$event = array(
			'object_type' => 'finding',
			'object_id'   => $key,
		);

		if ( $repeat ) {
			$event['context'] = array( 'repeat' => true );
		}

		Writer::instance()->record( 'finding_opened', $severity, $event );
	}

	/**
	 * Whether a finding coming back is the problem already told about: closed
	 * within the last two weeks, no worse than it was, and naming nothing it
	 * didn't name then, such as another tool or a newer release.
	 *
	 * @param string               $key      The finding.
	 * @param object               $existing The finding's row as it stood.
	 * @param array<string, mixed> $evidence What it found this time.
	 */
	private static function is_repeat( string $key, object $existing, int $severity, array $evidence ): bool {
		$closed = null === $existing->resolved_at ? false : strtotime( (string) $existing->resolved_at . ' UTC' );

		return false !== $closed
			&& ( time() - $closed ) < self::REPEAT_DAYS * DAY_IN_SECONDS
			&& $severity <= (int) $existing->severity
			&& ! self::total_rose( $evidence, json_decode( (string) $existing->evidence, true ) )
			&& array() === array_diff( self::names_in( $evidence, $key ), self::names_in( json_decode( (string) $existing->evidence, true ), $key ) );
	}

	/**
	 * Whether a finding now counts more of what it names than it did.
	 *
	 * Numbers are otherwise left out, because most are readings. A top-level
	 * `total` is not: it counts the things the finding names, and the list
	 * beside it is often cut short, so a higher total is something new the
	 * list may not show, such as another tampered day older than the ten named.
	 * A lower one is fewer of the same, which is no news.
	 *
	 * @param array<string, mixed> $evidence What it found this time.
	 * @param mixed                $was      What it found when it closed.
	 */
	private static function total_rose( array $evidence, $was ): bool {
		return is_int( $evidence['total'] ?? null )
			&& is_array( $was )
			&& is_int( $was['total'] ?? null )
			&& $evidence['total'] > $was['total'];
	}

	/**
	 * The words a finding's evidence names, each with where it sits. Moments
	 * and numbers are left out: they change between any two readings of one
	 * problem. A moment is known by its key, never by its value: a day listed
	 * as what the finding is about, such as a day whose log was changed, names
	 * the problem, and another day is another problem.
	 *
	 * @param mixed  $evidence A finding's evidence, or a part of it.
	 * @param string $key      The finding.
	 * @return string[]
	 */
	private static function names_in( $evidence, string $key, string $path = '' ): array {
		// A disk's evidence is its folder and how much is free, and the folder is what it names.
		if ( 'disk_space_low' === $key ) {
			return array_map( 'strval', array_keys( (array) $evidence ) );
		}

		if ( is_array( $evidence ) ) {
			$names = array();

			foreach ( $evidence as $name => $value ) {
				if ( is_string( $name ) && 1 === preg_match( '/(_at|_as_of|_since|_ago)$|^(behind|last_run|last_error|when)$/', $name ) ) {
					continue;
				}

				$names = array_merge( $names, self::names_in( $value, $key, is_string( $name ) ? $path . '/' . $name : $path ) );
			}

			return $names;
		}

		return is_string( $evidence ) && '' !== $evidence ? array( $path . '=' . $evidence ) : array();
	}

	private static function mark_resolved( string $key, string $now ): void {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$closed = $wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'fixed', resolved_at = %s, last_seen_at = %s WHERE " . Schema::site_where( 'findings' ) . " AND finding_key = %s AND status = 'open'",
				Schema::table( 'findings' ),
				$now,
				$now,
				$key
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		// Only when a row actually moved. Every audit runs this for every
		// check that passes, and most of those have no row at all — recording
		// unconditionally would write a "resolved" line per passing check per
		// day, which is the log describing itself rather than the site.
		if ( 1 !== (int) $closed ) {
			return;
		}

		// A finding that closes loses its snooze here, not only at the next
		// audit's review: closed and opened again in between — a fix applied
		// and undone by an assistant, WP-CLI or the monitor — it came back
		// still set aside, and the regression stayed hidden for its days.
		if ( null !== Snooze::until( $key ) ) {
			Snooze::release( $key );
		}

		Writer::instance()->record(
			'finding_resolved',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'finding',
				'object_id'   => $key,
			)
		);
	}
}
