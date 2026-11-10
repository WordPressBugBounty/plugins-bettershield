<?php
/**
 * What this site has scheduled, and which of it nothing answers.
 *
 * Cron is where a backdoor re-establishes itself. Removing the file is not
 * enough if a scheduled event puts it back an hour later, and the event
 * survives every plugin update, every theme switch and most cleanups because
 * nothing ever looks at the list. WordPress offers no screen for it at all.
 *
 * **This states one provable fact and refuses to guess the rest.** A hook with
 * no code behind it is a scheduled call into nothing — which is either an
 * event a removed plugin left behind, or an event waiting for code that is not
 * there yet. Both are worth an owner's eyes; neither is an accusation, and
 * this makes none.
 *
 * **What "no code behind it" can and cannot mean.** `has_action()` answers for
 * the request it is asked in. A plugin that registers its hook only on the
 * front end, or only under WP-CLI, is registered nowhere the audit can see —
 * so an event of theirs would read as unanswered here while working perfectly
 * every night. That is a false positive on a finding whose whole value is that
 * it is provable, so the finding says which request looked and the copy never
 * says the event is malicious, only that nothing answered it. Events this
 * plugin itself schedules are excluded by name rather than by luck, and so
 * by name rather than by prefix: an event planted under `bettershield_` is
 * as unanswered as any other.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cron {

	/**
	 * How many unanswered hooks are named before the finding becomes a count.
	 * A site with forty has a cleanup job, not a list to read.
	 */
	public const MAX_NAMED = 10;

	/**
	 * Core's own scheduled work, which is answered by core rather than by a
	 * plugin and is registered in places an audit request may not reach.
	 *
	 * Named rather than detected, because "it starts with wp_" is a guess and
	 * a backdoor is free to pick a name that starts with wp_.
	 */
	private const CORE_HOOKS = array(
		'wp_version_check',
		'wp_update_plugins',
		'wp_update_themes',
		'wp_scheduled_delete',
		'wp_scheduled_auto_draft_delete',
		'delete_expired_transients',
		'wp_privacy_delete_old_export_files',
		'recovery_mode_clean_expired_keys',
		'wp_site_health_scheduled_check',
		'wp_https_detection',
		'wp_delete_temp_updater_backups',
		'wp_update_user_counts',
		'do_pings',
		'publish_future_post',
		'importer_scheduled_cleanup',
		'upgrader_scheduled_cleanup',
		'wp_maybe_auto_update',
	);

	/**
	 * Everything scheduled on this site, with the one fact worth reporting.
	 *
	 * Counted by hook rather than by scheduled run. WordPress stores the
	 * schedule as a timestamp-keyed map, and a hook queued at sixty times
	 * appears sixty times in it — which was reported as sixty problems, with
	 * the same hook named ten times over. It is one thing to look at, and how
	 * often it is queued is a number on it rather than a multiplier.
	 *
	 * @return array{events: array<int, array{hook: string, next_run: string, schedule: string, scheduled: int}>, total: int, unanswered: int, readable: bool, schedule: array{behind_seconds: int, overdue: int, stalled: bool}}
	 */
	public static function report(): array {
		/*
		 * The stored option is read first, and only to answer one question:
		 * is there a schedule here to read at all. `_get_cron_array()` is the
		 * right way to get the *shape* — it applies the version upgrade older
		 * sites still need — but it answers an empty array both for a site
		 * with nothing scheduled and for a site whose option is corrupt or
		 * filtered away. Those are different sites, and reporting the second
		 * as the first would say "nothing is scheduled" about a site where
		 * nothing is known, which is the opposite of what this report is for.
		 */
		$stored = get_option( 'cron' );

		if ( ! is_array( $stored ) ) {
			return array(
				'events'     => array(),
				'total'      => 0,
				'unanswered' => 0,
				'readable'   => false,
				'schedule'   => self::schedule(),
			);
		}

		$raw = _get_cron_array();

		$own     = self::own_hooks();
		$by_hook = array();

		foreach ( $raw as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}

			foreach ( $hooks as $hook => $instances ) {
				$hook = (string) $hook;

				if ( ! is_array( $instances ) || self::is_ours_or_core( $hook, $own ) ) {
					continue;
				}

				if ( isset( $by_hook[ $hook ] ) ) {
					$by_hook[ $hook ]['scheduled'] += count( $instances );
					// The soonest run is the one worth naming: it is what the
					// reader would see happen next.
					$by_hook[ $hook ]['at']         = min( $by_hook[ $hook ]['at'], (int) $timestamp );

					continue;
				}

				$first = reset( $instances );

				$by_hook[ $hook ] = array(
					// Asked once per hook rather than once per queued run.
					'answered'  => has_action( $hook ),
					'scheduled' => count( $instances ),
					'at'        => (int) $timestamp,
					// The empty string is core's own word for "once".
					'schedule'  => (string) ( is_array( $first ) && ! empty( $first['schedule'] ) ? $first['schedule'] : 'once' ),
				);
			}
		}

		$events     = array();
		$unanswered = 0;

		foreach ( $by_hook as $hook => $found ) {
			if ( $found['answered'] ) {
				continue;
			}

			++$unanswered;

			if ( count( $events ) >= self::MAX_NAMED ) {
				continue;
			}

			$events[] = array(
				'hook'      => (string) $hook,
				'next_run'  => gmdate( 'c', $found['at'] ),
				'schedule'  => $found['schedule'],
				'scheduled' => $found['scheduled'],
			);
		}

		return array(
			'events'     => $events,
			'total'      => count( $by_hook ),
			'unanswered' => $unanswered,
			'readable'   => true,
			'schedule'   => self::schedule(),
		);
	}

	/**
	 * Whether the schedule itself is being run.
	 *
	 * The report above is about what is scheduled; this is about whether
	 * anything runs it, which is a different question with a different
	 * failure. A schedule can be entirely answered and entirely stopped —
	 * every hook waiting behind an appointment nothing has kept — and on
	 * such a site "unanswered: 0" read as a clean bill. Measured on this
	 * plugin's own hooks, the ones it knows the interval of; see
	 * `Cron\Runner::schedule_lag()` for why a passed appointment is proof.
	 *
	 * @return array{behind_seconds: int, overdue: int, stalled: bool}
	 */
	public static function schedule(): array {
		$lag = \BetterShield\Cron\Runner::schedule_lag();

		return array(
			'behind_seconds' => $lag['behind_seconds'],
			// Hooks that have missed a whole cycle of their own recurrence.
			'overdue'        => $lag['overdue'],
			'stalled'        => $lag['overdue'] > 0,
		);
	}

	/**
	 * The hooks this plugin, and an add-on through its task names, schedules.
	 *
	 * Named, as core's are, because a prefix is a guess too: excluded by its
	 * `bettershield_` prefix, an event planted to run code that has not
	 * arrived yet could hide under this plugin's name and never be counted
	 * (#1815). Every task the runner registers has a name in the labels, and
	 * is answered wherever it is registered anyway.
	 *
	 * @return string[]
	 */
	public static function own_hooks(): array {
		return array_values(
			array_unique(
				array_merge(
					array_keys( \BetterShield\Cron\Labels::all() ),
					array(
						// Sent once, soon after setup; never a recurring task.
						\BetterShield\Onboarding\Usage::FIRST_TASK,
					)
				)
			)
		);
	}

	/**
	 * Whether this hook is core's own work or this plugin's.
	 *
	 * Both are answered by code that is registered somewhere an audit request
	 * may not reach, so reporting them would be reporting the tool.
	 *
	 * @param string[] $own What own_hooks() names.
	 */
	private static function is_ours_or_core( string $hook, array $own ): bool {
		return in_array( $hook, $own, true ) || in_array( $hook, self::CORE_HOOKS, true );
	}
}
