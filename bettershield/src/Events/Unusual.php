<?php
/**
 * What is unusual for this site, measured against its own last thirty days.
 *
 * Every volume rule elsewhere is a fixed number. A fixed number is too loud
 * for a busy store and too quiet for a brochure site. This keeps a small
 * daily record of two things the plugin already writes — failed sign-ins,
 * and how long each hourly task went between runs — and notes when the
 * present is out of line with that record.
 *
 * Plain rules, no model:
 *
 * - failed sign-ins in the last hour above both a floor and several times
 *   this site's usual hourly count;
 * - an hourly task that went more than three hours, and more than three times
 *   its own longest gap of the last thirty days, between runs.
 *
 * A note is one event at medium, `activity_unusual`, with what was seen and
 * what is usual; at most one per measure per hour. Medium stays out of the
 * instant path, nothing is blocked, and nothing is said at all until fourteen
 * days of history exist. With sign-in protection off or in safe mode nothing
 * reaches the attempts table, so that measure stands down rather than reading
 * a quiet day.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Database\Schema;
use BetterShield\Login\Protection;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Unusual {

	/** The daily record. Small, per site, never autoloaded. */
	public const OPTION = 'bettershield_activity_baseline';

	/** The hourly task that asks whether this hour's sign-ins are out of line. */
	public const TASK = 'bettershield_unusual_check';

	/** The event a note is recorded as. */
	public const EVENT = 'activity_unusual';

	/** When the plugin was last switched off here, so a gap across it is not a stall. */
	public const DEACTIVATED = 'bettershield_deactivated_at';

	/** Days kept. */
	public const DAYS = 30;

	/** Days of history before anything is said. */
	public const QUIET_DAYS = 14;

	/** Failed sign-ins in an hour below this are never unusual, whatever the history. */
	public const SIGNIN_FLOOR = 20;

	/** How many times the usual hourly count an hour has to reach. */
	public const SIGNIN_FACTOR = 5;

	/** A gap between hourly runs shorter than this is never unusual. */
	public const GAP_FLOOR = 3 * HOUR_IN_SECONDS;

	/** How many times its longest usual gap a task has to go. */
	public const GAP_FACTOR = 3;

	/**
	 * The record, cleaned: day => { signin_failed?: int, gaps?: { hook: seconds } }.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function days(): array {
		$stored = get_option( self::OPTION, array() );
		$days   = array();

		// The last thirty calendar days, not the last thirty recorded: after
		// months switched off, the record would otherwise still count as two
		// weeks of history and measure today against a different season.
		$since = gmdate( 'Y-m-d', time() - self::DAYS * DAY_IN_SECONDS );

		foreach ( is_array( $stored ) ? $stored : array() as $day => $values ) {
			if ( ! is_string( $day ) || 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) || ! is_array( $values ) || $day < $since ) {
				continue;
			}

			$clean = array();

			if ( isset( $values['signin_failed'] ) && is_numeric( $values['signin_failed'] ) ) {
				$clean['signin_failed'] = max( 0, (int) $values['signin_failed'] );
			}

			foreach ( (array) ( $values['gaps'] ?? array() ) as $hook => $gap ) {
				if ( is_string( $hook ) && is_numeric( $gap ) ) {
					$clean['gaps'][ $hook ] = max( 0, (int) $gap );
				}
			}

			$days[ $day ] = $clean;
		}

		ksort( $days );

		return array_slice( $days, -self::DAYS, null, true );
	}

	/** @param array<string, array<string, mixed>> $days */
	private static function save( array $days ): void {
		ksort( $days );
		update_option( self::OPTION, array_slice( $days, -self::DAYS, null, true ), false );
	}

	/* ---- failed sign-ins -------------------------------------------------- */

	/**
	 * Add each finished day's failed sign-ins to the record, before the
	 * attempts table forgets them. Called by the daily prune, ahead of its
	 * delete; a day already recorded is left as it was.
	 */
	public static function roll_up_signins(): void {
		global $wpdb;

		$days  = self::days();
		$today = gmdate( 'Y-m-d' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- a bounded aggregate of this plugin's own table, once a day.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(occurred_at) AS day, COUNT(*) AS failed FROM %i WHERE site_id = 0 AND surface = 'signin' AND outcome = 'failed' AND occurred_at < %s GROUP BY DATE(occurred_at)",
				Schema::table( 'login_attempts' ),
				$today . ' 00:00:00.000'
			)
		);

		if ( '' !== $wpdb->last_error || ! is_array( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			$day = (string) $row->day;

			if ( ! isset( $days[ $day ]['signin_failed'] ) ) {
				$days[ $day ]['signin_failed'] = (int) $row->failed;
			}
		}

		/*
		 * A finished day with nothing in the table had no failures, provided
		 * something was counting: it is part of the usual too. Every such day
		 * since counting began, not only yesterday. The table answers only
		 * for days that had failures, and a quiet day the job did not run on
		 * was never filled, so the usual was the average of busy days alone
		 * and the quiet period ended after fourteen busy ones.
		 */
		if ( self::signins_counted() ) {
			$yesterday = gmdate( 'Y-m-d', time() - DAY_IN_SECONDS );
			$counted   = array_keys( array_filter( $days, static fn( array $values ): bool => isset( $values['signin_failed'] ) ) );
			$from      = array() === $counted ? $yesterday : min( min( $counted ), $yesterday );

			for ( $at = (int) strtotime( $from . ' 00:00:00 UTC' ); gmdate( 'Y-m-d', $at ) <= $yesterday; $at += DAY_IN_SECONDS ) {
				$day = gmdate( 'Y-m-d', $at );

				if ( ! isset( $days[ $day ]['signin_failed'] ) ) {
					$days[ $day ]['signin_failed'] = 0;
				}
			}
		}

		self::save( $days );
	}

	/** Whether failed sign-ins reach the attempts table right now. */
	private static function signins_counted(): bool {
		$settings = Protection::instance()->settings();

		return ! SafeMode::is_active() && ! empty( $settings['enabled'] ) && ! empty( $settings['attempt_limit'] );
	}

	/**
	 * The hourly check: failed sign-ins in the last hour against this site's
	 * usual hour.
	 *
	 * @return array{observed: int, usual: float}|null What was noted, or null.
	 */
	public static function check_signins(): ?array {
		if ( ! self::signins_counted() ) {
			return null;
		}

		$counts = array_values(
			array_filter(
				array_map( static fn( array $values ) => $values['signin_failed'] ?? null, self::days() ),
				static fn( $value ): bool => null !== $value
			)
		);

		if ( count( $counts ) < self::QUIET_DAYS ) {
			return null;
		}

		$usual = array_sum( $counts ) / count( $counts ) / 24;

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one bounded count of this plugin's own table, once an hour.
		$observed = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND surface = 'signin' AND outcome = 'failed' AND occurred_at >= %s",
				Schema::table( 'login_attempts' ),
				Time::stamp( time() - HOUR_IN_SECONDS )
			)
		);

		if ( $observed < self::SIGNIN_FLOOR || $observed <= self::SIGNIN_FACTOR * $usual ) {
			return null;
		}

		$usual = round( $usual, 1 );

		return self::note( 'signin_failures', $observed, $usual ) ? array(
			'observed' => $observed,
			'usual'    => $usual,
		) : null;
	}

	/* ---- scheduler gaps ---------------------------------------------------- */

	/**
	 * A task is about to run: how long since it last did, against its own
	 * record. Called by the runner before it overwrites the last run, which is
	 * the only moment the gap can still be measured.
	 *
	 * @return array{observed: int, usual: int}|null What was noted, or null.
	 */
	public static function task_ran( string $hook, int $previous, int $now ): ?array {
		if ( $previous <= 0 || $now <= $previous ) {
			return null;
		}

		// A run from before the plugin was last switched off measures the
		// time it was off, not a stalled scheduler: every hourly task said so
		// on its first run back, and the gap became the usual.
		if ( $previous < (int) get_option( self::DEACTIVATED, 0 ) ) {
			return null;
		}

		$gap   = $now - $previous;
		$days  = self::days();
		$today = gmdate( 'Y-m-d', $now );

		$history = array();

		foreach ( $days as $day => $values ) {
			if ( $day !== $today && isset( $values['gaps'][ $hook ] ) ) {
				$history[] = (int) $values['gaps'][ $hook ];
			}
		}

		$days[ $today ]['gaps'][ $hook ] = max( $gap, (int) ( $days[ $today ]['gaps'][ $hook ] ?? 0 ) );
		self::save( $days );

		if ( count( $history ) < self::QUIET_DAYS ) {
			return null;
		}

		$usual = max( $history );

		if ( $gap <= self::GAP_FLOOR || $gap <= self::GAP_FACTOR * $usual ) {
			return null;
		}

		return self::note( 'task_gap', $gap, $usual, $hook ) ? array(
			'observed' => $gap,
			'usual'    => $usual,
		) : null;
	}

	/**
	 * Record one note, at most one per measure per hour.
	 *
	 * @param int|float $observed
	 * @param int|float $usual
	 */
	private static function note( string $metric, $observed, $usual, string $hook = '' ): bool {
		/*
		 * One key per measure, the tasks together. A scheduler that stalls
		 * stalls for every hourly task at once, and a key per task wrote one
		 * near-identical line for each of them, pushing the rest of the
		 * day's notes out of the panel.
		 */
		if ( null === Coalescer::admit( 'bettershield_unusual_' . $metric, HOUR_IN_SECONDS ) ) {
			return false;
		}

		$context = array(
			'metric'   => $metric,
			'observed' => $observed,
			'usual'    => $usual,
		);

		if ( '' !== $hook ) {
			$context['task'] = $hook;
		}

		Writer::instance()->record(
			self::EVENT,
			Writer::SEVERITY_MEDIUM,
			array(
				'actor_type'  => 'system',
				'object_type' => 'site',
				'object_id'   => $metric,
				'context'     => $context,
			)
		);

		return true;
	}

	/**
	 * What the Overview says: the notes of the last day, newest first, with
	 * what was seen and what is usual, and how much history there is.
	 *
	 * @return array{days: int, quiet_days: int, notes: array<int, array<string, mixed>>}
	 */
	public static function panel(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- five recent rows of this plugin's own table; the site predicate is integers from Schema::site_where(); every value bound.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT occurred_at, context FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND event_type = %s AND occurred_at >= %s ORDER BY id DESC LIMIT 5', Schema::table( 'events' ), self::EVENT, Time::stamp( time() - DAY_IN_SECONDS ) ) );

		$notes = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$context = json_decode( (string) $row->context, true );

			if ( ! is_array( $context ) || ! isset( $context['metric'] ) ) {
				continue;
			}

			$notes[] = array(
				'at'       => Time::utc_iso( (string) $row->occurred_at ),
				'metric'   => (string) $context['metric'],
				'observed' => $context['observed'] ?? 0,
				'usual'    => $context['usual'] ?? 0,
				'task'     => (string) ( $context['task'] ?? '' ),
			);
		}

		return array(
			'days'       => count( self::days() ),
			'quiet_days' => self::QUIET_DAYS,
			'notes'      => $notes,
		);
	}
}
