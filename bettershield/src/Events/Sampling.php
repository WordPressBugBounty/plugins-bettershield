<?php
/**
 * What the log does when one kind of event floods it.
 *
 * A site under a bot storm can produce tens of thousands of refused sign-ins
 * an hour. Recording every one costs the owner disk and costs every reader a
 * log they cannot see anything else in — the ten thousandth refused bot tells
 * nobody anything the hundredth did not. So above a per-type hourly threshold
 * the rest of that hour's events of that type are counted rather than stored.
 *
 * Two rules make that honest rather than a quiet lie.
 *
 * **The security-relevant types are never sampled.** `Writer::SECURITY_TYPES`
 * is the set an investigation needs, and a trail that thins under load is not
 * a trail. Those types are already exempt from every other drop policy in the
 * writer, and this is not the place that changes.
 *
 * **The true count is recorded, in the log itself.** When sampling engages, an
 * `events_sampled` row says so; when the hour closes, a second row states how
 * many of that type actually happened against how many were kept. A log that
 * looks complete while dropping events is a trust failure, which is a worse
 * outcome than the disk it saved.
 *
 * The threshold is a conservative default, high enough that an ordinary site
 * never reaches it. The number is filterable, because the right value belongs
 * to the site rather than to this file.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sampling {

	/**
	 * Rows of any one event type kept per hour before sampling engages.
	 *
	 * The assumption behind the number, so it can be argued with: the busiest
	 * *legitimate* type on a normal site is a sign-in or a page-adjacent event
	 * at well under a hundred an hour, and the types that reach thousands are
	 * refused bots and honeypot rejections, which are exactly the ones a count
	 * describes as well as a list would. Five hundred leaves an order of
	 * magnitude of headroom over the legitimate case while still capping a
	 * flood at a size a reader can page through.
	 *
	 * Filterable, so an operator who has measured their own site can say so.
	 */
	public const DEFAULT_THRESHOLD = 500;

	/** Where the current hour's per-type counts live. */
	private const STATE_OPTION = 'bettershield_event_rates';

	/**
	 * How many unclosed hours are carried while nothing can close them.
	 *
	 * A day. This only fills while the store that decides who closes an hour is
	 * unavailable, and the option is autoloaded, so it is bounded rather than
	 * left to grow through an outage — the oldest hours go first, which is the
	 * order they stop being worth reporting in.
	 */
	private const MAX_PENDING_HOURS = 24;

	/**
	 * The threshold in force, never below one — a threshold of zero would
	 * sample everything including the first event of an hour, which is a log
	 * that records nothing rather than a log that samples.
	 */
	public static function threshold(): int {
		/**
		 * Filters how many events of one type an hour holds before sampling.
		 *
		 * @param int $threshold Rows per event type per hour.
		 */
		$threshold = (int) apply_filters( 'bettershield_sampling_threshold', self::DEFAULT_THRESHOLD );

		return max( 1, $threshold );
	}

	/**
	 * Split a batch into what is kept and what is counted instead.
	 *
	 * Called once per flush with everything the request produced, so the state
	 * is read and written once however many events arrived — the alternative,
	 * a lookup per event, would make a flood expensive in exactly the moment it
	 * must not be.
	 *
	 * @param array<int, array<string, mixed>> $events Rows about to be written.
	 * @return array{keep: array<int, array<string, mixed>>, engaged: array<string, int>}
	 *         `engaged` maps event type to how many of it were dropped now.
	 */
	public static function apply( array $events ): array {
		if ( array() === $events ) {
			return array(
				'keep'    => array(),
				'engaged' => array(),
			);
		}

		$state     = self::state();
		$threshold = self::threshold();
		$keep      = array();
		$dropped   = array();
		$changed   = false;

		foreach ( $events as $event ) {
			$type = (string) $event['event_type'];

			// The investigation set, and this mechanism's own record of itself.
			// Sampling the row that says sampling happened would be the one
			// omission nobody could ever detect.
			if ( self::never_sampled( $type ) ) {
				$keep[] = $event;
				continue;
			}

			$seen = (int) ( $state['counts'][ $type ] ?? 0 );

			if ( $seen >= $threshold ) {
				$state['dropped'][ $type ] = (int) ( $state['dropped'][ $type ] ?? 0 ) + 1;
				$dropped[ $type ]          = (int) ( $dropped[ $type ] ?? 0 ) + 1;
				$changed                   = true;
				continue;
			}

			$state['counts'][ $type ] = $seen + 1;
			$changed                  = true;
			$keep[]                   = $event;

			// The row that announces sampling, written once per type per hour
			// at the moment the threshold is crossed rather than at the end of
			// it: a reader looking at the log while a flood is happening must
			// not have to wait an hour to be told it is happening.
			if ( $seen + 1 >= $threshold && empty( $state['announced'][ $type ] ) ) {
				$state['announced'][ $type ] = true;
				$keep[]                      = self::notice(
					$type,
					array(
						'state'     => 'engaged',
						'threshold' => $threshold,
					)
				);
			}
		}

		if ( $changed ) {
			self::save( $state );
		}

		return array(
			'keep'    => $keep,
			'engaged' => $dropped,
		);
	}

	/**
	 * Whether sampling is engaged right now, and for what.
	 *
	 * Read by the interface so the screen can say a flood is in progress rather
	 * than presenting a capped list as the whole story.
	 *
	 * @return array<int, array{type: string, label: string, recorded: int, dropped: int}>
	 */
	public static function engaged(): array {
		$state = self::state();
		$out   = array();

		foreach ( $state['dropped'] as $type => $count ) {
			$out[] = array(
				'type'     => (string) $type,
				'label'    => Types::label( (string) $type ),
				'recorded' => (int) ( $state['counts'][ $type ] ?? 0 ),
				'dropped'  => (int) $count,
			);
		}

		return $out;
	}

	/**
	 * Close out any hour that has ended, writing one row per sampled type with
	 * the numbers the log promised.
	 *
	 * Called from the flush path, where the ordinary case is that a later
	 * request rolls the hour over. A site that goes completely quiet after a
	 * flood would leave the summary unwritten, so the daily prune calls this
	 * too — the log's last word on an hour must not depend on the site staying
	 * busy enough to say it.
	 *
	 * @return array<int, array<string, mixed>> Rows to persist, possibly empty.
	 */
	public static function close_expired_hour(): array {
		$state = self::state( false );

		if ( array() === $state || self::hour() === $state['hour'] ) {
			return array();
		}

		/*
		 * Reading the counts and clearing them are two statements, and this
		 * runs at shutdown on every request that drained anything — so two
		 * requests crossing the hour boundary together both read the same
		 * counts and both report them, and the summary says an hour dropped
		 * twice what it dropped. Closing an hour is decided once, by an insert
		 * only one caller can win. The loser writes nothing, which is correct:
		 * the hour is being closed by somebody.
		 */
		if ( ! Claim::claim( 'sampling_close_' . (string) $state['hour'], HOUR_IN_SECONDS ) ) {
			return array();
		}

		/*
		 * Every hour still owed, oldest first: the ones carried because nothing
		 * could close them at the time, and then the one ending now.
		 */
		$owed = $state['pending'];

		$owed[ (string) $state['hour'] ] = array(
			'counts'  => $state['counts'],
			'dropped' => $state['dropped'],
		);

		$rows = array();

		foreach ( $owed as $hour => $totals ) {
			foreach ( $totals['dropped'] as $type => $dropped ) {
				$recorded = (int) ( $totals['counts'][ $type ] ?? 0 );
				$dropped  = (int) $dropped;

				$rows[] = self::notice(
					(string) $type,
					array(
						'state'    => 'summary',
						'hour'     => (string) $hour,
						'recorded' => $recorded,
						'dropped'  => $dropped,
						// Stated rather than left to be worked out, because this
						// is the number the whole mechanism exists to be honest
						// about.
						'total'    => $recorded + $dropped,
					)
				);
			}
		}

		/*
		 * Emptied rather than deleted. This row is read at `shutdown` on every
		 * request the writer drains, which includes ordinary front-end page
		 * views — and an absent option is not free: without a persistent object
		 * cache it is an uncached lookup on every single one. Deleting it
		 * therefore made the quiet state the expensive one, on a mechanism that
		 * only ever engages during a flood. Uninstall still removes the row.
		 */
		update_option( self::STATE_OPTION, array(), true );

		return $rows;
	}

	/**
	 * Types that are counted in full whatever the load.
	 *
	 * The two synthetic rows are here for the same reason and it is not the
	 * one the security types are here for: each exists to say that something
	 * was left out. Thinning either would omit the explanation of an omission,
	 * and the log would then report itself complete on exactly the request
	 * where it was not. At most one of each is produced per drain, so
	 * exempting them is bounded.
	 */
	public static function never_sampled( string $type ): bool {
		return in_array( $type, Writer::SECURITY_TYPES, true )
			|| 'events_sampled' === $type
			|| 'buffer_overflow' === $type;
	}

	/**
	 * A synthetic row, built the way the writer builds one so it travels
	 * through the same INSERT as everything else in the batch.
	 *
	 * @param array<string, mixed> $context
	 * @return array<string, mixed>
	 */
	private static function notice( string $type, array $context ): array {
		return Writer::instance()->build_synthetic(
			'events_sampled',
			Writer::SEVERITY_LOW,
			array(
				'actor_type'  => 'system',
				'object_type' => 'event_type',
				'object_id'   => $type,
				'context'     => $context,
			)
		);
	}

	/**
	 * The current hour's state, resetting when the hour turns over.
	 *
	 * `pending` holds the hours that ended without being closed out, keyed by
	 * hour and oldest first. It is normally empty: the ordinary rollover is
	 * closed by `close_expired_hour()` before anything reaches here. It fills
	 * only when that could not be decided at all — the store that arbitrates it
	 * was unavailable — and a clean slate then threw the previous hour's true
	 * numbers away, which is the one thing this mechanism must not do.
	 *
	 * @return array{hour: string, counts: array<string, int>, dropped: array<string, int>, announced: array<string, bool>, pending: array<string, array{counts: array<string, int>, dropped: array<string, int>}>}
	 */
	private static function state( bool $reset_stale = true ): array {
		$stored = get_option( self::STATE_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$empty = array(
			'hour'      => self::hour(),
			'counts'    => array(),
			'dropped'   => array(),
			'announced' => array(),
			'pending'   => array(),
		);

		if ( array() === $stored ) {
			return $reset_stale ? $empty : array();
		}

		$counts  = (array) ( $stored['counts'] ?? array() );
		$dropped = (array) ( $stored['dropped'] ?? array() );
		$pending = (array) ( $stored['pending'] ?? array() );

		if ( ( $stored['hour'] ?? '' ) !== self::hour() ) {
			// A previous hour's numbers. The caller closing it out wants them
			// as they are; everyone else wants a clean slate.
			if ( ! $reset_stale ) {
				return array(
					'hour'      => (string) ( $stored['hour'] ?? '' ),
					'counts'    => $counts,
					'dropped'   => $dropped,
					'announced' => (array) ( $stored['announced'] ?? array() ),
					'pending'   => $pending,
				);
			}

			// An hour that ended with something dropped in it and was never
			// closed out. Carried rather than discarded, so the next rollover
			// that can be decided still states what it held.
			if ( array() !== $dropped ) {
				$pending[ (string) ( $stored['hour'] ?? '' ) ] = array(
					'counts'  => $counts,
					'dropped' => $dropped,
				);

				if ( count( $pending ) > self::MAX_PENDING_HOURS ) {
					$pending = array_slice( $pending, -self::MAX_PENDING_HOURS, null, true );
				}
			}

			$empty['pending'] = $pending;

			return $empty;
		}

		return array(
			'hour'      => self::hour(),
			'counts'    => $counts,
			'dropped'   => $dropped,
			'announced' => (array) ( $stored['announced'] ?? array() ),
			'pending'   => $pending,
		);
	}

	/**
	 * @param array<string, mixed> $state
	 */
	private static function save( array $state ): void {
		/*
		 * Autoloaded, and deliberately.
		 *
		 * This is read on every flush. Left out of the autoload set it would
		 * cost a SELECT of its own each time; in it, it rides along with the
		 * single autoload query WordPress already runs, for a few dozen bytes.
		 * The read therefore costs nothing, which is what lets the whole
		 * mechanism be free on the request path it must not slow down: a batch
		 * containing only never-sampled types writes nothing at all.
		 */
		update_option( self::STATE_OPTION, $state, true );
	}

	/**
	 * UTC, so the window does not move when a site changes timezone and so two
	 * requests in the same hour agree on which hour that is.
	 */
	private static function hour(): string {
		return gmdate( 'Y-m-d-H' );
	}
}
