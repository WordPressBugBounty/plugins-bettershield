<?php
/**
 * The weekly summary: what changed on this site since the last one.
 *
 * A digest is a difference, not a status page. The score and the open count
 * are here because a summary that never says where the site stands is a
 * summary of nothing — but the body of it is what moved: findings that opened,
 * findings that closed, and the sign-in and account activity worth a look.
 *
 * The window is "since the last digest we sent", not "the last seven days".
 * Those are the same on a healthy schedule and different on a site whose cron
 * stopped for a fortnight, and in that case the honest report is the fortnight.
 *
 * @package BetterShield
 *
 * phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
 * -- the plugin-owned events table, for which no core API exists, read
 * uncached because a summary assembled from a stale copy would omit the most
 * recent thing that happened.
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Audit\Auditor;
use BetterShield\Database\Schema;
use BetterShield\Events\Types;
use BetterShield\Events\Writer;
use BetterShield\Support\Areas;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Digest {

	/** When the last digest went out. Absent until the first one does. */
	public const LAST_SENT_OPTION = 'bettershield_digest_last_sent';

	/**
	 * When the schedule last produced a digest, which is a different fact from
	 * when a digest last went out.
	 *
	 * One value used to carry both, and the two disagree the moment somebody
	 * presses "send now": that send has reported the window, so the window must
	 * advance or the next digest counts everything twice — but it is not the
	 * weekly digest, and reading it should not cost the owner the one they
	 * asked to receive on a Friday. Kept apart, both are true: the window is
	 * owned by whoever last reported it, and the schedule is owned by the
	 * schedule.
	 */
	public const LAST_SCHEDULED_OPTION = 'bettershield_digest_last_scheduled';

	/**
	 * The window a first-ever digest covers. Seven days, so the first one a
	 * site receives reads like every one after it.
	 */
	private const DEFAULT_WINDOW_DAYS = 7;

	/**
	 * How many findings a list in the message names before it says how many
	 * more there are.
	 *
	 * An ordinary week opens one or two. The exception is the first digest on
	 * a site that has just been installed, where every open finding is new and
	 * an uncapped list is a page of links nobody reads. Truncation is never
	 * silent: the true count is stated and the whole report is one click away.
	 */
	private const MAX_LISTED = 8;

	/**
	 * Everything the digest reports, as data. Rendering is separate so a test
	 * can assert on what was found rather than on the sentence it produced.
	 *
	 * @param string|null $since Where the window opens, as a stored-column
	 *                           datetime. Null is the digest's own window —
	 *                           since the last one went out — which is what
	 *                           the schedule always wants.
	 *
	 *                           A caller passing its own is asking the same
	 *                           question over a different period, and it asks
	 *                           here rather than assembling an answer of its
	 *                           own: two definitions of "what happened on this
	 *                           site since a date" would eventually disagree,
	 *                           and the one a reader trusts would be whichever
	 *                           they happened to open.
	 * @return array<string, mixed>
	 */
	public static function build( ?string $since = null ): array {
		$since    = null === $since || '' === $since ? self::window_start() : $since;
		$since_ts = (int) strtotime( $since . ' UTC' );
		$overview = Auditor::overview();

		$opened   = array();
		$resolved = array();
		$reopened = self::reopened_since( $since );

		foreach ( Auditor::findings() as $finding ) {
			$first    = null !== $finding['first_seen_at'] ? (int) strtotime( (string) $finding['first_seen_at'] ) : 0;
			$closed   = null !== $finding['resolved_at'] ? (int) strtotime( (string) $finding['resolved_at'] ) : 0;
			$shortened = array(
				'id'       => $finding['id'],
				'title'    => $finding['title'],
				'severity' => $finding['severity'],
			);

			if ( 'open' === $finding['status'] && $first > $since_ts ) {
				$opened[] = $shortened;
			} elseif ( 'open' === $finding['status'] && isset( $reopened[ $finding['id'] ] ) ) {
				/*
				 * Back after it was fixed. Its row keeps the day it was first
				 * seen, so it was left out here and showed only in the count,
				 * though a protection that stopped working this week is the
				 * same news as one that never worked.
				 */
				$opened[] = $shortened + array( 'back' => true );
			}

			if ( 'fixed' === $finding['status'] && $closed > $since_ts ) {
				$resolved[] = $shortened;
			}
		}

		// The next thing to do is the worst finding the owner has not set
		// aside for now. Findings arrive worst-first. The ones set aside are
		// still open and still counted, so the summary says how many there
		// are and when the first comes back rather than calling them nothing.
		$worst   = null;
		$snoozed = 0;
		$back    = null;

		foreach ( (array) $overview['findings'] as $finding ) {
			if ( ! empty( $finding['snoozed_until'] ) ) {
				++$snoozed;
				$back = null === $back || strcmp( (string) $finding['snoozed_until'], $back ) < 0 ? (string) $finding['snoozed_until'] : $back;
				continue;
			}

			if ( null === $worst ) {
				$worst = $finding;
			}
		}

		return array(
			'since'         => Time::utc_iso( $since ),
			'generated_at'  => gmdate( 'c' ),
			'score'         => (int) $overview['score'],
			'grade'         => (string) $overview['grade'],
			'open_findings' => (int) $overview['open_findings'],
			'last_audit_at' => $overview['generated_at'],
			// The worst thing open and not snoozed, which is what the one next
			// action points at.
			'worst'         => null !== $worst
				? array(
					'id'       => $worst['id'],
					'title'    => $worst['title'],
					'severity' => $worst['severity'],
				)
				: null,
			// Open findings set aside for now, and when the first comes back.
			'snoozed'       => $snoozed,
			'snoozed_back'  => $back,
			'opened'        => $opened,
			'resolved'      => $resolved,
			'activity'      => self::activity_since( $since ),
		) + self::sign_ins_stopped( $since );
	}

	/**
	 * Whether a digest built for this moment has anything to say beyond the
	 * score. Used to decide the subject line, never to decide whether to send:
	 * a weekly summary that only arrives in a bad week teaches its reader that
	 * its arrival is itself the bad news.
	 *
	 * @param array<string, mixed> $digest
	 */
	public static function has_changes( array $digest ): bool {
		return array() !== $digest['opened']
			|| array() !== $digest['resolved']
			|| $digest['activity']['total'] > 0;
	}

	/**
	 * The digest as the plain-text body of an email.
	 *
	 * What happened, why it matters, one next action, in that order, then the
	 * links. No upgrade prompt appears here or anywhere else in a message this
	 * plugin sends — that is a product principle, not a copy decision.
	 *
	 * @param array<string, mixed> $digest
	 */
	public static function render( array $digest ): string {
		$lines = array();

		$from = self::day( (string) $digest['since'] );
		$to   = self::day( (string) $digest['generated_at'] );

		// A summary sent again the same day covers one date: said twice, it
		// read like a bug.
		$lines[] = $from === $to
			? sprintf(
				/* translators: %s: today's date. */
				__( 'This is what changed on your site today, %s.', 'bettershield' ),
				$to
			)
			: sprintf(
				/* translators: 1: date the summary covers from, 2: date it covers to. */
				__( 'This is what changed on your site between %1$s and %2$s.', 'bettershield' ),
				$from,
				$to
			);
		$lines[] = '';

		$lines[] = sprintf(
			/* translators: 1: security score out of 100, 2: letter grade, 3: number of open findings. */
			_n(
				'Security score %1$d out of 100 (%2$s), with %3$d finding open.',
				'Security score %1$d out of 100 (%2$s), with %3$d findings open.',
				(int) $digest['open_findings'],
				'bettershield'
			),
			(int) $digest['score'],
			(string) $digest['grade'],
			(int) $digest['open_findings']
		);
		$lines[] = '';

		if ( array() !== $digest['opened'] ) {
			$lines[] = __( 'Opened this week:', 'bettershield' );
			foreach ( array_slice( $digest['opened'], 0, self::MAX_LISTED ) as $finding ) {
				$lines[] = ! empty( $finding['back'] )
					? sprintf(
						/* translators: 1: what the finding is, 2: its severity, one of critical, high, medium, low, info. */
						__( '  %1$s (%2$s, came back after it was fixed)', 'bettershield' ),
						$finding['title'],
						$finding['severity']
					)
					: sprintf(
						/* translators: 1: what the finding is, 2: its severity, one of critical, high, medium, low, info. */
						__( '  %1$s (%2$s)', 'bettershield' ),
						$finding['title'],
						$finding['severity']
					);
				$lines[] = '    ' . Links::finding( (string) $finding['id'] );
			}
			$lines = array_merge( $lines, self::and_the_rest( count( $digest['opened'] ) ) );
			$lines[] = '';
		}

		if ( array() !== $digest['resolved'] ) {
			$lines[] = __( 'Resolved this week:', 'bettershield' );
			foreach ( array_slice( $digest['resolved'], 0, self::MAX_LISTED ) as $finding ) {
				$lines[] = '  ' . $finding['title'];
			}
			$lines = array_merge( $lines, self::and_the_rest( count( $digest['resolved'] ) ) );
			$lines[] = '';
		}

		$stopped = (int) ( $digest['sign_ins_stopped'] ?? 0 );
		$right   = (int) ( $digest['password_right_lockouts'] ?? 0 );

		if ( $stopped > 0 && $right > 0 ) {
			// A correct password was used, and its holder was told to act, so
			// the summary can't say there is nothing to do.
			$lines[] = sprintf(
				/* translators: %d: number of sign-in attempts. */
				_n( '%d sign-in attempt was stopped.', '%d sign-in attempts were stopped.', $stopped, 'bettershield' ),
				$stopped
			) . ' ' . sprintf(
				/* translators: %d: number of lockouts that followed a correct password. */
				_n( '%d lockout came after a correct password, so that account holder was emailed.', '%d lockouts came after a correct password, so those account holders were emailed.', $right, 'bettershield' ),
				$right
			);
			$lines[] = '';
		} elseif ( $stopped > 0 ) {
			$lines[] = sprintf(
				/* translators: %d: number of sign-in attempts. */
				_n( '%d sign-in attempt was stopped. You don’t need to do anything.', '%d sign-in attempts were stopped. You don’t need to do anything.', $stopped, 'bettershield' ),
				$stopped
			);
			$lines[] = '';
		}

		if ( array() !== $digest['activity']['areas'] ) {
			$lines[] = __( 'Activity this week:', 'bettershield' );
			foreach ( $digest['activity']['areas'] as $area ) {
				$lines[] = sprintf(
					/* translators: 1: area of the site, 2: number of recorded events. */
					_n( '  %1$s: %2$d event', '  %1$s: %2$d events', (int) $area['count'], 'bettershield' ),
					$area['label'],
					(int) $area['count']
				);

				foreach ( $area['types'] as $type ) {
					$lines[] = sprintf(
						/* translators: 1: what happened, 2: how many times. */
						__( '    %1$s × %2$d', 'bettershield' ),
						$type['label'],
						(int) $type['count']
					);
				}
			}
			$lines[] = '';
		}

		if ( ! self::has_changes( $digest ) ) {
			$lines[] = __( 'No findings were opened or resolved, and no security events were recorded. The score above was measured today.', 'bettershield' );
			$lines[] = '';
		}

		// Why it matters, then the one next action. Both are about the site as
		// it stands now rather than about the week, because that is what the
		// reader can actually do something about.
		$snoozed = (int) ( $digest['snoozed'] ?? 0 );

		if ( null !== $digest['worst'] ) {
			$lines[] = sprintf(
				$snoozed > 0
					/* translators: %s: what the finding is. */
					? __( 'Your most serious open finding (not counting snoozed ones): %s', 'bettershield' )
					/* translators: %s: what the finding is. */
					: __( 'Your most serious open finding: %s', 'bettershield' ),
				(string) $digest['worst']['title']
			);
			$lines[] = '';
			$lines[] = __( 'Next: open it to see what it means and how to fix it.', 'bettershield' );
			$lines[] = Links::finding( (string) $digest['worst']['id'] );

			// The rest are snoozed, and may outrank the one named: said, with
			// when the first comes back, rather than left out.
			if ( $snoozed > 0 ) {
				$lines[] = '';
				$lines[] = sprintf(
					/* translators: 1: number of open findings snoozed, 2: the date the first comes back. */
					_n(
						'%1$d more open finding is snoozed, and comes back on %2$s.',
						'%1$d more open findings are snoozed. The first comes back on %2$s.',
						$snoozed,
						'bettershield'
					),
					$snoozed,
					self::day( (string) $digest['snoozed_back'] )
				);
				$lines[] = Links::findings( 'snoozed' );
			}
		} elseif ( $snoozed > 0 ) {
			$lines[] = sprintf(
				/* translators: 1: number of open findings snoozed, 2: the date the first comes back. */
				_n(
					'The %1$d open finding is snoozed, and comes back on %2$s.',
					'All %1$d open findings are snoozed. The first comes back on %2$s.',
					$snoozed,
					'bettershield'
				),
				$snoozed,
				self::day( (string) $digest['snoozed_back'] )
			);
			$lines[] = Links::findings( 'snoozed' );
		} else {
			$lines[] = __( 'Nothing is open, so there is nothing to do.', 'bettershield' );
			$lines[] = Links::findings();
		}

		$lines[] = '';
		$lines[] = __( 'See everything that happened in BetterShield › Activity:', 'bettershield' );
		$lines[] = Links::activity();

		// How to stop receiving this is appended by the mailer, to every kind
		// of message, so it cannot be left off a new one.
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * The line that follows a truncated list, or nothing where none was.
	 *
	 * @return string[]
	 */
	private static function and_the_rest( int $total ): array {
		if ( $total <= self::MAX_LISTED ) {
			return array();
		}

		$more = $total - self::MAX_LISTED;

		// A whole sentence, indented here rather than inside it: handed over
		// as "  and %d more, in the report:", a translator had the tail of a
		// sentence that code had begun, and no plural to work with (#1779).
		return array(
			'  ' . sprintf(
				/* translators: %d: how many more findings there are than the list above shows. */
				_n( '%d more is in the report:', '%d more are in the report:', $more, 'bettershield' ),
				$more
			),
			'    ' . Links::findings(),
		);
	}

	/**
	 * When the window this digest covers begins, as a stored-column datetime.
	 */
	public static function window_start(): string {
		$last = (string) get_option( self::LAST_SENT_OPTION, '' );

		if ( '' !== $last ) {
			return $last;
		}

		$week = ( new \DateTimeImmutable( '-' . self::DEFAULT_WINDOW_DAYS . ' days', new \DateTimeZone( 'UTC' ) ) )
			->format( 'Y-m-d H:i:s.v' );

		// Never before BetterShield was there: the first summary on a fresh
		// site said what changed in the week before it was installed (#2486).
		$activated = self::activated_at();

		return null !== $activated && $activated > strtotime( $week . ' UTC' ) ? Time::stamp( $activated ) : $week;
	}

	/**
	 * When the plugin was first activated here, or null where it never said.
	 */
	public static function activated_at(): ?int {
		$stored = (string) get_option( 'bettershield_activated_at', '' );
		$at     = '' === $stored ? false : strtotime( $stored . ' UTC' );

		return false === $at ? null : $at;
	}

	/**
	 * Move the window on. Every send does this, however it was triggered:
	 * what has been reported has been reported.
	 */
	public static function mark_sent(): void {
		update_option( self::LAST_SENT_OPTION, self::stamp(), false );
	}

	/**
	 * Record that the *schedule* produced a digest. Only the weekly tick calls
	 * this, so a manual send never moves the owner's chosen day.
	 */
	public static function mark_scheduled(): void {
		update_option( self::LAST_SCHEDULED_OPTION, self::stamp(), false );
	}

	/** When the schedule last fired, or an empty string if it never has. */
	public static function last_scheduled(): string {
		return (string) get_option( self::LAST_SCHEDULED_OPTION, '' );
	}

	private static function stamp(): string {
		return ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}

	/**
	 * The wrong sign-ins that lockouts stopped since the window opened, and
	 * how many of those lockouts followed a correct password.
	 *
	 * @return array{sign_ins_stopped: int, password_right_lockouts: int}
	 */
	private static function sign_ins_stopped( string $since ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table, read for one summary; the site predicate is integers assembled by Schema::site_where(), and every value is bound.
		$rows = (array) $wpdb->get_col(
			$wpdb->prepare(
				"SELECT context FROM %i WHERE " . Schema::site_where( 'events' ) . " AND event_type = 'login_lockout_started' AND occurred_at > %s LIMIT 5000",
				Schema::table( 'events' ),
				$since
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$total = 0;
		$right = 0;

		foreach ( $rows as $context ) {
			$context = json_decode( (string) $context, true );
			$total  += is_array( $context ) ? max( 1, (int) ( $context['attempts'] ?? 1 ) ) : 1;
			$right  += is_array( $context ) && ! empty( $context['password_right'] ) ? 1 : 0;
		}

		return array(
			'sign_ins_stopped'        => $total,
			'password_right_lockouts' => $right,
		);
	}

	/**
	 * The findings opened since the window opened, by the record of their
	 * opening: a finding fixed and back again keeps the day it was first seen
	 * on its row, and the record is what says it came back.
	 *
	 * @return array<string, true> By finding key.
	 */
	private static function reopened_since( string $since ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- read fresh from this plugin's own table; the site predicate is integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$keys = (array) $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT object_id FROM %i WHERE " . Schema::site_where( 'events' ) . " AND event_type = 'finding_opened' AND occurred_at > %s",
				Schema::table( 'events' ),
				$since
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array_fill_keys( array_map( 'strval', array_filter( $keys ) ), true );
	}

	/**
	 * The occurrences coalesced rows stand for beyond themselves, by type.
	 *
	 * A burst of failed sign-ins is one row carrying how many more it stands
	 * for, and counted by rows seven failures read as "× 1" (#2077). Only the
	 * rows that carry a count are read, and the count is added in PHP rather
	 * than with JSON functions not every supported database has.
	 *
	 * @param string   $since From when.
	 * @param string[] $types The types counted.
	 * @return array<string, int>
	 */
	private static function carried_since( string $since, array $types ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the IN list is a class constant of the writer, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT event_type, context FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at > %s AND context LIKE %s AND event_type IN ('
					. implode( ',', array_fill( 0, count( $types ), '%s' ) )
					. ') LIMIT 5000',
				array_merge( array( Schema::table( 'events' ), $since, '%' . $wpdb->esc_like( '"unlogged_attempts"' ) . '%' ), $types )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$carried = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$context = json_decode( (string) $row->context, true );
			$more    = is_array( $context ) ? (int) ( $context['unlogged_attempts'] ?? 0 ) : 0;

			if ( $more > 0 ) {
				$carried[ (string) $row->event_type ] = ( $carried[ (string) $row->event_type ] ?? 0 ) + $more;
			}
		}

		return $carried;
	}

	/**
	 * What would have emailed at once since the window opened, for a site
	 * whose host takes the routine alerts: those were promised a place in
	 * this summary, whatever the log counts as security.
	 *
	 * @return string[]
	 */
	private static function held_for_host( string $since ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own table, read for one summary; the site predicate is integers assembled by Schema::site_where(), and every value is bound.
		$types = $wpdb->get_col(
			$wpdb->prepare(
				'SELECT DISTINCT event_type FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at > %s AND severity >= %d',
				Schema::table( 'events' ),
				$since,
				Writer::SEVERITY_HIGH
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array_values( array_filter( array_map( 'strval', (array) $types ), static fn( string $type ): bool => 'alert_' !== substr( $type, 0, 6 ) ) );
	}

	/**
	 * Security-relevant events since the window opened, counted by area and by
	 * what happened.
	 *
	 * Only the types an investigation needs are counted. The rest of the log is
	 * a fuller record than a weekly email should try to be, and it is one click
	 * away in every message.
	 *
	 * @return array{total: int, areas: array<int, array{slug: string, label: string, count: int, types: array<int, array{type: string, label: string, count: int}>}>}
	 */
	private static function activity_since( string $since ): array {
		global $wpdb;

		// And the types the owner moved here from the instant email, which
		// were promised a place in this summary whether or not they are kept
		// under load (#1973).
		$settings = Settings::instance()->settings();
		$types    = array_values( array_unique( array_merge( Writer::SECURITY_TYPES, $settings['instant_off'], $settings['host_managed'] ? self::held_for_host( $since ) : array() ) ) );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the IN list is the writer's class constant and registered type names from the settings; its length comes from that registry and never from a request, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT event_type, COUNT(*) AS total FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at > %s AND event_type IN ('
					. implode( ',', array_fill( 0, count( $types ), '%s' ) )
					. ') GROUP BY event_type',
				array_merge( array( Schema::table( 'events' ), $since ), $types )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$areas_of = Types::areas();
		$labels   = Areas::all();
		$buckets  = array();
		$total    = 0;
		$carried  = self::carried_since( $since, $types );

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$type  = (string) $row->event_type;
			$count = (int) $row->total + ( $carried[ $type ] ?? 0 );
			$area  = $areas_of[ $type ] ?? Areas::PLUGIN;

			$total += $count;

			if ( ! isset( $buckets[ $area ] ) ) {
				$buckets[ $area ] = array(
					'slug'  => $area,
					'label' => $labels[ $area ] ?? $area,
					'count' => 0,
					'types' => array(),
				);
			}

			$buckets[ $area ]['count'] += $count;
			$buckets[ $area ]['types'][] = array(
				'type'  => $type,
				'label' => Types::label( $type ),
				'count' => $count,
			);
		}

		// Busiest area first, and inside it the commonest thing first: a reader
		// scanning one screen of text should meet the largest number first.
		foreach ( $buckets as &$bucket ) {
			usort(
				$bucket['types'],
				static function ( array $a, array $b ): int {
					return $b['count'] <=> $a['count'];
				}
			);
		}
		unset( $bucket );

		usort(
			$buckets,
			static function ( array $a, array $b ): int {
				return $b['count'] <=> $a['count'];
			}
		);

		return array(
			'total' => $total,
			'areas' => array_values( $buckets ),
		);
	}

	/**
	 * A date in the site's own format and timezone. Times are left off: a
	 * weekly window's precision is the day, and a timestamp would suggest
	 * otherwise.
	 */
	private static function day( string $iso ): string {
		$stamp = strtotime( $iso );

		if ( false === $stamp ) {
			return $iso;
		}

		return wp_date( (string) get_option( 'date_format', 'Y-m-d' ), $stamp );
	}
}
