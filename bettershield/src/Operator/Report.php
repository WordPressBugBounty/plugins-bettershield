<?php
/**
 * The security report an owner asks for: one self-contained HTML page they
 * can keep, forward or print to PDF, built from the same figures the weekly
 * summary reports.
 *
 * On demand and unbranded. Nothing is scheduled, nothing is sent anywhere,
 * and the page carries no link back into the dashboard: it is read away from
 * the site, by somebody who may not be able to sign in to it. It states
 * counts and names, never an address, a login or an email, because a file
 * that lists a site's open weaknesses leaves the site with whoever holds it.
 *
 * Every period figure comes from `Digest::build( $since )`. Two answers to
 * "what happened on this site since a date" would eventually disagree, and
 * the digest's docblock asks every such question to come through it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

use BetterShield\Alerts\Digest;
use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Incidents\Repository;
use BetterShield\Support\Areas;
use BetterShield\Support\Tier;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Report {

	/** The period a report covers when nobody says otherwise. */
	public const DEFAULT_DAYS = 30;

	/** How many incidents of each kind the page names before it counts the rest. */
	private const MAX_INCIDENTS = 20;

	/** How many protection changes the page names before it says there were more. */
	private const MAX_FIXES = 200;

	/**
	 * The sections a report can carry, each behind the capability that reads
	 * the same thing on screen: findings and the score for whoever may read
	 * the posture, changes for whoever manages the site, and the log and its
	 * incidents for whoever may read the activity.
	 */
	private const SECTIONS = array(
		'posture'   => Capabilities::READ_POSTURE,
		'fixes'     => Capabilities::MANAGE,
		'activity'  => Capabilities::READ_ACTIVITY,
		'incidents' => Capabilities::READ_ACTIVITY,
	);

	/**
	 * A period in whole days, held inside what the log keeps: a report
	 * cannot describe days the pruner has already emptied.
	 */
	public static function days( int $asked ): int {
		return max( 1, min( $asked, Tier::retention_days() ) );
	}

	/**
	 * The sections the current reader may see.
	 *
	 * @return string[]
	 */
	public static function sections_for_reader(): array {
		return array_keys( array_filter( self::SECTIONS, static fn( string $capability ): bool => current_user_can( $capability ) ) );
	}

	/**
	 * Everything the report states, as data. Rendering is separate so a test
	 * can assert on what was found rather than on the page it produced.
	 *
	 * @param string[]|null $sections Which sections to include; the reader's own when null.
	 * @return array<string, mixed>
	 */
	public static function build( int $days = self::DEFAULT_DAYS, ?array $sections = null ): array {
		$days     = self::days( $days );
		$sections = null === $sections ? self::sections_for_reader() : array_values( array_intersect( $sections, array_keys( self::SECTIONS ) ) );
		$since    = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$floor    = substr( Tier::retention_floor(), 0, 19 );

		// The same instant as the period, never older than the log.
		if ( strcmp( $since, $floor ) < 0 ) {
			$since = $floor;
		}

		$digest  = Digest::build( $since );
		$posture = in_array( 'posture', $sections, true );
		$fixes   = in_array( 'fixes', $sections, true ) ? self::fixes( $since ) : null;

		return array(
			'site'          => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
			'days'          => $days,
			'since'         => (string) $digest['since'],
			'generated_at'  => (string) $digest['generated_at'],
			'last_audit_at' => $digest['last_audit_at'],
			'score'         => $posture ? (int) $digest['score'] : null,
			'grade'         => $posture ? (string) $digest['grade'] : null,
			'open_count'    => $posture ? (int) $digest['open_findings'] : null,
			'trend'         => $posture ? self::trend( $since ) : null,
			'findings'      => $posture ? self::open_findings() : null,
			'opened'        => $posture ? $digest['opened'] : null,
			'resolved'      => $posture ? $digest['resolved'] : null,
			'fixes'         => $fixes['list'] ?? null,
			'fixes_more'    => (bool) ( $fixes['more'] ?? false ),
			'activity'      => in_array( 'activity', $sections, true ) ? $digest['activity'] : null,
			'incidents'     => in_array( 'incidents', $sections, true ) ? self::incidents( (string) $digest['since'] ) : null,
		);
	}

	/**
	 * The score's daily points inside the period, oldest first.
	 *
	 * @return array<int, array{at: string, score: int}>
	 */
	private static function trend( string $since ): array {
		$day = substr( $since, 0, 10 );

		return array_values(
			array_filter(
				Auditor::score_history(),
				static fn( array $point ): bool => strcmp( substr( (string) $point['at'], 0, 10 ), $day ) >= 0
			)
		);
	}

	/**
	 * Every open finding, worst first, as the report names it.
	 *
	 * @return array<int, array{title: string, severity: string, area: string, snoozed: bool}>
	 */
	private static function open_findings(): array {
		$areas = Areas::all();
		$out   = array();

		foreach ( (array) Auditor::overview()['findings'] as $finding ) {
			$out[] = array(
				'title'    => (string) $finding['title'],
				'severity' => (string) $finding['severity'],
				'area'     => (string) ( $areas[ $finding['group'] ?? '' ] ?? '' ),
				'snoozed'  => ! empty( $finding['snoozed_until'] ),
			);
		}

		return $out;
	}

	/**
	 * The protections applied in the period, newest first, each with whether
	 * it is still on and what the last visitor's page view saw of it.
	 *
	 * One more entry than the page names is read, so a period busier than the
	 * cap keeps its latest changes and says older ones were left out, rather
	 * than silently ending before the newest (#2276).
	 *
	 * @return array{list: array<int, array{title: string, at: string, reverted: bool, active: bool, verification: string}>, more: bool}
	 */
	private static function fixes( string $since ): array {
		$definitions = Items::all();
		$manager     = Manager::instance();
		$out         = array();
		$rows        = Ledger::since( 'harden_', $since, self::MAX_FIXES + 1 );
		$more        = count( $rows ) > self::MAX_FIXES;

		foreach ( array_slice( $rows, 0, self::MAX_FIXES ) as $row ) {
			$item = substr( $row['action_key'], strlen( 'harden_' ) );

			// A removed item, or an `_action` variant that belongs to a
			// control rather than to the item itself.
			if ( ! isset( $definitions[ $item ] ) ) {
				continue;
			}

			$out[] = array(
				'title'        => (string) $definitions[ $item ]['title'],
				'at'           => (string) $row['at'],
				'reverted'     => null !== $row['reverted_at'],
				'active'       => $manager->is_active( $item ),
				'verification' => self::verification( $item ),
			);
		}

		return array(
			'list' => $out,
			'more' => $more,
		);
	}

	/**
	 * What the last check of a protection saw, in a word the page can say:
	 * `present`, `absent`, `unknown`, `unchecked`, or `unobservable` for an
	 * effect no page view can see.
	 */
	private static function verification( string $item ): string {
		if ( ! \BetterShield\Verify\Checks::is_observable( $item ) ) {
			return 'unobservable';
		}

		$state = \BetterShield\Verify\State::for_item( $item );

		return is_array( $state ) && in_array( $state['status'] ?? '', array( 'present', 'absent', 'unknown' ), true ) ? (string) $state['status'] : 'unchecked';
	}

	/**
	 * The open incidents, and those handled in the period. Where the
	 * incident records cannot be read the page says so, rather than
	 * reporting none.
	 *
	 * @param string $since The period's start, as an ISO 8601 UTC string.
	 * @return array<string, mixed>
	 */
	private static function incidents( string $since ): array {
		$open     = Repository::page( 'open', 0, self::MAX_INCIDENTS );
		$resolved = Repository::page( 'resolved', 0, self::MAX_INCIDENTS );
		$counts   = Repository::status_counts();

		if ( is_wp_error( $open ) || is_wp_error( $resolved ) ) {
			return array( 'unreadable' => true );
		}

		$from    = (int) strtotime( $since );
		$handled = array_values( array_filter( $resolved['incidents'], static fn( array $incident ): bool => (int) strtotime( (string) $incident['resolved_at'] ) >= $from ) );
		$shape   = static fn( array $incident ): array => array(
			'id'          => (int) $incident['id'],
			'confidence'  => (string) ( $incident['confidence'] ?? '' ),
			'opened_at'   => (string) $incident['opened_at'],
			'resolved_at' => (string) ( $incident['resolved_at'] ?? '' ),
			'evidence'    => (int) ( $incident['evidence_count'] ?? 0 ),
		);

		// A next page says more were resolved somewhere in what the log keeps,
		// not that more were resolved in this period: only when the last row
		// read still falls inside the period can the page say "more" (#2276).
		$last = end( $resolved['incidents'] );
		$more = $resolved['next_cursor'] > 0 && is_array( $last ) && (int) strtotime( (string) $last['resolved_at'] ) >= $from;

		return array(
			'open_total' => is_array( $counts ) ? (int) $counts['open'] : count( $open['incidents'] ),
			'open'       => array_map( $shape, $open['incidents'] ),
			'handled'    => array_map( $shape, $handled ),
			'more'       => $more,
		);
	}

	/** What the saved file is called. */
	public static function filename(): string {
		return 'bettershield-security-report-' . wp_date( 'Y-m-d' ) . '.html';
	}

	/**
	 * The report as one HTML page with its own styles, readable offline and
	 * printable to PDF from any browser.
	 *
	 * @param array<string, mixed> $report What build() returned.
	 */
	public static function render( array $report ): string {
		$from = self::day( (string) $report['since'] );
		$to   = self::day( (string) $report['generated_at'] );

		$body  = '<header class="head">';
		$body .= '<p class="eyebrow">' . esc_html__( 'Security report', 'bettershield' ) . '</p>';
		$body .= '<h1>' . esc_html( '' !== trim( (string) $report['site'] ) ? (string) $report['site'] : __( 'This site', 'bettershield' ) ) . '</h1>';
		$body .= '<p class="period">' . esc_html(
			sprintf(
				/* translators: 1: date the report covers from, 2: date it covers to, 3: how many days. */
				_n( '%1$s to %2$s (%3$d day)', '%1$s to %2$s (%3$d days)', (int) $report['days'], 'bettershield' ),
				$from,
				$to,
				(int) $report['days']
			)
		) . '</p>';
		$body .= '<p class="meta">' . esc_html(
			sprintf(
				/* translators: %s: date and time the report was made. */
				__( 'Made %s.', 'bettershield' ),
				self::moment( (string) $report['generated_at'] )
			)
		) . ' ' . esc_html(
			null !== $report['last_audit_at']
				/* translators: %s: date and time of the last audit. */
				? sprintf( __( 'Last audit %s.', 'bettershield' ), self::moment( (string) $report['last_audit_at'] ) )
				: __( 'No audit has run yet.', 'bettershield' )
		) . '</p>';
		$body .= '</header>';

		if ( null !== $report['score'] ) {
			$body .= self::score_section( $report );
			$body .= self::findings_section( (array) $report['findings'] );
			$body .= self::period_findings_section( (array) $report['opened'], (array) $report['resolved'] );
		}

		if ( null !== $report['fixes'] ) {
			$body .= self::fixes_section( (array) $report['fixes'], ! empty( $report['fixes_more'] ) );
		}

		if ( null !== $report['activity'] ) {
			$body .= self::activity_section( (array) $report['activity'] );
		}

		if ( null !== $report['incidents'] ) {
			$body .= self::incidents_section( (array) $report['incidents'] );
		}

		$body .= '<footer><p>' . esc_html__( 'Counts and names only: this report leaves out addresses, logins and email addresses. Times are in the site’s time zone.', 'bettershield' ) . '</p></footer>';

		return '<!doctype html><html lang="' . esc_attr( str_replace( '_', '-', determine_locale() ) ) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'
			. esc_html(
				sprintf(
					/* translators: 1: the site's name, 2: the date the report was made. */
					__( 'Security report: %1$s, %2$s', 'bettershield' ),
					'' !== trim( (string) $report['site'] ) ? (string) $report['site'] : __( 'This site', 'bettershield' ),
					$to
				)
			)
			. '</title><style>' . self::styles() . '</style></head><body><main>' . $body . '</main></body></html>';
	}

	/** @param array<string, mixed> $report */
	private static function score_section( array $report ): string {
		$html  = '<section class="score"><h2>' . esc_html__( 'Score', 'bettershield' ) . '</h2>';
		$html .= '<div class="score__row"><p class="score__value"><span class="score__number">' . (int) $report['score'] . '</span><span class="score__of">/100</span></p>';
		$html .= '<p class="score__grade">' . esc_html(
			sprintf(
				/* translators: %s: a letter grade, A to F. */
				__( 'Grade %s', 'bettershield' ),
				(string) $report['grade']
			)
		) . '<br>' . esc_html(
			sprintf(
				/* translators: %d: how many findings are open. */
				_n( '%d open finding', '%d open findings', (int) $report['open_count'], 'bettershield' ),
				(int) $report['open_count']
			)
		) . '</p></div>';

		$trend = (array) $report['trend'];

		if ( count( $trend ) >= 2 ) {
			$first = reset( $trend );
			$last  = end( $trend );
			$html .= self::sparkline( $trend );
			$html .= '<p class="note">' . esc_html(
				sprintf(
					/* translators: 1: the score at the start of the period, 2: the date it was recorded, 3: the latest score, 4: the date it was recorded. */
					__( 'The score went from %1$d on %2$s to %3$d on %4$s.', 'bettershield' ),
					(int) $first['score'],
					self::day( (string) $first['at'] ),
					(int) $last['score'],
					self::day( (string) $last['at'] )
				)
			) . '</p>';

			// The score's history keeps a bounded number of days, so a long
			// period can start before the first point kept: say how much the
			// drawing covers rather than let it pass for the period (#2276).
			if ( strcmp( substr( (string) $first['at'], 0, 10 ), substr( (string) $report['since'], 0, 10 ) ) > 0 ) {
				$html .= '<p class="note">' . esc_html(
					sprintf(
						/* translators: %d: how many daily scores the trend shows. */
						_n( 'The trend shows the last %d recorded day, not the whole period.', 'The trend shows the last %d recorded days, not the whole period.', count( $trend ), 'bettershield' ),
						count( $trend )
					)
				) . '</p>';
			}
		} else {
			$html .= '<p class="note">' . esc_html__( 'Not enough days are recorded in this period to show a trend.', 'bettershield' ) . '</p>';
		}

		return $html . '</section>';
	}

	/**
	 * The trend as a small inline drawing, with its numbers in words for a
	 * reader who cannot see it.
	 *
	 * @param array<int, array{at: string, score: int}> $points
	 */
	private static function sparkline( array $points ): string {
		$width  = 600;
		$height = 120;
		$count  = count( $points );
		$coords = array();

		foreach ( array_values( $points ) as $index => $point ) {
			$x        = $count > 1 ? round( $index * $width / ( $count - 1 ), 1 ) : 0;
			$y        = round( $height - ( max( 0, min( 100, (int) $point['score'] ) ) * ( $height - 8 ) / 100 ) - 4, 1 );
			$coords[] = $x . ',' . $y;
		}

		$scores = array_map( static fn( array $point ): int => (int) $point['score'], $points );

		return '<svg class="trend" viewBox="0 0 ' . $width . ' ' . $height . '" preserveAspectRatio="none" role="img" aria-label="' . esc_attr(
			sprintf(
				/* translators: 1: lowest score in the period, 2: highest score in the period. */
				__( 'Daily score, lowest %1$d and highest %2$d', 'bettershield' ),
				min( $scores ),
				max( $scores )
			)
		) . '"><polyline fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" points="' . esc_attr( implode( ' ', $coords ) ) . '"/></svg>';
	}

	/** @param array<int, array<string, mixed>> $findings */
	private static function findings_section( array $findings ): string {
		$html = '<section><h2>' . esc_html__( 'Open findings', 'bettershield' ) . '</h2>';

		if ( array() === $findings ) {
			return $html . '<p class="note">' . esc_html__( 'No findings are open.', 'bettershield' ) . '</p></section>';
		}

		$html .= '<table><thead><tr><th scope="col">' . esc_html__( 'Finding', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Severity', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Area', 'bettershield' ) . '</th></tr></thead><tbody>';

		foreach ( $findings as $finding ) {
			$html .= '<tr><td>' . esc_html( (string) $finding['title'] )
				. ( ! empty( $finding['snoozed'] ) ? ' <span class="tag">' . esc_html__( 'snoozed', 'bettershield' ) . '</span>' : '' )
				. '</td><td><span class="sev sev--' . esc_attr( (string) $finding['severity'] ) . '">' . esc_html( self::severity( (string) $finding['severity'] ) ) . '</span></td><td>' . esc_html( (string) $finding['area'] ) . '</td></tr>';
		}

		return $html . '</tbody></table></section>';
	}

	/**
	 * @param array<int, array<string, mixed>> $opened
	 * @param array<int, array<string, mixed>> $resolved
	 */
	private static function period_findings_section( array $opened, array $resolved ): string {
		$html = '<section><h2>' . esc_html__( 'In this period', 'bettershield' ) . '</h2><div class="pair">';

		foreach (
			array(
				array( __( 'Opened or back', 'bettershield' ), $opened, __( 'Nothing new opened.', 'bettershield' ) ),
				array( __( 'Fixed', 'bettershield' ), $resolved, __( 'Nothing was fixed.', 'bettershield' ) ),
			) as $part
		) {
			$html .= '<div><h3>' . esc_html( $part[0] ) . ' <span class="count">' . count( $part[1] ) . '</span></h3>';

			if ( array() === $part[1] ) {
				$html .= '<p class="note">' . esc_html( $part[2] ) . '</p></div>';
				continue;
			}

			$html .= '<ul>';

			foreach ( $part[1] as $finding ) {
				$html .= '<li>' . esc_html( (string) $finding['title'] ) . ' <span class="sev sev--' . esc_attr( (string) $finding['severity'] ) . '">' . esc_html( self::severity( (string) $finding['severity'] ) ) . '</span>'
					. ( ! empty( $finding['back'] ) ? ' <span class="tag">' . esc_html__( 'back after a fix', 'bettershield' ) . '</span>' : '' ) . '</li>';
			}

			$html .= '</ul></div>';
		}

		return $html . '</div></section>';
	}

	/**
	 * @param array<int, array<string, mixed>> $fixes
	 * @param bool                             $more  Whether older changes in the period were left out.
	 */
	private static function fixes_section( array $fixes, bool $more = false ): string {
		$html = '<section><h2>' . esc_html__( 'Protections changed', 'bettershield' ) . '</h2>';

		if ( array() === $fixes && ! $more ) {
			return $html . '<p class="note">' . esc_html__( 'No protection was applied in this period.', 'bettershield' ) . '</p></section>';
		}

		$html .= '<table><thead><tr><th scope="col">' . esc_html__( 'Protection', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Applied', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Now', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Last check', 'bettershield' ) . '</th></tr></thead><tbody>';

		$checks = array(
			'present'      => __( 'Seen working', 'bettershield' ),
			'absent'       => __( 'Not seen on the last check', 'bettershield' ),
			'unknown'      => __( 'Could not be checked', 'bettershield' ),
			'unchecked'    => __( 'Not checked yet', 'bettershield' ),
			'unobservable' => __( 'Not visible to a page view', 'bettershield' ),
		);

		foreach ( $fixes as $fix ) {
			$now = $fix['reverted']
				? __( 'Undone', 'bettershield' )
				: ( $fix['active'] ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) );

			$html .= '<tr><td>' . esc_html( (string) $fix['title'] ) . '</td><td>' . esc_html( self::moment( (string) $fix['at'] ) ) . '</td><td>' . esc_html( $now ) . '</td><td>'
				. esc_html( $fix['reverted'] ? '—' : ( $checks[ (string) $fix['verification'] ] ?? $checks['unchecked'] ) ) . '</td></tr>';
		}

		$html .= '</tbody></table>';

		if ( $more ) {
			$html .= '<p class="note">' . esc_html__( 'And more: only the latest changes are listed. Older changes in this period are left out.', 'bettershield' ) . '</p>';
		}

		return $html . '</section>';
	}

	/** @param array<string, mixed> $activity */
	private static function activity_section( array $activity ): string {
		$html = '<section><h2>' . esc_html__( 'Activity', 'bettershield' ) . '</h2>';

		if ( 0 === (int) ( $activity['total'] ?? 0 ) ) {
			return $html . '<p class="note">' . esc_html__( 'No security events were recorded in this period.', 'bettershield' ) . '</p></section>';
		}

		$html .= '<p class="note">' . esc_html(
			sprintf(
				/* translators: %d: how many security events were recorded. */
				_n( '%d security event was recorded.', '%d security events were recorded.', (int) $activity['total'], 'bettershield' ),
				(int) $activity['total']
			)
		) . '</p><table><thead><tr><th scope="col">' . esc_html__( 'Area', 'bettershield' ) . '</th><th scope="col" class="num">' . esc_html__( 'Events', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'Most common', 'bettershield' ) . '</th></tr></thead><tbody>';

		foreach ( (array) ( $activity['areas'] ?? array() ) as $area ) {
			$top = array_slice( (array) ( $area['types'] ?? array() ), 0, 3 );

			$html .= '<tr><td>' . esc_html( (string) $area['label'] ) . '</td><td class="num">' . (int) $area['count'] . '</td><td>'
				. esc_html(
					implode(
						', ',
						array_map(
							static fn( array $type ): string => sprintf(
								/* translators: 1: what kind of event, 2: how many. */
								__( '%1$s (%2$d)', 'bettershield' ),
								(string) $type['label'],
								(int) $type['count']
							),
							$top
						)
					)
				) . '</td></tr>';
		}

		return $html . '</tbody></table></section>';
	}

	/** @param array<string, mixed> $incidents */
	private static function incidents_section( array $incidents ): string {
		$row    = static function ( array $incident, bool $handled ): string {
			return '<tr><td>' . esc_html(
				sprintf(
					/* translators: %d: an incident's own number. */
					__( 'Incident #%d', 'bettershield' ),
					(int) $incident['id']
				)
			) . '</td><td>' . esc_html( '' !== \BetterShield\Incidents\Repository::claim( (string) $incident['confidence'] ) ? \BetterShield\Incidents\Repository::claim( (string) $incident['confidence'] ) : __( 'Review the evidence', 'bettershield' ) ) . '</td><td>'
				. esc_html( self::day( (string) ( $handled ? $incident['resolved_at'] : $incident['opened_at'] ) ) ) . '</td><td class="num">' . (int) $incident['evidence'] . '</td></tr>';
		};
		$head   = static fn( string $when ): string => '<table><thead><tr><th scope="col">' . esc_html__( 'Incident', 'bettershield' ) . '</th><th scope="col">' . esc_html__( 'What links it', 'bettershield' ) . '</th><th scope="col">' . esc_html( $when ) . '</th><th scope="col" class="num">' . esc_html__( 'Evidence', 'bettershield' ) . '</th></tr></thead><tbody>';

		$html = '<section><h2>' . esc_html__( 'Incidents', 'bettershield' ) . '</h2>';

		if ( ! empty( $incidents['unreadable'] ) ) {
			return $html . '<p class="note">' . esc_html__( 'The incident records could not be read for this report.', 'bettershield' ) . '</p></section>';
		}

		$html .= '<h3>' . esc_html__( 'Open', 'bettershield' ) . ' <span class="count">' . (int) $incidents['open_total'] . '</span></h3>';

		if ( array() === $incidents['open'] ) {
			$html .= '<p class="note">' . esc_html__( 'No incident is open.', 'bettershield' ) . '</p>';
		} else {
			$html .= $head( __( 'Opened', 'bettershield' ) );

			foreach ( $incidents['open'] as $incident ) {
				$html .= $row( $incident, false );
			}

			$html .= '</tbody></table>';

			if ( (int) $incidents['open_total'] > count( $incidents['open'] ) ) {
				$html .= '<p class="note">' . esc_html(
					sprintf(
						/* translators: %d: how many open incidents are not listed. */
						_n( 'And %d more.', 'And %d more.', (int) $incidents['open_total'] - count( $incidents['open'] ), 'bettershield' ),
						(int) $incidents['open_total'] - count( $incidents['open'] )
					)
				) . '</p>';
			}
		}

		$html .= '<h3>' . esc_html__( 'Handled in this period', 'bettershield' ) . ' <span class="count">' . count( $incidents['handled'] ) . ( ! empty( $incidents['more'] ) ? '+' : '' ) . '</span></h3>';

		if ( array() === $incidents['handled'] ) {
			$html .= '<p class="note">' . esc_html__( 'No incident was handled in this period.', 'bettershield' ) . '</p>';
		} else {
			$html .= $head( __( 'Handled', 'bettershield' ) );

			foreach ( $incidents['handled'] as $incident ) {
				$html .= $row( $incident, true );
			}

			$html .= '</tbody></table>';
		}

		return $html . '</section>';
	}

	/**
	 * A severity in the reader's words, from the one place that translates
	 * them, so the report and the dashboard widget cannot disagree.
	 */
	private static function severity( string $severity ): string {
		return Widget::severity_labels()[ $severity ] ?? $severity;
	}

	/** A day, in the site's date format and zone. */
	private static function day( string $when ): string {
		$stamp = strtotime( $when );

		return false === $stamp ? $when : wp_date( (string) get_option( 'date_format', 'Y-m-d' ), $stamp );
	}

	/** A moment, in the site's date and time formats and zone. */
	private static function moment( string $when ): string {
		$stamp = strtotime( $when );

		return false === $stamp ? $when : wp_date( get_option( 'date_format', 'Y-m-d' ) . ' ' . get_option( 'time_format', 'H:i' ), $stamp );
	}

	/** The page's own styles, for the screen and for paper. */
	private static function styles(): string {
		return 'html{color-scheme:light}body{margin:0;background:#fff;color:#1d2327;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}'
			. 'main{max-width:780px;margin:0 auto;padding:32px 16px 48px}'
			. 'h1{font-size:28px;line-height:1.2;margin:4px 0 6px}h2{font-size:19px;margin:0 0 12px}h3{font-size:15px;margin:16px 0 8px}'
			. '.eyebrow{margin:0;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:#50575e}.period{margin:0;font-size:16px}.meta,.note,footer{color:#50575e;font-size:13px}'
			. 'section{border-top:1px solid #dcdcde;padding:20px 0 4px;break-inside:avoid-page}'
			. '.score__row{display:flex;align-items:center;gap:24px;flex-wrap:wrap}.score__value{margin:0}.score__number{font-size:48px;font-weight:600;line-height:1}.score__of{color:#50575e;margin-left:2px}.score__grade{margin:0}'
			. '.trend{display:block;width:100%;height:80px;margin:12px 0 4px;color:#2271b1}'
			. 'table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid #ececec}th{font-weight:600;color:#50575e;font-size:12px}td.num,th.num{text-align:right;white-space:nowrap}'
			. 'tr{break-inside:avoid}thead{display:table-header-group}'
			. 'ul{margin:0;padding-left:18px}li{margin:3px 0}.pair{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:8px 24px}'
			. '.count{display:inline-block;min-width:1.4em;padding:0 6px;border-radius:9px;background:#f0f0f1;font-size:12px;text-align:center}'
			. '.tag{font-size:12px;color:#50575e;border:1px solid #dcdcde;border-radius:4px;padding:0 4px;white-space:nowrap}'
			. '.sev{font-size:12px;font-weight:600;white-space:nowrap;text-transform:capitalize}.sev--critical{color:#b32d2e}.sev--high{color:#b32d2e}.sev--medium{color:#996800}.sev--low,.sev--info{color:#50575e}'
			. 'footer{border-top:1px solid #dcdcde;margin-top:20px;padding-top:12px}'
			. '@page{margin:16mm 14mm}@media print{body{font-size:12px}main{max-width:none;padding:0}h1{font-size:22px}.score__number{font-size:36px}section{padding-top:12px}}';
	}
}
