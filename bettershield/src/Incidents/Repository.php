<?php
/** Durable, site-local incidents. Open evidence does not expire. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Incidents;
use BetterShield\Database\Schema;
use BetterShield\Support\Time;
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- plugin-owned tables; fresh evidence and lifecycle checks.
final class Repository {

	/** @var array<int, array{type: string, at: string, file: string}> See opened_by(). */
	private static array $opened_now = array();
	/** The longest handled incidents are kept, in days. The default is the activity log's thirty. */
	public const HISTORY_DAYS_MAX = 180;
	/** Handled incidents older than this are no longer read or counted. */
	public static function retention_floor(): string {
		return Time::stamp( time() - self::history_days() * DAY_IN_SECONDS );
	}
	public static function history_days(): int {
		// Never shorter than what an update found kept, while its grace lasts (#1721).
		return max( self::answered_days(), \BetterShield\Database\RetentionGrace::days( 'incidents' ) );
	}
	/** How long handled incidents stay on disk: the read window, or a longer one answered within the last thirty days (#1355). */
	public static function kept_days(): int {
		return max( self::history_days(), \BetterShield\Database\RetentionHold::days( 'incidents', self::answered_days() ) );
	}
	/** What the filter answers, held to its range. */
	private static function answered_days(): int {
		/**
		 * How many days handled incidents are kept, from thirty to 180. Open
		 * incidents never expire. Anything outside the range is held to its
		 * nearer end.
		 *
		 * @param int $days Thirty by default.
		 */
		$days = (int) apply_filters( 'bettershield_incident_history_days', \BetterShield\Database\Pruner::RETENTION_DAYS );
		return max( \BetterShield\Database\Pruner::RETENTION_DAYS, min( self::HISTORY_DAYS_MAX, $days ) );
	}
	public static function error(): \WP_Error { return new \WP_Error( 'bettershield_incidents_unreadable', __( 'Incident records could not be read or saved. Try again after checking database health.', 'bettershield' ), array( 'status' => 503 ) ); }

	/** Internal writer, serialized by Engine's site claim. False retains the source cursor. */
	public static function ingest( array $signal ): bool {
		global $wpdb;
		$table = Schema::table( 'incident_evidence' );
		$subject = $signal['snapshot'];
		$signal['subject_key'] = in_array( $subject['object_type'], array( 'user', 'file' ), true ) && '' !== $subject['object_id'] ? hash( 'sha256', $subject['object_type'] . ':' . $subject['object_id'] ) : '';
		$existing = $wpdb->get_row( $wpdb->prepare( 'SELECT id, incident_id FROM %i WHERE source_key = %s', $table, $signal['source_key'] ) );
		if ( '' !== $wpdb->last_error ) { return false; }
		if ( null === $existing ) {
			$row = $signal;
			// Said in the opening's own record, and no column of the evidence.
			unset( $row['announced'] );
			$row['snapshot'] = wp_json_encode( $row['snapshot'] );
			if ( false === $wpdb->insert( $table, $row ) ) { return false; }
			$id = (int) $wpdb->insert_id;
		} else {
			if ( (int) $existing->incident_id > 0 ) { return true; }
			$id = (int) $existing->id;
		}
		return self::attach( $id, $signal );
	}

	/** Temporal proximity is labeled as such; it never supplies an actor. */
	private static function attach( int $id, array $signal ): bool {
		global $wpdb;
		$announced = ! empty( $signal['announced'] );
		$incident_table = Schema::table( 'incidents' );
		$evidence = Schema::table( 'incident_evidence' );
		$at = strtotime( $signal['occurred_at'] . ' UTC' );
		$actor = (int) $signal['actor_id'];
		$subject = (string) ( $signal['subject_key'] ?? '' );
		$from = Time::stamp( $at - DAY_IN_SECONDS ); $to = Time::stamp( $at + DAY_IN_SECONDS );
		// Prepared identifiers and scalar bounds only. The subquery requires
		// a recorded actor on an anchor, never on an inferred file observation.
		$incident = $wpdb->get_row( $wpdb->prepare(
			"SELECT i.id, MAX(a.actor_id=%d AND %d>0) AS same_actor, MAX(a.subject_key=%s AND %s<>'') AS same_subject FROM %i i INNER JOIN %i a ON a.incident_id=i.id AND a.anchor<>'' WHERE i.status IN ('new','acknowledged') AND (a.occurred_at BETWEEN %s AND %s OR (a.actor_id=%d AND %d>0) OR (a.subject_key=%s AND %s<>'')) GROUP BY i.id ORDER BY same_actor DESC, same_subject DESC, i.id ASC LIMIT 1",
			$actor, $actor, $subject, $subject, $incident_table, $evidence, $from, $to, $actor, $actor, $subject, $subject
		) );
		if ( '' !== $wpdb->last_error ) { return false; }
		$relation = $incident && $incident->same_actor ? 'same_actor' : ( $incident && $incident->same_subject ? 'same_subject' : 'within_24h' );
		if ( ! $incident && '' !== $signal['anchor'] ) {
			$made = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO %i (anchor_key, opened_at, updated_at) VALUES (%s, %s, %s)", $incident_table, $signal['source_key'], $signal['occurred_at'], $signal['occurred_at'] ) );
			if ( false === $made ) { return false; }
			$incident = $wpdb->get_row( $wpdb->prepare( 'SELECT id FROM %i WHERE anchor_key=%s', $incident_table, $signal['source_key'] ) );
			if ( ! $incident || '' !== $wpdb->last_error ) { return false; }
			$relation = 'anchor';
			// Its opening is news on its own, high, so the instant alert names
			// it: the emails about its events never said one had opened (#2246).
			if ( 1 === (int) $made ) {
				// What opened it, so only an email about that row names it.
				self::$opened_now[ (int) $incident->id ] = array(
					'type' => (string) $signal['event_type'],
					'at'   => (string) $signal['occurred_at'],
					'file' => 'file' === ( $signal['snapshot']['object_type'] ?? '' ) ? (string) $signal['snapshot']['object_id'] : '',
				);
				\BetterShield\Events\Writer::instance()->record( 'incident_opened', \BetterShield\Events\Writer::SEVERITY_HIGH, array( 'object_type' => 'incident', 'object_id' => (string) $incident->id, 'context' => array( 'anchor' => (string) $signal['anchor'], 'source' => (string) $signal['event_type'], 'announced' => $announced ) ) );
			}
		}
		if ( ! $incident ) { return true; }
		if ( false === $wpdb->update( $evidence, array( 'incident_id' => (int) $incident->id, 'relation' => $relation ), array( 'id' => $id, 'incident_id' => 0 ) ) ) { return false; }
		return false !== $wpdb->query( $wpdb->prepare( 'UPDATE %i SET updated_at=GREATEST(updated_at,%s) WHERE id=%d', $incident_table, $signal['occurred_at'], $incident->id ) );
	}

	/**
	 * The incidents this request opened from one of these events, for the
	 * email going out about them. Matched on the opening row's type and
	 * moment, or for a code file, on its path: the file's own alert carries
	 * its path, not the moment the check found it. An incident opened in the
	 * same request by an unrelated event is not one of them.
	 *
	 * @param array<int, array{type: string, at: string, id?: ?string}> $events
	 * @return int[]
	 */
	public static function opened_by( array $events ): array {
		$ids = array();
		foreach ( self::$opened_now as $id => $opening ) {
			foreach ( $events as $event ) {
				$same_row  = (string) $event['type'] === $opening['type'] && (string) $event['at'] === $opening['at'];
				$same_file = '' !== $opening['file'] && 'file_changed' === (string) $event['type'] && $opening['file'] === (string) ( $event['id'] ?? '' );
				if ( $same_row || $same_file ) { $ids[] = (int) $id; break; }
			}
		}
		return $ids;
	}

	/**
	 * The open incidents that hold any of these events as evidence, newest
	 * first, each with when it opened and how much evidence it holds: what an
	 * instant alert says about the events it lists (#2246). Matched on the
	 * event's type and moment, which is what its evidence row copies. Empty
	 * when none does, or the tables cannot be read.
	 *
	 * @param array<int, array{type: string, at: string}> $events
	 * @return array<int, array{id: int, opened_at: string, evidence: int}>
	 */
	public static function holding( array $events ): array {
		global $wpdb;
		if ( array() === $events || ! Schema::ready( 'incidents' ) ) { return array(); }
		$where = array(); $values = array( Schema::table( 'incident_evidence' ), Schema::table( 'incidents' ) );
		foreach ( array_slice( $events, 0, 20 ) as $event ) { $where[] = '(e.event_type=%s AND e.occurred_at=%s)'; $values[] = (string) $event['type']; $values[] = (string) $event['at']; }
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- placeholder list built above, every value bound.
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT e.incident_id FROM %i e INNER JOIN %i i ON i.id=e.incident_id WHERE i.status IN ('new','acknowledged') AND (" . implode( ' OR ', $where ) . ') ORDER BY e.incident_id DESC LIMIT 3', $values ) );
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		if ( '' !== $wpdb->last_error || ! is_array( $ids ) ) { return array(); }
		return self::described( array_map( 'intval', $ids ) );
	}

	/**
	 * Open incidents by number, newest first, each with when it opened and
	 * how much evidence it holds. Numbers that are not open are left out.
	 *
	 * @param int[] $ids
	 * @return array<int, array{id: int, opened_at: string, evidence: int}>
	 */
	public static function described( array $ids ): array {
		global $wpdb;
		$ids = array_values( array_filter( array_unique( array_map( 'intval', $ids ) ) ) );
		if ( array() === $ids || ! Schema::ready( 'incidents' ) ) { return array(); }
		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- placeholder list from integers, every value bound.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT i.id, i.opened_at, COUNT(e.id) AS evidence FROM %i i LEFT JOIN %i e ON e.incident_id=i.id WHERE i.status IN ('new','acknowledged') AND i.id IN (" . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ') GROUP BY i.id, i.opened_at ORDER BY i.id DESC', array_merge( array( Schema::table( 'incidents' ), Schema::table( 'incident_evidence' ) ), $ids ) ), ARRAY_A );
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		if ( '' !== $wpdb->last_error || ! is_array( $rows ) ) { return array(); }
		return array_map(
			static function ( array $row ): array {
				$stats = self::stats( (int) $row['id'] );
				// Its title, as the Incidents screen names it (#2616).
				return array( 'id' => (int) $row['id'], 'opened_at' => (string) $row['opened_at'], 'evidence' => (int) $row['evidence'], 'title' => self::claim( is_wp_error( $stats ) ? 'review' : (string) $stats['confidence'] ) ?: self::claim( 'review' ) );
			},
			$rows
		);
	}

	/**
	 * What an incident's correlation claims, as its title: the words the
	 * Incidents screen, the report and the alert email all use for it.
	 * '' for a confidence it doesn't know.
	 */
	public static function claim( string $confidence ): string {
		$claims = array(
			'review'        => __( 'Related changes worth a look', 'bettershield' ),
			'pattern'       => __( 'Changes to sign-ins and files happened close together', 'bettershield' ),
			'linked_access' => __( 'One account made several sign-in or role changes', 'bettershield' ),
			'decoy_used'    => __( 'Someone tried to sign in with the decoy credential', 'bettershield' ),
		);

		return $claims[ $confidence ] ?? '';
	}

	/** Backfill earlier corroboration after an anchor arrives. Bounded per tick. */
	public static function attach_waiting(): int|false {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT e.id,e.occurred_at,e.actor_id,e.subject_key,e.anchor,e.source_key FROM %i e WHERE e.incident_id=0 AND EXISTS(SELECT 1 FROM %i i INNER JOIN %i a ON a.incident_id=i.id AND a.anchor<>'' WHERE i.status IN ('new','acknowledged') AND (ABS(TIMESTAMPDIFF(SECOND,a.occurred_at,e.occurred_at))<=86400 OR (e.actor_id>0 AND a.actor_id=e.actor_id) OR (e.subject_key<>'' AND a.subject_key=e.subject_key))) ORDER BY e.id ASC LIMIT 200", Schema::table( 'incident_evidence' ), Schema::table( 'incidents' ), Schema::table( 'incident_evidence' ) ), ARRAY_A );
		if ( '' !== $wpdb->last_error ) { return false; }
		foreach ( $rows as $row ) { if ( ! self::attach( (int) $row['id'], $row ) ) { return false; } }
		return count( $rows );
	}

	/**
	 * How many incidents are open: new or acknowledged, the set `page()`
	 * lists for `open`. Null when the table cannot be read.
	 */
	public static function open_count(): ?int {
		global $wpdb;
		if ( ! Schema::ready( 'incidents' ) ) { return null; }
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE status IN ('new','acknowledged')", Schema::table( 'incidents' ) ) );
		return '' !== $wpdb->last_error || null === $count ? null : (int) $count;
	}

	/**
	 * How many each list of `page()` holds, open and handled, so both tabs
	 * can say it: the tab not open said nothing, and after Mark handled the
	 * incident just moved was counted nowhere (#1921). Null when the table
	 * cannot be read.
	 *
	 * The evidence behind the open ones too: the cards above the list
	 * summed the page on screen, so the Handled tab read "Evidence 0" while
	 * an open incident had two, and more than a page undercounted (#2243).
	 *
	 * @return array{open: int, resolved: int, open_evidence: int}|null
	 */
	public static function status_counts(): ?array {
		global $wpdb;
		if ( ! Schema::ready( 'incidents' ) ) { return null; }
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT SUM(status IN ('new','acknowledged')) AS open_count, SUM(status='resolved' AND resolved_at>=%s) AS resolved_count FROM %i", self::retention_floor(), Schema::table( 'incidents' ) ), ARRAY_A );
		if ( '' !== $wpdb->last_error || ! is_array( $row ) ) { return null; }
		$evidence = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i e INNER JOIN %i i ON i.id=e.incident_id WHERE i.status IN ('new','acknowledged')", Schema::table( 'incident_evidence' ), Schema::table( 'incidents' ) ) );
		if ( '' !== $wpdb->last_error ) { return null; }
		return array( 'open' => (int) $row['open_count'], 'resolved' => (int) $row['resolved_count'], 'open_evidence' => (int) $evidence );
	}

	/** @return array|\WP_Error */
	public static function page( string $status = 'open', int $before = 0, int $limit = 20 ): array|\WP_Error {
		global $wpdb;
		$floor = self::retention_floor();
		$limit = max( 1, min( 20, $limit ) );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM %i WHERE ((%s='open' AND status IN ('new','acknowledged')) OR (%s='resolved' AND status='resolved' AND resolved_at>=%s)) AND (%d=0 OR id<%d) ORDER BY id DESC LIMIT %d", Schema::table( 'incidents' ), $status, $status, $floor, $before, $before, $limit + 1 ), ARRAY_A );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		$more = count( $rows ) > $limit; $rows = array_slice( $rows, 0, $limit );
		foreach ( $rows as &$row ) {
			$stats = self::stats( (int) $row['id'] );
			if ( is_wp_error( $stats ) ) { return $stats; }
			$row = self::projection( $row ) + $stats;
		}
		unset( $row );
		return array( 'incidents' => $rows, 'next_cursor' => $more ? (int) $rows[ count( $rows ) - 1 ]['id'] : 0 );
	}
	/**
	 * The name of the plugin or theme a file record's path is inside, as its
	 * header names it, for the row the timeline folds its files into: the
	 * folder said "bettershield" where every other screen says "BetterShield"
	 * (#2484). Null for a file in no plugin or theme folder.
	 *
	 * @param array<string, mixed> $snapshot The record's snapshot.
	 */
	private static function package_name( array $snapshot ): ?string {
		$parts = explode( '/', (string) ( $snapshot['object_id'] ?? '' ) );

		if ( 'file' !== ( $snapshot['object_type'] ?? '' ) || 'wp-content' !== $parts[0] || ! isset( $parts[2] ) || ! in_array( $parts[1], array( 'plugins', 'themes' ), true ) ) {
			return null;
		}

		return \BetterShield\Integrity\Packages::name_of( 'themes' === $parts[1] ? 'theme' : 'plugin', $parts[2] );
	}
	private static function projection( array $row ): array {
		return array( 'id' => (int) $row['id'], 'status' => $row['status'], 'opened_at' => Time::utc_iso( $row['opened_at'] ), 'updated_at' => Time::utc_iso( $row['updated_at'] ), 'resolved_at' => empty( $row['resolved_at'] ) ? '' : Time::utc_iso( $row['resolved_at'] ) );
	}
	/**
	 * The network each activity row came from, read from its log row as the
	 * record is shown and never copied into the snapshot: the snapshot
	 * outlives the log, and a network kept there would escape the erasure a
	 * person may ask for.
	 *
	 * Only for rows a person or an anonymous visitor caused. A scheduled task
	 * records whatever address ran the scheduler, which says nothing about who
	 * acted. A log row since pruned, or one recorded without a request behind
	 * it, answers null, which the screen says as "No network recorded".
	 *
	 * @param array<int, array<string, mixed>> $evidence
	 * @return array<int, array<string, mixed>>
	 */
	private static function with_networks( array $evidence ): array {
		global $wpdb;
		$ids = array();
		foreach ( $evidence as $e ) {
			if ( 'activity' === ( $e['snapshot']['source'] ?? '' ) && (int) ( $e['snapshot']['source_id'] ?? 0 ) > 0 ) { $ids[] = (int) $e['snapshot']['source_id']; }
		}
		$networks = array();
		if ( array() !== $ids ) {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers from Schema::site_where(), and the ids are integers bound through placeholders.
			$found = $wpdb->get_results( $wpdb->prepare( 'SELECT id, actor_type, ip_prefix FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND id IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', array_merge( array( Schema::table( 'events' ) ), $ids ) ) );
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			foreach ( is_array( $found ) ? $found : array() as $event ) {
				if ( in_array( (string) $event->actor_type, array( 'user', 'anonymous' ), true ) ) { $networks[ (int) $event->id ] = \BetterShield\Support\Ip::prefix_label( $event->ip_prefix ?? null ); }
			}
		}
		foreach ( $evidence as $index => $e ) {
			if ( 'activity' === ( $e['snapshot']['source'] ?? '' ) ) { $evidence[ $index ]['network'] = $networks[ (int) ( $e['snapshot']['source_id'] ?? 0 ) ] ?? null; }
		}
		return $evidence;
	}

	/**
	 * The incident's span as whole days in the site's own time zone, and as
	 * the moments it starts and ends.
	 *
	 * The activity log reads its days in the reader's calendar, so the screen
	 * turns the moments into the reader's own days: site days slid off the
	 * incident's rows for a reader in another zone.
	 *
	 * From the earliest evidence, not the anchor: the same account or subject
	 * joins with no time limit, so evidence can be days older than the anchor,
	 * and a span that began at the anchor left it out of every link to the
	 * activity around the incident.
	 *
	 * @param array<string, mixed>                       $row
	 * @param array{first?: ?string, last?: ?string}     $span The earliest and latest evidence, as stored.
	 * @return array{since: string, until: string, start: ?string, end: ?string}
	 */
	private static function window( array $row, array $span = array() ): array {
		$opened  = (int) strtotime( (string) $row['opened_at'] . ' UTC' );
		$updated = (int) strtotime( (string) $row['updated_at'] . ' UTC' );
		$first   = empty( $span['first'] ) ? $opened : min( $opened, (int) strtotime( (string) $span['first'] . ' UTC' ) );
		$last    = max( $opened, $updated, empty( $span['last'] ) ? 0 : (int) strtotime( (string) $span['last'] . ' UTC' ) );

		return array(
			'since' => wp_date( 'Y-m-d', $first ),
			'until' => wp_date( 'Y-m-d', $last ),
			'start' => gmdate( 'Y-m-d\TH:i:s\Z', $first ),
			'end'   => gmdate( 'Y-m-d\TH:i:s\Z', $last ),
		);
	}
	private static function stats( int $id ): array|\WP_Error {
		global $wpdb;
		// A named sign of compromise on an added file counts as one more
		// piece of corroboration, as a second row would: it can move an
		// incident from review to pattern, and nothing more.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS total, SUM(anchor<>'') AS anchors, SUM(anchor='credential') AS credential, COUNT(DISTINCT CASE WHEN anchor<>'' AND actor_id>0 THEN actor_id ELSE NULL END) AS actors, SUM(snapshot LIKE %s) AS signs FROM %i WHERE incident_id=%d", '%' . $wpdb->esc_like( '"signals":[{' ) . '%', Schema::table( 'incident_evidence' ), $id ), ARRAY_A );
		if ( ! $row || '' !== $wpdb->last_error ) { return self::error(); }
		$repeat = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM %i WHERE incident_id=%d AND anchor<>'' AND actor_id>0 GROUP BY actor_id HAVING COUNT(*)>=2 LIMIT 1", Schema::table( 'incident_evidence' ), $id ) );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		$confidence = (int) $row['credential'] > 0 ? 'decoy_used' : ( (int) $repeat > 1 ? 'linked_access' : ( (int) $row['total'] + (int) $row['signs'] > 1 ? 'pattern' : 'review' ) );
		return array( 'confidence' => $confidence, 'evidence_count' => (int) $row['total'], 'anchor_count' => (int) $row['anchors'] );
	}
	public static function detail( int $id, int $after = 0 ): array|\WP_Error {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM %i WHERE id=%d AND (status<>'resolved' OR resolved_at>=%s)", Schema::table( 'incidents' ), $id, self::retention_floor() ), ARRAY_A );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		if ( ! $row ) { return new \WP_Error( 'bettershield_incident_missing', __( 'That incident is not available on this site.', 'bettershield' ), array( 'status' => 404 ) ); }
		$stats = self::stats( $id ); if ( is_wp_error( $stats ) ) { return $stats; }
		// ID order makes the cursor stable even when a late scan finds earlier evidence.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE incident_id=%d AND id>%d ORDER BY id ASC LIMIT 101', Schema::table( 'incident_evidence' ), $id, $after ), ARRAY_A );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		$more = count( $rows ) > 100; $rows = array_slice( $rows, 0, 100 );
		$out = array();
		foreach ( $rows as $e ) {
			$snapshot = json_decode( $e['snapshot'], true );
			$snapshot = is_array( $snapshot ) ? $snapshot : array();
			$out[]    = array( 'id' => (int) $e['id'], 'occurred_at' => Time::utc_iso( $e['occurred_at'] ), 'actor_id' => (int) $e['actor_id'], 'anchor' => $e['anchor'], 'type' => $e['event_type'], 'label' => \BetterShield\Events\Types::label( $e['event_type'] ), 'relation' => $e['relation'], 'snapshot' => $snapshot,
				// What the record is about, named as the activity log names it,
				// rather than as a bare id or key (#1793). The details hold what
				// names it, such as a plugin's name in place of its file.
				'object_label' => \BetterShield\Events\Query::object_label( (string) $e['event_type'], isset( $snapshot['object_type'] ) ? (string) $snapshot['object_type'] : null, isset( $snapshot['object_id'] ) ? (string) $snapshot['object_id'] : null, $snapshot['details'] ?? array() ),
				'package_name' => self::package_name( $snapshot ),
			);
		}
		$out = self::with_networks( $out );
		// Over all of the incident's evidence, not the page loaded.
		$span = $wpdb->get_row( $wpdb->prepare( 'SELECT MIN(occurred_at) AS first, MAX(occurred_at) AS last FROM %i WHERE incident_id=%d', Schema::table( 'incident_evidence' ), $id ), ARRAY_A );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		return self::projection( $row ) + $stats + array( 'site_id' => get_current_blog_id(), 'window' => self::window( $row, is_array( $span ) ? $span : array() ), 'evidence' => $out, 'next_cursor' => $more ? (int) end( $out )['id'] : 0 );
	}
	public const STATUS_UNDO = 'incident_status';
	/** Only bounded facts: changing evidence or status invalidates the plan. */
	public static function status_digest( array $record ): string {
		return (string) \BetterShield\Agents\Capture::digest( array_intersect_key( $record, array_flip( array( 'id', 'site_id', 'status', 'opened_at', 'updated_at', 'resolved_at', 'evidence_count', 'anchor_count' ) ) ) );
	}
	public static function status( int $id, string $status, ?string $expected = null, bool $undo = false ): array|\WP_Error {
		if ( ! \BetterShield\Support\Claim::claim( Engine::CLAIM, 30 ) ) { return new \WP_Error( 'bettershield_incident_busy', __( 'Incident records are updating. Try again shortly.', 'bettershield' ), array( 'status' => 409 ) ); }
		try {
			$record = self::detail( $id ); if ( is_wp_error( $record ) ) { return $record; }
			if ( null !== $expected && ! hash_equals( $expected, self::status_digest( $record ) ) ) { return \BetterShield\Abilities\WriteTriage::moved(); }
			$token = null;
			if ( $undo && 'resolved' === $status && 'resolved' !== $record['status'] ) {
				$token = \BetterShield\Undo\Ledger::open( self::STATUS_UNDO, array( 'incident_id' => $id, 'status' => $record['status'] ), array( 'incident_id' => $id, 'status' => 'resolved' ) );
				if ( null === $token ) { return new \WP_Error( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 503 ) ); }
			}
			$result = self::set_status( $id, $status, $token );
			if ( is_wp_error( $result ) ) { if ( null !== $token ) { \BetterShield\Undo\Ledger::mark_reverted( $token ); } return $result; }
			return $result + ( null === $token ? array() : array( 'undo_token' => $token ) );
		} finally { \BetterShield\Support\Claim::release( Engine::CLAIM ); }
	}
	/** An old handle never reopens an incident that has since been reopened and handled again. */
	public static function undo_status( string $token ): array|\WP_Error {
		if ( ! \BetterShield\Support\Claim::claim( Engine::CLAIM, 30 ) ) { return new \WP_Error( 'bettershield_incident_busy', __( 'Incident records are updating. Try again shortly.', 'bettershield' ), array( 'status' => 409 ) ); }
		try {
			$entry = \BetterShield\Undo\Ledger::find( $token );
			if ( null === $entry || self::STATUS_UNDO !== $entry->action_key || null !== $entry->reverted_at ) { return new \WP_Error( 'bettershield_unknown_undo', __( 'That incident change is no longer available to undo.', 'bettershield' ), array( 'status' => 409 ) ); }
			$id = (int) ( $entry->applied_state['incident_id'] ?? 0 );
			$record = self::detail( $id ); if ( is_wp_error( $record ) ) { return $record; }
			if ( 'resolved' !== $record['status'] ) { return \BetterShield\Abilities\WriteTriage::moved(); }
			return self::set_status( $id, 'acknowledged' );
		} finally { \BetterShield\Support\Claim::release( Engine::CLAIM ); }
	}
	private static function set_status( int $id, string $status, ?string $keep_token = null ): array|\WP_Error {
		global $wpdb;
		if ( ! in_array( $status, array( 'acknowledged', 'resolved' ), true ) ) { return new \WP_Error( 'bettershield_incident_status', __( 'Choose acknowledged or resolved.', 'bettershield' ), array( 'status' => 400 ) ); }
		$record = self::detail( $id ); if ( is_wp_error( $record ) ) { return $record; }
		if ( $status === $record['status'] ) { return $record; }
		// Acknowledged from handled is a reopening: it is open again, collects
		// evidence again and is not pruned. Marking handled was final, and a
		// click on the wrong row stopped an incident growing for good.
		$reopened = 'resolved' === $record['status'];
		// Retire every earlier handle in the same statement as the status change.
		// A failed retirement must never leave an old handle able to reopen a later resolution.
		$now = Time::stamp();
		$changed = $wpdb->query( $wpdb->prepare(
			"UPDATE %i i LEFT JOIN %i u ON u.action_key=%s AND u.site_id=0 AND u.reverted_at IS NULL AND JSON_UNQUOTE(JSON_EXTRACT(u.applied_state, '$.incident_id'))=%s AND u.token<>%s SET i.status=%s,i.resolved_at=CASE WHEN %s='resolved' THEN %s ELSE NULL END,u.reverted_at=%s WHERE i.id=%d",
			Schema::table( 'incidents' ), Schema::table( 'undo' ), self::STATUS_UNDO, (string) $id, $keep_token ?? '', $status, $status, $now, $now, $id
		) );
		if ( false === $changed ) { return self::error(); }
		\BetterShield\Events\Writer::instance()->record( 'incident_status_changed', \BetterShield\Events\Writer::SEVERITY_MEDIUM, array( 'object_type' => 'incident', 'object_id' => (string) $id, 'context' => array( 'status' => $status ) + ( $reopened ? array( 'reopened' => true ) : array() ) ) );
		return self::detail( $id );
	}

	/** Counts from retained evidence, never a claim about unobserved history. */
	public static function history( int $id ): array|\WP_Error {
		global $wpdb;
		// Never before this plugin was watching: a site that had it for a day
		// was told about six months it never saw.
		// A missing stamp is no bound: strtotime( ' UTC' ) is this second, which
		// counted nothing older than the request.
		$stamp     = (string) get_option( 'bettershield_activated_at', '' );
		$activated = '' !== $stamp ? strtotime( $stamp . ' UTC' ) : false;
		$floor     = max( Time::stamp( time() - 180 * DAY_IN_SECONDS ), self::retention_floor(), false !== $activated && $activated > 0 ? Time::stamp( $activated ) : '' );
		$total = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE opened_at>=%s', Schema::table( 'incidents' ), $floor ) );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		$related = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT i.id) FROM %i i INNER JOIN %i e ON e.incident_id=i.id AND e.anchor<>'' AND e.actor_id>0 WHERE i.id<>%d AND i.opened_at>=%s AND EXISTS(SELECT 1 FROM %i a WHERE a.incident_id=%d AND a.anchor<>'' AND a.actor_id=e.actor_id)", Schema::table( 'incidents' ), Schema::table( 'incident_evidence' ), $id, $floor, Schema::table( 'incident_evidence' ), $id ) );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		return array( 'since' => Time::utc_iso( $floor ), 'recorded_incidents' => (int) $total, 'other_incidents_sharing_actor' => (int) $related );
	}

	/** Open records and their evidence never expire. Closed records are kept for the history window, or a longer one still held to (`Database\RetentionHold`). */
	public static function prune(): void {
		global $wpdb;
		\BetterShield\Database\RetentionHold::note( 'incidents', self::answered_days() );
		$cutoff = Time::stamp( time() - self::kept_days() * DAY_IN_SECONDS );
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM %i WHERE status='resolved' AND resolved_at<%s ORDER BY id LIMIT 20", Schema::table( 'incidents' ), $cutoff ) );
		foreach ( $ids as $id ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE incident_id=%d LIMIT 500', Schema::table( 'incident_evidence' ), $id ) );
			$left = $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM %i WHERE incident_id=%d LIMIT 1', Schema::table( 'incident_evidence' ), $id ) );
			if ( '' === $wpdb->last_error && null === $left ) { $wpdb->delete( Schema::table( 'incidents' ), array( 'id' => $id ) ); }
		}
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE incident_id=0 AND occurred_at<%s LIMIT 500', Schema::table( 'incident_evidence' ), $cutoff ) );
	}
}
