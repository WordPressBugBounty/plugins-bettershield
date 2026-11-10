<?php
/**
 * What the integrity check has to say, for every surface that asks.
 *
 * One definition, read by the audit check that scores it, the REST route the
 * screen draws from, the WP-CLI command, and Site Health. Four readers of the
 * same facts that computed them separately would eventually disagree, and a
 * security screen disagreeing with its own terminal is the kind of small
 * dishonesty this product exists not to commit.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Report {

	/** Statuses that still want a decision from somebody. */
	public const OPEN_STATUSES = array( 'new', 'acknowledged' );

	/** How many changes marked expected one page of that list carries. */
	public const EXPECTED_PAGE = 50;

	/**
	 * Where a change lives, as the screen's filter names it, and the
	 * contexts each place covers: a plugin nothing publishes is a plugin, and
	 * the root, drop-ins, must-use plugins and configuration files are the
	 * rest.
	 */
	public const PLACES = array(
		'core'   => array( Manifest::CONTEXT_CORE ),
		'plugin' => array( Manifest::CONTEXT_PLUGIN, Unpublished::CONTEXT_UNLISTED ),
		'theme'  => array( Unpublished::CONTEXT_THEME ),
		'other'  => array( Manifest::CONTEXT_EXTRA, Unpublished::CONTEXT_DROPIN, Unpublished::CONTEXT_MUPLUGIN, Unpublished::CONTEXT_CONFIG ),
	);

	/** The kinds of change a filter can ask for. */
	public const CHANGE_TYPES = array( 'modified', 'added', 'removed', 'unreadable', IncomingPackage::CHANGE_TYPE );

	/** The grades a change can carry (Scanner::grade_of()). */
	public const SEVERITIES = array( 'critical', 'high', 'medium', 'low' );

	/** The longest path search the filter takes. */
	public const SEARCH_MAX = 200;

	/** How many added code files the count of a filter's matches names. */
	public const NAMED_CODE = 20;

	/**
	 * How far along a check is, in terms somebody waiting can read.
	 *
	 * The longest operation this plugin has showed an indeterminate spinner
	 * and one sentence, which on a multi-minute job on a large site reads as
	 * hung — and the thing somebody does about a hung page is reload it, which
	 * starts the run again. The scanner already knows all of this: it chunks
	 * by target and keeps its cursor so it can resume.
	 *
	 * Deliberately coarse. Within a target the offset is a position in a list
	 * whose length is known only while that chunk is in hand, so a percentage
	 * derived from it would move in jumps and stall for whole minutes on a big
	 * plugin. Targets completed is a number that only ever goes up, and the
	 * file count beside it is the evidence that something is happening between
	 * one target and the next.
	 *
	 * @param array<string, mixed> $running
	 * @return array<string, mixed>|null
	 */
	private static function progress( array $running ): ?array {
		if ( array() === $running ) {
			return null;
		}

		$targets = (array) ( $running['targets'] ?? array() );
		$index   = (int) ( $running['index'] ?? 0 );
		$current = $targets[ $index ] ?? null;

		return array(
			'target'  => $index,
			'targets' => count( $targets ),
			// Which of the two passes this is: the published list, then the
			// disk walk that finds what nobody published at all.
			'phase'   => (string) ( $running['phase'] ?? 'manifest' ),
			'checked' => (int) ( $running['stats']['checked'] ?? 0 ),
			// What is being checked right now, so the sentence names something
			// the reader recognizes rather than a number out of a number.
			'label'   => is_array( $current ) ? self::target_label( $current ) : null,
		);
	}

	/**
	 * What to call a target on screen.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function target_label( array $target ): string {
		if ( Manifest::CONTEXT_CORE === ( $target['context'] ?? '' ) ) {
			return __( 'WordPress itself', 'bettershield' );
		}

		$slug = (string) ( $target['slug'] ?? '' );

		return '' !== $slug ? $slug : __( 'this site', 'bettershield' );
	}

	/**
	 * The whole state: what the last run found, what is still open, what could
	 * not be checked, and when any of it last happened.
	 *
	 * @param string                $cursor Where the page of open changes starts.
	 * @param array<string, string> $filter Narrows the open changes listed; see changes().
	 * @return array<string, mixed>
	 */
	public static function all( string $cursor = '', array $filter = array() ): array {
		$result  = Scanner::last_result();
		$running = Scanner::state();
		$page = self::changes_page( $cursor, $filter );
		$expected = self::suppressed_page();
		$batches  = Packages::batches_page();

		return array(
			// Always present, always the truth about freshness. A screen that
			// cannot say when a check last ran cannot be trusted to say a site
			// is clean.
			'last_run_at'    => isset( $result['finished_at'] ) ? (string) $result['finished_at'] : null,
			'ever_run'       => null !== $result,
			// A subsite of a network reads the main site's check and runs none.
			'elsewhere'      => Shared::elsewhere(),
			'running'        => array() !== $running,
			'progress'       => self::progress( $running ),
			'stats'          => isset( $result['stats'] ) ? (array) $result['stats'] : null,
			// Named rather than counted: "two things could not be checked" is
			// not actionable, and "your commercial plugin and a release
			// candidate could not be checked" is.
			'unverifiable'   => isset( $result['unverifiable'] ) ? (array) $result['unverifiable'] : array(),
			// With how many of them can be put back, counted across every
			// page: the screen leads with that number and the group it heads.
			'open_changes'   => array_merge( self::open_count(), array( 'restorable' => self::open_restorable() ) ),
			'changes'        => is_wp_error( $page ) ? array() : $page['changes'],
			'changes_error'  => is_wp_error( $page ) ? $page->get_error_message() : null,
			'next_cursor'    => is_wp_error( $page ) ? null : $page['next_cursor'],
			// Only when the list is narrowed: how many open changes match,
			// whatever one page of them shows.
			'matching'       => array() !== $filter ? self::open_matching( $filter ) : null,
			// What was marked expected, so a marking can be taken back from
			// where it was made. Hidden from the list above by design, it was
			// otherwise shown nowhere. A page of it, with the count of all of
			// it and where the next page starts: a site with more marked than
			// one page holds was shown a list and a badge that both stopped
			// at the page.
			'suppressed'       => is_wp_error( $expected ) ? array() : $expected['changes'],
			'suppressed_total' => self::suppressed_total(),
			'suppressed_next'  => is_wp_error( $expected ) ? null : $expected['next_cursor'],
			// The open changes by plugin and version, counted across every
			// page, so a group can be checked again or marked as one.
			'packages'         => Packages::all(),
			// WordPress core's own changed files, summed apart from them and
			// shown first (#2118).
			'core'             => Packages::core(),
			// Markings made a group at a time, one line each: a page of
			// them, the count of all of them and where the next page starts,
			// the same way as the single markings above.
			'batches'          => $batches['batches'],
			'batches_total'    => Packages::batches_total(),
			'batches_next'     => $batches['next_cursor'],
			'next_run_at'    => self::next_run(),
			'missed_run_at'  => self::missed_run(),
		);
	}

	/**
	 * The first page of changes marked expected, newest first, or none where
	 * they cannot be read: the open list says when it cannot load, and this is
	 * its footnote.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function suppressed(): array {
		$page = self::suppressed_page();

		return is_wp_error( $page ) ? array() : $page['changes'];
	}

	/**
	 * One page of the changes marked expected one at a time, and where the
	 * next starts.
	 *
	 * A row a batch marking holds is left out: its batch is listed once, as
	 * one line, and a batch of hundreds here pushed every single marking off
	 * the page.
	 *
	 * @return array{changes: array<int, array<string, mixed>>, next_cursor: ?string}|\WP_Error
	 */
	public static function suppressed_page( string $cursor = '' ) {
		return self::page( array( 'suppressed' ), self::EXPECTED_PAGE, $cursor, __( 'The accepted changes could not be loaded. Try again.', 'bettershield' ), false, array_keys( Packages::held() ) );
	}

	/** How many changes are marked expected one at a time, whatever one page of them shows. */
	public static function suppressed_total(): int {
		global $wpdb;

		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status = 'suppressed'",
				Schema::table( 'integrity_changes' )
			)
		);

		foreach ( array_chunk( array_keys( Packages::held() ), 500 ) as $ids ) {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder run's length is the chunk's own, and every id is bound.
			$total -= (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status = 'suppressed' AND id IN (" . implode( ', ', array_fill( 0, count( $ids ), '%d' ) ) . ')',
					array_merge( array( Schema::table( 'integrity_changes' ) ), $ids )
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		return max( 0, $total );
	}

	/**
	 * One page of the open changes: the ones that can be put back first, then
	 * added files that can run as code, then the rest, newest first within
	 * each.
	 *
	 * The screen ranks that group first and counts it, and with it ordered by
	 * date alone a site with many newer unpublished files had it on the last
	 * page. A continuation carries the group and both immutable ordering
	 * values, even if its row is removed.
	 *
	 * @param string                $cursor Where the page starts.
	 * @param array<string, string> $filter Narrows the list; see changes().
	 */
	public static function changes_page( string $cursor = '', array $filter = array() ) {
		return self::page( self::OPEN_STATUSES, 200, $cursor, __( 'The open file changes could not be loaded. Try again.', 'bettershield' ), true, array(), $filter );
	}

	/**
	 * How many open changes a filter matches, whatever one page of them shows.
	 *
	 * @param array<string, string> $filter See changes().
	 */
	public static function open_matching( array $filter ): int {
		global $wpdb;

		list( $where, $args ) = self::filter_condition( $filter );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the condition is fixed SQL with placeholders, and every value is bound.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged'){$where}",
				array_merge( array( Schema::table( 'integrity_changes' ) ), $args )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	/**
	 * The screen's filter from what a request asked for: the place, the kind
	 * of change, the grade and a path search, each kept only where it is one
	 * this report knows, so an empty or unknown value narrows nothing.
	 *
	 * @param array<string, mixed> $params
	 * @return array<string, string>
	 */
	public static function filter_of( array $params ): array {
		$filter = array();
		$known  = array(
			'place'       => array_keys( self::PLACES ),
			'change_type' => self::CHANGE_TYPES,
			'severity'    => self::SEVERITIES,
		);

		foreach ( $known as $key => $values ) {
			$value = is_scalar( $params[ $key ] ?? null ) ? (string) $params[ $key ] : '';

			if ( in_array( $value, $values, true ) ) {
				$filter[ $key ] = $value;
			}
		}

		$search = is_scalar( $params['search'] ?? null ) ? trim( (string) $params['search'] ) : '';

		if ( '' !== $search ) {
			$filter['search'] = function_exists( 'mb_substr' ) ? mb_substr( $search, 0, self::SEARCH_MAX ) : substr( $search, 0, self::SEARCH_MAX );
		}

		return $filter;
	}

	/**
	 * A filter as a condition on a row: `change_type` and `context` matched
	 * exactly, `place` as the contexts it covers, `severity` by the rule
	 * Scanner::grade_of() applies to one row, `search` anywhere in the path
	 * or the plugin's folder name, `after` and `through` as a run of ids, and
	 * `restorable` as the rule restorable_condition() applies. Each only
	 * where it is given and not empty.
	 *
	 * @param array<string, string> $filter
	 * @return array{0: string, 1: array<int, string>} The condition, led by AND, and its values in order.
	 */
	private static function filter_condition( array $filter ): array {
		global $wpdb;

		$where = '';
		$args  = array();

		foreach ( array( 'change_type', 'context' ) as $column ) {
			if ( '' !== (string) ( $filter[ $column ] ?? '' ) ) {
				$where .= " AND {$column} = %s";
				$args[] = (string) $filter[ $column ];
			}
		}

		$place = (string) ( $filter['place'] ?? '' );

		if ( isset( self::PLACES[ $place ] ) ) {
			$where .= ' AND context IN (' . implode( ', ', array_fill( 0, count( self::PLACES[ $place ] ), '%s' ) ) . ')';
			$args   = array_merge( $args, self::PLACES[ $place ] );
		}

		if ( in_array( (string) ( $filter['severity'] ?? '' ), self::SEVERITIES, true ) ) {
			// Scanner::severity_of_change(), as a condition, in its order.
			$where .= " AND (CASE WHEN change_type = 'unreadable' THEN 'low'"
				. " WHEN change_type = 'removed' THEN 'medium'"
				. ' WHEN unconfirmed_update = ' . KnownWrites::EXPLAINED . " THEN 'medium'"
				. " WHEN change_type = '" . IncomingPackage::CHANGE_TYPE . "' THEN 'high'"
				. " WHEN change_type = 'added' AND context = %s THEN 'medium'"
				. " WHEN context = %s THEN 'medium'"
				. " WHEN change_type = 'added' AND context <> %s AND LOWER( path ) NOT REGEXP %s THEN 'medium'"
				. " WHEN unconfirmed_update = 1 THEN 'high'"
				. " ELSE 'critical' END) = %s";
			$args   = array_merge( $args, array( Unpublished::CONTEXT_CONFIG, Manifest::CONTEXT_EXTRA, Manifest::CONTEXT_CORE, Packages::RUNNABLE_PATTERN, (string) $filter['severity'] ) );
		}

		if ( '' !== (string) ( $filter['search'] ?? '' ) ) {
			$like   = '%' . $wpdb->esc_like( (string) $filter['search'] ) . '%';
			$where .= ' AND (path LIKE %s OR slug LIKE %s)';
			$args[] = $like;
			$args[] = $like;
		}

		// Not the screen's own: a run of ids, for a decision about every
		// row matched, held to the newest one counted.
		foreach ( array( 'after' => '>', 'through' => '<=' ) as $key => $operator ) {
			if ( isset( $filter[ $key ] ) ) {
				$where .= " AND id {$operator} %d";
				$args[] = max( 0, (int) $filter[ $key ] );
			}
		}

		// And the ones that can be put back, for a decision that puts them
		// back.
		if ( ! empty( $filter['restorable'] ) ) {
			list( $restorable, $restorable_args ) = self::restorable_condition();

			$where .= " AND {$restorable}";
			$args   = array_merge( $args, $restorable_args );
		}

		return array( $where, $args );
	}

	/**
	 * What every open change a filter matches holds, counted across every
	 * page, for a decision about all of them: by kind, how many can be put
	 * back, the added files that can run as code (named up to a point, then
	 * counted), and the newest row counted, which the decision is held to.
	 * A package's own difference is never one of a selection, so it is not
	 * counted here.
	 *
	 * @param array<string, string> $filter See filter_of().
	 * @return array{total: int, modified: int, added: int, removed: int, unreadable: int, restorable: int, added_code: string[], added_code_total: int, through: int}
	 */
	public static function matching( array $filter ): array {
		global $wpdb;

		list( $where, $args ) = self::filter_condition( $filter );
		$types                = Packages::SELECTION_TYPES;
		$in                   = ' AND change_type IN (' . implode( ', ', array_fill( 0, count( $types ), '%s' ) ) . ')';
		$table                = Schema::table( 'integrity_changes' );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the conditions are fixed SQL with placeholders, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT change_type, COUNT(*) AS n, MAX(id) AS top FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged'){$in}{$where} GROUP BY change_type",
				array_merge( array( $table ), $types, $args )
			)
		);

		$code_where = " AND change_type = 'added' AND LOWER( path ) REGEXP %s";
		$code_total = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT path) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged'){$where}{$code_where}",
				array_merge( array( $table ), $args, array( Packages::CODE_PATTERN ) )
			)
		);
		$code       = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT path FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged'){$where}{$code_where} ORDER BY path ASC LIMIT %d",
				array_merge( array( $table ), $args, array( Packages::CODE_PATTERN, self::NAMED_CODE ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array_merge( array( 'total' => 0 ), array_fill_keys( $types, 0 ) );
		$top = 0;

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[ (string) $row->change_type ] = (int) $row->n;
			$out['total']                     += (int) $row->n;
			$top                               = max( $top, (int) $row->top );
		}

		return $out + array(
			'restorable'       => self::open_matching( $filter + array( 'restorable' => '1' ) ),
			'added_code'       => array_map( 'strval', is_array( $code ) ? $code : array() ),
			'added_code_total' => $code_total,
			'through'          => $top,
		);
	}

	/**
	 * The open changes a filter matches, a bounded run of them by id, oldest
	 * first: past `$after`, at or below `$through` (the newest the owner was
	 * shown), never a package's own difference, and only the ones that can be
	 * put back where asked.
	 *
	 * @param array<string, string> $filter See filter_of().
	 * @return int[]
	 */
	public static function matching_ids( array $filter, int $after, int $through, int $limit, bool $restorable = false ): array {
		global $wpdb;

		$range                = array( 'after' => (string) $after, 'through' => (string) $through ) + ( $restorable ? array( 'restorable' => '1' ) : array() );
		list( $where, $args ) = self::filter_condition( $range + $filter );
		$types                = Packages::SELECTION_TYPES;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the condition is fixed SQL with placeholders, and every value is bound.
		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT id FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND change_type IN ("
					. implode( ', ', array_fill( 0, count( $types ), '%s' ) )
					. "){$where} ORDER BY id ASC LIMIT %d",
				array_merge( array( Schema::table( 'integrity_changes' ) ), $types, $args, array( max( 1, $limit ) ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array_map( 'intval', is_array( $ids ) ? $ids : array() );
	}

	/**
	 * One page of changes in the given statuses, newest first.
	 *
	 * @param string[]              $statuses
	 * @param array<string, string> $filter
	 * @return array{changes: array<int, array<string, mixed>>, next_cursor: ?string}|\WP_Error
	 */
	private static function page( array $statuses, int $size, string $cursor, string $unavailable, bool $restorable_first = false, array $except = array(), array $filter = array() ) {
		$at = ''; $id = 0; $group = 0;
		if ( '' !== $cursor ) {
			$shape = $restorable_first ? '/\A([0-4])\|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\|([1-9]\d{0,18})\z/D' : '/\A()(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\|([1-9]\d{0,18})\z/D';
			if ( ! preg_match( $shape, $cursor, $parts ) ) {
				return new \WP_Error( 'bettershield_bad_cursor', __( 'Reload the file list to start a new page.', 'bettershield' ), array( 'status' => 400 ) );
			}
			$group = (int) $parts[1]; $at = str_replace( array( 'T', 'Z' ), array( ' ', '' ), $parts[2] ); $id = (int) $parts[3];
		}
		try { $rows = self::changes( $statuses, $size + 1, $at, $id, $restorable_first, $group, $except, $filter ); }
		catch ( \RuntimeException $error ) { return new \WP_Error( 'bettershield_integrity_unavailable', $unavailable, array( 'status' => 503 ) ); }
		$more = count( $rows ) > $size; $rows = array_slice( $rows, 0, $size ); $last = $rows ? end( $rows ) : null;
		$next = $more ? ( $restorable_first ? $last['group'] . '|' : '' ) . $last['detected_at'] . '|' . $last['id'] : null;
		// The group is the cursor's business, not the reader's.
		$rows = array_map( static function ( array $row ): array { unset( $row['group'] ); return $row; }, $rows );
		return array( 'changes' => $rows, 'next_cursor' => $next );
	}

	/**
	 * Changes worth showing, newest first, with whether each can be put back.
	 *
	 * @param string[]              $statuses
	 * @param int[]                 $except   Change ids to leave out.
	 * @param array<string, string> $filter   Only the rows of this `change_type` and this `context`, where given.
	 * @return array<int, array<string, mixed>>
	 */
	public static function changes( array $statuses = self::OPEN_STATUSES, int $limit = 200, string $before_at = '', int $before_id = 0, bool $restorable_first = false, int $before_group = 0, array $except = array(), array $filter = array() ): array {
		global $wpdb;

		if ( array() === $statuses ) {
			return array();
		}

		/*
		 * 0 and 1 for a change that can be put back, core's first, 2 for any
		 * other core change, 3 for an added file that can run as code and 4
		 * for the rest, when the caller wants those first.
		 * A constant otherwise, so one statement serves both orders. Added
		 * code came wherever its date put it: a dropped PHP file at the root
		 * was eighth among sitemaps and exports (#1968). Code is what the
		 * Overview counts as such (open_added_code()).
		 */
		/*
		 * And a WordPress core file first within each: the classic sign of a
		 * compromised site was row 256, after one plugin's every file (#2118).
		 */
		list( $restorable, $restorable_args ) = $restorable_first ? self::restorable_condition() : array( '1 = 0', array() );
		$core                                 = $restorable_first ? "context = 'core'" : '1 = 0';
		$code                                 = $restorable_first ? "change_type = 'added' AND LOWER( path ) REGEXP %s" : '1 = 0';
		// The condition is asked twice, for core and for the rest.
		$restorable_args                      = $restorable_first ? array_merge( $restorable_args, $restorable_args, array( Packages::CODE_PATTERN ) ) : $restorable_args;
		$group                                = "(CASE WHEN {$core} AND {$restorable} THEN 0 WHEN {$restorable} THEN 1 WHEN {$core} THEN 2 WHEN {$code} THEN 3 ELSE 4 END)";
		$before_group                         = $restorable_first ? $before_group : 4;
		$after                                = '' !== $before_at
			? " AND ({$group} > %d OR ({$group} = %d AND (detected_at < %s OR (detected_at = %s AND id < %d))))"
			: '';
		$after_args                           = '' !== $before_at
			? array_merge( $restorable_args, array( $before_group ), $restorable_args, array( $before_group, $before_at, $before_at, $before_id ) )
			: array();
		list( $narrow, $narrow_args )         = self::filter_condition( $filter );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder runs' lengths come from the caller's status list and the installed plugins, never from a request, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT *, {$group} AS bs_group FROM %i WHERE site_id = 0 AND status IN ("
					. implode( ',', array_fill( 0, count( $statuses ), '%s' ) )
					. ')' . ( array() !== $except ? ' AND id NOT IN (' . implode( ',', array_fill( 0, count( $except ), '%d' ) ) . ')' : '' )
					. "{$narrow}{$after} ORDER BY bs_group ASC, detected_at DESC, id DESC LIMIT %d",
				array_merge( $restorable_args, array( Schema::table( 'integrity_changes' ) ), $statuses, array_map( 'intval', $except ), $narrow_args, $after_args, array( max( 1, min( 500, $limit ) ) ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( '' !== $wpdb->last_error ) { throw new \RuntimeException( 'File change listing failed.' ); }
		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$availability = Restore::availability( $row );

			$entry = array(
				'id'          => (int) $row->id,
				'path'        => (string) $row->path,
				'change_type' => (string) $row->change_type,
				'context'     => (string) $row->context,
				// Graded as its activity row and its alert were (#1831).
				'severity'    => Scanner::grade_of( (string) $row->change_type, (string) $row->context, (string) $row->path, ! empty( $row->unconfirmed_update ), KnownWrites::EXPLAINED === (int) ( $row->unconfirmed_update ?? 0 ) ),
				'slug'        => (string) $row->slug,
				'version'     => (string) $row->version,
				'status'      => (string) $row->status,
				'detected_at' => Time::utc_iso( (string) $row->detected_at ),
				// Hashes travel; contents never do. Truncated for display, in
				// full nowhere, because a hash is for comparing not reading.
				'hash_before' => null !== $row->hash_before ? (string) $row->hash_before : null,
				'hash_after'  => null !== $row->hash_after ? (string) $row->hash_after : null,
				'size_after'  => null !== $row->size_after ? (int) $row->size_after : null,
				'restorable'  => $availability['restorable'],
				'why_not'     => $availability['reason'],
				// Said on the row, in the Overview's words (#1968).
				'can_run'     => 'added' === (string) $row->change_type && Packages::is_code( (string) $row->path ),
			);

			/*
			 * A whole package rather than one file, so the row alone cannot
			 * say what differs. The paths and the hash each side offers are
			 * kept beside it and joined here, in the one place every surface
			 * reads its changes from.
			 */
			if ( IncomingPackage::CHANGE_TYPE === (string) $row->change_type ) {
				$entry['package'] = IncomingPackage::finding( (string) $row->slug );
			}

			if ( $restorable_first ) {
				$entry['group'] = (int) $row->bs_group;
			}

			$out[] = $entry;
		}

		return $out;
	}

	/**
	 * Which changes can be put back, as a condition on a row, by the rule
	 * `Restore::availability()` applies to one: an altered file in a location
	 * somebody publishes, recorded against the release installed now. A
	 * plugin that is no longer installed, or that names no version, has no
	 * installed release to disagree with, and that rule lets it through too.
	 *
	 * @return array{0: string, 1: array<int, string>} The condition, and the values its placeholders take, in order.
	 */
	private static function restorable_condition(): array {
		global $wp_version;

		$slugs = array();
		$pairs = array();

		foreach ( Targets::installed_plugins() as $slug => $plugin ) {
			if ( '' !== (string) $plugin['version'] ) {
				$slugs[] = (string) $slug;
				$pairs[] = $slug . '|' . $plugin['version'];
			}
		}

		// An empty list is not valid SQL, and '' is no plugin's slug.
		$slugs = array() !== $slugs ? $slugs : array( '' );
		$pairs = array() !== $pairs ? $pairs : array( '' );

		$list = static fn( array $values ): string => implode( ', ', array_fill( 0, count( $values ), '%s' ) );

		return array(
			"(change_type = 'modified' AND version <> '' AND context NOT IN (" . $list( Unpublished::CONTEXTS ) . ')'
				. ' AND ((context = %s AND version = %s)'
				. ' OR (context = %s AND (slug NOT IN (' . $list( $slugs ) . ") OR CONCAT(slug, '|', version) IN (" . $list( $pairs ) . ')))'
				. ' OR context NOT IN (%s, %s)))',
			array_merge(
				Unpublished::CONTEXTS,
				array( Manifest::CONTEXT_CORE, (string) $wp_version, Manifest::CONTEXT_PLUGIN ),
				$slugs,
				$pairs,
				array( Manifest::CONTEXT_CORE, Manifest::CONTEXT_PLUGIN )
			),
		);
	}

	/** How many open changes can be put back, whatever one page of them shows. */
	public static function open_restorable(): int {
		global $wpdb;

		list( $condition, $args ) = self::restorable_condition();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the condition is built above from fixed SQL and placeholders, and every value is bound.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND {$condition}",
				array_merge( array( Schema::table( 'integrity_changes' ) ), $args )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	/**
	 * How many changes are still waiting on a decision, by kind.
	 *
	 * `clutter` counts separately and is a subset of `added`: a file at the
	 * install root that nothing published. It is worth showing and it is not
	 * the claim the rest of this count makes, so the finding that reads these
	 * numbers can grade the two differently instead of calling a leftover
	 * debug script a tampered core file.
	 *
	 * `unreadable` counts the open changes the scanner could not read, the
	 * same way the other kinds are counted.
	 *
	 * `other` counts by kind the changes in the screen's "other" place (the
	 * root, drop-ins, must-use plugins and configuration files): no plugin,
	 * theme or core release owns them, so a summary that names its sources
	 * names these on a line of their own, or its parts fall short of the
	 * whole (#2484).
	 *
	 * `read_failed` is true when the count itself could not be read, and then
	 * every number is 0 for want of one rather than because nothing is open.
	 * A reader that would take 0 as "clean" checks it first: a failed read is
	 * never a clean one. It has its own name because `unreadable` is also a
	 * kind of change, and sharing the key turned one unreadable file into a
	 * failed read on every screen that asked.
	 *
	 * @return array{total: int, modified: int, added: int, removed: int, unreadable: int, packages: int, clutter: int, other: array{modified: int, added: int, removed: int}, read_failed: bool}
	 */
	public static function open_count(): array {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT change_type, context, COUNT(*) AS total FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') GROUP BY change_type, context",
				Schema::table( 'integrity_changes' )
			)
		);

		$counts = array(
			'total'       => 0,
			'modified'    => 0,
			'added'       => 0,
			'removed'     => 0,
			'unreadable'  => 0,
			// An installed package that differs from the one published: a
			// row of the total like any other, so a bucket of its own, or the
			// parts never added up to the whole (#1817).
			'packages'    => 0,
			'clutter'     => 0,
			'other'       => array(
				'modified' => 0,
				'added'    => 0,
				'removed'  => 0,
			),
			'read_failed' => '' !== $wpdb->last_error,
		);

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$type  = (string) $row->change_type;
			$total = (int) $row->total;

			$counts['total'] += $total;

			if ( in_array( $type, array( 'modified', 'added', 'removed', 'unreadable' ), true ) ) {
				$counts[ $type ] += $total;
			} elseif ( IncomingPackage::CHANGE_TYPE === $type ) {
				$counts['packages'] += $total;
			}

			if ( \BetterShield\Integrity\Manifest::CONTEXT_EXTRA === (string) $row->context ) {
				$counts['clutter'] += $total;
			}

			if ( isset( $counts['other'][ $type ] ) && in_array( (string) $row->context, self::PLACES['other'], true ) ) {
				$counts['other'][ $type ] += $total;
			}
		}

		return $counts;
	}

	/**
	 * Whether an entry the last scan could not compare is a plugin nothing
	 * publishes: its files are watched against the copy first seen
	 * (Unpublished::unlisted_plugins()), so it is not unexamined (#1969).
	 *
	 * @param mixed $item An entry of the scan's `unverifiable` list.
	 */
	public static function is_watched( $item ): bool {
		return is_array( $item ) && Manifest::CONTEXT_PLUGIN === ( $item['context'] ?? '' ) && Manifest::REASON_NOT_PUBLISHED === ( $item['reason'] ?? '' );
	}

	/**
	 * How many open changes are added files that can run as code: the ones
	 * worth naming beside any count, since one injected file is exactly what
	 * a large number hides.
	 */
	public static function open_added_code(): int {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND change_type = 'added' AND LOWER( path ) REGEXP %s",
				Schema::table( 'integrity_changes' ),
				Packages::CODE_PATTERN
			)
		);
	}

	/**
	 * The open changes most worth a first look: loudest first, newest first
	 * within a grade.
	 *
	 * Graded as the file check grades a change when it records one (see
	 * Scanner::severity_of_change()), so an altered file, or an added one that
	 * can run, comes before a missing one however recently that was noticed.
	 *
	 * @return array<int, array{id: int, path: string, change_type: string, context: string, slug: string, unconfirmed_update: int}>
	 */
	public static function loudest_open( int $limit = 3 ): array {
		global $wpdb;

		// 0 is critical, 1 high, 2 medium and 3 low. Added code is what the web server
		// runs or reads as configuration: Scanner::can_execute(), as a pattern.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, path, change_type, context, slug, unconfirmed_update FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged')
				 ORDER BY CASE
					WHEN change_type = 'unreadable' THEN 3
					WHEN change_type = 'removed' OR context = %s OR unconfirmed_update = %d THEN 2
					WHEN change_type = %s THEN 1
					WHEN change_type = 'added' AND ( context = %s OR ( context <> %s AND LOWER( path ) NOT REGEXP %s ) ) THEN 2
					WHEN unconfirmed_update = 1 THEN 1
					ELSE 0
				 END,
				 CASE WHEN change_type = 'added' AND LOWER( path ) REGEXP %s THEN 0 ELSE 1 END,
				 detected_at DESC, id DESC LIMIT %d",
				Schema::table( 'integrity_changes' ),
				Manifest::CONTEXT_EXTRA,
				KnownWrites::EXPLAINED,
				IncomingPackage::CHANGE_TYPE,
				Unpublished::CONTEXT_CONFIG,
				Manifest::CONTEXT_CORE,
				Packages::RUNNABLE_PATTERN,
				// Within a grade, added code first: a root PHP file ranked with
				// the sitemaps beside it (#1968).
				Packages::CODE_PATTERN,
				max( 1, min( 20, $limit ) )
			)
		);

		if ( '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'File change listing failed.' );
		}

		return array_map(
			static fn( object $row ): array => array(
				'id'          => (int) $row->id,
				'path'        => (string) $row->path,
				'change_type' => (string) $row->change_type,
				'context'     => (string) $row->context,
				'slug'        => (string) $row->slug,
				'unconfirmed_update' => (int) $row->unconfirmed_update,
			),
			is_array( $rows ) ? $rows : array()
		);
	}

	/**
	 * The grade of the worst open change, for the finding that sums them up.
	 *
	 * @throws \RuntimeException When the list can't be read.
	 */
	public static function worst_open_grade(): string {
		$row = self::loudest_open( 1 )[0] ?? null;

		return null === $row ? 'critical' : Scanner::grade_of( $row['change_type'], $row['context'], $row['path'], 0 !== $row['unconfirmed_update'], KnownWrites::EXPLAINED === $row['unconfirmed_update'] );
	}

	/**
	 * Whether the last check is old enough that its answer should not be read
	 * as current.
	 *
	 * Stale data is never presented as current — and on a site whose cron has
	 * stopped, which is common, that is the difference between a screen saying
	 * "clean" and a screen saying "last looked a fortnight ago".
	 */
	public static function is_stale(): bool {
		$result = Scanner::last_result();

		if ( null === $result || empty( $result['finished_at'] ) ) {
			return true;
		}

		$finished = strtotime( (string) $result['finished_at'] );

		return false === $finished || ( time() - $finished ) > 2 * DAY_IN_SECONDS;
	}

	/**
	 * The next appointment, or null when the one on record has passed.
	 *
	 * WordPress moves an appointment only when it keeps it, so on a site
	 * whose scheduler has stopped the stored one stays where it was — and
	 * handed through as it stood, it read as a future check on a site that
	 * was not checking, ten minutes before the last check it followed. A
	 * timestamp in the past is not an appointment.
	 */
	private static function next_run(): ?string {
		$next = wp_next_scheduled( 'bettershield_integrity_scan' );

		return false !== $next && $next > time() ? gmdate( 'c', $next ) : null;
	}

	/**
	 * The appointment that has passed without being kept, or null.
	 *
	 * What `next_run()` leaves out, kept: "never scheduled" and "the
	 * appointment was missed" are different answers, and an empty next run
	 * alone reads as the first.
	 */
	private static function missed_run(): ?string {
		$next = wp_next_scheduled( 'bettershield_integrity_scan' );

		return false !== $next && $next <= time() ? gmdate( 'c', $next ) : null;
	}

	/**
	 * Whether the check is running on its own schedule.
	 *
	 * Measured against the scan's own recurrence, read off its schedule
	 * entry: the last finished check is recent when it is within two of the
	 * scan's intervals — an hourly scan that last finished three hours ago
	 * has missed two cycles, and a screen calling that "monitoring" was
	 * telling a site nobody was watching that somebody was. The two-day
	 * measure in is_stale() is the screen's word for data too old to show
	 * as current, which is a different, looser question.
	 */
	public static function on_schedule(): bool {
		$result = Scanner::last_result();

		if ( null === $result || empty( $result['finished_at'] ) ) {
			return false;
		}

		$finished = strtotime( (string) $result['finished_at'] );

		if ( false === $finished ) {
			return false;
		}

		$event    = wp_get_scheduled_event( 'bettershield_integrity_scan' );
		$interval = is_object( $event ) && ! empty( $event->interval ) ? max( 1, (int) $event->interval ) : HOUR_IN_SECONDS;

		return ( time() - $finished ) <= 2 * $interval;
	}
}
