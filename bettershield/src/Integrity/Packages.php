<?php
/**
 * One plugin's file changes as a group: counted, checked again, or marked
 * expected together, with one record and one undo.
 *
 * Every action on the file report used to take one row. That is right for a
 * file somebody is looking at, and wrong for an update that left hundreds of
 * rows behind: nobody marks a thousand files expected one click at a time, so
 * the rows stay open and the report stops being read.
 *
 * A group is one plugin at one recorded version. Both parts matter. Marking
 * is scoped to the version the rows were recorded against, so a file that
 * changes again after the next update is reported again; and a batch never
 * mixes versions, so one injected file cannot ride along with another
 * release's legitimate changes.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Packages {

	/** The undo record a batch marking writes. */
	public const EXPECT_UNDO = 'integrity_batch_expected';

	/** The contexts a group is formed in: the ones with a slug and a version. */
	private const CONTEXTS = array( 'plugin', 'theme', Unpublished::CONTEXT_UNLISTED );

	/** The file changes a group counts; a package difference is its own row. */
	private const TYPES = array( 'modified', 'added', 'removed' );

	/** The largest batch one marking takes; past it, the rows stay one by one. */
	public const MAX_BATCH = 5000;

	/** How many batch markings one page of them lists. */
	public const BATCH_PAGE = 50;

	/**
	 * The extensions a web server may hand to PHP, as an alternation. Stock
	 * Debian and Ubuntu Apache map `.phar` to the handler, and many hosts map
	 * `.php5`, `.php7`, `.pht`, `.phtm` and `.phps` as well; the uploads rule
	 * blocks the same set (`UploadsPhp::rules()`). One list, so the file
	 * check never walks, grades and sorts by three different ideas of what
	 * can run.
	 */
	public const SERVER_PHP = 'php[0-9]?|pht|phtm|phtml|phps|phar';

	/**
	 * A file name that can run as code, as a pattern both PHP and the
	 * database read, so a count taken in a query and a list named here agree.
	 * `.inc` is not handed to PHP by a server, but PHP code includes it.
	 */
	public const CODE_PATTERN = '\\.(' . self::SERVER_PHP . '|inc)$';

	/**
	 * Everything the file check treats as able to run: code, the scripts a
	 * page loads, and the two files a web server reads as configuration.
	 * Also a pattern both PHP and the database read.
	 */
	public const RUNNABLE_PATTERN = '(\\.(' . self::SERVER_PHP . '|inc|js)|(^|/)\\.htaccess|(^|/)\\.user\\.ini)$';

	/** How many added code files a preview names before it counts the rest. */
	private const NAMED_CODE = 50;

	/** A marking made from a selection rather than for one plugin's version. */
	public const SELECTION = 'selection';

	/** The most changes one selection marks expected at once. */
	public const MAX_SELECTION = 500;

	/** What a selection may mark: every file change, never a package's difference. */
	public const SELECTION_TYPES = array( 'modified', 'added', 'removed', 'unreadable' );

	/** How long one "check again" request spends before it hands back a cursor. */
	private const RECHECK_SECONDS = 8.0;

	/**
	 * Every group with open rows, the largest first.
	 *
	 * @return array<int, array{context: string, slug: string, version: string, name: string, total: int, modified: int, added: int, removed: int}>
	 */
	public static function all(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, grouped for one screen.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT context, slug, version, change_type, COUNT(*) AS n FROM %i
				 WHERE site_id = 0 AND status IN ('new','acknowledged') AND context IN (%s, %s, %s) AND slug IS NOT NULL AND slug <> '' AND change_type IN (%s, %s, %s)
				 GROUP BY context, slug, version, change_type",
				Schema::table( 'integrity_changes' ),
				self::CONTEXTS[0],
				self::CONTEXTS[1],
				self::CONTEXTS[2],
				self::TYPES[0],
				self::TYPES[1],
				self::TYPES[2]
			)
		);

		$groups = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$key = $row->context . '|' . $row->slug . '|' . (string) $row->version;

			if ( ! isset( $groups[ $key ] ) ) {
				$groups[ $key ] = array(
					'context'  => (string) $row->context,
					'slug'     => (string) $row->slug,
					'version'  => (string) $row->version,
					'name'     => self::name_of( (string) $row->context, (string) $row->slug ),
					'total'    => 0,
					'modified' => 0,
					'added'    => 0,
					'removed'  => 0,
				);
			}

			$groups[ $key ][ (string) $row->change_type ] = (int) $row->n;
			$groups[ $key ]['total']                    += (int) $row->n;
		}

		$groups = array_values( $groups );

		usort( $groups, static fn( array $a, array $b ): int => $b['total'] <=> $a['total'] );

		return $groups;
	}

	/**
	 * The open changes to WordPress core's own files, counted by kind, or
	 * null when there are none.
	 *
	 * Core is not a group that can be checked again or marked expected, so
	 * it is not among all() above, and with one plugin's many changes there
	 * a changed core file had no summary anywhere (#2118).
	 *
	 * @return array{version: string, total: int, modified: int, added: int, removed: int}|null
	 */
	public static function core(): ?array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, counted for one screen.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT version, change_type, COUNT(*) AS n FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context = %s AND change_type IN (%s, %s, %s) GROUP BY version, change_type",
				Schema::table( 'integrity_changes' ),
				Manifest::CONTEXT_CORE,
				self::TYPES[0],
				self::TYPES[1],
				self::TYPES[2]
			)
		);

		$core = array(
			'version'  => '',
			'total'    => 0,
			'modified' => 0,
			'added'    => 0,
			'removed'  => 0,
		);

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$core['version']                       = '' !== $core['version'] ? $core['version'] : (string) $row->version;
			$core[ (string) $row->change_type ] += (int) $row->n;
			$core['total']                        += (int) $row->n;
		}

		return $core['total'] > 0 ? $core : null;
	}

	/**
	 * What marking one group expected would cover: the counts by kind, and
	 * each added file that can run as code, named, because one injected file
	 * among a release's changes is exactly what a batch could hide.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function preview( string $context, string $slug, string $version ) {
		$rows = self::open_rows( $context, $slug, $version );

		if ( is_wp_error( $rows ) ) {
			return $rows;
		}

		$counts = array_fill_keys( self::TYPES, 0 );
		$code   = array();

		foreach ( $rows as $row ) {
			++$counts[ (string) $row->change_type ];

			if ( 'added' === (string) $row->change_type && self::is_code( (string) $row->path ) ) {
				$code[] = (string) $row->path;
			}
		}

		// A path can carry more than one open row; it is named once.
		$code = array_values( array_unique( $code ) );
		sort( $code );

		return array(
			'context'    => $context,
			'slug'       => $slug,
			'version'    => $version,
			'name'       => self::name_of( $context, $slug ),
			'total'      => count( $rows ),
			'modified'   => $counts['modified'],
			'added'      => $counts['added'],
			'removed'    => $counts['removed'],
			'added_code' => array_slice( $code, 0, self::NAMED_CODE ),
			'added_code_total' => count( $code ),
			// Which rows, not only how many: it goes back with the marking.
			'digest'     => self::digest( $rows ),
		);
	}

	/**
	 * The exact set of rows a preview showed, as one string a marking can be
	 * held to. The order rows come back in is not part of the set.
	 *
	 * @param array<int, object> $rows
	 */
	private static function digest( array $rows ): string {
		$ids = array_map( static fn( object $row ): int => (int) $row->id, $rows );
		sort( $ids );

		return hash( 'sha256', implode( ',', $ids ) );
	}

	/**
	 * Mark every open change in one group expected, as one decision.
	 *
	 * The count the owner saw in the preview comes back with the request, and
	 * so does the digest of the rows it listed. A group that has grown or
	 * shrunk since, or whose rows changed at the same count (one left, an
	 * added file joined), is refused rather than marked: one confirmation
	 * covers exactly what it was shown. One undo record holds each row and
	 * the status it had, one log entry says what was marked, and the undo
	 * puts back exactly those rows and no others.
	 *
	 * @param string $digest The preview's digest; '' holds the marking to the count alone.
	 * @return array{undo: string, count: int}|\WP_Error
	 */
	public static function expect( string $context, string $slug, string $version, int $seen, string $digest = '' ) {
		$rows = self::open_rows( $context, $slug, $version );

		if ( is_wp_error( $rows ) ) {
			return $rows;
		}

		if ( array() === $rows ) {
			return new \WP_Error( 'bettershield_batch_empty', __( 'Nothing in that group is still open.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( count( $rows ) !== $seen ) {
			return new \WP_Error(
				'bettershield_batch_changed',
				sprintf(
					/* translators: 1: how many were shown, 2: how many there are now. */
					_n(
						'The list changed since you opened it (%1$d before, %2$d now). Nothing was accepted. Open it again to review.',
						'The list changed since you opened it (%1$d before, %2$d now). Nothing was accepted. Open it again to review.',
						$seen,
						'bettershield'
					),
					$seen,
					count( $rows )
				),
				array( 'status' => 409 )
			);
		}

		if ( '' !== $digest && ! hash_equals( self::digest( $rows ), $digest ) ) {
			return new \WP_Error(
				'bettershield_batch_changed',
				__( 'The list changed since you opened it. Nothing was accepted. Open it again to review.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$prior = array();

		foreach ( $rows as $row ) {
			$prior[] = array( (int) $row->id, (string) $row->status );
		}

		$token = Ledger::open(
			self::EXPECT_UNDO,
			array(
				'context' => $context,
				'slug'    => $slug,
				'version' => $version,
				'changes' => $prior,
			),
			array(
				'status' => 'suppressed',
				'count'  => count( $prior ),
			)
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::suppress_rows( array_column( $prior, 0 ) );

		$counts = array_count_values( array_map( static fn( object $row ): string => (string) $row->change_type, $rows ) );

		Writer::instance()->record(
			'file_changes_expected',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => self::object_type_of( $context ),
				'object_id'   => $slug,
				'context'     => array(
					'version'  => $version,
					'count'    => count( $prior ),
					'modified' => (int) ( $counts['modified'] ?? 0 ),
					'added'    => (int) ( $counts['added'] ?? 0 ),
					'removed'  => (int) ( $counts['removed'] ?? 0 ),
					'undo'     => $token,
				),
			)
		);

		return array(
			'undo'  => $token,
			'count' => count( $prior ),
		);
	}

	/**
	 * Mark a selection of open changes expected, as one decision.
	 *
	 * The rows the owner picked, from any plugin, theme or core, after one
	 * question that counted them. A row is one state of one file (a file that
	 * changes again is a new row), so the marking covers exactly the states
	 * shown, and a file that changes again is reported again. A row dealt with
	 * since is left out and counted rather than refusing the rest; a
	 * package's own difference, answered by adopting it, is never marked here.
	 * One undo record, one log line.
	 *
	 * @param int[] $ids
	 * @return array{undo: string, count: int, skipped: int}|\WP_Error
	 */
	public static function expect_selection( array $ids ) {
		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ), static fn( int $id ): bool => $id > 0 ) ) );

		if ( array() === $ids || count( $ids ) > self::MAX_SELECTION ) {
			return new \WP_Error(
				'bettershield_selection_size',
				sprintf(
					/* translators: %d: the most changes one marking takes. */
					__( 'Select 1 to %d changes at a time. Nothing was changed.', 'bettershield' ),
					self::MAX_SELECTION
				),
				array( 'status' => 400 )
			);
		}

		$rows = self::selection_rows( $ids );

		if ( array() === $rows ) {
			return new \WP_Error( 'bettershield_batch_empty', __( 'None of the selected changes is still open.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$marked = self::mark_selection( $rows );

		return is_wp_error( $marked ) ? $marked : $marked + array( 'skipped' => count( $ids ) - $marked['count'] );
	}

	/**
	 * Mark every open change a filter matches expected, as one decision: the
	 * rows of every page, not only the ones on screen.
	 *
	 * The count the owner was shown comes back with the request, and so does
	 * the newest row it counted. A row recorded after that is left out, so
	 * the marking never covers more than was counted; a row dealt with since
	 * is counted as left out, as a selection's is; and more than were counted
	 * is refused rather than marked. Bounded as one plugin's marking is, in
	 * bounded statements. One undo record, one log line.
	 *
	 * @param array<string, string> $filter  See Report::filter_of().
	 * @param int                   $seen    How many the owner was shown.
	 * @param int                   $through The newest row counted.
	 * @return array{undo: string, count: int, skipped: int}|\WP_Error
	 */
	public static function expect_matching( array $filter, int $seen, int $through ) {
		$ids = Report::matching_ids( $filter, 0, $through, self::MAX_BATCH + 1 );

		if ( count( $ids ) > self::MAX_BATCH ) {
			return new \WP_Error(
				'bettershield_selection_size',
				sprintf(
					/* translators: %d: the most changes one marking takes. */
					__( 'More than %d changes match. Use the filters to select fewer. Nothing was changed.', 'bettershield' ),
					self::MAX_BATCH
				),
				array( 'status' => 400 )
			);
		}

		if ( array() === $ids ) {
			return new \WP_Error( 'bettershield_batch_empty', __( 'None of the matching changes is still open.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( count( $ids ) > $seen ) {
			return new \WP_Error(
				'bettershield_batch_changed',
				sprintf(
					/* translators: 1: how many were counted, 2: how many match now. */
					_n(
						'The list changed while you were choosing (%1$d before, %2$d now). Nothing was changed. Select them again.',
						'The list changed while you were choosing (%1$d before, %2$d now). Nothing was changed. Select them again.',
						$seen,
						'bettershield'
					),
					$seen,
					count( $ids )
				),
				array( 'status' => 409 )
			);
		}

		$rows = array();

		foreach ( array_chunk( $ids, 500 ) as $chunk ) {
			$rows = array_merge( $rows, self::selection_rows( $chunk ) );
		}

		if ( array() === $rows ) {
			return new \WP_Error( 'bettershield_batch_empty', __( 'None of the matching changes is still open.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$marked = self::mark_selection( $rows, $filter );

		return is_wp_error( $marked ) ? $marked : $marked + array( 'skipped' => max( 0, $seen - $marked['count'] ) );
	}

	/**
	 * The rows of these that a selection may mark and are still open.
	 *
	 * @param int[] $ids
	 * @return array<int, object>
	 */
	private static function selection_rows( array $ids ): array {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- the placeholder runs' lengths are the type list's and the chunk's own, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, path, change_type, status FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND change_type IN ("
					. implode( ', ', array_fill( 0, count( self::SELECTION_TYPES ), '%s' ) )
					. ') AND id IN (' . implode( ', ', array_fill( 0, count( $ids ), '%d' ) ) . ') ORDER BY id ASC',
				array_merge( array( Schema::table( 'integrity_changes' ) ), self::SELECTION_TYPES, $ids )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Mark these open rows expected as one selection: the undo record first,
	 * then the rows, then one line in the log.
	 *
	 * @param array<int, object>    $rows
	 * @param array<string, string> $filter The filter they were chosen by, where they were.
	 * @return array{undo: string, count: int}|\WP_Error
	 */
	private static function mark_selection( array $rows, ?array $filter = null ) {
		$prior = array();

		foreach ( $rows as $row ) {
			$prior[] = array( (int) $row->id, (string) $row->status );
		}

		$token = Ledger::open(
			self::EXPECT_UNDO,
			array(
				// A selection names no plugin and no version: its rows are the record.
				'context' => self::SELECTION,
				'slug'    => '',
				'version' => '',
				'changes' => $prior,
			),
			array(
				'status' => 'suppressed',
				'count'  => count( $prior ),
			)
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::suppress_rows( array_column( $prior, 0 ) );

		$counts  = array_count_values( array_map( static fn( object $row ): string => (string) $row->change_type, $rows ) );
		$context = array(
			'count'      => count( $prior ),
			'modified'   => (int) ( $counts['modified'] ?? 0 ),
			'added'      => (int) ( $counts['added'] ?? 0 ),
			'removed'    => (int) ( $counts['removed'] ?? 0 ),
			'unreadable' => (int) ( $counts['unreadable'] ?? 0 ),
			// What a decision about many rows could hide, counted.
			'added_code' => count( array_filter( $rows, static fn( object $row ): bool => 'added' === (string) $row->change_type && self::is_code( (string) $row->path ) ) ),
			'undo'       => $token,
		);

		// Every row a filter matched, rather than rows picked one by one.
		if ( null !== $filter ) {
			$context['filter'] = $filter;
		}

		Writer::instance()->record(
			'file_selection_expected',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => self::SELECTION,
				'context'     => $context,
			)
		);

		return array(
			'undo'  => $token,
			'count' => count( $prior ),
		);
	}

	/**
	 * Mark these rows expected, the ones still open, in bounded statements.
	 *
	 * @param int[] $ids
	 */
	private static function suppress_rows( array $ids ): void {
		global $wpdb;

		foreach ( array_chunk( $ids, 500 ) as $chunk ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- the placeholder run's length is the chunk's own, and every id is bound.
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET status = 'suppressed' WHERE site_id = 0 AND status IN ('new','acknowledged') AND id IN (" . implode( ', ', array_fill( 0, count( $chunk ), '%d' ) ) . ')',
					array_merge( array( Schema::table( 'integrity_changes' ) ), $chunk )
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		}
	}

	/**
	 * Take a batch marking back: each row it marked that is still marked
	 * returns to the status it had, and nothing else moves.
	 *
	 * Still marked is not enough on its own. A row taken out of the batch and
	 * then marked expected on its own is marked by that newer decision, which
	 * stays in force with its own undo record.
	 *
	 * @return array{count: int}|\WP_Error
	 */
	public static function undo( string $token ) {
		global $wpdb;

		$entry = Ledger::find( $token );

		if ( null === $entry || self::EXPECT_UNDO !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'There is no such marking on record.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior    = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$alone    = Restore::marked_alone_since( (int) $entry->id );
		$returned = 0;

		foreach ( (array) ( $prior['changes'] ?? array() ) as $pair ) {
			$id     = (int) ( $pair[0] ?? 0 );
			$status = in_array( $pair[1] ?? '', array( 'new', 'acknowledged' ), true ) ? (string) $pair[1] : 'new';

			if ( isset( $alone[ $id ] ) ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table.
			$returned += (int) $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET status = %s WHERE site_id = 0 AND id = %d AND status = 'suppressed'",
					Schema::table( 'integrity_changes' ),
					$status,
					$id
				)
			);
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'file_changes_unexpected',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => self::object_type_of( (string) ( $prior['context'] ?? 'plugin' ) ),
				'object_id'   => (string) ( $prior['slug'] ?? '' ),
				'context'     => array(
					'version' => (string) ( $prior['version'] ?? '' ),
					'count'   => $returned,
				),
			)
		);

		return array( 'count' => $returned );
	}

	/**
	 * The rows a batch marking still holds, with the status each had before
	 * it: every row of a batch that can still be taken back, unless a single
	 * marking made since has taken that row over.
	 *
	 * These are listed once, as their batch, under "Marked expected
	 * together". The per-row list of markings leaves them out, or a batch of
	 * hundreds fills it and pushes every single marking off it.
	 *
	 * @return array<int, string> The status before the batch, by change id.
	 */
	public static function held(): array {
		// The newest single marking in force for each change, by its record.
		$alone = array();

		foreach ( Ledger::open_tokens( Restore::SUPPRESS_UNDO ) as $token ) {
			$entry = Ledger::find( $token );

			if ( null !== $entry && is_array( $entry->applied_state ) ) {
				$change           = (int) ( $entry->applied_state['change'] ?? 0 );
				$alone[ $change ] = max( $alone[ $change ] ?? 0, (int) $entry->id );
			}
		}

		$held = array();

		foreach ( Ledger::open_tokens( self::EXPECT_UNDO ) as $token ) {
			$entry = Ledger::find( $token );

			if ( null === $entry || ! is_array( $entry->prior_state ) ) {
				continue;
			}

			foreach ( (array) ( $entry->prior_state['changes'] ?? array() ) as $pair ) {
				$id = (int) ( $pair[0] ?? 0 );

				if ( $id <= 0 || isset( $held[ $id ] ) || ( $alone[ $id ] ?? 0 ) > (int) $entry->id ) {
					continue;
				}

				$held[ $id ] = in_array( $pair[1] ?? '', array( 'new', 'acknowledged' ), true ) ? (string) $pair[1] : 'new';
			}
		}

		return $held;
	}

	/**
	 * The first page of the batch markings that can still be taken back,
	 * newest first, one line each: a batch of hundreds would otherwise fill
	 * the marked list row by row and push every single marking off it.
	 *
	 * @return array<int, array{undo: string, context: string, slug: string, version: string, name: string, count: int, at: ?string}>
	 */
	public static function batches(): array {
		return self::batches_page()['batches'];
	}

	/**
	 * One page of the batch markings that can still be taken back, and where
	 * the next starts: the id of the last one listed, or null when there are
	 * no more. A list cut at the page with nothing after it said a site had
	 * as many as one page holds, and the older ones could not be taken back
	 * from the screen.
	 *
	 * @param int $before Only markings older than this ledger id; 0 for the newest.
	 * @return array{batches: array<int, array{undo: string, context: string, slug: string, version: string, name: string, count: int, at: ?string}>, next_cursor: ?int}
	 */
	public static function batches_page( int $before = 0 ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, a page at a time by id.
		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, token FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL AND ( %d = 0 OR id < %d ) ORDER BY id DESC LIMIT %d',
				Schema::table( 'undo' ),
				self::EXPECT_UNDO,
				$before,
				$before,
				self::BATCH_PAGE + 1
			)
		);

		$more = count( $rows ) > self::BATCH_PAGE;
		$rows = array_slice( $rows, 0, self::BATCH_PAGE );
		$out  = array();

		foreach ( $rows as $row ) {
			$token = (string) $row->token;
			$entry = Ledger::find( $token );

			if ( null === $entry || ! is_array( $entry->prior_state ) ) {
				continue;
			}

			$context = (string) ( $entry->prior_state['context'] ?? 'plugin' );
			$slug    = (string) ( $entry->prior_state['slug'] ?? '' );

			$out[] = array(
				'undo'    => $token,
				'context' => $context,
				'slug'    => $slug,
				'version' => (string) ( $entry->prior_state['version'] ?? '' ),
				'name'    => self::SELECTION === $context ? __( 'Selected changes', 'bettershield' ) : self::name_of( $context, $slug ),
				'count'   => count( (array) ( $entry->prior_state['changes'] ?? array() ) ),
				'at'      => \BetterShield\Support\Time::utc_iso( (string) $entry->created_at ),
			);
		}

		return array(
			'batches'     => $out,
			'next_cursor' => $more && array() !== $rows ? (int) end( $rows )->id : null,
		);
	}

	/** How many batch markings can still be taken back, whatever one page of them shows. */
	public static function batches_total(): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL',
				Schema::table( 'undo' ),
				self::EXPECT_UNDO
			)
		);
	}

	/** How many of one plugin's file rows are open, the ones recheck() compares. */
	public static function open_rechecks( string $slug ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context = 'plugin' AND slug = %s AND change_type IN ('modified','added','removed')",
				Schema::table( 'integrity_changes' ),
				Targets::folder_name( $slug )
			)
		);
	}

	/**
	 * Compare one plugin's open rows again, now, against what the directory
	 * published for the version installed, and close each that matches.
	 *
	 * Only the rows already open are looked at: finding new differences is
	 * the full check's work, and this is the answer to "that update has
	 * finished, look again". A file that matches is closed as put back, an
	 * added file that is gone is closed the same way, and anything else
	 * stays open. The time spent is bounded, and a plugin with more rows than
	 * one request can hash hands back where to carry on.
	 *
	 * @return array{checked: int, closed: int, left: int, after: int, version: string}|\WP_Error
	 */
	public static function recheck( string $slug, int $after = 0 ) {
		global $wpdb;

		$slug      = Targets::folder_name( $slug );
		$installed = self::installed_version( $slug );

		if ( '' === $installed ) {
			return new \WP_Error( 'bettershield_not_installed', __( 'That plugin is not installed, so there is nothing to compare.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$manifest = Manifest::plugin( $slug, $installed );

		if ( is_wp_error( $manifest ) ) {
			return new \WP_Error(
				'bettershield_no_published_copy',
				sprintf(
					/* translators: %s: a version number. */
					__( 'No published copy of version %s is available. Accept these changes if you made them.', 'bettershield' ),
					$installed
				),
				array( 'status' => 409 )
			);
		}

		$algo     = (string) ( $manifest['algo'] ?? 'sha256' );
		$deadline = microtime( true ) + self::RECHECK_SECONDS;
		$checked  = 0;
		$closed   = 0;
		$last     = $after;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, walked by id.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, path, context, slug, change_type FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context = 'plugin' AND slug = %s AND change_type IN ('modified','added','removed') AND id > %d ORDER BY id ASC LIMIT 100",
					Schema::table( 'integrity_changes' ),
					$slug,
					$last
				)
			);

			if ( ! is_array( $rows ) || array() === $rows ) {
				break;
			}

			foreach ( $rows as $row ) {
				$last = (int) $row->id;
				++$checked;

				if ( self::matches_now( $row, $manifest, $algo ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table.
					$closed += (int) $wpdb->update(
						Schema::table( 'integrity_changes' ),
						array( 'status' => 'restored' ),
						array(
							'site_id' => 0,
							'id'      => (int) $row->id,
						),
						array( '%s' ),
						array( '%d', '%d' )
					);
				}

				if ( microtime( true ) >= $deadline ) {
					break 2;
				}
			}
		} while ( true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table.
		$left = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context = 'plugin' AND slug = %s AND change_type IN ('modified','added','removed') AND id > %d",
				Schema::table( 'integrity_changes' ),
				$slug,
				$last
			)
		);

		Writer::instance()->record(
			'file_package_rechecked',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'plugin',
				'object_id'   => $slug,
				'context'     => array(
					'version' => $installed,
					'checked' => $checked,
					'closed'  => $closed,
					'left'    => $left,
				),
			)
		);

		return array(
			'checked' => $checked,
			'closed'  => $closed,
			'left'    => $left,
			'after'   => 0 === $left ? 0 : $last,
			'version' => $installed,
		);
	}

	/**
	 * Whether a row's file now agrees with the published copy.
	 *
	 * @param array<string, mixed> $manifest
	 */
	private static function matches_now( object $row, array $manifest, string $algo ): bool {
		$relative = Restore::relative_path( $row );
		$absolute = Restore::absolute_path( $row );

		if ( '' === $absolute ) {
			return false;
		}

		$published = array() !== Manifest::hashes_for( $manifest, $relative );

		/*
		 * An added file that is gone is no longer true of the site. Nor is a
		 * row about a file the installed release does not ship, now that the
		 * file is not there: that absence is what the release looks like. A
		 * run that compared against the release before an update recorded
		 * every file the new one dropped as removed.
		 */
		if ( ! is_file( $absolute ) && ( 'added' === (string) $row->change_type || ! $published ) ) {
			return true;
		}

		if ( ! $published || ! is_file( $absolute ) ) {
			return false;
		}

		$hash = Manifest::hash_file( $absolute, $algo );

		return null !== $hash && Manifest::matches( $manifest, $relative, $hash );
	}

	/** What the log calls a group's owner: `unlisted` is a place, and it is still a plugin. */
	private static function object_type_of( string $context ): string {
		return Unpublished::CONTEXT_UNLISTED === $context ? 'plugin' : $context;
	}

	/**
	 * The open rows of one group, or a refusal for a group that is not one.
	 *
	 * @return array<int, object>|\WP_Error
	 */
	private static function open_rows( string $context, string $slug, string $version ) {
		global $wpdb;

		if ( ! in_array( $context, self::CONTEXTS, true ) || '' === $slug ) {
			return new \WP_Error( 'bettershield_batch_unknown', __( 'Name a plugin or theme and the version its changes were recorded against.', 'bettershield' ), array( 'status' => 400 ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, bounded.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, path, change_type, status FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context = %s AND slug = %s AND version = %s AND change_type IN ('modified','added','removed') ORDER BY id ASC LIMIT %d",
				Schema::table( 'integrity_changes' ),
				$context,
				$slug,
				$version,
				self::MAX_BATCH + 1
			)
		);

		$rows = is_array( $rows ) ? $rows : array();

		if ( count( $rows ) > self::MAX_BATCH ) {
			return new \WP_Error(
				'bettershield_batch_too_large',
				/* translators: %d: the largest batch. */
				sprintf( __( 'Over %d changes is too many to mark at once. Check the group again; matching ones will close.', 'bettershield' ), self::MAX_BATCH ),
				array( 'status' => 409 )
			);
		}

		return $rows;
	}

	/** Whether a path names a file a web server may run as code. */
	public static function is_code( string $path ): bool {
		return 1 === preg_match( '/' . self::CODE_PATTERN . '/i', $path );
	}

	/**
	 * Whether a path names a file the server would run, include or read as
	 * configuration. By name rather than by contents: reading the file to
	 * decide would mean holding the bytes of something just called suspicious.
	 */
	public static function can_run( string $path ): bool {
		return 1 === preg_match( '#' . self::RUNNABLE_PATTERN . '#i', $path );
	}

	/** Whether a plugin or theme is still installed under this folder. */
	public static function is_installed( string $context, string $slug ): bool {
		if ( 'theme' === $context ) {
			return wp_get_theme( $slug )->exists();
		}

		foreach ( array_keys( self::plugins() ) as $file ) {
			if ( dirname( (string) $file ) === $slug || (string) $file === $slug ) {
				return true;
			}
		}

		return false;
	}

	/** What the owner calls a plugin or theme, or its slug. */
	public static function name_of( string $context, string $slug ): string {
		if ( 'theme' === $context ) {
			$theme = wp_get_theme( $slug );

			return $theme->exists() ? wp_strip_all_tags( (string) $theme->get( 'Name' ) ) : $slug;
		}

		foreach ( self::plugins() as $file => $plugin ) {
			// A plugin that is one file is filed under that file's name.
			if ( dirname( (string) $file ) === $slug || (string) $file === $slug ) {
				return wp_strip_all_tags( (string) ( $plugin['Name'] ?? $slug ) );
			}
		}

		return $slug;
	}

	/** The installed version of a plugin by its folder, or ''. */
	private static function installed_version( string $slug ): string {
		foreach ( self::plugins() as $file => $plugin ) {
			if ( dirname( (string) $file ) === $slug ) {
				return (string) ( $plugin['Version'] ?? '' );
			}
		}

		return '';
	}

	/** @return array<string, array<string, mixed>> */
	private static function plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return get_plugins();
	}
}
