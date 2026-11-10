<?php
/**
 * The check itself: does every published file still hash to what was
 * published, is anything missing, and is anything there that nobody shipped.
 *
 * **It runs in resumable chunks under a wall-clock budget, and stopping early
 * is normal.** A 10GB site on shared hosting cannot hash three thousand core
 * files inside one cron request, and a check that tries is a check that gets
 * killed halfway and reports nothing. So a run holds a cursor, does as much as
 * its budget allows, saves where it got to, and the next tick picks it up. A
 * run that takes six hours across twenty ticks is a success.
 *
 * Two passes per target, deliberately different in cost:
 *
 * - **Manifest against disk**, which hashes and is therefore chunked. This
 *   finds a file that changed and a file that went missing.
 * - **Disk against manifest**, which only reads directory entries and is
 *   therefore done in one go. This finds a file nobody published — which is
 *   what a dropped backdoor looks like, and the reason walking the disk is
 *   worth doing at all rather than trusting the manifest to be the world.
 *
 * The budget and the chunk size are conservative defaults with the reasoning
 * written beside them. Nothing here has been measured on real shared hosting
 * yet; both are filterable so an operator who has measured theirs can say so.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * The plugin-owned integrity tables, for which no core API exists. Uncached on
 * purpose: a check reporting from a stale copy of its own results is the exact
 * failure this feature exists to prevent.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Scanner {

	/** Where a part-finished run remembers what it has done. */
	public const STATE_OPTION = 'bettershield_integrity_run';

	/** What the last completed run concluded. */
	public const RESULT_OPTION = 'bettershield_integrity_result';

	/** A run over everything this site has to check. */
	public const SCOPE_ALL = '';

	/**
	 * A run over the locations nobody publishes a checksum for, and nothing
	 * else.
	 *
	 * Theirs is the only comparison that costs nothing but disk: a published
	 * target needs its publisher's list of checksums, so a run including one
	 * cannot be repeated often without asking for lists that cannot have
	 * changed since the last ask. Restricting a run is what lets those
	 * locations be watched on a shorter cycle than the rest.
	 *
	 * A scoped run keeps its own cursor and publishes no result of its own.
	 * What it looked at is a part of the site rather than the site, and the
	 * result, the summary the audit reads and the completed-check event all
	 * answer for the whole of it. What it finds is recorded exactly as a full
	 * run's findings are — same rows, same events, same screens.
	 */
	public const SCOPE_UNPUBLISHED = 'unpublished';

	/**
	 * The disk listing for the target a run is in the middle of.
	 *
	 * Kept out of the cursor on purpose. A walk of a WordPress root is up to
	 * twenty thousand paths, and the cursor is rewritten as the run advances —
	 * carrying the listing inside it would mean rewriting hundreds of kilobytes
	 * of one row to move a counter. This one is written when a target's disk
	 * pass begins and removed when the target is done.
	 */
	public const PATHS_OPTION = 'bettershield_integrity_run_paths';

	/**
	 * The key that decides which request runs a scan.
	 *
	 * A tick is a read of the cursor, some work, and a write back. Two of them
	 * at once — the hourly task, the loopback fallback, the button on the
	 * screen and the terminal all reach the same code — interleave those writes
	 * and repeat each other's work, and one of them can close a run the other
	 * is still in the middle of.
	 */
	private const RUN_CLAIM = 'integrity_run';

	/**
	 * How long a claim on a whole run is held.
	 *
	 * Long enough that a run working through several ticks is not overtaken
	 * mid-cursor, short enough that a request killed while holding it does not
	 * keep the next one out for long.
	 */
	private const RUN_CLAIM_SECONDS = 120;

	/**
	 * Written whole rather than built from the one above.
	 *
	 * Spelled out because a name assembled by concatenation is a name nothing
	 * can find: the uninstall guard greps shipped source for the literals a
	 * site stores, and this one existed in no file as a string, so it was
	 * written on every scan and removed by nothing.
	 */
	public const SUMMARY_OPTION = 'bettershield_integrity_result_summary';

	/**
	 * How long one tick may spend.
	 *
	 * Shared hosting commonly caps PHP at 30 seconds, and a cron request is
	 * doing other work besides this. Ten seconds leaves room for that and for
	 * the request to end cleanly rather than be killed mid-write — which is
	 * what would leave a cursor pointing at work already done.
	 */
	public const DEFAULT_BUDGET_SECONDS = 10.0;

	/**
	 * How many files one tick may hash before checking the clock again.
	 *
	 * Hashing is streamed, so cost tracks file size rather than count, and
	 * core's largest files are a few hundred kilobytes. Two hundred is small
	 * enough that the clock is consulted often on a slow disk and large enough
	 * that the per-chunk overhead stays irrelevant.
	 */
	public const DEFAULT_CHUNK = 200;

	/**
	 * How many files an update's note names, and how many of those with a
	 * hidden name. Past it the note says how many more there were.
	 */
	private const UPDATE_CODE_NAMED = 20;

	/**
	 * How many set-aside folders one location's line names. Past it the line
	 * says how many more there were.
	 */
	private const SET_ASIDE_NAMED = 5;

	/**
	 * How many rows a newer row replaced one full run closes. Bounded so a
	 * site carrying thousands of them settles over a few runs rather than in
	 * one request.
	 */
	private const REPLACED_PER_RUN = 500;

	/**
	 * Deleting a plugin or a theme through WordPress closes what was open
	 * against it at once, rather than at the end of the next full run.
	 */
	public static function register(): void {
		add_action( 'deleted_plugin', array( self::class, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'deleted_theme', array( self::class, 'on_theme_deleted' ), 10, 2 );
	}

	/**
	 * @param mixed $plugin  The plugin file, relative to the plugins directory.
	 * @param mixed $deleted Whether the files went.
	 */
	public static function on_plugin_deleted( $plugin, $deleted = true ): void {
		$plugin = (string) $plugin;
		$slug   = dirname( $plugin );

		if ( ! $deleted || '' === $slug || self::own_files_gone( $plugin ) ) {
			return;
		}

		// A plugin that is one file was compared under its own name.
		if ( '.' === $slug ) {
			if ( Unpublished::is_single_file( $plugin ) && ! self::location_present( Unpublished::CONTEXT_UNLISTED, $plugin ) ) {
				self::forget_location( Unpublished::CONTEXT_UNLISTED, $plugin );
			}

			return;
		}

		foreach ( array( Manifest::CONTEXT_PLUGIN, Unpublished::CONTEXT_UNLISTED ) as $context ) {
			if ( ! self::location_present( $context, $slug ) ) {
				self::forget_location( $context, $slug );
			}
		}
	}

	/**
	 * Whether this plugin's own files are gone, or are what was just deleted.
	 *
	 * Deleting this plugin fires the hook after its files are removed, so the
	 * classes this listener reaches for can no longer be loaded and the
	 * uninstall ended in a fatal error (#1818). The same holds for a plugin
	 * deleted after this one in the same bulk deletion. There is nothing left
	 * to close then: the uninstall has kept or removed the rows already.
	 */
	private static function own_files_gone( string $plugin ): bool {
		return plugin_basename( BETTERSHIELD_FILE ) === $plugin || ! file_exists( BETTERSHIELD_FILE );
	}

	/**
	 * @param mixed $stylesheet The theme's folder name.
	 * @param mixed $deleted    Whether the files went.
	 */
	public static function on_theme_deleted( $stylesheet, $deleted = true ): void {
		$slug = (string) $stylesheet;

		if ( ! file_exists( BETTERSHIELD_FILE ) ) {
			return;
		}

		if ( $deleted && '' !== $slug && ! self::location_present( Unpublished::CONTEXT_THEME, $slug ) ) {
			self::forget_location( Unpublished::CONTEXT_THEME, $slug );
		}
	}

	public static function budget_seconds(): float {
		/**
		 * Filters how long one integrity tick may spend.
		 *
		 * @param float $seconds Wall-clock budget for a single tick.
		 */
		return max( 1.0, (float) apply_filters( 'bettershield_integrity_budget', self::DEFAULT_BUDGET_SECONDS ) );
	}

	public static function chunk_size(): int {
		/**
		 * Filters how many files are hashed between clock checks.
		 *
		 * @param int $files Files per chunk.
		 */
		return max( 10, (int) apply_filters( 'bettershield_integrity_chunk', self::DEFAULT_CHUNK ) );
	}

	/**
	 * Do as much of a run as the budget allows.
	 *
	 * Starts one if none is in progress. Returns the state as it stands, so a
	 * caller can report progress or notice that it finished.
	 *
	 * **One chunk always happens**, whatever the budget says. The loop is
	 * do-while rather than while for that reason: a budget small enough to be
	 * spent before the first chunk would otherwise mean a tick that does
	 * nothing, saves nothing, and leaves the next tick in exactly the same
	 * place — a run that never finishes and never says why. Guaranteeing
	 * forward progress costs one chunk of overrun at worst.
	 *
	 * **One run at a time.** A tick is a read of the cursor, some work, and a
	 * write back, and four things reach this code: the hourly task, the
	 * loopback fallback, the button on the screen and the terminal. Two of them
	 * at once interleave those writes, repeat each other's work, and one can
	 * close a run the other is still in the middle of. A caller that loses the
	 * claim is handed the run as it stands and does nothing.
	 *
	 * **The claim is one for the whole scanner, not one per scope.** Two runs
	 * over the same target write the same change rows, and interleaving them
	 * would record one file's alteration twice or close a row the other had
	 * just opened. A scoped run that arrives while a full one is in progress
	 * is handed the cursor as it stands and does nothing — which is right,
	 * because the run holding the claim is already checking those targets.
	 *
	 * @param float|null $budget  Seconds this tick may spend; the filtered default when null.
	 * @param int|null   $chunk   Files per chunk; the filtered default when null.
	 * @param bool       $refresh Discard cached manifests, but only if this call starts a run.
	 * @param string     $scope   Which targets this run covers; everything by default.
	 * @return array<string, mixed>
	 */
	public static function tick( ?float $budget = null, ?int $chunk = null, bool $refresh = false, string $scope = self::SCOPE_ALL ): array {
		// The main site's check answers for this site's code too.
		if ( Shared::elsewhere() ) {
			return self::state( $scope );
		}

		$seconds = null !== $budget ? max( 0.0, $budget ) : self::budget_seconds();

		if ( ! Claim::claim( self::RUN_CLAIM, (int) ceil( $seconds ) + 5 ) ) {
			return self::state( $scope );
		}

		try {
			return self::work( $seconds, $chunk, $refresh, $scope );
		} finally {
			Claim::release( self::RUN_CLAIM );
		}
	}

	/**
	 * One tick's work, with the claim already taken.
	 *
	 * @param int|null $chunk Files per chunk; the filtered default when null.
	 * @param string   $scope Which targets this run covers.
	 * @return array<string, mixed>
	 */
	private static function work( float $seconds, ?int $chunk, bool $refresh, string $scope = self::SCOPE_ALL ): array {
		$state = self::state( $scope );

		if ( array() === $state || 3 !== (int) ( $state['v'] ?? 0 ) ) {
			/*
			 * Asked for by hand usually means "ask again", so a cached answer
			 * from last week is not what the owner wants. Only where a run is
			 * genuinely starting, though: throwing the cache away on a call
			 * that resumes one would re-fetch every publisher's list partway
			 * through the comparison that is using it.
			 */
			if ( $refresh ) {
				Manifest::forget_all();
			}

			$state = self::begin( $scope );
		}

		$deadline = microtime( true ) + $seconds;
		$chunk    = null !== $chunk ? max( 1, $chunk ) : self::chunk_size();
		$found    = self::changes_counted( $state );

		do {
			if ( $state['index'] >= count( $state['targets'] ) ) {
				return self::finish( $state );
			}

			$was   = (int) $state['index'];
			$state = self::as_installed( $state );

			/*
			 * The list was fixed when the run began, and a run takes many
			 * minutes. A plugin deleted since then was still walked, and
			 * every file it shipped was recorded as removed: a finding and
			 * an alert each, for something the owner did on purpose.
			 */
			if ( self::target_gone( $state['targets'][ $state['index'] ] ) ) {
				$gone = $state['targets'][ $state['index'] ];

				self::forget_location( (string) $gone['context'], (string) $gone['slug'] );
				$state = self::next_target( $state );
			} else {
				$state = self::advance( $state, $state['targets'][ $state['index'] ], $chunk );
			}

			/*
			 * Saved when the run moves on to another target, and once more when
			 * the tick ends — not once per chunk. The cursor carries every
			 * target's file list, so writing it per chunk meant rewriting
			 * hundreds of kilobytes of one row to advance a counter, dozens of
			 * times a tick. A request killed mid-tick now loses at most the
			 * chunks since the last target boundary, which the next tick
			 * simply does again.
			 */
			if ( (int) $state['index'] !== $was ) {
				self::save( $state );
			}
		} while ( microtime( true ) < $deadline );

		self::save( $state );

		/*
		 * A run takes many ticks, and the findings were refreshed only at its
		 * end, so a change found part way through left "Files have not been
		 * checked" open beside the Overview's altered file and the log's
		 * critical row until the next daily audit (#2194). The first tick
		 * that records one, while that finding is still open, refreshes them;
		 * once it has closed, later ticks have nothing to correct.
		 */
		if ( self::changes_counted( $state ) > $found && \BetterShield\Audit\Auditor::is_open( 'files_never_checked' ) ) {
			\BetterShield\Audit\Auditor::run();
		}

		return $state;
	}

	/**
	 * How many changes this run has recorded so far.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function changes_counted( array $state ): int {
		$stats = isset( $state['stats'] ) && is_array( $state['stats'] ) ? $state['stats'] : array();

		return (int) ( $stats['modified'] ?? 0 ) + (int) ( $stats['added'] ?? 0 ) + (int) ( $stats['removed'] ?? 0 );
	}

	/**
	 * Run to completion regardless of the budget, ticking until it is done.
	 *
	 * For WP-CLI and for the terminal, where somebody is waiting and the
	 * execution limit is not a cron request's. Bounded by a generous ceiling so
	 * a pathological site cannot loop forever.
	 *
	 * The claim covers the whole loop rather than each tick, so a scan starting
	 * elsewhere mid-loop reports progress instead of interleaving. A call that
	 * could not take the claim, or lost it partway, says so with `elsewhere`:
	 * it compared nothing more, and the caller should not read the state it
	 * hands back as a check of its own.
	 *
	 * @param bool $refresh Discard cached manifests, but only if this call starts a run.
	 * @return array<string, mixed>
	 */
	public static function run_to_completion( int $max_ticks = 200, bool $refresh = false ): array {
		// The main site's check answers for this site's code too.
		if ( Shared::elsewhere() ) {
			return array_merge( self::state(), array( 'elsewhere' => true ) );
		}

		if ( ! Claim::claim( self::RUN_CLAIM, self::RUN_CLAIM_SECONDS ) ) {
			return array_merge( self::state(), array( 'elsewhere' => true ) );
		}

		$state   = array();
		$holding = true;

		try {
			for ( $i = 0; $i < $max_ticks; $i++ ) {
				/*
				 * Renewed rather than held for however long the whole loop may
				 * take: a run that outlives one window carries on, and a
				 * request killed mid-run frees the feature within that window
				 * rather than for as long as the run might have taken.
				 */
				if ( $i > 0 && ! Claim::held( self::RUN_CLAIM ) ) {
					$holding = Claim::claim( self::RUN_CLAIM, self::RUN_CLAIM_SECONDS );

					if ( ! $holding ) {
						return array_merge( $state, array( 'elsewhere' => true ) );
					}
				}

				$state = self::work( self::budget_seconds(), null, $refresh && 0 === $i );

				if ( ! empty( $state['finished_at'] ) ) {
					return $state;
				}
			}

			return $state;
		} finally {
			if ( $holding ) {
				Claim::release( self::RUN_CLAIM );
			}
		}
	}

	/**
	 * Start a run: work out what there is to check, and clear the decks.
	 *
	 * The target list is filtered from the whole one rather than assembled
	 * from a shorter source, so a scoped run sees exactly what a full run
	 * would have seen of the same locations — including whatever the targets
	 * filter put there.
	 *
	 * @param string $scope Which targets this run covers.
	 * @return array<string, mixed>
	 */
	private static function begin( string $scope = self::SCOPE_ALL ): array {
		$whole = self::SCOPE_ALL === $scope;

		if ( $whole ) {
			self::forget_bundled_sample_rows();
			self::close_replaced_rows();
		}

		$targets = array();

		foreach ( Targets::all() as $target ) {
			if ( ! $whole && ! Unpublished::is_unpublished( (string) ( $target['context'] ?? '' ) ) ) {
				continue;
			}

			$targets[] = $target;
		}

		/*
		 * Only a full run may throw the walk listing away. A scoped run never
		 * walks a disk — the unpublished locations carry their own file lists
		 * — so clearing it here would cost a full run in progress its
		 * enumeration of a target it is halfway through, once an hour.
		 */
		if ( $whole ) {
			self::forget_walk();
		}

		$state = array(
			// Bumped when the meaning of a saved cursor changes — an offset
			// into a path list this release filters differently would silently
			// skip a chunk. An old cursor restarts the run instead.
			'v'                => 3,
			// Carried in the cursor rather than passed down, so every step
			// that has the cursor knows which run it is in. A cursor written
			// before scopes existed has none, which is the full run it was.
			'scope'            => $scope,
			'started_at'       => gmdate( 'c' ),
			'finished_at'      => null,
			'targets'          => $targets,
			'index'            => 0,
			'phase'            => 'manifest',
			'offset'           => 0,
			// Reset with the offset: a cursor is a position inside one
			// target's file list and means nothing in the next one's.
			'cursor'           => '',
			// Decided once per unpublished location and carried across its
			// chunks; null until the run reaches one.
			'baseline_first'   => null,
			'baseline_updated' => null,
			'baseline_moved'   => null,
			// What an update of an unlisted plugin brought, gathered across
			// the location's chunks; null everywhere else.
			'update_code'      => null,
			'stats'            => array(
				'checked'      => 0,
				'modified'     => 0,
				'removed'      => 0,
				'unreadable'   => 0,
				'added'        => 0,
				'unverifiable' => 0,
			),
			// Targets nothing published, named so the report can say which
			// rather than only how many.
			'unverifiable'     => array(),
		);

		self::save( $state );

		return $state;
	}

	/**
	 * Close open core-context rows under wp-content: the core manifest
	 * genuinely lists the bundled sample plugins, and one release compared
	 * them, telling fresh installs dozens of files had been "removed". Those
	 * paths are excluded from the comparison now, so the rows it opened
	 * would stay open forever — nothing revisits them to notice.
	 *
	 * In this table's own statuses: it asked for the findings table's
	 * 'open', which no row here holds, and closed nothing. Closed as
	 * superseded, kept on record; a row somebody marked expected keeps that.
	 */
	private static function forget_bundled_sample_rows(): void {
		global $wpdb;

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'superseded' WHERE site_id = 0 AND context = 'core' AND status IN ('new','acknowledged') AND path LIKE %s",
				Schema::table( 'integrity_changes' ),
				'wp-content/%'
			)
		);
	}

	/**
	 * Close open rows that a newer row for the same file has replaced.
	 *
	 * The recorder closes the row before when it opens one now, but it used
	 * to leave both open, and sites still carry those: one file counted and
	 * listed once per change. Only the newest row for a path is about the
	 * bytes on disk. A whole-package finding is answered on its own record.
	 */
	private static function close_replaced_rows(): void {
		global $wpdb;

		$table = Schema::table( 'integrity_changes' );
		$ids   = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT a.id FROM %i a WHERE a.site_id = 0 AND a.status IN ('new','acknowledged') AND a.change_type <> %s
				 AND EXISTS ( SELECT 1 FROM %i b WHERE b.site_id = 0 AND b.path_hash = a.path_hash AND b.id > a.id )
				 ORDER BY a.id ASC LIMIT %d",
				$table,
				IncomingPackage::CHANGE_TYPE,
				$table,
				self::REPLACED_PER_RUN
			)
		);

		$ids = array_map( 'intval', is_array( $ids ) ? $ids : array() );

		if ( array() === $ids ) {
			return;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- the placeholder run's length is the list's own, and every id is bound.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'superseded' WHERE site_id = 0 AND status IN ('new','acknowledged') AND id IN (" . implode( ', ', array_fill( 0, count( $ids ), '%d' ) ) . ')',
				array_merge( array( $table ), $ids )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
	}

	/**
	 * The target the run is on, at the version installed now.
	 *
	 * The cursor carries each plugin's version from the moment the run began,
	 * and a run spans many ticks. A plugin updated between two of them was
	 * compared against the release before it: every file the release changed
	 * read as tampering, every file it dropped as removed, and Put back would
	 * have written the old copies into the new release. So the version is
	 * asked again before each chunk, and a target whose version has moved
	 * starts over at the version on disk. Core fetches its list for the
	 * running version whatever the cursor says, so only a plugin or a theme
	 * needs this. A location held to its baseline also takes a fresh file list
	 * and decides again whether this is an update.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>
	 */
	private static function as_installed( array $state ): array {
		$index  = (int) $state['index'];
		$target = $state['targets'][ $index ];

		$held = in_array( (string) $target['context'], array( Unpublished::CONTEXT_THEME, Unpublished::CONTEXT_UNLISTED ), true );

		if ( ! $held && Manifest::CONTEXT_PLUGIN !== (string) $target['context'] ) {
			return $state;
		}

		$installed = $held ? Unpublished::version_on_disk( $target ) : Targets::installed_version( $target );

		if ( '' === $installed || $installed === (string) $target['version'] ) {
			return $state;
		}

		$state['targets'][ $index ]['version'] = $installed;
		$state['phase']                        = 'manifest';
		$state['offset']                       = 0;
		$state['cursor']                       = '';

		if ( $held ) {
			$truncated = false;

			$state['targets'][ $index ]['files']     = Unpublished::is_single_file( (string) $target['slug'] ) ? (array) $target['files'] : Unpublished::files_under( (string) $target['root'], $truncated );
			$state['targets'][ $index ]['truncated'] = $truncated;
			$state['baseline_first']                 = null;
			$state['baseline_updated']               = null;
			$state['baseline_moved']                 = null;
			$state['update_code']                    = null;
		}

		if ( self::SCOPE_ALL === (string) ( $state['scope'] ?? self::SCOPE_ALL ) ) {
			self::forget_walk();
		}

		return $state;
	}

	/**
	 * One chunk of work against one target.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $target
	 * @return array<string, mixed>
	 */
	private static function advance( array $state, array $target, int $chunk ): array {
		// The unpublished locations have no manifest to fetch and no publisher
		// to ask, so they take the other road entirely.
		if ( Unpublished::is_unpublished( (string) $target['context'] ) ) {
			return self::compare_baseline( $state, $target, $chunk );
		}

		$manifest = Manifest::CONTEXT_CORE === $target['context']
			? Manifest::core()
			: Manifest::plugin( (string) $target['slug'], (string) $target['version'] );

		if ( is_wp_error( $manifest ) ) {
			// Nothing published this, or nothing could be fetched. Either way
			// there is no comparison to make, and the honest report is that
			// this target could not be verified — never that it passed.
			$state['unverifiable'][] = array(
				'context' => $target['context'],
				'slug'    => $target['slug'],
				'name'    => self::name_of( $target ),
				'version' => $target['version'],
				'reason'  => (string) ( $manifest->get_error_data()['reason'] ?? Manifest::REASON_UNREACHABLE ),
				'message' => $manifest->get_error_message(),
			);
			++$state['stats']['unverifiable'];

			return self::next_target( $state );
		}

		if ( 'manifest' === $state['phase'] ) {
			return self::compare_manifest( $state, $target, $manifest, $chunk );
		}

		return self::find_unpublished( $state, $target, $manifest, $chunk );
	}

	/**
	 * Published files against what is on disk: modified, and removed.
	 *
	 * @param array<string, mixed>                                          $state
	 * @param array<string, mixed>                                          $target
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 * @return array<string, mixed>
	 */
	private static function compare_manifest( array $state, array $target, array $manifest, int $chunk ): array {
		$paths = array_keys( $manifest['files'] );

		/*
		 * The core manifest lists the bundled sample plugins — the release
		 * zip genuinely carries Akismet and Hello Dolly — but wp-content
		 * belongs to the site, not to core, and many installers never seed
		 * those files. The disk walk already excludes wp-content for the
		 * core context; without the same exclusion here, a site that never
		 * had them was told 48 files "no longer match the official copy",
		 * into the alert email. A plugin actually on disk is checked by its
		 * own target either way: a folder against what its publisher ships or
		 * a baseline, and a plugin that is one file, Hello Dolly among them,
		 * against a baseline.
		 */
		if ( Manifest::CONTEXT_CORE === $target['context'] ) {
			$paths = array_values(
				array_filter(
					$paths,
					static function ( string $path ): bool {
						return 0 !== strpos( $path, 'wp-content/' );
					}
				)
			);
		}

		$slice = array_slice( $paths, (int) $state['offset'], $chunk );

		if ( array() === $slice ) {
			$state['phase']  = 'disk';
			$state['offset'] = 0;
			$state['cursor'] = '';

			return $state;
		}

		// What this slice settled, closed together once it is done: one
		// statement per status rather than one round trip per file.
		$closing = array();

		foreach ( $slice as $relative ) {
			$absolute = $target['root'] . '/' . $relative;
			// The first hash offered, for the record on the change row; the
			// comparison itself accepts any of them.
			$expected = (string) ( Manifest::hashes_for( $manifest, $relative )[0] ?? '' );
			$actual   = Manifest::hash_file( $absolute, $manifest['algo'] );

			++$state['stats']['checked'];

			/*
			 * A copy the owner reviewed and said is their own. The comparison
			 * still ran — this is the answer to it rather than a way around
			 * it: only the exact hash that was adopted is expected here, so a
			 * file altered again since differs from the published copy and
			 * from the adopted one and falls through to be reported like any
			 * other. Nothing is recorded for the expected case, because a
			 * quieter row saying so on every cycle is the same noise one
			 * grade down — the adoption itself is in the activity log.
			 *
			 * Unless the owner stopped ignoring this very copy: their word on
			 * one file outranks the adoption's on the package, and the row
			 * stays open until the file changes or they mark it again.
			 */
			if ( self::adoption_covers( $target, $relative, $actual ) ) {
				self::remember_baseline( $target, $manifest, $relative, (string) $actual, (int) @filesize( $absolute ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.

				if ( ! Restore::taken_back( (string) $target['prefix'] . $relative, (string) $actual ) ) {
					$closing['suppressed'][] = hash( 'sha256', (string) $target['prefix'] . $relative );
				}

				continue;
			}

			if ( null === $actual ) {
				/*
				 * `hash_file()` answers null for a file that is absent and for
				 * one that is present but not readable by the web user, and
				 * calling both "removed" told the owner to reinstall whatever
				 * installed a file that is sitting right there. The remedy was
				 * the part that was actually wrong: a permissions problem is
				 * fixed by fixing permissions.
				 *
				 * Core publishes a handful of files that a given install may
				 * legitimately not have — a locale build, a dropped readme —
				 * so a genuinely missing file is still reported rather than
				 * treated as an error.
				 */
				$change_type = file_exists( $absolute ) ? 'unreadable' : 'removed';

				self::record(
					$target,
					$manifest,
					$relative,
					$change_type,
					$expected,
					null,
					null
				);
				++$state['stats'][ $change_type ];
				continue;
			}

			if ( ! Manifest::matches( $manifest, $relative, $actual ) ) {
				self::record(
					$target,
					$manifest,
					$relative,
					'modified',
					$expected,
					$actual,
					(int) @filesize( $absolute ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a size that cannot be read is recorded as unknown, not as a warning in a dashboard.
				);
				++$state['stats']['modified'];
			} else {
				// Matching is worth recording too: it is what lets a later run
				// tell "changed since we last looked" from "first time seen".
				self::remember_baseline( $target, $manifest, $relative, $actual, (int) @filesize( $absolute ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
				$closing['restored'][] = hash( 'sha256', (string) $target['prefix'] . $relative );
			}
		}

		self::close_changes( $closing );

		$state['offset'] = (int) $state['offset'] + count( $slice );

		return $state;
	}

	/**
	 * What is on disk that nobody published.
	 *
	 * This is the pass that finds a dropped file, which is the shape most real
	 * infections take.
	 *
	 * It was written as one unchunked pass on the grounds that it only reads
	 * directory entries. It does not: every unpublished file it finds is
	 * hashed, and the hash is worth keeping — it is what identifies a file
	 * across scans and against a known sample. So the pass is chunked like the
	 * manifest one, with its own offset in the run state.
	 *
	 * The input is the one thing this plugin does not control: a `node_modules`
	 * left inside a plugin folder, a cache directory, a backup dumped into
	 * wp-content. Unbounded, a big enough one killed the request before it
	 * finished, which meant the cursor never advanced past that target and the
	 * scan re-attempted the same one every hour, forever.
	 *
	 * @param array<string, mixed>                                          $state
	 * @param array<string, mixed>                                          $target
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 * @return array<string, mixed>
	 */
	private static function find_unpublished( array $state, array $target, array $manifest, int $chunk ): array {
		$published = $manifest['files'];
		$walk      = self::walk_paths( $state, $target, $manifest );
		$paths     = $walk['paths'];

		if ( $walk['truncated'] ) {
			$state = self::note_truncated( $state, $target );
		}

		if ( array() !== $walk['set_aside'] ) {
			$state = self::note_set_aside( $state, $target, $walk['set_aside'] );
		}

		/*
		 * Resumed at the last path this walk actually looked at, not at a
		 * count of how many it had seen. A file created or deleted between two
		 * chunks shifts every index after it — and an index that shifted down
		 * stepped over a file nothing had examined, on the one pass whose whole
		 * purpose is to find a file nobody published.
		 *
		 * The list is sorted, so "after" is a comparison rather than a search.
		 */
		$after = (string) ( $state['cursor'] ?? '' );
		$slice = array();

		foreach ( $paths as $relative ) {
			if ( '' !== $after && strcmp( (string) $relative, $after ) <= 0 ) {
				continue;
			}

			$slice[] = $relative;

			if ( count( $slice ) >= $chunk ) {
				break;
			}
		}

		if ( array() === $slice ) {
			// The walk only ever sees files that exist, so an "added" row for
			// a file since deleted could never be closed by it: the dropped
			// backdoor was removed and the site kept reporting a critical
			// finding about a path with nothing at it. Swept here, where the
			// pass has established the complete listing. An omitted path in
			// a capped or interrupted walk is not evidence of its removal,
			// and no more is it evidence that a row from another release is
			// no longer true: the file it names may sit past the cap.
			if ( ! $walk['truncated'] ) {
				self::clear_vanished_additions( $target, $paths );
				self::close_superseded( $target, (string) $manifest['version'] );
			}

			return self::next_target( $state );
		}

		foreach ( $slice as $relative ) {
			$state['cursor'] = (string) $relative;
			// Counted for the record only: this pass resumes from the cursor
			// above, never from a position. Kept because how far into a target
			// a run has got is worth knowing while it is still going.
			++$state['offset'];

			if ( isset( $published[ $relative ] ) ) {
				continue;
			}

			if ( Targets::is_expected_extra( $target, $relative ) ) {
				continue;
			}

			$absolute = $target['root'] . '/' . $relative;

			// The listing was saved earlier in the pass, and this one has gone since.
			if ( ! file_exists( $absolute ) ) {
				continue;
			}

			self::record(
				$target,
				$manifest,
				$relative,
				'added',
				null,
				Manifest::hash_file( $absolute, $manifest['algo'] ),
				(int) @filesize( $absolute ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			);

			++$state['stats']['added'];
		}

		// More of this target's disk to walk: the next tick resumes here rather
		// than starting the target again.
		return $state;
	}

	/**
	 * One slice of an unpublished location, against what it was last time.
	 *
	 * Chunked like everything else here, with its own offset in the run state,
	 * so a theme with three thousand files is walked across several ticks
	 * rather than in one that gets killed. The slices are cut from the
	 * location's listing, so a file that is no longer there is in none of
	 * them; the last slice is told it is the last, and that is when what was
	 * recorded and is no longer found gets settled.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $target
	 * @return array<string, mixed>
	 */
	private static function compare_baseline( array $state, array $target, int $chunk ): array {
		$files = (array) ( $target['files'] ?? array() );
		$slice = array_slice( $files, (int) $state['offset'], $chunk );

		if ( array() === $slice ) {
			return self::next_target( $state );
		}

		/*
		 * "Never looked at this before" and "this has been updated since" are
		 * facts about the location, not about the slice in hand — and the first
		 * slice records what it saw, which changes both answers for every slice
		 * after it. So they are settled once, when the run reaches the location,
		 * and carried in the cursor from there, with a quiet answer held outside
		 * it for a run that loses its cursor or never had this one.
		 */
		if ( null === ( $state['baseline_first'] ?? null ) ) {
			$status                    = Baseline::decide( $target );
			$state['baseline_first']   = $status['first'];
			$state['baseline_updated'] = $status['updated'];
			$state['baseline_moved']   = $status['moved'];
			$state['update_code']      = self::update_code_start( $target, $status );

			if ( ! empty( $target['truncated'] ) ) {
				$state = self::note_truncated( $state, $target );
			}
		}

		// Another run finished this update while this one waited, and said what it brought.
		if ( is_array( $state['update_code'] ?? null ) && null === Baseline::held( $target ) ) {
			$state['update_code'] = null;
		}

		$complete = (int) $state['offset'] + count( $slice ) >= count( $files );
		$seen     = Baseline::compare( $target, $slice, (bool) $state['baseline_first'], (bool) $state['baseline_updated'], $complete );

		$state['offset']            = (int) $state['offset'] + count( $slice );
		$state['stats']['checked'] += (int) $seen['checked'];

		// The location's first look at its `vendor` folders is had once, and
		// so is its first look at the names the walk used to leave out.
		if ( $complete && ! empty( $target['first_look'] ) ) {
			Unpublished::mark_dependencies_seen( (string) $target['context'], (string) $target['slug'] );
		}

		if ( $complete && ! empty( $target['new_names'] ) ) {
			Unpublished::mark_names_seen( (string) $target['context'], (string) $target['slug'] );
		}

		if ( $complete && ! empty( $state['baseline_moved'] ) ) {
			Baseline::note_unconfirmed_checked( $target );
		}

		if ( $complete ) {
			Baseline::release_hold( $target );
		}

		if ( is_array( $state['update_code'] ?? null ) ) {
			$state['update_code'] = self::update_code_add( $state['update_code'], (array) ( $seen['updated'] ?? array() ) );

			if ( $complete ) {
				self::update_code_note( $target, $state['update_code'] );
				$state['update_code'] = null;
			}
		}

		$manifest = array(
			'algo'    => 'sha256',
			'version' => (string) $target['version'],
			'files'   => array(),
		);

		$target['unconfirmed_update'] = ! empty( $state['baseline_moved'] );

		foreach ( array( 'modified', 'added', 'removed', 'unreadable' ) as $change_type ) {
			foreach ( $seen[ $change_type ] as $relative ) {
				// A file reported as added and deleted since is put back as it
				// was, not reported again as missing.
				if ( 'removed' === $change_type && self::close_vanished_addition( $target, (string) $relative ) ) {
					continue;
				}

				// Both hashes, so a second alteration of the same file is a
				// different fact from the first rather than an identical row
				// the recorder skips — and so the screen can say what changed.
				$hashes = $seen['hashes'][ $relative ] ?? array();

				self::record(
					$target,
					$manifest,
					$relative,
					$change_type,
					$hashes['before'] ?? null,
					$hashes['after'] ?? null,
					isset( $hashes['size'] ) ? (int) $hashes['size'] : null
				);
				++$state['stats'][ $change_type ];
			}
		}

		if ( $complete && empty( $target['truncated'] ) ) {
			self::settle_baseline_rows( $target );
		}

		// After the rows above: they're held against what it was before this pass.
		if ( $complete && Unpublished::CONTEXT_CONFIG === (string) $target['context'] && Unpublished::SLUG_WP_CONFIG === (string) $target['slug'] ) {
			KnownWrites::remember_config_if_settled( (string) $target['root'] . '/' . Unpublished::SLUG_WP_CONFIG, (string) $target['prefix'] . Unpublished::SLUG_WP_CONFIG );
		}

		return $state;
	}

	/**
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>
	 */
	private static function next_target( array $state ): array {
		$state['index']  = (int) $state['index'] + 1;
		$state['phase']  = 'manifest';
		$state['offset'] = 0;
		// A cursor is a position inside one target's file list. Carried into
		// the next target it would skip every path sorting below it.
		$state['cursor'] = '';
		// Both are answers about the location just finished.
		$state['baseline_first']   = null;
		$state['baseline_updated'] = null;
		$state['baseline_moved']   = null;
		$state['update_code']      = null;

		if ( self::SCOPE_ALL === (string) ( $state['scope'] ?? self::SCOPE_ALL ) ) {
			self::forget_walk();
		}

		return $state;
	}

	/**
	 * Close the run and publish what it found.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>
	 */
	private static function finish( array $state ): array {
		$state['finished_at'] = gmdate( 'c' );

		// Package differences left open about copies since replaced, from
		// builds that kept more than one (#2145), close with each pass.
		$closed = IncomingPackage::close_outdated();
		$scope                = (string) ( $state['scope'] ?? self::SCOPE_ALL );

		/*
		 * A scoped run looked at a part of the site, so everything below is
		 * not its to write: the result, the summary the audit reads and the
		 * completed-check event each answer for the whole of it, and a run
		 * over five locations publishing them would tell every screen the site
		 * had been checked when a fraction of it had. What it found is already
		 * recorded — the change rows are written as the comparison makes them.
		 */
		if ( self::SCOPE_ALL !== $scope ) {
			delete_option( self::state_option( $scope ) );

			return $state;
		}

		self::forget_walk();

		$settled = self::settle_gone_locations( (array) $state['targets'] );

		update_option(
			self::RESULT_OPTION,
			array(
				'started_at'   => $state['started_at'],
				'finished_at'  => $state['finished_at'],
				'stats'        => $state['stats'],
				'unverifiable' => $state['unverifiable'],
			),
			false
		);

		delete_option( self::STATE_OPTION );

		// `unreadable` is deliberately absent: nothing about the site changed,
		// the check simply could not see one of its files.
		$changed = (int) $state['stats']['modified'] + (int) $state['stats']['added'] + (int) $state['stats']['removed'];

		Writer::instance()->record(
			'integrity_scan_completed',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'integrity',
				'context'     => array(
					'checked'      => (int) $state['stats']['checked'],
					'changed'      => $changed,
					'unverifiable' => (int) $state['stats']['unverifiable'],
				),
			)
		);

		/*
		 * The audit and this scanner are two clocks: an audit snapshot taken
		 * while a run was still ticking recorded "files have not been
		 * checked", and nothing was obliged to correct it until the next
		 * unrelated trigger. The moment this run changes the answer, the
		 * findings are recomputed — the scanner finishing IS the trigger.
		 *
		 * Only when the answer actually changed, though: on a site whose run
		 * fits one tick, the hourly task completes a run every hour, and an
		 * unconditional re-audit here multiplied the daily audit by
		 * twenty-four for nothing.
		 */
		$previous = get_option( self::SUMMARY_OPTION, null );
		$summary  = array( $state['stats'], $state['unverifiable'] );

		// Rows closed for a location that is gone change the answer too, and
		// so do package rows about a copy since replaced: a version changed
		// without the upgrader (a deploy) kept the critical finding up until
		// the daily audit (#2145).
		if ( $summary !== $previous || $settled > 0 || $closed > 0 ) {
			update_option( self::SUMMARY_OPTION, $summary, false );
			\BetterShield\Audit\Auditor::run();
		}

		return $state;
	}

	/**
	 * What the last completed run concluded, or null if none has.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last_result(): ?array {
		$stored = Shared::option( self::RESULT_OPTION, array() );

		return is_array( $stored ) && array() !== $stored ? $stored : null;
	}

	/**
	 * The run in progress at this scope, or an empty array.
	 *
	 * @param string $scope Which run to read the cursor of.
	 * @return array<string, mixed>
	 */
	public static function state( string $scope = self::SCOPE_ALL ): array {
		$stored = Shared::option( self::state_option( $scope ), array() );

		if ( ! is_array( $stored ) || ! isset( $stored['targets'] ) || ! is_array( $stored['targets'] ) ) {
			return array();
		}

		return $stored;
	}

	/**
	 * Where a run of this scope keeps its cursor.
	 *
	 * One option per scope. Two runs sharing a cursor would each resume at the
	 * other's position — an offset into a target list that is not theirs,
	 * which is a chunk stepped over rather than an error anything reports.
	 */
	public static function state_option( string $scope = self::SCOPE_ALL ): string {
		return self::SCOPE_ALL === $scope ? self::STATE_OPTION : self::STATE_OPTION . '_' . $scope;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	private static function save( array $state ): void {
		update_option( self::state_option( (string) ( $state['scope'] ?? self::SCOPE_ALL ) ), $state, false );
	}

	/**
	 * The target's disk listing, enumerated once for as long as the run is on
	 * that target, with the folders the walk set aside.
	 *
	 * A recursive walk of a WordPress root is thousands of directory reads, and
	 * the disk pass runs one chunk at a time — enumerating inside the chunk
	 * meant repeating the whole walk for every two hundred files examined.
	 *
	 * Resumption is unchanged: the walk still resumes at the last path it
	 * looked at rather than at a count, so a file appearing or disappearing
	 * between two ticks still cannot make it step over one it never examined.
	 *
	 * @param array<string, mixed>                                          $state
	 * @param array<string, mixed>                                          $target
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest What the publisher ships, which decides the folders walked by name.
	 * @return array{paths: string[], truncated: bool, set_aside: array<string, array{files: int, complete: bool}>}
	 */
	private static function walk_paths( array $state, array $target, array $manifest ): array {
		$index  = (int) $state['index'];
		$stored = get_option( self::PATHS_OPTION, array() );

		if ( is_array( $stored ) && $index === (int) ( $stored['index'] ?? -1 ) && isset( $stored['paths'] ) && is_array( $stored['paths'] ) ) {
			return array(
				'paths'     => $stored['paths'],
				'truncated' => (bool) ( $stored['truncated'] ?? false ),
				'set_aside' => is_array( $stored['set_aside'] ?? null ) ? $stored['set_aside'] : array(),
			);
		}

		$walk = Targets::walk( $target, array_keys( (array) ( $manifest['files'] ?? array() ) ) );

		update_option(
			self::PATHS_OPTION,
			array(
				'index'     => $index,
				'paths'     => $walk['paths'],
				'truncated' => $walk['truncated'],
				'set_aside' => $walk['set_aside'],
			),
			false
		);

		return $walk;
	}

	/**
	 * Drop a listing that belonged to a target the run has finished with.
	 */
	private static function forget_walk(): void {
		if ( array() !== (array) get_option( self::PATHS_OPTION, array() ) ) {
			delete_option( self::PATHS_OPTION );
		}
	}

	/**
	 * What to call a location on a report, which is not what to look it up by.
	 *
	 * A slug is an address; a name is what the owner installed. Core carries
	 * neither and is named by the screen that shows it, so an empty answer
	 * here is the right one rather than a gap to fill in.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function name_of( array $target ): string {
		$name = trim( (string) ( $target['name'] ?? '' ) );

		return '' !== $name ? $name : (string) $target['slug'];
	}

	/**
	 * Note a location the walk could not enumerate completely.
	 *
	 * A cap is the right answer to a runaway directory; a cap that stops a walk
	 * without saying so is not, because what was left unwalked is exactly where
	 * a file nobody published would sit. The report already has the channel for
	 * this and already names rather than counts what is in it.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $target
	 * @return array<string, mixed>
	 */
	private static function note_truncated( array $state, array $target ): array {
		foreach ( (array) ( $state['unverifiable'] ?? array() ) as $noted ) {
			if ( is_array( $noted )
				&& Manifest::REASON_TRUNCATED === ( $noted['reason'] ?? '' )
				&& (string) $target['context'] === (string) ( $noted['context'] ?? '' )
				&& (string) $target['slug'] === (string) ( $noted['slug'] ?? '' ) ) {
				return $state;
			}
		}

		$state['unverifiable'][] = array(
			'context' => (string) $target['context'],
			'slug'    => (string) $target['slug'],
			'name'    => self::name_of( $target ),
			'version' => (string) $target['version'],
			'reason'  => Manifest::REASON_TRUNCATED,
			'message' => __( 'This folder has too many files to check at once. Some were skipped.', 'bettershield' ),
		);

		$state['stats']['unverifiable'] = (int) ( $state['stats']['unverifiable'] ?? 0 ) + 1;

		return $state;
	}

	/**
	 * Name, once per location, the folders its walk set aside.
	 *
	 * A folder by a dependency or version-control name that its publisher
	 * ships nothing under is not walked file by file, because a build left in
	 * a plugin is thousands of files and each one reported is noise. Left
	 * unsaid, it was also the one place a dropped file was never looked for,
	 * so each is named with how many files it holds: a folder of one file
	 * where a dependency tree would be reads as what it is.
	 *
	 * @param array<string, mixed>                             $state
	 * @param array<string, mixed>                             $target
	 * @param array<string, array{files: int, complete: bool}> $set_aside
	 * @return array<string, mixed>
	 */
	private static function note_set_aside( array $state, array $target, array $set_aside ): array {
		foreach ( (array) ( $state['unverifiable'] ?? array() ) as $noted ) {
			if ( is_array( $noted )
				&& Manifest::REASON_SET_ASIDE === ( $noted['reason'] ?? '' )
				&& (string) $target['context'] === (string) ( $noted['context'] ?? '' )
				&& (string) $target['slug'] === (string) ( $noted['slug'] ?? '' ) ) {
				return $state;
			}
		}

		$named = array();

		foreach ( array_slice( $set_aside, 0, self::SET_ASIDE_NAMED, true ) as $folder => $count ) {
			$files = (int) ( $count['files'] ?? 0 );

			if ( empty( $count['complete'] ) && 0 === $files ) {
				/* translators: %s: a folder's path. */
				$named[] = sprintf( __( '%s (its files could not be counted)', 'bettershield' ), $folder );
				continue;
			}

			if ( empty( $count['complete'] ) ) {
				/* translators: 1: a folder's path, 2: a number of files. */
				$named[] = sprintf( __( '%1$s (at least %2$s files)', 'bettershield' ), $folder, number_format_i18n( $files ) );
				continue;
			}

			/* translators: 1: a folder's path, 2: a number of files. */
			$named[] = sprintf( _n( '%1$s (%2$s file)', '%1$s (%2$s files)', $files, 'bettershield' ), $folder, number_format_i18n( $files ) );
		}

		$more = count( $set_aside ) - count( $named );

		if ( $more > 0 ) {
			/* translators: %s: how many more folders. */
			$named[] = sprintf( _n( '%s more folder', '%s more folders', $more, 'bettershield' ), number_format_i18n( $more ) );
		}

		$state['unverifiable'][] = array(
			'context' => (string) $target['context'],
			'slug'    => (string) $target['slug'],
			'name'    => self::name_of( $target ),
			'version' => (string) $target['version'],
			'reason'  => Manifest::REASON_SET_ASIDE,
			/* translators: %s: a list of folders, each with how many files it holds. */
			'message' => sprintf( __( 'Folders that don’t come with the plugin or theme were skipped: %s.', 'bettershield' ), wp_sprintf( '%l', $named ) ),
		);

		$state['stats']['unverifiable'] = (int) ( $state['stats']['unverifiable'] ?? 0 ) + 1;

		return $state;
	}

	/* ---- the record ---------------------------------------------------- */

	/**
	 * Note a file as it now stands, so the next run can tell new from ongoing.
	 *
	 * @param array<string, mixed>                                          $target
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 */
	private static function remember_baseline( array $target, array $manifest, string $relative, string $hash, int $size ): void {
		global $wpdb;

		$path = (string) $target['prefix'] . $relative;

		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (site_id, path_hash, path, context, slug, version, algo, file_hash, file_size, recorded_at)
				 VALUES (0, %s, %s, %s, %s, %s, %s, %s, %d, %s)
				 ON DUPLICATE KEY UPDATE version = VALUES(version), algo = VALUES(algo), file_hash = VALUES(file_hash), file_size = VALUES(file_size), recorded_at = VALUES(recorded_at)',
				Schema::table( 'integrity_baseline' ),
				hash( 'sha256', $path ),
				$path,
				(string) $target['context'],
				(string) $target['slug'],
				(string) $manifest['version'],
				(string) $manifest['algo'],
				$hash,
				$size,
				self::now()
			)
		);
	}

	/**
	 * A change's grade in the words a screen uses, by the rule its activity
	 * row and its alert are graded by, so the Files screen does not grade
	 * the same file another way (#1831).
	 */
	public static function grade_of( string $change_type, string $context, string $path, bool $unconfirmed = false, bool $explained = false ): string {
		$names = array(
			Writer::SEVERITY_INFO     => 'info',
			Writer::SEVERITY_LOW      => 'low',
			Writer::SEVERITY_MEDIUM   => 'medium',
			Writer::SEVERITY_HIGH     => 'high',
			Writer::SEVERITY_CRITICAL => 'critical',
		);

		return $names[ self::severity_of_change( $change_type, $context, $path, $unconfirmed, $explained ) ] ?? 'critical';
	}

	/**
	 * How loudly a difference is reported.
	 *
	 * An altered file, or one nobody published where a publisher's files live,
	 * is the loudest thing this plugin says. A file that is merely absent is
	 * not rated the same:
	 * removals are routinely a locale build, a host's own tidying, or a plugin
	 * that ships fewer files than its manifest lists. A file that is present
	 * but cannot be read is quieter still — it says something about this
	 * server's permissions rather than about this site's code.
	 *
	 * The context is the resolved one, and it settles the rest. A file that
	 * appeared at the install root is a deploy artifact as often as it is code
	 * somebody left behind, so it is recorded below the grade that mails
	 * immediately — otherwise the loudest channel this plugin has goes to a
	 * forgotten debug script on the first scan of every developer's site.
	 *
	 * A configuration file that arrives is graded as an arrival rather than as
	 * the configuration it is: what is known is that it is there, and the grade
	 * that mails the owner at once is kept for a file whose contents no longer
	 * match what they were.
	 *
	 * An arrival is also graded by what the file can do. A dropped `.php`
	 * inside somebody's plugin or theme folder is the shape a backdoor takes; a
	 * source map, a text file or an image beside it is a build artifact, and
	 * grading the two the same spends the channel that mails immediately on the
	 * commonest noise. Inside a directory WordPress itself owns the question
	 * does not arise: nothing belongs there that core did not ship.
	 *
	 * @param string $context  The context the row was filed under, after the
	 *                         classifier has had its say.
	 * A location whose version header moved with nothing to confirm an update
	 * is graded high. The header can be edited by whoever edits the files, so
	 * this lowers how loud the change is and proves nothing: it is still a
	 * finding, and a hidden executable stays critical.
	 *
	 * @param string $relative The file's path within the target.
	 * @param bool   $unconfirmed Whether the change came under an unconfirmed version.
	 * @param bool   $explained   Whether the contents are what a known plugin writes. See KnownWrites.
	 */
	private static function severity_of_change( string $change_type, string $context, string $relative = '', bool $unconfirmed = false, bool $explained = false ): int {
		if ( 'unreadable' === $change_type ) {
			return Writer::SEVERITY_LOW;
		}

		if ( $explained ) {
			return Writer::SEVERITY_MEDIUM;
		}

		if ( 'removed' === $change_type ) {
			return Writer::SEVERITY_MEDIUM;
		}

		// A package that differs from the official copy, as its event grades it.
		if ( IncomingPackage::CHANGE_TYPE === $change_type ) {
			return Writer::SEVERITY_HIGH;
		}

		// A configuration file that was not there when this site's
		// configuration was last recorded is reported below the grade that
		// mails the owner at once: that it is there is the whole of what is
		// known about it, nothing having been held against anything. An
		// alteration to one already being watched has contents to compare and
		// falls through to the grade below.
		if ( 'added' === $change_type && Unpublished::CONTEXT_CONFIG === $context ) {
			return Writer::SEVERITY_MEDIUM;
		}

		if ( Manifest::CONTEXT_EXTRA === $context ) {
			return Writer::SEVERITY_MEDIUM;
		}

		if ( 'added' === $change_type && Manifest::CONTEXT_CORE !== $context && ! self::can_execute( $relative ) ) {
			return Writer::SEVERITY_MEDIUM;
		}

		return $unconfirmed && ! self::is_hidden_executable( $relative ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_CRITICAL;
	}

	/** Whether a file can run and any part of its path starts with a dot. */
	private static function is_hidden_executable( string $relative ): bool {
		return self::can_execute( $relative ) && 1 === preg_match( '~(?:^|/)\.~', $relative );
	}

	/**
	 * What an update of a plugin nobody publishes brought, gathered across
	 * the slices its location is compared in and said once.
	 *
	 * Only for a plugin the directory does not publish: a directory plugin's
	 * update is checked against the copy its publisher shipped, and nothing
	 * checks this one. Names only. Nothing is opened: which files are new or
	 * different is the fact, and it is a fact about the update, not a finding.
	 * The one thing read into a name is whether any part of its path starts
	 * with a dot, since a hidden executable is worth a first look.
	 *
	 * @param array<string, mixed> $target
	 * @param array<string, mixed> $status
	 * @return array{from: string, to: string, added: int, changed: int, files: string[], hidden: string[]}|null
	 */
	private static function update_code_start( array $target, array $status ): ?array {
		if ( Unpublished::CONTEXT_UNLISTED !== (string) ( $target['context'] ?? '' ) || empty( $status['updated'] ) || ! empty( $status['first'] ) ) {
			return null;
		}

		return array(
			'from'    => (string) ( $status['previous'] ?? '' ),
			'to'      => (string) ( $target['version'] ?? '' ),
			'added'   => 0,
			'changed' => 0,
			'files'   => array(),
			'hidden'  => array(),
		);
	}

	/**
	 * @param array<string, mixed>            $gathered
	 * @param array{added?: string[], changed?: string[]} $updated
	 * @return array<string, mixed>
	 */
	private static function update_code_add( array $gathered, array $updated ): array {
		foreach ( array( 'added', 'changed' ) as $kind ) {
			foreach ( (array) ( $updated[ $kind ] ?? array() ) as $relative ) {
				$relative = (string) $relative;

				if ( ! self::can_execute( $relative ) ) {
					continue;
				}

				++$gathered[ $kind ];

				if ( count( $gathered['files'] ) < self::UPDATE_CODE_NAMED ) {
					$gathered['files'][] = $relative;
				}

				if ( count( $gathered['hidden'] ) < self::UPDATE_CODE_NAMED && preg_match( '~(?:^|/)\.~', $relative ) ) {
					$gathered['hidden'][] = $relative;
				}
			}
		}

		return $gathered;
	}

	/**
	 * One low line in the activity record, when the update brought any
	 * executable file at all. No alert, and it never opens an incident: it
	 * is what the new version contains, stated for whoever looks. An
	 * incident already open around it takes it in as corroborating evidence
	 * (Incidents\Signals, #2343).
	 *
	 * @param array<string, mixed> $target
	 * @param array<string, mixed> $gathered
	 */
	private static function update_code_note( array $target, array $gathered ): void {
		$total = (int) $gathered['added'] + (int) $gathered['changed'];

		if ( 0 === $total ) {
			return;
		}

		Writer::instance()->record(
			'update_code_changed',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'plugin',
				'object_id'   => (string) ( $target['slug'] ?? '' ),
				'context'     => array(
					'name'    => self::name_of( $target ),
					'from'    => (string) $gathered['from'],
					'to'      => (string) $gathered['to'],
					'added'   => (int) $gathered['added'],
					'changed' => (int) $gathered['changed'],
					'files'   => array_values( (array) $gathered['files'] ),
					'hidden'  => array_values( (array) $gathered['hidden'] ),
					'more'    => max( 0, $total - count( (array) $gathered['files'] ) ),
				),
			)
		);
	}

	/**
	 * Whether a file at this path is one the server would run or include.
	 *
	 * By name rather than by contents: reading the file to decide would mean
	 * this plugin holding the bytes of something it just called suspicious.
	 */
	private static function can_execute( string $relative ): bool {
		// The module's one list, which the baseline walk and the Files
		// screen's sorting read too.
		return Packages::can_run( $relative );
	}

	/**
	 * Which context an unpublished file belongs to.
	 *
	 * Only the core target can produce this question, and only for a file the
	 * manifest does not list. Inside a directory WordPress owns, that is code
	 * placed where WordPress runs it, and the claim "this does not match what
	 * the publisher shipped" is exactly right. At the install root it is as
	 * likely to be a deploy artifact, a forgotten debug script or a tool's
	 * output — worth showing, and not the same sentence.
	 *
	 * Everything else is returned untouched: a plugin's own folder has no root
	 * that is not the plugin.
	 *
	 * @param array<string, mixed> $target
	 * @return array<string, mixed>
	 */
	private static function context_for_addition( array $target, string $relative ): array {
		if ( Manifest::CONTEXT_CORE !== (string) $target['context'] ) {
			return $target;
		}

		$directory = trim( (string) wp_parse_url( $relative, PHP_URL_PATH ), '/' );
		$directory = false !== strpos( $directory, '/' ) ? strstr( $directory, '/', true ) : '';

		if ( in_array( $directory, array( 'wp-admin', 'wp-includes' ), true ) ) {
			return $target;
		}

		$target['context'] = Manifest::CONTEXT_EXTRA;

		return $target;
	}

	/**
	 * Record a difference, or leave an existing open one alone.
	 *
	 * A file that has been altered and stays altered is one finding, not one
	 * per day: re-recording it every run would bury the reader and would make
	 * "detected at" meaningless. A suppressed one is never resurrected.
	 *
	 * @param array<string, mixed>                                          $target
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 */
	private static function record( array $target, array $manifest, string $relative, string $change_type, ?string $before, ?string $after, ?int $size_after ): void {
		global $wpdb;

		// Decided here rather than at the call site, so a future caller that
		// records an addition cannot route around it and file root clutter as
		// a tampered core file again.
		if ( 'added' === $change_type ) {
			$target = self::context_for_addition( $target, $relative );
		}

		$path      = (string) $target['prefix'] . $relative;
		$path_hash = hash( 'sha256', $path );
		$table     = Schema::table( 'integrity_changes' );

		// Held on the row, because a screen grades it long after the run that
		// knew, and the screen and the alert have to give one answer (#1831).
		$unconfirmed = ! empty( $target['unconfirmed_update'] ) && ! self::is_hidden_executable( $relative );
		$known       = KnownWrites::standing( $target, $relative, $change_type );
		$explained   = KnownWrites::EXPLAINED === $known;
		$unconfirmed = $unconfirmed || 1 === $known;

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT id, status, version, change_type, hash_before, hash_after FROM %i WHERE site_id = 0 AND path_hash = %s ORDER BY id DESC LIMIT 1',
				$table,
				$path_hash
			)
		);

		if ( null !== $existing ) {
			// A file kept in quarantine is held to the placeholder left in its
			// place in the same way: the same bytes are nothing new (#1971).
			$open = in_array( (string) $existing->status, array( 'new', 'acknowledged', 'suppressed', KeepInQuarantine::STATUS ), true );

			// Still open and still the same file: nothing new to say. A
			// suppressed row is open for this purpose, which is what makes the
			// fall-through below correct — a suppression covers the state that
			// was judged acceptable, not the path forever, so a file that has
			// changed again since fails this test and is recorded anew.
			if ( $open && (string) $existing->hash_after === (string) $after ) {
				/*
				 * The same bytes, compared against another release: an update
				 * laid over the folder that left this file as it was. Still
				 * the same finding, so the row is moved to the release that
				 * was just compared. Left naming the one before, it was closed
				 * as put back by the sweep for rows from another release,
				 * while the file was still on disk.
				 */
				if ( (string) $existing->version !== (string) $manifest['version']
					|| (string) $existing->change_type !== $change_type
					|| (string) $existing->hash_before !== (string) $before ) {
					$wpdb->update(
						$table,
						array(
							'version'     => (string) $manifest['version'],
							'change_type' => $change_type,
							'hash_before' => $before,
						),
						array(
							'site_id' => 0,
							'id'      => (int) $existing->id,
						),
						array( '%s', '%s', '%s' ),
						array( '%d', '%d' )
					);
				}

				return;
			}

			/*
			 * Back to the bytes it had before the change in hand: the change
			 * is undone, not a new one. Reinstalling the same release put the
			 * original back, and a fresh "modified" row reported the return as
			 * a compromise and fed it to an open incident as evidence (#2342).
			 * The change is every row since the path was last settled — put
			 * back, accepted, kept in quarantine — so a file edited twice and
			 * then restored closes both of its rows.
			 *
			 * Only the starting bytes of the earliest of those rows count:
			 * they are the last bytes known to be good. A later row starts
			 * from an altered copy, and returning to that copy is still an
			 * altered file, recorded below like any other change.
			 */
			if ( 'modified' === $change_type && null !== $after ) {
				$settled = (int) $wpdb->get_var(
					$wpdb->prepare(
						"SELECT COALESCE( MAX( id ), 0 ) FROM %i WHERE site_id = 0 AND path_hash = %s AND status NOT IN ('new','acknowledged','superseded')",
						$table,
						$path_hash
					)
				);
				$start   = $wpdb->get_var(
					$wpdb->prepare(
						"SELECT hash_before FROM %i WHERE site_id = 0 AND path_hash = %s AND id > %d AND status IN ('new','acknowledged','superseded') ORDER BY id ASC LIMIT 1",
						$table,
						$path_hash,
						$settled
					)
				);

				if ( null !== $start && (string) $start === (string) $after ) {
					$wpdb->query(
						$wpdb->prepare(
							"UPDATE %i SET status = 'restored' WHERE site_id = 0 AND path_hash = %s AND id > %d AND status IN ('new','acknowledged','superseded')",
							$table,
							$path_hash,
							$settled
						)
					);

					return;
				}
			}

			/*
			 * A file has one open finding, about its newest bytes. The rows
			 * before this one describe bytes that are no longer on disk, and
			 * left open they counted and listed one file once per change, to
			 * be marked expected once per row. Closed rather than deleted, so
			 * each change stays on record.
			 */
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET status = 'superseded' WHERE site_id = 0 AND path_hash = %s AND status IN ('new','acknowledged')",
					$table,
					$path_hash
				)
			);
		}

		$wpdb->insert(
			$table,
			array(
				'site_id'     => 0,
				'path_hash'   => $path_hash,
				'path'        => $path,
				'context'     => (string) $target['context'],
				'slug'        => (string) $target['slug'],
				'version'     => (string) $manifest['version'],
				'detected_at' => self::now(),
				'change_type' => $change_type,
				'algo'        => (string) $manifest['algo'],
				'hash_before' => $before,
				'hash_after'  => $after,
				'size_after'  => $size_after,
				'status'      => 'new',
				'unconfirmed_update' => $explained ? KnownWrites::EXPLAINED : ( $unconfirmed ? 1 : 0 ),
			)
		);

		/*
		 * The first event this plugin records at critical, and the reason the
		 * instant-alert path exists: a core or plugin file that no longer
		 * matches what its publisher shipped is the clearest signal available
		 * that something is wrong right now.
		 *
		 * A file that is merely absent is not rated the same. Removals are
		 * routinely a locale build, a host's own tidying, or a plugin that
		 * ships fewer files than its manifest lists.
		 *
		 * The grade is read off the resolved context for the same reason the
		 * row above is written with it: a file that appeared at the install
		 * root is graded medium on the report, and mailing the owner at
		 * critical about a finding their dashboard calls medium is two
		 * different answers to one question.
		 *
		 * A run can find hundreds of changes in one request, and the writer
		 * holds two hundred rows until shutdown. Past that, this row may not
		 * thin and was dropped, with only a count left in the log. Written
		 * out first instead: one INSERT is nothing beside the hashing.
		 */
		if ( Writer::instance()->full() ) {
			Writer::instance()->flush();
		}

		Writer::instance()->record(
			'file_changed',
			self::severity_of_change( $change_type, (string) $target['context'], $relative, $unconfirmed, $explained ),
			array(
				// What the site found, whoever's request ran the check: a
				// check somebody pressed must not credit them with the change.
				'actor_type'  => 'system',
				'object_type' => 'file',
				'object_id'   => $path,
				'context'     => array(
					'change'  => $change_type,
					'area'    => (string) $target['context'],
					'slug'    => (string) $target['slug'],
					// Hashes, never contents. A log that copied the altered
					// file would become the thing worth stealing.
					'before'  => $before,
					'after'   => $after,
				),
			)
		);
	}

	/**
	 * Whether this file is one the owner has already reviewed and adopted.
	 *
	 * Only a published package can be adopted, and only at the version that
	 * was reviewed — an update moves the version and the question is asked
	 * again, which is what makes the answer a decision about a copy rather
	 * than about a path.
	 *
	 * @param array<string, mixed> $target
	 * @param string|null          $actual The hash on disk, or null when the file is gone.
	 */
	private static function adoption_covers( array $target, string $relative, ?string $actual ): bool {
		if ( Manifest::CONTEXT_PLUGIN !== (string) $target['context'] ) {
			return false;
		}

		return IncomingPackage::covers(
			(string) $target['slug'],
			(string) $target['version'],
			$relative,
			$actual
		);
	}

	/**
	 * A file that matches again, or that matches what was adopted, closes
	 * whatever was open against it.
	 *
	 * The two answers are not the same sentence: `restored` says the published
	 * bytes are back, and a row about an adopted copy would be untrue if it
	 * said so. `suppressed` says somebody decided this is expected, which is
	 * what happened — and it stays open for the recorder's purposes, so a
	 * later alteration of the same file is recorded anew rather than skipped.
	 *
	 * Many files at once, as status => path hashes, in bounded statements: a
	 * tick settles hundreds of files on a real site, and one round trip each
	 * was hundreds of statements in one request.
	 *
	 * @param array<string, string[]> $closing
	 */
	private static function close_changes( array $closing ): void {
		global $wpdb;

		foreach ( $closing as $status => $hashes ) {
			foreach ( array_chunk( array_values( array_unique( $hashes ) ), 200 ) as $chunk ) {
				$in = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );

				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- $in is placeholders only; every value goes through prepare().
				$wpdb->query( $wpdb->prepare( "UPDATE %i SET status = %s WHERE site_id = 0 AND path_hash IN ($in) AND status IN ('new','acknowledged')", array_merge( array( Schema::table( 'integrity_changes' ), (string) $status ), $chunk ) ) );
			}
		}
	}

	/**
	 * Close open "added" rows for files that are no longer there.
	 *
	 * A file nobody published, then deleted, is no longer true of this site —
	 * and the record of having found it stays in the activity log, which is
	 * where that history belongs.
	 *
	 * Bounded by the location a row was filed under rather than by the shape of
	 * its path. The core target's prefix is the empty string, which as a
	 * pattern matches every row on the site: core is checked first and never
	 * looks inside wp-content, so a prefix-bounded sweep closed every finding
	 * every other target had open, every run.
	 *
	 * @param array<string, mixed> $target
	 * @param string[]             $on_disk Relative paths the walk just saw.
	 */
	private static function clear_vanished_additions( array $target, array $on_disk ): void {
		global $wpdb;

		$prefix = (string) $target['prefix'];

		/*
		 * Two contexts for core, one for everything else: a file that appeared
		 * at the install root is filed under `extra` by the classifier, and the
		 * core walk is the only pass that can answer for it. The pair is named
		 * twice rather than built into the statement, so the placeholder count
		 * is fixed and the query stays a prepared one.
		 */
		$contexts = Manifest::CONTEXT_CORE === (string) $target['context']
			? array( Manifest::CONTEXT_CORE, Manifest::CONTEXT_EXTRA )
			: array( (string) $target['context'], (string) $target['context'] );

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, path FROM %i WHERE site_id = 0 AND change_type = 'added' AND status IN ('new','acknowledged') AND slug = %s AND context IN (%s, %s)",
				Schema::table( 'integrity_changes' ),
				(string) $target['slug'],
				$contexts[0],
				$contexts[1]
			)
		);

		if ( ! is_array( $rows ) || array() === $rows ) {
			return;
		}

		$present = array_flip( $on_disk );

		foreach ( $rows as $row ) {
			$relative = substr( (string) $row->path, strlen( $prefix ) );

			if ( isset( $present[ $relative ] ) ) {
				continue;
			}

			$wpdb->update(
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
	}

	/**
	 * Close what a comparison against another release of this target left
	 * open.
	 *
	 * A row is a difference from one release. Once the release installed has
	 * been compared in full, a row naming another one is about files as that
	 * release shipped them — a file changed since, or one the installed
	 * release no longer ships at all, which no later pass would revisit. The
	 * comparison that just finished moved anything still true to the release
	 * installed (see `record()`), and runs this only after a complete walk. A
	 * whole-package finding keeps its own record beside it and is answered
	 * there.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function close_superseded( array $target, string $version ): void {
		global $wpdb;

		if ( '' === $version ) {
			return;
		}

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'restored' WHERE site_id = 0 AND context = %s AND slug = %s AND version <> %s AND change_type <> %s AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				(string) $target['context'],
				(string) $target['slug'],
				$version,
				IncomingPackage::CHANGE_TYPE
			)
		);
	}

	/**
	 * Close the open "added" row for a file the baseline walk found gone.
	 *
	 * @param array<string, mixed> $target
	 * @return bool Whether there was one.
	 */
	private static function close_vanished_addition( array $target, string $relative ): bool {
		global $wpdb;

		$closed = $wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'restored' WHERE site_id = 0 AND path_hash = %s AND context = %s AND slug = %s AND change_type = 'added' AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				hash( 'sha256', (string) $target['prefix'] . $relative ),
				(string) $target['context'],
				(string) $target['slug']
			)
		);

		return is_int( $closed ) && $closed > 0;
	}

	/**
	 * Close what a location compared against its own baseline left open and
	 * is no longer on disk.
	 *
	 * A location with no published checksums is held against what this site
	 * recorded, so a row is closed by the files, not by a release: an added
	 * file that is gone, and a changed file under another version whose
	 * changed copy is gone, since reinstalling a release overwrote it. A file
	 * still holding what its row recorded stays open, whatever version the
	 * header now names. Run after a complete, untruncated walk only.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function settle_baseline_rows( array $target ): void {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, path, version, change_type, hash_after FROM %i WHERE site_id = 0 AND context = %s AND slug = %s AND change_type IN ('added','modified') AND status IN ('new','acknowledged') LIMIT 500",
				Schema::table( 'integrity_changes' ),
				(string) $target['context'],
				(string) $target['slug']
			)
		);

		if ( ! is_array( $rows ) || array() === $rows ) {
			return;
		}

		$prefix  = (string) $target['prefix'];
		$version = (string) ( $target['version'] ?? '' );

		foreach ( $rows as $row ) {
			$path = (string) $row->path;

			if ( '' !== $prefix && 0 !== strpos( $path, $prefix ) ) {
				continue;
			}

			$absolute = (string) $target['root'] . '/' . substr( $path, strlen( $prefix ) );
			$present  = file_exists( $absolute );

			if ( 'added' === (string) $row->change_type ) {
				$gone = ! $present;
			} else {
				$now  = $present ? Manifest::hash_file( $absolute, 'sha256' ) : null;
				$gone = (string) $row->version !== $version && ( ! $present || ( null !== $now && null !== $row->hash_after && ! hash_equals( (string) $row->hash_after, $now ) ) );
			}

			if ( ! $gone ) {
				continue;
			}

			$wpdb->update(
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
	}

	/* ---- locations that are no longer there ------------------------------- */

	/** The contexts whose location can be removed from the site. */
	private const REMOVABLE = array(
		Manifest::CONTEXT_PLUGIN,
		Unpublished::CONTEXT_UNLISTED,
		Unpublished::CONTEXT_THEME,
		Unpublished::CONTEXT_DROPIN,
		Unpublished::CONTEXT_MUPLUGIN,
	);

	/**
	 * Whether a target's location has gone since the run listed it.
	 *
	 * Read from the target's own root rather than looked up by slug, so a
	 * location a filter stood in is judged by the folder it named.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function target_gone( array $target ): bool {
		$context = (string) ( $target['context'] ?? '' );
		$root    = (string) ( $target['root'] ?? '' );

		if ( ! in_array( $context, self::REMOVABLE, true ) || '' === $root ) {
			return false;
		}

		clearstatcache();

		// A drop-in's location is its file, not the folder it sits in, and so
		// is a plugin's that is one file.
		if ( Unpublished::CONTEXT_DROPIN === $context || ( Unpublished::CONTEXT_UNLISTED === $context && Unpublished::is_single_file( (string) ( $target['slug'] ?? '' ) ) ) ) {
			foreach ( (array) ( $target['files'] ?? array( $target['slug'] ) ) as $file ) {
				if ( is_file( $root . '/' . (string) $file ) ) {
					return false;
				}
			}

			return true;
		}

		return ! is_dir( $root );
	}

	/**
	 * Whether a location is still on this site, checked or not.
	 *
	 * Core and the configuration files are always there to be watched, and a
	 * context this does not know is treated the same way: only a location
	 * that is demonstrably gone has its rows closed.
	 */
	private static function location_present( string $context, string $slug ): bool {
		if ( ! in_array( $context, self::REMOVABLE, true ) || '' === $slug ) {
			return true;
		}

		switch ( $context ) {
			case Unpublished::CONTEXT_THEME:
				return wp_get_theme( $slug )->exists();
			case Unpublished::CONTEXT_DROPIN:
				return is_file( WP_CONTENT_DIR . '/' . $slug );
			case Unpublished::CONTEXT_MUPLUGIN:
				return defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR );
			default:
				// A plugin that is one file is there while its file is.
				return Unpublished::is_single_file( $slug ) ? is_file( WP_PLUGIN_DIR . '/' . $slug ) : is_dir( WP_PLUGIN_DIR . '/' . $slug );
		}
	}

	/**
	 * Close what was open against a location that is no longer installed,
	 * and forget its baseline.
	 *
	 * Deleting a plugin through WordPress is not tampering, and its rows have
	 * nothing left to be compared against, so no check could ever close them.
	 * They stay on record as `uninstalled`; the deletion itself is in the
	 * activity log. A baseline left behind would hold a later install with
	 * the same name, such as another cache plugin's drop-in, to these files.
	 *
	 * @return int How many rows were closed.
	 */
	private static function forget_location( string $context, string $slug ): int {
		global $wpdb;

		$closed = $wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'uninstalled' WHERE site_id = 0 AND context = %s AND slug = %s AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				$context,
				$slug
			)
		);

		Baseline::forget( $context, $slug );

		return is_int( $closed ) ? $closed : 0;
	}

	/**
	 * At the end of a full run, close the rows of every location that is gone.
	 *
	 * A location removed between two runs is not a target of the next one, so
	 * nothing visits its rows again. A location is settled only when it is
	 * neither one this run checked nor still on disk: one a filter stopped
	 * checking, or a theme switched away from, keeps its rows.
	 *
	 * @param array<int, array<string, mixed>> $targets The run's targets.
	 * @return int How many rows were closed.
	 */
	private static function settle_gone_locations( array $targets ): int {
		global $wpdb;

		$checked = array();

		foreach ( $targets as $target ) {
			if ( is_array( $target ) && ! self::target_gone( $target ) ) {
				$checked[ (string) ( $target['context'] ?? '' ) . '|' . (string) ( $target['slug'] ?? '' ) ] = true;
			}
		}

		// The open rows, and the baselines: a location with nothing open can
		// still leave a baseline that a later install of the same name meets.
		// One placeholder per entry in REMOVABLE.
		$found = array_merge(
			(array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT DISTINCT context, slug FROM %i WHERE site_id = 0 AND status IN ('new','acknowledged') AND context IN (%s, %s, %s, %s, %s)",
					Schema::table( 'integrity_changes' ),
					self::REMOVABLE[0],
					self::REMOVABLE[1],
					self::REMOVABLE[2],
					self::REMOVABLE[3],
					self::REMOVABLE[4]
				)
			),
			(array) $wpdb->get_results(
				$wpdb->prepare(
					'SELECT DISTINCT context, slug FROM %i WHERE site_id = 0 AND context IN (%s, %s, %s, %s, %s)',
					Schema::table( 'integrity_baseline' ),
					self::REMOVABLE[0],
					self::REMOVABLE[1],
					self::REMOVABLE[2],
					self::REMOVABLE[3],
					self::REMOVABLE[4]
				)
			)
		);

		$pairs = array();

		foreach ( $found as $row ) {
			if ( is_object( $row ) ) {
				$pairs[ (string) $row->context . '|' . (string) $row->slug ] = array( (string) $row->context, (string) $row->slug );
			}
		}

		$closed = 0;

		foreach ( $pairs as $key => $pair ) {
			if ( isset( $checked[ $key ] ) || self::location_present( $pair[0], $pair[1] ) ) {
				continue;
			}

			$closed += self::forget_location( $pair[0], $pair[1] );
		}

		return $closed;
	}

	private static function now(): string {
		return ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}
}
