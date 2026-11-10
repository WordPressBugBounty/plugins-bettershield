<?php
/**
 * Hardening item: stop directory listings in uploads.
 *
 * A directory with no index file may list its contents to anyone who asks,
 * handing out file names that were never linked anywhere. Core ships guard
 * index.php files in wp-content, plugins and themes; the uploads tree is the
 * one it leaves open.
 *
 * The fix is guard files, not a server directive, on purpose. `Options
 * -Indexes` sits in an .htaccess class that a restrictively configured host
 * answers with a site-wide 500 — taking down the admin and the undo with it.
 * A guard file works on every server and can break nothing: the worst it can
 * do is exist.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Files\Guarded;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DirectoryBrowsing {

	/**
	 * Directories examined: uploads, its children, and their children —
	 * which is the whole of the standard year/month layout.
	 */
	private const DEPTH = 2;

	/**
	 * Guards written in one apply. Far above any real uploads tree at the
	 * covered depth; a bound, not a target.
	 */
	private const MAX_GUARDS = 500;

	private const GUARD = "<?php\n// Silence is golden.\n";

	/** The ledger action every guard is recorded under. */
	private const ACTION = 'harden_directory_browsing';

	/**
	 * Recorded guards looked at by removed_guards(): ten passes at the
	 * cap, which is past any real tree; a bound, not a target.
	 */
	private const MAX_CHECKED = 5000;

	/**
	 * Guards placed in one pass. Filterable the way the integrity budget is,
	 * which is also what lets a test exercise the cap without five hundred
	 * directories.
	 */
	private static function cap(): int {
		return max( 1, (int) apply_filters( 'bettershield_guard_cap', self::MAX_GUARDS ) );
	}

	/**
	 * @param array<string, mixed> $state Unused; the guard files are the effect.
	 */
	public static function enforce( array $state ): void {}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {}

	/**
	 * One bounded pass of guard placement: the loop apply() and top_up()
	 * share, so the ledger action, the file name and the guard bytes exist
	 * in exactly one place.
	 *
	 * @return array{tokens: string[], failures: int, capped: bool}
	 */
	private static function place_guards( string $base ): array {
		$cap = self::cap();
		$root = realpath( $base );

		// One more than the pass can place, which is all it takes to know the
		// tree ran past the cap — and all the walk has to look at.
		$dirs     = self::bare_directories( $base, $cap + 1 );
		$tokens   = array();
		$failures = 0;

		foreach ( array_slice( $dirs, 0, $cap ) as $dir ) {
			// Recheck the boundary at the writer as well as during enumeration.
			$resolved = realpath( $dir );
			if ( false === $root || false === $resolved || ( $resolved !== $root && ( is_link( $dir ) || ! str_starts_with( wp_normalize_path( $resolved ), trailingslashit( wp_normalize_path( $root ) ) ) ) ) ) {
				++$failures;
				continue;
			}
			$token = Guarded::create_owned( self::ACTION, $dir . '/index.php', self::GUARD );

			if ( is_wp_error( $token ) ) {
				// One unwritable directory is a note, not a reason to abandon
				// the rest; the guards are independent of each other.
				++$failures;
				continue;
			}

			$tokens[] = $token;
		}

		return array(
			'tokens'   => $tokens,
			'failures' => $failures,
			'capped'   => count( $dirs ) > $cap,
		);
	}

	/**
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		$uploads = wp_get_upload_dir();
		$base    = untrailingslashit( (string) $uploads['basedir'] );

		if ( ! is_dir( $base ) ) {
			return new \WP_Error( 'bettershield_no_uploads', __( 'The change was not applied: the uploads directory does not exist.', 'bettershield' ) );
		}

		// A fresh apply starts the count over; a rest the previous life of
		// the item earned must not stop the top-up finishing this one.
		delete_transient( 'bettershield_guards_complete' );

		$placed   = self::place_guards( $base );
		$tokens   = $placed['tokens'];
		$written  = count( $tokens );
		$capped   = $placed['capped'];
		$failures = $placed['failures'];

		/*
		 * Nothing was placed and it was not simply an empty tree: on a host
		 * where PHP cannot write into uploads, every guard failed and this used
		 * to return success anyway, so the item read as Applied, the score
		 * credited it, and the owner was told they were covered while no
		 * protection existed on disk. The two file items beside this one
		 * already refuse in the same situation.
		 *
		 * A partial success is still a success — the guards are independent,
		 * and the note below names how many were skipped.
		 */
		if ( 0 === $written && $failures > 0 ) {
			return new \WP_Error(
				'bettershield_no_guards_written',
				sprintf(
					/* translators: %d: number of directories. */
					_n(
						'The change was not applied: the %d uploads directory could not be written to.',
						'The change was not applied: none of the %d uploads directories could be written to.',
						$failures,
						'bettershield'
					),
					$failures
				)
			);
		}

		// Nothing to place and nothing that failed means every directory was
		// already guarded — by an earlier plugin, or by this one on a site
		// that has since had its state cleared. Reported as a count it read
		// "guard files were placed in 0 uploads directories", which is a
		// sentence about work that did not happen.
		$notes = 0 === $written
			? array( __( 'Every uploads folder was already hidden.', 'bettershield' ) )
			: array(
				sprintf(
					/* translators: %d: number of directories. */
					_n( '%d uploads folder is now hidden.', '%d uploads folders are now hidden.', $written, 'bettershield' ),
					$written
				),
			);

		if ( $failures > 0 ) {
			$notes[] = sprintf(
				/* translators: %d: number of directories. */
				_n( '%d directory could not be written and was skipped.', '%d directories could not be written and were skipped.', $failures, 'bettershield' ),
				$failures
			);
		}

		if ( $capped ) {
			$notes[] = __( 'The rest are placed daily, 500 at a time.', 'bettershield' );
		}

		return array(
			'tokens' => $tokens,
			'notes'  => $notes,
		);
	}

	/**
	 * Continue where the cap stopped: the daily task's half of the promise
	 * the capped note makes. A re-apply cannot do this — the API refuses an
	 * item that is already active. Each pass is bounded exactly like
	 * apply(); each guard is ledgered and joins the item's own tokens, so
	 * undo removes every one of them.
	 */
	public static function top_up(): void {
		/*
		 * Under the same mutex every apply and revert holds. This reads the
		 * state, decides, and then writes files and ledger rows — so a revert
		 * completing in between would clear the state and sweep the open rows
		 * before these guards existed, leaving them on disk with rows nothing
		 * names. A pass that cannot take the claim skips; there is another
		 * tomorrow.
		 */
		\BetterShield\Hardening\Manager::instance()->with_state_claimed(
			static function (): void {
				self::top_up_claimed();
			}
		);
	}

	/**
	 * The current month's uploads folder and its year folder, guarded if
	 * bare: two file checks, and a pass over the year's few folders only
	 * when one of them has no guard. Only folders inside uploads: with
	 * year/month folders switched off, the "month" is the uploads folder
	 * itself, and its parent is not this item's to touch.
	 *
	 * @return array{tokens: string[], failures: int}
	 */
	private static function guard_this_month(): array {
		$uploads = wp_get_upload_dir();
		$base    = wp_normalize_path( untrailingslashit( (string) $uploads['basedir'] ) );
		$month   = wp_normalize_path( untrailingslashit( (string) $uploads['path'] ) );
		$placed  = array(
			'tokens'   => array(),
			'failures' => 0,
		);

		foreach ( array( dirname( $month ), $month ) as $dir ) {
			if ( ! str_starts_with( $dir, trailingslashit( $base ) ) || ! is_dir( $dir ) || is_file( $dir . '/index.php' ) ) {
				continue;
			}

			$pass                = self::place_guards( $dir );
			$placed['tokens']    = array_merge( $placed['tokens'], $pass['tokens'] );
			$placed['failures'] += $pass['failures'];
		}

		return $placed;
	}

	private static function top_up_claimed(): void {
		if ( ! \BetterShield\Hardening\Manager::instance()->is_active( 'directory_browsing' ) ) {
			return;
		}

		// Once a pass finds nothing bare, the daily walk of the whole tree (a
		// stat per entry, large on big media libraries) rests for a week
		// instead of re-confirming "complete" every day forever. It cannot
		// rest blind, though: core makes the month's folder the first time
		// something asks for it, which can be after that pass, and plugins
		// make folders of their own at any time. The month's folder and its
		// year are looked at every day, and the week brings the rest in.
		if ( false !== get_transient( 'bettershield_guards_complete' ) ) {
			self::record_continued( self::guard_this_month() );

			return;
		}

		$uploads = wp_get_upload_dir();
		$base    = untrailingslashit( (string) $uploads['basedir'] );

		if ( ! is_dir( $base ) ) {
			return;
		}

		$placed = self::place_guards( $base );

		/*
		 * Read from the pass that just ran rather than by walking the tree a
		 * second time: a pass that was not capped saw every bare directory
		 * there was, and if none of them refused the write then none of them
		 * is bare now. The second walk cost a full pass over a media library
		 * to learn what this one had already established.
		 */
		if ( ! $placed['capped'] && 0 === $placed['failures'] ) {
			set_transient( 'bettershield_guards_complete', '1', WEEK_IN_SECONDS );
		}

		self::record_continued( $placed );
	}

	/**
	 * Guards the daily task placed, in the activity log as the item's own
	 * continuation, whichever pass placed them: the month's folder gets
	 * the same line the full walk does.
	 *
	 * Nothing to attach to the item's state: every guard is ledgered under
	 * this item's own action, and revert already sweeps every open ledger
	 * row for the item after restoring the recorded tokens — so these come
	 * off with the same one undo. Writing them into the shared, autoloaded
	 * state option instead grew it without bound on a large tree and raced
	 * the owner's own apply and revert.
	 *
	 * @param array{tokens: string[], failures: int} $placed What the pass placed.
	 */
	private static function record_continued( array $placed ): void {
		if ( array() === $placed['tokens'] ) {
			return;
		}

		\BetterShield\Events\Writer::instance()->record(
			'hardening_applied',
			\BetterShield\Events\Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'directory_browsing',
				'context'     => array(
					'continued' => true,
					'guards'    => count( $placed['tokens'] ),
					'failures'  => $placed['failures'],
				),
			)
		);
	}

	/**
	 * @param array<string, mixed> $state
	 * @return true|array{notes: string[]}|\WP_Error
	 */
	public static function revert( array $state ) {
		// Each guard stands alone, so one somebody replaced is left to them
		// and the rest still go.
		return FileTokens::restore( $state, true );
	}

	/**
	 * Folders this item guarded that are bare again: the guard it placed and
	 * recorded is gone, and nothing else stands in for it.
	 *
	 * Read from the item's own ledger rows rather than from a walk for bare
	 * folders. A folder a plugin made after the last pass, a subsite's first
	 * upload or the new month's folder was never guarded, so it is not a
	 * guard somebody removed; the top-up's business, not a finding. A folder
	 * that went away with its guard leaves nothing to list.
	 *
	 * @param int $limit Stop once this many are found.
	 * @return string[]
	 */
	public static function removed_guards( int $limit = 1 ): array {
		$found = array();

		foreach ( \BetterShield\Undo\Ledger::open_states( self::ACTION, self::MAX_CHECKED ) as $state ) {
			$path = (string) ( $state['path'] ?? '' );
			$dir  = dirname( $path );

			if ( '' === $path || is_file( $path ) || ! is_dir( $dir ) || is_file( $dir . '/index.html' ) ) {
				continue;
			}

			$found[] = $dir;

			if ( count( $found ) >= $limit ) {
				break;
			}
		}

		return $found;
	}

	/**
	 * Directories under uploads, to the covered depth, that have no index
	 * file of their own. Sorted for a stable apply order.
	 *
	 * A caller that can only act on so many says so, and the walk stops when
	 * it has that many — a directory read per entry is the expensive part of
	 * this item on a large media library, and one nobody will look at is one
	 * nobody should pay for.
	 *
	 * @param int|null $limit Stop once this many are found; null walks it all.
	 * @return string[]
	 */
	public static function bare_directories( string $base, ?int $limit = null ): array {
		$root = realpath( $base );
		if ( false === $root || ! is_dir( $root ) ) {
			return array();
		}
		$root = wp_normalize_path( $root );
		$seen = array();
		$found = array();
		$queue = array(
			array(
				'path'  => $base,
				'depth' => 0,
			),
		);

		while ( array() !== $queue ) {
			if ( null !== $limit && count( $found ) >= $limit ) {
				break;
			}

			$entry = array_shift( $queue );
			$resolved = realpath( $entry['path'] );
			if ( false === $resolved || ( $entry['depth'] > 0 && is_link( $entry['path'] ) ) ) {
				continue;
			}
			$resolved = wp_normalize_path( $resolved );
			if ( isset( $seen[ $resolved ] ) || ( $resolved !== $root && ! str_starts_with( $resolved, trailingslashit( $root ) ) ) ) {
				continue;
			}
			$seen[ $resolved ] = true;

			if ( ! is_file( $entry['path'] . '/index.php' ) && ! is_file( $entry['path'] . '/index.html' ) ) {
				$found[] = $entry['path'];
			}

			if ( $entry['depth'] >= self::DEPTH ) {
				continue;
			}

			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a directory this process may not list is one with nothing to report, not a warning to write into a log.
			foreach ( (array) @scandir( $entry['path'] ) as $name ) {
				if ( '.' === $name || '..' === $name || is_link( $entry['path'] . '/' . $name ) || ! is_dir( $entry['path'] . '/' . $name ) ) {
					continue;
				}

				$queue[] = array(
					'path'  => $entry['path'] . '/' . $name,
					'depth' => $entry['depth'] + 1,
				);
			}
		}

		sort( $found );

		return $found;
	}
}
