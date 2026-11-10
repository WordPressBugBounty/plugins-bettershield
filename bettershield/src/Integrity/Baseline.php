<?php
/**
 * "Is this what it was" — for the code no publisher answers for.
 *
 * The manifest comparison asks whether a file matches what its publisher
 * shipped. For drop-ins, must-use plugins and the theme there is no publisher
 * answer to ask for, so this asks the only question that can be asked: is
 * this file what it was the last time anybody looked?
 *
 * That is a weaker claim and the screen says so. It is also the only claim
 * available for the three locations where persistence actually hides.
 *
 * **The first look is never a finding**, with one exception. A baseline that
 * reported everything as changed the moment it was taken would be reporting the
 * act of taking it. The exception is a configuration file nothing in WordPress
 * ever writes, which is an arrival rather than a first sight once this site's
 * configuration has been recorded before — `Unpublished::reports_first_sight()`
 * names them.
 *
 * **An update is not a change, and a version header is not an update.** A
 * theme carries a version, and when WordPress installs a new one every file
 * moves with it, so the baseline is retaken quietly and nothing is reported —
 * three hundred altered files because somebody pressed Update is how a
 * security tool teaches people to ignore it. But the version is a line in the
 * theme's own `style.css`, and whoever can edit `functions.php` can edit that
 * line in the same sitting. So a moved version counts as an update only when
 * the activity log holds the update itself: the row the upgrader hook records
 * for this location, no earlier than the baseline was last taken. Without it
 * the bump is one more edit — every changed file is reported exactly as it
 * would be at the old version, and the baseline keeps the version it knew
 * until an update WordPress performed moves it. Drop-ins, must-use plugins and
 * the configuration files at the site root have no version, so every change to
 * them is reported; they are the files nobody should be editing quietly.
 *
 * **What is gone is a finding too.** The slices a location is compared in are
 * cut from a listing of its disk, so a deleted file is in none of them; what
 * was recorded and the walk no longer finds is settled once the last slice is
 * in. A file that is there but cannot be read is a different fact from one
 * that is gone, and is said as one.
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

final class Baseline {

	/** Location => when it finished taking the version it holds. See `version_taken_at()`. */
	public const VERSION_TAKEN_OPTION = 'bettershield_integrity_version_taken';

	/**
	 * Location => the quiet decision reached for it, while a comparison works
	 * through it. See `decide()`.
	 */
	public const QUIET_OPTION = 'bettershield_integrity_quiet_hold';

	/** Location => the unconfirmed version it has already been checked at once. */
	public const UNCONFIRMED_OPTION = 'bettershield_integrity_unconfirmed_checked';

	/**
	 * Compare one slice of a location against what was recorded, and record
	 * what was not.
	 *
	 * `$first` and `$updated` are answers about the whole location, not about
	 * this slice, so a caller comparing a location across several slices has to
	 * decide them once and pass the same pair every time — see `status_of()`.
	 * `$complete` says whether this slice is the location's last, which is when
	 * what was recorded and is no longer on disk can be settled. Left out, all
	 * three are worked out here, which is the right answer only when the whole
	 * location is compared in one call.
	 *
	 * @param array<string, mixed> $target
	 * @param string[]             $slice    Relative paths to look at now.
	 * @param bool|null            $first    Whether this location has never been recorded.
	 * @param bool|null            $updated  Whether WordPress has installed a new version of it since.
	 * @param bool|null            $complete Whether this slice finishes the location.
	 * `updated` names what an update brought, by path only: files the update
	 * added and files whose hash it changed. Those are re-recorded quietly like
	 * everything else an update moves, and are never a finding here; they are
	 * listed so the caller can say, once, what the new version contains that
	 * the old one did not.
	 *
	 * @return array{checked: int, modified: string[], added: string[], removed: string[], unreadable: string[], hashes: array<string, array{before: string|null, after: string|null, size: int|null}>, updated: array{added: string[], changed: string[]}}
	 */
	public static function compare( array $target, array $slice, ?bool $first = null, ?bool $updated = null, ?bool $complete = null ): array {
		$context  = (string) $target['context'];
		$slug     = (string) $target['slug'];
		$recorded = self::recorded_for( $context, $slug );

		if ( null === $first || null === $updated ) {
			$decided = self::status_of( $target );
			$first   = $first ?? $decided['first'];
			$updated = $updated ?? $decided['updated'];
		}

		$complete = $complete ?? true;

		// Nothing was recorded for this location yet, or WordPress has
		// installed a new version of it: what is on disk is recorded as it
		// stands, and none of it is a finding.
		$quiet = $first || $updated;

		/*
		 * The version the rows are written under. A moved version that no
		 * update accounts for is not learned: the rows keep the version
		 * WordPress last installed, so the header stays a line in a file rather
		 * than a way of telling this baseline what to expect.
		 */
		$version = $quiet ? (string) $target['version'] : self::recorded_version( $context, $slug );

		$result = array(
			'checked'    => 0,
			'modified'   => array(),
			'added'      => array(),
			'removed'    => array(),
			'unreadable' => array(),
			// The hashes behind the lists above, so the caller can record what
			// a file was and what it is now. A parallel map rather than a
			// change of shape: the lists are what every reader wants, and what
			// changed is what one of them wants as well.
			'hashes'     => array(),
			'updated'    => array(
				'added'   => array(),
				'changed' => array(),
			),
		);

		foreach ( $slice as $relative ) {
			$absolute = $target['root'] . '/' . $relative;
			$hash     = Manifest::hash_file( $absolute, 'sha256' );
			$path     = (string) $target['prefix'] . $relative;
			$known    = $recorded[ $path ] ?? null;

			++$result['checked'];

			if ( null === $hash ) {
				/*
				 * Null for a file that is absent and for one that is present
				 * but not readable by this process, and the two are different
				 * facts: a permissions problem is fixed by fixing permissions,
				 * and only the absence changes what this baseline knows.
				 *
				 * A file that cannot be read is said whatever the location's
				 * status. It is not a change to the site; it is a file the
				 * check cannot see and so cannot watch. Its row, where there is
				 * one, stays: what the file was is still the right thing to
				 * hold it against once it can be read again.
				 */
				if ( file_exists( $absolute ) ) {
					$result['unreadable'][]        = $relative;
					$result['hashes'][ $relative ] = self::absent( $known );
					continue;
				}

				// Listed by the walk, and gone before it was hashed.
				if ( null !== $known ) {
					self::unrecord( $target, $relative );

					if ( ! $quiet ) {
						$result['removed'][]           = $relative;
						$result['hashes'][ $relative ] = self::absent( $known );
					}
				}

				continue;
			}

			$size = (int) @filesize( $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- size is a detail, absence is handled above.

			if ( $quiet ) {
				// An update, not a first look: what it brought is worth naming,
				// though none of it is a finding.
				if ( $updated && ! $first ) {
					if ( null === $known ) {
						$result['updated']['added'][] = $relative;
					} elseif ( ! hash_equals( $known, $hash ) ) {
						$result['updated']['changed'][] = $relative;
					}
				}

				self::record( $target, $relative, $hash, $size, $version );
				continue;
			}

			if ( null === $known ) {
				/*
				 * A file in a `vendor` folder this location's baseline was
				 * taken without, met on the first walk that enters it. Its
				 * first look is taken in silence, as the location's own was;
				 * from the next walk on, a file arriving there is reported
				 * like any other. See `Unpublished::DEPENDENCIES_OPTION`.
				 */
				if ( ! empty( $target['first_look'] ) && Unpublished::in_dependency_folder( $relative ) ) {
					self::record( $target, $relative, $hash, $size, $version );
					continue;
				}

				// The same once for a name the walk used to leave out, in a
				// location already baselined without it. See
				// `Unpublished::NAMES_OPTION`.
				if ( ! empty( $target['new_names'] ) && Unpublished::newly_walked( $relative ) ) {
					self::record( $target, $relative, $hash, $size, $version );
					continue;
				}

				$result['added'][]              = $relative;
				$result['hashes'][ $relative ] = array(
					'before' => null,
					'after'  => $hash,
					'size'   => $size,
				);
				self::record( $target, $relative, $hash, $size, $version );
				continue;
			}

			if ( ! hash_equals( $known, $hash ) ) {
				$result['modified'][]           = $relative;
				$result['hashes'][ $relative ] = array(
					'before' => $known,
					'after'  => $hash,
					'size'   => $size,
				);
				self::record( $target, $relative, $hash, $size, $version );
			}
		}

		if ( $complete ) {
			$result = self::sweep( $target, $recorded, $quiet, $result );
		}

		if ( $complete && $quiet ) {
			self::note_version_taken( $context, $slug );
		}

		return $result;
	}

	/**
	 * What was recorded for a location and its walk no longer lists.
	 *
	 * The slices are cut from a listing of the disk, so a deleted file is in
	 * none of them: the only way to notice it is to ask, once the location has
	 * been walked, what the baseline knows that the walk did not find. A file
	 * that is gone is said once and forgotten, so the next walk does not find
	 * it missing again; one that is still there and cannot be read is said and
	 * kept, for the reason given above; one that is there and readable was
	 * left out by the walk on purpose — a directory it never enters — and is
	 * nothing to report. A location the walk could not finish is left alone
	 * entirely: the files past its cap were not looked at, and calling them
	 * gone would be reporting the cap.
	 *
	 * @param array<string, mixed>  $target
	 * @param array<string, string> $recorded What the location's rows said before this call.
	 * @param array<string, mixed>  $result
	 * @return array<string, mixed>
	 */
	private static function sweep( array $target, array $recorded, bool $quiet, array $result ): array {
		if ( ! empty( $target['truncated'] ) ) {
			return $result;
		}

		$prefix = (string) $target['prefix'];
		$walked = array();

		foreach ( (array) ( $target['files'] ?? array() ) as $relative ) {
			$walked[ $prefix . (string) $relative ] = true;
		}

		foreach ( $recorded as $path => $known ) {
			if ( isset( $walked[ $path ] ) || ( '' !== $prefix && 0 !== strpos( $path, $prefix ) ) ) {
				continue;
			}

			$relative = substr( $path, strlen( $prefix ) );
			$absolute = $target['root'] . '/' . $relative;

			if ( file_exists( $absolute ) ) {
				if ( null === Manifest::hash_file( $absolute, 'sha256' ) ) {
					$result['unreadable'][]        = $relative;
					$result['hashes'][ $relative ] = self::absent( $known );
				}

				continue;
			}

			self::unrecord( $target, $relative );

			if ( ! $quiet ) {
				$result['removed'][]           = $relative;
				$result['hashes'][ $relative ] = self::absent( $known );
			}
		}

		return $result;
	}

	/**
	 * The hash record for a file there is no longer a hash of: what it was,
	 * and nothing after.
	 *
	 * @return array{before: string|null, after: null, size: null}
	 */
	private static function absent( ?string $known ): array {
		return array(
			'before' => $known,
			'after'  => null,
			'size'   => null,
		);
	}

	/**
	 * Whether a location has been looked at before, and whether WordPress has
	 * installed a new version of it since — both decided for the location as
	 * a whole.
	 *
	 * A location larger than one chunk is compared across several calls, and
	 * the first of those calls records what it saw. Answered afresh per call,
	 * both flip after that first chunk: the location is no longer new, and its
	 * recorded version is already the one on disk. Every file after the first
	 * chunk then reads as a change nobody made.
	 *
	 * A moved version is half of an update. The other half is the upgrader's
	 * own record of installing it, and without that the version is a line in
	 * a file that moved with the rest of them — see `was_updated()`.
	 *
	 * @param array<string, mixed> $target
	 * @return array{first: bool, updated: bool, moved: bool, previous: string}
	 */
	public static function status_of( array $target ): array {
		$context = (string) $target['context'];
		$slug    = (string) $target['slug'];
		$first   = ! self::exists_for( $context, $slug );

		/*
		 * A file whose arrival is somebody's act is reported on the run that
		 * first meets it and recorded in the same pass, so the run after it is
		 * quiet. Held back until configuration has been recorded here before:
		 * on the run that takes the very first baseline, an ordinary install
		 * would otherwise be reported as an arrival. See
		 * `Unpublished::reports_first_sight()`.
		 *
		 * Asked of the context rather than of `wp-config.php` specifically.
		 * The question is whether this site's configuration has been recorded
		 * before, which is a fact about the context; asked of one slug, an
		 * install whose `wp-config.php` cannot be located from here — the
		 * layouts that keep it outside the tree — never satisfied it, so the
		 * arrival was never reported at all and a `.user.ini` planting an
		 * `auto_prepend_file` was baselined in silence. On a site with no
		 * configuration recorded yet the answer is still no, which is right:
		 * the first run records and the second reports.
		 */
		if ( $first
			&& Unpublished::reports_first_sight( $context, $slug )
			&& self::context_exists( Unpublished::CONTEXT_CONFIG )
		) {
			$first = false;
		}

		$version = (string) $target['version'];
		$moved   = ! $first && '' !== $version && $version !== self::recorded_version( $context, $slug );

		$updated = $moved && self::was_updated( $target );

		return array(
			'first'    => $first,
			'updated'  => $updated,
			// The header says a new version and nothing confirms it. A plugin
			// or theme only: nothing else here has a version to move.
			// Said for one pass per version: what came with the moved header is
			// quieter, and what comes after it is an ordinary change.
			'moved'    => $moved && ! $updated && in_array( $context, array( Unpublished::CONTEXT_THEME, Unpublished::CONTEXT_UNLISTED ), true ) && ! self::unconfirmed_checked( $target ),
			'previous' => $first ? '' : self::recorded_version( $context, $slug ),
		);
	}

	/**
	 * The location's status for a run reaching it, held where it is a quiet one.
	 *
	 * The first slice of a first look or an update rewrites rows that change
	 * the answer, and a run's cursor holds that decision only between ticks.
	 * A killed request lost it, and a scoped run between two ticks never had
	 * it: either one decided again, with rows half rewritten, and reported the
	 * rest of the location. So a quiet decision is written down before the
	 * first slice, for any run reaching this version, until the last slice.
	 * A decision that isn't quiet comes out the same however often it's asked.
	 *
	 * @param array<string, mixed> $target
	 * @return array{first: bool, updated: bool, moved: bool, previous: string}
	 */
	public static function decide( array $target ): array {
		$held = self::held( $target );

		if ( null !== $held ) {
			return $held;
		}

		self::take_over_compared_rows( $target );
		self::forget_old_spelling( $target );

		$status = self::status_of( $target );

		if ( $status['first'] || $status['updated'] ) {
			$holds = get_option( self::QUIET_OPTION, array() );
			$holds = is_array( $holds ) ? $holds : array();

			$holds[ $target['context'] . '|' . $target['slug'] ] = array( 'version' => (string) $target['version'] ) + $status;

			update_option( self::QUIET_OPTION, $holds, false );
		}

		return $status;
	}

	/**
	 * Hold a plugin with no checksums for this version to what it was last
	 * compared at. Those rows stay under the checksum pass's context, so read
	 * by this one's, a plugin that had checksums looked new on every run and
	 * went in unseen. Rows are one per path, so this can't collide.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function take_over_compared_rows( array $target ): void {
		global $wpdb;

		if ( Unpublished::CONTEXT_UNLISTED !== (string) $target['context'] || Unpublished::is_single_file( (string) $target['slug'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table, once per location per run.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET context = %s WHERE site_id = 0 AND context = %s AND slug = %s AND algo = 'sha256'",
				Schema::table( 'integrity_baseline' ),
				Unpublished::CONTEXT_UNLISTED,
				Manifest::CONTEXT_PLUGIN,
				(string) $target['slug']
			)
		);
	}

	/**
	 * Drop rows a folder's lowercased name left behind. A disk that ignores
	 * case found those files under it, and read against the real name every
	 * file would be an arrival and every row a removal. Only for a name that
	 * lowercasing changes, so the location gets one quiet first look.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function forget_old_spelling( array $target ): void {
		global $wpdb;

		$slug = (string) $target['slug'];

		if ( Unpublished::CONTEXT_UNLISTED !== (string) $target['context'] || sanitize_key( $slug ) === $slug || Unpublished::is_single_file( $slug ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table, once per location per run.
		$wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE site_id = 0 AND context = %s AND slug = %s AND BINARY path NOT LIKE %s',
				Schema::table( 'integrity_baseline' ),
				Unpublished::CONTEXT_UNLISTED,
				$slug,
				$wpdb->esc_like( (string) $target['prefix'] ) . '%'
			)
		);
	}

	/**
	 * The quiet decision held for a location at this version, or null.
	 *
	 * @param array<string, mixed> $target
	 * @return array{first: bool, updated: bool, moved: bool, previous: string}|null
	 */
	public static function held( array $target ): ?array {
		$holds = get_option( self::QUIET_OPTION, array() );
		$hold  = is_array( $holds ) ? ( $holds[ $target['context'] . '|' . $target['slug'] ] ?? null ) : null;

		if ( ! is_array( $hold ) || (string) ( $hold['version'] ?? '' ) !== (string) $target['version'] ) {
			return null;
		}

		return array(
			'first'    => ! empty( $hold['first'] ),
			'updated'  => ! empty( $hold['updated'] ),
			'moved'    => false,
			'previous' => (string) ( $hold['previous'] ?? '' ),
		);
	}

	/**
	 * A location's last slice is done: what was held has been recorded.
	 *
	 * @param array<string, mixed> $target
	 */
	public static function release_hold( array $target ): void {
		self::forget_entry( self::QUIET_OPTION, (string) $target['context'], (string) $target['slug'] );
	}

	/**
	 * Whether WordPress itself installed the version now on disk.
	 *
	 * The version is read from the location's own header, and whoever can
	 * edit its files can edit that line, so a moved version proves nothing on
	 * its own. The upgrader hook records every install and update in the
	 * activity log as it performs it, and that row is the other half: an
	 * update event for this location, no earlier than the baseline was last
	 * took its version, naming the version on disk. The bound is the baseline's
	 * own clock rather than a window of hours — a run that reaches this
	 * location days after the update still has to read it as one, and an update
	 * this baseline has already taken in must not vouch for an edit made after it.
	 *
	 * At whole seconds, because the log stamps its rows at that precision and
	 * the baseline at milliseconds.
	 *
	 * An install counts as well as an update. "Replace current with uploaded"
	 * and `wp plugin install --force` overwrite the folder through the
	 * installer, so the upgrader logs them as installed; read as edits, every
	 * file the new version changed was reported as tampering. Only a row that
	 * names this location does: the refused first pass of a Replace names
	 * nothing.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function was_updated( array $target ): bool {
		global $wpdb;

		$context = (string) $target['context'];
		$slug    = (string) $target['slug'];

		if ( Unpublished::CONTEXT_THEME === $context ) {
			$events = array( 'theme_updated', 'theme_installed' );
			$object = $wpdb->esc_like( $slug );
		} elseif ( Unpublished::CONTEXT_UNLISTED === $context ) {
			// The upgrader names a plugin by its main file, and the main file
			// is not always named after its folder. A plugin that is one file
			// is named by that file.
			$events = array( 'plugin_updated', 'plugin_installed' );
			$object = Unpublished::is_single_file( $slug ) ? $wpdb->esc_like( $slug ) : $wpdb->esc_like( $slug ) . '/%';
		} else {
			return false;
		}

		if ( '' === $slug ) {
			return false;
		}

		$since = self::version_taken_at( $context, $slug );

		if ( '' === $since ) {
			return false;
		}

		/*
		 * On a network, the upgrader's row is where the update ran, usually
		 * the main site, which a subsite's own read can't see. Only someone
		 * who may update plugins writes these, so a row from any site counts.
		 */
		$sources = array( array( Schema::table( 'events' ), Schema::site_where( 'events' ) ) );

		if ( is_multisite() ) {
			$sources[] = array( Schema::network_table( 'events' ), '1 = 1' );
		}

		$rows = array();

		foreach ( $sources as list( $table, $where ) ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- plugin-owned table; the predicate is built from an internal name.
			$rows = array_merge(
				$rows,
				(array) $wpdb->get_col(
					$wpdb->prepare(
						'SELECT context FROM %i WHERE ' . $where . ' AND event_type IN (%s, %s) AND object_id LIKE %s AND occurred_at >= %s ORDER BY id DESC LIMIT 50',
						$table,
						$events[0],
						$events[1],
						$object,
						$since
					)
				)
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		}

		foreach ( $rows as $row ) {
			$saved = json_decode( (string) $row, true );
			$to    = is_array( $saved ) ? (string) ( $saved['to'] ?? '' ) : '';

			// A row that names no version vouches for whatever is on disk.
			if ( '' === $to || (string) $target['version'] === $to ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * When this location's baseline took the version it holds, at whole
	 * seconds. Not when a row was last written: a file taken in or a change
	 * recorded under the old version moved that past the update it should
	 * have accepted. Empty when nothing was recorded.
	 *
	 * Before this was kept, the oldest row stands in: every row was written
	 * when the location took its version, and only changed files since.
	 */
	private static function version_taken_at( string $context, string $slug ): string {
		global $wpdb;

		$taken = get_option( self::VERSION_TAKEN_OPTION, array() );
		$at    = is_array( $taken ) ? (int) ( $taken[ $context . '|' . $slug ] ?? 0 ) : 0;

		if ( $at > 0 ) {
			return Time::stamp( $at );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- as above.
		$oldest = (string) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT MIN(recorded_at) FROM %i WHERE site_id = 0 AND context = %s AND slug = %s',
				Schema::table( 'integrity_baseline' ),
				$context,
				$slug
			)
		);

		$moment = '' === $oldest ? false : strtotime( $oldest . ' UTC' );

		return false === $moment ? '' : Time::stamp( $moment );
	}

	/**
	 * Whether a location has had its one quieter pass at this unconfirmed version.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function unconfirmed_checked( array $target ): bool {
		$checked = get_option( self::UNCONFIRMED_OPTION, array() );

		return is_array( $checked ) && (string) $target['version'] === ( $checked[ $target['context'] . '|' . $target['slug'] ] ?? null );
	}

	/**
	 * A location finished its comparison at a version nothing confirms.
	 *
	 * @param array<string, mixed> $target
	 */
	public static function note_unconfirmed_checked( array $target ): void {
		$checked = get_option( self::UNCONFIRMED_OPTION, array() );
		$checked = is_array( $checked ) ? $checked : array();

		$checked[ $target['context'] . '|' . $target['slug'] ] = (string) $target['version'];

		update_option( self::UNCONFIRMED_OPTION, $checked, false );
	}

	/** Forget a location's entry in one of the per-location options. */
	private static function forget_entry( string $option, string $context, string $slug ): void {
		$map = get_option( $option, array() );

		if ( is_array( $map ) && isset( $map[ $context . '|' . $slug ] ) ) {
			unset( $map[ $context . '|' . $slug ] );
			update_option( $option, $map, false );
		}
	}

	/** Hold the moment a location finished taking a version. A plugin or theme only. */
	private static function note_version_taken( string $context, string $slug ): void {
		if ( ! in_array( $context, array( Unpublished::CONTEXT_THEME, Unpublished::CONTEXT_UNLISTED ), true ) ) {
			return;
		}

		$taken = get_option( self::VERSION_TAKEN_OPTION, array() );
		$taken = is_array( $taken ) ? $taken : array();

		$taken[ $context . '|' . $slug ] = time();

		update_option( self::VERSION_TAKEN_OPTION, $taken, false );
		self::forget_entry( self::UNCONFIRMED_OPTION, $context, $slug );
	}

	/**
	 * Whether this location has ever been recorded.
	 */
	public static function exists_for( string $context, string $slug ): bool {
		return array() !== self::recorded_for( $context, $slug );
	}

	/**
	 * Whether this check has recorded anything at all in one context here.
	 *
	 * A fact about the context rather than about any location in it: it is
	 * what tells the run that takes the very first baseline from every run
	 * after it, and no single location can answer that for a context whose
	 * members differ from site to site.
	 */
	public static function context_exists( string $context ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table, asked once per location per scan tick.
		return null !== $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM %i WHERE site_id = 0 AND context = %s LIMIT 1',
				Schema::table( 'integrity_baseline' ),
				$context
			)
		);
	}

	/**
	 * Everything recorded for one location, keyed by stored path.
	 *
	 * @return array<string, string>
	 */
	public static function recorded_for( string $context, string $slug ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table, read once per location per scan tick.
		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT path, file_hash FROM %i WHERE site_id = 0 AND context = %s AND slug = %s',
				Schema::table( 'integrity_baseline' ),
				$context,
				$slug
			)
		);

		$out = array();

		foreach ( $rows as $row ) {
			$out[ (string) $row->path ] = (string) $row->file_hash;
		}

		return $out;
	}

	/**
	 * The version this location was recorded under.
	 *
	 * Ordered rather than left to the storage engine: without it "the one row"
	 * is whichever the index hands back first, which is not the same row before
	 * and after a chunk of the same location has been rewritten.
	 */
	public static function recorded_version( string $context, string $slug ): string {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- as above.
		return (string) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT version FROM %i WHERE site_id = 0 AND context = %s AND slug = %s ORDER BY id ASC LIMIT 1',
				Schema::table( 'integrity_baseline' ),
				$context,
				$slug
			)
		);
	}

	/**
	 * A must-use plugin file this plugin or its add-on has just written or
	 * removed itself, recorded as it now stands, so the next check doesn't
	 * report our own write as an arrival (#2682).
	 *
	 * The bytes on disk are recorded, not the name: a later edit to the file
	 * by anyone else is still reported. Only a file directly in the folder.
	 * Where the folder has no baseline yet, the next check would either take
	 * its first look in silence, and then there is nothing to record, or
	 * report every file in it as an arrival, and then this file is recorded
	 * as the folder's first entry so only the others are.
	 *
	 * A removal also closes what was open against the file: with the file
	 * gone the folder may be empty, and an empty folder is never walked, so
	 * no check would close it.
	 *
	 * There is no filter and no route to this: only code that has just
	 * written the file itself calls it.
	 */
	public static function expect_own_file( string $name ): void {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) || basename( $name ) !== $name || '' === $name || '.' === $name[0] ) {
			return;
		}

		$target = array(
			'context' => Unpublished::CONTEXT_MUPLUGIN,
			'slug'    => 'mu-plugins',
			'version' => '',
			'prefix'  => 'wp-content/mu-plugins/',
		);
		$path   = trailingslashit( WPMU_PLUGIN_DIR ) . $name;
		$hash   = Manifest::hash_file( $path, 'sha256' );

		if ( null === $hash ) {
			self::unrecord( $target, $name );
			self::close_open_addition( (string) $target['prefix'] . $name );

			return;
		}

		if ( self::status_of( $target )['first'] ) {
			return;
		}

		self::record( $target, $name, $hash, (int) @filesize( $path ), self::recorded_version( Unpublished::CONTEXT_MUPLUGIN, 'mu-plugins' ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the file was hashed a line above; if it went since, a size of 0 is recorded and the next check reports it.
	}

	/**
	 * Close an open "added" row for a file that is no longer there, as a
	 * check that walked its folder would. The finding stays in the activity
	 * log.
	 */
	private static function close_open_addition( string $path ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own changes table, one indexed update.
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'restored' WHERE site_id = 0 AND path_hash = %s AND change_type = 'added' AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				hash( 'sha256', $path )
			)
		);
	}

	/**
	 * Forget a location entirely — a theme switched away from, a drop-in
	 * removed. Its baseline describes something that is no longer there.
	 */
	public static function forget( string $context, string $slug ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- as above.
		$wpdb->delete(
			Schema::table( 'integrity_baseline' ),
			array(
				'site_id' => 0,
				'context' => $context,
				'slug'    => $slug,
			)
		);

		self::forget_entry( self::VERSION_TAKEN_OPTION, $context, $slug );
		self::forget_entry( self::UNCONFIRMED_OPTION, $context, $slug );
		self::forget_entry( self::QUIET_OPTION, $context, $slug );
	}

	/**
	 * @param array<string, mixed> $target
	 * @param string               $version The version the row is written under — see `compare()`.
	 */
	private static function record( array $target, string $relative, string $hash, int $size, string $version ): void {
		global $wpdb;

		$path = (string) $target['prefix'] . $relative;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (site_id, path_hash, path, context, slug, version, algo, file_hash, file_size, recorded_at)
				 VALUES (0, %s, %s, %s, %s, %s, %s, %s, %d, %s)
				 ON DUPLICATE KEY UPDATE version = VALUES(version), file_hash = VALUES(file_hash), file_size = VALUES(file_size), recorded_at = VALUES(recorded_at)',
				Schema::table( 'integrity_baseline' ),
				hash( 'sha256', $path ),
				$path,
				(string) $target['context'],
				(string) $target['slug'],
				$version,
				'sha256',
				$hash,
				$size,
				( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' )
			)
		);
	}

	/**
	 * This plugin has just written a watched configuration file, so the check
	 * doesn't report that as a change somebody made (#2742). Only where the
	 * file matched the baseline just before the write: moved forward from
	 * anything else, someone else's edit would be taken in with it.
	 *
	 * @param string      $path   The file, as written.
	 * @param string|null $before Its hash just before the write.
	 */
	public static function follow_own_write( string $path, ?string $before ): void {
		$name = basename( $path );

		if ( null === $before || ! in_array( $name, array( '.htaccess', Unpublished::SLUG_WP_CONFIG ), true ) ) {
			return;
		}

		$watched = '.htaccess' === $name ? \BetterShield\Files\Guarded::htaccess_path() : \BetterShield\Files\Guarded::wp_config_path();

		if ( null === $watched || realpath( $watched ) !== realpath( $path ) ) {
			return;
		}

		$known = self::recorded_for( Unpublished::CONTEXT_CONFIG, $name )[ $name ] ?? null;
		$hash  = Manifest::hash_file( $path, 'sha256' );

		if ( null === $known || null === $hash || ! hash_equals( $known, $before ) ) {
			return;
		}

		self::take_in(
			array(
				'context' => Unpublished::CONTEXT_CONFIG,
				'slug'    => $name,
				'prefix'  => '',
			),
			$name,
			$hash,
			(int) @filesize( $path ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the file was just hashed; a size of 0 is only a detail.
		);

		if ( Unpublished::SLUG_WP_CONFIG === $name ) {
			KnownWrites::remember_config( $path );
		}
	}

	/**
	 * Hold one file to the contents it has now, under the version the
	 * location is recorded at, so taking in a file never moves that version.
	 *
	 * @param array<string, mixed> $target
	 */
	public static function take_in( array $target, string $relative, string $hash, int $size ): void {
		self::record( $target, $relative, $hash, $size, self::recorded_version( (string) $target['context'], (string) $target['slug'] ) );
	}

	/**
	 * Put one row back to what it was before a file was taken in, or remove
	 * it where there was none, so the next check reports the file. Only while
	 * the row still holds what was taken in.
	 *
	 * @param string      $path  From the site root, as the row names it.
	 * @param string      $taken The hash that was taken in.
	 * @param string|null $prior The hash before it, if any.
	 */
	public static function put_back( string $context, string $slug, string $path, string $taken, ?string $prior ): void {
		global $wpdb;

		$known = self::recorded_for( $context, $slug )[ $path ] ?? null;

		if ( null === $known || ! hash_equals( $known, $taken ) ) {
			return;
		}

		$where = array(
			'site_id'   => 0,
			'path_hash' => hash( 'sha256', $path ),
		);

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own baseline table.
		if ( null === $prior ) {
			$wpdb->delete( Schema::table( 'integrity_baseline' ), $where );
			return;
		}

		$wpdb->update( Schema::table( 'integrity_baseline' ), array( 'file_hash' => $prior ), $where );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	}

	/**
	 * Drop one file from a location's baseline. It is gone, and a row saying
	 * what it was would have the next walk finding it missing all over again.
	 *
	 * Bounded by the location as well as the path: the path is unique across
	 * the table, and this must never reach a row another location filed.
	 *
	 * @param array<string, mixed> $target
	 */
	private static function unrecord( array $target, string $relative ): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- as above.
		$wpdb->delete(
			Schema::table( 'integrity_baseline' ),
			array(
				'site_id'   => 0,
				'path_hash' => hash( 'sha256', (string) $target['prefix'] . $relative ),
				'context'   => (string) $target['context'],
				'slug'      => (string) $target['slug'],
			)
		);
	}
}
