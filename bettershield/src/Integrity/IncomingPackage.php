<?php
/**
 * What arrived, checked against what the publisher published, before it
 * replaces what is already there.
 *
 * The file check compares a site against the official copies and can put an
 * altered file back. It runs after the fact. This is the same comparison one
 * moment earlier: an update has been downloaded and unpacked into a temporary
 * directory, and nothing has been overwritten yet, so this is the last point
 * at which "the copy that arrived is not the copy that was published" is a
 * thing somebody can be told before it becomes the site.
 *
 * **It never stops an update.** This filter can abort an install by returning
 * a `WP_Error`, and it never does — the source is handed back untouched on
 * every path, including every failure of its own. A plugin whose first promise
 * is that everything is reversible must not be the reason somebody cannot
 * patch a vulnerability, and the failure modes here are all the wrong shape
 * for blocking: a publisher who has not yet posted checksums for a version, a
 * mirror that is slow, a package legitimately built from source. Reporting is
 * useful even when it is occasionally uncertain; blocking on the same evidence
 * would not be.
 *
 * **A difference can be answered, not only reported.** The same plugin built
 * from source, or patched for one site, differs from its published copy at
 * every update for as long as it is installed — and a report that arrives at
 * high, with an alert, every time, for a reason the owner already knows is a
 * report they learn to ignore. So a difference opens a finding they can act
 * on: the paths, the hash each side offers, and the option of saying the copy
 * is theirs. The adoption names one version and every file that differed in
 * it, so it goes quiet for exactly that copy — a byte out of place, or a
 * version they have not seen, and the finding is back.
 *
 * For the same reason the signature-verification half of this idea is not
 * built. Registering hosts into `wp_signature_hosts` with softfail off makes
 * core abort a download on any key rotation, which is a hard block on the
 * update path reached through somebody else's operational mistake.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Support\Time;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class IncomingPackage {

	/**
	 * What one inspection is allowed to cost.
	 *
	 * This runs inside an update somebody is waiting on, so it is bounded by
	 * both counts rather than trusted to be small: a plugin that ships a
	 * vendor tree can be thousands of files, and hashing all of them would
	 * turn a fast update into a slow one. Past either bound the answer is
	 * "not fully checked", which is said rather than rounded to "fine".
	 */
	private const MAX_FILES = 1500;
	private const MAX_BYTES = 40000000;

	/**
	 * What one lookup, and a whole request's worth of them, may cost.
	 *
	 * The default fifteen seconds belongs to a scheduled check nobody is
	 * waiting on. Here somebody is: core itself uses three seconds off-cron
	 * for the same class of question.
	 *
	 * The ceiling is the part that matters on a bulk update. Every plugin in
	 * one is a different lookup, so a host that drops packets rather than
	 * refusing them costs the timeout again for each — and updating forty
	 * plugins is one PHP request. Past the ceiling the remaining plugins are
	 * not checked, which is the right way to fail: the update goes through
	 * either way, and the check must never be the reason one does not.
	 */
	private const FETCH_TIMEOUT = 5;
	private const MAX_SECONDS   = 20.0;

	/**
	 * Copies of a package the owner has said are their own.
	 *
	 * Keyed by slug, and each entry names one version and the hash of every
	 * file that differed in it. A plugin built from source or patched for a
	 * client differs from its published copy at every update, forever, and an
	 * owner who cannot say so learns to ignore the report — which costs the
	 * report its meaning on the day it is somebody else's code.
	 */
	public const ADOPTED_OPTION = 'bettershield_adopted_packages';

	/**
	 * The differing paths behind an open package finding, per slug.
	 *
	 * The finding itself is a row among the file changes, so the screen, the
	 * audit check and the command line all read it the way they read every
	 * other one. What has no column there is the list of paths and the hash
	 * each side offers, which is the whole of what the owner decides on — so
	 * it is kept beside the row and dropped when the row is answered.
	 */
	public const MISMATCH_OPTION = 'bettershield_package_mismatches';

	/** How a package difference is filed among the file changes. */
	public const CHANGE_TYPE = 'package_mismatch';

	/**
	 * The most differing paths one finding carries.
	 *
	 * An adoption has to name every path it covers, because a path outside the
	 * set is what raises the finding again. Past this many the honest answer is
	 * not "this is my modified copy" but "this is a different package", and the
	 * adoption says so rather than quietly covering part of it.
	 */
	private const MAX_MISMATCH_FILES = 200;

	/** How many paths a screen or a log line is given at once. */
	private const MAX_SHOWN = 10;

	/**
	 * Seconds this request has already spent looking things up.
	 *
	 * Static because the unit being bounded is the request, not the plugin:
	 * a bulk update runs every one of them inside a single PHP process.
	 */
	private static float $spent = 0.0;

	/**
	 * Plugins whose incoming package matched its published copy in full, by
	 * slug, waiting for the upgrader to say the files are in place.
	 *
	 * @var array<string, true>
	 */
	private static array $clean = array();

	public static function register(): void {
		add_filter( 'upgrader_source_selection', array( self::class, 'inspect' ), 10, 4 );
		add_filter( 'upgrader_post_install', array( self::class, 'installed' ), 10, 3 );
		// After core has cleared its plugin list, so the version read is the
		// one that landed.
		add_action( 'upgrader_process_complete', array( self::class, 'recheck_landed' ), 20, 0 );
		add_action( self::RECHECK_HOOK, array( self::class, 'recheck_now' ), 10, 2 );
	}

	/** The one-off task that carries a recheck on past one request's time. */
	public const RECHECK_HOOK = 'bettershield_recheck_landed_plugin';

	/**
	 * The plugins an install put in place on this request, by folder.
	 *
	 * @var array<string, true>
	 */
	private static array $landed = array();

	/**
	 * Compare the open file rows of each plugin installed on this request
	 * again, now.
	 *
	 * "Install it again from the directory" is what this plugin tells an
	 * owner whose files differ, and for a plugin past MAX_FILES the check
	 * above stops partway and closes nothing: every per-file row stayed open
	 * until the hourly check reached it, the finding critical meanwhile
	 * (#2086). The open rows alone are cheap to compare, so they are,
	 * whether or not the whole-package check finished.
	 */
	public static function recheck_landed(): void {
		$landed       = array_keys( self::$landed );
		self::$landed = array();

		if ( array() === $landed ) {
			return;
		}

		/*
		 * The version read must be the one that landed. Core clears its
		 * plugin list before this hook only when asked to, and an automatic
		 * update does not ask: the old version was read back, and the new
		 * files compared against the old release's list.
		 */
		wp_cache_delete( 'plugins', 'plugins' );

		// A difference about the copy an update replaced is about nothing on
		// disk now (#2145).
		self::close_outdated();

		// One request's worth across every plugin a bulk update put in place;
		// the ones not reached are handed to the task.
		$deadline = microtime( true ) + self::RECHECK_BUDGET;

		foreach ( $landed as $slug ) {
			if ( microtime( true ) >= $deadline ) {
				self::recheck_later( (string) $slug, 0 );
				continue;
			}

			try {
				self::recheck_now( (string) $slug );
			} catch ( \Throwable $e ) {
				// Never a reason to interrupt somebody's install.
				continue;
			}
		}
	}

	/** Seconds one request spends comparing the rows of plugins it installed. */
	private const RECHECK_BUDGET = 8.0;

	/**
	 * Hand a plugin's rows, from where a pass stopped, to the task.
	 *
	 * @param string $slug  The plugin's folder.
	 * @param int    $after Where to carry on from.
	 */
	private static function recheck_later( string $slug, int $after ): void {
		if ( ! wp_next_scheduled( self::RECHECK_HOOK, array( $slug, $after ) ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::RECHECK_HOOK, array( $slug, $after ) );
		}
	}

	/**
	 * One plugin's open rows compared, as far as one request's time goes,
	 * and the rest handed to a task of its own.
	 *
	 * @param string $slug  The plugin's folder.
	 * @param int    $after Where an earlier pass stopped.
	 */
	public static function recheck_now( $slug, $after = 0 ): void {
		$slug = (string) $slug;

		if ( 0 === Packages::open_rechecks( $slug ) ) {
			return;
		}

		$result = Packages::recheck( $slug, (int) $after );

		if ( is_wp_error( $result ) || $result['left'] <= 0 || $result['after'] <= 0 ) {
			return;
		}

		self::recheck_later( $slug, (int) $result['after'] );
	}

	/**
	 * Start the accounting over.
	 *
	 * The budget covers one request. A process that serves more than one — a
	 * long-running worker, a queue consumer — needs a way to say where the
	 * next one begins, or the first request's spending closes the check for
	 * the life of the process.
	 */
	public static function reset_budget(): void {
		self::$spent = 0.0;
	}

	private static function budget_seconds(): float {
		/**
		 * Filters how long one request may spend comparing incoming packages
		 * against their published copies.
		 *
		 * @param float $seconds Wall-clock ceiling across the whole request.
		 */
		return max( 1.0, (float) apply_filters( 'bettershield_incoming_budget', self::MAX_SECONDS ) );
	}

	/**
	 * Look, record, and hand the source back exactly as it arrived.
	 *
	 * @param mixed $source
	 * @param mixed $remote_source
	 * @param mixed $upgrader
	 * @param mixed $hook_extra
	 * @return mixed The source, always, whatever was found or went wrong.
	 */
	public static function inspect( $source, $remote_source = null, $upgrader = null, $hook_extra = null ) {
		try {
			if ( is_string( $source ) && '' !== $source ) {
				self::look( $source, is_array( $hook_extra ) ? $hook_extra : array() );
			}
		} catch ( \Throwable $e ) {
			// An inspection that throws is an inspection that did not happen,
			// which is the same outcome as one that found nothing. It is never
			// a reason to interrupt somebody's update.
			return $source;
		}

		return $source;
	}

	/**
	 * Close the package finding of a copy found to match its published one,
	 * now that the upgrader has put it in place.
	 *
	 * @param mixed $response   True, or the error the install ended on.
	 * @param mixed $hook_extra What the upgrader was doing.
	 * @param mixed $result     Where the files went.
	 * @return mixed The response, unchanged.
	 */
	public static function installed( $response, $hook_extra = null, $result = null ) {
		try {
			$plugin = is_array( $hook_extra ) && isset( $hook_extra['plugin'] ) ? (string) $hook_extra['plugin'] : '';
			$slug   = '' !== $plugin ? dirname( $plugin ) : ( is_array( $result ) ? (string) ( $result['destination_name'] ?? '' ) : '' );

			if ( '' !== $slug && isset( self::$clean[ $slug ] ) ) {
				unset( self::$clean[ $slug ] );

				if ( ! is_wp_error( $response ) ) {
					self::close_finding( $slug, 'restored' );
				}
			}

			// A plugin in place: its open rows are compared again once the
			// upgrader has finished (recheck_landed()).
			$is_plugin = '' !== $plugin || ( is_array( $hook_extra ) && 'plugin' === ( $hook_extra['type'] ?? '' ) );

			if ( '' !== $slug && '.' !== $slug && $is_plugin && ! is_wp_error( $response ) ) {
				self::$landed[ $slug ] = true;
			}
		} catch ( \Throwable $e ) {
			// Never a reason to interrupt somebody's install.
			return $response;
		}

		return $response;
	}

	/**
	 * @param array<string, mixed> $hook_extra
	 */
	private static function look( string $source, array $hook_extra ): void {
		$plugin = isset( $hook_extra['plugin'] ) ? (string) $hook_extra['plugin'] : '';
		$type   = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';

		// Plugin updates only. Themes publish no per-file checksums at all, so
		// there is nothing to compare a theme against and saying so once here
		// is better than a check that always answers "unknown".
		if ( '' === $plugin && 'plugin' !== $type ) {
			return;
		}

		if ( '' !== $plugin && '.' === dirname( $plugin ) ) {
			/*
			 * A one-file plugin, which has no directory to name it by. The
			 * folder an upgrade is unpacked into is named after the temporary
			 * download and carries a random suffix, so falling back to it
			 * would send a made-up string to the directory on every such
			 * update and cache the miss under it. Nothing can be looked up
			 * here, and saying so is standing down rather than guessing.
			 */
			return;
		}

		$slug = '' !== $plugin ? dirname( $plugin ) : basename( untrailingslashit( $source ) );

		// On an update the upgrader names the plugin's own entry file, which
		// is the file carrying the version. On an install nothing names it.
		$version = self::version_in( $source, '' !== $plugin ? basename( $plugin ) : '' );

		if ( '' === $slug || '' === $version ) {
			return;
		}

		if ( self::$spent >= self::budget_seconds() ) {
			return;
		}

		$started = microtime( true );

		$manifest = Manifest::plugin( $slug, $version, array( 'timeout' => self::FETCH_TIMEOUT ) );
		$result   = is_wp_error( $manifest ) ? null : self::compare( $source, $manifest );

		self::$spent += microtime( true ) - $started;

		// Not published, not yet posted, or unreachable. None of those is a
		// finding: the overwhelming majority of them are a plugin that simply
		// does not come from the directory.
		if ( is_wp_error( $manifest ) || null === $result ) {
			return;
		}

		if ( array() === $result['differs'] ) {
			$reason = self::incomplete( $result );

			/*
			 * Every file compared, and every one the published copy: whatever
			 * was open about this plugin's package described one that is no
			 * longer installed. Installing it again from the directory is what
			 * the refusal to adopt a large difference tells the owner to do,
			 * and the finding stayed open after they had. A check cut short
			 * answers nothing: the files it did not reach may be the ones.
			 */
			if ( null === $reason ) {
				/*
				 * Answered once the upgrader has put the files in place, not
				 * here: this filter runs before core checks the destination,
				 * the plugin's requirements and the copy, and a canceled
				 * replace, a refused requirement or a failed copy each leave
				 * the old copy installed, and its finding with it.
				 */
				self::$clean[ $slug ] = true;

				return;
			}

			// Nothing looked wrong, but not everything was looked at. Said
			// quietly, because a silent partial check is the thing that would
			// let somebody read this as a guarantee it never gave — and under
			// its own type, because the label the mismatch uses is the one a
			// summary email states as fact.
			Writer::instance()->record(
				'package_partly_checked',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'plugin',
					'object_id'   => $slug,
					'context'     => array(
						'version' => $version,
						'reason'  => $reason,
						// Both numbers, because one without the other says
						// nothing: 1,500 of 1,600 files and 1,500 of 6,000
						// are the same "partly" and mean different things.
						'checked' => $result['checked'],
						'listed'  => count( $manifest['files'] ),
					),
				)
			);

			return;
		}

		$adoption = self::adoption( $slug );
		$adopted  = null !== $adoption && (string) ( $adoption['version'] ?? '' ) === $version
			? (array) ( $adoption['files'] ?? array() )
			: null;

		/*
		 * The copy the owner already said is theirs, arriving again. Nothing
		 * at all is recorded: this is the expected case for a plugin built
		 * from source, and a quieter row saying so every time would be the
		 * same noise one severity down.
		 */
		if ( null !== $adopted && self::same_copy( $adopted, $result['differs'] ) ) {
			/*
			 * And anything still open against this plugin is answered, because
			 * it described a package that is no longer the one installed — a
			 * downgrade back to an adopted version leaves the newer version's
			 * finding on the screen otherwise, about files nobody has.
			 */
			self::close_finding( $slug );

			return;
		}

		// Which paths the adoption no longer accounts for. Named, because
		// "your own copy changed" and "this never matched" are two different
		// things to be told, and only one of them is about a decision the
		// owner already made.
		$changed = null === $adopted ? array() : self::changed_since( $adopted, $result['differs'] );

		$paths = array_keys( $result['differs'] );

		Writer::instance()->record(
			'package_unverified',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'plugin',
				'object_id'   => $slug,
				'context'     => array(
					'version' => $version,
					'reason'  => array() === $changed ? 'does_not_match_published' : 'adopted_copy_changed',
					// The paths, not a count: which file differs is the whole
					// of what anybody does next with this.
					'files'   => array_slice( $paths, 0, self::MAX_SHOWN ),
					'total'   => count( $paths ),
					'partial' => $result['partial'],
					'changed' => array_slice( $changed, 0, self::MAX_SHOWN ),
				),
			)
		);

		self::open_finding( $slug, $version, $manifest, $result['differs'], $changed );
	}

	/* ---- the finding the screen answers --------------------------------- */

	/**
	 * Record the difference as something that stays open until it is answered.
	 *
	 * The event above says it happened. This says it is still true — which is
	 * the half somebody acts on, and the half that has to stop being true when
	 * they do.
	 *
	 * @param array{algo: string, files: array<string, mixed>, version: string} $manifest
	 * @param array<string, string>                                             $differs Path to the hash that arrived.
	 * @param string[]                                                          $changed Paths an adoption no longer covers.
	 */
	private static function open_finding( string $slug, string $version, array $manifest, array $differs, array $changed ): void {
		global $wpdb;

		$files     = array();
		$truncated = false;

		foreach ( $differs as $relative => $found ) {
			if ( count( $files ) >= self::MAX_MISMATCH_FILES ) {
				$truncated = true;
				break;
			}

			$offered = Manifest::hashes_for( $manifest, (string) $relative );

			$files[ (string) $relative ] = array(
				'published' => (string) ( $offered[0] ?? '' ),
				'found'     => (string) $found,
			);
		}

		ksort( $files );

		$detail = array(
			'version'         => $version,
			'files'           => $files,
			'total'           => count( $differs ),
			'truncated'       => $truncated,
			'adopted_changed' => array() !== $changed,
			'changed'         => array_slice( $changed, 0, self::MAX_SHOWN ),
		);

		$open          = self::mismatches();
		$open[ $slug ] = $detail;
		update_option( self::MISMATCH_OPTION, $open, false );

		// One string for the whole difference, so a package that arrives
		// unchanged is the finding that is already open rather than a second
		// one — and a package that arrives changed is a new fact with its own
		// date on it.
		$digest    = hash( 'sha256', (string) wp_json_encode( array( $version, $files, $truncated ) ) );
		$path      = self::package_path( $slug );
		$path_hash = hash( 'sha256', $path );
		$table     = Schema::table( 'integrity_changes' );

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT id, status, hash_after FROM %i WHERE site_id = 0 AND path_hash = %s ORDER BY id DESC LIMIT 1',
				$table,
				$path_hash
			)
		);

		if (
			null !== $existing
			&& in_array( (string) $existing->status, array( 'new', 'acknowledged' ), true )
			&& hash_equals( (string) $existing->hash_after, $digest )
		) {
			return;
		}

		/*
		 * One open difference per package. A second build that also differs
		 * left the first one's row open beside it, both counted, while what
		 * is kept about the difference describes only the newest (#1817).
		 * The earlier one is replaced, as the file check replaces a file's
		 * older row.
		 */
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = 'superseded' WHERE site_id = 0 AND path_hash = %s AND change_type = %s AND status IN ('new','acknowledged')",
				$table,
				$path_hash,
				self::CHANGE_TYPE
			)
		);

		$wpdb->insert(
			$table,
			array(
				'site_id'     => 0,
				'path_hash'   => $path_hash,
				'path'        => $path,
				'context'     => Manifest::CONTEXT_PLUGIN,
				'slug'        => $slug,
				'version'     => $version,
				'detected_at' => Time::stamp(),
				'change_type' => self::CHANGE_TYPE,
				'algo'        => (string) $manifest['algo'],
				'hash_before' => null,
				'hash_after'  => $digest,
				'size_after'  => null,
				'status'      => 'new',
			)
		);
	}

	/** Where a package sits, as the change rows spell a path. */
	private static function package_path( string $slug ): string {
		return 'wp-content/plugins/' . $slug;
	}

	/**
	 * The open difference for one slug, or null.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function mismatch( string $slug ): ?array {
		$entry = self::mismatches()[ $slug ] ?? null;

		return is_array( $entry ) ? $entry : null;
	}

	/**
	 * The same, shaped for a screen: the paths bounded, the hashes beside them.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function finding( string $slug ): ?array {
		$open = self::mismatch( $slug );

		if ( null === $open ) {
			return null;
		}

		$files = array();

		foreach ( (array) ( $open['files'] ?? array() ) as $path => $pair ) {
			if ( count( $files ) >= self::MAX_SHOWN ) {
				break;
			}

			$files[] = array(
				'path'      => (string) $path,
				'published' => (string) ( $pair['published'] ?? '' ),
			);
		}

		return array(
			'slug'            => $slug,
			'name'            => Packages::name_of( 'plugin', $slug ),
			'version'         => (string) ( $open['version'] ?? '' ),
			'files'           => $files,
			'total'           => (int) ( $open['total'] ?? count( $files ) ),
			'truncated'       => (bool) ( $open['truncated'] ?? false ),
			'adopted_changed' => (bool) ( $open['adopted_changed'] ?? false ),
			'changed'         => array_values( array_map( 'strval', (array) ( $open['changed'] ?? array() ) ) ),
		);
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	private static function mismatches(): array {
		$stored = get_option( self::MISMATCH_OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/* ---- "this one is mine" --------------------------------------------- */

	/**
	 * Every copy the owner has adopted, keyed by slug.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function adopted(): array {
		$stored = get_option( self::ADOPTED_OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * What was adopted for one slug, or null when nothing was.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function adoption( string $slug ): ?array {
		$entry = self::adopted()[ $slug ] ?? null;

		return is_array( $entry ) ? $entry : null;
	}

	/**
	 * Record that this exact copy, at this exact version, is the owner's own.
	 *
	 * Written to the ledger before it is made, like every other change here,
	 * so the offer to put it back is one that can be kept.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function adopt( string $slug, string $version ) {
		$slug    = Targets::folder_name( $slug );
		$version = trim( $version );
		$open    = '' === $slug ? null : self::mismatch( $slug );

		if ( null === $open ) {
			return new \WP_Error(
				'bettershield_no_package_difference',
				__( 'Nothing is open against that plugin, so there is no copy to adopt.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		if ( (string) ( $open['version'] ?? '' ) !== $version || '' === $version ) {
			return new \WP_Error(
				'bettershield_package_version_moved',
				__( 'That version does not match the record. Check again, then adopt the current copy.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		/*
		 * An adoption that covers only part of what differs would never go
		 * quiet: the paths outside it raise the finding again on the next
		 * update, every time, which is the noise this exists to end.
		 */
		if ( ! empty( $open['truncated'] ) ) {
			return new \WP_Error(
				'bettershield_package_too_different',
				Manifest::from_publisher( $slug )
					? __( 'Too many files differ to adopt this copy. Compare them, and reinstall from your account if they are unexpected.', 'bettershield' )
					: __( 'Too many files differ to adopt this copy. Compare them, and reinstall from WordPress.org if they are unexpected.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$files = array();

		foreach ( (array) ( $open['files'] ?? array() ) as $path => $pair ) {
			$files[ (string) $path ] = (string) ( $pair['found'] ?? '' );
		}

		$adopted = self::adopted();
		$entry   = array(
			'version'    => $version,
			'files'      => $files,
			'adopted_at' => Time::stamp(),
			'by'         => get_current_user_id() > 0 ? get_current_user_id() : null,
		);

		$token = Ledger::open(
			'integrity_package_adopt',
			array(
				'slug'     => $slug,
				'adoption' => $adopted[ $slug ] ?? null,
				// What adopting answers, so putting it back can report the
				// difference again at once rather than at the next update.
				'mismatch' => $open,
				'rows'     => self::open_finding_ids( $slug ),
			),
			array(
				'slug'     => $slug,
				'adoption' => $entry,
			)
		);

		if ( null === $token ) {
			return new \WP_Error(
				'bettershield_undo_unavailable',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$adopted[ $slug ] = $entry;
		update_option( self::ADOPTED_OPTION, $adopted, false );

		self::close_finding( $slug );

		Writer::instance()->record(
			'package_adopted',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'plugin',
				'object_id'   => $slug,
				'context'     => array(
					'undo'    => $token,
					'version' => $version,
					'files'   => count( $files ),
				),
			)
		);

		return array(
			'slug'    => $slug,
			'version' => $version,
			'files'   => count( $files ),
			'undo'    => $token,
		);
	}

	/**
	 * Put an adoption back, so the next inspection reports the difference again.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function revert_adoption( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || 'integrity_package_adopt' !== (string) $entry->action_key ) {
			return new \WP_Error(
				'bettershield_unknown_undo',
				__( 'There is no such adoption on record.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error(
				'bettershield_already_reverted',
				__( 'That adoption has already been put back.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();
		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$slug    = Targets::folder_name( (string) ( $applied['slug'] ?? '' ) );

		if ( '' === $slug ) {
			return new \WP_Error(
				'bettershield_unknown_undo',
				__( 'That record names no plugin, so nothing can be put back.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$adopted = self::adopted();

		// Exactly what was there before, which is usually nothing and is
		// sometimes an earlier adoption of the same slug.
		if ( is_array( $prior['adoption'] ?? null ) ) {
			$adopted[ $slug ] = $prior['adoption'];
		} else {
			unset( $adopted[ $slug ] );
		}

		update_option( self::ADOPTED_OPTION, $adopted, false );

		self::reopen( $slug, $prior, is_array( $applied['adoption'] ?? null ) ? $applied['adoption'] : array() );

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'package_adoption_undone',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'plugin',
				'object_id'   => $slug,
				'context'     => array( 'undo' => $token ),
			)
		);

		return array( 'slug' => $slug );
	}

	/**
	 * The ids of the slug's open package rows, which adopting closes.
	 *
	 * @return int[]
	 */
	private static function open_finding_ids( string $slug ): array {
		global $wpdb;

		$ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT id FROM %i WHERE site_id = 0 AND change_type = %s AND slug = %s AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				self::CHANGE_TYPE,
				$slug
			)
		);

		return array_map( 'intval', is_array( $ids ) ? $ids : array() );
	}

	/**
	 * Report again what an adoption had answered, as it was before.
	 *
	 * The package's own entry and row, which adopting closed, and each file's
	 * row the routine check closed as expected because the adoption covered
	 * it: one closed as expected at the adopted version, holding the very
	 * bytes that were adopted for its path. Without this the difference came
	 * back only with the plugin's next update — the check recording nothing
	 * new for a file whose bytes had not changed since its row was closed.
	 *
	 * @param array<string, mixed> $prior    The undo record's state from before.
	 * @param array<string, mixed> $adoption The adoption being withdrawn.
	 */
	private static function reopen( string $slug, array $prior, array $adoption ): void {
		global $wpdb;

		$table   = Schema::table( 'integrity_changes' );
		$version = (string) ( $adoption['version'] ?? '' );

		// An update since has replaced the copy that was adopted, and what it
		// differed in describes a version that is no longer installed.
		$installed = Targets::installed_version(
			array(
				'context' => Manifest::CONTEXT_PLUGIN,
				'slug'    => $slug,
			)
		);

		if ( '' !== $installed && $installed !== $version ) {
			return;
		}

		// Not over one an update wrote since, which is about the copy there now.
		if ( is_array( $prior['mismatch'] ?? null ) && null === self::mismatch( $slug ) ) {
			$open          = self::mismatches();
			$open[ $slug ] = $prior['mismatch'];

			update_option( self::MISMATCH_OPTION, $open, false );

			foreach ( array_map( 'intval', (array) ( $prior['rows'] ?? array() ) ) as $id ) {
				$wpdb->query(
					$wpdb->prepare(
						"UPDATE %i SET status = 'new' WHERE site_id = 0 AND id = %d AND change_type = %s AND status = 'suppressed'",
						$table,
						$id,
						self::CHANGE_TYPE
					)
				);
			}
		}

		$files  = (array) ( $adoption['files'] ?? array() );
		$prefix = 'wp-content/plugins/' . $slug . '/';

		// Rows the owner marked expected on their own or in a batch stay as
		// they marked them: their undo records are still open, and a batch
		// would go on being listed with its rows reported again.
		$kept = Packages::held() + Restore::marked_alone_since( 0 );

		foreach ( $files as $relative => $hash ) {
			if ( '' === $version || '' === (string) $hash ) {
				continue;
			}

			$ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT id FROM %i WHERE site_id = 0 AND path_hash = %s AND slug = %s AND version = %s AND hash_after = %s AND change_type <> %s AND status = 'suppressed'",
					$table,
					hash( 'sha256', $prefix . (string) $relative ),
					$slug,
					$version,
					(string) $hash,
					self::CHANGE_TYPE
				)
			);

			foreach ( array_map( 'intval', is_array( $ids ) ? $ids : array() ) as $id ) {
				if ( isset( $kept[ $id ] ) ) {
					continue;
				}

				$wpdb->query(
					$wpdb->prepare(
						"UPDATE %i SET status = 'new' WHERE site_id = 0 AND id = %d AND status = 'suppressed'",
						$table,
						$id
					)
				);
			}
		}
	}

	/**
	 * Close the open package differences recorded against a version that is
	 * no longer the one installed, and all but the newest for a version that
	 * is.
	 *
	 * One open row per package holds only from the build that added it on:
	 * a site that ran earlier builds kept every older row open, four
	 * "bettershield 1.0.0 differs" rows beside 1.1.2 installed, each keeping
	 * the critical finding up (#2145). An update replaces the package, so a
	 * row about the copy it replaced describes nothing on disk.
	 *
	 * @return int How many rows it closed.
	 */
	public static function close_outdated(): int {
		global $wpdb;

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = array();

		foreach ( get_plugins() as $file => $data ) {
			if ( str_contains( (string) $file, '/' ) ) {
				$installed[ dirname( (string) $file ) ] = (string) ( $data['Version'] ?? '' );
			}
		}

		$table = Schema::table( 'integrity_changes' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table, read once per pass.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, slug, version FROM %i WHERE site_id = 0 AND change_type = %s AND status IN ('new','acknowledged') ORDER BY id DESC", $table, self::CHANGE_TYPE ) );
		$kept = array();
		$gone = array();

		foreach ( (array) $rows as $row ) {
			$slug = (string) $row->slug;

			if ( ! isset( $installed[ $slug ] ) || $installed[ $slug ] !== (string) $row->version || isset( $kept[ $slug ] ) ) {
				$gone[] = (int) $row->id;
			} else {
				$kept[ $slug ] = true;
			}
		}

		if ( array() !== $gone ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table.
			$wpdb->query( $wpdb->prepare( "UPDATE %i SET status = 'superseded' WHERE id IN (" . implode( ',', array_fill( 0, count( $gone ), '%d' ) ) . ')', array_merge( array( $table ), $gone ) ) );
		}

		// What is kept about a difference goes with its row.
		$open    = self::mismatches();
		$trimmed = array_filter( $open, static fn( $entry, $slug ): bool => isset( $kept[ $slug ] ) && $installed[ $slug ] === (string) ( $entry['version'] ?? '' ), ARRAY_FILTER_USE_BOTH );

		if ( $trimmed !== $open ) {
			update_option( self::MISMATCH_OPTION, $trimmed, false );
		}

		return count( $gone );
	}

	/**
	 * Answer the open finding for a slug and forget what it was about:
	 * marked expected when the owner adopted the copy, put back when the
	 * published copy itself arrived again.
	 */
	private static function close_finding( string $slug, string $status = 'suppressed' ): void {
		global $wpdb;

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE %i SET status = %s WHERE site_id = 0 AND change_type = %s AND slug = %s AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				'restored' === $status ? 'restored' : 'suppressed',
				self::CHANGE_TYPE,
				$slug
			)
		);

		$open = self::mismatches();

		unset( $open[ $slug ] );

		update_option( self::MISMATCH_OPTION, $open, false );
	}

	/**
	 * Whether one file, as it is on disk now, is part of a copy the owner has
	 * already reviewed and adopted at this version.
	 *
	 * Asked by the routine check as well as by the update-time one. Both read
	 * the same files against the same published list, and an adoption that
	 * quieted only the second of them left the owner a finding a scan about a
	 * difference they had already answered for.
	 *
	 * A file that is not there is never covered: what was adopted is a set of
	 * files that were present and differed, so an absence is a fact nobody
	 * has said is expected.
	 *
	 * @param string      $version  The version the file is being compared at.
	 * @param string      $relative The file's path inside the package.
	 * @param string|null $hash     The hash found on disk, or null when it is gone.
	 */
	public static function covers( string $slug, string $version, string $relative, ?string $hash ): bool {
		if ( '' === $version || null === $hash || '' === $hash ) {
			return false;
		}

		$adoption = self::adoption( $slug );

		if ( null === $adoption || (string) ( $adoption['version'] ?? '' ) !== $version ) {
			return false;
		}

		$files = (array) ( $adoption['files'] ?? array() );

		return isset( $files[ $relative ] )
			&& array() === self::changed_since( $files, array( $relative => $hash ) );
	}

	/**
	 * Whether what arrived is, path for path and hash for hash, what was
	 * adopted.
	 *
	 * @param array<string, string> $adopted
	 * @param array<string, string> $differs
	 */
	private static function same_copy( array $adopted, array $differs ): bool {
		if ( count( $adopted ) !== count( $differs ) ) {
			return false;
		}

		return array() === self::changed_since( $adopted, $differs );
	}

	/**
	 * The paths an adoption does not account for: a file whose hash has moved,
	 * and a file that differs now and did not before.
	 *
	 * @param array<string, string> $adopted
	 * @param array<string, string> $differs
	 * @return string[]
	 */
	private static function changed_since( array $adopted, array $differs ): array {
		$changed = array();

		foreach ( $differs as $relative => $found ) {
			$known = (string) ( $adopted[ (string) $relative ] ?? '' );

			if ( '' === $known || ! hash_equals( $known, (string) $found ) ) {
				$changed[] = (string) $relative;
			}
		}

		sort( $changed );

		return $changed;
	}

	/**
	 * The manifest's paths, the ones that can run first.
	 *
	 * Order inside each group is left exactly as published, so the same
	 * package checked twice on the same site checks the same files. This
	 * raises the value of a partial answer; it does not make one complete,
	 * which is why the row still says how far it got.
	 *
	 * @param array<int, int|string> $paths
	 * @return array<int, int|string>
	 */
	private static function code_first( array $paths ): array {
		$code  = array();
		$other = array();

		foreach ( $paths as $path ) {
			if ( Packages::can_run( (string) $path ) ) {
				$code[] = $path;
			} else {
				$other[] = $path;
			}
		}

		return array_merge( $code, $other );
	}

	/**
	 * Why this inspection may not be reported as complete, or null when it may.
	 *
	 * A comparison that read nothing produces no differences, which is the
	 * same shape as a comparison that read everything and found none. The two
	 * have to be told apart here or the second is what gets shown.
	 *
	 * @param array{differs: array<string, string>, partial: bool, checked: int, considered: int, present: int} $result
	 */
	private static function incomplete( array $result ): ?string {
		/*
		 * Files were named and none of them, or not all of them, could be
		 * hashed. Where WordPress writes an update over FTP or SSH rather than
		 * directly, the path handed to this filter is relative to that
		 * account's own root, so everything the manifest names is somewhere
		 * PHP cannot see: the update succeeds and the comparison quietly
		 * examines nothing.
		 */
		if ( $result['considered'] > 0 && ( 0 === $result['checked'] || $result['checked'] < $result['present'] ) ) {
			return 'could_not_read';
		}

		return $result['partial'] ? 'too_large_to_check' : null;
	}

	/**
	 * The version this package says it is.
	 *
	 * Read from the package rather than from what is installed, because the
	 * point is to check the thing that arrived against its own published
	 * copy — a version taken from the site would compare the new files against
	 * the old version's manifest and disagree with everything.
	 *
	 * @param string $entry_file The plugin's own entry file, where one is
	 *                           named. The glob below is a guess at it and
	 *                           takes whatever the filesystem lists first,
	 *                           which is a build script or an uninstaller as
	 *                           readily as the plugin.
	 */
	private static function version_in( string $source, string $entry_file = '' ): string {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$named = '' !== $entry_file ? trailingslashit( $source ) . $entry_file : '';

		if ( '' !== $named && is_file( $named ) ) {
			$data = get_plugin_data( $named, false, false );

			// Whatever it says, including nothing: this is the file WordPress
			// itself reads a plugin's version from, so a second opinion from
			// elsewhere in the package would not be a better answer.
			return empty( $data['Version'] ) ? '' : trim( (string) $data['Version'] );
		}

		foreach ( (array) glob( trailingslashit( $source ) . '*.php' ) as $file ) {
			$data = get_plugin_data( (string) $file, false, false );

			if ( ! empty( $data['Version'] ) ) {
				return trim( (string) $data['Version'] );
			}
		}

		return '';
	}

	/**
	 * Hash what arrived and compare it with what was published.
	 *
	 * A file the manifest does not mention is not reported. Publishers ship
	 * things the checksum list does not carry, and the question being asked
	 * here is whether what was published arrived intact — not whether the
	 * package holds anything extra, which the file check answers later and
	 * with the site's own context.
	 *
	 * Three counts come back rather than one, because "no differences" is not
	 * a result on its own: how many paths were reachable, how many of those
	 * were in the package, and how many were actually hashed are what
	 * separate a clean comparison from one that never happened.
	 *
	 * The differing paths come back with the hash each one actually has, not
	 * as a bare list. An adoption is a statement about those hashes — this
	 * exact copy, rather than this plugin — so the copy has to be described
	 * here, where it is in hand, and not re-read from a package that is about
	 * to become the site.
	 *
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 * @return array{differs: array<string, string>, partial: bool, checked: int, considered: int, present: int}
	 */
	private static function compare( string $source, array $manifest ): array {
		$root       = trailingslashit( $source );
		$differs    = array();
		$considered = 0;
		$present    = 0;
		$checked    = 0;
		$bytes      = 0;
		$partial    = false;

		foreach ( self::code_first( array_keys( $manifest['files'] ) ) as $relative ) {
			$relative = (string) $relative;

			// Before the path check rather than after it, so a manifest of
			// paths this plugin will not act on cannot keep the loop running
			// past the point where it has already stopped hashing anything.
			if ( $checked >= self::MAX_FILES || $bytes >= self::MAX_BYTES ) {
				$partial = true;
				break;
			}

			/*
			 * Asked again here, and not redundantly. The fetch path filters
			 * these keys; the cache path rebuilds a manifest from a stored
			 * value and does not. This is what stands between an options row
			 * somebody has edited and a path used to build a filesystem
			 * location.
			 */
			if ( ! Manifest::is_safe_relative_path( $relative ) ) {
				continue;
			}

			++$considered;

			$absolute = $root . $relative;

			// Absent from the package. Publishers drop files between versions
			// and the manifest is per version, so this is only interesting
			// when it is present and different.
			if ( ! is_file( $absolute ) ) {
				continue;
			}

			++$present;

			$size   = (int) @filesize( $absolute );
			$bytes += max( 0, $size );

			$actual = Manifest::hash_file( $absolute, (string) $manifest['algo'] );

			if ( null === $actual ) {
				continue;
			}

			++$checked;

			if ( ! Manifest::matches( $manifest, $relative, $actual ) ) {
				$differs[ $relative ] = $actual;
			}
		}

		return array(
			'differs'    => $differs,
			'partial'    => $partial,
			'checked'    => $checked,
			'considered' => $considered,
			'present'    => $present,
		);
	}
}
