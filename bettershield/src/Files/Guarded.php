<?php
/**
 * Guarded file writes: every write is recorded before it happens and can be
 * put back exactly.
 *
 * Two kinds of file, two rules.
 *
 * Shared files — .htaccess, wp-config.php — belong to the site, not to this
 * plugin. We only ever own a marked block inside them: the block is inserted,
 * replaced or removed, and the bytes outside it are never rewritten. The
 * ledger records the block's prior contents (or its absence), not the whole
 * file, for two reasons that both matter. A whole-file snapshot restored later
 * would silently discard any edit made to the rest of the file in between,
 * which is a change nobody asked for. And wp-config.php holds the database
 * credentials and the authentication salts: copying it into a database table
 * would put the secrets that protect the database inside the database.
 *
 * Owned files — an index.php dropped into a listable directory — are created
 * whole and removed whole. Creation refuses to overwrite anything already
 * there, and removal refuses to delete anything whose bytes are not the ones
 * we wrote. We never destroy a file we did not create.
 *
 * Writes go through a temporary file renamed into place, so a reader never
 * sees a half-written wp-config.php. The trade is that two writers in the same
 * instant could race; a partially served configuration file is the worse
 * failure by far.
 *
 * Every refusal here names an HTTP status, because some callers hand what they
 * get straight to the REST layer, which answers a statusless error with a
 * generic 500 — the shape of an unhandled crash rather than of a decision.
 * Two classes, and the line between them is who has to do something about it.
 * A file that is absent, already there, not readable or not writable is the
 * state of the site disagreeing with what was asked: 409, and the owner can
 * change it. A ledger row that would not be written and a quarantine folder
 * that could not be made are this site failing at its own job with nothing for
 * the owner to correct: 500.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Files;

use BetterShield\Support\Server;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * The functions below operate on files this plugin is explicitly writing as a
 * recorded, reversible change; the WP_Filesystem abstraction exists for
 * credential-mediated installs and would hide the failure modes we need to
 * report exactly.
 */
// phpcs:disable WordPress.WP.AlternativeFunctions

final class Guarded {

	/**
	 * A marked block larger than this is refused rather than truncated.
	 */
	public const MAX_BLOCK_BYTES = 65536;

	/**
	 * Names of the "# BEGIN <name>" blocks other software keeps in a file —
	 * WordPress's own excluded, and this plugin's own excluded. Read-only:
	 * a probe for the conflict warning, never a judgment on the rules.
	 *
	 * @return string[]
	 */
	public static function foreign_blocks( string $path ): array {
		if ( ! is_readable( $path ) ) {
			return array();
		}

		$contents = (string) @file_get_contents( $path, false, null, 0, self::MAX_BLOCK_BYTES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local read of a file this plugin may write; a file that goes away between the check above and here answers with an empty list.

		if ( 1 > preg_match_all( '/^\s*#\s*BEGIN\s+(.+?)\s*$/m', $contents, $matches ) ) {
			return array();
		}

		$names = array();
		foreach ( $matches[1] as $name ) {
			$name = trim( $name );
			if ( '' === $name || 'WordPress' === $name || str_starts_with( $name, 'BetterShield' ) ) {
				continue;
			}
			$names[ $name ] = $name;
		}

		return array_values( $names );
	}

	/**
	 * An owned file larger than this is refused rather than truncated.
	 */
	public const MAX_OWNED_BYTES = 1048576;

	/**
	 * Placement of a new block: appended at the end of the file.
	 */
	public const PLACE_END = 'end';

	/**
	 * Placement of a new block: before the point in wp-config.php where core
	 * takes over, so a define() inside the block is seen by wp-settings.php.
	 *
	 * Nothing shipped asks for this. The audit tells owners that this plugin
	 * never edits wp-config.php, and that is true because no item passes this
	 * — not because the mechanism is absent. `GuardedFilesTest` is what keeps
	 * the two statements from parting company.
	 */
	public const PLACE_BEFORE_SETTINGS = 'before_settings';

	private const MODE_BLOCK = 'block';
	private const MODE_OWNED = 'owned';

	/**
	 * A file this plugin did not create, replaced with a verified copy of
	 * itself, its previous bytes kept beside it.
	 *
	 * This is a third mode, and it exists because integrity restore needs
	 * something the other two cannot express: putting an official file back
	 * means overwriting a file somebody else installed. The rule that mode
	 * one and mode two enforce is not "only touch our own files" for its own
	 * sake — it is that no write may happen without the previous state
	 * captured first and restorable byte for byte. A restore satisfies that
	 * rule exactly: the displaced bytes are written to quarantine *before*
	 * the replacement lands, the ledger records where they went, and undo puts
	 * them back unchanged.
	 *
	 * What it does not do is invent a file. The target must already exist, and
	 * the replacement must already have been verified against a published
	 * checksum by the caller — this class writes bytes, it does not decide
	 * whether they are the right ones.
	 */
	private const MODE_REPLACED = 'replaced';

	/**
	 * The quarantine folder's seal written on the owner's say-so: where the
	 * file was absent, or held the rule an earlier version wrote. What was
	 * there is recorded, and undo puts exactly that back (#2207).
	 */
	private const MODE_SEAL = 'seal';

	/**
	 * Where displaced bytes go: inside the uploads directory, so it survives a
	 * core update and inherits whatever protection the host already applies
	 * there, and behind its own index and .htaccess so nothing serves it.
	 */
	public const QUARANTINE_DIR = 'bettershield-quarantine';

	/* ---- well-known paths ------------------------------------------- */

	/**
	 * Where wp-config.php actually is: the web root, or one directory above it
	 * — the same two places core looks, in the same order.
	 */
	public static function wp_config_path(): ?string {
		$in_root = ABSPATH . 'wp-config.php';

		if ( is_file( $in_root ) ) {
			return $in_root;
		}

		$above = dirname( ABSPATH ) . '/wp-config.php';

		// Core's rule: a wp-config.php one level up counts only when that
		// directory is not itself another WordPress install.
		if ( is_file( $above ) && ! is_file( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return $above;
		}

		return null;
	}

	/**
	 * The .htaccess that governs the site's front end, or null when it cannot
	 * be identified from here.
	 *
	 * The file lives at the *home* path rather than the install root, because
	 * that is where core writes the rewrite rules. In a subdirectory install
	 * the home path is the install root's parent, so this genuinely resolves
	 * outside ABSPATH and has to.
	 *
	 * Derived from the two address options and the install root, and from
	 * nothing else. Core's `get_home_path()` answers the same question by
	 * subtracting the URL path from `SCRIPT_FILENAME`, which is a different
	 * string on an admin screen, on the front controller a REST request comes
	 * through, and under WP-CLI. Wherever the marker was not in that string
	 * the subtraction produced an empty prefix and the answer was `/.htaccess`
	 * — the root of the disk. So the item was applied to one file from the
	 * dashboard and looked for at another by everything else, and the
	 * everything-else answer was a path the process cannot write.
	 *
	 * Null where the URL path is not a suffix of the filesystem path: an
	 * alias, a symlinked docroot, a rewrite in front of the whole site.
	 * Guessing which file governs the site would mean writing rules into
	 * somebody else's, so the callers are told instead.
	 */
	public static function htaccess_path(): ?string {
		$home    = set_url_scheme( (string) get_option( 'home' ), 'http' );
		$siteurl = set_url_scheme( (string) get_option( 'siteurl' ), 'http' );
		$root    = untrailingslashit( str_replace( '\\', '/', ABSPATH ) );

		if ( '' === $home || 0 === strcasecmp( $home, $siteurl ) ) {
			return trailingslashit( self::target( $root ) ) . '.htaccess';
		}

		$relative = trim( str_ireplace( $home, '', $siteurl ), '/' );

		/*
		 * The two differ by host or by scheme rather than by path — a www
		 * mismatch between the options, which is a far more common state than
		 * a subdirectory install. Same directory, named two ways.
		 */
		if ( '' === $relative || str_contains( $relative, '://' ) ) {
			return trailingslashit( self::target( $root ) ) . '.htaccess';
		}

		if ( ! str_ends_with( $root, '/' . $relative ) ) {
			return null;
		}

		return trailingslashit( self::target( substr( $root, 0, -strlen( '/' . $relative ) ) ) ) . '.htaccess';
	}

	/**
	 * The path a write really lands on. A symbolic link is followed to its
	 * target: writing through a temporary file and a rename at the link's own
	 * path would replace the link with a copy — silently breaking a deploy
	 * layout that keeps wp-config.php or .htaccess in a shared directory,
	 * and dropping the block on the next release. Following the link keeps
	 * the file where the site keeps it.
	 */
	public static function target( string $path ): string {
		if ( ! is_link( $path ) ) {
			return $path;
		}

		$real = realpath( $path );

		return false === $real ? $path : $real;
	}

	/* ---- marked blocks ---------------------------------------------- */

	/**
	 * Insert or replace this plugin's marked block in a shared file.
	 *
	 * The prior block (or its absence) is written to the undo ledger before
	 * the file is touched. If the ledger write fails, nothing is written.
	 *
	 * @param string $action_key Stable ledger key, e.g. 'harden_uploads_php'.
	 * @param string $path       The shared file.
	 * @param string $marker     Distinguishes this block from our others in the same file.
	 * @param string $body       The block's contents, without the marker lines.
	 * @param string $place      PLACE_END or PLACE_BEFORE_SETTINGS.
	 * @return string|\WP_Error The undo token.
	 */
	public static function write_block( string $action_key, string $path, string $marker, string $body, string $place = self::PLACE_END ) {
		if ( strlen( $body ) > self::MAX_BLOCK_BYTES ) {
			return new \WP_Error( 'bettershield_file_too_large', __( 'The change was not applied: the block is over the size limit.', 'bettershield' ) );
		}

		$path    = self::target( $path );
		$existed = file_exists( $path );
		$current = self::read_shared( $path );
		if ( is_wp_error( $current ) ) {
			return $current;
		}

		$existing = self::locate_block( $current, $path, $marker );
		if ( is_wp_error( $existing ) ) {
			return $existing;
		}

		$next = self::splice_block( $current, $path, $marker, $body, $place, $existing );
		if ( is_wp_error( $next ) ) {
			return $next;
		}

		// A block already carrying our marker is ours: a leftover from an
		// earlier install whose undo record is gone, or an apply that never
		// finished. It is not the site's prior state, and recording it as
		// such would make undo put our own rules back. Prior is therefore
		// "absent" — undo removes the block, which is what the owner means by
		// undo — and the file counts as having existed only if it held
		// something other than that leftover.
		$existed_without_ours = $existed;
		if ( null !== $existing ) {
			$existed_without_ours = '' !== trim( self::without_block( $current, $existing, null ) );
		}

		$token = Ledger::open(
			$action_key,
			self::block_state( $path, $marker, $place, null, $current, $existed_without_ours ),
			self::block_state( $path, $marker, $place, $body, $next, true )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$written = self::write_atomic( $path, $next );
		if ( is_wp_error( $written ) ) {
			// The change never took effect: the ledger row closes at once.
			Ledger::mark_reverted( $token );

			return $written;
		}

		return $token;
	}

	/**
	 * Remove this plugin's marked block from a shared file, recorded so it can
	 * be put back. Removing a block that is not there is a success that
	 * changes nothing and writes no ledger row.
	 *
	 * @return string|true|\WP_Error The undo token, or true when there was nothing to remove.
	 */
	public static function remove_block( string $action_key, string $path, string $marker ) {
		$path = self::target( $path );

		if ( ! is_file( $path ) ) {
			return true;
		}

		$current = self::read_shared( $path );
		if ( is_wp_error( $current ) ) {
			return $current;
		}

		$existing = self::locate_block( $current, $path, $marker );
		if ( is_wp_error( $existing ) ) {
			return $existing;
		}

		if ( null === $existing ) {
			return true;
		}

		$next = self::without_block( $current, $existing, null );

		$token = Ledger::open(
			$action_key,
			self::block_state( $path, $marker, self::PLACE_END, $existing['body'], $current, true ),
			self::block_state( $path, $marker, self::PLACE_END, null, $next, true )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$written = self::write_atomic( $path, $next );
		if ( is_wp_error( $written ) ) {
			// The change never took effect: the ledger row closes at once.
			Ledger::mark_reverted( $token );

			return $written;
		}

		return $token;
	}

	/**
	 * The current body of our marked block in a file, or null when absent.
	 *
	 * @return string|null|\WP_Error
	 */
	public static function read_block( string $path, string $marker ) {
		$path = self::target( $path );

		if ( ! is_file( $path ) ) {
			return null;
		}

		$current = self::read_shared( $path );
		if ( is_wp_error( $current ) ) {
			return $current;
		}

		$existing = self::locate_block( $current, $path, $marker );
		if ( is_wp_error( $existing ) || null === $existing ) {
			return $existing;
		}

		return $existing['body'];
	}

	/* ---- owned files -------------------------------------------------- */

	/**
	 * Create a file this plugin owns outright. Refuses if anything is already
	 * at the path: we do not overwrite files we did not create.
	 *
	 * @return string|\WP_Error The undo token.
	 */
	public static function create_owned( string $action_key, string $path, string $contents ) {
		if ( strlen( $contents ) > self::MAX_OWNED_BYTES ) {
			return new \WP_Error( 'bettershield_file_too_large', __( 'The change was not applied: the file is over the size limit.', 'bettershield' ) );
		}

		$path = self::target( $path );

		if ( file_exists( $path ) ) {
			return new \WP_Error( 'bettershield_file_exists', __( 'The change was not applied: a file this plugin did not create is already there.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! is_dir( dirname( $path ) ) || ! wp_is_writable( dirname( $path ) ) ) {
			return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the directory is not writable.', 'bettershield' ), array( 'status' => 409 ) );
		}

		// Claim the path exclusively and fill it through the same handle: a
		// file that appears between the check above and this belongs to
		// whoever put it there, and this plugin will not replace it.
		//
		// The contents go in here rather than through write_atomic(), which is
		// what every other write uses. That dance exists so a partial write
		// cannot destroy the version a site already depended on — and there is
		// no previous version here, because this method has just refused to
		// touch a path that had one. What it did cost was a window: the claim
		// sat empty while the ledger row was written, and an interrupted
		// request left an empty file with no record, which the undo then
		// refused to remove because it had never heard of it.
		$claim = @fopen( $path, 'x' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- an exclusive create is the whole point; WP_Filesystem has no equivalent.
		if ( false === $claim ) {
			return new \WP_Error( 'bettershield_file_exists', __( 'The change was not applied: a file this plugin did not create is already there.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$put = fwrite( $claim, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite
		fclose( $claim ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

		if ( false === $put || strlen( $contents ) !== $put ) {
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- a partly written file is not a file we created.

			return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the file could not be written.', 'bettershield' ), array( 'status' => 409 ) );
		}

		// Recorded from the bytes that actually landed rather than from the
		// ones that were meant to, so a later restore compares like with like.
		$bytes = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a file that cannot be read back falls through to the bytes we meant to write.

		$token = Ledger::open(
			$action_key,
			array(
				'mode'    => self::MODE_OWNED,
				'path'    => $path,
				'existed' => false,
			),
			array(
				'mode'   => self::MODE_OWNED,
				'path'   => $path,
				'sha256' => hash( 'sha256', false === $bytes ? $contents : $bytes ),
			)
		);

		if ( null === $token ) {
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- no undo record, so nothing of ours stays.

			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		return $token;
	}

	/**
	 * Replace an existing file with a verified copy, keeping the old bytes.
	 *
	 * The order is the whole design. The displaced file is copied to
	 * quarantine first, then the ledger row is written naming where it went,
	 * and only then does the replacement land. A crash at any point leaves
	 * either the original in place or a quarantine copy the ledger can find —
	 * never a replaced file with its predecessor gone.
	 *
	 * The caller is responsible for having verified the replacement against a
	 * published checksum. This method writes bytes; it does not judge them.
	 *
	 * @param string $path        Absolute path of the file being replaced.
	 * @param string $contents    The verified replacement.
	 * @param string $description What is being put back, for the quarantine name.
	 * @param string $algo        How $expected_sha256 was taken: sha256, or md5 where
	 *                            the record is WordPress's own core checksum.
	 * @return string|\WP_Error The undo token.
	 */
	public static function replace_verified( string $action_key, string $path, string $contents, string $description = '', ?string $expected_sha256 = null, string $algo = 'sha256' ) {
		$path = self::target( $path );

		/*
		 * One request at a time per file. Two at once — two administrators,
		 * a scheduled re-check and a click, two response plans — both read
		 * the file before either wrote: two quarantine copies, two undo
		 * records each claiming the file holds its own bytes, and the file
		 * holding whichever landed last. The integrity scan holds a claim for
		 * the same reason; this is the write side of the same module.
		 */
		$claim = 'file_replace_' . md5( wp_normalize_path( $path ) );

		if ( ! \BetterShield\Support\Claim::claim( $claim, 60 ) ) {
			return new \WP_Error(
				'bettershield_file_busy',
				__( 'Another request is changing this file. Nothing was changed; try again in a moment.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		try {
			return self::replace_verified_claimed( $action_key, $path, $contents, $description, $expected_sha256, $algo );
		} finally {
			\BetterShield\Support\Claim::release( $claim );
		}
	}

	/**
	 * The replacement itself, under the file's claim.
	 *
	 * @return string|\WP_Error The undo token.
	 */
	private static function replace_verified_claimed( string $action_key, string $path, string $contents, string $description, ?string $expected_sha256, string $algo ) {
		if ( ! is_file( $path ) ) {
			return new \WP_Error(
				'bettershield_file_missing',
				__( 'That file is missing, and this plugin does not create missing files.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( ! wp_is_writable( $path ) || ! wp_is_writable( dirname( $path ) ) ) {
			return new \WP_Error(
				'bettershield_file_unwritable',
				__( 'The file was not replaced: the host does not let this plugin write there.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading the file being displaced, byte for byte, to keep it.
		if ( null === $expected_sha256 ) {
			$displaced = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is reported below, not warned about into a dashboard.
		} else {
			$displaced = @file_get_contents( $path, false, null, 0, 2 * MB_IN_BYTES + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- bounded incident response read; failure is a refusal.
		}

		if ( false === $displaced ) {
			return new \WP_Error(
				'bettershield_file_unreadable',
				__( 'The change was not applied: the file could not be read.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// Compared as it was taken: a core file's record is WordPress's MD5.
		if ( null !== $expected_sha256 && ( strlen( $displaced ) > 2 * MB_IN_BYTES || ! in_array( $algo, array( 'sha256', 'md5' ), true ) || ! hash_equals( $expected_sha256, hash( $algo, $displaced ) ) ) ) {
			return new \WP_Error( 'bettershield_file_changed', __( 'The file changed after review. Nothing was replaced.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$quarantined = self::quarantine( $path, (string) $displaced, $description );

		if ( is_wp_error( $quarantined ) ) {
			return $quarantined;
		}

		$token = Ledger::open(
			$action_key,
			array(
				'mode'       => self::MODE_REPLACED,
				'path'       => $path,
				'quarantine' => $quarantined,
				'sha256'     => hash( 'sha256', (string) $displaced ),
				'size'       => strlen( (string) $displaced ),
			),
			array(
				'mode'   => self::MODE_REPLACED,
				'path'   => $path,
				'sha256' => hash( 'sha256', $contents ),
				'size'   => strlen( $contents ),
			)
		);

		if ( null === $token ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$written = self::write_atomic( $path, $contents );

		if ( is_wp_error( $written ) ) {
			Ledger::mark_reverted( $token );

			return $written;
		}

		return $token;
	}

	/**
	 * The quarantine folder, made and sealed where it is not yet: for every
	 * caller that keeps a copy there.
	 *
	 * @return string|\WP_Error Its absolute path.
	 */
	public static function quarantine_folder() {
		$uploads = wp_upload_dir();

		if ( ! empty( $uploads['error'] ) ) {
			return new \WP_Error( 'bettershield_no_quarantine', __( 'Nothing was changed: there is nowhere to keep the old file.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$dir = untrailingslashit( $uploads['basedir'] ) . '/' . self::QUARANTINE_DIR;

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'bettershield_no_quarantine', __( 'Nothing was changed: the quarantine folder could not be created.', 'bettershield' ), array( 'status' => 500 ) );
		}

		// Nothing here is ever served: an index file against directory
		// listings, and a deny rule where the server honors one. A stored
		// copy of a malicious file must not be reachable over the web.
		self::seal_quarantine( $dir );

		return $dir;
	}

	/**
	 * Keep a copy of displaced bytes where nothing will serve them.
	 *
	 * Quarantine, never deletion — a locked principle, and the practical
	 * reason is that the altered file is evidence. Somebody investigating an
	 * intrusion needs to read what was put there.
	 *
	 * @return string|\WP_Error Absolute path of the kept copy.
	 */
	private static function quarantine( string $path, string $contents, string $description ) {
		$dir = self::quarantine_folder();

		if ( is_wp_error( $dir ) ) {
			return $dir;
		}

		/*
		 * Named for what it was and when, and stored with an extension no
		 * server executes. The path hash keeps two files of the same name
		 * from colliding — and the random component keeps the name from
		 * being derivable: on a server where the deny rule is inert, a name
		 * anyone could compute from the path and the minute is the whole of
		 * the protection. The seal is still written where it works; this is
		 * what stands when it cannot.
		 */
		$name = sprintf(
			'%s-%s-%s-%s.quarantined',
			gmdate( 'Ymd-His' ),
			substr( hash( 'sha256', $path ), 0, 12 ),
			wp_generate_password( 20, false, false ),
			sanitize_file_name( '' !== $description ? $description : basename( $path ) )
		);

		$destination = $dir . '/' . $name;

		$written = self::write_atomic( $destination, $contents );

		if ( is_wp_error( $written ) ) {
			return $written;
		}

		return $destination;
	}

	/**
	 * What seals the quarantine folder against being served.
	 *
	 * `RedirectMatch` rather than `Require all denied`, for the reason the
	 * uploads hardening item already sets out at length: it is the directive
	 * class core itself writes for permalinks, so a host that serves pretty
	 * permalinks accepts it, while `Require` is a class a restrictive or older
	 * server answers with a 500. Denial that fails closed with an error is
	 * still denial, but it puts an unexplained 500 in the owner's logs
	 * pointing at a folder this plugin created.
	 */
	public const QUARANTINE_RULES = 'RedirectMatch 404 ".*"';

	/** What earlier versions sealed with, replaced on sight so a folder heals. */
	public const QUARANTINE_RULES_PRIOR = 'Require all denied';

	/**
	 * Make the quarantine folder unreachable and unlistable. Best effort by
	 * design: on a server that honors neither, the extension is still one
	 * nothing executes.
	 */
	private static function seal_quarantine( string $dir ): bool {
		if ( ! is_file( $dir . '/index.php' ) ) {
			self::write_atomic( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
		}

		/*
		 * On a server where .htaccess is inert there is no seal to write, and
		 * saying so is the whole of this method's honesty. Nothing stores the
		 * answer, deliberately: the audit asks `quarantine_is_sealed()` at the
		 * moment it reports, so a site moved from Apache to nginx is told
		 * about today's server rather than the one it was on when a file was
		 * first displaced. Silently returning success left displaced bytes —
		 * which may be a webshell — reachable to anyone who could derive the
		 * name.
		 *
		 * Only a server that says it ignores the file stops the write. A
		 * server that names itself as nothing recognizable — WP-CLI, where
		 * every command-line restore runs, and some FPM setups — is not
		 * evidence the rule would be inert, and treating it as such left the
		 * folder holding displaced bytes with an index file and nothing else
		 * on Apache hosts. Writing an unenforced rule costs a few bytes;
		 * skipping an enforced one costs the seal.
		 */
		if ( false === Server::honors_htaccess() ) {
			return false;
		}

		$htaccess = $dir . '/.htaccess';

		/*
		 * Written when absent, and when what is there is exactly what an
		 * earlier version of this method wrote. The seal is only ever written
		 * once, so a folder sealed before the directive changed would keep the
		 * old one for the life of the site otherwise. Anything else found here
		 * is somebody's own and is left alone.
		 */
		if ( is_file( $htaccess ) ) {
			$existing = self::read_shared( $htaccess );

			if ( is_wp_error( $existing ) || self::QUARANTINE_RULES_PRIOR !== trim( (string) $existing ) ) {
				// Somebody else's rules, left alone — and left sealed, which
				// is what they are for.
				return true;
			}
		}

		return ! is_wp_error( self::write_atomic( $htaccess, self::QUARANTINE_RULES . "\n" ) );
	}

	/**
	 * Whether the quarantine folder is sealed against the web: true where the
	 * deny rule is in the folder and this server reads it, false where it is
	 * inert or is not there at all, and null where the rule is there but the
	 * server cannot be identified and neither answer would be honest.
	 *
	 * Both halves are asked, because either alone gives a wrong answer. Read
	 * from the server only, this said "sealed" for every Apache host —
	 * including one where the write had never happened, which is the case
	 * worth reporting. Read from the folder only, it would say "sealed" on
	 * nginx, where the rule is a comment.
	 *
	 * Asked at the moment the audit reports rather than stored: a site moved
	 * from Apache to nginx must answer with today's server, not the one it was
	 * on when a file was first displaced.
	 */
	public static function quarantine_is_sealed(): ?bool {
		// The seal is RedirectMatch, which OpenLiteSpeed does not read.
		$honors = Server::honors_redirect_rules();

		if ( false === $honors ) {
			return false;
		}

		$uploads = wp_upload_dir( null, false );

		if ( ! empty( $uploads['error'] ) ) {
			return null; // Nowhere to look, so no claim either way.
		}

		$htaccess = untrailingslashit( (string) $uploads['basedir'] ) . '/' . self::QUARANTINE_DIR . '/.htaccess';

		if ( ! is_file( $htaccess ) ) {
			return false;
		}

		// Bounded: the file this reads is one of ours, a line long, and a
		// file somebody else has grown is not a reason to read all of it.
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading a marker file this plugin wrote.
		$rules = trim( (string) @file_get_contents( $htaccess, false, null, 0, 4096 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is answered below, not warned about.

		if ( self::QUARANTINE_RULES !== $rules && self::QUARANTINE_RULES_PRIOR !== $rules ) {
			// Somebody else's rules. What they do is theirs to say, and
			// guessing at it is not an answer this can give.
			return null;
		}

		return $honors;
	}

	/**
	 * Write the quarantine folder's seal, where the server reads it, because
	 * the owner asked (#2207).
	 *
	 * Only over nothing, or over the rule an earlier version of this plugin
	 * wrote: a file with anything else in it is somebody's own, and is
	 * refused rather than overwritten. What was there is recorded before the
	 * write. The rule is read back afterwards, and a seal the check still
	 * calls unsealed is taken back at once.
	 *
	 * @return string|\WP_Error The undo token.
	 */
	public static function repair_quarantine_seal( string $action_key ) {
		if ( false === Server::honors_redirect_rules() ) {
			return new \WP_Error( 'bettershield_seal_not_read', __( 'This server does not read the folder’s own rule. Add the server rule instead.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$uploads = wp_upload_dir( null, false );
		$dir     = empty( $uploads['error'] ) ? untrailingslashit( (string) $uploads['basedir'] ) . '/' . self::QUARANTINE_DIR : '';

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return new \WP_Error( 'bettershield_no_quarantine', __( 'Nothing was changed: there is no quarantine folder to seal.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$path = $dir . '/.htaccess';
		$had  = null;

		if ( file_exists( $path ) ) {
			$existing = is_file( $path ) ? self::read_shared( $path ) : new \WP_Error( 'bettershield_seal_custom', '' );

			if ( is_wp_error( $existing ) || self::QUARANTINE_RULES_PRIOR !== trim( (string) $existing ) ) {
				return new \WP_Error( 'bettershield_seal_custom', __( 'The folder already has rules of its own. They were left as they are.', 'bettershield' ), array( 'status' => 409 ) );
			}

			$had = (string) $existing;
		}

		$rules = self::QUARANTINE_RULES . "\n";
		$token = Ledger::open(
			$action_key,
			array(
				'mode' => self::MODE_SEAL,
				'path' => $path,
				'had'  => $had,
			),
			array( 'sha256' => hash( 'sha256', $rules ) )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$written = self::write_atomic( $path, $rules );

		if ( is_wp_error( $written ) ) {
			// Nothing was written, so nothing is left to undo.
			Ledger::mark_reverted( $token );

			return $written;
		}

		if ( false === self::quarantine_is_sealed() ) {
			$undone = self::restore( $token );

			if ( is_wp_error( $undone ) ) {
				return new \WP_Error( 'bettershield_seal_not_read', __( 'The rule was written and still did not seal the folder, and taking it back failed. Use Undo, then add the server rule instead.', 'bettershield' ), array( 'status' => 409 ) );
			}

			return new \WP_Error( 'bettershield_seal_not_read', __( 'The rule was written and still did not seal the folder, so it was taken back. Add the server rule instead.', 'bettershield' ), array( 'status' => 409 ) );
		}

		return $token;
	}

	/**
	 * Put the seal back as it was: removed where there was none, or the
	 * earlier rule where that was there. Only while the file still holds
	 * what was written; an edit since is the owner's and is left alone.
	 *
	 * @param array<string, mixed> $prior
	 * @param array<string, mixed> $applied
	 * @return true|\WP_Error
	 */
	private static function restore_seal( array $prior, array $applied ) {
		$path = (string) ( $prior['path'] ?? '' );

		if ( '' === $path || '.htaccess' !== basename( $path ) || self::QUARANTINE_DIR !== basename( dirname( $path ) ) ) {
			return new \WP_Error( 'bettershield_corrupt_record', __( 'The undo record is incomplete.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( is_file( $path ) ) {
			$current = self::read_shared( $path );

			if ( is_wp_error( $current ) || ! hash_equals( (string) ( $applied['sha256'] ?? '' ), hash( 'sha256', (string) $current ) ) ) {
				return new \WP_Error( 'bettershield_file_changed', __( 'The seal was edited since, so undo left it alone.', 'bettershield' ), array( 'status' => 409 ) );
			}
		}

		if ( null === ( $prior['had'] ?? null ) ) {
			return ! is_file( $path ) || @unlink( $path ) ? true : new \WP_Error( 'bettershield_file_unwritable', __( 'The file could not be removed.', 'bettershield' ), array( 'status' => 409 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- the refusal is the report.
		}

		$written = self::write_atomic( $path, (string) $prior['had'] );

		return is_wp_error( $written ) ? $written : true;
	}

	/* ---- restore ------------------------------------------------------ */

	/**
	 * Restore every open file record under an action key. The orphans an
	 * interrupted apply leaves behind — files written and ledgered, but never
	 * attached to the item's state because the request died first — are
	 * found here by the key every write under that item shares, and put back
	 * before the item is applied again or after it is reverted.
	 *
	 * Every open record, page after page: an item that keeps writing — the
	 * daily guard top-up across a large uploads tree — leaves more than one
	 * page, and a sweep of the newest page alone left the oldest files on
	 * disk while the item said it was off. Paged by id, so a record skipped
	 * or not restored, which stays open, is never read twice.
	 *
	 * @return string[] Error messages for records that could not be restored.
	 */
	public static function restore_open( string $action_key ): array {
		$problems = array();
		$before   = PHP_INT_MAX;

		do {
			$page = Ledger::open_token_page( $action_key, $before );

			foreach ( $page as $id => $token ) {
				$before   = min( $before, (int) $id );
				$problems = array_merge( $problems, self::restore_open_one( $token ) );
			}
		} while ( array() !== $page );

		return $problems;
	}

	/**
	 * Put back one open record of restore_open()'s, if it is a file record.
	 *
	 * @return string[] The error message, when it could not be restored.
	 */
	private static function restore_open_one( string $token ): array {
		$entry = Ledger::find( $token );
		$mode  = is_object( $entry ) && is_array( $entry->prior_state ) ? (string) ( $entry->prior_state['mode'] ?? '' ) : '';

		if ( self::MODE_BLOCK !== $mode && self::MODE_OWNED !== $mode ) {
			/*
			 * Two things are skipped here and they are skipped for different
			 * reasons. A row that is not a file record at all — the item's
			 * own state row, for instance — has nothing to put back. A
			 * displaced file is a file record and is skipped anyway: this is
			 * the repair path for a hardening item that was interrupted, and
			 * putting a quarantined file back is the owner's decision to make
			 * from the quarantine screen, not something an item's re-apply
			 * does on their behalf.
			 */
			return array();
		}

		$result = self::restore( $token );

		return is_wp_error( $result ) && 'bettershield_already_reverted' !== $result->get_error_code()
			? array( $result->get_error_message() )
			: array();
	}

	/**
	 * Put a recorded write back exactly. Marks the ledger entry reverted on
	 * success; on failure records the reason and leaves the entry open so it
	 * can be retried.
	 *
	 * @return true|\WP_Error
	 */
	public static function restore( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();

		switch ( $prior['mode'] ?? '' ) {
			case self::MODE_BLOCK:
				$result = self::restore_block( $prior, $applied );
				break;

			case self::MODE_OWNED:
				$result = self::restore_owned( $prior, $applied );
				break;

			case self::MODE_REPLACED:
				$result = self::restore_replaced_claimed( $prior, $applied );
				break;

			case self::MODE_SEAL:
				$result = self::restore_seal( $prior, $applied );
				break;

			default:
				$result = new \WP_Error( 'bettershield_unknown_mode', __( 'That undo record is not a file change.', 'bettershield' ) );
		}

		if ( is_wp_error( $result ) ) {
			Ledger::mark_revert_failed( $token, $result->get_error_code() . ': ' . $result->get_error_message() );

			return $result;
		}

		Ledger::mark_reverted( $token );

		return true;
	}

	/**
	 * Put a displaced file back under the same per-file claim a replacement
	 * takes. The check that the file still holds what this plugin wrote, and
	 * the write after it, were otherwise open to a replacement landing in
	 * between: the ledger would say the official copy, the disk the altered
	 * one. Two put-backs of one record at once both wrote and both logged.
	 *
	 * @param array<string, mixed> $prior
	 * @param array<string, mixed> $applied
	 * @return true|\WP_Error
	 */
	private static function restore_replaced_claimed( array $prior, array $applied ) {
		$path  = (string) ( $prior['path'] ?? '' );
		$claim = 'file_replace_' . md5( wp_normalize_path( $path ) );

		if ( '' !== $path && ! \BetterShield\Support\Claim::claim( $claim, 60 ) ) {
			return new \WP_Error(
				'bettershield_file_busy',
				__( 'Another request is changing this file. Nothing was changed; try again in a moment.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		try {
			return self::restore_replaced( $prior, $applied );
		} finally {
			if ( '' !== $path ) {
				\BetterShield\Support\Claim::release( $claim );
			}
		}
	}

	/**
	 * Put the displaced file back, byte for byte, from quarantine.
	 *
	 * The hash recorded when it was displaced is checked before it goes back:
	 * a quarantine copy that no longer matches what was kept is not something
	 * to write over a working file on the strength of a filename.
	 *
	 * @param array<string, mixed> $prior
	 * @return true|\WP_Error
	 */
	private static function restore_replaced( array $prior, array $applied = array() ) {
		$path       = (string) ( $prior['path'] ?? '' );
		$quarantine = (string) ( $prior['quarantine'] ?? '' );
		$expected   = (string) ( $prior['sha256'] ?? '' );
		$written    = (string) ( $applied['sha256'] ?? '' );

		if ( '' === $path || '' === $quarantine ) {
			return new \WP_Error( 'bettershield_corrupt_record', __( 'The undo record is incomplete.', 'bettershield' ), array( 'status' => 409 ) );
		}

		/*
		 * Only over what this plugin wrote. The kept bytes went back over
		 * whatever was there: after an update that was the old file written
		 * into the new version, with the newer one kept nowhere, and after a
		 * delete the file came back. One check here, for every caller.
		 */
		if ( '' !== $written ) {
			if ( ! is_file( $path ) ) {
				return new \WP_Error(
					'bettershield_file_gone_since',
					__( 'The file was removed after the restore, so nothing was written. The kept copy can still be downloaded.', 'bettershield' ),
					array( 'status' => 409 )
				);
			}

			$now = @hash_file( 'sha256', $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is refused below.

			if ( false === $now || ! hash_equals( $written, $now ) ) {
				return new \WP_Error(
					'bettershield_file_changed_since',
					__( 'The file changed after the restore, so nothing was written. The kept copy can still be downloaded.', 'bettershield' ),
					array( 'status' => 409 )
				);
			}
		}

		if ( ! is_file( $quarantine ) ) {
			return new \WP_Error(
				'bettershield_quarantine_missing',
				__( 'The kept copy is gone, so it could not be put back.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading this plugin's own quarantine copy.
		$contents = @file_get_contents( $quarantine ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- reported below.

		if ( false === $contents ) {
			return new \WP_Error( 'bettershield_quarantine_unreadable', __( 'The kept copy could not be read.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( '' !== $expected && ! hash_equals( $expected, hash( 'sha256', (string) $contents ) ) ) {
			return new \WP_Error(
				'bettershield_quarantine_altered',
				__( 'The kept copy no longer matches what was stored, so it was not restored.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return self::write_atomic( $path, (string) $contents );
	}

	/**
	 * @param array<string, mixed> $prior
	 * @return true|\WP_Error
	 */
	private static function restore_block( array $prior, array $applied = array() ) {
		$path       = (string) ( $prior['path'] ?? '' );
		$marker     = (string) ( $prior['marker'] ?? '' );
		$place      = (string) ( $prior['place'] ?? self::PLACE_END );
		$prior_body = isset( $prior['block'] ) && is_string( $prior['block'] ) ? base64_decode( $prior['block'], true ) : null;

		if ( '' === $path || '' === $marker ) {
			return new \WP_Error( 'bettershield_corrupt_record', __( 'The undo record is incomplete.', 'bettershield' ), array( 'status' => 409 ) );
		}

		/*
		 * A block that is recorded but cannot be decoded. Absent and
		 * undecodable are different rows and must not collapse into one:
		 * reading this as "there was no block" would take the block out
		 * instead of putting a body back, which is a change nobody asked for
		 * made on the strength of a row nobody could read.
		 */
		if ( isset( $prior['block'] ) && ! is_string( $prior_body ) ) {
			return new \WP_Error( 'bettershield_corrupt_record', __( 'The undo record is incomplete.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! is_file( $path ) ) {
			// The block was absent before and the file is gone now: nothing of
			// ours remains, which is the state being asked for.
			if ( null === $prior_body ) {
				return true;
			}

			// Recreating a file that no longer exists would be inventing one.
			/* translators: %s: file path. */
			return new \WP_Error( 'bettershield_file_missing', sprintf( __( 'The file %s no longer exists, so nothing was put back.', 'bettershield' ), $path ), array( 'status' => 409 ) );
		}

		$current = self::read_shared( $path );
		if ( is_wp_error( $current ) ) {
			return $current;
		}

		$existing = self::locate_block( $current, $path, $marker );
		if ( is_wp_error( $existing ) ) {
			return $existing;
		}

		// What we wrote, against what is in there now. The sibling method
		// below does this for a file we own outright and refuses to delete one
		// that changed; a block is the same promise on a smaller scale. Our
		// block is the obvious place in a shared file to add one more rule of
		// your own, and overwriting what we merely remember writing is how
		// that rule disappears with no warning, no message and no copy.
		$written = isset( $applied['block'] ) && is_string( $applied['block'] ) ? base64_decode( $applied['block'], true ) : null;

		if ( is_string( $written ) && null !== $existing && $written !== $existing['body'] ) {
			return new \WP_Error(
				'bettershield_block_changed',
				sprintf(
					/* translators: %s: file path. */
					__( 'The block in %s was edited, so undo left it alone. Save any additions, then remove it by hand.', 'bettershield' ),
					$path
				)
			);
		}

		if ( null === $prior_body ) {
			if ( null === $existing ) {
				return true;
			}

			$prior_sha = isset( $prior['file_sha256'] ) ? (string) $prior['file_sha256'] : null;
			$next      = self::without_block( $current, $existing, $prior_sha );

			/*
			 * A file that only ever existed to hold our block goes away with it,
			 * but only if nothing else has been written into it since. So does
			 * one whose other rules were taken out by their owner after we
			 * wrote: that plugin deletes the file once nothing else is in it,
			 * so with our block beside it, only its blank lines stayed. A file
			 * that held only blank lines when we wrote is put back byte for
			 * byte. A PHP file is never deleted this way.
			 */
			$emptied = '' === trim( $next ) && (
				empty( $prior['existed'] )
				|| ( '#' === self::comment_prefix( $path ) && null !== $prior_sha && ! hash_equals( $prior_sha, hash( 'sha256', $next ) ) )
			);

			if ( $emptied ) {
				return @unlink( $path ) ? true : new \WP_Error( 'bettershield_file_unwritable', __( 'The file could not be removed.', 'bettershield' ), array( 'status' => 409 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- the refusal below is the report; the warning would only add the site's path to a log.
			}
		} else {
			$next = self::splice_block( $current, $path, $marker, $prior_body, $place, $existing );
			if ( is_wp_error( $next ) ) {
				return $next;
			}
		}

		return self::write_atomic( $path, $next );
	}

	/**
	 * @param array<string, mixed> $prior
	 * @param array<string, mixed> $applied
	 * @return true|\WP_Error
	 */
	private static function restore_owned( array $prior, array $applied ) {
		$path = (string) ( $prior['path'] ?? '' );
		$sha  = (string) ( $applied['sha256'] ?? '' );

		if ( '' === $path || '' === $sha ) {
			return new \WP_Error( 'bettershield_corrupt_record', __( 'The undo record is incomplete.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! file_exists( $path ) ) {
			return true;
		}

		$bytes = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reported below rather than warned about.
		if ( false === $bytes ) {
			return new \WP_Error( 'bettershield_file_unreadable', __( 'The file could not be read.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! hash_equals( $sha, hash( 'sha256', $bytes ) ) ) {
			/* translators: %s: file path. */
			return new \WP_Error( 'bettershield_file_changed', sprintf( __( 'The file %s has changed, so undo left it alone. Remove it by hand if not needed.', 'bettershield' ), $path ), array( 'status' => 409 ) );
		}

		if ( ! @unlink( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- reported below rather than warned about.
			return new \WP_Error( 'bettershield_file_unwritable', __( 'The file could not be removed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		return true;
	}

	/* ---- internals ----------------------------------------------------- */

	/**
	 * @return array<string, mixed>
	 */
	private static function block_state( string $path, string $marker, string $place, ?string $body, string $whole_file, bool $existed ): array {
		return array(
			'mode'        => self::MODE_BLOCK,
			'path'        => $path,
			'marker'      => $marker,
			'place'       => $place,
			// Base64 so the ledger row survives any byte sequence, and so a
			// glance at the table does not show configuration in the clear.
			'block'       => null === $body ? null : base64_encode( $body ),
			'file_sha256' => hash( 'sha256', $whole_file ),
			// Whether the file was there at all: a .htaccess we created to hold
			// our block goes away again when the block does.
			'existed'     => $existed,
		);
	}

	/**
	 * Contents of a shared file, or an empty string when it does not exist yet
	 * and can be created.
	 *
	 * @return string|\WP_Error
	 */
	private static function read_shared( string $path ) {
		if ( ! file_exists( $path ) ) {
			if ( ! is_dir( dirname( $path ) ) || ! wp_is_writable( dirname( $path ) ) ) {
				return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the file is missing and its folder is not writable.', 'bettershield' ), array( 'status' => 409 ) );
			}

			return '';
		}

		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return new \WP_Error( 'bettershield_file_unreadable', __( 'The change was not applied: the file could not be read.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! wp_is_writable( $path ) ) {
			return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the file is not writable.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$bytes = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reported below rather than warned about.

		if ( false === $bytes ) {
			return new \WP_Error( 'bettershield_file_unreadable', __( 'The change was not applied: the file could not be read.', 'bettershield' ), array( 'status' => 409 ) );
		}

		return $bytes;
	}

	/**
	 * Comment prefix for marker lines: PHP files take `//`, everything else `#`.
	 */
	private static function comment_prefix( string $path ): string {
		return 'php' === strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ) ? '//' : '#';
	}

	private static function begin_line( string $path, string $marker ): string {
		return self::comment_prefix( $path ) . ' BEGIN BetterShield ' . $marker;
	}

	private static function end_line( string $path, string $marker ): string {
		return self::comment_prefix( $path ) . ' END BetterShield ' . $marker;
	}

	/**
	 * The file's line ending, taken from the file itself so an edited
	 * wp-config.php on a Windows host keeps its CRLFs.
	 */
	private static function eol( string $contents ): string {
		return str_contains( $contents, "\r\n" ) ? "\r\n" : "\n";
	}

	/**
	 * Find our block. Returns null when absent, an error when the file holds
	 * more than one — a state we did not create and will not guess about.
	 *
	 * @return array{start: int, end: int, body: string}|null|\WP_Error
	 */
	private static function locate_block( string $contents, string $path, string $marker ) {
		$pattern = '/^' . preg_quote( self::begin_line( $path, $marker ), '/' ) . '\R(.*?)^' . preg_quote( self::end_line( $path, $marker ), '/' ) . '(?:\R|\z)/ms';

		$count = preg_match_all( $pattern, $contents, $matches, PREG_OFFSET_CAPTURE );

		if ( false === $count || 0 === $count ) {
			return null;
		}

		if ( $count > 1 ) {
			return new \WP_Error( 'bettershield_file_ambiguous', __( 'The change was not applied: this block appears more than once in the file. Check it by hand.', 'bettershield' ) );
		}

		$whole = $matches[0][0];
		$body  = $matches[1][0][0];

		return array(
			'start' => $whole[1],
			'end'   => $whole[1] + strlen( $whole[0] ),
			'body'  => self::strip_trailing_eol( $body ),
		);
	}

	private static function strip_trailing_eol( string $s ): string {
		return rtrim( $s, "\r\n" );
	}

	/**
	 * The file with our block taken out, together with the one blank line of
	 * breathing room splice_block() put beside it.
	 *
	 * Which side that line is on depends on where the block was placed and
	 * what surrounded it, so when the file's prior hash is known the
	 * candidates are tried against it and the exact match wins. When nothing
	 * matches — the file has been edited elsewhere since — the preceding blank
	 * line goes, which is what an appended block always brought with it.
	 *
	 * @param array{start: int, end: int, body: string} $existing
	 */
	private static function without_block( string $contents, array $existing, ?string $prior_sha256 ): string {
		$eol    = self::eol( $contents );
		$before = substr( $contents, 0, $existing['start'] );
		$after  = substr( $contents, $existing['end'] );

		$blank_before = str_ends_with( $before, $eol . $eol );
		$blank_after  = str_starts_with( $after, $eol );

		$candidates = array();

		if ( $blank_before ) {
			$candidates[] = substr( $before, 0, -strlen( $eol ) ) . $after;
			// A file that had no final newline gained one as well as the blank
			// line; both belong to us.
			$candidates[] = substr( $before, 0, -2 * strlen( $eol ) ) . $after;
		}
		if ( $blank_after ) {
			$candidates[] = $before . substr( $after, strlen( $eol ) );
		}
		$candidates[] = $before . $after;
		// Blank space without a final newline gained only that newline.
		if ( ! $blank_before && str_ends_with( $before, $eol ) ) {
			$candidates[] = substr( $before, 0, -strlen( $eol ) ) . $after;
		}

		if ( null !== $prior_sha256 ) {
			foreach ( $candidates as $candidate ) {
				if ( hash_equals( $prior_sha256, hash( 'sha256', $candidate ) ) ) {
					return $candidate;
				}
			}
		}

		return $candidates[0];
	}

	/**
	 * The file with our block set to $body — replacing the existing block in
	 * place, or inserting a new one at $place.
	 *
	 * @param array{start: int, end: int, body: string}|null $existing
	 * @return string|\WP_Error
	 */
	private static function splice_block( string $contents, string $path, string $marker, string $body, string $place, ?array $existing ) {
		$eol   = self::eol( $contents );
		$block = self::begin_line( $path, $marker ) . $eol
			. ( '' === $body ? '' : self::strip_trailing_eol( $body ) . $eol )
			. self::end_line( $path, $marker ) . $eol;

		if ( null !== $existing ) {
			return substr( $contents, 0, $existing['start'] ) . $block . substr( $contents, $existing['end'] );
		}

		if ( self::PLACE_BEFORE_SETTINGS === $place ) {
			$anchor = self::settings_anchor( $contents );

			if ( null === $anchor ) {
				/*
				 * Not translated, and that is the point: no shipped caller asks
				 * for this placement, so no owner can be shown this sentence and
				 * a translator would be working on something nobody reads.
				 * `GuardedFilesTest` holds that — the first item that writes to
				 * wp-config.php fails it, and whoever adds one translates this
				 * and revisits the audit copy that says this plugin never edits
				 * that file.
				 */
				return new \WP_Error( 'bettershield_file_no_anchor', 'wp-config.php has an unfamiliar layout, so no block was placed in it.' );
			}

			return substr( $contents, 0, $anchor ) . $block . $eol . substr( $contents, $anchor );
		}

		if ( '' === $contents ) {
			return $block;
		}

		$separator = str_ends_with( $contents, $eol ) ? '' : $eol;

		// Blank space needs no blank line to keep it apart from the block:
		// one added there only put an empty line in front of the rules.
		if ( '' === trim( $contents ) ) {
			return $contents . $separator . $block;
		}

		return $contents . $separator . $eol . $block;
	}

	/**
	 * Byte offset of the line in wp-config.php before which our block must sit
	 * for a define() to be seen: the "stop editing" comment core ships, or
	 * failing that the wp-settings.php require. Null when neither is found.
	 */
	private static function settings_anchor( string $contents ): ?int {
		$patterns = array(
			'/^[ \t]*\/\*[ \t]*That\'s all, stop editing!/m',
			'/^[ \t]*require_once[ \t(]*ABSPATH[ \t]*\.[ \t]*[\'"]wp-settings\.php[\'"]/m',
		);

		foreach ( $patterns as $pattern ) {
			if ( 1 === preg_match( $pattern, $contents, $m, PREG_OFFSET_CAPTURE ) ) {
				return $m[0][1];
			}
		}

		return null;
	}

	/**
	 * Write the new contents somewhere they can be renamed over the target
	 * from, and return that path.
	 *
	 * The staging file used to sit beside the target, which for every file
	 * this class touches means inside the web root, ending .tmp — so a web
	 * server would hand it over as plain text for as long as the write took.
	 * Nothing it writes today carries a secret, but this class already holds
	 * the machinery for editing wp-config.php, and the first item to use it
	 * would have staged the database password in a fetchable file.
	 *
	 * WordPress's own upgrade directory is the first choice, because that is
	 * where core stages the same kind of thing and hosts treat it accordingly.
	 * rename() cannot cross a filesystem, though, so when that fails the file
	 * is staged beside the target as before — correctness first, and the name
	 * still carries 48 bits nobody can guess inside the window.
	 *
	 * The mode is narrowed before any content goes in, so the file never
	 * exists with contents at whatever the umask would have given it.
	 *
	 * Nothing here flushes the staging file to the disk before the rename, so
	 * the rename is atomic against other readers but not against a power loss
	 * in the instant between the two.
	 *
	 * @return string|\WP_Error
	 */
	private static function stage( string $path, string $contents ) {
		$name = '.' . basename( $path ) . '.bettershield-' . bin2hex( random_bytes( 6 ) ) . '.tmp';

		$candidates = array();

		$upgrade = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/upgrade' : '';

		if ( '' !== $upgrade && ( is_dir( $upgrade ) || wp_mkdir_p( $upgrade ) ) ) {
			$candidates[] = $upgrade . '/' . $name;
		}

		$candidates[] = dirname( $path ) . '/' . $name;

		foreach ( $candidates as $temp ) {
			// Judged before anything is written, not after: a directory that
			// cannot be renamed from is one this file would have to be
			// discarded from, and discarding it after filling it would leave
			// the contents in the very place this method exists to avoid.
			if ( ! self::same_filesystem( $temp, $path ) || ! @touch( $temp ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_touch -- a directory this plugin may not write to is answered by trying the next candidate.
				continue;
			}

			@chmod( $temp, 0600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- narrowed before the contents arrive; a host that refuses still gets the rename.

			// Suppressed like every other call around it, and for the same
			// reason: a directory this plugin may not write to is an answer, not
			// a fault. Unsuppressed, the refusal was correct and clean and also
			// wrote the site's full absolute server path into the error log —
			// or onto the page, on a host showing warnings — every time it
			// happened.
			if ( false === @file_put_contents( $temp, $contents, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- the guarded writer's own staging write; the caller turns false into a WP_Error.
				@unlink( $temp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- cleaning up a staging file we could not fill.
				continue;
			}

			return $temp;
		}

		return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the file could not be written.', 'bettershield' ), array( 'status' => 409 ) );
	}

	/**
	 * Whether a rename between these two can be atomic. Compared on the device
	 * the directories sit on, because rename() refuses to cross one.
	 */
	private static function same_filesystem( string $a, string $b ): bool {
		$one = @stat( dirname( $a ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable directory answers "no", which is the safe answer.
		$two = @stat( dirname( $b ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.

		return is_array( $one ) && is_array( $two ) && $one['dev'] === $two['dev'];
	}

	/**
	 * Write the whole file through a temporary copy renamed into place,
	 * keeping the original's permissions.
	 *
	 * Mode is kept exactly. Ownership is put back where the process is
	 * allowed to — `rename()` publishes the staging file's inode, which
	 * belongs to whoever PHP runs as, so a file that was the account's and
	 * group-writable would otherwise come out belonging to the web server and
	 * stop being editable over SFTP. Changing the owner needs root and simply
	 * fails on shared hosting; changing the group usually succeeds, which is
	 * the case that matters. **Where neither is permitted the file's owner
	 * changes**, and the setuid and setgid bits and any ACL are not carried
	 * over at all.
	 *
	 * The rename itself is atomic — a reader sees the old file or the new one
	 * and never half of either — but the staging file is not flushed to the
	 * disk first, so a power loss between the write and the rename can still
	 * publish a short file.
	 *
	 * @return true|\WP_Error
	 */
	private static function write_atomic( string $path, string $contents ) {
		$existing = file_exists( $path ) ? @stat( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a file whose metadata cannot be read is written with the defaults below.
		$before   = is_array( $existing ) ? \BetterShield\Integrity\Manifest::hash_file( $path, 'sha256' ) : null;
		$mode     = is_array( $existing ) ? ( $existing['mode'] & 0777 ) : ( defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 );

		$temp = self::stage( $path, $contents );

		if ( is_wp_error( $temp ) ) {
			return $temp;
		}

		@chmod( $temp, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best effort; the rename below is what matters.

		if ( ! @rename( $temp, $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rename -- turned into the refusal below; the warning would name both paths in somebody's log.
			@unlink( $temp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- cleaning up after a failed rename.

			return new \WP_Error( 'bettershield_file_unwritable', __( 'The change was not applied: the file could not be replaced.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( is_array( $existing ) ) {
			// Both are refused rather than obeyed on most hosts, and a refusal
			// here is not a failed write — the contents are already in place
			// and correct. Attempted rather than reported for that reason.
			@chown( $path, (int) $existing['uid'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- see above.
			@chgrp( $path, (int) $existing['gid'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- see above.
		}

		if ( function_exists( 'opcache_invalidate' ) && 'php' === strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unavailable under some SAPIs; harmless when it fails.
		}

		\BetterShield\Integrity\Baseline::follow_own_write( $path, $before );

		return true;
	}
}
