<?php
/**
 * Putting the official file back.
 *
 * This is the answer to "does it scan for malware", and it is a different
 * answer from the one that question usually gets: no signature corpus, no
 * detection claim, no judgment about what a file means. It compares a file
 * against the copy its publisher shipped, shows what differs, and — if the
 * owner says so — writes the published copy back and keeps the altered one.
 *
 * **Nothing is written that has not been verified first.** The fetched copy is
 * hashed and compared against the published checksum before it goes anywhere
 * near the filesystem. That is what makes fetching from a public host safe: a
 * tampered answer fails the comparison and the restore refuses, rather than
 * this feature becoming a way to write attacker-chosen bytes into wp-includes.
 *
 * **The altered file is kept, never deleted.** It is evidence — somebody
 * investigating an intrusion needs to read what was put there — and the undo
 * that puts it back is the same mechanism every other change in this plugin
 * uses.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Support\Http;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Restore {

	/** The undo record a change marked expected writes, and its reversal reads. */
	public const SUPPRESS_UNDO = 'integrity_change_suppress';

	/**
	 * Copies of files the owner stopped ignoring, keyed by path hash, each
	 * with the hash of the copy they took back.
	 *
	 * A file inside an adopted package is marked expected by the adoption on
	 * every scan, so "Stop ignoring" on one lasted until the next run. The
	 * owner's word on that copy of that file outranks the adoption; a
	 * different copy is a new fact, and marking it expected again hands the
	 * file back to the adoption.
	 */
	public const TAKEN_BACK_OPTION = 'bettershield_integrity_taken_back';

	/** How many taken-back files are remembered; the oldest go first. */
	private const TAKEN_BACK_MAX = 500;

	/**
	 * The largest file this will fetch and write.
	 *
	 * Core and plugin source files are kilobytes. A cap keeps a mistaken or
	 * hostile response from being read into memory on shared hosting.
	 */
	private const MAX_BYTES = 2097152;

	/**
	 * The most changes one request puts back: each writes two lines in the
	 * log, and the log keeps two hundred a request.
	 */
	public const BATCH_MAX = 25;

	/**
	 * How long one request spends putting files back before it hands the rest
	 * back. Checked before each file, and one file's copy from WordPress.org
	 * can take its own fifteen seconds, so this stays well under the thirty
	 * a host's gateway commonly allows: past it the screen is told the
	 * request failed while files were in fact put back.
	 */
	private const BATCH_SECONDS = 10.0;

	/**
	 * What a restore would do, without doing any of it.
	 *
	 * @return array<string, mixed>|\WP_Error
	 *
	 * @param bool $whole Draw the whole file rather than the part that differs,
	 *                    where it fits one comparison.
	 */
	public static function preview( int $change_id, string $path = '', bool $whole = false ) {
		$change = self::change( $change_id );

		if ( is_wp_error( $change ) ) {
			return $change;
		}

		/*
		 * A package finding names many files, so the caller has to say which
		 * one. Exactly one is fetched, and only one the package's own list
		 * carries: a path from the request that reached the network would make
		 * the owner's Compare button a way to ask this site to fetch anything
		 * the allow-list happens to serve.
		 */
		if ( IncomingPackage::CHANGE_TYPE === (string) $change->change_type ) {
			$change = self::file_within_package( $change, $path );

			if ( is_wp_error( $change ) ) {
				return $change;
			}
		}

		$official = self::fetch_official( $change );

		if ( is_wp_error( $official ) ) {
			return $official;
		}

		$absolute = self::absolute_path( $change );

		if ( '' === $absolute ) {
			return self::unresolvable_path();
		}

		/*
		 * The copy fetched from the directory is refused over MAX_BYTES; the
		 * copy on disk was read whole with no bound at all. Its size is chosen
		 * by whoever altered it, which is precisely the case this tool exists
		 * for — a file padded large turned the owner's Preview click into a
		 * memory-limit fatal, on the one file they most needed to look at.
		 */
		$size = is_file( $absolute ) ? (int) @filesize( $absolute ) : 0; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- absence is handled as a state.

		if ( $size > self::MAX_BYTES ) {
			return new \WP_Error(
				'bettershield_file_too_large',
				sprintf(
					/* translators: %s: the size limit, already formatted. */
					__( 'This file is over %s, too large to compare here. Download it, or restore it from a backup.', 'bettershield' ),
					size_format( self::MAX_BYTES )
				),
				array( 'status' => 413 )
			);
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading the file on this site to show what differs.
		$current = is_file( $absolute ) ? (string) @file_get_contents( $absolute, false, null, 0, self::MAX_BYTES ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- absence is handled as a state, not a warning.

		return array(
			'change_id'   => (int) $change->id,
			'path'        => (string) $change->path,
			'change_type' => (string) $change->change_type,
			'diff'        => self::diff( $current, $official, (string) $change->path, $whole ),
			// Only the changed region is drawn, and the whole file can be
			// asked for: the screen offers it.
			'partial'     => ! $whole && self::partial( $current, $official ),
			'restorable'  => true,
		);
	}

	/**
	 * One file of a package difference, as a change the rest of this class can
	 * answer for.
	 *
	 * The row on record is the package. What is compared is a file inside it,
	 * at the version the package declared, and the published copy of that file
	 * is fetched the same way and verified against the same checksum as any
	 * other restore.
	 *
	 * @return object|\WP_Error
	 */
	private static function file_within_package( object $change, string $path ) {
		$slug     = (string) $change->slug;
		$mismatch = IncomingPackage::mismatch( $slug );
		$files    = is_array( $mismatch ) ? (array) ( $mismatch['files'] ?? array() ) : array();

		if ( '' === $path || ! isset( $files[ $path ] ) || ! Manifest::is_safe_relative_path( $path ) ) {
			return new \WP_Error(
				'bettershield_not_in_package',
				__( 'That file is not among this plugin’s recorded differences, so nothing was fetched.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		return (object) array(
			'id'          => (int) $change->id,
			'path'        => 'wp-content/plugins/' . $slug . '/' . $path,
			'context'     => Manifest::CONTEXT_PLUGIN,
			'slug'        => $slug,
			'version'     => (string) $change->version,
			// The comparison a package difference is: a file that is here and
			// is not what was published.
			'change_type' => 'modified',
			'status'      => (string) $change->status,
		);
	}

	/**
	 * Put the official file back.
	 *
	 * @param string|null $expected_sha256 The file's checksum the caller judged, if any.
	 * @param string      $algo            How it was taken: sha256, or md5 for a core
	 *                                     file's record.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function apply( int $change_id, ?string $expected_sha256 = null, string $algo = 'sha256' ) {
		/*
		 * Once at a time per change: its open-status check below and the
		 * "restored" mark at the end are a read and a write with nothing
		 * holding the row between them, so two requests at once both passed.
		 */
		$claim = 'integrity_restore_' . $change_id;

		if ( ! \BetterShield\Support\Claim::claim( $claim, 120 ) ) {
			return new \WP_Error(
				'bettershield_restore_busy',
				__( 'Another request is putting this file back. Nothing was changed; try again in a moment.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		try {
			return self::apply_claimed( $change_id, $expected_sha256, $algo );
		} finally {
			\BetterShield\Support\Claim::release( $claim );
		}
	}

	/**
	 * Put several files back from their official copies, each exactly as one
	 * put back alone: fetched, checked against the published checksum, the
	 * file there kept in quarantine first, its own undo and its own lines in
	 * the log. A file that cannot be put back is named with the reason, and
	 * the rest go on; what one request's time did not reach is handed back.
	 *
	 * @param int[] $ids
	 * @param float $budget How long it may spend, in seconds, before it hands the rest back.
	 * @return array{restored: array<int, array<string, mixed>>, skipped: array<int, string>, left: int[]}|\WP_Error
	 */
	public static function apply_many( array $ids, float $budget = self::BATCH_SECONDS ) {
		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ), static fn( int $id ): bool => $id > 0 ) ) );

		if ( array() === $ids || count( $ids ) > self::BATCH_MAX ) {
			return new \WP_Error(
				'bettershield_restore_batch_size',
				sprintf(
					/* translators: %d: the most changes one request puts back. */
					__( 'Select 1 to %d changes at a time. Nothing was changed.', 'bettershield' ),
					self::BATCH_MAX
				),
				array( 'status' => 400 )
			);
		}

		$start    = microtime( true );
		$restored = array();
		$skipped  = array();
		$left     = array();

		foreach ( $ids as $index => $id ) {
			// The first is always tried, so every request moves the list on.
			if ( $index > 0 && microtime( true ) - $start > $budget ) {
				$left = array_slice( $ids, $index );
				break;
			}

			$result = self::apply( $id );

			if ( is_wp_error( $result ) ) {
				$skipped[ $id ] = $result->get_error_message();
				continue;
			}

			$restored[] = $result;
		}

		return array(
			'restored' => $restored,
			'skipped'  => $skipped,
			'left'     => $left,
		);
	}

	/**
	 * Put back the official copies of the open changes a filter matches, the
	 * next few after `$after`, each exactly as apply_many() puts one back.
	 *
	 * The rows of every page, not only the ones on screen, so the request
	 * carries where the last one stopped rather than ids, and the newest row
	 * the owner was shown, so a change recorded since is never put back on a
	 * question that did not count it. A file left as it was stays behind the
	 * cursor, so the next request moves on past it.
	 *
	 * @param array<string, string> $filter  See Report::filter_of().
	 * @param int                   $through The newest row counted.
	 * @param int                   $after   Where the last request stopped; 0 to start.
	 * @param int                   $limit   The most this request takes, at most BATCH_MAX.
	 * @param float                 $budget  How long it may spend, in seconds.
	 * @return array{restored: array<int, array<string, mixed>>, skipped: array<int, string>, left: int[], named: array<int, string>, after: int, remaining: int}|\WP_Error
	 */
	public static function apply_matching( array $filter, int $through, int $after = 0, int $limit = self::BATCH_MAX, float $budget = self::BATCH_SECONDS ) {
		$ids = Report::matching_ids( $filter, $after, $through, max( 1, min( self::BATCH_MAX, $limit ) ), true );

		if ( array() === $ids ) {
			return array(
				'restored'  => array(),
				'skipped'   => array(),
				'left'      => array(),
				'named'     => array(),
				'after'     => $after,
				'remaining' => 0,
			);
		}

		$result = self::apply_many( $ids, $budget );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Oldest first, and what the time did not reach is the tail: the
		// cursor is the last one tried.
		$tried = array_slice( $ids, 0, count( $ids ) - count( $result['left'] ) );
		$after = array() !== $tried ? (int) end( $tried ) : $after;

		// A file left as it was is named by its path: the screen asking may
		// never have loaded its row.
		$named = array();

		foreach ( array_keys( $result['skipped'] ) as $id ) {
			$row          = self::change( (int) $id, false );
			$named[ $id ] = is_wp_error( $row ) ? '' : (string) $row->path;
		}

		return $result + array(
			'named'     => $named,
			'after'     => $after,
			'remaining' => Report::open_matching(
				$filter + array(
					'after'      => (string) $after,
					'through'    => (string) $through,
					'restorable' => '1',
				)
			),
		);
	}

	/**
	 * The restore itself, under the change's claim.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function apply_claimed( int $change_id, ?string $expected_sha256, string $algo ) {
		$change = self::change( $change_id );

		if ( is_wp_error( $change ) ) {
			return $change;
		}

		$official = self::fetch_official( $change );

		if ( is_wp_error( $official ) ) {
			return $official;
		}

		$absolute = self::absolute_path( $change );

		if ( '' === $absolute ) {
			return self::unresolvable_path();
		}

		/*
		 * Restoring displaces the current file into quarantine, which means
		 * reading all of it — "quarantine, never delete" cannot be honored
		 * half a file at a time. So the refusal has to happen here, before the
		 * read, rather than by truncating it: an altered file padded past this
		 * would otherwise exhaust memory in the middle of the write.
		 */
		$size = is_file( $absolute ) ? (int) @filesize( $absolute ) : 0; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- absence is handled by the writer.

		if ( $size > self::MAX_BYTES ) {
			return new \WP_Error(
				'bettershield_file_too_large',
				sprintf(
					/* translators: %s: the size limit, already formatted. */
					__( 'This file is over %s, too large to copy before putting back. Use a backup instead.', 'bettershield' ),
					size_format( self::MAX_BYTES )
				),
				array( 'status' => 413 )
			);
		}

		$token = Guarded::replace_verified(
			'integrity_restore',
			$absolute,
			$official,
			basename( (string) $change->path ),
			$expected_sha256,
			$algo
		);

		if ( is_wp_error( $token ) ) {
			return self::with_status( $token );
		}

		self::set_status( (int) $change->id, 'restored' );

		Writer::instance()->record(
			'file_restored',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => (string) $change->path,
				'context'     => array(
					'undo'    => $token,
					'area'    => (string) $change->context,
					'slug'    => (string) $change->slug,
					'version' => (string) $change->version,
				),
			)
		);

		Writer::instance()->record(
			'file_quarantined',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'file',
				'object_id'   => (string) $change->path,
				'context'     => array( 'undo' => $token ),
			)
		);

		return array(
			'change_id' => (int) $change->id,
			'path'      => (string) $change->path,
			'undo'      => $token,
		);
	}

	/**
	 * Give an error this method is only passing on an HTTP status, if it has
	 * none of its own.
	 *
	 * The writer below this names one for every refusal it makes, and this is
	 * the belt to that pair of braces: an error arriving here without one is
	 * answered by REST as a generic 500, which is what an unhandled crash
	 * looks like and tells the owner nothing about which half of the restore
	 * stopped. The default is the server class deliberately — a failure
	 * nothing downstream recognized is this site's own, not a decision about
	 * the request — and whatever the error says travels with it.
	 */
	private static function with_status( \WP_Error $error, int $status = 500 ): \WP_Error {
		$code = (string) $error->get_error_code();
		$data = $error->get_error_data( $code );

		if ( is_array( $data ) && isset( $data['status'] ) ) {
			return $error;
		}

		$error->add_data(
			array_merge( is_array( $data ) ? $data : array(), array( 'status' => $status ) ),
			$code
		);

		return $error;
	}

	/**
	 * Mark a change as expected, so it stops being reported.
	 *
	 * The suppression covers the file as it stands, not the path forever: if
	 * it is altered again to something else, that is a new fact and is
	 * reported again. Recorded, because a decision to stop being told about
	 * something is exactly the decision an investigation later wants to find.
	 *
	 * And reversible, like every other decision here: the status it replaces
	 * is written to the undo ledger first, and `unsuppress()` puts it back. It
	 * hides evidence that a shipped file was altered, so a wrong click must
	 * not need a database edit to take back.
	 *
	 * @return array{undo: string}|\WP_Error
	 */
	public static function suppress( int $change_id, ?string $expected = null ) {
		$change = self::change( $change_id, false );

		if ( is_wp_error( $change ) ) {
			return $change;
		}

		/*
		 * Already marked, from another tab or by another administrator. A
		 * second marking wrote a second undo record that reporting the change
		 * again left open, and its token later took back a newer marking.
		 */
		if ( 'suppressed' === (string) $change->status ) {
			return new \WP_Error(
				'bettershield_change_already_suppressed',
				__( 'That change is already accepted.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( null !== $expected && ! hash_equals( $expected, \BetterShield\Abilities\WriteTriage::file_digest( $change ) ) ) { return \BetterShield\Abilities\WriteTriage::moved(); }

		$token = Ledger::open(
			self::SUPPRESS_UNDO,
			array(
				'change' => (int) $change->id,
				'status' => (string) $change->status,
			),
			array(
				'change' => (int) $change->id,
				'status' => 'suppressed',
			)
		);

		if ( null === $token ) {
			return new \WP_Error(
				'bettershield_undo_unavailable',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		if ( ! self::set_triage_status( $change, 'suppressed' ) ) { Ledger::mark_reverted( $token ); return \BetterShield\Abilities\WriteTriage::moved(); }
		self::take_back( (string) $change->path, '' );

		/*
		 * A critical added file that can run as code, silenced, is logged as
		 * loud as the arrival it hides, so it reaches the instant alert too
		 * (#2247). Any other acceptance is the routine decision it was.
		 */
		$loud = 'added' === (string) $change->change_type
			&& Packages::is_code( (string) $change->path )
			&& 'critical' === Scanner::grade_of( (string) $change->change_type, (string) $change->context, (string) $change->path, ! empty( $change->unconfirmed_update ), KnownWrites::EXPLAINED === (int) ( $change->unconfirmed_update ?? 0 ) );

		Writer::instance()->record(
			'file_change_suppressed',
			$loud ? Writer::SEVERITY_HIGH : Writer::SEVERITY_LOW,
			array(
				'object_type' => 'file',
				'object_id'   => (string) $change->path,
				'context'     => array(
					'change' => (string) $change->change_type,
					'undo'   => $token,
				),
			)
		);

		return array( 'undo' => $token );
	}

	/**
	 * Report a change marked expected again.
	 *
	 * Puts back the status it had before it was marked, from the undo record
	 * that marking wrote, and closes that record. A change marked before the
	 * record existed goes back to new.
	 *
	 * Every open record of a marking of the change is closed, not only the
	 * newest: one left open, as a second marking of the same change once left
	 * them, stayed live and later took back a newer marking. The status put
	 * back is the one the earliest of them replaced.
	 *
	 * @return true|\WP_Error
	 */
	public static function unsuppress( int $change_id ) {
		$change = self::change( $change_id, false );

		if ( is_wp_error( $change ) ) {
			return $change;
		}

		if ( 'suppressed' !== (string) $change->status ) {
			return new \WP_Error(
				'bettershield_change_not_suppressed',
				__( 'That change isn’t accepted.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$tokens = self::suppression_tokens( (int) $change->id );
		$entry  = array() !== $tokens ? Ledger::find( (string) end( $tokens ) ) : null;
		$prior  = null !== $entry && is_array( $entry->prior_state ) ? (string) ( $entry->prior_state['status'] ?? '' ) : '';

		// Marked as part of a batch rather than on its own: the batch's record
		// holds the status it replaced.
		if ( null === $entry ) {
			$prior = (string) ( Packages::held()[ (int) $change->id ] ?? '' );
		}

		$status = in_array( $prior, array( 'new', 'acknowledged' ), true ) ? $prior : 'new';

		if ( ! self::set_triage_status( $change, $status ) ) { return \BetterShield\Abilities\WriteTriage::moved(); }
		self::take_back( (string) $change->path, (string) $change->hash_after );

		foreach ( $tokens as $token ) {
			Ledger::mark_reverted( $token );
		}

		Writer::instance()->record(
			'file_change_unsuppressed',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'file',
				'object_id'   => (string) $change->path,
				'context'     => array( 'change' => (string) $change->change_type ),
			)
		);

		return true;
	}

	/**
	 * Take back a marking by the undo token it handed out.
	 *
	 * @return true|\WP_Error
	 */
	public static function revert_suppression( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::SUPPRESS_UNDO !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_undo', __( 'There is no such marking on record.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();

		return self::unsuppress( (int) ( $applied['change'] ?? 0 ) );
	}

	/**
	 * The changes marked expected on their own, by a marking still in force,
	 * after the undo record numbered `$after` was written.
	 *
	 * @return array<int, true> Keyed by change id.
	 */
	public static function marked_alone_since( int $after ): array {
		$marked = array();

		foreach ( Ledger::open_tokens( self::SUPPRESS_UNDO ) as $token ) {
			$entry = Ledger::find( (string) $token );

			if ( null === $entry ) {
				continue;
			}

			// Newest first, so every one after this is older still.
			if ( (int) $entry->id <= $after ) {
				break;
			}

			if ( is_array( $entry->applied_state ) ) {
				$marked[ (int) ( $entry->applied_state['change'] ?? 0 ) ] = true;
			}
		}

		return $marked;
	}

	/**
	 * The open undo records of a change's markings, newest first.
	 *
	 * @return string[]
	 */
	private static function suppression_tokens( int $change_id ): array {
		$tokens = array();

		foreach ( Ledger::open_tokens( self::SUPPRESS_UNDO ) as $token ) {
			$entry = Ledger::find( (string) $token );

			if ( null !== $entry && is_array( $entry->applied_state ) && $change_id === (int) ( $entry->applied_state['change'] ?? 0 ) ) {
				$tokens[] = (string) $token;
			}
		}

		return $tokens;
	}

	/**
	 * Whether a change has an official copy to be put back from, and why not.
	 *
	 * Asked before a button is drawn, so a restore that cannot work is never
	 * offered. Premium code, custom code, a file added by something that never
	 * published it: none of these have an official version, and a guess is
	 * worse than an honest "this one is yours to judge".
	 *
	 * @return array{restorable: bool, reason: string}
	 */
	public static function availability( object $change ): array {
		/*
		 * A whole package rather than one file. There is no single copy to
		 * write back, and the answer the owner actually wants — is this my own
		 * build, or somebody else's code — is one they give rather than one
		 * this can give them.
		 */
		if ( IncomingPackage::CHANGE_TYPE === (string) $change->change_type ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'This is a whole plugin, not one file. Review its files, then trust this version if you or your developer edited it.', 'bettershield' ),
			);
		}

		if ( 'added' === (string) $change->change_type ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'Look at each file. If you didn’t add one, move it to quarantine. Nothing is deleted, and you can put it back.', 'bettershield' ),
			);
		}

		/*
		 * Present, but this server will not let PHP read it. Nothing is wrong
		 * with the file and reinstalling would not touch the cause, so the
		 * remedy named is the actual one.
		 */
		if ( 'unreadable' === (string) $change->change_type ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'Your server blocks reading this file. Ask your host to make it readable, then check again.', 'bettershield' ),
			);
		}

		/*
		 * A file that is gone. The button used to be drawn for these and the
		 * preview used to promise the copy would be written back, but the
		 * guarded writer refuses a path that does not exist — deliberately, so
		 * that nothing is ever overwritten without its previous bytes captured
		 * first, and there are none to capture here. Refusing at the point the
		 * button is drawn is what this method exists for.
		 */
		if ( 'removed' === (string) $change->change_type ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'BetterShield can’t recreate missing files. Reinstall the plugin, theme or WordPress version it came from, then check again.', 'bettershield' ),
			);
		}

		/*
		 * Nothing published this, so there is no official copy to fetch and no
		 * "put it back" this plugin can honestly offer. Refused here, where the
		 * button is drawn, rather than downstream where the reader would meet
		 * a sentence about checksums for a file that was never going to have
		 * any — the theme, a drop-in, a commercial plugin, and the
		 * configuration files at the root of the site.
		 */
		if ( Unpublished::is_unpublished( (string) $change->context ) ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'BetterShield has no earlier copy of this file. Restore it from your backup or from the plugin or theme author.', 'bettershield' ),
			);
		}

		/*
		 * One of WPDeveloper's own paid plugins. Its publisher lists checksums,
		 * so the comparison is made, but the files themselves sit behind a
		 * license: there is no public copy this could fetch and write back.
		 */
		if ( Manifest::CONTEXT_PLUGIN === (string) $change->context && Manifest::from_publisher( (string) $change->slug ) ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'This file was checked against its publisher’s list, but the official copy needs your license. Reinstall the plugin from your account to put it back.', 'bettershield' ),
			);
		}

		if ( '' === (string) $change->version ) {
			return array(
				'restorable' => false,
				'reason'     => __( 'The version is unknown, so the official copy can’t be found. Update or reinstall it, then check again.', 'bettershield' ),
			);
		}

		/*
		 * Compared against a release that is not the one installed now, which
		 * is what an update between the comparison and this moment leaves
		 * behind. The official copy of that release is the wrong file: written
		 * into the release on disk it is old code calling what the new code
		 * took away. The next check compares against the installed release.
		 */
		$installed = Targets::installed_version(
			array(
				'context' => (string) $change->context,
				'slug'    => (string) ( $change->slug ?? '' ),
			)
		);

		if ( '' !== $installed && $installed !== (string) $change->version ) {
			return array(
				'restorable' => false,
				'reason'     => sprintf(
					/* translators: 1: the version the file was compared against, 2: the version installed now. */
					__( 'Version %2$s is installed now, not %1$s. Press Check Now to compare with the right version.', 'bettershield' ),
					(string) $change->version,
					$installed
				),
			);
		}

		return array(
			'restorable' => true,
			'reason'     => '',
		);
	}

	/* ---- fetching, and verifying what came back ------------------------ */

	/**
	 * The official bytes for this exact file at this exact version, verified
	 * against the published checksum before they are returned.
	 *
	 * @return string|\WP_Error
	 */
	private static function fetch_official( object $change ) {
		$available = self::availability( $change );

		if ( ! $available['restorable'] ) {
			return new \WP_Error( 'bettershield_not_restorable', $available['reason'], array( 'status' => 409 ) );
		}

		$manifest = Manifest::CONTEXT_CORE === (string) $change->context
			? Manifest::core()
			: Manifest::plugin( (string) $change->slug, (string) $change->version );

		if ( is_wp_error( $manifest ) ) {
			return $manifest;
		}

		$relative = self::relative_path( $change );
		$offered  = Manifest::hashes_for( $manifest, $relative );
		$expected = $offered[0] ?? null;

		if ( null === $expected ) {
			return new \WP_Error(
				'bettershield_not_published',
				__( 'This file is not in that version’s published list.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		// The cap travels with the request rather than being applied to what
		// came back: the check below can only refuse a body already resident in
		// memory, while this stops the transfer at the same number.
		$response = Http::get(
			self::source_url( $change, $relative ),
			array(
				'headers'             => array( 'Accept' => '*/*' ),
				'limit_response_size' => self::MAX_BYTES,
			)
		);

		if ( is_wp_error( $response ) ) {
			// An upstream failure is not this REST endpoint's own HTTP status.
			return new \WP_Error(
				'bettershield_official_unreachable',
				__( 'The official copy could not be fetched. Nothing was changed; try again later.', 'bettershield' ),
				array( 'status' => 502 )
			);
		}

		$body = (string) wp_remote_retrieve_body( $response );

		if ( '' === $body || strlen( $body ) > self::MAX_BYTES ) {
			return new \WP_Error(
				'bettershield_official_unusable',
				__( 'Nothing was changed: the official copy came back empty or too large.', 'bettershield' ),
				array( 'status' => 502 )
			);
		}

		/*
		 * The check that makes all of this safe. Whatever arrived is hashed
		 * with the algorithm its publisher used and compared against the
		 * published value. A mismatch means the bytes are not the official
		 * ones, whoever sent them and for whatever reason, and they go no
		 * further — writing them would turn a repair into an injection.
		 */
		$actual = hash( 'md5' === $manifest['algo'] ? 'md5' : 'sha256', $body );

		// Any hash the publisher offers for that path, not only the first:
		// where two tags map to one version the feed lists both, and refusing
		// the second would refuse a genuinely official copy.
		if ( ! Manifest::matches( $manifest, $relative, $actual ) ) {
			return new \WP_Error(
				'bettershield_official_mismatch',
				__( 'The downloaded copy did not match the published checksum, so nothing was written.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return $body;
	}

	/**
	 * Where one official file lives, at one released version.
	 */
	private static function source_url( object $change, string $relative ): string {
		if ( Manifest::CONTEXT_CORE === (string) $change->context ) {
			return sprintf(
				'https://core.svn.wordpress.org/tags/%s/%s',
				rawurlencode( (string) $change->version ),
				self::encode_path( $relative )
			);
		}

		return sprintf(
			'https://plugins.svn.wordpress.org/%s/tags/%s/%s',
			rawurlencode( (string) $change->slug ),
			rawurlencode( (string) $change->version ),
			self::encode_path( $relative )
		);
	}

	/** Each segment encoded, the separators left alone. */
	private static function encode_path( string $relative ): string {
		return implode( '/', array_map( 'rawurlencode', explode( '/', $relative ) ) );
	}

	/* ---- paths ---------------------------------------------------------- */

	/**
	 * The path as its publisher names it: relative to the WordPress root for
	 * core, relative to its own folder for a plugin.
	 */
	public static function relative_path( object $change ): string {
		$path = (string) $change->path;

		if ( Manifest::CONTEXT_CORE === (string) $change->context ) {
			return $path;
		}

		$prefix = 'wp-content/plugins/' . (string) $change->slug . '/';

		return 0 === strpos( $path, $prefix ) ? substr( $path, strlen( $prefix ) ) : $path;
	}

	/**
	 * Where a recorded path is on disk, or an empty string when the row does
	 * not name a place this installation can resolve.
	 *
	 * Asked again here even though the manifests filter their own keys, for
	 * the reason `Quarantine::stored_path()` gives for its containment check:
	 * this is the one place a stored string becomes a file operation, and a
	 * row can outlive the code that wrote it — a restored database, a
	 * half-finished migration, a hand edit. Refusing costs one condition.
	 *
	 * The root comes from the target the scan walked, not from ABSPATH and the
	 * prefix the row carries. On a site whose content directory is elsewhere
	 * those are two different files, and resolving against the wrong one is
	 * worse than failing: where a stale copy happened to sit under ABSPATH,
	 * that one was quarantined and overwritten and the change marked restored,
	 * while the altered file stayed exactly where it was.
	 */
	public static function absolute_path( object $change ): string {
		$path = (string) $change->path;

		if ( ! Manifest::is_safe_relative_path( $path ) ) {
			return '';
		}

		$context = (string) $change->context;
		$slug    = (string) $change->slug;

		foreach ( Targets::all() as $target ) {
			if ( $context !== (string) ( $target['context'] ?? '' ) || $slug !== (string) ( $target['slug'] ?? '' ) ) {
				continue;
			}

			$prefix = (string) ( $target['prefix'] ?? '' );

			if ( '' !== $prefix && 0 !== strpos( $path, $prefix ) ) {
				continue;
			}

			return untrailingslashit( (string) $target['root'] ) . '/' . substr( $path, strlen( $prefix ) );
		}

		/*
		 * Nothing on this site claims the file now — a plugin uninstalled
		 * between the scan and the click, most often. The layout is still the
		 * one the constants describe, so it is read from them rather than
		 * assembled from the recorded string.
		 */
		if ( Manifest::CONTEXT_CORE === $context ) {
			return untrailingslashit( ABSPATH ) . '/' . $path;
		}

		$prefix = 'wp-content/plugins/' . $slug . '/';

		return Manifest::CONTEXT_PLUGIN === $context && 0 === strpos( $path, $prefix )
			? untrailingslashit( WP_PLUGIN_DIR ) . '/' . $slug . '/' . substr( $path, strlen( $prefix ) )
			: '';
	}

	/**
	 * The refusal both callers of the above share.
	 */
	private static function unresolvable_path(): \WP_Error {
		return new \WP_Error(
			'bettershield_bad_path',
			__( 'That record names a file outside this WordPress installation, so nothing was read or written.', 'bettershield' ),
			array( 'status' => 400 )
		);
	}

	/* ---- the record ------------------------------------------------------ */

	/**
	 * @return object|\WP_Error
	 */
	private static function change( int $change_id, bool $must_be_open = true ) {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE site_id = 0 AND id = %d',
				Schema::table( 'integrity_changes' ),
				$change_id
			)
		);

		if ( null === $row ) {
			return new \WP_Error( 'bettershield_unknown_change', __( 'There is no such file change on record.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( $must_be_open && ! in_array( (string) $row->status, array( 'new', 'acknowledged' ), true ) ) {
			return new \WP_Error(
				'bettershield_change_not_open',
				__( 'That file change has already been dealt with.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return $row;
	}

	/**
	 * Whether the owner stopped ignoring this very copy of a file, which an
	 * adoption covering it must then leave open.
	 *
	 * @param string $path The file's path as a change row names it.
	 * @param string $hash The hash of the copy on disk now.
	 */
	public static function taken_back( string $path, string $hash ): bool {
		$stored = get_option( self::TAKEN_BACK_OPTION, array() );

		return '' !== $hash && is_array( $stored ) && $hash === ( $stored[ hash( 'sha256', $path ) ] ?? null );
	}

	/**
	 * Remember a copy the owner took back, or forget the file with ''.
	 */
	private static function take_back( string $path, string $hash ): void {
		$stored = get_option( self::TAKEN_BACK_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$key    = hash( 'sha256', $path );

		if ( '' === $hash && ! isset( $stored[ $key ] ) ) {
			return;
		}

		unset( $stored[ $key ] );

		if ( '' !== $hash ) {
			$stored[ $key ] = $hash;
			$stored         = array_slice( $stored, -self::TAKEN_BACK_MAX, null, true );
		}

		update_option( self::TAKEN_BACK_OPTION, $stored, false );
	}

	/**
	 * Open again the change a restore closed, now that the file it displaced
	 * is back.
	 *
	 * Found from what was put back rather than from a stored id: the restore's
	 * undo record names the file and its bytes, and the row the restore closed
	 * is the newest one marked put back for those bytes that resolves to that
	 * file. Nothing is reopened beside a row already open for the file; a
	 * check that ran in between has listed it there.
	 *
	 * @param string $absolute Where the file was put back.
	 * @param string $sha256   The bytes that were put back.
	 * @return bool Whether the difference is listed now.
	 */
	public static function reopen_put_back( string $absolute, string $sha256 ): bool {
		global $wpdb;

		if ( '' === $absolute || '' === $sha256 ) {
			return false;
		}

		/*
		 * A change is recorded with its manifest's digest: SHA-256 for the
		 * directory's packages, MD5 for core's checksums. Looked up by the
		 * kept copy's SHA-256 alone, a core file put back never had its
		 * difference listed again (#1830). The bytes now on disk are the
		 * bytes put back, so they give the MD5 to look for as well, and each
		 * row is held to its own algorithm.
		 */
		$md5   = (string) Manifest::hash_file( $absolute, 'md5' );
		$table = Schema::table( 'integrity_changes' );
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM %i WHERE site_id = 0 AND status = 'restored' AND hash_after IN ( %s, %s ) ORDER BY id DESC LIMIT 20",
				$table,
				$sha256,
				'' !== $md5 ? $md5 : $sha256
			)
		);

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$expected = 'md5' === (string) ( $row->algo ?? 'sha256' ) ? $md5 : $sha256;

			if ( '' === $expected || ! hash_equals( $expected, (string) $row->hash_after ) || self::absolute_path( $row ) !== $absolute ) {
				continue;
			}

			$open = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND path_hash = %s AND status IN ('new','acknowledged')",
					$table,
					(string) $row->path_hash
				)
			);

			if ( 0 === $open ) {
				self::set_status( (int) $row->id, 'new' );
			}

			return true;
		}

		return false;
	}

	/** Compare the exact state read before the ledger write, including a concurrent scan's checksum. */
	private static function set_triage_status( object $change, string $status ): bool {
		global $wpdb;
		return 1 === $wpdb->update( Schema::table( 'integrity_changes' ), array( 'status' => $status ), array( 'site_id' => 0, 'id' => (int) $change->id, 'status' => (string) $change->status, 'hash_after' => $change->hash_after, 'hash_before' => $change->hash_before ) );
	}

	private static function set_status( int $change_id, string $status ): void {
		global $wpdb;

		$wpdb->update(
			Schema::table( 'integrity_changes' ),
			array( 'status' => $status ),
			array(
				'site_id' => 0,
				'id'      => $change_id,
			),
			array( '%s' ),
			array( '%d', '%d' )
		);
	}

	/* ---- what differs ---------------------------------------------------- */

	/**
	 * How many lines one side of a comparison may have.
	 *
	 * Core's table renderer pairs changed lines up by comparing every line on
	 * one side against every line on the other, so what it holds is the
	 * product of the two counts rather than their sum. The count on the altered
	 * side is chosen by whoever altered the file, and padding costs them
	 * nothing: a file well inside the byte cap could still be thousands of
	 * lines, and the comparison of it a memory-limit fatal on the one file the
	 * owner most needed to look at.
	 */
	private const MAX_DIFF_LINES = 3000;

	/**
	 * And how many bytes, which bounds a file of very long lines the same way.
	 */
	private const MAX_DIFF_BYTES = 262144;

	/**
	 * Unchanged lines kept either side of the changed region, when only the
	 * region can be drawn.
	 *
	 * A changed line with nothing around it is a line out of context, and
	 * whether an edit is a developer's or an injection is usually decided by
	 * what sits beside it.
	 */
	private const DIFF_CONTEXT_LINES = 6;

	/**
	 * A unified diff of the file as it is against the file as published.
	 *
	 * Shown so the owner can decide rather than be told to trust a verdict:
	 * a changed file is sometimes a developer's edit and sometimes an
	 * injection, and the difference is visible in the lines.
	 *
	 * Binary content is not diffed — a screenful of mojibake helps nobody, and
	 * the hashes above it already say it differs.
	 */
	private static function diff( string $current, string $official, string $path, bool $whole = false ): string {
		if ( '' === $current ) {
			return __( 'This file is missing. Reinstall the plugin, theme or WordPress version it came from.', 'bettershield' );
		}

		if ( self::looks_binary( $current ) || self::looks_binary( $official ) ) {
			return __( 'This isn’t a text file, so the lines can’t be shown. It differs from the official copy.', 'bettershield' );
		}

		// Past the budget the whole file cannot be drawn. The part that
		// differs still can be, when it is small enough on its own.
		if ( self::too_much_to_compare( $current ) || self::too_much_to_compare( $official ) ) {
			return self::windowed( $current, $official, $path, true );
		}

		// Inside it, the part that differs is still what is drawn first: a
		// one-line change at the end of a long file was found only by
		// scrolling past every unchanged row, each read out as such.
		if ( ! $whole && self::partial( $current, $official ) ) {
			return self::windowed( $current, $official, $path, false );
		}

		return self::rendered( $current, $official, $path );
	}

	/**
	 * Whether drawing only the part that differs, with its context, leaves
	 * lines out, for a file that could be drawn whole.
	 */
	private static function partial( string $current, string $official ): bool {
		if ( '' === $current || self::looks_binary( $current ) || self::looks_binary( $official ) ) {
			return false;
		}

		if ( self::too_much_to_compare( $current ) || self::too_much_to_compare( $official ) ) {
			return false;
		}

		$bounds = self::changed_bounds( explode( "\n", $current ), explode( "\n", $official ) );

		return $bounds[0] > 0 || $bounds[1] > 0;
	}

	/**
	 * How many lines at the start and at the end both sides share, less the
	 * context kept either side of the change.
	 *
	 * @param string[] $now       The file as it stands, by line.
	 * @param string[] $published The published copy, by line.
	 * @return int[] The lines to leave off the start and off the end.
	 */
	private static function changed_bounds( array $now, array $published ): array {
		$shortest = min( count( $now ), count( $published ) );
		$head     = 0;

		while ( $head < $shortest && $now[ $head ] === $published[ $head ] ) {
			++$head;
		}

		$tail = 0;

		while ( $tail < $shortest - $head
			&& $now[ count( $now ) - 1 - $tail ] === $published[ count( $published ) - 1 - $tail ] ) {
			++$tail;
		}

		return array( max( 0, $head - self::DIFF_CONTEXT_LINES ), max( 0, $tail - self::DIFF_CONTEXT_LINES ) );
	}

	/**
	 * The changed region of two files too long to compare whole.
	 *
	 * What the line budget bounds is the table renderer, which pairs changed
	 * lines by comparing every line on one side against every line on the
	 * other — so what it holds is the product of the two counts. Trimming the
	 * run of identical lines off each end costs one pass over the file and
	 * leaves a region bounded by the size of the change rather than by the
	 * size of the file, which is what makes the biggest files drawable at all.
	 *
	 * It also does not reopen the hole the budget closed: padding a file adds
	 * lines that differ from the published copy, so it enlarges the region
	 * rather than moving it, and a file padded around its edit is refused here
	 * exactly as it was before.
	 */
	private static function windowed( string $current, string $official, string $path, bool $over = true ): string {
		$now       = explode( "\n", $current );
		$published = explode( "\n", $official );

		list( $head, $tail ) = self::changed_bounds( $now, $published );

		$window_now       = array_slice( $now, $head, count( $now ) - $head - $tail );
		$window_published = array_slice( $published, $head, count( $published ) - $head - $tail );

		$shown_now       = implode( "\n", $window_now );
		$shown_published = implode( "\n", $window_published );

		if ( self::too_much_to_compare( $shown_now ) || self::too_much_to_compare( $shown_published ) ) {
			return self::not_as_lines();
		}

		$rendered = self::rendered( $shown_now, $shown_published, $path );

		if ( self::not_as_lines() === $rendered ) {
			return $rendered;
		}

		// Which part of the file this is, because a table of lines with no
		// position in it is a comparison somebody has to go and locate by hand.
		// A final newline ends the last line rather than starting another.
		$lines = count( $now ) - ( '' === end( $now ) ? 1 : 0 );
		$note  = $over
			? sprintf(
				/* translators: 1: the first line number shown, 2: the last line number shown. */
				__( 'This file is long, so only the changed part is shown (lines %1$d to %2$d).', 'bettershield' ),
				$head + 1,
				$head + count( $window_now )
			)
			: sprintf(
				/* translators: 1: the first line number shown, 2: the last line number shown, 3: how many lines the file has. */
				__( 'This shows the part that differs and nearby lines: lines %1$d to %2$d of %3$d in this site’s copy.', 'bettershield' ),
				$head + 1,
				min( $head + count( $window_now ), $lines ),
				$lines
			);

		return '<p>' . esc_html( $note ) . '</p>' . $rendered;
	}

	/**
	 * Two strings through core's own differ, or the answer that says it could
	 * not be drawn.
	 */
	private static function rendered( string $current, string $official, string $path ): string {
		require_once ABSPATH . 'wp-admin/includes/revision.php';

		$rendered = wp_text_diff(
			$official,
			$current,
			array(
				/*
				 * Core drops this straight into a <caption> without escaping —
				 * a known quirk of `wp_text_diff()` rather than something to
				 * fix upstream, and one its own callers handle the same way.
				 * The lines either side of it are escaped by core's differ;
				 * the caption is not.
				 */
				'title'       => esc_html( $path ),
				'title_left'  => __( 'Official copy', 'bettershield' ),
				'title_right' => __( 'On your site now', 'bettershield' ),
			)
		);

		return is_string( $rendered ) && '' !== $rendered ? $rendered : self::not_as_lines();
	}

	/** What the hashes are left to say when the lines cannot say it. */
	private static function not_as_lines(): string {
		return __( 'The difference cannot be shown line by line.', 'bettershield' );
	}

	private static function looks_binary( string $contents ): bool {
		return false !== strpos( substr( $contents, 0, 8000 ), "\0" );
	}

	/** Whether one side is past what a line-by-line comparison can hold. */
	private static function too_much_to_compare( string $contents ): bool {
		return strlen( $contents ) > self::MAX_DIFF_BYTES
			|| substr_count( $contents, "\n" ) + 1 > self::MAX_DIFF_LINES;
	}
}
