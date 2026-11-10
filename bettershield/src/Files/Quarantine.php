<?php
/**
 * What is in quarantine, and the three things an owner can do about it.
 *
 * "Quarantine, never delete" is a locked principle and the mechanism honors
 * it: `Guarded::replace_verified()` writes the displaced bytes into an
 * uploads folder sealed against being served, and records where they went in
 * the undo ledger before the write happens. Then nothing — there was no way
 * to see what was in there, no way to fetch a copy, and no way to empty it.
 * The word reached the owner exactly twice, both times telling them a file
 * had gone somewhere they could not look.
 *
 * This is that door. It reads the ledger rather than the folder, because the
 * ledger is what knows *why* each file was displaced and what it was; a
 * directory listing would know only that something is there.
 *
 * Three rules shape it. Fetching is itself a security-relevant act — it hands
 * somebody the bytes of a file that was displaced for being altered — so it
 * is capability-gated and logged like any other. Deleting is per item, named,
 * and logged, because it is the one action here that cannot be undone. And
 * nothing is ever served from the quarantine folder: a copy is streamed
 * through this plugin as an attachment, never linked to.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Files;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Support\Server;
use BetterShield\Support\Time;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Quarantine {

	/**
	 * How many items a listing answers with. The folder is not a log and is
	 * not expected to grow without bound; a site with more than this has a
	 * bigger question than this screen answers.
	 */
	public const MAX_ITEMS = 200;

	/** How many ledger rows the archive's index reads at a time. */
	private const INDEX_PAGE = 500;

	/**
	 * The most copies one batch acts on: few enough that each still writes its
	 * own line in the log inside one request.
	 */
	public const BATCH_MAX = 50;

	/**
	 * How far one listing will walk past rows it cannot shape.
	 *
	 * Generous, because those rows are rare and skipping them is the point;
	 * bounded, because reading a whole ledger inside one request is not
	 * something a screen or an agent call may do.
	 */
	private const MAX_SCAN_ROWS = 1000;

	/**
	 * What the index of a packaged archive is called inside it.
	 *
	 * At the archive root, beside the `files/` tree, so that opening the zip
	 * shows the list before it shows the copies.
	 */
	public const INDEX_ENTRY = 'bettershield-quarantine-index.json';

	/**
	 * Names in the folder that are this plugin's seal against the folder being
	 * served, rather than anything kept for the owner. They are not packaged,
	 * and they are not what makes a folder non-empty.
	 */
	public const SEALS = array( 'index.php', 'index.html', '.htaccess' );

	/**
	 * The directory inside the quarantine folder that a hand-back is written
	 * to.
	 *
	 * Inside rather than beside it, because the archive holds every displaced
	 * copy — which is to say whatever somebody put on the site, plus an index
	 * naming every altered file — and a `.zip` in the uploads root is served
	 * to anyone who asks for it by name. A directory of its own rather than
	 * the quarantine folder itself, because the copies are taken out of that
	 * folder afterwards and its seal goes with them; the archive has to be
	 * still standing behind one when they are gone.
	 */
	public const HANDBACK_DIR = 'handback';

	/**
	 * What a folder this plugin writes into is sealed with, where the server
	 * reads it.
	 *
	 * `RedirectMatch` rather than `Require all denied`, for the reason the
	 * quarantine folder's own seal gives: it is the directive class core
	 * itself writes for permalinks, so a host serving pretty permalinks
	 * accepts it, while `Require` is a class a restrictive or older server
	 * answers with a 500.
	 */
	private const SEAL_RULES = 'RedirectMatch 404 ".*"';

	/**
	 * Everything currently in quarantine, newest first.
	 *
	 * Read from the ledger: every displaced file has a row naming where it
	 * came from, where it went, its size and its digest. A row whose file is
	 * no longer on disk is still listed, marked, rather than quietly dropped —
	 * something removed it, and that is worth seeing.
	 *
	 * `$before_id` continues an earlier page: only entries older than that
	 * ledger row. Each item carries the `ledger_id` a caller passes back.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function items( int $before_id = 0, int $limit = self::MAX_ITEMS ): array {
		return self::scan( $before_id, max( 1, min( $limit, self::MAX_ITEMS ) ) )['items'];
	}

	/**
	 * Ledger rows this listing is built from, newest first.
	 *
	 * @return array<int, object>
	 */
	private static function rows( int $before_id, int $limit ): array {
		global $wpdb;

		if ( $before_id > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own ledger table; read on an admin screen, and a cache would only be able to go stale against a delete this same class performs.
			return (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, token, action_key, prior_state, created_at, reverted_at FROM %i WHERE site_id = 0 AND prior_state LIKE %s AND id < %d ORDER BY id DESC LIMIT %d",
					Schema::table( 'undo' ),
					'%"mode":"replaced"%',
					$before_id,
					$limit
				)
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own ledger table; read on an admin screen, and a cache would only be able to go stale against a delete this same class performs.
		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, token, action_key, prior_state, created_at, reverted_at FROM %i WHERE site_id = 0 AND prior_state LIKE %s ORDER BY id DESC LIMIT %d",
				Schema::table( 'undo' ),
				'%"mode":"replaced"%',
				$limit
			)
		);
	}

	/**
	 * Walk the ledger until `$want` entries have been shaped, or it ends.
	 *
	 * A row can match the query and still not be a displaced file: `shape()`
	 * returns null for a `replaced` row whose stored state does not decode or
	 * names no copy, and those rows are the reason this walks rather than
	 * reads once. Counting raw rows instead would let a single unshapeable row
	 * at a page boundary report the listing as finished, which strands every
	 * older entry with nothing said — the failure paging was added to remove.
	 *
	 * The walk is bounded. On a ledger holding more unshapeable rows than the
	 * bound allows, it stops and says the listing is unfinished rather than
	 * reading the whole table inside one request, and the continuation carries
	 * the last row it looked at so the next call resumes instead of repeating.
	 *
	 * @return array{items: array<int, array<string, mixed>>, last_id: int, ended: bool}
	 */
	private static function scan( int $before_id, int $want ): array {
		$items    = array();
		$cursor   = $before_id;
		$examined = 0;
		$ended    = false;

		while ( count( $items ) < $want && $examined < self::MAX_SCAN_ROWS ) {
			$ask   = max( 1, min( self::MAX_ITEMS, $want - count( $items ) ) );
			$batch = self::rows( $cursor, $ask );

			if ( array() === $batch ) {
				$ended = true;
				break;
			}

			foreach ( $batch as $row ) {
				++$examined;
				$cursor = (int) $row->id;
				$item   = self::shape( $row );

				if ( null !== $item ) {
					$item['ledger_id'] = (int) $row->id;
					$items[]           = $item;
				}
			}

			if ( count( $batch ) < $ask ) {
				$ended = true;
				break;
			}
		}

		return array(
			'items'   => $items,
			'last_id' => $cursor,
			'ended'   => $ended,
		);
	}

	/**
	 * One page of the same listing, with what to ask for next.
	 *
	 * A cap with nothing to page past it makes the oldest entries unreachable
	 * to every caller that is not the screen — and a site with more than a
	 * page of displaced files is the mass-cleanup this feature exists for.
	 *
	 * @return array{items: array<int, array<string, mixed>>, next_before_id: int, has_more: bool}
	 */
	public static function page( int $before_id = 0, int $limit = self::MAX_ITEMS ): array {
		$limit = max( 1, min( $limit, self::MAX_ITEMS ) );

		// One past the page, so "there is more" is something this saw rather
		// than something it guessed from the next row along.
		$scan  = self::scan( $before_id, $limit + 1 );
		$items = $scan['items'];

		$overflowed = count( $items ) > $limit;
		$items      = array_slice( $items, 0, $limit );

		// Unfinished is unfinished either way: one entry past the page, or a
		// walk that stopped at its bound with ledger left.
		$more = $overflowed || ! $scan['ended'];
		$next = 0;

		if ( $more ) {
			$next = $overflowed ? (int) end( $items )['ledger_id'] : (int) $scan['last_id'];
		}

		return array(
			'items'          => $items,
			'next_before_id' => $next,
			'has_more'       => $more,
		);
	}

	/**
	 * One ledger row as this screen describes it, or null when the row is not
	 * a displaced file after all.
	 *
	 * @param object $row A row of the columns `items()` and `item()` select.
	 * @return array<string, mixed>|null
	 */
	private static function shape( object $row ): ?array {
		$prior = json_decode( (string) $row->prior_state, true );

		if ( ! is_array( $prior ) || 'replaced' !== ( $prior['mode'] ?? '' ) ) {
			return null;
		}

		$stored = (string) ( $prior['quarantine'] ?? '' );

		if ( '' === $stored ) {
			return null;
		}

		return array(
			'token'       => (string) $row->token,
			'action'      => (string) $row->action_key,
			// Where it was on the site, not where it is now: the quarantine
			// filename is an implementation detail and naming it on screen
			// invites somebody to go looking for it.
			//
			// Relative to the install, too. The ledger stores an absolute path
			// because that is what it has to write back to, but on a typical
			// host the absolute one names the hosting account, and that
			// belongs in nobody's screenshot or support ticket.
			'path'        => self::site_relative( (string) ( $prior['path'] ?? '' ) ),
			'size'        => (int) ( $prior['size'] ?? 0 ),
			'sha256'      => (string) ( $prior['sha256'] ?? '' ),
			'at'          => Time::utc_iso( (string) $row->created_at ),
			'restored'    => null !== $row->reverted_at,
			// When, so an entry already put back can say so rather than
			// offering a Put back that can only be refused.
			'restored_at' => null !== $row->reverted_at ? Time::utc_iso( (string) $row->reverted_at ) : null,
			'present'     => is_file( $stored ),
			// Altered code a restore or a response took out, which a put back
			// runs again; null for anything else (#2244).
			'code'        => null === $row->reverted_at && is_file( $stored ) ? self::code_of( (string) $row->token, (string) $row->action_key, (string) ( $prior['path'] ?? '' ) ) : null,
		);
	}

	/**
	 * What putting a kept copy back would bring back, where it is server code
	 * that a file check or an incident response took out: the published copy
	 * it differs from, and the incident whose response removed it.
	 *
	 * "Put This File Back" wrote tampered code over the clean official file
	 * with one press, no word of what it was or which incident took it out,
	 * and logged it as Medium (#2244). Null for anything else kept here,
	 * which a put back returns to as it was.
	 *
	 * @return array{against: string, incident: int}|null
	 */
	private static function code_of( string $token, string $action, string $absolute ): ?array {
		global $wpdb;

		if ( ! in_array( $action, array( 'integrity_restore', 'incident_quarantine' ), true ) || ! preg_match( '/\.(?:' . \BetterShield\Integrity\Packages::SERVER_PHP . ')\z/i', $absolute ) ) {
			return null;
		}

		$like    = '%' . $wpdb->esc_like( '"undo":"' . $token . '"' ) . '%';
		$against = '';

		// The restore's own row says which published copy replaced it.
		if ( 'integrity_restore' === $action ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own log; the site predicate is integers from Schema::site_where(), every value is bound.
			$context = $wpdb->get_var( $wpdb->prepare( 'SELECT context FROM %i WHERE ' . Schema::site_where( 'events' ) . " AND event_type = 'file_restored' AND context LIKE %s ORDER BY id DESC LIMIT 1", Schema::table( 'events' ), $like ) );
			$context = is_string( $context ) ? json_decode( $context, true ) : null;
			$version = is_array( $context ) ? (string) ( $context['version'] ?? '' ) : '';

			if ( is_array( $context ) && 'plugin' === ( $context['area'] ?? '' ) ) {
				$name    = \BetterShield\Integrity\Packages::name_of( 'plugin', (string) ( $context['slug'] ?? '' ) );
				$against = '' !== $version
					/* translators: 1: a plugin's name, 2: its version. */
					? sprintf( __( 'the official %1$s %2$s download', 'bettershield' ), $name, $version )
					/* translators: %s: a plugin's name. */
					: sprintf( __( 'the official %s download', 'bettershield' ), $name );
			} else {
				/* translators: %s: a WordPress version, e.g. 7.1.3. */
				$against = sprintf( __( 'WordPress %s', 'bettershield' ), '' !== $version ? $version : (string) get_bloginfo( 'version' ) );
			}
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own ledger table; one response receipt naming this copy's undo.
		$plan     = $wpdb->get_var( $wpdb->prepare( 'SELECT prior_state FROM %i WHERE site_id = 0 AND action_key = %s AND applied_state LIKE %s ORDER BY id DESC LIMIT 1', Schema::table( 'undo' ), \BetterShield\Incidents\Response::KEY, $like ) );
		$plan     = is_string( $plan ) ? json_decode( $plan, true ) : null;
		$incident = is_array( $plan ) ? (int) ( $plan['id'] ?? 0 ) : 0;

		return array(
			'against'  => $against,
			'incident' => $incident,
		);
	}

	/**
	 * One item's bytes, for an owner who wants to look at what was on their
	 * site — the forensics path, which until now meant SFTP.
	 *
	 * @return array{filename: string, bytes: string}|\WP_Error
	 */
	public static function fetch( string $token ) {
		$stored = self::stored_path( $token );

		if ( is_wp_error( $stored ) ) {
			return $stored;
		}

		$bytes = @file_get_contents( $stored ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reading a file this plugin put there itself.

		if ( false === $bytes ) {
			return new \WP_Error( 'bettershield_quarantine_unreadable', __( 'That copy could not be read.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$item = self::item( $token );

		/*
		 * Handing somebody the bytes of a file that was displaced for being
		 * altered is a security-relevant act in its own right, so it is
		 * recorded like one. The digest goes in the record; the contents never
		 * do.
		 */
		Writer::instance()->record(
			'quarantine_downloaded',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => (string) ( $item['path'] ?? '' ),
				'context'     => array(
					'sha256' => (string) ( $item['sha256'] ?? '' ),
					'size'   => (int) ( $item['size'] ?? 0 ),
				),
			)
		);

		return array(
			// Never the original extension: this is evidence being carried off
			// the site, not a file being put back into service anywhere.
			'filename' => 'bettershield-quarantined-' . substr( $token, 0, 12 ) . '.txt',
			'bytes'    => (string) $bytes,
		);
	}

	/**
	 * Remove one item for good.
	 *
	 * The only irreversible action in this plugin, which is why each copy is
	 * named, removed and recorded on its own, and nothing ever empties the
	 * folder: forget_many() is a short list of named copies, bounded and
	 * confirmed by its count, each removed exactly as here. The ledger row stays: it is the record that this
	 * happened, and deleting the record of a deletion is how a log becomes
	 * decoration. The row simply stops naming a file that exists.
	 *
	 * @return array{deleted: true}|\WP_Error
	 */
	public static function forget( string $token ) {
		$stored = self::stored_path( $token );

		if ( is_wp_error( $stored ) ) {
			return $stored;
		}

		$item = self::item( $token );

		if ( ! @unlink( $stored ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- a file this plugin created, in a folder it owns.
			return new \WP_Error( 'bettershield_quarantine_not_removed', __( 'That copy could not be removed.', 'bettershield' ), array( 'status' => 500 ) );
		}

		// No undo follows this one, so it goes out ahead of the digest rather
		// than in it: a week is too long to learn that the evidence itself was
		// destroyed.
		Writer::instance()->record(
			'quarantine_deleted',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'file',
				'object_id'   => (string) ( $item['path'] ?? '' ),
				'context'     => array(
					'sha256' => (string) ( $item['sha256'] ?? '' ),
					'size'   => (int) ( $item['size'] ?? 0 ),
				),
			)
		);

		return array( 'deleted' => true );
	}

	/**
	 * Put a displaced file back where it came from.
	 *
	 * The undo every restore generates, finally reachable: the token was
	 * ledgered and promised on screen from the first release, and nothing
	 * could invoke it — a reversible change with no way to reverse it is the
	 * plugin's own first principle broken where it is most visible. The
	 * guarded writer that displaced the file is what puts it back, byte for
	 * byte, so this is the same mechanism running backwards rather than a
	 * second one that has to agree with it.
	 *
	 * @return array{restored: true}|\WP_Error
	 */
	public static function put_back( string $token ) {
		$item = self::item( $token );

		if ( null === $item ) {
			return new \WP_Error(
				'bettershield_quarantine_unknown',
				__( 'There is no quarantined file with that name.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		// Read before the restore: once it succeeds the record is closed.
		$entry    = Ledger::find( $token );
		$absolute = null !== $entry && is_array( $entry->prior_state ) ? (string) ( $entry->prior_state['path'] ?? '' ) : '';
		$restored = Guarded::restore( $token );

		if ( is_wp_error( $restored ) ) {
			$restored->add_data( array( 'status' => 409 ) );

			return $restored;
		}

		/*
		 * The difference is back on disk, so the change a restore closed is
		 * open again rather than waiting for the next check to find it. Only
		 * a restore from the file check closed one.
		 */
		$reported = 'integrity_restore' === (string) ( $item['action'] ?? '' )
			&& \BetterShield\Integrity\Restore::reopen_put_back( $absolute, (string) ( $item['sha256'] ?? '' ) );

		/*
		 * Altered code back on disk is the change the file check reports as
		 * critical, and is recorded as one, so the instant alert carries it
		 * and the incident that took it out sees it come back (#2244).
		 */
		$code    = $item['code'] ?? null;
		$context = array( 'sha256' => (string) ( $item['sha256'] ?? '' ) );

		if ( is_array( $code ) ) {
			$context += array_filter( array( 'against' => $code['against'], 'incident' => $code['incident'] ) );
			self::evidence( (string) ( $item['path'] ?? '' ), (string) ( $item['sha256'] ?? '' ), $token );
		}

		Writer::instance()->record(
			'file_restore_undone',
			is_array( $code ) ? Writer::SEVERITY_CRITICAL : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => (string) ( $item['path'] ?? '' ),
				'context'     => $context,
			)
		);

		return array(
			'restored' => true,
			'reported' => $reported,
		);
	}

	/**
	 * Altered code put back, as evidence for the open incident it belongs
	 * to: the file check reported it when it first changed, and the
	 * reopened change is not read again, so the incident never saw it
	 * return.
	 */
	private static function evidence( string $path, string $sha256, string $token ): void {
		if ( '' === $path || ! Schema::ready( 'incidents' ) ) {
			return;
		}

		\BetterShield\Incidents\Repository::ingest(
			array(
				'source_key'  => hash( 'sha256', 'put_back:' . $token ),
				'occurred_at' => Time::stamp(),
				'anchor'      => '',
				'actor_id'    => 0,
				'event_type'  => 'incident_code_modified',
				'snapshot'    => array(
					'source'      => 'quarantine',
					'source_id'   => 0,
					'object_type' => 'file',
					'object_id'   => \BetterShield\Support\Text::clip( $path, 1024 ),
					'target_user' => 0,
					'details'     => array(
						'comparison'    => 'put_back',
						'sha256_or_md5' => $sha256,
					),
				),
			)
		);
	}

	/**
	 * Put several displaced files back, each exactly as one put back alone:
	 * its own guarded write, its own undo spent, its own line in the log. A
	 * file that cannot be put back is left as it is and named with the reason
	 * the single action gives, and the rest go on.
	 *
	 * @param string[] $tokens
	 * @return array{done: string[], skipped: array<string, string>, reported: int}|\WP_Error
	 */
	public static function put_back_many( array $tokens ) {
		$reported = 0;
		$result   = self::each(
			$tokens,
			static function ( string $token ) use ( &$reported ) {
				$done = self::put_back( $token );

				if ( is_array( $done ) && ! empty( $done['reported'] ) ) {
					++$reported;
				}

				return $done;
			}
		);

		return is_wp_error( $result ) ? $result : $result + array( 'reported' => $reported );
	}

	/**
	 * Remove several copies for good, each exactly as one removed alone: its
	 * own containment check, and its own record at high, which is the only
	 * trace a removal leaves. Only the copies named, never the folder.
	 *
	 * @param string[] $tokens
	 * @return array{done: string[], skipped: array<string, string>}|\WP_Error
	 */
	public static function forget_many( array $tokens ) {
		return self::each( $tokens, array( self::class, 'forget' ) );
	}

	/**
	 * One action on each named copy in turn, refused whole when the list is
	 * empty or past the bound rather than cut short.
	 *
	 * @param string[] $tokens
	 * @return array{done: string[], skipped: array<string, string>}|\WP_Error
	 */
	private static function each( array $tokens, callable $one ) {
		$tokens = array_values( array_unique( array_map( 'strval', $tokens ) ) );

		if ( array() === $tokens || count( $tokens ) > self::BATCH_MAX ) {
			return new \WP_Error(
				'bettershield_quarantine_batch_size',
				sprintf(
					/* translators: %d: the most kept copies one batch acts on. */
					__( 'Select 1 to %d kept copies at a time. Nothing was changed.', 'bettershield' ),
					self::BATCH_MAX
				),
				array( 'status' => 400 )
			);
		}

		$done    = array();
		$skipped = array();

		foreach ( $tokens as $token ) {
			$result = $one( $token );

			if ( is_wp_error( $result ) ) {
				$skipped[ $token ] = $result->get_error_message();
				continue;
			}

			$done[] = $token;
		}

		return array(
			'done'    => $done,
			'skipped' => $skipped,
		);
	}

	/**
	 * An absolute path as the site would name it.
	 *
	 * Public because the audit names the quarantine folder to the owner and
	 * has to name the same place this class reads and writes — a site that
	 * moved its uploads, or any subsite of a network, keeps them somewhere
	 * other than `wp-content/uploads`.
	 */
	public static function site_relative( string $path ): string {
		$root = untrailingslashit( ABSPATH );

		if ( '' !== $root && str_starts_with( $path, $root . '/' ) ) {
			return substr( $path, strlen( $root ) + 1 );
		}

		// Outside the install — wp-config.php one directory up is the case
		// this exists for. The basename alone says which file without saying
		// where the account lives.
		return basename( $path );
	}

	/**
	 * One item by token, whether or not it is on the current page.
	 *
	 * Its own query rather than a walk of `items()`, which is a listing and is
	 * capped at `MAX_ITEMS`. Reading a single item out of that page meant the
	 * older ones could not be put back at all, and the two actions that reach
	 * the file by token anyway — fetching a copy, and deleting one — recorded
	 * that they had happened without naming the file. The record of a deletion
	 * is the only trace the deletion leaves.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function item( string $token ): ?array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own ledger table; one row by token, immediately before an action on the file it names.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT token, action_key, prior_state, created_at, reverted_at FROM %i WHERE site_id = 0 AND token = %s',
				Schema::table( 'undo' ),
				$token
			)
		);

		return null === $row ? null : self::shape( $row );
	}

	/**
	 * The on-disk path a token names, once it is established that the token is
	 * one of ours and the path is inside the folder this plugin owns.
	 *
	 * @return string|\WP_Error
	 */
	private static function stored_path( string $token ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- as above; one row, by token, immediately before a file operation that must not act on a cached answer.
		$prior = (string) $wpdb->get_var(
			$wpdb->prepare( 'SELECT prior_state FROM %i WHERE site_id = 0 AND token = %s', Schema::table( 'undo' ), $token )
		);

		$state = json_decode( $prior, true );

		if ( ! is_array( $state ) || 'replaced' !== ( $state['mode'] ?? '' ) ) {
			return new \WP_Error( 'bettershield_quarantine_unknown', __( 'No such quarantined file.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$stored = (string) ( $state['quarantine'] ?? '' );
		$folder = untrailingslashit( (string) wp_upload_dir()['basedir'] ) . '/' . Guarded::QUARANTINE_DIR;

		/*
		 * The path came out of this plugin's own ledger, so this is belt and
		 * braces — but it is the one place a stored string becomes a file
		 * operation, and a containment check is one condition.
		 */
		$real   = realpath( $stored );
		$inside = false !== $real && false !== realpath( $folder ) && str_starts_with( $real, realpath( $folder ) . DIRECTORY_SEPARATOR );

		if ( ! $inside || ! is_file( $real ) ) {
			return new \WP_Error( 'bettershield_quarantine_missing', __( 'That copy is no longer on this site.', 'bettershield' ), array( 'status' => 404 ) );
		}

		return $real;
	}

	/**
	 * The folder the displaced copies are kept in, or an empty string where
	 * this site has no uploads folder to keep them in.
	 *
	 * Public because uninstall reaches for it with the plugin's classes loaded
	 * but nothing else booted, and because a site that moved its uploads keeps
	 * quarantine somewhere other than `wp-content/uploads`.
	 */
	public static function folder(): string {
		$uploads = wp_upload_dir();

		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}

		return untrailingslashit( (string) $uploads['basedir'] ) . '/' . Guarded::QUARANTINE_DIR;
	}

	/**
	 * How many copies are in the folder right now.
	 *
	 * Counted from the folder rather than from the ledger, because this answers
	 * a question about files: it is what an owner is offered a copy of, and
	 * what removal would take. A ledger row whose file something else already
	 * removed is not a copy anybody can be handed.
	 *
	 * Counted without the listing bound. The number is what an owner decides
	 * the third answer on, and bounded it said the bound: a folder holding
	 * more than one archive takes reported the archive's worth, and the
	 * copies past it went unmentioned right up to the moment they were
	 * correctly left behind.
	 */
	public static function count(): int {
		return count( self::folder_files( 0 ) );
	}

	/** What the web server answered for a kept copy, when it was last asked. */
	public const SERVED_OPTION = 'bettershield_quarantine_served';

	/**
	 * How long that answer stands before the folder is reported again: a
	 * little over the week between the weekly sweep's questions, so an answer
	 * the sweep keeps fresh never lapses between two of them.
	 */
	private const SERVED_FOR = 8 * DAY_IN_SECONDS;

	/**
	 * The answers a seal is read from: forbidden, not there, gone. A sign-in
	 * prompt is somebody standing in front of the whole site, not a rule
	 * about this folder.
	 */
	private const REFUSALS = array( 403, 404, 410 );

	/**
	 * Ask the web server whether it serves a kept copy, and keep its answer.
	 *
	 * The deny rule this plugin writes is Apache's, so on nginx and IIS the
	 * folder is reported unsealed however the owner configured the server:
	 * denying the folder there, which the finding names as the fix, changed
	 * nothing the finding read. So, when a person runs an audit, the server
	 * is asked for one kept copy, over this site's own address. Only the
	 * status is kept; the body is never read past its first byte, stored or
	 * logged, and this is not a download of the evidence.
	 *
	 * Not asked on every audit: an audit runs on many requests, and asking
	 * the server is a request of its own. Asked by a person's audit and by
	 * the weekly sweep, and not where the rule is known to be in force, or
	 * nothing is kept.
	 *
	 * Not asked, and nothing forgotten, where this request cannot name its
	 * server — WP-CLI has no web server in front of it — because the answer
	 * is about the web server, and the one it has is the web's.
	 */
	public static function ask_the_server(): void {
		if ( Server::UNKNOWN === Server::kind() ) {
			return;
		}

		if ( 0 === self::count() || false !== Guarded::quarantine_is_sealed() ) {
			delete_option( self::SERVED_OPTION );

			return;
		}

		$files     = self::folder_files( 1 );
		$uploads   = wp_upload_dir( null, false );
		$base_url  = isset( $uploads['baseurl'] ) ? (string) $uploads['baseurl'] : '';
		$base      = (string) wp_parse_url( $base_url, PHP_URL_PATH );
		$home      = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$same_host = strtolower( (string) wp_parse_url( $base_url, PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );

		// Where uploads are served from another host, a CDN or an upload
		// address of its own, or from outside this site's own address, there
		// is no honest request to make: the path asked of the origin is not
		// the one a stranger is served.
		if ( array() === $files || '' === $base || ! $same_host || ( '' !== trim( $home, '/' ) && ! str_starts_with( $base, untrailingslashit( $home ) . '/' ) ) ) {
			delete_option( self::SERVED_OPTION );

			return;
		}

		$relative = ltrim( substr( $base, strlen( untrailingslashit( $home ) ) ), '/' );
		$response = \BetterShield\Support\Http::same_site( $relative . '/' . Guarded::QUARANTINE_DIR . '/' . rawurlencode( basename( $files[0] ) ), array( 'limit_response_size' => 1 ) );
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );

		// A refusal is believed only where the same server answers its own
		// REST root. A firewall or a CDN rule that refuses this server's own
		// address refuses every path, and a stranger may still be served the
		// copy.
		if ( in_array( $code, self::REFUSALS, true ) && ! self::answers_itself() ) {
			$code = 0;
		}

		update_option(
			self::SERVED_OPTION,
			array(
				'code'   => $code,
				'at'     => time(),
				'server' => Server::kind(),
			),
			false
		);
	}

	/** Whether this server answers its own REST root, the control a refusal is read against. */
	private static function answers_itself(): bool {
		$control = \BetterShield\Audit\XmlRpc::relative_to_home( rest_url() );

		if ( null === $control ) {
			return false;
		}

		$check = \BetterShield\Support\Http::same_site( $control, array( 'headers' => array( 'Accept' => 'application/json' ) ) );

		return ! is_wp_error( $check ) && 200 === (int) wp_remote_retrieve_response_code( $check );
	}

	/**
	 * Whether the web server itself refused a kept copy, recently, on the
	 * server this site runs on now. A request that did not complete, or any
	 * answer that is not a refusal, is not a seal.
	 */
	public static function server_refuses(): bool {
		$served = get_option( self::SERVED_OPTION );
		$kind   = Server::kind();

		return is_array( $served )
			&& in_array( (int) ( $served['code'] ?? 0 ), self::REFUSALS, true )
			&& time() - (int) ( $served['at'] ?? 0 ) < self::SERVED_FOR
			// The server it was asked on, compared only where this request
			// can name its own: WP-CLI reads the web's answer as it stands.
			&& ( Server::UNKNOWN === $kind || $kind === (string) ( $served['server'] ?? '' ) );
	}

	/**
	 * Package every quarantined copy into one archive the owner can take away.
	 *
	 * The point is the hand-back: "quarantine, never delete" means the copies
	 * outlive the plugin, and an owner who wants the folder gone is owed what
	 * was in it first. Nothing is removed here — packaging and removing are
	 * two acts, and only the caller that got an archive out of this one is in
	 * a position to perform the second.
	 *
	 * Entries are named for where each file was on the site, so the archive
	 * reads as the tree it was taken from; the quarantine filename is this
	 * plugin's bookkeeping and means nothing to whoever opens it. An index
	 * beside them carries what the names cannot: when each copy was displaced,
	 * its digest, its size, and whether it was put back since.
	 *
	 * Bounded at `MAX_ITEMS`, and it says which copies it took: a folder
	 * holding more than one archive's worth is the one case where packaging
	 * and removing part ways, and a caller that removed the folder on the
	 * strength of the count alone would destroy the copies that did not fit.
	 *
	 * The archive lands inside the quarantine folder, in a sealed directory
	 * of its own and under a name that carries twenty random characters. It
	 * is retrieved by whoever has file access to the site — over SFTP, or
	 * through a host's file manager — and never over the web: nothing here
	 * links to it, and at the one moment this runs from the uninstall script
	 * there is no longer a plugin to serve it through.
	 *
	 * @return array{path: string, count: int, packaged: array<int, string>}|\WP_Error
	 */
	public static function package() {
		$folder = self::folder();

		if ( '' === $folder ) {
			return new \WP_Error(
				'bettershield_quarantine_no_uploads',
				__( 'This site has no uploads folder to write the archive to.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		$files = self::folder_files();

		if ( array() === $files ) {
			return new \WP_Error(
				'bettershield_quarantine_empty',
				__( 'There is nothing in quarantine to package.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		$known   = self::stored_index( array_map( 'basename', $files ) );
		$entries = array();
		$listed  = array();

		foreach ( $files as $path ) {
			$name = basename( $path );
			$item = $known[ $name ] ?? null;
			$was  = null === $item ? '' : (string) $item['path'];

			/*
			 * Two copies of the same file — a restore undone and redone — would
			 * otherwise claim one entry and the second would replace the first.
			 * The loser keeps its stored name, which is unique in the folder by
			 * construction, and the index says which original it belongs to.
			 */
			$entry = 'files/' . ( '' === $was ? $name : ltrim( $was, '/' ) );

			if ( isset( $entries[ $entry ] ) ) {
				$entry = 'files/' . $name;
			}

			$entries[ $entry ] = $path;
			$listed[]          = array(
				'entry'          => $entry,
				'path'           => $was,
				// Read from disk only for a copy the ledger no longer names; a
				// file that went between the walk and here is an ordinary result
				// and is reported as a zero rather than warned about with a path.
				'size'           => null === $item ? (int) @filesize( $path ) : (int) $item['size'], // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				'sha256'         => null === $item ? (string) @hash_file( 'sha256', $path ) : (string) $item['sha256'], // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				'quarantined_at' => null === $item ? '' : (string) $item['at'],
				'restored'       => null !== $item && (bool) $item['restored'],
			);
		}

		$index = (string) wp_json_encode(
			array(
				'generated_at' => gmdate( 'c' ),
				'count'        => count( $listed ),
				'files'        => $listed,
			)
		);

		$directory = $folder . '/' . self::HANDBACK_DIR;

		if ( ! is_dir( $directory ) && ! wp_mkdir_p( $directory ) ) {
			return self::not_packaged();
		}

		self::seal( $directory );

		/*
		 * Named for the moment it was made and for twenty characters no clock
		 * can produce. The seal above is what stands where the server reads
		 * it; where it is inert, a name anybody could compute from the folder
		 * and the minute would be the whole of the protection — which is why
		 * every stored copy already carries one.
		 */
		$archive = $directory . '/bettershield-quarantine-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 20, false, false ) . '.zip';

		// Core carries its own zip writer for hosts without the extension, and
		// it is loaded the same way core's own updater loads it.
		$written = class_exists( '\\ZipArchive' )
			? self::write_with_zip_archive( $archive, $entries, $index )
			: self::write_with_pclzip( $archive, $entries, $index );

		if ( is_wp_error( $written ) ) {
			return $written;
		}

		/*
		 * Handing somebody the bytes of files displaced for having been altered
		 * is a security-relevant act, recorded like one — the same record a
		 * single copy leaves. Nothing is written where this runs from the
		 * uninstall script: the writer has stood down by then, and where the
		 * archive is written is what the readme is for.
		 */
		Writer::instance()->record(
			'quarantine_downloaded',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => self::site_relative( $archive ),
				'context'     => array( 'count' => count( $entries ) ),
			)
		);

		return array(
			'path'     => $archive,
			'count'    => count( $entries ),
			'packaged' => array_values( $entries ),
		);
	}

	/**
	 * Make a folder this plugin wrote unreachable and unlistable.
	 *
	 * Best effort by design, exactly as the quarantine folder's own seal is:
	 * on a server that honors neither, the random component in the archive's
	 * name is what is left. Anything already at either name is somebody
	 * else's and is left alone.
	 */
	private static function seal( string $directory ): void {
		if ( ! is_file( $directory . '/index.php' ) ) {
			@file_put_contents( $directory . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- a folder this plugin created; a seal that could not be written is reported by the folder being listable, not by a path in a log.
		}

		/*
		 * Only a server that says it ignores the file stops the write. One
		 * that names itself as nothing recognizable — WP-CLI, where every
		 * command-line deletion runs, and some FPM setups — is not evidence
		 * the rule would be inert, and treating it as such would leave the
		 * archive with an index file and nothing else on Apache.
		 */
		if ( false === Server::honors_htaccess() || is_file( $directory . '/.htaccess' ) ) {
			return;
		}

		@file_put_contents( $directory . '/.htaccess', self::SEAL_RULES . "\n" ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- as above.
	}

	/**
	 * Every copy in the folder, absolute, bounded by `MAX_ITEMS`.
	 *
	 * Read from the folder rather than from the ledger because this is the set
	 * of files that would be removed: a copy whose ledger row was pruned is
	 * still somebody's evidence, and a hand-back that missed it would delete
	 * the only remaining version of a file.
	 *
	 * @param int $bound How many to stop at, or 0 for all of them.
	 * @return array<int, string>
	 */
	private static function folder_files( int $bound = self::MAX_ITEMS ): array {
		$folder = self::folder();

		if ( '' === $folder || ! is_dir( $folder ) ) {
			return array();
		}

		$names = @scandir( $folder ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable folder is an empty answer here, not a path to print into a log.

		if ( false === $names ) {
			return array();
		}

		sort( $names );
		$files = array();

		foreach ( $names as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}

			// The seals this plugin writes into the folder to keep it from
			// being served are its own, not anything an owner was kept a copy
			// of.
			if ( in_array( $name, self::SEALS, true ) ) {
				continue;
			}

			$path = $folder . '/' . $name;

			// A link here is not a quarantined copy, and following one would
			// put a file from outside the folder into the archive — or remove
			// it later, on the strength of a name somebody else chose.
			if ( is_link( $path ) || ! is_file( $path ) ) {
				continue;
			}

			$files[] = $path;

			if ( $bound > 0 && count( $files ) >= $bound ) {
				break;
			}
		}

		return $files;
	}

	/**
	 * What the ledger knows about these copies, keyed by the name on disk.
	 *
	 * Keyed by name rather than by path because the two spellings of the same
	 * folder — the one the ledger stored and the one this site reports today —
	 * need not match on a host that moved its uploads or symlinks its temp
	 * directory, and the name carries enough randomness to be unique in a
	 * folder without help.
	 *
	 * Read for the copies being packaged, newest row first, page after page
	 * until each is found or the ledger runs out. One page of the newest rows
	 * missed the oldest copies, which are the ones packaged first, once more
	 * than a page of files had ever been displaced; they went into the
	 * archive with no path and no date, and the ledger was dropped after.
	 *
	 * @param array<int, string> $names The names on disk to find.
	 * @return array<string, array<string, mixed>>
	 */
	private static function stored_index( array $names ): array {
		global $wpdb;

		$wanted = array_fill_keys( $names, true );
		$index  = array();
		$before = PHP_INT_MAX;

		while ( array() !== $wanted ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own ledger table; read immediately before the files it names are packaged.
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT id, token, action_key, prior_state, created_at, reverted_at FROM %i WHERE site_id = 0 AND prior_state LIKE %s AND id < %d ORDER BY id DESC LIMIT %d",
					Schema::table( 'undo' ),
					'%"mode":"replaced"%',
					$before,
					self::INDEX_PAGE
				)
			);

			foreach ( $rows as $row ) {
				$before = (int) $row->id;
				$item   = self::shape( $row );
				$prior  = json_decode( (string) $row->prior_state, true );

				if ( null === $item || ! is_array( $prior ) ) {
					continue;
				}

				$stored = basename( (string) ( $prior['quarantine'] ?? '' ) );

				if ( isset( $wanted[ $stored ] ) ) {
					$index[ $stored ] = $item;
					unset( $wanted[ $stored ] );
				}
			}

			if ( count( $rows ) < self::INDEX_PAGE ) {
				break;
			}
		}

		return $index;
	}

	/**
	 * @param array<string, string> $entries Archive entry name => absolute path.
	 * @return true|\WP_Error
	 */
	private static function write_with_zip_archive( string $archive, array $entries, string $index ) {
		$zip = new \ZipArchive();

		if ( true !== $zip->open( $archive, \ZipArchive::CREATE | \ZipArchive::OVERWRITE ) ) {
			return self::not_packaged();
		}

		$added = $zip->addFromString( self::INDEX_ENTRY, $index );

		foreach ( $entries as $entry => $path ) {
			$added = $zip->addFile( $path, $entry ) && $added;
		}

		// Closing is where the bytes are read, so a file that went away between
		// the add and here fails there rather than above.
		if ( ! $zip->close() || ! $added ) {
			if ( is_file( $archive ) ) {
				@unlink( $archive ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- removing a half-written archive this method just created; the refusal below is the report.
			}

			return self::not_packaged();
		}

		return true;
	}

	/**
	 * @param array<string, string> $entries Archive entry name => absolute path.
	 * @return true|\WP_Error
	 */
	private static function write_with_pclzip( string $archive, array $entries, string $index ) {
		require_once ABSPATH . 'wp-admin/includes/class-pclzip.php';

		$list = array(
			array(
				PCLZIP_ATT_FILE_NAME    => self::INDEX_ENTRY,
				PCLZIP_ATT_FILE_CONTENT => $index,
			),
		);

		foreach ( $entries as $entry => $path ) {
			$list[] = array(
				PCLZIP_ATT_FILE_NAME          => $path,
				PCLZIP_ATT_FILE_NEW_FULL_NAME => $entry,
			);
		}

		$zip     = new \PclZip( $archive );
		$written = $zip->create( $list );

		if ( ! is_array( $written ) || count( $written ) !== count( $list ) ) {
			if ( is_file( $archive ) ) {
				@unlink( $archive ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- removing a half-written archive this method just created; the refusal below is the report.
			}

			return self::not_packaged();
		}

		return true;
	}

	/**
	 * One refusal for both writers: what went wrong inside a zip library is not
	 * something to put on a screen, and the consequence is the same either way
	 * — there is no archive, so nothing may be removed.
	 */
	private static function not_packaged(): \WP_Error {
		return new \WP_Error(
			'bettershield_quarantine_not_packaged',
			__( 'The archive could not be written, so no copies were removed.', 'bettershield' ),
			array( 'status' => 500 )
		);
	}
}
