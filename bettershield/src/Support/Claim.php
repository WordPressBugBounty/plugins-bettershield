<?php
/**
 * Claim: the one place this plugin decides which request goes first.
 *
 * Nearly every "do this once" in a web application is written as three steps
 * — read the state, decide, write it back — and between the read and the
 * write the state is still what it was. A second request arriving in that
 * window reads the same thing, reaches the same decision, and acts too. One
 * unlock email becomes two, a counter capped at ten admits twelve, a token
 * good for one use is spent twice.
 *
 * None of the usual candidates can arbitrate that here. A transient is a read
 * followed by a write, which is the shape of the problem rather than a way
 * out of it. `add_option` overwrites the other claimant instead of losing to
 * it. `wp_cache_add` is genuinely atomic, but only where a persistent object
 * cache is installed, and nothing in this plugin may assume one.
 *
 * What can arbitrate is the database. Every answer here is a single statement
 * whose outcome the database decides — a unique key that admits one INSERT,
 * or an UPDATE reporting how many rows it actually changed — so the answer is
 * the same whether the two requests are milliseconds or microseconds apart.
 *
 * Keys are the caller's own namespace and mean nothing here. A key belongs to
 * the site whose table it lands in, so on a network each subsite claims
 * independently; a caller needing one answer for a whole network is not
 * served by this.
 *
 * These rows are working state, not a record of anything. They expire, and
 * the daily prune removes them in bounded batches like any other.
 *
 * **A statement that does not run has two right answers, and the caller picks
 * one.** `bump()` and `count()` answer as though nothing were counted, which
 * is right for a limit on volume. `bump_or_fail()` and `count_or_fail()`
 * answer null, and the caps standing in front of a credential refuse on it:
 * a wrong-code cap that cannot count is an offer to guess a second factor as
 * often as you like. Those two try to put a missing table back first.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Audit\Auditor;
use BetterShield\Database\Schema;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Claim {

	/** Where the audit reads that a statement here could not run. */
	private const FAILED_OPTION = 'bettershield_claims_failed';

	/**
	 * What the database said about the last statement, captured while it was
	 * still the last thing the database had said. Anything at all in between —
	 * a conditional tag, an option read — replaces it.
	 */
	private static string $last_failure = '';

	/** Whether this request has already reported the records as unreadable. */
	private static bool $reported = false;

	/** Whether this request has already looked at the flag above. */
	private static bool $flag_read = false;

	/**
	 * Forget what this request has already recorded. Production never needs
	 * this — the state lives and dies with the request — but the test process
	 * is many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::$last_failure = '';
		self::$reported     = false;
		self::$flag_read    = false;
	}

	/**
	 * Take a key for a while.
	 *
	 * True means this request holds it and no other does. False means someone
	 * else holds it and has not finished — so the caller should do nothing,
	 * rather than doing it a second time.
	 *
	 * The INSERT is refused by the unique key when the key is already held,
	 * and the UPDATE that follows takes the key over only if what is there has
	 * lapsed. Both are decided by the database, and a request that loses both
	 * has genuinely lost. A caller that cannot afford to act twice should
	 * treat a database that will not answer as a loss, which is what returning
	 * false on error does.
	 */
	public static function claim( string $key, int $ttl_seconds ): bool {
		global $wpdb;

		$table   = Schema::table( 'claims' );
		$now     = self::stamp( time() );
		$expires = self::stamp( time() + max( 1, $ttl_seconds ) );

		$inserted = self::quietly(
			$wpdb->prepare(
				'INSERT INTO %i (claim_key, count, created_at, expires_at) VALUES (%s, 1, %s, %s)',
				$table,
				$key,
				$now,
				$expires
			)
		);

		if ( 1 === $inserted ) {
			return true;
		}

		// Somebody holds it. It is available only if theirs has lapsed, and
		// the row count is what says whether this request is the one that
		// took it over — two requests finding the same lapsed row, only one
		// of them changes it.
		return 1 === self::quietly(
			$wpdb->prepare(
				'UPDATE %i SET created_at = %s, expires_at = %s, count = 1 WHERE claim_key = %s AND expires_at <= %s',
				$table,
				$now,
				$expires,
				$key,
				$now
			)
		);
	}

	/**
	 * Give a key back before its time is up, so a retry need not wait out the
	 * window. Only the holder should call this, and only on a path where what
	 * the claim guarded did not happen.
	 */
	public static function release( string $key ): void {
		global $wpdb;

		self::quietly(
			$wpdb->prepare(
				'DELETE FROM %i WHERE claim_key = %s',
				Schema::table( 'claims' ),
				$key
			)
		);
	}

	/**
	 * Count one occurrence in a fixed window and answer how many are in it,
	 * this one included. The caller compares that to its own cap.
	 *
	 * The window is fixed, not sliding: it opens when the first occurrence
	 * lands and closes on time regardless of what arrives inside it. That is
	 * the difference between "twenty an hour" and "twenty, then quiet for an
	 * hour", and writing it as a transient gets the second one by accident,
	 * because storing a value refreshes its lifetime.
	 *
	 * Returns 1 if the row could not be written, so a database that will not
	 * answer refuses nobody. That is the right trade for a limit on volume —
	 * how many challenges an hour, how many explanations a day — and the wrong
	 * one for a limit standing in front of a credential, where it would hand
	 * out an unlimited guessing budget. Those callers use `bump_or_fail()`.
	 */
	public static function bump( string $key, int $ttl_seconds ): int {
		return self::run_bump( $key, $ttl_seconds ) ?? 1;
	}

	/**
	 * The same count, for a caller that must refuse when it cannot be taken.
	 *
	 * Null means the statement did not run, so there is nowhere to count and
	 * therefore no cap. A duplicate key is not that: it is this class's whole
	 * mechanism answering, and it comes back as a number like any other.
	 *
	 * A missing table is the one failure worth trying to mend rather than only
	 * reporting — it happens between an update landing and the migration
	 * running, and it happens afterwards, and either way the caps above it
	 * are refusing sign-ins until it is fixed. So the statement is run again
	 * once the installer has had its chance, and only then is the answer null.
	 */
	public static function bump_or_fail( string $key, int $ttl_seconds ): ?int {
		return self::insisting(
			static function () use ( $key, $ttl_seconds ): ?int {
				return self::run_bump( $key, $ttl_seconds );
			}
		);
	}

	/**
	 * The same count, refusing as `bump_or_fail()` does, in a window that
	 * stays open while occurrences keep arriving.
	 *
	 * For a count of things in flight rather than things done, which goes up
	 * on the way in and back down through `give_back()`. A fixed window closes
	 * on time whatever it holds, and the next occurrence then starts from one
	 * while the ones counted before it are still running — so whoever knows
	 * when the window opened can send a second full count across its close.
	 * Here each occurrence moves the close, and the count starts over only
	 * after a whole window with nothing arriving.
	 */
	public static function hold_or_fail( string $key, int $ttl_seconds ): ?int {
		return self::insisting(
			static function () use ( $key, $ttl_seconds ): ?int {
				return self::run_bump( $key, $ttl_seconds, true );
			}
		);
	}

	/**
	 * Count one occurrence, or null when the statement did not run.
	 *
	 * @param bool $sliding Whether this occurrence moves the window's close.
	 */
	private static function run_bump( string $key, int $ttl_seconds, bool $sliding = false ): ?int {
		global $wpdb;

		$now     = self::stamp( time() );
		$expires = self::stamp( time() + max( 1, $ttl_seconds ) );

		/*
		 * MySQL performs these assignments in the order written and each
		 * right-hand side is evaluated before its own column is assigned, so
		 * all three read the stored `expires_at` — the one being replaced.
		 * Reordering them would have the later two testing a window this
		 * statement had already moved.
		 *
		 * `LAST_INSERT_ID(expr)` hands the chosen count back through
		 * `insert_id`, which is how one statement both counts and reports.
		 */
		$affected = self::quietly(
			$wpdb->prepare(
				'INSERT INTO %i (claim_key, count, created_at, expires_at) VALUES (%s, 1, %s, %s)
				ON DUPLICATE KEY UPDATE
					count      = LAST_INSERT_ID(IF(expires_at <= %s, 1, count + 1)),
					created_at = IF(expires_at <= %s, %s, created_at),
					expires_at = IF(expires_at <= %s, %s, IF(%d = 1, %s, expires_at))',
				Schema::table( 'claims' ),
				$key,
				$now,
				$expires,
				$now,
				$now,
				$now,
				$now,
				$expires,
				$sliding ? 1 : 0,
				$expires
			)
		);

		if ( false === $affected ) {
			return null;
		}

		// A plain INSERT reports one row and leaves `insert_id` holding the
		// new row's id rather than the count; every other outcome went
		// through the clause above and reports the count itself.
		if ( 1 === $affected ) {
			return 1;
		}

		return max( 1, (int) $wpdb->insert_id );
	}

	/**
	 * Take back one occurrence this request counted, in the window it was
	 * counted in.
	 *
	 * For a cap that counts on the way in, because the count and the decision
	 * have to be one statement, but where an attempt that turns out right must
	 * not spend the budget. One back rather than the whole count, so whatever
	 * else the window holds stays counted: a guesser's wrong answers are not
	 * cleared because the owner then got one right. Never below zero, and
	 * never in a window that has already closed.
	 */
	public static function give_back( string $key ): void {
		global $wpdb;

		self::quietly(
			$wpdb->prepare(
				'UPDATE %i SET count = count - 1 WHERE claim_key = %s AND count > 0 AND expires_at > %s',
				Schema::table( 'claims' ),
				$key,
				self::stamp( time() )
			)
		);
	}

	/**
	 * Whether a key is currently held, without taking it. For reporting only:
	 * anything that acts on the answer wants `claim()`, because between this
	 * answering and the caller acting the key can change hands.
	 */
	public static function held( string $key ): bool {
		return self::count( $key ) > 0;
	}

	/**
	 * When a held key lapses, as a Unix time, or 0 when nobody holds it or
	 * the read did not run. For a caller that must act the moment a window
	 * closes rather than whenever something next happens to look.
	 */
	public static function lapses_at( string $key ): int {
		global $wpdb;

		$was_suppressed = $wpdb->suppress_errors( true );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a plugin-owned table with no core API, read uncached for the reason run_count() gives.
		$expires = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT expires_at FROM %i WHERE claim_key = %s AND expires_at > %s',
				Schema::table( 'claims' ),
				$key,
				self::stamp( time() )
			)
		);

		$wpdb->suppress_errors( $was_suppressed );

		$at = is_string( $expires ) ? strtotime( $expires . ' UTC' ) : false;

		return false === $at ? 0 : (int) $at;
	}

	/**
	 * How many occurrences the current window holds, without adding one. Zero
	 * when the window has closed or never opened.
	 *
	 * For a caller that counts only some of what it sees — a cap on wrong
	 * answers, say, where a right one must not count — so that reading the
	 * total and adding to it stay separate operations. Reading is a plain
	 * read and carries the usual caveat: by the time the caller acts, the
	 * count may have moved. That is the right trade for a cap, which bounds
	 * volume rather than deciding a single outcome.
	 *
	 * Zero when the read itself did not run, for the same reason `bump()`
	 * answers one: a limit on volume lets everyone through rather than nobody.
	 * A caller standing in front of a credential wants `count_or_fail()`.
	 */
	public static function count( string $key ): int {
		return self::run_count( $key ) ?? 0;
	}

	/**
	 * The same read, for a caller that must refuse when it cannot be taken.
	 *
	 * Null means the statement did not run. Zero means it ran and the window
	 * is empty, which is an ordinary answer and the commonest one.
	 */
	public static function count_or_fail( string $key ): ?int {
		return self::insisting(
			static function () use ( $key ): ?int {
				return self::run_count( $key );
			}
		);
	}

	/**
	 * Read the current window, or null when the statement did not run.
	 *
	 * `get_var()` answers null for a row that is not there and for a query
	 * that failed, so what the database said afterwards is the only thing that
	 * tells the two apart.
	 */
	private static function run_count( string $key ): ?int {
		global $wpdb;

		$was_suppressed     = $wpdb->suppress_errors( true );
		$wpdb->last_error   = '';
		self::$last_failure = '';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a plugin-owned table with no core API, and deliberately uncached: a cap read from a stale cache admits the requests it exists to refuse.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT count FROM %i WHERE claim_key = %s AND expires_at > %s',
				Schema::table( 'claims' ),
				$key,
				self::stamp( time() )
			)
		);

		self::$last_failure = (string) $wpdb->last_error;

		$wpdb->suppress_errors( $was_suppressed );

		if ( '' !== self::$last_failure ) {
			return null;
		}

		return null === $count ? 0 : (int) $count;
	}

	/**
	 * Remove lapsed rows, in bounded batches under a wall-clock budget.
	 * Returns how many went.
	 */
	public static function prune( float $budget_seconds = 2.0, int $batch_size = 1000 ): int {
		global $wpdb;

		$table   = Schema::table( 'claims' );
		$cutoff  = self::stamp( time() );
		$start   = microtime( true );
		$removed = 0;

		do {
			$deleted = self::quietly(
				$wpdb->prepare(
					'DELETE FROM %i WHERE expires_at <= %s ORDER BY id ASC LIMIT %d',
					$table,
					$cutoff,
					$batch_size
				)
			);

			$removed += (int) $deleted;

			if ( (int) $deleted < $batch_size ) {
				break;
			}
		} while ( microtime( true ) - $start < $budget_seconds );

		return $removed;
	}

	/**
	 * Run one statement without letting its failure reach the page.
	 *
	 * Two failures are expected rather than exceptional here. A duplicate key
	 * is this class's whole mechanism — it is how a second claimant is refused,
	 * and it is an answer, not a fault. And between a plugin update landing on
	 * disk and the migration running on the next admin page load, the table
	 * this writes to does not exist yet, while front-end requests carry on
	 * calling in. Neither may print a database error into somebody's page, and
	 * with `WP_DEBUG_DISPLAY` on an unsuppressed one prints the statement, the
	 * table name and the call stack to whoever is looking at the site.
	 *
	 * `claim()` treats a false as "somebody else has this", which is the safe
	 * reading when the truth is "there is nowhere to record it". What the
	 * database said is kept, because the callers that must fail closed need to
	 * know whether it was a duplicate key — an answer — or a table that is not
	 * there, which is a thing to mend.
	 *
	 * @return int|false Rows affected, or false if the statement did not run.
	 */
	private static function quietly( string $sql ) {
		global $wpdb;

		$was_suppressed = $wpdb->suppress_errors( true );

		/*
		 * Every caller passes a string that came straight out of
		 * `$wpdb->prepare()` — this method exists only to add the error
		 * suppression around it, and it is private so no other caller can
		 * reach it with anything else.
		 */
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter -- prepared by the caller; see above.
		$result = $wpdb->query( $sql );

		self::$last_failure = false === $result ? (string) $wpdb->last_error : '';

		$wpdb->suppress_errors( $was_suppressed );

		return $result;
	}

	/**
	 * Run a statement a credential cap depends on: once, and once more after
	 * the installer has had its chance when what stopped it was the table not
	 * being there.
	 *
	 * Whatever the outcome, it is recorded where the audit can read it — the
	 * caps are refusing sign-ins while this is failing, and the owner is owed
	 * the reason before tomorrow.
	 *
	 * @param callable(): ?int $statement
	 */
	private static function insisting( callable $statement ): ?int {
		$answer = $statement();

		if ( null !== $answer ) {
			self::cleared();

			return $answer;
		}

		/*
		 * Nothing at all is added to a store request: not a migration, not an
		 * option write, not a finding. The cap still refuses — the answer is
		 * the same one — and the record of why is left to the next request
		 * that is not somebody's order.
		 */
		if ( self::on_the_store_path() ) {
			return null;
		}

		if ( self::table_is_absent() ) {
			Schema::repair( 'claims' );

			$answer = $statement();
		}

		if ( null === $answer ) {
			self::refused();

			return null;
		}

		self::cleared();

		return $answer;
	}

	/**
	 * Whether what stopped the last statement was the table not being there.
	 *
	 * A privilege that was revoked, a lock, a full disk: none of those is this
	 * and none is answered by running the installer. Matched on the database's
	 * own wording, which covers both the plain form and the one a storage
	 * engine adds to it, because `$wpdb` does not carry the error number.
	 */
	private static function table_is_absent(): bool {
		return false !== stripos( self::$last_failure, 'exist' );
	}

	/**
	 * Whether this request is somebody's cart or checkout.
	 *
	 * Read from the address as well as from the store's own tags, the way the
	 * schema catch-up reads it: the checkout shapes that never reach a
	 * template load answer for themselves, and a site with no store installed
	 * is settled by the address alone.
	 */
	private static function on_the_store_path(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a structural test; never stored, never echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		return Checkout::is_store_uri( $uri ) || Checkout::is_store_path();
	}

	/**
	 * Say, once for the request, that a cap could not be enforced.
	 *
	 * The flag is what the audit reads on its next run; the finding is opened
	 * straight away because the consequence is already happening — codes are
	 * being refused — and a daily audit is too late to explain it.
	 */
	private static function refused(): void {
		if ( self::$reported ) {
			return;
		}

		self::$reported  = true;
		self::$flag_read = true;

		$observed = gmdate( 'c' );

		update_option( self::FAILED_OPTION, $observed, false );

		Auditor::open_now( 'claims_unreadable', array( 'observed_at' => $observed ) );
	}

	/**
	 * A statement that ran is the end of it. Read once per request rather than
	 * on every successful cap: the option is not autoloaded, and a sign-in
	 * consults several of these.
	 */
	private static function cleared(): void {
		if ( self::$flag_read ) {
			return;
		}

		self::$flag_read = true;

		if ( false !== get_option( self::FAILED_OPTION, false ) ) {
			delete_option( self::FAILED_OPTION );
		}
	}

	/**
	 * A moment as this table's DATETIME(3) columns store it. One definition,
	 * shared with every other column of the same kind.
	 */
	private static function stamp( int $timestamp ): string {
		return Time::stamp( $timestamp );
	}
}
