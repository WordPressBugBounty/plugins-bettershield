<?php
/**
 * What an agent asked to change, and the one confirmation a person may mint
 * against it.
 *
 * The whole write ladder rests on a single property: a confirmation is minted
 * by a person, bound to one proposal, and spent exactly once. That property is
 * the database's to enforce, not this code's — `spend()` is one UPDATE with
 * every condition in its WHERE clause, so two requests carrying the same
 * string cannot both find it unspent however they interleave. The reason for a
 * refusal is read afterwards, from the row that refused.
 *
 * The confirmation itself is returned once, at the mint, and stored only as a
 * SHA-256 digest. It appears in no log, no option and no later response.
 *
 * This is the one place rows in this table are written. Everything else asks.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

use BetterShield\Database\Schema;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Every query below targets the plugin-owned proposals table: there is no core
 * API for it, and it is deliberately never cached — a proposal read from a
 * stale cache is a confirmation spent twice.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Proposals {

	/**
	 * How long a proposal stands.
	 *
	 * The same window the password confirmation uses, deliberately: both
	 * answer "is this still the same piece of work", and two different answers
	 * to that question would be two different windows to reason about.
	 */
	public const WINDOW_SECONDS = 900;

	/** Rows one page of the owner's screen carries. */
	public const PER_PAGE = 20;

	/**
	 * How many requests are waiting for an answer, and when the soonest of
	 * them runs out.
	 *
	 * Autoloaded, because the menu reads it on every admin page and a count
	 * behind a query there would be a query on every admin page. The deadline
	 * travels with the count for the one way the number can go stale with
	 * nothing written: time passing.
	 */
	public const OPEN_COUNT_OPTION = 'bettershield_open_proposals';

	/**
	 * Record a proposal. Returns its id, or null when the row could not be
	 * written — in which case the caller must not answer with a plan, because
	 * there would be nothing for a person to confirm against.
	 *
	 * @param array<string, mixed> $plan Exactly the object returned to the caller.
	 */
	public static function open( string $ability, string $target, string $target_type, array $plan, string $state_digest ): ?int {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return null;
		}

		$encoded = wp_json_encode( $plan );

		// A plan that will not survive being written down is not a plan a
		// person can be shown and asked to confirm.
		if ( ! is_string( $encoded ) ) {
			return null;
		}

		$was_suppressed = $wpdb->suppress_errors( true );

		$inserted = $wpdb->insert(
			Schema::table( 'write_proposals' ),
			array(
				// The columns count characters; the shared helper is the one
				// place that knows that, and knows what to do on a host with
				// no mbstring rather than falling back to bytes.
				'ability'              => Text::clip( $ability, 64 ),
				'target'               => Text::clip( $target, 191 ),
				'target_type'          => Text::clip( $target_type, 32 ),
				'plan'                 => $encoded,
				'state_digest'         => $state_digest,
				'proposed_by'          => max( 0, get_current_user_id() ),
				'proposed_at'          => Time::stamp(),
				'proposed_correlation' => self::correlation(),
				'expires_at'           => Time::stamp( time() + self::WINDOW_SECONDS ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		$wpdb->suppress_errors( $was_suppressed );

		if ( false === $inserted ) {
			return null;
		}

		// Read before the recount, which issues a query of its own and takes
		// the last insert's id with it.
		$id = (int) $wpdb->insert_id;

		self::refresh_open_count();

		return $id;
	}

	/**
	 * How many requests are waiting for somebody to answer them.
	 *
	 * Read from the option rather than from the table. The menu asks this on
	 * every admin page, and the answer only changes when a proposal is made,
	 * allowed, spent, withdrawn or pruned — each of which recomputes it — or
	 * when one runs out of time, which nothing writes. So the soonest deadline
	 * is kept beside the count: once it has passed, and only then, the number
	 * is recomputed once.
	 *
	 * "Waiting" is a proposal nobody has answered yet. One that has been
	 * allowed has had its answer, and a bubble that stayed up afterwards would
	 * be asking for something already given.
	 */
	public static function open_count(): int {
		$cached = get_option( self::OPEN_COUNT_OPTION );

		if ( ! is_array( $cached ) || ! isset( $cached['count'] ) ) {
			return self::refresh_open_count();
		}

		$count = max( 0, (int) $cached['count'] );

		if ( 0 === $count ) {
			return 0;
		}

		$until = (string) ( $cached['until'] ?? '' );

		if ( '' === $until || strtotime( $until . ' UTC' ) <= time() ) {
			return self::refresh_open_count();
		}

		return $count;
	}

	/**
	 * Count the waiting requests again, and record the answer.
	 *
	 * One statement for both facts: a second query to learn the soonest
	 * deadline would be a second query on every write.
	 */
	public static function refresh_open_count(): int {
		global $wpdb;

		$count = 0;
		$until = '';

		if ( Schema::ready( 'write_proposals' ) ) {
			$row = $wpdb->get_row(
				$wpdb->prepare(
					'SELECT COUNT(*) AS waiting, MIN(expires_at) AS soonest FROM %i'
						. ' WHERE token_hash IS NULL AND spent_at IS NULL AND withdrawn_at IS NULL AND expires_at > %s',
					Schema::table( 'write_proposals' ),
					Time::stamp()
				)
			);

			if ( null !== $row ) {
				$count = max( 0, (int) $row->waiting );
				$until = null === $row->soonest ? '' : (string) $row->soonest;
			}
		}

		update_option(
			self::OPEN_COUNT_OPTION,
			array(
				'count' => $count,
				'until' => $until,
			),
			true
		);

		return $count;
	}

	/**
	 * One proposal by id, with its plan decoded, or null if unknown.
	 */
	public static function find( int $id ): ?object {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return null;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', Schema::table( 'write_proposals' ), $id )
		);

		return null === $row ? null : self::decode( $row );
	}

	/**
	 * A page of proposals, newest first.
	 *
	 * `open` is what an owner is being asked to answer: proposed and not yet
	 * answered, not spent, not withdrawn, not past its expiry. `all` is the record,
	 * including what was refused and what nobody answered in time.
	 *
	 * @return array{proposals: object[], next_cursor: ?int}
	 */
	public static function page( string $status, int $after, int $limit ): array {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return array(
				'proposals'   => array(),
				'next_cursor' => null,
			);
		}

		$limit = max( 1, min( self::PER_PAGE, $limit ) );
		$table = Schema::table( 'write_proposals' );

		// One more than the page, so "is there another page" is answered by
		// what came back rather than by a second count over the same window.
		$fetch = $limit + 1;

		// The cursor is always bound: with no cursor the bound is the largest
		// id there can be, so both statements stay one fixed string with one
		// fixed set of placeholders rather than two shapes assembled at run
		// time.
		$before = $after > 0 ? $after : PHP_INT_MAX;

		// Waiting is waiting for an answer, as refresh_open_count() counts
		// it: allowed rows were listed under "Waiting 0" (#1918). An allowed
		// one stays on the full list, where it can still be withdrawn.
		if ( 'open' === $status ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM %i WHERE token_hash IS NULL AND spent_at IS NULL AND withdrawn_at IS NULL AND expires_at > %s AND id < %d ORDER BY id DESC LIMIT %d',
					$table,
					Time::stamp(),
					$before,
					$fetch
				)
			);
		} else {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM %i WHERE id < %d ORDER BY id DESC LIMIT %d',
					$table,
					$before,
					$fetch
				)
			);
		}

		$rows = is_array( $rows ) ? $rows : array();
		$more = count( $rows ) > $limit;
		$rows = array_slice( $rows, 0, $limit );

		return array(
			'proposals'   => array_map( array( self::class, 'decode' ), $rows ),
			'next_cursor' => $more && array() !== $rows ? (int) end( $rows )->id : null,
		);
	}

	/**
	 * Mint the one confirmation this proposal will ever carry.
	 *
	 * The plaintext is returned here and nowhere else, ever. Only its digest
	 * is stored, so a database in somebody else's hands carries no confirmation
	 * anybody can spend.
	 *
	 * Refuses a proposal that is spent, withdrawn, past its expiry, or already
	 * minted: a second confirmation for one action would be a second action.
	 */
	public static function mint( int $id, int $user_id, bool $with_sudo ): ?string {
		global $wpdb;

		$row = self::find( $id );

		if ( null === $row || 'proposed' !== self::status_of( $row ) ) {
			return null;
		}

		$confirmation = wp_generate_password( 32, false );

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET token_hash = %s, minted_by = %d, minted_at = %s, minted_with_sudo = %d'
					. ' WHERE id = %d AND token_hash IS NULL AND spent_at IS NULL AND withdrawn_at IS NULL AND expires_at > %s LIMIT 1',
				Schema::table( 'write_proposals' ),
				hash( 'sha256', $confirmation ),
				$user_id,
				Time::stamp(),
				$with_sudo ? 1 : 0,
				$id,
				Time::stamp()
			)
		);

		if ( 1 !== (int) $updated ) {
			return null;
		}

		// It has been answered, so it is no longer waiting for one.
		self::refresh_open_count();

		return $confirmation;
	}

	/**
	 * Spend a confirmation against the ability that is about to run.
	 *
	 * One statement. Every condition that makes spending legitimate is in its
	 * WHERE clause, so the database decides which of two concurrent requests
	 * gets the row, and the loser is refused rather than told to try again.
	 * The reason is worked out afterwards by reading the row the digest names,
	 * which costs a read on the refusal path only.
	 *
	 * @return object|\WP_Error The spent proposal, or the reason it was not.
	 */
	public static function spend( string $confirmation, string $ability ) {
		global $wpdb;

		$unknown = new \WP_Error(
			'bettershield_confirmation_unknown',
			__( 'That confirmation does not match a change waiting to be made.', 'bettershield' ),
			array( 'status' => 403 )
		);

		if ( '' === $confirmation || ! Schema::ready( 'write_proposals' ) ) {
			return $unknown;
		}

		$hash  = hash( 'sha256', $confirmation );
		$table = Schema::table( 'write_proposals' );

		$spent = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET spent_at = %s, spent_correlation = %s'
					. ' WHERE token_hash = %s AND ability = %s AND spent_at IS NULL AND withdrawn_at IS NULL AND expires_at > %s',
				$table,
				Time::stamp(),
				self::correlation(),
				$hash,
				$ability,
				Time::stamp()
			)
		);

		if ( 1 === (int) $spent ) {
			self::refresh_open_count();

			$row = $wpdb->get_row(
				$wpdb->prepare( 'SELECT * FROM %i WHERE token_hash = %s', $table, $hash )
			);

			return null === $row ? $unknown : self::decode( $row );
		}

		// Nothing was taken. Which of the four reasons it was is read from the
		// row itself, so the caller can say what happened rather than guess.
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE token_hash = %s', $table, $hash )
		);

		if ( null === $row || (string) $row->ability !== $ability ) {
			return $unknown;
		}

		if ( null !== $row->withdrawn_at ) {
			return new \WP_Error(
				'bettershield_confirmation_withdrawn',
				__( 'That change was withdrawn, so its confirmation no longer stands.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( null !== $row->spent_at ) {
			return new \WP_Error(
				'bettershield_confirmation_spent',
				__( 'That confirmation has already been used. Each one allows a single change.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		return new \WP_Error(
			'bettershield_confirmation_expired',
			__( 'That confirmation has run out. Ask for the change again and confirm the new one.', 'bettershield' ),
			array( 'status' => 409 )
		);
	}

	/**
	 * Take a proposal off the table. An owner who reads a plan and does not
	 * want it should not have to wait fifteen minutes for it to lapse.
	 */
	public static function withdraw( int $id ): bool {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return false;
		}

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET withdrawn_at = %s WHERE id = %d AND spent_at IS NULL AND withdrawn_at IS NULL',
				Schema::table( 'write_proposals' ),
				Time::stamp(),
				$id
			)
		);

		if ( 1 !== (int) $updated ) {
			return false;
		}

		self::refresh_open_count();

		return true;
	}

	/**
	 * What became of a spent proposal, and the handle that puts it back.
	 *
	 * Written after the action either way: an outcome recorded only on success
	 * would leave a refusal looking like a change nobody finished.
	 */
	public static function record_outcome( int $id, string $outcome, ?string $undo_token ): bool {
		global $wpdb;

		if ( ! Schema::ready( 'write_proposals' ) ) {
			return false;
		}

		$updated = $wpdb->update(
			Schema::table( 'write_proposals' ),
			array(
				'outcome'    => Text::clip( $outcome, 64 ),
				'undo_token' => null === $undo_token ? null : Text::clip( $undo_token, 64 ),
			),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		return false !== $updated;
	}

	/**
	 * The spent plan that left this undo handle, or null.
	 *
	 * What tells a handle these abilities issued from one the dashboard
	 * issued: a restore's undo puts an altered file back, and an assistant
	 * takes back only what an assistant did.
	 */
	public static function by_undo_token( string $token ): ?object {
		global $wpdb;

		if ( '' === $token || ! Schema::ready( 'write_proposals' ) ) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- plugin-owned table.
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE undo_token = %s LIMIT 1', Schema::table( 'write_proposals' ), $token ) );

		return null === $row ? null : self::decode( $row );
	}

	/**
	 * Where a proposal stands, in one word.
	 *
	 * Spent and withdrawn are facts about the row; expired is a fact about the
	 * clock, so it is computed rather than stored — a row nobody read is not a
	 * row anybody updated. A plan taken off the table before anybody allowed
	 * it was declined, not withdrawn: there was nothing allowed to withdraw.
	 */
	public static function status_of( object $row ): string {
		if ( null !== $row->spent_at ) {
			return 'spent';
		}

		if ( null !== $row->withdrawn_at ) {
			return null === $row->minted_at ? 'declined' : 'withdrawn';
		}

		if ( strtotime( (string) $row->expires_at . ' UTC' ) <= time() ) {
			return 'expired';
		}

		// `minted_at` rather than the digest: the digest is stripped on the way
		// out of this class, and the two are written in one statement anyway.
		return null === $row->minted_at ? 'proposed' : 'allowed';
	}

	/* ---- helpers -------------------------------------------------------------- */

	/**
	 * The row as callers read it: the plan decoded, and the digest of the
	 * confirmation removed. Nothing outside this class ever holds the hash.
	 */
	private static function decode( object $row ): object {
		$row->id   = (int) $row->id;
		$row->plan = json_decode( (string) $row->plan, true );
		$row->plan = is_array( $row->plan ) ? $row->plan : array();

		unset( $row->token_hash );

		return $row;
	}

	/**
	 * The invocation this request belongs to, where the platform records one.
	 *
	 * Read from the invocation the capture is following rather than minted
	 * here, so the proposal and the call that made it are the same story on
	 * the agent activity screen.
	 */
	private static function correlation(): ?string {
		$correlation = \BetterShield\Agents\Capture::instance()->current_correlation();

		return '' === (string) $correlation ? null : Text::clip( (string) $correlation, 64 );
	}
}
