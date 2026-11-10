<?php
/**
 * Reversibility ledger.
 *
 * Every state-changing action records its exact prior state here BEFORE
 * executing, so an action that crashes halfway still leaves a revert
 * path. Writes are synchronous by design — durability before the action
 * matters more than request latency on an admin-initiated change.
 *
 * Ledger rows are never pruned by retention: undo must outlive log
 * history, so a change applied long ago can still be reverted.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Undo;

use BetterShield\Database\Schema;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Every query below targets the plugin-owned undo table: there is no core API
 * for it, and it is deliberately never cached — an undo record read from a
 * stale cache is a revert applied to the wrong prior state.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Ledger {

	/**
	 * Record an action about to be executed. Call BEFORE performing the
	 * change; returns the undo token, or null if the row could not be
	 * written — in which case the caller must not proceed.
	 *
	 * Errors are suppressed for the duration of the write. Every reason it
	 * fails is a database fault, and with `WP_DEBUG_DISPLAY` on an unsuppressed
	 * one prints the statement, the table name and the prior state itself to
	 * whoever is looking at the page. The refusal is carried in the return
	 * value, which is what the caller acts on.
	 *
	 * @param string $action_key    Stable identifier, e.g. 'harden_xmlrpc'.
	 * @param array  $prior_state   Enough data to restore exactly.
	 * @param array  $applied_state The state the action is about to apply.
	 */
	public static function open( string $action_key, array $prior_state, array $applied_state ): ?string {
		global $wpdb;

		$prior   = wp_json_encode( $prior_state );
		$applied = wp_json_encode( $applied_state );

		/*
		 * A state that will not survive being written down is not a state this
		 * can put back. Cast to a string, a refused encode became an empty
		 * column that decodes to nothing — and a token was handed back for it,
		 * so the offer to revert stood and would have applied an empty array.
		 */
		if ( ! is_string( $prior ) || ! is_string( $applied ) ) {
			return null;
		}

		$token = bin2hex( random_bytes( 16 ) );

		$was_suppressed = $wpdb->suppress_errors( true );

		$inserted = $wpdb->insert(
			Schema::table( 'undo' ),
			array(
				'site_id'       => 0,
				'token'         => $token,
				'action_key'    => substr( $action_key, 0, 64 ),
				'created_at'    => Time::stamp(),
				'created_by'    => get_current_user_id() > 0 ? get_current_user_id() : null,
				'prior_state'   => $prior,
				'applied_state' => $applied,
			),
			array( '%d', '%s', '%s', '%s', '%d', '%s', '%s' )
		);

		$wpdb->suppress_errors( $was_suppressed );

		return false === $inserted ? null : $token;
	}

	/**
	 * Tokens of the entries under an action key that are still open — not
	 * reverted. Newest first, bounded: an item writes at most a few hundred
	 * files, and a caller walking these is repairing, not paging.
	 *
	 * @return string[]
	 */
	public static function open_tokens( string $action_key, int $limit = 1000 ): array {
		global $wpdb;

		return array_map(
			'strval',
			(array) $wpdb->get_col(
				$wpdb->prepare(
					'SELECT token FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL ORDER BY id DESC LIMIT %d',
					Schema::table( 'undo' ),
					$action_key,
					$limit
				)
			)
		);
	}

	/**
	 * One page of the open entries under an action key, newest first, older
	 * than an id: for a caller that has to reach every one of them. An item
	 * that keeps writing over time — the daily guard top-up — leaves more
	 * than one page, and a sweep of the first page alone left the rest.
	 *
	 * @param int $before_id Only entries with a smaller id; PHP_INT_MAX for the newest.
	 * @return array<int, string> Token by entry id.
	 */
	public static function open_token_page( string $action_key, int $before_id, int $limit = 500 ): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, token FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL AND id < %d ORDER BY id DESC LIMIT %d',
				Schema::table( 'undo' ),
				$action_key,
				$before_id,
				$limit
			)
		);

		$page = array();

		foreach ( $rows as $row ) {
			$page[ (int) $row->id ] = (string) $row->token;
		}

		return $page;
	}

	/**
	 * The entries under an action key made after a given one and still open,
	 * oldest first, with both of their states.
	 *
	 * @param int $after_id Only entries with a larger id.
	 * @return array<int, array{prior: array<string, mixed>, applied: array<string, mixed>}>
	 */
	public static function open_after( string $action_key, int $after_id, int $limit = 1000 ): array {
		global $wpdb;

		$rows    = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT prior_state, applied_state FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL AND id > %d ORDER BY id ASC LIMIT %d',
				Schema::table( 'undo' ),
				$action_key,
				$after_id,
				$limit
			)
		);
		$entries = array();

		foreach ( $rows as $row ) {
			$prior   = json_decode( (string) $row->prior_state, true );
			$applied = json_decode( (string) $row->applied_state, true );

			$entries[] = array(
				'prior'   => is_array( $prior ) ? $prior : array(),
				'applied' => is_array( $applied ) ? $applied : array(),
			);
		}

		return $entries;
	}

	/**
	 * The applied states of the entries under an action key that are still
	 * open, newest first and bounded like open_tokens(). One query for a
	 * caller asking what each change put in place, rather than a find() per
	 * token.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function open_states( string $action_key, int $limit = 1000 ): array {
		global $wpdb;

		$states = array();

		foreach ( (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT applied_state FROM %i WHERE site_id = 0 AND action_key = %s AND reverted_at IS NULL ORDER BY id DESC LIMIT %d',
				Schema::table( 'undo' ),
				$action_key,
				$limit
			)
		) as $json ) {
			$state = json_decode( (string) $json, true );

			if ( is_array( $state ) ) {
				$states[] = $state;
			}
		}

		return $states;
	}

	/**
	 * The most recent entries under a family of action keys, newest first.
	 *
	 * For the screen that reports what was done lately, which is a different
	 * question from what is still revertible: an entry that has been reverted
	 * stays in the list and says so, because "you applied this and then put it
	 * back" is the history somebody is looking for, and hiding the second half
	 * of it makes the first half look like it never happened.
	 *
	 * The prefix is matched with LIKE against a literal assembled here —
	 * callers pass a family name, never a pattern, and `esc_like` is what
	 * keeps an underscore in one of our own keys from matching any character.
	 *
	 * Bounded by the caller and capped here: this is a peek at the end of a
	 * table that retention never prunes.
	 *
	 * @param string $prefix Action-key family, e.g. 'harden_'.
	 * @param int    $limit  How many rows at most.
	 * @return array<int, array<string, mixed>> Newest first.
	 */
	public static function recent( string $prefix, int $limit = 5 ): array {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// site_id 0 as everything else in this file writes and reads
				// it: the undo table is not network-scoped.
				'SELECT action_key, created_at, reverted_at FROM %i WHERE site_id = 0 AND action_key LIKE %s ORDER BY id DESC LIMIT %d',
				Schema::table( 'undo' ),
				$wpdb->esc_like( $prefix ) . '%',
				max( 1, min( 50, $limit ) )
			)
		);

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[] = array(
				'action_key'  => (string) $row->action_key,
				// Stored UTC without a zone marker; say so explicitly rather
				// than let the browser read it as local time.
				'at'          => Time::utc_iso( (string) $row->created_at ),
				'reverted_at' => null !== $row->reverted_at ? Time::utc_iso( (string) $row->reverted_at ) : null,
			);
		}

		return $out;
	}

	/**
	 * Entries whose key starts with a prefix, opened after a moment, newest
	 * first: what a report says was changed in its period. Bounded by date
	 * where recent() is bounded by count, and capped, so a period of heavy
	 * work is a long list rather than an unbounded one. Newest first because
	 * the cap has to drop the oldest entries, never the latest change (#2276):
	 * a caller that asks for one more than it shows can tell it was cut.
	 *
	 * @param string $since A stored-column UTC datetime.
	 * @return array<int, array{action_key: string, at: string, reverted_at: string|null}>
	 */
	public static function since( string $prefix, string $since, int $limit = 200 ): array {
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT action_key, created_at, reverted_at FROM %i WHERE site_id = 0 AND action_key LIKE %s AND created_at > %s ORDER BY id DESC LIMIT %d',
				Schema::table( 'undo' ),
				$wpdb->esc_like( $prefix ) . '%',
				$since,
				max( 1, min( 500, $limit ) )
			)
		);

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[] = array(
				'action_key'  => (string) $row->action_key,
				'at'          => Time::utc_iso( (string) $row->created_at ),
				'reverted_at' => null !== $row->reverted_at ? Time::utc_iso( (string) $row->reverted_at ) : null,
			);
		}

		return $out;
	}

	/**
	 * Ledger entry for a token, with states decoded, or null if unknown.
	 */
	public static function find( string $token ): ?object {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM %i WHERE token = %s', Schema::table( 'undo' ), $token )
		);

		if ( null === $row ) {
			return null;
		}

		$row->prior_state   = json_decode( (string) $row->prior_state, true );
		$row->applied_state = json_decode( (string) $row->applied_state, true );

		return $row;
	}

	/**
	 * Mark an entry as reverted. Returns false if the token is unknown or
	 * was already reverted — reverting twice is a caller bug.
	 */
	public static function mark_reverted( string $token ): bool {
		global $wpdb;

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET reverted_at = %s WHERE token = %s AND reverted_at IS NULL',
				Schema::table( 'undo' ),
				Time::stamp(),
				$token
			)
		);

		return 1 === $updated;
	}

	/**
	 * Record that a revert was attempted and failed, keeping the entry
	 * open so it can be retried.
	 */
	public static function mark_revert_failed( string $token, string $reason ): bool {
		global $wpdb;

		$updated = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET revert_failed_reason = %s WHERE token = %s AND reverted_at IS NULL',
				Schema::table( 'undo' ),
				// The column counts characters; the shared helper is the one
				// place that knows that, and knows what to do on a host with
				// no mbstring rather than falling back to bytes.
				Text::clip( $reason, 255 ),
				$token
			)
		);

		return 1 === $updated;
	}
}
