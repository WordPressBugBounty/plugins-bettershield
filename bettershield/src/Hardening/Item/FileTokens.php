<?php
/**
 * Shared revert path for items whose apply wrote files.
 *
 * An item's state carries the undo tokens of every file write it made, in the
 * order it made them. Revert restores them newest-first, and stops at the
 * first failure rather than pressing on: a half-reverted item that reports
 * success would be the interface lying about the site.
 *
 * A token that was already restored on an earlier, interrupted attempt is
 * not a failure — it is the part of the work that is done. Treating it as one
 * would wedge the item: the first retry stops at the first finished token
 * and never reaches the one that actually failed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Files\Guarded;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FileTokens {

	/**
	 * @param array<string, mixed> $state         The item's stored state.
	 * @param bool                 $leave_changed Whether a file somebody has changed since it was written is left
	 *                                            where it is, and given up, while the rest are undone, rather than
	 *                                            stopping the undo. For an item whose files each stand alone.
	 * @return true|array{notes: string[]}|\WP_Error
	 */
	public static function restore( array $state, bool $leave_changed = false ) {
		$tokens = isset( $state['file_tokens'] ) && is_array( $state['file_tokens'] ) ? $state['file_tokens'] : array();
		$left   = array();

		foreach ( array_reverse( $tokens ) as $token ) {
			if ( ! is_string( $token ) ) {
				continue;
			}

			$result = Guarded::restore( $token );

			/*
			 * One guard somebody replaced with their own file stopped every
			 * other guard being removed, and the item could never be undone
			 * (#2088). Theirs stays where it is and stops being this
			 * plugin's: its record is closed, so nothing later puts it back
			 * or counts it as a guard.
			 */
			if ( $leave_changed && is_wp_error( $result ) && 'bettershield_file_changed' === $result->get_error_code() ) {
				$entry  = \BetterShield\Undo\Ledger::find( $token );
				$path   = is_object( $entry ) && is_array( $entry->prior_state ) ? (string) ( $entry->prior_state['path'] ?? '' ) : '';
				$left[] = '' === $path ? $token : ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ), '/' );

				\BetterShield\Undo\Ledger::mark_reverted( $token );
				continue;
			}

			if ( is_wp_error( $result ) && ! in_array( $result->get_error_code(), array( 'bettershield_already_reverted', 'bettershield_unknown_token' ), true ) ) {
				// The files given up so far are said with the failure: they
				// are not this plugin's any more, and the retry skips them.
				return array() === $left ? $result : new \WP_Error( $result->get_error_code(), $result->get_error_message() . ' ' . self::left_note( $left ), $result->get_error_data() );
			}
		}

		if ( array() === $left ) {
			return true;
		}

		return array( 'notes' => array( self::left_note( $left ) ) );
	}

	/**
	 * The files an undo left where they were, in one sentence.
	 *
	 * @param string[] $left Paths, relative to the site.
	 */
	private static function left_note( array $left ): string {
		return sprintf(
			/* translators: %s: comma-separated file paths. */
			_n(
				'%s was changed by someone else since this plugin wrote it, so it was left in place and is no longer counted as this plugin’s.',
				'%s were changed by someone else since this plugin wrote them, so they were left in place and are no longer counted as this plugin’s.',
				count( $left ),
				'bettershield'
			),
			implode( ', ', array_slice( $left, 0, 10 ) ) . ( count( $left ) > 10 ? sprintf( ' (+%d)', count( $left ) - 10 ) : '' )
		);
	}

	/**
	 * Which of an item's tokens no longer have a ledger record — a database
	 * restored from before the apply, or an opt-in uninstall and reinstall.
	 * Nothing can be restored from a record that is gone; the item still
	 * reverts, and says which files it could not account for so the owner
	 * can look.
	 *
	 * @param array<string, mixed> $state
	 * @return string[]
	 */
	public static function unaccounted( array $state ): array {
		$tokens = isset( $state['file_tokens'] ) && is_array( $state['file_tokens'] ) ? $state['file_tokens'] : array();
		$lost   = array();

		foreach ( $tokens as $token ) {
			if ( is_string( $token ) && null === \BetterShield\Undo\Ledger::find( $token ) ) {
				$lost[] = $token;
			}
		}

		return $lost;
	}
}
