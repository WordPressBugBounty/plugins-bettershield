<?php
/**
 * Fix for "Some accounts signed in with passwords below the policy" (#2430).
 *
 * Each account the policy flagged, and Ask for a new password for the ones
 * chosen: through the new-password hold, their current password stops
 * signing them in until they set one, and WordPress emails each a reset
 * link. The password itself is never touched, so undo only lifts the hold.
 *
 * The policy alone never does this to anyone; it is the owner's choice,
 * account by account. The hold's own rules keep the way back in: never the
 * account asking, never the last administrator, and safe mode stands it
 * down. An email that cannot be sent lifts the hold again.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Password\Policy;
use BetterShield\Remediation\Accounts;
use BetterShield\Remediation\PasswordHold;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WeakPasswords {

	/** What a hold placed here is kept as, so its lasting Undo can find it. */
	public const WHY = 'below_policy';

	/** How many are listed, and so asked at once: each is one email. */
	public const MAX_LISTED = 20;

	/**
	 * The flagged accounts not already held, each with why it cannot be
	 * asked from here, where it cannot, and which is the person asking.
	 *
	 * @return array{accounts: array<int, array<string, mixed>>, total: int}
	 */
	public static function state(): array {
		if ( ! Policy::instance()->settings()['enabled'] ) {
			return array(
				'accounts' => array(),
				'total'    => 0,
			);
		}

		$query = new \WP_User_Query(
			array(
				'meta_key'    => Policy::flag_key(), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- a manage-only read of the panel, never a front-end request.
				'meta_value'  => '1', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'exclude'     => PasswordHold::blocked_ids(), // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- at most the hold's own bound.
				'number'      => self::MAX_LISTED,
				'orderby'     => 'ID',
				'count_total' => true,
			)
		);

		$rows = array();

		foreach ( (array) $query->get_results() as $user ) {
			if ( ! $user instanceof \WP_User ) {
				continue;
			}

			// The person asking is never held from here, so their row keeps
			// its refusal; their password is still theirs to change, so the
			// panel is told it is their own and where their profile is.
			$own = (int) $user->ID === get_current_user_id();

			$rows[] = array(
				'id'         => (int) $user->ID,
				'login'      => (string) $user->user_login,
				'privileged' => Policy::instance()->is_privileged( (array) $user->roles, $user ),
				'refused'    => self::refusal( (int) $user->ID ),
				'self'       => $own,
				'profile'    => $own ? get_edit_profile_url( (int) $user->ID ) : '',
			);
		}

		return array(
			'accounts' => $rows,
			'total'    => max( (int) $query->get_total(), count( $rows ) ),
		);
	}

	/**
	 * Why an account cannot be asked for a new password from here, or ''.
	 *
	 * The hold's own rules, which on a network are the network's, then
	 * whether the reset link could reach the account at all.
	 */
	public static function refusal( int $id ): string {
		$refusal = Accounts::refusal( $id, true );

		if ( '' !== $refusal ) {
			return $refusal;
		}

		$user = get_userdata( $id );

		if ( ! $user instanceof \WP_User || true !== wp_is_password_reset_allowed_for_user( $user ) ) {
			return __( 'This site does not let this account reset its password.', 'bettershield' );
		}

		if ( ! is_email( $user->user_email ) ) {
			return __( 'This account has no email address a reset link could reach.', 'bettershield' );
		}

		return '';
	}

	/**
	 * Hold each chosen account the list still names, and send its reset link.
	 *
	 * @param int[] $ids
	 * @return array{held: array<int, array<string, mixed>>, refused: array<int, array<string, mixed>>, state: array<string, mixed>}|\WP_Error
	 */
	public static function hold( array $ids ) {
		$listed = array_column( self::state()['accounts'], null, 'id' );
		$chosen = array_values( array_intersect( array_unique( array_map( 'intval', $ids ) ), array_keys( $listed ) ) );

		if ( array() === $chosen ) {
			return new \WP_Error( 'bettershield_none_listed', __( 'None of those is on the list now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$held    = array();
		$refused = array();

		foreach ( $chosen as $id ) {
			$login  = (string) $listed[ $id ]['login'];
			$reason = $listed[ $id ]['refused'];
			$undo   = '';

			if ( '' === $reason ) {
				// Written with its way back before it takes effect.
				$undo   = PasswordHold::place( $id, self::WHY );
				$reason = '' === $undo ? __( 'It could not be asked. It signs in as before.', 'bettershield' ) : '';
			}

			// A hold nobody was told how to clear would only be a lockout.
			if ( '' === $reason && true !== retrieve_password( $login ) ) {
				PasswordHold::lift( $id, 'not_sent' );
				$reason = __( 'The reset email failed, so it signs in as before.', 'bettershield' );
			}

			if ( '' !== $reason ) {
				$refused[] = array(
					'id'     => $id,
					'login'  => $login,
					'reason' => $reason,
				);
				continue;
			}

			Writer::instance()->record(
				'incident_password_held',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'user',
					'object_id'   => (string) $id,
					'context'     => array(
						'reason' => 'below_policy',
						'undo'   => $undo,
					),
				)
			);

			$held[] = array(
				'id'    => $id,
				'login' => $login,
				'undo'  => $undo,
			);
		}

		Policy::forget_flagged();
		Auditor::run();

		return array(
			'held'    => $held,
			'refused' => $refused,
			'state'   => self::state(),
		);
	}

	/**
	 * The holds placed here that are still in force, each only while this
	 * person could lift it: the hold's own rules, which on a network are the
	 * network's.
	 *
	 * @return array<int, array{id: int, login: string, undo: string}>
	 */
	public static function open_holds(): array {
		$open = array();

		foreach ( Ledger::open_token_page( PasswordHold::KEY, PHP_INT_MAX, 100 ) as $token ) {
			$entry = Ledger::find( $token );
			$prior = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();
			$id    = (int) ( $prior['user'] ?? 0 );
			$user  = $id > 0 ? get_userdata( $id ) : false;

			if ( self::WHY !== ( $prior['why'] ?? '' ) || ! $user instanceof \WP_User || PasswordHold::token( $id ) !== $token || '' !== Accounts::refusal( $id, true ) ) {
				continue;
			}

			$open[] = array(
				'id'    => $id,
				'login' => (string) $user->user_login,
				'undo'  => $token,
			);
		}

		return $open;
	}

	/**
	 * Lift one hold placed here: the account signs in with its password
	 * again. The hold's own record of the lift is written by the hold.
	 *
	 * @return array{id: int}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		// Only this fix's own hold: an incident response's is lifted where it was placed.
		if ( null === $entry || PasswordHold::KEY !== (string) $entry->action_key || self::WHY !== ( $entry->prior_state['why'] ?? '' ) ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$id = (int) ( $entry->prior_state['user'] ?? 0 );

		if ( null !== $entry->reverted_at || PasswordHold::token( $id ) !== $token ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'This account is not waiting for a new password now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$refusal = Accounts::refusal( $id, true );

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_account_refused', $refusal, array( 'status' => 403 ) );
		}

		if ( ! PasswordHold::lift( $id, 'undo' ) ) {
			return new \WP_Error( 'bettershield_lift_failed', __( 'It could not be lifted. Try again.', 'bettershield' ), array( 'status' => 500 ) );
		}

		Policy::forget_flagged();
		Auditor::run();

		return array( 'id' => $id );
	}
}
