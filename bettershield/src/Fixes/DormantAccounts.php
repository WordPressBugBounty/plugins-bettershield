<?php
/**
 * Fix for "An admin-level account has gone unused for a long time" (#2430).
 *
 * Each account the finding names, and Suspend for the ones chosen: the
 * account keeps its role, content and passwords and cannot sign in until it
 * is let back in. Each suspension is kept first, with its own way back.
 *
 * Never the account doing the suspending, the last administrator, or an
 * account the recovery link or alert emails go to: the owner always keeps a
 * way in, and somebody who was only on leave is one press from getting
 * theirs back.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Dormant;
use BetterShield\Events\Writer;
use BetterShield\Remediation\Accounts;
use BetterShield\Remediation\Suspension;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DormantAccounts {

	/** The ledger action each suspension is kept under. */
	public const ACTION = 'dormant_account_suspended';

	/** Where a suspension made here is lifted. */
	public const LIFT_PATH = '/bettershield/v1/findings/privileged_account_dormant/suspend/undo';

	/** How many accounts are listed, and so may be suspended, at once. */
	public const MAX_LISTED = 50;

	public static function register(): void {
		add_filter( 'bettershield_suspension_lift_hint', array( self::class, 'lift_hint' ), 10, 3 );
		add_filter( 'bettershield_suspension_lift_path', array( self::class, 'lift_path' ), 10, 3 );
	}

	/**
	 * The dormant accounts, each with why it cannot be suspended from here,
	 * where it cannot.
	 *
	 * @return array{accounts: array<int, array<string, mixed>>, total: int}
	 */
	public static function state(): array {
		$found = Dormant::accounts();
		$rows  = array();

		foreach ( array_slice( $found, 0, self::MAX_LISTED ) as $account ) {
			$rows[] = $account + array( 'refused' => self::refusal( (int) $account['id'] ) );
		}

		return array(
			'accounts' => $rows,
			'total'    => count( $found ),
		);
	}

	/**
	 * Why an account cannot be suspended from here, or ''.
	 *
	 * A network super admin first, with what can be done about it. Then the
	 * shared rules: this reader's say over it, never the account making the
	 * request, and never the last administrator. Then an account the way back
	 * in goes to.
	 */
	public static function refusal( int $id ): string {
		if ( is_multisite() && is_super_admin( $id ) && get_current_user_id() !== $id ) {
			return self::super_admin_note();
		}

		$refusal = Accounts::refusal( $id );

		if ( '' !== $refusal ) {
			return $refusal;
		}

		if ( self::keeps_a_way_back( $id ) ) {
			return __( 'Recovery or alert emails go to this account, so it stays able to sign in.', 'bettershield' );
		}

		return '';
	}

	/**
	 * What can be done about a dormant super admin, who stays counted and can't
	 * be suspended from one site: it signs in to every site on the network.
	 * Whichever account reads this, the row says who can act.
	 */
	private static function super_admin_note(): string {
		return current_user_can( 'manage_network_users' )
			? __( 'A network super admin can’t be suspended here. Sign in with it to clear this, or remove its super admin role in Network Admin › Users and suspend it here.', 'bettershield' )
			: __( 'This is a network super admin, so it can’t be suspended here. Ask your network administrator to sign in with it, or to take away its super admin role.', 'bettershield' );
	}

	/**
	 * Suspend the chosen accounts the finding names now.
	 *
	 * @param int[] $ids
	 * @return array{suspended: array<int, array<string, mixed>>, refused: array<int, array<string, mixed>>, state: array<string, mixed>}|\WP_Error
	 */
	public static function suspend( array $ids ) {
		$listed = array_column( Dormant::accounts(), null, 'id' );
		$chosen = array_values( array_intersect( array_unique( array_map( 'intval', $ids ) ), array_keys( $listed ) ) );

		if ( array() === $chosen ) {
			return new \WP_Error( 'bettershield_none_listed', __( 'None of those is on the list now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$suspended = array();
		$refused   = array();

		foreach ( $chosen as $id ) {
			$login  = (string) $listed[ $id ]['login'];
			$reason = self::refusal( $id );
			$token  = '';

			if ( '' === $reason ) {
				// Kept before it takes effect: no record, no change.
				$token  = (string) Ledger::open( self::ACTION, array( 'user' => $id, 'login' => $login ), array( 'suspended' => true ) );
				$reason = '' === $token ? __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ) : '';
			}

			if ( '' === $reason && ! Suspension::change( $id, $token, '' ) ) {
				Ledger::mark_reverted( $token );
				$reason = __( 'It could not be suspended. It signs in as before.', 'bettershield' );
			}

			if ( '' !== $reason ) {
				$refused[] = array(
					'id'     => $id,
					'login'  => $login,
					'reason' => $reason,
				);
				continue;
			}

			self::recorded( 'account_suspended', $id, $token );

			$suspended[] = array(
				'id'    => $id,
				'login' => $login,
				'undo'  => $token,
			);
		}

		Auditor::run();

		return array(
			'suspended' => $suspended,
			'refused'   => $refused,
			'state'     => self::state(),
		);
	}

	/**
	 * Let a suspended account back in, while the suspension is still the
	 * one made here.
	 *
	 * @return array{id: int, login: string}|\WP_Error
	 */
	public static function lift( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$id = (int) ( $entry->prior_state['user'] ?? 0 );

		if ( null !== $entry->reverted_at || Suspension::token( $id ) !== $token ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'This account is not suspended from here now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! Suspension::change( $id, '', $token ) ) {
			$refusal = Accounts::refusal( $id );

			return new \WP_Error( 'bettershield_lift_refused', '' !== $refusal ? $refusal : __( 'It could not be let back in. Try again.', 'bettershield' ), array( 'status' => 409 ) );
		}

		Ledger::mark_reverted( $token );
		self::recorded( 'account_suspension_lifted', $id, $token );
		Auditor::run();

		return array(
			'id'    => $id,
			'login' => (string) ( $entry->prior_state['login'] ?? '' ),
		);
	}

	/**
	 * What the list of suspensions says about one made here.
	 *
	 * @param mixed $hint
	 * @param mixed $id
	 * @param mixed $key
	 * @return mixed
	 */
	public static function lift_hint( $hint, $id = 0, $key = '' ) {
		return self::ACTION === $key ? __( 'Suspended from Findings because it went unused.', 'bettershield' ) : $hint;
	}

	/**
	 * Where the list of suspensions lets one made here back in.
	 *
	 * @param mixed $path
	 * @param mixed $id
	 * @param mixed $key
	 * @return mixed
	 */
	public static function lift_path( $path, $id = 0, $key = '' ) {
		return self::ACTION === $key ? self::LIFT_PATH : $path;
	}

	/**
	 * Whether the recovery link or an alert email is sent to this account's
	 * address: suspending it would take away the way back in it carries.
	 */
	private static function keeps_a_way_back( int $id ): bool {
		$user  = get_userdata( $id );
		$email = $user instanceof \WP_User ? strtolower( (string) $user->user_email ) : '';

		if ( '' === $email ) {
			return false;
		}

		$addresses = array_merge( array( \BetterShield\Recovery\RecoveryLink::mailed_to() ), \BetterShield\Alerts\Settings::instance()->recipients() );

		return in_array( $email, array_map( 'strtolower', array_map( 'strval', $addresses ) ), true );
	}

	private static function recorded( string $type, int $id, string $undo ): void {
		Writer::instance()->record(
			$type,
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $id,
				'context'     => array(
					'reason' => 'dormant',
					'undo'   => $undo,
				),
			)
		);
	}
}
