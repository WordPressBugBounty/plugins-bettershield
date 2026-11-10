<?php
/**
 * A reversible hold that makes an account set a new password before its
 * password signs it in again.
 *
 * Demoting an account, ending its sessions and revoking its application
 * passwords all leave one door as it was: whoever holds the password signs
 * straight back in. The obvious answer, overwriting the password, cannot be
 * undone without keeping the old hash, which the response ledger never stores.
 * So this never touches the password at all. It refuses the password at
 * sign-in and names the way through, "Lost your password?", which sends a
 * link to the account's own address. Setting a new password by any route
 * lifts the hold by itself; undo lifts it without one.
 *
 * Four rules keep it on the safe side of the recovery invariant:
 *
 * - **The password is checked first.** The refusal comes after WordPress has
 *   verified the password, so a stranger typing the username learns nothing
 *   about the hold, and the refusal does not count toward a lockout.
 * - **Password sign-in only.** A passkey, an application password and this
 *   plugin's own flows re-running the chain are not what the hold is about,
 *   and are decided by the one seam every password gate here shares.
 * - **Safe mode stands it down**, as it stands down every protection, so the
 *   recovery link always opens the site.
 * - **Never the last administrator**, checked again at sign-in rather than
 *   only when the hold was placed.
 *
 * On a network the password belongs to the network, so the hold does too.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Remediation;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\TwoFactor\Manager;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PasswordHold {

	/** The holds in force, by user id, each with its ledger token. */
	public const OPTION = 'bettershield_password_holds';

	/** The ledger action a hold is written under. */
	public const KEY = 'incident_password_hold';

	/** The refusal's error code, which the sign-in counters leave uncounted. */
	public const REFUSAL = 'bettershield_new_password_required';

	/** A bound on the stored map, so it cannot grow without end. */
	private const MAX_HOLDS = 100;

	/** @return array<int, string> */
	private static function state(): array {
		$stored = get_site_option( self::OPTION, array() );
		$out    = array();

		foreach ( is_array( $stored ) ? $stored : array() as $id => $token ) {
			if ( (int) $id > 0 && is_string( $token ) && '' !== $token ) {
				$out[ (int) $id ] = $token;
			}
		}

		return $out;
	}

	public static function token( int $id ): string {
		return self::state()[ $id ] ?? '';
	}

	public static function has( int $id ): bool {
		return '' !== self::token( $id );
	}

	/**
	 * The accounts whose password the hold refuses right now.
	 *
	 * @return int[]
	 */
	public static function blocked_ids(): array {
		return array_values( array_filter( array_keys( self::state() ), array( self::class, 'blocks' ) ) );
	}

	/**
	 * Whether the hold refuses this account's password right now.
	 */
	public static function blocks( int $id ): bool {
		if ( $id < 1 || ! self::has( $id ) || SafeMode::is_active() ) {
			return false;
		}

		$user = get_userdata( $id );

		if ( ! $user ) {
			return false;
		}

		// A later role change must not leave the site with nobody who can
		// sign in to manage it by password.
		if ( ! empty( $user->allcaps['manage_options'] ) && ! get_users(
			array(
				'capability'    => 'manage_options',
				'exclude'       => array_unique( array_merge( array( $id ), array_keys( self::state() ) ) ),
				'number'        => 1,
				'fields'        => 'ID',
				'cache_results' => false,
			)
		) ) {
			return false;
		}

		return true;
	}

	/**
	 * Place a hold, written to the ledger before it takes effect.
	 *
	 * @param string $why What placed it, kept with the way back so a list of
	 *                    one kind of hold can tell its own apart.
	 * @return string The ledger token that undoes it, or '' when refused.
	 */
	public static function place( int $id, string $why = '' ): string {
		if ( '' !== Accounts::refusal( $id, true ) || self::has( $id ) || count( self::state() ) >= self::MAX_HOLDS ) {
			return '';
		}

		$token = Ledger::open( self::KEY, array( 'user' => $id ) + ( '' === $why ? array() : array( 'why' => $why ) ), array( 'held' => true ) );

		if ( ! $token ) {
			return '';
		}

		$state        = self::state();
		$state[ $id ] = $token;

		if ( ! update_site_option( self::OPTION, $state ) && self::state() !== $state ) {
			return '';
		}

		return self::token( $id ) === $token ? $token : '';
	}

	/**
	 * Lift a hold. `$reason` is `undo` for a person pressing Undo,
	 * `new_password` when the holder set one, or `not_sent` when the reset
	 * email that goes with the hold could not be sent.
	 */
	public static function lift( int $id, string $reason ): bool {
		$token = self::token( $id );

		if ( '' === $token ) {
			return false;
		}

		$state = self::state();
		unset( $state[ $id ] );

		if ( ! update_site_option( self::OPTION, $state ) && self::state() !== $state ) {
			return false;
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'password_hold_lifted',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $id,
				'context'     => array( 'reason' => in_array( $reason, array( 'new_password', 'not_sent' ), true ) ? $reason : 'undo' ),
			)
		);

		return true;
	}

	/**
	 * Refuse a correct password for an account on hold.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public static function gate( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || ! self::blocks( (int) $user->ID ) ) {
			return $user;
		}

		/*
		 * Every way in that is not this password stands aside — a passkey, a
		 * session, an application password — but a sign-in parked for its
		 * code after the password was checked is that password sign-in
		 * finishing, even if the hold arrived while it waited.
		 */
		if ( Manager::instance()->password_path_exempt( $user, (string) $password ) && ! Manager::instance()->finishing_a_password( (int) $user->ID ) ) {
			return $user;
		}

		return self::error();
	}

	public static function error(): \WP_Error {
		return new \WP_Error(
			self::REFUSAL,
			__( 'Set a different password to sign in: use the reset link emailed to this account, or “Lost your password?”.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * A new password, however it was set, lifts the hold.
	 *
	 * Only a real change: core also sets the password when it rehashes one at
	 * sign-in and when an account is created, and on those paths the new
	 * password still matches the hash it replaces.
	 *
	 * @param mixed $password
	 * @param mixed $user_id
	 * @param mixed $old_user_data
	 */
	public static function password_set( $password, $user_id, $old_user_data = null ): void {
		if ( ! $old_user_data instanceof \WP_User || ! self::has( (int) $user_id ) ) {
			return;
		}

		// Compared as WordPress stored it, trimmed: the old password with
		// spaces around it is the old password, and not a new one.
		if ( wp_check_password( trim( (string) $password ), (string) $old_user_data->user_pass, (int) $user_id ) ) {
			return;
		}

		self::lift( (int) $user_id, 'new_password' );
	}

	/**
	 * The reset form refuses the password the account already has while it
	 * is on hold.
	 *
	 * Core's form accepts the same password, and only a real change lifts
	 * the hold, so the person was sent back to "Lost your password?" again
	 * with no way through but an owner's undo. Compared trimmed, as a new
	 * password is.
	 *
	 * @param mixed $errors
	 * @param mixed $user
	 */
	public static function check_reset( $errors, $user ): void {
		if ( ! $errors instanceof \WP_Error || ! $user instanceof \WP_User || ! self::has( (int) $user->ID ) ) {
			return;
		}

		// Read from where the reset form posts it; absent means the form is
		// being drawn, not submitted.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the reset flow, core's or a store's, verifies its own key before this hook fires.
		$posted   = isset( $_POST['pass1'] ) ? $_POST['pass1'] : ( $_POST['password_1'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Missing -- unslashed on the next line; a password is compared, never stored or output.
		$password = trim( (string) wp_unslash( $posted ) );

		if ( '' !== $password && wp_check_password( $password, (string) $user->user_pass, (int) $user->ID ) ) {
			$errors->add( 'bettershield_new_password_same', __( 'Choose a different password. This account needs a new one to sign in.', 'bettershield' ) );
		}
	}

	/**
	 * The profile screen and `wp_update_user()` set a password without
	 * calling `wp_set_password()`, so the change is read from the stored
	 * hash instead: only a save that changed it counts.
	 *
	 * @param mixed                $old_user_data
	 * @param array<string, mixed> $userdata
	 */
	public static function profile_updated( int $user_id, $old_user_data, array $userdata = array() ): void {
		if (
			$old_user_data instanceof \WP_User
			&& isset( $userdata['user_pass'] )
			&& (string) $userdata['user_pass'] !== (string) $old_user_data->user_pass
			&& self::has( $user_id )
		) {
			self::lift( $user_id, 'new_password' );
		}
	}

	/** An account that is deleted takes its hold with it. */
	public static function account_deleted( int $id ): void {
		if ( ! self::has( $id ) ) {
			return;
		}

		$state = self::state();
		unset( $state[ $id ] );
		update_site_option( self::OPTION, $state );
	}

	public static function register(): void {
		// After lockdown (32) and before the passkey-only gate (35) and the
		// second factor (40): the password has been verified by then, and an
		// account on hold is never sent on to a code screen.
		add_filter( 'authenticate', array( self::class, 'gate' ), 34, 3 );
		add_action( 'wp_set_password', array( self::class, 'password_set' ), 10, 3 );
		add_action( 'validate_password_reset', array( self::class, 'check_reset' ), 10, 2 );
		add_action( 'profile_update', array( self::class, 'profile_updated' ), 10, 3 );
		add_action( 'deleted_user', array( self::class, 'account_deleted' ) );
		add_action( 'wpmu_delete_user', array( self::class, 'account_deleted' ) );
	}
}
