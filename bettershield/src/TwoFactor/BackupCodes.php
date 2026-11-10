<?php
/**
 * Backup codes: the second factor for the day the first one is gone.
 *
 * Ten codes, generated at enrollment, shown exactly once, stored only as
 * password hashes, each usable exactly once — a property `consume()` holds
 * by conditioning its write on the set it read, rather than by the order of
 * statements inside one request. The plaintext exists for the duration of
 * one HTTP response and is never written anywhere — the same discipline as
 * the recovery link.
 *
 * A new set is staged before it takes effect. Until the person says they
 * have stored it, the set already in force keeps working: an enrollment
 * abandoned halfway must never leave someone holding codes that stopped
 * working without anyone telling them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class BackupCodes {

	public const COUNT = 10;

	private const META    = 'bettershield_backup_codes';
	private const PENDING = 'bettershield_backup_codes_pending';

	/** The bcrypt cost of a code brought over; see `bring_over()`. */
	private const IMPORTED_COST = 4;

	/**
	 * Generate a set for an enrollment that has not armed yet. The hashes
	 * are held aside; whatever set is in force stays in force. Returns the
	 * plaintext codes — the only moment they exist in the clear.
	 *
	 * @return string[]
	 */
	public static function stage( int $user_id ): array {
		$codes  = array();
		$hashes = array();

		for ( $i = 0; $i < self::COUNT; $i++ ) {
			// Eight digits, grouped for reading aloud over a phone. Distinct
			// in shape from a six-digit TOTP code, so the login field can
			// accept either and tell them apart.
			$code = str_pad( (string) random_int( 0, 99999999 ), 8, '0', STR_PAD_LEFT );

			$codes[]  = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
			$hashes[] = password_hash( $code, PASSWORD_DEFAULT );
		}

		update_user_meta( $user_id, self::PENDING, $hashes );

		return $codes;
	}

	/**
	 * Put the staged set in force, replacing the one before it. False when
	 * nothing was staged: a factor must never arm on codes that were never
	 * put in front of anybody.
	 */
	public static function promote( int $user_id ): bool {
		$hashes = get_user_meta( $user_id, self::PENDING, true );

		if ( ! is_array( $hashes ) || array() === $hashes ) {
			return false;
		}

		update_user_meta( $user_id, self::META, array_values( $hashes ) );
		delete_user_meta( $user_id, self::PENDING );

		return true;
	}

	/**
	 * Issue a fresh set for an account already using two-factor, replacing
	 * whatever it had.
	 *
	 * Ten codes were minted once, at enrollment, and from then on only ever
	 * decreased — the class had `consume`, `discard` and `forget` and no way at
	 * all to mint a set for an enrolled account. An editor who spent theirs and
	 * then lost their phone had no way in: the app is gone, the codes are gone,
	 * and the recovery link is the site owner's credential rather than theirs.
	 * The codes were built as a step of enrollment instead of as a credential
	 * with a life of its own.
	 *
	 * Replaced whole, never appended to. A set that grows would mean an old
	 * code printed a year ago still opens the account, which is the opposite of
	 * what reissuing is for.
	 *
	 * Returns the plaintext codes — the only moment they exist in the clear.
	 * The caller has already proved it holds a current code; see the route.
	 *
	 * @return string[]
	 */
	public static function reissue( int $user_id ): array {
		$codes = self::stage( $user_id );

		self::promote( $user_id );

		return $codes;
	}

	/**
	 * Whether a set is staged and still waiting to be acknowledged.
	 *
	 * Asked before staging another. The plaintext of a staged set exists for
	 * exactly one response, so a second staging replaces a set the person is
	 * still reading off the screen with one they have never seen — and the
	 * acknowledgment then promotes the one they are not holding.
	 */
	public static function staged( int $user_id ): bool {
		$hashes = get_user_meta( $user_id, self::PENDING, true );

		return is_array( $hashes ) && array() !== $hashes;
	}

	/**
	 * Throw a staged set away, leaving the one in force untouched.
	 */
	public static function discard( int $user_id ): void {
		delete_user_meta( $user_id, self::PENDING );
	}

	/**
	 * Put codes brought over from another plugin in force, as this account's
	 * set: `remaining()`, a new set and erasure then treat them as any other.
	 *
	 * Hashed at the lowest bcrypt cost. Each is 64 random bits, so a slow hash
	 * adds nothing against guessing, and this runs per account inside the one
	 * request that deactivates the other plugin. Never use this cost for
	 * anything a person chooses.
	 *
	 * @param string[] $codes The codes, as `imported_code()` reduces them.
	 * @return int How many were put in force.
	 */
	public static function bring_over( int $user_id, array $codes ): int {
		$hashes = array();

		foreach ( $codes as $code ) {
			$hashes[] = password_hash( $code, PASSWORD_BCRYPT, array( 'cost' => self::IMPORTED_COST ) );
		}

		if ( array() === $hashes ) {
			return 0;
		}

		update_user_meta( $user_id, self::META, $hashes );

		return count( $hashes );
	}

	/**
	 * A submitted code reduced to the shape of a code brought over from
	 * another plugin, sixteen hex characters in lower case, or '' for any
	 * other shape. Spaces, dashes and capitals are how a printed one is typed.
	 */
	public static function imported_code( string $submitted ): string {
		$compact = (string) preg_replace( '/[\s-]+/', '', $submitted );

		return 1 === preg_match( '/^[0-9a-f]{16}$/iD', $compact ) ? strtolower( $compact ) : '';
	}

	/**
	 * Whether this account still holds a code brought over from another
	 * plugin. Those have letters in them, so a keypad of digits can't type them.
	 */
	public static function holds_imported( int $user_id ): bool {
		$hashes = get_user_meta( $user_id, self::META, true );
		$prefix = sprintf( '$2y$%02d$', self::IMPORTED_COST );

		foreach ( is_array( $hashes ) ? $hashes : array() as $hash ) {
			if ( is_string( $hash ) && str_starts_with( $hash, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Try a submitted code. A match consumes it, and the write that removes
	 * the hash is what decides the answer.
	 *
	 * Verifying and then writing are two steps, and between them the set on
	 * disk is still the set that contains this code — so two requests
	 * carrying one code both verify against a hash neither has spent yet, and
	 * both are told yes. The write therefore names the set it read as its own
	 * condition: the database admits whichever request still finds that set
	 * in place and refuses the other. One use per code, however the two are
	 * timed.
	 *
	 * A code refused for arriving second is indistinguishable to the caller
	 * from a wrong one, and counts toward the hourly guess cap like any
	 * other. That is a fair price: provoking it takes a valid code to begin
	 * with, and the holder is asked to try again with the next one.
	 */
	public static function consume( int $user_id, string $submitted ): bool {
		$imported  = self::imported_code( $submitted );
		$submitted = '' !== $imported ? $imported : (string) preg_replace( '/[^0-9]/', '', $submitted );

		if ( '' === $imported && 8 !== strlen( $submitted ) ) {
			return false;
		}

		$hashes = get_user_meta( $user_id, self::META, true );

		// An empty set cannot be the condition of a conditional write, and
		// has nothing to match in any case.
		if ( ! is_array( $hashes ) || array() === $hashes ) {
			return false;
		}

		foreach ( $hashes as $index => $hash ) {
			if ( ! is_string( $hash ) || ! password_verify( $submitted, $hash ) ) {
				continue;
			}

			$remaining = $hashes;
			unset( $remaining[ $index ] );

			// The fourth argument is the condition: core turns it into
			// `UPDATE ... WHERE meta_value = <the set just read>`, and reports
			// the row count back as false when nothing matched.
			return (bool) update_user_meta( $user_id, self::META, array_values( $remaining ), $hashes );
		}

		return false;
	}

	public static function remaining( int $user_id ): int {
		$hashes = get_user_meta( $user_id, self::META, true );

		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
		delete_user_meta( $user_id, self::PENDING );
	}
}
