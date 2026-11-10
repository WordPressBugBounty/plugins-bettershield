<?php
/**
 * Time-based one-time passwords, RFC 6238 over RFC 4226.
 *
 * Implemented here rather than pulled in: the distributed plugin carries no
 * Composer runtime and no vendor directory, and TOTP — unlike WebAuthn — is
 * small enough to hold in one readable file: one HMAC, one truncation, one
 * modulo. The test suite pins this implementation to the RFC's own published
 * vectors, which is a stronger guarantee than trusting a library version.
 *
 * Standard parameters throughout, because authenticator apps assume them:
 * SHA-1, thirty-second steps, six digits. SHA-1's known weaknesses do not
 * apply to HMAC use, and every authenticator app speaks it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Totp {

	public const PERIOD = 30;
	public const DIGITS = 6;

	private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * A fresh shared secret: 20 random bytes (RFC 4226's recommended
	 * minimum), base32 for the authenticator app.
	 */
	public static function generate_secret(): string {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The code an authenticator shows at a moment in time.
	 */
	public static function code( string $base32_secret, int $timestamp ): string {
		return self::hotp( self::base32_decode( $base32_secret ), intdiv( $timestamp, self::PERIOD ) );
	}

	/**
	 * Verify a submitted code, answering WHICH timestep matched, or null.
	 *
	 * The window is one step either side: phone clocks drift, and a code
	 * typed in the last seconds of its step must not fail for network time.
	 * The caller stores the matched step and refuses anything at or below
	 * it, which is what makes a stolen-over-the-shoulder code worthless.
	 */
	public static function verify( string $base32_secret, string $submitted, int $timestamp, int $last_used_step = 0 ): ?int {
		$secret = self::base32_decode( $base32_secret );

		/*
		 * A secret nobody set verifies a code anybody can compute. Refused at
		 * the primitive so no caller can reintroduce it — and judged on the
		 * decoded key rather than on the string it came in as, because
		 * base32_decode() drops every foreign character rather than failing.
		 * "-----" and "01890" are both empty keys wearing a costume. Ten bytes
		 * is the shortest RFC 4226 contemplates.
		 */
		if ( strlen( $secret ) < 10 ) {
			return null;
		}

		$submitted = preg_replace( '/\s+/', '', $submitted );

		if ( ! is_string( $submitted ) || 1 !== preg_match( '/^[0-9]{' . self::DIGITS . '}$/', $submitted ) ) {
			return null;
		}

		$step = intdiv( $timestamp, self::PERIOD );

		foreach ( array( 0, -1, 1 ) as $offset ) {
			$candidate = $step + $offset;

			if ( $candidate <= $last_used_step ) {
				continue; // Replay: this step, or an older one, already signed someone in.
			}

			if ( hash_equals( self::hotp( $secret, $candidate ), $submitted ) ) {
				return $candidate;
			}
		}

		return null;
	}

	/**
	 * The otpauth:// URI an authenticator app enrolls from, rendered as a QR
	 * code by the screen and shown as text beside it.
	 */
	public static function enrollment_uri( string $base32_secret, string $account, string $issuer ): string {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			$base32_secret,
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}

	/* ---- RFC 4226 ---------------------------------------------------------- */

	private static function hotp( string $secret, int $counter ): string {
		// 64-bit big-endian counter, HMAC-SHA1, dynamic truncation.
		$hash   = hash_hmac( 'sha1', pack( 'J', $counter ), $secret, true );
		$offset = ord( $hash[19] ) & 0x0F;

		$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ord( $hash[ $offset + 1 ] ) << 16 )
			| ( ord( $hash[ $offset + 2 ] ) << 8 )
			| ord( $hash[ $offset + 3 ] );

		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/* ---- base32 (RFC 4648, unpadded) ---------------------------------------- */

	public static function base32_encode( string $bytes ): string {
		$out    = '';
		$buffer = 0;
		$bits   = 0;

		foreach ( str_split( $bytes ) as $byte ) {
			$buffer = ( $buffer << 8 ) | ord( $byte );
			$bits  += 8;

			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::BASE32_ALPHABET[ ( $buffer >> $bits ) & 0x1F ];
			}
		}

		if ( $bits > 0 ) {
			$out .= self::BASE32_ALPHABET[ ( $buffer << ( 5 - $bits ) ) & 0x1F ];
		}

		return $out;
	}

	public static function base32_decode( string $base32 ): string {
		$base32 = strtoupper( str_replace( array( ' ', '=' ), '', $base32 ) );
		$out    = '';
		$buffer = 0;
		$bits   = 0;

		foreach ( str_split( $base32 ) as $char ) {
			$index = strpos( self::BASE32_ALPHABET, $char );

			if ( false === $index ) {
				continue; // Foreign characters are dropped, not fatal: apps show secrets in spaced groups.
			}

			$buffer = ( $buffer << 5 ) | $index;
			$bits  += 5;

			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}

		return $out;
	}
}
