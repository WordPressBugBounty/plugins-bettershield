<?php
/**
 * Just enough CBOR to read what an authenticator sends.
 *
 * WebAuthn wraps its attestation object and its public keys in CBOR, and PHP
 * has no CBOR decoder. The usual answer is a WebAuthn library that arrives
 * with forty dependencies; this is the other answer, and it is small enough to
 * read in one sitting.
 *
 * **Only the subset WebAuthn actually uses is implemented**, and anything
 * outside it is refused rather than guessed at. Tags, indefinite lengths,
 * floats and 64-bit lengths do not appear in an attestation object, and a
 * decoder that quietly accepted them would be a decoder attacker-supplied
 * bytes could steer.
 *
 * Every failure is an exception, never a partial result. Half-decoded
 * cryptographic material is worse than none.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cbor {

	/** Guards a malicious payload from nesting until the stack gives out. */
	private const MAX_DEPTH = 16;

	/** Nothing WebAuthn sends is remotely this large. */
	private const MAX_ITEMS = 1024;

	private string $data;
	private int $offset = 0;

	private function __construct( string $data ) {
		$this->data = $data;
	}

	/**
	 * Decode one CBOR value. Trailing bytes are an error, not something to
	 * ignore: an attestation object is exactly one value.
	 *
	 * @return mixed
	 * @throws \RuntimeException When the bytes are not CBOR this understands.
	 */
	public static function decode( string $data ) {
		$decoder = new self( $data );
		$value   = $decoder->value( 0 );

		if ( $decoder->offset !== strlen( $data ) ) {
			throw new \RuntimeException( 'Trailing bytes after the CBOR value.' );
		}

		return $value;
	}

	/**
	 * Decode one value and report where it ended.
	 *
	 * The authenticator data inside an attestation statement is followed by
	 * bytes that are not part of it, so the credential parser needs to know
	 * where the public key stopped.
	 *
	 * @return array{0: mixed, 1: int}
	 * @throws \RuntimeException When the bytes are not CBOR this understands.
	 */
	public static function decode_first( string $data ): array {
		$decoder = new self( $data );
		$value   = $decoder->value( 0 );

		return array( $value, $decoder->offset );
	}

	/**
	 * @return mixed
	 * @throws \RuntimeException
	 */
	private function value( int $depth ) {
		if ( $depth > self::MAX_DEPTH ) {
			throw new \RuntimeException( 'CBOR nested too deeply.' );
		}

		$initial = $this->byte();
		$major   = $initial >> 5;
		$minor   = $initial & 0x1F;

		switch ( $major ) {
			case 0: // Unsigned integer.
				return $this->argument( $minor );

			case 1: // Negative integer. COSE key labels are negative.
				return -1 - $this->argument( $minor );

			case 2: // Byte string.
				return $this->take( $this->argument( $minor ) );

			case 3: // Text string.
				return $this->take( $this->argument( $minor ) );

			case 4: // Array.
				$count = $this->argument( $minor );
				$this->guard_count( $count );
				$out = array();
				for ( $i = 0; $i < $count; $i++ ) {
					$out[] = $this->value( $depth + 1 );
				}
				return $out;

			case 5: // Map.
				$count = $this->argument( $minor );
				$this->guard_count( $count );
				$out = array();
				for ( $i = 0; $i < $count; $i++ ) {
					$key = $this->value( $depth + 1 );

					if ( ! is_int( $key ) && ! is_string( $key ) ) {
						throw new \RuntimeException( 'CBOR map key is neither an integer nor a string.' );
					}

					// RFC 8949 §5.6. Two values under one key means two readers
					// can disagree about what these bytes say, which is the
					// property this decoder exists to deny.
					if ( array_key_exists( $key, $out ) ) {
						throw new \RuntimeException( 'Duplicate CBOR map key.' );
					}

					$out[ $key ] = $this->value( $depth + 1 );
				}
				return $out;

			case 7: // Simple values: only the three that carry meaning here.
				if ( 20 === $minor ) {
					return false;
				}
				if ( 21 === $minor ) {
					return true;
				}
				if ( 22 === $minor ) {
					return null;
				}
				throw new \RuntimeException( 'Unsupported CBOR simple value.' );

			default:
				// Major type 6 is tagging. Nothing in WebAuthn uses it, so it
				// is refused rather than unwrapped.
				throw new \RuntimeException( 'Unsupported CBOR major type.' );
		}
	}

	/**
	 * The length or value that follows the initial byte.
	 *
	 * @throws \RuntimeException
	 */
	private function argument( int $minor ): int {
		if ( $minor < 24 ) {
			return $minor;
		}

		switch ( $minor ) {
			case 24:
				return $this->byte();
			case 25:
				return $this->integer( 2 );
			case 26:
				return $this->integer( 4 );
			default:
				// 27 is a 64-bit length and 31 is an indefinite one. Neither
				// occurs in what an authenticator sends, and both are how a
				// decoder gets talked into allocating.
				throw new \RuntimeException( 'Unsupported CBOR length encoding.' );
		}
	}

	private function integer( int $bytes ): int {
		$value = 0;

		for ( $i = 0; $i < $bytes; $i++ ) {
			$value = ( $value << 8 ) | $this->byte();
		}

		return $value;
	}

	/**
	 * @throws \RuntimeException
	 */
	private function byte(): int {
		if ( $this->offset >= strlen( $this->data ) ) {
			throw new \RuntimeException( 'CBOR ended early.' );
		}

		return ord( $this->data[ $this->offset++ ] );
	}

	/**
	 * @throws \RuntimeException
	 */
	private function take( int $length ): string {
		if ( $length < 0 || $this->offset + $length > strlen( $this->data ) ) {
			throw new \RuntimeException( 'CBOR string runs past the end of the data.' );
		}

		$out           = substr( $this->data, $this->offset, $length );
		$this->offset += $length;

		return $out;
	}

	/**
	 * @throws \RuntimeException
	 */
	private function guard_count( int $count ): void {
		if ( $count > self::MAX_ITEMS ) {
			throw new \RuntimeException( 'CBOR collection is implausibly large.' );
		}
	}
}
