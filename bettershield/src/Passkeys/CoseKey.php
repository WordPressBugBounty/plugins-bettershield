<?php
/**
 * The public key an authenticator gave us, in a form PHP can verify with.
 *
 * WebAuthn hands over public keys as COSE maps — a set of numbered fields
 * holding raw curve coordinates or RSA components. PHP's openssl wants a PEM
 * SubjectPublicKeyInfo. The conversion is a fixed ASN.1 prefix and the raw
 * numbers appended, which is why this needs no library and no big-integer
 * extension: nothing here does arithmetic, it only reassembles bytes into the
 * envelope openssl already knows how to read.
 *
 * Three algorithms, in the order authenticators actually use them. **An
 * algorithm not on this list is refused rather than approximated** — a
 * signature check that silently fell back to something else would be a
 * signature check in name only.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CoseKey {

	/** ECDSA with P-256 and SHA-256. What almost every authenticator uses. */
	public const ES256 = -7;

	/** EdDSA with Ed25519. Verified through sodium, not openssl. */
	public const EDDSA = -8;

	/** RSASSA-PKCS1-v1_5 with SHA-256. Windows Hello, mostly. */
	public const RS256 = -257;

	/**
	 * The algorithms this plugin will accept, most preferred first. Sent to
	 * the authenticator at registration so it never enrolls a key we could not
	 * later verify.
	 *
	 * @return int[]
	 */
	public static function supported(): array {
		$supported = array( self::ES256, self::RS256 );

		// Only offered where it can be checked. Sodium ships with PHP 7.2 and
		// later, but a host can still build without it.
		if ( function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			$supported[] = self::EDDSA;
		}

		return $supported;
	}

	/**
	 * A COSE key map as a PEM public key, plus the algorithm it belongs to.
	 *
	 * @param array<int|string, mixed> $cose
	 * @return array{pem: string, alg: int}|\WP_Error
	 */
	public static function to_pem( array $cose ) {
		$kty = isset( $cose[1] ) ? (int) $cose[1] : 0;
		$alg = isset( $cose[3] ) ? (int) $cose[3] : 0;

		if ( ! in_array( $alg, self::supported(), true ) ) {
			return new \WP_Error(
				'bettershield_passkey_algorithm',
				__( 'That security key uses an unsupported signing method. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		// 2 = EC2, 3 = RSA, 1 = OKP (Ed25519).
		if ( 2 === $kty && self::ES256 === $alg ) {
			return self::ec2_pem( $cose );
		}

		if ( 3 === $kty && self::RS256 === $alg ) {
			return self::rsa_pem( $cose );
		}

		if ( 1 === $kty && self::EDDSA === $alg ) {
			return self::okp_pem( $cose );
		}

		return new \WP_Error(
			'bettershield_passkey_key_type',
			__( 'That security key uses an unsupported key type. Nothing was saved.', 'bettershield' ),
			array( 'status' => 400 )
		);
	}

	/**
	 * Verify a signature made by a stored key.
	 *
	 * @param string $signed The exact bytes the authenticator signed.
	 */
	public static function verify( string $pem, int $alg, string $signed, string $signature ): bool {
		if ( self::EDDSA === $alg ) {
			if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
				return false;
			}

			// The PEM for Ed25519 wraps the raw 32-byte key; sodium wants it raw.
			$raw = self::raw_from_pem( $pem );

			if ( 32 !== strlen( $raw ) || 64 !== strlen( $signature ) ) {
				return false;
			}

			try {
				return sodium_crypto_sign_verify_detached( $signature, $signed, $raw );
			} catch ( \Throwable $e ) {
				return false;
			}
		}

		$key = openssl_pkey_get_public( $pem );

		if ( false === $key ) {
			return false;
		}

		// ECDSA signatures arrive already DER-encoded per the WebAuthn spec,
		// which is the shape openssl expects, so there is nothing to convert.
		return 1 === openssl_verify( $signed, $signature, $key, OPENSSL_ALGO_SHA256 );
	}

	/**
	 * P-256, rebuilt from the two raw coordinates.
	 *
	 * The prefix is the constant SubjectPublicKeyInfo header for an
	 * uncompressed prime256v1 point: the ecPublicKey and prime256v1 object
	 * identifiers, then a bit string of the right length.
	 *
	 * @param array<int|string, mixed> $cose
	 * @return array{pem: string, alg: int}|\WP_Error
	 */
	private static function ec2_pem( array $cose ) {
		$curve = isset( $cose[-1] ) ? (int) $cose[-1] : 0;
		$x     = isset( $cose[-2] ) ? (string) $cose[-2] : '';
		$y     = isset( $cose[-3] ) ? (string) $cose[-3] : '';

		// 1 is P-256. Nothing else pairs with ES256.
		if ( 1 !== $curve || 32 !== strlen( $x ) || 32 !== strlen( $y ) ) {
			return new \WP_Error(
				'bettershield_passkey_curve',
				__( 'That security key sent unreadable key data. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		$der = (string) hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $x . $y;

		return array(
			'pem' => self::pem( $der ),
			'alg' => self::ES256,
		);
	}

	/**
	 * RSA, rebuilt from modulus and exponent.
	 *
	 * @param array<int|string, mixed> $cose
	 * @return array{pem: string, alg: int}|\WP_Error
	 */
	private static function rsa_pem( array $cose ) {
		$n = isset( $cose[-1] ) ? (string) $cose[-1] : '';
		$e = isset( $cose[-2] ) ? (string) $cose[-2] : '';

		if ( '' === $n || '' === $e ) {
			return new \WP_Error(
				'bettershield_passkey_rsa',
				__( 'That security key sent an incomplete public key. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		/*
		 * The other two key types are pinned to an exact length because their
		 * curves have one. RSA does not, so the size arrives from the client
		 * and nothing upstream has checked it: the attestation object is
		 * decoded and handed here unverified, which makes this the only place
		 * the question is asked. A modulus small enough to factor is not a
		 * public key in any useful sense, and one large enough to overrun the
		 * column it is stored in would be truncated rather than refused.
		 * Leading zero bytes are not size.
		 */
		$modulus = strlen( ltrim( $n, "\x00" ) );

		if ( $modulus < 256 || $modulus > 512 ) {
			return new \WP_Error(
				'bettershield_passkey_rsa_size',
				__( 'That security key sent a public key of an unsupported size. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		/*
		 * And the exponent, which arrives from the same unverified place the
		 * modulus does. With e=1, PKCS#1 v1.5 verification reduces to
		 * "signature mod n" — a signature anybody can produce with no private
		 * key at all — and OpenSSL loads such a key without complaint. An even
		 * exponent is not an RSA exponent in the first place. Odd, at least 3,
		 * and no wider than a machine word: real authenticators send 65537.
		 */
		$exponent = ltrim( $e, "\x00" );
		$width    = strlen( $exponent );

		if ( $width < 1 || $width > 4
			|| 0 === ( ord( $exponent[ $width - 1 ] ) & 1 )
			|| ( 1 === $width && ord( $exponent ) < 3 ) ) {
			return new \WP_Error(
				'bettershield_passkey_rsa_exponent',
				__( 'That security key sent an unsupported public key. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		$sequence = self::der( 0x30, self::der_integer( $n ) . self::der_integer( $e ) );
		$bits     = self::der( 0x03, "\x00" . $sequence );
		$header   = (string) hex2bin( '300d06092a864886f70d0101010500' );
		$der      = self::der( 0x30, $header . $bits );

		return array(
			'pem' => self::pem( $der ),
			'alg' => self::RS256,
		);
	}

	/**
	 * Ed25519. The PEM is only a container here — verification goes through
	 * sodium with the raw key, so this stores it in the same shape as the rest
	 * rather than inventing a second storage format.
	 *
	 * @param array<int|string, mixed> $cose
	 * @return array{pem: string, alg: int}|\WP_Error
	 */
	private static function okp_pem( array $cose ) {
		$x = isset( $cose[-2] ) ? (string) $cose[-2] : '';

		if ( 32 !== strlen( $x ) ) {
			return new \WP_Error(
				'bettershield_passkey_okp',
				__( 'That security key sent a public key of the wrong size. Nothing was saved.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		$der = (string) hex2bin( '302a300506032b6570032100' ) . $x;

		return array(
			'pem' => self::pem( $der ),
			'alg' => self::EDDSA,
		);
	}

	/** The raw key bytes back out of the PEM this class produced. */
	private static function raw_from_pem( string $pem ): string {
		$body = preg_replace( '/-----[A-Z ]+-----|\s+/', '', $pem );
		$der  = (string) base64_decode( (string) $body, true );

		// The Ed25519 header is a fixed twelve bytes; the key is the rest.
		return strlen( $der ) > 12 ? substr( $der, 12 ) : '';
	}

	private static function pem( string $der ): string {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/** One DER element: tag, length, contents. */
	private static function der( int $tag, string $contents ): string {
		$length = strlen( $contents );

		if ( $length < 0x80 ) {
			$header = chr( $length );
		} else {
			$bytes  = ltrim( pack( 'N', $length ), "\x00" );
			$header = chr( 0x80 | strlen( $bytes ) ) . $bytes;
		}

		return chr( $tag ) . $header . $contents;
	}

	/**
	 * A DER INTEGER from raw big-endian bytes. A leading zero is prepended
	 * where the high bit is set, because DER integers are signed and a modulus
	 * is not.
	 */
	private static function der_integer( string $bytes ): string {
		$bytes = ltrim( $bytes, "\x00" );

		if ( '' === $bytes ) {
			$bytes = "\x00";
		}

		if ( 0x80 & ord( $bytes[0] ) ) {
			$bytes = "\x00" . $bytes;
		}

		return self::der( 0x02, $bytes );
	}
}
