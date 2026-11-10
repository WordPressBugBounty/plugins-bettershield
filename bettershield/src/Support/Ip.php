<?php
/**
 * IP address handling.
 *
 * Full IP addresses are personal data and are never stored. Addresses
 * are truncated before persistence: IPv4 to /24, IPv6 to /64, packed as
 * 16-byte binary (IPv4 in v4-mapped-v6 form) so one column handles both.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ip {

	/**
	 * The 96-bit prefix that marks an IPv4 address carried inside an IPv6 one.
	 * A dual-stack host hands PHP this form for every IPv4 visitor, so any
	 * code that decides who a caller is has to unwrap it first.
	 */
	public const V4_MAPPED_PREFIX = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

	/**
	 * The IPv4 address inside a packed v4-mapped v6 address, or null when the
	 * address is not one.
	 */
	public static function unmapped( string $packed ): ?string {
		if ( 16 !== strlen( $packed ) || self::V4_MAPPED_PREFIX !== substr( $packed, 0, 12 ) ) {
			return null;
		}

		$v4 = inet_ntop( substr( $packed, 12 ) );

		return is_string( $v4 ) ? $v4 : null;
	}

	/**
	 * Truncated 16-byte binary form of an IP, or null when unparseable.
	 */
	public static function truncated_binary( string $ip ): ?string {
		if ( '' === $ip ) {
			return null;
		}

		$packed = @inet_pton( $ip ); // phpcs:ignore -- invalid input intentionally yields null, not a warning.

		if ( false === $packed ) {
			return null;
		}

		if ( 4 === strlen( $packed ) ) {
			$packed[3] = "\x00"; // /24
			return "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" . $packed;
		}

		if ( 16 === strlen( $packed ) ) {
			// ::ffff:a.b.c.d is an IPv4 address in IPv6 clothing — what a
			// dual-stack host hands PHP. Truncated as IPv6 it would collapse
			// every such client onto ::/64; it is truncated as the IPv4 it is.
			if ( self::V4_MAPPED_PREFIX === substr( $packed, 0, 12 ) ) {
				$packed[15] = "\x00"; // /24
				return $packed;
			}

			return substr( $packed, 0, 8 ) . str_repeat( "\x00", 8 ); // /64
		}

		return null;
	}

	/**
	 * The display form of a stored 16-byte truncated prefix — "203.0.113.0/24"
	 * or "2001:db8::/64". The label never claims more precision than is kept.
	 */
	public static function prefix_label( ?string $binary ): ?string {
		if ( ! is_string( $binary ) || 16 !== strlen( $binary ) ) {
			return null;
		}

		$ip = inet_ntop( $binary );

		if ( false === $ip ) {
			return null;
		}

		if ( str_starts_with( $ip, '::ffff:' ) ) {
			return substr( $ip, 7 ) . '/24';
		}

		return $ip . '/64';
	}

	/**
	 * The same prefix for a reader who has never met range notation, as an
	 * address with its hidden part shown as "x": "203.0.113.x", or
	 * "2001:db8:0:0:x:x:x:x". For emails to account holders (#2403).
	 */
	public static function address_label( ?string $binary ): ?string {
		$label = self::prefix_label( $binary );

		if ( null === $label ) {
			return null;
		}

		if ( str_ends_with( $label, '/24' ) ) {
			return substr( $label, 0, (int) strrpos( $label, '.' ) ) . '.x';
		}

		$groups = array_map( static fn( string $pair ): string => dechex( (int) hexdec( $pair ) ), str_split( bin2hex( substr( (string) $binary, 0, 8 ) ), 4 ) );

		return implode( ':', $groups ) . ':x:x:x:x';
	}

	/**
	 * The stored 16-byte prefix a network label names, or null when the text
	 * is not exactly such a label — "203.0.113.0/24" or "2001:db8::/64".
	 *
	 * The reverse of `prefix_label()`, and deliberately strict: a full address
	 * is refused rather than truncated, so a link or a filter can name a
	 * network and never carry the address it came from.
	 */
	public static function from_label( string $label ): ?string {
		$label = trim( $label );

		if ( 1 === preg_match( '#^([0-9.]+)/24$#', $label, $m ) ) {
			$binary = self::truncated_binary( $m[1] );

			return null !== $binary && self::prefix_label( $binary ) === $label ? $binary : null;
		}

		if ( 1 === preg_match( '#^([0-9a-fA-F:]+)/64$#', $label, $m ) && str_contains( $m[1], ':' ) ) {
			$binary = self::truncated_binary( $m[1] );

			return null !== $binary && 0 === strcasecmp( (string) self::prefix_label( $binary ), $label ) ? $binary : null;
		}

		return null;
	}
}
