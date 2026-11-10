<?php
/**
 * Conservative version ranges shared with the intelligence service.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
final class Versions {
	/** Unsupported spellings are unknown, never silently safe. */
	public static function compare( string $a, string $b ): ?int {
		$a = self::parse( $a );
		$b = self::parse( $b );
		if ( null === $a || null === $b ) {
			return null;
		}
		$n = max( count( $a[0] ), count( $b[0] ) );
		for ( $i = 0; $i < $n; $i++ ) {
			$c = self::number( $a[0][ $i ] ?? '0', $b[0][ $i ] ?? '0' );
			if ( 0 !== $c ) {
				return $c;
			}
		}
		return ( $a[1] <=> $b[1] ) ?: self::number( $a[2], $b[2] );
	}

	private static function parse( string $v ): ?array {
		if ( strlen( $v ) > 128 || ! preg_match( '/^([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(dev|alpha|a|beta|b|RC|rc|pl|p)([0-9]*))?$/D', $v, $m ) ) {
			return null;
		}
		$rank = array( 'dev' => 0, 'alpha' => 1, 'a' => 1, 'beta' => 2, 'b' => 2, 'RC' => 3, 'rc' => 3, '' => 4, 'pl' => 5, 'p' => 5 );
		return array( explode( '.', $m[1] ), $rank[ $m[2] ?? '' ], $m[3] ?? '0' );
	}

	private static function number( string $a, string $b ): int {
		$a = ltrim( $a, '0' );
		$b = ltrim( $b, '0' );
		return ( strlen( $a ) <=> strlen( $b ) ) ?: ( strcmp( $a, $b ) <=> 0 );
	}
	public static function in_range( string $v, array $range ): ?bool {
		$from = $range['from'];
		$to = $range['to'];
		if ( null === $from && null === $to ) {
			return true;
		}
		if ( null !== $from && null !== $to ) {
			$order = self::compare( $from, $to );
			if ( null === $order || $order > 0 || ( 0 === $order && ( ! $range['from_inclusive'] || ! $range['to_inclusive'] ) ) ) {
				return null;
			}
		}
		$lower = null === $from ? 1 : self::compare( $v, $from );
		$upper = null === $to ? -1 : self::compare( $v, $to );
		if ( null === $lower || null === $upper ) {
			return null;
		}
		return ( $lower > 0 || ( 0 === $lower && $range['from_inclusive'] ) ) && ( $upper < 0 || ( 0 === $upper && $range['to_inclusive'] ) );
	}
	public static function result( string $v, array $a ): string {
		$unknown_patch = false;
		foreach ( $a['patched_versions'] ?? array() as $patch ) {
			$c = self::compare( $v, $patch );
			if ( 0 === $c ) {
				return 'unaffected';
			}
			$unknown_patch = $unknown_patch || null === $c;
		}
		foreach ( $a['patched_ranges'] ?? array() as $range ) {
			$c = self::in_range( $v, $range );
			if ( true === $c ) {
				return 'unaffected';
			}
			$unknown_patch = $unknown_patch || null === $c;
		}
		$unknown = false;
		foreach ( $a['affected_ranges'] as $range ) {
			$c = self::in_range( $v, $range );
			if ( true === $c ) {
				return $unknown_patch ? 'unknown' : 'affected';
			}
			$unknown = $unknown || null === $c;
		}
		return $unknown || ! $a['affected_ranges'] ? 'unknown' : 'unaffected';
	}
}
