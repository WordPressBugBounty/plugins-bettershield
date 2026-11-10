<?php
/**
 * One SPF value to publish in place of what the domain has now (#2203).
 *
 * A wrong SPF record stops legitimate mail, so this proposes a value only
 * where it can read every part of the old one. Every mechanism and modifier
 * there stays, in its order; two records become one; an "all" that lets
 * anyone send becomes ~all; and a sending service identified without doubt
 * is added. Anything it cannot read, two records that disagree, or a value
 * that would pass the ten DNS lookups SPF allows is refused, and the owner
 * is told why rather than handed a guess.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SpfRecord {

	/** The most DNS lookups an SPF check may make (RFC 7208 4.6.4). */
	public const LOOKUP_LIMIT = 10;

	/** Mechanisms that cost a lookup, and the one modifier that does. */
	private const LOOKUPS = array( 'include', 'a', 'mx', 'ptr', 'exists', 'redirect' );

	/** How strongly each "all" refuses, strongest first. */
	private const ALL_ORDER = array( '-', '~', '?' );

	/**
	 * The value to publish, or why none is offered.
	 *
	 * @param string[] $records  The SPF records published now; none where it is missing.
	 * @param string[] $includes Sending services to add, as `include:` targets.
	 * @return array{value?: string, added?: string[], refused?: string}
	 */
	public static function propose( array $records, array $includes = array() ): array {
		$mechanisms = array();
		$modifiers  = array();
		$alls       = array();
		$missing    = array() === $records;

		foreach ( $records as $record ) {
			$terms = preg_split( '/\s+/', trim( (string) $record ) );

			if ( ! is_array( $terms ) || 'v=spf1' !== strtolower( (string) array_shift( $terms ) ) ) {
				return array( 'refused' => 'unreadable' );
			}

			foreach ( $terms as $term ) {
				if ( '' === $term ) {
					continue;
				}

				if ( 1 === preg_match( '/^([a-z][a-z0-9_.\-]*)=(\S*)$/i', $term, $match ) ) {
					$name = strtolower( $match[1] );

					// The same modifier twice with two values cannot be one
					// record (RFC 7208 6): which was meant is the owner's call.
					if ( isset( $modifiers[ $name ] ) && strtolower( $modifiers[ $name ] ) !== strtolower( $match[2] ) ) {
						return array( 'refused' => 'conflict' );
					}

					$modifiers[ $name ] = $match[2];
					continue;
				}

				if ( 1 !== preg_match( '/^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:(:)([^\s\/]+))?(\/\/?\d{1,3}(?:\/\/\d{1,3})?|\/\d{1,3})?$/i', $term, $match ) ) {
					return array( 'refused' => 'unreadable' );
				}

				$kind   = strtolower( $match[2] );
				$target = $match[4] ?? '';
				$cidr   = $match[5] ?? '';
				$needs  = in_array( $kind, array( 'include', 'exists', 'ip4', 'ip6' ), true );

				// A mechanism missing the target it needs, or "all" given one.
				if ( ( $needs && '' === $target ) || ( 'all' === $kind && ( '' !== $target || '' !== $cidr ) ) ) {
					return array( 'refused' => 'unreadable' );
				}

				if ( 'all' === $kind ) {
					$alls[] = $match[1];
					continue;
				}

				$key = strtolower( ltrim( $term, '+' ) );

				if ( ! isset( $mechanisms[ $key ] ) ) {
					$mechanisms[ $key ] = $term;
				}
			}
		}

		// Two records, one sending somewhere else entirely: the other's
		// mechanisms would never be read.
		if ( count( $records ) > 1 && isset( $modifiers['redirect'] ) ) {
			return array( 'refused' => 'conflict' );
		}

		if ( $missing ) {
			$mechanisms = array(
				'mx' => 'mx',
				'a'  => 'a',
			);
		}

		$added = array();

		foreach ( $includes as $include ) {
			$include = strtolower( trim( (string) $include ) );
			$key     = 'include:' . $include;

			if ( '' === $include || 1 !== preg_match( '/^[a-z0-9_.\-]+$/', $include ) || isset( $mechanisms[ $key ] ) || isset( $mechanisms[ '-' . $key ] ) || isset( $mechanisms[ '~' . $key ] ) || isset( $mechanisms[ '?' . $key ] ) ) {
				continue;
			}

			$mechanisms[ $key ] = $key;
			$added[]            = $key;
		}

		$lookups = isset( $modifiers['redirect'] ) ? 1 : 0;

		foreach ( array_keys( $mechanisms ) as $key ) {
			$kind = (string) preg_replace( '/^[+\-~?]|[:\/].*$/', '', $key );

			if ( in_array( $kind, self::LOOKUPS, true ) ) {
				++$lookups;
			}
		}

		if ( $lookups > self::LOOKUP_LIMIT ) {
			return array( 'refused' => 'lookups' );
		}

		$terms = array_values( $mechanisms );
		$all   = self::final_all( $alls, $missing );

		if ( null !== $all ) {
			$terms[] = $all;
		}

		foreach ( $modifiers as $name => $value ) {
			$terms[] = $name . '=' . $value;
		}

		return array(
			'value' => 'v=spf1 ' . implode( ' ', $terms ),
			'added' => $added,
		);
	}

	/**
	 * The one "all" the record ends with: the strictest it had, where that
	 * was ~all, -all or ?all; ~all in place of one that lets anybody send,
	 * and ~all on a new record. A record that had none keeps having none.
	 *
	 * @param string[] $alls The qualifiers of the "all" terms it had.
	 */
	private static function final_all( array $alls, bool $missing ): ?string {
		if ( $missing ) {
			return '~all';
		}

		if ( array() === $alls ) {
			return null;
		}

		foreach ( self::ALL_ORDER as $qualifier ) {
			if ( in_array( $qualifier, $alls, true ) ) {
				return $qualifier . 'all';
			}
		}

		return '~all';
	}
}
