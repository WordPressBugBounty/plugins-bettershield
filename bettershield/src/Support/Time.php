<?php
/**
 * Stored timestamps, said out loud.
 *
 * Every datetime column this plugin owns holds UTC, written explicitly by the
 * caller, and the database hands it back with no marker on it: `2026-08-13
 * 05:29:38.504`. A browser reads a string in that shape as *local* time, so a
 * value that leaves here unmarked is displayed shifted by the reader's whole
 * offset from UTC — a change made at eleven this morning appearing to have been
 * made at five. Nothing errors; the screen is simply wrong, which is the worst
 * way for a security record to fail.
 *
 * One conversion, used by everything that returns a stored time, so a payload
 * cannot end up half marked and half not.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Time {

	/**
	 * A stored UTC datetime as ISO-8601, or null when there is nothing stored.
	 *
	 * Null passes through rather than becoming an epoch: a finding that was
	 * never resolved has no resolution time, and inventing one would be a
	 * different lie from the one this fixes.
	 */
	public static function utc_iso( ?string $stored ): ?string {
		if ( null === $stored || '' === $stored ) {
			return null;
		}

		// Already carries a zone: a value assembled by gmdate( 'c' ) rather than
		// read from a column. Returned untouched, so this is safe to apply to a
		// mixed set without having to know which is which.
		if ( 1 === preg_match( '/(Z|[+-]\d{2}:?\d{2})$/', $stored ) ) {
			return $stored;
		}

		return str_replace( ' ', 'T', $stored ) . 'Z';
	}

	/**
	 * A moment as one of this plugin's own datetime columns stores it: UTC,
	 * written explicitly, with the milliseconds field the DATETIME(3) columns
	 * carry.
	 *
	 * The write-side counterpart of utc_iso(), and here for the same reason: a
	 * format string repeated at every call site is a format string that
	 * eventually differs at one of them, and a column written in the site's
	 * local zone is wrong in a way nothing errors on.
	 *
	 * `v` always yields `000` for a whole-second timestamp, which is what these
	 * columns want.
	 *
	 * @param int|null $timestamp Unix time, or null for now.
	 */
	public static function stamp( ?int $timestamp = null ): string {
		return gmdate( 'Y-m-d H:i:s.v', null === $timestamp ? time() : $timestamp );
	}

	/**
	 * A moment as every email says it: the site's own date and time formats,
	 * in the site's time zone, with the zone named. The emails used three
	 * formats and zones for one moment, and "+06" named none (#2486).
	 *
	 * @param int $timestamp Unix time.
	 */
	public static function said( int $timestamp ): string {
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) . ' ' . self::zone( $timestamp );
	}

	/**
	 * The site's zone at a moment: its abbreviation where it has a real one
	 * ("EST", "CET"), otherwise its offset as "UTC+6" or "UTC+5:30".
	 *
	 * @param int $timestamp Unix time.
	 */
	public static function zone( int $timestamp ): string {
		$abbr = (string) wp_date( 'T', $timestamp );

		if ( 1 === preg_match( '/^[A-Z]{2,5}$/', $abbr ) && 'GMT' !== $abbr ) {
			return $abbr;
		}

		$offset = (int) wp_timezone()->getOffset( new \DateTimeImmutable( '@' . $timestamp ) );

		if ( 0 === $offset ) {
			return 'UTC';
		}

		$minutes = intdiv( abs( $offset ), 60 );
		$label   = 'UTC' . ( $offset < 0 ? '-' : '+' ) . intdiv( $minutes, 60 );

		return 0 === $minutes % 60 ? $label : $label . sprintf( ':%02d', $minutes % 60 );
	}
}
