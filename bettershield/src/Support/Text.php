<?php
/**
 * Cutting text to fit a column, in the unit the column actually counts.
 *
 * Every `varchar(N)` in this schema counts **characters**; `substr()` counts
 * **bytes**. For any script that is not Latin the two disagree by a factor of
 * two to four, so a byte-wise cut stores a fraction of the value the column
 * had room for — and lands at a boundary that can fall inside a multi-byte
 * sequence. WordPress drops `STRICT_TRANS_TABLES` on connect, so the database
 * then truncates the broken sequence and writes the row rather than refusing
 * it: a mangled value, silently, with nothing reporting a problem.
 *
 * This existed three times in three files before it existed once here.
 *
 * `mbstring` is optional on cheap hosts, so there is a fallback that reaches
 * the same answer through PCRE's UTF-8 mode.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Text {

	/**
	 * The first `$characters` characters — never bytes, never a partial one.
	 */
	public static function clip( string $value, int $characters ): string {
		if ( $characters <= 0 || '' === $value ) {
			return '';
		}

		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $value, 0, $characters, 'UTF-8' );
		}

		return self::clip_with_pcre( $value, $characters );
	}

	/**
	 * The same answer on a host without mbstring.
	 *
	 * Split out so it can be exercised: on a host that has mbstring — which is
	 * every host this suite runs on — the branch above returns first, and this
	 * would otherwise be code nothing ever reads.
	 *
	 * The greedy `{0,n}` matches as far as it is allowed and no further, and
	 * `/u` makes `.` one character rather than one byte. What it does not do is
	 * build an array: `preg_match_all` with a `$matches` argument allocates one
	 * element per character of the **whole** input before anything is sliced
	 * off it, and this is reachable with a typed login name and a browser's own
	 * user agent string — a POST-sized value is a million-element array built
	 * to keep sixty characters of it.
	 */
	private static function clip_with_pcre( string $value, int $characters ): string {
		// PCRE's own repetition ceiling. Nothing here clips anywhere near that
		// far; the slow path stays for a caller that one day does, because
		// falling back to bytes there would be the defect this class exists to
		// remove.
		if ( $characters > 65535 ) {
			$matched = preg_match_all( '/./us', $value, $parts );

			return false === $matched ? substr( $value, 0, $characters ) : implode( '', array_slice( $parts[0], 0, $characters ) );
		}

		$found = array();

		// Not valid UTF-8 at all: nothing here can improve on the bytes, and
		// refusing to store the value would lose more than truncating it.
		if ( 1 !== preg_match( '/^.{0,' . $characters . '}/us', $value, $found ) ) {
			return substr( $value, 0, $characters );
		}

		return (string) $found[0];
	}

	/**
	 * A value as a spreadsheet cell that is read and never run.
	 *
	 * A spreadsheet treats a cell beginning with `=`, `+`, `-` or `@` — or a
	 * tab or carriage return ahead of one — as a formula to evaluate, and the
	 * exported logs hold text a stranger chose: the login name typed at a
	 * sign-in form, an account's display name. A log of an attack must not
	 * become the attack, so such a cell is prefixed with a quote, which
	 * spreadsheets strip on display and treat as text throughout. Every CSV
	 * this plugin writes passes its cells through here, so one export cannot
	 * be guarded while another is not.
	 */
	public static function csv_cell( string $value ): string {
		if ( '' !== $value && 1 === preg_match( '/^[=+\-@\t\r]/', $value ) ) {
			return "'" . $value;
		}

		return $value;
	}

	/**
	 * One CSV line, quoted to RFC 4180 and safe to open in a spreadsheet.
	 *
	 * Written out rather than delegated to `fputcsv`, for two reasons that
	 * both matter here. That function needs a stream, and a security plugin
	 * reaching for direct filesystem calls is a thing a reviewer is right to
	 * stop at. And its escape-character behavior is not RFC 4180: it can emit
	 * backslashes that a spreadsheet reads back as part of the value.
	 *
	 * Every field goes through `csv_cell()` above on its way in, so an export
	 * built from these lines cannot skip the guard the way a hand-assembled
	 * one can.
	 *
	 * @param array<int, string> $fields
	 */
	public static function csv_row( array $fields ): string {
		$out = array();

		foreach ( $fields as $field ) {
			$field = self::csv_cell( (string) $field );

			if ( 1 === preg_match( '/["\r\n,]/', $field ) ) {
				$field = '"' . str_replace( '"', '""', $field ) . '"';
			}

			$out[] = $field;
		}

		return implode( ',', $out );
	}

	/**
	 * How many characters a string holds, for the checks that compare against
	 * a column width rather than cutting to it.
	 */
	public static function length( string $value ): int {
		if ( function_exists( 'mb_strlen' ) ) {
			return (int) mb_strlen( $value, 'UTF-8' );
		}

		$count = preg_match_all( '/./us', $value );

		return false === $count ? strlen( $value ) : (int) $count;
	}
}
