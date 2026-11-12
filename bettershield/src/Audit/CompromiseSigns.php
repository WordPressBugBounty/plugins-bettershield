<?php
/**
 * The named signs of compromise: one short, fixed list of tests on what a
 * piece of code does, read as text.
 *
 * Every check that reads code or markup for a sign of compromise asks this
 * list, so there is one list to keep honest rather than one per check. Three
 * things it never is:
 *
 * - **Not a sample list.** No known-bad hashes, names, domains or keywords.
 *   Each test describes a behavior (decoding something and running it at
 *   once, hiding where data is sent), so it can't age into a signature set.
 * - **Never run.** The text is matched and nothing else: no code is
 *   evaluated, included or fetched.
 * - **Never a verdict.** A match is something worth a look, said with where
 *   it was and which test matched. No match says nothing at all, because a
 *   short list of tests can't promise a site is clean.
 *
 * What a match carries is the test's id and the line it was on, never the
 * matched text: whoever wrote that text may have written it to be read back.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CompromiseSigns {

	/** Sends data to an address it decodes first, so the address can't be read. */
	public const HIDES_WHERE_IT_SENDS = 'hides_where_it_sends';

	/** Decodes text and runs it in the same breath. */
	public const DECODES_AND_RUNS = 'decodes_and_runs';

	/** Machine-packed: many names of the `_0x1a2b` kind. */
	public const PACKED = 'packed';

	/** Names card fields and has a way to send them. */
	public const CARD_FIELDS_AND_SEND = 'card_fields_and_send';

	/** PHP that decodes text and runs it. */
	public const PHP_DECODES_AND_RUNS = 'php_decodes_and_runs';

	/** PHP that takes card fields from a form and sends them to another site. */
	public const PHP_SENDS_CARD_FIELDS = 'php_sends_card_fields';

	/**
	 * An executable file whose name starts with a dot, so file listings hide
	 * it. Judged by name alone, never by reading the file.
	 */
	public const HIDDEN_NAME = 'hidden_name';

	/** How many distinct `_0x` names make code packed. */
	private const PACKED_NAMES = 10;

	/** The JavaScript tests that hold anywhere a script can be. */
	public const SCRIPT = array( self::HIDES_WHERE_IT_SENDS, self::DECODES_AND_RUNS, self::PACKED );

	/**
	 * The JavaScript tests for a place that prints or runs code. The card
	 * test stays out of everywhere else: payment plugins' own scripts name
	 * card fields and send them, as they should.
	 */
	public const SCRIPT_WHERE_IT_RUNS = array( self::HIDES_WHERE_IT_SENDS, self::DECODES_AND_RUNS, self::PACKED, self::CARD_FIELDS_AND_SEND );

	/** The PHP tests. */
	public const PHP = array( self::PHP_DECODES_AND_RUNS, self::PHP_SENDS_CARD_FIELDS );

	/**
	 * The patterns each single-pattern test is. Nested straight inside one
	 * another, never anywhere in the same text: `Function(` in one place and
	 * `fromCharCode` in another is ordinary code.
	 *
	 * @return array<string, string>
	 */
	private static function patterns(): array {
		return array(
			self::HIDES_WHERE_IT_SENDS => '/(?:\bsendBeacon|\bfetch)\s*\(\s*atob\s*\(|\.open\s*\(\s*([\'"])POST\1\s*,\s*atob\s*\(/i',
			self::DECODES_AND_RUNS     => '/\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\s*\.\s*fromCharCode)\s*\(/',
			self::PHP_DECODES_AND_RUNS => '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i',
		);
	}

	/**
	 * Which of the given tests the text matches, each with the first line it
	 * matched on.
	 *
	 * @param string   $text  The code, read as text.
	 * @param string[] $tests Which tests to run, from the lists above.
	 * @return array<int, array{test: string, line: int}>
	 */
	public static function match( string $text, array $tests ): array {
		$found    = array();
		$patterns = self::patterns();

		foreach ( $tests as $test ) {
			$at = null;

			if ( isset( $patterns[ $test ] ) ) {
				if ( preg_match( $patterns[ $test ], $text, $m, PREG_OFFSET_CAPTURE ) ) {
					$at = (int) $m[0][1];
				}
			} elseif ( self::PACKED === $test ) {
				$at = self::packed( $text );
			} elseif ( self::CARD_FIELDS_AND_SEND === $test ) {
				$at = self::card_fields_and_send( $text );
			} elseif ( self::PHP_SENDS_CARD_FIELDS === $test ) {
				$at = self::php_sends_card_fields( $text );
			}

			if ( null !== $at ) {
				$found[] = array(
					'test' => $test,
					'line' => substr_count( substr( $text, 0, $at ), "\n" ) + 1,
				);
			}
		}

		return $found;
	}

	/**
	 * Signs kept as `test` or `test:line`, joined by commas, read back.
	 * Anything that isn't a known test is dropped.
	 *
	 * @return array<int, array{test: string, line: int}>
	 */
	public static function parse( string $stored ): array {
		$known = array_merge( self::SCRIPT_WHERE_IT_RUNS, self::PHP, array( self::HIDDEN_NAME ) );
		$out   = array();

		foreach ( array_filter( explode( ',', $stored ) ) as $part ) {
			$bits = explode( ':', $part, 2 );

			if ( in_array( $bits[0], $known, true ) ) {
				$out[] = array(
					'test' => $bits[0],
					'line' => isset( $bits[1] ) ? max( 0, (int) $bits[1] ) : 0,
				);
			}
		}

		return $out;
	}

	/** Where packed code starts, or null when it isn't packed. */
	private static function packed( string $text ): ?int {
		if ( ! preg_match_all( '/\b_0x[0-9a-f]{3,8}\b/i', $text, $m, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}

		$names = array_unique( array_map( 'strtolower', array_column( $m[0], 0 ) ) );

		return count( $names ) >= self::PACKED_NAMES ? (int) $m[0][0][1] : null;
	}

	/** Where a card field is named beside a way to send it, or null. */
	private static function card_fields_and_send( string $text ): ?int {
		if ( ! preg_match( '/\b(?:cvv|cvc|cardnumber|card_number|cc-number)\b/i', $text, $field, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}

		if ( ! preg_match( '/\bsendBeacon\b|\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+Image\b|\$\s*\.\s*(?:post|ajax)\s*\(/', $text ) ) {
			return null;
		}

		return (int) $field[0][1];
	}

	/** Where PHP reads a card field from a form and can send it out, or null. */
	private static function php_sends_card_fields( string $text ): ?int {
		if ( ! preg_match( '/\$_(?:POST|REQUEST)\s*\[\s*[\'"][^\'"]*(?:cvv|cvc|cardnumber|card_number|cc-number|cc_number)[^\'"]*[\'"]/i', $text, $field, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}

		if ( ! preg_match( '/\bcurl_exec\s*\(|\bwp_remote_post\s*\(|\bfsockopen\s*\(|\bfile_get_contents\s*\(\s*[\'"]https?:\/\//i', $text ) ) {
			return null;
		}

		return (int) $field[0][1];
	}
}
