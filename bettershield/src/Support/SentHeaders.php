<?php
/**
 * The headers this response already carries, from anywhere.
 *
 * The `wp_headers` array holds only what WordPress is about to send. A header
 * the web server added, or one another plugin set by calling `header()`
 * directly, is not in that array — so an item that reads only the array adds
 * its own on top of one somebody chose deliberately. `header()` replaces by
 * default, and for a header whose value carries its strength that is a
 * downgrade rather than a duplicate. Every item that adds a header asks here
 * first, and leaves one it finds exactly alone.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SentHeaders {

	/**
	 * Headers a test says this response carries. Null means ask PHP.
	 *
	 * A seam rather than a filter: whether a site's existing policy is
	 * preserved is not a decision to expose for anybody to answer. It exists
	 * because `headers_list()` is empty under the CLI the suite runs on, so
	 * the branch that matters most could not otherwise be reached by a test.
	 *
	 * @var string[]|null
	 */
	private static ?array $override = null;

	/**
	 * Test seam. Pass null to return to asking PHP.
	 *
	 * @param string[]|null $headers Raw header lines, `Name: value`.
	 */
	public static function override( ?array $headers ): void {
		self::$override = $headers;
	}

	/**
	 * Whether a header of this name has already been set on this response.
	 *
	 * Compared without regard to case, as header names are.
	 */
	public static function carries( string $name ): bool {
		$sent = self::$override ?? headers_list();

		foreach ( $sent as $header ) {
			if ( 0 === strcasecmp( $name, trim( (string) strtok( (string) $header, ':' ) ) ) ) {
				return true;
			}
		}

		return false;
	}
}
