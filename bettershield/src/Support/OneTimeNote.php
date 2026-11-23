<?php
/**
 * A short explanation carried across one redirect, by a random name.
 *
 * A form that refuses something and then sends the browser to another page
 * (the sign-in page, a membership plugin's reset form) has nowhere to put
 * the reason: the address must not carry the text itself, or anybody could
 * make the page say anything. So the reason is kept on the site for a few
 * minutes under a random name the address carries, shown once as plain
 * text, and gone. A name that is wrong, old or made up shows nothing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OneTimeNote {

	/** The transient a note is kept in, by its random name. */
	public const PREFIX = 'bettershield_note_';

	/** Long enough for the next page to load, short enough to be gone. */
	private const SECONDS = 300;

	/** How long a note's name is. */
	private const LENGTH = 20;

	/**
	 * Keep a reason, as plain text, and answer the note's name, or '' when
	 * there was nothing to keep.
	 */
	public static function keep( string $message ): string {
		$text = trim( html_entity_decode( wp_strip_all_tags( $message ), ENT_QUOTES, 'UTF-8' ) );

		if ( '' === $text ) {
			return '';
		}

		$note = strtolower( wp_generate_password( self::LENGTH, false, false ) );

		set_transient( self::PREFIX . $note, Text::clip( $text, 500 ), self::SECONDS );

		return $note;
	}

	/**
	 * The plain text a note holds, said once, or null for a name that holds
	 * nothing. The caller escapes it where it prints it.
	 *
	 * @param mixed $note The name, as the address carried it.
	 */
	public static function take( $note ): ?string {
		$note = is_string( $note ) ? (string) preg_replace( '/[^a-z0-9]/', '', strtolower( $note ) ) : '';

		if ( self::LENGTH !== strlen( $note ) ) {
			return null;
		}

		$text = get_transient( self::PREFIX . $note );

		if ( ! is_string( $text ) || '' === $text ) {
			return null;
		}

		delete_transient( self::PREFIX . $note );

		return $text;
	}
}
