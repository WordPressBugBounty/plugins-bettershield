<?php
/**
 * Whether this plugin speaks the reader's language, said rather than left to
 * be guessed from a half-English screen.
 *
 * On a site whose language is not English, WordPress's own menus and buttons
 * arrive translated while every string this plugin wrote stays English until
 * a translation for it exists. Nothing on the page says which of the two is
 * the case, and an owner reading a severity or the name of a protection in a
 * second language should know it is a second language by design, not a gap
 * about to be filled.
 *
 * Read from the files WordPress itself would load, for the reader's own
 * locale: the screens are translated by the admin bundle's JSON catalog, and
 * everything rendered on the server (email, notices, WP-CLI) by the plugin's
 * PHP catalog. Either can exist without the other, and the line says so. A
 * file counts only when it holds a translation: a language pack whose
 * download was cut short, or an empty file a failed update left, translates
 * nothing, and the reader would see English under a row saying otherwise.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Admin\Menu;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Language {

	/**
	 * The most of a screens catalog read to see whether it holds anything.
	 * A full translation of the bundle is a few hundred kilobytes, so a
	 * file that fills this is not empty, whatever its last bytes say.
	 */
	private const CATALOG_READ_BYTES = 4194304;

	/**
	 * The reader's language and what is translated into it, or null when the
	 * reader works in English and there is nothing to say.
	 *
	 * Any English variant counts as English: the plugin is written in it, and
	 * telling a reader in en_GB that their screens are "not translated" would
	 * be true and of no use to them.
	 *
	 * @return ?array{locale: string, name: string, native: string, core: bool, screens: bool, catalog: bool}
	 */
	public static function report(): ?array {
		$locale = get_user_locale();

		if ( 'en' === $locale || 0 === strpos( $locale, 'en_' ) ) {
			return null;
		}

		$names = self::names( $locale );

		return array(
			'locale'  => $locale,
			'name'    => $names['name'],
			'native'  => $names['native'],
			// WordPress's own language pack, as Settings › General lists it.
			'core'    => in_array( $locale, get_available_languages(), true ),
			'screens' => self::screens_translated( $locale ),
			'catalog' => self::catalog_translated( $locale ),
		);
	}

	/**
	 * Whether the admin screens have a catalog in this locale.
	 *
	 * The file `load_script_textdomain()` looks for: the domain, the locale
	 * and a hash of the bundle's path inside the plugin, in the plugin's own
	 * folder first and then the site's. A catalog for some other file of the
	 * plugin does not translate the screens, so it does not count.
	 *
	 * WordPress passes over a file with nothing in it and hands the screens
	 * the first that has anything, so that one decides, even when all it
	 * holds is a header or JSON cut off partway.
	 */
	private static function screens_translated( string $locale ): bool {
		$file = 'bettershield-' . $locale . '-' . md5( 'assets/build/' . Menu::BUNDLE . '.js' ) . '.json';

		foreach ( array( BETTERSHIELD_PATH . '/languages', WP_LANG_DIR . '/plugins' ) as $dir ) {
			if ( ! is_readable( $dir . '/' . $file ) ) {
				continue;
			}

			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local catalog, read as load_script_translations() reads it, capped; one that cannot be read is passed over as WordPress passes it over, and nothing is stored or echoed.
			$json = (string) @file_get_contents( $dir . '/' . $file, false, null, 0, self::CATALOG_READ_BYTES );

			if ( '' !== $json ) {
				return strlen( $json ) >= self::CATALOG_READ_BYTES || self::json_translates( $json );
			}
		}

		return false;
	}

	/**
	 * Whether a screens catalog holds a translation: a message besides the
	 * header, under the domain or under "messages", where the script
	 * WordPress prints with the catalog looks for them.
	 */
	private static function json_translates( string $json ): bool {
		$catalog  = json_decode( $json, true );
		$messages = $catalog['locale_data']['bettershield'] ?? $catalog['locale_data']['messages'] ?? null;

		return is_array( $messages ) && array() !== array_diff_key( $messages, array( '' => true ) );
	}

	/**
	 * Whether the strings rendered on the server have a catalog in this
	 * locale: where WordPress loads a plugin's catalog when it is first
	 * needed, in either format it reads.
	 *
	 * `load_textdomain()` loads the first of the two that is there and does
	 * not read it until a string is asked for, so that file decides: one
	 * that is empty, cut short or holds no entries leaves every string in
	 * English, and the other file is not tried.
	 */
	private static function catalog_translated( string $locale ): bool {
		$base = WP_LANG_DIR . '/plugins/bettershield-' . $locale;

		foreach ( array( $base . '.l10n.php', $base . '.mo' ) as $file ) {
			if ( is_readable( $file ) ) {
				return self::catalog_translates( $file );
			}
		}

		return false;
	}

	/**
	 * Whether a server catalog holds a translation, read as WordPress reads
	 * it when a string is first asked for.
	 */
	private static function catalog_translates( string $file ): bool {
		try {
			$catalog = \WP_Translation_File::create( $file );

			// The entries first: the file is read when they are asked for,
			// and only then does it know whether it read.
			return $catalog instanceof \WP_Translation_File && array() !== $catalog->entries() && ! $catalog->error();
		} catch ( \Throwable $unreadable ) {
			// A PHP catalog cut short is PHP that does not parse.
			return false;
		}
	}

	/**
	 * A locale's name in English, as Settings › General lists it, or the
	 * code where neither WordPress nor intl knows it.
	 */
	public static function name_of( string $locale ): string {
		return self::names( $locale )['name'];
	}

	/**
	 * The language's name in English and in itself: "Arabic" and "العربية".
	 *
	 * From the list of languages WordPress last fetched for its own language
	 * picker first, so the name matches the one the reader chose it by. intl
	 * reads the variant in a WordPress locale as a raw tag, and named
	 * de_DE_formal "German (Germany, FORMAL)" where the picker says "German
	 * (Formal)". Then intl where the host has it, and only when neither knows
	 * it, the locale code. Nothing here makes a request.
	 *
	 * @return array{name: string, native: string}
	 */
	private static function names( string $locale ): array {
		$known = get_site_transient( 'available_translations' );

		if ( is_array( $known ) && isset( $known[ $locale ]['english_name'] ) ) {
			return array(
				'name'   => (string) $known[ $locale ]['english_name'],
				'native' => (string) ( $known[ $locale ]['native_name'] ?? $known[ $locale ]['english_name'] ),
			);
		}

		// intl names a language it does not know by its code: "xx (YY)".
		if ( class_exists( '\Locale' ) && (string) \Locale::getDisplayLanguage( $locale, 'en' ) !== (string) \Locale::getPrimaryLanguage( $locale ) ) {
			$name   = (string) \Locale::getDisplayName( $locale, 'en' );
			$native = (string) \Locale::getDisplayName( $locale, $locale );

			return array(
				'name'   => $name,
				'native' => '' !== $native ? $native : $name,
			);
		}

		return array(
			'name'   => $locale,
			'native' => $locale,
		);
	}
}
