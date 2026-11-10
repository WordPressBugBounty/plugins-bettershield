<?php
/**
 * Files a well-known plugin writes where WordPress runs them.
 *
 * A page cache writes `advanced-cache.php` and a line or two of wp-config.php,
 * an object cache writes `object-cache.php`, and each does it on activation
 * and on many settings changes. Read as tampering, every one was a Critical
 * email. The names alone explain nothing, because those are the names a
 * backdoor would use, so what is checked is the contents:
 *
 * - A file identical to the copy its active owner ships is Medium.
 * - A generated file that only carries its owner's marker is High: the plugin
 *   is there, and a marker can be copied.
 * - wp-config.php differing only by the cache lines these plugins add is
 *   Medium. Those lines load the drop-in, which is judged on its own.
 * - Anything else keeps its grade.
 *
 * There is no filter here, because code planted on a site can reach those.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class KnownWrites {

	/** The hash of wp-config.php without its cache lines, as last recorded. Never its contents. */
	public const CONFIG_OPTION = 'bettershield_integrity_config_shape';

	/** The most of wp-config.php read to judge its cache lines. Far above any real one. */
	private const CONFIG_MAX_BYTES = 1048576;

	/** A row whose change is explained, held in the column that marks an unconfirmed update. */
	public const EXPLAINED = 2;

	/** File => owner's main file => the copy it ships, from the plugins directory. */
	private const SHIPPED = array(
		'advanced-cache.php'      => array(
			'wp-super-cache/wp-cache.php'       => 'wp-super-cache/advanced-cache.php',
			'w3-total-cache/w3-total-cache.php' => 'w3-total-cache/wp-content/advanced-cache.php',
		),
		'object-cache.php'        => array(
			'redis-cache/redis-cache.php'                 => 'redis-cache/includes/object-cache.php',
			'sqlite-object-cache/sqlite-object-cache.php' => 'sqlite-object-cache/assets/drop-in/object-cache.php',
			'litespeed-cache/litespeed-cache.php'         => 'litespeed-cache/lib/object-cache.php',
			'w3-total-cache/w3-total-cache.php'           => 'w3-total-cache/wp-content/object-cache.php',
		),
		'elementor-safe-mode.php' => array(
			'elementor/elementor.php' => 'elementor/modules/safe-mode/mu-plugin/elementor-safe-mode.php',
		),
	);

	/** File => owner's main file => what the file it generates always says. */
	private const MARKED = array(
		'advanced-cache.php' => array(
			'wp-rocket/wp-rocket.php' => 'WP_ROCKET_ADVANCED_CACHE',
		),
		'0-worker.php'       => array(
			'worker/init.php' => 'ManageWP - Worker Loader',
		),
	);

	/**
	 * What a change to one file comes to: self::EXPLAINED, 1 for quieter, or
	 * 0 for nothing known about it.
	 *
	 * @param array<string, mixed> $target
	 */
	public static function standing( array $target, string $relative, string $change_type ): int {
		if ( ! in_array( $change_type, array( 'added', 'modified' ), true ) ) {
			return 0;
		}

		$context = (string) $target['context'];
		$file    = (string) $target['root'] . '/' . $relative;

		if ( Unpublished::CONTEXT_CONFIG === $context ) {
			return Unpublished::SLUG_WP_CONFIG === (string) $target['slug'] && self::only_cache_lines_changed( $file ) ? self::EXPLAINED : 0;
		}

		if ( ! in_array( $context, array( Unpublished::CONTEXT_DROPIN, Unpublished::CONTEXT_MUPLUGIN ), true ) ) {
			return 0;
		}

		$hash = Manifest::hash_file( $file, 'sha256' );

		foreach ( self::SHIPPED[ $relative ] ?? array() as $owner => $copy ) {
			$shipped = self::active( $owner ) ? Manifest::hash_file( WP_PLUGIN_DIR . '/' . $copy, 'sha256' ) : null;

			if ( null !== $hash && null !== $shipped && hash_equals( $shipped, $hash ) ) {
				return self::EXPLAINED;
			}
		}

		foreach ( self::MARKED[ $relative ] ?? array() as $owner => $marker ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- a local file, the first few kilobytes.
			if ( self::active( $owner ) && str_contains( (string) @file_get_contents( $file, false, null, 0, 8192 ), $marker ) ) {
				return 1;
			}
		}

		return 0;
	}

	/**
	 * Hold what wp-config.php comes to without its cache lines, at the end of
	 * a pass, unless a change to it is still open that nothing explains.
	 *
	 * @param string $file The file on disk.
	 * @param string $path The path its change rows are kept under.
	 */
	public static function remember_config_if_settled( string $file, string $path ): void {
		global $wpdb;

		// While a change to the file nothing explains is still open, the shape
		// stays at what the baseline took in. Moving it then would let the next
		// cache-line edit pass the unexplained change off as explained.
		$open = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND path_hash = %s AND status IN ('new','acknowledged','suppressed') AND COALESCE( unconfirmed_update, 0 ) <> %d",
				\BetterShield\Database\Schema::table( 'integrity_changes' ),
				hash( 'sha256', $path ),
				self::EXPLAINED
			)
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- one indexed count on the plugin's own table, at the end of a pass.

		if ( 0 === $open ) {
			self::remember_config( $file );
		}
	}

	/**
	 * Hold what wp-config.php comes to without its cache lines, for the next
	 * change to be held against.
	 */
	public static function remember_config( string $file ): void {
		$shape = self::config_shape( $file );

		if ( null !== $shape && get_option( self::CONFIG_OPTION ) !== $shape ) {
			update_option( self::CONFIG_OPTION, $shape, false );
		}
	}

	private static function only_cache_lines_changed( string $file ): bool {
		$known = get_option( self::CONFIG_OPTION );
		$now   = self::config_shape( $file );

		return is_string( $known ) && null !== $now && hash_equals( $known, $now );
	}

	/**
	 * The file's hash without the lines a cache plugin adds. Only these exact
	 * forms come out, with a plain value, so nothing that runs can hide in one.
	 * A trailing comment may not hold `?>`: that ends a `//` comment, and what
	 * follows it runs. A backslash in the value is read with the character
	 * after it, as PHP reads it, so an escaped quote never ends the value
	 * early and lets code pass as the comment.
	 */
	private static function config_shape( string $file ): ?string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- the site's own configuration, hashed and never kept.
		$contents = is_file( $file ) ? @file_get_contents( $file, false, null, 0, self::CONFIG_MAX_BYTES + 1 ) : false;

		// Too big to judge is never "only cache lines": it stays critical.
		if ( ! is_string( $contents ) || strlen( $contents ) > self::CONFIG_MAX_BYTES ) {
			return null;
		}

		$line = '~^[ \t]*(?:/\*\* Enable W3 Total Cache \*\*?/|define\s*\(\s*(?:[\'"]WP_CACHE[\'"]\s*,\s*(?:true|false|1|0)|[\'"]WPCACHEHOME[\'"]\s*,\s*(?:\'(?:[^\'\\\\\r\n]|\\\\[^\r\n])*\'|"(?:[^"$\\\\\r\n]|\\\\[^\r\n])*"))\s*\)\s*;[ \t]*(?://(?:(?!\?>)[^\r\n])*)?)[ \t]*\r?$\n?~mi';
		$kept = preg_replace( array( $line, '~^[ \t]*\r?\n~m' ), '', $contents );

		return is_string( $kept ) ? hash( 'sha256', $kept ) : null;
	}

	private static function active( string $file ): bool {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return is_plugin_active( $file );
	}
}
