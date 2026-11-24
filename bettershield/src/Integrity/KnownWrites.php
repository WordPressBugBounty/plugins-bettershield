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
 * - .htaccess differing only inside a block an active cache plugin writes
 *   under its own marker is Medium, unless the block holds a line that runs
 *   or changes PHP or sends visitors to another host.
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

	/** The hash of .htaccess without the blocks known plugins write, as last recorded. Never its contents. */
	public const HTACCESS_OPTION = 'bettershield_integrity_htaccess_shape';

	/** The name the root .htaccess is watched under. */
	private const HTACCESS = '.htaccess';

	/**
	 * Owner's main file => the `# BEGIN` markers of the .htaccess blocks it
	 * writes, as patterns over the whole marker.
	 */
	private const BLOCKS = array(
		'xspeed/xspeed.php'                          => '~^xSpeed (?:Static Cache|GZIP|Browser Cache|CDN)$~',
		'litespeed-cache/litespeed-cache.php'        => '~^(?:NON_)?LSCACHE$~',
		'w3-total-cache/w3-total-cache.php'          => '~^W3TC [A-Za-z0-9 ]+$~',
		'wp-super-cache/wp-cache.php'                => '~^WPSuperCache$~',
		'wp-fastest-cache/wpFastestCache.php'        => '~^(?:Gzip|LBC|WEBP)?WpFastestCache$~',
		'wp-optimize/wp-optimize.php'                => '~^WP-Optimize [A-Za-z ]+$~',
		'breeze/breeze.php'                          => '~^(?:GzipofBreezeWPCache|[A-Za-z ]+ by Breeze|BreezeWPCache[A-Za-z]*)$~',
		'sg-cachepress/sg-cachepress.php'            => '~^[A-Za-z ]+ by SG-Optimizer$~',
		'hummingbird-performance/wp-hummingbird.php' => '~^WP-HUMMINGBIRD-[A-Z_-]+$~',
	);

	/**
	 * A line that keeps a known block from being explained: anything that
	 * runs PHP or changes how it runs (removing its handler serves the source
	 * as text), and anything that sends a request to an address it names.
	 */
	private const UNSAFE_LINE = '~^\s*(?:php_(?:admin_)?(?:value|flag)\b|(?:AddHandler|SetHandler|RemoveHandler|RemoveType|Action|ForceType|ScriptAlias|Include(?:Optional)?|LoadModule|SetEnv\s+PHPRC)\b|Options\b.*\bExecCGI\b|AddType\b.*(?:php|phtml|phar|x-httpd)|.*\b(?:auto_prepend_file|auto_append_file)\b)~i';

	/** A directive that sends a visitor somewhere, read for the address it names. */
	private const REDIRECT_LINE = '~^\s*(?:RewriteRule|Redirect(?:Match|Permanent|Temp)?|ErrorDocument)\b~i';

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
			'xspeed/xspeed.php'                           => 'xspeed/includes/object-cache.php',
		),
		'elementor-safe-mode.php' => array(
			'elementor/elementor.php' => 'elementor/modules/safe-mode/mu-plugin/elementor-safe-mode.php',
		),
	);

	/** File => owner's main file => what the file it generates always says. */
	private const MARKED = array(
		'advanced-cache.php' => array(
			'wp-rocket/wp-rocket.php' => 'WP_ROCKET_ADVANCED_CACHE',
			'xspeed/xspeed.php'       => 'XSPEED_DROPIN',
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
			$slug = (string) $target['slug'];

			if ( ! in_array( $slug, array( Unpublished::SLUG_WP_CONFIG, self::HTACCESS ), true ) ) {
				return 0;
			}

			return self::only_known_lines_changed( $file ) ? self::EXPLAINED : 0;
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
	 * Hold what a watched configuration file comes to without what known
	 * plugins write in it, at the end of a pass, unless a change to it is
	 * still open that nothing explains.
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
	 * Hold what wp-config.php or .htaccess comes to without what known
	 * plugins write in it, for the next change to be held against.
	 */
	public static function remember_config( string $file ): void {
		$option = self::option_for( $file );
		$shape  = self::shape_of( $file );

		if ( null !== $shape && get_option( $option ) !== $shape ) {
			update_option( $option, $shape, false );
		}
	}

	/** Whether a configuration file has one of the shapes kept here. */
	public static function keeps_shape( string $slug ): bool {
		return in_array( $slug, array( Unpublished::SLUG_WP_CONFIG, self::HTACCESS ), true );
	}

	private static function only_known_lines_changed( string $file ): bool {
		$known = get_option( self::option_for( $file ) );
		$now   = self::shape_of( $file );

		return is_string( $known ) && null !== $now && hash_equals( $known, $now );
	}

	private static function option_for( string $file ): string {
		return self::HTACCESS === basename( $file ) ? self::HTACCESS_OPTION : self::CONFIG_OPTION;
	}

	private static function shape_of( string $file ): ?string {
		return self::HTACCESS === basename( $file ) ? self::htaccess_shape( $file ) : self::config_shape( $file );
	}

	/**
	 * The file's hash without the blocks an active, known plugin writes under
	 * its own marker. A block comes out only whole, between its own BEGIN and
	 * END, and only when no line in it runs or changes PHP or sends visitors
	 * to another host; anything else stays in, so a change to it is still a
	 * change. Blank lines are left out, as the markers' own spacing varies.
	 */
	private static function htaccess_shape( string $file ): ?string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- the site's own server rules, hashed and never kept.
		$contents = is_file( $file ) ? @file_get_contents( $file, false, null, 0, self::CONFIG_MAX_BYTES + 1 ) : false;

		if ( ! is_string( $contents ) || strlen( $contents ) > self::CONFIG_MAX_BYTES ) {
			return null;
		}

		$lines = preg_split( '~\r\n|\r|\n~', $contents );
		$kept  = array();
		$block = null;

		foreach ( (array) $lines as $line ) {
			$line = (string) $line;

			if ( null === $block ) {
				if ( preg_match( '~^\s*# BEGIN (.+?)\s*$~', $line, $begin ) && self::known_marker( $begin[1] ) ) {
					$block = array(
						'marker' => $begin[1],
						'lines'  => array( $line ),
					);
				} elseif ( '' !== trim( $line ) ) {
					$kept[] = rtrim( $line );
				}

				continue;
			}

			$block['lines'][] = $line;

			if ( preg_match( '~^\s*# END (.+?)\s*$~', $line, $end ) && $end[1] === $block['marker'] ) {
				if ( ! self::block_is_safe( $block['lines'] ) ) {
					foreach ( $block['lines'] as $held ) {
						if ( '' !== trim( $held ) ) {
							$kept[] = rtrim( $held );
						}
					}
				}

				$block = null;
			} elseif ( preg_match( '~^\s*# BEGIN ~', $line ) ) {
				// Another block opened inside this one: not a block a plugin wrote.
				foreach ( $block['lines'] as $held ) {
					if ( '' !== trim( $held ) ) {
						$kept[] = rtrim( $held );
					}
				}

				$block = null;
			}
		}

		// A block never closed is not one either.
		foreach ( null === $block ? array() : $block['lines'] as $held ) {
			if ( '' !== trim( $held ) ) {
				$kept[] = rtrim( $held );
			}
		}

		return hash( 'sha256', implode( "\n", $kept ) );
	}

	/** Whether an active plugin writes a block under this marker. */
	private static function known_marker( string $marker ): bool {
		foreach ( self::BLOCKS as $owner => $pattern ) {
			if ( preg_match( $pattern, $marker ) && self::active( $owner ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether every line of a block is one a cache plugin's rules are made
	 * of: no PHP handling, and no redirect to a host other than this site's.
	 *
	 * @param array<int, string> $lines The block, its markers included.
	 */
	private static function block_is_safe( array $lines ): bool {
		$hosts = array_filter(
			array(
				strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ),
				strtolower( (string) wp_parse_url( site_url(), PHP_URL_HOST ) ),
			)
		);

		foreach ( $lines as $line ) {
			if ( preg_match( '~^\s*#~', $line ) ) {
				continue;
			}

			if ( preg_match( self::UNSAFE_LINE, $line ) ) {
				return false;
			}

			if ( ! preg_match( self::REDIRECT_LINE, $line ) ) {
				continue;
			}

			// A proxied request goes wherever the rule says, whatever the host.
			if ( preg_match( '~\[[^\]]*\bP\b[^\]]*\]~i', $line ) ) {
				return false;
			}

			if ( preg_match_all( '~(?:[a-z][a-z0-9+.-]*:|(?<![^\s"\'=]))//([^/\s"\'?#\]]*)~i', $line, $urls ) ) {
				foreach ( $urls[1] as $authority ) {
					$host = strtolower( (string) preg_replace( '~^[^@]*@|:\d+$~', '', $authority ) );

					// The request's own host, as a variable, is this site.
					if ( '%{http_host}' === $host || '%{server_name}' === $host ) {
						continue;
					}

					if ( ! in_array( $host, $hosts, true ) ) {
						return false;
					}
				}
			}
		}

		return true;
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
		$patterns = array( $line );

		// xSpeed writes its object cache connection into wp-config.php as one
		// block of its own constants. The block comes out only whole, only
		// while xSpeed is active, and only when every line in it defines an
		// XSPEED_OC_ constant to a plain value: any other line keeps it in,
		// so a change to it is still a change.
		if ( self::active( 'xspeed/xspeed.php' ) ) {
			$patterns[] = '~^/\* BEGIN xSpeed Object Cache \*/[ \t]*\r?\n(?:[ \t]*define\( \'XSPEED_OC_[A-Z_]+\', (?:\'(?:[^\'\\\\\r\n]|\\\\[^\r\n])*\'|-?\d+|true|false) \);[ \t]*\r?\n)+/\* END xSpeed Object Cache \*/[ \t]*\r?$\n?~m';
		}

		$patterns[] = '~^[ \t]*\r?\n~m';
		$kept       = preg_replace( $patterns, '', $contents );

		return is_string( $kept ) ? hash( 'sha256', $kept ) : null;
	}

	private static function active( string $file ): bool {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return is_plugin_active( $file );
	}
}
