<?php
/**
 * What this site runs, in the shape a feed is asked about: plugins and
 * themes by directory slug and version, and core. Slugs and versions only —
 * this is the whole of what a feed ever learns about a site.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Inventory {

	/** Must-use loaders BetterShield's add-on writes itself, by file name. */
	public const OWN_LOADERS = array( 'bettershield-ultra-early.php' );

	/**
	 * WordPress's version without the build number a nightly or a develop
	 * checkout adds.
	 *
	 * `7.2-beta3-65022` and `7.2-beta3-64914-src` can't be compared with any
	 * advisory, so every core advisory read "Couldn't compare your version"
	 * (#2680). The build number says nothing the part before it doesn't, so
	 * they're read as `7.2-beta3`. Releases are left as they are.
	 */
	public static function core_version( string $version ): string {
		return (string) preg_replace( '/^(\d+(?:\.\d+)*(?:-(?:alpha|beta\d+|RC\d+))?)(?:-\d+)?(?:-src)?$/D', '$1', $version );
	}

	/**
	 * @return array<int, array{type: string, slug: string, version: string, name: string, active: bool}>
	 */
	public static function collect(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$items = array(
			array(
				'type'    => 'core',
				'slug'    => 'wordpress',
				'version' => self::core_version( (string) get_bloginfo( 'version' ) ),
				'name'    => 'WordPress',
				'active'  => true,
			),
		);

		$active  = (array) get_option( 'active_plugins', array() );
		$by_slug = array();

		/*
		 * Folded by slug rather than appended. A folder may hold more than one
		 * plugin header — core lists each file that carries one — and the slug
		 * an advisory names is the folder, so the later entry replaced the
		 * earlier one outright and a legacy file with no `Version:` line
		 * erased the version the matcher works from. The entry has to be the
		 * best answer any of the files gives.
		 */
		$fold = static function ( array $entry ) use ( &$by_slug ): void {
			$seen = $by_slug[ $entry['slug'] ] ?? null;
			$entry['versions'] = array_values( array_unique( array_merge( $seen['versions'] ?? array(), array( $entry['version'] ) ) ) );

			if ( null === $seen ) {
				$by_slug[ $entry['slug'] ] = $entry;

				return;
			}

			$entry['active'] = $entry['active'] || $seen['active'];

			$keep_seen = '' === $entry['version']
				|| ( '' !== $seen['version'] && version_compare( $entry['version'], $seen['version'], '<=' ) );

			if ( $keep_seen ) {
				$by_slug[ $entry['slug'] ]['active'] = $entry['active'];
				$by_slug[ $entry['slug'] ]['versions'] = $entry['versions'];

				return;
			}

			$by_slug[ $entry['slug'] ] = $entry;
		};

		foreach ( get_plugins() as $file => $data ) {
			$slug = self::slug_for( (string) $file );

			$fold(
				array(
					'type'    => 'plugin',
					'slug'    => $slug,
					'version' => (string) ( $data['Version'] ?? '' ),
					'name'    => (string) ( $data['Name'] ?? $slug ),
					'active'  => in_array( $file, $active, true ) || is_plugin_active_for_network( $file ),
				)
			);
		}

		/*
		 * Code a host or a developer dropped into mu-plugins runs on every
		 * request with no way to switch it off, so an advisory naming it is
		 * about this site more urgently than one naming a plugin somebody can
		 * deactivate. `get_plugins()` reads one directory and this is the
		 * other. Drop-ins are deliberately absent: `get_dropins()` is keyed by
		 * a fixed filename with no directory behind it, and sending
		 * `object-cache.php` to a feed as a slug asks about a plugin nobody
		 * published.
		 */
		foreach ( get_mu_plugins() as $file => $data ) {
			// The add-on's own early loader is part of the add-on, already
			// listed, and nobody's advisory names it. Listed, it changed the
			// inventory the moment protection was switched on.
			if ( in_array( (string) $file, self::OWN_LOADERS, true ) ) {
				continue;
			}

			$slug = self::slug_for( (string) $file );

			$fold(
				array(
					'type'    => 'plugin',
					'slug'    => $slug,
					'version' => (string) ( $data['Version'] ?? '' ),
					'name'    => (string) ( $data['Name'] ?? $slug ),
					// An mu-plugin has no off switch.
					'active'  => true,
				)
			);
		}

		$items = array_merge( $items, array_values( $by_slug ) );

		$in_use = array( wp_get_theme()->get_stylesheet(), wp_get_theme()->get_template() );

		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$items[] = array(
				'type'    => 'theme',
				'slug'    => (string) $stylesheet,
				'version' => (string) $theme->get( 'Version' ),
				'name'    => (string) $theme->get( 'Name' ),
				'active'  => in_array( $stylesheet, $in_use, true ),
			);
		}

		return $items;
	}

	/**
	 * The inventory as a feed sees it: type, slug, version, nothing else.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<int, array{type: string, slug: string, version: string}>
	 */
	public static function for_feed( array $items ): array {
		$unique = array();
		foreach ( $items as $item ) {
			$type = (string) $item['type'];
			$slug = (string) $item['slug'];
			if ( ! in_array( $type, array( 'core', 'plugin', 'theme' ), true ) || strlen( $slug ) > 200 || 1 !== preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]*$/D', $slug ) ) {
				continue;
			}
			foreach ( $item['versions'] ?? array( $item['version'] ) as $version ) {
				$version = (string) $version;
				// Unsupported version spellings remain present as unknown.
				if ( strlen( $version ) > 128 || '*' === $version || preg_match( '/(?:^\s|\s$|[\x00-\x1f\x7f])/u', $version ) || 1 !== preg_match( '//u', $version ) ) {
					$version = '';
				}
				$row = array( 'type' => $type, 'slug' => $slug, 'version' => $version );
				$unique[ wp_json_encode( $row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ] = $row;
			}
		}
		$out = array_values( $unique );
		usort( $out, static function ( array $a, array $b ): int {
			foreach ( array( 'type', 'slug', 'version' ) as $key ) {
				$comparison = strcmp( $a[ $key ], $b[ $key ] );
				if ( 0 !== $comparison ) {
					return $comparison;
				}
			}
			return 0;
		} );
		return $out;
	}

	/** Digest of the canonical inventory, shared by feeds and signed service requests. */
	public static function digest( array $items ): string {
		return hash( 'sha256', wp_json_encode( self::for_feed( $items ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
	}

	/** Refresh file headers even when called from cron without admin includes. */
	public static function fresh(): array {
		if ( ! function_exists( 'wp_clean_plugins_cache' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		wp_clean_plugins_cache( false );
		wp_clean_themes_cache( false );
		return self::collect();
	}

	/**
	 * The slug a plugin file answers to: the directory for a plugin that has
	 * one, the file's own name for a single-file plugin at the root. One rule,
	 * here, for everything that turns a file into a slug or a slug back into
	 * a file.
	 */
	public static function slug_for( string $file ): string {
		return str_contains( $file, '/' ) ? dirname( $file ) : basename( $file, '.php' );
	}

	/**
	 * The plugin file behind a slug, as WordPress names it — `dir/main.php`,
	 * or `single.php` for a plugin with no directory — or null when nothing
	 * installed answers to it.
	 */
	public static function file_for( string $slug ): ?string {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( self::slug_for( (string) $file ) === $slug ) {
				return (string) $file;
			}
		}

		return null;
	}
}
