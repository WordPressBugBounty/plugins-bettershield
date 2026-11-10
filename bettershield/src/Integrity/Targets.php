<?php
/**
 * What there is to check, and where it lives.
 *
 * One target is one thing with a publisher: WordPress itself, or a plugin
 * installed from the WordPress.org directory. A target names the directory its
 * files are under and the manifest that says what they should be.
 *
 * **Uploads are not a target and cannot become one.** Nothing published them,
 * so there is nothing to compare them against, and walking them is how a file
 * integrity check turns into an hour of hashing somebody's photo library. The
 * exclusion is structural rather than a setting: this class only ever returns
 * core and plugin directories.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Targets {

	/**
	 * How many files one target's walk enumerates.
	 *
	 * Bounded rather than unbounded: a site with a runaway directory under a
	 * plugin folder must not turn this into an out-of-memory error.
	 */
	public const DEFAULT_WALK_LIMIT = 20000;

	/**
	 * Directories a walk does not enter by name alone, whatever the target.
	 *
	 * Build output, dependency trees and version-control metadata: tens of
	 * thousands of files that nobody edits by hand. They cost twice over — the
	 * cap is spent on them before the walk reaches the code it was looking
	 * for, and every one of them is reported as a file nobody published.
	 *
	 * The name alone does not decide, though, because publishers ship them: a
	 * directory plugin's `vendor` is code it loads like any other, and core
	 * ships one under `wp-includes`. So a folder by one of these names is
	 * walked where its publisher ships files under it, and anywhere inside a
	 * directory WordPress itself owns, where nothing belongs that core did not
	 * ship. Anywhere else it is set aside and named once, with how many files
	 * it holds, rather than walked file by file: a folder with a familiar name
	 * was the one place a dropped file was never looked for. See `walk()`.
	 */
	public const SKIP_ANYWHERE = array( 'node_modules', '.git', '.svn', '.hg', 'vendor', 'bower_components', '.idea', '.vscode' );

	/** The directories at a WordPress root that core alone fills. */
	private const CORE_OWNED = array( 'wp-admin', 'wp-includes' );

	/**
	 * How many files a set-aside folder is counted up to. Past it the count is
	 * a floor, which is all the report has to say.
	 */
	public const SET_ASIDE_COUNT_MAX = 1000;

	/**
	 * Everything worth checking on this site, core first.
	 *
	 * @return array<int, array{context: string, slug: string, version: string, root: string, prefix: string}>
	 */
	public static function all(): array {
		global $wp_version;

		$targets = array(
			array(
				'context' => Manifest::CONTEXT_CORE,
				'slug'    => '',
				'version' => (string) $wp_version,
				// Core's manifest paths are relative to the WordPress root.
				'root'    => untrailingslashit( ABSPATH ),
				'prefix'  => '',
			),
		);

		foreach ( self::installed_plugins() as $slug => $plugin ) {
			$targets[] = array(
				'context' => Manifest::CONTEXT_PLUGIN,
				'slug'    => $slug,
				// Carried alongside the slug rather than looked up again by
				// whoever reports on this target: the report naming what could
				// not be checked runs from a saved result, long after the
				// plugin list that knows the name was read.
				'name'    => $plugin['name'],
				'version' => $plugin['version'],
				'root'    => untrailingslashit( WP_PLUGIN_DIR ) . '/' . $slug,
				// A plugin's manifest paths are relative to its own folder, so
				// the recorded path carries the folder to stay unambiguous
				// across the whole site.
				'prefix'  => 'wp-content/plugins/' . $slug . '/',
			);
		}

		/*
		 * And the three locations nobody publishes a checksum for. They are
		 * compared against a baseline rather than a manifest — a weaker claim,
		 * and the only one available for the places persistence actually
		 * hides.
		 */
		foreach ( Unpublished::all() as $unpublished ) {
			$targets[] = $unpublished;
		}

		/**
		 * Filters what the integrity check looks at.
		 *
		 * Uploads are absent by construction rather than by omission, and a
		 * filter that added them would be adding an hour of hashing to a daily
		 * job for files nobody published. Present so a test can stand a fixture
		 * in for a real target, and so a host with an unusual layout can
		 * correct one.
		 *
		 * @param array<int, array{context: string, slug: string, version: string, root: string, prefix: string, name?: string}> $targets
		 */
		return (array) apply_filters( 'bettershield_integrity_targets', $targets );
	}

	/**
	 * The version of a target installed now, or '' where this cannot say: a
	 * location nobody publishes, or a target a filter stood in for a plugin
	 * that is not installed.
	 *
	 * Asked again rather than taken from a saved run, because a plugin can be
	 * updated between two ticks of one, and so can core.
	 *
	 * @param array{context?: string, slug?: string} $target
	 */
	public static function installed_version( array $target ): string {
		$context = (string) ( $target['context'] ?? '' );

		if ( Manifest::CONTEXT_CORE === $context ) {
			global $wp_version;

			return (string) $wp_version;
		}

		if ( Manifest::CONTEXT_PLUGIN === $context ) {
			return (string) ( self::installed_plugins()[ (string) ( $target['slug'] ?? '' ) ]['version'] ?? '' );
		}

		return '';
	}

	/**
	 * Installed plugins that live in a folder, by slug.
	 *
	 * Single-file plugins are not among them: the directory publishes
	 * checksums per folder, and a plugin that is one file has no manifest to
	 * be compared against. It is held to a baseline instead, as a plugin the
	 * directory does not list — see `Unpublished::single_file_plugins()`.
	 *
	 * @return array<string, array{version: string, name: string, file: string}>
	 */
	public static function installed_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$out = array();

		foreach ( get_plugins() as $file => $data ) {
			$file = (string) $file;

			if ( false === strpos( $file, '/' ) ) {
				continue; // A single-file plugin has no folder to compare.
			}

			// The real folder: lowercased or with its dots stripped, the name
			// points at a folder that isn't there, which reads as deleted.
			$slug = self::folder_name( (string) strtok( $file, '/' ) );

			if ( '' === $slug || isset( $out[ $slug ] ) ) {
				continue;
			}

			$out[ $slug ] = array(
				'version' => (string) ( $data['Version'] ?? '' ),
				'name'    => wp_strip_all_tags( (string) ( $data['Name'] ?? $slug ) ),
				'file'    => $file,
			);
		}

		return $out;
	}

	/**
	 * A plugin's folder as it is on disk, or empty for a name that isn't one
	 * folder directly under the plugins folder.
	 */
	public static function folder_name( string $name ): string {
		return Manifest::is_safe_relative_path( $name ) && 1 !== preg_match( '#[/\\\\]#', $name ) ? $name : '';
	}

	/**
	 * How many files one target's walk may enumerate.
	 */
	public static function walk_limit(): int {
		/**
		 * Filters how many files one target's walk enumerates.
		 *
		 * Reaching the cap is reported rather than hidden, so raising it is a
		 * trade between memory and how much of a large location is examined.
		 *
		 * @param int $files Paths one walk may return.
		 */
		return max( 1, (int) apply_filters( 'bettershield_integrity_walk_limit', self::DEFAULT_WALK_LIMIT ) );
	}

	/**
	 * The real path a walk of this directory is bounded by, or null when the
	 * directory does not resolve to one.
	 *
	 * Resolved once, at the top of the walk, so that every directory the walk
	 * meets can be measured against where this location actually is. A
	 * location reached through a symbolic link is ordinary — a deploy layout
	 * that links the current release into place makes every one of them one —
	 * so the bound is the resolved path rather than the path that was asked
	 * for.
	 */
	public static function walk_root( string $root ): ?string {
		$real = realpath( $root );

		return false === $real ? null : rtrim( str_replace( '\\', '/', $real ), '/' );
	}

	/**
	 * Whether a walk may descend into a directory it has reached.
	 *
	 * A directory tree is only a tree while nothing in it points back at
	 * something above it. A link that does — planted, or left behind by
	 * somebody sharing a library folder between two plugins — turns one
	 * location into an unbounded supply of paths, each of them the same files
	 * under a longer name. The walks that meet one have no budget between them
	 * and the request's own time limit, and the caller that was waiting for an
	 * answer gets a killed request instead of a report.
	 *
	 * So a directory is descended into only where all of this holds: it
	 * resolves, it resolves to somewhere inside the location being walked, and
	 * this walk has not already been there. A link to a directory inside the
	 * location is refused as well, rather than claiming that directory's real
	 * path for itself: the files are walked where they live, and the path this
	 * reports them under stays the same from one walk to the next.
	 *
	 * @param array<string, bool> $visited Real paths this walk has descended into, added to here.
	 */
	public static function may_descend( \SplFileInfo $directory, string $real_root, array &$visited ): bool {
		$real = $directory->getRealPath();

		if ( false === $real ) {
			// A link with nothing at the end of it, or a directory that went
			// away between the listing and this question.
			return false;
		}

		$real = rtrim( str_replace( '\\', '/', $real ), '/' );

		// Somebody else's tree, reached through a link inside this one. Where
		// it leads is not bounded and what is in it is not this location's to
		// report on.
		if ( $real !== $real_root && 0 !== strpos( $real . '/', $real_root . '/' ) ) {
			return false;
		}

		if ( isset( $visited[ $real ] ) || $directory->isLink() ) {
			return false;
		}

		$visited[ $real ] = true;

		return true;
	}

	/**
	 * Directories this target's walk does not descend into.
	 *
	 * The content and uploads directories are read from the constants rather
	 * than named: a site is free to move them, and a check whose exclusion is a
	 * string literal walks somebody's media library the moment they do. The
	 * literal is kept beside them, because a site that moved the constant and
	 * left the old directory in place still has files there that core does not
	 * publish.
	 *
	 * @param array<string, mixed> $target
	 * @return string[] Paths relative to the target's root.
	 */
	public static function skipped_dirs( array $target ): array {
		if ( Manifest::CONTEXT_CORE !== ( $target['context'] ?? '' ) ) {
			return array();
		}

		$root  = untrailingslashit( str_replace( '\\', '/', (string) $target['root'] ) );
		$found = array();

		$uploads = wp_upload_dir( null, false );

		foreach ( array( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : '', $uploads['basedir'] ?? '' ) as $dir ) {
			$dir = untrailingslashit( str_replace( '\\', '/', (string) $dir ) );

			if ( '' === $dir || 0 !== strpos( $dir . '/', $root . '/' ) ) {
				continue; // Not under this root, so this walk never reaches it.
			}

			$inside = ltrim( substr( $dir, strlen( $root ) ), '/' );

			if ( '' !== $inside ) {
				$found[] = $inside;
			}
		}

		$found[] = 'wp-content';

		return array_values( array_unique( $found ) );
	}

	/**
	 * Paths that exist under a target's root, relative to it.
	 *
	 * The listing alone, for a caller with no publisher's file list to hand;
	 * the check itself uses `walk()`.
	 *
	 * @param array<string, mixed> $target
	 * @param int|null             $limit     Paths to return at most; the filtered default when null.
	 * @param bool|null            $truncated Set when the cap or a read error prevents a complete listing.
	 * @return array<int, string>
	 */
	public static function disk_paths( array $target, ?int $limit = null, ?bool &$truncated = null ): array {
		$walk      = self::walk( $target, array(), $limit );
		$truncated = $walk['truncated'];

		return $walk['paths'];
	}

	/**
	 * Paths that exist under a target's root, relative to it, and the folders
	 * the walk set aside.
	 *
	 * Enumeration only — nothing here is read or hashed, so this is cheap
	 * enough to do in one pass for a target while the hashing that follows is
	 * chunked. Directories that are somebody else's business are skipped: for
	 * core that is the content directory, which core does not publish and which
	 * holds the uploads this check must never walk. A folder by one of the names
	 * in SKIP_ANYWHERE is walked or set aside by the rule given there, which is
	 * why the publisher's own list is asked for.
	 *
	 * @param array<string, mixed> $target
	 * @param string[]             $published Paths the target's publisher ships, relative to its root.
	 * @param int|null             $limit     Paths to return at most; the filtered default when null.
	 * @return array{paths: string[], truncated: bool, set_aside: array<string, array{files: int, complete: bool}>}
	 */
	public static function walk( array $target, array $published = array(), ?int $limit = null ): array {
		$root  = (string) ( $target['root'] ?? '' );
		$limit = null !== $limit ? max( 1, $limit ) : self::walk_limit();
		$walk  = array(
			'paths'     => array(),
			'truncated' => false,
			'set_aside' => array(),
		);

		if ( ! is_dir( $root ) ) {
			return $walk;
		}

		$real_root = self::walk_root( $root );

		if ( null === $real_root ) {
			// It was a directory a moment ago. An answer this walk cannot
			// stand behind is an incomplete one rather than an empty one.
			$walk['truncated'] = true;

			return $walk;
		}

		$skip_dirs = self::skipped_dirs( $target );
		$shipped   = self::published_dirs( $published );
		$core      = Manifest::CONTEXT_CORE === ( $target['context'] ?? '' );
		$visited   = array( $real_root => true );
		$set_aside = array();
		$found     = array();
		$truncated = false;

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
					static function ( \SplFileInfo $file, string $key, \RecursiveDirectoryIterator $inner ) use ( $root, $real_root, $skip_dirs, $shipped, $core, &$visited, &$set_aside ): bool {
						if ( ! $inner->isDir() ) {
							return true;
						}

						$relative = ltrim( str_replace( $root, '', $file->getPathname() ), '/' );

						foreach ( $skip_dirs as $skip ) {
							if ( $relative === $skip || 0 === strpos( $relative, $skip . '/' ) ) {
								return false;
							}
						}

						// By name at any depth, because a build directory is as
						// likely to be three levels inside a plugin as at its
						// root; and then by where it is, because so is a
						// dependency folder its publisher ships.
						if ( in_array( $file->getFilename(), self::SKIP_ANYWHERE, true ) && ! isset( $shipped[ $relative ] ) && ! ( $core && self::core_owns( $relative ) ) ) {
							$set_aside[ $relative . '/' ] = self::count_files( $file, $real_root );

							return false;
						}

						return self::may_descend( $file, $real_root, $visited );
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				$found[] = ltrim( str_replace( $root, '', $file->getPathname() ), '/' );

				/*
				 * The cap is applied to the sorted set rather than to whatever
				 * the filesystem happened to hand back first, so which files a
				 * capped walk kept is the same answer every time. Compacting at
				 * twice the cap bounds the memory this holds while the walk is
				 * still running.
				 */
				if ( count( $found ) > $limit * 2 ) {
					$found     = self::capped( $found, $limit );
					$truncated = true;
				}
			}
		} catch ( \Throwable $e ) {
			// An unreadable directory is a fact about the host, not a crash.
			$truncated = true;
		}

		ksort( $set_aside );

		/*
		 * Sorted, because the caller walks this in chunks across requests and
		 * resumes where it left off. The iterator's own order is whatever the
		 * filesystem hands back, which is not stable between two enumerations
		 * of the same tree — so a scan that resumed at an offset was indexing
		 * into a differently ordered list and could step straight over a file
		 * it had never looked at.
		 */
		return array(
			'paths'     => self::capped( $found, $limit ),
			'truncated' => $truncated || count( $found ) > $limit,
			'set_aside' => $set_aside,
		);
	}

	/**
	 * Sort, then keep the first `$limit`.
	 *
	 * @param string[] $found
	 * @return string[]
	 */
	private static function capped( array $found, int $limit ): array {
		sort( $found );

		return count( $found ) > $limit ? array_slice( $found, 0, $limit ) : $found;
	}

	/**
	 * Every directory a publisher ships a file somewhere under, relative to
	 * the target's root.
	 *
	 * @param string[] $published
	 * @return array<string, true>
	 */
	private static function published_dirs( array $published ): array {
		$dirs = array();

		foreach ( $published as $path ) {
			$directory = dirname( (string) $path );

			// An ancestor already listed was listed with all of its own.
			while ( '.' !== $directory && '/' !== $directory && '' !== $directory && ! isset( $dirs[ $directory ] ) ) {
				$dirs[ $directory ] = true;
				$directory          = dirname( $directory );
			}
		}

		return $dirs;
	}

	/**
	 * Whether a path, relative to the WordPress root, lies inside a directory
	 * core alone fills.
	 */
	private static function core_owns( string $relative ): bool {
		return in_array( strstr( $relative . '/', '/', true ), self::CORE_OWNED, true );
	}

	/**
	 * How many files a folder this walk set aside holds, counted up to
	 * SET_ASIDE_COUNT_MAX and bounded the way the walk is.
	 *
	 * @return array{files: int, complete: bool}
	 */
	private static function count_files( \SplFileInfo $directory, string $real_root ): array {
		$visited = array();
		$files   = 0;

		if ( ! self::may_descend( $directory, $real_root, $visited ) ) {
			return array(
				'files'    => 0,
				'complete' => false,
			);
		}

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $directory->getPathname(), \FilesystemIterator::SKIP_DOTS ),
					static function ( \SplFileInfo $file, string $key, \RecursiveDirectoryIterator $inner ) use ( $real_root, &$visited ): bool {
						return ! $inner->isDir() || self::may_descend( $file, $real_root, $visited );
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ( $iterator as $file ) {
				if ( $file->isFile() && ++$files >= self::SET_ASIDE_COUNT_MAX ) {
					return array(
						'files'    => $files,
						'complete' => false,
					);
				}
			}
		} catch ( \Throwable $e ) {
			return array(
				'files'    => $files,
				'complete' => false,
			);
		}

		return array(
			'files'    => $files,
			'complete' => true,
		);
	}

	/**
	 * Files core does not publish and never will, which are therefore not
	 * "added" when they turn up.
	 *
	 * `wp-config.php` is written by the installer and holds this site's own
	 * secrets. The rest are written by servers, installers and WordPress
	 * itself. Reporting any of them as an unexpected file would train the
	 * reader to ignore the one that matters.
	 *
	 * An `.htaccess` or a `.user.ini` is expected at the install root only,
	 * where the config watch hashes it. Nothing in WordPress writes either one
	 * into a plugin's folder, and either can run code before every script
	 * beneath it, so one the publisher did not ship is an addition there and
	 * is graded as code (`Packages::can_run()`).
	 */
	public static function is_expected_extra( array $target, string $relative ): bool {
		if ( Manifest::CONTEXT_CORE !== $target['context'] ) {
			// Under a plugin folder, anything the directory did not publish is
			// worth reporting — except what a server or an editor drops beside
			// any file.
			return in_array( basename( $relative ), array( '.DS_Store', 'error_log' ), true );
		}

		$expected = array(
			'wp-config.php',
			'.htaccess',
			'.user.ini',
			'.maintenance',
			'php.ini',
			'.DS_Store',
			'error_log',
			'robots.txt',
			'favicon.ico',
			'sitemap.xml',
			'sitemap.xml.gz',
		);

		return in_array( $relative, $expected, true ) || in_array( basename( $relative ), array( '.DS_Store', 'error_log' ), true );
	}
}
