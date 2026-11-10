<?php
/**
 * What sits in the plugins directory that no installed plugin claims.
 *
 * WordPress decides what a plugin is by reading one header: the comment block
 * at the top of a PHP file at the top of the plugins directory, or one level
 * down inside a folder. Anything else in that directory — a loose PHP file with
 * no header, a folder of PHP in which no file carries one — is listed on no
 * screen, updated by nothing and loaded only if something else asks for it.
 * That is the shape code takes when it is copied in to be called from
 * somewhere else, and it is also the shape of a data folder a host or a plugin
 * keeps there, or a copy somebody forgot to delete.
 *
 * **This states what is there and refuses to guess the rest.** It names the
 * paths and reads nothing beyond the header WordPress itself already reads: no
 * file is opened, hashed or searched. "No installed plugin claims this" is a
 * fact; "this is malicious" is not, and the copy never says it.
 *
 * The directory's own `index.php`, which WordPress ships to stop the folder
 * being listed, is the one name left out.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Integrity\Packages;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PluginsDirectory {

	/**
	 * How many unclaimed paths are named before the finding becomes a count.
	 * Beyond ten there is a cleanup to plan, not a list to read.
	 */
	public const MAX_NAMED = 10;

	/**
	 * How many entries one pass looks at inside unclaimed folders, all of them
	 * together, shared out between them. A folder with ten thousand files is
	 * reported with a count that says it is a floor, rather than read in full
	 * on an audit's time.
	 */
	public const MAX_WALK = 2000;

	/**
	 * The file names a web server may run as PHP, or that PHP code includes.
	 * The same family the incident signals watch, plus `.inc`.
	 */
	private const EXECUTABLE = '/' . Packages::CODE_PATTERN . '/i';

	/**
	 * Everything in the plugins directory that no installed plugin claims.
	 *
	 * @return array{readable: bool, items: array<int, array{path: string, kind: string, php_files?: int, counted_all?: bool}>, total: int, complete: bool}
	 */
	public static function report(): array {
		$root  = untrailingslashit( WP_PLUGIN_DIR );
		$names = is_dir( $root ) ? @scandir( $root ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable directory is answered below, not warned about.

		if ( ! is_array( $names ) ) {
			return array(
				'readable' => false,
				'items'    => array(),
				'total'    => 0,
				'complete' => false,
			);
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$files   = array();
		$folders = array();

		foreach ( array_keys( get_plugins() ) as $plugin ) {
			$plugin = (string) $plugin;

			if ( false === strpos( $plugin, '/' ) ) {
				$files[ $plugin ] = true;
			} else {
				$folders[ (string) strstr( $plugin, '/', true ) ] = true;
			}
		}

		$items    = array();
		$complete = true;
		$budget   = self::MAX_WALK;

		sort( $names, SORT_STRING );

		/*
		 * The budget is shared out between the unclaimed folders rather than
		 * spent in name order: one folder of data files that sorted first
		 * used all of it, and every folder after it was left out unwalked.
		 */
		$waiting = 0;

		foreach ( $names as $name ) {
			$name = (string) $name;

			if ( '.' !== $name && '..' !== $name && ! isset( $folders[ $name ] ) && is_dir( $root . '/' . $name ) ) {
				++$waiting;
			}
		}

		foreach ( $names as $name ) {
			$name = (string) $name;

			if ( '.' === $name || '..' === $name ) {
				continue;
			}

			$path = $root . '/' . $name;

			if ( is_dir( $path ) ) {
				if ( isset( $folders[ $name ] ) ) {
					continue;
				}

				// An even share of what is left, so the folders after this
				// one keep theirs; what this one does not use stays in.
				$share  = intdiv( $budget, max( 1, $waiting-- ) );
				$left   = $share;
				$count  = $share > 0 ? self::count_executable( $path, $left ) : array( 'files' => 0, 'all' => false );
				$budget -= $share - $left;

				if ( null === $count ) {
					// Unreadable: what is inside is not known, so the list
					// is a floor rather than the whole of it.
					$complete = false;

					continue;
				}

				// Walked only partly, or not at all: what the rest holds is
				// not known either.
				if ( ! $count['all'] ) {
					$complete = false;
				}

				if ( $count['files'] > 0 ) {
					$items[] = array(
						'path'        => self::shown( $name ),
						'kind'        => 'folder',
						'php_files'   => $count['files'],
						'counted_all' => $count['all'],
					);
				}

				continue;
			}

			if ( 'index.php' === $name || isset( $files[ $name ] ) || ! preg_match( self::EXECUTABLE, $name ) ) {
				continue;
			}

			$items[] = array(
				'path' => self::shown( $name ),
				'kind' => 'file',
			);
		}

		return array(
			'readable' => true,
			'items'    => $items,
			'total'    => count( $items ),
			'complete' => $complete,
		);
	}

	/**
	 * How many executable files a folder holds, anywhere inside it.
	 *
	 * Symbolic links are not followed, so a link pointing back up the tree
	 * cannot turn the count into a loop. Null when the folder cannot be read.
	 *
	 * @param int $budget Entries left for this pass; spent here.
	 * @return array{files: int, all: bool}|null
	 */
	private static function count_executable( string $path, int &$budget ): ?array {
		if ( ! is_readable( $path ) ) {
			return null;
		}

		try {
			$walk = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $path, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY,
				\RecursiveIteratorIterator::CATCH_GET_CHILD
			);

			$files = 0;

			foreach ( $walk as $entry ) {
				if ( $budget <= 0 ) {
					return array(
						'files' => $files,
						'all'   => false,
					);
				}

				--$budget;

				if ( $entry instanceof \SplFileInfo && $entry->isFile() && preg_match( self::EXECUTABLE, $entry->getFilename() ) ) {
					++$files;
				}
			}
		} catch ( \UnexpectedValueException $e ) {
			return null;
		}

		return array(
			'files' => $files,
			'all'   => true,
		);
	}

	/**
	 * A path as a person finds it: from the site's root where the plugins
	 * directory is under it, otherwise from the plugins directory's own name.
	 */
	private static function shown( string $name ): string {
		$root = wp_normalize_path( untrailingslashit( WP_PLUGIN_DIR ) );
		$base = wp_normalize_path( untrailingslashit( ABSPATH ) );

		$directory = 0 === strpos( $root, $base . '/' ) ? substr( $root, strlen( $base ) + 1 ) : basename( $root );

		return $directory . '/' . $name;
	}
}
