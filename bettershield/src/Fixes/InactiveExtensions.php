<?php
/**
 * Fix for "Deactivated plugins or themes are still installed" (#2430).
 *
 * Each deactivated plugin and dormant theme the finding counts can be moved
 * into quarantine, one at a time at the owner's press, and put back from
 * the same panel. Nothing is deleted: the folder is packed into one archive
 * in the quarantine folder, the archive is read back and counted, and only
 * then is the folder taken out of the plugins or themes folder. Put back
 * unpacks it where it was. The plugin's uninstall routine never runs, so its
 * settings stay in the database and come back with it.
 *
 * The archive is stored with an extension no server runs and a name nobody
 * can work out, in the folder sealed against being served, so the code it
 * holds cannot be reached from the web while it is there.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class InactiveExtensions {

	/** The undo ledger's key for a plugin or theme moved into quarantine. */
	public const ACTION = 'extension_quarantine';

	/** The most files one move packs inside one request. */
	public const MAX_FILES = 5000;

	/** The most bytes one move packs inside one request. */
	public const MAX_BYTES = 64 * MB_IN_BYTES;

	/**
	 * The deactivated plugins and dormant themes, by plugin file and theme
	 * folder, each with its name; null where they are not this site's to
	 * report, or where a network is too large to say which are in use.
	 *
	 * @return array{plugins: array<string, string>, themes: array<string, string>}|null
	 */
	public static function dormant(): ?array {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		/*
		 * Plugins and themes are the network's, installed and deleted once
		 * for every site, so the finding is the main site's. A subsite's
		 * administrator can delete neither.
		 */
		if ( is_multisite() && ! is_main_site() ) {
			return null;
		}

		$active = (array) get_option( 'active_plugins', array() );
		$in_use = array();

		// Network-activated plugins live in a network option, not in any
		// single site's list. Counting only the site's list called every one
		// of them abandoned — nudging the owner to delete a plugin that is
		// running everywhere.
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );

			/*
			 * And what any other site of the network has active: a plugin
			 * running on one site, or the theme another site shows, is not
			 * one to delete. Read within the bound the network's own overview
			 * keeps; past it, what the sites left unread run cannot be known,
			 * and nothing is reported rather than a guess.
			 */
			$sites = get_sites(
				array(
					'fields'     => 'ids',
					'number'     => \BetterShield\Network\Policies::MAX_SITES + 1,
					'network_id' => get_current_network_id(),
				)
			);

			$capped = count( $sites ) > \BetterShield\Network\Policies::MAX_SITES;

			if ( $capped ) {
				return null;
			}

			foreach ( $sites as $site ) {
				if ( (int) $site === (int) get_current_blog_id() ) {
					continue;
				}

				$active   = array_merge( $active, (array) get_blog_option( (int) $site, 'active_plugins', array() ) );
				$in_use[] = (string) get_blog_option( (int) $site, 'stylesheet', '' );
				$in_use[] = (string) get_blog_option( (int) $site, 'template', '' );
			}
		}

		// This plugin is never one of them. Core fires the activation hook
		// BEFORE it writes the active list, so the baseline audit that runs
		// during activation would otherwise find BetterShield missing from it
		// and report itself as the deactivated plugin on the very first
		// screen the owner sees.
		$active[] = defined( 'BETTERSHIELD_FILE' ) ? plugin_basename( BETTERSHIELD_FILE ) : '';
		$active   = array_unique( array_filter( $active ) );
		$plugins  = array();

		foreach ( get_plugins() as $file => $data ) {
			if ( ! in_array( $file, $active, true ) ) {
				$plugins[ (string) $file ] = '' !== (string) ( $data['Name'] ?? '' ) ? wp_strip_all_tags( (string) $data['Name'] ) : (string) $file;
			}
		}

		// Themes: the active one plus any parent it depends on are in use;
		// everything else is dormant.
		$theme    = wp_get_theme();
		$in_use[] = $theme->get_stylesheet();
		if ( $theme->parent() ) {
			$in_use[] = $theme->get_template();
		}

		// And the default WordPress theme, which Site Health says to keep and
		// flags when it is gone: WordPress falls back to it when the chosen
		// theme breaks. Counted as dormant, a site keeping what core
		// recommends never cleared this.
		$default = \WP_Theme::get_core_default_theme();
		if ( $default instanceof \WP_Theme ) {
			$in_use[] = $default->get_stylesheet();
		}

		$in_use = array_unique( array_filter( $in_use ) );
		$themes = array();

		foreach ( wp_get_themes() as $stylesheet => $data ) {
			if ( ! in_array( (string) $stylesheet, $in_use, true ) ) {
				$themes[ (string) $stylesheet ] = wp_strip_all_tags( (string) $data->get( 'Name' ) );
			}
		}

		return array(
			'plugins' => $plugins,
			'themes'  => $themes,
		);
	}

	/**
	 * What the panel shows: each plugin and theme, why it cannot be moved
	 * here when it cannot, and what was moved and can be put back.
	 *
	 * @return array{rows: array<int, array{kind: string, id: string, name: string, refused: string}>, moved: array<int, array{kind: string, name: string, undo: string, blocked: string}>}
	 */
	public static function state(): array {
		$dormant = self::dormant();
		$rows    = array();

		foreach ( array( 'plugin' => 'plugins', 'theme' => 'themes' ) as $kind => $list ) {
			foreach ( null === $dormant ? array() : $dormant[ $list ] as $id => $name ) {
				$rows[] = array(
					'kind'    => $kind,
					'id'      => (string) $id,
					'name'    => $name,
					'refused' => self::refusal( $kind, (string) $id, $dormant ),
				);
			}
		}

		return array(
			'rows'  => $rows,
			'moved' => self::moved(),
		);
	}

	/**
	 * Move one deactivated plugin or dormant theme into quarantine.
	 *
	 * @param string $kind `plugin` or `theme`.
	 * @param string $id   The plugin's file or the theme's folder, as the panel names it.
	 * @return array{kind: string, name: string, undo: string}|\WP_Error
	 */
	public static function move( string $kind, string $id ) {
		$dormant = self::dormant();
		$list    = 'theme' === $kind ? 'themes' : 'plugins';

		// Only what the finding counts now: anything else, or anything that
		// has been switched on since, is left alone.
		if ( null === $dormant || ! isset( $dormant[ $list ][ $id ] ) ) {
			return new \WP_Error( 'bettershield_not_dormant', __( 'That is not a deactivated plugin or theme the finding counts now, so it was left alone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$refused = self::refusal( $kind, $id, $dormant );

		if ( '' !== $refused ) {
			return new \WP_Error( 'bettershield_move_refused', $refused, array( 'status' => 409 ) );
		}

		$folder = Guarded::quarantine_folder();

		if ( is_wp_error( $folder ) ) {
			return $folder;
		}

		$name    = $dormant[ $list ][ $id ];
		$source  = (string) self::source( $kind, $id );
		$root    = self::root( $kind, $id );
		$archive = sprintf( '%s-%s-%s-%s.quarantined', gmdate( 'Ymd-His' ), substr( hash( 'sha256', $source ), 0, 12 ), wp_generate_password( 20, false, false ), sanitize_file_name( basename( $source ) ) );
		$files   = self::files( $source );

		// The way back first: if it cannot be written down, nothing moves.
		$token = Ledger::open(
			self::ACTION,
			array(
				'kind'    => $kind,
				'id'      => $id,
				'name'    => $name,
				'entry'   => basename( $source ),
				'archive' => $archive,
				'files'   => count( $files ),
			),
			array( 'present' => false )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$path   = $folder . '/' . $archive;
		$packed = self::pack( $source, $root, $files, $path );

		if ( is_wp_error( $packed ) ) {
			Ledger::mark_reverted( $token );
			@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- an archive this request made and could not complete.

			return $packed;
		}

		if ( ! self::remove( $source ) ) {
			// Whatever was taken goes back from the archive just made, and
			// the archive stays as the copy if even that fails.
			$back = self::unpack( $path, $root );

			Ledger::mark_reverted( $token );

			return new \WP_Error(
				'bettershield_move_incomplete',
				is_wp_error( $back )
					? __( 'It could not be moved, and some files could not be put back. A full copy is kept in the quarantine folder.', 'bettershield' )
					: __( 'It could not be moved, so it was left where it was.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		wp_clean_plugins_cache();
		wp_clean_themes_cache();

		Writer::instance()->record(
			'extension_quarantined',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => $kind,
				'object_id'   => $id,
				'context'     => array( 'files' => count( $files ) ),
			)
		);

		Auditor::run();

		return array(
			'kind' => $kind,
			'name' => $name,
			'undo' => $token,
		);
	}

	/**
	 * Put a moved plugin or theme back where it was.
	 *
	 * @return array{kind: string, name: string}|\WP_Error
	 */
	public static function put_back( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$kind    = 'theme' === ( $prior['kind'] ?? '' ) ? 'theme' : 'plugin';
		$id      = (string) ( $prior['id'] ?? '' );
		$blocked = self::blocked( $prior );

		if ( '' !== $blocked ) {
			return new \WP_Error( 'bettershield_put_back_refused', $blocked, array( 'status' => 409 ) );
		}

		$path = self::archive_path( (string) ( $prior['archive'] ?? '' ) );
		$back = self::unpack( (string) $path, self::root( $kind, $id ) );

		if ( is_wp_error( $back ) || ! file_exists( (string) self::source( $kind, $id ) ) ) {
			Ledger::mark_revert_failed( $token, 'unpack' );

			return new \WP_Error( 'bettershield_put_back_failed', __( 'It could not be put back. The copy is still in the quarantine folder.', 'bettershield' ), array( 'status' => 409 ) );
		}

		// Back in place, so the copy kept while it was away is not needed.
		@unlink( (string) $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink -- the archive this made, unpacked and in place again.

		Ledger::mark_reverted( $token );

		wp_clean_plugins_cache();
		wp_clean_themes_cache();

		Writer::instance()->record(
			'extension_put_back',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => $kind,
				'object_id'   => $id,
				'context'     => array(),
			)
		);

		Auditor::run();

		return array(
			'kind' => $kind,
			'name' => (string) ( $prior['name'] ?? $id ),
		);
	}

	/**
	 * What was moved from here and can be put back, newest first.
	 *
	 * @return array<int, array{kind: string, name: string, undo: string, blocked: string}>
	 */
	public static function moved(): array {
		$moved = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 50 ) as $token ) {
			$entry = Ledger::find( $token );
			$prior = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();

			$moved[] = array(
				'kind'    => 'theme' === ( $prior['kind'] ?? '' ) ? 'theme' : 'plugin',
				'name'    => (string) ( $prior['name'] ?? '' ),
				'undo'    => $token,
				'blocked' => self::blocked( $prior ),
			);
		}

		return $moved;
	}

	/**
	 * Why a moved one cannot be put back now, or an empty string.
	 *
	 * @param array<string, mixed> $prior What the ledger kept.
	 */
	private static function blocked( array $prior ): string {
		$kind = 'theme' === ( $prior['kind'] ?? '' ) ? 'theme' : 'plugin';
		$id   = (string) ( $prior['id'] ?? '' );

		if ( null === self::archive_path( (string) ( $prior['archive'] ?? '' ) ) ) {
			return __( 'Its copy is no longer in the quarantine folder.', 'bettershield' );
		}

		$source = self::source( $kind, $id );

		if ( null === $source || file_exists( $source ) ) {
			return __( 'Something with the same name was installed since, so it was left alone.', 'bettershield' );
		}

		return self::can_write() ? '' : self::reason( 'filesystem' );
	}

	/**
	 * Why a plugin or theme cannot be moved here, or an empty string.
	 *
	 * @param array{plugins: array<string, string>, themes: array<string, string>} $dormant
	 */
	private static function refusal( string $kind, string $id, array $dormant ): string {
		$allowed = 'theme' === $kind ? current_user_can( 'delete_themes' ) : current_user_can( 'delete_plugins' );

		if ( ! $allowed || ( is_multisite() && ! current_user_can( 'manage_network_plugins' ) ) ) {
			return self::reason( 'capability' );
		}

		if ( ! class_exists( 'ZipArchive' ) ) {
			return self::reason( 'zip' );
		}

		if ( ! self::can_write() ) {
			return self::reason( 'filesystem' );
		}

		$source = self::source( $kind, $id );

		if ( null === $source ) {
			return self::reason( 'unresolved' );
		}

		/*
		 * A folder can hold more than one plugin, and the folder is what
		 * moves: one of them running anywhere keeps all of them here.
		 */
		if ( 'plugin' === $kind && str_contains( $id, '/' ) ) {
			foreach ( array_keys( get_plugins() ) as $file ) {
				if ( str_starts_with( (string) $file, basename( $source ) . '/' ) && ! isset( $dormant['plugins'][ $file ] ) ) {
					return self::reason( 'shared' );
				}
			}
		}

		$files = self::files( $source );

		if ( null === $files ) {
			return self::reason( 'link' );
		}

		$bytes = 0;

		foreach ( $files as $file ) {
			$bytes += (int) @filesize( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable size counts as nothing; the archive is checked after.
		}

		if ( count( $files ) > self::MAX_FILES || $bytes > self::MAX_BYTES ) {
			return self::reason( 'large' );
		}

		return '';
	}

	/**
	 * The folder, or the single file, a plugin or theme is, inside the folder
	 * WordPress keeps it in; null where it resolves anywhere else.
	 */
	private static function source( string $kind, string $id ): ?string {
		if ( '' === $id || str_contains( $id, '..' ) || 0 !== validate_file( $id ) ) {
			return null;
		}

		if ( 'theme' === $kind ) {
			if ( str_contains( $id, '/' ) ) {
				return null;
			}

			return untrailingslashit( self::root( 'theme', $id ) ) . '/' . $id;
		}

		$top = str_contains( $id, '/' ) ? strtok( $id, '/' ) : $id;

		return untrailingslashit( WP_PLUGIN_DIR ) . '/' . $top;
	}

	/**
	 * The folder a plugin or theme lives in: the plugins folder, or the
	 * themes folder that holds this theme.
	 */
	private static function root( string $kind, string $id ): string {
		return 'theme' === $kind ? untrailingslashit( (string) get_theme_root( $id ) ) : untrailingslashit( WP_PLUGIN_DIR );
	}

	/**
	 * Every file under a folder (or the one file), or null where a link is
	 * met: following one would pack, and then take, files from elsewhere.
	 *
	 * @return string[]|null
	 */
	private static function files( string $source ): ?array {
		if ( is_link( $source ) ) {
			return null;
		}

		if ( is_file( $source ) ) {
			return array( $source );
		}

		if ( ! is_dir( $source ) ) {
			return array();
		}

		$files    = array();
		$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $source, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::SELF_FIRST );

		foreach ( $iterator as $node ) {
			if ( $node->isLink() ) {
				return null;
			}

			if ( $node->isFile() ) {
				$files[] = $node->getPathname();
			}

			if ( count( $files ) > self::MAX_FILES ) {
				break;
			}
		}

		return $files;
	}

	/**
	 * Pack the files into one archive, named below the root as they are on
	 * disk, and read it back.
	 *
	 * @param string[] $files
	 * @return true|\WP_Error
	 */
	private static function pack( string $source, string $root, array $files, string $path ) {
		$zip = new \ZipArchive();

		if ( true !== $zip->open( $path, \ZipArchive::CREATE | \ZipArchive::EXCL ) ) {
			return new \WP_Error( 'bettershield_pack_failed', __( 'Nothing was changed: the copy could not be made.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$base    = strlen( trailingslashit( $root ) );
		$folders = array();

		// Every folder, so an empty one is still there to put back.
		if ( is_dir( $source ) ) {
			$folders[] = $source;
			$iterator  = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $source, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::SELF_FIRST );

			foreach ( $iterator as $node ) {
				if ( $node->isDir() && ! $node->isLink() ) {
					$folders[] = $node->getPathname();
				}
			}
		}

		foreach ( $folders as $folder ) {
			$zip->addEmptyDir( substr( $folder, $base ) );
		}

		foreach ( $files as $file ) {
			$zip->addFile( $file, substr( $file, $base ) );
		}

		$closed = $zip->close();

		$check = new \ZipArchive();
		$count = true === $check->open( $path ) ? $check->numFiles : -1;

		if ( $count >= 0 ) {
			$check->close();
		}

		if ( ! $closed || $count !== count( $files ) + count( $folders ) ) {
			return new \WP_Error( 'bettershield_pack_failed', __( 'Nothing was changed: the copy could not be made.', 'bettershield' ), array( 'status' => 500 ) );
		}

		return true;
	}

	/**
	 * Take the folder (or the file) out, now a checked copy is kept.
	 */
	private static function remove( string $source ): bool {
		global $wp_filesystem;

		if ( ! self::filesystem() ) {
			return false;
		}

		$wp_filesystem->delete( $source, true );

		clearstatcache();

		return ! file_exists( $source );
	}

	/**
	 * Unpack an archive into the root it was packed from.
	 *
	 * @return true|\WP_Error
	 */
	private static function unpack( string $path, string $root ) {
		if ( ! self::filesystem() ) {
			return new \WP_Error( 'bettershield_no_filesystem', self::reason( 'filesystem' ) );
		}

		return unzip_file( $path, $root );
	}

	/**
	 * The kept archive's full path, while it is in the quarantine folder.
	 */
	private static function archive_path( string $name ): ?string {
		if ( '' === $name || basename( $name ) !== $name ) {
			return null;
		}

		$folder = \BetterShield\Files\Quarantine::folder();
		$path   = '' === $folder ? '' : $folder . '/' . $name;

		return '' !== $path && is_file( $path ) && ! is_link( $path ) ? $path : null;
	}

	private static function can_write(): bool {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		return 'direct' === get_filesystem_method( array(), WP_PLUGIN_DIR );
	}

	private static function filesystem(): bool {
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		return self::can_write() && true === WP_Filesystem();
	}

	/**
	 * The words for each reason one is left where it is.
	 */
	private static function reason( string $why ): string {
		switch ( $why ) {
			case 'capability':
				return __( 'Your account cannot remove plugins and themes here. On a network, a network administrator does.', 'bettershield' );
			case 'zip':
				return __( 'This server cannot make the archive the copy is kept in. Remove it from the Plugins or Themes screen instead.', 'bettershield' );
			case 'filesystem':
				return __( 'WordPress asks for server credentials to change these folders, so it is left where it is.', 'bettershield' );
			case 'link':
				return __( 'It links to files elsewhere on the server, so it is left where it is.', 'bettershield' );
			case 'shared':
				return __( 'Its folder holds another plugin that is switched on, so it is left where it is.', 'bettershield' );
			case 'large':
				return __( 'It is too large to move in one step. Remove it from the Plugins or Themes screen instead.', 'bettershield' );
		}

		return __( 'Where it is could not be worked out, so it is left alone.', 'bettershield' );
	}
}
