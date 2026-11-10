<?php
/**
 * An update made with this plugin out of the way, recorded afterwards.
 *
 * A deploy, a `--skip-plugins` run or a vendor's own updater leaves no row for
 * the baseline to read, so the update is reported as tampering. A host that
 * made one writes the row the upgrader would have written, from the command
 * line, and the next comparison reads it as an update.
 *
 * The baseline takes every change in the folder on the strength of that row,
 * so it is written only for a version that really moved: a row with nothing
 * to account for would stand ready to vouch for the next edit of the header.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UpdateRecord {

	/**
	 * @param string $type    `plugin` or `theme`.
	 * @param string $slug    Its folder, or a one-file plugin's file name.
	 * @param string $version The version on disk, as the caller believes it.
	 * @return array{name: string, from: string, to: string, open: int}|\WP_Error
	 */
	public static function record( string $type, string $slug, string $version ) {
		if ( '' === $slug || '' === $version ) {
			return self::refused( 'bettershield_update_unnamed', __( 'Name the update with --slug=<folder> and --version=<version>.', 'bettershield' ) );
		}

		$found = 'theme' === $type ? self::theme( $slug ) : self::plugin( $slug );

		if ( null === $found ) {
			return self::refused(
				'bettershield_update_not_installed',
				/* translators: %s: a plugin or theme folder. */
				sprintf( __( '%s is not installed.', 'bettershield' ), $slug ),
				404
			);
		}

		if ( ! Baseline::exists_for( $found['context'], $slug ) ) {
			return self::refused(
				'bettershield_update_not_held',
				/* translators: %s: a plugin or theme folder. */
				sprintf( __( '%s has no recorded copy on this site to compare, so there is no update to record. A plugin wordpress.org publishes is checked against the published copy.', 'bettershield' ), $slug ),
				409
			);
		}

		if ( $found['version'] !== $version ) {
			return self::refused(
				'bettershield_update_other_version',
				sprintf(
					/* translators: 1: a plugin or theme folder, 2: a version number. */
					__( '%1$s is at version %2$s on disk.', 'bettershield' ),
					$slug,
					$found['version']
				),
				409
			);
		}

		$from = Baseline::recorded_version( $found['context'], $slug );

		if ( $from === $version ) {
			return self::refused(
				'bettershield_update_not_moved',
				sprintf(
					/* translators: 1: a plugin or theme folder, 2: a version number. */
					__( '%1$s is already recorded at version %2$s, so there is no update to record.', 'bettershield' ),
					$slug,
					$version
				),
				409
			);
		}

		$writer = Writer::instance();

		$writer->record(
			$found['event'],
			Writer::SEVERITY_INFO,
			array(
				'object_type' => $found['object_type'],
				'object_id'   => $found['object_id'],
				'context'     => array(
					'name' => $found['name'],
					'from' => $from,
					'to'   => $version,
				),
			)
		);
		// Now rather than at shutdown: the deploy's next line may be a check.
		$writer->flush();

		$open = Packages::preview( $found['context'], $slug, $version );

		return array(
			'name' => $found['name'],
			'from' => $from,
			'to'   => $version,
			'open' => is_wp_error( $open ) ? 0 : (int) $open['total'],
		);
	}

	/**
	 * Named by its main file, as the upgrader names a plugin.
	 *
	 * @return array{context: string, event: string, object_type: string, object_id: string, name: string, version: string}|null
	 */
	private static function plugin( string $slug ): ?array {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		wp_clean_plugins_cache( false );

		foreach ( array_keys( get_plugins() ) as $file ) {
			$file = (string) $file;

			if ( dirname( $file ) !== $slug && $file !== $slug ) {
				continue;
			}

			// Off the file, past any copy of the header held from before.
			$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $file, false, false );

			return array(
				'context'     => Unpublished::CONTEXT_UNLISTED,
				'event'       => 'plugin_updated',
				'object_type' => 'plugin',
				'object_id'   => $file,
				'name'        => (string) ( $data['Name'] ?? $slug ),
				'version'     => (string) ( $data['Version'] ?? '' ),
			);
		}

		return null;
	}

	/**
	 * @return array{context: string, event: string, object_type: string, object_id: string, name: string, version: string}|null
	 */
	private static function theme( string $slug ): ?array {
		$theme = wp_get_theme( $slug );

		if ( ! $theme->exists() ) {
			return null;
		}

		return array(
			'context'     => Unpublished::CONTEXT_THEME,
			'event'       => 'theme_updated',
			'object_type' => 'theme',
			'object_id'   => $slug,
			'name'        => (string) $theme->get( 'Name' ),
			'version'     => (string) $theme->get( 'Version' ),
		);
	}

	/** @return \WP_Error */
	private static function refused( string $code, string $message, int $status = 400 ): \WP_Error {
		return new \WP_Error( $code, $message, array( 'status' => $status ) );
	}
}
