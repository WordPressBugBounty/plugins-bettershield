<?php
/**
 * Whether the disk the site writes to is close to full.
 *
 * A full disk fails quietly and everywhere at once: the activity log stops
 * recording, the daily seal cannot be written, quarantine has nowhere to keep
 * a file, and an update unpacks halfway. Security records stop exactly when
 * they may be needed, so this is read with the rest of the audit rather than
 * discovered afterwards.
 *
 * Read from the operating system for the two folders this site writes to:
 * the content folder and the uploads folder, once where they share a volume.
 * What the disk reports is the disk, not a hosting account's quota, which
 * PHP cannot see; a host that hides both answers "could not tell".
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DiskSpace {

	/** Below this, free space is low whatever the size of the disk. */
	public const LOW_BYTES = 524288000;

	/**
	 * Below this share of the disk, free space is low too, while it is also
	 * under the ceiling below: five percent of a very large disk is still a
	 * great deal of room.
	 */
	public const LOW_SHARE = 0.05;

	/** The ceiling the share applies under. */
	public const SHARE_CEILING_BYTES = 5368709120;

	/** Below this, the next large write, an update say, may fail. */
	public const CRITICAL_BYTES = 104857600;

	/**
	 * Free and total space for each folder the site writes to, or null where
	 * neither can be read.
	 *
	 * @return array<int, array{folder: string, free: int, total: int}>|null
	 */
	public static function measure(): ?array {
		$uploads = wp_upload_dir( null, false );
		$folders = array(
			'content' => WP_CONTENT_DIR,
			'uploads' => empty( $uploads['error'] ) ? (string) $uploads['basedir'] : '',
		);

		$volumes = array();
		$seen    = array();

		foreach ( $folders as $folder => $path ) {
			if ( '' === $path || ! is_dir( $path ) ) {
				continue;
			}

			// The same volume, reached by two folders, is one answer.
			$stat   = @stat( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a folder that cannot be read is simply measured.
			$device = is_array( $stat ) ? (string) $stat['dev'] : $path;

			if ( isset( $seen[ $device ] ) ) {
				continue;
			}

			$free  = function_exists( 'disk_free_space' ) ? @disk_free_space( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a host that disables it is answered with "could not tell".
			$total = function_exists( 'disk_total_space' ) ? @disk_total_space( $path ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.

			if ( ! is_numeric( $free ) || ! is_numeric( $total ) || (float) $total <= 0 ) {
				continue;
			}

			$seen[ $device ] = true;
			$volumes[]       = array(
				'folder' => $folder,
				'free'   => (int) $free,
				'total'  => (int) $total,
			);
		}

		/**
		 * Filters the measured volumes.
		 *
		 * For a host whose PHP sees a different disk than the one the site
		 * writes to: return what the host reports instead, as the same shape.
		 *
		 * @param array<int, array{folder: string, free: int, total: int}> $volumes
		 */
		$volumes = apply_filters( 'bettershield_disk_space', $volumes );

		return is_array( $volumes ) && array() !== $volumes ? array_values( $volumes ) : null;
	}

	/**
	 * Whether one volume is low, and how low.
	 *
	 * @param array{free: int, total: int} $volume
	 * @return string '' when there is room, 'low', or 'critical'.
	 */
	public static function level( array $volume ): string {
		$free  = (int) $volume['free'];
		$share = $free / max( 1, (int) $volume['total'] );

		if ( $free < self::CRITICAL_BYTES ) {
			return 'critical';
		}

		if ( $free < self::LOW_BYTES || ( $share < self::LOW_SHARE && $free < self::SHARE_CEILING_BYTES ) ) {
			return 'low';
		}

		return '';
	}

	/**
	 * The lowest of the volumes: '' with room everywhere, 'low', or
	 * 'critical'.
	 */
	public static function worst(): string {
		$levels = array_map( array( self::class, 'level' ), (array) self::measure() );

		if ( in_array( 'critical', $levels, true ) ) {
			return 'critical';
		}

		return in_array( 'low', $levels, true ) ? 'low' : '';
	}

	/**
	 * The audit's answer: null with room to spare, the volumes that are low,
	 * or "could not tell".
	 *
	 * @return array<string, string>|\WP_Error|null
	 */
	public static function finding() {
		$volumes = self::measure();

		if ( null === $volumes ) {
			return new \WP_Error( 'bettershield_audit_unknown', __( 'This server does not say how much disk space is free.', 'bettershield' ) );
		}

		$evidence = array();

		foreach ( $volumes as $volume ) {
			if ( '' === self::level( $volume ) ) {
				continue;
			}

			$evidence[ (string) $volume['folder'] ] = sprintf(
				/* translators: 1: free space, e.g. "312 MB", 2: disk size, 3: percentage free. */
				__( '%1$s free of %2$s (%3$s%%)', 'bettershield' ),
				// Whole megabytes below a gigabyte, where a decimal adds nothing.
				size_format( $volume['free'], $volume['free'] < GB_IN_BYTES ? 0 : 1 ),
				size_format( $volume['total'], 0 ),
				number_format_i18n( 100 * $volume['free'] / max( 1, $volume['total'] ), 1 )
			);
		}

		return array() === $evidence ? null : $evidence;
	}
}
