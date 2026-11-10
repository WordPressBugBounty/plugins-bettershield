<?php
/**
 * A file a host wrote, recorded as expected right after it wrote it.
 *
 * A host that rewrites a helper in mu-plugins leaves a change nothing can tell
 * from tampering, and the alert goes out before anyone can accept it. This
 * takes in the file's exact contents and nothing else: it is not a list of
 * paths, because mu-plugins is where a backdoor survives, so any other
 * contents at that path are reported as they always were.
 *
 * Reachable from the command line alone, on purpose: there is no filter,
 * ability or route to this, because code planted on a site can reach those.
 * Core and directory plugins answer to their publisher and are refused.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ExpectedFile {

	public const UNDO = 'integrity_expected_file';

	/**
	 * @param string $path From the site root, as the Files screen names it.
	 * @return array{undo: string, path: string}|\WP_Error An empty undo means nothing needed changing.
	 */
	public static function record( string $path ) {
		$found = self::location_of( $path );

		if ( is_wp_error( $found ) ) {
			return $found;
		}

		list( $target, $relative ) = $found;

		$absolute = $target['root'] . '/' . $relative;
		$hash     = is_file( $absolute ) ? Manifest::hash_file( $absolute, 'sha256' ) : null;

		if ( ! is_string( $hash ) || '' === $hash ) {
			return self::refused(
				'bettershield_expected_unreadable',
				/* translators: %s: a file path. */
				sprintf( __( '%s can’t be read, so there is nothing to record.', 'bettershield' ), $path ),
				404
			);
		}

		$context = (string) $target['context'];
		$slug    = (string) $target['slug'];
		$prior   = Baseline::recorded_for( $context, $slug )[ $path ] ?? null;
		$rows    = self::open_rows( $path, $hash );

		if ( null !== $prior && hash_equals( $prior, $hash ) && array() === $rows ) {
			return array(
				'undo' => '',
				'path' => $path,
			);
		}

		$token = Ledger::open(
			self::UNDO,
			array(
				'context' => $context,
				'slug'    => $slug,
				'path'    => $path,
				'hash'    => $prior,
				'rows'    => $rows,
			),
			array( 'hash' => $hash )
		);

		if ( null === $token ) {
			return self::refused( 'bettershield_undo_unavailable', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), 500 );
		}

		Baseline::take_in( $target, $relative, $hash, (int) @filesize( $absolute ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the file was hashed above; if it went since, a size of 0 is recorded and the next check reports it.
		self::set_status( array_keys( $rows ), 'suppressed' );

		Writer::instance()->record(
			'file_expected',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => $path,
				'context'     => array(
					'area'  => $context,
					'after' => $hash,
					'undo'  => $token,
				),
			)
		);

		return array(
			'undo' => $token,
			'path' => $path,
		);
	}

	/**
	 * Take it back: the baseline holds what it held before, and a row that
	 * was closed opens again. A file recorded since is left alone.
	 *
	 * @return array{path: string}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::UNDO !== (string) $entry->action_key ) {
			return self::refused( 'bettershield_unknown_undo', __( 'There is no such record.', 'bettershield' ), 404 );
		}

		if ( null !== $entry->reverted_at ) {
			return self::refused( 'bettershield_already_reverted', __( 'That has already been undone.', 'bettershield' ), 409 );
		}

		$prior = (array) $entry->prior_state;
		$path  = (string) ( $prior['path'] ?? '' );
		$hash  = (string) ( ( (array) $entry->applied_state )['hash'] ?? '' );

		Baseline::put_back( (string) ( $prior['context'] ?? '' ), (string) ( $prior['slug'] ?? '' ), $path, $hash, isset( $prior['hash'] ) ? (string) $prior['hash'] : null );

		foreach ( (array) ( $prior['rows'] ?? array() ) as $id => $status ) {
			self::set_status( array( (int) $id ), (string) $status, 'suppressed' );
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'file_expected_undone',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => $path,
			)
		);

		return array( 'path' => $path );
	}

	/**
	 * The watched location a path sits in, where nobody publishes a copy.
	 *
	 * Read off the locations the check itself walks, so a path it does not
	 * look at can't be recorded. A theme is not among them.
	 *
	 * @return array{0: array<string, mixed>, 1: string}|\WP_Error
	 */
	private static function location_of( string $path ) {
		if ( Manifest::is_safe_relative_path( $path ) ) {
			foreach ( Unpublished::all() as $target ) {
				$prefix = (string) $target['prefix'];

				if ( Unpublished::CONTEXT_THEME === $target['context'] || ( '' !== $prefix && ! str_starts_with( $path, $prefix ) ) ) {
					continue;
				}

				$relative = substr( $path, strlen( $prefix ) );

				if ( in_array( $relative, (array) $target['files'], true ) ) {
					return array( $target, $relative );
				}
			}
		}

		return self::refused(
			'bettershield_expected_outside',
			/* translators: %s: a file path. */
			sprintf( __( '%s is not in must-use plugins, drop-ins, configuration or a plugin nobody publishes.', 'bettershield' ), $path )
		);
	}

	/**
	 * The open rows that the file as it stands answers, with their status.
	 *
	 * @return array<int, string>
	 */
	private static function open_rows( string $path, string $hash ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, one path.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, status FROM %i WHERE site_id = 0 AND path_hash = %s AND hash_after = %s AND status IN ('new','acknowledged')",
				Schema::table( 'integrity_changes' ),
				hash( 'sha256', $path ),
				$hash
			)
		);

		$open = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$open[ (int) $row->id ] = (string) $row->status;
		}

		return $open;
	}

	/**
	 * @param int[]  $ids
	 * @param string $status The status to write.
	 * @param string $only   Only rows at this status, when given.
	 */
	private static function set_status( array $ids, string $status, string $only = '' ): void {
		global $wpdb;

		foreach ( $ids as $id ) {
			$where = array(
				'site_id' => 0,
				'id'      => $id,
			);

			if ( '' !== $only ) {
				$where['status'] = $only;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- the plugin's own table, by id.
			$wpdb->update( Schema::table( 'integrity_changes' ), array( 'status' => $status ), $where );
		}
	}

	/** @return \WP_Error */
	private static function refused( string $code, string $message, int $status = 400 ): \WP_Error {
		return new \WP_Error( $code, $message, array( 'status' => $status ) );
	}
}
