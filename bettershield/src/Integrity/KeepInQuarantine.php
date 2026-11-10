<?php
/**
 * Keep a file nobody published in quarantine, from Activity › Files (#1971).
 *
 * A file the integrity check found that no publisher shipped could only be
 * judged and deleted by hand, or quarantined once it ended up in an
 * incident. This moves it from its own row: the bytes kept in quarantine,
 * an inert placeholder left where it was (a PHP stub for a PHP file, empty
 * for anything else), and Put back on the quarantine list. Never deleted.
 *
 * The same gate as an incident's response: a working way back in, not in
 * safe mode, never on the store's checkout path, and the same checks on the
 * file (a current record, inside a registered folder, no links, never this
 * plugin's own code or wp-config.php, 2 MB at most).
 *
 * The change record then holds the placeholder's bytes and the status
 * `quarantined`, so the next check does not report the placeholder as a new
 * file; a file put back has its old bytes again, and is reported again.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Incidents\Response;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class KeepInQuarantine {

	/** The status a change is left with once its file is kept. */
	public const STATUS = 'quarantined';

	/**
	 * @return array{path: string, undo: string}|\WP_Error
	 */
	public static function apply( int $id ) {
		global $wpdb;

		if ( ! Response::ready() ) {
			return new \WP_Error(
				'bettershield_quarantine_not_ready',
				__( 'Set up a recovery link or recovery codes first, and leave safe mode: moving a file can break the site, and those are the way back in.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$table = Schema::table( 'integrity_changes' );
		$row   = $wpdb->get_row( $wpdb->prepare( 'SELECT id, change_type, algo FROM %i WHERE site_id = 0 AND id = %d', $table, $id ) );

		if ( ! $row || 'added' !== (string) $row->change_type ) {
			return new \WP_Error( 'bettershield_not_unpublished', __( 'Only an added file, one that isn’t in the official release, can be kept in quarantine from here.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$state = Response::file_state( $id, false, false );

		if ( is_wp_error( $state ) ) {
			$state->add_data( array( 'status' => 409 ) );

			return $state;
		}

		$placeholder = self::placeholder( (string) $state['path'] );
		$undo        = Guarded::replace_verified( 'integrity_quarantine', (string) $state['path'], $placeholder, __( 'An added file', 'bettershield' ), (string) $state['sha256'] );

		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		self::hold( $id, (string) $state['path'] );

		Writer::instance()->record(
			'file_quarantined',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => (string) $state['registered'],
				'context'     => array(
					'undo' => $undo,
					'from' => 'files',
				),
			)
		);

		return array(
			'path' => (string) $state['registered'],
			'undo' => $undo,
		);
	}

	/**
	 * Record a change as kept in quarantine, holding the placeholder now on
	 * disk: what is there, in the record's own algorithm, so the next check
	 * finds the same bytes and says nothing new. Shared by Activity › Files
	 * and an incident's response, which leave the same kind of placeholder
	 * (#2345); a later edit to the placeholder is still a change.
	 */
	public static function hold( int $id, string $path ): void {
		global $wpdb;

		$table = Schema::table( 'integrity_changes' );
		clearstatcache( true, $path );

		$algo  = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT algo FROM %i WHERE site_id = 0 AND id = %d', $table, $id ) );

		$wpdb->update(
			$table,
			array(
				'status'     => self::STATUS,
				'hash_after' => (string) Manifest::hash_file( $path, 'md5' === $algo ? 'md5' : 'sha256' ),
				'size_after' => (int) @filesize( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- written a moment ago; a size that cannot be read is recorded as nothing.
			),
			array(
				'site_id' => 0,
				'id'      => $id,
			),
			array( '%s', '%s', '%d' ),
			array( '%d', '%d' )
		);
	}

	/**
	 * What is left in the file's place: a PHP file keeps a PHP file's name
	 * and runs nothing; anything else is left empty.
	 */
	public static function placeholder( string $path ): string {
		return 1 === preg_match( '/\.(?:' . Packages::SERVER_PHP . ')\z/i', $path )
			? "<?php\n// Contents preserved in BetterShield quarantine.\n"
			: '';
	}
}
