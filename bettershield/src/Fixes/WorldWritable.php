<?php
/**
 * Fix for "Folders under wp-content can be written by every account on the
 * server" (#2211).
 *
 * Takes away only the write access every account has (mode & ~0002), from
 * the folders the finding names and the owner picks, keeping the owner's
 * and the group's: many hosts need group write, and forcing 0755 on them
 * would break the site. Each change is ledgered with the exact mode before
 * it, read back after, and put back at once if the folder no longer reads
 * as that mode or WordPress can no longer write to it. Nothing is chowned,
 * and nothing below the folder is touched.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Checks;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WorldWritable {

	/** The undo ledger's key for a folder's mode changed from here. */
	public const ACTION = 'content_dir_mode';

	/**
	 * The folders the finding names, each with its mode now, the mode it
	 * would be given, and why it cannot be changed here when it cannot.
	 *
	 * @return array{windows: bool, folders: array<int, array{name: string, mode: string, proposed: string, refused: string}>}
	 */
	public static function state(): array {
		$windows = ! Checks::mode_bits_describe_access( PHP_OS_FAMILY );
		$folders = array();

		foreach ( Checks::content_folders() as $name => $path ) {
			$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is reported below as a reason.

			if ( false !== $perms && ! ( $perms & 0002 ) ) {
				continue;
			}

			$mode      = false === $perms ? 0 : ( $perms & 07777 );
			$folders[] = array(
				'name'     => (string) $name,
				'mode'     => false === $perms ? '' : self::octal( $mode ),
				'proposed' => false === $perms ? '' : self::octal( $mode & ~0002 ),
				'refused'  => $windows ? self::reason( 'windows' ) : self::refusal( $path, $perms ),
			);
		}

		return array(
			'windows' => $windows,
			'folders' => $folders,
		);
	}

	/**
	 * The folders whose change made here undo can still put back: the
	 * newest open change of each, while the folder still has the mode that
	 * change gave it.
	 *
	 * @return array<int, array{name: string, from: string, to: string, undo: string}>
	 */
	public static function open_changes(): array {
		$known = Checks::content_folders();
		$open  = array();
		$seen  = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 20 ) as $token ) {
			$entry   = Ledger::find( $token );
			$prior   = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();
			$applied = null !== $entry && is_array( $entry->applied_state ) ? $entry->applied_state : array();
			$name    = (string) ( $prior['name'] ?? '' );
			$path    = $known[ $name ] ?? '';

			// Newest first: an older change of the same folder is one its mode
			// was changed under since.
			if ( '' === $path || isset( $seen[ $name ] ) ) {
				continue;
			}

			$seen[ $name ] = true;

			clearstatcache( true, $path );
			$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable offers no undo.

			if ( false === $perms || ( $perms & 07777 ) !== (int) ( $applied['mode'] ?? -1 ) || (int) ( $prior['mode'] ?? -1 ) < 0 ) {
				continue;
			}

			$open[] = array(
				'name' => $name,
				'from' => self::octal( (int) $prior['mode'] ),
				'to'   => self::octal( $perms ),
				'undo' => $token,
			);
		}

		return $open;
	}

	/**
	 * Take away the world-write bit from each named folder that may be
	 * changed, one at a time, and look again.
	 *
	 * @param string[] $names The folders, by the names the finding shows.
	 * @return array{changed: array<int, array{name: string, from: string, to: string, undo: string}>, refused: array<int, array{name: string, reason: string}>}
	 */
	public static function apply( array $names ): array {
		$known   = Checks::content_folders();
		$changed = array();
		$refused = array();

		foreach ( array_values( array_unique( array_map( 'strval', $names ) ) ) as $name ) {
			$path = $known[ $name ] ?? null;

			if ( null === $path ) {
				$refused[] = array( 'name' => $name, 'reason' => self::reason( 'unknown' ) );
				continue;
			}

			$done = self::tighten( $name, $path );

			if ( is_wp_error( $done ) ) {
				$refused[] = array( 'name' => $name, 'reason' => $done->get_error_message() );
				continue;
			}

			$changed[] = $done;
		}

		if ( array() !== $changed ) {
			Auditor::run();
		}

		return array(
			'changed' => $changed,
			'refused' => $refused,
		);
	}

	/**
	 * Put a folder's mode back as it was before a change made here, while
	 * the folder still has the mode that change gave it.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();
		$name    = (string) ( $prior['name'] ?? '' );
		$path    = Checks::content_folders()[ $name ] ?? '';
		$perms   = '' === $path ? false : @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused below.

		if ( false === $perms || ( $perms & 07777 ) !== (int) ( $applied['mode'] ?? -1 ) ) {
			return new \WP_Error( 'bettershield_mode_changed', __( 'The folder’s permissions changed since, so undo left them alone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$before = (int) ( $prior['mode'] ?? -1 );

		if ( $before < 0 || ! @chmod( $path, $before ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- the refusal below is the report.
			Ledger::mark_revert_failed( $token, 'chmod' );

			return new \WP_Error( 'bettershield_mode_unchanged', __( 'The folder’s permissions could not be put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		clearstatcache( true, $path );
		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'folder_mode_restored',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'folder',
				'object_id'   => $name,
				'context'     => array(
					'from' => self::octal( (int) $applied['mode'] ),
					'to'   => self::octal( $before ),
				),
			)
		);

		Auditor::run();

		return true;
	}

	/**
	 * One folder: checked, ledgered, changed, read back, and put back at
	 * once if it did not take.
	 *
	 * @return array{name: string, from: string, to: string, undo: string}|\WP_Error
	 */
	private static function tighten( string $name, string $path ) {
		if ( ! Checks::mode_bits_describe_access( PHP_OS_FAMILY ) ) {
			return new \WP_Error( 'bettershield_mode_refused', self::reason( 'windows' ) );
		}

		$perms   = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused below.
		$refusal = self::refusal( $path, $perms );

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_mode_refused', $refusal );
		}

		$before = (int) $perms & 07777;
		$after  = $before & ~0002;

		if ( $after === $before ) {
			return new \WP_Error( 'bettershield_mode_refused', self::reason( 'already' ) );
		}

		$token = Ledger::open( self::ACTION, array( 'name' => $name, 'mode' => $before ), array( 'mode' => $after ) );

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ) );
		}

		$set = @chmod( $path, $after ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- a refusal is reported below.

		clearstatcache( true, $path );

		$now = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable counts as not taken.

		if ( ! $set || false === $now || ( $now & 07777 ) !== $after || ! wp_is_writable( $path ) ) {
			@chmod( $path, $before ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- best effort back to where it was; the refusal says so.
			clearstatcache( true, $path );
			Ledger::mark_reverted( $token );

			return new \WP_Error( 'bettershield_mode_unchanged', __( 'The change did not take, or WordPress could not write to the folder after it, so its permissions were put back.', 'bettershield' ) );
		}

		Writer::instance()->record(
			'folder_mode_tightened',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'folder',
				'object_id'   => $name,
				'context'     => array(
					'from' => self::octal( $before ),
					'to'   => self::octal( $after ),
				),
			)
		);

		return array(
			'name' => $name,
			'from' => self::octal( $before ),
			'to'   => self::octal( $after ),
			'undo' => $token,
		);
	}

	/**
	 * Why a folder cannot be changed here, or an empty string.
	 *
	 * @param int|false $perms Its mode, as read.
	 */
	private static function refusal( string $path, $perms ): string {
		if ( is_link( $path ) ) {
			return self::reason( 'link' );
		}

		if ( false === $perms ) {
			return self::reason( 'unreadable' );
		}

		$real = realpath( $path );

		if ( false === $real || ! is_dir( $real ) ) {
			return self::reason( 'unresolved' );
		}

		$owner = @fileowner( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused.

		if ( ! function_exists( 'posix_geteuid' ) || false === $owner ) {
			return self::reason( 'owner_unknown' );
		}

		if ( posix_geteuid() !== $owner ) {
			return self::reason( 'not_owner' );
		}

		return '';
	}

	/**
	 * The words for each reason a folder is left alone.
	 */
	private static function reason( string $why ): string {
		switch ( $why ) {
			case 'windows':
				return __( 'On a Windows server, permissions are not set this way.', 'bettershield' );
			case 'link':
				return __( 'It is a link to another folder, so it is left alone.', 'bettershield' );
			case 'unreadable':
				return __( 'Its permissions could not be read.', 'bettershield' );
			case 'unresolved':
				return __( 'Where it really is could not be worked out.', 'bettershield' );
			case 'owner_unknown':
				return __( 'This server does not say which account runs WordPress, so it is left alone.', 'bettershield' );
			case 'not_owner':
				return __( 'Another account owns it, so only your host can change it.', 'bettershield' );
			case 'already':
				return __( 'It is no longer writable by every account.', 'bettershield' );
		}

		return __( 'The finding does not name that folder.', 'bettershield' );
	}

	private static function octal( int $mode ): string {
		return sprintf( '%04o', $mode & 07777 );
	}
}
