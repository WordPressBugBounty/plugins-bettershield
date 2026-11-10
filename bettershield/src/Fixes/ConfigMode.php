<?php
/**
 * Fix for "wp-config.php can be written by other accounts on the server"
 * (#1868, #2430).
 *
 * Takes away only the write access the group and every other account have
 * (mode & ~0022), keeping the owner's, so WordPress still reads the file and
 * the owner can still edit it. The change is ledgered with the exact mode
 * before it, read back after, and put back at once if the file no longer
 * reads as that mode or WordPress can no longer read it. Nothing is chowned,
 * and the file's contents are never read or written: only its mode changes.
 *
 * The folders under wp-content have the same Fix (#2211), which takes only
 * the world-write bit: a folder's group write is often how a host deploys,
 * and a configuration file's is not.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Checks;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ConfigMode {

	/** The undo ledger's key for the file's mode changed from here. */
	public const ACTION = 'config_file_mode';

	/** The write access taken: the group's and everybody else's. */
	private const TAKEN = 0022;

	/**
	 * The file's mode now, the mode it would get, why it cannot be changed
	 * here when it cannot, and the open change made from here, if any.
	 *
	 * @return array{windows: bool, found: bool, mode: string, proposed: string, writable: bool, refused: string, undo: string, from: string}
	 */
	public static function state(): array {
		$windows = ! Checks::mode_bits_describe_access( PHP_OS_FAMILY );
		$path    = self::path();
		$perms   = null === $path ? false : @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is reported below as a reason.
		$mode    = false === $perms ? 0 : ( $perms & 07777 );
		$open    = self::open_change();

		return array(
			'windows'  => $windows,
			'found'    => null !== $path,
			'mode'     => false === $perms ? '' : self::octal( $mode ),
			'proposed' => false === $perms ? '' : self::octal( $mode & ~self::TAKEN ),
			'writable' => false !== $perms && 0 !== ( $mode & self::TAKEN ),
			'refused'  => null === $path ? '' : ( $windows ? self::reason( 'windows' ) : self::refusal( $path, $perms ) ),
			// The way back, while the change made here is still the file's mode.
			'undo'     => null === $open ? '' : $open['undo'],
			'from'     => null === $open ? '' : $open['from'],
		);
	}

	/**
	 * Take the group's and every other account's write access away, read
	 * the file back, and check again.
	 *
	 * @return array{from: string, to: string, undo: string}|\WP_Error
	 */
	public static function apply() {
		if ( ! Checks::mode_bits_describe_access( PHP_OS_FAMILY ) ) {
			return new \WP_Error( 'bettershield_mode_refused', self::reason( 'windows' ), array( 'status' => 409 ) );
		}

		$path = self::path();

		if ( null === $path ) {
			return new \WP_Error( 'bettershield_mode_refused', self::reason( 'missing' ), array( 'status' => 409 ) );
		}

		$perms   = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused below.
		$refusal = self::refusal( $path, $perms );

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_mode_refused', $refusal, array( 'status' => 409 ) );
		}

		$before = (int) $perms & 07777;
		$after  = $before & ~self::TAKEN;

		if ( $after === $before ) {
			return new \WP_Error( 'bettershield_mode_refused', self::reason( 'already' ), array( 'status' => 409 ) );
		}

		// The way back first: if it cannot be written down, nothing changes.
		$token = Ledger::open( self::ACTION, array( 'mode' => $before ), array( 'mode' => $after ) );

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$set = @chmod( $path, $after ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- a refusal is reported below.

		clearstatcache( true, $path );

		$now = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable counts as not taken.

		if ( ! $set || false === $now || ( $now & 07777 ) !== $after || ! is_readable( $path ) ) {
			@chmod( $path, $before ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- best effort back to where it was; the refusal says so.
			clearstatcache( true, $path );
			Ledger::mark_reverted( $token );

			return new \WP_Error( 'bettershield_mode_unchanged', __( 'The change did not take, or WordPress could not read the file after it, so its permissions were put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		Writer::instance()->record(
			'config_mode_tightened',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'file',
				'object_id'   => 'wp-config.php',
				'context'     => array(
					'from' => self::octal( $before ),
					'to'   => self::octal( $after ),
				),
			)
		);

		Auditor::run();

		return array(
			'from' => self::octal( $before ),
			'to'   => self::octal( $after ),
			'undo' => $token,
		);
	}

	/**
	 * Put the file's mode back as it was before the change made here, while
	 * the file still has the mode that change gave it.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();
		$path    = self::path();
		$perms   = null === $path ? false : @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused below.

		if ( false === $perms || ( $perms & 07777 ) !== (int) ( $applied['mode'] ?? -1 ) ) {
			return new \WP_Error( 'bettershield_mode_changed', __( 'The file’s permissions changed since, so undo left them alone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$before = (int) ( $prior['mode'] ?? -1 );

		if ( $before < 0 || ! @chmod( (string) $path, $before ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- the refusal below is the report.
			Ledger::mark_revert_failed( $token, 'chmod' );

			return new \WP_Error( 'bettershield_mode_unchanged', __( 'The file’s permissions could not be put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		clearstatcache( true, (string) $path );
		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'config_mode_restored',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => 'wp-config.php',
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
	 * The change made here that is still the file's mode, or null.
	 *
	 * @return array{undo: string, from: string}|null
	 */
	public static function open_change(): ?array {
		$path  = self::path();
		$perms = null === $path ? false : @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable offers no undo.

		if ( false === $perms ) {
			return null;
		}

		// The newest few: one file, so an older open change is one somebody
		// changed the mode under since.
		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 3 ) as $token ) {
			$entry   = Ledger::find( $token );
			$applied = null !== $entry && is_array( $entry->applied_state ) ? $entry->applied_state : array();
			$prior   = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();

			if ( (int) ( $applied['mode'] ?? -1 ) === ( $perms & 07777 ) ) {
				return array(
					'undo' => $token,
					'from' => self::octal( (int) ( $prior['mode'] ?? 0 ) ),
				);
			}
		}

		return null;
	}

	/**
	 * Why the file cannot be changed here, or an empty string.
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

		$owner = @fileowner( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- unreadable is refused.

		if ( ! function_exists( 'posix_geteuid' ) || false === $owner ) {
			return self::reason( 'owner_unknown' );
		}

		if ( posix_geteuid() !== $owner ) {
			return self::reason( 'not_owner' );
		}

		return '';
	}

	/**
	 * The words for each reason the file is left alone.
	 */
	private static function reason( string $why ): string {
		switch ( $why ) {
			case 'windows':
				return __( 'On a Windows server, permissions are not set this way.', 'bettershield' );
			case 'missing':
				return __( 'wp-config.php could not be found where WordPress looks for it.', 'bettershield' );
			case 'link':
				return __( 'It is a link to another file, so it is left alone.', 'bettershield' );
			case 'unreadable':
				return __( 'Its permissions could not be read.', 'bettershield' );
			case 'owner_unknown':
				return __( 'This server does not say which account runs WordPress, so it is left alone.', 'bettershield' );
			case 'not_owner':
				return __( 'Another account owns it, so only your host can change it.', 'bettershield' );
		}

		return __( 'Only its owner can write to it already.', 'bettershield' );
	}

	/**
	 * Where wp-config.php is, read afresh: its mode may have changed in this
	 * request, under a cached answer.
	 */
	private static function path(): ?string {
		$path = Guarded::wp_config_path();

		if ( null !== $path ) {
			clearstatcache( true, $path );
		}

		return $path;
	}

	private static function octal( int $mode ): string {
		return sprintf( '%04o', $mode & 07777 );
	}
}
