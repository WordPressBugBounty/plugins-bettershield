<?php
/**
 * Fix for "Quarantined files are not blocked from the web" (#2207).
 *
 * Where the server reads the folder's own rule, the seal is written for the
 * owner, with Undo. Where it does not, the exact rule for that server and
 * that folder is handed over to add to the server's configuration. Either
 * way the server is asked again in the background, never in the request,
 * and only the audit after it says the folder is refused.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Cron\Runner;
use BetterShield\Events\Writer;
use BetterShield\Files\Guarded;
use BetterShield\Files\Quarantine;
use BetterShield\Support\Server;
use BetterShield\Support\ServerRule;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class QuarantineSeal {

	/** The undo ledger's key for a seal written from here. */
	public const ACTION = 'quarantine_seal';

	/** The background task that asks the server, as the weekly sweep does. */
	public const PROBE = 'bettershield_artifact_probe';

	/**
	 * What the panel offers: the server, the folder the finding tested, and
	 * either the repair or the server's rule.
	 *
	 * @return array{server: string, folder: string, repair: bool, custom: bool, rule: ?array, checking: bool}
	 */
	public static function state(): array {
		$uploads = wp_upload_dir( null, false );
		$dir     = empty( $uploads['error'] ) ? untrailingslashit( (string) $uploads['basedir'] ) . '/' . Guarded::QUARANTINE_DIR : '';
		$folder  = '' === $dir ? '' : trailingslashit( Quarantine::site_relative( $dir ) );
		$reads   = Server::honors_redirect_rules();
		$file    = '' === $dir ? '' : $dir . '/.htaccess';
		$custom  = '' !== $file && file_exists( $file ) && ! in_array( self::rules_in( $file ), array( Guarded::QUARANTINE_RULES, Guarded::QUARANTINE_RULES_PRIOR ), true );
		$pending = Runner::pending_request();

		return array(
			'server'   => Server::label(),
			'folder'   => $folder,
			// Written here only where the server reads it, over nothing or
			// over this plugin's own earlier rule.
			'repair'   => false !== $reads && '' !== $dir && is_dir( $dir ) && ! $custom && false === Guarded::quarantine_is_sealed(),
			'custom'   => $custom,
			'rule'     => false === $reads && '' !== $dir ? ServerRule::deny_folder( self::web_folder( $uploads ) ) : null,
			'checking' => is_array( $pending ) && self::PROBE === ( $pending['hook'] ?? '' ),
		);
	}

	/**
	 * The quarantine folder as the server is asked for it: the uploads
	 * address's path, not the path on disk. They differ where WordPress
	 * lives in a subfolder (/wp/wp-content/…) and where uploads live outside
	 * it (Bedrock's /app/uploads/), and a rule naming the disk path matches
	 * no request there.
	 *
	 * @param array<string, mixed> $uploads wp_upload_dir()'s answer.
	 */
	private static function web_folder( array $uploads ): string {
		$path = (string) wp_parse_url( (string) ( $uploads['baseurl'] ?? '' ), PHP_URL_PATH );

		return trim( $path, '/' ) . '/' . Guarded::QUARANTINE_DIR . '/';
	}

	/**
	 * The rules a seal file holds, bounded as the check reads them.
	 */
	private static function rules_in( string $file ): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- a one-line marker file; unreadable reads as somebody else's.
		return trim( (string) @file_get_contents( $file, false, null, 0, 4096 ) );
	}

	/**
	 * Write the seal, record it and look again.
	 *
	 * @return array{undo: string}|\WP_Error
	 */
	public static function repair() {
		$token = Guarded::repair_quarantine_seal( self::ACTION );

		if ( is_wp_error( $token ) ) {
			return $token;
		}

		Writer::instance()->record( 'quarantine_sealed', Writer::SEVERITY_LOW, array( 'object_type' => 'quarantine', 'context' => array( 'server' => Server::kind() ) ) );
		Auditor::run();

		return array( 'undo' => $token );
	}

	/**
	 * The seal written from here that still stands, for the list of ways
	 * back kept after the finding closes (#2658), or null.
	 *
	 * @return array{undo: string}|null
	 */
	public static function open_seal(): ?array {
		if ( true !== Guarded::quarantine_is_sealed() ) {
			return null;
		}

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 1 ) as $token ) {
			return array( 'undo' => $token );
		}

		return null;
	}

	/**
	 * Take back a seal written from here, and only such a seal.
	 *
	 * @return true|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$undone = Guarded::restore( $token );

		if ( is_wp_error( $undone ) ) {
			return $undone;
		}

		Writer::instance()->record( 'quarantine_seal_undone', Writer::SEVERITY_MEDIUM, array( 'object_type' => 'quarantine', 'context' => array( 'server' => Server::kind() ) ) );
		Auditor::run();

		return true;
	}

	/**
	 * Ask the server again in the background; the audit that runs after it
	 * decides whether the finding closes.
	 *
	 * @return true|\WP_Error
	 */
	public static function check_again( int $user_id ) {
		return Runner::instance()->request_run( self::PROBE, $user_id );
	}
}
