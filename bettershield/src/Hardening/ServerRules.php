<?php
/**
 * Whether the web server already refuses what two .htaccess items refuse.
 *
 * On a server that does not read .htaccess files (nginx, IIS), "Stop PHP
 * running in uploads" and "Hide sensitive files from visitors" cannot write
 * their rules, and said "your host can add it" for good: on a host that had,
 * every site kept asking its owner for something already done (#2048). So
 * the server is asked, the way the quarantine folder's deny rule is: a
 * harmless file of each kind placed in uploads beside a plain-text control,
 * each requested once over this site's own address, then removed.
 *
 * A refusal is believed only beside a control the same server serves: a
 * server that answers 404 to everything has said nothing about these rules.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

use BetterShield\Support\Http;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ServerRules {

	/** The last answer: when it was asked, of which server, and per item. */
	public const OPTION = 'bettershield_server_rules';

	/** How long an answer stands without being asked again. */
	public const FRESH_FOR = 14 * DAY_IN_SECONDS;

	/** What a server answers when it refuses a file. */
	private const REFUSALS = array( 403, 404, 410 );

	/**
	 * Each item, and the kind of file its rule refuses. The PHP marker holds
	 * plain text and no opening tag, so it is harmless if the server runs it,
	 * and running it is exactly the answer "not refused".
	 */
	private const MARKERS = array(
		'uploads_php'     => 'php',
		'sensitive_files' => 'log',
	);

	/**
	 * Ask the web server, and keep its answer.
	 *
	 * Asked by a person's audit and by the weekly sweep, the moments the
	 * quarantine folder is asked about, and never where the request cannot
	 * name its server (WP-CLI) or where the rules this plugin writes are
	 * read, since there the item's own answer is the true one.
	 */
	public static function ask(): void {
		$kind = Server::kind();

		if ( Server::UNKNOWN === $kind ) {
			return;
		}

		if ( false !== Server::honors_redirect_rules() ) {
			delete_option( self::OPTION );

			return;
		}

		$uploads  = wp_upload_dir( null, false );
		$dir      = isset( $uploads['basedir'] ) ? untrailingslashit( (string) $uploads['basedir'] ) : '';
		$base_url = isset( $uploads['baseurl'] ) ? (string) $uploads['baseurl'] : '';
		$base     = (string) wp_parse_url( $base_url, PHP_URL_PATH );
		$home     = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$same     = strtolower( (string) wp_parse_url( $base_url, PHP_URL_HOST ) ) === strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );

		// Uploads served from another host, or from outside this site's own
		// address, are not the files a stranger would be refused here.
		if ( '' === $dir || ! is_dir( $dir ) || ! wp_is_writable( $dir ) || '' === $base || ! $same || ( '' !== trim( $home, '/' ) && ! str_starts_with( $base, untrailingslashit( $home ) . '/' ) ) ) {
			delete_option( self::OPTION );

			return;
		}

		$relative = ltrim( substr( $base, strlen( untrailingslashit( $home ) ) ), '/' );
		$name     = 'bettershield-probe-' . strtolower( wp_generate_password( 12, false ) );
		$text     = "BetterShield server check. This file is removed straight away.\n";
		$written  = array();
		$answers  = array();

		try {
			$files = array( 'control' => 'txt' ) + self::MARKERS;

			foreach ( $files as $key => $extension ) {
				$path = $dir . '/' . $name . '.' . $extension;

				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- a throwaway file of this plugin's own, removed below; a refused write is answered by leaving, without the path in a warning.
				if ( false === @file_put_contents( $path, $text ) ) {
					return;
				}

				$written[ $key ] = $path;
			}

			if ( 200 !== self::status( $relative . '/' . $name . '.txt' ) ) {
				// Not served even the plain file: nothing here can be read.
				delete_option( self::OPTION );

				return;
			}

			foreach ( self::MARKERS as $item => $extension ) {
				$answers[ $item ] = in_array( self::status( $relative . '/' . $name . '.' . $extension ), self::REFUSALS, true );
			}
		} finally {
			foreach ( $written as $path ) {
				if ( is_file( $path ) ) {
					wp_delete_file( $path );
				}
			}
		}

		update_option(
			self::OPTION,
			array(
				'at'       => time(),
				'server'   => $kind,
				'enforced' => $answers,
			),
			false
		);
	}

	/**
	 * Whether the server refused this item's kind of file, recently, on the
	 * server this site runs on now.
	 *
	 * @param string $item The hardening item.
	 */
	public static function enforced( string $item ): bool {
		$stored = get_option( self::OPTION );
		$kind   = Server::kind();

		return is_array( $stored )
			&& ! empty( $stored['enforced'][ $item ] )
			&& time() - (int) ( $stored['at'] ?? 0 ) < self::FRESH_FOR
			// The server it was asked on, compared only where this request
			// can name its own: WP-CLI reads the web's answer as it stands.
			&& ( Server::UNKNOWN === $kind || $kind === (string) ( $stored['server'] ?? '' ) );
	}

	/** The status this site's own server answers a path under it with, or 0. */
	private static function status( string $relative ): int {
		$response = Http::same_site( $relative, array( 'limit_response_size' => 1 ) );

		return is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
	}
}
