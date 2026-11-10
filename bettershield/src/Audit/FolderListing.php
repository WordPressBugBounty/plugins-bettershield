<?php
/**
 * Whether the web server lists an uploads folder that has no index file.
 *
 * The folder-listing finding reads the files: any uploads folder without an
 * index file is open. On a server that never lists folders, nginx's default,
 * that folder shows nobody anything, and the finding stayed open for it.
 *
 * **This asks rather than guesses.** It requests the first such folder by
 * its address, once, as a visitor with no cookies. A 403 or 404 means the
 * server does not list it, and counts only when a control request to the
 * REST API is answered normally, because a firewall that refuses this
 * server's own address refuses every request from here. A 200 that is a
 * listing means it is listed. Anything else (a redirect, a timeout, a 200
 * that is a page rather than a listing) records that this could not tell,
 * and the finding keeps reading the files.
 *
 * A request a site makes to itself never leaves the server, so this reaches
 * no third party.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Hardening\Item\DirectoryBrowsing;
use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FolderListing {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_folder_listing';

	/** The statuses a web server refuses a folder with. */
	private const REFUSALS = array( 403, 404 );

	/**
	 * Ask for the first uploads folder without an index file, and remember
	 * the answer.
	 *
	 * @return array{checked_at: string, reliable: bool, refused: bool, reason?: string, code?: int}
	 */
	public static function probe(): array {
		$answer = array(
			'checked_at' => gmdate( 'c' ),
			'reliable'   => true,
			'refused'    => false,
		);

		$uploads = wp_get_upload_dir();
		$base    = is_array( $uploads ) ? (string) ( $uploads['basedir'] ?? '' ) : '';
		$url     = is_array( $uploads ) ? (string) ( $uploads['baseurl'] ?? '' ) : '';

		if ( '' === $base || '' === $url || ! is_dir( $base ) ) {
			return self::unreliable( $answer, 'no_folder' );
		}

		$bare = DirectoryBrowsing::bare_directories( $base, 1 );

		if ( array() === $bare ) {
			return self::unreliable( $answer, 'no_folder' );
		}

		$root     = trailingslashit( wp_normalize_path( $base ) );
		$folder   = wp_normalize_path( (string) $bare[0] );
		$relative = str_starts_with( trailingslashit( $folder ), $root ) ? ltrim( substr( trailingslashit( $folder ), strlen( $root ) ), '/' ) : '';
		$path     = XmlRpc::relative_to_home( trailingslashit( $url ) . $relative );
		$control  = XmlRpc::relative_to_home( rest_url() );

		// Uploads served from another host is not this server's to answer.
		if ( null === $path || null === $control ) {
			return self::unreliable( $answer, 'elsewhere' );
		}

		$response = Http::same_site( trailingslashit( $path ) );

		if ( is_wp_error( $response ) ) {
			return self::unreliable( $answer, 'unreachable' );
		}

		$code           = (int) wp_remote_retrieve_response_code( $response );
		$answer['code'] = $code;

		if ( 200 === $code ) {
			if ( self::is_listing( (string) wp_remote_retrieve_body( $response ) ) ) {
				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			return self::unreliable( $answer, 'not_a_listing' );
		}

		if ( ! in_array( $code, self::REFUSALS, true ) ) {
			return self::unreliable( $answer, $code >= 300 && $code < 400 ? 'redirected' : 'refused' );
		}

		$check = Http::same_site( $control, array( 'headers' => array( 'Accept' => 'application/json' ) ) );

		if ( is_wp_error( $check ) || 200 !== (int) wp_remote_retrieve_response_code( $check ) ) {
			return self::unreliable( $answer, 'refused' );
		}

		$answer['refused'] = true;

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * The last answer, or nothing if this has never run.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['checked_at'] ) ? $stored : null;
	}

	/**
	 * Whether the last answer was a refusal this can stand behind.
	 */
	public static function refused(): bool {
		$last = self::last();

		return null !== $last && ! empty( $last['reliable'] ) && ! empty( $last['refused'] );
	}

	/**
	 * Whether a page is a folder listing: the title Apache, nginx and
	 * LiteSpeed give one.
	 */
	private static function is_listing( string $body ): bool {
		return 1 === preg_match( '/<title>\s*Index of\s/i', $body ) || 1 === preg_match( '/<h1>\s*Index of\s/i', $body );
	}

	/**
	 * Record a run that could not tell, and answer with it.
	 *
	 * @param array<string, mixed> $answer
	 * @return array<string, mixed>
	 */
	private static function unreliable( array $answer, string $reason ): array {
		// A request that failed says nothing about a rule the host answered
		// with lately, so that answer stands, for as long as a server's answer
		// is trusted without being asked again. Its date doesn't move, and any
		// other reason is news about the site itself.
		$last = self::last();

		if ( null !== $last && in_array( $reason, array( 'unreachable', 'refused', 'redirected' ), true ) && self::refused() && time() - (int) strtotime( (string) $last['checked_at'] ) < \BetterShield\Hardening\ServerRules::FRESH_FOR ) {
			return $last;
		}

		$answer['reliable'] = false;
		$answer['reason']   = $reason;
		$answer['refused']  = false;

		update_option( self::OPTION, $answer, false );

		return $answer;
	}
}
