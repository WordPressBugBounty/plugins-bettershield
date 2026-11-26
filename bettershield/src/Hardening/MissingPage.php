<?php
/**
 * The site's own "Page not found", fetched as a visitor would see it.
 *
 * A dashboard request has loaded every plugin's dashboard code before this
 * plugin's first hook runs, so a not-found page drawn inside it is not the
 * page a visitor gets for a missing address, and a plugin's dashboard script
 * can print what the page is meant to keep to itself. This asks the site for
 * one of its own missing addresses instead, as a signed-out visitor, where
 * every plugin takes its front-end path, and answers with that page.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening;

use BetterShield\Support\Claim;
use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class MissingPage {

	/** The fetched page, or a note that fetching failed, per site. */
	public const TRANSIENT = 'bettershield_missing_page';

	/** How long a fetched page, or a failed fetch, is kept. */
	public const KEEP_FOR = 10 * MINUTE_IN_SECONDS;

	/** How long the site is given to answer. */
	public const TIMEOUT = 3;

	/** The largest page kept; anything larger is answered with the plain page. */
	public const MAX_BYTES = 2 * MB_IN_BYTES;

	/** The post ID asked for where the site has plain permalinks: one no site reaches. */
	private const NO_POST = 2147483647;

	/** The response headers a missing page carries that are passed on, as WordPress spells them. */
	private const HEADERS = array(
		'content-type' => 'Content-Type',
		'link'         => 'Link',
		'vary'         => 'Vary',
		'x-pingback'   => 'X-Pingback',
	);

	/** The one fetch at a time. */
	private const CLAIM = 'missing_page_fetch';

	/**
	 * What the page is drawn from, besides the theme and plugins: the
	 * site's name and icon, its language, menus, widgets, and the templates
	 * and styles a block theme keeps as posts.
	 */
	private const DRAWN_FROM = array( 'update_option_blogname', 'update_option_blogdescription', 'update_option_site_icon', 'update_option_WPLANG', 'update_option_sidebars_widgets', 'wp_update_nav_menu', 'save_post_wp_template', 'save_post_wp_template_part', 'save_post_wp_global_styles', 'save_post_wp_navigation' );

	/** Forget the page whenever what draws it may have changed. */
	public static function register(): void {
		foreach ( array_merge( array( 'switch_theme', 'activated_plugin', 'deactivated_plugin', 'upgrader_process_complete', 'customize_save_after', 'permalink_structure_changed' ), self::DRAWN_FROM ) as $hook ) {
			add_action( $hook, array( self::class, 'forget' ) );
		}
	}

	public static function forget(): void {
		delete_transient( self::TRANSIENT );
	}

	/**
	 * Answers this request with the site's not-found page, naming the path
	 * that was asked for, and ends it. Returns, having sent nothing, when the
	 * page can't be had: the caller answers with its plain page.
	 */
	public static function serve(): void {
		$page = self::page();

		if ( null === $page ) {
			return;
		}

		status_header( 404 );
		nocache_headers();

		foreach ( $page['headers'] as $name => $value ) {
			header( $name . ': ' . $value );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against a fixed word.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'HEAD' !== strtoupper( (string) $_SERVER['REQUEST_METHOD'] ) ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the site's own page, as the site served it to a visitor.
			echo self::naming( $page['body'], self::asked_path() );
		}

		exit;
	}

	/**
	 * The page, from the store or fetched now, or null.
	 *
	 * @return array{body: string, headers: array<string, string>}|null
	 */
	public static function page(): ?array {
		$kept = get_transient( self::TRANSIENT );

		if ( is_array( $kept ) ) {
			return isset( $kept['body'], $kept['headers'] ) ? $kept : null;
		}

		// Nothing is fetched, and nothing kept, for a request whose site
		// address isn't the one the site stores.
		if ( ! self::home_is_stored() ) {
			return null;
		}

		// Another request is fetching it: this one gets the plain page rather
		// than a second request to the site.
		if ( ! Claim::claim( self::CLAIM, self::TIMEOUT * 5 ) ) {
			return null;
		}

		try {
			$page = self::fetch();
			set_transient( self::TRANSIENT, $page ?? array( 'failed' => time() ), self::KEEP_FOR );

			return $page;
		} finally {
			Claim::release( self::CLAIM );
		}
	}

	/**
	 * Asks the site for its missing address as a signed-out visitor.
	 *
	 * Without cookies, so nothing in the page belongs to a visitor and it can
	 * be kept for the next. Only a 404 with an HTML page is taken; a redirect,
	 * a timeout, a host that refuses requests to itself or anything else is
	 * null.
	 *
	 * @return array{body: string, headers: array<string, string>}|null
	 */
	public static function fetch(): ?array {
		$response = Http::same_site(
			self::missing_address(),
			array(
				'timeout'             => self::TIMEOUT,
				'limit_response_size' => self::MAX_BYTES + 1,
				'cookies'             => array(),
				'headers'             => array( 'Accept' => 'text/html' ),
			)
		);

		if ( is_wp_error( $response ) || 404 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = (string) wp_remote_retrieve_body( $response );
		$type = (string) wp_remote_retrieve_header( $response, 'content-type' );

		if ( '' === $body || strlen( $body ) > self::MAX_BYTES || 0 !== stripos( $type, 'text/html' ) ) {
			return null;
		}

		$headers = array();

		foreach ( self::HEADERS as $name => $spelled ) {
			$value = wp_remote_retrieve_header( $response, $name );
			$value = is_array( $value ) ? implode( ', ', $value ) : (string) $value;

			// One line, as a header has to be.
			if ( '' !== $value && 1 !== preg_match( '/[\r\n]/', $value ) ) {
				$headers[ $spelled ] = $value;
			}
		}

		return array(
			'body'    => $body,
			'headers' => $headers,
		);
	}

	/**
	 * The page with the address it was fetched from replaced by the one
	 * asked for, wherever the page prints it: as written, escaped for a
	 * script, or encoded in a link. A real missing page names the address
	 * that was asked for, never one the visitor didn't type.
	 */
	public static function naming( string $body, string $asked ): string {
		$fetched = self::fetched_path();
		$pairs   = array(
			$fetched                            => $asked,
			str_replace( '/', '\\/', $fetched ) => str_replace( '/', '\\/', $asked ),
			rawurlencode( $fetched )            => rawurlencode( $asked ),
		);

		return strtr( $body, $pairs );
	}

	/**
	 * Whether the address the page would be fetched from is on the host the
	 * site stores as its own. Where the site address is built from the
	 * request, as some configurations build it from the Host header, any
	 * request could otherwise name the host the page is fetched from, and
	 * that host's page would be kept and shown to every visitor.
	 */
	private static function home_is_stored(): bool {
		$host = self::host_of( home_url( '/' ) );

		return '' !== $host && self::host_of( (string) ( wp_load_alloptions()['home'] ?? '' ) ) === $host;
	}

	/** A URL's host and port, lowercased, or an empty string. */
	private static function host_of( string $url ): string {
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		return strtolower( (string) $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	/** The path, from the site root, the missing page is fetched from. */
	public static function missing_address(): string {
		if ( '' === (string) get_option( 'permalink_structure' ) ) {
			return '?p=' . self::NO_POST;
		}

		return 'bs-' . substr( wp_hash( 'bettershield_missing_page' ), 0, 12 ) . '/';
	}

	/** That address as the page prints it: the site's path and the missing address. */
	private static function fetched_path(): string {
		return trailingslashit( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ) . self::missing_address();
	}

	/**
	 * The path this request asked for, without its query, when it is plain
	 * enough to print anywhere; otherwise the dashboard's own address.
	 */
	public static function asked_path(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- held to a fixed set of characters below; anything else is not used.
		$path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );

		if ( 1 === preg_match( '#^/[A-Za-z0-9/._-]{0,200}$#D', $path ) ) {
			return $path;
		}

		return trailingslashit( (string) wp_parse_url( admin_url( '/' ), PHP_URL_PATH ) );
	}
}
