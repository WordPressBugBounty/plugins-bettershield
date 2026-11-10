<?php
/** An opt-in inert URL. A touch proves a request, not a compromise. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Agents;

use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class DecoyPage {
	public const OPTION = 'bettershield_decoy_page';

	public static function register(): void {
		add_action( 'template_redirect', array( self::class, 'route' ), -100 );
	}

	public static function report(): array {
		$stored = get_option( self::OPTION, array() );
		$slug = is_array( $stored ) ? (string) ( $stored['slug'] ?? '' ) : '';
		return array( 'enabled' => '' !== $slug, 'slug' => $slug, 'url' => '' === $slug ? '' : home_url( '/' . $slug . '/' ) );
	}

	/** @return array|\WP_Error */
	public static function save( bool $enabled, string $slug ) {
		// A pasted path often brings a space at either end (#2664).
		$slug = trim( $slug );

		if ( $enabled ) {
			// One extensionless site-relative segment: no server files, query
			// routes, WordPress endpoints, hidden login paths or URL redirects.
			// Each rule says itself, so the owner hears which one failed.
			$broken = '';

			if ( str_starts_with( $slug, 'wp-' ) || str_starts_with( $slug, 'bettershield' ) ) {
				$broken = __( 'Paths beginning wp- or bettershield are reserved. Choose another.', 'bettershield' );
			} elseif ( strlen( $slug ) < 8 || strlen( $slug ) > 80 ) {
				$broken = __( 'Use 8–80 characters.', 'bettershield' );
			} elseif ( ! preg_match( '/\A[a-z]/', $slug ) ) {
				$broken = __( 'Start the path with a lowercase letter.', 'bettershield' );
			} elseif ( ! preg_match( '/\A[a-z][a-z0-9-]{7,79}\z/D', $slug ) ) {
				$broken = __( 'Use only lowercase letters, digits and hyphens.', 'bettershield' );
			}

			if ( '' !== $broken ) {
				return new \WP_Error( 'bettershield_decoy_path', $broken, array( 'status' => 400 ) );
			}
			$login = (string) wp_parse_url( wp_login_url(), PHP_URL_PATH );
			$target = (string) wp_parse_url( home_url( '/' . $slug . '/' ), PHP_URL_PATH );
			if ( get_page_by_path( $slug, OBJECT, get_post_types() ) || url_to_postid( home_url( '/' . $slug . '/' ) ) || file_exists( ABSPATH . $slug ) || trim( $target, '/' ) === trim( $login, '/' ) || in_array( $slug, array( 'checkout', 'my-account', 'robots-txt', 'sitemap-index', 'xmlrpc-php' ), true ) ) {
				return new \WP_Error( 'bettershield_decoy_collision', __( 'That path is already in use. Choose another.', 'bettershield' ), array( 'status' => 409 ) );
			}
		}
		$previous = self::report();
		$next = $enabled ? array( 'slug' => $slug ) : array();
		// Its way back first, as the other agent switches' (#1824).
		if ( false === \BetterShield\Undo\SettingsLedger::record( 'decoy_page', array( 'enabled' => $previous['enabled'], 'slug' => $previous['slug'] ), array( 'enabled' => $enabled, 'slug' => $enabled ? $slug : '' ) ) ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}
		// Autoloaded: read on every front-end page view, so keeping it out of
		// the one query WordPress already makes buys a query on every one.
		if ( get_option( self::OPTION, array() ) !== $next && ! update_option( self::OPTION, $next, true ) ) {
			return new \WP_Error( 'bettershield_decoy_save', __( 'The decoy setting could not be saved.', 'bettershield' ), array( 'status' => 503 ) );
		}
		Writer::instance()->record( 'canary_page_changed', $previous['enabled'] && ( ! $enabled || $previous['slug'] !== $slug ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM, array( 'context' => array( 'enabled' => $enabled ) ) );
		return self::report();
	}

	public static function matches( string $uri ): bool {
		$report = self::report();
		if ( ! $report['enabled'] || ! str_starts_with( $uri, '/' ) || str_starts_with( $uri, '//' ) ) { return false; }
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		return is_string( $path ) && rtrim( rawurldecode( $path ), '/' ) === rtrim( (string) wp_parse_url( $report['url'], PHP_URL_PATH ), '/' );
	}

	/**
	 * What has taken the decoy's path since it was saved, or '': 'sign_in'
	 * for the moved sign-in address, 'content' for a published post or page.
	 * Saving refuses a path in use; this asks the same of a setting already
	 * live, which is when one turns up there. Asked by the screen and the
	 * owner's test, never on a page view.
	 */
	public static function collision(): string {
		$report = self::report();
		if ( ! $report['enabled'] ) { return ''; }
		// The moved sign-in address took the path: the sign-in form answers
		// there, and the decoy never fires.
		if ( trim( (string) wp_parse_url( $report['url'], PHP_URL_PATH ), '/' ) === trim( (string) wp_parse_url( wp_login_url(), PHP_URL_PATH ), '/' ) ) { return 'sign_in'; }
		$post = get_page_by_path( $report['slug'], OBJECT, get_post_types( array( 'public' => true ) ) );
		if ( ( $post instanceof \WP_Post && 'publish' === $post->post_status ) || 0 !== url_to_postid( $report['url'] ) ) { return 'content'; }
		return '';
	}

	/** The report, with what has taken the path since: for the screen. */
	public static function described(): array {
		return self::report() + array( 'collision' => self::collision() );
	}

	/** The explicit owner test uses the same matcher, without an urgent alert. */
	public static function test(): array {
		// A path something else now answers is not being watched, whatever
		// the matcher says about its shape.
		$collision = self::collision();
		$matched = '' === $collision && self::matches( (string) wp_parse_url( self::report()['url'], PHP_URL_PATH ) );
		Writer::instance()->record( 'canary_page_tested', Writer::SEVERITY_INFO, array( 'context' => array( 'matched' => $matched ) ) );
		return array( 'matched' => $matched, 'status' => $matched ? 404 : null, 'collision' => $collision );
	}

	/**
	 * The posts that live at the decoy's own path, by the two readings the
	 * collision check uses: the post that carries the path as its slug, and
	 * what WordPress routes the address alone to.
	 *
	 * @return int[]
	 */
	private static function content_at_path(): array {
		$report = self::report();
		$found  = array( url_to_postid( $report['url'] ) );
		$post   = get_page_by_path( $report['slug'], OBJECT, get_post_types( array( 'public' => true ) ) );

		if ( $post instanceof \WP_Post ) {
			$found[] = (int) $post->ID;
		}

		return array_values( array_filter( array_map( 'intval', $found ) ) );
	}

	/** Whether the main query is showing the post that lives at the decoy's path. */
	private static function shows_content_at_path( \WP_Query $query ): bool {
		if ( $query->is_404() || ! $query->have_posts() || ! $query->is_singular() ) {
			return false;
		}

		return in_array( (int) $query->get_queried_object_id(), self::content_at_path(), true );
	}

	/** Called only when WordPress receives the request; edge caches can bypass PHP. */
	public static function route(): void {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared as a path only; never stored or echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		if ( ! self::matches( $uri ) ) { return; }
		// Content published at the path after the decoy was saved is real:
		// it is shown, and a visit to it is not a probe. Forced to 404, the
		// post was unreachable and every reader raised a critical alert.
		// Only that post stands the decoy down. WordPress lets a query
		// parameter outrank the address, so "the query found a post" said
		// nothing about the path: `?name=` with any published slug found one.
		global $wp_query;
		if ( $wp_query instanceof \WP_Query && self::shows_content_at_path( $wp_query ) ) { return; }
		// One site-wide report per minute bounds anonymous mail/log amplification.
		// Query parameters, cookies and user-agent strings cannot exempt a probe.
		if ( Claim::claim( 'canary_page:touch', MINUTE_IN_SECONDS ) ) {
			Writer::instance()->record( 'canary_page_touched', Writer::SEVERITY_CRITICAL, array( 'object_type' => 'decoy_page', 'context' => array( 'meaning' => 'decoy_requested_not_proof_of_compromise' ) ) );
		}
		$wp_query->set_404();
		$wp_query->posts = array();
		$wp_query->post = null;
		$wp_query->post_count = 0;
		remove_action( 'template_redirect', 'redirect_canonical' );
		status_header( 404 );
		nocache_headers();
		// Force the ordinary theme's 404, even if another query matched a post.
		add_filter( 'template_include', static function ( $template ) { return get_404_template() ?: __DIR__ . '/decoy-404.php'; }, PHP_INT_MAX );
	}
}
