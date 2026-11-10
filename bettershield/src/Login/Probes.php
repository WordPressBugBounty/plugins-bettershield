<?php
/**
 * Requests for pages that do not exist, counted per source (#690).
 *
 * A scanner works through a word list — `/.env`, `/wp-config.php.bak`,
 * `/adminer.php`, `/?author=1` — and every miss lands in a 404 nobody reads.
 * This counts those misses per source as one more request-protection surface,
 * under the same rules the forms keep: off until the owner turns it on and
 * picks a number, stood down by safe mode, an address nothing vouched for
 * recorded and never closed, an allowlisted one not counted at all, and a
 * total nobody else's surface can read.
 *
 * Three choices keep it from catching the wrong people:
 *
 * - **Distinct paths, not hits.** A broken image on a theme is a 404 on every
 *   page view of every reader; counted per hit it would close the site to its
 *   own audience. One source asking for the same missing path again counts
 *   once in the window.
 * - **A known probe counts in full on the first hit.** Nobody reaches a
 *   configuration backup or a migration installer by following a link, so a
 *   request for one closes the surface at once, as a firewall's hard fail
 *   does.
 * - **Closed means a plain 404, and nothing more.** Only a page that was
 *   missing anyway is answered differently — without the theme. Every page
 *   that exists keeps loading for that source, and nothing goes to the server
 *   firewall or the edge, where a crawler caught after a site move would lose
 *   the whole site.
 *
 * The count is written at shutdown, after the page has been sent, so a
 * visitor never waits on it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Audit\ExposedArtifacts;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Probes {

	/** What a numbered author archive is recorded as when it is probed for. */
	public const AUTHOR = '?author=';

	/**
	 * Names nobody reaches by following a link, beside the configuration
	 * backups and leftover tools the audit already asks about.
	 */
	private const KNOWN = array( '.env', 'database.sql', 'backup.sql', 'debug.log' );

	private static ?Probes $instance = null;

	/**
	 * The miss waiting to be counted at shutdown, if any.
	 *
	 * @var array{source: array, subject: string, known: bool}|null
	 */
	private ?array $pending = null;

	public static function instance(): Probes {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Last, after core's canonical redirect has had its chance to send a
		// mistyped address somewhere real: only what is still a 404 counts.
		add_action( 'template_redirect', array( $this, 'on_missing' ), 9999, 0 );
	}

	/**
	 * Whether the surface is on: protection on, safe mode off, the surfaces
	 * migration landed, and the owner turned this one on.
	 */
	public static function armed(): bool {
		$settings = Protection::instance()->settings();

		if ( ! $settings['enabled'] || SafeMode::is_active() || ! Gate::surfaced() ) {
			return false;
		}

		return (bool) Protection::instance()->surface_policy( Surfaces::PROBE )['enabled'];
	}

	/**
	 * A front-end request WordPress answered with a 404.
	 */
	public function on_missing(): void {
		if ( ! is_404() || is_user_logged_in() || ! self::armed() ) {
			return;
		}

		// Closed to this source: the page was missing anyway, so it is
		// answered without the theme, and not counted again while closed.
		if ( Gate::closed( Surfaces::PROBE, $this->source() ) ) {
			self::bare_404();
		}

		$this->note_miss( self::path() );
	}

	/**
	 * Hold one missing path for counting at shutdown: a known probe in full,
	 * anything else once per window.
	 */
	public function note_miss( string $path ): void {
		$known = self::known( $path );

		/*
		 * A missing image, stylesheet or script is the page's own request,
		 * not the visitor's question: a post with twenty broken uploads
		 * closed every reader, and the image crawler, in one page view.
		 */
		if ( ! $known && self::is_asset( $path ) ) {
			return;
		}

		$this->later( $this->source(), $path, $known );
	}

	/** File types a page fetches for itself. */
	private const ASSETS = array( 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp', 'css', 'js', 'mjs', 'map', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp4', 'webm', 'mp3', 'json' );

	/** Whether a path names a file a page loads for itself. */
	public static function is_asset( string $path ): bool {
		$extension = strtolower( (string) pathinfo( $path, PATHINFO_EXTENSION ) );

		return '' !== $extension && in_array( $extension, self::ASSETS, true );
	}

	/**
	 * A numbered author archive, refused by "Username privacy" before
	 * it was ever a 404: the same scanner's first question, counted as a known
	 * probe where it is already caught.
	 */
	public function note_author_probe(): void {
		// With plain permalinks ?author=N is the address a theme's byline
		// links to, so a reader following one is not a scanner.
		if ( is_user_logged_in() || ! self::armed() || '' === (string) get_option( 'permalink_structure' ) ) {
			return;
		}

		$this->later( $this->source(), self::AUTHOR, true );
	}

	/**
	 * Hold the miss for shutdown. One per request: a request is one question.
	 *
	 * @param array{ip: string, method: string, confident: bool} $source
	 */
	private function later( array $source, string $subject, bool $known ): void {
		if ( null !== $this->pending ) {
			return;
		}

		$this->pending = array(
			'source'  => $source,
			'subject' => $subject,
			'known'   => $known,
		);

		add_action( 'shutdown', array( $this, 'count' ), 0, 0 );
	}

	/**
	 * Count the held miss, once per distinct path in the window. Public for
	 * the shutdown hook.
	 */
	public function count(): void {
		$pending       = $this->pending;
		$this->pending = null;

		/*
		 * An address this site cannot verify is never closed, so counting it
		 * only cost a database write for every random path anybody asked
		 * for, with nothing to show for it.
		 */
		if ( null === $pending || '' === $pending['source']['ip'] || empty( $pending['source']['confident'] ) ) {
			return;
		}

		$policy = Protection::instance()->surface_policy( Surfaces::PROBE );

		if ( $pending['known'] ) {
			// Counted in full: the threshold is this one request.
			$policy['threshold'] = 1;
		} else {
			$hmac  = ClientIp::lockout_hmac( $pending['source'] );
			$since = Time::stamp( time() - $policy['window_minutes'] * 60 );

			if ( Gate::counted( Surfaces::PROBE, $hmac, $pending['subject'], $since ) ) {
				return;
			}
		}

		Gate::note_failure( Surfaces::PROBE, $pending['source'], $policy, $pending['subject'] );
	}

	/**
	 * Whether a path is one only a scanner asks for.
	 */
	public static function known( string $path ): bool {
		$path = strtolower( ltrim( $path, '/' ) );

		if ( '' === $path ) {
			return false;
		}

		if ( str_starts_with( $path, '.git/' ) || str_contains( $path, '/.git/' ) ) {
			return true;
		}

		$name = basename( $path );

		return in_array( $name, self::KNOWN, true )
			|| isset( ExposedArtifacts::CONFIG_BACKUPS[ $name ] )
			|| isset( ExposedArtifacts::TOOLS[ $name ] );
	}

	/**
	 * The path asked for, without its query, as it is recorded: clipped to the
	 * column it is stored in, and never the query string, which can carry
	 * anything.
	 */
	public static function path(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- reduced to a path and clipped below; never echoed.
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = '' === $path ? '/' : sanitize_text_field( rawurldecode( $path ) );

		return Text::clip( $path, 60 );
	}

	/** @return array{ip: string, method: string, confident: bool, paired_with: ?string} */
	private function source(): array {
		$settings = Protection::instance()->settings();

		return ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );
	}

	/**
	 * A plain 404, sent instead of the theme's.
	 */
	private static function bare_404(): void {
		status_header( 404 );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html__( 'Not found.', 'bettershield' );
		exit;
	}
}
