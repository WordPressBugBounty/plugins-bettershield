<?php
/**
 * Send plain-HTTP requests to the HTTPS address, in PHP (#1290).
 *
 * A site whose address is HTTPS still answers on http://: core's canonical
 * redirect compares host, path, port and query but never the scheme, and
 * only FORCE_SSL_ADMIN moves the sign-in page. A server rule would do it on
 * Apache alone and, written wrong, takes the whole site and its undo down
 * with it; a redirect in PHP behaves the same on every server and can only
 * ever affect the requests it answers.
 *
 * It answers GET and HEAD on the front end, the sign-in page, the dashboard
 * and the REST API. A POST has already sent its body in the clear, and a
 * redirect would drop it. The recovery link is never redirected: it has to
 * work when HTTPS does not.
 *
 * Temporary (302) for the first day, permanent (301) once that day passes,
 * because a browser keeps a 301 after the undo. After applying, the site
 * asks itself for its http:// front page and requires one redirect to the
 * same page over HTTPS that then answers 200; anything else, a loop
 * included, undoes it on the spot.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Hardening\Manager;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HttpsRedirect {

	public const ITEM = 'https_redirect';

	/** How long the redirect stays temporary before it becomes permanent. */
	public const REVIEW_SECONDS = DAY_IN_SECONDS;

	/** The query argument the recovery link arrives with, never redirected. */
	private const RECOVERY_ARG = 'bettershield_recovery';

	/** The self-check's own argument, and where its one-time token's hash waits. */
	private const PROBE_ARG = 'bettershield_redirect_probe';

	private const PROBE_TRANSIENT = 'bettershield_https_redirect_probe';

	/**
	 * Offered once the address is HTTPS, and not where every request reaches
	 * WordPress looking plain: behind a proxy that hides the encryption the
	 * redirect would send each request back to itself.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( Manager::instance()->is_active( self::ITEM ) ) {
			return array(
				'available' => true,
				'note'      => null,
			);
		}

		if ( ! Server::address_is_https() ) {
			return array(
				'available' => false,
				'reason'    => 'https',
				'note'      => HttpsAddress::needed_first(),
			);
		}

		// Not while the address switch is still waiting for Keep HTTPS: it
		// goes back to http on its own if nobody keeps it, and a redirect
		// applied in those five minutes would outlive it (#2282).
		if ( null !== HttpsAddress::pending_until() ) {
			return array(
				'available' => false,
				'reason'    => 'https',
				'note'      => __( 'The switch to HTTPS is still waiting for Keep HTTPS. Keep it first, then turn this on.', 'bettershield' ),
			);
		}

		$names = \BetterShield\Onboarding\Coexistence::doing( self::ITEM );

		if ( array() !== $names ) {
			return array(
				'available' => false,
				'reason'    => 'other_plugin',
				'note'      => sprintf(
					/* translators: %s: one or more plugin names. */
					__( '%s already redirects plain HTTP to HTTPS, so this stays off.', 'bettershield' ),
					implode( ', ', $names )
				),
			);
		}

		if ( Server::tls_terminates_upstream() ) {
			return array(
				'available' => false,
				'reason'    => 'server_config',
				'note'      => __( 'This request reached WordPress as plain HTTP. Open the dashboard over HTTPS to apply this. If it already is, a proxy hides the encryption, and a redirect would loop.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/** Another plugin already redirecting, named, or null. */
	public static function conflict(): ?string {
		$names = \BetterShield\Onboarding\Coexistence::doing( self::ITEM );

		if ( array() === $names ) {
			return null;
		}

		return sprintf(
			/* translators: %s: one or more plugin names. */
			__( '%s already redirects plain HTTP to HTTPS. Leave it to one of them.', 'bettershield' ),
			wp_sprintf( '%l', $names )
		);
	}

	/**
	 * Turn it on, then prove it: the http:// front page must answer one
	 * redirect to itself over HTTPS, which must answer 200. Refused, with
	 * the reason, when it does not; the manager then closes the ledger row.
	 *
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		unset( $options );

		$problem = self::probe();

		if ( null !== $problem ) {
			return new \WP_Error( 'bettershield_https_redirect_failed', $problem );
		}

		return array(
			'tokens' => array(),
			'notes'  => array(
				__( 'Temporary for a day, then permanent. Undo within the day leaves no trace in browsers.', 'bettershield' ),
			),
		);
	}

	/**
	 * What the site's own http:// front page answers, checked as a browser
	 * would follow it: null when it is one redirect to the same page over
	 * HTTPS that answers 200, or why not.
	 *
	 * The redirect is attached for the requests it asks, so the answer is the
	 * one visitors will get; nothing else on this site changes until the
	 * manager records it on.
	 */
	public static function probe(): ?string {
		/**
		 * Short-circuits the self-check, for a host that cannot reach
		 * itself over plain HTTP from PHP and for the tests: null or a
		 * reason, as probe() answers.
		 *
		 * @param string|null|false $pre False to run the check.
		 */
		$pre = apply_filters( 'bettershield_pre_https_redirect_probe', false );

		if ( false !== $pre ) {
			return is_string( $pre ) ? $pre : null;
		}

		$http  = set_url_scheme( home_url( '/' ), 'http' );
		$https = set_url_scheme( home_url( '/' ), 'https' );
		$token = wp_generate_password( 32, false );

		// The item is not on yet, so the request carries a one-time token
		// that turns the redirect on for that request alone.
		set_transient( self::PROBE_TRANSIENT, hash( 'sha256', $token ), MINUTE_IN_SECONDS );

		// The token stays until both requests are answered: the HTTPS one
		// carries it too, and has to meet the redirect switched on. Gone
		// before it, a proxy that hides the encryption (is_ssl() false on
		// every request) answered 200 and the loop it makes passed (#2282).
		try {
			return self::follow( $token, $http, $https );
		} finally {
			delete_transient( self::PROBE_TRANSIENT );
		}
	}

	/**
	 * The self-check's two requests, while the one-time token waits.
	 */
	private static function follow( string $token, string $http, string $https ): ?string {
		// Through the plugin's own gate, held to this site's host.
		$first = \BetterShield\Support\Http::same_site_at(
			add_query_arg( self::PROBE_ARG, $token, $http ),
			array( 'headers' => array( 'Cache-Control' => 'no-cache' ) )
		);

		if ( is_wp_error( $first ) ) {
			return __( 'The site did not answer over plain HTTP, so the redirect could not be checked. Nothing was changed.', 'bettershield' );
		}

		$code     = (int) wp_remote_retrieve_response_code( $first );
		$location = (string) wp_remote_retrieve_header( $first, 'location' );

		if ( ! in_array( $code, array( 301, 302 ), true ) || ! str_starts_with( $location, $https ) ) {
			return __( 'Plain HTTP did not answer with a redirect to HTTPS, so something in front of WordPress answers it. Nothing was changed.', 'bettershield' );
		}

		$second = \BetterShield\Support\Http::same_site_at( $location, array( 'headers' => array( 'Cache-Control' => 'no-cache' ) ) );

		if ( is_wp_error( $second ) ) {
			return __( 'The HTTPS address the redirect leads to did not answer with a trusted certificate. Nothing was changed.', 'bettershield' );
		}

		if ( 200 !== (int) wp_remote_retrieve_response_code( $second ) ) {
			return __( 'The HTTPS address answered with another redirect or an error, which would loop. Nothing was changed.', 'bettershield' );
		}

		return null;
	}

	/**
	 * Registered from the plugin's own load: the self-check's request is
	 * redirected before the item is on. Costs one query-argument lookup.
	 */
	public static function register_early(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the argument carries its own one-time token, checked against a stored hash.
		if ( isset( $_GET[ self::PROBE_ARG ] ) ) {
			add_action( 'init', array( self::class, 'probed' ), 1 );
		}
	}

	/**
	 * Redirect the self-check's request, when its token is the one waiting.
	 */
	public static function probed(): void {
		$stored = get_transient( self::PROBE_TRANSIENT );
		$token  = isset( $_GET[ self::PROBE_ARG ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ self::PROBE_ARG ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checked against the stored hash below.

		if ( is_string( $stored ) && '' !== $token && hash_equals( $stored, hash( 'sha256', $token ) ) ) {
			self::redirect();
		}
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		add_action( 'init', array( self::class, 'redirect' ), 1 );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_action( 'init', array( self::class, 'redirect' ), 1 );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'init', array( self::class, 'redirect' ) );
	}

	/**
	 * Send this request to the same address over HTTPS, when it is one this
	 * answers.
	 */
	public static function redirect(): void {
		$target = self::target();

		if ( null === $target ) {
			return;
		}

		wp_redirect( $target, self::status() ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the site's own host, from its stored address.
		exit;
	}

	/**
	 * Where this request goes over HTTPS, or null when it is not redirected:
	 * the stored address is no longer HTTPS, already secure, not GET or
	 * HEAD, the command line or the scheduler, or the recovery link.
	 */
	public static function target(): ?string {
		// The address going back to http (not kept, a recovery, an undo, or
		// a change under Settings › General) means HTTPS is not to be
		// trusted here: sending every visitor to it, and soon with a 301
		// browsers keep, would take the site down with it (#2282).
		if ( 'https' !== wp_parse_url( (string) get_option( 'home' ), PHP_URL_SCHEME ) ) {
			return null;
		}

		if ( is_ssl() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return null;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';

		if ( ! in_array( $method, array( 'GET', 'HEAD' ), true ) ) {
			return null;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only its presence is read, to leave the recovery link alone.
		if ( isset( $_GET[ self::RECOVERY_ARG ] ) ) {
			return null;
		}

		// The host and port from the stored address, never from the request:
		// a forged Host header must not turn this into an open redirect.
		$home = wp_parse_url( home_url() );
		$host = (string) ( $home['host'] ?? '' );

		if ( '' === $host ) {
			return null;
		}

		$port = isset( $home['port'] ) ? ':' . (int) $home['port'] : '';
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( (string) $_SERVER['REQUEST_URI'] ) : '/'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a path sent back to the same host, escaped by wp_redirect().

		return 'https://' . $host . $port . ( str_starts_with( $uri, '/' ) ? $uri : '/' . $uri );
	}

	/** 302 for the first day after it was applied, 301 after. */
	public static function status(): int {
		$applied = strtotime( (string) ( Manager::instance()->item_state( self::ITEM )['applied_at'] ?? '' ) );

		return false !== $applied && time() - $applied >= self::REVIEW_SECONDS ? 301 : 302;
	}

	/**
	 * The card's one line while the item is on.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		unset( $state );

		return 301 === self::status()
			? __( 'Plain HTTP is redirected to HTTPS permanently.', 'bettershield' )
			: __( 'Plain HTTP is redirected to HTTPS, temporarily for the first day.', 'bettershield' );
	}
}
