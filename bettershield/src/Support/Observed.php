<?php
/**
 * Facts about the site that only a web request can see.
 *
 * Two audit checks used to read the PHP process they happened to be running
 * in. Run the audit from WP-CLI and it answered about the CLI binary; run it
 * from cron and it answered about the web one. On a host where those differ —
 * common, and the reason `php -v` on a server so often surprises people — the
 * same site produced two scores in the same minute, and neither was wrong from
 * where it stood.
 *
 * So the answer is taken where it is true, and remembered. A web request
 * records what it can see; the checks read the record, whatever they are
 * running under. Until a web request has happened there is nothing recorded,
 * and the checks fall back to the running process, which is the old behavior
 * and the best available.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Login\Protection;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Observed {

	private const OPTION = 'bettershield_observed';

	/**
	 * Holds the write while an answer is moving. Not the read: a record that
	 * has settled costs one option read and nothing else, which is the steady
	 * state this is protecting.
	 */
	private const RECENT = 'bettershield_observed_recent';

	/**
	 * Record what this request can see, if this request can see anything.
	 *
	 * Cheap and idempotent: one option read, and a write only when the answer
	 * actually changed — a version does not change between page views, so the
	 * steady state is a read and nothing else.
	 */
	public static function record(): void {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() || wp_doing_ajax() ) {
			return;
		}

		/*
		 * Being in the admin is not being a person on a screen. admin-ajax.php
		 * and admin-post.php both define WP_ADMIN before WordPress loads, and
		 * the second answers requests carrying no session at all — so without
		 * the second condition anybody on the internet decides what this record
		 * says, one uncached option write at a time, simply by choosing which
		 * headers to send. The caller keeps this to screens for the same
		 * reason; the guard is repeated here so a future caller cannot
		 * reintroduce either cost by accident.
		 */
		if ( ! is_admin() || ! is_user_logged_in() ) {
			return;
		}

		$stored = get_option( self::OPTION );
		$stored = is_array( $stored ) ? $stored : array();

		$proxies    = Protection::trusted_proxies();
		$cloudflare = Protection::cloudflare();

		// Whether a real request can be attributed to a client at all. The audit
		// cannot ask this for itself: under WP-CLI there is no connecting
		// address, and from a cron tick the address is the loopback, so the
		// answer would depend on which request happened to run the audit — the
		// same inconsistency this class exists to remove for the PHP version.
		$resolved = ClientIp::resolve( $proxies, $cloudflare );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against the named ranges only, never stored.
		$remote      = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$named_proxy = ClientIp::named_proxy_without_header( $resolved, $remote, $proxies );
		$no_visitor  = ClientIp::named_proxy_without_visitor( $resolved, $remote, $proxies );

		/*
		 * What the two client answers are derived from, besides the request
		 * itself. They are kept worst-first below, and a worst-first answer
		 * with no way back would report a site as unable to attribute requests
		 * forever — including after the owner did the one thing the finding
		 * asks of them. Changing what the answer is derived from is what starts
		 * the record over.
		 */
		$basis = md5( (string) wp_json_encode( array( $proxies, $cloudflare ) ) );
		$same  = $basis === ( $stored['basis'] ?? '' );

		/*
		 * Worst wins. One request in ten arriving with a header nothing
		 * vouches for still means this site cannot attribute one request in
		 * ten, and lockouts are only as good as the worst of them. Keeping
		 * whatever the most recent screen load happened to see made the
		 * finding appear and disappear as somebody clicked around.
		 */
		$now = array(
			'php_version'     => PHP_VERSION,
			'client_resolved' => $same
				? ( (bool) ( $stored['client_resolved'] ?? true ) && (bool) $resolved['confident'] )
				: (bool) $resolved['confident'],
			'ignored_headers' => $same
				? ( (bool) ( $stored['ignored_headers'] ?? false ) || (bool) $resolved['ignored_headers'] )
				: (bool) $resolved['ignored_headers'],
			// Which of the two reasons it was, when it was not the headers:
			// the named proxy sending none, or an address nothing names.
			'named_proxy'     => $same
				? ( (bool) ( $stored['named_proxy'] ?? false ) || $named_proxy )
				: $named_proxy,
			// And when it was the headers, whether they came from the named
			// proxy and named nobody usable rather than from nothing named.
			'named_proxy_no_visitor' => $same
				? ( (bool) ( $stored['named_proxy_no_visitor'] ?? false ) || $no_visitor )
				: $no_visitor,
			// Whether a request came from Cloudflare's published ranges while
			// the owner has not said the site is behind it: read from the
			// connection, never from a header, so the proxy panel can offer
			// that one setting (#2205). Kept worst-first like the rest.
			'cloudflare_seen' => $same
				? ( (bool) ( $stored['cloudflare_seen'] ?? false ) || ClientIp::METHOD_CLOUDFLARE_UNCONFIRMED === $resolved['method'] )
				: ClientIp::METHOD_CLOUDFLARE_UNCONFIRMED === $resolved['method'],
			'basis'           => $basis,
			/*
			 * Whether PHP prints errors into the page, as this page is served:
			 * after WordPress applied its debug constants. With WP_DEBUG off
			 * core leaves the server's own setting alone, and the audit's
			 * process — cron, WP-CLI — often has a different one.
			 */
			'display_errors'  => \BetterShield\Audit\Checks::display_errors_prints( (string) ini_get( 'display_errors' ) ),
			'recorded_at'     => gmdate( 'c' ),
		);

		if ( ( $stored['php_version'] ?? '' ) === $now['php_version']
			&& ( $stored['client_resolved'] ?? null ) === $now['client_resolved']
			&& ( $stored['ignored_headers'] ?? null ) === $now['ignored_headers']
			&& ( $stored['named_proxy'] ?? null ) === $now['named_proxy']
			&& ( $stored['named_proxy_no_visitor'] ?? null ) === $now['named_proxy_no_visitor']
			&& ( $stored['cloudflare_seen'] ?? null ) === $now['cloudflare_seen']
			&& ( $stored['display_errors'] ?? null ) === $now['display_errors']
			&& $same ) {
			return;
		}

		/*
		 * At most one write a minute. A dashboard left open re-runs this on
		 * every screen, and an answer that genuinely differs between two of
		 * them would otherwise cost an uncached option write on each — while
		 * saying nothing the audit reads any sooner.
		 */
		if ( false !== get_transient( self::RECENT ) ) {
			return;
		}

		set_transient( self::RECENT, 1, MINUTE_IN_SECONDS );

		update_option( self::OPTION, $now, false );
	}

	/**
	 * Whether the last real web request could be attributed to a client.
	 *
	 * Null when nothing has been recorded yet, which is not the same as false:
	 * a site nobody has opened the dashboard on has not been observed, and
	 * saying "lockouts are not running" on that basis would be a guess.
	 *
	 * @return array{resolved: bool, ignored_headers: bool, named_proxy: bool, named_proxy_no_visitor: bool, cloudflare_seen: bool, current: bool}|null
	 */
	public static function client_resolution(): ?array {
		$stored = get_option( self::OPTION );

		if ( ! is_array( $stored ) || ! array_key_exists( 'client_resolved', $stored ) ) {
			return null;
		}

		return array(
			'resolved'        => (bool) $stored['client_resolved'],
			'ignored_headers' => (bool) ( $stored['ignored_headers'] ?? false ),
			'named_proxy'     => (bool) ( $stored['named_proxy'] ?? false ),
			'named_proxy_no_visitor' => (bool) ( $stored['named_proxy_no_visitor'] ?? false ),
			'cloudflare_seen' => (bool) ( $stored['cloudflare_seen'] ?? false ),
			// Whether the record was made under the proxy settings in force
			// now. Until a request is seen after a change, it describes the
			// settings before it, and nothing is fixed on its say-so.
			'current'         => md5( (string) wp_json_encode( array( Protection::trusted_proxies(), Protection::cloudflare() ) ) ) === ( $stored['basis'] ?? '' ),
		);
	}

	/**
	 * Whether the site's own pages are served with PHP printing errors.
	 *
	 * Null when no page has been observed yet, which is not "off".
	 */
	public static function display_errors(): ?bool {
		$stored = get_option( self::OPTION );

		if ( ! is_array( $stored ) || ! array_key_exists( 'display_errors', $stored ) ) {
			return null;
		}

		return (bool) $stored['display_errors'];
	}

	/**
	 * The PHP version the site actually serves pages with.
	 */
	public static function php_version(): string {
		$stored = get_option( self::OPTION );

		if ( is_array( $stored ) && ! empty( $stored['php_version'] ) ) {
			return (string) $stored['php_version'];
		}

		return PHP_VERSION;
	}
}
