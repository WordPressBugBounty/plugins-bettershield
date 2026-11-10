<?php
/**
 * Which web server is in front of PHP, and does it read .htaccess?
 *
 * Several hardening items are conventionally applied through .htaccess. That
 * file does nothing on nginx or IIS, so an item that wrote it there and
 * reported success would be claiming a protection the site does not have.
 * Every such item asks here first and says what it found.
 *
 * The answer is derived from what the server tells PHP about itself, never
 * from a network request.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Server {

	public const APACHE    = 'apache';
	public const LITESPEED = 'litespeed';
	public const NGINX     = 'nginx';
	public const IIS       = 'iis';
	public const UNKNOWN   = 'unknown';

	/**
	 * The server family, from the SERVER_SOFTWARE header PHP receives.
	 *
	 * Core sets $is_apache, $is_nginx and $is_IIS from the same string, but
	 * folds LiteSpeed into Apache and settles them once at load time; reading
	 * the string here keeps the answer testable and LiteSpeed distinguishable
	 * for the copy.
	 */
	public static function kind( ?string $software = null ): string {
		if ( null === $software ) {
			$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against fixed tokens only.
		}

		$software = strtolower( $software );

		if ( '' === $software ) {
			return self::UNKNOWN;
		}

		if ( str_contains( $software, 'litespeed' ) ) {
			return self::LITESPEED;
		}

		if ( str_contains( $software, 'apache' ) ) {
			return self::APACHE;
		}

		if ( str_contains( $software, 'nginx' ) ) {
			return self::NGINX;
		}

		if ( str_contains( $software, 'microsoft-iis' ) ) {
			return self::IIS;
		}

		return self::UNKNOWN;
	}

	/**
	 * Whether the server reads .htaccess at all.
	 *
	 * Null means "not knowable from here": an unrecognized server string.
	 * Apache and LiteSpeed answer true even though an AllowOverride None
	 * would make them ignore the file — that setting is not visible from
	 * PHP, so the writing items add their own "not confirmed" note whenever
	 * pretty permalinks give no evidence the file is processed. Callers
	 * treat null as "probe before claiming", never as yes.
	 */
	public static function honors_htaccess( ?string $software = null ): ?bool {
		switch ( self::kind( $software ) ) {
			case self::APACHE:
			case self::LITESPEED:
				return true;

			case self::NGINX:
			case self::IIS:
				return false;
		}

		return null;
	}

	/**
	 * Whether the server reads RedirectMatch from .htaccess — Apache's
	 * mod_alias, which is what the uploads, sensitive-files and quarantine
	 * rules are written in. Apache does. OpenLiteSpeed reads only rewrite
	 * rules from the file and skips the rest without an error; LiteSpeed's
	 * paid edition reads them, and both can report themselves as plain
	 * "LiteSpeed". So a LiteSpeed that does not name its edition cannot be
	 * confirmed either way, and one that names itself OpenLiteSpeed is a no.
	 */
	public static function honors_redirect_rules( ?string $software = null ): ?bool {
		if ( null === $software ) {
			$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against fixed tokens only.
		}

		if ( self::LITESPEED === self::kind( $software ) ) {
			return str_contains( strtolower( $software ), 'openlitespeed' ) ? false : null;
		}

		return self::honors_htaccess( $software );
	}

	/**
	 * Whether the server is one that can process rewrite rules at all.
	 *
	 * A question about the server, not about the site: core's answer is
	 * mod_rewrite being loaded, or the server being one whose configuration
	 * carries rewriting instead. It never reads `permalink_structure`, so
	 * nothing built on this answer may say anything about permalinks — a
	 * sentence that did was stating a fact about the site nothing had
	 * measured.
	 *
	 * It is also generous: `got_mod_rewrite()` defaults to true when the
	 * module list cannot be read, which is most hosts. Callers use it to
	 * withhold a claim, never to make one.
	 *
	 * Core's answer lives in `got_url_rewrite()`, which is defined in
	 * `wp-admin/includes/misc.php` — a file WordPress loads for admin screens
	 * and NOT for REST requests. Calling it directly fataled every apply of the
	 * two hardening items that ask, because the dashboard applies them over
	 * REST: an admin-only function reached from a non-admin request.
	 *
	 * Loading the file on demand keeps core's definition as the single answer
	 * rather than reimplementing it here and drifting from it.
	 */
	public static function supports_url_rewrite(): bool {
		if ( ! function_exists( 'got_url_rewrite' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		return (bool) got_url_rewrite();
	}

	/**
	 * Whether this request arrived over an encrypted connection.
	 *
	 * is_ssl() reads $_SERVER alone — HTTPS and SERVER_PORT, never
	 * X-Forwarded-Proto — so a site whose encryption ends at a proxy or load
	 * balancer answers false on every request unless wp-config.php sets
	 * $_SERVER['HTTPS'] itself. Named here so the three places that condition
	 * behavior on it read the same answer and can be told apart from the
	 * address below.
	 */
	public static function connection_is_https(): bool {
		return is_ssl();
	}

	/**
	 * Whether the address this site hands out is https.
	 *
	 * A stored setting, not an observation: it says what visitors are sent to,
	 * and nothing about how the current request arrived.
	 */
	public static function address_is_https(): bool {
		return 'https' === strtolower( (string) wp_parse_url( home_url(), PHP_URL_SCHEME ) );
	}

	/**
	 * Whether encryption ends somewhere in front of PHP.
	 *
	 * The two answers above disagreeing is knowable, and it is the case that
	 * silently breaks anything conditioned on is_ssl(): a secure cookie flag
	 * that never gets set, a header that never gets sent. Callers say so
	 * rather than reporting a success the site did not get.
	 */
	public static function tls_terminates_upstream(): bool {
		return self::address_is_https() && ! self::connection_is_https();
	}

	/**
	 * A short label for the copy: "Apache", "nginx", and so on.
	 */
	public static function label( ?string $software = null ): string {
		switch ( self::kind( $software ) ) {
			case self::APACHE:
				return 'Apache';
			case self::LITESPEED:
				return 'LiteSpeed';
			case self::NGINX:
				return 'nginx';
			case self::IIS:
				return 'IIS';
		}

		return __( 'an unrecognized server', 'bettershield' );
	}
}
