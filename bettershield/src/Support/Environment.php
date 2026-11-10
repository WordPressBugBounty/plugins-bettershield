<?php
/**
 * Is this a live site, or someone's laptop?
 *
 * Two findings mean different things depending on the answer. Serving a login
 * page over plain HTTP is a present-tense exposure on a production site and
 * completely normal on a development one; the same is true of printing debug
 * output. Grading both the same way means either crying wolf on every local
 * install or staying quiet about a real problem on a live one.
 *
 * The answer is derived, never asked for, and never involves a network call.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Environment {

	/**
	 * Host names that are local by definition.
	 */
	private const LOCAL_HOSTS = array( 'localhost', '127.0.0.1', '::1' );

	/**
	 * Suffixes reserved for local and test use. `.local` is what most local
	 * development tooling issues by default.
	 */
	private const LOCAL_SUFFIXES = array( '.local', '.test', '.localhost', '.example', '.invalid' );

	/**
	 * Treat the site as live unless something says otherwise.
	 *
	 * Defaulting to production is the safe direction: mistaking a live site for
	 * a laptop would quietly downgrade a real finding, while the reverse only
	 * over-reports on a machine nobody can reach.
	 */
	public static function is_production(): bool {
		$host       = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$production = 'production' === wp_get_environment_type() && ! self::is_local_host( $host );

		/**
		 * Filters whether the site is treated as live.
		 *
		 * Useful where the derived answer is wrong: an internal production site
		 * on a private address, or a public staging site that should be graded
		 * gently.
		 *
		 * @param bool $production Whether the site is treated as production.
		 */
		return (bool) apply_filters( 'bettershield_is_production', $production );
	}

	/**
	 * Whether a host name is one nobody outside the machine or network can
	 * reach.
	 *
	 * wp_get_environment_type() answers 'production' whenever nothing has set
	 * WP_ENVIRONMENT_TYPE, which is the common case on local installs — so the
	 * host name has to be read as well before believing it.
	 *
	 * Public and taking the host as an argument so it can be exercised
	 * directly: wp_get_environment_type() caches its answer for the process,
	 * which means a test cannot reach this branch through is_production().
	 */
	public static function is_local_host( string $host ): bool {
		$host = strtolower( $host );

		if ( '' === $host ) {
			return false;
		}

		if ( in_array( $host, self::LOCAL_HOSTS, true ) ) {
			return true;
		}

		foreach ( self::LOCAL_SUFFIXES as $suffix ) {
			if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
				return true;
			}
		}

		// A private or reserved address is not reachable from the internet.
		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return ! filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		}

		return false;
	}
}
