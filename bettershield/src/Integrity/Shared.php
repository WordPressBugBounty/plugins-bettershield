<?php
/**
 * The file check on a network.
 *
 * Every site of a network runs the same core, plugins, themes and configuration
 * files, so one check answers for all of them: the main site's, in one pair of
 * tables, with one row and one alert for each change. A subsite reads that
 * answer and runs nothing. A plugin activated on one site alone keeps that
 * site's own check, because the main site may not have the plugin at all.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Shared {

	/** The tables one check keeps for the whole network. */
	public const TABLES = array( 'integrity_baseline', 'integrity_changes' );

	/** Whether this plugin runs across the network, so one check answers for it. */
	public static function applies(): bool {
		if ( ! is_multisite() || ! defined( 'BETTERSHIELD_FILE' ) ) {
			return false;
		}

		$active = get_site_option( 'active_sitewide_plugins', array() );

		return is_array( $active ) && isset( $active[ plugin_basename( BETTERSHIELD_FILE ) ] );
	}

	/** Whether this site reads the main site's check instead of running its own. */
	public static function elsewhere(): bool {
		return self::applies() && ! is_main_site();
	}

	/**
	 * An option the check keeps, from the site that runs it.
	 *
	 * @param mixed $fallback What to answer when it isn't there.
	 * @return mixed
	 */
	public static function option( string $name, $fallback = array() ) {
		return self::elsewhere() ? get_blog_option( (int) get_main_site_id(), $name, $fallback ) : get_option( $name, $fallback );
	}
}
