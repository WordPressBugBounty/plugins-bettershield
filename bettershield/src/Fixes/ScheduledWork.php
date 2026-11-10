<?php
/**
 * Fix for "Scheduled work has stopped running" (#2209).
 *
 * Try now asks the site to run its own schedule through core's
 * non-blocking spawner, inside the runner's five-minute claim, and never
 * runs a task in the request: a stalled site can have a long backlog. Where
 * it stays stalled, the panel says whether WordPress's own trigger is off and
 * gives the system cron line a host runs every five minutes.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Cron\Runner;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScheduledWork {

	/**
	 * What the panel shows: how far behind the schedule is, whether
	 * WordPress's own trigger is off, and how a host would run it.
	 *
	 * @return array{overdue: int, behind_seconds: int, disabled: bool, cron_url: string, command: string, exact: bool, url_command: string}
	 */
	public static function state(): array {
		$lag  = Runner::schedule_lag();
		$url  = site_url( 'wp-cron.php' );
		$php  = self::php();
		$path = untrailingslashit( ABSPATH );

		return array(
			'overdue'        => (int) $lag['overdue'],
			'behind_seconds' => (int) $lag['behind_seconds'],
			'disabled'       => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'cron_url'       => $url,
			// Run by the host's own PHP where it can be named for certain;
			// otherwise the same line with the part to fill in said plainly.
			'command'        => '*/5 * * * * cd ' . escapeshellarg( $path ) . ' && ' . ( '' !== $php ? escapeshellarg( $php ) : '/path/to/php' ) . ' wp-cron.php > /dev/null 2>&1',
			'exact'          => '' !== $php,
			'url_command'    => '*/5 * * * * curl -s ' . escapeshellarg( $url ) . ' > /dev/null 2>&1',
		);
	}

	/**
	 * Ask the site to run its schedule now, and say what came of it.
	 *
	 * @return array{result: string, state: array<string, mixed>}
	 */
	public static function try_now(): array {
		return array(
			'result' => Runner::instance()->try_rescue(),
			'state'  => self::state(),
		);
	}

	/**
	 * The PHP that runs this request, where it is a command-line PHP that a
	 * crontab could call. A web server's PHP (php-fpm, an Apache module) is
	 * not, and is never offered.
	 */
	private static function php(): string {
		$binary = defined( 'PHP_BINARY' ) ? (string) PHP_BINARY : '';

		if ( '' === $binary || 1 !== preg_match( '/^php(?:\d+(?:\.\d+)*)?$/', basename( $binary ) ) || ! @is_executable( $binary ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir may hide it, which reads as "cannot name it".
			return '';
		}

		return $binary;
	}
}
