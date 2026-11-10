<?php
/**
 * The report-a-problem block: everything a support thread needs to know
 * about how this plugin is set up here, and nothing that identifies the site
 * or anyone on it.
 *
 * Assembled locally and handed to the owner as text to paste. Nothing is
 * sent anywhere by this plugin — the owner decides where it goes, and reads
 * it before it goes there.
 *
 * The line that matters most is the one about what is left out. No URL, no
 * email address, no username, no IP address or address digest, no key, no
 * token, no hash, no file contents. Plugin and theme names are included:
 * a conflict hunt is the commonest reason for a support thread, and a
 * report that cannot say what else is installed cannot help with one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

use BetterShield\Abilities\Registrar;
use BetterShield\Alerts\Settings as AlertSettings;
use BetterShield\Audit\Auditor;
use BetterShield\Database\Schema;
use BetterShield\Hardening\Manager;
use BetterShield\Login\Protection;
use BetterShield\Password\Policy;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Environment;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Diagnostics {

	/**
	 * Where a report goes, if the owner chooses to send it. A link, never a
	 * request — this report is never transmitted by the plugin, whatever else
	 * the plugin is allowed to contact.
	 */
	public const SUPPORT_URL = 'https://wordpress.org/support/plugin/bettershield/';

	/**
	 * Event types that mean something this plugin tried went wrong. These
	 * are what "recent errors" lists — the log already holds them, with the
	 * reason code and without anything a report must not carry.
	 */
	private const ERROR_TYPES = array(
		'hardening_failed',
		'hardening_revert_failed',
		'recovery_link_failed',
		'buffer_overflow',
	);

	/**
	 * The report as structured data.
	 *
	 * @return array<string, mixed>
	 */
	public static function report(): array {
		global $wp_version;

		$manager   = Manager::instance();
		$overview  = Auditor::overview();
		$login     = Protection::instance()->settings();
		$policy    = Policy::instance()->settings();
		$alerts    = AlertSettings::instance()->settings();
		$active    = array();
		$failed    = array();
		$available = array();

		/*
		 * One walk. `describe_all()` already reads each item's stored state
		 * and carries all three of these, so asking `item_state()` again for
		 * the first two read every item's row twice.
		 */
		foreach ( $manager->describe_all() as $item ) {
			if ( ! empty( $item['active'] ) ) {
				$active[] = $item['id'];
			}
			if ( ! empty( $item['revert_failed'] ) ) {
				$failed[] = $item['id'];
			}
			if ( ! $item['available'] ) {
				// With its cause: needing HTTPS or the main site is not a
				// server that cannot do it (#2235).
				$available[ $item['id'] ] = '' !== (string) ( $item['availability_reason'] ?? '' ) ? (string) $item['availability_reason'] : 'unknown';
			}
		}

		$by_severity = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		);
		foreach ( $overview['findings'] as $finding ) {
			if ( isset( $by_severity[ $finding['severity'] ] ) ) {
				++$by_severity[ $finding['severity'] ];
			}
		}

		return array(
			'generated_at'      => gmdate( 'c' ),
			'plugin'            => array(
				'version'        => defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '',
				'schema_version' => (int) get_option( 'bettershield_schema_version', 0 ),
			),
			'platform'          => array(
				'wordpress'        => (string) $wp_version,
				'multisite'        => is_multisite(),
				'php'              => PHP_VERSION,
				'server'           => Server::kind(),
				'htaccess_honored' => Server::honors_htaccess(),
				'environment_type' => function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'unknown',
				'graded_as'        => Environment::is_production() ? 'production' : 'development',
				'locale'           => get_locale(),
			),
			'safe_mode'         => array(
				'active' => SafeMode::is_active(),
				'until'  => null !== SafeMode::until() ? gmdate( 'c', SafeMode::until() ) : null,
			),
			'recovery_link'     => array( 'exists' => RecoveryLink::link_exists() ),
			// Switched on, whether or not safe mode is standing it down.
			'lockdown'          => array( 'active' => \BetterShield\Recovery\Lockdown::state()['active'] ),
			'hardening'         => array(
				'active'        => $active,
				'revert_failed' => $failed,
				'unavailable'   => $available,
			),
			'login_protection'  => array(
				'enabled'         => $login['enabled'],
				// The switch Login & access shows, and what pauses sign-ins:
				// off on its own whenever another plugin keeps that job.
				'attempt_limit'   => $login['attempt_limit'],
				'threshold'       => $login['threshold'],
				'window_minutes'  => $login['window_minutes'],
				'lockout_minutes' => $login['lockout_minutes'],
				'honeypot'        => $login['honeypot'],
				'proof_of_work'   => $login['proof_of_work'],
				'new_location'    => $login['new_location_notice'],
				// As enforced, and who decided it: a host can set it for
				// every site it runs, and a server without syslog cannot.
				'host_ban_line'   => \BetterShield\Support\AuthLog::on(),
				'host_ban_by'     => null !== \BetterShield\Support\AuthLog::forced() ? 'host' : 'site',
				'host_ban_ready'  => \BetterShield\Support\AuthLog::available(),
				'idle_minutes'    => $login['idle_minutes'],
				'session_cap'     => $login['session_cap'],
				// Whether a cap can be kept here at all. A site that replaced
				// how WordPress stores sessions has nothing to remove entries
				// from, and a number reported without this reads as enforced.
				'cap_supported'   => \BetterShield\Login\Sessions::instance()->cap_supported(),
				// Counts, never entries: a blocklist is a description of who
				// the site refuses.
				'allowlist'       => count( $login['allowlist'] ),
				'blocklist'       => count( $login['blocklist'] ),
				'trusted_proxies' => count( $login['trusted_proxies'] ),
			),
			'password_policy'   => $policy,
			'two_factor'        => array( 'accounts_enrolled' => self::two_factor_count() ),
			'abilities'         => array(
				'available' => Registrar::is_available(),
				'enabled'   => Registrar::is_enabled(),
			),
			'alerts'            => array(
				// As alerts behave here: a staging answer's mute lapses on
				// the copy's new address while the stored switch reads on.
				'muted'            => \BetterShield\Alerts\Settings::instance()->is_muted(),
				'digest'           => $alerts['digest'],
				'digest_day'       => $alerts['digest_day'],
				'instant_critical' => $alerts['instant_critical'],
				// A count, never the addresses: a support thread has no need to
				// know who this site emails.
				'recipients'       => count( AlertSettings::instance()->recipients() ),
			),
			'audit'             => array(
				'last_run'      => $overview['generated_at'],
				'checks'        => $overview['checks_count'],
				'checks_ran'    => $overview['checks_ran'] ?? $overview['checks_count'],
				'score'         => $overview['score'],
				'open_findings' => $overview['open_findings'],
				'by_severity'   => $by_severity,
			),
			'recent_errors'     => self::recent_errors(),
			'active_plugins'    => self::active_plugins(),
			'theme'             => self::theme(),
		);
	}

	/**
	 * The report as the text block the owner copies.
	 */
	public static function render(): string {
		$r     = self::report();
		$lines = array();

		$yes = static function ( $value ): string {
			if ( null === $value ) {
				return 'unknown';
			}

			return $value ? 'yes' : 'no';
		};

		$lines[] = 'BetterShield diagnostic report';
		$lines[] = 'Generated: ' . $r['generated_at'];
		$lines[] = '';
		$lines[] = sprintf( 'Plugin: %s (schema %d)', $r['plugin']['version'], $r['plugin']['schema_version'] );
		$lines[] = sprintf(
			'WordPress: %s | multisite: %s | PHP: %s | server: %s (htaccess honored: %s)',
			$r['platform']['wordpress'],
			$yes( $r['platform']['multisite'] ),
			$r['platform']['php'],
			$r['platform']['server'],
			$yes( $r['platform']['htaccess_honored'] )
		);
		$lines[] = sprintf(
			'Environment: %s (graded as %s) | locale: %s',
			$r['platform']['environment_type'],
			$r['platform']['graded_as'],
			$r['platform']['locale']
		);
		$lines[] = '';
		$lines[] = sprintf(
			'Safe mode: %s%s | lockdown: %s | recovery link on record: %s',
			$r['safe_mode']['active'] ? 'ON' : 'off',
			// In the site's zone with its offset, as `activity` prints the
			// same moment beside it; the record itself keeps UTC (#2181).
			$r['safe_mode']['active'] ? ' until ' . self::site_time( (string) $r['safe_mode']['until'] ) : '',
			$r['lockdown']['active'] ? ( $r['safe_mode']['active'] ? 'ON (paused by safe mode)' : 'ON' ) : 'off',
			$yes( $r['recovery_link']['exists'] )
		);
		$lines[] = sprintf(
			'Hardening active (%d): %s',
			count( $r['hardening']['active'] ),
			array() === $r['hardening']['active'] ? 'none' : implode( ', ', $r['hardening']['active'] )
		);
		if ( array() !== $r['hardening']['revert_failed'] ) {
			$lines[] = 'Hardening with a failed undo: ' . implode( ', ', $r['hardening']['revert_failed'] );
		}
		if ( array() !== $r['hardening']['unavailable'] ) {
			$lines[] = 'Hardening not available here: ' . implode(
				', ',
				array_map(
					static fn( string $id, string $why ): string => $id . ' (' . $why . ')',
					array_keys( $r['hardening']['unavailable'] ),
					array_values( $r['hardening']['unavailable'] )
				)
			);
		}
		$lines[] = sprintf(
			'Login protection: %s | attempt limit: %s (threshold %d in %d min, lockout %d min) | honeypot: %s | proof of work: %s | new-location notice: %s | host-ban line: %s%s | idle timeout: %d min | session cap: %d%s | allowlist: %d | blocklist: %d | trusted proxies: %d',
			$r['login_protection']['enabled'] ? 'on' : 'off',
			$r['login_protection']['attempt_limit'] ? 'on' : 'off',
			$r['login_protection']['threshold'],
			$r['login_protection']['window_minutes'],
			$r['login_protection']['lockout_minutes'],
			$yes( $r['login_protection']['honeypot'] ),
			$yes( $r['login_protection']['proof_of_work'] ),
			$yes( $r['login_protection']['new_location'] ),
			$yes( $r['login_protection']['host_ban_line'] ),
			$r['login_protection']['host_ban_ready'] ? ( 'host' === $r['login_protection']['host_ban_by'] ? ' (set by the host)' : '' ) : ' (syslog unavailable)',
			$r['login_protection']['idle_minutes'],
			$r['login_protection']['session_cap'],
			$r['login_protection']['cap_supported'] ? '' : ' (cannot be applied: session storage replaced)',
			$r['login_protection']['allowlist'],
			$r['login_protection']['blocklist'],
			$r['login_protection']['trusted_proxies']
		);
		$lines[] = sprintf(
			'Password policy: %s (minimum %d, privileged %d)',
			$r['password_policy']['enabled'] ? 'on' : 'off',
			$r['password_policy']['min_length'],
			$r['password_policy']['min_length_privileged']
		);
		$lines[] = sprintf( 1 === $r['two_factor']['accounts_enrolled'] ? 'Two-factor: %d account enrolled' : 'Two-factor: %d accounts enrolled', $r['two_factor']['accounts_enrolled'] );
		$lines[] = sprintf(
			'Agent read abilities: %s (platform support: %s)',
			$r['abilities']['enabled'] ? 'on' : 'off',
			$yes( $r['abilities']['available'] )
		);
		$lines[] = sprintf(
			'Alerts: %s | weekly digest: %s (day %d) | instant on high and critical: %s | recipients: %d',
			$r['alerts']['muted'] ? 'MUTED' : 'on',
			$r['alerts']['digest'] ? 'on' : 'off',
			$r['alerts']['digest_day'],
			$yes( $r['alerts']['instant_critical'] ),
			$r['alerts']['recipients']
		);
		$lines[] = '';
		$lines[] = sprintf(
			'Last audit: %s | %s | score %d | open findings %d (critical %d, high %d, medium %d, low %d, info %d)',
			$r['audit']['last_run'] ?? 'never',
			$r['audit']['checks_ran'] === $r['audit']['checks']
				? sprintf( '%d checks', $r['audit']['checks'] )
				: sprintf( '%d of %d checks', $r['audit']['checks_ran'], $r['audit']['checks'] ),
			$r['audit']['score'],
			$r['audit']['open_findings'],
			$r['audit']['by_severity']['critical'],
			$r['audit']['by_severity']['high'],
			$r['audit']['by_severity']['medium'],
			$r['audit']['by_severity']['low'],
			$r['audit']['by_severity']['info']
		);
		$lines[] = '';
		$lines[] = 'Recent plugin errors (7 days):';
		if ( array() === $r['recent_errors'] ) {
			$lines[] = '  none';
		}
		foreach ( $r['recent_errors'] as $error ) {
			$lines[] = sprintf(
				'  %s  %s%s%s',
				$error['occurred_at'],
				$error['type'],
				null !== $error['object'] ? ' ' . $error['object'] : '',
				null !== $error['reason'] ? ' (' . $error['reason'] . ')' : ''
			);
		}
		$lines[] = '';
		$lines[] = sprintf( 'Theme: %s %s', $r['theme']['name'], $r['theme']['version'] );
		$lines[] = sprintf( 'Active plugins (%d):', count( $r['active_plugins'] ) );
		foreach ( $r['active_plugins'] as $plugin ) {
			$lines[] = sprintf( '  %s %s', $plugin['name'], $plugin['version'] );
		}
		$lines[] = '';
		$lines[] = 'Left out on purpose: site address, email addresses, usernames, IP addresses, keys, tokens, hashes and file contents.';

		return implode( "\n", $lines );
	}

	/**
	 * A UTC moment from the record as the site's clock reads it, with its
	 * offset, so the line cannot be taken for either zone.
	 */
	private static function site_time( string $utc ): string {
		$moment = strtotime( $utc );

		return false === $moment ? $utc : wp_date( 'Y-m-d H:i P', $moment );
	}

	private static function two_factor_count(): int {
		global $wpdb;

		// One indexed count over usermeta; the enrollment secret's presence is
		// what "enabled" means throughout the two-factor code.
		if ( ! is_multisite() ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			return (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value <> ''",
					'bettershield_totp_secret'
				)
			);
		}

		/*
		 * On a network usermeta is the network's, so the plain count was every
		 * enrolled account on every site, in a report that describes this one.
		 * A member of this site is an account holding its capabilities key.
		 */
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT secret.user_id) FROM {$wpdb->usermeta} AS secret INNER JOIN {$wpdb->usermeta} AS member ON member.user_id = secret.user_id AND member.meta_key = %s WHERE secret.meta_key = %s AND secret.meta_value <> ''",
				$wpdb->get_blog_prefix() . 'capabilities',
				'bettershield_totp_secret'
			)
		);
	}

	/**
	 * The last few error-class events, reduced to when, what, and the reason
	 * code the plugin recorded. Never the actor, never the address.
	 *
	 * @return array<int, array{occurred_at: string, type: string, object: ?string, reason: ?string}>
	 */
	private static function recent_errors(): array {
		global $wpdb;

		$since = ( new \DateTimeImmutable( '-7 days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the IN list is a fixed constant of this class; every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT occurred_at, event_type, object_id, context FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at > %s AND event_type IN (' . implode( ',', array_fill( 0, count( self::ERROR_TYPES ), '%s' ) ) . ') ORDER BY id DESC LIMIT 10',
				array_merge( array( Schema::table( 'events' ), $since ), self::ERROR_TYPES )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$out = array();
		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$context = null !== $row->context ? json_decode( (string) $row->context, true ) : null;
			$reason  = null;
			if ( is_array( $context ) ) {
				if ( isset( $context['reason'] ) ) {
					$reason = (string) $context['reason'];
				} elseif ( isset( $context['dropped'] ) ) {
					$reason = 'dropped ' . (int) $context['dropped'];
				}
			}

			$out[] = array(
				'occurred_at' => substr( (string) $row->occurred_at, 0, 19 ) . 'Z',
				'type'        => (string) $row->event_type,
				'object'      => null !== $row->object_id ? (string) $row->object_id : null,
				'reason'      => $reason,
			);
		}

		return $out;
	}

	/**
	 * @return array<int, array{name: string, version: string}>
	 */
	private static function active_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$all    = get_plugins();
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}

		$out = array();
		foreach ( array_unique( $active ) as $file ) {
			if ( ! isset( $all[ $file ] ) ) {
				continue;
			}
			$out[] = array(
				'name'    => wp_strip_all_tags( (string) $all[ $file ]['Name'] ),
				'version' => wp_strip_all_tags( (string) $all[ $file ]['Version'] ),
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcasecmp( $a['name'], $b['name'] );
			}
		);

		return $out;
	}

	/**
	 * @return array{name: string, version: string}
	 */
	private static function theme(): array {
		$theme = wp_get_theme();

		return array(
			'name'    => wp_strip_all_tags( (string) $theme->get( 'Name' ) ),
			'version' => wp_strip_all_tags( (string) $theme->get( 'Version' ) ),
		);
	}
}
