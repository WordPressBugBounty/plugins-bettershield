<?php
/**
 * AuthLog: one line in this server's auth log when a connection is paused.
 *
 * A pause here is enforced in PHP, so the request that was refused was still
 * served. A host that runs its own firewall jail can do better than that: it
 * reads the auth log and drops the network at the firewall, before PHP is
 * reached at all. This writes the line that jail reads.
 *
 * The line goes through PHP's own `syslog()` to the machine the site runs
 * on. Nothing is queued and nothing leaves the server: the call is local and
 * it is made the moment the pause starts, so a short pause has not already
 * ended by the time the jail sees it.
 *
 * It carries the network this plugin already keeps for every event — IPv4
 * cut to /24, IPv6 to /64 — and never the full address or a username. The
 * site's own address keeps one site's lines apart from another's in an auth
 * log several sites share.
 *
 *     bettershield[1234]: lockout surface=signin network=203.0.113.0/24 minutes=15 site=example.com
 *
 * Off unless the owner turns it on, or the host does for every site it runs:
 *
 *     add_filter( 'bettershield_host_ban_line', '__return_true' );
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

use BetterShield\Login\Protection;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AuthLog {

	/**
	 * The host's say, for every site it runs. Null leaves it to the switch on
	 * the screen; true or false decides it, whatever the switch says.
	 */
	public const FILTER = 'bettershield_host_ban_line';

	/** The program name the line is logged under, which a jail matches on. */
	public const IDENT = 'bettershield';

	/**
	 * Whether PHP can write to the system log here. A host that lists
	 * `openlog` or `syslog` in `disable_functions` has neither defined, and
	 * the screen says so rather than offering a switch that writes nothing.
	 */
	public static function available(): bool {
		return function_exists( 'openlog' ) && function_exists( 'syslog' ) && function_exists( 'closelog' ) && null !== self::facility();
	}

	/**
	 * What the host decided, or null when it left it to the owner.
	 */
	public static function forced(): ?bool {
		$forced = apply_filters( self::FILTER, null ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- self::FILTER is 'bettershield_host_ban_line'.

		return null === $forced ? null : (bool) $forced;
	}

	/**
	 * Whether a pause starting now writes its line.
	 */
	public static function on(): bool {
		if ( ! self::available() ) {
			return false;
		}

		return self::forced() ?? (bool) ( self::from_main_site( static fn(): array => Protection::instance()->settings() )['host_ban_line'] ?? false );
	}

	/**
	 * Whether the switch here is the network's rather than this site's.
	 *
	 * The firewall a line feeds bans at the server, for every site on it, so
	 * on a network the decision is the main site's, where its administrators
	 * set it. A subsite's administrator could otherwise have a network the
	 * network's administrators allowed banned for every site, out of reach
	 * of any recovery link.
	 */
	public static function set_from_main_site(): bool {
		return is_multisite() && ! is_main_site();
	}

	/**
	 * What the main site answers, read on it; on a single site, or on the
	 * main site itself, what this site answers.
	 *
	 * @template T
	 * @param callable(): T $read
	 * @return T
	 */
	private static function from_main_site( callable $read ) {
		if ( ! self::set_from_main_site() ) {
			return $read();
		}

		switch_to_blog( get_main_site_id() );

		try {
			return $read();
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * What the screen needs to describe the switch honestly.
	 *
	 * @return array{available: bool, forced: ?bool, on: bool}
	 */
	public static function status(): array {
		return array(
			'available' => self::available(),
			'forced'    => self::forced(),
			'on'        => self::on(),
			// On a network's subsite the switch is the main site's.
			'network'   => self::set_from_main_site(),
		);
	}

	/**
	 * Write the line for a pause that has just started on one surface.
	 *
	 * Never throws and never blocks the request it runs in: a system log
	 * that is not there costs a dropped datagram, not a refused sign-in.
	 */
	public static function lockout( string $surface, string $ip, int $minutes ): void {
		if ( ! self::on() ) {
			return;
		}

		$network = Ip::prefix_label( Ip::truncated_binary( $ip ) );

		// A ban at the firewall covers the whole network, wider than this
		// pause, and the recovery link cannot lift it. A network the owner
		// has allowed an address in is paused here and nowhere else.
		if ( null === $network || self::holds_allowed( $network ) ) {
			return;
		}

		/*
		 * On a subsite, which address a request is pinned on follows that
		 * site's own trusted proxies, which its administrator sets. A line
		 * reaches every site on the server, so it is written only for an
		 * address the main site's own proxy settings resolve the same way
		 * and vouch for.
		 */
		if ( self::set_from_main_site() && ! self::main_site_vouches_for( $ip ) ) {
			return;
		}

		$line = self::line( $surface, $network, $minutes );

		if ( self::write( $line ) ) {
			/**
			 * After the line was handed to the system log.
			 *
			 * @param string $line The line, without the program name and process id the system log adds.
			 */
			do_action( 'bettershield_auth_log_line', $line );
		}
	}

	/**
	 * Whether an allowed address or range falls inside this network, or the
	 * network inside it. Two CIDR blocks either nest or do not meet, so each
	 * is asked whether it holds the other's first address.
	 */
	private static function holds_allowed( string $network ): bool {
		$base = (string) strstr( $network, '/', true );

		// This site's allowed list, and on a network the main site's too: a
		// network its administrators allowed is not banned for every site
		// by a line from one of them.
		$ranges = array_merge(
			array_column( (array) ( Protection::instance()->settings()['allowlist'] ?? array() ), 'range' ),
			self::set_from_main_site() ? array_column( (array) ( self::from_main_site( static fn(): array => Protection::instance()->settings() )['allowlist'] ?? array() ), 'range' ) : array()
		);

		foreach ( $ranges as $range ) {
			$range = (string) $range;
			$start = false === strpos( $range, '/' ) ? $range : (string) strstr( $range, '/', true );

			if ( '' === $range ) {
				continue;
			}

			if ( ( '' !== $base && ClientIp::in_ranges( $base, array( $range ) ) ) || ClientIp::in_ranges( $start, array( $network ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether this request resolves to the same address, confidently, under
	 * the main site's trusted proxies and Cloudflare setting.
	 */
	private static function main_site_vouches_for( string $ip ): bool {
		$resolved = self::from_main_site( static fn(): array => ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() ) );

		return ! empty( $resolved['confident'] ) && (string) $resolved['ip'] === $ip;
	}

	/**
	 * The line itself. Every field is one token of a known alphabet, so a
	 * value can never end the line or reach into the next field.
	 */
	public static function line( string $surface, string $network, int $minutes ): string {
		return sprintf(
			'lockout surface=%s network=%s minutes=%d site=%s',
			self::token( $surface, '/[^a-z0-9_-]/' ),
			self::token( $network, '#[^0-9a-fA-F.:/]#' ),
			max( 1, $minutes ),
			self::site()
		);
	}

	/**
	 * This site's address without its scheme, path kept: on a network whose
	 * sites share a host, the path is what tells them apart.
	 */
	private static function site(): string {
		$home = (string) preg_replace( '#^[a-z][a-z0-9+.-]*://#i', '', untrailingslashit( home_url() ) );

		return self::token( strtolower( $home ), '#[^a-z0-9.:/_~-]#' );
	}

	private static function token( string $value, string $outside ): string {
		$value = (string) preg_replace( $outside, '', $value );

		return '' === $value ? '-' : $value;
	}

	/**
	 * The auth facility, where hosts point their jails. A system without it
	 * names the private one; one without either has no auth log to write to.
	 */
	private static function facility(): ?int {
		if ( defined( 'LOG_AUTH' ) ) {
			return (int) LOG_AUTH;
		}

		return defined( 'LOG_AUTHPRIV' ) ? (int) LOG_AUTHPRIV : null;
	}

	private static function write( string $line ): bool {
		$facility = self::facility();

		if ( null === $facility ) {
			return false;
		}

		// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged -- a missing system log must not surface as a warning on a visitor's request.
		if ( ! @openlog( self::IDENT, LOG_PID | LOG_NDELAY, $facility ) ) {
			return false;
		}

		$written = @syslog( LOG_WARNING, $line );

		// Closed again, so the program name does not stay set for anything
		// else in this process that writes to the system log.
		@closelog();
		// phpcs:enable WordPress.PHP.NoSilencedErrors.Discouraged

		return (bool) $written;
	}
}
