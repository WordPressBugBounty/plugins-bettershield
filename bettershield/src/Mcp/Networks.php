<?php
/**
 * Where each assistant's connection has been used from, and a row when one is
 * used from a network it never has been (#1880).
 *
 * `last_used` said when a connection was last used, never from where. A
 * stolen bearer token used by somebody else looked exactly like the owner's
 * assistant. People are told when their account signs in from somewhere new;
 * a connection now is, too.
 *
 * Per connection, at most ten networks are kept, each as a keyed digest of
 * its /24 or /64 under the plugin's own signing key, so no address is kept.
 * The first call from a network not among them is recorded as
 * `agent_new_network`: high, and so emailed at once, when the tool writes;
 * medium, and so in the digest, when it only reads. The connection's first
 * call ever only takes note, as a first sign-in does. An assistant platform
 * that calls out from a published range of its own counts as one network
 * wherever in that range a call comes from, so its hops are not news.
 *
 * Nothing is blocked. An address nothing vouches for (behind a proxy nobody
 * has named) is left alone, as the lockouts leave it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Ip;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Networks {

	/** Connection => network digest => when it was last seen. Not autoloaded. */
	public const OPTION = 'bettershield_agent_networks';

	/** How many networks are kept per connection, the least recent let go. */
	public const KEPT = 10;

	/** How stale a known network's stamp may get before it is written again. */
	private const RESTAMP = DAY_IN_SECONDS;

	/**
	 * Assistant platforms that call MCP servers from published ranges of
	 * their own, each counted as one network. Anthropic's outbound range
	 * (platform.claude.com/docs/en/api/ip-addresses, read 24 October 2026).
	 * Shipped rather than fetched, and filterable for a platform whose list
	 * is too long or changes too often to ship.
	 */
	private const PROVIDERS = array(
		'anthropic' => array( '160.79.104.0/21' ),
	);

	/** Connections already looked at on this request. */
	private static array $seen = array();

	/**
	 * A tool was called on the connection this request authenticated with.
	 *
	 * @param bool $writes Whether the tool changes the site.
	 */
	public static function observe( string $connection, bool $writes ): void {
		if ( '' === $connection || isset( self::$seen[ $connection ] ) ) {
			return;
		}

		self::$seen[ $connection ] = true;

		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );

		if ( empty( $resolved['confident'] ) ) {
			return;
		}

		$network = self::network( (string) $resolved['ip'] );

		if ( null === $network ) {
			return;
		}

		$all   = self::all();
		$known = $all[ $connection ] ?? array();
		$now   = time();

		if ( isset( $known[ $network['digest'] ] ) ) {
			if ( $now - (int) $known[ $network['digest'] ] >= self::RESTAMP ) {
				$known[ $network['digest'] ] = $now;
				self::save( $all, $connection, $known );
			}

			return;
		}

		$first = array() === $known;

		$known[ $network['digest'] ] = $now;
		self::save( $all, $connection, $known );

		if ( $first ) {
			return;
		}

		Writer::instance()->record(
			'agent_new_network',
			$writes ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'mcp_connection',
				'object_id'   => $connection,
				'context'     => array(
					'connection' => $connection,
					'name'       => Audit::connection_label( $connection ),
					'writes'     => $writes,
					'provider'   => $network['provider'],
				),
			)
		);
	}

	/**
	 * The network an address is counted under: a platform's whole range, or
	 * its /24 or /64, as a keyed digest.
	 *
	 * @return array{digest: string, provider: string}|null
	 */
	public static function network( string $ip ): ?array {
		foreach ( self::providers() as $provider => $ranges ) {
			if ( ClientIp::in_ranges( $ip, (array) $ranges ) ) {
				return array(
					'digest'   => self::digest( 'provider:' . $provider ),
					'provider' => (string) $provider,
				);
			}
		}

		$label = Ip::prefix_label( Ip::truncated_binary( $ip ) );

		return null === $label ? null : array(
			'digest'   => self::digest( 'net:' . $label ),
			'provider' => '',
		);
	}

	/**
	 * The platforms' ranges, by platform.
	 *
	 * @return array<string, string[]>
	 */
	public static function providers(): array {
		/**
		 * Filters the published ranges an assistant platform calls out from,
		 * each platform counted as one network.
		 *
		 * @param array<string, string[]> $providers Platform => CIDR ranges.
		 */
		$providers = apply_filters( 'bettershield_agent_provider_ranges', self::PROVIDERS );

		return is_array( $providers ) ? $providers : self::PROVIDERS;
	}

	/** Forget one connection's networks: it was revoked. */
	public static function forget( string $connection ): void {
		$all = self::all();

		if ( isset( $all[ $connection ] ) ) {
			unset( $all[ $connection ] );
			update_option( self::OPTION, $all, false );
		}
	}

	/** Forget every connection's: every connection ended. */
	public static function forget_all(): void {
		delete_option( self::OPTION );
	}

	/** Forget what this request looked at. For tests, which are many requests. */
	public static function reset_request_state(): void {
		self::$seen = array();
	}

	/** @return array<string, array<string, int>> */
	private static function all(): array {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * @param array<string, array<string, int>> $all
	 * @param array<string, int>                $known
	 */
	private static function save( array $all, string $connection, array $known ): void {
		arsort( $known );
		$all[ $connection ] = array_slice( $known, 0, self::KEPT, true );

		update_option( self::OPTION, $all, false );
	}

	private static function digest( string $network ): string {
		return hash_hmac( 'sha256', 'agent-network|' . $network, ClientIp::signing_secret() );
	}
}
