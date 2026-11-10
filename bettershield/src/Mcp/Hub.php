<?php
/**
 * The optional hub connection: where it lives, and the ticket that starts it.
 *
 * Connecting a site to a hub is an ordinary OAuth grant through this site's
 * own consent page — the hub registers as a client, a person approves it, and
 * the grant is listed and revocable like any other. What this class adds is
 * the one thing a plain grant cannot prove: that the person approving it
 * started from this site's dashboard. A consent link for the hub's return
 * address is refused unless it carries a ticket minted here, by the account
 * that is approving, within the last fifteen minutes. Without that rule
 * anybody could start a connection in their own hub account and send the
 * owner a genuine consent page that would land the site in the wrong place.
 *
 * The ticket is stored as a digest and spent at the token exchange, so it
 * binds one approval to one code and cannot be replayed.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Hub {

	/**
	 * Where older versions kept an address saved on screen. Nothing reads it:
	 * it is deleted on upgrade and on uninstall.
	 */
	public const OPTION = 'bettershield_hub';

	/** Outstanding connect tickets, by digest. */
	public const TICKETS_OPTION = 'bettershield_hub_tickets';

	/** Where a site connects when nobody has said otherwise. */
	public const DEFAULT_URL = 'https://hub.bettershield.ai';

	/** How long a ticket is good for, in seconds. */
	public const TICKET_TTL = 900;

	/** How many tickets may be outstanding at once. */
	private const MAX_TICKETS = 5;

	/** The claim a ticket's spending takes, keyed by its digest. */
	public const TICKET_CLAIM = 'hub_ticket_';

	/** The access levels a connection may be started with. */
	public const ACCESS_READ  = 'read';
	public const ACCESS_WRITE = 'write';

	/* ---- the address ----------------------------------------------------------- */

	/**
	 * The hub's address, without a trailing slash.
	 *
	 * The default, unless `BETTERSHIELD_HUB_URL` in wp-config.php (or the
	 * `bettershield_hub_url` filter) pins another. There is no setting: an
	 * address any administrator could change decides who is handed a grant.
	 *
	 * A pinned address this cannot use is no address, '' here, and never the
	 * default: the host pinned it to keep this site away from the public hub,
	 * and quietly connecting there instead is the one outcome they ruled out.
	 */
	public static function url(): string {
		if ( self::is_pinned() ) {
			return (string) self::normalize_url( self::pinned() );
		}

		return self::DEFAULT_URL;
	}

	/** Whether configuration pins an address other than the default. */
	public static function is_pinned(): bool {
		return '' !== self::pinned();
	}

	/** Whether the address pinned in configuration is not one this can use. */
	public static function pin_is_invalid(): bool {
		return self::is_pinned() && null === self::normalize_url( self::pinned() );
	}

	/** The address wp-config.php pins, as written there, or '' where it pins none. */
	private static function pinned(): string {
		/**
		 * The hub address this site is pinned to, from `BETTERSHIELD_HUB_URL`
		 * in wp-config.php unless something else answers. '' leaves the
		 * default in place.
		 *
		 * @param string $pinned The address as configured, or '' for none.
		 */
		$pinned = apply_filters( 'bettershield_hub_url', defined( 'BETTERSHIELD_HUB_URL' ) ? (string) constant( 'BETTERSHIELD_HUB_URL' ) : '' );

		return is_string( $pinned ) ? trim( $pinned ) : '';
	}

	/**
	 * An https address with a host and nothing a browser could be steered by.
	 *
	 * A path is allowed, because a hub may live under one; a query, a
	 * fragment and credentials are not. Nor is a host that is not a name or
	 * an address, a port outside the range, or a path that climbs with `..`:
	 * the parser takes all three as written, so `https://exa mple.com` was
	 * saved and shown as the hub.
	 */
	public static function normalize_url( string $url ): ?string {
		$url   = trim( $url );
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || 'https' !== strtolower( (string) ( $parts['scheme'] ?? '' ) ) ) {
			return null;
		}

		$host = strtolower( (string) ( $parts['host'] ?? '' ) );

		if ( '' === $host || isset( $parts['query'] ) || isset( $parts['fragment'] ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return null;
		}

		$path = untrailingslashit( (string) ( $parts['path'] ?? '' ) );

		if ( ! self::host_is_valid( $host ) || ! self::path_is_valid( $path ) || ( isset( $parts['port'] ) && ( (int) $parts['port'] < 1 || (int) $parts['port'] > 65535 ) ) ) {
			return null;
		}

		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';

		return 'https://' . $host . $port . $path;
	}

	/** A name, an IPv4 address or a bracketed IPv6 one, as a browser would read it. */
	private static function host_is_valid( string $host ): bool {
		if ( 1 === preg_match( '/^\[[0-9a-f:.]+\]$/i', $host ) ) {
			return true;
		}

		return 1 === preg_match( '/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i', $host );
	}

	/** No `.` or `..` segment, spelled out or encoded, and nothing unprintable. */
	private static function path_is_valid( string $path ): bool {
		$decoded = rawurldecode( $path );

		return 1 !== preg_match( '#(?:^|/)\.{1,2}(?:/|$)#', $decoded ) && 1 !== preg_match( '/[\s\x00-\x1f\x7f\\\\]/', $decoded );
	}

	/**
	 * Retire the address older versions saved on screen.
	 *
	 * A grant made through that address before grants carried their hub is
	 * recognized only by where it sends people, which stops matching once the
	 * address is gone, so it is marked as that hub's first: it stays on the
	 * card, and ends with Disconnect, as before.
	 */
	public static function retire_saved_address(): void {
		$stored = get_option( self::OPTION );

		if ( false === $stored ) {
			return;
		}

		$host = is_array( $stored ) && isset( $stored['url'] ) ? self::host_of( (string) $stored['url'] ) : '';

		if ( '' !== $host ) {
			foreach ( OAuth::connected_apps() as $app ) {
				if ( '' !== $app['hub'] ) {
					continue;
				}

				foreach ( OAuth::redirect_uris_of( (string) $app['id'] ) as $uri ) {
					if ( hash_equals( $host, self::host_of( $uri ) ) ) {
						OAuth::mark_hub( (string) $app['id'], $host );
						break;
					}
				}
			}
		}

		delete_option( self::OPTION );
	}

	/** The hub's host, with its port where it names one other than the scheme's own. */
	public static function host(): string {
		return self::host_of( self::url() );
	}

	/**
	 * The host an https address names, written the way host() writes the
	 * hub's. Empty for anything else.
	 */
	public static function host_of( string $url ): string {
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || 'https' !== strtolower( (string) ( $parts['scheme'] ?? '' ) ) ) {
			return '';
		}

		return self::authority( $parts );
	}

	/**
	 * Whether a return address sends a code to the hub.
	 *
	 * An exact host match over https. No wildcard and no parent domain: a
	 * subdomain of the hub is somebody else as far as this check is
	 * concerned. Spellings that reach the same server — the scheme's own port
	 * written out, a trailing dot — are the hub, or a client registered with
	 * one would be delivered the hub's code without the ticket it needs.
	 */
	public static function is_hub_redirect( string $redirect_uri ): bool {
		$parts = wp_parse_url( $redirect_uri );

		if ( ! is_array( $parts ) || 'https' !== strtolower( (string) ( $parts['scheme'] ?? '' ) ) ) {
			return false;
		}

		$host = self::authority( $parts );

		return '' !== $host && hash_equals( self::host(), $host );
	}

	/**
	 * A parsed address's host and port, written one way.
	 *
	 * Lowercase, one trailing dot dropped, and the port left out when it is
	 * the scheme's own.
	 *
	 * @param array<string, mixed> $parts From wp_parse_url().
	 */
	private static function authority( array $parts ): string {
		$host = strtolower( (string) ( $parts['host'] ?? '' ) );

		if ( '.' === substr( $host, -1 ) ) {
			$host = substr( $host, 0, -1 );
		}

		if ( ! isset( $parts['port'] ) ) {
			return $host;
		}

		$port    = (int) $parts['port'];
		$default = 'http' === strtolower( (string) ( $parts['scheme'] ?? '' ) ) ? 80 : 443;

		return $port === $default ? $host : $host . ':' . $port;
	}

	/* ---- tickets --------------------------------------------------------------- */

	/**
	 * Mint the single-use ticket a connection starts with.
	 *
	 * Handed back once, in plaintext, to travel through the browser to the
	 * hub and back to the consent page. Only its digest is kept.
	 */
	public static function mint_ticket( int $user_id, string $access ): string {
		$ticket  = bin2hex( random_bytes( 32 ) );
		$tickets = self::live_tickets();

		$tickets[ self::digest( $ticket ) ] = array(
			'user_id' => $user_id,
			'access'  => self::ACCESS_WRITE === $access ? self::ACCESS_WRITE : self::ACCESS_READ,
			'expires' => time() + self::TICKET_TTL,
		);

		// Oldest first out, so a person pressing the button repeatedly keeps
		// their latest ticket rather than their first.
		uasort(
			$tickets,
			static function ( array $a, array $b ): int {
				return $b['expires'] <=> $a['expires'];
			}
		);

		update_option( self::TICKETS_OPTION, array_slice( $tickets, 0, self::MAX_TICKETS, true ), false );

		return $ticket;
	}

	/** Whether a ticket is outstanding and was minted by this account. */
	public static function ticket_ok( string $ticket, int $user_id ): bool {
		return null !== self::ticket( $ticket, $user_id );
	}

	/**
	 * An outstanding ticket this account minted, or null.
	 *
	 * @return array{user_id: int, access: string, expires: int}|null
	 */
	public static function ticket( string $ticket, int $user_id ): ?array {
		if ( '' === $ticket || $user_id <= 0 ) {
			return null;
		}

		$entry = self::live_tickets()[ self::digest( $ticket ) ] ?? null;

		return is_array( $entry ) && (int) $entry['user_id'] === $user_id ? $entry : null;
	}

	/**
	 * Spend a ticket. True only for one that was outstanding.
	 *
	 * One ticket can ride two codes — the consent form sent twice — and two
	 * exchanges both find it outstanding in the option before either writes
	 * it away. The database decides which one spends it, in one statement,
	 * before anything is read; one that cannot be arbitrated is not spent.
	 */
	public static function spend_ticket( string $ticket ): bool {
		if ( '' === $ticket ) {
			return false;
		}

		$key = self::digest( $ticket );

		if ( ! Claim::claim( self::TICKET_CLAIM . $key, self::TICKET_TTL ) ) {
			return false;
		}

		$tickets = self::live_tickets();

		if ( ! isset( $tickets[ $key ] ) ) {
			return false;
		}

		unset( $tickets[ $key ] );
		update_option( self::TICKETS_OPTION, $tickets, false );

		return true;
	}

	/** A ticket's digest, which is all that is ever stored. */
	public static function digest( string $ticket ): string {
		return hash( 'sha256', $ticket );
	}

	/**
	 * @return array<string, array{user_id: int, access: string, expires: int}>
	 */
	private static function live_tickets(): array {
		$stored = get_option( self::TICKETS_OPTION );
		$live   = array();

		if ( ! is_array( $stored ) ) {
			return $live;
		}

		foreach ( $stored as $key => $entry ) {
			if ( is_string( $key ) && is_array( $entry ) && (int) ( $entry['expires'] ?? 0 ) > time() ) {
				$live[ $key ] = array(
					'user_id' => (int) ( $entry['user_id'] ?? 0 ),
					'access'  => (string) ( $entry['access'] ?? self::ACCESS_READ ),
					'expires' => (int) $entry['expires'],
				);
			}
		}

		return $live;
	}

	/* ---- the connection -------------------------------------------------------- */

	/**
	 * Where the browser goes to start connecting.
	 *
	 * @param string $from Where the owner pressed Connect: 'setup' for the
	 *                     Quick Setup, which they come back to; '' otherwise.
	 */
	public static function connect_url( string $ticket, string $access, string $from = '' ): string {
		return add_query_arg(
			array(
				'site'   => rawurlencode( untrailingslashit( home_url( '/' ) ) ),
				'ticket' => rawurlencode( $ticket ),
				'access' => self::ACCESS_WRITE === $access ? self::ACCESS_WRITE : self::ACCESS_READ,
				'return' => rawurlencode( self::return_url( $from ) ),
			),
			self::url() . '/connect'
		);
	}

	/** The screen the hub sends a person back to. */
	public static function return_url( string $from = '' ): string {
		// Connected from the Quick Setup's last step, the owner goes back to
		// it, which says the site is connected (#2297).
		if ( 'setup' === $from ) {
			return \BetterShield\Onboarding\QuickSetup::url();
		}

		return admin_url( 'admin.php?page=bettershield-agents&tab=connect' );
	}

	/**
	 * What this site says about itself at the token exchange, so the hub can
	 * refuse a code that came back from somewhere other than where it began.
	 *
	 * @return array{home_url: string, blog_id: int, version: string, multisite: array<string, mixed>}
	 */
	public static function site_facts(): array {
		return array(
			'home_url'  => untrailingslashit( home_url( '/' ) ),
			'blog_id'   => get_current_blog_id(),
			'version'   => defined( 'BETTERSHIELD_VERSION' ) ? (string) BETTERSHIELD_VERSION : '',
			'multisite' => self::network_identity(),
		);
	}

	/**
	 * Which site of which network this is, in one shape whoever asks: the
	 * network, this site and the main site, the main site's address, whether
	 * sites are subdomains or paths, and whether this plugin is
	 * network-active. On a single site, `enabled` is false and the rest are
	 * zero or empty.
	 *
	 * @return array{enabled: bool, network_id: int, site_id: int, main_site_id: int, main_site_url: string, subdomain_install: bool, network_active: bool}
	 */
	public static function network_identity(): array {
		if ( ! is_multisite() ) {
			return array( 'enabled' => false, 'network_id' => 0, 'site_id' => 0, 'main_site_id' => 0, 'main_site_url' => '', 'subdomain_install' => false, 'network_active' => false );
		}

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$main = get_main_site_id();

		return array(
			'enabled'           => true,
			'network_id'        => get_current_network_id(),
			'site_id'           => get_current_blog_id(),
			'main_site_id'      => $main,
			'main_site_url'     => untrailingslashit( get_home_url( $main ) ),
			'subdomain_install' => is_subdomain_install(),
			'network_active'    => is_plugin_active_for_network( plugin_basename( BETTERSHIELD_FILE ) ),
		);
	}

	/**
	 * The live hub grants.
	 *
	 * A grant made through a hub ticket names the hub it was approved for,
	 * and stays that hub's when the address changes underneath it — through
	 * wp-config.php, say — so it can still be seen and ended here. A grant
	 * made before grants carried that is recognized by a return address at
	 * the hub this site points at now, and marked as that hub's on the spot,
	 * since the address it was recognized by can move.
	 *
	 * @return array<int, array{id: string, name: string, granted_at: int, granted_by: int, last_used: int, scope: string, hub: string}>
	 */
	public static function apps(): array {
		$apps = array();

		foreach ( OAuth::connected_apps() as $app ) {
			if ( '' !== $app['hub'] ) {
				$apps[] = $app;
				continue;
			}

			$host = self::unmarked_host( (string) $app['id'] );

			if ( '' === $host ) {
				continue;
			}

			// Recognized by where it sends people, which is only true until
			// the address moves: marked now, it stays the hub's after that.
			OAuth::mark_hub( (string) $app['id'], $host );

			$app['hub'] = $host;
			$apps[]     = $app;
		}

		return $apps;
	}

	/**
	 * The hub's host for a client whose grant carries no hub, when it sends
	 * people back to the hub this site points at now; empty otherwise.
	 */
	public static function unmarked_host( string $client_id ): string {
		return self::redirects_to_hub( $client_id ) ? self::host() : '';
	}

	/**
	 * Whether a registered client is the hub: one holding a grant approved
	 * for a hub, or one that sends people back to the hub this site points at.
	 */
	public static function is_hub_client( string $client_id ): bool {
		foreach ( OAuth::connected_apps() as $app ) {
			if ( $client_id === $app['id'] && '' !== $app['hub'] ) {
				return true;
			}
		}

		return self::redirects_to_hub( $client_id );
	}

	/** Whether a registered client names the current hub as a return address. */
	private static function redirects_to_hub( string $client_id ): bool {
		foreach ( OAuth::redirect_uris_of( $client_id ) as $uri ) {
			if ( self::is_hub_redirect( $uri ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * End every hub grant this site holds.
	 *
	 * @return int How many were ended.
	 */
	public static function disconnect(): int {
		$count = 0;

		foreach ( self::apps() as $app ) {
			if ( OAuth::revoke_client( (string) $app['id'] ) ) {
				++$count;
			}
		}

		delete_option( self::TICKETS_OPTION );

		// The link sends only while the site is connected, and its key is no
		// use to anybody once it is not.
		\BetterShield\Hub\Link\Link::disable( 'disconnected' );

		return $count;
	}

	/**
	 * Every one of this site's own answers that refuses the hub right now,
	 * or none when a grant it holds is let in.
	 *
	 * In the order a hub call meets them: a staging copy refuses the hub's
	 * token, the switched-off connection refuses every call, a lockdown
	 * pauses every connected app until it is lifted, and with reading off
	 * there is nothing to call. All of them are named, not the first:
	 * undoing one lets the hub in only when it was the only one.
	 *
	 * @return string[]
	 */
	public static function refused_by(): array {
		$refusals = array();

		if ( \BetterShield\Onboarding\SiteIdentity::is_staging() ) {
			$refusals[] = 'staging';
		}

		if ( ! Manager::is_enabled() ) {
			$refusals[] = 'connection';
		}

		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			$refusals[] = 'lockdown';
		}

		if ( ! \BetterShield\Abilities\Registrar::is_enabled() ) {
			$refusals[] = 'reading';
		}

		return $refusals;
	}

	/**
	 * Whether connecting can be offered: assistants are available here, no
	 * hub is connected yet, the address is usable, the site routes the
	 * pretty addresses the hub signs in through, no lockdown is pausing
	 * connected apps, and this is not a staging copy, which refuses the hub.
	 */
	public static function offerable(): bool {
		return Manager::is_available()
			&& array() === self::apps()
			&& ! self::pin_is_invalid()
			&& Pairing::pretty_routed()
			&& ! \BetterShield\Recovery\Lockdown::is_active()
			&& ! \BetterShield\Onboarding\SiteIdentity::is_staging();
	}

	/** Everything this class stores, gone, and the link's with it. */
	public static function forget(): void {
		delete_option( self::OPTION );
		delete_option( self::TICKETS_OPTION );
		\BetterShield\Hub\Link\Link::forget();
	}
}
