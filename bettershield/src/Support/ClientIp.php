<?php
/**
 * Who is actually connecting, and how sure are we?
 *
 * Behind Cloudflare or a reverse proxy, REMOTE_ADDR is the proxy — lock
 * "the attacker's IP" there and every visitor shares the sentence, which is
 * the documented failure mode of half this category. Forward headers name
 * the real client, but anyone can send a header: trust X-Forwarded-For from
 * a direct connection and an attacker rotates identities for free.
 *
 * So the answer here is three things, not one: the address, the method that
 * produced it, and whether it is CONFIDENT — meaning the header was verified
 * to come from infrastructure entitled to set it. Callers enforce by
 * confidence: an unconfident address is fine to record and display, and
 * never a basis for locking anyone out.
 *
 * Cloudflare is the one case where the connection itself looks like a
 * voucher, and it is not one. A request made from inside Cloudflare's address
 * space — a worker, a tunnel, another tenant — reaches a site that is not
 * behind Cloudflare too, and it can name any client it likes in the header.
 * So the voucher is a statement the OWNER makes: a setting that says this site
 * is behind Cloudflare. Until they make it, a header arriving from those
 * ranges is answered as `cloudflare-unconfirmed`, and the address that really
 * connected travels with the answer as `paired_with`; enforcement counts the
 * two together, so a request cannot pick which key its failures land on and no
 * visitor behind the edge shares a sentence with the others. Once the owner
 * vouches, the header alone names the client, which is what makes a lockout
 * follow one visitor rather than a pair.
 *
 * A forwarding header on a connection nothing vouches for is IGNORED, not
 * believed and not allowed to disarm anything: the connecting address is the
 * client, confidently, and the header's presence is merely reported. The
 * alternative — treating such a header as a sign of an unknown proxy and
 * standing down — hands every attacker on a plainly hosted site a one-line
 * exemption from lockouts. A site that really is behind an unnamed proxy
 * sees the same report on its own dashboard, and names the proxy.
 *
 * That holds wherever the connecting address could be a client. A private or
 * reserved one cannot: PHP is behind something that speaks for every visitor
 * at once, so the answer there is unconfident whatever arrived with it —
 * neither disarmed by a header nor armed by the absence of one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ClientIp {

	public const METHOD_DIRECT     = 'direct';
	public const METHOD_CLOUDFLARE = 'cloudflare';
	public const METHOD_PROXY      = 'trusted-proxy';

	/**
	 * A Cloudflare header this site has not vouched for. The claim is used —
	 * shown, and truncated into the log — while enforcement counts it together
	 * with the address it arrived from. See the file header.
	 */
	public const METHOD_CLOUDFLARE_UNCONFIRMED = 'cloudflare-unconfirmed';

	/**
	 * How much larger a shared bucket's cap is than a per-source one.
	 *
	 * A per-source cap denies one caller their own share. A shared one denies
	 * everybody at once, so it has to be set high enough that a site with
	 * this topology and real traffic never reaches it in ordinary use.
	 */
	public const SHARED_BUCKET_FACTOR = 20;

	/**
	 * Cloudflare's published egress ranges (www.cloudflare.com/ips, read
	 * 16 August 2026). Shipped rather than fetched — this plugin makes no
	 * external calls — and revisited at every gate like every other shipped
	 * fact. A connection from inside these ranges came through Cloudflare's
	 * network — which is necessary for CF-Connecting-IP to be believed, and
	 * not sufficient: see the file header for the statement the owner makes.
	 */
	private const CLOUDFLARE_RANGES = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Resolve the client address for this request.
	 *
	 * @param string[] $trusted_proxies Owner-configured CIDR ranges whose
	 *                                  forward headers are believed.
	 * @param bool     $cloudflare      Whether the owner has said this site is
	 *                                  behind Cloudflare.
	 * @return array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string}
	 */
	public static function resolve( array $trusted_proxies = array(), bool $cloudflare = false ): array {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- addresses are validated with inet_pton below; nothing is stored or echoed raw.
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$cf     = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? (string) $_SERVER['HTTP_CF_CONNECTING_IP'] : '';
		$xff    = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? (string) $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
		// phpcs:enable

		return self::resolve_from( $remote, $cf, $xff, $trusted_proxies, $cloudflare );
	}

	/**
	 * The resolution itself, taking its inputs as arguments so every branch
	 * is exercisable without forging a request.
	 *
	 * @param string[] $trusted_proxies
	 * @return array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string}
	 */
	public static function resolve_from( string $remote, string $cf_header, string $xff_header, array $trusted_proxies = array(), bool $cloudflare = false ): array {
		$remote  = self::valid( $remote );
		$headers = '' !== $cf_header || '' !== $xff_header;

		// Cloudflare: the header names the client when the connection comes
		// from Cloudflare's own ranges AND the owner has said this site is
		// behind Cloudflare. Without that statement the connection proves only
		// that something in those ranges is calling, so the two are paired.
		if ( '' !== $cf_header && null !== $remote && self::in_ranges( $remote, self::CLOUDFLARE_RANGES ) ) {
			$client = self::valid( $cf_header );

			if ( null !== $client ) {
				return self::edge_answer( $client, $remote, $cloudflare );
			}
		}

		// A reverse proxy in front of PHP: the connection comes from private
		// space or from a range the owner explicitly trusts. Walk the
		// forwarded chain from the right — the hop nearest us — skipping
		// every hop that is itself infrastructure (private, a trusted proxy,
		// or Cloudflare): the first hop that is none of those is the client
		// that proxy actually saw connect. A Cloudflare hop met on the way
		// means Cloudflare fronted the proxy, and its own header names the
		// client more reliably than the chain does.
		/*
		 * Only a range the OWNER named vouches for a forwarding header.
		 *
		 * A private REMOTE_ADDR used to be enough on its own, and that was a
		 * hole rather than a shortcut: PHP sees a private address on most
		 * containerized and php-fpm hosts, so on those an attacker could send
		 * `X-Forwarded-For: <anything>`, be believed confidently, and rotate the
		 * value to make every failed sign-in look like a different client — the
		 * lockout never accumulating against any of them. Nothing about a
		 * private connecting address says a proxy set that header; it only says
		 * PHP is not on the edge.
		 *
		 * The reverse reading — trust nothing and lock on the proxy's own
		 * address — is worse, because every visitor then shares one sentence.
		 * That case is handled below by declining to be confident at all, which
		 * the lockout reads as "not a basis for locking anyone out".
		 */
		$local_proxy = null !== $remote && array() !== $trusted_proxies && self::in_ranges( $remote, $trusted_proxies );

		if ( '' !== $xff_header && $local_proxy ) {
			$hops = array_map( 'trim', explode( ',', $xff_header ) );

			for ( $i = count( $hops ) - 1; $i >= 0; $i-- ) {
				$hop = self::hop( $hops[ $i ] );

				/*
				 * An entry that cannot be read ends the walk rather than
				 * being stepped over. Everything to the left of a hop is
				 * text an earlier party wrote, and the only reason to
				 * believe any of it is that the hops to its right were
				 * written by infrastructure entitled to write them. Once one
				 * of those cannot be read that chain is broken, and walking
				 * on hands the answer to whoever supplied the next entry —
				 * which on a proxy that writes a port or a placeholder is
				 * the attacker, confidently, on every request.
				 *
				 * Stopping answers unconfident, which the lockout already
				 * reads as "not a basis for locking anyone out" and counts
				 * by the connecting address instead.
				 */
				if ( null === $hop ) {
					break;
				}

				if ( self::is_private( $hop ) ) {
					continue;
				}

				if ( self::in_ranges( $hop, self::CLOUDFLARE_RANGES ) ) {
					$client = '' !== $cf_header ? self::valid( $cf_header ) : null;
					if ( null !== $client ) {
						// Paired with the hop rather than with the connecting
						// address: the named proxy wrote that hop from what it
						// saw, so it is the one entry in the chain the request
						// did not choose. Pairing with the proxy itself would
						// be pairing with a constant, which is no pairing.
						return self::edge_answer( $client, $hop, $cloudflare );
					}
					continue;
				}

				if ( array() !== $trusted_proxies && self::in_ranges( $hop, $trusted_proxies ) ) {
					continue;
				}

				return self::answer( $hop, self::METHOD_PROXY, true );
			}
		}

		/*
		 * The owner named this address as a proxy, and nothing arrived with
		 * the connection that names the client it is carrying — nginx's
		 * `proxy_pass` adds no forwarding header unless it is configured to,
		 * so naming the proxy and never seeing a header is an ordinary
		 * pairing rather than a contradiction.
		 *
		 * The connecting address is then not a client, and the owner is the
		 * one who said so. Answering with it confidently gave every visitor
		 * behind that proxy a single identity, which a handful of failures by
		 * any one of them closed the site against — including the owner.
		 * Reported, and never a basis for acting against anybody.
		 */
		if ( $local_proxy ) {
			return self::answer( (string) $remote, self::METHOD_DIRECT, false, $headers );
		}

		/*
		 * PHP is not on the edge, and nothing vouches for whatever claims to
		 * say who is: the topology is genuinely unresolvable from here.
		 * Answering with the connecting address would be answering with the
		 * proxy, and locking that address locks every visitor behind it —
		 * including the owner. So the address is reported and the answer is
		 * explicitly NOT confident, which the lockout reads as "never a basis
		 * for locking anyone out".
		 *
		 * Whether a header arrived is not part of the question, in either
		 * direction. A proxy adds one only where it is configured to, so
		 * requiring one left the topology that strips them answering
		 * confidently — and mass-locking on the one address it has. While a
		 * header could make the difference, sending one was also a one-line
		 * way to stand the lockout down on any host where PHP sees a private
		 * address, which is most of them.
		 *
		 * The site loses lockouts until the owner names their proxy under
		 * Login & Access, which the screen tells them; it does not gain a
		 * lockout that any attacker can step around, and it never mass-locks.
		 * A site that really is one machine loses lockouts it has no second
		 * visitor to apply.
		 */
		if ( null !== $remote && self::is_private( $remote ) ) {
			return self::answer( $remote, self::METHOD_DIRECT, false, $headers );
		}

		// Everything else is the connecting address itself. Forwarding
		// headers that arrived on a connection nothing vouches for are noted
		// and ignored — see the file header for why they never stand anything
		// down.
		return self::answer( (string) $remote, self::METHOD_DIRECT, null !== $remote, $headers );
	}

	/**
	 * The Cloudflare answer, with or without the owner's voucher.
	 *
	 * @param string $client     The address the header names.
	 * @param string $connecting The address entitled to set it, as seen here.
	 * @param bool   $vouched    Whether the owner has said this site is behind Cloudflare.
	 * @return array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string}
	 */
	private static function edge_answer( string $client, string $connecting, bool $vouched ): array {
		if ( $vouched ) {
			return self::answer( $client, self::METHOD_CLOUDFLARE, true );
		}

		return self::answer( $client, self::METHOD_CLOUDFLARE_UNCONFIRMED, true, false, $connecting );
	}

	/**
	 * @return array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string}
	 */
	private static function answer( string $ip, string $method, bool $confident, bool $ignored_headers = false, ?string $paired_with = null ): array {
		return array(
			'ip'              => $ip,
			'method'          => $method,
			'confident'       => $confident,
			'ignored_headers' => $ignored_headers,
			'paired_with'     => $paired_with,
		);
	}

	/**
	 * Where a per-source cap actually counts this request, and the cap it
	 * counts against.
	 *
	 * A cap keyed on the resolved address is a per-source cap only while that
	 * address identifies a source. Where the topology is unresolvable — PHP
	 * behind a proxy nobody has named, which is the ordinary state of a
	 * containerized host — every visitor resolves to the same address, and
	 * keying on it puts all of them in one bucket. A few dozen anonymous
	 * requests then exhaust it for everybody, renewably: the site loses the
	 * door rather than the flood losing it.
	 *
	 * The lockout and the sign-in puzzle answer that by standing down, which
	 * they can afford because something slower still bounds the same abuse.
	 * These caps cannot stand down — they are the only thing bounding what an
	 * unauthenticated request may write — so an unresolved topology counts in
	 * one site-wide bucket with a proportionally larger cap instead. Nobody
	 * is singled out, and the total written is bounded harder than one bucket
	 * per claimed source ever bounded it.
	 *
	 * @param array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string} $resolved
	 * @param string $prefix Key prefix for this purpose; also the unresolved site-wide bucket.
	 * @return array{key: string, cap: int, shared: bool}
	 */
	public static function rate_bucket( array $resolved, string $prefix, int $cap ): array {
		$confident = ! empty( $resolved['confident'] );
		$shared = ! $confident || ! empty( $resolved['paired_with'] );
		$key = $prefix . '_' . substr( self::hmac( self::volume_source( $resolved ) ), 0, 32 );

		return array(
			'key'    => $confident ? $key : $prefix,
			'cap'    => $shared ? $cap * self::SHARED_BUCKET_FACTOR : $cap,
			'shared' => $shared,
		);
	}

	/**
	 * The connection to count for volume, distinct from a paired lockout.
	 * Coalescers use this too, keeping their existing key format and windows.
	 *
	 * @param array{ip: string, paired_with?: ?string} $resolved
	 */
	public static function volume_source( array $resolved ): string {
		return (string) ( ! empty( $resolved['paired_with'] ) ? $resolved['paired_with'] : $resolved['ip'] );
	}

	/**
	 * The identity an address counts under. IPv4 counts per address. IPv6
	 * counts per /64 — the network a household or a phone holds — because a
	 * single client can move through the whole 2^64 space beneath it at will,
	 * and counting per address would let it start every burst fresh. The same
	 * truncation the display already uses.
	 */
	public static function identity( string $ip ): string {
		if ( ! str_contains( $ip, ':' ) ) {
			return $ip;
		}

		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input keeps the literal.

		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return $ip;
		}

		// ::ffff:a.b.c.d is an IPv4 address in IPv6 clothing, and it is what a
		// dual-stack host — an ordinary default — hands PHP for every IPv4
		// visitor. Truncated as IPv6 it collapses all of them onto ::/64, so
		// one bot getting a password wrong five times would lock out every
		// IPv4 client on the internet, the site's owner included. It counts as
		// the IPv4 address it is. The display already knew this; the decision
		// did not, which is why the screen named an innocent network.
		$unmapped = Ip::unmapped( $packed );

		if ( null !== $unmapped ) {
			return $unmapped;
		}

		$network = substr( $packed, 0, 8 ) . str_repeat( "\0", 8 );

		return (string) inet_ntop( $network ) . '/64';
	}

	/**
	 * Keyed digest of an address, for matching without storing. The key is
	 * plugin-held and independent of the salts (which this plugin can itself
	 * rotate — lockouts must not evaporate when keys do).
	 */
	public static function hmac( string $ip ): string {
		return hash_hmac( 'sha256', self::identity( $ip ), self::signing_secret() );
	}

	/**
	 * The key a lockout, a failure count or a release is filed under.
	 *
	 * Ordinarily the client's own identity. Where the answer carries a pair —
	 * a Cloudflare header on a site nobody has vouched for — it is both halves
	 * together, so the run of failures accumulates against "this edge address
	 * carrying this claim" rather than against the claim alone. A request from
	 * elsewhere in those ranges cannot then aim a lockout at an address it
	 * names, and a lockout earned by one pair does not close the door on
	 * everybody the same edge forwards.
	 *
	 * Each half goes through identity() before they are joined. Joining first
	 * would hand identity() a string inet_pton cannot read, and an IPv6 client
	 * would count per address instead of per /64 — a fresh count for every one
	 * of the 2^64 addresses beneath it.
	 *
	 * @param array{ip: string, paired_with?: ?string} $resolved
	 */
	public static function lockout_hmac( array $resolved ): string {
		$ip     = (string) ( $resolved['ip'] ?? '' );
		$paired = isset( $resolved['paired_with'] ) ? (string) $resolved['paired_with'] : '';

		if ( '' === $paired ) {
			return self::hmac( $ip );
		}

		return hash_hmac( 'sha256', self::identity( $paired ) . '|' . self::identity( $ip ), self::signing_secret() );
	}

	/**
	 * The plugin-held key, created on first use.
	 *
	 * Public because it is not only addresses that need a key the salts cannot
	 * rotate out from under: anything this plugin signs and expects to still
	 * verify after `auth_keys` has been applied needs the same property.
	 */
	public static function signing_secret(): string {
		$secret = get_option( 'bettershield_ip_secret' );

		if ( ! is_string( $secret ) || '' === $secret ) {
			$secret = bin2hex( random_bytes( 32 ) );
			// Autoloaded: read on every login attempt.
			update_option( 'bettershield_ip_secret', $secret, true );
		}

		return $secret;
	}

	/**
	 * Whether an answer that is not a basis for lockouts comes from a proxy
	 * the owner named that sent no forwarding header, rather than from an
	 * address nothing names.
	 *
	 * Both stand lockouts down, and they ask for different things: the first
	 * proxy has to be configured to say who it is carrying, the second has to
	 * be named. Telling an owner whose proxy is already named to name it is
	 * advice they cannot act on.
	 *
	 * @param array{confident: bool, ignored_headers: bool} $resolved What `resolve()` answered.
	 * @param string                                       $remote   The connecting address.
	 * @param string[]                                     $trusted_proxies
	 */
	public static function named_proxy_without_header( array $resolved, string $remote, array $trusted_proxies ): bool {
		return ! $resolved['confident']
			&& ! $resolved['ignored_headers']
			&& '' !== $remote
			&& array() !== $trusted_proxies
			&& self::in_ranges( $remote, $trusted_proxies );
	}

	/**
	 * Whether an answer that is not a basis for lockouts comes from a proxy
	 * the owner named whose forwarding header arrived and names no visitor
	 * this site can use: every hop in it private, or one that cannot be read
	 * (a placeholder such as `unknown`) before any that can.
	 *
	 * The proxy is named and it does send a header, so neither "name it" nor
	 * "send one" is advice the owner can act on. What it writes has to change.
	 *
	 * @param array{confident: bool, ignored_headers: bool} $resolved What `resolve()` answered.
	 * @param string                                       $remote   The connecting address.
	 * @param string[]                                     $trusted_proxies
	 */
	public static function named_proxy_without_visitor( array $resolved, string $remote, array $trusted_proxies ): bool {
		return ! $resolved['confident']
			&& $resolved['ignored_headers']
			&& '' !== $remote
			&& array() !== $trusted_proxies
			&& self::in_ranges( $remote, $trusted_proxies );
	}

	/**
	 * Whether an address sits inside any of the CIDR ranges. Bare addresses
	 * count as single-address ranges.
	 *
	 * @param string[] $ranges
	 */
	public static function in_ranges( string $ip, array $ranges ): bool {
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input answers false, not a warning.

		if ( false === $packed ) {
			return false;
		}

		/*
		 * An IPv4 address in IPv6 clothing is matched as the IPv4 address it
		 * is. A mapped address packs to sixteen bytes and every range an owner
		 * writes for it packs to four, so without this the length guard below
		 * skips every IPv4 range and the address matches nothing at all.
		 */
		$unmapped = Ip::unmapped( $packed );

		if ( null !== $unmapped ) {
			$repacked = @inet_pton( $unmapped ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

			if ( false !== $repacked ) {
				$packed = $repacked;
			}
		}

		foreach ( $ranges as $range ) {
			$range = trim( (string) $range );

			if ( '' === $range ) {
				continue;
			}

			if ( ! str_contains( $range, '/' ) ) {
				$single = @inet_pton( $range ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false !== $single && $single === $packed ) {
					return true;
				}
				continue;
			}

			list( $base, $bits ) = explode( '/', $range, 2 );

			$base_packed = @inet_pton( trim( $base ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$bits        = (int) $bits;

			if ( false === $base_packed || strlen( $base_packed ) !== strlen( $packed ) ) {
				continue;
			}

			if ( $bits < 0 || $bits > strlen( $packed ) * 8 ) {
				continue;
			}

			$bytes = intdiv( $bits, 8 );
			$rem   = $bits % 8;

			if ( 0 !== $bytes && substr( $packed, 0, $bytes ) !== substr( $base_packed, 0, $bytes ) ) {
				continue;
			}

			if ( 0 === $rem ) {
				return true;
			}

			$mask = 0xFF << ( 8 - $rem ) & 0xFF;

			if ( ( ord( $packed[ $bytes ] ) & $mask ) === ( ord( $base_packed[ $bytes ] ) & $mask ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a valid CIDR range or bare address. For validating owner input.
	 */
	public static function valid_range( string $range ): bool {
		$range = trim( $range );

		if ( '' === $range ) {
			return false;
		}

		if ( ! str_contains( $range, '/' ) ) {
			return null !== self::valid( $range );
		}

		list( $base, $bits ) = explode( '/', $range, 2 );

		$base = self::valid( trim( $base ) );

		if ( null === $base || ! is_numeric( $bits ) ) {
			return false;
		}

		$max = str_contains( $base, ':' ) ? 128 : 32;

		return (int) $bits >= 0 && (int) $bits <= $max;
	}

	private static function valid( string $ip ): ?string {
		$ip = trim( $ip );

		return false === filter_var( $ip, FILTER_VALIDATE_IP ) ? null : $ip;
	}

	/**
	 * One forwarded hop, as the address it names.
	 *
	 * Several widely deployed proxies write the source port into the header —
	 * `203.0.113.9:51234`, `[2001:db8::9]:51234` — and the bracketed form
	 * without a port is ordinary too. None of those passes a plain address
	 * validation, and an entry the proxy wrote that this could not read used
	 * to be stepped over as noise, which handed the answer to the entry
	 * before it.
	 *
	 * Null is kept for what it should mean: an entry that names no address at
	 * all, `unknown` and `_hidden` among them.
	 */
	private static function hop( string $value ): ?string {
		$value = trim( $value );

		if ( '' === $value ) {
			return null;
		}

		if ( '[' === $value[0] ) {
			$close = strpos( $value, ']' );
			$value = false === $close ? $value : substr( $value, 1, $close - 1 );
		} elseif ( 1 === substr_count( $value, ':' ) ) {
			// One colon is a port on an IPv4 address; an IPv6 address has
			// more, and a bracketed one was handled above.
			$value = substr( $value, 0, (int) strpos( $value, ':' ) );
		}

		return self::valid( $value );
	}

	private static function is_private( string $ip ): bool {
		// An IPv4 address in IPv6 clothing is judged as the IPv4 address it
		// is. Newer PHP counts the whole mapped range as reserved, which
		// would make every IPv4 visitor of a dual-stack server — the
		// ordinary default — an address the site cannot attribute, and stand
		// the lockout down for all of them.
		$packed = inet_pton( $ip );

		if ( false !== $packed ) {
			$unmapped = Ip::unmapped( $packed );

			if ( null !== $unmapped ) {
				$ip = $unmapped;
			}
		}

		return false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}
}
