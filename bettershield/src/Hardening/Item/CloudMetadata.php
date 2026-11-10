<?php
/**
 * Hardening item: refuse requests to cloud-metadata addresses.
 *
 * A cloud server answers a request to its metadata address with facts about
 * itself, and on several clouds with the credentials it runs under. Nothing
 * on the internet can reach that address; the server itself can. So a plugin
 * that fetches whatever address it is handed (an image importer, a link
 * preview, a webhook test) can be pointed at it, and made to hand the answer
 * back to whoever pointed it there.
 *
 * This refuses those requests when they go through the WordPress HTTP API,
 * whichever plugin makes them: the address written out, spelled another way,
 * or a name that resolves to it, and a redirect that leads there. It does not
 * refuse requests into the server's own network, where search, cache and
 * queue services live; it notes them in the activity log, once a day for each
 * destination and plugin, so the owner can see what talks to what.
 *
 * What it cannot see it does not claim to cover: a plugin that opens its own
 * connection goes around the HTTP API, and a name whose answer changes
 * between this check and the connection is a race the check cannot win.
 *
 * It is on from the update that added it, and from a new site's activation.
 * Like every item it has an undo, safe mode stands it down, and it stays off
 * the store's cart and checkout.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Writer;
use BetterShield\Hardening\Manager;
use BetterShield\Support\Checkout;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Http;
use BetterShield\Support\Ip;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CloudMetadata {

	public const ID = 'cloud_metadata';

	/**
	 * When this site had the block switched on for it, at activation or at
	 * the update that brought it. Read only where that can happen, never on
	 * an ordinary request.
	 */
	public const SEEDED_OPTION = 'bettershield_cloud_metadata_seeded';

	/**
	 * Destinations a host lets through for every site it runs, beside the
	 * owner's own list: host names, addresses or ranges.
	 */
	public const FILTER = 'bettershield_outbound_allowed';

	/** What a destination is, in the log's words. */
	public const KIND_METADATA = 'metadata';
	public const KIND_PRIVATE  = 'private';

	/**
	 * Late, so a request another filter has already answered (a cache, a
	 * test's stand-in) is not looked at: it was never going to leave.
	 */
	public const PRIORITY = PHP_INT_MAX - 1;

	/** Most destinations the owner may let through. */
	public const MAX_ALLOWED = 50;

	/**
	 * Where clouds answer with instance metadata and the credentials an
	 * instance or a container runs under: all of IPv4 and IPv6 link-local,
	 * which nothing a site fetches lives on, Alibaba Cloud's address, and the
	 * address EC2 answers on over IPv6.
	 */
	private const METADATA_RANGES = array( '169.254.0.0/16', 'fe80::/10', '100.100.100.200', 'fd00:ec2::254' );

	/** The names Google Cloud answers on, refused whatever they resolve to here. */
	private const METADATA_NAMES = array( 'metadata.google.internal', 'metadata.goog', 'metadata' );

	/**
	 * The server's own network: loopback, the private ranges, the
	 * carrier-grade NAT range several clouds use inside, and the unspecified
	 * addresses, which reach the server itself.
	 */
	private const PRIVATE_RANGES = array( '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '0.0.0.0/8', '::1', '::', 'fc00::/7' );

	/** @var array{names: string[], ranges: string[]} The owner's list, as the item was enforced. */
	private static array $allowed = array(
		'names'  => array(),
		'ranges' => array(),
	);

	/** @var array<string, string[]> What the resolver answered this request, by host. */
	private static array $resolved = array();

	/** @var array<string, bool> What this request has already put in the log. */
	private static array $noted = array();

	/* ---- the item ---------------------------------------------------------------- */

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'allow',
				'label'       => __( 'Addresses to allow', 'bettershield' ),
				'description' => __( 'Anything listed is let through and not logged.', 'bettershield' ),
				'placeholder' => 'search.internal, 10.0.0.0/24',
				'required'    => false,
				'default'     => '',
			),
		);
	}

	/**
	 * The owner's list, each entry as the item keeps it.
	 *
	 * @param array<string, mixed> $options
	 * @return array{allow: string[]}|\WP_Error
	 */
	public static function validate( array $options ) {
		$typed   = $options['allow'] ?? array();
		$entries = is_array( $typed ) ? $typed : (array) preg_split( '/[\s,]+/', is_scalar( $typed ) ? (string) $typed : '' );
		$allow   = array();

		foreach ( $entries as $entry ) {
			if ( ! is_scalar( $entry ) || '' === trim( (string) $entry ) ) {
				continue;
			}

			$destination = self::destination( (string) $entry );

			if ( null === $destination ) {
				return new \WP_Error(
					'bettershield_bad_destination',
					sprintf(
						/* translators: %s: what was typed, as typed. */
						__( '“%s” isn’t a valid address. Use a host name, an IP address or a range (no wider than /8, or /16 for IPv6), without wildcards.', 'bettershield' ),
						substr( wp_strip_all_tags( (string) $entry ), 0, 80 )
					)
				);
			}

			$allow[ $destination ] = true;
		}

		if ( count( $allow ) > self::MAX_ALLOWED ) {
			return new \WP_Error(
				'bettershield_too_many_destinations',
				sprintf(
					/* translators: %d: how many destinations may be listed. */
					__( 'At most %d destinations can be let through.', 'bettershield' ),
					self::MAX_ALLOWED
				)
			);
		}

		$allow = array_map( 'strval', array_keys( $allow ) );
		sort( $allow );

		return array( 'allow' => $allow );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();
		$list    = array(
			'names'  => array(),
			'ranges' => array(),
		);

		foreach ( (array) ( $options['allow'] ?? array() ) as $entry ) {
			$destination = is_scalar( $entry ) ? self::destination( (string) $entry ) : null;

			if ( null !== $destination ) {
				self::sort_into( $list, $destination );
			}
		}

		self::$allowed = $list;

		add_filter( 'pre_http_request', array( self::class, 'guard' ), self::PRIORITY, 3 );
		add_action( 'requests-requests.before_redirect', array( self::class, 'guard_redirect' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused; the hooks are the whole of it.
	 */
	public static function unenforce( array $state ): void {
		remove_filter( 'pre_http_request', array( self::class, 'guard' ), self::PRIORITY );
		remove_action( 'requests-requests.before_redirect', array( self::class, 'guard_redirect' ) );
	}

	/**
	 * Whether both hooks are still attached on this request. Switched on is
	 * not the same as working: another plugin's remove_filter() leaves the
	 * item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		return false !== has_filter( 'pre_http_request', array( self::class, 'guard' ) )
			&& false !== has_action( 'requests-requests.before_redirect', array( self::class, 'guard_redirect' ) );
	}

	/**
	 * Switch the block on once in this site's life: at the update that adds
	 * it, or at a new site's activation. Never again after that, so an owner
	 * who switched it off keeps it off through later updates, reactivations
	 * and repairs.
	 */
	public static function seed(): void {
		if ( false !== get_option( self::SEEDED_OPTION, false ) ) {
			return;
		}

		$manager = Manager::instance();

		// Applied here before, and perhaps switched off since: the owner's
		// choice, which nothing here overrules.
		if ( array() !== $manager->item_state( self::ID ) ) {
			update_option( self::SEEDED_OPTION, gmdate( 'Y-m-d H:i:s' ), false );

			return;
		}

		// Marked once it is on. A change refused for a busy state, or for an
		// undo row that could not be written, leaves it unmarked, so the next
		// activation tries again; the release panel reads whether it is on,
		// so an owner sees that it is not.
		if ( is_array( $manager->apply( self::ID ) ) ) {
			update_option( self::SEEDED_OPTION, gmdate( 'Y-m-d H:i:s' ), false );
		}
	}

	/**
	 * Forget what this request resolved and logged. Production never needs
	 * this; the test process is many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::$resolved = array();
		self::$noted    = array();
	}

	/* ---- the requests ------------------------------------------------------------ */

	/**
	 * Refuse a request on its way to a cloud-metadata address; note one on
	 * its way into the server's own network, and let it go.
	 *
	 * @param mixed $pre  What an earlier filter answered; false for nothing.
	 * @param mixed $args The request's arguments. Unused.
	 * @param mixed $url  Where it is going.
	 * @return mixed
	 */
	public static function guard( $pre, $args = array(), $url = '' ) {
		if ( false !== $pre || ! is_string( $url ) || '' === $url || Checkout::is_store_path( true ) ) {
			return $pre;
		}

		$verdict = self::judge( $url );

		if ( null === $verdict ) {
			return $pre;
		}

		$refused = self::KIND_METADATA === $verdict['kind'];

		self::note_unless_routine( $verdict, $refused );

		return $refused ? new \WP_Error( 'bettershield_cloud_metadata', self::refusal() ) : $pre;
	}

	/**
	 * The same question, asked of every redirect the HTTP library is about to
	 * follow: an address that answers "go to the metadata address instead" is
	 * the oldest way around a check made on the first hop only.
	 *
	 * @param mixed $location Where the answer says to go next.
	 * @throws \WpOrg\Requests\Exception When that is a cloud-metadata address.
	 */
	public static function guard_redirect( &$location ): void {
		if ( ! is_string( $location ) || '' === $location || Checkout::is_store_path( true ) ) {
			return;
		}

		$verdict = self::judge( $location );

		if ( null === $verdict ) {
			return;
		}

		$refused = self::KIND_METADATA === $verdict['kind'];

		self::note_unless_routine( $verdict, $refused );

		if ( $refused ) {
			throw new \WpOrg\Requests\Exception( esc_html( self::refusal() ), 'bettershield.cloud_metadata' );
		}
	}

	/**
	 * What a destination is, or null where this item has nothing to say about
	 * it: the public internet, this site's own address, a host this plugin
	 * contacts itself, a destination let through, or a name with no address.
	 *
	 * @return array{kind: string, host: string, network: string, port: int}|null
	 */
	public static function judge( string $url ): ?array {
		$parts = wp_parse_url( $url );

		if ( ! is_array( $parts ) || ! isset( $parts['host'] ) ) {
			return null;
		}

		$host = rtrim( strtolower( trim( self::decoded( (string) $parts['host'] ), '[]' ) ), '.' );

		if ( '' === $host || isset( Http::ALLOWED[ $host ] ) || self::is_this_site( $host ) ) {
			return null;
		}

		$allowed = self::allow_list();

		if ( in_array( $host, $allowed['names'], true ) ) {
			return null;
		}

		$verdict = array(
			'kind'    => '',
			// A name is kept as written; an address only as its network.
			'host'    => false === filter_var( $host, FILTER_VALIDATE_IP ) && null === self::numeric_v4( $host ) ? $host : '',
			'network' => '',
			'port'    => isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === strtolower( (string) ( $parts['scheme'] ?? '' ) ) ? 443 : 80 ),
		);

		if ( in_array( $host, self::METADATA_NAMES, true ) ) {
			$verdict['kind'] = self::KIND_METADATA;

			return $verdict;
		}

		foreach ( self::addresses( $host ) as $address ) {
			if ( array() !== $allowed['ranges'] && ClientIp::in_ranges( $address, $allowed['ranges'] ) ) {
				continue;
			}

			$kind = self::kind_of( $address );

			// A refused address decides it; a private one stands until one does.
			if ( '' === $kind || ( self::KIND_PRIVATE === $kind && '' !== $verdict['kind'] ) ) {
				continue;
			}

			$verdict['kind']    = $kind;
			$verdict['network'] = (string) Ip::prefix_label( Ip::truncated_binary( $address ) );

			if ( self::KIND_METADATA === $kind ) {
				break;
			}
		}

		return '' === $verdict['kind'] ? null : $verdict;
	}

	/**
	 * A host as the connection reaches it. The HTTP library decodes a
	 * percent-encoded host before it connects, so %31%36%39.254.169.254 is
	 * 169.254.169.254 by the time anything is sent, and judged as written it
	 * was no name, no address and no numeric spelling, and went through
	 * (#1841). Decoded until nothing changes, a few times at most, so a host
	 * encoded twice over is judged as what it finally stands for.
	 */
	private static function decoded( string $host ): string {
		for ( $round = 0; $round < 4 && str_contains( $host, '%' ); $round++ ) {
			$next = rawurldecode( $host );

			if ( $next === $host ) {
				break;
			}

			$host = $next;
		}

		/*
		 * Up to the first control character, which is where anything reading
		 * the name as a C string stops: a NUL handed on to the resolver ended
		 * the request in an error rather than in a verdict, and the part
		 * before it is what a connection would reach.
		 */
		$host = (string) preg_replace( '/[\x00-\x1f\x7f].*$/s', '', $host );

		// A name outside ASCII goes out as the library encodes it, xn-- and all.
		if ( 1 === preg_match( '/[^\x00-\x7f]/', $host ) && class_exists( '\WpOrg\Requests\IdnaEncoder' ) ) {
			try {
				$host = \WpOrg\Requests\IdnaEncoder::encode( $host );
			} catch ( \Throwable $e ) {
				return $host;
			}
		}

		return $host;
	}

	/** Which kind of destination an address is: metadata, private, or '' for neither. */
	private static function kind_of( string $address ): string {
		if ( ClientIp::in_ranges( $address, self::METADATA_RANGES ) ) {
			return self::KIND_METADATA;
		}

		return ClientIp::in_ranges( $address, self::PRIVATE_RANGES ) ? self::KIND_PRIVATE : '';
	}

	/**
	 * Every address a host is reached at: itself when it is one, in whatever
	 * spelling, otherwise what the resolver answers.
	 *
	 * @return string[]
	 */
	private static function addresses( string $host ): array {
		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( self::unwrapped( $host ) );
		}

		$numeric = self::numeric_v4( $host );

		if ( null !== $numeric ) {
			return array( $numeric );
		}

		if ( ! isset( self::$resolved[ $host ] ) ) {
			// Bounded: a request that asks for a great many hosts keeps the
			// answers it is still using rather than all of them.
			if ( count( self::$resolved ) >= 64 ) {
				self::$resolved = array();
			}

			self::$resolved[ $host ] = self::resolve( $host );
		}

		return self::$resolved[ $host ];
	}

	/**
	 * What the resolver answers for a name: every IPv4 address, or where there
	 * is none, every IPv6 one. Nothing where it answers nothing, or where the
	 * host has the lookups switched off.
	 *
	 * @return string[]
	 */
	private static function resolve( string $host ): array {
		$found = function_exists( 'gethostbynamel' ) ? @gethostbynamel( $host ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a name that does not resolve is answered as no address, not as a warning.
		$found = is_array( $found ) ? array_map( 'strval', $found ) : array();

		if ( array() === $found && function_exists( 'dns_get_record' ) ) {
			$records = @dns_get_record( $host, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the same.

			foreach ( is_array( $records ) ? $records : array() as $record ) {
				if ( is_array( $record ) && isset( $record['ipv6'] ) ) {
					$found[] = (string) $record['ipv6'];
				}
			}
		}

		return array_values( array_unique( array_map( static fn( string $address ): string => self::unwrapped( $address ), $found ) ) );
	}

	/**
	 * The IPv4 address a host written one of the old numeric ways stands for,
	 * or null for a host that is not one: 2852039166, 0xa9fea9fe,
	 * 0251.0376.0251.0376 and 169.254.43518 are all 169.254.169.254 to the
	 * resolver and to the connection, so they are to this as well.
	 */
	private static function numeric_v4( string $host ): ?string {
		if ( 1 !== preg_match( '/^(?:0x[0-9a-f]*|\d+)(?:\.(?:0x[0-9a-f]*|\d+)){0,3}$/i', $host ) ) {
			return null;
		}

		$values = array();

		foreach ( explode( '.', $host ) as $part ) {
			if ( 0 === strncasecmp( $part, '0x', 2 ) ) {
				$values[] = '' === substr( $part, 2 ) ? 0 : hexdec( substr( $part, 2 ) );
			} elseif ( strlen( $part ) > 1 && '0' === $part[0] ) {
				if ( 1 !== preg_match( '/^[0-7]+$/', $part ) ) {
					return null;
				}

				$values[] = octdec( $part );
			} else {
				$values[] = (float) $part;
			}
		}

		$last  = array_pop( $values );
		$limit = array( 0xFFFFFFFF, 0xFFFFFF, 0xFFFF, 0xFF )[ count( $values ) ];

		if ( $last > $limit ) {
			return null;
		}

		$address = 0;

		foreach ( $values as $index => $value ) {
			if ( $value > 0xFF ) {
				return null;
			}

			$address |= (int) $value << ( 24 - 8 * $index );
		}

		return long2ip( $address | (int) $last );
	}

	/**
	 * An address as the connection reads it: one that carries an IPv4 address
	 * inside an IPv6 one (mapped, translated, NAT64, 6to4, or the old
	 * compatible form) is that IPv4 address.
	 */
	private static function unwrapped( string $address ): string {
		$packed = @inet_pton( $address ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an address that will not parse is answered as written.

		if ( false === $packed || 16 !== strlen( $packed ) ) {
			return $address;
		}

		$mapped = Ip::unmapped( $packed );

		if ( null !== $mapped ) {
			return $mapped;
		}

		$prefix = substr( $packed, 0, 12 );
		$tail   = substr( $packed, 12, 4 );
		$zeros  = str_repeat( "\x00", 8 );

		if ( 0 === strncmp( $packed, "\x20\x02", 2 ) ) {
			// 2002::/16, 6to4: the address follows the prefix.
			$embedded = substr( $packed, 2, 4 );
		} elseif (
			"\x00\x64\xff\x9b" . $zeros === $prefix // 64:ff9b::/96, NAT64.
			|| "\x00\x64\xff\x9b\x00\x01" . str_repeat( "\x00", 6 ) === $prefix // 64:ff9b:1::/96, local-use NAT64.
			|| $zeros . "\xff\xff\x00\x00" === $prefix // ::ffff:0:a.b.c.d, IPv4-translated.
			|| ( $zeros . "\x00\x00\x00\x00" === $prefix && ! in_array( $tail, array( "\x00\x00\x00\x00", "\x00\x00\x00\x01" ), true ) ) // ::a.b.c.d, IPv4-compatible.
		) {
			$embedded = $tail;
		} else {
			return $address;
		}

		$v4 = inet_ntop( $embedded );

		return is_string( $v4 ) ? $v4 : $address;
	}

	/** Whether a host is this site's own, which WordPress asks to run its schedule and to check itself. */
	private static function is_this_site( string $host ): bool {
		foreach ( array( home_url(), site_url() ) as $own ) {
			if ( rtrim( strtolower( (string) wp_parse_url( $own, PHP_URL_HOST ) ), '.' ) === $host ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * What may be reached whatever it is: the owner's list, as the item was
	 * enforced, and what the host adds for every site it runs.
	 *
	 * @return array{names: string[], ranges: string[]}
	 */
	private static function allow_list(): array {
		$list  = self::$allowed;
		$added = apply_filters( self::FILTER, array() ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- self::FILTER is 'bettershield_outbound_allowed'.

		foreach ( is_array( $added ) ? $added : array() as $entry ) {
			$destination = is_scalar( $entry ) ? self::destination( (string) $entry ) : null;

			if ( null !== $destination ) {
				self::sort_into( $list, $destination );
			}
		}

		return $list;
	}

	/**
	 * One destination as the list keeps it, or null where it is none: a host
	 * name, an address, or a range no wider than a /8 (a /16 for IPv6).
	 */
	private static function destination( string $typed ): ?string {
		$typed = rtrim( strtolower( trim( $typed ) ), '.' );

		if ( '' === $typed || str_contains( $typed, '*' ) ) {
			return null;
		}

		if ( str_contains( $typed, '/' ) ) {
			list( $base, $bits ) = explode( '/', $typed, 2 );

			$packed = @inet_pton( trim( $base, '[]' ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- what is not an address is refused below, not warned about.

			if ( false === $packed || 1 !== preg_match( '/^\d{1,3}$/', $bits ) ) {
				return null;
			}

			$v4 = 4 === strlen( $packed );

			if ( (int) $bits < ( $v4 ? 8 : 16 ) || (int) $bits > ( $v4 ? 32 : 128 ) ) {
				return null;
			}

			return (string) inet_ntop( $packed ) . '/' . (int) $bits;
		}

		$address = trim( $typed, '[]' );

		if ( false !== filter_var( $address, FILTER_VALIDATE_IP ) ) {
			$packed = inet_pton( $address );

			return false === $packed ? null : (string) inet_ntop( $packed );
		}

		return 1 === preg_match( '/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/', $typed ) ? $typed : null;
	}

	/**
	 * @param array{names: string[], ranges: string[]} $list
	 */
	private static function sort_into( array &$list, string $destination ): void {
		$address = str_contains( $destination, '/' ) || false !== filter_var( $destination, FILTER_VALIDATE_IP );

		$list[ $address ? 'ranges' : 'names' ][] = $destination;
	}

	/**
	 * Note a refusal always, and a request into the server's own network
	 * everywhere but a visitor's page view. Noting asks the database twice,
	 * and a site whose search runs on a server in its own network would pay
	 * that on every search page; the dashboard, a scheduled task, the REST
	 * API and the command line still note it, so it is seen all the same.
	 *
	 * @param array{kind: string, host: string, network: string, port: int} $verdict
	 */
	private static function note_unless_routine( array $verdict, bool $refused ): void {
		if ( $refused || ! self::is_page_view() ) {
			self::note( $verdict, $refused );
		}
	}

	/**
	 * Whether this request is a visitor's page view: not the dashboard, a
	 * scheduled task, an AJAX call, the REST API or the command line.
	 */
	private static function is_page_view(): bool {
		return ! is_admin()
			&& ! wp_doing_cron()
			&& ! wp_doing_ajax()
			&& ! ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			&& ! ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * Say in the activity log that a request was refused, or that one went
	 * into the server's own network: once an hour for each refused
	 * destination and caller, once a day for each one let through, so a
	 * plugin that does this on every page view writes one line, not thousands.
	 *
	 * @param array{kind: string, host: string, network: string, port: int} $verdict
	 */
	private static function note( array $verdict, bool $refused ): void {
		$caller = self::caller();
		$key    = ( $refused ? 'refused' : 'internal' ) . '|' . $verdict['host'] . '|' . $verdict['network'] . '|' . $verdict['port'] . '|' . $caller;

		if ( isset( self::$noted[ $key ] ) ) {
			return;
		}

		self::$noted[ $key ] = true;

		if ( ! Claim::claim( 'outbound_' . md5( $key ), $refused ? HOUR_IN_SECONDS : DAY_IN_SECONDS ) ) {
			return;
		}

		Writer::instance()->record(
			$refused ? 'outbound_refused' : 'outbound_internal',
			$refused ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => self::ID,
				'context'     => array_filter(
					array(
						'kind'    => $verdict['kind'],
						'host'    => $verdict['host'],
						'network' => $verdict['network'],
						'port'    => $verdict['port'],
						'caller'  => $caller,
					),
					static fn( $value ): bool => '' !== $value
				),
			)
		);
	}

	/**
	 * The plugin, must-use plugin or theme whose code made the request, or
	 * `wordpress` for core's own. Asked only on the requests this item
	 * refuses or notes, and arguments are never read.
	 */
	private static function caller(): string {
		$roots = array(
			'plugin'    => trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ),
			'mu-plugin' => trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) ),
			'theme'     => trailingslashit( wp_normalize_path( get_theme_root() ) ),
		);
		$own   = trailingslashit( wp_normalize_path( BETTERSHIELD_PATH ) );

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- names the plugin behind a refused or noted request; arguments are left out and never read.
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 40 ) as $frame ) {
			$file = isset( $frame['file'] ) ? wp_normalize_path( (string) $frame['file'] ) : '';

			if ( '' === $file || str_starts_with( $file, $own ) ) {
				continue;
			}

			foreach ( $roots as $kind => $root ) {
				if ( str_starts_with( $file, $root ) ) {
					$slug = (string) strtok( substr( $file, strlen( $root ) ), '/' );

					return $kind . ':' . substr( (string) preg_replace( '/[^a-z0-9._-]/i', '', $slug ), 0, 64 );
				}
			}
		}

		return 'wordpress';
	}

	/**
	 * What the plugin whose request was refused is told, and passes on to
	 * whoever reads its error: why, and where it is let through.
	 */
	private static function refusal(): string {
		// Before init the translations may not be loaded; the reason is worth
		// more said plainly than not said at all.
		if ( ! did_action( 'init' ) ) {
			return 'BetterShield refused this request because it was going to a cloud-metadata address. If the plugin that made it needs that address, let it through under Protection > Hardening.';
		}

		return __( 'BetterShield refused this request to a cloud-metadata address. To allow it, add the address under Protection › Hardening.', 'bettershield' );
	}
}
