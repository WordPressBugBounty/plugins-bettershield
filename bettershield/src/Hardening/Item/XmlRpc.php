<?php
/**
 * Hardening item: turn off XML-RPC, or only its pingbacks.
 *
 * The whole endpoint is the stronger answer, and the default. It is also the
 * one a site that needs XML-RPC cannot take: Jetpack and the mobile apps sign
 * in through it. Those sites kept `pingback.ping` open, the method a stranger
 * calls to make this site fetch an address of their choosing, and nothing
 * counted it, because it is not a sign-in. "Pingbacks only" removes the two
 * pingback methods and stops advertising them, and leaves every other method
 * where WordPress put it.
 *
 * Trackbacks (`wp-trackback.php`) are a separate path, and neither choice
 * touches them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class XmlRpc {

	/** The whole endpoint: the default, and what the item always did. */
	public const SCOPE_ALL = 'all';

	/** Only the pingback methods and what advertises them. */
	public const SCOPE_PINGBACKS = 'pingbacks';

	/**
	 * The whole endpoint, except for connections from Jetpack's servers: a
	 * Jetpack site can turn XML-RPC off for everybody else (#1978).
	 */
	public const SCOPE_JETPACK = 'jetpack';

	/**
	 * The ranges Jetpack publishes for its servers (jetpack.com/ips-v4.txt;
	 * there is no IPv6 list), moved in a release when they change. A range
	 * added between releases is refused until the next one, which the item
	 * says, and pingbacks only is the way out.
	 */
	public const JETPACK_RANGES = array(
		'122.248.245.244/32',
		'54.217.201.243/32',
		'54.232.116.4/32',
		'192.0.80.0/20',
		'192.0.96.0/20',
		'192.0.112.0/20',
		'195.234.108.0/22',
		'192.0.64.0/18',
	);

	/** The methods another site calls to ping this one, as core names them. */
	public const PINGBACK_METHODS = array( 'pingback.ping', 'pingback.extensions.getPingbacks' );

	/** The header that marks a refusal as this plugin's; the XML-RPC probe reads it. */
	public const REFUSED_HEADER = 'X-BetterShield-Refused';

	/**
	 * Whether the RSD discovery link was hooked when the whole endpoint was
	 * turned off, so undo puts it back only if this took it away.
	 */
	private static bool $rsd_link_removed = false;

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'scope',
				'label'       => __( 'What to turn off', 'bettershield' ),
				'description' => __( 'Using Jetpack? Choose Everything except Jetpack. Using the WordPress mobile app? Choose Only link notifications from other sites.', 'bettershield' ),
				'required'    => true,
				// On a Jetpack site the whole endpoint would cut Jetpack off.
				'default'     => class_exists( 'Jetpack' ) || defined( 'JETPACK__VERSION' ) ? self::SCOPE_JETPACK : self::SCOPE_ALL,
				'choices'     => array(
					array(
						'value' => self::SCOPE_ALL,
						'label' => __( 'Everything', 'bettershield' ),
						// "How this works" for the choice that is picked, before it is applied.
						'how'   => __( 'Blocks all access to xmlrpc.php.', 'bettershield' ),
					),
					array(
						'value' => self::SCOPE_JETPACK,
						'label' => __( 'Everything except Jetpack', 'bettershield' ),
						'how'   => __( 'Blocks all access to xmlrpc.php, except from Jetpack’s published server addresses.', 'bettershield' ),
					),
					array(
						'value' => self::SCOPE_PINGBACKS,
						'label' => __( 'Only link notifications from other sites (pingbacks)', 'bettershield' ),
						'how'   => __( 'Removes the pingback methods from XML-RPC, so other sites can no longer ping this one.', 'bettershield' ),
					),
				),
			),
		);
	}

	/**
	 * The whole endpoint is stored as no options at all, which is how it was
	 * stored before there was a choice: a site that applied it then, and
	 * every caller that names no scope, reads the same state as before.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate( array $options ) {
		$scope = isset( $options['scope'] ) && '' !== $options['scope'] ? (string) $options['scope'] : self::SCOPE_ALL;

		if ( ! in_array( $scope, array( self::SCOPE_ALL, self::SCOPE_JETPACK, self::SCOPE_PINGBACKS ), true ) ) {
			return new \WP_Error( 'bettershield_bad_xmlrpc_scope', __( 'Choose all of XML-RPC, all except Jetpack, or pingbacks only.', 'bettershield' ) );
		}

		/*
		 * Jetpack is recognized by the address it connects from. Where this
		 * site cannot tell a visitor's address with confidence (a proxy in
		 * front of it that is not named), nothing would match, and Jetpack
		 * would be refused with everybody else: refused here, as a lockout
		 * refuses an address it cannot be sure of.
		 */
		if ( self::SCOPE_JETPACK === $scope && ! self::client()['confident'] ) {
			return new \WP_Error( 'bettershield_xmlrpc_unconfident', __( 'This site can’t read visitors’ real addresses yet, so it can’t recognize Jetpack. Add your CDN or proxy under Login & Access, or choose pingbacks only.', 'bettershield' ) );
		}

		if ( self::SCOPE_ALL === $scope ) {
			return array();
		}

		return array( 'scope' => $scope );
	}

	/**
	 * @param array<string, mixed> $options Validated or stored options.
	 */
	public static function pingbacks_only( array $options ): bool {
		return self::SCOPE_PINGBACKS === ( $options['scope'] ?? '' );
	}

	/**
	 * @param array<string, mixed> $options Validated or stored options.
	 */
	public static function jetpack_only( array $options ): bool {
		return self::SCOPE_JETPACK === ( $options['scope'] ?? '' );
	}

	/**
	 * This request's client, as the sign-in protections resolve it.
	 *
	 * @return array{ip: string, confident: bool}
	 */
	private static function client(): array {
		$settings = \BetterShield\Login\Protection::instance()->settings();
		$resolved = \BetterShield\Support\ClientIp::resolve( (array) $settings['trusted_proxies'], (bool) $settings['cloudflare'] );

		return array(
			'ip'        => (string) $resolved['ip'],
			'confident' => ! empty( $resolved['confident'] ),
		);
	}

	/**
	 * Whether this request comes from one of Jetpack's servers, by an address
	 * this site is sure of.
	 */
	public static function from_jetpack(): bool {
		$client = self::client();

		return $client['confident'] && '' !== $client['ip'] && \BetterShield\Support\ClientIp::in_ranges( $client['ip'], self::JETPACK_RANGES );
	}

	/**
	 * Whether an XML-RPC request body calls a pingback method, on its own or
	 * inside a system.multicall: what pingbacks only would have refused, for
	 * the monitor that counts it before anything is.
	 */
	public static function calls_pingback( string $body ): bool {
		if ( 1 === preg_match( '/<methodName>\s*pingback\./i', $body ) ) {
			return true;
		}

		// Inside a multicall each call's name is a value of its own struct.
		return false !== stripos( $body, 'system.multicall' )
			&& 1 === preg_match( '#<value>\s*(?:<string>)?\s*pingback\.(?:ping|extensions\.getPingbacks)\s*(?:</string>)?\s*</value>#i', $body );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();

		if ( self::jetpack_only( $options ) ) {
			return __( 'All except Jetpack. If Jetpack stops connecting, switch to pingbacks only.', 'bettershield' );
		}

		return self::pingbacks_only( $options )
			? __( 'Pingbacks only. Every other XML-RPC method still answers.', 'bettershield' )
			: null;
	}

	/**
	 * The choice in a few words, for a switch that otherwise reads as all of
	 * XML-RPC being off. Null for the default, which the title already says.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function scope( array $state ): ?string {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();

		if ( self::jetpack_only( $options ) ) {
			return __( 'all except Jetpack', 'bettershield' );
		}

		return self::pingbacks_only( $options ) ? __( 'pingbacks only', 'bettershield' ) : null;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();

		// Neither choice leaves the pingback advertised.
		add_filter( 'wp_headers', array( self::class, 'drop_pingback_header' ) );
		add_filter( 'bloginfo_url', array( self::class, 'blank_pingback_url' ), 10, 2 );

		if ( self::pingbacks_only( $options ) ) {
			add_filter( 'xmlrpc_methods', array( self::class, 'drop_pingback_methods' ) );

			return;
		}

		// Jetpack's own requests keep every method but the pingbacks;
		// everybody else is refused as under the whole endpoint.
		if ( self::jetpack_only( $options ) ) {
			add_filter( 'xmlrpc_methods', array( self::class, 'drop_pingback_methods' ) );
			self::$rsd_link_removed = remove_action( 'wp_head', 'rsd_link' );
			add_action( 'init', array( self::class, 'refuse_unless_jetpack' ), 0 );

			return;
		}

		// xmlrpc_enabled alone only disables the authenticated methods: the
		// endpoint keeps loading, keeps answering system.listMethods, and
		// keeps advertising itself. Each of those is closed here.
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );
		self::$rsd_link_removed = remove_action( 'wp_head', 'rsd_link' );
		// Priority 0: before anything on init could want the request.
		add_action( 'init', array( self::class, 'refuse_request' ), 0 );
	}

	/**
	 * Takes off what either choice put on: by the time an undo runs, the
	 * state that said which one it was may already be gone.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		remove_filter( 'wp_headers', array( self::class, 'drop_pingback_header' ) );
		remove_filter( 'bloginfo_url', array( self::class, 'blank_pingback_url' ), 10 );
		remove_filter( 'xmlrpc_methods', array( self::class, 'drop_pingback_methods' ) );
		remove_filter( 'xmlrpc_enabled', '__return_false' );
		remove_filter( 'xmlrpc_methods', '__return_empty_array' );

		if ( self::$rsd_link_removed ) {
			add_action( 'wp_head', 'rsd_link' );
			self::$rsd_link_removed = false;
		}

		remove_action( 'init', array( self::class, 'refuse_request' ), 0 );
		remove_action( 'init', array( self::class, 'refuse_unless_jetpack' ), 0 );
	}

	/**
	 * Answer the XML-RPC endpoint itself with 403.
	 *
	 * xmlrpc.php loads WordPress before it serves anything, so init runs first
	 * and this is the earliest place to refuse the request without a server
	 * rule. A scanner that probes the endpoint sees a refusal, not a method
	 * list — which is what "disabled" has to mean.
	 */
	public static function refuse_request(): void {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			self::refuse();
		}
	}

	/**
	 * The endpoint answered with 403, except for a request from Jetpack.
	 */
	public static function refuse_unless_jetpack(): void {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && ! self::from_jetpack() ) {
			self::refuse();
		}
	}

	/**
	 * The refusal itself, separate from the request check so the response can
	 * be exercised without defining a process-wide constant.
	 */
	public static function refuse(): void {
		status_header( 403 );
		nocache_headers();
		if ( ! headers_sent() ) {
			foreach ( self::refusal_headers() as $name => $value ) {
				header( $name . ': ' . $value );
			}
		}
		echo "XML-RPC is disabled on this site.\n";

		// wp_die() rather than exit: the XML-RPC handler still ends the request,
		// and the test suite can observe the refusal instead of losing the process.
		wp_die( '', '', array( 'response' => 403 ) );
	}

	/**
	 * The headers the refusal sends beside its status and the no-cache ones.
	 * Named here rather than inline, because the CLI the suite runs on keeps
	 * no list of sent headers, and the probe's reading of the last one is
	 * only as good as this still sending it.
	 *
	 * @return array<string, string>
	 */
	public static function refusal_headers(): array {
		return array(
			'Content-Type'       => 'text/plain; charset=utf-8',
			// Says the refusal is this plugin's, sent from inside WordPress,
			// so the XML-RPC probe never takes it for the web server's block.
			self::REFUSED_HEADER => 'xmlrpc',
		);
	}

	/**
	 * The two pingback methods out of the table, and nothing else.
	 *
	 * @param array<string, mixed> $methods
	 * @return array<string, mixed>
	 */
	public static function drop_pingback_methods( $methods ): array {
		$methods = is_array( $methods ) ? $methods : array();

		foreach ( self::PINGBACK_METHODS as $method ) {
			unset( $methods[ $method ] );
		}

		return $methods;
	}

	/**
	 * Stop advertising the pingback endpoint on every singular page.
	 *
	 * @param array<string, string> $headers
	 * @return array<string, string>
	 */
	public static function drop_pingback_header( $headers ): array {
		$headers = is_array( $headers ) ? $headers : array();

		unset( $headers['X-Pingback'] );

		return $headers;
	}

	/**
	 * Themes print the pingback URL into <head>; an empty one advertises
	 * nothing. Only the pingback URL is touched.
	 *
	 * This reaches only a theme that prints it through `bloginfo()`, the one
	 * route core filters. The default themes print the raw
	 * `get_bloginfo( 'pingback_url' )` and keep the address, which the item's
	 * effect lines say rather than promise the link is gone.
	 *
	 * @param string $output The URL.
	 * @param string $show   Which bloginfo value is being read.
	 */
	public static function blank_pingback_url( $output, $show ): string {
		return 'pingback_url' === $show ? '' : (string) $output;
	}
}
