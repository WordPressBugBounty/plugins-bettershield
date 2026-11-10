<?php
/**
 * The only way out of this plugin to the network.
 *
 * Until now there was no way out at all, and the readme said so. That promise
 * changes shape here rather than disappearing: instead of "this plugin makes
 * no external requests", it becomes "this plugin talks to these hosts, for
 * these reasons, and to nothing else" — which is a promise a test can still
 * hold, and one the readme discloses under guideline 7.
 *
 * Every request goes through this class and every host it may reach is named
 * in ALLOWED below. A host that is not on the list is refused here rather than
 * attempted and failed, so adding an outbound call is a deliberate edit to a
 * short list somebody reviews, not an incidental consequence of writing a
 * feature.
 *
 * Three rules the callers inherit:
 *
 * - **Nothing about the site travels without the owner's yes.** These requests
 *   ask public questions — what are the published checksums for this version
 *   of this plugin — and carry no address, no email, no key and no identifier.
 *   The only site-shaped fact on the wire is which versions of which public
 *   software are installed, which is unavoidable in asking the question at
 *   all. The one question that is not about the site is the breached-password
 *   check, which sends the first five characters of the hash of a password
 *   somebody is choosing: several hundred published hashes come back and the
 *   comparison happens here, so what left names no account and no site. The
 *   exceptions are the usage report and the Hub link, which are about the
 *   site by design and are sent only to the hosts in CONSENTED, only after
 *   the owner has said yes, through `post()` below.
 * - **A failure is a fact, never an exception.** The network is somebody
 *   else's, and a security plugin that breaks a dashboard because an API was
 *   slow has done more harm than the check was worth. Callers get a WP_Error
 *   and are expected to say "could not check" rather than "nothing is wrong".
 * - **Never inside a page a visitor is rendering, and never on the checkout.**
 *   The callers are scheduled work, explicit admin actions, and one credential
 *   check at the moment a password is chosen — which is a sign-in or
 *   registration form POST, so it is neither of the first two and has to be
 *   named.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Http {

	/**
	 * Every host this plugin may contact, and what for.
	 *
	 * Adding one is a product decision with a disclosure attached: the readme's
	 * external-services section lists the same set, and a test asserts the two
	 * agree. Nothing here may be a wildcard.
	 *
	 * @var array<string, string>
	 */
	public const ALLOWED = array(
		// The published checksums for a WordPress release, so core files can be
		// compared against what WordPress shipped.
		'api.wordpress.org'       => 'core checksums',
		// The published checksums for a directory plugin at an exact version.
		'downloads.wordpress.org' => 'plugin checksums',
		// The checksums WPDeveloper publishes for its own paid plugins, which
		// the directory never lists. Asked only for the slugs fixed in
		// Integrity\Manifest, and the same public question the directory is
		// asked: a slug and a version, nothing about the site.
		'checksums.wpdeveloper.com' => 'checksums for paid plugins by the same publisher',
		// The same for BetterShield Ultra alone, for the releases the address
		// above does not hold.
		'bettershield.ai'         => 'checksums for BetterShield Ultra, by the same publisher',
		// One official file at one released version, fetched when an altered
		// file is being put back. Whatever arrives is hashed and compared
		// against the published checksum before it is written anywhere, so
		// these serve bytes this plugin verifies rather than bytes it trusts.
		'core.svn.wordpress.org'    => 'the official copy of a core file',
		'plugins.svn.wordpress.org' => 'the official copy of a plugin file',
		// Every published password hash beginning with five given characters,
		// asked only when the breached-password item is switched on and only
		// as somebody chooses a password. The five characters are the whole of
		// the question: they describe several hundred hashes rather than one,
		// and the comparison happens here.
		'api.pwnedpasswords.com'    => 'published password hashes beginning with five characters',
		// The usage report, and only after the owner has said yes to sending
		// it. A host on this list that receives facts about the site — the
		// address and the administrator email among them — which is why
		// nothing reaches it without that answer.
		'send.wpinsight.com'        => 'the usage report, only after the owner opts in',
		// The Hub link, and only after the owner turns it on: this site's
		// security events and a heartbeat, signed, sent to the hub the site
		// is connected to. About the site by design, so it is consented to
		// like the usage report. And the accountless vulnerability check,
		// only once the owner enables it: plugin and theme slugs and
		// versions, nothing about the site's people.
		'hub.bettershield.ai'       => 'the Hub link and published vulnerability advisories, each only after the owner turns it on',
	);

	/**
	 * Hosts on the list that are sent something about the site, and so may
	 * only be reached with the owner's say-so. Every other host is asked a
	 * public question and gets nothing that identifies where it came from.
	 */
	public const CONSENTED = array( 'send.wpinsight.com', 'hub.bettershield.ai' );

	/**
	 * How much of an answer is read before the transfer is abandoned.
	 *
	 * WordPress buffers a whole response body into memory before a caller sees
	 * any of it, so with no limit the size of the answer is chosen by whoever
	 * sends it rather than by the code that asked. A megabyte is generous for
	 * the published lists these checks read; a caller fetching a file raises it
	 * deliberately and says how far.
	 */
	public const MAX_BODY_BYTES = 1048576;

	/**
	 * The same, for a request this site makes to itself.
	 *
	 * The one caller reads the opening of the body to recognize a file, so this
	 * is headroom rather than a budget — and the whole point of that check is
	 * that the file on the other end may be a database dump.
	 */
	public const MAX_SAME_SITE_BODY_BYTES = 8192;

	/**
	 * A GET, if the host is one this plugin is allowed to talk to.
	 *
	 * Any status but 200 is a failure by default and its body is discarded:
	 * an error page is not the answer that was asked for, and a caller handed
	 * one would be reasoning about somebody else's HTML. The exception is an
	 * API that carries meaning in the status rather than only failure, and a
	 * caller that knows it is talking to one names the statuses whose body is
	 * still an answer — `array( 200, 404 )` for an endpoint that says "this is
	 * gone, and here is why" with a 404. Naming a status buys the body and
	 * nothing more: which answer arrived is then the body's shape to say, and
	 * the caller's to read.
	 *
	 * @param array<string, mixed> $args     Passed through to the HTTP API.
	 * @param int[]                $statuses Statuses whose body is an answer.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function get( string $url, array $args = array(), array $statuses = array( 200 ) ) {
		$host = self::host_of( $url );

		if ( null === $host ) {
			return new \WP_Error(
				'bettershield_bad_url',
				__( 'That is not an address this plugin can read.', 'bettershield' )
			);
		}

		if ( ! isset( self::ALLOWED[ $host ] ) ) {
			return new \WP_Error(
				'bettershield_host_not_allowed',
				sprintf(
					/* translators: %s: a host name. */
					__( 'This plugin does not contact %s.', 'bettershield' ),
					$host
				)
			);
		}

		$defaults = array(
			// Short on purpose. A scheduled check that hangs for thirty seconds
			// per request turns one slow API into a site-wide problem.
			'timeout'             => 15,
			'redirection'         => 2,
			'user-agent'          => self::user_agent(),
			'headers'             => array( 'Accept' => 'application/json' ),
			// The transfer stops here rather than the string being trimmed
			// afterwards: both transports honor this mid-stream, so an endpoint
			// answering with a gigabyte costs a megabyte and a dropped
			// connection instead of the site's whole memory limit.
			'limit_response_size' => self::MAX_BODY_BYTES,
		);

		$request = array_merge( $defaults, $args );

		/*
		 * Two values a caller does not get a say in, set after the merge for
		 * exactly that reason. A caller may raise the size limit or shorten the
		 * timeout because it knows what it is fetching; nothing here knows
		 * enough to switch off certificate verification, and an integrity check
		 * answered over an unverified connection is worse than no answer.
		 */
		$request['sslverify']          = true;
		$request['reject_unsafe_urls'] = true;

		/*
		 * wp_safe_remote_get rather than wp_remote_get: it refuses redirects to
		 * private address ranges. The hosts above are public and this is belt
		 * and braces, but the belt costs nothing and the failure it prevents —
		 * an outbound request talked into reaching something inside the
		 * network — is the expensive kind.
		 *
		 * It is not the whole answer, though. What core validates on a
		 * redirect is the address range, so an allowed host answering "302,
		 * try somewhere else" would be followed to any public host on the
		 * internet, and the list this class exists to enforce would have been
		 * checked on the first hop only. Restored file bytes are hashed
		 * against the published checksum afterwards and would fail there; a
		 * manifest is not, and a manifest is what decides which of a site's
		 * files are called official. So the list is asked again on each hop,
		 * for the length of this call and no longer.
		 */
		add_action( 'requests-requests.before_redirect', array( __CLASS__, 'refuse_redirect_off_the_list' ) );

		try {
			$response = wp_safe_remote_get( $url, $request );
		} finally {
			remove_action( 'requests-requests.before_redirect', array( __CLASS__, 'refuse_redirect_off_the_list' ) );
		}

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( ! in_array( $code, $statuses, true ) ) {
			return new \WP_Error(
				'bettershield_http_status',
				sprintf(
					/* translators: %d: an HTTP status code. */
					__( 'The request was answered with status %d.', 'bettershield' ),
					$code
				),
				array( 'status' => $code )
			);
		}

		return $response;
	}

	/**
	 * A POST, to a host that takes a report and only after consent.
	 *
	 * Narrower than `get()` on purpose: only a host in CONSENTED may be posted
	 * to, because a body is how something about the site leaves it, and this
	 * plugin sends something about the site only where the owner said yes: the
	 * usage report, and the Hub link. The caller holds the answer and asks this
	 * only after reading it; the list here is the second of the two checks.
	 *
	 * The same guards as a GET: TLS with verification, no redirect off the
	 * list, a bounded answer, and a user agent that names this plugin rather
	 * than the site.
	 *
	 * @param array<string, mixed> $args     Passed through to the HTTP API; `body` is the report.
	 * @param int[]                $statuses Statuses whose body is an answer.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function post( string $url, array $args = array(), array $statuses = array( 200 ) ) {
		$host = self::host_of( $url );

		if ( null === $host || ! isset( self::ALLOWED[ $host ] ) || ! in_array( $host, self::CONSENTED, true ) ) {
			return new \WP_Error(
				'bettershield_host_not_allowed',
				sprintf(
					/* translators: %s: a host name. */
					__( 'This plugin does not send anything to %s.', 'bettershield' ),
					null === $host ? '?' : $host
				)
			);
		}

		$request = array_merge(
			array(
				'timeout'             => 15,
				'redirection'         => 2,
				'user-agent'          => self::user_agent(),
				'limit_response_size' => self::MAX_BODY_BYTES,
			),
			$args
		);

		$request['sslverify']          = true;
		$request['reject_unsafe_urls'] = true;

		add_action( 'requests-requests.before_redirect', array( __CLASS__, 'refuse_redirect_off_the_list' ) );

		try {
			$response = wp_safe_remote_post( $url, $request );
		} finally {
			remove_action( 'requests-requests.before_redirect', array( __CLASS__, 'refuse_redirect_off_the_list' ) );
		}

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( ! in_array( $code, $statuses, true ) ) {
			return new \WP_Error(
				'bettershield_http_status',
				sprintf(
					/* translators: %d: an HTTP status code. */
					__( 'The request was answered with status %d.', 'bettershield' ),
					$code
				),
				array( 'status' => $code )
			);
		}

		return $response;
	}

	/**
	 * Stop a redirect that leaves the allow-list.
	 *
	 * Public because it is a hook callback and for no other reason. The hook
	 * is the one the HTTP library fires before it follows a redirect, which
	 * WordPress republishes as an action; throwing there is how the library is
	 * told not to, and the HTTP API turns the exception into a WP_Error the
	 * caller reads like any other failure. The location arrives by reference
	 * because the hook lets a listener rewrite it — this one only ever
	 * refuses.
	 *
	 * @param string $location Where the answer says to go next.
	 * @throws \WpOrg\Requests\Exception When that is not a host this plugin contacts.
	 */
	public static function refuse_redirect_off_the_list( &$location ): void {
		if ( self::allows( (string) $location ) ) {
			return;
		}

		$host = self::any_host_of( (string) $location );

		// The address itself is never repeated back: it is written by whoever
		// answered, and a message is somewhere it would be read.
		if ( null === $host ) {
			throw new \WpOrg\Requests\Exception(
				esc_html__( 'The response redirected to an address that could not be read, so it was not followed.', 'bettershield' ),
				'bettershield.redirect_not_allowed'
			);
		}

		throw new \WpOrg\Requests\Exception(
			esc_html(
				sprintf(
					/* translators: %s: a host name. */
					__( 'This plugin does not follow a redirect to %s.', 'bettershield' ),
					$host
				)
			),
			'bettershield.redirect_not_allowed'
		);
	}

	/**
	 * A GET this site makes to itself.
	 *
	 * A request a site makes to itself never leaves the server, engages no
	 * third party and needs no disclosure — so it does not belong on the
	 * allow-list above, whose whole purpose is naming outside services in the
	 * readme. It still belongs *here*, in the gate, rather than as a second
	 * exemption somewhere else: this class exists to be the one place that
	 * knows what the plugin may contact, and "itself" is a thing it can know.
	 *
	 * The caller supplies a path and never a host. The host comes from
	 * `home_url()` and the result is checked against it again before anything
	 * is sent, so a path carrying `//evil.example` cannot turn a self-check
	 * into an outbound request.
	 *
	 * @param string               $path A site-root-relative path.
	 * @param array<string, mixed> $args Passed to WordPress, the guards aside.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function same_site( string $path, array $args = array() ) {
		$url = self::same_site_url( $path );

		if ( is_wp_error( $url ) ) {
			return $url;
		}

		$request = array_merge(
			array(
				'timeout'             => 5,
				'user-agent'          => self::user_agent(),
				'headers'             => array( 'Accept' => '*/*' ),
				// The caller of this one is looking for a file that should
				// not be reachable, and a database dump is a plausible
				// answer. Reading the opening is the whole check, so the
				// transfer stops there instead of pulling the dump into
				// memory to throw it away.
				'limit_response_size' => self::MAX_SAME_SITE_BODY_BYTES,
			),
			$args
		);

		self::reassert_guards( $request );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_remote_get_wp_remote_get -- this class is the gate; see the class docblock.
		return wp_remote_get( $url, $request );
	}

	/**
	 * A GET this site makes to one of its own addresses on either scheme, for
	 * a check that must ask over plain HTTP or follow its own redirect. The
	 * host is held to this site's as in same_site(), and the same guards hold.
	 *
	 * @param array<string, mixed> $args Passed through to the HTTP API.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function same_site_at( string $url, array $args = array() ) {
		$host = self::any_host_of( home_url( '/' ) );

		if ( null === $host || $host !== self::any_host_of( $url ) || ! in_array( wp_parse_url( $url, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) ) {
			return new \WP_Error(
				'bettershield_not_same_site',
				__( 'That path leads off this site, so it was not requested.', 'bettershield' )
			);
		}

		$request = array_merge(
			array(
				'timeout'             => 5,
				'user-agent'          => self::user_agent(),
				'limit_response_size' => self::MAX_SAME_SITE_BODY_BYTES,
			),
			$args
		);

		self::reassert_guards( $request );

		// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_remote_get_wp_remote_get -- this class is the gate; see the class docblock.
		return wp_remote_get( $url, $request );
	}

	/**
	 * A POST this site makes to itself.
	 *
	 * The same rules as the GET above, for the one check that has to send a
	 * body: the caller supplies a path and never a host, the host comes from
	 * `home_url()`, and what the path resolved to is compared against it again
	 * before anything is sent.
	 *
	 * Redirects are deliberately not followed. A redirect here IS the finding
	 * — it is what a site whose two addresses disagree about the scheme does,
	 * and following it would report success for a configuration that refuses
	 * every real client, because a client does not resend a credential across
	 * one.
	 *
	 * @param string               $path A site-root-relative path.
	 * @param array<string, mixed> $args Passed to WordPress, the guards aside.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function same_site_post( string $path, array $args = array() ) {
		$url = self::same_site_url( $path );

		if ( is_wp_error( $url ) ) {
			return $url;
		}

		$request = array_merge(
			array(
				'timeout'             => 10,
				'user-agent'          => self::user_agent(),
				'limit_response_size' => self::MAX_BODY_BYTES,
			),
			$args
		);

		self::reassert_guards( $request );

		// phpcs:ignore WordPress.WP.AlternativeFunctions -- this class is the gate; see the class docblock.
		return wp_remote_post( $url, $request );
	}

	/**
	 * The two values a same-site caller does not get a say in.
	 *
	 * Set after the merge for exactly that reason, the way the outbound `get()`
	 * above sets its own. A caller may shorten the timeout or lower the size
	 * limit because it knows what it is fetching; nothing here knows enough to
	 * follow a redirect — a redirect on a self-check IS the finding, and the
	 * one caller that would see one is looking for a site whose two addresses
	 * disagree about the scheme — and nothing knows enough to switch
	 * certificate verification off.
	 *
	 * @param array<string, mixed> $request
	 */
	private static function reassert_guards( array &$request ): void {
		$request['redirection'] = 0;
		$request['sslverify']   = true;
	}

	/**
	 * A path turned into a URL on this site, or a refusal.
	 *
	 * Shared by both same-site callers so the two cannot come to different
	 * conclusions about what counts as this site.
	 *
	 * @return string|\WP_Error
	 */
	private static function same_site_url( string $path ) {
		$home = home_url( '/' );
		$host = self::any_host_of( $home );

		if ( null === $host ) {
			return new \WP_Error( 'bettershield_no_home', __( 'This site’s own address could not be read.', 'bettershield' ) );
		}

		if ( '' !== (string) wp_parse_url( $path, PHP_URL_HOST ) || 0 === strpos( $path, '//' ) || str_contains( $path, '://' ) ) {
			return new \WP_Error(
				'bettershield_not_same_site',
				__( 'That is an address rather than a path, so it was not requested.', 'bettershield' )
			);
		}

		$url = $home . ltrim( $path, '/' );

		if ( $host !== self::any_host_of( $url ) ) {
			return new \WP_Error(
				'bettershield_not_same_site',
				__( 'That path leads off this site, so it was not requested.', 'bettershield' )
			);
		}

		return $url;
	}

	/**
	 * The host of a URL on any scheme, for the same-site comparison above.
	 *
	 * Separate from `host_of()`, which requires https because the things it
	 * guards are integrity checks that must not be rewritable in transit. A
	 * site served over plain HTTP is still a site, and refusing to check it
	 * for an exposed database dump would leave the least secure sites the
	 * least served.
	 */
	private static function any_host_of( string $url ): ?string {
		$host = wp_parse_url( $url, PHP_URL_HOST );

		return is_string( $host ) && '' !== $host ? strtolower( $host ) : null;
	}

	/**
	 * A GET whose body is expected to be JSON, decoded.
	 *
	 * @param array<string, mixed> $args     Passed through to the HTTP API.
	 * @param int[]                $statuses Statuses whose body is an answer.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function get_json( string $url, array $args = array(), array $statuses = array( 200 ) ) {
		$response = self::get( $url, $args, $statuses );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $decoded ) ) {
			return new \WP_Error(
				'bettershield_bad_json',
				__( 'The answer was not in a shape this plugin understands.', 'bettershield' )
			);
		}

		return $decoded;
	}

	/**
	 * Whether a host is one this plugin may contact. Public so a caller can
	 * refuse early, and so a test can read the list rather than restate it.
	 */
	public static function allows( string $url ): bool {
		$host = self::host_of( $url );

		return null !== $host && isset( self::ALLOWED[ $host ] );
	}

	private static function host_of( string $url ): ?string {
		// Only over TLS. These are integrity checks: an answer that could be
		// rewritten in transit is worse than no answer, because it would be
		// believed.
		if ( 0 !== stripos( $url, 'https://' ) ) {
			return null;
		}

		$host = wp_parse_url( $url, PHP_URL_HOST );

		return is_string( $host ) && '' !== $host ? strtolower( $host ) : null;
	}

	/**
	 * Names the plugin and its version, and nothing about the site.
	 */
	private static function user_agent(): string {
		return 'BetterShield/' . ( defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '0' );
	}
}
