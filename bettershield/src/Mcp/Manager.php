<?php
/**
 * The site side of the assistant endpoint: the URLs, the routes, and the
 * switch that governs all of them.
 *
 * This plugin speaks the protocol at the site's own address. There is no
 * broker in the path and nothing is proxied anywhere: an assistant is given
 * this site's URL, and the request it makes is answered by this installation.
 *
 *     https://example.com/bettershield/mcp             the pretty path
 *     https://example.com/wp-json/bettershield/v1/mcp  always served
 *
 * The credential travels in the `Authorization` header and nowhere else. A
 * secret in a path is a secret in the access log, in the proxy's log, in the
 * browser's history and in the next request's `Referer`; a client with only a
 * URL field is served by the browser sign-in flow instead.
 *
 * The pretty path is a rewrite rule, and rules go missing — a permalink save, a
 * migration, a plugin that flushes and rebuilds. So the REST namespace is the
 * one that is always there, and the rules are rebuilt once whenever the set
 * this plugin registers stops matching the set it last wrote. That comparison
 * is one autoloaded value; reading the whole stored rule table on every request
 * to look for a missing key was a cost every front-end page view paid.
 *
 * The discovery documents are served at the path-suffixed well-known URLs
 * rather than the bare ones. Rewrite rules are keyed by their pattern, so two
 * plugins registering the same broad rule leave only whichever registered
 * last — and a site running a second assistant endpoint would then have one of
 * them silently answering for the other. The rule table is also one ordered
 * list, and a neighbor's broad rule registered above these takes their
 * addresses before they are reached, so the two discovery addresses are
 * claimed from the request path before the table is read at all.
 *
 * The MCP switch gates discovery, consent and token issuance. Revocation
 * remains available with the switch off or during lockdown. Abilities follow
 * their separate read and write opt-ins, independently of the MCP switch.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Abilities\Registrar;
use BetterShield\Events\Writer;
use BetterShield\Support\Checkout;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Manager {

	/** The master switch, off until an administrator turns it on. */
	public const OPTION = 'bettershield_mcp_enabled';

	/**
	 * The fingerprint of the rule set this plugin last had written.
	 *
	 * A version rather than a probe. The rules change when this file changes
	 * and when the plugin's version changes, and at no other time — so a
	 * comparison against one stored string answers "do these need rebuilding"
	 * without reading the rule table at all.
	 */
	public const RULES_OPTION = 'bettershield_mcp_rules';

	/** The REST namespace this plugin already owns. */
	private const NS = 'bettershield/v1';

	/** Set on a request for the pretty endpoint. */
	private const VAR_ENDPOINT = 'bettershield_mcp';

	/** Names which discovery document was asked for. */
	private const VAR_WELLKNOWN = 'bettershield_mcp_wellknown';

	/**
	 * Set on a request for the consent page.
	 *
	 * Served as an ordinary front-end URL rather than a REST route, and that
	 * is the whole reason it exists as a query variable: a browser returning
	 * from the sign-in screen carries a cookie and no REST nonce, which a REST
	 * route reads as signed out. The consent page would then send the person
	 * back to sign in, from a screen they reached by signing in.
	 */
	private const VAR_AUTHORIZE = 'bettershield_mcp_authorize';

	/** The parameters the consent page reads, each validated by name. */
	private const CONSENT_PARAMS = array(
		'client_id',
		'redirect_uri',
		'response_type',
		'code_challenge',
		'code_challenge_method',
		'scope',
		'state',
		'resource',
		'approve',
		'deny',
		'nonce',
		'allow_changes',
		'hub_ticket',
		'hub_link',
	);

	public function register(): void {
		add_action( 'init', array( $this, 'add_rewrites' ) );
		add_filter( 'do_parse_request', array( $this, 'claim_discovery' ), 0 );
		add_action( 'parse_request', array( $this, 'maybe_answer' ) );
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_filter( 'rest_pre_dispatch', array( $this, 'refuse_rest_method' ), 10, 3 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'read_own_body' ), 10, 3 );

		/*
		 * Deactivation leaves the stored rules behind otherwise, and a URL
		 * routed to a query variable nothing registers any more is answered
		 * with the site's front page rather than a plain 404 — which is the
		 * one answer a client reads as "this server is broken" instead of
		 * "this server is gone". Armed here rather than in the plugin file
		 * because this class owns the rules; there is no capability check
		 * inside it, because a deactivation hook runs without a user under
		 * WP-CLI.
		 */
		if ( defined( 'BETTERSHIELD_FILE' ) ) {
			register_deactivation_hook( BETTERSHIELD_FILE, array( self::class, 'forget_rules' ) );
		}

		/*
		 * The pairing record and the OAuth state are each read several times
		 * on one authenticated call, so each is held for the request. Held
		 * state that outlives a write is a lie, and the write can come from
		 * anywhere — this screen, WP-CLI, another plugin, a test — so the
		 * invalidation is hung off the option itself rather than left to every
		 * caller to remember.
		 */
		foreach ( array( Pairing::OPTION, OAuth::OPTION ) as $option ) {
			add_action( 'add_option_' . $option, array( self::class, 'forget_stored_state' ) );
			add_action( 'update_option_' . $option, array( self::class, 'forget_stored_state' ) );
		}

		add_action( 'deleted_option', array( self::class, 'forget_deleted_state' ) );
	}

	/** Both held copies, dropped. */
	public static function forget_stored_state(): void {
		Pairing::reset_request_state();
		OAuth::forget_state();
	}

	/**
	 * The one setting this connection owns, in the shape the release panel
	 * reads: it asks each source for its settings and looks a key up.
	 *
	 * @return array<string, bool>
	 */
	public function settings(): array {
		return array( 'enabled' => self::is_enabled() );
	}

	/**
	 * One record, forgotten, when it is one of ours that went.
	 *
	 * `deleted_option` is the only deletion hook that fires after the row has
	 * actually gone; the per-option one fires before, and a read in between
	 * would put the value that is about to disappear straight back.
	 *
	 * @param mixed $option
	 */
	public static function forget_deleted_state( $option = '' ): void {
		$name = (string) $option;

		if ( Pairing::OPTION === $name || OAuth::OPTION === $name ) {
			self::forget_stored_state();
		}
	}

	/** Whether the endpoint is open at all. */
	public static function is_enabled(): bool {
		return '1' === get_option( self::OPTION );
	}

	/**
	 * Open or close it, on the record either way.
	 *
	 * One path for the screen and the terminal alike, so a flip is logged the
	 * same way whichever of them made it, with its way back written first.
	 *
	 * @return true|\WP_Error
	 */
	public static function set_enabled( bool $enabled ) {
		// Its way back first, as the other agent switches' (#1824).
		if ( false === \BetterShield\Undo\SettingsLedger::record( 'mcp', array( 'enabled' => self::is_enabled() ), array( 'enabled' => $enabled ) ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $enabled ? '1' : '0', true );

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array( 'enabled' => $enabled ),
			)
		);

		return true;
	}

	/**
	 * Whether the platform can offer tools at all.
	 *
	 * The endpoint answers on any supported version; what it can offer is
	 * whatever the abilities runtime registered, and below the version that
	 * has one — with nothing bundled — that is nothing.
	 */
	public static function is_available(): bool {
		return function_exists( 'wp_register_ability' );
	}

	/* ---- the URLs -------------------------------------------------------------- */

	/**
	 * Every rule this endpoint needs, as pattern to destination.
	 *
	 * @return array<string, string>
	 */
	public static function rules(): array {
		return array(
			'^bettershield/mcp/?$' => 'index.php?' . self::VAR_ENDPOINT . '=1',

			/*
			 * The specification places the well-known segment before the
			 * resource path; the older convention appends it instead, and
			 * clients built on a library that only knows the older one never
			 * fall back. Serving both costs one rule and removes a whole class
			 * of "this server has no sign-in flow" reports. Both name this
			 * endpoint's own path, so neither can answer for a neighbor's
			 * server. A neighbor's broader rule can still sit above them in
			 * the table, which is why claim_discovery() answers these two
			 * addresses before the table is read.
			 */
			'^\.well-known/oauth-(protected-resource|authorization-server)/bettershield/mcp/?$' => 'index.php?' . self::VAR_WELLKNOWN . '=$matches[1]',
			'^bettershield/mcp/\.well-known/oauth-(protected-resource|authorization-server)/?$' => 'index.php?' . self::VAR_WELLKNOWN . '=$matches[1]',

			'^bettershield/authorize/?$' => 'index.php?' . self::VAR_AUTHORIZE . '=1',
		);
	}

	/**
	 * Register the pretty paths, and arrange a rebuild where one is due.
	 *
	 * Registration is inline and unconditional: a rule has to exist before the
	 * request that uses it. The rebuild is neither — it is a full regeneration
	 * of the site's rule table plus an option write, and the request that
	 * happens to arrive with a stale fingerprint is as likely as not to be a
	 * visitor's.
	 */
	public function add_rewrites(): void {
		foreach ( self::rules() as $pattern => $destination ) {
			add_rewrite_rule( $pattern, $destination, 'top' );
		}

		if ( get_option( self::RULES_OPTION ) === self::rules_fingerprint() ) {
			return;
		}

		if ( ! self::may_rebuild_here() ) {
			return;
		}

		/*
		 * `WP_Rewrite::flush_rules()` refuses to run before `wp_loaded` and
		 * re-hooks itself there, so a flush asked for on `init` performs
		 * nothing at the moment it is asked. The fingerprint has to be written
		 * by the rebuild that actually happened, so the two travel together.
		 */
		if ( did_action( 'wp_loaded' ) ) {
			self::rebuild_rules();

			return;
		}

		add_action( 'wp_loaded', array( self::class, 'rebuild_rules' ), 20 );
	}

	/**
	 * Whether this request may rebuild the rule table at all.
	 *
	 * Never on the checkout, and never on any other request a visitor is
	 * waiting for. What is left is an administrator's page, a cron run and the
	 * terminal — and activation, which calls the rebuild directly. A site that
	 * never sees one of those still routes: the rules are registered on every
	 * request above, and WordPress regenerates a table it finds empty.
	 */
	private static function may_rebuild_here(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a structural test; never stored, never echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		if ( Checkout::is_store_uri( $uri ) ) {
			return false;
		}

		return is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * Rebuild the stored rule table, and record that it was rebuilt.
	 *
	 * Public because activation calls it: the plugin's own `init` has not run
	 * for the copy being activated, so the rules are registered here before
	 * they are written.
	 */
	public static function rebuild_rules(): void {
		foreach ( self::rules() as $pattern => $destination ) {
			add_rewrite_rule( $pattern, $destination, 'top' );
		}

		if ( is_multisite() && ms_is_switched() ) {
			/*
			 * A blog switch swaps the database handle and the cache and
			 * nothing else: `$wp_rewrite` still holds the permalink structure
			 * of whichever site was current when it was built, so a flush here
			 * would write that site's table over this one's. Emptying the row
			 * leaves this site to regenerate from its own structure and its own
			 * registered rules on its next request.
			 */
			delete_option( 'rewrite_rules' );
			delete_option( self::RULES_OPTION );

			return;
		}

		flush_rewrite_rules( false );

		/*
		 * Autoloaded, which is the exception this plugin's rule about autoload
		 * exists for rather than a breach of it: this value is read on `init`,
		 * so it is read on every request a visitor makes, and an option read on
		 * every request and not autoloaded is one uncached query per visitor on
		 * any host without a persistent object cache.
		 */
		update_option( self::RULES_OPTION, self::rules_fingerprint(), true );
	}

	/**
	 * Take the rules out again, on deactivation.
	 *
	 * The registered rules are dropped from this request's table before the
	 * flush, or the flush would write back the very rules it is meant to
	 * remove — this hook runs long after `init` added them. The fingerprint
	 * goes too, so reactivating rebuilds rather than believing the table is
	 * already right.
	 */
	public static function forget_rules(): void {
		global $wp_rewrite;

		if ( isset( $wp_rewrite->extra_rules_top ) && is_array( $wp_rewrite->extra_rules_top ) ) {
			foreach ( array_keys( self::rules() ) as $pattern ) {
				unset( $wp_rewrite->extra_rules_top[ $pattern ] );
			}
		}

		delete_option( self::RULES_OPTION );

		flush_rewrite_rules( false );
	}

	/**
	 * What the stored rules should be, as one string.
	 */
	private static function rules_fingerprint(): string {
		return substr(
			hash(
				'sha256',
				(string) wp_json_encode( self::rules() ) . '|' . ( defined( 'BETTERSHIELD_VERSION' ) ? BETTERSHIELD_VERSION : '' )
			),
			0,
			32
		);
	}

	/**
	 * Which surface of this endpoint a request actually reached.
	 *
	 * Decided from the rule WordPress matched and from the destination that
	 * rule substituted — never from `$wp->query_vars`. `WP::parse_request()`
	 * fills a public query variable from `$_POST` and `$_GET` before it looks
	 * at the matched rule, so a variable read from there says what the caller
	 * wrote rather than what the address resolves to: on the home page, on any
	 * post, on any invented path, and on this endpoint's own canonical URL as
	 * whichever surface the caller preferred.
	 *
	 * Pure, and public, so the decision can be exercised: every branch of the
	 * caller below ends the request, which is right for a page and leaves
	 * nothing for a test to hold.
	 *
	 * @param mixed $wp The request object WordPress is about to run.
	 * @return array{surface: string, wellknown: string}
	 */
	public static function asked_for( $wp ): array {
		$nothing = array(
			'surface'   => '',
			'wellknown' => '',
		);

		if ( ! is_object( $wp ) || ! isset( $wp->matched_rule ) || ! is_string( $wp->matched_rule ) ) {
			return $nothing;
		}

		if ( ! isset( self::rules()[ $wp->matched_rule ] ) ) {
			return $nothing;
		}

		$vars = array();

		// Core stores the substituted destination slashed, the way it stores
		// every other request value.
		parse_str(
			(string) wp_unslash( isset( $wp->matched_query ) && is_string( $wp->matched_query ) ? $wp->matched_query : '' ),
			$vars
		);

		$wellknown = self::wellknown_name( $vars[ self::VAR_WELLKNOWN ] ?? '' );

		if ( '' !== $wellknown ) {
			return array(
				'surface'   => 'wellknown',
				'wellknown' => $wellknown,
			);
		}

		foreach ( array( self::VAR_AUTHORIZE => 'authorize', self::VAR_ENDPOINT => 'endpoint' ) as $variable => $surface ) {
			if ( self::flag( $vars, $variable ) ) {
				return array(
					'surface'   => $surface,
					'wellknown' => '',
				);
			}
		}

		return $nothing;
	}

	/**
	 * Which discovery document was named, or an empty string.
	 *
	 * An allow-list, so an unrecognized selector is answered with nothing
	 * rather than with whichever document the fall-through happened to pick.
	 * The scalar test is not decoration: a value cast from an array is a
	 * warning into the site's error log and the literal `Array` in its place.
	 *
	 * @param mixed $value
	 */
	public static function wellknown_name( $value ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$which = (string) $value;

		return in_array( $which, array( 'authorization-server', 'protected-resource' ), true ) ? $which : '';
	}

	/**
	 * Whether one of the rules' own flags is set.
	 *
	 * @param array<string, mixed> $vars
	 */
	private static function flag( array $vars, string $name ): bool {
		if ( ! isset( $vars[ $name ] ) || ! is_scalar( $vars[ $name ] ) ) {
			return false;
		}

		$value = (string) $vars[ $name ];

		return '' !== $value && '0' !== $value;
	}

	/**
	 * Answer this endpoint's discovery documents before any rule is matched.
	 *
	 * The rule table is one ordered list shared by every plugin on the site. A
	 * neighbor's rule that claims every `.well-known/oauth-*` address, if it is
	 * registered above these, takes this endpoint's own discovery addresses
	 * before its rules are reached. Its owner then answers with its own
	 * metadata or with a 404. Or it declines, and WordPress serves a page
	 * and redirects it to a trailing slash. A client refuses all three, and
	 * nothing on the site says why. Deciding from the path here, where only this
	 * endpoint's own two addresses can match, leaves every other address to the
	 * table.
	 *
	 * @param mixed $continue Whether WordPress goes on to parse the request.
	 * @return mixed The flag, unchanged, on every address that is not ours.
	 */
	public function claim_discovery( $continue ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared with this endpoint's own patterns; never stored, never echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		// Every front-end request passes through here, and almost none is this.
		if ( false === strpos( $uri, '.well-known' ) ) {
			return $continue;
		}

		$which = self::discovery_claimed( self::requested_path( $uri, home_url( '/' ) ) );

		if ( '' !== $which ) {
			$this->serve_discovery( $which );
		}

		$subsite = self::subsite_discovery( $uri );

		if ( null !== $subsite ) {
			// Its own documents, from its own options: issuer, addresses and
			// whether it is switched on at all are all that subsite's.
			switch_to_blog( $subsite['site'] );
			$this->serve_discovery( $subsite['which'] );
		}

		return $continue;
	}

	/**
	 * The subsite a root-anchored discovery address names, on a network whose
	 * sites live in directories.
	 *
	 * A subsite's issuer carries its directory, and the specification puts
	 * that issuer's documents at the network's root with the whole path after
	 * the well-known segment: `/.well-known/oauth-authorization-server/shop/
	 * bettershield/mcp`. That address reaches the site serving the root, whose
	 * own rules cover only its own path, so standard clients found no sign-in
	 * server for any subsite. Answered for a site that exists at exactly the
	 * named directory and is open, and for this endpoint's path only.
	 *
	 * @param string $uri The request line's path and query.
	 * @return array{site: int, which: string}|null
	 */
	public static function subsite_discovery( string $uri ): ?array {
		if ( ! is_multisite() || is_subdomain_install() ) {
			return null;
		}

		$path = trim( explode( '?', $uri, 2 )[0], '/' );

		if ( 1 !== preg_match( '#^\.well-known/oauth-(protected-resource|authorization-server)/(.+)/bettershield/mcp/?$#', $path, $matches ) ) {
			return null;
		}

		$directory = '/' . strtolower( trim( $matches[2], '/' ) ) . '/';
		$network   = get_network();
		$site      = $network ? get_site_by_path( $network->domain, $directory ) : false;

		if ( ! $site instanceof \WP_Site || strtolower( $site->path ) !== $directory ) {
			return null;
		}

		if ( '0' !== (string) $site->archived || '0' !== (string) $site->deleted || '0' !== (string) $site->spam ) {
			return null;
		}

		return array(
			'site'  => (int) $site->blog_id,
			'which' => self::wellknown_name( $matches[1] ),
		);
	}

	/**
	 * Which discovery document a path names under this endpoint's own rules,
	 * or an empty string.
	 *
	 * The patterns are the ones the rule table carries, so the table and this
	 * can never disagree about which addresses are ours.
	 *
	 * @param string $path A path as requested_path() gives it.
	 */
	public static function discovery_claimed( string $path ): string {
		foreach ( self::rules() as $pattern => $destination ) {
			if ( false === strpos( $destination, self::VAR_WELLKNOWN . '=' ) ) {
				continue;
			}

			if ( 1 === preg_match( '#' . $pattern . '#', $path, $matches ) ) {
				return self::wellknown_name( $matches[1] ?? '' );
			}
		}

		return '';
	}

	/**
	 * The path WordPress matches its rules against, worked out the way it does.
	 *
	 * The request's path without its query string, with the directory the site
	 * lives in taken off the front (compared without regard to case, as
	 * WordPress compares it) and no slash at either end. Where the permalinks go
	 * through `index.php`, that segment comes off too. A path outside the site's
	 * directory is none of the site's, and comes back empty.
	 *
	 * Pure, and public, so it can be exercised without a request.
	 *
	 * @param string $uri  The request line's path and query.
	 * @param string $home The site's home URL.
	 */
	public static function requested_path( string $uri, string $home ): string {
		$path = trim( explode( '?', $uri, 2 )[0], '/' );
		$base = trim( (string) wp_parse_url( $home, PHP_URL_PATH ), '/' );

		if ( '' !== $base ) {
			if ( 0 !== stripos( $path . '/', $base . '/' ) ) {
				return '';
			}

			$path = trim( substr( $path, strlen( $base ) ), '/' );
		}

		if ( 0 === strpos( $path . '/', 'index.php/' ) ) {
			$path = trim( substr( $path, strlen( 'index.php' ) ), '/' );
		}

		return $path;
	}

	/**
	 * Answer one of the pretty paths, before the main query runs.
	 *
	 * Every branch here ends the request. Nothing falls through to the theme:
	 * these are machine paths, and a client handed a rendered page instead of
	 * JSON reports something entirely unrelated to what went wrong.
	 *
	 * @param mixed $wp The request object WordPress is about to run.
	 */
	public function maybe_answer( $wp ): void {
		$asked = self::asked_for( $wp );

		if ( 'wellknown' === $asked['surface'] ) {
			$this->serve_discovery( $asked['wellknown'] );
		}

		if ( 'authorize' === $asked['surface'] ) {
			if ( ! self::is_enabled() ) {
				$this->gone();
			}

			$this->serve_consent();
		}

		if ( 'endpoint' !== $asked['surface'] ) {
			return;
		}

		// One method, said plainly. A browser opening this address is the
		// commonest way somebody checks whether the endpoint is there, and the
		// front page is the least useful answer it could get.
		$refusal = self::method_refusal( self::request_method() );

		if ( null !== $refusal ) {
			$this->refuse_method( $refusal );
		}

		$request = self::endpoint_request();

		/*
		 * The raw body, which nothing in WordPress hands back at this point —
		 * the REST server that would is not built yet, and building it to read
		 * one string would register every route on the site to answer one.
		 *
		 * One byte past the cap, so the handler can tell a body at the limit
		 * from one over it rather than silently truncating a large request into
		 * a malformed small one. Suppressed, because a body that cannot be read
		 * is answered below as a body that is not JSON, which is the same
		 * answer said properly.
		 */
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- an unreadable body is answered below rather than warned about.
		$request->set_body( (string) @file_get_contents( 'php://input', false, null, 0, Server::MAX_BODY_BYTES + 1 ) );

		$this->emit( Server::handle( $request ) );
	}

	/**
	 * The request the handler sees, built from this request's own headers.
	 *
	 * The REST server is not built here — building it to read a few strings
	 * would register every route on the site to answer one — so the headers
	 * the handler reads are copied across by hand: the credential, and what
	 * the client accepts, which decides whether an answer may go out as an
	 * event stream. Without the second, a notification the handler had to
	 * send had nowhere to go on this address while the REST address carried
	 * it fine.
	 */
	public static function endpoint_request(): \WP_REST_Request {
		$request = new \WP_REST_Request( 'POST', '/' . self::NS . '/mcp' );
		$request->set_header( 'content-type', 'application/json' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read below, where the two names it can arrive under are handled together.
		$header = self::bearer_from( isset( $_SERVER ) && is_array( $_SERVER ) ? $_SERVER : array() );

		if ( null !== $header ) {
			$request->set_header( 'authorization', $header );
		}

		if ( ! empty( $_SERVER['HTTP_ACCEPT'] ) ) {
			$request->set_header( 'accept', sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_ACCEPT'] ) ) );
		}

		return $request;
	}

	/**
	 * Serve one discovery document, or nothing when the endpoint is closed.
	 */
	private function serve_discovery( string $which ): void {
		if ( ! self::is_enabled() ) {
			$this->gone();
		}

		$document = 'authorization-server' === $which
			? OAuth::authorization_server_metadata()
			: OAuth::protected_resource_metadata();

		status_header( 200 );
		self::send_page_headers();
		header( 'Content-Type: application/json; charset=utf-8' );

		echo wp_json_encode( $document ); // phpcs:ignore WordPress.Security.EscapeOutput -- JSON, encoded by WordPress, served as JSON.
		exit;
	}

	/**
	 * What every page and document this class serves carries.
	 *
	 * These surfaces are answered inside `parse_request`, which ends the
	 * request before WordPress sends a header of its own, so nothing else on
	 * the site reaches them — not the theme, not the site's own header
	 * settings, not this plugin's hardening item. The consent page is the one
	 * that needs them most: it is the single screen in this feature whose job
	 * is to look trustworthy, and a framed copy of it is a click somebody made
	 * somewhere else.
	 *
	 * Nothing here is cacheable. The consent page is per-person by
	 * construction, and a discovery document served with a shared lifetime is
	 * a document a cache may keep under a key the caller chose.
	 *
	 * @return array<string, string>
	 */
	public static function page_headers(): array {
		return array(
			'X-Frame-Options'         => 'DENY',
			'Content-Security-Policy' => "frame-ancestors 'none'",
			'X-Content-Type-Options'  => 'nosniff',
			'Referrer-Policy'         => 'no-referrer',
			'Cache-Control'           => 'no-store',
		);
	}

	/** The same, sent. */
	private static function send_page_headers( int $status = 0 ): void {
		foreach ( self::page_headers() as $name => $value ) {
			if ( $status > 0 ) {
				header( $name . ': ' . $value, true, $status );

				continue;
			}

			header( $name . ': ' . $value );
		}
	}

	/** A closed endpoint is absent rather than refusing, and says nothing more. */
	private function gone(): void {
		status_header( 404 );
		self::send_page_headers( 404 );
		exit;
	}

	/**
	 * What to answer a request on the endpoint that is not a POST, or null.
	 *
	 * Decided here rather than inside the page so it can be exercised: the
	 * page below ends the request, which is right for a page and leaves
	 * nothing for a test to hold.
	 *
	 * @return array{status: int, allow: string, body: array<string, mixed>}|null
	 */
	public static function method_refusal( string $method ): ?array {
		if ( 'POST' === strtoupper( $method ) ) {
			return null;
		}

		return array(
			'status' => 405,
			'allow'  => 'POST',
			'body'   => array(
				'jsonrpc' => '2.0',
				'id'      => null,
				'error'   => array(
					'code'    => -32600,
					'message' => __( 'This endpoint answers a POST carrying one JSON-RPC message.', 'bettershield' ),
				),
			),
		);
	}

	/**
	 * The one method this endpoint answers, said in the protocol's own shape.
	 *
	 * @param array{status: int, allow: string, body: array<string, mixed>} $refusal
	 */
	private function refuse_method( array $refusal ): void {
		status_header( $refusal['status'] );
		self::send_page_headers( $refusal['status'] );
		header( 'Allow: ' . $refusal['allow'], true, $refusal['status'] );
		header( 'Content-Type: application/json; charset=utf-8', true, $refusal['status'] );

		echo wp_json_encode( $refusal['body'] ); // phpcs:ignore WordPress.Security.EscapeOutput -- JSON, encoded by WordPress, served as JSON.
		exit;
	}

	/* ---- REST ------------------------------------------------------------------ */

	/**
	 * The endpoint's own routes.
	 *
	 * All three authenticate inside the handler, so the permission callback
	 * lets them through: a server-to-server call carries no WordPress user,
	 * and a bare permission failure would tell a client nothing about how to
	 * authenticate. The management routes an owner's screen uses are
	 * registered elsewhere, behind the capability, like every other screen.
	 */
	public function register_routes(): void {
		register_rest_route(
			self::NS,
			'/mcp',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'answer_rest' ),
				'permission_callback' => '__return_true',
			)
		);

		/*
		 * The document a refusal names, on the path that is always served.
		 *
		 * The pretty well-known address is a rewrite, and a site with plain
		 * permalinks answers every unknown path with its front page — so the
		 * `WWW-Authenticate` header, which is the whole of what a client
		 * holding nothing has to go on, used to name a page of HTML.
		 */
		register_rest_route(
			self::NS,
			'/mcp/protected-resource',
			array(
				'methods'             => \WP_REST_Server::READABLE,
				'callback'            => array( $this, 'answer_protected_resource' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/mcp/oauth/register',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'answer_registration' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			self::NS,
			'/mcp/oauth/token',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'answer_token' ),
				'permission_callback' => '__return_true',
			)
		);

		/*
		 * RFC 7009. Answered whether the connection is on or off, and during
		 * a lockdown: both exist to keep access from being used, and handing
		 * a grant back takes access away.
		 */
		register_rest_route(
			self::NS,
			'/mcp/oauth/revoke',
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'answer_revocation' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * The endpoint on the path that is always served.
	 */
	public function answer_rest( \WP_REST_Request $request ): \WP_REST_Response {
		$response = Server::handle( $request );
		$response->header( 'MCP-Protocol-Version', Server::PROTOCOL_VERSION );

		return $response;
	}

	/**
	 * A method the endpoint does not answer, on the path that is always
	 * served: the same 405, `Allow` and body as the pretty address. A client
	 * opens a GET for the server's stream after `initialize`, and a server
	 * without one answers 405; core's "No route was found" read as no
	 * endpoint at all, to the client and to anybody checking the address the
	 * config-file setups use.
	 *
	 * Answered before routing rather than registered on the route, because
	 * core's `Allow` names every method a route registers, and the route list
	 * would offer methods that do nothing. OPTIONS stays with core, which
	 * answers a browser client's preflight with it.
	 *
	 * @param mixed $result
	 * @param mixed $server
	 * @param mixed $request
	 * @return mixed
	 */
	public function refuse_rest_method( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof \WP_REST_Request || 'OPTIONS' === $request->get_method() ) {
			return $result;
		}

		if ( 0 !== strcasecmp( untrailingslashit( $request->get_route() ), '/' . self::NS . '/mcp' ) ) {
			return $result;
		}

		$refusal = self::method_refusal( $request->get_method() );

		if ( null === $refusal ) {
			return $result;
		}

		$response = new \WP_REST_Response( $refusal['body'], $refusal['status'] );
		$response->header( 'Allow', $refusal['allow'] );

		foreach ( self::page_headers() as $name => $value ) {
			$response->header( $name, $value );
		}

		return $response;
	}

	/**
	 * A body that is not JSON, answered by the server in JSON-RPC rather than
	 * by core. Core parses a JSON request before any callback runs and
	 * answers one it cannot parse with its own `rest_invalid_json`, which a
	 * client reading JSON-RPC cannot read; an empty body here, and any body
	 * on the pretty address, already got -32700. Set aside on this route
	 * alone, so the server reads the raw body itself.
	 *
	 * @param mixed $response
	 * @param mixed $handler
	 * @param mixed $request
	 * @return mixed
	 */
	public function read_own_body( $response, $handler, $request ) {
		if ( ! is_wp_error( $response ) || 'rest_invalid_json' !== $response->get_error_code() || ! $request instanceof \WP_REST_Request ) {
			return $response;
		}

		return 0 === strcasecmp( untrailingslashit( $request->get_route() ), '/' . self::NS . '/mcp' ) ? null : $response;
	}

	/**
	 * The protected-resource document, where a rewrite cannot carry it.
	 */
	public function answer_protected_resource(): \WP_REST_Response {
		if ( ! self::is_enabled() ) {
			return new \WP_REST_Response( null, 404 );
		}

		$response = new \WP_REST_Response( OAuth::protected_resource_metadata(), 200 );

		foreach ( self::page_headers() as $name => $value ) {
			$response->header( $name, $value );
		}

		return $response;
	}

	/**
	 * Registration, which a client does before it holds anything.
	 *
	 * Answered in RFC 7591's own error shape throughout, because a client
	 * reading this route reads that and nothing else — this plugin's own error
	 * envelope is a body it would report as an unparseable response.
	 */
	public function answer_registration( \WP_REST_Request $request ): \WP_REST_Response {
		/*
		 * Before the counter and before anything is parsed: how much arrived
		 * is the caller's choice, and reading past this point is the cost
		 * being refused. Without it the only bound on one unauthenticated
		 * registration is whatever the host left `post_max_size` at.
		 */
		if ( strlen( (string) $request->get_body() ) > Server::MAX_BODY_BYTES ) {
			return self::oauth_error(
				'invalid_client_metadata',
				__( 'That registration is larger than this endpoint accepts.', 'bettershield' ),
				413
			);
		}

		// Nobody new arrives during a lockdown, an app included.
		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			return self::oauth_error( 'temporarily_unavailable', __( 'This site is locked down, so connected apps are paused until the owner lifts it.', 'bettershield' ), 403, 'lockdown' );
		}

		// Counted before anything is parsed: every attempt is a write somebody
		// with no credential asked this site to make.
		if ( ! RateLimiter::registration_allowed() ) {
			$response = self::oauth_error(
				'temporarily_unavailable',
				__( 'Too many registration attempts from this network. Try again later.', 'bettershield' ),
				429
			);
			$response->header( 'Retry-After', (string) RateLimiter::anonymous_retry_after() );

			return $response;
		}

		// The switch is read where the registration is decided, so one gate
		// and one sentence answer a client whichever way it arrived here.
		$body   = $request->get_json_params();
		$result = OAuth::register_client( is_array( $body ) ? $body : array() );

		if ( is_wp_error( $result ) ) {
			$data = $result->get_error_data();

			return self::oauth_error(
				isset( $data['error'] ) ? (string) $data['error'] : 'invalid_client_metadata',
				isset( $data['error_description'] ) ? (string) $data['error_description'] : $result->get_error_message(),
				isset( $data['status'] ) ? (int) $data['status'] : 400
			);
		}

		$response = new \WP_REST_Response( $result, 201 );
		$response->header( 'Cache-Control', 'no-store' );

		return $response;
	}

	/**
	 * The token exchange, answered in the shape the specification defines
	 * rather than in this plugin's own error shape — a client reads the former
	 * and nothing else.
	 */
	public function answer_token( \WP_REST_Request $request ): \WP_REST_Response {
		/*
		 * Before anything is parsed, for the reason registration states: how
		 * much arrived is the caller's choice, and this route is reachable
		 * with no credential too.
		 */
		if ( strlen( (string) $request->get_body() ) > Server::MAX_BODY_BYTES ) {
			return self::oauth_error(
				'invalid_request',
				__( 'That request is larger than this endpoint accepts.', 'bettershield' ),
				413
			);
		}

		if ( ! self::is_enabled() ) {
			return self::oauth_error( 'invalid_request', __( 'Assistant access is turned off on this site.', 'bettershield' ), 403 );
		}

		// A lockdown pauses every grant, and a refresh would keep a stolen one
		// alive through it to work again the moment it is lifted.
		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			return self::oauth_error( 'temporarily_unavailable', __( 'This site is locked down, so connected apps are paused until the owner lifts it.', 'bettershield' ), 403, 'lockdown' );
		}

		// Only failures are counted, so a client refreshing normally never
		// approaches this however busy it is.
		if ( ! RateLimiter::token_exchange_allowed() ) {
			$response = self::oauth_error(
				'temporarily_unavailable',
				__( 'Too many failed token requests from this network. Try again later.', 'bettershield' ),
				429
			);
			$response->header( 'Retry-After', (string) RateLimiter::anonymous_retry_after() );

			return $response;
		}

		// Form encoding is what the specification asks for; JSON is accepted
		// too, because clients send it.
		$body = $request->get_body_params();

		if ( array() === $body ) {
			$json = $request->get_json_params();
			$body = is_array( $json ) ? $json : array();
		}

		$body = array_map(
			static function ( $value ): string {
				return is_scalar( $value ) ? (string) $value : '';
			},
			$body
		);

		$client_id = (string) ( $body['client_id'] ?? '' );

		/*
		 * Every exchange this client is granted appends a digest to a stored
		 * option, with a life measured in weeks, on a route that answers as
		 * fast as anything can post to it. The failure counter above says
		 * nothing about that: a client holding a live grant never fails.
		 */
		if ( '' !== $client_id && ! RateLimiter::token_issue_allowed( $client_id ) ) {
			$response = self::oauth_error(
				'temporarily_unavailable',
				__( 'This application has been issued too many tokens in a short time. Try again later.', 'bettershield' ),
				429
			);
			$response->header( 'Retry-After', (string) RateLimiter::anonymous_retry_after() );

			return $response;
		}

		$result = OAuth::exchange_token( $body );

		if ( is_wp_error( $result ) ) {
			RateLimiter::record_token_failure();

			$data = $result->get_error_data();

			return self::oauth_error(
				isset( $data['error'] ) ? (string) $data['error'] : 'invalid_request',
				isset( $data['error_description'] ) ? (string) $data['error_description'] : $result->get_error_message(),
				isset( $data['status'] ) ? (int) $data['status'] : 400
			);
		}

		if ( '' !== $client_id ) {
			RateLimiter::record_token_issue( $client_id );
		}

		$response = new \WP_REST_Response( $result, 200 );
		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );

		return $response;
	}

	/**
	 * Revocation: an application handing back a grant it holds (RFC 7009).
	 *
	 * Answered 200 with no body whether or not the token was one this site
	 * issued to that application, as the specification asks, so the answer
	 * tells a caller nothing about any token. A request that names no token or
	 * no application is the caller's own mistake, answered in the token
	 * endpoint's error shape. A token that ended nothing counts against the
	 * network as a failed exchange does, so this cannot try tokens faster than
	 * the token endpoint can.
	 */
	public function answer_revocation( \WP_REST_Request $request ): \WP_REST_Response {
		// Before anything is parsed, for the reason the token endpoint states.
		if ( strlen( (string) $request->get_body() ) > Server::MAX_BODY_BYTES ) {
			return self::oauth_error(
				'invalid_request',
				__( 'That request is larger than this endpoint accepts.', 'bettershield' ),
				413
			);
		}

		if ( ! RateLimiter::token_exchange_allowed() ) {
			$response = self::oauth_error(
				'temporarily_unavailable',
				__( 'Too many failed token requests from this network. Try again later.', 'bettershield' ),
				429
			);
			$response->header( 'Retry-After', (string) RateLimiter::anonymous_retry_after() );

			return $response;
		}

		// Form encoding is what the specification asks for; JSON is accepted
		// too, as at the token endpoint.
		$body = $request->get_body_params();

		if ( array() === $body ) {
			$json = $request->get_json_params();
			$body = is_array( $json ) ? $json : array();
		}

		$body = array_map(
			static function ( $value ): string {
				return is_scalar( $value ) ? (string) $value : '';
			},
			$body
		);

		$result = OAuth::revoke_token( $body );

		if ( is_wp_error( $result ) ) {
			RateLimiter::record_token_failure();

			$data = $result->get_error_data();

			return self::oauth_error(
				isset( $data['error'] ) ? (string) $data['error'] : 'invalid_request',
				isset( $data['error_description'] ) ? (string) $data['error_description'] : $result->get_error_message(),
				isset( $data['status'] ) ? (int) $data['status'] : 400
			);
		}

		if ( empty( $result['ended'] ) ) {
			RateLimiter::record_token_failure();
		}

		$response = new \WP_REST_Response( null, 200 );
		$response->header( 'Cache-Control', 'no-store' );
		$response->header( 'Pragma', 'no-cache' );

		return $response;
	}


	/**
	 * @param string $reason Why, for a program: `lockdown` while the site is locked down. Left out when empty.
	 */
	private static function oauth_error( string $code, string $description, int $status, string $reason = '' ): \WP_REST_Response {
		$body = array(
			'error'             => $code,
			'error_description' => $description,
		);

		// The standard error stays what it was; the reason sits beside it, so a client that knows to look can say why.
		if ( '' !== $reason ) {
			$body['reason'] = $reason;
		}

		$response = new \WP_REST_Response( $body, $status );
		$response->header( 'Cache-Control', 'no-store' );

		return $response;
	}

	/* ---- the consent page ------------------------------------------------------ */

	/**
	 * Ask a person whether an assistant may reach this site, and how far.
	 *
	 * A normal front-end request, so the cookie is read the ordinary way. A
	 * visitor who is not signed in goes to the sign-in screen and comes back
	 * here; anybody who is signed in and cannot manage this plugin is told so
	 * rather than shown a button that would fail.
	 */
	private function serve_consent(): void {
		$posted = 'POST' === self::request_method();

		/*
		 * Read verbatim and validated per parameter in the OAuth server, never
		 * run through a text sanitizer. That one strips every `%XX` octet it
		 * finds, which silently corrupts a double-encoded callback and any
		 * `state` carrying a percent — and `state` is the value a client
		 * compares byte for byte when the answer comes back.
		 */
		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the nonce is checked below, after the request has been validated; every value here is matched against an explicit allow-list in OAuth::validate_authorize_request() and none is stored or echoed unescaped.
		$source = $posted ? $_POST : $_GET;

		$params = array();

		foreach ( self::CONSENT_PARAMS as $key ) {
			$params[ $key ] = isset( $source[ $key ] ) && is_scalar( $source[ $key ] )
				? (string) wp_unslash( $source[ $key ] )
				: '';
		}

		// Only ever from the form, and passed to the password check as typed.
		$params['password'] = $posted && isset( $_POST['password'] ) && is_scalar( $_POST['password'] )
			? (string) wp_unslash( $_POST['password'] )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$outcome = self::consent_outcome( $params, $posted );

		/*
		 * The password the gate asks for, checked by the same rate-limited
		 * confirmation every protected action in the dashboard uses, after
		 * every other check above has passed. It opens the same window, so
		 * the decision is simply taken again with it open.
		 */
		if ( 'confirm_password' === $outcome['action'] ) {
			$confirmed = \BetterShield\Rest\Sudo::confirm( $params['password'] );

			$outcome = is_wp_error( $confirmed )
				? array(
					'action'  => 'ask',
					'request' => $outcome['request'],
					'message' => $confirmed->get_error_message(),
				)
				: self::consent_outcome( $params, $posted );
		}

		switch ( $outcome['action'] ) {
			case 'redirect_error':
				$this->send_back( (string) $outcome['redirect_uri'], array( 'error' => (string) $outcome['error'] ), (string) $outcome['state'] );

				return;

			case 'refuse':
				$this->say( __( 'This connection could not be set up', 'bettershield' ), (string) $outcome['message'], (int) $outcome['status'], $outcome['link'] ?? null );

				return;

			case 'sign_in':
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- assembled into a URL and cleaned in return_to().
				$here = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

				wp_safe_redirect( wp_login_url( self::return_to( $here ) ) );
				exit;

			case 'deny':
				$this->send_back( (string) $outcome['request']['redirect_uri'], array( 'error' => 'access_denied' ), (string) $outcome['request']['state'] );

				return;

			case 'approve':
				$request = $outcome['request'];
				$code    = OAuth::issue_code( $request, get_current_user_id() );

				/*
				 * Recorded high, and its revocation low. An approved
				 * application holds a credential that runs as the account that
				 * approved it and survives the password change an owner makes
				 * on suspecting compromise, so this is the direction that
				 * cannot wait for the weekly summary.
				 */
				Writer::instance()->record(
					'mcp_app_granted',
					Writer::SEVERITY_HIGH,
					array(
						'object_type' => 'mcp_app',
						'object_id'   => (string) $request['client_id'],
						'context'     => array(
							'name'  => (string) $request['client_name'],
							'scope' => (string) $request['scope'],
						),
					)
				);
				Writer::instance()->flush();

				$this->send_back( (string) $request['redirect_uri'], array( 'code' => $code ), (string) $request['state'] );

				return;

			default:
				$this->ask( $outcome['request'], (string) ( $outcome['message'] ?? '' ) );
		}
	}

	/**
	 * What the consent page should do, decided without doing any of it.
	 *
	 * Separated from the page so the decision can be exercised: the page
	 * itself ends the request in every branch, which is right for a page and
	 * leaves nothing for a test to hold. Nothing here writes, redirects or
	 * prints — the caller does all three — so the order of the checks is the
	 * whole of what this returns, and the order is the security property.
	 *
	 * @param array<string, string> $params The request's own parameters.
	 * @return array<string, mixed>
	 */
	public static function consent_outcome( array $params, bool $posted ): array {
		$checked = OAuth::validate_authorize_request( $params );

		if ( is_wp_error( $checked ) ) {
			$data = $checked->get_error_data();

			// Only an address the client actually registered is redirected to,
			// and the validator marks an error redirectable only after it has
			// proved that. Anything else is answered on this page, or a
			// mistyped request becomes a redirector for whoever made it.
			if ( is_array( $data ) && ! empty( $data['redirectable'] ) && '' !== (string) ( $params['redirect_uri'] ?? '' ) ) {
				return array(
					'action'       => 'redirect_error',
					'error'        => $checked->get_error_code(),
					'redirect_uri' => (string) $params['redirect_uri'],
					'state'        => (string) ( $params['state'] ?? '' ),
				);
			}

			return array(
				'action'  => 'refuse',
				'message' => $checked->get_error_message(),
				'status'  => 400,
			);
		}

		if ( ! is_user_logged_in() ) {
			return array( 'action' => 'sign_in' );
		}

		if ( ! current_user_can( \BetterShield\Capabilities::MANAGE ) ) {
			return array(
				'action'  => 'refuse',
				'message' => __( 'Connecting an assistant to this site is an administrator’s decision, and this account cannot manage the site’s security.', 'bettershield' ),
				'status'  => 403,
			);
		}

		/*
		 * The exchange refuses every code while a lockdown is on, so an
		 * approval now would record a grant nothing can use. Refused here,
		 * before anything is approved or spent, so a hub ticket is still good
		 * once the lockdown is lifted.
		 */
		if ( \BetterShield\Recovery\Lockdown::is_active() ) {
			return array(
				'action'  => 'refuse',
				'message' => __( 'This site is locked down, which pauses connected apps. Connect once the lockdown ends.', 'bettershield' ),
				'status'  => 403,
			);
		}

		/*
		 * A code for the hub's return address is issued only against a ticket
		 * this account minted from the dashboard. Without it, anybody could
		 * start a connection in their own hub account and send the owner a
		 * consent page that is genuine in every word, and the site would land
		 * in their workspace.
		 */
		$hub_access = '';

		if ( Hub::is_hub_redirect( (string) $checked['redirect_uri'] ) ) {
			$ticket = Hub::ticket( (string) ( $params['hub_ticket'] ?? '' ), get_current_user_id() );

			if ( null === $ticket ) {
				// Named for the screen with the hub's Connect button, and
				// linked: the person reading it is signed in here.
				return array(
					'action'  => 'refuse',
					'message' => __( 'Connecting this site to BetterShield Hub starts from this site’s dashboard, under BetterShield › Hub, while signed in as the administrator approving it. Start there and the hub brings you back to this page.', 'bettershield' ),
					'status'  => 403,
					'link'    => array(
						'href'  => admin_url( 'admin.php?page=' . \BetterShield\Admin\Sections::HUB ),
						'label' => __( 'Open BetterShield › Hub', 'bettershield' ),
					),
				);
			}

			$checked['hub_ticket'] = (string) $params['hub_ticket'];
			$hub_access            = (string) $ticket['access'];

			// The Hub link can be turned on with the connection, where it could
			// be on the Hub card once connected. Unticked: it is a choice of its
			// own, and connecting does not make it.
			$checked['link_offered'] = \BetterShield\Hub\Link\Link::offered_to( Hub::host_of( (string) $checked['redirect_uri'] ) );
		}

		/*
		 * Whether a change is on the table at all. Two conditions, and both
		 * have to hold: the account approving may make agent changes here —
		 * the owner has turned the write surface on and this account holds
		 * what it is used with, since the grant runs as this account — and
		 * the client asked for it. Neither is assumed from the other — and a
		 * hub connection started as read only stays read only whatever the
		 * client asks for.
		 */
		$checked['may_change'] = Registrar::can_write()
			&& Scopes::allows_write( (string) $checked['scope'] )
			&& Hub::ACCESS_READ !== $hub_access;

		/*
		 * A write grant is the same standing credential Agents › Connect mints,
		 * and a write-scoped connection's own plans stand in for the password
		 * on what it later does. So where this site asks for the password
		 * before minting one there, approving one here asks too. Reading alone
		 * does not.
		 */
		$checked['password_needed'] = $checked['may_change'] && true !== \BetterShield\Rest\Sudo::confirmed();

		if ( ! $posted ) {
			return array(
				'action'  => 'ask',
				'request' => $checked,
			);
		}

		if ( ! wp_verify_nonce( (string) ( $params['nonce'] ?? '' ), self::consent_nonce_action( $checked ) ) ) {
			return array(
				'action'  => 'refuse',
				'message' => __( 'The security check on that form did not pass. Start the connection again from your assistant.', 'bettershield' ),
				'status'  => 403,
			);
		}

		$approving = '' !== (string) ( $params['approve'] ?? '' );
		$changes   = $checked['may_change'] && '' !== (string) ( $params['allow_changes'] ?? '' );

		// Kept on the request whatever happens next, so a page shown again for
		// the password still has it ticked.
		$checked['hub_link'] = ! empty( $checked['link_offered'] ) && '' !== (string) ( $params['hub_link'] ?? '' );

		/*
		 * A write approval without the confirmation is not refused outright:
		 * the page is shown again with the password field and a line saying
		 * why, so the reader can type it or untick the box. A typed password
		 * is handed back to the page to check, because checking it writes —
		 * and nothing here does.
		 */
		if ( $approving && $changes && $checked['password_needed'] ) {
			$typed = '' !== (string) ( $params['password'] ?? '' );

			return array(
				'action'  => $typed ? 'confirm_password' : 'ask',
				'request' => $checked,
				'message' => $typed ? '' : __( 'Enter your password to let it change this site, or untick “Allow it to change this site” to connect it for reading only.', 'bettershield' ),
			);
		}

		// What was actually granted: never more than the client asked for,
		// never more than this site allows, and never more than the person
		// approving it left ticked.
		$checked['scope'] = Scopes::canonical( $changes );

		return array(
			'action'  => $approving ? 'approve' : 'deny',
			'request' => $checked,
		);
	}

	/**
	 * The action the consent form's nonce is taken against.
	 *
	 * Bound to the connection the page was rendered for, and not to the page.
	 * The nonce lives only in that page's own DOM, so this is not a live path
	 * — but it is the whole of what stands between a nonce that leaks by some
	 * other route and a grant for a client, a return address and a scope the
	 * reader never saw. A digest, because the values it covers are longer than
	 * a nonce action wants to be.
	 *
	 * @param array<string, mixed> $request The checked authorize request.
	 */
	public static function consent_nonce_action( array $request ): string {
		$bound = implode(
			'|',
			array(
				(string) ( $request['client_id'] ?? '' ),
				(string) ( $request['redirect_uri'] ?? '' ),
				(string) ( $request['code_challenge'] ?? '' ),
				(string) ( $request['scope'] ?? '' ),
				(string) ( $request['hub_ticket'] ?? '' ),
			)
		);

		return 'bettershield_mcp_consent_' . substr( hash( 'sha256', $bound ), 0, 32 );
	}

	/**
	 * Where a browser is sent back to after signing in.
	 *
	 * Built from this site's own origin plus the request line, rather than
	 * from `home_url( $path )`: `get_home_url()` appends what it is given to a
	 * home URL that on a subdirectory install already carries the path, so the
	 * administrator signs in and lands on a doubled address and a 404 — with
	 * nothing logged and a client watching a flow that never returns.
	 */
	public static function return_to( string $request_uri ): string {
		$home = wp_parse_url( home_url( '/' ) );

		if ( ! is_array( $home ) || '' === (string) ( $home['host'] ?? '' ) ) {
			return home_url( '/' );
		}

		$origin = (string) ( $home['scheme'] ?? 'http' ) . '://' . (string) $home['host'];

		if ( isset( $home['port'] ) ) {
			$origin .= ':' . (int) $home['port'];
		}

		return (string) esc_url_raw( $origin . '/' . ltrim( $request_uri, '/' ) );
	}

	/**
	 * Back to the client, with whatever the answer was.
	 *
	 * Not the safe redirect: this address belongs to the client by design and
	 * has already been checked against the ones it registered. Every value is
	 * encoded on the way in, so a `state` carrying an ampersand cannot append
	 * a second parameter to the callback.
	 *
	 * @param array<string, string> $args
	 */
	private function send_back( string $redirect_uri, array $args, string $state ): void {
		wp_redirect( self::callback_url( $redirect_uri, $args, $state ) ); // phpcs:ignore WordPress.Security.SafeRedirect -- a return address the client registered and this request already matched against it.
		exit;
	}

	/**
	 * The address the client is sent back to, built and not sent.
	 *
	 * Every value is percent-encoded on the way in. `add_query_arg` builds its
	 * query with encoding switched off, so a `state` carrying an ampersand
	 * would otherwise append a second parameter to the callback — and a second
	 * `code` on the callback is a code the client did not ask for, arriving
	 * beside the one it did.
	 *
	 * @param array<string, string> $args
	 */
	public static function callback_url( string $redirect_uri, array $args, string $state ): string {
		if ( '' !== $state ) {
			$args['state'] = $state;
		}

		return (string) add_query_arg( array_map( 'rawurlencode', $args ), $redirect_uri );
	}

	/**
	 * The box that lets a connection change the site. It starts unticked:
	 * changing the site is what the owner chooses, and the note under it
	 * says leaving it unticked reads only. Ticked by default, one press of
	 * Connect gave a just-registered application write access (#2212).
	 */
	public static function change_choice(): string {
		return '<label class="bs-choice"><input type="checkbox" name="allow_changes" value="1" /> <span>'
			. esc_html__( 'Allow it to change this site', 'bettershield' )
			. '</span></label>';
	}

	/**
	 * The consent screen itself.
	 *
	 * Self-contained: it is shown to a person arriving from their assistant,
	 * outside the dashboard, and it says four things before any button — which
	 * site, who they are signed in as, **where the answer will be sent**, and
	 * what the connection would be able to do.
	 *
	 * The third of those is the one that matters most and was the easiest to
	 * leave out. Registration is open to anyone: a stranger can register a
	 * client calling itself by a name the reader trusts and pointing at their
	 * own callback. The name on this page is theirs to choose. The address the
	 * code goes to is not.
	 *
	 * @param array<string, mixed> $request The checked authorize request.
	 * @param string               $problem Why the last answer did not go through, if it did not.
	 */
	private function ask( array $request, string $problem = '' ): void {
		$client     = '' === $request['client_name'] ? __( 'An assistant', 'bettershield' ) : (string) $request['client_name'];
		$user       = wp_get_current_user();
		$may_change = ! empty( $request['may_change'] );

		$fields = '';

		foreach ( array( 'client_id', 'redirect_uri', 'code_challenge', 'scope', 'state', 'resource', 'hub_ticket' ) as $key ) {
			$fields .= sprintf(
				'<input type="hidden" name="%s" value="%s" />',
				esc_attr( $key ),
				esc_attr( (string) ( $request[ $key ] ?? '' ) )
			);
		}

		$fields .= '<input type="hidden" name="code_challenge_method" value="S256" />';
		$fields .= '<input type="hidden" name="response_type" value="code" />';
		$fields .= '<input type="hidden" name="nonce" value="' . esc_attr( wp_create_nonce( self::consent_nonce_action( $request ) ) ) . '" />';

		status_header( 200 );
		self::send_page_headers();
		header( 'Content-Type: text/html; charset=utf-8' );

		echo self::page_head( __( 'Connect an assistant', 'bettershield' ) ); // phpcs:ignore WordPress.Security.EscapeOutput -- assembled and escaped in page_head().

		echo '<p class="bs-eyebrow">' . esc_html__( 'BetterShield', 'bettershield' ) . '</p>';
		echo '<h1>' . esc_html__( 'Connect an assistant', 'bettershield' ) . '</h1>';
		echo '<p class="bs-lead">' . esc_html(
			$may_change
				? sprintf(
					/* translators: %s: the name the assistant registered itself under. */
					__( '%s is asking to read this site’s security, and to change the site where you allow it.', 'bettershield' ),
					$client
				)
				: sprintf(
					/* translators: %s: the name the assistant registered itself under. */
					__( '%s is asking to read this site’s security. It will not be able to change anything.', 'bettershield' ),
					$client
				)
		) . '</p>';

		echo '<dl class="bs-facts">';
		echo '<div><dt>' . esc_html__( 'Site', 'bettershield' ) . '</dt><dd>' . esc_html( self::site_label() ) . '</dd></div>';
		echo '<div><dt>' . esc_html__( 'Signed in as', 'bettershield' ) . '</dt><dd>' . esc_html( (string) $user->user_login ) . '</dd></div>';
		echo '<div><dt>' . esc_html__( 'Sends you back to', 'bettershield' ) . '</dt><dd>' . esc_html( self::return_label( (string) $request['redirect_uri'] ) ) . '</dd></div>';
		echo '</dl>';

		if ( ! empty( $request['first_seen'] ) ) {
			echo '<p class="bs-first-seen">' . esc_html(
				sprintf(
					/* translators: %s: how long ago the application registered itself, e.g. "3 mins". */
					__( 'This application registered itself with this site %s ago, and has not been connected to it before. If you did not just start this from your assistant, close this page.', 'bettershield' ),
					human_time_diff( (int) ( $request['client_created'] ?? time() ), time() )
				)
			) . '</p>';
		}

		if ( '' !== $problem ) {
			echo '<p class="bs-problem" role="alert">' . esc_html( $problem ) . '</p>';
		}

		echo '<form method="post" action="' . esc_url( OAuth::authorize_url() ) . '">';
		echo $fields; // phpcs:ignore WordPress.Security.EscapeOutput -- assembled above with esc_attr on every value.

		if ( $may_change ) {
			echo self::change_choice(); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped where it is built.

			// Not marked required: unticking the box above connects for
			// reading, which needs no password.
			if ( ! empty( $request['password_needed'] ) ) {
				echo '<label class="bs-password"><span>' . esc_html__( 'Your password, to allow changes', 'bettershield' ) . '</span>'
					. '<input type="password" name="password" autocomplete="current-password" /></label>';
			}

			// A write grant agrees each heavier change in the conversation
			// (Registrar::confirms_in_conversation()), so nothing it proposes
			// waits under Requests; saying it did promised a check the grant
			// does not have (#2011).
			echo '<p class="bs-note">' . esc_html__( 'Leave this unticked and the connection can read this site and nothing else. Either way it runs as your account, so it reaches exactly what you reach, and every action it takes is recorded in the activity log. Before a change that cannot be undone at once, it shows you the plan and applies it only once you agree in the conversation.', 'bettershield' ) . '</p>';
		} else {
			echo '<p class="bs-note">' . esc_html__( 'The connection runs as this account, so it reaches exactly what you reach and nothing else. Every action it takes is recorded in the activity log, and you can end the connection at any time under Agents.', 'bettershield' ) . '</p>';
		}

		if ( ! empty( $request['link_offered'] ) ) {
			echo '<label class="bs-choice"><input type="checkbox" name="hub_link" value="1"' . ( empty( $request['hub_link'] ) ? '' : ' checked="checked"' ) . ' /> <span>'
				. esc_html__( 'Also send this site’s security events to the hub as they happen', 'bettershield' )
				. '</span></label>';

			echo '<p class="bs-note">' . esc_html__( 'The Hub link: alerts reach the hub in seconds rather than at its next read. This site signs what it sends with a key that stays here. Turn it off at any time under BetterShield › Hub, which deletes the key.', 'bettershield' ) . '</p>';
		}

		echo self::actions(); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped where it is assembled.
		echo '</form></main></body></html>';
		exit;
	}

	/**
	 * The form's two answers.
	 *
	 * Enter in a field submits with the form's first submit button, and the
	 * first one drawn is "Not Now": an owner who typed the password the page
	 * asked for and pressed Enter turned the assistant away (#2019). So a
	 * Connect the eye and the keyboard never meet comes first, and Enter
	 * connects; the two that are seen keep their order and their tab order.
	 */
	private static function actions(): string {
		return '<div class="bs-actions">'
			. '<button type="submit" name="approve" value="1" class="bs-default" hidden tabindex="-1" aria-hidden="true">' . esc_html__( 'Connect', 'bettershield' ) . '</button>'
			. '<button type="submit" name="deny" value="1" class="bs-secondary">' . esc_html__( 'Not Now', 'bettershield' ) . '</button>'
			. '<button type="submit" name="approve" value="1" class="bs-primary">' . esc_html__( 'Connect', 'bettershield' ) . '</button>'
			. '</div>';
	}

	/**
	 * The site being granted, said so it can be told from its neighbors: its
	 * name, and its home address with the port and path kept. The host alone
	 * read the same for every subsite of a subdirectory network and for two
	 * sites on one machine, so a super admin could not tell which they were
	 * granting.
	 */
	public static function site_label(): string {
		$address = (string) preg_replace( '#^[a-z][a-z0-9+.-]*://#i', '', untrailingslashit( home_url() ) );
		// Stored with its entities encoded; the page escapes it once.
		$name = trim( wp_strip_all_tags( wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ) ) );

		return '' === $name
			? $address
			: sprintf(
				/* translators: 1: the site's name, 2: its home address without the scheme. */
				__( '%1$s (%2$s)', 'bettershield' ),
				$name,
				$address
			);
	}

	/**
	 * Where the code would be sent, said as a person would recognize it.
	 *
	 * The host, because that is the part a reader can judge. An application's
	 * own private-use scheme has no host at all, so that one is named by its
	 * scheme, which is the reverse-domain name the application registered.
	 */
	public static function return_label( string $redirect_uri ): string {
		$parts = wp_parse_url( $redirect_uri );

		if ( ! is_array( $parts ) ) {
			return $redirect_uri;
		}

		$host = (string) ( $parts['host'] ?? '' );

		if ( '' !== $host ) {
			return isset( $parts['port'] ) ? $host . ':' . (int) $parts['port'] : $host;
		}

		return (string) ( $parts['scheme'] ?? $redirect_uri );
	}

	/**
	 * A plain page saying why nothing happened.
	 *
	 * @param array{href: string, label: string}|null $link Where to go instead, when there is somewhere.
	 */
	private function say( string $heading, string $message, int $status, ?array $link = null ): void {
		status_header( $status );
		self::send_page_headers( $status );
		header( 'Content-Type: text/html; charset=utf-8', true, $status );

		echo self::page_head( $heading ); // phpcs:ignore WordPress.Security.EscapeOutput -- assembled and escaped in page_head().
		echo '<h1>' . esc_html( $heading ) . '</h1><p class="bs-lead">' . esc_html( $message ) . '</p>';

		if ( null !== $link ) {
			echo '<p class="bs-actions"><a class="bs-primary bs-link" href="' . esc_url( (string) $link['href'] ) . '">' . esc_html( (string) $link['label'] ) . '</a></p>';
		}
		echo '</main></body></html>';
		exit;
	}

	/**
	 * Everything above the first paragraph of the two pages above.
	 *
	 * These pages echo their own document rather than inheriting one, so the
	 * language and the reading direction have to be stated here: nothing else
	 * on a front-end request outside the dashboard will say them. Every string
	 * on both pages is translated, and a document announcing itself as English
	 * hands a screen reader French text to pronounce as English and lays Arabic
	 * out left to right.
	 *
	 * Public for the same reason as the decision above it: the pages end the
	 * request in every branch, so what they print can only be held here.
	 */
	public static function page_head( string $title ): string {
		$language = str_replace( '_', '-', get_locale() );

		return '<!doctype html><html lang="' . esc_attr( $language ) . '"' . ( is_rtl() ? ' dir="rtl"' : '' )
			. '><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" /><title>'
			. esc_html( $title ) . '</title>'
			. '<style>' . self::page_styles() . '</style></head><body><main class="bs-card">';
	}

	/**
	 * The styles for the two pages above.
	 *
	 * Written here rather than in the admin stylesheets because these pages
	 * are served outside the dashboard, to a browser that has loaded nothing
	 * of this plugin: there is no token layer to inherit from, so the page
	 * declares its own and uses it.
	 */
	private static function page_styles(): string {
		return ':root{--bs-page:#f6f7f7;--bs-surface:#fff;--bs-line:#dcdcde;--bs-ink:#1e1e1e;--bs-muted:#50575e;--bs-accent:#2271b1;--bs-accent-ink:#fff}'
			. '@media (prefers-color-scheme:dark){:root{--bs-page:#1d2327;--bs-surface:#2c3338;--bs-line:#3c434a;--bs-ink:#f0f0f1;--bs-muted:#c3c4c7;--bs-accent:#3582c4;--bs-accent-ink:#fff}}'
			. '*{box-sizing:border-box}'
			. 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;'
			. 'background:var(--bs-page);color:var(--bs-ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}'
			. '.bs-card{width:100%;max-width:420px;background:var(--bs-surface);border:1px solid var(--bs-line);border-radius:12px;padding:32px}'
			. '.bs-eyebrow{margin:0 0 8px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--bs-muted)}'
			. 'h1{margin:0 0 8px;font-size:20px;line-height:1.3}'
			. '.bs-lead{margin:0 0 20px;color:var(--bs-muted)}'
			. '.bs-facts{margin:0 0 20px;border:1px solid var(--bs-line);border-radius:8px;overflow:hidden}'
			. '.bs-facts div{display:flex;justify-content:space-between;gap:16px;padding:12px 16px;font-size:14px}'
			. '.bs-facts div+div{border-top:1px solid var(--bs-line)}'
			. '.bs-facts dt{margin:0;color:var(--bs-muted)}.bs-facts dd{margin:0;font-weight:600;word-break:break-word;text-align:end}'
			. '.bs-first-seen{margin:0 0 20px;padding:12px 16px;border:1px solid var(--bs-line);border-radius:8px;font-size:13px;color:var(--bs-ink)}'
			. '.bs-choice{display:flex;align-items:flex-start;gap:10px;margin:0 0 12px;font-size:14px;font-weight:600}'
			. '.bs-choice input{margin:4px 0 0}'
			. '.bs-password{display:flex;flex-direction:column;gap:6px;margin:0 0 12px 24px;font-size:13px;color:var(--bs-muted)}'
			. '.bs-password input{width:100%;padding:10px 12px;border:1px solid var(--bs-line);border-radius:8px;background:var(--bs-surface);color:var(--bs-ink);font:inherit}'
			. '.bs-problem{margin:0 0 20px;padding:12px 16px;border:1px solid var(--bs-line);border-left:3px solid var(--bs-accent);border-radius:8px;font-size:14px;color:var(--bs-ink)}'
			. '.bs-note{margin:0 0 24px;font-size:13px;color:var(--bs-muted)}'
			. '.bs-actions{display:flex;gap:12px}'
			. 'button{flex:1;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}'
			. '.bs-primary{border:1px solid var(--bs-accent);background:var(--bs-accent);color:var(--bs-accent-ink)}'
			. '.bs-secondary{border:1px solid var(--bs-line);background:transparent;color:var(--bs-ink)}'
			. '.bs-link{flex:1;margin:0;padding:12px;border-radius:8px;font-size:14px;font-weight:600;text-align:center;text-decoration:none}';
	}

	/* ---- plumbing -------------------------------------------------------------- */

	/** The method of the live request, upper-cased. */
	private static function request_method(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared against literals; never stored or echoed.
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
	}

	/**
	 * The `Authorization` header of a request, under either name it arrives
	 * with.
	 *
	 * The pretty path is answered before the REST server exists, so there is
	 * nothing to ask for it but the request itself — and asking for
	 * `HTTP_AUTHORIZATION` alone misses the configuration this path only
	 * exists in. Pretty permalinks on Apache are an internal redirect into
	 * `index.php`, and an internal redirect is what prefixes the variable with
	 * `REDIRECT_`. Core's REST server carries the same fallback, for the same
	 * reason.
	 *
	 * @param array<string, mixed> $server The request's own server variables.
	 */
	public static function bearer_from( array $server ): ?string {
		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $key ) {
			if ( ! isset( $server[ $key ] ) || ! is_scalar( $server[ $key ] ) ) {
				continue;
			}

			$header = (string) wp_unslash( $server[ $key ] );

			if ( '' !== $header ) {
				return $header;
			}
		}

		return null;
	}

	/**
	 * Send a prepared response and stop.
	 *
	 * The status is restated on every header. PHP special-cases
	 * `WWW-Authenticate` and forces a 401 when no status accompanies it, which
	 * would quietly turn the lockout's own answer into an ordinary refusal and
	 * take the wait with it.
	 */
	private function emit( \WP_REST_Response $response ): void {
		$status = $response->get_status();

		status_header( $status );
		self::send_page_headers( $status );
		header( 'MCP-Protocol-Version: ' . Server::PROTOCOL_VERSION, true, $status );

		foreach ( $response->get_headers() as $name => $value ) {
			header( $name . ': ' . $value, true, $status );
		}

		$data = $response->get_data();

		// An answer built as an event stream goes out as one: its content type
		// was sent with the response's own headers above, and its body is text
		// this endpoint has already encoded, message by message.
		if ( $data instanceof EventStream ) {
			echo $data->body; // phpcs:ignore WordPress.Security.EscapeOutput -- an event stream of JSON this endpoint encoded itself.
		} elseif ( null !== $data ) {
			header( 'Content-Type: application/json; charset=utf-8', true, $status );

			echo wp_json_encode( $data ); // phpcs:ignore WordPress.Security.EscapeOutput -- JSON, encoded by WordPress, served as JSON.
		}

		exit;
	}
}
