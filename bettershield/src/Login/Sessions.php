<?php
/**
 * Session controls, on core's own session-token machinery.
 *
 * WordPress already keeps a session record per sign-in — token, start time,
 * expiry, address and browser — in user meta. Core just offers almost no
 * surface over it: one button on your own profile. This adds the rest:
 * an idle timeout, an optional cap on concurrent sessions, an admin view of
 * who is signed in from where, and the two ending actions.
 *
 * Front-end cost discipline: validation piggybacks on reads WordPress
 * already performs; the only write this adds is the idle-timeout's activity
 * stamp, throttled to once a minute per session and skipped on the checkout
 * path — with one stated exception, where the alternative is ending a
 * customer's session mid-order. See `settle_idle()`.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Checkout;
use BetterShield\Support\ClientIp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sessions {

	/**
	 * Session key for the last-seen stamp. Core preserves unknown keys.
	 *
	 * Public because the account's own sessions screen reads the same stamp,
	 * and two spellings of one key is a defect waiting for a rename.
	 */
	public const LAST = 'bettershield_last_seen';

	/**
	 * When the idle timeout was last switched on, as a Unix time.
	 *
	 * No activity is stamped while the timeout is off, so at the moment it is
	 * switched on every session's last sign of life is its sign-in, or a stamp
	 * left from an earlier time it was on. Measured from that, the first
	 * request of every session that signed in longer ago than the limit ended
	 * it — the owner's own, on the screen's reload right after Save. Idle time
	 * is counted from no earlier than this, so every window starts at the
	 * switch.
	 */
	public const IDLE_SINCE = 'bettershield_idle_since';

	/**
	 * How many accounts one press of the site-wide end reaches.
	 *
	 * The same reasoning as the emergency lockdown's own bound: a control an
	 * administrator presses once has to finish, and a request that dies part
	 * way through leaves some sessions ended and others not with nothing
	 * saying which. Past this the surplus is counted and reported rather than
	 * attempted.
	 */
	public const MAX_ENDINGS = 500;

	/** The sign-in page's query key for why a session ended. */
	public const SIGNED_OUT = 'bettershield_signed_out';

	/**
	 * The network this session signed in from, resolved the way everything
	 * else in this plugin resolves one.
	 *
	 * Core stores `$_SERVER['REMOTE_ADDR']` in its own `ip` field, and behind
	 * a CDN or a reverse proxy that address is the edge rather than the
	 * visitor — so both session screens showed the owner a list of their own
	 * CDN's data centers and called it "where you are signed in from", which
	 * is exactly the question those screens exist to answer. Core writes that
	 * field itself after this filter runs, so it cannot be corrected in place;
	 * the resolved answer is kept beside it under our own key and preferred on
	 * read. Stored already truncated: this plugin does not keep a full address
	 * anywhere, and a session record is not the place to start.
	 *
	 * Stored as the printable label rather than the packed prefix everything
	 * else uses. A session record is serialized into user meta, and packed
	 * IPv4 carries null bytes that do not survive that round trip — written
	 * that way it corrupted the whole record, which is every session on the
	 * account. The label is the same fact, already truncated, and is text.
	 */
	private const NETWORK = 'bettershield_network';

	/**
	 * Which site of a network a session was opened on, and that a passkey
	 * opened it: two more keys beside the network in core's own record of the
	 * session, written on a network only. See `attach_origin()`.
	 */
	private const OPENED_ON = 'bettershield_opened_on';
	private const OPENED_BY = 'bettershield_opened_by';

	/** How the next session this request opens was proved, and where, when not here. */
	private static string $next_by = '';

	private static ?int $next_on = null;

	private static ?Sessions $instance = null;

	public static function instance(): Sessions {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Idle timeout: decided while core validates the cookie it already
		// validates, ended by destroying the token core already knows how to
		// destroy. Ending it is not enough on its own: wp_validate_auth_cookie
		// still returns the user ID for the request that tripped the timeout,
		// so the last filter on the way to a current user says "nobody".
		add_action( 'auth_cookie_valid', array( $this, 'check_idle' ), 10, 2 );
		add_action( 'auth_cookie_valid', array( $this, 'check_blocked_name' ), 11, 2 );
		add_action( 'auth_cookie_valid', array( $this, 'check_site_rules' ), 12, 2 );
		add_filter( 'determine_current_user', array( $this, 'nobody_if_ended' ), 99 );
		add_filter( 'rest_pre_dispatch', array( $this, 'before_rest_dispatch' ), 0, 3 );

		// Both halves of the timeout are settled after the request's nature is
		// known, because `auth_cookie_valid` fires before the main query exists
		// and "is this the checkout" cannot be answered there. `wp` is the
		// earliest point it can be, and it is still before anything renders;
		// `shutdown` catches the requests that never reach `wp` at all.
		// This callback takes a transport override only from our direct
		// callers, never the WP object supplied by the public `wp` hook.
		add_action( 'wp', array( $this, 'settle_idle' ), 1, 0 );
		add_filter( 'attach_session_information', array( $this, 'attach_network' ) );
		add_filter( 'attach_session_information', array( $this, 'attach_origin' ) );
		add_action( 'shutdown', array( $this, 'settle_idle' ), 89, 0 );
		add_action( 'shutdown', array( $this, 'stamp_activity' ), 90 );

		/*
		 * A session this request ended is not a session to stamp. The stamp
		 * is queued while the cookie is validated and written at shutdown,
		 * and core's own update() writes the record whether or not it still
		 * exists — so on a Log Out, which destroys the session and then
		 * redirects, the stamp put the token back with its original expiry.
		 * The person saw their cookie cleared and a copy of it kept working
		 * for up to a fortnight. Fires on wp_logout and on every other path
		 * that clears the cookie.
		 */
		add_action( 'clear_auth_cookie', array( $this, 'forget_queued_stamp' ) );

		// Concurrent cap, applied at the moment a new session begins.
		add_action( 'wp_login', array( $this, 'apply_cap' ), 20, 2 );

		// Core says this only once the cookie's signature has checked out, so
		// it was this site's own session, ended since.
		add_action( 'auth_cookie_bad_session_token', array( $this, 'note_ended_session' ) );
		add_filter( 'wp_login_errors', array( $this, 'say_why_signed_out' ) );
	}

	private function idle_minutes(): int {
		return (int) Protection::instance()->settings()['idle_minutes'];
	}

	/**
	 * When a session was last seen, as a Unix time, or 0 where that is not
	 * recorded.
	 *
	 * Activity is stamped only while the idle timeout is on: with it off, a
	 * session's sign-in time stood in, and the screens said "last seen" at
	 * a sign-in an hour old on a session in use all that hour (#2068).
	 *
	 * @param array<string, mixed> $session A session as WordPress stores it.
	 */
	public static function last_seen( array $session ): int {
		if ( 0 === self::instance()->idle_minutes() ) {
			return 0;
		}

		return (int) ( $session[ self::LAST ] ?? $session['login'] ?? 0 );
	}

	/* ---- idle timeout ------------------------------------------------------ */

	/** Whether this request's own session was ended by the idle timeout. */
	private bool $ended_this_request = false;

	/** The session to stamp: user ID, token, session record, write-regardless. */
	private ?array $to_stamp = null;

	/** The session the timeout means to end, once this request is knowable. */
	private ?array $to_end = null;

	/** Whether this request's session belongs to a name this site refuses. */
	private bool $name_refused = false;

	/** Whether this site refuses, by a sign-in rule of its own, the session this request carries. */
	private bool $refused_here = false;

	/** Whether this site's sign-in rules are being read for the cookie now, so a nested check stands aside. */
	private bool $checking_site_rules = false;

	/**
	 * Why the session this request carried has ended, when it provably was
	 * one: `idle` when the timeout ended it here, `ended` when its cookie
	 * still checks out but its session is gone (the session limit, or a
	 * sign-out elsewhere). Empty otherwise, a forged cookie included.
	 */
	private string $ended_why = '';

	/** Test seam: a new request, as far as this request's memory goes. */
	public function reset_request_state(): void {
		$this->ended_this_request = false;
		$this->name_refused       = false;
		$this->refused_here       = false;
		$this->ended_why          = '';
		$this->to_stamp           = null;
		$this->to_end             = null;
		self::$next_by            = '';
		self::$next_on            = null;
	}

	/**
	 * @param mixed $user_id
	 * @return mixed
	 */
	public function nobody_if_ended( $user_id ) {
		return $this->ended_this_request || $this->name_refused || $this->refused_here ? false : $user_id;
	}

	/**
	 * A session opened before its name was put on "Never allowed to sign in".
	 *
	 * The list is judged at the sign-in form, which an open session never
	 * goes back to, so it went on working until it expired. It is judged
	 * here, on every use, as the idle timeout is: the request is nobody. Where
	 * the entry is the name alone, on a single site, every session of the
	 * account is ended at once, since none of them can be used again. A name
	 * paired with a network or a browser allows the account elsewhere, and on
	 * a network a session belongs to every site and one site's list does not
	 * end it on the others: in both, it is refused here and kept.
	 *
	 * The cookie is left as it is: clearing it would ask who the request is
	 * while WordPress is still working that out. With its session gone it
	 * names nobody.
	 *
	 * @param mixed $cookie_elements
	 * @param mixed $user
	 */
	public function check_blocked_name( $cookie_elements, $user ): void {
		if ( ! $user instanceof \WP_User || ! Protection::instance()->blocks_name( $user ) ) {
			return;
		}

		$this->name_refused = true;
		$this->to_stamp     = null;
		$this->to_end       = null;

		if ( is_multisite() || ! Protection::instance()->blocks_name( $user, true ) ) {
			return;
		}

		\WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
		\BetterShield\Rest\Sudo::forget( $user->ID );

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'system',
				'object_type' => 'session',
				'object_id'   => (string) $user->ID,
				'context'     => array( 'reason' => 'name_blocked' ),
			)
		);
	}

	/**
	 * A session opened on another site of this network, asked this site's own
	 * sign-in rules where its cookie is presented: the lockdown, and
	 * passkey-only.
	 *
	 * Both are kept at the sign-in form of the site that set them. On a
	 * network every site's form signs an account in, and the cookie it sets is
	 * good on every site that shares its path or its domain, so a password
	 * typed at another site's form never met them, while its cookie opens this
	 * one. The request is nobody here and the session stands everywhere else,
	 * because those rules are this site's and not the network's.
	 *
	 * @param mixed $cookie_elements
	 * @param mixed $user
	 */
	public function check_site_rules( $cookie_elements, $user ): void {
		if ( ! is_multisite() || ! $user instanceof \WP_User || ! is_array( $cookie_elements ) || ! isset( $cookie_elements['token'] ) ) {
			return;
		}

		/*
		 * Anything the rules below reach that asks for the current user runs
		 * the cookie check, and this hook, again: one pass at a time, or the
		 * request runs out of memory (#2628).
		 */
		if ( $this->checking_site_rules ) {
			return;
		}

		$session = \WP_Session_Tokens::get_instance( $user->ID )->get( (string) $cookie_elements['token'] );

		if ( ! is_array( $session ) ) {
			return;
		}

		$this->checking_site_rules = true;

		try {
			$refused = \BetterShield\Recovery\Lockdown::refuses_session( $user, $session ) || \BetterShield\Passkeys\Policy::instance()->refuses_session( $user, $session );
		} finally {
			$this->checking_site_rules = false;
		}

		if ( $refused ) {
			$this->refused_here = true;
			$this->to_stamp     = null;
			$this->to_end       = null;
		}
	}

	/**
	 * @param array<string, mixed> $cookie_elements
	 * @param mixed $user
	 */
	public function check_idle( $cookie_elements, $user ): void {
		$minutes = $this->idle_minutes();

		if ( 0 === $minutes || SafeMode::is_active() || ! $user instanceof \WP_User || ! is_array( $cookie_elements ) || ! isset( $cookie_elements['token'] ) ) {
			return;
		}

		$token   = (string) $cookie_elements['token'];
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		$session = $manager->get( $token );

		if ( null === $session ) {
			return;
		}

		$last = (int) ( $session[ self::LAST ] ?? $session['login'] ?? 0 );

		// Not idle before the timeout existed; see IDLE_SINCE.
		$last = max( $last, (int) get_option( self::IDLE_SINCE, 0 ) );

		if ( $last > 0 && ( time() - $last ) > $minutes * MINUTE_IN_SECONDS ) {
			$this->to_end = array( $user->ID, $token, $session );

			/*
			 * Settled here when this request cannot be the checkout however it
			 * turns out — no store installed, or wp-admin, which never is one.
			 * That is the overwhelming majority of sites and requests, and it
			 * keeps the end where it has always been for them: immediate, on
			 * the request that found the session stale.
			 */
			if ( is_admin() && wp_doing_ajax() ) {
				// admin-ajax's action is already known before cookie validation.
				// Read it exactly as the dispatcher does; a query parameter for
				// another transport cannot grant a checkout exception here.
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read to classify the request, never to act on; compared against a fixed list, never stored or printed.
				$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? wp_unslash( $_REQUEST['action'] ) : '';
				$this->settle_idle( Checkout::is_store_ajax_action( $action ) );
			} elseif ( ! Checkout::store_present() || is_admin() ) {
				$this->settle_idle( false );
			}

			return;
		}

		// The activity stamp, throttled: a session is "active this minute",
		// not "active at this microsecond". Deferred to shutdown, where the
		// request's nature is known.
		if ( ( time() - $last ) >= MINUTE_IN_SECONDS ) {
			$this->to_stamp = array( $user->ID, $token, $session, false );
		}
	}

	/**
	 * End the stale session, unless this request is the customer's checkout.
	 *
	 * The timeout was decided in one place and enforced in another, and the two
	 * disagreed about which paths were off-limits. `stamp_activity()` refuses
	 * to write on the cart, the checkout, the Store API and any non-GET,
	 * because those are the paths this plugin promised to add nothing to. The
	 * *end* had no such refusal, so a customer driving a block checkout — which
	 * produces Store API calls and no stamped page views at all — accrued idle
	 * time they had no way to clear, and was signed out on their next request.
	 * Often that request was the checkout page itself.
	 *
	 * Two things follow, and the second matters as much as the first.
	 *
	 * **The end never happens on the store path.** Not deferred to the next
	 * page, canceled: it was measured against a clock the customer was never
	 * allowed to wind.
	 *
	 * **Time spent on the store path is activity.** So the stamp that was
	 * skipped is written instead of the end — otherwise the clock keeps running
	 * through the whole checkout and ends the session on the order confirmation
	 * page, which is the same defect one page later. It is one write, at
	 * shutdown, after the response has gone, at most once per idle window per
	 * session, and only ever in place of ending a customer's session mid-order.
	 */
	public function settle_idle( ?bool $store_path = null ): void {
		if ( null === $this->to_end ) {
			return;
		}

		list( $user_id, $token, $session ) = $this->to_end;
		$this->to_end                      = null;

		if ( $store_path ?? Checkout::is_store_path() ) {
			/*
			 * Spared either way — ending a session mid-order is the thing this
			 * exists to avoid, and being generous about what counts costs
			 * nothing there.
			 *
			 * The clock is a different question. Standing down also stamped
			 * the session, so anyone holding a cookie could hold it open
			 * forever by asking for a store address more often than the
			 * timeout, without ever having a cart. Whoever is actually part
			 * way through an order carries the store's own session cookie —
			 * validated by the store, for this account — and still moves the
			 * clock; a request with no shopper behind it is spared and buys
			 * no more time.
			 */
			$this->to_stamp = array( $user_id, $token, $session, Checkout::shopper_present( (int) $user_id ) );

			return;
		}

		\WP_Session_Tokens::get_instance( $user_id )->destroy( $token );

		// The cookie was valid a moment ago; the rest of this request must not
		// proceed as the user whose session just ended. Guarded because the
		// backstop runs at shutdown, where the response may already have gone
		// and setting a cookie is a warning rather than an effect — the token
		// is destroyed either way, so the next request has nothing to present.
		if ( ! headers_sent() ) {
			wp_clear_auth_cookie();
		}

		$this->ended_this_request = true;
		$this->ended_why          = 'idle';
		wp_set_current_user( 0 );

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'session',
				'object_id'   => (string) $user_id,
				'context'     => array( 'reason' => 'idle' ),
			)
		);
	}

	/**
	 * REST never reaches the front-end `wp` hook. Settle before permissions
	 * and callbacks run, using the actual dispatched route. A forged wc-ajax
	 * query on a privileged REST request must not postpone its expiry.
	 *
	 * @param mixed $result
	 * @return mixed
	 */
	public function before_rest_dispatch( $result, \WP_REST_Server $server, \WP_REST_Request $request ) {
		wp_get_current_user();
		$this->settle_idle( Checkout::is_store_rest_route( $request->get_route() ) );
		if ( $this->ended_this_request ) {
			return new \WP_Error( 'bettershield_session_expired', __( 'Your session ended after being idle. Sign in again.', 'bettershield' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	/**
	 * Record the truncated network on a session as it is created.
	 *
	 * @param mixed $info
	 * @return mixed
	 */
	public function attach_network( $info ) {
		if ( ! is_array( $info ) ) {
			return $info;
		}

		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		$label    = \BetterShield\Support\Ip::prefix_label( \BetterShield\Support\Ip::truncated_binary( (string) $resolved['ip'] ) );

		if ( is_string( $label ) && '' !== $label ) {
			$info[ self::NETWORK ] = $label;
		}

		return $info;
	}

	/**
	 * Record, on a network, which site a session was opened on and whether a
	 * passkey opened it: what `check_site_rules()` asks of a session presented
	 * to another site. Neither is about the person: a site's number, and one
	 * word.
	 *
	 * @param mixed $info
	 * @return mixed
	 */
	public function attach_origin( $info ) {
		$by            = self::$next_by;
		$on            = self::$next_on;
		self::$next_by = '';
		self::$next_on = null;

		if ( ! is_array( $info ) || ! is_multisite() ) {
			return $info;
		}

		$info[ self::OPENED_ON ] = $on ?? get_current_blog_id();

		if ( 'passkey' === $by ) {
			$info[ self::OPENED_BY ] = 'passkey';
		}

		return $info;
	}

	/**
	 * Say how the session about to be opened was proved. The passkey sign-in
	 * says so just before it sets the cookie; every other session is recorded
	 * as opened some other way.
	 */
	public static function opening_by( string $proof ): void {
		self::$next_by = 'passkey' === $proof ? 'passkey' : '';
	}

	/**
	 * Carry the current session's origin onto the next one this request opens
	 * for the account: a session minted in its place, as a key rotation's
	 * hand-off mints one, is the same sign-in.
	 */
	public static function carry_current_origin( int $user_id ): void {
		$session = \WP_Session_Tokens::get_instance( $user_id )->get( (string) wp_get_session_token() );

		if ( ! is_array( $session ) ) {
			return;
		}

		self::$next_by = self::opened_by_passkey( $session ) ? 'passkey' : '';
		self::$next_on = isset( $session[ self::OPENED_ON ] ) ? (int) $session[ self::OPENED_ON ] : null;
	}

	/**
	 * Whether a session was opened on a site of this network other than this
	 * one, as its record says; null for a record from before sessions said.
	 *
	 * @param array<string, mixed> $session
	 */
	public static function opened_elsewhere( array $session ): ?bool {
		if ( ! isset( $session[ self::OPENED_ON ] ) ) {
			return null;
		}

		return (int) $session[ self::OPENED_ON ] !== get_current_blog_id();
	}

	/**
	 * Whether a passkey opened this session.
	 *
	 * @param array<string, mixed> $session
	 */
	public static function opened_by_passkey( array $session ): bool {
		return 'passkey' === ( $session[ self::OPENED_BY ] ?? '' );
	}

	/**
	 * A browser string as a person reads it: "Chrome on macOS".
	 *
	 * The raw string, cut to a column's width, ended mid-token and left two
	 * phones on the same system looking identical. Only the browser and the
	 * system are named; what is not recognized falls back to the raw string.
	 */
	public static function device_label( string $user_agent ): string {
		$browsers = array(
			'/HeadlessChrome\//'          => __( 'Chrome (headless)', 'bettershield' ),
			'/Edg(?:e|A|iOS)?\//'          => 'Edge',
			'/OPR\/|Opera/'                => 'Opera',
			'/SamsungBrowser\//'           => 'Samsung Internet',
			'/Firefox\/|FxiOS\//'          => 'Firefox',
			'/Chrome\/|CriOS\/|Chromium\//' => 'Chrome',
			'/Version\/[\d.]+.*Safari\//' => 'Safari',
		);
		$systems  = array(
			'/iPhone/'        => 'iPhone',
			'/iPad/'          => 'iPad',
			'/Android/'       => 'Android',
			'/Windows/'       => 'Windows',
			'/CrOS/'          => 'ChromeOS',
			'/Mac OS X|Macintosh/' => 'macOS',
			'/Linux/'         => 'Linux',
		);
		$find     = static function ( array $patterns ) use ( $user_agent ): string {
			foreach ( $patterns as $pattern => $name ) {
				if ( 1 === preg_match( $pattern, $user_agent ) ) {
					return $name;
				}
			}

			return '';
		};
		$browser  = $find( $browsers );
		$system   = $find( $systems );

		if ( '' !== $browser && '' !== $system ) {
			/* translators: 1: a browser, e.g. "Chrome"; 2: an operating system, e.g. "macOS". */
			return sprintf( __( '%1$s on %2$s', 'bettershield' ), $browser, $system );
		}

		return '' !== $browser . $system ? $browser . $system : \BetterShield\Support\Text::clip( $user_agent, 120 );
	}

	/**
	 * The network to show for one session record.
	 *
	 * Ours where we have it, core's `ip` where we do not — a session created
	 * before this existed, or by something that signed a user in another way.
	 * Truncated either way, so nothing here can show a full address.
	 *
	 * @param array<string, mixed> $session
	 */
	public static function network_label( array $session ): string {
		$stored = (string) ( $session[ self::NETWORK ] ?? '' );

		if ( '' !== $stored ) {
			return $stored;
		}

		return (string) ( \BetterShield\Support\Ip::prefix_label( \BetterShield\Support\Ip::truncated_binary( (string) ( $session['ip'] ?? '' ) ) ) ?? '' );
	}

	public function note_ended_session(): void {
		if ( '' === $this->ended_why ) {
			$this->ended_why = 'ended';
		}
	}

	/**
	 * Why the session this request carried ended, when it provably was a
	 * session of this site; see `$ended_why`. Read after the current user
	 * has been worked out.
	 */
	public function ended_why(): string {
		return $this->ended_why;
	}

	/**
	 * The reason on the sign-in page a dashboard click was sent to after its
	 * session ended. Only a fixed message is shown, so the query carries
	 * nothing anyone could inject.
	 *
	 * @param mixed $errors
	 * @return mixed
	 */
	public function say_why_signed_out( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- picks one of two fixed messages, nothing is acted on.
		$why = isset( $_GET[ self::SIGNED_OUT ] ) && is_string( $_GET[ self::SIGNED_OUT ] ) ? sanitize_key( wp_unslash( $_GET[ self::SIGNED_OUT ] ) ) : '';

		if ( ! $errors instanceof \WP_Error || ! in_array( $why, array( 'idle', 'ended' ), true ) ) {
			return $errors;
		}

		$errors->add(
			'bettershield_signed_out',
			'idle' === $why
				? __( 'You were signed out after being idle. Sign in again to continue.', 'bettershield' )
				: __( 'You were signed out, because this account signed in somewhere else or its session was ended. Sign in again to continue.', 'bettershield' ),
			'message'
		);

		return $errors;
	}

	/**
	 * Drop the queued stamp: whatever it was about is over.
	 */
	public function forget_queued_stamp(): void {
		$this->to_stamp           = null;
		$this->ended_this_request = true;
	}

	/**
	 * Write the deferred activity stamp — on a plain page view only. Never
	 * on the checkout or cart, never on a POST or a store/AJAX call: the
	 * stamp rewrites the user's whole session record, which is a write this
	 * plugin promised never to add to those paths. A session that only ever
	 * touches those paths is stamped on its next ordinary page.
	 *
	 * The one exception is the stamp `settle_idle()` writes in place of ending
	 * a session on the store path, which carries its own reason and is
	 * explained there.
	 */
	public function stamp_activity(): void {
		if ( null === $this->to_stamp || $this->ended_this_request ) {
			return;
		}

		list( $user_id, $token, $session, $regardless ) = $this->to_stamp;
		$this->to_stamp                                 = null;

		if ( ! $regardless && ! $this->stampable_request() ) {
			return;
		}

		$session[ self::LAST ] = time();
		\WP_Session_Tokens::get_instance( $user_id )->update( $token, $session );
	}

	/**
	 * Whether this request is one the routine activity stamp may be written on.
	 *
	 * The rule this replaces was "a plain GET page view, and nothing else",
	 * which is not a statement about whether somebody is present — it is a
	 * statement about how their work happens to reach the server. All of the
	 * block editor is autosaves over REST and heartbeats over admin-ajax, and
	 * none of it is a page view, so an editor working on one long post was read
	 * as idle from the moment they opened it and signed out mid-sentence. Their
	 * next autosave was refused, which is where they found out.
	 *
	 * So the question is presence, not shape:
	 *
	 * **A background poll is not activity.** The heartbeat runs because a tab is
	 * open, not because a person is at it, and stamping on it would turn the
	 * idle timeout into a timeout that never fires for anybody who left a tab
	 * open — which is precisely who it is for.
	 *
	 * **Anything a person had to do is.** A save, an autosave, an upload, a
	 * settings change: core does not make those requests on its own. Written at
	 * shutdown, after the response, and at most once a minute per session, so
	 * the request that carries it is not made to wait for it.
	 *
	 * The store path is excluded here whatever the shape, and stays excluded —
	 * a checkout gets the one stamp `settle_idle()` writes in place of ending
	 * the session, and no other.
	 */
	private function stampable_request(): bool {
		if ( $this->is_checkout() || $this->is_background_poll() ) {
			return false;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) ) : '';

		// A page somebody asked for.
		if ( 'GET' === $method ) {
			return ! wp_doing_ajax() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		}

		// Or a change somebody made. The cookie that carried this request is
		// how we got here at all, so the person is signed in and deliberate.
		return true;
	}

	/**
	 * Whether this request is WordPress talking to itself while a tab is open.
	 *
	 * Named rather than inferred from the shape: the heartbeat is a POST to
	 * admin-ajax, which is the same shape as an autosave and the opposite thing.
	 */
	private function is_background_poll(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read to classify the request, never to act on. Core verifies the heartbeat's own nonce.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( (string) $_REQUEST['action'] ) ) : '';

		return 'heartbeat' === $action;
	}

	/* ---- concurrent cap ----------------------------------------------------- */

	/**
	 * Whether a cap can be enforced on this site at all.
	 *
	 * Enforcing it means removing entries from the `session_tokens` user meta
	 * WordPress keeps sessions in — core's manager exposes no way to end one
	 * specific session, so there is no API to do this through. A site that
	 * swapped the manager for a cache-backed or SSO one has no such meta, and
	 * the cap was a silent no-op there: the screen said a limit was set, and
	 * every extra session was allowed.
	 *
	 * Asked of the manager this site actually built, the same way the
	 * per-session control asks — a site that swapped the class through some
	 * other route than the filter still answers correctly.
	 */
	public function cap_supported(): bool {
		return \WP_Session_Tokens::get_instance( get_current_user_id() ) instanceof \WP_User_Meta_Session_Tokens;
	}

	/**
	 * @param mixed $user
	 */
	public function apply_cap( string $user_login, $user ): void {
		$cap = (int) Protection::instance()->settings()['session_cap'];

		if ( $cap < 1 || SafeMode::is_active() || ! $user instanceof \WP_User ) {
			return;
		}

		// Nothing here can work on this site. Not recorded as an event — that
		// would be a row on every sign-in for a condition that does not change
		// between them; the screen that offers the setting is where it is said,
		// beside the field, before anybody relies on it.
		if ( ! ( \WP_Session_Tokens::get_instance( (int) $user->ID ) instanceof \WP_User_Meta_Session_Tokens ) ) {
			return;
		}

		// Core keeps sessions as user meta keyed by token verifier; ending
		// specific ones means editing that array. Oldest sign-ins go first,
		// and the session that just started is by definition the newest.
		$sessions = get_user_meta( $user->ID, 'session_tokens', true );

		if ( ! is_array( $sessions ) || count( $sessions ) <= $cap ) {
			return;
		}

		uasort(
			$sessions,
			static function ( array $a, array $b ): int {
				return ( $a['login'] ?? 0 ) <=> ( $b['login'] ?? 0 );
			}
		);

		$excess = array_slice( array_keys( $sessions ), 0, count( $sessions ) - $cap );

		foreach ( $excess as $verifier ) {
			unset( $sessions[ $verifier ] );
		}

		update_user_meta( $user->ID, 'session_tokens', $sessions );

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'session',
				'object_id'   => (string) $user->ID,
				'context'     => array(
					'reason' => 'cap',
					'ended'  => count( $excess ),
				),
			)
		);
	}

	/* ---- admin surface -------------------------------------------------------- */

	/**
	 * How many accounts one read of the list carries. A store's customers
	 * stay signed in for two weeks, and three thousand of them made a
	 * megabyte answer and a page three hundred thousand pixels tall.
	 */
	public const LISTED = 50;

	/**
	 * How many live sessions each account here holds, by account ID, in
	 * login order: every signed-in account, without loading any of them.
	 *
	 * The accounts are found by their session row and read as IDs, and the
	 * rows are read a batch at a time, that one key alone. Loading the
	 * accounts brought every meta row each one holds along with it, so a
	 * store's thousands of customers were all in memory to answer one page
	 * of fifty. An account whose sessions have all expired is left out: core
	 * keeps the row until the person signs in again.
	 *
	 * @return array<int, int>
	 */
	public function live_counts(): array {
		global $wpdb;

		$holders = get_users(
			array(
				'fields'       => 'ID',
				'meta_key'     => 'session_tokens', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- IDs only; an admin-screen read, never front-end.
				'meta_compare' => 'EXISTS',
			)
		);

		$now  = time();
		$live = array();

		foreach ( array_chunk( array_map( 'intval', $holders ), 500 ) as $batch ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one meta key for a bounded batch of accounts, which no core API reads without loading every other key they hold; the placeholder run's length is the batch's own, and every value is bound.
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					'SELECT user_id, meta_value FROM %i WHERE meta_key = %s AND user_id IN (' . implode( ', ', array_fill( 0, count( $batch ), '%d' ) ) . ') ORDER BY umeta_id',
					$wpdb->usermeta,
					'session_tokens',
					...$batch
				)
			);
			// phpcs:enable

			$held = array();

			foreach ( $rows as $row ) {
				$user_id = (int) $row->user_id;

				// The first row only, as get_user_meta( ..., true ) reads it.
				if ( isset( $held[ $user_id ] ) ) {
					continue;
				}

				$held[ $user_id ] = 0;
				$sessions         = maybe_unserialize( $row->meta_value );

				foreach ( is_array( $sessions ) ? $sessions : array() as $session ) {
					if ( is_array( $session ) && ( $session['expiration'] ?? 0 ) >= $now ) {
						++$held[ $user_id ];
					}
				}
			}

			foreach ( $batch as $user_id ) {
				if ( ( $held[ $user_id ] ?? 0 ) > 0 ) {
					$live[ $user_id ] = $held[ $user_id ];
				}
			}
		}

		return $live;
	}

	/**
	 * The accounts in the order the list reads them: the reader first, then
	 * the accounts that can change the site, then everyone else, each part
	 * by login. A page of the list is then the part worth reading: on a store
	 * the rest are customers, who stay signed in for two weeks at a time.
	 *
	 * Which accounts can change the site is asked of the database, so the
	 * order loads none of them. A capability only a filter grants at runtime
	 * is not there to be found; such an account is still marked privileged
	 * on its own row, and sorts with the rest.
	 *
	 * @param array<int, int> $live Live session counts by account, in login order.
	 * @return int[]
	 */
	private function ordered( array $live ): array {
		$me         = get_current_user_id();
		$privileged = array_flip(
			\BetterShield\Password\Policy::instance()->privileged_ids(
				array(
					'meta_key'     => 'session_tokens', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- IDs only; an admin-screen read, never front-end.
					'meta_compare' => 'EXISTS',
				)
			)
		);
		$parts      = array( array(), array(), array() );

		foreach ( array_keys( $live ) as $user_id ) {
			if ( $me === $user_id ) {
				$parts[0][] = $user_id;
			} elseif ( isset( $privileged[ $user_id ] ) ) {
				$parts[1][] = $user_id;
			} else {
				$parts[2][] = $user_id;
			}
		}

		return array_merge( ...$parts );
	}

	/**
	 * Who is signed in: user, role, and each session's start, last activity,
	 * expiry, network and browser, for one page of the accounts in the list's
	 * order, or every account when no page is asked for. Core keeps the
	 * address in full in its own session record; this plugin shows it the way
	 * it shows every address — the network, never the host — so a screen of
	 * this plugin never displays what it promised never to keep.
	 *
	 * Only the accounts on the page are loaded.
	 *
	 * @param int                  $offset How many accounts of the list come before the page.
	 * @param int|null             $limit  How many accounts the page holds; null for the rest of the list.
	 * @param array<int, int>|null $live   live_counts(), where the caller has read it already.
	 * @return array<int, array<string, mixed>>
	 */
	public function active( int $offset = 0, ?int $limit = null, ?array $live = null ): array {
		$page = array_slice( $this->ordered( $live ?? $this->live_counts() ), max( 0, $offset ), $limit );

		if ( array() === $page ) {
			return array();
		}

		// One read for the page's accounts and their meta together, rather
		// than one for every account on it.
		cache_users( $page );

		$out = array();
		$now = time();
		$me  = get_current_user_id();

		foreach ( $page as $user_id ) {
			$user = get_userdata( $user_id );

			if ( ! $user instanceof \WP_User ) {
				continue;
			}

			$sessions = get_user_meta( $user_id, 'session_tokens', true );

			if ( ! is_array( $sessions ) ) {
				continue;
			}

			$rows = array();
			foreach ( $sessions as $session ) {
				if ( ! is_array( $session ) || ( $session['expiration'] ?? 0 ) < $now ) {
					continue;
				}

				$rows[] = array(
					'signed_in_at' => gmdate( 'c', (int) ( $session['login'] ?? 0 ) ),
					'last_seen_at' => 0 === self::last_seen( $session ) ? null : gmdate( 'c', self::last_seen( $session ) ),
					'expires_at'   => gmdate( 'c', (int) ( $session['expiration'] ?? 0 ) ),
					'ip'           => self::network_label( $session ),
					'browser'      => substr( (string) ( $session['ua'] ?? '' ), 0, 120 ),
				);
			}

			// Ended or expired since the accounts were counted.
			if ( array() === $rows ) {
				continue;
			}

			$out[] = array(
				'user_id'    => $user->ID,
				'login'      => $user->user_login,
				'roles'      => array_values( (array) $user->roles ),
				'is_me'      => $me === $user->ID,
				'privileged' => \BetterShield\Password\Policy::instance()->user_is_privileged( $user ),
				'sessions'   => $rows,
			);
		}

		return $out;
	}

	/**
	 * End every session one user holds.
	 *
	 * On a network that is every session on every site: session tokens are
	 * user meta, and user meta is one table for the whole network. There is no
	 * such thing as signing somebody out of one site of a network, so the
	 * answer says how far this went rather than letting the screen call it a
	 * site-level act.
	 *
	 * @return array{ended_own: bool, network_wide: bool}
	 */
	public function end_for_user( int $user_id ): array {
		// Ending your own row from this control ends the session the request
		// is being served under. A stamp queued earlier in the same request
		// would write the destroyed token back at shutdown, and the screen
		// has already promised the opposite. Conditional, unlike the sweep's:
		// this control can be pointed at somebody else, and canceling the
		// caller's own stamp then would be ending a session nobody asked to
		// end.
		if ( get_current_user_id() === $user_id ) {
			$this->forget_queued_stamp();
		}

		\WP_Session_Tokens::get_instance( $user_id )->destroy_all();

		// A confirmation given under the sessions just ended does not survive
		// them — otherwise a fresh sign-in inside the window inherits it.
		\BetterShield\Rest\Sudo::forget( $user_id );

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'session',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'reason'       => 'admin_user',
					'network_wide' => is_multisite(),
				),
			)
		);

		return array(
			'ended_own'    => get_current_user_id() === $user_id,
			'network_wide' => is_multisite(),
		);
	}

	/**
	 * The accounts a sweep of this site should reach.
	 *
	 * Members with a session, plus — on a network — the super admins, found by
	 * name. A capability or membership query is answered from this site's own
	 * capabilities meta, and an account with no role here has no such row,
	 * which is the ordinary state of the accounts that hold the run of every
	 * site on the network. They are the sessions a sweep most needs to reach,
	 * so leaving them out made the button quietest about exactly the accounts
	 * that matter most. The lockdown's own sweep closed this; this one had
	 * not.
	 *
	 * @return int[]
	 */
	private function sweepable_members(): array {
		$ids = array();

		/*
		 * The network's own administrators come first of all, and on a network
		 * they outrank this site's own capable accounts: the docblock above
		 * says they are the sessions a sweep most needs to reach, and they are
		 * the ones with nothing on this site to be found by. Collected before
		 * the local queries rather than appended after them, because the cut
		 * falls on the tail and appending put them there — on a subsite whose
		 * roster already fills the bound, "sign out everyone" silently spared
		 * the one account with the run of every site on the network.
		 */
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$super = get_user_by( 'login', (string) $login );

				if ( $super instanceof \WP_User ) {
					$ids[] = (int) $super->ID;
				}
			}

			$ids = array_values( array_unique( $ids ) );
		}

		/*
		 * Then the accounts that can reach the dashboard, and the cut falls on
		 * the rest.
		 *
		 * The set is "every account holding a session_tokens row", and core
		 * leaves that row behind until the person signs in again — so on a
		 * store or a membership site it is mostly long-dormant customers. With
		 * no order given, the query answers alphabetically by login, so a cap
		 * of five hundred kept the first five hundred names and could leave an
		 * administrator signed in on a larger site. That is the one account
		 * the panic button exists for, and an attacker who picks their own
		 * username decides where in that list they sort.
		 *
		 * Each read asks for what is left of the bound and excludes what is
		 * already held, so the total still stops one past it — which is what
		 * lets the caller report a surplus that means what it says.
		 */
		$capable = count( $ids ) > self::MAX_ENDINGS
			? array()
			: get_users(
				array(
					'fields'       => 'ID',
					'number'       => self::MAX_ENDINGS + 1 - count( $ids ),
					'capability'   => 'edit_posts',
					'exclude'      => $ids,
					'meta_key'     => 'session_tokens', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- bounded above; an administrator's own button, never a front-end path.
					'meta_compare' => 'EXISTS',
				)
			);

		foreach ( $capable as $member_id ) {
			$ids[] = (int) $member_id;
		}

		$members = count( $ids ) > self::MAX_ENDINGS
			? array()
			: get_users(
				array(
					'fields'       => 'ID',
					'number'       => self::MAX_ENDINGS + 1 - count( $ids ),
					'exclude'      => $ids,
					'meta_key'     => 'session_tokens', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- bounded above; an administrator's own button, never a front-end path.
					'meta_compare' => 'EXISTS',
				)
			);

		foreach ( $members as $member_id ) {
			$ids[] = (int) $member_id;
		}

		return array_values( array_unique( $ids ) );
	}

	/**
	 * How many accounts the sweep would reach with no bound: every account
	 * here holding a session, and on a network its administrators who do not.
	 * Counted by the database, never read.
	 */
	private function count_sweepable(): int {
		$query = new \WP_User_Query(
			array(
				'fields'       => 'ID',
				'number'       => 1,
				'count_total'  => true,
				'meta_key'     => 'session_tokens', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- one count, only once the bound has been reached; an administrator's own button.
				'meta_compare' => 'EXISTS',
			)
		);

		$total = (int) $query->get_total();

		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$super = get_user_by( 'login', (string) $login );

				if ( $super instanceof \WP_User && ! ( is_user_member_of_blog( (int) $super->ID ) && '' !== get_user_meta( (int) $super->ID, 'session_tokens', true ) ) ) {
					++$total;
				}
			}
		}

		return $total;
	}

	/** The same bounded accounts and authority the site-wide ending uses, for its confirmation plan. */
	public function ending_preview(): array {
		$members = $this->sweepable_members();
		$surplus = count( $members ) > self::MAX_ENDINGS ? max( count( $members ), $this->count_sweepable() ) - self::MAX_ENDINGS : 0;
		$accounts = array(); $skipped = 0;
		foreach ( array_slice( $members, 0, self::MAX_ENDINGS ) as $id ) {
			if ( ! current_user_can( 'edit_user', (int) $id ) ) { ++$skipped; continue; }
			$accounts[ (int) $id ] = count( \WP_Session_Tokens::get_instance( (int) $id )->get_all() );
		}
		return array( 'accounts' => $accounts, 'skipped' => $skipped, 'surplus' => $surplus, 'reach' => $this->site_wide_reach( $accounts ) );
	}

	/**
	 * End every session the caller has the standing to end.
	 *
	 * This is the panic button, and it keeps doing what it is for: throwing an
	 * intruder out of every door at once. What it no longer does is reach
	 * accounts the person pressing it has no say over. Managing this plugin
	 * can be delegated below administrator, and a delegated manager signing
	 * the site's own owners out is not incident response — it is the lockout
	 * this plugin exists to prevent, performed by the plugin.
	 *
	 * So the same rule the per-account path uses decides the set: an account
	 * is included when the caller may edit it. An administrator still reaches
	 * everybody, because an administrator may edit everybody. The count is
	 * returned so the screen can say what it will reach before it is pressed,
	 * and say what it reached afterwards.
	 *
	 * @return array{ended_own: bool, ended: int, skipped: int, surplus: int}
	 */
	public function end_all(): array {
		$ended     = 0;
		$skipped   = 0;
		$self      = get_current_user_id();
		$ended_own = false;

		// This sweep ends the caller's own session too, and the confirmation
		// says so. A stamp queued earlier in the same request would put it
		// straight back at shutdown.
		$this->forget_queued_stamp();

		/*
		 * Only accounts that hold a session, plus the network's own
		 * administrators. Ending one is a delete against the meta table, and
		 * core looks the key up before it can know there is nothing there to
		 * remove — so a sweep over every member of the site paid an uncached
		 * read for each account that was signed in nowhere at all.
		 */
		$members = $this->sweepable_members();

		/*
		 * Bounded, and honest about the bound: the read asks for one more than
		 * the bound, so a non-zero surplus means "at least this many were not
		 * reached" and a record of this sweep never means more than it says.
		 */
		$surplus = 0;

		if ( count( $members ) > self::MAX_ENDINGS ) {
			// The read stops one past the bound, so its own count could never
			// say more than one was left. How many hold a session is counted
			// instead, once, and only when the bound was reached.
			$surplus = max( count( $members ), $this->count_sweepable() ) - self::MAX_ENDINGS;
			$members = array_slice( $members, 0, self::MAX_ENDINGS );
		}

		foreach ( $members as $member_id ) {
			$member_id = (int) $member_id;

			if ( ! current_user_can( 'edit_user', $member_id ) ) {
				++$skipped;
				continue;
			}

			\WP_Session_Tokens::get_instance( $member_id )->destroy_all();
			++$ended;

			if ( $member_id === $self ) {
				$ended_own = true;
			}
		}

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'session',
				'object_id'   => 'site',
				'context'     => array(
					'reason'  => 'admin_site',
					'ended'   => $ended,
					// Named rather than silent: a panic button that quietly
					// reached less than everything would be read as having
					// reached everything. The two reasons are kept apart —
					// accounts this caller has no say over, and accounts past
					// the bound — because they call for different answers.
					'skipped' => $skipped,
					'surplus' => $surplus,
					// And how far each ending went, which on a network is
					// further than the button's name suggests.
					'network_wide' => is_multisite(),
				),
			)
		);

		return array(
			'ended_own'    => $ended_own,
			'ended'        => $ended,
			'skipped'      => $skipped,
			'surplus'      => $surplus,
			'network_wide' => is_multisite(),
		);
	}

	/**
	 * How long a rotation's sweep of a network runs before it stops.
	 *
	 * The same clock the activation walk keeps, for the same reason: this is
	 * somebody's click, and a network large enough to outrun a request must
	 * not turn it into one that never comes back. Sites the clock stops short
	 * of are reported rather than passed over silently — the keys have already
	 * changed everywhere, so nobody on them is signed in regardless; what they
	 * are missing is the row saying so.
	 */
	private const NETWORK_SWEEP_SECONDS = 20.0;

	/** How many sites one page of the sweep holds. */
	private const SITES_PER_PAGE = 200;

	/**
	 * End every session on every site of a network, sparing one.
	 *
	 * Used by the network key rotation, which has already replaced the secret
	 * every cookie is signed with — so the sessions this walks are already
	 * worthless, and what the walk is really for is the record: each site gets
	 * its own row saying its members were signed out and why, on the site
	 * whose log the people affected will read.
	 *
	 * The account named by `$keep` keeps the one token it is holding and loses
	 * its others, the way the lockdown sweep spares the person throwing the
	 * switch. Everything else goes.
	 *
	 * @return array{ended: int, accounts: int, sites: int, capped: bool}
	 */
	public function end_across_network( int $keep, string $keep_token, string $reason ): array {
		$ended    = 0;
		$accounts = 0;
		$sites    = 0;
		$started  = microtime( true );
		$offset   = 0;
		$capped   = false;

		do {
			$site_ids = get_sites(
				array(
					'fields'     => 'ids',
					'number'     => self::SITES_PER_PAGE,
					'offset'     => $offset,
					// The key this sweep follows is a network option, so the
					// sweep covers that network's sites and not every network
					// sharing the installation.
					'network_id' => get_current_network_id(),
				)
			);

			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );

				// The restore is in a `finally` for the same reason the flush
				// is inside the switch: one site's share of this walk touching
				// the database and the session store can throw, and a throw
				// that skipped the restore would leave every query for the
				// rest of the request — the buffered rows above all —
				// answering for whichever site the walk stopped on.
				try {
					$here = $this->end_here_for_rotation( $keep, $keep_token, $reason );

					$ended    += $here['ended'];
					$accounts += $here['accounts'];
					++$sites;

					// Drained inside the switch: a buffered row flushed after
					// the site is restored would be written into a different
					// site's table on a network the migration has not finished
					// carrying over.
					Writer::instance()->flush();
				} finally {
					restore_current_blog();
				}
			}

			$offset += self::SITES_PER_PAGE;

			if ( count( $site_ids ) === self::SITES_PER_PAGE && microtime( true ) - $started >= self::NETWORK_SWEEP_SECONDS ) {
				$capped = true;

				break;
			}
		} while ( count( $site_ids ) === self::SITES_PER_PAGE );

		return array(
			'ended'    => $ended,
			'accounts' => $accounts,
			'sites'    => $sites,
			'capped'   => $capped,
		);
	}

	/**
	 * One site's share of the sweep above, with this site switched to — and,
	 * on a single site, the whole of it, which is why it is reachable from
	 * outside. A single site's key rotation ends the same sessions for the
	 * same reason, and a second copy of this walk would drift from it.
	 *
	 * No capability question is asked here, and that is the difference from
	 * the site-wide button: this is not one administrator reaching across
	 * accounts they have no say over, it is the consequence of a key that no
	 * longer signs anybody's cookie. Refusing to record it for an account
	 * whose sessions have already stopped working would only make the log
	 * less true than the site.
	 *
	 * @return array{ended: int, accounts: int}
	 */
	public function end_here_for_rotation( int $keep, string $keep_token, string $reason ): array {
		$ended    = 0;
		$accounts = 0;
		$members  = $this->sweepable_members();
		$surplus  = 0;

		if ( count( $members ) > self::MAX_ENDINGS ) {
			// As end_all() counts it (#1775): the read stops one past the
			// bound, so its own count could never say more than one was left.
			$surplus = max( count( $members ), $this->count_sweepable() ) - self::MAX_ENDINGS;
			$members = array_slice( $members, 0, self::MAX_ENDINGS );
		}

		foreach ( $members as $member_id ) {
			$manager = \WP_Session_Tokens::get_instance( $member_id );

			if ( $member_id === $keep && '' !== $keep_token ) {
				$others = max( 0, count( $manager->get_all() ) - 1 );

				$manager->destroy_others( $keep_token );

				$ended += $others;
				++$accounts;

				continue;
			}

			$ended += count( $manager->get_all() );

			$manager->destroy_all();
			\BetterShield\Rest\Sudo::forget( $member_id );

			++$accounts;
		}

		Writer::instance()->record(
			'sessions_ended',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'session',
				'object_id'   => 'site',
				'context'     => array(
					'reason'       => $reason,
					'ended'        => $ended,
					'surplus'      => $surplus,
					'network_wide' => is_multisite(),
				),
			)
		);

		return array(
			'ended'    => $ended,
			'accounts' => $accounts,
		);
	}

	/**
	 * How many sessions a site-wide end would reach, and how many it would
	 * leave, so the screen can say so before anybody presses it.
	 *
	 * Sessions, not accounts: the sentence on the screen says sessions, and an
	 * owner signed in on four devices is four things the button ends.
	 *
	 * The counts are taken as an argument because the one caller has already
	 * read them for the total beside this number, and reading every session
	 * twice to answer the same question once is a cost paid for nothing.
	 *
	 * On a network the rule that decides this is core's, not the plugin's:
	 * `edit_user` is denied for anybody but yourself below `manage_network_users`,
	 * so a subsite's administrator reaches their own session and nothing else.
	 * That is correct — a site's administrator does not get to sign a network's
	 * accounts out — and the numbers here are what let the screen say it before
	 * the button rather than after.
	 *
	 * @param array<int, int>|null $live live_counts(), or null to read them.
	 * @return array{reaches: int, leaves: int, network_wide: bool}
	 */
	public function site_wide_reach( ?array $live = null ): array {
		$reaches = 0;
		$leaves  = 0;

		foreach ( $live ?? $this->live_counts() as $user_id => $count ) {
			if ( current_user_can( 'edit_user', (int) $user_id ) ) {
				$reaches += $count;
			} else {
				$leaves += $count;
			}
		}

		return array(
			'reaches' => $reaches,
			'leaves'  => $leaves,
			// Each session it does reach ends everywhere on a network, because
			// there is no per-site session to end.
			'network_wide' => is_multisite(),
		);
	}

	/**
	 * Whether this request is the cart or the checkout.
	 *
	 * Public so the decision can be read without staging a request. The answer
	 * itself lives in `Support\Checkout`, which is where all three mechanisms
	 * that stand down on the store path now ask — this was the copy that had
	 * never heard of the Store API, and the idle timeout is the mechanism that
	 * paid for it.
	 */
	public function is_checkout(): bool {
		return Checkout::is_store_path();
	}
}
