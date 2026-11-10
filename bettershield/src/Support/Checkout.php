<?php
/**
 * One answer to "is this request the store's cart or checkout".
 *
 * Three mechanisms have to know, and each carried its own copy: the event
 * writer, the verification sampler, and the session idle timeout. The copies
 * were not equivalent. The writer's had learned about the two checkout shapes
 * that never reach a template load — the Store API the block checkout posts
 * to, and the callback a gateway redirects back through — and the other two
 * had not. So a promise the writer kept, the idle timeout broke: a customer
 * driving the block checkout produces Store API requests and nothing else,
 * the timeout could not see them as the checkout, and it ended the session
 * underneath them.
 *
 * The answer lives here now, and the three ask it rather than keeping copies.
 *
 * **What "unclear" means is the caller's decision, not this class's.** A
 * conditional tag can in principle throw, and the safe answer depends on what
 * the asker does with it: a mechanism deciding whether to *act* is safest
 * treating an unclear request as the checkout and standing down, while the
 * writer is deciding what to *keep*, where the same answer would silently drop
 * log rows. Both are correct for their caller, so the choice is a named
 * argument instead of a difference between copies nobody could see.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Checkout {

	/**
	 * The address the classic checkout is creating an account for in this
	 * request, as the store will pass it on, or null before it says.
	 */
	private static ?string $checkout_email = null;

	public static function register(): void {
		// Last, so the address is the one the store's own filters settled on.
		add_filter( 'woocommerce_checkout_posted_data', array( self::class, 'note_checkout_email' ), PHP_INT_MAX );
	}

	/**
	 * @param mixed $data The checkout's posted data.
	 * @return mixed
	 */
	public static function note_checkout_email( $data ) {
		self::$checkout_email = is_array( $data ) && isset( $data['billing_email'] ) && is_string( $data['billing_email'] ) ? strtolower( $data['billing_email'] ) : '';

		return $data;
	}

	/**
	 * The public WooCommerce cart/checkout handlers also registered on
	 * admin-ajax. An unrelated admin action with ?wc-ajax=checkout is not one.
	 */
	public static function is_store_ajax_action( string $action ): bool {
		return self::store_present() && in_array( $action, array(
			'woocommerce_get_refreshed_fragments', 'woocommerce_apply_coupon',
			'woocommerce_remove_coupon', 'woocommerce_update_shipping_method',
			'woocommerce_get_cart_totals', 'woocommerce_update_order_review',
			'woocommerce_add_to_cart', 'woocommerce_remove_from_cart',
			'woocommerce_checkout', 'woocommerce_get_variation',
			'woocommerce_get_customer_location',
		), true );
	}

	/** Use the dispatched REST route, never an unrelated query parameter. */
	public static function is_store_rest_route( string $route ): bool {
		return self::store_present() && str_starts_with( strtolower( $route ), '/wc/store/' );
	}

	/**
	 * Whether a store is installed at all.
	 *
	 * A site without one has no checkout path, so every question below is
	 * settled before it is asked and nothing pays for the rest of this class.
	 * The conditional tags are accepted as evidence alongside the class,
	 * because a store that ships them is a store whatever it calls itself.
	 */
	public static function store_present(): bool {
		return class_exists( 'WooCommerce' ) || function_exists( 'is_checkout' ) || function_exists( 'is_cart' );
	}

	/**
	 * Whether this request carries a shopper the store itself vouches for.
	 *
	 * A store gives a customer its own cookie the moment they have a cart, so
	 * one is present for every request a real order passes through. But a
	 * cookie's name is whatever the browser says it is, and tested by name
	 * alone, anyone signed in could hold a session open forever with a header
	 * they typed. The value is what the store signs, and only the store's own
	 * session handler can validate it: it answers with the customer the cookie
	 * belongs to, or with nothing. That customer has to be the account whose
	 * session is being weighed, and a store that is not loaded on this
	 * request can vouch for nobody.
	 *
	 * This does not decide whether to stand down — that is `is_store_path()`,
	 * and it stays deliberately generous, because ending a session mid-order
	 * is the thing being avoided and a false positive there costs nothing.
	 * This decides only whether the idle clock is allowed to move: a request
	 * with no shopper behind it may be spared, and may not buy more time.
	 *
	 * @param int $user_id The account whose session is being weighed.
	 */
	public static function shopper_present( int $user_id ): bool {
		if ( $user_id <= 0 || ! function_exists( 'WC' ) ) {
			return false;
		}

		$store   = WC();
		$session = is_object( $store ) && isset( $store->session ) ? $store->session : null;

		if ( ! is_object( $session ) || ! method_exists( $session, 'get_session_cookie' ) ) {
			return false;
		}

		$cookie = $session->get_session_cookie();

		// The customer comes first in what the store hands back, and for a
		// signed-in shopper the store writes the account's own id there.
		return is_array( $cookie ) && isset( $cookie[0] ) && (string) $cookie[0] === (string) $user_id;
	}

	/**
	 * Whether this request is on the cart or checkout path.
	 *
	 * @param bool $when_unclear The answer to give if a conditional tag throws.
	 *                           True for anything deciding whether to act.
	 */
	public static function is_store_path( bool $when_unclear = true ): bool {
		// `wp` fires from `WP::main()`, which runs for front-end requests only.
		// So `did_action( 'wp' )` being 0 does not mean "too early to tell", it
		// means this is not a template load. Every shape the conditional tags
		// cannot answer for — whether or not it reaches one — is matched by
		// address below.
		if ( did_action( 'wp' ) ) {
			try {
				if ( ( function_exists( 'is_checkout' ) && is_checkout() ) || ( function_exists( 'is_cart' ) && is_cart() ) ) {
					return true;
				}
			} catch ( \Throwable $e ) {
				return $when_unclear;
			}
		}

		/*
		 * The same question the class opens with, asked the same way. This
		 * branch insisted on the literal class while `store_present()` accepts
		 * the conditional tags as evidence — so on a store that ships them
		 * under a different main class, the two disagreed: `check_idle()` saw
		 * a store and deferred here, and here there was no store, so the
		 * address was never read and the session was ended mid-order. That is
		 * the same sign-out the wc-ajax fix closed, reached by the other side.
		 */
		if ( ! self::store_present() ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a structural test; never stored, never echoed.
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';

		return self::is_store_uri( $uri );
	}

	/**
	 * Whether this request is the store's checkout itself, for the controls
	 * an anonymous flood is counted against.
	 *
	 * Stricter than `is_store_path()`, which also answers for the cart and
	 * for the checkout's parameters on any front-end address. The sign-up
	 * throttle and the honeypot stand down on the checkout because the store
	 * creates the customer's account there, and a request that merely names
	 * `wc-ajax` is one anybody can compose: added to the store's own sign-up
	 * form, it took that form out from under the throttle. The address as a
	 * whole cannot decide it either, because the store's sign-up handler runs
	 * on whatever address its fields arrive at. So this is judged by what the
	 * request is doing — the classic checkout reaching its customer step, the
	 * checkout page, or the Store API route WordPress is serving — each of
	 * which the store or WordPress sets, and a requester cannot.
	 */
	public static function is_checkout_request(): bool {
		if ( ! self::store_present() ) {
			return false;
		}

		/*
		 * The classic checkout asks for the order's customer only once its
		 * nonce and fields have passed, and creates the account straight
		 * after — on the form and over wc-ajax alike.
		 *
		 * Not the store's `WOOCOMMERCE_CHECKOUT` marker: the store defines it
		 * for any front-end post that names a checkout field while the cart
		 * holds an item, before it checks anything, so one item in a cart
		 * and one field added to every sign-up took them all out of the count.
		 */
		if ( did_filter( 'woocommerce_checkout_customer_id' ) ) {
			return true;
		}

		/*
		 * The checkout page after the main query, where the order
		 * confirmation creates an account. The store's own tag answers true
		 * whenever its marker is defined, so where the marker is, the tag
		 * says nothing the marker did not.
		 */
		if ( did_action( 'wp' ) && ! defined( 'WOOCOMMERCE_CHECKOUT' ) ) {
			try {
				if ( function_exists( 'is_checkout' ) && is_checkout() ) {
					return true;
				}
			} catch ( \Throwable $e ) {
				return true;
			}
		}

		// The Store API's checkout creates the account inside its own route,
		// which WordPress has resolved by the time that route runs. The route
		// it resolved, not the address: the sign-up handler runs before it,
		// on any address, and must not be read as the route it arrived on.
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST && isset( $GLOBALS['wp'] ) && $GLOBALS['wp'] instanceof \WP ) {
			$route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';

			return is_string( $route ) && 0 === strpos( strtolower( $route ), '/wc/store/' );
		}

		return false;
	}

	/**
	 * Whether the account a sign-up filter is asked about is the one the
	 * store's checkout is creating, which the sign-up controls do not count.
	 *
	 * Narrower than `is_checkout_request()`, which stays true for the rest of
	 * a request once the classic checkout has reached its customer step. A
	 * checkout that fails after that step, outside AJAX, lets the request go
	 * on to the store's own sign-up handler, so the step alone would excuse a
	 * second account. It excuses only the address the checkout posted. And
	 * never on core's sign-up filter, which no checkout uses: the store
	 * creates its accounts through its own.
	 */
	public static function is_checkout_account( string $email ): bool {
		if ( doing_filter( 'registration_errors' ) || ! self::is_checkout_request() ) {
			return false;
		}

		// The checkout page, or the Store API route: nothing else runs there.
		if ( ! did_filter( 'woocommerce_checkout_customer_id' ) ) {
			return true;
		}

		return null !== self::$checkout_email && '' !== self::$checkout_email && strtolower( $email ) === self::$checkout_email;
	}

	/**
	 * Whether an address is one of the checkout shapes the conditional tags
	 * cannot answer for.
	 *
	 * Not the same as never reaching a template load: one of them does reach
	 * one, and is still invisible to the tags when this is asked.
	 *
	 * Public so it can be tested without a store installed — every caller
	 * keeps the `class_exists` guard, so no site without one pays for this.
	 *
	 * **Read as structure, not as text.** A substring test was tried first and
	 * handed the decision to whoever composed the address: appending
	 * `?x=wc-api=1` to any address made this answer true, and answering true
	 * drops every non-security event that request would have recorded. An
	 * outsider must not be able to choose what this site writes down, so the
	 * parameter has to be named and the Store API path has to sit under the
	 * REST prefix rather than merely appear somewhere in the address.
	 */
	public static function is_store_uri( string $uri ): bool {
		if ( '' === $uri ) {
			return false;
		}

		$path  = strtolower( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$query = (string) wp_parse_url( $uri, PHP_URL_QUERY );

		$args = array();
		if ( '' !== $query ) {
			wp_parse_str( $query, $args );
		}

		/*
		 * A parameter is evidence only where the store could have put it. The
		 * store serves its AJAX, its gateway callbacks and its REST from the
		 * front end, never from one of core's own entry scripts, so on
		 * `wp-login.php`, `xmlrpc.php` or anything under `wp-admin` the same
		 * parameter is one the requester appended — and answering true there
		 * stood the sign-up throttle and the honeypot down for any anonymous
		 * request that added `wc-ajax` to the sign-up address.
		 */
		if ( 1 === preg_match( '#/(?!index\.php$)[^/]+\.php$#', $path ) ) {
			$args = array();
		}

		// The Store API reached through `rest_route`, which is how a site
		// without pretty permalinks addresses REST at all.
		$route = isset( $args['rest_route'] ) && is_string( $args['rest_route'] )
			? strtolower( $args['rest_route'] )
			: '';

		$prefix = strtolower( trim( rest_get_url_prefix(), '/' ) );

		/*
		 * Nor on a REST address, by either spelling. The store answers its
		 * AJAX and its gateway callbacks on a page load, and REST is served
		 * before one, so on `/wp-json/…` or beside `rest_route` those markers
		 * are ones the requester added — and answering true there stood the
		 * breached-password check down for a signed-in account's password
		 * change on core's users route, and thinned that request's activity
		 * rows. The Store API is still recognized, below, by its route.
		 */
		$rest = array_key_exists( 'rest_route', $args )
			|| ( '' !== $prefix && false !== strpos( $path . '/', '/' . $prefix . '/' ) );

		if ( ! $rest ) {
			// A gateway that redirects off-site names this parameter. A
			// request that merely carries the characters inside some other
			// value has not.
			if ( array_key_exists( 'wc-api', $args ) ) {
				return true;
			}

			// The shortcode checkout — the one every store had before the
			// block checkout, and many still run — submits the order over this
			// parameter and refreshes the order review over it on every field
			// the customer edits. It reaches neither shape above: the address
			// is the site's own front page with a parameter on it, so the main
			// query resolves to the front page, the conditional tags answer
			// false, and this parameter is the only evidence the request
			// carries. Named, for the reason above.
			if ( array_key_exists( 'wc-ajax', $args ) ) {
				return true;
			}

			// The gateway callback is reachable as a path as well, which the
			// substring test never matched because it looked for the `=`. The
			// second is defensive rather than observed: a stock store
			// registers no rewrite for it, and it is a host, a CDN, or a
			// filtered endpoint that produces one. Both are safe to read as
			// path segments, because reaching one means requesting a different
			// resource rather than appending to the one you were already
			// asking for.
			if ( false !== strpos( $path, '/wc-api/' ) || false !== strpos( $path, '/wc-ajax/' ) ) {
				return true;
			}
		}

		if ( 0 === strpos( $route, '/wc/store/' ) ) {
			return true;
		}

		// The pretty path, anchored to the REST prefix so an ordinary page
		// published at `/wc/store/…` is not mistaken for the Store API.
		// Contained rather than leading, because a subdirectory install
		// carries its folder in front.
		return '' !== $prefix && false !== strpos( $path, '/' . $prefix . '/wc/store/' );
	}
}
