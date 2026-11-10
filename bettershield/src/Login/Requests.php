<?php
/**
 * The three forms that are not the sign-in form.
 *
 * A comment box, a lost-password form and a sign-up form. Until now this
 * plugin counted nothing on any of them, so a script could work through them
 * all day at whatever rate it liked and the only trace was in somebody else's
 * access log.
 *
 * **The person on the other side of these forms is not the site's owner.**
 * That one fact sets every rule below. A sign-in lockout falls on somebody
 * looking at a dashboard, who is told what happened and how long it lasts. A
 * refusal here can fall on a reader with no account, no way to ask and no idea
 * this plugin exists — so the thresholds are generous, the message says plainly
 * what to do, and the comment surface does not refuse at all:
 *
 * - **A comment over the threshold is held for moderation, never dropped.** A
 *   false positive somebody can still find and approve costs a delay. One that
 *   vanished costs a reader their words and tells the owner nothing.
 * - **A reset throttle refuses the source and never the account.** An attacker
 *   who could freeze an account's own way back in would have defeated the
 *   recovery promise from outside it, using a form that exists to keep that
 *   promise.
 * - **A reset refusal is the same answer a successful request gets**, for the
 *   same reason the lost-password form already hides whether an account
 *   exists: a throttle that announced itself would be the enumeration oracle
 *   that hiding was for.
 *
 * Everything shared with the sign-in gate — the confidence rule, the
 * allowlist, safe mode, counting that cannot cross between forms — lives in
 * `Gate` and is not restated here.
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

final class Requests {

	private static ?Requests $instance = null;

	/** Whether the comment being processed right now arrived over the line. */
	private bool $held = false;

	/** Whether the record of that has already been written for this comment. */
	private bool $recorded = false;

	public static function instance(): Requests {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Priority 20: after the honeypot at 5, which refuses outright and
		// whose refusals are not ours to count — a bot caught by an invisible
		// field never reached a threshold, it failed a different test.
		add_filter( 'preprocess_comment', array( $this, 'note_comment' ), 20, 1 );
		add_filter( 'pre_comment_approved', array( $this, 'hold_comment' ), 20, 2 );

		// A comment core refuses before it is created never reaches the two
		// filters above, so a script posting to closed or made-up posts was
		// never counted. Each refusal counts once toward the same limit.
		foreach ( array( 'comment_id_not_found', 'comment_closed', 'comment_on_trash', 'comment_on_draft', 'comment_on_password_protected' ) as $refused ) {
			add_action( $refused, array( $this, 'note_refused_comment' ), 20, 0 );
		}

		add_action( 'lostpassword_post', array( $this, 'guard_reset' ), 10, 1 );
		add_filter( 'registration_errors', array( $this, 'guard_registration' ), 20, 3 );
		// A store's own sign-up form never runs core's filter — the same gap
		// the honeypot had to learn about, and the same fix.
		add_filter( 'woocommerce_registration_errors', array( $this, 'guard_registration' ), 20, 3 );
	}

	/**
	 * Whether a surface is armed, which is three questions rather than one.
	 */
	private function armed( string $surface ): bool {
		$settings = Protection::instance()->settings();

		if ( ! $settings['enabled'] || SafeMode::is_active() ) {
			return false;
		}

		// New files can be running before the migration that separates
		// surfaces has landed. Until it has, these forms wait: a count that
		// cannot be kept apart from the sign-in gate's is worse than no count.
		if ( ! Gate::surfaced() ) {
			return false;
		}

		return (bool) Protection::instance()->surface_policy( $surface )['enabled'];
	}

	/** @return array{ip: string, method: string, confident: bool, paired_with: ?string} */
	private function source(): array {
		$settings = Protection::instance()->settings();

		return ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );
	}

	/* ---- comments ----------------------------------------------------------- */

	/**
	 * Count a comment, and remember whether this one crossed the line.
	 *
	 * Counted at the point the comment arrives rather than at the point it is
	 * approved, because the thing being measured is the rate of arrival. The
	 * decision is applied on `pre_comment_approved`, which is where WordPress
	 * asks what should happen to it.
	 *
	 * @param array<string, mixed> $data
	 * @return array<string, mixed>
	 */
	public function note_comment( $data ) {
		/*
		 * Cleared first, on every path out of here. The verdict belongs to the
		 * comment being processed right now, and an early return that left the
		 * previous one standing would apply it to this comment — so a
		 * moderator's reply, arriving after a flood, would be held on a
		 * judgment that was never about them.
		 */
		$this->held     = false;
		$this->recorded = false;

		if ( ! is_array( $data ) || ! $this->armed( Surfaces::COMMENT ) ) {
			return $data;
		}

		/*
		 * Somebody who can moderate is not a flood, whatever the rate. They
		 * are also the one person whose comments going to the queue would be
		 * invisible to them, since the queue is the thing they are looking at.
		 */
		if ( current_user_can( 'moderate_comments' ) ) {
			return $data;
		}

		$source = $this->source();
		$policy = Protection::instance()->surface_policy( Surfaces::COMMENT );

		$this->held = Gate::closed( Surfaces::COMMENT, $source )
			|| null !== Gate::note_failure( Surfaces::COMMENT, $source, $policy );

		return $data;
	}

	/**
	 * Count a comment core refused before creating it: to a post that is
	 * missing, closed, trashed, a draft, or behind a password.
	 *
	 * Counted as a comment is, with the same exemptions, so a source posting
	 * at posts that take no comments moves toward the limit; once the limit
	 * closes, its next real comment waits for moderation. There is nothing
	 * to hold here, since no comment was made, and this leaves the verdict
	 * for the comment being processed, if any, alone.
	 */
	public function note_refused_comment(): void {
		if ( ! $this->armed( Surfaces::COMMENT ) || current_user_can( 'moderate_comments' ) ) {
			return;
		}

		Gate::note_failure( Surfaces::COMMENT, $this->source(), Protection::instance()->surface_policy( Surfaces::COMMENT ) );
	}

	/**
	 * Hold it, rather than refuse it.
	 *
	 * Returning `0` is what core itself does for a comment awaiting
	 * moderation, so the commenter sees the message a site already shows for
	 * that — "your comment is awaiting moderation" — and the owner finds it in
	 * the queue they already read. Nothing new has to be explained to either
	 * of them, and nothing is lost if the threshold was wrong.
	 *
	 * A comment already marked as spam by something else keeps that verdict:
	 * this decides between "published" and "wait", not between anything and
	 * spam.
	 *
	 * **This filter runs more than once for one comment.** Core asks the
	 * question again after asking it, and an answer that held the comment the
	 * first time and let it through the second is the answer that gets stored
	 * — so the verdict is not consumed here. It is set once, when the comment
	 * arrives, and every reader of it in the same request gets the same answer
	 * about the same comment. Only the log entry is one-shot, because a
	 * doubled question is not a doubled event.
	 *
	 * @param string|int $approved
	 * @param array<string, mixed> $data
	 * @return string|int
	 */
	public function hold_comment( $approved, $data = array() ) {
		if ( ! $this->held || 'spam' === $approved || 'trash' === $approved ) {
			return $approved;
		}

		if ( 0 === $approved || '0' === $approved ) {
			return $approved;
		}

		if ( ! $this->recorded ) {
			$this->recorded = true;

			Writer::instance()->record(
				'comment_held',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'comment',
					'context'     => array( 'surface' => Surfaces::COMMENT ),
				)
			);
		}

		return 0;
	}

	/* ---- password resets ---------------------------------------------------- */

	/**
	 * Throttle the source of reset requests, and say nothing about it.
	 *
	 * The refusal is the same redirect a *successful* request gets, which is
	 * the one already used to stop this form answering "does this account
	 * exist". A throttle with a message of its own would restore that answer
	 * one attempt at a time, and would do it on the form whose whole job is to
	 * let somebody back in.
	 *
	 * Never touches the account. An attacker who could freeze an account's own
	 * reset would have taken the owner's way back in using the feature meant
	 * to protect it.
	 *
	 * @param mixed $errors
	 */
	public function guard_reset( $errors = null ): void {
		if ( ! $this->armed( Surfaces::RESET ) ) {
			return;
		}

		$source = $this->source();
		$policy = Protection::instance()->surface_policy( Surfaces::RESET );

		$closed = Gate::closed( Surfaces::RESET, $source );
		$now    = null !== Gate::note_failure( Surfaces::RESET, $source, $policy );

		if ( ! $closed && ! $now ) {
			return;
		}

		Writer::instance()->record(
			'password_reset_throttled',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'lockout',
				'context'     => array( 'surface' => Surfaces::RESET, 'method' => $source['method'] ),
			)
		);

		wp_safe_redirect( self::reset_answer() );
		exit;
	}

	/**
	 * Where a successful reset request from the same form would have gone.
	 */
	private static function reset_answer(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- read only to mirror the success path; wp_safe_redirect refuses anything off this site.
		$requested = isset( $_REQUEST['redirect_to'] ) ? (string) wp_unslash( $_REQUEST['redirect_to'] ) : '';

		if ( '' !== $requested ) {
			return $requested;
		}

		/*
		 * The store's My Account form fires the same action and sends no
		 * redirect_to; its own success stays on My Account. Sent to the core
		 * sign-in screen instead, a throttled customer left the store's theme
		 * while one who was not stayed in it: two answers, which this one
		 * exists not to give.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read only to tell which form asked; the store verifies its own nonce.
		if ( isset( $_POST['wc_reset_password'] ) && function_exists( 'wc_get_account_endpoint_url' ) ) {
			return add_query_arg( 'reset-link-sent', 'true', (string) wc_get_account_endpoint_url( 'lost-password' ) );
		}

		/*
		 * Built absolutely, from the helper core's own wp_lostpassword_url()
		 * uses. A relative Location resolves against the directory of the
		 * request, and this fires from whatever handler called the action —
		 * so the bare literal is the confirmation page only when the caller
		 * happens to sit at the site root, and a 404 anywhere else.
		 */
		return add_query_arg( 'checkemail', 'confirm', network_site_url( 'wp-login.php', 'login' ) );
	}

	/* ---- registration -------------------------------------------------------- */

	/**
	 * Refuse a sign-up over the threshold, and say so.
	 *
	 * Unlike the other two this one speaks plainly. There is nothing to hide —
	 * a registration form announces that registration exists — and the person
	 * refused is somebody who wanted an account and needs to know they can try
	 * again rather than that the site is broken.
	 *
	 * @param mixed  $errors
	 * @param string $username Unused; the filters pass it before the address.
	 * @param string $email    The address the account is being created for.
	 * @return mixed
	 */
	public function guard_registration( $errors = null, $username = '', $email = '' ) {
		if ( ! $this->armed( Surfaces::REGISTER ) ) {
			return $errors;
		}

		// Refused already by the bot check, which runs first on the same two
		// filters: its refusals are not ours to count, as on the comment side.
		// Counted, a bot caught by the hidden field closed the form for its
		// address and every person behind it.
		if ( $errors instanceof \WP_Error && in_array( 'bettershield_honeypot', $errors->get_error_codes(), true ) ) {
			return $errors;
		}

		/*
		 * Never on the store's checkout. WooCommerce applies this same filter
		 * inside wc_create_new_customer(), which is where classic checkout,
		 * order-confirmation account creation and the sign-up form all create
		 * an account — so a shop taking more than the threshold of first-time
		 * orders in an hour had the throttle refuse the account, and with it
		 * the order, for shoppers sharing one address behind a school, an
		 * office or carrier-grade NAT. The rule is older than this gate:
		 * nothing at all runs on the checkout path.
		 *
		 * Judged by what the request is doing rather than by its address: a
		 * `wc-ajax` parameter is one any anonymous request can append, and
		 * read as the checkout it took every sign-up out of the count. And
		 * only the account the checkout itself is creating, never one made
		 * beside it in the same request.
		 */
		if ( Checkout::is_checkout_account( (string) $email ) ) {
			return $errors;
		}

		/*
		 * Nor on an account somebody with the standing to create accounts is
		 * creating. This surface counts anonymous sign-ups, and the same
		 * WooCommerce filter fires inside `wc_create_new_customer()` whichever
		 * way the account arrives — including `POST wc/v3/customers`, which is
		 * an authenticated, capability-gated write and not a flood. A headless
		 * storefront, a mobile app, a CRM sync, a POS or a store import runs
		 * from one server address, so the ninth customer in an hour was
		 * refused with "too many sign-ups from your connection" and the REST
		 * call failed on it.
		 *
		 * The comment surface next door draws the same line for the same
		 * reason: somebody who can moderate is not a flood, whatever the rate.
		 */
		if ( current_user_can( 'create_users' ) || current_user_can( 'list_users' ) ) {
			return $errors;
		}

		$source = $this->source();
		$policy = Protection::instance()->surface_policy( Surfaces::REGISTER );

		$closed = Gate::closed( Surfaces::REGISTER, $source );
		$now    = null !== Gate::note_failure( Surfaces::REGISTER, $source, $policy );

		if ( ! $closed && ! $now ) {
			return $errors;
		}

		Writer::instance()->record(
			'registration_refused',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'lockout',
				'context'     => array( 'surface' => Surfaces::REGISTER, 'method' => $source['method'] ),
			)
		);

		if ( ! is_wp_error( $errors ) ) {
			$errors = new \WP_Error();
		}

		$errors->add(
			'bettershield_registration_throttled',
			__( '<strong>Error:</strong> Too many sign-ups from your connection. Try again a little later.', 'bettershield' )
		);

		return $errors;
	}
}
