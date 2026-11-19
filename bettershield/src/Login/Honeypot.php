<?php
/**
 * Honeypot bot protection: an invisible field and a clock, no puzzle.
 *
 * Two observations about unsophisticated automation, each turned into a
 * check. Bots fill in every field they find, so a field a person never sees
 * comes back non-empty exactly when a script filled it. And bots submit
 * instantly, so a form that comes back within two seconds of being rendered
 * was not filled in by hands. People see nothing, solve nothing, and prove
 * nothing — which is the point: a visual challenge would need an outside
 * service, and this plugin makes no external calls.
 *
 * Forms this plugin did not render are exempt by architecture: the check
 * only runs when its own fields are present in the submission, so a custom
 * login form, an app password or an XML-RPC client is never rejected for
 * lacking a field nobody gave it.
 *
 * The forms this plugin always draws the fields into are the exceptions.
 * Once this site's comment form has been drawn with the fields, a guest
 * comment sent to wp-comments-post.php without them had them taken out, so it
 * goes to Spam: not refused, since a page cached before the switch was on has
 * no fields and a person on it would lose what they wrote. The same holds for
 * a guest submission to a contact form once that plugin's form has been drawn
 * with them, which is marked spam in that plugin's own way, and for a
 * signed-out lost-password request from the sign-in page's own form or the
 * store's, which is refused like a caught one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Checkout;
use BetterShield\Support\ClientIp;
use BetterShield\Support\LoginForms;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Honeypot {

	/**
	 * The trap field. A name autofill has no interest in: browsers and
	 * password managers fill fields they recognize, and rejecting a person
	 * because their browser helpfully filled "website" would be a false
	 * positive of our own construction.
	 */
	private const FIELD = 'bettershield_hp_check';

	/**
	 * The clock field, carrying "timestamp.signature".
	 */
	private const STAMP = 'bettershield_hp_time';

	/**
	 * Faster than this, in seconds, is not typing.
	 */
	private const MIN_SECONDS = 2;

	/**
	 * Set once this site's comment form has been drawn with the fields, so a
	 * guest comment without them is known to have had them taken out.
	 */
	public const COMMENT_FIELDS_SEEN = 'bettershield_hp_comment_form';

	/**
	 * Contact-form plugin => when this site first drew its form with the
	 * fields, so a guest submission to it without them is known to have had
	 * them taken out.
	 */
	public const FORM_FIELDS_SEEN = 'bettershield_hp_forms_seen';

	/** Whether the last check caught only the clock: sent too soon, nothing else wrong. */
	private bool $too_fast = false;

	private static ?Honeypot $instance = null;

	public static function instance(): Honeypot {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Every sign-in and registration form this plugin can reach, not only
		// the two WordPress renders itself. A store that has moved its
		// customers to My Account — the WooCommerce default — fires its own
		// hooks, and while only core's were listed the trap was never on the
		// form the site's actual customers use.
		foreach ( array_merge( LoginForms::sign_in_hooks(), LoginForms::registration_hooks() ) as $hook ) {
			add_action( $hook, array( $this, 'render' ) );
		}

		add_action( 'comment_form', array( $this, 'render_comment' ) );

		// The lost-password forms too: a script could otherwise make the site
		// mail reset links to real accounts until the reset limit tripped.
		foreach ( LoginForms::reset_hooks() as $hook ) {
			add_action( $hook, array( $this, 'render' ) );
		}

		// Contact forms, through each plugin's own hooks. Nothing is added
		// while the plugin is not there: its hooks never fire.
		add_filter( 'wpcf7_form_elements', array( $this, 'render_cf7' ) );
		add_filter( 'wpcf7_spam', array( $this, 'check_cf7' ), 10, 2 );
		add_filter( 'wpcf7_posted_data', array( $this, 'without_fields' ) );
		add_action( 'wpforms_display_submit_before', array( $this, 'render_wpforms' ) );
		add_filter( 'wpforms_process_honeypot', array( $this, 'check_wpforms' ), 10, 4 );
		add_action( 'fluentform/form_element_start', array( $this, 'render_fluentform' ) );
		add_filter( 'fluentform/validation_errors', array( $this, 'check_fluentform' ), 10, 2 );
		add_filter( 'fluentform/insert_response_data', array( $this, 'without_fields' ) );

		// Priority 25: after core has resolved credentials (20), before
		// anything acts on the signed-in user. A wrong password fails on its
		// own; this only turns a would-be success by a bot into a refusal.
		add_filter( 'authenticate', array( $this, 'check_login' ), 25, 1 );
		add_filter( 'registration_errors', array( $this, 'check_registration' ), 10, 3 );
		// WooCommerce's own sign-up form does not run core's registration
		// filter, and the field is drawn on it — so on a store the trap was
		// laid and never looked at. Same callback: the filter passes a
		// WP_Error first, as core's does.
		add_filter( 'woocommerce_registration_errors', array( $this, 'check_registration' ), 10, 3 );
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ), 5, 1 );
		// Priority 30: after the comment limit's own hold at 20, so a comment
		// without the fields goes to Spam whatever that one decided.
		add_filter( 'pre_comment_approved', array( $this, 'spam_without_fields' ), 30, 2 );
		// Priority 5: before the reset limit at 10, so a caught bot is not
		// counted toward it.
		add_action( 'lostpassword_post', array( $this, 'check_reset' ), 5, 1 );
	}

	private function enabled(): bool {
		return Protection::instance()->settings()['honeypot'] && ! SafeMode::is_active();
	}

	/**
	 * Whether this request is the store's own checkout, where the trap is
	 * not read. A field that was never rendered must not be judged: on the
	 * checkout the account creation carries no trap, so an absent one is the
	 * ordinary state rather than evidence of anything.
	 *
	 * Judged by what the request is doing, not by a `wc-ajax` parameter on
	 * its address: that one anybody can append to a sign-in or sign-up that
	 * did carry the trap, and a filled trap was then never read.
	 */
	private function on_store_path(): bool {
		return Checkout::is_checkout_request();
	}

	/* ---- render ------------------------------------------------------------- */

	public function render(): void {
		echo $this->fields(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts in fields().
	}

	/** The comment form's fields, noting once that this site's form carries them. */
	public function render_comment(): void {
		$fields = $this->fields();

		if ( '' !== $fields && ! get_option( self::COMMENT_FIELDS_SEEN ) ) {
			update_option( self::COMMENT_FIELDS_SEEN, time(), true );
		}

		echo $fields; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts in fields().
	}

	/**
	 * Contact Form 7's form, with the fields inside it: its hidden-fields
	 * filter takes only hidden inputs, so it could not carry the trap.
	 *
	 * @param mixed $elements The form's markup.
	 * @return mixed
	 */
	public function render_cf7( $elements ) {
		return is_string( $elements ) ? $elements . $this->form_fields( 'cf7' ) : $elements;
	}

	/** WPForms' form, with the fields before its submit button. */
	public function render_wpforms(): void {
		echo $this->form_fields( 'wpforms' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts in fields().
	}

	/** Fluent Forms' form, with the fields at its start. */
	public function render_fluentform(): void {
		echo $this->form_fields( 'fluentform' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts in fields().
	}

	/** A contact form's fields, noting once that this site's form of that kind carries them. */
	private function form_fields( string $surface ): string {
		$fields = $this->fields();

		if ( '' !== $fields ) {
			$seen = get_option( self::FORM_FIELDS_SEEN, array() );
			$seen = is_array( $seen ) ? $seen : array();

			if ( ! isset( $seen[ $surface ] ) ) {
				$seen[ $surface ] = time();
				update_option( self::FORM_FIELDS_SEEN, $seen, false );
			}
		}

		return $fields;
	}

	/** The two fields' markup, or '' where none is drawn. */
	private function fields(): string {
		if ( ! $this->enabled() ) {
			return '';
		}

		/*
		 * Nothing is added to the cart or the checkout. WooCommerce fires its
		 * sign-in form hook inside the checkout page when the store lets
		 * customers log in there, so the trap was being drawn into a page the
		 * readme promises is left alone — and into a page a full-page cache
		 * hands to every shopper.
		 */
		if ( Checkout::is_store_path() ) {
			return '';
		}

		$time = (string) time();

		// aria-hidden plus tabindex -1 plus a box clipped to nothing: invisible
		// to people, absent from tab order and screen readers, present in the
		// DOM for anything that parses fields mechanically. Clipped where it
		// stands rather than pushed off the page, because an offset to the left
		// is where a right-to-left page scrolls to.
		return sprintf(
			'<div style="position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0,0,0,0);clip-path:inset(50%%);white-space:nowrap;" aria-hidden="true"><label>%1$s<input type="text" name="%2$s" value="" tabindex="-1" autocomplete="off"></label></div><input type="hidden" name="%3$s" value="%4$s">',
			esc_html__( 'Leave this field empty', 'bettershield' ),
			esc_attr( self::FIELD ),
			esc_attr( self::STAMP ),
			esc_attr( $time . '.' . $this->sign( $time ) )
		);
	}

	/* ---- checks -------------------------------------------------------------- */

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function check_login( $user ) {
		if ( ! $user instanceof \WP_User || ! $this->submitted() || ! $this->enabled() || $this->on_store_path() ) {
			return $user;
		}

		if ( $this->caught() ) {
			$this->record( 'login' );

			/*
			 * Right credentials, sent sooner than a person types: a password
			 * manager that fills and submits as the page loads, or a quick
			 * hand. Told to wait rather than left with no reason. Anything
			 * else caught keeps the plain answer.
			 */
			return new \WP_Error(
				'bettershield_honeypot',
				$this->too_fast
					? __( 'That was sent too soon after the page opened. Wait a second, then sign in again.', 'bettershield' )
					: __( 'That did not go through. Please try signing in again.', 'bettershield' )
			);
		}

		return $user;
	}

	/**
	 * @param string $username Unused; the filters pass it before the address.
	 * @param string $email    The address the account is being created for.
	 */
	public function check_registration( \WP_Error $errors, $username = '', $email = '' ): \WP_Error {
		// The checkout's own account only, as the sign-up throttle reads it.
		if ( $this->submitted() && $this->enabled() && ! Checkout::is_checkout_account( (string) $email ) && $this->caught() ) {
			$this->record( 'registration' );
			$errors->add( 'bettershield_honeypot', __( 'That did not go through. Please try again.', 'bettershield' ) );
		}

		return $errors;
	}

	/**
	 * @param array<string, mixed> $comment
	 * @return array<string, mixed>
	 */
	public function check_comment( $comment ) {
		if ( is_user_logged_in() || ! $this->submitted() || ! $this->enabled() || ! $this->caught() ) {
			return $comment;
		}

		$this->record( 'comment' );

		wp_die(
			esc_html__( 'That did not go through. Go back and try again.', 'bettershield' ),
			esc_html__( 'Comment not posted', 'bettershield' ),
			array(
				'response'  => 400,
				'back_link' => true,
			)
		);
	}

	/**
	 * A guest comment sent to wp-comments-post.php without either field, on
	 * a site whose comment form carries them, goes to Spam. Spam rather than
	 * refused: a page cached before the switch was on has no fields, and in
	 * Spam a real comment waits for Not Spam, with no moderation email per
	 * bot as Pending would send.
	 *
	 * Signed-in commenters, REST and XML-RPC comments, and a site whose theme
	 * never draws the comment form's hook are left as they are.
	 *
	 * @param int|string|\WP_Error $approved
	 * @param array<string, mixed> $comment
	 * @return int|string|\WP_Error
	 */
	public function spam_without_fields( $approved, $comment = array() ) {
		if ( is_wp_error( $approved ) || 'trash' === $approved || 'spam' === $approved || is_user_logged_in() || $this->submitted() || ! $this->enabled() ) {
			return $approved;
		}

		// Only a submission through the comment form's own handler: REST and
		// XML-RPC create comments without running it.
		if ( ! did_action( 'pre_comment_on_post' ) || ! get_option( self::COMMENT_FIELDS_SEEN ) ) {
			return $approved;
		}

		/*
		 * A comment form drawn somewhere this plugin cannot reach, such as one
		 * served in a frame from another service, posts without the fields
		 * through no fault of its own.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence check only.
		$framed = isset( $_POST['hc_post_as'] );

		/**
		 * Filters whether a guest comment that arrived without the bot check's
		 * fields owes them.
		 *
		 * @param bool                 $owes    Whether it goes to Spam.
		 * @param array<string, mixed> $comment The comment.
		 */
		if ( ! (bool) apply_filters( 'bettershield_honeypot_comment_owes_fields', ! $framed, is_array( $comment ) ? $comment : array() ) ) {
			return $approved;
		}

		$this->record( 'comment' );

		return 'spam';
	}

	/**
	 * A lost-password request with the fields, caught: no reset email, an
	 * error on the form, and the same answer whether the account exists.
	 *
	 * Without them, a signed-out request from the sign-in page's own form or
	 * the store's is caught too: both always carry the fields, so they were
	 * taken out. Anything else without them is not judged: Send Reset Link on
	 * a profile or the Users screen fires the same action for a signed-in
	 * administrator, and another plugin's reset form never had them.
	 *
	 * @param mixed $errors
	 */
	public function check_reset( $errors = null ): void {
		if ( ! $errors instanceof \WP_Error || ! $this->enabled() ) {
			return;
		}

		if ( $this->submitted() ? ! $this->caught() : ! $this->reset_owes_fields() ) {
			return;
		}

		$this->record( 'reset' );

		// Core's "no such account" beside it would tell the two apart.
		$errors->remove( 'invalid_email' );
		$errors->add(
			'bettershield_honeypot',
			$this->too_fast
				? __( 'That was sent too soon after the page opened. Wait a second, then try again.', 'bettershield' )
				: __( 'That did not go through. Please try again.', 'bettershield' )
		);
	}

	/**
	 * Contact Form 7: a caught submission is spam, so it shows its own spam
	 * message and sends no mail.
	 *
	 * @param mixed $spam
	 * @param mixed $submission
	 * @return mixed
	 */
	public function check_cf7( $spam, $submission = null ) {
		if ( $spam || ! $this->enabled() ) {
			return $spam;
		}

		$missing = ! $this->submitted();

		if ( $missing ? ! $this->form_owes_fields( 'cf7' ) : ! $this->caught() ) {
			return $spam;
		}

		$this->record( 'cf7' );

		if ( is_object( $submission ) && method_exists( $submission, 'add_spam_log' ) ) {
			$submission->add_spam_log(
				array(
					'agent'  => 'bettershield',
					'reason' => $this->spam_reason( $missing ),
				)
			);
		}

		return true;
	}

	/**
	 * WPForms: a reason marks the submission as spam, which WPForms logs and
	 * answers without an email, as with its own honeypot.
	 *
	 * @param mixed $honeypot A reason already given, or empty.
	 * @return mixed
	 */
	public function check_wpforms( $honeypot ) {
		if ( ! empty( $honeypot ) || ! $this->enabled() ) {
			return $honeypot;
		}

		$missing = ! $this->submitted();

		if ( $missing ? ! $this->form_owes_fields( 'wpforms' ) : ! $this->caught() ) {
			return $honeypot;
		}

		$this->record( 'wpforms' );

		return $this->spam_reason( $missing );
	}

	/**
	 * Fluent Forms: its fields come serialized in the request. The data it
	 * hands over keeps only the form's own fields, so the two are read from
	 * that serialized form as well.
	 *
	 * @param mixed $errors
	 * @param mixed $data The submitted form data.
	 * @return mixed
	 */
	public function check_fluentform( $errors, $data = array() ) {
		$data = array_merge( is_array( $data ) ? $data : array(), $this->fluentform_fields() );

		if ( ! is_array( $errors ) || ! $this->enabled() ) {
			return $errors;
		}

		if ( $this->submitted( $data ) ? ! $this->caught( $data ) : ! $this->form_owes_fields( 'fluentform' ) ) {
			return $errors;
		}

		$this->record( 'fluentform' );
		$errors['bettershield_hp'] = array(
			$this->too_fast
				? __( 'That was sent too soon after the page opened. Wait a second, then try again.', 'bettershield' )
				: __( 'That did not go through. Please try again.', 'bettershield' ),
		);

		return $errors;
	}

	/**
	 * The two fields from the serialized form Fluent Forms posts as `data`.
	 *
	 * @return array<string, mixed>
	 */
	private function fluentform_fields(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Fluent Forms verifies its own nonce; only this plugin's two fields are kept, and caught() sanitizes them.
		$raw = isset( $_POST['data'] ) && is_string( $_POST['data'] ) ? wp_unslash( $_POST['data'] ) : '';

		if ( '' === $raw ) {
			return array();
		}

		parse_str( $raw, $parsed );

		return array_intersect_key( $parsed, array( self::FIELD => true, self::STAMP => true ) );
	}

	/**
	 * A form plugin's submitted data without the two fields, so they are not
	 * mailed or stored with an entry.
	 *
	 * @param mixed $data
	 * @return mixed
	 */
	public function without_fields( $data ) {
		if ( is_array( $data ) ) {
			unset( $data[ self::FIELD ], $data[ self::STAMP ] );
		}

		return $data;
	}

	/* ---- internals ------------------------------------------------------------- */

	/**
	 * Whether a lost-password request without the fields had them taken out:
	 * signed out, and sent from a form this plugin always draws them into,
	 * the sign-in page's own or the store's My Account one.
	 */
	private function reset_owes_fields(): bool {
		$this->too_fast = false;

		if ( is_user_logged_in() ) {
			return false;
		}

		// phpcs:disable WordPress.Security.NonceVerification -- presence checks only; core and the store verify their own forms.
		$core  = LoginForms::is_core_sign_in_request() && in_array( isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '', array( 'lostpassword', 'retrievepassword' ), true );
		$store = isset( $_POST['wc_reset_password'] ) && in_array( 'woocommerce_lostpassword_form', LoginForms::reset_hooks(), true );
		// phpcs:enable

		if ( ! $core && ! $store ) {
			return false;
		}

		/**
		 * Filters whether a signed-out lost-password request that arrived
		 * without the bot check's fields owes them.
		 *
		 * @param bool   $owes Whether it is refused like a caught one.
		 * @param string $form 'core' for the sign-in page, 'store' for My Account.
		 */
		return (bool) apply_filters( 'bettershield_honeypot_reset_owes_fields', true, $core ? 'core' : 'store' );
	}

	/**
	 * Whether a contact-form submission without the fields had them taken
	 * out: from a guest, to a plugin whose form this site has drawn with them.
	 * A signed-in person is left alone, as on the comment form.
	 */
	private function form_owes_fields( string $surface ): bool {
		$this->too_fast = false;

		if ( is_user_logged_in() ) {
			return false;
		}

		$seen = get_option( self::FORM_FIELDS_SEEN, array() );

		if ( ! is_array( $seen ) || ! isset( $seen[ $surface ] ) ) {
			return false;
		}

		/**
		 * Filters whether a guest contact-form submission that arrived without
		 * the bot check's fields owes them, for a form drawn somewhere this
		 * plugin can't reach.
		 *
		 * @param bool   $owes    Whether it is marked spam.
		 * @param string $surface 'cf7', 'wpforms' or 'fluentform'.
		 */
		return (bool) apply_filters( 'bettershield_honeypot_form_owes_fields', true, $surface );
	}

	/** Why a contact-form submission was marked spam, in its plugin's log. */
	private function spam_reason( bool $missing ): string {
		return $missing
			? __( 'Bot check: the hidden fields were left out.', 'bettershield' )
			: __( 'Bot check: hidden field filled, or sent too fast.', 'bettershield' );
	}

	/**
	 * Whether this submission carries our fields at all — the architecture
	 * exemption for forms we never rendered. Either one: a filled trap sent
	 * without the clock is still read.
	 *
	 * @param array<string, mixed>|null $data The submitted data; the request's own when null.
	 */
	private function submitted( ?array $data = null ): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- presence check only; each consuming flow verifies its own credentials.
		$data = $data ?? $_POST;

		return isset( $data[ self::STAMP ] ) || isset( $data[ self::FIELD ] );
	}

	/**
	 * @param array<string, mixed>|null $data The submitted data; the request's own when null.
	 */
	private function caught( ?array $data = null ): bool {
		$this->too_fast = false;

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- these fields are this plugin's own bot check; the surrounding flow (login, registration, comment) carries its own verification.
		$from  = null === $data;
		$data  = $data ?? $_POST;
		$trap  = isset( $data[ self::FIELD ] ) && is_scalar( $data[ self::FIELD ] ) ? (string) ( $from ? wp_unslash( $data[ self::FIELD ] ) : $data[ self::FIELD ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared to empty, never stored.
		$stamp = isset( $data[ self::STAMP ] ) && is_scalar( $data[ self::STAMP ] ) ? sanitize_text_field( (string) ( $from ? wp_unslash( $data[ self::STAMP ] ) : $data[ self::STAMP ] ) ) : '';
		// phpcs:enable

		if ( '' !== $trap ) {
			return true;
		}

		$parts = explode( '.', $stamp, 2 );

		if ( 2 !== count( $parts ) || ! hash_equals( $this->sign( $parts[0] ), $parts[1] ) ) {
			// A forged or mangled clock is its own answer.
			return true;
		}

		$age = time() - (int) $parts[0];

		// Too fast is a script. Old is fine: a cached page renders an old
		// clock, and a person who left the tab open for an hour is still a
		// person. Negative is a forged clock from the future.
		$this->too_fast = $age >= 0 && $age < self::MIN_SECONDS;

		return $age < self::MIN_SECONDS;
	}

	/**
	 * Signed with a key this plugin owns rather than with `wp_salt()`.
	 *
	 * The `auth_keys` hardening item rotates the salts — that is what it is
	 * for — and every stamp already rendered into a page then failed to
	 * verify, so the submission was refused as a bot. That undid the age
	 * tolerance deliberately built two methods up, at exactly the moment it
	 * was most needed: a cached page keeps serving stale forms for the length
	 * of its TTL, and an anonymous commenter on one has no session to lose and
	 * no idea why they were turned away.
	 *
	 * `ClientIp::hmac()` already makes this argument for its own secret —
	 * lockouts must not evaporate when keys rotate — and the same requirement
	 * applies here. Reusing that key rather than adding a sibling: both are
	 * plugin-held, neither leaves the site, and one fewer option is one fewer
	 * thing to keep in step.
	 */
	private function sign( string $time ): string {
		return hash_hmac( 'sha256', 'bettershield-hp|' . $time, ClientIp::signing_secret() );
	}

	private function record( string $surface ): void {
		Writer::instance()->record(
			'honeypot_rejected',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'honeypot',
				'object_id'   => $surface,
			)
		);
	}
}
