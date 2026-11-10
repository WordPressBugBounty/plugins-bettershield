<?php
/**
 * Hardening item: refuse a password that already appears in a published
 * breach.
 *
 * A password's strength is a property of the string; whether it has already
 * been published is a fact about the world, and the second one is what
 * credential-stuffing actually runs on. A twelve-character password with
 * mixed case and a digit can pass every local rule this plugin has and still
 * be on a list somebody downloaded this morning.
 *
 * The question is asked without sending the password, and without sending
 * anything a service could tie to this site. The candidate is hashed here,
 * the first five characters of that hash are sent, and the service answers
 * with every hash it holds that begins the same way — several hundred of
 * them. The comparison happens on this server. Nothing identifies the site,
 * the account or the password, and no account of any kind exists to hold it.
 *
 * Three rules the rest of this class is arranged around:
 *
 * - **It never touches signing in.** This is asked when somebody CHOOSES a
 *   password, never when they use one. An existing password is never
 *   refused, never reset, and never reported to anybody.
 * - **Nobody signed in, nothing happens.** No request, no cached answer, no
 *   claim row. See `may_ask()`.
 * - **A check that cannot be made allows the password.** The network is
 *   somebody else's, and refusing to let a person choose a password because a
 *   third party is down would turn an outage into a lockout. The failure is
 *   recorded — at most once an hour, because a service that is down is down
 *   for every attempt — and the password is accepted.
 * - **Nothing about a candidate is written down.** Not the password, not its
 *   hash, and not the part of the hash that was sent. What is held is the
 *   service's public answer, under a key derived from those five characters
 *   rather than spelling them — see `range()`.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Writer;
use BetterShield\Password\RestAccounts;
use BetterShield\Support\Checkout;
use BetterShield\Support\Claim;
use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class BreachedPasswords {

	/**
	 * The range endpoint, which takes five characters and returns everything
	 * beginning with them.
	 */
	private const ENDPOINT = 'https://api.pwnedpasswords.com/range/';

	/**
	 * The hooks this item listens on, in one place because the conflict probe
	 * reads the same list enforcement registers on.
	 */
	private const HOOKS = array(
		'user_profile_update_errors',
		'validate_password_reset',
		'registration_errors',
		'woocommerce_save_account_details_errors',
	);

	/**
	 * How long one range answer is held.
	 *
	 * Long enough that correcting a typo in the confirmation field, or fixing
	 * an unrelated error on the same form, does not ask the same question
	 * again; short enough that nothing here is a store of anything. What is
	 * held is the service's public answer for five characters — the same five
	 * that were already sent — and it expires on its own.
	 */
	private const CACHE_SECONDS = 300;

	private const CACHE_PREFIX = 'bettershield_pwrange_';

	/**
	 * The key that remembers an outage, and how long for.
	 *
	 * One key for the service rather than one per five characters: a service
	 * that is down is down for the next submission too, whatever it is being
	 * asked about, and asking again per submission spends a five-second wait
	 * on each of them. Short, because the answer is about right now — the
	 * service coming back must not wait a cache out.
	 *
	 * Under the same prefix as the answers, so the sweep that clears them on
	 * uninstall clears this too.
	 */
	private const UNAVAILABLE_CACHE = self::CACHE_PREFIX . 'unavailable';

	private const UNAVAILABLE_SECONDS = 60;

	/**
	 * The key that keeps the "could not check" record to one an hour.
	 *
	 * A claim rather than a transient: this decides whether a row is written
	 * at all, and two password forms submitted in the same second is an
	 * ordinary thing on a busy site.
	 */
	private const UNAVAILABLE_KEY = 'breach_unavailable';

	/**
	 * Whether anything else already answers on the same forms.
	 *
	 * Two refusals on one field are not a failure — the form shows both and
	 * the stricter one decides — but an owner should know before applying
	 * that a message they have seen before may not have been this item's.
	 */
	public static function conflict(): ?string {
		if ( ! self::another_plugin_listens() ) {
			return null;
		}

		// What the probe can see is another plugin on these forms' error
		// hooks, which is where a CAPTCHA or a profile field is checked too,
		// not that it checks passwords: said as that, so a site where this
		// would be the only password check is not told it has another.
		return __( 'Another plugin also checks these forms. Both can run together.', 'bettershield' );
	}

	/**
	 * A line for the item's card once it is applied.
	 *
	 * @param array<string, mixed> $state Unused; this item stores no options.
	 */
	public static function summary( array $state ): ?string {
		// Live state: switched off, nothing is checked.
		if ( empty( $state['active'] ) ) {
			return null;
		}

		return __( 'New passwords set while signed in are checked. Signing in is unaffected.', 'bettershield' );
	}

	/**
	 * @param array<string, mixed> $state Unused; runtime-only.
	 */
	public static function enforce( array $state ): void {
		/*
		 * Priority 20, after the password policy's own checks at 10. Length,
		 * reuse of the account's own name and the common-word list are decided
		 * here on this server, cost nothing and refuse most of what this would
		 * otherwise ask about — so a password that fails one of those never
		 * causes a request to leave the site at all.
		 */
		add_action( 'user_profile_update_errors', array( self::class, 'check_profile' ), 20, 3 );
		add_action( 'validate_password_reset', array( self::class, 'check_reset' ), 20, 2 );
		add_filter( 'registration_errors', array( self::class, 'check_registration' ), 20, 1 );

		/*
		 * The two the password policy beside this item already names, and for
		 * the reasons it gives. A store moves both forms above to its own
		 * account pages, which is where the sites with the most accounts on
		 * them do their password changing; and the REST routes that set a
		 * password — core's users route and the store's customers route with
		 * its batch — are the ones none of the above fires for, including
		 * creating a new administrator. Named unconditionally: the store hook never fires on
		 * a site with no store, so listing it costs such a site nothing.
		 */
		add_action( 'woocommerce_save_account_details_errors', array( self::class, 'check_store_account' ), 20, 2 );
		add_filter( 'rest_dispatch_request', array( self::class, 'check_rest' ), 20, 4 );
	}

	/**
	 * Whether what enforce() attaches is still attached on this request.
	 * Switched on is not the same as working: another plugin's
	 * remove_filter() leaves the item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'user_profile_update_errors', array( self::class, 'check_profile' ) )
			&& false !== has_action( 'validate_password_reset', array( self::class, 'check_reset' ) )
			&& false !== has_filter( 'registration_errors', array( self::class, 'check_registration' ) )
			&& false !== has_action( 'woocommerce_save_account_details_errors', array( self::class, 'check_store_account' ) )
			&& false !== has_filter( 'rest_dispatch_request', array( self::class, 'check_rest' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		remove_action( 'user_profile_update_errors', array( self::class, 'check_profile' ), 20 );
		remove_action( 'validate_password_reset', array( self::class, 'check_reset' ), 20 );
		remove_filter( 'registration_errors', array( self::class, 'check_registration' ), 20 );
		remove_action( 'woocommerce_save_account_details_errors', array( self::class, 'check_store_account' ), 20 );
		remove_filter( 'rest_dispatch_request', array( self::class, 'check_rest' ), 20 );
	}

	/* ---- where a password is chosen ------------------------------------- */

	/**
	 * A profile update carrying a new password, which is also an
	 * administrator typing one into the new-user form.
	 *
	 * The plaintext arrives on the record about to be saved, so nothing here
	 * reads the request.
	 *
	 * @param bool            $update Whether this is an update rather than a creation.
	 * @param \stdClass|mixed $user   The user data about to be saved.
	 */
	public static function check_profile( \WP_Error $errors, bool $update, $user ): void {
		if ( ! is_object( $user ) || ! isset( $user->user_pass ) ) {
			return;
		}

		self::refuse_if_published( $errors, (string) $user->user_pass, (int) ( $user->ID ?? 0 ) );
	}

	/**
	 * A reset form submission, which is also how core's own registration
	 * sets the first password.
	 *
	 * @param \WP_User|mixed $user The account the reset key was verified for.
	 */
	public static function check_reset( \WP_Error $errors, $user ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		self::refuse_if_published( $errors, self::posted_password(), (int) $user->ID );
	}

	/**
	 * A registration that carries a password.
	 *
	 * Core's own registration form does not: it generates one and mails a
	 * link, and the password is chosen on the reset form above. This covers
	 * the registration forms that do ask for one on the spot, which fire this
	 * same filter — so the answer is the same wherever the account begins.
	 *
	 * @param \WP_Error|mixed $errors
	 * @return \WP_Error|mixed
	 */
	public static function check_registration( $errors ) {
		if ( ! $errors instanceof \WP_Error ) {
			return $errors;
		}

		self::refuse_if_published( $errors, self::posted_password(), 0 );

		return $errors;
	}

	/**
	 * A password arriving through a store's own account page.
	 *
	 * The same evaluation the profile screen gets, from the same shape of
	 * object: a partial record carrying the ID and, when a password is being
	 * changed, the one that is about to be stored.
	 *
	 * @param \stdClass|mixed $user The user data about to be saved.
	 */
	public static function check_store_account( \WP_Error $errors, $user ): void {
		self::check_profile( $errors, true, $user );
	}

	/**
	 * A password arriving through a REST route that sets one — core's users
	 * route or the store's customers route and its batch — on creation or on
	 * update.
	 *
	 * Runs after the route's permission callback and in place of its own
	 * callback, which is where core lets a refusal actually stop the write:
	 * returning a WP_Error here short-circuits the request with that error.
	 * Not `rest_pre_insert_user`, which core applies inside
	 * `prepare_item_for_database()` and then never checks the return of, so a
	 * refusal there is discarded and the write proceeds. Not
	 * `rest_request_before_callbacks` either, which runs ahead of the route's
	 * own permission callback and would answer a caller the route has not yet
	 * agreed to talk to.
	 *
	 * @param mixed            $dispatch_result Whatever an earlier filter decided, or null.
	 * @param \WP_REST_Request $request         The request.
	 * @param string           $route           The matched route.
	 * @param array            $handler         The matched route handler.
	 * @return mixed
	 */
	public static function check_rest( $dispatch_result, $request, $route = '', $handler = array() ) {
		// Somebody ahead of this one has already replaced the dispatch; that
		// decision is theirs.
		if ( null !== $dispatch_result || ! $request instanceof \WP_REST_Request ) {
			return $dispatch_result;
		}

		/*
		 * Cheapest checks first, and deliberately so: this runs on every REST
		 * request the site serves, ours and everyone else's.
		 */
		if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			return $dispatch_result;
		}

		// The routes the password policy beside this item covers, read the
		// same way: `/wp/v2/users` (`/<id>`, `/me`), and the store's
		// customers route with each item of its batch. Namespaced copies of
		// the users route registered by other plugins are not covered and are
		// not this item's business.
		if ( ! RestAccounts::covers( (string) $request->get_route() ) ) {
			return $dispatch_result;
		}

		foreach ( RestAccounts::passwords( $request ) as $entry ) {
			if ( ! self::is_published( $entry['password'] ) ) {
				continue;
			}

			self::record_refusal( $entry['account'] );

			$data = array( 'status' => 400 );

			if ( '' !== $entry['item'] ) {
				$data['item'] = $entry['item'];
			}

			return new \WP_Error( 'bettershield_password_published', self::refusal(), $data );
		}

		return $dispatch_result;
	}

	/**
	 * The password being submitted, from the field names the forms that carry
	 * one actually use.
	 *
	 * Read rather than trusted: it is compared and discarded inside this
	 * request, and nothing here stores, logs or echoes it.
	 */
	private static function posted_password(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the reset flow verifies its own key, and registration is an unauthenticated form by design; this reads what was submitted rather than deciding anything on its own.
		$posted = $_POST['pass1'] ?? ( $_POST['password_1'] ?? ( $_POST['password'] ?? '' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Missing -- unslashed on the next line; a password is compared, never stored or output.

		return is_string( $posted ) ? (string) wp_unslash( $posted ) : '';
	}

	/* ---- the check ------------------------------------------------------- */

	/**
	 * Add the refusal if this password has been published, and nothing
	 * otherwise.
	 *
	 * @param int $user_id The account choosing it, or 0 where there is not one yet.
	 */
	private static function refuse_if_published( \WP_Error $errors, string $password, int $user_id ): void {
		/*
		 * Something has already refused this submission, so the form will not
		 * save whatever this answered — and asking would spend a request on a
		 * password nobody is going to end up with.
		 */
		if ( $errors->has_errors() || ! self::is_published( $password ) ) {
			return;
		}

		$errors->add( 'bettershield_password_published', self::refusal() );

		self::record_refusal( $user_id );
	}

	/** One sentence, on every form and on the route. */
	private static function refusal(): string {
		return __( 'This password appears in a published breach. Choose a different one.', 'bettershield' );
	}

	/**
	 * Whether this password is on a published list, as far as anything here
	 * can tell.
	 *
	 * False for a password nobody has published and false for one that could
	 * not be looked up, which are different facts the caller treats the same
	 * way: neither refuses anything.
	 */
	private static function is_published( string $password ): bool {
		// The password WordPress will store, which core hashes trimmed: a
		// published one with a space after it is still the published one.
		$password = trim( $password );

		if ( '' === $password || ! self::may_ask() ) {
			return false;
		}

		$sightings = self::sightings( $password );

		return null !== $sightings && $sightings > 0;
	}

	/**
	 * Whether this request is one the question may be asked on at all.
	 *
	 * Two conditions, and nothing happens on either side of them — no
	 * request, no cached answer, no claim row.
	 *
	 * Nothing at all on the checkout path, which is a rule this plugin keeps
	 * whatever the request looks like it is doing — judged by what the store
	 * and WordPress set while an order is processed, never by a parameter in
	 * the address. `wc-ajax` is one anybody can type, and added to a REST
	 * address or to the store's own account form it stood this check down on
	 * every store, for the password change it exists to check.
	 *
	 * And nothing for a submission nobody signed in for: a registration form a
	 * membership or community plugin puts on an ordinary page is a visitor's
	 * page view, and the gate this would reach the network through says in as
	 * many words that nothing may be reached from one. An administrator
	 * creating an account, somebody changing their own password, and a reset
	 * finished by a person who is signed in are all covered; a visitor filling
	 * in a form is not the reason anything leaves this site or is written to
	 * it.
	 */
	private static function may_ask(): bool {
		if ( Checkout::is_checkout_request() ) {
			return false;
		}

		return is_user_logged_in();
	}

	/**
	 * How many times this password appears in the published set, or null when
	 * the question could not be asked.
	 *
	 * Null and zero are deliberately different answers and the caller treats
	 * them the same way, which is the point: "not found" and "could not look"
	 * both let the password through, and only one of them is worth a record.
	 */
	private static function sightings( string $password ): ?int {
		$hash = strtoupper( sha1( $password ) );

		$answer = self::range( substr( $hash, 0, 5 ) );

		if ( null === $answer ) {
			self::note_unavailable();

			return null;
		}

		return self::sightings_in( $answer, substr( $hash, 5 ) );
	}

	/**
	 * The published answer for five characters, from the short-lived cache or
	 * from the service.
	 *
	 * The five characters are the whole of what leaves this site. They
	 * describe several hundred published hashes rather than one, which is what
	 * makes the answer usable without the question naming anything.
	 */
	private static function range( string $prefix ): ?string {
		// A service that is down is down for the next submission too, and the
		// wait is what the person on the form pays. One request an outage
		// rather than one per submission.
		if ( '' !== (string) get_transient( self::UNAVAILABLE_CACHE ) ) {
			return null;
		}

		/*
		 * Derived from the five characters rather than spelling them. They
		 * are public on the wire, but an option NAME saying this site chose a
		 * password in that bucket a moment ago is a different fact, and it
		 * would sit in the same table as the stored hash it narrows.
		 */
		$key    = self::CACHE_PREFIX . substr( hash( 'sha256', $prefix ), 0, 16 );
		$cached = get_transient( $key );

		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}

		$response = Http::get(
			self::ENDPOINT . $prefix,
			array(
				/*
				 * Shorter than the gate's own default. A person is waiting on
				 * a form while this runs, and fifteen seconds of a slow third
				 * party is worse for them than being allowed a password this
				 * could not check.
				 */
				'timeout' => 5,
				'headers' => array(
					'Accept' => 'text/plain',
					/*
					 * The answer is padded to a fixed size, so its length says
					 * nothing about how many real hashes begin with these five
					 * characters. Without it, anybody watching the connection
					 * learns something about the password from the size of a
					 * response they cannot read.
					 */
					'Add-Padding' => 'true',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return self::note_outage();
		}

		$body = (string) wp_remote_retrieve_body( $response );

		if ( '' === $body ) {
			return self::note_outage();
		}

		set_transient( $key, $body, self::CACHE_SECONDS );

		return $body;
	}

	/**
	 * Remember for a minute that the service did not answer, and say so.
	 */
	private static function note_outage(): ?string {
		set_transient( self::UNAVAILABLE_CACHE, '1', self::UNAVAILABLE_SECONDS );

		return null;
	}

	/**
	 * Find one suffix in the published answer.
	 *
	 * The count matters for one reason only: padding. The answer carries
	 * invented rows so that its size says nothing, and every invented row
	 * carries a count of zero — so a line that matches with a count of zero is
	 * padding that happened to collide, not a sighting.
	 */
	private static function sightings_in( string $answer, string $suffix ): int {
		foreach ( explode( "\n", $answer ) as $line ) {
			$row = explode( ':', trim( $line ) );

			if ( count( $row ) < 2 || 0 !== strcasecmp( $row[0], $suffix ) ) {
				continue;
			}

			return max( 0, (int) $row[1] );
		}

		return 0;
	}

	/* ---- what the log carries ------------------------------------------- */

	/**
	 * That a password was refused, and which account was choosing it.
	 *
	 * The account and nothing else. Not the password, not its hash, not the
	 * part of the hash that was sent, and not the number of times it has been
	 * published — that last one would say how bad the password was, which is
	 * a description of a password this site is still storing somewhere else.
	 */
	private static function record_refusal( int $user_id ): void {
		$args = array(
			'object_type' => 'hardening',
			'object_id'   => 'breached_passwords',
		);

		if ( $user_id > 0 ) {
			$args['actor_type']  = 'user';
			$args['actor_id']    = $user_id;
			$args['object_type'] = 'user';
			$args['object_id']   = (string) $user_id;
		}

		Writer::instance()->record( 'password_refused_breached', Writer::SEVERITY_LOW, $args );
	}

	/**
	 * That the check could not be made, at most once an hour.
	 *
	 * A service that is unreachable is unreachable for every attempt, so one
	 * row an hour says the same thing a row per attempt would and leaves the
	 * log readable. Silence would be worse than either: an owner who switched
	 * this on is entitled to know when it was not answering.
	 */
	private static function note_unavailable(): void {
		if ( ! Claim::claim( self::UNAVAILABLE_KEY, HOUR_IN_SECONDS ) ) {
			return;
		}

		Writer::instance()->record(
			'breach_check_unavailable',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'breached_passwords',
			)
		);
	}

	/* ---- the conflict probe ---------------------------------------------- */

	/**
	 * Whether anything outside this plugin is already listening on the forms
	 * this item answers on.
	 *
	 * Asked of the hooks rather than of a list of plugin names: the password
	 * policy in this plugin listens on two of the three, so "is anything
	 * registered" would be true on every site and say nothing.
	 */
	private static function another_plugin_listens(): bool {
		global $wp_filter;

		foreach ( self::HOOKS as $hook ) {
			if ( ! isset( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof \WP_Hook ) {
				continue;
			}

			foreach ( $wp_filter[ $hook ]->callbacks as $registered ) {
				foreach ( $registered as $listener ) {
					if ( ! self::is_ours( $listener['function'] ?? null ) ) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Whether a registered callback belongs to this plugin or its add-on.
	 *
	 * @param mixed $callback Whatever was registered.
	 */
	private static function is_ours( $callback ): bool {
		if ( is_array( $callback ) && isset( $callback[0] ) ) {
			$target = is_object( $callback[0] ) ? get_class( $callback[0] ) : (string) $callback[0];
		} elseif ( is_string( $callback ) ) {
			$target = $callback;
		} else {
			// A closure, or something this cannot name. Neither is ours.
			return false;
		}

		// The add-on is this plugin too: its own listeners on these forms
		// (an access request, a challenge on sign-up) are not another
		// plugin checking them (#2054).
		return 0 === strpos( $target, 'BetterShield\\' ) || 0 === strpos( $target, 'BetterShieldUltra\\' );
	}
}
