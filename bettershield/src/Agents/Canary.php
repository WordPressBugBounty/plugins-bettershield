<?php
/**
 * A credential that exists only to be used by somebody who should not have it.
 *
 * Every other signal in this plugin is an inference: a file no longer matches
 * what its publisher shipped, an account has not been used for six months, a
 * connection failed too many times. Each is strong and each has a reading
 * where nothing is wrong.
 *
 * This one does not. The canary is an application password that belongs to no
 * tool, is written into no configuration, and is used by no workflow — so the
 * only way it authenticates is that somebody read it out of this site's
 * database or its backups. There is no innocent explanation and this plugin
 * does not have to construct one. It is the strongest possible evidence with
 * no signatures, no heuristics, and no false positives.
 *
 * **Opt-in, and plainly visible to the owner.** The deception is of an
 * attacker; the owner is told exactly what it is, where it is, and that it
 * will fire if anything touches it. A tripwire the owner does not know about
 * is a tripwire that fires at three in the morning and nobody knows why.
 *
 * **The safest cut, deliberately.** A decoy administrator account is the
 * heavier version of this idea and it is not built: it changes the site's own
 * user list, appears in every export and every count, and would have to be
 * explained on every screen that counts administrators — including this
 * plugin's own findings.
 *
 * **It cannot be used to get in.** The credential belongs to an account that
 * already exists, and using it is recorded and alerted before anything else
 * happens — but a canary that granted real access would be a back door this
 * plugin installed. So the authentication is refused as well as reported.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Canary {

	/** Which application password is the decoy, by uuid and owner. */
	public const OPTION = 'bettershield_canary';

	/**
	 * Which account each site of the network planted a decoy on, kept once for
	 * the whole network.
	 *
	 * An application password is user meta, which a network shares; the record
	 * naming one is a site option, which it does not. So a subsite asked to
	 * recognize a decoy planted next door has nothing of its own to read, and
	 * this is the one thing every site of a network can see: which accounts a
	 * decoy exists on for a name to be evidence about.
	 *
	 * The account and not merely the site. "Somebody on this network planted
	 * one" is not enough for a public name to prove anything, because the name
	 * proves nothing about the account holding the credential — see
	 * `is_decoy()`. Each entry is an array so a record written before the
	 * account was kept is recognizable as the older shape and read as naming
	 * nobody; the site's next sweep writes the account and it counts again.
	 */
	public const NETWORK_OPTION = 'bettershield_canary_sites';

	/** What it is called, so the owner recognizes it in core's own list. */
	public const NAME = 'BetterShield trap password (do not use)';

	/** What it was called before (#2414), still recognized on a decoy planted under it. */
	public const FORMER_NAMES = array( 'BetterShield canary (do not use)' );

	/**
	 * Whether the decoy is being created right now.
	 *
	 * Core's own hook reports the credential as it is made, and the activity
	 * listener on it recorded a second creation, at the privilege's severity,
	 * with nothing to say it was the decoy: an instant alert for the plugin
	 * planting its own tripwire. Planting records its own row; the listener
	 * stands aside while this is set. Not told apart by the name, which any
	 * account can give a credential of its own.
	 */
	private static bool $planting = false;

	/** Whether the credential being created is the decoy this class is planting. */
	public static function planting(): bool {
		return self::$planting;
	}

	/**
	 * Plant one, replacing any that was there.
	 *
	 * @return array{name: string, user_id: int}|\WP_Error
	 */
	public static function plant( int $user_id ) {
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return new \WP_Error(
				'bettershield_no_app_passwords',
				__( 'Application passwords are unavailable here, so no decoy can be planted.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( ! user_can( $user_id, 'edit_user', $user_id ) ) {
			return new \WP_Error(
				'bettershield_bad_canary_owner',
				__( 'That account cannot hold an application password.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		// The one being replaced goes without a disarm on the record: the
		// tripwire is back up as soon as this one is planted.
		self::take_down();

		self::$planting = true;

		try {
			$made = \WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => self::NAME ) );
		} finally {
			self::$planting = false;
		}

		if ( is_wp_error( $made ) ) {
			return $made;
		}

		/*
		 * The password itself is thrown away here and never shown to anybody,
		 * which is the point: nothing legitimate is ever going to use it, so
		 * nobody needs to hold it. What is kept is which credential it is.
		 */
		update_option(
			self::OPTION,
			array(
				'user_id'    => $user_id,
				'uuid'       => (string) $made[1]['uuid'],
				'planted_at' => gmdate( 'c' ),
			),
			false
		);

		self::join_roster( $user_id );

		Writer::instance()->record(
			'app_password_created',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'app_password',
				'object_id'   => (string) $made[1]['uuid'],
				'context'     => array(
					'name' => self::NAME,
					'kind' => 'canary',
				),
			)
		);

		return array(
			'name'    => self::NAME,
			'user_id' => $user_id,
		);
	}

	/**
	 * The decoy, if there is still one that can be tripped.
	 *
	 * The stored record is not proof on its own. The credential can go without
	 * this plugin being asked — the owner revoking it from their profile,
	 * another plugin, the account itself being deleted — and a record kept past
	 * that would have the screen reporting a tripwire that can no longer fire.
	 * So the record is checked against core's own list before it is believed.
	 *
	 * **This only reads.** Tidying the stale record away is `reconcile()`, and
	 * it is called from the paths that already write — the daily sweep — rather
	 * than from every screen that asks a question. An accessor that deletes a
	 * row and writes a log line is one an ability annotated as a read can call
	 * without anybody noticing, which is what this used to be.
	 *
	 * @return array{user_id: int, uuid: string, planted_at: string}|null
	 */
	public static function planted(): ?array {
		$stored = get_option( self::OPTION, null );

		if ( ! is_array( $stored ) || empty( $stored['uuid'] ) ) {
			return null;
		}

		$record = array(
			'user_id'    => (int) $stored['user_id'],
			'uuid'       => (string) $stored['uuid'],
			'planted_at' => (string) ( $stored['planted_at'] ?? '' ),
		);

		// Nothing to check it against on this site, so the record stands rather
		// than being discarded on an answer nobody here can give.
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return $record;
		}

		foreach ( \WP_Application_Passwords::get_user_application_passwords( $record['user_id'] ) as $password ) {
			if ( $record['uuid'] === (string) ( $password['uuid'] ?? '' ) ) {
				return $record;
			}
		}

		return null;
	}

	/**
	 * When the planted decoy was last used, and how many times, read from the
	 * log the alarm writes to. Null while nothing has used it.
	 *
	 * The screen that shows the decoy said nothing had touched it whatever
	 * the log held, because it only ever learned that one was planted.
	 *
	 * @return array{at: ?string, count: int}|null
	 */
	public static function last_use( string $uuid ): ?array {
		global $wpdb;

		if ( '' === $uuid ) {
			return null;
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one bounded read on the plugin's own table, for a dashboard screen; the site predicate is integers assembled by Schema::site_where(), and every value is bound.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT COUNT(*) AS uses, MAX(occurred_at) AS last FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND event_type = %s AND object_id = %s',
				Schema::table( 'events' ),
				'canary_used',
				$uuid
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( ! $row || (int) $row->uses < 1 ) {
			return null;
		}

		return array(
			'at'    => Time::utc_iso( (string) $row->last ),
			'count' => (int) $row->uses,
		);
	}

	/**
	 * Let go of a record whose credential has gone, and say so once.
	 *
	 * Separate from reading it because this writes: it removes the record and
	 * records that the protection the screen was reporting is off. Called from
	 * the daily sweep, which is already a write and already runs without
	 * anybody waiting on it.
	 *
	 * It is also where this site's roster entry catches up. A record written
	 * before the account was kept names a site and nobody, and the network
	 * cannot read a name as evidence without knowing whose account it belongs
	 * to; the sweep is the one path here that already writes and that nothing
	 * is waiting on, so the catching up happens there rather than on the
	 * authentication it would otherwise slow down.
	 */
	public static function reconcile(): void {
		$stored = get_option( self::OPTION, null );

		if ( ! is_array( $stored ) || empty( $stored['uuid'] ) ) {
			return;
		}

		// Still there is the ordinary case and costs one cached meta read.
		$planted = self::planted();

		if ( null !== $planted ) {
			self::join_roster( $planted['user_id'] );

			return;
		}

		self::forget( (string) $stored['uuid'] );
	}

	/**
	 * Let go of a decoy whose credential is no longer there.
	 *
	 * The credential's own removal is already in the log, whoever did it. This
	 * row is the other half: the protection the screen was reporting is off,
	 * and it takes planting another to get it back. Its own type, rather than
	 * a settings row, because the log thins to security events on a visitor's
	 * request and a tripwire coming down is one.
	 */
	private static function forget( string $uuid ): void {
		delete_option( self::OPTION );
		self::leave_roster();

		Writer::instance()->record(
			'canary_disarmed',
			Writer::SEVERITY_HIGH,
			array(
				'actor_type'  => 'system',
				'object_type' => 'app_password',
				'object_id'   => $uuid,
				'context'     => array(
					'reason' => 'credential_removed',
				),
			)
		);
	}

	/**
	 * Take it away, at the owner's word.
	 *
	 * The credential's deletion is recorded by core's hook as any removal
	 * is. The tripwire coming down is said as well, as forget() says it when
	 * the credential went some other way: the owner's own switch left only
	 * the generic removal, weaker evidence than any other way of disarming.
	 */
	public static function remove(): void {
		$uuid = self::take_down();

		if ( null === $uuid ) {
			return;
		}

		Writer::instance()->record(
			'canary_disarmed',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'app_password',
				'object_id'   => $uuid,
				'context'     => array(
					'reason' => 'owner_disabled',
				),
			)
		);
	}

	/**
	 * Delete the decoy's credential and let it go.
	 *
	 * @return string|null Which credential it was, or null when none was planted.
	 */
	private static function take_down(): ?string {
		$planted = self::planted();

		if ( null !== $planted && class_exists( 'WP_Application_Passwords' ) ) {
			\WP_Application_Passwords::delete_application_password( $planted['user_id'], $planted['uuid'] );
		}

		delete_option( self::OPTION );
		self::leave_roster();

		return null !== $planted ? (string) $planted['uuid'] : null;
	}

	/* ---- where a decoy exists to be named -------------------------------- */

	/**
	 * Which account each site of this network planted a decoy on.
	 *
	 * @return array<int, array{user_id: int}> Keyed by the site that planted it.
	 */
	private static function roster(): array {
		$stored = get_network_option( null, self::NETWORK_OPTION, array() );

		if ( ! is_array( $stored ) ) {
			return array();
		}

		$roster = array();

		foreach ( $stored as $blog_id => $entry ) {
			// The older shape named a site and no account, which says a decoy
			// exists somewhere and not whose it is. That is not enough for a
			// name to be evidence, so the entry is carried but names nobody
			// until the site that owns it writes the account.
			$user_id = is_array( $entry ) ? (int) ( $entry['user_id'] ?? 0 ) : 0;

			$roster[ (int) $blog_id ] = array( 'user_id' => max( 0, $user_id ) );
		}

		return $roster;
	}

	/**
	 * The accounts of this network a decoy is planted on.
	 *
	 * @return int[]
	 */
	private static function decoy_accounts(): array {
		$accounts = array();

		foreach ( self::roster() as $entry ) {
			if ( $entry['user_id'] > 0 ) {
				$accounts[] = $entry['user_id'];
			}
		}

		return array_values( array_unique( $accounts ) );
	}

	private static function join_roster( int $user_id ): void {
		$roster = self::roster();
		$here   = get_current_blog_id();

		if ( isset( $roster[ $here ] ) && $roster[ $here ]['user_id'] === $user_id ) {
			return;
		}

		$roster[ $here ] = array( 'user_id' => $user_id );

		update_network_option( null, self::NETWORK_OPTION, $roster );
	}

	private static function leave_roster(): void {
		$roster = self::roster();
		$left   = $roster;

		unset( $left[ get_current_blog_id() ] );

		if ( $left === $roster ) {
			return;
		}

		if ( array() === $left ) {
			// Nothing planted anywhere, and the row saying otherwise is the
			// thing the name would be believed on. It goes rather than sits
			// empty.
			delete_network_option( null, self::NETWORK_OPTION );

			return;
		}

		update_network_option( null, self::NETWORK_OPTION, $left );
	}

	/**
	 * The credential the authentication chain is checking right now, held
	 * for the length of core's own check and no longer.
	 *
	 * @var array{0: string, 1: string}|null
	 */
	private static ?array $presented = null;

	public static function register(): void {
		add_action( 'application_password_did_authenticate', array( self::class, 'tripped' ), 1, 2 );

		/*
		 * Where application passwords are switched off — for the accounts
		 * that manage the site by the hardening fix, or for everyone by a
		 * lockdown — core refuses before it checks the password, and the
		 * hook above never fires. The decoy belongs to a privileged account,
		 * so both leave it silent while its card reports it armed. The
		 * refusal is heard too, and the credential matched against the decoy.
		 */
		add_action( 'application_password_failed_authentication', array( self::class, 'refused' ), 1 );
		add_filter( 'authenticate', array( self::class, 'present' ), 19, 3 );
		add_filter( 'authenticate', array( self::class, 'let_go' ), 21 );

		/*
		 * Switched off for everyone, core's REST door does not even refuse:
		 * it returns before it reads the credential, so the refusal above
		 * never fires there. The request's credential is matched as REST
		 * starts to serve it, rather than on REST's authentication filter,
		 * where this plugin hangs nothing: nothing it adds can fence REST.
		 * XML-RPC needs nothing more: a lockdown closes it before any
		 * credential is checked, so nothing can use the decoy there.
		 */
		add_action( 'rest_api_init', array( self::class, 'heard_over_rest' ), 1 );
	}

	/**
	 * A REST request carrying a credential while application passwords are
	 * switched off for everyone, matched against the decoy.
	 */
	public static function heard_over_rest(): void {
		if ( ! wp_is_application_passwords_available() && isset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) ) {
			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared against a hash and an account name, never stored or printed.
			self::match_decoy( (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ), (string) wp_unslash( $_SERVER['PHP_AUTH_PW'] ) );
			// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
	}

	/**
	 * Hold what the authentication chain was handed until core's check of
	 * application passwords, at the priority after this, is done with it.
	 *
	 * The REST door hands core the credential from the request itself, which
	 * `refused()` can read there; XML-RPC goes through this chain, and only
	 * the chain is handed what was presented.
	 *
	 * @param mixed $user
	 * @param mixed $username
	 * @param mixed $password
	 * @return mixed
	 */
	public static function present( $user, $username = '', $password = '' ) {
		self::$presented = is_string( $username ) && is_string( $password ) ? array( $username, $password ) : null;

		return $user;
	}

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public static function let_go( $user ) {
		self::$presented = null;

		return $user;
	}

	/**
	 * Core refused an application password before checking it, because
	 * application passwords are switched off. Whether it was the decoy is
	 * asked of the account's own decoys only, so no other credential is
	 * hashed here.
	 *
	 * @param mixed $error
	 */
	public static function refused( $error ): void {
		if ( ! $error instanceof \WP_Error || ! in_array( $error->get_error_code(), array( 'application_passwords_disabled', 'application_passwords_disabled_for_user' ), true ) ) {
			return;
		}

		if ( null !== self::$presented ) {
			list( $username, $password ) = self::$presented;
		} else {
			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- compared against a hash and an account name, never stored or printed.
			$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
			$password = isset( $_SERVER['PHP_AUTH_PW'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_PW'] ) : '';
			// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}

		self::$presented = null;

		self::match_decoy( $username, $password );
	}

	/**
	 * Report a refused credential that is the account's decoy. Asked of the
	 * account's own decoys only, so no other credential is hashed here.
	 */
	private static function match_decoy( string $username, string $password ): void {
		$user = '' === $username ? false : get_user_by( 'login', $username );

		if ( ! $user && is_email( $username ) ) {
			$user = get_user_by( 'email', $username );
		}

		if ( ! $user instanceof \WP_User || '' === $password || ! class_exists( 'WP_Application_Passwords' ) ) {
			return;
		}

		// As core reads it: generated passwords are alphanumeric, and may be
		// written with spaces between the groups.
		$password = (string) preg_replace( '/[^a-z\d]/i', '', $password );

		foreach ( \WP_Application_Passwords::get_user_application_passwords( $user->ID ) as $item ) {
			if ( self::is_decoy( $item, (int) $user->ID ) && self::hash_matches( $password, (string) $item['password'] ) ) {
				// Already refused by core, so it is only reported.
				self::report( $user, (string) $item['uuid'], (string) ( $item['name'] ?? '' ) );

				return;
			}
		}
	}

	/**
	 * Whether a password is the one behind a stored application-password
	 * hash. Core's own check arrives in WordPress 6.8; below it every stored
	 * hash came from wp_hash_password(), and wp_check_password() is what 6.8
	 * itself falls back to for one. No account ID is passed, as 6.8 passes
	 * none: with one, an MD5-length hash would be rehashed onto the account's
	 * own sign-in password.
	 */
	private static function hash_matches( string $password, string $hash ): bool {
		if ( method_exists( \WP_Application_Passwords::class, 'check_password' ) ) {
			return \WP_Application_Passwords::check_password( $password, $hash );
		}

		return wp_check_password( $password, $hash );
	}

	/**
	 * Something authenticated with the decoy.
	 *
	 * Recorded at critical, which is the instant-alert path — this is the one
	 * signal in the plugin with no innocent reading, and the owner should hear
	 * about it while it is happening rather than in a weekly summary.
	 *
	 * @param mixed $user The account that authenticated.
	 * @param mixed $item The application password used.
	 */
	public static function tripped( $user = null, $item = array() ): void {
		$uuid    = is_array( $item ) && isset( $item['uuid'] ) ? (string) $item['uuid'] : '';
		$user_id = $user instanceof \WP_User ? (int) $user->ID : 0;

		if ( '' === $uuid || ! self::is_decoy( $item, $user_id ) ) {
			return;
		}

		self::report( $user, $uuid, is_array( $item ) && isset( $item['name'] ) ? (string) $item['name'] : '' );

		/*
		 * And it is refused. Reporting the use is the point, but a credential
		 * this plugin planted that then let somebody in would be a back door
		 * this plugin installed — and the report would be of a break-in it
		 * held the door open for.
		 */
		self::refuse();
	}

	/**
	 * Record a use of the decoy.
	 *
	 * @param mixed  $user The account it was issued against.
	 * @param string $name The credential's name, as the email and the log name it.
	 */
	private static function report( $user, string $uuid, string $name = '' ): void {
		Writer::instance()->record(
			'canary_used',
			Writer::SEVERITY_CRITICAL,
			array(
				'actor_type'  => 'system',
				'object_type' => 'app_password',
				'object_id'   => $uuid,
				'context'     => array(
					// The account it was issued against, so the owner knows
					// which credential store to consider compromised. No
					// address: this plugin does not keep full ones anywhere,
					// and the sign-in record already carries the truncated one.
					'user' => $user instanceof \WP_User ? $user->user_login : '',
					// Named, never by its ID, which tells a reader nothing.
					'name' => \BetterShield\Support\Text::clip( $name, 100 ),
				),
			)
		);
	}

	/**
	 * Whether the credential just used is the decoy.
	 *
	 * Asked of the credential rather than of the stored record, because the
	 * two do not live in the same place. An application password is user meta,
	 * which a network shares; the record naming it is this site's own option,
	 * which a network does not. Read from the record, a decoy planted on one
	 * subsite went unrecognized on every other — alerted nowhere and refused
	 * nowhere, on the shape where an operator has the most sites to lose.
	 *
	 * The name is the evidence because the name travels with the credential.
	 * It is not a secret and does not need to be: nothing legitimate is ever
	 * going to use a credential called this, so somebody who reads the name
	 * and creates their own is holding a credential that does not work.
	 *
	 * But the name is evidence only on an account a decoy was actually planted
	 * on. It is a public constant and every account can create an application
	 * password for itself, so a subscriber — a store customer — can name one
	 * exactly this. Believing the name alone would let them raise the one
	 * signal in this plugin with no innocent reading, mail it immediately, and
	 * exempt the credential they named from the sweep that retires the
	 * forgotten. A tripwire anybody can trip on purpose is not a tripwire, and
	 * one anybody can hide behind is worse than none.
	 *
	 * So the account has to match: this site's own decoy, or one planted
	 * anywhere on this network. The account is passed in rather than read from
	 * the credential, because core's own record of an application password
	 * does not carry whose it is.
	 *
	 * Public because the expiry sweep asks the same question of every
	 * credential it considers, and for the same reason: what it holds is
	 * the credential, and the record naming it may belong to another site.
	 *
	 * @param mixed $item    An application password, as core hands it out.
	 * @param int   $user_id The account the credential belongs to.
	 */
	public static function is_decoy( $item, int $user_id ): bool {
		if ( ! is_array( $item ) ) {
			return false;
		}

		// The record still answers for this site, so a decoy renamed after it
		// was planted is recognized here even though the name no longer says
		// what it is.
		$planted = self::planted();

		if ( null !== $planted && (string) ( $item['uuid'] ?? '' ) === $planted['uuid'] ) {
			return true;
		}

		if ( ! in_array( (string) ( $item['name'] ?? '' ), array_merge( array( self::NAME ), self::FORMER_NAMES ), true ) ) {
			return false;
		}

		$accounts = self::decoy_accounts();

		if ( null !== $planted ) {
			$accounts[] = $planted['user_id'];
		}

		return $user_id > 0 && in_array( $user_id, $accounts, true );
	}

	/**
	 * Take the authentication back.
	 *
	 * Core has already accepted the password by the time the hook above fires,
	 * so the account is cleared for the rest of the request and the request
	 * itself is answered with a refusal.
	 *
	 * Refused at the authentication chain rather than only at REST. Core
	 * accepts an application password on XML-RPC as well, and
	 * `rest_authentication_errors` is applied by the REST server alone — so
	 * the same credential that was refused on one door signed in on the other,
	 * while the alert said it had been stopped. The account is cleared, the
	 * chain is told there is no user, and REST additionally gets a 401 with a
	 * body rather than an empty refusal.
	 */
	private static function refuse(): void {
		wp_set_current_user( 0 );

		add_filter( 'rest_authentication_errors', array( self::class, 'refusal' ), PHP_INT_MAX );
		add_filter( 'determine_current_user', '__return_false', PHP_INT_MAX );
		add_filter( 'authenticate', array( self::class, 'refusal' ), PHP_INT_MAX );
	}

	/**
	 * @param mixed $error
	 * @return mixed
	 */
	public static function refusal( $error ) {
		return new \WP_Error(
			'bettershield_canary',
			__( 'That credential is not usable.', 'bettershield' ),
			array( 'status' => 401 )
		);
	}
}
