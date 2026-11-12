<?php
/**
 * Enrolled passkeys: where they live, and the challenges that precede them.
 *
 * Nothing secret is stored. A passkey's private half never leaves the device
 * that made it, and what sits here is a public key, a counter and a label —
 * a table an attacker who read it could do nothing with, which is the whole
 * point of the technology.
 *
 * A challenge is single-use and short-lived. It is consumed on the first look,
 * so a replayed response finds nothing to match against.
 *
 * A credential belongs to the account on the whole host rather than to one
 * site of it: the browser binds it to a domain, and a host whose sites share
 * that domain shares the credential whether this code likes it or not. So the
 * reads below name the account and not the site, and `site_id` records where
 * an enrollment happened rather than who may use it. Where the table is this
 * site's alone, the column keeps its old value and the reads name it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

use BetterShield\Database\Schema;
use BetterShield\Login\Protection;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

final class Store {

	/**
	 * How long a challenge stays answerable.
	 *
	 * Long enough to find a phone and use a fingerprint, short enough that a
	 * challenge captured from a screen is worthless by the time it is typed.
	 */
	private const CHALLENGE_SECONDS = 300;

	/**
	 * Nobody needs more than this, and a cap bounds what one account can
	 * store. Counted over the account rather than over one site: the
	 * credentials are the account's wherever they were enrolled, so a cap
	 * counted per site would be no cap at all on a host with many.
	 */
	public const MAX_PER_USER = 10;

	/**
	 * Challenges one connection may ask for inside a window, per purpose.
	 *
	 * Generous for a person — a browser that cannot find a key, a second
	 * device, a few honest retries — and far below the rate a flood needs to
	 * grow the options table.
	 */
	public const MAX_CHALLENGES_PER_WINDOW = 30;

	/** How long that count is kept. */
	public const CHALLENGE_RATE_SECONDS = 300;

	/**
	 * Hosts already resolved for a site id, for the length of the request.
	 *
	 * Keyed by the site asking as well as the site asked about: a request that
	 * switches sites gets a different answer for the same row, because `0`
	 * means the site the read is running on.
	 *
	 * @var array<string, string>
	 */
	private static array $hosts = array();

	/* ---- challenges ---------------------------------------------------- */

	/**
	 * Issue a challenge and remember it.
	 *
	 * Keyed by handle rather than by user, because the authentication
	 * challenge is issued before anybody knows who is signing in.
	 *
	 * A registration challenge also names the account and the session it was
	 * issued to, because asking for one is where the holder proves it is
	 * them: a handle another account or another session obtained must not
	 * finish a registration here.
	 *
	 * @return array{handle: string, challenge: string}|\WP_Error Challenge is raw bytes.
	 */
	public static function issue_challenge( string $purpose, int $user_id = 0 ) {
		$refused = self::source_refusal( $purpose );

		if ( null !== $refused ) {
			return $refused;
		}

		$handle    = bin2hex( random_bytes( 16 ) );
		$challenge = random_bytes( 32 );

		set_transient(
			self::challenge_key( $handle ),
			array(
				'purpose'   => $purpose,
				'challenge' => base64_encode( $challenge ),
				'user'      => $user_id,
				'session'   => self::session_mark(),
			),
			self::CHALLENGE_SECONDS
		);

		return array(
			'handle'    => $handle,
			'challenge' => $challenge,
		);
	}

	/**
	 * Whether this connection has asked for more challenges than a person
	 * would.
	 *
	 * The sign-in options route is open to anyone — it has to be, because
	 * signing in happens before there is anybody to check — and it wrote a
	 * fresh transient on every request. WordPress does not proactively purge
	 * expired transients, so a sustained stream of unauthenticated requests
	 * grew `wp_options` without bound, or flooded an object cache into
	 * evicting everything else. The recovery route already coalesces its
	 * anonymous writes for exactly this reason; this one was left without.
	 *
	 * Counted per source and per purpose, against the truncated, HMACed
	 * address this plugin uses everywhere else — never a full one. A person
	 * signing in retries a handful of times; the cap is far above that and far
	 * below what a flood needs.
	 *
	 * Per source only while there is a source to count: behind a proxy nobody
	 * has named, every visitor is one address, and thirty-one anonymous posts
	 * to a route that is open by design closed passkey sign-in for the whole
	 * site — renewably, and with no door left at all for an account whose
	 * role signs in this way only. `rate_bucket()` decides that once for
	 * every cap of this shape.
	 *
	 * And a source only while the address is not the request's own to write.
	 * On an edge nobody has vouched for, the client address is a header: one
	 * connection rotating it had a fresh bucket per value, which is no cap at
	 * all. What counts there is the address the request really arrived from —
	 * the one half of the pair it did not choose — and everybody that edge
	 * forwards shares it, so it counts against the shared cap for the same
	 * reason every other shared bucket does.
	 */
	private static function source_is_over_rate( string $purpose ): bool {
		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		$bucket = ClientIp::rate_bucket( $resolved, 'pkrate_' . $purpose, self::MAX_CHALLENGES_PER_WINDOW );

		/*
		 * The window starts at the first request and is not extended by the
		 * ones inside it, so a caller at the cap is refused for the remainder
		 * of that window rather than indefinitely. Counted in one statement
		 * for both halves of that promise: written as a read and then a write
		 * the count was lost under exactly the load it exists to bound, and
		 * storing a value refreshes its lifetime — so a steady drip pushed the
		 * window along ahead of itself and it never closed.
		 */
		return Claim::bump( $bucket['key'], self::CHALLENGE_RATE_SECONDS ) > $bucket['cap'];
	}

	/**
	 * The refusal a connection over the cap is answered with, or null while
	 * it is under it.
	 *
	 * Asked by both halves of a sign-in — the request for a challenge and
	 * the answer to one — so that a caller who skips the first half is
	 * counted all the same. Every ask counts whichever half it is: one
	 * honest sign-in is two, and the cap is far above what a person needs.
	 */
	public static function source_refusal( string $purpose ): ?\WP_Error {
		if ( ! self::source_is_over_rate( $purpose ) ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_passkey_rate_limited',
			__( 'Too many sign-in attempts from this connection. Wait a minute and try again.', 'bettershield' ),
			array( 'status' => 429 )
		);
	}

	/**
	 * Take a challenge back, once.
	 *
	 * Read first, then claimed, then deleted, and the order carries two
	 * promises.
	 *
	 * The read comes first because a handle is a string in an anonymous
	 * request. A claim is a row, and claiming before looking wrote a row for
	 * every handle a caller made up — on the one route the challenge cap did
	 * not cover, growing the one table the cap exists to protect. A handle
	 * nothing was issued under is refused from the read alone and costs
	 * nothing.
	 *
	 * Spending a real one is decided by an insert only one caller can win,
	 * and not by the transient underneath. Reading a transient and then
	 * deleting it is two statements: two responses to one challenge both
	 * read before either delete lands, and both are handed the same
	 * challenge back. That is the shape of the problem rather than a way out
	 * of it.
	 *
	 * The claim is not released on any path. A challenge is spent by being
	 * looked at — the transient is gone whatever the answer was — so a second
	 * caller must be told no even when the first one's purpose did not match.
	 * A database that will not answer is a loss for the same reason: this can
	 * afford to refuse a sign-in far more than it can afford to allow one
	 * challenge to be answered twice.
	 */
	public static function consume_challenge( string $handle, string $purpose, int $user_id = 0 ): ?string {
		$key    = self::challenge_key( $handle );
		$stored = get_transient( $key );

		if ( ! is_array( $stored ) ) {
			return null;
		}

		if ( ! Claim::claim( 'pkchal_' . $handle, self::CHALLENGE_SECONDS ) ) {
			return null;
		}

		delete_transient( $key );

		if ( ( $stored['purpose'] ?? '' ) !== $purpose ) {
			return null;
		}

		if ( (int) ( $stored['user'] ?? 0 ) !== $user_id || ! hash_equals( (string) ( $stored['session'] ?? '' ), self::session_mark() ) ) {
			return null;
		}

		$challenge = base64_decode( (string) ( $stored['challenge'] ?? '' ), true );

		return is_string( $challenge ) && '' !== $challenge ? $challenge : null;
	}

	/** The session this request is signed in on, as a digest; empty when none. */
	private static function session_mark(): string {
		$token = wp_get_session_token();

		return '' === $token ? '' : hash( 'sha256', $token );
	}

	private static function challenge_key( string $handle ): string {
		return 'bettershield_pkchal_' . $handle;
	}

	/* ---- which rows answer here ---------------------------------------- */

	/**
	 * The predicate for "this account's credentials", wherever they were made.
	 *
	 * Where the credentials of a host live in one table, an account's are read
	 * whole: the browser offers a credential for the domain, not for the site,
	 * so a read that named one site would hide a credential the browser is
	 * about to present. Off that table the column keeps its own value and the
	 * read names it, which is the single-site behavior unchanged.
	 */
	private static function account_where(): string {
		return Schema::is_network_table_here( 'passkeys' ) ? '1 = 1' : Schema::site_where( 'passkeys' );
	}

	/**
	 * The relying party a stored credential was created under.
	 *
	 * A row written before the column records nothing, and belongs to the host
	 * of the site it was enrolled on — which is what the browser bound it to
	 * at the time.
	 */
	public static function rp_id_of( int $site_id, string $rp_id ): string {
		return '' !== $rp_id ? strtolower( $rp_id ) : self::host_of_site( $site_id );
	}

	/**
	 * Whether a stored credential is one a browser here would offer.
	 *
	 * A credential cannot be re-scoped: asked for one relying party, a browser
	 * will not present a credential made for another, whatever this site
	 * sends. So a row of an older generation is kept and shown, and counts for
	 * nothing that decides whether an account can sign in.
	 */
	public static function is_usable( int $site_id, string $rp_id ): bool {
		return self::rp_id_of( $site_id, $rp_id ) === Manager::rp_id();
	}

	/**
	 * The host a site is addressed at, for a credential enrolled on it.
	 *
	 * `0` is this site off a network. On one it is a row written before the
	 * site column carried a value, which belongs to the main site.
	 */
	private static function host_of_site( int $site_id ): string {
		$memo = ( is_multisite() ? (int) get_current_blog_id() : 0 ) . ':' . $site_id;

		if ( isset( self::$hosts[ $memo ] ) ) {
			return self::$hosts[ $memo ];
		}

		$blog = $site_id;

		if ( is_multisite() && 0 === $site_id ) {
			$blog = (int) get_main_site_id();
		}

		if ( ! is_multisite() || $blog === (int) get_current_blog_id() ) {
			self::$hosts[ $memo ] = self::host_of( (string) home_url() );

			return self::$hosts[ $memo ];
		}

		$home = get_blog_option( $blog, 'home', '' );

		self::$hosts[ $memo ] = self::host_of( is_string( $home ) ? $home : '' );

		return self::$hosts[ $memo ];
	}

	private static function host_of( string $url ): string {
		$host = '' !== $url ? wp_parse_url( $url, PHP_URL_HOST ) : null;

		return is_string( $host ) && '' !== $host ? strtolower( $host ) : 'localhost';
	}

	/**
	 * Forget the resolved hosts. For a request that changes site, and tests.
	 */
	public static function forget_hosts(): void {
		self::$hosts = array();
	}

	/* ---- credentials --------------------------------------------------- */

	/**
	 * @return array{id: int, user_id: int, site_id: int, rp_id: string, credential_id: string, public_key: string, algorithm: int, sign_count: int, label: string}|null
	 */
	public static function find( string $credential_id ): ?array {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE ' . self::account_where() . ' AND credential_id = %s',
				Schema::table( 'passkeys' ),
				$credential_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( null === $row ) {
			return null;
		}

		return array(
			'id'            => (int) $row->id,
			'user_id'       => (int) $row->user_id,
			'site_id'       => (int) $row->site_id,
			'rp_id'         => (string) $row->rp_id,
			'credential_id' => (string) $row->credential_id,
			'public_key'    => (string) $row->public_key,
			'algorithm'     => (int) $row->algorithm,
			'sign_count'    => (int) $row->sign_count,
			'label'         => (string) $row->label,
		);
	}

	/**
	 * Everything one account has enrolled, for the screen that manages them.
	 *
	 * `usable` is what the panel reads: a credential of an older generation is
	 * listed, and said to be listed for removal rather than for signing in.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function for_user( int $user_id ): array {
		$out = array();

		foreach ( self::rows_for_user( $user_id ) as $row ) {
			$out[] = array
			(
				'id'           => (int) $row->id,
				'label'        => (string) $row->label,
				'transports'   => (string) $row->transports,
				'usable'       => self::is_usable( (int) $row->site_id, (string) $row->rp_id ),
				'created_at'   => Time::utc_iso( (string) $row->created_at ),
				'last_used_at' => Time::utc_iso( null !== $row->last_used_at ? (string) $row->last_used_at : null ),
			);
		}

		return $out;
	}

	/**
	 * One account's rows, in enrollment order.
	 *
	 * @return array<int, object>
	 */
	private static function rows_for_user( int $user_id ): array {
		global $wpdb;
		$verification = Schema::ready( 'passkey_verification' ) ? 'user_verified' : 'NULL AS user_verified';
		$discoverable = Schema::ready( 'passkey_discoverable' ) ? 'discoverable' : 'NULL AS discoverable';

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, site_id, rp_id, credential_id, label, transports, created_at, last_used_at, ' . $verification . ', ' . $discoverable . ' FROM %i WHERE ' . self::account_where() . ' AND user_id = %d ORDER BY id ASC',
				Schema::table( 'passkeys' ),
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * The credential ids one account can sign in with here, for the browser's
	 * passkey store to keep. One removed, or one of an older generation, is
	 * left out, so the store can stop offering it.
	 *
	 * @return string[]
	 */
	public static function usable_credential_ids_for_user( int $user_id ): array {
		$out = array();

		foreach ( self::rows_for_user( $user_id ) as $row ) {
			if ( self::is_usable( (int) $row->site_id, (string) $row->rp_id ) ) {
				$out[] = (string) $row->credential_id;
			}
		}

		return $out;
	}

	/**
	 * The credential ids one account already has, so the browser can decline
	 * to enroll the same device twice.
	 *
	 * @return string[]
	 */
	public static function credential_ids_for_user( int $user_id ): array {
		$out = array();

		foreach ( self::rows_for_user( $user_id ) as $row ) {
			$out[] = (string) $row->credential_id;
		}

		return $out;
	}

	/**
	 * How many credentials this account holds, of any generation.
	 *
	 * This is the number the cap is counted against, and the number the
	 * management screen shows. What decides whether a password may be refused
	 * is `count_usable_for_user()` below, which is a smaller number on a host
	 * whose relying party has changed.
	 */
	public static function count_for_user( int $user_id ): int {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE ' . self::account_where() . ' AND user_id = %d',
				Schema::table( 'passkeys' ),
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	/**
	 * How many of this account's credentials a browser here would offer.
	 *
	 * The safety number. A credential made under a relying party this host no
	 * longer asks for is never presented, so an account holding only those has
	 * no passkey in any sense that matters — and a policy that refused its
	 * password on the strength of one would be refusing both doors at once.
	 */
	public static function count_usable_for_user( int $user_id ): int {
		$usable = 0;

		foreach ( self::rows_for_user( $user_id ) as $row ) {
			if ( self::signs_in( $row ) ) {
				++$usable;
			}
		}

		return $usable;
	}

	/** Credentials that have actually verified their holder, at enrollment or in a signed assertion. */
	public static function count_verified_for_user( int $user_id ): int {
		$verified = 0;
		foreach ( self::rows_for_user( $user_id ) as $row ) {
			if ( 1 === (int) $row->user_verified && self::signs_in( $row ) ) { ++$verified; }
		}
		return $verified;
	}

	/**
	 * Whether a stored row is a credential the sign-in form can use: offered
	 * by a browser here, and not one the browser said needs a username first
	 * (#2469). The sign-in has no username step, so such a key is never
	 * offered there. Rows from before the record, and from browsers that did
	 * not say, are unknown and still count, as they always did.
	 */
	private static function signs_in( object $row ): bool {
		if ( isset( $row->discoverable ) && null !== $row->discoverable && 0 === (int) $row->discoverable ) {
			return false;
		}

		return self::is_usable( (int) $row->site_id, (string) $row->rp_id );
	}

	/** Add and remove share one account claim, including requests through different subsites. */
	private static function mutation_claim( int $user_id, bool $release = false ): bool {
		if ( is_multisite() ) { switch_to_blog( (int) get_main_site_id( get_main_network_id() ) ); }
		try {
			if ( $release ) { Claim::release( 'pkadd_' . $user_id ); return true; }
			return Claim::claim( 'pkadd_' . $user_id, 30 );
		} finally {
			if ( is_multisite() ) { restore_current_blog(); }
		}
	}

	private static function busy(): \WP_Error {
		return new \WP_Error( 'bettershield_passkey_busy', __( 'Another passkey change is still finishing. Try again in a moment.', 'bettershield' ), array( 'status' => 409 ) );
	}

	private static function verification_unavailable(): \WP_Error {
		return new \WP_Error( 'bettershield_passkey_storage', __( 'Passkey records could not be checked, so nothing was changed. Try again after the site finishes updating.', 'bettershield' ), array( 'status' => 503 ) );
	}

	/**
	 * Whether anybody holds a credential a browser here would offer.
	 *
	 * Asked before the sign-in button is drawn, and deliberately not per
	 * account: the sign-in form does not know who is standing in front of it,
	 * and asking would mean telling an anonymous visitor which accounts have
	 * one.
	 */
	public static function any_enrolled(): bool {
		global $wpdb;

		/*
		 * The distinct pairs rather than the rows: what decides the answer is
		 * the relying party of each generation and the site it came from.
		 * Bounded, because this runs on every render of the sign-in page.
		 *
		 * Only the pairs that can be usable here: this relying party, or none
		 * recorded, which a row from before the column was kept still
		 * resolves by its site. On a network every site with a passkey adds a
		 * pair of its own, and asking the first fifty in no order left a site
		 * at its own domain without its button once fifty others existed.
		 * Those under this relying party come first, then this site's own.
		 */
		$rp_id = Manager::rp_id();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$pairs = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT DISTINCT site_id, rp_id FROM %i WHERE ' . self::account_where() . " AND rp_id IN ( %s, '' ) ORDER BY ( rp_id = %s ) DESC, ( site_id = %d ) DESC LIMIT %d",
				Schema::table( 'passkeys' ),
				$rp_id,
				$rp_id,
				is_multisite() ? get_current_blog_id() : 0,
				50
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( is_array( $pairs ) ? $pairs : array() as $pair ) {
			if ( self::is_usable( (int) $pair->site_id, (string) $pair->rp_id ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * How many of these accounts hold at least one usable passkey, in one
	 * query.
	 *
	 * The per-account counter above answers a different question and is right
	 * for one account; asked in a loop it is a query per account, which is how
	 * a settings panel came to cost six hundred of them.
	 *
	 * @param array<int, int> $user_ids
	 */
	public static function count_enrolled_among( array $user_ids ): int {
		global $wpdb;

		$ids = array_values( array_unique( array_filter( array_map( 'intval', $user_ids ) ) ) );

		if ( array() === $ids ) {
			return 0;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		// A key the browser said needs a username never signs anybody in here.
		$discoverable = Schema::ready( 'passkey_discoverable' ) ? ' AND ( discoverable IS NULL OR discoverable <> 0 )' : '';

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT DISTINCT user_id, site_id, rp_id FROM %i WHERE ' . self::account_where() . $discoverable . ' AND user_id IN ('
					. implode( ',', array_fill( 0, count( $ids ), '%d' ) )
					. ')',
				array_merge( array( Schema::table( 'passkeys' ) ), $ids )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$enrolled = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			if ( self::is_usable( (int) $row->site_id, (string) $row->rp_id ) ) {
				$enrolled[ (int) $row->user_id ] = true;
			}
		}

		return count( $enrolled );
	}

	/**
	 * @param bool|null $discoverable Whether the browser reported the key as able to sign in without a username; null where it did not say.
	 * @return true|\WP_Error
	 */
	public static function add( int $user_id, string $credential_id, string $public_key, int $algorithm, int $sign_count, string $transports, string $label, bool $user_verified = false, ?bool $discoverable = null ) {
		global $wpdb;

		/*
		 * The limit is counted and then inserted against, and nothing in the
		 * table constrains rows per account — the only unique index is on the
		 * credential id. So two registrations arriving together both counted
		 * one below the limit and both stored a row. Held for the count and the
		 * insert together, the way the challenge above already is.
		 */
		if ( ! Schema::ready( 'passkey_verification' ) ) { return self::verification_unavailable(); }
		if ( ! self::mutation_claim( $user_id ) ) { return self::busy(); }

		try {
			$user = get_userdata( $user_id );
			// Recheck inside the same claim as removal: a verified key may have
			// been removed while this browser was completing registration.
			if ( ! $user_verified && $user instanceof \WP_User && Policy::instance()->applies_to( $user ) && 0 === self::count_verified_for_user( $user_id ) ) {
				return new \WP_Error( 'bettershield_passkey_verification_needed', __( 'Add a passkey that checks your fingerprint, face or PIN before adding a touch-only key.', 'bettershield' ), array( 'status' => 400 ) );
			}
			if ( self::count_for_user( $user_id ) >= self::MAX_PER_USER ) {
				return new \WP_Error(
					'bettershield_passkey_limit',
					sprintf(
						/* translators: %d: the maximum number of passkeys per account. */
						__( 'This account already has %d passkeys, the limit. Remove one before adding another.', 'bettershield' ),
						self::MAX_PER_USER
					),
					array( 'status' => 409 )
				);
			}

			/*
			 * The unique index is being used as a check here, and the answer
			 * it gives is an ordinary one a person reads — a device already
			 * enrolled, offered again. Left unsuppressed, every one of those
			 * writes a database error into the log, which is more common on a
			 * host whose sites share their credentials: the same device
			 * offered on a second site is the expected way to meet it.
			 */
			$was_suppressed = $wpdb->suppress_errors( true );

			$row = array(
				'site_id'       => Schema::site_id( 'passkeys' ),
				'user_id'       => $user_id,
				'credential_id' => $credential_id,
				'public_key'    => $public_key,
				'algorithm'     => $algorithm,
				'sign_count'    => max( 0, $sign_count ),
				'user_verified' => $user_verified ? 1 : 0,
				// Client-supplied: the spec names a closed set, but nothing
				// obliges a browser to send one of them.
				'transports'    => Text::clip( $transports, 191 ),
				// The column counts characters, not bytes: a byte-wise cut of
				// a name in a non-Latin script would store a broken sequence.
				'label'         => Text::clip( $label, 191 ),
				// What the browser was asked for, recorded because it cannot
				// be changed afterwards and a later read has no other way of
				// knowing which generation this row belongs to.
				'rp_id'         => Manager::rp_id(),
					'created_at'    => self::now(),
			);

			// Recorded where the column exists. Without it the row is written
			// as an older one would be: unknown, and counted.
			if ( null !== $discoverable && Schema::ready( 'passkey_discoverable' ) ) {
				$row['discoverable'] = $discoverable ? 1 : 0;
			}

			$inserted = $wpdb->insert( Schema::table( 'passkeys' ), $row );

			$wpdb->suppress_errors( $was_suppressed );

			if ( ! $inserted ) {
				// The unique index is what makes this reachable: the same key
				// enrolled twice. Reported rather than silently updated, because a
				// credential already on record belongs to whoever holds it.
				return self::already_registered( $credential_id );
			}

			return true;
		} finally {
			// Released on every path, unlike the challenge claim: this one
			// bounds one registration at a time rather than spending anything,
			// so a refused attempt must leave the next one free to try.
			self::mutation_claim( $user_id, true );
		}
	}

	/**
	 * The refusal for a credential already on record, naming where it was
	 * enrolled.
	 *
	 * Where the credentials of a host are shared, "already registered" on its
	 * own sends somebody looking through a list that does not hold it. The
	 * site it was enrolled on is the one place they can.
	 */
	private static function already_registered( string $credential_id ): \WP_Error {
		$site = self::site_of_credential( $credential_id );

		if ( null === $site || ! is_multisite() || $site === (int) get_current_blog_id() || 0 === $site ) {
			return new \WP_Error(
				'bettershield_passkey_exists',
				__( 'That passkey is already registered on this site.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$name = get_blog_option( $site, 'blogname', '' );
		$name = is_string( $name ) && '' !== $name ? wp_specialchars_decode( $name, ENT_QUOTES ) : (string) $site;

		return new \WP_Error(
			'bettershield_passkey_exists',
			sprintf(
				/* translators: %s: the name of the site the passkey was enrolled on. */
				__( 'That passkey is already registered on %s and works on every site here.', 'bettershield' ),
				$name
			),
			array( 'status' => 409 )
		);
	}

	/**
	 * Which site a credential was enrolled on, or null if it is not on record.
	 */
	private static function site_of_credential( string $credential_id ): ?int {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$site = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT site_id FROM %i WHERE ' . self::account_where() . ' AND credential_id = %s',
				Schema::table( 'passkeys' ),
				$credential_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return null === $site ? null : (int) $site;
	}

	/**
	 * Record a successful use, and the counter that came with it. The
	 * counter is monotonic at the write itself: whatever the caller's guard
	 * decided, this column never goes backwards — a lower value written even
	 * once would disarm the clone check for the credential's whole life.
	 */
	public static function mark_used( int $id, int $sign_count, bool $user_verified = false ): void {
		global $wpdb;
		$verification = $user_verified && Schema::ready( 'passkey_verification' ) ? ', user_verified = 1' : '';

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET sign_count = GREATEST( sign_count, %d ), last_used_at = %s' . $verification . ' WHERE ' . self::account_where() . ' AND id = %d',
				Schema::table( 'passkeys' ),
				max( 0, $sign_count ),
				self::now(),
				$id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	}

	/**
	 * Remove one, but only from the account that owns it.
	 *
	 * Not scoped to the site the row was enrolled on: the panel lists the
	 * account's credentials wherever they were made, and a list offering a
	 * Remove button that cannot remove is worse than no button.
	 */
	public static function remove( int $user_id, int $id ): bool {
		return true === self::remove_checked( $user_id, $id );
	}

	/** @return true|\WP_Error Keep another verified way in when a passkey-only account retains credentials. */
	public static function remove_checked( int $user_id, int $id ) {
		global $wpdb;
		if ( ! Schema::ready( 'passkey_verification' ) ) { return self::verification_unavailable(); }
		if ( ! self::mutation_claim( $user_id ) ) { return self::busy(); }
		try {
			$rows = self::rows_for_user( $user_id );
			if ( '' !== $wpdb->last_error ) { return self::verification_unavailable(); }
			$target = null; $remaining = 0; $verified = 0;
			foreach ( $rows as $row ) {
				if ( (int) $row->id === $id ) { $target = $row; continue; }
				if ( self::signs_in( $row ) ) {
					++$remaining;
					if ( 1 === (int) $row->user_verified ) { ++$verified; }
				}
			}
			if ( null === $target ) { return new \WP_Error( 'bettershield_passkey_unknown', __( 'That passkey is not on this account.', 'bettershield' ), array( 'status' => 404 ) ); }
			$user = get_userdata( $user_id );
			/**
			 * Whether this person may remove their own passkey. Counted while
			 * holding the account claim, so a second removal cannot reuse it.
			 * @param bool $allowed Whether removal is allowed.
			 * @param \WP_User $user The account.
			 * @param int $remaining Credentials held before this removal.
			 */
			if ( $user instanceof \WP_User && ! apply_filters( 'bettershield_passkey_self_remove_allowed', true, $user, count( $rows ) ) ) {
				return new \WP_Error( 'bettershield_passkey_required_by_policy', __( 'Your role requires a passkey, so the last one cannot be removed. Add another first, or ask an administrator.', 'bettershield' ), array( 'status' => 403 ) );
			}
			if ( $user instanceof \WP_User && Policy::instance()->applies_to( $user ) && $remaining > 0 && 0 === $verified && ( null === $target->user_verified || 1 === (int) $target->user_verified ) && self::signs_in( $target ) ) {
				return new \WP_Error( 'bettershield_passkey_verified_required', __( 'Removing this would leave no passkey that checks your fingerprint, face or PIN. Add one, or verify with another passkey first.', 'bettershield' ), array( 'status' => 409 ) );
			}

			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
			$deleted = $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE ' . self::account_where() . ' AND id = %d AND user_id = %d',
					Schema::table( 'passkeys' ),
					$id,
					$user_id
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			return 1 === $deleted ? true : self::verification_unavailable();
		} finally { self::mutation_claim( $user_id, true ); }
	}

	/**
	 * Remove one passkey from an account on somebody else's say, as an
	 * administrator does: no proof from the holder, and none of the
	 * holder's own limits, which protect a person removing their own.
	 * Only from the account that owns it.
	 */
	public static function remove_for_account( int $user_id, int $id ): bool {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE ' . self::account_where() . ' AND id = %d AND user_id = %d',
				Schema::table( 'passkeys' ),
				$id,
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return 1 === $deleted;
	}

	/**
	 * Remove every credential an account holds, and say how many there were.
	 *
	 * For an account that is going away: what is left otherwise is a row
	 * naming a user id the site no longer has, and a credential the person
	 * still holds on a device.
	 */
	public static function forget_user( int $user_id ): int {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- account_where() is a literal or a site predicate of integers assembled by Schema::site_where(); nothing from a request reaches the string.
		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE ' . self::account_where() . ' AND user_id = %d',
				Schema::table( 'passkeys' ),
				$user_id
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return is_numeric( $deleted ) ? (int) $deleted : 0;
	}

	private static function now(): string {
		return ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s.v' );
	}
}
