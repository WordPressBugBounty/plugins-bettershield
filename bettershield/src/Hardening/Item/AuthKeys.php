<?php
/**
 * Hardening item: strengthen and rotate the authentication keys.
 *
 * WordPress signs every login cookie and every nonce with the keys and salts
 * in wp-config.php. Two things go wrong with them in practice: they are left
 * at the sample values, so core falls back to salts stored in the database;
 * and they are never rotated, so a copy taken once is good forever.
 *
 * Rewriting the constants in wp-config.php is the conventional fix and the
 * wrong one here. A define() cannot be overridden by a later define(), so a
 * marked block cannot change a key that is already set — only editing the
 * original lines would, and those lines are not ours to rewrite. Instead this
 * item mixes a plugin-held secret into every key WordPress derives, through
 * the `salt` filter core provides for exactly this. The effective key becomes
 * a function of both the constant on disk and the secret in the database, so
 * an attacker needs both, and rotating the secret rotates every key at once.
 * The constants in wp-config.php are never touched.
 *
 * Applying, rotating and reverting all end every session the retired key was
 * signing — with one exception, minted in the same request: the administrator
 * who made the change from a signed-in browser is handed a session under the
 * key that now exists. A change made without one carries nobody over. This
 * item writes no undo row, because the prior value of a secret is a key and no
 * key is ever stored, so an owner signed out by their own press would have
 * nothing to press to get back. The toggle says what will happen first, and
 * the recovery link is shown beside it, because that is the moment someone
 * might need it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AuthKeys {

	/**
	 * The plugin-held secret. Autoloaded on a single site, because it is read
	 * before init on every request that authenticates.
	 *
	 * On a network the same name holds the secret in the network's options
	 * instead. A sign-in cookie there is issued for the whole network, so the
	 * key that signs it has to be the same on every site: kept per site it was
	 * a different key per site — sign in on one, arrive at the next signed
	 * out, go back and be signed in again, on every crossing, with nothing
	 * said. A network option has no autoload flag, so it is a row read on the
	 * first ask of a request rather than a free one; that is the price of a
	 * key the network can share, and it is paid once.
	 */
	public const OPTION = 'bettershield_auth_secret';

	/**
	 * The account a key change in this request carried over, or 0. The
	 * hand-off retires the session the request arrived with, so read again
	 * after it, the request's own cookie names a session that is gone, and
	 * the answer to the change said "yours included" beside "yours was kept".
	 */
	private static int $carried = 0;

	/**
	 * The secret in force here, from wherever this installation keeps it.
	 */
	public static function secret(): string {
		if ( ! is_multisite() ) {
			return (string) get_option( self::OPTION, '' );
		}

		$secret = get_network_option( null, self::OPTION, null );

		/*
		 * Absent rather than empty, which is what a site that has just become
		 * a network looks like: nothing has seeded the shared secret yet, and
		 * the key that site has been signing its cookies with is sitting in
		 * its own options. It is promoted here rather than replaced, or
		 * turning a site into a network would sign every account out at that
		 * moment with nothing said. Once, because this writes what it read.
		 */
		if ( null === $secret ) {
			$secret = (string) get_blog_option( get_main_site_id(), self::OPTION, '' );

			update_network_option( null, self::OPTION, $secret );
		}

		return (string) $secret;
	}

	/**
	 * Store the secret where this installation keeps it.
	 */
	private static function store_secret( string $value ): bool {
		if ( is_multisite() ) {
			return (bool) update_network_option( null, self::OPTION, $value );
		}

		return update_option( self::OPTION, $value, true );
	}

	/**
	 * The item is a site's switch, and on a network the thing it switches is
	 * not the site's to switch.
	 *
	 * Rotating ends every session on every site of the network at once, so it
	 * is offered from the network dashboard behind the network's own
	 * permission rather than from any one site's hardening screen. The sentence
	 * says where to go instead of leaving a toggle that would reach further
	 * than the screen it sits on.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( is_multisite() ) {
			return array(
				'available' => false,
				'reason'    => 'network_admin',
				'note'      => __( 'On a network, rotating the shared sign-in key ends every session on every site. Use the network dashboard.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * Rotate the secret the whole network shares.
	 *
	 * Called only by the hardening manager's network path, which holds the
	 * state mutex, performs the hand-off that keeps the acting administrator
	 * signed in — `hand_off_session()` below, the same one this item's own
	 * single-site paths use — and ends everything else. Nothing here writes an
	 * event: the caller records one on the main site, beside the sweep it can
	 * count.
	 *
	 * @return true|\WP_Error
	 */
	public static function rotate_network() {
		if ( ! is_multisite() ) {
			return new \WP_Error(
				'bettershield_not_a_network',
				__( 'This is a single site. Rotate the key under Protection › Login & Access.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$owed = \BetterShield\Events\Seal::owed_before_rekey();

		if ( ! update_network_option( null, self::OPTION, self::fresh_secret() ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'The keys were not rotated: the secret could not be stored.', 'bettershield' ), array( 'status' => 500 ) );
		}

		// Mixing has to be on for the rest of this request as well. The
		// hand-off that follows re-signs the acting administrator's cookie,
		// and a cookie signed before the filter is hooked is signed with the
		// key that was just retired.
		add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );

		// An owed log reseal's proof is made with these keys.
		\BetterShield\Events\Seal::resign_owed( $owed );

		return true;
	}

	/**
	 * Registered from the plugin's own load, before anything else can ask for
	 * a salt. Left to enforce() it went on at plugins_loaded, and a drop-in or
	 * an early plugin that resolved a salt first got the unmixed one — which
	 * is a session that looks signed out on some requests and not others,
	 * depending on which other plugins a site happens to run.
	 *
	 * Costs one autoloaded option read on sites where the item is off — which
	 * is only true because the option is seeded and autoloaded whether the item
	 * was ever applied or not (`Support\HotOptions`). Absent, this same line
	 * was an uncached query on every front-end page view of every site that had
	 * never turned the fix on.
	 */
	public static function register_early(): void {
		if ( '' === self::secret() ) {
			return;
		}

		add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );
	}

	/**
	 * @param array<string, mixed> $state Unused; the secret is read from its option.
	 */
	public static function enforce( array $state ): void {
		add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );
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

		return false !== has_filter( 'salt', array( self::class, 'mix' ) );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		remove_filter( 'salt', array( self::class, 'mix' ), 10 );
	}

	/**
	 * Generate the secret. Every session the retired key was signing ends
	 * here, and the administrator who applied it is carried into a new one.
	 *
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		$owed = \BetterShield\Events\Seal::owed_before_rekey();

		if ( ! self::store_secret( self::fresh_secret() ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'The change was not applied: the secret could not be stored.', 'bettershield' ) );
		}

		// Mixing has to be on for the rest of this request as well. The
		// hand-off below signs the acting administrator a fresh cookie, and a
		// cookie signed before the filter is hooked is signed with the key
		// that was just retired — which the manager hooks only once this has
		// returned.
		add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );

		// An owed log reseal's proof is made with these keys.
		\BetterShield\Events\Seal::resign_owed( $owed );

		return array(
			'tokens' => array(),
			'notes'  => array( self::sweep_note( self::hand_off_and_sweep() ) ),
		);
	}

	/**
	 * Remove the secret. The keys go back to what wp-config.php alone
	 * derives, which is a different value again — so revert ends every session
	 * as well, and carries the acting administrator across exactly as applying
	 * does.
	 *
	 * @param array<string, mixed> $state Unused.
	 * @return true|\WP_Error
	 */
	public static function revert( array $state ) {
		// Emptied rather than deleted. An absent option is not free: it is a
		// lookup on every front-end page view, on the line that reads it before
		// anything can ask for a salt. Deleting therefore handed a site that
		// reverted this item the exact cost the item's absence was supposed to
		// mean. Empty reads the same to every caller — `register_early()` tests
		// for `''` — and uninstall still removes the row.
		$owed = \BetterShield\Events\Seal::owed_before_rekey();

		self::store_secret( '' );

		// Nothing to hook or unhook here: with the secret empty, mixing is the
		// identity, so the key back in force is the one wp-config.php alone
		// derives whether the filter is still on or not. The manager takes it
		// off once this has returned.
		\BetterShield\Events\Seal::resign_owed( $owed );
		self::hand_off_and_sweep();

		return true;
	}

	/**
	 * @return array<int, array{key: string, label: string, description: string}>
	 */
	public static function actions(): array {
		return array(
			array(
				'key'         => 'rotate',
				'label'       => __( 'Sign Out All Devices', 'bettershield' ),
				'description' => self::carries_session()
					? __( 'Generates a new secret. Every other session is signed out; yours is kept.', 'bettershield' )
					: __( 'Generates a new secret. Every session is signed out, yours included.', 'bettershield' ),
			),
		);
	}

	/**
	 * @param array<string, mixed> $state
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function act( string $action, array $state ) {
		if ( 'rotate' !== $action ) {
			return new \WP_Error( 'bettershield_unknown_action', __( 'This item has no such action.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$owed = \BetterShield\Events\Seal::owed_before_rekey();

		if ( ! self::store_secret( self::fresh_secret() ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'The keys were not rotated: the secret could not be stored.', 'bettershield' ), array( 'status' => 500 ) );
		}

		// Idempotent, and needed for the same reason the network path re-hooks
		// it: the hand-off below signs a cookie, and it has to be signed with
		// the key that now exists rather than the one just retired.
		add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );

		// An owed log reseal's proof is made with these keys.
		\BetterShield\Events\Seal::resign_owed( $owed );

		$swept = self::hand_off_and_sweep();
		$when  = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );

		$note = $swept['handed_off']
			? sprintf(
				/* translators: %s: date and time. */
				__( 'Keys last rotated %s, signing out every session but yours.', 'bettershield' ),
				$when
			)
			: sprintf(
				/* translators: %s: date and time. */
				__( 'Keys last rotated %s, signing out every session.', 'bettershield' ),
				$when
			);

		Writer::instance()->record(
			'keys_rotated',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'auth_keys',
				'context'     => array(
					'handed_off' => $swept['handed_off'],
					'ended'      => $swept['ended'],
				),
			)
		);

		return array(
			'rotated'    => true,
			'handed_off' => $swept['handed_off'],
			'ended'      => $swept['ended'],
			// No ledger row for this one. The prior value of the secret is a
			// key, and no key is ever stored — so there is nothing to put
			// back, and a row carrying only the note below would name itself
			// an undo of a rotation it could not reverse. Deriving a different
			// key again is the way back, which the description says.
			'ledger'     => false,
			'state'      => array(
				'notes' => array( $note ),
			),
		);
	}

	/**
	 * Carry the administrator who moved the key into a session under the key
	 * that now exists, then end every session the retired one was signing.
	 *
	 * One routine for all three ways a single site moves the key — applying,
	 * rotating and reverting — because all three move it, and a copy of this
	 * per path is a path that quietly stops handing anybody over.
	 *
	 * @return array{handed_off: bool, ended: int}
	 */
	private static function hand_off_and_sweep(): array {
		// WP-CLI, a scheduled run, an assistant's call, a request nobody is
		// signed in for: there is no session to carry, so everybody goes and
		// the notes say so rather than promising the reader theirs survived.
		$keeping = self::carries_session() ? get_current_user_id() : 0;
		$token   = 0 === $keeping ? '' : self::hand_off_session( $keeping );

		if ( '' !== $token ) {
			self::$carried = $keeping;
		}

		$swept = \BetterShield\Login\Sessions::instance()->end_here_for_rotation( $keeping, $token, 'key_rotation' );

		return array(
			'handed_off' => '' !== $token,
			'ended'      => $swept['ended'],
		);
	}

	/**
	 * Whether this request came with a live session of the account acting in
	 * it, which is the only session a key change can carry over.
	 *
	 * Carrying one over means answering this request with new sign-in
	 * cookies. A request that came without a session — an assistant's call
	 * on its bearer credential, WP-CLI with --user — has no browser to take
	 * them: the cookies would go to whatever made the call, as a full
	 * administrator login. Asked of the session store rather than of the
	 * cookie's signature, so the answer holds after the key has moved.
	 *
	 * Nor does a call on an assistant's credential, even one that brings the
	 * administrator's browser cookies along, as a client on the site's own
	 * address does: the new cookies are held back from it, so the browser was
	 * signed out after being told it was kept.
	 */
	public static function carries_session(): bool {
		if ( null !== \BetterShield\Mcp\Server::current_scope() ) {
			return false;
		}

		$user_id = get_current_user_id();

		// Carried over already, in this request: its session is the new one.
		if ( $user_id > 0 && self::$carried === $user_id ) {
			return true;
		}

		$token   = (string) wp_get_session_token();

		return $user_id > 0 && '' !== $token && \WP_Session_Tokens::get_instance( $user_id )->verify( $token );
	}

	/**
	 * Mint one account a session under the key that now exists.
	 *
	 * The token is captured from the cookie hook rather than guessed at,
	 * because the sweep that follows has to know exactly which one to spare —
	 * and the account's newest session is not something core will name back to
	 * a caller.
	 *
	 * @return string The token to spare, or an empty string when none was minted.
	 */
	public static function hand_off_session( int $user_id, bool $remember = false ): string {
		$minted = '';

		$capture = static function ( $cookie, $expire, $expiration, $captured_id, $scheme, $token ) use ( &$minted ): void {
			$minted = (string) $token;
		};

		add_action( 'set_logged_in_cookie', $capture, 10, 6 );
		// The session minted in place of this one is the same sign-in.
		\BetterShield\Login\Sessions::carry_current_origin( $user_id );
		wp_set_auth_cookie( $user_id, $remember );
		remove_action( 'set_logged_in_cookie', $capture, 10 );

		return $minted;
	}

	/**
	 * Carry the administrator who switched this plugin off, or on, into a
	 * session under the key that applies once it has.
	 *
	 * The secret is mixed in by this plugin's own filter, so it applies while
	 * the plugin runs and not otherwise: switching the plugin off ends every
	 * session the mixed key signed, and switching it on ends every one the
	 * plain key signed. The administrator who pressed it went with everybody
	 * else, sent to the sign-in page with no warning. Their own session is
	 * carried over, as a rotation carries it; the Plugins screen says
	 * beforehand that everybody else's is not.
	 *
	 * @param bool $mixing Whether the key that applies next is the mixed one.
	 * @return bool Whether a session was carried over.
	 */
	public static function hand_off_for_switch( bool $mixing ): bool {
		if ( '' === self::secret() || ! self::carries_session() ) {
			return false;
		}

		if ( $mixing ) {
			add_filter( 'salt', array( self::class, 'mix' ), 10, 2 );
		} else {
			remove_filter( 'salt', array( self::class, 'mix' ), 10 );
		}

		return '' !== self::hand_off_session( get_current_user_id() );
	}

	/**
	 * Said on the Plugins screen while a secret is in force, beside the link
	 * that would switch it off: nothing else says, before the click, that
	 * everybody else will be signed out.
	 *
	 * Only where the switch carries the presser over: a single site, and the
	 * network screen. A subsite switching off its own copy leaves the key in
	 * force on every other site that runs it.
	 *
	 * @param mixed $meta
	 * @param mixed $file
	 * @return mixed
	 */
	public static function row_meta( $meta, $file ) {
		if ( ! is_array( $meta ) || plugin_basename( BETTERSHIELD_FILE ) !== $file || '' === self::secret() ) {
			return $meta;
		}

		if ( is_multisite() && ! is_network_admin() ) {
			return $meta;
		}

		$meta[] = esc_html__( 'Deactivating BetterShield signs everyone else out, because it adds to how WordPress keeps people signed in. You stay signed in.', 'bettershield' );

		return $meta;
	}

	/**
	 * What a key change tells the owner it did, which depends on whether there
	 * was anybody to carry over.
	 *
	 * @param array{handed_off: bool, ended: int} $swept
	 */
	private static function sweep_note( array $swept ): string {
		if ( $swept['handed_off'] ) {
			return __( 'Every other session was signed out; yours was kept.', 'bettershield' );
		}

		return __( 'Every session was signed out.', 'bettershield' );
	}

	/**
	 * Mix the secret into a derived key. Fires for every scheme WordPress
	 * asks for — auth, secure_auth, logged_in, nonce — and yields nothing
	 * recognizable as either input.
	 */
	public static function mix( string $salt, string $scheme ): string {
		$secret = self::secret();

		if ( '' === $secret ) {
			return $salt;
		}

		return hash_hmac( 'sha256', $scheme . '|' . $salt, $secret );
	}

	private static function fresh_secret(): string {
		return bin2hex( random_bytes( 32 ) );
	}
}
