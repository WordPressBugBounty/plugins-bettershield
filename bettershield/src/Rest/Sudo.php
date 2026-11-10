<?php
/**
 * Ask for the password again before the defenses come down.
 *
 * The interactive guard fixed a specific hole: a credential exempt from the
 * sign-in gate could remove the protections it was exempt from. After that
 * fix, the underlying property is unchanged — **anything holding
 * `bettershield_manage` can still lower every defense on this site with no
 * further proof.** A browser session left open on a shared machine, a laptop
 * somebody walked away from, an XSS in an unrelated plugin.
 *
 * So the handful of actions that *remove* protection ask for the password
 * once, and then stop asking for a while. GitHub calls this sudo mode and the
 * shape is well understood by the people it protects.
 *
 * **It gates removal, never addition, and never a read.** Somebody hardening
 * a site in a hurry is not the threat, and a plugin that asked for a password
 * before every click would be turned off. The list is short on purpose: the
 * actions where being wrong means the site is less protected than the owner
 * believes.
 *
 * **It is never in the way of getting back in.** Safe mode stands it down
 * with everything else, and an account that has no password to re-enter —
 * signed in by a passkey alone — is not asked for one it does not have.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Rest;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sudo {

	/**
	 * How long one confirmation lasts.
	 *
	 * Long enough to finish a piece of work — reverting three items, importing
	 * a document, checking the result — without being asked again in the
	 * middle of it. Short enough that a machine left unlocked over lunch is
	 * not still confirmed when somebody sits down at it.
	 */
	public const WINDOW_SECONDS = 900;

	private const META = 'bettershield_sudo_until';

	/**
	 * The same window for an account that confirmed itself with one of its
	 * own passkeys. Kept apart, because a receipt saying a password was
	 * re-entered has to mean a password was re-entered.
	 */
	private const PASSKEY_META = 'bettershield_passkey_confirmed_until';

	/** Wrong answers allowed per account, and the window they are counted in. */
	private const MAX_ATTEMPTS   = 5;
	private const ATTEMPT_WINDOW = 5 * MINUTE_IN_SECONDS;

	/**
	 * Whether this request may perform an action that removes protection.
	 *
	 * `$for_network` is what a network route passes. The switch is a per-site
	 * option while a network request lands on whichever site answered it, so
	 * a network action asked the site of the moment and got a different answer
	 * depending on where the administrator came from. The confirmation itself
	 * needs no such flag: it is user metadata, which a network shares.
	 *
	 * @return true|\WP_Error
	 */
	public static function confirmed( bool $for_network = false ) {
		$user_id = get_current_user_id();

		if ( 0 === $user_id ) {
			return new \WP_Error( 'bettershield_not_signed_in', __( 'Sign in first.', 'bettershield' ), array( 'status' => 401 ) );
		}

		// Safe mode is the way back in, and nothing may stand in front of it.
		if ( SafeMode::is_active() ) {
			return true;
		}

		if ( ! self::required( $for_network ) ) {
			return true;
		}

		$window = get_user_meta( $user_id, self::META, true );

		if (
			is_array( $window )
			&& time() < (int) ( $window['until'] ?? 0 )
			&& hash_equals( (string) ( $window['session'] ?? '' ), self::session_mark() )
		) {
			return true;
		}

		return new \WP_Error(
			'bettershield_confirm_password',
			__( 'This removes a protection, so confirm your password. You will not be asked again for a while.', 'bettershield' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Whether this account actually typed its password inside the window.
	 *
	 * A narrower question than `confirmed()`, and the only one worth asking
	 * where the answer is recorded as proof rather than used as a gate.
	 * `confirmed()` answers true in two situations where nobody proved
	 * anything: the owner has the gate switched off, and safe mode is
	 * standing every protection down so that somebody locked out can get back
	 * in. Both are right for a gate and wrong for a receipt — a stamp saying a
	 * password was re-entered has to mean a password was re-entered.
	 */
	public static function password_confirmed_recently( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$window = get_user_meta( $user_id, self::META, true );

		return is_array( $window )
			&& time() < (int) ( $window['until'] ?? 0 )
			&& hash_equals( (string) ( $window['session'] ?? '' ), self::session_mark() );
	}

	/**
	 * Whether this account confirmed itself with one of its own passkeys
	 * inside the window, in this session.
	 */
	public static function passkey_confirmed_recently( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}

		$window = get_user_meta( $user_id, self::PASSKEY_META, true );

		return is_array( $window )
			&& time() < (int) ( $window['until'] ?? 0 )
			&& hash_equals( (string) ( $window['session'] ?? '' ), self::session_mark() );
	}

	/**
	 * Accept one of this account's own passkeys in place of a password it
	 * does not have, and open the window for changing its passkeys.
	 *
	 * Every attempt spends a challenge, and the challenges a connection may
	 * ask for are already capped, so wrong answers need no counter of their
	 * own here.
	 *
	 * @param array<string, mixed> $assertion What the browser returned.
	 * @return array{confirmed_until: int}|\WP_Error
	 */
	public static function confirm_passkey( array $assertion ) {
		$user = wp_get_current_user();

		if ( ! $user instanceof \WP_User || 0 === $user->ID ) {
			return new \WP_Error( 'bettershield_not_signed_in', __( 'Sign in first.', 'bettershield' ), array( 'status' => 401 ) );
		}

		$verified = \BetterShield\Passkeys\Manager::verify_confirmation( $user, $assertion );

		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		$until = time() + self::WINDOW_SECONDS;

		update_user_meta(
			$user->ID,
			self::PASSKEY_META,
			array(
				'until'   => $until,
				'session' => self::session_mark(),
			)
		);

		Writer::instance()->record(
			'sudo_confirmed',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => (int) $user->ID,
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array( 'with' => 'passkey' ),
			)
		);

		return array( 'confirmed_until' => $until );
	}

	/**
	 * Whether the owner switched the gate on. Distinct from required(),
	 * which also asks whether the current account can meet it.
	 */
	public static function enabled(): bool {
		return (bool) get_option( 'bettershield_sudo', false );
	}

	/**
	 * The same switch, read from the main site.
	 *
	 * What a network action is gated by has to be one answer for the network,
	 * and this option is per site. The main site's is the one the network
	 * administrator sets from the dashboard they manage the network with.
	 */
	public static function enabled_for_network(): bool {
		if ( ! is_multisite() ) {
			return false;
		}

		switch_to_blog( (int) get_main_site_id() );

		try {
			return self::enabled();
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * The owner's switch. Turning the gate off removes a protection, so the
	 * route that calls this asks for a signed-in session either way.
	 *
	 * The way back is written first, and a switch that cannot have one does
	 * not move: standing the gate down with nothing to put back is removing a
	 * protection nobody could later undo.
	 *
	 * @return true|\WP_Error
	 */
	public static function set_enabled( bool $enabled ) {
		$was  = self::enabled();
		$undo = \BetterShield\Undo\SettingsLedger::record( 'sudo', array( 'enabled' => $was ), array( 'enabled' => $enabled ) );

		if ( false === $undo ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( 'bettershield_sudo', $enabled ? '1' : '0', false );

		// Graded by direction, as the other protections' switches are: the gate
		// coming off reaches the instant path, and going on does not.
		Writer::instance()->record(
			'setting_changed',
			$was && ! $enabled ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => 'bettershield_sudo',
				'context'     => array( 'enabled' => $enabled ),
			)
		);

		return true;
	}

	/**
	 * Whether this site asks at all.
	 *
	 * Off by default. It is a real friction on a real workflow, and an owner
	 * who has not asked for it should not meet it after an update.
	 */
	public static function required( bool $for_network = false ): bool {
		if ( ! ( $for_network ? self::enabled_for_network() : self::enabled() ) ) {
			return false;
		}

		/*
		 * An account signed in by a passkey alone has no password to re-enter
		 * — asking for one it may never have set would be asking it to do
		 * something impossible in order to manage its own site. That is an
		 * account with no stored password at all, and one whose password the
		 * sign-in refuses. A stored hash alone says little: WordPress keeps
		 * one for every account it creates, so asking only that spared nobody
		 * who signs in by passkey.
		 */
		$user = wp_get_current_user();

		return $user->exists()
			&& '' !== (string) $user->user_pass
			&& ! \BetterShield\Passkeys\Policy::instance()->refuses_password( $user );
	}

	/**
	 * Accept a password and open the window.
	 *
	 * @return array{confirmed_until: int}|\WP_Error
	 */
	public static function confirm( string $password ) {
		$user = wp_get_current_user();

		if ( ! $user instanceof \WP_User || 0 === $user->ID ) {
			return new \WP_Error( 'bettershield_not_signed_in', __( 'Sign in first.', 'bettershield' ), array( 'status' => 401 ) );
		}

		/*
		 * Rate limited per account. This endpoint takes a password and says
		 * whether it was right, which is a guessing oracle if it is left
		 * unbounded — and the guesser is already signed in, so the sign-in
		 * lockout never sees them.
		 *
		 * Counted per site on a network, so the effective budget against one
		 * network-global password is this cap times the number of subsites.
		 * That is the settled trade: counting across a network would mean
		 * shared state, and one subsite's traffic locking an account out on
		 * every other. The sign-in and backup-code counters carry the same
		 * shape for the same reason.
		 */
		$attempts = 'sudo_tries_' . $user->ID;

		// Reserve the attempt atomically before invoking the password oracle.
		$tries = Claim::bump_or_fail( $attempts, self::ATTEMPT_WINDOW );

		/*
		 * A ceiling that cannot be read is not a ceiling with room under it.
		 * The right password is refused with the wrong ones, because what
		 * stands between a stolen session and every protection on this site is
		 * the limit rather than the password — and the limit is the part that
		 * stopped working. Nothing is changed either way, and the message says
		 * so and names the way back in.
		 */
		if ( null === $tries ) {
			Writer::instance()->record(
				'sudo_refused',
				Writer::SEVERITY_HIGH,
				array(
					'actor_type'  => 'user',
					'actor_id'    => (int) $user->ID,
					'object_type' => 'user',
					'object_id'   => (string) $user->ID,
					'context'     => array( 'reason' => 'records_unreadable' ),
				)
			);

			return new \WP_Error(
				'bettershield_records_unreadable',
				__( 'Your password cannot be confirmed right now; nothing was changed. If you are locked out, use this site’s recovery link.', 'bettershield' ),
				array( 'status' => 503 )
			);
		}

		if ( $tries > self::MAX_ATTEMPTS ) {
			return new \WP_Error(
				'bettershield_too_many',
				__( 'Too many attempts. Wait a few minutes and try again.', 'bettershield' ),
				array( 'status' => 429 )
			);
		}

		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {

			Writer::instance()->record(
				'sudo_refused',
				Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'user',
					'actor_id'    => (int) $user->ID,
					'object_type' => 'user',
					'object_id'   => (string) $user->ID,
				)
			);

			return new \WP_Error( 'bettershield_wrong_password', __( 'That password did not match.', 'bettershield' ), array( 'status' => 403 ) );
		}

		/*
		 * Cleared where it is kept. The counter moved into the claims table
		 * and this line did not follow it, so `delete_transient()` was
		 * removing a key nothing had ever written — and the count survived
		 * every successful confirmation. Four slips, the right password, and
		 * one slip later the gate answered 429 to the person holding the
		 * correct password. The limit is here because the endpoint is a
		 * guessing oracle; it was never meant to punish a right answer.
		 */
		Claim::release( $attempts );

		$until = time() + self::WINDOW_SECONDS;

		// Keyed to the session that typed the password: "once per session"
		// means a fresh sign-in inside the window is asked again, and a
		// session that ends takes its confirmation with it.
		update_user_meta(
			$user->ID,
			self::META,
			array(
				'until'   => $until,
				'session' => self::session_mark(),
			)
		);

		Writer::instance()->record(
			'sudo_confirmed',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'user',
				'actor_id'    => (int) $user->ID,
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
			)
		);

		return array( 'confirmed_until' => $until );
	}

	/**
	 * An opaque name for the current session, and never the token itself:
	 * this value sits in user meta, and meta is not where a live credential
	 * or anything derived plainly from one belongs.
	 */
	private static function session_mark(): string {
		return hash_hmac( 'sha256', 'sudo|' . (string) wp_get_session_token(), \BetterShield\Support\ClientIp::signing_secret() );
	}

	/**
	 * End the window early — signing out, or changing the password, should not
	 * leave a confirmation standing behind them.
	 */
	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
		delete_user_meta( $user_id, self::PASSKEY_META );
	}

	public static function register(): void {
		add_action(
			'clear_auth_cookie',
			static function (): void {
				self::forget( get_current_user_id() );
			}
		);

		add_action(
			'after_password_reset',
			static function ( $user ): void {
				if ( $user instanceof \WP_User ) {
					self::forget( (int) $user->ID );
				}
			}
		);
	}
}
