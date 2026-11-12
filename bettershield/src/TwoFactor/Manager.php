<?php
/**
 * Two-factor enrollment lifecycle and the login gate.
 *
 * The lifecycle exists to make one promise — no sequence of enrollment
 * actions can lock out the enabling user — true by construction rather than
 * by luck.
 * Enforcement arms at exactly one moment: after the user has proved their
 * device generates valid codes (confirm) AND stated they stored their backup
 * codes (acknowledge). Every earlier state — a secret generated and
 * abandoned, a device confirmed and the codes never acknowledged — leaves
 * sign-in exactly as it was. There is no path onto the gate that did not
 * pass through both proofs.
 *
 * The gate is a second screen, not a field on the first. The password form
 * stays exactly what WordPress ships; when the password is right and the
 * account has a factor armed, the sign-in is parked and the browser is sent
 * to a screen that asks for the code (see LoginStep). One field there takes a
 * six-digit app code or an eight-digit backup code; their shapes are
 * disjoint, so nothing needs to be chosen. Interactive sign-ins are the only
 * gated surface — an application password IS a second factor (generated,
 * per-integration, revocable), so API requests it authenticates proceed,
 * which is what keeps existing integrations working the day 2FA turns on.
 * Password auth over XML-RPC for a 2FA user is refused with the reason and
 * the fix, because a gate that password-only XML-RPC walks around is not a
 * gate.
 *
 * The TOTP secret is stored in user meta in the clear, deliberately: it
 * must be readable to verify codes, an encryption key kept beside the data
 * it locks adds ceremony rather than protection, and deriving one from the
 * salts would break every enrollment the day the owner rotates keys — a
 * self-inflicted mass lockout. The audit's storage-format check covers the
 * database's own exposure honestly.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Manager {

	private const META_SECRET    = 'bettershield_totp_secret';
	private const META_PENDING   = 'bettershield_totp_pending';
	private const META_CONFIRMED = 'bettershield_totp_confirmed';
	private const META_LAST_STEP = 'bettershield_totp_last_step';

	/** This plugin's XML-RPC sign-in refusals, each of which names the fix. */

	private static ?Manager $instance = null;

	/**
	 * The user an application password authenticated in this request, if
	 * any — the signal that THAT user's sign-in must not meet the interactive
	 * gate. Bound to a user ID, never a bare flag: XML-RPC's system.multicall
	 * runs many sign-ins in one request, and a flag set by one account's
	 * application password must not wave through a different account's
	 * password-only sign-in later in the same call.
	 */
	private int $application_password_user = 0;

	/** Wrong backup-code guesses per account per hour before they stop being checked. */
	private const BACKUP_GUESS_CAP = 10;

	/**
	 * Wrong codes of any shape, per account, per hour.
	 *
	 * The cap lives here rather than on the sign-in screen because the screen
	 * is not the only caller: the REST routes that start, confirm, disable and
	 * reissue check a code too, and while the counter sat on the screen those
	 * routes could be asked an unlimited number of times. A limit only one
	 * caller consults is not a limit.
	 */
	public const WRONG_CODE_CAP = 10;

	/** The claim one confirm holds while it stages a set, keyed by account. */
	public const STAGE_CLAIM = '2fa_stage_';

	/**
	 * How long that claim stands if the request holding it dies. Staging is
	 * ten bcrypt hashes, well inside this.
	 */
	private const STAGE_CLAIM_TTL = 30;

	public static function instance(): Manager {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/** How long one account and source stay one row. */
	private const SKIPPED_WINDOW = 30 * DAY_IN_SECONDS;

	/** The account the gate let through in this request's current chain. */
	private int $passed_gate = 0;

	/**
	 * Clear per-request state. Production never needs this — the flag lives
	 * and dies with the request — but the test process is many requests in
	 * one lifetime.
	 */
	public function reset_request_state(): void {
		$this->application_password_user = 0;
		$this->passed_gate               = 0;
		LoginStep::instance()->reset_request_state();
	}

	public function register(): void {
		LoginStep::instance()->register();

		// Every authenticate chain starts clean: whatever an application
		// password established in an earlier chain of the same request (an
		// XML-RPC multicall) says nothing about this one.
		add_filter( 'authenticate', array( $this, 'begin_chain' ), 1, 1 );

		// Priority 40: after the password (20), the honeypot (25) and the
		// lockout gate (30) have all had their say.
		add_filter( 'authenticate', array( $this, 'gate' ), 40, 3 );

		// A session made some other way than through that gate.
		add_action( 'set_logged_in_cookie', array( $this, 'note_session_past_gate' ), 10, 4 );

		add_action(
			'application_password_did_authenticate',
			function ( $user ): void {
				$this->application_password_user = $user instanceof \WP_User ? (int) $user->ID : 0;
			}
		);

		// A right password refused here gets core's own "Incorrect username
		// or password." over XML-RPC, as a wrong one does: telling the two
		// apart there would confirm a guessed password for exactly the
		// accounts with a second factor or passkey-only sign-in.
	}

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function begin_chain( $user ) {
		$this->application_password_user = 0;
		$this->passed_gate               = 0;

		return $user;
	}

	/* ---- state ---------------------------------------------------------------- */

	public function enabled( int $user_id ): bool {
		return '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * @return array{enabled: bool, pending: bool, confirmed: bool, backup_remaining: int, password_turn_off: bool}
	 */
	public function status( int $user_id ): array {
		$enabled = $this->enabled( $user_id );

		return array(
			'enabled'           => $enabled,
			'pending'           => '' !== (string) get_user_meta( $user_id, self::META_PENDING, true ),
			'confirmed'         => '1' === get_user_meta( $user_id, self::META_CONFIRMED, true ),
			'backup_remaining'  => BackupCodes::remaining( $user_id ),
			// Whether this account's password turns its own factor off now:
			// only while safe mode is on, the way back for an account whose
			// phone and backup codes are both gone.
			'password_turn_off' => $enabled && SafeMode::is_active(),
		);
	}

	/* ---- enrollment ------------------------------------------------------------- */

	/**
	 * Begin enrollment: a fresh pending secret. Idempotent-by-replacement —
	 * starting again invalidates the earlier pending secret and nothing
	 * else. Enforcement is untouched.
	 *
	 * @return array{secret: string, uri: string}|\WP_Error
	 */
	public function start( \WP_User $user, string $current_code = '' ) {
		// Re-enrolling replaces the secret and the backup codes. On an
		// account that already has a working factor, that is exactly what an
		// intruder holding a session would want to do — so it needs the
		// factor it is about to replace.
		if ( $this->enabled( $user->ID ) ) {
			if ( ! self::offers_a_code( $current_code ) ) {
				return new \WP_Error(
					'bettershield_current_code_needed',
					__( 'Two-factor is already on. Setting it up again needs a current app code or an unused backup code.', 'bettershield' ),
					array( 'status' => 403 )
				);
			}

			$checked = $this->check_code( $user->ID, $current_code );

			// Not checked at all is not a wrong code, and says so.
			if ( is_wp_error( $checked ) ) {
				return $checked;
			}

			if ( true !== $checked ) {
				return new \WP_Error(
					'bettershield_current_code_needed',
					$this->wrong_code_message( (int) $user->ID, $current_code, __( 'That code does not match. Use a current app code or an unused backup code.', 'bettershield' ) ),
					array( 'status' => 403 )
				);
			}
		}

		$secret = Totp::generate_secret();

		update_user_meta( $user->ID, self::META_PENDING, $secret );
		delete_user_meta( $user->ID, self::META_CONFIRMED );
		BackupCodes::discard( $user->ID );

		return array(
			'secret' => $secret,
			'uri'    => Totp::enrollment_uri( $secret, $user->user_login, wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ) ),
		);
	}

	/**
	 * Prove the device: a valid code from the pending secret. On success a
	 * set of backup codes is generated and returned — the once they are
	 * visible. Enforcement is STILL off, and so is the new set: until the
	 * user says they have stored it, the codes they already hold are the
	 * ones that work.
	 *
	 * @return array{backup_codes: string[]}|\WP_Error
	 */
	public function confirm( \WP_User $user, string $code ) {
		$pending = (string) get_user_meta( $user->ID, self::META_PENDING, true );

		if ( '' === $pending ) {
			return new \WP_Error( 'bettershield_no_enrollment', __( 'Nothing is waiting to be confirmed. Start again.', 'bettershield' ), array( 'status' => 409 ) );
		}

		/*
		 * The pending secret is checked here rather than through
		 * accept_code(), which reads the armed one — so the cap is applied by
		 * hand rather than inherited.
		 *
		 * Every attempt counts, not only the wrong ones. A right answer here
		 * stages ten bcrypt hashes, and this route is open to any signed-in
		 * session; counting only the failures left the expensive path
		 * uncapped for a caller who holds the pending secret and can compute
		 * valid codes for it all day. Counted on a budget of its own, though:
		 * setting the factor up is not signing in, and it must not leave the
		 * account fewer sign-in codes for the hour.
		 */
		$allowed = self::within( Claim::bump_or_fail( self::confirm_key( $user->ID ), HOUR_IN_SECONDS ), self::WRONG_CODE_CAP );

		if ( null === $allowed ) {
			return $this->records_unreadable( (int) $user->ID );
		}

		if ( ! $allowed ) {
			return new \WP_Error( 'bettershield_2fa_capped', __( 'Too many code attempts in the last hour. Wait a while and try again.', 'bettershield' ), array( 'status' => 429 ) );
		}

		if ( null === Totp::verify( $pending, $code, time() ) ) {
			return new \WP_Error( 'bettershield_wrong_code', __( 'That code does not match. Try the code your app shows right now.', 'bettershield' ), array( 'status' => 400 ) );
		}

		/*
		 * A set already staged is the set the person is reading off the
		 * screen. There is no replay stamp on this check — the same code is
		 * accepted for its whole window — so a retried POST, a proxy repeating
		 * one, or a double-click staged a second set under them, and
		 * acknowledge() promoted the one they are not holding. That is exactly
		 * the outcome BackupCodes says must never happen: someone left with
		 * codes that stopped working and nobody telling them.
		 *
		 * The check and the write are two steps, so two requests arriving
		 * together both found nothing staged and both staged, each answering
		 * with its own set. The claim makes them one: the database admits one
		 * request to stage, and the other is told a set is already waiting.
		 */
		$already = new \WP_Error(
			'bettershield_codes_already_staged',
			__( 'Backup codes are already waiting. Save the ones you were shown, or start over for new ones.', 'bettershield' ),
			array( 'status' => 409 )
		);

		if ( ! Claim::claim( self::STAGE_CLAIM . $user->ID, self::STAGE_CLAIM_TTL ) ) {
			return $already;
		}

		try {
			if ( BackupCodes::staged( (int) $user->ID ) ) {
				return $already;
			}

			update_user_meta( $user->ID, self::META_CONFIRMED, '1' );

			return array( 'backup_codes' => BackupCodes::stage( $user->ID ) );
		} finally {
			Claim::release( self::STAGE_CLAIM . $user->ID );
		}
	}

	/**
	 * The user states the codes are stored. Only now does the gate arm.
	 *
	 * @return array{enabled: true}|\WP_Error
	 */
	public function acknowledge( \WP_User $user ) {
		$pending = (string) get_user_meta( $user->ID, self::META_PENDING, true );

		if ( '' === $pending || '1' !== get_user_meta( $user->ID, self::META_CONFIRMED, true ) ) {
			return new \WP_Error( 'bettershield_not_confirmed', __( 'Confirm a code from your app first.', 'bettershield' ), array( 'status' => 409 ) );
		}

		// The codes come into force first. If there is no staged set to put
		// into force, nothing arms: a second factor whose backup path was
		// never shown to anyone is the lockout this whole order prevents.
		if ( ! BackupCodes::promote( $user->ID ) ) {
			return new \WP_Error( 'bettershield_no_backup_codes', __( 'These backup codes are no longer available. Start again to get a new set.', 'bettershield' ), array( 'status' => 409 ) );
		}

		update_user_meta( $user->ID, self::META_SECRET, $pending );
		delete_user_meta( $user->ID, self::META_PENDING );
		delete_user_meta( $user->ID, self::META_CONFIRMED );
		update_user_meta( $user->ID, self::META_LAST_STEP, (string) intdiv( time(), Totp::PERIOD ) );

		/**
		 * Invalidate conveniences vouched for by the previous factor. Pending
		 * enrollment never fires this: the new factor must actually be armed.
		 *
		 * @param int $user_id The account whose second factor changed.
		 */
		do_action( 'bettershield_two_factor_changed', (int) $user->ID );

		Writer::instance()->record(
			'two_factor_enabled',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
			)
		);

		return array( 'enabled' => true );
	}

	/**
	 * Abandon an enrollment in progress. The pending secret goes; a factor
	 * that is already armed is untouched, which is why this asks for no
	 * code — it can only ever leave signing in exactly as it was.
	 *
	 * @return array{pending: false}
	 */
	public function discard( \WP_User $user ): array {
		delete_user_meta( $user->ID, self::META_PENDING );
		delete_user_meta( $user->ID, self::META_CONFIRMED );
		BackupCodes::discard( $user->ID );

		return array( 'pending' => false );
	}

	/**
	 * Issue a fresh set of backup codes for the signed-in account.
	 *
	 * Proof of possession is demanded for the same reason `disable()` demands
	 * it, and it is not optional here: without it a hijacked session could
	 * quietly mint itself ten long-lived credentials that outlive the session
	 * and survive a password change. That is strictly worse than what the
	 * intruder started with, so the route that hands out credentials asks for
	 * the same proof as the one that removes the factor.
	 *
	 * The way in when both are gone is unchanged and deliberate: an
	 * administrator turns the factor off, and the account holder sets it up
	 * again. Reissuing is for the person who still has their app and wants
	 * codes for when they do not.
	 *
	 * @return array{codes: string[], remaining: int}|\WP_Error
	 */
	public function reissue_backup_codes( \WP_User $user, string $code ) {
		if ( ! $this->enabled( $user->ID ) ) {
			return new \WP_Error( 'bettershield_not_enabled', __( 'Two-factor is not on for this account.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$checked = self::offers_a_code( $code ) ? $this->check_code( $user->ID, $code ) : false;

		if ( is_wp_error( $checked ) ) {
			return $checked;
		}

		if ( true !== $checked ) {
			return new \WP_Error(
				'bettershield_wrong_code',
				$this->wrong_code_message( (int) $user->ID, $code, __( 'That code does not match. Use a current app code or an unused backup code.', 'bettershield' ) ),
				array( 'status' => 400 )
			);
		}

		$codes = BackupCodes::reissue( (int) $user->ID );

		Writer::instance()->record(
			'two_factor_backup_reissued',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				// A count, because the codes themselves exist in the clear for
				// exactly one response and belong in no record anywhere.
				'context'     => array( 'issued' => count( $codes ) ),
			)
		);

		return array(
			'codes'     => $codes,
			'remaining' => BackupCodes::remaining( (int) $user->ID ),
		);
	}

	/**
	 * Self-service disable, proving possession with a current code or a
	 * backup code. An administrator disabling someone else goes through
	 * disable_for() instead, which requires the capability and not the code
	 * — the support path for the user whose phone is in a lake.
	 *
	 * @return array{enabled: false}|\WP_Error
	 */
	public function disable( \WP_User $user, string $code ) {
		if ( ! $this->enabled( $user->ID ) ) {
			return new \WP_Error( 'bettershield_not_enabled', __( 'Two-factor is not on for this account.', 'bettershield' ), array( 'status' => 409 ) );
		}

		/**
		 * Whether this person may turn their own second factor off. An
		 * add-on that requires it for their role answers false; an
		 * administrator's disable_for() is not asked.
		 *
		 * @param bool     $allowed True by default.
		 * @param \WP_User $user    The account.
		 */
		if ( ! apply_filters( 'bettershield_two_factor_self_disable_allowed', true, $user ) ) {
			/*
			 * Somebody who sets that requirement on this site is told how to
			 * lift it. Sent to "an administrator", the site's only one was
			 * sent to nobody: the administrator's route refuses one's own
			 * account (#1794).
			 */
			$own = array_intersect( (array) $user->roles, (array) Policy::instance()->settings()['roles'] );

			return new \WP_Error(
				'bettershield_two_factor_required_by_policy',
				array() !== $own && user_can( $user, \BetterShield\Capabilities::MANAGE )
					? __( 'Your role requires two-factor. To turn it off, first untick your role under "Require two-factor of a role".', 'bettershield' )
					: __( 'Your role requires two-factor, so you cannot turn it off. An administrator can do it for you.', 'bettershield' ),
				array( 'status' => 403 )
			);
		}

		$checked = self::offers_a_code( $code ) ? $this->check_code( $user->ID, $code ) : false;

		if ( is_wp_error( $checked ) ) {
			return $checked;
		}

		if ( true !== $checked ) {
			return new \WP_Error( 'bettershield_wrong_code', $this->wrong_code_message( (int) $user->ID, $code, __( 'That code does not match. Use a current app code or an unused backup code.', 'bettershield' ) ), array( 'status' => 400 ) );
		}

		$this->wipe( $user->ID, 'self' );

		return array( 'enabled' => false );
	}

	/**
	 * Turn your own two-factor off with your password, while safe mode is on.
	 *
	 * The way back for an account whose phone and backup codes are both gone
	 * and that nobody else can reset, the only administrator above all: the
	 * recovery link turns safe mode on, the password signs in, and this takes
	 * the factor off so the next sign-in after safe mode does not stop at the
	 * code screen again. It asks for the password, counted against the limit
	 * the password confirmation keeps, and it is loud: the alert goes out at
	 * high whatever the account.
	 *
	 * A policy that keeps people from turning their own factor off is not
	 * asked here. It sends a sole administrator to an administrator who does
	 * not exist; a role that requires the factor asks for it again as it does
	 * of any account without one.
	 *
	 * @return array{enabled: false}|\WP_Error
	 */
	public function disable_in_safe_mode( \WP_User $user, string $password ) {
		if ( ! SafeMode::is_active() ) {
			return new \WP_Error(
				'bettershield_not_in_safe_mode',
				__( 'Your password turns two-factor off only in safe mode. Use an app or backup code, or use your recovery link first.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		if ( (int) $user->ID !== get_current_user_id() ) {
			return new \WP_Error( 'bettershield_own_two_factor', __( 'This turns off only your own two-factor.', 'bettershield' ), array( 'status' => 403 ) );
		}

		if ( ! $this->enabled( $user->ID ) ) {
			return new \WP_Error( 'bettershield_not_enabled', __( 'Two-factor is not on for this account.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$confirmed = \BetterShield\Rest\Sudo::confirm( $password );

		if ( is_wp_error( $confirmed ) ) {
			return $confirmed;
		}

		$this->wipe( (int) $user->ID, 'safe_mode', true );

		return array( 'enabled' => false );
	}

	/**
	 * Arm a factor the account already proved with another plugin: the same
	 * shared secret, so the authenticator app the person holds keeps working.
	 *
	 * Only on an account with nothing armed here, so nobody's own factor is
	 * ever replaced. An enrollment left half way protects nothing, and gives
	 * way once the secret is in place. Backup codes are the importer's to
	 * bring, where the other plugin's can be read at all; without any, the
	 * person makes a new set from their profile with a code from the app. True
	 * only when the secret reads back as written.
	 */
	public function adopt( int $user_id, string $secret ): bool {
		if ( $this->enabled( $user_id ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_SECRET, $secret );

		if ( (string) get_user_meta( $user_id, self::META_SECRET, true ) !== $secret ) {
			delete_user_meta( $user_id, self::META_SECRET );

			return false;
		}

		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_CONFIRMED );
		BackupCodes::discard( $user_id );

		do_action( 'bettershield_two_factor_changed', $user_id );

		return true;
	}

	/**
	 * Take back a factor `adopt()` armed, while it is still that secret: one
	 * the person set up again since is theirs, and stays. Sessions are left
	 * alone, since the account goes back to the plugin it came from rather
	 * than losing its protection to somebody else's hand.
	 *
	 * @param string $digest SHA-256 of the adopted secret.
	 */
	public function withdraw( int $user_id, string $digest ): bool {
		$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );

		if ( '' === $secret || ! hash_equals( $digest, hash( 'sha256', $secret ) ) ) {
			return false;
		}

		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_LAST_STEP );
		BackupCodes::forget( $user_id );
		LoginStep::forget_for( $user_id );
		do_action( 'bettershield_two_factor_changed', $user_id );

		return true;
	}

	/**
	 * @return array{enabled: false}
	 */
	public function disable_for( int $user_id, string $reason ): array {
		$this->wipe( $user_id, $reason );

		return array( 'enabled' => false );
	}

	/**
	 * Take an account's second factor off from the server's command line, for
	 * the person who lost their phone and their codes. Recorded high whatever
	 * the account, since it came off by a way that asks for no factor, and
	 * the account is told it came off from the terminal.
	 *
	 * @return array{enabled: false}
	 */
	public function reset_from_terminal( int $user_id ): array {
		$this->wipe( $user_id, 'cli', true );

		return array( 'enabled' => false );
	}

	/**
	 * @param bool $loud High whatever the account: the factor came off by a way that asks for no factor.
	 */
	private function wipe( int $user_id, string $reason, bool $loud = false ): void {
		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_PENDING );
		delete_user_meta( $user_id, self::META_CONFIRMED );
		delete_user_meta( $user_id, self::META_LAST_STEP );
		BackupCodes::forget( $user_id );
		LoginStep::forget_for( $user_id );
		do_action( 'bettershield_two_factor_changed', $user_id );

		// Losing the second factor on a privileged account is a protection
		// coming off where it matters most, and it goes out ahead of the
		// digest. On an ordinary account it stays the quiet event it was.
		$privileged = \BetterShield\Password\Policy::instance()->user_is_privileged( $user_id );

		Writer::instance()->record(
			'two_factor_disabled',
			$loud || $privileged ? Writer::SEVERITY_HIGH : Writer::SEVERITY_LOW,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array( 'by' => $reason ),
			)
		);

		// The sessions the factor vouched for end with it; the person who
		// turned it off themselves keeps the device they did it on.
		\BetterShield\Login\SessionReset::credential_changed( $user_id, 'two_factor' );
	}

	/* ---- the login gate ---------------------------------------------------------- */

	/**
	 * The account one of this plugin's own flows is re-running the
	 * `authenticate` chain for, so the gates can tell their own re-entry
	 * from a third-party passwordless sign-in. Bound to a user ID, never a
	 * bare flag — a filter running inside the re-entered chain that swaps
	 * in a different account must not inherit the exemption.
	 */
	private ?int $reentered_for = null;

	/** Whether the sign-in being re-entered began with a password. */
	private bool $reentered_with_password = false;

	/**
	 * Whether this plugin is currently re-running the chain for exactly
	 * this account. Read by its own sign-in gates and nothing else.
	 */
	public function reentering( int $user_id ): bool {
		return null !== $this->reentered_for && $this->reentered_for === $user_id;
	}

	/**
	 * Run the `authenticate` chain from an already-verified account, with
	 * this plugin's own gates standing aside for that account — everything
	 * hooked after them runs exactly as it would have. The only way to be
	 * exempted by name: the second screen finishing a parked sign-in, and
	 * the passkey route applying the site's other rules, both call through
	 * here.
	 *
	 * @return \WP_User|\WP_Error|mixed Whatever the chain answers.
	 */
	public function reenter_chain( \WP_User $user, bool $with_password = false ) {
		$this->reentered_for           = (int) $user->ID;
		$this->reentered_with_password = $with_password;

		try {
			return apply_filters( 'authenticate', $user, $user->user_login, '' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter.
		} finally {
			$this->reentered_for           = null;
			$this->reentered_with_password = false;
		}
	}

	/**
	 * Whether this re-entry is finishing a sign-in that began with a
	 * password: the second screen after a password, not a passkey. A
	 * protection about passwords still has its say over it.
	 */
	public function finishing_a_password( int $user_id ): bool {
		return $this->reentering( $user_id ) && $this->reentered_with_password;
	}

	/**
	 * Whether this request carries a valid session cookie for exactly this
	 * account. Checked the way core's own cookie handler does, on both the
	 * signed-in scheme and the context-dependent auth scheme.
	 */
	private function holds_session_cookie_for( int $user_id ): bool {
		if ( $user_id < 1 ) {
			return false;
		}

		return (int) wp_validate_auth_cookie( '', 'logged_in' ) === $user_id
			|| (int) wp_validate_auth_cookie() === $user_id;
	}

	/**
	 * After the password: pass, refuse, or hand the sign-in to the second
	 * screen. Handing over does not return — the browser is redirected before
	 * any cookie that signs anybody in exists.
	 *
	 * @param mixed  $user
	 * @param string $username
	 * @param string $password
	 * @return mixed
	 */
	public function gate( $user, $username = '', $password = '' ) {
		if ( ! $user instanceof \WP_User || ! $this->enabled( $user->ID ) || SafeMode::is_active() ) {
			return $user;
		}

		if ( $this->password_path_exempt( $user, (string) $password ) ) {
			$this->passed_gate = (int) $user->ID;

			return $user;
		}

		// Password-only XML-RPC would walk around the gate; refuse it with
		// the fix named. (When the XML-RPC hardening item is on, requests
		// never get this far.)
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return new \WP_Error(
				'bettershield_2fa_xmlrpc',
				__( 'This account uses two-factor authentication, so XML-RPC needs an application password.', 'bettershield' )
			);
		}

		// A sign-in that is not a person at a browser cannot be sent to a
		// second screen: it gets a refusal that names the alternatives. This
		// refusal is one of the plugin's own and does not count as a wrong
		// password toward a lockout.
		if ( ! LoginStep::interactive() ) {
			return LoginStep::refusal( $user );
		}

		// A device the owner chose to trust, through the seam a paid add-on
		// answers on: the free plugin itself never stands down here.
		if ( ! LoginStep::second_factor_required( $user, 'password' ) ) {
			$this->passed_gate = (int) $user->ID;

			return $user;
		}

		// Park the sign-in and go to the code screen; nothing that signs
		// anybody in has been set yet. Returns only when the response has
		// already started and there is no way to send the browser on.
		return LoginStep::instance()->begin( $user );
	}

	/**
	 * Record a session made for an account with two-factor that this request
	 * never took through the gate: a plugin calling `wp_set_auth_cookie()` runs
	 * no `authenticate` filter. Recorded and not refused, because refusing would
	 * lock people out on sites that use single sign-on.
	 *
	 * Once per account and source per window, so it isn't an email per sign-in.
	 *
	 * @param mixed $cookie     The cookie's value.
	 * @param mixed $expire     When the browser drops it.
	 * @param mixed $expiration When it stops being accepted.
	 * @param mixed $user_id    The account it signs in.
	 */
	public function note_session_past_gate( $cookie, $expire, $expiration, $user_id ): void {
		unset( $cookie, $expire, $expiration );

		$user_id = (int) $user_id;

		if ( $user_id < 1 || $this->passed_gate === $user_id || ! $this->enabled( $user_id ) || SafeMode::is_active() ) {
			return;
		}

		// A session being rotated, as changing your own password does.
		$token = wp_get_session_token();

		if ( '' !== $token && \WP_Session_Tokens::get_instance( $user_id )->verify( $token ) ) {
			return;
		}

		$user = get_userdata( $user_id );

		// That plugin may be setting this cookie after its own second step.
		if ( ! $user instanceof \WP_User || '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user ) ) {
			return;
		}

		$source = self::session_source();

		if ( null === \BetterShield\Events\Coalescer::admit( 'bettershield_2fa_skipped_' . md5( $user_id . '|' . $source ), self::SKIPPED_WINDOW ) ) {
			return;
		}

		Writer::instance()->record(
			'two_factor_skipped',
			\BetterShield\Password\Policy::instance()->user_is_privileged( $user ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'actor_type'  => 'system',
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'source' => \BetterShield\Abilities\AgentSurface::source_label( $source ),
				),
			)
		);
	}

	/** The plugin that asked for this session: the first caller that isn't WordPress. */
	private static function session_source(): string {
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 25 ) as $frame ) { // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- only on a session about to be flagged, for the source's name.
			$file = (string) ( $frame['file'] ?? '' );

			if ( '' === $file || __FILE__ === $file ) {
				continue;
			}

			$source = \BetterShield\Abilities\AgentSurface::source_path( $file );

			if ( 'wordpress' !== $source ) {
				return $source;
			}
		}

		return 'wordpress';
	}

	/**
	 * Whether this authenticate call is one no password gate owes anything.
	 *
	 * Three cases, and every gate in this plugin that stands between a
	 * password and a session has to agree about all three — so they are
	 * decided here once rather than restated per gate, which is how two gates
	 * come to disagree about who is exempt.
	 *
	 * 1. **One of this plugin's own flows re-running the chain** from an
	 *    account it has already verified — the second screen finishing, a
	 *    passkey sign-in applying the site's other rules. Named by the marker
	 *    rather than inferred from an empty password: any plugin can resolve a
	 *    user on `authenticate` without a password (social login, magic links
	 *    and SSO all do), and an inference that broad let every one of them
	 *    walk past the second factor. Bound to the account, so a filter
	 *    swapping in a different user mid-chain answers for itself.
	 * 2. **wp-login.php re-validating an existing session**, which core does
	 *    on every visit, resolving the account from its cookie with no
	 *    password. That session passed these gates when it was created and the
	 *    cookie proves it; a passwordless provider cannot mint one.
	 * 3. **An application password**, which is itself a second factor:
	 *    generated, scoped to one integration, revocable alone. The request it
	 *    authenticated is not an interactive sign-in and owes these gates
	 *    nothing — this is what "without breaking integrations" means.
	 */
	public function password_path_exempt( \WP_User $user, string $password ): bool {
		return $this->reentering( (int) $user->ID )
			|| ( '' === $password && $this->holds_session_cookie_for( (int) $user->ID ) )
			|| $this->application_password_user === (int) $user->ID;
	}

	/**
	 * Ten wrong backup-code guesses an hour is a person who has lost their
	 * codes, or a script working through the space; after that the codes
	 * stop being checked for an hour. Each check is a bcrypt verify across
	 * every remaining code, so the cap bounds the CPU too. Counted per
	 * account, in a transient that holds a number and nothing else.
	 *
	 * Counted per site on a network, which means the effective budget for a
	 * network-global credential is this cap times the number of subsites. That
	 * is the settled trade: counting across a network would mean shared state,
	 * and one subsite's traffic locking an account out on every other. The
	 * sign-in counters carry the same shape for the same reason.
	 */
	private function backup_guess_allowed( int $user_id ): ?bool {
		// Counted in one statement. Written as a read and then a write, a
		// parallel run of guesses all read the same total before any of them
		// stored it, so a cap meant to bound both guessing and bcrypt work
		// bounded neither.
		return self::within( Claim::bump_or_fail( self::backup_key( $user_id ), HOUR_IN_SECONDS ), self::BACKUP_GUESS_CAP );
	}

	/**
	 * Whether a count is inside a cap, or null when there was no count.
	 *
	 * A cap standing in front of a credential cannot be open when it is
	 * unsure: the records these are kept in went missing once, every count
	 * came back as one, and ten wrong codes an hour became as many as anybody
	 * cared to send. Null in, null out — and the callers refuse on it.
	 */
	private static function within( ?int $count, int $cap ): ?bool {
		return null === $count ? null : $count <= $cap;
	}

	/**
	 * Whether this account has any guesses left this hour. Public because the
	 * sign-in screen asks first, so it can say so rather than reporting a
	 * wrong code the tenth time and a wrong code the eleventh.
	 *
	 * Counted per site on a network, which means the effective budget for a
	 * network-global credential is this cap times the number of subsites. That
	 * is the settled trade: counting across a network would mean shared state,
	 * and one subsite's traffic locking an account out on every other. The
	 * sign-in counters carry the same shape for the same reason.
	 */
	public function guess_allowed( int $user_id ): bool {
		$count = Claim::count_or_fail( self::wrong_key( $user_id ) );

		// A budget that could not be read is not a budget with room in it.
		return null !== $count && $count < self::WRONG_CODE_CAP;
	}

	/**
	 * Whether this attempt is inside the hourly budget, counting it.
	 *
	 * The decision every code check acts on, as opposed to the read-only
	 * question above that the sign-in screen asks so it can say so. Counted in
	 * one statement, for the reason `backup_guess_allowed()` already carries:
	 * written as a read and then a write, a parallel run of guesses all read
	 * the same total before any of them stored it, and a cap meant to bound
	 * guessing bounded nothing.
	 */
	private function guess_attempt_allowed( int $user_id ): ?bool {
		return self::within( Claim::bump_or_fail( self::wrong_key( $user_id ), HOUR_IN_SECONDS ), self::WRONG_CODE_CAP );
	}

	private static function wrong_key( int $user_id ): string {
		return '2fa_wrong_' . $user_id;
	}

	private static function backup_key( int $user_id ): string {
		return 'backup_guesses_' . $user_id;
	}

	/** Attempts to confirm a new app, counted apart from signing in. */
	private static function confirm_key( int $user_id ): string {
		return '2fa_confirm_' . $user_id;
	}

	/**
	 * Hand back what a right code took from the budget on the way in.
	 *
	 * The count is taken before the answer is known, so that the count and
	 * the decision are one statement; a code that turns out right gives its
	 * one back. Only the one: wrong codes already in the window stay counted.
	 */
	private static function accepted( int $user_id ): bool {
		Claim::give_back( self::wrong_key( $user_id ) );

		return true;
	}

	/**
	 * The answer once an hour's guesses are spent: nothing was compared, and
	 * "That code does not match" said about the right code sends somebody to
	 * try the next one, which is not checked either.
	 */
	private static function capped(): \WP_Error {
		return new \WP_Error(
			'bettershield_2fa_capped',
			__( 'Too many wrong codes in the last hour, so codes are paused for this account. Locked out? Use your recovery link.', 'bettershield' ),
			array( 'status' => 429 )
		);
	}

	/**
	 * The refusal when no code can be checked at all, because the records the
	 * cap is kept in did not answer.
	 *
	 * A correct code is refused with the rest, which is the point: a check
	 * with no limit on how often it may be repeated is an offer to guess. The
	 * message names the way back in rather than only saying no — the recovery
	 * link and the printed codes do not depend on these records — and it says
	 * nothing about which table, which account, or what the database replied.
	 *
	 * Recorded at high severity under the type a rejected code already uses:
	 * this is a sign-in being refused, and an account that suddenly cannot get
	 * in should find the reason in the log beside the attempt.
	 */
	private function records_unreadable( int $user_id ): \WP_Error {
		Writer::instance()->record(
			'two_factor_failed',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array( 'reason' => 'records_unreadable' ),
			)
		);

		return new \WP_Error(
			'bettershield_records_unreadable',
			__( 'Sign-in codes cannot be checked: their records could not be read. Locked out? Use this site’s recovery link.', 'bettershield' ),
			array( 'status' => 503 )
		);
	}

	/**
	 * Whether anything of a checkable shape was offered at all.
	 *
	 * An absent credential is not a wrong one. `accept_code()` normalizes to
	 * digits and counts anything that is neither six nor eight of them as a
	 * guess, which is right when somebody typed something and wrong when
	 * nobody typed anything: a caller that sends no code at all was spending
	 * the account's hourly budget a request at a time, and past ten the
	 * account stopped checking its owner's own sign-in code for the rest of
	 * the hour. Asked by the three callers that take a code from a request
	 * body, before the check rather than inside it — inside, the shape and the
	 * wrongness are the same answer.
	 */
	private static function offers_a_code( string $code ): bool {
		$digits = (string) preg_replace( '/[^0-9]/', '', $code );

		return Totp::DIGITS === strlen( $digits ) || 8 === strlen( $digits ) || '' !== BackupCodes::imported_code( $code );
	}

	/**
	 * Record the step a code was accepted at, and answer whether this request
	 * is the one that recorded it.
	 *
	 * `Totp::verify()` refuses any step at or below the stored one, so the
	 * stamp is what spends a code. Reading the stamp, deciding, and then
	 * writing it leaves a window in which a second request carrying the same
	 * code reads the same stamp and passes the same check — so the write
	 * carries the value it expects to replace, and the database admits one of
	 * the two. The accepted step is always above the stored one, so the row
	 * always changes and a matched condition always reports a written row.
	 *
	 * @param string $stamped The stored value this request read, unmodified.
	 */
	private function stamp_step( int $user_id, int $step, string $stamped ): bool {
		if ( '' === $stamped ) {
			/*
			 * No stamp to condition on. Enrollment writes one, so this is an
			 * account that armed before it did; the first code such an account
			 * presents is the one moment this cannot arbitrate, and every code
			 * after it is covered by the branch below.
			 */
			update_user_meta( $user_id, self::META_LAST_STEP, (string) $step );

			return true;
		}

		return (bool) update_user_meta( $user_id, self::META_LAST_STEP, (string) $step, $stamped );
	}

	/**
	 * A six-digit shape is an app code, an eight-digit shape a backup code,
	 * and sixteen hex characters a backup code brought over from another
	 * plugin; disjoint by construction, so one field serves all. Accepting a code
	 * spends it: an app code's step is stamped, a backup code is consumed.
	 *
	 * Attempts are counted here, and past the cap nothing is checked at all —
	 * a right code included, which is the point of a cap. Counted on the way
	 * in rather than after the answer is known: the count and the decision are
	 * then one statement, so requests arriving together cannot all read the
	 * same total and all be checked. A code that turns out right gives its
	 * count back, so only wrong codes — and a right one offered again after
	 * the stamp spent it — use the budget up.
	 */
	public function accept_code( int $user_id, string $code ): bool {
		return true === $this->check_code( $user_id, $code );
	}

	/**
	 * Why a code asked for on a dashboard screen was refused: just used, as
	 * sign-in says (#2076), or the screen's own words for a mismatch (#2138).
	 */
	public function wrong_code_message( int $user_id, string $code, string $otherwise ): string {
		return $this->was_just_used( $user_id, $code )
			? __( 'That code was just used. Wait for your app to show a new one, or use an unused backup code.', 'bettershield' )
			: $otherwise;
	}

	/**
	 * Whether a refused app code was the right one, refused because it was
	 * already spent: the step it belongs to, or a later one, has signed in.
	 *
	 * Asked only after check_code() said no, to say why. Typing the code the
	 * app still showed right after turning two-factor on was answered "That
	 * code does not match", and told to try the code the app shows, which
	 * was the same code (#2076). The refusal stands and stays counted.
	 */
	public function was_just_used( int $user_id, string $code ): bool {
		$digits = (string) preg_replace( '/[^0-9]/', '', $code );
		$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );
		$spent  = (int) get_user_meta( $user_id, self::META_LAST_STEP, true );

		if ( Totp::DIGITS !== strlen( $digits ) || '' === $secret || $spent <= 0 ) {
			return false;
		}

		$step = Totp::verify( $secret, $digits, time() );

		return null !== $step && $step <= $spent;
	}

	/**
	 * The same check, keeping the difference between a code that was wrong and
	 * a code that could not be checked at all.
	 *
	 * The routes that answer a person — turning the factor off, issuing a new
	 * set of codes — say which of the two happened, because "that code does
	 * not match" is a lie when nothing was compared, and it sends somebody to
	 * try their next code instead of to their recovery link.
	 *
	 * @return bool|\WP_Error True accepted, false wrong, an error when the
	 *                        hour's guesses are spent or the records the
	 *                        cap is kept in did not answer.
	 */
	public function check_code( int $user_id, string $code ) {
		$allowed = $this->guess_attempt_allowed( $user_id );

		if ( null === $allowed ) {
			return $this->records_unreadable( $user_id );
		}

		if ( ! $allowed ) {
			return self::capped();
		}

		$digits   = (string) preg_replace( '/[^0-9]/', '', $code );
		$imported = BackupCodes::imported_code( $code );

		if ( '' === $imported && Totp::DIGITS === strlen( $digits ) ) {
			$secret = (string) get_user_meta( $user_id, self::META_SECRET, true );

			/*
			 * An empty secret is not a weak secret, it is no secret:
			 * `base32_decode( '' )` is `''`, and the HMAC of a counter under an
			 * empty key is a value anybody can compute offline. Every caller
			 * today checks `enabled()` first, so this is a landmine rather than
			 * a hole — but the fifth caller is the one it hurts, and the
			 * failure mode is a silent authentication bypass rather than an
			 * error. The same guard sits inside `Totp::verify()` so the
			 * property holds for any future caller rather than for this one.
			 */
			if ( '' === $secret ) {
				return false;
			}

			$stamped = (string) get_user_meta( $user_id, self::META_LAST_STEP, true );
			$step    = Totp::verify( $secret, $digits, time(), (int) $stamped );

			if ( null !== $step ) {
				// A code is spent by the stamp, not by the check — so if the
				// stamp did not land, another request carrying this same code
				// got there first and this is the replay, which stays counted.
				return $this->stamp_step( $user_id, $step, $stamped ) && self::accepted( $user_id );
			}

			return false;
		}

		if ( '' === $imported && 8 !== strlen( $digits ) ) {
			return false;
		}

		$backup = $this->backup_guess_allowed( $user_id );

		if ( null === $backup ) {
			return $this->records_unreadable( $user_id );
		}

		if ( ! $backup ) {
			return self::capped();
		}

		if ( BackupCodes::consume( $user_id, '' !== $imported ? $imported : $digits ) ) {
			// Consumed, so it cannot be offered again; the check it cost the
			// backup-code budget is given back with the other.
			Claim::give_back( self::backup_key( $user_id ) );

			Writer::instance()->record(
				'two_factor_backup_used',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'user',
					'object_id'   => (string) $user_id,
					'context'     => array( 'remaining' => BackupCodes::remaining( $user_id ) ),
				)
			);

			return self::accepted( $user_id );
		}

		return false;
	}
}
