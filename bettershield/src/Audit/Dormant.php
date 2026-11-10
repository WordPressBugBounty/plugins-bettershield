<?php
/**
 * Privileged accounts nobody has used for a long time.
 *
 * A dormant administrator is a wide, quiet door: full rights, an old password,
 * nobody watching the mail it can reset through, and no one who would notice
 * it being used. It is the account a former contractor left behind, or the
 * test admin somebody made during a migration and never removed.
 *
 * The audit already flags an account named `admin` and the first account still
 * being an administrator. Neither looks at whether anyone actually signs in.
 *
 * **The stamp had to be added, and that shapes what this can honestly say.**
 * Nothing recorded a last sign-in before this, so on the day it ships every
 * account looks dormant and none of them is. So the reading is: an account is
 * dormant when it has not signed in since the *later* of its own stamp and the
 * day this plugin started watching — and nothing at all is reported until this
 * plugin has been watching for longer than the threshold. A tool that cannot
 * yet know says so by staying quiet, rather than by guessing.
 *
 * **A sign-in is not the only way an account is used.** An administrator that
 * authenticates over REST with an application password — a headless front end,
 * a deployment, an agent, which is the audience this plugin courts — never
 * fires `wp_login` and so never stamped anything here. Reading the stamp alone
 * reported an account used four minutes ago as untouched for six months, in
 * the one finding whose whole value is that it is worth acting on. Every
 * signal the site actually has is taken, and the newest of them wins.
 *
 * **It reports and does not act.** Demoting somebody's account automatically
 * is a decision with a person on the other end of it, and getting it wrong
 * locks out a colleague who was on parental leave.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Dormant {

	public const META = 'bettershield_last_login';

	/**
	 * How long is long enough to be worth mentioning.
	 *
	 * Six months, because a quarter is a sabbatical and a year is too late to
	 * be useful. Filterable, because an agency and a newsroom disagree about
	 * this and both are right about their own site.
	 */
	public const DEFAULT_DAYS = 180;

	/** How many accounts are named before the finding becomes a count. */
	public const MAX_NAMED = 10;

	/**
	 * How many privileged accounts one pass looks at.
	 *
	 * A ceiling on the work, not on the answer — but it does mean a site with
	 * more privileged accounts than this has a total that is a floor, and
	 * `examined_every_privileged_account()` is how the finding says so.
	 */
	public const MAX_EXAMINED = 200;

	/**
	 * Whether the last `accounts()` pass reached the end of the site's
	 * privileged accounts, or stopped at the examination ceiling.
	 */
	private static bool $examined_all = true;

	public static function register(): void {
		add_action( 'wp_login', array( self::class, 'stamp' ), 10, 2 );

		/*
		 * XML-RPC signs in with a username and password on every request,
		 * through wp_authenticate(), and never fires wp_login — so an
		 * administrator publishing daily from a desktop client was reported
		 * as dormant. Placed after the gates that can still refuse a sign-in
		 * the password check accepted (the lockdown at 32, the passkey-only
		 * rule at 35, the second factor at 40), so a refused sign-in is never
		 * stamped. One argument: the password is not wanted here.
		 */
		add_filter( 'authenticate', array( self::class, 'observe_authentication' ), 50, 1 );
	}

	/**
	 * @param mixed $user
	 */
	public static function stamp( string $user_login, $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		// XML-RPC authenticates on every request, and a threshold measured
		// in days gains nothing from a stamp measured in seconds: one write
		// an hour per account, whichever door it came through.
		$now  = time();
		$last = (int) get_user_meta( $user->ID, self::META, true );

		if ( $last > 0 && $now - $last < HOUR_IN_SECONDS ) {
			return;
		}

		$since = max( $last, (int) strtotime( (string) get_option( 'bettershield_activated_at', '' ) ), (int) strtotime( $user->user_registered . ' UTC' ) );
		if ( $since > 0 && $now - $since >= self::threshold_days() * DAY_IN_SECONDS && \BetterShield\Password\Policy::instance()->user_is_privileged( $user ) ) {
			\BetterShield\Events\Writer::instance()->record( 'dormant_privileged_login', \BetterShield\Events\Writer::SEVERITY_MEDIUM, array( 'actor_type' => 'user', 'actor_id' => (int) $user->ID, 'object_type' => 'user', 'object_id' => (string) $user->ID, 'context' => array( 'days_idle' => (int) floor( ( $now - $since ) / DAY_IN_SECONDS ) ) ) );
		}
		update_user_meta( $user->ID, self::META, $now );
	}

	/**
	 * A sign-in that reached the end of the chain as an account is a use of
	 * that account. Anything else — an error, nothing — passes through
	 * untouched.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public static function observe_authentication( $user ) {
		if ( $user instanceof \WP_User ) {
			self::stamp( (string) $user->user_login, $user );
		}

		return $user;
	}

	public static function threshold_days(): int {
		/**
		 * How many days without a sign-in makes a privileged account dormant.
		 *
		 * @param int $days
		 */
		return max( 30, (int) apply_filters( 'bettershield_dormant_days', self::DEFAULT_DAYS ) );
	}

	/**
	 * Whether this plugin has been watching long enough to have an opinion.
	 *
	 * Without this, every account on the site is reported dormant on the day
	 * the feature ships — which is the fastest way to teach somebody that this
	 * screen is wrong.
	 */
	public static function watching_long_enough(): bool {
		$since = strtotime( (string) get_option( 'bettershield_activated_at', '' ) );

		if ( false === $since ) {
			return false;
		}

		return ( time() - $since ) > ( self::threshold_days() * DAY_IN_SECONDS );
	}

	/** How long, in seconds, this plugin has been watching sign-ins here; 0 when it cannot say. */
	public static function watched_for(): int {
		$since = strtotime( (string) get_option( 'bettershield_activated_at', '' ) );

		return false === $since ? 0 : max( 0, time() - $since );
	}

	/**
	 * Privileged accounts that have not signed in for too long.
	 *
	 * @return array<int, array{id: int, login: string, days: int}>
	 */
	public static function accounts(): array {
		if ( ! self::watching_long_enough() ) {
			return array();
		}

		return self::idle_for( self::threshold_days() );
	}

	/**
	 * Privileged accounts not used for a given number of days, by the same
	 * reading the finding makes: every signal the site has, and the clock
	 * from when this started watching where nothing is known.
	 *
	 * For an add-on that acts on its owner's own threshold, so the diagnosis
	 * stays one definition. It does not ask whether this plugin has watched
	 * long enough for the finding's threshold; the caller decides that for
	 * its own (`watched_for()`).
	 *
	 * @return array<int, array{id: int, login: string, days: int}>
	 */
	public static function idle_for( int $days ): array {
		$cutoff = time() - ( max( 1, $days ) * DAY_IN_SECONDS );
		$found  = array();

		$privileged         = self::privileged();
		self::$examined_all = count( $privileged ) < self::MAX_EXAMINED;

		// Read once rather than once per account: the same option, parsed the
		// same way, up to two hundred times over.
		$watching_since = (int) strtotime( (string) get_option( 'bettershield_activated_at', '' ) );

		foreach ( $privileged as $user ) {
			$last = self::last_used( $user );

			/*
			 * No stamp means nobody has signed in since this started watching,
			 * which is exactly the case the feature is for — so the clock runs
			 * from when watching began rather than from the account's creation,
			 * which would be a guess about the years before. For an account
			 * created *after* watching began, registration is the later and
			 * truer anchor: without it, a day-old contractor account was
			 * reported dormant for the two hundred days before it existed.
			 */
			if ( 0 === $last ) {
				$last = max(
					$watching_since,
					(int) strtotime( $user->user_registered . ' UTC' )
				);
			}

			if ( 0 === $last || $last > $cutoff ) {
				continue;
			}

			// The account being used to read this is not dormant, whatever a
			// stale stamp says.
			if ( get_current_user_id() === (int) $user->ID ) {
				continue;
			}

			// A suspended account cannot sign in, so it is no longer a door.
			if ( \BetterShield\Remediation\Suspension::blocks( (int) $user->ID ) ) {
				continue;
			}

			$found[] = array(
				'id'    => (int) $user->ID,
				'login' => (string) $user->user_login,
				'days'  => (int) floor( ( time() - $last ) / DAY_IN_SECONDS ),
			);
		}

		/*
		 * Every one of them, not the first ten. This used to stop at the
		 * naming limit, so a site with forty dormant administrators produced a
		 * list of ten and no total — and ten of ten reads exactly like ten of
		 * forty on the finding. Naming is the caller's job now; counting is
		 * this one's, and the loop is over accounts already read into memory.
		 */
		return $found;
	}

	/**
	 * Whether the last `accounts()` pass saw every privileged account.
	 *
	 * False means the total it returned is a floor rather than the number, and
	 * the finding says "at least" instead of naming a figure it cannot stand
	 * behind.
	 */
	public static function examined_every_privileged_account(): bool {
		return self::$examined_all;
	}

	/**
	 * The most recent evidence this account was used, from any of the ways it
	 * can be.
	 *
	 * The interactive sign-in stamp, and the newest `last_used` across the
	 * account's application passwords — which core records itself and this
	 * plugin already reads elsewhere, for a different check, while this one
	 * ignored it. A credential used today is a credential used today, whatever
	 * door it came through.
	 *
	 * Zero when nothing is known, which the caller resolves against the day
	 * this plugin started watching.
	 */
	private static function last_used( \WP_User $user ): int {
		$last = (int) get_user_meta( $user->ID, self::META, true );

		if ( ! class_exists( '\WP_Application_Passwords' ) ) {
			return $last;
		}

		foreach ( (array) \WP_Application_Passwords::get_user_application_passwords( (int) $user->ID ) as $password ) {
			$used = (int) ( $password['last_used'] ?? 0 );

			if ( $used > $last ) {
				$last = $used;
			}
		}

		return $last;
	}

	/**
	 * Accounts that can change this site.
	 *
	 * By capability rather than by role name, for the same reason the password
	 * policy is: a super admin and a custom high-privilege role are both
	 * accounts whose disuse matters, and neither is called `administrator`.
	 *
	 * @return \WP_User[]
	 */
	private static function privileged(): array {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- get_users is the API; bounded below and read by the daily audit only.
		return (array) get_users(
			array(
				'capability' => 'manage_options',
				'number'     => self::MAX_EXAMINED,
				'fields'     => 'all',
				// The default is user_login, which makes the database sort the
				// whole capability-matched set before the limit applies. The
				// order is irrelevant here — every match is returned and the
				// caller does the naming cap — and the primary key is already
				// in the order the rows come out in.
				'orderby'    => 'ID',
			)
		);
	}
}
