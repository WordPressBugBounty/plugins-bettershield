<?php
/**
 * One email before a two-factor deadline, to the account it is about.
 *
 * An account past its window is sent to the setup screen whenever it opens the
 * dashboard, and the countdown on every dashboard page is how it hears that
 * coming. That reaches everybody who opens the dashboard during the window,
 * since the clock starts on the first page they see. It misses somebody who
 * saw it once and did not come back: an editor who looks in once a month can
 * lose the whole window between two visits. This is the one message that
 * reaches them, a few days before the date.
 *
 * Only an account whose clock is running is written to. One this site has
 * never met has no deadline yet, and a reminder must not be what starts one,
 * so clocks are read without being started (`Policy::peek()`).
 *
 * Nothing is kept about anybody for this. Each run takes the reminders that
 * fell due since the run before, so one message per deadline comes from the
 * order of the runs rather than from a mark on the account. A deadline moved
 * later is a new one and is reminded again; one moved earlier, past a reminder
 * already due, is not, and the countdown still says how long is left.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Onboarding\SiteIdentity;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Reminder {

	/** The daily task. */
	public const TASK = 'bettershield_two_factor_reminders';

	/** The latest moment a run has sent the reminders due up to, as Unix time. */
	public const REACHED_OPTION = 'bettershield_two_factor_reminded_through';

	/** How many days before a deadline its account is written to, by default. */
	public const DAYS_BEFORE = 3;

	/** The most accounts one run reads; the rest are the next run's. */
	private const BATCH = 50;

	/** How long one run may spend sending, in seconds; the rest are the next run's. */
	private const BUDGET_SECONDS = 15;

	/** Held while a run sends, so two runs cannot write to the same people. */
	private const CLAIM = 'two_factor_reminders';

	public static function run(): void {
		/**
		 * How many days before a two-factor deadline its account is emailed,
		 * once. Zero sends nothing.
		 *
		 * @param int $days Three by default.
		 */
		$before = (int) apply_filters( 'bettershield_two_factor_reminder_days', self::DAYS_BEFORE );
		$grace  = Policy::instance()->grace_days();

		/*
		 * Nothing goes out from a staging copy, which writes to nobody as the
		 * live site would, or while safe mode stands the policy down; the
		 * reminders wait for the next run. A window no longer than the lead
		 * time has no moment to remind in: the countdown gave the date on the
		 * first page the account saw.
		 */
		if ( $before < 1 || $grace <= $before || SiteIdentity::is_staging() || SafeMode::is_active() ) {
			return;
		}

		if ( ! Claim::claim( self::CLAIM, 10 * MINUTE_IN_SECONDS ) ) {
			return;
		}

		try {
			self::remind( $grace, $before );
		} finally {
			Claim::release( self::CLAIM );
		}
	}

	private static function remind( int $grace, int $before ): void {
		$policy = Policy::instance();
		$now    = time();
		$offset = ( $grace - $before ) * DAY_IN_SECONDS;

		/*
		 * The reminders that fell due since the last run, for deadlines still
		 * ahead. The first run has no last one and takes every running clock
		 * already inside its last days, none of which was reminded.
		 */
		$from   = max( (int) get_option( self::REACHED_OPTION, 0 ), $now - $before * DAY_IN_SECONDS );
		$clocks = $policy->clocks_started_between( $from - $offset, $now - $offset, self::BATCH );

		// A full page may have more behind it: this run reaches as far as the
		// last clock it read, and the next carries on from there.
		$reached = count( $clocks ) < self::BATCH ? $now : (int) end( $clocks ) + $offset;
		$began   = time();

		foreach ( $clocks as $user_id => $since ) {
			// Out of time: this one and the rest are the next run's.
			if ( time() - $began >= self::BUDGET_SECONDS ) {
				$reached = $since + $offset - 1;
				break;
			}

			$user  = get_userdata( $user_id );
			$state = $user instanceof \WP_User ? $policy->peek( $user ) : null;

			// Set up since, no longer covered, or a clock from an earlier spell
			// of the requirement: nothing is owed, so nothing is said.
			if ( null !== $state && Policy::IN_GRACE === $state['status'] && null !== $state['due_at'] ) {
				self::send( $user, (int) $state['due_at'] );
			}
		}

		update_option( self::REACHED_OPTION, $reached, false );
	}

	/**
	 * In the account holder's own language, as core writes its own mail to an
	 * account, with the place this account can set it up.
	 */
	private static function send( \WP_User $user, int $due_at ): void {
		if ( ! is_email( $user->user_email ) ) {
			return;
		}

		$switched = switch_to_user_locale( (int) $user->ID );

		try {
			$site = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
			$days = max( 1, (int) ceil( ( $due_at - time() ) / DAY_IN_SECONDS ) );

			wp_mail(
				$user->user_email,
				sprintf(
					/* translators: %s: site name. */
					__( 'Set up two-factor sign-in for %s', 'bettershield' ),
					$site
				),
				sprintf(
					/* translators: 1: site name, 2: number of days, 3: the date the time runs out. */
					_n(
						'%1$s asks you to use two-factor sign-in. You have %2$d day left, until %3$s.',
						'%1$s asks you to use two-factor sign-in. You have %2$d days left, until %3$s.',
						$days,
						'bettershield'
					),
					$site,
					$days,
					wp_date( (string) get_option( 'date_format' ), $due_at )
				) . "\n\n" . sprintf(
					/* translators: %s: where to set it up. */
					__( 'Set it up with a free authenticator app on your phone, such as Google Authenticator or Microsoft Authenticator: %s', 'bettershield' ),
					esc_url_raw( Policy::instance()->enrollment_url_for( $user ) )
				) . "\n\n" . __( 'After that date, you’ll be asked to finish setup each time you sign in before you can use the dashboard.', 'bettershield' )
			);
		} finally {
			if ( $switched ) {
				restore_previous_locale();
			}
		}
	}
}
