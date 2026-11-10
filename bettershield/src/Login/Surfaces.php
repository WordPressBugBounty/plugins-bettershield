<?php
/**
 * The forms this plugin is allowed to count, and how hard it counts each.
 *
 * Until now there was one: the sign-in form. Everything about the counting
 * machinery assumed it, down to the table names. The list below is what makes
 * the machinery answerable to more than one form without any of them being
 * able to reach the others — a surface is the unit a threshold applies to, and
 * two surfaces never share a total.
 *
 * **Why the numbers here are looser than the sign-in gate's.** A sign-in
 * lockout falls on somebody who is trying to reach a dashboard and who will
 * see, on that same screen, what happened and how long it lasts. A refusal on
 * a public form falls on somebody who may have no account, no way to ask, and
 * no idea this plugin exists. The cost of being wrong is higher and the
 * evidence is thinner, so the thresholds are set where a person doing a normal
 * thing quickly cannot reach them, rather than where an attacker is caught
 * soonest.
 *
 * These are a first position, not a measurement. Real numbers from a fleet
 * running this at scale are what should replace them, and the shape here — a
 * default an owner may override per surface — is built so that replacing them
 * is an edit rather than a migration.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Surfaces {

	/**
	 * The sign-in form, and the only surface that existed before this list.
	 *
	 * Its policy does not live in the table below: it is the four settings an
	 * owner has been able to change since the beginning, and moving them here
	 * would either break their meaning or duplicate it.
	 */
	public const SIGNIN = 'signin';

	public const COMMENT  = 'comment';
	public const RESET    = 'reset';
	public const REGISTER = 'register';

	/**
	 * Requests for pages that do not exist, and for files only a scanner asks
	 * for (#690). Not a form, but counted the same way and kept apart the same
	 * way: a source working through a list of paths on the front end can never
	 * add to a sign-in total.
	 */
	public const PROBE = 'probe';

	/**
	 * Every surface the gate may be asked about.
	 *
	 * `signin` is included because the column records it and a reader asking
	 * "which surfaces are there" should get a true answer, not one missing the
	 * oldest member.
	 *
	 * @var string[]
	 */
	public const ALL = array( self::SIGNIN, self::COMMENT, self::RESET, self::REGISTER, self::PROBE );

	/** The surfaces this class holds a policy for — every one but the sign-in form. */
	public const GATED = array( self::COMMENT, self::RESET, self::REGISTER, self::PROBE );

	/**
	 * The surfaces an owner turns on rather than off. Every request a site
	 * answers with a 404 runs through this one, so it counts nothing until
	 * somebody chose a number for it: nothing blocks a request the owner has
	 * not configured a threshold for.
	 *
	 * @var string[]
	 */
	public const OFF_BY_DEFAULT = array( self::PROBE );

	/**
	 * What each surface does when its threshold is passed.
	 *
	 * `hold` is the comment answer and the reason this is a field rather than
	 * an assumption: a comment over the threshold goes to the moderation queue
	 * instead of being refused, because a false positive somebody can still
	 * find and approve is recoverable and one that vanished is not.
	 */
	public const ACTION_REFUSE = 'refuse';
	public const ACTION_HOLD   = 'hold';

	/**
	 * The probe answer: a page that was missing anyway is answered with a
	 * plain 404 instead of the theme's. Pages that exist keep loading, and no
	 * firewall line is written, so a crawler caught after a site move loses
	 * nothing it could have had.
	 */
	public const ACTION_BARE = 'bare';

	/**
	 * Defaults per gated surface.
	 *
	 * threshold        — attempts inside the window before the surface closes.
	 * window_minutes   — how far back the count reaches.
	 * lockout_minutes  — how long the surface stays closed to that source.
	 * action           — what passing the threshold does.
	 *
	 * @return array<string, array{threshold: int, window_minutes: int, lockout_minutes: int, action: string}>
	 */
	public static function defaults(): array {
		return array(
			/*
			 * Ten in ten minutes. A person in a lively thread might post three
			 * or four; ten is a script. The action is the reason this number
			 * can afford to be generous — nothing is refused at it, a comment
			 * is queued for a human, so the cost of catching a real person is
			 * a delay rather than a loss.
			 */
			self::COMMENT  => array(
				'threshold'       => 10,
				'window_minutes'  => 10,
				'lockout_minutes' => 30,
				'action'          => self::ACTION_HOLD,
			),

			/*
			 * Eight in fifteen minutes. Somebody whose mail is slow will ask
			 * two or three times; eight is somebody working through a list of
			 * addresses. Deliberately above the sign-in threshold: this form
			 * is the one a person reaches for when they are already locked out
			 * of something, and it must not be the second door that closes.
			 */
			self::RESET    => array(
				'threshold'       => 8,
				'window_minutes'  => 15,
				'lockout_minutes' => 15,
			   'action'          => self::ACTION_REFUSE,
			),

			/*
			 * Eight in an hour. Sign-ups are not a thing one person does
			 * repeatedly, so the window is long and the count still generous —
			 * an office behind one address signing up together is the case
			 * this must not catch, and the confidence rule already spares the
			 * address it cannot verify.
			 */
			self::REGISTER => array(
				'threshold'       => 8,
				'window_minutes'  => 60,
				'lockout_minutes' => 60,
				'action'          => self::ACTION_REFUSE,
			),

			/*
			 * Twenty different missing pages in ten minutes. A reader who
			 * follows a few dead links is nowhere near it; a scanner working
			 * through a word list passes it in seconds. Distinct paths only,
			 * so a broken image on every page view counts once.
			 */
			self::PROBE    => array(
				'threshold'       => 20,
				'window_minutes'  => 10,
				'lockout_minutes' => 60,
				'action'          => self::ACTION_BARE,
			),
		);
	}

	/** Whether a string names a surface this plugin knows. */
	public static function known( string $surface ): bool {
		return in_array( $surface, self::ALL, true );
	}

	/**
	 * A surface's label, for the log and the screen.
	 *
	 * @return string
	 */
	public static function label( string $surface ): string {
		$labels = array(
			self::SIGNIN   => __( 'Sign-in', 'bettershield' ),
			self::COMMENT  => __( 'Comments', 'bettershield' ),
			self::RESET    => __( 'Password resets', 'bettershield' ),
			self::REGISTER => __( 'Registration', 'bettershield' ),
			self::PROBE    => __( 'Missing pages', 'bettershield' ),
		);

		return $labels[ $surface ] ?? $surface;
	}
}
