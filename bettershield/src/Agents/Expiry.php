<?php
/**
 * Retiring an application password nobody has used.
 *
 * An application password is a long-lived bearer credential. WordPress gives
 * it no expiry at all, so on an agency site they accumulate: a plugin somebody
 * trialled two years ago, a deploy script from an agency that no longer has
 * the contract, a phone app that was uninstalled. Every one of them still
 * opens the site, and nobody remembers they exist.
 *
 * **Off by default, and it stays off until somebody chooses.** This revokes
 * credentials, and a plugin that starts revoking credentials on an update is a
 * plugin that breaks somebody's deploy at three in the morning.
 *
 * **It is the one thing this plugin does that cannot be undone.** Everything
 * else puts back exactly what it changed. A revoked application password
 * cannot be put back, because the secret was never stored — only its hash, and
 * that goes with it. So the copy says so plainly rather than implying the
 * usual safety net, and the log records the name of every one retired, which
 * is the only thing anybody can act on afterwards: whoever owned it makes a
 * new one, and they need to know which one to make.
 *
 * **Never the credential the request arrived on.** A sweep that retired the
 * key running it would lock out whatever ran it, mid-run.
 *
 * **Nor the decoy this plugin plants.** Going unused is the whole of what a
 * decoy is for, so a sweep that retires the unused would take that one first
 * and leave nothing watching.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Expiry {

	public const OPTION = 'bettershield_app_password_expiry';

	/**
	 * The shortest window that may be chosen.
	 *
	 * A credential can go a month unused and still be the one that runs the
	 * quarterly export. Below this, the setting stops retiring the forgotten
	 * and starts retiring the occasional.
	 */
	public const MIN_DAYS = 30;

	/** The longest window that may be chosen: ten years. */
	public const MAX_DAYS = 3650;

	/**
	 * How many credentials one run looks at. The task runs unattended and
	 * deletes as it goes, so it is bounded rather than however many the site
	 * happens to hold; what it does not reach, the next run does.
	 */
	public const SWEEP_MAX = 500;

	/** And how long one run may spend, whatever it has got through. */
	public const SWEEP_SECONDS = 10;

	/** @return array{enabled: bool, days: int} */
	public function defaults(): array {
		return array(
			'enabled' => false,
			'days'    => 180,
		);
	}

	/** @return array{enabled: bool, days: int} */
	public function settings(): array {
		$stored   = get_option( self::OPTION, array() );
		$stored   = is_array( $stored ) ? $stored : array();
		$defaults = $this->defaults();

		return array(
			'enabled' => (bool) ( $stored['enabled'] ?? $defaults['enabled'] ),
			'days'    => max( self::MIN_DAYS, (int) ( $stored['days'] ?? $defaults['days'] ) ),
		);
	}

	/**
	 * What a save would store, or the refusal it would meet.
	 *
	 * Separate from the save so an import can be planned by the same rule the
	 * apply enforces: a plan computed any other way is a description of
	 * something else.
	 *
	 * @param array<string, mixed> $input
	 * @return array{enabled: bool, days: int}|\WP_Error
	 */
	public function validate( array $input ) {
		$current = $this->settings();

		// A yes or a no, and nothing else: cast, the word "false" was a yes,
		// and switching this on starts revoking passwords that cannot be
		// restored. The route and a settings document both read through here.
		if ( isset( $input['enabled'] ) && ! is_bool( $input['enabled'] ) ) {
			return new \WP_Error(
				'bettershield_bad_enabled',
				__( 'Retiring unused application passwords must be true or false.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		$days = isset( $input['days'] ) ? (int) $input['days'] : $current['days'];

		if ( $days < self::MIN_DAYS ) {
			return new \WP_Error(
				'bettershield_bad_expiry',
				sprintf(
					/* translators: %d: the smallest number of days that may be chosen. */
					__( 'Choose at least %d days, so rarely used passwords are not retired too soon.', 'bettershield' ),
					self::MIN_DAYS
				),
				array( 'status' => 400 )
			);
		}

		// Its own sentence: the floor's said nothing to somebody past the
		// ceiling about what to type instead.
		if ( $days > self::MAX_DAYS ) {
			return new \WP_Error(
				'bettershield_bad_expiry',
				sprintf(
					/* translators: %d: the largest number of days that may be chosen. */
					__( 'Choose %d days or fewer.', 'bettershield' ),
					self::MAX_DAYS
				),
				array( 'status' => 400 )
			);
		}

		return array(
			'enabled' => $input['enabled'] ?? $current['enabled'],
			'days'    => $days,
		);
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{enabled: bool, days: int}|\WP_Error
	 */
	public function update_settings( array $input ) {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		/*
		 * Before the write, so the way back exists whether or not it succeeds.
		 * What is reversible is the decision; the credentials a sweep has
		 * already retired are gone, and the copy says so.
		 *
		 * False is the one answer that stops this: there was a prior state and
		 * it could not be written down. Going on from there switches an
		 * unattended sweep of somebody's credentials on with no record of what
		 * it was before.
		 */
		if ( false === \BetterShield\Undo\SettingsLedger::record( 'app_password_expiry', $this->settings(), $next ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $next, false );

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => 'app_password_expiry',
				'context'     => array(
					'enabled' => $next['enabled'],
					'days'    => $next['days'],
				),
			)
		);

		return $next;
	}

	/**
	 * Retire what has gone unused past the chosen window.
	 *
	 * Bounded twice, because this deletes credentials on an unattended task
	 * and the sites it exists for are the ones with thousands of them: it
	 * looks at a fixed number per run, and it stops early if the run has been
	 * going long enough that the host might end it mid-delete. Where it
	 * stopped is kept, so the next run starts there rather than spending its
	 * whole allowance on the same first accounts every night and never
	 * reaching what is behind them. The walk is by account id, ascending, and
	 * a finished run starts over.
	 *
	 * @return array{retired: int, considered: int, finished: bool}
	 */
	public function sweep(): array {
		$settings = $this->settings();
		$outcome  = array(
			'retired'    => 0,
			'considered' => 0,
			'finished'   => true,
		);

		if ( ! $settings['enabled'] || ! class_exists( 'WP_Application_Passwords' ) ) {
			return $outcome;
		}

		/**
		 * How many credentials one run may look at.
		 *
		 * @param int $max The default, self::SWEEP_MAX.
		 */
		$max = max( 1, (int) apply_filters( 'bettershield_app_password_sweep_max', self::SWEEP_MAX ) );

		/**
		 * How long one run may spend, in seconds.
		 *
		 * @param int $seconds The default, self::SWEEP_SECONDS.
		 */
		$deadline = microtime( true ) + max( 1, (int) apply_filters( 'bettershield_app_password_sweep_seconds', self::SWEEP_SECONDS ) );

		$cutoff  = time() - ( $settings['days'] * DAY_IN_SECONDS );
		$in_use  = self::credential_in_use();
		// The sweep is already a write and already runs with nobody waiting on
		// it, so it is where a record whose credential has gone is tidied away.
		Canary::reconcile();

		$resume  = self::resume_after();
		$reached = $resume;
		$stored = get_option( self::OPTION, array() );
		$resume_user = (int) ( $stored['swept_user'] ?? 0 );
		$resume_uuid = (string) ( $stored['swept_uuid'] ?? '' );
		$partial_user = 0;
		$partial_uuid = '';

		foreach ( \BetterShield\Abilities\AgentSurface::application_passwords() as $holder ) {
			$user_id = (int) $holder['user_id'];

			// Already looked at, in a run that ran out of allowance before it
			// reached the end.
			if ( $user_id <= $resume ) {
				continue;
			}

			if ( $outcome['considered'] >= $max || microtime( true ) >= $deadline ) {
				$outcome['finished'] = false;
				break;
			}

			// A stable credential cursor makes progress even when one account has
			// more current (non-retiring) credentials than a whole run can inspect.
			$passwords = \WP_Application_Passwords::get_user_application_passwords( $user_id );
			usort( $passwords, static fn( $a, $b ) => strcmp( (string) ( $a['uuid'] ?? '' ), (string) ( $b['uuid'] ?? '' ) ) );
			$last_uuid = $user_id === $resume_user ? $resume_uuid : '';
			foreach ( $passwords as $password ) {
				$uuid = (string) ( $password['uuid'] ?? '' );
				if ( '' !== $last_uuid && strcmp( $uuid, $last_uuid ) <= 0 ) { continue; }
				if ( $outcome['considered'] >= $max || microtime( true ) >= $deadline ) {
					$outcome['finished'] = false;
					$partial_user = $user_id;
					$partial_uuid = $last_uuid;
					break 2;
				}
				++$outcome['considered'];
				$last_uuid = $uuid;

				// Never the one this request arrived on: retiring it would
				// lock out whatever is running the sweep, mid-run.
				if ( '' === $uuid || ( '' !== $in_use && $uuid === $in_use ) ) {
					continue;
				}

				// Never the decoy either. Going unused is what it is for, so
				// this sweep would retire it ahead of anything else and leave
				// nothing watching. Asked of the credential rather than of
				// this site's record: on a network the record belongs to the
				// site that planted it and the credential to every site, so
				// a sweep next door had no record to read and retired it. The
				// account goes with it, because the decoy's name is public and
				// an exemption anybody could claim by naming their own
				// credential after it is not one.
				if ( Canary::is_decoy( $password, $user_id ) ) {
					continue;
				}

				/*
				 * Never used counts from creation. Dormant since birth is the
				 * staler state, not a fresher one — and a credential issued
				 * and never touched is the commonest kind of forgotten.
				 */
				$last = (int) ( $password['last_used'] ?? 0 );
				$last = $last > 0 ? $last : (int) ( $password['created'] ?? time() );

				if ( $last > $cutoff ) {
					continue;
				}

				$removed = \WP_Application_Passwords::delete_application_password( $user_id, $uuid );

				if ( is_wp_error( $removed ) || ! $removed ) {
					continue;
				}

				++$outcome['retired'];

				Writer::instance()->record(
					'app_password_revoked',
					Writer::SEVERITY_MEDIUM,
					array(
						'actor_type'  => 'system',
						'object_type' => 'app_password',
						'object_id'   => $uuid,
						'context'     => array(
							// The name, because it is the only thing anybody
							// can act on afterwards: whoever owned this makes
							// a new one, and needs to know which.
							'name'        => \BetterShield\Support\Text::clip( (string) ( $password['name'] ?? '' ), 100 ),
							'user'        => (string) $holder['login'],
							'unused_days' => (int) floor( ( time() - $last ) / DAY_IN_SECONDS ),
							'reason'      => 'unused',
						),
					)
				);
			}
			$reached = $user_id;
		}

		// A run that reached the end starts over; one that did not says where
		// it got to, so the next carries on rather than repeating itself.
		self::remember_reached( $outcome['finished'] ? 0 : $reached, $partial_user, $partial_uuid );

		return $outcome;
	}

	/**
	 * The account the last run stopped after, or 0 when it finished.
	 */
	private static function resume_after(): int {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? (int) ( $stored['swept_after'] ?? 0 ) : 0;
	}

	/**
	 * Kept beside the setting rather than in an option of its own: it is one
	 * integer, it is read only by the run that follows, and a settings save
	 * that drops it costs nothing more than a sweep starting over.
	 */
	private static function remember_reached( int $user_id, int $partial_user = 0, string $partial_uuid = '' ): void {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		if ( (int) ( $stored['swept_after'] ?? 0 ) === $user_id && (int) ( $stored['swept_user'] ?? 0 ) === $partial_user && (string) ( $stored['swept_uuid'] ?? '' ) === $partial_uuid ) {
			return;
		}

		$stored['swept_after'] = $user_id;
		$stored['swept_user'] = $partial_user;
		$stored['swept_uuid'] = $partial_uuid;

		update_option( self::OPTION, $stored, false );
	}

	/**
	 * The application password this request authenticated with, if any.
	 *
	 * Core records it for the length of the request; an empty answer means
	 * this is not an application-password request at all, which is the case
	 * for a cron tick and for somebody pressing a button in the dashboard.
	 */
	private static function credential_in_use(): string {
		if ( ! function_exists( 'rest_get_authenticated_app_password' ) ) {
			return '';
		}

		$uuid = rest_get_authenticated_app_password();

		return is_string( $uuid ) ? $uuid : '';
	}
}
