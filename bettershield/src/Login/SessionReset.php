<?php
/**
 * When a credential is revoked, the sessions it vouched for end with it.
 *
 * "Change your password" is the canonical response to a stolen account, and
 * core deliberately leaves the second half to the caller: `wp_set_password()`
 * never touches `session_tokens`, so the intruder's session survives the
 * response meant to evict them, for up to fourteen days. The same held for a
 * removed second factor, a removed passkey, and a role change. This class is
 * the one place that rule lives — for every way a password can be set,
 * including the direct call another plugin makes, which is the one this class
 * described and did not cover.
 *
 * Core announces some of these more than once for a single action. Whatever
 * arrives, one action ends the sessions once and is recorded once; see
 * `$done`.
 *
 * The shape of the reset depends on who acted. A person changing their own
 * credential keeps the device they did it on — signing someone out of the
 * screen they are acting from teaches them not to act — and every other
 * session ends. A credential changed from anywhere else (an administrator's
 * reset, a recovery flow with nobody signed in) ends every session, because
 * there is no device known to be the owner's.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Events\Writer;
use BetterShield\Rest\Sudo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SessionReset {

	private static bool $registered = false;

	/**
	 * Accounts already evicted on this request, keyed by user and credential.
	 *
	 * One action reaches this class more than once, and by design rather than
	 * by accident. `WP_User::set_role()` announces the removal, the addition
	 * and the replacement separately, so promoting one account to
	 * administrator — the single most security-relevant thing that can happen
	 * to a user record — arrived three times. `reset_password()` calls
	 * `wp_set_password()` and then fires `after_password_reset`, so a reset
	 * arrives twice.
	 *
	 * The eviction itself is idempotent: the second and third passes find
	 * nothing left to destroy. The record was not. Three identical rows
	 * milliseconds apart tell an owner reading the log after an incident that
	 * three evictions happened, and inflate the same count in the weekly
	 * digest.
	 *
	 * Scoped to the request, which is the unit one action happens in. A
	 * long-running WP-CLI process that changed the same credential on the
	 * same account twice would evict once and record once — the second
	 * eviction has nothing left to destroy in any case, and the alternative
	 * is a window measured in fractions of a second, which is a guess about
	 * how fast core fires three hooks.
	 *
	 * @var array<string, true>
	 */
	private static array $done = array();

	/** Test seam: forget what this request has already evicted. */
	public static function forget_this_request(): void {
		self::$done = array();
	}

	public static function register(): void {
		// Once: a second registration would evict twice and log twice.
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		// The reset flow: reset_password() → wp_set_password(), nobody
		// signed in, and the hash the sessions were minted under is gone.
		add_action(
			'after_password_reset',
			static function ( $user ): void {
				if ( $user instanceof \WP_User ) {
					self::credential_changed( (int) $user->ID, 'password' );
				}
			}
		);

		// A password change from the profile screen or wp_update_user()
		// fires profile_update, not after_password_reset. Only a change to
		// the hash counts — the hook fires for every profile save, and its
		// own third argument already carries the new data, so a save that
		// left the password alone costs no query here.
		add_action(
			'profile_update',
			static function ( int $user_id, $old_user_data, array $userdata = array() ): void {
				if (
					$old_user_data instanceof \WP_User
					&& isset( $userdata['user_pass'] )
					&& (string) $userdata['user_pass'] !== (string) $old_user_data->user_pass
				) {
					self::credential_changed( $user_id, 'password' );
				}
			},
			10,
			3
		);

		/*
		 * The call this class's own docblock names, and the one it did not
		 * listen to. `wp_set_password()` is a public core API and it is what
		 * another security plugin reaches for when force-resetting a
		 * compromised account — precisely the button somebody presses during
		 * an incident. It fires neither hook above, so the administrator got
		 * the new password and the intruder kept the session, for up to
		 * fourteen days, with nothing in the log to say otherwise.
		 *
		 * Not hooked naively, because core calls it on a path where evicting
		 * would be actively wrong: signing in rehashes the stored hash when
		 * the algorithm has moved on, and account creation sets the first
		 * password through the same call. Comparing hashes does not separate
		 * those from a real change — a rehash of the same password produces a
		 * different hash. The plaintext does: on a rehash and on a creation
		 * the new password still matches the hash it is being compared
		 * against, and on a genuine change it does not. That check is load
		 * bearing rather than defensive; without it, signing in after a
		 * hashing change would sign everybody out of every other device.
		 */
		add_action(
			'wp_set_password',
			static function ( $password, $user_id, $old_user_data = null ): void {
				// Core passes the prior record from 6.7, which is the floor.
				// Guarded as a type check rather than as a version one: a
				// filter or a direct caller can still invoke the action with
				// fewer arguments, and there is nothing to compare against
				// then either.
				if ( ! $old_user_data instanceof \WP_User ) {
					return;
				}

				if ( wp_check_password( (string) $password, (string) $old_user_data->user_pass, (int) $user_id ) ) {
					return;
				}

				self::credential_changed( (int) $user_id, 'password' );
			},
			10,
			3
		);

		// A role change that touches privilege re-scopes every session the
		// account holds: a token minted for a subscriber must not quietly
		// become an administrator's, and one minted for an administrator
		// should not outlive the demotion. Changes between ordinary roles —
		// a membership site moving people on every purchase, an expiry cron
		// downgrading a cohort at midnight — evict nobody: that churn is the
		// site working, not a credential changing.
		add_action(
			'set_user_role',
			static function ( int $user_id, string $role, array $old_roles = array() ): void {
				// The first assignment is the account being created; there is
				// no session yet and nothing to re-scope.
				if ( array() === $old_roles ) {
					return;
				}

				self::role_set_changed( $user_id, $old_roles, array( $role ) );
			},
			10,
			3
		);

		// set_user_role fires only when the whole set is replaced. A role
		// added alongside the others — the shape escalation usually takes —
		// or removed from among them arrives on these two instead.
		add_action(
			'add_user_role',
			static function ( int $user_id, string $role ): void {
				$user = get_userdata( $user_id );
				$now  = $user instanceof \WP_User ? (array) $user->roles : array();

				self::role_set_changed( $user_id, array_values( array_diff( $now, array( $role ) ) ), $now );
			},
			10,
			2
		);

		add_action(
			'remove_user_role',
			static function ( int $user_id, string $role ): void {
				$user = get_userdata( $user_id );
				$now  = $user instanceof \WP_User ? (array) $user->roles : array();

				self::role_set_changed( $user_id, array_values( array_merge( $now, array( $role ) ) ), $now );
			},
			10,
			2
		);
	}

	/**
	 * A role set moved from one shape to another: end the sessions only when
	 * the move genuinely changed something and privilege is involved on
	 * either side.
	 *
	 * @param string[] $old_roles
	 * @param string[] $new_roles
	 */
	private static function role_set_changed( int $user_id, array $old_roles, array $new_roles ): void {
		/*
		 * A site being created hands its first administrator their role on
		 * it, the account that created it as a rule. Nothing of that site
		 * existed for a session to have been scoped to, so this is joining a
		 * site, not a credential changing: reset, it signed the super admin
		 * out on every other device each time a site was made, and out of
		 * every session from WP-CLI (#1827).
		 */
		if ( doing_action( 'wp_initialize_site' ) ) {
			return;
		}

		sort( $old_roles );
		sort( $new_roles );

		if ( $old_roles === $new_roles ) {
			return;
		}

		$policy = \BetterShield\Password\Policy::instance();

		if ( ! $policy->roles_are_privileged( $old_roles ) && ! $policy->roles_are_privileged( $new_roles ) ) {
			return;
		}

		self::credential_changed( $user_id, 'role' );
	}

	/**
	 * A credential on this account changed: end the sessions it vouched for,
	 * and close any re-authentication window standing open.
	 *
	 * @param string $what Which credential: password, two_factor, passkey, role.
	 */
	public static function credential_changed( int $user_id, string $what ): void {
		if ( $user_id < 1 ) {
			return;
		}

		// One action, one eviction, one row — however many hooks core fires
		// on the way there. See `$done`.
		$once = $user_id . ':' . $what;

		if ( isset( self::$done[ $once ] ) ) {
			return;
		}

		self::$done[ $once ] = true;

		$own_token = get_current_user_id() === $user_id ? (string) wp_get_session_token() : '';

		if ( '' !== $own_token ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy_others( $own_token );
			$scope = 'others';
		} else {
			\WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			$scope = 'all';
		}

		// A confirmation given under the old credential does not survive it.
		Sudo::forget( $user_id );

		Writer::instance()->record(
			'sessions_reset',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'credential' => $what,
					'scope'      => $scope,
				),
			)
		);
	}
}
