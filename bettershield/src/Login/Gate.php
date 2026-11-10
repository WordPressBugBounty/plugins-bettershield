<?php
/**
 * Counting attempts and closing a surface, for any surface.
 *
 * This is the machinery the sign-in gate has always had, lifted out of it so
 * that a second form can use the same decision rather than a second copy of
 * it. A copy is how two gates drift: one learns that an unverified address may
 * not be locked and the other does not, and the plugin locks out an office
 * through the door nobody re-read.
 *
 * What stayed behind in `Protection` is everything that is about signing in
 * specifically — the refusal codes, the emailed unlock link, the blocked-name
 * list, which messages a person needs in order to get back in. What moved here
 * is arithmetic and two tables.
 *
 * **Surfaces never share a total.** Every read and every write in this class
 * carries a surface, and the count for one is invisible to the others. That is
 * the whole safety property of adding gates to public forms: a flood of
 * refused comments is a comment problem, and it can never become the reason an
 * owner cannot reach their own dashboard.
 *
 * **The rules that are not negotiable per surface**, because they are the ones
 * that protect people rather than the site: an address the resolution could
 * not vouch for is recorded and never locked, since it may be a thousand
 * people behind one proxy; an allowlisted address is not counted at all; and
 * safe mode stands every surface down, because somebody recovering a site is
 * doing it through these same forms.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\AuthLog;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Ip;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- plugin-owned tables with no core API, deliberately uncached: a lockout decision made from a stale cache is wrong in both directions.

final class Gate {

	/**
	 * Whether the column that separates surfaces is on this site yet.
	 *
	 * New files arrive before the migration does. On a front-end request the
	 * upgrade is deliberately deferred to `shutdown`, so a visitor never pays
	 * for DDL — which leaves a real window, between deploying and the first
	 * admin page load, where this code is running and that column is not
	 * there. Naming it in a query through that window does not just log an
	 * error: the query returns nothing, and a lockout that answers "nobody is
	 * locked out" has quietly stopped enforcing.
	 *
	 * So every query below asks first. Before the column exists there is
	 * exactly one surface — these tables have never held anything else — and
	 * the un-surfaced query is therefore the correct query, not a degraded
	 * one. The public forms stand down until it lands, because they are the
	 * ones that would be wrong.
	 */
	public static function surfaced(): bool {
		return Schema::ready( 'request_surfaces' );
	}

	/**
	 * Whether this request is the site's own work rather than a public form.
	 *
	 * `lostpassword_post` is not fired only by the public lost-password form:
	 * core fires it again from `wp_ajax_send_password_reset()`, which is the
	 * Send Reset Link button on a user's profile. Counting that on the public
	 * surface breaks the isolation in the direction nobody checked — activity
	 * on a public form can never lock an owner out of their dashboard, but a
	 * dashboard action was feeding the public form's total — and refusing it
	 * answers an AJAX request with a redirect the script cannot read.
	 *
	 * Both halves are needed. `admin-ajax.php` reports `is_admin()` true for
	 * signed-out visitors too, so the context alone would exempt an attacker;
	 * and a store's lost-password form runs on the front end for a signed-out
	 * visitor, so a capability alone would still gate the dashboard. Scheduled
	 * work has no visitor behind it at all.
	 *
	 * The sign-in surface is never exempted here: it is the one surface whose
	 * whole purpose is refusing somebody who is not signed in yet.
	 */
	private static function site_side_request( string $surface ): bool {
		if ( Surfaces::SIGNIN === $surface ) {
			return false;
		}

		if ( wp_doing_cron() ) {
			return true;
		}

		// The dashboard's own REST calls are the same work by the same people:
		// an incident response sending a reset link runs there, and a closed
		// public form must neither count it nor end the request with a
		// redirect. A REST request resolves no user without a valid nonce or
		// credential, so the capability below still gates it.
		if ( ! is_admin() && ! wp_doing_ajax() && ! wp_is_serving_rest_request() ) {
			return false;
		}

		return is_user_logged_in() && current_user_can( 'edit_users' );
	}

	/**
	 * Record one attempt against a surface.
	 *
	 * `$subject` is whatever identifies what was being attempted — a username
	 * on the sign-in form, the address a reset was asked for. It is stored
	 * through the same clipping every identifier here goes through and is
	 * never the raw field.
	 *
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 */
	public static function record( string $surface, array $resolved, string $subject = '', string $outcome = 'failed' ): void {
		global $wpdb;

		$row = array(
			'site_id'     => 0,
			'occurred_at' => Time::stamp(),
			'ip_hmac'     => ClientIp::lockout_hmac( $resolved ),
			'ip_prefix'   => Ip::truncated_binary( $resolved['ip'] ),
			'username'    => $subject,
			'outcome'     => $outcome,
			'method'      => $resolved['method'],
		);

		if ( self::surfaced() ) {
			$row['surface'] = $surface;
		}

		$wpdb->insert( Schema::table( 'login_attempts' ), $row );
	}

	/**
	 * How many failures this source has on this surface inside the window.
	 *
	 * Failures older than the surface's last lockout are excluded by the
	 * caller passing a later `$since`: they have already been answered once,
	 * and counting them again re-locks somebody on their very next slip.
	 */
	public static function failures_since( string $surface, string $hmac, string $since ): int {
		global $wpdb;

		if ( ! self::surfaced() ) {
			return (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND ip_hmac = %s AND outcome = 'failed' AND occurred_at > %s",
					Schema::table( 'login_attempts' ),
					$hmac,
					$since
				)
			);
		}

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND outcome = 'failed' AND occurred_at > %s",
				Schema::table( 'login_attempts' ),
				$surface,
				$hmac,
				$since
			)
		);
	}

	/**
	 * Whether this source already has a failure on this surface carrying this
	 * subject since a moment. The probe surface counts distinct paths, so a
	 * missing image asked for on every page view counts once.
	 */
	public static function counted( string $surface, string $hmac, string $subject, string $since ): bool {
		global $wpdb;

		if ( ! self::surfaced() ) {
			return false;
		}

		return null !== $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND username = %s AND outcome = 'failed' AND occurred_at > %s LIMIT 1",
				Schema::table( 'login_attempts' ),
				$surface,
				$hmac,
				$subject,
				$since
			)
		);
	}

	/**
	 * The names this source's failures on this surface carried since a
	 * moment, at most `$limit` of them. Each is the clipped identifier
	 * `record()` stored, so every spelling of one account reads as its login.
	 *
	 * @return list<string>
	 */
	public static function subjects_since( string $surface, string $hmac, string $since, int $limit = 2 ): array {
		global $wpdb;

		$subjects = self::surfaced()
			? $wpdb->get_col(
				$wpdb->prepare(
					"SELECT DISTINCT username FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND outcome = 'failed' AND occurred_at > %s LIMIT %d",
					Schema::table( 'login_attempts' ),
					$surface,
					$hmac,
					$since,
					$limit
				)
			)
			: $wpdb->get_col(
				$wpdb->prepare(
					"SELECT DISTINCT username FROM %i WHERE site_id = 0 AND ip_hmac = %s AND outcome = 'failed' AND occurred_at > %s LIMIT %d",
					Schema::table( 'login_attempts' ),
					$hmac,
					$since,
					$limit
				)
			);

		return array_values( array_map( 'strval', (array) $subjects ) );
	}

	/**
	 * When this source was last locked out of this surface, or null.
	 *
	 * @return string|null
	 */
	public static function last_lockout_started( string $surface, string $hmac ): ?string {
		global $wpdb;

		$started = self::surfaced()
			? $wpdb->get_var(
				$wpdb->prepare(
					'SELECT started_at FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s ORDER BY id DESC LIMIT 1',
					Schema::table( 'lockouts' ),
					$surface,
					$hmac
				)
			)
			: $wpdb->get_var(
				$wpdb->prepare(
					'SELECT started_at FROM %i WHERE site_id = 0 AND ip_hmac = %s ORDER BY id DESC LIMIT 1',
					Schema::table( 'lockouts' ),
					$hmac
				)
			);

		return is_string( $started ) ? $started : null;
	}

	/** The longest a lockout grows to, however often its source returns. */
	public const LONGEST_LOCKOUT_MINUTES = 1440;

	/**
	 * How long a new lockout of this source lasts, and how many before it in
	 * the last day it is longer for.
	 *
	 * A lockout of fixed length is a schedule to a patient source: wait it
	 * out, try again. So each earlier lockout of the same source, on the same
	 * surface, in the last day doubles the next, up to a day. The source is
	 * the same key the lockout itself is held against, so a proxy the site
	 * trusts is seen through the same way.
	 *
	 * A release starts the count over. An administrator's release and the
	 * owner's own unlock link both say the source was not the problem, so
	 * neither the lockout released nor any before it counts, the next one
	 * starts from the configured length again, and the way back in is never
	 * made longer by having been used.
	 *
	 * @return array{minutes: int, repeat: int}
	 */
	public static function escalation( string $surface, string $hmac, int $minutes ): array {
		global $wpdb;

		$since = Time::stamp( time() - DAY_IN_SECONDS );

		/*
		 * A release starts the count over: only lockouts that began after the
		 * source's last release count. The owner's emailed link releases the
		 * lockout still running and leaves one that already ran out on its
		 * own, so counting unreleased rows alone kept doubling a pause its
		 * owner had ended with the link.
		 */
		$released = self::surfaced()
			? $wpdb->get_var(
				$wpdb->prepare(
					'SELECT MAX(released_at) FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND released_at IS NOT NULL',
					Schema::table( 'lockouts' ),
					$surface,
					$hmac
				)
			)
			: $wpdb->get_var(
				$wpdb->prepare(
					'SELECT MAX(released_at) FROM %i WHERE site_id = 0 AND ip_hmac = %s AND released_at IS NOT NULL',
					Schema::table( 'lockouts' ),
					$hmac
				)
			);

		if ( is_string( $released ) && $released > $since ) {
			$since = $released;
		}

		$earlier = self::surfaced()
			? $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND released_at IS NULL AND started_at >= %s',
					Schema::table( 'lockouts' ),
					$surface,
					$hmac,
					$since
				)
			)
			: $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM %i WHERE site_id = 0 AND ip_hmac = %s AND released_at IS NULL AND started_at >= %s',
					Schema::table( 'lockouts' ),
					$hmac,
					$since
				)
			);

		// Eleven doublings pass a day from any length this accepts.
		$repeat = min( 11, max( 0, (int) $earlier ) );

		return array(
			'minutes' => max( $minutes, min( self::LONGEST_LOCKOUT_MINUTES, $minutes * ( 2 ** $repeat ) ) ),
			'repeat'  => $repeat,
		);
	}

	/**
	 * The lockout running against this source on this surface, or null.
	 *
	 * @return object|null
	 */
	public static function active_lockout( string $surface, string $hmac ) {
		global $wpdb;

		if ( ! self::surfaced() ) {
			return $wpdb->get_row(
				$wpdb->prepare(
					'SELECT id, expires_at, unlock_token_hash, last_username FROM %i WHERE site_id = 0 AND ip_hmac = %s AND released_at IS NULL AND expires_at > %s ORDER BY id DESC LIMIT 1',
					Schema::table( 'lockouts' ),
					$hmac,
					Time::stamp()
				)
			);
		}

		return $wpdb->get_row(
			$wpdb->prepare(
				'SELECT id, expires_at, unlock_token_hash, last_username FROM %i WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND released_at IS NULL AND expires_at > %s ORDER BY id DESC LIMIT 1',
				Schema::table( 'lockouts' ),
				$surface,
				$hmac,
				Time::stamp()
			)
		);
	}

	/**
	 * Give a running lockout a new unlock token, for a link asked for after
	 * the one it opened with was never sent.
	 */
	public static function replace_unlock_token( int $lockout_id, string $token_hash ): bool {
		global $wpdb;

		return 1 === (int) $wpdb->update(
			Schema::table( 'lockouts' ),
			array( 'unlock_token_hash' => $token_hash ),
			array( 'id' => $lockout_id ),
			array( '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Open a lockout on a surface and return its row id.
	 *
	 * `$token_hash` backs an emailed way out and belongs to the sign-in
	 * surface alone. A public form has nobody to send such a link to — the
	 * person on the other side of it may have no account at all — so those
	 * lockouts carry none and end the way they were always going to: by
	 * expiring, or by an owner clearing them.
	 *
	 * Returns 0, and opens nothing, when one is already running or another
	 * request is opening it. Two failures crossing the threshold together
	 * both found none running and both opened one: two announcements, two
	 * mails, and a row that counted as a repeat and doubled the next
	 * lockout. Taking the key first, and looking again once it is held, is
	 * the one statement the database settles. A key that cannot be taken
	 * because the table will not answer does not stop the lockout.
	 *
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 */
	public static function open_lockout( string $surface, array $resolved, int $attempts, string $subject, int $minutes, ?string $token_hash = null ): int {
		$hmac  = ClientIp::lockout_hmac( $resolved );
		$claim = 'lockout_open_' . $surface . '_' . $hmac;
		$taken = Claim::claim( $claim, MINUTE_IN_SECONDS );

		if ( ! $taken && Claim::held( $claim ) ) {
			return 0;
		}

		try {
			if ( null !== self::active_lockout( $surface, $hmac ) ) {
				return 0;
			}

			return self::insert_lockout( $surface, $resolved, $attempts, $subject, $minutes, $token_hash );
		} finally {
			if ( $taken ) {
				Claim::release( $claim );
			}
		}
	}

	/**
	 * Write a lockout row and return its id.
	 *
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 */
	private static function insert_lockout( string $surface, array $resolved, int $attempts, string $subject, int $minutes, ?string $token_hash ): int {
		global $wpdb;

		$row = array(
			'site_id'           => 0,
			'ip_hmac'           => ClientIp::lockout_hmac( $resolved ),
			'ip_prefix'         => Ip::truncated_binary( $resolved['ip'] ),
			'started_at'        => Time::stamp(),
			'expires_at'        => Time::stamp( time() + $minutes * 60 ),
			'attempts'          => $attempts,
			'last_username'     => $subject,
			'unlock_token_hash' => $token_hash,
		);

		if ( self::surfaced() ) {
			$row['surface'] = $surface;
		}

		$wpdb->insert( Schema::table( 'lockouts' ), $row );

		return (int) $wpdb->insert_id;
	}

	/**
	 * The whole decision for a gated surface, in one call.
	 *
	 * Returns the lockout id when this attempt was the one that closed the
	 * surface, and null every other time — including when the surface was
	 * already closed, so a caller cannot announce the same lockout twice.
	 * An attempt that crossed the threshold at the same moment as another
	 * closed it too, and is answered with that lockout's id (0 while it is
	 * still being written); only the one that opened it announces it.
	 *
	 * Every guard that spares a person rather than the site is here rather
	 * than in the callers, because a caller that forgets one is a caller that
	 * locks out an office: safe mode stands the gate down, an address nothing
	 * vouched for is recorded and never locked, and an allowlisted address is
	 * not even recorded.
	 *
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 * @param array{threshold: int, window_minutes: int, lockout_minutes: int, action: string} $policy
	 */
	public static function note_failure( string $surface, array $resolved, array $policy, string $subject = '' ): ?int {
		if ( SafeMode::is_active() || '' === $resolved['ip'] ) {
			return null;
		}

		// Not counted at all, rather than counted and spared: a total that
		// includes an address the owner vouched for is a total that closes the
		// surface on somebody else's behalf the moment the exemption is
		// removed.
		if ( Protection::instance()->is_allowlisted( $resolved['ip'] ) ) {
			return null;
		}

		if ( self::site_side_request( $surface ) ) {
			return null;
		}

		// A surface other than the sign-in form cannot be counted correctly
		// until the column that keeps surfaces apart exists. Standing down is
		// the only honest answer: counting into the sign-in total is the one
		// outcome this whole design exists to prevent.
		if ( Surfaces::SIGNIN !== $surface && ! self::surfaced() ) {
			return null;
		}

		self::record( $surface, $resolved, $subject );

		// The shared-proxy guard, stated as code: no confidence, no lockout.
		if ( ! $resolved['confident'] ) {
			return null;
		}

		$hmac  = ClientIp::lockout_hmac( $resolved );
		$since = Time::stamp( time() - $policy['window_minutes'] * 60 );
		$last  = self::last_lockout_started( $surface, $hmac );

		if ( null !== $last && $last > $since ) {
			$since = $last;
		}

		$failures = self::failures_since( $surface, $hmac, $since );

		if ( $failures < $policy['threshold'] || null !== self::active_lockout( $surface, $hmac ) ) {
			return null;
		}

		$id = self::open_lockout( $surface, $resolved, $failures, $subject, $policy['lockout_minutes'] );

		// Another failure crossing the threshold at the same moment opened it
		// first, and announces it. This attempt is over the limit all the
		// same, so the caller is still told to refuse it: the lockout's id,
		// or 0 while the other request is still writing it.
		if ( 0 === $id ) {
			$running = self::active_lockout( $surface, $hmac );

			return null !== $running ? (int) $running->id : 0;
		}

		Writer::instance()->record(
			'surface_closed',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'lockout',
				'object_id'   => (string) $id,
				'context'     => array(
					'surface'  => $surface,
					'attempts' => $failures,
					'method'   => $resolved['method'],
					'minutes'  => $policy['lockout_minutes'],
					'action'   => $policy['action'],
				),
			)
		);

		// Only a form that refuses. One that holds a comment for moderation
		// turns nobody away, and a firewall ban on its network would.
		if ( Surfaces::ACTION_REFUSE === $policy['action'] ) {
			AuthLog::lockout( $surface, $resolved['ip'], $policy['lockout_minutes'] );
		}

		return $id;
	}

	/**
	 * Whether this source is currently shut out of this surface.
	 *
	 * Safe mode answers no for every surface, unconditionally. Somebody
	 * recovering a site reaches for these same forms, and a recovery that runs
	 * into a lockout the recovery itself cannot clear is not a recovery.
	 *
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 */
	public static function closed( string $surface, array $resolved ): bool {
		if ( SafeMode::is_active() || '' === $resolved['ip'] ) {
			return false;
		}

		if ( Protection::instance()->is_allowlisted( $resolved['ip'] ) ) {
			return false;
		}

		if ( self::site_side_request( $surface ) ) {
			return false;
		}

		return null !== self::active_lockout( $surface, ClientIp::lockout_hmac( $resolved ) );
	}
}
