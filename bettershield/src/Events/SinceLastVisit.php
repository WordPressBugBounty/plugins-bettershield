<?php
/**
 * What changed on this site since the person reading last looked at it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BetterShield\Database\Schema;
use BetterShield\Support\Tier;
use BetterShield\Support\Time;

/*
 * A plugin-owned table with no core API, read without a cache: an answer served
 * from a stale copy would omit the most recent change, which is the entry most
 * likely to be the reason somebody opened the screen.
 */
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching

/**
 * Everything here is already in the activity log, and that is the problem this
 * solves. A new administrator, a role change and a protection being switched
 * off are each one line in a flat list of hundreds, indistinguishable from a
 * successful sign-in — so the owner who opens the dashboard once a fortnight
 * has no way to see what happened while they were away short of reading the
 * whole thing.
 *
 * **The list of types is curated rather than driven by severity, and the two
 * questions are genuinely different.** Severity answers "how bad is this";
 * this answers "did somebody change something". A flood of failed sign-ins is
 * high severity and is not a change — it is the site working. A plugin being
 * activated is a change and carries no severity at all. Filtering on severity
 * would have produced a list that was loud and not about change.
 *
 * **A visit is not a page load**, and that takes two stamps rather than one.
 * One moves on every request and exists only to tell a refresh from a return;
 * the other is what "since" means for the sitting in progress and holds still
 * until a return moves it. With a single stamp the block emptied on refresh —
 * advancing it on the first request of a visit meant the second request
 * computed from the new value and found nothing, which is precisely the
 * failure this is built to avoid.
 *
 * The window is clamped to what the log still holds. Saying "since your last
 * visit" over a window that reaches further back than retention would be a
 * claim about a period this plugin cannot see, so when that happens the answer
 * says which it is.
 */
final class SinceLastVisit {

	/**
	 * Two stamps, because one cannot answer both questions.
	 *
	 * `LAST_SEEN` moves on every request and exists only to tell a refresh
	 * from a return. `WINDOW` is what "since" actually means for the sitting
	 * in progress, and holds still until a return moves it.
	 *
	 * Built with one stamp first, and the single stamp had the defect the
	 * whole design exists to avoid: advancing it on the first request of a
	 * visit meant the next request computed from the new value and found
	 * nothing, so the block emptied on refresh.
	 */
	private const META        = 'bettershield_last_overview_visit';
	private const META_WINDOW = 'bettershield_overview_visit_window';

	/**
	 * How long a gap makes the next look a new visit.
	 *
	 * Half an hour: long enough that reading the screen, opening a finding and
	 * coming back is all one sitting, and short enough that picking it up
	 * after lunch is a fresh one.
	 */
	public const VISIT_GAP = 1800;

	/** How many changes are named before the rest are counted. */
	public const MAX_LISTED = 8;

	/**
	 * The changes worth leading a dashboard with: somebody gained privilege,
	 * code that runs on the site changed, or a protection moved.
	 *
	 * Deliberately not every security type. `login_failed` belongs in the log
	 * and not here; so does a successful sign-in. What is here is the set an
	 * owner returning after a week would want to be told without having to ask.
	 */
	public const CHANGE_TYPES = array(
		// Somebody can do more than they could.
		'user_created',
		'user_role_changed',
		'user_role_granted',
		'user_role_revoked',
		'role_capabilities_changed',
		'user_deleted',
		'temporary_access_end_refused',
		// Code that runs on this site.
		'plugin_activated',
		'plugin_deactivated',
		'plugin_installed',
		'plugin_deleted',
		'theme_changed',
		'core_updated',
		'file_changed',
		// A protection moved, in either direction.
		'hardening_applied',
		'hardening_reverted',
		'two_factor_policy_changed',
		'passkey_policy_changed',
		/*
		 * And the protections kept on this plugin's own settings screens: the
		 * sign-in protection, the password policy, the alerts and the decoy
		 * page. The writer calls each one loosened a defense switched off, and
		 * the Overview counts each as a change made through this plugin.
		 */
		'login_protection_updated',
		'password_policy_updated',
		'alerts_updated',
		'canary_page_changed',
		'csp_enforced',
		'csp_report_only_restored',
		'settings_imported',
		'keys_rotated',
		// What deleting this plugin takes with it.
		'uninstall_choice_changed',
		/*
		 * And what an incident response and the file tools did: an account
		 * stripped, a schedule changed, a file replaced, put back, kept or
		 * deleted. The Overview counts each as a change made (#2245).
		 */
		'incident_response_applied',
		'incident_account_demoted',
		'incident_cron_unscheduled',
		'incident_password_held',
		'file_restored',
		'file_restore_undone',
		'file_quarantined',
		'quarantine_deleted',
		/*
		 * And a credential an assistant reaches this site with, minted or
		 * replaced, and an application allowed to hold one. Standing access
		 * granted to something that is not a person belongs in the same
		 * sentence as a role grant: the removals either side of them do not,
		 * because taking access back is the safe direction and this panel is
		 * about what somebody can do now that they could not before.
		 */
		'mcp_connected',
		'mcp_rotated',
		'mcp_app_granted',
		// A copied credential found, and the access it gave ended.
		'mcp_refresh_reused',
		// The same for a person's account: an application password, read
		// only where it is on a privileged account. See SEVERITY_FLOORS.
		'app_password_created',
		/*
		 * And the other steps an account is taken with, read only where it is
		 * privileged: a passkey added is a standing way in, its second factor
		 * taken off is the protection gone, and its address changed is what
		 * makes the reset that follows look legitimate. On any other account
		 * each is its holder's own upkeep. See SEVERITY_FLOORS.
		 */
		'passkey_registered',
		'two_factor_disabled',
		'user_email_changed',
		// The site was closed, or opened up so somebody could get back in.
		'lockdown_entered',
		'lockdown_left',
		'safe_mode_entered',
		'safe_mode_exited',
		'recovery_link_generated',
		/*
		 * And the plain core settings a takeover changes first: registration
		 * opened, the default role raised, the site address moved, the admin
		 * email pointed somewhere else. Those arrive as
		 * `site_setting_changed`, and the rest of the watched list as
		 * `setting_changed`; without both, this panel could say nothing had
		 * happened on the visit where all four did.
		 */
		'setting_changed',
		'site_setting_changed',
	);

	/**
	 * The kinds that lead the list: somebody, or something, can now do more
	 * than they could. Chosen ahead of every other kind before the list is
	 * cut, then newest first; the rest follow newest first.
	 *
	 * Taken newest first across every kind, nine routine settings saves after
	 * a new administrator was created pushed the administrator off the list.
	 * The kind this panel exists to lead with was the first thing cut, and
	 * "more than this changed" did not say that was what went.
	 */
	private const LEADING_TYPES = array(
		'user_created',
		'user_role_changed',
		'user_role_granted',
		'role_capabilities_changed',
		'temporary_access_end_refused',
		'mcp_connected',
		'mcp_rotated',
		'mcp_app_granted',
		'app_password_created',
		'passkey_registered',
	);

	/**
	 * Kinds read only at or above a severity. An application password is
	 * recorded high on a privileged account and lower on any other, where it
	 * is usually an integration being set up: standing access to the first
	 * is what this panel leads with, and the second is the log's business.
	 * A passkey, a second factor taken off and an address changed are graded
	 * by the same privilege, and read the same way.
	 */
	private const SEVERITY_FLOORS = array(
		'app_password_created' => Writer::SEVERITY_HIGH,
		'passkey_registered'   => Writer::SEVERITY_HIGH,
		'two_factor_disabled'  => Writer::SEVERITY_HIGH,
		'user_email_changed'   => Writer::SEVERITY_HIGH,
	);

	/**
	 * The block for whoever is asking, advancing their stamp if this is a new
	 * visit.
	 *
	 * The side effect is deliberate and is why this is not part of
	 * `Auditor::overview()`: that payload is shared with the read ability, the
	 * dashboard widget and the diagnostics report, and none of those is a
	 * person looking at a screen. An agent asking about posture must not
	 * consume the owner's unread changes.
	 *
	 * `$advance` false reads the block without moving either stamp, for a
	 * caller that may read the screen's payload without being a person at
	 * the screen — an application password polling it, say.
	 *
	 * @return array{since: ?string, changes: array<int, array<string, mixed>>, more: bool, clamped: bool}
	 */
	public static function block( int $user_id, bool $advance = true ): array {
		// The same keys the populated answer carries, so a reader never has to
		// discover which shape it received this time.
		$empty = array(
			'since'   => null,
			'changes' => array(),
			'more'    => false,
			'clamped' => false,
		);

		if ( $user_id < 1 ) {
			return $empty;
		}

		$now       = time();
		$last_seen = (int) get_user_meta( $user_id, self::key(), true );

		// Every visit moves this, which is the only thing it is for.
		if ( $advance ) {
			update_user_meta( $user_id, self::key(), $now );
		}

		// Never looked before. There is no "since" to report, and inventing
		// one — the account's creation, the plugin's activation — would be a
		// different claim than the one this makes.
		if ( 0 === $last_seen ) {
			return $empty;
		}

		$window = (int) get_user_meta( $user_id, self::window_key(), true );

		/*
		 * Long enough since the last request to be a different sitting, so the
		 * window becomes everything since that request. Inside the gap the
		 * window holds still, which is what lets somebody refresh, open a
		 * finding and come back without the block emptying out from under
		 * them before they have acted on it.
		 */
		if ( 0 === $window || ( $now - $last_seen ) >= self::VISIT_GAP ) {
			$window = $last_seen;

			if ( $advance ) {
				update_user_meta( $user_id, self::window_key(), $window );
			}
		}

		return self::changes_since( $window );
	}

	/**
	 * The same list since a moment the caller names, moving nobody's stamp: a
	 * reader that keeps its own record of when a person last looked asks for
	 * what changed since then, and this site's record of that person's last
	 * visit is left as it was.
	 *
	 * @return array{since: ?string, changes: array<int, array<string, mixed>>, more: bool, clamped: bool}
	 */
	public static function changes_from( int $since ): array {
		return self::changes_since( max( 0, $since ) );
	}

	/**
	 * @return array{since: ?string, changes: array<int, array<string, mixed>>, more: bool, clamped: bool}
	 */
	private static function changes_since( int $since ): array {
		global $wpdb;

		$stamp = Time::stamp( $since );
		$floor = Tier::retention_floor();

		// The log cannot answer for a period it no longer holds.
		$clamped = $stamp < $floor;
		$from    = $clamped ? $floor : $stamp;

		$types = self::CHANGE_TYPES;

		// A floored kind is read only at or above its severity.
		$floors = '';
		$floor_values = array();

		foreach ( self::SEVERITY_FLOORS as $type => $severity ) {
			$floors        .= ' AND ( event_type <> %s OR severity >= %d )';
			$floor_values[] = $type;
			$floor_values[] = $severity;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, occurred_at, event_type, severity, actor_label, actor_type, actor_id, object_type, object_id, context FROM %i'
					. ' WHERE ' . Schema::site_where( 'events' ) . ' AND occurred_at > %s AND event_type IN ('
					. implode( ',', array_fill( 0, count( $types ), '%s' ) )
					. ')' . $floors . ' ORDER BY ( event_type IN ('
					. implode( ',', array_fill( 0, count( self::LEADING_TYPES ), '%s' ) )
					. ') ) DESC, id DESC LIMIT %d',
				array_merge( array( Schema::table( 'events' ), $from ), $types, $floor_values, self::LEADING_TYPES, array( self::MAX_LISTED + 1 ) )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$rows = is_array( $rows ) ? $rows : array();

		/*
		 * One more than the list length is fetched so "and N others" can be
		 * honest about there being more without a second COUNT over the table
		 * — and when there are more, the count is reported as "at least",
		 * because that is what one extra row proves.
		 */
		$more = count( $rows ) > self::MAX_LISTED;

		if ( $more ) {
			array_pop( $rows );
		}

		// The accounts the rows name, and the logins recorded for any since
		// deleted, read once for the list.
		Query::load_accounts( $rows );

		$changes = array();

		foreach ( $rows as $row ) {
			$context = null !== $row->context ? json_decode( (string) $row->context, true ) : null;
			$name    = Query::object_label(
				(string) $row->event_type,
				null !== $row->object_type ? (string) $row->object_type : null,
				null !== $row->object_id ? (string) $row->object_id : null,
				$context
			);

			$changes[] = array(
				'id'              => (int) $row->id,
				// Stamped as UTC. Sent bare, a reader in any zone west of it saw
				// rows dated hours before the heading they sit under, and the
				// panel's whole claim is what happened since a moment.
				'occurred_at'     => Time::utc_iso( (string) $row->occurred_at ),
				'type'            => (string) $row->event_type,
				// Said as the activity log says the same row: a set of printed
				// codes read "Recovery link generated" here (#1916).
				'label'           => Query::label_of( (string) $row->event_type, $context, null !== $row->object_type ? (string) $row->object_type : null ),
				'severity'        => (int) $row->severity,
				'actor'           => self::actor( $row ),
				'subject'         => $name ?? self::subject( (string) $row->object_id ),
				// A name is set as text and an identifier as code, the way the
				// activity log sets the same row.
				'subject_is_name' => null !== $name,
				// The accounts behind the two names, so a reader that may not
				// be given a login can name them its own way.
				'actor_id'        => 'user' === (string) $row->actor_type ? (int) $row->actor_id : 0,
				'subject_user'    => 'user' === (string) $row->object_type ? (int) $row->object_id : 0,
			);

			// What an allowed assistant may do, beside its name: read the
			// site, or change it too. The panel words it.
			if ( 'mcp_app_granted' === (string) $row->event_type && is_array( $context ) && isset( $context['scope'] ) ) {
				$changes[ count( $changes ) - 1 ]['scope'] = (string) $context['scope'];
			}
		}

		return array(
			'since'   => gmdate( 'c', $since ),
			'changes' => $changes,
			'more'    => $more,
			'clamped' => $clamped,
		);
	}

	/**
	 * What the change was to, when that is worth showing.
	 *
	 * A settings event identifies itself by its option name, which is right
	 * for the log and useless here — "Passkey-only requirement changed
	 * bettershield_passkey_policy" tells a reader nothing the label did not
	 * already say, and puts an internal identifier on the first screen of the
	 * product. The label carries it alone in that case; a hardening item or a
	 * file path is the opposite and is the whole point of the line.
	 */
	private static function subject( string $object_id ): ?string {
		if ( '' === $object_id || str_starts_with( $object_id, 'bettershield_' ) ) {
			return null;
		}

		return $object_id;
	}

	private static function actor( object $row ): string {
		$label = (string) $row->actor_label;

		if ( '' !== $label ) {
			return $label;
		}

		return 'system' === (string) $row->actor_type
			? __( 'WordPress or the server (not a signed-in user)', 'bettershield' )
			: __( 'a signed-out visitor', 'bettershield' );
	}

	/**
	 * The stamp is per site on a network.
	 *
	 * User meta is network-global, and "what changed since you last looked" is
	 * a question about one site — so a single key would have one subsite's
	 * visit silencing the block on every other subsite the same person
	 * administers. This is the same trap `TwoFactor\Policy` records for its
	 * grace clock.
	 */
	private static function key(): string {
		return is_multisite() ? self::META . '_' . get_current_blog_id() : self::META;
	}

	private static function window_key(): string {
		return is_multisite() ? self::META_WINDOW . '_' . get_current_blog_id() : self::META_WINDOW;
	}

	/**
	 * Forget this person's stamp. Used by uninstall and by the tests.
	 */
	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::key() );
		delete_user_meta( $user_id, self::window_key() );
	}
}
