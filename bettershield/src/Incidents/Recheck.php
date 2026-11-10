<?php
/**
 * After an incident response, look again: what the plan acted on, is it
 * still open?
 *
 * The response plan stopped at its receipt, and a receipt says what was done,
 * not whether it held. This runs the audit, one bounded piece of the file
 * check, and reads each target the plan named against the state the plan
 * recorded before it acted — the account's capabilities, its sessions, the
 * credentials that were revoked, the scheduled occurrence, the file's bytes —
 * and says, per line, whether it is still open. What the plan did not act on
 * is said as not done; what nothing here can check is said as a manual step.
 *
 * Nothing here is a clean bill of health, and the words never claim one:
 * "nothing we re-checked is still open", with when each check ran. A file
 * check too large to finish in the time allowed says it is still checking.
 * It changes nothing on the site; it sits outside the response's claim, so
 * it never holds a batch up.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Incidents;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Database\Schema;
use BetterShield\Integrity\Report;
use BetterShield\Integrity\Scanner;
use BetterShield\Remediation\Accounts;
use BetterShield\Remediation\PasswordHold;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recheck {

	/** How long the file check may run inside the request. */
	private const INLINE_SECONDS = 5.0;

	public const OPEN        = 'open';
	public const CLOSED      = 'closed';
	public const NOT_DONE    = 'not_done';
	public const MANUAL      = 'manual';
	public const NOT_CHECKED = 'not_checked';
	public const CHECKING    = 'checking';

	/**
	 * Re-check what one applied plan acted on.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function run( string $token ) {
		$row = Ledger::find( $token );

		if ( ! $row || Response::KEY !== $row->action_key || ! current_user_can( Capabilities::MANAGE ) || (int) $row->created_by !== get_current_user_id() ) {
			return Response::error();
		}

		$receipt = is_array( $row->applied_state ) ? $row->applied_state : array();

		if ( empty( $receipt['complete'] ) ) {
			return Response::error( __( 'Apply the plan before checking what is still open.', 'bettershield' ) );
		}

		Auditor::run();
		Scanner::tick( self::INLINE_SECONDS, null, true );
		$files = Report::all();

		// The open changes are counted by kind; the total is the number. Cast
		// whole, a non-empty array is 1, so the line was always open.
		$changed = (int) ( $files['open_changes']['total'] ?? 0 );

		$contain = array();
		$verify  = array();

		foreach ( (array) $row->prior_state['items'] as $key => $item ) {
			$line = array(
				'key'   => (string) $key,
				'label' => (string) $item['label'],
			) + self::state_of( $item, $receipt['results'][ $key ] ?? null );

			if ( in_array( $item['kind'], array( 'demote', 'sessions', 'passwords', 'reset' ), true ) ) {
				$contain[] = $line;
			} else {
				$verify[] = $line;
			}
		}

		$overview = Auditor::overview();
		$serious  = count(
			array_filter(
				(array) ( $overview['findings'] ?? array() ),
				static fn( $finding ): bool => in_array( $finding['severity'] ?? '', array( 'high', 'critical' ), true )
			)
		);

		$incident = Repository::detail( (int) $row->prior_state['id'] );
		$covered  = count( (array) $row->prior_state['items'] );
		$evidence = is_array( $incident ) ? (int) ( $incident['evidence_count'] ?? 0 ) : 0;

		$confirm = array(
			array(
				'key'    => 'audit',
				'label'  => __( 'Security check', 'bettershield' ),
				'status' => $serious > 0 ? self::OPEN : self::CLOSED,
				'detail' => $serious > 0
					? sprintf(
						/* translators: %d: number of open findings at high or critical. */
						_n( '%d high or critical finding is open.', '%d high or critical findings are open.', $serious, 'bettershield' ),
						$serious
					)
					: __( 'No finding at high or critical is open.', 'bettershield' ),
				'url'    => admin_url( 'admin.php?page=bettershield-findings' ),
			),
			array(
				'key'    => 'files',
				'label'  => __( 'File changes', 'bettershield' ),
				'status' => ! empty( $files['running'] ) ? self::CHECKING : ( $changed > 0 ? self::OPEN : self::CLOSED ),
				'detail' => ! empty( $files['running'] )
					? __( 'Still checking in the background. Look again shortly.', 'bettershield' )
					: ( $changed > 0
						? __( 'Changed files are still listed on the file report.', 'bettershield' )
						: __( 'No changed file is listed on the file report.', 'bettershield' ) ),
				'url'    => admin_url( 'admin.php?page=bettershield-activity&tab=files' ),
			),
			array(
				'key'    => 'evidence',
				'label'  => __( 'Records the plan didn’t cover', 'bettershield' ),
				'status' => self::NOT_CHECKED,
				'detail' => sprintf(
					/* translators: 1: evidence records on the incident, e.g. "12 evidence records", 2: actions the plan held, e.g. "3 actions". */
					__( 'This incident has %1$s; the plan covered %2$s. Review the rest of the timeline yourself.', 'bettershield' ),
					/* translators: %d: number of evidence records. */
					sprintf( _n( '%d evidence record', '%d evidence records', $evidence, 'bettershield' ), $evidence ),
					/* translators: %d: number of actions. */
					sprintf( _n( '%d action', '%d actions', $covered, 'bettershield' ), $covered )
				),
				'url'    => '',
			),
		);

		// Two steps no plan takes for you: each affects the person acting as
		// well, so each has a reviewed control of its own.
		$recover = array(
			array(
				'key'    => 'keys',
				'label'  => __( 'Rotate the sign-in keys', 'bettershield' ),
				'status' => self::MANUAL,
				'detail' => __( 'Signs every account out, yours included, ending any stolen sessions.', 'bettershield' ),
				'url'    => admin_url( 'admin.php?page=bettershield-protect&tab=login' ),
			),
			array(
				'key'    => 'lockdown',
				'label'  => __( 'Lock the site down', 'bettershield' ),
				'status' => self::MANUAL,
				'detail' => __( 'Only site managers can sign in, and the recovery link still works. Lift it any time.', 'bettershield' ),
				'url'    => admin_url( 'admin.php?page=bettershield-protect&tab=recovery' ),
			),
		);

		$groups = array(
			array(
				'key'   => 'contain',
				'title' => __( 'Stop it spreading', 'bettershield' ),
				'lines' => $contain,
			),
			array(
				'key'   => 'verify',
				'title' => __( 'Check what changed', 'bettershield' ),
				'lines' => $verify,
			),
			array(
				'key'   => 'recover',
				'title' => __( 'Secure sign-ins', 'bettershield' ),
				'lines' => $recover,
			),
			array(
				'key'   => 'confirm',
				'title' => __( 'Confirm the site is OK', 'bettershield' ),
				'lines' => $confirm,
			),
		);

		$open = 0;

		foreach ( $groups as $group ) {
			foreach ( $group['lines'] as $line ) {
				$open += self::OPEN === $line['status'] ? 1 : 0;
			}
		}

		return array(
			'token'      => $token,
			'checked_at' => gmdate( 'c' ),
			'open'       => $open,
			'checking'   => ! empty( $files['running'] ),
			'groups'     => array_values( array_filter( $groups, static fn( array $group ): bool => array() !== $group['lines'] ) ),
		);
	}

	/**
	 * Whether the last time an account's new-password requirement was lifted,
	 * it was a new password that lifted it.
	 *
	 * On a network the hold is the network's, and the holder sets the new
	 * password through the network's own sign-in, on the main site, so that
	 * is where the lift is recorded. A subsite reads the main site's record
	 * too, and the later of the two decides.
	 *
	 * The plan's receipt asks the same question of the same records, so the
	 * receipt and this line say the same thing.
	 */
	public static function renewed( int $user ): bool {
		$last = self::last_lift( $user );

		if ( is_multisite() && ! is_main_site() ) {
			switch_to_blog( (int) get_main_site_id() );

			try {
				$main = self::last_lift( $user );
			} finally {
				restore_current_blog();
			}

			if ( null !== $main && ( null === $last || $main['at'] > $last['at'] ) ) {
				$last = $main;
			}
		}

		return null !== $last && 'new_password' === $last['reason'];
	}

	/**
	 * When an account's new-password requirement was last lifted on this
	 * site, and why, or null when it never was here.
	 *
	 * @return array{at: string, reason: string}|null
	 */
	private static function last_lift( int $user ): ?array {
		global $wpdb;

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site predicate is integers assembled by Schema::site_where(); the table and the id are bound.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT occurred_at, context FROM %i WHERE " . Schema::site_where( 'events' ) . " AND event_type = 'password_hold_lifted' AND object_type = 'user' AND object_id = %s ORDER BY occurred_at DESC, id DESC LIMIT 1",
				Schema::table( 'events' ),
				(string) $user
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( ! is_object( $row ) ) {
			return null;
		}

		$context = is_string( $row->context ) ? json_decode( $row->context, true ) : null;

		return array(
			'at'     => (string) $row->occurred_at,
			'reason' => is_array( $context ) ? (string) ( $context['reason'] ?? '' ) : '',
		);
	}

	/**
	 * One plan item as it stands now, against what the plan recorded before
	 * it acted.
	 *
	 * @param array<string, mixed>      $item
	 * @param array<string, mixed>|null $result
	 * @return array{status: string, detail: string, url: string}
	 */
	private static function state_of( array $item, ?array $result ): array {
		$status = (string) ( $result['status'] ?? '' );

		if ( 'applied' !== $status ) {
			return array(
				'status' => self::NOT_DONE,
				'detail' => 'undone' === $status
					? __( 'Undone after it was applied.', 'bettershield' )
					: ( 'refused' === $status ? __( 'Refused when the plan ran.', 'bettershield' ) : __( 'Not part of the actions applied.', 'bettershield' ) ),
				'url'    => '',
			);
		}

		$target = $item['target'];
		$before = (array) $item['before'];

		switch ( $item['kind'] ) {
			case 'demote':
				$open   = array() !== Accounts::caps( (int) $target );
				$detail = $open ? __( 'The account holds roles or capabilities again.', 'bettershield' ) : __( 'The account still holds no role.', 'bettershield' );
				$url    = admin_url( 'user-edit.php?user_id=' . (int) $target );
				break;

			case 'sessions':
				wp_cache_delete( (int) $target, 'user_meta' );
				$sessions = get_user_meta( (int) $target, 'session_tokens', true );
				$count    = is_array( $sessions ) ? count( $sessions ) : 0;
				$open     = $count > 0;
				$detail   = $open
					? sprintf(
						/* translators: %d: number of sessions. */
						_n( '%d session is live on this account again.', '%d sessions are live on this account again.', $count, 'bettershield' ),
						$count
					)
					: __( 'No session is live on this account.', 'bettershield' );
				$url      = admin_url( 'user-edit.php?user_id=' . (int) $target );
				break;

			case 'passwords':
				$passwords = \WP_Application_Passwords::get_user_application_passwords( (int) $target );
				$back      = array_intersect( (array) ( $before['uuids'] ?? array() ), array_column( $passwords, 'uuid' ) );

				/*
				 * WordPress gives every new password a fresh id, so asking only
				 * whether a revoked one is back never opened the line. Any
				 * password created since the step ran does, as a live session
				 * opens the line beside it. A receipt from before the step's
				 * time was kept has none, and is read as before.
				 */
				$since  = (int) ( $result['at'] ?? 0 );
				$made   = $since > 0 ? count( array_filter( $passwords, static fn( array $password ): bool => (int) $password['created'] >= $since ) ) : 0;
				$open   = array() !== $back || $made > 0;
				$detail = array() !== $back
					? __( 'A revoked application password exists again.', 'bettershield' )
					: ( $made > 0
						? sprintf(
							/* translators: %d: number of application passwords. */
							_n( '%d application password was created since the response.', '%d application passwords were created since the response.', $made, 'bettershield' ),
							$made
						)
						: __( 'None of the revoked application passwords exists.', 'bettershield' ) );
				$url    = admin_url( 'user-edit.php?user_id=' . (int) $target . '#application-passwords-section' );
				break;

			case 'cron':
				$open   = false !== wp_next_scheduled( (string) $target );
				$detail = $open ? __( 'The scheduled task is back.', 'bettershield' ) : __( 'The scheduled task is gone.', 'bettershield' );
				$url    = '';
				break;

			case 'reset':
				// Closed while the hold stands, and once a new password lifted
				// it, which is the step done. Lifted any other way — undone,
				// or its email never sent — the password signs in again.
				$held   = PasswordHold::has( (int) $target );
				$open   = ! $held && ! self::renewed( (int) $target );
				$detail = $held
					? __( 'Password sign-in stays blocked until a new password is set.', 'bettershield' )
					: ( $open
						? __( 'The new-password requirement was lifted without a new password being set.', 'bettershield' )
						: __( 'A new password was set, which lifted the requirement.', 'bettershield' ) );
				$url    = admin_url( 'user-edit.php?user_id=' . (int) $target );
				break;

			case 'restore':
			case 'quarantine':
				$state  = Response::file_state( (int) $target, true );
				$open   = is_array( $state ) && isset( $before['sha256'] ) && hash_equals( (string) $before['sha256'], (string) $state['sha256'] );
				$detail = $open ? __( 'The file holds the flagged contents again.', 'bettershield' ) : __( 'The file no longer holds the flagged contents.', 'bettershield' );
				$url    = admin_url( 'admin.php?page=bettershield-activity&tab=files' );
				break;

			// A kind this does not know how to look at is said as that, never
			// sent to the file check, which read an account's id as a file's.
			default:
				return array(
					'status' => self::NOT_CHECKED,
					'detail' => __( 'This step is not re-checked. Review it yourself.', 'bettershield' ),
					'url'    => '',
				);
		}

		return array(
			'status' => $open ? self::OPEN : self::CLOSED,
			'detail' => $detail,
			'url'    => $url,
		);
	}
}
