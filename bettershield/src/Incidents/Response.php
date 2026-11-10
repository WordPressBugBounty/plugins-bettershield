<?php
/** Prepared, owner-bound response batches. Durable receipts precede each action. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Incidents;
use BetterShield\Capabilities;
use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;
use BetterShield\Remediation\Accounts;
use BetterShield\Remediation\PasswordHold;
use BetterShield\Support\Claim;
use BetterShield\Files\Guarded;
use BetterShield\Integrity\Packages;
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- fresh scoped records and durable receipts.
final class Response {
	public const KEY = 'incident_response_plan';
	public const MAX_ITEMS = 20;
	public static function error( string $message = '' ): \WP_Error { return new \WP_Error( 'bettershield_response_refused', $message ?: __( 'The target or plan changed. Prepare a fresh plan; no further actions were attempted.', 'bettershield' ), array( 'status' => 409 ) ); }
	private static function owner(): string { return hash( 'sha256', get_current_blog_id() . ':' . get_current_user_id() . ':' . wp_get_session_token() ); }
	public static function ready(): bool { return current_user_can( Capabilities::MANAGE ) && ! \BetterShield\Recovery\SafeMode::is_active() && ( \BetterShield\Recovery\RecoveryLink::usable() || \BetterShield\Recovery\OfflineCodes::exist() ) && ! \BetterShield\Support\Checkout::is_store_path( false ); }
	private static function fingerprint( array $incident ): string { return hash( 'sha256', wp_json_encode( array( $incident['status'], $incident['evidence_count'], $incident['evidence'] ) ) ); }
	public static function prepare( int $id ): array|\WP_Error {
		if ( ! current_user_can( Capabilities::MANAGE ) ) { return self::error(); }
		$incident = Repository::detail( $id ); if ( is_wp_error( $incident ) ) { return $incident; }
		if ( 'resolved' === $incident['status'] ) { return self::error( __( 'A handled incident cannot start another response.', 'bettershield' ) ); }
		$items = array(); $users = array(); $hooks = array(); $extra_cron = 0; $cron_checked = 0;
		foreach ( $incident['evidence'] as $e ) {
			foreach ( array( $e['actor_id'], (int) ( $e['snapshot']['target_user'] ?? 0 ) ) as $user ) { if ( $user > 0 ) { $users[ $user ] = true; } }
			if ( 'integrity' === ( $e['snapshot']['source'] ?? '' ) ) {
				$target = (int) $e['snapshot']['source_id'];
				$state = self::file_state( $target );
				$refusal = is_wp_error( $state ) ? $state->get_error_message() : '';
				$kind = is_array( $state ) ? ( ( $state['change_type'] ?? '' ) === 'modified' && in_array( $state['context'] ?? '', array( 'core', 'plugin' ), true ) ? 'restore' : 'quarantine' ) : self::file_kind( $target );
				$items[ 'file-' . $target ] = array( 'kind' => $kind, 'target' => $target, 'label' => ( 'restore' === $kind ? __( 'Replace with the official version of this file: ', 'bettershield' ) : __( 'Move this file to safe storage and leave an empty file in its place: ', 'bettershield' ) ) . $e['snapshot']['object_id'], 'detail' => __( 'This may break the plugin or theme that uses this file. Nothing is deleted. You can undo it if the file isn’t edited again.', 'bettershield' ), 'refusal' => $refusal, 'before' => is_array( $state ) ? $state : array(), 'reversible' => true );
			}
			foreach ( (array) ( $e['snapshot']['details']['hooks'] ?? array() ) as $hook ) { $hooks[ $hook ] = true; }
		}
		foreach ( array_slice( array_keys( $users ), 0, 5 ) as $user ) {
			foreach ( array( 'demote', 'passwords', 'sessions', 'reset' ) as $kind ) {
				$refusal = Accounts::refusal( $user, 'demote' !== $kind );
				if ( '' === $refusal && 'demote' === $kind && ! current_user_can( 'promote_user', $user ) ) { $refusal = __( 'You cannot change this account’s capabilities.', 'bettershield' ); }
				// From a day before the incident opened, the window the credential step uses.
				$from = (int) strtotime( $incident['opened_at'] ) - DAY_IN_SECONDS;
				if ( '' === $refusal && 'reset' === $kind ) { $refusal = self::reset_refusal( $user, $from ); }
				$before = 'demote' === $kind ? Accounts::caps( $user ) : ( 'reset' === $kind ? array( 'email' => self::email_digest( $user ), 'from' => $from ) : array( 'digest' => Accounts::fingerprint( $user, $kind ) ) );
				if ( 'passwords' === $kind ) {
					$from = strtotime( $incident['opened_at'] ) - DAY_IN_SECONDS; $to = strtotime( $incident['updated_at'] ) + DAY_IN_SECONDS;
					$before['uuids'] = array_values( array_map( static fn( $p ) => $p['uuid'], array_filter( \WP_Application_Passwords::get_user_application_passwords( $user ), static fn( $p ) => $p['created'] >= $from && $p['created'] <= $to ) ) );
					if ( '' === $refusal && ! $before['uuids'] ) { $refusal = __( 'No current application passwords were created within a day of the incident.', 'bettershield' ); }
				}
				$labels = array( 'demote' => __( 'Remove all of this account’s roles and permissions', 'bettershield' ), 'sessions' => __( 'Sign this account out everywhere', 'bettershield' ), 'passwords' => __( 'Remove app passwords this account created around the time of the incident', 'bettershield' ), 'reset' => __( 'Require a new password before the next password sign-in', 'bettershield' ) );
				$details = array(
					'demote'    => __( 'The account is kept with no role. Undo restores its roles and capabilities if they have not changed.', 'bettershield' ),
					'reset'     => __( 'Password sign-in stops until a new password is set; WordPress emails the account a reset link. Undo lifts this.', 'bettershield' ),
					'sessions'  => __( 'Can’t be undone. They’ll need to sign in again. Being listed doesn’t mean they did anything wrong.', 'bettershield' ),
					'passwords' => __( 'Can’t be undone. Apps using these passwords stop working until new ones are made.', 'bettershield' ),
				);
				// Kept by number; view() names the account for whoever reads it.
				/* translators: 1: response action label, 2: numeric account ID. */
				$items[ $kind . '-' . $user ] = array( 'kind' => $kind, 'target' => $user, 'action' => $labels[ $kind ], 'label' => sprintf( __( '%1$s — account #%2$d', 'bettershield' ), $labels[ $kind ], $user ), 'detail' => $details[ $kind ], 'refusal' => $refusal, 'before' => $before, 'reversible' => in_array( $kind, array( 'demote', 'reset' ), true ) );
				if ( 'reset' === $kind ) { $items[ $kind . '-' . $user ]['note'] = __( 'Passkeys and application passwords still work; revoke them separately. On a network, this applies on every site.', 'bettershield' ); }
			}
		}
		$cron = get_option( 'cron', array() );
		if ( is_array( $cron ) && 2 === ( $cron['version'] ?? 0 ) ) {
			foreach ( $cron as $at => $entries ) { if ( ! is_array( $entries ) ) { continue; }
				foreach ( $entries as $hook => $events ) { if ( ! isset( $hooks[ $hook ] ) ) { continue; }
					foreach ( $events as $event ) {
						if ( ++$cron_checked > 100 ) { ++$extra_cron; continue; }
						$key = 'cron-' . hash( 'sha256', $at . $hook . serialize( $event ) );
						$items[ $key ] = array( 'kind' => 'cron', 'target' => $hook, 'label' => __( 'Cancel a scheduled task that has no code to run it: ', 'bettershield' ) . $hook, 'detail' => __( 'If you undo this, the task may run right away. Tasks with extra settings must be checked by hand.', 'bettershield' ), 'refusal' => has_action( $hook ) || ! empty( $event['args'] ) || str_starts_with( $hook, 'bettershield' ) ? __( 'This task is in use, belongs to BetterShield, or has extra settings, so it can’t be canceled here.', 'bettershield' ) : '', 'before' => array( 'at' => (int) $at, 'schedule' => $event['schedule'] ), 'reversible' => true );
					}
				}
			}
		}
		// Fair selection across action kinds; a refused file must never displace
		// an available account or cron response. Candidates are bounded by the
		// evidence page, five accounts and 100 matching cron occurrences.
		$buckets = array_fill_keys( array( 'demote', 'sessions', 'passwords', 'reset', 'cron', 'restore', 'quarantine' ), array() );
		foreach ( $items as $key => $item ) { $buckets[ $item['kind'] ][ $key ] = $item; }
		$selected = array();
		foreach ( array( false, true ) as $refused ) {
			do {
				$added = false;
				foreach ( $buckets as $kind => $bucket ) {
					foreach ( $bucket as $key => $item ) {
						if ( (bool) $item['refusal'] !== $refused ) { continue; }
						$selected[ $key ] = $item; unset( $buckets[ $kind ][ $key ] ); $added = true;
						if ( count( $selected ) >= self::MAX_ITEMS ) { break 3; }
						break;
					}
				}
			} while ( $added );
			if ( count( $selected ) >= self::MAX_ITEMS ) { break; }
		}
		$omitted = array_map( 'count', $buckets );
		foreach ( array( 'demote', 'sessions', 'passwords', 'reset' ) as $kind ) { $omitted[ $kind ] += max( 0, count( $users ) - 5 ); }
		$omitted['cron'] += $extra_cron;
		$limited = array_sum( $omitted ) > 0 || $incident['next_cursor'] > 0;
		$items = $selected;
		$prior = array( 'id' => $id, 'owner' => self::owner(), 'expires' => time() + 600, 'fingerprint' => self::fingerprint( $incident ), 'items' => $items, 'limited' => $limited, 'omitted' => $omitted );
		$token = Ledger::open( self::KEY, $prior, array() );
		return $token ? self::view( $token ) : Repository::error();
	}
	public static function latest( int $id ): array|\WP_Error {
		global $wpdb;
		if ( ! current_user_can( Capabilities::MANAGE ) ) { return self::error(); }
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT token,prior_state FROM %i WHERE action_key=%s AND created_by=%d ORDER BY id DESC LIMIT 100', Schema::table( 'undo' ), self::KEY, get_current_user_id() ) );
		if ( '' !== $wpdb->last_error ) { return Repository::error(); }
		foreach ( $rows as $row ) { if ( (int) ( json_decode( $row->prior_state, true )['id'] ?? 0 ) === $id ) { return self::view( $row->token ); } }
		return array();
	}
	/** Paginated owner-only history. Walk the ledger so older receipts never disappear behind a fixed cap. */
	public static function history( int $id, int $cursor = 0 ): array|\WP_Error {
		global $wpdb;
		if ( ! current_user_can( Capabilities::MANAGE ) || $id < 1 || $cursor < 0 ) { return self::error(); }
		$rows = $wpdb->get_results( $wpdb->prepare(
			'SELECT id,token,created_at,prior_state FROM %i WHERE action_key=%s AND created_by=%d AND (%d=0 OR id<%d) ORDER BY id DESC LIMIT 51',
			Schema::table( 'undo' ), self::KEY, get_current_user_id(), $cursor, $cursor
		) );
		if ( '' !== $wpdb->last_error ) { return Repository::error(); }
		$more = count( $rows ) > 50;
		$rows = array_slice( $rows, 0, 50 );
		$plans = array();
		foreach ( $rows as $row ) {
			if ( (int) ( json_decode( $row->prior_state, true )['id'] ?? 0 ) === $id ) {
				$plans[] = array( 'token' => $row->token, 'created_at' => gmdate( 'c', strtotime( $row->created_at . ' UTC' ) ) );
			}
		}
		return array( 'plans' => $plans, 'next_cursor' => $more ? (int) end( $rows )->id : 0 );
	}

	/**
	 * Why a prepared plan can no longer be acted on, or '' while it can: it
	 * belongs to the sign-in session that prepared it, and to ten minutes.
	 * Shown and refused for what it is, rather than offered and then refused
	 * as though the recovery method or Safe mode were at fault.
	 */
	private static function stale( object $row ): string {
		if ( ! hash_equals( (string) ( $row->prior_state['owner'] ?? '' ), self::owner() ) ) { return 'session'; }
		return time() > (int) ( $row->prior_state['expires'] ?? 0 ) ? 'expired' : '';
	}
	public static function view( string $token ): array|\WP_Error {
		$row = Ledger::find( $token );
		if ( ! $row || self::KEY !== $row->action_key || ! current_user_can( Capabilities::MANAGE ) || (int) $row->created_by !== get_current_user_id() ) { return self::error(); }
		$items = array();
		foreach ( $row->prior_state['items'] as $key => $item ) {
			unset( $item['before'] );
			if ( isset( $item['action'] ) && is_int( $item['target'] ) ) { $item['label'] = sprintf( '%1$s — %2$s', $item['action'], self::account_named( $item['target'] ) ); }
			unset( $item['action'] );
			$items[] = array( 'id' => $key ) + $item;
		}
		$stale = self::stale( $row );
		return array( 'token' => $token, 'incident_id' => $row->prior_state['id'], 'expires' => gmdate( 'c', $row->prior_state['expires'] ), 'items' => $items, 'limited' => $row->prior_state['limited'], 'omitted' => $row->prior_state['omitted'] ?? array(), 'ready' => self::ready(), 'actionable' => '' === $stale, 'stale' => $stale, 'receipt' => self::settled( $row->applied_state ), 'refusals' => array( __( 'Rotating sign-in keys signs you out too, so it has its own control.', 'bettershield' ), __( 'Recovery links and file deletion are never response actions.', 'bettershield' ) ) );
	}
	/**
	 * The receipt as it stands now: a new-password step whose hold has since
	 * been lifted is no longer "Applied" with an undo.
	 *
	 * A new password lifts the hold and reverts its ledger row, and the plan
	 * went on offering an Undo that could only fail. Said as met where a new
	 * password lifted it, and as lifted where something else did.
	 *
	 * Read from the hold itself, not only from this site's ledger: on a
	 * network the hold is the network's and the new password is set on the
	 * main site, so a subsite's row stays open after the hold is gone.
	 *
	 * @param mixed $receipt
	 * @return mixed
	 */
	private static function settled( $receipt ) {
		if ( ! is_array( $receipt ) || ! isset( $receipt['results'] ) || ! is_array( $receipt['results'] ) ) {
			return $receipt;
		}
		foreach ( $receipt['results'] as $key => $result ) {
			if ( 'applied' !== ( $result['status'] ?? '' ) || empty( $result['undo'] ) ) { continue; }
			$undo = Ledger::find( (string) $result['undo'] );
			if ( ! $undo || ! self::hold_gone( $undo ) ) { continue; }
			$met = Recheck::renewed( (int) ( $undo->prior_state['user'] ?? 0 ) );
			$receipt['results'][ $key ] = array(
				'status'  => $met ? 'met' : 'lifted',
				'message' => $met
					? __( 'A new password was set, so there is nothing to undo.', 'bettershield' )
					: __( 'The requirement was lifted outside this plan. There is nothing to undo.', 'bettershield' ),
			);
		}
		return $receipt;
	}
	/**
	 * Whether a new-password step's hold is no longer the one it placed:
	 * its row reverted here, or the account's hold gone or replaced.
	 *
	 * @param object $undo The step's ledger row.
	 */
	private static function hold_gone( $undo ): bool {
		return PasswordHold::KEY === $undo->action_key
			&& ( $undo->reverted_at || PasswordHold::token( (int) ( $undo->prior_state['user'] ?? 0 ) ) !== $undo->token );
	}
	private static function save( string $token, array $state ): bool {
		global $wpdb;
		$encoded = wp_json_encode( $state );
		if ( ! is_string( $encoded ) || false === $wpdb->update( Schema::table( 'undo' ), array( 'applied_state' => $encoded ), array( 'token' => $token, 'action_key' => self::KEY ) ) ) { return false; }
		$stored = Ledger::find( $token );
		return $stored && $stored->applied_state === $state;
	}
	public static function apply( string $token, array $selected ): array|\WP_Error {
		if ( ! Claim::claim( 'incident_response', 300 ) ) { return self::error(); }
		try {
			$row = Ledger::find( $token );
			if ( ! $row || self::KEY !== $row->action_key || (int) $row->created_by !== get_current_user_id() ) { return self::error(); }
			if ( 'session' === self::stale( $row ) ) { return self::error( __( 'This plan was made in another browser or sign-in, so it can only be viewed. Prepare a new plan to act.', 'bettershield' ) ); }
			if ( ! self::ready() ) { return self::error( __( 'To apply this plan, set up a recovery method and turn off safe mode under Protection › Recovery.', 'bettershield' ) ); }
			$selected = array_values( array_unique( $selected ) ); sort( $selected );
			$state = $row->applied_state;
			if ( $state ) { return ( $state['selected'] ?? null ) === $selected ? self::view( $token ) : self::error(); }
			if ( 'expired' === self::stale( $row ) ) { return self::error( __( 'This plan expired after ten minutes. Prepare a fresh plan to act.', 'bettershield' ) ); }
			$incident = Repository::detail( (int) $row->prior_state['id'] );
			if ( is_wp_error( $incident ) || ! hash_equals( $row->prior_state['fingerprint'], self::fingerprint( $incident ) ) || ! $selected || array_diff( $selected, array_keys( $row->prior_state['items'] ) ) ) { return self::error(); }
			$state = array( 'selected' => $selected, 'results' => array(), 'complete' => false );
			if ( ! self::save( $token, $state ) ) { return Repository::error(); }
			// A new-password step runs before anything else: it is offered only
			// to an account that can change the site, so run after the same
			// account's demotion it was refused as one that could not.
			$items = $row->prior_state['items'];
			$items = array_filter( $items, static fn( array $item ): bool => 'reset' === $item['kind'] ) + $items;
			foreach ( $items as $key => $item ) {
				if ( ! in_array( $key, $selected, true ) ) { continue; }
				$state['results'][ $key ] = array( 'status' => 'uncertain', 'message' => __( 'This step may not have finished. Check its target before preparing another plan.', 'bettershield' ) );
				if ( ! self::save( $token, $state ) ) { return Repository::error(); }
				try { $result = self::execute( $item ); } catch ( \Throwable $e ) { return self::view( $token ); }
				$state['results'][ $key ] = is_wp_error( $result ) ? array( 'status' => 'refused', 'message' => $result->get_error_message() ) : array( 'status' => 'applied', 'undo' => $result, 'at' => time() );
				if ( ! self::save( $token, $state ) ) { return Repository::error(); }
			}
			$state['complete'] = true;
			if ( ! self::save( $token, $state ) ) { return Repository::error(); }
			// What the batch did, not only that it ran: how many of the
			// selected steps landed and which kinds, so the row and its alert
			// say "2 of 2 applied" rather than an incident's bare id (#2242).
			$applied = array_keys( array_filter( $state['results'], static fn( array $result ): bool => 'applied' === $result['status'] ) );
			$done    = array_values( array_unique( array_map( static fn( string $key ): string => (string) $items[ $key ]['kind'], $applied ) ) );
			Writer::instance()->record( 'incident_response_applied', Writer::SEVERITY_HIGH, array( 'object_type' => 'incident', 'object_id' => (string) $incident['id'], 'context' => array( 'plan' => $token, 'actions' => count( $selected ), 'applied' => count( $applied ), 'refused' => count( $selected ) - count( $applied ), 'done' => $done ) ) );
			return self::view( $token );
		} finally { Claim::release( 'incident_response' ); }
	}
	/**
	 * One applied action's own row, written and persisted where it happened.
	 *
	 * Per item rather than only in the aggregate row at the end of the batch:
	 * everything executed before an interruption is genuinely and durably
	 * applied, while the aggregate that would have named it never gets
	 * written. Flushed here for the same reason — a buffer emptied at shutdown
	 * is a buffer a killed request never empties. Ending sessions, revoking
	 * credentials and the checksum-verified restore are already recorded by
	 * the code that performs them; these three had nothing watching.
	 *
	 * @param array<string, mixed> $context
	 */
	private static function note( string $type, int $severity, string $object_type, string $object_id, array $context ): void {
		Writer::instance()->record( $type, $severity, array( 'object_type' => $object_type, 'object_id' => $object_id, 'context' => $context ) );
		Writer::instance()->flush();
	}
	private static function execute( array $item ): string|\WP_Error {
		if ( ! self::ready() || $item['refusal'] ) { return self::error( $item['refusal'] ); }
		$kind = $item['kind']; $target = $item['target']; $before = $item['before'];
		if ( in_array( $kind, array( 'quarantine', 'restore' ), true ) ) {
			$state = self::file_state( $target ); if ( is_wp_error( $state ) || $state !== $before ) { return self::error(); }
			if ( 'restore' === $kind ) { $r = \BetterShield\Integrity\Restore::apply( $target, $before['sha256'] ); return is_wp_error( $r ) ? $r : $r['undo']; }
			$undo = Guarded::replace_verified( 'incident_quarantine', $state['path'], "<?php\n// Contents preserved in BetterShield quarantine.\n", __( 'Incident response', 'bettershield' ), $state['sha256'] );
			if ( is_wp_error( $undo ) ) { return $undo; }
			// The placeholder is this response's own, not a new change (#2345).
			\BetterShield\Integrity\KeepInQuarantine::hold( (int) $target, $state['path'] );
			self::note( 'file_quarantined', Writer::SEVERITY_MEDIUM, 'file', $state['registered'], array( 'undo' => $undo ) );
			return $undo;
		}
		if ( 'cron' === $kind ) {
			$event = wp_get_scheduled_event( $target, array(), $before['at'] );
			if ( has_action( $target ) || ! $event || $event->schedule !== $before['schedule'] ) { return self::error(); }
			$undo = Ledger::open( 'incident_cron', array( 'hook' => $target ) + $before, array() ); if ( ! $undo ) { return Repository::error(); }
			$r = wp_unschedule_event( $before['at'], $target, array(), true );
			if ( is_wp_error( $r ) ) { return $r; }
			if ( ! $r ) { return self::error(); }
			self::note( 'incident_cron_unscheduled', Writer::SEVERITY_MEDIUM, 'cron', $target, array( 'undo' => $undo, 'at' => (int) $before['at'], 'schedule' => (string) $before['schedule'] ) );
			return $undo;
		}
		$refusal = Accounts::refusal( $target, 'demote' !== $kind ); if ( $refusal ) { return self::error( $refusal ); }
		if ( 'reset' === $kind ) { return self::hold( $target, $before ); }
		if ( 'demote' === $kind ) {
			if ( Accounts::caps( $target ) !== $before || ! current_user_can( 'promote_user', $target ) ) { return self::error(); }
			$undo = Ledger::open( 'incident_demote', array( 'user' => $target, 'caps' => $before ), array( 'caps' => array() ) ); if ( ! $undo ) { return Repository::error(); }
			if ( ! Accounts::replace_caps( $target, $before, array() ) ) { return self::error(); }
			self::note( 'incident_account_demoted', Writer::SEVERITY_MEDIUM, 'user', (string) $target, array( 'undo' => $undo, 'removed' => count( $before ) ) );
			return $undo;
		}
		if ( ! hash_equals( $before['digest'], Accounts::fingerprint( $target, $kind ) ) ) { return self::error(); }
		if ( 'sessions' === $kind ) { \BetterShield\Login\Sessions::instance()->end_for_user( $target ); wp_cache_delete( $target, 'user_meta' ); return get_user_meta( $target, 'session_tokens', true ) ? self::error( __( 'Session removal could not be verified.', 'bettershield' ) ) : ''; }
		foreach ( $before['uuids'] as $uuid ) { $r = \WP_Application_Passwords::delete_application_password( $target, $uuid ); if ( is_wp_error( $r ) || ! $r ) { return self::error( __( 'Removal stopped. Some application passwords may already be revoked. Check the account.', 'bettershield' ) ); } }
		return '';
	}
	public static function undo( string $plan, string $item_id ): array|\WP_Error {
		if ( ! Claim::claim( 'incident_response', 300 ) ) { return self::error(); }
		try {
			$view = self::view( $plan ); if ( is_wp_error( $view ) || ! self::ready() ) { return self::error(); }
			$row = Ledger::find( $plan ); $result = $row->applied_state['results'][ $item_id ] ?? array();
			$token = $result['undo'] ?? ''; $undo = $token ? Ledger::find( $token ) : null;
			if ( $undo && ( $undo->reverted_at || self::hold_gone( $undo ) ) && 'applied' === ( $result['status'] ?? '' ) ) { return self::error( __( 'This was already reversed outside this plan.', 'bettershield' ) ); }
			if ( ! $undo || $undo->reverted_at || 'applied' !== ( $result['status'] ?? '' ) ) { return self::error(); }
			$before = $undo->prior_state;
			if ( 'incident_demote' === $undo->action_key ) {
				// Empty capability maps need a nonempty CAS sentinel in core's API.
				global $wpdb; $id = $before['user'];
				if ( Accounts::refusal( $id ) || ! current_user_can( 'promote_user', $id ) || Accounts::caps( $id ) !== array() ) { return self::error(); }
				$changed = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET meta_value=%s WHERE user_id=%d AND meta_key=%s AND meta_value=%s LIMIT 1', $wpdb->usermeta, maybe_serialize( $before['caps'] ), $id, $wpdb->get_blog_prefix() . 'capabilities', maybe_serialize( array() ) ) );
				clean_user_cache( $id ); if ( 1 !== $changed ) { return self::error(); } ( new \WP_User( $id ) )->update_user_level_from_caps();
				Ledger::mark_reverted( $token );
			} elseif ( PasswordHold::KEY === $undo->action_key ) {
				$id = (int) $before['user'];
				if ( Accounts::refusal( $id, true ) || PasswordHold::token( $id ) !== $token || ! PasswordHold::lift( $id, 'undo' ) ) { return self::error(); }
			} elseif ( 'incident_cron' === $undo->action_key ) {
				if ( wp_get_scheduled_event( $before['hook'], array(), $before['at'] ) ) { return self::error(); }
				$r = $before['schedule'] ? wp_schedule_event( $before['at'], $before['schedule'], $before['hook'], array(), true ) : wp_schedule_single_event( $before['at'], $before['hook'], array(), true );
				if ( is_wp_error( $r ) || ! $r ) { return self::error(); } Ledger::mark_reverted( $token );
			} else {
				$state = self::file_state( $row->prior_state['items'][ $item_id ]['target'], true );
				// Both sides resolved: the plan reads the file's real path, and a
				// restore records the path through a linked folder above it.
				if ( is_wp_error( $state ) || $state['path'] !== realpath( (string) $undo->applied_state['path'] ) || ! hash_equals( $undo->applied_state['sha256'], $state['sha256'] ) ) { return self::error(); }
				$r = Guarded::restore( $token ); if ( is_wp_error( $r ) ) { return $r; }
			}
			$receipt = $row->applied_state; $receipt['results'][ $item_id ]['status'] = 'undone';
			if ( ! self::save( $plan, $receipt ) ) { return Repository::error(); }
			return self::view( $plan );
		} finally { Claim::release( 'incident_response' ); }
	}
	/**
	 * Why an account cannot be asked for a new password, or ''.
	 *
	 * The hold sends the reset link to the account's own address, so the step
	 * is refused wherever that link could not work or would reach the wrong
	 * person: an address that changed during the incident goes to whoever
	 * changed it. An activity record that cannot be read refuses too, since
	 * nothing could then say the address is the owner's.
	 */
	private static function reset_refusal( int $id, int $from ): string {
		global $wpdb;
		$user = get_userdata( $id );
		if ( ! $user || ! \BetterShield\Password\Policy::instance()->user_is_privileged( $id ) ) { return __( 'Only accounts that can change the site are offered this step.', 'bettershield' ); }
		if ( PasswordHold::has( $id ) ) { return __( 'Password sign-in is already blocked until a new password is set.', 'bettershield' ); }
		if ( true !== wp_is_password_reset_allowed_for_user( $user ) ) { return __( 'This site does not let this account reset its password.', 'bettershield' ); }
		if ( ! is_email( $user->user_email ) ) { return __( 'This account has no email address a reset link could reach.', 'bettershield' ); }
		$changed = self::email_changed( $id, gmdate( 'Y-m-d H:i:s', $from ) );
		if ( null === $changed ) { return __( 'The activity record could not be read to check this account’s email address.', 'bettershield' ); }
		if ( $changed ) { return __( 'This account’s email changed during the incident, so a reset link would go to whoever changed it. Check the address first.', 'bettershield' ); }
		return '';
	}
	/**
	 * Whether the account's email address changed since then, or null when a
	 * record could not be read.
	 *
	 * On a network the address and the hold are the network's, so the change
	 * counts from whichever site made it: every site's rows in the network
	 * table, and the own log of any site whose rows have not moved there yet.
	 * A site with no log at all has nothing to say.
	 */
	private static function email_changed( int $id, string $since ): ?bool {
		global $wpdb;

		$logs = self::event_logs();

		if ( null === $logs ) {
			return null;
		}

		foreach ( $logs as list( $table, $where ) ) {
			$hit = $wpdb->get_var( $wpdb->prepare( 'SELECT 1 FROM %i WHERE ' . $where . ' AND event_type=%s AND object_id=%s AND occurred_at>=%s LIMIT 1', $table, 'user_email_changed', (string) $id, $since ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the site clause is built by Schema from integers and literal names.

			if ( '' !== $wpdb->last_error ) {
				return null;
			}

			if ( $hit ) {
				return true;
			}
		}

		return false;
	}

	/** The last answer to which logs hold the network's events, with what it was worked out from. */
	private static ?array $event_logs = null;

	/**
	 * Every log an account's events can be in, each with the clause that reads
	 * it; null when one could not be read. Worked out again only once a site
	 * has been added or changed, or a site's log has moved.
	 *
	 * @return array<int, array{0: string, 1: string}>|null
	 */
	private static function event_logs(): ?array {
		global $wpdb;

		$basis = wp_cache_get_last_changed( 'sites' ) . '|' . md5( (string) wp_json_encode( \BetterShield\Database\NetworkMigration::state()['switched'] ?? array() ) );

		if ( null !== self::$event_logs && self::$event_logs[0] === $basis ) {
			return self::$event_logs[1];
		}

		$logs = array( array( Schema::table( 'events' ), Schema::site_where( 'events' ) ) );

		if ( is_multisite() ) {
			$logs     = array( array( Schema::network_table( 'events' ), Schema::network_where( array() ) ) );
			$switched = (array) ( \BetterShield\Database\NetworkMigration::state()['switched'] ?? array() );

			$page     = 0;

			do {
				$ids = get_sites(
					array(
						'network_id' => get_current_network_id(),
						'fields'     => 'ids',
						'number'     => 200,
						'offset'     => 200 * $page++,
					)
				);

				foreach ( $ids as $site ) {
					if ( (int) $site === (int) get_main_site_id() || ! empty( $switched[ (string) $site ]['events'] ) ) {
						continue;
					}

					$own = $wpdb->get_blog_prefix( (int) $site ) . 'bettershield_events';

					// Read rather than listed, so a table this request made
					// is seen too. A site with no log has nothing to say; any
					// other failure means a log nobody could read.
					$was = $wpdb->suppress_errors( true );
					$wpdb->query( $wpdb->prepare( 'SELECT 1 FROM %i LIMIT 0', $own ) );
					$wpdb->suppress_errors( $was );

					if ( '' === $wpdb->last_error ) {
						$logs[] = array( $own, 'site_id = 0' );
					} elseif ( false === stripos( $wpdb->last_error, "doesn't exist" ) ) {
						return null;
					}
				}
			} while ( 200 === count( $ids ) );
		}

		self::$event_logs = array( $basis, $logs );

		return $logs;
	}
	/**
	 * The address a reset link would go to, as a keyed digest: enough to see it change, nothing to read back.
	 * Keyed on the plugin's own secret: one keyed on the salts changed when the keys were rotated between
	 * preparing a plan and applying it, and the reset step refused a plan nothing had changed.
	 */
	private static function email_digest( int $id ): string {
		$user = get_userdata( $id );
		return $user ? hash_hmac( 'sha256', 'reset-email|' . strtolower( (string) $user->user_email ), \BetterShield\Support\ClientIp::signing_secret() ) : '';
	}
	/**
	 * Place the new-password hold and send core's reset email.
	 *
	 * The hold is written, with its way back, before the email goes. An email
	 * that could not be sent lifts it again: a hold nobody was told how to
	 * clear would only be a lockout.
	 */
	private static function hold( int $id, array $before ): string|\WP_Error {
		$refusal = self::reset_refusal( $id, (int) ( $before['from'] ?? 0 ) );
		if ( $refusal ) { return self::error( $refusal ); }
		if ( ! hash_equals( (string) ( $before['email'] ?? '' ), self::email_digest( $id ) ) ) { return self::error(); }
		$undo = PasswordHold::place( $id );
		if ( '' === $undo ) { return self::error(); }
		$sent = retrieve_password( get_userdata( $id )->user_login );
		if ( true !== $sent ) {
			PasswordHold::lift( $id, 'not_sent' );
			return self::error( __( 'The reset email failed, so the account signs in as before.', 'bettershield' ) );
		}
		self::note( 'incident_password_held', Writer::SEVERITY_MEDIUM, 'user', (string) $id, array( 'undo' => $undo ) );
		return $undo;
	}
	/**
	 * What a recorded change calls for, read off the change itself, so a
	 * refusal does not change what the plan offers: a modified core file
	 * refused because it was already put back was offered as a quarantine.
	 */
	private static function file_kind( int $id ): string {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT change_type, context FROM %i WHERE site_id=0 AND id=%d', Schema::table( 'integrity_changes' ), $id ) );
		return $row && 'modified' === $row->change_type && in_array( $row->context, array( 'core', 'plugin' ), true ) ? 'restore' : 'quarantine';
	}
	/**
	 * Resolve only a current integrity record into its registered target. No links, self-code, or config.
	 *
	 * Each refusal says what is true of the change. They all said "The target
	 * or plan changed. Prepare a fresh plan", and a fresh plan refused the
	 * same change the same way.
	 *
	 * `$php_only` false lets a file of any type through, for a file kept from
	 * Activity › Files rather than from an incident's plan.
	 */
	public static function file_state( int $id, bool $undo = false, bool $php_only = true ): array|\WP_Error {
		global $wpdb;
		if ( ! current_user_can( 'update_plugins' ) || ( is_multisite() && ! current_user_can( 'manage_network' ) ) ) { return self::error( is_multisite() && ! current_user_can( 'manage_network' ) ? __( 'Only a network administrator can change the files every site on this network shares. Ask one to review this change.', 'bettershield' ) : __( 'Changing these files needs permission to update plugins. Ask an administrator to review this change.', 'bettershield' ) ); }
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE site_id=0 AND id=%d', Schema::table( 'integrity_changes' ), $id ) );
		if ( ! $row ) { return self::error( __( 'That file change is no longer on record.', 'bettershield' ) ); }
		if ( ! $undo && ! in_array( $row->status, array( 'new', 'acknowledged' ), true ) ) { return self::error( __( 'This change is already dealt with: the file was put back, accepted, or matches again.', 'bettershield' ) ); }
		if ( ! \BetterShield\Integrity\Manifest::is_safe_relative_path( $row->path ) ) { return self::error(); }
		// Any type for a file kept from Activity › Files (#1971); an incident's
		// response stays with the PHP files it was built for.
		if ( preg_match( '~(?:^|/)(?:bettershield(?:-ultra)?|wp-config\.php)(?:/|$)~i', $row->path ) ) { return self::error( __( 'BetterShield’s own files and wp-config.php are never moved.', 'bettershield' ) ); }
		if ( $php_only && ! preg_match( '/\.(?:' . Packages::SERVER_PHP . ')\z/i', $row->path ) ) { return self::error( __( 'Only PHP code files can be moved here. BetterShield’s own files and wp-config.php are never moved.', 'bettershield' ) ); }
		// A file at the install root nobody published is recorded as `extra`
		// against core's own target, and can be kept from Activity › Files
		// too. Never the server's own configuration files there: those are
		// shared files, written only through a marked block.
		$extra = ! $php_only && \BetterShield\Integrity\Manifest::CONTEXT_EXTRA === $row->context;
		if ( $extra && preg_match( '~(?:^|/)(?:\.htaccess|\.user\.ini|php\.ini|web\.config|nginx\.conf)\z~i', $row->path ) ) { return self::error( __( 'The server’s own configuration files are never moved.', 'bettershield' ) ); }
		foreach ( \BetterShield\Integrity\Targets::all() as $t ) {
			$context = $extra && \BetterShield\Integrity\Manifest::CONTEXT_CORE === $t['context'] ? \BetterShield\Integrity\Manifest::CONTEXT_EXTRA : $t['context'];
			if ( $context !== $row->context || $t['slug'] !== $row->slug || ! str_starts_with( $row->path, $t['prefix'] ) ) { continue; }
			$root = rtrim( $t['root'], '/' ); $relative = substr( $row->path, strlen( $t['prefix'] ) ); $path = $root . '/' . $relative;
			// A registered root may itself be relocated, but nothing below it may redirect a write.
			$root_real = realpath( $root ); $real = realpath( $path );
			if ( ! $root_real || ! $real || ! str_starts_with( $real, $root_real . '/' ) ) { continue; }
			$walk = $root; foreach ( explode( '/', $relative ) as $part ) { $walk .= '/' . $part; if ( is_link( $walk ) ) { return self::error( __( 'A linked file path requires manual review.', 'bettershield' ) ); } }
			if ( ! is_file( $real ) || @filesize( $real ) > 2 * MB_IN_BYTES || ! is_readable( $real ) ) { return self::error( __( 'The file is missing, unreadable, or larger than 2 MB.', 'bettershield' ) ); }
			foreach ( array_filter( array( realpath( BETTERSHIELD_PATH ), defined( 'BETTERSHIELD_ULTRA_PATH' ) ? realpath( BETTERSHIELD_ULTRA_PATH ) : false ) ) as $protected ) { if ( str_starts_with( $real, $protected . '/' ) ) { return self::error( __( 'Recovery and protection code cannot be a response target.', 'bettershield' ) ); } }
			$hash = @hash_file( 'sha256', $real );
			if ( ! $hash ) { return self::error( __( 'The file is missing, unreadable, or larger than 2 MB.', 'bettershield' ) ); }
			if ( ! $undo && ! hash_equals( $row->hash_after, 'md5' === $row->algo ? (string) @hash_file( 'md5', $real ) : $hash ) ) { return self::error( __( 'The file changed since the last check. Check again, then prepare a fresh plan.', 'bettershield' ) ); }
			return array( 'path' => $real, 'sha256' => $hash, 'change_type' => $row->change_type, 'context' => $row->context, 'registered' => (string) $row->path );
		}
		return self::error( __( 'The recorded file is no longer within a supported target.', 'bettershield' ) );
	}

	/**
	 * The account an action is about, as the owner knows it: its name and
	 * its role here, then its number, since two accounts can share a name.
	 * "Account #2" alone left the owner to look up an administrator before
	 * removing its roles (#1932). Said when the plan is read, so no name is
	 * kept with it; someone who may not list accounts is told the number
	 * only, as before.
	 */
	private static function account_named( int $user ): string {
		$account = get_userdata( $user );

		if ( ! $account instanceof \WP_User || ! current_user_can( 'list_users' ) ) {
			/* translators: %d: numeric account ID. */
			return sprintf( __( 'account #%d', 'bettershield' ), $user );
		}

		$names = wp_roles()->get_names();
		$roles = array_values( array_filter( array_map( static fn( $role ) => isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : '', (array) $account->roles ) ) );
		$name  = '' !== trim( (string) $account->display_name ) ? (string) $account->display_name : (string) $account->user_login;

		return sprintf(
			/* translators: 1: an account's display name, 2: its roles on this site, 3: its numeric ID. */
			__( '%1$s (%2$s, account #%3$d)', 'bettershield' ),
			$name,
			$roles ? implode( ', ', $roles ) : __( 'no role', 'bettershield' ),
			$user
		);
	}
}
