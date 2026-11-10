<?php
/** Resumable correlation over persisted sources, outside visitor responses. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Incidents;
use BetterShield\Database\Schema;
use BetterShield\Support\Claim;
use BetterShield\Support\Time;
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- bounded plugin-owned evidence reads.
final class Engine {
	public const OPTION = 'bettershield_incident_cursor';
	public const TASK = 'bettershield_incident_tick';
	public const CLAIM = 'incidents:write';
	public static function register(): void {
		add_action( self::TASK, array( self::class, 'tick' ) );
		add_action( 'bettershield_events_flushed', array( self::class, 'observe' ), 30, 2 );
	}
	public static function observe( array $events, array $context ): void {
		if ( ! empty( $context['checkout'] ) ) { return; }
		foreach ( $events as $event ) {
			if ( in_array( $event['event_type'], array_merge( Signals::EVENTS, array( 'file_changed', 'audit_ran' ) ), true ) ) {
				if ( ! wp_next_scheduled( self::TASK ) ) { wp_schedule_single_event( time() + 5, self::TASK ); }
				return;
			}
		}
	}
	public static function report(): array {
		$state = (array) get_option( self::OPTION, array() );
		return array( 'last_checked_at' => (string) ( $state['checked_at'] ?? '' ), 'pending' => ! empty( $state['pending'] ), 'failed' => ! empty( $state['failed'] ) );
	}
	public static function tick(): bool {
		if ( \BetterShield\Support\Checkout::is_store_path() || ! Schema::ready( 'incidents' ) || ! Claim::claim( self::CLAIM, 30 ) ) { return false; }
		global $wpdb;
		wp_cache_delete( self::OPTION, 'options' );
		$state = (array) get_option( self::OPTION, array() );
		$state['since'] = $state['since'] ?? Time::stamp( time() - DAY_IN_SECONDS );
		$started = microtime( true );
		$state['failed'] = false; $state['pending'] = false;
		try {
			$table = Schema::table( 'events' );
			if ( ( $state['event_table'] ?? '' ) !== $table ) { $state['event_table'] = $table; $state['event_id'] = 0; }
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- site predicate from Schema; placeholder list from a private fixed registry, all values bound.
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND id>%d AND occurred_at>=%s AND event_type IN (' . implode( ',', array_fill( 0, count( Signals::EVENTS ), '%s' ) ) . ') ORDER BY id ASC LIMIT 100', array_merge( array( $table, (int) ( $state['event_id'] ?? 0 ), $state['since'] ), Signals::EVENTS ) ), ARRAY_A );
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
			if ( '' !== $wpdb->last_error ) { throw new \RuntimeException(); }
			$state['pending'] = count( $rows ) === 100;
			foreach ( $rows as $row ) {
				$signal = Signals::event( $row );
				if ( $signal && ! Repository::ingest( $signal ) ) { throw new \RuntimeException(); }
				Takeover::observe( $row );
				$state['event_id'] = (int) $row['id'];
				if ( microtime( true ) - $started > 2 ) { $state['pending'] = true; break; }
			}
			// One incident for a shared file, on the site that runs the check.
			$rows = \BetterShield\Integrity\Shared::elsewhere() ? array() : $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE site_id=0 AND id>%d ORDER BY id ASC LIMIT 100', Schema::table( 'integrity_changes' ), (int) ( $state['integrity_id'] ?? 0 ) ), ARRAY_A );
			if ( '' !== $wpdb->last_error ) { throw new \RuntimeException(); }
			$state['pending'] = $state['pending'] || count( $rows ) === 100;
			foreach ( $rows as $row ) {
				$signal = Signals::integrity( $row );
				if ( $signal && ! Repository::ingest( $signal ) ) { throw new \RuntimeException(); }
				$state['integrity_id'] = (int) $row['id'];
				if ( microtime( true ) - $started > 2 ) { $state['pending'] = true; break; }
			}
			// The saved audit's observation, not a fresh execution of cron
			// callbacks. Hook arguments are never copied into an incident.
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- site predicate contains only Schema-generated identifiers/integers.
			$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM %i WHERE " . Schema::site_where( 'findings' ) . " AND finding_key='cron_events_unanswered' AND status='open' LIMIT 1", Schema::table( 'findings' ) ), ARRAY_A );
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			if ( '' !== $wpdb->last_error ) { throw new \RuntimeException(); }
			if ( $finding ) {
				$payload = json_decode( (string) $finding['evidence'], true );
				$hooks = array();
				foreach ( array_slice( (array) ( $payload['events'] ?? array() ), 0, 10 ) as $event ) { if ( isset( $event['hook'] ) ) { $hooks[] = \BetterShield\Support\Text::clip( (string) $event['hook'], 191 ); } }
				sort( $hooks );
				$digest = hash( 'sha256', wp_json_encode( $hooks ) . ':' . (int) ( $payload['total'] ?? 0 ) );
				if ( ( $state['cron_digest'] ?? '' ) !== $digest && ! Repository::ingest( array( 'source_key' => hash( 'sha256', 'cron:' . $finding['last_seen_at'] . ':' . $digest ), 'occurred_at' => $finding['last_seen_at'], 'anchor' => '', 'actor_id' => 0, 'event_type' => 'incident_cron_unanswered', 'snapshot' => array( 'source' => 'audit', 'source_id' => (int) $finding['id'], 'object_type' => 'cron', 'object_id' => 'cron_events_unanswered', 'target_user' => 0, 'details' => array( 'hooks' => $hooks, 'total' => (int) ( $payload['total'] ?? 0 ) ) ) ) ) ) { throw new \RuntimeException(); }
				$state['cron_digest'] = $digest;
			} else { unset( $state['cron_digest'] ); }
			$attached = Repository::attach_waiting();
			if ( false === $attached ) { throw new \RuntimeException(); }
			$state['pending'] = $state['pending'] || 200 === $attached;
			$state['checked_at'] = gmdate( 'c' );
		} catch ( \Throwable $error ) { $state['failed'] = true; }
		finally { $saved = update_option( self::OPTION, $state, false ); Claim::release( self::CLAIM ); }
		if ( ! $saved && get_option( self::OPTION ) !== $state ) { return false; }
		if ( $state['pending'] && ! wp_next_scheduled( self::TASK ) ) { wp_schedule_single_event( time() + 10, self::TASK ); }
		return ! $state['failed'];
	}
}
