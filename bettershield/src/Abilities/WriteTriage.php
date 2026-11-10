<?php
/** File and incident triage contracts shared by the registry and callbacks. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Abilities;
use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Agents\Capture;
use BetterShield\Incidents\Repository;
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- fresh plugin-owned state and durable intent verification.
final class WriteTriage {
	public const NAMES = array( 'propose-file-expected', 'mark-file-expected', 'stop-ignoring-file', 'propose-incident-status', 'set-incident-status' );
	public static function definitions( callable $execute, array $plan_meta, array $act_meta, array $plan_fields, array $plan_required ): array {
		$id = array( 'type' => 'integer', 'minimum' => 1 ); $string = array( 'type' => 'string' ); $boolean = array( 'type' => 'boolean' );
		$status = array( 'type' => 'string', 'enum' => array( 'acknowledged', 'resolved' ) );
		$confirmation = array( 'proposal_id' => $id, 'confirmation' => $string );
		$specs = array(
			'propose-file-expected' => array( __( 'Suggest accepting a file change', 'bettershield' ), __( 'Describes accepting one recorded file change. This hides it from open changes without editing the file. Show the plan and use mark-file-expected only after the person agrees.', 'bettershield' ), array( 'change_id' => $id ), array( 'change_id' ) ),
			'mark-file-expected' => array( __( 'Accept a file change', 'bettershield' ), __( 'Accepts the exact file change in a confirmed proposal, after checking that its checksum and status have not moved. Returns the undo handle that reports it again. Changes no file bytes.', 'bettershield' ), $confirmation + array( 'change_id' => $id ), array( 'proposal_id', 'confirmation' ) ),
			'stop-ignoring-file' => array( __( 'Report a file change again', 'bettershield' ), __( 'Reports one accepted file change again, including a change marked from the site dashboard. Requires write access but no confirmation. Changes no file bytes.', 'bettershield' ), array( 'change_id' => $id ), array( 'change_id' ) ),
			'propose-incident-status' => array( __( 'Suggest changing an incident status', 'bettershield' ), __( 'Describes acknowledging or handling one incident. Handling stops new evidence collection and needs the person’s agreement to this plan. Its undo reopens the incident as acknowledged.', 'bettershield' ), array( 'incident_id' => $id, 'status' => $status ), array( 'incident_id', 'status' ) ),
			'set-incident-status' => array( __( 'Change an incident status', 'bettershield' ), __( 'Acknowledges one incident directly with incident_id and status acknowledged, or applies a confirmed proposal with proposal_id and confirmation. Handling requires a proposal because it stops evidence collection; its undo reopens the incident as acknowledged.', 'bettershield' ), $confirmation + array( 'incident_id' => $id, 'status' => $status ), array() ),
		);
		$out = array();
		foreach ( $specs as $name => $spec ) {
			$plan = str_starts_with( $name, 'propose-' ); $file = str_contains( $name, 'file' );
			$fields = array( $file ? 'change_id' : 'incident_id' => $id ) + ( $file ? array( 'path' => $string ) : array( 'status' => $status ) );
			$output = $plan ? $plan_fields + $fields : $fields + array( 'applied' => $boolean, 'undo_token' => $string );
			$out[ 'bettershield/' . $name ] = ( $plan ? $plan_meta : $act_meta ) + array(
				'label' => $spec[0], 'description' => $spec[1],
				'input_schema' => array( 'type' => 'object', 'properties' => $spec[2], 'required' => $spec[3] ),
				'output_schema' => array( 'type' => 'object', 'properties' => $output, 'required' => array_merge( $plan ? $plan_required : array( 'applied' ), array_keys( $fields ) ) ),
				'execute_callback' => static function ( $input ) use ( $execute, $name ) { return $execute( $name, $input ); },
			);
		}
		return $out;
	}
	public static function input( string $name, array $input ): ?\WP_Error {
		if ( ! in_array( $name, self::NAMES, true ) ) { return self::error( 'bettershield_triage_input', __( 'Choose a supported file or incident action.', 'bettershield' ), 400 ); }
		$confirmed = 'mark-file-expected' === $name || ( 'set-incident-status' === $name && ( isset( $input['proposal_id'] ) || isset( $input['confirmation'] ) ) );
		if ( $confirmed ) {
			if ( ! is_int( $input['proposal_id'] ?? null ) || $input['proposal_id'] <= 0 || ! is_string( $input['confirmation'] ?? null ) || '' === $input['confirmation'] ) { return self::error( 'bettershield_confirmation_required', __( 'Use the proposal and its single-use confirmation after the person agrees.', 'bettershield' ), 403 ); }
			return null;
		}
		$key = str_contains( $name, 'file' ) ? 'change_id' : 'incident_id';
		if ( ! is_int( $input[ $key ] ?? null ) || $input[ $key ] <= 0 || ( 'incident_id' === $key && ! in_array( $input['status'] ?? '', array( 'acknowledged', 'resolved' ), true ) ) ) { return self::error( 'bettershield_triage_input', __( 'Name one recorded change or incident and a supported status.', 'bettershield' ), 400 ); }
		if ( 'set-incident-status' === $name && 'resolved' === $input['status'] ) { return self::error( 'bettershield_confirmation_required', __( 'Handling stops evidence collection. Ask for the plan and the person’s agreement first.', 'bettershield' ), 403 ); }
		return null;
	}
	public static function file( int $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE site_id=0 AND id=%d', Schema::table( 'integrity_changes' ), $id ) );
		return null === $row ? self::error( 'bettershield_unknown_change', __( 'There is no such file change on record.', 'bettershield' ), 404 ) : $row;
	}
	public static function file_digest( object $row ): string {
		return (string) Capture::digest( array( 'id' => (int) $row->id, 'path' => (string) $row->path, 'status' => (string) $row->status, 'hash_before' => $row->hash_before, 'hash_after' => $row->hash_after, 'change_type' => (string) $row->change_type ) );
	}
	public static function moved(): \WP_Error { return self::error( 'bettershield_state_moved', __( 'That record changed after the plan was prepared. Read it again and ask for a new plan.', 'bettershield' ), 409 ); }
	public static function error( string $code, string $message, int $status ): \WP_Error { return new \WP_Error( $code, $message, array( 'status' => $status ) ); }
	/** Verify this invocation's event reached disk before anything changes. */
	public static function intent( string $ability ): ?\WP_Error {
		global $wpdb; $operation = wp_generate_uuid4();
		Writer::instance()->record( 'agent_triage_requested', Writer::SEVERITY_MEDIUM, array( 'object_type' => 'ability', 'object_id' => $ability, 'context' => array( 'operation_id' => $operation ) ) );
		Writer::instance()->flush();
		$found = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM %i WHERE event_type='agent_triage_requested' AND JSON_UNQUOTE(JSON_EXTRACT(context, '$.operation_id'))=%s LIMIT 1", Schema::table( 'events' ), $operation ) );
		return null !== $found && '' === $wpdb->last_error ? null : self::error( 'bettershield_activity_unavailable', __( 'The activity record could not be saved. Nothing was changed.', 'bettershield' ), 503 );
	}
}
