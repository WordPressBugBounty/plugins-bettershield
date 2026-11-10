<?php
/** Confirmed actions, Free's own and add-ons', registered through the native Abilities API. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Abilities;
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WriteExtensions {
	/**
	 * Free's own confirmed fixes first, then trusted add-on declarations; Free
	 * owns the gates and confirmation lifecycle. An add-on cannot take a name
	 * Free declares, as the act or as the plan.
	 */
	public static function extensions(): array {
		$filtered = apply_filters( 'bettershield_write_abilities', array() );
		$out = WriteFixes::confirmed();
		$taken = array_merge( array_keys( $out ), array_column( $out, 'propose' ) );
		foreach ( is_array( $filtered ) ? $filtered : array() as $act => $spec ) {
			if ( in_array( $act, $taken, true ) || in_array( $spec['propose'] ?? null, $taken, true ) ) { continue; }
			if ( ! is_string( $act ) || ! preg_match( '/^[a-z][a-z0-9-]{0,51}$/D', $act ) || ! is_array( $spec )
				|| ! is_string( $spec['propose'] ?? null ) || ! preg_match( '/^propose-[a-z0-9-]{1,44}$/D', $spec['propose'] )
				|| ! is_string( $spec['label'] ?? null ) || ! is_string( $spec['description'] ?? null )
				|| ! is_string( $spec['target_type'] ?? null ) || ! is_array( $spec['input_schema'] ?? null )
				|| ! is_array( $spec['output'] ?? null ) || ! is_callable( $spec['snapshot'] ?? null ) || ! is_callable( $spec['execute'] ?? null ) ) { continue; }
			if ( isset( $spec['undo_key'] ) && ( ! is_string( $spec['undo_key'] ) || ! is_callable( $spec['undo_snapshot'] ?? null ) || ! is_callable( $spec['undo_execute'] ?? null ) ) ) { continue; }
			$out[ $act ] = $spec;
		}
		return $out;
	}

	/** Resolve the registered pair rather than trusting an ability-name prefix. */
	public static function named( string $name ): ?array {
		foreach ( self::extensions() as $act => $spec ) {
			if ( $name === $act || $name === $spec['propose'] ) { return array( 'act' => $act ) + $spec; }
		}
		return null;
	}

	/** Only a declared add-on undo key can enter the extension undo path. */
	public static function undo( string $key ): ?array {
		foreach ( self::extensions() as $act => $spec ) {
			if ( in_array( $key, (array) ( $spec['undo_key'] ?? array() ), true ) ) { return array( 'act' => $act ) + $spec; }
		}
		return null;
	}

	/** Metadata cannot replace Free's permission callback or its execution wrapper. */
	public static function definitions( callable $execute, array $plan_meta, array $act_meta, array $plan_fields, array $plan_required ): array {
		$out = array();
		$act_meta['meta']['annotations']['idempotent'] = false;
		$id = array( 'type' => 'integer', 'minimum' => 1 ); $string = array( 'type' => 'string' );
		$confirmation = array( 'proposal_id' => $id, 'confirmation' => $string );
		foreach ( self::extensions() as $act => $spec ) {
			// A way back is spent through revert-hardening, so an undo-only pair registers its plan alone.
			foreach ( empty( $spec['undo_only'] ) ? array( $spec['propose'], $act ) : array( $spec['propose'] ) as $name ) {
				$plan = $name === $spec['propose'];
				$out[ 'bettershield/' . $name ] = ( $plan ? $plan_meta : $act_meta ) + array(
					'label' => $plan ? sprintf( /* translators: %s: the suggested action. */ __( 'Suggest: %s', 'bettershield' ), $spec['label'] ) : $spec['label'],
					'description' => $spec['description'] . ' ' . __( 'Show the plan to the person and execute only after they agree, using its single-use confirmation. No direct execution path is offered.', 'bettershield' ),
					'input_schema' => $plan ? $spec['input_schema'] : array( 'type' => 'object', 'properties' => $confirmation, 'required' => array_keys( $confirmation ) ),
					'output_schema' => array( 'type' => 'object', 'properties' => ( $plan ? $plan_fields : array( 'applied' => array( 'type' => 'boolean' ), 'undo_token' => $string ) ) + $spec['output'], 'required' => array_merge( $plan ? $plan_required : array( 'applied' ), $spec['output_required'] ?? array() ) ),
					'execute_callback' => static function ( $input ) use ( $execute, $name ) { return $execute( $name, $input ); },
				);
			}
		}
		return $out;
	}

	/** Reject replacement targets even though core's schema subset allows extra properties. */
	public static function valid_input( array $input, array $spec, bool $plan, bool $undo ): bool {
		if ( $plan ) {
			return array() === array_diff( array_keys( $input ), array_keys( $spec['input_schema']['properties'] ?? array() ) )
				&& true === rest_validate_value_from_schema( $input, $spec['input_schema'] );
		}
		$keys = $undo ? array( 'undo_token', 'confirmation', 'proposal_id' ) : array( 'proposal_id', 'confirmation' );
		if ( array() !== array_diff( array_keys( $input ), $keys ) || ! is_string( $input['confirmation'] ?? null ) || '' === $input['confirmation'] ) { return false; }
		if ( ! $undo || isset( $input['proposal_id'] ) ) {
			if ( ! is_int( $input['proposal_id'] ?? null ) || $input['proposal_id'] < 1 ) { return false; }
		}
		return ! $undo || ( is_string( $input['undo_token'] ?? null ) && '' !== $input['undo_token'] );
	}
}
