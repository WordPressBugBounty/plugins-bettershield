<?php
/** Write consent belongs to one generation of the site's access grants. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Mcp;
use BetterShield\Abilities\Registrar;
if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WriteGrants {

	public const OPTION = 'bettershield_mcp_write_generation';

	/** Read the authority afresh, including across a pending token rotation or an object-cache race. */
	public static function current(): array {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- two option keys are the revocation boundary; a request's cached opt-in can predate a concurrent withdrawal.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT option_name, option_value FROM %i WHERE option_name IN (%s, %s)', $wpdb->options, self::OPTION, Registrar::WRITE_OPTION ), ARRAY_A );
		$valid = '' === $wpdb->last_error && is_array( $rows );
		$options = array_column( is_array( $rows ) ? $rows : array(), 'option_value', 'option_name' );
		$generation = (string) ( $options[ self::OPTION ] ?? '' );
		$valid = $valid && ( '' === $generation || 1 === preg_match( '/^[a-f0-9]{32}$/D', $generation ) );
		return array( 'enabled' => $valid && '1' === ( $options[ Registrar::WRITE_OPTION ] ?? '' ), 'generation' => $generation, 'valid' => $valid );
	}

	/** A new approval, never a renewal. An opt-in that went off before issuance wins. */
	public static function issue( string $scope ): array {
		$current = self::current();
		return array( 'scope' => Scopes::canonical( $current['enabled'] && Scopes::allows_write( $scope ) ), 'write_generation' => $current['generation'] );
	}

	/** Old and in-flight credentials stay narrowed, even if a stale writer restores their stored scope. */
	public static function scope( array $entry, ?array $current = null ): string {
		$current = $current ?? self::current();
		return Scopes::canonical( $current['enabled'] && hash_equals( $current['generation'], (string) ( $entry['write_generation'] ?? '' ) ) && Scopes::allows_write( (string) ( $entry['scope'] ?? '' ) ) );
	}

	/** Change the consent generation before any later opt-in can give write access again. */
	public static function withdraw(): bool {
		$generation = bin2hex( random_bytes( 16 ) );
		update_option( self::OPTION, $generation, false );
		$current = self::current();
		if ( ! $current['valid'] || ! hash_equals( $generation, $current['generation'] ) ) { return false; }
		Pairing::narrow_write_scope();
		OAuth::narrow_write_scopes();
		return true;
	}
}
