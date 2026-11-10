<?php
/**
 * The vulnerability data source, as an interface.
 *
 * The source behind vulnerability data is a commercial decision that may
 * change; the ability that reports it must not. Everything that reads
 * vulnerability state reads it through this interface, so swapping the
 * supply touches one binding and zero features.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface Source {

	/**
	 * Whether this source can answer at all right now.
	 */
	public function available(): bool;

	/**
	 * When the data was last refreshed, ISO 8601 UTC, or null when never.
	 * Staleness is always shown, never hidden.
	 */
	public function last_updated(): ?string;

	/**
	 * Vulnerability state for what this site runs.
	 *
	 * @param string $severity_min Lowest severity to include.
	 * @param int    $limit        Row ceiling.
	 * @return array<int, array<string, mixed>> Rows of
	 *         { slug, name, installed_version, vulnerable, severity,
	 *           cve_ids, fixed_in, patch_available, disclosed_at }.
	 */
	public function state( string $severity_min, int $limit ): array;
}
