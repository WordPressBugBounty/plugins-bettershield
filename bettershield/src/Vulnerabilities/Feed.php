<?php
/**
 * Where vulnerability data comes from — the one interface the supply hides
 * behind.
 *
 * A feed is asked about what this site runs and answers with the advisories
 * that touch it: slug-keyed, version-bounded, with identifiers a person or
 * an agent can follow. Which company's data stands behind it is a commercial
 * decision that may change; the matcher, the findings, the alerts and the
 * ability never learn. The default adapter consults the Hub only after explicit owner consent.
 * A custom filter can replace or disable that adapter.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface Feed {

	/** A stable machine name for this supply: what the state records. */
	public function id(): string;

	/** What a person is told is being consulted. */
	public function label(): string;

	/**
	 * Advisories touching the given inventory.
	 *
	 * @param array<int, array{type: string, slug: string, version: string}> $inventory What the site runs.
	 * @return array{advisories: array<int, array<string, mixed>>, published_at: string}|\WP_Error
	 *         Each advisory: { id, type: plugin|theme|core, slug, title, severity,
	 *         cve_ids: string[], affected_max: string|null (last vulnerable
	 *         version, inclusive), fixed_in: string|null (null = no fix yet),
	 *         disclosed_at, references: string[] }. published_at is the
	 *         feed's own currency, ISO 8601 UTC. Normalized advisories also keep
	 *         affected_ranges, patched_ranges, patched_versions, provenance and
	 *         attribution; those ranges override the legacy single-bound fields.
	 */
	public function advisories( array $inventory );
}
