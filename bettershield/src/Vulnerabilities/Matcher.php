<?php
/**
 * Which advisories touch which installed versions.
 *
 * The rule is the one every feed states in its own words: a version is
 * vulnerable when it is below the fix, or — with no fix yet — at or below
 * the last version known affected, or — with neither bound — always. Ties
 * are decided by version_compare(), which is what WordPress itself updates
 * by. Results are grouped by the thing installed, worst severity first, so
 * one plugin with three advisories is one finding that lists three.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Matcher {

	public const SEVERITIES = array( 'critical', 'high', 'medium', 'low', 'info' );

	/**
	 * @param array<int, array<string, mixed>> $inventory  From Inventory::collect().
	 * @param array<int, array<string, mixed>> $advisories From a Feed.
	 * @return array<int, array<string, mixed>> Affected items: { type, slug, name,
	 *         installed_version, active, severity, fixed_in (highest fix across
	 *         advisories, or null), patch_available, advisories: [{ id, title,
	 *         severity, cve_ids, fixed_in, affected_max, disclosed_at,
	 *         references }] }.
	 */
	public static function match( array $inventory, array $advisories ): array {
		$installed = array();
		foreach ( $inventory as $item ) {
			$key = $item['type'] . ':' . strtolower( $item['slug'] );
			if ( isset( $installed[ $key ] ) ) {
				// Distinct folders can differ only by case on a case-sensitive filesystem.
				$seen = $installed[ $key ];
				$item['versions'] = array_values( array_unique( array_merge( $seen['versions'] ?? array( $seen['version'] ), $item['versions'] ?? array( $item['version'] ) ) ) );
				$item['active'] = ! empty( $seen['active'] ) || ! empty( $item['active'] );
			}
			$installed[ $key ] = $item;
		}

		$affected = array();

		foreach ( $advisories as $advisory ) {
			// A record the feed marks informational is a note about the
			// software, not a hole in it. Matched like the rest, a range of
			// every version made current WordPress read as vulnerable, and its
			// missing fix hid the real one for every older core (#2675).
			if ( ! empty( $advisory['informational'] ) ) {
				continue;
			}

			$key = ( $advisory['type'] ?? '' ) . ':' . strtolower( $advisory['slug'] ?? '' );

			if ( ! isset( $installed[ $key ] ) || 'unaffected' === self::installed_result( $installed[ $key ], $advisory ) ) {
				continue;
			}

			if ( ! isset( $affected[ $key ] ) ) {
				$item             = $installed[ $key ];
				$affected[ $key ] = array(
					'type'              => (string) $item['type'],
					'slug'              => (string) $item['slug'],
					'name'              => (string) ( $item['name'] ?? $item['slug'] ),
					'installed_version' => (string) $item['version'],
					'compared_versions' => $item['versions'] ?? array( $item['version'] ),
					'active'            => ! empty( $item['active'] ),
					'severity'          => 'info',
					'fixed_in'          => null,
					'patch_available'   => false,
					'advisories'        => array(),
				);
			}

			$status = self::installed_result( $installed[ $key ], $advisory );
			$affected[ $key ]['match_status'] = 'affected' === $status || 'affected' === ( $affected[ $key ]['match_status'] ?? '' ) ? 'affected' : 'unknown';
			// Known only when the provider gave one, in either shape: null, a
			// blank or no severity at all is unknown, not medium (#1956).
			$severity_known = is_scalar( $advisory['severity'] ?? null ) && '' !== trim( (string) $advisory['severity'] );
			$severity = $severity_known ? self::normalize_severity( (string) $advisory['severity'] ) : 'info';
			$fixed_in = isset( $advisory['fixed_in'] ) && '' !== (string) $advisory['fixed_in'] ? (string) $advisory['fixed_in'] : null;

			$normalized = array_intersect_key( $advisory, array_flip( array( 'affected_ranges', 'patched_ranges', 'patched_versions', 'attribution', 'exploited', 'informational', 'cvss_score', 'remediation', 'provider', 'provider_id' ) ) );
			// The bound is kept with the advisory, so a version other than the
			// one installed — an update on offer, a release in the directory —
			// can be judged by the same rule later.
			$affected[ $key ]['advisories'][] = $normalized + array(
				'match_status' => $status,
				'source_severity' => $severity_known ? $severity : null,
				'severity_known' => $severity_known,
				'id'           => (string) ( $advisory['id'] ?? '' ),
				'title'        => (string) ( $advisory['title'] ?? '' ),
				'severity'     => $severity,
				'cve_ids'      => array_values( array_map( 'strval', (array) ( $advisory['cve_ids'] ?? array() ) ) ),
				'fixed_in'     => $fixed_in,
				'affected_max' => isset( $advisory['affected_max'] ) && '' !== (string) $advisory['affected_max'] ? (string) $advisory['affected_max'] : null,
				'disclosed_at' => (string) ( $advisory['disclosed_at'] ?? '' ),
				'references'   => array_values( array_map( 'strval', (array) ( $advisory['references'] ?? array() ) ) ),
			);

			if ( array_search( $severity, self::SEVERITIES, true ) < array_search( $affected[ $key ]['severity'], self::SEVERITIES, true ) ) {
				$affected[ $key ]['severity'] = $severity;
			}

			// The version to update to: the highest fix named across every
			// advisory that touches this item — below it, something is open.
			if ( null !== $fixed_in && ( null === $affected[ $key ]['fixed_in'] || self::below( $affected[ $key ]['fixed_in'], $fixed_in ) ) ) {
				$affected[ $key ]['fixed_in'] = $fixed_in;
			}
		}

		foreach ( $affected as &$item ) {
			$confirmed = array_values( array_filter( $item['advisories'], static fn( array $a ): bool => 'affected' === $a['match_status'] ) );
			$ranked = $confirmed;
			usort( $ranked, static fn( array $a, array $b ): int => array_search( $a['severity'], self::SEVERITIES, true ) <=> array_search( $b['severity'], self::SEVERITIES, true ) );
			$known = array_values( array_filter( $ranked, static fn( array $a ): bool => $a['severity_known'] ?? true ) );
			$item['severity_known'] = (bool) $known;
			$item['source_severity'] = $known ? $known[0]['severity'] : null;
			$item['severity'] = $known ? $known[0]['severity'] : 'info';
			// A confirmed advisory nobody gave a severity takes medium, as the
			// finding grades it, so a known lower one beside it cannot hide it
			// as info or low (#1956).
			if ( $known && count( $known ) < count( $ranked ) && array_search( 'medium', self::SEVERITIES, true ) < array_search( $item['severity'], self::SEVERITIES, true ) ) {
				$item['severity'] = 'medium';
			}
			$candidates = array();
			foreach ( $item['advisories'] as $advisory ) {
				foreach ( $advisory['patched_versions'] ?? array() as $candidate ) { $candidates[] = $candidate; }
				foreach ( $advisory['patched_ranges'] ?? array() as $range ) { if ( null !== $range['from'] && $range['from_inclusive'] ) { $candidates[] = $range['from']; } }
			}
			foreach ( array_unique( $candidates ) as $candidate ) {
				$order = Versions::compare( $candidate, $item['installed_version'] );
				if ( null === $order || $order < 0 ) { continue; }
				$safe = true;
				// Only an advisory known to affect the candidate rules it out.
				// One whose versions can't be compared ruled out every
				// candidate, and an outdated plugin read "no fix yet" (#2676).
				foreach ( $item['advisories'] as $advisory ) { if ( self::affects( $candidate, $advisory ) ) { $safe = false; break; } }
				if ( $safe && ( null === $item['fixed_in'] || Versions::compare( $candidate, $item['fixed_in'] ) < 0 ) ) { $item['fixed_in'] = $candidate; }
			}
			// A patch is available only when every advisory names a fix.
			$item['patch_available'] = null !== $item['fixed_in'] && array() === array_filter( $item['advisories'], static fn( array $a ): bool => self::affects( $item['fixed_in'], $a ) );

			usort( $item['advisories'], static fn( array $a, array $b ): int => array_search( $a['severity'], self::SEVERITIES, true ) <=> array_search( $b['severity'], self::SEVERITIES, true ) );
		}
		unset( $item );

		usort( $affected, static fn( array $a, array $b ): int => array_search( $a['severity'], self::SEVERITIES, true ) <=> array_search( $b['severity'], self::SEVERITIES, true ) );

		return array_values( $affected );
	}

	/** Multiple headers in one folder never erase an older or unknown version. */
	private static function installed_result( array $item, array $advisory ): string {
		$unknown = false;
		foreach ( $item['versions'] ?? array( $item['version'] ) as $version ) {
			$result = isset( $advisory['affected_ranges'] ) ? Versions::result( (string) $version, $advisory ) : ( self::touches( (string) $version, $advisory ) ? 'affected' : 'unaffected' );
			if ( 'affected' === $result ) { return 'affected'; }
			$unknown = $unknown || 'unknown' === $result;
		}
		return $unknown ? 'unknown' : 'unaffected';
	}

	/**
	 * One stored item's advisories, each with its own severity and bounds,
	 * ready for touches().
	 *
	 * The item's own severity and fix are the worst and the highest across
	 * all of them, so a version judged by those alone is judged by an
	 * advisory that may not exist. An item stored without advisories is read
	 * as one advisory carrying the item's own severity and fix; one stored
	 * before the bound was kept reads as having none.
	 *
	 * @param array<string, mixed> $item An affected item from match().
	 * @return array<int, array{severity: string, fixed_in: ?string, affected_max: ?string}>
	 */
	public static function advisories( array $item ): array {
		$listed = isset( $item['advisories'] ) && is_array( $item['advisories'] ) && array() !== $item['advisories']
			? $item['advisories']
			: array( $item );
		$out    = array();

		foreach ( $listed as $advisory ) {
			if ( ! is_array( $advisory ) ) {
				continue;
			}

			$out[] = array_intersect_key( $advisory, array_flip( array( 'affected_ranges', 'patched_ranges', 'patched_versions', 'severity_known', 'source_severity' ) ) ) + array(
				'severity'     => self::normalize_severity( (string) ( $advisory['severity'] ?? 'medium' ) ),
				'fixed_in'     => isset( $advisory['fixed_in'] ) && '' !== (string) $advisory['fixed_in'] ? (string) $advisory['fixed_in'] : null,
				'affected_max' => isset( $advisory['affected_max'] ) && '' !== (string) $advisory['affected_max'] ? (string) $advisory['affected_max'] : null,
			);
		}

		return $out;
	}

	/**
	 * Whether an advisory is known to affect a version.
	 *
	 * Stricter than touches(): an advisory whose versions can't be compared
	 * is listed as unknown, but it says nothing about a version we would
	 * point someone to. Counting it there named no fix at all (#2676).
	 *
	 * @param array<string, mixed> $advisory
	 */
	public static function affects( string $version, array $advisory ): bool {
		if ( isset( $advisory['affected_ranges'] ) ) {
			return 'affected' === Versions::result( $version, $advisory );
		}

		return self::touches( $version, $advisory );
	}

	/**
	 * @param array<string, mixed> $advisory
	 */
	public static function touches( string $installed, array $advisory ): bool {
		if ( isset( $advisory['affected_ranges'] ) ) {
			return 'unaffected' !== Versions::result( $installed, $advisory );
		}
		$fixed_in     = isset( $advisory['fixed_in'] ) && '' !== (string) $advisory['fixed_in'] ? (string) $advisory['fixed_in'] : null;
		$affected_max = isset( $advisory['affected_max'] ) && '' !== (string) $advisory['affected_max'] ? (string) $advisory['affected_max'] : null;

		/*
		 * Decided before a version is required. With neither bound the
		 * advisory names every version, and a component whose header carries
		 * no version is running one of them — so the components nothing can be
		 * said about were exactly the ones exempted from the advisory that
		 * says it applies to all of them.
		 */
		if ( null === $fixed_in && null === $affected_max ) {
			return true;
		}

		// A bound still needs something to compare against.
		if ( '' === $installed ) {
			return false;
		}

		if ( null !== $fixed_in ) {
			return self::below( $installed, $fixed_in );
		}

		return ! self::below( $affected_max, $installed );
	}

	/**
	 * Whether one version is below another, reading `2.1` and `2.1.0` as the
	 * same release.
	 *
	 * `version_compare` reads a missing component as lower than a zero, so the
	 * two ways every feed and every plugin header write the same release
	 * compared as different ones — and a site running the fixed version was
	 * told it was vulnerable. Padding to a common length settles that without
	 * touching what a suffix means: `2.1-beta` still loses to `2.1`, because
	 * padding both to three parts leaves the pre-release marker where
	 * `version_compare` already ranks it below a number.
	 *
	 * Public so that every place comparing a version with a fix reads the two
	 * notations the same way the check does.
	 */
	public static function below( string $lower, string $higher ): bool {
		$a = explode( '.', $lower );
		$b = explode( '.', $higher );
		$n = max( count( $a ), count( $b ) );

		return version_compare(
			implode( '.', array_pad( $a, $n, '0' ) ),
			implode( '.', array_pad( $b, $n, '0' ) ),
			'<'
		);
	}

	public static function normalize_severity( string $severity ): string {
		$severity = strtolower( trim( $severity ) );

		return in_array( $severity, self::SEVERITIES, true ) ? $severity : 'medium';
	}
}
