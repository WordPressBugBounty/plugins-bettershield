<?php
/**
 * What the last check found, kept locally, with its age always attached.
 *
 * One option holds the affected items and when the feed said its data was
 * current. Every reader — the audit check, the ability, the screen — reads
 * through here, and every one of them gets the age with the answer, because
 * data presented without its age is data presented as current.
 *
 * This is also the plugin's `Vulnerabilities\Source`, so the ability that
 * reports vulnerability state reads the same record as everything else.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class State implements Source {

	public const OPTION = 'bettershield_vulnerability_state';

	/** Data older than this is called stale, and a finding says so. */
	public const STALE_AFTER_DAYS = 3;

	/**
	 * @return array{feed: string, feed_label: string, fetched_at: string, published_at: string, checked: int, affected: array<int, array<string, mixed>>, error: string}
	 */
	public static function get(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'feed'         => (string) ( $stored['feed'] ?? '' ),
			'feed_label'   => (string) ( $stored['feed_label'] ?? '' ),
			'fetched_at'   => (string) ( $stored['fetched_at'] ?? '' ),
			'published_at' => (string) ( $stored['published_at'] ?? '' ),
			'checked'      => (int) ( $stored['checked'] ?? 0 ),
			'affected'     => isset( $stored['affected'] ) && is_array( $stored['affected'] ) ? array_values( $stored['affected'] ) : array(),
			'error'        => (string) ( $stored['error'] ?? '' ),
			// Whether the error is the feed's or the site's own (an inventory
			// that moved mid-check), which the screen words apart (#2136).
			'error_kind'   => 'inventory' === ( $stored['error_kind'] ?? '' ) ? 'inventory' : 'feed',
			'revision'     => (int) ( $stored['revision'] ?? 0 ),
			'attribution'  => (array) ( $stored['attribution'] ?? array() ),
		);
	}

	/**
	 * @param array<int, array<string, mixed>> $affected
	 */
	public static function record( Feed $feed, string $published_at, int $checked, array $affected, array $metadata = array() ): void {
		update_option(
			self::OPTION,
			array(
				'feed'         => $feed->id(),
				'feed_label'   => $feed->label(),
				'fetched_at'   => gmdate( 'c' ),
				'published_at' => $published_at,
				'checked'      => $checked,
				'affected'     => $affected,
				'error'        => '',
				'revision'     => (int) ( $metadata['revision'] ?? 0 ),
				'attribution'  => (array) ( $metadata['attribution'] ?? array() ),
			),
			false
		);
	}

	/**
	 * A failed check keeps the last good data and its age; only the error
	 * is new. Old data is never dropped for a failure — it is aged instead.
	 */
	public static function record_failure( Feed $feed, string $error, string $kind = 'feed' ): void {
		$state          = self::get();
		if ( '' === $state['fetched_at'] ) {
			$state['feed'] = $feed->id();
			$state['feed_label'] = $feed->label();
		}
		$state['error']      = $error;
		$state['error_kind'] = 'inventory' === $kind ? 'inventory' : 'feed';

		update_option( self::OPTION, $state, false );
	}

	/**
	 * What the stored advisories name among what is installed now.
	 *
	 * The record holds the versions installed when the check last ran, once
	 * a day. Updated to the fix since, or deleted, an item went on being
	 * reported at full severity with its old version until the next check
	 * (#1810). The stored advisories are matched again here against the
	 * inventory as it stands, by the same rule the check matched them by.
	 *
	 * @return array<int, array<string, mixed>> Affected items, as Matcher::match() returns them.
	 */
	public static function affected_now(): array {
		$stored = self::get()['affected'];

		if ( array() === $stored ) {
			return array();
		}

		$advisories = array();

		foreach ( $stored as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}

			// An item stored before its advisories were kept is its own one.
			$listed = isset( $item['advisories'] ) && is_array( $item['advisories'] ) && array() !== $item['advisories'] ? $item['advisories'] : array( $item );

			foreach ( $listed as $advisory ) {
				if ( ! is_array( $advisory ) ) {
					continue;
				}

				// Stored as "info" for ranking, an advisory the provider gave
				// no severity goes back to having none, or matching it again
				// would read it as a known "info" one.
				if ( false === ( $advisory['severity_known'] ?? true ) ) {
					$advisory['severity'] = null;
				}

				$advisories[] = array(
					'type' => (string) ( $item['type'] ?? 'plugin' ),
					'slug' => (string) ( $item['slug'] ?? '' ),
				) + $advisory;
			}
		}

		return Matcher::match( Inventory::collect(), $advisories );
	}

	public static function forget(): void {
		delete_option( self::OPTION );
	}

	/** Whether a check has ever completed. */
	public static function has_data(): bool {
		return '' !== self::get()['fetched_at'];
	}

	/**
	 * How old the data is, in whole days, or null when there is none.
	 */
	public static function age_days(): ?int {
		$state = self::get();
		$when  = '' !== $state['published_at'] ? $state['published_at'] : $state['fetched_at'];

		if ( '' === $when ) {
			return null;
		}

		$then = strtotime( $when );

		return false === $then ? null : max( 0, (int) floor( ( time() - $then ) / DAY_IN_SECONDS ) );
	}

	public static function is_stale(): bool {
		$age = self::age_days();

		return null === $age || $age >= self::STALE_AFTER_DAYS;
	}

	/* ---- Source: what the ability reads ------------------------------------ */

	public function available(): bool {
		return self::has_data();
	}

	public function last_updated(): ?string {
		$state = self::get();
		$when  = '' !== $state['published_at'] ? $state['published_at'] : $state['fetched_at'];

		return '' !== $when ? $when : null;
	}

	public function state( string $severity_min, int $limit ): array {
		$floor = array_search( Matcher::normalize_severity( $severity_min ), Matcher::SEVERITIES, true );
		$rows  = array();

		foreach ( self::affected_now() as $item ) {
			if ( false !== ( $item['severity_known'] ?? true ) && array_search( $item['severity'], Matcher::SEVERITIES, true ) > $floor ) {
				continue;
			}

			$cves = array();
			foreach ( $item['advisories'] as $advisory ) {
				$cves = array_merge( $cves, $advisory['cve_ids'] );
			}

			$row = array(
				'slug'              => (string) $item['slug'],
				'name'              => (string) $item['name'],
				'installed_version' => (string) $item['installed_version'],
				'compared_versions' => $item['compared_versions'] ?? array( $item['installed_version'] ),
				// Only a match known to affect what's installed. One that
				// can't be compared is listed with its status, not as a hole.
				'vulnerable'        => 'affected' === (string) ( $item['match_status'] ?? 'affected' ),
				'match_status'      => (string) ( $item['match_status'] ?? 'affected' ),
				'type'              => (string) $item['type'],
				'advisories'        => array_map( static function ( array $a ): array { if ( false === ( $a['severity_known'] ?? true ) ) { $a['severity'] = null; } return $a; }, $item['advisories'] ),
				'advisory_ids'      => array_values( array_map( static fn( array $a ): string => (string) $a['id'], $item['advisories'] ) ),
				'exploited'         => in_array( true, array_column( $item['advisories'], 'exploited' ), true ) ? true : ( in_array( null, array_map( static fn( array $a ) => $a['exploited'] ?? null, $item['advisories'] ), true ) ? null : false ),
				'severity'          => false === ( $item['severity_known'] ?? true ) ? null : (string) $item['severity'],
				'severity_known'    => $item['severity_known'] ?? true,
				'cve_ids'           => array_values( array_unique( $cves ) ),
				'patch_available'   => (bool) $item['patch_available'],
				'disclosed_at'      => (string) ( $item['advisories'][0]['disclosed_at'] ?? '' ),
			);

			if ( null !== $item['fixed_in'] ) {
				$row['fixed_in'] = (string) $item['fixed_in'];
			}

			$rows[] = $row;

			if ( count( $rows ) >= $limit ) {
				break;
			}
		}

		return $rows;
	}
}
