<?php
/**
 * Backup plugin presence, not proof that a backup ran or can be restored.
 * Host backups are outside this inventory and are always reported as unknown.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Vulnerabilities\Inventory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class BackupVisibility {
	/**
	 * Slugs from the publishers' WordPress.org listings, reviewed 2026-09-08.
	 * This is a deliberately non-exhaustive presence map. Adding a provider
	 * does not certify its configuration, backup age or restore capability.
	 *
	 * @return array<string, string>
	 */
	public static function providers(): array {
		$providers = apply_filters( 'bettershield_backup_plugins', array(
			'updraftplus' => 'UpdraftPlus',
			'backwpup' => 'BackWPup',
			'duplicator' => 'Duplicator',
			// The paid editions install under folders of their own.
			'backwpup-pro' => 'BackWPup Pro',
			'duplicator-pro' => 'Duplicator Pro',
			// Dedicated backup plugins, each checked against its listing.
			'all-in-one-wp-migration' => 'All-in-One WP Migration and Backup',
			'wpvivid-backuprestore' => 'WPvivid Backup',
			'jetpack-backup' => 'Jetpack VaultPress Backup',
			'blogvault-real-time-backup' => 'BlogVault',
			'backup-backup' => 'Backup Migration',
			'boldgrid-backup' => 'Total Upkeep',
			'xcloner-backup-and-restore' => 'XCloner',
		) );
		$valid = array();
		foreach ( is_array( $providers ) ? $providers : array() as $slug => $label ) {
			if ( is_string( $slug ) && preg_match( '/^[a-z0-9_-]+$/', $slug ) && is_string( $label ) && '' !== trim( $label ) ) {
				$valid[ $slug ] = \BetterShield\Support\Text::clip( sanitize_text_field( $label ), 120 );
			}
		}
		return $valid;
	}

	/**
	 * @param array<int, array<string, mixed>>|null $inventory Existing inventory, when the caller already has it.
	 */
	public static function report( ?array $inventory = null ): array {
		$known = self::providers();
		$active = array();
		$inactive = array();
		foreach ( $inventory ?? Inventory::collect() as $item ) {
			$slug = (string) ( $item['slug'] ?? '' );
			if ( 'plugin' !== ( $item['type'] ?? '' ) || ! isset( $known[ $slug ] ) ) {
				continue;
			}
			if ( ! empty( $item['active'] ) ) {
				$active[ $slug ] = $known[ $slug ];
			} else {
				$inactive[ $slug ] = $known[ $slug ];
			}
		}
		ksort( $active );
		ksort( $inactive );
		return array(
			'active_plugins' => array_values( $active ),
			'inactive_plugins' => array_values( array_diff_key( $inactive, $active ) ),
			'host_backups' => HostProtections::provides( 'backups' ) ? 'reported_by_host' : 'unknown',
			'last_backup' => 'unknown',
			'restore_test' => 'not_checked',
		);
	}

	public static function finding(): ?array {
		$report = self::report();
		return array() === $report['active_plugins'] ? $report : null;
	}
}
