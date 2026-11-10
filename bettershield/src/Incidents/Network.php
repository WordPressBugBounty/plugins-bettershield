<?php
/** A bounded network view over each site's own incident records. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Incidents;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class Network {
	public static function page( int $after = 0 ): array {
		global $wpdb;
		// Network identity is fixed by the current network, never a request parameter.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ids = $wpdb->get_col( $wpdb->prepare( 'SELECT blog_id FROM %i WHERE site_id=%d AND blog_id>%d AND deleted=0 AND spam=0 AND archived=0 ORDER BY blog_id ASC LIMIT 11', $wpdb->blogs, get_current_network_id(), max( 0, $after ) ) );
		if ( '' !== $wpdb->last_error ) { return array( 'sites' => array(), 'failed' => true, 'next_cursor' => 0 ); }
		$more = count( $ids ) > 10; $ids = array_slice( $ids, 0, 10 ); $sites = array();
		foreach ( $ids as $id ) {
			switch_to_blog( (int) $id );
			try {
				$ready  = \BetterShield\Database\Schema::ready( 'incidents' );
				$result = $ready ? Repository::page( 'open', 0, 5 ) : Repository::error();
				// Why it could not be read: tables the site's Overview can repair, or a read to try again (#2235).
				$sites[] = array( 'site_id' => (int) $id, 'label' => \BetterShield\Support\Text::clip( (string) get_option( 'blogname' ), 120 ), 'url' => get_admin_url( (int) $id, 'admin.php?page=bettershield-activity&tab=incidents' ), 'unavailable' => is_wp_error( $result ), 'unavailable_reason' => ! is_wp_error( $result ) ? '' : ( $ready ? 'read' : 'storage' ), 'repair_url' => $ready ? '' : get_admin_url( (int) $id, 'admin.php?page=bettershield' ), 'incidents' => is_wp_error( $result ) ? array() : $result['incidents'], 'more_incidents' => ! is_wp_error( $result ) && $result['next_cursor'] > 0, 'engine' => Engine::report() );
			} finally { restore_current_blog(); }
		}
		return array( 'sites' => $sites, 'failed' => false, 'next_cursor' => $more ? (int) end( $ids ) : 0 );
	}
}
