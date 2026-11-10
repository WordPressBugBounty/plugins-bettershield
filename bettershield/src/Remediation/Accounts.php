<?php
/** Shared account response guards. No account or credential secrets in the ledger. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Remediation;
use BetterShield\Capabilities;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class Accounts {
	public static function refusal( int $id, bool $global = false ): string {
		if ( ! current_user_can( Capabilities::MANAGE ) || ! current_user_can( 'edit_user', $id ) ) { return __( 'You cannot manage this account.', 'bettershield' ); }
		if ( $id === get_current_user_id() ) { return __( 'The account making the request is never a response target.', 'bettershield' ); }
		if ( ! get_userdata( $id ) || ( is_multisite() && ! is_user_member_of_blog( $id ) ) ) { return __( 'This account is not a member of this site.', 'bettershield' ); }
		if ( is_multisite() && ( is_super_admin( $id ) || ( $global && ! current_user_can( 'manage_network' ) ) ) ) { return __( 'This account or its shared network credentials require separate network review.', 'bettershield' ); }
		if ( user_can( $id, 'manage_options' ) && ! get_users( array( 'capability' => 'manage_options', 'exclude' => array_unique( array_merge( array( $id ), Suspension::ids() ) ), 'number' => 1, 'fields' => 'ID' ) ) ) { return __( 'The last administrator cannot be a response target.', 'bettershield' ); }
		return '';
	}
	public static function caps( int $id ): array {
		global $wpdb; wp_cache_delete( $id, 'user_meta' );
		return (array) get_user_meta( $id, $wpdb->get_blog_prefix() . 'capabilities', true );
	}
	/** Compare the exact individual map, including explicit caps that set_role leaves behind. */
	public static function replace_caps( int $id, array $before, array $after ): bool {
		global $wpdb;
		if ( '' !== self::refusal( $id ) || ! current_user_can( 'promote_user', $id ) || self::caps( $id ) !== $before || ! $before ) { return false; }
		if ( ! update_user_meta( $id, $wpdb->get_blog_prefix() . 'capabilities', $after, $before ) ) { return false; }
		clean_user_cache( $id ); ( new \WP_User( $id ) )->update_user_level_from_caps();
		return self::caps( $id ) === $after;
	}
	public static function fingerprint( int $id, string $kind ): string {
		wp_cache_delete( $id, 'user_meta' );
		$value = 'sessions' === $kind ? get_user_meta( $id, 'session_tokens', true ) : \WP_Application_Passwords::get_user_application_passwords( $id );
		return hash( 'sha256', serialize( $value ) );
	}
}
