<?php
/** Reversible site-local access suspension; account data and credentials stay intact. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Remediation;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class Suspension {
	public const OPTION = 'bettershield_account_suspensions';
	private static bool $resetting = false;
	private static function state(): array { $s = get_option( self::OPTION, array() ); return is_array( $s ) ? $s : array(); }
	public static function ids(): array { return array_map( 'intval', array_keys( self::state() ) ); }
	public static function token( int $id ): string { return (string) ( self::state()[ $id ] ?? '' ); }
	public static function has( int $id ): bool { return '' !== self::token( $id ); }
	public static function blocks( int $id ): bool {
		if ( $id < 1 || ! self::has( $id ) || \BetterShield\Recovery\SafeMode::is_active() || ( is_multisite() && ( is_super_admin( $id ) || ! is_user_member_of_blog( $id ) ) ) ) { return false; }
		$user = get_userdata( $id ); if ( ! $user ) { return false; }
		// A later role/member change must not leave the last administrator unable to recover.
		if ( ! empty( $user->allcaps['manage_options'] ) && ! get_users( array( 'capability' => 'manage_options', 'exclude' => array_unique( array_merge( array( $id ), self::ids() ) ), 'number' => 1, 'fields' => 'ID', 'cache_results' => false ) ) ) { return false; }
		return true;
	}
	public static function change( int $id, string $token, string $expected ): bool {
		if ( Accounts::refusal( $id ) || self::token( $id ) !== $expected || ( $token && count( self::state() ) >= 100 ) ) { return false; }
		$s = self::state(); if ( $token ) { $s[ $id ] = $token; } else { unset( $s[ $id ] ); }
		return ( update_option( self::OPTION, $s, true ) || self::state() === $s ) && self::token( $id ) === $token;
	}
	public static function error(): \WP_Error { return new \WP_Error( 'bettershield_account_unavailable', __( 'This account cannot sign in right now. Contact a site administrator.', 'bettershield' ), array( 'status' => 403 ) ); }
	public static function authenticate( $user ) { return $user instanceof \WP_User && self::blocks( (int) $user->ID ) ? self::error() : $user; }
	public static function current_user( $id ) { return self::blocks( (int) $id ) ? 0 : $id; }
	public static function cookies( bool $send, int $expires = 0, int $expiration = 0, int $id = 0 ): bool { return $send && ! self::blocks( $id ); }
	public static function capabilities( array $all, array $caps, array $args, \WP_User $user ): array { return self::blocks( (int) $user->ID ) ? array() : $all; }
	public static function settled(): void {
		if ( self::$resetting || ! self::blocks( get_current_user_id() ) ) { return; }
		self::$resetting = true; try { wp_set_current_user( 0 ); } finally { self::$resetting = false; }
	}
	public static function application_password( \WP_Error $error, \WP_User $user ): void { if ( self::blocks( (int) $user->ID ) ) { $refused = self::error(); $error->add( $refused->get_error_code(), $refused->get_error_message(), $refused->get_error_data() ); } }
	public static function register(): void {
		add_action( 'wp_authenticate_application_password_errors', array( self::class, 'application_password' ), PHP_INT_MAX, 2 );
		add_filter( 'authenticate', array( self::class, 'authenticate' ), PHP_INT_MAX, 1 );
		add_filter( 'wp_authenticate_user', array( self::class, 'authenticate' ), PHP_INT_MAX, 1 );
		add_filter( 'determine_current_user', array( self::class, 'current_user' ), PHP_INT_MAX, 1 );
		add_filter( 'send_auth_cookies', array( self::class, 'cookies' ), PHP_INT_MAX, 4 );
		add_filter( 'user_has_cap', array( self::class, 'capabilities' ), PHP_INT_MAX, 4 );
		add_action( 'init', array( self::class, 'settled' ), 1 );
		add_action( 'set_current_user', array( self::class, 'settled' ), PHP_INT_MAX );
	}
}
