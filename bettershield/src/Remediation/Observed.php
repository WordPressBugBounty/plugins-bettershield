<?php
/** Opt-in captured external changes and explicitly reviewed, reversible responses. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Remediation;
use BetterShield\Capabilities;
use BetterShield\Undo\Ledger;
use BetterShield\Support\Claim;
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- exact option comparisons and durable scoped receipts.
final class Observed {
	public const OPTION = 'bettershield_observed_changes';
	public const KEY = 'observed_change';
	private static bool $changing = false;
	private static int $captured = 0;
	public static function policy(): array { $s = get_option( self::OPTION, array() ); return is_array( $s ) ? $s + array( 'enabled' => false, 'used' => 0 ) : array( 'enabled' => false, 'used' => 0 ); }
	public static function listing( int $cursor = PHP_INT_MAX ): array|\WP_Error {
		if ( ! current_user_can( Capabilities::MANAGE ) ) { return self::error(); }
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id,token,prior_state,applied_state,created_at FROM %i WHERE action_key=%s AND id<%d ORDER BY id DESC LIMIT 21', \BetterShield\Database\Schema::table( 'undo' ), self::KEY, max( 1, $cursor ) ) );
		if ( '' !== $wpdb->last_error ) { return self::error(); }
		$more = count( $rows ) > 20; $rows = array_slice( $rows, 0, 20 );
		$recent = array(); foreach ( $rows as $row ) { $r = json_decode( $row->prior_state, true ); $s = json_decode( $row->applied_state, true ); $recent[] = array( 'token' => $row->token, 'target' => $r['target'], 'kind' => $r['kind'], 'name' => self::name_of( $r ), 'phase' => $s['phase'] ?? 'ready', 'created_at' => \BetterShield\Support\Time::utc_iso( (string) $row->created_at ) ); }
		return self::policy() + array( 'recent' => $recent, 'next_cursor' => $more ? (int) end( $rows )->id : null, 'suspensions' => array_map( static fn( $id ) => array( 'target' => $id, 'name' => self::name_of( array( 'kind' => 'account', 'target' => $id ) ), 'token' => Suspension::token( $id ), 'paused' => ! Suspension::blocks( $id ), 'elsewhere' => self::elsewhere( $id ), 'lift' => self::lift_path( $id ) ), Suspension::ids() ), 'available' => \BetterShield\Database\Schema::ready( 'observed_changes' ), 'fixes' => \BetterShield\Fixes\FixUndos::listing() );
	}
	public static function settings( bool $enabled ): array|\WP_Error {
		if ( ! current_user_can( Capabilities::MANAGE ) || ( $enabled && ! \BetterShield\Database\Schema::ready( 'observed_changes' ) ) || ! Claim::claim( self::OPTION, 30 ) ) { return self::error(); }
		try { $s = self::policy(); $s['enabled'] = $enabled; if ( ! update_option( self::OPTION, $s, true ) && self::policy() !== $s ) { return self::error(); } self::event( 'capture_policy', '' ); return $s; } finally { Claim::release( self::OPTION ); }
	}
	private static function capture( array $record ): string {
		$json = wp_json_encode( $record );
		if ( ! \BetterShield\Database\Schema::ready( 'observed_changes' ) || self::$changing || ! self::policy()['enabled'] || self::$captured >= 20 || \BetterShield\Support\Checkout::is_store_path( false ) || ! is_string( $json ) || strlen( $json ) > 16000 || ! Claim::claim( self::OPTION, 30 ) ) { return ''; }
		try {
			$s = self::policy(); if ( ! $s['enabled'] || $s['used'] >= 1000 ) { return ''; }
			$n = Claim::bump_or_fail( 'observed_capture_hour_' . intdiv( time(), HOUR_IN_SECONDS ), HOUR_IN_SECONDS + 60 ); if ( null === $n || $n > 100 ) { return ''; }
			++$s['used']; if ( ! update_option( self::OPTION, $s, true ) ) { return ''; }
			++self::$captured; return Ledger::open( self::KEY, $record, array() ) ?? '';
		} finally { Claim::release( self::OPTION ); }
	}
	public static function option( string $name, $old, $new ): string {
		if ( ! self::policy()['enabled'] || self::$changing ) { return ''; }
		global $wpdb;
		if ( $name === $wpdb->get_blog_prefix() . 'user_roles' && is_array( $old ) && is_array( $new ) ) {
			$changed = array(); foreach ( array_unique( array_merge( array_keys( $old ), array_keys( $new ) ) ) as $role ) { if ( ( $old[ $role ] ?? null ) !== ( $new[ $role ] ?? null ) ) { $changed[] = $role; } }
			if ( count( $changed ) !== 1 ) { return ''; } $role = $changed[0];
			if ( ! isset( $old[ $role ]['capabilities'], $new[ $role ]['capabilities'] ) || $old[ $role ]['name'] !== $new[ $role ]['name'] ) { return ''; }
			return self::capture( array( 'kind' => 'role', 'target' => $role, 'before' => $old[ $role ]['capabilities'], 'after' => $new[ $role ]['capabilities'], 'name' => $new[ $role ]['name'] ) );
		}
		if ( ! in_array( $name, array( 'users_can_register', 'default_role', 'admin_email', 'siteurl' ), true ) || ! is_scalar( $old ) || ! is_scalar( $new ) || strlen( (string) $old ) > 1000 || strlen( (string) $new ) > 1000 ) { return ''; }
		if ( 'siteurl' === $name && ( preg_match( '~[?#@]~', (string) $old . (string) $new ) || ! in_array( wp_parse_url( (string) $old, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) || ! in_array( wp_parse_url( (string) $new, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) ) ) { return ''; }
		return self::capture( array( 'kind' => 'option', 'target' => $name, 'before' => (string) $old, 'after' => (string) $new ) );
	}
	public static function account( int $id ): string {
		if ( ! self::policy()['enabled'] || ! user_can( $id, 'manage_options' ) ) { return ''; }
		$user = get_userdata( $id );
		return $user ? self::capture( array( 'kind' => 'account', 'target' => $id, 'before' => false, 'after' => true, 'caps' => Accounts::caps( $id ), 'registered' => $user->user_registered ) ) : '';
	}
	public static function plugin( string $file, bool $network = false ): string {
		if ( ! self::policy()['enabled'] || $network || ( is_multisite() && is_plugin_active_for_network( $file ) ) ) { return ''; }
		$hash = self::plugin_hash( $file );
		return $hash ? self::capture( array( 'kind' => 'plugin', 'target' => $file, 'before' => false, 'after' => true, 'hash' => $hash ) ) : '';
	}
	private static function error( string $message = '' ): \WP_Error { return new \WP_Error( 'bettershield_observed_refused', $message ?: __( 'This change cannot be safely restored. Review it manually.', 'bettershield' ), array( 'status' => 409 ) ); }
	/**
	 * What the owner calls a row's subject: a role's name, a plugin's name, an
	 * account's login. Empty where none is known, and the screen falls back to
	 * the slug, the file or the ID (#2379, #2381).
	 */
	private static function name_of( array $r ): string {
		if ( 'role' === $r['kind'] ) { $roles = wp_roles()->roles; return isset( $roles[ $r['target'] ]['name'] ) ? translate_user_role( (string) $roles[ $r['target'] ]['name'] ) : (string) ( $r['name'] ?? '' ); }
		if ( 'plugin' === $r['kind'] ) { $path = WP_PLUGIN_DIR . '/' . $r['target']; if ( ! function_exists( 'get_plugin_data' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; } return is_readable( $path ) ? (string) ( get_plugin_data( $path, false, false )['Name'] ?? '' ) : ''; }
		if ( 'account' === $r['kind'] ) { $user = get_userdata( (int) $r['target'] ); return $user ? (string) $user->user_login : ''; }
		return '';
	}
	/**
	 * Where an account suspended by something other than a response here is
	 * let back in, or '' when a response here suspended it.
	 *
	 * Every suspension shares one list, so the review of one this class never
	 * made would otherwise read as a change that cannot be restored. The
	 * feature that made it can name its own way back through
	 * `bettershield_suspension_lift_hint`, given the account and the undo
	 * entry's action key.
	 */
	private static function elsewhere( int $id ): string {
		$token = Suspension::token( $id ); $row = '' === $token ? null : Ledger::find( $token );
		if ( '' === $token || ( $row && self::KEY === $row->action_key ) ) { return ''; }
		$default = __( 'This account was suspended by another BetterShield feature. Lift it from that screen.', 'bettershield' );
		$hint = apply_filters( 'bettershield_suspension_lift_hint', $default, $id, $row ? (string) $row->action_key : '' );
		$hint = is_string( $hint ) ? trim( wp_strip_all_tags( $hint ) ) : '';
		return '' !== $hint ? $hint : $default;
	}
	/**
	 * The route that lets an account suspended by another feature back in,
	 * where that feature names one, or ''. Only this plugin's own routes.
	 */
	private static function lift_path( int $id ): string {
		$token = Suspension::token( $id ); $row = '' === $token ? null : Ledger::find( $token );
		if ( ! $row || self::KEY === $row->action_key ) { return ''; }
		$path = apply_filters( 'bettershield_suspension_lift_path', '', $id, (string) $row->action_key );
		return is_string( $path ) && str_starts_with( $path, '/bettershield/v1/' ) ? $path : '';
	}
	private static function row( string $token ): ?object { $r = Ledger::find( $token ); return $r && self::KEY === $r->action_key && current_user_can( Capabilities::MANAGE ) ? $r : null; }
	private static function plugin_hash( string $file ): string {
		if ( ! function_exists( 'get_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
		if ( ! isset( get_plugins()[ $file ] ) || 0 !== validate_file( $file ) ) { return ''; }
		$root = realpath( WP_PLUGIN_DIR ); $path = realpath( WP_PLUGIN_DIR . '/' . $file );
		if ( ! $root || ! $path || ! str_starts_with( $path, $root . '/' ) || @filesize( $path ) > 2 * MB_IN_BYTES ) { return ''; }
		foreach ( array_filter( array( realpath( BETTERSHIELD_PATH ), defined( 'BETTERSHIELD_ULTRA_PATH' ) ? realpath( BETTERSHIELD_ULTRA_PATH ) : false ) ) as $protected ) { if ( str_starts_with( $path, $protected . '/' ) ) { return ''; } }
		return (string) @hash_file( 'sha256', $path );
	}
	private static function current( array $r ) {
		if ( 'option' === $r['kind'] ) { return (string) get_option( $r['target'], '' ); }
		if ( 'role' === $r['kind'] ) { global $wpdb; $roles = get_option( $wpdb->get_blog_prefix() . 'user_roles', array() ); return $roles[ $r['target'] ]['capabilities'] ?? null; }
		if ( 'plugin' === $r['kind'] ) { if ( ! function_exists( 'is_plugin_active' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; } return is_plugin_active( $r['target'] ); }
		return Suspension::has( (int) $r['target'] );
	}
	private static function refusal( array $r, bool $undo, string $token ): string {
		$target = $r['target']; $desired = $undo ? $r['after'] : $r['before'];
		if ( ! \BetterShield\Incidents\Response::ready() ) { return __( 'Set up a recovery method and turn off safe mode (Protection › Recovery) to restore changes.', 'bettershield' ); }
		if ( 'option' === $r['kind'] ) {
			if ( ! current_user_can( 'manage_options' ) ) { return __( 'Site settings permission is required.', 'bettershield' ); }
			if ( 'users_can_register' === $target && is_multisite() ) { return __( 'The network controls registration. Review it in the network’s settings.', 'bettershield' ); }
			if ( 'siteurl' === $target ) { return __( 'Changing the WordPress address can sign you out or break your recovery link, so it is not restored automatically.', 'bettershield' ); }
			if ( 'admin_email' === $target && ! is_email( $desired ) ) { return __( 'The recorded email is no longer a valid address.', 'bettershield' ); }
			if ( 'users_can_register' === $target && ! in_array( $desired, array( '0', '1' ), true ) ) { return __( 'The recorded registration value is not supported.', 'bettershield' ); }
			if ( 'default_role' === $target || ( 'users_can_register' === $target && '1' === $desired ) ) {
				global $wpdb; $roles = get_option( $wpdb->get_blog_prefix() . 'user_roles', array() );
				$caps = $roles[ 'default_role' === $target ? $desired : (string) get_option( 'default_role' ) ]['capabilities'] ?? null;
				if ( ! is_array( $caps ) || ! empty( $caps['manage_options'] ) || ! empty( $caps[ Capabilities::MANAGE ] ) || ! empty( $caps['edit_users'] ) ) { return __( 'Public registration cannot be restored with a missing or administrative default role.', 'bettershield' ); }
			}
		} elseif ( 'role' === $r['kind'] ) {
			if ( ! current_user_can( 'promote_users' ) || in_array( $target, wp_get_current_user()->roles, true ) ) { return __( 'A role you hold cannot be restored here, and you also need permission to manage roles.', 'bettershield' ); }
			if ( ! is_array( $desired ) || count( $desired ) > 500 ) { return __( 'This role’s permissions are too complex to restore here. Change them by hand.', 'bettershield' ); }
			foreach ( $desired as $cap => $allow ) { if ( ! is_string( $cap ) || ! preg_match( '/^[a-zA-Z0-9_\-]{1,100}$/D', $cap ) || ! is_bool( $allow ) ) { return __( 'This role’s permissions are too complex to restore here. Change them by hand.', 'bettershield' ); } }
			$role = get_role( $target ); if ( ! $role || $role->name !== $target ) { return __( 'The role no longer exists.', 'bettershield' ); }
			if ( $role->has_cap( 'manage_options' ) && empty( $desired['manage_options'] ) && ! get_users( array( 'capability' => 'manage_options', 'role__not_in' => array( $target ), 'exclude' => Suspension::ids(), 'number' => 1, 'fields' => 'ID' ) ) ) { return __( 'The last available administrator must keep access.', 'bettershield' ); }
		} elseif ( 'plugin' === $r['kind'] ) {
			if ( ! current_user_can( 'activate_plugins' ) || ( is_multisite() && ( ! current_user_can( 'manage_network_plugins' ) || is_plugin_active_for_network( $target ) ) ) || ! hash_equals( $r['hash'], self::plugin_hash( $target ) ) ) { return __( 'Plugin permissions, code or network activation changed. Review it manually.', 'bettershield' ); }
			if ( class_exists( '\WP_Plugin_Dependencies' ) ) { \WP_Plugin_Dependencies::initialize(); if ( ! $desired && \WP_Plugin_Dependencies::has_active_dependents( $target ) ) { return __( 'Another active plugin requires this plugin.', 'bettershield' ); } }
			if ( $desired && is_wp_error( validate_plugin_requirements( $target ) ) ) { return __( 'The plugin’s current requirements are not met.', 'bettershield' ); }
		} else {
			$reason = Accounts::refusal( (int) $target ); if ( $reason ) { return $reason; }
			$user = get_userdata( (int) $target ); if ( ! $user || $user->user_registered !== $r['registered'] || Accounts::caps( (int) $target ) !== $r['caps'] ) { return __( 'The account changed since this observation.', 'bettershield' ); }
			if ( $undo && Suspension::token( (int) $target ) !== $token ) { return __( 'This suspension was changed elsewhere, so it can’t be undone here.', 'bettershield' ); }
		}
		$expected = 'account' === $r['kind'] ? $undo : ( $undo ? $r['before'] : $r['after'] );
		return self::current( $r ) !== $expected ? __( 'This was changed again later, so it won’t be overwritten.', 'bettershield' ) : '';
	}
	public static function view( string $token ): array|\WP_Error {
		$row = self::row( $token );
		if ( ! $row ) {
			// A suspension another feature made is listed here too; say where it is lifted.
			foreach ( current_user_can( Capabilities::MANAGE ) && '' !== $token ? Suspension::ids() : array() as $id ) { if ( Suspension::token( $id ) === $token ) { return self::error( self::elsewhere( $id ) ); } }
			return self::error();
		}
		$r = $row->prior_state; $phase = $row->applied_state['phase'] ?? 'ready'; $undo = 'applied' === $phase;
		$refusal = in_array( $phase, array( 'ready', 'applied' ), true ) ? self::refusal( $r, $undo, $token ) : __( 'This response already finished or was interrupted. Check the target first.', 'bettershield' );
		return array( 'token' => $token, 'kind' => $r['kind'], 'target' => $r['target'], 'before' => $r['before'], 'after' => $r['after'], 'current' => self::current( $r ), 'phase' => $phase, 'refusal' => $refusal, 'network' => self::network(), 'set_in_config' => 'option' === $r['kind'] && 'siteurl' === $r['target'] && defined( 'WP_SITEURL' ), 'revision' => hash( 'sha256', wp_json_encode( array( $token, $row->applied_state, self::current( $r ) ) ) ) );
	}
	/**
	 * Where a network keeps what a site's own Settings screen does not show.
	 *
	 * On a network, Settings, General leaves out the default role and the
	 * registration switch on every site, so guidance pointing there sends the
	 * owner to a screen without the field. What the review needs instead is
	 * whether this viewer can open the network's screen for the site, and the
	 * address the command line names the site by.
	 *
	 * The address is the network's own row for the site, never `site_url()`:
	 * that reads the option a recorded change may have moved, and WP-CLI
	 * picks a site by domain and path, so the changed address named the main
	 * site on a subdirectory network and nothing at all across domains.
	 *
	 * @return array{manages_sites: bool, url: string}|null Null off a network.
	 */
	private static function network(): ?array {
		if ( ! is_multisite() ) { return null; }
		$site = get_site();
		return array( 'manages_sites' => current_user_can( 'manage_sites' ), 'url' => $site ? set_url_scheme( 'http://' . $site->domain . $site->path ) : site_url( '/' ) );
	}
	private static function save( string $token, array $receipt ): bool {
		global $wpdb; $json = wp_json_encode( $receipt ); if ( ! is_string( $json ) || false === $wpdb->update( \BetterShield\Database\Schema::table( 'undo' ), array( 'applied_state' => $json ), array( 'token' => $token, 'action_key' => self::KEY ) ) ) { return false; } $row = self::row( $token ); return $row && $row->applied_state === $receipt;
	}
	public static function act( string $token, string $action, string $revision ): array|\WP_Error {
		if ( ! in_array( $action, array( 'apply', 'undo' ), true ) || ! current_user_can( Capabilities::MANAGE ) || ! Claim::claim( 'observed_response', 30 ) ) { return self::error(); }
		try {
			$view = self::view( $token ); if ( is_wp_error( $view ) || ! hash_equals( $view['revision'], $revision ) || $view['refusal'] || ( 'apply' === $action ? 'ready' !== $view['phase'] : 'applied' !== $view['phase'] ) ) { return self::error( is_array( $view ) ? $view['refusal'] : '' ); }
			$r = self::row( $token )->prior_state; $undo = 'undo' === $action;
			if ( ! self::save( $token, array( 'phase' => 'started', 'action' => $action ) ) ) { return self::error(); }
			self::$changing = true;
			try { $result = self::execute( $r, $undo, $token ); } catch ( \Throwable $e ) { return self::error( __( 'The response was interrupted. Check the current state before trying again.', 'bettershield' ) ); } finally { self::$changing = false; }
			if ( is_wp_error( $result ) || ! $result ) { self::event( 'interrupted', $token ); return self::error( __( 'We couldn’t confirm this worked. Check the setting before trying again.', 'bettershield' ) ); }
			if ( ! self::save( $token, array( 'phase' => $undo ? 'undone' : 'applied', 'at' => gmdate( 'c' ) ) ) ) { return self::error(); }
			self::event( $undo ? 'undone' : 'applied', $token ); return self::view( $token );
		} finally { Claim::release( 'observed_response' ); }
	}
	private static function execute( array $r, bool $undo, string $token ): bool|\WP_Error {
		$target = $r['target']; $value = $undo ? $r['after'] : $r['before'];
		if ( 'account' === $r['kind'] ) { return Suspension::change( (int) $target, $undo ? '' : $token, $undo ? $token : '' ); }
		if ( 'plugin' === $r['kind'] ) {
			if ( $value ) { $result = activate_plugin( $target, '', false, false ); if ( is_wp_error( $result ) ) { return $result; } } else { deactivate_plugins( $target, false, false ); }
			return is_plugin_active( $target ) === $value;
		}
		if ( 'role' === $r['kind'] ) {
			global $wpdb; $name = $wpdb->get_blog_prefix() . 'user_roles'; $old = get_option( $name, array() );
			if ( ( $old[ $target ]['name'] ?? '' ) !== $r['name'] ) { return false; }
			$new = $old; $new[ $target ]['capabilities'] = $value; $result = self::option_cas( $name, $old, $new, static fn() => '' === self::refusal( $r, $undo, $token ) ); if ( $result ) { wp_roles()->for_site( get_current_blog_id() ); } return $result;
		}
		return self::option_cas( $target, $undo ? $r['before'] : $r['after'], $value, static fn() => '' === self::refusal( $r, $undo, $token ) );
	}
	/** Core validation/filter hooks followed by a single conditional write; never overwrites a later option edit. */
	private static function option_cas( string $name, $old, $value, callable $guard ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own option hooks, fired as update_option() fires them.
		$clean = sanitize_option( $name, $value ); $clean = apply_filters( "pre_update_option_{$name}", $clean, $old, $name ); $clean = apply_filters( 'pre_update_option', $clean, $name, $old );
		if ( is_scalar( $value ) ? ! is_scalar( $clean ) || (string) $clean !== (string) $value : $clean !== $value ) { return false; }
		do_action( 'update_option', $name, $old, $value ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- as above.
		if ( ! $guard() ) { return false; }
		$changed = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET option_value=%s WHERE option_name=%s AND option_value=%s', $wpdb->options, maybe_serialize( $value ), $name, maybe_serialize( $old ) ) );
		wp_cache_delete( $name, 'options' ); wp_cache_delete( 'alloptions', 'options' ); wp_cache_delete( 'notoptions', 'options' );
		if ( 1 !== $changed ) { return false; }
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- as above.
		do_action( "update_option_{$name}", $old, $value, $name ); do_action( 'updated_option', $name, $old, $value );
		return is_scalar( $value ) ? (string) get_option( $name ) === (string) $value : get_option( $name ) === $value;
	}
	private static function event( string $action, string $token ): void { \BetterShield\Events\Writer::instance()->record( 'observed_change_response', \BetterShield\Events\Writer::SEVERITY_HIGH, array( 'object_type' => 'change', 'object_id' => $token, 'context' => array( 'action' => $action ) ) ); }
}
