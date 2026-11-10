<?php
/** Observe supported predicates without enforcing; bounded, opt-in rollback after real denials. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Hardening;
use BetterShield\Support\Claim;
use BetterShield\Capabilities;
if ( ! defined( 'ABSPATH' ) ) { exit; }
final class Monitor {
	public const OPTION = 'bettershield_hardening_monitors';
	public const TASK = 'bettershield_hardening_monitor_review';
	public const SUPPORTED = array( 'xmlrpc', 'application_passwords', 'admin_gate', 'admin_area_access', 'login_url', 'takeover_settings' );
	private static array $pending = array();
	private static function state(): array { $s = get_option( self::OPTION, array() ); return is_array( $s ) ? $s : array(); }
	private static function save( array $state ): bool { return update_option( self::OPTION, $state, true ) || self::state() === $state; }
	private static function error( string $message = '' ): \WP_Error { return new \WP_Error( 'bettershield_monitor_refused', '' !== $message ? $message : __( 'This could not run. Reload and check the current state.', 'bettershield' ), array( 'status' => 409 ) ); }
	private static function key( array $s, string $kind ): string { return 'hardening_monitor_' . $s['id'] . '_' . $kind; }
	private static function count( array $s, string $kind ): ?int { $n = Claim::count_or_fail( self::key( $s, $kind ) ); return null === $n || $n < 1 || time() >= $s['retained_until'] ? null : $n - 1; }
	public static function describe( string $item ): array {
		$s = self::state()[ $item ] ?? array(); $supported = in_array( $item, self::SUPPORTED, true );
		$out = array( 'supported' => $supported, 'auto_revert_supported' => 'admin_area_access' === $item, 'state' => null );
		if ( $s ) {
			$phase = 'watching' === $s['phase'] && time() >= $s['ends'] ? 'finished' : $s['phase'];
			// Enforced by this window and since undone, or put on again some
			// other way: the stored phase still said "Enforced" beside a row
			// reading Off, because only the review tick moves it.
			if ( in_array( $phase, array( 'enforced', 'review_ended' ), true ) && ( Manager::instance()->item_state( $item )['token'] ?? '' ) !== ( $s['token'] ?? '' ) ) { $phase = 'undone'; }
			$out['state'] = array( 'id' => $s['id'], 'phase' => $phase, 'started' => gmdate( 'c', $s['started'] ), 'ends' => gmdate( 'c', $s['ends'] ), 'options' => $s['options'], 'observed' => self::count( $s, 'seen' ), 'matched' => self::count( $s, 'matched' ), 'denied' => self::count( $s, 'denied' ), 'threshold' => $s['threshold'] ?? 0, 'review_until' => isset( $s['review_until'] ) ? gmdate( 'c', $s['review_until'] ) : null, 'review_blocked' => ! empty( $s['review_blocked'] ), 'storage_failed' => ! empty( $s['storage_failed'] ) );
		}
		return $out;
	}
	public static function change( string $item, string $action, array $options = array(), int $seconds = DAY_IN_SECONDS, int $threshold = 0, string $id = '', bool $override_preflight = false ): array|\WP_Error {
		if ( ! current_user_can( Capabilities::MANAGE ) || ! in_array( $item, self::SUPPORTED, true ) || ! in_array( $action, array( 'start', 'stop', 'enforce' ), true ) || ! Claim::claim( self::OPTION, 30 ) ) { return self::error(); }
		try {
			$all = self::state(); $s = $all[ $item ] ?? array(); $manager = Manager::instance();
			if ( 'start' === $action ) {
				if ( $manager->is_active( $item ) || ! in_array( $seconds, array( HOUR_IN_SECONDS, DAY_IN_SECONDS, WEEK_IN_SECONDS ), true ) ) { return self::error(); }
				$handler = Items::handlers()[ $item ] ?? null;
				$options = $handler && method_exists( $handler, 'validate' ) ? $handler::validate( $options ) : array(); if ( is_wp_error( $options ) ) { $options->add_data( array( 'status' => 400 ) ); return $options; }
				$preview = $manager->dry_run( $item, $options ); if ( is_wp_error( $preview ) || ! $preview['available'] || $preview['refusal'] ) { return self::error(); }
				// A fresh window replaces whatever the last one ended as, an
				// automatic rollback nobody has read yet included. That is why the
				// rollback's durable record is the activity log entry and the cause
				// it carries, which nothing here can overwrite.
				$s = array( 'id' => wp_generate_uuid4(), 'phase' => 'watching', 'options' => $options, 'started' => time(), 'ends' => time() + $seconds, 'retained_until' => time() + $seconds + WEEK_IN_SECONDS );
				foreach ( array( 'seen', 'matched', 'denied' ) as $kind ) { if ( 1 !== Claim::bump_or_fail( self::key( $s, $kind ), $seconds + WEEK_IN_SECONDS ) ) { return self::error(); } }
			} else {
				if ( ! $s || ! hash_equals( $s['id'], $id ) || 'watching' !== $s['phase'] || $manager->is_active( $item ) ) { return self::error(); }
				if ( 'stop' === $action ) { $s['ends'] = min( time(), $s['ends'] ); }
				$failure = null;
				if ( 'enforce' === $action ) {
					// Enforcing a sign-in item is the change its switch makes, so it
					// waits for the same proved way back in, takes the same second
					// confirmation, and is recorded the same way. Asked first: the
					// readiness leg below answers a missing way back in only with the
					// monitor's own refusal.
					$failure = \BetterShield\Rest\Permissions::changes_signing_in( $item ) ? \BetterShield\Recovery\Preflight::failure() : null;
					if ( null !== $failure && ! $override_preflight ) { return \BetterShield\Recovery\Preflight::refusal( $failure ); }
					// The two legs of the readiness check a person can act on, each
					// in words: the combined refusal below says only to reload, and
					// reloading changes neither. XML-RPC has no pre-flight, and the
					// pre-flight does not look at safe mode.
					if ( \BetterShield\Recovery\SafeMode::is_active() ) { return self::error( __( 'Safe mode is on. End it before enforcing.', 'bettershield' ) ); }
					if ( ! \BetterShield\Recovery\RecoveryLink::usable() && ! \BetterShield\Recovery\OfflineCodes::exist() ) { return self::error( __( 'There is no working way back in yet. Set up the recovery link or recovery codes under Protection › Recovery first.', 'bettershield' ) ); }
					if ( time() < $s['ends'] || ! \BetterShield\Incidents\Response::ready() || ! empty( $s['storage_failed'] ) || null === self::count( $s, 'seen' ) || null === self::count( $s, 'matched' ) || ! in_array( $threshold, array( 0, 1, 5, 10 ), true ) || ( $threshold && 'admin_area_access' !== $item ) ) { return self::error(); }
					// Intent first: interruption never claims an armed rollback or retries an apply.
					$s['phase'] = 'applying'; $all[ $item ] = $s; if ( ! self::save( $all ) ) { return self::error(); }
					$result = $manager->apply( $item, $s['options'] );
					if ( is_wp_error( $result ) ) { $s['phase'] = 'watching'; $all[ $item ] = $s; self::save( $all ); return $result; }
					$current = $manager->item_state( $item );
					if ( empty( $current['active'] ) || ( $current['token'] ?? '' ) !== $result['undo_token'] ) { return self::error(); }
					$s['phase'] = 'enforced'; $s['token'] = $result['undo_token']; $s['owner'] = get_current_user_id(); $s['threshold'] = $threshold; $s['review_until'] = time() + DAY_IN_SECONDS;
					if ( null !== $failure ) { \BetterShield\Recovery\Preflight::overridden( $failure, $item, 'dashboard' ); }
				}
			}
			$all[ $item ] = $s; if ( ! self::save( $all ) ) { return self::error(); }
			\BetterShield\Events\Writer::instance()->record( 'setting_changed', \BetterShield\Events\Writer::SEVERITY_INFO, array( 'object_type' => 'hardening', 'object_id' => $item, 'context' => array( 'monitor' => $action ) ) );
			return self::describe( $item );
		} finally { Claim::release( self::OPTION ); }
	}
	public static function register(): void {
		if ( ! self::state() ) { return; }
		add_action( 'init', array( self::class, 'observe_init' ), -1 );
		add_action( 'admin_init', array( self::class, 'observe_admin' ), 0 );
		add_action( 'application_password_did_authenticate', array( self::class, 'observe_password' ), 10, 1 );
		add_filter( 'pre_update_option', array( self::class, 'observe_option' ), PHP_INT_MAX - 1, 3 );
		add_action( 'shutdown', array( self::class, 'flush' ), 1 );
	}
	private static function watching( string $item ): ?array {
		$s = self::state()[ $item ] ?? array();
		return $s && 'watching' === $s['phase'] && time() < $s['ends'] && ! Manager::instance()->is_active( $item ) ? $s : null;
	}
	public static function observe_init(): void {
		global $pagenow;
		$x = self::watching( 'xmlrpc' );
		// Pingbacks only would refuse a request only if it calls a pingback method.
		// All except Jetpack would refuse every request that is not Jetpack's.
		if ( $x && defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) { self::queue( 'xmlrpc', Item\XmlRpc::jetpack_only( $x['options'] ) ? ! Item\XmlRpc::from_jetpack() : ( ! Item\XmlRpc::pingbacks_only( $x['options'] ) || Item\XmlRpc::calls_pingback( (string) ( $GLOBALS['HTTP_RAW_POST_DATA'] ?? '' ) ) ) ); }
		if ( self::watching( 'admin_gate' ) && is_admin() ) { self::queue( 'admin_gate', Item\AdminGate::should_refuse() ); }
		if ( self::watching( 'login_url' ) && 'wp-login.php' === $pagenow ) { self::queue( 'login_url', Item\LoginUrl::would_refuse_direct_login() ); }
	}
	public static function observe_admin(): void { $s = self::watching( 'admin_area_access' ); if ( $s ) { self::queue( 'admin_area_access', Item\AdminAreaAccess::would_gate( $s['options'] ) ); } }
	/**
	 * A write to one of the takeover settings, counted as one the guard would
	 * refuse or let through. The value is handed back unchanged.
	 *
	 * @param mixed $value
	 * @param mixed $option
	 * @param mixed $old
	 * @return mixed
	 */
	public static function observe_option( $value, $option = '', $old = null ) {
		// MySQL matches option names without regard to case.
		if ( in_array( strtolower( trim( (string) $option ) ), \BetterShield\Events\Listeners::TAKEOVER_SETTINGS, true ) && self::watching( 'takeover_settings' ) ) {
			self::queue( 'takeover_settings', Item\TakeoverSettings::would_refuse( (string) $option, $value, $old ) );
		}

		return $value;
	}
	public static function observe_password( \WP_User $user ): void { $s = self::watching( 'application_passwords' ); if ( $s ) { self::queue( 'application_passwords', ( $s['options']['mode'] ?? '' ) === 'everyone' || Item\ApplicationPasswords::is_privileged( $user ) ); } }
	/**
	 * Every count here can lead to an automatic undo, so the checkout test takes its documented default: a request whose
	 * tags throw is treated as the checkout and left alone, where Writer and Observed, deciding only what to keep, answer false.
	 */
	public static function queue( string $item, bool $matched, bool $denied = false ): void {
		if ( \BetterShield\Recovery\SafeMode::is_active() || \BetterShield\Support\Checkout::is_store_path() ) { return; }
		$s = self::state()[ $item ] ?? array();
		if ( ! $s || ( $denied ? 'enforced' !== $s['phase'] || ! is_user_logged_in() || time() > $s['review_until'] || ( Manager::instance()->item_state( $item )['token'] ?? '' ) !== $s['token'] : ! self::watching( $item ) ) ) { return; }
		$site = get_current_blog_id(); $old = self::$pending[ $site ][ $item ] ?? array();
		self::$pending[ $site ][ $item ] = array( 'id' => $s['id'], 'matched' => $matched || ! empty( $old['matched'] ), 'denied' => $denied || ! empty( $old['denied'] ) );
	}
	/** One bounded counter update per category/request, after the response. No identity or request contents. */
	public static function flush(): void {
		$pending = self::$pending; self::$pending = array();
		if ( \BetterShield\Support\Checkout::is_store_path() || \BetterShield\Recovery\SafeMode::is_active() ) { return; }
		foreach ( $pending as $site => $items ) {
			$switched = $site !== get_current_blog_id(); if ( $switched ) { switch_to_blog( $site ); }
			try {
				foreach ( $items as $item => $hit ) {
					$s = self::state()[ $item ] ?? array(); if ( ! $s || $s['id'] !== $hit['id'] || time() >= $s['retained_until'] ) { continue; }
					$kinds = $hit['denied'] ? array( 'denied' ) : ( $hit['matched'] ? array( 'seen', 'matched' ) : array( 'seen' ) );
					foreach ( $kinds as $kind ) {
						$count = self::count( $s, $kind );
						$bumped = null === $count ? null : Claim::bump_or_fail( self::key( $s, $kind ), $s['retained_until'] - time() );
						if ( ( null === $bumped || $bumped < 2 ) && Claim::claim( self::OPTION, 30 ) ) {
							try { $all = self::state(); if ( ( $all[ $item ]['id'] ?? '' ) === $s['id'] ) { $all[ $item ]['storage_failed'] = true; self::save( $all ); } } finally { Claim::release( self::OPTION ); }
						}
					}
				}
			} finally { if ( $switched ) { restore_current_blog(); } }
		}
	}
	public static function tick(): void {
		if ( ! wp_doing_cron() || \BetterShield\Support\Checkout::is_store_path() || ! Claim::claim( self::OPTION, 30 ) ) { return; }
		$previous = get_current_user_id();
		try {
			$all = self::state();
			foreach ( $all as $item => &$s ) {
				if ( 'enforced' !== $s['phase'] || empty( $s['threshold'] ) ) { continue; }
				if ( time() > $s['review_until'] ) { $s['phase'] = 'review_ended'; continue; }
				if ( ( Manager::instance()->item_state( $item )['token'] ?? '' ) !== $s['token'] ) { $s['phase'] = 'review_changed'; continue; }
				if ( is_multisite() && ! is_user_member_of_blog( $s['owner'] ) ) { $s['review_blocked'] = true; continue; }
				wp_set_current_user( $s['owner'] ); if ( ! \BetterShield\Incidents\Response::ready() ) { $s['review_blocked'] = true; continue; }
				$s['review_blocked'] = false;
				$count = self::count( $s, 'denied' ); if ( null === $count || $count < $s['threshold'] ) { continue; }
				$result = Manager::instance()->revert_if_token( $item, $s['token'], Manager::CAUSE_MONITOR_AUTO_UNDO );
				$s['phase'] = is_wp_error( $result ) ? 'review_failed' : 'reverted';
			}
			unset( $s ); self::save( $all );
		} finally { wp_set_current_user( $previous ); Claim::release( self::OPTION ); }
	}
}
