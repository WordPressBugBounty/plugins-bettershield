<?php
/**
 * Hardening item: only administrators can change the takeover settings.
 *
 * The site's address, where the administrator's mail goes, whether strangers
 * may register and as what: the settings a takeover changes first. The bug
 * that hands them out is a plugin's AJAX or REST handler calling
 * update_option() with no capability check, so one request from nobody opens
 * registration with administrator as the default role.
 *
 * This guards the write itself. A change to one of them goes through only
 * for an account that may manage the site's options (the network's, for a
 * network option), from WP-CLI, during an install, on core's RELOCATE path,
 * or from BetterShield's own way back. Anything else keeps the value it had
 * and is recorded at critical, with the plugin or theme the call came from.
 *
 * It reads no request and runs only when one of these options is written.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Listeners;
use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TakeoverSettings {

	public const ITEM = 'takeover_settings';

	/** How deep BetterShield's own writes to these are nested on this request. */
	private static int $trusted = 0;

	/** Options already refused on this request, recorded once each. */
	private static array $refused = array();

	/** What a guarded option held before a refused delete, by name. */
	private static array $deleted = array();

	/**
	 * A write BetterShield makes to one of these on purpose, with nobody
	 * signed in perhaps: the HTTPS switch going back on its own.
	 *
	 * @param callable $work
	 * @return mixed What the work returns.
	 */
	public static function as_bettershield( callable $work ) {
		++self::$trusted;

		try {
			return $work();
		} finally {
			--self::$trusted;
		}
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		// Last, so a plugin filtering the value is answered after it.
		add_filter( 'pre_update_option', array( self::class, 'guard' ), PHP_INT_MAX, 3 );

		// Deleting one and adding it back never passes pre_update_option.
		add_action( 'delete_option', array( self::class, 'before_delete' ), PHP_INT_MAX, 1 );
		add_action( 'deleted_option', array( self::class, 'after_delete' ), PHP_INT_MAX, 1 );
		add_action( 'added_option', array( self::class, 'after_add' ), PHP_INT_MAX, 2 );

		if ( is_multisite() ) {
			foreach ( Listeners::watched_network_options() as $option ) {
				add_filter( 'pre_update_site_option_' . $option, array( self::class, 'guard_network' ), PHP_INT_MAX, 3 );
			}
		}
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'pre_update_option', array( self::class, 'guard' ), PHP_INT_MAX );
		remove_action( 'delete_option', array( self::class, 'before_delete' ), PHP_INT_MAX );
		remove_action( 'deleted_option', array( self::class, 'after_delete' ), PHP_INT_MAX );
		remove_action( 'added_option', array( self::class, 'after_add' ), PHP_INT_MAX );

		foreach ( Listeners::watched_network_options() as $option ) {
			remove_filter( 'pre_update_site_option_' . $option, array( self::class, 'guard_network' ), PHP_INT_MAX );
		}
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_filter( 'pre_update_option', array( self::class, 'guard' ) );
	}

	/**
	 * A site option written: kept as it was when nobody allowed to change it
	 * is changing it.
	 *
	 * @param mixed $value     What is being written.
	 * @param mixed $option    The option.
	 * @param mixed $old_value What it holds now.
	 * @return mixed
	 */
	public static function guard( $value, $option = '', $old_value = null ) {
		if ( ! self::would_refuse( (string) $option, $value, $old_value, 'manage_options' ) ) {
			return $value;
		}

		self::refuse( self::name( (string) $option ), false );

		return $old_value;
	}

	/**
	 * A guarded option about to be deleted by somebody not allowed to
	 * change it: what it holds is kept, to be put back once it is gone.
	 *
	 * @param mixed $option
	 */
	public static function before_delete( $option ): void {
		$name = self::name( (string) $option );
		$old  = get_option( $name );

		if ( false !== $old && self::would_refuse( $name, null, $old ) ) {
			self::$deleted[ $name ] = $old;
		}
	}

	/**
	 * @param mixed $option
	 */
	public static function after_delete( $option ): void {
		$name = self::name( (string) $option );

		if ( ! array_key_exists( $name, self::$deleted ) ) {
			return;
		}

		$old = self::$deleted[ $name ];
		unset( self::$deleted[ $name ] );

		self::as_bettershield(
			static function () use ( $name, $old ): void {
				add_option( $name, $old );
			}
		);

		self::refuse( $name, false );
	}

	/**
	 * A guarded option added by somebody not allowed to change it, where it
	 * was not there: taken away again.
	 *
	 * @param mixed $option
	 * @param mixed $value
	 */
	public static function after_add( $option, $value = null ): void {
		$name = self::name( (string) $option );

		if ( ! self::would_refuse( $name, $value, null ) ) {
			return;
		}

		self::as_bettershield(
			static function () use ( $option ): void {
				delete_option( (string) $option );
			}
		);

		self::refuse( $name, false );
	}

	/**
	 * An option's name as the database matches it: MySQL compares option
	 * names without regard to case, so `DEFAULT_ROLE` writes default_role.
	 */
	private static function name( string $option ): string {
		return strtolower( trim( $option ) );
	}

	/**
	 * The same for the network's own takeover options.
	 *
	 * @param mixed $value
	 * @param mixed $old_value
	 * @param mixed $option
	 * @return mixed
	 */
	public static function guard_network( $value, $old_value = null, $option = '' ) {
		if ( ! in_array( (string) $option, Listeners::watched_network_options(), true ) || self::same( $value, $old_value ) || self::allowed( 'manage_network_options' ) ) {
			return $value;
		}

		self::refuse( (string) $option, true );

		return $old_value;
	}

	/**
	 * Whether a write to a site option would be refused, without refusing
	 * it: what Monitor first counts.
	 *
	 * @param mixed $value
	 * @param mixed $old_value
	 */
	public static function would_refuse( string $option, $value, $old_value, string $capability = 'manage_options' ): bool {
		return in_array( self::name( $option ), Listeners::TAKEOVER_SETTINGS, true ) && ! self::same( $value, $old_value ) && ! self::allowed( $capability );
	}

	private static function allowed( string $capability ): bool {
		global $pagenow;

		if ( self::$trusted > 0 || wp_installing() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return true;
		}

		// Core's own way to move a site: wp-login.php writes the address it
		// was reached at when wp-config.php asks it to.
		if ( defined( 'RELOCATE' ) && RELOCATE && 'wp-login.php' === $pagenow ) {
			return true;
		}

		return current_user_can( $capability );
	}

	/**
	 * @param mixed $value
	 * @param mixed $old_value
	 */
	private static function same( $value, $old_value ): bool {
		return is_scalar( $value ) && is_scalar( $old_value ) ? (string) $value === (string) $old_value : $value === $old_value;
	}

	private static function refuse( string $option, bool $network ): void {
		$key = ( $network ? 'network:' : '' ) . $option;

		if ( isset( self::$refused[ $key ] ) ) {
			return;
		}

		self::$refused[ $key ] = true;
		$source                = self::source();

		Writer::instance()->record(
			'takeover_setting_refused',
			Writer::SEVERITY_CRITICAL,
			array(
				'object_type' => 'option',
				'object_id'   => $option,
				'context'     => array(
					'option'  => $option,
					'network' => $network,
					'source'  => $source,
					'name'    => '' === $source ? '' : \BetterShield\Abilities\AgentSurface::source_label( $source ),
				),
			)
		);
	}

	/**
	 * The plugin, theme or must-use code the write came from: the first
	 * frame outside WordPress and this plugin. Taken only on a refusal.
	 */
	private static function source(): string {
		$own = basename( BETTERSHIELD_PATH );

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace -- read once, on a refusal, to name the code that wrote.
		foreach ( debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS ) as $frame ) {
			if ( empty( $frame['file'] ) ) {
				continue;
			}

			$file  = wp_normalize_path( (string) $frame['file'] );
			$theme = trailingslashit( wp_normalize_path( get_theme_root() ) );

			if ( str_starts_with( $file, $theme ) ) {
				return 'theme:' . strtok( substr( $file, strlen( $theme ) ), '/' );
			}

			$source = \BetterShield\Abilities\AgentSurface::source_path( $file );

			if ( ! in_array( $source, array( 'wordpress', 'unknown', $own ), true ) ) {
				return $source;
			}
		}

		return '';
	}

	/** Forget what this request refused and kept. For tests. */
	public static function reset_request_state(): void {
		self::$refused = array();
		self::$deleted = array();
	}
}
