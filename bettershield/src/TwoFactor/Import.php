<?php
/**
 * Two-factor brought over from another plugin as it is switched off.
 *
 * Two Factor, WP 2FA and Wordfence Login Security keep the same kind of
 * factor this plugin does: a TOTP shared secret, SHA-1, thirty-second steps,
 * six digits. When the owner has handed two-factor to BetterShield and one of
 * them is deactivated, each account it has an authenticator app set up for
 * gets that same secret here, so the app keeps working and the account is
 * never left signing in with a password alone.
 *
 * The copy runs on `deactivate_plugin`, before WordPress switches the plugin
 * off, so it covers every way of deactivating it: the setup's own route, the
 * link the setup opens, the Plugins screen and WP-CLI. Before, because WP 2FA
 * keeps its secrets encrypted and only its own code, still loaded then, can
 * read them. The other plugin's records are read and never written, so
 * turning it back on finds everything as it was.
 *
 * What cannot come over is said, never skipped quietly: an account whose
 * factor there is not an authenticator app (an email code, a security key),
 * or whose secret cannot be read, is named to the owner before the switch
 * and told by email after it. Wordfence's unused recovery codes come over
 * with the secret, hashed the moment they are read. Two Factor and WP 2FA
 * keep only hashes of theirs, so those accounts, and any with no code left,
 * are told to make a new set.
 *
 * The whole copy is one undo: the ledger keeps which accounts got a secret
 * and a SHA-256 digest of each, never the secret, and taking it back removes
 * only a secret still equal to the one brought over, and the backup codes
 * that went with it.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Alerts\AccountNotices;
use BetterShield\Events\Writer;
use BetterShield\Password\Policy;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Import {

	/** The undo ledger's key for one plugin's accounts brought over. */
	public const ACTION = 'two_factor_import';

	/** Each plugin read here, by its file, and how its records are read. */
	private const SOURCES = array(
		'two-factor/two-factor.php'                             => 'two_factor',
		'wp-2fa/wp-2fa.php'                                     => 'wp_2fa',
		'wordfence/wordfence.php'                               => 'wordfence',
		'wordfence-login-security/wordfence-login-security.php' => 'wordfence',
	);

	/** At most this many accounts are named on screen; the rest are counted. */
	public const NAMED = 10;

	/**
	 * The sites of a network whose setup handed two-factor to BetterShield,
	 * kept network-wide. Each site writes only its own entry, when its answer
	 * is saved, so switching a plugin off across the network reads one value
	 * instead of every site's.
	 */
	public const NETWORK_OPTION = 'bettershield_two_factor_handed_sites';

	/** The accounts already told their two-factor couldn't move, by plugin. */
	public const NOT_MOVED_OPTION = 'bettershield_two_factor_not_moved_told';

	public static function register(): void {
		add_action( 'deactivate_plugin', array( self::class, 'on_deactivate' ), 5, 2 );
		add_action( 'activated_plugin', array( self::class, 'on_activate' ), 5, 2 );

		$option = \BetterShield\Onboarding\QuickSetup::OPTION;

		add_action( 'add_option_' . $option, static fn( $name, $value ) => self::note_answer( $value ), 10, 2 );
		add_action( 'update_option_' . $option, static fn( $old, $value ) => self::note_answer( $value ), 10, 2 );
		add_action( 'delete_option_' . $option, static fn() => self::note_answer( array() ) );
		add_action( 'wp_uninitialize_site', array( self::class, 'forget_site' ) );
	}

	/**
	 * Keep this site's entry in the network's list in step with its answer.
	 *
	 * @param mixed $state The setup's stored state.
	 */
	public static function note_answer( $state ): void {
		if ( ! is_multisite() ) {
			return;
		}

		$handed = is_array( $state ) && ! empty( $state['coexistence_saved'] ) && 'bettershield' === ( $state['coexistence']['two_factor'] ?? '' );

		self::set_handed( get_current_blog_id(), $handed );
	}

	/**
	 * A site being deleted leaves the list.
	 *
	 * @param mixed $site The site core is removing.
	 */
	public static function forget_site( $site ): void {
		if ( $site instanceof \WP_Site ) {
			self::set_handed( (int) $site->blog_id, false );
		}
	}

	private static function set_handed( int $blog_id, bool $handed ): void {
		$stored = get_network_option( null, self::NETWORK_OPTION, array() );
		$sites  = is_array( $stored ) ? array_map( 'intval', $stored ) : array();
		$next   = $handed ? array_values( array_unique( array_merge( $sites, array( $blog_id ) ) ) ) : array_values( array_diff( $sites, array( $blog_id ) ) );

		if ( $next === $sites ) {
			return;
		}

		if ( array() === $next ) {
			delete_network_option( null, self::NETWORK_OPTION );

			return;
		}

		update_network_option( null, self::NETWORK_OPTION, $next );
	}

	/**
	 * Whether this plugin is one whose two-factor records are read here.
	 */
	public static function reads( string $file ): bool {
		return isset( self::SOURCES[ $file ] );
	}

	/**
	 * Whether the owner has handed two-factor to BetterShield in the setup.
	 * Nobody's factor is moved without that choice.
	 */
	public static function chosen(): bool {
		$state = \BetterShield\Onboarding\QuickSetup::state();

		return $state['coexistence_saved'] && 'bettershield' === ( $state['coexistence']['two_factor'] ?? '' );
	}

	/**
	 * Whether any site on the network handed two-factor to BetterShield. Only
	 * the network can switch a network-active plugin off, and that runs on
	 * the main site, so a subsite's answer would otherwise never be read.
	 * Accounts are shared across the network, so one answer covers them.
	 */
	private static function chosen_on_any_site(): bool {
		$stored = get_network_option( null, self::NETWORK_OPTION, array() );

		return is_array( $stored ) && array() !== $stored;
	}

	/**
	 * Core is about to switch a plugin off.
	 *
	 * @param mixed $file    The plugin's file.
	 * @param mixed $network Whether it is being switched off across the network.
	 */
	public static function on_deactivate( $file, $network = false ): void {
		if ( ! is_string( $file ) || ! ( self::chosen() || ( $network && is_multisite() && self::chosen_on_any_site() ) ) ) {
			return;
		}

		if ( self::reads( $file ) ) {
			self::carry( $file );
		} else {
			self::left_behind( $file );
		}
	}

	/**
	 * A plugin whose secrets can't be brought over, as it is switched off:
	 * each account it had two-factor set up for, and not set up here, is
	 * told as one whose secret could not come over is. Google Authenticator's
	 * accounts were never told they now sign in with a password alone.
	 *
	 * @return int How many accounts were told.
	 */
	public static function left_behind( string $file ): int {
		$active = \BetterShield\Onboarding\Coexistence::active();

		// Only while it really does two-factor here, as the setup counted it.
		if ( ! in_array( 'two_factor', $active[ $file ]['jobs'] ?? array(), true ) ) {
			return 0;
		}

		$ids = \BetterShield\Onboarding\Coexistence::two_factor_left_behind_ids( $file );

		foreach ( $ids as $user_id ) {
			self::record( 'two_factor_not_moved', $user_id, (string) $active[ $file ]['name'] );
		}

		return count( $ids );
	}

	/**
	 * A plugin something was brought over from is on again, from whichever
	 * screen. It asks for its own code, so its accounts go back to it and
	 * aren't asked for two.
	 *
	 * @param mixed $file    The plugin's file.
	 * @param mixed $network Whether it was switched on across the network.
	 */
	public static function on_activate( $file, $network = false ): void {
		if ( ! is_string( $file ) || ! self::reads( $file ) || ! in_array( $file, array_column( self::open_imports(), 'plugin' ), true ) ) {
			return;
		}

		\BetterShield\Onboarding\QuickSetup::keep_two_factor_elsewhere();
		self::take_back( $file );

		if ( ! $network || ! is_multisite() ) {
			return;
		}

		$stored = get_network_option( null, self::NETWORK_OPTION, array() );

		foreach ( is_array( $stored ) ? array_map( 'intval', $stored ) : array() as $site ) {
			switch_to_blog( $site );
			\BetterShield\Onboarding\QuickSetup::keep_two_factor_elsewhere();
			restore_current_blog();
		}
	}

	/**
	 * What deactivating a plugin would bring over, for the setup to say
	 * before it happens: how many accounts keep their app, how many are
	 * already set up here, and who cannot come over.
	 *
	 * @return array{moving: int, already: int, staying: int, named: string[], codes_moving: int}
	 */
	public static function preview( string $file ): array {
		$moving  = 0;
		$already = 0;
		$named   = array();
		$staying = 0;
		$with    = 0;
		$manager = Manager::instance();
		$codes   = self::codes_of( $file );

		foreach ( self::accounts( $file ) as $user_id => $secret ) {
			if ( $manager->enabled( $user_id ) ) {
				++$already;
			} elseif ( '' !== $secret ) {
				++$moving;
				$with += array() === ( $codes[ $user_id ] ?? array() ) ? 0 : 1;
			} else {
				++$staying;

				if ( count( $named ) < self::NAMED ) {
					$named[] = self::display_name( $user_id );
				}
			}
		}

		return array(
			'moving'       => $moving,
			'already'      => $already,
			'staying'      => $staying,
			'named'        => $named,
			'codes_moving' => $with,
		);
	}

	/**
	 * Bring over every account a plugin has an authenticator app set up for.
	 * Accounts already set up here are left as they are, so running this
	 * twice moves nobody twice.
	 *
	 * @return array{moved: int, staying: int, undo: string}|\WP_Error
	 */
	public static function carry( string $file ) {
		$accounts = self::accounts( $file );
		$manager  = Manager::instance();
		$moving   = array();
		$staying  = array();

		foreach ( $accounts as $user_id => $secret ) {
			if ( $manager->enabled( $user_id ) ) {
				continue;
			}

			if ( '' === $secret ) {
				$staying[] = $user_id;
			} else {
				$moving[ $user_id ] = $secret;
			}
		}

		$name = self::name( $file );

		if ( array() === $moving && array() === $staying ) {
			return array(
				'moved'   => 0,
				'staying' => 0,
				'undo'    => '',
			);
		}

		$token = '';

		if ( array() !== $moving ) {
			$token = (string) Ledger::open(
				self::ACTION,
				array(
					'plugin' => $file,
					// Nothing of this plugin's own on any of them before.
					'users'  => array_keys( $moving ),
				),
				array(
					'plugin'  => $file,
					'name'    => $name,
					'accounts' => array_map(
						static fn( int $user_id, string $secret ): array => array(
							'user'   => $user_id,
							'digest' => hash( 'sha256', $secret ),
						),
						array_keys( $moving ),
						array_values( $moving )
					),
				)
			);

			if ( '' === $token ) {
				Writer::instance()->record(
					'two_factor_import_failed',
					Writer::SEVERITY_HIGH,
					array( 'context' => array( 'plugin' => $name, 'accounts' => count( $moving ) ) )
				);

				return new \WP_Error(
					'bettershield_two_factor_not_moved',
					/* translators: %s: a plugin's name. */
					sprintf( __( 'Two-factor could not be brought over from %s, because the record of the change could not be saved. Nothing was changed.', 'bettershield' ), $name ),
					array( 'status' => 500 )
				);
			}
		}

		$moved = 0;
		$codes = self::codes_of( $file );

		foreach ( $moving as $user_id => $secret ) {
			if ( $manager->adopt( $user_id, $secret ) ) {
				++$moved;
				self::record( 'two_factor_moved', $user_id, $name, BackupCodes::bring_over( $user_id, $codes[ $user_id ] ?? array() ) );
			} else {
				$staying[] = $user_id;
			}
		}

		$told = get_option( self::NOT_MOVED_OPTION, array() );
		$told = is_array( $told ) ? $told : array();
		$said = array_map( 'intval', (array) ( $told[ $file ] ?? array() ) );

		// Once per account per plugin: nothing about it changes each time the
		// plugin goes off again.
		foreach ( $staying as $user_id ) {
			if ( ! in_array( (int) $user_id, $said, true ) ) {
				self::record( 'two_factor_not_moved', (int) $user_id, $name );
				$said[] = (int) $user_id;
			}
		}

		if ( array() === $said ) {
			unset( $told[ $file ] );
		} else {
			$told[ $file ] = array_values( array_intersect( $said, array_map( 'intval', array_merge( array_keys( $accounts ), $staying ) ) ) );
		}

		update_option( self::NOT_MOVED_OPTION, $told, false );

		if ( '' !== $token && 0 === $moved ) {
			Ledger::mark_reverted( $token );
			$token = '';
		}

		// A summary says something moved: with nobody moved, each account left
		// behind has its own row, the first time.
		if ( $moved > 0 ) {
			Writer::instance()->record(
				'two_factor_imported',
				array() === $staying ? Writer::SEVERITY_INFO : Writer::SEVERITY_MEDIUM,
				array(
					'context' => array(
						'plugin'  => $name,
						'moved'   => $moved,
						'staying' => count( $staying ),
					),
				)
			);
		}

		return array(
			'moved'   => $moved,
			'staying' => count( $staying ),
			'undo'    => $token,
		);
	}

	/**
	 * Take a copy back: each account brought over loses the secret it was
	 * given, unless it has set two-factor up again here since.
	 *
	 * @return array{removed: int, kept: int}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key || null !== ( $entry->reverted_at ?? null ) ) {
			return new \WP_Error( 'bettershield_undo_unknown', __( 'That change has already been undone, or was never made here.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$applied  = is_array( $entry->applied_state ) ? $entry->applied_state : array();
		$accounts = is_array( $applied['accounts'] ?? null ) ? $applied['accounts'] : array();
		$name     = (string) ( $applied['name'] ?? '' );
		$removed  = 0;

		// What the copy recorded has to be queued before it can be taken out.
		Writer::instance()->flush();

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$protected = is_plugin_active( (string) ( $applied['plugin'] ?? '' ) );

		foreach ( $accounts as $account ) {
			$user_id = is_array( $account ) ? (int) ( $account['user'] ?? 0 ) : 0;

			if ( ! is_array( $account ) || ! Manager::instance()->withdraw( $user_id, (string) ( $account['digest'] ?? '' ) ) ) {
				continue;
			}

			++$removed;

			// "Your authenticator app keeps working" is no longer true.
			AccountNotices::drop( $user_id, 'two_factor_moved' );

			// With the plugin off, the account is down to its password. With it
			// on, the account is back as it was, so there's nothing to tell it.
			if ( ! $protected ) {
				Writer::instance()->record(
					'two_factor_disabled',
					Policy::instance()->user_is_privileged( $user_id ) ? Writer::SEVERITY_HIGH : Writer::SEVERITY_LOW,
					array(
						'object_type' => 'user',
						'object_id'   => (string) $user_id,
						'context'     => array(
							'by'   => 'import_undone',
							'name' => $name,
						),
					)
				);
			}
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'two_factor_import_undone',
			Writer::SEVERITY_MEDIUM,
			array(
				'context' => array(
					'plugin'  => $name,
					'removed' => $removed,
				),
			)
		);

		return array(
			'removed' => $removed,
			'kept'    => count( $accounts ) - $removed,
		);
	}

	/**
	 * Take back what was brought over from a plugin that is on again. Its
	 * records were never touched, so each account is back as it was, and is
	 * not asked for a code by both plugins.
	 */
	public static function take_back( string $file ): void {
		foreach ( self::open_imports() as $row ) {
			if ( $file === $row['plugin'] ) {
				self::undo( $row['undo'] );
			}
		}
	}

	/**
	 * The copies still open, newest first, for the list of ways back.
	 *
	 * @return array<int, array{undo: string, name: string, accounts: int}>
	 */
	public static function open_imports(): array {
		$rows = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 5 ) as $token ) {
			$entry   = Ledger::find( $token );
			$applied = null === $entry ? null : $entry->applied_state;

			if ( ! is_array( $applied ) ) {
				continue;
			}

			$rows[] = array(
				'undo'     => $token,
				'plugin'   => (string) ( $applied['plugin'] ?? '' ),
				'name'     => (string) ( $applied['name'] ?? '' ),
				'accounts' => is_array( $applied['accounts'] ?? null ) ? count( $applied['accounts'] ) : 0,
			);
		}

		return $rows;
	}

	/**
	 * Every account a plugin has two-factor set up for, each with the base32
	 * secret of its authenticator app, or '' where it has none this plugin
	 * can use.
	 *
	 * @return array<int, string> User ID => secret.
	 */
	public static function accounts( string $file ): array {
		switch ( self::SOURCES[ $file ] ?? '' ) {
			case 'two_factor':
				return self::from_two_factor();
			case 'wp_2fa':
				return self::from_wp_2fa();
			case 'wordfence':
				return self::from_wordfence();
		}

		return array();
	}

	/**
	 * Two Factor: the providers on, as a list of class names, and the TOTP
	 * secret in base32 beside them.
	 *
	 * @return array<int, string>
	 */
	private static function from_two_factor(): array {
		$out = array();

		foreach ( self::meta_rows( '_two_factor_enabled_providers', '_two_factor_totp_key' ) as $user_id => $meta ) {
			$providers = maybe_unserialize( $meta['_two_factor_enabled_providers'] ?? '' );

			if ( ! is_array( $providers ) || array() === array_filter( $providers ) ) {
				continue;
			}

			$out[ $user_id ] = in_array( 'Two_Factor_Totp', $providers, true )
				? self::usable( (string) ( $meta['_two_factor_totp_key'] ?? '' ) )
				: '';
		}

		return $out;
	}

	/**
	 * WP 2FA: the method on, by name, and the TOTP secret, sealed with its
	 * own key where the host has OpenSSL. Opened only through its own code,
	 * and only through calls that read: nothing of its is written back.
	 *
	 * @return array<int, string>
	 */
	private static function from_wp_2fa(): array {
		$out = array();

		foreach ( self::meta_rows( 'wp_2fa_enabled_methods', 'wp_2fa_totp_key' ) as $user_id => $meta ) {
			$method = (string) ( $meta['wp_2fa_enabled_methods'] ?? '' );

			if ( '' === trim( $method ) ) {
				continue;
			}

			$out[ $user_id ] = 'totp' === $method
				? self::usable( self::open_wp_2fa( (string) ( $meta['wp_2fa_totp_key'] ?? '' ) ) )
				: '';
		}

		return $out;
	}

	/**
	 * A WP 2FA secret as stored, opened: one of its prefixes says which of
	 * its keys sealed it, and none means it was stored in the clear.
	 */
	private static function open_wp_2fa( string $stored ): string {
		$class = '\WP2FA\Authenticator\Open_SSL';

		if ( '' === $stored || 1 === preg_match( '/^[A-Za-z2-7]+=*$/', $stored ) ) {
			return $stored;
		}

		if ( ! class_exists( $class ) ) {
			return '';
		}

		$current = defined( $class . '::SECRET_KEY_PREFIX' ) ? (string) constant( $class . '::SECRET_KEY_PREFIX' ) : '';
		$openers = array(
			$current => 'decrypt',
			'ssl_'   => 'decrypt_legacy',
			'wps_'   => 'decrypt_wps',
		);

		foreach ( $openers as $prefix => $method ) {
			if ( '' === $prefix || 0 !== strpos( $stored, $prefix ) || ! method_exists( $class, $method ) ) {
				continue;
			}

			try {
				return (string) call_user_func( array( $class, $method ), substr( $stored, strlen( $prefix ) ) );
			} catch ( \Throwable $e ) {
				return '';
			}
		}

		return '';
	}

	/**
	 * Wordfence: a table of the network's own, one row per account with the
	 * secret as raw bytes, which an authenticator app was given in base32.
	 *
	 * @return array<int, string>
	 */
	private static function from_wordfence(): array {
		global $wpdb;

		$quiet = $wpdb->suppress_errors( true );

		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- another plugin's own table, read once as it is switched off; there is no API for it, and nothing is written to it.
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT user_id, secret FROM %i', $wpdb->base_prefix . 'wfls_2fa_secrets' ) );
		} finally {
			$wpdb->suppress_errors( $quiet );
		}

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$user_id = (int) $row->user_id;
			$bytes   = (string) $row->secret;

			if ( $user_id > 0 && get_userdata( $user_id ) instanceof \WP_User ) {
				$out[ $user_id ] = strlen( $bytes ) >= 10 ? Totp::base32_encode( $bytes ) : '';
			}
		}

		return $out;
	}

	/**
	 * The unused backup codes a plugin holds in a form that can be read, by
	 * account. Only Wordfence's can.
	 *
	 * @return array<int, string[]> User ID => codes, as `BackupCodes::imported_code()` reduces them.
	 */
	private static function codes_of( string $file ): array {
		return 'wordfence' === ( self::SOURCES[ $file ] ?? '' ) ? self::wordfence_codes() : array();
	}

	/**
	 * Wordfence's recovery codes, kept as one run of eight random bytes each
	 * and typed as their hex. A run that isn't a whole number of codes isn't
	 * one this reading of the table can trust, so that account gets none.
	 *
	 * @return array<int, string[]>
	 */
	private static function wordfence_codes(): array {
		global $wpdb;

		$quiet = $wpdb->suppress_errors( true );

		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- another plugin's own table, read once as it is switched off; there is no API for it, and nothing is written to it.
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT user_id, recovery FROM %i', $wpdb->base_prefix . 'wfls_2fa_secrets' ) );
		} finally {
			$wpdb->suppress_errors( $quiet );
		}

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$bytes = (string) $row->recovery;

			if ( '' !== $bytes && 0 === strlen( $bytes ) % 8 ) {
				$out[ (int) $row->user_id ] = str_split( bin2hex( $bytes ), 16 );
			}
		}

		return $out;
	}

	/**
	 * Two meta keys' values by account, in one query, for the accounts that
	 * have the first and still exist.
	 *
	 * @return array<int, array<string, string>> User ID => key => value.
	 */
	private static function meta_rows( string $marker, string $secret ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- another plugin's two-factor records, read whole in one query; no API reads one meta key across accounts without loading each.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT m.user_id, m.meta_key, m.meta_value FROM {$wpdb->usermeta} m INNER JOIN {$wpdb->users} u ON u.ID = m.user_id WHERE m.meta_key IN (%s, %s)", $marker, $secret ) );
		$out  = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[ (int) $row->user_id ][ (string) $row->meta_key ] = (string) $row->meta_value;
		}

		return array_filter( $out, static fn( array $meta ): bool => isset( $meta[ $marker ] ) );
	}

	/**
	 * A secret in the form this plugin keeps, or '' where it is not one an
	 * authenticator app could hold: base32, upper case, no padding or
	 * spaces, at least 80 bits.
	 */
	public static function usable( string $secret ): string {
		$secret = strtoupper( (string) preg_replace( '/[\s=]+/', '', $secret ) );

		if ( 1 !== preg_match( '/^[A-Z2-7]+$/', $secret ) || strlen( Totp::base32_decode( $secret ) ) < 10 ) {
			return '';
		}

		return $secret;
	}

	private static function record( string $type, int $user_id, string $name, int $codes = 0 ): void {
		Writer::instance()->record(
			$type,
			'two_factor_moved' === $type ? Writer::SEVERITY_INFO : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user_id,
				'context'     => array(
					'name'  => $name,
					'codes' => $codes,
				),
			)
		);
	}

	private static function name( string $file ): string {
		// The name its own header gives, as every other row about it says.
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$path = WP_PLUGIN_DIR . '/' . $file;
		$own  = is_readable( $path ) ? wp_strip_all_tags( (string) ( get_plugin_data( $path, false, false )['Name'] ?? '' ) ) : '';

		if ( '' !== $own ) {
			return $own;
		}

		$known = array(
			'two-factor/two-factor.php'                             => 'Two Factor',
			'wp-2fa/wp-2fa.php'                                     => 'WP 2FA',
			'wordfence/wordfence.php'                               => 'Wordfence',
			'wordfence-login-security/wordfence-login-security.php' => 'Wordfence Login Security',
		);

		return $known[ $file ] ?? $file;
	}

	private static function display_name( int $user_id ): string {
		$user = get_userdata( $user_id );

		return $user instanceof \WP_User ? (string) $user->display_name : '';
	}
}
