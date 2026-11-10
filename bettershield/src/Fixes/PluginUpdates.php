<?php
/**
 * Fix for "Plugins have updates available" and "Installed components have
 * published advisories" (#2430): Update now, one plugin at a time, the way
 * WordPress's own Update now button does it, at the owner's press.
 *
 * Updating is not cleanly reversible, and this says so before the press
 * rather than after. It is offered only for plugins the WordPress.org
 * directory publishes, because that is the one place every earlier release
 * has an address that can be worked out: Undo installs the version that
 * was there again, through the same installer. That puts the code back, not
 * anything the newer version changed in the database, which nothing can.
 * A plugin that updates from its own publisher is left to the Updates
 * screen, where its own way back is the publisher's.
 *
 * The version that was there is written down before the update starts, so
 * an update that stops halfway still leaves the way back. Nothing here runs
 * on a schedule or on a visitor's request: only on an administrator's press.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\BackupVisibility;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;
use BetterShield\Undo\Ledger;
use BetterShield\Vulnerabilities\Inventory;
use BetterShield\Vulnerabilities\State;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PluginUpdates {

	/** The undo ledger's key for a plugin updated from a finding. */
	public const ACTION = 'finding_plugin_update';

	/** The findings this answers. */
	public const FINDINGS = array( 'plugin_updates_available', 'vulnerabilities_known' );

	/** One update at a time, across every request. */
	private const MUTEX = 'finding_plugin_update';

	/** A version as the directory names its downloads. */
	private const VERSION = '/^[0-9A-Za-z][0-9A-Za-z.\-]{0,40}$/';

	/** A directory slug. */
	private const SLUG = '/^[a-z0-9][a-z0-9\-]{0,190}$/';

	/**
	 * What the panel shows for one finding: each plugin, what it would be
	 * updated to, and why it cannot be updated here when it cannot.
	 *
	 * @return array<string, mixed>
	 */
	public static function state( string $finding ): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$offers    = self::offers();
		$installed = get_plugins();
		$rows      = array();

		if ( 'vulnerabilities_known' === $finding ) {
			foreach ( State::affected_now() as $item ) {
				if ( 'plugin' !== ( $item['type'] ?? '' ) ) {
					// A theme or WordPress itself: its update is on the Updates screen.
					$rows[] = array(
						'file'     => '',
						'name'     => (string) ( $item['name'] ?? $item['slug'] ?? '' ),
						'version'  => (string) ( $item['installed_version'] ?? '' ),
						'offer'    => '',
						'fixed_in' => (string) ( $item['fixed_in'] ?? '' ),
						'refused'  => self::reason( 'not_plugin' ),
					);
					continue;
				}

				$file = Inventory::file_for( (string) ( $item['slug'] ?? '' ) );

				if ( null === $file ) {
					continue;
				}

				$rows[] = self::row( $file, $installed[ $file ] ?? array(), $offers[ $file ] ?? null ) + array( 'fixed_in' => (string) ( $item['fixed_in'] ?? '' ) );
			}
		} else {
			foreach ( $offers as $file => $offer ) {
				if ( isset( $installed[ $file ] ) ) {
					$rows[] = self::row( $file, $installed[ $file ], $offer ) + array( 'fixed_in' => '' );
				}
			}
		}

		return array(
			'rows'        => $rows,
			// Who may update, here: on a network, plugins are the network's.
			'may_update'  => self::may_update(),
			// Whether WordPress can write the plugins folder without asking
			// for a password nobody is there to type.
			'can_install' => self::can_install(),
			'backup_seen' => array() !== BackupVisibility::report()['active_plugins'],
			'updates_url' => is_multisite() ? network_admin_url( 'update-core.php' ) : admin_url( 'update-core.php' ),
			'updated'     => self::open_updates(),
		);
	}

	/**
	 * Update one plugin the update cache offers a newer version of.
	 *
	 * @return array{name: string, from: string, to: string, undo: string}|\WP_Error
	 */
	public static function update( string $file ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$offers    = self::offers();
		$installed = get_plugins();

		if ( ! isset( $offers[ $file ], $installed[ $file ] ) ) {
			return new \WP_Error( 'bettershield_no_update', __( 'WordPress offers no newer version of that plugin now, so nothing was changed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$row = self::row( $file, $installed[ $file ], $offers[ $file ] );

		if ( '' !== $row['refused'] ) {
			return new \WP_Error( 'bettershield_update_refused', $row['refused'], array( 'status' => 409 ) );
		}

		if ( ! Claim::claim( self::MUTEX, 5 * MINUTE_IN_SECONDS ) ) {
			return new \WP_Error( 'bettershield_update_busy', __( 'Another update is running. Try again in a moment.', 'bettershield' ), array( 'status' => 409 ) );
		}

		try {
			return self::update_claimed( $file, $row, $offers[ $file ] );
		} finally {
			Claim::release( self::MUTEX );
		}
	}

	/**
	 * Install the version that was there before an update made here.
	 *
	 * @return array{name: string, version: string}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = '' === $token ? null : Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();
		$file    = (string) ( $prior['plugin'] ?? '' );
		$slug    = (string) ( $prior['slug'] ?? '' );
		$version = (string) ( $prior['version'] ?? '' );

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// Read from disk, not from what this request read before.
		wp_clean_plugins_cache( false );

		$now = (string) ( get_plugins()[ $file ]['Version'] ?? '' );

		// Only over the version this put there: a later update, or the
		// plugin's removal, is somebody else's change to keep.
		if ( '' === $now || $now !== (string) ( $applied['version'] ?? '' ) ) {
			return new \WP_Error( 'bettershield_version_moved', __( 'The plugin changed since, so undo left it alone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( 1 !== preg_match( self::SLUG, $slug ) || 1 !== preg_match( self::VERSION, $version ) ) {
			return new \WP_Error( 'bettershield_no_version', __( 'The version that was there was not recorded, so it cannot be put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! self::can_install() ) {
			return new \WP_Error( 'bettershield_no_filesystem', self::reason( 'filesystem' ), array( 'status' => 409 ) );
		}

		if ( ! Claim::claim( self::MUTEX, 5 * MINUTE_IN_SECONDS ) ) {
			return new \WP_Error( 'bettershield_update_busy', __( 'Another update is running. Try again in a moment.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$cache = get_site_transient( 'update_plugins' );

		try {
			self::load_upgrader();

			$skin     = new \WP_Ajax_Upgrader_Skin();
			$upgrader = new \Plugin_Upgrader( $skin );
			$level    = ob_get_level();
			$outcome  = $upgrader->run(
				array(
					// The directory keeps every release at this address.
					'package'           => 'https://downloads.wordpress.org/plugin/' . rawurlencode( $slug ) . '.' . rawurlencode( $version ) . '.zip',
					'destination'       => WP_PLUGIN_DIR,
					'clear_destination' => true,
					'clear_working'     => true,
					'hook_extra'        => array(
						'plugin' => $file,
						'type'   => 'plugin',
						'action' => 'update',
					),
				)
			);
		} finally {
			self::close_buffers( $level ?? ob_get_level() );
			Claim::release( self::MUTEX );
		}

		wp_clean_plugins_cache();

		$back = (string) ( get_plugins()[ $file ]['Version'] ?? '' );

		// The version undone is offered again, as it was before the update.
		$again = is_array( $applied['offer'] ?? null ) && version_compare( (string) ( $applied['offer']['new_version'] ?? '' ), $back, '>' ) ? $applied['offer'] : null;

		self::keep_offers( $cache, $file, $again );

		if ( is_wp_error( $outcome ) || ! $outcome || is_wp_error( $skin->result ) || $back !== $version ) {
			Ledger::mark_revert_failed( $token, 'reinstall' );

			return new \WP_Error(
				'bettershield_put_back_failed',
				/* translators: %s: a version number. */
				sprintf( __( 'Version %s could not be installed again. WordPress.org may no longer publish it.', 'bettershield' ), $version ),
				array( 'status' => 409 )
			);
		}

		if ( ! empty( $prior['active'] ) && ! is_plugin_active( $file ) ) {
			activate_plugin( $file, '', ! empty( $prior['network'] ) );
		}

		Ledger::mark_reverted( $token );

		$name = (string) ( $prior['name'] ?? $slug );

		Writer::instance()->record(
			'plugin_update_undone',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'plugin',
				'object_id'   => $file,
				'context'     => array(
					'from' => (string) ( $applied['version'] ?? '' ),
					'to'   => $version,
				),
			)
		);

		Auditor::run();

		return array(
			'name'    => $name,
			'version' => $version,
		);
	}

	/**
	 * @param array<string, mixed> $row   What the panel shows for it.
	 * @param array<string, mixed> $offer What the update cache offers for it.
	 * @return array{name: string, from: string, to: string, undo: string}|\WP_Error
	 */
	private static function update_claimed( string $file, array $row, array $offer ) {
		$network = is_multisite() && is_plugin_active_for_network( $file );
		$active  = is_plugin_active( $file );

		// The way back first: if it cannot be written down, nothing changes.
		$token = Ledger::open(
			self::ACTION,
			array(
				'plugin'  => $file,
				'slug'    => $row['slug'],
				'name'    => $row['name'],
				'version' => $row['version'],
				'active'  => $active,
				'network' => $network,
			),
			array(
				'version' => $row['offer'],
				// Offered again on Undo, so the plugin's row comes back.
				'offer'   => $offer,
			)
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::load_upgrader();

		$cache = get_site_transient( 'update_plugins' );

		// As WordPress's own Update now does: one plugin through the bulk
		// path, which leaves a running plugin running.
		$skin     = new \WP_Ajax_Upgrader_Skin();
		$upgrader = new \Plugin_Upgrader( $skin );
		$level    = ob_get_level();
		$result   = $upgrader->bulk_upgrade( array( $file ) );

		self::close_buffers( $level );

		wp_clean_plugins_cache();

		$to = (string) ( get_plugins()[ $file ]['Version'] ?? '' );

		self::keep_offers( $cache, $file, '' !== $to && version_compare( $to, $row['version'], '>' ) ? null : $offer );

		if ( ! is_array( $result ) || empty( $result[ $file ] ) || true === $result[ $file ] || is_wp_error( $skin->result ) || '' === $to || version_compare( $to, $row['version'], '<=' ) ) {
			// Nothing newer arrived, so there is nothing to undo.
			Ledger::mark_reverted( $token );

			$why = is_wp_error( $skin->result ) ? wp_strip_all_tags( $skin->result->get_error_message() ) : '';

			return new \WP_Error(
				'bettershield_update_failed',
				'' !== $why
					/* translators: %s: WordPress's own reason. */
					? sprintf( __( 'WordPress could not install the update: %s', 'bettershield' ), $why )
					: __( 'WordPress could not install the update, so the plugin is as it was.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		Writer::instance()->record(
			'plugin_update_applied',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'plugin',
				'object_id'   => $file,
				'context'     => array(
					'from' => $row['version'],
					'to'   => $to,
				),
			)
		);

		Auditor::run();

		return array(
			'name' => $row['name'],
			'from' => $row['version'],
			'to'   => $to,
			'undo' => $token,
		);
	}

	/**
	 * Put the update cache back after an upgrade emptied it.
	 *
	 * WordPress's upgrader deletes the cache when it is done, and every other
	 * plugin's offer went with it: the panel dropped their rows until the
	 * next check, and the audit run after the update could not read them
	 * (#2483). It is written back as it was, with this plugin's offer as it
	 * now stands: gone once updated, back once undone.
	 *
	 * @param mixed                     $cache The cache as it was before the upgrade.
	 * @param array<string, mixed>|null $offer This plugin's offer now, or null for none.
	 */
	private static function keep_offers( $cache, string $file, ?array $offer ): void {
		if ( ! is_object( $cache ) || false !== get_site_transient( 'update_plugins' ) ) {
			return;
		}

		$response = (array) ( $cache->response ?? array() );

		unset( $response[ $file ] );

		if ( null !== $offer ) {
			$response[ $file ] = (object) $offer;
		}

		$cache->response = $response;

		set_site_transient( 'update_plugins', $cache );
	}

	/**
	 * One plugin as the panel shows it.
	 *
	 * @param array<string, mixed>      $data  Its header, as get_plugins() reads it.
	 * @param array<string, mixed>|null $offer What the update cache offers for it.
	 * @return array{file: string, slug: string, name: string, version: string, offer: string, refused: string}
	 */
	private static function row( string $file, array $data, ?array $offer ): array {
		$version = (string) ( $data['Version'] ?? '' );
		$new     = null === $offer ? '' : (string) ( $offer['new_version'] ?? '' );
		$slug    = null === $offer ? Inventory::slug_for( $file ) : (string) ( $offer['slug'] ?? Inventory::slug_for( $file ) );
		$refused = '';

		if ( '' === $new ) {
			$refused = self::reason( 'no_offer' );
		} elseif ( ! self::from_directory( $offer ) || 1 !== preg_match( self::SLUG, $slug ) || 1 !== preg_match( self::VERSION, $version ) ) {
			$refused = self::reason( 'publisher' );
		} elseif ( ! self::may_update() ) {
			$refused = self::reason( 'network' );
		} elseif ( ! self::can_install() ) {
			$refused = self::reason( 'filesystem' );
		}

		return array(
			'file'    => $file,
			'slug'    => $slug,
			'name'    => '' !== (string) ( $data['Name'] ?? '' ) ? wp_strip_all_tags( (string) $data['Name'] ) : $slug,
			'version' => $version,
			'offer'   => $new,
			'refused' => $refused,
		);
	}

	/**
	 * What the update cache offers, by plugin file, for each plugin it
	 * offers a version newer than the one installed.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function offers(): array {
		$data = get_site_transient( 'update_plugins' );

		if ( ! is_object( $data ) ) {
			return array();
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$offers    = array();

		foreach ( (array) ( $data->response ?? array() ) as $file => $offer ) {
			$offer   = (array) $offer;
			$new     = (string) ( $offer['new_version'] ?? '' );
			$running = (string) ( $installed[ (string) $file ]['Version'] ?? '' );

			if ( '' !== $new && '' !== $running && version_compare( $new, $running, '>' ) ) {
				$offers[ (string) $file ] = $offer;
			}
		}

		return $offers;
	}

	/**
	 * Whether WordPress.org publishes the plugin the offer is for: the one
	 * place an earlier version can be fetched again for Undo.
	 *
	 * @param array<string, mixed>|null $offer
	 */
	private static function from_directory( ?array $offer ): bool {
		if ( null === $offer ) {
			return false;
		}

		$package = (string) ( $offer['package'] ?? '' );

		return str_starts_with( (string) ( $offer['id'] ?? '' ), 'w.org/plugins/' )
			&& 'downloads.wordpress.org' === strtolower( (string) wp_parse_url( $package, PHP_URL_HOST ) );
	}

	/**
	 * Whether the person asking may update plugins here. On a network the
	 * plugins are every site's, so only a network administrator may.
	 */
	private static function may_update(): bool {
		return current_user_can( 'update_plugins' ) && ( ! is_multisite() || current_user_can( 'manage_network_plugins' ) );
	}

	/**
	 * Whether WordPress can write the plugins folder without asking for
	 * credentials, which a request with nobody to type them cannot answer.
	 */
	private static function can_install(): bool {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		return 'direct' === get_filesystem_method( array(), WP_PLUGIN_DIR );
	}

	/**
	 * The updates made here that can still be put back: newest first, the
	 * plugin still at the version the update gave it.
	 *
	 * @return array<int, array{name: string, from: string, to: string, undo: string}>
	 */
	public static function open_updates(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$open      = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 10 ) as $token ) {
			$entry   = Ledger::find( $token );
			$prior   = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();
			$applied = null !== $entry && is_array( $entry->applied_state ) ? $entry->applied_state : array();
			$now     = (string) ( $installed[ (string) ( $prior['plugin'] ?? '' ) ]['Version'] ?? '' );

			if ( '' !== $now && $now === (string) ( $applied['version'] ?? '' ) ) {
				$open[] = array(
					'name' => (string) ( $prior['name'] ?? '' ),
					'from' => (string) ( $prior['version'] ?? '' ),
					'to'   => $now,
					'undo' => $token,
				);
			}
		}

		return $open;
	}

	/**
	 * Close what the upgrader's skin left open on a failure, so its words
	 * are not printed in front of the answer this request gives.
	 */
	private static function close_buffers( int $level ): void {
		while ( ob_get_level() > $level ) {
			ob_end_clean();
		}
	}

	private static function load_upgrader(): void {
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	/**
	 * The words for each reason a plugin is left to the Updates screen.
	 */
	private static function reason( string $why ): string {
		switch ( $why ) {
			case 'not_plugin':
				return __( 'Update it from Dashboard › Updates.', 'bettershield' );
			case 'no_offer':
				return __( 'No fixed version is offered yet. Consider deactivating it from the Plugins screen until one is.', 'bettershield' );
			case 'publisher':
				return __( 'It updates from its own publisher, so BetterShield could not put it back. Update it from Dashboard › Updates.', 'bettershield' );
			case 'network':
				return __( 'On a network, a network administrator updates plugins.', 'bettershield' );
		}

		return __( 'WordPress asks for server credentials to write plugins here. Update it from Dashboard › Updates.', 'bettershield' );
	}
}
