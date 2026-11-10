<?php
/**
 * The ways back from the one-press fixes that outlive their finding
 * (#2430, #2471): a plugin update, an unused plugin or theme moved into
 * quarantine, wp-config.php's permissions, the account renamed from
 * "admin", scheduled events removed, folders' permissions narrowed,
 * accounts asked for a new password, this site's own links rewritten to
 * https:// and the quarantine folder sealed (#2658).
 *
 * Each fix closes its finding, and with it the panel that held its Undo.
 * These are listed again where the setting changes are undone, each with
 * the route its panel used, so the same session and password gates apply.
 * Only what can still be put back is listed, and only to somebody with the
 * say over what each one changed: the shared code and configuration, the
 * site's own schedule, or the account.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Rest\Permissions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FixUndos {

	/**
	 * Every way back still open, newest kind first.
	 *
	 * @return array<int, array{kind: string, token: string, name: string, from: string, to: string, blocked: string}>
	 */
	public static function listing(): array {
		if ( ! Permissions::manage() ) {
			return array();
		}

		// Their own gate: who may change the account, asked of each one.
		$rows = array();

		foreach ( AdminUsername::open_renames() as $row ) {
			$rows[] = array(
				'kind'    => 'admin_rename',
				'token'   => $row['undo'],
				'name'    => $row['name'],
				'from'    => $row['name'],
				'to'      => $row['to'],
				'blocked' => '',
			);
		}

		foreach ( WeakPasswords::open_holds() as $row ) {
			$rows[] = array(
				'kind'    => 'password_hold',
				'token'   => $row['undo'],
				'name'    => $row['login'],
				'from'    => '',
				'to'      => '',
				'blocked' => '',
			);
		}

		// The REST routes picked here: this site's own answers, a site's
		// administrator's to open again (#1870).
		foreach ( RestRoutes::open_changes() as $row ) {
			$rows[] = array(
				'kind'    => 'rest_route',
				'token'   => $row['undo'],
				'name'    => $row['route'],
				'from'    => '',
				'to'      => $row['state'],
				'blocked' => '',
			);
		}

		// The site's own schedule: a site's administrator removed them, and
		// may put them back.
		foreach ( ScheduledEvents::open_removals() as $row ) {
			$rows[] = array(
				'kind'    => 'scheduled_events',
				'token'   => $row['undo'],
				'name'    => implode( ', ', $row['hooks'] ),
				'from'    => '',
				'to'      => '',
				'blocked' => '',
			);
		}

		// This site's own published posts, put back as they were (#2658).
		$links = ContentLinks::open_run();

		if ( null !== $links ) {
			$rows[] = array(
				'kind'    => 'content_links',
				'token'   => $links['undo'],
				'name'    => '',
				'from'    => '',
				'to'      => (string) $links['posts'],
				'blocked' => '',
			);
		}

		// Two-factor brought over from another plugin as it was switched off:
		// a site's administrator handed the job over, and may take it back.
		foreach ( \BetterShield\TwoFactor\Import::open_imports() as $row ) {
			$rows[] = array(
				'kind'    => 'two_factor_import',
				'token'   => $row['undo'],
				'name'    => $row['name'],
				'from'    => '',
				'to'      => (string) $row['accounts'],
				'blocked' => '',
			);
		}

		// The quarantine folder's seal, a site's administrator's to take back.
		$seal = QuarantineSeal::open_seal();

		if ( null !== $seal ) {
			$rows[] = array(
				'kind'    => 'quarantine_seal',
				'token'   => $seal['undo'],
				'name'    => '',
				'from'    => '',
				'to'      => '',
				'blocked' => '',
			);
		}

		if ( true !== Permissions::shared_code() ) {
			return $rows;
		}

		foreach ( PluginUpdates::open_updates() as $row ) {
			$rows[] = array(
				'kind'    => 'plugin_update',
				'token'   => $row['undo'],
				'name'    => $row['name'],
				'from'    => $row['from'],
				'to'      => $row['to'],
				'blocked' => '',
			);
		}

		foreach ( InactiveExtensions::moved() as $row ) {
			$rows[] = array(
				'kind'    => 'theme' === $row['kind'] ? 'theme_quarantined' : 'plugin_quarantined',
				'token'   => $row['undo'],
				'name'    => $row['name'],
				'from'    => '',
				'to'      => '',
				'blocked' => $row['blocked'],
			);
		}

		foreach ( WorldWritable::open_changes() as $row ) {
			$rows[] = array(
				'kind'    => 'folder_mode',
				'token'   => $row['undo'],
				'name'    => $row['name'],
				'from'    => $row['from'],
				'to'      => $row['to'],
				'blocked' => '',
			);
		}

		$config = ConfigMode::open_change();

		if ( null !== $config ) {
			$rows[] = array(
				'kind'    => 'config_mode',
				'token'   => $config['undo'],
				'name'    => 'wp-config.php',
				'from'    => $config['from'],
				'to'      => ConfigMode::state()['mode'],
				'blocked' => '',
			);
		}

		return $rows;
	}
}
