<?php
/**
 * The one-press finding fixes, plugin updates and account fixes, offered to
 * an assistant on the same terms the rest of the write surface keeps.
 *
 * Three shapes, each calling the same fix class the dashboard's button
 * calls, so the two cannot drift apart. A fix that only adds protection and
 * whose fix class writes its undo row before it acts is applied directly. A
 * change to code, to an account, to published policy, or anything whose way
 * back is conditional, is a plan a person agrees to and a single-use
 * confirmation spent once. Every way back from these fixes takes protection
 * away again, so every one of them is a plan too, spent through
 * revert-hardening.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

use BetterShield\Agents\Capture;
use BetterShield\Audit\Cron;
use BetterShield\Audit\ExposedArtifacts;
use BetterShield\Fixes\AdminUsername;
use BetterShield\Fixes\DomainMailRecords;
use BetterShield\Fixes\DormantAccounts;
use BetterShield\Fixes\InactiveExtensions;
use BetterShield\Fixes\PluginUpdates;
use BetterShield\Fixes\ProtectionRepair;
use BetterShield\Fixes\RestRoutes;
use BetterShield\Fixes\ScheduledEvents;
use BetterShield\Fixes\StalePasswords;
use BetterShield\Fixes\WeakPasswords;
use BetterShield\Fixes\WorldWritable;
use BetterShield\Hardening\Item\ContentSecurityPolicy;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\Lockdown;
use BetterShield\Recovery\SafeMode;
use BetterShield\Remediation\PasswordHold;
use BetterShield\Rest\Permissions;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class WriteFixes {

	/** Fixes that only add protection, each written to the undo ledger by its own fix class before it acts. */
	public const DIRECT = array( 'remove-scheduled-events', 'guard-rest-route', 'narrow-folder-permissions', 'reapply-protection', 'remove-script-source' );

	/** The direct fixes that change code or folders every site of a network shares. */
	private const SHARED_CODE = array( 'narrow-folder-permissions' );

	/** The findings whose fix lists get-fix-targets reads. */
	public const TARGETS = array(
		'cron_events_unanswered',
		'rest_surface_unreviewed',
		'content_dirs_world_writable',
		'hardening_not_working',
		'domain_mail_records',
		'plugin_updates_available',
		'vulnerabilities_known',
		'inactive_extensions',
		'leftover_tools_reachable',
		'artifacts_downloadable',
		'admin_username_exists',
		'application_passwords_stale',
		'privileged_account_dormant',
		'passwords_below_policy',
		'csp_report_only',
	);

	/** At most this many rows in one read. */
	public const MAX_TARGETS = 50;

	/** The ledger keys whose way back spends a propose-fix-undo plan. */
	public static function undo_keys(): array {
		return array( ScheduledEvents::ACTION, RestRoutes::ACTION, WorldWritable::ACTION, PluginUpdates::ACTION, InactiveExtensions::ACTION, AdminUsername::ACTION, DormantAccounts::ACTION, PasswordHold::KEY );
	}

	/** What the dashboard calls a proposal for each of these, when it lists one. */
	public static function labels(): array {
		return array(
			'bettershield/update-plugin'           => __( 'Update a plugin', 'bettershield' ),
			'bettershield/quarantine-extension'    => __( 'Move an unused plugin or theme into quarantine', 'bettershield' ),
			'bettershield/quarantine-exposed-file' => __( 'Move a downloadable file into quarantine', 'bettershield' ),
			'bettershield/rename-admin-account'    => __( 'Rename the account named admin', 'bettershield' ),
			'bettershield/revoke-app-password'     => __( 'Revoke an unused application password', 'bettershield' ),
			'bettershield/suspend-account'         => __( 'Suspend an unused privileged account', 'bettershield' ),
			'bettershield/hold-password'           => __( 'Ask an account for a new password', 'bettershield' ),
			'bettershield/change-script-policy'    => __( 'Change the script and content policy', 'bettershield' ),
		);
	}

	/**
	 * A locked-down site or one in safe mode takes no change from an
	 * assistant: both are a person's emergency state, and both are lifted on
	 * the site.
	 */
	public static function gate(): ?\WP_Error {
		if ( Lockdown::is_active() || SafeMode::is_active() ) {
			return self::error( 'bettershield_site_paused', __( 'The site is locked down or in safe mode, so it takes no change from an assistant. A person lifts that on the site.', 'bettershield' ), 409 );
		}

		return null;
	}

	/** BetterShield itself, or one of its add-ons: their code is changed on the site, never by an assistant. */
	public static function own_code( string $file ): bool {
		$folder = strtok( $file, '/' );

		return plugin_basename( BETTERSHIELD_FILE ) === $file || 'bettershield' === $folder || str_starts_with( (string) $folder, 'bettershield-' );
	}

	public static function shared_code( string $short ): bool {
		return in_array( $short, self::SHARED_CODE, true );
	}

	/* ---- the direct fixes ------------------------------------------------ */

	public static function definitions( callable $execute ): array {
		$string  = array( 'type' => 'string' );
		$boolean = array( 'type' => 'boolean' );
		$names   = array(
			'type'  => 'array',
			'items' => array( 'type' => 'string' ),
		);
		$specs   = array(
			'remove-scheduled-events'   => array(
				'label'       => __( 'Remove unanswered scheduled events', 'bettershield' ),
				'description' => __( 'Removes every scheduled run of the named hooks, which nothing on the site answers now. Name hooks get-fix-targets lists for cron_events_unanswered, in one call. The runs are kept in the undo record first; putting them back takes a plan from propose-fix-undo.', 'bettershield' ),
				'input'       => array(
					'hooks' => array(
						'type'     => 'array',
						'items'    => array( 'type' => 'string', 'maxLength' => 191 ),
						'minItems' => 1,
						'maxItems' => Cron::MAX_NAMED,
					),
				),
				'required'    => array( 'hooks' ),
				'output'      => array( 'removed' => $names ),
			),
			'guard-rest-route'          => array(
				'label'       => __( 'Watch or close an open REST route', 'bettershield' ),
				'description' => __( 'Starts watching who reads one REST route that answers anyone, or, after a week of watching, requires sign-in for it. Name a route get-fix-targets lists for rest_surface_unreviewed. Opening it to anyone again takes a plan from propose-fix-undo with the undo_token returned when watching started.', 'bettershield' ),
				'input'       => array(
					'route'  => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 512 ),
					'action' => array( 'type' => 'string', 'enum' => array( 'watch', 'close' ) ),
				),
				'required'    => array( 'route', 'action' ),
				'output'      => array( 'route' => $string, 'state' => $string ),
			),
			'narrow-folder-permissions' => array(
				'label'       => __( 'Stop anyone on the server writing to content folders', 'bettershield' ),
				'description' => __( 'Takes the world-write permission away from the named content folders get-fix-targets lists for content_dirs_world_writable. Each folder gets its own undo_token; giving the permission back takes a plan from propose-fix-undo.', 'bettershield' ),
				'input'       => array(
					'folders' => array(
						'type'     => 'array',
						'items'    => array( 'type' => 'string', 'maxLength' => 64 ),
						'minItems' => 1,
						'maxItems' => 10,
					),
				),
				'required'    => array( 'folders' ),
				'output'      => array(
					'changed' => array(
						'type'  => 'array',
						'items' => array(
							'type'       => 'object',
							'properties' => array( 'name' => $string, 'from' => $string, 'to' => $string, 'undo_token' => $string ),
						),
					),
					'refused' => array(
						'type'  => 'array',
						'items' => array(
							'type'       => 'object',
							'properties' => array( 'name' => $string, 'reason' => $string ),
						),
					),
				),
			),
			'reapply-protection'        => array(
				'label'       => __( 'Apply a protection that stopped working again', 'bettershield' ),
				'description' => __( 'Applies one protection that is on but reads as not working again, with the settings it already has. Only a protection get-fix-targets lists for hardening_not_working. A protection that changes how people sign in or the site’s address is applied again on the site.', 'bettershield' ),
				'input'       => array(
					'item_id' => array( 'type' => 'string', 'enum' => Items::ids() ),
				),
				'required'    => array( 'item_id' ),
				'output'      => array( 'item_id' => $string, 'working' => $boolean ),
			),
			'remove-script-source'      => array(
				'label'       => __( 'Take a source off the script and content policy', 'bettershield' ),
				'description' => __( 'Takes one allowed source off the test script and content policy, so the policy reports it again. This narrows the policy. Allowing it again takes a plan from propose-script-policy.', 'bettershield' ),
				'input'       => array(
					'directive' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 40 ),
					'source'    => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 300 ),
				),
				'required'    => array( 'directive', 'source' ),
				'output'      => array( 'directive' => $string, 'source' => $string, 'note' => $string ),
			),
		);

		$out = array();

		foreach ( $specs as $short => $spec ) {
			$properties = array( 'applied' => $boolean ) + $spec['output'];

			if ( in_array( $short, array( 'remove-scheduled-events', 'guard-rest-route', 'remove-script-source' ), true ) ) {
				$properties['undo_token'] = $string;
			}

			$out[ 'bettershield/' . $short ] = array(
				'category'            => 'bettershield',
				'permission_callback' => array( Registrar::class, 'can_write' ),
				'label'               => $spec['label'],
				'description'         => $spec['description'],
				'meta'                => array(
					// It changes the site; doing it twice finds nothing left to do.
					'annotations'  => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => true,
					),
					'show_in_rest' => true,
				),
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => $spec['input'],
					'required'   => $spec['required'],
				),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => $properties,
					'required'   => array( 'applied' ),
				),
				'execute_callback'    => static function ( $input ) use ( $execute, $short ) {
					return $execute( $short, $input );
				},
			);
		}

		return $out;
	}

	/** Shape only; refused before the hour's allowance is taken. Core does not reject extra keys, so this does. */
	public static function validate( string $short, array $input ): ?\WP_Error {
		$bad    = self::error( 'bettershield_fix_input', __( 'Name what get-fix-targets lists for this fix, and nothing else.', 'bettershield' ), 400 );
		$fields = array(
			'remove-scheduled-events'   => array( 'hooks' ),
			'guard-rest-route'          => array( 'route', 'action' ),
			'narrow-folder-permissions' => array( 'folders' ),
			'reapply-protection'        => array( 'item_id' ),
			'remove-script-source'      => array( 'directive', 'source' ),
		);

		if ( ! isset( $fields[ $short ] ) || array() !== array_diff( array_keys( $input ), $fields[ $short ] ) ) {
			return $bad;
		}

		foreach ( $fields[ $short ] as $key ) {
			$value = $input[ $key ] ?? null;

			if ( in_array( $key, array( 'hooks', 'folders' ), true ) ) {
				$max = 'hooks' === $key ? Cron::MAX_NAMED : 10;

				if ( ! is_array( $value ) || array() === $value || count( $value ) > $max || array_filter( $value, static fn( $one ): bool => ! is_string( $one ) || '' === $one ) ) {
					return $bad;
				}
			} elseif ( ! is_string( $value ) || '' === $value ) {
				return $bad;
			}
		}

		if ( 'guard-rest-route' === $short && ! in_array( $input['action'], array( 'watch', 'close' ), true ) ) {
			return $bad;
		}

		// Enforcing, a source taken off is blocked for every visitor at once, checkout included.
		if ( 'remove-script-source' === $short && ContentSecurityPolicy::MODE_ENFORCING === ContentSecurityPolicy::mode( Manager::instance()->item_state( 'csp_report_only' ) ) ) {
			return self::error( 'bettershield_csp_enforcing', __( 'The policy is enforced, so taking a source off is done on the site.', 'bettershield' ), 409 );
		}

		if ( 'reapply-protection' === $short ) {
			$item = $input['item_id'];

			if ( ! in_array( $item, Items::ids(), true ) ) {
				return $bad;
			}

			// The route asks for the session for these; an assistant does not reach them.
			if ( Permissions::needs_way_back( $item ) || in_array( $item, Registrar::HUMAN_ONLY_ITEMS, true ) || ! Registrar::item_is_reversible( $item ) ) {
				return self::error( 'bettershield_human_only', __( 'This protection changes how people sign in, the site’s address or something its undo cannot fully reach, so it is applied again on the site.', 'bettershield' ), 403 );
			}
		}

		return null;
	}

	/**
	 * Called only after Registrar repeated every gate, took the hour's slot
	 * and saved the intent. Each fix class writes its own undo row before it
	 * acts.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function apply( string $short, array $input ) {
		switch ( $short ) {
			case 'remove-scheduled-events':
				$done = ScheduledEvents::remove( $input['hooks'] );

				return is_wp_error( $done ) ? $done : array(
					'applied'    => true,
					'removed'    => array_values( array_map( 'strval', $done['removed'] ) ),
					'undo_token' => (string) $done['undo'],
				);
			case 'guard-rest-route':
				$route = $input['route'];
				$done  = 'watch' === $input['action'] ? RestRoutes::watch( $route ) : RestRoutes::close( $route );

				if ( is_wp_error( $done ) ) {
					return $done;
				}

				// Closing keeps the record watching opened: the one way back for both.
				$entry = RestRoutes::picked()[ $route ] ?? array();

				return array(
					'applied'    => true,
					'route'      => $route,
					'state'      => (string) ( $entry['state'] ?? '' ),
					'undo_token' => (string) ( $entry['undo'] ?? '' ),
				);
			case 'narrow-folder-permissions':
				$done = WorldWritable::apply( $input['folders'] );

				if ( array() === $done['changed'] ) {
					return self::error( 'bettershield_nothing_changed', (string) ( $done['refused'][0]['reason'] ?? __( 'None of those folders could be changed.', 'bettershield' ) ), 409 );
				}

				return array(
					'applied' => true,
					'changed' => array_map(
						static fn( array $row ): array => array(
							'name'       => (string) $row['name'],
							'from'       => (string) $row['from'],
							'to'         => (string) $row['to'],
							'undo_token' => (string) $row['undo'],
						),
						$done['changed']
					),
					'refused' => array_map(
						static fn( array $row ): array => array(
							'name'   => (string) $row['name'],
							'reason' => (string) $row['reason'],
						),
						$done['refused']
					),
				);
			case 'reapply-protection':
				$done = ProtectionRepair::reapply( $input['item_id'], false );

				return is_wp_error( $done ) ? $done : array(
					'applied' => true,
					'item_id' => (string) $done['item'],
					'working' => (bool) $done['working'],
				);
			case 'remove-script-source':
				$done = Manager::instance()->act( 'csp_report_only', 'remove_source', array( 'directive' => $input['directive'], 'source' => $input['source'] ) );

				return is_wp_error( $done ) ? $done : array(
					'applied'   => true,
					'directive' => $input['directive'],
					'source'    => strtolower( trim( $input['source'] ) ),
					'note'      => (string) ( $done['note'] ?? '' ),
				) + ( isset( $done['undo_token'] ) ? array( 'undo_token' => (string) $done['undo_token'] ) : array() );
		}

		return self::error( 'bettershield_fix_input', __( 'There is no such fix.', 'bettershield' ), 400 );
	}

	/* ---- the confirmed pairs --------------------------------------------- */

	/**
	 * Declared in the shape WriteExtensions runs, so the plan, the
	 * single-use confirmation, the state digest and the intent row are the
	 * same code an add-on's confirmed action already goes through.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function confirmed(): array {
		$string  = array( 'type' => 'string' );
		$id      = array( 'type' => 'integer', 'minimum' => 1 );
		$account = array( 'user_id' => $id, 'user_name' => $string );

		return array(
			'update-plugin'           => array(
				'propose'         => 'propose-plugin-update',
				'label'           => __( 'Update a plugin', 'bettershield' ),
				'description'     => __( 'Updates one plugin to the newer version wordpress.org offers, keeping the current version so it can be put back. Name a plugin file get-fix-targets lists for plugin_updates_available or vulnerabilities_known. New code can break a site in ways putting the old version back does not fully reverse, so this is always a plan a person agrees to.', 'bettershield' ),
				'target_type'     => 'plugin_update',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array( 'plugin' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 255 ) ),
					'required'   => array( 'plugin' ),
				),
				'output'          => array( 'plugin' => $string, 'name' => $string, 'from' => $string, 'to' => $string ),
				'output_required' => array( 'plugin', 'name' ),
				'snapshot'        => array( self::class, 'plugin_update' ),
				'execute'         => array( self::class, 'do_plugin_update' ),
			),
			'quarantine-extension'    => array(
				'propose'         => 'propose-extension-quarantine',
				'label'           => __( 'Move an unused plugin or theme into quarantine', 'bettershield' ),
				'description'     => __( 'Moves one deactivated plugin or unused theme get-fix-targets lists for inactive_extensions into quarantine, out of visitors’ reach. It is not running, so the site behaves as before. Putting it back takes a plan from propose-fix-undo.', 'bettershield' ),
				'target_type'     => 'extension',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'kind' => array( 'type' => 'string', 'enum' => array( 'plugin', 'theme' ) ),
						'id'   => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 255 ),
					),
					'required'   => array( 'kind', 'id' ),
				),
				'output'          => array( 'kind' => $string, 'id' => $string, 'name' => $string ),
				'output_required' => array( 'kind', 'id' ),
				'snapshot'        => array( self::class, 'extension' ),
				'execute'         => array( self::class, 'do_extension' ),
			),
			'quarantine-exposed-file' => array(
				'propose'         => 'propose-exposed-file-quarantine',
				'label'           => __( 'Move a downloadable file into quarantine', 'bettershield' ),
				'description'     => __( 'Moves one leftover tool, backup, dump or log that visitors can download into quarantine. Name a path get-fix-targets lists for leftover_tools_reachable or artifacts_downloadable. A moved file is put back from the quarantine list on the site.', 'bettershield' ),
				'target_type'     => 'exposed_file',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'kind' => array( 'type' => 'string', 'enum' => array( 'tool', 'artifact' ) ),
						'path' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 512 ),
					),
					'required'   => array( 'kind', 'path' ),
				),
				'output'          => array( 'kind' => $string, 'path' => $string ),
				'output_required' => array( 'kind', 'path' ),
				'snapshot'        => array( self::class, 'exposed_file' ),
				'execute'         => array( self::class, 'do_exposed_file' ),
			),
			'rename-admin-account'    => array(
				'propose'         => 'propose-admin-rename',
				'label'           => __( 'Rename the account named admin', 'bettershield' ),
				'description'     => __( 'Gives the account whose username is "admin" a new username. That person signs in with the new one from then on. Behind a recovery link verified within the day, and never the account the assistant acts as. Renaming it back takes a plan from propose-fix-undo.', 'bettershield' ),
				'target_type'     => 'account',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array( 'username' => array( 'type' => 'string', 'minLength' => 1, 'maxLength' => 60 ) ),
					'required'   => array( 'username' ),
				),
				'output'          => $account + array( 'username' => $string ),
				'output_required' => array( 'user_id', 'username' ),
				'snapshot'        => array( self::class, 'admin_rename' ),
				'execute'         => array( self::class, 'do_admin_rename' ),
			),
			'revoke-app-password'     => array(
				'propose'         => 'propose-app-password-revoke',
				'label'           => __( 'Revoke an unused application password', 'bettershield' ),
				'description'     => __( 'Revokes one application password nobody has used for a long time. Name the key get-fix-targets lists for application_passwords_stale. A revoked password cannot be restored, and the credential the caller uses is never revoked here.', 'bettershield' ),
				'target_type'     => 'application_password',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'password' => array(
							'type'    => 'string',
							'pattern' => '^[0-9]+:[a-f0-9-]{36}$',
						),
					),
					'required'   => array( 'password' ),
				),
				'output'          => $account + array( 'password' => $string, 'name' => $string ),
				'output_required' => array( 'password' ),
				'snapshot'        => array( self::class, 'app_password' ),
				'execute'         => array( self::class, 'do_app_password' ),
			),
			'suspend-account'         => array(
				'propose'         => 'propose-account-suspension',
				'label'           => __( 'Suspend an unused privileged account', 'bettershield' ),
				'description'     => __( 'Suspends one privileged account get-fix-targets lists for privileged_account_dormant, so it cannot sign in. Never the acting account, the last administrator, or an account recovery or alerts go to. Letting it back in takes a plan from propose-fix-undo.', 'bettershield' ),
				'target_type'     => 'account',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array( 'user_id' => $id ),
					'required'   => array( 'user_id' ),
				),
				'output'          => $account,
				'output_required' => array( 'user_id' ),
				'snapshot'        => array( self::class, 'dormant' ),
				'execute'         => array( self::class, 'do_dormant' ),
			),
			'hold-password'           => array(
				'propose'         => 'propose-password-reset',
				'label'           => __( 'Ask an account for a new password', 'bettershield' ),
				'description'     => __( 'Stops one account get-fix-targets lists for passwords_below_policy signing in with its current password and emails it a reset link. Never the acting account or the last administrator. Lifting the hold takes a plan from propose-fix-undo.', 'bettershield' ),
				'target_type'     => 'account',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array( 'user_id' => $id ),
					'required'   => array( 'user_id' ),
				),
				'output'          => $account,
				'output_required' => array( 'user_id' ),
				'snapshot'        => array( self::class, 'weak_password' ),
				'execute'         => array( self::class, 'do_weak_password' ),
			),
			'change-script-policy'    => array(
				'propose'         => 'propose-script-policy',
				'label'           => __( 'Change the script and content policy', 'bettershield' ),
				'description'     => __( 'Either starts enforcing the script and content policy under test (change: enforce), which can stop checkout or other pages loading something they need, or allows one source the policy reported (change: allow_source, with directive and source from get-fix-targets for csp_report_only), which widens it. Enforcing is taken back on the site; an allowed source is taken off with remove-script-source.', 'bettershield' ),
				'target_type'     => 'script_policy',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'change'    => array( 'type' => 'string', 'enum' => array( 'enforce', 'allow_source' ) ),
						'directive' => array( 'type' => 'string', 'maxLength' => 40 ),
						'source'    => array( 'type' => 'string', 'maxLength' => 300 ),
					),
					'required'   => array( 'change' ),
				),
				'output'          => array( 'change' => $string, 'note' => $string ),
				'output_required' => array( 'change' ),
				'snapshot'        => array( self::class, 'script_policy' ),
				'execute'         => array( self::class, 'do_script_policy' ),
			),
			'undo-fix'                => array(
				'propose'         => 'propose-fix-undo',
				// The way back is spent through revert-hardening; nothing registers this name.
				'undo_only'       => true,
				'label'           => __( 'Undo a fix', 'bettershield' ),
				'description'     => __( 'Describes taking back one fix these abilities or the dashboard made: scheduled events, a REST route, a folder’s permissions, a plugin update, a plugin or theme in quarantine, the admin rename, a suspension or a password hold. Each takes protection away again, so a person agrees to the plan and revert-hardening spends it with the same undo_token and the confirmation.', 'bettershield' ),
				'target_type'     => 'fix_undo',
				'input_schema'    => array(
					'type'       => 'object',
					'properties' => array( 'undo_token' => array( 'type' => 'string', 'pattern' => '^[a-f0-9]{32}$' ) ),
					'required'   => array( 'undo_token' ),
				),
				'output'          => array( 'undo_of' => $string ),
				'output_required' => array( 'undo_of' ),
				'snapshot'        => array( self::class, 'undo_needed' ),
				'execute'         => array( self::class, 'undo_needed' ),
				'undo_key'        => self::undo_keys(),
				'undo_snapshot'   => array( self::class, 'undo_snapshot' ),
				'undo_execute'    => array( self::class, 'undo_execute' ),
			),
		);
	}

	/** @return array{target: array<string, mixed>, effect: string[], reversible: bool, digest: string, object_id: string, changes_signing_in?: bool} */
	private static function live( string $object_id, array $target, array $effect, bool $reversible, array $state, bool $signs_in = false ): array {
		return array(
			'target'             => $target,
			'effect'             => $effect,
			'reversible'         => $reversible,
			'changes_signing_in' => $signs_in,
			// Who is asking and where, so a plan cannot be carried to another site or account.
			'digest'             => (string) Capture::digest( $state + array( 'actor' => get_current_user_id(), 'site' => get_current_blog_id(), 'object' => $object_id ) ),
			'object_id'          => $object_id,
		);
	}

	/** The say over code every site of a network runs, as the dashboard's routes ask for it. */
	public static function code_gate( bool $update_rights = true ): ?\WP_Error {
		$allowed = Permissions::shared_code( $update_rights );

		return true === $allowed ? null : $allowed;
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function plugin_update( array $input ) {
		$refused = self::gate() ?? self::code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$file = (string) ( $input['plugin'] ?? '' );
		$row  = null;

		if ( self::own_code( $file ) ) {
			return self::error( 'bettershield_self_update', __( 'BetterShield is updated on the site.', 'bettershield' ), 403 );
		}

		foreach ( PluginUpdates::state( 'plugin_updates_available' )['rows'] as $candidate ) {
			if ( $file === ( $candidate['file'] ?? null ) ) {
				$row = $candidate;
				break;
			}
		}

		if ( null === $row ) {
			return self::error( 'bettershield_no_update', __( 'WordPress offers no newer version of that plugin now.', 'bettershield' ), 409 );
		}

		if ( '' !== (string) $row['refused'] ) {
			return self::error( 'bettershield_update_refused', (string) $row['refused'], 409 );
		}

		$effect = array(
			/* translators: 1: plugin name, 2: installed version, 3: offered version. */
			sprintf( __( 'Updates %1$s from %2$s to %3$s, the version wordpress.org publishes.', 'bettershield' ), $row['name'], $row['version'], $row['offer'] ),
			__( 'The current version is kept first, so a later plan can put it back. Anything the new version changes in the database stays changed.', 'bettershield' ),
			__( 'New code can break the site. Read the site once the update has finished.', 'bettershield' ),
		);

		if ( is_multisite() ) {
			$effect[] = __( 'Plugins are shared: every site of the network runs the new version.', 'bettershield' );
		}

		return self::live(
			$file,
			array( 'plugin' => $file, 'name' => (string) $row['name'], 'from' => (string) $row['version'], 'to' => (string) $row['offer'] ),
			$effect,
			false,
			array( 'file' => $file, 'version' => $row['version'], 'offer' => $row['offer'] )
		);
	}

	public static function do_plugin_update( array $live ) {
		$done = PluginUpdates::update( (string) $live['target']['plugin'] );

		return is_wp_error( $done ) ? $done : array(
			'applied'    => true,
			'plugin'     => (string) $live['target']['plugin'],
			'name'       => (string) $done['name'],
			'from'       => (string) $done['from'],
			'to'         => (string) $done['to'],
			'undo_token' => (string) $done['undo'],
		);
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function extension( array $input ) {
		$refused = self::gate() ?? self::code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$kind = (string) ( $input['kind'] ?? '' );
		$id   = (string) ( $input['id'] ?? '' );
		$row  = null;

		foreach ( InactiveExtensions::state()['rows'] as $candidate ) {
			if ( $kind === $candidate['kind'] && $id === $candidate['id'] ) {
				$row = $candidate;
				break;
			}
		}

		if ( null === $row ) {
			return self::error( 'bettershield_not_dormant', __( 'That is not a deactivated plugin or unused theme the finding counts now.', 'bettershield' ), 409 );
		}

		if ( '' !== $row['refused'] ) {
			return self::error( 'bettershield_move_refused', (string) $row['refused'], 409 );
		}

		return self::live(
			$kind . ':' . $id,
			array( 'kind' => $kind, 'id' => $id, 'name' => (string) $row['name'] ),
			array(
				'theme' === $kind
					/* translators: %s: theme name. */
					? sprintf( __( 'Moves the unused theme %s into quarantine.', 'bettershield' ), $row['name'] )
					/* translators: %s: plugin name. */
					: sprintf( __( 'Moves the deactivated plugin %s into quarantine.', 'bettershield' ), $row['name'] ),
				__( 'It is not running, so the site behaves as before. Its files leave visitors’ reach.', 'bettershield' ),
				__( 'Putting it back is a plan of its own. It comes back deactivated, and can be refused if its folder has been reused since.', 'bettershield' ),
			),
			false,
			$row
		);
	}

	public static function do_extension( array $live ) {
		$done = InactiveExtensions::move( (string) $live['target']['kind'], (string) $live['target']['id'] );

		return is_wp_error( $done ) ? $done : array( 'applied' => true, 'undo_token' => (string) $done['undo'] ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function exposed_file( array $input ) {
		$refused = self::gate() ?? self::code_gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$kind  = (string) ( $input['kind'] ?? '' );
		$path  = (string) ( $input['path'] ?? '' );
		$last  = ExposedArtifacts::last() ?? array();
		$found = false;

		foreach ( (array) ( $last[ 'tool' === $kind ? 'tools' : 'exposed' ] ?? array() ) as $entry ) {
			if ( is_array( $entry ) && $path === ( $entry['path'] ?? null ) ) {
				$found = true;
				break;
			}
		}

		if ( ! $found ) {
			return self::error( 'bettershield_file_unknown', __( 'The last check did not find that file. Run the audit again.', 'bettershield' ), 404 );
		}

		return self::live(
			$kind . ':' . $path,
			array( 'kind' => $kind, 'path' => $path ),
			array(
				/* translators: %s: a path on the site. */
				sprintf( __( 'Moves %s, which anyone can download now, into quarantine.', 'bettershield' ), $path ),
				__( 'Anything that still links to it stops finding it.', 'bettershield' ),
				__( 'It is put back from the quarantine list on the site. There is no way back through an assistant.', 'bettershield' ),
			),
			false,
			array( 'kind' => $kind, 'path' => $path, 'checked_at' => (string) ( $last['checked_at'] ?? '' ) )
		);
	}

	public static function do_exposed_file( array $live ) {
		$path = (string) $live['target']['path'];
		$done = 'tool' === $live['target']['kind'] ? ExposedArtifacts::quarantine_tool( $path ) : ExposedArtifacts::quarantine_artifact( $path );

		return is_wp_error( $done ) ? $done : array( 'applied' => true ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function admin_rename( array $input ) {
		$refused = self::gate() ?? self::recovery();

		if ( null !== $refused ) {
			return $refused;
		}

		$state = AdminUsername::state();

		if ( null === $state['account'] ) {
			return self::error( 'bettershield_no_admin_account', __( 'No account is named admin now.', 'bettershield' ), 404 );
		}

		$id = (int) $state['account']['id'];

		// Its own sign-in is that person's to change, on the site.
		if ( $state['account']['you'] ) {
			return self::error( 'bettershield_own_account', __( 'The account named admin is the one this assistant acts as. Rename it on the site.', 'bettershield' ), 403 );
		}

		if ( '' !== $state['refused'] ) {
			return self::error( 'bettershield_account_refused', (string) $state['refused'], 403 );
		}

		$name    = (string) ( $input['username'] ?? '' );
		$invalid = AdminUsername::invalid( $name, $id );

		if ( '' !== $invalid ) {
			return self::error( 'bettershield_username_invalid', $invalid, 400 );
		}

		$label = ReadSurface::account_label( $id );

		return self::live(
			(string) $id,
			array( 'user_id' => $id, 'user_name' => $label, 'username' => $name ),
			array(
				__( 'Changes how one person signs in: the recovery link was verified within the day.', 'bettershield' ),
				/* translators: 1: an account's name, 2: the new username. */
				sprintf( __( 'Renames the username of %1$s from admin to %2$s. They sign in with the new username from now on; the password, sessions and email address stay.', 'bettershield' ), $label, $name ),
				is_multisite() ? __( 'On a network the username signs in on every site.', 'bettershield' ) : __( 'Tell them before it happens.', 'bettershield' ),
				__( 'Renaming it back to admin is a plan of its own.', 'bettershield' ),
			),
			true,
			array( 'id' => $id, 'username' => $name, 'posts' => (int) $state['account']['posts'] ),
			true
		);
	}

	public static function do_admin_rename( array $live ) {
		$done = AdminUsername::rename( (string) $live['target']['username'] );

		return is_wp_error( $done ) ? $done : array( 'applied' => true, 'undo_token' => (string) $done['undo'] ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function app_password( array $input ) {
		$refused = self::gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$key = (string) ( $input['password'] ?? '' );
		$row = null;

		foreach ( StalePasswords::state()['passwords'] as $candidate ) {
			if ( $key === $candidate['key'] ) {
				$row = $candidate;
				break;
			}
		}

		if ( null === $row ) {
			return self::error( 'bettershield_none_listed', __( 'That application password is not on the list of unused ones now.', 'bettershield' ), 409 );
		}

		if ( '' !== $row['refused'] ) {
			return self::error( 'bettershield_account_refused', (string) $row['refused'], 403 );
		}

		$calling = function_exists( 'rest_get_authenticated_app_password' ) ? rest_get_authenticated_app_password() : null;

		if ( is_string( $calling ) && $calling === $row['uuid'] ) {
			return self::error( 'bettershield_calling_credential', __( 'That is the credential making this request. Revoke it on the site.', 'bettershield' ), 403 );
		}

		$label = ReadSurface::account_label( (int) $row['user_id'] );

		return self::live(
			$key,
			array( 'password' => $key, 'user_id' => (int) $row['user_id'], 'user_name' => $label, 'name' => (string) $row['name'] ),
			array(
				/* translators: 1: application password name, 2: an account's name, 3: number of days. */
				sprintf( __( 'Revokes the application password "%1$s" of %2$s, unused for %3$d days. Anything still using it stops working.', 'bettershield' ), $row['name'], $label, (int) $row['days'] ),
				__( 'This cannot be undone. A new application password is created on the site.', 'bettershield' ),
			),
			false,
			array( 'key' => $key, 'days' => (int) $row['days'], 'used' => (bool) $row['used'] )
		);
	}

	public static function do_app_password( array $live ) {
		$done = StalePasswords::revoke( array( (string) $live['target']['password'] ) );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( array() === $done['revoked'] ) {
			return self::error( 'bettershield_revoke_refused', (string) ( $done['refused'][0]['reason'] ?? __( 'It could not be revoked.', 'bettershield' ) ), 409 );
		}

		return array( 'applied' => true ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function dormant( array $input ) {
		$refused = self::gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$id  = (int) ( $input['user_id'] ?? 0 );
		$row = null;

		foreach ( DormantAccounts::state()['accounts'] as $candidate ) {
			if ( $id === (int) $candidate['id'] ) {
				$row = $candidate;
				break;
			}
		}

		if ( null === $row ) {
			return self::error( 'bettershield_none_listed', __( 'That account is not on the list of unused privileged accounts now.', 'bettershield' ), 409 );
		}

		if ( '' !== $row['refused'] ) {
			return self::error( 'bettershield_account_refused', (string) $row['refused'], 403 );
		}

		$label = ReadSurface::account_label( $id );
		unset( $row['login'] );

		return self::live(
			(string) $id,
			array( 'user_id' => $id, 'user_name' => $label ),
			array(
				/* translators: %s: an account's name. */
				sprintf( __( 'Suspends %s, a privileged account nobody has used for a long time. It cannot sign in until the suspension is lifted.', 'bettershield' ), $label ),
				__( 'Letting it back in is a plan of its own.', 'bettershield' ),
			),
			true,
			$row
		);
	}

	public static function do_dormant( array $live ) {
		$done = DormantAccounts::suspend( array( (int) $live['target']['user_id'] ) );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( array() === $done['suspended'] ) {
			return self::error( 'bettershield_suspend_refused', (string) ( $done['refused'][0]['reason'] ?? __( 'It could not be suspended.', 'bettershield' ) ), 409 );
		}

		return array( 'applied' => true, 'undo_token' => (string) $done['suspended'][0]['undo'] ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function weak_password( array $input ) {
		$refused = self::gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$id  = (int) ( $input['user_id'] ?? 0 );
		$row = null;

		foreach ( WeakPasswords::state()['accounts'] as $candidate ) {
			if ( $id === (int) $candidate['id'] ) {
				$row = $candidate;
				break;
			}
		}

		if ( null === $row ) {
			return self::error( 'bettershield_none_listed', __( 'That account is not on the list of passwords below the policy now.', 'bettershield' ), 409 );
		}

		if ( '' !== $row['refused'] ) {
			return self::error( 'bettershield_account_refused', (string) $row['refused'], 403 );
		}

		$label = ReadSurface::account_label( $id );

		return self::live(
			(string) $id,
			array( 'user_id' => $id, 'user_name' => $label ),
			array(
				/* translators: %s: an account's name. */
				sprintf( __( 'Stops %s signing in with its current password and emails the account a reset link.', 'bettershield' ), $label ),
				__( 'Lifting the hold, so the old password works again, is a plan of its own.', 'bettershield' ),
			),
			true,
			array( 'id' => $id, 'privileged' => (bool) $row['privileged'] )
		);
	}

	public static function do_weak_password( array $live ) {
		$done = WeakPasswords::hold( array( (int) $live['target']['user_id'] ) );

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( array() === $done['held'] ) {
			return self::error( 'bettershield_hold_refused', (string) ( $done['refused'][0]['reason'] ?? __( 'It could not be held.', 'bettershield' ) ), 409 );
		}

		return array( 'applied' => true, 'undo_token' => (string) ( $done['held'][0]['undo'] ?? '' ) ) + $live['target'];
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function script_policy( array $input ) {
		$refused = self::gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$manager = Manager::instance();

		if ( ! $manager->is_active( 'csp_report_only' ) ) {
			return self::error( 'bettershield_not_active', __( 'The script and content policy is not on.', 'bettershield' ), 409 );
		}

		$change = (string) ( $input['change'] ?? '' );
		$state  = $manager->item_state( 'csp_report_only' );
		$mode   = ContentSecurityPolicy::mode( $state );
		$base   = array( 'change' => $change, 'mode' => $mode, 'allowed' => ContentSecurityPolicy::allowed_sources() );

		if ( 'enforce' === $change ) {
			if ( ContentSecurityPolicy::MODE_ENFORCING === $mode ) {
				return self::error( 'bettershield_already_enforcing', __( 'The policy is enforced already.', 'bettershield' ), 409 );
			}

			$ready = ContentSecurityPolicy::promotable( false );

			if ( ! $ready['ready'] ) {
				return self::error( 'bettershield_csp_not_ready', (string) $ready['reason'], 409 );
			}

			return self::live(
				'csp_report_only:enforce',
				array( 'change' => 'enforce' ),
				array(
					__( 'Starts enforcing the script and content policy under test. Anything it blocks stops loading for every visitor, on checkout too.', 'bettershield' ),
					/* translators: %d: number of days nothing was reported. */
					sprintf( __( 'Nothing has been reported for %d days.', 'bettershield' ), (int) $ready['quiet_days'] ),
					__( 'Back to Test Mode on the site takes it back.', 'bettershield' ),
				),
				false,
				$base
			);
		}

		$directive = strtolower( trim( (string) ( $input['directive'] ?? '' ) ) );
		$source    = strtolower( trim( (string) ( $input['source'] ?? '' ) ) );
		$reported  = false;

		foreach ( ContentSecurityPolicy::reports() as $row ) {
			if ( $directive === strtolower( (string) ( $row['directive'] ?? '' ) ) && $source === strtolower( (string) ( $row['blocked'] ?? '' ) ) ) {
				$reported = true;
				break;
			}
		}

		if ( 'allow_source' !== $change || '' === $directive || '' === $source || ! $reported ) {
			return self::error( 'bettershield_csp_not_reported', __( 'Name a directive and source the policy reported, as get-fix-targets lists them.', 'bettershield' ), 409 );
		}

		return self::live(
			'csp_report_only:allow:' . $directive . ' ' . $source,
			array( 'change' => 'allow_source', 'directive' => $directive, 'source' => $source ),
			array(
				/* translators: 1: an address such as https://example.com, 2: a policy directive. */
				sprintf( __( 'Allows %1$s for %2$s. This widens the policy: anything loaded from there is no longer reported or blocked.', 'bettershield' ), $source, $directive ),
				__( 'The 7-day quiet period starts over. remove-script-source takes it off again.', 'bettershield' ),
			),
			true,
			$base + array( 'directive' => $directive, 'source' => $source )
		);
	}

	public static function do_script_policy( array $live ) {
		$target = $live['target'];
		$args   = 'allow_source' === $target['change'] ? array( 'directive' => (string) $target['directive'], 'source' => (string) $target['source'] ) : array();
		$done   = Manager::instance()->act( 'csp_report_only', (string) $target['change'], $args );

		return is_wp_error( $done ) ? $done : array( 'applied' => true, 'change' => (string) $target['change'], 'note' => (string) ( $done['note'] ?? '' ) );
	}

	/** propose-fix-undo plans only the way back. */
	public static function undo_needed() {
		return self::error( 'bettershield_fix_input', __( 'Name the undo_token a fix returned.', 'bettershield' ), 400 );
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function undo_snapshot( array $input ) {
		$refused = self::gate();

		if ( null !== $refused ) {
			return $refused;
		}

		$token = (string) ( $input['undo_token'] ?? '' );
		$entry = 1 === preg_match( '/^[a-f0-9]{32}$/D', $token ) ? Ledger::find( $token ) : null;
		$key   = null === $entry ? '' : (string) $entry->action_key;

		if ( null === $entry || ! in_array( $key, self::undo_keys(), true ) ) {
			return self::error( 'bettershield_unknown_undo', __( 'That change is not one this site recorded.', 'bettershield' ), 404 );
		}

		if ( null !== $entry->reverted_at ) {
			return self::error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), 409 );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$applied = is_array( $entry->applied_state ) ? $entry->applied_state : array();

		if ( PluginUpdates::ACTION === $key && self::own_code( (string) ( $prior['plugin'] ?? '' ) ) ) {
			return self::error( 'bettershield_self_update', __( 'BetterShield is updated on the site.', 'bettershield' ), 403 );
		}

		// Its own sign-in is the requester's to change, on the site.
		if ( AdminUsername::ACTION === $key && (int) ( $prior['user'] ?? 0 ) === get_current_user_id() ) {
			return self::error( 'bettershield_own_account', __( 'That rename was of the account this assistant acts as. Rename it back on the site.', 'bettershield' ), 403 );
		}

		// Only the weak-password fix's hold: an incident response's hold is lifted on the site.
		if ( PasswordHold::KEY === $key && WeakPasswords::WHY !== ( $prior['why'] ?? '' ) ) {
			return self::error( 'bettershield_unknown_undo', __( 'That hold was placed by an incident response. Lift it on the site.', 'bettershield' ), 403 );
		}

		if ( in_array( $key, array( WorldWritable::ACTION, PluginUpdates::ACTION, InactiveExtensions::ACTION ), true ) ) {
			$refused = self::code_gate();
		} elseif ( AdminUsername::ACTION === $key ) {
			$refused = self::recovery();
		}

		if ( null !== $refused ) {
			return $refused;
		}

		$signs_in = AdminUsername::ACTION === $key;
		$user     = ReadSurface::account_label( (int) ( $prior['user'] ?? 0 ) );
		$effects  = array(
			ScheduledEvents::ACTION    => array( 'scheduled_events', sprintf( /* translators: %s: hook names. */ __( 'Schedules the removed runs of %s again. Nothing on the site answers them now.', 'bettershield' ), implode( ', ', array_map( 'strval', (array) ( $applied['removed'] ?? array() ) ) ) ) ),
			RestRoutes::ACTION         => array( 'rest_route', sprintf( /* translators: %s: a REST route. */ __( 'Stops watching %s and lets anyone read it again, without signing in.', 'bettershield' ), (string) ( $prior['route'] ?? '' ) ) ),
			WorldWritable::ACTION      => array( 'folder_mode', sprintf( /* translators: %s: a folder name. */ __( 'Gives %s its earlier permissions back, so anyone on the server may write to it again.', 'bettershield' ), (string) ( $prior['name'] ?? '' ) ) ),
			PluginUpdates::ACTION      => array( 'plugin_update', __( 'Installs the version this plugin had before the update again. That older version may be the one an advisory names.', 'bettershield' ) ),
			InactiveExtensions::ACTION => array( 'extension', __( 'Puts the plugin or theme back where it was, deactivated, and within visitors’ reach again.', 'bettershield' ) ),
			AdminUsername::ACTION      => array( 'admin_rename', sprintf( /* translators: %s: an account's name. */ __( 'Changes how one person signs in: renames %s back to admin, the username most often guessed.', 'bettershield' ), $user ) ),
			DormantAccounts::ACTION    => array( 'account_suspension', sprintf( /* translators: %s: an account's name. */ __( 'Lets %s sign in again.', 'bettershield' ), $user ) ),
			PasswordHold::KEY          => array( 'password_hold', sprintf( /* translators: %s: an account's name. */ __( 'Lets %s sign in with the password the policy flagged again.', 'bettershield' ), $user ) ),
		);

		return self::live(
			$key . ':' . substr( hash( 'sha256', $token ), 0, 16 ),
			array( 'undo_of' => $effects[ $key ][0] ),
			array( $effects[ $key ][1], __( 'This takes protection away again, so it waits for a person.', 'bettershield' ) ),
			false,
			array( 'token' => hash( 'sha256', $token ), 'key' => $key, 'applied' => $applied ),
			$signs_in
		) + array( 'token' => $token, 'key' => $key );
	}

	/** @return array<string, mixed>|\WP_Error */
	public static function undo_execute( array $live ) {
		$token = (string) $live['token'];

		switch ( $live['key'] ) {
			case ScheduledEvents::ACTION:
				$done = ScheduledEvents::undo( $token );
				break;
			case RestRoutes::ACTION:
				$done = RestRoutes::undo( $token );
				break;
			case WorldWritable::ACTION:
				$done = WorldWritable::undo( $token );
				break;
			case PluginUpdates::ACTION:
				$done = PluginUpdates::undo( $token );
				break;
			case InactiveExtensions::ACTION:
				$done = InactiveExtensions::put_back( $token );
				break;
			case AdminUsername::ACTION:
				$done = AdminUsername::undo( $token );
				break;
			case DormantAccounts::ACTION:
				$done = DormantAccounts::lift( $token );
				break;
			default:
				$done = WeakPasswords::undo( $token );
		}

		return is_wp_error( $done ) ? $done : array(
			'reverted'    => true,
			'target'      => (string) $live['object_id'],
			'target_type' => (string) $live['target']['undo_of'],
			'notes'       => array(),
		);
	}

	private static function recovery(): ?\WP_Error {
		return Registrar::recovery_ready() ? null : self::error( 'bettershield_recovery_unverified', __( 'A change to how somebody signs in waits for a recovery link verified within the last day. Run run-recovery-check, or set the link up on the site.', 'bettershield' ), 409 );
	}

	/* ---- the read -------------------------------------------------------- */

	public static function read_definition( array $meta, callable $audit ): array {
		$string = array( 'type' => 'string' );

		return array(
			'bettershield/get-fix-targets' => array( 'permission_callback' => array( Registrar::class, 'can_manage' ) ) + $meta + array(
				'label'            => __( 'List what a finding’s fix would act on', 'bettershield' ),
				'description'      => __( 'For one finding, the things its fix names: scheduled hooks, REST routes, folders, protections, mail and certificate records to publish, plugin updates, unused plugins and themes, downloadable files, accounts and application passwords, or the script policy’s reported and allowed sources. Accounts are named by display name and id, never by login. At most fifty rows, with the total. Reads only; the same management permission the dashboard asks for.', 'bettershield' ),
				'input_schema'     => array(
					'type'       => 'object',
					'properties' => array( 'finding' => array( 'type' => 'string', 'enum' => self::TARGETS ) ),
					'required'   => array( 'finding' ),
				),
				'output_schema'    => array(
					'type'       => 'object',
					'properties' => array(
						'finding'   => $string,
						'total'     => array( 'type' => 'integer', 'minimum' => 0 ),
						'truncated' => array( 'type' => 'boolean' ),
						'targets'   => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'      => $string,
									'label'   => $string,
									'detail'  => $string,
									'refused' => $string,
								),
								'required'   => array( 'id', 'label' ),
							),
						),
					),
					'required'   => array( 'finding', 'total', 'truncated', 'targets' ),
				),
				'execute_callback' => static function ( $input ) use ( $audit ) {
					$audit( 'bettershield/get-fix-targets', $input );

					if ( ! Registrar::can_manage() ) {
						return self::error( 'bettershield_read_denied', __( 'Reading this needs the permission that manages BetterShield.', 'bettershield' ), 403 );
					}

					$finding = is_array( $input ) ? (string) ( $input['finding'] ?? '' ) : '';

					return in_array( $finding, self::TARGETS, true ) ? self::targets( $finding ) : self::error( 'bettershield_fix_input', __( 'Name a finding this read lists.', 'bettershield' ), 400 );
				},
			),
		);
	}

	/** @return array{finding: string, total: int, truncated: bool, targets: array<int, array<string, string>>} */
	public static function targets( string $finding ): array {
		$rows   = array();
		$people = current_user_can( 'list_users' );

		switch ( $finding ) {
			case 'cron_events_unanswered':
				foreach ( (array) ( Cron::report()['events'] ?? array() ) as $event ) {
					$rows[] = self::row( (string) ( $event['hook'] ?? '' ), (string) ( $event['hook'] ?? '' ) );
				}
				break;
			case 'rest_surface_unreviewed':
				foreach ( RestRoutes::describe( RestRoutes::named() ) as $route ) {
					$rows[] = self::row( (string) $route['route'], (string) $route['route'], (string) $route['state'] . ( '' !== (string) $route['closable_at'] ? ' ' . $route['closable_at'] : '' ), $route['offered'] ? '' : __( 'BetterShield leaves this route open.', 'bettershield' ) );
				}
				break;
			case 'content_dirs_world_writable':
				foreach ( WorldWritable::state()['folders'] as $folder ) {
					$rows[] = self::row( $folder['name'], $folder['name'], $folder['mode'] . ' → ' . $folder['proposed'], $folder['refused'] );
				}
				break;
			case 'hardening_not_working':
				foreach ( ProtectionRepair::state()['items'] as $item ) {
					$rows[] = self::row( $item['id'], $item['title'], $item['reason'], $item['signs_in'] ? __( 'Applied again on the site.', 'bettershield' ) : '' );
				}
				break;
			case 'domain_mail_records':
				foreach ( DomainMailRecords::state()['records'] as $record ) {
					$rows[] = self::row( (string) ( $record['family'] ?? '' ), (string) ( $record['type'] ?? '' ) . ' ' . (string) ( $record['host'] ?? '' ), (string) ( $record['value'] ?? '' ), (string) ( $record['refused'] ?? '' ) );
				}
				break;
			case 'plugin_updates_available':
			case 'vulnerabilities_known':
				foreach ( PluginUpdates::state( $finding )['rows'] as $row ) {
					if ( self::own_code( (string) $row['file'] ) ) {
						continue;
					}

					$rows[] = self::row( (string) $row['file'], (string) $row['name'], trim( $row['version'] . ' → ' . $row['offer'] . ( '' !== (string) ( $row['fixed_in'] ?? '' ) ? ' (fixed in ' . $row['fixed_in'] . ')' : '' ) ), (string) $row['refused'] );
				}
				break;
			case 'inactive_extensions':
				foreach ( InactiveExtensions::state()['rows'] as $row ) {
					$rows[] = self::row( $row['id'], $row['name'], $row['kind'], $row['refused'] );
				}
				break;
			case 'leftover_tools_reachable':
			case 'artifacts_downloadable':
				$last = ExposedArtifacts::last() ?? array();

				foreach ( (array) ( $last[ 'leftover_tools_reachable' === $finding ? 'tools' : 'exposed' ] ?? array() ) as $entry ) {
					if ( is_array( $entry ) && isset( $entry['path'] ) ) {
						$rows[] = self::row( (string) $entry['path'], (string) $entry['path'] );
					}
				}
				break;
			case 'admin_username_exists':
				$state = AdminUsername::state();

				if ( $people && null !== $state['account'] ) {
					$id     = (int) $state['account']['id'];
					$rows[] = self::row( (string) $id, ReadSurface::account_label( $id ), '', $state['account']['you'] ? __( 'The account this request acts as.', 'bettershield' ) : (string) $state['refused'] );
				}
				break;
			case 'application_passwords_stale':
				foreach ( $people ? StalePasswords::state()['passwords'] : array() as $row ) {
					$rows[] = self::row(
						(string) $row['key'],
						ReadSurface::account_label( (int) $row['user_id'] ) . ' · ' . $row['name'],
						/* translators: %d: days an application password has gone unused. */
						sprintf( _n( 'Unused for %d day', 'Unused for %d days', (int) $row['days'], 'bettershield' ), (int) $row['days'] ),
						(string) $row['refused']
					);
				}
				break;
			case 'privileged_account_dormant':
				foreach ( $people ? DormantAccounts::state()['accounts'] : array() as $row ) {
					$rows[] = self::row( (string) $row['id'], ReadSurface::account_label( (int) $row['id'] ), '', (string) $row['refused'] );
				}
				break;
			case 'passwords_below_policy':
				foreach ( $people ? WeakPasswords::state()['accounts'] : array() as $row ) {
					$rows[] = self::row( (string) $row['id'], ReadSurface::account_label( (int) $row['id'] ), $row['privileged'] ? __( 'Privileged', 'bettershield' ) : '', (string) $row['refused'] );
				}
				break;
			case 'csp_report_only':
				foreach ( ContentSecurityPolicy::reports() as $row ) {
					$rows[] = self::row( 'reported:' . (string) ( $row['directive'] ?? '' ) . ' ' . (string) ( $row['blocked'] ?? '' ), (string) ( $row['blocked'] ?? '' ), (string) ( $row['directive'] ?? '' ) . ' · ' . __( 'reported', 'bettershield' ), (string) ( $row['allow']['refused'] ?? '' ) );
				}

				foreach ( ContentSecurityPolicy::allowed_sources() as $row ) {
					$rows[] = self::row( 'allowed:' . $row['directive'] . ' ' . $row['source'], $row['source'], $row['directive'] . ' · ' . __( 'allowed', 'bettershield' ) );
				}
				break;
		}

		return array(
			'finding'   => $finding,
			'total'     => count( $rows ),
			'truncated' => count( $rows ) > self::MAX_TARGETS,
			'targets'   => array_slice( $rows, 0, self::MAX_TARGETS ),
		);
	}

	/** Site-supplied text, bounded: hook names, routes and labels are data, never instructions. */
	private static function row( string $id, string $label, string $detail = '', string $refused = '' ): array {
		$clip = static fn( string $text ): string => mb_substr( wp_strip_all_tags( $text ), 0, 300 );

		return array(
			'id'      => $clip( $id ),
			'label'   => $clip( $label ),
			'detail'  => $clip( $detail ),
			'refused' => $clip( $refused ),
		);
	}

	public static function error( string $code, string $message, int $status ): \WP_Error {
		return new \WP_Error( $code, $message, array( 'status' => $status ) );
	}
}
