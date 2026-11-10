<?php
/**
 * What the registered abilities were, and what an update changed (#1878).
 *
 * Agents › Surface shows the abilities registered now. An update that
 * registers a new write ability, or loosens who may call an existing one,
 * made a new tool reachable to every connected assistant and recorded
 * nothing. A baseline of each ability (who registered it, whether it says it
 * only reads, whether REST reaches it, and whether a subscriber passes its
 * permission check) is kept, and compared after a plugin or theme is
 * updated or activated, and once a day:
 *
 * - `ability_added`: a new ability that writes. High where a non-
 *   administrator can call it over REST, medium otherwise.
 * - `ability_widened`: one that said it only reads and now writes, or that
 *   a subscriber is now let through. High where that leaves a write a
 *   non-administrator can call over REST.
 *
 * Each change is recorded once and waits under "New since the last update"
 * until the owner accepts it, which takes the abilities as they are now as
 * the baseline and is logged. Nothing is blocked or unregistered.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Abilities;

use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Baseline {

	/** The abilities as last accepted. Not autoloaded: read only by these checks. */
	public const OPTION = 'bettershield_ability_baseline';

	/** The changes waiting for the owner, by ability name. */
	public const CHANGES_OPTION = 'bettershield_ability_changes';

	/** The task that compares, daily and soon after an update or activation. */
	public const TASK = 'bettershield_ability_review';

	/** The undo ledger's key for an accept. */
	public const ACCEPT_ACTION = 'ability_changes_accept';

	public static function register(): void {
		add_action( 'upgrader_process_complete', array( self::class, 'soon' ), 20, 0 );
		add_action( 'activated_plugin', array( self::class, 'soon' ), 20, 0 );
	}

	/**
	 * Compare on a later request, once the new code is the code that loads.
	 */
	public static function soon(): void {
		if ( false === wp_next_scheduled( self::TASK, array( 'soon' ) ) ) {
			wp_schedule_single_event( time() + 30, self::TASK, array( 'soon' ) );
		}
	}

	/**
	 * The abilities now, as the baseline keeps them.
	 *
	 * @return array<string, array{owner: string, readonly: bool, rest: bool, open: bool}>
	 */
	public static function snapshot(): array {
		$out = array();

		foreach ( AgentSurface::abilities() as $row ) {
			// This plugin's own abilities come and go with its own switches
			// for agent reading and writing, which are the owner's choice,
			// not an update's: turning them on is not news.
			if ( str_starts_with( (string) $row['name'], 'bettershield/' ) ) {
				continue;
			}

			$out[ (string) $row['name'] ] = array(
				'owner'    => (string) $row['registering_source'],
				'readonly' => (bool) $row['annotated_readonly'],
				'rest'     => (bool) $row['exposed_in_rest'],
				'open'     => AgentSurface::ACCESS_ALLOWED === $row['low_privilege_access'],
			);
		}

		ksort( $out );

		return $out;
	}

	/**
	 * Compare the abilities now with the baseline, and record what is new.
	 * The first run, with no baseline yet, only takes one.
	 *
	 * @return array<string, array<string, mixed>> The changes waiting now.
	 */
	public static function review(): array {
		if ( ! Registrar::is_available() ) {
			return array();
		}

		$now      = self::snapshot();
		$baseline = get_option( self::OPTION, null );

		if ( ! is_array( $baseline ) ) {
			update_option( self::OPTION, $now, false );

			return array();
		}

		$waiting = self::changes();

		foreach ( $now as $name => $ability ) {
			$was    = $baseline[ $name ] ?? null;
			$change = self::change( $was, $ability );
			$kind   = $change;

			if ( null === $change ) {
				continue;
			}

			// Already waiting as this change: news again only where it has
			// opened wider since it was recorded, which keeps its place in
			// the list and is recorded as widened.
			if ( ( $waiting[ $name ]['kind'] ?? '' ) === $change ) {
				if ( ! self::wider_than( $waiting[ $name ], $ability ) ) {
					continue;
				}

				$kind = 'widened';
			}

			$high = ! $ability['readonly'] && $ability['rest'] && $ability['open'];

			$waiting[ $name ] = array(
				'kind'     => $change,
				'owner'    => $ability['owner'],
				'readonly' => $ability['readonly'],
				'rest'     => $ability['rest'],
				'open'     => $ability['open'],
				'at'       => gmdate( 'c' ),
			);

			Writer::instance()->record(
				'added' === $kind ? 'ability_added' : 'ability_widened',
				$high ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'system',
					'object_type' => 'ability',
					'object_id'   => $name,
					'context'     => array(
						'owner'    => $ability['owner'],
						'readonly' => $ability['readonly'],
						'open'     => $ability['open'],
					),
				)
			);
		}

		update_option( self::CHANGES_OPTION, $waiting, false );

		return $waiting;
	}

	/**
	 * What changed about one ability that is worth telling the owner, or
	 * null. A new read-only ability, and anything narrowed, is not.
	 *
	 * @param array<string, mixed>|null $was
	 * @param array<string, mixed>      $now
	 */
	public static function change( ?array $was, array $now ): ?string {
		if ( null === $was ) {
			return $now['readonly'] ? null : 'added';
		}

		$writes_now  = ! $now['readonly'] && ! empty( $was['readonly'] );
		$opened_now  = $now['open'] && empty( $was['open'] );

		return $writes_now || ( $opened_now && ! $now['readonly'] ) ? 'widened' : null;
	}

	/**
	 * Whether an ability opened wider than a waiting change says it was:
	 * it now writes, a subscriber is now let through, or REST now reaches it.
	 *
	 * @param array<string, mixed> $waiting
	 * @param array<string, mixed> $now
	 */
	private static function wider_than( array $waiting, array $now ): bool {
		return ( ! $now['readonly'] && ! empty( $waiting['readonly'] ) )
			|| ( $now['open'] && empty( $waiting['open'] ) )
			|| ( $now['rest'] && array_key_exists( 'rest', $waiting ) && empty( $waiting['rest'] ) );
	}

	/**
	 * The changes waiting for the owner, each with its plugin's name.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function changes(): array {
		$stored = get_option( self::CHANGES_OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * The waiting changes for the screen, newest first.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function described(): array {
		$out = array();

		foreach ( self::changes() as $name => $change ) {
			$out[] = array(
				'name'        => (string) $name,
				'kind'        => (string) ( $change['kind'] ?? '' ),
				'owner_label' => AgentSurface::source_label( (string) ( $change['owner'] ?? '' ) ),
				'readonly'    => (bool) ( $change['readonly'] ?? false ),
				'open'        => (bool) ( $change['open'] ?? false ),
				'at'          => (string) ( $change['at'] ?? '' ),
			);
		}

		usort( $out, static fn( array $a, array $b ): int => strcmp( $b['at'], $a['at'] ) );

		return $out;
	}

	/**
	 * Take the abilities as they are now as the baseline, and clear what was
	 * waiting. Logged, since it is the owner saying these are expected, and
	 * kept in the undo ledger first, so the changes can be brought back.
	 *
	 * @return array{accepted: int, undo: string}|\WP_Error
	 */
	public static function accept() {
		$changes  = self::changes();
		$count    = count( $changes );
		$snapshot = self::snapshot();
		$prior    = get_option( self::OPTION, null );

		$token = Ledger::open(
			self::ACCEPT_ACTION,
			array(
				'baseline' => is_array( $prior ) ? $prior : null,
				'changes'  => $changes,
			),
			array( 'baseline' => $snapshot )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		update_option( self::OPTION, $snapshot, false );
		update_option( self::CHANGES_OPTION, array(), false );

		Writer::instance()->record(
			'ability_changes_accepted',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'ability',
				'object_id'   => (string) $count,
				'context'     => array(
					'accepted' => $count,
					'undo'     => $token,
				),
			)
		);

		return array(
			'accepted' => $count,
			'undo'     => $token,
		);
	}

	/**
	 * Undo an accept: the baseline and the waiting changes go back to what
	 * they were, so the changes wait for the owner again.
	 *
	 * @return array{restored: int}|\WP_Error
	 */
	public static function undo_accept( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::ACCEPT_ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior   = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$changes = is_array( $prior['changes'] ?? null ) ? $prior['changes'] : array();

		if ( is_array( $prior['baseline'] ?? null ) ) {
			update_option( self::OPTION, $prior['baseline'], false );
		} else {
			delete_option( self::OPTION );
		}

		// Anything recorded since the accept stays waiting beside them.
		update_option( self::CHANGES_OPTION, self::changes() + $changes, false );

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'ability_changes_accept_undone',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'ability',
				'object_id'   => (string) count( $changes ),
				'context'     => array( 'restored' => count( $changes ) ),
			)
		);

		return array( 'restored' => count( $changes ) );
	}
}
