<?php
/**
 * Fix for "Something is scheduled that no code answers" (#1952).
 *
 * The hooks the finding names, removed from the schedule in one step, each
 * kept first so undo can put it back as it was. WordPress has no screen for
 * its schedule, so without this the owner's only ways were a cron plugin or
 * WP-CLI.
 *
 * Before anything is unscheduled, every scheduled run of the chosen hooks
 * goes into one undo record: its hook, arguments, next run and recurrence.
 * Undo schedules each again exactly, on its old schedule. Only hooks the
 * finding names can be removed: the request names hooks, and they are
 * matched against what the check finds now rather than trusted.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Cron;
use BetterShield\Events\Writer;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScheduledEvents {

	public const ACTION = 'cron_events_removed';

	/**
	 * Remove every scheduled run of the chosen hooks, kept for undo first.
	 *
	 * @param string[] $hooks
	 * @return array{removed: string[], undo: string}|\WP_Error
	 */
	public static function remove( array $hooks ) {
		$chosen = self::chosen( $hooks );

		if ( is_wp_error( $chosen ) ) {
			return $chosen;
		}

		$events = self::runs( $chosen );

		// Kept before anything is removed: no record, no change.
		$token = Ledger::open( self::ACTION, array( 'events' => $events ), array( 'removed' => $chosen ) );

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$removed = array();

		foreach ( $events as $event ) {
			if ( true === wp_unschedule_event( $event['at'], $event['hook'], $event['args'] ) ) {
				$removed[ $event['hook'] ] = true;
			}
		}

		// Only the hooks that actually came off are said to have.
		$chosen = array_values( array_intersect( $chosen, array_keys( $removed ) ) );

		Writer::instance()->record(
			'cron_events_removed',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'cron',
				'object_id'   => implode( ', ', $chosen ),
				'context'     => array(
					'hooks' => $chosen,
					'undo'  => $token,
				),
			)
		);

		Auditor::run();

		return array(
			'removed' => $chosen,
			'undo'    => $token,
		);
	}

	/**
	 * The named hooks the check finds with nothing to answer them now.
	 *
	 * @param string[] $hooks
	 * @return string[]|\WP_Error
	 */
	public static function chosen( array $hooks ) {
		$named  = array_column( Cron::report()['events'], 'hook' );
		$chosen = array_values( array_intersect( $named, array_map( 'strval', $hooks ) ) );

		if ( array() === $chosen ) {
			return new \WP_Error( 'bettershield_no_events', __( 'None of those is scheduled with nothing to answer it now, so nothing was removed.', 'bettershield' ), array( 'status' => 409 ) );
		}

		return $chosen;
	}

	/**
	 * Every scheduled run of these hooks.
	 *
	 * @param string[] $hooks
	 * @return array<int, array{hook: string, at: int, args: array<mixed>, schedule: string, interval: int}>
	 */
	public static function runs( array $hooks ): array {
		$events = array();

		foreach ( _get_cron_array() as $timestamp => $scheduled ) {
			foreach ( (array) $scheduled as $hook => $instances ) {
				if ( ! in_array( (string) $hook, $hooks, true ) ) {
					continue;
				}

				foreach ( (array) $instances as $instance ) {
					$events[] = array(
						'hook'     => (string) $hook,
						'at'       => (int) $timestamp,
						// As stored: core keys a run by its serialized arguments,
						// so renumbering named ones would name a run that is not there.
						'args'     => (array) ( $instance['args'] ?? array() ),
						'schedule' => (string) ( $instance['schedule'] ?? '' ),
						'interval' => (int) ( $instance['interval'] ?? 0 ),
					);
				}
			}
		}

		return $events;
	}

	/**
	 * The removals undo can still put back: each open record with the hooks
	 * of it that are not scheduled again since. A record whose every run is
	 * back has nothing left to undo, so it is not listed.
	 *
	 * @return array<int, array{hooks: string[], undo: string}>
	 */
	public static function open_removals(): array {
		$open = array();

		foreach ( Ledger::open_token_page( self::ACTION, PHP_INT_MAX, 10 ) as $token ) {
			$entry   = Ledger::find( $token );
			$prior   = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : array();
			$missing = array();

			foreach ( (array) ( $prior['events'] ?? array() ) as $event ) {
				$hook = (string) ( $event['hook'] ?? '' );

				if ( '' !== $hook && (int) ( $event['at'] ?? 0 ) > 0 && false === wp_next_scheduled( $hook, (array) ( $event['args'] ?? array() ) ) ) {
					$missing[ $hook ] = true;
				}
			}

			if ( array() === $missing ) {
				continue;
			}

			$open[] = array(
				'hooks' => array_keys( $missing ),
				'undo'  => $token,
			);
		}

		return $open;
	}

	/**
	 * Schedule every removed run again, as it was. A run scheduled again
	 * since is left as it is rather than doubled.
	 *
	 * @return array{restored: int}|\WP_Error
	 */
	public static function undo( string $token ) {
		$entry = Ledger::find( $token );

		if ( null === $entry || self::ACTION !== (string) $entry->action_key ) {
			return new \WP_Error( 'bettershield_unknown_token', __( 'No undo record exists for that change.', 'bettershield' ), array( 'status' => 404 ) );
		}

		if ( null !== $entry->reverted_at ) {
			return new \WP_Error( 'bettershield_already_reverted', __( 'That change has already been undone.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior     = is_array( $entry->prior_state ) ? $entry->prior_state : array();
		$schedules = wp_get_schedules();
		$restored  = 0;
		$hooks     = array();

		foreach ( (array) ( $prior['events'] ?? array() ) as $event ) {
			$hook = (string) ( $event['hook'] ?? '' );
			$args = (array) ( $event['args'] ?? array() );
			$at   = (int) ( $event['at'] ?? 0 );

			if ( '' === $hook || $at <= 0 || false !== wp_next_scheduled( $hook, $args ) ) {
				continue;
			}

			$recurrence = (string) ( $event['schedule'] ?? '' );
			$interval   = (int) ( $event['interval'] ?? 0 );

			if ( '' === $recurrence ) {
				$done = wp_schedule_single_event( $at, $hook, $args, true );
			} elseif ( isset( $schedules[ $recurrence ] ) ) {
				$done = wp_schedule_event( $at, $recurrence, $hook, $args, true );
			} else {
				// A recurrence its plugin registered and nothing registers now:
				// the scheduling functions refuse it, so the entry is written
				// back as core keeps it, name and interval included, rather
				// than coming back as a single run.
				$done = self::put_back( $at, $hook, $args, $recurrence, $interval );
			}

			if ( true === $done ) {
				++$restored;
				$hooks[] = $hook;
			}
		}

		Ledger::mark_reverted( $token );

		Writer::instance()->record(
			'cron_events_restored',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'cron',
				'object_id'   => implode( ', ', array_values( array_unique( $hooks ) ) ),
				'context'     => array( 'hooks' => array_values( array_unique( $hooks ) ) ),
			)
		);

		Auditor::run();

		return array( 'restored' => $restored );
	}

	/**
	 * One run written back into core's schedule, in core's own shape.
	 *
	 * @param array<int, mixed> $args
	 */
	private static function put_back( int $at, string $hook, array $args, string $recurrence, int $interval ): bool {
		$crons = _get_cron_array();
		$key   = md5( serialize( $args ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- core keys a run by the serialized arguments.

		$crons[ $at ][ $hook ][ $key ] = array(
			'schedule' => $recurrence,
			'args'     => $args,
			'interval' => $interval,
		);

		ksort( $crons );

		return true === _set_cron_array( $crons, true );
	}
}
