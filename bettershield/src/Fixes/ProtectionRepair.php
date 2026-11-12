<?php
/**
 * Fix for "Some protections that are switched on are not working" (#2430).
 *
 * Each protection the finding names is applied again, with the settings it
 * has now, the way the settings import and WP-CLI change an applied item:
 * undone and applied again as one settings change, and put back on with
 * the same settings if the second step is refused, so it is never left
 * off. That rewrites the rules or guards it placed and attaches its hooks
 * again. A protection that changes how people sign in waits for the
 * recovery pre-flight first, as applying it does.
 *
 * Nothing new is kept for an undo: the protection ends where it started,
 * on, and its own Undo on Protection stays the way to take it off.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Audit\Checks;
use BetterShield\Hardening\Item\LoginUrl;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\Preflight;
use BetterShield\Rest\Permissions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProtectionRepair {

	/**
	 * The protections the finding names, each with its title and why it
	 * reads as not working.
	 *
	 * @return array{items: array<int, array{id: string, title: string, reason: string, signs_in: bool}>}
	 */
	public static function state(): array {
		$titles = Items::all();
		$items  = array();

		foreach ( Checks::protections_failing() as $id => $reason ) {
			$items[] = array(
				'id'       => (string) $id,
				'title'    => (string) ( $titles[ $id ]['title'] ?? $id ),
				'reason'   => (string) $reason,
				// Applying it waits for a proved way back in.
				'signs_in' => Permissions::needs_way_back( (string) $id ),
			);
		}

		return array( 'items' => $items );
	}

	/** Why this protection can't be applied again now, or null. A plan asks the same question the fix does. */
	public static function refusal( string $item ): ?\WP_Error {
		// Only a protection the finding names: anything else is applied, or
		// taken off, on Protection, where its own settings are.
		if ( ! isset( Checks::protections_failing()[ $item ] ) ) {
			return new \WP_Error( 'bettershield_not_failing', __( 'That protection is not one the finding names, so it was left as it is.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! Manager::instance()->is_active( $item ) ) {
			return new \WP_Error( 'bettershield_not_active', __( 'That protection is off, so there is nothing to apply again. Switch it on under Protection.', 'bettershield' ), array( 'status' => 409 ) );
		}

		return null;
	}

	/**
	 * Apply one named protection again, and check again.
	 *
	 * @param string $item     The protection, by id.
	 * @param bool   $override Whether the person went ahead past a failed pre-flight.
	 * @return array{item: string, working: bool, state: array<string, mixed>}|\WP_Error
	 */
	public static function reapply( string $item, bool $override ) {
		$refused = self::refusal( $item );

		if ( null !== $refused ) {
			return $refused;
		}

		$manager = Manager::instance();
		$failure = Permissions::needs_way_back( $item ) ? Preflight::failure() : null;

		if ( null !== $failure && ! $override ) {
			return Preflight::refusal( $failure );
		}

		$options = $manager->item_state( $item )['options'] ?? array();
		$options = is_array( $options ) ? $options : array();

		// The address in use was accepted when it was set, so content found
		// there since does not stop it being set again.
		if ( LoginAddress::ITEM === $item ) {
			LoginUrl::restoring( (string) ( $options['slug'] ?? '' ) );
		}

		try {
			$done = $manager->revert( $item, Manager::CAUSE_RECONFIGURE );

			if ( ! is_wp_error( $done ) ) {
				$done = $manager->apply( $item, $options );

				if ( is_wp_error( $done ) ) {
					$back = $manager->apply( $item, $options );

					if ( is_wp_error( $back ) ) {
						return new \WP_Error(
							'bettershield_protection_lost',
							__( 'It could not be applied again, and is off now. Switch it on again under Protection.', 'bettershield' ),
							array( 'status' => 500 )
						);
					}
				}
			}
		} finally {
			LoginUrl::restoring( null );
		}

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( null !== $failure ) {
			Preflight::overridden( $failure, $item, 'dashboard' );
		}

		Auditor::run();

		return array(
			'item'    => $item,
			'working' => ! isset( Checks::protections_failing()[ $item ] ),
			'state'   => self::state(),
		);
	}
}
