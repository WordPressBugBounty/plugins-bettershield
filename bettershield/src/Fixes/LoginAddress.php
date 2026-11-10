<?php
/**
 * Fix for "Something published at the moved sign-in address is hidden by
 * the sign-in form" (#2210).
 *
 * The sign-in address is moved again, to one the item's own rules accept,
 * the way the settings import and WP-CLI change an applied item's settings:
 * after the recovery pre-flight, undone and applied again as one settings
 * change, and put back as it was if the second step is refused, so the
 * standard sign-in page is never left answering. Nothing published is
 * renamed or unpublished.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Audit\Auditor;
use BetterShield\Hardening\Item\LoginUrl;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\Preflight;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginAddress {

	/** The hardening item that moves the sign-in address. */
	public const ITEM = 'login_url';

	/**
	 * What the panel shows: the address now, what it hides, and where that
	 * content is edited, for somebody who may edit it.
	 *
	 * @return array{active: bool, address: string, shadowed: ?array, edit_url: string, field: array<string, mixed>}
	 */
	public static function state(): array {
		$manager  = Manager::instance();
		$active   = $manager->is_active( self::ITEM );
		$slug     = $active ? (string) ( $manager->item_state( self::ITEM )['options']['slug'] ?? '' ) : '';
		$shadowed = '' === $slug ? null : LoginUrl::shadowed_content( $slug );
		$post     = null !== $shadowed && $shadowed['id'] > 0 ? (int) $shadowed['id'] : 0;

		return array(
			'active'   => $active,
			'address'  => '' === $slug ? '' : LoginUrl::url_for( $slug ),
			'shadowed' => $shadowed,
			'edit_url' => $post > 0 && current_user_can( 'edit_post', $post ) ? (string) get_edit_post_link( $post, 'raw' ) : '',
			// The item's own field, so the panel checks the rule it states.
			'field'    => LoginUrl::fields()[0],
		);
	}

	/**
	 * Move the sign-in address to a new one.
	 *
	 * @param string $slug     The address asked for.
	 * @param bool   $override Whether the person went ahead past a failed pre-flight.
	 * @return array<string, mixed>|\WP_Error The new address and the panel's state, or the refusal.
	 */
	public static function change( string $slug, bool $override ) {
		$manager = Manager::instance();

		if ( ! $manager->is_active( self::ITEM ) ) {
			return new \WP_Error( 'bettershield_not_active', __( 'The sign-in address is not moved, so there is nothing to change.', 'bettershield' ), array( 'status' => 409 ) );
		}

		// Refused before anything is undone, so a bad value never takes the
		// protection off even for a moment.
		$valid = LoginUrl::validate( array( 'slug' => $slug ) );

		if ( is_wp_error( $valid ) ) {
			$valid->add_data( array( 'status' => 400 ) );

			return $valid;
		}

		$previous = $manager->item_state( self::ITEM )['options'] ?? array();
		$previous = is_array( $previous ) ? $previous : array();

		if ( ( $previous['slug'] ?? '' ) === $valid['slug'] ) {
			return new \WP_Error( 'bettershield_login_address_same', __( 'That is the address in use now. Choose another.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$failure = Preflight::failure();

		if ( null !== $failure && ! $override ) {
			return Preflight::refusal( $failure );
		}

		$done = $manager->revert( self::ITEM, Manager::CAUSE_RECONFIGURE );

		if ( ! is_wp_error( $done ) ) {
			$done = $manager->apply( self::ITEM, $valid );

			if ( is_wp_error( $done ) ) {
				// Put the address in use back. Its content is the very reason
				// for this finding, so the item's own rule would refuse it
				// and leave the standard sign-in page answering.
				LoginUrl::restoring( (string) ( $previous['slug'] ?? '' ) );

				try {
					$back = $manager->apply( self::ITEM, $previous );
				} finally {
					LoginUrl::restoring( null );
				}

				if ( is_wp_error( $back ) ) {
					return new \WP_Error(
						'bettershield_login_address_lost',
						__( 'The address could not be moved or put back, so the standard sign-in page is answering now. Move the sign-in address again from Protection.', 'bettershield' ),
						array( 'status' => 500 )
					);
				}
			}
		}

		if ( is_wp_error( $done ) ) {
			return $done;
		}

		if ( null !== $failure ) {
			Preflight::overridden( $failure, self::ITEM, 'dashboard' );
		}

		Auditor::run();

		return array(
			'address' => LoginUrl::url_for( $valid['slug'] ),
			'state'   => self::state(),
		);
	}
}
