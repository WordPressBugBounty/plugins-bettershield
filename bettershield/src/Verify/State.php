<?php
/**
 * What the last visitor's page view said about each applied protection.
 *
 * One option, not a table: this is the current answer per item, not a history.
 * The history is the activity log, which already carries a row every time an
 * answer changes.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Verify;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class State {

	public const OPTION = 'bettershield_verification';

	/**
	 * Autoloaded, and it has to be.
	 *
	 * The sampler asks whether anything is due on ordinary front-end page
	 * views, so a row that is not autoloaded is one uncached database query
	 * per visitor on every host without an object cache — on the plugin whose
	 * first promise is that it never slows a site down. Stored `false`, it was
	 * exactly that, and it is the second time this shape has reached the front
	 * end: recording the observed PHP version did the same thing and was
	 * caught the same way.
	 *
	 * It stays small by construction — one short array per observable
	 * hardening item, and there are a handful — so autoloading it costs
	 * nothing measurable in the query core already makes.
	 *
	 * Getting an existing site's row onto that flag, and seeding one for a site
	 * that has never recorded a verification, is `Support\HotOptions` — which
	 * carries every option in this shape rather than one fix per class.
	 */
	public const AUTOLOAD = true;

	/**
	 * How long an answer stands before the sampler looks again. Long enough
	 * that a busy site is not re-checking on every page, short enough that a
	 * protection somebody broke this morning is not reported as fine all day.
	 */
	public const FRESH_SECONDS = 21600;

	/**
	 * @return array<string, array{status: string, detail: string, at: int}>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );

		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * @return array{status: string, detail: string, at: int}|null
	 */
	public static function for_item( string $item ): ?array {
		$all = self::all();

		$record = isset( $all[ $item ] ) && is_array( $all[ $item ] ) ? $all[ $item ] : null;
		// Older versions stored API/hook checks as confirmation of the whole
		// protection. Do not keep displaying that claim until the next sample.
		if ( $record && Checks::PRESENT === $record['status'] && in_array( $item, array( 'user_enumeration', 'version_disclosure' ), true ) ) {
			$record['status'] = Checks::UNKNOWN;
			$record['detail'] = __( 'The earlier check did not confirm the full protection.', 'bettershield' );
			$record['pending'] = true;
		}
		return $record;
	}

	/**
	 * Whether this item is due to be looked at again.
	 *
	 * Due when it has never been checked, when the last answer has gone stale,
	 * or when something asked for it explicitly — which is what applying an
	 * item does, so the owner gets a real answer on the next page view rather
	 * than six hours later.
	 */
	public static function is_due( string $item ): bool {
		$record = self::for_item( $item );

		if ( null === $record ) {
			return true;
		}

		if ( ! empty( $record['pending'] ) ) {
			return true;
		}

		return ( time() - (int) ( $record['at'] ?? 0 ) ) > self::FRESH_SECONDS;
	}

	/**
	 * Mark an item as wanting an answer on the next page a visitor loads.
	 *
	 * Called when an item is applied. The alternative — reporting it verified
	 * because it was just switched on — is the exact reasoning this whole
	 * mechanism exists to replace.
	 */
	public static function mark_pending( string $item ): void {
		$all = self::all();

		$all[ $item ] = array(
			'status'  => Checks::UNKNOWN,
			'detail'  => __( 'Applied. This can be confirmed once a visitor loads a page.', 'bettershield' ),
			'at'      => time(),
			'pending' => true,
		);

		update_option( self::OPTION, $all, self::AUTOLOAD );
	}

	/**
	 * Record what a page view saw.
	 *
	 * @return bool Whether this changed the stored answer, which is what
	 *              decides whether the change is worth a log entry.
	 */
	public static function record( string $item, string $status, string $detail ): bool {
		$all      = self::all();
		$previous = isset( $all[ $item ]['status'] ) ? (string) $all[ $item ]['status'] : '';

		$all[ $item ] = array(
			'status'  => $status,
			'detail'  => $detail,
			'at'      => time(),
			'pending' => false,
		);

		update_option( self::OPTION, $all, self::AUTOLOAD );

		return $previous !== $status;
	}

	/**
	 * Drop an item's answer, so a reverted item does not keep reporting on a
	 * protection that is no longer meant to be there.
	 */
	public static function forget( string $item ): void {
		$all = self::all();

		if ( ! isset( $all[ $item ] ) ) {
			return;
		}

		unset( $all[ $item ] );

		update_option( self::OPTION, $all, self::AUTOLOAD );
	}
}
