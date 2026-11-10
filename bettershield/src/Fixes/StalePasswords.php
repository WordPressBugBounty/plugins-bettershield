<?php
/**
 * Fix for "Application passwords that nothing has used for months" (#2430).
 *
 * Each application password nothing has used for as long as the finding
 * counts, by its account and name, and Revoke for the ones chosen. Only one
 * the list holds now can be revoked: the request names them, and they are
 * matched against what is found now rather than trusted.
 *
 * A revoked application password cannot be put back; WordPress keeps only a
 * hash of it. So there is no undo here, the panel says so before the press,
 * and core's own hook records each revoke in the activity log. The decoy
 * credential is never listed: being unused is what it is for.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Abilities\AgentSurface;
use BetterShield\Audit\Auditor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class StalePasswords {

	/** How many are listed, and so may be revoked, at once. */
	public const MAX_LISTED = 50;

	/**
	 * The stale application passwords, each with why it cannot be revoked
	 * from here, where it cannot.
	 *
	 * @return array{passwords: array<int, array<string, mixed>>, total: int, days: int}
	 */
	public static function state(): array {
		$rows = self::stale();

		return array(
			'passwords' => array_slice( $rows, 0, self::MAX_LISTED ),
			'total'     => count( $rows ),
			'days'      => AgentSurface::STALE_DAYS,
		);
	}

	/**
	 * Why this reader may not revoke an account's application passwords,
	 * or ''. On a network one signs in on every site, so it is the
	 * network's to revoke.
	 */
	public static function refusal( int $user_id ): string {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return __( 'You cannot manage this account.', 'bettershield' );
		}

		if ( is_multisite() && ! current_user_can( 'manage_network' ) ) {
			return __( 'On a network, application passwords work on every site, so a network administrator revokes them.', 'bettershield' );
		}

		return '';
	}

	/**
	 * Revoke the chosen ones the list still holds.
	 *
	 * @param string[] $keys Each "account id:password uuid", as the list gives it.
	 * @return array{revoked: array<int, array<string, mixed>>, refused: array<int, array<string, mixed>>, state: array<string, mixed>}|\WP_Error
	 */
	public static function revoke( array $keys ) {
		$listed = array_column( self::stale(), null, 'key' );
		$chosen = array_values( array_unique( array_map( 'strval', $keys ) ) );

		if ( array() === array_intersect( $chosen, array_keys( $listed ) ) ) {
			return new \WP_Error( 'bettershield_none_listed', __( 'None of those is on the list now, so nothing was revoked.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$revoked = array();
		$refused = array();

		foreach ( $chosen as $key ) {
			if ( ! isset( $listed[ $key ] ) ) {
				continue;
			}

			$row    = $listed[ $key ];
			$reason = $row['refused'];

			if ( '' === $reason ) {
				$done   = \WP_Application_Passwords::delete_application_password( (int) $row['user_id'], (string) $row['uuid'] );
				$reason = true === $done ? '' : __( 'WordPress could not revoke it. Try again.', 'bettershield' );
			}

			$named = array(
				'key'   => $key,
				'login' => $row['login'],
				'name'  => $row['name'],
			);

			if ( '' === $reason ) {
				$revoked[] = $named;
			} else {
				$refused[] = $named + array( 'reason' => $reason );
			}
		}

		Auditor::run();

		return array(
			'revoked' => $revoked,
			'refused' => $refused,
			'state'   => self::state(),
		);
	}

	/**
	 * Every application password unused for the finding's span, oldest
	 * first, read the way the finding reads them.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function stale(): array {
		$now  = time();
		$rows = array();

		foreach ( AgentSurface::application_passwords( true ) as $holder ) {
			if ( (int) $holder['oldest_unused_days'] < AgentSurface::STALE_DAYS ) {
				continue;
			}

			$refused = self::refusal( (int) $holder['user_id'] );

			foreach ( (array) ( $holder['passwords'] ?? array() ) as $password ) {
				if ( ! empty( $password['decoy'] ) || '' === (string) $password['uuid'] ) {
					continue;
				}

				// Never used counts from creation, as the finding counts it.
				$alive = (int) strtotime( (string) ( $password['last_used_at'] ?? $password['created_at'] ) );
				$days  = (int) floor( ( $now - $alive ) / DAY_IN_SECONDS );

				if ( $days < AgentSurface::STALE_DAYS ) {
					continue;
				}

				$rows[] = array(
					'key'     => (int) $holder['user_id'] . ':' . $password['uuid'],
					'user_id' => (int) $holder['user_id'],
					'uuid'    => (string) $password['uuid'],
					'login'   => (string) $holder['login'],
					'name'    => (string) $password['name'],
					'days'    => $days,
					'used'    => null !== $password['last_used_at'],
					'refused' => $refused,
				);
			}
		}

		usort( $rows, static fn( array $a, array $b ): int => $b['days'] <=> $a['days'] );

		return $rows;
	}
}
