<?php
/**
 * Whether a published vulnerability can be reached on this site: who it
 * needs to be, and whether anybody here is.
 *
 * Severity says how bad a flaw is anywhere. Two flaws of the same severity
 * are not the same job on one site: one an anonymous visitor can use, one
 * that needs an editor's account on a site where nobody but the owner signs
 * in. What separates them is already on the site (who holds which
 * capability, and whether anyone can register) and in the advisory (which
 * account it needs, named in its title, and whether it is being exploited).
 *
 * This only orders and explains. It never hides a row, never dismisses one,
 * and never calls one safe: a wrong reading of an advisory only moves a row.
 *
 * The site's half is read when it is asked for and never stored, so an
 * account added today changes the answer today.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

use BetterShield\Audit\Checks;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Reach {

	/** The accounts a flaw may need, from none up. */
	public const PRIVILEGES = array( 'none', 'subscriber', 'contributor', 'author', 'editor', 'admin' );

	/**
	 * The capability that stands for each: asked by capability, not by role
	 * name, so a custom role that grants it counts.
	 */
	private const CAPABILITIES = array(
		'subscriber'  => 'read',
		'contributor' => 'edit_posts',
		'author'      => 'publish_posts',
		'editor'      => 'edit_others_posts',
		'admin'       => 'manage_options',
	);

	/** Role names as advisories write them, to the level above. */
	private const NAMES = array(
		'subscriber'    => 'subscriber',
		'customer'      => 'subscriber',
		'contributor'   => 'contributor',
		'author'        => 'author',
		'editor'        => 'editor',
		'shop manager'  => 'editor',
		'administrator' => 'admin',
		'admin'         => 'admin',
	);

	/** Asked once per request, per capability. */
	private static array $held = array();

	/**
	 * The account an advisory needs, from its title, or null where the title
	 * does not say. "Authenticated" with no role named takes the lowest, so
	 * the row errs toward reachable.
	 */
	public static function privilege_from_title( string $title ): ?string {
		if ( 1 === preg_match( '/\bunauthenticated\b/i', $title ) ) {
			return 'none';
		}

		// "Authenticated (Contributor+)", "(Shop Manager or higher)",
		// "(Author-level)": the first role named inside the brackets.
		if ( 1 === preg_match( '/\bauthenticated\s*\(\s*(administrator|shop manager|subscriber|contributor|customer|author|editor|admin)\b/i', $title, $named ) ) {
			return self::NAMES[ strtolower( $named[1] ) ];
		}

		if ( 1 === preg_match( '/\bauthenticated\b/i', $title ) ) {
			return 'subscriber';
		}

		return null;
	}

	/**
	 * The least an attacker needs across a row's advisories: the most
	 * reachable of them decides. Null when no title says.
	 *
	 * @param array<int, array<string, mixed>> $advisories
	 */
	public static function privilege_of( array $advisories ): ?string {
		$least = null;

		foreach ( $advisories as $advisory ) {
			$needs = self::privilege_from_title( (string) ( $advisory['title'] ?? '' ) );

			if ( null !== $needs && ( null === $least || array_search( $needs, self::PRIVILEGES, true ) < array_search( $least, self::PRIVILEGES, true ) ) ) {
				$least = $needs;
			}
		}

		return $least;
	}

	/**
	 * How a row stands here, read now.
	 *
	 * - `exploited`: an advisory says it is being exploited. Above everything.
	 * - `no_account`: it needs no account.
	 * - `open_registration`: anybody can register an account that has what it needs.
	 * - `held`: an account here other than an administrator has what it needs.
	 * - `not_held`: only administrators here have it, and nobody can
	 *   register for it.
	 * - `admin_only`: it needs an administrator's account.
	 * - null: the advisory does not say what it needs, so it ranks as before.
	 *
	 * @param ?bool   $exploited Whether an advisory says so; null where none says.
	 * @param ?string $privilege What it needs.
	 */
	public static function reach( ?bool $exploited, ?string $privilege ): ?string {
		if ( true === $exploited ) {
			return 'exploited';
		}

		if ( null === $privilege || ! in_array( $privilege, self::PRIVILEGES, true ) ) {
			return null;
		}

		if ( 'none' === $privilege ) {
			return 'no_account';
		}

		// Somebody who already holds an administrator's account holds the
		// site; a flaw that needs one is the last on this list.
		if ( 'admin' === $privilege ) {
			return 'admin_only';
		}

		$capability = self::CAPABILITIES[ $privilege ];

		if ( Checks::registration_is_open() && self::new_accounts_get( $capability ) ) {
			return 'open_registration';
		}

		return self::anybody_holds( $capability ) ? 'held' : 'not_held';
	}

	/**
	 * Rows in the order they matter here: exploited, then reachable, then
	 * the ones no advisory said enough about, then the ones that need an
	 * account nobody here has. Within each, the order they came in.
	 *
	 * @param array<int, array<string, mixed>> $rows Each with `reach`.
	 * @return array<int, array<string, mixed>>
	 */
	public static function order( array $rows ): array {
		$rank = static function ( ?string $reach ): int {
			switch ( $reach ) {
				case 'exploited':
					return 0;
				case 'no_account':
				case 'open_registration':
				case 'held':
					return 1;
				case 'not_held':
				case 'admin_only':
					return 3;
				default:
					return 2;
			}
		};

		$keyed = array();

		foreach ( array_values( $rows ) as $index => $row ) {
			$keyed[] = array( $rank( $row['reach'] ?? null ), $index, $row );
		}

		usort( $keyed, static fn( array $a, array $b ): int => array( $a[0], $a[1] ) <=> array( $b[0], $b[1] ) );

		return array_column( $keyed, 2 );
	}

	/** Forget what was asked, for a request that changed accounts. */
	public static function reset(): void {
		self::$held = array();
	}

	/**
	 * Whether an account other than an administrator's holds this. An
	 * administrator holds every capability, so counting theirs would make
	 * every flaw reachable on every site, including one where nobody but the
	 * owner signs in.
	 */
	private static function anybody_holds( string $capability ): bool {
		if ( ! isset( self::$held[ $capability ] ) ) {
			self::$held[ $capability ] = array() !== get_users(
				array(
					'capability'        => $capability,
					'capability__not_in' => array( 'manage_options' ),
					'number'            => 1,
					'fields'            => 'ID',
				)
			);
		}

		return self::$held[ $capability ];
	}

	/** Whether the role a new account gets here has this capability. */
	private static function new_accounts_get( string $capability ): bool {
		$role = get_role( (string) get_option( 'default_role', 'subscriber' ) );

		return null !== $role && $role->has_cap( $capability );
	}
}
