<?php
/**
 * What a credential is allowed to do here, and the only vocabulary either half
 * of the endpoint says it in.
 *
 * Two values and no more: `read`, and `read write`. Reading is never optional —
 * a connection that may change this site may obviously also look at it — so the
 * write scope is always the pair, and a credential either carries it or does
 * not.
 *
 * What a scope reaches is decided nowhere in this file and never by a name. An
 * ability declares `readonly` in its own annotations; a tool whose ability does
 * not declare it is a write tool, and so is every ability the write opt-in
 * registers, plans included — see `Tools::needs_write_scope()`. That is the
 * direction a default has to fail in: an ability nobody annotated is one
 * nobody has thought about, and guessing from a `get-` prefix is how a tool
 * that quietly persists what it computed ends up reachable from a read-only
 * credential.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scopes {

	/** Looking at the site. Every credential has this one. */
	public const READ = 'read';

	/** Changing it. Only ever held alongside the one above. */
	public const WRITE = 'write';

	/** The two spellings a stored or reported scope is ever written as. */
	public const READ_ONLY  = 'read';
	public const READ_WRITE = 'read write';

	/**
	 * What the discovery documents advertise, in the order they advertise it.
	 *
	 * @return string[]
	 */
	public static function supported(): array {
		return array( self::READ, self::WRITE );
	}

	/**
	 * Whether every token of a requested scope is one this server issues.
	 *
	 * An empty request is not a bad one: a client that names no scope is asking
	 * for whatever the site is willing to give, and the person approving it
	 * decides.
	 */
	public static function are_supported( string $requested ): bool {
		foreach ( self::tokens( $requested ) as $token ) {
			if ( ! in_array( $token, self::supported(), true ) ) {
				return false;
			}
		}

		return true;
	}

	/** Whether this scope may call a tool that changes the site. */
	public static function allows_write( string $scope ): bool {
		return in_array( self::WRITE, self::tokens( $scope ), true );
	}

	/** The canonical spelling for a yes or a no. */
	public static function canonical( bool $write ): string {
		return $write ? self::READ_WRITE : self::READ_ONLY;
	}

	/**
	 * Any scope string narrowed to one of the two canonical spellings.
	 *
	 * A stored record with no scope at all reads as the smaller one. That is
	 * the safe direction and the visible one: the connection screen names the
	 * scope, and replacing the credential is how an owner widens it.
	 */
	public static function normalize( string $scope ): string {
		return self::canonical( self::allows_write( $scope ) );
	}

	/**
	 * @return string[]
	 */
	private static function tokens( string $scope ): array {
		$parts = preg_split( '/\s+/', trim( $scope ) );

		if ( ! is_array( $parts ) ) {
			return array();
		}

		return array_values(
			array_filter(
				$parts,
				static function ( string $token ): bool {
					return '' !== $token;
				}
			)
		);
	}
}
