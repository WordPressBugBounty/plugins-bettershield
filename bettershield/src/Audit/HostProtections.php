<?php
/**
 * What the host says it does for this site at the server.
 *
 * Some protections run where nothing inside WordPress can see or test them:
 * a backup the host takes of the whole server, or a way for the owner to get
 * into the site from the host's own panel. A host that provides one can say
 * so for every site it runs, and the matching check then passes:
 *
 *     add_filter(
 *         'bettershield_host_protections',
 *         static fn( array $said ): array => array_merge( $said, array( 'backups' => true ) )
 *     );
 *
 * The keys:
 *
 * - `ai_bot_blocker`: the host turns away AI crawlers before they reach
 *   WordPress. True or false; left out, nothing is said.
 * - `backups`: the host backs up this site and can restore it.
 * - `recovery`: the host gives the owner a way into this site that does not
 *   go through the sign-in form this plugin guards, so a lockout, a paused
 *   network or a two-factor requirement here cannot stop it. A host whose
 *   way in signs the owner in through wp-login.php must not set this.
 *
 * Unknown keys are ignored, and so is a value that is not true or false.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HostProtections {

	/** The filter a host answers. */
	public const FILTER = 'bettershield_host_protections';

	/** The keys this reads; anything else in the answer is ignored. */
	public const KEYS = array( 'ai_bot_blocker', 'backups', 'recovery' );

	/**
	 * What the host said, by key, for the keys it said something about.
	 *
	 * @return array<string, bool>
	 */
	public static function said(): array {
		$said = apply_filters( self::FILTER, array() ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- self::FILTER is 'bettershield_host_protections'.

		if ( ! is_array( $said ) ) {
			return array();
		}

		$out = array();

		foreach ( self::KEYS as $key ) {
			if ( isset( $said[ $key ] ) && is_bool( $said[ $key ] ) ) {
				$out[ $key ] = $said[ $key ];
			}
		}

		return $out;
	}

	/**
	 * Whether the host says it provides this protection.
	 */
	public static function provides( string $key ): bool {
		return true === ( self::said()[ $key ] ?? null );
	}
}
