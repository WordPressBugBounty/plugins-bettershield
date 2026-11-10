<?php
/**
 * The tools each connected application may use (#1879).
 *
 * A connection carries `read` or `read write` and nothing finer, so an owner
 * who wanted an assistant to read the log and apply hardening, but never put
 * a file back, had to choose between every write and none. Per application,
 * the tools the owner unticks are kept here: that application's tool list
 * leaves them out, and a call to one is refused with
 * `bettershield_tool_not_allowed` and recorded as a refused call.
 *
 * Only ever a narrowing. The scopes stay two; nothing here lets an
 * application use a tool its scope does not already allow. An application
 * with nothing unticked uses everything its scope allows, as before, and a
 * tool added later is offered to it until it is unticked.
 *
 * Changes are written with their way back in the settings undo list.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AppTools {

	/** Application id => the tool names it may not use. */
	public const OPTION = 'bettershield_mcp_app_tools';

	/** The settings undo list's name for these. */
	public const SURFACE = 'mcp_app_tools';

	/** The refusal a call to an unticked tool gets. */
	public const REFUSAL = 'bettershield_tool_not_allowed';

	/**
	 * Every application's unticked tools.
	 *
	 * @return array<string, string[]>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );
		$out    = array();

		foreach ( is_array( $stored ) ? $stored : array() as $client => $tools ) {
			$tools = self::clean( $tools );

			if ( '' !== (string) $client && array() !== $tools ) {
				$out[ (string) $client ] = $tools;
			}
		}

		ksort( $out );

		return $out;
	}

	/**
	 * One application's unticked tools.
	 *
	 * @return string[]
	 */
	public static function denied( string $client_id ): array {
		return self::all()[ $client_id ] ?? array();
	}

	/**
	 * Whether the application this request authenticated as may not use a
	 * tool. A manual credential, and a request with no credential of this
	 * server's, is never narrowed here.
	 */
	public static function refuses( string $tool ): bool {
		return Audit::APP === Audit::kind() && in_array( $tool, self::denied( Audit::id() ), true );
	}

	/**
	 * Untick these tools for one application, and tick every other, with
	 * the way back recorded first.
	 *
	 * @param string[] $tools
	 * @return true|\WP_Error
	 */
	public static function set( string $client_id, array $tools ) {
		$before = self::all();
		$after  = $before;
		$tools  = self::clean( $tools );

		if ( array() === $tools ) {
			unset( $after[ $client_id ] );
		} else {
			$after[ $client_id ] = $tools;
		}

		if ( false === SettingsLedger::record( self::SURFACE, array( 'tools_denied' => $before ), array( 'tools_denied' => $after ) ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		self::put( $after );

		return true;
	}

	/**
	 * Whether unticking these, in place of what is unticked now, lets the
	 * application use a tool it could not: the direction that is asked for
	 * the password.
	 *
	 * @param string[] $tools
	 */
	public static function widens( string $client_id, array $tools ): bool {
		return array() !== array_diff( self::denied( $client_id ), self::clean( $tools ) );
	}

	/**
	 * Store a whole map, as the undo list puts one back.
	 *
	 * @param mixed $map
	 */
	public static function put( $map ): bool {
		$clean = array();

		foreach ( is_array( $map ) ? $map : array() as $client => $tools ) {
			$tools = self::clean( $tools );

			if ( '' !== (string) $client && array() !== $tools ) {
				$clean[ (string) $client ] = $tools;
			}
		}

		if ( array() === $clean ) {
			delete_option( self::OPTION );

			return true;
		}

		update_option( self::OPTION, $clean, false );

		return true;
	}

	/** Forget one application's: it was revoked. */
	public static function forget( string $client_id ): void {
		$all = self::all();

		if ( isset( $all[ $client_id ] ) ) {
			unset( $all[ $client_id ] );
			self::put( $all );
		}
	}

	/** Forget every application's: every grant ended. */
	public static function forget_all(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Tool names, each once and in order.
	 *
	 * @param mixed $tools
	 * @return string[]
	 */
	private static function clean( $tools ): array {
		$out = array();

		foreach ( is_array( $tools ) ? $tools : array() as $tool ) {
			if ( is_string( $tool ) && 1 === preg_match( '/^[a-z0-9][a-z0-9_-]{0,63}$/', $tool ) ) {
				$out[] = $tool;
			}
		}

		$out = array_values( array_unique( $out ) );
		sort( $out );

		return $out;
	}
}
