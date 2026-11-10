<?php
/**
 * The Hub link's heartbeat: a short signed account of the site, every ten
 * minutes while the link is on, and about half a minute after a plugin or
 * theme is updated, switched on or off (`Push::inventory_changed()`).
 *
 * Versions, and digests in place of what they digest: the tools this site
 * offers, its score and open findings, the vulnerabilities it knows of, and
 * what it runs. The hub keeps them and reads the site again when one changes,
 * from the site's own tools rather than from the digest. What the site runs
 * is sent in full only when its digest has changed since the hub last took
 * it. The newest day the activity log was sealed is sent as well, so a copy of
 * where the chain stood lives off the site.
 *
 * A heartbeat that does not arrive is not an outage: the hub's own check on
 * the front page decides that.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hub\Link;

use BetterShield\Abilities\Registrar;
use BetterShield\Audit\Auditor;
use BetterShield\Events\Seal;
use BetterShield\Mcp\Scopes;
use BetterShield\Mcp\Tools;
use BetterShield\Vulnerabilities\Inventory;
use BetterShield\Vulnerabilities\State;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Heartbeat {

	/** How often one is sent: inside the contract's five to fifteen minutes. */
	public const EVERY = 10 * MINUTE_IN_SECONDS;

	/**
	 * Whether one is due.
	 *
	 * @param array<string, mixed> $state The sender's state.
	 */
	public static function due( array $state ): bool {
		return time() - (int) ( $state['heartbeat_at'] ?? 0 ) >= self::EVERY;
	}

	/**
	 * The heartbeat's own fields, and the inventory digest they carry. The
	 * version, the site and the moment of signing are added as it is sent.
	 *
	 * @param string $taken The inventory digest the hub last took, '' for none.
	 * @return array{payload: array<string, mixed>, inventory_digest: string}
	 */
	public static function payload( string $taken ): array {
		$inventory = self::inventory();
		$digest    = self::digest( $inventory );
		$feed      = self::vulnerabilities();

		return array(
			'payload'          => array(
				'versions'             => self::versions(),
				'catalog_hash'         => self::catalog_hash(),
				'posture_digest'       => self::posture_digest(),
				'vulnerability_digest' => $feed['digest'],
				'feed_age_s'           => $feed['age'],
				'inventory_digest'     => $digest,
				'inventory'            => $digest === $taken ? null : $inventory,
				'seal_head'            => self::seal_head(),
			),
			'inventory_digest' => $digest,
		);
	}

	/**
	 * This plugin's, the add-on's, WordPress's and PHP's versions. The add-on's
	 * is null where it is not loaded.
	 *
	 * @return array{plugin: string, ultra: ?string, wordpress: string, php: string}
	 */
	public static function versions(): array {
		return array(
			'plugin'    => defined( 'BETTERSHIELD_VERSION' ) ? (string) BETTERSHIELD_VERSION : '',
			'ultra'     => defined( 'BETTERSHIELD_ULTRA_VERSION' ) ? (string) constant( 'BETTERSHIELD_ULTRA_VERSION' ) : null,
			'wordpress' => (string) get_bloginfo( 'version' ),
			'php'       => PHP_VERSION,
		);
	}

	/**
	 * A digest of the tools this site offers a connection: every read, with its
	 * description and schemas, and the names of those that change the site while
	 * changes are on. It moves when a tool is added, removed or reworded, and
	 * when changes are turned on or off.
	 */
	public static function catalog_hash(): string {
		$changes = Registrar::write_enabled() ? Registrar::write_ability_names() : array();
		sort( $changes );

		return self::sha( array( Tools::catalog( Scopes::READ_ONLY ), $changes ) );
	}

	/**
	 * A digest of the score, the grade and each open finding's check, status
	 * and snooze: the posture as the hub reads it, in one value. A snooze set,
	 * ended or run out moves it, so the hub reads the site again and stops, or
	 * starts again, counting that finding as needing attention.
	 */
	public static function posture_digest(): string {
		$overview = Auditor::overview();
		$open     = array();

		foreach ( Auditor::findings() as $finding ) {
			if ( 'open' === (string) $finding['status'] ) {
				$open[] = array( (string) $finding['id'], (string) $finding['status'], (string) ( $finding['snoozed_until'] ?? '' ) );
			}
		}

		sort( $open );

		return self::sha( array( (int) ( $overview['score'] ?? 0 ), (string) ( $overview['grade'] ?? '' ), $open ) );
	}

	/**
	 * A digest of the known vulnerabilities, from whichever feed answered, and
	 * how many seconds ago it last did. The age is null where no check has
	 * ever completed.
	 *
	 * @return array{digest: string, age: ?int}
	 */
	public static function vulnerabilities(): array {
		$state    = State::get();
		$affected = array();

		foreach ( $state['affected'] as $item ) {
			$affected[] = (string) wp_json_encode( self::sorted( (array) $item ) );
		}

		sort( $affected );

		$fetched = '' !== $state['fetched_at'] ? strtotime( $state['fetched_at'] ) : false;

		return array(
			'digest' => self::sha( array( $state['feed'], $affected ) ),
			'age'    => false === $fetched ? null : max( 0, time() - $fetched ),
		);
	}

	/**
	 * What this site runs: core, each plugin and each theme, by slug, version
	 * and type, in a fixed order. The same slugs and versions a vulnerability
	 * feed is asked about, and nothing more.
	 *
	 * @return array<int, array{slug: string, version: string, type: string}>
	 */
	public static function inventory(): array {
		return array_slice( Inventory::for_feed( Inventory::collect() ), 0, 1000 );
	}

	/**
	 * The newest sealed day and its chained digest, or null before the first
	 * seal.
	 *
	 * @return array{day: string, hash: string}|null
	 */
	public static function seal_head(): ?array {
		$seals = Seal::all();

		if ( array() === $seals ) {
			return null;
		}

		ksort( $seals );

		$day  = (string) array_key_last( $seals );
		$hash = (string) ( $seals[ $day ]['digest'] ?? '' );

		return 1 === preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) && '' !== $hash
			? array(
				'day'  => $day,
				'hash' => $hash,
			)
			: null;
	}

	/**
	 * The inventory's digest.
	 *
	 * @param array<int, array{slug: string, version: string, type: string}> $inventory
	 */
	public static function digest( array $inventory ): string {
		return 'sha256:' . Inventory::digest( $inventory );
	}

	/** A value's digest, as the contract writes one. */
	private static function sha( $value ): string {
		return 'sha256:' . hash( 'sha256', (string) wp_json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
	}

	/**
	 * An array with its keys in order, all the way down, so two equal records
	 * stored in different orders digest alike.
	 *
	 * @param array<mixed> $value
	 * @return array<mixed>
	 */
	private static function sorted( array $value ): array {
		ksort( $value );

		foreach ( $value as $name => $inner ) {
			if ( is_array( $inner ) ) {
				$value[ $name ] = self::sorted( $inner );
			}
		}

		return $value;
	}
}
