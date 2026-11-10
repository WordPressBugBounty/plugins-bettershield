<?php
/**
 * A feed built from an array: what the engine is developed and tested
 * against until a supply is bound. Nothing in the plugin constructs one; a
 * test does, or a developer through the `bettershield_vulnerability_feed`
 * filter.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FixtureFeed implements Feed {

	/** @var array<int, array<string, mixed>> */
	private array $advisories;

	private string $published_at;

	/**
	 * @param array<int, array<string, mixed>> $advisories
	 */
	public function __construct( array $advisories, ?string $published_at = null ) {
		$this->advisories   = $advisories;
		$this->published_at = $published_at ?? gmdate( 'c' );
	}

	public function id(): string {
		return 'fixture';
	}

	public function label(): string {
		return 'Fixture feed';
	}

	public function advisories( array $inventory ) {
		$wanted = array();
		foreach ( $inventory as $item ) {
			$wanted[ $item['type'] . ':' . $item['slug'] ] = true;
		}

		return array(
			'advisories'   => array_values(
				array_filter(
					$this->advisories,
					static fn( array $advisory ): bool => isset( $wanted[ ( $advisory['type'] ?? '' ) . ':' . ( $advisory['slug'] ?? '' ) ] )
				)
			),
			'published_at' => $this->published_at,
		);
	}
}
