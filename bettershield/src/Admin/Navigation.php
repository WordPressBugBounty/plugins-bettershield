<?php
/**
 * The sidebar: every screen of the app, in zones, each zone in groups.
 *
 * The first zone is this plugin's own, grouped the way its sections are —
 * the summary and the report, then Protect, Agents, Activity and Settings —
 * so the sidebar and the admin menu tell the same story. Each add-on that
 * adds a section gets a zone of its own under its section's name, below this
 * plugin's, grouped however it declares. Nothing an add-on brings is mixed in
 * among this plugin's screens, and nothing of this plugin's is listed under
 * an add-on's name: which product a screen belongs to is visible at a glance.
 *
 * The sidebar lists screens rather than pages — a tab, or a section that has
 * none — so every screen is one entry. Where a screen lives, what it is
 * called in the address bar and who may open it are all still the section's;
 * the sidebar only decides where it is listed.
 *
 * Built on the server for the reason the rest of the model is: the labels are
 * translated and the addresses are WordPress's to construct. It is built from
 * the sections the config already filtered by capability, so the sidebar can
 * never offer a door that answers with a permissions error.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Navigation {

	/** This plugin's own zone. */
	public const CORE = 'core';

	/**
	 * Where a screen nobody placed is listed, inside its own zone. Never
	 * dropped: a tab an add-on forgot to place is still a tab its owner has to
	 * be able to reach.
	 */
	public const FALLBACK = 'more';

	/**
	 * This plugin's groups, in sidebar order: its sections, as the admin menu
	 * lists them. The first carries no heading — it holds the two screens
	 * about the site as a whole. A group with nothing in it is not drawn.
	 *
	 * @return array<string, string> Key => heading.
	 */
	public static function groups(): array {
		return array(
			'home'         => '',
			'protect'      => __( 'Protection', 'bettershield' ),
			'agents'       => __( 'Agents', 'bettershield' ),
			'activity'     => __( 'Activity', 'bettershield' ),
			'settings'     => __( 'Settings', 'bettershield' ),
			self::FALLBACK => __( 'More', 'bettershield' ),
		);
	}

	/**
	 * The mark of each of this plugin's groups that is a menu of its own.
	 *
	 * A group with a mark is drawn as a main entry that opens onto its
	 * screens, so the sidebar shows six entries rather than twenty until
	 * somebody opens one. A group without one — the first, and every group
	 * an add-on declares without a mark in `nav_marks` — lists its screens
	 * under a heading. An add-on's zone is long enough to want the same, so
	 * the marks it declares are drawn the same way, under the same rule.
	 *
	 * Only while an add-on has screens in the sidebar too. On its own, this
	 * plugin's screens fit the sidebar laid out in full, and every one in
	 * sight is worth more than the clicks a menu saves; it is an add-on's
	 * zone below them that makes the list long enough to fold.
	 */
	private const GROUP_MARKS = array(
		'protect'  => 'protect',
		'agents'   => 'agents',
		'activity' => 'activity',
		'settings' => 'settings',
	);

	/**
	 * The sidebar for the sections a reader may open.
	 *
	 * @param array<int, array{slug: string, label: string, url: string, tabs: array<int, array{slug: string, label: string, url: string}>}> $sections The sections as the config lists them, already filtered by capability.
	 * @param array<string, array{label?: string, addon?: bool, nav?: array<string, array{group: string, icon: string, label: string}>, nav_groups?: array<string, string>, nav_marks?: array<string, string>}> $registry Where each section placed its screens: Sections::all() or Sections::network().
	 * @param array<int, array{key: string, group: string, label: string, url: string, icon: string}>                                        $extras   Screens of this plugin's no section serves — a page of their own, reached by a document load.
	 * @return array<int, array{key: string, label: string, groups: array<int, array{key: string, label: string, icon: string, items: array<int, array{key: string, section: string, tab: string, label: string, url: string, icon: string, count: int}>}>}>
	 */
	public static function build( array $sections, array $registry, array $extras = array() ): array {
		// Zone key => its heading, its groups (key => heading) in order, and
		// the group a screen nobody placed goes to.
		$zones  = array(
			self::CORE => array(
				'label'    => '',
				'groups'   => self::groups(),
				'fallback' => self::FALLBACK,
				'marks'    => self::GROUP_MARKS,
			),
		);
		$placed = array( self::CORE => array() );

		foreach ( $sections as $section ) {
			$entry = $registry[ $section['slug'] ] ?? array();
			$zone  = self::CORE;

			if ( ! empty( $entry['addon'] ) ) {
				$zone = $section['slug'];

				if ( ! isset( $zones[ $zone ] ) ) {
					$declared = $entry['nav_groups'] ?? array();

					// An add-on that declared no groups lists its screens under
					// its zone's heading alone, rather than under "More".
					$zones[ $zone ]  = array(
						'label'    => $section['label'],
						'groups'   => array() === $declared ? array( '' => '' ) : $declared + array( self::FALLBACK => __( 'More', 'bettershield' ) ),
						'fallback' => array() === $declared ? '' : self::FALLBACK,
						'marks'    => $entry['nav_marks'] ?? array(),
					);
					$placed[ $zone ] = array();
				}
			}

			foreach ( self::screens( $section, $entry['nav'] ?? array() ) as $screen ) {
				$place = $screen['place'];
				$group = isset( $place['group'], $zones[ $zone ]['groups'][ $place['group'] ] ) ? $place['group'] : $zones[ $zone ]['fallback'];

				$placed[ $zone ][ $group ][] = array(
					'key'     => '' === $screen['slug'] ? $section['slug'] : $section['slug'] . '/' . $screen['slug'],
					'section' => $section['slug'],
					'tab'     => $screen['slug'],
					'label'   => '' !== ( $place['label'] ?? '' ) ? $place['label'] : $screen['label'],
					'url'     => $screen['url'],
					'icon'    => $place['icon'] ?? '',
					'count'   => self::count( $section['slug'], $screen['slug'] ),
				);
			}
		}

		foreach ( $extras as $extra ) {
			$group = isset( $zones[ self::CORE ]['groups'][ $extra['group'] ] ) ? $extra['group'] : self::FALLBACK;

			$placed[ self::CORE ][ $group ][] = array(
				'key'     => $extra['key'],
				'section' => '',
				'tab'     => '',
				'label'   => $extra['label'],
				'url'     => $extra['url'],
				'icon'    => $extra['icon'],
				'count'   => 0,
			);
		}

		$crowded = false;

		foreach ( $placed as $zone => $screens ) {
			if ( self::CORE !== $zone && array() !== array_filter( $screens ) ) {
				$crowded = true;
			}
		}

		$out = array();

		foreach ( $zones as $zone => $definition ) {
			$groups = array();

			foreach ( $definition['groups'] as $key => $label ) {
				if ( empty( $placed[ $zone ][ $key ] ) ) {
					continue;
				}

				// More is a heading in every zone, never a menu: what lands there
				// is what nobody placed, and folding it shut would hide it. An
				// add-on's marks can name it, so it is held back here.
				$groups[] = array(
					'key'   => (string) $key,
					'label' => $label,
					'icon'  => $crowded && '' !== $label && self::FALLBACK !== $key ? (string) ( $definition['marks'][ $key ] ?? '' ) : '',
					'items' => $placed[ $zone ][ $key ],
				);
			}

			if ( array() === $groups ) {
				continue;
			}

			$out[] = array(
				'key'    => $zone,
				'label'  => $definition['label'],
				'groups' => $groups,
			);
		}

		return $out;
	}

	/**
	 * A section's screens — each tab, or the section itself where it has
	 * none — with where the section placed each, in the order it placed them.
	 *
	 * That order need not be the order of the tab row; anything the section
	 * did not place keeps its own order after the rest. The sort is stable, so
	 * ties stay put.
	 *
	 * @param array{slug: string, label: string, url: string, tabs: array<int, array{slug: string, label: string, url: string}>} $section
	 * @param array<string, array{group: string, icon: string, label: string}>                                               $nav
	 * @return array<int, array{slug: string, label: string, url: string, place: array<string, string>}>
	 */
	private static function screens( array $section, array $nav ): array {
		$screens = array() === $section['tabs']
			? array(
				array(
					'slug'  => '',
					'label' => $section['label'],
					'url'   => $section['url'],
				),
			)
			: $section['tabs'];

		$order = array_flip( array_map( 'strval', array_keys( $nav ) ) );

		usort(
			$screens,
			static function ( array $a, array $b ) use ( $order ): int {
				return ( $order[ $a['slug'] ] ?? PHP_INT_MAX ) <=> ( $order[ $b['slug'] ] ?? PHP_INT_MAX );
			}
		);

		foreach ( $screens as $index => $screen ) {
			$screens[ $index ]['place'] = $nav[ $screen['slug'] ] ?? array();
		}

		return $screens;
	}

	/**
	 * A number a screen carries in the sidebar, or zero for none.
	 *
	 * One screen has one: a request an agent made waits for a person and runs
	 * out on its own, so it is counted where the person will see it — the
	 * same cached count the admin menu's bubble reads, never a query.
	 */
	private static function count( string $section, string $tab ): int {
		if ( Sections::AGENTS !== $section || 'requests' !== $tab ) {
			return 0;
		}

		return max( 0, \BetterShield\Abilities\Proposals::open_count() );
	}
}
