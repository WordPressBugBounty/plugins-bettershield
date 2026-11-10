<?php
/**
 * The navigation model, in one place.
 *
 * Five sections, closed set. Each is a real WordPress admin page with its own
 * slug and its own capability, which is what makes the capability separation
 * this plugin declares actually reachable: a single page can carry a single
 * capability, so an owner could never be given the record without also being
 * given the controls.
 *
 * Sections are capability areas rather than features. Features arrive as tabs
 * inside them. A section reaching six tabs means the grouping is wrong, not
 * that a fourth level is needed.
 *
 * What the reader navigates is not this list but the sidebar built from it
 * (Navigation): every screen — a tab, or a section with none — is one entry.
 * This plugin's own screens are grouped the way these sections are; an
 * add-on's are listed in a zone of their own, under its section's name, in
 * groups it declares. Each section says where its screens go under `nav`,
 * keyed by tab slug, or by an empty string for a section with no tabs. The
 * pages, their addresses and their capabilities stay exactly as they are.
 *
 * The network registry below is a second, separate list rather than an
 * addition to the first. The two answer to different capabilities, live under
 * different menus and are never drawn together: a screen about one site has no
 * place on a page about the whole network, and a screen about the network
 * cannot be reached from a site's own dashboard.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Admin;

use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Sections {

	/**
	 * The parent slug, and the Overview section: WordPress expects the first
	 * submenu entry to reuse the parent's slug, or the menu shows its own title
	 * twice.
	 */
	public const ROOT = 'bettershield';

	/**
	 * The same, for the network's own menu. Its slug differs from the site
	 * one's because both menus can exist on the same install, and a shared
	 * slug would make a click on one land on the other.
	 */
	public const NETWORK_ROOT = 'bettershield-network';

	/**
	 * The section everything about connected assistants lives under.
	 *
	 * Named, because two places outside the registry have to know it: the menu
	 * puts a count beside this one entry, and the screen that used to hold all
	 * of it redirects here.
	 */
	public const AGENTS = 'bettershield-agents';

	/** The optional hub connection, a section of its own in the menu. */
	public const HUB = 'bettershield-hub';

	/**
	 * Screens that used to be somewhere else.
	 *
	 * A tab address is a thing people bookmark, link to from a note, and read
	 * out of a finding recorded before the screen moved. Keyed by the old
	 * address and answered with the new one, so the move is stated once rather
	 * than remembered in each place that has to honor it.
	 *
	 * @var array<string, array{0: string, 1: string}>
	 */
	private const MOVED = array(
		'bettershield-protect|agents' => array( self::AGENTS, 'connect' ),
	);

	/**
	 * The capability the network screens answer to.
	 *
	 * The narrower `manage_network_options` gates the writes, inside the
	 * routes that make them; reading every site's posture is what a network
	 * administrator does, and nothing less than one may.
	 */
	public const NETWORK_CAPABILITY = 'manage_network';

	/**
	 * The registry, once per request.
	 *
	 * Nothing about it can change between two reads inside one request, and it
	 * is read nine or ten times while a single screen is assembled — once to
	 * add the menu, once for the config the app renders from, and once per
	 * section for the tab row. Each read re-ran six pairs of translations and
	 * the filter below.
	 *
	 * @var array<string, array{label: string, capability: string, tabs: array<string, string>, nav: array<string, array{group: string, icon: string, label: string}>, addon?: bool, nav_groups?: array<string, string>, nav_marks?: array<string, string>, drawn?: array<int, string>}>|null
	 */
	private static ?array $memo = null;

	/**
	 * The network registry, memoized separately for the same reason.
	 *
	 * @var array<string, array{label: string, capability: string, tabs: array<string, string>, nav: array<string, array{group: string, icon: string, label: string}>, addon?: bool, nav_groups?: array<string, string>, nav_marks?: array<string, string>, drawn?: array<int, string>}>|null
	 */
	private static ?array $network_memo = null;

	/**
	 * Forget both memos. For tests, which change what the filter answers
	 * between one assertion and the next; a real request has one answer.
	 */
	public static function reset(): void {
		self::$memo         = null;
		self::$network_memo = null;
	}

	/**
	 * Translated, so this must not be called before init.
	 *
	 * @return array<string, array{label: string, capability: string, tabs: array<string, string>, nav: array<string, array{group: string, icon: string, label: string}>, addon?: bool, nav_groups?: array<string, string>, nav_marks?: array<string, string>, drawn?: array<int, string>}>
	 */
	public static function all(): array {
		if ( null !== self::$memo ) {
			return self::$memo;
		}

		$sections = self::own();

		/**
		 * Sections an add-on adds to this plugin's menu, drawn inside the same
		 * chrome. Each entry: label, capability, tabs (slug => label), and
		 * optionally how the sidebar lists them. The sidebar gives each add-on
		 * section a zone of its own, headed by its label, below this plugin's
		 * screens: nav_groups names the zone's groups in order (key =>
		 * heading, an empty heading for a group that needs none), nav_marks
		 * gives a group a mark (key => mark), which draws it as a main entry
		 * that opens onto its screens the way this plugin's sections are, and
		 * nav places each tab, as tab slug => { group, icon, label } — the
		 * label being the sidebar's name for it where the tab's own reads
		 * badly out of context. A tab with no placement is listed under "More"
		 * in the add-on's zone. The add-on renders the body itself into the
		 * slot the app leaves for it. `drawn` lists the tabs the add-on draws
		 * with the redesigned dashboard's components (or is true for all of
		 * them): their slot sits in the redesign's content box, every other
		 * tab's in the wrapper that carries the classic look.
		 *
		 * @param array<string, array{label: string, capability: string, tabs: array<string, string>, nav_groups?: array<string, string>, nav_marks?: array<string, string>, nav?: array<string, array{group?: string, icon?: string, label?: string}>, drawn?: bool|array<int, string>}> $added Empty by default.
		 */
		$added = apply_filters( 'bettershield_sections', array() );

		foreach ( is_array( $added ) ? $added : array() as $slug => $section ) {
			$slug = sanitize_key( (string) $slug );

			if ( '' === $slug || isset( $sections[ $slug ] ) || ! is_array( $section ) || empty( $section['label'] ) || empty( $section['capability'] ) ) {
				continue;
			}

			$tabs = array();
			foreach ( isset( $section['tabs'] ) && is_array( $section['tabs'] ) ? $section['tabs'] : array() as $tab => $label ) {
				$tab = sanitize_key( (string) $tab );
				if ( '' !== $tab && is_string( $label ) && '' !== $label ) {
					$tabs[ $tab ] = $label;
				}
			}

			$sections[ $slug ] = array(
				'label'      => (string) $section['label'],
				'capability' => (string) $section['capability'],
				'tabs'       => $tabs,
				'nav'        => self::placements( $section['nav'] ?? array(), $tabs ),
				'nav_groups' => self::group_names( $section['nav_groups'] ?? array() ),
				'nav_marks'  => self::group_marks( $section['nav_marks'] ?? array() ),
				'drawn'      => self::drawn_tabs( $section['drawn'] ?? array(), $tabs ),
				'addon'      => true,
			);
		}

		self::$memo = $sections;

		return $sections;
	}

	/**
	 * Where an add-on's screens sit in the sidebar, kept to what can be drawn.
	 *
	 * Only screens the section actually has — a placement for a tab that does
	 * not exist would be an entry pointing nowhere — and only strings, cleaned
	 * the way every other key in this registry is. The group and the mark are
	 * names the app looks up, so an unknown one falls back there rather than
	 * being refused here.
	 *
	 * @param mixed                 $nav  What the add-on said.
	 * @param array<string, string> $tabs The section's tabs, already cleaned.
	 * @return array<string, array{group: string, icon: string, label: string}>
	 */
	private static function placements( $nav, array $tabs ): array {
		$screens = array() === $tabs ? array( '' ) : array_map( 'strval', array_keys( $tabs ) );
		$out     = array();

		foreach ( is_array( $nav ) ? $nav : array() as $screen => $place ) {
			$screen = sanitize_key( (string) $screen );

			if ( ! in_array( $screen, $screens, true ) || ! is_array( $place ) ) {
				continue;
			}

			$out[ $screen ] = array(
				'group' => isset( $place['group'] ) && is_string( $place['group'] ) ? sanitize_key( $place['group'] ) : '',
				'icon'  => isset( $place['icon'] ) && is_string( $place['icon'] ) ? sanitize_key( $place['icon'] ) : '',
				'label' => isset( $place['label'] ) && is_string( $place['label'] ) ? $place['label'] : '',
			);
		}

		return $out;
	}

	/**
	 * The tabs an add-on draws with the redesign's components, kept to tabs
	 * the section has. True stands for every one of them; anything else that
	 * is not a list names none, so an add-on that says nothing keeps the
	 * classic wrapper on every tab.
	 *
	 * @param mixed                 $drawn What the add-on said.
	 * @param array<string, string> $tabs  The section's tabs, already cleaned.
	 * @return array<int, string>
	 */
	private static function drawn_tabs( $drawn, array $tabs ): array {
		$screens = array() === $tabs ? array( '' ) : array_map( 'strval', array_keys( $tabs ) );

		if ( true === $drawn ) {
			return $screens;
		}

		$out = array();

		foreach ( is_array( $drawn ) ? $drawn : array() as $screen ) {
			$screen = is_string( $screen ) ? sanitize_key( $screen ) : null;

			if ( null !== $screen && in_array( $screen, $screens, true ) && ! in_array( $screen, $out, true ) ) {
				$out[] = $screen;
			}
		}

		return $out;
	}

	/**
	 * An add-on's sidebar groups, kept to what can be drawn: a cleaned key and
	 * a string heading each, in the order given.
	 *
	 * @param mixed $groups What the add-on said.
	 * @return array<string, string>
	 */
	private static function group_names( $groups ): array {
		$out = array();

		foreach ( is_array( $groups ) ? $groups : array() as $key => $label ) {
			$key = sanitize_key( (string) $key );

			if ( '' !== $key && is_string( $label ) ) {
				$out[ $key ] = $label;
			}
		}

		return $out;
	}

	/**
	 * The marks an add-on gives its groups, key => mark, both kept to the
	 * shape a key has. A group left out keeps its heading.
	 *
	 * @param mixed $marks
	 * @return array<string, string>
	 */
	private static function group_marks( $marks ): array {
		$out = array();

		foreach ( is_array( $marks ) ? $marks : array() as $key => $mark ) {
			$key  = sanitize_key( (string) $key );
			$mark = is_string( $mark ) ? sanitize_key( $mark ) : '';

			if ( '' !== $key && '' !== $mark ) {
				$out[ $key ] = $mark;
			}
		}

		return $out;
	}

	/** The Hub's name in the menu: "BetterShield Hub", or the owner's label's. */
	private static function hub_label(): string {
		/* translators: %s: the plugin's name, or the label the site owner gave it. */
		return sprintf( __( '%s Hub', 'bettershield' ), \BetterShield\Support\Branding::name() );
	}

	/**
	 * One sidebar placement. The label is the sidebar's own name for a screen
	 * whose tab label only makes sense beside its siblings ("Site", "Files"),
	 * and empty where the tab's label already reads on its own.
	 *
	 * @return array{group: string, icon: string, label: string}
	 */
	private static function place( string $group, string $icon, string $label = '' ): array {
		return array(
			'group' => $group,
			'icon'  => $icon,
			'label' => $label,
		);
	}

	/**
	 * @return array<string, array{label: string, capability: string, tabs: array<string, string>, nav: array<string, array{group: string, icon: string, label: string}>}>
	 */
	private static function own(): array {
		return array(

			self::ROOT               => array(
				'label'      => __( 'Overview', 'bettershield' ),
				'capability' => Capabilities::READ_POSTURE,
				'tabs'       => array(),
				'nav'        => array(
					'' => self::place( 'home', 'overview' ),
				),
			),

			'bettershield-findings'  => array(
				'label'      => __( 'Findings', 'bettershield' ),
				'capability' => Capabilities::READ_POSTURE,
				'tabs'       => array(),
				'nav'        => array(
					'' => self::place( 'home', 'findings' ),
				),
			),

			// Controls that change what happens to a visitor or a sign-in.
			// Everything that gates entry to the site is a tab of this one
			// section, so an owner looks in one place for all of it.
			'bettershield-protect'   => array(
				'label'      => __( 'Protection', 'bettershield' ),
				'capability' => Capabilities::MANAGE,
				'tabs'       => array(
					'hardening'  => __( 'Hardening', 'bettershield' ),
					'login'      => __( 'Login & Access', 'bettershield' ),
					'two-factor' => __( 'Two-Factor', 'bettershield' ),
					'recovery'   => __( 'Recovery', 'bettershield' ),
				),
				'nav'        => array(
					'hardening'  => self::place( 'protect', 'hardening' ),
					'login'      => self::place( 'protect', 'login' ),
					'two-factor' => self::place( 'protect', 'two-factor' ),
					'recovery'   => self::place( 'protect', 'recovery' ),
				),
			),

			/*
			 * Connecting an assistant, and everything that follows from having
			 * done it. A section of its own rather than a tab of Protect: the
			 * inventory of what is registered is a fact sheet read once, and
			 * with it on top the controls somebody actually comes for — allow
			 * reading, allow a change, connect — sat six cards down.
			 *
			 * The order of the tabs is the order the job is done, and the
			 * thing read once is last.
			 */
			self::AGENTS             => array(
				'label'      => __( 'Agents', 'bettershield' ),
				'capability' => Capabilities::MANAGE,
				'tabs'       => array(
					'connect'     => __( 'Connect', 'bettershield' ),
					'requests'    => __( 'Requests', 'bettershield' ),
					'permissions' => __( 'Permissions', 'bettershield' ),
					'surface'     => __( 'Agent surface', 'bettershield' ),
				),
				'nav'        => array(
					'connect'     => self::place( 'agents', 'connect' ),
					'requests'    => self::place( 'agents', 'requests' ),
					'permissions' => self::place( 'agents', 'permissions' ),
					'surface'     => self::place( 'agents', 'surface' ),
				),
			),

			/*
			 * Connecting this site to BetterShield Hub. Optional, and a
			 * section of its own so it can be found without knowing that the
			 * hub reaches the site the way an assistant does.
			 */
			self::HUB                => array(
				// Under the owner's label where one is set, as the menu is (#582).
				'label'      => self::hub_label(),
				'capability' => Capabilities::MANAGE,
				'tabs'       => array(),
				'nav'        => array(
					'' => self::place( 'agents', 'hub', self::hub_label() ),
				),
			),

			/*
			 * Append-only history. A group from the start because the records
			 * are genuinely different: site activity, file changes and agent
			 * invocations have different shapes, different volumes and their
			 * own tables. One tab each, one query each, no union.
			 *
			 * Each tab is named for its record, in the sidebar and on the tab
			 * row alike: "Site" and "Files" on their own named nothing.
			 */
			'bettershield-activity'  => array(
				'label'      => __( 'Activity', 'bettershield' ),
				'capability' => Capabilities::READ_ACTIVITY,
				'tabs'       => array(
					'site'   => __( 'Site Activity', 'bettershield' ),
					'files'  => __( 'File Changes', 'bettershield' ),
					'incidents' => __( 'Incidents', 'bettershield' ),
					'agents' => __( 'Agent Activity', 'bettershield' ),
				),
				'nav'        => array(
					'site'      => self::place( 'activity', 'log' ),
					'files'     => self::place( 'activity', 'files' ),
					'incidents' => self::place( 'activity', 'incidents' ),
					'agents'    => self::place( 'activity', 'agent-activity', __( 'Agent activity', 'bettershield' ) ),
				),
			),

			'bettershield-settings'  => array(
				'label'      => __( 'Settings', 'bettershield' ),
				'capability' => Capabilities::MANAGE,
				'tabs'       => array(
					'general' => __( 'General', 'bettershield' ),
					'alerts'  => __( 'Email Alerts', 'bettershield' ),
				),
				'nav'        => array(
					'general' => self::place( 'settings', 'general' ),
					'alerts'  => self::place( 'settings', 'email' ),
				),
			),
		);
	}

	/**
	 * The network's own sections, in the order the menu lists them.
	 *
	 * Two, and deliberately flat: what every site's posture is, and what the
	 * whole network's log says. Everything else the network administrator can
	 * change — the policies, the recovery link, the migration — belongs to the
	 * first of them, because each is one card about the network rather than an
	 * area a reader navigates to.
	 *
	 * @return array<string, array{label: string, capability: string, tabs: array<string, string>, nav: array<string, array{group: string, icon: string, label: string}>}>
	 */
	public static function network(): array {
		if ( null !== self::$network_memo ) {
			return self::$network_memo;
		}

		self::$network_memo = array(

			self::NETWORK_ROOT              => array(
				'label'      => __( 'Network', 'bettershield' ),
				'capability' => self::NETWORK_CAPABILITY,
				'tabs'       => array(),
				'nav'        => array(
					'' => self::place( 'home', 'network' ),
				),
			),

			'bettershield-network-activity' => array(
				'label'      => __( 'Activity', 'bettershield' ),
				'capability' => self::NETWORK_CAPABILITY,
				'tabs'       => array(
					'site'      => __( 'Activity', 'bettershield' ),
					'incidents' => __( 'Incidents', 'bettershield' ),
				),
				'nav'        => array(
					'site'      => self::place( 'home', 'activity' ),
					'incidents' => self::place( 'home', 'incidents' ),
				),
			),
		);

		return self::$network_memo;
	}

	/**
	 * Whether a section keeps its screen but is left out of the admin menu
	 * and the sidebar.
	 *
	 * Hub, while an owner's label asks for this plugin's links to be left out
	 * and the site holds no hub connection: unconnected, the entry only offers
	 * the publisher's hosted service, which the label keeps out of the chrome
	 * as it does the publisher's other plugins. Connected, it is listed again,
	 * since what the site sends and Disconnect live there. The screen stays
	 * reachable from Settings either way.
	 */
	public static function unlisted( string $slug ): bool {
		return self::HUB === $slug
			&& \BetterShield\Support\Branding::hides_help_links()
			&& ! \BetterShield\Hub\Link\Link::is_on()
			&& array() === \BetterShield\Mcp\Hub::apps();
	}

	public static function exists( string $slug ): bool {
		return isset( self::all()[ $slug ] );
	}

	public static function network_exists( string $slug ): bool {
		return isset( self::network()[ $slug ] );
	}

	/**
	 * The tabs a section offers as a choice, which is not the same as the tabs
	 * it has: one tab is not a choice, so no row is drawn for it. The row
	 * appears by itself when a second arrives.
	 *
	 * @return array<string, string>
	 */
	public static function tab_row( string $slug ): array {
		$tabs = self::all()[ $slug ]['tabs'] ?? array();

		return count( $tabs ) > 1 ? $tabs : array();
	}

	/**
	 * Where an address that has moved now points, or null if it has not.
	 *
	 * Answers only for a tab that is genuinely gone: once the old tab exists
	 * again under the same section the entry here would send a live screen
	 * somewhere else, which is a redirect loop waiting to be written.
	 *
	 * @return array{0: string, 1: string}|null Section slug and tab.
	 */
	public static function moved( string $section, string $tab ): ?array {
		$destination = self::MOVED[ $section . '|' . $tab ] ?? null;

		if ( null === $destination || isset( self::all()[ $section ]['tabs'][ $tab ] ) ) {
			return null;
		}

		return $destination;
	}

	/**
	 * The tab a request resolves to.
	 *
	 * An unknown tab falls back to the section's first, never to Overview: a
	 * renamed tab must not throw the reader out of the area they were in.
	 */
	public static function resolve_tab( string $section, string $requested ): string {
		$tabs = self::all()[ $section ]['tabs'] ?? array();

		if ( array() === $tabs ) {
			return '';
		}

		return isset( $tabs[ $requested ] ) ? $requested : (string) array_key_first( $tabs );
	}
}
