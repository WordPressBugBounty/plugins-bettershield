<?php
/**
 * Admin menu and asset loading.
 *
 * One top-level entry with a page per section beneath it. Sections are real
 * admin pages rather than client-side routes, which is what lets each carry its
 * own capability and lets WordPress mark the current submenu item itself —
 * sharing one page slug across sections is what creates the highlighting
 * problem, and not sharing it is the whole fix.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Admin;

use BetterShield\Capabilities;
use BetterShield\Onboarding\QuickSetup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Menu {

	/** The dashboard's bundle, in `assets/build/`, without its extension. */
	public const BUNDLE = 'next';

	/**
	 * Page hooks returned by registration, so assets load on our screens only.
	 *
	 * @var string[]
	 */
	private array $hooks = array();

	/**
	 * What `add_menu_page` is given for the icon: nothing it draws itself.
	 *
	 * The mark is the product's own, dots and gradient, and core can only
	 * draw an icon it may repaint in one color. So the slot stays empty and
	 * paint_mark() draws the real file into it. Public because the network
	 * menu draws the same entry and the two disagreeing would be two marks.
	 */
	public static function menu_icon(): string {
		return 'none';
	}

	/**
	 * The real mark in the menu's icon slot, for the site menu and the
	 * network's.
	 *
	 * Drawn at 28px because the shield fills only the middle of its file:
	 * there it stands as tall as core's 20px icons beside it. The light admin
	 * color scheme has a pale sidebar and gets the mark made for one. An
	 * owner's own image (Branding) replaces the site menu's mark and is left
	 * alone.
	 */
	public static function paint_mark(): void {
		// Hooked by both menus; once a request is enough.
		static $painted = false;

		if ( $painted ) {
			return;
		}

		$painted = true;
		$targets = array( '#adminmenu #toplevel_page_' . Sections::NETWORK_ROOT );

		if ( '' === \BetterShield\Support\Branding::logo_url() ) {
			$targets[] = '#adminmenu #toplevel_page_' . Sections::ROOT;
		}

		$dark  = esc_url_raw( plugins_url( 'assets/images/mark-dark.svg', BETTERSHIELD_FILE ) );
		$light = esc_url_raw( plugins_url( 'assets/images/mark-light.svg', BETTERSHIELD_FILE ) );
		$pale  = 'light' === get_user_option( 'admin_color' );
		$css   = '';

		foreach ( $targets as $target ) {
			$css .= $target . ' .wp-menu-image{background:url("' . ( $pale ? $light : $dark ) . '") center/28px no-repeat}'
				. $target . ' .wp-menu-image::before{content:none}';

			// The light scheme's open and hovered entry sits on dark gray.
			if ( $pale ) {
				$css .= $target . '.wp-has-current-submenu .wp-menu-image,' . $target . ':hover .wp-menu-image{background-image:url("' . $dark . '")}';
			}
		}

		wp_add_inline_style( 'admin-menu', $css );
	}

	/**
	 * The site menu's icon: the owner's image where a label carries one, and
	 * the product mark otherwise. The network's menu keeps the mark.
	 */
	private static function site_menu_icon(): string {
		$logo = \BetterShield\Support\Branding::logo_url();

		return '' !== $logo ? $logo : self::menu_icon();
	}

	/**
	 * Hold an owner's image to the size of the icon beside it.
	 *
	 * Core draws an image address as an `<img>` at whatever size the file
	 * is, where the mark is drawn at twenty pixels; a logo would push the
	 * menu apart on every admin page.
	 */
	public function size_the_menu_image(): void {
		if ( '' === \BetterShield\Support\Branding::logo_url() ) {
			return;
		}

		wp_add_inline_style(
			'admin-menu',
			'#adminmenu #toplevel_page_' . Sections::ROOT . ' .wp-menu-image img{width:20px;height:20px;padding:7px 0 0;object-fit:contain;opacity:1}'
		);
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'size_the_menu_image' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'paint_mark' ) );
		add_action( 'admin_init', array( $this, 'redirect_moved_screens' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( BETTERSHIELD_FILE ), array( self::class, 'row_links' ) );
		Quiet::register();
	}

	/**
	 * The way in from the Plugins screen: Quick Setup until it is finished,
	 * then the Overview. The row offered only Deactivate (#2406).
	 *
	 * @param mixed $links The row's action links.
	 * @return mixed
	 */
	public static function row_links( $links ) {
		if ( ! is_array( $links ) || ! current_user_can( Capabilities::MANAGE ) ) {
			return $links;
		}

		$link = QuickSetup::is_done()
			? sprintf( '<a href="%s">%s</a>', esc_url( admin_url( 'admin.php?page=' . Sections::ROOT ) ), esc_html__( 'Overview', 'bettershield' ) )
			: sprintf( '<a href="%s">%s</a>', esc_url( QuickSetup::url() ), esc_html__( 'Quick Setup', 'bettershield' ) );

		return array_merge( array( 'bettershield' => $link ), $links );
	}

	/**
	 * A screen that has moved answers from its old address.
	 *
	 * Server-side rather than in the app, because the old address is what a
	 * bookmark, an emailed link and a finding recorded before the move all
	 * carry — and none of those reaches the app's router without a document
	 * load first. Everything else in the query string travels, so a link that
	 * pointed at one row still points at it.
	 */
	public function redirect_moved_screens(): void {
		if ( wp_doing_ajax() || is_network_admin() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen was asked for, not acting on a submission.
		$query = wp_unslash( $_GET );

		if ( ! is_array( $query ) ) {
			return;
		}

		$page = isset( $query['page'] ) && is_string( $query['page'] ) ? sanitize_key( $query['page'] ) : '';
		$tab  = isset( $query['tab'] ) && is_string( $query['tab'] ) ? sanitize_key( $query['tab'] ) : '';

		$destination = Sections::moved( $page, $tab );

		if ( null === $destination ) {
			return;
		}

		$url = admin_url( 'admin.php?page=' . $destination[0] );
		$url = add_query_arg( 'tab', $destination[1], $url );

		foreach ( $query as $name => $value ) {
			// Scalars only: nothing this app puts in an admin address is an
			// array, and carrying one would mean guessing how deep to clean it.
			if ( in_array( $name, array( 'page', 'tab' ), true ) || ! is_scalar( $value ) ) {
				continue;
			}

			$url = add_query_arg(
				sanitize_key( (string) $name ),
				rawurlencode( sanitize_text_field( (string) $value ) ),
				$url
			);
		}

		// Temporary: the destination is this plugin's to change again, and a
		// permanent redirect is one a browser keeps after we stop sending it.
		if ( wp_safe_redirect( $url ) ) {
			exit;
		}
	}

	/**
	 * Single top-level entry — never multiple menus.
	 */
	public function add_menu(): void {
		/*
		 * Position 78, not 80: 80 is core's own Settings, and add_menu_page
		 * resolves that collision by nudging to 80.0000x, which lands the menu
		 * underneath Settings at the very bottom of the sidebar. 76 to 79 sit
		 * between Tools and Settings and collide with nothing in core.
		 */
		$this->hooks[] = (string) add_menu_page(
			// An owner's label where an add-on gives one (Branding): the
			// menu is chrome, and the Plugins screen row keeps the name.
			\BetterShield\Support\Branding::name(),
			\BetterShield\Support\Branding::name(),
			// The floor for reaching the plugin at all. Sections then gate
			// themselves individually, upward from here.
			Capabilities::READ_POSTURE,
			Sections::ROOT,
			array( $this, 'render' ),
			self::site_menu_icon(),
			78
		);

		foreach ( Sections::all() as $slug => $section ) {
			$hook = add_submenu_page(
				Sections::ROOT,
				$section['label'],
				self::menu_title( $slug, $section['label'] ),
				$section['capability'],
				$slug,
				array( $this, 'render' )
			);

			// A section the current user cannot reach registers nothing and
			// answers false. Casting that to a string would put an empty entry
			// in the list every hook is later matched against.
			if ( is_string( $hook ) ) {
				$this->hooks[] = $hook;
			}

			// An unlisted section keeps its screen, its title and its place
			// under the menu, and its entry is drawn hidden.
			if ( is_string( $hook ) && Sections::unlisted( $slug ) ) {
				self::hide_entry( $slug );
			}
		}

		// Every screen the app draws carries this plugin's notices and no one
		// else's (Quiet explains why).
		foreach ( $this->hooks as $hook ) {
			Quiet::claim( $hook );
		}
	}

	/**
	 * Draw a section's entry in the admin menu hidden, with core's own class.
	 *
	 * Left in the list rather than taken out of it: core finds a screen's
	 * title and which menu to hold open from that entry, and a screen
	 * registered with no parent has neither.
	 */
	private static function hide_entry( string $slug ): void {
		global $submenu;

		foreach ( $submenu[ Sections::ROOT ] ?? array() as $index => $entry ) {
			if ( $slug === ( $entry[2] ?? '' ) ) {
				$submenu[ Sections::ROOT ][ $index ][4] = trim( ( $entry[4] ?? '' ) . ' hidden' ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- the entry's class, which core reads from here.
			}
		}
	}

	/**
	 * The label the sidebar carries, which is not always the label the page
	 * carries.
	 *
	 * A request an agent has made waits for a person to answer it and expires
	 * on its own, so it cannot depend on somebody remembering to look. The
	 * bubble is core's own — the same markup and the same classes the Plugins
	 * entry uses for updates — so it inherits the admin color scheme and reads
	 * as part of the menu rather than as something this plugin drew.
	 *
	 * The count is the cached one: a number on every admin page load is a
	 * query on every admin page load, and this is a menu.
	 */
	private static function menu_title( string $slug, string $label ): string {
		if ( Sections::AGENTS !== $slug ) {
			return $label;
		}

		$waiting = \BetterShield\Abilities\Proposals::open_count();

		if ( $waiting < 1 ) {
			return $label;
		}

		return $label . ' <span class="update-plugins count-' . $waiting . '"><span class="plugin-count">'
			. esc_html( number_format_i18n( $waiting ) ) . '</span></span>';
	}

	/**
	 * The slug being viewed. Read from the request because WordPress has
	 * already decided it, and already refused anyone without the capability.
	 */
	private function current_section(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen is open, not acting on a submission.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';

		return Sections::exists( $page ) ? $page : Sections::ROOT;
	}

	private function current_tab( string $section ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- as above.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( (string) $_GET['tab'] ) ) : '';

		return Sections::resolve_tab( $section, $tab );
	}

	public function render(): void {
		echo '<div id="bettershield-root" class="bs-root"></div>';
	}

	/**
	 * The navigation model the interface renders from.
	 *
	 * Built here rather than in JavaScript because the labels are translatable
	 * and the URLs are WordPress's to construct. Sections the current user
	 * cannot reach are left out entirely, so the sidebar built from them
	 * (Navigation) never offers a door that answers with a permissions error.
	 *
	 * @return array<string, mixed>
	 */
	private function config(): array {
		$section  = $this->current_section();
		$sections = array();

		foreach ( Sections::all() as $slug => $definition ) {
			if ( ! current_user_can( $definition['capability'] ) ) {
				continue;
			}

			$url  = (string) menu_page_url( $slug, false );
			$tabs = array();

			// Every tab travels, because the router has to be able to validate
			// one that arrives in a URL. Whether a *row* is drawn for them is a
			// separate question, answered once here rather than re-derived in
			// the interface.
			foreach ( $definition['tabs'] as $tab_slug => $label ) {
				$tabs[] = array(
					'slug'  => $tab_slug,
					'label' => $label,
					'url'   => add_query_arg( 'tab', $tab_slug, $url ),
				);
			}

			$entry = array(
				'slug'      => $slug,
				'label'     => $definition['label'],
				'url'       => $url,
				'tabs'      => $tabs,
				'show_tabs' => array() !== Sections::tab_row( $slug ),
			);

			// Which of an add-on's tabs it draws with the redesign's
			// components: the app gives those a slot in its content box.
			if ( ! empty( $definition['addon'] ) ) {
				$entry['drawn'] = array_values( $definition['drawn'] ?? array() );
			}

			$sections[] = $entry;
		}

		/*
		 * Areas travel with the chrome rather than in each response, for the
		 * same reason section labels do: translated display text, constant for
		 * the request, identical on every row that shows them.
		 *
		 * Each surface gets only the areas it can actually produce, derived
		 * from its own registry. An audit says nothing about this plugin's own
		 * doings, and no event is about an end-of-life PHP branch, so a shared
		 * list would hand both screens permanent zeroes.
		 */
		$areas = array(
			'findings' => \BetterShield\Support\Areas::label_list( \BetterShield\Audit\Checks::groups() ),
			'activity' => \BetterShield\Support\Areas::label_list(
				array_values( array_unique( array_values( \BetterShield\Events\Types::areas() ) ) )
			),
		);

		return array(
			'section'  => $section,
			'tab'      => $this->current_tab( $section ),
			'sections' => $sections,
			'nav'      => Navigation::build( array_values( array_filter( $sections, static fn( array $entry ): bool => ! Sections::unlisted( $entry['slug'] ) ) ), Sections::all(), self::extras() ),
			// What this reader may do beyond reading, for the controls that
			// are not a section: the sections above are already filtered,
			// and a button the route refuses is a door that answers with a
			// permissions error.
			'can'      => array(
				'manage'       => current_user_can( Capabilities::MANAGE ),
				// The Overview is read ahead on every screen, for a reader
				// who may read it.
				'read_posture' => current_user_can( Capabilities::READ_POSTURE ),
				// Whether this reader edits what every site shares: on a
				// network wp-config.php is the network's, so the lines that
				// replace its keys are a network administrator's to take.
				'shared_config' => ! is_multisite() || current_user_can( 'manage_network_options' ),
				// Whether this reader may restore, accept or quarantine the
				// files every site shares: on a network, a network
				// administrator only (#2615).
				'shared_code'   => true === \BetterShield\Rest\Permissions::shared_code( false ),
			),
			'areas'    => $areas,
			// The top bar's way to the hub, read here rather than from the
			// hub's route on every screen just to draw the bar.
			'hub'      => in_array( Sections::HUB, array_column( $sections, 'slug' ), true ) ? self::hub_way() : array(
				'connected' => false,
				'url'       => '',
			),
			'brand'    => \BetterShield\Support\Branding::name(),
			// An owner's label (Branding): the image the sidebar draws in
			// place of the mark, whether a label is in force at all, and
			// whether the links to this plugin's support are offered.
			'brandLogo' => \BetterShield\Support\Branding::logo_url(),
			'branded'   => null !== \BetterShield\Support\Branding::get(),
			'helpLinks' => ! \BetterShield\Support\Branding::hides_help_links(),
			// The tier the site is served at, and what — if anything — the
			// interface may say about a paid one, in the places the product
			// rules allow. Both come from the server so the bundle promises
			// nothing on its own.
			'tier'     => \BetterShield\Support\Tier::current(),
			'offer'    => \BetterShield\Support\Tier::offer(),
			'limits'   => array(
				'retention_days' => \BetterShield\Support\Tier::retention_days(),
			),
		);
	}

	/**
	 * Whether the site holds a hub connection, and the hub's address where
	 * the Hub screen's "Open the Hub" would offer it: '' where the address
	 * moved since the connection was approved, or the pinned one is invalid,
	 * as that button is not offered then either.
	 *
	 * @return array{connected: bool, url: string}
	 */
	private static function hub_way(): array {
		$apps = \BetterShield\Mcp\Hub::apps();

		if ( array() === $apps ) {
			return array(
				'connected' => false,
				'url'       => '',
			);
		}

		// The grant that reaches furthest, as the Hub screen picks it.
		$writes = array_values( array_filter( $apps, static fn( array $app ): bool => 'read write' === $app['scope'] ) );
		$app    = $writes[0] ?? $apps[0];
		$host   = '' !== $app['hub'] ? (string) $app['hub'] : \BetterShield\Mcp\Hub::host();
		$open   = ! \BetterShield\Mcp\Hub::pin_is_invalid() && \BetterShield\Mcp\Hub::host() === $host;

		return array(
			'connected' => true,
			'url'       => $open ? \BetterShield\Mcp\Hub::url() : '',
		);
	}

	/**
	 * Screens in the sidebar that no section serves.
	 *
	 * The Quick Setup is a page of its own rather than a section — it draws
	 * without the app's frame, on purpose — and is listed with the settings
	 * until it is finished. Then Settings offers it to run again instead.
	 * Only once its page exists for this reader: `menu_page_url()` answers an
	 * empty string otherwise, and an entry pointing nowhere is worse than no
	 * entry.
	 *
	 * @return array<int, array{key: string, group: string, label: string, url: string, icon: string}>
	 */
	private static function extras(): array {
		if ( ! current_user_can( Capabilities::MANAGE ) || \BetterShield\Onboarding\QuickSetup::is_done() ) {
			return array();
		}

		$url = (string) menu_page_url( \BetterShield\Onboarding\QuickSetup::PAGE, false );

		if ( '' === $url ) {
			return array();
		}

		return array(
			array(
				'key'   => \BetterShield\Onboarding\QuickSetup::PAGE,
				'group' => 'settings',
				'label' => __( 'Quick Setup', 'bettershield' ),
				'url'   => $url,
				'icon'  => 'setup',
			),
		);
	}

	/**
	 * Assets load on our screens only — never admin-wide.
	 */
	public function enqueue_assets( string $hook ): void {
		if ( ! in_array( $hook, $this->hooks, true ) ) {
			return;
		}

		self::enqueue_app( $this->config(), $hook );
	}

	/**
	 * Put the app on the screen, whichever menu drew it.
	 *
	 * The per-site screens load the dashboard bundle and the network's load
	 * their own, but the mechanics of getting either onto a page — the
	 * dependency handling, the inlined model, the RTL swap, the add-on signal —
	 * live once. Everything else that differs is inside `$config`.
	 *
	 * @param array<string, mixed> $config The navigation model the app renders from.
	 * @param string               $hook   The screen's hook suffix.
	 */
	public static function enqueue_app( array $config, string $hook ): void {
		$config['assetsUrl'] = plugins_url( 'assets/images/', BETTERSHIELD_FILE );
		$config['version']   = BETTERSHIELD_VERSION;
		$config['siteName']  = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		// One dashboard for a site's screens and the network's alike: the
		// network's sections are drawn in the same frame.
		$bundle = self::BUNDLE;

		// The sidebar names the reader under the product's name.
		$config['userName'] = wp_specialchars_decode( wp_get_current_user()->display_name, ENT_QUOTES );

		$asset_file = BETTERSHIELD_PATH . '/assets/build/' . $bundle . '.asset.php';
		if ( ! is_file( $asset_file ) ) {
			return; // Build output missing: leave the root empty rather than fatal.
		}
		$asset = require $asset_file;

		$script_deps = $asset['dependencies'];
		// WP 7.1+ registers the wp-theme script (ThemeProvider). The app
		// feature-detects window.wp.theme at runtime, so older WordPress
		// simply skips the provider. Never a hard dependency.
		if ( wp_script_is( 'wp-theme', 'registered' ) ) {
			$script_deps[] = 'wp-theme';
		}

		wp_enqueue_script(
			'bettershield-admin',
			plugins_url( 'assets/build/' . $bundle . '.js', BETTERSHIELD_FILE ),
			$script_deps,
			$asset['version'],
			true
		);

		/*
		 * Which screen this is, and where the others are. Inlined before the app
		 * so it is present the moment the module runs.
		 *
		 * This is the one place in the plugin where a value is written into a
		 * browser context rather than returned as JSON, so it is escaped for that
		 * context rather than merely encoded. Plain JSON leaves angle brackets
		 * alone, and a single `</script>` inside any string would close the block
		 * early and turn the rest of it into markup. The flags render every
		 * character that could do that as a \u escape, which JavaScript reads
		 * back as exactly the same string.
		 *
		 * Nothing here is attacker-supplied today: the labels are ours and the
		 * URLs are WordPress's. Both travel through a translation catalog and
		 * the options table on the way, though, and neither is a place this
		 * plugin should be willing to trust on the strength of who usually
		 * writes to it.
		 */
		wp_add_inline_script(
			'bettershield-admin',
			'window.bettershield = ' . wp_json_encode(
				$config,
				JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
			) . ';',
			'before'
		);

		// Without this the strings in the app stay English however well they
		// are translated: the JSON that translate.wordpress.org builds is only
		// loaded for scripts that ask for it.
		wp_set_script_translations( 'bettershield-admin', 'bettershield', BETTERSHIELD_PATH . '/languages' );

		// The component library's own stylesheet: required, because the app
		// uses core components for its interactive primitives.
		$style_deps = array( 'wp-components' );

		// WP 7.1+ also registers the wp-theme stylesheet carrying --wpds-*
		// design tokens. Our token layer ships literal fallback values, so
		// older WordPress renders identically without it.
		if ( wp_style_is( 'wp-theme', 'registered' ) ) {
			$style_deps[] = 'wp-theme';
		}
		// The stylesheet is built alongside the script: every component imports
		// the CSS file that lives beside it, and webpack folds them into this
		// one bundle. The authored files ship in assets/css and assets/js for
		// the same reason the JS sources do — the build reproduces this file
		// byte for byte.
		$style_path = BETTERSHIELD_PATH . '/assets/build/' . $bundle . '.css';
		wp_enqueue_style(
			'bettershield-admin',
			plugins_url( 'assets/build/' . $bundle . '.css', BETTERSHIELD_FILE ),
			$style_deps,
			// File mtime as version: style edits bust caches without a release.
			// A missing file falls back to the release version rather than
			// warning on every screen load.
			is_file( $style_path ) ? (string) filemtime( $style_path ) : BETTERSHIELD_VERSION
		);

		// The build also emits <bundle>-rtl.css; this swaps it in for RTL
		// locales, which the hand-enqueued stylesheet never did.
		wp_style_add_data( 'bettershield-admin', 'rtl', 'replace' );

		self::addon_styles();

		/**
		 * The app is on this screen. An add-on that draws a section into the
		 * app's slot enqueues its own script and style here — on every screen
		 * the app runs on, not only its own page — because the app moves
		 * between sections without a document load, so a bundle that only
		 * arrives with its own page never arrives at all when the reader
		 * comes from another section.
		 *
		 * @param string $hook The screen's hook suffix.
		 */
		do_action( 'bettershield_admin_assets', $hook );
	}

	/** The add-on release that styles its own disclosures. */
	private const ADDON_STYLED_SINCE = '1.0.2';

	/**
	 * Whether the add-on active here is a release built against 1.1.0's
	 * stylesheet, before 1.0.2.
	 *
	 * Its bundle draws the "How this works" disclosures, the reveals and the
	 * callout marks with classes whose look this plugin's stylesheet carried,
	 * and it no longer does: each question was drawn as a full-size icon in
	 * a gray box. This plugin updates on its own, often before the add-on.
	 */
	public static function needs_addon_styles(): bool {
		return defined( 'BETTERSHIELD_ULTRA_VERSION' )
			&& version_compare( (string) constant( 'BETTERSHIELD_ULTRA_VERSION' ), self::ADDON_STYLED_SINCE, '<' );
	}

	/**
	 * Those styles, beside such a release and nowhere else. A release that
	 * carries them itself does not get them twice.
	 */
	private static function addon_styles(): void {
		if ( ! self::needs_addon_styles() ) {
			return;
		}

		$path = BETTERSHIELD_PATH . '/assets/css/addon-1-0.css';

		wp_enqueue_style(
			'bettershield-addon-1-0',
			plugins_url( 'assets/css/addon-1-0.css', BETTERSHIELD_FILE ),
			array( 'bettershield-admin' ),
			is_file( $path ) ? (string) filemtime( $path ) : BETTERSHIELD_VERSION
		);
	}
}
