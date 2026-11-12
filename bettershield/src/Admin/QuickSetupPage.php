<?php
/**
 * The page the Quick Setup is drawn on.
 *
 * A page of its own rather than a section of the app: the setup has one job
 * and a start and an end, and the app's tabs, its audit button and its
 * masthead would be seven ways out of it. It stays in the menu after it is
 * finished, so it can be opened again; opened again, it shows the site as it
 * is and changes only what the owner changes.
 *
 * Its own bundle, too, so the app's screens never carry the setup's weight and
 * the setup never carries theirs.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Admin;

use BetterShield\Capabilities;
use BetterShield\Integrity\FirstScan;
use BetterShield\Onboarding\QuickSetup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class QuickSetupPage {

	private string $hook = '';

	public function register(): void {
		// After the app's own sections, so the entry sits at the foot of them.
		add_action( 'admin_menu', array( $this, 'add_page' ), 20 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_filter( 'admin_body_class', array( $this, 'body_class' ) );

		// A site nobody was redirected from on activation (each site of a
		// network, a bulk or terminal activation) runs its setup the first
		// time its administrator opens this plugin.
		add_action( 'admin_init', array( $this, 'maybe_open_first' ) );
	}

	public function add_page(): void {
		$hook = add_submenu_page(
			Sections::ROOT,
			__( 'Quick Setup', 'bettershield' ),
			__( 'Quick Setup', 'bettershield' ),
			Capabilities::MANAGE,
			QuickSetup::PAGE,
			array( $this, 'render' )
		);

		if ( is_string( $hook ) ) {
			$this->hook = $hook;
			Quiet::claim( $hook );
			add_action( 'load-' . $hook, array( $this, 'leave_when_finished' ) );
			// However the setup was reached, having seen it once is enough:
			// the first visit to the plugin does not send the owner back.
			add_action( 'load-' . $hook, array( QuickSetup::class, 'mark_opened' ) );
		}

		/*
		 * A finished setup leaves the menu; Settings carries the way back in.
		 * The page stays registered, so that link and any bookmark still open
		 * it, and while it is open its entry stays, so the screen keeps its
		 * title and the menu keeps its place.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen was asked for, not acting on a submission.
		$page = isset( $_GET['page'] ) && is_string( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';

		if ( QuickSetup::is_done() && QuickSetup::PAGE !== $page ) {
			remove_submenu_page( Sections::ROOT, QuickSetup::PAGE );
		}
	}

	/**
	 * A finished setup is not drawn again by accident. Reached by a bookmark,
	 * a copied link or the Back button, it sends the owner to the dashboard;
	 * only Settings' "Run Quick Setup Again" opens it, for a while.
	 */
	public function leave_when_finished(): void {
		if ( QuickSetup::is_open() ) {
			return;
		}

		if ( wp_safe_redirect( admin_url( 'admin.php?page=' . Sections::ROOT ) ) ) {
			exit;
		}
	}

	/**
	 * Read from the page asked for rather than from a screen hook: a hook
	 * name is built from the translated menu title, and the slug is not.
	 */
	public function maybe_open_first(): void {
		if ( wp_doing_ajax() || is_network_admin() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which screen was asked for, not acting on a submission.
		$page = isset( $_GET['page'] ) && is_string( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';

		if ( ! Sections::exists( $page ) || ! current_user_can( Capabilities::MANAGE ) || ! QuickSetup::opens_on_first_visit() ) {
			return;
		}

		QuickSetup::mark_opened();

		if ( wp_safe_redirect( QuickSetup::url() ) ) {
			exit;
		}
	}

	/**
	 * The design's tokens are declared on `bs-ds-body`, so the page carries
	 * it from its first paint: the background, the stand-in and the line for
	 * a browser that runs no scripts read them before the bundle runs.
	 *
	 * @param string $classes Space-separated classes.
	 */
	public function body_class( $classes ): string {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;

		if ( '' !== $this->hook && $screen && $screen->id === $this->hook ) {
			$classes .= ' bs-setup-page bs-ds-body';
		}

		return (string) $classes;
	}

	/**
	 * The root the bundle mounts into, holding a quiet stand-in until it does
	 * and a plain explanation for a browser that runs no scripts.
	 */
	public function render(): void {
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to open the Quick Setup.', 'bettershield' ) );
		}
		?>
		<div id="bettershield-setup" class="bs-ds-setup-mount">
			<div class="bs-ds-setup-boot" role="status" aria-live="polite">
				<span class="screen-reader-text"><?php esc_html_e( 'Loading the Quick Setup…', 'bettershield' ); ?></span>
			</div>
			<noscript>
				<p class="bs-ds-setup-noscript">
					<?php esc_html_e( 'The Quick Setup needs JavaScript. Everything it offers is also on the BetterShield screens.', 'bettershield' ); ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . Sections::ROOT ) ); ?>"><?php esc_html_e( 'Go to BetterShield', 'bettershield' ); ?></a>
				</p>
			</noscript>
		</div>
		<?php
	}

	public function enqueue( string $hook ): void {
		if ( '' === $this->hook || $hook !== $this->hook ) {
			return;
		}

		$asset_file = BETTERSHIELD_PATH . '/assets/build/setup.asset.php';

		if ( ! is_file( $asset_file ) ) {
			return;
		}

		$asset = require $asset_file;
		$deps  = $asset['dependencies'];

		if ( wp_script_is( 'wp-theme', 'registered' ) ) {
			$deps[] = 'wp-theme';
		}

		wp_enqueue_script( 'bettershield-setup', plugins_url( 'assets/build/setup.js', BETTERSHIELD_FILE ), $deps, $asset['version'], true );

		/*
		 * Two globals: the shared artwork and brand name the app's own
		 * components read, and the setup's state. The state travels with the
		 * page so the first step paints without a round trip. Escaped for a
		 * script context for the reason Menu::enqueue_app gives.
		 */
		$flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;

		// Before any step can show a score the check could still move.
		if ( ! QuickSetup::is_done() ) {
			FirstScan::begin( true );
		}

		wp_add_inline_script(
			'bettershield-setup',
			'window.bettershield = ' . wp_json_encode(
				array(
					'assetsUrl' => plugins_url( 'assets/images/', BETTERSHIELD_FILE ),
					'brand'     => \BetterShield\Support\Branding::name(),
					'helpLinks' => ! \BetterShield\Support\Branding::hides_help_links(),
					'version'   => BETTERSHIELD_VERSION,
				),
				$flags
			) . ';' .
			'window.bettershieldSetup = ' . wp_json_encode(
				array(
					'state' => QuickSetup::payload( QuickSetup::is_done() && 'ready' === QuickSetup::state()['step'] ),
					'links' => self::links(),
					'site'  => wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ),
				),
				$flags
			) . ';',
			'before'
		);

		wp_set_script_translations( 'bettershield-setup', 'bettershield', BETTERSHIELD_PATH . '/languages' );

		$style_deps = array( 'wp-components' );

		if ( wp_style_is( 'wp-theme', 'registered' ) ) {
			$style_deps[] = 'wp-theme';
		}

		$style_path = BETTERSHIELD_PATH . '/assets/build/setup.css';

		wp_enqueue_style(
			'bettershield-setup',
			plugins_url( 'assets/build/setup.css', BETTERSHIELD_FILE ),
			$style_deps,
			is_file( $style_path ) ? (string) filemtime( $style_path ) : BETTERSHIELD_VERSION
		);
		wp_style_add_data( 'bettershield-setup', 'rtl', 'replace' );
	}

	/**
	 * The screens the setup points at. Built here because the URLs are
	 * WordPress's to construct.
	 *
	 * @return array<string, string>
	 */
	private static function links(): array {
		$section = static fn( string $slug, string $tab = '' ): string => '' === $tab
			? admin_url( 'admin.php?page=' . $slug )
			: add_query_arg( 'tab', $tab, admin_url( 'admin.php?page=' . $slug ) );

		return array(
			'dashboard' => $section( Sections::ROOT ),
			'activity'  => $section( 'bettershield-activity' ),
			'hub'       => $section( Sections::HUB ),
			'hardening' => $section( 'bettershield-protect', 'hardening' ),
			'login'     => $section( 'bettershield-protect', 'login' ),
			'twoFactor' => $section( 'bettershield-protect', 'two-factor' ),
			'recovery'  => $section( 'bettershield-protect', 'recovery' ),
			'alerts'    => $section( 'bettershield-settings', 'alerts' ),
			'settings'  => $section( 'bettershield-settings', 'general' ),
			'agents'    => $section( Sections::AGENTS, 'permissions' ),
			'plugins'   => admin_url( 'plugins.php?plugin_status=active' ),
			// Only for an account that can use it.
			'networkPlugins' => is_multisite() && current_user_can( 'manage_network_plugins' ) ? network_admin_url( 'plugins.php?plugin_status=active' ) : '',
		);
	}
}
