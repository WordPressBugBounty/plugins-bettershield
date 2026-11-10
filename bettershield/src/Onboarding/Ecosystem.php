<?php
/**
 * Other plugins from the same publisher, offered once and never pushed.
 *
 * Nothing is switched on in advance: each card has its own switch, and the
 * plugins the owner switches on are installed and activated one at a time
 * when they continue, through WordPress's own installer, from the
 * WordPress.org directory. A plugin that is already installed is not offered
 * at all, and the whole step is left out for anybody who cannot install
 * plugins here.
 *
 * At most three are recommended, each for a reason this site's own setup
 * gives; the rest are listed once below them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Ecosystem {

	/** How many plugins may be recommended at once. */
	private const MAX_RECOMMENDED = 3;

	/**
	 * Plugin directories whose presence means an SEO plugin is already doing
	 * that job.
	 */
	private const SEO_PLUGINS = array( 'wordpress-seo', 'wordpress-seo-premium', 'seo-by-rank-math', 'seo-by-rank-math-pro', 'all-in-one-seo-pack', 'all-in-one-seo-pack-pro', 'wp-seopress', 'wp-seopress-pro', 'autodescription' );

	/** The same, for page caching. */
	private const CACHE_PLUGINS = array( 'wp-rocket', 'litespeed-cache', 'w3-total-cache', 'wp-super-cache', 'wp-optimize' );

	/** Plugins that put the classic editor back in place of the block editor. */
	private const CLASSIC_EDITORS = array( 'classic-editor', 'disable-gutenberg', 'classic-editor-addon' );

	/**
	 * The plugins whose own icon ships in assets/images/ecosystem, by slug.
	 *
	 * Shipped rather than fetched, because the page asking an outside server
	 * for images would be a request the owner never agreed to. A plugin not
	 * listed here is drawn with its initials instead.
	 */
	private const ICONS = array( 'essential-addons-for-elementor-lite', 'templately', 'essential-blocks', 'embedpress', 'betterdocs', 'notificationx', 'betterlinks', 'wp-scheduled-posts', 'better-payment', 'easyjobs', 'thinkrank', 'xspeed' );

	/**
	 * The publisher's plugins, keyed by their WordPress.org directory slug, in
	 * the order the list shows them.
	 *
	 * @return array<string, array{name: string, description: string, short: string}>
	 */
	public static function catalog(): array {
		return array(
			'essential-addons-for-elementor-lite' => array(
				'name'        => 'Essential Addons',
				'description' => __( 'Over a hundred widgets and extensions for Elementor.', 'bettershield' ),
				'short'       => __( 'Widgets for Elementor', 'bettershield' ),
			),
			'templately'                          => array(
				'name'        => 'Templately',
				'description' => __( 'Ready-made templates for Elementor and the block editor.', 'bettershield' ),
				'short'       => __( 'Ready-made templates', 'bettershield' ),
			),
			'essential-blocks'                    => array(
				'name'        => 'Essential Blocks',
				'description' => __( 'Extra blocks and patterns for the block editor.', 'bettershield' ),
				'short'       => __( 'Blocks and patterns', 'bettershield' ),
			),
			'embedpress'                          => array(
				'name'        => 'EmbedPress',
				'description' => __( 'Embed videos, documents, maps and more from over 100 sources.', 'bettershield' ),
				'short'       => __( 'Embed from 100+ sources', 'bettershield' ),
			),
			'betterdocs'                          => array(
				'name'        => 'BetterDocs',
				'description' => __( 'A searchable documentation and knowledge base for your site.', 'bettershield' ),
				'short'       => __( 'Docs and knowledge base', 'bettershield' ),
			),
			'notificationx'                       => array(
				'name'        => 'NotificationX',
				'description' => __( 'Show recent sales, reviews and announcements as small notices.', 'bettershield' ),
				'short'       => __( 'Sales and review notices', 'bettershield' ),
			),
			'betterlinks'                         => array(
				'name'        => 'BetterLinks',
				'description' => __( 'Short links with click counts, managed from your dashboard.', 'bettershield' ),
				'short'       => __( 'Short links with clicks', 'bettershield' ),
			),
			'wp-scheduled-posts'                  => array(
				'name'        => 'SchedulePress',
				'description' => __( 'A calendar for planning and scheduling your posts.', 'bettershield' ),
				'short'       => __( 'Plan and schedule posts', 'bettershield' ),
			),
			'thinkrank'                           => array(
				'name'        => 'ThinkRank',
				'description' => __( 'SEO settings, sitemaps and content suggestions for your pages.', 'bettershield' ),
				'short'       => __( 'SEO and sitemaps', 'bettershield' ),
			),
			'xspeed'                              => array(
				'name'        => 'xSpeed',
				'description' => __( 'Page caching and other speed improvements for your site.', 'bettershield' ),
				'short'       => __( 'Page caching', 'bettershield' ),
			),
			'better-payment'                      => array(
				'name'        => 'Better Payment',
				'description' => __( 'Take payments through PayPal and Stripe on Elementor forms.', 'bettershield' ),
				'short'       => __( 'PayPal and Stripe forms', 'bettershield' ),
			),
			'easyjobs'                            => array(
				'name'        => 'easy.jobs',
				'description' => __( 'Post jobs and manage applicants from your own site.', 'bettershield' ),
				'short'       => __( 'Jobs and applicants', 'bettershield' ),
			),
		);
	}

	/**
	 * Whether this person may be offered installs at all.
	 *
	 * No file modifications, no install capability or no activate capability
	 * each mean the button could only fail, and a button that can only fail is
	 * not offered. On a network that rules out a subsite's own administrator,
	 * which is where core puts installing.
	 */
	public static function available(): bool {
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			return false;
		}

		// An owner who labeled the chrome as their own and asked for this
		// plugin's links to be left out is not offered its publisher's.
		if ( \BetterShield\Support\Branding::hides_help_links() ) {
			return false;
		}

		return current_user_can( 'install_plugins' ) && current_user_can( 'activate_plugins' );
	}

	/**
	 * Directory slugs of every plugin installed here, active or not.
	 *
	 * @return string[]
	 */
	private static function installed_slugs(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$slugs = array();

		foreach ( array_keys( get_plugins() ) as $file ) {
			$slugs[] = false === strpos( (string) $file, '/' ) ? basename( (string) $file, '.php' ) : dirname( (string) $file );
		}

		return array_values( array_unique( $slugs ) );
	}

	/**
	 * Directory slugs of the plugins active here, network-wide ones included.
	 *
	 * @return string[]
	 */
	private static function active_slugs(): array {
		$files = (array) get_option( 'active_plugins', array() );

		if ( is_multisite() ) {
			$files = array_merge( $files, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}

		return array_values(
			array_unique(
				array_map(
					static fn( $file ): string => dirname( (string) $file ),
					$files
				)
			)
		);
	}

	/**
	 * The recommendations this site's setup gives, in priority order, before
	 * anything already installed is taken out.
	 *
	 * @return array<string, string> Slug => why it is recommended.
	 */
	private static function reasons(): array {
		$active    = self::active_slugs();
		$elementor = in_array( 'elementor', $active, true ) || defined( 'ELEMENTOR_VERSION' );
		$reasons   = array();

		if ( array() === array_intersect( self::SEO_PLUGINS, $active ) ) {
			$reasons['thinkrank'] = __( 'No SEO plugin is active.', 'bettershield' );
		}

		if ( array() === array_intersect( self::CACHE_PLUGINS, $active ) ) {
			$reasons['xspeed'] = __( 'No caching plugin is active.', 'bettershield' );
		}

		if ( $elementor ) {
			$reasons['essential-addons-for-elementor-lite'] = __( 'Elementor is active.', 'bettershield' );
			$reasons['templately']                          = __( 'Elementor is active.', 'bettershield' );
		} elseif ( array() === array_intersect( self::CLASSIC_EDITORS, $active ) ) {
			// Only where the block editor is the editor: with Classic Editor
			// active, pages do not use it and the blocks are not there (#2144).
			$reasons['essential-blocks'] = __( 'Your pages are built with the block editor.', 'bettershield' );
		}

		if ( in_array( 'woocommerce', $active, true ) || class_exists( 'WooCommerce' ) ) {
			$reasons['notificationx'] = __( 'WooCommerce is active.', 'bettershield' );
		}

		return $reasons;
	}

	/**
	 * Both lists, each plugin in at most one of them, installed plugins in
	 * neither.
	 *
	 * @return array{recommended: array<int, array<string, string>>, more: array<int, array<string, string>>}
	 */
	public static function lists(): array {
		$catalog   = self::catalog();
		$installed = self::installed_slugs();
		$reasons   = self::reasons();

		$recommended = array();

		foreach ( $reasons as $slug => $why ) {
			if ( count( $recommended ) >= self::MAX_RECOMMENDED ) {
				break;
			}

			if ( ! isset( $catalog[ $slug ] ) || in_array( $slug, $installed, true ) ) {
				continue;
			}

			$recommended[ $slug ] = self::card( $slug, $catalog[ $slug ], $why );
		}

		$more = array();

		foreach ( $catalog as $slug => $plugin ) {
			if ( isset( $recommended[ $slug ] ) || in_array( $slug, $installed, true ) ) {
				continue;
			}

			$more[] = self::card( $slug, $plugin, '' );
		}

		return array(
			'recommended' => array_values( $recommended ),
			'more'        => $more,
		);
	}

	/**
	 * @param array{name: string, description: string} $plugin
	 * @return array<string, string>
	 */
	private static function card( string $slug, array $plugin, string $why ): array {
		return array(
			'slug'        => $slug,
			'name'        => $plugin['name'],
			'description' => $plugin['description'],
			// The one line the compact list shows; the description stays
			// for the tooltip and screen readers.
			'short'       => $plugin['short'] ?? $plugin['description'],
			'why'         => $why,
			'url'         => 'https://wordpress.org/plugins/' . $slug . '/',
			'icon'        => in_array( $slug, self::ICONS, true ) ? plugins_url( 'assets/images/ecosystem/' . $slug . '.svg', BETTERSHIELD_FILE ) : '',
		);
	}

	/**
	 * Install one plugin from the directory and activate it.
	 *
	 * The work is WordPress's own: the same installer the Add Plugins screen
	 * uses, asking the directory for the package and unpacking it the way core
	 * does. A failure — file permissions, a host with no way out, a package
	 * the directory would not give, a plugin that would not switch on — comes
	 * back as a sentence the step shows beside that one card, and the setup
	 * carries on.
	 *
	 * Only a fresh copy is installed and switched on. A copy already on disk
	 * may be any version and may have been changed, and the step never offers
	 * one, so this route refuses it rather than activating it as it stands:
	 * it is the owner's to review, update and switch on from the Plugins
	 * screen.
	 *
	 * @return array{status: string}|\WP_Error
	 */
	public static function install( string $slug ) {
		if ( ! isset( self::catalog()[ $slug ] ) ) {
			return new \WP_Error( 'bettershield_not_offered', __( 'That plugin is not one this setup offers.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( ! self::available() ) {
			return new \WP_Error( 'bettershield_cannot_install', __( 'Your account cannot install plugins on this site.', 'bettershield' ), array( 'status' => 403 ) );
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

		$file = self::installed_file( $slug );

		if ( null !== $file ) {
			if ( is_plugin_active( $file ) ) {
				return array( 'status' => 'active' );
			}

			return new \WP_Error(
				'bettershield_already_installed',
				__( 'This plugin is installed but switched off. Update and activate it from the Plugins screen.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$api = plugins_api(
			'plugin_information',
			array(
				'slug'   => $slug,
				'fields' => array( 'sections' => false ),
			)
		);

		if ( is_wp_error( $api ) || empty( $api->download_link ) ) {
			return new \WP_Error(
				'bettershield_install_failed',
				__( 'WordPress.org could not be reached for this plugin.', 'bettershield' ),
				array( 'status' => 502 )
			);
		}

		$skin     = new \WP_Ajax_Upgrader_Skin();
		$upgrader = new \Plugin_Upgrader( $skin );
		$result   = $upgrader->install( (string) $api->download_link );

		if ( is_wp_error( $result ) ) {
			return self::failed( $result->get_error_message() );
		}

		if ( is_wp_error( $skin->result ) ) {
			return self::failed( $skin->result->get_error_message() );
		}

		if ( ! $result ) {
			$errors = $skin->get_errors();

			return self::failed( $errors instanceof \WP_Error && $errors->has_errors() ? $errors->get_error_message() : '' );
		}

		$file = $upgrader->plugin_info();

		if ( ! is_string( $file ) || '' === $file ) {
			return self::failed( '' );
		}

		$done = self::activate( $file );

		// Something the setup did, which Ready names (#2117).
		if ( ! is_wp_error( $done ) ) {
			QuickSetup::note_installed( $slug );
		}

		return $done;
	}

	/**
	 * Switch on a plugin this setup has just installed.
	 *
	 * A plugin that will not switch on is a failure the owner has to hear
	 * about, with WordPress's own reason: reporting it as installed let the
	 * step say every plugin chosen was active when one was not.
	 *
	 * @return array{status: string}|\WP_Error
	 */
	private static function activate( string $file ) {
		if ( is_plugin_active( $file ) ) {
			return array( 'status' => 'active' );
		}

		$activated = activate_plugin( $file );

		/*
		 * Switched on and then found to have printed something: WordPress
		 * writes the active list before it looks at the output, and answers
		 * with an error for a plugin that is running. Its own Plugins screen
		 * leaves it active with a notice, and so does this.
		 */
		if ( is_wp_error( $activated ) && is_plugin_active( $file ) ) {
			return array( 'status' => 'active' );
		}

		if ( is_wp_error( $activated ) ) {
			$message = __( 'The plugin was installed but could not be switched on. Activate it from the Plugins screen.', 'bettershield' );
			$reason  = wp_strip_all_tags( $activated->get_error_message() );

			return new \WP_Error(
				'bettershield_activation_failed',
				'' !== $reason ? $message . ' ' . $reason : $message,
				array( 'status' => 500 )
			);
		}

		return array( 'status' => 'active' );
	}

	/**
	 * A failed install, in words the step can show beside the card.
	 */
	private static function failed( string $detail ): \WP_Error {
		$message = __( 'The plugin could not be installed, usually because of server file permissions.', 'bettershield' );

		if ( '' !== $detail ) {
			$message .= ' ' . wp_strip_all_tags( $detail );
		}

		return new \WP_Error( 'bettershield_install_failed', $message, array( 'status' => 500 ) );
	}

	private static function installed_file( string $slug ): ?string {
		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( 0 === strpos( (string) $file, $slug . '/' ) ) {
				return (string) $file;
			}
		}

		return null;
	}
}
