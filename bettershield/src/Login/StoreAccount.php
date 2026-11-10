<?php
/**
 * Two-factor, passkeys and signed-in devices on a store's My Account page.
 *
 * WooCommerce sends every account that cannot edit posts, manage the store or
 * view the dashboard away from wp-admin, profile.php included, to My Account.
 * That is where a customer lives, and profile.php is where every panel this
 * plugin offers a person about their own sign-in was drawn. So a customer
 * could not set up two-factor or add a passkey anywhere, and a policy that
 * named their role asked them for something they had no way to give.
 *
 * This draws the same three panels on a My Account tab of its own, against the
 * same REST routes, which any signed-in browser session already satisfies:
 * nothing here is a second way of enrolling. And for an account WooCommerce
 * keeps out, the links that pointed at profile.php point here.
 *
 * It stays off the cart and the checkout entirely: nothing is added to them,
 * and nothing is loaded on them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Network\Policies as NetworkPolicies;
use BetterShield\Passkeys\Policy as PasskeyPolicy;
use BetterShield\Passkeys\ProfilePanel as PasskeysPanel;
use BetterShield\Passkeys\Store as PasskeyStore;
use BetterShield\TwoFactor\Manager as TwoFactorManager;
use BetterShield\TwoFactor\Policy as TwoFactorPolicy;
use BetterShield\TwoFactor\ProfilePanel as TwoFactorPanel;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class StoreAccount {

	/** The My Account endpoint, and the tab's address under it. */
	public const ENDPOINT = 'sign-in-security';

	/**
	 * The capabilities any one of which WooCommerce accepts as a reason to let
	 * an account into wp-admin. Without all three, it is sent to My Account.
	 */
	public const ADMIN_CAPS = array( 'edit_posts', 'manage_woocommerce', 'view_admin_dashboard' );

	/** Whether kept_out() is the one asking WooCommerce's filter. */
	private static bool $asking = false;

	/**
	 * This plugin's own capabilities, each a reason to open its screens. A
	 * site grants one to a role on purpose, so the role can read the posture
	 * or manage it without being a store manager.
	 */
	private const OWN_CAPS = array( \BetterShield\Capabilities::READ_POSTURE, \BetterShield\Capabilities::MANAGE, \BetterShield\Capabilities::READ_ACTIVITY );

	/**
	 * Which version of the endpoint's rewrite rule this site has written, so a
	 * new endpoint is flushed in once and never on a visitor's request.
	 */
	public const RULES_OPTION = 'bettershield_store_endpoint';

	private static ?StoreAccount $instance = null;

	public static function instance(): StoreAccount {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_filter( 'woocommerce_get_query_vars', array( $this, 'query_vars' ) );
		add_filter( 'woocommerce_account_menu_items', array( $this, 'menu_items' ) );
		add_filter( 'woocommerce_endpoint_' . self::ENDPOINT . '_title', array( $this, 'title' ) );
		add_action( 'woocommerce_account_' . self::ENDPOINT . '_endpoint', array( $this, 'render' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_init', array( $this, 'maybe_write_rules' ) );
		// WooCommerce's own word on who stays out of wp-admin.
		add_filter( 'woocommerce_prevent_admin_access', array( $this, 'let_in_holders' ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce's hook, answered for our own capabilities.
	}

	/**
	 * Whether a store is here to draw on at all.
	 *
	 * The store announcing itself, rather than its functions merely existing:
	 * WooCommerce fires `woocommerce_init` once it is loaded, before anything
	 * here asks, and a copy of its functions without the store behind them
	 * answers nothing.
	 */
	public static function available(): bool {
		return did_action( 'woocommerce_init' ) > 0 && function_exists( 'wc_get_account_endpoint_url' ) && function_exists( 'is_account_page' );
	}

	/**
	 * Whether WooCommerce keeps this account out of wp-admin, so that
	 * profile.php is a page it can never reach.
	 *
	 * The same test WooCommerce makes: none of its three capabilities, and its
	 * own filter left to have the last word.
	 */
	public static function kept_out( \WP_User $user ): bool {
		if ( ! self::available() || 0 === (int) $user->ID ) {
			return false;
		}

		$prevent = true;

		foreach ( array_merge( self::ADMIN_CAPS, self::OWN_CAPS ) as $capability ) {
			if ( user_can( $user, $capability ) ) {
				$prevent = false;
				break;
			}
		}

		/*
		 * This filter is WooCommerce's own. Asked here about $user, who may
		 * not be the current user, so this plugin's own answer to it, which
		 * reads the current user, stands aside: the loop above already
		 * counted our capabilities for the account in question.
		 */
		self::$asking = true;

		try {
			return (bool) apply_filters( 'woocommerce_prevent_admin_access', $prevent ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce's hook, asked the question it answers.
		} finally {
			self::$asking = false;
		}
	}

	/**
	 * A role given only this plugin's capabilities was sent to My Account by
	 * WooCommerce and never reached BetterShield: its rule lets in only the
	 * store's editing and management capabilities. Somebody holding one of
	 * ours is let into wp-admin, where those screens are.
	 *
	 * @param mixed $prevent What WooCommerce decided.
	 */
	public function let_in_holders( $prevent ): bool {
		if ( ! $prevent || self::$asking ) {
			return (bool) $prevent;
		}

		foreach ( self::OWN_CAPS as $capability ) {
			if ( current_user_can( $capability ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Whether a role, as the site defines it, is kept out of wp-admin by
	 * WooCommerce: what a role picker needs to warn about.
	 */
	public static function role_kept_out( string $role ): bool {
		if ( ! self::available() ) {
			return false;
		}

		$object = get_role( $role );

		if ( ! $object instanceof \WP_Role ) {
			return false;
		}

		foreach ( array_merge( self::ADMIN_CAPS, self::OWN_CAPS ) as $capability ) {
			if ( $object->has_cap( $capability ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Where an account's own sign-in settings are, for an account WooCommerce
	 * keeps out of wp-admin; null for every other account.
	 *
	 * @param string $fragment Which panel to open at, without the `#`.
	 */
	public static function url_for( \WP_User $user, string $fragment = '' ): ?string {
		if ( ! self::kept_out( $user ) ) {
			return null;
		}

		$url = (string) wc_get_account_endpoint_url( self::ENDPOINT );

		return '' === $fragment ? $url : $url . '#' . $fragment;
	}

	/**
	 * @param array<string, string> $vars
	 * @return array<string, string>
	 */
	public function query_vars( $vars ): array {
		$vars                   = is_array( $vars ) ? $vars : array();
		$vars[ self::ENDPOINT ] = self::ENDPOINT;

		return $vars;
	}

	/**
	 * The tab, placed before "Log out" so it reads with the account's own
	 * settings rather than after the way out. Left off, items untouched, when
	 * the owner has turned it off and this account has no need of it.
	 *
	 * @param array<string, string> $items
	 * @return array<string, string>
	 */
	public function menu_items( $items ): array {
		$items = is_array( $items ) ? $items : array();

		if ( ! TwoFactorPolicy::instance()->settings()['store_tab'] && ! self::needs_tab( wp_get_current_user() ) ) {
			return $items;
		}

		$label = __( 'Sign-in security', 'bettershield' );

		if ( ! isset( $items['customer-logout'] ) ) {
			$items[ self::ENDPOINT ] = $label;

			return $items;
		}

		$out = array();

		foreach ( $items as $key => $value ) {
			if ( 'customer-logout' === $key ) {
				$out[ self::ENDPOINT ] = $label;
			}

			$out[ $key ] = $value;
		}

		return $out;
	}

	/**
	 * Whether this account needs the tab whatever the owner chose: a rule asks
	 * a second factor or a passkey of it, or it already holds one it may have
	 * to renew or remove. Hiding the tab from it would leave it nowhere to go.
	 */
	public static function needs_tab( \WP_User $user ): bool {
		$user_id = (int) $user->ID;

		if ( 0 === $user_id ) {
			return false;
		}

		if ( TwoFactorManager::instance()->enabled( $user_id ) || PasskeyStore::count_for_user( $user_id ) > 0 || PasskeyPolicy::instance()->applies_to( $user ) ) {
			return true;
		}

		// The roles an add-on asks two-factor of under rules of its own.
		$elsewhere = apply_filters( 'bettershield_two_factor_roles_required_elsewhere', array() );
		$required  = array_merge(
			NetworkPolicies::effective_two_factor_roles( TwoFactorPolicy::instance()->settings()['roles'] ),
			array_map( 'strval', is_array( $elsewhere ) ? $elsewhere : array() )
		);

		return array() !== array_intersect( (array) $user->roles, $required );
	}

	/**
	 * @param mixed $title
	 * @return mixed
	 */
	public function title( $title ) {
		return __( 'Sign-in security', 'bettershield' );
	}

	/**
	 * The three panels profile.php carries, drawn the same way: the markup
	 * each panel's own class writes, driven by the same script.
	 */
	public function render(): void {
		$user = wp_get_current_user();

		if ( ! $user instanceof \WP_User || 0 === (int) $user->ID ) {
			return;
		}

		echo '<div class="bs-store-account">';
		TwoFactorPanel::instance()->render( $user );
		PasskeysPanel::instance()->render( $user );
		MySessions::instance()->render_in_store();
		echo '</div>';
	}

	/**
	 * The profile bundle, on this tab only. The cart and the checkout never
	 * load it, and neither does any other My Account tab.
	 */
	public function assets(): void {
		if ( $this->on_endpoint() ) {
			self::enqueue_panels();
		}
	}

	/** The profile bundle the panels run on, for wherever they are drawn. */
	public static function enqueue_panels(): void {
		$asset_file = BETTERSHIELD_PATH . '/assets/build/profile.asset.php';
		$asset      = is_file( $asset_file ) ? require $asset_file : array(
			'dependencies' => array(),
			'version'      => BETTERSHIELD_VERSION,
		);

		wp_enqueue_script(
			'bettershield-profile',
			plugins_url( 'assets/build/profile.js', BETTERSHIELD_FILE ),
			$asset['dependencies'],
			(string) $asset['version'],
			true
		);
		wp_set_script_translations( 'bettershield-profile', 'bettershield', BETTERSHIELD_PATH . '/languages' );

		wp_enqueue_style(
			'bettershield-profile',
			plugins_url( 'assets/build/profile.css', BETTERSHIELD_FILE ),
			array(),
			(string) $asset['version']
		);
		wp_style_add_data( 'bettershield-profile', 'rtl', 'replace' );
	}

	private function on_endpoint(): bool {
		if ( ! self::available() || ! is_user_logged_in() || ! function_exists( 'is_wc_endpoint_url' ) ) {
			return false;
		}

		return is_account_page() && is_wc_endpoint_url( self::ENDPOINT );
	}

	/**
	 * Write the endpoint's rewrite rule once, from the dashboard.
	 *
	 * WooCommerce registers its endpoints on every request, but a new one is
	 * only reachable at its pretty address after the rules are written again.
	 * Doing that from an admin request, once per version of the rule, keeps
	 * the write off every visitor's request.
	 */
	public function maybe_write_rules(): void {
		/*
		 * `admin_init` also fires on admin-ajax.php and admin-post.php with
		 * nobody signed in, and a store's own queue runner reaches the first
		 * about once a minute. Somebody's dashboard visit is what this waits
		 * for, so a request that is not one reads nothing.
		 */
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		if ( ! self::available() || self::ENDPOINT === get_option( self::RULES_OPTION ) ) {
			return;
		}

		if ( is_multisite() && ms_is_switched() ) {
			return;
		}

		flush_rewrite_rules( false );
		update_option( self::RULES_OPTION, self::ENDPOINT, false );
	}
}
