<?php
/**
 * Two-factor, passkeys and signed-in devices on a page of the owner's choosing.
 *
 * A site that keeps members out of wp-admin, with no store to offer them My
 * Account, had nowhere they could set any of this up, and a rule naming their
 * role asked for something they could not give. The same three panels the
 * store's tab draws go on a page through a shortcode or a block, against the
 * same REST routes: nothing here is a second way of enrolling.
 *
 * The owner picks the page. With none picked, every link stays as it was.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\TwoFactor\Policy as TwoFactorPolicy;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AccountPage {

	public const SHORTCODE = 'bettershield_account';

	public const BLOCK = 'bettershield/account';

	/** The editor script's handle. */
	private const EDITOR_SCRIPT = 'bettershield-account-block';

	private static ?AccountPage $instance = null;

	public static function instance(): AccountPage {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'init', array( $this, 'register_surfaces' ) );
	}

	public function register_surfaces(): void {
		add_shortcode( self::SHORTCODE, array( $this, 'render' ) );

		$asset_file = BETTERSHIELD_PATH . '/assets/build/account-block.asset.php';
		$asset      = is_file( $asset_file ) ? require $asset_file : array(
			'dependencies' => array(),
			'version'      => BETTERSHIELD_VERSION,
		);

		wp_register_script(
			self::EDITOR_SCRIPT,
			plugins_url( 'assets/build/account-block.js', BETTERSHIELD_FILE ),
			$asset['dependencies'],
			(string) $asset['version'],
			true
		);
		wp_set_script_translations( self::EDITOR_SCRIPT, 'bettershield', BETTERSHIELD_PATH . '/languages' );

		register_block_type(
			self::BLOCK,
			array(
				'api_version'     => 3,
				'title'           => __( 'Sign-in Security', 'bettershield' ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'editor_script'   => self::EDITOR_SCRIPT,
				'render_callback' => array( $this, 'render' ),
				'supports'        => array( 'html' => false ),
			)
		);
	}

	/**
	 * The panels for whoever is signed in, and one line for anyone who isn't.
	 * The bundle loads from here because a page builder's shortcode widget
	 * can't be found in the post's content ahead of time.
	 */
	public function render(): string {
		// A page builder's editor asks for this from wp-admin or the REST API.
		if ( is_admin() || wp_is_serving_rest_request() ) {
			return '<p>' . esc_html__( 'Two-factor, passkeys and signed-in devices appear here for people who are signed in.', 'bettershield' ) . '</p>';
		}

		// The panels carry a nonce, which a cached copy would serve stale.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}

		if ( ! is_user_logged_in() ) {
			return '<p>' . sprintf(
				/* translators: %s: the address of the sign-in page. */
				wp_kses( __( '<a href="%s">Sign in</a> to manage your two-factor, passkeys and signed-in devices.', 'bettershield' ), array( 'a' => array( 'href' => array() ) ) ),
				esc_url( wp_login_url( (string) get_permalink() ) )
			) . '</p>';
		}

		StoreAccount::enqueue_panels();

		ob_start();
		StoreAccount::instance()->render();

		return (string) ob_get_clean();
	}

	/** The chosen page's address, or '' when there is no page to send anyone to. */
	public static function url(): string {
		$post = get_post( TwoFactorPolicy::instance()->settings()['account_page'] );

		return self::usable( $post ) ? (string) get_permalink( $post ) : '';
	}

	/**
	 * Whether a page can be sent to: one nobody needs a password or a role to
	 * open, because a link to anything else is a dead end for a member.
	 *
	 * @param mixed $post What was read for the setting.
	 */
	public static function usable( $post ): bool {
		return $post instanceof \WP_Post && 'page' === $post->post_type && 'publish' === $post->post_status && '' === $post->post_password;
	}

	/**
	 * Where an account's own sign-in settings are, for one that has no way
	 * into the dashboard; null for every other account, or with no page.
	 *
	 * @param string $fragment Which panel to open at, without the `#`.
	 */
	public static function url_for( \WP_User $user, string $fragment = '' ): ?string {
		foreach ( StoreAccount::ADMIN_CAPS as $capability ) {
			if ( user_can( $user, $capability ) ) {
				return null;
			}
		}

		$url = 0 === (int) $user->ID ? '' : self::url();

		if ( '' === $url ) {
			return null;
		}

		return '' === $fragment ? $url : $url . '#' . $fragment;
	}

	/**
	 * The front-end home of an account's sign-in settings: My Account, then
	 * the chosen page. Null means profile.php is the place.
	 *
	 * @param string $fragment Which panel to open at, without the `#`.
	 */
	public static function front_end_url( \WP_User $user, string $fragment = '' ): ?string {
		return StoreAccount::url_for( $user, $fragment ) ?? self::url_for( $user, $fragment );
	}

	/**
	 * The pages the owner can choose from, by title, with the one in force
	 * kept in the list however far down it falls.
	 *
	 * @return array<int, array{id: int, title: string}>
	 */
	public static function choices(): array {
		$pages = get_pages(
			array(
				'post_status'  => 'publish',
				'sort_column'  => 'post_title',
				'number'       => 200,
				'hierarchical' => false,
			)
		);
		$pages = is_array( $pages ) ? $pages : array();
		$saved = get_post( TwoFactorPolicy::instance()->settings()['account_page'] );

		if ( self::usable( $saved ) && ! in_array( (int) $saved->ID, array_map( 'intval', wp_list_pluck( $pages, 'ID' ) ), true ) ) {
			$pages[] = $saved;
		}

		$out = array();

		foreach ( $pages as $page ) {
			if ( self::usable( $page ) ) {
				$out[] = array(
					'id'    => (int) $page->ID,
					'title' => '' === $page->post_title ? '#' . $page->ID : wp_specialchars_decode( $page->post_title, ENT_QUOTES ),
				);
			}
		}

		return $out;
	}
}
