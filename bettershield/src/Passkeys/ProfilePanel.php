<?php
/**
 * Adding and removing a passkey on a person's own profile screen.
 *
 * **It lives on the profile screen, not on this plugin's own.** Every screen
 * this plugin draws needs a capability an author or an editor does not have,
 * and the passkey-only policy can name any role on the site — so without this
 * panel a named role was told its password was about to stop working and had
 * nowhere at all to enroll the credential that would replace it.
 *
 * **No `<form>` element is rendered.** `show_user_profile` fires inside core's
 * own profile form, and a nested form start tag is dropped by the HTML parser
 * — its buttons would submit the profile form instead. The panel drives the
 * plugin's existing REST passkey routes, which any signed-in browser session
 * satisfies, the way core's Application Passwords section drives its own.
 *
 * An administrator cannot enroll a passkey for somebody else — the credential
 * is made by the device in front of whoever is at the keyboard — so on
 * somebody else's profile, `edit_user_profile`, this offers one thing only:
 * removing the passkeys an account holds, for a holder who has lost the
 * device and, under passkey-only, has no password to fall back on.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Passkeys;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProfilePanel {

	private static ?ProfilePanel $instance = null;

	public static function instance(): ProfilePanel {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render_for_administrator' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	/**
	 * What an administrator sees on somebody else's profile.
	 *
	 * Says what is true of the account either way, and draws the control only
	 * where it would do something and for somebody the route would also let
	 * through — the route re-checks, and this decides whether to offer.
	 */
	public function render_for_administrator( \WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', (int) $user->ID ) ) {
			return;
		}

		$count = Store::count_for_user( (int) $user->ID );

		// Nothing to say about a feature this site does not offer, to an
		// account that never used it.
		if ( 0 === $count && ! Manager::availability()['available'] ) {
			return;
		}

		echo '<h2 id="bettershield-passkeys">' . esc_html__( 'Passkeys', 'bettershield' ) . '</h2>';

		if ( 0 === $count ) {
			echo '<p class="description">' . esc_html__( 'This user has no passkeys. Only they can add one, from their own profile.', 'bettershield' ) . '</p>';

			return;
		}

		if ( ! $this->may_remove( (int) $user->ID ) ) {
			echo '<p class="description">' . esc_html(
				\BetterShield\Rest\PasskeyController::may_remove_across_sites()
					? __( 'This user signs in with passkeys. If they lose their device, a BetterShield administrator can remove them.', 'bettershield' )
					: __( 'This account uses passkeys, which work network-wide. Only a network administrator can remove them.', 'bettershield' )
			) . '</p>';

			return;
		}

		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: %d: how many passkeys the account holds. */
				_n(
					'This user has %d passkey. Removing it lets them sign in with their password.',
					'This user has %d passkeys. Removing them lets them sign in with their password.',
					$count,
					'bettershield'
				),
				$count
			)
		) . '</p>';

		printf(
			'<div id="bettershield-passkeys-admin-remove" class="bs-profile-2fa" data-user="%d"></div>',
			(int) $user->ID
		);
		echo '<noscript><p>' . esc_html__( 'Removing someone’s passkeys needs JavaScript on this page.', 'bettershield' ) . '</p></noscript>';
	}

	/** Whether the route behind the control would let the signed-in account through. */
	private function may_remove( int $user_id ): bool {
		return get_current_user_id() !== $user_id
			&& current_user_can( 'edit_user', $user_id )
			&& current_user_can( \BetterShield\Capabilities::MANAGE )
			&& \BetterShield\Rest\PasskeyController::may_remove_across_sites();
	}

	/**
	 * The same bundle the two-factor panel uses, on the same screen. Enqueued
	 * here as well so this panel keeps working if that one is ever gated
	 * differently; `wp_enqueue_script` is idempotent, so the second call costs
	 * nothing.
	 *
	 * One hook name covers both places a person reaches their own profile:
	 * the site's own screen and the user dashboard, which is where somebody
	 * with no role on the site they are looking at ends up. The panel's REST
	 * calls resolve against whichever site answered, and the credentials they
	 * read are the account's rather than that site's, so either lands on the
	 * same list.
	 */
	public function assets( string $hook ): void {
		if ( 'profile.php' !== $hook && ! $this->editing_one_with_passkeys( $hook ) ) {
			return;
		}

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

	/** Somebody else's profile, with passkeys the signed-in account may remove. */
	private function editing_one_with_passkeys( string $hook ): bool {
		if ( 'user-edit.php' !== $hook ) {
			return false;
		}

		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which profile is on screen, to decide whether to enqueue.

		return $user_id > 0 && $this->may_remove( $user_id ) && Store::count_for_user( $user_id ) > 0;
	}

	public function render( \WP_User $user ): void {
		echo '<h2 id="bettershield-passkeys">' . esc_html__( 'Passkeys', 'bettershield' ) . '</h2>';

		$availability = Manager::availability();

		if ( ! $availability['available'] ) {
			echo '<p class="description">' . esc_html( $availability['reason'] ) . '</p>';

			return;
		}

		echo '<p class="description">' . esc_html( $this->intro_for( $user ) ) . '</p>';

		// Drawn and driven by assets/js/profile.js against the /passkeys REST
		// routes, which any signed-in browser session satisfies.
		printf(
			'<div id="bettershield-passkeys-panel" class="bs-profile-2fa" data-max="%s"></div>',
			esc_attr( (string) Store::MAX_PER_USER )
		);
		echo '<noscript><p>' . esc_html__( 'Adding a passkey needs JavaScript on this page.', 'bettershield' ) . '</p></noscript>';
	}

	/**
	 * What to say above the button: whether this account's password is about
	 * to stop working, has already, or whether a passkey is simply on offer.
	 */
	public function intro_for( \WP_User $user ): string {
		if ( '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user ) ) {
			return Manager::elsewhere_words();
		}

		$policy = Policy::instance();

		if ( $policy->armed_for( $user ) ) {
			return __( 'Your password no longer signs you in. Keep a passkey on a device you always have.', 'bettershield' );
		}

		if ( $policy->awaiting( $user ) ) {
			return __( 'This site asks you to add a passkey. Once you do, your password no longer signs you in.', 'bettershield' );
		}

		/*
		 * Only what this account has. The panel is drawn on a store's My
		 * Account too, and a customer has no recovery link (that is the site
		 * owner's) and no codes unless they turned two-factor on.
		 */
		$codes = \BetterShield\TwoFactor\Manager::instance()->enabled( (int) $user->ID );
		// A link that works, as the preflight that refuses sign-in changes
		// without one counts it: offered on a site that never set one up,
		// the card promised a way back the Save beside it said was not
		// there (#2219).
		$link = user_can( $user, \BetterShield\Capabilities::MANAGE ) && 'available' === \BetterShield\Recovery\Readiness::link_state();

		if ( $codes && $link ) {
			return __( 'Sign in with your fingerprint, face or PIN. Your password, two-factor codes and recovery link still work.', 'bettershield' );
		}

		if ( $codes ) {
			return __( 'Sign in with your fingerprint, face or PIN. Your password and two-factor codes still work.', 'bettershield' );
		}

		if ( $link ) {
			return __( 'Sign in with your fingerprint, face or PIN. Your password and recovery link still work.', 'bettershield' );
		}

		return __( 'Sign in with your fingerprint, face or PIN. Your password still works.', 'bettershield' );
	}
}
