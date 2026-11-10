<?php
/**
 * Two-factor enrollment on a person's own profile screen.
 *
 * **It lives on the profile screen, not on this plugin's own.** Every screen
 * this plugin draws needs a capability an author or an editor does not have —
 * and those are exactly the roles a two-factor policy targets. An account the
 * policy holds as overdue is sent here, to a page it can always open, rather
 * than to a screen that answers "you are not allowed" with no way to comply.
 *
 * **No `<form>` element is rendered.** `show_user_profile` fires inside
 * core's own profile form, and a nested form start tag is dropped by the
 * HTML parser — its buttons would submit the profile form instead. The
 * panel drives the plugin's existing REST enrollment routes, which any
 * signed-in session satisfies, the way core's Application Passwords
 * section drives its own.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\TwoFactor;

use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProfilePanel {

	/** At or below this many codes left, the panel says so rather than counting. */
	private const LOW_WATER = 3;

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

	public function assets( string $hook ): void {
		if ( ! $this->screen_needs_assets( $hook ) ) {
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
			// Its times read the site's zone from WordPress's date script.
			array_merge( (array) $asset['dependencies'], array( 'wp-date' ) ),
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

	/**
	 * Whether this screen draws something the bundle has to drive.
	 *
	 * `profile.php` needs it either way now — to enroll while nothing is armed,
	 * and to issue fresh backup codes once something is. It used to be gated on
	 * *not* being enrolled, which is why the enrolled panel had no script to
	 * draw with and no mount to draw into, and reported a countdown it could
	 * offer nothing about.
	 *
	 * `user-edit.php` needs it to offer the reset, and only while there is one.
	 */
	private function screen_needs_assets( string $hook ): bool {
		if ( 'profile.php' === $hook ) {
			return true;
		}

		if ( 'user-edit.php' !== $hook ) {
			return false;
		}

		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which profile is on screen, to decide whether to enqueue.

		return $user_id > 0
			&& current_user_can( 'edit_user', $user_id )
			&& current_user_can( Capabilities::MANAGE )
			&& Manager::instance()->enabled( $user_id );
	}

	/**
	 * What an administrator sees on somebody else's profile.
	 *
	 * Read-only where there is nothing to reset, so the screen says what is
	 * true of the account either way rather than going blank. The control is
	 * drawn only where it would do something, and only for somebody the
	 * REST route would also let through — the route re-checks, and this
	 * decides whether to offer.
	 */
	public function render_for_administrator( \WP_User $user ): void {
		if ( ! current_user_can( 'edit_user', (int) $user->ID ) ) {
			return;
		}

		echo '<h2 id="bettershield-two-factor">' . esc_html__( 'Two-factor sign-in', 'bettershield' ) . '</h2>';

		if ( ! Manager::instance()->enabled( (int) $user->ID ) ) {
			echo '<p class="description">' . esc_html__( 'Two-factor is off for this user. Only they can set it up, from their own profile.', 'bettershield' ) . '</p>';

			return;
		}

		/*
		 * Editing an account is not the same as managing this plugin, and the
		 * route behind the reset answers only the second: a store manager on a
		 * customer's profile was offered a button that could only be refused.
		 */
		if ( ! current_user_can( Capabilities::MANAGE ) ) {
			echo '<p class="description">' . esc_html__( 'This user signs in with two-factor. If they lose their phone and backup codes, a BetterShield administrator can turn it off.', 'bettershield' ) . '</p>';

			return;
		}

		echo '<p class="description">' . esc_html__( 'Turning off two-factor lets this user sign in with only their password.', 'bettershield' ) . '</p>';

		printf(
			'<div id="bettershield-2fa-admin-reset" class="bs-profile-2fa" data-user="%d"></div>',
			(int) $user->ID
		);
		echo '<noscript><p>' . esc_html__( 'Turning two-factor off for someone needs JavaScript on this page.', 'bettershield' ) . '</p></noscript>';
	}

	public function render( \WP_User $user ): void {
		echo '<h2 id="bettershield-two-factor">' . esc_html__( 'Two-factor sign-in', 'bettershield' ) . '</h2>';

		// Kept in Quick Setup: enrolling here as well means two codes at
		// every sign-in. Still offered, for whoever chooses it.
		$elsewhere = \BetterShield\Onboarding\Coexistence::two_factor_handled_by();

		if ( '' !== $elsewhere ) {
			if ( current_user_can( Capabilities::MANAGE ) ) {
				/* translators: %s: the name of the other plugin, or several separated by commas. */
				$line = sprintf( __( 'Two-factor is handled by %s on this site.', 'bettershield' ), $elsewhere );
			} else {
				// Which security plugin a site runs is for whoever runs it,
				// not for every account and store customer.
				$line = __( 'Two-factor is handled by another plugin on this site.', 'bettershield' );
			}

			echo '<p class="description bs-profile-2fa-elsewhere">' . esc_html( $line ) . '</p>';
		}

		if ( Manager::instance()->enabled( (int) $user->ID ) ) {
			$remaining = BackupCodes::remaining( (int) $user->ID );

			// Named, as is the warning below it, so issuing a new set on this
			// screen redraws both rather than leaving the old count above it.
			echo '<p class="description" id="bettershield-2fa-backup-count">';
			echo esc_html(
				sprintf(
					/* translators: %d: number of unused backup codes. */
					_n(
						'Two-factor is on. You have %d backup code left.',
						'Two-factor is on. You have %d backup codes left.',
						$remaining,
						'bettershield'
					),
					$remaining
				)
			);
			echo '</p>';

			/*
			 * A count on its own leaves the reader to work out what it means,
			 * and by the time it means something it is too late to act on. So
			 * the low-water case says what it is for and offers the remedy in
			 * the same breath, while the app that can authorize a new set is
			 * still in the person's pocket.
			 */
			if ( $remaining <= self::LOW_WATER ) {
				echo '<p class="description" id="bettershield-2fa-backup-low">';
				echo esc_html(
					0 === $remaining
						? __( 'Backup codes sign you in if you lose your phone. You have none left. Create new codes now.', 'bettershield' )
						: __( 'Backup codes sign you in if you lose your phone. You are almost out. Create new codes now.', 'bettershield' )
				);
				echo '</p>';
			}

			// Drawn and driven by assets/js/profile.js, which asks for a
			// current code before the route will issue anything.
			printf(
				'<div id="bettershield-2fa-backup-codes" class="bs-profile-2fa" data-remaining="%s"></div>',
				esc_attr( (string) $remaining )
			);
			echo '<noscript><p>' . esc_html__( 'Issuing new backup codes needs JavaScript. Without it, ask an administrator to turn two-factor off for you.', 'bettershield' ) . '</p></noscript>';

			return;
		}

		echo '<p class="description">' . esc_html( $this->intro_for( $user ) ) . '</p>';

		// The enrollment steps are drawn and driven by assets/js/profile.js
		// against the /two-factor REST routes.
		echo '<div id="bettershield-2fa-enroll" class="bs-profile-2fa"></div>';
		echo '<noscript><p>' . esc_html__( 'Setting up two-factor needs JavaScript. Without it, ask an administrator for help.', 'bettershield' ) . '</p></noscript>';
	}

	/**
	 * What to say above the button: whether this account is asked to enroll,
	 * required to, or simply may.
	 */
	private function intro_for( \WP_User $user ): string {
		$state = Policy::instance()->state_for( $user );

		if ( Policy::OVERDUE === $state['status'] ) {
			return __( 'Your role requires two-factor sign-in. Set it up to use the rest of the dashboard.', 'bettershield' );
		}

		if ( Policy::IN_GRACE === $state['status'] ) {
			return sprintf(
				/* translators: %d: number of days. */
				_n(
					'This site asks you to set up two-factor sign-in. You have %d day left.',
					'This site asks you to set up two-factor sign-in. You have %d days left.',
					(int) $state['days_left'],
					'bettershield'
				),
				(int) $state['days_left']
			);
		}

		return __( 'Add a second step to sign-in: after your password, enter a code from an authenticator app on your phone.', 'bettershield' );
	}
}
