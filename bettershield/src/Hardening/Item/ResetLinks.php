<?php
/**
 * Hardening item: password-reset links for privileged accounts expire sooner
 * (#1863).
 *
 * Core's reset link works for a day for every account. An administrator's
 * link sitting in a mailbox for a day is a takeover for anyone who reads that
 * mailbox. With this on, a privileged account's link works for the time the
 * owner chose (an hour unless they chose otherwise), and everyone else keeps
 * core's day.
 *
 * Judged where core asks: validate_password_reset, which runs once core has
 * accepted the key, from the time core stored beside it in
 * user_activation_key. A link past the shorter time is answered as core
 * answers one past its own: on wp-login.php the visitor is sent to request a
 * new link with core's "expired" message, and on any other reset form the
 * reset is refused with that same message. A privileged account is told
 * nothing a visitor could not already learn by trying an old link.
 *
 * Only the window shrinks. Nothing is added to the way back in, such as a
 * second factor on reset, and the recovery link and safe mode never pass
 * through here.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Password\Policy;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ResetLinks {

	public const ITEM = 'reset_link_lifetime';

	/** The lifetimes offered, in minutes. */
	public const CHOICES = array( 15, 60, 240 );

	public const DEFAULT_MINUTES = 60;

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'minutes',
				'label'       => __( 'How long their reset link works', 'bettershield' ),
				'description' => __( 'Everyone else keeps the usual 24 hours.', 'bettershield' ),
				'required'    => true,
				'default'     => (string) self::DEFAULT_MINUTES,
				'choices'     => array(
					array(
						'value' => '15',
						'label' => __( '15 minutes', 'bettershield' ),
					),
					array(
						'value' => '60',
						'label' => __( '1 hour', 'bettershield' ),
					),
					array(
						'value' => '240',
						'label' => __( '4 hours', 'bettershield' ),
					),
				),
			),
		);
	}

	/**
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate( array $options ) {
		$minutes = isset( $options['minutes'] ) && is_scalar( $options['minutes'] ) ? (int) $options['minutes'] : self::DEFAULT_MINUTES;

		if ( ! in_array( $minutes, self::CHOICES, true ) ) {
			return new \WP_Error( 'bettershield_bad_reset_lifetime', __( 'Choose 15 minutes, 1 hour or 4 hours.', 'bettershield' ) );
		}

		return array( 'minutes' => $minutes );
	}

	/**
	 * @param array<string, mixed> $options
	 * @return string[]
	 */
	public static function preview( array $options ): array {
		$validated = self::validate( $options );

		if ( is_wp_error( $validated ) ) {
			return array();
		}

		return array( self::lifetime_sentence( (int) $validated['minutes'] ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		if ( empty( $state['active'] ) ) {
			return null;
		}

		return self::lifetime_sentence( self::minutes( $state ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		add_action( 'validate_password_reset', array( self::class, 'check' ), 5, 2 );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_action( 'validate_password_reset', array( self::class, 'check' ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_action( 'validate_password_reset', array( self::class, 'check' ), 5 );
	}

	/**
	 * A reset core has accepted: refused when the account is privileged and
	 * its link is older than the shorter lifetime.
	 *
	 * @param mixed $errors
	 * @param mixed $user
	 */
	public static function check( $errors, $user = null ): void {
		if ( ! $errors instanceof \WP_Error || ! $user instanceof \WP_User || ! self::expired( $user ) ) {
			return;
		}

		// Core's own answer to an expired link, word for word, translated
		// by core rather than carried in this plugin's catalog.
		$errors->add( 'expiredkey', translate( 'Your password reset link has expired. Please request a new link below.', 'default' ) ); // phpcs:ignore WordPress.WP.I18n -- core's own string.

		// On core's form, the same redirect core makes for an expired link,
		// with the cookie that carried the key cleared as core clears it.
		if ( 'wp-login.php' === ( $GLOBALS['pagenow'] ?? '' ) && ! headers_sent() ) {
			$cookie = 'wp-resetpass-' . COOKIEHASH;
			$path   = (string) wp_parse_url( wp_unslash( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) ), PHP_URL_PATH ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a path compared, never printed.

			setcookie( $cookie, ' ', time() - YEAR_IN_SECONDS, $path, COOKIE_DOMAIN, is_ssl(), true );
			wp_safe_redirect( site_url( 'wp-login.php?action=lostpassword&error=expiredkey' ) );
			exit;
		}
	}

	/**
	 * Whether this account's current reset link is past the shorter lifetime.
	 * An account that is not privileged, or a key with no time beside it, is
	 * left to core.
	 */
	public static function expired( \WP_User $user, ?int $now = null ): bool {
		$key = (string) $user->user_activation_key;

		if ( ! str_contains( $key, ':' ) || ! Policy::instance()->is_privileged( (array) $user->roles, $user ) ) {
			return false;
		}

		$requested = (int) strtok( $key, ':' );

		if ( $requested <= 0 ) {
			return false;
		}

		$state = \BetterShield\Hardening\Manager::instance()->item_state( self::ITEM );

		return ( $now ?? time() ) >= $requested + self::minutes( $state ) * MINUTE_IN_SECONDS;
	}

	/**
	 * The lifetime chosen, in minutes.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function minutes( array $state ): int {
		$minutes = (int) ( $state['options']['minutes'] ?? self::DEFAULT_MINUTES );

		return in_array( $minutes, self::CHOICES, true ) ? $minutes : self::DEFAULT_MINUTES;
	}

	private static function lifetime_sentence( int $minutes ): string {
		return $minutes < 60
			/* translators: %d: minutes. */
			? sprintf( __( 'Reset links for privileged accounts work for %d minutes.', 'bettershield' ), $minutes )
			/* translators: %d: hours. */
			: sprintf( _n( 'Reset links for privileged accounts work for %d hour.', 'Reset links for privileged accounts work for %d hours.', (int) ( $minutes / 60 ), 'bettershield' ), (int) ( $minutes / 60 ) );
	}
}
