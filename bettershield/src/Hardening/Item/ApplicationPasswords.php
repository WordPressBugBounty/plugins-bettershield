<?php
/**
 * Hardening item: refuse application passwords, for everyone or for the
 * accounts that can manage the site.
 *
 * An application password is a password that skips the second factor. That is
 * deliberate in WordPress and reasonable for an integration, but it means the
 * strongest sign-in protection a site has does not apply to a credential that
 * can be issued once and used from anywhere for as long as it exists. On a
 * site that has enrolled two-factor, an administrator's application password
 * is the weakest way in.
 *
 * Two modes, because the answer is not the same on every site. Narrowing to
 * privileged accounts leaves an integration that publishes posts or reads
 * orders working, and removes the credential that could change the site's
 * defenses. Refusing them site-wide is the answer for a site with no
 * integrations at all.
 *
 * Nothing is deleted either way. Existing application passwords stay on their
 * accounts and stop being accepted; undo makes them work again, which is what
 * keeps this reversible in the way every item here has to be.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ApplicationPasswords {

	/**
	 * Refuse them for accounts that can manage the site; leave the rest.
	 */
	public const MODE_PRIVILEGED = 'privileged';

	/**
	 * Refuse them for every account.
	 */
	public const MODE_EVERYONE = 'everyone';

	/**
	 * The capability that decides "privileged" in the narrower mode.
	 *
	 * Read as a capability rather than a role name on purpose: a super admin
	 * on a network, and a custom role somebody built with these rights, are
	 * both accounts whose token can change the site, and neither is called
	 * `administrator`.
	 */
	private const PRIVILEGED_CAPS = array( 'manage_options', 'edit_users', 'install_plugins' );

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'mode',
				'label'       => __( 'Who this applies to', 'bettershield' ),
				// No help line: the row says nothing is deleted, and undo
				// is said on every row.
				'required'    => true,
				'default'     => self::MODE_PRIVILEGED,
				'choices'     => array(
					array(
						'value' => self::MODE_PRIVILEGED,
						'label' => __( 'Accounts that can manage this site', 'bettershield' ),
					),
					array(
						'value' => self::MODE_EVERYONE,
						'label' => __( 'Every account', 'bettershield' ),
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
		$mode = isset( $options['mode'] ) ? (string) $options['mode'] : self::MODE_PRIVILEGED;

		if ( ! in_array( $mode, array( self::MODE_PRIVILEGED, self::MODE_EVERYONE ), true ) ) {
			return new \WP_Error( 'bettershield_bad_mode', __( 'Choose every account, or only accounts that can manage this site.', 'bettershield' ) );
		}

		return array( 'mode' => $mode );
	}

	/**
	 * @param array<string, mixed> $options
	 * @return string[]
	 */
	public static function preview( array $options ): array {
		$mode = isset( $options['mode'] ) ? (string) $options['mode'] : self::MODE_PRIVILEGED;

		if ( self::MODE_EVERYONE === $mode ) {
			return array(
				__( 'Blocks app passwords for every account.', 'bettershield' ),
			);
		}

		// Counted only where a line uses it. Site-wide refusal names no number,
		// and the count walks accounts.
		$count = self::privileged_holders();

		return array(
			__( 'Blocks app passwords for accounts that can manage this site.', 'bettershield' ),
			// None holding one is said as none (#2575).
			0 === $count ? __( 'No account is affected right now.', 'bettershield' ) : sprintf(
				/* translators: %d: number of privileged accounts holding at least one application password. */
				_n(
					'%d such account holds an application password and could no longer use it.',
					'%d such accounts hold application passwords and could no longer use them.',
					$count,
					'bettershield'
				),
				$count
			),
		);
	}

	/**
	 * A line for the item's card once it is applied.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		// Live state: switched off, nothing is refused.
		if ( empty( $state['active'] ) ) {
			return null;
		}

		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();
		$mode    = isset( $options['mode'] ) ? (string) $options['mode'] : self::MODE_PRIVILEGED;

		return self::MODE_EVERYONE === $mode
			? __( 'Refused for every account.', 'bettershield' )
			: __( 'Refused for accounts that can manage this site.', 'bettershield' );
	}

	/**
	 * Whether anything else has already taken application passwords away.
	 *
	 * Worth saying plainly rather than letting the item report a change it did
	 * not make: applying over a site where they are already off is not wrong,
	 * but the owner should know the protection was not this item's doing.
	 */
	public static function conflict(): ?string {
		if ( ! function_exists( 'wp_is_application_passwords_available' ) ) {
			return __( 'This WordPress version has no application passwords, so there is nothing to refuse.', 'bettershield' );
		}

		// Not while this item is the reason: applied, it is its own answer.
		// Asked of the stored state rather than of the hook. Core keys a
		// filter on the callback and a plain function name is its own key, so
		// `__return_false` here is one slot shared with every other plugin
		// that uses it — read as ours, somebody else's protection suppressed
		// the warning below on every request.
		if ( \BetterShield\Hardening\Manager::instance()->is_active( 'application_passwords' ) ) {
			return null;
		}

		if ( ! wp_is_application_passwords_available() ) {
			return __( 'Already off (another plugin, or no HTTPS). Applying changes nothing for now.', 'bettershield' );
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	private static function mode_of( array $state ): string {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();
		$mode    = isset( $options['mode'] ) ? (string) $options['mode'] : self::MODE_PRIVILEGED;

		return self::MODE_EVERYONE === $mode ? self::MODE_EVERYONE : self::MODE_PRIVILEGED;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		if ( self::MODE_EVERYONE === self::mode_of( $state ) ) {
			add_filter( 'wp_is_application_passwords_available', array( self::class, 'refuse_all' ) );

			return;
		}

		add_filter( 'wp_is_application_passwords_available_for_user', array( self::class, 'refuse_for_privileged' ), 10, 2 );
	}

	/**
	 * Whether what enforce() attaches is still attached on this request.
	 * Switched on is not the same as working: another plugin's
	 * remove_filter() leaves the item reading active with nothing in force.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		if ( self::MODE_EVERYONE === self::mode_of( $state ) ) {
			return false !== has_filter( 'wp_is_application_passwords_available', array( self::class, 'refuse_all' ) );
		}

		return false !== has_filter( 'wp_is_application_passwords_available_for_user', array( self::class, 'refuse_for_privileged' ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		remove_filter( 'wp_is_application_passwords_available', array( self::class, 'refuse_all' ) );
		remove_filter( 'wp_is_application_passwords_available_for_user', array( self::class, 'refuse_for_privileged' ), 10 );
	}

	/**
	 * The whole-site refusal, as a method rather than `__return_false`.
	 *
	 * Core keys a filter on the callback, and a plain function name is its own
	 * key — so every plugin registering `__return_false` on this hook at the
	 * same priority shares one slot. Ours removed theirs on undo, and their
	 * presence read as ours to the probe above. A class method is a name
	 * nobody else registers.
	 */
	public static function refuse_all(): bool {
		return false;
	}

	/**
	 * @param bool $available Whether core would allow them for this account.
	 */
	public static function refuse_for_privileged( $available, $user ): bool {
		if ( ! $available || ! $user instanceof \WP_User ) {
			return (bool) $available;
		}

		return ! self::is_privileged( $user );
	}

	/**
	 * Whether an account can change this site, by capability rather than by
	 * the name of its role.
	 */
	public static function is_privileged( \WP_User $user ): bool {
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return true;
		}

		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			if ( user_can( $user, $cap ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * How many privileged accounts hold at least one application password —
	 * the number that says what applying this would actually interrupt.
	 *
	 * Bounded: on a site with a great many users this is a preview line, not
	 * a report, and it is not worth walking every account to draw it.
	 */
	private static function privileged_holders(): int {
		if ( ! class_exists( '\WP_Application_Passwords' ) ) {
			return 0;
		}

		// The same capability set enforcement reads, or the preview counts a
		// different crowd than applying will interrupt.
		$users = get_users(
			array(
				'number'         => 200,
				'fields'         => array( 'ID' ),
				'capability__in' => self::PRIVILEGED_CAPS,
			)
		);

		$ids = array_map( static fn( $user ): int => (int) $user->ID, $users );

		if ( array() === $ids ) {
			return 0;
		}

		/*
		 * Core keeps application passwords in user meta and the getter below
		 * reads it one account at a time, so an unprimed cache turned this
		 * preview line into two hundred queries on a site with two hundred
		 * administrators. One round trip fills the cache every one of those
		 * reads then hits.
		 */
		update_meta_cache( 'user', $ids );

		$holders = 0;

		foreach ( $ids as $id ) {
			if ( array() !== \WP_Application_Passwords::get_user_application_passwords( $id ) ) {
				++$holders;
			}
		}

		return $holders;
	}
}
