<?php
/**
 * Hardening item: a privileged account's new email address takes effect only
 * once it is confirmed from that address, on every path that can change it
 * (#1856).
 *
 * Core asks for confirmation only when people change their own address on
 * their profile screen. The REST API, another administrator's edit and
 * front-end account forms change it at once, and the address is where
 * password resets go: one request from a hijacked session or application
 * password could send the next reset to someone else.
 *
 * With this on, such a change to a privileged account is held. The address
 * stays as it was, and core's own pending change is set up instead: the
 * `_new_email` record core keeps, the notice on the profile screen with its
 * cancel link, and a confirmation link mailed to the new address. The old
 * address is told a change was asked for. Once the account holder, signed
 * in, opens the link, core makes the change, and both steps are recorded.
 *
 * A REST caller gets the account back with its old address and a
 * `bettershield_email_pending` field, not an error. WP-CLI, installing and
 * the store's checkout are left alone, as are accounts that are not
 * privileged.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Writer;
use BetterShield\Password\Policy;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EmailChange {

	public const ITEM = 'email_change_confirm';

	/** The field a REST caller reads the waiting address from. */
	public const REST_FIELD = 'bettershield_email_pending';

	/** Accounts whose change was held on this request, so each is mailed once. */
	private static array $held = array();

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		if ( empty( $state['active'] ) ) {
			return null;
		}

		return __( 'A privileged account’s new email address waits for confirmation from that address.', 'bettershield' );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		// Late, so another plugin's own change to the data is seen first.
		add_filter( 'wp_pre_insert_user_data', array( self::class, 'hold' ), 99, 4 );
		add_filter( 'send_email_change_email', array( self::class, 'quiet_core_notice' ), 99, 3 );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return false !== has_filter( 'wp_pre_insert_user_data', array( self::class, 'hold' ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'wp_pre_insert_user_data', array( self::class, 'hold' ), 99 );
		remove_filter( 'send_email_change_email', array( self::class, 'quiet_core_notice' ), 99 );
	}

	/**
	 * Core mails the old address "your email was changed to …" after any
	 * save that asks for a new one, deciding before the save. For a change
	 * this holds nothing changes, and the old address gets this plugin's
	 * own notice instead.
	 *
	 * @param mixed $send
	 * @param mixed $user     The account as it was.
	 * @param mixed $userdata What the save asked for.
	 * @return mixed
	 */
	public static function quiet_core_notice( $send, $user = array(), $userdata = array() ) {
		$id      = is_array( $user ) ? (int) ( $user['ID'] ?? 0 ) : 0;
		$new     = is_array( $userdata ) ? (string) ( $userdata['user_email'] ?? '' ) : '';
		$account = $id > 0 ? get_userdata( $id ) : false;

		return $account instanceof \WP_User && self::holds( $account, $new ) ? false : $send;
	}

	/**
	 * Whether a save asking for this address on this account is held.
	 */
	private static function holds( \WP_User $user, string $new ): bool {
		return '' !== $new
			&& 0 !== strcasecmp( $new, (string) $user->user_email )
			&& ! self::left_alone()
			&& Policy::instance()->is_privileged( (array) $user->roles, $user )
			&& ! self::is_confirmation( $user, $new );
	}

	/**
	 * The REST field, registered whatever the item's state, so a client
	 * reading it is not told the schema changed when the owner flips it.
	 */
	public static function register(): void {
		add_action(
			'rest_api_init',
			static function (): void {
				register_rest_field(
					'user',
					self::REST_FIELD,
					array(
						'get_callback' => array( self::class, 'rest_value' ),
						'schema'       => array(
							'description' => __( 'A new email address waiting for confirmation from that address, or an empty string.', 'bettershield' ),
							'type'        => 'string',
							'context'     => array( 'edit' ),
							'readonly'    => true,
						),
					)
				);
			}
		);

		add_action( 'admin_notices', array( self::class, 'notice' ) );
	}

	/**
	 * On another account's edit screen, where core says nothing of a
	 * pending change: the address shown is the old one, and why.
	 */
	public static function notice(): void {
		global $pagenow;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reads which account the screen shows.
		$id = 'user-edit.php' === $pagenow && isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;

		if ( $id <= 0 || $id === get_current_user_id() || ! current_user_can( 'edit_user', $id ) ) {
			return;
		}

		$waiting = self::pending( $id );

		if ( '' === $waiting ) {
			return;
		}

		printf(
			'<div class="notice notice-info"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: the new email address. */
					__( 'The change to %s is waiting for confirmation. It takes effect once the account holder opens the link sent to that address.', 'bettershield' ),
					$waiting
				)
			)
		);
	}

	/**
	 * @param array<string, mixed> $user As the REST controller prepared it.
	 */
	public static function rest_value( array $user ): string {
		$id = (int) ( $user['id'] ?? 0 );

		if ( $id <= 0 || ! current_user_can( 'edit_user', $id ) ) {
			return '';
		}

		return self::pending( $id );
	}

	/** The address waiting for confirmation on an account, or ''. */
	public static function pending( int $user_id ): string {
		$waiting = get_user_meta( $user_id, '_new_email', true );

		return is_array( $waiting ) && isset( $waiting['newemail'] ) ? (string) $waiting['newemail'] : '';
	}

	/**
	 * An account about to be saved: a changed address on a privileged
	 * account is kept as it was, and set up as core's pending change.
	 *
	 * @param mixed $data     What is about to be written.
	 * @param mixed $update   Whether this is an existing account.
	 * @param mixed $user_id  The account.
	 * @param mixed $userdata What the caller passed.
	 * @return mixed
	 */
	public static function hold( $data, $update = false, $user_id = null, $userdata = array() ) {
		unset( $userdata );

		if ( ! is_array( $data ) || ! $update || ! is_numeric( $user_id ) || ! isset( $data['user_email'] ) ) {
			return $data;
		}

		$user = get_userdata( (int) $user_id );

		if ( ! $user instanceof \WP_User ) {
			return $data;
		}

		$new = (string) $data['user_email'];
		$old = (string) $user->user_email;

		if ( 0 === strcasecmp( $new, $old ) || '' === $new || self::left_alone() || ! Policy::instance()->is_privileged( (array) $user->roles, $user ) ) {
			return $data;
		}

		// Core's own confirmation, opened by the account holder: let it
		// through, and record that the change was confirmed.
		if ( self::is_confirmation( $user, $new ) ) {
			// Used once: the link is spent when the change is made.
			$id = (int) $user->ID;
			add_action(
				'profile_update',
				static function ( $updated ) use ( $id ): void {
					if ( (int) $updated === $id ) {
						delete_user_meta( $id, '_new_email' );
					}
				}
			);

			Writer::instance()->record(
				'email_change_confirmed',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'user',
					'object_id'   => (string) $user->ID,
					'context'     => array( 'target_login' => $user->user_login ),
				)
			);

			return $data;
		}

		$data['user_email'] = $old;

		if ( ! isset( self::$held[ $user->ID ] ) ) {
			self::$held[ $user->ID ] = true;
			self::set_pending( $user, $new );
		}

		return $data;
	}

	/**
	 * WP-CLI, an install, and the store's checkout are not paths this holds.
	 */
	private static function left_alone(): bool {
		return wp_installing() || ( defined( 'WP_CLI' ) && WP_CLI ) || \BetterShield\Support\Checkout::is_checkout_request();
	}

	/**
	 * Whether this save is core's confirmation from the profile screen: the
	 * account holder, signed in with a browser session, opening the link
	 * mailed to the new address. Never a REST, XML-RPC or application-
	 * password request: a stolen application password could otherwise
	 * replay the hash over REST with an address of its own.
	 */
	private static function is_confirmation( \WP_User $user, string $new ): bool {
		global $pagenow;

		if ( ! is_admin() || 'profile.php' !== $pagenow
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| did_action( 'application_password_did_authenticate' ) > 0
			|| ( function_exists( 'rest_get_authenticated_app_password' ) && null !== rest_get_authenticated_app_password() ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- core's own confirmation link carries a hash, compared below, not a nonce.
		$hash    = isset( $_GET['newuseremail'] ) && is_string( $_GET['newuseremail'] ) ? sanitize_text_field( wp_unslash( $_GET['newuseremail'] ) ) : '';
		$waiting = get_user_meta( $user->ID, '_new_email', true );

		return '' !== $hash
			&& get_current_user_id() === (int) $user->ID
			&& is_array( $waiting )
			&& isset( $waiting['hash'], $waiting['newemail'] )
			&& hash_equals( (string) $waiting['hash'], $hash )
			&& 0 === strcasecmp( trim( (string) $waiting['newemail'] ), $new );
	}

	/**
	 * Set up core's pending change, mail the link to the new address and a
	 * notice to the old one, and record it.
	 */
	private static function set_pending( \WP_User $user, string $new ): void {
		$hash = md5( $new . time() . wp_rand() );

		update_user_meta(
			$user->ID,
			'_new_email',
			array(
				'hash'     => $hash,
				'newemail' => $new,
			)
		);

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$link = admin_url( 'profile.php?newuseremail=' . $hash );

		wp_mail(
			$new,
			/* translators: %s: the site's name. */
			sprintf( __( '[%s] Confirm your new email address', 'bettershield' ), $site ),
			implode(
				"\n\n",
				array(
					/* translators: %s: the account's username. */
					sprintf( __( 'Someone asked for this to become the email address of the account %s.', 'bettershield' ), $user->user_login ),
					__( 'To confirm it, sign in to that account and open this link:', 'bettershield' ),
					$link,
					__( 'If you did not ask for this, ignore this email. Nothing changes until it is confirmed.', 'bettershield' ),
				)
			)
		);

		wp_mail(
			(string) $user->user_email,
			/* translators: %s: the site's name. */
			sprintf( __( '[%s] A change of your email address was requested', 'bettershield' ), $site ),
			implode(
				"\n\n",
				array(
					/* translators: %s: the account's username. */
					sprintf( __( 'A change of the email address on the account %s was requested. It takes effect only once confirmed from the new address.', 'bettershield' ), $user->user_login ),
					__( 'If this was not you, sign in, cancel the pending change on your profile, and change your password.', 'bettershield' ),
					admin_url( 'profile.php' ),
				)
			)
		);

		Writer::instance()->record(
			'email_change_held',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array(
					'target_login' => $user->user_login,
					'by_self'      => get_current_user_id() === (int) $user->ID,
				),
			)
		);
	}

	/** Forget which accounts this request already held. For tests. */
	public static function reset_request_state(): void {
		self::$held = array();
	}
}
