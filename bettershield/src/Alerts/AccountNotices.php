<?php
/**
 * Tells the person whose account it is when a way of signing in to it is
 * added or removed (#1855).
 *
 * Two-factor turned on or off, new backup codes, a passkey added or removed,
 * an application password created or revoked: each is logged, and the
 * site's alert recipients hear about the serious ones. The account holder,
 * the one person who would recognize a passkey that is not theirs, was
 * never told. Core mails them about a new password or address, and nothing
 * else.
 *
 * One plain email to the account's own address, saying what changed, when,
 * from which /24 or /64 network and in which browser, and where to look.
 * Changes within ten minutes of the first go in one email, so setting up
 * two-factor and printing the codes is one message. On by default for
 * accounts that can manage the site, off for the others, both chosen under
 * Email alerts. Nothing is blocked.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Events\Writer;
use BetterShield\Login\Sessions;
use BetterShield\Password\Policy;
use BetterShield\Support\Ip;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AccountNotices {

	/** The task that sends one account's email once the ten minutes are up. */
	public const TASK = 'bettershield_account_notice';

	/** What is waiting to be sent, on the account itself. */
	public const META = 'bettershield_account_notice_queue';

	/** How long after the first change the email goes. */
	public const WINDOW = 10 * MINUTE_IN_SECONDS;

	/** At most this many changes are listed in one email. */
	private const MAX_LISTED = 20;

	/** The events that change how an account can be signed in to. */
	public const TYPES = array(
		'two_factor_enabled',
		'two_factor_disabled',
		'two_factor_backup_reissued',
		'two_factor_moved',
		'two_factor_not_moved',
		'passkey_registered',
		'passkey_removed',
		'app_password_created',
		'app_password_revoked',
	);

	public static function register(): void {
		add_action( 'bettershield_events_flushed', array( self::class, 'observe' ), 20, 1 );
		add_action( self::TASK, array( self::class, 'send' ), 10, 1 );
	}

	/**
	 * Events just written: queue the ones about an account's ways in.
	 *
	 * @param mixed $events
	 */
	public static function observe( $events ): void {
		foreach ( is_array( $events ) ? $events : array() as $event ) {
			if ( ! is_array( $event ) || ! in_array( (string) ( $event['event_type'] ?? '' ), self::TYPES, true ) || 'user' !== ( $event['object_type'] ?? '' ) ) {
				continue;
			}

			$user = get_userdata( (int) ( $event['object_id'] ?? 0 ) );

			// A factor taken off from the server's command line is told to
			// the account whatever the owner chose: nobody signed in did it,
			// and the person is the one who can say it wasn't asked for.
			$context  = is_array( $event['context'] ?? null ) ? $event['context'] : (array) json_decode( (string) ( $event['context'] ?? '' ), true );
			$terminal = 'cli' === ( $context['by'] ?? '' );

			if ( ! $user instanceof \WP_User || ! ( $terminal ? self::reachable( $user ) : self::wanted_for( $user ) ) ) {
				continue;
			}

			self::queue( $user, $event );
		}
	}

	/** Whether this account can be told at all: an address, and not a staging copy. */
	private static function reachable( \WP_User $user ): bool {
		return is_email( $user->user_email ) && ! \BetterShield\Onboarding\SiteIdentity::is_staging();
	}

	/** Whether this account is to be told, as the owner chose. */
	public static function wanted_for( \WP_User $user ): bool {
		if ( ! self::reachable( $user ) ) {
			return false;
		}

		$settings = Settings::instance()->settings();

		return Policy::instance()->is_privileged( (array) $user->roles, $user )
			? $settings['account_notices_privileged']
			: $settings['account_notices_others'];
	}

	/**
	 * @param array<string, mixed> $event
	 */
	private static function queue( \WP_User $user, array $event ): void {
		$queue   = get_user_meta( $user->ID, self::META, true );
		$queue   = is_array( $queue ) ? $queue : array();
		$context = is_array( $event['context'] ?? null ) ? $event['context'] : (array) json_decode( (string) ( $event['context'] ?? '' ), true );
		$agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		if ( count( $queue ) < self::MAX_LISTED ) {
			$queue[] = array(
				'type'    => (string) $event['event_type'],
				'at'      => time(),
				'network' => is_string( $event['ip_prefix'] ?? null ) ? (string) Ip::prefix_label( $event['ip_prefix'] ) : '',
				'browser' => '' === $agent ? '' : Sessions::device_label( $agent ),
				'name'    => \BetterShield\Support\Text::clip( (string) ( $context['label'] ?? $context['name'] ?? '' ), 100 ),
				'codes'   => (int) ( $context['codes'] ?? 0 ),
				'by'      => 'cli' === ( $context['by'] ?? '' ) ? 'cli' : '',
			);
		}

		update_user_meta( $user->ID, self::META, $queue );

		if ( false === wp_next_scheduled( self::TASK, array( (int) $user->ID ) ) ) {
			wp_schedule_single_event( time() + self::WINDOW, self::TASK, array( (int) $user->ID ) );
		}
	}

	/**
	 * Send one account's email with everything queued for it.
	 *
	 * @param mixed $user_id
	 */
	public static function send( $user_id ): bool {
		$user  = get_userdata( (int) $user_id );
		$queue = $user ? get_user_meta( $user->ID, self::META, true ) : array();

		if ( ! $user instanceof \WP_User ) {
			return false;
		}

		delete_user_meta( $user->ID, self::META );

		if ( ! is_array( $queue ) || array() === $queue ) {
			return false;
		}

		// Where the owner keeps these notices off, a change made from the
		// server's command line is still told, and only that change.
		if ( ! self::wanted_for( $user ) ) {
			$queue = self::reachable( $user ) ? array_values( array_filter( $queue, static fn( $item ): bool => is_array( $item ) && 'cli' === ( $item['by'] ?? '' ) ) ) : array();

			if ( array() === $queue ) {
				return false;
			}
		}

		$switched = switch_to_user_locale( (int) $user->ID );

		try {
			$sent = wp_mail( $user->user_email, self::subject(), self::body( $user, $queue ) );
		} finally {
			if ( $switched ) {
				restore_previous_locale();
			}
		}

		Writer::instance()->record(
			'account_notice_sent',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
				'context'     => array(
					'changes' => count( $queue ),
					'sent'    => (bool) $sent,
				),
			)
		);

		return (bool) $sent;
	}

	/** Take one kind of change out of what is waiting for an account. */
	public static function drop( int $user_id, string $type ): void {
		$queue = get_user_meta( $user_id, self::META, true );

		if ( ! is_array( $queue ) ) {
			return;
		}

		$kept = array_values( array_filter( $queue, static fn( $item ): bool => ! is_array( $item ) || $type !== ( $item['type'] ?? '' ) ) );

		if ( array() === $kept ) {
			self::forget( $user_id );

			return;
		}

		update_user_meta( $user_id, self::META, $kept );
	}

	/** Forget what is waiting for an account, and the send it was waiting for. */
	public static function forget( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
		wp_clear_scheduled_hook( self::TASK, array( $user_id ) );
	}

	private static function subject(): string {
		return sprintf(
			/* translators: %s: the site's name. */
			__( '[%s] Your sign-in settings changed', 'bettershield' ),
			wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
		);
	}

	/**
	 * @param array<int, array<string, mixed>> $queue
	 */
	private static function body( \WP_User $user, array $queue ): string {
		$lines = array(
			sprintf(
				/* translators: 1: the account's username, 2: the site's name. */
				__( 'These sign-in settings changed for your account %1$s on %2$s:', 'bettershield' ),
				$user->user_login,
				wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			),
			'',
		);

		foreach ( $queue as $item ) {
			$lines[] = '- ' . ( 'cli' === ( $item['by'] ?? '' ) ? self::from_terminal( (string) ( $item['type'] ?? '' ) ) : self::what( (string) ( $item['type'] ?? '' ), (string) ( $item['name'] ?? '' ), (int) ( $item['codes'] ?? 0 ) ) );

			// A change from the server's command line has no visitor's address
			// or browser to name: the line above already says where it came from.
			$terminal = 'cli' === ( $item['by'] ?? '' );

			$where = array_filter(
				array(
					// The same way every other email says a moment (#2486).
					\BetterShield\Support\Time::said( (int) ( $item['at'] ?? time() ) ),
					! $terminal && '' !== (string) ( $item['network'] ?? '' ) ? sprintf(
						/* translators: %s: an internet address with its last part hidden, e.g. 203.0.113.x. */
						__( 'from internet address %s', 'bettershield' ),
						// Kept as the network label; said as an address a reader
						// can recognize, never in range notation (#2404).
						Ip::address_label( Ip::from_label( (string) $item['network'] ) ) ?? $item['network']
					) : '',
					$terminal ? '' : (string) ( $item['browser'] ?? '' ),
				)
			);

			$lines[] = '  ' . implode( ' · ', $where );
		}

		$lines[] = '';
		$lines[] = __( 'Wasn’t you? Sign in, change your password, and check your sign-in settings on your profile:', 'bettershield' );
		$lines[] = \BetterShield\Login\AccountPage::front_end_url( $user ) ?? admin_url( 'profile.php' );

		return implode( "\n", $lines ) . "\n";
	}

	/** One change made from the server's command line, as the account holder reads it. */
	private static function from_terminal( string $type ): string {
		return 'passkey_removed' === $type
			? __( 'A passkey was removed from your account from the server’s command line. It can’t be put back: add a new one on your profile.', 'bettershield' )
			: __( 'Two-factor sign-in was turned off for your account from the server’s command line. It can’t be put back: set it up again on your profile.', 'bettershield' );
	}

	/** One change, as the account holder reads it. */
	private static function what( string $type, string $name, int $codes = 0 ): string {
		switch ( $type ) {
			case 'two_factor_enabled':
				return __( 'Two-factor sign-in was turned on.', 'bettershield' );
			case 'two_factor_disabled':
				return '' === $name
					? __( 'Two-factor sign-in was turned off.', 'bettershield' )
					: sprintf(
						/* translators: %s: the name of the plugin two-factor was set up with. */
						__( 'Two-factor sign-in brought over from %s was undone, so your account signs in with its password alone for now.', 'bettershield' ),
						$name
					);
			case 'two_factor_backup_reissued':
				return __( 'New backup codes were made. The old ones no longer work.', 'bettershield' );
			case 'two_factor_moved':
				if ( $codes > 0 ) {
					return sprintf(
						/* translators: %s: the name of the plugin two-factor was set up with. */
						__( 'Two-factor sign-in moved here from %s. Your authenticator app and your unused backup codes keep working as before.', 'bettershield' ),
						'' === $name ? __( 'another plugin', 'bettershield' ) : $name
					);
				}

				return sprintf(
					/* translators: %s: the name of the plugin two-factor was set up with. */
					__( 'Two-factor sign-in moved here from %s. Your authenticator app keeps working as before. Your backup codes did not move: make a new set on your profile.', 'bettershield' ),
					'' === $name ? __( 'another plugin', 'bettershield' ) : $name
				);
			case 'two_factor_not_moved':
				return sprintf(
					/* translators: %s: the name of the plugin two-factor was set up with. */
					__( 'Two-factor sign-in from %s could not move here, so your account signs in with its password alone for now. Set up two-factor again on your profile.', 'bettershield' ),
					'' === $name ? __( 'another plugin', 'bettershield' ) : $name
				);
			case 'passkey_registered':
				/* translators: %s: the passkey's name. */
				return '' === $name ? __( 'A passkey was added.', 'bettershield' ) : sprintf( __( 'A passkey was added: %s.', 'bettershield' ), $name );
			case 'passkey_removed':
				return __( 'A passkey was removed.', 'bettershield' );
			case 'app_password_created':
				/* translators: %s: the application password's name. */
				return '' === $name ? __( 'An application password was created.', 'bettershield' ) : sprintf( __( 'An application password was created: %s.', 'bettershield' ), $name );
			case 'app_password_revoked':
				/* translators: %s: the application password's name. */
				return '' === $name ? __( 'An application password was revoked.', 'bettershield' ) : sprintf( __( 'An application password was revoked: %s.', 'bettershield' ), $name );
		}

		return $type;
	}
}
