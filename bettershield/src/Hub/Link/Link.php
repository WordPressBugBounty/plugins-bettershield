<?php
/**
 * The Hub link: whether this site tells BetterShield Hub what happens on it
 * as it happens, and the key it signs what it sends with.
 *
 * Without it the hub learns what happened on a site when it next reads the
 * site, every few hours. With it the site sends its security events within
 * minutes, and a high or critical one sooner, so an alert the hub sends is
 * about now. It is the owner's choice and off until they make it: connecting
 * to the hub does not turn it on by itself, and nothing in this plugin waits
 * on it.
 *
 * - **The key.** Turning the link on makes an Ed25519 key pair with the sodium
 *   WordPress bundles. The secret half is kept in an option of its own that is
 *   never autoloaded, and is never shown or sent. The hub learns the public
 *   half by reading `get-hub-link` over the grant it already holds, and trusts
 *   no key it learned any other way. The key calls nothing on this site: it
 *   only signs what the site sends. Turning the link off, a disconnect on
 *   either side, and the hub saying it no longer reads this site each delete
 *   it.
 * - **Where.** Only to hub.bettershield.ai, the one host the link is on the
 *   outbound list for, and only while this site is connected to that hub.
 * - **Which site.** The key is bound to the address it was made at. A copy of
 *   the site at another address carries the same key in its database, and
 *   sending from there would be the copy speaking as the original. So a copy
 *   sends nothing and offers the hub no key until the link is turned on there,
 *   which makes it a key of its own. A copy marked as staging sends nothing.
 *
 * What is sent, and when, is `Push`'s and `Heartbeat`'s; signing and sending
 * one message is `Wire`'s.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hub\Link;

use BetterShield\Events\Writer;
use BetterShield\Mcp\Hub;
use BetterShield\Onboarding\SiteIdentity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Link {

	/**
	 * The owner's choice and what it was made with: whether it is on, the id
	 * the site signs as, the public key, the classes it sends and the address
	 * the key was made at. Autoloaded, because once the link is on it is read
	 * by every request that writes to the log; while the link is off, no
	 * visitor's request reads it at all (`Push::scheduled()`).
	 */
	public const OPTION = 'bettershield_hub_link';

	/** The secret half of the key, alone, and never autoloaded. */
	public const KEY_OPTION = 'bettershield_hub_link_key';

	/** The one host the link sends to. */
	public const HOST = 'hub.bettershield.ai';

	/** Why the link is not sending, when it is not. */
	public const OFF         = 'off';
	public const UNAVAILABLE = 'unavailable';
	public const STAGING     = 'staging';
	public const MOVED       = 'moved';
	public const OTHER_HUB   = 'other_hub';
	public const NOT_HUB     = 'not_connected';

	/** The first line of what a proof of the key signs, naming its format. */
	public const PROOF_FORMAT = 'bettershield hub link proof v1';

	/** The length of an Ed25519 secret key, in bytes. */
	private const SECRET_BYTES = 64;

	/**
	 * The stored choice, in one shape whatever is stored.
	 *
	 * Posture is sent unless the owner turned it off, and the full log only
	 * once they turn it on; the alerting class is always sent and is not a
	 * choice.
	 *
	 * @return array{enabled: bool, site: string, public_key: string, posture: bool, full_log: bool, home: string, since: int}
	 */
	public static function record(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$on     = ! empty( $stored['enabled'] ) && is_string( $stored['public_key'] ?? null ) && '' !== $stored['public_key'];

		return array(
			'enabled'    => $on,
			'site'       => $on ? (string) ( $stored['site'] ?? '' ) : '',
			'public_key' => $on ? (string) $stored['public_key'] : '',
			'posture'    => ! array_key_exists( 'posture', $stored ) || ! empty( $stored['posture'] ),
			'full_log'   => ! empty( $stored['full_log'] ),
			'home'       => $on ? (string) ( $stored['home'] ?? '' ) : '',
			'since'      => $on ? (int) ( $stored['since'] ?? 0 ) : 0,
		);
	}

	/**
	 * The link as its undo row keeps it: on or off, and which classes.
	 *
	 * @return array{on: bool, posture: bool, full_log: bool}
	 */
	public static function undoable(): array {
		$record = self::record();

		return array(
			'on'       => $record['enabled'],
			'posture'  => $record['posture'],
			'full_log' => $record['full_log'],
		);
	}

	/**
	 * Put the link back as an undo row kept it. Turning it on again needs the
	 * hub still connected, and says so where it is not.
	 *
	 * @param array<string, mixed> $values
	 * @return true|\WP_Error
	 */
	public static function put_back( array $values ) {
		$posture  = ! empty( $values['posture'] );
		$full_log = ! empty( $values['full_log'] );

		if ( empty( $values['on'] ) ) {
			self::disable( 'owner' );
			self::set_classes( $posture, $full_log );

			return true;
		}

		return self::enable( $posture, $full_log );
	}

	/**
	 * Write the link's way back before an owner's change to it (#1824).
	 *
	 * @param array{on: bool, posture: bool, full_log: bool} $after
	 */
	private static function record_undo( array $after ): bool {
		return false !== \BetterShield\Undo\SettingsLedger::record( 'hub_link', self::undoable(), $after );
	}

	/** Whether the owner has the link on, whatever stops it sending right now. */
	public static function is_on(): bool {
		return self::record()['enabled'];
	}

	/**
	 * Why the link is not sending right now, or '' when it may.
	 *
	 * In the order a send meets them. Off, with no key, is off. A staging copy
	 * and a copy at another address keep the owner's choice and send nothing,
	 * because the answer that stops them is the owner's to undo. A site whose
	 * hub grant has gone is no longer connected, which ends the link
	 * (`Push::run()`).
	 */
	public static function standing(): string {
		$record = self::record();

		if ( ! $record['enabled'] || '' === self::secret() ) {
			return self::OFF;
		}

		if ( ! self::sodium() ) {
			return self::UNAVAILABLE;
		}

		if ( SiteIdentity::is_staging() ) {
			return self::STAGING;
		}

		if ( SiteIdentity::current()['home'] !== $record['home'] ) {
			return self::MOVED;
		}

		return self::reach();
	}

	/**
	 * Why the link cannot be turned on here, or '' when it can.
	 *
	 * The same answers as `standing()` makes about a link that is on, less the
	 * two that turning it on settles: off, and a key made at another address.
	 */
	public static function refusal(): string {
		if ( ! self::sodium() ) {
			return self::UNAVAILABLE;
		}

		if ( SiteIdentity::is_staging() ) {
			return self::STAGING;
		}

		return self::reach();
	}

	/**
	 * Whether the link can be offered with a connection to a hub at this
	 * host, which the consent page asks before the grant exists: the same
	 * answers as `refusal()`, with the host the connection is for standing in
	 * for the grant.
	 */
	public static function offered_to( string $host ): bool {
		return self::HOST === $host && self::sodium() && ! SiteIdentity::is_staging();
	}

	/**
	 * Whether this site holds a grant for hub.bettershield.ai: '' when it
	 * does, otherwise whether it holds one for a hub at another address or
	 * none at all.
	 */
	private static function reach(): string {
		$apps = Hub::apps();

		foreach ( $apps as $app ) {
			if ( self::HOST === (string) $app['hub'] ) {
				return '';
			}
		}

		return array() === $apps ? self::NOT_HUB : self::OTHER_HUB;
	}

	/**
	 * Turn the link on.
	 *
	 * A fresh key every time it is turned on, bound to this address, and the
	 * log is sent from here on rather than from its beginning. On a link that
	 * is already on and sending, only the classes change.
	 *
	 * @param int $user_id Who turned it on, where that is not the signed-in account: the approval a hub connection's code carried.
	 * @return true|\WP_Error
	 */
	public static function enable( bool $posture = true, bool $full_log = false, int $user_id = 0 ) {
		$refusal = self::refusal();

		if ( '' !== $refusal ) {
			return new \WP_Error( 'bettershield_hub_link_unavailable', self::refusal_message( $refusal ), array( 'status' => 409 ) );
		}

		if ( '' === self::standing() ) {
			self::set_classes( $posture, $full_log );

			return true;
		}

		if ( ! self::record_undo( array( 'on' => true, 'posture' => $posture, 'full_log' => $full_log ) ) ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		$pair = sodium_crypto_sign_keypair();

		update_option( self::KEY_OPTION, base64_encode( sodium_crypto_sign_secretkey( $pair ) ), false );
		update_option(
			self::OPTION,
			array(
				'enabled'    => true,
				// The id the site signs as: random, so it says nothing about
				// the site, and new with each key.
				'site'       => 'st_' . bin2hex( random_bytes( 12 ) ),
				'public_key' => self::base64url( sodium_crypto_sign_publickey( $pair ) ),
				'posture'    => $posture,
				'full_log'   => $full_log,
				'home'       => SiteIdentity::current()['home'],
				'since'      => time(),
			),
			true
		);

		Push::start();

		Writer::instance()->record(
			'hub_link_enabled',
			Writer::SEVERITY_MEDIUM,
			self::attributed(
				array(
					'object_type' => 'setting',
					'object_id'   => self::OPTION,
					'context'     => array(
						'host'     => self::HOST,
						'posture'  => $posture,
						'full_log' => $full_log,
					),
				),
				$user_id
			)
		);

		return true;
	}

	/**
	 * Turn the link off, and forget its key and its place in the log.
	 *
	 * @param string $reason `owner`; `disconnected`, when this site no longer
	 *                       holds the hub's grant; `hub`, when the hub said it
	 *                       no longer reads this site or another address
	 *                       holds the key.
	 */
	public static function disable( string $reason ): void {
		$record = self::record();

		// Whatever is left on the schedule goes, whether or not there is
		// anything else to end.
		Push::stop();

		if ( ! $record['enabled'] && '' === self::secret() ) {
			return;
		}

		// Only the owner's own switch has a way back: a link ended because
		// the hub's grant did cannot be turned on again from an undo row.
		if ( 'owner' === $reason && $record['enabled'] ) {
			self::record_undo( array( 'on' => false, 'posture' => $record['posture'], 'full_log' => $record['full_log'] ) );
		}

		delete_option( self::KEY_OPTION );

		// Kept as the owner's class choices rather than deleted, so turning
		// the link on again offers what they chose before.
		update_option(
			self::OPTION,
			array(
				'enabled'  => false,
				'posture'  => $record['posture'],
				'full_log' => $record['full_log'],
			),
			true
		);

		if ( ! $record['enabled'] ) {
			return;
		}

		Writer::instance()->record(
			'hub_link_disabled',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array( 'reason' => $reason ),
			)
		);
	}

	/**
	 * Whether these classes stop one the link is sending now: monitoring
	 * taken away, as turning the link off takes it away. Choosing classes for
	 * a link that is off sends nothing less than it sends.
	 */
	public static function narrows( bool $posture, bool $full_log ): bool {
		$record = self::record();

		return $record['enabled'] && ( ( $record['posture'] && ! $posture ) || ( $record['full_log'] && ! $full_log ) );
	}

	/** Which classes besides the alerting one the link sends. */
	public static function set_classes( bool $posture, bool $full_log ): void {
		$record = self::record();
		$narrow = self::narrows( $posture, $full_log );

		if ( $record['posture'] === $posture && $record['full_log'] === $full_log ) {
			return;
		}

		self::record_undo( array( 'on' => $record['enabled'], 'posture' => $posture, 'full_log' => $full_log ) );

		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$stored['posture']  = $posture;
		$stored['full_log'] = $full_log;

		update_option( self::OPTION, $stored, true );

		// A feed turned down is said at high, a class the hub always receives.
		// At medium the record was itself a posture event, and the change it
		// described kept it from the hub.
		Writer::instance()->record(
			'setting_changed',
			$narrow ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array(
					'posture'  => $posture,
					'full_log' => $full_log,
				),
			)
		);
	}

	/**
	 * The signature header's value for a body, or '' when there is no key to
	 * sign with.
	 */
	public static function sign( string $body ): string {
		$secret = self::secret();

		return '' === $secret ? '' : 'ed25519=' . self::base64url( sodium_crypto_sign_detached( $body, $secret ) );
	}

	/**
	 * The key the digests that stand for people are taken with, derived from
	 * the link's own key: the hub can tell two events by one account from two
	 * by two accounts, and never which account. Empty without a key.
	 */
	public static function digest_key(): string {
		$secret = self::secret();

		return '' === $secret ? '' : hash_hmac( 'sha256', 'bettershield hub link: who', $secret, true );
	}

	/**
	 * What `get-hub-link` answers: on only while the link may send, with the
	 * public key and the id the site signs as. Never the secret key.
	 *
	 * Any site can answer with another site's public key and id, so with the
	 * hub's nonce the answer also carries a proof: the link key's signature
	 * over `proof_text()`, which only the site holding the secret half can
	 * make. Empty without a challenge, while the link is off, and when the
	 * key stored here is not the one the record offers.
	 *
	 * @param string $challenge The hub's nonce, 32 bytes of base64url, or '' for none.
	 * @return array{enabled: bool, public_key: string, site: string, classes: array{alerting: bool, posture: bool, full_log: bool}, proof: string}
	 */
	public static function read( string $challenge = '' ): array {
		$record = self::record();
		$on     = '' === self::standing();

		return array(
			'enabled'    => $on,
			'public_key' => $on ? $record['public_key'] : '',
			'site'       => $on ? $record['site'] : '',
			'classes'    => array(
				'alerting' => true,
				'posture'  => $record['posture'],
				'full_log' => $record['full_log'],
			),
			'proof'      => $on ? self::proof( $record, $challenge ) : '',
		);
	}

	/**
	 * What a proof signs, one part a line: the format, the hub it is for,
	 * this site's address as the token exchange gave it to the hub, the id
	 * the site signs as and the challenge. A proof for one hub, address, id
	 * or challenge is therefore no good for another.
	 */
	public static function proof_text( string $site, string $challenge ): string {
		return implode( "\n", array( self::PROOF_FORMAT, 'https://' . self::HOST, untrailingslashit( home_url( '/' ) ), $site, $challenge ) );
	}

	/**
	 * The signature over `proof_text()`, or '' when there is no valid
	 * challenge or the secret key's public half is not the key the record
	 * offers.
	 *
	 * @param array<string, mixed> $record
	 */
	private static function proof( array $record, string $challenge ): string {
		$secret = self::secret();

		if ( 1 !== preg_match( '/^[A-Za-z0-9_-]{43}$/D', $challenge ) || '' === $secret ) {
			return '';
		}

		if ( ! hash_equals( self::base64url( sodium_crypto_sign_publickey_from_secretkey( $secret ) ), (string) $record['public_key'] ) ) {
			return '';
		}

		return self::base64url( sodium_crypto_sign_detached( self::proof_text( (string) $record['site'], $challenge ), $secret ) );
	}

	/**
	 * The link as the Hub card reads it.
	 *
	 * @return array<string, mixed>
	 */
	public static function state(): array {
		$record = self::record();

		return array(
			'host'     => self::HOST,
			'on'       => $record['enabled'],
			// Why a link that is on sends nothing right now; '' while it sends.
			'standing' => $record['enabled'] ? self::standing() : self::OFF,
			// Why it cannot be turned on here; '' when it can.
			'refusal'  => self::refusal(),
			'posture'  => $record['posture'],
			'full_log' => $record['full_log'],
			'since'    => $record['since'] > 0 ? gmdate( 'c', $record['since'] ) : null,
		) + Push::status();
	}

	/** What to tell the owner when the link cannot be turned on. */
	public static function refusal_message( string $refusal ): string {
		switch ( $refusal ) {
			case self::UNAVAILABLE:
				return __( 'The Hub link cannot be turned on: this server’s PHP cannot create its signing key.', 'bettershield' );
			case self::STAGING:
				return __( 'This site is marked a staging copy and sends nothing to the hub. Change that on the Overview.', 'bettershield' );
			case self::OTHER_HUB:
				return __( 'This site is connected to a different hub; the Hub link sends only to hub.bettershield.ai.', 'bettershield' );
			default:
				return __( 'This site is not connected to hub.bettershield.ai, where the Hub link sends. Connect it first.', 'bettershield' );
		}
	}

	/** Everything this class and its parts store, gone. Called on uninstall. */
	public static function forget(): void {
		Push::forget();
		delete_option( self::KEY_OPTION );
		delete_option( self::OPTION );
	}

	/** The secret key, or '' when there is none or it is not one. */
	private static function secret(): string {
		$secret = base64_decode( (string) get_option( self::KEY_OPTION, '' ), true );

		return is_string( $secret ) && self::SECRET_BYTES === strlen( $secret ) ? $secret : '';
	}

	/** Whether this PHP can sign: its own sodium, or the copy WordPress bundles. */
	private static function sodium(): bool {
		return function_exists( 'sodium_crypto_sign_keypair' ) && function_exists( 'sodium_crypto_sign_detached' );
	}

	/**
	 * A record's arguments with the account that acted named, where it is not
	 * the signed-in one.
	 *
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>
	 */
	private static function attributed( array $args, int $user_id ): array {
		$user = $user_id > 0 ? get_userdata( $user_id ) : false;

		if ( ! $user instanceof \WP_User ) {
			return $args;
		}

		return $args + array(
			'actor_type'  => 'user',
			'actor_id'    => (int) $user->ID,
			'actor_label' => '' !== $user->display_name ? $user->display_name : $user->user_login,
		);
	}

	/** Base64 for a URL or a header: the alphabet's two symbols swapped, and no padding. */
	private static function base64url( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}
}
