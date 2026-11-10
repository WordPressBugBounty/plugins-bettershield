<?php
/**
 * The only path from this plugin to the alert recipients' inboxes. Mail about
 * a person's own account goes straight to that person and is not an alert;
 * `Settings` names it.
 *
 * Everything an alert must obey lives here rather than at each call site,
 * because a rule enforced in three places is a rule with three chances to be
 * forgotten. The mute is checked here even though every caller checks it too —
 * this is the last gate before `wp_mail`, and it is the one that must hold.
 *
 * Two promises are structural rather than editorial. **No message this plugin
 * sends contains an upgrade prompt, ever** — not a link, not a mention, not a
 * footer. And every message says how to stop receiving it, appended here so a
 * new kind of alert cannot ship without that line.
 *
 * Plain text on purpose. An alert is read on a phone at an awkward moment, it
 * must survive every mail client, and a security message that renders as a
 * marketing layout reads as one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mailer {

	/**
	 * When the mail server last refused an alert to the owner's addresses,
	 * and which kind, until one is accepted again. What the audit reads to
	 * say alerts are not arriving (#2251).
	 */
	public const REFUSED_OPTION = 'bettershield_alert_refused';

	/**
	 * Send one alert.
	 *
	 * In each recipient's own language (#1885): an address that belongs to an
	 * account here reads the message in that account's language, and any
	 * other address in the site's. The subject and body are written once per
	 * language among the recipients, not once per recipient. A caller that
	 * hands over finished text gets it sent as it is, with the subject's
	 * prefix and the footer still in each reader's language.
	 *
	 * @param string                 $kind    What this message is — `digest` or `critical`. Recorded, never shown.
	 * @param string|callable        $subject Without the site prefix, which is added here; or a callable that writes it.
	 * @param string|callable        $body    Plain text, already in what-happened, why, next-action order; or a callable that writes it.
	 * @param array<string, mixed>   $context Extra detail for the activity record. Never addresses.
	 * @param string[]               $also    Addresses this message is owed besides the recipients.
	 * @return bool Whether the message was handed to WordPress for sending.
	 */
	public static function send( string $kind, $subject, $body, array $context = array(), array $also = array() ): bool {
		$settings = Settings::instance();

		// The last gate. Callers check this too; this is the one that decides.
		if ( ! self::can_send() ) {
			return false;
		}

		// The addresses that asked for this kind of message (#1886), and
		// anyone else it owes, such as the address alerts went to before the
		// one it reports took its place, once each.
		$recipients = $settings->audience( $kind, (int) ( $context['severity'] ?? Writer::SEVERITY_HIGH ) );

		foreach ( $also as $address ) {
			if ( is_email( $address ) && ! in_array( strtolower( $address ), array_map( 'strtolower', $recipients ), true ) ) {
				$recipients[] = $address;
			}
		}

		if ( array() === $recipients ) {
			return false;
		}

		// A receipt identifies this message, not the finding or the reader.
		// It grants no access; feedback still requires the management capability.
		$delivery = bin2hex( random_bytes( 16 ) );
		$prefix = admin_url( 'admin.php?page=bettershield' );
		$languages = self::by_language( $recipients );
		$delivered = true;

		foreach ( $languages as $locale => $addresses ) {
			$switched = switch_to_locale( $locale );

			try {
				$text = preg_replace_callback( '~https?://[^\s<>]+~', static function ( $match ) use ( $delivery, $prefix ) {
					return str_starts_with( $match[0], $prefix ) && str_contains( $match[0], Links::FROM_ALERT ) ? add_query_arg( 'delivery', $delivery, $match[0] ) : $match[0];
				}, self::written( $body ) );

				// Every language is tried even after one is refused, so one
				// refusal never costs the others their alert.
				$delivered = wp_mail(
					$addresses,
					self::subject( self::written( $subject ) ),
					$text . "\n" . self::footer()
				) && $delivered;
			} finally {
				if ( $switched ) {
					restore_previous_locale();
				}
			}
		}

		self::remember( $kind, (bool) $delivered );

		/*
		 * A refused alert is not an info row: the critical one is the alarm
		 * nobody heard, and a site whose mail server refuses everything was
		 * told only by an info line and the test button (#2251).
		 */
		$refused = 'critical' === $kind ? Writer::SEVERITY_HIGH : Writer::SEVERITY_MEDIUM;

		Writer::instance()->record(
			'alert_sent',
			$delivered ? Writer::SEVERITY_INFO : $refused,
			array(
				// The site sends its own alerts. A queued one goes out on
				// whatever request comes next, and crediting that request named
				// a signed-out visitor or an administrator as the sender.
				'actor_type'  => 'system',
				'object_type' => 'alert',
				'object_id'   => $kind,
				'context'     => array_merge(
					$context,
					array(
						'kind' => $kind,
						'delivery' => $delivery,
						// A count, never the addresses. Who a site alerts is not
						// something the activity log needs to accumulate.
						'to'   => count( $recipients ),
						// How many languages it was written in, which is how
						// many messages it took.
						'languages' => count( $languages ),
						// Recorded either way: an alert that failed to send is
						// the case the owner most needs to be able to discover,
						// and silence would look identical to a quiet week.
						'sent' => (bool) $delivered,
					)
				),
			)
		);

		return (bool) $delivered;
	}

	/**
	 * Text as a caller handed it over, written now when it is a callable so it
	 * comes out in the language switched to.
	 *
	 * @param string|callable $text
	 */
	private static function written( $text ): string {
		return is_callable( $text ) ? (string) $text() : (string) $text;
	}

	/**
	 * The language each address reads, from the account it belongs to, or
	 * the site's for an address that is nobody's account here.
	 *
	 * @param string[] $addresses
	 * @return array<string, string[]> Addresses grouped by locale, in first-seen order.
	 */
	public static function by_language( array $addresses ): array {
		// Read before anything is switched: the site's own language, not the
		// language of whoever's request this happens to be.
		$site   = get_locale();
		$groups = array();

		foreach ( $addresses as $address ) {
			$user   = get_user_by( 'email', $address );
			$locale = $user instanceof \WP_User ? get_user_locale( $user ) : $site;

			$groups[ '' !== $locale ? $locale : 'en_US' ][] = $address;
		}

		return $groups;
	}

	/**
	 * Keep the last refusal until a message is accepted again.
	 */
	private static function remember( string $kind, bool $delivered ): void {
		if ( $delivered ) {
			delete_option( self::REFUSED_OPTION );

			return;
		}

		update_option(
			self::REFUSED_OPTION,
			array(
				'at'   => time(),
				'kind' => $kind,
			),
			false
		);
	}

	/**
	 * The last refusal, while no alert has been accepted since.
	 *
	 * @return array{at: int, kind: string}|null
	 */
	public static function refused(): ?array {
		$stored = get_option( self::REFUSED_OPTION, null );

		return is_array( $stored ) && (int) ( $stored['at'] ?? 0 ) > 0
			? array(
				'at'   => (int) $stored['at'],
				'kind' => (string) ( $stored['kind'] ?? '' ),
			)
			: null;
	}

	/**
	 * Send one message to addresses an add-on names, beside the owner's own
	 * rather than instead of them: a help desk that turns mail into tickets,
	 * a second contact told about what nobody picked up.
	 *
	 * The rules every alert keeps are kept: muted means muted, the subject
	 * carries the site's name, the footer says who sent it and how to stop
	 * it, and the activity record says it was sent and to how many, never to
	 * whom. Headers carry what threads a message into one conversation
	 * (`Message-ID`, `In-Reply-To`, `References`); anything that is not a
	 * header line is dropped.
	 *
	 * @param string[]             $to      The addresses, each checked.
	 * @param string               $kind    What this message is. Recorded, never shown.
	 * @param string               $subject Without the site prefix, which is added here.
	 * @param string               $body    Plain text.
	 * @param string[]             $headers Header lines, "Name: value".
	 * @param array<string, mixed> $context Extra detail for the activity record. Never addresses.
	 * @return bool Whether the message was handed to WordPress for sending.
	 */
	public static function send_to( array $to, string $kind, string $subject, string $body, array $headers = array(), array $context = array() ): bool {
		if ( Settings::instance()->is_muted() ) {
			return false;
		}

		$to = array_values( array_unique( array_filter( array_map( 'strval', $to ), 'is_email' ) ) );

		if ( array() === $to ) {
			return false;
		}

		// One header to a line, and nothing a value could smuggle a second into.
		$headers = array_values(
			array_filter(
				array_map( 'strval', $headers ),
				// Recipients come from $to alone, so the count recorded is
				// who it went to.
				static fn( string $line ): bool => 1 === preg_match( '/^[A-Za-z][A-Za-z0-9-]*: [^\r\n]+$/', $line ) && 1 !== preg_match( '/^(To|Cc|Bcc):/i', $line )
			)
		);

		/*
		 * The mailer writes a Message-ID of its own, and one passed as a
		 * header would be a second: the message's own id is set on the
		 * mailer instead, for this message only, so a thread can be started
		 * by it and replied to.
		 */
		$id = '';

		foreach ( $headers as $index => $line ) {
			if ( 0 === stripos( $line, 'Message-ID: ' ) ) {
				$id = trim( substr( $line, strlen( 'Message-ID: ' ) ) );
				unset( $headers[ $index ] );
			}
		}

		$set_id = static function ( $phpmailer ) use ( $id ): void {
			if ( is_object( $phpmailer ) && property_exists( $phpmailer, 'MessageID' ) ) {
				$phpmailer->MessageID = $id; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer's own property.
			}
		};

		if ( 1 === preg_match( '/^<[^<>\s@]+@[^<>\s@]+>$/', $id ) ) {
			add_action( 'phpmailer_init', $set_id );
		}

		try {
			$delivered = wp_mail( $to, self::subject( $subject ), $body . "\n" . self::footer(), array_values( $headers ) );
		} finally {
			remove_action( 'phpmailer_init', $set_id );

			// Core keeps one mailer for the request and never clears its
			// id, so every later message would go out under this one.
			global $phpmailer;

			if ( '' !== $id && is_object( $phpmailer ) && property_exists( $phpmailer, 'MessageID' ) ) {
				$phpmailer->MessageID = ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer's own property.
			}
		}

		Writer::instance()->record(
			'alert_sent',
			Writer::SEVERITY_INFO,
			array(
				'actor_type'  => 'system',
				'object_type' => 'alert',
				'object_id'   => $kind,
				'context'     => array_merge(
					$context,
					array(
						'kind' => $kind,
						'to'   => count( $to ),
						'sent' => (bool) $delivered,
					)
				),
			)
		);

		return (bool) $delivered;
	}

	/**
	 * Prove delivery, on request: one real message through the exact path
	 * every live alert takes, with the honest three-way answer a bare "test
	 * sent" hides. An alerting system nobody can verify is a promise nobody
	 * can trust — and a critical alert has already been shown to vanish on a
	 * refusing mail server, silently.
	 *
	 * @return array{outcome: string, to: int, languages?: array<int, array{address: string, locale: string, language: string}>} Outcome: sent, refused, muted, no_recipient, or too_soon.
	 */
	public static function test(): array {
		$settings = Settings::instance();

		if ( $settings->is_muted() ) {
			return array(
				'outcome' => 'muted',
				'to'      => 0,
			);
		}

		$recipients = $settings->recipients();

		if ( array() === $recipients ) {
			return array(
				'outcome' => 'no_recipient',
				'to'      => 0,
			);
		}

		/*
		 * One proof at a time, and after the two answers above so that a site
		 * which cannot send at all still says why however often it is asked.
		 *
		 * The route behind this is deliberately reachable by a stored
		 * credential — proving delivery takes no protection away, and a
		 * monitoring account may reasonably ask for it. A route in that
		 * position which hands `wp_mail` a message per call is a way to fill
		 * the owner's own inbox and spend the host's outbound-mail allowance,
		 * so it is paced the way the digest next door has always been paced.
		 *
		 * Not released when the message goes: a test that went out has been
		 * answered, and the window is a floor on how often proof is offered
		 * rather than the length of one send.
		 */
		if ( ! Claim::claim( 'alert_test', 5 * MINUTE_IN_SECONDS ) ) {
			return array(
				'outcome' => 'too_soon',
				'to'      => 0,
			);
		}

		$delivered = self::send(
			'test',
			static fn(): string => __( 'Test email: BetterShield alerts can reach you', 'bettershield' ),
			static fn(): string => __( 'Someone sent a test from BetterShield › Settings › Email Alerts. It arrived, so alert emails reach this inbox. Nothing on your site changed.', 'bettershield' ),
			array( 'test' => true )
		);

		return array(
			'outcome'   => $delivered ? 'sent' : 'refused',
			'to'        => count( $recipients ),
			// Which language each address was sent, so the screen can say so
			// (#1885). The addresses are the ones the alerts screen already
			// shows to whoever may press this.
			'languages' => self::languages_of( $recipients ),
		);
	}

	/**
	 * Each address and the language its alerts are written in.
	 *
	 * @param string[] $addresses
	 * @return array<int, array{address: string, locale: string, language: string}>
	 */
	public static function languages_of( array $addresses ): array {
		$said = array();

		foreach ( self::by_language( $addresses ) as $locale => $group ) {
			foreach ( $group as $address ) {
				$said[] = array(
					'address'  => $address,
					'locale'   => (string) $locale,
					'language' => \BetterShield\Support\Language::name_of( (string) $locale ),
				);
			}
		}

		return $said;
	}

	/**
	 * Whether a message would actually be handed to WordPress.
	 *
	 * Separate from `send()` because refusing to send and failing to send are
	 * different facts, and the return of `send()` cannot tell them apart — it
	 * is false for a muted site, for a site with nowhere to send, and for a
	 * mail server that would not take the message. A caller that records
	 * something on the strength of having sent needs to know which it got.
	 *
	 * @param string $kind A kind whose recipients' choices count, such as
	 *                     `digest`; empty for any address at all.
	 */
	public static function can_send( string $kind = '' ): bool {
		$settings = Settings::instance();

		if ( $settings->is_muted() ) {
			return false;
		}

		// A kind names whose choices count: a weekly summary nobody takes
		// is not sent, which is not the same as having nowhere to send.
		return array() !== ( '' === $kind ? $settings->recipients() : $settings->audience( $kind ) );
	}

	/**
	 * `[Site name] What this is`, which is the shape a mail client can filter
	 * on and a person can recognize in a list.
	 */
	public static function subject( string $subject ): string {
		return sprintf(
			/* translators: 1: site name, 2: what the message is about. */
			__( '[%1$s] %2$s', 'bettershield' ),
			self::site_name(),
			$subject
		);
	}

	/**
	 * The site's name as a message calls it, or its address where it has
	 * none: a subject read "[] A critical finding was found", as the footer
	 * once read "from ," (#1774).
	 */
	private static function site_name(): string {
		$site = trim( wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES ) );

		return '' !== $site ? $site : (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Appended to every message, so no kind of alert can ship without telling
	 * its reader how to stop it.
	 *
	 * And whose link that is. Recipients need not be accounts on the site,
	 * and the screen it opens is only for somebody who manages it: an outside
	 * address told simply to change what arrives there met a sign-in form
	 * and nothing saying who could. One message goes to every recipient, so
	 * the one footer says both.
	 */
	private static function footer(): string {
		// A site with no title is named by its address, rather than "from ,".
		$site = self::site_name();

		return "\n-- \n"
			. sprintf(
				/* translators: %s: the site's name, or its address where it has none. */
				__( 'BetterShield on %s sends these emails to addresses the site’s administrators chose. An administrator can change or stop them here:', 'bettershield' ),
				$site
			)
			. "\n" . Links::alert_settings() . "\n"
			. __( 'Not an administrator? Ask the site’s administrator to remove your address.', 'bettershield' ) . "\n";
	}
}
