<?php
/**
 * RecoveryMail: the one layout every recovery link email is sent in.
 *
 * The recovery link is how an owner gets back in when they are locked out,
 * and its emails read like any routine notice: plain text from WordPress's
 * default sender, opening on "Here is the link you asked for", with a bare
 * URL between paragraphs (#1963). These say what they are in the subject,
 * come from BetterShield, and lead with keeping the email.
 *
 * HTML with a plain-text part beside it, for these emails alone. Alerts stay
 * plain text (Alerts\Mailer): a security alert in a styled layout reads as
 * marketing. This one is a plain page with one button, and every client that
 * shows only text reads the same words from the plain part.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RecoveryMail {

	/**
	 * Send one recovery email.
	 *
	 * @param string   $to      The address.
	 * @param string   $subject The full subject line.
	 * @param string   $heading The first line, said large.
	 * @param string   $lead    Why this email came, where it needs saying first.
	 * @param string   $url     The recovery link.
	 * @param string[] $lines   What the link does and how long it lasts.
	 * @param string   $last    What to do if this was not asked for.
	 * @return bool Whether the mail was accepted for sending.
	 */
	public static function send( string $to, string $subject, string $heading, string $lead, string $url, array $lines, string $last ): bool {
		$lines = array_values( array_filter( $lines, static fn( $line ): bool => '' !== (string) $line ) );
		$plain = self::plain( $heading, $lead, $url, $lines, $last );

		$from = static fn(): string => 'BetterShield';
		$alt  = static function ( $phpmailer ) use ( $plain ): void {
			$phpmailer->AltBody = $plain; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer's own property.
		};

		// Only for this send: everything else this site mails keeps its own.
		add_filter( 'wp_mail_from_name', $from );
		add_action( 'phpmailer_init', $alt );

		try {
			return (bool) wp_mail(
				$to,
				$subject,
				self::html( $heading, $lead, $url, $lines, $last ),
				array( 'Content-Type: text/html; charset=UTF-8' )
			);
		} finally {
			remove_filter( 'wp_mail_from_name', $from );
			remove_action( 'phpmailer_init', $alt );
		}
	}

	/**
	 * The same words as plain text, for the part a text-only client shows.
	 *
	 * @param string[] $lines
	 */
	public static function plain( string $heading, string $lead, string $url, array $lines, string $last ): string {
		return implode( "\n\n", array_filter( array_merge( array( $heading, $lead, $url ), $lines, array( $last ) ), static fn( $part ): bool => '' !== (string) $part ) );
	}

	/**
	 * A plain page: a heading, a button with the address under it, short
	 * lines, and the last one. Inline styles only, which is all a mail client
	 * reads.
	 *
	 * @param string[] $lines
	 */
	private static function html( string $heading, string $lead, string $url, array $lines, string $last ): string {
		$text = 'margin:0 0 12px;font-size:15px;line-height:1.5;color:#1f2328;';
		$body = '<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#1f2328;">' . esc_html( $heading ) . '</h1>';

		if ( '' !== $lead ) {
			$body .= '<p style="' . $text . '">' . esc_html( $lead ) . '</p>';
		}

		$body .= '<p style="margin:20px 0 8px;"><a href="' . esc_url( $url ) . '" style="display:inline-block;padding:12px 20px;border-radius:6px;background:#1f2328;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;">'
			. esc_html__( 'Open the recovery link', 'bettershield' ) . '</a></p>'
			. '<p style="margin:0 0 20px;font-size:13px;line-height:1.5;color:#59636e;word-break:break-all;">' . esc_html( $url ) . '</p>';

		foreach ( $lines as $line ) {
			$body .= '<p style="' . $text . '">' . esc_html( $line ) . '</p>';
		}

		$body .= '<p style="margin:20px 0 0;font-size:13px;line-height:1.5;color:#59636e;">' . esc_html( $last ) . '</p>';

		return '<!doctype html><html><body style="margin:0;padding:24px;background:#ffffff;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;">'
			. '<div style="max-width:560px;">' . $body . '</div></body></html>';
	}
}
