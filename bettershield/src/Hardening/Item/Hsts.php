<?php
/**
 * Hardening item: tell browsers to refuse plain HTTP for this site.
 *
 * `Items.php` excluded HSTS from the general security-headers item and said
 * why, in the sentence this file exists to honor: it is the one header there
 * that can make a site unreachable, because a browser that has seen it
 * refuses plain HTTP for the whole `max-age` whatever the site does next.
 * Undoing it does not undo it — every browser that already saw the header
 * keeps refusing until the time it was told runs out.
 *
 * That makes it the only item here where **undo is not the whole safety net**,
 * and the shape of this file follows from that:
 *
 * - It refuses to apply on a site that is not already fully HTTPS. There is no
 *   possible good outcome from telling browsers to insist on something the
 *   site cannot serve.
 * - It starts at **five minutes**. Long enough to prove the site is fine over
 *   HTTPS for real visitors and real browsers; short enough that a mistake
 *   costs an afternoon rather than a year. The long duration is a second,
 *   separate decision made once the short one has been lived with.
 * - It never offers `preload`. Preloading is a submission to a list baked into
 *   browsers, removal takes months, and it is not this plugin's to hand out
 *   from a checkbox.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Audit\Certificate;
use BetterShield\Support\SentHeaders;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Hsts {

	/** Five minutes: enough to prove it, cheap to be wrong about. */
	public const SHORT = 300;

	/** Six months, the usual recommendation, once the short one has held. */
	public const LONG = 15768000;

	public const MODE_SHORT = 'short';
	public const MODE_LONG  = 'long';

	/**
	 * Whether these options ask for the form whose undo is real.
	 *
	 * The short form is that one: a browser that saw the header forgets it
	 * within the period, so taking the header away puts the site back inside
	 * five minutes. That is the line between what an assistant may apply on
	 * its own and what waits for a person.
	 *
	 * `includeSubDomains` is on the far side of that line at every duration,
	 * which is why it is answered first. Nothing here can tell whether a
	 * staging, mail or legacy subdomain answers over HTTPS — `availability()`
	 * proves that of this address and of no other — so the only thing between
	 * the option and an unrelated host going dark for the whole period is the
	 * sentence beside the field, and a sentence needs somebody reading it.
	 *
	 * @param array<string, mixed> $options
	 */
	public static function is_short( array $options ): bool {
		if ( 'yes' === ( $options['subdomains'] ?? '' ) ) {
			return false;
		}

		return self::MODE_LONG !== (string) ( $options['mode'] ?? self::MODE_SHORT );
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		$subdomains = __( 'Choose only if every subdomain uses HTTPS, including staging or mail. Any that does not can go offline.', 'bettershield' );
		$note       = self::subdomain_note( is_multisite() && is_subdomain_install(), is_multisite() && is_main_site() );

		if ( null !== $note ) {
			$subdomains .= ' ' . $note;
		}

		return array(
			array(
				'key'         => 'mode',
				'label'       => __( 'How long browsers should insist', 'bettershield' ),
				'description' => __( 'Browsers that saw it keep refusing plain HTTP this long, even after undo.', 'bettershield' ),
				'required'    => true,
				'default'     => self::MODE_SHORT,
				'choices'     => array(
					array(
						'value' => self::MODE_SHORT,
						'label' => __( 'Five minutes, to prove it works', 'bettershield' ),
					),
					array(
						'value' => self::MODE_LONG,
						'label' => __( 'Six months, once you have lived with the short one', 'bettershield' ),
					),
				),
			),
			array(
				'key'         => 'subdomains',
				'label'       => __( 'Include subdomains', 'bettershield' ),
				'description' => $subdomains,
				'required'    => false,
				'default'     => '',
				'choices'     => array(
					array(
						'value' => '',
						'label' => __( 'This domain only', 'bettershield' ),
					),
					array(
						'value' => 'yes',
						'label' => __( 'Every subdomain as well', 'bettershield' ),
					),
				),
			),
		);
	}

	/**
	 * What "every subdomain" means on the main site of a subdomain network:
	 * every site of it. A browser that has seen the header from the network's
	 * domain insists on HTTPS for each of them, so the warning that the option
	 * already carries has to name them. Elsewhere — a single site, a
	 * subdirectory network, a subsite — the sentence would be untrue or
	 * redundant, and there is none.
	 */
	public static function subdomain_note( bool $subdomain_network, bool $main_site ): ?string {
		if ( ! $subdomain_network || ! $main_site ) {
			return null;
		}

		return __( 'On this network, that means every site: all must already use HTTPS.', 'bettershield' );
	}

	/**
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function validate( array $options ) {
		$mode = isset( $options['mode'] ) ? (string) $options['mode'] : self::MODE_SHORT;

		if ( ! in_array( $mode, array( self::MODE_SHORT, self::MODE_LONG ), true ) ) {
			return new \WP_Error( 'bettershield_bad_hsts_mode', __( 'Choose either the short period or the long one.', 'bettershield' ) );
		}

		return array(
			'mode'       => $mode,
			'subdomains' => isset( $options['subdomains'] ) && 'yes' === (string) $options['subdomains'] ? 'yes' : '',
		);
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

		$lines = array(
			self::MODE_LONG === ( $validated['mode'] ?? self::MODE_SHORT )
				? __( 'Tells browsers to use only HTTPS here for six months after each visit.', 'bettershield' )
				: __( 'Tells browsers to use only HTTPS here for 5 minutes after each visit.', 'bettershield' ),
		);

		if ( 'yes' === ( $validated['subdomains'] ?? '' ) ) {
			$lines[] = __( 'Covers every subdomain as well.', 'bettershield' );
		}

		return $lines;
	}

	/**
	 * Whether this can be applied on this site at all.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( ! Certificate::site_is_https() ) {
			return array(
				'available' => false,
				'reason'    => 'https',
				'note'      => HttpsAddress::needed_first(),
			);
		}

		// The header goes out only on requests WordPress sees as encrypted,
		// and WordPress reads that from $_SERVER alone. Where the encryption
		// ends at a proxy that does not say so, every request looks plain and
		// the header is never sent — while the item would otherwise show as
		// applied. Still offered, because the site may be adding the header
		// itself, but never reported as a plain success.
		if ( Server::tls_terminates_upstream() ) {
			return array(
				'available' => true,
				'note'      => __( 'Your site’s HTTPS setup isn’t visible to WordPress, so this would do nothing yet. Ask your host to set the HTTPS server variable in wp-config.php.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	public static function conflict(): ?string {
		$days = Certificate::days_left();

		if ( null !== $days && $days < 0 ) {
			return __( 'This site’s certificate has expired. Renew it first: browsers told to use HTTPS show an error visitors cannot skip.', 'bettershield' );
		}

		if ( null !== $days && $days <= Certificate::SOON ) {
			return sprintf(
				/* translators: %d: number of days. */
				_n(
					'This site’s certificate expires in %d day. Renew it first: once it lapses, browsers told to use HTTPS show an error visitors cannot skip.',
					'This site’s certificate expires in %d days. Renew it first: once it lapses, browsers told to use HTTPS show an error visitors cannot skip.',
					$days,
					'bettershield'
				),
				$days
			);
		}

		return null;
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();

		if ( array() === $options ) {
			return null;
		}

		return self::header_value( $options );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		add_filter( 'wp_headers', array( self::class, 'add_header' ) );
		// wp_headers runs only for the front-end responses WordPress renders
		// itself. The sign-in page, the dashboard and the REST API — the
		// surfaces a password or a token actually crosses — send headers
		// their own way, so each is hooked where the general headers item is.
		add_action( 'login_init', array( self::class, 'send_header' ), 0 );
		add_action( 'admin_init', array( self::class, 'send_header' ), 0 );
		add_filter( 'rest_pre_serve_request', array( self::class, 'send_header_for_rest' ), 10, 1 );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		remove_filter( 'wp_headers', array( self::class, 'add_header' ) );
		remove_action( 'login_init', array( self::class, 'send_header' ), 0 );
		remove_action( 'admin_init', array( self::class, 'send_header' ), 0 );
		remove_filter( 'rest_pre_serve_request', array( self::class, 'send_header_for_rest' ), 10 );
	}

	/**
	 * @param array<string, string> $headers
	 * @return array<string, string>
	 */
	public static function add_header( $headers ): array {
		$headers = is_array( $headers ) ? $headers : array();

		// Never over plain HTTP: the header is meaningless there, and sending
		// it on a request that arrived unencrypted is how a proxy in front of
		// this site gets told something about a connection it did not make.
		if ( ! Server::connection_is_https() ) {
			return $headers;
		}

		/*
		 * Something already sending it is left exactly alone, the way the
		 * general headers item treats every header it adds — which means asking
		 * both places a header can come from: the `wp_headers` array holds
		 * what WordPress is about to send, and a header set by the web server
		 * or by another plugin calling `header()` directly is not in it.
		 *
		 * This is the one header in the plugin where the *value* carries the
		 * strength, so it is the one where overwriting is a downgrade rather
		 * than a duplicate.
		 */
		if ( isset( $headers['Strict-Transport-Security'] ) || SentHeaders::carries( 'Strict-Transport-Security' ) ) {
			return $headers;
		}

		/*
		 * One the web server adds after PHP has answered is in neither place.
		 * The daily same-site probe asks for it, and this stands aside on the
		 * probe's own request so what comes back is the server's; once it has
		 * been seen, the server's is left to stand on its own. Two headers
		 * with different max-ages leave the browser to keep the first.
		 */
		$manager = \BetterShield\Hardening\Manager::instance();

		if ( $manager->is_header_probe() ) {
			return $headers;
		}

		$state   = $manager->item_state( 'hsts' );
		$options = isset( $state['options'] ) && is_array( $state['options'] ) ? $state['options'] : array();

		if ( ! empty( $state['server_sends'] ) ) {
			return $headers;
		}

		$headers['Strict-Transport-Security'] = self::header_value( $options );

		return $headers;
	}

	/**
	 * The same header on a surface that does not run `wp_headers`.
	 *
	 * Sent rather than filtered, through the same decision the filter makes:
	 * never over plain HTTP, and never on top of one already there.
	 */
	public static function send_header(): void {
		if ( headers_sent() ) {
			return;
		}

		$headers = self::add_header( array() );

		if ( isset( $headers['Strict-Transport-Security'] ) ) {
			header( 'Strict-Transport-Security: ' . $headers['Strict-Transport-Security'] );
		}
	}

	/**
	 * REST responses, which bypass `wp_headers` entirely.
	 *
	 * @param bool $served Whether the request has already been served.
	 * @return bool
	 */
	public static function send_header_for_rest( $served ) {
		self::send_header();

		return $served;
	}

	/**
	 * @param array<string, mixed> $options
	 */
	public static function header_value( array $options ): string {
		$seconds = self::MODE_LONG === ( $options['mode'] ?? self::MODE_SHORT ) ? self::LONG : self::SHORT;
		$value   = 'max-age=' . $seconds;

		if ( 'yes' === ( $options['subdomains'] ?? '' ) ) {
			$value .= '; includeSubDomains';
		}

		// `preload` is deliberately never added. It is a submission to a list
		// compiled into browsers, removal from it takes months, and it is not
		// something to hand out from a checkbox on a settings screen.
		return $value;
	}
}
