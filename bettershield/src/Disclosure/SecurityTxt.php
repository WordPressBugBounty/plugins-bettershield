<?php
/**
 * Serves `/.well-known/security.txt`, so a finder knows how to reach you.
 *
 * The difference between a researcher emailing the owner and posting what
 * they found publicly is, very often, whether the site said where to send it.
 * RFC 9116 is the standards-based way to say it, and no WordPress security
 * plugin makes it a field and a toggle.
 *
 * **Served rather than written.** A file on disk would need a writable web
 * root, would need removing on uninstall, and would be invisible to this
 * plugin the moment somebody edited it. A response assembled on the request
 * turns off cleanly, works on nginx exactly as on Apache, and cannot drift
 * from the settings that describe it.
 *
 * `Expires` is mandatory in RFC 9116, and it is the field that keeps the file
 * honest: a contact published four years ago and never revisited is worse
 * than none, because a finder trusts it and gets nowhere. So the expiry is
 * stored, the response carries it, and an audit check raises a finding as it
 * approaches. This plugin does not publish a promise it is not tracking.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Disclosure;

use BetterShield\Events\Writer;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SecurityTxt {

	public const OPTION = 'bettershield_security_txt';

	/** The path RFC 9116 reserves. Nothing else is served from here. */
	public const PATH = '.well-known/security.txt';

	/** How far ahead a fresh expiry is set when the owner does not choose. */
	public const DEFAULT_MONTHS = 12;

	/** The most characters the contact or the policy address may hold. */
	public const MAX_FIELD_LENGTH = 255;

	private static ?SecurityTxt $instance = null;

	public static function instance(): SecurityTxt {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Early on parse_request: this answers before WordPress decides the
		// address is a 404, and before any theme is asked for one.
		add_action( 'parse_request', array( $this, 'maybe_serve' ), 1 );
	}

	/**
	 * @return array{enabled: bool, contact: string, policy: string, expires: string, root_note: string}
	 */
	public function settings(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'enabled'   => (bool) ( $stored['enabled'] ?? false ),
			'contact'   => (string) ( $stored['contact'] ?? '' ),
			'policy'    => (string) ( $stored['policy'] ?? '' ),
			'expires'   => (string) ( $stored['expires'] ?? '' ),
			// Derived from where WordPress lives, never stored: it is a fact
			// about the install rather than a setting anybody chose.
			'root_note' => $this->root_note(),
		);
	}

	/**
	 * What this cannot do on an install under a path, or an empty string.
	 *
	 * RFC 9116 puts the file at the domain root, and on `example.org/blog/`
	 * that address never reaches WordPress at all — no plugin can answer it.
	 * The address under the install is served and is worth serving, but the
	 * standard one has to be put there by whoever controls the web root, so
	 * this names it rather than letting the toggle imply otherwise.
	 */
	public function root_note(): string {
		$home = wp_parse_url( home_url( '/' ) );

		if ( ! is_array( $home ) || '' === trim( (string) ( $home['path'] ?? '' ), '/' ) ) {
			return '';
		}

		$root = ( isset( $home['scheme'] ) ? $home['scheme'] . '://' : '//' )
			. (string) ( $home['host'] ?? '' )
			. ( isset( $home['port'] ) ? ':' . $home['port'] : '' )
			. '/' . self::PATH;

		return sprintf(
			/* translators: 1: the address the standard reserves, 2: the address this site answers. */
			__( 'WordPress is installed in a subfolder, so the file is at %2$s instead of %1$s. To publish it at %1$s, copy it there with your host’s file manager.', 'bettershield' ),
			$root,
			home_url( '/' . self::PATH )
		);
	}

	/**
	 * What this input would become, or the refusal it earns.
	 *
	 * Separate from the write so a dry run can ask the same question the save
	 * will: a settings import plans every section through its own validator,
	 * and a section without one could only be planned by guessing.
	 *
	 * The note is derived rather than stored, so it is not part of what this
	 * returns — the caller merges it back where a reader expects it.
	 *
	 * @param array<string, mixed> $input
	 * @return array{enabled: bool, contact: string, policy: string, expires: string}|\WP_Error
	 */
	public function validate( array $input ) {
		$current = $this->settings();

		// A yes or a no, and text where text belongs. Cast, the word "false"
		// published the contact, and a list of addresses was stored as the
		// word "Array". The route and a settings document both read here.
		if ( isset( $input['enabled'] ) && ! is_bool( $input['enabled'] ) ) {
			return new \WP_Error(
				'bettershield_bad_enabled',
				__( 'Say true or false for whether security.txt is published.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		foreach ( array( 'contact', 'policy' ) as $key ) {
			if ( isset( $input[ $key ] ) && ! is_string( $input[ $key ] ) ) {
				return new \WP_Error(
					'bettershield_bad_contact',
					__( 'Contact and policy must each be one address, as text.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			// One address is short: a 5,000-character value was saved and
			// grew the option to match, where only its scheme was checked
			// (#2175).
			if ( isset( $input[ $key ] ) && strlen( trim( $input[ $key ] ) ) > self::MAX_FIELD_LENGTH ) {
				return new \WP_Error(
					'bettershield_contact_too_long',
					/* translators: %d: the most characters the field may hold. */
					sprintf( __( 'Keep the contact and policy under %d characters each.', 'bettershield' ), self::MAX_FIELD_LENGTH ),
					array( 'status' => 400 )
				);
			}
		}

		$enabled = $input['enabled'] ?? $current['enabled'];
		$contact = isset( $input['contact'] ) ? trim( (string) $input['contact'] ) : $current['contact'];
		$policy  = isset( $input['policy'] ) ? trim( (string) $input['policy'] ) : $current['policy'];

		if ( $enabled && ! $this->is_valid_contact( $contact ) ) {
			return new \WP_Error(
				'bettershield_bad_contact',
				__( 'Add a contact: an email address or an https address for reports.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		if ( '' !== $policy && ! $this->is_https_url( $policy ) ) {
			return new \WP_Error(
				'bettershield_bad_policy',
				__( 'The policy must be an https address, or empty.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		// A date is text too: anything else is refused before it is read as one.
		if ( isset( $input['expires'] ) && ! is_string( $input['expires'] ) ) {
			return new \WP_Error( 'bettershield_bad_expires', __( 'Choose a future expiry date, or leave it empty to set one a year out.', 'bettershield' ), array( 'status' => 400 ) );
		}

		$given   = isset( $input['expires'] ) ? trim( (string) $input['expires'] ) : null;
		$expires = null !== $given ? $given : $current['expires'];

		/*
		 * A date nobody set just now is renewed rather than refused: a contact
		 * published again is published afresh, an edit to one whose date has
		 * passed vouches for it again, and a renewal asks for exactly that.
		 * The stored date came back with every save, so once it had passed
		 * every edit, and switching the file off and on, was refused for it,
		 * and before then "move the date on" had no way to be done.
		 */
		$kept   = null === $given || $given === $current['expires'];
		$lapsed = '' !== $current['expires'] && false !== strtotime( $current['expires'] ) && strtotime( $current['expires'] ) <= time();

		// A stored date beyond the year, saved before that was refused, is
		// renewed the same way: the card sends no date, so refusing it would
		// leave every edit refused for a date nobody can see (#2250).
		$distant = '' !== $current['expires'] && false !== strtotime( $current['expires'] ) && strtotime( $current['expires'] ) > self::latest_expiry();

		if ( $enabled && $kept && ( ! empty( $input['renew'] ) || ! $current['enabled'] || $lapsed || $distant ) ) {
			$expires = '';
		}

		// Turning it on without naming a date sets one a year out, which is
		// the shape RFC 9116 recommends and better than asking an owner to
		// hand-write an ISO 8601 string.
		if ( $enabled && '' === $expires ) {
			$expires = gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '+' . self::DEFAULT_MONTHS . ' months' ) );
		}

		/*
		 * A date the file cannot carry is refused rather than served: an
		 * unparseable Expires makes the whole document RFC-invalid AND
		 * silently disarms this plugin's own expiry check, which is the
		 * promise-keeping half of the feature. Re-stated in the RFC's own
		 * shape so what is served is canonical whatever was typed.
		 */
		if ( '' !== $expires ) {
			$at = strtotime( $expires );

			if ( false === $at ) {
				return new \WP_Error(
					'bettershield_bad_expires',
					__( 'Use a real expiry date, like 2027-08-20, or leave it empty for one year.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			if ( $enabled && $at <= time() ) {
				return new \WP_Error( 'bettershield_bad_expires', __( 'Choose a future expiry date, or leave it empty to set one a year out.', 'bettershield' ), array( 'status' => 400 ) );
			}

			// RFC 9116 §2.5.5 asks for less than a year, so the contact is
			// looked at again: a date decades out was published as it was,
			// and the reminder a month before it never came (#2250). The
			// same rule holds on a settings import, which saves through here.
			if ( $enabled && $at > self::latest_expiry() ) {
				return new \WP_Error( 'bettershield_bad_expires', __( 'Pick an expiry date within a year. The standard asks that this contact be checked at least yearly.', 'bettershield' ), array( 'status' => 400 ) );
			}

			$expires = gmdate( 'Y-m-d\TH:i:s\Z', $at );
		}

		return array(
			'enabled' => $enabled,
			'contact' => $contact,
			'policy'  => $policy,
			'expires' => $expires,
		);
	}

	/**
	 * Whether saving this input would take away the published way to reach
	 * the owner: the file withdrawn, its contact or policy address replaced or
	 * removed, or its expiry brought forward. Publishing one, or adding to
	 * one, takes nothing away. Neither does input the save would refuse,
	 * since nothing is written.
	 *
	 * @param array<string, mixed> $input
	 */
	public function weakens( array $input ): bool {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return false;
		}

		$current = $this->settings();

		if ( ! $current['enabled'] ) {
			return false;
		}

		return ! $next['enabled']
			|| $next['contact'] !== $current['contact']
			|| ( '' !== $current['policy'] && $next['policy'] !== $current['policy'] )
			|| ( '' !== $current['expires'] && strtotime( $next['expires'] ) < strtotime( $current['expires'] ) );
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function update_settings( array $input ) {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		/*
		 * Before the write, so the way back exists whether or not it succeeds,
		 * and the write is abandoned where it does not: an address published
		 * with no record of what was there before is a promise nobody can
		 * withdraw by pressing undo.
		 *
		 * Both sides carry the note, which is derived from where WordPress
		 * lives and identical either way — so the ledger compares the change
		 * the owner actually made rather than always finding one.
		 */
		$before = $this->settings();
		$after  = array_merge( $next, array( 'root_note' => $this->root_note() ) );

		// A save that changes nothing writes nothing: no undo row, and no
		// "published" event for a publication that already stood. The screen
		// no longer sends one, but the route is open to any caller with the
		// capability, and a log filling with changes nobody made is noise
		// exactly where the record must stay readable.
		if ( SettingsLedger::same( $before, $after ) ) {
			return $before;
		}

		$recorded = SettingsLedger::record( 'security_txt', $before, $after );

		if ( false === $recorded ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		update_option( self::OPTION, $next, false );

		Writer::instance()->record(
			$next['enabled'] ? 'security_txt_published' : 'security_txt_withdrawn',
			Writer::SEVERITY_INFO,
			array( 'object_type' => 'disclosure' )
		);

		// The reader's shape, so every caller sees the same one.
		return $this->settings();
	}

	/**
	 * Answer the reserved address, and nothing else.
	 */
	public function maybe_serve(): void {
		if ( ! $this->is_the_reserved_path() ) {
			return;
		}

		$settings = $this->settings();

		/*
		 * Not switched on: say nothing at all, and in particular never answer
		 * 200 with an empty body — that tells a finder there is a disclosure
		 * policy and then gives them none, which is worse than a 404.
		 */
		if ( ! $settings['enabled'] ) {
			return;
		}

		$body = $this->body( $settings );

		if ( '' === $body ) {
			return;
		}

		status_header( 200 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		nocache_headers();

		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- assembled from validated fields and served as text/plain, where HTML escaping would corrupt it.
		exit;
	}

	/**
	 * The file, in the order RFC 9116 documents.
	 *
	 * @param array<string, mixed> $settings
	 */
	public function body( array $settings ): string {
		// This is a line-oriented format and every value below becomes part
		// of a line: a control character in one would let a stored value
		// write lines of its own. Belt over the input validation.
		$field   = static function ( $value ): string {
			return trim( (string) preg_replace( '/[\x00-\x1f\x7f]/', '', (string) $value ) );
		};
		$contact = $field( $settings['contact'] ?? '' );

		if ( '' === $contact ) {
			return '';
		}

		$lines = array(
			// A bare address gains the scheme; one the owner already wrote in
			// full is served exactly as they wrote it.
			'Contact: ' . ( is_email( $contact ) ? 'mailto:' . $contact : $contact ),
		);

		if ( '' !== $field( $settings['expires'] ?? '' ) ) {
			$lines[] = 'Expires: ' . $field( $settings['expires'] );
		}

		if ( '' !== $field( $settings['policy'] ?? '' ) ) {
			$lines[] = 'Policy: ' . $field( $settings['policy'] );
		}

		// Where this file itself lives, which is how a finder tells a genuine
		// one from a copy somebody pasted onto another host.
		$lines[] = 'Canonical: ' . home_url( '/' . self::PATH );
		/*
		 * The language tag as the site states it, not its first two letters:
		 * cutting `bn-BD` to `bn` is right by luck, and cutting a
		 * three-letter code like `fil` or `haw` to `fi`/`ha` names a
		 * different language entirely. RFC 9116 wants a tag, and core's own
		 * value already is one.
		 */
		$language = strtolower( (string) get_bloginfo( 'language' ) );

		if ( 1 === preg_match( '/^[a-z]{2,3}(-[a-z0-9]{2,8})*$/', $language ) ) {
			$lines[] = 'Preferred-Languages: ' . $language;
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Days until the published expiry, or null when nothing is published.
	 *
	 * The audit reads this: a lapsed contact is worse than none, because a
	 * finder trusts it and gets nowhere.
	 */
	public function days_until_expiry(): ?int {
		$settings = $this->settings();

		if ( ! $settings['enabled'] || '' === $settings['expires'] ) {
			return null;
		}

		$at = strtotime( $settings['expires'] );

		if ( false === $at ) {
			return null;
		}

		return (int) floor( ( $at - time() ) / DAY_IN_SECONDS );
	}

	/**
	 * Whether a request address is the one this answers.
	 *
	 * Measured against where WordPress lives rather than against the bare
	 * literal: an install under a path — `example.org/blog/` — sends every
	 * request through that prefix, so comparing the whole path matched
	 * nothing there and the file was never served on any of those sites.
	 *
	 * Pure and static so it can be proved without a request: the caller ends
	 * in `exit`, and a matcher that cannot be tested is one nobody notices
	 * has stopped matching.
	 */
	public static function serves( string $uri ): bool {
		$path = strtolower( trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' ) );
		$home = strtolower( trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' ) );

		if ( '' !== $home ) {
			if ( $path !== $home && 0 !== strpos( $path, $home . '/' ) ) {
				return false;
			}

			$path = trim( substr( $path, strlen( $home ) ), '/' );
		}

		// The reserved location, and the legacy root one older tooling still
		// looks at.
		return self::PATH === $path || 'security.txt' === $path;
	}

	/**
	 * The latest expiry the file may carry: a year out, the same as the
	 * date set when the owner does not choose one.
	 */
	private static function latest_expiry(): int {
		return (int) strtotime( '+' . self::DEFAULT_MONTHS . ' months' );
	}

	private function is_the_reserved_path(): bool {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a path comparison; never stored, never echoed.
		return self::serves( isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '' );
	}

	private function is_valid_contact( string $contact ): bool {
		/*
		 * The three shapes RFC 9116 documents. A bare address is accepted and
		 * served as `mailto:`; one already written that way was refused,
		 * which told an owner following the standard that they had it wrong.
		 */
		if ( 0 === stripos( $contact, 'mailto:' ) ) {
			// `is_email()` hands back the address itself when it likes it, so
			// the comparison is what makes this a bool.
			return false !== is_email( substr( $contact, 7 ) );
		}

		if ( 0 === stripos( $contact, 'tel:' ) ) {
			return 1 === preg_match( '/^tel:\+?[0-9.\-() ]{3,30}$/i', $contact );
		}

		return is_email( $contact ) || $this->is_https_url( $contact );
	}

	private function is_https_url( string $url ): bool {
		return 'https' === strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) )
			&& '' !== (string) wp_parse_url( $url, PHP_URL_HOST );
	}
}
