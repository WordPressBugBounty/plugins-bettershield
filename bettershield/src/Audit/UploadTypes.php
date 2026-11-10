<?php
/**
 * Which file types an account below administrator may upload, read in a
 * request of the account's own.
 *
 * Signing the account in partway through the scan's request and asking
 * `get_allowed_mime_types()` is not enough. A plugin that works the answer
 * out once per request and keeps it in a static gives every later account
 * the answer of whoever asked first, and WordPress asks first: building the
 * REST server reads the list as whoever is signed in. An administrator's scan
 * then reported editors as able to upload SVG when they could not, and a
 * scan with nobody signed in missed a role that really could.
 *
 * So each account is asked in a loopback of its own. The request carries a
 * one-time token whose hash is stored with the account's ID for a minute.
 * The request is that account from its first question about who is signed
 * in, answers only the matching extensions once the site has loaded, and
 * sets no cookie. A loopback that fails reads as unknown rather than as the
 * in-process answer this replaces.
 *
 * It goes to admin-ajax.php: a page cache answers the home page for a query
 * string often, and this address almost never.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UploadTypes {

	/** The query argument the loopback carries its token in. */
	public const ARG = 'bettershield_upload_types';

	/**
	 * Set the first time this read gives an answer here. Until then an open
	 * finding can only have come from the in-process read this replaced.
	 */
	public const ANSWERED_OPTION = 'bettershield_upload_types_answered';

	/** Where a token's hash waits, with the account it stands for. */
	private const TRANSIENT = 'bettershield_upload_types_';

	/**
	 * Answers already read in this request, by account ID. The severity and
	 * the test both ask during one audit, and one loopback per role is enough.
	 *
	 * @var array<int, string[]|null>
	 */
	private static array $read = array();

	/**
	 * What stopped the read most recently in this request, or null.
	 *
	 * @var array{kind: string, code: int}|null
	 */
	private static ?array $failure = null;

	/** The account this request's token stood for; 0 on any other request. */
	private static int $claimed = 0;

	/**
	 * Registered from the plugin's own load, before anything asks who is
	 * signed in. Costs one query-argument lookup on every other request.
	 */
	public static function register_early(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the argument carries its own one-time token, checked against a stored hash.
		if ( ! isset( $_GET[ self::ARG ] ) ) {
			return;
		}

		$account = self::claim( sanitize_text_field( wp_unslash( (string) $_GET[ self::ARG ] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- as above.

		if ( 0 === $account ) {
			return;
		}

		self::$claimed = $account;

		add_filter(
			'determine_current_user',
			static function () use ( $account ): int {
				return $account;
			},
			PHP_INT_MAX
		);

		add_action( 'wp_loaded', array( self::class, 'answer' ), PHP_INT_MAX );
	}

	/**
	 * The risky types the signed-in account may upload, and nothing else.
	 */
	public static function answer(): void {
		// Something that asked who is signed in before this plugin loaded left
		// WordPress holding nobody, and the filter above never runs after that.
		// The token has already said which account this request is.
		if ( self::$claimed > 0 ) {
			wp_set_current_user( self::$claimed );
		}

		$account = wp_get_current_user();

		// Only an account below administrator is ever read this way, so a
		// token that somehow names one answers nothing.
		if ( ! $account->exists() || user_can( $account, 'manage_options' ) ) {
			wp_send_json( array( 'types' => null ), 403 );
		}

		nocache_headers();
		wp_send_json( array( 'types' => self::risky_types( $account ) ) );
	}

	/**
	 * The risky types an account may upload, or null when it could not be
	 * asked.
	 *
	 * @return string[]|null
	 */
	public static function of( \WP_User $account ): ?array {
		/**
		 * Short-circuits the loopback, for a host that cannot reach itself
		 * and for the tests: an array of extensions, or null for unknown.
		 *
		 * @param string[]|null|false $pre     False to ask the site.
		 * @param \WP_User            $account The account being read.
		 */
		$pre = apply_filters( 'bettershield_pre_upload_types', false, $account );

		if ( false !== $pre ) {
			if ( ! is_array( $pre ) ) {
				return null;
			}

			self::note_answered();

			return array_values( array_map( 'strval', $pre ) );
		}

		if ( array_key_exists( $account->ID, self::$read ) ) {
			return self::$read[ $account->ID ];
		}

		self::$read[ $account->ID ] = self::ask( $account );

		if ( null !== self::$read[ $account->ID ] ) {
			self::note_answered();
		}

		return self::$read[ $account->ID ];
	}

	/**
	 * What stopped the read most recently in this request, or null.
	 *
	 * @return array{kind: string, code: int}|null
	 */
	public static function last_failure(): ?array {
		return self::$failure;
	}

	/** Whether this read has ever given an answer on this site. */
	public static function has_answered(): bool {
		return false !== get_option( self::ANSWERED_OPTION );
	}

	private static function note_answered(): void {
		if ( ! self::has_answered() ) {
			update_option( self::ANSWERED_OPTION, time(), false );
		}
	}

	/**
	 * Read in this request, with the account signed in and whoever was
	 * signed in put back after. Right for a filter that asks the signed-in
	 * account every time, wrong for one that keeps its first answer, which
	 * is why the scan asks over a loopback instead.
	 *
	 * @return string[]
	 */
	public static function in_process( \WP_User $account ): array {
		$was = get_current_user_id();

		try {
			wp_set_current_user( $account->ID );

			return self::risky_types( $account );
		} finally {
			wp_set_current_user( $was );
		}
	}

	/**
	 * The extensions in an account's upload list that run as script, or as
	 * PHP. HTML and JavaScript are core's own answer for an account that may
	 * publish unfiltered HTML, so for it only SVG counts.
	 *
	 * @return string[]
	 */
	private static function risky_types( \WP_User $account ): array {
		$risky = array_merge( user_can( $account, 'unfiltered_html' ) ? array( 'svg', 'svgz' ) : Checks::SCRIPT_TYPES, Checks::PHP_TYPES );
		$types = array();

		foreach ( array_keys( get_allowed_mime_types( $account ) ) as $pattern ) {
			foreach ( explode( '|', strtolower( (string) $pattern ) ) as $extension ) {
				if ( in_array( $extension, $risky, true ) ) {
					$types[] = $extension;
				}
			}
		}

		return array_values( array_unique( $types ) );
	}

	/**
	 * One loopback for one account.
	 *
	 * @return string[]|null
	 */
	private static function ask( \WP_User $account ): ?array {
		$token = wp_generate_password( 32, false );
		$key   = self::TRANSIENT . hash( 'sha256', $token );

		set_transient( $key, (int) $account->ID, MINUTE_IN_SECONDS );

		try {
			$response = Http::same_site_at(
				admin_url( 'admin-ajax.php' ) . '?' . self::ARG . '=' . rawurlencode( $token ),
				array( 'headers' => array( 'Cache-Control' => 'no-cache' ) )
			);
		} finally {
			delete_transient( $key );
		}

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			self::$failure = SelfRequest::failure( $response );

			return null;
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $body ) || ! is_array( $body['types'] ?? null ) ) {
			self::$failure = array( 'kind' => SelfRequest::UNREACHABLE, 'code' => 200 );

			return null;
		}

		$allowed = array_merge( Checks::SCRIPT_TYPES, Checks::PHP_TYPES );

		return array_values( array_intersect( array_map( 'strval', $body['types'] ), $allowed ) );
	}

	/**
	 * The account a token stands for, used up as it is read; 0 when the
	 * token is unknown or spent.
	 */
	private static function claim( string $token ): int {
		if ( '' === $token ) {
			return 0;
		}

		$key     = self::TRANSIENT . hash( 'sha256', $token );
		$account = get_transient( $key );

		delete_transient( $key );

		return is_numeric( $account ) ? (int) $account : 0;
	}

	/** Forget the answers read in this request. For the tests. */
	public static function forget(): void {
		self::$read    = array();
		self::$failure = null;
		self::$claimed = 0;
	}
}
