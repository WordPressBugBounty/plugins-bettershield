<?php
/**
 * Hardening item: answer admin-ajax only for this site's own addresses.
 *
 * WordPress lets admin-ajax answer another website, with the visitor's
 * cookies, only for the origins on its allowed list: the site's own home and
 * WordPress addresses. A plugin that widens that list lets any page a
 * signed-in visitor opens call admin-ajax as them and read the answer.
 *
 * This puts the list back to WordPress's own, plus any origins the owner
 * names, on admin-ajax requests only, and refuses every other origin. It is
 * answered late, so a plugin widening the list is answered after it, and
 * just before the cross-origin check records what WordPress decided.
 *
 * A header the web server adds never reaches WordPress's list, so it is not
 * something this can take back, and the finding offers this item only where
 * the widening was found in code. The REST API's own policy is untouched.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AjaxOrigins {

	public const ITEM = 'ajax_origins';

	/** The cross-origin check's task, run early after a change so the finding follows. */
	private const PROBE = 'bettershield_cross_origin_probe';

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields(): array {
		return array(
			array(
				'key'         => 'origins',
				'label'       => __( 'Other websites to allow', 'bettershield' ),
				'description' => __( 'Only add a site or app of yours that needs to read data from this one, like https://shop.example.com.', 'bettershield' ),
				'placeholder' => 'https://app.example.com',
				'required'    => false,
				'default'     => '',
			),
		);
	}

	/**
	 * Each origin as a browser sends it: a scheme, a host and, where it is
	 * not the default, a port, with no path.
	 *
	 * @param array<string, mixed> $options
	 * @return array{origins: string[]}|\WP_Error
	 */
	public static function validate( array $options ) {
		$typed   = $options['origins'] ?? array();
		$entries = is_array( $typed ) ? $typed : (array) preg_split( '/[\s,]+/', is_scalar( $typed ) ? (string) $typed : '' );
		$origins = array();

		foreach ( $entries as $entry ) {
			if ( ! is_scalar( $entry ) || '' === trim( (string) $entry ) ) {
				continue;
			}

			$origin = self::origin( (string) $entry );

			if ( null === $origin ) {
				return new \WP_Error(
					'bettershield_bad_origin',
					sprintf(
						/* translators: %s: what was typed, as typed. */
						__( '“%s” isn’t a website address. Use the form https://example.com, or http://example.com:8080, with no path.', 'bettershield' ),
						substr( wp_strip_all_tags( (string) $entry ), 0, 80 )
					)
				);
			}

			$origins[] = $origin;
		}

		return array( 'origins' => array_values( array_unique( $origins ) ) );
	}

	private static function origin( string $typed ): ?string {
		$typed = rtrim( strtolower( trim( $typed ) ), '/' );
		$parts = wp_parse_url( $typed );

		if ( ! is_array( $parts ) || ! in_array( $parts['scheme'] ?? '', array( 'http', 'https' ), true ) || empty( $parts['host'] ) ) {
			return null;
		}

		if ( isset( $parts['path'] ) || isset( $parts['query'] ) || isset( $parts['fragment'] ) || isset( $parts['user'] ) || str_contains( (string) $parts['host'], '*' ) ) {
			return null;
		}

		return $parts['scheme'] . '://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	/**
	 * Who widened the list, as the last check found it, so the card says
	 * whose feature may stop working.
	 */
	public static function conflict(): ?string {
		$names = \BetterShield\Audit\CrossOrigin::owner_names( 'allowed_http_origins' );
		$names = array_values( array_unique( array_merge( $names, \BetterShield\Audit\CrossOrigin::owner_names( 'allowed_http_origin' ) ) ) );

		if ( array() === $names ) {
			return null;
		}

		return sprintf(
			/* translators: %s: a list of plugin or theme names. */
			__( 'Allowed origins are widened by: %s. A front end or app on another address that calls admin-ajax stops working until its address is added here.', 'bettershield' ),
			implode( ', ', $names )
		);
	}

	/**
	 * @param array<string, mixed> $options Validated.
	 * @return array{tokens: string[], notes: string[]}
	 */
	public static function apply( array $options ): array {
		unset( $options );

		return array(
			'tokens' => array(),
			'notes'  => self::check_again(),
		);
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 * @return array{notes: string[]}
	 */
	public static function revert( array $state ): array {
		unset( $state );

		return array( 'notes' => self::check_again() );
	}

	/**
	 * The cross-origin check, asked to run again in the background, since
	 * only it can tell whether admin-ajax now refuses another website. Asked
	 * once this request ends, when the item's new state is saved and the
	 * check's own request reads it.
	 *
	 * @return string[]
	 */
	private static function check_again(): array {
		add_action( 'shutdown', array( self::class, 'queue_check' ) );

		return array( __( 'The cross-origin check runs again in the background, and the finding updates when it finishes.', 'bettershield' ) );
	}

	public static function queue_check(): void {
		\BetterShield\Cron\Runner::instance()->request_run( self::PROBE, get_current_user_id() );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		unset( $state );

		if ( ! wp_doing_ajax() ) {
			return;
		}

		add_filter( 'allowed_http_origins', array( self::class, 'own_origins' ), PHP_INT_MAX );
		// One below the cross-origin check's witness, so it records this answer.
		add_filter( 'allowed_http_origin', array( self::class, 'refuse_others' ), PHP_INT_MAX - 1, 2 );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );

		remove_filter( 'allowed_http_origins', array( self::class, 'own_origins' ), PHP_INT_MAX );
		remove_filter( 'allowed_http_origin', array( self::class, 'refuse_others' ), PHP_INT_MAX - 1 );
	}

	/**
	 * Attached only on admin-ajax, so every other request answers true.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return ! wp_doing_ajax()
			|| ( false !== has_filter( 'allowed_http_origins', array( self::class, 'own_origins' ) )
				&& false !== has_filter( 'allowed_http_origin', array( self::class, 'refuse_others' ) ) );
	}

	/**
	 * WordPress's own list, built as core builds it, and the owner's.
	 *
	 * @param mixed $origins Unused: the list as other code left it.
	 * @return string[]
	 */
	public static function own_origins( $origins = array() ): array {
		unset( $origins );

		return self::answered();
	}

	/**
	 * @param mixed $allowed The origin WordPress allows, or ''.
	 * @param mixed $origin  The origin it was asked about.
	 * @return mixed
	 */
	public static function refuse_others( $allowed, $origin = '' ) {
		return in_array( (string) $origin, self::answered(), true ) ? $allowed : '';
	}

	/**
	 * @return string[]
	 */
	public static function answered(): array {
		$admin = wp_parse_url( admin_url() );
		$home  = wp_parse_url( home_url() );
		$own   = array();

		foreach ( array( $admin['host'] ?? '', $home['host'] ?? '' ) as $host ) {
			if ( '' !== $host ) {
				$own[] = 'http://' . $host;
				$own[] = 'https://' . $host;
			}
		}

		$state = \BetterShield\Hardening\Manager::instance()->item_state( self::ITEM );
		$extra = isset( $state['options']['origins'] ) ? array_map( 'strval', (array) $state['options']['origins'] ) : array();

		return array_values( array_unique( array_merge( $own, $extra ) ) );
	}
}
