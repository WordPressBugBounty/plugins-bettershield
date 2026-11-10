<?php
/**
 * Switch the site address to HTTPS, and switch it back on its own unless a
 * person confirms it from the dashboard over HTTPS within five minutes (#1289).
 *
 * WordPress has had the switch since 5.7 — Site Health's "Update your site to
 * use HTTPS" checks the certificate with a loopback and calls
 * `wp_update_urls_to_https()` — but with no way back: a certificate that
 * fails for visitors after the switch is never caught, and the dashboard it
 * would be undone from is then on the address that fails. This is core's own
 * switch with the two things it lacks: the same check first, and a pending
 * period that ends in a revert unless somebody proves the HTTPS dashboard
 * works by pressing Keep HTTPS on it.
 *
 * The revert needs nothing to be working but PHP: plain HTTP still reaches
 * the site when the certificate is broken, so the first request of any kind
 * after the five minutes puts both addresses back. It is registered from the
 * plugin's own load rather than from enforcement, because safe mode pauses
 * enforcement and must not pause the way back.
 *
 * Single site only. On a network every site's addresses also live in the
 * network's own tables, which this does not write.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Hardening\Manager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HttpsAddress {

	public const ITEM = 'https_address';

	/** The addresses this replaced, and whether it is still waiting to be kept. */
	public const OPTION = 'bettershield_https_address';

	/** How long a switch waits for Keep HTTPS before it puts the addresses back. */
	public const PENDING_SECONDS = 5 * MINUTE_IN_SECONDS;

	/**
	 * Why it cannot be offered here, before anything is checked over the
	 * network. The certificate is checked when it is applied, not on every
	 * read of the hardening screen: that check is a request to the site.
	 *
	 * @return array{available: bool, reason?: string, note: ?string}
	 */
	public static function availability(): array {
		if ( is_multisite() ) {
			return array(
				'available' => false,
				'reason'    => 'network_admin',
				'note'      => __( 'On a network, each site’s address also lives in the network’s own tables. Change it under Network Admin › Sites.', 'bettershield' ),
			);
		}

		if ( Manager::instance()->is_active( self::ITEM ) ) {
			return array(
				'available' => true,
				'note'      => null,
			);
		}

		$pinned = self::pinned();

		if ( '' !== $pinned ) {
			return array(
				'available' => false,
				'reason'    => 'server_config',
				/* translators: %s: the wp-config.php constant, WP_HOME or WP_SITEURL. */
				'note'      => sprintf( __( '%s is set in wp-config.php, so the address cannot be changed from here. Change it to https there.', 'bettershield' ), $pinned ),
			);
		}

		if ( self::is_https() ) {
			return array(
				'available' => false,
				'reason'    => 'https',
				'note'      => __( 'The site address is already HTTPS.', 'bettershield' ),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * What an item that needs an HTTPS address says while the address is
	 * plain HTTP. One sentence for every such row, pointing at this one where
	 * it can make the switch: two rows gave two different fixes for the same
	 * block (#2575).
	 */
	public static function needed_first(): string {
		$availability = self::availability();

		if ( $availability['available'] ) {
			return __( 'Needs HTTPS. Turn on “HTTPS site address” above first.', 'bettershield' );
		}

		/* translators: %s: why the site address cannot be switched from here, e.g. "WP_HOME is set in wp-config.php…". */
		return sprintf( __( 'Needs HTTPS. %s', 'bettershield' ), (string) $availability['note'] );
	}

	/**
	 * The wp-config.php constant that pins an address, or ''. With either in
	 * place the stored option changes nothing, and core's own switch reverts
	 * itself.
	 */
	private static function pinned(): string {
		// Core answers the option from the constant through its own filter,
		// which is what makes the stored address moot.
		$pins = array(
			'WP_HOME'    => array( 'option_home', '_config_wp_home' ),
			'WP_SITEURL' => array( 'option_siteurl', '_config_wp_siteurl' ),
		);

		foreach ( $pins as $constant => $filter ) {
			if ( defined( $constant ) && false !== has_filter( $filter[0], $filter[1] ) ) {
				return $constant;
			}
		}

		return '';
	}

	/** Whether both stored addresses are HTTPS already. */
	public static function is_https(): bool {
		return 'https' === wp_parse_url( (string) get_option( 'home' ), PHP_URL_SCHEME )
			&& 'https' === wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_SCHEME );
	}

	/**
	 * What WordPress finds when it asks this site for its own front page over
	 * HTTPS, verifying the certificate, in words. Empty when it works.
	 *
	 * Core's own check, the one Site Health asks before offering the switch,
	 * so the two never disagree. It is a request to the site and waits for it.
	 *
	 * @return string[]
	 */
	public static function problems(): array {
		if ( ! function_exists( 'wp_get_https_detection_errors' ) ) {
			require_once ABSPATH . WPINC . '/https-detection.php';
		}

		$words = array(
			'ssl_verification_failed' => __( 'The site answers over HTTPS, but its certificate is not trusted: it may be expired, self-signed or for another name.', 'bettershield' ),
			'https_request_failed'    => __( 'The site does not answer over HTTPS. Ask your host to add a certificate first.', 'bettershield' ),
			'bad_response_code'       => __( 'The site answers over HTTPS with an error instead of its front page.', 'bettershield' ),
			'bad_response_source'     => __( 'Something answers over HTTPS, but not this site.', 'bettershield' ),
		);

		$out = array();

		foreach ( array_keys( (array) wp_get_https_detection_errors() ) as $code ) {
			$out[] = $words[ $code ] ?? __( 'The HTTPS check did not pass.', 'bettershield' );
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Switch both addresses through core's own function, after the same check
	 * core makes, keeping the addresses it replaced.
	 *
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		unset( $options );

		$problems = self::problems();

		if ( array() !== $problems ) {
			return new \WP_Error( 'bettershield_https_not_ready', implode( ' ', $problems ) );
		}

		$prior = array(
			'home'      => (string) get_option( 'home' ),
			'siteurl'   => (string) get_option( 'siteurl' ),
			// What core's flag was, so the way back is that and not a guess.
			'migration' => get_option( 'https_migration_required', null ),
			'until'     => time() + self::PENDING_SECONDS,
			'kept_at'   => 0,
		);

		if ( ! update_option( self::OPTION, $prior, true ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'Nothing was changed: the addresses to come back to could not be stored.', 'bettershield' ) );
		}

		if ( ! function_exists( 'wp_update_urls_to_https' ) ) {
			require_once ABSPATH . WPINC . '/https-migration.php';
		}

		if ( ! wp_update_urls_to_https() ) {
			delete_option( self::OPTION );

			return new \WP_Error( 'bettershield_https_not_switched', __( 'WordPress did not take the new address, so nothing was changed.', 'bettershield' ) );
		}

		return array(
			'tokens' => array(),
			'notes'  => array(
				sprintf(
					/* translators: %d: minutes. */
					__( 'Open the dashboard over HTTPS and press Keep HTTPS within %d minutes, or both addresses go back to http on their own.', 'bettershield' ),
					(int) ( self::PENDING_SECONDS / MINUTE_IN_SECONDS )
				),
				__( 'If a page cache serves this site, clear it so pages are built with the new address.', 'bettershield' ),
			),
		);
	}

	/**
	 * Put both addresses back as they were, and core's flag with them.
	 *
	 * @param array<string, mixed> $state Unused; the addresses are read from their option.
	 * @return true|\WP_Error
	 */
	public static function revert( array $state ) {
		unset( $state );

		$prior = get_option( self::OPTION );

		if ( ! is_array( $prior ) || '' === (string) ( $prior['home'] ?? '' ) || '' === (string) ( $prior['siteurl'] ?? '' ) ) {
			return new \WP_Error( 'bettershield_https_prior_lost', __( 'The addresses to come back to were not found, so nothing was changed. Set them under Settings › General.', 'bettershield' ) );
		}

		// Often on a visitor's request, with nobody signed in: the way back is
		// BetterShield's own write, which the takeover guard lets through.
		TakeoverSettings::as_bettershield(
			static function () use ( $prior ): void {
				update_option( 'home', (string) $prior['home'] );
				update_option( 'siteurl', (string) $prior['siteurl'] );
			}
		);

		// Moving home back fires core's own hook, which decides the flag
		// afresh; what it was before the switch is what it goes back to.
		if ( null === $prior['migration'] ) {
			delete_option( 'https_migration_required' );
		} else {
			update_option( 'https_migration_required', $prior['migration'] );
		}

		delete_option( self::OPTION );

		// Often on a visitor's request, where the audit is not run inline:
		// the finding the switch closed opens again on the next screen.
		\BetterShield\Plugin::owe_audit();

		return true;
	}

	/**
	 * Nothing to hook: the switch is the stored address itself, and the way
	 * back is registered from the plugin's own load, not from enforcement.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {
		unset( $state );
	}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {
		unset( $state );
	}

	/**
	 * Whether the address is HTTPS now: something else moving it back
	 * leaves the item reading on with nothing in force.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function is_enforced( array $state ): bool {
		unset( $state );

		return self::is_https();
	}

	/**
	 * When the five minutes end, if nobody pressed Keep HTTPS.
	 *
	 * @return int|null A Unix time, or null when nothing is pending.
	 */
	public static function pending_until(): ?int {
		if ( ! Manager::instance()->is_active( self::ITEM ) ) {
			return null;
		}

		$prior = get_option( self::OPTION );
		$until = is_array( $prior ) ? (int) ( $prior['until'] ?? 0 ) : 0;

		return $until > 0 ? $until : null;
	}

	/**
	 * Registered from the plugin's own load, on every request, safe mode
	 * included: the way back does not wait for anything else to work. Costs
	 * the hardening state's own autoloaded read on a site that never applied
	 * this.
	 */
	public static function register_early(): void {
		add_action( 'init', array( self::class, 'settle' ), 0 );
	}

	/**
	 * Put the addresses back if the five minutes ran out without Keep HTTPS.
	 */
	public static function settle(): void {
		$until = self::pending_until();

		if ( null === $until || time() < $until ) {
			return;
		}

		Manager::instance()->revert( self::ITEM, Manager::CAUSE_NOT_KEPT );
	}

	/**
	 * A recovery link or printed code was used: somebody is locked out, and
	 * an HTTPS address may be why. A switch still waiting to be kept goes
	 * back at once; so does a kept one when the recovery arrived over plain
	 * HTTP, the one way in a broken certificate leaves.
	 */
	public static function stand_down(): void {
		if ( ! Manager::instance()->is_active( self::ITEM ) ) {
			return;
		}

		if ( null !== self::pending_until() || ! is_ssl() ) {
			Manager::instance()->revert( self::ITEM, Manager::CAUSE_RECOVERY );
		}
	}

	/**
	 * @return array<int, array{key: string, label: string, description: string}>
	 */
	public static function actions(): array {
		if ( null === self::pending_until() ) {
			return array();
		}

		return array(
			array(
				'key'         => 'keep',
				'label'       => __( 'Keep HTTPS', 'bettershield' ),
				'description' => __( 'Works only on a dashboard opened over HTTPS, which proves the new address works.', 'bettershield' ),
			),
		);
	}

	/**
	 * Keep HTTPS: end the pending period. Only from a request that arrived
	 * over HTTPS, because that request is the proof the new address works.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function act( string $action, array $state, array $args = array() ) {
		unset( $state, $args );

		if ( 'keep' !== $action ) {
			return new \WP_Error( 'bettershield_unknown_action', __( 'This item has no such action.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$prior = get_option( self::OPTION );

		if ( ! is_array( $prior ) || 0 === (int) ( $prior['until'] ?? 0 ) ) {
			return new \WP_Error( 'bettershield_https_not_pending', __( 'HTTPS is already kept. There is nothing to confirm.', 'bettershield' ), array( 'status' => 409 ) );
		}

		if ( ! is_ssl() ) {
			return new \WP_Error( 'bettershield_https_keep_over_http', __( 'Open this dashboard over HTTPS and press Keep HTTPS there. Pressed over http, it proves nothing about the new address.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$prior['until']   = 0;
		$prior['kept_at'] = time();

		if ( ! update_option( self::OPTION, $prior, true ) ) {
			return new \WP_Error( 'bettershield_option_failed', __( 'This could not be saved. Press Keep HTTPS again.', 'bettershield' ), array( 'status' => 500 ) );
		}

		return array(
			'kept'    => true,
			// Keeping is not a change of its own to undo: undoing the item
			// puts the addresses back.
			'ledger'  => false,
			'message' => __( 'HTTPS is kept. Undo puts both addresses back to http.', 'bettershield' ),
		);
	}

	/**
	 * The card's one line while the item is on.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		unset( $state );

		$until = self::pending_until();

		if ( null === $until ) {
			return __( 'The site address is HTTPS.', 'bettershield' );
		}

		return sprintf(
			/* translators: %s: a time of day. */
			__( 'Waiting for Keep HTTPS. Goes back to http at %s.', 'bettershield' ),
			wp_date( (string) get_option( 'time_format' ), $until )
		);
	}
}
