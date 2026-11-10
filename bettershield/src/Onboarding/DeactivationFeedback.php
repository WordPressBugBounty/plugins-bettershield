<?php
/**
 * Why the plugin is being switched off, asked once on the way out.
 *
 * Asked only where the answer has somewhere to go: the deactivation report
 * `Usage::deactivated()` sends to a site that chose to share usage data. On
 * every other site — sharing off, a staging copy, one site of a network
 * switching off its own copy, which sends nothing — Deactivate works as it
 * always has, so "nothing leaves your site unless you choose it" stays true
 * without a second question.
 *
 * The answer is kept until that report goes and is taken by it, whether the
 * report lands or not. It is stored as the English wording the family's
 * usage service already groups these reasons by, whatever language the
 * dashboard is in, with the free text sanitised and cut to a short length.
 *
 * Only the Deactivate link on the Plugins screen asks. Bulk actions and
 * WP-CLI switch the plugin off without asking, and their report goes without
 * a reason, as it always did.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DeactivationFeedback {

	/** The answer waiting for the deactivation report. autoload=false. */
	public const OPTION = 'bettershield_deactivation_reason';

	/** The longest free-text answer kept, in characters. */
	public const DETAILS_MAX = 200;

	/**
	 * The reasons offered, keyed as the screen sends them, each with the
	 * wording the report carries. English on purpose, and the old form's
	 * wording exactly: the service groups these across the family's plugins
	 * by the words themselves.
	 */
	public const REASONS = array(
		'no_longer_needed' => 'I no longer need the plugin',
		'found_better'     => 'I found a better plugin',
		'not_working'      => "I couldn't get the plugin to work",
		'temporary'        => "It's a temporary deactivation",
		'other'            => 'Other',
	);

	/** The two reasons that take a few words more. */
	private const WITH_DETAILS = array( 'found_better', 'other' );

	public function register(): void {
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	/**
	 * Whether the Deactivate link on this Plugins screen asks first.
	 *
	 * On a single site, wherever deactivating sends the last report. On a
	 * network, only on the network's Plugins screen while the plugin is
	 * network-active: the report is the network's, and one site switching
	 * off its own copy sends nothing.
	 */
	public static function offered(): bool {
		if ( ! Usage::sends_on_deactivation() ) {
			return false;
		}

		if ( ! is_multisite() ) {
			return current_user_can( 'activate_plugins' );
		}

		if ( ! is_network_admin() || ! current_user_can( 'manage_network_plugins' ) ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		return is_plugin_active_for_network( plugin_basename( BETTERSHIELD_FILE ) );
	}

	/** How long an answer waits for the deactivation it was given for. */
	public const FRESH_FOR = 10 * MINUTE_IN_SECONDS;

	/**
	 * Keep an answer for the deactivation report.
	 *
	 * @param string $reason  One of the keys of REASONS.
	 * @param string $details The few words a reason that takes them was given.
	 */
	public static function store( string $reason, string $details = '' ): bool {
		if ( ! isset( self::REASONS[ $reason ] ) ) {
			return false;
		}

		$details = in_array( $reason, self::WITH_DETAILS, true )
			? Text::clip( trim( sanitize_text_field( $details ) ), self::DETAILS_MAX )
			: '';

		$answer = array(
			'reason'  => self::REASONS[ $reason ],
			'details' => $details,
			'at'      => time(),
		);

		// On a network the report is the network's, so its answer is too.
		if ( is_multisite() ) {
			delete_site_option( self::OPTION );

			return add_site_option( self::OPTION, $answer );
		}

		delete_option( self::OPTION );

		return add_option( self::OPTION, $answer, '', false );
	}

	/**
	 * The answer waiting, removed as it is read.
	 *
	 * @return array{reason: string, details: string}|null
	 */
	public static function take(): ?array {
		$stored = is_multisite() ? get_site_option( self::OPTION, null ) : get_option( self::OPTION, null );

		if ( is_multisite() ) {
			delete_site_option( self::OPTION );
		} else {
			delete_option( self::OPTION );
		}

		if ( ! is_array( $stored ) || ! in_array( $stored['reason'] ?? null, self::REASONS, true ) ) {
			return null;
		}

		// Given for the deactivation that follows it at once. One that did
		// not happen leaves an answer nobody gave for a later one, which may
		// come from WP-CLI where nobody was asked: it goes unsent.
		if ( (int) ( $stored['at'] ?? 0 ) < time() - self::FRESH_FOR ) {
			return null;
		}

		return array(
			'reason'  => (string) $stored['reason'],
			'details' => is_string( $stored['details'] ?? null ) ? $stored['details'] : '',
		);
	}

	/**
	 * The script that asks, on the Plugins screen only, and only where the
	 * answer would be sent.
	 */
	public function assets( string $hook ): void {
		if ( 'plugins.php' !== $hook || ! self::offered() ) {
			return;
		}

		$asset_file = BETTERSHIELD_PATH . '/assets/build/deactivate.asset.php';
		$asset      = is_file( $asset_file ) ? require $asset_file : array(
			'dependencies' => array(),
			'version'      => BETTERSHIELD_VERSION,
		);

		wp_enqueue_script(
			'bettershield-deactivate',
			plugins_url( 'assets/build/deactivate.js', BETTERSHIELD_FILE ),
			$asset['dependencies'],
			(string) $asset['version'],
			true
		);
		wp_set_script_translations( 'bettershield-deactivate', 'bettershield', BETTERSHIELD_PATH . '/languages' );
		wp_add_inline_script(
			'bettershield-deactivate',
			'window.bettershieldDeactivate = ' . wp_json_encode(
				array(
					'plugin' => plugin_basename( BETTERSHIELD_FILE ),
					// The owner's label where an add-on gives one.
					'name'   => \BetterShield\Support\Branding::name(),
				)
			) . ';',
			'before'
		);

		wp_enqueue_style(
			'bettershield-deactivate',
			plugins_url( 'assets/build/deactivate.css', BETTERSHIELD_FILE ),
			array(),
			(string) $asset['version']
		);
		wp_style_add_data( 'bettershield-deactivate', 'rtl', 'replace' );
	}
}
