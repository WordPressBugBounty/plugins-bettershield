<?php
/**
 * An owner's label on the admin chrome of their own site.
 *
 * The plugin draws its own name in a handful of places an owner looks at
 * every day: the admin menu, the screens' sidebar, the dashboard widget and
 * the Quick Setup. An add-on may answer `bettershield_branding` with a name,
 * an image and whether the support links are shown, and those places use
 * them. Without an answer nothing here changes anything.
 *
 * Only that chrome. Everything a person reads when something has gone
 * wrong, or has to recognize to get back in, keeps this plugin's name
 * whatever the filter says: the Plugins screen rows, the add-on's license
 * notice, Site Health, alert and recovery mail, the recovery pages, notices
 * and the consent page an assistant is sent to. Somebody locked out reaches
 * for the name the Plugins screen shows. Nothing on those surfaces reads
 * this class.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Branding {

	public const FILTER = 'bettershield_branding';

	/** Long enough for a business name, short enough for the menu. */
	public const MAX_NAME = 40;

	/**
	 * The label in force, or null for this plugin's own.
	 *
	 * A label with no name is no label: an image or a hidden link on its own
	 * would leave the chrome half one product and half another.
	 *
	 * @return array{name: string, logo_url: string, hide_help_links: bool}|null
	 */
	public static function get(): ?array {
		/**
		 * Filters the label the admin chrome carries on this site.
		 *
		 * @param array{name?: string, logo_url?: string, hide_help_links?: bool}|null $branding Null for this plugin's own.
		 */
		$raw = apply_filters( self::FILTER, null );

		if ( ! is_array( $raw ) ) {
			return null;
		}

		$name = isset( $raw['name'] ) && is_scalar( $raw['name'] ) ? trim( sanitize_text_field( (string) $raw['name'] ) ) : '';

		if ( '' === $name ) {
			return null;
		}

		// An image a browser fetches over the web, and nothing else: a data
		// address or inline markup is not drawn where an image is expected.
		$logo = isset( $raw['logo_url'] ) && is_scalar( $raw['logo_url'] ) ? esc_url_raw( (string) $raw['logo_url'], array( 'http', 'https' ) ) : '';

		return array(
			'name'            => mb_substr( $name, 0, self::MAX_NAME ),
			'logo_url'        => $logo,
			'hide_help_links' => ! empty( $raw['hide_help_links'] ),
		);
	}

	/** The name the chrome carries. */
	public static function name(): string {
		$branding = self::get();

		return null === $branding ? __( 'BetterShield', 'bettershield' ) : $branding['name'];
	}

	/** The image the chrome carries in place of the mark, or '' for the mark. */
	public static function logo_url(): string {
		$branding = self::get();

		return null === $branding ? '' : $branding['logo_url'];
	}

	/**
	 * Whether the links to this plugin's support and its publisher's other
	 * plugins are left out, and Hub's menu entry while unconnected
	 * (`Sections::unlisted()`).
	 */
	public static function hides_help_links(): bool {
		$branding = self::get();

		return null !== $branding && $branding['hide_help_links'];
	}
}
