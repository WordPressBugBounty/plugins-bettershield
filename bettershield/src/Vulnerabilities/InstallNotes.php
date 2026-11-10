<?php
/**
 * What is already known about a plugin, said before it is installed.
 *
 * Every signal this plugin has about a plugin's health used to arrive after
 * the install: closed by the directory, not updated for years, a known hole
 * in the version installed. The cheapest moment to hear it is on Plugins, Add
 * New, beside the Install button.
 *
 * Built from what is already in hand, and nothing else: the date the
 * directory's own answer on that screen carries, and what the closed-plugin
 * and vulnerability checks already stored. No request is made for it, and
 * nothing is blocked; the button works exactly as it did.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class InstallNotes {

	public function register(): void {
		add_filter( 'plugin_install_description', array( $this, 'description' ), 10, 2 );
	}

	/**
	 * The card's description, with what is known said under it.
	 *
	 * Not among the card's links: core sets those in a column 120px wide, so
	 * a sentence there wrapped to five lines and two notes ran over the
	 * bottom of the card. Core prints the description inside a paragraph, so
	 * each note is a span set on a line of its own, with the icon beside the
	 * text. The screen carries none of this plugin's styles, hence inline.
	 *
	 * @param mixed $description The card's description.
	 * @param mixed $plugin      The directory's answer for this plugin.
	 * @return mixed
	 */
	public function description( $description, $plugin ) {
		if ( ! is_string( $description ) ) {
			return $description;
		}

		foreach ( self::notes( is_array( $plugin ) ? $plugin : (array) $plugin ) as $note ) {
			$description .= '<span class="bettershield-install-note" style="display:flex;gap:4px;align-items:flex-start;margin-top:8px">'
				. '<span class="dashicons dashicons-warning" style="flex:none;color:#996800" aria-hidden="true"></span>'
				. '<span>' . esc_html( $note ) . '</span></span>';
		}

		return $description;
	}

	/**
	 * What is known about one plugin in the directory's answer, as sentences.
	 *
	 * @param array<string, mixed> $plugin
	 * @return string[]
	 */
	public static function notes( array $plugin ): array {
		$slug = sanitize_key( (string) ( $plugin['slug'] ?? '' ) );

		if ( '' === $slug ) {
			return array();
		}

		$notes = array();
		$known = Directory::known()[ $slug ] ?? null;

		if ( is_array( $known ) && Directory::CLOSED === ( $known['status'] ?? '' ) ) {
			$notes[] = __( 'Closed on WordPress.org: it gets no further updates there.', 'bettershield' );
		}

		$updated = strtotime( (string) ( $plugin['last_updated'] ?? '' ) );

		if ( false !== $updated && $updated < time() - Directory::stale_after_days() * DAY_IN_SECONDS ) {
			$notes[] = sprintf(
				/* translators: %s: a date. */
				__( 'No update since %s.', 'bettershield' ),
				wp_date( get_option( 'date_format' ), $updated )
			);
		}

		$version = (string) ( $plugin['version'] ?? '' );

		foreach ( State::get()['affected'] as $item ) {
			if ( 'plugin' !== ( $item['type'] ?? 'plugin' ) || $slug !== (string) ( $item['slug'] ?? '' ) ) {
				continue;
			}

			if ( '' === $version ) {
				continue;
			}

			/*
			 * Known about the version installed here; said about the version
			 * on offer only where one of the advisories still touches it, each
			 * judged by its own fix or last affected version. The item's own
			 * fix is the highest across them, which says nothing about an
			 * advisory that has none. Only an advisory known to affect it
			 * counts: one whose versions can't be compared says nothing
			 * about the version on offer (#2676).
			 */
			$touched = false;

			foreach ( Matcher::advisories( $item ) as $advisory ) {
				if ( Matcher::affects( $version, $advisory ) ) {
					$touched = true;
					break;
				}
			}

			if ( ! $touched ) {
				continue;
			}

			$notes[] = sprintf(
				/* translators: %s: a version number. */
				__( 'Known unfixed vulnerability in version %s.', 'bettershield' ),
				$version
			);

			// Said once: the sentence is the same whichever entry named the
			// plugin, and a second entry for it wrote it twice on one card.
			break;
		}

		return $notes;
	}
}
