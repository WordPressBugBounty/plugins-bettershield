<?php
/**
 * Which of the waiting updates fix a known vulnerability, said where updates
 * are chosen.
 *
 * WordPress lists every update the same way, so the one that closes a known
 * hole waits with the rest. Where the last vulnerability check found the
 * installed version affected, and the update on offer reaches the version
 * that fixes it, the Plugins screen says so under that plugin's own update
 * notice and the Updates screen names it above the list.
 *
 * Only on a real match: an advisory for the installed version, and an update
 * at or past its fix. Nothing is said about an update that fixes nothing, and
 * nothing here is a nudge to update in general. It reads what the check
 * already stored and asks nobody anything.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

use BetterShield\Capabilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UpdateNotes {

	public function register(): void {
		add_action( 'load-plugins.php', array( $this, 'on_plugins_screen' ) );
		add_action( 'load-update-core.php', array( $this, 'on_updates_load' ) );
	}

	/**
	 * The Updates screen, as it loads: print with its notices, at the top.
	 *
	 * Not on `core_upgrade_preamble`, which despite its name fires after the
	 * core, plugin and theme tables, below every Update button. The same file
	 * also runs each update once one is chosen, and only its opening screen
	 * lists them.
	 */
	public function on_updates_load(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- reading which step of the screen was asked for, not acting on a submission.
		$action = isset( $_GET['action'] ) && is_string( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : 'upgrade-core';

		if ( 'upgrade-core' === $action ) {
			add_action( 'all_admin_notices', array( $this, 'on_updates_screen' ) );
		}
	}

	/**
	 * Updates waiting that fix a known vulnerability in what is installed,
	 * the most serious first.
	 *
	 * Each is worded by the advisories the update itself fixes: the stored
	 * item carries the worst severity and the highest fix across all of its
	 * advisories, and an update that reaches a low advisory's fix does not
	 * close a critical one that has no fix, or a later one.
	 *
	 * @return array<int, array{type: string, slug: string, file: string, name: string, installed_version: string, new_version: string, fixed_in: string, severity: string, still_open: bool}>
	 */
	public static function security_updates(): array {
		$state = State::get();

		if ( array() === $state['affected'] ) {
			return array();
		}

		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );
		$offers  = array();

		foreach ( ( is_object( $plugins ) && isset( $plugins->response ) ? (array) $plugins->response : array() ) as $file => $offer ) {
			$offer = (object) $offer;
			$slug  = isset( $offer->slug ) ? (string) $offer->slug : dirname( (string) $file );

			$offers[ 'plugin:' . $slug ] = array(
				'file'        => (string) $file,
				'new_version' => (string) ( $offer->new_version ?? '' ),
			);
		}

		foreach ( ( is_object( $themes ) && isset( $themes->response ) ? (array) $themes->response : array() ) as $stylesheet => $offer ) {
			$offers[ 'theme:' . $stylesheet ] = array(
				'file'        => (string) $stylesheet,
				'new_version' => (string) ( ( (array) $offer )['new_version'] ?? '' ),
			);
		}

		$out = array();

		foreach ( $state['affected'] as $item ) {
			$type = (string) ( $item['type'] ?? 'plugin' );
			$key  = $type . ':' . (string) ( $item['slug'] ?? '' );

			if ( ! isset( $offers[ $key ] ) || '' === $offers[ $key ]['new_version'] ) {
				continue;
			}

			$offer = $offers[ $key ]['new_version'];

			/*
			 * What is installed now decides which advisories still apply. The
			 * check that stored this runs once a day, and an update taken since
			 * then — to a fix, with a later release still on offer — has
			 * already closed the hole it names.
			 */
			$installed = self::installed_version( $type, $offers[ $key ]['file'] );
			$fixes     = array();
			$open      = false;

			foreach ( Matcher::advisories( $item ) as $advisory ) {
				if ( ! Matcher::touches( $installed, $advisory ) ) {
					continue;
				}

				if ( isset( $advisory['affected_ranges'] ) ) {
					// Still open only when it's known to affect the update on
					// offer. One that can't be compared on either version
					// said a hole stayed open after every update (#2676).
					$after = Versions::result( $offer, $advisory );
					if ( 'affected' === $after ) { $open = true; continue; }
					if ( 'affected' !== Versions::result( $installed, $advisory ) || 'unaffected' !== $after ) { continue; }
					$advisory['fixed_in'] = $offer;
					$fixes[] = $advisory;
					continue;
				}

				// An advisory with no fix, or a fix past the update on offer,
				// is still open after it; `2.1` reaches `2.1.0`, as in the check.
				if ( null === $advisory['fixed_in'] || Matcher::below( $offer, $advisory['fixed_in'] ) ) {
					$open = true;
					continue;
				}

				$fixes[] = $advisory;
			}

			if ( array() === $fixes ) {
				continue;
			}

			$severity = 'info';
			$severity_known = false;
			$fixed    = '';

			foreach ( $fixes as $advisory ) {
				$severity_known = $severity_known || ( $advisory['severity_known'] ?? true );
				if ( array_search( $advisory['severity'], Matcher::SEVERITIES, true ) < array_search( $severity, Matcher::SEVERITIES, true ) ) {
					$severity = $advisory['severity'];
				}

				if ( '' === $fixed || Matcher::below( $fixed, $advisory['fixed_in'] ) ) {
					$fixed = $advisory['fixed_in'];
				}
			}

			$out[] = array(
				'type'              => $type,
				'slug'              => (string) $item['slug'],
				'file'              => $offers[ $key ]['file'],
				'name'              => (string) ( $item['name'] ?? $item['slug'] ),
				'installed_version' => $installed,
				'new_version'       => $offer,
				'fixed_in'          => $fixed,
				'severity'          => $severity,
				'severity_known'    => $severity_known,
				'still_open'        => $open,
			);
		}

		usort(
			$out,
			static fn( array $a, array $b ): int => (int) array_search( $a['severity'], Matcher::SEVERITIES, true ) <=> (int) array_search( $b['severity'], Matcher::SEVERITIES, true )
		);

		return $out;
	}

	/**
	 * The version of a plugin or theme installed now, or nothing where it is
	 * not installed.
	 *
	 * @param string $file The plugin's file, or the theme's stylesheet.
	 */
	private static function installed_version( string $type, string $file ): string {
		if ( 'theme' === $type ) {
			$theme = wp_get_theme( $file );

			return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();

		return isset( $plugins[ $file ]['Version'] ) ? (string) $plugins[ $file ]['Version'] : '';
	}

	/**
	 * On the Plugins screen: a line under each such plugin's update notice.
	 */
	public function on_plugins_screen(): void {
		foreach ( self::security_updates() as $update ) {
			if ( 'plugin' !== $update['type'] ) {
				continue;
			}

			add_action(
				'in_plugin_update_message-' . $update['file'],
				static function () use ( $update ): void {
					echo ' <strong>' . esc_html( self::sentence( $update ) ) . '</strong>' . self::link(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- link() escapes its own parts.
				}
			);
		}
	}

	/**
	 * On the Updates screen: which of the updates below to take first.
	 *
	 * Printed among the screen's notices and not marked inline, so core
	 * moves it under the screen's heading, above the first Update button.
	 */
	public function on_updates_screen(): void {
		$updates = self::security_updates();

		if ( array() === $updates ) {
			return;
		}

		echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Some of these updates fix a known vulnerability. Update them first:', 'bettershield' ) . '</strong></p><ul class="ul-disc">';

		foreach ( $updates as $update ) {
			echo '<li>' . esc_html(
				sprintf(
					/* translators: 1: a plugin or theme name, 2: installed version, 3: version on offer, 4: a sentence about the vulnerability. */
					__( '%1$s %2$s to %3$s: %4$s', 'bettershield' ),
					$update['name'],
					$update['installed_version'],
					$update['new_version'],
					self::sentence( $update )
				)
			) . '</li>';
		}

		echo '</ul><p>' . self::link() . '</p></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- link() escapes its own parts.
	}

	/**
	 * What one update fixes, in the severity vocabulary used everywhere else,
	 * and whether it leaves another known vulnerability open.
	 *
	 * @param array<string, mixed> $update
	 */
	public static function sentence( array $update ): string {
		switch ( false === ( $update['severity_known'] ?? true ) ? 'unknown' : $update['severity'] ) {
			case 'unknown':
				$sentence = __( 'Fixes a vulnerability of unknown severity in the installed version.', 'bettershield' );
				break;
			case 'critical':
				$sentence = __( 'Fixes a critical vulnerability in the installed version. Update first.', 'bettershield' );
				break;
			case 'high':
				$sentence = __( 'Fixes a high-severity vulnerability in the installed version. Update first.', 'bettershield' );
				break;
			case 'medium':
				$sentence = __( 'Fixes a medium-severity vulnerability in the installed version.', 'bettershield' );
				break;
			default:
				$sentence = __( 'Fixes a low-severity vulnerability in the installed version.', 'bettershield' );
		}

		if ( ! empty( $update['still_open'] ) ) {
			$sentence .= ' ' . __( 'Another known vulnerability stays open after this update.', 'bettershield' );
		}

		return $sentence;
	}

	/**
	 * The finding it answers, for whoever may read it.
	 */
	private static function link(): string {
		if ( ! current_user_can( Capabilities::READ_POSTURE ) ) {
			return '';
		}

		return ' <a href="' . esc_url( admin_url( 'admin.php?page=bettershield-findings&finding=vulnerabilities_known' ) ) . '">' . esc_html__( 'See the finding', 'bettershield' ) . '</a>';
	}
}
