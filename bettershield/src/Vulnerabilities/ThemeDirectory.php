<?php
/**
 * Whether an installed theme is still in the WordPress.org theme directory,
 * and when the directory last updated it.
 *
 * Themes have no published checksums, so what the directory says about a
 * theme is the only signal there is for one: a theme it no longer lists gets
 * no more updates, and one it has not updated in years may have nobody
 * fixing it. An inactive theme left installed carries the same files.
 *
 * Three things shape how it asks, after the plugin lookup beside it:
 *
 * - **Only a theme this site saw listed can be called removed.** The theme
 *   directory answers a removed theme and one it never had the same way, so
 *   a theme is named as removed only when an earlier answer listed it, with
 *   the version installed here among its releases, and the directory no
 *   longer does. One that was never seen listed is never named.
 * - **A name is not proof of where a theme came from.** A private theme in a
 *   folder that shares a name with a directory theme would be named with that
 *   theme's dates. So the installed version has to be one the directory
 *   published, a theme whose `Update URI` names somewhere else is skipped as
 *   WordPress skips it, and a child theme is judged through its parent.
 * - **A few at a time, never on a page view, and silence is not an answer.**
 *   A handful per daily run, each remembered for a week. A request that fails
 *   leaves what was known before.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ThemeDirectory {

	/** Where each theme's last answer is kept. */
	public const OPTION = 'bettershield_theme_directory_status';

	/** How long an answer stands before it is asked again. */
	private const FRESH_FOR = WEEK_IN_SECONDS;

	/** How many themes one run asks about. A site rarely has many. */
	private const PER_RUN = 4;

	/** Listed, with the installed version among the directory's releases. */
	public const LISTED = 'listed';

	/**
	 * Listed, but the installed version is not one of its releases: another
	 * theme that shares the name. Never named.
	 */
	public const OTHER = 'other';

	/** Not in the directory, and not seen in it by this site either. */
	public const NOT_LISTED = 'not_listed';

	/** Seen listed here before, and no longer in the directory. */
	public const REMOVED = 'removed';

	/**
	 * Ask about the themes whose answer has run out, and return what is known.
	 *
	 * @param array<int, array<string, mixed>> $items The inventory.
	 * @return array<string, array{status: string, checked_at: int, last_updated: ?string, gone_since: ?string}>
	 */
	public static function refresh( array $items ): array {
		$known  = self::known();
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$asked  = 0;
		$now    = time();

		// The theme the site runs on, and its parent, first: on a site with
		// many themes left installed, theirs is the answer that matters.
		$themes = self::themes( $items );
		$order  = self::asked_about( $items );

		uksort(
			$order,
			static fn( $a, $b ): int => (int) empty( $themes[ $a ]['active'] ) <=> (int) empty( $themes[ $b ]['active'] )
		);

		foreach ( $order as $slug => $version ) {
			if ( $asked >= self::PER_RUN ) {
				break;
			}

			$seen = $known[ $slug ] ?? null;

			if ( is_array( $seen ) && ( $now - $seen['checked_at'] ) < self::FRESH_FOR ) {
				continue;
			}

			++$asked;

			$answer = self::ask( $slug, $version, $seen );

			// A failed request leaves whatever was known before.
			if ( null !== $answer ) {
				$stored[ $slug ] = $answer;
			}
		}

		if ( $asked > 0 ) {
			update_option( self::OPTION, $stored, false );

			return self::known();
		}

		return $known;
	}

	/**
	 * Everything answered so far.
	 *
	 * @return array<string, array{status: string, checked_at: int, last_updated: ?string, gone_since: ?string}>
	 */
	public static function known(): array {
		$stored = get_option( self::OPTION, array() );
		$known  = array();
		$states = array( self::LISTED, self::OTHER, self::NOT_LISTED, self::REMOVED );

		foreach ( is_array( $stored ) ? $stored : array() as $slug => $answer ) {
			if ( ! is_array( $answer ) || ! in_array( $answer['status'] ?? '', $states, true ) ) {
				continue;
			}

			$known[ (string) $slug ] = array(
				'status'       => (string) $answer['status'],
				'checked_at'   => (int) ( $answer['checked_at'] ?? 0 ),
				'last_updated' => isset( $answer['last_updated'] ) ? (string) $answer['last_updated'] : null,
				'gone_since'   => isset( $answer['gone_since'] ) ? (string) $answer['gone_since'] : null,
			);
		}

		return $known;
	}

	/**
	 * The installed themes the directory listed when this site asked before,
	 * and no longer does.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<int, array{slug: string, name: string, gone_since: ?string, active: bool}>
	 */
	public static function removed( array $items ): array {
		$known   = self::known();
		$asked   = self::asked_about( $items );
		$removed = array();

		foreach ( self::themes( $items ) as $slug => $item ) {
			if ( ! isset( $asked[ $slug ] ) || self::REMOVED !== ( $known[ $slug ]['status'] ?? '' ) ) {
				continue;
			}

			$removed[] = array(
				'slug'       => $slug,
				'name'       => (string) ( $item['name'] ?? $slug ),
				'gone_since' => $known[ $slug ]['gone_since'],
				'active'     => (bool) ( $item['active'] ?? false ),
			);
		}

		return $removed;
	}

	/**
	 * The installed themes whose last update in the directory is older than
	 * the plugins' threshold, named with that date. A removed theme is left to
	 * the removed-theme finding.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<int, array{slug: string, name: string, last_updated: string, active: bool}>
	 */
	public static function stale( array $items ): array {
		$known  = self::known();
		$asked  = self::asked_about( $items );
		$before = gmdate( 'Y-m-d', time() - Directory::stale_after_days() * DAY_IN_SECONDS );
		$stale  = array();

		foreach ( self::themes( $items ) as $slug => $item ) {
			$answer = $known[ $slug ] ?? null;

			if ( ! isset( $asked[ $slug ] ) || null === $answer || self::LISTED !== $answer['status'] ) {
				continue;
			}

			// Y-m-d strings compare in date order.
			if ( null === $answer['last_updated'] || $answer['last_updated'] >= $before ) {
				continue;
			}

			$stale[] = array(
				'slug'         => $slug,
				'name'         => (string) ( $item['name'] ?? $slug ),
				'last_updated' => $answer['last_updated'],
				'active'       => (bool) ( $item['active'] ?? false ),
			);
		}

		return $stale;
	}

	/**
	 * How far the sweep has got: the themes asked about with an answer, and
	 * the ones no run has reached yet. Until every one has an answer, a count
	 * of findings is a floor.
	 *
	 * @param array<int, array<string, mixed>> $items The inventory.
	 * @return array{checked: int, unchecked: int}
	 */
	public static function coverage( array $items ): array {
		$known    = self::known();
		$coverage = array(
			'checked'   => 0,
			'unchecked' => 0,
		);

		foreach ( array_keys( self::asked_about( $items ) ) as $slug ) {
			++$coverage[ isset( $known[ $slug ] ) ? 'checked' : 'unchecked' ];
		}

		return $coverage;
	}

	/**
	 * The installed themes by folder.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<string, array<string, mixed>>
	 */
	private static function themes( array $items ): array {
		$themes = array();

		foreach ( $items as $item ) {
			$slug = (string) ( $item['slug'] ?? '' );

			if ( 'theme' === ( $item['type'] ?? '' ) && '' !== $slug ) {
				$themes[ $slug ] = $item;
			}
		}

		return $themes;
	}

	/**
	 * The themes asked about, with the version installed: every installed
	 * theme but a child theme, which is judged through its parent, and one
	 * whose `Update URI` names somewhere other than WordPress.org, which
	 * WordPress does not look up there either.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<string, string> Version by folder.
	 */
	private static function asked_about( array $items ): array {
		$asked = array();

		foreach ( self::themes( $items ) as $slug => $item ) {
			$theme = wp_get_theme( $slug );

			if ( ! $theme->exists() || $theme->get_stylesheet() !== $theme->get_template() ) {
				continue;
			}

			$update_uri = (string) $theme->get( 'UpdateURI' );

			if ( '' !== $update_uri ) {
				$host = wp_parse_url( sanitize_url( $update_uri ), PHP_URL_HOST );

				if ( ! in_array( $host, array( 'wordpress.org', 'w.org' ), true ) ) {
					continue;
				}
			}

			$asked[ $slug ] = (string) ( $item['version'] ?? '' );
		}

		return $asked;
	}

	/**
	 * One question to the directory about one theme.
	 *
	 * The request carries the slug and nothing else: no site address and no
	 * version. The installed version is compared here, against the releases
	 * the answer lists. Null when no answer could be had.
	 *
	 * @param array{status: string, checked_at: int, last_updated: ?string, gone_since: ?string}|null $before The last answer.
	 * @return array{status: string, checked_at: int, last_updated: ?string, gone_since: ?string}|null
	 */
	private static function ask( string $slug, string $version, ?array $before ): ?array {
		$answer = Http::get_json(
			'https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][versions]=1&request[fields][sections]=0',
			array(),
			array( 200, 404 )
		);

		if ( is_wp_error( $answer ) ) {
			return null;
		}

		if ( isset( $answer['slug'] ) && $slug === (string) $answer['slug'] ) {
			$releases  = isset( $answer['versions'] ) && is_array( $answer['versions'] ) ? array_map( 'strval', array_keys( $answer['versions'] ) ) : array();
			$published = '' !== $version && ( in_array( $version, $releases, true ) || $version === (string) ( $answer['version'] ?? '' ) );

			return array(
				'status'       => $published ? self::LISTED : self::OTHER,
				'checked_at'   => time(),
				'last_updated' => self::date_of( $answer['last_updated'] ?? null ),
				'gone_since'   => null,
			);
		}

		if ( 'Theme not found' === ( $answer['error'] ?? null ) ) {
			$was = is_array( $before ) ? $before['status'] : '';

			if ( self::LISTED === $was || self::REMOVED === $was ) {
				return array(
					'status'       => self::REMOVED,
					'checked_at'   => time(),
					'last_updated' => $before['last_updated'],
					// The first answer that did not list it: the directory
					// does not say when, so this says when it was noticed.
					'gone_since'   => $before['gone_since'] ?? gmdate( 'Y-m-d' ),
				);
			}

			return array(
				'status'       => self::NOT_LISTED,
				'checked_at'   => time(),
				'last_updated' => null,
				'gone_since'   => null,
			);
		}

		return null;
	}

	/**
	 * The directory's last-updated text as a date, or null.
	 *
	 * @param mixed $value
	 */
	private static function date_of( $value ): ?string {
		if ( ! is_string( $value ) || '' === trim( $value ) ) {
			return null;
		}

		$at = strtotime( $value );

		return false === $at ? null : gmdate( 'Y-m-d', $at );
	}
}
