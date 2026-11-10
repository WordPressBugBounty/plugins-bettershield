<?php
/**
 * Whether a plugin is still in the WordPress.org directory it came from.
 *
 * A plugin the directory has closed is a leading signal that no advisory feed
 * carries: closure usually *precedes* public disclosure, and it always means
 * the same two things — no future fixes, and a reason somebody at
 * WordPress.org decided the listing should stop. An owner running that plugin
 * has a decision to make, and today nothing anywhere tells them to make it.
 *
 * **This states the status and the date and reads nothing into either.** The
 * directory does not publish why a plugin was closed, so neither does this.
 * "Removed on this date, which usually means an unresolved problem and no
 * future fixes" is the whole claim.
 *
 * Three things shape how it asks:
 *
 * - **Only explicit closures are reported.** The integrity inventory includes
 *   commercial and custom folder plugins. A recognized "not found" answer is
 *   cached as non-closed, so those candidates do not consume every run.
 * - **A few at a time, and never on a page view.** One request per plugin
 *   would be forty requests from a site with forty plugins. This asks about a
 *   handful per run and remembers each answer for a week, so a large site
 *   works through its list over a few days and then costs almost nothing.
 * - **Silence is not an answer.** A request that fails leaves the previous
 *   answer, or no answer, and never becomes "closed" — a network that is down
 *   for an hour must not tell an owner their plugins were pulled.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Vulnerabilities;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Directory {

	/** Where each slug's last answer is kept. */
	private const OPTION = 'bettershield_directory_status';

	/** How long an answer stands before it is asked again. */
	private const FRESH_FOR = WEEK_IN_SECONDS;

	/**
	 * How many slugs one run asks about.
	 *
	 * Small deliberately. A site with sixty plugins finishes its first sweep
	 * over a week of daily runs rather than making sixty requests the first
	 * time somebody presses a button, and after that the sweep is whatever
	 * expired that day.
	 */
	private const PER_RUN = 8;

	public const OPEN   = 'open';
	public const CLOSED = 'closed';

	/**
	 * How long without a release in the directory before a listed plugin is
	 * named, by default: two years. A filter can move it; see
	 * `stale_after_days()`.
	 */
	public const DEFAULT_STALE_DAYS = 730;

	/**
	 * The shortest a filter may set it to. Under a year, ordinary release
	 * gaps would fill the findings with plugins that are being looked after.
	 */
	public const MIN_STALE_DAYS = 365;

	/**
	 * The longest it may be set to: a hundred years. A larger value, turned
	 * into seconds, overflowed to a float that the date functions refuse.
	 */
	public const MAX_STALE_DAYS = 36500;

	/**
	 * Ask about the slugs whose answer has run out, and return what is known.
	 *
	 * @param array<int, array<string, mixed>> $items The inventory.
	 * @return array<string, array{status: string, checked_at: int, closed_at: ?string, last_updated?: ?string, dated?: bool}>
	 */
	public static function refresh( array $items ): array {
		$known = self::known();
		$asked = 0;
		$now   = time();

		/*
		 * What is saved is the answers as they were stored, with only the
		 * ones asked about now replaced. Writing back `known()`'s reading of
		 * them gave every answer a last-updated key, so one stored before
		 * dates were kept was saved as dated, with no date, and counted as
		 * checked until it was asked again.
		 */
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		foreach ( self::listed_slugs( $items ) as $slug ) {
			if ( $asked >= self::PER_RUN ) {
				break;
			}

			$seen = $known[ $slug ] ?? null;

			if ( is_array( $seen ) && ( $now - (int) ( $seen['checked_at'] ?? 0 ) ) < self::FRESH_FOR ) {
				continue;
			}

			++$asked;

			$answer = self::ask( $slug );

			// A failed request leaves whatever was known before, which may be
			// nothing. It never writes a status.
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
	 * `dated` says whether the answer was asked for since the directory's
	 * last-updated date was kept. An answer stored before that has no date to
	 * read, which is not the same as a plugin without one, so it counts as not
	 * yet asked until the next time it is (a week at most).
	 *
	 * @return array<string, array{status: string, checked_at: int, closed_at: ?string, last_updated: ?string, dated: bool}>
	 */
	public static function known(): array {
		$stored = get_option( self::OPTION, array() );
		$known  = array();

		foreach ( is_array( $stored ) ? $stored : array() as $slug => $answer ) {
			if ( is_array( $answer ) && isset( $answer['status'] ) ) {
				$known[ (string) $slug ] = array(
					'status'       => self::CLOSED === $answer['status'] ? self::CLOSED : self::OPEN,
					'checked_at'   => (int) ( $answer['checked_at'] ?? 0 ),
					'closed_at'    => isset( $answer['closed_at'] ) ? (string) $answer['closed_at'] : null,
					'last_updated' => isset( $answer['last_updated'] ) ? self::date_of( $answer['last_updated'] ) : null,
					'dated'        => array_key_exists( 'last_updated', $answer ),
				);
			}
		}

		return $known;
	}

	/**
	 * How many days without a release in the directory before a listed plugin
	 * is named: two years unless a filter says otherwise, never under one, and
	 * never over a hundred.
	 */
	public static function stale_after_days(): int {
		/**
		 * How many days since a plugin's last update in the WordPress.org
		 * directory before it is named. Never less than a year.
		 *
		 * @param int $days
		 */
		return min( self::MAX_STALE_DAYS, max( self::MIN_STALE_DAYS, (int) apply_filters( 'bettershield_directory_stale_days', self::DEFAULT_STALE_DAYS ) ) );
	}

	/**
	 * The installed plugins whose last update in the directory is older than
	 * the threshold, named with that date.
	 *
	 * A closed listing is left to the closed-plugin finding: one plugin, one
	 * finding, and closure is the stronger thing to say about it.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<int, array{slug: string, name: string, last_updated: string, active: bool}>
	 */
	public static function stale( array $items ): array {
		$known  = self::known();
		$skip   = self::updated_elsewhere();
		$before = gmdate( 'Y-m-d', time() - self::stale_after_days() * DAY_IN_SECONDS );
		$stale  = array();

		foreach ( $items as $item ) {
			$slug   = (string) ( $item['slug'] ?? '' );
			$answer = $known[ $slug ] ?? null;

			// An answer stored about a plugin updated from elsewhere is about
			// somebody else's listing.
			if ( 'plugin' !== ( $item['type'] ?? '' ) || null === $answer || self::OPEN !== $answer['status'] || isset( $skip[ $slug ] ) ) {
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
	 * How far the sweep has got for the last-updated question: the listed
	 * plugins with an answer asked since the date was kept, and the rest.
	 *
	 * @param array<int, array<string, mixed>> $items The inventory.
	 * @return array{checked: int, unchecked: int}
	 */
	public static function dated_coverage( array $items ): array {
		$known    = self::known();
		$coverage = array(
			'checked'   => 0,
			'unchecked' => 0,
		);

		foreach ( self::listed_slugs( $items ) as $slug ) {
			++$coverage[ ! empty( $known[ $slug ]['dated'] ) ? 'checked' : 'unchecked' ];
		}

		return $coverage;
	}

	/**
	 * The directory's last-updated text as a date, or null.
	 *
	 * The directory writes it for people, as `2026-05-28 1:51am GMT`; a stored
	 * answer already holds `2026-05-28`. Anything that does not read as a
	 * date is kept as no date rather than guessed at.
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

	/**
	 * How far the sweep has got: the listed plugins with an answer of any
	 * kind, and the ones no run has reached yet.
	 *
	 * A few are asked about per run, so for the first days the answers cover
	 * a fraction of the site — and a finding that counts closures has to say
	 * whether it has looked at every plugin the count is about.
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

		foreach ( self::listed_slugs( $items ) as $slug ) {
			++$coverage[ isset( $known[ $slug ] ) ? 'checked' : 'unchecked' ];
		}

		return $coverage;
	}

	/**
	 * Whether every listed plugin has been answered about at least once: the
	 * condition for a count of closures to be the number rather than a floor.
	 *
	 * @param array<int, array<string, mixed>> $items The inventory.
	 */
	public static function examined_all( array $items ): bool {
		return 0 === self::coverage( $items )['unchecked'];
	}

	/**
	 * The folder plugins on this site that may be in the directory, and so
	 * are asked about.
	 *
	 * The directory is asked by folder name, and a folder name is not proof
	 * of where a plugin came from: a private plugin in a folder that shares a
	 * name with an old listing would be named with that listing's date or
	 * closure. A plugin whose `Update URI` header names somewhere other than
	 * WordPress.org says it is not that listing, and WordPress skips it when
	 * it checks for updates for the same reason, so it is skipped here too.
	 * Every other folder plugin is asked about, and one the directory never
	 * published answers "not found", which is cached and never reported.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return string[]
	 */
	private static function listed_slugs( array $items ): array {
		$published = array();

		foreach ( \BetterShield\Integrity\Targets::all() as $target ) {
			if ( \BetterShield\Integrity\Manifest::CONTEXT_PLUGIN === ( $target['context'] ?? '' ) ) {
				$published[ (string) ( $target['slug'] ?? '' ) ] = true;
			}
		}

		$published = array_diff_key( $published, self::updated_elsewhere() );

		$slugs = array();

		foreach ( $items as $item ) {
			$slug = (string) ( $item['slug'] ?? '' );

			if ( 'plugin' === ( $item['type'] ?? '' ) && '' !== $slug && isset( $published[ $slug ] ) ) {
				$slugs[] = $slug;
			}
		}

		return $slugs;
	}

	/**
	 * The folder plugins whose `Update URI` header names somewhere other than
	 * WordPress.org, by folder: the rule `wp_update_plugins()` applies.
	 *
	 * @return array<string, true>
	 */
	private static function updated_elsewhere(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$elsewhere = array();

		foreach ( get_plugins() as $file => $plugin ) {
			$update_uri = (string) ( $plugin['UpdateURI'] ?? '' );

			if ( '' === $update_uri || false === strpos( (string) $file, '/' ) ) {
				continue;
			}

			$host = wp_parse_url( sanitize_url( $update_uri ), PHP_URL_HOST );

			if ( ! in_array( $host, array( 'wordpress.org', 'w.org' ), true ) ) {
				$elsewhere[ sanitize_key( (string) strtok( (string) $file, '/' ) ) ] = true;
			}
		}

		return $elsewhere;
	}

	/**
	 * One question to the directory about one plugin.
	 *
	 * The request carries the slug and nothing else — no site address, no
	 * version, no count of anything. Null when the answer could not be had,
	 * which is never the same as "closed".
	 *
	 * @return array{status: string, checked_at: int, closed_at: ?string, last_updated: ?string}|null
	 */
	private static function ask( string $slug ): ?array {
		/*
		 * A closed listing is answered with 404, and the body of that 404 is
		 * the closure itself. So the status is asked for rather than trusted:
		 * discarding it would throw away the only answer worth having.
		 */
		$answer = Http::get_json(
			'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ),
			array(),
			array( 200, 404 )
		);

		if ( is_wp_error( $answer ) ) {
			return null;
		}

		/*
		 * The directory answers a closed listing with an error object naming
		 * the closure, and an open one with the plugin's own record. The
		 * closed object also carries the plugin's slug and name, so the
		 * closure is recognized first — testing for the open shape first would
		 * read every closure as open.
		 *
		 * Only `closed` is a closure. `Plugin not found.` arrives at the same
		 * status and means something else entirely — never listed, or long
		 * gone. Cache that recognized answer without reporting a closure.
		 * An unrecognized shape remains unknown, never evidence that a
		 * working plugin was pulled.
		 */
		$error = isset( $answer['error'] ) && is_string( $answer['error'] ) ? $answer['error'] : '';

		if ( ! empty( $answer['closed'] ) || 'closed' === $error ) {
			return array(
				'status'       => self::CLOSED,
				'checked_at'   => time(),
				// Published only for some closures; null where the directory
				// does not say, and the finding words itself accordingly.
				'closed_at'    => isset( $answer['closed_date'] ) ? (string) $answer['closed_date'] : null,
				'last_updated' => null,
			);
		}

		// A recognized unlisted response is not a closure, but is a completed
		// check. Cache it so commercial plugins cannot starve later slugs.
		if ( 'Plugin not found.' === $error || isset( $answer['slug'] ) || isset( $answer['version'] ) ) {
			return array(
				'status'       => self::OPEN,
				'checked_at'   => time(),
				'closed_at'    => null,
				// The same answer already carries it; keeping it costs no
				// request. Null where the directory gave none.
				'last_updated' => self::date_of( $answer['last_updated'] ?? null ),
			);
		}

		return null;
	}

	/**
	 * The installed plugins the directory has closed, named.
	 *
	 * @param array<int, array<string, mixed>> $items
	 * @return array<int, array{slug: string, name: string, closed_at: ?string, active: bool}>
	 */
	public static function closed( array $items ): array {
		$known  = self::known();
		$skip   = self::updated_elsewhere();
		$closed = array();

		foreach ( $items as $item ) {
			$slug = (string) ( $item['slug'] ?? '' );

			if ( 'plugin' !== ( $item['type'] ?? '' ) || ! isset( $known[ $slug ] ) || isset( $skip[ $slug ] ) ) {
				continue;
			}

			if ( self::CLOSED !== $known[ $slug ]['status'] ) {
				continue;
			}

			$closed[] = array(
				'slug'      => $slug,
				'name'      => (string) ( $item['name'] ?? $slug ),
				'closed_at' => $known[ $slug ]['closed_at'],
				'active'    => (bool) ( $item['active'] ?? false ),
			);
		}

		return $closed;
	}
}
