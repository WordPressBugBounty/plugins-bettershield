<?php
/**
 * What the official files are supposed to look like.
 *
 * A manifest is a list of paths and the hash each one should have, fetched
 * from the place that published the software. There are two publishers and
 * they do not agree on the algorithm: WordPress publishes core checksums as
 * **MD5**, and the plugin directory publishes **SHA-256** (and MD5 beside it).
 * A manifest therefore names the algorithm it uses, and every comparison
 * hashes the file on disk the same way rather than assuming.
 *
 * MD5 is what wordpress.org publishes for core and is what core's own
 * verify-checksums uses. It is sound for the question actually being asked —
 * has this file changed — and this plugin never describes it as more than
 * that. No screen and no string claims a cryptographic guarantee it cannot
 * keep.
 *
 * **The absence of a manifest is a result, not an error to swallow.** A site
 * on a release candidate, a plugin installed from outside the directory, a
 * commercial plugin, a locally modified theme: none of these have anything to
 * compare against, and the honest report is "nothing published this, so
 * nothing can be verified" rather than silence that reads as approval.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Manifest {

	public const CONTEXT_CORE   = 'core';
	public const CONTEXT_PLUGIN = 'plugin';

	/**
	 * A file found at the WordPress install root that nothing published.
	 *
	 * Its own context because "core" is a claim, not a location. A file inside
	 * wp-admin or wp-includes that core did not ship is somebody putting code
	 * where WordPress runs it; a file at the root is as likely to be a deploy
	 * artifact, a forgotten debug script or a tool's output, which real sites
	 * have. Recording both as `core` and grading both critical made the two
	 * indistinguishable and taught the reader that critical means clutter.
	 */
	public const CONTEXT_EXTRA = 'extra';

	/**
	 * How long a fetched manifest is kept.
	 *
	 * A published checksum list for a released version never changes — the
	 * version is part of the address — so this could be far longer. A week
	 * bounds how long a bad or partial answer can persist while still meaning
	 * the daily check almost never asks twice for the same thing.
	 */
	private const CACHE_SECONDS = WEEK_IN_SECONDS;

	/**
	 * Why a manifest could not be had. Distinguished because they mean
	 * different things to a reader: one is a fact about the software, the
	 * other is a fact about today's network.
	 */
	public const REASON_NOT_PUBLISHED = 'not_published';
	public const REASON_UNREACHABLE   = 'unreachable';

	/** A location with more files in it than one walk enumerates. */
	public const REASON_TRUNCATED = 'truncated';

	/**
	 * A location holding folders by a dependency or version-control name that
	 * its publisher ships nothing under, named rather than walked file by file.
	 */
	public const REASON_SET_ASIDE = 'set_aside';

	/**
	 * Where a plugin manifest came from: the directory, or the publisher of
	 * one of WPDeveloper's own paid plugins, which the directory never lists.
	 */
	public const SOURCE_DIRECTORY = 'directory';
	public const SOURCE_PUBLISHER = 'publisher';

	/**
	 * WPDeveloper's own paid plugins, whose checksums WPDeveloper publishes
	 * because wordpress.org has none for them. The list and the address are
	 * fixed here rather than read from a filter or a plugin header, so no
	 * plugin can vouch for its own files by naming itself.
	 */
	public const PUBLISHER_SLUGS = array(
		'better-payment-pro',
		'betterdocs-ai-chatbot',
		'betterdocs-pro',
		'betterlinks-pro',
		'bettershield-ultra',
		'embedpress-pro',
		'essential-addons-elementor',
		'essential-blocks-pro',
		'notificationx-pro',
		'thinkrank-pro',
		'wp-scheduled-posts-pro',
		'xspeed-pro',
	);

	/** The publisher's checksums, in wordpress.org's own format. */
	private const PUBLISHER_URL = 'https://checksums.wpdeveloper.com/plugin-checksums/%s/%s.json';

	/**
	 * BetterShield Ultra's own earlier address, which holds the releases the
	 * address above does not. Asked for that one plugin only, after a 404.
	 */
	private const ULTRA_URL = 'https://bettershield.ai/plugin-checksums/%s/%s.json';

	/**
	 * The manifest for the running WordPress, or why there is not one.
	 *
	 * @return array{algo: string, files: array<string, string>, version: string}|\WP_Error
	 */
	public static function core() {
		global $wp_version;

		$version = (string) $wp_version;
		// Asked for here, and asked for again inside cache_key(). The key has
		// exactly one spelling and it lives in that method, so the second call
		// is what keeps `forget_all()` able to name what this stored.
		$locale = self::core_locale();
		$key    = self::cache_key( self::CONTEXT_CORE, '', $version );

		$cached = self::cached( $key );
		if ( null !== $cached ) {
			return $cached;
		}

		$missed = self::recently_failed( $key );
		if ( null !== $missed ) {
			return $missed;
		}

		/*
		 * Asked through this plugin's own gate rather than through core's
		 * `get_core_checksums()`, which was the obvious choice and is the
		 * wrong one here for two reasons that are both about this request in
		 * particular.
		 *
		 * It answers a TLS failure by asking the same question again over
		 * plain HTTP. For most of what core fetches that is resilience; for
		 * this it is not. The whole worth of a checksum list is that nobody
		 * between this site and the publisher chose it, and a cleartext
		 * answer is one anybody on the path can write — which would decide,
		 * silently, which of this site's files are reported as official.
		 *
		 * And its default user agent names the site's own address. Nothing
		 * about the site travels on these requests; the gate's user agent
		 * names the plugin and its version and nothing else.
		 *
		 * What is given up is core's knowledge of the endpoint and the
		 * response shape, so both are spelled out here: the version and
		 * locale are the address, and the answer nests the file list under
		 * the version when the API had to work out which version was meant.
		 *
		 * The status still has to be recovered, because a falsy answer covers
		 * two different facts. A version wordpress.org never released — a
		 * release candidate, a nightly, a locally built copy — answers 200
		 * with nothing in it, and that is a fact about the software. A
		 * timeout, a rate limit, a momentary bad gateway is a fact about
		 * today's network. The two carry different sentences and different
		 * cooldowns, and reading the first for the second announced a live,
		 * current, very much published version as one nobody publishes.
		 */
		$response = Http::get_json(
			sprintf(
				'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
				rawurlencode( $version ),
				rawurlencode( $locale )
			)
		);

		if ( is_wp_error( $response ) ) {
			// A refused or failed request carries no status of its own; zero
			// says so without pretending to be one.
			$status    = (int) ( $response->get_error_data()['status'] ?? 0 );
			$checksums = array();
		} else {
			$status    = 200;
			$checksums = $response['checksums'] ?? array();

			// Nested under the version where the API inferred it, flat where
			// it was told. We always tell it, so this is the defensive half.
			if ( is_array( $checksums ) && isset( $checksums[ $version ] ) && is_array( $checksums[ $version ] ) ) {
				$checksums = $checksums[ $version ];
			}
		}

		if ( ! is_array( $checksums ) || array() === $checksums ) {
			/*
			 * The API answers 200 with no checksums for a version it never
			 * published, which is the only shape that is a fact about the
			 * software. Everything else — a failed request, a 5xx, a rate
			 * limit, or no request observed at all — is today's network, and
			 * saying so keeps the difference the class docblock promises.
			 */
			$published = 200 === $status;

			$error = $published
				? new \WP_Error(
					'bettershield_core_not_published',
					sprintf(
						/* translators: %s: a WordPress version string. */
						__( 'WordPress.org publishes no checksums for version %s, so core files were not compared.', 'bettershield' ),
						$version
					),
					array( 'reason' => self::REASON_NOT_PUBLISHED, 'status' => 404 )
				)
				: new \WP_Error(
					'bettershield_core_unreachable',
					sprintf(
						/* translators: %s: a WordPress version string. */
						__( 'Checksums for version %s could not be fetched, so core files were not compared this time.', 'bettershield' ),
						$version
					),
					array( 'reason' => self::REASON_UNREACHABLE, 'status' => 502 )
				);

			// Remembered briefly, and for different lengths: a release
			// candidate stays unpublished, and asking again on the next chunk
			// can only get the same answer, while a network blip clears in a
			// minute. `remember_failure()` reads the reason to decide which.
			self::remember_failure( $key, $error );

			return $error;
		}

		/*
		 * wp-content belongs to the site, not to core, and the release zip's
		 * bundled sample plugins are listed here anyway. Stripped at the
		 * source so every reader — the comparison, the restore preview, the
		 * availability answer — agrees; filtering in one consumer left the
		 * others answering for files this site never had.
		 */
		$files = array();

		foreach ( $checksums as $path => $hash ) {
			/*
			 * These keys become filesystem paths: hashed, stored on the change
			 * row, and resolved by the restore writer. The sibling loop in
			 * `plugin()` states the same condition and the same reason — it is
			 * one line, and without it the invariant this class documents is
			 * not actually enforced anywhere.
			 */
			if ( ! self::is_safe_relative_path( (string) $path ) || ! is_string( $hash ) ) {
				continue;
			}

			if ( 0 !== strpos( (string) $path, 'wp-content/' ) ) {
				$files[ (string) $path ] = $hash;
			}
		}

		$manifest = array(
			'algo'    => 'md5',
			'files'   => $files,
			'version' => $version,
		);

		self::remember( $key, $manifest );

		return $manifest;
	}

	/**
	 * Every hash a manifest offers for one path, as a list.
	 *
	 * A publisher may offer more than one — the plugin feed does, where two
	 * SVN tags map to the same version — so every reader asks through here
	 * rather than assuming a single scalar. A path nothing published answers
	 * with an empty list.
	 *
	 * @param array<string, mixed> $manifest
	 * @return string[]
	 */
	public static function hashes_for( array $manifest, string $relative ): array {
		$offered = $manifest['files'][ $relative ] ?? null;

		if ( null === $offered ) {
			return array();
		}

		return array_values( array_filter( array_map( 'strval', (array) $offered ) ) );
	}

	/**
	 * Whether a hash from disk is one the publisher offers for that path.
	 *
	 * @param array<string, mixed> $manifest
	 */
	public static function matches( array $manifest, string $relative, string $actual ): bool {
		foreach ( self::hashes_for( $manifest, $relative ) as $expected ) {
			if ( hash_equals( $expected, $actual ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The manifest for one directory plugin at the exact version installed.
	 *
	 * @param array<string, mixed> $args Request arguments, for a caller with
	 *                                   less patience than a scheduled check.
	 *                                   An update somebody is waiting on is
	 *                                   the case this exists for.
	 * For one of WPDeveloper's own paid plugins the directory has nothing, so
	 * a 404 there is asked again of the publisher, and the manifest says which
	 * of the two answered. Only a 404 moves on: a connection problem says
	 * nothing about whether the next address has the list.
	 *
	 * @return array{algo: string, files: array<string, string>, version: string, source: string}|\WP_Error
	 */
	public static function plugin( string $slug, string $version, array $args = array() ) {
		$slug    = sanitize_key( $slug );
		$version = trim( $version );

		if ( '' === $slug || '' === $version ) {
			return new \WP_Error(
				'bettershield_plugin_unidentified',
				__( 'This plugin does not name its directory entry or version, so no checksums can be looked up.', 'bettershield' ),
				array( 'reason' => self::REASON_NOT_PUBLISHED, 'status' => 404 )
			);
		}

		$key    = self::cache_key( self::CONTEXT_PLUGIN, $slug, $version );
		$cached = self::cached( $key );
		if ( null !== $cached ) {
			return $cached;
		}

		$missed = self::recently_failed( $key );
		if ( null !== $missed ) {
			return $missed;
		}

		$body = Http::get_json(
			sprintf(
				'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
				rawurlencode( $slug ),
				rawurlencode( $version )
			),
			$args
		);
		$source = self::SOURCE_DIRECTORY;

		foreach ( self::publisher_urls( $slug ) as $url ) {
			if ( ! is_wp_error( $body ) || 404 !== (int) ( $body->get_error_data()['status'] ?? 0 ) ) {
				break;
			}

			$body   = Http::get_json( sprintf( $url, rawurlencode( $slug ), rawurlencode( $version ) ), $args );
			$source = self::SOURCE_PUBLISHER;
		}

		if ( is_wp_error( $body ) ) {
			// A 404 means the directory has no such plugin at that version:
			// installed from elsewhere, or commercial, or a version that never
			// shipped. Anything else is the network having a bad day, and the
			// two must not read the same on screen.
			$status = (int) ( $body->get_error_data()['status'] ?? 0 );

			$error = new \WP_Error(
				'bettershield_plugin_not_published',
				404 === $status
					? sprintf(
						self::SOURCE_PUBLISHER === $source
							/* translators: 1: a plugin's directory slug, 2: its version. */
							? __( 'Neither WordPress.org nor its publisher lists checksums for %1$s version %2$s, so its files were not compared.', 'bettershield' )
							/* translators: 1: a plugin's directory slug, 2: its version. */
							: __( 'WordPress.org publishes no checksums for %1$s version %2$s, so its files were not compared.', 'bettershield' ),
						$slug,
						$version
					)
					: __( 'The checksums could not be fetched: a connection problem, not a finding about your site.', 'bettershield' ),
				array(
					'reason' => 404 === $status ? self::REASON_NOT_PUBLISHED : self::REASON_UNREACHABLE,
					'status' => 404 === $status ? 404 : 502,
				)
			);

			self::remember_failure( $key, $error );

			return $error;
		}

		$files = array();

		foreach ( (array) ( $body['files'] ?? array() ) as $path => $hashes ) {
			/*
			 * These keys become filesystem paths: hashed, stored on the change
			 * row, and resolved by the restore writer. The source is the
			 * directory over TLS through the allow-list, and the write path
			 * has a second lock — nothing is written that does not match a
			 * published checksum — so this is the other half of that stated
			 * invariant rather than a live hole. It is one condition, and
			 * without it the invariant is not actually enforced anywhere.
			 */
			if ( ! self::is_safe_relative_path( (string) $path ) ) {
				continue;
			}

			/*
			 * SHA-256 where it is offered, which is everywhere in this feed;
			 * MD5 only if a future response omits it.
			 *
			 * The feed answers with an ARRAY of hashes where more than one
			 * SVN tag maps to the requested version — a real and legitimate
			 * shape. Cast straight to string it became the literal "Array",
			 * which no file on earth hashes to, so every install of an
			 * affected plugin was told a file had been altered. Kept as a
			 * list: the file matches if it matches any hash its publisher
			 * offers for that version.
			 */
			if ( ! is_array( $hashes ) || ! isset( $hashes['sha256'] ) ) {
				continue;
			}

			$offered = array_values(
				array_filter(
					array_map( 'strval', (array) $hashes['sha256'] ),
					static function ( string $hash ): bool {
						return 1 === preg_match( '/^[a-f0-9]{64}$/i', $hash );
					}
				)
			);

			if ( array() !== $offered ) {
				$files[ (string) $path ] = $offered;
			}
		}

		if ( array() === $files ) {
			$error = new \WP_Error(
				'bettershield_plugin_manifest_empty',
				__( 'The published checksums for this plugin could not be read.', 'bettershield' ),
				array( 'reason' => self::REASON_UNREACHABLE, 'status' => 502 )
			);

			self::remember_failure( $key, $error );

			return $error;
		}

		$manifest = array(
			'algo'    => 'sha256',
			'files'   => $files,
			'version' => $version,
			'source'  => $source,
		);

		self::remember( $key, $manifest );

		return $manifest;
	}

	/**
	 * Whether a plugin is one of WPDeveloper's own paid plugins, whose
	 * checksums its publisher lists in place of the directory.
	 */
	public static function from_publisher( string $slug ): bool {
		return in_array( sanitize_key( $slug ), self::PUBLISHER_SLUGS, true );
	}

	/**
	 * Where a plugin's publisher lists its checksums, in the order to ask.
	 * Nothing for a plugin off the fixed list.
	 *
	 * @return string[] Addresses with a slug and a version still to fill in.
	 */
	private static function publisher_urls( string $slug ): array {
		if ( ! self::from_publisher( $slug ) ) {
			return array();
		}

		return 'bettershield-ultra' === $slug ? array( self::PUBLISHER_URL, self::ULTRA_URL ) : array( self::PUBLISHER_URL );
	}

	/**
	 * Whether a manifest key is a path this plugin will act on: relative, with
	 * no traversal and no absolute root.
	 */
	public static function is_safe_relative_path( string $path ): bool {
		if ( '' === $path || str_starts_with( $path, '/' ) || str_starts_with( $path, '\\' ) ) {
			return false;
		}

		// A Windows drive letter or a UNC path is absolute too.
		if ( 1 === preg_match( '#^[a-zA-Z]:#', $path ) ) {
			return false;
		}

		foreach ( (array) preg_split( '#[/\\\\]#', $path ) as $segment ) {
			if ( '..' === $segment ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Hash a file the way its manifest was published, or null if it cannot be
	 * read. Never loads the file into a string: hash_file streams it, which is
	 * what keeps a large file from becoming a memory limit.
	 */
	public static function hash_file( string $absolute_path, string $algo ): ?string {
		if ( ! is_readable( $absolute_path ) || ! is_file( $absolute_path ) ) {
			return null;
		}

		$hash = @hash_file( 'md5' === $algo ? 'md5' : 'sha256', $absolute_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is a result, not a warning to print into someone's dashboard.

		return is_string( $hash ) && '' !== $hash ? $hash : null;
	}

	/**
	 * Forget every cached manifest. Used when a check is started by hand,
	 * where the point is usually to ask again.
	 *
	 * **Named one at a time, never flushed.** This used to end in
	 * `wp_cache_flush()`, which empties the whole object cache across every
	 * group — core's options, another plugin's state, a store's cart
	 * fragments — on any host with Redis or Memcached installed, which is
	 * most managed hosts. That is a site-wide cache stampede triggered by a
	 * button, on a plugin whose first promise is that it does not slow a site
	 * down. The keys are ours and we can name them, so we name them.
	 */
	public static function forget_all(): void {
		global $wpdb;

		foreach ( Targets::all() as $target ) {
			$key = self::cache_key(
				(string) $target['context'],
				sanitize_key( (string) $target['slug'] ),
				trim( (string) $target['version'] )
			);

			self::cache_delete( self::transient( $key ) );
			self::cache_delete( self::transient( $key ) . '_miss' );
		}

		/*
		 * What is left over from a version that has since been updated, whose
		 * key can no longer be constructed. Such an entry is unreachable
		 * rather than stale — a manifest is keyed by the version it describes
		 * — so this is tidying, not the mechanism. A site with a persistent
		 * object cache writes no row here at all and the loop above is what
		 * actually forgets; a site without one has both.
		 */
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- no API lists transients by prefix.
		$wpdb->query(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_bettershield\_manifest\_%' OR option_name LIKE '\_transient\_timeout\_bettershield\_manifest\_%'"
		);

		if ( is_multisite() ) {
			// The same tidying where a network keeps them. Without this the
			// cache-bust reads as working — the loop above names live keys
			// and clears them — while an unreachable entry from a version
			// since updated stays in sitemeta forever.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- no API lists site transients by prefix.
			$wpdb->query(
				"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\_site\_transient\_bettershield\_manifest\_%' OR meta_key LIKE '\_site\_transient\_timeout\_bettershield\_manifest\_%'"
			);
		}
	}

	/**
	 * The cache key for one manifest.
	 *
	 * One definition, because `forget_all()` has to name exactly what `core()`
	 * and `plugin()` stored. A second spelling here would forget nothing and
	 * report that it had.
	 */
	private static function cache_key( string $context, string $slug, string $version ): string {
		return self::CONTEXT_CORE === $context
			? 'core:' . $version . ':' . self::core_locale()
			: 'plugin:' . $slug . ':' . $version;
	}

	/**
	 * The locale of the core package that is installed, not the language the
	 * site is displayed in.
	 *
	 * The checksums endpoint is keyed by the package: a localized build
	 * carries its own `wp-includes/version.php` and, for some locales, its own
	 * `readme.html`. Site Language installs translation files and changes no
	 * core PHP file at all, so asking by it compares a stock en_US install
	 * against another package's checksums and reports untouched core files as
	 * modified — at critical severity, with an alert and a restore offer
	 * behind it. Core's own verifier reads `$wp_local_package` for this, and
	 * so does this.
	 */
	private static function core_locale(): string {
		global $wp_local_package;

		$package = isset( $wp_local_package ) ? (string) $wp_local_package : '';

		// The API keys en_US as the default build and takes other locales as
		// they are; an install with no package global is that default build.
		return '' !== $package ? $package : 'en_US';
	}

	/**
	 * @return array{algo: string, files: array<string, string>, version: string}|null
	 */
	private static function cached( string $key ) {
		$stored = self::cache_get( self::transient( $key ) );

		if ( ! is_array( $stored ) || ! isset( $stored['files'] ) || ! is_array( $stored['files'] ) ) {
			return null;
		}

		return array(
			'algo'    => (string) ( $stored['algo'] ?? 'sha256' ),
			/*
			 * A value may be one hash or a list of them — the plugin feed
			 * offers several where two tags carry one version. Flattening
			 * with strval() here turned a list into the literal "Array",
			 * which no file hashes to, so every affected install was told a
			 * file had been altered. Readers ask through hashes_for().
			 */
			'files'   => array_map(
				static function ( $value ) {
					return is_array( $value ) ? array_values( array_map( 'strval', $value ) ) : (string) $value;
				},
				$stored['files']
			),
			'version' => (string) ( $stored['version'] ?? '' ),
			'source'  => (string) ( $stored['source'] ?? self::SOURCE_DIRECTORY ),
		);
	}

	/**
	 * @param array{algo: string, files: array<string, string>, version: string} $manifest
	 */
	private static function remember( string $key, array $manifest ): void {
		self::cache_set( self::transient( $key ), $manifest, self::CACHE_SECONDS );
	}

	/**
	 * A failure is remembered too, briefly — the whole error, so the memo
	 * can answer with the same refusal the network did. Without it, a site
	 * on a release candidate asks wordpress.org the same unanswerable
	 * question on every chunk of every run: three writers and no reader was
	 * ~480 wasted requests a day.
	 */
	private static function remember_failure( string $key, \WP_Error $error ): void {
		$reason = (string) ( $error->get_error_data()['reason'] ?? self::REASON_UNREACHABLE );

		self::cache_set(
			self::transient( $key ) . '_miss',
			array(
				'code'    => (string) $error->get_error_code(),
				'message' => (string) $error->get_error_message(),
				'reason'  => $reason,
			),
			// An unpublished version cannot become published inside the hour;
			// a network blip can clear in a minute, and an hour-long memo of
			// one made "check files again" repeat a stale connection error
			// with no way to force a real retry.
			self::REASON_NOT_PUBLISHED === $reason ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS
		);
	}

	/**
	 * The remembered refusal, reconstructed — or null when there is none and
	 * the real question should be asked.
	 */
	public static function recently_failed( string $key ): ?\WP_Error {
		$memo = self::cache_get( self::transient( $key ) . '_miss' );

		if ( ! is_array( $memo ) || '' === (string) ( $memo['code'] ?? '' ) ) {
			return null;
		}

		return new \WP_Error(
			(string) $memo['code'],
			(string) ( $memo['message'] ?? '' ),
			array(
				'reason' => (string) ( $memo['reason'] ?? self::REASON_UNREACHABLE ),
				// Derive it from the reason so existing negative cache entries also
				// carry a truthful REST status after an upgrade.
				'status' => self::REASON_NOT_PUBLISHED === ( $memo['reason'] ?? '' ) ? 404 : 502,
			)
		);
	}

	private static function transient( string $key ): string {
		// Hashed because a transient name is bounded and a plugin slug plus a
		// version is not.
		return 'bettershield_manifest_' . md5( $key );
	}

	/**
	 * Read a cached manifest, from the network on a network.
	 *
	 * The only thing this class caches is what a publisher published: a list
	 * of files and their checksums for one version and locale, byte-identical
	 * to every site that asks. Cached per site, an operator with fifty
	 * subsites fetched the same list fifty times a week and stored fifty
	 * copies of it, over one shared filesystem.
	 *
	 * What is NOT shared, and stays per site, is everything computed from it:
	 * the baseline of what this site's files actually hash to, its findings,
	 * and its schedule. Nothing here lets one site's answer become another's
	 * — it is the upstream copy that is held once instead of many times.
	 *
	 * @return mixed
	 */
	private static function cache_get( string $name ) {
		return is_multisite() ? get_site_transient( $name ) : get_transient( $name );
	}

	/**
	 * @param mixed $value
	 */
	private static function cache_set( string $name, $value, int $ttl ): void {
		if ( is_multisite() ) {
			set_site_transient( $name, $value, $ttl );

			return;
		}

		set_transient( $name, $value, $ttl );
	}

	private static function cache_delete( string $name ): void {
		if ( is_multisite() ) {
			delete_site_transient( $name );

			return;
		}

		delete_transient( $name );
	}
}
