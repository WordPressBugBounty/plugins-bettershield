<?php
/**
 * The three places nobody publishes a checksum for.
 *
 * The integrity check compares files against what their publisher says they
 * should be, and for core and directory plugins that works. For three
 * locations it cannot work at all, because there is nothing to compare
 * against:
 *
 * - **Drop-ins.** `object-cache.php`, `advanced-cache.php`, `db.php` and the
 *   rest load before almost everything else and are answerable to nobody.
 * - **Must-use plugins.** Loaded first, cannot be deactivated from the
 *   dashboard, and do not appear in the plugins list the way an ordinary one
 *   does.
 * - **The active theme.** Verified 19 August 2026: wordpress.org publishes
 *   per-file checksums for plugins and for core and **none at all** for
 *   themes — the endpoint answers 404 for every theme and version, and the
 *   theme information API carries no checksum field. A baseline is the only
 *   way a theme can be watched.
 *
 * These are exactly where persistence hides, so the baseline watches them
 * wherever this plugin runs.
 *
 * The mechanism is a **baseline**: record what is there the first time, and
 * report what changes afterwards. It answers a different question from the
 * manifest comparison — "is this what it was" rather than "is this what its
 * publisher shipped" — and the screen says so rather than implying an
 * authority that does not exist.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Integrity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Unpublished {

	public const CONTEXT_DROPIN   = 'dropin';
	public const CONTEXT_MUPLUGIN = 'muplugin';
	public const CONTEXT_THEME    = 'theme';

	/**
	 * The configuration files at the root of the site that nobody publishes
	 * and everybody targets.
	 */
	public const CONTEXT_CONFIG = 'config';

	/**
	 * The configuration file every install has, and so the one whose baseline
	 * says this check has recorded configuration on this site before.
	 */
	public const SLUG_WP_CONFIG = 'wp-config.php';

	/**
	 * A plugin the directory does not publish — commercial, custom, or a
	 * copy of a paid one from somewhere it should not have come from.
	 */
	public const CONTEXT_UNLISTED = 'unlisted';

	/** Every context compared against a baseline rather than a manifest. */
	public const CONTEXTS = array( self::CONTEXT_DROPIN, self::CONTEXT_MUPLUGIN, self::CONTEXT_THEME, self::CONTEXT_CONFIG, self::CONTEXT_UNLISTED );

	/**
	 * How many files one location is walked for.
	 *
	 * A theme is a few hundred files; a build left in one is tens of
	 * thousands. The cap is what keeps a badly packaged theme from turning
	 * every scan into a scan of that theme and nothing else, and the report
	 * says when it was hit rather than quietly stopping.
	 */
	public const MAX_FILES = 3000;

	/**
	 * Folders a baseline walk does not enter: the names in
	 * `Targets::SKIP_ANYWHERE` that hold nothing a request runs — a build's
	 * dependency trees, and version-control and editor metadata.
	 *
	 * `vendor` is not among them. A theme or a plugin loads its own from there
	 * on every request, and `vendor/autoload.php` is the first file it
	 * includes, so a change there is a change to the code that runs.
	 */
	public const SKIP_BASELINE = array( 'node_modules', '.git', '.svn', '.hg', 'bower_components', '.idea', '.vscode' );

	/**
	 * Which locations have had their first look at the `vendor` folders a
	 * baseline walk used to leave out, keyed `context|slug`.
	 *
	 * A baseline taken before those folders were walked holds nothing for
	 * them, and reading every file in one as an arrival would be reporting the
	 * act of looking. So the first walk to meet them records them in silence,
	 * once per location, as a location's own first look is taken; from then
	 * on a file arriving there is reported like any other.
	 */
	public const DEPENDENCIES_OPTION = 'bettershield_integrity_dependencies_seen';

	/**
	 * Which locations have had their first look at the file names a baseline
	 * walk used to leave out, keyed `context|slug`.
	 *
	 * The walk kept five extensions and now keeps every name that can run
	 * (`Packages::can_run()`): `.phar`, the numbered and short PHP spellings,
	 * `.user.ini`. A baseline taken before holds none of them, and a theme
	 * that ships one would otherwise raise a critical arrival the first time
	 * it is walked. The same once-per-location silence as `vendor` above.
	 */
	public const NAMES_OPTION = 'bettershield_integrity_names_seen';

	/** The extensions the walk kept before it read `Packages::can_run()`. */
	private const WALKED_BEFORE = array( 'php', 'js', 'phtml', 'inc', 'htaccess' );

	/**
	 * Every unpublished location on this site, as scan targets.
	 *
	 * The shape matches a manifest target so the scanner can walk both with
	 * one loop, but `version` means something different here: it is half of
	 * what distinguishes an *update* from a *change*. A theme whose version
	 * moved because WordPress installed a new one has been updated, and
	 * re-baselining quietly is the correct response — reporting three hundred
	 * altered files because somebody pressed Update is how a security tool
	 * teaches people to ignore it. The other half is the upgrader's own record
	 * of the update in the activity log, which the baseline asks for; a
	 * version that moved without one is a line somebody edited.
	 *
	 * Drop-ins and must-use plugins carry no version, and that is not an
	 * oversight in this code: they genuinely have none, so every change to
	 * them is reported. Those are the files nobody should be editing quietly.
	 *
	 * @return array<int, array{context: string, slug: string, version: string, root: string, prefix: string, files: string[]}>
	 */
	public static function all(): array {
		return array_merge( self::dropins(), self::mu_plugins(), self::themes(), self::config_files(), self::unlisted_plugins(), self::single_file_plugins() );
	}

	/**
	 * The configuration a web server reads before it reads any of the code.
	 *
	 * The highest-value tamper targets on a WordPress site and the ones with
	 * no publisher to ask about: a redirect or a backdoor injected into any of
	 * them survives a plugin being removed, a theme being switched, and most
	 * cleanups. Nothing in this plugin looked at them until now — the option
	 * listener watches settings and the manifest comparison watches published
	 * code, and these fell between the two.
	 *
	 * `wp-config.php` and `.htaccess` are the two everyone names. `.user.ini`
	 * is the third and the one most easily missed: PHP reads it per directory
	 * under CGI and FPM, an `auto_prepend_file` line in one runs arbitrary
	 * code on every request, and it keeps working on the servers where
	 * `.htaccess` is inert. This plugin already rates it as configuration the
	 * server executes when it decides how serious a change is, so its contents
	 * are held against what they were, exactly as `.htaccess` is.
	 *
	 * Every directory a `.user.ini` can govern from is listed, because what
	 * one of them says is no answer about another. Under CGI and FPM the scan
	 * runs from the executing script's directory upward to the document root,
	 * so the copy above the install governs every request a subdirectory
	 * install serves — the case the two inside the install miss entirely. That
	 * directory is derived from the two address options, exactly as the
	 * `.htaccess` path is and for the reason given there: the document root
	 * the web server supplies is absent or means something else wherever this
	 * check actually runs, which is cron and the command line as often as a
	 * loopback request. The two under `wp-content` are a narrower claim and
	 * worth saying plainly — they govern PHP reached directly inside those
	 * directories rather than every request the site serves.
	 *
	 * A candidate is listed whether or not the file is there. A watched file
	 * that disappears is a finding too — an `.htaccess` deleted takes every
	 * rule this plugin wrote with it — and a candidate skipped for being
	 * absent is one the comparison never runs for, so the removal was silent
	 * and the recorded row outlived the file forever. Absent and never
	 * recorded is no finding either way: there is nothing to compare against,
	 * which is what the comparison already answers. One that arrives later is
	 * a different fact, and `reports_first_sight()` says which of these are
	 * reported the run they are first met on rather than recorded in silence.
	 *
	 * No version, deliberately, and for the same reason drop-ins have none:
	 * these files have no release to move with, so every change to them is a
	 * change somebody made. That includes changes this plugin makes itself
	 * through `Files\Guarded` — which is correct. A marked block appearing in
	 * `.htaccess` is a real edit to a real file, and an owner reading the
	 * report should see it there next to its own undo rather than learn that
	 * this tool exempts itself from the watch it sells.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function config_files(): array {
		$found = array();

		/*
		 * The ones whose arrival is reported rather than recorded in silence
		 * are listed first, and the order carries weight: the report is gated
		 * on this site's configuration having been recorded before, so a run
		 * that reached another config file first would take its baseline and
		 * then read an ordinary install's `.user.ini` as an arrival. See
		 * `reports_first_sight()`.
		 */
		$candidates = self::user_ini_candidates();

		// Named at the place it would be even when it is not there, so a file
		// that goes is still compared against what it was.
		$candidates[ self::SLUG_WP_CONFIG ] = \BetterShield\Files\Guarded::wp_config_path() ?? ABSPATH . self::SLUG_WP_CONFIG;
		$candidates['.htaccess']            = \BetterShield\Files\Guarded::htaccess_path();

		foreach ( $candidates as $name => $absolute ) {
			if ( null === $absolute || '' === $absolute ) {
				continue;
			}

			$name      = (string) $name;
			$directory = dirname( $name );

			/*
			 * Walked from the file's own directory rather than from ABSPATH:
			 * `wp-config.php` is allowed to sit one level above the install,
			 * and a prefix built from ABSPATH would name a path that is not
			 * where the file is. The prefix carries whatever directory the
			 * name has, because two files with the same name in two
			 * directories need recorded paths that tell them apart.
			 */
			$found[] = array(
				'context' => self::CONTEXT_CONFIG,
				'slug'    => $name,
				'version' => '',
				'root'    => dirname( $absolute ),
				'prefix'  => '.' === $directory ? '' : $directory . '/',
				'files'   => array( basename( $absolute ) ),
			);
		}

		return $found;
	}

	/**
	 * Every directory a `.user.ini` could govern this install from, keyed by
	 * the slug the file in it is watched under.
	 *
	 * Keyed rather than listed so the two spellings of one directory — a
	 * single-site install whose home path is the install root — collapse to
	 * one candidate instead of being watched twice under two names.
	 *
	 * @return array<string, string>
	 */
	private static function user_ini_candidates(): array {
		$directories = array( ABSPATH, ABSPATH . 'wp-admin/', WP_CONTENT_DIR, WP_PLUGIN_DIR );

		/*
		 * The site's home directory, derived exactly as the `.htaccess` this
		 * plugin writes to is derived, and from nothing else. On a
		 * subdirectory install this is the install root's parent and is where
		 * a `.user.ini` governing every request the site serves would sit.
		 */
		$htaccess = \BetterShield\Files\Guarded::htaccess_path();

		if ( null !== $htaccess ) {
			$directories[] = dirname( $htaccess );
		}

		$candidates = array();

		foreach ( $directories as $directory ) {
			$relative = self::relative_to_root( (string) $directory );

			// A directory this cannot name relative to the install — a
			// wp-content moved somewhere else entirely — would need a slug
			// nothing could read back, so it is left unwatched rather than
			// watched under a name that means nothing.
			if ( null === $relative ) {
				continue;
			}

			$candidates[ $relative . '.user.ini' ] = trailingslashit( (string) $directory ) . '.user.ini';
		}

		return $candidates;
	}

	/**
	 * One directory as a path relative to the install root, or null where it
	 * is neither inside it nor above it.
	 *
	 * The answer is a slug: it is what the baseline rows are filed under and
	 * what the report prints, so it has to read as a place — `wp-admin/`, or
	 * `../` for the directory a subdirectory install sits in.
	 */
	private static function relative_to_root( string $directory ): ?string {
		$root = trailingslashit( str_replace( '\\', '/', ABSPATH ) );
		$path = trailingslashit( str_replace( '\\', '/', $directory ) );

		if ( $path === $root ) {
			return '';
		}

		if ( str_starts_with( $path, $root ) ) {
			return substr( $path, strlen( $root ) );
		}

		if ( str_starts_with( $root, $path ) ) {
			return str_repeat( '../', substr_count( substr( $root, strlen( $path ) ), '/' ) );
		}

		return null;
	}

	/**
	 * Whether a location this check has never recorded is reported rather than
	 * baselined in silence.
	 *
	 * The first look is never a finding: a baseline that reported everything
	 * the moment it was taken would be reporting the act of taking it.
	 * `.user.ini` is the one exception, and it is one because nothing in
	 * WordPress ever writes such a file — core, the dashboard and every
	 * upgrade path leave it alone. A copy that was not there when
	 * configuration was last recorded is therefore somebody's act, and PHP
	 * reads it on every request under CGI and FPM, which is where the
	 * mechanism this watches lives. Must-use plugins and drop-ins are the same
	 * kind of act: WordPress loads each on every request without anyone
	 * activating it, so a folder that was empty when configuration was
	 * recorded and now holds a file is somebody's doing, and it is reported
	 * (#2341). `.htaccess` keeps the quiet first sight:
	 * saving permalinks writes it, and reporting that would teach the reader
	 * to skip the one that matters.
	 *
	 * This answers about the file alone. Whether the check has recorded
	 * configuration on this site before is the caller's half, because on the
	 * run that takes the very first baseline there is nothing an arrival could
	 * stand against.
	 */
	public static function reports_first_sight( string $context, string $slug ): bool {
		// Read off the name rather than from a second list of the same slugs:
		// the candidates are built per directory, and a list repeated here
		// went stale the moment one was added.
		if ( self::CONTEXT_MUPLUGIN === $context || self::CONTEXT_DROPIN === $context ) {
			return true;
		}

		return self::CONTEXT_CONFIG === $context && str_ends_with( $slug, '.user.ini' );
	}

	/**
	 * Every installed plugin the directory has no answer for.
	 *
	 * These are the files the manifest comparison goes silent on — a
	 * commercial plugin has no published checksums, so it was reported as
	 * unverifiable and then not looked at again. That is the honest answer to
	 * "does this match what its publisher shipped", and it is the wrong place
	 * to stop: a weaker question can still be asked, and it is the same one
	 * already asked of drop-ins and the theme. Has this changed since the last
	 * time anybody looked?
	 *
	 * Read from what the last scan actually found rather than guessed at, and
	 * only where the reason was that nothing publishes it. A plugin that could
	 * not be checked because the network was down is not an unlisted plugin,
	 * and baselining it on that basis would silently downgrade a published
	 * plugin to the weaker claim for good.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function unlisted_plugins(): array {
		$result = Scanner::last_result();

		if ( ! is_array( $result ) || ! isset( $result['unverifiable'] ) ) {
			return array();
		}

		$installed = Targets::installed_plugins();
		$found     = array();

		foreach ( (array) $result['unverifiable'] as $item ) {
			if ( ! is_array( $item ) || Manifest::CONTEXT_PLUGIN !== ( $item['context'] ?? '' ) ) {
				continue;
			}

			if ( Manifest::REASON_NOT_PUBLISHED !== ( $item['reason'] ?? '' ) ) {
				continue;
			}

			$slug = (string) ( $item['slug'] ?? '' );
			$root = WP_PLUGIN_DIR . '/' . $slug;

			if ( '' === $slug || ! is_dir( $root ) ) {
				continue;
			}

			$truncated = false;
			$files     = self::files_under( $root, $truncated );

			$found[] = array(
				'context'    => self::CONTEXT_UNLISTED,
				'slug'       => $slug,
				// The plugin's own version, so an update WordPress installed
				// re-baselines quietly rather than reporting every file in it
				// as altered.
				'version'    => self::installed_version( $slug, $installed, (string) ( $item['version'] ?? '' ) ),
				'root'       => $root,
				'prefix'     => 'wp-content/plugins/' . $slug . '/',
				'files'      => $files,
				// A location the walk could not finish is reported as one, so
				// a partial answer is never read as a clean one.
				'truncated'  => $truncated,
				'first_look' => ! self::dependencies_seen( self::CONTEXT_UNLISTED, $slug ),
				'new_names'  => ! self::names_seen( self::CONTEXT_UNLISTED, $slug ),
			);
		}

		return $found;
	}

	/**
	 * The version a plugin's header carries now, rather than the one the last
	 * full scan happened to see.
	 *
	 * The list this reads from is refreshed by the scan, and a full scan runs
	 * once a day. Between an update and the next one, the version recorded
	 * there is still the version from before the update — so the location's
	 * version has not moved, the update is never recognized as one, and every
	 * file the update rewrote reads as a line somebody edited. A theme was
	 * never affected, because its version is read from the theme. This reads
	 * the plugin's header for the same reason, through the list WordPress
	 * already keeps of what is installed.
	 *
	 * The recorded version is kept only for a plugin whose header cannot be
	 * read at all — a folder with no plugin file in it any more, where a day
	 * old answer is better than none.
	 *
	 * @param array<string, array{version: string, name: string, file: string}> $installed
	 */
	private static function installed_version( string $slug, array $installed, string $recorded ): string {
		$version = (string) ( $installed[ $slug ]['version'] ?? '' );

		return '' !== $version ? $version : $recorded;
	}

	/**
	 * The version a theme's or an unlisted plugin's header says right now,
	 * read from the file: a deploy leaves WordPress's cached list as it was.
	 * Empty for any other location, or where the header can't be read.
	 *
	 * @param array<string, mixed> $target
	 */
	public static function version_on_disk( array $target ): string {
		$slug = (string) ( $target['slug'] ?? '' );
		$file = '';

		if ( self::CONTEXT_THEME === ( $target['context'] ?? '' ) ) {
			$file = (string) $target['root'] . '/style.css';
		} elseif ( self::CONTEXT_UNLISTED === ( $target['context'] ?? '' ) ) {
			$file = WP_PLUGIN_DIR . '/' . ( self::is_single_file( $slug ) ? $slug : (string) ( Targets::installed_plugins()[ $slug ]['file'] ?? '' ) );
		}

		if ( '' === $file || ! is_file( $file ) ) {
			return '';
		}

		return trim( (string) ( get_file_data( $file, array( 'version' => 'Version' ) )['version'] ?? '' ) );
	}

	/**
	 * Plugins that are one file at the top of the plugins directory.
	 *
	 * The directory publishes checksums per folder, so these have nothing to
	 * be compared against, and the copy of Hello Dolly that WordPress bundles
	 * is not the one core's checksums describe: core leaves it alone when it
	 * updates, and the published hash moves between releases. They are held
	 * to a baseline instead, like a plugin the directory does not list, and
	 * filed under the file's own name.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function single_file_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$found = array();

		foreach ( get_plugins() as $file => $data ) {
			$file = (string) $file;

			if ( ! self::is_single_file( $file ) || ! Manifest::is_safe_relative_path( $file ) ) {
				continue;
			}

			$found[] = array(
				'context' => self::CONTEXT_UNLISTED,
				'slug'    => $file,
				'name'    => wp_strip_all_tags( (string) ( $data['Name'] ?? $file ) ),
				// The header's version, with the upgrader's record of
				// installing it, is what tells an update from a change.
				'version' => (string) ( $data['Version'] ?? '' ),
				'root'    => untrailingslashit( WP_PLUGIN_DIR ),
				'prefix'  => 'wp-content/plugins/',
				'files'   => array( $file ),
			);
		}

		return $found;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	private static function dropins(): array {
		if ( ! function_exists( 'get_dropins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$found = array();

		foreach ( array_keys( (array) get_dropins() ) as $file ) {
			$absolute = WP_CONTENT_DIR . '/' . $file;

			if ( ! is_file( $absolute ) ) {
				continue;
			}

			$found[] = array(
				'context' => self::CONTEXT_DROPIN,
				'slug'    => (string) $file,
				// No version exists for these, and inventing one would make
				// every edit look like an update.
				'version' => '',
				'root'    => WP_CONTENT_DIR,
				'prefix'  => 'wp-content/',
				'files'   => array( (string) $file ),
			);
		}

		return $found;
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	private static function mu_plugins(): array {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) || ! is_dir( WPMU_PLUGIN_DIR ) ) {
			return array();
		}

		$truncated = false;
		$files     = self::files_under( WPMU_PLUGIN_DIR, $truncated );

		if ( array() === $files ) {
			return array();
		}

		return array(
			array(
				'context'    => self::CONTEXT_MUPLUGIN,
				'slug'       => 'mu-plugins',
				'version'    => '',
				'root'       => untrailingslashit( WPMU_PLUGIN_DIR ),
				'prefix'     => 'wp-content/mu-plugins/',
				'files'      => $files,
				'truncated'  => $truncated,
				'first_look' => ! self::dependencies_seen( self::CONTEXT_MUPLUGIN, 'mu-plugins' ),
				'new_names'  => ! self::names_seen( self::CONTEXT_MUPLUGIN, 'mu-plugins' ),
			),
		);
	}

	/**
	 * The active theme, and its parent where there is one.
	 *
	 * A child theme is usually where a site's own code lives, so it is the
	 * more interesting of the two, and both are walked.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function themes(): array {
		$out  = array();
		$seen = array();

		foreach ( array( wp_get_theme(), wp_get_theme()->parent() ) as $theme ) {
			if ( ! $theme instanceof \WP_Theme || ! $theme->exists() ) {
				continue;
			}

			$slug = (string) $theme->get_stylesheet();

			if ( isset( $seen[ $slug ] ) ) {
				continue;
			}

			$seen[ $slug ] = true;
			$root          = untrailingslashit( (string) $theme->get_stylesheet_directory() );
			$truncated     = false;
			$files         = self::files_under( $root, $truncated );

			if ( array() === $files ) {
				continue;
			}

			$out[] = array(
				'context'    => self::CONTEXT_THEME,
				'slug'       => $slug,
				// The version, with the upgrader's record of installing it,
				// is what tells an update from a change.
				'version'    => (string) $theme->get( 'Version' ),
				'root'       => $root,
				'prefix'     => 'wp-content/themes/' . $slug . '/',
				'files'      => $files,
				'truncated'  => $truncated,
				'first_look' => ! self::dependencies_seen( self::CONTEXT_THEME, $slug ),
				'new_names'  => ! self::names_seen( self::CONTEXT_THEME, $slug ),
			);
		}

		return $out;
	}

	/**
	 * Every file worth hashing under a directory, relative to it.
	 *
	 * Only the files that can execute, be included or configure the server
	 * (`Packages::can_run()`, the list the grading reads). A theme's images
	 * and fonts are the bulk of its bytes and none of its risk, and hashing
	 * them would spend the whole budget on files that cannot do anything.
	 *
	 * The cap counts files kept rather than files seen, and is applied to the
	 * sorted set: a location full of images was being cut off before its code
	 * was reached, and which files a capped walk kept changed from one
	 * enumeration to the next.
	 *
	 * Bounded by where the location really is as well as by the cap — see
	 * `Targets::may_descend()`, which is what keeps a directory that points
	 * back at one above it from turning this into a walk with no end.
	 *
	 * @param bool|null $truncated Set to whether the cap was reached.
	 * @return string[]
	 */
	public static function files_under( string $root, ?bool &$truncated = null ): array {
		$truncated = false;

		if ( ! is_dir( $root ) ) {
			return array();
		}

		$real_root = Targets::walk_root( $root );

		if ( null === $real_root ) {
			// It was a directory a moment ago. An answer this walk cannot
			// stand behind is an incomplete one rather than an empty one.
			$truncated = true;

			return array();
		}

		$limit       = self::max_files();
		$visited     = array( $real_root => true );
		$found       = array();

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
					static function ( \SplFileInfo $file, string $key, \RecursiveDirectoryIterator $inner ) use ( $real_root, &$visited ): bool {
						if ( ! $inner->isDir() ) {
							return true;
						}

						// A dependency tree a build left behind is not walked, and
						// a `vendor` folder is: see SKIP_BASELINE.
						if ( in_array( $file->getFilename(), self::SKIP_BASELINE, true ) ) {
							return false;
						}

						return Targets::may_descend( $file, $real_root, $visited );
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}

				if ( ! Packages::can_run( (string) $file->getFilename() ) ) {
					continue;
				}

				$relative = ltrim( str_replace( $root, '', (string) $file->getPathname() ), '/\\' );

				if ( '' !== $relative && Manifest::is_safe_relative_path( $relative ) ) {
					$found[] = $relative;
				}

				// Compacted at twice the cap, which bounds what this holds
				// while the walk is still running.
				if ( count( $found ) > $limit * 2 ) {
					$found     = self::capped( $found, $limit );
					$truncated = true;
				}
			}
		} catch ( \Throwable $e ) {
			// An unreadable directory is a result, not a fatal: whatever was
			// found before it is still worth comparing.
			$truncated = true;

			return self::capped( $found, $limit );
		}

		$truncated = $truncated || count( $found ) > $limit;

		return self::capped( $found, $limit );
	}

	/**
	 * How many files one unpublished location is walked for.
	 */
	public static function max_files(): int {
		/**
		 * Filters how many files one unpublished location is walked for.
		 *
		 * Reaching the cap is reported rather than hidden, so raising it is a
		 * trade between memory and how much of a large location is examined.
		 *
		 * @param int $files Paths one walk may return.
		 */
		return max( 1, (int) apply_filters( 'bettershield_integrity_max_files', self::MAX_FILES ) );
	}

	/**
	 * Sort, then keep the first `$limit`.
	 *
	 * @param string[] $found
	 * @return string[]
	 */
	private static function capped( array $found, int $limit ): array {
		sort( $found );

		return count( $found ) > $limit ? array_slice( $found, 0, $limit ) : $found;
	}

	/**
	 * Whether a plugin slug names a plugin that is one file. A folder's slug
	 * is a sanitized key and never ends in `.php`.
	 */
	public static function is_single_file( string $slug ): bool {
		return str_ends_with( $slug, '.php' ) && false === strpos( $slug, '/' );
	}

	/**
	 * Whether a path lies inside a `vendor` folder: the one name a baseline
	 * walk used to leave out and now enters.
	 */
	public static function in_dependency_folder( string $relative ): bool {
		return 1 === preg_match( '~(?:\A|/)vendor/~', $relative );
	}

	/**
	 * Whether a location has had its first look at its `vendor` folders. See
	 * DEPENDENCIES_OPTION.
	 */
	public static function dependencies_seen( string $context, string $slug ): bool {
		return self::seen( self::DEPENDENCIES_OPTION, $context, $slug );
	}

	/** Record that a location has had that first look. */
	public static function mark_dependencies_seen( string $context, string $slug ): void {
		self::mark_seen( self::DEPENDENCIES_OPTION, $context, $slug );
	}

	/**
	 * Whether a file has a name the walk did not keep before it read
	 * `Packages::can_run()`. See NAMES_OPTION.
	 */
	public static function newly_walked( string $relative ): bool {
		return ! in_array( strtolower( (string) pathinfo( $relative, PATHINFO_EXTENSION ) ), self::WALKED_BEFORE, true );
	}

	/**
	 * Whether a location has had its first look at the names the walk used
	 * to leave out. See NAMES_OPTION.
	 */
	public static function names_seen( string $context, string $slug ): bool {
		return self::seen( self::NAMES_OPTION, $context, $slug );
	}

	/** Record that a location has had that first look. */
	public static function mark_names_seen( string $context, string $slug ): void {
		self::mark_seen( self::NAMES_OPTION, $context, $slug );
	}

	/** Whether a location is in one of the first-look options above. */
	private static function seen( string $option, string $context, string $slug ): bool {
		$seen = get_option( $option, array() );

		return is_array( $seen ) && isset( $seen[ $context . '|' . $slug ] );
	}

	/** Put a location in one of the first-look options above. */
	private static function mark_seen( string $option, string $context, string $slug ): void {
		$seen = get_option( $option, array() );
		$seen = is_array( $seen ) ? $seen : array();

		if ( isset( $seen[ $context . '|' . $slug ] ) ) {
			return;
		}

		$seen[ $context . '|' . $slug ] = true;

		update_option( $option, $seen, false );
	}

	/**
	 * Whether a context is one of these rather than a published one.
	 */
	public static function is_unpublished( string $context ): bool {
		return in_array( $context, self::CONTEXTS, true );
	}
}
