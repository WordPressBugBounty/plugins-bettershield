<?php
/**
 * Whether a stranger can download this site's leftovers.
 *
 * An exposed `.git` directory hands over the whole history of a site's code,
 * including whatever was committed and later removed. A `.env` or a stray
 * `database.sql` hands over the credentials directly. These are among the most
 * common real breaches, and they are almost never a plugin's fault — they are
 * a deploy that copied too much, or a backup somebody made before an edit and
 * left in the web root.
 *
 * **This asks rather than guesses.** Every other check here reads
 * configuration and reasons about it. This one requests the address and
 * reports what came back, because "your `.git/config` is downloadable, here is
 * the address" is a fact somebody can check for themselves in five seconds,
 * and "your server *might* serve dotfiles" is not.
 *
 * A request a site makes to itself never leaves the server, so this reaches no
 * third party and needs no disclosure. It goes through the same gate every
 * other request does.
 *
 * **The trap it has to avoid.** A site that answers 200 for everything — a
 * catch-all route, a staging password page, some maintenance plugins — would
 * have every artifact reported as exposed, which is a false alarm about
 * credentials on every one of those sites at once. So a path that cannot
 * exist is requested first, and if *that* comes back 200 the probe reports
 * that it could not tell rather than reporting a catastrophe.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ExposedArtifacts {

	/** Where the last answer is kept. */
	public const OPTION = 'bettershield_exposed_artifacts';

	/**
	 * The names a configuration backup is left under, and what each one is:
	 * a copy somebody made before an edit, or the file an editor writes
	 * beside the one it has open.
	 *
	 * The same names the sensitive-files hardening refuses to serve, and a
	 * test holds the two together: every name here must match one of that
	 * item's rules, so the probe cannot ask for less than the hardening
	 * blocks.
	 */
	public const CONFIG_BACKUPS = array(
		'wp-config.php.bak'  => 'copy',
		'wp-config.php.old'  => 'copy',
		'wp-config.php.orig' => 'copy',
		'wp-config.php.save' => 'editor',
		'wp-config.php~'     => 'editor',
		// The names hosts, backup plugins and people actually write, which
		// the rules that hide these now cover too.
		'wp-config.php_bak'  => 'copy',
		'wp-config.php-bak'  => 'copy',
		'wp-config.zip'      => 'copy',
		'wp-config.tar.gz'   => 'copy',
		'wp-config.bak'      => 'copy',
		'wp-config.old'      => 'copy',
		'wp-config.orig'     => 'copy',
		'wp-config.txt'      => 'copy',
	);

	/**
	 * Tools left in the web root after a migration or a debugging session,
	 * by the name they are left under, and what kind of tool each one is.
	 *
	 * Unlike the files above these are programs: a stranger does not download
	 * them, they run them. A database manager asks for a password and then
	 * hands over the database; a search-and-replace script and a migration
	 * installer rewrite it without asking for anything.
	 */
	public const TOOLS = array(
		'adminer.php'          => 'database_manager',
		'phpinfo.php'          => 'php_information',
		'info.php'             => 'php_information',
		'searchreplacedb2.php' => 'search_replace',
		'installer.php'        => 'installer',
		'installer-backup.php' => 'installer',
		'importbuddy.php'      => 'installer',
	);

	/**
	 * The kinds recognized from the file rather than by asking for it.
	 *
	 * Asked for, they run: a migration installer unpacks its archive into the
	 * web root and writes a log beside it on a plain GET, and a
	 * search-and-replace script connects to the database for whoever opens
	 * it. No request is free of that — a HEAD runs the program too — so a
	 * check that is meant to change nothing reads the opening of the file in
	 * the web root instead, and runs nothing.
	 */
	private const READ_FROM_DISK = array( 'installer', 'search_replace' );

	/** How much of a file's opening is read to recognize it. */
	private const DISK_READ_BYTES = 65536;

	/**
	 * A migration archive, which is named for the site and the moment it was
	 * made, so it is looked for on disk rather than guessed at.
	 */
	private const ARCHIVE_PATTERN = '/_archive\.(?:zip|daf)$/i';

	/** How many archives one run asks about, beside the fixed names. */
	private const MAX_ARCHIVES = 5;

	/** The largest tool quarantine keeps a copy of, read whole to keep it. */
	public const MAX_QUARANTINE_BYTES = 2097152;

	/**
	 * What is asked for, and what handing it over means.
	 *
	 * Short on purpose. This is a request per entry against the site's own web
	 * server, so the list is the handful that are both common and severe
	 * rather than everything anybody has ever left lying about.
	 *
	 * Built rather than written down, because the addresses are not fixed:
	 * several popular layouts move the content directory, and WordPress in a
	 * directory of its own puts the configuration file somewhere the home
	 * address does not reach. Eight literals hung off the home address asked a
	 * relocated site for paths it does not have, got a 404 for each, and
	 * reported it clean — which is the one thing this must never do. Each
	 * entry is a path relative to the home address, because that is what the
	 * same-site gate takes; addresses on another host are left out, since a
	 * request there would not be a self-check.
	 *
	 * @return array<string, string>
	 */
	public static function paths(): array {
		$paths = array();

		$add = static function ( ?string $base, string $file, string $means ) use ( &$paths ): void {
			if ( null === $base ) {
				return;
			}

			$path = ltrim( '' === $base ? $file : $base . '/' . $file, '/' );

			// On the ordinary layout the three bases are the same place, and
			// asking one address three times is two requests spent on an
			// answer already given — against a budget the sweep has to keep.
			if ( ! isset( $paths[ $path ] ) ) {
				$paths[ $path ] = $means;
			}
		};

		$home    = '';
		$content = self::relative_to_home( content_url() );
		$install = self::relative_to_home( site_url() );

		$config = __( 'A copy of your configuration file, served as text. It exposes database credentials and security keys.', 'bettershield' );
		$editor = __( 'An editor’s backup of your configuration file, served as text.', 'bettershield' );
		$dump   = __( 'A database dump: every account, every password hash, everything on the site.', 'bettershield' );

		$add( $home, '.git/config', __( 'Your git history, including anything committed and later removed.', 'bettershield' ) );
		$add( $home, '.env', __( 'Environment variables, usually holding database and API credentials.', 'bettershield' ) );

		/*
		 * Beside WordPress and in the directory above it: both are places
		 * WordPress itself reads wp-config.php from, so both are places a
		 * backup of it is left.
		 */
		foreach ( self::CONFIG_BACKUPS as $file => $kind ) {
			$means = 'editor' === $kind ? $editor : $config;

			$add( $install, (string) $file, $means );
			$add( $home, (string) $file, $means );
		}

		$add( $home, 'database.sql', $dump );
		$add( $home, 'backup.sql', $dump );
		$add( $install, 'database.sql', $dump );
		$add( $install, 'backup.sql', $dump );

		// Wherever the content directory actually is, which is not
		// `wp-content` on every layout.
		$add( $content, 'debug.log', __( 'The debug log, which records file paths, queries and sometimes credentials.', 'bettershield' ) );

		return $paths;
	}

	/**
	 * The leftover tools asked about, as a path below the home address with
	 * where the file would be on disk and what kind of tool it is.
	 *
	 * Asked at the two places a tool is dropped: beside WordPress and at the
	 * home address, which differ only where WordPress has a directory of its
	 * own. A migration archive has no fixed name, so the same two folders are
	 * listed for one, and only what is there is asked about.
	 *
	 * @return array<string, array{base: string, file: string, kind: string}>
	 */
	public static function tool_paths(): array {
		$bases = array(
			'install' => self::relative_to_home( site_url() ),
			'home'    => '',
		);

		$paths = array();

		foreach ( $bases as $base => $relative ) {
			if ( null === $relative ) {
				continue;
			}

			$files = self::TOOLS;

			foreach ( array_slice( self::archives_in( self::base_directory( $base ) ), 0, self::MAX_ARCHIVES ) as $archive ) {
				$files[ $archive ] = 'archive';
			}

			foreach ( $files as $file => $kind ) {
				$path = ltrim( '' === $relative ? (string) $file : $relative . '/' . $file, '/' );

				if ( ! isset( $paths[ $path ] ) ) {
					$paths[ $path ] = array(
						'base' => $base,
						'file' => (string) $file,
						'kind' => $kind,
					);
				}
			}
		}

		return $paths;
	}

	/**
	 * What a kind of tool is, in the words the finding uses.
	 */
	public static function tool_means( string $kind ): string {
		switch ( $kind ) {
			case 'database_manager':
				return __( 'A database manager. Anyone who reaches it can try the database password, and with it read or change everything.', 'bettershield' );
			case 'php_information':
				return __( 'A PHP information page. It shows an intruder the server’s software, paths and settings.', 'bettershield' );
			case 'search_replace':
				return __( 'A database search-and-replace script. Whoever opens it can rewrite the database, using the site’s own credentials.', 'bettershield' );
			case 'installer':
				return __( 'A site migration installer. Opening it can overwrite this site, or reveal the credentials it was given.', 'bettershield' );
			case 'archive':
				return __( 'A site migration archive: a full copy of the files and database, credentials included, that anyone can download.', 'bettershield' );
		}

		return '';
	}

	/**
	 * How serious a kind of tool is when a stranger can reach it.
	 */
	public static function tool_severity( string $kind ): string {
		switch ( $kind ) {
			case 'search_replace':
			case 'installer':
			case 'archive':
				return 'critical';
			case 'database_manager':
				return 'high';
		}

		return 'medium';
	}

	/**
	 * Where a base is on disk, or null where that cannot be told.
	 */
	public static function base_directory( string $base ): ?string {
		if ( 'install' === $base ) {
			return untrailingslashit( ABSPATH );
		}

		$htaccess = \BetterShield\Files\Guarded::htaccess_path();

		return null === $htaccess ? null : dirname( $htaccess );
	}

	/**
	 * How many archives in the web root no check this run asks about: those
	 * past the newest MAX_ARCHIVES in a folder. Any of them could be the one
	 * a stranger downloads, so a run that left some unasked cannot call the
	 * site clean, and a finding about the rest is not the whole list.
	 */
	public static function archives_unasked(): int {
		$unasked = 0;
		$seen    = array();

		foreach ( array( 'install', 'home' ) as $base ) {
			$directory = self::base_directory( $base );

			// On the ordinary layout both bases are one folder.
			if ( null === $directory || isset( $seen[ $directory ] ) ) {
				continue;
			}

			$seen[ $directory ] = true;
			$unasked           += max( 0, count( self::archives_in( $directory ) ) - self::MAX_ARCHIVES );
		}

		return $unasked;
	}

	/**
	 * The migration archives in one folder, by name, newest first.
	 *
	 * Only the folder itself is listed, never below it, and only names and
	 * sizes are read: nothing is opened. An empty file is not an archive and
	 * is left out: it is what a quarantine leaves under the archive's name,
	 * the newest file in the folder from then on, and counted it would take
	 * a slot from an archive that can still be downloaded.
	 *
	 * @return string[]
	 */
	private static function archives_in( ?string $directory ): array {
		if ( null === $directory || ! is_dir( $directory ) ) {
			return array();
		}

		$names = @scandir( $directory ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable folder is answered by asking about no archive in it.

		if ( ! is_array( $names ) ) {
			return array();
		}

		$found = array();

		foreach ( $names as $name ) {
			if ( 1 === preg_match( self::ARCHIVE_PATTERN, $name ) && is_file( $directory . '/' . $name ) && 0 !== (int) @filesize( $directory . '/' . $name ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a size that cannot be read is not taken for an empty file.
				$found[ $name ] = (int) @filemtime( $directory . '/' . $name ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a file whose time cannot be read sorts last.
			}
		}

		arsort( $found );

		return array_keys( $found );
	}

	/**
	 * One of this site's own addresses as a path below the home address, or
	 * null where it is not below it at all.
	 *
	 * A content directory served from a CDN, or a WordPress install on another
	 * host entirely, is somewhere this has no business requesting: the
	 * same-site gate would refuse it, and refusing it here says why.
	 */
	private static function relative_to_home( string $url ): ?string {
		$home = home_url( '/' );

		$host      = wp_parse_url( $url, PHP_URL_HOST );
		$home_host = wp_parse_url( $home, PHP_URL_HOST );

		if ( ! is_string( $host ) || ! is_string( $home_host ) || strtolower( $host ) !== strtolower( $home_host ) ) {
			return null;
		}

		$path      = trim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
		$home_path = trim( (string) wp_parse_url( $home, PHP_URL_PATH ), '/' );

		if ( '' === $home_path ) {
			return $path;
		}

		if ( $path !== $home_path && 0 !== strpos( $path, $home_path . '/' ) ) {
			return null;
		}

		return trim( substr( $path, strlen( $home_path ) ), '/' );
	}

	/**
	 * Ask the site about each one, and remember the answer.
	 *
	 * The budget bounds the sweep as a whole, which the per-request timeout
	 * cannot: a dozen addresses each given five seconds is a minute of one
	 * run, and the overdue-task fallback can start that run on an admin page
	 * load. A sweep that stops early reports that it did, because a partial
	 * sweep presented as a finished one is the comfortable answer rather than
	 * the true one — the same thing the canary above exists to prevent.
	 *
	 * @return array{checked_at: string, reliable: bool, reason?: string, exposed: array<int, array{path: string, means: string}>}
	 */
	public static function probe( float $budget_seconds = 20.0 ): array {
		$start = microtime( true );

		$answer = array(
			'checked_at' => gmdate( 'c' ),
			// Whether the answers can be believed at all — see the class
			// docblock. False means every result below is discarded.
			'reliable'   => true,
			'exposed'    => array(),
			// Leftover tools a stranger can run, kept apart from the files
			// above because they are a finding of their own, with their own
			// answer to whether they can be believed.
			'tools'          => array(),
			'tools_reliable' => true,
		);

		/*
		 * A path nothing can be serving. If this answers 200 then so will
		 * everything else, and every artifact below would be reported as
		 * downloadable on a site where none of them is.
		 */
		$canary = self::probe_path( 'bettershield-no-such-path-' . wp_generate_password( 12, false ) );

		/*
		 * The canary is believed only when it answers the way a path that
		 * does not exist answers. Anything else is an answer about the
		 * request rather than about the path, and it is the same answer every
		 * artifact below will get: a 200 means the site answers everything, a
		 * zero means this server could not reach its own address, and a
		 * uniform 301, 401, 403, 429 or 503 — a redirect to https or www,
		 * basic auth on a staging site, a firewall or CDN rule that blocks
		 * the server's own address, maintenance mode — makes every artifact
		 * skip and the run store "nothing exposed". A file that really is
		 * downloadable would have been answered the same way, so that result
		 * is not a clean site, it is a probe that could not tell — and read
		 * as clean it resolves a live critical finding.
		 */
		if ( ! in_array( $canary['code'], array( 404, 410 ), true ) ) {
			$answer['reliable'] = false;
			$answer['reason']   = 200 === $canary['code']
				? 'answers_everything'
				: ( 0 === $canary['code'] ? 'unreachable' : 'uniform_answer' );
			$answer['canary']   = (int) $canary['code'];

			// A site answering everything with a page is not one that stopped
			// the request, and that stays the check's own sentence.
			if ( SelfRequest::UNREACHABLE !== $canary['failure']['kind'] || 0 === $canary['code'] ) {
				$answer['failure'] = $canary['failure'];
			}

			update_option( self::OPTION, $answer, false );

			return $answer;
		}

		foreach ( self::paths() as $path => $means ) {
			if ( microtime( true ) - $start >= $budget_seconds ) {
				$answer['reliable'] = false;
				$answer['reason']   = 'incomplete';

				/*
				 * What was found before the clock ran out is kept. It was
				 * genuinely asked and genuinely answered, and the finding is
				 * already withheld by the flag above — throwing it away as
				 * well would lose a true answer and gain nothing.
				 */
				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			$result = self::probe_path( (string) $path );

			// One path that did not complete is enough: the rest of this run
			// would be a mix of answers and silences, reported as answers.
			if ( 0 === $result['code'] ) {
				$answer['reliable'] = false;
				$answer['reason']   = 'unreachable';
				$answer['failure']  = $result['failure'];
				$answer['exposed']  = array();

				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			if ( 200 !== $result['code'] ) {
				continue;
			}

			/*
			 * A 200 is not an exposed file. Plenty of sites answer 200 with
			 * their own not-found page, a maintenance notice or a security
			 * plugin's block page — and every one of those was being reported
			 * to the owner as a downloadable database, which is the loudest
			 * possible way to be wrong.
			 */
			if ( ! self::body_is_the_artifact( (string) $path, $result['body'] ) ) {
				continue;
			}

			$answer['exposed'][] = array(
				'path'  => $path,
				'means' => $means,
			);
		}

		/*
		 * The tools are asked after the files, in what is left of the same
		 * budget. A tool sweep that runs out of time or cannot reach a path
		 * says nothing about the files, which were asked and answered above:
		 * it makes only the tools unknown. Marking the whole run unreliable,
		 * and clearing the files, turned a complete answer about downloadable
		 * files into "could not be checked" as well.
		 */
		foreach ( self::tool_paths() as $path => $tool ) {
			if ( microtime( true ) - $start >= $budget_seconds ) {
				$answer['tools_reliable'] = false;
				$answer['tools_reason']   = 'incomplete';
				$answer['tools']          = array();

				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			if ( in_array( $tool['kind'], self::READ_FROM_DISK, true ) ) {
				if ( self::file_is_the_tool( $tool ) ) {
					$answer['tools'][] = array(
						'path' => (string) $path,
						'base' => $tool['base'],
						'file' => $tool['file'],
						'kind' => $tool['kind'],
					);
				}

				continue;
			}

			// A tool's own page is a document, and what names it can sit
			// below a block of styles, so more of the opening is read.
			$result = self::probe_path( (string) $path, Http::MAX_SAME_SITE_BODY_BYTES );

			if ( 0 === $result['code'] ) {
				$answer['tools_reliable'] = false;
				$answer['tools_reason']   = 'unreachable';
				$answer['tools_failure']  = $result['failure'];
				$answer['tools']          = array();

				update_option( self::OPTION, $answer, false );

				return $answer;
			}

			if ( 200 !== $result['code'] || ! self::body_is_the_tool( $tool['kind'], $result['body'] ) ) {
				continue;
			}

			$answer['tools'][] = array(
				'path' => (string) $path,
				'base' => $tool['base'],
				'file' => $tool['file'],
				'kind' => $tool['kind'],
			);
		}

		$answer['archives_unasked'] = self::archives_unasked();

		update_option( self::OPTION, $answer, false );

		return $answer;
	}

	/**
	 * Ask again, now, about the files the last sweep listed, and only those.
	 *
	 * For an audit a person started. The finding tells the owner removing the
	 * file is theirs to do, and after they had, Run audit read the week-old
	 * answer back and the file stayed listed, critical, until the weekly
	 * sweep. The sweep stays on its schedule — it runs every other plugin's
	 * routes and is kept off page loads — and this asks only what is already
	 * listed, one request each.
	 *
	 * A path leaves the list only when it answers as a path that is not
	 * there. A refusal, a timeout or anything else is not evidence the file
	 * has gone: a firewall that started refusing the server's own address
	 * would otherwise clear a file a stranger can still download.
	 */
	public static function recheck_exposed( float $budget_seconds = 10.0 ): void {
		$start = microtime( true );
		$last  = self::last();

		if ( null === $last || empty( $last['reliable'] ) || empty( $last['exposed'] ) ) {
			return;
		}

		$kept = array();

		foreach ( (array) $last['exposed'] as $entry ) {
			$path = is_array( $entry ) ? (string) ( $entry['path'] ?? '' ) : '';

			if ( '' === $path ) {
				continue;
			}

			// Past the budget, a path not asked about stays listed: one not
			// asked is not one gone, and the audit a person is waiting on
			// does not wait five seconds a path.
			if ( microtime( true ) - $start > $budget_seconds ) {
				$kept[] = $entry;
				continue;
			}

			$result = self::probe_path( $path );

			if ( in_array( $result['code'], array( 404, 410 ), true ) ) {
				continue;
			}

			$kept[] = $entry;
		}

		if ( count( $kept ) === count( (array) $last['exposed'] ) ) {
			return;
		}

		$last['exposed'] = $kept;

		update_option( self::OPTION, $last, false );
	}

	/**
	 * The last answer, or nothing if this has never run.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function last(): ?array {
		$stored = get_option( self::OPTION, null );

		return is_array( $stored ) && isset( $stored['checked_at'] ) ? $stored : null;
	}

	/**
	 * What this site answers for one path.
	 *
	 * Anything that is not a completed request is zero rather than a status,
	 * because a request that did not arrive says nothing about what a stranger
	 * would get — and reporting a timeout as "not exposed" would be the
	 * comfortable answer rather than the true one. The unreliable-site guard
	 * above is what turns a site of those into a stated "could not tell".
	 */
	private static function probe_path( string $path, int $read = 2048 ): array {
		$response = Http::same_site( $path );

		if ( is_wp_error( $response ) ) {
			return array( 'code' => 0, 'body' => '', 'failure' => SelfRequest::failure( $response ) );
		}

		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'failure' => SelfRequest::failure( $response ),
			// The opening of it, which is all it takes to recognize the shape.
			// The transfer itself is capped by the same-site gate, so a
			// database dump is refused partway rather than read whole and then
			// trimmed here; none of what does arrive is stored or logged.
			'body' => substr( (string) wp_remote_retrieve_body( $response ), 0, $read ),
		);
	}

	/**
	 * Whether what came back is the artifact rather than a page about it.
	 *
	 * Each of these has a shape that a rendered page does not. The test is
	 * deliberately narrow: a body this does not recognize is not reported,
	 * because telling an owner their database is downloadable when it is not
	 * costs more than staying quiet about one that is — and the file check
	 * says the rest.
	 */
	private static function body_is_the_artifact( string $path, string $body ): bool {
		$trimmed = ltrim( $body );

		if ( '' === $trimmed ) {
			return false;
		}

		// Anything that opens as a document is a page, whatever it is about.
		if ( 1 === preg_match( '/^(?:<!doctype html|<html|<\?xml)/i', $trimmed ) ) {
			return false;
		}

		if ( '.git/config' === $path ) {
			return false !== strpos( $trimmed, '[core]' );
		}

		if ( '.env' === $path ) {
			return 1 === preg_match( '/^[A-Z_][A-Z0-9_]*=/m', $trimmed );
		}

		if ( 1 === preg_match( '/\.sql$/', $path ) ) {
			return 1 === preg_match( '/CREATE TABLE|INSERT INTO|-- MySQL dump/i', $trimmed );
		}

		if ( false !== strpos( $path, 'wp-config' ) ) {
			return false !== strpos( $trimmed, 'DB_NAME' );
		}

		if ( false !== strpos( $path, 'debug.log' ) ) {
			return 1 === preg_match( '/PHP (?:Notice|Warning|Fatal error|Deprecated)|^\[\d{2}-[A-Za-z]{3}-\d{4}/m', $trimmed );
		}

		return false;
	}

	/**
	 * Whether what came back is the tool rather than a page about it.
	 *
	 * The same narrow test as the files above: each tool is recognized by
	 * what it prints, and a page this does not recognize is not reported. A
	 * site's own page that happens to be called `info.php` is somebody's
	 * page, not a leftover.
	 */
	private static function body_is_the_tool( string $kind, string $body ): bool {
		$trimmed = ltrim( $body );

		if ( '' === $trimmed ) {
			return false;
		}

		switch ( $kind ) {
			case 'database_manager':
				return 1 === preg_match( '/<title>[^<]*\bAdminer\b|adminer\.org/i', $trimmed );

			case 'php_information':
				return 1 === preg_match( '/phpinfo\(\)|\.e \{background-color: #ccf/', $trimmed );

			// An installer and a search-and-replace script are never asked
			// for; see READ_FROM_DISK.

			case 'archive':
				// A zip opens with its own signature; the other format opens
				// with its header tag. A page about the file opens as a page.
				return 0 === strpos( $body, "PK\x03\x04" ) || 0 === strpos( $trimmed, '<A>' );
		}

		return false;
	}

	/**
	 * Whether the file in the web root is the tool, judged by its opening and
	 * never by running it.
	 *
	 * The same narrow test as a page: a file this does not recognize — the
	 * site's own page under that name, or the inert file a quarantine leaves —
	 * is not reported, and neither is one that cannot be read.
	 *
	 * @param array{base: string, file: string, kind: string} $tool
	 */
	private static function file_is_the_tool( array $tool ): bool {
		$directory = self::base_directory( $tool['base'] );

		if ( null === $directory ) {
			return false;
		}

		$file = $directory . '/' . basename( $tool['file'] );

		if ( ! is_file( $file ) || ! is_readable( $file ) ) {
			return false;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- the opening of a local file, read to recognize it; nothing is stored, echoed or run.
		$opening = @file_get_contents( $file, false, null, 0, self::DISK_READ_BYTES );

		if ( ! is_string( $opening ) || '' === $opening ) {
			return false;
		}

		switch ( $tool['kind'] ) {
			case 'installer':
				return 1 === preg_match( '/Duplicator|dup-installer|DUPX|InstallerBootstrapData|ImportBuddy|BackupBuddy|pluginbuddy/i', $opening );

			case 'search_replace':
				return 1 === preg_match( '/interconnect\/?it|Search[ _-]?(?:and|&|&amp;)?[ _-]?Replace|searchreplacedb/i', $opening );
		}

		return false;
	}

	/**
	 * Move one leftover tool into quarantine, leaving an inert file where it
	 * was.
	 *
	 * Only a tool the last check found reachable can be moved, and only by the
	 * name it was found under: the request names a path, and the path is
	 * matched against what was found rather than trusted. The bytes are kept
	 * in quarantine and the undo puts them back exactly, from the quarantine
	 * list on the Files screen.
	 *
	 * @return array{path: string, undo: string}|\WP_Error
	 */
	public static function quarantine_tool( string $path ) {
		$last  = self::last();
		$found = null;

		foreach ( (array) ( $last['tools'] ?? array() ) as $tool ) {
			if ( is_array( $tool ) && $path === ( $tool['path'] ?? null ) ) {
				$found = $tool;
				break;
			}
		}

		if ( null === $found ) {
			return new \WP_Error(
				'bettershield_tool_unknown',
				__( 'The last check did not find that file, so nothing was moved. Run the check again.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		$file      = basename( (string) ( $found['file'] ?? '' ) );
		$directory = self::base_directory( (string) ( $found['base'] ?? '' ) );
		$known     = isset( self::TOOLS[ $file ] ) || 1 === preg_match( self::ARCHIVE_PATTERN, $file );

		if ( null === $directory || '' === $file || ! $known ) {
			return new \WP_Error(
				'bettershield_tool_unknown',
				__( 'The file’s location could not be confirmed, so nothing was moved.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$absolute = $directory . '/' . $file;

		if ( ! is_file( $absolute ) ) {
			self::forget_tool( $path );

			return new \WP_Error(
				'bettershield_file_missing',
				__( 'That file is no longer there, so there is nothing to move.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$size = (int) @filesize( $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable size is refused below.

		if ( $size <= 0 || $size > self::MAX_QUARANTINE_BYTES ) {
			return new \WP_Error(
				'bettershield_tool_too_large',
				__( 'That file is too large to quarantine. Move it out of the web root with your host’s file manager.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$sha256 = (string) @hash_file( 'sha256', $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is refused by the writer below.

		// A PHP file keeps a PHP file's name and runs nothing; anything else
		// is left empty.
		$inert = 'php' === strtolower( pathinfo( $file, PATHINFO_EXTENSION ) )
			? "<?php\n// Contents preserved in BetterShield quarantine.\n"
			: '';

		$undo = \BetterShield\Files\Guarded::replace_verified( 'leftover_tool_quarantine', $absolute, $inert, __( 'Leftover tool', 'bettershield' ), '' !== $sha256 ? $sha256 : null );

		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		\BetterShield\Events\Writer::instance()->record(
			'leftover_tool_quarantined',
			\BetterShield\Events\Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => \BetterShield\Files\Quarantine::site_relative( $absolute ),
				'context'     => array(
					'undo' => $undo,
					'kind' => (string) ( $found['kind'] ?? '' ),
				),
			)
		);

		self::forget_tool( $path );

		return array(
			'path' => $path,
			'undo' => $undo,
		);
	}

	/**
	 * The downloadable files quarantine may move: configuration backups,
	 * database dumps and the debug log. Never `.git` or `.env`: a deploy, or
	 * the application that reads them, breaks when they move.
	 */
	public const QUARANTINABLE = array( 'database.sql', 'backup.sql', 'debug.log' );

	/**
	 * Where a downloadable file found by the last check is on disk, or null
	 * where it is not one quarantine may move or the place cannot be told.
	 *
	 * Matched against the three places the check asks (beside WordPress, at
	 * the home address and in the content directory), by the same addresses
	 * it asked, never by a path the request supplies.
	 */
	public static function artifact_file( string $path ): ?string {
		$file = basename( $path );

		if ( ! isset( self::CONFIG_BACKUPS[ $file ] ) && ! in_array( $file, self::QUARANTINABLE, true ) ) {
			return null;
		}

		$places = array(
			array( self::relative_to_home( site_url() ), untrailingslashit( ABSPATH ) ),
			array( '', self::base_directory( 'home' ) ),
			array( self::relative_to_home( content_url() ), untrailingslashit( WP_CONTENT_DIR ) ),
		);

		foreach ( $places as $place ) {
			list( $relative, $directory ) = $place;

			if ( null === $relative || null === $directory ) {
				continue;
			}

			if ( ltrim( '' === $relative ? $file : $relative . '/' . $file, '/' ) === $path && is_file( $directory . '/' . $file ) ) {
				return $directory . '/' . $file;
			}
		}

		return null;
	}

	/**
	 * Move one downloadable file the last check found into quarantine,
	 * leaving an empty file where it was. The bytes are kept, and the
	 * Files screen's quarantine list puts them back.
	 *
	 * @return array{path: string, undo: string}|\WP_Error
	 */
	public static function quarantine_artifact( string $path ) {
		$last  = self::last();
		$found = false;

		foreach ( (array) ( $last['exposed'] ?? array() ) as $entry ) {
			if ( is_array( $entry ) && $path === ( $entry['path'] ?? null ) ) {
				$found = true;
				break;
			}
		}

		$absolute = $found ? self::artifact_file( $path ) : null;

		if ( null === $absolute ) {
			return new \WP_Error(
				'bettershield_artifact_unknown',
				__( 'The last check did not find that file where quarantine can move it, so nothing was moved.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		$size = (int) @filesize( $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable size is refused below.

		if ( $size <= 0 || $size > self::MAX_QUARANTINE_BYTES ) {
			return new \WP_Error(
				'bettershield_artifact_too_large',
				__( 'That file is too large to quarantine. Move it out of the web root with your host’s file manager.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		$sha256 = (string) @hash_file( 'sha256', $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is refused by the writer below.
		$undo   = \BetterShield\Files\Guarded::replace_verified( 'exposed_file_quarantine', $absolute, '', __( 'Downloadable file', 'bettershield' ), '' !== $sha256 ? $sha256 : null );

		if ( is_wp_error( $undo ) ) {
			return $undo;
		}

		\BetterShield\Events\Writer::instance()->record(
			'exposed_file_quarantined',
			\BetterShield\Events\Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'file',
				'object_id'   => \BetterShield\Files\Quarantine::site_relative( $absolute ),
				'context'     => array( 'undo' => $undo ),
			)
		);

		$last['exposed'] = array_values(
			array_filter(
				(array) $last['exposed'],
				static fn( $entry ): bool => ! is_array( $entry ) || $path !== ( $entry['path'] ?? null )
			)
		);

		update_option( self::OPTION, $last, false );

		return array(
			'path' => $path,
			'undo' => $undo,
		);
	}

	/**
	 * Whether a downloadable file is larger than quarantine keeps a copy of.
	 */
	public static function artifact_too_large( string $path ): bool {
		$absolute = self::artifact_file( $path );

		return null !== $absolute && (int) @filesize( $absolute ) > self::MAX_QUARANTINE_BYTES; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable size is left to the move to refuse.
	}

	/**
	 * Whether a found tool is larger than quarantine keeps a copy of, so the
	 * finding can say so rather than offer a move that is always refused.
	 *
	 * @param array<string, mixed> $tool One entry of the last answer's tools.
	 */
	public static function too_large_to_quarantine( array $tool ): bool {
		$file      = basename( (string) ( $tool['file'] ?? '' ) );
		$directory = self::base_directory( (string) ( $tool['base'] ?? '' ) );

		if ( null === $directory || '' === $file || ! is_file( $directory . '/' . $file ) ) {
			return false;
		}

		return (int) @filesize( $directory . '/' . $file ) > self::MAX_QUARANTINE_BYTES; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable size is left to the move to refuse.
	}

	/**
	 * Take one tool off the last answer, so the finding closes on the next
	 * read instead of waiting a week for the next check.
	 */
	private static function forget_tool( string $path ): void {
		$last = self::last();

		if ( null === $last || ! isset( $last['tools'] ) ) {
			return;
		}

		$last['tools'] = array_values(
			array_filter(
				(array) $last['tools'],
				static fn( $tool ): bool => ! is_array( $tool ) || $path !== ( $tool['path'] ?? null )
			)
		);

		update_option( self::OPTION, $last, false );
	}
}
