<?php
/**
 * Hardening item: answer requests for sensitive files with 404.
 *
 * Certain files say too much when fetched directly: debug.log narrates the
 * site's errors, readme.html names the WordPress version, a wp-config.php
 * backup left by an editor serves the database password as plain text, and a
 * exposed .git directory hands over the site's entire source history.
 *
 * The rules use mod_alias's RedirectMatch with FileInfo overrides, avoiding
 * the AuthConfig overrides needed by Require. Core's permalink rules use
 * mod_rewrite, so working permalinks do not prove that mod_alias is loaded
 * or that an AllowOverrideList allows RedirectMatch. Both remain host
 * requirements. The answer is 404 regardless of whether a matching file
 * exists, so the refusal does not confirm its presence.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Files\Guarded;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SensitiveFiles {

	private const MARKER = 'sensitive-files';

	/**
	 * @param array<string, mixed> $state Unused; the server enforces the rules.
	 */
	public static function enforce( array $state ): void {}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {}

	/**
	 * Another plugin's rules already in the site's .htaccess: ours go in a
	 * separate block and touch nothing of theirs.
	 */
	public static function conflict(): ?string {
		$path = Guarded::htaccess_path();

		// Which file governs the site could not be worked out, so nothing can
		// be said about what is already in it. The refusal belongs at the
		// apply, where it is acted on, not in a warning about contents nobody
		// has read.
		if ( null === $path ) {
			return null;
		}

		$blocks = Guarded::foreign_blocks( $path );

		if ( array() === $blocks ) {
			return null;
		}

		return sprintf(
			/* translators: %s: names of the other blocks found in the file. */
			__( 'The site’s .htaccess already has rules from %s. This adds its own block and leaves theirs alone.', 'bettershield' ),
			implode( ', ', $blocks )
		);
	}

	/**
	 * @return array{available: bool, reason?: string, tone?: string, note: ?string}
	 */
	public static function availability(): array {
		// One .htaccess serves every site on a network. Two sites writing the
		// same block into it would take turns owning it, and one's undo would
		// strand the other's rules; the main site applies it for all.
		if ( is_multisite() && ! is_main_site() ) {
			return array(
				'available' => false,
				'reason'    => 'main_site',
				'note'      => __( 'On a network, every site shares one .htaccess. Apply this from the main site to protect them all.', 'bettershield' ),
			);
		}

		// The rules are RedirectMatch, which not every server that reads
		// .htaccess reads (OpenLiteSpeed reads only rewrite rules).
		$honors = Server::honors_redirect_rules();

		if ( Server::LITESPEED === Server::kind() ) {
			return false === $honors
				? array(
					'available' => false,
					'reason'    => 'server_config',
					'note'      => __( 'Your server type ignores these rules. Ask your host to add the same protection.', 'bettershield' ),
				)
				: array(
					'available' => true,
					'note'      => __( 'Your server may ignore these rules. Ask your host to check.', 'bettershield' ),
				);
		}

		if ( false === $honors ) {
			// The host may already have done what this cannot: the server
			// is asked, and its answer said rather than the request (#2048).
			if ( \BetterShield\Hardening\ServerRules::enforced( 'sensitive_files' ) ) {
				return array(
					'available' => false,
					'reason'    => 'server_enforced',
					'tone'      => 'success',
					'note'      => sprintf(
						/* translators: %s: web server name. */
						__( '%s refused a .log file placed in uploads when this site last asked it, so its rules likely cover this. Only that one file was tried. Nothing to apply here.', 'bettershield' ),
						Server::label()
					),
				);
			}

			return array(
				'available' => false,
				'reason'    => 'server_config',
				'note'      => sprintf(
					/* translators: %s: web server name. */
					__( 'This site runs on %s, which ignores .htaccess. Your host can add the rules to the server configuration.', 'bettershield' ),
					Server::label()
				),
			);
		}

		if ( null === $honors ) {
			return array(
				'available' => true,
				'note'      => sprintf(
					/* translators: %s: the plugin's name. */
					__( 'Your server may ignore the file %s writes for this, so it may not work.', 'bettershield' ),
					\BetterShield\Support\Branding::name()
				),
			);
		}

		return array(
			'available' => true,
			'note'      => null,
		);
	}

	/**
	 * @param array<string, mixed> $options Unused.
	 * @return array{tokens: string[], notes: string[]}|\WP_Error
	 */
	public static function apply( array $options ) {
		$path = Guarded::htaccess_path();

		// Writing rules into a file guessed at is writing into somebody
		// else's. Saying so is the honest answer, and it matches how this
		// module answers a server whose .htaccess does nothing.
		if ( null === $path ) {
			return new \WP_Error(
				'bettershield_no_htaccess',
				__( 'Nothing was written: it is unclear which .htaccess file serves this site. Your host can add the rules to the server configuration.', 'bettershield' )
			);
		}

		$token = Guarded::write_block( 'harden_sensitive_files', $path, self::MARKER, self::rules() );

		if ( is_wp_error( $token ) ) {
			return $token;
		}

		$notes        = array();
		$availability = self::availability();

		if ( null !== $availability['note'] ) {
			$notes[] = $availability['note'];
		}

		// What is measured is the server, not the site's permalinks — so the
		// note says the server, which is the only thing the answer knows.
		if ( ! \BetterShield\Support\Server::supports_url_rewrite() ) {
			$notes[] = __( 'The rules are written, but this server may ignore .htaccess.', 'bettershield' );
		}

		return array(
			'tokens' => array( $token ),
			'notes'  => $notes,
		);
	}

	/**
	 * @param array<string, mixed> $state
	 * @return true|\WP_Error
	 */
	public static function revert( array $state ) {
		return FileTokens::restore( $state );
	}

	/**
	 * The same rules for the server this site runs on, for the owner or the
	 * host to add by hand where the .htaccess file cannot carry them: nginx
	 * reads no .htaccess file at all. Null where there is nothing to add by
	 * hand: a server that reads the file, one this cannot write rules for,
	 * or a site of a network other than the main one, whose server block is
	 * the network's.
	 *
	 * @return array{server: string, label: string, where: string, text: string}|null
	 */
	public static function server_rule(): ?array {
		if ( Server::NGINX !== Server::kind() || ( is_multisite() && ! is_main_site() ) ) {
			return null;
		}

		return array(
			'server' => Server::NGINX,
			'label'  => __( 'Rules for your host', 'bettershield' ),
			'where'  => __( 'Your server (nginx) needs these added by your host. Send them these lines.', 'bettershield' ),
			'text'   => self::nginx_rules(),
		);
	}

	/**
	 * The patterns below as nginx locations. Each answers 404, as the
	 * .htaccess rules do: nginx's own `deny` answers 403, which tells whoever
	 * asked that the file is there.
	 */
	public static function nginx_rules(): string {
		$lines = array( '# BetterShield: hide sensitive files from visitors.' );

		foreach ( self::patterns() as $pattern ) {
			$lines[] = 'location ~* "' . $pattern . '" { return 404; }';
		}

		return implode( "\n", $lines );
	}

	/**
	 * The rules as Apache's alias module reads them, from the site's
	 * .htaccess: each pattern tested against the whole URL path, and `(?i)`
	 * making it case-insensitive.
	 */
	public static function rules(): string {
		return implode(
			"\n",
			array_map(
				static fn( string $pattern ): string => 'RedirectMatch 404 "(?i)' . $pattern . '"',
				self::patterns()
			)
		);
	}

	/**
	 * What a request must not fetch, as patterns over the whole URL path,
	 * matched without regard to case. One list, which both renderings read,
	 * so a rule a host adds by hand refuses exactly what the written one does.
	 *
	 * - wp-config.php with any suffix: the backups editors leave behind
	 *   (.bak, .old, .save, ~) are served as plain text. The rule used to
	 *   require a dot after `php`, so `wp-config.php~` — the one vim leaves
	 *   without being asked — walked straight through a list written to stop
	 *   exactly that, and so did `.wp-config.php.swp`, whose leading dot puts
	 *   it out of reach of a pattern anchored on `/wp-config`.
	 * - Editor swap files anywhere: .swp, .swo and the numbered siblings vim
	 *   makes when a file is open more than once. A swap file holds the
	 *   buffer, so one left beside wp-config.php is the credentials.
	 * - Log files anywhere, debug.log above all — and `error_log`, which has
	 *   no extension at all. It is what cPanel and stock Apache write per
	 *   directory, so it is the log most likely to exist, and it carries
	 *   absolute paths and stack traces.
	 * - Database dumps: .sql, and .sql packed in any common archive (gz, zip,
	 *   bz2, xz, 7z, tgz, tar, tar.gz, rar). One at the web root is every
	 *   account on the site, password hashes included.
	 * - readme.html and license.txt, which date the install.
	 * - wp-config-sample.php, which ships with every install and, requested
	 *   directly, bootstraps WordPress with placeholder credentials and prints
	 *   a database error naming paths.
	 * - Dotted version-control and environment paths: .git, .svn, .hg, .env.
	 * - .htaccess and .htpasswd themselves, and their backups — a copy of the
	 *   file carrying these very rules, or of the one naming a password file.
	 *
	 * wp-config.php itself is not in the list: requesting it runs it, which
	 * outputs nothing — and a rule denying it here would suggest this block
	 * is what stands between the site and its configuration, which must
	 * never become true.
	 *
	 * @return string[]
	 */
	public static function patterns(): array {
		/*
		 * Where wp-config.php can be served from: the folder WordPress is in,
		 * and the one above it, which is the site root when WordPress sits in
		 * a subfolder. RedirectMatch is tested against the whole URL path, so
		 * a pattern anchored nowhere refused every upload and post whose name
		 * began wp-config-, on the tutorial blogs most likely to turn this on.
		 */
		$folders = array();

		foreach ( array( site_url( '/' ), home_url( '/' ) ) as $address ) {
			$folder    = trailingslashit( (string) wp_parse_url( $address, PHP_URL_PATH ) );
			$folders[] = preg_quote( '/' === $folder[0] ? $folder : '/' . $folder, '#' );
		}

		// A leading dot too: an editor's swap and undo files (.wp-config.php.swp,
		// .wp-config.php.un~) and a hidden copy sit beside the live file.
		$at = '^(?:' . implode( '|', array_unique( $folders ) ) . ')\\.?';

		return array(
			/*
			 * Anything whose name begins wp-config and does not end at
			 * the live file. The rules used to require a dot or a tilde
			 * after `php`, and a known extension after `wp-config`, so
			 * the names hosts and backup tools actually write — an
			 * underscore or hyphen suffix, a trailing digit, a copy
			 * kept as an archive — walked straight through a list
			 * written to stop exactly that. None of them is a PHP file,
			 * so the server hands over the database credentials and the
			 * salts as plain text.
			 *
			 * The live file is the one name that must still be served:
			 * it ends at `.php`, and every pattern here requires
			 * something after it.
			 */
			$at . 'wp-config\\.php[^/]+',
			$at . 'wp-config[^/.]*\\.(bak|old|orig|save|txt|swp|zip|gz|tar|tar\\.gz|tgz|rar|7z|bz2|xz|back|backup|copy|tmp|temp|inc|dist|sample)$',
			// The live file is the one name that must keep being served,
			// and it is the only one this excludes.
			$at . 'wp-config[._-](?!php$)[^/]*$',
			'\\.(log|sql(\\.(gz|zip|bz2|xz|7z|tgz|tar|tar\\.gz|rar))?)$',
			// No extension to anchor on: matched as a whole name.
			'/error_log$',
			'\\.sw[a-p]$',
			'/(readme\\.html|license\\.txt|wp-config-sample\\.php)$',
			'(^|/)\\.(git|svn|hg|env)',
			'(^|/)\\.(htaccess|htpasswd)',
		);
	}
}
