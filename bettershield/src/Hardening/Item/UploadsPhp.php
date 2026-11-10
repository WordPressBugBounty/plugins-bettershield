<?php
/**
 * Hardening item: stop PHP running from the uploads directory.
 *
 * The uploads directory exists to hold files visitors gave the site. A PHP
 * file that ends up there — through a vulnerable upload form, a compromised
 * plugin, anything — runs with the site's full privileges the moment its URL
 * is requested. Denying execution there closes the most common way an
 * uploaded file becomes a shell.
 *
 * The mechanism is an .htaccess in the uploads directory, which is why this
 * item is honest about servers: nginx and IIS never read that file, so on
 * those servers the item offers information instead of a toggle that would
 * claim protection it cannot give. The file lives in uploads rather than the
 * web root on purpose — if a hostile server configuration rejects it, what
 * breaks is the uploads tree, never the admin or the recovery path.
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

final class UploadsPhp {

	public const MARKER = 'uploads-php-execution';

	/**
	 * Runtime-wise there is nothing to do: the server enforces the rules.
	 *
	 * @param array<string, mixed> $state Unused.
	 */
	public static function enforce( array $state ): void {}

	/**
	 * @param array<string, mixed> $state Unused.
	 */
	public static function unenforce( array $state ): void {}

	/**
	 * Another plugin's rules already in the uploads .htaccess: ours go in a
	 * separate block and touch nothing of theirs, but the owner should know
	 * two sets of rules will apply.
	 */
	public static function conflict(): ?string {
		$blocks = Guarded::foreign_blocks( trailingslashit( (string) wp_get_upload_dir()['basedir'] ) . '.htaccess' );

		if ( array() === $blocks ) {
			return null;
		}

		return sprintf(
			/* translators: %s: names of the other blocks found in the file. */
			__( 'The uploads .htaccess already has rules from %s. This adds its own block and leaves theirs alone.', 'bettershield' ),
			implode( ', ', $blocks )
		);
	}

	/**
	 * @return array{available: bool, reason?: string, tone?: string, note: ?string}
	 */
	public static function availability(): array {
		// The rules are RedirectMatch, which not every server that reads
		// .htaccess reads (OpenLiteSpeed reads only rewrite rules).
		$honors = Server::honors_redirect_rules();

		if ( Server::LITESPEED === Server::kind() ) {
			return false === $honors
				? array(
					'available' => false,
					'reason'    => 'server_config',
					'note'      => __( 'Your server type ignores this rule. Ask your host to add the same protection.', 'bettershield' ),
				)
				: array(
					'available' => true,
					'note'      => __( 'Your server may ignore these rules. Ask your host to check.', 'bettershield' ),
				);
		}

		if ( false === $honors ) {
			// The host may already have done what this cannot: the server
			// is asked, and its answer said rather than the request (#2048).
			if ( \BetterShield\Hardening\ServerRules::enforced( 'uploads_php' ) ) {
				return array(
					'available' => false,
					'reason'    => 'server_enforced',
					'tone'      => 'success',
					'note'      => sprintf(
						/* translators: %s: web server name. */
						__( '%s refused a PHP file placed in uploads when this site last asked it, so its rules likely cover this. Only that one file was tried. Nothing to apply here.', 'bettershield' ),
						Server::label()
					),
				);
			}

			return array(
				'available' => false,
				'reason'    => 'server_config',
				'note'      => sprintf(
					/* translators: %s: web server name. */
					__( 'This site runs on %s, which ignores .htaccess. Your host can add the rule to the server configuration.', 'bettershield' ),
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
		$uploads = wp_get_upload_dir();
		$path    = trailingslashit( (string) $uploads['basedir'] ) . '.htaccess';

		$token = Guarded::write_block( 'harden_uploads_php', $path, self::MARKER, self::rules() );

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
			$notes[] = __( 'The rule is written, but this server may ignore .htaccess.', 'bettershield' );
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
	 * The extensions the rule refuses and how a request for one ends, matched
	 * without regard to case. One pattern, which both renderings read.
	 *
	 * `pht` and `phtm` belong here with `phtml`: several server
	 * configurations map them to the PHP handler, and a block-list that omits
	 * one spelling of the same thing is the gap somebody uploads through.
	 *
	 * The trailing group has to accept `/` as well as a dot or the end of the
	 * path. `shell.php/anything` still reaches the handler as `shell.php` with
	 * the rest passed along as path info, and the rule is tested against the
	 * whole undivided URL path, so a group anchored at end-of-path lets
	 * exactly that request through.
	 */
	public const PATTERN = '\\.(php|phar|pht|phtm|phtml|phps|php[0-9])(\\.|/|$)';

	/**
	 * Answer any PHP-shaped request in uploads with 404, covering every
	 * variant extension and the trailing-dot trick.
	 *
	 * RedirectMatch is supplied by mod_alias and uses FileInfo overrides.
	 * Core's permalink rules use mod_rewrite; working permalinks alone do not
	 * prove that mod_alias is loaded or that an AllowOverrideList permits this
	 * directive. The host must support both. This choice avoids requiring the
	 * AuthConfig overrides used by Require. A matching request receives 404
	 * before reaching the PHP handler.
	 */
	public static function rules(): string {
		return 'RedirectMatch 404 "(?i)' . self::PATTERN . '"';
	}

	/**
	 * The same rule as an nginx location, or null where the uploads folder
	 * has no address of its own to keep it to.
	 *
	 * An .htaccess file reaches only the folder it sits in, so the rule
	 * written there names no folder. A server block reaches the whole site,
	 * so this one names the uploads folder: without it, it would answer 404
	 * for every PHP file on the site, the sign-in page and the dashboard
	 * included.
	 */
	public static function nginx_rules(): ?string {
		$path = trim( (string) wp_parse_url( (string) wp_get_upload_dir()['baseurl'], PHP_URL_PATH ), '/' );

		if ( '' === $path ) {
			return null;
		}

		return implode(
			"\n",
			array(
				'# BetterShield: stop PHP running in uploads.',
				'location ~* "^/' . preg_quote( $path, '#' ) . '/.*' . self::PATTERN . '" { return 404; }',
			)
		);
	}

	/**
	 * The same rule for the server this site runs on, for the owner or the
	 * host to add by hand: nginx reads no .htaccess file. Null elsewhere.
	 *
	 * @return array{server: string, label: string, where: string, text: string}|null
	 */
	public static function server_rule(): ?array {
		$text = Server::NGINX === Server::kind() ? self::nginx_rules() : null;

		if ( null === $text ) {
			return null;
		}

		return array(
			'server' => Server::NGINX,
			'label'  => __( 'Rule for your host', 'bettershield' ),
			'where'  => __( 'Your server (nginx) needs this added by your host. Send them this line.', 'bettershield' ),
			'text'   => $text,
		);
	}
}
