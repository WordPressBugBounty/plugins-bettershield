<?php
/**
 * The exact rule that keeps a folder from being served, for servers that do
 * not read a rule placed in the folder itself.
 *
 * nginx and IIS read no .htaccess at all, and OpenLiteSpeed reads only its
 * rewrite rules, so where this plugin seals a folder by a file in it, on
 * those servers the owner has to add the rule to the server's own
 * configuration. The rule is written here once, per server, so every screen
 * that hands one out (the quarantine folder's, and the file-writing
 * hardening items' after it, #1351) says the same thing.
 *
 * Only for a folder path made of the characters an uploads path is made of:
 * anything else is refused rather than escaped, since a rule that matched
 * something other than the folder it names would hide or expose the wrong
 * files.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ServerRule {

	/**
	 * A rule that answers 404 for everything in one folder, and where it
	 * goes. Null for a server this has no rule for, and for a folder path it
	 * will not write a rule around.
	 *
	 * @param string      $folder The folder from the site's root, e.g. "wp-content/uploads/bettershield-quarantine/".
	 * @param string|null $kind   One of Server's kinds; the current server's when null.
	 * @return array{server: string, where: string, rule: string}|null
	 */
	public static function deny_folder( string $folder, ?string $kind = null ): ?array {
		$folder = trim( $folder, '/' );
		$kind   = null === $kind ? Server::kind() : $kind;

		if ( '' === $folder || 1 !== preg_match( '#^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$#', $folder ) || str_contains( $folder, '..' ) ) {
			return null;
		}

		$path = '/' . $folder . '/';

		switch ( $kind ) {
			case Server::NGINX:
				return array(
					'server' => 'nginx',
					'where'  => __( 'Inside this site’s server block, then reload nginx.', 'bettershield' ),
					'rule'   => 'location ^~ ' . $path . " {\n\treturn 404;\n}",
				);

			case Server::LITESPEED:
				return array(
					'server' => 'LiteSpeed',
					'where'  => __( 'In the virtual host’s configuration as a context, then restart LiteSpeed.', 'bettershield' ),
					'rule'   => 'context ' . $path . " {\n  allowBrowse 0\n}",
				);

			case Server::IIS:
				return array(
					'server' => 'IIS',
					'where'  => __( 'In web.config at the site’s root, inside <system.webServer>.', 'bettershield' ),
					'rule'   => "<security>\n  <requestFiltering>\n    <hiddenSegments>\n      <add segment=\"" . basename( $folder ) . "\" />\n    </hiddenSegments>\n  </requestFiltering>\n</security>",
				);
		}

		return null;
	}
}
