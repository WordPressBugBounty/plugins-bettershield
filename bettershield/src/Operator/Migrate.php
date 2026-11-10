<?php
/**
 * Settings another security plugin left on this site, read as a partial
 * settings document this plugin can plan and apply.
 *
 * Only read. Nothing here writes to, configures or deactivates the other
 * plugin, and its settings are read whether it is active or not. What it
 * turns into is an ordinary settings document, handed to the same plan and
 * apply an exported file goes through, so every change is previewed first,
 * passes the same checks, and keeps its own undo.
 *
 * Mapped by value only: a protection it switched on becomes the item here
 * that does the same job, and its sign-in attempt numbers become these. A
 * setting whose shape is not the one expected, or that has no one-to-one
 * item here, is left out and listed with the reason, never guessed at.
 *
 * The plugins are named by their file, never in words: what the screen calls
 * each one is read from its own header, as the coexistence step does.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Migrate {

	/**
	 * Each source this reads: the plugin files that name it, the free edition
	 * first. A paid edition keeps its settings where the free one does, so
	 * either of them installed or active is the source installed or active.
	 * Every file here is one the coexistence step knows too.
	 */
	private const SOURCES = array(
		'solid'     => array( 'better-wp-security/better-wp-security.php', 'ithemes-security-pro/ithemes-security-pro.php' ),
		'aios'      => array( 'all-in-one-wp-security-and-firewall/wp-security.php' ),
		'rsssl'     => array( 'really-simple-ssl/rlrsssl-really-simple-ssl.php', 'really-simple-ssl-pro/really-simple-ssl-pro.php' ),
		'wf'        => array( 'wordfence/wordfence.php' ),
		// The two most installed sign-in limiters the setup recognizes (#1964).
		'llar'      => array( 'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php' ),
		'loginizer' => array( 'loginizer/loginizer.php' ),
		// Two more that limit sign-ins, each with nothing to bring before.
		'sgs'       => array( 'sg-security/sg-security.php' ),
		'lockdown'  => array( 'login-lockdown/loginlockdown.php' ),
		// A moved sign-in address, and the dashboard hidden with it.
		'wps'       => array( 'wps-hide-login/wps-hide-login.php' ),
	);

	/**
	 * The settings that source keeps one option each, under its own prefix:
	 * its attempt limit as a number, 0 for off; its sign-in address type;
	 * and switches, 1 for on, 0 or missing for off.
	 */
	private const SGS_SETTINGS = array(
		'login_attempts',
		'login_type',
		'disable_xml_rpc',
		'disable_file_edit',
		'wp_remove_version',
		'rest_user_enumeration',
		'lock_system_folders',
		'xss_protection',
		'delete_readme',
		'disable_feed',
		'disable_usernames',
		'sg2fa',
	);

	/**
	 * What that source uses for any setting it has not saved, which it keeps
	 * as one array: it limits sign-ins from the moment it loads, before its
	 * settings are ever saved.
	 */
	private const LOCKDOWN_DEFAULTS = array(
		'max_login_retries' => 3,
		'retries_within'    => 5,
		'lockout_length'    => 60,
		'mask_login_errors' => 0,
		'captcha'           => 'disabled',
		'global_block'      => 0,
		'whitelist'         => array(),
	);

	/** Items the readers may name; anything else is not produced. */
	private const ITEMS = array( 'xmlrpc', 'file_editor', 'user_enumeration', 'uploads_php', 'directory_browsing', 'version_disclosure', 'breached_passwords', 'admin_gate' );

	/**
	 * The settings read from the one source that keeps them in a table of its
	 * own rather than in options: only these rows, and only as stored.
	 */
	private const WF_SETTINGS = array(
		'loginSecurityEnabled',
		'loginSec_maxFailures',
		'loginSec_countFailMins',
		'loginSec_lockoutMins',
		'loginSec_lockInvalidUsers',
		'loginSec_userBlacklist',
		'loginSec_breachPasswds_enabled',
		'loginSec_disableAuthorScan',
		'other_hideWPVersion',
		'disableCodeExecutionUploads',
		'whitelisted',
		'firewallEnabled',
		'maxGlobalRequests',
		'cbl_countries',
	);

	/**
	 * Every source whose settings are on this site, with the document its
	 * settings become and what was left out.
	 *
	 * @return array<int, array{key: string, name: string, active: bool, document: array<string, mixed>, mapped: int, unmapped: array<int, array{setting: string, reason: string}>}>
	 */
	public static function sources(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$out       = array();
		$network   = self::reads_the_network();

		foreach ( self::SOURCES as $key => $files ) {
			$raw = self::raw( $key, $network );

			if ( null === $raw ) {
				continue;
			}

			// Active on this site or across the network, either edition.
			$running = array_values( array_filter( $files, 'is_plugin_active' ) );
			$active  = array() !== $running;
			$read    = self::read( $key, $raw );
			$name    = '';

			// Named after the edition that runs, or else the one installed.
			foreach ( array_merge( $running, $files ) as $file ) {
				if ( isset( $installed[ $file ]['Name'] ) ) {
					$name = wp_strip_all_tags( (string) $installed[ $file ]['Name'] );
					break;
				}
			}

			$out[] = array(
				'key'      => $key,
				'name'     => '' !== $name ? $name : __( 'A security plugin that is no longer installed', 'bettershield' ),
				'active'   => $active,
				'document' => $read['document'],
				'mapped'   => count( $read['document']['hardening'] ?? array() ) + self::carried_login( (array) ( $read['document']['login_protection'] ?? array() ) ),
				'unmapped' => $read['unmapped'],
			);
		}

		return $out;
	}

	/**
	 * How many sign-in settings a document carries: the attempt limits as
	 * one, and each list as one.
	 *
	 * @param array<string, mixed> $login
	 */
	private static function carried_login( array $login ): int {
		return ( isset( $login['threshold'] ) ? 1 : 0 ) + ( isset( $login['allowlist'] ) ? 1 : 0 ) + ( isset( $login['blocklist'] ) ? 1 : 0 );
	}

	/**
	 * Whether this caller may read the settings a network keeps for the whole
	 * network: on a single site everyone who may import, and on a network
	 * whoever administers it, or the operator at the terminal. A site's
	 * administrator reads what that site keeps, and nothing the network does:
	 * the network's allowlist names the addresses it trusts, and its blocked
	 * usernames are a list of the accounts it protects.
	 */
	private static function reads_the_network(): bool {
		return ! is_multisite() || current_user_can( 'manage_network_options' ) || ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * A source's stored settings, or null when there are none to read, or
	 * none this caller may read.
	 *
	 * @param bool $network Whether settings the network keeps may be read.
	 * @return array<string, mixed>|null
	 */
	private static function raw( string $key, bool $network = true ): ?array {
		switch ( $key ) {
			case 'solid':
				if ( ! $network ) {
					return null;
				}

				// Kept network-wide on a network, and in the site's own
				// options otherwise; the site-option read answers both.
				$storage = get_site_option( 'itsec-storage' );

				return is_array( $storage ) ? array(
					'storage' => $storage,
					'modules' => (array) get_site_option( 'itsec_active_modules', array() ),
				) : null;

			case 'aios':
				$configs = get_option( 'aio_wp_security_configs' );

				if ( ! is_array( $configs ) ) {
					return null;
				}

				/*
				 * The full XML-RPC block is kept in the firewall's own file,
				 * not in the option: a current AIOS leaves the option's key at
				 * its legacy '0' whatever its screen says. Either store saying
				 * on is on.
				 */
				$firewall = self::aios_firewall();

				if ( self::on( $firewall['aiowps_enable_pingback_firewall'] ?? null ) ) {
					$configs['aiowps_enable_pingback_firewall'] = '1';
				}

				return $configs;

			case 'rsssl':
				$options = get_option( 'rsssl_options' );

				if ( ! is_array( $options ) && is_multisite() && $network ) {
					$options = get_site_option( 'rsssl_options' );
				}

				return is_array( $options ) ? $options : null;

			case 'wf':
				// Its tables sit at the base prefix: on a network, the network's.
				return $network || ! is_multisite() ? self::wf_raw() : null;

			case 'llar':
				// One option per setting. On a network it may keep them for
				// the whole network instead, in the network's options.
				$read = static function ( string $name ) use ( $network ) {
					$value = get_option( 'limit_login_' . $name, null );

					return null === $value && is_multisite() && $network ? get_site_option( 'limit_login_' . $name, null ) : $value;
				};

				if ( null === $read( 'allowed_retries' ) ) {
					return null;
				}

				return array(
					'allowed_retries'  => $read( 'allowed_retries' ),
					'valid_duration'   => $read( 'valid_duration' ),
					'lockout_duration' => $read( 'lockout_duration' ),
					'whitelist'        => $read( 'whitelist' ),
					'blacklist'        => $read( 'blacklist' ),
					'lockouts'         => $read( 'allowed_lockouts' ),
					'long_duration'    => $read( 'long_duration' ),
					'usernames'        => $read( 'whitelist_usernames' ),
					'blocked_names'    => $read( 'blacklist_usernames' ),
				);

			case 'sgs':
				// One option per switch; none of them saved, it was never set up here.
				$settings = array();

				foreach ( self::SGS_SETTINGS as $name ) {
					$value = get_option( 'sg_security_' . $name, null );

					if ( null !== $value ) {
						$settings[ $name ] = $value;
					}
				}

				if ( array() === $settings ) {
					return null;
				}

				$settings['login_access'] = get_option( 'sg_login_access', array() );

				return $settings;

			case 'lockdown':
				$options = get_option( 'loginlockdown_options' );

				if ( ! is_array( $options ) ) {
					$options = get_option( 'loginlockdownAdminOptions' );
				}

				if ( is_array( $options ) ) {
					return $options;
				}

				// Limiting on its defaults from activation, before anything is saved.
				return false !== get_option( 'loginlockdown_meta' ) ? array() : null;

			case 'wps':
				$page     = self::wps_option( 'whl_page', $network );
				$redirect = self::wps_option( 'whl_redirect_admin', $network );

				// Active, it moves the address to its default before one is saved.
				if ( '' === $page && '' === $redirect && ! is_plugin_active( self::SOURCES['wps'][0] ) ) {
					return null;
				}

				return array(
					'page'     => '' !== $page ? $page : 'login',
					'redirect' => '' !== $redirect ? $redirect : '404',
				);

			case 'loginizer':
				$options = get_option( 'loginizer_options' );

				return is_array( $options ) ? array(
					'options'   => $options,
					'whitelist' => get_option( 'loginizer_whitelist', array() ),
					'blacklist' => get_option( 'loginizer_blacklist', array() ),
				) : null;
		}

		return null;
	}

	/**
	 * One of the address mover's settings, as it reads them: the site's own, or
	 * while the site has none and it is network-activated, the network's.
	 *
	 * @param bool $network Whether settings the network keeps may be read.
	 */
	private static function wps_option( string $name, bool $network ): string {
		$value = get_option( $name, '' );

		if ( ( ! is_string( $value ) || '' === $value ) && $network && is_multisite() && is_plugin_active_for_network( self::SOURCES['wps'][0] ) ) {
			$value = get_site_option( $name, '' );
		}

		return is_string( $value ) ? trim( $value, '/ ' ) : '';
	}

	/**
	 * AIOS's firewall settings, from the file it keeps them in.
	 *
	 * AIOS writes them under the main site's uploads, one file for a whole
	 * network, as PHP that halts at once followed by a JSON object, so its
	 * firewall can read them before WordPress loads. The file stays after
	 * AIOS is switched off. Nothing in it is run here: it is read as text and
	 * the object decoded.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function aios_firewall(): ?array {
		$base = (string) ( wp_get_upload_dir()['basedir'] ?? '' );

		if ( '' === $base ) {
			return null;
		}

		if ( is_multisite() && ! is_main_site() ) {
			$base = (string) preg_replace( '#/sites/' . get_current_blog_id() . '/?$#', '', $base );
		}

		$file = trailingslashit( $base ) . 'aios/firewall-rules/settings.php';

		if ( ! is_readable( $file ) ) {
			return null;
		}

		// Read to a ceiling: a file cut short by it decodes to nothing.
		$contents = @file_get_contents( $file, false, null, 0, 512 * KB_IN_BYTES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- another plugin's local settings file, read as text when the owner asks what can be brought over; one that cannot be read is no setting found.

		if ( ! is_string( $contents ) || ! preg_match( '/\{.*\}/s', $contents, $json ) ) {
			return null;
		}

		$settings = json_decode( $json[0], true );

		return is_array( $settings ) ? $settings : null;
	}

	/**
	 * The rows the source that keeps its settings in a table of its own has
	 * stored, by name, or null when there is no such table or nothing in it.
	 *
	 * The table is the network's, named in the case that plugin chose when it
	 * created it; both spellings are asked for, and neither is written to.
	 *
	 * @return array<string, string>|null
	 */
	private static function wf_raw(): ?array {
		global $wpdb;

		$table = self::existing_table( array( $wpdb->base_prefix . 'wfconfig', $wpdb->base_prefix . 'wfConfig' ) );

		if ( null === $table ) {
			return null;
		}

		$placeholders = implode( ', ', array_fill( 0, count( self::WF_SETTINGS ), '%s' ) );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- another plugin's own settings table, read once when the owner asks what can be brought over; the placeholder run is this class's own fixed list, and every value is bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT name, val FROM %i WHERE name IN (' . $placeholders . ')',
				array_merge( array( $table ), self::WF_SETTINGS )
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber

		$out = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$out[ (string) $row->name ] = (string) $row->val;
		}

		if ( array() === $out ) {
			return null;
		}

		// Whether anybody is enrolled in its two-factor: a count, never a row.
		$secrets = self::existing_table( array( $wpdb->base_prefix . 'wfls_2fa_secrets' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- as above: a count of another plugin's own table, read on request.
		$out['_two_factor_enrolled'] = null !== $secrets && (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $secrets ) ) > 0 ? '1' : '0';

		return $out;
	}

	/**
	 * The first of these tables that exists, or null.
	 *
	 * @param string[] $names
	 */
	private static function existing_table( array $names ): ?string {
		global $wpdb;

		/*
		 * Asked by reading nothing from it rather than by listing tables: a
		 * listing is a second question with its own case rules, and the read
		 * that follows is the one that has to work. A table that is not there
		 * answers with an error, which is an answer here and not a fault, so
		 * it is kept out of the log.
		 */
		$quiet = $wpdb->suppress_errors( true );

		try {
			foreach ( $names as $name ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- asking whether another plugin's table exists before reading it.
				if ( false !== $wpdb->query( $wpdb->prepare( 'SELECT 1 FROM %i LIMIT 0', $name ) ) ) {
					return $name;
				}
			}
		} finally {
			$wpdb->suppress_errors( $quiet );
		}

		return null;
	}

	/**
	 * Turn one source's settings into a document and a list of what was left.
	 *
	 * @param array<string, mixed> $raw
	 * @return array{document: array<string, mixed>, unmapped: array<int, array{setting: string, reason: string}>}
	 */
	public static function read( string $key, array $raw ): array {
		$items    = array();
		$login    = null;
		$lists    = null;
		$blocked  = array();
		$unmapped = array();
		$address  = null;

		if ( 'solid' === $key ) {
			$storage = (array) ( $raw['storage'] ?? array() );
			$tweaks  = (array) ( $storage['wordpress-tweaks'] ?? array() );
			$system  = (array) ( $storage['system-tweaks'] ?? array() );
			$modules = (array) ( $raw['modules'] ?? array() );

			self::flag( $items, 'file_editor', $tweaks['file_editor'] ?? null );
			self::flag( $items, 'directory_browsing', $system['directory_browsing'] ?? null );
			self::flag( $items, 'uploads_php', $system['uploads_php'] ?? null );

			if ( 'disable' === ( $tweaks['disable_xmlrpc'] ?? '' ) ) {
				$items[] = 'xmlrpc';
			} elseif ( 'disable_pingbacks' === ( $tweaks['disable_xmlrpc'] ?? '' ) ) {
				$unmapped[] = self::pingbacks_only();
			}

			if ( 'restrict-access' === ( $tweaks['rest_api'] ?? '' ) ) {
				$unmapped[] = array(
					'setting' => __( 'Restricting the REST API for signed-out visitors', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: %s: the name of a hardening fix, e.g. "Username privacy". */
						__( '“%s” covers only the user list; the rest of the REST API stays open.', 'bettershield' ),
						self::item_title( 'user_enumeration' )
					),
				);
			}

			if ( true === ( $system['protect_files'] ?? null ) ) {
				$unmapped[] = array(
					'setting' => __( 'Blocking access to system files', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: %s: the name of a hardening fix, e.g. "Hide sensitive files from visitors". */
						__( 'Not carried in this version. Review “%s” on the Hardening tab.', 'bettershield' ),
						self::item_title( 'sensitive_files' )
					),
				);
			}

			// A module switched off is stored as false; one never touched is
			// on by default in that plugin.
			if ( false !== ( $modules['brute-force'] ?? true ) ) {
				$brute  = (array) ( $storage['brute-force'] ?? array() );
				$global = (array) ( $storage['global'] ?? array() );
				$login  = self::numbers( $brute['max_attempts_host'] ?? null, $brute['check_period'] ?? null, $global['lockout_period'] ?? null );
			}

			if ( true === ( $storage['hide-backend']['enabled'] ?? null ) ) {
				$unmapped[] = self::sign_in_address();
			}

			if ( true === ( $modules['two-factor'] ?? null ) ) {
				$unmapped[] = self::two_factor();
			}

			// The addresses it never locks out, which its numbers carried here
			// without: an office it exempted could be locked out after the
			// switch, and nothing said so.
			$lists    = self::lists( $storage['global']['lockout_white_list'] ?? '' );
			$unmapped = array_merge( $unmapped, $lists['unmapped'] );
		} elseif ( 'aios' === $key ) {
			self::flag( $items, 'file_editor', $raw['aiowps_disable_file_editing'] ?? null );
			self::flag( $items, 'user_enumeration', $raw['aiowps_prevent_users_enumeration'] ?? null );
			self::flag( $items, 'version_disclosure', $raw['aiowps_remove_wp_generator_meta_info'] ?? null );
			self::flag( $items, 'directory_browsing', $raw['aiowps_disable_index_views'] ?? null );
			self::flag( $items, 'xmlrpc', $raw['aiowps_enable_pingback_firewall'] ?? null );

			if ( self::on( $raw['aiowps_disable_xmlrpc_pingback_methods'] ?? null ) && ! in_array( 'xmlrpc', $items, true ) ) {
				$unmapped[] = self::pingbacks_only();
			}

			if ( self::on( $raw['aiowps_enable_login_lockdown'] ?? null ) ) {
				$login = self::numbers( $raw['aiowps_max_login_attempts'] ?? null, $raw['aiowps_retry_time_period'] ?? null, $raw['aiowps_lockout_time_length'] ?? null );
			}

			if ( self::on( $raw['aiowps_enable_rename_login_page'] ?? null ) ) {
				$unmapped[] = self::sign_in_address();
			}

			// Its lockdown's allowed addresses, only while that plugin used
			// them: carrying a list it had switched off would exempt
			// addresses nobody was exempting.
			if ( self::on( $raw['aiowps_lockdown_enable_whitelisting'] ?? null ) ) {
				$lists    = self::lists( $raw['aiowps_lockdown_allowed_ip_addresses'] ?? '' );
				$unmapped = array_merge( $unmapped, $lists['unmapped'] );
			}

			/*
			 * Its blocked addresses and its sign-in allowlist have no reader
			 * here, and were dropped without a word: an owner switching it
			 * off could think those addresses were still refused (#2150).
			 */
			if ( self::on( $raw['aiowps_enable_blacklisting'] ?? null ) && '' !== trim( (string) ( $raw['aiowps_banned_ip_addresses'] ?? '' ) ) ) {
				$unmapped[] = self::blocked_addresses( preg_split( '/[\s,]+/', trim( (string) $raw['aiowps_banned_ip_addresses'] ) ) ?: array() );
			}

			if ( self::on( $raw['aiowps_enable_whitelisting'] ?? null ) ) {
				$unmapped[] = self::only_listed_addresses();
			}
		} elseif ( 'wf' === $key ) {
			self::flag( $items, 'user_enumeration', $raw['loginSec_disableAuthorScan'] ?? null );
			self::flag( $items, 'version_disclosure', $raw['other_hideWPVersion'] ?? null );
			self::flag( $items, 'uploads_php', $raw['disableCodeExecutionUploads'] ?? null );
			self::flag( $items, 'breached_passwords', $raw['loginSec_breachPasswds_enabled'] ?? null );

			if ( self::on( $raw['loginSecurityEnabled'] ?? null ) ) {
				$login = self::numbers( $raw['loginSec_maxFailures'] ?? null, $raw['loginSec_countFailMins'] ?? null, $raw['loginSec_lockoutMins'] ?? null );
			}

			$lists    = self::lists( $raw['whitelisted'] ?? '' );
			$unmapped = array_merge( $unmapped, $lists['unmapped'], self::wf_not_carried( $raw ) );
		} elseif ( 'llar' === $key ) {
			// Its times are kept in seconds; these are minutes.
			$login = self::numbers( $raw['allowed_retries'] ?? null, self::minutes( $raw['valid_duration'] ?? null ), self::minutes( $raw['lockout_duration'] ?? null ) );
			$lists = self::lists( $raw['whitelist'] ?? '' );

			$unmapped = array_merge( $unmapped, $lists['unmapped'] );

			$refused  = is_array( $raw['blacklist'] ?? null ) ? $raw['blacklist'] : array();
			$blocked  = self::blocked_list( $refused, $raw['blocked_names'] ?? array() );
			$unmapped = array_merge( $unmapped, $blocked['unmapped'] );

			// Its longer lockout and its username allowlist were dropped
			// without a word, while Loginizer's longer lockout was named (#2512).
			if ( is_numeric( $raw['lockouts'] ?? null ) && is_numeric( $raw['long_duration'] ?? null ) && (int) $raw['long_duration'] > (int) ( $raw['lockout_duration'] ?? 0 ) ) {
				$unmapped[] = self::longer_lockout();
			}

			$usernames = is_array( $raw['usernames'] ?? null ) ? array_values( array_filter( array_map( static fn( $entry ): string => is_scalar( $entry ) ? trim( (string) $entry ) : '', $raw['usernames'] ) ) ) : array();

			if ( array() !== $usernames ) {
				$unmapped[] = array(
					'setting' => __( 'Usernames that are never locked out', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: 1: the plugin's name, or the label the site owner gave it, 2: the usernames, the first ten and how many more. */
						__( '%1$s can only exempt addresses, not usernames. Once the other plugin is turned off, these accounts are limited like any other: %2$s.', 'bettershield' ),
						\BetterShield\Support\Branding::name(),
						self::first_ten( $usernames )
					),
				);
			}
		} elseif ( 'loginizer' === $key ) {
			$options = (array) ( $raw['options'] ?? array() );
			$login   = self::numbers( $options['max_retries'] ?? null, self::minutes( $options['reset_retries'] ?? null ), self::minutes( $options['lockout_time'] ?? null ) );

			// Its allowlist is kept as from-to pairs: one address is a pair
			// that starts and ends on it, and a span is listed, not guessed.
			$listed = array();

			foreach ( is_array( $raw['whitelist'] ?? null ) ? $raw['whitelist'] : array() as $entry ) {
				$start = is_array( $entry ) && is_scalar( $entry['start'] ?? null ) ? trim( (string) $entry['start'] ) : '';
				$end   = is_array( $entry ) && is_scalar( $entry['end'] ?? null ) ? trim( (string) $entry['end'] ) : $start;

				if ( '' !== $start ) {
					$listed[] = $start === $end || '' === $end ? $start : $start . '-' . $end;
				}
			}

			$lists    = self::lists( $listed );
			$blocked  = self::blocked_list( array_map( array( self::class, 'span' ), is_array( $raw['blacklist'] ?? null ) ? $raw['blacklist'] : array() ) );
			$unmapped = array_merge( $unmapped, $lists['unmapped'], $blocked['unmapped'] );

			if ( self::on( $options['trusted_ips'] ?? null ) ) {
				$unmapped[] = self::only_listed_addresses();
			}

			if ( is_numeric( $options['max_lockouts'] ?? null ) && is_numeric( $options['lockouts_extend'] ?? null ) && (int) $options['lockouts_extend'] > (int) ( $options['lockout_time'] ?? 0 ) ) {
				$unmapped[] = self::longer_lockout();
			}
		} elseif ( 'sgs' === $key ) {
			self::flag( $items, 'xmlrpc', $raw['disable_xml_rpc'] ?? null );
			self::flag( $items, 'file_editor', $raw['disable_file_edit'] ?? null );
			self::flag( $items, 'version_disclosure', $raw['wp_remove_version'] ?? null );
			self::flag( $items, 'user_enumeration', $raw['rest_user_enumeration'] ?? null );
			// Its folder lock refuses PHP in uploads, wp-content and
			// wp-includes; the uploads part is the same job as one here.
			self::flag( $items, 'uploads_php', $raw['lock_system_folders'] ?? null );

			/*
			 * A number of attempts, 0 for off. It locks out for an hour and
			 * keeps counting until a sign-in succeeds, so the window is the
			 * longest one here, a day. Its longer lockouts after that are
			 * named below.
			 */
			$attempts = is_numeric( $raw['login_attempts'] ?? null ) ? (int) $raw['login_attempts'] : 0;

			if ( $attempts > 0 ) {
				$login      = self::numbers( $attempts, 1440, 60 );
				$unmapped[] = self::longer_lockout();
			}

			$unmapped = array_merge( $unmapped, self::sgs_not_carried( $raw ) );
		} elseif ( 'wps' === $key ) {
			/*
			 * The address people already use comes over as it is, with the
			 * dashboard hidden as it hid it: with the address alone, a
			 * signed-out visitor at /wp-admin/ was sent on to it once the
			 * other plugin was switched off.
			 */
			$slug    = strtolower( (string) ( $raw['page'] ?? '' ) );
			$refusal = \BetterShield\Hardening\Item\LoginUrl::takeover_refusal( $slug );

			if ( null === $refusal ) {
				$address = $slug;
			} else {
				$unmapped[] = array(
					'setting' => __( 'A changed sign-in address', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: %s: why the address cannot be used, e.g. "That address is already part of WordPress. Choose another." */
						__( '%s Its address keeps working while the other plugin stays on.', 'bettershield' ),
						$refusal
					),
				);
			}

			$items[] = 'admin_gate';

			$redirect = (string) ( $raw['redirect'] ?? '404' );

			if ( '404' !== $redirect ) {
				$unmapped[] = array(
					/* translators: %s: an address on this site, e.g. /welcome/. */
					'setting' => sprintf( __( 'Sending signed-out visitors at /wp-admin/ to %s', 'bettershield' ), user_trailingslashit( '/' . $redirect ) ),
					'reason'  => sprintf(
						/* translators: %s: the name of a hardening fix, e.g. "Dashboard privacy for visitors". */
						__( '“%s” shows them a page-not-found instead.', 'bettershield' ),
						self::item_title( 'admin_gate' )
					),
				);
			}
		} elseif ( 'lockdown' === $key ) {
			$options = array_merge( self::LOCKDOWN_DEFAULTS, $raw );

			// Its times are kept in minutes already.
			$login = self::numbers( $options['max_login_retries'], $options['retries_within'], $options['lockout_length'] );

			// Each entry is one address, matched exactly, never locked out.
			$lists    = self::lists( $options['whitelist'] );
			$unmapped = array_merge( $unmapped, $lists['unmapped'] );

			if ( self::on( $options['mask_login_errors'] ) ) {
				$unmapped[] = self::error_details();
			}

			if ( is_scalar( $options['captcha'] ) && ! in_array( (string) $options['captcha'], array( '', 'disabled' ), true ) ) {
				$unmapped[] = array(
					'setting' => __( 'A challenge on the sign-in form', 'bettershield' ),
					'reason'  => self::no_setting(),
				);
			}

			if ( self::on( $options['global_block'] ) ) {
				$unmapped[] = array(
					'setting' => __( 'Blocking locked-out addresses from the whole site', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: %s: the plugin's name, or the label the site owner gave it. */
						__( '%s locks an address out of signing in only. The rest of the site stays open to it.', 'bettershield' ),
						\BetterShield\Support\Branding::name()
					),
				);
			}
		} elseif ( 'rsssl' === $key ) {
			self::flag( $items, 'file_editor', $raw['disable_file_editing'] ?? null );
			self::flag( $items, 'xmlrpc', $raw['disable_xmlrpc'] ?? null );
			self::flag( $items, 'user_enumeration', $raw['disable_user_enumeration'] ?? null );
			self::flag( $items, 'directory_browsing', $raw['disable_indexing'] ?? null );
			self::flag( $items, 'version_disclosure', $raw['hide_wordpress_version'] ?? null );
			self::flag( $items, 'uploads_php', $raw['block_code_execution_uploads'] ?? null );

			if ( self::on( $raw['enable_limited_login_attempts'] ?? null ) ) {
				$login = self::numbers( $raw['limit_login_attempts_amount'] ?? null, $raw['limit_login_attempts_duration'] ?? null, $raw['limit_login_attempts_locked_out_duration'] ?? null );
			}

			$unmapped = array_merge( $unmapped, self::rsssl_not_carried( $raw, $items ) );
		}

		$document = array(
			'format'    => SettingsDocument::FORMAT,
			'version'   => SettingsDocument::VERSION,
			'hardening' => array(),
		);

		foreach ( array_values( array_unique( array_intersect( $items, self::ITEMS ) ) ) as $item ) {
			$document['hardening'][ $item ] = array( 'active' => true );
		}

		if ( null !== $address ) {
			$document['hardening']['login_url'] = array(
				'active'  => true,
				'options' => array( 'slug' => $address ),
			);
		}

		/*
		 * Addresses join the list already here rather than replacing it: the
		 * document is planned against these settings, so the preview shows
		 * exactly what is added and nothing else moves.
		 */
		if ( is_array( $lists ) && array() !== $lists['allowlist'] ) {
			$current = \BetterShield\Login\Protection::instance()->settings();

			$document['login_protection'] = array(
				'allowlist' => self::merged( (array) $current['allowlist'], $lists['allowlist'], 'range' ),
			);
		}

		if ( array() !== ( $blocked['blocklist'] ?? array() ) ) {
			$current = \BetterShield\Login\Protection::instance()->settings();
			$list    = self::merged( (array) $current['blocklist'], array_values( array_filter( $blocked['blocklist'], static fn( array $entry ): bool => isset( $entry['range'] ) ) ), 'range' );

			$document['login_protection']['blocklist'] = self::merged( $list, array_values( array_filter( $blocked['blocklist'], static fn( array $entry ): bool => isset( $entry['username'] ) ) ), 'username' );
		}

		if ( is_array( $login ) && isset( $login['unmapped'] ) ) {
			$unmapped[] = $login['unmapped'];
		} elseif ( is_array( $login ) ) {
			/*
			 * Two plugins counting the same sign-ins would lock people out on
			 * whichever total runs out first. While any active plugin limits
			 * sign-ins, the source or one the owner kept for the job in the
			 * setup, the numbers are left with it, unless the owner gave this
			 * job to this plugin there.
			 */
			$elsewhere = \BetterShield\Onboarding\Coexistence::doing( 'login_limits' );

			if ( array() !== $elsewhere && ! self::sign_in_limits_given_here() ) {
				$unmapped[] = array(
					'setting' => __( 'Sign-in attempt limits', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: 1: the names of the active plugins that limit sign-ins, separated by commas, 2: the plugin's name, or the label the site owner gave it. */
						_n(
							'%1$s still limits sign-ins. Bring these over once it stops, or choose Use %2$s for sign-in attempt limits in Quick Setup.',
							'%1$s still limit sign-ins. Bring these over once none of them does, or choose Use %2$s for sign-in attempt limits in Quick Setup.',
							count( $elsewhere ),
							'bettershield'
						),
						implode( ', ', $elsewhere ),
						\BetterShield\Support\Branding::name()
					),
				);
			} else {
				$document['login_protection'] = array_merge( $document['login_protection'] ?? array(), $login );
			}
		}

		return array(
			'document' => $document,
			'unmapped' => $unmapped,
		);
	}

	/**
	 * The addresses a source never locks out, as entries of this plugin's
	 * allowlist, and those that cannot be carried. Each source keeps its
	 * list in its own shape, a list or a string split by commas, spaces or
	 * lines, and each is read the same way.
	 *
	 * @param mixed $listed
	 * @return array{allowlist: array<int, array<string, string>>, unmapped: array<int, array{setting: string, reason: string}>}
	 */
	private static function lists( $listed ): array {
		$allowlist = array();
		$skipped   = array();
		$listed    = is_array( $listed ) ? implode( "\n", array_filter( $listed, 'is_scalar' ) ) : ( is_scalar( $listed ) ? (string) $listed : '' );

		foreach ( preg_split( '/[\s,]+/', $listed ) ?: array() as $range ) {
			$range = trim( $range );

			if ( '' === $range ) {
				continue;
			}

			// Only a single address or a CIDR range is a range here; the
			// other notations that plugin accepts are listed, not guessed.
			if ( self::acceptable_range( $range ) ) {
				$allowlist[] = array(
					'range' => $range,
					'note'  => __( 'Brought over from another security plugin', 'bettershield' ),
				);
			} else {
				$skipped[] = $range;
			}
		}

		$unmapped = array();

		if ( array() !== $skipped ) {
			$unmapped[] = array(
				'setting' => __( 'Some allowed addresses', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: a list of addresses as that plugin wrote them. */
					__( 'Only single IP addresses and standard address ranges were imported. Add these yourself if you still need them: %s', 'bettershield' ),
					// Past ten, how many more: the eleventh on was left out
					// without a word, and copied by hand the list fell short (#2201).
					self::first_ten( $skipped )
				),
			);
		}

		return array(
			'allowlist' => $allowlist,
			'unmapped'  => $unmapped,
		);
	}

	/**
	 * What a source refuses, as entries of this plugin's blocklist, and the
	 * addresses that cannot be carried, named. The source already refused each
	 * of these, so carrying them refuses nobody new.
	 *
	 * @param array<int|string, mixed> $addresses
	 * @param mixed                    $usernames
	 * @return array{blocklist: array<int, array<string, string>>, unmapped: array<int, array{setting: string, reason: string}>}
	 */
	private static function blocked_list( array $addresses, $usernames = array() ): array {
		$note    = __( 'Brought over from another security plugin', 'bettershield' );
		$entries = array();
		$skipped = array();

		foreach ( array_filter( $addresses, 'is_scalar' ) as $address ) {
			$address = trim( (string) $address );

			if ( self::acceptable_range( $address ) ) {
				$entries[] = array(
					'range' => $address,
					'note'  => $note,
				);
			} elseif ( '' !== $address ) {
				$skipped[] = $address;
			}
		}

		foreach ( is_array( $usernames ) ? array_filter( $usernames, 'is_scalar' ) : array() as $username ) {
			if ( '' !== trim( (string) $username ) ) {
				$entries[] = array(
					'username' => trim( (string) $username ),
					'note'     => $note,
				);
			}
		}

		return array(
			'blocklist' => $entries,
			'unmapped'  => array() !== $skipped ? array( self::blocked_addresses( $skipped ) ) : array(),
		);
	}

	/**
	 * One of Loginizer's from-to pairs as a range this plugin can hold: one
	 * address, or the IPv4 CIDR block the pair covers exactly. Any other span
	 * stays as written, to be named rather than guessed.
	 *
	 * @param mixed $entry
	 */
	private static function span( $entry ): string {
		$start = is_array( $entry ) && is_scalar( $entry['start'] ?? null ) ? trim( (string) $entry['start'] ) : '';
		$end   = is_array( $entry ) && is_scalar( $entry['end'] ?? null ) ? trim( (string) $entry['end'] ) : $start;

		if ( '' === $end || $start === $end ) {
			return $start;
		}

		$from = ip2long( $start );
		$to   = ip2long( $end );

		if ( false !== $from && false !== $to && $to > $from ) {
			$size = $to - $from + 1;

			if ( 0 === ( $size & ( $size - 1 ) ) && 0 === ( $from & ( $size - 1 ) ) ) {
				return $start . '/' . ( 32 - (int) log( $size, 2 ) );
			}
		}

		return $start . '-' . $end;
	}

	/** @return array{setting: string, reason: string} */
	private static function only_listed_addresses(): array {
		return array(
			'setting' => __( 'Letting only listed addresses sign in', 'bettershield' ),
			'reason'  => sprintf(
				/* translators: %s: the plugin's name, or the label the site owner gave it. */
				__( '%s has no setting for this. Once the other plugin is turned off, anyone can reach the sign-in page.', 'bettershield' ),
				\BetterShield\Support\Branding::name()
			),
		);
	}

	/**
	 * What that source does that has no equivalent here, each only where it
	 * is switched on, so nothing is dropped without being named.
	 *
	 * @param array<string, string> $raw
	 * @return array<int, array{setting: string, reason: string}>
	 */
	private static function wf_not_carried( array $raw ): array {
		$out = array();

		if ( self::on( $raw['firewallEnabled'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'The firewall and its rules', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: the plugin's name, or the label the site owner gave it. */
					__( '%s doesn’t run a firewall, so there’s nothing to bring these into.', 'bettershield' ),
					\BetterShield\Support\Branding::name()
				),
			);
		}

		$rate = strtoupper( (string) ( $raw['maxGlobalRequests'] ?? 'DISABLED' ) );

		if ( '' !== $rate && 'DISABLED' !== $rate ) {
			$out[] = array(
				'setting' => __( 'Rate limiting', 'bettershield' ),
				'reason'  => __( 'Sign-in attempts are limited under Login & Access, and public forms under Request protection.', 'bettershield' ),
			);
		}

		if ( '' !== trim( (string) ( $raw['cbl_countries'] ?? '' ) ) ) {
			$out[] = array(
				'setting' => __( 'Country blocking', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: the plugin's name, or the label the site owner gave it. */
					__( '%s doesn’t block by country.', 'bettershield' ),
					\BetterShield\Support\Branding::name()
				),
			);
		}

		/*
		 * That plugin blocks the address of whoever tries a listed name, and
		 * only while its sign-in security is on. A blocked username here
		 * stops the account with that name from signing in instead, so a
		 * carried name would block nothing until an account was given it,
		 * and then that account for good.
		 */
		if ( self::on( $raw['loginSecurityEnabled'] ?? null ) && '' !== trim( (string) ( $raw['loginSec_userBlacklist'] ?? '' ) ) ) {
			$out[] = array(
				'setting' => __( 'Blocked usernames', 'bettershield' ),
				'reason'  => __( 'Here a wrong username already counts toward the attempt limit, and blocking a name would lock out any account later given it.', 'bettershield' ),
			);
		}

		if ( self::on( $raw['loginSec_lockInvalidUsers'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'Locking out a username that does not exist at once', 'bettershield' ),
				'reason'  => __( 'A wrong username already counts toward the sign-in attempt limit, like any other failure.', 'bettershield' ),
			);
		}

		if ( self::on( $raw['_two_factor_enrolled'] ?? null ) ) {
			$out[] = self::two_factor( true );
		}

		return $out;
	}

	/**
	 * What Really Simple Security has switched on that is not carried, each
	 * named with where to find it here, so nothing is dropped without a word
	 * (#2152). The changed sign-in address matters most: after the switch an
	 * owner may think the sign-in page is still hidden.
	 *
	 * @param array<string, mixed> $raw
	 * @return array<int, array{setting: string, reason: string}>
	 */
	private static function rsssl_not_carried( array $raw, array $items = array() ): array {
		$out = array();

		/*
		 * Its sign-in error details are hidden here by "Block public user
		 * listing", which gives one sign-in error for any wrong name or
		 * password: carried with it, nothing is left behind.
		 */
		if ( self::on( $raw['disable_login_feedback'] ?? null ) && ! in_array( 'user_enumeration', $items, true ) ) {
			$out[] = self::error_details();
		}

		if ( self::on( $raw['change_login_url_enabled'] ?? null ) ) {
			$out[] = self::sign_in_address();
		}

		if ( self::on( $raw['login_protection_enabled'] ?? null ) ) {
			$out[] = self::two_factor();
		}

		if ( self::on( $raw['disable_application_passwords'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'Turning off application passwords', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: the name of a hardening fix. */
					__( 'It changes how apps sign in, so it is not switched on by an import. Review “%s” on the Hardening tab.', 'bettershield' ),
					self::item_title( 'application_passwords' )
				),
			);
		}

		$none = array(
			'disable_anyone_can_register' => __( 'Turning off open registration', 'bettershield' ),
			'block_admin_creation'        => __( 'Blocking new administrator accounts', 'bettershield' ),
			'disable_http_methods'        => __( 'Turning off unused HTTP methods', 'bettershield' ),
		);

		foreach ( $none as $key => $setting ) {
			if ( self::on( $raw[ $key ] ?? null ) ) {
				$out[] = array(
					'setting' => $setting,
					'reason'  => self::no_setting(),
				);
			}
		}

		return $out;
	}

	/**
	 * What the source keeping one option per switch has on that is not
	 * carried, each named with where to find it here, so nothing is dropped
	 * without a word. Its sign-in limit and the switches with an item of
	 * their own here come over and are not listed.
	 *
	 * @param array<string, mixed> $raw
	 * @return array<int, array{setting: string, reason: string}>
	 */
	private static function sgs_not_carried( array $raw ): array {
		$out = array();

		if ( self::on( $raw['lock_system_folders'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'Blocking code in the wp-content and wp-includes folders', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: 1: the name of a hardening fix, e.g. "Uploads code block", 2: the plugin's name, or the label the site owner gave it. */
					__( '“%1$s” comes over for the uploads folder. %2$s has no setting for the other two folders.', 'bettershield' ),
					self::item_title( 'uploads_php' ),
					\BetterShield\Support\Branding::name()
				),
			);
		}

		if ( self::on( $raw['xss_protection'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'Security headers for browsers', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: the name of a hardening fix, e.g. "Browser protections". */
					__( 'Turn on “%s” on the Hardening tab. It sends the same file-type header, and today’s browsers ignore the older XSS one.', 'bettershield' ),
					self::item_title( 'security_headers' )
				),
			);
		}

		if ( self::on( $raw['delete_readme'] ?? null ) ) {
			$out[] = array(
				'setting' => __( 'Deleting readme.html after WordPress updates', 'bettershield' ),
				'reason'  => sprintf(
					/* translators: %s: the name of a hardening fix, e.g. "Private file protection". */
					__( 'Turn on “%s” on the Hardening tab, which hides readme.html from visitors.', 'bettershield' ),
					self::item_title( 'sensitive_files' )
				),
			);
		}

		if ( ! in_array( $raw['login_access'] ?? array(), array( array(), '', null ), true ) ) {
			$out[] = self::only_listed_addresses();
		}

		if ( 'custom' === ( $raw['login_type'] ?? '' ) ) {
			$out[] = self::sign_in_address();
		}

		if ( self::on( $raw['sg2fa'] ?? null ) ) {
			$out[] = self::two_factor();
		}

		$none = array(
			'disable_usernames' => __( 'Blocking common usernames such as admin', 'bettershield' ),
			'disable_feed'      => __( 'Turning off RSS feeds', 'bettershield' ),
		);

		foreach ( $none as $key => $setting ) {
			if ( self::on( $raw[ $key ] ?? null ) ) {
				$out[] = array(
					'setting' => $setting,
					'reason'  => self::no_setting(),
				);
			}
		}

		return $out;
	}

	/** The reason given for a protection with nothing like it here. */
	private static function no_setting(): string {
		/* translators: %s: the plugin's name, or the label the site owner gave it. */
		return sprintf( __( '%s has no setting for this. It stops working when the other plugin is turned off.', 'bettershield' ), \BetterShield\Support\Branding::name() );
	}

	/** @return array{setting: string, reason: string} */
	private static function error_details(): array {
		return array(
			'setting' => __( 'Hiding sign-in error details', 'bettershield' ),
			'reason'  => sprintf(
				/* translators: %s: the name of a hardening fix, e.g. "Username privacy". */
				__( 'Turn on “%s” on the Hardening tab, which gives one sign-in error for any wrong name or password.', 'bettershield' ),
				self::item_title( 'user_enumeration' )
			),
		);
	}

	/**
	 * Whether the allowlist here would take a range: an address or a CIDR
	 * range no wider than it accepts.
	 */
	private static function acceptable_range( string $range ): bool {
		if ( ! \BetterShield\Support\ClientIp::valid_range( $range ) ) {
			return false;
		}

		if ( ! str_contains( $range, '/' ) ) {
			return true;
		}

		list( $base, $bits ) = explode( '/', $range, 2 );

		return (int) $bits >= ( str_contains( $base, ':' ) ? 32 : 8 );
	}

	/**
	 * A list as it stands here, with new entries added where one with the
	 * same value is not already on it.
	 *
	 * @param array<int, array<string, mixed>> $current
	 * @param array<int, array<string, string>> $added
	 * @return array<int, array<string, mixed>>
	 */
	private static function merged( array $current, array $added, string $field ): array {
		$have = array();

		foreach ( $current as $entry ) {
			if ( is_array( $entry ) && isset( $entry[ $field ] ) ) {
				$have[ strtolower( (string) $entry[ $field ] ) ] = true;
			}
		}

		foreach ( $added as $entry ) {
			$value = strtolower( $entry[ $field ] );

			if ( ! isset( $have[ $value ] ) ) {
				$current[]      = $entry;
				$have[ $value ] = true;
			}
		}

		return array_values( $current );
	}

	/** Whether a stored value says a protection is on. */
	private static function on( $value ): bool {
		return true === $value || 1 === $value || in_array( $value, array( '1', 'on', 'yes', 'true' ), true );
	}

	/**
	 * @param string[] $items
	 * @param mixed    $value
	 */
	private static function flag( array &$items, string $item, $value ): void {
		if ( self::on( $value ) ) {
			$items[] = $item;
		}
	}

	/**
	 * Sign-in attempt numbers as this plugin keeps them, or the reason they
	 * cannot be carried.
	 *
	 * @param mixed $attempts
	 * @param mixed $window   Minutes.
	 * @param mixed $lockout  Minutes.
	 * @return array<string, mixed>|null
	 */
	private static function numbers( $attempts, $window, $lockout ): ?array {
		if ( ! is_numeric( $attempts ) || ! is_numeric( $window ) || ! is_numeric( $lockout ) ) {
			return null;
		}

		$attempts = (int) $attempts;
		$window   = (int) $window;
		$lockout  = (int) $lockout;

		if ( $attempts < 3 || $attempts > 100 || $window < 1 || $window > 1440 || $lockout < 1 || $lockout > 1440 ) {
			return array(
				'unmapped' => array(
					'setting' => __( 'Sign-in attempt limits', 'bettershield' ),
					'reason'  => sprintf(
						/* translators: 1: attempts allowed, e.g. "5 attempts", 2: time counted, e.g. "15 minutes", 3: time locked out, e.g. "30 minutes". */
						__( '%1$s in %2$s, then %3$s out, is out of range: 3 to 100 attempts, 1 minute to 1 day.', 'bettershield' ),
						/* translators: %d: number of sign-in attempts. */
						sprintf( _n( '%d attempt', '%d attempts', $attempts, 'bettershield' ), $attempts ),
						/* translators: %d: number of minutes. */
						sprintf( _n( '%d minute', '%d minutes', $window, 'bettershield' ), $window ),
						/* translators: %d: number of minutes. */
						sprintf( _n( '%d minute', '%d minutes', $lockout, 'bettershield' ), $lockout )
					),
				),
			);
		}

		/*
		 * The attempt limit has a switch of its own, which keeping another
		 * plugin for the job turns off. Numbers carried with it left off
		 * would be saved and enforced by nothing.
		 */
		return array(
			'enabled'         => true,
			'attempt_limit'   => true,
			'threshold'       => $attempts,
			'window_minutes'  => $window,
			'lockout_minutes' => $lockout,
		);
	}

	/**
	 * Seconds as whole minutes, rounded up so a limit never gets shorter, or
	 * null for a value that is not a number.
	 *
	 * @param mixed $seconds
	 */
	private static function minutes( $seconds ): ?int {
		return is_numeric( $seconds ) ? (int) ceil( (float) $seconds / 60 ) : null;
	}

	/**
	 * Addresses a source refuses, which have no reader here: named, so an
	 * owner switching it off knows they are no longer refused (#2150).
	 *
	 * @param string[] $blocked
	 * @return array{setting: string, reason: string}
	 */
	private static function blocked_addresses( array $blocked ): array {
		return array(
			'setting' => __( 'Blocked addresses', 'bettershield' ),
			'reason'  => sprintf(
				/* translators: %s: a list of addresses as that plugin wrote them. */
				__( 'Not carried over. Add any you still want refused to the blocklist under Login & Access: %s', 'bettershield' ),
				self::first_ten( $blocked )
			),
		);
	}

	/**
	 * The Quick Setup's login-limits answer as the setup's card has it on
	 * screen, for working out what an import would carry under either
	 * answer before it is saved; null reads the saved one.
	 *
	 * @var bool|null
	 */
	public static $limits_given = null;

	/** Whether the Quick Setup gave sign-in limits to this plugin. */
	private static function sign_in_limits_given_here(): bool {
		if ( null !== self::$limits_given ) {
			return self::$limits_given;
		}

		$state = get_option( \BetterShield\Onboarding\QuickSetup::OPTION, array() );

		return is_array( $state ) && 'bettershield' === ( $state['coexistence']['login_limits'] ?? '' );
	}

	/** @return array{setting: string, reason: string} */
	private static function pingbacks_only(): array {
		return array(
			'setting' => __( 'Turning off only XML-RPC pingbacks', 'bettershield' ),
			'reason'  => sprintf(
				/* translators: %s: the name of a hardening fix, e.g. "Disable XML-RPC". */
				__( '“%s” on the Hardening tab has a Pingbacks only choice that does the same.', 'bettershield' ),
				self::item_title( 'xmlrpc' )
			),
		);
	}

	/**
	 * A hardening fix by the name its own row shows, so a reason that points
	 * the owner at it cannot name it something no screen does.
	 */
	private static function item_title( string $item ): string {
		return (string) ( \BetterShield\Hardening\Items::all()[ $item ]['title'] ?? $item );
	}

	/** @return array{setting: string, reason: string} */
	private static function sign_in_address(): array {
		return array(
			'setting' => __( 'A changed sign-in address', 'bettershield' ),
			'reason'  => __( 'Set the sign-in address under Login & Access, which first checks for a working recovery method.', 'bettershield' ),
		);
	}

	/**
	 * Another plugin's longer lockout after repeated ones. Its numbers have
	 * nowhere to go: BetterShield lengthens repeat lockouts on its own (see
	 * Gate::escalation()), so the note says how rather than that every
	 * lockout lasts the same.
	 *
	 * @return array{setting: string, reason: string}
	 */
	private static function longer_lockout(): array {
		return array(
			'setting' => __( 'A longer lockout after repeated lockouts', 'bettershield' ),
			'reason'  => sprintf(
				/* translators: %s: the plugin's name, or the label the site owner gave it. */
				__( '%s does this its own way: each lockout of the same address within a day lasts twice as long as the one before, up to a day.', 'bettershield' ),
				\BetterShield\Support\Branding::name()
			),
		);
	}

	/**
	 * @param bool $moves Whether its authenticator-app enrollments come over
	 *                    as the plugin is switched off with two-factor handed
	 *                    to BetterShield.
	 * @return array{setting: string, reason: string}
	 */
	private static function two_factor( bool $moves = false ): array {
		return array(
			'setting' => __( 'Two-factor authentication', 'bettershield' ),
			'reason'  => $moves
				? sprintf(
					/* translators: %s: the plugin's name, or the label the site owner gave it. */
					__( 'Not imported as a setting. With two-factor handed to %s, switching the plugin off brings each authenticator app over. Backup codes don’t carry over; each person makes new ones.', 'bettershield' ),
					\BetterShield\Support\Branding::name()
				)
				: __( 'Enrollments cannot be moved. Each person sets up two-factor again.', 'bettershield' ),
		);
	}

	/**
	 * Addresses for a note, the first ten and then how many more, so none
	 * is dropped without a word (#2150, #2201).
	 *
	 * @param string[] $items
	 */
	private static function first_ten( array $items ): string {
		$shown = implode( ', ', array_slice( $items, 0, 10 ) );

		if ( count( $items ) <= 10 ) {
			return $shown;
		}

		return sprintf(
			/* translators: 1: the first addresses, 2: how many more there are. */
			_n( '%1$s and %2$d more', '%1$s and %2$d more', count( $items ) - 10, 'bettershield' ),
			$shown,
			count( $items ) - 10
		);
	}
}
