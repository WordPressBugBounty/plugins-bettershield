<?php
/**
 * Another security plugin on the same site, and which one does which job.
 *
 * Two plugins limiting sign-in attempts lock a person out twice, and two
 * asking for a second factor ask twice. So when one of the plugins below is
 * active, the Quick Setup shows one row per job the two of them share and
 * lets the owner say which keeps it. Every row starts on BetterShield: the
 * step never recommends keeping another plugin. A choice already saved keeps
 * its value.
 *
 * This class reads which plugins are active, and never writes to one.
 * Choosing BetterShield for a job switches on BetterShield's side of it and
 * brings over the other plugin's settings the import can read, previewed in
 * the step first (`imports()`). Switching the other plugin off stays the
 * owner's own press: the step calls WordPress's own Deactivate for it in
 * place, where core checks the nonce and the capability as it does on the
 * Plugins screen, and its Turn It Back On calls core's own Activate the
 * same way (`watch_deactivate_link()` notes both for Ready). The
 * plugin itself switches nothing off unless a site turns the setup's
 * in-place deactivation on (`deactivation_enabled()`, off by default), after
 * a confirmation naming the plugin. An agent switching plugins off is a
 * separate switch, `Registrar::deactivation_enabled()`.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Hardening\Items;
use BetterShield\Login\Protection;
use BetterShield\Operator\Migrate;
use BetterShield\Operator\SettingsDocument;
use BetterShield\Recovery\Preflight;
use BetterShield\Rest\Permissions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Coexistence {

	/** Jobs where the owner chooses who does it. */
	public const CHOICE_JOBS = array( 'login_limits', 'two_factor', 'login_url' );

	/**
	 * The items an import brings with a sign-in address, carried only while
	 * the sign-in address is given to BetterShield.
	 */
	private const ADDRESS_ITEMS = array( 'login_url', 'admin_gate' );

	/**
	 * Jobs that are stated rather than chosen. Not a firewall: the step is not
	 * where this plugin tells an owner to keep another one (#2298). A plugin
	 * running one still lists it among its jobs, so the step never offers to
	 * switch that plugin off (#2113).
	 */
	public const INFO_JOBS = array( 'vulnerabilities', 'https_redirect' );

	/** The login-protection keys that make up a source's attempt-limit numbers. */
	private const LIMIT_KEYS = array( 'enabled', 'attempt_limit', 'threshold', 'window_minutes', 'lockout_minutes' );

	/**
	 * Jobs one of the plugins below does only while a switch of its own is
	 * on, by plugin file: the job, the option that holds the switch, whether
	 * it is on when it has never been saved, and, where the option holds a
	 * plugin's settings together, the key of the one that is the switch. A
	 * job whose switch is off is not a job that plugin is doing.
	 *
	 * A fourth entry lists the values that mean on, for a setting with more
	 * than two answers, or is `set` for one that is on whenever it holds
	 * anything (a number of attempts, a moved address). A job some plugin
	 * does through either of two switches lists both, and is on while
	 * either is.
	 */
	private const SWITCHED_JOBS = array(
		// Moves the sign-in page only once a new address is saved, and has two
		// kinds of two-factor, by app and by email, each off out of the box.
		// Either runs only under its own master switch and for the roles it
		// names, which active() reads (wph_two_factor_on()).
		'wp-hide-security-enhancer/wp-hide.php' => array(
			'login_url'  => array( 'wph_settings', false, array( 'module_settings', 'new_wp_login_php' ), 'set' ),
			'two_factor' => array(
				array( 'wph_settings', false, array( 'module_settings', '2fa_app' ), array( 'yes' ) ),
				array( 'wph_settings', false, array( 'module_settings', '2fa_email' ), array( 'yes' ) ),
			),
		),
		// Its limit is a number of attempts, 0 for none, and 5 from install;
		// its two-factor is required of editors and administrators while
		// switched on; its address moves only when its type is custom.
		'sg-security/sg-security.php' => array(
			'login_limits' => array( 'sg_security_login_attempts', false, array(), 'set' ),
			'two_factor'   => array( 'sg_security_sg2fa', false ),
			'login_url'    => array( 'sg_security_login_type', false, array(), array( 'custom' ) ),
		),
		// Keeps its settings together as JSON, on the main site for a whole
		// network. Its address moves in any mode but the default one. Its
		// two-factor switch only offers it: it asks only the accounts that
		// set it up, so that is read from them (two_factor_record()).
		'hide-my-wp/index.php' => array(
			'login_limits' => array( 'hmwp_options', false, 'hmwp_bruteforce' ),
			'login_url'    => array( 'hmwp_options', false, 'hmwp_mode', array( 'lite', 'ninja' ) ),
		),
		// Locks out an address after failed sign-ins only while its lockout
		// is switched on, kept for the whole network; its two-factor is read
		// from the accounts that set it up (two_factor_record()).
		'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => array(
			'login_limits' => array( 'mo2f_brute_force_lockout_settings', false, 'enabled' ),
		),
		// Its moved address is on out of the box. Its two-factor in this
		// edition is emailed codes, asked only of the accounts that verified
		// an address while it is switched on; active() reads the switch and
		// two_factor_record() the accounts.
		'change-wp-admin-login/change-wp-admin-login.php' => array(
			'login_url' => array( 'aio_login__cwpal_enable', false ),
		),
		// Each limits sign-ins only while its lockout is switched on: on out
		// of the box in the first two, off in the others. One more keeps
		// that switch in a table of its own. See active().
		// Its hidden backend moves the sign-in page, off until it is set up,
		// and kept in its settings by module and then by key.
		'better-wp-security/better-wp-security.php' => array(
			'login_limits' => array( 'itsec_active_modules', true, 'brute-force' ),
			'login_url'    => array( 'itsec-storage', false, array( 'hide-backend', 'enabled' ) ),
		),
		'ithemes-security-pro/ithemes-security-pro.php' => array(
			'login_limits' => array( 'itsec_active_modules', true, 'brute-force' ),
			'login_url'    => array( 'itsec-storage', false, array( 'hide-backend', 'enabled' ) ),
		),
		// Its moved sign-in address is off out of the box too, behind a
		// switch in the same settings.
		'all-in-one-wp-security-and-firewall/wp-security.php' => array(
			'login_limits' => array( 'aio_wp_security_configs', false, 'aiowps_enable_login_lockdown' ),
			'login_url'    => array( 'aio_wp_security_configs', false, 'aiowps_enable_rename_login_page' ),
		),
		'really-simple-ssl-pro/really-simple-ssl-pro.php' => array(
			'login_limits'   => array( 'rsssl_options', false, 'enable_limited_login_attempts' ),
			// Redirects plain HTTP in PHP or in .htaccess, or not at all.
			'https_redirect' => array( 'rsssl_options', false, 'redirect', array( 'wp_redirect', 'htaccess' ) ),
		),
		'really-simple-ssl/rlrsssl-really-simple-ssl.php' => array(
			'https_redirect' => array( 'rsssl_options', false, 'redirect', array( 'wp_redirect', 'htaccess' ) ),
		),
		// Its sign-in limit blocks only in protect mode, the third of its three,
		// and its two-factor is one switch. See active() for its firewall.
		'blogvault-real-time-backup/blogvault.php' => array(
			'login_limits' => array( 'bvconfig', false, array( 'protect', 'lp', 'mode' ), array( 3 ) ),
			'two_factor'   => array( 'bvWp2faConf', false, 'enabled', array( true ) ),
		),
		'malcare-security/malcare.php' => array(
			'login_limits' => array( 'mcconfig', false, array( 'protect', 'lp', 'mode' ), array( 3 ) ),
			'two_factor'   => array( 'mcWp2faConf', false, 'enabled', array( true ) ),
		),
		'patchstack/patchstack.php' => array(
			'login_limits'    => array( 'patchstack_block_bruteforce_ips', false ),
			'two_factor'      => array( 'patchstack_login_2fa', false ),
			'login_url'       => array( 'patchstack_mv_wp_login', false ),
			// Its firewall, which is what applies the virtual patches.
			'firewall'        => array( 'patchstack_basic_firewall', false ),
			'vulnerabilities' => array( 'patchstack_basic_firewall', false ),
		),
	);

	/**
	 * Plugins whose switches do nothing until a license is connected and
	 * paid for, by plugin file: the option saying the license is active, and
	 * the one saying it is the free tier. Patchstack's hardening, sign-in
	 * protection, firewall and activity log all stand down otherwise, and a
	 * switch read on its own credited an unconnected copy with protections
	 * none of which were running.
	 */
	private const LICENSED = array(
		'patchstack/patchstack.php' => array( 'patchstack_license_activated', 'patchstack_license_free' ),
	);

	/**
	 * Hardening items another plugin already applies with a switch of its
	 * own, by plugin file, in the same shape. Applying this plugin's copy of
	 * one of those would do the same thing twice.
	 */
	private const SWITCHED_ITEMS = array(
		'patchstack/patchstack.php' => array(
			'xmlrpc'             => array( 'patchstack_xmlrpc_is_disabled', false ),
			'user_enumeration'   => array( 'patchstack_userenum', false ),
			'version_disclosure' => array( 'patchstack_hidewpversion', false ),
			'file_editor'        => array( 'patchstack_pluginedit', true ),
			'security_headers'   => array( 'patchstack_add_security_headers', false ),
		),
	);

	/**
	 * The plugins looked for, by the file WordPress knows them by, and the
	 * jobs each one does in the version most sites run. Their names are read
	 * from their own headers rather than written here, so the screen calls
	 * each one what the owner sees on the Plugins screen.
	 *
	 * @return array<string, string[]>
	 */
	private static function known(): array {
		return array(
			'wordfence/wordfence.php'                                         => array( 'login_limits', 'two_factor', 'firewall' ),
			'better-wp-security/better-wp-security.php'                       => array( 'login_limits', 'two_factor', 'login_url', 'firewall' ),
			// The paid edition under its own folder: the same jobs.
			'ithemes-security-pro/ithemes-security-pro.php'                   => array( 'login_limits', 'two_factor', 'login_url', 'firewall' ),
			'all-in-one-wp-security-and-firewall/wp-security.php'             => array( 'login_limits', 'two_factor', 'login_url', 'firewall' ),
			'really-simple-ssl/rlrsssl-really-simple-ssl.php'                 => array( 'two_factor', 'https_redirect' ),
			'really-simple-ssl-pro/really-simple-ssl-pro.php'                 => array( 'login_limits', 'two_factor', 'firewall', 'https_redirect' ),
			'wp-simple-firewall/icwp-wpsf.php'                                => array( 'login_limits', 'two_factor', 'firewall' ),
			'defender-security/wp-defender.php'                               => array( 'login_limits', 'two_factor', 'login_url', 'firewall' ),
			'wp-cerber/wp-cerber.php'                                         => array( 'login_limits', 'two_factor' ),
			// Its sign-in limit is its Login Protection, which is off until it
			// is switched on. See active().
			'ninjafirewall/ninjafirewall.php'                                 => array( 'login_limits', 'firewall' ),
			'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php' => array( 'login_limits' ),
			'limit-login-attempts/limit-login-attempts.php'                   => array( 'login_limits' ),
			'loginizer/loginizer.php'                                         => array( 'login_limits' ),
			// Limits from the moment it loads, with no switch to turn it off.
			'wps-limit-login/wps-limit-login.php'                             => array( 'login_limits' ),
			'wp-2fa/wp-2fa.php'                                               => array( 'two_factor' ),
			'two-factor/two-factor.php'                                       => array( 'two_factor' ),
			// Wordfence's sign-in module on its own: two-factor, and no limit
			// on attempts, which stays with the main plugin.
			'wordfence-login-security/wordfence-login-security.php'           => array( 'two_factor' ),
			'sucuri-scanner/sucuri.php'                                       => array( 'firewall' ),
			'wps-hide-login/wps-hide-login.php'                               => array( 'login_url' ),
			'wp-hide-security-enhancer/wp-hide.php'                           => array( 'login_url', 'two_factor' ),
			'sg-security/sg-security.php'                                     => array( 'login_limits', 'two_factor', 'login_url' ),
			'hide-my-wp/index.php'                                            => array( 'login_limits', 'two_factor', 'login_url' ),
			// Its limit is in its paid edition only; this one moves the
			// address and emails codes.
			'change-wp-admin-login/change-wp-admin-login.php'                 => array( 'login_url', 'two_factor' ),
			// Limits from the moment it loads, with no switch to turn it off.
			'login-lockdown/loginlockdown.php'                                => array( 'login_limits' ),
			'google-authenticator/google-authenticator.php'                   => array( 'two_factor' ),
			'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => array( 'login_limits', 'two_factor' ),
			'rename-wp-login/rename-wp-login.php'                             => array( 'login_url' ),
			// A firewall with virtual patches for known vulnerabilities, and
			// its own event log. Each counts only on a connected, paid
			// license and while its own switch is on. See active().
			'patchstack/patchstack.php'                                       => array( 'login_limits', 'two_factor', 'login_url', 'firewall', 'vulnerabilities' ),
			// Only its brute-force module does a job BetterShield does, and
			// only while that module is switched on. See active().
			'jetpack/jetpack.php'                                             => array( 'login_limits' ),
			// The same module, in the standalone plugin.
			'jetpack-protect/jetpack-protect.php'                             => array( 'login_limits' ),
			// One codebase under two names. Nothing runs until its own service
			// connects and switches it on. See active().
			'blogvault-real-time-backup/blogvault.php'                        => array( 'login_limits', 'two_factor', 'firewall' ),
			'malcare-security/malcare.php'                                    => array( 'login_limits', 'two_factor', 'firewall' ),
		);
	}

	/**
	 * The listed plugins that are active here, with the jobs they do.
	 *
	 * @return array<string, array{name: string, jobs: string[]}>
	 */
	public static function active(): array {
		if ( ! function_exists( 'is_plugin_active' ) || ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$found     = array();

		foreach ( self::known() as $file => $jobs ) {
			if ( ! is_plugin_active( $file ) ) {
				continue;
			}

			/*
			 * Listed as active with its file gone from disk: deleted or
			 * renamed outside WordPress, over FTP or by a deploy. WordPress
			 * does not load it, and the list keeps the entry until somebody
			 * opens the Plugins screen, so it is doing none of these jobs.
			 * Counted, it kept "Nothing is limiting sign-in attempts" from
			 * being raised while nothing was.
			 */
			if ( ! file_exists( WP_PLUGIN_DIR . '/' . $file ) ) {
				continue;
			}

			if ( 'wordfence/wordfence.php' === $file && ! self::table_setting_on( 'loginSecurityEnabled', true ) ) {
				$jobs = array_diff( $jobs, array( 'login_limits' ) );
			}

			if ( in_array( $file, array( 'jetpack/jetpack.php', 'jetpack-protect/jetpack-protect.php' ), true ) && ! self::jetpack_protects() ) {
				continue;
			}

			if ( 'defender-security/wp-defender.php' === $file && ! self::defender_masks_login() ) {
				$jobs = array_diff( $jobs, array( 'login_url' ) );
			}

			// One limiter shared by both: named once, by Jetpack.
			if ( 'jetpack-protect/jetpack-protect.php' === $file && is_plugin_active( 'jetpack/jetpack.php' ) && file_exists( WP_PLUGIN_DIR . '/jetpack/jetpack.php' ) ) {
				continue;
			}

			if ( 'wp-hide-security-enhancer/wp-hide.php' === $file && ! self::wph_two_factor_on() ) {
				$jobs = array_diff( $jobs, array( 'two_factor' ) );
			}

			// Its own address typed in as the new one moves nothing.
			if ( 'wp-hide-security-enhancer/wp-hide.php' === $file && 'wp-login.php' === trim( (string) ( self::wph_settings()['new_wp_login_php'] ?? '' ), '/ ' ) ) {
				$jobs = array_diff( $jobs, array( 'login_url' ) );
			}

			/*
			 * Two-factor that asks nobody while its own switch is off, though
			 * the accounts that set it up keep their records: these read the
			 * accounts (two_factor_record()) and the switch together.
			 */
			if ( 'change-wp-admin-login/change-wp-admin-login.php' === $file && 'on' !== get_option( 'aio_login_pro__2fa_email_otp_enable' ) ) {
				$jobs = array_diff( $jobs, array( 'two_factor' ) );
			}

			if ( 'hide-my-wp/index.php' === $file && ! self::switched_on( array( 'hmwp_options', false, 'hmwp_2falogin' ) ) ) {
				$jobs = array_diff( $jobs, array( 'two_factor' ) );
			}

			// Kept for the whole network; 0, or not yet written, until it is
			// turned on. Anything but a plain value, a corrupt option, is off:
			// cast as it was, an object warned on every read.
			if ( 'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' === $file ) {
				$mo2f = get_site_option( 'mo2f_activate_plugin', 0 );

				if ( ! is_scalar( $mo2f ) || 1 !== (int) $mo2f ) {
					$jobs = array_diff( $jobs, array( 'two_factor' ) );
				}
			}

			/*
			 * Two-factor nobody has set up isn't a job it's doing. Listed as
			 * active, it closed the password-only finding, raised the score,
			 * and said it handled a job it wasn't. A plugin with a switch for
			 * this is read from that switch instead, below.
			 */
			if ( ! isset( self::SWITCHED_JOBS[ $file ]['two_factor'] ) && in_array( 'two_factor', $jobs, true ) && 0 === self::enrolled_count( $file ) ) {
				$jobs = array_diff( $jobs, array( 'two_factor' ) );
			}

			if ( 'ninjafirewall/ninjafirewall.php' === $file && ! self::login_protection_file_on() ) {
				$jobs = array_diff( $jobs, array( 'login_limits' ) );
			}

			if ( in_array( $file, array( 'blogvault-real-time-backup/blogvault.php', 'malcare-security/malcare.php' ), true ) && ! self::blogvault_firewall_installed() ) {
				$jobs = array_diff( $jobs, array( 'firewall' ) );
			}

			$jobs = array_values(
				array_filter(
					$jobs,
					static fn( string $job ): bool => ! isset( self::SWITCHED_JOBS[ $file ][ $job ] ) || ( self::licensed( $file ) && self::switched_on( self::SWITCHED_JOBS[ $file ][ $job ] ) )
				)
			);

			// Left doing none of these jobs, it has none to share.
			if ( array() === $jobs ) {
				continue;
			}

			// Not a job to share, and it stops with the plugin, so the step says so.
			if ( 'blogvault-real-time-backup/blogvault.php' === $file ) {
				$jobs[] = 'backups';
			}

			$name = isset( $installed[ $file ]['Name'] ) ? wp_strip_all_tags( (string) $installed[ $file ]['Name'] ) : '';

			$found[ $file ] = array(
				'name' => '' !== $name ? $name : dirname( $file ),
				'jobs' => $jobs,
			);
		}

		/**
		 * The security plugins the Quick Setup's coexistence check found.
		 *
		 * @param array<string, array{name: string, jobs: string[]}> $found Keyed by plugin file.
		 */
		$filtered = apply_filters( 'bettershield_coexisting_plugins', $found );

		return is_array( $filtered ) ? $filtered : $found;
	}

	/**
	 * Whether another plugin's switch is on, read the way that plugin reads
	 * it: this site's own option, or the network's where the site has none.
	 *
	 * @param array<int, mixed> $switch The option, its value when never saved, the key within it (or the path of keys, outermost first), and the values that mean on, or `set`; or a list of such switches.
	 */
	private static function switched_on( array $switch ): bool {
		// Two switches for one job: on while either is.
		if ( is_array( $switch[0] ) ) {
			foreach ( $switch as $one ) {
				if ( self::switched_on( $one ) ) {
					return true;
				}
			}

			return false;
		}

		list( $option, $default ) = $switch;

		$value = self::plugin_option( $option, null );

		if ( null === $value && is_multisite() ) {
			$value = get_site_option( $option, null );
		}

		$path = isset( $switch[2] ) ? (array) $switch[2] : array();

		// Settings kept together as JSON are read the same way.
		if ( array() !== $path && is_string( $value ) ) {
			$value = json_decode( $value, true );
		}

		foreach ( $path as $key ) {
			$value = is_array( $value ) ? ( $value[ $key ] ?? null ) : null;
		}

		if ( null === $value ) {
			return $default;
		}

		// On whenever it holds anything: a number of attempts, an address.
		if ( 'set' === ( $switch[3] ?? null ) ) {
			return ! in_array( $value, array( '', '0', 0, false ), true );
		}

		// A setting with more than two answers names the ones that mean on.
		if ( isset( $switch[3] ) ) {
			return in_array( $value, (array) $switch[3], true );
		}

		return true === $value || 1 === $value || in_array( $value, array( '1', 'on', 'yes', 'true' ), true );
	}

	/**
	 * Whether a plugin's switches can be doing anything: true for every
	 * plugin that needs no license, and for one that does, only while it is
	 * connected and not the free tier.
	 */
	private static function licensed( string $file ): bool {
		if ( ! isset( self::LICENSED[ $file ] ) ) {
			return true;
		}

		list( $activated, $free ) = self::LICENSED[ $file ];

		return self::switched_on( array( $activated, false ) ) && ! self::switched_on( array( $free, false ) );
	}

	/**
	 * The name of an active plugin that already applies a hardening item with
	 * a switch of its own, or '' when none does.
	 */
	public static function applied_elsewhere( string $item ): string {
		$active = self::active();

		foreach ( self::SWITCHED_ITEMS as $file => $items ) {
			if ( isset( $active[ $file ], $items[ $item ] ) && self::licensed( $file ) && self::switched_on( $items[ $item ] ) ) {
				return $active[ $file ]['name'];
			}
		}

		return '';
	}

	/**
	 * Which plugin does which job, for the Overview: each other plugin with
	 * the jobs it keeps, and the jobs this plugin does. Null where no other
	 * security plugin is active.
	 *
	 * A job the owner kept with the other plugin is theirs; one given to this
	 * plugin is ours. What is only stated, vulnerability patching among it, is theirs,
	 * except a firewall: the panel does not credit another plugin with one,
	 * as the step does not (#2298). A job nobody chose here is still the
	 * other plugin's, whatever the step would open on.
	 *
	 * Also the plugins still keeping sign-in limits or two-factor, which the
	 * Overview offers to migrate from, and of those, the ones limiting
	 * sign-ins while this plugin's own limit is on too: only those lock
	 * people out twice. Kept by choice, this plugin's limit is off, and
	 * saying "locked out twice" would not be true. Not Patchstack, which
	 * this plugin is built to run beside, and not a plugin that only moves
	 * the sign-in address (#2755).
	 *
	 * @param array<string, string> $saved Job => choice, as last saved.
	 * @return array{others: array<int, array{name: string, jobs: string[]}>, ours: string[], migrate: string[], double: string[]}|null
	 */
	public static function split( array $saved ): ?array {
		$active = self::active();

		if ( array() === $active ) {
			return null;
		}

		$labels  = self::job_labels();
		$others  = array();
		$given   = array();
		$migrate = array();
		$double  = array();

		/*
		 * Whether this plugin's attempt limit is running, not what the
		 * choice says. With nothing saved the choice reads as "keep", and a
		 * limit switched back on after a saved choice stays on: either way
		 * the panel said only the other plugin limited sign-ins while this
		 * one was pausing connections.
		 */
		$limits    = Protection::instance()->settings();
		$limits_on  = ! empty( $limits['enabled'] ) && ! empty( $limits['attempt_limit'] );

		foreach ( $active as $file => $plugin ) {
			$jobs = array();

			// In the order the labels are listed, whatever order the map
			// gives them in.
			foreach ( array_intersect( array_keys( $labels ), $plugin['jobs'] ) as $job ) {
				if ( 'firewall' === $job ) {
					continue;
				}

				$choice = in_array( $job, self::CHOICE_JOBS, true ) ? ( isset( $saved[ $job ] ) ? self::choice_of( $job, $saved ) : 'keep' ) : '';

				if ( 'bettershield' === $choice ) {
					$given[ $job ] = true;
					continue;
				}

				if ( isset( $labels[ $job ] ) ) {
					$jobs[] = $labels[ $job ];
				}

				if ( 'keep' === $choice ) {
					$given[ $job ] = false;

					if ( 'patchstack/patchstack.php' !== $file && ! in_array( $plugin['name'], $migrate, true ) ) {
						$migrate[] = $plugin['name'];
					}

					// Both limiting at once: the one case where people really are locked out twice.
					if ( 'login_limits' === $job && $limits_on && 'patchstack/patchstack.php' !== $file && ! in_array( $plugin['name'], $double, true ) ) {
						$double[] = $plugin['name'];
					}
				}
			}

			if ( array() !== $jobs ) {
				$others[] = array(
					'name' => $plugin['name'],
					'jobs' => $jobs,
				);
			}
		}

		$ours = array();

		if ( $limits_on ) {
			$ours[] = __( 'sign-in protection', 'bettershield' );
		}

		if ( false !== ( $given['two_factor'] ?? true ) ) {
			$ours[] = __( 'two-factor', 'bettershield' );
		}

		$ours[] = __( 'account recovery', 'bettershield' );
		$ours[] = __( 'file change checks', 'bettershield' );
		$ours[] = __( 'the activity log', 'bettershield' );
		$ours[] = __( 'AI assistant access', 'bettershield' );

		return array(
			'others'  => $others,
			'ours'    => $ours,
			'migrate' => $migrate,
			'double'  => $double,
		);
	}

	/**
	 * Each job in the words the Overview uses.
	 *
	 * @return array<string, string>
	 */
	private static function job_labels(): array {
		return array(
			'vulnerabilities' => __( 'known vulnerabilities and virtual patching', 'bettershield' ),
			'firewall'        => __( 'the firewall', 'bettershield' ),
			'backups'         => __( 'backups', 'bettershield' ),
			'login_limits'    => __( 'sign-in attempt limits', 'bettershield' ),
			'two_factor'      => __( 'two-factor', 'bettershield' ),
			'login_url'       => __( 'the sign-in address', 'bettershield' ),
			'https_redirect'  => __( 'redirecting plain HTTP to HTTPS', 'bettershield' ),
		);
	}

	/**
	 * One switch of the plugin that keeps its settings in a table of its own
	 * rather than in options. The table is the network's, named in the case
	 * that plugin chose when it made it; both spellings are asked for, and
	 * neither is written to. A switch never saved there has its default.
	 */
	private static function table_setting_on( string $name, bool $default ): bool {
		global $wpdb;

		// A table that is not there answers with an error, which is an
		// answer here and not a fault, so it is kept out of the log.
		$quiet = $wpdb->suppress_errors( true );

		try {
			foreach ( array( 'wfconfig', 'wfConfig' ) as $table ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- another plugin's own settings table, read for one switch and never written.
				$value = $wpdb->get_var( $wpdb->prepare( 'SELECT val FROM %i WHERE name = %s', $wpdb->base_prefix . $table, $name ) );

				if ( null !== $value ) {
					return '' !== $value && '0' !== $value;
				}
			}
		} finally {
			$wpdb->suppress_errors( $quiet );
		}

		return $default;
	}

	private static function jetpack_protects(): bool {
		$modules = get_option( 'jetpack_active_modules', array() );
		$on      = ( is_array( $modules ) && in_array( 'protect', $modules, true ) ) || ( is_multisite() && get_site_option( 'jetpack_protect_active' ) );

		// It guards sign-ins only while the site is connected; disconnected,
		// the module stays listed and does nothing.
		$options = get_option( 'jetpack_options', array() );

		return $on && is_array( $options ) && ! empty( $options['id'] );
	}

	/**
	 * Whether WP Hide's two-factor asks anybody: its master switch on and at
	 * least one role named. Either kind, app or email, is read from its own
	 * switch in SWITCHED_JOBS.
	 */
	private static function wph_two_factor_on(): bool {
		return array() !== self::wph_two_factor_roles();
	}

	/**
	 * The roles WP Hide asks for a code, while its master switch is on.
	 *
	 * @return string[]
	 */
	private static function wph_two_factor_roles(): array {
		$settings = self::wph_settings();

		if ( 'yes' !== ( $settings['2fa_enabled'] ?? '' ) ) {
			return array();
		}

		return array_values( array_diff( (array) ( $settings['2fa_enable_for_roles'] ?? array() ), array( '', '--none--' ) ) );
	}

	/**
	 * WP Hide's emailed codes need no setup: every account in its roles is
	 * asked for one. The roles, while they are on; none otherwise.
	 *
	 * @return string[]
	 */
	private static function wph_email_roles(): array {
		return 'yes' === ( self::wph_settings()['2fa_email'] ?? '' ) ? self::wph_two_factor_roles() : array();
	}

	/**
	 * WP Hide's module settings.
	 *
	 * @return array<string, mixed>
	 */
	private static function wph_settings(): array {
		$saved = get_option( 'wph_settings', array() );

		return is_array( $saved ) && is_array( $saved['module_settings'] ?? null ) ? $saved['module_settings'] : array();
	}

	/**
	 * Another plugin's option, read where that plugin keeps it: a few keep
	 * one copy for a whole network on its main site.
	 *
	 * @param mixed $fallback The value when there is none.
	 * @return mixed
	 */
	private static function plugin_option( string $option, $fallback ) {
		if ( 'hmwp_options' === $option && is_multisite() ) {
			return get_blog_option( defined( 'BLOG_ID_CURRENT_SITE' ) ? (int) BLOG_ID_CURRENT_SITE : get_main_site_id(), $option, $fallback );
		}

		return get_option( $option, $fallback );
	}

	/**
	 * Whether Defender's Mask Login is on. It keeps that switch network-wide,
	 * so its sign-in address counts only while it is.
	 */
	private static function defender_masks_login(): bool {
		$saved = json_decode( (string) get_site_option( 'wd_masking_login_settings', '' ), true );

		return is_array( $saved ) && ! empty( $saved['enabled'] );
	}

	/**
	 * Whether the firewall that keeps its Login Protection switch in a file
	 * of its own, under its log folder, has it on. `bf_enable` 1 guards the
	 * sign-in form while it is under attack and 2 always; 0, or no file at
	 * all, which is how it starts out, guards nothing. A version before 4.9.1
	 * kept the same switch in an older file, in another notation.
	 *
	 * Only that one value is looked for, near the start of the file: it is
	 * read as text and never unserialized.
	 */
	private static function login_protection_file_on(): bool {
		$dir = ( defined( 'NFW_LOG_DIR' ) ? (string) constant( 'NFW_LOG_DIR' ) : WP_CONTENT_DIR ) . '/nfwlog/cache/';

		foreach ( array( 'login_protection.php', 'bf_conf.php' ) as $name ) {
			if ( ! is_file( $dir . $name ) ) {
				continue;
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- another plugin's settings file, read for one switch.
			$config = (string) @file_get_contents( $dir . $name, false, null, 0, 4096 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a file that cannot be read is a switch that cannot be seen to be on.

			return 1 === preg_match( '/bf_enable(?:";i:|";s:1:"|=)[12]\b/', $config );
		}

		return false;
	}

	/**
	 * Whether BlogVault's firewall has been put in place. Its service writes
	 * these once the firewall is set up; the plugin ships neither.
	 */
	private static function blogvault_firewall_installed(): bool {
		return is_file( ABSPATH . 'malcare-waf.php' ) || is_dir( WP_CONTENT_DIR . '/mc_data' );
	}

	public static function applies(): bool {
		return array() !== self::active();
	}

	/**
	 * The names of the plugins doing one job, in the order they were found.
	 *
	 * @param array<string, array{name: string, jobs: string[]}> $active
	 * @return string[]
	 */
	private static function names_for( string $job, array $active ): array {
		$names = array();

		foreach ( $active as $plugin ) {
			if ( in_array( $job, $plugin['jobs'], true ) && ! in_array( $plugin['name'], $names, true ) ) {
				$names[] = $plugin['name'];
			}
		}

		return $names;
	}

	/**
	 * The names of the active plugins doing one job, or none.
	 *
	 * Asked again whenever it matters, never remembered from the setup: a
	 * job handed to another plugin there is still BetterShield's to cover once
	 * that plugin is deactivated or deleted.
	 *
	 * @return string[]
	 */
	public static function doing( string $job ): array {
		return self::names_for( $job, self::active() );
	}

	/**
	 * The sign-in address an active plugin moved the page to, where it keeps
	 * that where it can be read, for a way back in that names one that answers.
	 *
	 * @return string[]
	 */
	public static function moved_sign_in_addresses(): array {
		return array_values( array_unique( self::moved_sign_in_by_file( self::active() ) ) );
	}

	/**
	 * The same addresses by the file of the plugin that moved the page, for
	 * the step to name the one that stops working when it is switched off.
	 *
	 * @param array<string, array{name: string, jobs: string[]}> $active
	 * @return array<string, string> Plugin file => full address.
	 */
	private static function moved_sign_in_by_file( array $active ): array {
		/*
		 * Each by its option, the path of keys within it, the address it
		 * uses while none is saved, and whether that address is under the
		 * home address or WordPress's own (one installed in a folder).
		 */
		$readable = array(
			'wps-hide-login/wps-hide-login.php'               => array( 'whl_page', array(), 'login', 'home' ),
			'rename-wp-login/rename-wp-login.php'             => array( 'rwl_page', array(), '', 'home' ),
			'change-wp-admin-login/change-wp-admin-login.php' => array( 'rwl_page', array(), 'login', 'home' ),
			'wp-hide-security-enhancer/wp-hide.php'           => array( 'wph_settings', array( 'module_settings', 'new_wp_login_php' ), '', 'home' ),
			'sg-security/sg-security.php'                     => array( 'sg_security_login_url', array(), 'login', 'home' ),
			'hide-my-wp/index.php'                            => array( 'hmwp_options', array( 'hmwp_login_url' ), '', 'site' ),
		);
		$out      = array();

		foreach ( $readable as $file => $where ) {
			// Only while it is moving the address, which active() has read.
			if ( ! in_array( 'login_url', $active[ $file ]['jobs'] ?? array(), true ) ) {
				continue;
			}

			$value = self::plugin_option( $where[0], '' );

			// Network-activated, these read the network's address: one only, the other while the site has none.
			if ( 'change-wp-admin-login/change-wp-admin-login.php' === $file && is_multisite() && is_plugin_active_for_network( $file ) ) {
				$value = get_site_option( 'rwl_page', '' );
			}

			if ( 'wps-hide-login/wps-hide-login.php' === $file && '' === $value && is_multisite() && is_plugin_active_for_network( $file ) ) {
				$value = get_site_option( 'whl_page', '' );
			}

			if ( array() !== $where[1] && is_string( $value ) ) {
				$value = json_decode( $value, true );
			}

			foreach ( $where[1] as $key ) {
				$value = is_array( $value ) ? ( $value[ $key ] ?? '' ) : '';
			}

			$slug = is_string( $value ) ? trim( $value, '/ ' ) : '';
			$slug = '' !== $slug ? $slug : $where[2];

			if ( '' !== $slug && 'wp-login.php' !== $slug ) {
				$out[ $file ] = user_trailingslashit( ( 'site' === $where[3] ? site_url( '/' . $slug ) : home_url( '/' . $slug ) ) );
			}
		}

		return $out;
	}

	/**
	 * The path of WordPress's own sign-in page, where it is once no plugin
	 * moves it: under the folder WordPress is installed in, e.g.
	 * /blog/wp-login.php. Read from the saved address, not wp_login_url(),
	 * which a plugin moving the page filters to its own.
	 */
	public static function default_sign_in_path(): string {
		$path = (string) wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_PATH );

		return rtrim( $path, '/' ) . '/wp-login.php';
	}

	/**
	 * The path of a full address, e.g. /secret-door/, or '' for none.
	 */
	private static function path_of( string $url ): string {
		if ( '' === $url ) {
			return '';
		}

		$path = (string) wp_parse_url( $url, PHP_URL_PATH );

		return '' !== $path ? $path : '/';
	}

	/**
	 * The files of the active plugins limiting sign-in attempts, sorted:
	 * which plugins a choice for that job was made over, saved beside it.
	 *
	 * @return string[]
	 */
	public static function limiter_files(): array {
		$files = array();

		foreach ( self::active() as $file => $plugin ) {
			if ( in_array( 'login_limits', $plugin['jobs'], true ) ) {
				$files[] = (string) $file;
			}
		}

		sort( $files );

		return $files;
	}

	/**
	 * The names of the active plugins limiting sign-in attempts that no
	 * saved choice keeps beside this plugin's own limit.
	 *
	 * Choosing BetterShield for the job while another limiter is active is
	 * the owner keeping both: the setup turns this plugin's limit on and
	 * says where the other one is switched off by hand. That choice covers
	 * the plugins that were limiting sign-ins when it was saved and no
	 * others, so one activated since is still news. Nothing saved, or the
	 * job kept with the other plugin while this one's limit runs anyway,
	 * covers none of them.
	 *
	 * A choice saved before the plugins it was made over were stored with
	 * it covers whichever are active now: it was made, and over which of
	 * them can no longer be told.
	 *
	 * @param array<string, string> $saved   Job => choice, as last saved.
	 * @param string[]|null         $covered The files limiting sign-ins when it was saved; null when not stored.
	 * @return string[]
	 */
	public static function limiters_not_chosen( array $saved, ?array $covered ): array {
		$active = self::active();

		if ( 'bettershield' === ( $saved['login_limits'] ?? '' ) ) {
			$active = null === $covered ? array() : array_diff_key( $active, array_flip( $covered ) );
		}

		return self::names_for( 'login_limits', $active );
	}

	/**
	 * One row per job the site has two plugins for, with the saved choice or
	 * the default where there is none.
	 *
	 * @param array<string, string> $saved Job => choice, as last saved.
	 * @return array<int, array<string, mixed>>
	 */
	public static function rows( array $saved = array() ): array {
		$active = self::active();
		$moved  = self::moved_sign_in_by_file( $active );
		$rows   = array();

		foreach ( array_merge( self::CHOICE_JOBS, self::INFO_JOBS ) as $job ) {
			$names = self::names_for( $job, $active );

			if ( array() === $names ) {
				continue;
			}

			$choice = in_array( $job, self::CHOICE_JOBS, true ) ? self::choice_of( $job, $saved ) : '';

			$rows[] = array(
				'job'        => $job,
				'kind'       => '' === $choice ? 'info' : 'choice',
				'plugins'    => $names,
				// Each plugin by its file, for the setup's own Deactivate.
				'deactivate' => self::switchable( $job, $active, $moved ),
				'choice'     => $choice,
				'options'    => self::options_for( $job ),
				// Turned on here before that plugin came, or before this was refused.
				'ours_on'    => in_array( $job, array( 'login_url', 'https_redirect' ), true ) && \BetterShield\Hardening\Manager::instance()->is_active( $job ),
				// On at the very address that plugin answers at, as an import leaves it: both work there.
				'ours_shared' => 'login_url' === $job && \BetterShield\Hardening\Item\LoginUrl::shares_its_address(),
				// Whether choosing BetterShield keeps the address people use, for the card to say so.
				'address_carried' => 'login_url' === $job && self::address_comes_over(),
			);
		}

		return $rows;
	}

	/**
	 * The active plugins doing one job, each with why the person asking may
	 * not switch it off from the setup, or '' when they may, every job it
	 * does here, and the link to WordPress's own Deactivate for it, or ''
	 * where they may not use it: switching it off stops all of its jobs, not
	 * only this one, so the step offers it only once each is handed to
	 * BetterShield. Also WordPress's own Deactivate as the Plugins screen has
	 * it, for the step to open in a new tab where it would otherwise only
	 * point to that screen, or '' where the person asking may not use it.
	 *
	 * Also, for one that moved the sign-in page, the path it moved it to,
	 * which stops working once it is off, or '' where that is not known.
	 *
	 * @param array<string, array{name: string, jobs: string[]}> $active
	 * @param array<string, string>                               $moved Plugin file => the sign-in address it moved the page to.
	 * @return array<int, array{file: string, name: string, why: string, jobs: string[], link: string, deactivate_url: string, activate_url: string, sign_in_path: string}>
	 */
	private static function switchable( string $job, array $active, array $moved = array() ): array {
		$plugins = array();

		foreach ( $active as $file => $plugin ) {
			if ( in_array( $job, $plugin['jobs'], true ) ) {
				$plugins[] = array(
					'file'           => (string) $file,
					'name'           => (string) $plugin['name'],
					'why'            => self::why_not_deactivate( (string) $file ),
					'jobs'           => array_values( $plugin['jobs'] ),
					'link'           => self::offers_link( $plugin['jobs'] ) ? self::deactivate_link( (string) $file ) : '',
					'deactivate_url' => self::deactivate_url( (string) $file ),
					// For the step's Turn It Back On, once it is off.
					'activate_url'   => self::activate_url( (string) $file ),
					'sign_in_path'   => self::path_of( $moved[ (string) $file ] ?? '' ),
				);
			}
		}

		return $plugins;
	}

	/**
	 * Whether a plugin doing these jobs may be offered the in-place link:
	 * only when every one of them is a job the step can hand to BetterShield.
	 * One that also runs a firewall, or another job with no choice here,
	 * would lose it on that press, so it keeps the Plugins-screen pointer and
	 * its warning instead (#2113).
	 *
	 * @param string[] $jobs The plugin's jobs.
	 */
	private static function offers_link( array $jobs ): bool {
		return array() === array_diff( $jobs, self::CHOICE_JOBS );
	}

	/**
	 * Whether the setup may switch another plugin off at the owner's press.
	 *
	 * Off by default (#2107): wordpress.org's guidelines say a plugin may
	 * not change the activation status of other plugins, and whether an
	 * owner's own press counts is a question the plugins team has not yet
	 * answered. Until it does, the step points to the Plugins screen. A site that
	 * turns the filter on gets the in-place Deactivate, which the owner
	 * still confirms by name. Agents never use this.
	 */
	public static function deactivation_enabled(): bool {
		return (bool) apply_filters( 'bettershield_setup_deactivation_enabled', false );
	}

	/**
	 * Why the person asking may not switch a plugin off here: `network` for
	 * one switched on for the whole network, which only the network's Plugins
	 * screen switches off, whatever else is true; `off` where the site has
	 * turned the setup's deactivation off; `capability` for an account that
	 * may not deactivate it; '' when they may.
	 */
	public static function why_not_deactivate( string $file ): string {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( is_multisite() && is_plugin_active_for_network( $file ) ) {
			return 'network';
		}

		if ( ! self::deactivation_enabled() ) {
			return 'off';
		}

		return current_user_can( 'deactivate_plugin', $file ) ? '' : 'capability';
	}

	/**
	 * The link to WordPress's own Deactivate for a plugin, as its row on the
	 * Plugins screen has it, or '' where the person asking may not use it:
	 * one switched on for the whole network, which only the network's
	 * Plugins screen switches off, or one their account may not deactivate.
	 *
	 * Following it is the owner switching the plugin off, not this plugin:
	 * WordPress checks the nonce and the capability and does the rest, as it
	 * does for the Plugins screen.
	 */
	public static function deactivate_url( string $file ): string {
		if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( ( is_multisite() && is_plugin_active_for_network( $file ) ) || ! current_user_can( 'deactivate_plugin', $file ) ) {
			return '';
		}

		// Raw, not wp_nonce_url(): that escapes `&` for HTML, and the page
		// follows this as a URL, so `&amp;` cost WordPress the nonce (403).
		return add_query_arg(
			array(
				'action'   => 'deactivate',
				'plugin'   => rawurlencode( $file ),
				'_wpnonce' => wp_create_nonce( 'deactivate-plugin_' . $file ),
			),
			admin_url( 'plugins.php' )
		);
	}

	/**
	 * WordPress's own Activate for a plugin the step switched off, marked as
	 * the setup's, for its Turn It Back On; '' where the person asking may
	 * not use it. Like Deactivate, WordPress checks the nonce and the
	 * capability and does the rest.
	 */
	public static function activate_url( string $file ): string {
		if ( ! current_user_can( 'activate_plugin', $file ) ) {
			return '';
		}

		return add_query_arg(
			array(
				'action'             => 'activate',
				'plugin'             => rawurlencode( $file ),
				'_wpnonce'           => wp_create_nonce( 'activate-plugin_' . $file ),
				'bettershield_setup' => '1',
			),
			admin_url( 'plugins.php' )
		);
	}

	/**
	 * The same link, for the step to follow in place: the marker on it only
	 * brings the owner back to the setup afterwards.
	 */
	public static function deactivate_link( string $file ): string {
		$url = self::deactivate_url( $file );

		return '' === $url ? '' : add_query_arg( 'bettershield_setup', '1', $url );
	}

	/**
	 * On the Plugins screen, when the owner followed the setup's link to
	 * switch one of the plugins it found off: once WordPress has switched it
	 * off, back to the setup, with the plugin noted for Ready to name. The
	 * step follows the link in place and reads the setup again itself; a
	 * plugin it turns back on the same way is no longer named.
	 *
	 * Only the redirect after a deactivation WordPress made is changed, and
	 * only for a plugin this class names. Anything else, a refused nonce
	 * among them, goes where WordPress sends it.
	 */
	public static function watch_deactivate_link(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- WordPress checks this request's nonce itself before it deactivates anything; this only reads where to send the owner after.
		$action = sanitize_key( (string) ( $_GET['action'] ?? '' ) );

		if ( empty( $_GET['bettershield_setup'] ) || ! in_array( $action, array( 'deactivate', 'activate' ), true ) || ! isset( $_GET['plugin'] ) ) {
			return;
		}

		$file = sanitize_text_field( wp_unslash( (string) $_GET['plugin'] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// Turned back on from the step: Ready no longer names it as switched off.
		if ( 'activate' === $action ) {
			add_filter(
				'wp_redirect',
				static function ( $location ) use ( $file ) {
					if ( is_string( $location ) && false !== strpos( $location, 'activate=true' ) && is_plugin_active( $file ) ) {
						QuickSetup::forget_deactivated( $file );

						// It does two-factor again, so its accounts go back to it.
						if ( in_array( 'two_factor', self::known()[ $file ] ?? array(), true ) ) {
							QuickSetup::keep_two_factor_elsewhere();
							\BetterShield\TwoFactor\Import::take_back( $file );
						}

						// It limits sign-ins again, beside this plugin's own limit.
						if ( in_array( 'login_limits', self::active()[ $file ]['jobs'] ?? array(), true ) ) {
							QuickSetup::keep_login_limits_elsewhere();
						}
					}

					return $location;
				}
			);

			return;
		}

		$active = self::active();

		if ( ! isset( $active[ $file ] ) ) {
			return;
		}

		$name = $active[ $file ]['name'];

		add_filter(
			'wp_redirect',
			static function ( $location ) use ( $file, $name ) {
				if ( ! is_string( $location ) || false === strpos( $location, 'deactivate=true' ) || is_plugin_active( $file ) ) {
					return $location;
				}

				QuickSetup::note_deactivated( $file, $name );
				\BetterShield\Integrity\FirstScan::again();

				return QuickSetup::url();
			}
		);
	}

	/**
	 * The settings each active plugin left here that the step can bring
	 * over now, as the import would: what carries over, by name, and what
	 * does not, with why. A plugin with nothing to carry is left out.
	 *
	 * The way back in is set up later in the setup, so until it is proved, a
	 * setting that changes how people sign in is held back here and said
	 * so: the import refuses it, as the same change made on its own screen
	 * waits. Settings › General brings it over afterwards.
	 *
	 * @return array<int, array{key: string, name: string, carried: string[], waits: array<string, string>, left: array<int, array{setting: string, reason: string}>, limits: array{rank: int, waits: string, drops: string[]}|null}>
	 */
	public static function imports(): array {
		/*
		 * What each source would carry under either login-limits answer.
		 * The card follows the answer on screen, and Save applies the new
		 * answer before it imports, so a row that only one answer carries is
		 * marked with the job it waits on, for the card to show and count
		 * only while that answer is chosen (#2498).
		 */
		$kept  = self::carried_by_source( false );
		$given = self::carried_by_source( true );
		$out   = array();

		// Strictest first, as `import()` picks among the plugins it brings.
		$rank = array_flip( self::by_strictness( array_values( $given ) ) );

		foreach ( $given as $key => $source ) {
			$without = $kept[ $key ]['carried'] ?? array();
			$waits   = array_values( array_diff( $source['carried'], $without ) );

			$out[] = array(
				'key'     => $source['key'],
				'name'    => $source['name'],
				'carried' => $source['carried'],
				// Carried only while sign-in limits, or the address, are given to BetterShield.
				'waits'   => array_fill_keys( $waits, 'login_limits' ) + array_fill_keys( array_values( array_intersect( $source['carried'], self::address_titles() ) ), 'login_url' ),
				'left'    => $kept[ $key ]['left'] ?? $source['left'],
				/*
				 * Its attempt-limit numbers, where it brings any: their place
				 * among the others' (0 is the strictest, the one kept when
				 * several come over), whether they wait on the login-limits
				 * answer, and the rows that go with them when another
				 * plugin's are kept instead.
				 */
				'limits'  => isset( $rank[ $key ] ) ? array(
					'rank'  => $rank[ $key ],
					'waits' => null === ( $kept[ $key ]['limits'] ?? null ) ? 'login_limits' : '',
					'drops' => array_values( array_diff( $source['carried'], $source['without'] ) ),
				) : null,
			);
		}

		return $out;
	}

	/**
	 * What does not come over from each active plugin, whether or not
	 * anything else does: it stops working once that plugin is switched off,
	 * so the step says so before it is.
	 *
	 * Like `imports()`, it follows the login-limits answer on screen, saved or
	 * not: a row left out only while another plugin keeps that job is marked
	 * with the job, for the card to show only while that answer is not Use
	 * BetterShield. Read from the saved answer alone, a first visit listed the
	 * sign-in numbers as staying behind while Save was about to bring them
	 * over (#2839).
	 *
	 * @return array<int, array{name: string, left: array<int, array{setting: string, reason: string, unless?: string}>}>
	 */
	public static function not_carried(): array {
		$kept  = self::left_by_source( false );
		$given = self::left_by_source( true );
		$out   = array();

		foreach ( $kept as $key => $source ) {
			$both = array_column( $given[ $key ]['left'] ?? array(), 'setting' );
			$left = array_map(
				static fn( array $row ): array => in_array( $row['setting'], $both, true ) ? $row : $row + array( 'unless' => 'login_limits' ),
				$source['left']
			);

			$out[] = array(
				'name' => $source['name'],
				'left' => $left,
			);
		}

		return $out;
	}

	/**
	 * What does not come over from each active plugin, under one
	 * login-limits answer. A plugin that leaves nothing behind is left out.
	 *
	 * @return array<string, array{name: string, left: array<int, array{setting: string, reason: string}>}>
	 */
	private static function left_by_source( bool $limits_given ): array {
		$was                    = Migrate::$limits_given;
		Migrate::$limits_given = $limits_given;

		try {
			$held    = array_column( self::import_sources(), 'held', 'key' );
			$sources = Migrate::sources();
		} finally {
			Migrate::$limits_given = $was;
		}

		$out = array();

		foreach ( $sources as $source ) {
			$left = array_merge( $held[ $source['key'] ] ?? array(), $source['unmapped'] );

			if ( $source['active'] && array() !== $left ) {
				$out[ (string) $source['key'] ] = array(
					'name' => (string) $source['name'],
					'left' => $left,
				);
			}
		}

		return $out;
	}

	/**
	 * Each source that carries anything, with what it carries, under one
	 * login-limits answer.
	 *
	 * @return array<string, array{key: string, name: string, carried: string[], left: array<int, array{setting: string, reason: string}>, document: array<string, mixed>, limits: array<string, int>|null, without: string[]}>
	 */
	private static function carried_by_source( bool $limits_given ): array {
		$was                    = Migrate::$limits_given;
		Migrate::$limits_given = $limits_given;

		try {
			$sources = self::import_sources();
		} finally {
			Migrate::$limits_given = $was;
		}

		$out = array();

		foreach ( $sources as $source ) {
			$carried = self::carried_titles( $source['document'] );

			if ( null === $carried || array() === $carried ) {
				continue;
			}

			$limits = self::limits_of( $source['document'] );

			$out[ $source['key'] ] = array(
				'key'      => $source['key'],
				'name'     => $source['name'],
				'carried'  => $carried,
				'left'     => array_merge( $source['held'], $source['unmapped'] ),
				'document' => $source['document'],
				'limits'   => $limits,
				// What it still carries when another plugin's numbers are kept.
				'without'  => null === $limits ? $carried : (array) self::carried_titles( self::without_limits( $source['document'] ) ),
			);
		}

		return $out;
	}

	/**
	 * The titles of what a document would change here, as the import's
	 * preview names them, or null where it cannot be planned.
	 *
	 * @param array<string, mixed> $document
	 * @return string[]|null
	 */
	private static function carried_titles( array $document ): ?array {
		$plan = SettingsDocument::plan( $document );

		if ( is_wp_error( $plan ) ) {
			return null;
		}

		$carried = array();

		foreach ( array_merge( $plan['hardening'], $plan['settings'] ) as $row ) {
			if ( in_array( $row['action'], array( 'apply', 'reconfigure', 'change' ), true ) ) {
				$carried[] = (string) $row['title'];
			}
		}

		return $carried;
	}

	/**
	 * A document's attempt-limit numbers, or null where it carries none.
	 *
	 * @param array<string, mixed> $document
	 * @return array{threshold: int, window_minutes: int, lockout_minutes: int}|null
	 */
	private static function limits_of( array $document ): ?array {
		$login = (array) ( $document['login_protection'] ?? array() );

		if ( ! isset( $login['threshold'], $login['window_minutes'], $login['lockout_minutes'] ) ) {
			return null;
		}

		return array(
			'threshold'       => (int) $login['threshold'],
			'window_minutes'  => (int) $login['window_minutes'],
			'lockout_minutes' => (int) $login['lockout_minutes'],
		);
	}

	/**
	 * A document without its attempt-limit numbers, keeping its lists.
	 *
	 * @param array<string, mixed> $document
	 * @return array<string, mixed>
	 */
	private static function without_limits( array $document ): array {
		if ( ! isset( $document['login_protection'] ) || ! is_array( $document['login_protection'] ) ) {
			return $document;
		}

		$login = array_diff_key( $document['login_protection'], array_flip( self::LIMIT_KEYS ) );

		if ( array() === $login ) {
			unset( $document['login_protection'] );
		} else {
			$document['login_protection'] = $login;
		}

		return $document;
	}

	/**
	 * The sources that bring attempt-limit numbers, by key, strictest
	 * first.
	 *
	 * BetterShield keeps one set of numbers, so where several plugins bring
	 * theirs, one whole set is kept, never a mix: the screen can then say
	 * plainly whose. The strictest is kept, so moving over never loosens
	 * the limit: the fewest attempts, then the longest lockout, then the
	 * longest window; on a full tie, the plugin listed first.
	 *
	 * @param array<int, array{key: string, document: array<string, mixed>}> $sources In the order the import reads them.
	 * @return string[]
	 */
	private static function by_strictness( array $sources ): array {
		$found = array();

		foreach ( array_values( $sources ) as $at => $source ) {
			$limits = self::limits_of( $source['document'] );

			if ( null !== $limits ) {
				$found[] = array(
					'key'   => (string) $source['key'],
					'order' => array( $limits['threshold'], -$limits['lockout_minutes'], -$limits['window_minutes'], $at ),
				);
			}
		}

		usort( $found, static fn( array $a, array $b ): int => $a['order'] <=> $b['order'] );

		return array_column( $found, 'key' );
	}

	/**
	 * Bring over the settings `imports()` offers, from the plugins the owner
	 * left ticked, through the import's own apply: every change keeps its
	 * own undo, as an imported file's does.
	 *
	 * Lists from several plugins all join this site's, and of their
	 * attempt-limit numbers one set is kept, as `imports()` ranks them; the
	 * others' numbers are left out of what each brings and counts.
	 *
	 * @param string[] $keys The sources to bring over, by key.
	 * @return array<int, array{name: string, count: int}>|\WP_Error What each brought over, where it brought anything.
	 */
	public static function import( array $keys ) {
		$done   = array();
		$picked = array_values( array_filter( self::import_sources(), static fn( array $source ): bool => in_array( $source['key'], $keys, true ) ) );

		// One set of attempt-limit numbers is kept: the strictest (see by_strictness()).
		$limits = self::by_strictness( $picked )[0] ?? null;

		foreach ( array_column( $picked, 'key' ) as $key ) {
			/*
			 * Read again before each: a source's lists are this site's lists
			 * with its own entries added. Read once for all, each held the
			 * lists as they stood before any was applied, and the last one
			 * applied replaced the others' entries.
			 */
			$source = current( array_filter( self::import_sources(), static fn( array $source ): bool => $key === $source['key'] ) );

			if ( false === $source ) {
				continue;
			}

			$document = null !== $limits && $limits !== $key ? self::without_limits( $source['document'] ) : $source['document'];

			// Saved before this runs: kept with the other plugin, the address stays there.
			if ( 'bettershield' !== self::choice_of( 'login_url', QuickSetup::state()['coexistence'] ) ) {
				$document = self::without_address( $document );
			}
			$result   = SettingsDocument::apply( $document, false, 'dashboard' );

			if ( is_wp_error( $result ) ) {
				return $result;
			}

			$count = (int) ( $result['counts']['applied'] ?? 0 ) + (int) ( $result['counts']['settings'] ?? 0 );

			if ( $count > 0 ) {
				$done[] = array(
					'name'  => $source['name'],
					'count' => $count,
				);
			}
		}

		return $done;
	}

	/**
	 * The import's sources from plugins active here with something to bring,
	 * each with the settings that wait for the way back in taken out of its
	 * document and listed apart.
	 *
	 * @return array<int, array{key: string, name: string, document: array<string, mixed>, held: array<int, array{setting: string, reason: string}>, unmapped: array<int, array{setting: string, reason: string}>}>
	 */
	private static function import_sources(): array {
		$waiting = null !== Preflight::failure();
		$titles  = Items::all();
		$out     = array();

		foreach ( Migrate::sources() as $source ) {
			if ( ! $source['active'] || $source['mapped'] < 1 ) {
				continue;
			}

			$document = $source['document'];
			$held     = array();

			foreach ( $waiting ? array_keys( (array) ( $document['hardening'] ?? array() ) ) : array() as $item ) {
				if ( Permissions::needs_way_back( (string) $item ) ) {
					unset( $document['hardening'][ $item ] );
					$held[] = array(
						'setting' => (string) ( $titles[ $item ]['title'] ?? $item ),
						'reason'  => __( 'This changes how people sign in, so it waits until your way back in is set up. Bring it over from Settings › General after setup.', 'bettershield' ),
					);
				}
			}

			$out[] = array(
				'key'      => (string) $source['key'],
				'name'     => (string) $source['name'],
				'document' => $document,
				'held'     => $held,
				'unmapped' => $source['unmapped'],
			);
		}

		return $out;
	}

	/**
	 * Switch off another security plugin the setup found doing a job, when
	 * the owner presses Deactivate for it there.
	 *
	 * Only a plugin `active()` names, so the route cannot switch off anything
	 * else, and only as the Plugins screen would: through core's own
	 * deactivation, which runs the plugin's deactivation routine and keeps
	 * its settings, and which the activity log records as any deactivation.
	 *
	 * And only once every job it does here is BetterShield's in the choices
	 * on screen (or, without them, the saved ones): switching it off stops
	 * all of them at once, so one handed over must not take the others with
	 * it, and a job BetterShield has no answer for (a firewall, say) is never
	 * handed over (#2113).
	 *
	 * @param array<string, string>|null $choices Job => choice, as on screen; null for the saved ones.
	 * @return true|\WP_Error
	 */
	public static function deactivate( string $file, ?array $choices = null ) {
		$active = self::active();

		if ( ! isset( $active[ $file ] ) ) {
			return new \WP_Error(
				'bettershield_not_coexisting',
				__( 'That plugin is not one Quick Setup found doing a security job here, so it was left as it is.', 'bettershield' ),
				array( 'status' => 404 )
			);
		}

		$name = $active[ $file ]['name'];
		$why  = self::why_not_deactivate( $file );
		$kept = self::kept_for( $active[ $file ]['jobs'], null === $choices ? QuickSetup::state()['coexistence'] : self::clean( $choices ) );

		// Off, as it is by default: another plugin's activation is the
		// owner's to change on the Plugins screen.
		if ( 'off' === $why ) {
			return new \WP_Error(
				'bettershield_deactivation_off',
				/* translators: %s: a plugin's name. */
				sprintf( __( 'BetterShield does not switch other plugins off. Deactivate %s from the Plugins screen.', 'bettershield' ), $name ),
				array( 'status' => 403 )
			);
		}

		if ( array() !== $kept ) {
			$labels = self::job_labels();

			return new \WP_Error(
				'bettershield_plugin_kept',
				sprintf(
					/* translators: 1: a plugin's name, 2: one or more of its jobs. */
					__( '%1$s also handles %2$s here, so it was left on.', 'bettershield' ),
					$name,
					wp_sprintf( '%l', array_map( static fn( string $job ): string => $labels[ $job ] ?? $job, $kept ) )
				),
				array( 'status' => 409 )
			);
		}

		if ( 'network' === $why ) {
			return new \WP_Error(
				'bettershield_network_plugin',
				/* translators: %s: a plugin's name. */
				sprintf( __( '%s is switched on for the whole network, so a network administrator switches it off from the network’s Plugins screen.', 'bettershield' ), $name ),
				array( 'status' => 409 )
			);
		}

		if ( 'capability' === $why ) {
			return new \WP_Error(
				'bettershield_cannot_deactivate',
				/* translators: %s: a plugin's name. */
				sprintf( __( 'Your account cannot deactivate %s on this site.', 'bettershield' ), $name ),
				array( 'status' => 403 )
			);
		}

		/*
		 * Two-factor first: switched off with its accounts still on their
		 * own, every one of them would sign in with a password alone. Core's
		 * deactivation would bring them over too, but this route can still
		 * refuse, so a copy that fails leaves the plugin on.
		 */
		$copied = false;

		if ( \BetterShield\TwoFactor\Import::reads( $file ) && \BetterShield\TwoFactor\Import::chosen() ) {
			$carried = \BetterShield\TwoFactor\Import::carry( $file );

			if ( is_wp_error( $carried ) ) {
				return $carried;
			}

			$copied = true;
		}

		/*
		 * Copied just now, so core's own deactivation hook is held off for
		 * this one call: run again, it recorded the accounts that could not
		 * move, and the summary, a second time.
		 */
		$hook = array( \BetterShield\TwoFactor\Import::class, 'on_deactivate' );

		if ( $copied ) {
			remove_action( 'deactivate_plugin', $hook, 5 );
		}

		try {
			deactivate_plugins( $file );
		} finally {
			if ( $copied ) {
				add_action( 'deactivate_plugin', $hook, 5, 1 );
			}
		}

		if ( is_plugin_active( $file ) ) {
			return new \WP_Error(
				'bettershield_still_active',
				/* translators: %s: a plugin's name. */
				sprintf( __( '%s is still switched on: something on this site turned it back on. Deactivate it from the Plugins screen.', 'bettershield' ), $name ),
				array( 'status' => 500 )
			);
		}

		/*
		 * The last plugin limiting sign-in attempts is gone, so this plugin's
		 * own limit is the only one left to do it. Kept off by an earlier
		 * "keep the other plugin", it would leave sign-in unlimited, which
		 * the setup's own sentence promised would not happen.
		 */
		if ( in_array( 'login_limits', $active[ $file ]['jobs'], true ) && array() === self::names_for( 'login_limits', self::active() ) && ! (bool) ( Protection::instance()->settings()['attempt_limit'] ?? true ) ) {
			$result = Protection::instance()->update_settings( array( 'attempt_limit' => true ) );

			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		return true;
	}

	/**
	 * The jobs a plugin does here that are not BetterShield's in the given
	 * choices. A job with no choice (a firewall, the sign-in address, virtual
	 * patching) is never BetterShield's, so it always keeps the plugin.
	 *
	 * @param string[]              $jobs    The plugin's jobs.
	 * @param array<string, string> $choices Job => choice.
	 * @return string[]
	 */
	private static function kept_for( array $jobs, array $choices ): array {
		return array_values( array_filter( $jobs, static fn( string $job ): bool => 'bettershield' !== ( $choices[ $job ] ?? '' ) ) );
	}

	/**
	 * The saved choice for a job, or the default where there is none.
	 *
	 * @param array<string, string> $saved
	 */
	private static function choice_of( string $job, array $saved ): string {
		$choice = $saved[ $job ] ?? '';

		if ( in_array( $choice, self::options_for( $job ), true ) ) {
			return $choice;
		}

		/*
		 * The address is BetterShield's by default only where its import
		 * brings the one people use. Otherwise switching the other plugin
		 * off would put the sign-in page back at WordPress's own address.
		 */
		if ( 'login_url' === $job && ! self::address_comes_over() ) {
			return 'keep';
		}

		return self::options_for( $job )[0];
	}

	/**
	 * Whether an import from an active plugin brings its sign-in address
	 * over now: not held for the way back in, and not refused.
	 */
	private static function address_comes_over(): bool {
		foreach ( self::import_sources() as $source ) {
			if ( isset( $source['document']['hardening']['login_url'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A source's document without the items that come with a sign-in
	 * address, for when another plugin keeps the address.
	 *
	 * @param array<string, mixed> $document
	 * @return array<string, mixed>
	 */
	private static function without_address( array $document ): array {
		foreach ( self::ADDRESS_ITEMS as $item ) {
			unset( $document['hardening'][ $item ] );
		}

		return $document;
	}

	/** @return string[] The titles of the items that come with a sign-in address. */
	private static function address_titles(): array {
		$titles = Items::all();

		return array_map( static fn( string $item ): string => (string) ( $titles[ $item ]['title'] ?? $item ), self::ADDRESS_ITEMS );
	}

	/**
	 * What may be chosen for a job, the default first: BetterShield, since the
	 * step never recommends keeping another plugin.
	 *
	 * Sign-in limits, two-factor and the sign-in address are either-or: two
	 * of any of them is the problem.
	 *
	 * @return string[]
	 */
	public static function options_for( string $job ): array {
		if ( in_array( $job, array( 'login_limits', 'two_factor', 'login_url' ), true ) ) {
			return array( 'bettershield', 'keep' );
		}

		return array();
	}

	/**
	 * Keep only choices that name a real job and one of its options.
	 *
	 * @param mixed $input What the request carried.
	 * @return array<string, string>
	 */
	public static function clean( $input ): array {
		$out = array();

		if ( ! is_array( $input ) ) {
			return $out;
		}

		foreach ( self::CHOICE_JOBS as $job ) {
			$choice = isset( $input[ $job ] ) && is_string( $input[ $job ] ) ? $input[ $job ] : '';

			if ( in_array( $choice, self::options_for( $job ), true ) ) {
				$out[ $job ] = $choice;
			}
		}

		return $out;
	}

	/**
	 * Put the choices into effect on BetterShield's own side.
	 *
	 * Only sign-in limits have a switch of BetterShield's to move: keeping the
	 * other plugin turns BetterShield's attempt limit off, and choosing
	 * BetterShield turns it on, with sign-in protection itself where that was
	 * off too, so the job handed over is one BetterShield does (#1964). The
	 * attempt limit is the limit's own switch, so the blocklists and the
	 * public-form throttles go on working either way. Two-factor has none,
	 * because nobody is enrolled in BetterShield's until they enroll
	 * themselves; the choice decides whether the setup offers that
	 * enrollment.
	 *
	 * The switches are written only when they would change, so saving the
	 * same choices twice records nothing twice.
	 *
	 * @param array<string, string> $choices Cleaned choices, for jobs that apply.
	 * @return true|\WP_Error
	 */
	public static function apply( array $choices ) {
		if ( isset( $choices['login_limits'] ) && array() !== self::names_for( 'login_limits', self::active() ) ) {
			$want     = 'bettershield' === $choices['login_limits'];
			$settings = Protection::instance()->settings();
			$changes  = array();

			if ( $want !== (bool) ( $settings['attempt_limit'] ?? true ) ) {
				$changes['attempt_limit'] = $want;
			}

			if ( $want && ! (bool) ( $settings['enabled'] ?? true ) ) {
				$changes['enabled'] = true;
			}

			if ( array() !== $changes ) {
				$result = Protection::instance()->update_settings( $changes );

				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		return true;
	}

	/**
	 * Which plugin handles two-factor instead of BetterShield, or ''.
	 *
	 * Anything but an explicit choice of BetterShield leaves the other plugin
	 * in charge, including a coexistence step that was skipped: nobody is
	 * moved off what they are already enrolled in without a choice.
	 *
	 * @param array<string, string> $saved
	 */
	public static function two_factor_elsewhere( array $saved ): string {
		$names = self::names_for( 'two_factor', self::active() );

		if ( array() === $names || 'bettershield' === ( $saved['two_factor'] ?? '' ) ) {
			return '';
		}

		return implode( ', ', $names );
	}

	/**
	 * The same answer, for the screens outside the setup, once the owner has
	 * kept the other plugin's two-factor there.
	 *
	 * Keeping it changed only the setup: Protect, the profile panel and the
	 * store's tab went on offering BetterShield's with nothing said, and
	 * whoever enrolled there, or whose role was required there, was asked
	 * for two codes. Said only where the owner chose it: a step skipped or
	 * never run is no answer, and the list credits a plugin with two-factor
	 * without reading whether its own is switched on, so on every profile
	 * and store account it could name a plugin that asks for nothing.
	 */
	public static function two_factor_handled_by(): string {
		$state = QuickSetup::state();

		if ( ! $state['coexistence_saved'] || 'keep' !== ( $state['coexistence']['two_factor'] ?? '' ) ) {
			return '';
		}

		return self::two_factor_elsewhere( $state['coexistence'] );
	}

	/**
	 * The other security plugin that has two-factor set up for this account,
	 * by name, or '' where none has (#2465).
	 *
	 * Such a plugin asks for its own code whenever the account signs in, a
	 * passkey sign-in included: it takes over the sign-in BetterShield
	 * completes and the browser ends signed out. So a passkey cannot sign the
	 * account in here, and is neither offered to it nor counted as the
	 * account's way in. Its check is never worked around: switching it off
	 * is the owner's choice, made in that plugin's own settings.
	 *
	 * Only plugins whose per-account record is known are read. For any other,
	 * the sign-in form says what happened when that plugin steps in.
	 */
	public static function two_factor_for_user( \WP_User $user ): string {
		foreach ( self::active() as $file => $plugin ) {
			if ( in_array( 'two_factor', $plugin['jobs'], true ) && self::two_factor_set_up( (string) $file, (int) $user->ID ) ) {
				return (string) $plugin['name'];
			}
		}

		return '';
	}

	/**
	 * Accounts another security plugin has two-factor set up for, for the
	 * owner: the first such plugin and how many of its accounts a passkey
	 * cannot sign in, or null where there are none.
	 *
	 * @return array{name: string, count: int}|null
	 */
	public static function two_factor_accounts_elsewhere(): ?array {
		foreach ( self::active() as $file => $plugin ) {
			if ( ! in_array( 'two_factor', $plugin['jobs'], true ) ) {
				continue;
			}

			$count = self::two_factor_set_up_count( (string) $file );

			if ( $count > 0 ) {
				return array(
					'name'  => (string) $plugin['name'],
					'count' => $count,
				);
			}
		}

		return null;
	}

	/**
	 * What switching each active two-factor plugin off brings over, for the
	 * card to say before it happens, by plugin file.
	 *
	 * A plugin whose secrets can't be brought over, but whose accounts are
	 * known, moves nobody: each account it has set up must set up two-factor
	 * here again. Only a plugin whose accounts can't be read is left out, so
	 * the card says what happens in general (#2847).
	 *
	 * @return array<int, array{file: string, name: string, moving: int, already: int, staying: int, named: string[]}>
	 */
	public static function two_factor_moves(): array {
		$out = array();

		foreach ( self::active() as $file => $plugin ) {
			if ( ! in_array( 'two_factor', $plugin['jobs'], true ) ) {
				continue;
			}

			if ( \BetterShield\TwoFactor\Import::reads( (string) $file ) ) {
				$preview = \BetterShield\TwoFactor\Import::preview( (string) $file );
			} elseif ( array() !== self::two_factor_record( (string) $file ) ) {
				$preview = self::two_factor_left_behind( (string) $file );
			} else {
				continue;
			}

			$out[] = array(
				'file' => (string) $file,
				'name' => (string) $plugin['name'],
			) + $preview;
		}

		return $out;
	}

	/**
	 * What switching off a plugin whose secrets can't be brought over leaves
	 * behind: every account it has set up, but for those already set up
	 * here, must set up two-factor again. Named as `Import::preview()` names.
	 *
	 * @return array{moving: int, already: int, staying: int, named: string[]}
	 */
	private static function two_factor_left_behind( string $file ): array {
		$ids = self::two_factor_set_up_ids( $file );

		if ( array() !== $ids ) {
			cache_users( $ids );
		}

		$manager = \BetterShield\TwoFactor\Manager::instance();
		$already = 0;
		$staying = 0;
		$named   = array();

		foreach ( $ids as $user_id ) {
			$user = get_userdata( $user_id );

			// A row left behind by an account since deleted.
			if ( ! $user instanceof \WP_User ) {
				continue;
			}

			if ( $manager->enabled( $user_id ) ) {
				++$already;

				continue;
			}

			++$staying;

			if ( count( $named ) < \BetterShield\TwoFactor\Import::NAMED ) {
				$named[] = (string) $user->display_name;
			}
		}

		// Past the accounts walked, the rest are counted as they are, never truncated.
		$total = self::two_factor_set_up_count( $file );

		if ( $total > count( $ids ) ) {
			$staying += $total - count( $ids );
		}

		return array(
			'moving'  => 0,
			'already' => $already,
			'staying' => $staying,
			'named'   => $named,
		);
	}

	/**
	 * The accounts switching off a plugin whose secrets can't be brought
	 * over leaves without two-factor: each it has set up, but for those set
	 * up here already, as `two_factor_left_behind()` names them. Empty for
	 * a plugin whose secrets do come over, which says so itself.
	 *
	 * @return int[]
	 */
	public static function two_factor_left_behind_ids( string $file ): array {
		if ( \BetterShield\TwoFactor\Import::reads( $file ) || array() === self::two_factor_record( $file ) ) {
			return array();
		}

		$ids = self::two_factor_set_up_ids( $file );

		if ( array() !== $ids ) {
			cache_users( $ids );
		}

		$manager = \BetterShield\TwoFactor\Manager::instance();

		return array_values( array_filter( $ids, static fn( int $user_id ): bool => get_userdata( $user_id ) instanceof \WP_User && ! $manager->enabled( $user_id ) ) );
	}

	/** At most this many accounts in a plugin's two-factor roles are walked to name them. */
	private const WALKED = 1000;

	/**
	 * Where each plugin records an account's own two-factor: a user meta
	 * key, or a table of secrets by account.
	 *
	 * @return array{meta?: string|string[], field?: string, on?: string, table?: string}
	 */
	private static function two_factor_record( string $file ): array {
		$records = array(
			'wp-2fa/wp-2fa.php'                                     => array( 'meta' => 'wp_2fa_enabled_methods' ),
			'two-factor/two-factor.php'                             => array( 'meta' => '_two_factor_enabled_providers' ),
			'better-wp-security/better-wp-security.php'             => array( 'meta' => '_two_factor_enabled_providers' ),
			'ithemes-security-pro/ithemes-security-pro.php'         => array( 'meta' => '_two_factor_enabled_providers' ),
			'defender-security/wp-defender.php'                     => array( 'meta' => 'wd_2fa_enabled_providers' ),
			// Turned off, this is kept with a 0.
			'all-in-one-wp-security-and-firewall/wp-security.php'   => array( 'meta' => 'tfa_enable_tfa', 'on' => '1' ),
			'really-simple-ssl/rlrsssl-really-simple-ssl.php'       => array( 'meta' => array( 'rsssl_two_fa_status_totp', 'rsssl_two_fa_status_email' ), 'on' => 'active' ),
			'really-simple-ssl-pro/really-simple-ssl-pro.php'       => array( 'meta' => array( 'rsssl_two_fa_status_totp', 'rsssl_two_fa_status_email' ), 'on' => 'active' ),
			'wordfence/wordfence.php'                               => array( 'table' => 'wfls_2fa_secrets' ),
			'sg-security/sg-security.php'                           => array( 'meta' => 'sg_security_2fa_configured', 'on' => '1' ),
			'wp-hide-security-enhancer/wp-hide.php'                 => array( 'meta' => '_2fa_app_setup_completed', 'on' => 'true' ),
			// Any of its three kinds, each kept only once set up.
			'hide-my-wp/index.php'                                  => array( 'meta' => array( '_hmwp_totp_key', '_hmwp_email_address', '_hmwp_passkeys' ) ),
			'change-wp-admin-login/change-wp-admin-login.php'       => array( 'meta' => 'aio_login_pro__2fa_email_profile_verified', 'on' => '1' ),
			// One array per account; set up once its status says so.
			'miniorange-2-factor-authentication/miniorange_2_factor_settings.php' => array( 'meta' => 'mo2f_user_2fa_data', 'field' => 'mo_2factor_user_registration_status', 'on' => 'MO_2_FACTOR_PLUGIN_SETTINGS' ),
			// Saved for every site at once, so the key carries no prefix.
			'google-authenticator/google-authenticator.php'         => array( 'meta' => 'googleauthenticator_enabled', 'on' => 'enabled' ),
			'wordfence-login-security/wordfence-login-security.php' => array( 'table' => 'wfls_2fa_secrets' ),
		);

		return $records[ $file ] ?? array();
	}

	private static function two_factor_set_up( string $file, int $user_id ): bool {
		$record = self::two_factor_record( $file );

		if ( 'wp-hide-security-enhancer/wp-hide.php' === $file && array() !== self::wph_email_roles() ) {
			$user = get_userdata( $user_id );

			if ( $user && array() !== array_intersect( (array) $user->roles, self::wph_email_roles() ) ) {
				return true;
			}
		}

		foreach ( (array) ( $record['meta'] ?? array() ) as $key ) {
			$value = get_user_meta( $user_id, $key, true );

			// A key inside an array the plugin keeps per account.
			if ( isset( $record['field'] ) ) {
				$value = is_array( $value ) ? ( $value[ $record['field'] ] ?? '' ) : '';
			}

			if ( isset( $record['on'] ) ? $record['on'] === (string) $value : ( is_array( $value ) ? array() !== array_filter( $value ) : '' !== trim( (string) $value ) ) ) {
				return true;
			}
		}

		if ( isset( $record['meta'] ) ) {
			return false;
		}

		if ( isset( $record['table'] ) ) {
			return self::two_factor_rows( $record['table'], $user_id ) > 0;
		}

		/**
		 * Whether another security plugin has two-factor set up for an
		 * account, where BetterShield does not know where it keeps that.
		 *
		 * @param bool   $set_up  False: not known here.
		 * @param string $file    The other plugin's file.
		 * @param int    $user_id The account.
		 */
		return (bool) apply_filters( 'bettershield_two_factor_set_up_elsewhere', false, $file, $user_id );
	}

	/**
	 * How many accounts have a plugin's two-factor set up, once per plugin
	 * until any account's meta changes: `active()` is read often.
	 */
	private static function enrolled_count( string $file ): int {
		static $counts = array();

		$key = $file . ':' . wp_cache_get_last_changed( 'users' ) . ':' . get_current_blog_id();

		if ( ! isset( $counts[ $key ] ) ) {
			$counts[ $key ] = self::two_factor_set_up_count( $file );
		}

		return $counts[ $key ];
	}

	/**
	 * Whether a plugin doing two-factor here can't be asked about each
	 * account, so the job can only be read as its own for the whole site.
	 *
	 * @param array<string, string> $saved Job => choice, as last saved.
	 */
	public static function two_factor_unread_elsewhere( array $saved ): bool {
		if ( 'bettershield' === ( $saved['two_factor'] ?? '' ) ) {
			return false;
		}

		foreach ( self::active() as $file => $plugin ) {
			if ( in_array( 'two_factor', $plugin['jobs'], true ) && array() === self::two_factor_record( (string) $file ) ) {
				return true;
			}
		}

		return false;
	}

	private static function two_factor_set_up_count( string $file ): int {
		global $wpdb;

		$record = self::two_factor_record( $file );

		// Every account in the roles it emails codes to, whether or not it set up the app too.
		if ( 'wp-hide-security-enhancer/wp-hide.php' === $file && array() !== self::wph_email_roles() ) {
			$query = new \WP_User_Query(
				array(
					'role__in'    => self::wph_email_roles(),
					'fields'      => 'ID',
					'number'      => 1,
					'count_total' => true,
				)
			);

			return (int) $query->get_total();
		}

		if ( isset( $record['meta'] ) ) {
			list( $where, $args ) = self::two_factor_meta_where( $record );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- a count of accounts another plugin has two-factor set up for; there is no API for it. Only placeholders are built here.
			return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE {$where}", $args ) );
		}

		return isset( $record['table'] ) ? self::two_factor_rows( $record['table'], 0 ) : 0;
	}

	/**
	 * The accounts a plugin has two-factor set up for, read the way
	 * `two_factor_set_up_count()` counts them, lowest ID first.
	 *
	 * @return int[]
	 */
	private static function two_factor_set_up_ids( string $file ): array {
		global $wpdb;

		$record = self::two_factor_record( $file );

		// Every account in the roles it emails codes to, whether or not it set up the app too.
		if ( 'wp-hide-security-enhancer/wp-hide.php' === $file && array() !== self::wph_email_roles() ) {
			$query = new \WP_User_Query(
				array(
					'role__in'    => self::wph_email_roles(),
					'fields'      => 'ID',
					'orderby'     => 'ID',
					'order'       => 'ASC',
					// Walked to name them; past this, the rest are counted, not walked.
					'number'      => self::WALKED,
					'count_total' => false,
				)
			);

			return array_map( 'intval', (array) $query->get_results() );
		}

		$ids = array();

		if ( isset( $record['meta'] ) ) {
			list( $where, $args ) = self::two_factor_meta_where( $record );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- the accounts another plugin has two-factor set up for; there is no API for it. Only placeholders are built here.
			$ids = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE {$where} ORDER BY user_id", $args ) );
		} elseif ( isset( $record['table'] ) ) {
			$quiet = $wpdb->suppress_errors( true );

			try {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- another plugin's own table, read for the accounts with its two-factor set up; nothing is written.
				$ids = $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT user_id FROM %i ORDER BY user_id', $wpdb->base_prefix . $record['table'] ) );
			} finally {
				$wpdb->suppress_errors( $quiet );
			}
		}

		return array_map( 'intval', is_array( $ids ) ? $ids : array() );
	}

	/**
	 * The user meta condition that marks a plugin's two-factor as set up,
	 * and its arguments, for a query of the user meta table.
	 *
	 * @param array{meta: string|string[], field?: string, on?: string} $record Where the plugin records it.
	 * @return array{0: string, 1: array<int, string>}
	 */
	private static function two_factor_meta_where( array $record ): array {
		global $wpdb;

		$keys   = (array) $record['meta'];
		$marks  = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );
		$values = isset( $record['on'] ) ? 'meta_value = %s' : "meta_value NOT IN ('', 'a:0:{}')";
		$args   = array_merge( $keys, isset( $record['on'] ) ? array( $record['on'] ) : array() );

		// Inside a serialized array: the value, quoted as serialize() writes it.
		if ( isset( $record['field'], $record['on'] ) ) {
			$values = 'meta_value LIKE %s';
			$args   = array_merge( $keys, array( '%' . $wpdb->esc_like( '"' . $record['on'] . '"' ) . '%' ) );
		}

		return array( "meta_key IN ({$marks}) AND {$values}", $args );
	}

	/**
	 * Rows in another plugin's table of two-factor secrets, for one account
	 * or, with 0, the accounts in it. The table is the network's, and one
	 * that is not there answers 0 rather than an error in the log.
	 */
	private static function two_factor_rows( string $table, int $user_id ): int {
		global $wpdb;

		$quiet = $wpdb->suppress_errors( true );

		try {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery -- another plugin's own table, read for whether an account has its two-factor set up; nothing is written.
			$count = 0 === $user_id
				? $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(DISTINCT user_id) FROM %i', $wpdb->base_prefix . $table ) )
				: $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE user_id = %d', $wpdb->base_prefix . $table, $user_id ) );
			// phpcs:enable WordPress.DB.DirectDatabaseQuery
		} finally {
			$wpdb->suppress_errors( $quiet );
		}

		return (int) $count;
	}
}
