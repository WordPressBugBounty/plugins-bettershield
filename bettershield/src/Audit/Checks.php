<?php
/**
 * Audit check registry.
 *
 * Every check is read-only and local — no network calls, no file writes,
 * no site modification of any kind. A check's `test` returns null when
 * the site passes, or an evidence array when a finding is open.
 *
 * Keys are stable identifiers; they are how the UI, the log and the
 * REST surface refer to the same finding across runs. Never rename one.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

use BetterShield\Audit\Certificate;
use BetterShield\Audit\Dormant;
use BetterShield\Audit\MixedContent;
use BetterShield\Audit\RestSurface;
use BetterShield\Hardening\Item\VersionDisclosure;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Events\Seal;
use BetterShield\Support\Areas;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Environment;
use BetterShield\Support\Observed;
use BetterShield\Verify\Verification;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Checks {

	/**
	 * A check's `severity` is either a fixed level or a callable returning one,
	 * because a couple of findings genuinely mean different things on a live
	 * site than on a laptop. Resolve it through here rather than reading the
	 * key directly.
	 *
	 * @param array<string, mixed> $check
	 */
	public static function severity_of( array $check ): string {
		$severity = $check['severity'];

		return is_string( $severity ) ? $severity : (string) $severity();
	}

	/**
	 * A check's title, which a few of them decide when they are read.
	 *
	 * Same shape as `severity_of()` and for the same reason: a check that has
	 * measured something knows more about how to name it than the registry did
	 * when it was written. "Close to expiring" is the wrong sentence for a
	 * certificate that expired last night.
	 *
	 * A finding row carries the severity it was recorded at, and a check that
	 * could not answer keeps that row as it was. A title decided when it is
	 * read is given that severity, so the row keeps the title of what it
	 * recorded rather than of whatever the latest look found.
	 *
	 * @param array<string, mixed> $check
	 * @param string|null          $severity The severity the row was recorded at, where there is a row.
	 */
	public static function title_of( array $check, ?string $severity = null ): string {
		$title = $check['title'];

		return is_string( $title ) ? $title : (string) $title( $severity );
	}

	/**
	 * PHP branches and the date their security support ends. Future dates
	 * are listed as soon as php.net publishes them: the check stays quiet
	 * until the date passes, so a site that outlives this plugin's last
	 * update still starts hearing about a branch the day it ages out. A
	 * branch missing here is newer than this list; extend it as new
	 * branches are released.
	 */
	private const PHP_EOL = array(
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/**
	 * Where the control that answers a finding lives, for the findings whose
	 * answer is not a one-click fix.
	 *
	 * A finding exists to be acted on, and every hop between "here is the
	 * problem" and "here is the control" loses the reader. The remediable ones
	 * carry their fix on the row already; these carried nothing but an
	 * explanation, so somebody who agreed with the finding was left to work out
	 * for themselves which of sixteen screens answered it.
	 *
	 * Deliberately partial. Several findings have no control anywhere — a
	 * certificate about to lapse belongs to the host, mixed content belongs to
	 * a post somebody wrote — and inventing a destination for those would be a
	 * button that goes somewhere unhelpful, which is worse than no button. A
	 * finding with nowhere to send anybody sends them nowhere.
	 *
	 * @return array<string, array{label: string, url: string}>
	 */
	private static function controls(): array {
		/*
		 * A long screen also names the setting that answers the finding, as
		 * `focus`: the screen brings that setting into view and focuses it,
		 * rather than opening at its top with nothing marked.
		 */
		$ours = static function ( string $slug, string $tab = '', string $focus = '' ): string {
			$url = admin_url( 'admin.php?page=' . $slug );
			$url = '' === $tab ? $url : add_query_arg( 'tab', $tab, $url );

			return '' === $focus ? $url : add_query_arg( 'focus', $focus, $url );
		};

		/*
		 * On a network an account is deleted from the network's Users screen,
		 * which only someone who manages the network's users can open. A
		 * site's administrator acts on its own members from the site's.
		 */
		$accounts = is_multisite() && current_user_can( 'manage_network_users' ) ? network_admin_url( 'users.php' ) : admin_url( 'users.php' );

		$controls = array(
			'lockouts_not_running'         => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'trusted_proxies' ),
			),
			'login_attempts_unlimited'     => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'attempt_limit' ),
			),
			// The switch it overlaps, with the note that links to the choice.
			'login_limits_overlap'         => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'attempt_limit' ),
			),
			'login_url_shadows_content'    => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'login_url' ),
			),
			'privileged_password_only'     => array(
				'label' => __( 'Open Two-Factor', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'two-factor' ),
			),
			// Issuing recovery codes there closes it. The setup opens at its
			// saved step, which its address cannot choose.
			'recovery_unconfirmed'         => array(
				'label' => __( 'Open Recovery', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'recovery' ),
			),
			'reset_form_unprotected'       => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'reset_form' ),
			),
			'comment_form_unprotected'     => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'comment_form' ),
			),
			'registration_form_unprotected' => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'register_form' ),
			),
			'form_bot_check_off'           => array(
				'label' => __( 'Open Login & Access', 'bettershield' ),
				'url'   => $ours( 'bettershield-protect', 'login', 'honeypot' ),
			),
			'recovery_readiness_incomplete' => array(
				'label' => __( 'Review Recovery Options', 'bettershield' ),
				'url' => $ours( 'bettershield-protect', 'recovery' ),
			),
			'alerts_undeliverable'         => array(
				'label' => __( 'Open Reports and Alerts', 'bettershield' ),
				'url'   => $ours( 'bettershield-settings', 'alerts' ),
			),
			'passwords_below_policy'       => array(
				'label' => __( 'Open the Password Policy', 'bettershield' ),
				'url'   => $ours( 'bettershield-settings', 'general', 'password_policy' ),
			),
			'disclosure_contact_lapsing'   => array(
				'label' => __( 'Open Security Contact Settings', 'bettershield' ),
				'url'   => $ours( 'bettershield-settings', 'general', 'security_contact' ),
			),
			'vulnerability_data_stale'     => array(
				'label' => __( 'Open Vulnerability Settings', 'bettershield' ),
				'url'   => $ours( 'bettershield-settings', 'general', 'vulnerability_checks' ),
			),
			'vulnerabilities_known'        => array(
				'label' => __( 'Open Vulnerability Settings', 'bettershield' ),
				'url'   => $ours( 'bettershield-settings', 'general', 'vulnerability_checks' ),
			),
			'mcp_endpoint_unauthenticated' => array(
				'label' => __( 'Open the Agent Surface', 'bettershield' ),
				'url'   => $ours( 'bettershield-agents', 'surface' ),
			),
			'application_passwords_stale'  => array(
				'label' => __( 'Open the Agent Surface', 'bettershield' ),
				'url'   => $ours( 'bettershield-agents', 'surface' ),
			),
			'privileged_app_password_unlimited' => array(
				'label' => __( 'Open the Agent Surface', 'bettershield' ),
				'url'   => $ours( 'bettershield-agents', 'surface' ),
			),
			'files_altered'                => array(
				'label' => __( 'Open File Changes', 'bettershield' ),
				'url'   => $ours( 'bettershield-activity', 'files' ),
			),
			'files_never_checked'          => array(
				'label' => __( 'Open File Changes', 'bettershield' ),
				'url'   => $ours( 'bettershield-activity', 'files' ),
			),
			'quarantine_unsealed'          => array(
				'label' => __( 'Open File Changes', 'bettershield' ),
				'url'   => $ours( 'bettershield-activity', 'files' ),
			),
			'schema_storage_unavailable'   => array(
				'label' => __( 'Open the Overview', 'bettershield' ),
				'url'   => $ours( 'bettershield' ),
			),

			/*
			 * WordPress's own screens, where the answer is WordPress's rather
			 * than this plugin's. Naming them is still the shortest path from
			 * the finding to the fix, and a security plugin that made somebody
			 * hunt for the Users screen would be adding a hop for the sake of
			 * staying inside its own walls.
			 */
			'admin_username_exists'        => array(
				'label' => __( 'Open Users', 'bettershield' ),
				'url'   => $accounts,
			),
			'admin_user_id_one'            => array(
				'label' => __( 'Open Users', 'bettershield' ),
				'url'   => $accounts,
			),
			'privileged_account_dormant'   => array(
				'label' => __( 'Open Users', 'bettershield' ),
				'url'   => admin_url( 'users.php' ),
			),
			'core_update_available'        => array(
				'label' => __( 'Open Updates', 'bettershield' ),
				'url'   => admin_url( 'update-core.php' ),
			),
			'plugin_updates_available'     => array(
				'label' => __( 'Open Updates', 'bettershield' ),
				'url'   => admin_url( 'update-core.php' ),
			),
			'inactive_extensions'          => array(
				'label' => __( 'Open Plugins', 'bettershield' ),
				// On a network plugins and themes are deleted from its own screen.
				'url'   => is_multisite() ? network_admin_url( 'plugins.php' ) : admin_url( 'plugins.php' ),
			),
		);

		/*
		 * On a single site the one-click fix answers this finding. On a
		 * network the site's own switch governs nothing: whether anybody may
		 * register is the network's setting.
		 */
		if ( is_multisite() ) {
			$controls['open_registration_privileged'] = array(
				'label' => __( 'Open Settings › General', 'bettershield' ),
				'url'   => network_admin_url( 'settings.php' ),
			);
		}

		/*
		 * On a network, updates, plugins and the membership setting are the
		 * network's screens, which a site's administrator cannot open: each
		 * of these buttons ended in "Sorry, you are not allowed to access
		 * this page" (#2121). Offered only to somebody who can open them.
		 */
		if ( is_multisite() ) {
			$network_only = array(
				'core_update_available'        => 'update_core',
				'plugin_updates_available'     => 'update_plugins',
				'inactive_extensions'          => 'manage_network_plugins',
				'open_registration_privileged' => 'manage_network_options',
			);

			foreach ( $network_only as $id => $capability ) {
				if ( ! current_user_can( $capability ) ) {
					unset( $controls[ $id ] );
				}
			}
		}

		return $controls;
	}

	/**
	 * Whether an account is this site's to report.
	 *
	 * On a network the user table is the network's. Asked on a subsite, the
	 * account checks found the network's first account (a super admin, and
	 * so an administrator everywhere) on every site, member or not, and
	 * its administrator could do nothing about it. A subsite reports an
	 * account of its own that is not a super admin; the network's own is
	 * reported once, on the main site, where its owner can change it.
	 */
	private static function this_sites_to_change( int $user_id ): bool {
		if ( ! is_multisite() || is_main_site() ) {
			return true;
		}

		return is_user_member_of_blog( $user_id ) && ! is_super_admin( $user_id );
	}

	/**
	 * The control that answers this finding, or null when there is not one.
	 *
	 * @return array{label: string, url: string}|null
	 */
	public static function control_for( string $id ): ?array {
		/*
		 * Built once per site rather than once per finding. `controls()`
		 * assembles twenty entries, each with a translated label and an admin
		 * address, and this is called once per row from both the overview
		 * payload and the full report — twenty rebuilds a request on a site
		 * with twenty findings, on the most-requested endpoint in the plugin.
		 *
		 * Keyed by site because `admin_url()` is per-site: the network roll-up
		 * switches between them, and an unkeyed memo would hand one site's
		 * addresses to another.
		 */
		static $memo = array();

		// And by whether the reader can open the network's Users screen,
		// which decides where the account findings send them.
		$site = get_current_blog_id() . ( is_multisite() && current_user_can( 'manage_network_users' ) ? ':network' : '' ) . ( is_multisite() && current_user_can( 'manage_network_plugins' ) ? ':plugins' : '' );

		if ( ! isset( $memo[ $site ] ) ) {
			$memo[ $site ] = self::controls();
		}

		return $memo[ $site ][ $id ] ?? null;
	}

	/**
	 * Where to send somebody whose fix is on and whose finding is still open.
	 *
	 * Not one of the controls above: those stand in for a one-click fix, and
	 * a finding never offers both. This one is read only while the item is
	 * on, when Apply fix is not offered, and only for an item that can be on
	 * and leave its finding open by choice: XML-RPC with pingbacks only.
	 *
	 * @param string $id     The finding.
	 * @param bool   $active Whether its hardening item is on.
	 * @return array{label: string, url: string}|null
	 */
	public static function control_when_applied( string $id, bool $active ): ?array {
		if ( ! $active || 'xmlrpc_enabled' !== $id ) {
			return null;
		}

		// The whole endpoint closes the finding; only pingbacks only leaves it open.
		if ( ! self::pingbacks_only_blocked() ) {
			return null;
		}

		// Focused on the XML-RPC row, where the scope is chosen.
		return array(
			'label' => __( 'Open Hardening', 'bettershield' ),
			'url'   => add_query_arg(
				array(
					'tab'   => 'hardening',
					'focus' => 'xmlrpc',
				),
				admin_url( 'admin.php?page=bettershield-protect' )
			),
		);
	}

	/**
	 * Whether the XML-RPC item is on with pingbacks only: the pingback half
	 * is closed, by the owner or by a host's panel writing the same setting,
	 * and the rest of the endpoint still answers.
	 */
	public static function pingbacks_only_blocked(): bool {
		$manager = Manager::instance();

		return $manager->is_active( 'xmlrpc' ) && \BetterShield\Hardening\Item\XmlRpc::pingbacks_only( (array) ( $manager->item_state( 'xmlrpc' )['options'] ?? array() ) );
	}

	/**
	 * Whether an open finding is partly answered already, so it is kept in
	 * the list and the score at its lower weight but not offered as worth
	 * doing first: XML-RPC with its pingbacks blocked.
	 *
	 * @param string $id The finding.
	 */
	public static function partly_handled( string $id ): bool {
		return 'xmlrpc_enabled' === $id && self::pingbacks_only_blocked();
	}

	/**
	 * Why an item's protection is not in force, in the evidence's words.
	 *
	 * Applied and unhooked is not "not switched on": in safe mode the
	 * Evidence panel said so directly under the note that the item is set to
	 * applied and paused (#1812). Applied, it is paused by safe mode or has
	 * come unhooked, as the "not working" finding says it (#1736).
	 */
	private static function why_not_in_force( string $item ): string {
		if ( ! Manager::instance()->is_active( $item ) ) {
			return 'enforcement_not_attached';
		}

		return \BetterShield\Recovery\SafeMode::is_active() ? 'paused_by_safe_mode' : 'hooks_detached';
	}

	/**
	 * Whether WordPress will keep errors off the page, given what
	 * `WP_DEBUG_DISPLAY` holds and what the running configuration says.
	 *
	 * Core reads this constant in three states, not two. Any falsy value
	 * forces `display_errors` off — `0`, `''` and `false` alike — and `null`
	 * is core's documented way of saying "leave whatever is configured
	 * alone", so that one case is decided by php.ini rather than by the
	 * constant. Reading only a literal `false` as off meant a site that had
	 * written `0` was told at high severity to set a constant it had set.
	 *
	 * Takes its inputs rather than reading them, because a constant cannot be
	 * redefined inside a running process and a rule nothing can test drifts.
	 *
	 * @param mixed $value What `WP_DEBUG_DISPLAY` holds.
	 */
	public static function debug_display_is_off( $value, string $display_errors ): bool {
		if ( null === $value ) {
			return ! self::display_errors_prints( $display_errors );
		}

		return ! $value;
	}

	/**
	 * What prints debug output into the site's pages, or null for nothing.
	 *
	 * With WP_DEBUG on and WP_DEBUG_DISPLAY set to a value, core sets
	 * display_errors from that value on every page it serves, so the
	 * constants settle it. They are read first: the reading from a dashboard
	 * page is kept at most once a minute and never from WP-CLI or cron, and
	 * an owner who had just fixed wp-config was told about the cause they
	 * removed, by an audit that never saw the change (#1813). Otherwise the
	 * server's own setting is what pages get: what a dashboard page was
	 * served with, or, with nothing observed yet, this process's reading.
	 *
	 * Takes its inputs, as debug_display_is_off() does, so the rule can be
	 * tested without redefining a constant.
	 *
	 * @param bool        $debug           Whether WP_DEBUG is on.
	 * @param bool        $display_defined Whether WP_DEBUG_DISPLAY is defined.
	 * @param mixed       $display         What WP_DEBUG_DISPLAY holds.
	 * @param bool|null   $observed        What a page was served with, if anything was observed.
	 * @param string      $display_errors  This process's display_errors.
	 * @return string|null 'wp_debug', 'php_settings', or null.
	 */
	public static function debug_output_set_by( bool $debug, bool $display_defined, $display, ?bool $observed, string $display_errors ): ?string {
		if ( $debug && $display_defined && null !== $display ) {
			return $display ? 'wp_debug' : null;
		}

		$shown = $observed ?? ( $debug && ! ( $display_defined && self::debug_display_is_off( $display, $display_errors ) ) );

		if ( ! $shown ) {
			return null;
		}

		return $debug ? 'wp_debug' : 'php_settings';
	}

	/**
	 * The one-click fix for the admin-ajax cross-origin finding, offered only
	 * where the last check found WordPress's own list widened by code. A
	 * header the web server adds never reaches that list, so narrowing it
	 * would report a fix that changes nothing.
	 */
	private static function cross_origin_fix(): ?string {
		foreach ( (array) ( \BetterShield\Audit\CrossOrigin::last()['open'] ?? array() ) as $row ) {
			if ( 'filter' === ( $row['source']['kind'] ?? '' ) ) {
				return 'ajax_origins';
			}
		}

		return null;
	}

	/**
	 * Whether a display_errors value prints into the page.
	 *
	 * PHP takes On, 1, yes and true, and also `stdout`, which prints into the
	 * page as On does; read as a boolean, `stdout` was off, and a server set
	 * that way printed every warning and its path with no finding (#1814).
	 * `stderr` goes to the server's error stream, not the page.
	 */
	public static function display_errors_prints( string $value ): bool {
		return 'stdout' === strtolower( trim( $value ) ) || filter_var( $value, FILTER_VALIDATE_BOOLEAN );
	}

	/**
	 * Whether a file's Unix mode bits say who can write it on this host.
	 *
	 * Not on Windows: PHP builds them there from the read-only attribute and
	 * copies the owner's bits to group and world, so every writable file
	 * reads 0666 and every writable folder 0777, whatever its access list
	 * says — and chmod only flips the read-only flag. Core keeps a separate
	 * Windows path in `wp_is_writable()` for the same reason. The family is
	 * passed in so both answers can be tested on any host.
	 */
	public static function mode_bits_describe_access( string $os_family ): bool {
		return 'Windows' !== $os_family;
	}

	/**
	 * Ask WordPress for its plugin updates again when the cache is empty.
	 *
	 * Updating a plugin clears core's update cache, and the audit that runs
	 * straight after an update then had nothing to read: "Plugins have
	 * updates available" could not be checked, with a banner until the next
	 * audit (#2146). Core's own check refills it, the request it makes on a
	 * schedule and on the Updates screen; only when the cache is empty.
	 */
	public static function refill_update_cache(): void {
		$data = get_site_transient( 'update_plugins' );

		if ( is_object( $data ) && ! empty( $data->last_checked ) ) {
			return;
		}

		if ( ! function_exists( 'wp_update_plugins' ) ) {
			require_once ABSPATH . WPINC . '/update.php';
		}

		wp_update_plugins();
	}

	/**
	 * One of core's update caches, when it is recent enough to answer from.
	 *
	 * Core refreshes them about twice a day from its own scheduled checks, and
	 * an admin page view refreshes them too. A cache that was never filled,
	 * or was filled days ago, says the checks stopped — and read as empty it
	 * was indistinguishable from a fresh "nothing to update". Three days
	 * leaves room for a quiet site and a missed run or two.
	 *
	 * @param string $name `update_core` or `update_plugins`.
	 * @return object|\WP_Error
	 */
	private static function fresh_update_cache( string $name ) {
		$data = get_site_transient( $name );

		if ( ! is_object( $data ) || empty( $data->last_checked ) ) {
			return new \WP_Error( 'bettershield_audit_unknown', __( 'WordPress has not checked for updates yet.', 'bettershield' ) );
		}

		/*
		 * An update the cache lists is still waiting however old the cache:
		 * core clears it when anything is updated. Past three days only a
		 * cache that lists nothing is unknown, and read as unknown a pending
		 * update stopped being reported at all.
		 */
		if ( self::cache_lists_an_update( $name, $data ) ) {
			return $data;
		}

		if ( time() - (int) $data->last_checked > 3 * DAY_IN_SECONDS ) {
			return new \WP_Error( 'bettershield_audit_unknown', __( 'WordPress hasn’t checked for updates in over three days, which usually means its background jobs aren’t running.', 'bettershield' ) );
		}

		/*
		 * Core stamps last_checked before it asks, so a request that failed
		 * leaves a fresh-looking cache with no answer in it. An answer always
		 * holds at least the latest-version offer for core, and for plugins
		 * the versions it compared or the list with nothing to update
		 * (WordPress 6.7 and older write only the list after a full check);
		 * without them the question never got through, as on a site that
		 * cannot reach WordPress.org.
		 */
		if ( 'update_core' === $name ? empty( $data->updates ) : ( ! isset( $data->checked ) && ! isset( $data->no_update ) ) ) {
			return new \WP_Error( 'bettershield_audit_unknown', __( 'WordPress could not reach WordPress.org on its last update check.', 'bettershield' ) );
		}

		return $data;
	}

	/**
	 * Whether one of core's update caches lists an update waiting.
	 */
	private static function cache_lists_an_update( string $name, object $data ): bool {
		return 'update_plugins' === $name ? self::plugin_offers( $data ) > 0 : '' !== self::core_offer( $data );
	}

	/**
	 * The version core's cache offers to upgrade to, when it is newer than
	 * the one running, or ''.
	 *
	 * Newer than what runs now, not merely listed: a site updated by a deploy
	 * rather than by WordPress, with its scheduled tasks stopped, keeps an old
	 * cache offering the very version it already runs.
	 */
	private static function core_offer( object $data ): string {
		global $wp_version;

		foreach ( (array) ( $data->updates ?? array() ) as $update ) {
			$version = is_object( $update ) ? (string) ( $update->version ?? '' ) : '';

			if ( is_object( $update ) && 'upgrade' === ( $update->response ?? '' ) && '' !== $version && version_compare( $version, (string) $wp_version, '>' ) ) {
				return $version;
			}
		}

		return '';
	}

	/**
	 * How many installed plugins the cache offers a newer version of, read
	 * against the version each one has now, for the same reason.
	 */
	private static function plugin_offers( object $data ): int {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$installed = get_plugins();
		$count     = 0;

		foreach ( (array) ( $data->response ?? array() ) as $file => $offer ) {
			$offer   = (array) $offer;
			$new     = (string) ( $offer['new_version'] ?? '' );
			$running = (string) ( $installed[ (string) $file ]['Version'] ?? '' );

			if ( '' !== $new && '' !== $running && version_compare( $new, $running, '>' ) ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Switched-on protections that are not working, as item title => why:
	 * the finding's evidence, which a person reads.
	 *
	 * @return array<string, string>
	 */
	private static function protections_not_working(): array {
		$titles = Items::all();
		$broken = array();

		foreach ( self::protections_failing() as $item => $why ) {
			$broken[ (string) ( $titles[ $item ]['title'] ?? $item ) ] = $why;
		}

		return $broken;
	}

	/**
	 * Switched-on protections that are not working, as item id => why: what
	 * the finding's Fix applies again.
	 *
	 * The items with a check of their own (XML-RPC, the file editor, user
	 * listing, the security headers, the version tag) answer there. These are
	 * the rest, each asked the one question that tells "switched on" from
	 * "in force" for it.
	 *
	 * @return array<string, string>
	 */
	public static function protections_failing(): array {
		$manager = Manager::instance();
		$broken  = array();

		/*
		 * Written to disk once, at apply, and never looked at again: the
		 * uploads folder is the one the integrity walk is told to skip, so a
		 * migration that rewrote its .htaccess left the item reading active.
		 */
		if ( $manager->is_active( 'uploads_php' ) ) {
			$block = \BetterShield\Files\Guarded::read_block( trailingslashit( (string) wp_get_upload_dir()['basedir'] ) . '.htaccess', \BetterShield\Hardening\Item\UploadsPhp::MARKER );

			if ( null === $block ) {
				$broken['uploads_php'] = 'rules_missing';
			} elseif ( is_string( $block ) && trim( $block ) !== trim( \BetterShield\Hardening\Item\UploadsPhp::rules() ) ) {
				$broken['uploads_php'] = 'rules_altered';
			}
		}

		/*
		 * The guards this item placed and recorded, one of which is gone and
		 * left its folder bare. A bare folder it never guarded (made by a
		 * plugin after the last pass, or the new month's) is not a guard
		 * somebody removed, so the walk for bare folders is not the question.
		 */
		if ( $manager->is_active( 'directory_browsing' ) && array() !== \BetterShield\Hardening\Item\DirectoryBrowsing::removed_guards() ) {
			$broken['directory_browsing'] = 'guards_missing';
		}

		/*
		 * The protections that work through hooks: a conflicting
		 * plugin's remove_filter(), or a theme re-registering the same hook,
		 * left these reading active with nothing attached, and nothing asked.
		 * Each handler names its own hooks.
		 */
		foreach ( array( 'login_url', 'admin_gate', 'admin_area_access', 'application_passwords', 'breached_passwords', 'reset_link_lifetime', 'email_change_confirm', 'auth_keys', 'cloud_metadata', 'unfiltered_code', 'script_uploads', 'ability_access' ) as $item ) {
			if ( $manager->is_active( $item ) && false === $manager->handler_enforced( $item ) ) {
				$broken[ $item ] = 'hooks_detached';
			}
		}

		/*
		 * The two headers the sampler can see on a visitor's page, the way
		 * it sees the security headers: observed missing is not working.
		 * Not yet observed is not a contradiction, and says nothing.
		 */
		foreach ( array( 'hsts', 'csp_report_only' ) as $item ) {
			if ( $manager->is_active( $item ) && null !== Verification::last_absence( $item ) ) {
				$broken[ $item ] = 'not_observed';
			}
		}

		return $broken;
	}

	/**
	 * The areas the checks below cover, in the order they first appear.
	 *
	 * Kept beside `all()` so the chrome can read five slugs without building a
	 * registry of every check and a closure for each of them, on every admin
	 * screen this plugin draws. A test asserts the two agree, so a check added
	 * under a new area fails the suite rather than quietly disappearing from a
	 * filter row.
	 *
	 * @return string[]
	 */
	public static function groups(): array {
		return array(
			Areas::ACCESS,
			Areas::EXPOSURE,
			Areas::EXTENSIONS,
			Areas::SERVER,
			Areas::CONFIGURATION,
		);
	}

	/**
	 * Whether anybody may register an account here.
	 *
	 * On a network the site's `users_can_register` is filtered by core into a
	 * read of the network's `registration` setting, and writing the site
	 * option changes nothing; so the network's own value is what is asked.
	 */
	private static function registration_is_open(): bool {
		if ( is_multisite() ) {
			return 'none' !== (string) get_site_option( 'registration', 'none' );
		}

		return (bool) get_option( 'users_can_register' );
	}

	/**
	 * Whether passkey-only sign-in is refusing passwords here: a role is named
	 * and this site can do passkeys. Where it cannot, the sign-in gate stands
	 * aside and a password still works, so a policy kept from before changes
	 * nothing about what a lapsing link means.
	 *
	 * Named by the site or by its network: the sign-in gate refuses on both,
	 * and a site whose roles came only from the network read as having none.
	 */
	private static function passkey_only_in_effect(): bool {
		return array() !== \BetterShield\Network\Policies::effective_passkey_roles( \BetterShield\Passkeys\Policy::instance()->settings()['roles'] )
			&& \BetterShield\Passkeys\Manager::availability()['available'];
	}

	/** How many roles one read names, so a site with dozens of them stays one short line. */
	private const MAX_ROLES_NAMED = 10;

	/** Upload types that run as script when served from the site's own address. */
	public const SCRIPT_TYPES = array( 'svg', 'svgz', 'htm', 'html', 'js' );

	/**
	 * Upload types a server can run as PHP. Risky for every role below
	 * administrator, whatever it may publish: they run on the server, not in
	 * a browser.
	 */
	public const PHP_TYPES = array( 'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps' );

	/**
	 * The filter a host answers to say whether its AI bot blocker is on for
	 * this site: true or false, or null to say nothing. Still read where the
	 * host says nothing about `ai_bot_blocker` in HostProtections::FILTER.
	 */
	public const HOST_AI_BOT_FILTER = 'bettershield_host_ai_bot_blocker';

	/**
	 * What the host says about its AI bot blocker, or null when it says
	 * nothing.
	 */
	public static function host_ai_bot_blocker(): ?bool {
		$host = HostProtections::said();

		if ( isset( $host['ai_bot_blocker'] ) ) {
			return $host['ai_bot_blocker'];
		}

		$said = apply_filters( self::HOST_AI_BOT_FILTER, null ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- self::HOST_AI_BOT_FILTER is 'bettershield_host_ai_bot_blocker'.

		return null === $said ? null : (bool) $said;
	}

	/**
	 * Whether a public form is guarded: sign-in protection on, and that
	 * form's own switch on.
	 */
	private static function form_guarded( string $surface ): bool {
		$protection = \BetterShield\Login\Protection::instance();

		return ! empty( $protection->settings()['enabled'] ) && $protection->surface_policy( $surface )['enabled'];
	}

	/**
	 * Roles whose accounts can change what the site is, and so deserve a
	 * second factor: administrators first, then the roles that edit everyone's
	 * content or run the store.
	 */
	private const PRIVILEGED_ROLES = array( 'administrator', 'editor', 'shop_manager' );

	/**
	 * How many privileged accounts sign in with a password alone: no second
	 * factor, no passkey, and no role requirement (the site's or the
	 * network's) that will ask them for one.
	 *
	 * Bounded: past a few hundred privileged accounts the answer is already
	 * "some", and an audit is not the place to read every one.
	 *
	 * @return array{administrators: int, others: int, ids: int[]}
	 */
	public static function password_only_accounts(): array {
		$required = \BetterShield\Network\Policies::effective_two_factor_roles( \BetterShield\TwoFactor\Policy::instance()->settings()['roles'] );
		$manager  = \BetterShield\TwoFactor\Manager::instance();
		$found    = array(
			'administrators' => 0,
			'others'         => 0,
			'ids'            => array(),
		);

		$ids = get_users(
			array(
				'role__in'    => self::PRIVILEGED_ROLES,
				'fields'      => 'ID',
				'number'      => 500,
				'count_total' => false,
				'orderby'     => 'ID',
			)
		);

		// A network's super admins hold every site whatever their role here.
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$admin = get_user_by( 'login', $login );

				if ( $admin instanceof \WP_User ) {
					$ids[] = $admin->ID;
				}
			}
		}

		foreach ( array_unique( array_map( 'intval', $ids ) ) as $id ) {
			$user = get_userdata( $id );

			if ( ! $user instanceof \WP_User ) {
				continue;
			}

			if ( array() !== array_intersect( (array) $user->roles, $required ) ) {
				continue;
			}

			if ( $manager->enabled( $id ) || \BetterShield\Passkeys\Store::count_for_user( $id ) > 0 || '' !== \BetterShield\Onboarding\Coexistence::two_factor_for_user( $user ) ) {
				continue;
			}

			if ( in_array( 'administrator', (array) $user->roles, true ) || is_super_admin( $id ) ) {
				++$found['administrators'];
			} else {
				++$found['others'];
			}

			$found['ids'][] = $id;
		}

		return $found;
	}

	/**
	 * A finding's evidence as this reader may see it. The stored row holds
	 * counts only, because every manager of the plugin reads it; a reader
	 * who may list users is also shown which accounts, by display name, at
	 * most ten, with their own account named as theirs.
	 *
	 * @param mixed $evidence As stored.
	 * @return mixed
	 */
	public static function evidence_for_reader( string $key, $evidence ) {
		if ( 'privileged_password_only' !== $key || ! is_array( $evidence ) || ! current_user_can( 'list_users' ) ) {
			return $evidence;
		}

		$ids = self::password_only_accounts()['ids'];

		if ( array() === $ids ) {
			return $evidence;
		}

		$names = array();

		foreach ( array_slice( $ids, 0, 10 ) as $id ) {
			$user    = get_userdata( $id );
			$names[] = get_current_user_id() === $id ? __( 'Your account', 'bettershield' ) : ( $user instanceof \WP_User ? $user->display_name : '#' . $id );
		}

		if ( count( $ids ) > 10 ) {
			/* translators: %d: how many more accounts are not listed. */
			$names[] = sprintf( _n( 'and %d more', 'and %d more', count( $ids ) - 10, 'bettershield' ), count( $ids ) - 10 );
		}

		$evidence['accounts'] = implode( ', ', $names );

		return $evidence;
	}

	/**
	 * Whether any account holds this role. A role nobody is in grants nothing
	 * today, and reporting it would name a template rather than a person.
	 */
	private static function role_is_held( string $slug ): bool {
		return array() !== get_users(
			array(
				'role'        => $slug,
				'number'      => 1,
				'fields'      => 'ID',
				'count_total' => false,
				'orderby'     => 'ID',
			)
		);
	}

	/**
	 * Roles below administrator, held by an account, whose capabilities let
	 * that account publish unfiltered markup or upload any file type.
	 *
	 * Core decides both capabilities before a role is asked: on a network only
	 * a super admin holds either, `DISALLOW_UNFILTERED_HTML` takes the first
	 * from everybody, and the second is refused to everybody unless the
	 * site's configuration allows unfiltered uploads. That decision is read
	 * from core's own capability mapping, which asks a role for the
	 * capability itself only when the site allows it. The Editor's unfiltered
	 * HTML is core's own default on a single site, so it is not reported.
	 *
	 * @return array<string, string>|null Capability => comma-separated role slugs.
	 */
	private static function unfiltered_roles(): ?array {
		$html   = ! is_multisite() && ! ( defined( 'DISALLOW_UNFILTERED_HTML' ) && DISALLOW_UNFILTERED_HTML );
		$upload = ! is_multisite() && in_array( 'unfiltered_upload', map_meta_cap( 'unfiltered_upload', 0 ), true );

		if ( ! $html && ! $upload ) {
			return null;
		}

		$found = array(
			'unfiltered_html'   => array(),
			'unfiltered_upload' => array(),
		);

		foreach ( wp_roles()->role_objects as $slug => $role ) {
			if ( $role->has_cap( 'manage_options' ) ) {
				continue;
			}

			$caps = array();

			if ( $html && 'editor' !== $slug && $role->has_cap( 'unfiltered_html' ) ) {
				$caps[] = 'unfiltered_html';
			}

			if ( $upload && $role->has_cap( 'unfiltered_upload' ) ) {
				$caps[] = 'unfiltered_upload';
			}

			// The account query runs only for a role that would be named.
			if ( array() === $caps || ! self::role_is_held( (string) $slug ) ) {
				continue;
			}

			foreach ( $caps as $cap ) {
				if ( count( $found[ $cap ] ) < self::MAX_ROLES_NAMED ) {
					$found[ $cap ][] = (string) $slug;
				}
			}
		}

		$found = array_filter( $found );

		return array() === $found ? null : array_map( static fn( array $slugs ): string => implode( ', ', $slugs ), $found );
	}

	/**
	 * Whether any administrator of this site who is not a network
	 * administrator can open the theme or plugin editor. Core gives them to
	 * network administrators alone; a plugin can grant them further.
	 */
	private static function site_admins_edit_files(): bool {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 50,
				'fields' => 'ID',
			)
		);

		foreach ( $admins as $id ) {
			if ( ! is_super_admin( (int) $id ) && ( user_can( (int) $id, 'edit_themes' ) || user_can( (int) $id, 'edit_plugins' ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether this plugin's own automatic updates are off by the owner's
	 * switch, with nothing in code deciding the question.
	 *
	 * Every automatic update switched off (a constant, a filter, or file
	 * changes refused outright), or the per-plugin switches hidden, is a
	 * policy the site set for itself, usually because a host or an agency's
	 * tools install updates instead; so is a value from `auto_update_plugin`,
	 * which decides either way without the switch being read. None of those
	 * is reported. What is left is the switch on this plugin's row being off.
	 *
	 * @return array{plugin: string}|null
	 */
	private static function own_auto_updates_off(): ?array {
		if ( null !== self::own_auto_updates_decided() ) {
			return null;
		}

		$file = plugin_basename( BETTERSHIELD_FILE );

		return in_array( $file, (array) get_site_option( 'auto_update_plugins', array() ), true ) ? null : array( 'plugin' => $file );
	}

	/**
	 * Why BetterShield's own auto-update switch is not the owner's to flip
	 * here, or null where it is: automatic updates off for the whole site,
	 * file changes not allowed, plugin auto-updates switched off, or a
	 * filter deciding it either way. The check stands down in each, and the
	 * one-click fix is not offered.
	 *
	 * @return string|null 'disabled', 'no_switch', 'forced', or null.
	 */
	public static function own_auto_updates_decided(): ?string {
		if ( ! function_exists( 'wp_is_auto_update_enabled_for_type' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core's own filter, read rather than declared.
		if ( ( defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED ) || apply_filters( 'automatic_updater_disabled', false ) || ! wp_is_file_mod_allowed( 'automatic_updater' ) ) {
			return 'disabled';
		}

		if ( ! wp_is_auto_update_enabled_for_type( 'plugin' ) ) {
			return 'no_switch';
		}

		$item = (object) array(
			'id'          => 'w.org/plugins/bettershield',
			'slug'        => 'bettershield',
			'plugin'      => plugin_basename( BETTERSHIELD_FILE ),
			'new_version' => BETTERSHIELD_VERSION,
			'url'         => '',
			'package'     => '',
		);

		return null !== wp_is_auto_update_forced_for_item( 'plugin', null, $item ) ? 'forced' : null;
	}

	/**
	 * The content folders anybody on the machine may write, with their mode.
	 *
	 * World-writable only. Group-writable is how a great many hosts share a
	 * folder between the site's account and the web server, and reporting it
	 * would be noise on almost every install. A folder that does not exist,
	 * such as an unused mu-plugins, is not a finding.
	 *
	 * @return array<string, string>|null Folder, relative to the WordPress root where it sits under it => mode.
	 */
	private static function writable_content_dirs(): ?array {
		$found = array();

		foreach ( self::content_folders() as $name => $path ) {
			$perms = @fileperms( $path ); // phpcs:ignore -- an unreadable path yields false, which is handled.

			if ( false === $perms || ! ( $perms & 0002 ) ) {
				continue;
			}

			$found[ $name ] = substr( sprintf( '%o', $perms ), -4 );
		}

		return array() === $found ? null : $found;
	}

	/**
	 * The folders the world-writable check reads, by the name the finding
	 * shows for each (from the site's root, or the folder's own name where
	 * it is outside it). Its Fix reads the same list (#2211), so it can only
	 * ever touch a folder the finding named.
	 *
	 * @return array<string, string> Name => normalized absolute path, existing folders only.
	 */
	public static function content_folders(): array {
		$uploads = wp_get_upload_dir();
		$folders = array(
			WP_CONTENT_DIR,
			WP_PLUGIN_DIR,
			WPMU_PLUGIN_DIR,
			get_theme_root(),
			is_array( $uploads ) ? (string) ( $uploads['basedir'] ?? '' ) : '',
		);

		$root  = wp_normalize_path( untrailingslashit( ABSPATH ) );
		$named = array();

		foreach ( array_unique( array_filter( array_map( static fn( $path ): string => wp_normalize_path( untrailingslashit( (string) $path ) ), $folders ) ) ) as $path ) {
			if ( ! is_dir( $path ) ) {
				continue;
			}

			$name           = str_starts_with( $path, $root . '/' ) ? substr( $path, strlen( $root ) + 1 ) : basename( $path );
			$named[ $name ] = $path;
		}

		return $named;
	}

	/**
	 * Roles below administrator whose accounts may upload a type that runs
	 * as script, read as one account in each role.
	 *
	 * Each account's list is read in a request of its own (`UploadTypes`):
	 * a filter that keeps its first answer for the whole request gave every
	 * account here the answer of whoever asked first. HTML and JavaScript are
	 * core's own answer for a role that may publish unfiltered HTML, and that
	 * role is the other check's subject, so for it only SVG is reported.
	 *
	 * The account read is never an administrator who also holds the role,
	 * nor a super admin: the fix leaves both alone, so their list would keep
	 * the finding open after it. A role held only by them is skipped.
	 *
	 * @return array<string, string>|\WP_Error|null Role slug => comma-separated types.
	 */
	private static function script_upload_types() {
		$found   = array();
		$unknown = 0;
		$asked   = 0;

		foreach ( wp_roles()->role_objects as $slug => $role ) {
			if ( count( $found ) >= self::MAX_ROLES_NAMED || $asked >= self::MAX_ROLES_NAMED ) {
				break;
			}

			if ( $role->has_cap( 'manage_options' ) || ! $role->has_cap( 'upload_files' ) ) {
				continue;
			}

			$account = get_users(
				array(
					'role'               => (string) $slug,
					'capability__not_in' => array( 'manage_options' ),
					'login__not_in'      => is_multisite() ? get_super_admins() : array(),
					'number'             => 1,
					'fields'             => 'all',
					'count_total'        => false,
					'orderby'            => 'ID',
				)
			)[0] ?? null;

			if ( ! $account instanceof \WP_User ) {
				continue;
			}

			++$asked;
			$types = UploadTypes::of( $account );

			if ( null === $types ) {
				++$unknown;
				continue;
			}

			if ( array() !== $types ) {
				$found[ (string) $slug ] = implode( ', ', $types );
			}
		}

		if ( array() !== $found ) {
			return $found;
		}

		// Nothing found, but some roles couldn't be asked: that isn't a pass.
		if ( $unknown > 0 ) {
			return new \WP_Error( 'bettershield_audit_unknown', SelfRequest::reason( UploadTypes::last_failure(), __( 'Your server couldn’t reach itself, so this check couldn’t run.', 'bettershield' ) ) );
		}

		return null;
	}

	/**
	 * An add-on's own checks, beside these, under keys of their own.
	 *
	 * Read on every call, so a check is there while its add-on is active and
	 * gone when it is not; a finding left behind is skipped by every reader,
	 * as one from a removed check is. A key this plugin owns is never
	 * replaced, and a check missing anything every reader needs is left out
	 * rather than read half-built.
	 *
	 * @param array<string, array<string, mixed>> $own
	 * @return array<string, array<string, mixed>>
	 */
	private static function with_addon_checks( array $own ): array {
		/**
		 * Checks an add-on runs with the audit. Each has the shape of the
		 * ones in `Checks::all()`: a group from `Support\Areas`, a title, a
		 * severity, why it matters, what fixing it could break, and a test
		 * that returns null when it passes, evidence when it does not, or a
		 * WP_Error when it cannot tell. An add-on check has no hardening item.
		 *
		 * @param array<string, array<string, mixed>> $checks Checks added so far.
		 */
		$added = apply_filters( 'bettershield_addon_checks', array() );

		foreach ( is_array( $added ) ? $added : array() as $key => $check ) {
			if ( ! is_string( $key ) || isset( $own[ $key ] ) || ! is_array( $check ) ) {
				continue;
			}

			$complete = in_array( $check['group'] ?? '', array( Areas::ACCESS, Areas::EXPOSURE, Areas::SERVER, Areas::CONFIGURATION, Areas::EXTENSIONS ), true )
				&& ( is_string( $check['title'] ?? null ) || is_callable( $check['title'] ?? null ) )
				&& in_array( $check['severity'] ?? '', array( 'info', 'low', 'medium', 'high', 'critical' ), true )
				&& is_string( $check['why'] ?? null )
				&& is_string( $check['break_note'] ?? null )
				&& is_callable( $check['test'] ?? null );

			if ( $complete ) {
				$own[ $key ] = array_merge( $check, array( 'hardening_item' => null ) );
			}
		}

		return $own;
	}

	/**
	 * Every check declares the area of the site it is about. The grouping is
	 * asserted in tests rather than defaulted, so a check added without one
	 * fails the suite instead of landing quietly in a catch-all bucket.
	 *
	 * Both `title` and `severity` may be a callable returning the string, which
	 * is why `title_of()` and `severity_of()` exist — several checks decide what
	 * to call a finding only once they have measured it.
	 *
	 * @return array<string, array{group: string, title: string|callable(): string, severity: string|callable(): string, why: string, break_note: string, hardening_item: ?string, test: callable}>
	 */
	public static function all(): array {
		$own = array(
			'recovery_readiness_incomplete' => array(
				'group' => Areas::ACCESS,
				'hardening_item' => null,
				'title' => __( 'Your recovery options aren’t fully set up', 'bettershield' ),
				'severity' => 'low',
				'why' => __( 'If you get locked out, a recovery link, recovery codes or an admin email get you back in. One or more of these is missing or not working.', 'bettershield' ),
				'break_note' => __( 'Nothing changes on your site. This check only looks.', 'bettershield' ),
				'test' => static function (): ?array {
					// A way in the host provides, outside the sign-in form.
					if ( HostProtections::provides( 'recovery' ) ) {
						return null;
					}

					return \BetterShield\Recovery\Readiness::finding();
				},
			),

			/*
			 * The four setup essentials that had no check of their own: each
			 * is one of the setup's 60 points (Auditor::SETUP_POINTS), and
			 * each passes where another plugin already does the job.
			 */
			'privileged_password_only' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				// Said as the reader's own when theirs is the only one.
				'title'          => static function (): string {
					$ids = self::password_only_accounts()['ids'];

					return array( get_current_user_id() ) === $ids && 0 !== get_current_user_id()
						? __( 'Your account signs in with a password alone', 'bettershield' )
						: __( 'Some privileged accounts sign in with a password alone', 'bettershield' );
				},
				// An administrator without a second factor is the account
				// takeover that matters most; an editor or shop manager is
				// still worth a second factor, one step lower.
				'severity'       => static function (): string {
					return self::password_only_accounts()['administrators'] > 0 ? 'high' : 'medium';
				},
				'why'            => __( 'A stolen or guessed password is enough to sign in as these accounts. A second factor or a passkey stops that, even when the password is known.', 'bettershield' ),
				'break_note'     => __( 'Requiring two-factor gives each account a grace period to set it up. Nobody is locked out on the day you turn it on.', 'bettershield' ),
				// Re-read on every overview, so turning the requirement on, or
				// the last account enrolling, shows at once.
				'reread'         => true,
				'test'           => static function (): ?array {
					// A plugin whose two-factor is one switch for the whole site,
					// unless the owner chose BetterShield's over it in the setup.
					// Every other plugin's is read per account below.
					if ( \BetterShield\Onboarding\Coexistence::two_factor_unread_elsewhere( \BetterShield\Onboarding\QuickSetup::state()['coexistence'] ) ) {
						return null;
					}

					$found = self::password_only_accounts();

					if ( 0 === $found['administrators'] + $found['others'] ) {
						return null;
					}

					// Counts only: a finding row is read by every manager of
					// the plugin, and names are for the Users screen.
					return array_filter(
						array(
							'administrators' => $found['administrators'],
							'other_accounts' => $found['others'],
						)
					);
				},
			),

			'recovery_unconfirmed' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Your recovery options aren’t confirmed yet', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'If a setting locks you out, a recovery email or recovery codes get you back in. Neither is confirmed yet.', 'bettershield' ),
				'break_note'     => __( 'Send the recovery email and confirm it arrived, or download the recovery codes. Nothing else on the site changes.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					if ( \BetterShield\Onboarding\QuickSetup::recovery_ready() || HostProtections::provides( 'recovery' ) ) {
						return null;
					}

					return array(
						'link'          => RecoveryLink::usable() ? __( 'Sent, not confirmed yet', 'bettershield' ) : __( 'None', 'bettershield' ),
						'offline_codes' => \BetterShield\Recovery\OfflineCodes::remaining(),
					);
				},
			),

			'directory_browsing_open' => array(
				'group'          => Areas::EXPOSURE,
				'hardening_item' => 'directory_browsing',
				'title'          => __( 'Folders in your uploads can be listed in a browser', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'A folder without an index file can show every file in it to anyone who opens its address, including files you never linked to.', 'bettershield' ),
				'break_note'     => __( 'Fix adds an empty index file to each folder. Your files and links keep working, and you can undo it.', 'bettershield' ),
				'test'           => static function (): ?array {
					// Another security plugin that does it with a switch of its
					// own, as the setup credits it.
					if ( '' !== \BetterShield\Onboarding\Coexistence::applied_elsewhere( 'directory_browsing' ) ) {
						return null;
					}

					$uploads = wp_get_upload_dir();
					$base    = is_array( $uploads ) ? (string) ( $uploads['basedir'] ?? '' ) : '';

					// No uploads folder at all is nothing to list.
					if ( '' === $base || ! is_dir( $base ) ) {
						return null;
					}

					$bare = \BetterShield\Hardening\Item\DirectoryBrowsing::bare_directories( $base, 1 );

					// Or the web server, asked for such a folder, refused to
					// list it.
					if ( array() === $bare || FolderListing::refused() ) {
						return null;
					}

					$base = trailingslashit( wp_normalize_path( $base ) );
					$path = wp_normalize_path( (string) $bare[0] );

					return array( 'folder' => 'wp-content/uploads/' . ltrim( str_starts_with( $path, $base ) ? substr( $path, strlen( $base ) ) : basename( $path ), '/' ) );
				},
			),

			'common_usernames_allowed' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Sign-in tries with common usernames are not refused', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Automated guessing starts with names like admin and test. Refusing names nobody here uses ends those tries before any password is checked.', 'bettershield' ),
				'break_note'     => __( 'Only names no account on this site uses are refused, so nobody who signs in today is affected.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					$offered = \BetterShield\Onboarding\QuickSetup::common_names()['offered'];

					return array() === $offered ? null : array( 'names' => implode( ', ', $offered ) );
				},
			),

			/*
			 * The rest of the sign-in protection a host's panel or the owner
			 * switches on: each a setup item, each re-read so a switch flipped
			 * from outside the dashboard moves the score at once.
			 */
			'reset_form_unprotected' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Repeated password reset requests are not slowed down', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'The lost-password form can be used to flood your users with reset emails or to test which accounts exist.', 'bettershield' ),
				'break_note'     => __( 'People who ask for a reset now and then are not affected. Only repeated requests from one connection wait.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					return self::form_guarded( \BetterShield\Login\Surfaces::RESET ) ? null : array();
				},
			),

			'comment_form_unprotected' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Repeated comment posts are not slowed down', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Automated comment spam arrives in bursts from one connection. Slowing those bursts keeps your comment queue readable.', 'bettershield' ),
				'break_note'     => __( 'A visitor who comments now and then is not affected. A burst is held for review, never thrown away.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					// Comments closed is a form nobody can post to.
					if ( 'closed' === (string) get_option( 'default_comment_status', 'open' ) ) {
						return null;
					}

					return self::form_guarded( \BetterShield\Login\Surfaces::COMMENT ) ? null : array();
				},
			),

			'registration_form_unprotected' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Repeated sign-ups are not slowed down', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Bots fill an open registration form with fake accounts. Slowing repeated sign-ups from one connection stops most of them.', 'bettershield' ),
				'break_note'     => __( 'A person signing up once is not affected. Only repeated sign-ups from one connection wait.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					// Registration closed is a form nobody can use.
					if ( ! self::registration_is_open() ) {
						return null;
					}

					return self::form_guarded( \BetterShield\Login\Surfaces::REGISTER ) ? null : array();
				},
			),

			'form_bot_check_off' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'The hidden bot check on your forms is off', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'A hidden field people never see catches most automated form fills, on sign-in, registration and comments, without asking anyone to solve a puzzle.', 'bettershield' ),
				'break_note'     => __( 'People see nothing new. Only form fills that complete the hidden field are refused.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					$settings = \BetterShield\Login\Protection::instance()->settings();

					return ! empty( $settings['enabled'] ) && ! empty( $settings['honeypot'] ) ? null : array();
				},
			),

			'proof_of_work_off' => array(
				'group'          => Areas::ACCESS,
				'hardening_item' => null,
				'title'          => __( 'Sign-in doesn’t slow down password guessing', 'bettershield' ),
				'severity'       => 'low',
				// Asked only after wrong passwords (ProofOfWork::AFTER_FAILURES),
				// as the Login & Access screen says, not on every sign-in.
				'why'            => __( 'After a few wrong passwords from one connection, the browser solves a small puzzle before the next try. It makes guessing thousands of passwords slow and costly.', 'bettershield' ),
				'break_note'     => __( 'After a few wrong passwords, the next try needs JavaScript. A failed puzzle never locks anyone out.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					$settings = \BetterShield\Login\Protection::instance()->settings();

					return ! empty( $settings['enabled'] ) && ! empty( $settings['proof_of_work'] ) ? null : array();
				},
			),

			/*
			 * The pingback half of XML-RPC, as its own setup item: blocking
			 * pingbacks only earns this, while remote publishing still open
			 * keeps xmlrpc_enabled in site health as before.
			 */
			'pingbacks_open' => array(
				'group'          => Areas::EXPOSURE,
				'hardening_item' => null,
				'title'          => __( 'Other sites can still send pingbacks to yours', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Pingbacks are used to make sites like yours flood others with requests. Few sites rely on them today.', 'bettershield' ),
				'break_note'     => __( 'Other sites can no longer notify yours when they link to it. Everything else that uses XML-RPC keeps working if you block pingbacks only.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					// The item on, all of XML-RPC or its pingbacks only.
					if ( Manager::instance()->is_active( 'xmlrpc' ) ) {
						return null;
					}

					$xmlrpc = self::all()['xmlrpc_enabled']['test'] ?? null;

					return is_callable( $xmlrpc ) && null === $xmlrpc() ? null : array();
				},
			),

			/*
			 * Blocking AI crawlers is a host's job, done at its edge. The host
			 * says so through the filter; with nothing said the item passes,
			 * so every setup point stays earnable on any host.
			 */
			'ai_bots_unblocked' => array(
				'group'          => Areas::EXPOSURE,
				'hardening_item' => null,
				'title'          => __( 'Your host is not blocking AI crawlers', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'AI crawlers can fetch every page of a site many times a day. Your host can turn away the ones that ignore your wishes before they reach WordPress.', 'bettershield' ),
				'break_note'     => __( 'Turn on your host’s AI bot blocker in its control panel. Nothing changes on your site from here.', 'bettershield' ),
				'reread'         => true,
				'test'           => static function (): ?array {
					return false === self::host_ai_bot_blocker() ? array() : null;
				},
			),

			'recovery_link_lapsing' => array(
				'group'      => Areas::ACCESS,
				// Declared even though there is no item to apply: the readers
				// take this key without a default, and a check that leaves it
				// out warns on every overview and every findings read.
				'hardening_item' => null,
				'title'      => static function (): string {
					return self::passkey_only_in_effect()
						? __( 'The recovery link is close to expiring, and passwords are switched off', 'bettershield' )
						: __( 'The recovery link is close to expiring', 'bettershield' );
				},
				/*
				 * The same lapse means two different things.
				 *
				 * On an ordinary site a password still signs the owner in, so
				 * a link running out is a thing to get round to. Where
				 * passkey-only is armed the password is refused, so the link
				 * is the way back — and the guard that made sure one existed
				 * runs when the setting is armed and never again. This is the
				 * only thing that notices afterward.
				 */
				'severity'   => static function (): string {
					return self::passkey_only_in_effect() ? 'high' : 'medium';
				},
				'why'        => __( 'Your recovery link gets you in if you are locked out. It lasts 90 days, so make a new one soon. Without passwords, it may be your only way in.', 'bettershield' ),
				'break_note' => __( 'Generating a new link retires the old one, so replace the copy you have saved.', 'bettershield' ),
				'test'       => static function (): ?array {
					$expires = RecoveryLink::expires_at();

					// No link at all is a different finding, and one this does
					// not want to duplicate.
					if ( null === $expires ) {
						return null;
					}

					$armed = self::passkey_only_in_effect();

					// A fortnight's notice: long enough to act on, short enough
					// that it is not standing on the dashboard for months. Where
					// the password is refused there is nothing else to fall back
					// to, so a lapsed link is reported after the fact as well.
					if ( $armed && $expires <= time() ) {
						return array( 'expires_at' => $expires, 'lapsed' => true, 'passkey_only' => true );
					}

					if ( $expires - time() >= 14 * DAY_IN_SECONDS ) {
						return null;
					}

					return $armed
						? array( 'expires_at' => $expires, 'passkey_only' => true )
						: array( 'expires_at' => $expires );
				},
			),

			'user_listing_public'   => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Anyone can see your usernames', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'WordPress shows usernames to anyone by default, which gives bots half of what they need to sign in.', 'bettershield' ),
				// On plain permalinks every author link is ?author=<id>, which
				// the fix sends home, so every author archive goes dark for a
				// signed-out visitor.
				'break_note'     => '' === (string) get_option( 'permalink_structure' )
					? __( 'Could break: author pages, if your links use plain permalinks (like ?p=123). Visitors who aren’t signed in go to the home page instead.', 'bettershield' )
					: __( 'Could break: author lists read from the public API, which most sites don’t use.', 'bettershield' ),
				'hardening_item' => 'user_enumeration',
				'test'           => static function (): ?array {
					// Another security plugin credited with this item, as the
					// setup and the Hardening card credit it: the same answer
					// here, rather than a finding whose one-click fix the
					// card says not to apply.
					if ( '' !== \BetterShield\Onboarding\Coexistence::applied_elsewhere( 'user_enumeration' ) ) {
						return null;
					}

					if ( ! Manager::instance()->is_active( 'user_enumeration' ) ) {
						return array();
					}

					/*
					 * Switched on is not the same as working. Reading only our
					 * own toggle reported the route closed whenever the setting
					 * said so, even if something had since unhooked us — which
					 * is exactly the case an audit exists to catch. Every route
					 * the item closes is checked, not the two this used to name:
					 * with the REST gate and the author redirect still hooked
					 * and the users sitemap unhooked underneath them, the
					 * finding read resolved while every author's login name was
					 * being served again. Nothing here proves what a visitor
					 * receives, and the copy does not claim it does.
					 */
					if ( ! Manager::instance()->enforcement_attached( 'user_enumeration' ) ) {
						return array( 'reason' => self::why_not_in_force( 'user_enumeration' ) );
					}

					// Attached here says it is hooked in wp-admin, where this
					// audit runs. Only a visitor's page can say it is hooked
					// where it matters.
					$observed = Verification::last_absence( 'user_enumeration' );

					return null === $observed ? null : array( 'reason' => 'not_observed', 'detail' => $observed );
				},
			),

			'lockouts_not_running'  => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Failed sign-ins are not being counted, so password guessing is not stopped', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Your host or CDN hides each visitor’s real address, so BetterShield cannot tell who keeps getting passwords wrong and cannot block them.', 'bettershield' ),
				'break_note'     => __( 'Press Fix and tell BetterShield which service sits in front of your site, such as Cloudflare. Your host can give you the details.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$settings = \BetterShield\Login\Protection::instance()->settings();

					if ( empty( $settings['enabled'] ) || empty( $settings['attempt_limit'] ) ) {
						return null;
					}

					/*
					 * Read from what a real request saw, not from this one.
					 * Asking directly made the answer depend on where the audit
					 * ran: under WP-CLI there is no connecting address at all,
					 * and from a cron tick it is the loopback, so the daily
					 * audit would never raise this while an audit run from the
					 * dashboard behind a proxy always would.
					 */
					$observed = Observed::client_resolution();

					// Nothing observed yet is not the same as nothing working.
					if ( null === $observed || $observed['resolved'] ) {
						return null;
					}

					// Which of four it is, since each asks for something
					// different; read in one place with the Fix panel's.
					return array( 'reason' => \BetterShield\Fixes\ProxySetup::reason( $observed ) );
				},
			),

			/*
			 * The case the check above stands aside for: the limit switched
			 * off. Setup switches it off when the owner keeps another plugin
			 * for the job, and nothing switches it back on when that plugin
			 * goes, so whether anything else is limiting sign-ins is asked on
			 * every audit rather than taken from the setup's answer. Another
			 * plugin's own settings are not read; one that is active and does
			 * the job is taken at its word.
			 */
			'login_attempts_unlimited' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Nothing is limiting sign-in attempts', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Nothing BetterShield recognizes stops someone from guessing passwords over and over. Turn on “Sign-in attempt limits” to block them after a few wrong tries.', 'bettershield' ),
				'break_note'     => __( 'Turn on “Sign-in attempt limits”. People who type their password correctly are not affected. If another plugin already does this, choose “I manage this myself”.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$settings = \BetterShield\Login\Protection::instance()->settings();

					if ( ! empty( $settings['enabled'] ) && ! empty( $settings['attempt_limit'] ) ) {
						return null;
					}

					return array() === \BetterShield\Onboarding\Coexistence::doing( 'login_limits' ) ? array( 'reason' => 'switched_off' ) : null;
				},
			),

			/*
			 * The other half of the check above: BetterShield's limit is on
			 * and so is another plugin's. Each counts every wrong password,
			 * so whichever limit is lower pauses the visitor, and this
			 * plugin's lockout list and unlock link cannot release the other
			 * plugin's pause. Quick Setup asks once; a limiter added later
			 * was never mentioned.
			 *
			 * An owner who chose BetterShield there with that plugin active
			 * kept both on purpose, and is not told again on every audit:
			 * only a limiter activated since that choice, or one no choice
			 * was ever saved over, is raised. Login & Access, where the
			 * finding sends the owner, clears it either way: switching this
			 * limit off there leaves the job to the other plugin, and the
			 * note beside that switch opens the setup's step again, where
			 * saving the choice with the plugins active now covers them.
			 */
			'login_limits_overlap' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Two plugins limit sign-in attempts', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Both plugins block people after wrong passwords. If the other plugin blocks someone, BetterShield cannot unblock them. Keep only one of the two switched on.', 'bettershield' ),
				'break_note'     => __( 'Press Fix to choose which plugin keeps this job.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$settings = \BetterShield\Login\Protection::instance()->settings();

					if ( empty( $settings['enabled'] ) || empty( $settings['attempt_limit'] ) ) {
						return null;
					}

					$setup  = \BetterShield\Onboarding\QuickSetup::state();
					$others = \BetterShield\Onboarding\Coexistence::limiters_not_chosen( $setup['coexistence'], $setup['coexistence_limiters'] );

					return array() === $others ? null : array( 'plugins' => $others );
				},
			),

			'admin_username_exists' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'A user is named “admin”', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Automated login tools try "admin" first, so they already know this account’s username.', 'bettershield' ),
				'break_note'     => __( 'Fix renames this account in place, keeping its posts and ID, and has Undo. Could break: signing in as “admin”; use the new username instead.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$user_id = username_exists( 'admin' );

					if ( false === $user_id || null === $user_id || ! self::this_sites_to_change( (int) $user_id ) ) {
						return null;
					}

					return array( 'user_id' => (int) $user_id );
				},
			),

			'admin_user_id_one'     => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'The original admin account (user ID 1) is still an administrator', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Bots go after user ID 1 because nearly every WordPress site has an admin there. Renaming it doesn’t help, because the ID stays the same.', 'bettershield' ),
				'break_note'     => __( 'Create a new administrator, sign in as them, then delete this account and give its posts to the new one. Nothing changes until you do.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$user = get_user_by( 'id', 1 );

					if ( ! $user instanceof \WP_User ) {
						return null; // Already gone, which is the point of the check.
					}

					if ( ! self::this_sites_to_change( 1 ) ) {
						return null;
					}

					// An account demoted out of administrator is not the risk.
					return user_can( $user, 'manage_options' ) ? array( 'user_id' => 1 ) : null;
				},
			),

			'role_unfiltered_below_admin' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Non-admin users can add code that runs in visitors’ browsers', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'People with these roles can add scripts to posts or uploads. The scripts run for everyone who views them, including admins. Editors can by default and are not listed.', 'bettershield' ),
				'break_note'     => __( 'Fix lets only administrators add scripts. Your roles aren’t edited. Could break: a plugin that gave these roles this power on purpose.', 'bettershield' ),
				'hardening_item' => is_multisite() ? null : 'unfiltered_code',
				'test'           => static function (): ?array {
					return self::unfiltered_roles();
				},
			),

			'admin_password_storage' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Some admin passwords are saved the old, less secure way', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'WordPress now saves passwords in a much safer way, but only after each person signs in again. Until then, these passwords are easier to crack if your database leaks.', 'bettershield' ),
				'break_note'     => __( 'Ask each of them to sign in once. Nobody needs a new password.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					/*
					 * WordPress 6.8 is where bcrypt replaced phpass. Before it,
					 * every password on every site was stored the old way, so
					 * reporting it would be a finding nobody could act on — the
					 * remedy there is updating WordPress, which its own check
					 * already covers.
					 *
					 * Compared by version rather than by asking whether
					 * wp_password_needs_rehash() exists, because that function
					 * arrived in the same release and naming it would put a
					 * 6.8-only call in a plugin whose floor is below that.
					 */
					// Against the alpha, so a pre-release of the version that
					// carries the function is not read as the version before
					// it: version_compare sorts every pre-release tag below
					// the release, and this check would otherwise be skipped
					// on precisely the builds testing it.
					if ( version_compare( (string) get_bloginfo( 'version' ), '6.8-alpha', '<' ) ) {
						return null;
					}

					// Administrators only: a bounded set, and the accounts where
					// this actually matters. On a membership site the same query
					// across every user would scan a table with no index for it.
					$administrators = get_users(
						array(
							'role'   => 'administrator',
							'fields' => array( 'ID', 'user_pass' ),
						)
					);

					$outdated = 0;
					$unsalted = 0;
					foreach ( $administrators as $administrator ) {
						/*
						 * Only hashes that positively look like phpass count —
						 * the prefixes core itself recognizes as the old format.
						 * A site running its own password hasher is left alone
						 * rather than told its passwords are weak on a guess.
						 */
						$prefix = substr( (string) $administrator->user_pass, 0, 3 );

						if ( '$P$' === $prefix || '$H$' === $prefix ) {
							++$outdated;
						} elseif ( 1 === preg_match( '/^[a-f0-9]{32}$/', (string) $administrator->user_pass ) ) {
							/*
							 * Plain MD5, the shape core's own MD5 branch accepts
							 * and rehashes at the next sign-in: what a reset
							 * through phpMyAdmin's MD5() leaves. Unsalted, so a
							 * copy of it falls to public lookup tables at once.
							 */
							++$outdated;
							++$unsalted;
						}
					}

					if ( 0 === $outdated ) {
						return null;
					}

					// Counts and nothing else. The stored password is read to
					// look at its format and is never recorded anywhere.
					return $unsalted > 0 ? array( 'accounts' => $outdated, 'unsalted' => $unsalted ) : array( 'accounts' => $outdated );
				},
			),

			'abilities_writable_low_privilege' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'A plugin lets any signed-in user, even a Subscriber, make changes to the site', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Any signed-in account, or an AI assistant signed in as one, can use this plugin feature to change your site.', 'bettershield' ),
				'break_note'     => __( 'Fix lets only administrators use it until the plugin is updated. Could break: other users or AI assistants that rely on it.', 'bettershield' ),
				'hardening_item' => 'ability_access',
				'test'           => static function (): ?array {
					if ( ! \BetterShield\Abilities\Registrar::is_available() ) {
						return null;
					}

					// Other plugins' abilities exist whether or not this
					// plugin's own are enabled; watching them is the job.
					$writes = \BetterShield\Abilities\AgentSurface::low_privilege_writes();

					if ( array() === $writes ) {
						return null;
					}

					return array(
						'abilities' => implode( ', ', $writes ),
						'count'     => count( $writes ),
					);
				},
			),

			/*
			 * Another plugin's MCP server that takes calls from anyone. Read
			 * from the REST routes, never called: the route's permission
			 * check is missing or answers yes to everybody (#1877).
			 */
			'mcp_endpoint_unauthenticated' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Another plugin lets AI assistants use your site without signing in', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Anyone can connect an AI assistant to this plugin and use its tools. Plugins like this have given strangers admin access before.', 'bettershield' ),
				'break_note'     => __( 'Update the plugin, turn off its AI connection or its no-sign-in option, or deactivate it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$open = array_values( array_filter( \BetterShield\Abilities\McpEndpoints::report(), static fn( array $row ): bool => $row['open'] ) );

					if ( array() === $open ) {
						return null;
					}

					return array(
						'endpoints' => array_map( static fn( array $row ): string => $row['route'] . ' (' . $row['owner_label'] . ')', $open ),
						'count'     => count( $open ),
					);
				},
			),

			'application_passwords_stale' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Some app passwords haven’t been used for months', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Apps and AI assistants use these to sign in to your site. An old one still works, and nobody would notice if it leaked.', 'bettershield' ),
				'break_note'     => __( 'Could break: any app still using it. Each user can delete their own under Users › Profile › Application Passwords.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$stale = \BetterShield\Abilities\AgentSurface::stale_password_summary();

					if ( 0 === $stale['accounts'] ) {
						return null;
					}

					// Counts only: which accounts hold dormant credentials is
					// for the Agent surface screen, not a stored evidence row.
					return $stale;
				},
			),

			'privileged_app_password_unlimited' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'An administrator’s app password has no limits', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'It skips the two-factor code, works from anywhere and can do everything the account can. Limit it to the routes and network it needs.', 'bettershield' ),
				'break_note'     => __( 'Could break: an app that uses it outside the limit you set.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					// The block item refuses administrators' passwords in both
					// of its modes, so an unlimited one cannot be used.
					if ( ! wp_is_application_passwords_available() || \BetterShield\Hardening\Manager::instance()->is_active( 'application_passwords' ) ) {
						return null;
					}

					$unlimited = \BetterShield\Abilities\AgentSurface::unlimited_privileged_password_summary();

					// Counts only, as for the stale passwords above.
					return 0 === $unlimited['accounts'] ? null : $unlimited;
				},
			),

			'passwords_below_policy' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Some people still use passwords weaker than your password rules', 'bettershield' ),
				// A weak administrator password and a weak subscriber password
				// are different findings wearing the same key.
				'severity'       => static function (): string {
					return \BetterShield\Password\Policy::instance()->flagged()['privileged'] > 0 ? 'medium' : 'low';
				},
				'why'            => __( 'These were set before you turned on the password rules. Each account stays on this list until that person changes their password.', 'bettershield' ),
				// True for both rows the Fix panel can show: a reset for
				// somebody else, the profile for the reader's own account.
				'break_note'     => __( 'Fix asks each person listed for a new password the next time they sign in, and you can undo it. If yours is listed, change it on your profile instead.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					if ( ! \BetterShield\Password\Policy::instance()->settings()['enabled'] ) {
						return null;
					}

					$flagged = \BetterShield\Password\Policy::instance()->flagged();

					if ( 0 === $flagged['total'] ) {
						return null;
					}

					// Counts only: a stored list of exactly which accounts
					// have weak passwords would be a shopping list. The
					// per-account flag lives in user meta, admin-readable.
					return array(
						'accounts'   => $flagged['total'],
						'privileged' => $flagged['privileged'],
						// The total is the database's count whatever the
						// bound; false says the privileged count came from
						// the accounts one pass reads, not every one of them.
						'complete'   => $flagged['complete'],
					);
				},
			),

			'claims_unreadable'     => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Sign-ins are being refused because BetterShield cannot save to the database', 'bettershield' ),
				'severity'       => 'critical',
				'why'            => __( 'BetterShield cannot write to the database, so it refuses every sign-in, even with the right password. Your recovery link still gets you in.', 'bettershield' ),
				'break_note'     => __( 'Deactivate and reactivate BetterShield. If this finding stays, ask your host to check that the database lets WordPress create and change tables.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$failed = get_option( 'bettershield_claims_failed', false );

					// Written by the statement that could not run, and removed
					// by the next one that can — so this reports what was
					// actually observed rather than probing the table itself,
					// which would report only one of the ways it can fail.
					if ( false === $failed || '' === (string) $failed ) {
						return null;
					}

					return array( 'observed_at' => (string) $failed );
				},
			),

			'core_update_available' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'A WordPress core update is available', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'WordPress updates often fix security problems, and those problems are targeted within hours once made public.', 'bettershield' ),
				'break_note'     => __( 'Update from Dashboard → Updates. Your host may also offer staged updates.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function () {
					$data = self::fresh_update_cache( 'update_core' );

					if ( is_wp_error( $data ) ) {
						return $data;
					}

					$offer = self::core_offer( $data );

					return '' === $offer ? null : array( 'available' => $offer );
				},
			),

			'plugin_updates_available' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Plugins have updates available', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Most WordPress compromises come through known plugin flaws that updates have already fixed.', 'bettershield' ),
				// Not "from Dashboard → Updates": the fix panel updates them itself (#2483).
				'break_note'     => __( 'Test on staging first if a plugin is business-critical.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function () {
					$data = self::fresh_update_cache( 'update_plugins' );

					if ( is_wp_error( $data ) ) {
						return $data;
					}

					$count = self::plugin_offers( $data );

					return 0 === $count ? null : array( 'count' => $count );
				},
			),

			'own_auto_updates_off'  => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Automatic updates are off for BetterShield', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'New releases, and the security fixes in them, wait until someone presses Update.', 'bettershield' ),
				'break_note'     => __( 'This does the same as “Enable auto-updates” for BetterShield on the Plugins screen. On a network, a network administrator does this from the main site.', 'bettershield' ),
				// One press on a network too, from the main site, where the
				// network's list is set (#2568): no Open Plugins dead end.
				'hardening_item' => 'own_auto_updates',
				'test'           => static function () {
					// A network's plugin auto-updates are set on its Plugins
					// screen, which a site administrator cannot open: on any
					// other site it cost points nobody there could win back,
					// and the main site carries it for the network (#2182).
					if ( is_multisite() && ! is_main_site() ) {
						return new \WP_Error( 'bettershield_audit_not_applicable', __( 'On a network, plugin auto-updates are set by a network administrator. The main site reports this.', 'bettershield' ) );
					}

					return self::own_auto_updates_off();
				},
			),

			'php_end_of_life'       => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'This PHP version no longer receives security fixes', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Any PHP security flaw found from now on stays unfixed on this version.', 'bettershield' ),
				'break_note'     => __( 'You can usually change your PHP version in your hosting panel. Check your site afterward.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					// The version the site SERVES pages with, not the one this
					// process happens to be. A host whose CLI and web PHP differ
					// used to get a different answer, and a different score,
					// depending on where the audit ran.
					$parts  = explode( '.', Observed::php_version() );
					$branch = ( $parts[0] ?? '' ) . '.' . ( $parts[1] ?? '' );

					if ( ! isset( self::PHP_EOL[ $branch ] ) ) {
						return null;
					}

					if ( gmdate( 'Y-m-d' ) <= self::PHP_EOL[ $branch ] ) {
						return null;
					}

					return array(
						'branch'    => $branch,
						'eol_since' => self::PHP_EOL[ $branch ],
					);
				},
			),

			'site_not_https'        => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'The site address is not HTTPS', 'bettershield' ),
				/*
				 * Critical is reserved for something wrong right now rather
				 * than a door left open, and this is one of the three checks
				 * that reach it: credentials already traveling in the clear, on
				 * every request, now. On a local or staging host
				 * plain HTTP is ordinary, so it grades as high there instead of
				 * turning every development install red.
				 */
				'severity'       => static function (): string {
					return Environment::is_production() ? 'critical' : 'high';
				},
				'why'            => __( 'Passwords and sign-in details are sent unencrypted, so anyone on the same network can read them.', 'bettershield' ),
				// A network keeps a site's addresses on its own screen, not on
				// Settings → General, and only its administrator can open it.
				'break_note'     => is_multisite()
					? __( 'Ask your host for a free SSL certificate. The network administrator then switches this site to https under Network Admin › Sites.', 'bettershield' )
					: __( 'Ask your host for a free SSL certificate, then press Fix to switch your site to https. On a test site on your computer, mark this not applicable.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					/*
					 * Switched by the fix and not yet kept: it goes back on its
					 * own in minutes, so it is not settled, and the finding
					 * stays open to carry the panel Keep HTTPS is pressed on.
					 */
					$pending = \BetterShield\Hardening\Item\HttpsAddress::pending_until();

					if ( null !== $pending ) {
						return array(
							'scheme'  => 'https',
							'address' => 'site_address',
							'goes_back_at' => gmdate( 'c', $pending ),
						);
					}

					// The stored address, not home_url(): core upgrades that to
					// https on any request that arrived over HTTPS, so a live
					// read on such a request called a plain-HTTP site fixed.
					$scheme = wp_parse_url( (string) get_option( 'home' ), PHP_URL_SCHEME );

					if ( 'https' !== $scheme ) {
						return array(
							'scheme'  => (string) $scheme,
							'address' => 'site_address',
						);
					}

					/*
					 * Credentials go to the WordPress address, not the site
					 * address: the sign-in form posts there, the dashboard and
					 * the cookies are served from it. FORCE_SSL_ADMIN puts both
					 * on HTTPS whatever the address says. Otherwise the stored
					 * address is read, not site_url( …, 'login_post' ): core
					 * answers that from the request it is asked on, so an audit
					 * run by cron or WP-CLI would read plain HTTP everywhere.
					 */
					if ( force_ssl_admin() ) {
						return null;
					}

					$scheme = wp_parse_url( (string) get_option( 'siteurl' ), PHP_URL_SCHEME );

					return 'https' === $scheme ? null : array(
						'scheme'  => (string) $scheme,
						'address' => 'wordpress_address',
					);
				},
			),

			'disclosure_contact_lapsing' => array(
				'group'          => Areas::EXPOSURE,
				/*
				 * Two titles and two severities, for the reason the
				 * certificate check has them: a date that has passed is not a
				 * warning about the future, and "about to expire" beside a
				 * contact that lapsed eight months ago is the check failing to
				 * read what it just measured.
				 */
				'title'          => static function (): string {
					$days = \BetterShield\Disclosure\SecurityTxt::instance()->days_until_expiry();

					return ( null !== $days && $days < 0 )
						? __( 'Your security contact file (security.txt) has expired', 'bettershield' )
						: __( 'Your security contact file (security.txt) expires soon', 'bettershield' );
				},
				/*
				 * Medium rather than higher once it has passed: a finder has
				 * been misled, which is what this file exists to prevent, but
				 * no door has been opened by it.
				 */
				'severity'       => static function (): string {
					$days = \BetterShield\Disclosure\SecurityTxt::instance()->days_until_expiry();

					return ( null !== $days && $days < 0 ) ? 'medium' : 'low';
				},
				'why'            => __( 'After it expires, people who find a security problem on your site may not know how to reach you.', 'bettershield' ),
				'break_note'     => __( 'Renew it for another year, or turn the file off in Settings.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$days = \BetterShield\Disclosure\SecurityTxt::instance()->days_until_expiry();

					if ( null === $days || $days > 30 ) {
						return null;
					}

					return array( 'days_left' => $days );
				},
			),

			/*
			 * Cron is where a backdoor re-establishes itself, and WordPress
			 * offers no screen for it at all. This states one provable thing —
			 * nothing answered this hook — and refuses to guess the rest.
			 */
			/*
			 * A closed listing is a leading signal no advisory feed carries:
			 * closure usually precedes public disclosure, and it always means
			 * no future fixes. The directory does not publish why, so neither
			 * does this.
			 */
			'plugin_closed_in_directory' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'An installed plugin is no longer in the WordPress.org directory', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'It will get no more updates, and WordPress.org does not say why. Closure is often the first public sign of a security problem.', 'bettershield' ),
				'break_note'     => __( 'Check the author’s site first: some closures are the author’s choice, not a security issue.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$items  = \BetterShield\Vulnerabilities\Inventory::collect();
					$closed = \BetterShield\Vulnerabilities\Directory::closed( $items );

					if ( array() === $closed ) {
						return null;
					}

					$coverage = \BetterShield\Vulnerabilities\Directory::coverage( $items );

					return array(
						'plugins'   => $closed,
						'total'     => count( $closed ),
						// A few plugins are asked about per run, so until every
						// listed one has an answer the total is a floor, and the
						// two counts say how far the sweep has got.
						'complete'  => \BetterShield\Vulnerabilities\Directory::examined_all( $items ),
						'checked'   => $coverage['checked'],
						'unchecked' => $coverage['unchecked'],
					);
				},
			),

			/*
			 * A loose PHP file or a folder of PHP with no plugin header is
			 * loaded by nothing WordPress lists, so no screen shows it. Named,
			 * never read: the header is the only thing looked at, the same one
			 * WordPress reads to build its plugin list.
			 */
			'plugins_directory_unclaimed' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'There are files in your plugins folder that don’t belong to any plugin', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'These files don’t show on the Plugins screen and never get updates. Usually they are leftovers, but sometimes someone put them there on purpose.', 'bettershield' ),
				'break_note'     => __( 'Check each one before removing it. A plugin may still use it, so download a copy first.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$report = \BetterShield\Audit\PluginsDirectory::report();

					// Unreadable is not empty: a directory nobody could list
					// says nothing about what is in it.
					if ( ! $report['readable'] ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'The plugins folder could not be listed.', 'bettershield' ) );
					}

					if ( 0 === $report['total'] ) {
						return null;
					}

					return array(
						'files'    => array_slice( $report['items'], 0, \BetterShield\Audit\PluginsDirectory::MAX_NAMED ),
						'total'    => $report['total'],
						'complete' => $report['complete'],
					);
				},
			),

			/*
			 * From the answer the closed-plugin sweep already gets: no new
			 * request, and nothing sent that was not sent before. The date is
			 * stated as the directory gives it, with no word for why.
			 */
			'plugin_not_updated_in_directory' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'An installed plugin has had no WordPress.org update for years', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Some small plugins are simply finished, but if nobody maintains one, a flaw found in it may never be fixed.', 'bettershield' ),
				'break_note'     => __( 'Check the plugin’s page and the author’s site first: a newer release may be elsewhere.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$items = \BetterShield\Vulnerabilities\Inventory::collect();
					$stale = \BetterShield\Vulnerabilities\Directory::stale( $items );

					if ( array() === $stale ) {
						return null;
					}

					$coverage = \BetterShield\Vulnerabilities\Directory::dated_coverage( $items );

					return array(
						'plugins'         => $stale,
						'total'           => count( $stale ),
						// The sweep asks about a few plugins a day, so until
						// each has a dated answer the total is a floor.
						'complete'        => 0 === $coverage['unchecked'],
						'checked'         => $coverage['checked'],
						'unchecked'       => $coverage['unchecked'],
						'older_than_days' => \BetterShield\Vulnerabilities\Directory::stale_after_days(),
					);
				},
			),

			/*
			 * The one check that asks rather than reasons. "Your .git/config
			 * is downloadable, here is the address" is a fact somebody can
			 * verify in five seconds; "your server might serve dotfiles" is
			 * not, and it is the one an owner ignores.
			 */
			'artifacts_downloadable' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Files that should be private can be downloaded from this site', 'bettershield' ),
				'severity'       => 'critical',
				'why'            => __( 'BetterShield tried to download each file below from your site, and it worked. Files like these usually contain passwords and keys.', 'bettershield' ),
				'break_note'     => __( 'Fix blocks these files from being downloaded, if your server allows it. If your server ignores this, move each file listed under Evidence out of your site’s public folder.', 'bettershield' ),
				'hardening_item' => 'sensitive_files',
				'test'           => static function (): array|\WP_Error|null {
					$last = \BetterShield\Audit\ExposedArtifacts::last();

					// Never asked, or asked and the answers cannot be
					// believed — a site that answers 200 to everything, or
					// one this server could not reach from inside. None of
					// those is a finding, and the last two are specifically
					// not one: reporting either would be a false alarm about
					// credentials.
					if ( null === $last || empty( $last['reliable'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', SelfRequest::reason( $last['failure'] ?? null, __( 'This test could not get a clear answer this time.', 'bettershield' ) ) );
					}
					if ( array() === (array) $last['exposed'] ) {
						return null;
					}

					$files = (array) $last['exposed'];

					/*
					 * Where the rule that hides these cannot apply on this
					 * server, each backup, dump or log can be moved into
					 * quarantine instead. `.git` and `.env` cannot: a deploy,
					 * or the application that reads them, breaks when they
					 * move.
					 */
					if ( ! \BetterShield\Hardening\Manager::instance()->available( 'sensitive_files' ) ) {
						foreach ( $files as $index => $file ) {
							$path = is_array( $file ) ? (string) ( $file['path'] ?? '' ) : '';

							$files[ $index ] = (array) $file + array(
								'quarantine' => null !== \BetterShield\Audit\ExposedArtifacts::artifact_file( $path ),
								'too_large'  => \BetterShield\Audit\ExposedArtifacts::artifact_too_large( $path ),
							);
						}
					}

					return array(
						'files'      => $files,
						'total'      => count( $files ),
						'complete'   => true,
						'checked_at' => (string) $last['checked_at'],
					);
				},
			),

			/*
			 * Asked by the same probe, under the same rule: nothing is
			 * reported unless the address answered and what came back is the
			 * tool itself, and a site whose answers cannot be believed is a
			 * stated "could not tell".
			 */
			'leftover_tools_reachable' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'A leftover setup or database tool is publicly reachable', 'bettershield' ),
				'severity'       => static function (): string {
					$last  = \BetterShield\Audit\ExposedArtifacts::last();
					$order = array( 'medium', 'high', 'critical' );
					$worst = 0;

					foreach ( (array) ( $last['tools'] ?? array() ) as $tool ) {
						$level = array_search( \BetterShield\Audit\ExposedArtifacts::tool_severity( (string) ( $tool['kind'] ?? '' ) ), $order, true );
						$worst = max( $worst, false === $level ? 0 : (int) $level );
					}

					return $order[ $worst ];
				},
				'why'            => __( 'Anyone who finds it can use it to change or copy your site. BetterShield only looked at these files and did not run them.', 'bettershield' ),
				'break_note'     => __( 'Quarantine moves the tool to a safe place. You can put it back from File Changes.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$last = \BetterShield\Audit\ExposedArtifacts::last();

					// Asked before this check existed, or asked and not
					// believable, the run or its tool sweep: neither is an
					// answer about these tools.
					if ( null === $last || empty( $last['reliable'] ) || ! isset( $last['tools'] ) || false === ( $last['tools_reliable'] ?? true ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', SelfRequest::reason( $last['tools_failure'] ?? $last['failure'] ?? null, __( 'This test could not get a clear answer this time.', 'bettershield' ) ) );
					}

					// Archives past the few one run asks about were never asked
					// about, and any of them could be downloadable.
					$unasked = (int) ( $last['archives_unasked'] ?? 0 );

					if ( array() === (array) $last['tools'] ) {
						return 0 === $unasked ? null : new \WP_Error( 'bettershield_audit_unknown', __( 'Your site folder has more site-migration backups than we could check at once. Move the ones you don’t need off the site.', 'bettershield' ) );
					}

					$tools = array();

					foreach ( (array) $last['tools'] as $tool ) {
						$kind    = (string) ( $tool['kind'] ?? '' );
						$tools[] = array(
							'path'      => (string) ( $tool['path'] ?? '' ),
							'kind'      => $kind,
							'means'     => \BetterShield\Audit\ExposedArtifacts::tool_means( $kind ),
							'severity'  => \BetterShield\Audit\ExposedArtifacts::tool_severity( $kind ),
							'too_large' => \BetterShield\Audit\ExposedArtifacts::too_large_to_quarantine( (array) $tool ),
						);
					}

					return array(
						'tools'      => $tools,
						'total'      => count( $tools ),
						'complete'   => 0 === $unasked,
						'checked_at' => (string) $last['checked_at'],
					);
				},
			),

			/*
			 * Asked, not reasoned: one request to admin-ajax naming an origin
			 * nobody can own, and the two headers that decide whether a
			 * browser shares a signed-in answer with it. The REST API's own
			 * policy is recorded and never reported; see CrossOrigin.
			 */
			'cross_origin_credentials' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Other websites can read private data from your site for signed-in visitors', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'BetterShield tested with a fake website and your site let it in. Any page a signed-in visitor opens could read their private data from your site.', 'bettershield' ),
				'break_note'     => __( 'Fix lets only your own site read this data. Could break: a separate app or website that talks to your site, until you add its address.', 'bettershield' ),
				'hardening_item' => self::cross_origin_fix(),
				'test'           => static function (): array|\WP_Error|null {
					$last = \BetterShield\Audit\CrossOrigin::last();

					if ( null !== $last && empty( $last['reliable'] ) && 'elsewhere' === ( $last['reason'] ?? '' ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'Your site’s background request address is on a different domain, so this could not be tested.', 'bettershield' ) );
					}

					if ( null === $last || empty( $last['reliable'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', SelfRequest::reason( $last['failure'] ?? null, __( 'This test could not get a clear answer this time.', 'bettershield' ) ) );
					}

					if ( array() === (array) ( $last['open'] ?? array() ) ) {
						return null;
					}

					$open = array();

					foreach ( (array) $last['open'] as $row ) {
						$open[] = array(
							'endpoint' => 'admin-ajax.php',
							'source'   => \BetterShield\Audit\CrossOrigin::describe_source( (array) ( $row['source'] ?? array() ) ),
						);
					}

					return array(
						'open'       => $open,
						'origin'     => \BetterShield\Audit\CrossOrigin::FOREIGN,
						'checked_at' => (string) $last['checked_at'],
					);
				},
			),

			/*
			 * Asked, not reasoned: the sign-in page twice, as a visitor with
			 * no cookies, and only a response a cache says it served is
			 * reported.
			 */
			'sign_in_page_cached'      => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'Your sign-in page is being cached', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Everyone sees the same saved copy, so a correct password can fail, or one person’s lockout message can show to others.', 'bettershield' ),
				'break_note'     => __( 'In your caching plugin or hosting panel, turn off caching for your sign-in page.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$last = \BetterShield\Audit\SignInCache::last();

					if ( null === $last || empty( $last['reliable'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', SelfRequest::reason( $last['failure'] ?? null, __( 'The sign-in page could not be tested from this server.', 'bettershield' ) ) );
					}

					if ( empty( $last['cached'] ) ) {
						return null;
					}

					$headers = array();

					foreach ( (array) ( $last['signals'] ?? array() ) as $signal ) {
						$headers[] = (string) ( $signal['header'] ?? '' ) . ': ' . (string) ( $signal['value'] ?? '' );
					}

					return array(
						// As asked for; an answer stored before that was kept
						// has only the path below the home address.
						'address' => '' !== (string) ( $last['address'] ?? '' ) ? (string) $last['address'] : '/' . ltrim( (string) ( $last['path'] ?? '' ), '/' ),
						'headers' => implode( ', ', $headers ),
					);
				},
			),

			'xmlrpc_enabled'        => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => static function ( ?string $severity = null ): string {
					// The row's own severity where there is one: low is what
					// this records with pingbacks already blocked.
					$partial = null !== $severity ? 'low' === $severity : self::pingbacks_only_blocked();

					return $partial
						? __( 'Pingbacks are blocked, and the rest of XML-RPC is still on', 'bettershield' )
						: __( 'Old remote publishing (XML-RPC) is turned on', 'bettershield' );
				},
				/*
				 * Pingbacks have their own setup item, which blocking them
				 * earns. What is left here is the sign-in surface, which
				 * the sign-in limits cover too, so it weighs less.
				 */
				'severity'       => static function (): string {
					return self::pingbacks_only_blocked() ? 'low' : 'medium';
				},
				'why'            => __( 'Most sites no longer use this old remote-access API, and automated login attempts often target it.', 'bettershield' ),
				'break_note'     => __( 'Could break: the WordPress mobile app and Jetpack, if you publish through them.', 'bettershield' ),
				'hardening_item' => 'xmlrpc',
				// Re-read on every screen load: a host's panel can switch the
				// item, or only its pingbacks, without an audit running.
				'reread'         => true,
				'test'           => static function (): ?array {
					// Core's own filter, read rather than declared: asking it is
					// the only accurate way to learn whether WordPress serves
					// XML-RPC, since any plugin may already have turned it off.
					// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
					if ( ! apply_filters( 'xmlrpc_enabled', true ) ) {
						return null;
					}

					/*
					 * And whether anybody can reach it: many hosts refuse
					 * xmlrpc.php at the web server, before WordPress runs. The
					 * probe says so only when it can stand behind it; anything
					 * it could not tell leaves the filter's answer.
					 */
					if ( \BetterShield\Audit\XmlRpc::blocked() ) {
						return null;
					}

					/*
					 * Pingbacks only leaves the endpoint answering, so this stays
					 * open; it says why, rather than standing beside a switch that
					 * reads On with nothing to explain the difference.
					 */
					if ( self::pingbacks_only_blocked() ) {
						return array( 'detail' => __( 'Pingbacks are blocked. The rest of XML-RPC, sign-ins included, still answers.', 'bettershield' ) );
					}

					return array();
				},
			),

			'file_editor_enabled'   => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'The dashboard file editor is enabled', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Any administrator can edit plugin and theme code from the dashboard. If someone takes over an admin account, this is the first thing they use.', 'bettershield' ),
				// On a network's other sites the editors live in Network Admin,
				// which runs as the main site: this site cannot change them, so
				// no fix is offered here, and the note says who can (#2089).
				'break_note'     => is_multisite() && ! is_main_site()
					? __( 'On a network, only a network administrator can turn the code editors off, from the main site. You can still edit files through your host.', 'bettershield' )
					: __( 'You can still edit files through your host.', 'bettershield' ),
				'hardening_item' => is_multisite() && ! is_main_site() ? null : 'file_editor',
				'test'           => static function () {
					if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
						return null;
					}

					// Core refuses the three editor capabilities whenever file
					// changes are not allowed — DISALLOW_FILE_MODS, or the
					// filter behind it — and asks exactly this to decide.
					if ( ! wp_is_file_mod_allowed( 'capability_edit_themes' ) ) {
						return null;
					}

					// Another security plugin credited with this item, as the
					// setup and the Hardening card credit it: the same answer
					// here, rather than a finding whose one-click fix the
					// card says not to apply.
					if ( '' !== \BetterShield\Onboarding\Coexistence::applied_elsewhere( 'file_editor' ) ) {
						return null;
					}

					/*
					 * The stored flag says what was configured; the filter says
					 * what is enforcing right now. Reading the flag called this
					 * resolved during safe mode, when nothing is hooked at all
					 * — one audit run, with the checks that probe reality
					 * re-opening and this one staying green.
					 */
					/*
					 * On a network's other sites the answer is the main site's:
					 * applied there, the editors are gone from Network Admin,
					 * and applied here, they are not. The site's own item
					 * closed this while the network still had them, and the
					 * network removing them left it open (#2089).
					 */
					if ( is_multisite() && ! is_main_site() ) {
						if ( Manager::instance()->active_on_main_site( 'file_editor' ) ) {
							return null;
						}

						/*
						 * Only network administrators hold the editors here, as
						 * the Hardening card says, so the finding cost points
						 * nobody on this site could act on (#2182). It stands
						 * where a site administrator has been given them; the
						 * main site carries it for the network.
						 */
						return self::site_admins_edit_files()
							? array( 'reason' => 'network_admin' )
							: new \WP_Error( 'bettershield_audit_not_applicable', __( 'On a network, only network administrators have the file editors. The main site reports this.', 'bettershield' ) );
					}

					return Manager::instance()->enforcement_attached( 'file_editor' ) ? null : array( 'reason' => self::why_not_in_force( 'file_editor' ) );
				},
			),

			/*
			 * The mail server refusing alerts was said by an info row and the
			 * test button alone, so a site whose critical alerts were all
			 * refused looked like a quiet one (#2251). Until an alert is
			 * accepted again; a site with alerts muted or off sends nothing to
			 * refuse.
			 */
			'alerts_undeliverable' => array(
				'group' => Areas::CONFIGURATION,
				'hardening_item' => null,
				'title' => __( 'Security alerts are not being delivered', 'bettershield' ),
				'severity' => 'high',
				'why' => __( 'Your site’s email server refused the last alert, so you may miss important ones. Check your email settings or SMTP plugin, then send a test.', 'bettershield' ),
				'break_note' => __( 'This check only reads whether the last alert was accepted.', 'bettershield' ),
				'test' => static function (): ?array {
					$refused = \BetterShield\Alerts\Mailer::refused();

					if ( null === $refused || \BetterShield\Alerts\Settings::instance()->sends_nothing() ) {
						return null;
					}

					return array( 'refused_at' => gmdate( 'c', $refused['at'] ), 'kind' => $refused['kind'] );
				},
			),

			/*
			 * Read from what the daily lookup stored, never looked up here:
			 * a slow resolver must not hold up the audit.
			 */
			'domain_mail_records'      => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => static function ( ?string $severity = null ): string {
					$last = \BetterShield\Audit\DomainRecords::last();

					// The row's own severity where there is one: medium is
					// what this records a spoofable domain at. The latest
					// lookup may not have been able to tell.
					$spoofing = null !== $severity
						? 'medium' === $severity
						: \BetterShield\Audit\DomainRecords::allows_spoofing( (array) ( $last['problems'] ?? array() ) );

					return $spoofing
						? __( 'Fake mail from this site’s domain is hard to spot', 'bettershield' )
						: __( 'Your domain’s email and SSL settings could be stronger', 'bettershield' );
				},
				'severity'       => static function (): string {
					$last = \BetterShield\Audit\DomainRecords::last();

					return \BetterShield\Audit\DomainRecords::allows_spoofing( (array) ( $last['problems'] ?? array() ) ) ? 'medium' : 'low';
				},
				'why'            => __( 'Without these domain settings, scammers can send email that looks like it’s from your site. BetterShield shows the exact records to add.', 'bettershield' ),
				'break_note'     => __( 'Could break: email from a service you forget to list. BetterShield shows safe starting values. Make the change where you bought your domain.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$last = \BetterShield\Audit\DomainRecords::last();

					// A name nobody answers for has no records to miss: not
					// evaluated, and a finding opened before is closed.
					if ( null !== $last && 'not_public' === ( $last['reason'] ?? '' ) ) {
						return new \WP_Error( 'bettershield_audit_not_applicable', __( 'Public DNS does not answer for this site’s domain, so mail records were not looked up.', 'bettershield' ) );
					}

					if ( null === $last || empty( $last['reliable'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'We couldn’t look up your domain’s settings from this server.', 'bettershield' ) );
					}

					$problems = (array) ( $last['problems'] ?? array() );

					if ( array() === $problems ) {
						return null;
					}

					$domain   = (string) ( $last['domain'] ?? '' );
					$evidence = array( 'domain' => $domain );

					foreach ( $problems as $problem ) {
						$family              = strtok( (string) $problem, '_' );
						$evidence[ $family ] = \BetterShield\Audit\DomainRecords::describe( (string) $problem, $domain );
					}

					return $evidence;
				},
			),

			// Read from the operating system as the audit runs: one call
			// per volume, and nothing to wait on.
			'disk_space_low'           => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'The disk this site writes to is almost full', 'bettershield' ),
				'severity'       => static function (): string {
					return 'critical' === \BetterShield\Audit\DiskSpace::worst() ? 'high' : 'medium';
				},
				'why'            => __( 'When the disk is full, updates can fail halfway and BetterShield can’t log activity. Your hosting plan may allow less space than this shows.', 'bettershield' ),
				'break_note'     => __( 'Remove old backups, logs or unused media, or ask your host for more space.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => array( \BetterShield\Audit\DiskSpace::class, 'finding' ),
			),

			'cron_events_unanswered' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Some background jobs belong to plugins that are no longer installed', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Usually a deleted plugin left them behind. Rarely, malicious code uses a job like this to reinstall itself.', 'bettershield' ),
				'break_note'     => __( 'Check before removing. Some working plugins show up here by mistake. Undo restores any job you remove.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$report = \BetterShield\Audit\Cron::report();

					// `report()` computes `readable` precisely so these two
					// stay apart, and says so in its own docblock: a site
					// whose cron option is corrupt or filtered away is not a
					// site with nothing scheduled. Folding them into one
					// `return null` said "nothing is scheduled" about a site
					// where nothing is known — and null is this registry's
					// word for clean, so the one check meant to catch the
					// place a backdoor re-establishes itself read as a pass.
					if ( ! $report['readable'] ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'The list of background jobs could not be loaded.', 'bettershield' ) );
					}

					if ( 0 === $report['unanswered'] ) {
						return null;
					}

					return array(
						'events'    => $report['events'],
						'total'     => $report['unanswered'],
						'complete'  => true,
						'scheduled' => $report['total'],
					);
				},
			),

			'cron_schedule_stalled' => array(
				'group'          => Areas::SERVER,
				// Read live, every time the posture is read: this is the one
				// finding whose channel is the thing it measures. Published
				// only by the daily audit, it appeared when the scheduler
				// stalled only once something ran the audit, and stayed open
				// for a day after the schedule caught up.
				'live'           => true,
				'title'          => __( 'BetterShield’s background jobs have stopped running', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'A background job is overdue. File checks, security checks, email summaries and cleanup won’t run until it catches up.', 'bettershield' ),
				'break_note'     => __( 'Press Fix to try running them now. If it keeps happening, ask your host to set up a cron job; Fix shows the exact line.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$lag = \BetterShield\Cron\Runner::schedule_lag();

					if ( 0 === $lag['overdue'] ) {
						return null;
					}

					return array(
						// The number, and the number as a person reads it.
						'behind'         => human_time_diff( time() - $lag['behind_seconds'] ),
						'behind_seconds' => $lag['behind_seconds'],
						'overdue'        => $lag['overdue'],
						'worst'          => $lag['worst'],
					);
				},
			),

			'rest_surface_unreviewed' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Some plugin data can be read by anyone without signing in', 'bettershield' ),
				'severity'       => 'info',
				'why'            => __( 'These plugin addresses answer anyone who asks. Most are meant to be public. Check that each one should be.', 'bettershield' ),
				'break_note'     => __( 'Most are public on purpose. Closing one without checking can break a separate app or front end that uses it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$last = RestSurface::last();

					// Never asked. Surveying every route on the site means
					// running every other plugin's permission callback, so it
					// happens on the daily task and this reads the answer.
					if ( null === $last ) {
						return null;
					}

					// WordPress's own namespace answering a visitor is how the
					// block editor and every theme preview work. Only what
					// something else registered is worth a line. Nor this
					// plugin's own: the assistant connection's sign-in and
					// discovery, passkey sign-in and policy reports are open
					// because a caller holding nothing has to reach them, and
					// each refuses inside its handler what it must. There is
					// no decision there for the owner to make.
					$others = array();
					// A route the owner closed answers nobody who is not
					// signed in, whatever its own permission says (#1870).
					$closed = \BetterShield\Fixes\RestRoutes::closed();

					foreach ( (array) $last['namespaces'] as $namespace => $counts ) {
						if ( 0 === $counts['open'] || str_starts_with( (string) $namespace, 'wp/' ) || 'bettershield/v1' === (string) $namespace ) {
							continue;
						}

						$routes = array_values( array_diff( (array) $counts['notable'], $closed ) );
						$open   = (int) $counts['open'] - ( count( (array) $counts['notable'] ) - count( $routes ) );

						if ( $open < 1 ) {
							continue;
						}

						$others[] = array(
							'namespace' => (string) $namespace,
							'open'      => $open,
							'routes'    => $routes,
						);
					}

					return array() === $others ? null : array( 'namespaces' => $others );
				},
			),

			'certificate_expiring' => array(
				'group'          => Areas::EXPOSURE,
				/*
				 * Two titles, because an expired certificate is not a warning
				 * about the future. The site is down for every visitor right
				 * now, and "close to expiring" beside that is the plugin
				 * failing to notice what it just measured.
				 */
				'title'          => static function (): string {
					$days = Certificate::days_left();

					return ( null !== $days && $days < 0 )
						? __( 'The site’s certificate has expired', 'bettershield' )
						: __( 'The site’s certificate is close to expiring', 'bettershield' );
				},
				/*
				 * Callable, like every other check whose severity varies.
				 * This one computed a rising ladder — critical when expired or
				 * two days out, high at a week — put it in its evidence, and
				 * then scored from a static "medium" that ignored it. So the
				 * most complete outage a site can have cost seven points
				 * instead of twenty-five, and the badge read "medium" directly
				 * beside evidence saying critical.
				 */
				'severity'       => static function (): string {
					$days = Certificate::days_left();

					return null === $days ? 'medium' : Certificate::severity_for( $days );
				},
				'why'            => __( 'When your SSL certificate expires, browsers show visitors a warning page instead of your site.', 'bettershield' ),
				'break_note'     => __( 'Renew with your host or certificate provider.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$days = Certificate::days_left();

					// Null is "not checked" or "could not be read" — a site
					// behind a proxy this server cannot reach from inside is
					// common, and reporting that as an expiry problem would be
					// a lie. It is left to the HTTPS check to say the rest.
					if ( null === $days && Certificate::site_is_https() ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'We could not read when your SSL certificate expires.', 'bettershield' ) );
					}
					if ( null === $days || $days > Certificate::SOON ) {
						return null;
					}

					return array(
						'days_left' => $days,
						'severity'  => Certificate::severity_for( $days ),
					);
				},
			),

			'backup_plugin_not_visible' => array(
				'group' => Areas::CONFIGURATION,
				'hardening_item' => null,
				'title' => __( 'No recognized backup plugin is active', 'bettershield' ),
				'severity' => 'low',
				'why' => __( 'Your host may already back up your site. Check that backups run and that you know how to restore one. If so, choose “I manage this myself”.', 'bettershield' ),
				'break_note' => __( 'This check only looks at your plugin list.', 'bettershield' ),
				'test' => static function (): ?array {
					return HostProtections::provides( 'backups' ) ? null : BackupVisibility::finding();
				},
			),

			'log_seal_broken'         => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'Some activity log entries were changed or deleted after they were saved', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'Entries for that day were changed or removed later. Someone who breaks into a site often deletes records of what they did.', 'bettershield' ),
				'break_note'     => __( 'Check who had access on that day, and change admin passwords if you don’t recognize the change.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$broken = Seal::broken_days();

					if ( array() === $broken ) {
						return null;
					}

					// Name recent affected days first and state the whole scope.
					usort( $broken, static fn( $a, $b ) => strcmp( $b['day'], $a['day'] ) );
					return array(
						'days'   => array_slice( wp_list_pluck( $broken, 'day' ), 0, 10 ),
						'total'  => count( $broken ),
						'reason' => (string) ( $broken[0]['reason'] ?? '' ),
					);
				},
			),

			'mixed_content_published' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Some posts still load images or files over insecure http://', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Browsers block or warn about http:// images and files on a secure page. This usually comes from an old link in a post.', 'bettershield' ),
				'break_note'     => __( 'This reads published content and changes none of it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					$last = MixedContent::last();

					// Never asked, or asked on a site that was not on HTTPS
					// then. Neither is a finding: this reads what the daily
					// task last learned, because the query behind it reads
					// every published post's content in full.
					if ( null === $last ) {
						return null;
					}

					// A stored answer from before this row carried the flag is
					// believed; one written by a run that could not count is
					// not, and unknown is said rather than resolved.
					if ( array_key_exists( 'reliable', $last ) && empty( $last['reliable'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'The published content could not be read this time.', 'bettershield' ) );
					}

					if ( 0 === (int) $last['total'] ) {
						return null;
					}

					return array(
						'posts'      => (array) $last['posts'],
						'total'      => (int) $last['total'],
						'complete'   => true,
						'checked_at' => (string) $last['checked_at'],
					) + ( empty( $last['core_covers'] ) ? array() : array(
						// Links to this site's own address are left out while
						// WordPress rewrites them on output (#1291).
						'own_links_covered' => true,
					) );
				},
			),

			'privileged_account_dormant' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'An administrator hasn’t signed in for months', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'It still has full control of your site, and nobody is watching it. It often belongs to a former team member, contractor or test user.', 'bettershield' ),
				'break_note'     => __( 'Check with the person first. Removing or downgrading the account locks them out if they still need it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$found = Dormant::accounts();

					if ( array() === $found ) {
						return null;
					}

					/*
					 * Named and counted separately. Ten names with no total
					 * reads as ten accounts, and on a site with forty it was
					 * the same finding — which is the one thing a count-based
					 * finding must not do.
					 */
					return array(
						'accounts' => array_slice( $found, 0, Dormant::MAX_NAMED ),
						'total'    => count( $found ),
						// False when the pass stopped at its examination
						// ceiling, so the screen says "at least" rather than
						// standing behind a number it did not finish.
						'complete' => Dormant::examined_every_privileged_account(),
						'days'     => Dormant::threshold_days(),
					);
				},
			),

			'security_headers_missing' => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Your site doesn’t send some standard browser safety settings', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'These settings tell browsers to block common tricks, like showing your pages inside another site or sharing your visitors’ page addresses.', 'bettershield' ),
				'break_note'     => __( 'Could break: other sites that show your pages inside theirs. Settings your server already has stay as they are.', 'bettershield' ),
				'hardening_item' => 'security_headers',
				'test'           => static function (): ?array {
					// As above: what is attached to this request, not what the
					// stored flag remembers being switched on — and then what a
					// real visitor's page actually carried, which is the one
					// thing an audit running in wp-admin cannot see for itself.
					$manager = Manager::instance();

					// Another security plugin credited with this item, as the
					// setup and the Hardening card credit it: the same answer
					// here, rather than a finding whose one-click fix the
					// card says not to apply.
					if ( '' !== \BetterShield\Onboarding\Coexistence::applied_elsewhere( 'security_headers' ) ) {
						return null;
					}

					if ( false !== has_filter( 'wp_headers', array( $manager, 'add_security_headers' ) ) ) {
						$observed = Verification::last_absence( 'security_headers' );

						return null === $observed ? null : array( 'reason' => 'not_observed', 'detail' => $observed );
					}

					/*
					 * headers_list() sees only what PHP has set on this response.
					 * A header added by nginx or Apache is applied after PHP has
					 * finished and is invisible from here, so the server's own
					 * answer is read from the daily asking. Until it has run, or
					 * where this site cannot reach itself, this can report a
					 * finding on a site that is already covered — which is why
					 * the remedy is written as harmless either way rather than
					 * as a defect to correct.
					 */
					// Header names are case-insensitive, so both sides are folded
					// before they are compared.
					$ours = array();
					foreach ( array_keys( Items::headers() ) as $name ) {
						$ours[ strtolower( $name ) ] = $name;
					}

					// And what the web server was seen sending on a visitor's
					// page when the daily task last asked it.
					$present = Manager::server_sends_headers();
					foreach ( headers_list() as $header ) {
						$present[] = strtolower( trim( (string) strtok( $header, ':' ) ) );
					}

					$missing = array();
					foreach ( $ours as $folded => $name ) {
						if ( ! in_array( $folded, $present, true ) ) {
							$missing[] = $name;
						}
					}

					return array() === $missing ? null : array( 'missing' => implode( ', ', $missing ) );
				},
			),

			'security_keys_weak'    => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'Your site’s security keys are missing or weak', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'WordPress uses these keys to keep people signed in safely. Weak keys make it easier for someone to fake a sign-in without a password.', 'bettershield' ),
				'break_note'     => __( 'How to fix creates new keys to paste into wp-config.php. Everyone, including you, is signed out once. Key rotation in Protection › Login & Access doesn’t change them.', 'bettershield' ),
				/*
				 * No one-click fix, because the item that looked like one does
				 * not touch these constants — it adds a stored secret beside
				 * them. Offered here, applying it reported success and left
				 * the finding exactly where it was, so the owner pressed a
				 * button that could never clear what it was attached to. On a
				 * network it was worse: that item is unavailable there, so the
				 * button failed outright. The two are each worth doing and
				 * neither is the other.
				 */
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$constants = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );

					$weak = 0;
					foreach ( $constants as $constant ) {
						if ( ! defined( $constant ) ) {
							++$weak;
							continue;
						}

						$value = (string) constant( $constant );

						// The placeholder wp-config-sample.php ships with, and
						// anything too short to be a generated phrase. The value
						// itself is never recorded — only the count.
						if ( 'put your unique phrase here' === $value || strlen( $value ) < 32 ) {
							++$weak;
						}
					}

					return $weak > 0 ? array( 'keys' => $weak ) : null;
				},
			),

			/*
			 * Widening the network's passkey-only policy is refused while a
			 * site has no way back, but that walk ran once, at the save. A
			 * link that lapsed or codes that ran out afterwards left a site
			 * under the policy with nothing to recover a lost passkey with,
			 * and nobody was told. The main site asks again on every audit;
			 * a subsite does not repeat the network's question.
			 */
			'network_passkey_no_way_back' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Some network sites have no recovery options set up', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'On these sites, nobody has a recovery link or recovery codes. Anyone who loses their passkey will need the network administrator to get back in.', 'bettershield' ),
				'break_note'     => __( 'On each site listed, generate a recovery link or print codes under Protection → Recovery. Nothing else changes.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					if ( ! is_multisite() || ! is_main_site() || array() === \BetterShield\Network\Policies::passkey()['roles'] ) {
						return null;
					}

					$walk = \BetterShield\Network\Policies::recovery_walk();

					if ( array() === $walk['missing'] ) {
						return null;
					}

					$names = array();

					foreach ( array_slice( $walk['missing'], 0, 10 ) as $site_id ) {
						$site    = get_site( (int) $site_id );
						$names[] = $site instanceof \WP_Site && '' !== (string) $site->blogname ? (string) $site->blogname : (string) $site_id;
					}

					return array(
						'count'  => count( $walk['missing'] ),
						'sites'  => $names,
						'capped' => $walk['capped'],
					);
				},
			),

			/*
			 * Switched on is not the same as working. Each protection below
			 * is asked whatever tells the two apart for it; the items with a
			 * check of their own answer there.
			 */
			'hardening_not_working' => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'Some protections that are switched on are not working', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Their settings were removed or turned off, often by a site move, a restore or another plugin. Your site is less protected than Protection shows.', 'bettershield' ),
				'break_note'     => __( 'Turn each one off and on again under Protection; sign-in fixes are on Protection › Login & Access. If it stops working again, another plugin is probably undoing it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$broken = self::protections_not_working();

					return array() === $broken ? null : $broken;
				},
			),

			'login_url_shadows_content' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'A page uses the same address as your custom sign-in page', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Visitors who open that page see your sign-in form instead, which also shows them your hidden sign-in address.', 'bettershield' ),
				'break_note'     => __( 'Press Fix to pick a new sign-in address, or change the page’s address. Your current sign-in address stops working, so save the new one.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					$manager = Manager::instance();

					if ( ! $manager->is_active( 'login_url' ) ) {
						return null;
					}

					return \BetterShield\Hardening\Item\LoginUrl::shadowed_content( (string) ( $manager->item_state( 'login_url' )['options']['slug'] ?? '' ) );
				},
			),

			'open_registration_privileged' => array(
				'group'          => Areas::ACCESS,
				'title'          => __( 'Anyone can sign up and get more than Subscriber access', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'A stranger gets a working account just by signing up, with no password to guess.', 'bettershield' ),
				'break_note'     => __( 'Fix makes new sign-ups Subscribers. Current users keep their roles. Could break: sign-ups that are meant to write posts.', 'bettershield' ),
				'hardening_item' => is_multisite() ? null : 'registration_role',
				'test'           => static function (): ?array {
					/*
					 * Not on a network: every site's sign-up goes to the
					 * network's own, and the account it makes is given no role
					 * on any site, so a site's default role is never what a
					 * stranger arrives with.
					 */
					if ( is_multisite() || ! self::registration_is_open() ) {
						return null;
					}

					$role = (string) get_option( 'default_role', 'subscriber' );

					// Open registration into subscriber is how membership and
					// comment-gated sites are meant to work, so it is not a
					// finding. A role that can write is.
					$granted = get_role( $role );

					if ( ! $granted instanceof \WP_Role || empty( $granted->capabilities['edit_posts'] ) ) {
						return null;
					}

					return array( 'default_role' => $role );
				},
			),

			'config_world_writable' => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'Other users on your server can change your main settings file', 'bettershield' ),
				'severity'       => 'high',
				'why'            => __( 'It holds your database password and keys, and whoever can write it can take over the site. On shared hosting, that may include other customers.', 'bettershield' ),
				'break_note'     => __( 'Fix stops other server users from changing this file, keeping the owner’s access, and you can undo it. Or ask your host to set its permissions to 644.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function () {
					if ( ! self::mode_bits_describe_access( PHP_OS_FAMILY ) ) {
						return new \WP_Error( 'bettershield_audit_not_applicable', __( 'On a Windows server, this check cannot read file permissions.', 'bettershield' ) );
					}

					$path = ABSPATH . 'wp-config.php';

					// One directory up is where WordPress also looks, and where
					// many installs actually keep it.
					if ( ! is_file( $path ) ) {
						$path = dirname( ABSPATH ) . '/wp-config.php';
					}

					if ( ! is_file( $path ) ) {
						return null; // Nothing to report about a file we cannot find.
					}

					$perms = @fileperms( $path ); // phpcs:ignore -- an unreadable path yields false, which is handled.

					if ( false === $perms ) {
						return null;
					}

					// Group- or world-writable. Readability is deliberately not
					// reported: 0644 is the norm on a great many hosts and
					// flagging it would be noise on almost every install.
					return ( $perms & 0022 ) ? array( 'mode' => substr( sprintf( '%o', $perms ), -4 ) ) : null;
				},
			),

			'content_dirs_world_writable' => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'Some site folders can be changed by any user on your server', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Whoever can write them can add code the site will run. On shared hosting, that may include other customers.', 'bettershield' ),
				'break_note'     => __( 'Fix stops other server users from changing these folders. Your site keeps working, and you can undo it.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function () {
					if ( ! self::mode_bits_describe_access( PHP_OS_FAMILY ) ) {
						return new \WP_Error( 'bettershield_audit_not_applicable', __( 'On a Windows server, this check cannot read file permissions.', 'bettershield' ) );
					}

					return self::writable_content_dirs();
				},
			),

			'upload_types_script'   => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Non-admin users can upload files that can run code', 'bettershield' ),
				// A type the server runs as PHP is code on the server for
				// anyone with an upload button, not script in a browser.
				'severity'       => static function (): string {
					$found = self::script_upload_types();

					foreach ( is_array( $found ) ? $found : array() as $types ) {
						if ( array() !== array_intersect( array_map( 'trim', explode( ',', (string) $types ) ), self::PHP_TYPES ) ) {
							return 'high';
						}
					}

					return 'medium';
				},
				'why'            => __( 'SVG, HTML and JavaScript files can run code in visitors’ browsers. A PHP file can run on your server.', 'bettershield' ),
				'break_note'     => __( 'Fix lets only administrators upload these file types. Could break: editors uploading SVG images. For PHP files, also turn on “Uploads code block”.', 'bettershield' ),
				'hardening_item' => 'script_uploads',
				'test'           => static function () {
					return self::script_upload_types();
				},
				// A row from before the read moved to a request of its own, on
				// a site that has never answered one, says nothing reliable:
				// the old read could blame a role that couldn't upload at all.
				'unknown_closes' => static fn(): bool => ! UploadTypes::has_answered(),
			),

			'default_table_prefix'  => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'Your database uses WordPress’s default table names', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'This alone isn’t a risk. It only helps someone who has already found another way into your database.', 'bettershield' ),
				'break_note'     => __( 'Renaming tables on a live site is risky; do it when you next move or rebuild the site.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					global $wpdb;

					// The base, not this site's own prefix. On a network the
					// two are the same only on site 1: every other site reads
					// `wp_2_`, `wp_3_` and so on, off the same guessable base
					// — so every site but the first reported clean.
					return 'wp_' === $wpdb->base_prefix ? array() : null;
				},
			),

			'version_disclosed'     => array(
				'group'          => Areas::EXPOSURE,
				'title'          => __( 'Your WordPress version is visible in your site’s code', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Automated scanners read it to pick which known flaws to try, so an out-of-date site advertises what will work against it.', 'bettershield' ),
				'break_note'     => __( 'Hiding the version is not a substitute for updating WordPress.', 'bettershield' ),
				'hardening_item' => 'version_disclosure',
				'test'           => static function (): ?array {
					// The hook may be in place while a filter blanks its output
					// — which is how the one-click fix works — so the finding
					// follows what a visitor actually receives, not the hook.
					//
					// Every place it is received, each while its own hook is
					// in place: the page's meta tag and each feed's
					// <generator>. Asking the page's hook first returned early
					// on the usual theme snippet, which removes that one hook
					// and leaves every feed naming the version.
					$surfaces = array(
						'xhtml'   => array( array( 'wp_head', 'wp_generator' ) ),
						'rss2'    => array( array( 'rss2_head', 'the_generator' ), array( 'commentsrss2_head', 'the_generator' ) ),
						'atom'    => array( array( 'atom_head', 'the_generator' ), array( 'comments_atom_head', 'the_generator' ), array( 'app_head', 'the_generator' ) ),
						'rdf'     => array( array( 'rdf_header', 'the_generator' ) ),
						'comment' => array( array( 'rss_head', 'the_generator' ), array( 'opml_head', 'the_generator' ) ),
					);

					foreach ( $surfaces as $type => $hooks ) {
						$hooked = false;

						foreach ( $hooks as $hook ) {
							$hooked = $hooked || false !== has_action( $hook[0], $hook[1] );
						}

						// Read through `the_generator`, the filter every one of
						// them prints through: blanking it is the usual theme
						// snippet, and what it returns is what a visitor gets.
						// Another plugin's own tag may still print beside it,
						// so what counts is whether it names the version.
						if ( $hooked && VersionDisclosure::names_core_version( (string) apply_filters( 'the_generator', get_the_generator( $type ), $type ) ) ) {
							return array();
						}
					}

					return null;
				},
			),

			'files_altered'         => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Some WordPress or plugin files have been changed', 'bettershield' ),
				/*
				 * The grade of the worst open change, by the rule its row and
				 * its email already use. Read as always critical, a removed file
				 * or an update graded lower still cost the critical's points and
				 * mailed at once, undoing the row's own grade. A count that
				 * could not be read is no evidence the changes are minor, so it
				 * keeps the stronger grade.
				 */
				'severity'       => static function (): string {
					$open = \BetterShield\Integrity\Report::open_count();

					if ( ! empty( $open['read_failed'] ) || $open['total'] < 1 ) {
						return 'critical';
					}

					try {
						return \BetterShield\Integrity\Report::worst_open_grade();
					} catch ( \RuntimeException $e ) {
						return 'critical';
					}
				},
				'why'            => __( 'A change can be your developer’s edit, or code added by someone else. File Changes shows each change line by line.', 'bettershield' ),
				'break_note'     => __( 'Restoring the original keeps the changed copy in quarantine, so nothing is lost. If a change was made on purpose, mark it as accepted.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					// Shared code is the network's to act on, so it costs a
					// subsite nothing. The main site carries the finding.
					if ( \BetterShield\Integrity\Shared::elsewhere() ) {
						return null;
					}

					$open = \BetterShield\Integrity\Report::open_count();

					/*
					 * An unreadable table is not an empty one. Read as 0, a
					 * failed query resolved the site's most serious finding,
					 * took its penalty off the score, and opened it again on
					 * the next good run with an alert either side.
					 */
					if ( ! empty( $open['read_failed'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'The list of changed files could not be loaded.', 'bettershield' ) );
					}

					if ( 0 === $open['total'] ) {
						return null;
					}

					return array_filter(
						array(
							'files'      => $open['total'],
							'altered'    => $open['modified'],
							'added'      => $open['added'],
							'missing'    => $open['removed'],
							// The rest of the total, named where there is any,
							// so the parts add up to it (#1817).
							'unreadable' => $open['unreadable'] ?? 0,
							'packages'   => $open['packages'] ?? 0,
							// Named so the reader can see why the grade is what
							// it is, rather than having to take the number on
							// trust.
							'clutter'    => $open['clutter'],
						),
						static fn( $value, string $key ): bool => ! in_array( $key, array( 'unreadable', 'packages' ), true ) || $value > 0,
						ARRAY_FILTER_USE_BOTH
					);
				},
			),

			'vulnerabilities_known' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Some installed plugins or themes have known security issues', 'bettershield' ),
				// The worst affected item sets the level; the evidence lists
				// each item with its own.
				'severity'       => static function (): string {
					$severity = 'info';
					foreach ( \BetterShield\Vulnerabilities\State::affected_now() as $item ) {
						if ( 'affected' !== ( $item['match_status'] ?? 'affected' ) ) {
							continue;
						}
						$levels = \BetterShield\Vulnerabilities\Matcher::SEVERITIES;
						// A match nobody gave a severity is stored as info for
						// ranking; graded so, it was harmless and cost nothing.
						// It takes the level an unreadable severity does (#1956).
						$level = false === ( $item['severity_known'] ?? true ) ? 'medium' : $item['severity'];
						if ( in_array( $level, $levels, true ) && array_search( $level, $levels, true ) < array_search( $severity, $levels, true ) ) {
							$severity = $level;
						}
					}
					return $severity;
				},
				'why'            => __( 'Once a security issue is made public, sites that haven’t updated get targeted within hours. “Couldn’t compare your version” means we couldn’t tell if yours is affected.', 'bettershield' ),
				'break_note'     => __( 'Update from Dashboard → Updates. If there is no fix yet, deactivate the plugin or switch themes.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					/*
					 * Only while the check is on and an advisory source is
					 * bound. The stored result outlives both, and read without
					 * them it put a critical "known vulnerabilities" on the page
					 * that said, beside it, that no source is connected.
					 */
					if ( ! \BetterShield\Vulnerabilities\Scanner::consented() || null === \BetterShield\Vulnerabilities\Scanner::feed() ) {
						return null;
					}

					$state = \BetterShield\Vulnerabilities\State::get();

					// As installed now, not as when the check last ran (#1810).
					$state['affected'] = \BetterShield\Vulnerabilities\State::affected_now();

					if ( array() === $state['affected'] ) {
						return null;
					}

					$items = array();
					foreach ( $state['affected'] as $item ) {
						$cves = array();
						foreach ( $item['advisories'] as $advisory ) {
							$cves = array_merge( $cves, $advisory['cve_ids'] );
						}
						$items[] = array(
							'type'              => $item['type'],
							'slug'              => $item['slug'],
							'name'              => $item['name'],
							'installed_version' => $item['installed_version'],
							'fixed_in'          => $item['fixed_in'],
							'patch_available'   => $item['patch_available'],
							'severity'          => $item['severity'],
							'active'            => $item['active'],
							'cve_ids'           => array_values( array_unique( $cves ) ),
							'advisories'        => count( $item['advisories'] ),
							'match_status'      => $item['match_status'] ?? 'affected',
							'severity_known'    => $item['severity_known'] ?? true,
						);
					}

					// The bound feed's own name, not the one stored with the
					// last result: a renamed source must not linger (#2461).
					$feed = \BetterShield\Vulnerabilities\Scanner::feed();

					return array(
						'count'      => count( $items ),
						'items'      => $items,
						'feed'       => null !== $feed && $feed->id() === $state['feed'] ? $feed->label() : $state['feed_label'],
						'data_as_of' => '' !== $state['published_at'] ? $state['published_at'] : $state['fetched_at'],
						'age_days'   => \BetterShield\Vulnerabilities\State::age_days(),
					);
				},
			),

			'vulnerability_data_stale' => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'The security issue list hasn’t been updated recently', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'New advisories may have come out since this site was last checked.', 'bettershield' ),
				'break_note'     => __( 'The list updates daily. If it keeps failing, Settings shows why. If the source is late, wait a day.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					// Only once a check has ever run — before that there is no
					// data to be old, and the screen already says none exists.
					if ( ! \BetterShield\Vulnerabilities\Scanner::consented() || null === \BetterShield\Vulnerabilities\Scanner::feed() || ! \BetterShield\Vulnerabilities\State::has_data() ) {
						return null;
					}

					if ( ! \BetterShield\Vulnerabilities\State::is_stale() ) {
						return null;
					}

					$state = \BetterShield\Vulnerabilities\State::get();

					return array(
						'age_days'   => \BetterShield\Vulnerabilities\State::age_days(),
						'data_as_of' => '' !== $state['published_at'] ? $state['published_at'] : $state['fetched_at'],
						'last_error' => $state['error'],
					);
				},
			),

			'quarantine_unsealed'   => array(
				'group'          => Areas::SERVER,
				'title'          => __( 'Files in quarantine can still be opened from the web', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Quarantine keeps copies of suspicious files. If someone can open them from the web, they can read them. Their names are hard to guess, but block the folder.', 'bettershield' ),
				'break_note'     => __( 'Press Fix to block the folder, or for the exact rule to give your host.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					// Only where something is actually being kept: a site that
					// has never displaced a file has nothing to seal, and a
					// finding about an empty folder is noise.
					$uploads = wp_upload_dir();

					if ( ! empty( $uploads['error'] ) ) {
						return null;
					}

					$dir = untrailingslashit( (string) $uploads['basedir'] ) . '/' . \BetterShield\Files\Guarded::QUARANTINE_DIR;

					/*
					 * Only where this plugin positively knows the folder is
					 * not sealed: the server ignores the rule, or the rule is
					 * not there. A server it cannot identify, with the rule
					 * written, gets no finding — "your server might not be
					 * sealing this" is a guess, and the unguessable names hold
					 * either way.
					 */
					if ( ! is_dir( $dir ) || false !== \BetterShield\Files\Guarded::quarantine_is_sealed() ) {
						return null;
					}

					// Nothing kept, nothing to seal: deleting the last copy
					// leaves the folder, and the finding went with neither.
					if ( 0 === \BetterShield\Files\Quarantine::count() ) {
						return null;
					}

					// Denied in the server's own configuration, which is the
					// fix this names, and the server refused a kept copy when
					// a person last ran an audit.
					if ( \BetterShield\Files\Quarantine::server_refuses() ) {
						return null;
					}

					return array(
						'server' => \BetterShield\Support\Server::label(),
						// Named from the same path that was just tested, not
						// from the default layout: a site that moved its
						// uploads, and every subsite of a network, keeps them
						// somewhere else, and the owner is being asked to deny
						// this exact folder in their server configuration.
						'folder' => trailingslashit( \BetterShield\Files\Quarantine::site_relative( $dir ) ),
					);
				},
			),

			'files_never_checked'   => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Your WordPress and plugin files haven’t been checked for changes yet', 'bettershield' ),
				'severity'       => 'medium',
				'why'            => __( 'Run a file check to see whether anything has been changed.', 'bettershield' ),
				'break_note'     => __( 'Start a check from File Changes. It changes nothing, and runs in the background on large sites.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): array|\WP_Error|null {
					if ( \BetterShield\Integrity\Shared::elsewhere() || ! \BetterShield\Integrity\Report::is_stale() ) {
						return null;
					}

					/*
					 * Open change rows are themselves proof the files HAVE
					 * been checked — that is how the rows exist. Without this,
					 * a staleness clock racing the scanner's own put "files
					 * have not been checked" and "files no longer match" on
					 * the same screen at once, and the reader cannot tell
					 * which to believe. The pair is exclusive by construction
					 * now, whatever order the two clocks fire in: while
					 * `files_altered` has evidence, this check stands down.
					 */
					$open = \BetterShield\Integrity\Report::open_count();

					// Whether that evidence exists is what an unreadable table
					// cannot say, so neither can this.
					if ( ! empty( $open['read_failed'] ) ) {
						return new \WP_Error( 'bettershield_audit_unknown', __( 'The list of changed files could not be loaded.', 'bettershield' ) );
					}

					if ( $open['total'] > 0 ) {
						return null;
					}

					$result = \BetterShield\Integrity\Scanner::last_result();

					return array(
						'last_run' => isset( $result['finished_at'] ) ? (string) $result['finished_at'] : 'never',
					);
				},
			),

			'inactive_extensions'   => array(
				'group'          => Areas::EXTENSIONS,
				'title'          => __( 'Deactivated plugins or themes are still installed', 'bettershield' ),
				'severity'       => 'low',
				'why'            => __( 'Their files can still be opened from the web, and they often miss updates.', 'bettershield' ),
				'break_note'     => __( 'Fix moves those you will not use again into quarantine, with Put back, and keeps their settings. Deleting one instead can remove its settings.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => static function (): ?array {
					// Plugins and themes are the network's, so a subsite reports
					// nothing, and nor does a network too large to read.
					$dormant = \BetterShield\Fixes\InactiveExtensions::dormant();

					if ( null === $dormant ) {
						return null;
					}

					$total = count( $dormant['plugins'] ) + count( $dormant['themes'] );

					return $total > 0
						? array(
							'plugins' => count( $dormant['plugins'] ),
							'themes'  => count( $dormant['themes'] ),
						)
						: null;
				},
			),

			'debug_display_enabled' => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'Error messages are visible to visitors', 'bettershield' ),
				/*
				 * Printing errors is how you work locally and a leak of file
				 * paths, queries and occasionally credentials on a live site.
				 */
				'severity'       => static function (): string {
					return Environment::is_production() ? 'high' : 'medium';
				},
				'why'            => __( 'Error messages on your pages can reveal your server’s folder layout and sometimes passwords.', 'bettershield' ),
				// The parenthesis is a promise about behavior, and it holds only
				// while no hardening item asks Files\Guarded to place a block in
				// wp-config.php. `GuardedFilesTest` is what enforces that.
				'break_note'     => __( 'Fix hides most error messages. Some can still appear before BetterShield loads, so ask your developer to turn off debug display in wp-config.php (this plugin never edits that file).', 'bettershield' ),
				'hardening_item' => 'php_error_display',
				'test'           => static function (): ?array {
					/*
					 * The item turns display_errors off after core applied
					 * the debug constants, so while it is on, what this
					 * process reads back settles it rather than the
					 * constants. A server that put it back is still a
					 * finding.
					 */
					if ( Manager::instance()->is_active( 'php_error_display' ) && ! self::display_errors_prints( (string) ini_get( 'display_errors' ) ) ) {
						return null;
					}

					$set_by = self::debug_output_set_by(
						defined( 'WP_DEBUG' ) && WP_DEBUG,
						defined( 'WP_DEBUG_DISPLAY' ),
						defined( 'WP_DEBUG_DISPLAY' ) ? WP_DEBUG_DISPLAY : null,
						\BetterShield\Support\Observed::display_errors(),
						(string) ini_get( 'display_errors' )
					);

					return null === $set_by ? null : array( 'set_by' => $set_by );
				},
			),

			'schema_storage_unavailable' => array(
				'group'          => Areas::CONFIGURATION,
				'title'          => __( 'BetterShield can’t save some of its data', 'bettershield' ),
				/*
				 * High because of what stops rather than what it threatens: a
				 * site whose log is not being written has no record of the
				 * period it was down for, and that gap cannot be filled in
				 * afterwards. The migration retries hourly by itself, so
				 * anything reported here has already had an attempt.
				 */
				'severity'       => 'high',
				'why'            => __( 'Part of BetterShield’s database is missing, so one feature can’t save its records. Press Fix, then Repair storage. Everything else still works.', 'bettershield' ),
				'break_note'     => __( 'Repair only adds what’s missing and never deletes your data.', 'bettershield' ),
				'hardening_item' => null,
				'test'           => array( self::class, 'storage_finding' ),
			),
		);

		return self::with_addon_checks( $own );
	}

	/**
	 * The storage finding as the audit records it.
	 *
	 * The readiness record keeps what the database actually said, because a
	 * refused privilege or a table it cannot open tells the owner far more
	 * than "missing" does, and the Overview card quotes it for exactly that
	 * reason. A finding's evidence is a different audience: it is stored, and
	 * it is what leaves for the owner's own AI provider when they press
	 * Explain. Every other evidence field in this registry is a count or a
	 * flag this plugin wrote; this one would be free text another system
	 * authored, carrying the site's database name and its full table prefix.
	 *
	 * So the finding carries the class of answer and the screen keeps the
	 * quotation.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function storage_finding(): ?array {
		$finding = \BetterShield\Database\Readiness::finding();

		if ( null === $finding ) {
			return null;
		}

		$finding['reason_code'] = self::storage_reason_code( (string) ( $finding['reason'] ?? '' ) );

		unset( $finding['reason'] );

		return $finding;
	}

	/**
	 * What class of answer the database gave, in a word this plugin chose.
	 *
	 * Matched on the phrases MySQL and MariaDB use, and on the sentences the
	 * migration writes when the database said nothing at all. Anything else
	 * is `unknown`, which is the honest answer and never a quotation.
	 */
	private static function storage_reason_code( string $reason ): string {
		$reason = strtolower( $reason );

		if ( str_contains( $reason, 'denied' ) ) {
			return 'denied';
		}

		if ( str_contains( $reason, 'column' ) ) {
			return 'missing_column';
		}

		if ( str_contains( $reason, 'index' ) ) {
			return 'missing_index';
		}

		if ( str_contains( $reason, 'table' ) ) {
			return 'missing_table';
		}

		return 'unknown';
	}
}
