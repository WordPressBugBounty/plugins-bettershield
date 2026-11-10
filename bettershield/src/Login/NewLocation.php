<?php
/**
 * Tells an account holder when their account signs in from somewhere new.
 *
 * Almost every message this plugin sends goes to a site-wide list of at most
 * five addresses, and asks somebody who was not there whether something
 * somebody else did was expected. This one asks the one person who knows.
 * That makes it the highest-signal message available to a security product,
 * and it is the reason it goes to the account holder's own address rather
 * than to the alert recipients.
 *
 * **Nothing is blocked.** A first sign-in from a new place is overwhelmingly
 * the owner on a train, and refusing it would make this plugin the reason
 * they could not work. The message is a notice, and the only action it offers
 * is one the person can take on their own account.
 *
 * Everything it needs was already being captured. `Events\Writer` stamps
 * `ip_prefix` — the truncated /24 or /64, never a full address — on every row
 * it writes, and a successful sign-in has been the `login` event type since
 * F6a. So the question is one indexed read: has this account signed in from a
 * different network before?
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Ip;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class NewLocation {

	/**
	 * One message per account per day, however many new networks it signs in
	 * from. Somebody traveling through three airports in an afternoon has
	 * changed network three times and does not need three emails; the first
	 * one already told them what they needed to know.
	 */
	private const THROTTLE_SECONDS = DAY_IN_SECONDS;

	/**
	 * How many distinct networks are looked at.
	 *
	 * Enough to know the places this account habitually works from, few enough
	 * that the read stays indexed and small. A person whose sign-ins all came
	 * from one network is telling us something; the fiftieth different network
	 * is not more informative for being the two-hundredth.
	 */
	private const HISTORY = 50;

	/**
	 * How far back the history reaches.
	 *
	 * A bound on the scan as much as on the answer: without one the read walks
	 * however many years of log the site has kept. A network nobody has signed
	 * in from for a year is not somewhere this account habitually works from.
	 */
	private const HISTORY_DAYS = 365;

	/** How many of the account's other sites of a network are read for its history. */
	private const SITES_READ = 20;

	private static ?NewLocation $instance = null;

	public static function instance(): NewLocation {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		/*
		 * Before the listener that records this sign-in, so the question "has
		 * this account been here before" is asked of history that does not yet
		 * include this arrival. The priority is what keeps that true; the
		 * writer's shutdown buffer keeps it true a second time.
		 */
		add_action( 'wp_login', array( $this, 'observe' ), 5, 2 );
	}

	/**
	 * @param mixed $user
	 */
	public function observe( string $user_login, $user = null ): void {
		if ( ! $user instanceof \WP_User || ! $this->enabled() ) {
			return;
		}

		// Safe mode is for the owner who is already locked out and working to
		// get back in. Mailing them about their own rescue is noise.
		if ( SafeMode::is_active() ) {
			return;
		}

		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );

		// Behind a proxy nobody has named, the address is the proxy's own:
		// every sign-in matched its network and none was ever reported, or a
		// second proxy's network read as somewhere new. Stood down, as the
		// lockouts and the puzzle stand down, on an address nothing vouches for.
		if ( empty( $resolved['confident'] ) ) {
			return;
		}

		$prefix = Ip::truncated_binary( (string) $resolved['ip'] );

		if ( null === $prefix ) {
			return;
		}

		$seen = $this->networks_seen( (int) $user->ID );

		/*
		 * No history at all means this is the first sign-in this plugin has
		 * observed for the account — which is true of every account on the day
		 * the plugin is installed. Telling everybody their own habitual
		 * location is new would spend the first impression of this feature on
		 * a false alarm, and teach them to ignore the second one.
		 */
		if ( array() === $seen ) {
			return;
		}

		foreach ( $seen as $known ) {
			if ( hash_equals( $known, $prefix ) ) {
				return;
			}
		}

		$this->notify( $user, $prefix );
	}

	/**
	 * Whether the owner has this switched on. Off by default: it emails people
	 * who are not the site's administrator, and a plugin that starts doing
	 * that on update without being asked is a plugin that gets uninstalled.
	 */
	public function enabled(): bool {
		$settings = Protection::instance()->settings();

		return ! empty( $settings['new_location_notice'] );
	}

	/**
	 * Whether this account has signed in from this connection's network. No
	 * history, or an address nothing vouches for, is a no: an answer that
	 * holds back an email has to be sure.
	 *
	 * @param array{ip: string, confident: bool} $resolved
	 */
	public function is_familiar( int $user_id, array $resolved ): bool {
		if ( empty( $resolved['confident'] ) ) {
			return false;
		}

		$prefix = Ip::truncated_binary( (string) $resolved['ip'] );

		if ( null === $prefix ) {
			return false;
		}

		foreach ( $this->networks_seen( $user_id ) as $known ) {
			if ( hash_equals( $known, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The networks this account has signed in from lately.
	 *
	 * On a network the account is one account on every site it belongs to,
	 * so its history is read on each of them: a network it signs in from
	 * every day on one site was "new" the first time it signed in to another,
	 * because only this site's slice of the log was read. Each site answers
	 * from its own table, moved to the network's or not, and a site whose log
	 * is not there is skipped. Bounded, because a network administrator can
	 * belong to every site; past the bound the answer is this site's and the
	 * first ones walked, which can only err towards saying so.
	 *
	 * @return string[] Raw truncated-binary prefixes.
	 */
	private function networks_seen( int $user_id ): array {
		$seen = $this->networks_seen_here( $user_id );

		if ( ! is_multisite() ) {
			return $seen;
		}

		$here    = (int) get_current_blog_id();
		$network = (int) get_current_network_id();
		$walked  = 0;

		foreach ( get_blogs_of_user( $user_id ) as $site_id => $site ) {
			if ( (int) $site_id === $here || (int) ( $site->site_id ?? $network ) !== $network ) {
				continue;
			}

			if ( ++$walked > self::SITES_READ ) {
				break;
			}

			switch_to_blog( (int) $site_id );

			try {
				if ( Schema::ready( 'events' ) ) {
					$seen = array_merge( $seen, $this->networks_seen_here( $user_id ) );
				}
			} finally {
				restore_current_blog();
			}
		}

		return array_values( array_unique( $seen ) );
	}

	/**
	 * The same, from the current site's own log.
	 *
	 * @return string[] Raw truncated-binary prefixes.
	 */
	private function networks_seen_here( int $user_id ): array {
		global $wpdb;

		/*
		 * `site_id` and `actor_type` are not decoration: every index on this
		 * table leads with the site column, and without it the read can use no
		 * index at all — a full scan of the whole activity log, in primary-key
		 * order, on every successful sign-in. The writer sets both columns on
		 * every row it writes, so naming them changes which plan is chosen and
		 * not which rows come back.
		 */
		$since = gmdate( 'Y-m-d H:i:s.v', time() - self::HISTORY_DAYS * DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the plugin's own log, read once per sign-in on an indexed column; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$rows = (array) $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT ip_prefix FROM %i
				 WHERE " . Schema::site_where( 'events' ) . " AND event_type = 'login' AND occurred_at > %s
				   AND actor_type = 'user' AND actor_id = %d AND ip_prefix IS NOT NULL
				 ORDER BY id DESC LIMIT %d",
				Schema::table( 'events' ),
				$since,
				$user_id,
				self::HISTORY
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return array_values( array_filter( array_map( 'strval', $rows ) ) );
	}

	/**
	 * Tell the person, and record that we did.
	 */
	private function notify( \WP_User $user, string $prefix ): void {
		$throttle = 'newloc_' . $user->ID;

		// The event is recorded whether or not the message goes out: a sign-in
		// from a network this account has never used is worth a row in the log
		// even on the day the throttle swallows the email.
		Writer::instance()->record(
			'login_new_network',
			Writer::SEVERITY_MEDIUM,
			array(
				'actor_type'  => 'user',
				'actor_id'    => (int) $user->ID,
				'actor_label' => $user->user_login,
				'object_type' => 'user',
				'object_id'   => (string) $user->ID,
			)
		);

		// A staging copy writes to nobody as the live site; the sign-in is
		// still recorded above.
		if ( ! is_email( $user->user_email ) || \BetterShield\Onboarding\SiteIdentity::is_staging() ) {
			return;
		}

		// The claim is the throttle. Two sign-ins from two new networks at the
		// same moment both used to find the day clear and both wrote to the
		// account holder; taking the day is now one statement the database
		// settles, so the second finds it taken.
		if ( ! Claim::claim( $throttle, self::THROTTLE_SECONDS ) ) {
			return;
		}

		// Where this person can see and end their sessions: a front-end page
		// for an account kept out of wp-admin, profile.php otherwise.
		$sessions = esc_url_raw( AccountPage::front_end_url( $user, 'bettershield-sessions' ) ?? admin_url( 'profile.php' ) );

		// In the account holder's own language, as core writes its own mail to
		// an account. Translated in the request's, it was the site's, or the
		// one picked on the sign-in screen.
		$switched = switch_to_user_locale( (int) $user->ID );

		try {
			$this->send_notice( $user, $prefix, $sessions );
		} finally {
			if ( $switched ) {
				restore_previous_locale();
			}
		}
	}

	/**
	 * The notice itself, in whichever language is in force.
	 */
	private function send_notice( \WP_User $user, string $prefix, string $sessions ): void {
		wp_mail(
			$user->user_email,
			sprintf(
				/* translators: %s: site name. */
				__( '[%s] Your account signed in from a new place', 'bettershield' ),
				wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			),
			sprintf(
				/* translators: %s: site name. */
				__( 'Someone signed in to your account on %s from an internet connection you haven’t used here before.', 'bettershield' ),
				wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			) . "\n\n" . sprintf(
				/* translators: 1: date and time, 2: internet address with its last part hidden, e.g. 203.0.113.x. */
				__( "When: %1\$s\nInternet address: %2\$s", 'bettershield' ),
				\BetterShield\Support\Time::said( time() ),
				Ip::address_label( $prefix )
			) . "\n\n" . sprintf(
				/* translators: %s: profile URL. */
				__( 'Not you? Change your password now and check your signed-in devices: %s', 'bettershield' ),
				$sessions
			) . "\n\n" . __( 'If this was you, no action needed. We send at most one of these emails a day.', 'bettershield' )
		);
	}
}
