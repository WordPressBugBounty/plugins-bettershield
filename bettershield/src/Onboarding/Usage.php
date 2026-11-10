<?php
/**
 * Usage data, sent only after the owner says yes.
 *
 * The question is asked once, on the first step of the Quick Setup, and the
 * yes is its own button there, "Allow & Continue". "Skip", beside it, is a
 * complete answer: nothing is sent, and one reminder is offered a week
 * later on this plugin's own screens, then never again. The answer can be
 * changed at any time from Settings, and turning sharing off stops it at
 * once.
 *
 * What travels is a closed list, and this class is the only place it is
 * written: the site address and title, the administrator email address, the
 * WordPress, PHP and web server versions, the site's language, character set
 * and text direction, whether it is a network, this plugin's place inside the
 * plugins folder, the installed and active plugins, the active theme and this
 * plugin's version — plus the reference the service files the reports under.
 * Never the absolute path on the server, which names the hosting account.
 * Nothing about visitors, accounts, sign-ins or anything this plugin has
 * recorded.
 * The screen that asks, the Settings panel and the readme all read the same
 * list from `described_fields()`, and a test compares it with the body that is
 * actually sent.
 *
 * On a network the answer is the network's. The report describes the whole
 * of it — every plugin installed anywhere on it, the network-active ones, the
 * server — so it is asked once, kept once for every site, and only a super
 * admin gives it or takes it back. A site administrator manages this plugin
 * on their own site and nothing about the rest of the network, so their Quick
 * Setup does not ask and their Settings show the answer without the switch.
 *
 * Sent through `Support\Http` like every other outbound request, to the one
 * host on its list that exists for this. Never while a visitor is loading a
 * page: the first report goes at the end of the owner's own request that gave
 * consent, once their answer is on its way back, and the rest from the daily
 * task. Every attempt's outcome is kept, so a report that did not land says
 * so on the Settings screen instead of vanishing.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Onboarding;

use BetterShield\Events\Writer;
use BetterShield\Support\Http;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Usage {

	/**
	 * The answer and its bookkeeping. autoload=false: read on our screens and
	 * by the daily task, never on a visitor's page.
	 */
	public const OPTION = 'bettershield_usage';

	/** The daily report, run through the task runner. */
	public const TASK = 'bettershield_usage_report';

	/** The one-off event behind the first report, in case it did not land. */
	public const FIRST_TASK = 'bettershield_usage_report_now';

	/** How long the one-off event waits before trying the first report again. */
	public const RETRY_AFTER = 5 * MINUTE_IN_SECONDS;

	/** Where the report goes. On the gate's allow-list, and nowhere else. */
	public const ENDPOINT = 'https://send.wpinsight.com/process-plugin-data';

	/** This product's slug on the service. */
	public const SLUG = 'bettershield';

	/** The version of the service's report format these reports follow. */
	public const FORMAT = '3.0.3';

	/** How long after a skip the one reminder is offered. */
	public const REMINDER_AFTER = 7 * DAY_IN_SECONDS;

	/**
	 * The project the service files this plugin's reports under.
	 *
	 * Overridable by constant or filter, and an empty value switches reporting
	 * off completely: an unconfigured build asks the question, records the
	 * answer, and sends nothing whatever the answer was.
	 */
	private const ITEM_ID = 'cb8eedc3424e2c172858';

	/**
	 * The stored state, with every key present.
	 *
	 * @return array{allowed: bool, answer: string, answered_at: int, skipped_at: int, reminder: string, site_id: string, registered_url: string, last_sent: int, last_attempt: int, last_error: string, last_digest: string}
	 */
	public static function state(): array {
		// On a network, the network's answer. One a site administrator gave on
		// their own site before is not read: it was never theirs to give.
		$stored = is_multisite() ? get_site_option( self::OPTION, array() ) : get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		return array(
			'allowed'        => ! empty( $stored['allowed'] ),
			// '' never asked, 'yes', 'no' (turned off later), 'skipped'.
			'answer'         => is_string( $stored['answer'] ?? null ) ? $stored['answer'] : '',
			'answered_at'    => (int) ( $stored['answered_at'] ?? 0 ),
			'skipped_at'     => (int) ( $stored['skipped_at'] ?? 0 ),
			// '' not owed, 'owed' after a skip, 'done' once it has been answered or dismissed.
			'reminder'       => is_string( $stored['reminder'] ?? null ) ? $stored['reminder'] : '',
			'site_id'        => is_string( $stored['site_id'] ?? null ) ? $stored['site_id'] : '',
			'registered_url' => is_string( $stored['registered_url'] ?? null ) ? $stored['registered_url'] : '',
			'last_sent'      => (int) ( $stored['last_sent'] ?? 0 ),
			'last_attempt'   => (int) ( $stored['last_attempt'] ?? 0 ),
			// Why the last attempt did not land: '' when it did, `status_<code>` or an error code.
			'last_error'     => is_string( $stored['last_error'] ?? null ) ? $stored['last_error'] : '',
			// What the last report that landed said about the site, as a
			// digest: enough to say whether the next differs, and nothing about
			// the site kept a second time.
			'last_digest'    => is_string( $stored['last_digest'] ?? null ) ? $stored['last_digest'] : '',
		);
	}

	/**
	 * @param array<string, mixed> $changes Keys of state() to change.
	 */
	private static function save( array $changes ): void {
		$next = array_merge( self::state(), $changes );

		if ( is_multisite() ) {
			update_site_option( self::OPTION, $next );

			return;
		}

		update_option( self::OPTION, $next, false );
	}

	/**
	 * Whether the person asking may give the answer, or take it back.
	 *
	 * Everyone who manages the plugin on a single site. On a network, a super
	 * admin only: see the class comment.
	 */
	public static function may_answer(): bool {
		return ! is_multisite() || is_super_admin();
	}

	public static function is_allowed(): bool {
		return self::state()['allowed'];
	}

	/**
	 * Whether the owner has been asked and answered either way.
	 */
	public static function was_asked(): bool {
		return '' !== self::state()['answer'];
	}

	public static function item_id(): string {
		$id = defined( 'BETTERSHIELD_INSIGHTS_ITEM_ID' ) && '' !== (string) BETTERSHIELD_INSIGHTS_ITEM_ID
			? (string) BETTERSHIELD_INSIGHTS_ITEM_ID
			: self::ITEM_ID;

		/**
		 * The project the usage report is filed under. Return an empty string
		 * to switch reporting off for this build whatever the owner answers.
		 *
		 * @param string $id The project id.
		 */
		$filtered = apply_filters( 'bettershield_insights_item_id', $id );

		return is_string( $filtered ) ? trim( $filtered ) : '';
	}

	public static function is_configured(): bool {
		return '' !== self::item_id();
	}

	/**
	 * Record the owner's answer.
	 *
	 * Yes sends the first report straight away and lets the daily task carry
	 * on from there. No stops everything at once: the task reads the answer
	 * each time it runs, so nothing that is already scheduled can send.
	 *
	 * An answer that does not change anything records nothing, so moving on
	 * with the box still ticked on a re-run does not add a second line to the log. It
	 * still sends when a report is due: a yes the site has been holding
	 * without one reaching the service is a yes still owed a report. A yes
	 * given again the day a report landed waits for the daily task, so
	 * switching off and on never sends twice in a day.
	 */
	public static function answer( bool $allowed ): void {
		if ( ! self::may_answer() ) {
			return;
		}

		$state   = self::state();
		$changed = $state['allowed'] !== $allowed || '' === $state['answer'];

		self::save(
			array(
				'allowed'     => $allowed,
				'answer'      => $allowed ? 'yes' : 'no',
				'answered_at' => time(),
				// Answered, so the reminder is never owed again.
				'reminder'    => 'done',
			)
		);

		if ( $changed ) {
			Writer::instance()->record( $allowed ? 'usage_tracking_enabled' : 'usage_tracking_disabled' );
		}

		if ( ! $allowed ) {
			wp_clear_scheduled_hook( self::FIRST_TASK );
			remove_action( 'shutdown', array( self::class, 'send_after_response' ), 1000 );

			return;
		}

		if ( self::is_due( $state ) ) {
			self::send_first_report();
		}
	}

	/**
	 * Whether a report is owed: none has landed in the last day. The hour's
	 * slack lets a daily run that fires a little early still send.
	 *
	 * @param array<string, mixed> $state The stored state.
	 */
	private static function is_due( array $state ): bool {
		return time() - (int) $state['last_sent'] >= DAY_IN_SECONDS - HOUR_IN_SECONDS;
	}

	/**
	 * The owner pressed Skip on the question.
	 *
	 * Only a first skip starts the reminder's clock. A site that already said
	 * yes or no keeps that answer: Skip on a re-run is "leave it as it is".
	 */
	public static function skip(): void {
		if ( ! self::may_answer() || self::was_asked() ) {
			return;
		}

		self::save(
			array(
				'allowed'    => false,
				'answer'     => 'skipped',
				'skipped_at' => time(),
				'reminder'   => 'owed',
			)
		);
	}

	/**
	 * Whether the one reminder is due: a week after a skip, never after an
	 * answer, never twice.
	 */
	public static function reminder_due(): bool {
		$state = self::state();

		return self::may_answer()
			&& ! $state['allowed']
			&& 'owed' === $state['reminder']
			&& $state['skipped_at'] > 0
			&& time() >= $state['skipped_at'] + self::REMINDER_AFTER;
	}

	public static function dismiss_reminder(): void {
		if ( ! self::may_answer() || 'owed' !== self::state()['reminder'] ) {
			return;
		}

		self::save( array( 'reminder' => 'done' ) );
	}

	/**
	 * The first report, at the end of the request that gave consent.
	 *
	 * Sent from that request rather than left to the scheduler: a site whose
	 * scheduler never runs — cron switched off without a system cron behind
	 * it, or a host that refuses the site's loopback to itself — would never
	 * send it at all. It goes after the answer, so the setup moves on without
	 * waiting for the service.
	 *
	 * A one-off event stands behind it. If the service cannot be reached, the
	 * scheduler tries again a few minutes later; a report that lands clears it.
	 */
	private static function send_first_report(): void {
		if ( ! self::is_configured() ) {
			return;
		}

		if ( false === wp_next_scheduled( self::FIRST_TASK ) ) {
			wp_schedule_single_event( time() + self::RETRY_AFTER, self::FIRST_TASK );
		}

		// Late, after the event writer's flush, and once however often the
		// answer is given in one request.
		add_action( 'shutdown', array( self::class, 'send_after_response' ), 1000 );
	}

	/**
	 * Send the first report once the owner has their answer.
	 *
	 * Where the server can close the connection first it does, so the browser
	 * is never kept waiting on the service; elsewhere the page has everything
	 * it needs already and only the connection stays open.
	 */
	public static function send_after_response(): void {
		// Due again here, not only when queued: two answers a moment apart are
		// two requests, and the second finds the first's report has landed.
		if ( ! self::is_allowed() || ! self::is_due( self::state() ) ) {
			return;
		}

		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		} elseif ( function_exists( 'litespeed_finish_request' ) ) {
			litespeed_finish_request();
		}

		if ( self::send() ) {
			wp_clear_scheduled_hook( self::FIRST_TASK );
		}
	}

	/**
	 * The one-off event behind the first report. Sends only if that report
	 * has still not landed; the daily task sends the next one.
	 */
	public static function retry(): void {
		if ( ! self::is_due( self::state() ) ) {
			return;
		}

		self::send();
	}

	public static function register(): void {
		add_action( self::FIRST_TASK, array( self::class, 'retry' ) );
	}

	/**
	 * Whether a report would come from a staging copy.
	 *
	 * On a network the report describes the network and the task runs on
	 * every site, so a network marked staging on its main site still sent its
	 * report from whichever subsite's task ran first. The main site's answer
	 * decides for every site.
	 */
	private static function from_staging(): bool {
		if ( SiteIdentity::is_staging() ) {
			return true;
		}

		if ( ! is_multisite() || is_main_site() ) {
			return false;
		}

		switch_to_blog( get_main_site_id() );

		try {
			return SiteIdentity::is_staging();
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * The daily run. At most one report a day, and none without consent.
	 */
	public static function run(): void {
		// A staging copy carries the live site's usage identity; it stays
		// silent rather than report as the live site.
		if ( self::from_staging() ) {
			return;
		}

		$state = self::state();

		if ( ! $state['allowed'] || ! self::is_due( $state ) ) {
			return;
		}

		self::send();
	}

	/**
	 * Send one report now, if the owner said yes and the build is configured.
	 *
	 * The first report registers the site and the service answers with the
	 * reference later reports are filed under; that reference is kept and
	 * sent in place of the project id from then on.
	 *
	 * @return bool Whether a report was accepted.
	 */
	public static function send(): bool {
		if ( ! self::is_allowed() || ! self::is_configured() ) {
			return false;
		}

		// A staging copy reports nothing, by any route: the daily run, the
		// first report after a yes, and its retry all come through here. It
		// carries the live site's identity, or would register as a site of
		// its own, and the owner was told usage reporting is off here.
		if ( self::from_staging() ) {
			return false;
		}

		$state   = self::state();
		$payload = self::payload();
		$body    = self::body( $state, $payload );

		$response = Http::post( self::ENDPOINT, array( 'body' => $body ) );

		if ( is_wp_error( $response ) ) {
			self::save(
				array(
					'last_attempt' => time(),
					'last_error'   => self::reason( $response ),
				)
			);

			return false;
		}

		$changes = array(
			'last_sent'    => time(),
			'last_attempt' => time(),
			'last_error'   => '',
			'last_digest'  => self::digest( $payload ),
		);

		if ( isset( $body['item_id'] ) ) {
			$answer  = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			$site_id = is_array( $answer ) && isset( $answer['siteId'] ) && is_scalar( $answer['siteId'] )
				? sanitize_key( (string) $answer['siteId'] )
				: '';

			if ( '' !== $site_id ) {
				$changes['site_id']        = Text::clip( $site_id, 64 );
				$changes['registered_url'] = $body['url'];
			}
		}

		self::save( $changes );

		return true;
	}

	/**
	 * The report as it would be posted now: what describes the site, and the
	 * reference it is filed under. The one assembly sending and the preview
	 * both read, so what the owner is shown cannot differ from what leaves.
	 *
	 * @param array<string, mixed> $state   The stored state.
	 * @param array<string, mixed> $payload What payload() built.
	 * @return array<string, mixed>
	 */
	private static function body( array $state, array $payload ): array {
		// A site that has moved is a different site to the service.
		if ( '' !== $state['site_id'] && $state['registered_url'] === $payload['url'] ) {
			$payload['site_id']      = $state['site_id'];
			$payload['original_url'] = $state['registered_url'];
		} else {
			$payload['item_id'] = self::item_id();
		}

		return $payload;
	}

	/**
	 * What a report says about the site, as one string the next report can be
	 * compared with. The reference is left out: it changes after the first
	 * report while the site does not.
	 *
	 * @param array<string, mixed> $payload
	 */
	private static function digest( array $payload ): string {
		// Nor the server software: a daily run started from WP-CLI or the
		// system's cron has no web server to name, so it would read as a
		// change to the site when nothing about the site changed.
		unset( $payload['server'] );

		return hash( 'sha256', (string) wp_json_encode( $payload ) );
	}

	/**
	 * What the next report would carry, exactly, built the way sending builds
	 * it and sent nowhere; and what the last one that landed was.
	 *
	 * @return array<string, mixed>
	 */
	public static function preview(): array {
		$state   = self::state();
		$payload = self::payload();
		$staging = self::from_staging();

		return array(
			'report'     => self::body( $state, $payload ),
			'endpoint'   => self::ENDPOINT,
			// Whether a report goes at all: a yes, a build that reports, and a
			// copy that is not marked staging.
			'sends'      => $state['allowed'] && self::is_configured() && ! $staging,
			'allowed'    => $state['allowed'],
			'configured' => self::is_configured(),
			'staging'    => $staging,
			'network'    => is_multisite(),
			'last_sent'  => $state['last_sent'] > 0 ? gmdate( 'c', $state['last_sent'] ) : null,
			'reference'  => $state['site_id'],
			// Whether the report above says the same about the site as the last
			// one did; null when there is no last one to compare with.
			'unchanged'  => '' === $state['last_digest'] ? null : hash_equals( $state['last_digest'], self::digest( $payload ) ),
			// At most one a day: the next goes with the first daily run after this.
			'next_after' => $state['allowed'] && $state['last_sent'] > 0 ? gmdate( 'c', $state['last_sent'] + DAY_IN_SECONDS - HOUR_IN_SECONDS ) : null,
		);
	}

	/**
	 * Whether switching the plugin off sends a last report: sharing is on,
	 * the service has given this site a reference, and this is not a staging
	 * copy, whose reference is the live site's and would tell the service the
	 * live site switched BetterShield off. Where it does not, the way out asks
	 * nothing, because an answer would have nowhere to go.
	 */
	public static function sends_on_deactivation(): bool {
		$state = self::state();

		return $state['allowed'] && self::is_configured() && '' !== $state['site_id'] && ! self::from_staging();
	}

	/**
	 * Tell the service this site has switched BetterShield off, so it is no
	 * longer counted as running it.
	 *
	 * Only for a site that said yes and was registered. The same report with
	 * its status changed, plus when; short, so a deactivation is never held
	 * up for long by a service that does not answer.
	 */
	public static function deactivated(): void {
		// The reason given on the way out goes with this report or nowhere:
		// taken now, so it never outlives the deactivation it was given for.
		$reason = DeactivationFeedback::take();

		if ( ! self::sends_on_deactivation() ) {
			return;
		}

		$state = self::state();
		$body  = array_merge(
			self::payload(),
			array(
				'status'           => 'Deactivated',
				'deactivated_date' => time(),
				'site_id'          => $state['site_id'],
				'original_url'     => $state['registered_url'],
			),
			// The field names the service already files the old form's
			// answers under, so this plugin's reasons group with the family's.
			null !== $reason
				? array(
					'deactivation_reason'  => $reason['reason'],
					'deactivation_details' => $reason['details'],
				)
				: array()
		);

		Http::post(
			self::ENDPOINT,
			array(
				'body'    => $body,
				'timeout' => 5,
			)
		);
	}

	/**
	 * Why a report did not land, kept short and to a key: the status the
	 * service answered with, or the error code of a request that never reached
	 * it. Nothing the service said is stored.
	 */
	private static function reason( \WP_Error $error ): string {
		$data = $error->get_error_data();

		if ( 'bettershield_http_status' === $error->get_error_code() && is_array( $data ) && isset( $data['status'] ) ) {
			return 'status_' . (int) $data['status'];
		}

		return Text::clip( sanitize_key( (string) $error->get_error_code() ), 64 );
	}

	/**
	 * The last attempt's failure, in words, or '' when it landed or none has
	 * been made.
	 *
	 * @param array<string, mixed> $state The stored state.
	 */
	private static function failure( array $state ): string {
		$reason = (string) $state['last_error'];

		if ( '' === $reason ) {
			return '';
		}

		if ( 1 === preg_match( '/^status_(\d{3})$/', $reason, $match ) ) {
			return sprintf(
				/* translators: %d: an HTTP status code. */
				__( 'The usage service refused the last report (status %d).', 'bettershield' ),
				(int) $match[1]
			);
		}

		return sprintf(
			/* translators: %s: an error code, e.g. http_request_failed. */
			__( 'The last report could not reach the usage service (%s).', 'bettershield' ),
			$reason
		);
	}

	/**
	 * The report, and everything in it.
	 *
	 * Keep this and `described_fields()` in step: a key added here without a
	 * line there is data the owner was not told about.
	 *
	 * @return array<string, mixed>
	 */
	public static function payload(): array {
		/*
		 * The same report whatever request builds it, so the preview an owner
		 * reads is the one the daily run posts. On a network that is the main
		 * site's: its plugins and its theme, whichever site's run sends it
		 * (the address, name and administrator are the network's already).
		 */
		$switched = is_multisite() && ! is_main_site();

		if ( $switched ) {
			switch_to_blog( get_main_site_id() );
		}

		try {
			return self::assemble();
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * The report, built on the site it describes.
	 *
	 * @return array<string, mixed>
	 */
	private static function assemble(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$active = (array) get_option( 'active_plugins', array() );

		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}

		$active = array_values( array_unique( array_map( 'strval', $active ) ) );
		$theme  = wp_get_theme();

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized on the next line.
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) : '';

		/*
		 * The site's language, never the reader's: a request from the screen
		 * asks for the account's own language (`_locale=user`), and the daily
		 * run reads the site's. The text direction is that language's.
		 */
		$language = (string) get_option( 'WPLANG' );

		if ( '' === $language && is_multisite() ) {
			$language = (string) get_site_option( 'WPLANG' );
		}

		$language = '' !== $language ? $language : 'en_US';
		$switched = switch_to_locale( $language );
		$rtl      = is_rtl();

		if ( $switched ) {
			restore_previous_locale();
		}

		/*
		 * On a network the report is the network's, whichever site's request
		 * or daily run sends it: its address, its name and its administrator,
		 * so every site sends the same report and the service files one site
		 * rather than registering each subsite it happened to hear from.
		 */
		$network = is_multisite() ? get_network() : null;
		$url     = $network ? network_home_url() : home_url();
		$name    = $network ? (string) $network->site_name : (string) get_bloginfo( 'name' );
		$email   = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );

		/*
		 * The field names and the report format's version are the service's
		 * own: a report missing one it files sites by is accepted and then
		 * never listed. One field its other clients send is left out on
		 * purpose: the country, which they look up by sending the visitor's
		 * address to another service.
		 */
		return array(
			// Which product the report is about, and that it is running.
			'plugin_slug'      => self::SLUG,
			'plugin'           => 'BetterShield',
			'version'          => BETTERSHIELD_VERSION,
			'status'           => 'Active',
			'wpins_version'    => self::FORMAT,
			'url'              => $url,
			'site_name'        => Text::clip( wp_specialchars_decode( $name, ENT_QUOTES ), 200 ),
			'email'            => (string) $email,
			'site_version'     => (string) get_bloginfo( 'version' ),
			'php_version'      => PHP_VERSION,
			'server'           => Text::clip( sanitize_text_field( $server ), 100 ),
			'site_language'    => str_replace( '_', '-', $language ),
			'charset'          => (string) get_bloginfo( 'charset' ),
			'text_direction'   => $rtl ? 'RTL' : 'LTR',
			'multisite'        => is_multisite(),
			// Where the plugin sits inside the plugins folder, and nothing
			// above it. The service's other clients send the absolute path,
			// which names the hosting account and lays out the server's
			// directories — reconnaissance, sent to a third party, for nothing
			// the versions and the plugin list do not already say.
			'file_location'    => plugin_basename( BETTERSHIELD_FILE ),
			'active_plugins'   => $active,
			'inactive_plugins' => array_values( array_diff( array_map( 'strval', array_keys( get_plugins() ) ), $active ) ),
			'theme'            => sanitize_text_field( (string) $theme->get( 'Name' ) ),
			'theme_version'    => sanitize_text_field( (string) $theme->get( 'Version' ) ),
		);
	}

	/**
	 * What the report holds, in words, in the order the screens list it.
	 *
	 * @return string[]
	 */
	public static function described_fields(): array {
		return array(
			__( 'Your site address and title', 'bettershield' ),
			__( 'Your administrator email address', 'bettershield' ),
			__( 'The WordPress and PHP versions, and your web server software', 'bettershield' ),
			__( 'Your site language, character set and text direction', 'bettershield' ),
			__( 'Whether the site is a multisite network', 'bettershield' ),
			__( 'Where BetterShield is installed (its folder and file name only)', 'bettershield' ),
			__( 'Which plugins are installed, and which of them are active', 'bettershield' ),
			__( 'Your active theme and its version', 'bettershield' ),
			__( 'The BetterShield version, and whether it is active or deactivated', 'bettershield' ),
			__( 'A random ID for your site, so reports can be told apart, and the report’s format version', 'bettershield' ),
			__( 'Why you deactivated BetterShield, only if you choose to say when you switch it off', 'bettershield' ),
		);
	}

	/**
	 * What the screens need to draw the question and the switch.
	 *
	 * @return array<string, mixed>
	 */
	public static function for_screen(): array {
		$state = self::state();

		return array(
			'allowed'    => $state['allowed'],
			'asked'      => '' !== $state['answer'],
			// False for a site administrator on a network, who is shown the
			// network's answer and is not asked for one.
			'can_answer' => self::may_answer(),
			'network'    => is_multisite(),
			'configured' => self::is_configured(),
			'fields'     => self::described_fields(),
			'reminder'   => self::reminder_due(),
			'last_sent'  => $state['last_sent'] > 0 ? gmdate( 'c', $state['last_sent'] ) : null,
			'failure'    => $state['allowed'] ? self::failure( $state ) : '',
		);
	}
}
