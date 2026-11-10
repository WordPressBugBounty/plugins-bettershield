<?php
/**
 * What the site owner is told, and how often.
 *
 * Five controls, and one of them outranks the rest. The mute is a single
 * switch that stops every alert — the digest included — and it is read by the
 * one class that sends them, so no alert can quietly bypass it. A mute that
 * silences the urgent mail but still posts a cheerful weekly summary would be
 * worse than no mute at all.
 *
 * It is not a switch for mail about a person's own account, which goes to
 * that person rather than to the recipients here: the link that clears a
 * paused sign-in, the notice of a sign-in from a new network, and the
 * recovery link. Those carry a way back in or answer the one person who
 * knows, and the screens that describe the mute say they still go out.
 *
 * Email alerts start off on a new install, until the owner turns them on in
 * Quick Setup or here. See start_off(). A site that has run without saving a
 * choice keeps them on, which is why a value that was never stored still reads
 * as on below.
 *
 * Recipients default to the address WordPress already has rather than to an
 * empty list, so alerting works on a site nobody configured. They are stored
 * as addresses and never as user IDs: the person who should hear about a
 * lockout is often not an account on the site.
 *
 * Each named address says what it wants (#1886): instant alerts at high and
 * critical, at critical only, or none, and the weekly summary or not. An
 * agency hears everything at once, the client reads Monday's summary, and the
 * developer is woken only for critical. One address always keeps instant
 * alerts at high and critical, so narrowing people one at a time can never
 * quietly turn alerting off.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Events\Writer;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings {

	public const OPTION = 'bettershield_alerts';

	/**
	 * The admin address alerts went to before it changed, while nobody is
	 * named: `array{address: string, at: int}`. See admin_email_changed().
	 */
	public const PREVIOUS_OPTION = 'bettershield_alerts_previous_recipient';

	/** How long the previous address still hears about what changed. */
	private const PREVIOUS_FOR = DAY_IN_SECONDS;

	/**
	 * Enough for an owner, a developer and an agency inbox, and few enough
	 * that this cannot become a mailing list run from a security plugin.
	 */
	public const MAX_RECIPIENTS = 5;

	/** Instant alerts at high and critical: what every address got before, and the default. */
	public const INSTANT_HIGH = 'high';

	/** Instant alerts only when something critical happens. */
	public const INSTANT_CRITICAL = 'critical';

	/** No instant alerts: the weekly summary, if that is on, is the whole of it. */
	public const INSTANT_OFF = 'off';

	private static ?Settings $instance = null;

	public static function instance(): Settings {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * @return array{digest: bool, digest_day: int, instant_critical: bool, muted: bool, host_managed: bool, recipients: string[], account_notices_privileged: bool, account_notices_others: bool, preferences: array<int, array{address: string, instant: string, digest: bool}>, instant_off: string[]}
	 */
	public function settings(): array {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$recipients = array();
		foreach ( (array) ( $stored['recipients'] ?? array() ) as $address ) {
			if ( ! is_string( $address ) ) { continue; }
			$address = sanitize_email( $address );
			if ( is_email( $address ) ) {
				$recipients[] = $address;
			}
		}

		return array(
			'digest'           => (bool) ( $stored['digest'] ?? true ),
			// Monday: a week's security summary is a thing to read at the start
			// of a working week, not on a Saturday when nobody will act on it.
			'digest_day'       => max( 0, min( 6, (int) ( $stored['digest_day'] ?? 1 ) ) ),
			'instant_critical' => (bool) ( $stored['instant_critical'] ?? true ),
			'muted'            => (bool) ( $stored['muted'] ?? false ),
			'host_managed'     => (bool) ( $stored['host_managed'] ?? false ),
			'recipients'       => self::distinct( $recipients ),
			// Telling account holders when a way of signing in to their own
			// account is added or removed (#1855): on for accounts that can
			// manage the site, off for the rest until the owner says.
			'account_notices_privileged' => (bool) ( $stored['account_notices_privileged'] ?? true ),
			'account_notices_others'     => (bool) ( $stored['account_notices_others'] ?? false ),
			'preferences'      => self::preferences_for( self::distinct( $recipients ), (array) ( $stored['preferences'] ?? array() ) ),
			// Event types that skip the instant email and wait for the weekly
			// summary (#1973). Still recorded in full; a critical row of one
			// still goes out at once.
			'instant_off'                => self::known_types( (array) ( $stored['instant_off'] ?? array() ) ),
		);
	}

	/**
	 * Start a new install with instant alerts and the weekly summary off.
	 *
	 * Called once, on a site's first activation. A site that was already
	 * running never comes through here, so its alerts stay as they were.
	 */
	public static function start_off(): void {
		if ( false === get_option( self::OPTION ) ) {
			add_option(
				self::OPTION,
				array(
					'digest'           => false,
					'instant_critical' => false,
				),
				'',
				false
			);
		}
	}

	/** Whether no alert or weekly summary is being sent, by a mute or by the two switches. */
	public function sends_nothing(): bool {
		$settings = $this->settings();

		return $this->is_muted() || ( ! $settings['digest'] && ! $settings['instant_critical'] );
	}

	/**
	 * What each named address chose, in the list's order, for the addresses
	 * that chose something other than the default: an address that has said
	 * nothing hears everything, as every address did before there was a
	 * choice, so adding one is not also a change to anybody's choices. An
	 * entry for an address no longer on the list is not kept.
	 *
	 * A list rather than a map keyed by address: the record of a settings
	 * change compares a map name by name and would write the addresses into
	 * it, and a list is counted, as the recipients are.
	 *
	 * @param string[]            $recipients
	 * @param array<mixed, mixed> $stored     Entries of `array{address: string, instant?: string, digest?: bool}`.
	 * @return array<int, array{address: string, instant: string, digest: bool}>
	 */
	private static function preferences_for( array $recipients, array $stored ): array {
		$given = self::by_address( $stored );

		$preferences = array();

		foreach ( $recipients as $address ) {
			$choice = self::choice_of( $given, $address );

			if ( self::INSTANT_HIGH !== $choice['instant'] || ! $choice['digest'] ) {
				$preferences[] = array( 'address' => $address ) + $choice;
			}
		}

		return $preferences;
	}

	/**
	 * One address's choice, or the default when it has made none.
	 *
	 * @param array<string, array<string, mixed>> $keyed Entries keyed by address in lower case.
	 * @return array{instant: string, digest: bool}
	 */
	private static function choice_of( array $keyed, string $address ): array {
		$entry   = $keyed[ strtolower( $address ) ] ?? array();
		$instant = (string) ( $entry['instant'] ?? self::INSTANT_HIGH );

		return array(
			'instant' => in_array( $instant, self::instant_levels(), true ) ? $instant : self::INSTANT_HIGH,
			'digest'  => (bool) ( $entry['digest'] ?? true ),
		);
	}

	/**
	 * Preference entries keyed by their address in lower case. Entries that
	 * are not an address and its choices are passed over.
	 *
	 * @param array<mixed, mixed> $entries
	 * @return array<string, array<string, mixed>>
	 */
	private static function by_address( array $entries ): array {
		$keyed = array();

		foreach ( $entries as $entry ) {
			if ( is_array( $entry ) && isset( $entry['address'] ) && is_string( $entry['address'] ) ) {
				$keyed[ strtolower( $entry['address'] ) ] = $entry;
			}
		}

		return $keyed;
	}

	/** @return string[] */
	private static function instant_levels(): array {
		return array( self::INSTANT_HIGH, self::INSTANT_CRITICAL, self::INSTANT_OFF );
	}

	/** How much of the instant path a level lets through, for comparing two. */
	private static function instant_rank( string $instant ): int {
		return array( self::INSTANT_OFF => 0, self::INSTANT_CRITICAL => 1, self::INSTANT_HIGH => 2 )[ $instant ] ?? 2;
	}

	/**
	 * Who a message of this kind goes to.
	 *
	 * An instant alert reaches the addresses whose level it meets, a weekly
	 * summary those that take it, and anything else — a test, the recovery
	 * reminder — every address, since none of those is what a preference is
	 * about. The site's admin address, where alerts go while nobody is named,
	 * hears everything.
	 *
	 * @param string $kind     `critical` (an instant alert), `digest`, or anything else.
	 * @param int    $severity The highest severity an instant alert carries.
	 * @return string[]
	 */
	public function audience( string $kind, int $severity = Writer::SEVERITY_HIGH ): array {
		$settings = $this->settings();

		if ( array() === $settings['recipients'] || ! in_array( $kind, array( 'critical', 'digest' ), true ) ) {
			return $this->recipients();
		}

		$preferences = self::by_address( $settings['preferences'] );

		return array_values(
			array_filter(
				$settings['recipients'],
				static function ( string $address ) use ( $preferences, $kind, $severity ): bool {
					$preference = self::choice_of( $preferences, $address );

					if ( 'digest' === $kind ) {
						return $preference['digest'];
					}

					if ( self::INSTANT_OFF === $preference['instant'] ) {
						return false;
					}

					return $severity >= ( self::INSTANT_CRITICAL === $preference['instant'] ? Writer::SEVERITY_CRITICAL : Writer::SEVERITY_HIGH );
				}
			)
		);
	}

	/**
	 * The registered event types among these, once each and in order. A type
	 * an add-on no longer registers is dropped rather than kept as a name the
	 * screen cannot show.
	 *
	 * @param array<int|string, mixed> $types
	 * @return string[]
	 */
	private static function known_types( array $types ): array {
		$known = \BetterShield\Events\Types::labels();
		$kept  = array();

		foreach ( $types as $type ) {
			if ( is_string( $type ) && isset( $known[ $type ] ) ) {
				$kept[ $type ] = $type;
			}
		}

		ksort( $kept );

		return array_values( $kept );
	}

	/**
	 * The event types an owner can move to the weekly summary: those this
	 * site has recorded at high or above, the level that sends an instant
	 * email, and those already moved. A type seen at critical is offered
	 * locked: critical always goes out at once.
	 *
	 * Read from the log over its retention window, so the list is the types
	 * that have actually emailed somebody, not every type there is.
	 *
	 * @return array<int, array{type: string, label: string, area: string, area_label: string, critical: bool, off: bool}>
	 */
	public function instant_types(): array {
		global $wpdb;

		$since = ( new \DateTimeImmutable( '-' . \BetterShield\Support\Tier::retention_days() . ' days', new \DateTimeZone( 'UTC' ) ) )->format( 'Y-m-d H:i:s' );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and every value is bound.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT event_type, MAX(severity) AS worst FROM %i WHERE ' . \BetterShield\Database\Schema::site_where( 'events' ) . ' AND severity >= %d AND occurred_at > %s GROUP BY event_type', \BetterShield\Database\Schema::table( 'events' ), Writer::SEVERITY_HIGH, $since ) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$worst = array();

		foreach ( is_array( $rows ) ? $rows : array() as $row ) {
			$type = (string) $row->event_type;

			// This mailer's own bookkeeping never sends an instant alert.
			if ( 'alert_' !== substr( $type, 0, 6 ) ) {
				$worst[ $type ] = (int) $row->worst;
			}
		}

		$off = $this->settings()['instant_off'];

		foreach ( $off as $type ) {
			$worst[ $type ] = $worst[ $type ] ?? Writer::SEVERITY_HIGH;
		}

		$areas  = \BetterShield\Events\Types::areas();
		$labels = \BetterShield\Support\Areas::all();
		$types  = array();

		foreach ( self::known_types( array_keys( $worst ) ) as $type ) {
			$area    = $areas[ $type ] ?? \BetterShield\Support\Areas::PLUGIN;
			$types[] = array(
				'type'       => $type,
				'label'      => \BetterShield\Events\Types::label( $type ),
				'area'       => $area,
				'area_label' => (string) ( $labels[ $area ] ?? $area ),
				'critical'   => $worst[ $type ] >= Writer::SEVERITY_CRITICAL,
				'off'        => in_array( $type, $off, true ),
			);
		}

		return $types;
	}

	/**
	 * Whether this event waits for the weekly summary instead of the instant
	 * email: its type is on the list and it is not critical.
	 *
	 * @param array<string, mixed> $event A row as the writer persisted it.
	 */
	public function waits_for_summary( array $event ): bool {
		if ( self::always_emails( (string) ( $event['event_type'] ?? '' ) ) ) {
			return false;
		}

		if ( $this->settings()['host_managed'] ) {
			return ! self::signs_an_attack( $event );
		}

		return (int) ( $event['severity'] ?? 0 ) < Writer::SEVERITY_CRITICAL
			&& in_array( (string) ( $event['event_type'] ?? '' ), $this->settings()['instant_off'], true );
	}

	/**
	 * Whether an event type emails even while instant alerts are off. These
	 * are close to free of false alarms, and a deliberate mute still silences
	 * them.
	 */
	public static function always_emails( string $type ): bool {
		/**
		 * The event types that email even while instant alerts are off.
		 *
		 * @param string[] $types Event types.
		 */
		$types = apply_filters( 'bettershield_always_email_types', array( 'canary_used' ) );

		return in_array( $type, is_array( $types ) ? $types : array(), true );
	}

	/**
	 * What still goes out at once while the host takes the routine alerts: a
	 * new administrator, a role raised to administrator, the trap password
	 * used, and an executable file changed or added. An update or a host's
	 * record leaves no change row, so a file row here is one nothing accounts
	 * for. Read off the event, so nothing about it needs recording twice.
	 *
	 * @param array<string, mixed> $event A row as the writer persisted it.
	 */
	private static function signs_an_attack( array $event ): bool {
		$context = $event['context'] ?? array();
		$context = is_string( $context ) ? json_decode( $context, true ) : $context;
		$context = is_array( $context ) ? $context : array();
		$names   = static fn( string $roles ): bool => in_array( 'administrator', explode( ',', $roles ), true );

		switch ( (string) ( $event['event_type'] ?? '' ) ) {
			case 'canary_used':
				return true;
			case 'user_created':
				return $names( (string) ( $context['roles'] ?? '' ) );
			case 'user_role_changed':
				return $names( (string) ( $context['to'] ?? '' ) ) && ! $names( (string) ( $context['from'] ?? '' ) );
			case 'file_changed':
				return in_array( (string) ( $context['change'] ?? '' ), array( 'modified', 'added' ), true )
					&& \BetterShield\Integrity\Packages::can_run( (string) ( $event['object_id'] ?? '' ) );
			default:
				return false;
		}
	}

	/**
	 * The addresses with any case variant of an earlier one left out, keeping
	 * the first spelling. A variant reaches the same inbox, and core's mailer
	 * drops it when sending, so kept in the list it was a second recipient
	 * only on the screen, in the count and against the limit.
	 *
	 * @param string[] $addresses
	 * @return string[]
	 */
	private static function distinct( array $addresses ): array {
		$kept = array();

		foreach ( $addresses as $address ) {
			$key = strtolower( $address );

			if ( ! isset( $kept[ $key ] ) ) {
				$kept[ $key ] = $address;
			}
		}

		return array_values( $kept );
	}

	/**
	 * Who a message actually goes to: the addresses on record, or the site's
	 * own admin address when nobody has named any.
	 *
	 * @return string[]
	 */
	public function recipients(): array {
		return $this->effective( $this->settings()['recipients'] );
	}

	/**
	 * The site's admin address changed. While nobody is named, alerts go to
	 * that address, and the alert about the change went out after it had
	 * changed: only to the new one, the person who made the change, and every
	 * alert after it as well, with nothing saying alerts had changed hands.
	 *
	 * The address alerts went to until now is kept for a day, for the alert
	 * that says what changed, and the hand-over is recorded as a recipient
	 * taken off an explicit list is.
	 *
	 * @param mixed $old The address before.
	 * @param mixed $new The address now.
	 */
	public function admin_email_changed( $old, $new ): void {
		$old = sanitize_email( (string) $old );

		if ( array() !== $this->settings()['recipients'] || ! is_email( $old ) || 0 === strcasecmp( $old, sanitize_email( (string) $new ) ) ) {
			return;
		}

		update_option(
			self::PREVIOUS_OPTION,
			array(
				'address' => $old,
				'at'      => time(),
			),
			false
		);

		$next = $this->settings();

		Writer::instance()->record(
			'alerts_updated',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array(
					'muted'              => $next['muted'],
					'digest'             => $next['digest'],
					'digest_day'         => $next['digest_day'],
					'instant_critical'   => $next['instant_critical'],
					'recipients'         => 1,
					'recipients_removed' => 1,
					'cause'              => 'admin_email_changed',
				),
			)
		);
	}

	/**
	 * The admin address alerts went to before it last changed, while it is
	 * still owed the alert about the change, or ''.
	 */
	public function previous_recipient(): string {
		$stored = get_option( self::PREVIOUS_OPTION, array() );

		if ( ! is_array( $stored ) || time() - (int) ( $stored['at'] ?? 0 ) > self::PREVIOUS_FOR ) {
			return '';
		}

		$address = sanitize_email( (string) ( $stored['address'] ?? '' ) );

		return is_email( $address ) ? $address : '';
	}

	/** The previous address has been told. */
	public function forget_previous_recipient(): void {
		delete_option( self::PREVIOUS_OPTION );
	}

	/**
	 * Who alerts reach now and what each address gets. The site's admin
	 * address, while it stands in for a list nobody named, has the defaults.
	 *
	 * @return array<int, array{address: string, instant: string, digest: bool}>
	 */
	public function deliveries(): array {
		$keyed = self::by_address( $this->settings()['preferences'] );

		return array_map(
			static fn( string $address ): array => array_merge( array( 'address' => $address ), self::choice_of( $keyed, $address ) ),
			$this->recipients()
		);
	}

	/**
	 * @param string[] $stored
	 * @return string[]
	 */
	private function effective( array $stored ): array {
		if ( array() !== $stored ) {
			return $stored;
		}

		$fallback = sanitize_email( (string) get_option( 'admin_email' ) );

		return is_email( $fallback ) ? array( $fallback ) : array();
	}

	/**
	 * Whether saving this input would make the site quieter, which is what
	 * the password gate asks about on this route. Input the save would
	 * refuse makes nothing quieter, since nothing is written.
	 *
	 * @param array<string, mixed> $input
	 */
	public function weakens( array $input ): bool {
		$next = $this->validate( $input );

		return ! is_wp_error( $next ) && $this->quieter( $this->settings(), $next );
	}

	/**
	 * Turning alerting down: muted, the weekly summary or the instant alert
	 * switched off, or somebody who was being told no longer told.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $next
	 */
	private function quieter( array $before, array $next ): bool {
		return ( $next['muted'] && ! $before['muted'] )
			|| ( $next['host_managed'] && ! $before['host_managed'] )
			|| ( ! $next['digest'] && $before['digest'] )
			|| ( ! $next['instant_critical'] && $before['instant_critical'] )
			|| ( ! $next['account_notices_privileged'] && $before['account_notices_privileged'] )
			|| ( ! $next['account_notices_others'] && $before['account_notices_others'] )
			|| array() !== $this->no_longer_told( $before, $next )
			|| array() !== self::narrowed( $before, $next )
			// A type moved out of the instant email, compared as lists so a
			// swap of one type for another is still a type turned down (#197).
			|| array() !== array_diff( $next['instant_off'], $before['instant_off'] );
	}

	/**
	 * The addresses on both lists that will now hear less: a lower instant
	 * level, or the weekly summary taken away. Narrowing one person is going
	 * quiet for that person, and is rated as removing them is (#1886).
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $next
	 * @return string[]
	 */
	private static function narrowed( array $before, array $next ): array {
		$narrowed = array();
		$earlier  = self::by_address( (array) ( $before['preferences'] ?? array() ) );
		$now      = self::by_address( (array) ( $next['preferences'] ?? array() ) );

		// Only the addresses on both lists: one taken off is counted as removed.
		foreach ( array_intersect( array_map( 'strtolower', (array) $before['recipients'] ), array_map( 'strtolower', (array) $next['recipients'] ) ) as $address ) {
			$was        = self::choice_of( $earlier, $address );
			$preference = self::choice_of( $now, $address );

			if ( self::instant_rank( $preference['instant'] ) < self::instant_rank( $was['instant'] ) || ( $was['digest'] && ! $preference['digest'] ) ) {
				$narrowed[] = $address;
			}
		}

		return $narrowed;
	}

	/**
	 * Who stops being told. Read on the addresses mail actually goes to, so
	 * naming an address in place of the site's admin address — where alerts
	 * go while none is named — is a swap like any other.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $next
	 * @return string[]
	 */
	private function no_longer_told( array $before, array $next ): array {
		return array_values( array_diff( $this->effective( $before['recipients'] ), $this->effective( $next['recipients'] ) ) );
	}

	/**
	 * Whether alerts are muted now. A mute a staging answer set is not
	 * honored on a site that is no longer where that answer was given: a
	 * staging copy pushed over the live site carried its mute with it.
	 */
	public function is_muted(): bool {
		return $this->settings()['muted'] && ! \BetterShield\Onboarding\SiteIdentity::staging_mute_lapsed();
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{digest: bool, digest_day: int, instant_critical: bool, muted: bool, host_managed: bool, recipients: string[], account_notices_privileged: bool, account_notices_others: bool, preferences: array<int, array{address: string, instant: string, digest: bool}>, instant_off: string[]}|\WP_Error
	 */
	public function update_settings( array $input ) {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		$before = $this->settings();

		/*
		 * Recorded before the write, and refused when there was a prior state
		 * that could not be written down. Muting a site, or moving the
		 * addresses off it, is how a site goes quiet — and going quiet with no
		 * record of what it was before is the change hardest to notice and
		 * hardest to undo.
		 */
		if ( false === SettingsLedger::record( 'alerts', $before, $next ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $next, false );

		/*
		 * Taking an address off the list is going quiet for whoever was on it.
		 *
		 * The three switches were the whole test, so replacing the owner's
		 * address with somebody else's — same count, alerts still enabled,
		 * every switch untouched — produced an ordinary informational row whose
		 * only recorded detail was a number that had not changed. Redirecting
		 * every security alert away from the owner is the plainest form of
		 * making a site go quiet, and it was the one form this event could not
		 * see. Adding an address is not that, and is not rated as it.
		 */
		$removed = $this->no_longer_told( $before, $next );

		// Turning alerting down is the change worth finding in the log later:
		// a site that went quiet did so because someone made it quiet, and the
		// record should be as easy to find as a lockout. Turning it back up is
		// ordinary housekeeping.
		$quieter = $this->quieter( $before, $next );

		Writer::instance()->record(
			'alerts_updated',
			$quieter ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_INFO,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array(
					'muted'              => $next['muted'],
					'host_managed'       => $next['host_managed'],
					'digest'             => $next['digest'],
					'digest_day'         => $next['digest_day'],
					'instant_critical'   => $next['instant_critical'],
					'account_notices_privileged' => $next['account_notices_privileged'],
					'account_notices_others'     => $next['account_notices_others'],
					// A count, never the addresses: the log is read by everyone
					// who can read the log, and it has no other reason to
					// accumulate people's email.
					'recipients'         => count( $next['recipients'] ),
					// How many stopped being told, which is the fact a count
					// alone cannot carry — a swap leaves the count identical.
					// Still no addresses: how many is the signal, and who is
					// on the alerts screen for anyone entitled to look.
					'recipients_removed' => count( $removed ),
					// How many still on the list will hear less. A count, for
					// the same reason as above.
					'recipients_narrowed' => count( self::narrowed( $before, $next ) ),
					// Event types, never anyone's data: which ones wait for the
					// weekly summary.
					'instant_off'        => $next['instant_off'],
				),
			)
		);

		return $next;
	}

	/**
	 * What an input would become, or the refusal it would meet, with nothing
	 * saved. A settings import plans through this, so what it shows is what an
	 * apply would do.
	 *
	 * @param array<string, mixed> $input
	 * @return array{digest: bool, digest_day: int, instant_critical: bool, muted: bool, host_managed: bool, recipients: string[], account_notices_privileged: bool, account_notices_others: bool, preferences: array<int, array{address: string, instant: string, digest: bool}>, instant_off: string[]}|\WP_Error
	 */
	public function validate( array $input ) {
		// A key left out keeps its current value: a body that only flips the
		// mute must not silently reset the recipients or the digest day.
		$current = $this->settings();

		$next = array(
			'digest'           => isset( $input['digest'] ) ? rest_sanitize_boolean( $input['digest'] ) : $current['digest'],
			'digest_day'       => isset( $input['digest_day'] ) ? (int) $input['digest_day'] : $current['digest_day'],
			'instant_critical' => isset( $input['instant_critical'] ) ? rest_sanitize_boolean( $input['instant_critical'] ) : $current['instant_critical'],
			'muted'            => isset( $input['muted'] ) ? rest_sanitize_boolean( $input['muted'] ) : $current['muted'],
			'host_managed'     => isset( $input['host_managed'] ) ? rest_sanitize_boolean( $input['host_managed'] ) : $current['host_managed'],
			'recipients'       => $current['recipients'],
			'account_notices_privileged' => isset( $input['account_notices_privileged'] ) ? rest_sanitize_boolean( $input['account_notices_privileged'] ) : $current['account_notices_privileged'],
			'account_notices_others'     => isset( $input['account_notices_others'] ) ? rest_sanitize_boolean( $input['account_notices_others'] ) : $current['account_notices_others'],
			'preferences'      => $current['preferences'],
			'instant_off'                => $current['instant_off'],
		);

		if ( isset( $input['instant_off'] ) ) {
			if ( ! is_array( $input['instant_off'] ) ) {
				return new \WP_Error(
					'bettershield_bad_instant_off',
					__( 'The event types to hold for the weekly summary are a list.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$known = \BetterShield\Events\Types::labels();

			foreach ( $input['instant_off'] as $type ) {
				if ( ! is_string( $type ) || ! isset( $known[ $type ] ) ) {
					return new \WP_Error(
						'bettershield_bad_instant_off',
						__( 'One of those event types doesn’t exist on this site. Reload the page and try again.', 'bettershield' ),
						array( 'status' => 400 )
					);
				}
			}

			$types = self::known_types( $input['instant_off'] );

			$critical = array_column( array_filter( $this->instant_types(), static fn( array $type ): bool => $type['critical'] ), 'label', 'type' );
			$refused  = array_values( array_intersect_key( $critical, array_flip( array_diff( $types, $current['instant_off'] ) ) ) );

			if ( array() !== $refused ) {
				return new \WP_Error(
					'bettershield_critical_instant_off',
					sprintf(
						/* translators: %s: an event type's name, e.g. "File change found". */
						__( '%s has been critical on this site, and critical alerts are always sent at once.', 'bettershield' ),
						$refused[0]
					),
					array( 'status' => 400 )
				);
			}

			$next['instant_off'] = $types;
		}

		if ( $next['digest_day'] < 0 || $next['digest_day'] > 6 ) {
			return new \WP_Error(
				'bettershield_bad_digest_day',
				__( 'Choose a day for the weekly summary.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		if ( isset( $input['recipients'] ) ) {
			if ( ! is_array( $input['recipients'] ) ) {
				return new \WP_Error(
					'bettershield_bad_recipients',
					__( 'Recipients are a list of email addresses.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			$recipients = array();

			foreach ( array_values( $input['recipients'] ) as $index => $address ) {
				if ( ! is_string( $address ) ) {
					return new \WP_Error( 'bettershield_bad_recipient', sprintf(
						/* translators: %d: the one-based recipient row number. */
						__( 'Address %d is not text. Enter one email address per row.', 'bettershield' ), $index + 1
					), array( 'status' => 400 ) );
				}
				$address = trim( $address );

				if ( '' === $address ) {
					continue; // An empty row in the form is a row nobody filled in.
				}

				// Checked as typed, not after sanitizing: sanitize_email() answers
				// an empty string for something that is not an address at all,
				// which is indistinguishable from a blank row, and it takes out
				// a character an address cannot have, which leaves a different
				// address: alerts@acme_corp.com became alerts@acmecorp.com,
				// somebody else's domain. A typo that silently sends alerts
				// nowhere, or to a stranger, is the failure this refusal exists
				// to prevent, so anything cleaning would change is refused.
				$cleaned = sanitize_email( $address );

				if ( ! is_email( $address ) || $cleaned !== $address ) {
					// Cleaned into a working address that is not the one typed:
					// said as that, since the risk is somebody else's inbox.
					if ( '' !== $cleaned && is_email( $cleaned ) && $cleaned !== $address ) {
						return new \WP_Error(
							'bettershield_bad_recipient',
							sprintf(
								/* translators: 1: the address as it was typed, 2: the different address cleaning it would give. */
								__( '%1$s contains a character that isn’t allowed in an email address, and it would be %2$s, a different address. Check it and try again.', 'bettershield' ),
								$address,
								$cleaned
							),
							array( 'status' => 400 )
						);
					}

					return new \WP_Error(
						'bettershield_bad_recipient',
						sprintf(
							/* translators: %s: the address as it was typed. */
							__( '%s was refused: it is not an email address.', 'bettershield' ),
							// What was typed, not what survived cleaning: an
							// address reported back as an empty string cannot
							// be recognized as the one that needs correcting.
							$address
						),
						array( 'status' => 400 )
					);
				}

				$recipients[] = $cleaned;
			}

			$recipients = self::distinct( $recipients );

			if ( count( $recipients ) > self::MAX_RECIPIENTS ) {
				return new \WP_Error(
					'bettershield_too_many_recipients',
					sprintf(
						/* translators: %d: the maximum number of recipients. */
						__( 'Up to %d addresses can be added.', 'bettershield' ),
						self::MAX_RECIPIENTS
					),
					array( 'status' => 400 )
				);
			}

			$next['recipients'] = $recipients;
		}

		$preferences = $this->validate_preferences( $input, $current['preferences'], $next['recipients'] );

		if ( is_wp_error( $preferences ) ) {
			return $preferences;
		}

		$next['preferences'] = $preferences;

		return $next;
	}

	/**
	 * What each address on the next list wants: what the input says for it,
	 * else what it said before, else the default. Refused when a level is not
	 * one of the three, or when nobody would be left with instant alerts at
	 * high and critical — narrowing everyone is muting by another route, and
	 * the mute is the one switch that is meant to do that.
	 *
	 * @param array<string, mixed>                                              $input
	 * @param array<int, array{address: string, instant: string, digest: bool}> $current
	 * @param string[]                                                          $recipients
	 * @return array<int, array{address: string, instant: string, digest: bool}>|\WP_Error
	 */
	private function validate_preferences( array $input, array $current, array $recipients ) {
		/*
		 * A save names only the addresses whose choice it changes, so the
		 * others keep theirs. Putting a change back hands over the whole
		 * earlier list, where an address left out had made no choice: merged
		 * like a save, an address narrowed from the default kept its
		 * narrowing while the undo reported success.
		 */
		$merged = SettingsLedger::is_reverting() && isset( $input['preferences'] ) ? array() : self::by_address( $current );

		if ( isset( $input['preferences'] ) ) {
			if ( ! is_array( $input['preferences'] ) ) {
				return new \WP_Error(
					'bettershield_bad_preferences',
					__( 'Each address’s choices are a list of addresses with what each one gets.', 'bettershield' ),
					array( 'status' => 400 )
				);
			}

			foreach ( $input['preferences'] as $preference ) {
				if ( ! is_array( $preference ) || ! isset( $preference['address'] ) || ! is_string( $preference['address'] ) ) {
					continue;
				}

				$address = $preference['address'];

				if ( isset( $preference['instant'] ) && ! in_array( $preference['instant'], self::instant_levels(), true ) ) {
					return new \WP_Error(
						'bettershield_bad_instant_level',
						sprintf(
							/* translators: %s: an email address. */
							__( 'Choose instant alerts for %s: high and critical, critical only, or none.', 'bettershield' ),
							$address
						),
						array( 'status' => 400 )
					);
				}

				$key = strtolower( $address );

				$merged[ $key ] = array_merge(
					$merged[ $key ] ?? array( 'address' => $address ),
					array_filter(
						array(
							'instant' => $preference['instant'] ?? null,
							'digest'  => isset( $preference['digest'] ) ? rest_sanitize_boolean( $preference['digest'] ) : null,
						),
						static fn( $value ): bool => null !== $value
					)
				);
			}
		}

		$preferences = self::preferences_for( $recipients, array_values( $merged ) );
		$keyed       = self::by_address( $preferences );
		$someone     = array_filter( $recipients, static fn( string $address ): bool => self::INSTANT_HIGH === self::choice_of( $keyed, $address )['instant'] );

		if ( array() !== $recipients && array() === $someone ) {
			return new \WP_Error(
				'bettershield_no_instant_recipient',
				__( 'Keep at least one address on instant alerts for high and critical events, so an urgent alert always reaches someone. To stop all alerts, use Mute everything.', 'bettershield' ),
				array( 'status' => 400 )
			);
		}

		return $preferences;
	}
}
