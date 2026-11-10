<?php
/**
 * The Hub link's sender: this site's security events, in signed batches,
 * read from the log itself.
 *
 * - **The outbox is the log.** Nothing is copied aside to be sent. A cursor
 *   holds the id of the last row the hub has, and each run reads the rows
 *   after it through `Events\Query`, the one definition of the log every
 *   reader shares. The cursor moves only once the hub has the batch.
 * - **Never on a visitor's request, never on the checkout.** A visitor's page
 *   view that records a high or critical event sets one flag and nothing
 *   else, and the checkout sets nothing. Sending is scheduled work: every five
 *   minutes, and once more at once when a request that is not a visitor's —
 *   the dashboard, the REST API, WP-CLI, a scheduled task — records a high or
 *   critical event, or an administrator's request finds the flag set. That run
 *   is put on the schedule and the schedule runs it; no request sends.
 * - **What leaves.** Each event's id, type, severity and time; the account
 *   behind it as a keyed digest that tells two accounts apart and names
 *   neither; its network as the /24 or /64 the log keeps; and its details,
 *   less anything that names a person or looks like an address, with what it
 *   is about named only where that is not a person. The hub's own reads are
 *   not sent back to it: it knows what it asked, and hearing of it would have
 *   it read the site again for having read it.
 * - **Which events.** Alerting, always: high and critical, vulnerabilities,
 *   protections applied or undone, plugin and theme changes, role changes and
 *   other assistants' calls. Posture, unless the owner turns it off: medium
 *   events and completed checks. The rest of the log only once they turn it
 *   on.
 * - **Answers.** 202 moves the cursor, and so does 409, a batch the hub has
 *   already. 410 ends the link: the hub no longer reads this site, or another
 *   address holds this key. 429 and 503 wait as long as they ask. 401 waits:
 *   a key turned on here is learned at the hub's next read of the site. A
 *   batch the hub calls malformed three times is let go. Anything else waits
 *   longer each time, up to an hour.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hub\Link;

use BetterShield\Events\Query;
use BetterShield\Events\Writer;
use BetterShield\Mcp\Hub;
use BetterShield\Support\Ip;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Push {

	/** The scheduled task. */
	public const TASK = 'bettershield_hub_link_send';

	/** Its cadence, a recurrence this plugin adds: every five minutes. */
	public const RECURRENCE = 'bettershield_five_minutes';

	/**
	 * The cursor and how the answers have gone. Written by the task, and read
	 * by it and the Hub card, so never autoloaded.
	 */
	public const STATE_OPTION = 'bettershield_hub_link_state';

	/**
	 * Set by a visitor's request that recorded a high or critical event, and
	 * cleared by the request that puts the run on the schedule. Autoloaded and
	 * written when the link is turned on, so the request that checks it pays
	 * nothing for it.
	 */
	public const URGENT_OPTION = 'bettershield_hub_link_urgent';

	/** The most events one batch carries, as the contract allows. */
	public const BATCH_MAX = 500;

	/** The most one batch's body may take, as the contract allows: 256 KB. */
	public const BATCH_BYTES = 262144;

	/** What a batch's body holds besides its events, allowed for generously. */
	private const ENVELOPE_BYTES = 512;

	/** How many batches one run sends at most, so a backlog drains over a few runs. */
	private const BATCHES_PER_RUN = 4;

	/**
	 * How many pages of the log one run reads at most, sent or passed over. A
	 * page with nothing in it this site sends costs a read and no send, so a
	 * busy log of events the owner does not send is still kept up with.
	 */
	private const READS_PER_RUN = 20;

	/**
	 * The argument of the run put on the schedule for now. It keeps core from
	 * taking that run for the recurring one, and core refuses a second like it
	 * while one waits, so a burst asks once.
	 */
	private const SOON = 'soon';

	/**
	 * The argument a run carries when what the site runs has just changed.
	 * Its own, so it doesn't stand in the way of an urgent run or get
	 * folded into one.
	 */
	public const INVENTORY = 'inventory';

	/**
	 * Seconds between an update, activation or theme switch and the
	 * heartbeat that reports it. Long enough that a bulk update of many
	 * plugins sends one heartbeat, not one per plugin.
	 */
	public const INVENTORY_DELAY = 30;

	/** The longest a run waits after a failure. */
	private const MAX_WAIT = HOUR_IN_SECONDS;

	/** How many times a batch the hub calls malformed is sent before it is let go. */
	private const MALFORMED_TRIES = 3;

	/** The most details one event carries, and how long one may be: the hub keeps no more. */
	private const MAX_DETAILS = 20;
	private const MAX_DETAILS_BYTES = 2048;
	private const MAX_DETAIL_LENGTH = 120;

	/** Role changes, which the alerting class carries whatever their severity. */
	private const ROLE_TYPES = array( 'user_role_changed', 'user_role_granted', 'user_role_revoked', 'role_capabilities_changed' );

	/** Protections applied or undone, and the ones that failed to be. */
	private const HARDENING_TYPES = array( 'hardening_applied', 'hardening_reverted', 'hardening_failed', 'hardening_revert_failed' );

	/** The completed checks the posture class carries whatever their severity. */
	private const CHECK_TYPES = array( 'scan_completed', 'integrity_scan_completed' );

	/**
	 * What an event can be about that is a person or a way in as one: an
	 * account (or the name somebody typed for one), a session, an application
	 * password, a recovery link, an agent's account. Sent only as a digest.
	 */
	private const PERSONAL_OBJECTS = array( 'user', 'session', 'app_password', 'recovery_link', 'agent' );

	/** Details that name a person, never sent: a login, a name, an address, a label somebody chose. */
	private const PERSONAL_DETAILS = array( 'login', 'user_login', 'username', 'display_name', 'email', 'user_email', 'address', 'by', 'label' );

	/**
	 * What looks like an email or IP address, never sent whatever it is filed
	 * under. The same test the hub applies to what it keeps.
	 */
	private const LOOKS_LIKE_AN_ADDRESS = '/@|\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b/i';

	public static function register(): void {
		add_filter( 'cron_schedules', array( self::class, 'schedules' ) );
		add_action( 'bettershield_events_flushed', array( self::class, 'observe' ), 40, 2 );
		add_action( 'admin_init', array( self::class, 'meet' ), 30 );
		add_action( 'rest_api_init', array( self::class, 'meet' ) );

		// What the site runs changed. The hub won't hand out new protection
		// until it hears the new inventory, so it shouldn't wait for the
		// next ten-minute heartbeat.
		add_action( 'upgrader_process_complete', array( self::class, 'inventory_changed' ), 30, 0 );
		add_action( 'activated_plugin', array( self::class, 'inventory_changed' ), 30, 0 );
		add_action( 'deactivated_plugin', array( self::class, 'inventory_changed' ), 30, 0 );
		add_action( 'switch_theme', array( self::class, 'inventory_changed' ), 30, 0 );
	}

	/**
	 * A plugin or theme was updated, installed, switched on or off, or the
	 * theme changed: mark the heartbeat due and send it shortly.
	 *
	 * Nothing is sent from here. The run is put on the schedule a little
	 * way out, and core won't schedule the same single event twice inside
	 * ten minutes, so a bulk update ends in one run. The run keeps its
	 * usual back-off: a hub that asked us to wait is still waited for.
	 */
	public static function inventory_changed(): void {
		if ( ! self::scheduled() || ! Link::is_on() ) {
			return;
		}

		$state = self::state();

		if ( 0 === $state['inventory_due'] ) {
			$state['inventory_due'] = 1;
			update_option( self::STATE_OPTION, $state, false );
		}

		if ( ! wp_next_scheduled( self::TASK, array( self::INVENTORY ) ) ) {
			wp_schedule_single_event( time() + self::INVENTORY_DELAY, self::TASK, array( self::INVENTORY ) );
		}
	}

	/**
	 * Whether the link's task is on the schedule, which it is exactly while the
	 * link is on.
	 *
	 * Read from the schedule, which every request loads anyway, so that a site
	 * that has never turned the link on pays nothing for it on a visitor's
	 * request: not even the read of its switch.
	 */
	public static function scheduled(): bool {
		return false !== wp_next_scheduled( self::TASK );
	}

	/**
	 * The five-minute recurrence the task runs on.
	 *
	 * @param mixed $schedules The recurrences registered so far.
	 * @return mixed
	 */
	public static function schedules( $schedules ) {
		if ( ! is_array( $schedules ) ) {
			return $schedules;
		}

		$schedules[ self::RECURRENCE ] = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			// Named once translations can be asked for: something can read
			// the recurrences before then, and a name asked for early is a
			// notice on every request that does.
			'display'  => did_action( 'after_setup_theme' ) ? __( 'Every five minutes', 'bettershield' ) : 'Every five minutes',
		);

		return $schedules;
	}

	/**
	 * What was just written to the log, and the request it happened on.
	 *
	 * Nothing is sent from here. A visitor's page view with a high or critical
	 * event sets the flag, once; any other request with one puts a run on the
	 * schedule for now; the checkout does neither.
	 *
	 * @param array<int, array<string, mixed>>           $events
	 * @param array{front_end_get: bool, checkout: bool} $context
	 */
	public static function observe( array $events, array $context ): void {
		if ( ! empty( $context['checkout'] ) || ! self::scheduled() || ! Link::is_on() ) {
			return;
		}

		$urgent = false;

		foreach ( $events as $event ) {
			if ( (int) ( $event['severity'] ?? 0 ) >= Writer::SEVERITY_HIGH ) {
				$urgent = true;
				break;
			}
		}

		if ( ! $urgent ) {
			return;
		}

		if ( ! empty( $context['front_end_get'] ) ) {
			if ( ! get_option( self::URGENT_OPTION ) ) {
				update_option( self::URGENT_OPTION, time(), true );
			}

			return;
		}

		self::soon();
	}

	/**
	 * An administrator's request, in the dashboard or through the REST API,
	 * meets what a visitor's left: the flag becomes a run on the schedule for
	 * now. And a link that is on but whose task fell off the schedule, which
	 * somebody else's tidying can do, is put back on it.
	 */
	public static function meet(): void {
		if ( ! current_user_can( 'manage_options' ) || ! Link::is_on() ) {
			return;
		}

		if ( ! self::scheduled() ) {
			wp_schedule_event( time() + MINUTE_IN_SECONDS, self::RECURRENCE, self::TASK );
		}

		if ( get_option( self::URGENT_OPTION ) ) {
			update_option( self::URGENT_OPTION, 0, true );
			self::soon();
		}
	}

	/** Put one run on the schedule for now. */
	public static function soon(): void {
		wp_schedule_single_event( time(), self::TASK, array( self::SOON ) );
	}

	/**
	 * The link was just turned on: send what the log records from here on,
	 * starting with the next run.
	 */
	public static function start(): void {
		update_option( self::STATE_OPTION, self::fresh( Query::latest_id() ), false );
		update_option( self::URGENT_OPTION, 0, true );

		wp_unschedule_hook( self::TASK );
		wp_schedule_event( time() + MINUTE_IN_SECONDS, self::RECURRENCE, self::TASK );
	}

	/** The link went off: nothing more is sent, and its place in the log is forgotten. */
	public static function stop(): void {
		delete_option( self::STATE_OPTION );
		delete_option( self::URGENT_OPTION );
		wp_unschedule_hook( self::TASK );
	}

	/** Everything this class stores, gone. */
	public static function forget(): void {
		self::stop();
	}

	/**
	 * One run: the batches the hub does not have yet, then the heartbeat when
	 * one is due.
	 */
	public static function run(): void {
		$standing = Link::standing();

		// Off: a run left on the schedule ends there.
		if ( Link::OFF === $standing ) {
			self::stop();

			return;
		}

		// The hub's grant is gone, ended here or there, and the link with it.
		if ( Link::NOT_HUB === $standing ) {
			Link::disable( 'disconnected' );

			return;
		}

		// A copy, a staging copy, another hub: nothing leaves, and nothing the
		// owner might want back is deleted.
		if ( '' !== $standing ) {
			return;
		}

		$state = self::state();

		if ( $state['retry_at'] > time() ) {
			return;
		}

		$record  = Link::record();
		$key     = Link::digest_key();
		$hub     = self::hub_clients();
		$sending = true;

		$sent    = 0;

		for ( $read = 0; $sending && $sent < self::BATCHES_PER_RUN && $read < self::READS_PER_RUN; $read++ ) {
			$batch = self::batch( $state['cursor'], $record, $key, $hub );

			if ( null === $batch ) {
				break;
			}

			// A stretch of the log with nothing in it to send is passed over.
			if ( array() === $batch['events'] ) {
				$state['cursor'] = $batch['through'];
				continue;
			}

			++$sent;

			$answer = Wire::send(
				Wire::EVENTS,
				array(
					'batch_id' => $batch['id'],
					'events'   => $batch['events'],
				)
			);

			$sending = self::answered( $state, $answer, $batch );
		}

		if ( ! Link::is_on() ) {
			return;
		}

		if ( $sending && ( Heartbeat::due( $state ) || 0 !== $state['inventory_due'] ) ) {
			self::beat( $state );
		}

		if ( Link::is_on() ) {
			update_option( self::STATE_OPTION, $state, false );
		}
	}

	/**
	 * Send the heartbeat, and keep what it says the hub now has.
	 *
	 * @param array<string, mixed> $state
	 */
	private static function beat( array &$state ): void {
		$beat   = Heartbeat::payload( (string) $state['inventory'] );
		$answer = Wire::send( Wire::HEARTBEAT, $beat['payload'] );

		if ( 202 === $answer['status'] ) {
			$state['heartbeat_at']  = time();
			$state['inventory']     = $beat['inventory_digest'];
			$state['inventory_due'] = 0;
		}

		// Malformed is not mended by sending it again in five minutes: the
		// next one goes when the next is due.
		if ( 400 === $answer['status'] || 413 === $answer['status'] ) {
			$state['heartbeat_at']  = time();
			$state['inventory_due'] = 0;
			$state['last_answer']  = $answer['status'];
			$state['answered_at']  = time();

			return;
		}

		self::answered( $state, $answer, null );
	}

	/**
	 * What one answer does to the state.
	 *
	 * @param array<string, mixed>                       $state
	 * @param array{status: int, retry_after: int}       $answer
	 * @param array{id: string, through: int, events: array<int, array<string, mixed>>}|null $batch The batch it answered, or null for a heartbeat.
	 * @return bool Whether the run may go on sending.
	 */
	private static function answered( array &$state, array $answer, ?array $batch ): bool {
		$status = (int) $answer['status'];

		$state['last_answer'] = $status;
		$state['answered_at'] = time();

		if ( 202 === $status || 409 === $status ) {
			if ( null !== $batch ) {
				$state['cursor']       = $batch['through'];
				$state['last_sent_at'] = time();
			}

			$state['failures']  = 0;
			$state['malformed'] = 0;
			$state['retry_at']  = 0;

			return true;
		}

		if ( 410 === $status ) {
			Link::disable( 'hub' );

			return false;
		}

		if ( 429 === $status || 503 === $status ) {
			$state['retry_at'] = time() + min( self::MAX_WAIT, max( MINUTE_IN_SECONDS, (int) $answer['retry_after'] ) );

			return false;
		}

		if ( null !== $batch && ( 400 === $status || 413 === $status ) ) {
			++$state['malformed'];

			if ( $state['malformed'] >= self::MALFORMED_TRIES ) {
				$state['cursor']    = $batch['through'];
				$state['skipped']  += count( $batch['events'] );
				$state['malformed'] = 0;

				return true;
			}

			$state['retry_at'] = time() + self::MAX_WAIT;

			return false;
		}

		// 401, no answer at all, or one the contract does not give: longer
		// each time, from a minute to an hour.
		++$state['failures'];
		$state['retry_at'] = time() + min( self::MAX_WAIT, MINUTE_IN_SECONDS * ( 2 ** min( 6, $state['failures'] - 1 ) ) );

		return false;
	}

	/**
	 * The next batch after the cursor: the events of the classes this site
	 * sends, up to 500 of them and 256 KB.
	 *
	 * Its id is taken from the rows it covers and the events it carries, so the
	 * same batch sent again is the same batch to the hub, and a batch that
	 * carries more is a different one.
	 *
	 * @param array<string, mixed> $record  The link's record.
	 * @param string               $key     The digest key.
	 * @param string[]             $clients The hub's own client ids.
	 * @return array{id: string, through: int, events: array<int, array<string, mixed>>}|null Null when the log holds nothing after the cursor.
	 */
	public static function batch( int $cursor, array $record, string $key, array $clients ): ?array {
		$rows = Query::after( $cursor, self::BATCH_MAX );

		if ( array() === $rows ) {
			return null;
		}

		$events  = array();
		$through = $cursor;
		$bytes   = self::ENVELOPE_BYTES;

		foreach ( $rows as $row ) {
			$event = self::event_of( $row, $record, $key, $clients );

			if ( null !== $event ) {
				$size = strlen( (string) wp_json_encode( $event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) + 1;

				if ( array() !== $events && $bytes + $size > self::BATCH_BYTES ) {
					break;
				}

				$bytes   += $size;
				$events[] = $event;
			}

			$through = (int) $row['id'];
		}

		return array(
			'id'      => 'b_' . ( $cursor + 1 ) . '_' . $through . '_' . substr( hash( 'sha256', implode( ',', array_column( $events, 'id' ) ) ), 0, 12 ),
			'through' => $through,
			'events'  => $events,
		);
	}

	/**
	 * Which class an event belongs to: `alerting`, `posture` or `full_log`.
	 */
	public static function class_of( string $type, int $severity ): string {
		if (
			$severity >= Writer::SEVERITY_HIGH
			|| 'ability_used' === $type
			|| in_array( $type, self::ROLE_TYPES, true )
			|| in_array( $type, self::HARDENING_TYPES, true )
			|| 1 === preg_match( '/^(vulnerability|plugin|theme)_/', $type )
		) {
			return 'alerting';
		}

		if ( Writer::SEVERITY_MEDIUM === $severity || in_array( $type, self::CHECK_TYPES, true ) ) {
			return 'posture';
		}

		return 'full_log';
	}

	/**
	 * One stored row as it leaves, or null when it does not.
	 *
	 * @param array<string, mixed> $row     As `Query::after()` reads it.
	 * @param array<string, mixed> $record  The link's record.
	 * @param string               $key     The digest key.
	 * @param string[]             $clients The hub's own client ids.
	 * @return array<string, mixed>|null
	 */
	public static function event_of( array $row, array $record, string $key, array $clients ): ?array {
		$type     = (string) $row['event_type'];
		$severity = (int) $row['severity'];
		$context  = null !== $row['context'] ? json_decode( (string) $row['context'], true ) : null;
		$context  = is_array( $context ) ? $context : array();

		if ( 'ability_used' === $type && 'app' === ( $context['via'] ?? '' ) && in_array( (string) ( $context['credential'] ?? '' ), $clients, true ) ) {
			return null;
		}

		$class = self::class_of( $type, $severity );

		if ( ( 'posture' === $class && empty( $record['posture'] ) ) || ( 'full_log' === $class && empty( $record['full_log'] ) ) ) {
			return null;
		}

		$event = array(
			'id'          => (int) $row['id'],
			'type'        => $type,
			'severity'    => $severity,
			'occurred_at' => (string) Time::utc_iso( (string) $row['occurred_at'] ),
			'actor_ref'   => 'user' === (string) $row['actor_type'] && (int) $row['actor_id'] > 0 ? self::digest( 'user:' . (int) $row['actor_id'], $key ) : null,
			'ip_prefix'   => Ip::prefix_label( null !== $row['ip_prefix'] ? (string) $row['ip_prefix'] : null ),
			'context'     => self::details( $row, $context, $key ),
		);

		// An event whose details cannot be written as JSON goes without them.
		if ( false === wp_json_encode( $event ) ) {
			$event['context'] = null;
		}

		return $event;
	}

	/**
	 * An event's details as they leave: plain values under plain names,
	 * nothing that names a person or looks like an address, and what the
	 * event is about — a person only as a digest.
	 *
	 * @param array<string, mixed> $row
	 * @param array<string, mixed> $context
	 * @return array<string, string|int|float|bool>|null
	 */
	private static function details( array $row, array $context, string $key ): ?array {
		$out  = array();
		$type = null !== $row['object_type'] ? (string) $row['object_type'] : '';
		$id   = null !== $row['object_id'] ? (string) $row['object_id'] : '';

		if ( '' !== $type ) {
			$out['object_type'] = Text::clip( $type, self::MAX_DETAIL_LENGTH );

			if ( '' !== $id && in_array( $type, self::PERSONAL_OBJECTS, true ) ) {
				$ref = self::digest( $type . ':' . $id, $key );

				if ( null !== $ref ) {
					$out['object_ref'] = $ref;
				}
			} elseif ( '' !== $id && 1 !== preg_match( self::LOOKS_LIKE_AN_ADDRESS, $id ) ) {
				$out['object_id'] = Text::clip( $id, self::MAX_DETAIL_LENGTH );
			}
		}

		foreach ( $context as $name => $value ) {
			if ( count( $out ) >= self::MAX_DETAILS ) {
				break;
			}

			if ( ! is_string( $name ) || 1 !== preg_match( '/^[a-z0-9_]{1,32}$/i', $name ) || isset( $out[ $name ] ) || in_array( strtolower( $name ), self::PERSONAL_DETAILS, true ) ) {
				continue;
			}

			if ( is_bool( $value ) || is_int( $value ) || ( is_float( $value ) && is_finite( $value ) ) ) {
				$out[ $name ] = $value;
				continue;
			}

			if ( is_string( $value ) && 1 !== preg_match( self::LOOKS_LIKE_AN_ADDRESS, $value ) ) {
				$out[ $name ] = Text::clip( wp_check_invalid_utf8( $value, true ), self::MAX_DETAIL_LENGTH );
			}
		}

		// Within what the hub keeps of one event's details, the last let go first.
		while ( array() !== $out && strlen( (string) wp_json_encode( $out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) > self::MAX_DETAILS_BYTES ) {
			array_pop( $out );
		}

		return array() === $out ? null : $out;
	}

	/** A keyed digest standing for a person, or null without a key. */
	private static function digest( string $value, string $key ): ?string {
		return '' === $key ? null : 'sha256:' . hash_hmac( 'sha256', $value, $key );
	}

	/**
	 * The client ids the hub's grants on this site are held under: an
	 * assistant call made under one of them is the hub's own.
	 *
	 * @return string[]
	 */
	private static function hub_clients(): array {
		return array_values( array_map( 'strval', array_column( Hub::apps(), 'id' ) ) );
	}

	/**
	 * How sending has gone, as the Hub card reads it.
	 *
	 * @return array{last_sent_at: ?string, heartbeat_at: ?string, answered_at: ?string, last_answer: ?int, retry_at: ?string, skipped: int}
	 */
	public static function status(): array {
		$state = self::state();
		$at    = static fn ( int $time ): ?string => $time > 0 ? gmdate( 'c', $time ) : null;

		return array(
			'last_sent_at' => $at( (int) $state['last_sent_at'] ),
			'heartbeat_at' => $at( (int) $state['heartbeat_at'] ),
			'answered_at'  => $at( (int) $state['answered_at'] ),
			'last_answer'  => (int) $state['answered_at'] > 0 ? (int) $state['last_answer'] : null,
			'retry_at'     => (int) $state['retry_at'] > time() ? $at( (int) $state['retry_at'] ) : null,
			'skipped'      => (int) $state['skipped'],
		);
	}

	/**
	 * The stored state, in one shape whatever is stored.
	 *
	 * @return array{cursor: int, retry_at: int, failures: int, malformed: int, skipped: int, last_answer: int, answered_at: int, last_sent_at: int, heartbeat_at: int, inventory: string, inventory_due: int}
	 */
	public static function state(): array {
		$stored = get_option( self::STATE_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$state  = self::fresh( 0 );

		foreach ( $state as $name => $default ) {
			if ( isset( $stored[ $name ] ) ) {
				$state[ $name ] = is_string( $default ) ? (string) $stored[ $name ] : (int) $stored[ $name ];
			}
		}

		return $state;
	}

	/**
	 * A state that starts after the given row.
	 *
	 * @return array{cursor: int, retry_at: int, failures: int, malformed: int, skipped: int, last_answer: int, answered_at: int, last_sent_at: int, heartbeat_at: int, inventory: string, inventory_due: int}
	 */
	private static function fresh( int $cursor ): array {
		return array(
			'cursor'        => $cursor,
			'retry_at'      => 0,
			'failures'      => 0,
			'malformed'     => 0,
			'skipped'       => 0,
			'last_answer'   => 0,
			'answered_at'   => 0,
			'last_sent_at'  => 0,
			'heartbeat_at'  => 0,
			'inventory'     => '',
			'inventory_due' => 0,
		);
	}
}
