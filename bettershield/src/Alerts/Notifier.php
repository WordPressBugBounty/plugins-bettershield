<?php
/**
 * Decides when a message goes out, and makes sure it is never a visitor who
 * pays for it.
 *
 * Two schedules, and one rule that governs both.
 *
 * **The rule.** Sending mail is a network call of unknown duration, and
 * `wp_mail` on a slow SMTP host can take seconds. It therefore never happens
 * on a front-end request or anywhere near the checkout path, not even at
 * shutdown: PHP's shutdown functions run while the worker still holds the
 * connection, so "after the response" is not the same as "off the visitor's
 * clock". A critical event recorded by a visitor's request is queued instead,
 * and goes out from the next request that is safe to send from — an admin page,
 * the REST route the dashboard calls, WP-CLI, or the hourly task.
 *
 * **Instant, for `high` and `critical`.** The first qualifying event sends
 * immediately; anything else arriving inside the following few minutes is held
 * and joins one follow-up message rather than becoming a message each. A burst
 * is one incident, and reporting it as fifteen emails is how an alerting
 * system teaches people to filter it.
 *
 * **The weekly digest.** The task ticks daily and the sender decides whether
 * today is the owner's chosen day and whether one has already gone out this
 * week. Daily ticks rather than a weekly schedule because the owner picks the
 * day, wp-cron cannot be asked to move an existing schedule to a different
 * weekday, and a daily tick is also what lets the runner's overdue fallback
 * catch a site whose cron stopped.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Alerts;

use BetterShield\Events\Types;
use BetterShield\Events\Writer;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Notifier {

	/** Qualifying events recorded but not yet sent. A delivery buffer, not a log. */
	public const PENDING_OPTION = 'bettershield_alerts_pending';

	/** Set for the coalescing window after a critical alert goes out. */
	private const HOLD_KEY = 'alert_hold';

	/** Held for the two option operations that append to the queue, and no longer. */
	private const QUEUE_KEY = 'alert_queue';

	/**
	 * The queue guard's lifetime. Generous next to what it covers, because it
	 * is released the moment the write is done and a lapsed row is what stops
	 * a worker that died mid-append from holding it forever.
	 */
	private const QUEUE_SECONDS = 5;

	/**
	 * How long a burst is allowed to gather. Long enough that a cascade of
	 * related events arrives as one message; short enough that the second
	 * message is still the same afternoon.
	 */
	private const HOLD_SECONDS = 300;

	/**
	 * The queue is bounded like the event buffer is. If more than this many
	 * critical events land inside one window, the message says so and names the
	 * true count rather than quietly reporting the first few.
	 */
	private const MAX_PENDING = 25;

	/**
	 * How many times a failing delivery is retried before the queue is let go.
	 *
	 * The hourly dispatch drains it, so this is roughly three hours of trying —
	 * long enough to outlast a relay having a bad morning, short enough that a
	 * site with mail permanently misconfigured is not still retrying next year.
	 */
	private const MAX_ATTEMPTS = 3;

	/**
	 * How long a refused delivery waits before it is worth another go.
	 *
	 * Without it the three attempts above were spent in the same minute: the
	 * hourly task is not the only caller, and every admin page load and every
	 * dashboard request dispatches too. So a relay having a bad morning
	 * exhausted the retries before the morning was over, and the queue those
	 * attempts existed to protect was let go.
	 */
	private const RETRY_AFTER_SECONDS = HOUR_IN_SECONDS;

	/**
	 * Whether a delivery has already failed in this request.
	 *
	 * `Writer::flush()` drains in a loop and fires its action once per pass, and
	 * a send records an event of its own, which produces another pass. On the
	 * failure path that meant one refused delivery burned every retry inside a
	 * single request — and paid for a slow SMTP timeout each time — so the queue
	 * was gone before the hourly task ever saw it. One failure per request; the
	 * schedule provides the retries.
	 *
	 * Only failures are held back. A successful send empties the queue, so a
	 * second pass finds nothing to do and costs nothing.
	 */
	private bool $failed_this_request = false;

	/**
	 * Whether this request is switching this plugin (or its add-on) off.
	 *
	 * The hold assumes a later moment to send what it holds: the follow-up
	 * dispatch, or the hourly task. Once the plugin is off neither runs, so
	 * an alert queued behind a hold that an earlier alert had taken — an
	 * administrator created a minute before, say — sat there until somebody
	 * switched the plugin back on (#2470). On this request the hold is not
	 * waited out.
	 */
	private bool $last_word = false;

	private static ?Notifier $instance = null;

	public static function instance(): Notifier {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'bettershield_events_flushed', array( $this, 'observe' ), 10, 2 );
		add_action( 'bettershield_maintenance_summary_ready', array( $this, 'dispatch' ), 10, 0 );
	}

	/**
	 * Everything that was just persisted, and the kind of request it happened
	 * on.
	 *
	 * @param array<int, array<string, mixed>>           $events
	 * @param array{front_end_get: bool, checkout: bool} $context
	 */
	public function observe( array $events, array $context ): void {
		$instant = array();

		// A role set on an account is recorded twice, as the role it gained
		// and as the change. The change names both roles, so the email lists
		// that one line for it rather than two (#2831).
		$changed = array();

		foreach ( $events as $event ) {
			if ( 'user_role_changed' === (string) ( $event['event_type'] ?? '' ) ) {
				$changed[ (string) ( $event['object_id'] ?? '' ) ] = true;
			}
		}

		foreach ( $events as $event ) {
			if ( 'user_role_granted' === (string) ( $event['event_type'] ?? '' ) && isset( $changed[ (string) ( $event['object_id'] ?? '' ) ] ) ) { continue; }

			// High and critical both go out ahead of the digest: the events
			// that most reliably mean a compromise in progress — a new
			// privileged account, a role gaining capabilities — are high, and
			// a week is too long to sit on them. The coalescing window below
			// bounds a burst either way. This mailer's own bookkeeping never
			// qualifies: alerting about a failed alert re-queued the failure
			// and the give-up path stopped terminating.
			if ( Maintenance::holds( $event ) ) { continue; }

			// Each open file change has its own row, which decides the email.
			// This would count the one change twice, and adds nothing to it.
			if ( 'finding_opened' === (string) $event['event_type'] && 'files_altered' === (string) ( $event['object_id'] ?? '' ) ) { continue; }
			// Likewise each flagged store script has its own row, told once.
			if ( 'finding_opened' === (string) $event['event_type'] && \BetterShield\Audit\StoreScripts::CHECK === (string) ( $event['object_id'] ?? '' ) ) { continue; }

			// The row that opened it is in the instant email, which names it.
			// Alone, this was a second email minutes later about the same event.
			if ( 'incident_opened' === (string) $event['event_type'] && ! empty( ( (array) json_decode( (string) ( $event['context'] ?? '' ), true ) )['announced'] ) ) { continue; }

			// A high finding back within two weeks of closing is the same problem,
			// already told. The row and the weekly summary still say so.
			if ( 'finding_opened' === (string) $event['event_type'] && Writer::SEVERITY_HIGH === (int) $event['severity'] && ! empty( ( (array) json_decode( (string) ( $event['context'] ?? '' ), true ) )['repeat'] ) ) { continue; }

			$summary = Maintenance::event_summary( $event );
			// A type the owner moved to the weekly summary waits there, unless
			// this row of it is critical (#1973).
			if ( null !== $summary || ( (int) $event['severity'] >= Writer::SEVERITY_HIGH && 'alert_' !== substr( (string) $event['event_type'], 0, 6 ) && ! Settings::instance()->waits_for_summary( $event ) ) ) {
				$instant[] = array(
					'summary' => $summary,
					'type' => (string) $event['event_type'],
					'at'   => (string) $event['occurred_at'],
					'id'   => isset( $event['object_id'] ) ? (string) $event['object_id'] : null,
					// What it is about, named now: an account deleted before
					// the alert goes has no name left to read (#1829).
					'subject' => self::subject_of( $event ),
					// Who did it, named now for the same reason: the email asks
					// the reader whether each was them, and named nobody (#2073).
					'actor'   => 'user' === ( $event['actor_type'] ?? null ) ? (string) ( $event['actor_label'] ?? '' ) : '',
					// Through an assistant's connection, the account is the one
					// the credential runs as, not a person who acted: named as
					// such, so "was this you?" is not answered yes for them.
					'via_assistant' => 'mcp' === ( $event['entry_path'] ?? null ),
					'finding' => 'finding' === ( $event['object_type'] ?? null ) ? (string) ( $event['object_id'] ?? '' ) : '',
					// Which addresses it reaches: one set to critical only is
					// told when something in the message is critical (#1886).
					// A maintenance summary is on the instant path whatever the
					// events it sums up were rated, so it counts as high.
					'severity' => max( Writer::SEVERITY_HIGH, (int) $event['severity'] ),
				);
			}
		}

		if ( array() !== $instant ) {
			$this->queue( $instant );

			// A follow-up is scheduled for a plugin that will still be here
			// to run it; one that is switching off sends now instead.
			if ( ! $this->last_word ) {
				$this->follow_up();
			}
		}

		// The rule, in one line: a visitor's request never sends mail.
		if ( $context['front_end_get'] || $context['checkout'] || Maintenance::defers_delivery() ) {
			return;
		}

		$this->dispatch();
	}

	/**
	 * Send whatever is waiting, if this is the moment to send it.
	 *
	 * @return bool Whether a message went out.
	 */
	public function dispatch(): bool {
		$pending = $this->pending();

		if ( array() === $pending['events'] ) {
			return false;
		}

		$settings = Settings::instance()->settings();

		// Muted, or instant alerts turned off: these are not going to be sent,
		// so the queue is cleared rather than kept. Unmuting a site must not
		// deliver a month of old alarms, and nothing is lost by dropping them —
		// the queue is a delivery buffer and the events themselves are in the
		// log, where the digest still finds them.
		if ( Settings::instance()->is_muted() ) {
			$this->clear();

			return false;
		}

		// With instant alerts off, only the events that always email are kept.
		if ( ! $settings['instant_critical'] ) {
			$pending = $this->only_what_always_emails( $pending );

			if ( array() === $pending['events'] ) {
				$this->clear();

				return false;
			}
		}

		if ( $this->failed_this_request || $this->held_off() ) {
			return false;
		}

		/*
		 * Taking the coalescing window is what decides whether this request
		 * sends, so it is one statement rather than a read and a write: two
		 * dispatches arriving together both used to find the window clear and
		 * both send. Taken before the mail rather than after it, because the
		 * window between deciding and sending is the whole of the race.
		 */
		$claimed = Claim::claim( self::HOLD_KEY, self::HOLD_SECONDS );

		if ( ! $claimed && ! $this->last_word ) {
			$this->follow_up();

			return false;
		}

		// The admin address alerts went to before it changed hears about the
		// change too, not only the address that took its place.
		$previous = Settings::instance()->previous_recipient();
		$severity = max( array_map( static fn( array $event ): int => (int) $event['severity'], $pending['events'] ) );

		/*
		 * Nobody asked to be interrupted at this level: every address is set
		 * to critical only and nothing here is critical. That is a choice
		 * made, not a failure to retry, and the events wait in the log for
		 * the weekly summary as anything below the instant path does.
		 */
		if ( '' === $previous && array() !== Settings::instance()->recipients() && array() === Settings::instance()->audience( 'critical', $severity ) ) {
			$this->clear_sent( $pending );

			if ( $claimed ) {
				Claim::release( self::HOLD_KEY );
			}

			return false;
		}

		/*
		 * Correlated before the email is written, so it can name an incident
		 * these events open, where the task scheduled for a few seconds later
		 * would find the email already gone. Already running elsewhere, this
		 * does nothing and the Incidents screen still shows it.
		 */
		try {
			\BetterShield\Incidents\Engine::tick();
		} catch ( \Throwable $e ) {
			unset( $e );
		}

		// Written once per language among the recipients.
		$sent = Mailer::send(
			'critical',
			fn(): string => $this->instant_subject( $pending ),
			fn(): string => $this->instant_body( $pending ),
			array(
				'events'   => $pending['total'],
				'severity' => $severity,
			),
			'' !== $previous ? array( $previous ) : array()
		);

		if ( $sent ) {
			$this->clear_sent( $pending );

			if ( '' !== $previous ) {
				Settings::instance()->forget_previous_recipient();
			}

			// The claim taken above is the hold, and it runs its full window
			// from here.
			return true;
		}

		// Nothing went out, so the window is given back at once rather than
		// silencing the hourly retry for the length of it. Only a window this
		// request took: one an earlier alert holds is that alert's.
		if ( $claimed ) {
			Claim::release( self::HOLD_KEY );
		}

		/*
		 * The send failed — an SMTP timeout, a refused sender, a rate-limited
		 * relay. The queue is kept so the hourly dispatch can try again, which
		 * is the whole reason it exists: a transient mail failure is exactly
		 * the moment the owner most needs the second attempt, and clearing
		 * here threw away the events instant alerting is for.
		 *
		 * Not forever, though. A permanently broken mail configuration would
		 * otherwise retry every hour for as long as the site runs, so after a
		 * few goes the queue is let go. Nothing is lost that was not already
		 * kept: the events are in the activity log, the digest still finds
		 * them there, and the mailer has recorded each failure.
		 */
		$this->failed_this_request = true;
		$this->record_failed_attempt( $pending );

		return false;
	}

	/**
	 * The queue with everything but the events that always email taken out.
	 *
	 * @param array{total: int, events: array<int, array<string, mixed>>, seq: int} $pending
	 * @return array{total: int, events: array<int, array<string, mixed>>, seq: int}
	 */
	private function only_what_always_emails( array $pending ): array {
		$kept = array_values( array_filter( $pending['events'], static fn( array $event ): bool => empty( $event['summary'] ) && Settings::always_emails( (string) $event['type'] ) ) );

		if ( count( $kept ) === count( $pending['events'] ) && $pending['total'] === count( $kept ) ) {
			return $pending;
		}

		$pending['events'] = $kept;
		$pending['total']  = count( $kept );

		update_option( self::PENDING_OPTION, $pending, false );

		return $pending;
	}

	/**
	 * Send what is waiting before this request ends, because this plugin is
	 * being switched off by it.
	 *
	 * Called from the deactivation hook, once the event saying so has been
	 * recorded. The writer's shutdown flush announces that event and the
	 * dispatch that follows sends it, the hold or no hold, together with
	 * anything else queued — so nothing waiting is left behind, and switching
	 * off this plugin and its add-on in one bulk action still sends one
	 * message, not one each. A last dispatch after the flush covers a queue
	 * the flush had nothing new to announce for.
	 *
	 * One attempt: a refused delivery is recorded and kept exactly as any
	 * other is, for the plugin's return. The mute and the instant-alerts
	 * setting still decide, as they always do.
	 */
	public function send_before_switch_off(): void {
		if ( $this->last_word ) {
			return;
		}

		$this->last_word = true;

		// After the writer's flush at 100, in the same request.
		add_action( 'shutdown', array( $this, 'last_dispatch' ), 101, 0 );
	}

	/**
	 * The final dispatch of a request that switched this plugin off. Public
	 * only because the shutdown hook calls it.
	 */
	public function last_dispatch(): void {
		if ( $this->last_word && ! $this->failed_this_request ) {
			$this->dispatch();
		}

		$this->last_word = false;
	}

	/**
	 * Have the queue sent when the coalescing window closes.
	 *
	 * Only another event or the hourly safety net sent it, so on a quiet site
	 * a critical alert queued a minute into the window waited up to an hour,
	 * not the few minutes the window promises (#2179). One dispatch is
	 * scheduled for the moment the hold lapses; one already due then is not
	 * doubled, and WordPress refuses an identical event within ten minutes.
	 */
	private function follow_up(): void {
		$at = Claim::lapses_at( self::HOLD_KEY );

		if ( $at <= time() ) {
			return;
		}

		$due  = $at + 5;
		$next = wp_next_scheduled( 'bettershield_alerts_dispatch' );

		if ( false !== $next && $next >= $at && $next <= $due + MINUTE_IN_SECONDS ) {
			return;
		}

		wp_schedule_single_event( $due, 'bettershield_alerts_dispatch' );
	}

	/**
	 * Whether the last delivery failed recently enough that trying again now
	 * would spend an attempt rather than make one.
	 *
	 * A queue with no recorded attempt has never been tried, and a queue an
	 * event has just been added to has had its attempt count reset along with
	 * this — giving up on the last incident is not a reason to stay quiet
	 * about the next one.
	 */
	private function held_off(): bool {
		$stored = get_option( self::PENDING_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$last   = (int) ( $stored['attempted_at'] ?? 0 );

		return $last > 0 && ( time() - $last ) < self::RETRY_AFTER_SECONDS;
	}

	/**
	 * Count a failed delivery, and give up once there have been enough.
	 *
	 * @param array{total: int, events: array<int, array<string, mixed>>} $pending
	 */
	private function record_failed_attempt( array $pending ): void {
		$stored   = get_option( self::PENDING_OPTION, array() );
		$stored   = is_array( $stored ) ? $stored : array();
		$attempts = (int) ( $stored['attempts'] ?? 0 ) + 1;

		if ( $attempts >= self::MAX_ATTEMPTS ) {
			$this->clear();

			Writer::instance()->record(
				'alert_delivery_failed',
				Writer::SEVERITY_HIGH,
				array(
					'object_type' => 'alert',
					'context'     => array(
						'events'   => $pending['total'],
						'attempts' => $attempts,
					),
				)
			);

			return;
		}

		$stored['attempts']     = $attempts;
		$stored['attempted_at'] = time();

		update_option( self::PENDING_OPTION, $stored, false );
	}

	/**
	 * The daily tick that produces a weekly digest.
	 */
	public static function digest_tick(): void {
		$settings = Settings::instance()->settings();

		if ( Settings::instance()->is_muted() || ! $settings['digest'] || array() === Settings::instance()->audience( 'digest' ) ) {
			return;
		}

		if ( ! self::digest_is_due( $settings['digest_day'] ) ) {
			return;
		}

		self::send_digest( true );
	}

	/**
	 * Build and send a digest now, whatever day it is. The scheduled path and
	 * a deliberate send from the screen both come through here, so what an
	 * owner previews is exactly what the schedule produces.
	 */
	public static function send_digest( bool $scheduled = false ): bool {
		return 'sent' === self::deliver_digest( $scheduled );
	}

	/**
	 * A deliberate send from the screen, and what became of it.
	 *
	 * One bit could not tell "a summary went out moments ago, so nothing was
	 * tried" from "the mail server refused it", and the screen said the second
	 * for both.
	 *
	 * @return string sent, refused, too_soon, just_tried, muted, no_recipient, or no_digest_recipient.
	 */
	public static function digest_now(): string {
		return self::deliver_digest( false );
	}

	/**
	 * @return string sent, refused, too_soon, just_tried, muted, no_recipient, or no_digest_recipient.
	 */
	private static function deliver_digest( bool $scheduled ): string {
		/*
		 * A refusal is not a report. The mailer declines outright when the
		 * site is muted or has nowhere to send, and marking the window sent on
		 * the strength of that stamped a digest nobody received — which then
		 * held the next real one back for up to six days, and moved the window
		 * it would eventually cover past the events it was meant to carry.
		 * A mail server that takes the message and fails to deliver it is a
		 * different thing, still marked, and recorded by the mailer where it
		 * can be seen.
		 */
		if ( ! Mailer::can_send() ) {
			return Settings::instance()->is_muted() ? 'muted' : 'no_recipient';
		}

		// Every address has turned the weekly summary off for itself (#1886).
		if ( ! Mailer::can_send( 'digest' ) ) {
			return 'no_digest_recipient';
		}

		/*
		 * Building a digest reads several tables and sending it waits on a
		 * mail server, so the gap between deciding to send and recording that
		 * it was sent is seconds wide — wide enough for a second run to decide
		 * the same thing. The claim closes it, and is not released: a send
		 * that completed must not be repeated by whatever arrives next.
		 */
		if ( ! Claim::claim( 'digest_send', 10 * MINUTE_IN_SECONDS ) ) {
			// The window is held after a summary that went out, and equally
			// after one the mail server refused or one still being sent. Only
			// the first may be answered as "one went out".
			return Claim::held( 'digest_went_out' ) ? 'too_soon' : 'just_tried';
		}

		// Whatever the last attempt did, this one has not gone out yet.
		Claim::release( 'digest_went_out' );

		$digest   = Digest::build();
		$built_in = get_locale();

		/*
		 * Written once per language among the recipients, each from a build
		 * made in that language: what the summary lists (a finding's title,
		 * say) is worded as it is read, and the build above already serves the
		 * language it was made in. The window is the same for every build, so
		 * every reader gets the same week.
		 */
		$sent = Mailer::send(
			'digest',
			static fn(): string => Digest::has_changes( $digest )
				? __( 'Your weekly security summary', 'bettershield' )
				: __( 'Your weekly security summary: a quiet week', 'bettershield' ),
			static fn(): string => Digest::render( get_locale() === $built_in ? $digest : Digest::build() ),
			array(
				'score'    => $digest['score'],
				'opened'   => count( $digest['opened'] ),
				'resolved' => count( $digest['resolved'] ),
			)
		);

		if ( $sent ) {
			Claim::claim( 'digest_went_out', 10 * MINUTE_IN_SECONDS );
		}

		// Marked whatever the mail server said. The window has been reported on
		// either way, and re-reporting it tomorrow would double-count every
		// finding in it; a delivery failure is recorded as its own fact by the
		// mailer, where it can be seen.
		Digest::mark_sent();

		// The schedule's marker moves only when the schedule is what called.
		// Pressing "send now" costs the owner nothing: the digest they chose
		// to receive still arrives on the day they chose.
		if ( $scheduled ) {
			Digest::mark_scheduled();
		}

		return $sent ? 'sent' : 'refused';
	}

	/**
	 * Whether today is the day and a week has actually passed.
	 *
	 * Both conditions, not either: the day alone would re-send after a manual
	 * digest, and the elapsed week alone would ignore the owner's choice.
	 */
	private static function digest_is_due( int $digest_day ): bool {
		// wp_date() with no timestamp is "now, in the site's own timezone",
		// which is the weekday the owner actually picked. Passing it
		// current_time('timestamp') would apply the site's offset twice, and a
		// Monday digest arriving on Sunday evening is the wrong week for the
		// person reading it.
		if ( (int) wp_date( 'w' ) !== $digest_day ) {
			return false;
		}

		// The schedule's own record, not "when a digest last went out" — a
		// manual send reports the window and moves it, but it is not the
		// weekly digest and must not stand in for one.
		$last = Digest::last_scheduled();

		if ( '' === $last ) {
			// The first one waits for a full day on record: installed on the
			// digest day, a summary arrived within minutes with nothing in
			// it to sum up (#2486).
			$activated = Digest::activated_at();

			return null === $activated || ( time() - $activated ) >= DAY_IN_SECONDS;
		}

		$sent_at = strtotime( $last . ' UTC' );

		if ( false === $sent_at ) {
			return true;
		}

		// Six days, not seven: the tick can land a few hours either side of the
		// same clock time each week, and a strict seven would skip a week
		// whenever it landed early.
		return ( time() - $sent_at ) > 6 * DAY_IN_SECONDS;
	}

	/* ---- the queue ---------------------------------------------------- */

	/**
	 * @param array<int, array{type: string, at: string, id: ?string}> $events
	 */
	private function queue( array $events ): void {
		/*
		 * Read, modify, write — the shape two workers lose an event to, and
		 * the queue is appended to from shutdown on any request that recorded
		 * a qualifying event. The claim is what decides which of them goes
		 * first; it covers two option operations and is given straight back,
		 * because this runs on a visitor's request and nothing there may wait
		 * on anything slower than the database. That is also why the send
		 * below cannot be guarded the same way: `wp_mail` is inside it.
		 *
		 * A request that loses the claim appends anyway rather than dropping
		 * what it was handed. An event kept through an unlikely interleaving
		 * is worth more than one discarded every time.
		 */
		$claimed = Claim::claim( self::QUEUE_KEY, self::QUEUE_SECONDS );

		// `pending()` returns the queue without the attempt count, so a newly
		// arrived critical event starts the retries over. That is deliberate:
		// giving up on the last incident is not a reason to stay quiet about
		// the next one.
		$pending = $this->pending();
		$seq     = $pending['seq'];

		foreach ( $events as $event ) {
			++$pending['total'];

			if ( count( $pending['events'] ) >= self::MAX_PENDING ) {
				/*
				 * Full. A kind already named waits in the count; a kind not
				 * yet named takes the place of the latest repeat of the most
				 * repeated one. Arrival order alone let a burst of file
				 * changes fill every line, and a new administrator created
				 * after it was only a number at the bottom.
				 */
				$slot = self::repeat_to_give_up( $pending['events'], (string) $event['type'] );

				if ( null === $slot ) {
					continue;
				}

				array_splice( $pending['events'], $slot, 1 );
			}

			++$seq;
			$event['seq']        = $seq;
			$pending['events'][] = $event;
		}

		$pending['seq'] = $seq;

		update_option( self::PENDING_OPTION, $pending, false );

		if ( $claimed ) {
			Claim::release( self::QUEUE_KEY );
		}
	}

	/**
	 * Which queued entry a new kind of event may take the place of: the
	 * latest of the kind repeated most, or null when the new one's kind is
	 * already named or nothing repeats.
	 *
	 * @param array<int, array<string, mixed>> $queued
	 */
	private static function repeat_to_give_up( array $queued, string $type ): ?int {
		$counts = array_count_values( array_map( static fn( array $event ): string => (string) $event['type'], $queued ) );

		if ( isset( $counts[ $type ] ) ) {
			return null;
		}

		arsort( $counts );
		$most = (string) array_key_first( $counts );

		if ( ( $counts[ $most ] ?? 0 ) < 2 ) {
			return null;
		}

		for ( $index = count( $queued ) - 1; $index >= 0; $index-- ) {
			if ( $most === (string) $queued[ $index ]['type'] ) {
				return $index;
			}
		}

		return null;
	}

	/**
	 * @return array{total: int, events: array<int, array{type: string, at: string, id: ?string, seq: int}>, seq: int}
	 */
	private function pending(): array {
		$stored = get_option( self::PENDING_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$events = array();
		$seq    = (int) ( $stored['seq'] ?? 0 );

		foreach ( (array) ( $stored['events'] ?? array() ) as $event ) {
			if ( ! is_array( $event ) || ! isset( $event['type'] ) ) {
				continue;
			}

			$events[] = array(
				'summary' => isset( $event['summary'] ) && is_array( $event['summary'] ) ? $event['summary'] : null,
				'type' => (string) $event['type'],
				'at'   => isset( $event['at'] ) ? (string) $event['at'] : '',
				'id'   => isset( $event['id'] ) && null !== $event['id'] ? (string) $event['id'] : null,
				'subject' => isset( $event['subject'] ) ? (string) $event['subject'] : '',
				'actor'   => isset( $event['actor'] ) ? (string) $event['actor'] : '',
				'via_assistant' => ! empty( $event['via_assistant'] ),
				'finding' => isset( $event['finding'] ) ? (string) $event['finding'] : '',
				// Queued before severities were kept, it qualified at high.
				'severity' => (int) ( $event['severity'] ?? Writer::SEVERITY_HIGH ),
				// Where this entry sits in the queue, which is the only thing
				// telling two events of the same type recorded in the same
				// millisecond apart. A queue written before this existed has
				// none, and reads as older than everything that follows.
				'seq'  => (int) ( $event['seq'] ?? 0 ),
			);

			$seq = max( $seq, (int) ( $event['seq'] ?? 0 ) );
		}

		return array(
			'total'  => max( count( $events ), (int) ( $stored['total'] ?? 0 ) ),
			'events' => $events,
			'seq'    => $seq,
		);
	}

	/**
	 * Take out what was just sent, and only that.
	 *
	 * The queue is read at the top of a dispatch and cleared at the bottom,
	 * with `wp_mail` between them — seconds, on a slow relay. Anything another
	 * request recorded inside that window was written by somebody who knew
	 * nothing about this one, and deleting the whole option deleted an event
	 * nobody had sent. So the clear names what it is clearing.
	 *
	 * @param array{total: int, events: array<int, array<string, mixed>>, seq: int} $sent
	 */
	private function clear_sent( array $sent ): void {
		$high = 0;

		foreach ( $sent['events'] as $event ) {
			$high = max( $high, (int) ( $event['seq'] ?? 0 ) );
		}

		$stored = get_option( self::PENDING_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$kept = array();

		foreach ( (array) ( $stored['events'] ?? array() ) as $event ) {
			if ( is_array( $event ) && (int) ( $event['seq'] ?? 0 ) > $high ) {
				$kept[] = $event;
			}
		}

		if ( array() === $kept ) {
			$this->clear();

			return;
		}

		update_option(
			self::PENDING_OPTION,
			array(
				// Never fewer than the entries that can still be named: what
				// arrived past the cap cannot be attributed to either side of
				// the send, and understating is the safer way to be wrong.
				'total'  => max( count( $kept ), (int) ( $stored['total'] ?? 0 ) - (int) $sent['total'] ),
				'events' => $kept,
				// A place in the queue that has been handed out is never
				// handed out again while anything still holds one.
				'seq'    => max( $high, (int) ( $stored['seq'] ?? 0 ) ),
			),
			false
		);
	}

	private function clear(): void {
		delete_option( self::PENDING_OPTION );
	}

	/* ---- what a critical alert says ----------------------------------- */

	/**
	 * @param array{total: int, events: array<int, array<string, mixed>>} $pending
	 */
	private function instant_subject( array $pending ): string {
		/*
		 * A maintenance summary is a message about events, not one of them:
		 * counted, it made "4 security events" of three (#1840).
		 */
		$summaries = count( array_filter( $pending['events'], static fn( array $event ): bool => ! empty( $event['summary'] ) ) );
		$events    = array_values( array_filter( $pending['events'], static fn( array $event ): bool => empty( $event['summary'] ) ) );
		$total     = max( 0, (int) $pending['total'] - $summaries );

		if ( 0 === $total ) {
			return __( 'Maintenance window ended: summary of what happened', 'bettershield' );
		}

		$urgent = array_values( array_filter( $events, array( self::class, 'needs_action' ) ) );

		if ( array() !== $urgent ) {
			if ( 1 !== $total ) {
				return sprintf(
					/* translators: %d: number of events. */
					_n( 'Action needed: %d security event recorded', 'Action needed: %d security events recorded', $total, 'bettershield' ),
					$total
				);
			}

			return 'file_changed' === (string) $urgent[0]['type']
				? __( 'Action needed: a code file changed and nothing explains it', 'bettershield' )
				: sprintf(
					/* translators: %s: what happened. */
					__( 'Action needed: %s', 'bettershield' ),
					Types::label( (string) $urgent[0]['type'] )
				);
		}

		// One event names what it was about, where it was about something:
		// "Finding opened" alone did not say which (#2396).
		if ( 1 === $total && isset( $events[0] ) ) {
			$about = (string) ( $events[0]['subject'] ?? '' );

			if ( '' !== $about && in_array( (string) $events[0]['type'], array( 'finding_opened', 'file_changed' ), true ) ) {
				return sprintf(
					/* translators: %s: what it is about: a finding, a file or the trap page. */
					__( 'Worth a look: %s', 'bettershield' ),
					$about
				);
			}

			// Requested by anything that follows links, so it's worth a look and no more.
			if ( 'canary_page_touched' === (string) $events[0]['type'] ) {
				return sprintf(
					/* translators: %s: what it is about: a finding, a file or the trap page. */
					__( 'Worth a look: %s', 'bettershield' ),
					Types::label( 'canary_page_touched' )
				);
			}

			return '' === $about
				? Types::label( (string) $events[0]['type'] )
				: sprintf(
					/* translators: 1: what happened, 2: what it was about (an account, a protection, a file, a finding). */
					__( '%1$s: %2$s', 'bettershield' ),
					Types::label( (string) $events[0]['type'] ),
					$about
				);
		}

		return sprintf(
			/* translators: %d: number of events. */
			_n(
				'Worth a look: %d security event recorded',
				'Worth a look: %d security events recorded',
				$total,
				'bettershield'
			),
			$total
		);
	}

	/**
	 * Whether a queued event asks the reader to act now: proof of an attack,
	 * or a critical change to a file that can run. The trap page is not on
	 * it: any scanner that follows links requests it, which proves nothing.
	 *
	 * @param array<string, mixed> $event A queued event.
	 */
	private static function needs_action( array $event ): bool {
		$type = (string) ( $event['type'] ?? '' );

		if ( Settings::always_emails( $type ) ) {
			// A booking is emailed at once so nobody is surprised when alerts
			// go quiet, not because something needs doing: the owner who booked
			// it reads "if you expected this", not "Action needed".
			return 'maintenance_window_booked' !== $type;
		}

		return 'file_changed' === $type
			&& (int) ( $event['severity'] ?? 0 ) >= Writer::SEVERITY_CRITICAL
			&& \BetterShield\Integrity\Packages::can_run( (string) ( $event['id'] ?? '' ) );
	}

	/**
	 * Whether a queued event is something a person did, so they can have
	 * expected it. A finding or a critical event is never that, and an
	 * assistant's connection is not a person.
	 *
	 * @param array<string, mixed> $event A queued event.
	 */
	private static function a_person_did( array $event ): bool {
		return '' !== (string) ( $event['actor'] ?? '' )
			&& empty( $event['via_assistant'] )
			&& '' === (string) ( $event['finding'] ?? '' )
			&& 'finding_opened' !== (string) ( $event['type'] ?? '' )
			&& (int) ( $event['severity'] ?? Writer::SEVERITY_CRITICAL ) < Writer::SEVERITY_CRITICAL;
	}

	/**
	 * What an event was about, in words: an account by its login (with its
	 * role, where it was just created), a protection or a finding by its
	 * title, a file by its path. Empty where only an internal name is known.
	 *
	 * @param array<string, mixed> $event An event as the writer flushed it.
	 */
	private static function subject_of( array $event ): string {
		$id      = isset( $event['object_id'] ) ? (string) $event['object_id'] : '';
		$type    = isset( $event['object_type'] ) ? (string) $event['object_type'] : null;
		$context = $event['context'] ?? null;
		$context = is_string( $context ) ? json_decode( $context, true ) : $context;
		$name    = \BetterShield\Events\Query::object_label( (string) ( $event['event_type'] ?? '' ), $type, $id, $context );

		// The pairing is the one credential there is; its key, "pairing",
		// is not a subject anybody reads (#2073).
		if ( 'mcp' === $type && 'pairing' === $id ) {
			return '';
		}

		if ( null === $name ) {
			// An option name says nothing the label did not, a setting's least
			// of all (#2489); an id of an account or an application password
			// nobody can name says nothing at all.
			$name = '' === $id || str_starts_with( $id, 'bettershield_' ) || in_array( $type, array( 'user', 'setting', 'network_setting', 'app_password' ), true ) ? '' : $id;

			// An application password by the name the row recorded for it.
			if ( 'app_password' === $type && is_array( $context ) && '' !== trim( (string) ( $context['name'] ?? '' ) ) ) {
				$name = (string) $context['name'];
			}
		}

		// The roles a change moved between, by the names the Users screen
		// gives them: "Role changed: bob" did not say which (#2831).
		if ( '' !== $name && 'user_role_changed' === ( $event['event_type'] ?? '' ) && is_array( $context ) && '' !== (string) ( $context['to'] ?? '' ) ) {
			$name = sprintf(
				/* translators: 1: an account's login, 2: the roles it had, 3: the roles it has now. */
				__( '%1$s, %2$s to %3$s', 'bettershield' ),
				$name,
				self::role_names( (string) ( $context['from'] ?? '' ) ),
				self::role_names( (string) $context['to'] )
			);
		}

		if ( '' !== $name && 'user_created' === ( $event['event_type'] ?? '' ) && is_array( $context ) && '' !== (string) ( $context['roles'] ?? '' ) ) {
			$name = sprintf(
				/* translators: 1: an account's login, 2: its role. */
				__( '%1$s (%2$s)', 'bettershield' ),
				$name,
				(string) $context['roles']
			);
		}

		/*
		 * What a policy change gave up, as the log's row says it: the alert
		 * for a weakened requirement said only who made it, never which
		 * roles it no longer covered.
		 */
		$weakened = is_array( $context ) && is_array( $context['weakened'] ?? null ) ? array_values( array_filter( array_map( static fn( $part ): string => is_scalar( $part ) ? trim( (string) $part ) : '', $context['weakened'] ) ) ) : array();

		// The passkey requirement records the roles it no longer covers by
		// slug; a reader is given each role's own name, as it was translated
		// for this site, and a slug only where the role is gone.
		if ( 'passkey_policy_changed' === ( $event['event_type'] ?? '' ) ) {
			$roles    = wp_roles()->roles;
			$weakened = array_map( static fn( string $slug ): string => isset( $roles[ $slug ]['name'] ) ? translate_user_role( (string) $roles[ $slug ]['name'] ) : $slug, $weakened );
		}

		if ( array() !== $weakened ) {
			$given = 'passkey_policy_changed' === ( $event['event_type'] ?? '' )
				/* translators: %s: the roles a requirement no longer covers, comma-separated. */
				? sprintf( __( 'no longer required for: %s', 'bettershield' ), implode( ', ', $weakened ) )
				/* translators: %s: what the change gave up, comma-separated. */
				: sprintf( __( 'made weaker: %s', 'bettershield' ), implode( ', ', $weakened ) );
			$name  = '' === $name
				? $given
				/* translators: 1: what it was about, 2: what the change gave up. */
				: sprintf( __( '%1$s (%2$s)', 'bettershield' ), $name, $given );
		}

		return \BetterShield\Support\Text::clip( $name, 120 );
	}

	/**
	 * A stored role list ("author,editor") by the roles' own names, as they
	 * were translated for this site; a slug only where the role is gone.
	 */
	private static function role_names( string $slugs ): string {
		$slugs = array_values( array_filter( array_map( 'trim', explode( ',', $slugs ) ) ) );

		if ( array() === $slugs ) {
			return __( 'no role', 'bettershield' );
		}

		$names = wp_roles()->get_names();

		return implode( ', ', array_map( static fn( string $slug ): string => isset( $names[ $slug ] ) ? translate_user_role( (string) $names[ $slug ] ) : $slug, $slugs ) );
	}

	/**
	 * For the connections used from a new network: "What it did" once per
	 * distinct connection, then where to revoke one.
	 *
	 * @param array<int, array<string, mixed>> $events
	 * @return string[]
	 */
	private static function connection_links( array $events ): array {
		$lines = array();
		$seen  = array();

		foreach ( $events as $event ) {
			$id = (string) ( $event['id'] ?? '' );

			if ( 'agent_new_network' !== ( $event['type'] ?? '' ) || '' === $id || isset( $seen[ $id ] ) ) {
				continue;
			}

			$seen[ $id ] = true;
			$lines[]     = '    ' . __( 'What it did:', 'bettershield' ) . ' ' . Links::agent_timeline( $id );
		}

		if ( array() !== $lines ) {
			$lines[] = '    ' . __( 'Don’t recognize this AI assistant? Disconnect it in BetterShield › Agents › Connect:', 'bettershield' ) . ' ' . Links::agent_connections();
		}

		return $lines;
	}

	/**
	 * The subjects of the queued events of one kind, a line each, the first
	 * few of them.
	 *
	 * @param array<int, array<string, mixed>> $events
	 * @return string[]
	 */
	private static function subjects_of( array $events, string $type ): array {
		$named = array();

		foreach ( $events as $event ) {
			$subject = (string) ( $event['subject'] ?? '' );

			if ( $type === (string) $event['type'] && '' !== $subject && ! in_array( $subject, $named, true ) ) {
				$named[] = $subject;
			}
		}

		return array_map( static fn( string $subject ): string => '    ' . $subject, array_slice( $named, 0, 5 ) );
	}

	/**
	 * The open incidents the queued events opened or joined.
	 *
	 * Asked when the email is written: correlation runs a few seconds after
	 * the events are recorded, so the first email about a burst may come
	 * before it, and the incident's opening then sends one of its own.
	 *
	 * @param array<int, array<string, mixed>> $events
	 * @return array<int, array{id: int, opened_at: string, evidence: int}>
	 */
	private static function incidents_of( array $events ): array {
		$opened = array();
		$others = array();

		foreach ( $events as $event ) {
			if ( ! empty( $event['summary'] ) ) {
				continue;
			}

			if ( 'incident_opened' === (string) $event['type'] ) {
				$opened[] = (int) ( $event['id'] ?? 0 );
			} else {
				$others[] = array(
					'type' => (string) $event['type'],
					'at'   => (string) ( $event['at'] ?? '' ),
					'id'   => isset( $event['id'] ) ? (string) $event['id'] : null,
				);
			}
		}

		$found = array_column( \BetterShield\Incidents\Repository::holding( $others ), 'id' );

		// One opened earlier in this request by another event is not named.
		return \BetterShield\Incidents\Repository::described( array_merge( $opened, $found, \BetterShield\Incidents\Repository::opened_by( $others ) ) );
	}

	/**
	 * A stored UTC moment as an alert says it: in the site's own date and time
	 * format and time zone, with the zone named. The weekly summary reads in
	 * the site's zone and the instant alert gave UTC, so one event was told
	 * at two clock times (#2085).
	 *
	 * @param string $utc A stored moment, in UTC.
	 */
	private static function site_moment( string $utc ): string {
		// An entry queued before events carried their moment has none, and
		// strtotime() reads " UTC" alone as now: say nothing rather than the
		// moment of sending.
		if ( '' === trim( $utc ) ) {
			return '';
		}

		$moment = strtotime( substr( $utc, 0, 19 ) . ' UTC' );

		if ( false === $moment ) {
			return substr( $utc, 0, 19 ) . ' UTC';
		}

		return \BetterShield\Support\Time::said( $moment );
	}

	/**
	 * Why an instant email came, for what is in it: a maintenance window that
	 * started was told it came because a window ended (#2486).
	 *
	 * @param array<int, array<string, mixed>> $events
	 */
	private static function why_right_away( array $events ): string {
		$kinds = array();

		foreach ( $events as $event ) {
			if ( ! empty( $event['summary'] ) ) {
				$kinds['ended'] = true;
			} elseif ( 'maintenance_window_started' === (string) ( $event['type'] ?? '' ) ) {
				$kinds['started'] = true;
			} elseif ( 'maintenance_window_booked' === (string) ( $event['type'] ?? '' ) ) {
				$kinds['booked'] = true;
			} else {
				$kinds['rated'] = true;
			}
		}

		if ( array( 'started' ) === array_keys( $kinds ) ) {
			return __( 'You got this email right away because planned maintenance started on your site. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
		}

		if ( array( 'booked' ) === array_keys( $kinds ) ) {
			return __( 'You got this email right away because planned maintenance was booked on your site. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
		}

		if ( array( 'ended' ) === array_keys( $kinds ) ) {
			return __( 'You got this email right away because a planned maintenance window ended. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
		}

		if ( array( 'rated' ) === array_keys( $kinds ) ) {
			return __( 'You got this email right away because these events are rated high or critical. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
		}

		return __( 'You got this email right away because these events are rated high or critical, or planned maintenance started or ended. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
	}

	/**
	 * What happened, why it matters, one next action, then the link.
	 *
	 * @param array{total: int, events: array<int, array<string, mixed>>} $pending
	 */
	private function instant_body( array $pending ): string {
		$lines = array();

		// The first thing read says whether to worry.
		$listed = array_values( array_filter( $pending['events'], static fn( array $event ): bool => empty( $event['summary'] ) ) );

		/*
		 * The incident these events opened or joined, read first: an incident
		 * this email opens is named and timed as the Incidents screen names
		 * it, its title and its opened time, not the event that started it
		 * and the moment that event was logged (#2616).
		 */
		$incidents = self::incidents_of( $pending['events'] );

		if ( array() !== array_filter( $listed, array( self::class, 'needs_action' ) ) ) {
			$lines[] = __( 'Action needed. Check this now, and don’t wait for the weekly summary.', 'bettershield' );
			$lines[] = '';
		} elseif ( array() === $incidents && array() !== $listed && array() === array_filter( $listed, static fn( array $event ): bool => ! self::a_person_did( $event ) ) ) {
			// Not beside an incident: being grouped with related records is
			// what makes it worth a look, whoever did it.

			$lines[] = __( 'If you or your team expected this, you don’t need to do anything.', 'bettershield' );
			$lines[] = '';
		}

		$lines[] = __( 'Recorded on your site:', 'bettershield' );
		$lines[] = '';

		// Repeats of one kind are one line with their count, as the digest
		// does, so every kind gets a line of its own.
		$counts = array();

		foreach ( $pending['events'] as $event ) {
			if ( empty( $event['summary'] ) ) {
				$counts[ (string) $event['type'] ] = ( $counts[ (string) $event['type'] ] ?? 0 ) + 1;
			}
		}

		$said = array();

		$known     = array_column( $incidents, null, 'id' );
		$opened    = array();

		foreach ( $pending['events'] as $event ) {
			if ( ! empty( $event['summary'] ) ) {
				$lines[] = Maintenance::summary_text( $event['summary'] );
				continue;
			}

			$type = (string) $event['type'];

			if ( 'incident_opened' === $type && isset( $known[ (int) ( $event['id'] ?? 0 ) ] ) ) {
				$incident         = $known[ (int) $event['id'] ];
				$opened[]         = $incident['id'];
				$event['at']      = $incident['opened_at'];
				$event['subject'] = '' !== $incident['title']
					/* translators: 1: an incident's own number, 2: its title, e.g. "Related changes worth a look". */
					? sprintf( __( 'Incident #%1$d, %2$s', 'bettershield' ), $incident['id'], $incident['title'] )
					: (string) ( $event['subject'] ?? '' );
			}

			if ( isset( $said[ $type ] ) ) {
				continue;
			}

			$said[ $type ] = true;
			$subject       = (string) ( $event['subject'] ?? '' );
			$actor         = (string) ( $event['actor'] ?? '' );

			// Who did it, beside what it was about. Not for a finding: the
			// audit opened it, and "by admin" read as if a person caused the
			// problem (#2831).
			if ( '' !== $actor && 'finding_opened' !== $type ) {
				$who = empty( $event['via_assistant'] )
					? $actor
					/* translators: %s: the account an assistant's credential runs as. */
					: sprintf( __( 'an AI assistant using the %s account', 'bettershield' ), $actor );

				$subject = '' === $subject
					/* translators: %s: who did it. */
					? sprintf( __( 'by %s', 'bettershield' ), $who )
					/* translators: 1: what it was about, 2: who did it. */
					: sprintf( __( '%1$s, by %2$s', 'bettershield' ), $subject, $who );
			}

			if ( $counts[ $type ] > 1 ) {
				$lines[] = sprintf(
					/* translators: 1: what happened, 2: how many times, 3: when it first did, in the site's date and time format, with its time zone. */
					__( '  %1$s, %2$d times, first at %3$s', 'bettershield' ),
					Types::label( $type ),
					$counts[ $type ],
					self::site_moment( (string) $event['at'] )
				);

				// Each one it was about, so the reader knows which (#1829).
				$lines = array_merge( $lines, self::subjects_of( $pending['events'], $type ) );

				// Each connection used from somewhere new: where to see what
				// it did, once per connection, and where to take it away (#1880).
				if ( 'agent_new_network' === $type ) {
					$lines = array_merge( $lines, self::connection_links( $pending['events'] ) );
				}
			} else {
				$lines[] = '' !== $subject
					? sprintf(
						/* translators: 1: what happened, 2: what it was about (an account, a protection, a file, a finding), 3: when, in the site's date and time format, with its time zone. */
						__( '  %1$s: %2$s — %3$s', 'bettershield' ),
						Types::label( $type ),
						$subject,
						self::site_moment( (string) $event['at'] )
					)
					: sprintf(
						/* translators: 1: what happened, 2: when, in the site's date and time format, with its time zone. */
						__( '  %1$s — %2$s', 'bettershield' ),
						Types::label( $type ),
						self::site_moment( (string) $event['at'] )
					);

				// A finding links to that finding, not to the whole log.
				if ( '' !== (string) ( $event['finding'] ?? '' ) ) {
					$lines[] = '    ' . Links::finding( (string) $event['finding'] );
				}

				// A connection used from somewhere new: where to see what it
				// did, and where to take it away (#1880).
				if ( 'agent_new_network' === $type ) {
					$lines = array_merge( $lines, self::connection_links( array( $event ) ) );
				}

				// A credential issued is not an assistant connected: nothing
				// has used it until one is given it (#2073).
				// Asked when the email is written, which a held or retried
				// alert does later: by then an assistant may have used it.
				if ( in_array( $type, array( 'mcp_connected', 'mcp_rotated' ), true ) && \BetterShield\Mcp\Pairing::is_connected() && 0 === \BetterShield\Mcp\Pairing::state()['last_used'] ) {
					$lines[] = '    ' . __( 'No AI assistant has used this connection key yet.', 'bettershield' );
				}
			}
		}

		if ( $pending['total'] > count( $pending['events'] ) ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: 1: number of events counted above, 2: true total. */
				__( '  Showing %1$d of %2$d events. See them all in BetterShield › Activity.', 'bettershield' ),
				count( $pending['events'] ),
				$pending['total']
			);
		}

		/*
		 * The incident these events opened or joined, in one line each with
		 * the way to it: the emails about an incident's own events never
		 * named it, and each sent the reader to the unfiltered log (#2246).
		 */
		if ( array() !== $incidents ) {
			$lines[] = '';

			foreach ( $incidents as $incident ) {
				// One this email opened is named above; it is not part of itself.
				$lines[] = in_array( $incident['id'], $opened, true )
					? sprintf(
						/* translators: 1: an incident's number, 2: how many related records it groups. */
						_n( 'Incident #%1$d now groups %2$d related record.', 'Incident #%1$d now groups %2$d related records.', $incident['evidence'], 'bettershield' ),
						$incident['id'],
						$incident['evidence']
					)
					: sprintf(
						/* translators: 1: an incident's number, 2: its title, e.g. "Related changes worth a look", 3: when it opened, in the site's date and time format, 4: how many related records it groups. */
						_n( 'Part of Incident #%1$d, %2$s (opened %3$s), which now groups %4$d related record.', 'Part of Incident #%1$d, %2$s (opened %3$s), which now groups %4$d related records.', $incident['evidence'], 'bettershield' ),
						$incident['id'],
						$incident['title'],
						self::site_moment( $incident['opened_at'] ),
						$incident['evidence']
					);
			}
		}

		$lines[] = '';
		// A whole sentence: it read as a fragment out of context (#2073).
		$lines[] = Settings::instance()->settings()['instant_critical']
			? self::why_right_away( $pending['events'] )
			: __( 'You got this even with instant alerts off, because this event always emails. Only muting alerts stops it. Change this in BetterShield › Settings › Email Alerts.', 'bettershield' );
		$lines[] = '';
		// Only findings: each has its own link above, and none was done by
		// somebody, so asking whether it was "you" made no sense of it.
		// A maintenance summary lists no finding, so an email of summaries
		// alone is not one of findings: it said "open each finding above"
		// with none above (#2611).
		$listed        = array_filter( $pending['events'], static fn( array $event ): bool => empty( $event['summary'] ) );
		$findings_only = array() !== $listed && array() === array_filter(
			$listed,
			static fn( array $event ): bool => '' === (string) ( $event['finding'] ?? '' )
		);

		if ( $findings_only ) {
			$lines[] = __( 'Next: open each finding above to see how to fix it.', 'bettershield' );
		} elseif ( array() !== $incidents ) {
			$lines[] = __( 'Next: open the incident to see what happened, in order, and the steps we recommend.', 'bettershield' );
			$lines[] = Links::incidents();
		} else {
			$lines[] = __( 'Next: open BetterShield › Activity and look for anything you or your team didn’t do.', 'bettershield' );
			$lines[] = Links::activity();
		}

		return implode( "\n", $lines ) . "\n";
	}
}
