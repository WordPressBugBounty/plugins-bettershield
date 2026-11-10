<?php
/**
 * Scheduled task runner.
 *
 * wp-cron only fires when the site gets traffic, so on low-traffic sites
 * scheduled jobs silently stop running. Every task records its last run;
 * when a task is overdue by more than twice its interval, it runs inline
 * on the next admin page load. Admin visits are the one traffic source a
 * managed site reliably has.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Cron;

use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Runner {

	private static ?Runner $instance = null;

	/**
	 * The shortest cycle the schedule is held to when it is asked how late it
	 * is: a one-off event's, which has none of its own, and the floor for a
	 * hook that runs more often than hourly.
	 */
	private const SINGLE_EVENT_INTERVAL = HOUR_IN_SECONDS;

	/** How each task's last run ended: when, and finished or failed. */
	public const DONE_PREFIX = 'bettershield_task_done_';

	/** The one early run somebody asked for and that has not finished yet. */
	public const REQUEST_OPTION = 'bettershield_task_requested';

	/**
	 * How long an early run that has not started may hold the next one back.
	 * Past it, the schedule that was to run it is not running, and asking
	 * again is the honest thing to let somebody do.
	 */
	private const REQUEST_WINDOW = 30 * MINUTE_IN_SECONDS;

	/** @var array<string, array{recurrence: string, callback: callable, inline_fallback: bool}> */
	private array $tasks = array();

	/** Whether this request has already spawned the schedule's run. */
	private bool $spawned = false;

	/**
	 * How deep inside a task's callback this request currently is.
	 *
	 * A depth rather than a flag, because one task's callback firing another
	 * task's hook would otherwise clear the mark on the way out of the inner
	 * one and leave the rest of the outer task looking like ordinary traffic.
	 */
	private static int $depth = 0;

	public static function instance(): Runner {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		add_action( 'init', array( $this, 'ensure_scheduled' ) );
		add_action( 'admin_init', array( $this, 'run_overdue_fallback' ), 20 );
		add_action( 'rest_api_init', array( $this, 'rescue_from_request' ) );
	}

	/**
	 * The rescue, asked from an authenticated request that is not a page
	 * load: the dashboard's own REST calls, and every call an assistant
	 * makes once the endpoint has become the account that granted its
	 * credential (`Mcp\Server::become()` asks from there, because that
	 * account is set after `rest_api_init` has fired).
	 *
	 * Gated on the capability alone. A nonce was asked for at first, to tell
	 * the owner's request from a cross-site one carrying the same cookie —
	 * but a nonce is a cookie session's artifact, and an assistant
	 * authenticating with a token can never present one, so the rescue never
	 * ran for the calls it was written for. Spawning the schedule changes
	 * nothing on the caller's behalf: it asks the site to run work it already
	 * owed, bounded by the five-minute claim and core's own lock. A cross-site
	 * request that makes an administrator's site catch up on its own overdue
	 * work is not an attack worth that cost.
	 */
	public function rescue_from_request(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$this->rescue_schedule();
	}

	/**
	 * Register a recurring task.
	 *
	 * `$inline_fallback` says whether an ordinary admin page load may be asked
	 * to run this one when the schedule has stopped. Work whose length nothing
	 * on this side can bound — a TLS handshake, a set of requests to the site's
	 * own web server, a walk of a directory tree — says no, and then runs only
	 * from wp-cron and from the loopback, where nobody is waiting for a page.
	 * The fallback is a rescue for a dead scheduler, not a warrant to spend a
	 * visit on anything at all.
	 *
	 * @param string   $hook            Unique cron hook name.
	 * @param string   $recurrence      A registered cron recurrence, e.g. 'daily'.
	 * @param callable $callback        Executed on each run; must be self-limiting.
	 * @param bool     $inline_fallback Whether an admin page load may run it inline.
	 */
	public function register_task( string $hook, string $recurrence, callable $callback, bool $inline_fallback = true ): void {
		$this->tasks[ $hook ] = array(
			'recurrence'      => $recurrence,
			'callback'        => $callback,
			'inline_fallback' => $inline_fallback,
		);

		add_action(
			$hook,
			// A requested run arrives with an argument (request_run()), which
			// the task reads to tell it from the schedule's own run.
			// do_action() with nothing to pass hands over an empty string.
			function ( ...$args ) use ( $hook ): void {
				$this->run_task( $hook, ...( array( '' ) === $args ? array() : $args ) );
			}
		);
	}

	/**
	 * Whether a task may run inside the overdue fallback on a web request.
	 *
	 * For reporting and for the guard that pins which tasks were kept off
	 * that path; the fallback itself reads the same flag.
	 */
	public function runs_inline( string $hook ): bool {
		return isset( $this->tasks[ $hook ] ) && (bool) $this->tasks[ $hook ]['inline_fallback'];
	}

	/**
	 * Schedule any registered task wp-cron does not know about yet.
	 */
	public function ensure_scheduled(): void {
		foreach ( $this->tasks as $hook => $task ) {
			if ( false === wp_next_scheduled( $hook ) ) {
				wp_schedule_event( time() + MINUTE_IN_SECONDS, $task['recurrence'], $hook );
			}
		}
	}

	/**
	 * Remove our events from wp-cron. Called on deactivation.
	 */
	public function unschedule_all(): void {
		wp_clear_scheduled_hook( 'bettershield_inventory_recheck' );
		foreach ( array_keys( $this->tasks ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Whether scheduled work is running right now.
	 *
	 * True from the moment a task's callback starts until it returns, on every
	 * path that reaches one — the cron hook, the loopback that stands in for a
	 * dead scheduler, and the overdue fallback below. None of those carries a
	 * signed-in user, so without this the rows a task writes are attributed to
	 * a signed-out visitor and the log names one for work the site did itself.
	 */
	public static function in_task(): bool {
		return self::$depth > 0;
	}

	/**
	 * Execute a task now and record the run.
	 *
	 * @param mixed ...$args What the event carried, handed to the task.
	 */
	public function run_task( string $hook, ...$args ): void {
		if ( ! isset( $this->tasks[ $hook ] ) ) {
			return;
		}

		// How long since the last run is measurable only here, before it is
		// overwritten; an hourly task's gap is kept against its own record.
		if ( 'hourly' === $this->tasks[ $hook ]['recurrence'] ) {
			\BetterShield\Events\Unusual::task_ran( $hook, (int) get_option( 'bettershield_last_run_' . $hook, 0 ), time() );
		}

		$started = time();

		update_option( 'bettershield_last_run_' . $hook, $started, false );

		++self::$depth;

		$outcome = 'failed';

		/*
		 * A task that throws must still hand the request back as an ordinary
		 * one, or everything written after it is credited to the scheduler.
		 *
		 * And the throw stops here, recorded as a failed run. The overdue
		 * fallback runs a task inside an administrator's own page load, so a
		 * throw that went on took that page down, and the next one when the
		 * same task was picked again a minute later; on the cron request it
		 * stopped every other event due in the same run.
		 */
		try {
			( $this->tasks[ $hook ]['callback'] )( ...$args );
			$outcome = 'finished';
		} catch ( \Throwable $e ) {
			unset( $e );
		} finally {
			--self::$depth;
			$this->finished( $hook, $outcome, $started );
		}
	}

	/**
	 * Write down how a run ended, and say so.
	 *
	 * The start was all that was ever kept, so a task that threw every night
	 * read exactly like one that worked. The end is kept beside it, and an
	 * early run somebody asked for gets its receipt: the row that says it
	 * finished, or did not, and who asked.
	 */
	private function finished( string $hook, string $outcome, int $started ): void {
		$seconds = max( 0, time() - $started );

		update_option(
			self::DONE_PREFIX . $hook,
			array(
				'at'      => time(),
				'outcome' => $outcome,
				'seconds' => $seconds,
			),
			false
		);

		$request = self::pending_request();

		// A run that was already under way when the ask came is not the run
		// that was asked for: it would hand out the receipt early and let a
		// second ask stack behind the one still queued.
		if ( null !== $request && $hook === $request['hook'] && $started >= $request['at'] ) {
			delete_option( self::REQUEST_OPTION );

			$context = array(
				'task'         => $hook,
				'outcome'      => $outcome,
				'seconds'      => $seconds,
				'requested_by' => $request['by'],
			);

			if ( 'finished' === $outcome ) {
				\BetterShield\Events\Writer::instance()->record( 'task_run_finished', \BetterShield\Events\Writer::SEVERITY_INFO, array( 'object_type' => 'task', 'object_id' => $hook, 'context' => $context ) );
			} else {
				\BetterShield\Events\Writer::instance()->record( 'task_run_failed', \BetterShield\Events\Writer::SEVERITY_MEDIUM, array( 'object_type' => 'task', 'object_id' => $hook, 'context' => $context ) );
			}
		}

		/**
		 * Fires when a scheduled task's run has ended, however it was started.
		 *
		 * @param string $hook    The task.
		 * @param string $outcome `finished`, or `failed` when it threw.
		 * @param int    $started When it started, as a Unix time.
		 * @param int    $seconds How long it ran.
		 */
		do_action( 'bettershield_task_finished', $hook, $outcome, $started, $seconds );
	}

	/**
	 * Every task this runner knows, as a schedule screen reads it.
	 *
	 * Named in the reader's words, with when it last started, how its last run
	 * ended and when it is next due. A task with no name of its own is listed
	 * under its hook rather than left out: a list of scheduled work that is
	 * missing some is worse than one with a name meant for code in it.
	 *
	 * @return array<string, array{hook: string, label: string, recurrence: string, interval: ?int, inline_fallback: bool, last_started: int, last_ended: int, last_outcome: string, next: int}>
	 */
	public function tasks(): array {
		$labels = Labels::all();
		$out    = array();

		foreach ( $this->tasks as $hook => $task ) {
			$done = get_option( self::DONE_PREFIX . $hook, array() );
			$done = is_array( $done ) ? $done : array();
			$next = wp_next_scheduled( $hook );

			$out[ $hook ] = array(
				'hook'            => (string) $hook,
				'label'           => $labels[ $hook ] ?? (string) $hook,
				'recurrence'      => (string) $task['recurrence'],
				'interval'        => $this->interval_seconds( (string) $task['recurrence'] ),
				'inline_fallback' => (bool) $task['inline_fallback'],
				'last_started'    => (int) get_option( 'bettershield_last_run_' . $hook, 0 ),
				'last_ended'      => (int) ( $done['at'] ?? 0 ),
				'last_outcome'    => (string) ( $done['outcome'] ?? '' ),
				'next'            => false === $next ? 0 : (int) $next,
			);
		}

		return $out;
	}

	/**
	 * Ask for one task to run early, in the background, and say who asked.
	 *
	 * Never in this request: the work some of these do — a file scan, a TLS
	 * handshake — has no length a person waiting for a screen can rely on. A
	 * one-off event is put on the schedule and the schedule is asked to run,
	 * the way the rescue above asks it; the task's own record and the receipt
	 * say when it actually did.
	 *
	 * One at a time across the site, so a run nobody has seen finish cannot
	 * be stacked behind another. Which tasks an early run means something for
	 * is the caller's to decide.
	 *
	 * @return true|\WP_Error
	 */
	public function request_run( string $hook, int $user_id ) {
		if ( ! isset( $this->tasks[ $hook ] ) ) {
			return new \WP_Error( 'bettershield_task_unknown', __( 'There is no such scheduled task on this site.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$pending = self::pending_request();

		if ( null !== $pending ) {
			return new \WP_Error(
				'bettershield_task_pending',
				__( 'An early run is still going. Try again once it finishes.', 'bettershield' ),
				array( 'status' => 409 )
			);
		}

		/*
		 * An argument of its own, so core does not take this for the recurring
		 * event it may be due beside and refuse it as a duplicate. A list, not
		 * keys: core hands the arguments to the hook spread, and on PHP 8 a
		 * keyed one arrives as a named parameter the callback does not have —
		 * a fatal error inside wp-cron.php, with the event already taken off
		 * the schedule.
		 */
		$scheduled = wp_schedule_single_event( time(), $hook, array( time() ), true );

		if ( is_wp_error( $scheduled ) || false === $scheduled ) {
			return new \WP_Error( 'bettershield_task_not_queued', __( 'The run could not be scheduled. Try again in a moment.', 'bettershield' ), array( 'status' => 500 ) );
		}

		update_option(
			self::REQUEST_OPTION,
			array(
				'hook' => $hook,
				'by'   => $user_id,
				'at'   => time(),
			),
			false
		);

		\BetterShield\Events\Writer::instance()->record(
			'task_run_requested',
			\BetterShield\Events\Writer::SEVERITY_LOW,
			array(
				'object_type' => 'task',
				'object_id'   => $hook,
				'context'     => array( 'task' => $hook ),
			)
		);

		if ( function_exists( 'spawn_cron' ) && ! ( defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ) ) {
			spawn_cron();
		}

		return true;
	}

	/**
	 * The early run asked for and not finished, while it may still hold the
	 * next one back.
	 *
	 * @return array{hook: string, by: int, at: int}|null
	 */
	public static function pending_request(): ?array {
		$stored = get_option( self::REQUEST_OPTION, array() );

		if ( ! is_array( $stored ) || '' === (string) ( $stored['hook'] ?? '' ) ) {
			return null;
		}

		$at = (int) ( $stored['at'] ?? 0 );

		if ( time() - $at > self::REQUEST_WINDOW ) {
			return null;
		}

		return array(
			'hook' => (string) $stored['hook'],
			'by'   => (int) ( $stored['by'] ?? 0 ),
			'at'   => $at,
		);
	}

	/**
	 * Inline fallback for missed schedules, hooked on admin_init.
	 *
	 * A task with no recorded run yet only starts its clock — running
	 * work inline on the first-ever admin visit would be surprising.
	 */
	public function run_overdue_fallback(): void {
		/*
		 * `admin_init` fires on more than an administrator looking at a page.
		 * admin-ajax.php reaches it with no session at all, and so does
		 * admin-post.php — core runs the action there *before* its own
		 * signed-in check, so a plain unauthenticated POST used to run this
		 * plugin's database work inline in a stranger's request. Guarding only
		 * the ajax sibling covered half of it.
		 *
		 * The rule the comment always described, stated once: this has to be
		 * the owner's own request. Signed in was not that test — a subscriber
		 * reaching their own profile screen passed it, and paid for a file scan,
		 * a TLS handshake and a set of requests to the site's own web server
		 * inside their page load.
		 *
		 * The core capability rather than this plugin's own, deliberately: the
		 * plugin's capabilities are removable by design, and a role-editor tweak
		 * must not be able to switch this off silently on exactly the site whose
		 * scheduler is already dead.
		 *
		 * And two admin requests arriving together must not both run the work —
		 * which needs a claim the database arbitrates, because reading a
		 * transient and then writing it lets both requests through and is what
		 * let a digest send twice.
		 */
		if ( wp_doing_ajax() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Deliberately not released at the end: the minute is a floor on how
		// often the fallback may run at all, not the length of one run.
		if ( ! Claim::claim( 'fallback_run', MINUTE_IN_SECONDS ) ) {
			return;
		}

		// A run just asked for covers every task, this request's included,
		// and two copies of the same task at once is what it must not start.
		if ( $this->rescue_schedule() ) {
			return;
		}

		/*
		 * One task, and the most overdue one.
		 *
		 * This walked every task and ran each that was due, in registration
		 * order, on the request that happened to trigger the fallback. On a
		 * site whose scheduler has been down — which is the only site this
		 * exists for — that is every task at once, with somebody waiting for
		 * an admin page while a file scan and several outbound requests run.
		 * The minute-long claim above paces the backlog instead: a handful of
		 * ordinary admin page views clears it, and no single one of them pays
		 * for all of it.
		 *
		 * Most overdue rather than first registered, because walking the same
		 * order every time lets a task near the front starve the rest.
		 *
		 * And only among the tasks that may run here at all. Some of this work
		 * opens a socket or asks the site's own web server a list of questions,
		 * and neither has a length a page view can rely on; those keep their
		 * place in the schedule and are simply never the answer to "what shall
		 * this request pay for".
		 */
		$worst    = null;
		$overdue  = 0;

		foreach ( $this->tasks as $hook => $task ) {
			if ( ! ( $task['inline_fallback'] ?? true ) ) {
				continue;
			}

			$interval = $this->interval_seconds( $task['recurrence'] );

			if ( null === $interval ) {
				continue;
			}

			$last = (int) get_option( 'bettershield_last_run_' . $hook, 0 );

			if ( 0 === $last ) {
				update_option( 'bettershield_last_run_' . $hook, time(), false );
				continue;
			}

			$late = time() - $last - ( 2 * $interval );

			if ( $late > 0 && ( null === $worst || $late > $overdue ) ) {
				$worst   = (string) $hook;
				$overdue = $late;
			}
		}

		if ( null !== $worst ) {
			$this->run_task( $worst );
		}
	}

	/**
	 * How far behind the schedule is, read off this plugin's own hooks.
	 *
	 * WordPress moves a hook's appointment only when it runs the hook, so an
	 * appointment that stays in the past is the one fact that says nothing is
	 * driving the schedule: not a visitor's page load, not a system cron, not
	 * anything. Measured on this plugin's hooks because they are the ones it
	 * knows to be answered and knows the interval of; the number is the
	 * seconds the most overdue of them is past its appointment, and 0 when
	 * none is.
	 *
	 * Late is measured against each hook's own recurrence, which the schedule
	 * carries on the entry: an hourly hook has missed a cycle an hour past
	 * its appointment, a daily one a day past. One threshold for both fit
	 * neither — set for the hourly ones it called a daily hook stopped over
	 * lunch, set for the daily ones it let the hourly ones miss a cycle and
	 * report healthy, and two hours did the second on a host whose cron had
	 * died. `overdue` counts the hooks that have missed a whole cycle.
	 *
	 * Read off the stored option rather than through core's reader, which
	 * upgrades and rewrites an old-shaped schedule on the way past: a report
	 * must not change what it reports on.
	 *
	 * @return array{behind_seconds: int, overdue: int, worst: ?string}
	 */
	public static function schedule_lag(): array {
		$stored   = get_option( 'cron' );
		$now      = time();
		$due      = array();
		$interval = array();

		if ( is_array( $stored ) ) {
			foreach ( $stored as $timestamp => $hooks ) {
				if ( ! is_int( $timestamp ) || ! is_array( $hooks ) ) {
					continue;
				}

				foreach ( $hooks as $hook => $instances ) {
					$hook = (string) $hook;

					if ( 0 !== strpos( $hook, 'bettershield_' ) ) {
						continue;
					}

					// The soonest appointment is the one that says whether
					// the hook is being run at all, and its own interval is
					// the cycle it can miss. A one-off event has none and is
					// held to an hour. So is a hook that runs more often than
					// that, such as the Hub link's every five minutes: on a
					// site whose schedule runs when somebody visits, a quiet
					// quarter of an hour is not a stopped scheduler.
					if ( ! isset( $due[ $hook ] ) || $timestamp < $due[ $hook ] ) {
						$due[ $hook ]      = $timestamp;
						$first             = is_array( $instances ) ? reset( $instances ) : null;
						$interval[ $hook ] = is_array( $first ) && ! empty( $first['interval'] )
							? max( self::SINGLE_EVENT_INTERVAL, (int) $first['interval'] )
							: self::SINGLE_EVENT_INTERVAL;
					}
				}
			}
		}

		$behind  = 0;
		$overdue = 0;
		$worst   = null;

		foreach ( $due as $hook => $at ) {
			$late = $now - $at;

			if ( $late > $interval[ $hook ] ) {
				++$overdue;
			}

			if ( $late > $behind ) {
				$behind = $late;
				$worst  = $hook;
			}
		}

		return array(
			'behind_seconds' => $behind,
			'overdue'        => $overdue,
			'worst'          => $worst,
		);
	}

	/**
	 * Ask the site to run its own schedule when nothing else is.
	 *
	 * WordPress runs scheduled work by spawning a non-blocking request to
	 * wp-cron.php from a visitor's page load, and a host that turns that off
	 * with `DISABLE_WP_CRON` is expected to drive the schedule with a system
	 * cron instead. When one of this plugin's own hooks has missed a whole
	 * cycle neither is happening, and the inline fallback covers only the
	 * tasks a page view may pay for. So the owner's request does what a
	 * visitor's would have: spawns the run and gets on with the page.
	 *
	 * Core's own spawner, because it carries the lock, the request filter
	 * hosts customize and the non-blocking timeout — asked directly, because
	 * the check that honors `DISABLE_WP_CRON` sits in front of it rather than
	 * inside it. That constant says "something else runs the schedule", and
	 * a schedule this far behind is the proof that nothing does. The
	 * alternate mode is left alone: it redirects the request it is called
	 * from, which is not a thing to do to an admin page.
	 *
	 * Once every few minutes at most, so a dashboard visit asks once rather
	 * than once per page, and the spawner itself declines while a run is
	 * under way.
	 *
	 * @return bool Whether a run was asked for.
	 */
	private function rescue_schedule(): bool {
		return 'asked' === $this->try_rescue();
	}

	/**
	 * The same rescue, saying what happened: `asked` where a run was spawned,
	 * `on_time` where nothing has missed a cycle, `paced` inside the five
	 * minutes since the last ask, `unsupported` where core's spawner cannot
	 * be used here, and `refused` where it declined (a run under way). For
	 * the stalled schedule's Try now (#2209), which says which it was.
	 */
	public function try_rescue(): string {
		if ( ! function_exists( 'spawn_cron' ) || ( defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ) ) {
			return 'unsupported';
		}

		// A hook that has missed a whole cycle of its own is the trigger: an
		// hourly one an hour late, not a daily one over lunch.
		if ( 0 === self::schedule_lag()['overdue'] ) {
			return 'on_time';
		}

		// Every request of somebody who may manage the site asks once, as the
		// REST API starts; a Try now arriving as that request is the one
		// that asked, not one held back.
		if ( ! Claim::claim( 'scheduler_spawn', 5 * MINUTE_IN_SECONDS ) ) {
			return $this->spawned ? 'asked' : 'paced';
		}

		$this->spawned = (bool) spawn_cron();

		return $this->spawned ? 'asked' : 'refused';
	}

	private function interval_seconds( string $recurrence ): ?int {
		$schedules = wp_get_schedules();

		return isset( $schedules[ $recurrence ]['interval'] )
			? (int) $schedules[ $recurrence ]['interval']
			: null;
	}
}
