<?php
/**
 * Records every Abilities API invocation on this site — whoever registered
 * the ability, whichever door the call came through, and whatever the answer
 * was.
 *
 * Two constraints shape this file, both measured on the shipped platform
 * rather than assumed.
 *
 * FIRST: `wp_ability_invoked` is not the spine of the lifecycle, and capture
 * must not be built on it. Core's REST run controller normalizes, validates
 * and permission-checks inside the route's own permission callback, reaching
 * execute() only if all three pass — and execute() returns early on a failed
 * callback or failed output validation, before `wp_after_execute_ability`.
 * Of the outcomes observable here, most are invisible to the invoked action
 * alone, and over REST an entire class of rejection never enters execute()
 * at all. Built the obvious way this would silently under-report refusals,
 * which are the events with the most security value. So capture hangs off
 * every lifecycle filter, and each one is commented with what only it can
 * see.
 *
 * SECOND: core calls several of those steps repeatedly while refusing a
 * single request — six times for one permission refusal. Every rejection
 * recorded from a step that ran outside execute() is therefore de-duplicated
 * per request. Without that, one refusal becomes six rows and the number the
 * whole feature turns on is wrong.
 *
 * Attribution is a naming convention, not a fact. `WP_Ability` exposes no
 * accessor for the callback that would name the plugin behind an ability, so
 * `registering_plugin` holds the ability name's namespace prefix and nothing
 * stronger. Nothing in this plugin may claim more than that.
 *
 * Removal is detected, never prevented. Another plugin can unhook this with
 * one line; when that happens the absence is noticed and recorded. That is
 * the honest claim — we notice when someone silences the record — and no
 * copy anywhere may say tamper-proof.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Agents;

use BetterShield\Events\Writer;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Capture {

	public const OPTION = 'bettershield_agent_capture';

	/**
	 * How many requests carrying a refusal, inside one window, stop being
	 * routine and become something worth interrupting somebody for.
	 *
	 * One refusal is a Tuesday. An agent asking for something it may not have,
	 * once, is the permission system working — and an instant alert on every
	 * one of those would make the most valuable signal this product has into
	 * its loudest noise, which is the failure the calm-copy rule exists to
	 * prevent. Repetition over time is the part that is not routine, and it is
	 * the shape the sign-in lockout already uses: the individual failure stays
	 * quiet and droppable, and the pattern raises its own louder event.
	 */
	public const REPEAT_THRESHOLD = 10;

	/** The window the threshold is counted in, in minutes. */
	public const REPEAT_WINDOW_MINUTES = 60;

	/**
	 * The WordPress version that ships the ability lifecycle filters this
	 * class listens to. Below it the hooks never fire and capture is inert.
	 */
	public const REQUIRES_WP = '7.1';

	/**
	 * Every outcome this capture layer can write, as measured against the
	 * shipped platform. `unknown` is the honest answer for a record whose
	 * lifecycle never finished — it is never promoted to `completed`, and a
	 * wrongly-labeled outcome is worse than an absent one.
	 */
	public const OUTCOMES = array(
		'completed',
		'permission_denied',
		'input_invalid',
		'input_not_normalizable',
		'output_invalid',
		'short_circuited',
		'failed',
		'unknown',
	);

	private static ?Capture $instance = null;

	/**
	 * Open invocations, a stack per ability name so that nested or repeated
	 * calls within one request each close against their own record. A single
	 * variable would cross-wire them; abilities can invoke abilities.
	 *
	 * @var array<string, array<int, array<string, mixed>>>
	 */
	private array $open = array();

	/**
	 * Rejections already recorded this request from a step that ran outside
	 * execute(), keyed ability|user|outcome. See the note at the top of the
	 * file: core repeats these steps while refusing once.
	 *
	 * @var array<string, true>
	 */
	private array $standalone = array();

	/**
	 * Refusals already announced to the activity log this request, keyed the
	 * same way. Every refusal is recorded in the invocation table; the log
	 * gets one line per distinct refusal per request, because the log is
	 * what alerting reads and an agent in a loop must not become a mailstorm.
	 *
	 * @var array<string, true>
	 */
	private array $announced = array();

	private bool $registered = false;

	/**
	 * How many deliberate probes are in flight.
	 *
	 * This plugin asks other plugins' permission callbacks what they would
	 * say to a low-privileged caller — that is the whole of the "who can call
	 * it" column on the agent surface. Those questions fire the same filter a
	 * real refusal fires, and without this counter every visit to that screen
	 * wrote one refusal per registered ability into this record AND raised a
	 * medium-severity event for each, which alerting sends. The product's own
	 * introspection would have become its loudest source of false alarms,
	 * about the one signal it most needs to be trusted.
	 *
	 * A counter rather than a flag because a probe can sit inside an ability
	 * invocation that is itself being recorded, and that invocation must
	 * still be recorded.
	 */
	private static int $suspended = 0;

	public static function instance(): Capture {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/* ---- deliberate probes ---------------------------------------------------- */

	/**
	 * Stop recording until the matching resume().
	 *
	 * For code in this plugin that asks a permission callback a question
	 * rather than making a call. Always paired in a `finally`, or a thrown
	 * exception leaves the record switched off for the rest of the request.
	 */
	public static function suspend(): void {
		++self::$suspended;
	}

	public static function resume(): void {
		if ( self::$suspended > 0 ) {
			--self::$suspended;
		}
	}

	public static function is_suspended(): bool {
		return self::$suspended > 0;
	}

	/* ---- the gates ---------------------------------------------------------- */

	/**
	 * Whether this platform has the lifecycle filters at all.
	 *
	 * Compared against the alpha of the required release rather than the
	 * release itself. `version_compare` sorts dev < alpha < beta < RC < final,
	 * so a plain comparison refuses every pre-release — which is to say it
	 * refuses exactly the builds that carry a filter before it ships, and the
	 * only builds anyone can test it on. Alpha sorts below every other
	 * pre-release tag, so this admits nightly, beta and RC and still refuses
	 * the release before.
	 */
	public static function is_available(): bool {
		return version_compare( (string) get_bloginfo( 'version' ), self::REQUIRES_WP . '-alpha', '>=' );
	}

	/**
	 * On by default. Diagnosis is free and a record nobody switched on is the
	 * only kind that is there when something happens. The setting exists for
	 * the site that decides the volume is not worth it, not as an invitation
	 * to leave it off.
	 */
	public static function is_enabled(): bool {
		return '0' !== get_option( self::OPTION, '1' );
	}

	/**
	 * The same shape every other settings holder answers in, so the release
	 * panel can ask this one what it is without a special case.
	 *
	 * @return array{recording: bool}
	 */
	public static function settings(): array {
		return array( 'recording' => self::is_enabled() );
	}

	/**
	 * Turn the record of agent activity on or off.
	 *
	 * @return true|\WP_Error True once the switch is stored.
	 */
	public static function set_enabled( bool $enabled ) {
		/*
		 * Written before the change, so the way back exists whether or not the
		 * write that follows succeeds.
		 *
		 * And false stops it. This is the switch whose consequence is that
		 * nothing is recorded, so moving it without a record of where it was
		 * is the one change here nobody could later notice had been made.
		 */
		$undo = \BetterShield\Undo\SettingsLedger::record(
			'agent_capture',
			self::settings(),
			array( 'recording' => $enabled )
		);

		if ( false === $undo ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $enabled ? '1' : '0', true );

		Writer::instance()->record(
			'setting_changed',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array( 'enabled' => $enabled ),
			)
		);

		return true;
	}

	/* ---- registration -------------------------------------------------------- */

	public function register(): void {
		if ( $this->registered || ! self::is_available() || ! self::is_enabled() ) {
			return;
		}

		$this->registered = true;

		InvocationWriter::instance()->register();

		// The one action, and the only hook that sees an invocation begin.
		add_action( 'wp_ability_invoked', array( $this, 'on_invoked' ), 10, 3 );

		/*
		 * The permission verdict. At 999 so any plugin that grants or refuses
		 * has already spoken. This is also the only hook that sees a refusal
		 * made outside execute() — which is how every REST refusal arrives,
		 * and refusals are the point of this feature.
		 */
		add_filter( 'wp_ability_permission_result', array( $this, 'on_permission' ), 999, 4 );

		/*
		 * The two input gates, between the short-circuit and the permission
		 * check. A call rejected for malformed input reaches no later hook at
		 * all: without these it would sit open until shutdown and be written
		 * as `unknown`, indistinguishable from a genuine correlation failure.
		 */
		add_filter( 'wp_ability_normalize_input', array( $this, 'on_normalized' ), 999, 3 );
		add_filter( 'wp_ability_validate_input', array( $this, 'on_validated' ), 999, 3 );

		/*
		 * Something claimed the invocation before it ran. The test is against
		 * core's sentinel, not against null: a short-circuit that legitimately
		 * returns null is still a short-circuit.
		 */
		add_filter( 'wp_pre_execute_ability', array( $this, 'on_pre' ), 999, 2 );

		/*
		 * The two exits at the far end of execute(), which core takes by
		 * returning early — before `wp_after_execute_ability`. A failed
		 * callback and a result that fails its own output schema both leave
		 * the lifecycle silently.
		 */
		add_filter( 'wp_ability_execute_result', array( $this, 'on_execute_result' ), 999, 2 );
		add_filter( 'wp_ability_validate_output', array( $this, 'on_validated_output' ), 999, 3 );

		// The ordinary ending.
		add_action( 'wp_after_execute_ability', array( $this, 'on_after' ), 10, 4 );

		// Ahead of the invocation writer's flush at 90, which is itself ahead
		// of the activity log's at 100.
		add_action( 'shutdown', array( $this, 'on_shutdown' ), 80 );
	}

	/**
	 * The correlation id of the invocation this request is inside, if any.
	 *
	 * A write ability records what it is about to do before it does it, and
	 * that record has to name the call it belongs to or the two halves of the
	 * story cannot be joined afterwards. The innermost open record answers,
	 * because an ability that invokes another is inside the inner one; null
	 * where nothing is open, which is what a direct call outside the API is.
	 */
	public function current_correlation( ?string $ability = null ): ?string {
		$stack = null === $ability
			? ( array() === $this->open ? array() : (array) end( $this->open ) )
			: ( $this->open[ $ability ] ?? array() );

		if ( array() === $stack ) {
			return null;
		}

		$record = end( $stack );

		return isset( $record['row']['correlation_id'] ) ? (string) $record['row']['correlation_id'] : null;
	}

	/* ---- capture ------------------------------------------------------------- */

	/**
	 * An invocation begins. Fires before normalization, validation and the
	 * permission check, and cannot block.
	 *
	 * @param mixed $input
	 * @param mixed $ability
	 */
	public function on_invoked( string $name, $input = null, $ability = null ): void {
		if ( self::is_suspended() ) {
			return;
		}

		$this->open[ $name ][] = array(
			'started' => hrtime( true ),
			'row'     => array(
				'site_id'            => \BetterShield\Database\Schema::site_id( 'agent_invocations' ),
				'invoked_at'         => self::now(),
				'correlation_id'     => self::correlation_id(),
				'ability_name'       => Text::clip( $name, 191 ),
				'registering_plugin' => self::namespace_of( $name ),
				'entry_path'         => Writer::entry_path(),
				'user_id'            => get_current_user_id(),
				'outcome'            => 'unknown',
				'error_code'         => null,
				'input_digest'       => self::digest( $input ),
				'duration_ms'        => null,
				// Which connection made the call, so two assistants on one
				// account read apart (#2213). Never the credential.
				'connection'         => \BetterShield\Mcp\Audit::connection(),
			),
		);
	}

	/**
	 * The permission verdict.
	 *
	 * A refusal ends the lifecycle — `wp_after_execute_ability` will not fire
	 * — so it is closed here. When there is no open record the check ran on
	 * its own, outside execute(): core's REST run controller does exactly
	 * that in the route's permission callback, and on refusal never reaches
	 * execute(), so `wp_ability_invoked` never fired. Recording it from this
	 * filter is the only way that refusal is ever seen.
	 *
	 * Only refusals are recorded from the standalone path. A standalone grant
	 * is followed by execute(), which opens its own record; recording here as
	 * well would count the invocation twice.
	 *
	 * @param mixed $result
	 * @param mixed $name
	 * @param mixed $input
	 * @param mixed $ability
	 * @return mixed
	 */
	public function on_permission( $result, $name = null, $input = null, $ability = null ) {
		if ( true === $result ) {
			return $result;
		}

		$this->close_or_record( self::name_of( $name ), 'permission_denied', $input );

		return $result;
	}

	/**
	 * Input that could not be normalized. Ends the lifecycle.
	 *
	 * @param mixed $input
	 * @param mixed $name
	 * @param mixed $ability
	 * @return mixed
	 */
	public function on_normalized( $input, $name = null, $ability = null ) {
		if ( is_wp_error( $input ) ) {
			/*
			 * No input, deliberately. What this filter carries on failure is
			 * the refusal, not what the caller sent — and a digest of the
			 * refusal, in a column that means "what was sent", correlates
			 * calls that have nothing to do with each other. The raw input is
			 * not reachable from here, and absent states that.
			 */
			$this->close_or_record( self::name_of( $name ), 'input_not_normalizable', null );
		}

		return $input;
	}

	/**
	 * Input that failed the ability's own schema. Ends the lifecycle.
	 *
	 * @param mixed $is_valid
	 * @param mixed $input
	 * @param mixed $name
	 * @return mixed
	 */
	public function on_validated( $is_valid, $input = null, $name = null ) {
		if ( is_wp_error( $is_valid ) ) {
			$this->close_or_record( self::name_of( $name ), 'input_invalid', $input );
		}

		return $is_valid;
	}

	/**
	 * Something answered for the ability before it ran.
	 *
	 * @param mixed $value
	 * @param mixed $name
	 * @return mixed
	 */
	public function on_pre( $value, $name = null ) {
		if ( ! ( $value instanceof \WP_Filter_Sentinel ) ) {
			$this->close( self::name_of( $name ), 'short_circuited' );
		}

		return $value;
	}

	/**
	 * The execute callback's own failure. Core returns it without firing
	 * `wp_after_execute_ability`, so this is the only place a failed ability
	 * can be named. Successes pass through untouched — the after action
	 * closes those, and closing here too would lose the completed label.
	 *
	 * @param mixed $result
	 * @param mixed $name
	 * @return mixed
	 */
	public function on_execute_result( $result, $name = null ) {
		if ( is_wp_error( $result ) ) {
			$this->close( self::name_of( $name ), self::failure_outcome( $result ), (string) $result->get_error_code() );
		}

		return $result;
	}

	/**
	 * A callback's refusal of input its schema could not express, such as a
	 * call naming neither of an ability's two shapes, is input rejected like
	 * the schema's own refusals. Everything else it returns is a failure.
	 */
	private static function failure_outcome( \WP_Error $error ): string {
		$data = $error->get_error_data();

		return is_array( $data ) && ! empty( $data['input_invalid'] ) ? 'input_invalid' : 'failed';
	}

	/**
	 * Output that failed its own schema — the second early return, after the
	 * callback itself succeeded.
	 *
	 * @param mixed $is_valid
	 * @param mixed $output
	 * @param mixed $name
	 * @return mixed
	 */
	public function on_validated_output( $is_valid, $output = null, $name = null ) {
		if ( is_wp_error( $is_valid ) ) {
			$this->close( self::name_of( $name ), 'output_invalid' );
		}

		return $is_valid;
	}

	/**
	 * The ordinary ending.
	 *
	 * @param mixed $name
	 * @param mixed $input
	 * @param mixed $result
	 * @param mixed $ability
	 */
	public function on_after( $name, $input = null, $result = null, $ability = null ): void {
		if ( is_wp_error( $result ) ) {
			$this->close( self::name_of( $name ), self::failure_outcome( $result ), (string) $result->get_error_code() );

			return;
		}

		$this->close( self::name_of( $name ), 'completed' );
	}

	/**
	 * Anything still open never finished its lifecycle. It is written as
	 * `unknown` rather than lost, and never promoted to `completed`.
	 *
	 * The tamper check is deliberately not conditioned on having captured
	 * something first. The realistic case is a plugin that unhooks at load,
	 * before any ability runs — which under a "only if we captured something"
	 * guard produces no rows and no notice either, which is silent removal.
	 * We registered the hook; if it is gone now, someone took it off, whether
	 * or not an ability ran in between.
	 */
	public function on_shutdown(): void {
		foreach ( $this->open as $records ) {
			foreach ( $records as $record ) {
				$this->persist( $record, 'unknown' );
			}
		}

		$this->open = array();

		$this->weigh_refusals();

		$dropped = InvocationWriter::instance()->dropped();

		if ( $dropped > 0 ) {
			// An omission that is not stated is a record that lies by looking
			// complete.
			Writer::instance()->record(
				'agent_capture_truncated',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'agent',
					'context'     => array( 'dropped' => $dropped ),
				)
			);
		}

		if ( false === has_action( 'wp_ability_invoked', array( $this, 'on_invoked' ) ) ) {
			/*
			 * Once an hour, not once a request. The condition persists — a
			 * plugin that unhooks this at load does it on every request — and
			 * the row is a security type, so it is exempt from every drop
			 * policy and from sampling. Unthrottled that is an unbounded write
			 * of an undroppable row for as long as the conflict lasts, which
			 * is the shape the application-password listener already throttles
			 * for the same reason. The signal is "somebody silenced the
			 * record", and it says that just as well once an hour.
			 */
			if ( ! Claim::claim( 'agentgone', HOUR_IN_SECONDS ) ) {
				return;
			}

			Writer::instance()->record(
				'agent_capture_removed',
				Writer::SEVERITY_HIGH,
				array(
					'object_type' => 'agent',
					'context'     => array(
						'entry_path' => Writer::entry_path(),
					),
				)
			);
		}
	}

	/* ---- closing ------------------------------------------------------------- */

	/**
	 * End the newest open record for an ability with a stated outcome.
	 */
	private function close( ?string $name, string $outcome, ?string $error_code = null ): void {
		if ( null === $name || ! isset( $this->open[ $name ] ) || array() === $this->open[ $name ] ) {
			return;
		}

		$this->persist( array_pop( $this->open[ $name ] ), $outcome, $error_code );
	}

	/**
	 * End a rejected invocation, wherever in the lifecycle it was rejected.
	 *
	 * Inside execute() there is an open record to close. Outside it there is
	 * not, and the rejection is recorded from the filter that did fire — with
	 * no duration, because there is no invocation to have timed.
	 *
	 * @param mixed $input
	 */
	private function close_or_record( ?string $name, string $outcome, $input = null ): void {
		if ( null === $name || self::is_suspended() ) {
			return;
		}

		if ( 'permission_denied' === $outcome ) {
			$this->announce_refusal( $name );
		}

		if ( isset( $this->open[ $name ] ) && array() !== $this->open[ $name ] ) {
			$this->close( $name, $outcome );

			return;
		}

		$key = $name . '|' . get_current_user_id() . '|' . $outcome;

		if ( isset( $this->standalone[ $key ] ) ) {
			return;
		}

		$this->standalone[ $key ] = true;

		InvocationWriter::instance()->record(
			array(
				'site_id'            => \BetterShield\Database\Schema::site_id( 'agent_invocations' ),
				'invoked_at'         => self::now(),
				'correlation_id'     => self::correlation_id(),
				'ability_name'       => Text::clip( $name, 191 ),
				'registering_plugin' => self::namespace_of( $name ),
				'entry_path'         => Writer::entry_path(),
				'user_id'            => get_current_user_id(),
				'outcome'            => $outcome,
				'error_code'         => null,
				'input_digest'       => self::digest( $input ),
				'duration_ms'        => null,
			)
		);
	}

	/**
	 * Put a refusal in the activity log, where alerting can see it.
	 *
	 * The invocation table records every refusal; this records one line per
	 * distinct refusal per request. An agent looping on an ability it lacks
	 * rights for is the signal this whole feature exists to surface, and it
	 * must reach the owner — but as a signal, not as one message per attempt.
	 */
	private function announce_refusal( string $name ): void {
		$key = $name . '|' . get_current_user_id();

		if ( isset( $this->announced[ $key ] ) ) {
			return;
		}

		$this->announced[ $key ] = true;

		Writer::instance()->record(
			'agent_permission_denied',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'ability',
				'object_id'   => Text::clip( $name, 191 ),
				'context'     => array(
					'namespace'  => self::namespace_of( $name ),
					'entry_path' => Writer::entry_path(),
				),
			)
		);
	}

	/**
	 * Decide whether this request's refusals amount to a pattern.
	 *
	 * Counted once per request rather than once per refusal, for two reasons
	 * that point the same way. The counter is a real query and the capture
	 * path's whole budget rests on not making one per invocation, so a request
	 * pays for this at most once and only when something was actually refused.
	 * And the unit is right: one request is one action however many calls it
	 * contained, so ten separate requests over an hour is the repetition worth
	 * naming, where one request refused ten times is a single misconfigured
	 * integration. That one is still fully recorded and still reaches the
	 * digest — it simply does not interrupt anybody.
	 *
	 * The event fires on the crossing bump alone. `Claim::bump()` hands back
	 * the count from the database, so exactly one caller sees the threshold
	 * value and exactly one event is raised per window, with no second key to
	 * keep in step.
	 */
	private function weigh_refusals(): void {
		if ( array() === $this->announced ) {
			return;
		}

		/**
		 * How many requests carrying a refusal, inside the window, raise the
		 * louder event. Zero or less switches the escalation off entirely and
		 * leaves the individual refusals in the log and the digest.
		 *
		 * @param int $threshold The default, self::REPEAT_THRESHOLD.
		 */
		$threshold = (int) apply_filters( 'bettershield_agent_refusal_threshold', self::REPEAT_THRESHOLD );

		if ( $threshold < 1 ) {
			return;
		}

		$count = Claim::bump( 'bsagentdeny', self::REPEAT_WINDOW_MINUTES * MINUTE_IN_SECONDS );

		if ( $count !== $threshold ) {
			return;
		}

		Writer::instance()->record(
			'agent_refusals_repeated',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'agent',
				'context'     => array(
					'requests'       => $count,
					'window_minutes' => self::REPEAT_WINDOW_MINUTES,
				),
			)
		);
	}

	/**
	 * @param array<string, mixed> $record
	 */
	private function persist( array $record, string $outcome, ?string $error_code = null ): void {
		$row = $record['row'];

		$row['outcome']    = $outcome;
		$row['error_code'] = null === $error_code ? null : Text::clip( $error_code, 64 );

		if ( isset( $record['started'] ) ) {
			$row['duration_ms'] = (int) round( ( hrtime( true ) - $record['started'] ) / 1e6 );
		}

		InvocationWriter::instance()->record( $row );
	}

	/* ---- helpers ------------------------------------------------------------- */

	private static function now(): string {
		return gmdate( 'Y-m-d H:i:s' ) . substr( (string) microtime( false ), 1, 4 );
	}

	private static function correlation_id(): string {
		return bin2hex( random_bytes( 16 ) );
	}

	/**
	 * The digest of an input, never the input. Ability inputs may carry
	 * secrets, and this column exists so calls can be correlated without any
	 * of that being kept.
	 *
	 * Keys are put in one order first. Object member order is not significant
	 * in JSON, and nothing upstream settles it: the hook that opens a record
	 * fires before normalization, deliberately, so what arrives here is the
	 * raw input in whatever order the caller wrote it. Digested as-is, one
	 * call spelled two ways read as two unrelated calls — in the column whose
	 * only job is to say they are the same one.
	 *
	 * An input that cannot be encoded has no digest rather than the digest of
	 * an empty string, which would correlate every such call with every other.
	 *
	 * Keyed, because an unkeyed hash over a small set of inputs is a lookup
	 * table rather than a one-way function: an ability that takes one of
	 * fifteen item ids would have its argument recovered from the column by
	 * anyone who can read the log. The key is the plugin's own, so the column
	 * still correlates calls on this site and no longer correlates them with
	 * anything off it.
	 *
	 * @param mixed $input
	 */
	public static function digest( $input ): ?string {
		if ( null === $input ) {
			return null;
		}

		$encoded = wp_json_encode( self::canonical( $input ) );

		return false === $encoded ? null : hash_hmac( 'sha256', $encoded, ClientIp::signing_secret() );
	}

	/**
	 * The same value with every array's keys in one order, however deeply
	 * they nest. A list keeps its order: its keys are already 0, 1, 2.
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	private static function canonical( $value ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		ksort( $value );

		foreach ( $value as $key => $item ) {
			$value[ $key ] = self::canonical( $item );
		}

		return $value;
	}

	/**
	 * The ability name's namespace prefix — the strongest attribution the
	 * platform supports. `WP_Ability` keeps its execute callback in a
	 * protected property with no accessor, so nothing maps an ability to the
	 * plugin that registered it beyond this convention.
	 */
	private static function namespace_of( string $name ): ?string {
		$slash = strpos( $name, '/' );

		if ( false === $slash || 0 === $slash ) {
			return null;
		}

		return Text::clip( substr( $name, 0, $slash ), 191 );
	}

	/**
	 * Core passes the ability name to some of these hooks and the object to
	 * others; both arrive here.
	 *
	 * @param mixed $ability
	 */
	private static function name_of( $ability ): ?string {
		if ( is_string( $ability ) && '' !== $ability ) {
			return $ability;
		}

		if ( is_object( $ability ) && method_exists( $ability, 'get_name' ) ) {
			$name = (string) $ability->get_name();

			return '' === $name ? null : $name;
		}

		return null;
	}

	/**
	 * Test seam.
	 */
	public function reset(): void {
		$this->open       = array();
		$this->standalone = array();
		$this->announced  = array();
		self::$suspended  = 0;
	}
}
