<?php
/** Checks and observation that change no protection. @package BetterShield */
declare( strict_types=1 );
namespace BetterShield\Abilities;

use BetterShield\Hardening\Monitor;
use BetterShield\Support\Claim;

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class WriteChecks {

	public const NAMES = array( 'run-audit', 'run-file-check', 'run-recovery-check', 'refresh-incidents', 'monitor-hardening', 'run-vulnerability-check', 'run-scheduled-work', 'recheck-finding', 'recheck-package' );

	/** The findings Check again answers for: the guidance findings, and the domain's records. */
	public static function recheckable(): array {
		return array_merge( \BetterShield\Fixes\Guidance::KEYS, array( 'domain_mail_records' ) );
	}

	/**
	 * Slices of a file check already under way, an hour. Each is bounded, and
	 * a site's check takes a dozen or more; counted against the hourly write
	 * allowance, an assistant could not finish a check it had started.
	 */
	public const FILE_CHECK_SLICES_PER_HOUR = 60;

	/** Whether a call to run-file-check would carry on a check already under way. */
	public static function continues_a_file_check( string $short ): bool {
		return 'run-file-check' === $short && array() !== \BetterShield\Integrity\Scanner::state();
	}

	/** Reuse the read contract so a completed check cannot drift from its read. */
	private static function overview(): array {
		return ReadSurface::definitions( array(), static function (): void {} )['bettershield/get-security-overview'];
	}

	public static function definitions( callable $execute ): array {
		$string = array( 'type' => 'string' );
		$integer = array( 'type' => 'integer' );
		$boolean = array( 'type' => 'boolean' );
		$overview = self::overview()['output_schema'];
		$specs = array(
			'run-audit' => array(
				'label' => __( 'Run a security audit', 'bettershield' ),
				'description' => __( 'Runs the site’s security audit and returns its Overview. Changes no protection. Requires write access and uses its own hourly allowance.', 'bettershield' ),
				'output' => $overview,
			),
			'run-file-check' => array(
				'label' => __( 'Check part of the site’s files', 'bettershield' ),
				'description' => __( 'Starts or continues one bounded slice of the file check. A running result needs further slices; the answer names the next scheduled check when one exists. Slices that continue a check under way have their own, larger hourly allowance. Changes no file or protection.', 'bettershield' ),
				'output' => self::object( array( 'running' => $boolean, 'progress' => self::object( array( 'target' => $integer, 'targets' => $integer, 'phase' => $string, 'checked' => $integer, 'label' => $string ) ), 'next_check_at' => $string, 'continuation' => $string ) ),
			),
			'run-recovery-check' => array(
				'label' => __( 'Check recovery readiness', 'bettershield' ),
				'description' => __( 'Verifies the site’s existing recovery setup and returns its readiness. At most once a minute. Never creates a recovery link or recovery codes and never accepts a caller’s claim that recovery is ready.', 'bettershield' ),
				'output' => self::object( array( 'recovery' => $overview['properties']['recovery'] ) ),
			),
			'refresh-incidents' => array(
				'label' => __( 'Refresh incident evidence', 'bettershield' ),
				'description' => __( 'Runs one bounded pass correlating existing evidence and returns whether more work is pending. Changes no protection and applies no incident response.', 'bettershield' ),
				'output' => self::object( array( 'engine' => self::object( array( 'last_checked_at' => $string, 'pending' => $boolean, 'failed' => $boolean ) ) ) ),
			),
			'monitor-hardening' => array(
				'label' => __( 'Test a protection without turning it on', 'bettershield' ),
				'description' => __( 'Starts observation for one hour, one day or one week, or stops the matching monitor_id. It enforces nothing. The sign-in address cannot be observed through an ability. Enforcing a protection still needs its own plan and any required confirmation.', 'bettershield' ),
				'input' => array( 'item_id' => array( 'type' => 'string', 'enum' => array_values( array_diff( Monitor::SUPPORTED, array( 'login_url' ) ) ) ), 'action' => array( 'type' => 'string', 'enum' => array( 'start', 'stop' ) ), 'duration' => array( 'type' => 'integer', 'enum' => array( HOUR_IN_SECONDS, DAY_IN_SECONDS, WEEK_IN_SECONDS ) ), 'monitor_id' => $string ),
				'required' => array( 'item_id', 'action' ),
				'output' => self::object( array( 'monitor' => array( 'type' => 'object' ), 'monitor_id' => $string ) ),
			),
			'run-vulnerability-check' => array(
				'label' => __( 'Check for known vulnerabilities now', 'bettershield' ),
				'description' => __( 'Compares the installed plugins, themes and WordPress against the vulnerability feed now rather than at the next daily run, then refreshes the findings. Read get-vulnerability-state for the result. Changes no code or protection.', 'bettershield' ),
				'output' => self::object( array( 'ran' => $boolean, 'reason' => $string, 'affected' => $integer ) ),
			),
			'run-scheduled-work' => array(
				'label' => __( 'Run the site’s overdue scheduled work', 'bettershield' ),
				'description' => __( 'Asks the site to run the scheduled work it has fallen behind on, once, inside the runner’s own claim. Answers with how far behind it is. Changes no protection.', 'bettershield' ),
				'output' => self::object( array( 'result' => $string, 'overdue' => $integer, 'behind_seconds' => $integer, 'disabled' => $boolean ) ),
			),
			'recheck-finding' => array(
				'label' => __( 'Check a finding again', 'bettershield' ),
				'description' => __( 'Asks one finding whose cause is outside this plugin, or the domain’s mail and certificate records, to be checked again. A certificate or records lookup is queued and answers later. Changes nothing on the site.', 'bettershield' ),
				'input' => array( 'finding' => array( 'type' => 'string', 'enum' => self::recheckable() ) ),
				'required' => array( 'finding' ),
				'output' => self::object( array( 'open' => $boolean, 'queued' => $boolean ) ),
			),
			'recheck-package' => array(
				'label' => __( 'Compare one plugin’s changed files again', 'bettershield' ),
				'description' => __( 'Compares one plugin’s open file changes against the copy wordpress.org published for the installed version, and closes each that matches now, as after an update finished. Bounded: pass the returned after to carry on while left is above zero. Changes no file.', 'bettershield' ),
				'input' => array( 'slug' => array( 'type' => 'string', 'pattern' => '^[a-z0-9][a-z0-9_-]{0,190}$' ), 'after' => array( 'type' => 'integer', 'minimum' => 0 ) ),
				'required' => array( 'slug' ),
				'output' => self::object( array( 'checked' => $integer, 'closed' => $integer, 'left' => $integer, 'after' => $integer, 'version' => $string ) ),
			),
		);
		$out = array();
		foreach ( $specs as $short => $spec ) {
			$out[ 'bettershield/' . $short ] = array(
				'category' => 'bettershield', 'permission_callback' => array( Registrar::class, 'can_write' ),
				'label' => $spec['label'], 'description' => $spec['description'],
				'meta' => array( 'annotations' => array( 'readonly' => false, 'destructive' => false, 'idempotent' => false ), 'show_in_rest' => true ),
				'input_schema' => array( 'type' => 'object', 'properties' => $spec['input'] ?? array(), 'required' => $spec['required'] ?? array() ),
				'output_schema' => $spec['output'],
				'execute_callback' => static function ( $input ) use ( $execute, $short ) { return $execute( $short, $input ); },
			);
		}
		return $out;
	}

	private static function object( array $properties ): array {
		return array( 'type' => 'object', 'properties' => $properties, 'required' => array_keys( $properties ) );
	}

	/** Validate before the hourly allowance is spent, including calls made directly in PHP. */
	public static function validate( string $short, array $input ): ?\WP_Error {
		if ( ! in_array( $short, self::NAMES, true ) ) {
			return new \WP_Error( 'bettershield_unknown_check', __( 'There is no such check.', 'bettershield' ), array( 'status' => 400 ) );
		}
		if ( 'recheck-finding' === $short && ( array( 'finding' ) !== array_keys( $input ) || ! in_array( $input['finding'], self::recheckable(), true ) ) ) {
			return new \WP_Error( 'bettershield_check_input', __( 'Name a finding that can be checked again.', 'bettershield' ), array( 'status' => 400 ) );
		}
		if ( 'recheck-package' === $short && ( array() !== array_diff( array_keys( $input ), array( 'slug', 'after' ) ) || ! is_string( $input['slug'] ?? null ) || 1 !== preg_match( '/^[a-z0-9][a-z0-9_-]{0,190}$/D', $input['slug'] ) || ( isset( $input['after'] ) && ( ! is_int( $input['after'] ) || $input['after'] < 0 ) ) ) ) {
			return new \WP_Error( 'bettershield_check_input', __( 'Name one installed plugin by its folder.', 'bettershield' ), array( 'status' => 400 ) );
		}
		if ( 'monitor-hardening' !== $short ) { return null; }
		$item = $input['item_id'] ?? '';
		$action = $input['action'] ?? '';
		if ( 'login_url' === $item || ! in_array( $item, Monitor::SUPPORTED, true ) || ! in_array( $action, array( 'start', 'stop' ), true )
			|| ! in_array( $input['duration'] ?? DAY_IN_SECONDS, array( HOUR_IN_SECONDS, DAY_IN_SECONDS, WEEK_IN_SECONDS ), true )
			|| ( 'stop' === $action && ( ! is_string( $input['monitor_id'] ?? null ) || '' === $input['monitor_id'] ) ) ) {
			return new \WP_Error( 'bettershield_monitor_input', __( 'Choose a supported protection and observation period, or name the monitor to stop. The sign-in address stays on the site.', 'bettershield' ), array( 'status' => 400 ) );
		}
		return null;
	}

	/** Called only after Registrar has repeated the gate and taken the allowance. */
	public static function run( string $short, array $input ) {
		switch ( $short ) {
			case 'run-audit':
				\BetterShield\Audit\ExposedArtifacts::recheck_exposed();
				\BetterShield\Files\Quarantine::ask_the_server();
				\BetterShield\Audit\Auditor::run();
				return ( self::overview()['execute_callback'] )( array( 'include_fixed' => true ) );
			case 'run-recovery-check':
				if ( ! Claim::claim( 'recovery_readiness_check', MINUTE_IN_SECONDS ) ) {
					return new \WP_Error( 'bettershield_readiness_paced', __( 'Recovery was checked recently. Wait a minute before checking again.', 'bettershield' ), array( 'status' => 429 ) );
				}
				\BetterShield\Recovery\Readiness::run_now();
				return array( 'recovery' => ( self::overview()['execute_callback'] )( array() )['recovery'] );
			case 'refresh-incidents':
				\BetterShield\Incidents\Engine::tick();
				return array( 'engine' => \BetterShield\Incidents\Engine::report() );
			case 'run-file-check':
				// Complete only when this slice finished the run, read from the
				// run it finished: its cursor is gone by then, and read back it
				// said nothing was checked. A run another request holds is
				// still running (#2215).
				$state = \BetterShield\Integrity\Scanner::tick( 5.0, null, true );
				$done = isset( $state['finished_at'] );
				$report = \BetterShield\Integrity\Report::all();
				$progress = (array) ( $report['progress'] ?? array() );
				$next = (string) ( $report['next_run_at'] ?? '' );
				if ( $done ) {
					$targets = count( (array) ( $state['targets'] ?? array() ) );
					$progress = array( 'target' => $targets, 'targets' => $targets, 'phase' => (string) ( $state['phase'] ?? '' ), 'checked' => (int) ( $state['stats']['checked'] ?? 0 ), 'label' => '' );
				}
				return array(
					'running' => ! $done,
					'progress' => array( 'target' => (int) ( $progress['target'] ?? 0 ), 'targets' => (int) ( $progress['targets'] ?? 0 ), 'phase' => (string) ( $progress['phase'] ?? '' ), 'checked' => (int) ( $progress['checked'] ?? 0 ), 'label' => (string) ( $progress['label'] ?? '' ) ),
					'next_check_at' => $next,
					'continuation' => $done ? 'complete' : ( '' !== $next ? 'scheduled' : 'manual' ),
				);
			case 'run-vulnerability-check':
				$ran = \BetterShield\Vulnerabilities\Scanner::run();
				\BetterShield\Audit\Auditor::run();
				return array( 'ran' => (bool) $ran['ran'], 'reason' => (string) $ran['reason'], 'affected' => (int) $ran['affected'] );
			case 'run-scheduled-work':
				// The host's crontab lines name the server's folders, so they stay on the site's own screen.
				$tried = \BetterShield\Fixes\ScheduledWork::try_now();
				return array( 'result' => (string) $tried['result'], 'overdue' => (int) $tried['state']['overdue'], 'behind_seconds' => (int) $tried['state']['behind_seconds'], 'disabled' => (bool) $tried['state']['disabled'] );
			case 'recheck-finding':
				if ( 'domain_mail_records' === $input['finding'] ) {
					$queued = \BetterShield\Fixes\DomainMailRecords::check_again( get_current_user_id() );
					return is_wp_error( $queued ) ? $queued : array( 'open' => \BetterShield\Audit\Auditor::is_open( 'domain_mail_records' ), 'queued' => true );
				}
				$again = \BetterShield\Fixes\Guidance::check_again( $input['finding'], get_current_user_id() );
				return is_wp_error( $again ) ? $again : array( 'open' => (bool) $again['open'], 'queued' => (bool) $again['queued'] );
			case 'recheck-package':
				$done = \BetterShield\Integrity\Packages::recheck( $input['slug'], (int) ( $input['after'] ?? 0 ) );
				return is_wp_error( $done ) ? $done : array( 'checked' => (int) $done['checked'], 'closed' => (int) $done['closed'], 'left' => (int) $done['left'], 'after' => (int) $done['after'], 'version' => (string) $done['version'] );
			case 'monitor-hardening':
				$monitor = Monitor::change( $input['item_id'], $input['action'], array(), $input['duration'] ?? DAY_IN_SECONDS, 0, $input['monitor_id'] ?? '' );
				return is_wp_error( $monitor ) ? $monitor : array( 'monitor' => $monitor, 'monitor_id' => (string) ( $monitor['state']['id'] ?? '' ) );
		}
		return new \WP_Error( 'bettershield_unknown_check', __( 'There is no such check.', 'bettershield' ), array( 'status' => 400 ) );
	}
}
