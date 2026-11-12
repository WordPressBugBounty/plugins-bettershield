<?php
/**
 * WP-CLI: `wp bettershield <command>`.
 *
 * Thin by design. Every command calls the same service the dashboard's REST
 * route calls — the auditor, the hardening manager, the recovery classes,
 * the settings document — so the terminal and the screen cannot disagree,
 * and every change made here lands in the activity log and the undo ledger
 * exactly as a click would, stamped as having come through WP-CLI.
 *
 * Two rules on who may run what. A command that changes the site runs as
 * someone: it asks for `--user=<login>` naming an account that can manage
 * this plugin, and refuses otherwise, because a change with no one recorded
 * against it is a hole in the log. Reads need no user — the shell already
 * has the database. And `recover` needs no user either, deliberately: it
 * exists for the moment when the site's administrator cannot sign in, and
 * that is not a moment to demand a login.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Cli;

use BetterShield\Alerts\Settings as AlertSettings;
use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Events\Query;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Integrity\Report;
use BetterShield\Integrity\Restore;
use BetterShield\Integrity\Scanner;
use BetterShield\Login\Protection;
use BetterShield\Login\Surfaces;
use BetterShield\Operator\Diagnostics;
use BetterShield\Operator\Report as SecurityReport;
use BetterShield\Operator\SettingsDocument;
use BetterShield\Recovery\Lockdown;
use BetterShield\Recovery\Preflight;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;
use BetterShield\Rest\Permissions;
use BetterShield\Support\Text;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads and changes BetterShield from the command line.
 */
final class Command {

	/**
	 * Register with WP-CLI when running under it. Inert everywhere else.
	 */
	public static function register(): void {
		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) || ! class_exists( '\WP_CLI' ) ) {
			return;
		}

		\WP_CLI::add_command( 'bettershield', self::class );
	}

	/**
	 * Runs the read-only audit and reports the score.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: summary
	 * options:
	 *   - summary
	 *   - json
	 * ---
	 *
	 * [--fail-under=<score>]
	 * : Exit non-zero when the score is below this.
	 *   A whole number from 0 to 100.
	 *
	 * [--fail-on=<severity>]
	 * : Exit non-zero when an open finding is at this severity or worse.
	 *   One of critical, high, medium, low.
	 *
	 * [--strict]
	 * : Also exit non-zero when any check could not be evaluated. A build that
	 *   goes green because a check could not run is what this stops.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield audit
	 *     wp bettershield audit --format=json
	 *     wp bettershield audit --fail-under=80
	 *     wp bettershield audit --fail-on=high
	 *     wp bettershield audit --fail-on=critical --strict
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function audit( array $args, array $assoc_args ): void {
		self::format_from( $assoc_args, array( 'summary', 'json' ) );
		$this->check_gate_arguments( $assoc_args );

		// Somebody asked for this audit: a file removed after the weekly
		// sweep listed it is asked about again first, and a server that does
		// not read the quarantine's deny rule is asked about a kept copy.
		\BetterShield\Audit\ExposedArtifacts::recheck_exposed();
		\BetterShield\Files\Quarantine::ask_the_server();

		Auditor::run();

		$overview = Auditor::overview();
		$reasons  = $this->gate_failure( $overview, $assoc_args );
		$failure  = array() === $reasons ? null : implode( ' ', $reasons );

		if ( 'json' === ( $assoc_args['format'] ?? 'summary' ) ) {
			// A gate asked for is in the document, so a pipeline that parses
			// it reads why the step failed, not only an exit code (#2237).
			if ( isset( $assoc_args['fail-under'] ) || isset( $assoc_args['fail-on'] ) || isset( $assoc_args['strict'] ) ) {
				$overview['gate'] = array(
					'fail_on'    => isset( $assoc_args['fail-on'] ) ? strtolower( (string) $assoc_args['fail-on'] ) : null,
					'fail_under' => isset( $assoc_args['fail-under'] ) ? (int) $assoc_args['fail-under'] : null,
					'strict'     => isset( $assoc_args['strict'] ),
					'tripped'    => null !== $failure,
					'reasons'    => $reasons,
				);
			}

			// Only the document, and nothing after it. Which checks could not
			// be evaluated is already in the body as `checks_unknown`, so the
			// named lines below are for the reader at a terminal; on this
			// stream they are trailing text after the closing brace, and the
			// parser a pipeline pipes this into fails on them.
			\WP_CLI::line( (string) wp_json_encode( $overview, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );

			if ( null !== $failure ) {
				// On stderr, which a warning goes to: the log of a failed step
				// says why, and stdout stays one JSON document (#2237).
				\WP_CLI::warning( $failure );
				\WP_CLI::halt( 1 );
			}

			return;
		}

		// Named rather than counted: a log that says a check did not run is
		// only useful if it says which, and why.
		foreach ( (array) ( $overview['checks_unknown'] ?? array() ) as $unknown ) {
			\WP_CLI::log(
				sprintf(
					'  could not evaluate: %s — %s',
					(string) ( $unknown['title'] ?? $unknown['key'] ?? '' ),
					(string) ( $unknown['reason'] ?? '' )
				)
			);
		}

		$counts = $this->count_by_severity( $overview['findings'] );

		// A run that could not evaluate every check says so in the count, so
		// a pipeline log never reads a partial run as a complete one.
		$ran    = (int) ( $overview['checks_ran'] ?? $overview['checks_count'] );
		$checks = $ran === (int) $overview['checks_count']
			? sprintf( '%d checks', $overview['checks_count'] )
			: sprintf( '%d of %d checks', $ran, $overview['checks_count'] );

		// Snoozed findings are still open and still in the score, but
		// `wp bettershield findings` lists them apart, so the line says how
		// many of these it holds (#1792).
		$open    = (int) $overview['open_findings'];
		$snoozed = (int) ( $overview['snoozed_findings'] ?? 0 );
		$opened  = sprintf( 1 === $open ? '%d open finding' : '%d open findings', $open ) . ( $snoozed > 0 ? sprintf( ' (%d snoozed)', $snoozed ) : '' );

		$summary = sprintf(
			'Score %d (%s). %s across %s: %d critical, %d high, %d medium, %d low, %d info.',
			$overview['score'],
			$overview['grade'],
			$opened,
			$checks,
			$counts['critical'],
			$counts['high'],
			$counts['medium'],
			$counts['low'],
			$counts['info']
		);

		if ( null !== $failure ) {
			// `error()` would print a red line and exit 1; this exits 1 after
			// the summary the pipeline's log should still carry. A plain line,
			// not "Success:", on a step about to fail (#2237).
			\WP_CLI::log( $summary );
			\WP_CLI::warning( $failure );
			\WP_CLI::halt( 1 );
		}

		\WP_CLI::success( $summary );
	}

	/**
	 * Refuse a threshold that cannot mean anything, before the audit runs.
	 *
	 * A gate in a pipeline is read by nobody until it fails to fail. A value
	 * cast to a number would turn "eighty" into 0, which no score is below, so
	 * a typo in a build variable would switch the gate off in silence.
	 *
	 * @param array<string, string> $assoc_args
	 */
	private function check_gate_arguments( array $assoc_args ): void {
		if ( isset( $assoc_args['fail-under'] ) ) {
			$floor = (string) $assoc_args['fail-under'];

			if ( ! ctype_digit( $floor ) || (int) $floor > 100 ) {
				\WP_CLI::error( 'Use a whole number from 0 to 100 for --fail-under.' );
			}
		}

		if ( isset( $assoc_args['fail-on'] ) && ! in_array( strtolower( (string) $assoc_args['fail-on'] ), array( 'low', 'medium', 'high', 'critical' ), true ) ) {
			\WP_CLI::error( 'Use one of: critical, high, medium, low.' );
		}
	}

	/**
	 * Why this run should fail a build; none if it should not.
	 *
	 * The audit has been headless and JSON-capable since it shipped; the only
	 * thing between it and a real gate in somebody's pipeline was an exit
	 * code. Both thresholds are opt-in, so a command with neither behaves
	 * exactly as it always has.
	 *
	 * @param array<string, mixed>  $overview
	 * @param array<string, string> $assoc_args
	 * @return string[] Each reason the gate tripped; none when it did not.
	 */
	private function gate_failure( array $overview, array $assoc_args ): array {
		$reasons = array();

		if ( isset( $assoc_args['fail-under'] ) ) {
			$floor = (int) $assoc_args['fail-under'];

			if ( (int) $overview['score'] < $floor ) {
				$reasons[] = sprintf( 'Score %d is below the %d this run asked for.', (int) $overview['score'], $floor );
			}
		}

		if ( isset( $assoc_args['fail-on'] ) ) {
			$order = array( 'low', 'medium', 'high', 'critical' );
			$at    = array_search( strtolower( (string) $assoc_args['fail-on'] ), $order, true );

			$counts = $this->count_by_severity( $overview['findings'] );
			$hit    = 0;

			foreach ( array_slice( $order, (int) $at ) as $severity ) {
				$hit += (int) ( $counts[ $severity ] ?? 0 );
			}

			if ( $hit > 0 ) {
				$reasons[] = sprintf(
					'%d open finding(s) at %s or worse.',
					$hit,
					strtolower( (string) $assoc_args['fail-on'] )
				);
			}
		}

		// The same third state the integrity and advisory gates have: a check
		// that could not answer is not a pass.
		if ( isset( $assoc_args['strict'] ) ) {
			$unknown = count( (array) ( $overview['checks_unknown'] ?? array() ) );

			if ( $unknown > 0 ) {
				$reasons[] = sprintf( '%d check(s) could not be evaluated, and --strict treats that as a failure.', $unknown );
			}
		}

		return $reasons;
	}

	/**
	 * Lists findings from the last audit, or settles one of them.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : Settle one finding instead of listing them, as its row on the
	 * Findings screen does. Needs --user=<login> naming an account that can
	 * manage BetterShield.
	 * ---
	 * options:
	 *   - not-applicable
	 *   - reopen
	 *   - snooze
	 *   - wake
	 * ---
	 *
	 * [<finding>]
	 * : With an action, the finding's id, as the list prints it.
	 *
	 * [--days=<days>]
	 * : With snooze, how long to set it aside: 7 or 30.
	 *
	 * [--status=<status>]
	 * : Which findings to list.
	 * ---
	 * default: open
	 * options:
	 *   - open
	 *   - snoozed
	 *   - suppressed
	 *   - fixed
	 *   - all
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format. With an action, json prints the finding as it now
	 * stands and the score, and table prints a line.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - count
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield findings
	 *     wp bettershield findings --status=snoozed
	 *     wp bettershield findings --status=all --format=json
	 *     wp bettershield findings not-applicable backup_plugin_not_visible --user=admin
	 *     wp bettershield findings reopen backup_plugin_not_visible --user=admin
	 *     wp bettershield findings snooze admin_username_exists --days=30 --user=admin --format=json
	 *     wp bettershield findings wake admin_username_exists --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function findings( array $args, array $assoc_args ): void {
		if ( array() !== $args ) {
			$this->settle_finding( $args, $assoc_args );
			return;
		}

		if ( isset( $assoc_args['days'] ) ) {
			\WP_CLI::error( '--days goes with snooze: `wp bettershield findings snooze <finding> --days=7' . self::as_someone() . '`. Nothing was changed.' );
		}

		self::format_from( $assoc_args, array( 'table', 'json', 'csv', 'count' ) );

		$status = (string) ( $assoc_args['status'] ?? 'open' );
		$rows   = array();

		foreach ( Auditor::findings() as $finding ) {
			// A snoozed finding is still open, and listed on its own, as the
			// screen lists it.
			$state = empty( $finding['snoozed_until'] ) ? $finding['status'] : 'snoozed';

			if ( 'all' !== $status && $state !== $status ) {
				continue;
			}

			$rows[] = array(
				'id'       => $finding['id'],
				'severity' => $finding['severity'],
				'status'   => 'snoozed' === $state ? 'snoozed until ' . substr( (string) $finding['snoozed_until'], 0, 10 ) : $state,
				'title'    => $finding['title'],
				'fix'      => $finding['remediable'] ? (string) $finding['hardening_item'] : '',
				'why'      => $finding['why'],
			);
		}

		$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv', 'count' ) );
		$fields = 'json' === $format ? array( 'id', 'severity', 'status', 'title', 'fix', 'why' ) : array( 'id', 'severity', 'status', 'title', 'fix' );

		// WP-CLI echoes the count with no line ending, so the shell prompt
		// was printed on the same line as the number (#2084).
		if ( 'count' === $format ) {
			\WP_CLI::line( (string) count( $rows ) );
			return;
		}

		\WP_CLI\Utils\format_items( $format, $rows, $fields );
	}

	/**
	 * Settle one finding as its row on the Findings screen does: through the
	 * same services, so the same activity row is written, stamped as having
	 * come through WP-CLI.
	 *
	 * @param string[]              $args       The action, then the finding.
	 * @param array<string, string> $assoc_args
	 */
	private function settle_finding( array $args, array $assoc_args ): void {
		$action = (string) $args[0];
		$key    = (string) ( $args[1] ?? '' );

		if ( ! in_array( $action, array( 'not-applicable', 'reopen', 'snooze', 'wake' ), true ) ) {
			\WP_CLI::error( sprintf( 'Use one of: not-applicable, reopen, snooze, wake, not "%s". Nothing was changed.', $action ) );
		}

		if ( '' === $key || count( $args ) > 2 ) {
			\WP_CLI::error( sprintf( 'Name one finding, as the list prints it: `wp bettershield findings %s <finding>%s`. Nothing was changed.', $action, self::as_someone() ) );
		}

		// WP-CLI fills in the list's default, open, on every line, so only
		// a status someone chose is refused.
		if ( 'open' !== (string) ( $assoc_args['status'] ?? 'open' ) ) {
			\WP_CLI::error( '--status chooses what the list shows, and settling a finding lists nothing. Nothing was changed.' );
		}

		$format = (string) ( $assoc_args['format'] ?? 'table' );

		if ( ! in_array( $format, array( 'table', 'json' ), true ) ) {
			\WP_CLI::error( sprintf( '--format takes table or json when settling a finding, not "%s". Nothing was changed.', $format ) );
		}

		$days = 0;

		if ( 'snooze' === $action ) {
			$given = (string) ( $assoc_args['days'] ?? '' );

			if ( ! ctype_digit( $given ) || ! in_array( (int) $given, \BetterShield\Audit\Snooze::DAYS, true ) ) {
				\WP_CLI::error( sprintf( 'Say how long with --days: %s. Nothing was changed.', implode( ' or ', \BetterShield\Audit\Snooze::DAYS ) ) );
			}

			$days = (int) $given;
		} elseif ( isset( $assoc_args['days'] ) ) {
			\WP_CLI::error( sprintf( '--days goes with snooze, not %s. Nothing was changed.', $action ) );
		}

		$this->require_manage();

		switch ( $action ) {
			case 'not-applicable':
				$result = Auditor::suppress( $key );
				break;
			case 'reopen':
				$result = Auditor::unsuppress( $key );
				break;
			case 'snooze':
				$result = \BetterShield\Audit\Snooze::snooze( $key, $days );
				break;
			default:
				$result = \BetterShield\Audit\Snooze::wake( $key );
		}

		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() . ' Nothing was changed.' );
		}

		$finding = null;

		foreach ( Auditor::findings() as $row ) {
			if ( $key === $row['id'] ) {
				$finding = $row;
				break;
			}
		}

		$title = (string) ( $finding['title'] ?? $key );
		$until = \BetterShield\Audit\Snooze::until_iso( $key );

		if ( 'json' === $format ) {
			\WP_CLI::line(
				(string) wp_json_encode(
					array(
						'id'            => $key,
						'action'        => $action,
						'status'        => null !== $until ? 'snoozed' : (string) ( $finding['status'] ?? '' ),
						'snoozed_until' => $until,
						'title'         => $title,
						'score'         => (int) Auditor::overview()['score'],
					),
					JSON_UNESCAPED_SLASHES
				)
			);
			return;
		}

		switch ( $action ) {
			case 'not-applicable':
				$line = sprintf( 'Marked not applicable: %1$s. It no longer counts in the score. Put it back with `wp bettershield findings reopen %2$s%3$s`.', $title, $key, self::as_someone() );
				break;
			case 'reopen':
				$line = sprintf( 'Back in the report: %s. The checks ran again, so it shows as it stands now.', $title );
				break;
			case 'snooze':
				$line = sprintf( 'Snoozed until %1$s: %2$s. It still counts in the score. Bring it back sooner with `wp bettershield findings wake %3$s%4$s`.', substr( (string) $until, 0, 10 ), $title, $key, self::as_someone() );
				break;
			default:
				$line = sprintf( 'Back with the open findings: %s.', $title );
		}

		\WP_CLI::success( $line );
	}

	/**
	 * Applies, previews or undoes a hardening item — or lists them all.
	 *
	 * ## OPTIONS
	 *
	 * [<item>]
	 * : The item. Omit to list every item with its state.
	 *
	 * [--dry-run]
	 * : Describe what applying would do, changing nothing. Not with --undo.
	 *
	 * [--undo]
	 * : Revert the item, restoring exactly what was there before.
	 *
	 * [--force]
	 * : Apply an item that changes how people sign in even though the recovery
	 * pre-flight check failed. Recorded in the activity log with the check.
	 *
	 * [--action=<action>]
	 * : Run one of an applied item's actions, as its screen does, e.g.
	 * --action=rotate for auth_keys. A dry run lists the ones it offers.
	 *
	 * [--network]
	 * : With auth_keys --action=rotate on a multisite network, rotate the key
	 * every site shares. Needs a network administrator.
	 *
	 * [--<field>=<value>]
	 * : An option the item takes, e.g. --slug=<address> for login_url. A list
	 * takes commas, e.g. --roles=subscriber,customer for admin_area_access.
	 * hsts takes --mode=short|long and --subdomains=yes.
	 *
	 * [--format=<format>]
	 * : Output format for the list.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield harden
	 *     wp bettershield harden xmlrpc --dry-run
	 *     wp bettershield harden xmlrpc --user=admin
	 *     wp bettershield harden login_url --slug=side-door --user=admin
	 *     wp bettershield harden admin_area_access --roles=subscriber,customer --user=admin
	 *     wp bettershield harden hsts --mode=long --subdomains=yes --dry-run
	 *     wp bettershield harden xmlrpc --undo --user=admin
	 *     wp bettershield harden auth_keys --action=rotate --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function harden( array $args, array $assoc_args ): void {
		$manager = Manager::instance();

		if ( array() === $args ) {
			$rows = array();
			foreach ( $manager->describe_all() as $item ) {
				$rows[] = array(
					'item'      => $item['id'],
					'title'     => $item['title'],
					'active'    => $item['active'] ? 'yes' : 'no',
					'available' => $item['available'] ? 'yes' : 'no',
					'note'      => (string) ( $item['availability_note'] ?? $item['revert_failed'] ?? '' ),
				);
			}

			\WP_CLI\Utils\format_items( self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) ), $rows, array( 'item', 'title', 'active', 'available', 'note' ) );
			return;
		}

		$item = (string) $args[0];

		if ( ! in_array( $item, Items::ids(), true ) ) {
			\WP_CLI::error( sprintf( 'Unknown item "%s". Run `wp bettershield harden` to list them.', $item ) );
		}

		// The item's own options: everything typed but this command's flags.
		$options = $assoc_args;
		unset( $options['dry-run'], $options['undo'], $options['format'], $options['force'], $options['action'], $options['network'] );

		/*
		 * An item's own action, such as rotating the sign-in keys after a
		 * suspected compromise, when SSH may be the only way in. The only
		 * route here was --undo and applying again, which signed everybody
		 * out twice and wrote two rows for one rotation (#2236).
		 */
		if ( isset( $assoc_args['action'] ) ) {
			$this->run_item_action( $item, $assoc_args, $options );
			return;
		}

		if ( isset( $assoc_args['network'] ) ) {
			\WP_CLI::error( '--network works only with auth_keys --action=rotate. Nothing was changed.' );
		}

		// A dry run previews applying. With --undo as well it previewed the
		// apply, and said nothing of the flag it had passed over.
		if ( isset( $assoc_args['dry-run'], $assoc_args['undo'] ) ) {
			\WP_CLI::error( '--dry-run previews applying an item; there is no preview of --undo. Run the undo without --dry-run, or the dry run without --undo. Nothing was changed.' );
		}

		self::check_item_options( $item, $options, ! isset( $assoc_args['undo'] ) );

		if ( isset( $assoc_args['dry-run'] ) ) {
			// With the options it would apply with, as the screen's preview and
			// the abilities ask: without them a value the apply refuses read
			// as a dry run that succeeded.
			$probe = $manager->dry_run( $item, $options );
			if ( is_wp_error( $probe ) ) {
				\WP_CLI::error( $probe->get_error_message() );
			}

			if ( null !== $probe['refusal'] ) {
				\WP_CLI::error( (string) $probe['refusal'] . ' Nothing was changed.' );
			}

			\WP_CLI::line( $probe['title'] . ( $probe['already_active'] ? ( is_array( self::new_settings( $item, $options ) ) ? ' (already applied; this would change its settings)' : ' (already applied)' ) : '' ) );
			foreach ( $probe['effect'] as $line ) {
				\WP_CLI::line( '  - ' . $line );
			}
			// The actions an applied item offers, each by the flag that runs
			// it: the effect lines promise them, and nothing said how.
			if ( $probe['already_active'] ) {
				foreach ( self::offered_actions( $item ) as $key => $label ) {
					\WP_CLI::line( sprintf( '  Run `wp bettershield harden %1$s --action=%2$s --user=<login>` to %3$s.', $item, $key, lcfirst( $label ) ) );
				}
			}
			if ( ! $probe['available'] ) {
				\WP_CLI::warning( (string) $probe['availability_label'] . ': ' . (string) $probe['availability_note'] );
			}
			if ( null !== $probe['conflict_warning'] ) {
				\WP_CLI::warning( (string) $probe['conflict_warning'] );
			}
			\WP_CLI::success( 'Dry run. Nothing was changed.' );
			return;
		}

		$this->require_manage();

		if ( isset( $assoc_args['undo'] ) ) {
			$done = $manager->revert( $item );
			if ( is_wp_error( $done ) ) {
				\WP_CLI::error( $done->get_error_message() );
			}

			Auditor::run();

			// What the undo left as it was, and why.
			foreach ( (array) ( $done['notes'] ?? array() ) as $note ) {
				\WP_CLI::line( '  ' . $note );
			}

			\WP_CLI::success( sprintf( 'Undone: %s. What was there before is back.', Items::all()[ $item ]['title'] ) );
			return;
		}

		// The same pre-flight the dashboard asks, with --force as its second
		// confirmation.
		$failure = Permissions::needs_way_back( $item ) ? Preflight::failure() : null;
		if ( null !== $failure && ! isset( $assoc_args['force'] ) ) {
			// The command to run is the one typed, with --force added: without
			// its options, the suggestion for the sign-in address failed on the
			// address it left out.
			$again = 'wp bettershield harden ' . $item;
			foreach ( $options as $key => $value ) {
				$again .= true === $value ? ' --' . $key : ' --' . $key . '=' . escapeshellarg( (string) $value );
			}

			\WP_CLI::error( $failure['message'] . ' Run `' . $again . ' --force' . self::as_someone() . '` to go ahead anyway; that is recorded in the activity log.' );
		}

		/*
		 * Applied already, with other settings typed: changed the way the
		 * settings import and the screen change it, undone and applied again
		 * as one settings change, after the same pre-flight. The only way
		 * through was --undo and then applying again, which put the standard
		 * sign-in page back in public between the two and raised a "Hardening
		 * undone" alert (#2083). A refused second step puts the item back on
		 * with the settings it had, so it is never left off.
		 */
		$next = $manager->is_active( $item ) ? self::new_settings( $item, $options ) : null;

		// Refused before anything is undone, so a bad value never takes the
		// protection off even for a moment.
		if ( is_wp_error( $next ) ) {
			\WP_CLI::error( $next->get_error_message() . ' Nothing was changed.' );
		}

		$reconfigure = is_array( $next );

		if ( $reconfigure ) {
			$previous = $manager->item_state( $item )['options'] ?? array();
			$done     = $manager->revert( $item, Manager::CAUSE_RECONFIGURE );

			if ( ! is_wp_error( $done ) ) {
				$done = $manager->apply( $item, $next );

				if ( is_wp_error( $done ) ) {
					$manager->apply( $item, is_array( $previous ) ? $previous : array() );
				}
			}
		} else {
			$done = $manager->apply( $item, $options );
		}

		if ( is_wp_error( $done ) ) {
			\WP_CLI::error( $done->get_error_message() );
		}

		if ( null !== $failure ) {
			Preflight::overridden( $failure, $item, 'cli' );
		}

		Auditor::run();

		// The address as it was stored, lowercased, beside the note that asks
		// for it to be kept somewhere: the command said to store it and never
		// said what it was (#2078).
		if ( 'login_url' === $item ) {
			foreach ( $manager->describe_all() as $described ) {
				if ( 'login_url' === $described['id'] && null !== $described['summary'] ) {
					\WP_CLI::line( '  Sign-in address: ' . $described['summary'] );
				}
			}
		}

		foreach ( $done['notes'] as $note ) {
			\WP_CLI::line( '  ' . $note );
		}
		if ( null !== $done['conflict_warning'] ) {
			\WP_CLI::warning( (string) $done['conflict_warning'] );
		}
		\WP_CLI::success(
			$reconfigure
				? sprintf( 'Changed: %s now runs with the new settings. Undo with `wp bettershield harden %s --undo%s`.', Items::all()[ $item ]['title'], $item, self::as_someone() )
				: sprintf( 'Applied: %s. Undo with `wp bettershield harden %s --undo%s`.', Items::all()[ $item ]['title'], $item, self::as_someone() )
		);
	}

	/**
	 * Run one of an applied item's actions, the way its screen runs it: the
	 * same call, so the same single activity row and the same handling
	 * inside the action. On a network the sign-in key is shared, so it is
	 * rotated for every site with --network, as the network dashboard does.
	 *
	 * @param string               $item       The item.
	 * @param array<string, mixed> $assoc_args Everything typed.
	 * @param array<string, mixed> $options    Everything typed but the command's own flags.
	 */
	private function run_item_action( string $item, array $assoc_args, array $options ): void {
		$action = $assoc_args['action'];

		if ( ! is_string( $action ) || '' === trim( $action ) ) {
			\WP_CLI::error( '--action needs the name of an action, e.g. --action=rotate. Nothing was changed.' );
		}

		foreach ( array( 'dry-run', 'undo', 'force' ) as $flag ) {
			if ( isset( $assoc_args[ $flag ] ) ) {
				\WP_CLI::error( sprintf( '--action runs on its own and cannot be combined with --%s. Nothing was changed.', $flag ) );
			}
		}

		if ( array() !== $options ) {
			\WP_CLI::error( sprintf( '--action takes no item options, so --%s would be ignored. Nothing was changed.', implode( ', --', array_map( 'strval', array_keys( $options ) ) ) ) );
		}

		$network = 'auth_keys' === $item && 'rotate' === $action;

		if ( isset( $assoc_args['network'] ) ) {
			self::refuse_off_network( '--network' );

			if ( ! $network ) {
				\WP_CLI::error( '--network works only with auth_keys --action=rotate. Nothing was changed.' );
			}

			if ( ! current_user_can( 'manage_network_options' ) ) {
				\WP_CLI::error( 'Rotating the key every site shares is a network administrator\'s: add --user=<login> naming one. Nothing was changed.' );
			}

			// No session comes with WP-CLI, so none is carried over.
			$rotated = Manager::instance()->rotate_network_keys( 0 );

			if ( is_wp_error( $rotated ) ) {
				\WP_CLI::error( $rotated->get_error_message() );
			}

			if ( $rotated['capped'] ) {
				\WP_CLI::warning( 'The time ran out before every site was reached. Their sessions end at their next request, since the key they were signed with is gone.' );
			}

			\WP_CLI::success( sprintf( 'Keys rotated for the whole network: %1$d sessions ended across %2$d sites. Everybody signs in again.', (int) $rotated['ended'], (int) $rotated['sites'] ) );
			return;
		}

		if ( $network && is_multisite() ) {
			\WP_CLI::error( 'On a network every site shares the sign-in key. Rotate it for all of them with `wp bettershield harden auth_keys --action=rotate --network --user=<login>`. Nothing was changed.' );
		}

		$this->require_manage();

		$manager = Manager::instance();

		if ( ! $manager->is_active( $item ) ) {
			\WP_CLI::error( sprintf( '%1$s is not applied, so it has no actions to run. Apply it first with `wp bettershield harden %1$s --user=<login>`. Nothing was changed.', $item ) );
		}

		$offered = self::offered_actions( $item );

		if ( ! isset( $offered[ $action ] ) ) {
			\WP_CLI::error(
				array() === $offered
					? sprintf( '%s offers no action to run right now. Nothing was changed.', $item )
					: sprintf( '%1$s has no action "%2$s" to run now. It offers --action=%3$s. Nothing was changed.', $item, $action, implode( ' and --action=', array_keys( $offered ) ) )
			);
		}

		$done = $manager->act( $item, $action );

		if ( is_wp_error( $done ) ) {
			\WP_CLI::error( $done->get_error_message() );
		}

		$notes = array_filter( array( (string) ( $done['note'] ?? '' ), (string) ( $done['message'] ?? '' ) ) );

		// A rotation ends sessions, and WP-CLI has none to carry over.
		if ( isset( $done['ended'] ) ) {
			$notes[] = sprintf( '%d sessions signed out. Everybody signs in again.', (int) $done['ended'] );
		}

		foreach ( $notes as $note ) {
			\WP_CLI::line( '  ' . $note );
		}

		\WP_CLI::success( sprintf( 'Done: %1$s, for %2$s.', $offered[ $action ], Items::all()[ $item ]['title'] ) );
	}

	/**
	 * The actions an item offers right now, by key, each with its label.
	 * One the item lists as not available yet is left out.
	 *
	 * @return array<string, string>
	 */
	private static function offered_actions( string $item ): array {
		$declared = Items::all()[ $item ]['actions'] ?? null;
		$offered  = array();

		foreach ( $declared instanceof \Closure ? (array) $declared() : array() as $one ) {
			if ( false !== ( $one['available'] ?? true ) ) {
				$offered[ (string) $one['key'] ] = (string) $one['label'];
			}
		}

		return $offered;
	}

	/**
	 * The settings an applied item would change to, checked by the item's own
	 * validator and compared as the settings import compares them; null when
	 * they are the ones it already runs with, or none were typed; the refusal
	 * when the validator refuses them. Compared as typed, "API.example.com"
	 * against the stored "api.example.com" undid and reapplied the item for
	 * nothing.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>|\WP_Error|null
	 */
	private static function new_settings( string $item, array $options ) {
		$handler = Items::handlers()[ $item ] ?? null;

		if ( array() === $options || null === $handler || ! method_exists( $handler, 'validate' ) ) {
			return null;
		}

		$valid = $handler::validate( $options );

		if ( is_wp_error( $valid ) ) {
			return $valid;
		}

		$here = Manager::instance()->item_state( $item )['options'] ?? array();

		return \BetterShield\Operator\SettingsDocument::same_options( (array) $valid, is_array( $here ) ? $here : array() ) ? null : (array) $valid;
	}

	/**
	 * The options typed for an item, held to the fields it declares (#2084).
	 * Passed on as they were, a misspelled one was dropped by the item's
	 * validator and its default applied instead: `--role=customer` kept the
	 * subscribers out and reported success. And a required option left out
	 * was answered as a bad value of it, which sent the reader to fix the
	 * value they had not typed.
	 *
	 * @param string               $item     The item.
	 * @param array<string, mixed> $options  Everything typed but the command's own flags.
	 * @param bool                 $applying Whether the item is being applied or previewed, rather than undone.
	 */
	private static function check_item_options( string $item, array $options, bool $applying ): void {
		$declared = Items::all()[ $item ];
		$fields   = isset( $declared['fields'] ) ? (array) ( $declared['fields'] )() : array();
		$fields   = array_filter( $fields, static fn( array $field ): bool => empty( $field['screen_only'] ) );
		$keys     = array_map( static fn( array $field ): string => (string) $field['key'], $fields );
		$unknown  = array_values( array_diff( array_map( 'strval', array_keys( $options ) ), $keys ) );

		if ( array() !== $unknown ) {
			$typed = '--' . implode( ', --', $unknown );

			\WP_CLI::error(
				array() === $keys
					? sprintf( '%1$s takes no options, so %2$s would be ignored. Nothing was changed.', $item, $typed )
					: sprintf( '%1$s takes --%2$s, not %3$s. Nothing was changed.', $item, implode( ' and --', $keys ), $typed )
			);
		}

		if ( ! $applying ) {
			return;
		}

		/*
		 * A value outside a field's choices, refused and the choices named.
		 * Left to the validator, `--subdomains=true`, `=1` and `=on` all read
		 * as "this domain only" in silence, and a bad `--mode` was answered
		 * in the screen's words, never naming short or long (#2239).
		 */
		foreach ( $fields as $field ) {
			if ( empty( $field['choices'] ) || ! empty( $field['multiple'] ) || ! array_key_exists( $field['key'], $options ) ) {
				continue;
			}

			$values = array_map( static fn( array $choice ): string => (string) $choice['value'], (array) $field['choices'] );
			$raw    = $options[ $field['key'] ];

			// A bare flag reaches here as true, which is no choice's value.
			if ( true !== $raw && in_array( (string) $raw, $values, true ) ) {
				continue;
			}

			$named = array();
			foreach ( array_diff( $values, array( '' ) ) as $value ) {
				$named[] = '--' . $field['key'] . '=' . $value;
			}

			\WP_CLI::error(
				sprintf(
					'%1$s is not a choice for %2$s. Use %3$s%4$s. Nothing was changed.',
					true === $raw ? '--' . $field['key'] . ' with no value' : '--' . $field['key'] . '=' . (string) $raw,
					$item,
					implode( ' or ', $named ),
					in_array( '', $values, true ) ? ', or leave it out' : ''
				)
			);
		}

		foreach ( $fields as $field ) {
			if ( empty( $field['required'] ) || array_key_exists( 'default', $field ) || array_key_exists( $field['key'], $options ) ) {
				continue;
			}

			$example = (string) ( $field['placeholder'] ?? '' );

			\WP_CLI::error(
				'' === $example
					? sprintf( '%1$s needs --%2$s. Nothing was changed.', $item, $field['key'] )
					: sprintf( '%1$s needs --%2$s, for example --%2$s=%3$s. Nothing was changed.', $item, $field['key'], $example )
			);
		}
	}

	/**
	 * The --format asked for, or the default, refused when it is not one the
	 * command lists (#2084). Help that lists the formats is read by WP-CLI
	 * itself; a command whose help named them in prose took any value and
	 * printed its table, exiting 0 for a script that asked for XML.
	 *
	 * @param array<string, mixed> $assoc_args
	 * @param string[]             $allowed    The listed formats, the default first.
	 */
	private static function format_from( array $assoc_args, array $allowed ): string {
		$format = (string) ( $assoc_args['format'] ?? $allowed[0] );

		if ( ! in_array( $format, $allowed, true ) ) {
			\WP_CLI::error( sprintf( '--format takes %1$s, not "%2$s".', implode( ', ', $allowed ), $format ) );
		}

		return $format;
	}

	/**
	 * A single site has no network for --network or --sites to read, and the
	 * command answered as if the option were not there: "the network-wide
	 * pause was not on", or this site's own log under a flag that said
	 * several sites (#2084).
	 *
	 * @param string $option The option, as typed.
	 */
	private static function refuse_off_network( string $option ): void {
		if ( ! is_multisite() ) {
			\WP_CLI::error( sprintf( '%s works on a multisite network, and this site is not part of one. Nothing was changed.', $option ) );
		}
	}

	/**
	 * A --limit as given, or the default where none was: a whole number from
	 * 1 to the most the list shows. Cast as it was, 0, -1 and "abc" each
	 * printed one entry and exited 0, so a script that passed a bad value
	 * read the site as having done one thing (#1799). Refused, as lockouts
	 * refuses one.
	 *
	 * @param array<string, mixed> $assoc_args
	 */
	private static function limit_from( array $assoc_args, int $default, int $max ): int {
		if ( ! isset( $assoc_args['limit'] ) ) {
			return $default;
		}

		$limit = trim( (string) $assoc_args['limit'] );

		if ( ! ctype_digit( $limit ) || (int) $limit < 1 || (int) $limit > $max ) {
			\WP_CLI::error( sprintf( '--limit takes a whole number from 1 to %d, not "%s".', $max, $limit ) );
		}

		return (int) $limit;
	}

	/**
	 * A CSV export carries every matching row, so a --limit given with it was
	 * dropped without a word, whatever its value: a script asking for ten
	 * rows got all of them and exited 0.
	 *
	 * @param array<string, mixed> $assoc_args
	 * @param string               $narrow     What narrows the export instead.
	 */
	private static function refuse_limit_with_export( array $assoc_args, string $narrow ): void {
		if ( isset( $assoc_args['limit'] ) ) {
			\WP_CLI::error( sprintf( '--limit sets a page, and --format=csv exports every matching row. Leave --limit out, or narrow the export with %s.', $narrow ) );
		}
	}

	/**
	 * Shows the activity log, newest first.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<number>]
	 * : How many entries. Default 40, at most 500.
	 *
	 * [--area=<area>]
	 * : One area only: access, exposure, server, configuration, extensions, plugin.
	 *
	 * [--search=<text>]
	 * : Match who did it, what it was done to, or the event's name.
	 *
	 * [--actor=<token>]
	 * : One actor only, as `user:<id>` or `type:system`, `type:anonymous`.
	 *
	 * [--from=<date>]
	 * : On or after this day, YYYY-MM-DD, read in the site's timezone.
	 *
	 * [--to=<date>]
	 * : On or before this day, YYYY-MM-DD, read in the site's timezone.
	 *
	 * [--sites=<ids>]
	 * : On a network only. Comma-separated site ids, or `all` for every site.
	 *   Each row then names the site it belongs to. Without this the command
	 *   reads the log of the site it runs against, as it always has.
	 *
	 * [--format=<format>]
	 * : Output format. csv exports every matching row rather than one page.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield activity
	 *     wp bettershield activity --area=access --limit=100
	 *     wp bettershield activity --search=hardening --format=json
	 *     wp bettershield activity --from=2026-08-01 --to=2026-08-15 --format=csv > august.csv
	 *     wp bettershield activity --actor=user:1
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function activity( array $args, array $assoc_args ): void {
		self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );

		$filters = array(
			'area'   => (string) ( $assoc_args['area'] ?? '' ),
			'search' => (string) ( $assoc_args['search'] ?? '' ),
			'actor'  => (string) ( $assoc_args['actor'] ?? '' ),
			'from'   => (string) ( $assoc_args['from'] ?? '' ),
			'to'     => (string) ( $assoc_args['to'] ?? '' ),
		);

		/*
		 * The checks the REST route runs before the same read. A filter the
		 * query cannot use answers it with nothing, and an empty table or a
		 * CSV of only its header, exiting 0, reads as "nothing happened"
		 * rather than as a mistyped filter.
		 */
		if ( ! Query::valid_filters( $filters ) ) {
			\WP_CLI::error(
				sprintf(
					'Use an area this log knows (%s) and calendar dates as YYYY-MM-DD, with --from no later than --to.',
					implode( ', ', array_keys( \BetterShield\Support\Areas::all() ) )
				)
			);
		}

		if ( '' !== trim( $filters['actor'] ) && ! Query::is_actor_token( $filters['actor'] ) ) {
			\WP_CLI::error( 'Name the actor as user:<id> or type:<kind>, for example --actor=user:1 or --actor=type:system.' );
		}

		/*
		 * Reading across a network is offered here without a further check: a
		 * shell that can run WP-CLI against this install already reaches every
		 * site's tables directly, so a capability test would be a sign rather
		 * than a gate. On a single site the option means nothing.
		 */
		$across = trim( (string) ( $assoc_args['sites'] ?? '' ) );

		if ( isset( $assoc_args['sites'] ) ) {
			self::refuse_off_network( '--sites' );
		}

		if ( '' !== $across && is_multisite() ) {
			$filters['network'] = true;
			$filters['sites']   = 'all' === $across ? array() : $this->network_sites( $across );
		}

		$format = (string) ( $assoc_args['format'] ?? 'table' );

		// The export is the same read through the same filters, written to
		// stdout so it can be redirected to a file or piped onward.
		if ( 'csv' === $format ) {
			self::refuse_limit_with_export( $assoc_args, '--from/--to' );

			$export = Query::export( $filters );

			echo $export['csv']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV to stdout; escaping for HTML would corrupt the file.

			if ( ! $export['complete'] ) {
				\WP_CLI::warning( 'More rows matched than this export carries. Narrow --from/--to and run it again.' );
			}

			return;
		}

		$page = Query::page(
			array_merge(
				$filters,
				array( 'per_page' => self::limit_from( $assoc_args, Query::PER_PAGE, 500 ) )
			)
		);

		$fields = array( 'id', 'occurred_at', 'type', 'label', 'severity', 'actor_type', 'actor_label', 'object_type', 'object_id', 'entry_path', 'context' );

		if ( isset( $filters['network'] ) ) {
			$fields[] = 'site_id';
			$fields[] = 'site_label';
		}

		if ( 'json' === $format ) {
			\WP_CLI\Utils\format_items( 'json', $page['events'], $fields );
			return;
		}

		$rows    = array();
		$columns = array( 'when', 'event', 'severity', 'who', 'what', 'via' );

		if ( isset( $filters['network'] ) ) {
			$columns[] = 'site';
		}

		foreach ( $page['events'] as $event ) {
			$row = array(
				'when'     => self::site_time( (string) $event['occurred_at'] ),
				'event'    => $event['label'],
				'severity' => $event['severity'],
				'who'      => null !== $event['actor_label'] ? $event['actor_label'] : $event['actor_type'],
				'what'     => trim( (string) $event['object_type'] . ' ' . (string) $event['object_id'] ),
				'via'      => $event['entry_path'],
			);

			if ( isset( $event['site_label'] ) ) {
				$row['site'] = (string) $event['site_label'];
			}

			$rows[] = $row;
		}

		\WP_CLI\Utils\format_items( $format, $rows, $columns );
	}

	/**
	 * A stored UTC moment as a table shows it: in the site's time zone, the
	 * zone in which --from and --to are read, with its offset. The table cut
	 * the UTC marker off, so on a site far from UTC a row inside the asked-for
	 * day read as the day before. JSON and CSV keep UTC, and say so.
	 */
	private static function site_time( string $utc ): string {
		$moment = strtotime( $utc );

		return false === $moment ? $utc : wp_date( 'Y-m-d H:i:s P', $moment );
	}

	/**
	 * The site ids `--sites` names, each one checked as the REST route checks
	 * it. Cast to numbers, a word became no site at all, which reads as every
	 * site; an id not on this network gave an empty table and exit 0, and a
	 * deleted site's id database errors.
	 *
	 * @return int[]
	 */
	private function network_sites( string $across ): array {
		$ids = array();

		foreach ( array_filter( array_map( 'trim', explode( ',', $across ) ), 'strlen' ) as $token ) {
			if ( ! ctype_digit( $token ) ) {
				\WP_CLI::error( sprintf( '"%s" is not a site id. Name sites by their numeric ids, comma-separated, or use --sites=all.', $token ) );
			}

			$site = get_site( (int) $token );

			if ( null === $site || (int) $site->network_id !== get_current_network_id() || '1' === (string) $site->deleted ) {
				\WP_CLI::error( sprintf( 'Site %d is not on this network.', (int) $token ) );
			}

			$ids[] = (int) $token;
		}

		if ( array() === $ids ) {
			\WP_CLI::error( 'Name the sites by their numeric ids, comma-separated, or use --sites=all.' );
		}

		return array_values( array_unique( $ids ) );
	}

	/**
	 * Shows what agents did on this site, newest first.
	 *
	 * Every ability invocation, whichever plugin registered the ability and
	 * whichever door the call came through. The refusals are the rows worth
	 * reading: `--outcome=permission_denied` is the one filter this command
	 * mainly exists for.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<number>]
	 * : How many entries. Default 40, at most 200. Does not apply to csv,
	 * which exports every matching row.
	 *
	 * [--outcome=<outcome>]
	 * : One outcome only: completed, permission_denied, input_invalid,
	 * input_not_normalizable, output_invalid, short_circuited, failed, unknown.
	 *
	 * [--ability=<name>]
	 * : One ability, by its exact name.
	 *
	 * [--namespace=<prefix>]
	 * : The ability name's namespace prefix. A naming convention, not a record
	 * of which plugin registered it — WordPress does not keep that.
	 *
	 * [--entry-path=<path>]
	 * : One door only: rest, mcp (a connected assistant), wp-cli, php.
	 *
	 * [--format=<format>]
	 * : Output format. csv exports every matching row rather than one page.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield agents
	 *     wp bettershield agents --outcome=permission_denied
	 *     wp bettershield agents --namespace=security-ninja --limit=100
	 *     wp bettershield agents --entry-path=rest --format=json
	 *     wp bettershield agents --format=csv > agents.csv
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function agents( array $args, array $assoc_args ): void {
		$filters = array(
			'outcome'    => (string) ( $assoc_args['outcome'] ?? '' ),
			'ability'    => (string) ( $assoc_args['ability'] ?? '' ),
			'namespace'  => (string) ( $assoc_args['namespace'] ?? '' ),
			'entry_path' => (string) ( $assoc_args['entry-path'] ?? '' ),
		);

		// An outcome that is not one the record can hold is the request being
		// wrong, not "no filter": answered as every row, a typo in the one
		// filter this command mainly exists for reads as a filtered count.
		if ( '' !== $filters['outcome'] && ! in_array( $filters['outcome'], \BetterShield\Agents\Capture::OUTCOMES, true ) ) {
			\WP_CLI::error( sprintf( 'Use one of: %s.', implode( ', ', \BetterShield\Agents\Capture::OUTCOMES ) ) );
		}

		// The same for the door: --entry-path=REST printed a header and
		// nothing, which reads as "no agent activity".
		if ( '' !== $filters['entry_path'] && ! in_array( $filters['entry_path'], \BetterShield\Events\Writer::ENTRIES, true ) ) {
			\WP_CLI::error( sprintf( 'Use one of: %s.', implode( ', ', \BetterShield\Events\Writer::ENTRIES ) ) );
		}

		$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );

		if ( 'csv' === $format ) {
			self::refuse_limit_with_export( $assoc_args, 'the filters' );
		}

		$per_page = self::limit_from( $assoc_args, \BetterShield\Agents\Invocations::PER_PAGE, 200 );

		// Below the WordPress that records agent activity there is nothing to
		// list, but the options are still checked first: --limit=0 was taken
		// there and exited 0.
		if ( ! \BetterShield\Agents\Capture::is_available() ) {
			\WP_CLI::warning( 'Recording agent activity needs WordPress ' . \BetterShield\Agents\Capture::REQUIRES_WP . '. Nothing has been recorded on this site.' );

			return;
		}

		if ( ! \BetterShield\Agents\Capture::is_enabled() ) {
			// Said before the rows rather than after them: an empty list read
			// without this reads as "nothing happened", which is a different
			// statement and not the true one.
			\WP_CLI::warning( 'Recording agent activity is switched off. Anything below was recorded before it was switched off.' );
		}

		// The export is the same read through the same filters, walked to the
		// end rather than stopped at a page, and written to stdout so it can
		// be redirected to a file or piped onward. Only the CSV walks: JSON
		// and the table are a person's read of a page, and --limit is theirs.
		if ( 'csv' === $format ) {
			$export = \BetterShield\Agents\Invocations::export( $filters );

			echo $export['csv']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV to stdout; escaping for HTML would corrupt the file.

			if ( ! $export['complete'] ) {
				\WP_CLI::warning( 'More invocations matched than this export carries. Narrow the filters and run it again.' );
			}

			return;
		}

		$page = \BetterShield\Agents\Invocations::page(
			array_merge(
				$filters,
				array( 'per_page' => $per_page )
			)
		);

		if ( 'json' === $format ) {
			\WP_CLI\Utils\format_items(
				'json',
				$page['invocations'],
				array( 'id', 'invoked_at', 'ability', 'namespace', 'entry_path', 'user_id', 'user_label', 'outcome', 'error_code', 'input_digest', 'duration_ms' )
			);

			return;
		}

		$rows = array();
		foreach ( $page['invocations'] as $invocation ) {
			$rows[] = array(
				'when'    => self::site_time( (string) $invocation['invoked_at'] ),
				'ability' => $invocation['ability'],
				'who'     => $invocation['user_label'],
				'via'     => $invocation['entry_path'],
				'outcome' => null === $invocation['error_code'] ? $invocation['outcome'] : $invocation['outcome'] . ':' . $invocation['error_code'],
			);
		}

		\WP_CLI\Utils\format_items( $format, $rows, array( 'when', 'ability', 'who', 'via', 'outcome' ) );
	}

	/**
	 * Pauses every protection for a while, so a locked-out owner can sign in.
	 *
	 * Runs without --user on purpose: this is for the moment the site's
	 * administrator cannot get in. Nothing is deactivated and no setting is
	 * lost; the standard sign-in page answers again for the duration.
	 *
	 * ## OPTIONS
	 *
	 * [--hours=<hours>]
	 * : How long, in whole hours from 1 to 24. Default 1.
	 *
	 * [--end]
	 * : End safe mode now instead, re-arming every protection.
	 *
	 * [--network]
	 * : With --end, end the network-wide pause the network's recovery link raised, on every site.
	 *
	 * [--new-link]
	 * : Also issue a fresh recovery link and print it once. The previous link stops working.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield recover
	 *     wp bettershield recover --hours=4 --new-link
	 *     wp bettershield recover --end
	 *     wp bettershield recover --end --network
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function recover( array $args, array $assoc_args ): void {
		/*
		 * A flag that does nothing is refused before anything changes (#1837).
		 * Ignored, --network without --end paused every protection on this
		 * site and reported success, and --end with --hours or --new-link
		 * ended safe mode without the link or the length asked for.
		 */
		if ( isset( $assoc_args['network'] ) ) {
			self::refuse_off_network( '--network' );
		}

		if ( isset( $assoc_args['network'] ) && ! isset( $assoc_args['end'] ) ) {
			\WP_CLI::error( '--network works only with --end, to end the network-wide pause. Nothing was changed.' );
		}

		if ( isset( $assoc_args['end'] ) && ( isset( $assoc_args['hours'] ) || isset( $assoc_args['new-link'] ) ) ) {
			\WP_CLI::error( '--end cannot be combined with --hours or --new-link. Nothing was changed.' );
		}

		if ( isset( $assoc_args['end'] ) ) {
			// The network's pause, asked for by name.
			if ( isset( $assoc_args['network'] ) ) {
				if ( ! SafeMode::is_network_active() ) {
					\WP_CLI::success( 'The network-wide pause was not on. Nothing to end.' );
					return;
				}

				SafeMode::end_network( 'wp-cli' );
				\WP_CLI::success(
					SafeMode::is_active()
						? 'The network-wide pause ended. This site is still in its own safe mode: end it with `wp bettershield recover --end`.'
						: 'The network-wide pause ended. Every protection is armed again on every site.'
				);
				return;
			}

			if ( ! SafeMode::is_site_active() ) {
				// Only the network's pause running: ending this site's own
				// would change nothing, and saying it ended would be untrue.
				if ( SafeMode::is_network_active() ) {
					\WP_CLI::error( 'Safe mode here comes from the network-wide pause, which ending this site\'s own does not touch. End it with `wp bettershield recover --end --network`.' );
				}

				\WP_CLI::success( 'Safe mode was not on. Nothing to end.' );
				return;
			}

			SafeMode::end( 'wp-cli' );
			\WP_CLI::success(
				SafeMode::is_network_active()
					? 'Safe mode on this site ended, and the network-wide pause is still on: end it with `wp bettershield recover --end --network`.'
					: 'Safe mode ended. Every protection is armed again.'
			);
			return;
		}

		// A whole number, as typed: cast, 2.9 became 2 without a word.
		$typed = isset( $assoc_args['hours'] ) ? trim( (string) $assoc_args['hours'] ) : '1';
		$hours = 1 === preg_match( '/^\d{1,2}$/', $typed ) ? (int) $typed : 0;
		if ( $hours < 1 || $hours > 24 ) {
			\WP_CLI::error( 'Hours must be a whole number between 1 and 24. Nothing was changed.' );
		}

		/*
		 * Already on: a second run said nothing of it, quietly replaced the
		 * end time, shorter as readily as longer, and logged a second "Safe
		 * mode started" that read as another pause (#2180). Said, and left
		 * as it is; a fresh link alone may still be asked for.
		 */
		$until = SafeMode::is_site_active() ? SafeMode::until() : null;

		if ( null !== $until ) {
			$when = wp_date( 'Y-m-d H:i P', $until );

			if ( ! isset( $assoc_args['new-link'] ) || isset( $assoc_args['hours'] ) ) {
				\WP_CLI::error( sprintf( 'Safe mode is already on until %s. Nothing was changed. To change how long, end it with `wp bettershield recover --end` and start it again.', $when ) );
			}

			\WP_CLI::line( sprintf( 'Safe mode is already on until %s, and was left as it is.', $when ) );
		} else {
			$this->enter_safe_mode( $hours );
		}

		if ( isset( $assoc_args['new-link'] ) ) {
			/*
			 * Printed once, to the operator's terminal; only its hash is
			 * stored. And mailed to the owner as every other way of issuing
			 * one does: the link in the "keep this email" message stopped
			 * working here and nobody was told, so the owner's way back in
			 * failed exactly when they were locked out (#2178).
			 */
			$url  = null;
			$sent = RecoveryLink::issue_and_mail( $url );

			if ( null === $sent ) {
				\WP_CLI::error( 'The recovery link could not be stored, so none was issued; the previous one still stands.' );
			}

			$to = (string) get_option( 'admin_email' );

			\WP_CLI::line( 'New recovery link (the previous one no longer works, including the one in any earlier email; keep this away from the site):' );
			\WP_CLI::line( (string) $url );
			\WP_CLI::line( RecoveryLink::expiry_sentence( RecoveryLink::expires_at() ) );

			if ( $sent ) {
				\WP_CLI::line( sprintf( 'Emailed to %s as the link to keep.', $to ) );
			} else {
				\WP_CLI::warning( sprintf( 'The email to %s was not accepted for sending, so the owner still holds the old link, which no longer works. Give them this one.', $to ) );
			}
		}
	}

	/**
	 * Start safe mode for a number of hours, and say what that does.
	 */
	private function enter_safe_mode( int $hours ): void {
		SafeMode::enter( $hours * HOUR_IN_SECONDS, 'wp-cli' );

		\WP_CLI::success(
			sprintf(
				'Safe mode is on for %s: every protection is paused and every setting is kept. %s End it early with `wp bettershield recover --end`.',
				self::counted( $hours, '%d hour', '%d hours' ),
				self::sign_in_answers()
			)
		);

		// Safe mode pauses this plugin alone, so say what it can't lift.
		$limiters = array_filter( \BetterShield\Onboarding\Coexistence::active(), static fn( array $plugin ): bool => in_array( 'login_limits', $plugin['jobs'], true ) );

		foreach ( $limiters as $file => $plugin ) {
			\WP_CLI::warning( sprintf( '%1$s also limits sign-ins, and safe mode does not pause it, so a lockout from %1$s still applies. Wait for it to end, clear it in that plugin, or switch it off with `wp plugin deactivate %2$s`.', $plugin['name'], dirname( (string) $file ) ) );
		}

		// Safe mode stands a lockdown down only while it lasts. Saying every
		// protection is paused, and nothing more, left an operator expecting
		// the site open again afterwards.
		if ( Lockdown::state()['active'] ) {
			\WP_CLI::warning( 'A site lockdown is on. It is paused while safe mode lasts and comes back when safe mode ends, unless you lift it: `wp bettershield lockdown off --user=<login>`.' );
		}
	}

	/**
	 * Where sign-in answers while safe mode lasts, checked rather than
	 * assumed: another plugin can filter wp_login_url() to an address that is
	 * not there, and move wp-login.php away as well. Said without a check
	 * where the site can't reach itself.
	 */
	private static function sign_in_answers(): string {
		$tried = array_values( array_unique( array_merge( array( wp_login_url() ), \BetterShield\Onboarding\Coexistence::moved_sign_in_addresses(), array( site_url( 'wp-login.php' ) ) ) ) );

		foreach ( $tried as $url ) {
			$response = \BetterShield\Support\Http::same_site_at(
				$url,
				array(
					'timeout'     => 3,
					'redirection' => 0,
				)
			);

			if ( is_wp_error( $response ) ) {
				return sprintf( 'The sign-in page should answer at %s. This could not be checked from here.', wp_login_url() );
			}

			if ( 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				return sprintf( 'Sign in at %s, which answers now.', $url );
			}
		}

		return sprintf( 'None of these sign-in addresses answered: %s. Another plugin may have moved the page, so check its settings.', implode( ', ', $tried ) );
	}

	/**
	 * Reads, turns on or lifts the site lockdown.
	 *
	 * A lockdown refuses every sign-in but the accounts that manage the site,
	 * stops new accounts, and freezes installing, updating and editing code
	 * from the dashboard. The recovery link and safe mode still outrank it.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : What to do.
	 * ---
	 * default: status
	 * options:
	 *   - status
	 *   - on
	 *   - off
	 * ---
	 *
	 * `status` needs no account. `on` and `off` change the site, so they run
	 * as someone: add --user=<login> naming an account that can manage
	 * BetterShield. From here there is no browser session to keep, so `on`
	 * signs out every dashboard session, your own included.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield lockdown
	 *     wp bettershield lockdown on --user=admin
	 *     wp bettershield lockdown off --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function lockdown( array $args, array $assoc_args ): void {
		$action = $args[0] ?? 'status';

		if ( 'status' === $action ) {
			$state = Lockdown::state();

			if ( ! $state['active'] ) {
				\WP_CLI::line( 'No lockdown is on.' );

				return;
			}

			\WP_CLI::line(
				sprintf(
					'A lockdown has been on since %s.%s',
					// With its offset, as `activity` prints a time: a bare
					// local time could be read as UTC (#2181).
					null !== $state['since'] ? wp_date( 'Y-m-d H:i P', $state['since'] ) : 'an unknown time',
					SafeMode::is_active() ? ' It is paused while safe mode lasts, and comes back when safe mode ends.' : ''
				)
			);

			return;
		}

		if ( ! in_array( $action, array( 'on', 'off' ), true ) ) {
			\WP_CLI::error( 'Say status, on or off.' );
		}

		$this->require_manage();

		if ( ( 'on' === $action ) === Lockdown::state()['active'] ) {
			\WP_CLI::success( 'on' === $action ? 'A lockdown was already on. Nothing changed.' : 'No lockdown was on. Nothing changed.' );

			return;
		}

		$result = 'on' === $action ? Lockdown::enter( get_current_user_id() ) : Lockdown::leave( 'wp-cli' );

		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}

		\WP_CLI::success(
			'on' === $action
				? 'The site is locked down, and every dashboard session was signed out. Lift it with `wp bettershield lockdown off' . self::as_someone() . '`.'
				: 'The lockdown is lifted.'
		);
	}

	/**
	 * Exports the plugin's settings as JSON, or imports a settings document.
	 *
	 * An import is a dry run unless --apply is given: it prints what would
	 * change and changes nothing. With --apply it goes through the same
	 * per-item path as the dashboard — every conflict probe, every validator.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : export or import.
	 * ---
	 * options:
	 *   - export
	 *   - import
	 * ---
	 *
	 * [<file>]
	 * : The document: read for import, written for export. Either this or
	 * --file, whichever suits the command line being written.
	 *
	 * [--file=<path>]
	 * : The same path as the positional argument. With neither, export prints
	 * the document to stdout so it can be piped onward.
	 *
	 * [--apply]
	 * : For import, make the changes. Without it, only the plan is shown.
	 *
	 * [--force]
	 * : For an import that changes how people sign in, go ahead although the
	 * recovery check did not pass. Recorded in the activity log.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield settings export
	 *     wp bettershield settings export posture.json
	 *     wp bettershield settings export --file=posture.json
	 *     wp bettershield settings import posture.json
	 *     wp bettershield settings import posture.json --apply --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function settings( array $args, array $assoc_args ): void {
		$action = (string) ( $args[0] ?? '' );

		/*
		 * One path, read the same way for both actions. WP-CLI merges every
		 * action's parameters into a single synopsis, so the help text offers
		 * both forms whatever the code does — and an export that dropped the
		 * positional argument wrote no file and said nothing about it, which
		 * is the one outcome a snapshot taken before a risky change must not
		 * have.
		 */
		$path = (string) ( $assoc_args['file'] ?? $args[1] ?? '' );

		if ( 'export' === $action ) {
			$json = (string) wp_json_encode( SettingsDocument::export(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

			if ( '' !== $path ) {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- an operator's own file, at the operator's own request; the line below says what happened without a second, rawer copy of it.
				if ( false === @file_put_contents( $path, $json . "\n" ) ) {
					\WP_CLI::error( sprintf( 'Could not write %s.', $path ) );
				}
				\WP_CLI::success( sprintf( 'Settings written to %s.', $path ) );
				return;
			}

			// No path at all still prints the document, which is what a pipe
			// on the other end of this command is reading.
			\WP_CLI::line( $json );
			return;
		}

		if ( 'import' !== $action ) {
			\WP_CLI::error( 'Say which: `settings export` or `settings import <file>`.' );
		}

		if ( '' === $path || ! is_readable( $path ) ) {
			\WP_CLI::error( 'Name a readable settings document to import.' );
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_file_get_contents -- an operator's own file, named on the command line; the error below says what happened.
		$document = json_decode( (string) @file_get_contents( $path ), true );
		if ( ! is_array( $document ) ) {
			\WP_CLI::error( 'That file is not a JSON document.' );
		}

		$apply = isset( $assoc_args['apply'] );

		if ( $apply ) {
			$this->require_manage();
			$plan = SettingsDocument::apply( $document, isset( $assoc_args['force'] ), 'cli' );

			// The same pre-flight as `harden`, with --force as its second
			// confirmation.
			if ( is_wp_error( $plan ) && 'bettershield_recovery_preflight' === $plan->get_error_code() ) {
				\WP_CLI::error( $plan->get_error_message() . ' Nothing was changed. Add --force to the same command to go ahead anyway; that is recorded in the activity log.' );
			}
		} else {
			$plan = SettingsDocument::plan( $document );
		}

		if ( is_wp_error( $plan ) ) {
			\WP_CLI::error( $plan->get_error_message() );
		}

		$this->print_plan( $plan );

		/*
		 * Sections the document named that this site refused or does not
		 * know. They were in the tables above and nowhere in the summary, so
		 * a document refused from top to bottom read as a success, and a
		 * deploy script saw exit 0.
		 */
		$refused = self::refused( $plan );
		$named   = array() === $refused ? '' : sprintf( ' %d section(s) refused: %s.', count( $refused ), implode( ', ', $refused ) );

		if ( ! $apply ) {
			if ( '' !== $named ) {
				\WP_CLI::warning( sprintf( 'Dry run: %d change(s) planned, none made.', $plan['changes'] ) . $named . ' The note on each says why.' );
				return;
			}

			\WP_CLI::success(
				0 === $plan['changes']
					? 'Nothing to change: this site already matches the document.'
					: sprintf( 'Dry run: %d change(s) planned, none made. Add --apply (and --user) to make them.', $plan['changes'] )
			);
			return;
		}

		$counts = $plan['counts'];
		$line   = sprintf(
			'Import finished: %d applied, %d undone, %d setting(s) changed, %d failed.',
			$counts['applied'],
			$counts['reverted'],
			$counts['settings'],
			$counts['failed']
		) . $named;

		if ( $counts['failed'] > 0 || '' !== $named ) {
			\WP_CLI::warning( $line );

			// A script reads the exit code, not the sentence.
			\WP_CLI::halt( 1 );
		}

		\WP_CLI::success( $line );
	}

	/**
	 * The parts of a plan this site refused or does not know, by name.
	 *
	 * @param array<string, mixed> $plan
	 * @return string[]
	 */
	private static function refused( array $plan ): array {
		$names = array();

		foreach ( array( 'hardening' => 'item', 'settings' => 'section' ) as $part => $key ) {
			foreach ( (array) ( $plan[ $part ] ?? array() ) as $row ) {
				if ( in_array( $row['action'] ?? '', array( 'invalid', 'unknown' ), true ) ) {
					$names[] = (string) ( $row[ $key ] ?? '' );
				}
			}
		}

		return $names;
	}

	/**
	 * Shows one account's sign-in methods and sessions, or changes them.
	 *
	 * Through the same services and guards as the dashboard: the account must
	 * be one the --user account may edit, your own is changed on your own
	 * profile, and each change lands in the activity log as having come
	 * through WP-CLI. Taking off a second factor or a passkey needs --yes,
	 * is recorded high, and emails the account, because it can't be put
	 * back: the person sets it up again. A new-password requirement can be
	 * lifted with --lift.
	 *
	 * ## OPTIONS
	 *
	 * <args>...
	 * : An account (login, email or id) to show it, or one of:
	 *   `two-factor reset <account>`, `passkey remove <account> <passkey id|all>`,
	 *   `sessions end <account>`, `require-new-password <account>`.
	 *
	 * [--yes]
	 * : Confirm taking off a second factor or a passkey.
	 *
	 * [--lift]
	 * : With require-new-password, lift the requirement instead.
	 *
	 * [--format=<format>]
	 * : Output format for showing an account.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield account jane
	 *     wp bettershield account jane --format=json
	 *     wp bettershield account two-factor reset jane --yes --user=admin
	 *     wp bettershield account passkey remove jane 12 --yes --user=admin
	 *     wp bettershield account passkey remove jane all --yes --user=admin
	 *     wp bettershield account sessions end jane --user=admin
	 *     wp bettershield account require-new-password jane --user=admin
	 *     wp bettershield account require-new-password jane --lift --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function account( array $args, array $assoc_args ): void {
		$action = (string) ( $args[0] ?? '' );

		if ( ! in_array( $action, array( 'two-factor', 'passkey', 'sessions', 'require-new-password' ), true ) ) {
			if ( count( $args ) > 1 ) {
				\WP_CLI::error( sprintf( 'Unknown change "%s". Use two-factor reset, passkey remove, sessions end or require-new-password.', implode( ' ', $args ) ) );
			}

			$this->show_account( self::account_named( $action ), self::format_from( $assoc_args, array( 'table', 'json' ) ) );
			return;
		}

		// The verb after the area, where the area has one.
		$verbs = array(
			'two-factor' => 'reset',
			'passkey'    => 'remove',
			'sessions'   => 'end',
		);

		if ( isset( $verbs[ $action ] ) && $verbs[ $action ] !== ( $args[1] ?? '' ) ) {
			\WP_CLI::error( sprintf( 'Say what to do: `wp bettershield account %1$s %2$s <account>%3$s`.', $action, $verbs[ $action ], 'passkey' === $action ? ' <passkey id|all>' : '' ) );
		}

		$target = self::account_named( (string) ( $args[ isset( $verbs[ $action ] ) ? 2 : 1 ] ?? '' ) );
		$this->may_change_account( $target );

		if ( 'two-factor' === $action ) {
			if ( ! \BetterShield\TwoFactor\Manager::instance()->enabled( $target->ID ) ) {
				\WP_CLI::error( sprintf( 'Two-factor is not on for %s, so nothing was changed.', $target->user_login ) );
			}

			self::require_yes( $assoc_args, sprintf( 'This turns off two-factor for %s. It can’t be put back: they set it up again on their profile.', $target->user_login ) );
			\BetterShield\TwoFactor\Manager::instance()->reset_from_terminal( $target->ID );
			\WP_CLI::success( sprintf( 'Two-factor is off for %s, and their sessions were ended. It can’t be put back: they set it up again on their profile. They will get an email, and the activity log records it.', $target->user_login ) );
			return;
		}

		if ( 'passkey' === $action ) {
			$this->remove_passkeys( $target, (string) ( $args[3] ?? '' ), $assoc_args );
			return;
		}

		if ( 'sessions' === $action ) {
			$ended = \BetterShield\Login\Sessions::instance()->end_for_user( $target->ID );
			\WP_CLI::success( sprintf( $ended['network_wide'] ? 'Ended every session %s had on every site of this network. Recorded in the activity log.' : 'Ended every session %s had. Recorded in the activity log.', $target->user_login ) );
			return;
		}

		$this->require_new_password( $target, isset( $assoc_args['lift'] ) );
	}

	/**
	 * One account's sign-in methods and sessions. Addresses are shown as
	 * their network, never in full, as the screens show them.
	 */
	private function show_account( \WP_User $user, string $format ): void {
		$status   = \BetterShield\TwoFactor\Manager::instance()->status( $user->ID );
		$passkeys = \BetterShield\Passkeys\Store::for_user( $user->ID );
		$tokens   = get_user_meta( $user->ID, 'session_tokens', true );
		$sessions = array();

		foreach ( is_array( $tokens ) ? $tokens : array() as $session ) {
			if ( ! is_array( $session ) || (int) ( $session['expiration'] ?? 0 ) < time() ) {
				continue;
			}

			$seen       = \BetterShield\Login\Sessions::last_seen( $session );
			$sessions[] = array(
				'network' => \BetterShield\Login\Sessions::network_label( $session ),
				'browser' => \BetterShield\Login\Sessions::device_label( (string) ( $session['ua'] ?? '' ) ),
				'started' => 'table' === $format ? self::site_time( gmdate( 'Y-m-d H:i:s', (int) ( $session['login'] ?? 0 ) ) ) : gmdate( 'c', (int) ( $session['login'] ?? 0 ) ),
				'seen'    => 0 === $seen ? '' : ( 'table' === $format ? self::site_time( gmdate( 'Y-m-d H:i:s', $seen ) ) : gmdate( 'c', $seen ) ),
			);
		}

		$last = (int) get_user_meta( $user->ID, \BetterShield\Audit\Dormant::META, true );
		$view = array(
			'account'              => $user->user_login,
			'id'                   => $user->ID,
			'two_factor'           => $status['enabled'] ? 'on' : ( $status['pending'] ? 'being set up' : 'off' ),
			'backup_codes_left'    => $status['backup_remaining'],
			'new_password_required' => \BetterShield\Remediation\PasswordHold::has( $user->ID ),
			'last_sign_in'         => 0 === $last ? '' : ( 'table' === $format ? self::site_time( gmdate( 'Y-m-d H:i:s', $last ) ) : gmdate( 'c', $last ) ),
			'passkeys'             => array_map(
				static fn( array $key ): array => array(
					'id'        => $key['id'],
					'label'     => $key['label'],
					'last_used' => self::moment( (string) ( $key['last_used_at'] ?? '' ), $format ),
				),
				$passkeys
			),
			'sessions'             => $sessions,
		);

		if ( 'json' === $format ) {
			\WP_CLI::line( (string) wp_json_encode( $view ) );
			return;
		}

		$rows = array();

		foreach ( array( 'account', 'id', 'two_factor', 'backup_codes_left', 'new_password_required', 'last_sign_in' ) as $field ) {
			$value  = $view[ $field ];
			$rows[] = array(
				'field' => $field,
				'value' => is_bool( $value ) ? ( $value ? 'yes' : 'no' ) : ( '' === $value ? '-' : (string) $value ),
			);
		}

		$this->print_rows( 'table', $rows, array( 'field', 'value' ) );
		\WP_CLI::line( '' );
		\WP_CLI::line( array() === $view['passkeys'] ? 'Passkeys: none.' : 'Passkeys:' );

		if ( array() !== $view['passkeys'] ) {
			$this->print_rows( 'table', $view['passkeys'], array( 'id', 'label', 'last_used' ) );
		}

		\WP_CLI::line( '' );
		\WP_CLI::line( array() === $sessions ? 'Sessions: none open.' : 'Sessions:' );

		if ( array() !== $sessions ) {
			$this->print_rows( 'table', $sessions, array( 'network', 'browser', 'started', 'seen' ) );
		}
	}

	/**
	 * A stored moment as the rest of the account view says one: the site's
	 * own time in a table, ISO 8601 in JSON, nothing when there is none.
	 */
	private static function moment( string $stored, string $format ): string {
		$at = '' === $stored ? false : strtotime( $stored );

		if ( false === $at ) {
			return '';
		}

		return 'table' === $format ? self::site_time( gmdate( 'Y-m-d H:i:s', $at ) ) : gmdate( 'c', $at );
	}

	/** The account a login, email or id names, or an error that says so. */
	private static function account_named( string $name ): \WP_User {
		if ( '' === $name ) {
			\WP_CLI::error( 'Name an account by its login, email or id.' );
		}

		$user = ctype_digit( $name ) ? get_user_by( 'id', (int) $name ) : ( is_email( $name ) ? get_user_by( 'email', $name ) : get_user_by( 'login', $name ) );

		// On a network, an account of another site is no account of this one.
		if ( ! $user instanceof \WP_User || ( is_multisite() && ! is_user_member_of_blog( $user->ID ) && ! is_super_admin( $user->ID ) ) ) {
			\WP_CLI::error( sprintf( 'No account "%s" on this site.', $name ) );
		}

		return $user;
	}

	/**
	 * The dashboard's guards for changing somebody else's account: a --user
	 * that manages this plugin and may edit that account, and never your own,
	 * which you change on your own profile.
	 */
	private function may_change_account( \WP_User $target ): void {
		$this->require_manage();

		if ( get_current_user_id() === $target->ID ) {
			\WP_CLI::error( 'That is the account named with --user. Change your own sign-in methods on your own profile. Nothing was changed.' );
		}

		if ( ! current_user_can( 'edit_user', $target->ID ) ) {
			\WP_CLI::error( sprintf( 'The account named with --user cannot edit %s. Nothing was changed.', $target->user_login ) );
		}
	}

	/**
	 * Refuse a change that can't be undone unless --yes was given.
	 *
	 * @param array<string, mixed> $assoc_args
	 */
	private static function require_yes( array $assoc_args, string $what ): void {
		if ( ! isset( $assoc_args['yes'] ) ) {
			\WP_CLI::error( $what . ' Add --yes to go ahead. Nothing was changed.' );
		}
	}

	/**
	 * Remove one passkey, or every one, from somebody else's account.
	 *
	 * @param array<string, mixed> $assoc_args
	 */
	private function remove_passkeys( \WP_User $target, string $which, array $assoc_args ): void {
		// Where a network keeps one table of passkeys for every site, they
		// come off every site at once: the network's decision.
		if ( ! \BetterShield\Rest\PasskeyController::may_remove_across_sites() ) {
			\WP_CLI::error( 'Passkeys work on every site in this network, so only a network administrator can remove them. Name one with --user. Nothing was changed.' );
		}

		$keys = \BetterShield\Passkeys\Store::for_user( $target->ID );

		if ( array() === $keys ) {
			\WP_CLI::error( sprintf( '%s has no passkeys, so nothing was changed.', $target->user_login ) );
		}

		if ( 'all' !== $which && ! ( ctype_digit( $which ) && in_array( (int) $which, array_column( $keys, 'id' ), true ) ) ) {
			\WP_CLI::error( sprintf( 'Name one of %1$s’s passkeys by its id, or say all. Run `wp bettershield account %1$s` to see them. Nothing was changed.', $target->user_login ) );
		}

		self::require_yes( $assoc_args, sprintf( 'all' === $which ? 'This removes every passkey %s has. It can’t be put back: they add new ones on their profile.' : 'This removes a passkey from %s. It can’t be put back: they add a new one on their profile.', $target->user_login ) );

		$removed = 'all' === $which ? \BetterShield\Passkeys\Store::forget_user( $target->ID ) : ( \BetterShield\Passkeys\Store::remove_for_account( $target->ID, (int) $which ) ? 1 : 0 );

		if ( 0 === $removed ) {
			\WP_CLI::error( 'The passkey could not be removed. Nothing was changed.' );
		}

		// What may have been opened with them does not outlive them.
		\BetterShield\Login\SessionReset::credential_changed( $target->ID, 'passkey' );

		\BetterShield\Events\Writer::instance()->record(
			'passkey_removed',
			\BetterShield\Events\Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $target->ID,
				'context'     => array(
					'by'    => 'cli',
					'count' => $removed,
				),
			)
		);

		\WP_CLI::success( sprintf( 1 === $removed ? 'Removed %2$d passkey from %1$s. It can’t be put back: they add a new one on their profile. They will get an email, and the activity log records it.' : 'Removed %2$d passkeys from %1$s. They can’t be put back: they add new ones on their profile. They will get an email, and the activity log records it.', $target->user_login, $removed ) );
	}

	/** Ask an account for a new password before it signs in again, or lift that. */
	private function require_new_password( \WP_User $target, bool $lift ): void {
		if ( $lift ) {
			if ( ! \BetterShield\Remediation\PasswordHold::has( $target->ID ) ) {
				\WP_CLI::error( sprintf( '%s is not asked for a new password, so nothing was changed.', $target->user_login ) );
			}

			if ( ! \BetterShield\Remediation\PasswordHold::lift( $target->ID, 'undo' ) ) {
				\WP_CLI::error( 'The requirement could not be lifted. Nothing was changed.' );
			}

			\WP_CLI::success( sprintf( '%s signs in with their password again. Recorded in the activity log.', $target->user_login ) );
			return;
		}

		if ( \BetterShield\Remediation\PasswordHold::has( $target->ID ) ) {
			\WP_CLI::error( sprintf( '%s is already asked for a new password, so nothing was changed.', $target->user_login ) );
		}

		// The same refusals as the dashboard's hold: the last way in, an
		// account in the middle of something else.
		$refused = \BetterShield\Remediation\Accounts::refusal( $target->ID, true );

		if ( '' !== $refused ) {
			\WP_CLI::error( $refused . ' Nothing was changed.' );
		}

		$undo = \BetterShield\Remediation\PasswordHold::place( $target->ID, 'cli' );

		if ( '' === $undo ) {
			\WP_CLI::error( 'The requirement could not be placed. Nothing was changed.' );
		}

		// A hold nobody was told how to clear would only be a lockout.
		if ( true !== retrieve_password( $target->user_login ) ) {
			\BetterShield\Remediation\PasswordHold::lift( $target->ID, 'not_sent' );
			\WP_CLI::error( 'The reset email failed, so nothing was changed: they sign in as before.' );
		}

		\BetterShield\Events\Writer::instance()->record(
			'incident_password_held',
			\BetterShield\Events\Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'user',
				'object_id'   => (string) $target->ID,
				'context'     => array(
					'reason' => 'cli',
					'undo'   => $undo,
				),
			)
		);

		\WP_CLI::success( sprintf( '%1$s must set a new password before signing in, and was sent the reset email. Lift it with `wp bettershield account require-new-password %1$s --lift --user=<login>`.', $target->user_login ) );
	}

	/**
	 * Lists or releases lockouts on the sign-in form and the public forms.
	 *
	 * A release is the one the Login & Access screen makes: that network may
	 * use that form again at once, and the clear is recorded in the activity
	 * log against the account given with --user. `release --all` lets every
	 * paused network back in together, and is recorded as a weakening.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : list or release. Omit to list.
	 * ---
	 * options:
	 *   - list
	 *   - release
	 * ---
	 *
	 * [<id>]
	 * : For release, the lockout's id, as the list shows it.
	 *
	 * [--all]
	 * : For release, every lockout running now, on --surface when it is given.
	 *
	 * [--surface=<surface>]
	 * : Only the lockouts on this form.
	 * ---
	 * options:
	 *   - signin
	 *   - comment
	 *   - reset
	 *   - register
	 * ---
	 *
	 * [--active]
	 * : For list, only the lockouts running now.
	 *
	 * [--limit=<number>]
	 * : For list, how many to show, from 1 to 1000. Running lockouts come
	 * first and are always shown, however many there are.
	 * ---
	 * default: 50
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format for the list.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield lockouts
	 *     wp bettershield lockouts list --active --format=json
	 *     wp bettershield lockouts list --surface=comment
	 *     wp bettershield lockouts release 42 --user=admin
	 *     wp bettershield lockouts release --all --surface=signin --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function lockouts( array $args, array $assoc_args ): void {
		$action   = (string) ( $args[0] ?? 'list' );
		$surface  = (string) ( $assoc_args['surface'] ?? '' );
		$surfaces = '' === $surface ? array() : array( $surface );

		if ( '' !== $surface && ! in_array( $surface, Surfaces::ALL, true ) ) {
			\WP_CLI::error( sprintf( 'Unknown form "%s". Use one of: %s.', $surface, implode( ', ', Surfaces::ALL ) ) );
		}

		$protection = Protection::instance();

		if ( 'list' === $action ) {
			$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );
			// From 1, as every other list reads it: 0 was taken as 1 and
			// printed a row (#2084).
			$limit  = self::limit_from( $assoc_args, 50, 1000 );
			$active = isset( $assoc_args['active'] );
			$rows   = array();

			foreach ( $protection->lockouts( $limit, $surfaces ) as $lockout ) {
				if ( $active && ! $lockout['active'] ) {
					continue;
				}

				$rows[] = array(
					'id'       => $lockout['id'],
					'surface'  => $lockout['surface'],
					'network'  => $lockout['network'],
					// In the site's time zone on the table, as `activity` reads
					// (#2085); JSON and CSV keep UTC, and say so.
					'started'  => 'table' === $format ? self::site_time( (string) $lockout['started_at'] ) : $lockout['started_at'],
					'expires'  => 'table' === $format ? self::site_time( (string) $lockout['expires_at'] ) : $lockout['expires_at'],
					'attempts' => $lockout['attempts'],
					'state'    => $lockout['active'] ? 'running' : ( $lockout['released'] ? 'released' : 'ended' ),
				);
			}

			$this->print_rows( $format, $rows, array( 'id', 'surface', 'network', 'started', 'expires', 'attempts', 'state' ) );

			// A cut list says it was cut, where a person is reading it; a
			// script asked for a format and reads the rows.
			$total = $active ? $protection->lockout_running( $surfaces ) : $protection->lockout_total( $surfaces );

			if ( 'table' === $format && $total > count( $rows ) ) {
				\WP_CLI::line( sprintf( 'Showing %d of %d. Add --limit to see more.', count( $rows ), $total ) );
			}

			return;
		}

		if ( 'release' !== $action ) {
			\WP_CLI::error( 'Say which: `lockouts list` or `lockouts release <id>`.' );
		}

		$id  = (string) ( $args[1] ?? '' );
		$all = isset( $assoc_args['all'] );

		// Both was answered as neither, which sent the reader to add the
		// --all they had already typed (#2084).
		if ( $all && '' !== $id ) {
			\WP_CLI::error( 'Name one lockout by its id or add --all, not both. Nothing was changed. Run `wp bettershield lockouts list --active` to see them.' );
		}

		if ( ! $all && '' === $id ) {
			\WP_CLI::error( 'Name one lockout by its id, or add --all to release every running one. Run `wp bettershield lockouts list --active` to see them.' );
		}

		if ( ! $all && ! ctype_digit( $id ) ) {
			\WP_CLI::error( sprintf( '"%s" is not a lockout id. Run `wp bettershield lockouts list` to see them.', $id ) );
		}

		$this->require_manage();

		if ( $all ) {
			$cleared = $protection->release_all( $surfaces );

			if ( 0 === $cleared ) {
				\WP_CLI::success( 'No lockout is running, so there was nothing to release.' );
				return;
			}

			\WP_CLI::success( sprintf( 1 === $cleared ? 'Released %d lockout. Recorded in the activity log.' : 'Released %d lockouts. Recorded in the activity log.', $cleared ) );
			return;
		}

		$done = $protection->release( (int) $id );

		if ( is_wp_error( $done ) ) {
			\WP_CLI::error( $done->get_error_message() . ( 'bettershield_unknown_lockout' === $done->get_error_code() ? ' Run `wp bettershield lockouts list` to see them.' : '' ) );
		}

		\WP_CLI::success( sprintf( 'Released lockout %d. Recorded in the activity log.', (int) $id ) );
	}

	/**
	 * Lists, adds to or removes from the sign-in blocklist.
	 *
	 * Through the same save as the Login & Access screen: the same checks
	 * on every entry, the same undo record in the settings history, and the
	 * same activity log row, which names a removal as a weakening. An entry
	 * refuses a network, a user agent, a username, or a combination of them,
	 * all of which have to match.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : list, add or remove. Omit to list.
	 * ---
	 * options:
	 *   - list
	 *   - add
	 *   - remove
	 * ---
	 *
	 * [--range=<range>]
	 * : An address or CIDR range, e.g. 203.0.113.0/24.
	 *
	 * [--ua=<pattern>]
	 * : Part of a user agent, four characters at least.
	 *
	 * [--username=<login>]
	 * : A username nobody may sign in as.
	 *
	 * [--note=<note>]
	 * : For add, why the entry is there.
	 *
	 * [--format=<format>]
	 * : Output format for the list.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield blocklist
	 *     wp bettershield blocklist add --range=203.0.113.0/24 --note="Scanner" --user=admin
	 *     wp bettershield blocklist add --ua=sqlmap --user=admin
	 *     wp bettershield blocklist add --username=administrator --user=admin
	 *     wp bettershield blocklist remove --range=203.0.113.0/24 --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function blocklist( array $args, array $assoc_args ): void {
		$action     = (string) ( $args[0] ?? 'list' );
		$protection = Protection::instance();
		$list       = $protection->settings()['blocklist'];

		if ( 'list' === $action ) {
			$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );
			$rows   = array();

			foreach ( $list as $entry ) {
				$rows[] = array(
					'range'    => (string) ( $entry['range'] ?? '' ),
					'ua'       => (string) ( $entry['ua'] ?? '' ),
					'username' => (string) ( $entry['username'] ?? '' ),
					'note'     => (string) ( $entry['note'] ?? '' ),
					'author'   => (string) ( $entry['author'] ?? '' ),
					'added'    => 'table' === $format && '' !== (string) ( $entry['added_at'] ?? '' ) ? self::site_time( (string) $entry['added_at'] ) : (string) ( $entry['added_at'] ?? '' ),
				);
			}

			$this->print_rows( $format, $rows, array( 'range', 'ua', 'username', 'note', 'author', 'added' ) );
			return;
		}

		if ( ! in_array( $action, array( 'add', 'remove' ), true ) ) {
			\WP_CLI::error( 'Say which: `blocklist list`, `blocklist add` or `blocklist remove`.' );
		}

		// The entry as typed: whichever of the three fields were given.
		$entry = array_filter(
			array(
				'range'    => trim( (string) ( $assoc_args['range'] ?? '' ) ),
				// Cleaned as the save cleans them, so `remove` finds what
				// `add` stored.
				'ua'       => trim( sanitize_text_field( (string) ( $assoc_args['ua'] ?? '' ) ) ),
				// As given: the save refuses a name it would store differently (#1800).
				'username' => trim( (string) ( $assoc_args['username'] ?? '' ) ),
			),
			static fn( string $value ): bool => '' !== $value
		);

		if ( array() === $entry ) {
			\WP_CLI::error( 'Give the entry: --range, --ua or --username, or a combination of them.' );
		}

		$this->require_manage();

		// Entries are matched field for field, as sign-in matches them (a name
		// and a browser string in any case): the same entry as the screen's,
		// and never one that merely overlaps it.
		$same = static function ( array $saved ) use ( $entry ): bool {
			return Protection::match_key( $saved ) === Protection::match_key( $entry );
		};

		$found = array_values( array_filter( $list, $same ) );

		if ( 'add' === $action ) {
			if ( array() !== $found ) {
				\WP_CLI::success( 'That entry is already on the blocklist. Nothing was changed.' );
				return;
			}

			if ( isset( $assoc_args['note'] ) ) {
				$entry['note'] = (string) $assoc_args['note'];
			}

			$next = array_merge( $list, array( $entry ) );
		} else {
			if ( array() === $found ) {
				\WP_CLI::error( 'No blocklist entry has exactly those fields. Run `wp bettershield blocklist` to see them.' );
			}

			$next = array_values( array_filter( $list, static fn( array $saved ): bool => ! $same( $saved ) ) );
		}

		$saved = $protection->update_settings( array( 'blocklist' => $next ) );

		if ( is_wp_error( $saved ) ) {
			\WP_CLI::error( $saved->get_error_message() . ' Nothing was changed.' );
		}

		\WP_CLI::success(
			'add' === $action
				? 'Added to the blocklist. Recorded in the activity log; Settings › General can put it back.'
				: 'Removed from the blocklist. Recorded in the activity log; Settings › General can put it back.'
		);
	}

	/**
	 * Lists or changes who gets this site's alert emails, or mutes them.
	 *
	 * ## OPTIONS
	 *
	 * <topic>
	 * : What to work on.
	 * ---
	 * options:
	 *   - recipients
	 *   - mute
	 *   - unmute
	 *   - host-managed
	 * ---
	 *
	 * [<action>]
	 * : For recipients: list (the default), add, remove or reset. Reset goes
	 * back to the site's admin email. For host-managed: on or off.
	 *
	 * [<address>...]
	 * : The addresses to add or remove. A site can name up to five.
	 *
	 * [--format=<format>]
	 * : Output format for recipients list. Table when left out. No default
	 * is declared here: WP-CLI would pass it on every line, and the actions
	 * that refuse --format could not tell it from one typed.
	 * ---
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * The list needs no account. Everything else changes the site, so it
	 * runs as someone: add --user=<login> naming an account that can manage
	 * BetterShield. Naming the first address replaces the site's admin email
	 * as the place alerts go, and taking the last one off puts it back.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield alerts recipients list
	 *     wp bettershield alerts recipients list --format=json
	 *     wp bettershield alerts recipients add alerts@agency.example --user=admin
	 *     wp bettershield alerts recipients remove old@agency.example --user=admin
	 *     wp bettershield alerts recipients reset --user=admin
	 *     wp bettershield alerts mute --user=admin
	 *     wp bettershield alerts unmute --user=admin
	 *     wp bettershield alerts host-managed on --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function alerts( array $args, array $assoc_args ): void {
		$topic = (string) ( $args[0] ?? '' );

		if ( in_array( $topic, array( 'mute', 'unmute' ), true ) ) {
			if ( count( $args ) > 1 || isset( $assoc_args['format'] ) ) {
				\WP_CLI::error( sprintf( '`alerts %s` takes nothing else. Nothing was changed.', $topic ) );
			}

			$this->require_manage();
			$this->switch_alerts( 'mute' === $topic );

			return;
		}

		if ( 'host-managed' === $topic ) {
			if ( ! in_array( $args[1] ?? '', array( 'on', 'off' ), true ) || count( $args ) > 2 || isset( $assoc_args['format'] ) ) {
				\WP_CLI::error( 'Say `alerts host-managed on` or `alerts host-managed off`. Nothing was changed.' );
			}

			$this->require_manage();
			$this->switch_host_managed( 'on' === $args[1] );

			return;
		}

		if ( 'recipients' !== $topic ) {
			\WP_CLI::error( 'Say which: `alerts recipients`, `alerts mute`, `alerts unmute` or `alerts host-managed`.' );
		}

		$action    = (string) ( $args[1] ?? 'list' );
		$addresses = array_slice( $args, 2 );

		if ( ! in_array( $action, array( 'list', 'add', 'remove', 'reset' ), true ) ) {
			\WP_CLI::error( 'Say which: `alerts recipients list`, `add`, `remove` or `reset`.' );
		}

		// Taken at face value, `reset old@example.com` would clear the whole
		// list for a line that names one address.
		if ( in_array( $action, array( 'list', 'reset' ), true ) && array() !== $addresses ) {
			\WP_CLI::error( sprintf( '`alerts recipients %s` takes no address. Nothing was changed.', $action ) );
		}

		if ( 'list' === $action ) {
			$this->list_alert_recipients( $assoc_args );
			return;
		}

		if ( isset( $assoc_args['format'] ) ) {
			\WP_CLI::error( '--format belongs to `alerts recipients list`. Nothing was changed.' );
		}

		if ( 'reset' !== $action && array() === $addresses ) {
			\WP_CLI::error( sprintf( 'Give at least one address to %s.', $action ) );
		}

		$this->require_manage();

		$this->change_alert_recipients( $action, $addresses );
	}

	/**
	 * @param array<string, string> $assoc_args
	 */
	private function list_alert_recipients( array $assoc_args ): void {
		$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );
		$alerts = AlertSettings::instance();
		$source = array() === $alerts->settings()['recipients'] ? 'admin email' : 'named';
		$rows   = array();

		foreach ( $alerts->deliveries() as $delivery ) {
			$rows[] = array(
				'address' => $delivery['address'],
				'source'  => $source,
				'instant' => $delivery['instant'],
				'digest'  => 'json' === $format ? $delivery['digest'] : ( $delivery['digest'] ? 'yes' : 'no' ),
			);
		}

		$this->print_rows( $format, $rows, array( 'address', 'source', 'instant', 'digest' ) );

		// On stderr, so a script reading the rows still reads only the rows.
		if ( $alerts->is_muted() ) {
			\WP_CLI::warning( 'Alerts are muted, so these addresses get no alerts for now.' );
		} elseif ( $alerts->sends_nothing() ) {
			\WP_CLI::warning( 'Email alerts are off, so these addresses get no alerts until they are turned on in Settings.' );
		}
	}

	/**
	 * The stored mute and the one in force differ once a site leaves staging:
	 * the mute set for the copy stops counting, while the setting stays on.
	 * Saying "already muted" there would be false, since alerts are going out.
	 */
	private function switch_alerts( bool $mute ): void {
		$alerts = AlertSettings::instance();
		$stored = $alerts->settings()['muted'];

		if ( $mute && $stored && ! $alerts->is_muted() ) {
			\WP_CLI::error( 'Alerts stay on: the mute set for a staging copy stopped counting when this site left staging. Nothing was changed.' );
		}

		if ( $mute === $stored ) {
			\WP_CLI::success( $mute ? 'Alerts were already muted. Nothing was changed.' : 'Alerts were not muted. Nothing was changed.' );
			return;
		}

		$saved = $alerts->update_settings( array( 'muted' => $mute ) );

		if ( is_wp_error( $saved ) ) {
			\WP_CLI::error( $saved->get_error_message() . ' Nothing was changed.' );
		}

		// The delivery check reads the mute, so the findings move with it, as
		// they do after the same save on the screen.
		Auditor::run();

		\WP_CLI::success(
			$mute
				? 'Alerts are muted. Recorded in the activity log. Turn them back on with `wp bettershield alerts unmute' . self::as_someone() . '`.'
				: 'Alerts are on. Recorded in the activity log.'
		);
	}

	private function switch_host_managed( bool $on ): void {
		$alerts = AlertSettings::instance();

		if ( $on === $alerts->settings()['host_managed'] ) {
			\WP_CLI::success( 'Nothing was changed.' );
			return;
		}

		$saved = $alerts->update_settings( array( 'host_managed' => $on ) );

		if ( is_wp_error( $saved ) ) {
			\WP_CLI::error( $saved->get_error_message() . ' Nothing was changed.' );
		}

		\WP_CLI::success(
			$on
				? 'Routine alerts wait for the weekly summary. Signs of an attack still email at once. Recorded in the activity log.'
				: 'Alerts email at once again. Recorded in the activity log.'
		);
	}

	/**
	 * Run again across a fleet, an address already added or already gone is
	 * nothing changed rather than a failure, so one site cannot stop the loop.
	 *
	 * @param string   $action    The action: add, remove or reset.
	 * @param string[] $addresses The addresses as typed.
	 */
	private function change_alert_recipients( string $action, array $addresses ): void {
		$alerts = AlertSettings::instance();
		$named  = $alerts->settings()['recipients'];
		$listed = array_map( 'strtolower', $named );
		$before = $alerts->recipients();

		if ( 'reset' === $action ) {
			$next = array();
		} elseif ( 'add' === $action ) {
			$next = array_merge(
				$named,
				array_filter( $addresses, static fn( string $address ): bool => ! in_array( strtolower( $address ), $listed, true ) )
			);
		} else {
			$typed = array_map( 'strtolower', $addresses );
			$next  = array_values( array_filter( $named, static fn( string $address ): bool => ! in_array( strtolower( $address ), $typed, true ) ) );

			foreach ( array_diff( $typed, $listed ) as $absent ) {
				\WP_CLI::warning( sprintf( '%s is not on the list.', $absent ) );
			}
		}

		if ( array_map( 'strtolower', $next ) === $listed ) {
			\WP_CLI::success( 'Nothing was changed.' );
			return;
		}

		$saved = $alerts->update_settings( array( 'recipients' => $next ) );

		if ( is_wp_error( $saved ) ) {
			\WP_CLI::error( $saved->get_error_message() . ' Nothing was changed.' );
		}

		$now = $alerts->recipients();

		if ( 'add' === $action ) {
			foreach ( array_udiff( $before, $now, 'strcasecmp' ) as $replaced ) {
				\WP_CLI::warning( sprintf( '%s no longer gets alerts: a named address replaces the site\'s admin email. Add it too to keep it on the list.', $replaced ) );
			}
		}

		if ( array() === $now ) {
			\WP_CLI::warning( 'Nobody gets alerts now: no address is named, and the site\'s admin email is not a working address.' );
		}

		\WP_CLI::success( sprintf( 'Alerts go to: %s. Recorded in the activity log.', '' !== implode( ', ', $now ) ? implode( ', ', $now ) : 'nobody' ) );
	}

	/**
	 * Prints the report-a-problem block, with nothing that identifies the site or anyone on it.
	 *
	 * The block says how the plugin is set up here, so it can go into a
	 * support thread as it is.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield diagnostics
	 *
	 * @param string[]             $args
	 * @param array<string, mixed> $assoc_args
	 */
	public function diagnostics( array $args = array(), array $assoc_args = array() ): void {
		self::refuse_options( $args, $assoc_args, 'diagnostics' );

		\WP_CLI::line( Diagnostics::render() );
	}

	/**
	 * Prints the security report as one HTML page, to keep or print to PDF.
	 *
	 * Built from the weekly summary's figures over the period: the score and
	 * its trend, open findings, what opened and was fixed, protections changed,
	 * activity by area and incidents. Counts and names only: no addresses,
	 * logins or email addresses. Redirect it into a file to keep it.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : How many days back the report covers, up to what the activity log keeps. Default 30.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield report > security-report.html
	 *     wp bettershield report --days=7 > last-week.html
	 */
	public function report( array $args, array $assoc_args ): void {
		$typed = isset( $assoc_args['days'] ) ? trim( (string) $assoc_args['days'] ) : (string) SecurityReport::DEFAULT_DAYS;

		// Any whole number: more days than the log keeps is held to what it
		// keeps, with the warning below, rather than refused (#2737).
		if ( 1 !== preg_match( '/^\d+$/', $typed ) || (int) $typed < 1 ) {
			\WP_CLI::error( 'Days must be a whole number of 1 or more.' );
		}

		// The command line is the operator's: every section, as a manager
		// reading the site's own screens would see.
		$report = SecurityReport::build( (int) $typed, array( 'posture', 'fixes', 'activity', 'incidents' ) );

		if ( $report['days'] < (int) $typed ) {
			\WP_CLI::warning( sprintf( 'The activity log keeps %d days, so the report covers those.', $report['days'] ) );
		}

		\WP_CLI::line( SecurityReport::render( $report ) );
	}

	/**
	 * Known vulnerabilities in what this site runs, and the check that finds them.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : What to do. `check` runs the daily check now.
	 * ---
	 * default: status
	 * options:
	 *   - status
	 *   - check
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * [--fail-on=<severity>]
	 * : Exit non-zero when an installed component is named by an advisory at
	 *   this severity or worse. One of critical, high, medium, low.
	 *
	 * [--strict]
	 * : With --fail-on, also exit non-zero when nothing could be checked — no
	 *   feed bound, the check switched off, or no data yet. A build that goes
	 *   green because the check could not run is what this stops.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield vulnerabilities
	 *     wp bettershield vulnerabilities check
	 *     wp bettershield vulnerabilities check --fail-on=high
	 *     wp bettershield vulnerabilities check --fail-on=high --strict
	 *
	 * @param string[]             $args
	 * @param array<string, mixed> $assoc_args
	 */
	public function vulnerabilities( array $args, array $assoc_args ): void {
		$action = (string) ( $args[0] ?? 'status' );
		$format = self::format_from( $assoc_args, array( 'table', 'json' ) );

		// Refused before the check runs or anything is printed: read only at
		// the gate, a typo let a CI job do the full run and print the status
		// first, so the log read as a normal check (#2173).
		if ( isset( $assoc_args['fail-on'] ) && ! in_array( strtolower( (string) $assoc_args['fail-on'] ), array( 'low', 'medium', 'high', 'critical' ), true ) ) {
			\WP_CLI::error( '--fail-on takes one of: critical, high, medium, low. Nothing was changed.' );
		}

		if ( 'check' === $action ) {
			$result = \BetterShield\Vulnerabilities\Scanner::run();

			if ( ! $result['ran'] ) {
				$reasons = array(
					'no_feed'     => 'No vulnerability data source is bound in this version, so there is nothing to check against.',
					'not_enabled' => 'The vulnerability check is turned off. Turn it on under Settings in the dashboard.',
					'feed_error'  => \BetterShield\Vulnerabilities\State::has_data()
						? 'The feed could not be refreshed; the last good data is kept, and its age is shown.'
						: 'The feed could not be reached and no check has succeeded yet. Try again later.',
					'busy' => 'Another check is running. A follow-up check is scheduled.',
					'inventory_changed' => 'Installed components changed during the check. Another check is scheduled.',
				);
				\WP_CLI::warning( $reasons[ $result['reason'] ] ?? $result['reason'] );
			} else {
				\BetterShield\Audit\Auditor::run();

				/*
				 * Said to a person at a terminal, and not onto the stream a
				 * pipeline parses. `WP_CLI::success()` writes to stdout, so on
				 * `--format=json` this line landed in front of the document
				 * and the first thing a parser met was the word "Success".
				 * Everything it says is in the body below — `checked` and
				 * `affected` are both in the summary — which is where a JSON
				 * consumer was always going to read it.
				 */
				if ( 'json' !== $format ) {
					\WP_CLI::success( sprintf( 'Checked. %d item(s) for review.', $result['affected'] ) );
				}
			}
		}

		$summary = \BetterShield\Vulnerabilities\Scanner::summary();
		$state   = \BetterShield\Vulnerabilities\State::get();
		$summary['check_incomplete'] = isset( $result ) && ! $result['ran'];

		// As installed now: updated to the fix or deleted since the check ran,
		// an item is no longer listed or counted against the gate (#1810).
		$state['affected'] = \BetterShield\Vulnerabilities\State::affected_now();

		if ( 'json' === $format ) {
			\WP_CLI::print_value( array( 'summary' => $summary, 'affected' => $state['affected'] ), array( 'format' => 'json' ) );
			$this->halt_on_advisories( $summary, $state, $assoc_args );
			return;
		}

		if ( ! $summary['feed_bound'] ) {
			$this->halt_on_advisories( $summary, $state, $assoc_args );
			\WP_CLI::line( 'No vulnerability data source is bound in this version. Nothing was checked; that is not the same as nothing being vulnerable.' );
			return;
		}

		\WP_CLI::line( sprintf( 'Feed: %s. Check %s. Data as of: %s (%s).', $summary['feed_label'], $summary['enabled'] ? 'on' : 'off', '' !== $summary['published_at'] ? $summary['published_at'] : 'never', null === $summary['age_days'] ? 'no data' : $summary['age_days'] . ' days old' ) );

		if ( array() === $state['affected'] ) {
			\WP_CLI::line( $summary['has_data'] ? 'Nothing installed is named by a current advisory.' : 'No check has run yet.' );
			// The branch --strict exists for: a feed is bound and the check is
			// on, but nothing has ever run, so "no affected packages" is not
			// an answer. The two early returns above already gate; this one
			// returned green on the emptiest state of all.
			$this->halt_on_advisories( $summary, $state, $assoc_args );
			return;
		}

		\WP_CLI\Utils\format_items(
			'table',
			array_map(
				static fn( array $item ): array => array(
					'type'      => $item['type'],
					'slug'      => $item['slug'],
					'installed' => $item['installed_version'],
					'fixed_in'  => $item['fixed_in'] ?? '—',
					'severity'  => 'unknown' === ( $item['match_status'] ?? '' ) ? 'Needs review' : ( false === ( $item['severity_known'] ?? true ) ? 'unknown' : $item['severity'] ),
					'advisories' => count( $item['advisories'] ),
				),
				$state['affected']
			),
			array( 'type', 'slug', 'installed', 'fixed_in', 'severity', 'advisories' )
		);

		$this->halt_on_advisories( $summary, $state, $assoc_args );
	}

	/**
	 * The build gate for the advisory check.
	 *
	 * @param array<string, mixed>  $summary
	 * @param array<string, mixed>  $state
	 * @param array<string, mixed>  $assoc_args
	 */
	private function halt_on_advisories( array $summary, array $state, array $assoc_args ): void {
		if ( isset( $assoc_args['fail-on'] ) ) {
			$order = array( 'low', 'medium', 'high', 'critical' );
			$at = array_search( strtolower( (string) $assoc_args['fail-on'] ), $order, true );
			if ( false === $at ) {
				\WP_CLI::error( 'Use one of: critical, high, medium, low.' );
			}
			$wanted = array_slice( $order, (int) $at );
			$hit = 0;
			foreach ( $state['affected'] ?? array() as $item ) {
				// A match nobody gave a severity counts at medium, the level the
				// audit grades it at, not as the info it is stored as (#1956).
				$level = false === ( $item['severity_known'] ?? true ) ? 'medium' : strtolower( (string) ( $item['severity'] ?? '' ) );
				if ( 'affected' === ( $item['match_status'] ?? 'affected' ) && in_array( $level, $wanted, true ) ) {
					++$hit;
				}
			}
			if ( $hit > 0 ) {
				\WP_CLI::warning( sprintf( '%d installed component(s) are named by an advisory at %s or worse.', $hit, strtolower( (string) $assoc_args['fail-on'] ) ) );
				\WP_CLI::halt( 1 );
			}
		}
		if ( isset( $assoc_args['strict'] ) && ( empty( $summary['feed_bound'] ) || empty( $summary['enabled'] ) || empty( $summary['has_data'] ) || ! empty( $summary['stale'] ) || ! empty( $summary['error'] ) || ! empty( $summary['unknown'] ) || ! empty( $summary['check_incomplete'] ) ) ) {
			\WP_CLI::warning( 'A complete, current advisory check was not available, and --strict treats that as a failure.' );
			\WP_CLI::halt( 1 );
		}
	}

	/**
	 * Compares core and directory-plugin files against the published copies.
	 *
	 * ## OPTIONS
	 *
	 * [<action>]
	 * : What to do.
	 * ---
	 * default: status
	 * options:
	 *   - status
	 *   - scan
	 *   - restore
	 *   - suppress
	 *   - unsuppress
	 *   - undo
	 *   - recheck
	 *   - expect
	 *   - record-update
	 *   - expect-file
	 * ---
	 *
	 * [--id=<change>]
	 * : Which recorded change, for restore, suppress and unsuppress.
	 *
	 * [--slug=<folder>]
	 * : Which plugin or theme, by its folder, for recheck, expect and
	 *   record-update.
	 *
	 * [--version=<version>]
	 * : For expect: the version its changes were recorded against, as
	 *   `wp bettershield integrity --format=json` lists it under "packages".
	 *   For record-update: the version now on disk.
	 *
	 * [--type=<type>]
	 * : For expect and record-update: plugin or theme. For expect, a plugin is
	 *   found whether wordpress.org publishes it or not.
	 * ---
	 * default: plugin
	 * options:
	 *   - plugin
	 *   - theme
	 * ---
	 *
	 * [--yes]
	 * : For expect: mark them. Without it, expect says what it would mark and
	 *   changes nothing.
	 *
	 * [--file=<path>]
	 * : For expect-file: the file, from the site root, in must-use plugins,
	 *   drop-ins, configuration or a plugin nobody publishes. (Not --path:
	 *   WP-CLI keeps that name for itself and never passes it on.)
	 *
	 * [--token=<undo>]
	 * : Which undo record, for undo. A restore and a suppress each print one.
	 *
	 * [--change=<kind>]
	 * : List only the open changes of this kind.
	 * ---
	 * options:
	 *   - modified
	 *   - added
	 *   - removed
	 *   - unreadable
	 *   - package_mismatch
	 * ---
	 *
	 * [--location=<where>]
	 * : List only the open changes in this location. (Not --context: WP-CLI
	 * keeps that name for itself and never passes it on.)
	 * ---
	 * options:
	 *   - core
	 *   - plugin
	 *   - theme
	 *   - muplugin
	 *   - dropin
	 *   - config
	 *   - unlisted
	 *   - extra
	 * ---
	 *
	 * [--cursor=<cursor>]
	 * : Start the list where the previous page ended. Under a table that was
	 *   cut, the command for the next page is printed; the JSON gives the
	 *   cursor as "next_cursor".
	 *
	 * [--format=<format>]
	 * : Output format. csv exports every matching open change rather than one
	 *   page.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * [--fail-on-changes]
	 * : Exit non-zero when any file differs from the copy its publisher
	 *   shipped, or is present where nothing shipped one.
	 *
	 * [--strict]
	 * : With --fail-on-changes, also exit non-zero when something could not be
	 *   checked — a blocked outbound request, an unpublished version, a walk
	 *   that did not finish. A build that goes green because the check could
	 *   not run is the failure this flag exists to stop.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield integrity
	 *     wp bettershield integrity --change=added --location=core
	 *     wp bettershield integrity --format=csv > changes.csv
	 *     wp bettershield integrity scan
	 *     wp bettershield integrity scan --fail-on-changes
	 *     wp bettershield integrity scan --fail-on-changes --strict
	 *     wp bettershield integrity restore --id=12 --user=admin
	 *     wp bettershield integrity undo --token=<undo> --user=admin
	 *     wp bettershield integrity suppress --id=12 --user=admin
	 *     wp bettershield integrity unsuppress --id=12 --user=admin
	 *     wp bettershield integrity recheck --slug=akismet --user=admin
	 *     wp bettershield integrity expect --slug=akismet --version=5.3
	 *     wp bettershield integrity expect --slug=akismet --version=5.3 --yes --user=admin
	 *     wp bettershield integrity record-update --slug=acme-pro --version=2.1.0 --user=admin
	 *     wp bettershield integrity expect-file --file=wp-content/mu-plugins/host-helper.php --user=admin
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function integrity( array $args, array $assoc_args ): void {
		$action = (string) ( $args[0] ?? 'status' );
		$format = self::format_from( $assoc_args, array( 'table', 'json', 'csv' ) );
		$filter = self::change_filter( $assoc_args );
		$cursor = trim( (string) ( $assoc_args['cursor'] ?? '' ) );
		$done   = null;

		/*
		 * The list was one page of 200, restorable edits first, with no way
		 * past it: on a site with more edited plugin files than that, a new
		 * PHP file in a core folder was never shown here (#2079). The JSON
		 * handed out a cursor nothing took.
		 */
		if ( 'csv' === $format && ! in_array( $action, array( 'status', 'scan' ), true ) ) {
			\WP_CLI::error( sprintf( '--format=csv exports the open changes. Run it without an action, or after `scan`, not with `%s`.', $action ) );
		}

		/*
		 * An option the action does not take was ignored without a word:
		 * `--slug=classic-editor` on the list printed every change, unfiltered
		 * (#2143). --type has a default, so only a value other than it counts
		 * as typed.
		 */
		$takes = array(
			'id'      => array( 'restore', 'suppress', 'unsuppress' ),
			'slug'    => array( 'recheck', 'expect', 'record-update' ),
			'version' => array( 'expect', 'record-update' ),
			'type'    => array( 'expect', 'record-update' ),
			'yes'     => array( 'expect' ),
			'token'   => array( 'undo' ),
			'file'    => array( 'expect-file' ),
		);

		foreach ( $takes as $option => $actions ) {
			$typed = 'type' === $option ? 'plugin' !== (string) ( $assoc_args['type'] ?? 'plugin' ) : isset( $assoc_args[ $option ] );

			if ( $typed && ! in_array( $action, $actions, true ) ) {
				\WP_CLI::error( sprintf( '--%1$s is used only with %2$s. Nothing was changed.', $option, preg_replace( '/, ([^,]+)$/', ' and $1', implode( ', ', $actions ) ) ) );
			}
		}

		if ( '' !== $cursor ) {
			$probe = Report::changes_page( $cursor, $filter );

			if ( is_wp_error( $probe ) && 'bettershield_bad_cursor' === $probe->get_error_code() ) {
				\WP_CLI::error( 'That --cursor is not one this list gave out. Run `wp bettershield integrity` to start from the first page.' );
			}
		}
		// Whether a scan asked for here finished, as opposed to the last check
		// that did, which is what the report below describes.
		$unfinished = false;

		switch ( $action ) {
			case 'scan':
				/*
				 * A scan only reads, so it needs no acting user — the same
				 * reasoning as `audit`.
				 *
				 * Asked for by hand means "ask again", so the cached manifests
				 * go. The scanner discards them itself, inside the claim it
				 * takes and only on the tick that begins a run: doing it out
				 * here threw them away before this call had even learned
				 * whether it was going to run, which took them out from under
				 * a scan already going on elsewhere.
				 */
				$state      = Scanner::run_to_completion( 200, true );
				$unfinished = empty( $state['finished_at'] );

				if ( $unfinished ) {
					\WP_CLI::warning(
						empty( $state['elsewhere'] )
							? 'The check ran out of passes before it finished. It keeps its place and carries on from the schedule.'
							: 'Another file check is running, so this one compared nothing. What follows is the last check that finished.'
					);
				}
				break;

			case 'undo':
				$this->require_shared_code();

				$token = (string) ( $assoc_args['token'] ?? '' );

				if ( '' === $token ) {
					\WP_CLI::error( 'Name the undo token with --token=<undo>. A restore prints one, and the Files screen lists what is in quarantine.' );
				}

				// A token names what it undoes: a marking taken back, a group
				// marked together taken back, or a restored file's copy put
				// back from quarantine.
				$record      = \BetterShield\Undo\Ledger::find( $token );
				$was_batch   = null !== $record && \BetterShield\Integrity\Packages::EXPECT_UNDO === (string) $record->action_key;

				if ( null !== $record && \BetterShield\Integrity\ExpectedFile::UNDO === (string) $record->action_key ) {
					$undone = \BetterShield\Integrity\ExpectedFile::undo( $token );

					if ( is_wp_error( $undone ) ) {
						\WP_CLI::error( $undone->get_error_message() );
					}

					$done = array(
						'action'  => 'undo',
						'message' => 'The file goes back to what the check held it to, and the next check reports it.',
					);
					break;
				}

				$was_marking = $was_batch || ( null !== $record && Restore::SUPPRESS_UNDO === (string) $record->action_key );

				if ( $was_batch ) {
					$undone = \BetterShield\Integrity\Packages::undo( $token );
				} else {
					$undone = $was_marking ? Restore::revert_suppression( $token ) : \BetterShield\Files\Quarantine::put_back( $token );
				}

				if ( is_wp_error( $undone ) ) {
					\WP_CLI::error( $undone->get_error_message() );
				}

				if ( $was_marking ) {
					$message = 'The change is reported again, as it was before it was marked expected.';
				} elseif ( ! empty( $undone['reported'] ) ) {
					$message = 'The previous file is back exactly as it was, and its difference is reported again.';
				} else {
					$message = 'The previous file is back exactly as it was. The next check compares it with the published copy.';
				}

				$done = array(
					'action'  => 'undo',
					'message' => $message,
				);
				break;

			case 'unsuppress':
				$this->require_shared_code();

				$id = self::change_id( $assoc_args, 'Name which change with --id=<change>. `wp bettershield integrity --format=json` lists the ones marked expected under "suppressed".' );

				$result = Restore::unsuppress( $id );

				if ( is_wp_error( $result ) ) {
					\WP_CLI::error( $result->get_error_message() );
				}

				$done = array(
					'action'  => 'unsuppress',
					'message' => 'Reported again. It stays listed until restored or marked expected.',
				);
				break;

			case 'recheck':
				$this->require_shared_code();

				$slug = (string) ( $assoc_args['slug'] ?? '' );

				if ( '' === $slug ) {
					\WP_CLI::error( 'Name the plugin with --slug=<folder>.' );
				}

				$after = 0;
				$total = array(
					'checked' => 0,
					'closed'  => 0,
				);

				// Carried on until every open row is compared: a terminal is
				// not a request with a time limit.
				do {
					$result = \BetterShield\Integrity\Packages::recheck( $slug, $after );

					if ( is_wp_error( $result ) ) {
						\WP_CLI::error( $result->get_error_message() );
					}

					$total['checked'] += $result['checked'];
					$total['closed']  += $result['closed'];
					$after             = $result['after'];
				} while ( $result['left'] > 0 && $after > 0 );

				$done = array(
					'action'  => 'recheck',
					'message' => sprintf(
						'Compared %1$s against version %2$s; %3$s.',
						self::counted( $total['checked'], '%d open change', '%d open changes' ),
						$result['version'],
						self::counted( $total['closed'], '%d matched and is closed', '%d matched and are closed' )
					),
					'checked' => $total['checked'],
					'closed'  => $total['closed'],
				);
				break;

			case 'expect':
				$slug    = (string) ( $assoc_args['slug'] ?? '' );
				$version = (string) ( $assoc_args['version'] ?? '' );
				$context = (string) ( $assoc_args['type'] ?? 'plugin' );

				if ( '' === $slug || '' === $version ) {
					\WP_CLI::error( 'Name the group with --slug=<folder> and --version=<version>. `wp bettershield integrity --format=json` lists them under "packages".' );
				}

				$preview = \BetterShield\Integrity\Packages::preview( $context, $slug, $version );

				if ( is_wp_error( $preview ) ) {
					\WP_CLI::error( $preview->get_error_message() );
				}

				/*
				 * A fleet script names a plugin, and cannot know which kind it
				 * is on each site. Published first: a plugin that became
				 * published can have rows in both, and those are two groups,
				 * so one line never marks a set its preview did not show.
				 */
				if ( 'plugin' === $context && 0 === (int) $preview['total'] ) {
					$unlisted = \BetterShield\Integrity\Packages::preview( \BetterShield\Integrity\Unpublished::CONTEXT_UNLISTED, $slug, $version );

					if ( is_wp_error( $unlisted ) ) {
						\WP_CLI::error( $unlisted->get_error_message() );
					}

					if ( (int) $unlisted['total'] > 0 ) {
						$context = \BetterShield\Integrity\Unpublished::CONTEXT_UNLISTED;
						$preview = $unlisted;
					}
				}

				/*
				 * Neither of these marks anything, and on `--format=json` each
				 * still answers with the document, as every other action does:
				 * a sentence there was stdout a pipeline could not parse.
				 */
				if ( 0 === (int) $preview['total'] ) {
					$nothing = 'Nothing in that group is open, so there is nothing to mark.';

					if ( 'json' !== $format ) {
						\WP_CLI::line( $nothing );
						return;
					}

					$done = array(
						'action'  => 'expect',
						'message' => $nothing,
						'marked'  => 0,
					);
					break;
				}

				if ( ! isset( $assoc_args['yes'] ) ) {
					$unchanged = 'Nothing was changed. Run again with --yes to mark these expected.';

					if ( 'json' === $format ) {
						$done = array(
							'action'  => 'expect',
							'message' => $unchanged,
							'marked'  => 0,
							'preview' => $preview,
						);
						break;
					}

					\WP_CLI::line( sprintf( '%1$s %2$s: %3$s (%4$d changed, %5$d added, %6$d removed).', $preview['name'], $version, self::counted( (int) $preview['total'], '%d change', '%d changes' ), $preview['modified'], $preview['added'], $preview['removed'] ) );

					foreach ( $preview['added_code'] as $path ) {
						\WP_CLI::line( '  added code: ' . $path );
					}

					\WP_CLI::line( $unchanged );
					return;
				}

				$this->require_shared_code();

				$result = \BetterShield\Integrity\Packages::expect( $context, $slug, $version, (int) $preview['total'], (string) $preview['digest'] );

				if ( is_wp_error( $result ) ) {
					\WP_CLI::error( $result->get_error_message() );
				}

				$done = array(
					'action'  => 'expect',
					'message' => sprintf( 'Marked %1$s expected together; undo token %2$s.', self::counted( (int) $result['count'], '%d change', '%d changes' ), $result['undo'] ),
					'undo'    => $result['undo'],
					'marked'  => (int) $result['count'],
				);
				break;

			case 'expect-file':
				$this->require_shared_code();

				$file = (string) ( $assoc_args['file'] ?? '' );

				if ( '' === $file ) {
					\WP_CLI::error( 'Name the file with --file=<path>, from the site root.' );
				}

				$taken = \BetterShield\Integrity\ExpectedFile::record( $file );

				if ( is_wp_error( $taken ) ) {
					\WP_CLI::error( $taken->get_error_message() );
				}

				$done = array(
					'action'  => 'expect-file',
					'message' => '' === $taken['undo']
						? 'That file is already held to these contents. Nothing was changed.'
						: sprintf( 'Recorded these contents of %1$s as expected. Any other contents are reported; undo token %2$s.', $file, $taken['undo'] ),
					'undo'    => $taken['undo'],
				);
				break;

			case 'record-update':
				$this->require_shared_code();

				$recorded = \BetterShield\Integrity\UpdateRecord::record( (string) ( $assoc_args['type'] ?? 'plugin' ), (string) ( $assoc_args['slug'] ?? '' ), (string) ( $assoc_args['version'] ?? '' ) );

				if ( is_wp_error( $recorded ) ) {
					\WP_CLI::error( $recorded->get_error_message() );
				}

				$done = array(
					'action'  => 'record-update',
					'message' => sprintf(
						'Recorded %1$s %2$s as an update. The next check reads it as one.%3$s',
						$recorded['name'],
						$recorded['to'],
						$recorded['open'] > 0 ? sprintf( ' %s already reported stay open: `wp bettershield integrity expect` takes them as a group.', self::counted( $recorded['open'], '%d change', '%d changes' ) ) : ''
					),
				);
				break;

			case 'restore':
			case 'suppress':
				$this->require_shared_code();

				$id = self::change_id( $assoc_args, 'Name which change with --id=<change>. `wp bettershield integrity` lists them.' );

				$result = 'restore' === $action ? Restore::apply( $id ) : Restore::suppress( $id );

				if ( is_wp_error( $result ) ) {
					\WP_CLI::error( $result->get_error_message() );
				}

				$done = 'restore' === $action
					? array(
						'action'  => 'restore',
						'message' => sprintf( 'Official copy put back. The file that was there is in quarantine; undo token %s.', (string) $result['undo'] ),
						'undo'    => (string) $result['undo'],
					)
					: array(
						'action'  => 'suppress',
						'message' => sprintf( 'Marked expected. It will not be reported again unless it changes to something else; undo token %s.', (string) $result['undo'] ),
						'undo'    => (string) $result['undo'],
					);
				break;
		}

		/*
		 * What an action did is said to a person at a terminal, and not onto
		 * the stream a pipeline parses: `WP_CLI::success()` writes to stdout,
		 * so on `--format=json` it landed in front of the document. There it
		 * goes in the document instead, with the undo token a restore hands
		 * back, so the action and its undo can be paired without reading text.
		 */
		if ( null !== $done && 'json' !== $format ) {
			\WP_CLI::success( $done['message'] );
		}

		$report = Report::all( $cursor, $filter );

		// The count the Overview leads with: one added file that can run is
		// what a long list of plugin edits hides.
		$report['open_changes']['added_code'] = Report::open_added_code();

		if ( array() !== $filter ) {
			$report['matching'] = Report::open_matching( $filter );
		}

		if ( null !== $done ) {
			$report['done'] = $done;
		}

		if ( 'scan' === $action ) {
			$report['scan_finished'] = ! $unfinished;
		}

		if ( 'json' === $format ) {
			\WP_CLI::line( (string) wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			// The gate belongs to the command, not to one of its output
			// formats — and capturing JSON for the build report while relying
			// on the exit code to gate the deploy is the shape a pipeline
			// actually takes. The advisory gate next door already does this.
			$this->halt_on_changes( $report, $assoc_args );
			return;
		}

		// Every matching row, page after page, the way `activity` exports:
		// a script gets the whole list without walking cursors itself.
		if ( 'csv' === $format ) {
			$rows = array();
			$next = $cursor;

			do {
				$page = Report::changes_page( $next, $filter );

				if ( is_wp_error( $page ) ) {
					$report['changes_error'] = $page->get_error_message();
					\WP_CLI::warning( 'The recorded changes could not be read just now, so this export stops here.' );
					break;
				}

				foreach ( $page['changes'] as $change ) {
					$rows[] = array(
						'id'         => $change['id'],
						'change'     => $change['change_type'],
						'path'       => $change['path'],
						'context'    => $change['context'],
						'slug'       => $change['slug'],
						'version'    => $change['version'],
						'detected'   => $change['detected_at'],
						'restorable' => $change['restorable'] ? 'yes' : 'no',
						'can_run'    => $change['can_run'] ? 'yes' : 'no',
					);
				}

				$next = (string) ( $page['next_cursor'] ?? '' );
			} while ( '' !== $next );

			$this->print_rows( 'csv', $rows, array( 'id', 'change', 'path', 'context', 'slug', 'version', 'detected', 'restorable', 'can_run' ) );
			$this->halt_on_changes( $report, $assoc_args );
			return;
		}

		\WP_CLI::line(
			$report['ever_run']
				? sprintf( 'Last checked: %s%s', self::site_time( (string) $report['last_run_at'] ), $report['running'] ? ' (a check is in progress)' : '' )
				: 'Never checked. Run `wp bettershield integrity scan`.'
		);

		foreach ( $report['unverifiable'] as $item ) {
			\WP_CLI::line(
				sprintf(
					'  Not verifiable: %s %s %s — %s',
					(string) $item['context'],
					// The name a person knows it by, where the entry carries
					// one; core carries none and reads as its context.
					(string) ( $item['name'] ?? $item['slug'] ?? '' ),
					(string) $item['version'],
					(string) $item['message']
				)
			);
		}

		$added_code = (int) $report['open_changes']['added_code'];

		if ( $added_code > 0 && array() === $filter ) {
			\WP_CLI::line( sprintf( '%s. `wp bettershield integrity --change=added` lists every added file.', self::counted( $added_code, '%d added file can run as code', '%d added files can run as code' ) ) );
		}

		if ( array() === $report['changes'] ) {
			/*
			 * An empty list is also what a check that could not run leaves:
			 * blocked fetches, an unreadable change table, no check at all.
			 * So the gate is read before anything is called clean, as on the
			 * JSON branch, and only a complete answer says every file matched.
			 */
			$this->halt_on_changes( $report, $assoc_args );

			if ( null !== ( $report['changes_error'] ?? null ) ) {
				\WP_CLI::warning( 'The recorded changes could not be read just now, so this says nothing about the files.' );
			} elseif ( ! $report['ever_run'] || $unfinished ) {
				// A scan that did not finish vouches for nothing; the warning
				// above has said why.
				return;
			} elseif ( array() !== $filter || '' !== $cursor ) {
				// A filter or a later page that is empty says nothing of the
				// rest of the files.
				\WP_CLI::success(
					sprintf(
						'%s %s open in all.',
						'' !== $cursor ? 'Nothing more to list.' : 'No open change matches ' . self::filter_flags( $filter ) . '.',
						self::counted( (int) ( $report['open_changes']['total'] ?? 0 ), '%d change is', '%d changes are' )
					)
				);
			} elseif ( array() !== $report['unverifiable'] ) {
				\WP_CLI::success( sprintf( 'Nothing differs among the files that could be compared. %d item(s) could not be checked.', count( $report['unverifiable'] ) ) );
			} else {
				\WP_CLI::success( 'Nothing differs from the published copies.' );
			}

			return;
		}

		$rows = array();
		foreach ( $report['changes'] as $change ) {
			$rows[] = array(
				'id'         => $change['id'],
				'change'     => $change['change_type'],
				'path'       => $change['path'],
				// Cut to the second, it had no zone at all and read as local
				// time (#2085).
				'detected'   => self::site_time( (string) $change['detected_at'] ),
				'restorable' => $change['restorable'] ? 'yes' : 'no',
			);
		}

		\WP_CLI\Utils\format_items( $format, $rows, array( 'id', 'change', 'path', 'detected', 'restorable' ) );

		// The list is one page. Said under a table, where a person reads it,
		// with the command for the next one; the JSON carries the total and
		// the cursor.
		$open = (int) ( $report['matching'] ?? $report['open_changes']['total'] ?? 0 );
		$what = array() === $filter ? 'open changes' : 'matching open changes';

		if ( $open > count( $rows ) ) {
			$line = '' === $cursor
				? sprintf( 'Listed the first %1$d of %2$d %3$s.', count( $rows ), $open, $what )
				: sprintf( 'Listed %1$d more of %2$d %3$s.', count( $rows ), $open, $what );

			if ( null !== $report['next_cursor'] ) {
				$line .= sprintf(
					' Next page: `wp bettershield integrity%s --cursor=%s`, or add --format=csv for every one.',
					array() === $filter ? '' : ' ' . self::filter_flags( $filter ),
					escapeshellarg( (string) $report['next_cursor'] )
				);
			}

			\WP_CLI::line( $line );
		}

		$this->halt_on_changes( $report, $assoc_args );
	}

	/**
	 * What --change and --location narrow the open changes to, each checked
	 * against what the file check records.
	 *
	 * @param array<string, mixed> $assoc_args
	 * @return array<string, string>
	 */
	private static function change_filter( array $assoc_args ): array {
		$known  = array(
			'change'  => array( 'modified', 'added', 'removed', 'unreadable', \BetterShield\Integrity\IncomingPackage::CHANGE_TYPE ),
			'location' => array_merge( array( \BetterShield\Integrity\Manifest::CONTEXT_CORE, \BetterShield\Integrity\Manifest::CONTEXT_PLUGIN ), \BetterShield\Integrity\Unpublished::CONTEXTS, array( \BetterShield\Integrity\Manifest::CONTEXT_EXTRA ) ),
		);
		$filter = array();

		foreach ( array( 'change' => 'change_type', 'location' => 'context' ) as $option => $column ) {
			if ( ! isset( $assoc_args[ $option ] ) ) {
				continue;
			}

			$value = strtolower( trim( (string) $assoc_args[ $option ] ) );

			if ( ! in_array( $value, $known[ $option ], true ) ) {
				\WP_CLI::error( sprintf( '--%1$s takes %2$s, not "%3$s".', $option, implode( ', ', $known[ $option ] ), $value ) );
			}

			$filter[ $column ] = $value;
		}

		return $filter;
	}

	/**
	 * A filter as the options that ask for it, to repeat in a command.
	 *
	 * @param array<string, string> $filter
	 */
	private static function filter_flags( array $filter ): string {
		$flags = array();

		foreach ( array( 'change_type' => 'change', 'context' => 'location' ) as $column => $option ) {
			if ( isset( $filter[ $column ] ) ) {
				$flags[] = '--' . $option . '=' . $filter[ $column ];
			}
		}

		return implode( ' ', $flags );
	}

	/**
	 * The change --id names. A word was cast to 0 and answered as no id at
	 * all, which told the reader to add the --id they had typed (#2084).
	 *
	 * @param array<string, mixed> $assoc_args
	 * @param string               $missing    What to say when no --id was given.
	 */
	private static function change_id( array $assoc_args, string $missing ): int {
		if ( ! isset( $assoc_args['id'] ) || true === $assoc_args['id'] ) {
			\WP_CLI::error( $missing );
		}

		$id = trim( (string) $assoc_args['id'] );

		if ( ! ctype_digit( $id ) || (int) $id < 1 ) {
			\WP_CLI::error( sprintf( '--id takes a change\'s number, as `wp bettershield integrity` lists it, not "%s".', $id ) );
		}

		return (int) $id;
	}

	/**
	 * The build gate for the file check, the same contract the audit's has.
	 *
	 * A check that only prints is a check a pipeline cannot enforce, and the
	 * two questions a deploy answers most directly — did files change, did I
	 * ship a known-vulnerable version — were the two without a gate.
	 *
	 * @param array<string, mixed>  $report
	 * @param array<string, string> $assoc_args
	 */
	private function halt_on_changes( array $report, array $assoc_args ): void {
		if ( ! isset( $assoc_args['fail-on-changes'] ) ) {
			return;
		}

		// Every open change, not the page of them the report lists: that is
		// cut at 200, and a site with more was told 200 differed. With a
		// filter, every open change it matches.
		$changes = isset( $report['matching'] )
			? (int) $report['matching']
			: max( (int) ( $report['open_changes']['total'] ?? 0 ), count( (array) ( $report['changes'] ?? array() ) ) );

		if ( $changes > 0 ) {
			\WP_CLI::warning( sprintf( '%d file(s) differ from the published copies.', $changes ) );
			\WP_CLI::halt( 1 );
		}

		if ( ! isset( $assoc_args['strict'] ) ) {
			return;
		}

		$unverifiable = count( (array) ( $report['unverifiable'] ?? array() ) );
		$unfinished   = empty( $report['ever_run'] ) || null !== ( $report['changes_error'] ?? null ) || false === ( $report['scan_finished'] ?? true );

		if ( $unverifiable > 0 || $unfinished ) {
			\WP_CLI::warning(
				$unfinished
					? 'The file check has not produced a complete answer, and --strict treats that as a failure.'
					: sprintf( '%d item(s) could not be checked, and --strict treats that as a failure.', $unverifiable )
			);
			\WP_CLI::halt( 1 );
		}
	}

	/* ---- helpers ------------------------------------------------------------ */

	/**
	 * Rows in the format asked for. A CSV goes through the plugin's own cell
	 * guard rather than WP-CLI's writer, which only guards formulas from
	 * 2.12 on: a blocklist note or user agent is typed text, and a file of it
	 * opened in a spreadsheet must not run it.
	 *
	 * @param array<int, array<string, mixed>> $rows
	 * @param string[]                         $fields
	 */
	private function print_rows( string $format, array $rows, array $fields ): void {
		if ( 'csv' !== $format ) {
			\WP_CLI\Utils\format_items( $format, $rows, $fields );
			return;
		}

		\WP_CLI::line( Text::csv_row( $fields ) );

		foreach ( $rows as $row ) {
			\WP_CLI::line( Text::csv_row( array_map( static fn( string $field ): string => (string) ( $row[ $field ] ?? '' ), $fields ) ) );
		}
	}

	/**
	 * A change is recorded against someone. Refuse to make one on behalf of
	 * nobody.
	 */
	private function require_manage(): void {
		if ( current_user_can( Capabilities::MANAGE ) ) {
			return;
		}

		// A --user that was given and cannot manage here was told to add the
		// --user it had already typed (#2737).
		if ( get_current_user_id() > 0 ) {
			\WP_CLI::error( 'The account named with --user cannot manage BetterShield on this site. Name one that can. Nothing was changed.' );
		}

		\WP_CLI::error( 'This changes the site, so it runs as someone: add --user=<login> naming an account that can manage BetterShield. The change is recorded against that account.' );
	}

	/**
	 * A command that takes no options, refusing any that was typed. WP-CLI
	 * checks options only against a command's listed ones, and a command
	 * that lists none took anything: `--format=json` printed text and exited
	 * 0 for a script that asked for JSON (#2737).
	 *
	 * @param string[]             $args
	 * @param array<string, mixed> $assoc_args
	 * @param string               $command    The command, as typed.
	 */
	private static function refuse_options( array $args, array $assoc_args, string $command ): void {
		$typed = array_merge( array_map( 'strval', $args ), array_map( static fn( $key ): string => '--' . $key, array_keys( $assoc_args ) ) );

		if ( array() !== $typed ) {
			\WP_CLI::error( sprintf( '%1$s takes no options or arguments, so %2$s would be ignored. Nothing was run.', $command, implode( ', ', $typed ) ) );
		}
	}

	/**
	 * A change to the network's record of the code every site runs, or to a
	 * file in it. On a network that is the network's say, as the REST routes
	 * for the same changes hold it: a site's administrator ran the same
	 * restore here that the Files screen refused them (#2736).
	 */
	private function require_shared_code(): void {
		$this->require_manage();

		$allowed = Permissions::shared_code( false );

		if ( true !== $allowed ) {
			\WP_CLI::error( ( is_wp_error( $allowed ) ? $allowed->get_error_message() : 'This changes code every site shares.' ) . ' Nothing was changed.' );
		}
	}

	/**
	 * @param array<string, mixed> $plan
	 */
	private function print_plan( array $plan ): void {
		if ( array() !== $plan['hardening'] ) {
			$rows = array();
			foreach ( $plan['hardening'] as $row ) {
				$result = (string) ( $row['result'] ?? '' );

				// The row's note and the item's warning are two facts; a
				// change that failed made nothing to warn about.
				$note = array_filter( array( (string) ( $row['note'] ?? '' ), 'failed' === $result ? '' : (string) ( $row['conflict_warning'] ?? '' ) ) );

				$rows[] = array(
					'item'   => $row['item'],
					'now'    => null === $row['current'] ? '-' : ( $row['current'] ? 'on' : 'off' ),
					'wanted' => $row['wanted'] ? 'on' : 'off',
					'plan'   => $row['action'],
					'result' => $result,
					'note'   => implode( ' ', $note ),
				);
			}
			\WP_CLI::line( 'Hardening:' );
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'item', 'now', 'wanted', 'plan', 'result', 'note' ) );
		}

		if ( array() !== $plan['settings'] ) {
			$rows = array();
			foreach ( $plan['settings'] as $row ) {
				$changes = array();
				foreach ( (array) $row['changes'] as $key => $change ) {
					$change = (array) $change;
					if ( isset( $change['added'] ) ) {
						$changes[] = sprintf( '%s: +%d/-%d', $key, $change['added'], $change['removed'] );
					} else {
						$changes[] = sprintf( '%s: %s -> %s', $key, wp_json_encode( $change['from'] ), wp_json_encode( $change['to'] ) );
					}
				}
				$rows[] = array(
					'section' => $row['section'],
					'plan'    => $row['action'],
					'result'  => (string) ( $row['result'] ?? '' ),
					'changes' => implode( '; ', $changes ),
					'note'    => (string) ( $row['note'] ?? '' ),
				);
			}
			\WP_CLI::line( 'Settings:' );
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'section', 'plan', 'result', 'changes', 'note' ) );
		}
	}

	/**
	 * The flags a printed follow-up command needs to run as printed: who it
	 * runs as, which every change asks for, and on a network the site this
	 * run was given (#2641).
	 */
	private static function as_someone(): string {
		$flags = ' --user=<login>';
		$url   = class_exists( '\\WP_CLI' ) && method_exists( '\\WP_CLI', 'get_config' ) ? \WP_CLI::get_config( 'url' ) : null;

		if ( is_multisite() && is_string( $url ) && '' !== $url ) {
			$flags .= ' --url=' . escapeshellarg( $url );
		}

		return $flags;
	}

	/**
	 * A count with its noun, in the singular for one. The terminal's own
	 * sentences are written here in English, so "1 changes" was a mistake on
	 * every site rather than a translator's to correct.
	 *
	 * @param int    $count How many.
	 * @param string $one   The phrase for one, with %d where the count goes.
	 * @param string $many  The phrase for any other count.
	 */
	private static function counted( int $count, string $one, string $many ): string {
		return sprintf( 1 === $count ? $one : $many, $count );
	}

	/**
	 * @param array<int, array<string, mixed>> $findings
	 * @return array<string, int>
	 */
	private function count_by_severity( array $findings ): array {
		$counts = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		);

		foreach ( $findings as $finding ) {
			if ( isset( $counts[ $finding['severity'] ] ) ) {
				++$counts[ $finding['severity'] ];
			}
		}

		return $counts;
	}

	/**
	 * Check the activity log against its daily seals.
	 *
	 * Answers whether anything in the sealed window has been altered or
	 * removed since it was written. It does not claim the log is tamper-proof
	 * — somebody who can write to the database can rewrite the seals too. What
	 * it buys is that doing so has to be complete and deliberate rather than a
	 * single DELETE nobody would ever see.
	 *
	 * The answer is stored as the daily check stores it, so a day that no
	 * longer matches is a finding and an alert at once.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bettershield verify-log
	 *
	 * @subcommand verify-log
	 * @alias verify_log
	 *
	 * @param string[]              $args
	 * @param array<string, string> $assoc_args
	 */
	public function verify_log( array $args, array $assoc_args ): void {
		self::refuse_options( $args, $assoc_args, 'verify-log' );

		$result = \BetterShield\Events\Seal::verify();

		if ( 0 === $result['checked'] ) {
			\WP_CLI::warning( 'Nothing has been sealed yet. Seals are written once a day, for days that have finished.' );

			return;
		}

		if ( \BetterShield\Events\Seal::reseal_owed() ) {
			\WP_CLI::warning( 'Rows were renumbered or anonymized since these seals were taken, and taking them again could not finish. Days changed that way read as not matching until the daily check takes them again.' );
		} elseif ( \BetterShield\Events\Seal::record( $result ) ) {
			/*
			 * Written down as the daily check writes it, and the audit asked
			 * again when the answer changed: a broken day found here opens
			 * its finding, with its activity row and its alert, now rather
			 * than at the next daily run, and a dashboard never goes on
			 * saying the log is intact after this said it was not (#2087).
			 * While a reseal is owed the daily check stands its verdict
			 * over too, since the days it owes read as edited.
			 */
			Auditor::run();
		}

		$reasons = array(
			'chain_broken'     => 'an earlier day was rewritten',
			'contents_changed' => 'the contents changed',
			'rows_removed'     => 'every row of that day was removed, and it is inside the window this site keeps',
		);

		foreach ( $result['broken'] as $broken ) {
			\WP_CLI::warning(
				sprintf(
					'%s does not match its seal: %d rows were sealed, %d are there now (%s).',
					$broken['day'],
					$broken['rows_sealed'],
					$broken['rows_now'],
					$reasons[ $broken['reason'] ] ?? 'the contents changed'
				)
			);
		}

		if ( array() !== $result['unreadable'] ) {
			\WP_CLI::warning(
				sprintf(
					'%d sealed day(s) could not be read from the database just now, so they were not checked: %s.',
					count( $result['unreadable'] ),
					implode( ', ', $result['unreadable'] )
				)
			);
		}

		if ( array() !== $result['broken'] || array() !== $result['unreadable'] ) {
			\WP_CLI::halt( 1 );
		}

		\WP_CLI::success(
			sprintf(
				'%d day(s) intact. %d could no longer be checked, their rows having passed retention.',
				$result['intact'],
				$result['unverifiable']
			)
		);
	}
}
