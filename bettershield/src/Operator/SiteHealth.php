<?php
/**
 * The plugin's open findings as Site Health tests, under its own badge.
 *
 * Site Health is where an operator already looks, so the findings appear
 * there too — one test per open finding, in this plugin's own words, each
 * linking back to the full report. Findings that core's own tests already
 * cover (HTTPS, PHP end of life, visible debug output, waiting updates,
 * inactive extensions, and on newer WordPress open registration) are left
 * out: a thing said twice on one screen is a thing the reader stops trusting
 * on both. Coverage is decided by what core actually registered on this
 * version, not by a list frozen at build time — a test core adds later
 * takes over from ours the release it arrives.
 *
 * Status maps to core's three: critical stays critical, everything else is
 * recommended. Red is core's badge color for critical alone; every other
 * badge is blue. Nothing here sells anything.
 *
 * The Info tab gets a section of its own: what this plugin keeps about the
 * people on the site, one line per record. Site Health is the screen an owner
 * copies out of, so the answer to "what does it hold about me" belongs where
 * they can copy it rather than only in the code.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

use BetterShield\Audit\Auditor;
use BetterShield\Privacy\PersonalData;
use BetterShield\Support\Tier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SiteHealth {

	/**
	 * Finding key => the core Site Health test that says the same thing.
	 * A finding is left out only when that core test is actually registered.
	 */
	public const CORE_COVERED = array(
		'site_not_https'               => 'https_status',
		'php_end_of_life'              => 'php_version',
		'debug_display_enabled'        => 'debug_enabled',
		'core_update_available'        => 'wordpress_version',
		'plugin_updates_available'     => 'plugin_version',
		'inactive_extensions'          => 'plugin_version',
		'open_registration_privileged' => 'insecure_registration',
	);

	public function register(): void {
		add_filter( 'site_status_tests', array( $this, 'add_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_information' ) );
	}

	/**
	 * What this plugin keeps about a person, as the Info tab's own section.
	 *
	 * The Status tab says what is wrong with the site; this says what is held
	 * about the people on it — one line per record, with how long it is kept
	 * and what an erasure request does to it. It reads from the same ledger
	 * the export and the eraser read, so the three cannot drift apart.
	 *
	 * This is the block an owner copies into a support thread, so every value
	 * is a plain sentence and none of them is anybody's data: the ledger
	 * describes records, it never reads one.
	 *
	 * @param array<string, array<string, mixed>> $info
	 * @return array<string, array<string, mixed>>
	 */
	public function add_debug_information( array $info ): array {
		$fields = array();

		foreach ( PersonalData::records() as $key => $record ) {
			$fields[ 'record_' . str_replace( '.', '_', $key ) ] = array(
				'label' => (string) $record['what'],
				'value' => sprintf(
					/* translators: 1: how long a record is kept, 2: "removed" or "kept". */
					__( 'Kept %1$s; %2$s on erasure.', 'bettershield' ),
					(string) $record['window'],
					PersonalData::ERASURE_KEPT === ( $record['on_erasure'] ?? '' )
						? __( 'kept', 'bettershield' )
						: __( 'removed', 'bettershield' )
				),
			);
		}

		// The window every dated record above is measured against, on its own
		// line: it is the first thing a support thread asks for, and reading it
		// off one record's sentence is not the same as being told it.
		$fields['activity_log_window'] = array(
			'label' => __( 'How long the activity log is kept', 'bettershield' ),
			'value' => sprintf(
				/* translators: %d: number of days the activity log is kept. */
				_n( '%d day', '%d days', Tier::kept_days(), 'bettershield' ),
				Tier::kept_days()
			),
		);

		$info['bettershield'] = array(
			'label'       => __( 'BetterShield: what it keeps about people', 'bettershield' ),
			'description' => __( 'It lists what is kept and for how long, never anyone’s data.', 'bettershield' ),
			'fields'      => $fields,
		);

		return $info;
	}

	/**
	 * @param array<string, array<string, array<string, mixed>>> $tests
	 * @return array<string, array<string, array<string, mixed>>>
	 */
	public function add_tests( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}

		$open = $this->open_findings( $tests );

		if ( array() === $open ) {
			$tests['direct']['bettershield_posture'] = array(
				'label' => __( 'BetterShield has no open security findings', 'bettershield' ),
				'test'  => array( $this, 'clean_result' ),
			);

			return $tests;
		}

		foreach ( $open as $finding ) {
			$tests['direct'][ 'bettershield_' . $finding['id'] ] = array(
				'label' => $finding['title'],
				'test'  => function () use ( $finding ): array {
					return $this->finding_result( $finding );
				},
			);
		}

		return $tests;
	}

	/**
	 * Open findings this screen should carry — every open finding, minus what
	 * core says itself on this version.
	 *
	 * @param array<string, array<string, mixed>> $tests The tests registered so far.
	 * @return array<int, array<string, mixed>>
	 */
	public function open_findings( array $tests ): array {
		$registered = array_merge(
			isset( $tests['direct'] ) && is_array( $tests['direct'] ) ? array_keys( $tests['direct'] ) : array(),
			isset( $tests['async'] ) && is_array( $tests['async'] ) ? array_keys( $tests['async'] ) : array()
		);

		$out = array();

		foreach ( Auditor::overview()['findings'] as $finding ) {
			$core = self::CORE_COVERED[ $finding['id'] ] ?? null;
			if ( null !== $core && in_array( $core, $registered, true ) ) {
				continue;
			}
			$out[] = $finding;
		}

		return $out;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function clean_result(): array {
		$at = strtotime( (string) ( Auditor::overview()['generated_at'] ?? '' ) );
		$fresh = false !== $at && $at >= time() - 2 * DAY_IN_SECONDS;
		return array(
			'label'       => __( 'BetterShield has no open security findings', 'bettershield' ),
			'status'      => $fresh ? 'good' : 'recommended',
			'badge'       => $this->badge( false ),
			'description' => '<p>' . esc_html__( 'The full report, with what was checked, is on the BetterShield Findings screen.', 'bettershield' ) . '</p>' . $this->freshness(),
			'actions'     => $this->actions(),
			'test'        => 'bettershield_posture',
		);
	}

	/**
	 * One finding as a Site Health result: the finding's own title, why it
	 * matters, and what could break — the same words the report uses.
	 *
	 * @param array<string, mixed> $finding
	 * @return array<string, mixed>
	 */
	public function finding_result( array $finding ): array {
		$critical    = 'critical' === $finding['severity'];
		$description = '<p>' . esc_html( (string) $finding['why'] ) . '</p>';

		if ( ! empty( $finding['break_note'] ) ) {
			$description .= '<p>' . esc_html( (string) $finding['break_note'] ) . '</p>';
		}

		return array(
			'label'       => (string) $finding['title'],
			'status'      => $critical ? 'critical' : 'recommended',
			'badge'       => $this->badge( $critical ),
			'description' => $description . $this->freshness(),
			'actions'     => $this->actions(),
			'test'        => 'bettershield_' . $finding['id'],
		);
	}

	/**
	 * @return array{label: string, color: string}
	 */
	private function badge( bool $critical ): array {
		return array(
			// The plugin's name, not "Security": core's own security tests wear
			// that badge, and the reader should see at a glance which of the
			// two is speaking.
			'label' => __( 'BetterShield', 'bettershield' ),
			'color' => $critical ? 'red' : 'blue',
		);
	}


	private function freshness(): string {
		$at = strtotime( (string) ( Auditor::overview()['generated_at'] ?? '' ) );
		if ( false === $at ) {
			return '<p>' . esc_html__( 'No audit has run yet. Run one in BetterShield before relying on this.', 'bettershield' ) . '</p>';
		}
		/* translators: %s: date and time of the last audit. */
		$text = sprintf( __( 'Last audit: %s.', 'bettershield' ), wp_date( 'Y-m-d H:i T', $at ) );
		if ( $at < time() - 2 * DAY_IN_SECONDS ) {
			$text .= ' ' . __( 'This audit is overdue. Run a fresh audit in BetterShield.', 'bettershield' );
		}
		return '<p>' . esc_html( $text ) . '</p>';
	}

	private function actions(): string {
		return sprintf(
			'<p><a href="%s">%s</a></p>',
			esc_url( admin_url( 'admin.php?page=bettershield-findings' ) ),
			esc_html__( 'See the finding in BetterShield', 'bettershield' )
		);
	}
}
