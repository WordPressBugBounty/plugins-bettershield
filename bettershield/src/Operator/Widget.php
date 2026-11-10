<?php
/**
 * The dashboard widget: the score, what is open, and whether anything has
 * changed — for the owner who opens the dashboard and nothing else.
 *
 * Rendered in PHP from the same overview the Overview screen reads, styled
 * by its own small stylesheet through the plugin's token roles. Red appears
 * for critical alone, and nothing here sells anything: a warning is never a
 * place to ask somebody for money.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Operator;

use BetterShield\Audit\Auditor;
use BetterShield\Capabilities;
use BetterShield\Recovery\SafeMode;
use BetterShield\Vulnerabilities\Matcher;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Widget {

	public function register(): void {
		add_action( 'wp_dashboard_setup', array( $this, 'add_widget' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_style' ) );
	}

	public function add_widget(): void {
		if ( ! current_user_can( Capabilities::READ_POSTURE ) || ! function_exists( 'wp_add_dashboard_widget' ) ) {
			return;
		}

		wp_add_dashboard_widget(
			'bettershield_posture',
			// The owner's label where an add-on gives one: the widget is chrome.
			\BetterShield\Support\Branding::name(),
			array( $this, 'render' )
		);
	}

	/**
	 * The dashboard is the one screen outside the plugin's own that carries
	 * its styles — and only this stylesheet, never the app bundle.
	 */
	public function enqueue_style( string $hook ): void {
		if ( 'index.php' !== $hook || ! current_user_can( Capabilities::READ_POSTURE ) ) {
			return;
		}

		$path = BETTERSHIELD_PATH . '/assets/build/widget.css';
		if ( ! is_file( $path ) ) {
			return;
		}

		wp_enqueue_style(
			'bettershield-widget',
			plugins_url( 'assets/build/widget.css', BETTERSHIELD_FILE ),
			array(),
			(string) filemtime( $path )
		);
		wp_style_add_data( 'bettershield-widget', 'rtl', 'replace' );
	}

	public function render(): void {
		echo $this->markup(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- markup() escapes every value it interpolates.
	}

	/**
	 * The severity words, in the order this widget lists them.
	 *
	 * The ladder itself is `Vulnerabilities\Matcher::SEVERITIES`, and the set
	 * is taken from there rather than written out again: a severity added to
	 * the ladder and forgotten here appears as its own key instead of not
	 * appearing at all, and the order comes from one place. Only the wording
	 * lives here, because a translation catalog is built from literals.
	 *
	 * @return array<string, string>
	 */
	public static function severity_labels(): array {
		$words = array(
			'critical' => __( 'critical', 'bettershield' ),
			'high'     => __( 'high', 'bettershield' ),
			'medium'   => __( 'medium', 'bettershield' ),
			'low'      => __( 'low', 'bettershield' ),
			'info'     => __( 'info', 'bettershield' ),
		);

		$labels = array();

		foreach ( Matcher::SEVERITIES as $severity ) {
			$labels[ $severity ] = $words[ $severity ] ?? $severity;
		}

		return $labels;
	}

	/**
	 * The widget as HTML. Public so a test can read it without output
	 * buffering.
	 */
	public function markup(): string {
		$overview = Auditor::overview();
		$labels   = self::severity_labels();
		$counts   = array_fill_keys( array_keys( $labels ), 0 );

		// A snoozed finding is not called open, as the Overview and Findings
		// screens do not call it so; it is said apart, still counted in the score.
		$awake   = 0;
		$snoozed = 0;

		foreach ( $overview['findings'] as $finding ) {
			if ( ! empty( $finding['snoozed_until'] ) ) {
				++$snoozed;
				continue;
			}

			++$awake;

			if ( isset( $counts[ $finding['severity'] ] ) ) {
				++$counts[ $finding['severity'] ];
			}
		}

		$html  = '<div class="bs-widget">';
		$html .= '<div class="bs-widget__head">';
		$scanning = \BetterShield\Integrity\FirstScan::report()['running'];
		// An image, so the label is what is read: on an element with no role
		// it is ignored, and the two pieces were read on their own as "0 F".
		// While the scan runs the circle holds only a dash, and the line below
		// says why, to everyone.
		$html .= sprintf(
			'<div class="bs-widget__score" %s><span class="bs-widget__number">%s</span><span class="bs-widget__grade">%s</span></div>',
			$scanning
				? 'aria-hidden="true"'
				: sprintf(
					'role="img" aria-label="%s"',
					esc_attr(
						sprintf(
							/* translators: 1: score out of 100, 2: letter grade. */
							__( 'Security score %1$d out of 100, grade %2$s', 'bettershield' ),
							(int) $overview['score'],
							(string) $overview['grade']
						)
					)
				),
			$scanning ? '&mdash;' : (string) (int) $overview['score'],
			$scanning
				? ''
				: esc_html(
					sprintf(
						/* translators: %s: letter grade, e.g. "F". */
						__( 'Grade %s', 'bettershield' ),
						(string) $overview['grade']
					)
				)
		);

		$html .= '<div class="bs-widget__summary">';
		if ( 0 === $awake ) {
			$html .= '<p class="bs-widget__lede">' . esc_html__( 'No open findings.', 'bettershield' ) . '</p>';
		} else {
			$html .= '<p class="bs-widget__lede">' . esc_html(
				sprintf(
					/* translators: %d: number of open findings. */
					_n( '%d open finding', '%d open findings', $awake, 'bettershield' ),
					$awake
				)
			) . '</p>';

			$html .= '<p class="bs-widget__chips">';
			foreach ( $counts as $severity => $count ) {
				if ( 0 === $count ) {
					continue;
				}
				$html .= sprintf(
					'<span class="bs-widget__chip is-%s">%d %s</span>',
					esc_attr( $severity ),
					$count,
					esc_html( $labels[ $severity ] )
				);
			}
			$html .= '</p>';
		}

		$html .= '</div></div>';

		if ( $snoozed > 0 ) {
			$html .= '<p class="bs-widget__quiet">' . esc_html(
				sprintf(
					/* translators: %d: number of snoozed findings. */
					_n(
						'%d snoozed finding is hidden until it returns, but still counts in the score.',
						'%d snoozed findings are hidden until they return, but still count in the score.',
						$snoozed,
						'bettershield'
					),
					$snoozed
				)
			) . '</p>';
		}

		if ( $scanning ) {
			$html .= '<p class="bs-widget__quiet">' . esc_html__( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) . '</p>';
		}

		$html .= '<p class="bs-widget__quiet">' . esc_html( $this->quiet_line( $overview ) ) . '</p>';

		/*
		 * The first thing an administrator sees after signing in said nothing
		 * of an open incident (#2245). Said, with the way to it, to whoever
		 * may read the incidents.
		 */
		$incidents = current_user_can( Capabilities::READ_ACTIVITY ) ? \BetterShield\Incidents\Repository::open_count() : null;

		if ( null !== $incidents && $incidents > 0 ) {
			$html .= sprintf(
				'<p class="bs-widget__safe">%s <a href="%s">%s</a></p>',
				esc_html(
					sprintf(
						/* translators: %d: how many incidents are open. */
						_n( '%d open incident.', '%d open incidents.', $incidents, 'bettershield' ),
						$incidents
					)
				),
				esc_url( admin_url( 'admin.php?page=bettershield-activity&tab=incidents' ) ),
				esc_html( _n( 'Review Incident', 'Review Incidents', $incidents, 'bettershield' ) )
			);
		}

		if ( SafeMode::is_active() ) {
			$html .= '<p class="bs-widget__safe">' . esc_html__( 'Safe mode is on: all protections are paused. Settings are kept.', 'bettershield' ) . '</p>';
		}

		// A silenced site and a quiet one look identical from here, and the
		// difference matters more than anything else on this widget.
		if ( ! empty( $overview['alerts_muted'] ) ) {
			$html .= '<p class="bs-widget__safe">' . esc_html__( 'Alerts are muted. No alert or weekly summary is emailed.', 'bettershield' ) . '</p>';
		}

		$html .= sprintf(
			'<p class="bs-widget__actions"><a class="button" href="%s">%s</a></p>',
			esc_url( admin_url( 'admin.php?page=bettershield' ) ),
			/* translators: %s: the plugin's name, or the label the site owner gave it. */
			esc_html( sprintf( __( 'Open %s', 'bettershield' ), \BetterShield\Support\Branding::name() ) )
		);
		$html .= '</div>';

		return $html;
	}

	/**
	 * The quiet state, in one sentence: when the last audit ran, and when the
	 * last thing this plugin controls changed. "Nothing since Tuesday" is the
	 * reassurance a dashboard can give that a red banner cannot.
	 *
	 * @param array<string, mixed> $overview
	 */
	private function quiet_line( array $overview ): string {
		$audit  = $this->relative( $overview['generated_at'] ?? null );
		$change = $this->relative( $overview['receipts']['last_change_at'] ?? null );

		if ( null === $audit ) {
			return __( 'No audit has run yet.', 'bettershield' );
		}

		$first = $audit['recent']
			/* translators: %s: how long ago, e.g. "2 hours ago". */
			? sprintf( __( 'Last audit %s.', 'bettershield' ), $audit['text'] )
			/* translators: %s: a date. */
			: sprintf( __( 'Last audit on %s.', 'bettershield' ), $audit['text'] );

		if ( null === $change ) {
			/* translators: %s: the plugin's name, or the label the site owner gave it. */
			return $first . ' ' . sprintf( __( 'No changes by %s yet.', 'bettershield' ), \BetterShield\Support\Branding::name() );
		}

		$second = $change['recent']
			/* translators: 1: the plugin's name, or the label the site owner gave it, 2: how long ago, e.g. "2 hours ago". */
			? sprintf( __( 'Last change by %1$s: %2$s.', 'bettershield' ), \BetterShield\Support\Branding::name(), $change['text'] )
			/* translators: 1: the plugin's name, or the label the site owner gave it, 2: a date. */
			: sprintf( __( 'No changes by %1$s since %2$s.', 'bettershield' ), \BetterShield\Support\Branding::name(), $change['text'] );

		return $first . ' ' . $second;
	}

	/**
	 * A time as a person would say it: "2 hours ago" while it is recent, a
	 * date once it is not.
	 *
	 * @return array{text: string, recent: bool}|null
	 */
	private function relative( ?string $iso ): ?array {
		if ( null === $iso || '' === $iso ) {
			return null;
		}

		$time = strtotime( $iso );
		if ( false === $time ) {
			return null;
		}

		$now = time();
		if ( $now - $time < DAY_IN_SECONDS ) {
			return array(
				'text'   => sprintf(
					/* translators: %s: a human-readable time difference, e.g. "2 hours". */
					__( '%s ago', 'bettershield' ),
					human_time_diff( $time, $now )
				),
				'recent' => true,
			);
		}

		return array(
			'text'   => wp_date( (string) get_option( 'date_format' ), $time ),
			'recent' => false,
		);
	}
}
