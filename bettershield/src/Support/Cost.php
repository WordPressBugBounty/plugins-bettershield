<?php
/**
 * What this plugin costs a visitor, measured on this site's own traffic.
 *
 * This plugin must not slow a page down, and "must not" is a claim only a
 * measurement can hold. So the cost is measured on the site's own traffic and
 * shown to the owner, where a regression is visible to whoever is running the
 * site rather than only to whoever wrote the code.
 *
 * The panel that reports the number says exactly what was measured.
 *
 * **It only ever measures what it can honestly attribute.** Two things are
 * counted, and nothing is inferred by subtracting one total from another:
 *
 * - **Time**, from the first line of the plugin's own file to the end of its
 *   registration, plus the work it does at `shutdown`. The second part runs
 *   after the response has already gone, so counting it overstates what a
 *   visitor waited for — which is the direction to be wrong in.
 * - **Queries** this plugin's own tables and options account for, recognized by
 *   name on the `query` filter. That deliberately catches the failure this
 *   number exists to make visible: an option read on a visitor's page that
 *   nobody autoloaded, which is a lookup on every request and looks harmless in
 *   review. It does not catch work reached through a core API that queries
 *   something else, and the panel does not claim it does.
 *
 * **The measurement must not become the cost.** Nothing is measured on 19 of
 * every 20 page views — those requests do not even hook the filter — and the
 * rolling total is written once per sampled request at `shutdown`, after the
 * response, never in the response path. The panel states the sample.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cost {

	/** Where the rolling total lives. Autoloaded: see Support\HotOptions. */
	public const OPTION = 'bettershield_front_end_cost';

	/**
	 * One page view in this many is measured.
	 *
	 * High enough that the write it ends in is rarer than the option write the
	 * verification sampler already makes on the same hook, low enough that a
	 * quiet site still fills a window in a reasonable number of days.
	 */
	private const ONE_IN = 20;

	/**
	 * Samples in a window before it starts again.
	 *
	 * A lifetime average would keep reporting a cost the current version does
	 * not have — a regression fixed last week would still be in the number
	 * months later, and so would an improvement. A window that restarts means
	 * the figure describes recent traffic, which is the only figure worth
	 * publishing.
	 */
	private const WINDOW_SAMPLES = 100;

	private static bool $measuring = false;

	private static int $queries = 0;

	private static float $started = 0.0;

	private static float $elapsed = 0.0;

	/**
	 * Arm the meter, if this request is one of the sampled ones.
	 *
	 * Called from the plugin's own file rather than a hook, because the read
	 * this most needs to see — the sign-in key, checked before anything can ask
	 * for a salt — happens before `plugins_loaded`. Arming on a hook would have
	 * measured everything except the query that prompted this.
	 *
	 * Whether the request turns out to be one worth recording is decided at
	 * shutdown, where REST and AJAX are finally knowable. A measurement taken
	 * on a request that does not qualify is simply dropped.
	 */
	public static function begin( float $started ): void {
		if ( is_admin() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		/*
		 * Only a GET is ever recorded, so arming on anything else is a filter
		 * added to every query of a request whose measurement is thrown away at
		 * shutdown. This also closes the Store API checkout POST and the classic
		 * `?wc-ajax=` order submission, which is the point: the checkout is the
		 * one path this plugin promises to add nothing at all to.
		 *
		 * Both tests are answerable here, which the obvious ones are not. This
		 * runs while the plugin's own file is being included, so REST_REQUEST is
		 * not defined yet and WooCommerce's own file has not loaded — a
		 * `class_exists` test would answer no on every store on earth.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput -- reads the request's shape to decide whether to measure it; compared, never stored or echoed.
		if ( 'GET' !== strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for a structural test; never stored, never echoed.
		if ( Checkout::is_store_uri( isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ) ) {
			return;
		}

		// Not `wp_rand`: this runs before pluggable functions are loaded. The
		// choice does not need to be unpredictable, only unbiased.
		try {
			$roll = random_int( 1, self::ONE_IN );
		} catch ( \Throwable $e ) {
			return;
		}

		if ( 1 !== $roll ) {
			return;
		}

		self::$measuring = true;
		self::$started   = $started;

		add_filter( 'query', array( self::class, 'note_query' ) );
	}

	public static function measuring(): bool {
		return self::$measuring;
	}

	/**
	 * Count a query this plugin's own tables or options account for.
	 *
	 * Recognized by name rather than by backtrace. A backtrace per query is the
	 * accurate way and is far too expensive to run on a visitor's page even one
	 * time in twenty; a name test is one `strpos` and is exact for the two
	 * things worth counting, because nothing else on a WordPress site names
	 * them.
	 *
	 * @param mixed $sql
	 * @return mixed
	 */
	public static function note_query( $sql ) {
		if ( self::$measuring && is_string( $sql ) && false !== strpos( $sql, 'bettershield' ) ) {
			++self::$queries;
		}

		return $sql;
	}

	/**
	 * Close the load-and-registration window.
	 *
	 * Called at the end of the main plugin file, before other plugins load. Anything after it that belongs to this plugin
	 * is measured by `around()` instead.
	 */
	public static function booted(): void {
		if ( ! self::$measuring || self::$started <= 0.0 ) {
			return;
		}

		self::$elapsed += microtime( true ) - self::$started;
		self::$started  = 0.0;
	}

	/**
	 * Measure one piece of this plugin's own work and return what it returned.
	 *
	 * @param callable $work
	 * @return mixed
	 */
	public static function around( callable $work ) {
		if ( ! self::$measuring ) {
			return $work();
		}

		$at = microtime( true );

		try {
			return $work();
		} finally {
			self::$elapsed += microtime( true ) - $at;
		}
	}

	/**
	 * Fold this request's measurement into the rolling window.
	 *
	 * Called from the verification sampler, which already runs at `shutdown`
	 * behind exactly the right gate: an ordinary front-end page view, never the
	 * admin, REST, AJAX, cron or CLI, never the cart or the checkout, and never
	 * while safe mode has stood everything down.
	 */
	public static function record(): void {
		if ( ! self::$measuring ) {
			return;
		}

		self::$measuring = false;

		$stored = get_option( self::OPTION, array() );
		$window = is_array( $stored ) ? $stored : array();

		$samples = (int) ( $window['samples'] ?? 0 );

		if ( $samples >= self::WINDOW_SAMPLES || 2 !== ( $window['version'] ?? 0 ) ) {
			$window = array(
				'version' => 2,
				'samples' => 0,
				'ms'      => 0.0,
				'queries' => 0,
				'since'   => gmdate( 'Y-m-d H:i:s' ),
			);
		}

		$window['samples'] = (int) $window['samples'] + 1;
		$window['ms']      = (float) $window['ms'] + ( self::$elapsed * 1000 );
		$window['queries'] = (int) $window['queries'] + self::$queries;

		// Autoloaded, because the panel is not the only reader: this same row
		// is read on the next sampled page view, and an option that is not
		// autoloaded is a lookup on every request — the exact cost this whole
		// mechanism exists to keep visible.
		update_option( self::OPTION, $window, true );
	}

	/**
	 * What to publish, or null while there is not enough to publish.
	 *
	 * A handful of samples is not a measurement, and a figure drawn from three
	 * page views would be argued with for the rest of the version's life. The
	 * panel says nothing until the window has something to say.
	 *
	 * @return array{pages: int, ms: float, queries: float, samples: int, one_in: int, since: string}|null
	 */
	public static function published(): ?array {
		$stored = get_option( self::OPTION, array() );
		$window = is_array( $stored ) ? $stored : array();

		$samples = (int) ( $window['samples'] ?? 0 );

		if ( $samples < 10 || 2 !== ( $window['version'] ?? 0 ) ) {
			return null;
		}

		return array(
			// Stated as pages rather than samples because that is the question
			// being answered — what your visitors' page views cost — and the
			// sample rate is published beside it rather than hidden inside it.
			'pages'   => $samples * self::ONE_IN,
			'ms'      => round( ( (float) $window['ms'] ) / $samples, 2 ),
			'queries' => round( ( (int) $window['queries'] ) / $samples, 2 ),
			'samples' => $samples,
			'one_in'  => self::ONE_IN,
			// Marked as UTC before it leaves, like every other time this
			// plugin publishes: stored as a bare column value it carries no
			// zone, and a screen that guesses one shows the wrong day.
			'since'   => (string) Time::utc_iso( (string) ( $window['since'] ?? '' ) ),
		);
	}

	/** Test seam: a new request, as far as the meter's memory goes. */
	public static function reset_request_state(): void {
		self::$measuring = false;
		self::$queries   = 0;
		self::$started   = 0.0;
		self::$elapsed   = 0.0;
	}

	/**
	 * Test seam: measure this request without waiting for the roll to land.
	 */
	public static function force( float $started ): void {
		self::$measuring = true;
		self::$started   = $started;
		self::$queries   = 0;
		self::$elapsed   = 0.0;
	}
}
