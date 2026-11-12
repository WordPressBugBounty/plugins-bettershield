<?php
/**
 * Hardening item: find out what a Content-Security-Policy would break, before
 * anything breaks.
 *
 * CSP is the most effective thing a page can do about injected script, and
 * the header most likely to take a site's own features offline: every inline
 * script, analytics tag and embed. That is why almost nobody deploys it, and
 * why a plugin that switched one on would be doing something reckless.
 *
 * So this item **starts** at `Content-Security-Policy-Report-Only`, always: a
 * browser receiving it loads everything and posts a note about what *would*
 * have been blocked. The owner watches that list until it is quiet, and only
 * then is promoting the same policy to enforcing a decision worth making.
 *
 * **That promotion now exists, and everything about how it is built is there
 * to keep it from being the reckless thing.** It is never automatic. It is
 * refused outright until the site's own reports have been empty for a week, so
 * the evidence is the site's rather than a promise. It is one of the item's
 * actions, which means it takes the person-only gate rather than a credential.
 * The policy enforced is byte-for-byte the one that was being observed, so
 * nothing arrives that the reports did not already cover. Rolling back to
 * report-only is a single action away and is never gated. And re-applying the
 * item returns it to report-only, because a protection coming back on should
 * not silently start enforcing a policy the site may have drifted away from
 * while it was off.
 *
 * **The report endpoint is the dangerous half, and it is bounded from the
 * start.** Browsers post to it unauthenticated, by design, from every page
 * view of every visitor. An unbounded endpoint like that grew `wp_options`
 * without limit the last time this plugin had one. So reports are aggregated
 * rather than stored, capped at a fixed number of distinct kinds, rate
 * limited per source, and the whole thing switches itself off once it has
 * seen enough to be useful.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hardening\Item;

use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\SentHeaders;
use BetterShield\Undo\Ledger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ContentSecurityPolicy {

	public const REPORTS_OPTION = 'bettershield_csp_reports';

	/** When this item started watching, which is what the quiet window counts from. */
	public const OBSERVING_OPTION = 'bettershield_csp_observing_since';

	/** Whether a visitor's browser can deliver a report: the reach probe's last answer. */
	public const REACH_OPTION = 'bettershield_csp_reach';

	public const MODE_REPORT_ONLY = 'report_only';
	public const MODE_ENFORCING   = 'enforcing';

	/**
	 * How long the reports must have been empty before enforcing is offered.
	 *
	 * A week rather than a day because the things a policy breaks are not
	 * evenly distributed through a week: the payment provider's script on a
	 * checkout nobody used on Tuesday, the embed on the one page that gets
	 * traffic at the weekend, the marketing tag that fires monthly. A quiet
	 * afternoon is not evidence; seven days of real traffic is the least that
	 * is.
	 */
	public const QUIET_DAYS = 7;

	/**
	 * Whether this request is sending the enforcing header.
	 *
	 * Captured when the item is hooked rather than read inside the header
	 * callback, which runs on every front-end response. The stored state is
	 * autoloaded, so reading it there would cost nothing measurable — but the
	 * callback has no business asking a question whose answer was already
	 * known when it was hooked.
	 */
	private static bool $enforcing = false;

	/**
	 * How many distinct kinds of violation are kept.
	 *
	 * A kind is a directive plus the thing it blocked, so a site loading forty
	 * different scripts from one host is a handful of kinds and not forty. Past
	 * this the report has already told the owner what they needed to know.
	 */
	public const MAX_KINDS = 50;

	/** Reports one connection may send inside the window. */
	public const MAX_PER_SOURCE = 20;

	private const RATE_SECONDS = 300;

	/**
	 * Most sources the owner may allow, across every directive.
	 *
	 * The policy is widened from its own reports: a source a visitor's
	 * browser reported can be allowed on the directive it was reported on,
	 * and taken off again; inline script, eval, wildcards and bare schemes
	 * never can. The list can be cleared, for a cause fixed on the site or a
	 * report that was never real. Each goes through the undo ledger, and each
	 * starts the quiet week again, so what is enforced is still what was
	 * watched.
	 */
	public const MAX_ALLOWED = 30;

	/** Where clearing the report list is recorded, with the list it cleared. */
	public const CLEAR_UNDO = 'harden_csp_report_only_clear_reports';

	/**
	 * The directives a source may be allowed on, as a browser reports them,
	 * and the directive this policy writes each into. A browser names the
	 * narrower `-elem` forms; written out, `script-src-elem` would take every
	 * script element from `script-src` and drop its `'unsafe-inline'`, and
	 * every inline script on the site would stop with it.
	 */
	private const ALLOWABLE = array(
		'script-src'      => 'script-src',
		'script-src-elem' => 'script-src',
		'style-src'       => 'style-src',
		'style-src-elem'  => 'style-src',
		'img-src'         => 'img-src',
		'font-src'        => 'font-src',
		'connect-src'     => 'connect-src',
		'frame-src'       => 'frame-src',
		'child-src'       => 'frame-src',
		'media-src'       => 'media-src',
		'manifest-src'    => 'manifest-src',
	);

	/** The directives the starting policy writes out itself. */
	private const WRITTEN = array( 'script-src', 'style-src', 'img-src', 'font-src' );

	/**
	 * Hosts that serve scripts from many projects. Allowing one for scripts
	 * lets any of them run here, and some can be made to run anything, so the
	 * owner is told before they agree.
	 *
	 * Written with their labels reversed, as `is_public_cdn()` compares them:
	 * the directory's checker reads a list of these hosts written plainly as
	 * code that loads from them, which this never does.
	 */
	private const PUBLIC_CDNS = array( 'net.jsdelivr.cdn', 'com.unpkg', 'com.cloudflare.cdnjs', 'com.googleapis.ajax', 'com.jquery.code', 'sh.esm', 'dev.skypack.cdn', 'io.jspm.ga', 'com.githack.raw', 'com.githack.rawcdn', 'io.statically.cdn', 'link.gitcdn' );

	/**
	 * The starting policy.
	 *
	 * Deliberately close to what a working WordPress site already does, so the
	 * first report names the genuinely surprising things rather than three
	 * hundred lines of ordinary. It is a starting point for a conversation
	 * with the owner's own site, not a recommendation to adopt as-is.
	 */
	public static function policy( ?array $state = null ): string {
		$self    = "'self'";
		$allowed = self::allowed( $state ?? \BetterShield\Hardening\Manager::instance()->item_state( 'csp_report_only' ) );
		$also    = static function ( string $directive ) use ( $allowed ): string {
			return isset( $allowed[ $directive ] ) ? ' ' . implode( ' ', $allowed[ $directive ] ) : '';
		};

		$directives = array(
			"default-src {$self}",
			// Inline script is where injected code lives, and also where
			// half of WordPress's own admin-facing output lives — which is
			// exactly the tension the report is there to measure.
			"script-src {$self} 'unsafe-inline'" . $also( 'script-src' ),
			"style-src {$self} 'unsafe-inline'" . $also( 'style-src' ),
			"img-src {$self} data:" . $also( 'img-src' ),
			"font-src {$self} data:" . $also( 'font-src' ),
		);

		// A directive the starting policy leaves to default-src is written
		// out only once a source is allowed on it, starting from what
		// default-src gave it, so allowing one source never takes 'self' away.
		foreach ( array_keys( $allowed ) as $directive ) {
			if ( ! in_array( $directive, self::WRITTEN, true ) ) {
				$directives[] = "{$directive} {$self}" . $also( $directive );
			}
		}

		$directives[] = "frame-ancestors {$self}";
		$directives[] = 'report-uri ' . self::report_url();

		return implode( '; ', $directives );
	}

	public static function report_url(): string {
		return rest_url( 'bettershield/v1/csp-report' );
	}

	/**
	 * Ask the report address the way a visitor's browser does, with no
	 * session, and keep whether it took the report. The daily task's.
	 *
	 * A quiet week is evidence only if a report could have arrived. A site
	 * whose REST API is closed to visitors answers every browser's report
	 * with a 401 before the route is reached, and so does a firewall rule
	 * against anonymous posts to it: nothing is stored, and the silence
	 * offered enforcement of a policy that would break what it never heard
	 * about. The report sent names no directive, so nothing is stored.
	 */
	public static function probe_reach(): void {
		if ( ! \BetterShield\Hardening\Manager::instance()->is_active( 'csp_report_only' ) ) {
			return;
		}

		$answer = array(
			'checked_at' => time(),
			'reachable'  => null,
			'code'       => 0,
		);

		$home = trailingslashit( home_url() );
		$url  = self::report_url();

		if ( str_starts_with( $url, $home ) ) {
			$response = \BetterShield\Support\Http::same_site_post(
				'/' . substr( $url, strlen( $home ) ),
				array(
					'headers' => array( 'Content-Type' => 'application/csp-report' ),
					'body'    => (string) wp_json_encode( array( 'csp-report' => array( 'document-uri' => $home ) ) ),
					'timeout' => 5,
				)
			);

			if ( ! is_wp_error( $response ) ) {
				$answer['code']      = (int) wp_remote_retrieve_response_code( $response );
				$answer['reachable'] = 204 === $answer['code'];
			}
		}

		update_option( self::REACH_OPTION, $answer, false );
	}

	/**
	 * Start the clock the promotion is measured against.
	 *
	 * Stamped here rather than lazily, because "how long has this been quiet"
	 * has no honest answer on a site that never recorded when it started
	 * watching — and the alternative, treating an absent stamp as "forever",
	 * would offer enforcement to a site that switched the item on a minute ago.
	 *
	 * @param array<string, mixed> $options
	 * @return array<string, mixed>
	 */
	public static function apply( array $options ): array {
		/*
		 * Unconditional, so the clock measures time this item was actually
		 * watching. Kept, it counted the months the item was switched off as
		 * evidence of a quiet report — so an owner who tried it, turned it
		 * off, and came back a year later could enforce a policy on the
		 * strength of observation that never happened.
		 *
		 * Only a genuine toggle reaches here: an already-active item is
		 * refused before this, and safe mode stands the item down and back up
		 * by another route that does not touch the stamp.
		 */
		update_option( self::OBSERVING_OPTION, time(), false );

		return array();
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function enforce( array $state ): void {
		self::$enforcing = self::MODE_ENFORCING === self::mode( $state );

		add_filter( 'wp_headers', array( self::class, 'add_header' ) );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function unenforce( array $state ): void {
		/*
		 * The mode is deliberately not reset here. Safe mode calls this to
		 * take every item's effect off for the duration, and a protection
		 * paused for a recovery window must come back configured exactly as it
		 * was — resetting here would quietly demote a site's enforced policy
		 * every time somebody used a recovery link.
		 */
		self::$enforcing = false;

		remove_filter( 'wp_headers', array( self::class, 'add_header' ) );
	}

	/**
	 * Which header this item is sending, from the item's own stored state.
	 *
	 * Absent means report-only, and that is what makes re-applying the item
	 * safe: applying rebuilds the state entry from scratch, so an item
	 * switched off and back on returns to watching rather than resuming
	 * enforcement of a policy the site may have drifted away from meanwhile.
	 *
	 * @param array<string, mixed> $state
	 */
	public static function mode( array $state ): string {
		return self::MODE_ENFORCING === ( $state['mode'] ?? '' ) ? self::MODE_ENFORCING : self::MODE_REPORT_ONLY;
	}

	/**
	 * @param array<string, string> $headers
	 * @return array<string, string>
	 */
	public static function add_header( $headers ): array {
		$headers = is_array( $headers ) ? $headers : array();

		/*
		 * Front-end responses only, as the card says. WordPress runs this
		 * filter inside wp-admin too: the Posts, Pages, Media and every post
		 * type list screen query through wp(), which sends headers. There the
		 * toolbar avatar and any plugin's admin assets were reported, holding
		 * enforcing back, and once enforcing they stopped loading.
		 */
		if ( is_admin() ) {
			return $headers;
		}

		/*
		 * One header or the other, never both: a browser given both enforces
		 * the first and reports on the second, which would mean a site paying
		 * the cost of enforcement while its reports described something else.
		 *
		 * Either way an existing header of that name is left alone — whether
		 * it is in the array WordPress is about to send or was already set
		 * with `header()` by the server or another plugin — because a policy
		 * somebody else set is their deliberate configuration, and
		 * overwriting it is how a security plugin breaks a site it was asked
		 * to protect.
		 */
		$name = self::$enforcing ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';

		if ( isset( $headers[ $name ] ) || SentHeaders::carries( $name ) ) {
			return $headers;
		}

		$headers[ $name ] = self::policy();

		return $headers;
	}

	/**
	 * Take one violation report from a browser.
	 *
	 * @param array<string, mixed> $report The `csp-report` object as posted.
	 */
	public static function receive( array $report ): void {
		// Only while the policy is actually being sent — read from the live
		// hook, never a stored toggle. With the item off no browser was ever
		// asked to report, so anything arriving is fabricated; storing it
		// would dress an unauthenticated POST up as telemetry on the card.
		// Safe mode unhooks the header, so reports pause with it.
		if ( ! has_filter( 'wp_headers', array( self::class, 'add_header' ) ) ) {
			return;
		}

		if ( ! self::within_rate() ) {
			return;
		}

		$directive = self::clean( (string) ( $report['effective-directive'] ?? $report['violated-directive'] ?? '' ) );
		$blocked   = self::origin_of( (string) ( $report['blocked-uri'] ?? '' ) );

		if ( '' === $directive ) {
			return;
		}

		/*
		 * Read, changed, written back, with no claim around it — deliberately.
		 * Browsers post here concurrently from every page view, and taking a
		 * mutex per report would put a database write in front of an
		 * unauthenticated endpoint that already has a cheaper defense. Two
		 * arriving together lose one increment, or one kind: this is a count
		 * of kinds seen, not an audit trail, and it is lossy by construction
		 * anyway — rate limited per source, capped, and evicted. The cap
		 * itself cannot be exceeded this way, because the whole array is
		 * replaced rather than appended to.
		 */
		$stored = get_option( self::REPORTS_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		// The origin, never the full address: a blocked URL can carry a query
		// string, and this plugin does not accumulate those from visitors.
		$key = $directive . ' ' . $blocked;

		// A full list makes room rather than turning the new kind away. The
		// cap is reachable by anybody who can POST, and a first-come list
		// that refuses everything after it is a list the site's own browsers
		// can be locked out of — which is also what pins the item, since a
		// policy is never promoted while anything is still open.
		while ( ! isset( $stored[ $key ] ) && count( $stored ) >= self::MAX_KINDS ) {
			$drop = self::least_recently_seen( $stored );

			if ( ! isset( $stored[ $drop ] ) ) {
				return;
			}

			unset( $stored[ $drop ] );
		}

		$stored[ $key ] = array(
			'directive' => $directive,
			'blocked'   => $blocked,
			'count'     => (int) ( $stored[ $key ]['count'] ?? 0 ) + 1,
			'last_at'   => time(),
		);

		update_option( self::REPORTS_OPTION, $stored, false );
	}

	/**
	 * The key of the kind nobody has seen for longest — the one to drop when
	 * room is needed. A row with no timestamp is oldest of all.
	 *
	 * @param array<string, array<string, mixed>> $stored
	 */
	private static function least_recently_seen( array $stored ): string {
		$oldest = '';
		$at     = PHP_INT_MAX;

		foreach ( $stored as $key => $row ) {
			$seen = isset( $row['last_at'] ) ? (int) $row['last_at'] : 0;

			if ( $seen < $at ) {
				$at     = $seen;
				$oldest = (string) $key;
			}
		}

		return $oldest;
	}

	/**
	 * What has been seen, loudest first, each with what the card may offer
	 * for it: the directive its source would be allowed on, or why not.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function reports(): array {
		$stored = get_option( self::REPORTS_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		$out = array();

		foreach ( $stored as $row ) {
			if ( is_array( $row ) ) {
				$row['allow'] = self::allowable( (string) ( $row['directive'] ?? '' ), (string) ( $row['blocked'] ?? '' ) );
				$out[]        = $row;
			}
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				return (int) ( $b['count'] ?? 0 ) <=> (int) ( $a['count'] ?? 0 );
			}
		);

		return $out;
	}

	public static function forget(): void {
		delete_option( self::REPORTS_OPTION );

		/*
		 * Clearing the list restarts the quiet window rather than satisfying
		 * it. An empty list is evidence only when it got that way by nothing
		 * being blocked; an empty list that got that way by somebody pressing
		 * a button is the evidence being erased, and treating the two the same
		 * would make the week-long wait a formality anybody could skip.
		 */
		update_option( self::OBSERVING_OPTION, time(), false );
	}

	/**
	 * Whether the site has earned the right to enforce, and if not, why not.
	 *
	 * @param bool $observe Start the clock for a policy applied before it had one. A read passes false and
	 *                      changes nothing: it reports what the stored clock says.
	 * @return array{ready: bool, quiet_days: int, needed: int, reason: ?string}
	 */
	public static function promotable( bool $observe = true ): array {
		$needed = self::QUIET_DAYS;
		$since  = (int) get_option( self::OBSERVING_OPTION, 0 );

		/*
		 * A site that applied this item before the promotion existed has no
		 * stamp, because `apply()` is the only thing that writes one and it
		 * does not re-run for an item that is already on. Left alone, exactly
		 * the sites with the most evidence behind them — months of an empty
		 * report list — were the ones that could never enforce, permanently
		 * and without being told why.
		 *
		 * The clock starts now rather than being backdated to the apply time.
		 * The honest claim is "nothing has been reported since we started
		 * measuring", and measuring started when this shipped; inventing a
		 * week of quiet from a period nothing was watching for would be the
		 * same overstatement the wait exists to prevent.
		 */
		if ( $observe && 0 === $since && \BetterShield\Hardening\Manager::instance()->is_active( 'csp_report_only' ) ) {
			$since = time();
			update_option( self::OBSERVING_OPTION, $since, false );
		}
		$days   = $since > 0 ? (int) floor( ( time() - $since ) / DAY_IN_SECONDS ) : 0;
		$open   = count( self::reports() );

		if ( $open > 0 ) {
			return array(
				'ready'      => false,
				'quiet_days' => 0,
				'needed'     => $needed,
				'reason'     => sprintf(
					/* translators: %d: number of distinct kinds of violation. */
					_n(
						'Turning this on now would block %d item visitors need. Fix or allow it first.',
						'Turning this on now would block %d items visitors need. Fix or allow them first.',
						$open,
						'bettershield'
					),
					$open
				),
			);
		}

		if ( 0 === $since ) {
			return array(
				'ready'      => false,
				'quiet_days' => 0,
				'needed'     => $needed,
				'reason'     => __( 'It has not been watching long enough yet.', 'bettershield' ),
			);
		}

		if ( $days < $needed ) {
			return array(
				'ready'      => false,
				'quiet_days' => $days,
				'needed'     => $needed,
				'reason'     => sprintf(
					/* translators: 1: days watched so far, 2: days required. */
					__( 'Nothing has been reported for %1$d of the %2$d days needed.', 'bettershield' ),
					$days,
					$needed
				),
			);
		}

		/*
		 * Silence counts only once reports are known to get through. A
		 * refusal of the probe is the site's own REST settings or a rule in
		 * front of it; no answer yet is a probe that has not run. A server
		 * that cannot ask itself at all keeps the plain week, as before: it
		 * could never be shown either way. So does one whose schedule never
		 * runs the probe, once its appointment is a whole cycle past: waiting
		 * there was waiting for good.
		 */
		$reach = get_option( self::REACH_OPTION, null );

		if ( ! is_array( $reach ) && ! self::reach_check_overdue() ) {
			return array(
				'ready'      => false,
				'quiet_days' => $days,
				'needed'     => $needed,
				'reason'     => __( 'Waiting for the daily check that browser reports can reach this site.', 'bettershield' ),
			);
		}

		if ( is_array( $reach ) && false === ( $reach['reachable'] ?? null ) ) {
			return array(
				'ready'      => false,
				'quiet_days' => $days,
				'needed'     => $needed,
				'reason'     => __( 'Reports cannot reach this site (usually a firewall or a closed REST API). Enforcing waits until they can.', 'bettershield' ),
			);
		}

		return array(
			'ready'      => true,
			'quiet_days' => $days,
			'needed'     => $needed,
			'reason'     => null,
		);
	}

	/**
	 * Whether the reach probe has missed a whole cycle of its own: an
	 * appointment one interval past and still not kept. The schedule moves
	 * an appointment only when it keeps it, so this is the probe that is not
	 * going to run, rather than one that has not run yet. Read off the
	 * runner's own record of the task; no appointment at all is one the next
	 * page load puts on the schedule, so it is not overdue.
	 */
	private static function reach_check_overdue(): bool {
		$task = \BetterShield\Cron\Runner::instance()->tasks()['bettershield_csp_reach'] ?? null;

		if ( null === $task || 0 === $task['next'] || null === $task['interval'] ) {
			return false;
		}

		return time() - $task['next'] > $task['interval'];
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function actions(): array {
		$state   = \BetterShield\Hardening\Manager::instance()->item_state( 'csp_report_only' );
		$actions = array();

		if ( self::MODE_ENFORCING === self::mode( $state ) ) {
			$actions[] = array(
				'key'         => 'report_only',
				'label'       => __( 'Back to Test Mode', 'bettershield' ),
				'description' => __( 'Stops enforcing. Anything the policy was blocking loads again at once.', 'bettershield' ),
			);
		} else {
			$promotable = self::promotable();
			$actions[]  = array(
				'key'         => 'enforce',
				'label'       => __( 'Turn the Policy On', 'bettershield' ),
				'description' => $promotable['ready']
					? sprintf(
						/* translators: %d: number of days nothing has been reported. */
						__( 'Nothing has been reported for %d days. Anything the policy blocks will stop loading. Back to Test Mode undoes it.', 'bettershield' ),
						$promotable['quiet_days']
					)
					: (string) $promotable['reason'],
				'available'   => $promotable['ready'],
			);
		}

		if ( array() !== self::reports() ) {
			$actions[] = array(
				'key'         => 'clear_reports',
				'label'       => __( 'Clear This List', 'bettershield' ),
				'description' => __( 'Empties the list and starts the 7-day quiet period over. Put the List Back undoes it.', 'bettershield' ),
			);
		}

		if ( array() !== Ledger::open_tokens( self::CLEAR_UNDO, 1 ) ) {
			$actions[] = array(
				'key'         => 'restore_reports',
				'label'       => __( 'Put the List Back', 'bettershield' ),
				'description' => __( 'Restores the list you last cleared, plus anything reported since.', 'bettershield' ),
			);
		}

		return $actions;
	}

	/**
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $args  For allowing and removing a source: the reported directive and the source.
	 * @return array<string, mixed>|\WP_Error
	 */
	public static function act( string $action, array $state, array $args = array() ) {
		if ( 'allow_source' === $action ) {
			return self::allow_source( $state, $args );
		}

		if ( 'remove_source' === $action ) {
			return self::remove_source( $state, $args );
		}

		if ( 'clear_reports' === $action ) {
			return self::clear_reports();
		}

		if ( 'restore_reports' === $action ) {
			return self::restore_reports();
		}

		if ( 'report_only' === $action ) {
			Writer::instance()->record(
				'csp_report_only_restored',
				Writer::SEVERITY_INFO,
				array(
					'object_type' => 'hardening',
					'object_id'   => 'csp_report_only',
				)
			);

			return array(
				// Stated rather than left to be inferred: an absent mode key
				// means report-only here, so an undo row built from the keys
				// that happen to exist would carry nothing at all.
				'prior' => array( 'mode' => self::mode( $state ) ),
				'state' => array( 'mode' => self::MODE_REPORT_ONLY ),
				'note'  => __( 'Back to watching. Nothing a visitor loads is being blocked.', 'bettershield' ),
			);
		}

		if ( 'enforce' !== $action ) {
			return new \WP_Error( 'bettershield_unknown_action', __( 'This item has no such action.', 'bettershield' ), array( 'status' => 404 ) );
		}

		/*
		 * Re-checked here rather than trusted from the button. The screen
		 * decides what to offer; this decides what may happen, and between the
		 * two a report can arrive from any visitor's browser. A caller that
		 * skipped the screen entirely gets the same answer.
		 */
		$promotable = self::promotable();

		if ( ! $promotable['ready'] ) {
			return new \WP_Error(
				'bettershield_csp_not_ready',
				(string) $promotable['reason'],
				array( 'status' => 409 )
			);
		}

		Writer::instance()->record(
			'csp_enforced',
			Writer::SEVERITY_HIGH,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'csp_report_only',
				'context'     => array( 'quiet_days' => $promotable['quiet_days'] ),
			)
		);

		return array(
			'prior' => array( 'mode' => self::mode( $state ) ),
			'state' => array( 'mode' => self::MODE_ENFORCING ),
			'note'  => __( 'Enforcing. Browsers now apply the policy you were watching.', 'bettershield' ),
		);
	}

	/**
	 * The actions that tighten the policy or put its evidence back, which the
	 * password gate does not stand in front of: it asks before a protection
	 * comes down, never before one goes up.
	 */
	public static function adds_protection( string $action ): bool {
		return in_array( $action, array( 'enforce', 'remove_source', 'restore_reports' ), true );
	}

	/**
	 * This source as the policy holds it, when it is on the allowed list.
	 *
	 * @return array{directive: string, source: string}|null
	 */
	public static function allowed_source( string $directive, string $source ): ?array {
		$directive = self::ALLOWABLE[ self::clean( $directive ) ] ?? '';
		$source    = strtolower( trim( $source ) );
		$allowed   = self::allowed( \BetterShield\Hardening\Manager::instance()->item_state( 'csp_report_only' ) );

		return '' !== $directive && in_array( $source, $allowed[ $directive ] ?? array(), true ) ? array( 'directive' => $directive, 'source' => $source ) : null;
	}

	/**
	 * The sources allowed now, one row each, for the card.
	 *
	 * @return array<int, array{directive: string, source: string}>
	 */
	public static function allowed_sources(): array {
		$rows = array();

		foreach ( self::allowed( \BetterShield\Hardening\Manager::instance()->item_state( 'csp_report_only' ) ) as $directive => $sources ) {
			foreach ( $sources as $source ) {
				$rows[] = array(
					'directive' => $directive,
					'source'    => $source,
				);
			}
		}

		return $rows;
	}

	/**
	 * The sources the owner allowed, by directive, read back through the same
	 * rules that let them in and in a fixed order, so the policy watched and
	 * the policy enforced are the same bytes.
	 *
	 * @param array<string, mixed> $state
	 * @return array<string, string[]>
	 */
	public static function allowed( array $state ): array {
		$stored  = isset( $state['allowed'] ) && is_array( $state['allowed'] ) ? $state['allowed'] : array();
		$allowed = array();

		foreach ( $stored as $directive => $sources ) {
			if ( ! is_string( $directive ) || ! in_array( $directive, self::ALLOWABLE, true ) || ! is_array( $sources ) ) {
				continue;
			}

			foreach ( $sources as $source ) {
				if ( is_string( $source ) && null === self::source_problem( $source ) ) {
					$allowed[ $directive ][] = $source;
				}
			}
		}

		foreach ( $allowed as $directive => $sources ) {
			$sources = array_values( array_unique( $sources ) );
			sort( $sources );
			$allowed[ $directive ] = $sources;
		}

		ksort( $allowed );

		return $allowed;
	}

	/**
	 * What the card may offer for one reported row.
	 *
	 * @return array{directive: ?string, refused: ?string, warning: ?string}
	 */
	private static function allowable( string $reported, string $source ): array {
		$directive = self::ALLOWABLE[ $reported ] ?? null;
		$source    = strtolower( $source );

		if ( null === $directive ) {
			return array(
				'directive' => null,
				'refused'   => sprintf(
					/* translators: %s: a Content-Security-Policy directive. */
					__( 'A source cannot be allowed on %s here.', 'bettershield' ),
					$reported
				),
				'warning'   => null,
			);
		}

		$problem = self::source_problem( $source );

		if ( null !== $problem ) {
			return array(
				'directive' => $directive,
				'refused'   => $problem,
				'warning'   => null,
			);
		}

		return array(
			'directive' => $directive,
			'refused'   => null,
			'warning'   => 'script-src' === $directive && self::is_public_cdn( $source )
				? __( 'Allowing this public code site removes most of the protection. Hosting the file on your own site is safer.', 'bettershield' )
				: null,
		);
	}

	/** Whether a source is one of the hosts that serve scripts from many projects. */
	private static function is_public_cdn( string $source ): bool {
		$host = strtolower( (string) wp_parse_url( $source, PHP_URL_HOST ) );

		return in_array( implode( '.', array_reverse( explode( '.', $host ) ) ), self::PUBLIC_CDNS, true );
	}

	/**
	 * Why a source cannot be allowed with one click, or null when it can:
	 * only an address such as https://example.com. Inline script and eval are
	 * code the page carries, and allowing either allows injected script too;
	 * a bare scheme or a wildcard is the whole internet.
	 */
	private static function source_problem( string $source ): ?string {
		if ( in_array( $source, array( 'inline', 'eval', 'wasm-eval' ), true ) ) {
			return __( 'Inline script and eval cannot be allowed. Move the code into a file on this site.', 'bettershield' );
		}

		// A content policy names a host by name or IPv4 address, never IPv6:
		// browsers drop a source written that way, so allowing it would
		// change nothing.
		if ( 1 === preg_match( '#^[a-z]+://\[#', $source ) ) {
			return __( 'A content policy cannot name an IPv6 address. Serve the file from a host name instead.', 'bettershield' );
		}

		if ( 1 !== preg_match( '#^(https?|wss?)://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$#', $source ) ) {
			return __( 'Only an address such as https://example.com can be allowed, not a bare scheme, wildcard or blank.', 'bettershield' );
		}

		return null;
	}

	/**
	 * Add a reported source to the directive it was reported on. Only a source
	 * the reports name. The rows it answers go, and the quiet week starts
	 * again, once the change is written.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function allow_source( array $state, array $args ) {
		$source  = strtolower( trim( (string) ( $args['source'] ?? '' ) ) );
		$verdict = self::allowable( self::clean( (string) ( $args['directive'] ?? '' ) ), $source );

		if ( null !== $verdict['refused'] || null === $verdict['directive'] ) {
			return new \WP_Error( 'bettershield_csp_not_allowable', (string) $verdict['refused'], array( 'status' => 400 ) );
		}

		$directive = (string) $verdict['directive'];

		if ( array() === self::rows_for( $directive, $source ) ) {
			return new \WP_Error( 'bettershield_csp_not_reported', __( 'That source is no longer listed as blocked. Reload and allow what the list shows.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$allowed = self::allowed( $state );
		$next    = $allowed;

		if ( ! in_array( $source, $next[ $directive ] ?? array(), true ) ) {
			if ( array_sum( array_map( 'count', $allowed ) ) >= self::MAX_ALLOWED ) {
				return new \WP_Error(
					'bettershield_csp_too_many_sources',
					sprintf(
						/* translators: %d: the most sources the policy may be widened by. */
						__( 'The policy already allows %d sources, the limit. Remove one before allowing another.', 'bettershield' ),
						self::MAX_ALLOWED
					),
					array( 'status' => 409 )
				);
			}

			$next[ $directive ][] = $source;
		}

		$warning = $verdict['warning'];

		return array(
			// Stated: an absent list means none, and a row built from the keys
			// that happen to exist would carry nothing to put back.
			'prior'   => array( 'allowed' => $allowed ),
			'state'   => array( 'allowed' => self::allowed( array( 'allowed' => $next ) ) ),
			'warning' => $warning,
			'note'    => sprintf(
				/* translators: 1: an address such as https://example.com, 2: a Content-Security-Policy directive. */
				__( '%1$s is allowed for %2$s. The 7-day quiet period starts over.', 'bettershield' ),
				$source,
				$directive
			),
			'after'   => static function () use ( $directive, $source, $warning ): void {
				self::drop_rows( $directive, $source );
				update_option( self::OBSERVING_OPTION, time(), false );

				Writer::instance()->record(
					'csp_source_allowed',
					Writer::SEVERITY_MEDIUM,
					array(
						'object_type' => 'hardening',
						'object_id'   => 'csp_report_only',
						'context'     => array(
							'directive' => $directive,
							'source'    => $source,
							'warned'    => null !== $warning,
						),
					)
				);
			},
		);
	}

	/**
	 * Take an allowed source back off: the way back from allowing it.
	 *
	 * @param array<string, mixed> $state
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function remove_source( array $state, array $args ) {
		$directive = self::ALLOWABLE[ self::clean( (string) ( $args['directive'] ?? '' ) ) ] ?? '';
		$source    = strtolower( trim( (string) ( $args['source'] ?? '' ) ) );
		$allowed   = self::allowed( $state );

		if ( '' === $directive || ! in_array( $source, $allowed[ $directive ] ?? array(), true ) ) {
			return new \WP_Error( 'bettershield_csp_not_allowed', __( 'That source is not on the allowed list.', 'bettershield' ), array( 'status' => 404 ) );
		}

		$next               = $allowed;
		$next[ $directive ] = array_values( array_diff( $next[ $directive ], array( $source ) ) );

		return array(
			'prior' => array( 'allowed' => $allowed ),
			'state' => array( 'allowed' => self::allowed( array( 'allowed' => $next ) ) ),
			'note'  => sprintf(
				/* translators: 1: an address such as https://example.com, 2: a Content-Security-Policy directive. */
				__( '%1$s is no longer allowed for %2$s. Anything loading from there is reported again. The 7-day quiet period starts over.', 'bettershield' ),
				$source,
				$directive
			),
			'after' => static function () use ( $directive, $source ): void {
				update_option( self::OBSERVING_OPTION, time(), false );

				Writer::instance()->record(
					'csp_source_removed',
					Writer::SEVERITY_INFO,
					array(
						'object_type' => 'hardening',
						'object_id'   => 'csp_report_only',
						'context'     => array(
							'directive' => $directive,
							'source'    => $source,
						),
					)
				);
			},
		);
	}

	/**
	 * Clear the list of what was blocked, for a cause the owner fixed or a
	 * report that was never real: the route takes posts nobody signed, so one
	 * invented report could otherwise hold enforcing back for good. The list
	 * goes into the undo ledger first, and the quiet week starts again.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function clear_reports() {
		$rows = get_option( self::REPORTS_OPTION, array() );
		$rows = is_array( $rows ) ? $rows : array();

		if ( array() === $rows ) {
			return new \WP_Error( 'bettershield_csp_nothing_to_clear', __( 'The list is already empty.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$token = Ledger::open(
			self::CLEAR_UNDO,
			array(
				'reports'         => $rows,
				'observing_since' => (int) get_option( self::OBSERVING_OPTION, 0 ),
			),
			array( 'reports' => array() )
		);

		if ( null === $token ) {
			return new \WP_Error( 'bettershield_ledger_failed', __( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ), array( 'status' => 500 ) );
		}

		self::forget();

		Writer::instance()->record(
			'csp_reports_cleared',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'csp_report_only',
				'context'     => array( 'kinds' => count( $rows ) ),
			)
		);

		return array(
			// Its own row is written above, with the list in it; the item's
			// stored state is not what changed.
			'ledger'     => false,
			'undo_token' => $token,
			'note'       => __( 'Cleared. The 7-day quiet period starts over, and anything still blocked is reported again.', 'bettershield' ),
		);
	}

	/**
	 * Put back the list last cleared, beside whatever has been reported since.
	 *
	 * @return array<string, mixed>|\WP_Error
	 */
	private static function restore_reports() {
		$tokens = Ledger::open_tokens( self::CLEAR_UNDO, 1 );
		$entry  = array() === $tokens ? null : Ledger::find( $tokens[0] );
		$prior  = null !== $entry && is_array( $entry->prior_state ) ? $entry->prior_state : null;

		if ( null === $prior ) {
			return new \WP_Error( 'bettershield_csp_nothing_to_restore', __( 'There is no cleared list to put back.', 'bettershield' ), array( 'status' => 409 ) );
		}

		$now      = get_option( self::REPORTS_OPTION, array() );
		$now      = is_array( $now ) ? $now : array();
		$restored = 0;

		foreach ( (array) ( $prior['reports'] ?? array() ) as $key => $row ) {
			if ( ! is_array( $row ) || '' === (string) ( $row['directive'] ?? '' ) ) {
				continue;
			}

			$key = (string) $key;

			if ( isset( $now[ $key ] ) ) {
				$now[ $key ]['count']   = (int) ( $now[ $key ]['count'] ?? 0 ) + (int) ( $row['count'] ?? 0 );
				$now[ $key ]['last_at'] = max( (int) ( $now[ $key ]['last_at'] ?? 0 ), (int) ( $row['last_at'] ?? 0 ) );
			} else {
				$now[ $key ] = array(
					'directive' => (string) $row['directive'],
					'blocked'   => (string) ( $row['blocked'] ?? '' ),
					'count'     => (int) ( $row['count'] ?? 0 ),
					'last_at'   => (int) ( $row['last_at'] ?? 0 ),
				);
			}

			++$restored;
		}

		while ( count( $now ) > self::MAX_KINDS ) {
			unset( $now[ self::least_recently_seen( $now ) ] );
		}

		update_option( self::REPORTS_OPTION, $now, false );

		// The clock it had, where rows came back: with any row open the policy
		// is held at watching whatever the clock says, so the earlier start
		// gives nothing away.
		$since = (int) ( $prior['observing_since'] ?? 0 );

		if ( $restored > 0 && $since > 0 && $since < (int) get_option( self::OBSERVING_OPTION, 0 ) ) {
			update_option( self::OBSERVING_OPTION, $since, false );
		}

		Ledger::mark_reverted( $tokens[0] );

		Writer::instance()->record(
			'csp_reports_restored',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'hardening',
				'object_id'   => 'csp_report_only',
				'context'     => array( 'kinds' => $restored ),
			)
		);

		return array(
			'ledger' => false,
			'note'   => __( 'The list you cleared is back.', 'bettershield' ),
		);
	}

	/**
	 * The stored rows a source allowed on a directive answers: every directive
	 * a browser names that this policy writes as that one.
	 *
	 * @return string[]
	 */
	private static function rows_for( string $directive, string $source ): array {
		$stored = get_option( self::REPORTS_OPTION, array() );
		$keys   = array();

		foreach ( is_array( $stored ) ? $stored : array() as $key => $row ) {
			if (
				is_array( $row )
				&& ( self::ALLOWABLE[ (string) ( $row['directive'] ?? '' ) ] ?? null ) === $directive
				&& strtolower( (string) ( $row['blocked'] ?? '' ) ) === $source
			) {
				$keys[] = (string) $key;
			}
		}

		return $keys;
	}

	private static function drop_rows( string $directive, string $source ): void {
		$stored = get_option( self::REPORTS_OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();

		foreach ( self::rows_for( $directive, $source ) as $key ) {
			unset( $stored[ $key ] );
		}

		update_option( self::REPORTS_OPTION, $stored, false );
	}

	/**
	 * @param array<string, mixed> $state
	 */
	public static function summary( array $state ): ?string {
		// Live state: switched off, nothing is watched or enforced. Reports
		// kept from while it was on stay on the card's own list.
		if ( empty( $state['active'] ) ) {
			return null;
		}

		$count = count( self::reports() );

		if ( self::MODE_ENFORCING === self::mode( $state ) ) {
			return 0 === $count
				? __( 'Enforcing. Nothing has been reported since.', 'bettershield' )
				: sprintf(
					/* translators: %d: number of distinct kinds of violation. */
					_n( 'Enforcing, and %d kind of thing is being blocked.', 'Enforcing, and %d kinds of thing are being blocked.', $count, 'bettershield' ),
					$count
				);
		}

		if ( 0 === $count ) {
			$promotable = self::promotable();

			return $promotable['ready']
				? __( 'Watching, and ready to enforce.', 'bettershield' )
				: __( 'Watching. Nothing has been reported yet.', 'bettershield' );
		}

		return sprintf(
			/* translators: %d: number of distinct kinds of violation. */
			_n( '%d kind of thing would have been blocked.', '%d kinds of thing would have been blocked.', $count, 'bettershield' ),
			$count
		);
	}

	public static function conflict(): ?string {
		return __( 'After a quiet week, you can turn on blocking and switch back anytime.', 'bettershield' );
	}

	/**
	 * Whether this connection has sent more than a page's worth.
	 *
	 * Browsers post here unauthenticated from every page view, which is the
	 * same unbounded-write shape that grew `wp_options` on the passkey
	 * challenge route. Counted against the truncated, HMACed address used
	 * everywhere else — never a full one.
	 */
	private static function within_rate(): bool {
		// The trusted-proxy list is passed for the same reason every other
		// caller passes it: without it, a site behind a named proxy resolves
		// every visitor to the proxy and puts them all in one bucket, so the
		// cap silences the reports of everybody at once. Where the topology
		// cannot be resolved even with the list, the same thing was true and
		// the list could not help — so that case counts site-wide, with a cap
		// to match, rather than silencing a whole site's browsers after
		// twenty page views.
		//
		// A source, too, only while the address is not the request's own to
		// write. On an edge nobody has vouched for, the client address is a
		// header: one connection rotating it had a fresh bucket per value and
		// went on writing here without limit. What counts there is the address
		// the request really arrived from — the one half of the pair it did
		// not choose — and everybody that edge forwards shares it, so it
		// counts against the shared cap.
		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		$bucket = ClientIp::rate_bucket( $resolved, 'csprate', self::MAX_PER_SOURCE );

		return Claim::bump( $bucket['key'], self::RATE_SECONDS ) <= $bucket['cap'];
	}

	private static function clean( string $value ): string {
		return substr( preg_replace( '/[^a-z0-9\\-]/i', '', $value ) ?? '', 0, 40 );
	}

	/**
	 * The scheme, host and port of a blocked address, and nothing else. The
	 * port only when the address names one: a policy that names a host allows
	 * it on the scheme's own port alone, so a source kept without its port
	 * would be allowed and still blocked.
	 */
	private static function origin_of( string $uri ): string {
		if ( '' === $uri ) {
			return '';
		}

		// Browsers send these bare for inline and eval violations.
		if ( in_array( $uri, array( 'inline', 'eval', 'self', 'data' ), true ) ) {
			return $uri;
		}

		$host = (string) wp_parse_url( $uri, PHP_URL_HOST );

		// No host — or a "host" past the DNS length limit, which is not an
		// address but a payload. wp_parse_url() accepts hosts of any length,
		// and an uncapped one turned this option into an unauthenticated
		// place to store hundreds of kilobytes per row.
		//
		// The character class is the same reasoning applied to content rather
		// than length: wp_parse_url() hands back whatever sat between the
		// scheme and the path, markup included, and this string is written to
		// an option an unauthenticated POST fills and the owner reads. The
		// class keeps everything a real address can be — punycode for IDN,
		// bracketed IPv6 literals, a port — and drops the rest.
		if ( '' === $host || 1 !== preg_match( '/^[a-z0-9.\\-:\\[\\]]{1,253}$/i', $host ) ) {
			return '';
		}

		$scheme = substr( (string) wp_parse_url( $uri, PHP_URL_SCHEME ), 0, 20 );
		$port   = (int) wp_parse_url( $uri, PHP_URL_PORT );

		return ( '' !== $scheme ? $scheme . '://' : '' ) . $host . ( $port > 0 && $port <= 65535 ? ':' . $port : '' );
	}
}
