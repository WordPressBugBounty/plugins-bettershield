<?php
/**
 * The counters standing in front of the assistant endpoint's three open doors.
 *
 * The credentials this endpoint accepts are 256-bit secrets, so guessing one
 * is not the risk. What this stops is cheaper: a flood of wrong tokens
 * burning CPU on a hash comparison and filling the log, a client left holding
 * a rotated-away token retrying forever, and the two routes that have to answer
 * a caller holding nothing at all — registration and the token exchange —
 * being used to rewrite a stored option as fast as a script can post.
 *
 * Counted under the identity every other refusal in this plugin counts under,
 * and keyed the same way: a keyed digest under the plugin's own secret,
 * because a stored key is a record and an unsalted digest of the space an
 * address occupies is a reversible one.
 *
 * Which identity that is, is not this file's call. An address identifies a
 * source only while the topology says so, so the volume counts go through the
 * shared-bucket rule and the failure count through the lockout's own pairing:
 * behind an unnamed proxy every visitor arrives as one address, and an edge
 * nobody has vouched for hands over an address the request itself wrote.
 *
 * A request carrying NO credential never reaches the failure counter. An
 * unauthenticated call is the opening move of the browser sign-in flow: the
 * client is asking for the challenge that tells it where to authenticate, not
 * guessing. Counting those would wall off every well-behaved client after a
 * handful of ordinary discovery probes, which is a failure mode with a body
 * count in the wild. Neither does a credential this site accepts: the lockout
 * is consulted only for a caller that has already been refused, so the site's
 * own connected assistant is never turned away by a stranger's mistakes.
 *
 * The window is fixed from the first failure. A failure inside an open window
 * never extends it, so waiting one window out is always enough — otherwise a
 * stranded client retrying every few minutes re-arms its own lockout for as
 * long as it keeps trying, which is exactly what a stranded client does.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

use BetterShield\Events\Writer;
use BetterShield\Login\Protection;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RateLimiter {

	/** Failures inside one window before the network is refused outright. */
	public const DEFAULT_MAX_FAILURES = 10;

	/** How long the window is, and how long the lockout lasts with it. */
	public const DEFAULT_WINDOW_SECONDS = 900;

	/** How many registrations one network may attempt inside a window. */
	public const DEFAULT_MAX_REGISTRATIONS = 5;

	/** How many token exchanges one network may fail inside a window. */
	public const DEFAULT_MAX_TOKEN_FAILURES = 10;

	/**
	 * How many tokens one application may be issued inside a window.
	 *
	 * A connected client refreshes once an hour, so this is headroom by an
	 * order of magnitude and a connection being set up never approaches it.
	 * What it bounds is the other case: a client holding a live grant rotating
	 * as fast as it can post, each rotation appending a digest to a stored
	 * option that every authenticated call reads.
	 */
	public const DEFAULT_MAX_TOKEN_ISSUES = 10;

	/** The window both of the two above are counted in. */
	public const DEFAULT_ANONYMOUS_WINDOW_SECONDS = 900;

	/** The claim namespace the failures are counted under. */
	private const COUNT_KEY = 'mcp_auth_fail_';

	/** The claim namespace that keeps one refusal row per network per hour. */
	private const NOTE_KEY = 'mcp_auth_note_';

	/** The claim namespace that keeps one lockout row per network per window. */
	private const LOCKOUT_KEY = 'mcp_locked_';

	/**
	 * The claim namespace registrations are counted under. No trailing
	 * separator: the bucket rule completes the key, and answers with the bare
	 * prefix where the topology gives it nobody to count separately.
	 */
	private const REGISTER_KEY = 'mcp_reg';

	/** The claim namespace failed token exchanges are counted under. */
	private const TOKEN_KEY = 'mcp_token_fail';

	/** The claim namespace issued tokens are counted under, per application. */
	private const ISSUE_KEY = 'mcp_token_issue_';

	/** The resolved address for this request, which cannot change inside one. */
	private static array $resolved = array();

	/**
	 * Whether this network is currently refused.
	 *
	 * Asked only about a caller whose credential has already been rejected, so
	 * a credential this site recognizes is never refused by this. A count that
	 * cannot be read is not a lockout: the caps standing in front of a
	 * credential refuse on a null, and this one is not that — it decides
	 * whether to refuse somebody who may be legitimate, so an unreadable
	 * counter lets them through and the comparison itself protects the site.
	 */
	public static function is_locked(): bool {
		list( $max ) = self::limits();

		return Claim::count( self::COUNT_KEY . self::failure_bucket() ) >= $max;
	}

	/**
	 * Count one failure, and say whether it closed the door.
	 *
	 * Called only where a credential was presented and rejected.
	 */
	public static function record_failure(): bool {
		list( $max, $window ) = self::limits();

		$bucket = self::failure_bucket();
		$count  = Claim::bump( self::COUNT_KEY . $bucket, $window );

		if ( $count < $max ) {
			self::note_refusal( $bucket, 'credential_refused', array() );

			return false;
		}

		// One row per network per window: the door closing is the event, and
		// a client that keeps retrying against a closed door is not a second
		// one.
		if ( Claim::claim( self::LOCKOUT_KEY . $bucket, $window ) ) {
			Writer::instance()->record(
				'mcp_locked_out',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'mcp',
					'object_id'   => 'endpoint',
					'context'     => array(
						'failures' => $count,
						'minutes'  => (int) round( $window / MINUTE_IN_SECONDS ),
					),
				)
			);
		}

		return true;
	}

	/**
	 * Clear the counter for this network. Called on a successful sign-in, so
	 * a client that finally presents the right credential is not still
	 * carrying its own earlier mistakes.
	 */
	public static function clear(): void {
		$key = self::COUNT_KEY . self::failure_bucket();

		/*
		 * Only where there is something to clear. This runs on every accepted
		 * credential, on the one request an assistant is waiting for, and an
		 * unconditional DELETE is a write against a row that on a healthy
		 * connection has never existed.
		 */
		if ( Claim::count( $key ) < 1 ) {
			return;
		}

		Claim::release( $key );
	}

	/**
	 * How long to say the caller should wait.
	 *
	 * The window length rather than what is left of it: the claim records an
	 * expiry it does not hand back, and overstating the wait by a few minutes
	 * is the safe direction for a value a client uses to schedule a retry.
	 */
	public static function retry_after(): int {
		return self::limits()[1];
	}

	/* ---- the two routes that answer a caller holding nothing ------------------- */

	/**
	 * Whether this network may register another application right now.
	 *
	 * Registration has to be open to a caller with no credential — a client
	 * cannot introduce itself otherwise — so every attempt is a write to a
	 * stored option made by a stranger. The connection switch decides whether
	 * that is possible at all; this bounds how fast it can be done while the
	 * switch is on. Attempts are counted, not successes: a script posting
	 * rubbish costs the same write.
	 */
	public static function registration_allowed(): bool {
		list( $max, $window ) = self::anonymous_limits();

		$bucket = self::volume_bucket( self::REGISTER_KEY, $max );

		return Claim::bump( $bucket['key'], $window ) <= $bucket['cap'];
	}

	/**
	 * Whether this network has failed the token exchange too often.
	 *
	 * Read before the exchange and counted only after one fails, so a client
	 * refreshing normally never approaches it however busy it is.
	 */
	public static function token_exchange_allowed(): bool {
		$bucket = self::volume_bucket( self::TOKEN_KEY, self::anonymous_limits()[2] );

		return Claim::count( $bucket['key'] ) < $bucket['cap'];
	}

	public static function record_token_failure(): void {
		list( , $window, $max ) = self::anonymous_limits();

		Claim::bump( self::volume_bucket( self::TOKEN_KEY, $max )['key'], $window );
	}

	/**
	 * Whether this application may be issued another token right now.
	 *
	 * Counted per application rather than per network, because the thing being
	 * bounded is what one grant can make this site store: the network a client
	 * refreshes from is not the interesting fact, and two assistants behind
	 * one address are not each other's problem.
	 */
	public static function token_issue_allowed( string $client_id ): bool {
		return Claim::count( self::ISSUE_KEY . $client_id ) < self::anonymous_limits()[3];
	}

	/** Count one token this application was actually issued. */
	public static function record_token_issue( string $client_id ): void {
		list( , $window ) = self::anonymous_limits();

		Claim::bump( self::ISSUE_KEY . $client_id, $window );
	}

	/** How long a throttled anonymous caller is told to wait. */
	public static function anonymous_retry_after(): int {
		return self::anonymous_limits()[1];
	}

	/**
	 * One activity row per network per hour for a refusal at this endpoint.
	 *
	 * A wrong token is worth recording and not worth recording repeatedly: a
	 * misconfigured client produces one every few seconds, and a log that
	 * fills with them is a log nobody reads. Public so the OAuth server can
	 * record a refusal of its own — a refresh token coming back after it was
	 * replaced — through the same throttle rather than beside it.
	 *
	 * @param array<string, mixed> $context
	 */
	public static function note_refusal_reason( string $reason, array $context = array() ): void {
		self::note_refusal( self::failure_bucket(), $reason, $context );
	}

	/**
	 * @param array<string, mixed> $context
	 */
	private static function note_refusal( string $bucket, string $reason, array $context ): void {
		if ( ! Claim::claim( self::NOTE_KEY . $reason . '_' . $bucket, HOUR_IN_SECONDS ) ) {
			return;
		}

		Writer::instance()->record(
			'mcp_auth_refused',
			Writer::SEVERITY_LOW,
			array(
				'object_type' => 'mcp',
				'object_id'   => 'endpoint',
				'context'     => array( 'reason' => $reason ) + $context,
			)
		);
	}

	/**
	 * Who is connecting, asked once. An address cannot change inside one
	 * request, and this is read on several paths through it.
	 *
	 * @return array{ip: string, method: string, confident: bool, ignored_headers: bool, paired_with: ?string}
	 */
	private static function resolved(): array {
		if ( array() === self::$resolved ) {
			self::$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		}

		return self::$resolved;
	}

	/**
	 * The key a run of refused credentials is counted under.
	 *
	 * The same key a failed sign-in is filed under, pairing included: where
	 * the client address is one the request wrote for itself, the count
	 * accumulates against that claim carried by the connection that made it,
	 * so nobody can aim this endpoint's refusals at an address they name. An
	 * address that cannot be parsed still gets a key, or a client with no
	 * readable address would be exempt from every count here.
	 */
	private static function failure_bucket(): string {
		return ClientIp::lockout_hmac( self::resolved() );
	}

	/**
	 * Where a volume cap counts this request, and the cap it counts against.
	 *
	 * These two bound what a caller holding no credential may make this site
	 * store, so unlike the lockout they cannot stand down when the topology is
	 * unresolvable. They count in one site-wide bucket with a proportionally
	 * larger cap instead — nobody singled out, and the total bounded harder
	 * than one bucket per claimed source ever bounded it.
	 *
	 * @return array{key: string, cap: int, shared: bool}
	 */
	private static function volume_bucket( string $prefix, int $cap ): array {
		return ClientIp::rate_bucket( self::resolved(), $prefix, $cap );
	}

	/**
	 * Forget the resolved address. Production never needs this — one request
	 * is one address — but a test process is many requests in one lifetime.
	 */
	public static function reset_request_state(): void {
		self::$resolved = array();
	}

	/**
	 * The threshold and the window, from the constants and then the filter.
	 *
	 * @return array{0: int, 1: int}
	 */
	private static function limits(): array {
		$max    = defined( 'BETTERSHIELD_MCP_MAX_FAILURES' ) ? (int) \BETTERSHIELD_MCP_MAX_FAILURES : self::DEFAULT_MAX_FAILURES;
		$window = defined( 'BETTERSHIELD_MCP_LOCKOUT_SECONDS' ) ? (int) \BETTERSHIELD_MCP_LOCKOUT_SECONDS : self::DEFAULT_WINDOW_SECONDS;

		/**
		 * The failed-authentication limit at the assistant endpoint.
		 *
		 * @param array{0: int, 1: int} $limits Failures allowed, and the window in seconds.
		 */
		$limits = (array) apply_filters( 'bettershield_mcp_rate_limit', array( $max, $window ) );

		return array(
			isset( $limits[0] ) ? max( 1, (int) $limits[0] ) : self::DEFAULT_MAX_FAILURES,
			isset( $limits[1] ) ? max( 1, (int) $limits[1] ) : self::DEFAULT_WINDOW_SECONDS,
		);
	}

	/**
	 * The limits on the routes a caller with no credential may reach.
	 *
	 * @return array{0: int, 1: int, 2: int, 3: int}
	 */
	private static function anonymous_limits(): array {
		/**
		 * The limits on registration and on the token endpoint.
		 *
		 * @param array{0: int, 1: int, 2: int, 3: int} $limits Registrations allowed, the window in seconds, failed exchanges allowed, and tokens one application may be issued.
		 */
		$limits = (array) apply_filters(
			'bettershield_mcp_anonymous_rate_limit',
			array(
				self::DEFAULT_MAX_REGISTRATIONS,
				self::DEFAULT_ANONYMOUS_WINDOW_SECONDS,
				self::DEFAULT_MAX_TOKEN_FAILURES,
				self::DEFAULT_MAX_TOKEN_ISSUES,
			)
		);

		return array(
			isset( $limits[0] ) ? max( 1, (int) $limits[0] ) : self::DEFAULT_MAX_REGISTRATIONS,
			isset( $limits[1] ) ? max( 1, (int) $limits[1] ) : self::DEFAULT_ANONYMOUS_WINDOW_SECONDS,
			isset( $limits[2] ) ? max( 1, (int) $limits[2] ) : self::DEFAULT_MAX_TOKEN_FAILURES,
			isset( $limits[3] ) ? max( 1, (int) $limits[3] ) : self::DEFAULT_MAX_TOKEN_ISSUES,
		);
	}
}
