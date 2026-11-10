<?php
/**
 * Login protection: attempt limits and lockouts that cannot strand an owner.
 *
 * Where the lockout incidents in this category actually come from is not the
 * threshold — it is identity. Locking "the attacker's address" when that
 * address is really a proxy shared by a thousand people locks the thousand.
 * So every enforcement decision here rides on ClientIp's confidence: an
 * address the resolution could not verify is recorded and displayed but
 * NEVER locked, whatever the attempt count. Quieter enforcement on strange
 * network layouts is the accepted cost; the alternative is being the plugin
 * that locked out an office.
 *
 * Three ways back in, layered:
 *  1. Lockouts expire on their own.
 *  2. The lockout email: when a lockout's attempts targeted a real account,
 *     that account's owner gets a single-use unlock link by mail —
 *     independent of the site's recovery link, and scoped to this one lockout.
 *  3. Safe mode pauses this entirely, like every other enforcement.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Database\Schema;
use BetterShield\Events\Writer;
use BetterShield\Recovery\RecoveryLink;
use BetterShield\Recovery\SafeMode;
use BetterShield\Support\AuthLog;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\Ip;
use BetterShield\Support\Text;
use BetterShield\Support\Time;
use BetterShield\Undo\SettingsLedger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- plugin-owned tables with no core API, deliberately uncached: a lockout decision made from a stale cache is wrong in both directions.

final class Protection {

	public const OPTION = 'bettershield_login_protection';

	/**
	 * The surface every count and every lockout in this class belongs to.
	 *
	 * Named rather than assumed, now that the tables hold more than one. Every
	 * query below carries it, so a run of refusals on a public form cannot
	 * become arithmetic on the sign-in gate — which is to say, cannot cost an
	 * owner their own dashboard.
	 */
	private const SURFACE = Surfaces::SIGNIN;

	private const UNLOCK_QUERY_VAR = 'bettershield_unlock';

	/** Asks for an unlock link, from a connection that is locked out. */
	private const UNLOCK_REQUEST_VAR = 'bettershield_unlock_request';

	/** How many times one connection may ask for a link in an hour. */
	private const UNLOCK_REQUESTS_PER_NETWORK = 5;

	/** How many requested links one site sends in an hour. */
	private const UNLOCK_LINKS_PER_SITE = 20;

	/**
	 * How many requested links one account is sent in an hour, across every
	 * connection asking. A lockout is one connection's, and each asks for one
	 * link an hour, so this bounds the mail an account gets from people
	 * locked out on several connections. Three leaves the owner room beside
	 * a stranger or two, and to use it up an attacker needs three connections,
	 * each locked out by tries at that one account. The owner still has the wait.
	 */
	private const UNLOCK_LINKS_PER_ACCOUNT = 3;

	/** Where a lockout's earlier link points at the hash of its newer one. */
	private const UNLOCK_ALIAS = 'bettershield_unlock_alias_';

	/** Most entries a list may hold, and the longest a field in one may be. */
	public const MAX_LIST_ENTRIES = 500;
	public const MAX_FIELD_LENGTH = 200;

	/**
	 * Refusal codes this plugin itself produces on the sign-in path. A
	 * refusal is not a wrong password: it must not count toward a lockout,
	 * or a locked-out client would deepen its own lockout with every knock.
	 * A wrong two-factor code (`bettershield_2fa_wrong`) is deliberately not
	 * here — that is a wrong credential, and it counts. Nor is the XML-RPC
	 * refusal of a two-factor account: a correct password arriving over
	 * password-only XML-RPC is a stolen password being tried, and the owner
	 * should hear about it the way they hear about any other run of failures.
	 */
	private const OWN_REFUSALS = array(
		'bettershield_locked',
		'bettershield_blocked',
		'bettershield_2fa_required',
		'bettershield_honeypot',
		'bettershield_pow_required',
		// The credential was right and the site is simply closed. Counting it
		// would leave accounts locked out past the end of the lockdown, which
		// is damage that outlasts the emergency it was meant to answer.
		'bettershield_lockdown',
		/*
		 * The password was RIGHT and this plugin refused it because the
		 * account signs in with a passkey. Counting that as a failed sign-in
		 * would lock the account for using its own correct credential — and
		 * lock it against the very person the feature protects, who is the
		 * one most likely to type it out of habit.
		 */
		'bettershield_passkey_only',
		'bettershield_passkey_only_xmlrpc',
		// The same: the password was right, and an incident response asked
		// for a new one before it signs in again.
		'bettershield_new_password_required',
		// A right application password used outside the limit its owner
		// gave it. Over REST core reports it on its own hook, which skips it;
		// over XML-RPC it arrives here through wp_authenticate().
		\BetterShield\Agents\PasswordLimits::REFUSED,
	);

	/**
	 * The refusals that are not a wrong credential: this plugin's own, and an
	 * add-on's that refuse a right one.
	 *
	 * `bettershield_own_refusals` lets another plugin name the codes it
	 * returns on the sign-in chain for a credential that was right — a sign-in
	 * outside the hours an account may use, say — so the refusal does not
	 * count toward a lockout. Counted, a few tries outside the hours paused
	 * the whole address and outlasted the refusal itself. Only additions: a
	 * code of this plugin's cannot be taken out, so no registration makes a
	 * refusal of its own count. Codes are kept as strings and nothing else.
	 *
	 * @return string[]
	 */
	private static function own_refusals(): array {
		$added = apply_filters( 'bettershield_own_refusals', array() );
		$added = array_filter( is_array( $added ) ? $added : array(), static fn( $code ): bool => is_string( $code ) && '' !== $code );

		return array_merge( self::OWN_REFUSALS, array_values( $added ) );
	}

	/**
	 * How many running lockouts the screen's list carries at most. The cut on
	 * the list applies to ended ones; this bounds the answer when far more
	 * than fifty networks are locked out at once.
	 */
	private const RUNNING_LISTED = 500;

	private static ?Protection $instance = null;

	/**
	 * This request's sign-in, while it runs. See note_attempt().
	 *
	 * @var array{0: \WP_User, 1: string}|null
	 */
	private ?array $attempt = null;

	/**
	 * Whether enforce() refused the sign-in in this request, so the failure
	 * core then reports is not recorded as an attempt.
	 */
	private bool $refused = false;

	/**
	 * Requested links waiting for this request's answer to go out first.
	 *
	 * @var array<int, array{0: \WP_User, 1: string, 2: int}>
	 */
	private array $queued_links = array();

	/**
	 * The name or email address the sign-in being judged was made with, as
	 * core will repeat it in its own refusal. Only read while core is
	 * running authenticate, where it was noted.
	 */
	private string $typed_login = '';

	/**
	 * The place this request holds among the tries its connection has in
	 * flight, as its claim key, or '' when it holds none. See reserve().
	 */
	private string $reserved = '';

	/**
	 * How long a place among the tries in flight is held when nothing gives
	 * it back: a request that died between the check and its outcome. The
	 * window slides (`Claim::hold_or_fail()`), so a burst cannot be split
	 * across its close.
	 */
	private const RESERVATION_SECONDS = 60;

	public static function instance(): Protection {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * What this site's sign-in counters cover, when that is less than an
	 * account.
	 *
	 * WordPress credentials are network-global — one account, one password,
	 * every subsite — while this plugin's attempt and lockout tables are the
	 * site's own, as everything else here is. So on a network the threshold is
	 * counted once per subsite, and somebody working through a password list
	 * can start again on the next subsite's sign-in form.
	 *
	 * Counting across the network is deliberately not what happens instead.
	 * That would mean shared state and one subsite's traffic locking an
	 * account on another, which is enforcement reaching across a network
	 * rather than a site protecting itself. What is owed here is the sentence,
	 * not the mechanism: a protection that covers less than the reader assumes
	 * has to say so, or the number on the screen is a promise this site cannot
	 * keep.
	 *
	 * Null on a single site, where the counter covers everything there is.
	 */
	public function counting_scope(): ?string {
		if ( ! is_multisite() ) {
			return null;
		}

		return __( 'Attempt counts, lockouts and lists are per site, but accounts are network-wide. Someone guessing a password can start again on another site.', 'bettershield' );
	}

	/**
	 * The same sentence the public forms are owed.
	 *
	 * These three gates are built on the same per-site tables the sign-in gate
	 * is, so the same gap between what the number says and what it covers is
	 * here too — and a reset request is the clearest case, because the account
	 * a reset concerns is network-global in exactly the way a password is.
	 * Saying it for one gate and not the other three would leave the second
	 * reading unsaid on the newer half of the same screen.
	 *
	 * Null on a single site, where the counters cover everything there is.
	 */
	public function counting_scope_public(): ?string {
		if ( ! is_multisite() ) {
			return null;
		}

		return __( 'Form counts and lockouts are per site, but accounts are network-wide. A connection stopped here can start again on another site’s forms.', 'bettershield' );
	}

	/**
	 * What this plugin recommends, before anybody has chosen anything.
	 *
	 * A security tool's defaults *are* its recommendation, and until now they
	 * were only ever visible as the value a fresh install happened to show —
	 * so somebody who had changed a number had no way back to it, and somebody
	 * unsure what "good" looked like had nothing to compare against. Held
	 * apart from `settings()` so the screen can show them and offer a way
	 * back, and so there is one copy of each rather than one per reader.
	 *
	 * @return array<string, mixed>
	 */
	public function defaults(): array {
		return array(
			'enabled'             => true,
			/*
			 * Counting failed sign-ins and pausing a connection that keeps
			 * failing, on its own switch. `enabled` is the whole feature — the
			 * blocklists, the public-form throttles, the refusals — and this
			 * is the one part another security plugin can already be doing:
			 * handing the job to it turns this off and nothing else.
			 */
			'attempt_limit'       => true,
			'threshold'           => 5,
			'window_minutes'      => 15,
			'lockout_minutes'     => 15,
			'allowlist'           => array(),
			'blocklist'           => array(),
			'trusted_proxies'     => array(),
			/*
			 * Off, because nobody has said otherwise yet. A site that is
			 * behind Cloudflare turns this on and its lockouts follow the
			 * visitor; a site that is not leaves it off and a request from
			 * inside Cloudflare's ranges cannot name whoever it likes and be
			 * believed. Defaulting to on would hand that to every site that
			 * never opens this screen.
			 */
			'cloudflare'          => false,
			'honeypot'            => true,
			'idle_minutes'        => 0,
			'session_cap'         => 0,
			/*
			 * Off, deliberately. This one emails people who are not the site's
			 * administrator, and a plugin that starts writing to a client's
			 * whole editorial team on update — without anybody asking it to —
			 * is a plugin that gets uninstalled by lunchtime.
			 */
			'new_location_notice' => false,
			/*
			 * Off: it needs JavaScript, and a site that turned it on without
			 * being asked would be adding a requirement its owner had not
			 * agreed to. The refusal it produces never counts toward a
			 * lockout, so nobody is ever driven into a longer block by it.
			 */
			'proof_of_work'       => false,
			/*
			 * Off: it writes to the server's auth log, which is only worth
			 * doing where a firewall jail on the same machine reads it. A host
			 * that runs one turns it on for every site through the filter in
			 * `Support\AuthLog`.
			 */
			'host_ban_line'       => false,
			/*
			 * On, all three. The honeypot has shipped on by default since the
			 * beginning and it *rejects* a comment outright; a threshold that
			 * sends one to the moderation queue is the milder of the two, and
			 * a protection nobody switches on protects nobody. The numbers are
			 * set in `Surfaces` where the reasoning for each one lives.
			 */
			'surfaces'            => self::surface_defaults(),
		);
	}

	/**
	 * @return array<string, array{enabled: bool, threshold: int, window_minutes: int, lockout_minutes: int}>
	 */
	private static function surface_defaults(): array {
		$out = array();

		foreach ( Surfaces::defaults() as $surface => $policy ) {
			$out[ $surface ] = array(
				'enabled'         => ! in_array( $surface, Surfaces::OFF_BY_DEFAULT, true ),
				'threshold'       => $policy['threshold'],
				'window_minutes'  => $policy['window_minutes'],
				'lockout_minutes' => $policy['lockout_minutes'],
			);
		}

		return $out;
	}

	/**
	 * A stored number, held to the bounds the save path enforces.
	 *
	 * The clamp belongs on both sides. A ceiling only on the way in leaves
	 * every value written before it existed — by an earlier release, an
	 * import, or a direct option write — flowing into enforcement unchecked,
	 * which for a threshold means a gate that reads enabled and never closes.
	 */
	private static function bounded( $value, int $floor, int $ceiling ): int {
		return min( $ceiling, max( $floor, (int) $value ) );
	}

	/**
	 * The same, for the two settings where zero is a value rather than a floor.
	 *
	 * An idle timeout and a session limit are both off at 0 and bounded above
	 * it, so neither can go through `bounded()` — a floor of five would read
	 * "off" as five minutes. Read-side, because `validate()` refuses anything
	 * outside these ranges on the way in and the way out had no ceiling at
	 * all: a value from an earlier release, an import, or a direct option
	 * write reached enforcement unclamped, where an over-large one quietly
	 * means the feature is off.
	 *
	 * @param mixed $value
	 */
	private static function bounded_or_off( $value, int $floor, int $ceiling ): int {
		$value = (int) $value;

		return $value <= 0 ? 0 : self::bounded( $value, $floor, $ceiling );
	}

	/**
	 * A gated surface's policy, defaults filled in and the action added back.
	 *
	 * The action is not an owner's to change: holding a comment rather than
	 * dropping it is the condition under which gating a public form was
	 * allowed at all, so it is read from the registry every time rather than
	 * stored anywhere somebody could edit it to `refuse`.
	 *
	 * @return array{enabled: bool, threshold: int, window_minutes: int, lockout_minutes: int, action: string}
	 */
	public function surface_policy( string $surface ): array {
		$stored   = $this->settings()['surfaces'][ $surface ] ?? array();
		$defaults = Surfaces::defaults()[ $surface ] ?? array(
			'threshold'       => 10,
			'window_minutes'  => 10,
			'lockout_minutes' => 30,
			'action'          => Surfaces::ACTION_REFUSE,
		);

		return array(
			'enabled'         => (bool) ( $stored['enabled'] ?? ! in_array( $surface, Surfaces::OFF_BY_DEFAULT, true ) ),
			'threshold'       => self::bounded( $stored['threshold'] ?? $defaults['threshold'], 3, 100 ),
			'window_minutes'  => self::bounded( $stored['window_minutes'] ?? $defaults['window_minutes'], 1, 1440 ),
			'lockout_minutes' => self::bounded( $stored['lockout_minutes'] ?? $defaults['lockout_minutes'], 1, 1440 ),
			'action'          => $defaults['action'],
		);
	}

	/**
	 * A whole set of these settings written before the attempt limit had a
	 * switch of its own, in the shape it has now.
	 *
	 * Then, `enabled` was that limit's switch, so it is read the way
	 * `settings()` reads a stored option of that shape: as `attempt_limit`,
	 * leaving the whole feature's switch as it is. A settings file exported
	 * then and an undo record written then both still carry it. Only for
	 * those: a save that names `enabled` alone means the whole feature, as it
	 * always does now.
	 *
	 * @param array<string, mixed> $values
	 * @return array<string, mixed>
	 */
	public static function upgraded( array $values ): array {
		if ( ! array_key_exists( 'enabled', $values ) || array_key_exists( 'attempt_limit', $values ) ) {
			return $values;
		}

		$values['attempt_limit'] = (bool) $values['enabled'];
		unset( $values['enabled'] );

		return $values;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function settings(): array {
		$stored   = get_option( self::OPTION, array() );
		$stored   = is_array( $stored ) ? $stored : array();
		$defaults = $this->defaults();

		/*
		 * Saved before the attempt limit had a switch of its own, `enabled`
		 * off meant that limit off: its only switch was "Pause sign-in after
		 * repeated failures", and keeping another plugin for sign-in limits
		 * wrote it too. Read that way, so a site that only turned the limit
		 * off gets its blocklists and form throttles back, as its screen
		 * already said it had.
		 */
		$legacy = ! array_key_exists( 'attempt_limit', $stored );

		return array(
			'enabled'         => $legacy ? $defaults['enabled'] : (bool) ( $stored['enabled'] ?? $defaults['enabled'] ),
			'attempt_limit'   => (bool) ( $legacy ? ( $stored['enabled'] ?? $defaults['attempt_limit'] ) : $stored['attempt_limit'] ),
			'threshold'       => self::bounded( $stored['threshold'] ?? $defaults['threshold'], 3, 100 ),
			'window_minutes'  => self::bounded( $stored['window_minutes'] ?? $defaults['window_minutes'], 1, 1440 ),
			'lockout_minutes' => self::bounded( $stored['lockout_minutes'] ?? $defaults['lockout_minutes'], 1, 1440 ),
			'allowlist'       => $this->clean_list( $stored['allowlist'] ?? array(), 'range' ),
			'blocklist'       => $this->clean_list( $stored['blocklist'] ?? array(), 'range', 'ua', 'username' ),
			'trusted_proxies' => array_values(
				array_filter(
					array_map( 'strval', (array) ( $stored['trusted_proxies'] ?? array() ) ),
					array( ClientIp::class, 'valid_range' )
				)
			),
			'cloudflare'      => (bool) ( $stored['cloudflare'] ?? $defaults['cloudflare'] ),
			'honeypot'        => (bool) ( $stored['honeypot'] ?? $defaults['honeypot'] ),
			'idle_minutes'    => self::bounded_or_off( $stored['idle_minutes'] ?? $defaults['idle_minutes'], 5, 1440 ),
			'session_cap'     => self::bounded_or_off( $stored['session_cap'] ?? $defaults['session_cap'], 1, 100 ),
			'new_location_notice' => (bool) ( $stored['new_location_notice'] ?? $defaults['new_location_notice'] ),
			'proof_of_work'   => (bool) ( $stored['proof_of_work'] ?? $defaults['proof_of_work'] ),
			'host_ban_line'   => (bool) ( $stored['host_ban_line'] ?? $defaults['host_ban_line'] ),
			'surfaces'        => $this->clean_surfaces( $stored['surfaces'] ?? array(), $defaults['surfaces'] ),
		);
	}

	/**
	 * @param mixed $stored
	 * @param array<string, array<string, mixed>> $defaults
	 * @return array<string, array{enabled: bool, threshold: int, window_minutes: int, lockout_minutes: int}>
	 */
	private function clean_surfaces( $stored, array $defaults ): array {
		$stored = is_array( $stored ) ? $stored : array();
		$out    = array();

		foreach ( $defaults as $surface => $policy ) {
			$saved = is_array( $stored[ $surface ] ?? null ) ? $stored[ $surface ] : array();

			$out[ $surface ] = array(
				'enabled' => (bool) ( $saved['enabled'] ?? $policy['enabled'] ),
				// Bounded the way the sign-in numbers are, and for the same
				// reasons: a threshold of one is not a threshold, it is a wall,
				// and a threshold nothing can reach is the gate turned off by a
				// number rather than by the switch that says so.
				'threshold'       => self::bounded( $saved['threshold'] ?? $policy['threshold'], 3, 100 ),
				'window_minutes'  => self::bounded( $saved['window_minutes'] ?? $policy['window_minutes'], 1, 1440 ),
				'lockout_minutes' => self::bounded( $saved['lockout_minutes'] ?? $policy['lockout_minutes'], 1, 1440 ),
			);
		}

		return $out;
	}

	/**
	 * Whether saving this input would take protection away, which is what
	 * the password gate asks about on this route. Anything that lets more
	 * through counts: a switch or a form's gate turned off, a number that
	 * counts fewer failures or pauses a connection for less time, a session
	 * rule loosened, an address allowed or believed, a block lifted.
	 * Tightening takes nothing away, and neither does input the save would
	 * refuse, since nothing is written.
	 *
	 * @param array<string, mixed> $input
	 */
	public function weakens( array $input ): bool {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return false;
		}

		$before = $this->settings();

		foreach ( array( 'enabled', 'attempt_limit', 'honeypot', 'proof_of_work', 'new_location_notice', 'host_ban_line' ) as $switch ) {
			if ( $before[ $switch ] && ! $next[ $switch ] ) {
				return true;
			}
		}

		// The one switch that gives something away by being turned on: it
		// decides whose forwarded header names the client.
		if ( $next['cloudflare'] && ! $before['cloudflare'] ) {
			return true;
		}

		if ( self::counts_less( $before, $next ) ) {
			return true;
		}

		foreach ( $before['surfaces'] as $surface => $policy ) {
			$after = $next['surfaces'][ $surface ] ?? $policy;

			if ( ( $policy['enabled'] && ! $after['enabled'] ) || self::counts_less( $policy, $after ) ) {
				return true;
			}
		}

		// Zero is off for both: switched off, or allowed longer or more.
		foreach ( array( 'idle_minutes', 'session_cap' ) as $limit ) {
			if ( $before[ $limit ] > 0 && ( 0 === $next[ $limit ] || $next[ $limit ] > $before[ $limit ] ) ) {
				return true;
			}
		}

		// Read as sets, entry by entry, so a reorder gives nothing away. An
		// address allowed or a proxy believed does, and so does a block
		// lifted.
		$allowed_now    = array_map( array( $this, 'entry_key' ), $next['allowlist'] );
		$allowed_before = array_map( array( $this, 'entry_key' ), $before['allowlist'] );
		$blocked_now    = array_map( array( $this, 'entry_key' ), $next['blocklist'] );
		$blocked_before = array_map( array( $this, 'entry_key' ), $before['blocklist'] );

		return array() !== array_diff( $allowed_now, $allowed_before )
			|| array() !== array_diff( $blocked_before, $blocked_now )
			|| array() !== array_diff( $next['trusted_proxies'], $before['trusted_proxies'] );
	}

	/**
	 * Whether these numbers count fewer failures: a higher threshold, a
	 * shorter window to reach it in, or a shorter pause once it is reached.
	 *
	 * @param array<string, mixed> $before
	 * @param array<string, mixed> $next
	 */
	private static function counts_less( array $before, array $next ): bool {
		return (int) $next['threshold'] > (int) $before['threshold']
			|| (int) $next['window_minutes'] < (int) $before['window_minutes']
			|| (int) $next['lockout_minutes'] < (int) $before['lockout_minutes'];
	}

	/**
	 * Update settings. New allowlist and blocklist entries are stamped with
	 * who added them and when — a blocklist is a record of decisions, and a
	 * decision without an author is not one.
	 *
	 * @param array<string, mixed> $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function update_settings( array $input ) {
		$next = $this->validate( $input );

		if ( is_wp_error( $next ) ) {
			return $next;
		}

		$before = $this->settings();

		// Before the write, so the record exists whether or not it lands.
		// False is the one answer that has to stop the save: there was a prior
		// state and it could not be written down, so proceeding would change
		// enforcement with nothing to put it back. Null is the ordinary "there
		// is nothing here to record" and carries on.
		if ( false === SettingsLedger::record( 'login_protection', $before, $next ) ) {
			return new \WP_Error(
				'bettershield_ledger_failed',
				__( 'Nothing was changed: the undo record could not be saved.', 'bettershield' ),
				array( 'status' => 500 )
			);
		}

		update_option( self::OPTION, $next, true );

		// Switching the idle timeout on starts every session's idle window
		// now, rather than at its sign-in; see Sessions::IDLE_SINCE.
		if ( $next['idle_minutes'] > 0 && 0 === (int) $before['idle_minutes'] ) {
			update_option( Sessions::IDLE_SINCE, time(), true );
		}

		/*
		 * A settings row that reads the same whether protection was tightened
		 * or switched off answers none of the questions it is kept for. The
		 * changes that take protection away are named, and the row carries the
		 * severity of the weakest thing in it.
		 *
		 * `trusted_proxies` is here because it decides whose forwarded headers
		 * are believed, which decides who a lockout is applied to — adding a
		 * range somebody controls is how lockouts stop working, and it was the
		 * one field the context never mentioned.
		 */
		$weakened = array();

		if ( ! $next['enabled'] && $before['enabled'] ) {
			$weakened[] = 'protection off';
		}

		if ( ! $next['attempt_limit'] && $before['attempt_limit'] ) {
			$weakened[] = 'attempt limit off';
		}

		if ( $next['threshold'] > $before['threshold'] ) {
			$weakened[] = 'threshold raised';
		}

		if ( ! $next['honeypot'] && $before['honeypot'] ) {
			$weakened[] = 'bot check off';
		}

		if ( ! $next['proof_of_work'] && $before['proof_of_work'] ) {
			$weakened[] = 'proof of work off';
		}

		/*
		 * The numbers say how much a lockout costs a guesser as much as the
		 * threshold does: a one-minute window with five tries never closes on
		 * a bot that tries four a minute, and a one-minute pause barely slows
		 * one that does trip it.
		 */
		if ( $next['lockout_minutes'] < $before['lockout_minutes'] ) {
			$weakened[] = 'lockout shortened';
		}

		if ( $next['window_minutes'] < $before['window_minutes'] ) {
			$weakened[] = 'window shortened';
		}

		// Each public form's throttle, read the same four ways.
		foreach ( $next['surfaces'] as $surface => $policy ) {
			$was = $before['surfaces'][ $surface ] ?? null;

			if ( ! is_array( $was ) ) {
				continue;
			}

			if ( ! $policy['enabled'] && $was['enabled'] ) {
				$weakened[] = $surface . ' throttle off';
			}

			if ( $policy['threshold'] > $was['threshold'] ) {
				$weakened[] = $surface . ' threshold raised';
			}

			if ( $policy['lockout_minutes'] < $was['lockout_minutes'] ) {
				$weakened[] = $surface . ' lockout shortened';
			}

			if ( $policy['window_minutes'] < $was['window_minutes'] ) {
				$weakened[] = $surface . ' window shortened';
			}
		}

		// And the session protections kept in the same settings, where 0 is
		// off rather than the strictest value.
		if ( 0 === $next['idle_minutes'] && $before['idle_minutes'] > 0 ) {
			$weakened[] = 'idle timeout off';
		} elseif ( $before['idle_minutes'] > 0 && $next['idle_minutes'] > $before['idle_minutes'] ) {
			$weakened[] = 'idle timeout lengthened';
		}

		if ( 0 === $next['session_cap'] && $before['session_cap'] > 0 ) {
			$weakened[] = 'session limit off';
		} elseif ( $before['session_cap'] > 0 && $next['session_cap'] > $before['session_cap'] ) {
			$weakened[] = 'session limit raised';
		}

		if ( ! $next['new_location_notice'] && $before['new_location_notice'] ) {
			$weakened[] = 'new location notice off';
		}

		// The server's firewall stops hearing about pauses. This site's own
		// enforcement is unchanged, so it takes the quieter grade below.
		if ( ! $next['host_ban_line'] && $before['host_ban_line'] ) {
			$weakened[] = 'host ban line off';
		}

		/*
		 * Read as a set, like the allowlist below it and for the same reason:
		 * the list decides which addresses may speak for somebody else, not in
		 * what order they may, so a reorder hands nothing to anybody. Graded
		 * as a weakening it would put a row in front of the owner for a change
		 * that gave nothing away, and teach them to skip the ones that did.
		 */
		if ( array() !== array_diff( $next['trusted_proxies'], $before['trusted_proxies'] ) ) {
			$weakened[] = 'trusted proxies changed';
		}

		/*
		 * Graded the same way and for the same reason: it decides whether a
		 * header from Cloudflare's ranges names the client on its own, which
		 * decides who a lockout is applied to. Only the arriving direction is
		 * a weakening — withdrawing the statement narrows what is believed.
		 */
		if ( $next['cloudflare'] && ! $before['cloudflare'] ) {
			$weakened[] = 'cloudflare trusted';
		}

		/*
		 * The allowlist is compared by identity and not by size. An allowed
		 * range bypasses the counting and the enforcement both, and it can be
		 * replaced without the count moving: the ranges swap, every number in
		 * this row stays where it was, and the bypass has been handed to a
		 * different network. So entries only being removed is not a weakening,
		 * and neither is reordering them, because the list is read as a set.
		 *
		 * Entries are matched as they are written rather than by the addresses
		 * they cover, so an entry edited into a narrower range still reads as
		 * a new one. That error runs the safe way — it says a list changed
		 * when it did, at a grade below the one that mails.
		 */
		$allowed_now    = array_map( array( $this, 'entry_key' ), $next['allowlist'] );
		$allowed_before = array_map( array( $this, 'entry_key' ), $before['allowlist'] );

		if ( array() !== array_diff( $allowed_now, $allowed_before ) ) {
			$weakened[] = 'allowlist widened';
		}

		// The blocklist the other way around: an entry gone is an address, an
		// agent or a name let back in. Matched the same way, so an edited
		// entry reads as one let back in, and it takes the same quieter grade.
		$blocked_now    = array_map( array( $this, 'entry_key' ), $next['blocklist'] );
		$blocked_before = array_map( array( $this, 'entry_key' ), $before['blocklist'] );

		if ( array() !== array_diff( $blocked_before, $blocked_now ) ) {
			$weakened[] = 'blocklist narrowed';
		}

		/*
		 * Graded by the signal, not by the event. A protection taken off
		 * reaches the grade that alerts, as removing the two-factor or passkey
		 * requirement does: one below it, turning brute-force protection off
		 * waited for the weekly summary. The lists matched entry by entry, and
		 * the Cloudflare trust graded with the proxies, can read as widened
		 * when nothing was given away, so those alone stay a grade below —
		 * but they never hold a row that also takes a protection off.
		 */
		$quiet    = array( 'trusted proxies changed', 'cloudflare trusted', 'allowlist widened', 'blocklist narrowed', 'host ban line off' );
		$severity = Writer::SEVERITY_INFO;

		if ( array() !== $weakened ) {
			$severity = array() === array_diff( $weakened, $quiet ) ? Writer::SEVERITY_MEDIUM : Writer::SEVERITY_HIGH;
		}

		Writer::instance()->record(
			'login_protection_updated',
			$severity,
			array(
				'object_type' => 'setting',
				'object_id'   => self::OPTION,
				'context'     => array(
					'enabled'         => $next['enabled'],
					'threshold'       => $next['threshold'],
					'honeypot'        => $next['honeypot'],
					'proof_of_work'   => $next['proof_of_work'],
					'allow'           => count( $next['allowlist'] ),
					'block'           => count( $next['blocklist'] ),
					// Counts, never entries: a proxy range is a decision about
					// who is believed, and the count moving is the signal.
					'trusted_proxies' => count( $next['trusted_proxies'] ),
					'cloudflare'      => $next['cloudflare'],
					'host_ban_line'   => $next['host_ban_line'],
					'weakened'        => $weakened,
				),
			)
		);

		return $this->settings();
	}

	/**
	 * The settings an input would become, or the refusal it would meet — with
	 * nothing saved. A settings import dry-runs through this so its plan
	 * names the same refusal the apply would produce.
	 *
	 * @param array<string, mixed> $input
	 * @return array<string, mixed>|\WP_Error
	 */
	public function validate( array $input ) {
		$current = $this->settings();

		$next = array(
			'enabled'         => isset( $input['enabled'] ) ? (bool) $input['enabled'] : $current['enabled'],
			'attempt_limit'   => isset( $input['attempt_limit'] ) ? (bool) $input['attempt_limit'] : $current['attempt_limit'],
			'threshold'       => isset( $input['threshold'] ) ? (int) $input['threshold'] : $current['threshold'],
			'window_minutes'  => isset( $input['window_minutes'] ) ? (int) $input['window_minutes'] : $current['window_minutes'],
			'lockout_minutes' => isset( $input['lockout_minutes'] ) ? (int) $input['lockout_minutes'] : $current['lockout_minutes'],
			'cloudflare'      => isset( $input['cloudflare'] ) ? (bool) $input['cloudflare'] : $current['cloudflare'],
			'honeypot'        => isset( $input['honeypot'] ) ? (bool) $input['honeypot'] : $current['honeypot'],
			'idle_minutes'    => isset( $input['idle_minutes'] ) ? (int) $input['idle_minutes'] : $current['idle_minutes'],
			'session_cap'     => isset( $input['session_cap'] ) ? (int) $input['session_cap'] : $current['session_cap'],
			'new_location_notice' => isset( $input['new_location_notice'] ) ? (bool) $input['new_location_notice'] : $current['new_location_notice'],
			'proof_of_work'   => isset( $input['proof_of_work'] ) ? (bool) $input['proof_of_work'] : $current['proof_of_work'],
			// On a network's subsite the switch is the main site's (see
			// AuthLog::set_from_main_site()), so whatever arrives for it is
			// ignored and the stored value carried: an import or an undo
			// holding the main site's answer still brings the rest of the
			// section. The screen's own save of it is refused, by
			// refuses_a_network_switch().
			'host_ban_line'   => \BetterShield\Support\AuthLog::set_from_main_site() || ! isset( $input['host_ban_line'] ) ? $current['host_ban_line'] : (bool) $input['host_ban_line'],
			// Carried whole and edited below, the way the lists are. A partial
			// save must not empty the forms it did not mention.
			'surfaces'        => $current['surfaces'],
		);

		/*
		 * A yes or a no, and nothing that is truthy by accident. This one
		 * decides whether a header from Cloudflare's ranges names the client
		 * on its own, so a stray "0" or "false" arriving as a string and being
		 * read as yes would hand that away silently. Its neighbors cast
		 * because their worst case is a number; this one's worst case is who
		 * gets locked out.
		 */
		if ( isset( $input['cloudflare'] ) && ! is_bool( $input['cloudflare'] ) ) {
			return new \WP_Error( 'bettershield_bad_cloudflare', __( 'The Cloudflare setting needs to be yes or no.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( $next['threshold'] < 3 || $next['threshold'] > 100 ) {
			return new \WP_Error( 'bettershield_bad_threshold', __( 'The attempt threshold needs to be between 3 and 100.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( $next['lockout_minutes'] < 1 || $next['lockout_minutes'] > 1440 ) {
			return new \WP_Error( 'bettershield_bad_duration', __( 'A lockout can last one minute to one day. To block for good, use the blocklist.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( $next['window_minutes'] < 1 || $next['window_minutes'] > 1440 ) {
			return new \WP_Error( 'bettershield_bad_window', __( 'The counting window needs to be between one minute and one day.', 'bettershield' ), array( 'status' => 400 ) );
		}

		/*
		 * Both of these reach the same REST route as the three above and had
		 * no range at all — the only floor was a max(0) further in. One minute
		 * signs everyone out a minute after they arrive; a billion silently
		 * means "off". Neither is a value anybody wants, and neither told the
		 * owner anything while the three settings beside them explained their
		 * limits.
		 */
		if ( 0 !== $next['idle_minutes'] && ( $next['idle_minutes'] < 5 || $next['idle_minutes'] > 1440 ) ) {
			return new \WP_Error( 'bettershield_bad_idle', __( 'An idle timeout needs to be between 5 minutes and one day, or 0 to leave it off.', 'bettershield' ), array( 'status' => 400 ) );
		}

		if ( 0 !== $next['session_cap'] && ( $next['session_cap'] < 1 || $next['session_cap'] > 100 ) ) {
			return new \WP_Error( 'bettershield_bad_session_cap', __( 'The session limit needs to be between 1 and 100, or 0 to leave it off.', 'bettershield' ), array( 'status' => 400 ) );
		}

		foreach ( array( 'allowlist', 'blocklist', 'trusted_proxies' ) as $list ) {
			if ( ! isset( $input[ $list ] ) ) {
				$next[ $list ] = $current[ $list ];
			}
		}

		foreach ( array( 'allowlist', 'blocklist', 'trusted_proxies' ) as $list ) {
			if ( isset( $input[ $list ] ) && ! is_array( $input[ $list ] ) ) {
				/* translators: %s: the setting's name. */
				return new \WP_Error( 'bettershield_bad_list', sprintf( __( '%s must be a list.', 'bettershield' ), $list ), array( 'status' => 400 ) );
			}
			if ( isset( $input[ $list ] ) && count( $input[ $list ] ) > self::MAX_LIST_ENTRIES ) {
				/* translators: 1: the setting's name, 2: the most entries it may hold. */
				return new \WP_Error( 'bettershield_list_too_long', sprintf( __( '%1$s may hold at most %2$d entries.', 'bettershield' ), $list, self::MAX_LIST_ENTRIES ), array( 'status' => 400 ) );
			}
		}

		if ( isset( $input['trusted_proxies'] ) ) {
			$proxies = array();
			foreach ( $input['trusted_proxies'] as $range ) {
				// The shape the allowlist and blocklist take on this route,
				// taken here too.
				if ( is_array( $range ) && array_key_exists( 'range', $range ) ) {
					$range = $range['range'];
				}
				// Checked before it is read as text: an array cast to a
				// string is "Array", with a warning, and was refused as that.
				if ( ! is_string( $range ) ) {
					return new \WP_Error( 'bettershield_bad_range', __( 'Each trusted proxy needs to be an IP address or CIDR range, written as text.', 'bettershield' ), array( 'status' => 400 ) );
				}
				$range = trim( $range );
				if ( '' === $range ) {
					continue;
				}
				$check = $this->check_range( $range, true );
				if ( is_wp_error( $check ) ) {
					return $check;
				}
				$proxies[] = $range;
			}
			// Read as a set everywhere it is used, so stored as one.
			$next['trusted_proxies'] = array_values( array_unique( $proxies ) );
		}

		if ( isset( $input['surfaces'] ) ) {
			if ( ! is_array( $input['surfaces'] ) ) {
				return new \WP_Error( 'bettershield_bad_surfaces', __( 'Form protection is a set of settings per form.', 'bettershield' ), array( 'status' => 400 ) );
			}

			foreach ( $input['surfaces'] as $surface => $policy ) {
				$surface = (string) $surface;

				if ( ! isset( $next['surfaces'][ $surface ] ) ) {
					/* translators: %s: the name of a form. */
					return new \WP_Error( 'bettershield_unknown_surface', sprintf( __( 'There is no form called %s to protect.', 'bettershield' ), $surface ), array( 'status' => 400 ) );
				}

				if ( ! is_array( $policy ) ) {
					return new \WP_Error( 'bettershield_bad_surfaces', __( 'Each form takes a set of settings.', 'bettershield' ), array( 'status' => 400 ) );
				}

				/*
				 * The same bounds the sign-in numbers carry, said again here
				 * rather than inherited, because these are the numbers that
				 * decide when somebody who is not signing in gets refused. A
				 * threshold below three is a wall, and a lockout longer than a
				 * day is a ban — which belongs on the blocklist, where it is a
				 * named decision with an author against it.
				 */
				if ( isset( $policy['threshold'] ) && ( (int) $policy['threshold'] < 3 || (int) $policy['threshold'] > 100 ) ) {
					return new \WP_Error( 'bettershield_bad_threshold', __( 'A form needs to allow between 3 and 100 attempts.', 'bettershield' ), array( 'status' => 400 ) );
				}

				if ( isset( $policy['lockout_minutes'] ) && ( (int) $policy['lockout_minutes'] < 1 || (int) $policy['lockout_minutes'] > 1440 ) ) {
					return new \WP_Error( 'bettershield_bad_duration', __( 'A form can stay closed for one minute to one day. To block for good, use the blocklist.', 'bettershield' ), array( 'status' => 400 ) );
				}

				if ( isset( $policy['window_minutes'] ) && ( (int) $policy['window_minutes'] < 1 || (int) $policy['window_minutes'] > 1440 ) ) {
					return new \WP_Error( 'bettershield_bad_window', __( 'A counting window runs between one minute and one day.', 'bettershield' ), array( 'status' => 400 ) );
				}

				$next['surfaces'][ $surface ] = array(
					'enabled'         => (bool) ( $policy['enabled'] ?? $next['surfaces'][ $surface ]['enabled'] ),
					'threshold'       => min( 100, max( 3, (int) ( $policy['threshold'] ?? $next['surfaces'][ $surface ]['threshold'] ) ) ),
					'window_minutes'  => max( 1, (int) ( $policy['window_minutes'] ?? $next['surfaces'][ $surface ]['window_minutes'] ) ),
					'lockout_minutes' => max( 1, (int) ( $policy['lockout_minutes'] ?? $next['surfaces'][ $surface ]['lockout_minutes'] ) ),
				);
			}
		}

		foreach ( array( 'allowlist', 'blocklist' ) as $list ) {
			if ( ! isset( $input[ $list ] ) ) {
				continue;
			}

			$entries  = array();
			$existing = array();
			$kept     = array();
			foreach ( $current[ $list ] as $entry ) {
				$existing[ self::match_key( $entry ) ] = $entry;
			}

			foreach ( $input[ $list ] as $entry ) {
				if ( ! is_array( $entry ) ) {
					return new \WP_Error( 'bettershield_bad_list', __( 'Each allowlist or blocklist entry needs an IP address or range. A blocklist entry can also name a browser or a username.', 'bettershield' ), array( 'status' => 400 ) );
				}

				$range = isset( $entry['range'] ) ? trim( (string) $entry['range'] ) : '';
				$ua    = isset( $entry['ua'] ) ? Text::clip( sanitize_text_field( (string) $entry['ua'] ), self::MAX_FIELD_LENGTH ) : '';
				$name  = isset( $entry['username'] ) ? Text::clip( sanitize_user( (string) $entry['username'], true ), 60 ) : '';

				/*
				 * The name as given, or a refusal. Cleaned without a word,
				 * "evil<b>x" was saved as "evilx", a name nobody typed that a
				 * real account may hold, under a success message (#1800).
				 */
				// Capitals aside: a network lowercases every name, and sign-in
				// matches a name in any case.
				if ( isset( $entry['username'] ) && 0 !== strcasecmp( $name, trim( (string) $entry['username'] ) ) ) {
					return new \WP_Error(
						'bettershield_bad_username',
						'' === $name
							? __( 'WordPress does not allow that username, so it was not added.', 'bettershield' )
							/* translators: %s: the name as WordPress would store it. */
							: sprintf( __( 'WordPress does not allow that username and would store it as "%s". Enter the account’s exact username.', 'bettershield' ), $name ),
						array( 'status' => 400 )
					);
				}

				if ( '' === $range && '' === $ua && '' === $name ) {
					continue;
				}

				if ( '' !== $range ) {
					// An allow entry that spans everyone disarms every protection
					// while the switch still reads on; a block entry that spans
					// everyone refuses everyone. Neither is a range.
					$check = $this->check_range( $range, true );
					if ( is_wp_error( $check ) ) {
						return $check;
					}
				}

				if ( 'allowlist' === $list && '' !== $ua ) {
					return new \WP_Error( 'bettershield_ua_allow', __( 'Allow entries take addresses only, since anyone can fake a user agent.', 'bettershield' ), array( 'status' => 400 ) );
				}

				if ( 'allowlist' === $list && '' !== $name ) {
					return new \WP_Error( 'bettershield_name_allow', __( 'Allow entries take addresses only. An allowed name would exempt anyone who knows it.', 'bettershield' ), array( 'status' => 400 ) );
				}

				/*
				 * The account the person editing this list signs in with. A
				 * security screen that lets somebody lock themselves out with
				 * one save is a screen that will do it, and the block takes
				 * effect on their very next sign-in — after the session they
				 * saved it in has gone.
				 */
				if ( '' !== $name ) {
					$editor = wp_get_current_user();

					// By login or by email address, as the list matches it.
					if ( $editor instanceof \WP_User && $editor->exists() && self::names_account( $name, $editor->user_login ) ) {
						return new \WP_Error( 'bettershield_name_self', __( 'You sign in with that name. Blocking it would end your sessions and lock you out at once.', 'bettershield' ), array( 'status' => 400 ) );
					}
				}

				if ( '' !== $ua && Text::length( $ua ) < 4 ) {
					return new \WP_Error( 'bettershield_ua_short', __( 'A user agent pattern needs at least four characters.', 'bettershield' ), array( 'status' => 400 ) );
				}

				$key = self::match_key(
					array(
						'range'    => $range,
						'ua'       => $ua,
						'username' => $name,
					)
				);

				// Sign-in matches a name and a browser string in any case, so
				// two entries that differ only in case refuse the same people,
				// and removing one left the name blocked (#1796). One is kept.
				if ( isset( $kept[ $key ] ) ) {
					continue;
				}

				$kept[ $key ] = true;

				if ( isset( $existing[ $key ] ) ) {
					// A surviving entry keeps its original author and date.
					$entries[] = $existing[ $key ];
					continue;
				}

				/*
				 * Naming an account refuses it everything it signs in with
				 * here, its open sessions included. That is done to the
				 * account rather than to the site, so it takes a say over the
				 * account, as ending its sessions does. A name no account that
				 * can act here holds is anybody's to refuse.
				 */
				if ( '' !== $name ) {
					$editor = wp_get_current_user();
					$named  = get_user_by( 'login', $name );

					if ( ! $named instanceof \WP_User && is_email( $name ) ) {
						$named = get_user_by( 'email', $name );
					}

					if (
						$editor instanceof \WP_User && $editor->exists()
						&& $named instanceof \WP_User
						&& ( ! is_multisite() || is_super_admin( $named->ID ) || is_user_member_of_blog( $named->ID ) )
						&& ! current_user_can( 'edit_user', $named->ID )
					) {
						return new \WP_Error( 'bettershield_cannot_edit_user', __( 'That name belongs to an account you cannot edit, so you cannot block it.', 'bettershield' ), array( 'status' => 403 ) );
					}
				}

				/*
				 * A note past the limit is refused rather than cut short
				 * (#2174). It is carried into every list row, the REST answer
				 * and the screen, and a cut note says something nobody typed.
				 */
				$note = isset( $entry['note'] ) ? sanitize_text_field( (string) $entry['note'] ) : '';

				if ( Text::length( $note ) > self::MAX_FIELD_LENGTH ) {
					return new \WP_Error(
						'bettershield_note_long',
						/* translators: %d: the most characters a note may have. */
						sprintf( __( 'A note can be at most %d characters.', 'bettershield' ), self::MAX_FIELD_LENGTH ),
						array( 'status' => 400 )
					);
				}

				$author    = wp_get_current_user();
				$entries[] = array_filter(
					array(
						'range'    => $range,
						'ua'       => $ua,
						'username' => $name,
						'note'     => $note,
						'author'   => $author instanceof \WP_User && $author->exists() ? $author->user_login : 'system',
						'added_at' => gmdate( 'c' ),
					),
					static function ( $value ): bool {
						return '' !== $value;
					}
				);
			}

			$next[ $list ] = $entries;
		}

		return $next;
	}

	/* ---- hooks ------------------------------------------------------------ */

	public function register(): void {
		// Enforcement, twice over, because of how core's own handlers behave.
		// wp_authenticate_username_password (authenticate, priority 20)
		// DISCARDS any error handed to it once a username and a password are
		// both present, and goes on to check the password — so a refusal
		// hooked earlier than 20 is thrown away. wp_authenticate_user fires
		// inside that handler before the password is checked, and is
		// honored; the late authenticate hook catches every other path.
		add_filter( 'wp_authenticate_user', array( $this, 'note_attempt' ), 1, 2 );
		add_filter( 'wp_authenticate_user', array( $this, 'enforce' ), 5, 1 );
		add_filter( 'authenticate', array( $this, 'enforce' ), 30, 1 );

		// What was typed, so a blocked name is refused in the words core
		// would use for that same attempt (see refuse_blocked_name()).
		add_filter( 'authenticate', array( $this, 'note_typed_login' ), 0, 2 );

		// Application passwords never pass through authenticate: core checks
		// them in wp_validate_application_password and announces a miss on
		// its own action. A miss counts like any other, and a locked source
		// finds application passwords unavailable.
		add_action( 'application_password_failed_authentication', array( $this, 'record_app_password_failure' ) );
		add_filter( 'wp_is_application_passwords_available', array( $this, 'app_passwords_available' ) );

		// A blocked name is refused on its application passwords as well,
		// which over REST never reach authenticate. Its open sessions are
		// judged where sessions are, in Sessions.
		add_action( 'wp_authenticate_application_password_errors', array( $this, 'refuse_blocked_app_password' ), 10, 3 );

		// Recording, after the outcome is known.
		add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 2 );
		add_action( 'wp_login', array( $this, 'record_success' ), 10, 2 );

		// A place reserved before the password check is given back when the
		// outcome is known: a failure once it is recorded, a sign-in once the
		// authenticate chain has accepted it (XML-RPC fires no wp_login), and
		// anything else as the request ends.
		add_filter( 'authenticate', array( $this, 'give_back_on_success' ), 99, 1 );
		add_action( 'shutdown', array( $this, 'give_back_reservation' ) );

		// The emailed unlock link, same shape as the recovery link: a secret
		// in a URL, usable exactly once, doing one narrow thing.
		add_action( 'init', array( $this, 'maybe_handle_unlock' ), 2 );
		add_action( 'init', array( $this, 'maybe_handle_unlock_request' ), 2 );
		add_filter( 'login_message', array( $this, 'offer_unlock_link' ) );
	}

	/**
	 * Failed sign-ins from one address inside the current window.
	 *
	 * The lockout computes this internally to decide whether to start one.
	 * The proof-of-work gate needs the same number to decide how hard to make
	 * the next attempt, and two counts of the same thing would eventually
	 * disagree.
	 */
	public function recent_failures( string $ip, ?string $paired_with = null ): int {
		global $wpdb;

		$settings = $this->settings();
		$hmac     = ClientIp::lockout_hmac(
			array(
				'ip'          => $ip,
				'paired_with' => $paired_with,
			)
		);
		$since    = Time::stamp( time() - ( $settings['window_minutes'] * MINUTE_IN_SECONDS ) );

		// Attempts from before the last lockout are already spent: the lockout
		// answered for them, and counting them again would make the puzzle
		// hard for somebody who has since been let back in.
		$last_lockout = Gate::last_lockout_started( self::SURFACE, $hmac );

		if ( null !== $last_lockout && $last_lockout > $since ) {
			$since = $last_lockout;
		}

		return Gate::failures_since( self::SURFACE, $hmac, $since );
	}

	/* ---- enforcement ------------------------------------------------------- */

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function enforce( $user ) {
		// Each evaluation decides afresh; the memory below is for the failure
		// core reports right after a refusal, and for nothing else.
		$this->refused = false;

		$settings = $this->settings();

		if ( ! $settings['enabled'] || SafeMode::is_active() ) {
			return $user;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		if ( '' === $resolved['ip'] ) {
			return $user;
		}

		/*
		 * A name the owner has blocked, judged before anything about the
		 * address. The allowlist below is an exemption from rate limiting for
		 * a network the owner trusts; it is not permission for an identity the
		 * owner banned, and a former employee on the office network is exactly
		 * the case the name list is written for.
		 *
		 * `$user` is a WP_User on `wp_authenticate_user`, which core fires
		 * after resolving the account and BEFORE checking the password, so a
		 * blocked name never reaches a password comparison at all — and an
		 * identifier that is really an email address is already resolved to
		 * its login by the time it arrives.
		 *
		 * A name nobody has an account for needs nothing from us here: core
		 * refuses it as `invalid_username`, and record_failure() pauses the
		 * source on that try when the name is on the list.
		 */
		if ( $user instanceof \WP_User && $this->blocklisted_username( $user->user_login, $resolved, $settings ) ) {
			Writer::instance()->record(
				'login_blocked',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'lockout',
					'object_id'   => 'blocklist',
					'context'     => array(
						'method' => $resolved['method'],
						'by'     => 'username',
					),
				)
			);

			return $this->refuse_blocked_name( $user );
		}

		if ( $this->allowlisted( $resolved['ip'], $settings ) ) {
			return $user;
		}

		if ( $this->blocklisted( $resolved, $settings ) ) {
			Writer::instance()->record(
				'login_blocked',
				Writer::SEVERITY_LOW,
				array(
					'object_type' => 'lockout',
					'object_id'   => 'blocklist',
					'context'     => array( 'method' => $resolved['method'] ),
				)
			);

			$this->refused = true;

			return new \WP_Error(
				'bettershield_blocked',
				__( 'Sign-in is not available from this connection.', 'bettershield' )
			);
		}

		// A pause is the attempt limit's, and stands down with it; the lists
		// above are the owner's own rules and do not.
		$lockout = $settings['attempt_limit'] ? $this->active_lockout( ClientIp::lockout_hmac( $resolved ) ) : null;

		if ( null !== $lockout ) {
			$this->refused = true;

			$ends    = strtotime( (string) $lockout->expires_at . ' UTC' );
			$minutes = false === $ends ? 0 : max( 1, (int) ceil( ( $ends - time() ) / MINUTE_IN_SECONDS ) );

			/*
			 * When it ends, rather than a promise of mail. The pause is the
			 * connection's, and its email went only to the one account every
			 * attempt that started it named — none when they named more than
			 * one, or a typo, or the account had one that hour — so "a message was sent" was
			 * untrue for everyone else on the connection. Said without saying
			 * whether a name exists or whether anything was sent.
			 *
			 * A pause a blocked name started mailed nobody a link, and is
			 * answered in these same words all the same: words of its own
			 * told, on the second try, that the name is on the list (#1957).
			 * Asking for a link promises nothing to someone who gets none.
			 */

			return new \WP_Error(
				'bettershield_locked',
				$minutes > 0
					? sprintf(
						/* translators: %d: minutes until sign-in from this connection is allowed again. */
						_n(
							'Too many failed sign-ins from this connection. Wait about %d minute, or ask for an unlock link on the sign-in page.',
							'Too many failed sign-ins from this connection. Wait about %d minutes, or ask for an unlock link on the sign-in page.',
							$minutes,
							'bettershield'
						),
						$minutes
					)
					: __( 'Too many failed sign-ins from this connection. Wait a little, or ask for an unlock link on the sign-in page.', 'bettershield' )
			);
		}

		// Only here, where core has found the account and not yet compared
		// the password: the one moment a try can still be turned away before
		// it is a guess.
		if ( $settings['attempt_limit'] && $resolved['confident'] && 'wp_authenticate_user' === current_filter() && ! $this->reserve( ClientIp::lockout_hmac( $resolved ), $settings ) ) {
			$this->refused = true;

			return new \WP_Error(
				'bettershield_locked',
				__( 'Too many failed sign-ins from this connection. Wait a little, or ask for an unlock link on the sign-in page.', 'bettershield' )
			);
		}

		return $user;
	}

	/**
	 * Take a place among the tries this connection has in flight, and say
	 * whether the threshold leaves room for it.
	 *
	 * The lockout above refuses only once its row exists, and the row is
	 * written after a failure is recorded. Tries sent together all found no
	 * row and all reached the password check, so a connection's guesses per
	 * lockout were as many as it could send at once. Counting a try on its
	 * way in, in one statement the database settles, and adding the failures
	 * already recorded, lets no more tries through than the threshold leaves.
	 * The place is given back when the outcome is recorded — after the
	 * failure's own row is written, so a try is always counted one way or the
	 * other — and a right password therefore spends nothing.
	 *
	 * When the count cannot be taken, the try goes on to the lockout check
	 * it always had. Refusing would turn a claims table that will not answer
	 * into nobody signing in to this site at all, owner included.
	 *
	 * @param array<string, mixed> $settings
	 */
	private function reserve( string $hmac, array $settings ): bool {
		if ( '' !== $this->reserved ) {
			return true;
		}

		$key  = 'signin_try_' . $hmac;
		$held = Claim::hold_or_fail( $key, self::RESERVATION_SECONDS );

		if ( null === $held ) {
			return true;
		}

		$this->reserved = $key;

		// The places left before the threshold, and never none: with failures
		// already at it and no lockout running (a threshold the owner lowered,
		// say), one try still goes through, so a right password signs in and a
		// wrong one opens the lockout rather than refusing with nothing to
		// release.
		$room = max( 1, (int) $settings['threshold'] - Gate::failures_since( self::SURFACE, $hmac, $this->counting_since( $hmac, $settings ) ) );

		if ( $held <= $room ) {
			return true;
		}

		$this->give_back_reservation();

		return false;
	}

	/**
	 * Give back this request's place once the authenticate chain has accepted
	 * the sign-in. A refusal keeps it until its failure is recorded.
	 *
	 * @param mixed $user Passed through untouched.
	 * @return mixed
	 */
	public function give_back_on_success( $user ) {
		if ( $user instanceof \WP_User ) {
			$this->give_back_reservation();
		}

		return $user;
	}

	/**
	 * Give back the place this request holds among the tries in flight.
	 * Hooked to the request's end as well, and a no-op once given back.
	 */
	public function give_back_reservation(): void {
		if ( '' === $this->reserved ) {
			return;
		}

		Claim::give_back( $this->reserved );
		$this->reserved = '';
	}

	/**
	 * Where the count toward a lockout starts: the window, or the last
	 * lockout's start when that is later. Failures before the last lockout
	 * began have already been answered with that lockout; counting them again
	 * would re-lock a just-unlocked owner on their very next slip, and send
	 * them another email.
	 *
	 * @param array<string, mixed> $settings
	 */
	private function counting_since( string $hmac, array $settings ): string {
		$since        = Time::stamp( time() - $settings['window_minutes'] * 60 );
		$last_lockout = Gate::last_lockout_started( self::SURFACE, $hmac );

		return null !== $last_lockout && $last_lockout > $since ? $last_lockout : $since;
	}

	/**
	 * Whether this connection is currently locked out or blocklisted — the
	 * question the application-password path has to ask itself, since it
	 * never runs the authenticate filters.
	 */
	public function is_refused_source(): bool {
		$settings = $this->settings();

		if ( ! $settings['enabled'] || SafeMode::is_active() ) {
			return false;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		if ( '' === $resolved['ip'] || $this->allowlisted( $resolved['ip'], $settings ) ) {
			return false;
		}

		return $this->blocklisted( $resolved, $settings )
			|| ( $settings['attempt_limit'] && null !== $this->active_lockout( ClientIp::lockout_hmac( $resolved ) ) );
	}

	/**
	 * Whether this site refuses this account by name, for the request at hand.
	 *
	 * The form asks it in enforce(). This is the same judgment for whatever
	 * else the account signs in with: an application password, and a session
	 * it opened before its name was added. Asked on every signed-in request,
	 * so a list naming nobody costs one loop and no address lookup.
	 *
	 * Never a super admin on a network. Their access to a site is the
	 * network's to decide, and one site's list does not reach it.
	 *
	 * Nothing here asks who the request is: it runs while WordPress is still
	 * working that out.
	 *
	 * @param bool $everywhere Only an entry with nothing beside the name, which
	 *                         refuses the account from any network and browser.
	 */
	public function blocks_name( \WP_User $user, bool $everywhere = false ): bool {
		$settings = $this->settings();

		if ( ! $settings['enabled'] || SafeMode::is_active() || ( is_multisite() && is_super_admin( $user->ID ) ) ) {
			return false;
		}

		$named = false;

		foreach ( $settings['blocklist'] as $entry ) {
			if ( ! is_array( $entry ) || ! self::names_account( (string) ( $entry['username'] ?? '' ), $user->user_login ) ) {
				continue;
			}

			if ( $everywhere && '' === (string) ( $entry['range'] ?? '' ) && '' === (string) ( $entry['ua'] ?? '' ) ) {
				return true;
			}

			$named = true;
		}

		return ! $everywhere && $named && $this->blocklisted_username( $user->user_login, ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] ), $settings );
	}

	/**
	 * Refuse a blocked name's application password.
	 *
	 * Over REST core checks one in `determine_current_user` and never runs
	 * authenticate, so enforce() never saw it, and the account went on
	 * working through a password minted before its name was added. The
	 * refusal is core's own for a wrong application password, for the reason
	 * refuse_blocked_name() gives, and core reports it as a miss, so it
	 * counts as one.
	 *
	 * Not while core is running authenticate, as it does for an XML-RPC call's
	 * own credentials: enforce() refuses the name there, and refusing here too
	 * would report the one attempt twice. And never the decoy, whose alarm
	 * core raises only when nothing here refused its use first.
	 *
	 * @param mixed $errors What the check has found so far.
	 * @param mixed $user   The account the password belongs to.
	 * @param mixed $item   The password, as core stores it.
	 */
	public function refuse_blocked_app_password( $errors, $user = null, $item = array() ): void {
		if ( ! $errors instanceof \WP_Error || ! $user instanceof \WP_User || doing_filter( 'authenticate' ) ) {
			return;
		}

		if ( ( is_array( $item ) && \BetterShield\Agents\Canary::is_decoy( $item, (int) $user->ID ) ) || ! $this->blocks_name( $user ) ) {
			return;
		}

		Writer::instance()->record(
			'login_blocked',
			Writer::SEVERITY_LOW,
			array(
				// Named rather than looked up: asking who the request is
				// would run this check again.
				'actor_type'  => 'system',
				'object_type' => 'lockout',
				'object_id'   => 'blocklist',
				'context'     => array(
					'by'  => 'username',
					'via' => 'application_password',
				),
			)
		);

		$errors->add( 'incorrect_password', __( 'The provided password is an invalid application password.', 'bettershield' ) );
	}

	/**
	 * @param bool $available
	 * @return bool
	 */
	public function app_passwords_available( $available ) {
		if ( ! $available ) {
			return $available;
		}

		/*
		 * Core evaluates this filter from `determine_current_user`, on every
		 * request, before it has looked at whether a credential was sent — so
		 * answering it unconditionally read the lockouts table on every
		 * anonymous page view, to refuse a credential that is not there.
		 *
		 * The question is only ever asked about a request that carries one.
		 * Where none does, the availability of the feature is somebody else's
		 * answer to give, and the screens that render the application-password
		 * UI ask on an admin request, which this still answers.
		 */
		if ( ! self::carries_basic_credential() && ! is_admin() ) {
			return $available;
		}

		return ! $this->is_refused_source();
	}

	/**
	 * Whether this request presents the kind of credential the filter is about.
	 *
	 * Application passwords arrive as HTTP Basic, which PHP hands over as
	 * PHP_AUTH_USER or leaves in the Authorization header for the site to
	 * decode — core reads both, so both are looked for here.
	 */
	private static function carries_basic_credential(): bool {
		if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
			return true;
		}

		foreach ( array( 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION' ) as $header ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- read for its scheme alone, never stored or output.
			$value = isset( $_SERVER[ $header ] ) ? (string) $_SERVER[ $header ] : '';

			if ( 0 === stripos( $value, 'basic ' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A wrong application password is a wrong credential from this source
	 * like any other; core announces it with the user it was tried against.
	 *
	 * @param mixed $user
	 */
	public function record_app_password_failure( $user = null ): void {
		// A right password used outside the limit its owner gave it is a
		// refusal of this plugin's own, not a wrong credential: it must not
		// lock out the source it came from.
		if ( $user instanceof \WP_Error && \BetterShield\Agents\PasswordLimits::REFUSED === $user->get_error_code() ) {
			return;
		}

		// Application passwords switched off, for everyone or for this
		// account: "Refuse application passwords", a lockdown, a running
		// pause. Core says so before it compares any password, so it is never
		// a wrong one, and counting it let a tool with the right password
		// pause its own server's address, the owner's sign-in included.
		if ( $user instanceof \WP_Error && in_array( $user->get_error_code(), array( 'application_passwords_disabled', 'application_passwords_disabled_for_user' ), true ) ) {
			return;
		}

		$login = $user instanceof \WP_User ? $user->user_login : '';
		$this->record_failure( $login, new \WP_Error( 'application_password_failed' ) );
	}

	/**
	 * Test seam: a new request, as far as the refusal memory is concerned.
	 */
	public function reset_request_state(): void {
		$this->refused      = false;
		$this->typed_login  = '';
		$this->reserved     = '';
		$this->queued_links = array();
	}

	/**
	 * Note the identifier a sign-in was made with. Core has already trimmed
	 * and sanitized it, and repeats exactly this in its own refusal.
	 *
	 * @param mixed $user     Passed through untouched.
	 * @param mixed $username What was typed.
	 * @return mixed
	 */
	public function note_typed_login( $user, $username = '' ) {
		$this->typed_login = is_string( $username ) ? $username : '';

		return $user;
	}

	/**
	 * A failed attempt: record it, and decide about a lockout — but only on
	 * an address the resolution actually vouched for.
	 *
	 * @param mixed $error The refusal core reports alongside the username, when it has one.
	 */
	public function record_failure( string $username, $error = null ): void {
		// The place this try held is given back only now, once its failure
		// is a row the next try's count includes.
		try {
			$this->count_failure( $username, $error );
		} finally {
			$this->attempt = null;
			$this->give_back_reservation();
		}
	}

	/**
	 * The account and password of this request's sign-in, held only until it
	 * ends in record_failure(), to tell a refused right password from a wrong one.
	 *
	 * @param mixed $user     The account core found.
	 * @param mixed $password What was typed.
	 * @return mixed The account, unchanged.
	 */
	public function note_attempt( $user, $password = '' ) {
		$this->attempt = $user instanceof \WP_User && is_string( $password ) ? array( $user, $password ) : null;

		return $user;
	}

	/**
	 * Another plugin's lockout or block refusals. A right password behind one
	 * of these is no guess, so it isn't counted. Any other refusal still is:
	 * a two-factor plugin that checks the password and the code in one
	 * request refuses with its own code, and those guesses must stay limited.
	 */
	private const OTHER_LOCKOUTS = array(
		'too_many_retries',     // Limit Login Attempts Reloaded.
		'username_blacklisted', // Limit Login Attempts Reloaded.
		'ip_blocked',           // Loginizer.
		'ip_blacklisted',       // Loginizer.
		'user_blacklisted',     // Loginizer.
	);

	/**
	 * Whether another plugin's lockout refused a sign-in whose password was
	 * right. That is no guess at a password, and counted as one it locked the
	 * owner out here too. Only those refusals pay for the check.
	 *
	 * @param mixed $error The refusal core reports.
	 */
	private function another_plugin_refused_right_password( $error ): bool {
		$code = $error instanceof \WP_Error ? (string) $error->get_error_code() : '';

		if ( null === $this->attempt || ! in_array( $code, self::OTHER_LOCKOUTS, true ) ) {
			return false;
		}

		list( $user, $password ) = $this->attempt;

		return wp_check_password( $password, $user->user_pass, $user->ID );
	}

	/**
	 * The count and the lockout decision behind record_failure().
	 *
	 * @param mixed $error The refusal core reports alongside the username, when it has one.
	 */
	private function count_failure( string $username, $error ): void {
		$settings = $this->settings();

		// The puzzle decides from this same count, so it is kept while either
		// is on: with the limit off and the puzzle on, nothing was counted and
		// the puzzle never appeared. Only the pause waits for the limit.
		if ( ! $settings['enabled'] || ( ! $settings['attempt_limit'] && ! $settings['proof_of_work'] ) || SafeMode::is_active() ) {
			return;
		}

		// A sign-in this plugin itself refused — locked, blocklisted, missing
		// its second factor, caught by the honeypot, or missing an unsolved
		// proof-of-work — is not a wrong password and does not count as one.
		// Otherwise every knock on a locked door would deepen the lockout, and
		// a legitimate user on a form this plugin never rendered would lock
		// themselves out asking for a code.
		if ( $this->refused || ( $error instanceof \WP_Error && in_array( $error->get_error_code(), self::own_refusals(), true ) ) ) {
			$this->refused = false;
			return;
		}

		if ( $this->another_plugin_refused_right_password( $error ) ) {
			return;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		if ( '' === $resolved['ip'] || $this->allowlisted( $resolved['ip'], $settings ) ) {
			return;
		}

		$hmac = ClientIp::lockout_hmac( $resolved );

		Gate::record( self::SURFACE, $resolved, self::loggable_identifier( $username ) );

		// A wrong second-factor code means the password was right; the owner
		// is told that plainly, because it changes what they should do next.
		// Kept, because a wrong password can be the try that starts the lockout.
		$after_password = $error instanceof \WP_Error && in_array( $error->get_error_code(), array( 'bettershield_2fa_wrong', 'bettershield_2fa_xmlrpc' ), true );

		if ( $after_password ) {
			Claim::claim( self::password_right_key( $hmac, self::loggable_identifier( $username ) ), HOUR_IN_SECONDS );
			Claim::claim( self::password_right_key( $hmac, '' ), HOUR_IN_SECONDS );
		}

		// The shared-proxy guard, stated as code: no confidence, no lockout.
		// And with the limit off the attempt is counted for the puzzle alone.
		if ( ! $resolved['confident'] || ! $settings['attempt_limit'] ) {
			return;
		}

		$since    = $this->counting_since( $hmac, $settings );
		$failures = Gate::failures_since( self::SURFACE, $hmac, $since );

		/*
		 * A name the owner blocked pauses its source on the first try,
		 * whether or not an account holds it. Nobody who may sign in here
		 * types one, so the threshold's patience is for nobody, and a bot
		 * working through `admin` on a site with no `admin` otherwise had the
		 * full count of tries before anything slowed it. The answer to the try
		 * itself is unchanged, so the list still says nothing about which
		 * names are accounts; only a verified source is ever paused (above),
		 * and an allowlisted one never is.
		 */
		$attempted = '' !== $username ? $username : self::credential_login( $error );
		$named     = $this->blocklisted_username( self::attempted_login( $attempted ), $resolved, $settings );

		if ( ( ! $named && $failures < $settings['threshold'] ) || null !== $this->active_lockout( $hmac ) ) {
			return;
		}

		/*
		 * The one account every failure being answered here named, or nobody.
		 * The unlock link goes to that account and no other: the name on the
		 * try that crossed the threshold is the guesser's to choose, so an
		 * attacker who held any account could end their own run of guesses on
		 * it and have the link that releases their connection mailed to
		 * themselves. A run that named one account throughout is that
		 * person's own mistyping, which is what the link is for.
		 */
		$subjects = Gate::subjects_since( self::SURFACE, $hmac, $since, max( 2, min( $failures, 100 ) ) );
		$sole     = 1 === count( $subjects ) ? $subjects[0] : '';

		/*
		 * Every account whose right password was used here, even if the try
		 * that started the lockout was only a wrong one, and whatever other
		 * names the run tried: one more wrong name must not hide it. Each name
		 * is looked up only when this connection got some password right.
		 */
		$password_right = $after_password ? array( self::loggable_identifier( $username ) ) : array();

		if ( Claim::held( self::password_right_key( $hmac, '' ) ) ) {
			foreach ( $subjects as $subject ) {
				if ( Claim::held( self::password_right_key( $hmac, $subject ) ) ) {
					$password_right[] = $subject;
				}
			}
		}

		$password_right = array_values( array_unique( array_filter( $password_right, 'strlen' ) ) );

		$this->start_lockout( $resolved, $hmac, max( 1, $failures ), $named ? $attempted : $username, $settings, $password_right, $named, $sole );
	}

	/**
	 * The mark that this connection got an account's password right, or with
	 * no login, any account's.
	 */
	private static function password_right_key( string $hmac, string $login ): string {
		return 'password_right_' . substr( hash( 'sha256', $hmac . '|' . $login ), 0, 40 );
	}

	/**
	 * The name an application password was sent with. Over REST core reports
	 * the miss without its account, so the credential itself is asked.
	 *
	 * @param mixed $error The refusal reported alongside the attempt.
	 */
	private static function credential_login( $error ): string {
		if ( ! $error instanceof \WP_Error || 'application_password_failed' !== $error->get_error_code() || ! isset( $_SERVER['PHP_AUTH_USER'] ) ) {
			return '';
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- sanitized as a login, compared against the list and never output.
		return sanitize_user( wp_unslash( (string) $_SERVER['PHP_AUTH_USER'] ) );
	}

	/**
	 * The login an attempt named. Core reports what was typed, which can be
	 * an email address; the blocklist holds logins.
	 */
	private static function attempted_login( string $typed ): string {
		if ( is_email( $typed ) ) {
			$account = get_user_by( 'email', $typed );

			return $account instanceof \WP_User ? $account->user_login : $typed;
		}

		return $typed;
	}

	/**
	 * @param mixed $user
	 */
	public function record_success( string $username, $user = null ): void {
		$settings = $this->settings();

		if ( ! $settings['enabled'] ) {
			return;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		if ( '' === $resolved['ip'] ) {
			return;
		}

		// A success resets the count the honest way: it is a row the window
		// query does not count, and the fact of it is worth having when an
		// admin reads the table.
		Gate::record( self::SURFACE, $resolved, self::loggable_identifier( $username ), 'success' );

		$this->give_back_reservation();
	}

	/**
	 * @param array{ip: string, method: string, confident: bool, paired_with: ?string} $resolved
	 * @param array<string, mixed> $settings
	 * @param string[]             $password_right The accounts whose right password was used here.
	 */
	private function start_lockout( array $resolved, string $hmac, int $failures, string $username, array $settings, array $password_right = array(), bool $named = false, string $sole = '' ): void {
		global $wpdb;

		$token = bin2hex( random_bytes( 32 ) );

		// Longer for a source that keeps coming back; see Gate::escalation().
		$escalation = Gate::escalation( self::SURFACE, $hmac, (int) $settings['lockout_minutes'] );
		$minutes    = $escalation['minutes'];

		$lockout_id = Gate::open_lockout(
			self::SURFACE,
			$resolved,
			$failures,
			self::loggable_identifier( $username ),
			$minutes,
			// A name's pause mails no link, so it keeps none that could work,
			// and nor does a run that named more than one account.
			$named || '' === $sole ? null : hash( 'sha256', $token )
		);

		// Another failure opened it first; that one announces and mails it.
		if ( 0 === $lockout_id ) {
			return;
		}

		$context = array(
			'attempts' => $failures,
			'method'   => $resolved['method'],
			'minutes'  => $minutes,
		);

		// A correct password was used: its holder is told to act, so the
		// weekly summary doesn't say this lockout needed nothing.
		if ( array() !== $password_right ) {
			$context['password_right'] = true;
		}

		// Why it started before the threshold was reached.
		if ( $named ) {
			$context['by'] = 'username';
		}

		// The record says when, and why, a lockout ran longer than configured.
		if ( $escalation['repeat'] > 0 ) {
			$context['repeat']     = $escalation['repeat'];
			$context['configured'] = (int) $settings['lockout_minutes'];
		}

		$event = array(
			'object_type' => 'lockout',
			'object_id'   => (string) $lockout_id,
			'context'     => $context,
		);

		// Started while WordPress is still working out who the request is,
		// as an application password's miss is: asking again would run the
		// credential check, and this failure, a second time.
		if ( doing_filter( 'determine_current_user' ) ) {
			$event['actor_type'] = 'anonymous';
		}

		Writer::instance()->record( 'login_lockout_started', Writer::SEVERITY_LOW, $event );

		// For a firewall jail on this server, when the owner or the host
		// asked for one. Written now rather than queued: the jail has to see
		// it while the pause is still running.
		AuthLog::lockout( self::SURFACE, $resolved['ip'], $minutes );

		// If every failure named one real account, its owner gets the way
		// back in — sent to the address on file, never echoed to the screen,
		// which tells the attacker nothing. The name is the login the attempts
		// were stored under, so an email spelling of it is already resolved.
		$account = '' === $sole ? false : get_user_by( 'login', $sole );

		// A staging copy writes to nobody as the live site: bots on a public
		// copy sent real account holders an unlock link on the staging host.
		if ( \BetterShield\Onboarding\SiteIdentity::is_staging() ) {
			return;
		}

		$unlock = esc_url_raw( add_query_arg( self::UNLOCK_QUERY_VAR, $token, home_url( '/' ) ) );

		/*
		 * Someone got an account's password right. Its holder is told
		 * whichever network it came from, and whatever else the run tried, a
		 * blocked name included, on a limit of its own: an hour's worth of bots
		 * already mailed about must not use up this one. The link goes only to
		 * the account every try named, as below, and never for a blocked name.
		 */
		$warned = false;

		foreach ( $password_right as $login ) {
			$holder = get_user_by( 'login', $login );

			if ( ! $holder instanceof \WP_User ) {
				continue;
			}

			$warned = true;

			if ( is_email( $holder->user_email ) && Claim::claim( 'password_right_mail_' . $holder->ID, HOUR_IN_SECONDS ) ) {
				$this->mail_lockout( $holder, 'password_right', ! $named && $account instanceof \WP_User && $account->ID === $holder->ID ? $unlock : '', $minutes );
			}
		}

		// Nor for a name the owner blocked: it is refused whatever the link
		// does, so the link would only invite another refused try.
		if ( $warned || $named ) {
			return;
		}

		/*
		 * Wrong passwords from a network this account has never used are
		 * bots, nearly always, so they mail nobody. The owner caught on a new
		 * network asks for the link on the sign-in page.
		 */
		if ( ! $account instanceof \WP_User || ! is_email( $account->user_email ) || ! NewLocation::instance()->is_familiar( (int) $account->ID, $resolved ) ) {
			return;
		}

		// One message an hour per account, however many lockouts its name
		// attracts: the link in the first is enough. Taking the hour is the
		// throttle, and it is one statement the database settles: two lockouts
		// crossing the threshold together both found the hour clear and both
		// sent, which is the inbox this exists to protect.
		$throttle = self::unlock_mail_key( (int) $account->ID );

		/*
		 * Except a lockout made longer because its source came back. Its link
		 * is the only one that works — a link releases only while its own
		 * lockout runs, and the one mailed earlier in the hour died with the
		 * shorter lockout it was sent for — so an owner caught by their own
		 * repeats was held for up to an hour with nothing to press. Each
		 * longer length is mailed once an hour, which bounds the extra mail at
		 * one per doubling, and a fresh source is still held to the hour.
		 */
		if ( Claim::claim( $throttle, HOUR_IN_SECONDS ) || ( $escalation['repeat'] > 0 && Claim::claim( $throttle . '_' . $minutes, HOUR_IN_SECONDS ) ) ) {
			$this->mail_lockout( $account, 'familiar', $unlock, $minutes );
		}
	}

	/** The hour an account's unlock mail holds. */
	private static function unlock_mail_key( int $user_id ): string {
		return 'unlock_mail_' . $user_id;
	}

	/**
	 * Tell an account holder about a lockout, and record that it was sent.
	 *
	 * @param string $why    `password_right`, `familiar` or `requested`.
	 * @param string $unlock The unlock link, or empty when this reader isn't owed one.
	 */
	private function mail_lockout( \WP_User $account, string $why, string $unlock, int $minutes ): void {
		// In the account holder's own language. Written in the request's, the
		// language was the one whoever was guessing picked on the sign-in screen.
		$switched = switch_to_user_locale( (int) $account->ID );
		$site     = wp_specialchars_decode( (string) get_option( 'blogname' ), ENT_QUOTES );

		if ( 'password_right' === $why ) {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] Action needed: someone has your password', 'bettershield' ), $site );
			$body    = __( 'Action needed.', 'bettershield' ) . ' ' . sprintf(
				/* translators: 1: number of minutes. */
				_n(
					'Someone entered your correct password, then wrong two-factor codes. Their internet connection is locked out of signing in for %1$d minute. If this wasn’t you, change your password now.',
					'Someone entered your correct password, then wrong two-factor codes. Their internet connection is locked out of signing in for %1$d minutes. If this wasn’t you, change your password now.',
					$minutes,
					'bettershield'
				),
				$minutes
			);
		} elseif ( 'requested' === $why ) {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] Your unlock link', 'bettershield' ), $site );
			$body    = __( 'Someone asked for a link to end a sign-in lockout on your account. If it wasn’t you, ignore this email. Your password hasn’t changed.', 'bettershield' );
		} else {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] Nothing urgent: your sign-in was paused', 'bettershield' ), $site );
			$body    = __( 'Nothing urgent.', 'bettershield' ) . ' ' . sprintf(
				/* translators: 1: number of minutes. */
				_n(
					'Someone entered wrong passwords for your account, so their internet connection is locked out of signing in for %1$d minute.',
					'Someone entered wrong passwords for your account, so their internet connection is locked out of signing in for %1$d minutes.',
					$minutes,
					'bettershield'
				),
				$minutes
			) . ' ' . __( 'Your password wasn’t guessed, and you can still sign in from anywhere else.', 'bettershield' );
		}

		if ( '' !== $unlock ) {
			$body .= "\n\n" . sprintf(
				/* translators: %s: unlock URL. */
				__( 'If this was you, use this link to sign in again right away: %s', 'bettershield' ),
				$unlock
			);
		}

		if ( $switched ) {
			restore_previous_locale();
		}

		$sent = wp_mail( $account->user_email, $subject, $body );

		$event = array(
			'object_type' => 'user',
			'object_id'   => (string) $account->ID,
			'context'     => array(
				'why'       => $why,
				'delivered' => (bool) $sent,
			),
		);

		// As the lockout's own row: asking who this is would run the
		// credential check again.
		if ( doing_filter( 'determine_current_user' ) ) {
			$event['actor_type'] = 'anonymous';
		}

		Writer::instance()->record( 'login_lockout_emailed', Writer::SEVERITY_INFO, $event );
	}

	/**
	 * The way to ask for an unlock link, on the sign-in screens of a connection
	 * that is locked out. It doesn't say why, so it says nothing of a blocked name.
	 *
	 * @param mixed $message What the screen already says above its form.
	 * @return mixed
	 */
	public function offer_unlock_link( $message ) {
		$settings = $this->settings();

		if ( ! $settings['enabled'] || ! $settings['attempt_limit'] || SafeMode::is_active() ) {
			return $message;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		if ( '' === $resolved['ip'] || empty( $resolved['confident'] ) || null === $this->active_lockout( ClientIp::lockout_hmac( $resolved ) ) ) {
			return $message;
		}

		return $message . '<p class="message">' . esc_html__( 'This connection is locked out of signing in for now.', 'bettershield' ) . ' <a href="' . esc_url( add_query_arg( self::UNLOCK_REQUEST_VAR, '1', home_url( '/' ) ) ) . '">' . esc_html__( 'Email Me an Unlock Link', 'bettershield' ) . '</a></p>';
	}

	/**
	 * The page that asks for an unlock link, and the request it sends.
	 *
	 * Reached from the home address, as the link itself is, so it works on a
	 * moved sign-in address. Every request gets the same answer. The link goes
	 * only to the address on the account, and only when this connection is
	 * locked out by tries that named that account alone, so someone holding
	 * an account of their own can't use it to go on guessing at another.
	 */
	public function maybe_handle_unlock_request(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no session to derive a nonce from; the limits below are the guard.
		if ( ! isset( $_REQUEST[ self::UNLOCK_REQUEST_VAR ] ) ) {
			return;
		}

		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET' ) ) {
			$this->show_unlock_request();

			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- no session to derive a nonce from; sanitized as a login and only ever looked up.
		$typed = isset( $_POST['bettershield_unlock_login'] ) && is_string( $_POST['bettershield_unlock_login'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['bettershield_unlock_login'] ) ) ) : '';

		$this->answer_unlock_request( $typed );
		$this->show_unlock_request( true );
	}

	/**
	 * Send the link when this request has earned one.
	 */
	private function answer_unlock_request( string $typed ): void {
		$settings = $this->settings();

		if ( ! $settings['enabled'] || '' === $typed || mb_strlen( $typed ) > 254 ) {
			return;
		}

		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		// A lockout is only ever held against a connection something vouches for.
		if ( '' === $resolved['ip'] || empty( $resolved['confident'] ) ) {
			return;
		}

		$hmac = ClientIp::lockout_hmac( $resolved );

		// Past this, nothing is written either: a flood stays one network's hour.
		if ( Claim::bump( 'unlock_ask_' . substr( $hmac, 0, 40 ), HOUR_IN_SECONDS ) > self::UNLOCK_REQUESTS_PER_NETWORK ) {
			return;
		}

		$sent    = false;
		$lockout = $this->active_lockout( $hmac );
		$login   = self::loggable_identifier( $typed );
		$account = '' === $login ? false : get_user_by( 'login', $login );

		// A lockout with no token is one that was never owed a link: a blocked
		// name, or tries at more than one account.
		if (
			null !== $lockout
			&& $account instanceof \WP_User
			&& null !== $lockout->unlock_token_hash
			&& $account->user_login === (string) $lockout->last_username
			&& is_email( $account->user_email )
			&& ! \BetterShield\Onboarding\SiteIdentity::is_staging()
			&& self::take_link_room( (int) $account->ID, $hmac, (int) $lockout->id, self::lockout_ends( $lockout ) )
		) {
			$token = bin2hex( random_bytes( 32 ) );
			$hash  = hash( 'sha256', $token );

			if ( Gate::replace_unlock_token( (int) $lockout->id, $hash ) ) {
				$ends = self::lockout_ends( $lockout );

				self::keep_earlier_link( (string) $lockout->unlock_token_hash, $hash, $ends );

				// Sent once the answer has gone, so how long the answer takes
				// doesn't say whether a link was owed.
				$this->queue_link( $account, esc_url_raw( add_query_arg( self::UNLOCK_QUERY_VAR, $token, home_url( '/' ) ) ), 0 === $ends ? 1 : max( 1, (int) ceil( ( $ends - time() ) / MINUTE_IN_SECONDS ) ) );
				$sent = true;
			}
		}

		Writer::instance()->record(
			'login_unlock_requested',
			Writer::SEVERITY_LOW,
			array(
				'actor_type'  => 'anonymous',
				'object_type' => 'lockout',
				'object_id'   => null !== $lockout ? (string) $lockout->id : '',
				'context'     => array( 'sent' => $sent ),
			)
		);
	}

	/**
	 * Take room to send one requested link, or leave everything as it was.
	 *
	 * One for each lockout, account and connection: a lockout made longer
	 * because its source came back is a new row, and its link is the only one
	 * that releases it, so it gets its own. Then the account's hourly limit
	 * across connections, and last the site's. Each is taken only when the one
	 * before it allowed it, and given back when a later one refuses, so a
	 * refused request uses up nothing.
	 *
	 * @param int $lockout_id The running lockout the link is for.
	 * @param int $ends       When that lockout ends, as a Unix time, or 0 if unknown.
	 */
	private static function take_link_room( int $user_id, string $hmac, int $lockout_id, int $ends ): bool {
		$connection = 'unlock_link_' . $user_id . '_' . $hmac . '_' . $lockout_id;
		$account    = 'unlock_links_account_' . $user_id;

		// Held for as long as the lockout runs, so a long one still gets one link.
		if ( ! Claim::claim( $connection, max( HOUR_IN_SECONDS, $ends - time() ) ) ) {
			return false;
		}

		if ( Claim::bump( $account, HOUR_IN_SECONDS ) > self::UNLOCK_LINKS_PER_ACCOUNT ) {
			Claim::give_back( $account );
			Claim::release( $connection );

			return false;
		}

		if ( Claim::bump( 'unlock_links_sent', HOUR_IN_SECONDS ) > self::UNLOCK_LINKS_PER_SITE ) {
			Claim::give_back( 'unlock_links_sent' );
			Claim::give_back( $account );
			Claim::release( $connection );

			return false;
		}

		return true;
	}

	/**
	 * When a lockout row ends, as a Unix time, or 0 if it can't be read.
	 */
	private static function lockout_ends( object $lockout ): int {
		$ends = strtotime( (string) $lockout->expires_at . ' UTC' );

		return false === $ends ? 0 : $ends;
	}

	/**
	 * Keep a lockout's earlier link working once a newer one is sent.
	 *
	 * The row holds one hash, so the earlier link's hash is kept here,
	 * pointing at the newer one's. It works only while the row still holds
	 * that newer hash: a third link retires the first, and a lockout that
	 * ends, by its link or its time, clears the hash and every link with it.
	 * Only hashes are stored, never a link. Held for the network, as the
	 * lockouts are: the earlier link may name another site of it.
	 *
	 * @param int $ends When the lockout ends, as a Unix time, or 0 if unknown.
	 */
	private static function keep_earlier_link( string $earlier, string $newer, int $ends ): void {
		if ( 1 !== preg_match( '/^[0-9a-f]{64}$/', $earlier ) ) {
			return;
		}

		set_site_transient( self::UNLOCK_ALIAS . $earlier, $newer, max( MINUTE_IN_SECONDS, $ends - time() ) );
	}

	/**
	 * The hash a running lockout holds for this link: the link's own, or for
	 * an earlier link of a lockout that has since sent a newer one, that one's.
	 */
	private static function stored_unlock_hash( string $token ): string {
		$hash  = hash( 'sha256', $token );
		$newer = get_site_transient( self::UNLOCK_ALIAS . $hash );

		return is_string( $newer ) && 1 === preg_match( '/^[0-9a-f]{64}$/', $newer ) ? $newer : $hash;
	}

	/**
	 * Send a requested link once this request's answer has gone.
	 */
	private function queue_link( \WP_User $account, string $unlock, int $minutes ): void {
		if ( array() === $this->queued_links ) {
			// After core empties its output buffers at 1, before the event
			// writer's flush at 100 records that the mail went.
			add_action( 'shutdown', array( $this, 'send_queued_links' ), 2 );
		}

		$this->queued_links[] = array( $account, $unlock, $minutes );
	}

	/**
	 * Send the links this request queued. Where the server can end the
	 * response first it does; elsewhere the page has already been written out.
	 */
	public function send_queued_links(): void {
		$queued             = $this->queued_links;
		$this->queued_links = array();

		if ( array() === $queued ) {
			return;
		}

		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
		} elseif ( function_exists( 'litespeed_finish_request' ) ) {
			litespeed_finish_request();
		} else {
			flush();
		}

		foreach ( $queued as list( $account, $unlock, $minutes ) ) {
			$this->mail_lockout( $account, 'requested', $unlock, $minutes );
		}
	}

	/**
	 * The form, or after it has been sent, the one answer it gives.
	 */
	private function show_unlock_request( bool $asked = false ): void {
		nocache_headers();

		$page = '<h1>' . esc_html__( 'Get an unlock link', 'bettershield' ) . '</h1>';

		if ( $asked ) {
			$page .= '<p>' . esc_html__( 'If this connection is locked out by tries at that account, an unlock link is on its way to the email address on the account.', 'bettershield' ) . '</p>';
		} else {
			$page .= '<p>' . esc_html__( 'Enter your username or email address. If it matches, we’ll email a link to the address on your account.', 'bettershield' ) . '</p>'
				. '<form method="post" action="' . esc_url( add_query_arg( self::UNLOCK_REQUEST_VAR, '1', home_url( '/' ) ) ) . '">'
				. '<p><label for="bettershield_unlock_login">' . esc_html__( 'Username or email address', 'bettershield' ) . '</label><br />'
				. '<input type="text" id="bettershield_unlock_login" name="bettershield_unlock_login" autocomplete="username" required="required" /></p>'
				. '<p><button type="submit" style="padding:10px 16px;font-size:15px;">' . esc_html__( 'Email Me an Unlock Link', 'bettershield' ) . '</button></p>'
				. '</form>';
		}

		// No link to the sign-in page: anyone can open this one, and on a moved
		// address that link would give the address away.
		$page .= '<p>' . esc_html__( 'A lockout also ends on its own after a short wait.', 'bettershield' ) . '</p>';

		wp_die( wp_kses( $page, self::UNLOCK_HTML ), esc_html__( 'Get an unlock link', 'bettershield' ), array( 'response' => 200 ) );
	}

	public function maybe_handle_unlock(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- the token is the credential, same shape as core's reset link and this plugin's recovery link; there is no session to derive a nonce from.
		$posted = isset( $_POST[ self::UNLOCK_QUERY_VAR ] ) && is_string( $_POST[ self::UNLOCK_QUERY_VAR ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::UNLOCK_QUERY_VAR ] ) ) : '';
		$given  = isset( $_GET[ self::UNLOCK_QUERY_VAR ] ) && is_string( $_GET[ self::UNLOCK_QUERY_VAR ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::UNLOCK_QUERY_VAR ] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended

		$token = '' !== $posted ? $posted : $given;

		if ( 1 !== preg_match( '/^[0-9a-f]{64}$/', $token ) ) {
			return;
		}

		/*
		 * Following the link shows a page; a person pressing its button is
		 * what clears the lockout.
		 *
		 * This link is emailed to the account being signed in to, while the
		 * lockout it clears belongs to whoever was guessing at it — so the
		 * mail gateway or link preview that opens every delivered link before
		 * a human sees it was lifting an attacker's block within seconds of
		 * it being set, and the owner's own click then found the link spent.
		 * Core's reset link, which this one is modeled on, works the same way
		 * round: the GET shows a form and the POST is the action.
		 */
		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET' ) ) {
			$this->show_unlock_confirm( $token );

			return;
		}

		global $wpdb;

		// The inner lookup carries the same freshness conditions as the outer
		// update. Without them the address could be resolved from a row the
		// token had long outlived — one already released, or expired hours ago
		// — while the update itself could only ever clear live rows. The
		// token's own row therefore kept its hash, and the link went on
		// releasing whatever later lockout that network happened to be under.
		/*
		 * Before the surface column lands, naming it here would match nothing
		 * and take away the one early exit from a lockout there is — and the
		 * link points at the front end, which is exactly where the migration
		 * is deferred to shutdown. Before the column exists every lockout is a
		 * sign-in lockout, so the un-surfaced statement is the correct one.
		 */
		$updated = Gate::surfaced()
			? $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET released_at = %s, release_reason = 'email_link', unlock_token_hash = NULL
					 WHERE site_id = 0 AND surface = %s AND ip_hmac = (
						SELECT ip_hmac FROM ( SELECT ip_hmac FROM %i WHERE site_id = 0 AND surface = %s AND unlock_token_hash = %s AND released_at IS NULL AND expires_at > %s LIMIT 1 ) AS matched
					 ) AND released_at IS NULL AND expires_at > %s",
					Schema::table( 'lockouts' ),
					Time::stamp(),
					self::SURFACE,
					Schema::table( 'lockouts' ),
					self::SURFACE,
					self::stored_unlock_hash( $token ),
					Time::stamp(),
					Time::stamp()
				)
			)
			: $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET released_at = %s, release_reason = 'email_link', unlock_token_hash = NULL
					 WHERE site_id = 0 AND ip_hmac = (
						SELECT ip_hmac FROM ( SELECT ip_hmac FROM %i WHERE site_id = 0 AND unlock_token_hash = %s AND released_at IS NULL AND expires_at > %s LIMIT 1 ) AS matched
					 ) AND released_at IS NULL AND expires_at > %s",
					Schema::table( 'lockouts' ),
					Time::stamp(),
					Schema::table( 'lockouts' ),
					self::stored_unlock_hash( $token ),
					Time::stamp(),
					Time::stamp()
				)
			);

		// A statement that could not run is not a token that did not match.
		// Only one of the two is evidence of anything, and counting the other
		// against the recovery door would answer an owner's own valid link
		// with a failure recorded against them.
		$errored = '' !== (string) $wpdb->last_error;

		// Every active row for that address, not the one row the token was
		// stored on. Failed sign-ins arriving at once can each open a lockout
		// for the same address — the owner is emailed one token, and clearing
		// only its row left them locked out by the rest, which is the opposite
		// of what the link is for.
		//
		// Every active row *on this surface*, since the tables hold more than
		// one. A link sent about a sign-in says nothing about a flood of
		// comments from the same network, and clearing that too would let one
		// email undo a decision it never mentioned.
		if ( $updated < 1 ) {
			if ( ! $errored ) {
				/*
				 * Through the same window the recovery link and the offline
				 * codes report to. Three credentials open this one door, and a
				 * run of guesses at any of them is one coalesced event rather
				 * than three separate quieter attacks — or, as this one was,
				 * none at all.
				 */
				RecoveryLink::record_failure();
			}

			wp_die(
				esc_html__( 'This unlock link was already used or has expired. A lockout ends on its own when its time is up.', 'bettershield' ),
				esc_html__( 'Link expired', 'bettershield' ),
				array( 'response' => 410 )
			);
		}

		Writer::instance()->record(
			'login_lockout_cleared',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'lockout',
				'object_id'   => 'email_link',
				// Only a sign-in lockout emails an unlock link.
				'context'     => array( 'surface' => Surfaces::SIGNIN ),
			)
		);

		wp_die(
			'<h1>' . esc_html__( 'Unlocked', 'bettershield' ) . '</h1><p>' .
			esc_html__( 'The lockout is cleared. You can sign in now.', 'bettershield' ) .
			'</p><p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Go to sign-in', 'bettershield' ) . '</a></p>',
			esc_html__( 'Unlocked', 'bettershield' ),
			array( 'response' => 200 )
		);
	}

	/**
	 * The markup the unlock page is made of, and nothing else: a heading, its
	 * paragraphs, and the form whose button clears the lockout.
	 */
	private const UNLOCK_HTML = array(
		'h1'     => array(),
		'p'      => array(),
		'form'   => array(
			'method' => true,
			'action' => true,
		),
		'input'  => array(
			'type'         => true,
			'name'         => true,
			'value'        => true,
			'id'           => true,
			'autocomplete' => true,
			'required'     => true,
		),
		'label'  => array(
			'for' => true,
		),
		'br'     => array(),
		'button' => array(
			'type'  => true,
			'style' => true,
		),
	);

	/**
	 * The page the emailed unlock link lands on, with the button that clears
	 * the lockout.
	 *
	 * Nothing is read, changed or spent here, and a request that never
	 * presses the button leaves the lockout exactly as it found it.
	 */
	private function show_unlock_confirm( string $token ): void {
		// The reader is the account holder the email went to, so the page
		// speaks to them, and says when the lockout ends rather than "after a
		// short wait": its length is the owner's setting, and longer for a
		// connection that keeps coming back (#2843).
		$minutes = self::unlock_minutes_left( $token );

		// A link already used, or whose lockout ended, says so now rather
		// than offering a button that can only fail. Still read only: a
		// preview that opens a spent link records nothing.
		if ( null === $minutes ) {
			wp_die(
				esc_html__( 'This unlock link was already used or has expired. A lockout ends on its own when its time is up.', 'bettershield' ),
				esc_html__( 'Link expired', 'bettershield' ),
				array( 'response' => 410 )
			);
		}

		$keep = $minutes > 0
			? sprintf(
				/* translators: %d: minutes until the lockout ends on its own. */
				_n(
					'If those sign-ins weren’t you, close this page. The lockout ends on its own in about %d minute.',
					'If those sign-ins weren’t you, close this page. The lockout ends on its own in about %d minutes.',
					$minutes,
					'bettershield'
				),
				$minutes
			)
			: __( 'If those sign-ins weren’t you, close this page. The lockout ends on its own when its time is up.', 'bettershield' );

		$page = '<h1>' . esc_html__( 'Clear the sign-in lockout?', 'bettershield' ) . '</h1><p>' .
			esc_html__( 'There were too many wrong sign-ins on your account, so the connection they came from is locked out.', 'bettershield' ) .
			'</p><p>' .
			esc_html( $keep ) .
			'</p><form method="post" action="' . esc_url( add_query_arg( self::UNLOCK_QUERY_VAR, $token, home_url( '/' ) ) ) . '">' .
			'<input type="hidden" name="' . esc_attr( self::UNLOCK_QUERY_VAR ) . '" value="' . esc_attr( $token ) . '" />' .
			'<p><button type="submit" style="padding:10px 16px;font-size:15px;">' . esc_html__( 'Clear the Lockout', 'bettershield' ) . '</button></p>' .
			'</form>';

		// Every part is escaped where it is built. Not filtered through the
		// post allowlist on the way out: that allows no form and no input, so
		// the button pressed nothing and no link could unlock anything.
		wp_die(
			wp_kses( $page, self::UNLOCK_HTML ),
			esc_html__( 'Unlock', 'bettershield' ),
			array( 'response' => 200 )
		);
	}

	/**
	 * Whole minutes until the lockout an unlock link would clear ends on its
	 * own, null where no running lockout carries that link, or 0 where the
	 * table could not be read, which says nothing about the link. Read only:
	 * the page that asks it changes nothing.
	 */
	private static function unlock_minutes_left( string $token ): ?int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the plugin's own table, read once for one page; every value is bound.
		$expires = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT expires_at FROM %i WHERE site_id = 0 AND unlock_token_hash = %s AND released_at IS NULL AND expires_at > %s ORDER BY expires_at DESC LIMIT 1',
				Schema::table( 'lockouts' ),
				self::stored_unlock_hash( $token ),
				Time::stamp()
			)
		);

		if ( null === $expires ) {
			return '' === (string) $wpdb->last_error ? null : 0;
		}

		$ends = strtotime( (string) $expires . ' UTC' );

		return false === $ends ? 0 : max( 1, (int) ceil( ( $ends - time() ) / MINUTE_IN_SECONDS ) );
	}

	/* ---- admin surface -------------------------------------------------------- */

	/**
	 * Lockouts for the screen: active first, then recent history.
	 *
	 * Running ones are ordered ahead of the cut, not only ahead of the rest of
	 * what survived it. The list is where a lockout is released, and one that
	 * started before fifty newer, already-ended ones would otherwise be off it
	 * while still running. The cut applies to ended ones only: with more
	 * running than it allows, the list grows to carry every one of them, up to
	 * RUNNING_LISTED. `lockout_total()` says how many there are in all, and
	 * `lockout_running()` how many are running.
	 *
	 * Every surface by default, not the sign-in form alone. A lockout the
	 * plugin opened on a public form has nobody to email and expires on its
	 * own, so the list is the only place an owner can see that it happened —
	 * and a list reading "no lockouts" while three are running teaches them to
	 * stop looking.
	 *
	 * @param string[] $surfaces Empty means every surface.
	 * @return array<int, array<string, mixed>>
	 */
	public function lockouts( int $limit = 50, array $surfaces = array() ): array {
		global $wpdb;

		$wanted = array() === $surfaces ? Surfaces::ALL : array_values( array_intersect( $surfaces, Surfaces::ALL ) );

		if ( array() === $wanted ) {
			return array();
		}

		$table = Schema::table( 'lockouts' );
		$now   = Time::stamp();
		$limit = max( $limit, min( $this->lockout_running( $wanted ), self::RUNNING_LISTED ) );

		if ( ! Gate::surfaced() ) {
			/*
			 * Before the column that keeps surfaces apart lands, every row in
			 * this table is a sign-in lockout — these tables have never held
			 * anything else — so the un-surfaced query is the correct query
			 * rather than a degraded one. Naming the column through that
			 * window returns nothing at all, which is how a screen comes to
			 * report quiet while lockouts are running.
			 */
			$rows = in_array( Surfaces::SIGNIN, $wanted, true )
				? $wpdb->get_results(
					$wpdb->prepare(
						'SELECT id, ip_prefix, started_at, expires_at, released_at, release_reason, attempts, last_username FROM %i
						 WHERE site_id = 0 ORDER BY ( released_at IS NULL AND expires_at > %s ) DESC, started_at DESC, id DESC LIMIT %d',
						$table,
						$now,
						$limit
					)
				)
				: array();
		} else {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder run's length comes from this class's own surface list, never from a request, and every value is bound.
			$placeholders = implode( ', ', array_fill( 0, count( $wanted ), '%s' ) );

			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT id, surface, ip_prefix, started_at, expires_at, released_at, release_reason, attempts, last_username FROM %i
					 WHERE site_id = 0 AND surface IN (' . $placeholders . ') ORDER BY ( released_at IS NULL AND expires_at > %s ) DESC, started_at DESC, id DESC LIMIT %d',
					array_merge( array( $table ), $wanted, array( $now, $limit ) )
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		$out = array();

		foreach ( $rows as $row ) {
			$surface = isset( $row->surface ) ? (string) $row->surface : Surfaces::SIGNIN;

			$out[] = array(
				'id'            => (int) $row->id,
				// Which form this row closed, said in words: a row that does
				// not name its surface is a row an owner cannot act on.
				'surface'       => $surface,
				'surface_label' => Surfaces::label( $surface ),
				// The stored prefix renders as the /24 or /64 it is — the
				// display never claims more precision than is kept.
				'network'       => Ip::prefix_label( (string) $row->ip_prefix ) ?? __( 'unknown network', 'bettershield' ),
				// Stored UTC without a zone marker; said explicitly, or the
				// browser reads both as local time.
				'started_at'    => Time::utc_iso( (string) $row->started_at ),
				'expires_at'    => Time::utc_iso( (string) $row->expires_at ),
				'active'        => null === $row->released_at && $row->expires_at > $now,
				'released'      => null !== $row->released_at,
				'release_reason' => $row->release_reason,
				'attempts'      => (int) $row->attempts,
				'last_username' => $row->last_username,
				// How long it was set to last, which a source that keeps
				// coming back makes longer than configured.
				'minutes'       => (int) round( ( (int) strtotime( (string) $row->expires_at . ' UTC' ) - (int) strtotime( (string) $row->started_at . ' UTC' ) ) / MINUTE_IN_SECONDS ),
				'repeat'        => 0,
			);
		}

		/*
		 * Whether a lockout ran longer because its source came back is a fact
		 * about when it started, and its own record carries it. Worked out on
		 * the screen against today's setting, every lockout made while the
		 * pause was longer read as escalated once the setting was lowered.
		 */
		$repeats = $this->repeats( $out, $rows );

		foreach ( array_keys( $out ) as $index ) {
			$out[ $index ]['repeat'] = $repeats[ $out[ $index ]['id'] ] ?? 0;
		}

		return $out;
	}

	/**
	 * How many earlier lockouts each listed sign-in lockout was made longer
	 * for, read from its `login_lockout_started` record. A lockout whose
	 * record is gone, past the log's retention, reads as not made longer:
	 * saying nothing is better than a reason that may not be true.
	 *
	 * @param array<int, array<string, mixed>> $lockouts
	 * @param array<int, object>               $rows
	 * @return array<int, int> Repeat count by lockout id.
	 */
	private function repeats( array $lockouts, array $rows ): array {
		global $wpdb;

		$ids      = array();
		$earliest = '';

		foreach ( $lockouts as $index => $lockout ) {
			if ( Surfaces::SIGNIN !== $lockout['surface'] ) {
				continue;
			}

			$ids[]   = (string) $lockout['id'];
			$started = (string) $rows[ $index ]->started_at;

			if ( '' === $earliest || $started < $earliest ) {
				$earliest = $started;
			}
		}

		if ( array() === $ids || ! Schema::ready( 'events' ) ) {
			return array();
		}

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder run's length is the number of rows just listed, never from a request, and every value is bound.
		$placeholders = implode( ', ', array_fill( 0, count( $ids ), '%s' ) );

		// Bounded below by the earliest listed start, so the type-and-time
		// index answers it whatever the log holds.
		$records = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT object_id, context FROM %i WHERE site_id = %d AND event_type = 'login_lockout_started' AND occurred_at >= %s AND object_type = 'lockout' AND object_id IN (" . $placeholders . ')',
				array_merge( array( Schema::table( 'events' ), Schema::site_id( 'events' ), Time::stamp( (int) strtotime( $earliest . ' UTC' ) - MINUTE_IN_SECONDS ) ), $ids )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$repeats = array();

		foreach ( (array) $records as $record ) {
			$context = json_decode( (string) $record->context, true );

			$repeats[ (int) $record->object_id ] = is_array( $context ) ? max( 0, (int) ( $context['repeat'] ?? 0 ) ) : 0;
		}

		return $repeats;
	}

	/**
	 * How many lockouts there are on the surfaces `lockouts()` lists, however
	 * many of them it listed, so the screen can say when its list was cut.
	 *
	 * @param string[] $surfaces Empty means every surface.
	 */
	public function lockout_total( array $surfaces = array() ): int {
		return $this->count_lockouts( $surfaces, false );
	}

	/**
	 * How many of those are running now. The screen counts what is in force
	 * from this rather than from the list it was sent, which can be cut.
	 *
	 * @param string[] $surfaces Empty means every surface.
	 */
	public function lockout_running( array $surfaces = array() ): int {
		return $this->count_lockouts( $surfaces, true );
	}

	/**
	 * A page of lockouts, newest first, for a reader that pages by the last
	 * id it was given: each one's form, network, window, whether it is in
	 * force and how many attempts set it off. Never the username it last saw,
	 * which belongs on the owner's screen and nowhere a connection reads.
	 *
	 * @param string[] $surfaces Empty means every surface.
	 * @param int      $before   Only lockouts older than this id; 0 for the newest.
	 * @return array{lockouts: array<int, array<string, mixed>>, has_more: bool}|\WP_Error
	 */
	public function lockout_page( array $surfaces, int $before, int $limit ) {
		global $wpdb;

		$wanted = array() === $surfaces ? Surfaces::ALL : array_values( array_intersect( $surfaces, Surfaces::ALL ) );
		$limit  = max( 1, min( 100, $limit ) );
		$table  = Schema::table( 'lockouts' );
		$now    = Time::stamp();

		if ( array() === $wanted ) {
			return array( 'lockouts' => array(), 'has_more' => false );
		}

		if ( ! Gate::surfaced() ) {
			// Every row is a sign-in lockout until the surface column lands; see lockouts().
			$rows = in_array( Surfaces::SIGNIN, $wanted, true )
				? $wpdb->get_results(
					$wpdb->prepare(
						'SELECT id, ip_prefix, started_at, expires_at, released_at, attempts FROM %i
						 WHERE site_id = 0 AND ( %d = 0 OR id < %d ) ORDER BY id DESC LIMIT %d',
						$table,
						$before,
						$before,
						$limit + 1
					)
				)
				: array();
		} else {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder run's length comes from this class's own surface list, never from a request, and every value is bound.
			$placeholders = implode( ', ', array_fill( 0, count( $wanted ), '%s' ) );

			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT id, surface, ip_prefix, started_at, expires_at, released_at, attempts FROM %i
					 WHERE site_id = 0 AND surface IN (' . $placeholders . ') AND ( %d = 0 OR id < %d ) ORDER BY id DESC LIMIT %d',
					array_merge( array( $table ), $wanted, array( $before, $before, $limit + 1 ) )
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		if ( '' !== $wpdb->last_error ) {
			return new \WP_Error( 'bettershield_lockouts_unreadable', __( 'The lockouts could not be read.', 'bettershield' ), array( 'status' => 503 ) );
		}

		$out = array();

		foreach ( array_slice( (array) $rows, 0, $limit ) as $row ) {
			$out[] = array(
				'id'             => (int) $row->id,
				'surface'        => isset( $row->surface ) ? (string) $row->surface : Surfaces::SIGNIN,
				'address_prefix' => Ip::prefix_label( (string) $row->ip_prefix ) ?? '',
				'started_at'     => Time::utc_iso( (string) $row->started_at ),
				'expires_at'     => Time::utc_iso( (string) $row->expires_at ),
				'active'         => null === $row->released_at && $row->expires_at > $now,
				'attempts'       => (int) $row->attempts,
			);
		}

		return array( 'lockouts' => $out, 'has_more' => count( (array) $rows ) > $limit );
	}

	/**
	 * @param string[] $surfaces Empty means every surface.
	 * @param bool     $running  Only the ones in force now.
	 */
	private function count_lockouts( array $surfaces, bool $running ): int {
		global $wpdb;

		$wanted = array() === $surfaces ? Surfaces::ALL : array_values( array_intersect( $surfaces, Surfaces::ALL ) );

		if ( array() === $wanted ) {
			return 0;
		}

		$table = Schema::table( 'lockouts' );
		$where = $running ? ' AND released_at IS NULL AND expires_at > %s' : '';
		$now   = $running ? array( Time::stamp() ) : array();

		// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the condition is one of two fixed strings and the placeholder run's length comes from this class's own surface list, never from a request; every value is bound.

		// The same two shapes as the list, for the same reason: before the
		// surface column lands, every row here is a sign-in lockout.
		if ( ! Gate::surfaced() ) {
			return in_array( Surfaces::SIGNIN, $wanted, true )
				? (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE site_id = 0' . $where, array_merge( array( $table ), $now ) ) )
				: 0;
		}

		$placeholders = implode( ', ', array_fill( 0, count( $wanted ), '%s' ) );

		$total = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM %i WHERE site_id = 0 AND surface IN (' . $placeholders . ')' . $where,
				array_merge( array( $table ), $wanted, $now )
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return $total;
	}

	/**
	 * Clear a lockout from the admin screen.
	 *
	 * @return true|\WP_Error
	 */
	public function release( int $id ) {
		global $wpdb;

		$table = Schema::table( 'lockouts' );

		/*
		 * The row's own surface, read from the row rather than assumed. Pinned
		 * to the sign-in constant this cleared nothing at all for the three
		 * public forms, and answered that their live lockout was already over.
		 * Dropping the condition instead would be worse: one click would
		 * release every surface that address is under, including a sign-in
		 * lockout nobody asked about.
		 */
		$matched = Gate::surfaced()
			? $wpdb->get_row( $wpdb->prepare( 'SELECT ip_hmac, surface FROM %i WHERE site_id = 0 AND id = %d LIMIT 1', $table, $id ) )
			: $wpdb->get_row( $wpdb->prepare( 'SELECT ip_hmac FROM %i WHERE site_id = 0 AND id = %d LIMIT 1', $table, $id ) );

		// An id nothing carries is not a lockout that ended (#1797).
		if ( null === $matched ) {
			return new \WP_Error( 'bettershield_unknown_lockout', __( 'No lockout has that id.', 'bettershield' ), array( 'status' => 404 ) );
		}

		/*
		 * Only what is still running is released. A row whose time ran out
		 * is over already, and releasing it said "released" and logged a
		 * release for a lockout that had ended on its own (#1797), as
		 * release_all() never did.
		 */
		$now = Time::stamp();

		// Same reasoning as the emailed link: release the address, not the row
		// the operator happened to click. Leaving siblings active would answer
		// "released" while the address stayed locked.
		$updated = Gate::surfaced()
			? $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET released_at = %s, release_reason = 'admin', unlock_token_hash = NULL
					 WHERE site_id = 0 AND surface = %s AND ip_hmac = %s AND released_at IS NULL AND expires_at > %s",
					$table,
					$now,
					(string) $matched->surface,
					(string) $matched->ip_hmac,
					$now
				)
			)
			: $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET released_at = %s, release_reason = 'admin', unlock_token_hash = NULL
					 WHERE site_id = 0 AND ip_hmac = %s AND released_at IS NULL AND expires_at > %s",
					$table,
					$now,
					(string) $matched->ip_hmac,
					$now
				)
			);

		if ( $updated < 1 ) {
			return new \WP_Error( 'bettershield_no_lockout', __( 'That lockout is already over.', 'bettershield' ), array( 'status' => 409 ) );
		}

		Writer::instance()->record(
			'login_lockout_cleared',
			Writer::SEVERITY_INFO,
			array(
				'object_type' => 'lockout',
				'object_id'   => (string) $id,
				// Which form's, so the log names it rather than calling every
				// release a sign-in one.
				'context'     => array( 'surface' => isset( $matched->surface ) ? (string) $matched->surface : Surfaces::SIGNIN ),
			)
		);

		return true;
	}

	/**
	 * Clear every lockout running now, on the surfaces named, in one go.
	 *
	 * One release is a decision about one network somebody recognized. All
	 * of them at once lets every paused source try again, which takes
	 * protection away for as long as it takes each to trip the limit anew,
	 * so it is one record, graded as a weakening rather than as a routine
	 * clear, and naming how many it let back in.
	 *
	 * @param string[] $surfaces Empty means every surface.
	 * @return int How many lockouts were cleared.
	 */
	public function release_all( array $surfaces = array() ): int {
		global $wpdb;

		$wanted = array() === $surfaces ? Surfaces::ALL : array_values( array_intersect( $surfaces, Surfaces::ALL ) );

		if ( array() === $wanted ) {
			return 0;
		}

		$table = Schema::table( 'lockouts' );
		$now   = Time::stamp();

		// The same two shapes as the list, for the same reason: before the
		// surface column lands, every row here is a sign-in lockout.
		if ( ! Gate::surfaced() ) {
			$cleared = in_array( Surfaces::SIGNIN, $wanted, true )
				? (int) $wpdb->query(
					$wpdb->prepare(
						"UPDATE %i SET released_at = %s, release_reason = 'admin', unlock_token_hash = NULL
						 WHERE site_id = 0 AND released_at IS NULL AND expires_at > %s",
						$table,
						$now,
						$now
					)
				)
				: 0;
		} else {
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the placeholder run's length comes from this class's own surface list, never from a request, and every value is bound.
			$placeholders = implode( ', ', array_fill( 0, count( $wanted ), '%s' ) );

			$cleared = (int) $wpdb->query(
				$wpdb->prepare(
					"UPDATE %i SET released_at = %s, release_reason = 'admin', unlock_token_hash = NULL
					 WHERE site_id = 0 AND released_at IS NULL AND expires_at > %s AND surface IN (" . $placeholders . ')',
					array_merge( array( $table, $now, $now ), $wanted )
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		if ( $cleared > 0 ) {
			Writer::instance()->record(
				'login_lockout_cleared',
				Writer::SEVERITY_MEDIUM,
				array(
					'object_type' => 'lockout',
					'object_id'   => 'all',
					'context'     => array(
						'count'    => $cleared,
						'surfaces' => $wanted,
						// What was let back in, by the forms asked for: on one
						// form the others' lockouts still stand.
						'weakened' => array() === array_diff( Surfaces::ALL, $wanted )
							? array( 'every lockout released' )
							: array_map( static fn( string $surface ): string => 'every ' . $surface . ' lockout released', $wanted ),
					),
				)
			);
		}

		return $cleared;
	}

	/**
	 * What this request resolves to, for the screen: the method in use and
	 * whether enforcement would trust it — the "which detection method was
	 * used" reporting the criteria require, live rather than abstract.
	 *
	 * The two addresses are the probe: the owner's own request is what tells
	 * them whether this site is really fronted, which is the question the
	 * Cloudflare statement asks them to answer. Shown to them about their own
	 * request and written nowhere — nothing here records an address, and
	 * nothing here may start to.
	 *
	 * @return array{method: string, confident: bool, ignored_headers: bool, named_proxy: bool, named_proxy_no_visitor: bool, connecting: string, claimed: ?string}
	 */
	public function resolution_report(): array {
		$settings = $this->settings();
		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated as an address below and never stored.
		$connecting = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated as an address below and never stored.
		$claimed = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? (string) $_SERVER['HTTP_CF_CONNECTING_IP'] : '';

		$connecting = false === filter_var( $connecting, FILTER_VALIDATE_IP ) ? '' : $connecting;
		$claimed    = false === filter_var( $claimed, FILTER_VALIDATE_IP ) ? null : $claimed;

		return array(
			'method'          => $resolved['method'],
			'confident'       => $resolved['confident'],
			'ignored_headers' => $resolved['ignored_headers'],
			// A proxy the owner named that sends no forwarding header, as
			// against an address nothing names; see ClientIp.
			'named_proxy'     => ClientIp::named_proxy_without_header( $resolved, $connecting, $settings['trusted_proxies'] ),
			// A proxy the owner named whose header names no usable visitor,
			// as against headers no named proxy vouches for.
			'named_proxy_no_visitor' => ClientIp::named_proxy_without_visitor( $resolved, $connecting, $settings['trusted_proxies'] ),
			'connecting'      => $connecting,
			'claimed'         => $claimed,
			// The address lockouts and the lists act on. Behind a named proxy
			// it is not the connecting one, and the card printed the proxy's
			// as though the visitor came directly. Shown to the person it
			// describes, and never stored, as the two above are not.
			'seen_as'         => false === filter_var( $resolved['ip'], FILTER_VALIDATE_IP ) ? '' : (string) $resolved['ip'],
		);
	}

	/**
	 * The trusted proxies as configured, for callers outside this class that
	 * need to resolve an address the same way (the event writer's prefix).
	 *
	 * @return string[]
	 */
	public static function trusted_proxies(): array {
		return self::instance()->settings()['trusted_proxies'];
	}

	/**
	 * Whether the owner has said this site is behind Cloudflare, for the same
	 * callers. Resolving without it treats a Cloudflare header as a claim, and
	 * two callers disagreeing about that would file one request's failures
	 * under two different keys.
	 */
	public static function cloudflare(): bool {
		return self::instance()->settings()['cloudflare'];
	}

	/**
	 * A typed sign-in identifier as the log may keep it. Sign-in forms take
	 * usernames and email addresses, and sometimes receive a password pasted
	 * into the wrong field; none of that belongs in a table other people
	 * read. An identifier that names an account is stored as that account's
	 * login; an email that names none is masked to its shape; anything else
	 * is reduced to what a login may contain and cut short.
	 */
	public static function loggable_identifier( string $typed ): string {
		$typed = trim( $typed );

		if ( '' === $typed ) {
			return '';
		}

		$account = get_user_by( 'login', $typed );
		if ( false === $account && is_email( $typed ) ) {
			$account = get_user_by( 'email', $typed );
		}

		/*
		 * Character-wise throughout. `username` is varchar(60), which counts
		 * characters, and WordPress permits a login in any script — so a
		 * byte-wise cut stored a third of a Bengali or Cyrillic username, at a
		 * boundary that can fall inside a multi-byte sequence. The masked
		 * email is worse: taking the first *byte* of a non-ASCII local part
		 * produces half a character and nothing valid at all.
		 */
		if ( $account instanceof \WP_User ) {
			return Text::clip( $account->user_login, 60 );
		}

		if ( is_email( $typed ) ) {
			list( $local, $domain ) = explode( '@', $typed, 2 );

			return Text::clip( Text::clip( $local, 1 ) . '…@' . $domain, 60 );
		}

		// `sanitize_user()` in strict mode already reduces this to what a login
		// may contain, which is ASCII — clipped the same way regardless, so
		// this function has one rule rather than two.
		return Text::clip( sanitize_user( $typed, true ), 60 );
	}

	/* ---- internals -------------------------------------------------------------- */

	/**
	 * A range as the lists accept it: a valid address or CIDR, and never one
	 * so wide it stops being a range — /8 is the floor for IPv4, /32 for
	 * IPv6. Wider entries are the way an allowlist silently disarms the
	 * whole feature, or a trusted-proxy entry lets any connection forge its
	 * address.
	 *
	 * @return true|\WP_Error
	 */
	private function check_range( string $range, bool $floor ) {
		if ( ! ClientIp::valid_range( $range ) ) {
			/* translators: %s: the rejected value. */
			return new \WP_Error( 'bettershield_bad_range', sprintf( __( '"%s" is not an IP address or CIDR range.', 'bettershield' ), $range ), array( 'status' => 400 ) );
		}

		if ( $floor && str_contains( $range, '/' ) ) {
			list( $base, $bits ) = explode( '/', $range, 2 );
			$minimum             = str_contains( $base, ':' ) ? 32 : 8;

			if ( (int) $bits < $minimum ) {
				return new \WP_Error(
					'bettershield_range_too_wide',
					sprintf(
						/* translators: 1: the rejected range, 2: the narrowest prefix length allowed. */
						__( '"%1$s" is too wide. The widest range allowed is /%2$d.', 'bettershield' ),
						$range,
						$minimum
					),
					array( 'status' => 400 )
				);
			}
		}

		return true;
	}

	/**
	 * Whether the owner has vouched for this address.
	 *
	 * Public because the gates on the other forms have to ask the same
	 * question, and the answer has to be one answer: a list that exempts an
	 * address from the sign-in gate and not from the comment gate is two
	 * lists wearing one name on the screen.
	 */
	public function is_allowlisted( string $ip ): bool {
		return $this->allowlisted( $ip, $this->settings() );
	}

	/**
	 * @param array<string, mixed> $settings
	 */
	private function allowlisted( string $ip, array $settings ): bool {
		$ranges = array_column( $settings['allowlist'], 'range' );

		return array() !== $ranges && ClientIp::in_ranges( $ip, $ranges );
	}

	/**
	 * Whether a name is one the owner has said may never sign in.
	 *
	 * Compared case-insensitively against `user_login`, because that is what
	 * WordPress itself treats as the same account, and a list that refused
	 * `admin` while letting `Admin` through would be a list that does nothing.
	 *
	 * An entry carrying a name AND a range means both: the name, from that
	 * network. An entry carrying only a name means the name, from anywhere —
	 * which is the common case and the one the list is for.
	 */
	private function blocklisted_username( string $login, array $resolved, array $settings ): bool {
		if ( '' === $login ) {
			return false;
		}

		foreach ( $settings['blocklist'] as $entry ) {
			$name = (string) ( $entry['username'] ?? '' );

			if ( ! self::names_account( $name, $login ) ) {
				continue;
			}

			$range = (string) ( $entry['range'] ?? '' );

			if ( '' !== $range && ( ! $resolved['confident'] || ! ClientIp::in_ranges( $resolved['ip'], array( $range ) ) ) ) {
				continue;
			}

			/*
			 * A qualifier on the entry narrows it, and an entry whose
			 * qualifier is ignored is a wider block than the owner wrote.
			 * Matched the way the address entries match it: a browser string
			 * is a claim anyone can make, which is unsafe to trust and fine to
			 * refuse on — and here it can only ever refuse less.
			 */
			$ua = (string) ( $entry['ua'] ?? '' );

			if ( '' !== $ua ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared case-insensitively, never stored or output.
				$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

				if ( '' === $agent || false === stripos( $agent, $ua ) ) {
					continue;
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * Whether a name on the list is this login: the login itself, in any
	 * case, or the email address of the account that holds it. The sign-in
	 * form takes either, and an entry saved as an account's email address
	 * was listed as blocked while that account went on signing in by its
	 * email and its login alike (#1843).
	 */
	private static function names_account( string $name, string $login ): bool {
		if ( '' === $name || '' === $login ) {
			return false;
		}

		if ( 0 === strcasecmp( $name, $login ) ) {
			return true;
		}

		if ( ! is_email( $name ) ) {
			return false;
		}

		$account = get_user_by( 'email', $name );

		return $account instanceof \WP_User && 0 === strcasecmp( $account->user_login, $login );
	}

	/**
	 * The refusal a blocked name gets, which has to be the refusal a wrong
	 * password gets.
	 *
	 * Two rules meet here and both point the same way. The user enumeration
	 * item exists to stop a visitor sorting names into real and not real one
	 * attempt at a time; a distinct message for a blocked name would hand back
	 * exactly that, and would do it *through* the item rather than around it,
	 * since the unification only replaces an error whose codes are all core's
	 * own. And a blocked name is, in the plainest sense, a credential that
	 * cannot work — which is what `incorrect_password` means.
	 *
	 * So the code is core's and the sentence is core's, reproduced rather than
	 * invented. Reproduced, not called: core builds this inside
	 * `wp_authenticate_username_password()` and offers no way to ask for it,
	 * and a sentence of our own here would be distinguishable from the real
	 * one by anybody comparing two responses — which is the entire attack.
	 *
	 * Deliberately NOT in `OWN_REFUSALS`, and deliberately not setting
	 * `$this->refused`. Every other refusal in this class is the plugin
	 * declining to re-judge something it has already judged, so counting it
	 * would deepen a lockout with each knock on a door already shut. This one
	 * is a fresh wrong credential from a source nothing has refused yet: a bot
	 * working through `admin` should reach the threshold and be locked out
	 * like any other, and on a site with the edge policy armed that lockout is
	 * what lifts the traffic off the origin.
	 *
	 * Core's sentence repeats what was typed, in the form core took it in:
	 * "for the email address X" when the account was found by its email, and
	 * the name as typed otherwise. Built from the stored login, an attempt
	 * made with the account's email address was told the login behind it, and
	 * one typed in other capitals answered differently from a wrong password
	 * (#1844). Core asks twice, as a login and then as an email address, and
	 * the second answer is the one it gives whenever the identifier is an
	 * email address: so the email form whenever what was typed is this
	 * account's email address, even when it is the login as well.
	 */
	private function refuse_blocked_name( \WP_User $user ): \WP_Error {
		$typed = doing_filter( 'authenticate' ) && '' !== $this->typed_login ? $this->typed_login : $user->user_login;

		$by_email = is_email( $typed ) ? get_user_by( 'email', $typed ) : false;

		if ( $by_email instanceof \WP_User && (int) $by_email->ID === (int) $user->ID ) {
			$sentence = sprintf(
				/* translators: %s: email address. */
				__( '<strong>Error:</strong> The password you entered for the email address %s is incorrect.', 'bettershield' ),
				'<strong>' . esc_html( $typed ) . '</strong>'
			);
		} else {
			$sentence = sprintf(
				/* translators: %s: username. */
				__( '<strong>Error:</strong> The password you entered for the username %s is incorrect.', 'bettershield' ),
				'<strong>' . esc_html( $typed ) . '</strong>'
			);
		}

		return new \WP_Error(
			'incorrect_password',
			// Unescaped, as core leaves it: escaped, the link differed from core's wherever the address carries a query.
			$sentence . ' <a href="' . wp_lostpassword_url() . '">' . __( 'Lost your password?', 'bettershield' ) . '</a>'
		);
	}

	/**
	 * @param array{ip: string, method: string, confident: bool} $resolved
	 * @param array<string, mixed> $settings
	 */
	private function blocklisted( array $resolved, array $settings ): bool {
		foreach ( $settings['blocklist'] as $entry ) {
			$range = (string) ( $entry['range'] ?? '' );
			$ua    = (string) ( $entry['ua'] ?? '' );

			/*
			 * An entry naming an account is judged by `blocklisted_username()`
			 * and never here. This loop reads an absent field as "no condition
			 * on this", which is right for a list whose entries are all about
			 * the connection — and catastrophic the moment one is not: a
			 * name-only entry has neither range nor user agent, so every guard
			 * below would be skipped and the loop would refuse the whole
			 * internet. A paired name and range is the same entry seen from
			 * the other side, and the range is its qualifier rather than a
			 * block of its own.
			 */
			if ( '' !== (string) ( $entry['username'] ?? '' ) ) {
				continue;
			}

			if ( '' !== $range ) {
				// The same guard as lockouts: an address the resolution
				// could not verify may be a crowd, and a range match on a
				// crowd refuses people the entry never meant.
				if ( ! $resolved['confident'] || ! ClientIp::in_ranges( $resolved['ip'], array( $range ) ) ) {
					continue;
				}
			}

			if ( '' !== $ua ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared case-insensitively, never stored or output.
				$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

				if ( '' === $agent || false === stripos( $agent, $ua ) ) {
					continue;
				}
			}

			return true;
		}

		return false;
	}

	/**
	 * A change to the host-ban line asked for on a network's subsite, where
	 * the switch is the main site's: refused in words, with 409. Only the
	 * screen's save asks; an import or an undo carries the stored value and
	 * goes on with the rest of the section (see validate()).
	 *
	 * @param array<string, mixed> $input
	 */
	public function refuses_a_network_switch( array $input ): ?\WP_Error {
		if ( ! isset( $input['host_ban_line'] ) || ! \BetterShield\Support\AuthLog::set_from_main_site() || (bool) $input['host_ban_line'] === $this->settings()['host_ban_line'] ) {
			return null;
		}

		return new \WP_Error(
			'bettershield_host_ban_line_network',
			__( 'Only the main site can set this: a server firewall ban covers every site on the server.', 'bettershield' ),
			array( 'status' => 409 )
		);
	}

	/**
	 * Whether a new block entry would refuse the person saving it: their own
	 * address range, or a user agent their browser carries.
	 *
	 * The list refused the editor's own name for exactly this reason, and
	 * nothing else: `198.51.100.0/24` saved from 198.51.100.77, or the user
	 * agent `Mozilla`, saved silently, and the next sign-in was "not
	 * available from this connection". Matched as `blocklisted()` matches,
	 * against this request, and only for entries not already on the list, so
	 * one saved before never holds every other save up.
	 *
	 * The exception is a save that takes the saver off the allowlist. A block
	 * saved while they were allowlisted never reached them; once the
	 * allowlist entry goes, it does, so then every block the next sign-in
	 * reads is judged, saved or new, and a save sending the allowlist alone
	 * is judged against the blocklist already saved.
	 *
	 * Asked by the screen's save, where the request is a person at a browser.
	 * The command line, an import and an assistant have no connection of the
	 * owner's to protect.
	 *
	 * @param array<string, mixed> $input
	 */
	public function refuses_the_saver( array $input ): ?\WP_Error {
		$sends_block = isset( $input['blocklist'] ) && is_array( $input['blocklist'] );
		$sends_allow = isset( $input['allowlist'] ) && is_array( $input['allowlist'] );

		if ( ! $sends_block && ! $sends_allow ) {
			return null;
		}

		$settings = $this->settings();
		$resolved = ClientIp::resolve( $settings['trusted_proxies'], $settings['cloudflare'] );
		$saved    = array();

		/*
		 * An allowlisted address signs in before any block is read (see
		 * enforce()), so no block refuses it. The allowlist this save sends
		 * is the one the next sign-in reads, when it sends one.
		 */
		$allow = $sends_allow ? $this->clean_list( $input['allowlist'], 'range' ) : $settings['allowlist'];

		if ( $this->allowlisted( $resolved['ip'], array( 'allowlist' => $allow ) ) ) {
			return null;
		}

		// Allowlisted until this save: the saved blocks are new to them too.
		$leaving = $this->allowlisted( $resolved['ip'], $settings );

		foreach ( $settings['blocklist'] as $entry ) {
			$saved[] = (string) ( $entry['range'] ?? '' ) . '|' . (string) ( $entry['ua'] ?? '' );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared case-insensitively, never stored or output.
		$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

		foreach ( $sends_block ? $input['blocklist'] : $settings['blocklist'] as $entry ) {
			if ( ! is_array( $entry ) || '' !== trim( (string) ( $entry['username'] ?? '' ) ) ) {
				continue;
			}

			$range = trim( (string) ( $entry['range'] ?? '' ) );
			$ua    = trim( (string) ( $entry['ua'] ?? '' ) );
			$old   = in_array( $range . '|' . $ua, $saved, true );

			if ( ( '' === $range && '' === $ua ) || ( $old && ! $leaving ) ) {
				continue;
			}

			$by_range = '' === $range || ( $resolved['confident'] && ClientIp::in_ranges( $resolved['ip'], array( $range ) ) );
			$by_agent = '' === $ua || ( '' !== $agent && false !== stripos( $agent, $ua ) );

			if ( ! $by_range || ! $by_agent ) {
				continue;
			}

			if ( $old ) {
				return '' !== $range
					? new \WP_Error( 'bettershield_range_self', __( 'Only your allowlist entry lets your current address past a saved block. Removing it would refuse your next sign-in.', 'bettershield' ), array( 'status' => 400 ) )
					: new \WP_Error( 'bettershield_ua_self', __( 'Only your allowlist entry lets this browser past a saved block. Removing it would refuse your next sign-in from it.', 'bettershield' ), array( 'status' => 400 ) );
			}

			return '' !== $range
				? new \WP_Error( 'bettershield_range_self', __( 'That covers your current address. Blocking it would refuse your next sign-in.', 'bettershield' ), array( 'status' => 400 ) )
				: new \WP_Error( 'bettershield_ua_self', __( 'That matches this browser and would refuse your next sign-in from it. Use a pattern only the unwanted client sends.', 'bettershield' ), array( 'status' => 400 ) );
		}

		return null;
	}

	/**
	 * @return object|null
	 */
	private function active_lockout( string $hmac ) {
		return Gate::active_lockout( self::SURFACE, $hmac );
	}

	/**
	 * @param array<int, mixed> $entries
	 * @return array<int, array<string, string>>
	 */
	private function clean_list( $entries, string ...$fields ): array {
		$out = array();

		foreach ( (array) $entries as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}

			$kept = array();
			foreach ( array_merge( $fields, array( 'note', 'author', 'added_at' ) ) as $field ) {
				if ( isset( $entry[ $field ] ) && '' !== (string) $entry[ $field ] ) {
					$kept[ $field ] = (string) $entry[ $field ];
				}
			}

			$has_subject = false;
			foreach ( $fields as $field ) {
				if ( isset( $kept[ $field ] ) ) {
					$has_subject = true;
				}
			}

			if ( $has_subject ) {
				$out[] = $kept;
			}
		}

		return $out;
	}

	/**
	 * An entry as sign-in matches it: a name and a browser string in any
	 * case, so two entries this key cannot tell apart refuse the same people.
	 *
	 * @param array<string, mixed> $entry
	 */
	public static function match_key( array $entry ): string {
		$range = (string) ( $entry['range'] ?? '' );
		$ua    = strtolower( (string) ( $entry['ua'] ?? '' ) );
		$name  = strtolower( (string) ( $entry['username'] ?? '' ) );

		return ( '' !== $range ? 'r:' . $range : '' ) . ( '' !== $ua ? '|u:' . $ua : '' ) . ( '' !== $name ? '|n:' . $name : '' );
	}

	private function entry_key( array $entry ): string {
		return ( isset( $entry['range'] ) ? 'r:' . $entry['range'] : '' )
			. ( isset( $entry['ua'] ) ? '|u:' . $entry['ua'] : '' )
			. ( isset( $entry['username'] ) ? '|n:' . $entry['username'] : '' );
	}
}
