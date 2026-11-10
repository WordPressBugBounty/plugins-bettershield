<?php
/**
 * Make the next attempt cost something, after a few wrong ones.
 *
 * The lockout is binary and collateral: it either lets an attempt through or
 * blocks an address that a whole office may share. Between "wrong password"
 * and "locked out" there is nothing, and that gap is where credential
 * stuffing lives — an attacker under the threshold pays nothing at all.
 *
 * This puts a cost there. After a few failures from one connection the sign-in
 * form carries a small puzzle: find a number whose hash, with the challenge,
 * starts with a run of zero bits. A browser spends a few hundred milliseconds
 * and a person notices a pause. A script that wants a thousand attempts an
 * hour pays that a thousand times, and a rising difficulty means the cost
 * climbs as the guessing continues. It needs no third party — no external
 * call, no privacy relationship — which is the reason it comes first.
 *
 * **And it must never become a lockout by another name.** A browser with
 * JavaScript off cannot solve a puzzle, and a plugin whose first principle is
 * that the owner can always get back in cannot answer that with a refusal
 * that has no way out. So:
 *
 * - An unsolved attempt is refused and **does not count toward the lockout**,
 *   so nobody is driven into a longer block by being unable to solve one.
 * - The requirement lifts when the failure window passes, with nothing
 *   required of anybody. The escape is time rather than a bypass: a person
 *   waits it out and signs in cleanly, while a script that waits has been
 *   rate-limited by exactly as much.
 * - Safe mode, the recovery link and allowlisted addresses never see it.
 * - **It is only ever asked of somebody who was shown it.** A sign-in that is
 *   not a person at a browser is not gated, nor is a form this plugin could
 *   not draw the puzzle on. The lockout reaches every path either way, so
 *   standing down here removes a wall rather than a protection.
 * - **It does not act on an identity the lockout would not act on.** Behind a
 *   proxy nobody has named as trusted every visitor is one connection, and
 *   enforcing against that is the collateral this exists to reduce.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Login;

use BetterShield\Recovery\SafeMode;
use BetterShield\Support\Claim;
use BetterShield\Support\ClientIp;
use BetterShield\Support\LoginForms;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProofOfWork {

	/** Failures from one connection before the puzzle appears. */
	public const AFTER_FAILURES = 2;

	/** Leading zero bits at the first difficulty, and how much each step adds. */
	public const BASE_BITS = 14;
	public const STEP_BITS = 2;

	/** Never harder than this: past it a slow phone is being punished. */
	public const MAX_BITS = 22;

	private static ?ProofOfWork $instance = null;

	public static function instance(): ProofOfWork {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Marks a submission as coming from a form this plugin put a puzzle on.
	 *
	 * Rendered beside the answer field, and it is what separates "solved it
	 * wrong" from "was never given one to solve".
	 */
	private const PRESENTED = 'bettershield_pow_form';

	/**
	 * What the browser's search says of itself: `working` once it has
	 * started, `done` once it has an answer. A submission that says
	 * `working` was sent by a browser running the check before it finished,
	 * which is a different thing to tell somebody than that it needs
	 * JavaScript.
	 */
	private const STATE = 'bettershield_pow_state';

	/**
	 * Where a spent solution is recorded, and where the per-challenge count
	 * of them is kept. Both are claim keys rather than transients: a claim is
	 * taken in one statement the database settles, so the check and the set
	 * are not two steps a perfectly timed pair of replays can slip between,
	 * and the rows are swept by this plugin's own prune.
	 */
	private const SPENT_PREFIX = 'pow_spent_';

	private const SOLVE_COUNT_PREFIX = 'pow_solves_';

	/**
	 * How many solutions one challenge — one connection-hour — may spend.
	 * Past this the connection is far beyond the lockout threshold anyway,
	 * and the cap is what stops a solver with CPU to burn minting rows
	 * without limit.
	 */
	private const MAX_SOLVES = 100;

	public function register(): void {
		// Every sign-in form this plugin can reach. While it was core's alone,
		// the puzzle was enforced on every credential path and rendered on one
		// — so a WooCommerce customer who typed the right password was refused
		// and pointed at a puzzle their page did not contain.
		foreach ( LoginForms::sign_in_hooks() as $hook ) {
			add_action( $hook, array( $this, 'render' ) );
		}

		// One decision per attempt, and `authenticate` is what opens every
		// attempt there is — including this plugin's own re-entry.
		add_filter( 'authenticate', array( $this, 'begin_attempt' ), 0, 1 );

		/*
		 * Before the password is compared, rather than after it.
		 *
		 * `wp_authenticate_user` fires inside core's own credential handlers
		 * before `wp_check_password` runs, and an error returned there is
		 * honored — while an error hooked to `authenticate` earlier than 20
		 * is discarded by those handlers whenever a username and a password
		 * are both present. Deciding after them meant the stored hash had
		 * already been compared by the time a puzzle was owed: a wrong guess
		 * carried core's own refusal away and owed nothing, so guessing cost
		 * exactly what it costs with no puzzle at all, and only the right
		 * password lived long enough to be handed one — which told whoever
		 * sent it that it was the right one.
		 */
		add_filter( 'wp_authenticate_user', array( $this, 'check_before_password' ), 5, 1 );

		// The credential paths that never reach the hook above: an account
		// resolved on `authenticate` by something that is not a password.
		add_filter( 'authenticate', array( $this, 'check' ), 24, 1 );
	}

	/**
	 * Whether this attempt was already answered for before its password was
	 * compared. The late hook covers the credential paths that never reach
	 * the early one; on the paths that do, the solution has been spent and
	 * asking a second time would refuse the attempt that just paid for
	 * itself.
	 */
	private bool $settled = false;

	/**
	 * @param mixed $user
	 * @return mixed
	 */
	public function begin_attempt( $user ) {
		$this->reset_request_state();

		return $user;
	}

	public function reset_request_state(): void {
		$this->settled = false;
	}

	public function enabled(): bool {
		return ! empty( Protection::instance()->settings()['proof_of_work'] );
	}

	/**
	 * Whether this request can run Web Crypto. A configured HTTPS address is
	 * not proof that this page arrived over HTTPS. Forwarded protocol is used
	 * only after the same proxy trust decision as the sign-in protection.
	 */
	public static function available(): bool {
		if ( \BetterShield\Support\Server::connection_is_https() ) {
			return true;
		}
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$request_host = strtolower( (string) wp_parse_url( 'http://' . (string) ( $_SERVER['HTTP_HOST'] ?? $host ), PHP_URL_HOST ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared only to the configured hostname.
		if ( $host === $request_host && ( 'localhost' === $host || str_ends_with( $host, '.localhost' ) || '127.0.0.1' === $host || '[::1]' === $host ) ) {
			return true;
		}
		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );
		$trusted = in_array( $resolved['method'], array( ClientIp::METHOD_PROXY, ClientIp::METHOD_CLOUDFLARE ), true );
		return $trusted && 'https' === ( $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared to a literal, never stored or output.
	}

	/**
	 * How hard this connection's puzzle is, or zero when there is none.
	 */
	public function bits_for_now(): int {
		if ( ! $this->enabled() || ! self::available() || SafeMode::is_active() ) {
			return 0;
		}

		$protection = Protection::instance();
		$resolved   = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );

		/*
		 * The shared-proxy guard, the same one the lockout states as code:
		 * no confidence, no enforcement.
		 *
		 * Behind a proxy the owner has not named, every visitor resolves to
		 * one identity — the normal state on containerized and load-balanced
		 * hosts. The lockout refuses to act on that identity because acting
		 * on it punishes an office for one person's typo. This skipped the
		 * guard, so two failures by anybody put a puzzle in front of
		 * everybody, and in front of anyone without JavaScript put a refusal.
		 * That is precisely the collateral the guard exists to prevent, from
		 * the mechanism that was added to make the lockout less collateral.
		 */
		if ( ! $resolved['confident'] ) {
			return 0;
		}

		// An allowlisted address is one the owner vouched for; it is exempt
		// from the lockout and is exempt from this for the same reason.
		if ( ClientIp::in_ranges( (string) $resolved['ip'], wp_list_pluck( $protection->settings()['allowlist'], 'range' ) ) ) {
			return 0;
		}

		$failures = $protection->recent_failures( (string) $resolved['ip'], $resolved['paired_with'] ?? null );

		if ( $failures < self::AFTER_FAILURES ) {
			return 0;
		}

		return (int) min(
			self::MAX_BITS,
			self::BASE_BITS + ( ( $failures - self::AFTER_FAILURES ) * self::STEP_BITS )
		);
	}

	/**
	 * The challenge string for this connection and this window.
	 *
	 * Derived rather than stored: no row is written for somebody who is only
	 * mistyping their password, and an attacker cannot fill a table by asking
	 * for challenges. It changes with the plugin's own secret and with the
	 * hour, so a solution cannot be computed once and reused all week — and
	 * within the hour each accepted solution is spent by consume(), so every
	 * attempt costs its own solve.
	 */
	public function challenge(): string {
		return $this->challenge_at( (int) floor( time() / HOUR_IN_SECONDS ) );
	}

	/**
	 * The current window's challenge and the one before it.
	 *
	 * A person is handed a puzzle, solves it, and posts the form — and if the
	 * hour turns between those two moments the answer is checked against a
	 * challenge nobody ever gave them. It is correct and it is refused, on a
	 * sign-in form, for no reason they could ever see or act on. That happens
	 * to somebody every hour on a site under a password run.
	 *
	 * Accepting the previous window costs nothing the design was relying on:
	 * each solution is still spent once by `consume()`, which is keyed per
	 * challenge, and the previous window's challenge is at most an hour old —
	 * the same life it always had for anybody who was handed it a minute
	 * before the turn.
	 *
	 * @return string[]
	 */
	public function challenges(): array {
		$hour = (int) floor( time() / HOUR_IN_SECONDS );

		return array( $this->challenge_at( $hour ), $this->challenge_at( $hour - 1 ) );
	}

	private function challenge_at( int $hour ): string {
		$resolved = ClientIp::resolve( Protection::trusted_proxies(), Protection::cloudflare() );

		return substr(
			hash_hmac(
				'sha256',
				'bettershield-pow|' . ClientIp::hmac( (string) $resolved['ip'] ) . '|' . $hour,
				ClientIp::signing_secret()
			),
			0,
			32
		);
	}

	/**
	 * Whether a proposed answer is right.
	 */
	public function solved( string $challenge, string $nonce, int $bits ): bool {
		if ( '' === $nonce || $bits < 1 ) {
			return false;
		}

		// A nonce is a number a browser counted up to. Anything else is
		// somebody trying something.
		if ( 1 !== preg_match( '/^[0-9]{1,20}$/', $nonce ) ) {
			return false;
		}

		$digest = hash( 'sha256', $challenge . $nonce, true );

		return self::leading_zero_bits( $digest ) >= $bits;
	}

	/**
	 * Spend an accepted solution, once. The challenge alone changes hourly,
	 * so without this a single solve replayed for the rest of the hour and
	 * the whole point — that N attempts cost N solves — did not hold.
	 *
	 * Only accepted solutions are recorded, which is what keeps this from
	 * becoming the unauthenticated storage vector the derived challenge was
	 * designed to avoid: every row here cost its writer a real solve first,
	 * and it lives no longer than the challenge it belongs to. The check and
	 * the set are not one atomic step, so a perfectly timed pair of replays
	 * may both land — that buys one extra attempt per solve, not the hour.
	 */
	private function consume( string $challenge, string $nonce ): bool {
		/*
		 * Taking the key IS the spend, and one statement the database settles
		 * decides who took it — so a pair of replays timed to arrive together
		 * no longer both land, which reading a value and writing it back
		 * could never prevent. The rows live no longer than the challenge
		 * they belong to and are swept in bounded batches by this plugin's
		 * own prune, rather than by the scheduler its task runner exists to
		 * distrust.
		 */
		if ( ! Claim::claim( self::SPENT_PREFIX . md5( $challenge . $nonce ), HOUR_IN_SECONDS ) ) {
			return false;
		}

		/*
		 * And capped per challenge — one connection-hour — so a solver with
		 * CPU to burn cannot mint rows without limit. Past the cap, further
		 * solutions for this challenge are refused: by then the connection is
		 * far beyond the lockout threshold anyway.
		 */
		return Claim::bump( self::SOLVE_COUNT_PREFIX . md5( $challenge ), HOUR_IN_SECONDS ) <= self::MAX_SOLVES;
	}

	/**
	 * How many zero bits a digest starts with.
	 */
	public static function leading_zero_bits( string $digest ): int {
		$zeros = 0;

		for ( $i = 0, $length = strlen( $digest ); $i < $length; $i++ ) {
			$byte = ord( $digest[ $i ] );

			if ( 0 === $byte ) {
				$zeros += 8;
				continue;
			}

			for ( $bit = 7; $bit >= 0; $bit-- ) {
				if ( 0 !== ( $byte & ( 1 << $bit ) ) ) {
					return $zeros;
				}

				++$zeros;
			}

			return $zeros;
		}

		return $zeros;
	}

	/**
	 * The gate, before the password is compared.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public function check_before_password( $user ) {
		$verdict = $this->check( $user );

		$this->settled = true;

		return $verdict;
	}

	/**
	 * The gate.
	 *
	 * @param mixed $user
	 * @return mixed
	 */
	public function check( $user ) {
		if ( $this->settled ) {
			return $user;
		}

		$bits = $this->bits_for_now();

		if ( 0 === $bits ) {
			return $user;
		}

		/*
		 * A sign-in that is not a person at a browser. An application password
		 * over REST, an XML-RPC client, WP-CLI, a request that asked for JSON:
		 * none of them can run a Web Crypto worker, so the puzzle is not a cost
		 * to them, it is a wall. And this gate runs before the second-factor
		 * gate that carefully exempts exactly these — so while this refused
		 * them first, that exemption never ran.
		 *
		 * The lockout still covers every one of these paths. Standing down here
		 * removes a wall, not a protection.
		 */
		if ( ! \BetterShield\TwoFactor\LoginStep::interactive() ) {
			return $user;
		}

		/*
		 * A form this plugin could not put a puzzle on.
		 *
		 * The check is decided on `authenticate`, which every credential path
		 * reaches, and the puzzle is drawn on a form's own render hook, which
		 * only the forms we know about fire. Where those two disagree, somebody
		 * with the right password was refused and told to solve something the
		 * page never showed them — a lockout by another name, which this
		 * mechanism's own contract forbids.
		 *
		 * So enforcement follows the rendering. A submission carrying the
		 * marker was given a puzzle and owes an answer. A submission to
		 * wp-login.php owes one whether it carries the marker or not, because
		 * that form always has one — an answer missing there was removed rather
		 * than never offered. Anything else is a form we cannot reach, and the
		 * lockout, which reaches everything, is what covers it.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read to classify the submission; the sign-in form has no nonce by design.
		$presented = isset( $_POST[ self::PRESENTED ] ) || LoginForms::is_core_sign_in_request();

		if ( ! $presented ) {
			return $user;
		}

		/*
		 * An account name nobody holds never reaches the hook that runs before
		 * the password is compared: core answers it first and this sees the
		 * answer. Left alone, a name somebody holds is refused with a puzzle
		 * and a name nobody holds with core's own message, so the gate itself
		 * would say which names are real — the leak the sign-in form is
		 * hardened against elsewhere, reopened by the mechanism that is
		 * supposed to make guessing more expensive.
		 *
		 * Only the two codes that mean no account matched are replaced. Every
		 * other refusal on this chain is somebody else's and carries
		 * instructions the person needs in order to get in.
		 */
		if ( is_wp_error( $user ) ) {
			$codes = $user->get_error_codes();

			return array() !== $codes && array() === array_diff( $codes, array( 'invalid_username', 'invalid_email' ) )
				? $this->refusal( self::unfinished() )
				: $user;
		}

		// This plugin re-running the chain for an account it already put
		// through this gate — the second-factor screen finishing a parked
		// sign-in, the passkey route applying the site's other rules. That
		// request carries no puzzle field and its earlier solution is spent,
		// so without this a correct code was refused in a loop for as long
		// as the failure window lasted.
		if ( $user instanceof \WP_User && \BetterShield\TwoFactor\Manager::instance()->reentering( (int) $user->ID ) ) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the sign-in form has no nonce by design; this value is verified as a proof, which is stronger than knowing a nonce.
		$nonce     = isset( $_POST['bettershield_pow'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['bettershield_pow'] ) ) : '';
		foreach ( $this->challenges() as $challenge ) {
			if ( $this->solved( $challenge, $nonce, $bits ) && $this->consume( $challenge, $nonce ) ) {
				return $user;
			}
		}

		return $this->refusal( self::unfinished() );
	}

	/**
	 * Whether this submission came from a browser whose check was still
	 * running: it says so, and carries no answer. Read from the form alone,
	 * so it says nothing about the account or the password.
	 */
	private static function unfinished(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- read to choose the words of a refusal; the sign-in form has no nonce by design.
		$state  = isset( $_POST[ self::STATE ] ) ? sanitize_key( wp_unslash( (string) $_POST[ self::STATE ] ) ) : '';
		$answer = isset( $_POST['bettershield_pow'] ) ? trim( sanitize_text_field( wp_unslash( (string) $_POST['bettershield_pow'] ) ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		return 'working' === $state && '' === $answer;
	}

	/**
	 * The refusal, deliberately carrying an error code the lockout counter
	 * does not treat as a wrong password. Somebody whose browser cannot run
	 * the puzzle must not be driven into a longer block by failing to — the
	 * way out is the window passing, which needs nothing of them.
	 *
	 * One sentence for every reason this gate refuses, so a right password, a
	 * wrong one and a name nobody holds are answered identically. The one
	 * other is for a browser that was running the check and was sent on
	 * before it finished, which the form alone says: told it needs
	 * JavaScript, somebody whose browser runs it was given a false reason.
	 *
	 * The shared sentence stands in for "no such account" too, where the
	 * check ran and passed, so it names no single cause (#2843): it says
	 * what to check, and that JavaScript or a few minutes' wait gets a right
	 * password through. Both are true for every case it covers.
	 */
	private function refusal( bool $unfinished = false ): \WP_Error {
		if ( $unfinished ) {
			return new \WP_Error(
				'bettershield_pow_required',
				__( 'The browser check had not finished. Sign in again once the note above the button says you can.', 'bettershield' )
			);
		}

		return new \WP_Error(
			'bettershield_pow_required',
			__( 'That didn’t work. Check your username or email and your password. If they’re right, turn on JavaScript or wait a few minutes.', 'bettershield' )
		);
	}

	/**
	 * The hidden field and the worker that fills it.
	 */
	public function render(): void {
		$bits = $this->bits_for_now();

		if ( 0 === $bits ) {
			return;
		}

		$challenge = $this->challenge();

		printf(
			'<input type="hidden" name="bettershield_pow" id="bettershield-pow" value="" />
			<input type="hidden" name="%s" value="1" />
			<input type="hidden" name="%s" id="bettershield-pow-state" value="" />
			<p class="bettershield-pow-note" id="bettershield-pow-note" role="status" style="font-size:12px;margin:0 0 8px">%s</p>',
			esc_attr( self::PRESENTED ),
			esc_attr( self::STATE ),
			esc_html__( 'Checking your browser first, after several failed sign-ins from this connection.', 'bettershield' )
		);

		/*
		 * Inline and tiny, on the sign-in page only. Enqueuing a file would
		 * mean a request before a form somebody is already waiting at, and the
		 * whole point of this is that the cost falls on the machine trying to
		 * guess rather than on the person signing in.
		 */
		/*
		 * A form sent before the answer is found is held, and sent by the
		 * search itself once it has one: a password manager that fills and
		 * sends at once, or anybody quick, was refused on every try. The note
		 * says it is still checking, then that it is done.
		 */
		wp_print_inline_script_tag(
			sprintf(
				'(function(){var c=%s,b=%d,f=document.getElementById("bettershield-pow"),t=document.getElementById("bettershield-pow-state"),o=document.getElementById("bettershield-pow-note");
				if(!f||!window.crypto||!window.crypto.subtle){return;}
				var m=f.form,w=null;if(t){t.value="working";}
				if(m){m.addEventListener("submit",function(v){if(f.value){return;}v.preventDefault();w=v.submitter||true;if(o){o.textContent=%s;}});}
				function ready(){if(t){t.value="done";}if(o){o.textContent=%s;}
				if(w&&m){var x=w;w=null;if(m.requestSubmit){m.requestSubmit(x===true?undefined:x);}else{m.submit();}}}
				var e=new TextEncoder();
				function zeros(v){var n=0;for(var i=0;i<v.length;i++){var x=v[i];if(x===0){n+=8;continue;}
				for(var j=7;j>=0;j--){if(x&(1<<j)){return n;}n++;}return n;}return n;}
				/* From a random start, not zero: each accepted answer is spent
				server-side, and a search that always began at zero would
				find the same spent number on the next attempt. */
				var s=crypto.getRandomValues(new Uint32Array(1))[0];
				(async function(){for(var i=0;i<5e7;i++){var n=s+i;
				var h=new Uint8Array(await crypto.subtle.digest("SHA-256",e.encode(c+n)));
				if(zeros(h)>=b){f.value=String(n);ready();return;}}})();})();',
				wp_json_encode( $challenge ),
				$bits,
				wp_json_encode( __( 'Still checking your browser. Your sign-in goes as soon as this is done.', 'bettershield' ) ),
				wp_json_encode( __( 'Your browser is checked. You can sign in.', 'bettershield' ) )
			)
		);
	}
}
