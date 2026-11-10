<?php
/**
 * The recovery link: the owner's guaranteed way back in.
 *
 * A random 64-character token is generated at activation; only its
 * SHA-256 hash is stored, never the token itself. Visiting the link
 * enters safe mode — no login, no credentials, no second factor needed —
 * which pauses all enforcement while keeping every setting intact.
 *
 * Because only the hash is stored, the link can be displayed exactly
 * once per generation. Regenerating invalidates the previous link.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Recovery;

use BetterShield\Audit\Auditor;
use BetterShield\Events\Writer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RecoveryLink {

	private const HASH_OPTION    = 'bettershield_recovery_token_hash';
	private const ISSUED_OPTION  = 'bettershield_recovery_token_issued';

	/**
	 * Whether the mail carrying a link was accepted for sending.
	 *
	 * Read through `Audit\Auditor::recovery_mail_result()`. Written by every
	 * path that attempts a send — activation, and the replacement this class
	 * mails when a link is spent — and cleared by `generate()`, because the
	 * record describes the link on record and generating one replaces that
	 * link. A path that makes no delivery claim writes nothing: the dashboard
	 * and the CLI hand the link straight to the person asking, and absent is
	 * the honest record for that.
	 *
	 * Written by activation alone, the first replacement cleared it for good:
	 * the state that says "nobody ever received this link" became unreachable
	 * for the life of the site, on exactly the path — a link replaced because
	 * somebody used it — where the mail is the only thing that tells an owner
	 * it was not them.
	 */
	private const MAILED_OPTION = 'bettershield_recovery_mailed';

	/**
	 * The address the link on record was mailed to, when the mail was
	 * accepted. The admin email can change afterwards (a host installs with
	 * its own, a network subsite gets the network's), and naming the address
	 * of the moment told the owner to look in an inbox that never got the
	 * link (#2114).
	 */
	private const MAILED_TO_OPTION = 'bettershield_recovery_mailed_to';

	/**
	 * How long a link stays good for.
	 *
	 * A break-glass credential that never expires is one an owner emailed
	 * themselves two years ago, from an inbox that has since been breached, to
	 * an address they no longer read. Ninety days is long enough that nobody
	 * is replacing it constantly and short enough that a copy left somewhere
	 * stops being a key eventually.
	 *
	 * A lapse is meant to be seen coming rather than prevented outright: using
	 * a link issues the next one, the dashboard reports a link within a
	 * fortnight of its end so the owner can replace it before it goes, and a
	 * link that has lapsed stops counting as a way back — so the one setting
	 * that takes a password away will not cover a new role behind it.
	 *
	 * What none of that does is renew a link on its own, or re-ask the
	 * question after the setting is armed. A site that armed behind a live
	 * link and then let it lapse is relying on the dashboard's warning having
	 * been read.
	 */
	private const LIFETIME = 90 * DAY_IN_SECONDS;
	private const QUERY_VAR      = 'bettershield_recovery';
	private const FAIL_TRANSIENT = 'bettershield_recovery_failures';

	/**
	 * The network's own link — one for the whole network, and the only
	 * credential here that stands every site down at once.
	 *
	 * It exists because a site's link opens the site it was issued for while
	 * the session it grants covers the network, so a network administrator
	 * locked out above the sites could open one of them and still meet
	 * everything set above it. Its hash lives in the network's options and it
	 * is answered at any site's reserved address, told apart from that site's
	 * own link by nothing but which hash matches: one address to write down,
	 * whichever credential is still to hand.
	 */
	private const NETWORK_HASH_OPTION   = 'bettershield_network_recovery_token_hash';
	private const NETWORK_ISSUED_OPTION = 'bettershield_network_recovery_token_issued';
	private const NETWORK_MAILED_OPTION = 'bettershield_network_recovery_mailed';

	/**
	 * The hash of the link just spent, and when the safe mode it started
	 * ends: `array{hash: string, until: int}`.
	 *
	 * The form that spends a link is posted twice by a double click, and
	 * again by a reload of the page it answers. The second post found the
	 * token retired and was told the link was not valid, with a failure on
	 * the record, while the safe mode the first post started was running and
	 * the replacement it printed had been thrown away with that response.
	 * Kept for as long as that safe mode, so the second post is answered
	 * with the page it belongs to. Nothing is spent or issued again.
	 */
	private const SPENT_OPTION         = 'bettershield_recovery_spent';
	private const NETWORK_SPENT_OPTION = 'bettershield_network_recovery_spent';

	public static function register(): void {
		// Priority 0: recovery must run before anything else the plugin
		// (or a future enforcement feature) does on init.
		add_action( 'init', array( self::class, 'handle_request' ), 0 );
	}

	public static function link_exists(): bool {
		return is_string( get_option( self::HASH_OPTION ) ) && '' !== get_option( self::HASH_OPTION );
	}

	/**
	 * How long a link is good for, filterable the way safe mode's duration is.
	 */
	public static function lifetime(): int {
		return max( DAY_IN_SECONDS, (int) apply_filters( 'bettershield_recovery_link_lifetime', self::LIFETIME ) );
	}

	/**
	 * When the current link stops working, or null when there is none.
	 *
	 * A link issued before this plugin recorded issue dates has no date to
	 * read. It is treated as issued now rather than as long expired, because
	 * the alternative is an update that quietly takes away the owner's way
	 * back in.
	 */
	public static function expires_at(): ?int {
		if ( ! self::link_exists() ) {
			return null;
		}

		$issued = (int) get_option( self::ISSUED_OPTION );

		if ( $issued <= 0 ) {
			$issued = time();
			update_option( self::ISSUED_OPTION, $issued, false );
		}

		return $issued + self::lifetime();
	}

	/**
	 * When a link stops working, said for an email: an owner who files the
	 * message away needs the date, and where a fresh one comes from.
	 *
	 * @param int|null $expires When it stops working.
	 * @param bool     $network Whether it is the network's link.
	 */
	public static function expiry_sentence( ?int $expires, bool $network = false ): string {
		if ( null === $expires ) {
			return '';
		}

		return sprintf(
			$network
				/* translators: %s: the date the link stops working. */
				? __( 'This link works until %s. Create a new one anytime from the network dashboard.', 'bettershield' )
				/* translators: %s: the date the link stops working. */
				: __( 'This link works until %s. Create a new one anytime in BetterShield › Protection › Recovery.', 'bettershield' ),
			wp_date( (string) get_option( 'date_format', 'F j, Y' ), $expires )
		);
	}

	/**
	 * Whether the link on record has passed its life.
	 */
	public static function expired(): bool {
		$expires = self::expires_at();

		return null !== $expires && time() > $expires;
	}

	/**
	 * Whether the link on record is one the owner could open today.
	 *
	 * `link_exists()` answers a narrower question — is a hash stored — and a
	 * stored hash is not a way back in on its own. Only the hash is kept here,
	 * so the link is a way back only while the owner is holding the token and
	 * it still opens the door. This adds the two ways that stops being true:
	 * the link has passed its life, or the mail carrying it was refused for
	 * sending, in which case nobody ever received it and nothing here can
	 * produce it again.
	 *
	 * A link with no delivery record is a link that was read on screen — the
	 * dashboard hands one back rather than mailing it, and so does the page a
	 * spent link lands on — which is the most reliable way back there is. Only
	 * a recorded failure counts against a link, which is why that record is
	 * kept as three states rather than two, and why generating a link clears
	 * it.
	 *
	 * Anything deciding whether this site can afford to take a password away
	 * wants this. Anything reporting what is on record — the posture payload,
	 * the first-run state — wants `link_exists()`, because saying no link
	 * exists when one does invites the owner to generate a second and silently
	 * retire the one they hold.
	 */
	public static function usable(): bool {
		return self::link_exists() && ! self::expired() && false !== Auditor::recovery_mail_result();
	}

	/**
	 * Where a printed code is used: this site's address with the code as the
	 * value of the same query argument the link carries. Given without a code,
	 * for a sheet of codes to say what to type before one.
	 */
	public static function code_address(): string {
		/*
		 * add_query_arg() writes an empty value as a bare key, and a code
		 * typed after a bare key is a different key altogether: the `=` is
		 * what the code has to follow. So the address is built around a
		 * stand-in value and the stand-in is taken out again.
		 */
		$stand_in = 'BETTERSHIELDCODE';

		return str_replace( $stand_in, '', add_query_arg( self::QUERY_VAR, $stand_in, home_url( '/' ) ) );
	}

	/**
	 * When the link on record was issued, or 0 when there is none.
	 *
	 * An owner saying "I received the recovery email" is saying it about one
	 * particular link. Recording this beside the answer is what lets a later
	 * link — which the owner has not received — stop counting as confirmed.
	 */
	public static function issued_at(): int {
		return self::link_exists() ? (int) get_option( self::ISSUED_OPTION ) : 0;
	}

	/**
	 * Issue a new link and email it to the administration address.
	 *
	 * The owner asked for the email again, which means the one on record never
	 * arrived or cannot be found. Only a hash is kept here, so the old link
	 * cannot be mailed a second time: a new one is issued, which retires the
	 * old, and the new one is what goes out. The delivery result is recorded
	 * against the new link the way activation records its own.
	 *
	 * The usual reason to ask again is mail that does not arrive, and on such
	 * a site this send fails too — after the old link was already retired. So
	 * the new link is always handed back through `$url`: the caller shows it
	 * once when the mail was not accepted, the way activation shows the first
	 * one, rather than leaving the owner a dead link and no live one.
	 *
	 * @param string|null $url Set to the new link whenever one was issued.
	 * @return bool|null Whether the mail was accepted for sending, or null when
	 *                   no link could be issued at all.
	 */
	public static function issue_and_mail( ?string &$url = null ): ?bool {
		$url = self::generate();

		if ( null === $url ) {
			return null;
		}

		$sent = RecoveryMail::send(
			(string) get_option( 'admin_email' ),
			self::keep_subject(),
			self::keep_heading(),
			'',
			$url,
			array(
				self::pauses_line(),
				self::works_once_line(),
				self::expiry_sentence( self::expires_at() ),
				__( 'Any recovery link sent before this one no longer works.', 'bettershield' ),
			),
			self::not_asked_line()
		);

		self::record_mailed( (bool) $sent, (string) get_option( 'admin_email' ) );

		return (bool) $sent;
	}

	/**
	 * Record whether the link on record was mailed, and to which address.
	 */
	public static function record_mailed( bool $sent, string $to ): void {
		update_option( self::MAILED_OPTION, $sent ? '1' : '0', false );

		if ( $sent ) {
			update_option( self::MAILED_TO_OPTION, $to, false );
		} else {
			delete_option( self::MAILED_TO_OPTION );
		}
	}

	/** The address the link on record was mailed to, or '' when unknown. */
	public static function mailed_to(): string {
		return (string) get_option( self::MAILED_TO_OPTION, '' );
	}

	/**
	 * The words every recovery email for one site shares, in one place, so
	 * the activation email and the one sent on request say the same (#1963).
	 */
	public static function keep_subject(): string {
		return \BetterShield\Alerts\Mailer::subject( __( 'Important: your emergency sign-in link for BetterShield (keep this email)', 'bettershield' ) );
	}

	public static function keep_heading(): string {
		return sprintf(
			/* translators: %s: the site's address without its scheme. */
			__( 'Save this email. If you’re ever locked out of %s, this link lets you back in.', 'bettershield' ),
			self::address( home_url() )
		);
	}

	public static function pauses_line(): string {
		return __( 'When you use it, BetterShield’s protections pause for one hour so you can sign in normally. No settings change.', 'bettershield' );
	}

	public static function works_once_line(): string {
		return __( 'You can use it once. After you press the button on the page it opens, you’ll get a new link to keep.', 'bettershield' );
	}

	public static function not_asked_line(): string {
		return __( 'Didn’t ask for this? Sign in and create a new link in BetterShield › Protection › Recovery. That turns this one off.', 'bettershield' );
	}

	/**
	 * An address without its scheme, path kept. On a subdirectory network
	 * every site shares the host, and the path is what tells one from another
	 * in a recovery mail: by host alone every subsite's read the same.
	 */
	public static function address( string $url ): string {
		return (string) preg_replace( '#^[a-z][a-z0-9+.-]*://#i', '', untrailingslashit( $url ) );
	}

	/**
	 * Create a new token, store only its hash, return the full URL — or null
	 * when the store refused the write, in which case nothing changed and no
	 * link was issued. Any previously issued link stops working.
	 *
	 * The hash is what makes the token a key. Handed back without it stored,
	 * the URL opens nothing, and the event recording it as issued would tell
	 * an owner their way back in is waiting when it is not — so the write is
	 * checked before either happens, the way every other sensitive action here
	 * checks its own. The hash is written first, so a store that is refusing
	 * writes refuses before the previous link is retired.
	 *
	 * What is checked is that the option holds the value afterward, not that
	 * the write reported a change — see `stored()`.
	 */
	public static function generate(): ?string {
		$replaced = self::link_exists();
		$token    = bin2hex( random_bytes( 32 ) );

		if ( ! self::stored( self::HASH_OPTION, hash( 'sha256', $token ) ) ) {
			return null;
		}

		// An issue date left behind by the link this one replaces would give
		// the new link the old one's expiry, and a way back in that reports
		// itself already over is not one.
		if ( ! self::stored( self::ISSUED_OPTION, (string) time() ) ) {
			return null;
		}

		// The delivery record belongs to the link on record, and this is a
		// different link. Left in place, a failure recorded against the link
		// this one replaces would go on saying the owner never received a link
		// they are in fact holding. Every path that attempts a send writes the
		// result of its own send afterward; the paths that hand the link
		// straight to the person asking write nothing, because they claim no
		// delivery.
		delete_option( self::MAILED_OPTION );
		delete_option( self::MAILED_TO_OPTION );

		// Generating a link silently retires the previous one, which is the
		// owner's only way back in without credentials. Neither the token nor
		// its hash is ever logged.
		Writer::instance()->record(
			'recovery_link_generated',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'recovery_link',
				'context'     => array( 'replaced_previous' => $replaced ),
			)
		);

		return add_query_arg( self::QUERY_VAR, $token, home_url( '/' ) );
	}

	/**
	 * Write an option and answer whether it holds that value afterward.
	 *
	 * `update_option()` answers false for a refused write and for a value that
	 * had not changed, and the second genuinely happens here: two links issued
	 * inside the same second carry the same issue date. Reading the option back
	 * tells the two apart, which is what the rest of this plugin does wherever
	 * a write has to be checked before the thing it enables goes ahead.
	 */
	private static function stored( string $option, string $value ): bool {
		return update_option( $option, $value, false ) || (string) get_option( $option ) === $value;
	}

	/**
	 * The same, for the network's own pair: two links issued inside one
	 * second write the same issue date, and an unchanged value is a write
	 * that landed rather than one that was refused.
	 */
	private static function network_stored( string $option, string $value ): bool {
		return update_network_option( null, $option, $value ) || (string) get_network_option( null, $option ) === $value;
	}

	/**
	 * Generate only if no link exists yet (activation path). Returns the
	 * URL when newly created, null when a link already exists — an
	 * existing link must never be silently invalidated.
	 */
	public static function ensure(): ?string {
		return self::link_exists() ? null : self::generate();
	}

	/**
	 * Verify a token and enter safe mode on success. Constant-time
	 * comparison; failures are logged as security-relevant events.
	 *
	 * **A link is spent by using it.** Succeeding here immediately issues a
	 * replacement, which is what retires the token just presented: a link read
	 * off an old email, a browser history, a proxy log or a shared screen is
	 * worth one use and then nothing. Before this it was a permanent
	 * pause-all-security credential for anyone who ever saw it.
	 *
	 * The replacement is handed back through `$replacement` and shown on the
	 * page, not merely mailed. That ordering is the whole safety of this: the
	 * person who just used a link is holding the next one before they leave the
	 * screen, so there is no instant — not even a failed-email one — in which
	 * the owner has no way back in. Mail is a convenience on top of that, and
	 * its failure costs nothing.
	 *
	 * @param string|null $replacement Set to the URL of the newly issued link
	 *                                 when this returns true.
	 */
	public static function attempt( string $token, ?string &$replacement = null ): bool {
		$stored = get_option( self::HASH_OPTION );

		if ( ! is_string( $stored ) || '' === $stored ) {
			return false;
		}

		/*
		 * Every token this plugin issues is 64 hex characters, so anything else
		 * was never one of ours and is refused before it can reach the log —
		 * which is what keeps ordinary scanner traffic from writing rows.
		 *
		 * The caller sees no difference: handle_request() answers 403 either
		 * way, so nothing here discloses what a real token looks like.
		 */
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}

		if ( ! hash_equals( $stored, hash( 'sha256', $token ) ) ) {
			/*
			 * A network link is presented at a site's own address, because one
			 * address to remember is the whole point of this door. So a token
			 * this site does not know is not yet a guess — it is a guess only
			 * once the network does not know it either, and the network's own
			 * attempt records it then.
			 */
			if ( ! self::network_matches( $token ) ) {
				self::record_failure();
			}

			return false;
		}

		// Refused the same way an unknown token is — same answer, same log —
		// so the page never reveals that a token was real but stale.
		if ( self::expired() ) {
			self::record_failure();

			return false;
		}

		$duration = (int) apply_filters( 'bettershield_safe_mode_duration', HOUR_IN_SECONDS );

		// The thing they came for happens first and unconditionally. Whatever
		// follows, the site is now in safe mode.
		SafeMode::enter( $duration, 'recovery_link' );

		// Storing the new hash is what makes the presented token dead, so the
		// replacement exists before the old one stops working rather than after.
		// A refused write leaves the presented token alive, which is the safer
		// of the two ways to fail here: the owner keeps a way back in.
		$replacement = self::generate();

		if ( null !== $replacement ) {
			update_option( self::SPENT_OPTION, self::spent_record( $token, $duration ), false );
			self::mail_replacement_after_response( $replacement );
		}

		return true;
	}

	/**
	 * What is kept of a link just spent: never the token, only its hash.
	 *
	 * @return array{hash: string, until: int}
	 */
	private static function spent_record( string $token, int $duration ): array {
		return array(
			'hash'  => hash( 'sha256', $token ),
			'until' => time() + $duration,
		);
	}

	/**
	 * Whether a token is the link that started the safe mode now running,
	 * and whose link it was: false for this site's, true for the network's,
	 * null when it is neither.
	 *
	 * Only while that safe mode lasts. Once it has ended, or been ended, the
	 * token is answered as any spent token is.
	 */
	private static function just_spent( string $token ): ?bool {
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return null;
		}

		$hash  = hash( 'sha256', $token );
		$kinds = array(
			array( get_option( self::SPENT_OPTION ), SafeMode::is_site_active(), false ),
			array( is_multisite() ? get_network_option( null, self::NETWORK_SPENT_OPTION ) : null, SafeMode::is_network_active(), true ),
		);

		foreach ( $kinds as list( $spent, $active, $network ) ) {
			if ( $active && is_array( $spent ) && isset( $spent['hash'], $spent['until'] ) && (int) $spent['until'] > time() && hash_equals( (string) $spent['hash'], $hash ) ) {
				return $network;
			}
		}

		return null;
	}

	/**
	 * Queue the notification to go out once the page has been produced.
	 *
	 * Using a recovery link is a front-end request, and this page is the one
	 * page on the site that must never fail: an owner opening it is already
	 * locked out. Sending the mail inline made that page wait on an external
	 * mail server, so a host with broken SMTP would hang it for the timeout at
	 * exactly the wrong moment. On shutdown the reader has their replacement
	 * link in front of them before anything is attempted, and a mail server
	 * that never answers costs them nothing.
	 *
	 * The mail still matters: it is the only thing that tells an owner their
	 * link was used by somebody who was not them.
	 */
	private static function mail_replacement_after_response( string $url ): void {
		add_action(
			'shutdown',
			static function () use ( $url ): void {
				self::mail_replacement( $url );
			},
			1000
		);
	}

	/**
	 * Send the freshly issued link to the site's admin address.
	 *
	 * Best-effort by design: the caller has already been handed the same link
	 * to read on screen, so a mail that never arrives costs convenience and
	 * nothing else. Failure is deliberately not surfaced as an error for the
	 * same reason.
	 *
	 * The result is still recorded, the way its network sibling records its
	 * own: `generate()` cleared the previous link's record on the way here, so
	 * without this the site would have no record at all, and the dashboard
	 * would go on reporting a link as available to an owner who never received
	 * it. A recorded failure is what makes the readiness screen say `refused`
	 * and keeps the one setting that takes a password away from arming behind
	 * a link nobody holds.
	 */
	private static function mail_replacement( string $url ): void {
		$sent = RecoveryMail::send(
			(string) get_option( 'admin_email' ),
			\BetterShield\Alerts\Mailer::subject( __( 'Important: your emergency sign-in link for BetterShield was used (keep this email)', 'bettershield' ) ),
			// What happened first, then why to keep the new link (#2843).
			__( 'Your recovery link was used. Protection is paused for one hour.', 'bettershield' ),
			__( 'If it was you, no action needed.', 'bettershield' ) . ' ' . self::keep_heading(),
			$url,
			array(
				self::pauses_line(),
				self::works_once_line(),
				self::expiry_sentence( self::expires_at() ),
			),
			__( 'Not you? Sign in and create a new link in BetterShield › Protection › Recovery. That turns the link above off at once.', 'bettershield' )
		);

		self::record_mailed( (bool) $sent, (string) get_option( 'admin_email' ) );
	}

	/**
	 * Record a failed attempt, coalesced.
	 *
	 * A well-formed token that does not match is a guess at 256 bits of
	 * entropy, which belongs on the record — but one row per guess lets anyone
	 * grow the events table from outside, and a log nobody can read is a log
	 * that failed. So the first failure in a window is recorded at once, the
	 * rest are counted, and the next recorded failure carries the count with
	 * it: the same "one synthetic event with the true count, never silently"
	 * arrangement the event writer already uses when its buffer overflows.
	 *
	 * State lives in a transient rather than an option, so a site with a
	 * persistent object cache absorbs a flood without touching the database at
	 * all, and a site without one still spends a fixed row instead of a
	 * growing table.
	 *
	 * The tail of a burst can be lost: if attempts stop and nothing else fails
	 * before the transient expires, the final count goes unreported. The event
	 * that opened the window has already said an attack is under way, which is
	 * the part worth knowing promptly.
	 *
	 * Shared with `OfflineCodes`, which is the other credential this same door
	 * accepts. One window for both, or a flood that alternates between the two
	 * shapes is coalesced as two separate quieter attacks.
	 */
	/* ---- the network's own link ------------------------------------ */

	public static function network_link_exists(): bool {
		$stored = get_network_option( null, self::NETWORK_HASH_OPTION, '' );

		return is_string( $stored ) && '' !== $stored;
	}

	/**
	 * When the network's link stops working, or null when there is none.
	 * Undated is read as issued now, for the reason `expires_at()` gives.
	 */
	public static function network_expires_at(): ?int {
		if ( ! self::network_link_exists() ) {
			return null;
		}

		$issued = (int) get_network_option( null, self::NETWORK_ISSUED_OPTION, 0 );

		if ( $issued <= 0 ) {
			$issued = time();
			update_network_option( null, self::NETWORK_ISSUED_OPTION, $issued );
		}

		return $issued + self::lifetime();
	}

	public static function network_expired(): bool {
		$expires = self::network_expires_at();

		return null !== $expires && time() > $expires;
	}

	/**
	 * Whether the mail carrying the network's link was accepted, or null
	 * where none was ever attempted.
	 *
	 * Three states rather than two, for the reason the per-site record keeps
	 * three: a link that was read on screen was never mailed, and reading
	 * that as a failure would say nobody holds one when somebody does.
	 */
	public static function network_mail_result(): ?bool {
		$recorded = get_network_option( null, self::NETWORK_MAILED_OPTION, null );

		return null === $recorded ? null : '1' === $recorded;
	}

	/**
	 * What the network dashboard shows about the link on record.
	 *
	 * @return array{exists: bool, expires: ?int, mailed: ?bool}
	 */
	public static function network_state(): array {
		return array(
			'exists'  => self::network_link_exists(),
			'expires' => self::network_expires_at(),
			'mailed'  => self::network_mail_result(),
		);
	}

	/**
	 * Create the network's link, store only its hash, return the full URL.
	 * Any previously issued network link stops working.
	 *
	 * The address is the network's own home, which is where somebody writing
	 * one down would expect to find it — but the handler runs on every site,
	 * so a network whose main site is the unreachable one is still opened
	 * from any other.
	 */
	public static function generate_network(): ?string {
		$replaced = self::network_link_exists();
		$token    = bin2hex( random_bytes( 32 ) );

		// The hash first, so a store refusing writes refuses before the
		// previous link is retired; a link whose hash never landed opens
		// nothing, so none is handed back and nothing is logged as issued.
		if ( ! self::network_stored( self::NETWORK_HASH_OPTION, hash( 'sha256', $token ) ) ) {
			return null;
		}

		if ( ! self::network_stored( self::NETWORK_ISSUED_OPTION, (string) time() ) ) {
			return null;
		}

		delete_network_option( null, self::NETWORK_MAILED_OPTION );

		// The network's link, on the network's record whichever site's
		// address served the use that replaced it (#2135).
		SafeMode::record_for_network(
			'recovery_link_generated',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'recovery_link',
				'context'     => array(
					'replaced_previous' => $replaced,
					'scope'             => 'network',
				),
			)
		);

		return add_query_arg( self::QUERY_VAR, $token, network_home_url( '/' ) );
	}

	/**
	 * Whether a well-formed token is the network's link, without spending it.
	 */
	private static function network_matches( string $token ): bool {
		if ( ! is_multisite() || 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}

		$stored = get_network_option( null, self::NETWORK_HASH_OPTION, '' );

		if ( ! is_string( $stored ) || '' === $stored ) {
			return false;
		}

		return hash_equals( $stored, hash( 'sha256', $token ) );
	}

	/**
	 * Verify the network's token and raise network safe mode on success.
	 *
	 * The same shape rule, the same constant-time comparison and the same
	 * spend-on-use replacement as the per-site link. What differs is only how
	 * far it reaches: every site of the network stands down, which is why it
	 * is issued from the network dashboard and nowhere else.
	 *
	 * @param string|null $replacement Set to the URL of the newly issued link
	 *                                 when this returns true.
	 */
	public static function attempt_network( string $token, ?string &$replacement = null ): bool {
		if ( ! self::network_matches( $token ) ) {
			return false;
		}

		// Refused the same way an unknown token is, so the page never reveals
		// that a token was real but stale.
		if ( self::network_expired() ) {
			self::record_failure();

			return false;
		}

		$duration = (int) apply_filters( 'bettershield_safe_mode_duration', HOUR_IN_SECONDS );

		SafeMode::enter_network( $duration, 'recovery_link' );

		$replacement = self::generate_network();

		// A replacement that could not be stored leaves the presented link
		// on record rather than pretending it was retired.
		if ( null !== $replacement ) {
			update_network_option( null, self::NETWORK_SPENT_OPTION, self::spent_record( $token, $duration ) );
			self::mail_network_replacement_after_response( $replacement );
		}

		return true;
	}

	private static function mail_network_replacement_after_response( string $url ): void {
		add_action(
			'shutdown',
			static function () use ( $url ): void {
				self::mail_network_replacement( $url );
			},
			1000
		);
	}

	/**
	 * Send the freshly issued network link to the network's own address.
	 *
	 * Best-effort, like its per-site sibling: the caller was handed the same
	 * link to read on screen before this is attempted. The result is recorded
	 * because the dashboard reports whether a link ever reached anybody.
	 */
	private static function mail_network_replacement( string $url ): void {
		$network = get_network();
		$name    = $network ? wp_specialchars_decode( (string) $network->site_name, ENT_QUOTES ) : '';

		$named = '' !== $name ? $name : self::address( network_home_url() );

		$sent = RecoveryMail::send(
			(string) get_network_option( null, 'admin_email', '' ),
			sprintf(
				/* translators: 1: the network's name, or its address where it has none. */
				__( '[%s] Important: your emergency sign-in link for the BetterShield network was used (keep this email)', 'bettershield' ),
				$named
			),
			// What happened first, then why to keep the new link (#2843).
			__( 'Your network’s recovery link was used. Protection is paused on every site for one hour.', 'bettershield' ),
			__( 'If it was you, no action needed.', 'bettershield' ) . ' ' . sprintf(
				/* translators: %s: the network's name, or its address. */
				__( 'Save this email. If you’re ever locked out of the %s network, this link lets you back in.', 'bettershield' ),
				$named
			),
			$url,
			array(
				__( 'Using it pauses BetterShield on every site for one hour and keeps every setting.', 'bettershield' ),
				self::works_once_line(),
				self::expiry_sentence( self::network_expires_at(), true ),
			),
			__( 'Not you? Sign in to the network dashboard and make a new link. That stops the link above at once.', 'bettershield' )
		);

		update_network_option( null, self::NETWORK_MAILED_OPTION, $sent ? '1' : '0' );
	}

	public static function record_failure(): void {
		/**
		 * Filters how long failed recovery attempts are coalesced into one
		 * logged event.
		 *
		 * @param int $seconds Window length in seconds.
		 */
		$window = (int) apply_filters( 'bettershield_recovery_failure_window', 5 * MINUTE_IN_SECONDS );

		$suppressed = \BetterShield\Events\Coalescer::admit( self::FAIL_TRANSIENT, $window );

		if ( null === $suppressed ) {
			return;
		}

		Writer::instance()->record(
			'recovery_link_failed',
			Writer::SEVERITY_MEDIUM,
			array(
				'object_type' => 'safe_mode',
				'context'     => $suppressed > 0 ? array( 'unlogged_attempts' => $suppressed ) : array(),
			)
		);
	}

	/**
	 * The markup the confirmation page is made of, and nothing else: a
	 * heading, its paragraphs, and the form whose button spends the
	 * credential.
	 */
	private const CONFIRM_HTML = array(
		'h1'     => array(),
		'p'      => array(),
		'form'   => array(
			'method'   => true,
			'action'   => true,
			'onsubmit' => true,
		),
		'input'  => array(
			'type'  => true,
			'name'  => true,
			'value' => true,
		),
		'button' => array(
			'type'  => true,
			'style' => true,
		),
	);

	/**
	 * The markup the safe-mode page is made of: its headings and paragraphs,
	 * the box the replacement link is shown in, and the way on to sign-in.
	 */
	private const ENTERED_HTML = array(
		'h1'   => array(),
		'h2'   => array(),
		'p'    => array(),
		'code' => array(
			'style' => true,
		),
		'a'    => array(
			'href' => true,
		),
	);

	public static function handle_request(): void {
		/*
		 * No nonce, and no capability check, by design.
		 *
		 * This is the same shape as core's own password reset link: a request
		 * from someone who cannot log in, carrying a secret as its only
		 * credential. A nonce is derived from a session, and the whole point of
		 * this handler is that there is no session — requiring one would make
		 * the link work everywhere except the situation it exists for.
		 *
		 * What stands in for it is the token: 256 bits from the CSPRNG, stored
		 * only as a SHA-256 hash, compared in constant time, and refused outright
		 * unless it matches the exact shape this plugin issues. A request without
		 * the token achieves nothing, and guessing is logged and coalesced so the
		 * attempt cannot grow the events table either.
		 *
		 * It is also not a CSRF target in the usual sense. Tricking a visitor
		 * into following this link accomplishes only what the link already does
		 * for anyone holding it, and doing so requires already knowing it.
		 */
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- the token is the credential, as above.
		$posted = isset( $_POST[ self::QUERY_VAR ] ) && is_string( $_POST[ self::QUERY_VAR ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::QUERY_VAR ] ) ) : '';
		$given  = isset( $_GET[ self::QUERY_VAR ] ) && is_string( $_GET[ self::QUERY_VAR ] ) ? sanitize_text_field( wp_unslash( $_GET[ self::QUERY_VAR ] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended

		$token = '' !== $posted ? $posted : $given;

		if ( '' === $token ) {
			return;
		}

		/*
		 * Following the link shows a page; a person pressing its button is
		 * what spends the credential.
		 *
		 * Core's password reset link is the model this handler names, and the
		 * comparison only holds with this half: there too the GET shows a
		 * form and the POST is the spend. Without it, the mail gateways and
		 * link-preview features that open every delivered link before a human
		 * sees it spend this one — safe mode starts, all enforcement pauses,
		 * and the replacement link is printed into a response nobody read.
		 * The owner's own click then arrives at a credential already used.
		 */
		if ( 'POST' !== strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET' ) ) {
			self::show_confirm( $token );

			return;
		}

		/*
		 * The link that started the safe mode now running, posted again by a
		 * double click or a reload. It worked; saying it was not valid, and
		 * logging a failure, told a locked-out owner the opposite of what had
		 * happened. Asked before anything that would count it as a guess.
		 */
		$spent = self::just_spent( $token );

		if ( null !== $spent ) {
			self::show_entered( SafeMode::until(), null, null, $spent, true );

			return;
		}

		/*
		 * A printed code arrives at the same door, because the door is the
		 * thing that works when nothing else does — one address to write down,
		 * one page that answers it, whichever credential the owner still has.
		 * Told apart by shape rather than by a second query variable: the two
		 * cannot be confused with each other (sixteen hex against sixty-four),
		 * and a page that took a different address for each would be a second
		 * thing to remember on the day remembering is hardest.
		 *
		 * A code spends itself and opens safe mode; it issues no replacement
		 * link, because the codes are independent of each other and of the
		 * link. What follows below is the same page either way.
		 */
		$replacement = null;

		if ( OfflineCodes::attempt( $token ) ) {
			self::show_entered( SafeMode::until(), null, OfflineCodes::remaining() );

			return;
		}

		/*
		 * The site's own link first, then the network's. Nothing but the
		 * matching hash tells them apart, which is what lets one address
		 * answer whichever credential the reader still holds.
		 */
		$own     = self::attempt( $token, $replacement );
		$network = ! $own && self::attempt_network( $token, $replacement );

		if ( $own || $network ) {
			$until = SafeMode::until();

			/*
			 * The replacement is put in front of the reader here, not left to
			 * the email. This page is the one moment the owner is certain to
			 * see, and a link that only ever went to an inbox that bounced
			 * would leave them with no way back in — which is the one failure
			 * this whole feature exists to prevent.
			 *
			 * Showing it is not a disclosure: whoever is reading it just proved
			 * they held a valid link, so they already had everything the new
			 * one grants.
			 */
			self::show_entered( $until, (string) $replacement, null, $network );
		}

		/*
		 * Refused for the pause on guessing rather than for the code: saying
		 * "not valid" sent an owner holding a good code to throw it away
		 * (#2773).
		 */
		if ( OfflineCodes::paused() ) {
			wp_die(
				wp_kses_post( self::invalid_page( true ) ),
				esc_html__( 'Recovery codes paused', 'bettershield' ),
				array( 'response' => 429 )
			);
		}

		wp_die(
			wp_kses_post( self::invalid_page() ),
			esc_html__( 'Invalid recovery link', 'bettershield' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * The page an unusable link or code ends on: what happened, and where to
	 * go from here. It was one line in a bare box, with no heading and no
	 * way on (#1938).
	 *
	 * The sign-in page is offered only where its address is not hidden: this
	 * page answers anybody holding any string, and handing them a hidden
	 * address would undo the protection that hid it. Hidden by this plugin or
	 * by another one: those rewrite the address wp_login_url() gives, so it
	 * is offered only while that is still wp-login.php.
	 *
	 * @param bool $paused Whether codes were refused for the pause on
	 *                     guessing rather than for the code itself.
	 */
	private static function invalid_page( bool $paused = false ): string {
		$ways = array(
			'<li>' . esc_html__( 'Have recovery codes? Open the address in your codes file or printout, with an unused code.', 'bettershield' ) . '</li>',
		);

		$login = wp_login_url();

		if ( ! \BetterShield\Hardening\Manager::instance()->is_active( 'login_url' ) && 'wp-login.php' === basename( (string) wp_parse_url( $login, PHP_URL_PATH ) ) ) {
			$ways[] = '<li><a href="' . esc_url( $login ) . '">' . esc_html__( 'Go to the sign-in page', 'bettershield' ) . '</a></li>';
		}

		$ways[] = '<li><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( 'Go to the home page', 'bettershield' ) . '</a></li>';

		if ( $paused ) {
			return '<h1>' . esc_html__( 'Recovery codes are paused for now', 'bettershield' ) . '</h1>'
				. '<p>' . esc_html__( 'Too many wrong codes were tried here, so codes are paused for up to an hour. Your code was not used. Try it again later.', 'bettershield' ) . '</p>'
				. '<p>' . esc_html__( 'What you can try next:', 'bettershield' ) . '</p>'
				. '<ul>' . implode( '', array_slice( $ways, 1 ) ) . '</ul>';
		}

		return '<h1>' . esc_html__( 'This recovery link did not work', 'bettershield' ) . '</h1>'
			. '<p>' . esc_html__( 'It may be mistyped or already used. Each link and code works once.', 'bettershield' ) . '</p>'
			. '<p>' . esc_html__( 'What you can try next:', 'bettershield' ) . '</p>'
			. '<ul>' . implode( '', $ways ) . '</ul>';
	}

	/**
	 * The page an emailed link lands on, with the button that spends it.
	 *
	 * Nothing is read, changed or spent here: the token travels through the
	 * form untouched, and a request that never presses the button leaves the
	 * credential exactly as it found it.
	 */
	private static function show_confirm( string $token ): void {
		/*
		 * A spent link is replaced and a spent code is not — the codes are a
		 * set of their own — so what pressing the button costs is said for the
		 * credential in hand. Told apart by shape, as handle_request() does.
		 */
		$spent = OfflineCodes::shaped_like_code( $token )
			? __( 'Pressing the button uses up this code, not your others. Didn’t ask for this? Close this page; nothing has happened yet.', 'bettershield' )
			: __( 'Pressing the button uses up this link and shows a new one. Didn’t ask for this? Close this page; nothing has happened yet.', 'bettershield' );

		// The network's link pauses every site of it, and says so. How long,
		// in words, from the same filter the pause itself reads: "briefly"
		// stood in for a number the email gives (#2843).
		$network = ! OfflineCodes::shaped_like_code( $token ) && self::network_matches( $token );
		$length  = human_time_diff( 0, max( MINUTE_IN_SECONDS, (int) apply_filters( 'bettershield_safe_mode_duration', HOUR_IN_SECONDS ) ) );
		$whose   = $network
			/* translators: %s: how long, e.g. "1 hour". */
			? sprintf( __( 'This pauses BetterShield protection on every site of this network for %s so you can sign in. No settings change.', 'bettershield' ), $length )
			/* translators: %s: how long, e.g. "1 hour". */
			: sprintf( __( 'This pauses BetterShield protection for %s so you can sign in. No settings change.', 'bettershield' ), $length );

		$page = '<h1>' . esc_html__( 'Pause protection and get back in?', 'bettershield' ) . '</h1><p>' .
			esc_html( $whose ) .
			'</p><p>' .
			esc_html( $spent ) .
			// One press is one post: a double click sent two, and the second
			// was answered for a credential the first had already spent.
			'</p><form method="post" action="' . esc_url( add_query_arg( self::QUERY_VAR, $token, home_url( '/' ) ) ) . '" onsubmit="this.querySelector(\'button\').disabled=true;">' .
			'<input type="hidden" name="' . esc_attr( self::QUERY_VAR ) . '" value="' . esc_attr( $token ) . '" />' .
			'<p><button type="submit" style="padding:10px 16px;font-size:15px;">' . esc_html__( 'Pause Protection and Continue', 'bettershield' ) . '</button></p>' .
			'</form>';

		/*
		 * Every part is escaped where it is built. Filtered on the way out as
		 * well, but not by the post allowlist: that one allows no form and no
		 * input, so the button was left outside any form and pressing it sent
		 * nothing — the link and every printed code stopped at this page.
		 */
		wp_die(
			wp_kses( $page, self::CONFIRM_HTML ),
			esc_html__( 'Recovery', 'bettershield' ),
			array( 'response' => 200 )
		);
	}

	/**
	 * The page somebody sees after getting back in.
	 *
	 * One page for both credentials, because the reader is in the same
	 * situation either way and the difference between them is one paragraph:
	 * a spent link is replaced and the replacement has to be put in front of
	 * them here, while a spent code is one of a set and what matters is how
	 * many are left.
	 *
	 * The replacement is shown rather than left to the email deliberately —
	 * this page is the one moment the owner is certain to see, and a link that
	 * only ever went to an inbox that bounced would leave them with no way
	 * back in, which is the one failure this whole feature exists to prevent.
	 * It is not a disclosure either way: whoever is reading it just proved
	 * they held a valid credential.
	 *
	 * @param int|null    $until       When safe mode ends.
	 * @param string|null $replacement The next link, when a link was used.
	 * @param int|null    $remaining   Codes left, when a code was used.
	 * @param bool        $network     Whether the network's link was used, which paused every site.
	 * @param bool        $again       Whether this is the link that started it, posted again.
	 */
	private static function show_entered( ?int $until, ?string $replacement, ?int $remaining, bool $network = false, bool $again = false ): void {
		/*
		 * The end in the site's own date and time format with its zone, and
		 * how long that is from now, which reads the same on any clock. A bare
		 * hour in the site's zone read as already past to an owner whose own
		 * clock was in another.
		 */
		$paused = null !== $until
			? sprintf(
				$network
					/* translators: 1: date, time and time zone, 2: how long from now, e.g. "1 hour". */
					? __( 'BetterShield protection is paused on every site of this network until %1$s, %2$s from now. Nothing was changed or deactivated.', 'bettershield' )
					/* translators: 1: date, time and time zone, 2: how long from now, e.g. "1 hour". */
					: __( 'BetterShield protection is paused until %1$s, %2$s from now. Nothing was changed or deactivated.', 'bettershield' ),
				\BetterShield\Support\Time::said( $until ),
				human_time_diff( time(), $until )
			)
			: ( $network
				? __( 'BetterShield protection is paused on every site of this network. Nothing was changed or deactivated.', 'bettershield' )
				: __( 'BetterShield protection is paused. Nothing was changed or deactivated.', 'bettershield' ) );

		$page = '<h1>' . esc_html__( 'Protection is paused', 'bettershield' ) . '</h1><p>' . esc_html( $paused ) . '</p>';

		if ( null !== $replacement ) {
			$page .= '<h2>' . esc_html__( 'Save your next recovery link', 'bettershield' ) . '</h2><p>' .
				esc_html(
					$network
						? __( 'Your old link no longer works. Copy the new one now; treat it like a password. It is also emailed to the network’s admin address.', 'bettershield' )
						: __( 'Your old link no longer works. Copy the new one now; treat it like a password. It is also emailed to the site’s admin address.', 'bettershield' )
				) .
				'</p><p><code style="display:block;word-break:break-all;padding:12px;background:#f0f0f1;">' . esc_html( $replacement ) . '</code></p>';
		}

		// The replacement was printed once, for whoever posted first; this
		// says where it went rather than printing it again.
		if ( $again ) {
			$page .= '<p>' . esc_html(
				$network
					? __( 'This link was already used and no longer works. Its replacement was shown then and emailed to the network’s admin address.', 'bettershield' )
					: __( 'This link was already used and no longer works. Its replacement was shown then and emailed to the site’s admin address.', 'bettershield' )
			) . '</p>';
		}

		if ( null !== $remaining ) {
			$page .= '<p>' . esc_html(
				sprintf(
					/* translators: %d: how many printed codes are left. */
					_n(
						'That code no longer works. You have %d recovery code left. When it is used, issue a new set from the Recovery screen.',
						'That code no longer works. You have %d recovery codes left. When they run out, issue a new set from the Recovery screen.',
						(int) $remaining,
						'bettershield'
					),
					(int) $remaining
				)
			) . '</p>';
		}

		$page .= '<p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Go to sign-in', 'bettershield' ) . '</a></p>';

		/*
		 * Every part is escaped where it is built, and filtered on the way out
		 * by this page's own allowlist. Core's style filter does not know
		 * word-break, and without it the sixty-four-character link never
		 * wrapped: on a phone it ran out of its box and the page laid out
		 * wider than the screen. It is allowed for this page only.
		 */
		$break = static function ( array $styles ): array {
			$styles[] = 'word-break';

			return $styles;
		};

		add_filter( 'safe_style_css', $break );

		try {
			wp_die(
				wp_kses( $page, self::ENTERED_HTML ),
				esc_html__( 'Protection is paused', 'bettershield' ),
				array( 'response' => 200 )
			);
		} finally {
			remove_filter( 'safe_style_css', $break );
		}
	}
}
