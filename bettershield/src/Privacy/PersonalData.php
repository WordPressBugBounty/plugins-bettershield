<?php
/**
 * What this plugin holds about one person, and what happens when they ask for
 * it to go.
 *
 * WordPress has had a place for this since 4.9.6: an account holder asks the
 * site owner, the owner presses a button, and every plugin that keeps
 * something about that person is expected to answer. A plugin that keeps
 * something and registers nothing is not refusing — it is silently absent, and
 * the owner sends an export that is missing whatever this plugin knows without
 * either of them finding out.
 *
 * **The erasure is not symmetrical with the export, and that is deliberate.**
 * The activity log is the record of what happened to a site, and the one thing
 * an intruder wants gone. Erasing it on request would make this plugin the
 * tool for doing that, and a request signed by whoever is holding the account
 * is exactly the shape that arrives. So the personally identifying parts of a
 * row are removed and the row itself stays, counted and declared: WordPress
 * has `items_retained` for precisely this, and the message says why in words
 * an owner can pass on.
 *
 * `records()` below is the ledger the whole thing turns on: one entry for
 * every record this plugin keeps that belongs to a person, saying what it
 * holds, why, how long it is kept, and what an erasure does to it. The export
 * hands it to the person, Site Health prints it for the owner, and a test
 * walks the source so a key cannot be added without its line.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Privacy;

// Ahead of the imports: a long header and a long import list would otherwise
// push it past the fiftieth line, which is as far as Plugin Check reads.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BetterShield\Audit\Dormant;
use BetterShield\Database\Schema;
use BetterShield\Events\Seal;
use BetterShield\Hardening\Manager;
use BetterShield\Events;
use BetterShield\Events\Types;
use BetterShield\Events\Writer;
use BetterShield\Login\Sessions;
use BetterShield\Mcp;
use BetterShield\Onboarding;
use BetterShield\Alerts;
use BetterShield\Password;
use BetterShield\Rest;
use BetterShield\Support\Claim;
use BetterShield\Support\Ip;
use BetterShield\Support\Tier;
use BetterShield\Support\Time;
use BetterShield\TwoFactor;

final class PersonalData {

	/**
	 * The rows about one account rather than by it, as a WHERE fragment: two
	 * placeholders, the account's id as a string and its login. Its id is the
	 * object of every user event; a reset request and a failed sign-in name
	 * the login instead (the second since #1821: the reset alone was taught).
	 */
	private const SUBJECT_ROWS = "( object_type = 'user' AND ( object_id = %s OR ( event_type IN ( 'password_reset_requested', 'login_failed' ) AND object_id = %s ) ) )";

	/** The user events that name the account by its login rather than its id. */
	private const LOGIN_NAMED = array( 'password_reset_requested', 'login_failed' );

	/** The group this plugin's rows appear under in an export. */
	private const GROUP = 'bettershield';

	/** What an erasure request does to a record. */
	public const ERASURE_REMOVED = 'removed';
	public const ERASURE_KEPT    = 'kept';

	/**
	 * The ledger keys a network stores once per site, because what they hold
	 * is about the account on one site rather than across the whole of it.
	 *
	 * @var string[]
	 */
	private const SITE_SCOPED_META = array(
		'bettershield_2fa_park',
		'bettershield_2fa_required_since',
		'bettershield_last_overview_visit',
		'bettershield_overview_visit_window',
		'bettershield_password_below_policy',
	);

	/**
	 * The list above once the filter has had its say, for this request.
	 *
	 * @var string[]|null
	 */
	private static ?array $site_scoped_meta = null;

	/**
	 * Every record this plugin keeps that belongs to a person rather than to
	 * the site: what it holds, why it is held, how long it is kept, and what
	 * an erasure request does to it.
	 *
	 * One list, read by the three places that have to agree — the Site Health
	 * report an owner pastes into a support thread, the export handed to the
	 * person who asked, and the erasure below that decides what stays. A key
	 * written without an entry here is a record about somebody that nothing in
	 * the product can describe, and a test walks the source to make that
	 * impossible.
	 *
	 * A method rather than a declared list because the sentences are
	 * translated and one window is read from the tier at the time of asking,
	 * neither of which a constant expression can do. Keys are written out
	 * rather than borrowed from the classes that own them: most of those
	 * constants are private to their own class, and the census that walks the
	 * source is what holds the two in step.
	 *
	 * A key is the storage — a user meta key, or `table.column` where a table
	 * holds rows against an account. The list is filterable, because a screen
	 * headed with what this plugin keeps about people is telling the owner a
	 * half-truth if an add-on holding something of its own cannot say so.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function records(): array {
		/**
		 * The whole ledger, for an add-on that keeps something about a person
		 * too. An entry carries `what`, `why`, `window` and `on_erasure`, and
		 * `kept_because` when an erasure keeps it; its key is the storage.
		 *
		 * A `table.column` key needs one field more: `held`, a callable taking
		 * an account id and answering whether that account has such a record.
		 * A meta key answers for itself, because the export asks the meta
		 * store — a table-backed one has nowhere to ask, so without `held` the
		 * declaration is accepted and the entry is then printed for nobody.
		 *
		 * @param array<string, array<string, mixed>> $records Keyed by storage key.
		 */
		return (array) apply_filters( 'bettershield_personal_data_records', self::own_records() );
	}

	/**
	 * The records this plugin keeps itself.
	 *
	 * Separated from `records()` so the filter cannot be reached by anything
	 * here: what this plugin holds is not an opinion, and the erasure and the
	 * census both read the ledger through the filter on purpose — an add-on
	 * that keeps something about a person has to be able to say so on the
	 * same screen, or the screen is telling the owner a half-truth.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function own_records(): array {
		$until_two_factor_off = __( 'until two-factor is turned off for the account', 'bettershield' );
		$until_setup_settles  = __( 'until the setup is confirmed or started again', 'bettershield' );
		$until_account_gone   = __( 'until the account is deleted', 'bettershield' );

		return array(
			'bettershield_totp_secret'           => array(
				'what'       => __( 'The shared secret behind the codes an authenticator app shows for this account.', 'bettershield' ),
				'why'        => __( 'A code cannot be checked against anything else.', 'bettershield' ),
				'window'     => $until_two_factor_off,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_totp_pending'          => array(
				'what'       => __( 'The shared secret for a two-factor setup that was started and not finished.', 'bettershield' ),
				'why'        => __( 'The setup screen has to offer the same secret until a code confirms it.', 'bettershield' ),
				'window'     => $until_setup_settles,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_totp_confirmed'        => array(
				'what'       => __( 'That a code from the setup screen was entered correctly.', 'bettershield' ),
				'why'        => __( 'It is what tells the last step of a setup from an unfinished one.', 'bettershield' ),
				'window'     => $until_setup_settles,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_totp_last_step'        => array(
				'what'       => __( 'The time step the last accepted code belonged to.', 'bettershield' ),
				'why'        => __( 'A code that has been used once is refused the second time, and this is what remembers which one it was.', 'bettershield' ),
				'window'     => $until_two_factor_off,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_backup_codes'          => array(
				'what'       => __( 'Hashes of the single-use backup codes issued with two-factor. The codes themselves are not stored.', 'bettershield' ),
				'why'        => __( 'A code typed at sign-in is checked against these, which is what makes a lost phone recoverable.', 'bettershield' ),
				'window'     => $until_two_factor_off,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_backup_codes_pending'  => array(
				'what'       => __( 'Hashes of the backup codes shown during a setup that is not finished.', 'bettershield' ),
				'why'        => __( 'The codes already on screen have to keep working once the setup is confirmed.', 'bettershield' ),
				'window'     => $until_setup_settles,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_2fa_park'              => array(
				'what'       => __( 'A hash naming a sign-in that is waiting on the second-factor screen.', 'bettershield' ),
				'why'        => __( 'It is how that screen finds the sign-in it belongs to, without the sign-in itself being stored where a hash could open it.', 'bettershield' ),
				'window'     => __( 'until that sign-in finishes, or the next one replaces it', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_2fa_required_since'    => array(
				'what'       => __( 'When a two-factor deadline started for this account on this site.', 'bettershield' ),
				'why'        => __( 'The clock starts when the policy first applies to the account, not when the account was made, so switching the policy on shuts nobody out the same day.', 'bettershield' ),
				'window'     => __( 'until two-factor is set up on the account', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_password_below_policy' => array(
				'what'       => __( 'That the password was below this site’s policy the last time it was seen.', 'bettershield' ),
				'why'        => __( 'It is what asks for a new one, and there is nowhere else to read it from, because a stored password cannot be measured again.', 'bettershield' ),
				'window'     => __( 'until the password is changed to one that meets the policy', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_sudo_until'            => array(
				'what'       => __( 'That the password was confirmed recently, and for which sign-in.', 'bettershield' ),
				'why'        => __( 'An action that takes a protection off asks once, and then not again for a short while.', 'bettershield' ),
				'window'     => __( 'until the confirmation lapses, a few minutes later', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_passkey_confirmed_until' => array(
				'what'       => __( 'That one of the account’s own passkeys confirmed it recently, and for which sign-in.', 'bettershield' ),
				'why'        => __( 'An account that signs in by passkey alone confirms it is its holder this way before its passkeys change, and is then not asked again for a short while.', 'bettershield' ),
				'window'     => __( 'until the confirmation lapses, a few minutes later', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_last_login'            => array(
				'what'         => __( 'The date this plugin last saw the account sign in.', 'bettershield' ),
				'why'          => __( 'It is the input to the check that finds accounts with real permissions nobody is using any more.', 'bettershield' ),
				'window'       => $until_account_gone,
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'An account that reads as never used is one nobody is ever asked to close, so the date stays and the answer to the request says it stayed.', 'bettershield' ),
			),
			'bettershield_release_seen'          => array(
				'what'       => __( 'Which version’s release panel this account has dismissed.', 'bettershield' ),
				'why'        => __( 'So a panel that has been read is not shown again.', 'bettershield' ),
				'window'     => $until_account_gone,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_app_password_limits'   => array(
				'what'         => __( 'The REST routes and the network each of this account’s application passwords is held to, where a limit was set.', 'bettershield' ),
				'why'          => __( 'So a request with one of those passwords outside its limit is refused.', 'bettershield' ),
				'window'       => __( 'Until the limit is removed or the password is revoked.', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'Erasing it would let the account’s application passwords reach everything again, from anywhere. It is a setting on a credential, and the answer to the request says it stayed.', 'bettershield' ),
			),
			// Core's own key for a pending address, which the email-change
			// fix also writes for changes made off the profile screen (#1856).
			'_new_email'                         => array(
				'what'       => __( 'A new email address for this account waiting for confirmation from that address.', 'bettershield' ),
				'why'        => __( 'So a change to where password resets go takes effect only once the new address confirms it.', 'bettershield' ),
				'window'     => __( 'Until the change is confirmed or canceled.', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_account_notice_queue'  => array(
				'what'       => __( 'Changes to how this account can be signed in to, with the time, a /24 or /64 network and the browser, waiting to be emailed to it.', 'bettershield' ),
				'why'        => __( 'So changes made within a few minutes reach the account holder as one email.', 'bettershield' ),
				'window'     => __( 'About ten minutes, until the email is sent.', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_last_overview_visit'   => array(
				'what'       => __( 'When this account last looked at the overview screen on this site.', 'bettershield' ),
				'why'        => __( 'It is what tells a return from a refresh, so the overview can say what changed since the last one.', 'bettershield' ),
				'window'     => $until_account_gone,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'bettershield_overview_visit_window' => array(
				'what'       => __( 'Which stretch of time the overview screen treats as new for the sitting in progress.', 'bettershield' ),
				'why'        => __( 'Held still while the screen is being read, or what changed empties on a refresh.', 'bettershield' ),
				'window'     => $until_account_gone,
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'session_tokens'                     => array(
				'what'         => __( 'The truncated network each open session was started from, and on a network which site it was started on and whether a passkey started it, written beside WordPress’s own record of that session.', 'bettershield' ),
				'why'          => __( 'The sessions screen says where a session came from, and this is how it says a network rather than the address WordPress keeps there. On a network, a site holds a session started on another site to its own sign-in rules.', 'bettershield' ),
				'window'       => __( 'until the session ends or the account is deleted', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'WordPress owns this record and removes it with the account. Taking it here would sign the person out of a site they still hold an account on.', 'bettershield' ),
			),
			'passkeys.user_id'                   => array(
				'what'       => __( 'Each passkey enrolled on the account: the name given to the device, when it was added, when it was last used, and the public half of the key.', 'bettershield' ),
				'why'        => __( 'A passkey cannot be checked at sign-in without it. Nothing secret is stored: the private half never leaves the device.', 'bettershield' ),
				'window'     => __( 'until the passkey is removed, or the account is deleted', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'undo.observed_change' => array(
				'what' => __( 'Opt-in recorded changes containing this email address or this account’s numeric reference, and any current site suspension.', 'bettershield' ),
				'why' => __( 'Keeps a reviewed response reversible after activity history expires.', 'bettershield' ),
				'window' => __( 'Until the site owner removes BetterShield with data removal enabled; activity retention does not prune undo records.', 'bettershield' ),
				'on_erasure' => self::ERASURE_KEPT,
				'kept_because' => self::observed_retention(),
			),
			'incident_evidence.actor_id' => array(
				'what' => __( 'Incident evidence where the account is a recorded actor or subject, with numeric identifiers and event times. No account names or source addresses are copied.', 'bettershield' ),
				'why' => __( 'Preserves the evidence behind an unresolved security investigation.', 'bettershield' ),
				'window' => __( 'Open incidents do not expire. Handled incident history follows the site’s retention window.', 'bettershield' ),
				'on_erasure' => self::ERASURE_KEPT,
				'kept_because' => __( 'Numeric account references and event evidence stay so a security investigation cannot be erased by the account involved.', 'bettershield' ),
			),
			'events.actor_id'                    => array(
				'what'         => __( 'The activity rows this account is the actor on: what happened, the name the account had at the time, and the network the request came from.', 'bettershield' ),
				'why'          => __( 'It is the record of what happened to the site.', 'bettershield' ),
				'window'       => self::retention_window(),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'The name and the network come off and the rows stay. A security log that can be emptied on request is one an intruder can empty, and the account asking is the account they would be holding.', 'bettershield' ),
			),
			'login_attempts.username'            => array(
				'what'       => __( 'Sign-in attempts made under this account’s username: when, how, the outcome, and the network.', 'bettershield' ),
				'why'        => __( 'It is what the lockout decision counts.', 'bettershield' ),
				'window'     => __( 'two days', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
			'lockouts.last_username'             => array(
				'what'         => __( 'The last username tried from an address that was locked out.', 'bettershield' ),
				'why'          => __( 'It is what the lockout screen and the unlock message say the lockout was about.', 'bettershield' ),
				'window'       => __( 'until thirty days after the lockout ends', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'A lockout is the record of an address being refused rather than of a person, and clearing it on request would let whoever is locked out end their own lockout.', 'bettershield' ),
			),
			'agent_invocations.user_id'          => array(
				'what'         => __( 'Which account an ability was run under, beside the ability’s name and how it ended. What it was asked is stored as a digest and never as itself.', 'bettershield' ),
				'why'          => __( 'An owner has to be able to see what an agent did on their site, and under whose permissions.', 'bettershield' ),
				'window'       => self::retention_window(),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'It is the record of what was done to the site through an ability, kept for the reason the activity rows are kept.', 'bettershield' ),
			),
			'write_proposals.proposed_by'        => array(
				'what'         => __( 'Changes an agent prepared under this account, and changes this account allowed once. The plan is kept as it was read; the confirmation itself is never stored.', 'bettershield' ),
				'why'          => __( 'A change made on somebody’s authority has to record whose, and this is that record.', 'bettershield' ),
				'window'       => __( 'seven days from the day the change was proposed', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'The proposals keep their plans and lose the people: what was asked for, what was allowed and what became of it stay, and who asked and who allowed comes off. A confirmation with nothing left of it would read as a change nobody ever permitted.', 'bettershield' ),
			),
			'mcp_pairing.user_id'                => array(
				'what'       => __( 'Which administrator minted the credential an assistant reaches this site with, when it was minted, and when it was last used. The credential itself is kept as a digest and the last four characters, and never as itself.', 'bettershield' ),
				'why'        => __( 'Every call an assistant makes runs as that account, so the record of whose permissions apply is the record of what the connection may do.', 'bettershield' ),
				'window'       => __( 'until the connection is ended or the credential is replaced', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'It is the record of an assistant being let in, and every call it makes runs as that account. Taking the name off would leave a live connection with nothing saying whose permissions it holds, and removing the connection would cut an assistant off as a side effect of a request that was not about it.', 'bettershield' ),
			),
			'mcp_oauth.user_id'                  => array(
				'what'         => __( 'Each application that was allowed to connect: the name it gave, which administrator approved it, when, and when it was last seen. Its tokens are kept as digests and never as themselves.', 'bettershield' ),
				'why'          => __( 'An owner has to be able to see which assistants can reach this site and on whose authority, and to cut one off.', 'bettershield' ),
				'window'       => __( 'until the application is revoked, or thirty days after it last refreshed its access', 'bettershield' ),
				'on_erasure'   => self::ERASURE_KEPT,
				'kept_because' => __( 'It is the record of access being granted to something that is not a person. Removing it on request would leave a live connection with nothing saying who allowed it, and the account asking is the account that allowed it.', 'bettershield' ),
			),
			'claims.claim_key'                   => array(
				'what'       => __( 'A mark saying this account has already been told about a sign-in from a network it has not used before.', 'bettershield' ),
				'why'        => __( 'One message a day, however many new networks a journey passes through.', 'bettershield' ),
				'window'     => __( 'one day', 'bettershield' ),
				'on_erasure' => self::ERASURE_REMOVED,
			),
		);
	}

	/**
	 * How long a row of the activity log is kept on disk, in words: the window it is read in, or the longer one the pruner is still holding to.
	 */
	private static function retention_window(): string {
		return sprintf(
			/* translators: %d: number of days the activity log is kept. */
			_n( '%d day from the day it was written', '%d days from the day it was written', Tier::kept_days(), 'bettershield' ),
			Tier::kept_days()
		);
	}

	/**
	 * The names one meta key from the ledger can be stored under here.
	 *
	 * The code that owns a site-scoped key adds the site's id on the way in;
	 * this is the same walk on the way back out.
	 *
	 * @return string[]
	 */
	private static function meta_key_variants( string $key ): array {
		$variants = array( $key );

		if ( is_multisite() && in_array( $key, self::site_scoped_meta(), true ) ) {
			$variants[] = $key . '_' . get_current_blog_id();
		}

		return $variants;
	}

	/**
	 * Which of the ledger's meta keys a network stores once per site.
	 *
	 * Held for the request rather than filtered afresh: the answer is read
	 * once per ledger key on every export and every erasure, and the list
	 * cannot change between two of those reads.
	 *
	 * @return string[]
	 */
	public static function site_scoped_meta(): array {
		if ( null !== self::$site_scoped_meta ) {
			return self::$site_scoped_meta;
		}

		/**
		 * The meta keys a network stores once per site, for an add-on that
		 * keeps a per-site record of its own. An entry is a user meta key as
		 * the add-on writes it on a single site; the site's id is appended to
		 * it on a network, here and wherever the add-on reads it back. An
		 * add-on that declares the scoped name instead is naming a key that
		 * exists on a network and nowhere else.
		 *
		 * @param string[] $keys Meta keys stored once per site.
		 */
		$keys  = (array) apply_filters( 'bettershield_personal_data_site_scoped_meta', self::SITE_SCOPED_META );
		$valid = array();

		foreach ( $keys as $key ) {
			// A key is a name, and anything else in this list would be asked
			// of the meta store as one.
			if ( is_string( $key ) && '' !== $key ) {
				$valid[] = $key;
			}
		}

		self::$site_scoped_meta = array_values( array_unique( $valid ) );

		return self::$site_scoped_meta;
	}

	/**
	 * How many rows one pass moves.
	 *
	 * Core calls these in a loop with a page number and stops when told there
	 * is no more, so this is a page size rather than a cap — an account with a
	 * long history is exported completely, a page at a time, and no single
	 * request pays for all of it.
	 */
	private const PER_PAGE = 250;

	public static function register(): void {
		add_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'exporters' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'erasers' ) );

		// Suggested text for the site's own privacy policy, at the place an
		// owner actually looks when they write one. Built from what this
		// plugin declares it keeps and which hosts it may contact, so the
		// paragraph cannot drift from the code the way hand-written copy does.
		add_action( 'admin_init', array( self::class, 'suggest_policy_text' ) );
	}

	/**
	 * What a site owner can paste into their privacy policy.
	 *
	 * A site running a security plugin processes personal data and, with some
	 * features switched on, contacts third parties. The owner is the one who
	 * has to describe that, and this plugin is the only party that knows
	 * exactly what it does — so the description is generated here rather than
	 * left to them to infer from a screen.
	 *
	 * Written in the present tense about what is actually on: a feature that
	 * is off contacts nobody, and saying otherwise would put a claim in
	 * somebody's policy that is not true of their site.
	 */
	public static function suggest_policy_text(): void {
		/*
		 * Nobody signed in, nobody to show it to: the admin-ajax.php and
		 * admin-post.php requests `admin_init` fires on without a session (a
		 * store's queue runner makes one about once a minute) read the
		 * options this text is built from for nothing. Only that: core
		 * compares the suggestions on every signed-in admin request, ajax
		 * included, and one that found this text missing would flag the
		 * policy as changed.
		 */
		if ( ! is_user_logged_in() ) {
			return;
		}

		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$sections = array(
			__( 'This site uses BetterShield to protect and audit itself. It records sign-in attempts and the lockouts that follow repeated failures, keeping the network an attempt came from truncated (the first three groups of an IPv4 address, the first four of an IPv6 one) instead of the address itself, together with the username that was tried.', 'bettershield' ),
			// How long the rows stay on disk, which is not a setting here, and a
			// policy has to state it.
			sprintf(
				/* translators: %d: how many days activity entries are kept. */
				_n(
					'It keeps an activity record of what changed on this site and who changed it: the account, the kind of change, and the truncated network. Entries are kept for %d day and removed after that.',
					'It keeps an activity record of what changed on this site and who changed it: the account, the kind of change, and the truncated network. Entries are kept for %d days and removed after that.',
					Tier::kept_days(),
					'bettershield'
				),
				Tier::kept_days()
			),
			__( 'Where two-factor sign-in or passkeys are in use, it stores what is needed to check them: a shared secret, a passkey’s public credential, and hashes of one-time backup codes. It never stores a password, a session token or a recovery code in a form that can be read back.', 'bettershield' ),
			__( 'Where an assistant is connected, it records which tool was called and when, with the arguments kept only as a keyed digest rather than as text.', 'bettershield' ),
			__( 'A person can ask for their data through this site’s existing privacy tools: the export includes what BetterShield holds about them, and the erase request removes their name and network from its records while keeping the entries themselves, because a security log is only useful if its entries cannot be removed on request.', 'bettershield' ),
		);

		$contacted = array(
			__( 'WordPress.org, to read the published checksums for this version of WordPress and of the plugins installed, so files can be compared with the copies their publishers shipped. Nothing about a visitor is sent.', 'bettershield' ),
		);

		if ( Manager::instance()->is_active( 'breached_passwords' ) ) {
			$contacted[] = __( 'The Pwned Passwords service, only while somebody is choosing a password, and only the first five characters of that password’s hash, which match several hundred published hashes, not one. The comparison happens on this site.', 'bettershield' );
		}

		// Only while sharing is on: a site that never said yes sends nothing,
		// and its policy must not say that it does.
		if ( Onboarding\Usage::is_allowed() ) {
			// On a network the answer is a super admin's, and the report is
			// the network's whichever site sends it.
			$contacted[] = is_multisite()
				? __( 'WPDeveloper’s usage service, because this network’s administrator chose to share usage data. At most once a day, and once more if BetterShield is deactivated, it receives a report about the network rather than this site: the network’s address and name, the network administrator’s email address, the WordPress, PHP and web server versions, the plugins installed and which of them are active, and the BetterShield version, with the language and active theme of whichever site sends it. Nothing about visitors or the people who use this site is in it. Privacy policy: https://wpdeveloper.com/privacy-policy', 'bettershield' )
				: __( 'WPDeveloper’s usage service, because this site’s owner chose to share usage data. At most once a day, and once more if BetterShield is deactivated, it receives a report with this site’s address and title, the administrator’s email address, the WordPress, PHP and web server versions, the site’s language, the plugins installed and which of them are active, the active theme, and the BetterShield version. Nothing about visitors or the people who use this site is in it. Privacy policy: https://wpdeveloper.com/privacy-policy', 'bettershield' );
		}

		/*
		 * Wherever WordPress's AI client is on, an explanation somebody asks
		 * for leaves for the provider connected to the site, if there is one.
		 * Whether one is connected is the providers' to answer, which is not
		 * a question for every admin page load; the sentence says "if".
		 */
		if ( function_exists( 'wp_supports_ai' ) && wp_supports_ai() ) {
			$contacted[] = __( 'The AI provider connected to this site under Settings › Connectors, if there is one, and only when somebody managing this site asks for an explanation: of one finding, of the open findings (up to twelve at once), or of an incident. It receives the recorded evidence that explanation is about, with web and email addresses stripped and the accounts and files in an incident named only as placeholders. It never receives file contents, usernames, keys or this site’s address.', 'bettershield' );
		}

		// Only while a hub holds a grant: it reads the activity record, which
		// names people, and a site that never connected must not say so.
		if ( array() !== Mcp\Hub::apps() ) {
			$contacted[] = __( 'BetterShield Hub, while this site is connected to it. The hub reads this site’s security score and findings and its activity record, which names the account behind each change and the truncated network it came from, and applies or undoes a protection when the site’s owner asks. Privacy policy: https://bettershield.ai/privacy', 'bettershield' );
		}

		/*
		 * The tutorial class marks guidance for the owner, and the Policy
		 * Guide's copy button leaves every element carrying it out of what it
		 * copies. This text is the suggestion itself, so only the lead-in
		 * wears it, the way core's own suggested text does: with it on every
		 * paragraph the button copied nothing and still said "Copied!".
		 */
		$content = '';
		$lead    = '<strong class="privacy-policy-tutorial">' . esc_html__( 'Suggested text:', 'bettershield' ) . ' </strong>';

		foreach ( $sections as $paragraph ) {
			$content .= '<p>' . $lead . esc_html( $paragraph ) . '</p>';
			$lead     = '';
		}

		$content .= '<p>' . esc_html__( 'Outside services this site contacts:', 'bettershield' ) . '</p><ul>';

		foreach ( $contacted as $service ) {
			$content .= '<li>' . esc_html( $service ) . '</li>';
		}

		$content .= '</ul>';

		wp_add_privacy_policy_content( 'BetterShield', wp_kses_post( $content ) );
	}

	/**
	 * @param array<string, mixed> $exporters
	 * @return array<string, mixed>
	 */
	public static function exporters( array $exporters ): array {
		$exporters[ self::GROUP ] = array(
			'exporter_friendly_name' => __( 'BetterShield', 'bettershield' ),
			'callback'               => array( self::class, 'export' ),
		);

		return $exporters;
	}

	/**
	 * @param array<string, mixed> $erasers
	 * @return array<string, mixed>
	 */
	public static function erasers( array $erasers ): array {
		$erasers[ self::GROUP ] = array(
			'eraser_friendly_name' => __( 'BetterShield', 'bettershield' ),
			'callback'             => array( self::class, 'erase' ),
		);

		return $erasers;
	}

	/**
	 * Everything this plugin holds about one person.
	 *
	 * Only what the account holder may already see on their own screens. The
	 * keyed digest of an address is never exported — it reverses to nothing
	 * and means nothing to the person asking, and handing it over would be
	 * publishing a value whose whole purpose is that it is not published. The
	 * truncated network is exported as the network it is, labeled as such, so
	 * nobody reads it as the address they signed in from.
	 *
	 * @return array{data: array<int, array<string, mixed>>, done: bool}
	 */
	public static function export( string $email, int $page = 1 ): array {
		$user = get_user_by( 'email', $email );
		$page = max( 1, $page );
		$observed = self::observed_personal( $email, $user instanceof \WP_User ? (int) $user->ID : 0, $page );

		if ( ! $user instanceof \WP_User ) {
			return $observed;
		}

		global $wpdb;

		$offset = ( $page - 1 ) * self::PER_PAGE;
		$items  = $observed['data'];
		$incident_rows = self::incident_rows( (int) $user->ID, self::PER_PAGE, $offset );
		foreach ( $incident_rows as $row ) {
			$items[] = array( 'group_id' => self::GROUP . '-incidents', 'group_label' => __( 'BetterShield incident evidence', 'bettershield' ), 'item_id' => self::GROUP . '-incident-evidence-' . (int) $row->id,
				'data' => array(
					array( 'name' => __( 'Incident', 'bettershield' ), 'value' => (string) $row->incident_id ),
					array( 'name' => __( 'When', 'bettershield' ), 'value' => (string) Time::utc_iso( $row->occurred_at ) ),
					array( 'name' => __( 'What happened', 'bettershield' ), 'value' => \BetterShield\Events\Types::label( $row->event_type ) ),
					array( 'name' => __( 'Account relationship', 'bettershield' ), 'value' => (int) $row->actor_id === (int) $user->ID ? __( 'Recorded actor', 'bettershield' ) : __( 'Recorded subject', 'bettershield' ) ),
				) );
		}


		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		// The rows they acted in, and the rows about their account: created,
		// deleted, its email changed, a reset asked for it. The second kind
		// carried their login and was in neither the export nor the erasure.
		$events = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, occurred_at, event_type, actor_id, actor_label, ip_prefix FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND ( actor_id = %d OR ' . self::SUBJECT_ROWS . ' ) ORDER BY id ASC LIMIT %d OFFSET %d',
				Schema::table( 'events' ),
				(int) $user->ID,
				(string) $user->ID,
				$user->user_login,
				self::PER_PAGE,
				$offset
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( (array) $events as $row ) {
			// A row about the account, made by somebody else: what happened to
			// it, and nothing of the person who did it.
			if ( (int) $row->actor_id !== (int) $user->ID ) {
				$items[] = array(
					'group_id'    => self::GROUP . '-activity',
					'group_label' => __( 'BetterShield activity', 'bettershield' ),
					'item_id'     => self::GROUP . '-event-' . (int) $row->id,
					'data'        => array(
						array( 'name' => __( 'When', 'bettershield' ), 'value' => (string) Time::utc_iso( (string) $row->occurred_at ) ),
						array( 'name' => __( 'What happened', 'bettershield' ), 'value' => Types::label( (string) $row->event_type ) ),
						array( 'name' => __( 'Account relationship', 'bettershield' ), 'value' => __( 'Recorded subject', 'bettershield' ) ),
					),
				);

				continue;
			}

			$items[] = array(
				'group_id'    => self::GROUP . '-activity',
				'group_label' => __( 'BetterShield activity', 'bettershield' ),
				'item_id'     => self::GROUP . '-event-' . (int) $row->id,
				'data'        => array(
					// Stored UTC without a zone marker; the file says so, or whoever
					// opens it reads the value as their own local time.
					array( 'name' => __( 'When', 'bettershield' ), 'value' => (string) Time::utc_iso( (string) $row->occurred_at ) ),
					array( 'name' => __( 'What happened', 'bettershield' ), 'value' => Types::label( (string) $row->event_type ) ),
					array( 'name' => __( 'Recorded as', 'bettershield' ), 'value' => (string) $row->actor_label ),
					array( 'name' => __( 'Network', 'bettershield' ), 'value' => self::network( $row->ip_prefix ) ),
				),
			);
		}

		// What is small and bounded per account travels on the first page
		// rather than being paged for no reason.
		if ( 1 === $page ) {
			/*
			 * What this plugin holds about the account itself. Whether a second
			 * factor is on, and when it last saw them sign in — the second is
			 * also the one record an erasure keeps, so an export that left it
			 * out would be silent about the very thing there is most to say.
			 */
			$enrollment = TwoFactor\Manager::instance()->status( (int) $user->ID );

			$items[] = array(
				'group_id'    => self::GROUP . '-account',
				'group_label' => __( 'BetterShield account', 'bettershield' ),
				'item_id'     => self::GROUP . '-account',
				'data'        => array(
					array( 'name' => __( 'Last signed in', 'bettershield' ), 'value' => self::sign_in_time( get_user_meta( (int) $user->ID, Dormant::META, true ) ) ),
					array( 'name' => __( 'Two-factor', 'bettershield' ), 'value' => self::enrollment_label( $enrollment ) ),
				),
			);

			/*
			 * And the networks their open sessions are on. Kept inside core's
			 * own session record rather than in a table here, and written there
			 * by this plugin, which makes it a thing this plugin holds. The
			 * session's own token identifies nothing in the export: an item id
			 * is a position in a list, never a credential, however truncated.
			 */
			$sessions = get_user_meta( (int) $user->ID, 'session_tokens', true );
			$position = 0;

			foreach ( ( is_array( $sessions ) ? $sessions : array() ) as $session ) {
				if ( ! is_array( $session ) ) {
					continue;
				}

				++$position;

				$items[] = array(
					'group_id'    => self::GROUP . '-sessions',
					'group_label' => __( 'BetterShield sessions', 'bettershield' ),
					'item_id'     => self::GROUP . '-session-' . $position,
					'data'        => array(
						array( 'name' => __( 'Signed in', 'bettershield' ), 'value' => self::sign_in_time( $session['login'] ?? null ) ),
						array( 'name' => __( 'Network', 'bettershield' ), 'value' => Sessions::network_label( $session ) ),
					),
				);
			}

			/*
			 * Not narrowed to one site, and that is the answer rather than an
			 * omission: a passkey is bound to a host, so on a network it is
			 * the person's credential everywhere under that host. The group
			 * label below says so, so nobody reading the export has to work
			 * out why there are more here than this site enrolled.
			 */
			$verification = Schema::ready( 'passkey_verification' ) ? 'user_verified' : 'NULL AS user_verified';
			// phpcs:disable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $verification is one of two closed SQL literals; no request input reaches it.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, no core API.
			$passkeys = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT id, label, created_at, last_used_at, ' . $verification . ' FROM %i WHERE user_id = %d ORDER BY id ASC',
					Schema::table( 'passkeys' ),
					(int) $user->ID
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

			foreach ( (array) $passkeys as $row ) {
				$items[] = array(
					'group_id'    => self::GROUP . '-passkeys',
					'group_label' => self::passkeys_group_label(),
					'item_id'     => self::GROUP . '-passkey-' . (int) $row->id,
					'data'        => array(
						array( 'name' => __( 'Name', 'bettershield' ), 'value' => (string) $row->label ),
						array( 'name' => __( 'Added', 'bettershield' ), 'value' => (string) Time::utc_iso( (string) $row->created_at ) ),
						array( 'name' => __( 'Last used', 'bettershield' ), 'value' => (string) Time::utc_iso( null === $row->last_used_at ? null : (string) $row->last_used_at ) ),
						array( 'name' => __( 'Verified its holder', 'bettershield' ), 'value' => null === $row->user_verified ? __( 'Unknown', 'bettershield' ) : ( (int) $row->user_verified ? __( 'Yes', 'bettershield' ) : __( 'Not yet', 'bettershield' ) ) ),
					),
				);
			}

		}

		/*
		 * Paged alongside the activity log rather than capped on the first
		 * page. These are the brute-force record: they grow with attack traffic
		 * rather than with the account, so six attempts an hour fills a page
		 * inside the two days they are kept for — and an export that stops
		 * there while the readme promises all of it is a silent truncation.
		 */
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$attempts = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, occurred_at, outcome, method, ip_prefix FROM %i WHERE ' . Schema::site_where( 'login_attempts' ) . ' AND username = %s ORDER BY id ASC LIMIT %d OFFSET %d',
				Schema::table( 'login_attempts' ),
				$user->user_login,
				self::PER_PAGE,
				$offset
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		foreach ( (array) $attempts as $row ) {
			$items[] = array(
				'group_id'    => self::GROUP . '-sign-ins',
				'group_label' => __( 'BetterShield sign-in attempts', 'bettershield' ),
				'item_id'     => self::GROUP . '-attempt-' . (int) $row->id,
				'data'        => array(
					array( 'name' => __( 'When', 'bettershield' ), 'value' => (string) Time::utc_iso( (string) $row->occurred_at ) ),
					array( 'name' => __( 'Outcome', 'bettershield' ), 'value' => (string) $row->outcome ),
					array( 'name' => __( 'How', 'bettershield' ), 'value' => (string) $row->method ),
					array( 'name' => __( 'Network', 'bettershield' ), 'value' => self::network( $row->ip_prefix ) ),
				),
			);
		}

		/*
		 * And the terms the rest of the export arrives under: every kind of
		 * record this plugin keeps about a person that this account actually
		 * has, each with why it is held, how long, and what an erasure does to
		 * it. Without it the person is handed the records and none of the
		 * terms, and has to ask the owner for the half that is not in the file.
		 *
		 * On the first page with the other account facts: it is one short list
		 * per account rather than something that grows with anything.
		 */
		if ( 1 === $page ) {
			$held = array(
				'events.actor_id'           => array() !== (array) $events,
				'undo.observed_change' => array() !== $observed['data'],
				'incident_evidence.actor_id' => array() !== $incident_rows,
				'passkeys.user_id'          => array() !== (array) $passkeys,
				'login_attempts.username'   => array() !== (array) $attempts,
				'lockouts.last_username'    => self::row_exists( 'lockouts', 'last_username', $user->user_login ),
				'agent_invocations.user_id' => self::row_exists( 'agent_invocations', 'user_id', (string) (int) $user->ID ),
				'write_proposals.proposed_by' => self::proposal_rows_exist( (int) $user->ID ),
				'claims.claim_key'          => Claim::held( 'newloc_' . (int) $user->ID ),
				'mcp_pairing.user_id'       => Mcp\Pairing::is_connected() && (int) $user->ID === Mcp\Pairing::user_id(),
				'mcp_oauth.user_id'         => self::approved_an_application( (int) $user->ID ),
			);

			foreach ( self::records() as $key => $record ) {
				if ( ! self::holds_record( (int) $user->ID, (string) $key, $record, $held ) ) {
					continue;
				}

				$items[] = array(
					'group_id'    => self::GROUP . '-what-is-kept',
					'group_label' => __( 'What BetterShield keeps about you', 'bettershield' ),
					'item_id'     => self::GROUP . '-kept-' . str_replace( array( '.', '_' ), '-', $key ),
					'data'        => array(
						array( 'name' => __( 'Record', 'bettershield' ), 'value' => (string) $record['what'] ),
						array( 'name' => __( 'Why it is kept', 'bettershield' ), 'value' => (string) $record['why'] ),
						array( 'name' => __( 'How long', 'bettershield' ), 'value' => (string) $record['window'] ),
						array( 'name' => __( 'If you ask for it to be erased', 'bettershield' ), 'value' => self::erasure_label( $record ) ),
					),
				);
			}
		}

		return array(
			'data' => $items,
			// Two of the three page, so this is done when both come back short.
			// The account facts and the passkeys travel on the first page: they
			// are small and bounded per account, which sign-in attempts are not.
			'done' => $observed['done'] && count( (array) $events ) < self::PER_PAGE && count( (array) $attempts ) < self::PER_PAGE && count( $incident_rows ) < self::PER_PAGE,
		);
	}

	/**
	 * The four per-person keys a network wrote before they were scoped to the
	 * site that wrote them.
	 *
	 * Each is written today as the key plus the blog id, and the code that
	 * owns it forgets it under that name. A network that has been running
	 * since before the suffix existed still holds the plain form, which no
	 * owner would ever be asked about again and which nothing above removes —
	 * so an erasure reported success while four records about the person
	 * stayed. On a single site the plain form is the current form and the
	 * owners above have already taken it.
	 *
	 * @var string[]
	 */
	private const LEGACY_UNSCOPED_META = array(
		'bettershield_2fa_park',
		'bettershield_2fa_required_since',
		'bettershield_last_overview_visit',
		'bettershield_overview_visit_window',
	);

	/**
	 * Remove what a network wrote before these keys named the site.
	 */
	private static function forget_unscoped_keys( int $user_id ): void {
		if ( ! is_multisite() ) {
			return;
		}

		foreach ( self::LEGACY_UNSCOPED_META as $key ) {
			delete_user_meta( $user_id, $key );
		}
	}

	/**
	 * What the passkeys group is called, and on a network what it covers.
	 *
	 * A credential is bound to a host rather than to a site, so on a network
	 * the export carries every one the account holds under that host. Saying
	 * it in the group name is the only place the person reading the file will
	 * meet it.
	 */
	private static function passkeys_group_label(): string {
		return is_multisite()
			? __( 'BetterShield passkeys (every site on this network)', 'bettershield' )
			: __( 'BetterShield passkeys', 'bettershield' );
	}

	/**
	 * Take the person out of what this plugin holds, and keep the record.
	 *
	 * The passkey goes: it is a credential belonging to one account, nobody
	 * else's security depends on it existing, and leaving it would leave a way
	 * in for an account somebody has asked to be forgotten.
	 *
	 * The activity rows stay and are anonymized. They are the record of what
	 * happened to the site, and the account that asks for them to go is the
	 * same account an intruder would be holding. Both parts are reported: what
	 * was removed, what was kept, and why — the owner has to be able to say
	 * that to the person who asked.
	 *
	 * @return array{items_removed: bool, items_retained: bool, messages: string[], done: bool}
	 */
	public static function erase( string $email, int $page = 1 ): array {
		$user = get_user_by( 'email', $email );
		$observed = self::observed_personal( $email, $user instanceof \WP_User ? (int) $user->ID : 0, max( 1, $page ) );

		if ( ! $user instanceof \WP_User ) {
			return array( 'items_removed' => false, 'items_retained' => (bool) $observed['data'], 'messages' => $observed['data'] ? array( self::observed_retention() ) : array(), 'done' => $observed['done'] );
		}

		global $wpdb;

		$removed  = 0;
		$retained = 0;

		$held_before = self::records_held( (int) $user->ID );

		/*
		 * A page at a time, because core already offers the contract: it calls
		 * this in a loop and stops when told the work is finished. An account
		 * with a long tail of attempts is erased completely, and no single
		 * request holds row locks over all of it while the buffered writer is
		 * trying to write.
		 */
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, no core API.
		$passkeys = (int) $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE user_id = %d ORDER BY id ASC LIMIT %d',
				Schema::table( 'passkeys' ),
				(int) $user->ID,
				self::PER_PAGE
			)
		);

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$attempts = (int) $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE ' . Schema::site_where( 'login_attempts' ) . ' AND username = %s ORDER BY id ASC LIMIT %d',
				Schema::table( 'login_attempts' ),
				$user->user_login,
				self::PER_PAGE
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$removed += $passkeys + $attempts;

		/*
		 * The name and the network go; the row and what it says happened stay.
		 * `actor_id` is kept because it is already an identifier core will
		 * remove with the account itself, and because a log that cannot tell
		 * two anonymized people apart is not a log any more.
		 *
		 * The last clause is what makes a re-run cheap: a row already
		 * anonymized is not matched again, so the pass that finds none is the
		 * pass that says the work is done. It asks what is left to clear
		 * rather than whether the name is blank, because a writer that names
		 * the person by id alone leaves the label NULL — which is never
		 * `<> ''` — while the row still carries their network.
		 */
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		// The days of the page about to be rewritten, read with the same
		// order and bound as the rewrite, so the reseal takes again only those
		// days and seals nobody else's edit to another day as genuine.
		$rewritten_days = (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT DISTINCT DATE(occurred_at) FROM ( SELECT occurred_at FROM %i WHERE ' . Schema::site_where( 'events' ) . ' AND actor_id = %d AND ( actor_label <> %s OR ip_prefix IS NOT NULL ) ORDER BY id ASC LIMIT %d ) AS page',
				Schema::table( 'events' ),
				(int) $user->ID,
				'',
				self::PER_PAGE
			)
		);

		/*
		 * And the rows that name the person as what was acted on rather than
		 * who acted: their account created, deleted, removed from a site or
		 * its email changed, with the login in the row's context, and a reset
		 * asked for it, with the login as the row's object. The login comes
		 * off those too, and their id stays, as `actor_id` does above. Read
		 * before anything is rewritten, so their days join the reseal.
		 */
		$subject = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, occurred_at, event_type, object_id, context FROM %i WHERE ' . Schema::site_where( 'events' ) . " AND object_type = 'user' AND ( ( object_id = %s AND context LIKE %s ) OR ( event_type IN ( 'password_reset_requested', 'login_failed' ) AND object_id = %s ) ) ORDER BY id ASC LIMIT %d",
				Schema::table( 'events' ),
				(string) $user->ID,
				'%' . $wpdb->esc_like( '"login":' ) . '%',
				$user->user_login,
				self::PER_PAGE
			)
		);

		foreach ( $subject as $row ) {
			$rewritten_days[] = substr( (string) $row->occurred_at, 0, 10 );
		}

		$rewritten_days = array_values( array_unique( array_map( 'strval', $rewritten_days ) ) );

		// Asked before the rewrite, while the answer is still about somebody
		// else: a day that already fails its seal is not taken again with it.
		$failing_days = class_exists( Seal::class ) ? Seal::failing_days( array_map( 'strval', $rewritten_days ) ) : array();

		$anonymized = (int) $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET actor_label = %s, ip_prefix = NULL WHERE ' . Schema::site_where( 'events' ) . ' AND actor_id = %d AND ( actor_label <> %s OR ip_prefix IS NOT NULL ) ORDER BY id ASC LIMIT %d',
				Schema::table( 'events' ),
				'',
				(int) $user->ID,
				'',
				self::PER_PAGE
			)
		);

		foreach ( $subject as $row ) {
			$context = json_decode( (string) $row->context, true );
			$context = is_array( $context ) ? $context : array();
			unset( $context['login'] );

			$by_login = in_array( (string) $row->event_type, self::LOGIN_NAMED, true );
			$fields   = array(
				'context'   => array() === $context ? null : wp_json_encode( $context ),
				'object_id' => $by_login ? (string) $user->ID : (string) $row->object_id,
			);

			// A row that named the person by their login keeps no network
			// either: the answer says both came off (#1821).
			if ( $by_login ) {
				$fields['ip_prefix'] = null;
			}

			$wpdb->update(
				Schema::table( 'events' ),
				$fields,
				array( 'id' => (int) $row->id ),
				// Core types `object_id` as a number, which would turn the id
				// kept in this text column into 0.
				$by_login ? array( '%s', '%s', '%s' ) : array( '%s', '%s' ),
				array( '%d' )
			);
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		$anonymized += count( $subject );
		$retained   += $anonymized;

		/*
		 * The proposals keep their plans and lose the people. The row is the
		 * audit of a confirmation — what was asked for, what was allowed, what
		 * became of it — and that survives; who asked and who allowed is what
		 * is about a person, and it comes off. Anonymizing rather than
		 * deleting, because a confirmation with nothing left of it would read
		 * as a change nobody ever permitted.
		 *
		 * Counted as retained, which is what it is: the row survives with its
		 * plan, its target, its outcome and its undo token. Counted as a
		 * removal, the answer handed to the person told them a record had gone
		 * that is still there.
		 */
		$proposals = self::anonymize_proposals( (int) $user->ID );

		$retained += $proposals;

		/*
		 * The second factor goes with the passkey, for the reason the passkey
		 * goes: a shared secret and a set of backup codes are a way in to the
		 * account somebody has asked to be forgotten, and an erasure that
		 * reports success while leaving them behind has taken the sign down and
		 * left the door. Only when there is something to take, so an account
		 * that never had one is not signed out and the log is not told a factor
		 * came off that was never on.
		 */
		$enrollment = TwoFactor\Manager::instance()->status( (int) $user->ID );

		if ( $enrollment['enabled'] || $enrollment['pending'] ) {
			TwoFactor\Manager::instance()->disable_for( (int) $user->ID, 'personal_data_erased' );
		}

		/*
		 * And the rest of what is kept about the person rather than about the
		 * site: a standing elevation on their account, a stored judgment about
		 * their password, the clock this site started against them, where they
		 * had read up to, and the mark saying they were already told about a
		 * sign-in from somewhere new. Each is forgotten by the code that owns it, so
		 * the multisite-scoped keys are scoped the same way here as they are
		 * written.
		 */
		Rest\Sudo::forget( (int) $user->ID );
		Password\Policy::forget_everywhere( (int) $user->ID );
		TwoFactor\Policy::forget( (int) $user->ID );
		Events\SinceLastVisit::forget( (int) $user->ID );
		Onboarding\Release::forget( (int) $user->ID );
		Claim::release( 'newloc_' . (int) $user->ID );
		// A pending address is a record about the person, and asked to be
		// forgotten, the change it would make is not made.
		delete_user_meta( (int) $user->ID, '_new_email' );
		Alerts\AccountNotices::forget( (int) $user->ID );
		self::forget_unscoped_keys( (int) $user->ID );

		$held_after = self::records_held( (int) $user->ID );

		$removed  += count( array_diff( $held_before, $held_after ) );
		$kept      = array_values( array_intersect( $held_before, $held_after ) );
		$retained += count( $kept );

		$messages = array();
		if ( $observed['data'] ) { ++$retained; $messages[] = self::observed_retention(); }
		if ( array() !== self::incident_rows( (int) $user->ID, 1, 0 ) ) {
			++$retained;
			$messages[] = __( 'BetterShield retained incident evidence and numeric account references for the security record. Incident evidence contains no account names or source addresses. Open incidents do not expire; handled history follows retention.', 'bettershield' );
		}


		/*
		 * Each record that stayed, named with its own reason from the ledger.
		 * This was one fixed sentence about the last sign-in, ending "and
		 * nothing else", printed whenever anything at all was kept — while
		 * the limits on the account's application passwords stayed as well.
		 */
		$records = self::records();

		foreach ( $kept as $key ) {
			$messages[] = self::kept_message( $key, $records[ $key ] ?? $records[ (string) preg_replace( '/_\d+$/', '', $key ) ] ?? array() );
		}

		/*
		 * And the network written beside each open session, which lives inside
		 * WordPress's own record of the sessions rather than under a key of
		 * this plugin's, so the count above cannot see it.
		 */
		if ( self::sessions_carry_network( (int) $user->ID ) ) {
			++$retained;
			$messages[] = self::kept_message( 'session_tokens', $records['session_tokens'] ?? array() );
		}

		if ( $anonymized > 0 ) {
			$messages[] = sprintf(
				/* translators: %d: number of days the activity log is kept. */
				_n(
					'BetterShield removed the name and network from this person’s activity rows and kept the rows themselves. The activity log is the record of what happened to this site, including anything done while an account was in somebody else’s hands, so it is kept for %d day from the day it was written and no longer.',
					'BetterShield removed the name and network from this person’s activity rows and kept the rows themselves. The activity log is the record of what happened to this site, including anything done while an account was in somebody else’s hands, so it is kept for %d days from the day it was written and no longer.',
					Tier::kept_days(),
					'bettershield'
				),
				Tier::kept_days()
			);
		}

		if ( $removed > 0 ) {
			Writer::instance()->record(
				'setting_changed',
				Writer::SEVERITY_MEDIUM,
				array(
					'actor_type'  => 'system',
					'object_type' => 'user',
					'object_id'   => (string) (int) $user->ID,
					'context'     => array( 'reason' => 'personal_data_erased' ),
				)
			);
		}

		// A page that filled up is not the end of the work. Core loops on
		// this, so nothing here needs a scheduler of its own.
		$done = $observed['done'] && $passkeys < self::PER_PAGE && $attempts < self::PER_PAGE && $anonymized - count( $subject ) < self::PER_PAGE && count( $subject ) < self::PER_PAGE && $proposals < self::PER_PAGE;

		/*
		 * The seal answers one question — has anything in the retained window
		 * been altered since it was written — and it covers the two columns
		 * this erasure rewrites. An authorized erasure is indistinguishable
		 * from tampering to a digest taken before it, so without this the
		 * ordinary handling of a privacy request opened a high-severity
		 * finding about the log, on every sealed day the person appeared in,
		 * which nothing could clear. Taken again over the rows as they now
		 * stand, the seal goes on answering truthfully about everything that
		 * happens after it.
		 *
		 * On the page that rewrote rows, rather than on the page that
		 * finishes the work. `$anonymized` counts one page and `$done`
		 * requires that page to be short, so the two are true together only
		 * when the last page rewrote something — and a person with exactly
		 * 250 anonymizable rows, or 500, or 750, fills a page, loops, and
		 * finishes on a page that finds nothing left. Their rows were
		 * rewritten and their day's digest left stale: the uncleanable
		 * high-severity log-seal finding this reseal exists to prevent, at
		 * the one count that hides it.
		 *
		 * Resealing per page costs a repeat of one query per sealed day on
		 * the erasures that run to more than one page, and the days do not
		 * change between them — `reseal_site()` recomputes the same digest
		 * from the same rows. That is the cheaper mistake to make: the other
		 * one leaves a finding on the log that nothing can clear.
		 */
		if ( $anonymized > 0 && class_exists( Seal::class ) ) {
			Seal::reseal_site( array_map( 'strval', $rewritten_days ), $failing_days, 'erasure' );
		}

		return array(
			'items_removed'  => $removed > 0,
			'items_retained' => $retained > 0,
			'messages'       => $messages,
			'done'           => $done,
		);
	}

	/**
	 * One record an erasure kept, said for the person who asked: what it is,
	 * and why it stayed.
	 *
	 * @param array<string, mixed> $record The ledger's entry, or nothing for a key it does not declare.
	 */
	private static function kept_message( string $key, array $record ): string {
		if ( ! isset( $record['what'], $record['kept_because'] ) ) {
			return sprintf(
				/* translators: %s: the name a record is stored under. */
				__( 'BetterShield kept a record about this account stored as %s.', 'bettershield' ),
				$key
			);
		}

		return sprintf(
			/* translators: 1: what the record is, 2: why it is kept when somebody asks to be forgotten. */
			__( 'BetterShield kept this: %1$s %2$s', 'bettershield' ),
			(string) $record['what'],
			(string) $record['kept_because']
		);
	}

	/**
	 * Whether any of the account's sessions carries the network this plugin
	 * writes beside it. The field's name is written out: the constant that
	 * owns it is private to the sessions class.
	 */
	private static function sessions_carry_network( int $user_id ): bool {
		$sessions = get_user_meta( $user_id, 'session_tokens', true );

		foreach ( is_array( $sessions ) ? $sessions : array() as $session ) {
			if ( is_array( $session ) && ! empty( $session['bettershield_network'] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * What an erasure does to one record, as a sentence for the person asking.
	 *
	 * @param array<string, string> $record
	 */
	private static function erasure_label( array $record ): string {
		if ( self::ERASURE_KEPT !== ( $record['on_erasure'] ?? '' ) ) {
			return __( 'It is removed.', 'bettershield' );
		}

		return sprintf(
			/* translators: %s: the reason this record is kept when somebody asks to be forgotten. */
			__( 'It is kept, and the answer to the request says so. %s', 'bettershield' ),
			(string) ( $record['kept_because'] ?? '' )
		);
	}

	/**
	 * Whether this account holds one of the ledger's records.
	 *
	 * Three answers in order: what this export already read, then a `held`
	 * callable the entry carries, then the meta store. The middle one is what
	 * makes the filter's `table.column` half work — an add-on has no way into
	 * the map above, and without it a declaration was accepted and the entry
	 * then printed for nobody.
	 *
	 * @param array<string, mixed> $record
	 * @param array<string, bool>  $known  Answers this export already has in hand.
	 */
	private static function holds_record( int $user_id, string $key, array $record, array $known ): bool {
		if ( isset( $known[ $key ] ) ) {
			return (bool) $known[ $key ];
		}

		if ( isset( $record['held'] ) && is_callable( $record['held'] ) ) {
			return (bool) call_user_func( $record['held'], $user_id );
		}

		return self::holds_meta( $user_id, $key );
	}

	/**
	 * Whether an assistant reaches this site on this account's authority.
	 *
	 * Read from the listing the connections screen reads, so the export and
	 * the screen cannot disagree about who approved what.
	 */
	private static function approved_an_application( int $user_id ): bool {
		foreach ( Mcp\OAuth::connected_apps() as $app ) {
			if ( $user_id === (int) $app['granted_by'] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether this account holds one of the ledger's meta records.
	 *
	 * Existence rather than a value: a key stored empty is still a key stored
	 * about the person, and an export that skipped it would be describing a
	 * record it holds as one it does not.
	 */
	private static function holds_meta( int $user_id, string $key ): bool {
		foreach ( self::meta_key_variants( $key ) as $variant ) {
			if ( metadata_exists( 'user', $user_id, $variant ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether one of this plugin's tables holds a row against a person.
	 *
	 * Asked only for the tables the export does not already read, and asked as
	 * an existence question — `LIMIT 1` rather than a count, because the answer
	 * is whether the ledger's entry applies and never how many.
	 */

	private static function observed_retention(): string {
		return __( 'BetterShield retained opt-in previous values and numeric account references needed to undo a reviewed response. This can include an administrative email address. Suspension state also remains so erasure cannot silently restore access. These local records outlive activity retention and are removed by an uninstall with data removal enabled.', 'bettershield' );
	}

	/** Paged only through the bounded observed-change key; never exports another address or an undo token. */
	private static function observed_personal( string $email, int $id, int $page ): array {
		if ( ! Schema::ready( 'observed_changes' ) ) { return array( 'data' => array(), 'done' => true ); }
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- site-local plugin ledger; index bounds the scan to opt-in captures.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT id,created_at,created_by,prior_state,applied_state FROM %i WHERE action_key=%s ORDER BY id ASC LIMIT %d OFFSET %d', Schema::table( 'undo' ), \BetterShield\Remediation\Observed::KEY, self::PER_PAGE, ( $page - 1 ) * self::PER_PAGE ) );
		if ( '' !== $wpdb->last_error ) { throw new \RuntimeException( 'BetterShield could not read retained change records. Retry the privacy request.' ); }
		$data = array();
		foreach ( $rows as $row ) {
			$r = json_decode( $row->prior_state, true ); $receipt = json_decode( $row->applied_state, true );
			$address = 'option' === ( $r['kind'] ?? '' ) && 'admin_email' === ( $r['target'] ?? '' ) && ( 0 === strcasecmp( $email, (string) $r['before'] ) || 0 === strcasecmp( $email, (string) $r['after'] ) );
			$account = $id > 0 && 'account' === ( $r['kind'] ?? '' ) && $id === (int) $r['target'];
			$actor = $id > 0 && $id === (int) $row->created_by;
			if ( ! $address && ! $account && ! $actor ) { continue; }
			$values = array( array( 'name' => __( 'When', 'bettershield' ), 'value' => (string) Time::utc_iso( $row->created_at ) ), array( 'name' => __( 'Response state', 'bettershield' ), 'value' => $receipt['phase'] ?? 'ready' ), array( 'name' => __( 'Retention', 'bettershield' ), 'value' => self::observed_retention() ) );
			if ( $address ) { $values[] = array( 'name' => __( 'Recorded administrative email', 'bettershield' ), 'value' => $email ); }
			if ( $account ) { $values[] = array( 'name' => __( 'Account reference', 'bettershield' ), 'value' => (string) $id ); $values[] = array( 'name' => __( 'Recorded capabilities', 'bettershield' ), 'value' => (string) wp_json_encode( $r['caps'] ) ); }
			if ( $actor ) { $values[] = array( 'name' => __( 'Account relationship', 'bettershield' ), 'value' => __( 'Recorded actor', 'bettershield' ) ); }
			$data[] = array( 'group_id' => self::GROUP . '-observed-changes', 'group_label' => __( 'BetterShield recorded changes', 'bettershield' ), 'item_id' => self::GROUP . '-observed-' . (int) $row->id, 'data' => $values );
		}
		if ( 1 === $page && $id > 0 && \BetterShield\Remediation\Suspension::has( $id ) ) {
			$data[] = array( 'group_id' => self::GROUP . '-observed-changes', 'group_label' => __( 'BetterShield recorded changes', 'bettershield' ), 'item_id' => self::GROUP . '-suspension-' . $id, 'data' => array( array( 'name' => __( 'Site access suspension', 'bettershield' ), 'value' => \BetterShield\Remediation\Suspension::blocks( $id ) ? __( 'Active', 'bettershield' ) : __( 'Paused by recovery or an account guard', 'bettershield' ) ) ) );
		}
		return array( 'data' => $data, 'done' => count( $rows ) < self::PER_PAGE );
	}

	private static function incident_rows( int $user_id, int $limit, int $offset ): array {
		if ( ! Schema::ready( 'incident_evidence' ) ) { return array(); }
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- current site's table only, bounded personal-data export.
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT id, incident_id, occurred_at, actor_id, event_type FROM %i WHERE actor_id=%d OR subject_key=%s ORDER BY id ASC LIMIT %d OFFSET %d', Schema::table( 'incident_evidence' ), $user_id, hash( 'sha256', 'user:' . $user_id ), $limit, $offset ) );
	}

	/**
	 * Whether this account appears on a write proposal, either side.
	 *
	 * Its own reader rather than `row_exists()`: that one narrows by the site
	 * column every shared table carries, and this table is one site's own and
	 * has none.
	 */
	private static function proposal_rows_exist( int $user_id ): bool {
		if ( ! Schema::ready( 'write_proposals' ) ) {
			return false;
		}

		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, no core API.
		$found = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT 1 FROM %i WHERE proposed_by = %d OR minted_by = %d LIMIT 1',
				Schema::table( 'write_proposals' ),
				$user_id,
				$user_id
			)
		);

		return null !== $found;
	}

	/**
	 * Take the account references off this person's proposals, a page at a
	 * time, and say how many rows changed.
	 */
	private static function anonymize_proposals( int $user_id ): int {
		if ( $user_id <= 0 || ! Schema::ready( 'write_proposals' ) ) {
			return 0;
		}

		global $wpdb;

		/*
		 * One statement per column, each clearing only the column that names
		 * the person who asked. Matched on either and cleared on both, an
		 * erasure took the administrator who allowed a change off a record
		 * whose whole point is saying who allowed it — on somebody else's
		 * request, and without either of them being told.
		 */
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, no core API.
		$proposed = (int) $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET proposed_by = 0 WHERE proposed_by = %d LIMIT %d',
				Schema::table( 'write_proposals' ),
				$user_id,
				self::PER_PAGE
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned table, no core API.
		$minted = (int) $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET minted_by = NULL WHERE minted_by = %d LIMIT %d',
				Schema::table( 'write_proposals' ),
				$user_id,
				self::PER_PAGE
			)
		);

		// Summed so the paging contract still terminates: a pass that changed
		// nothing is the pass that says the work is done.
		return $proposed + $minted;
	}

	private static function row_exists( string $table, string $column, string $value ): bool {
		if ( ! Schema::ready( $table ) ) {
			return false;
		}

		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin-owned table, no core API; the site predicate is integers assembled by Schema::site_where(), and nothing from a request reaches the string.
		$found = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT 1 FROM %i WHERE ' . Schema::site_where( $table ) . ' AND %i = %s LIMIT 1',
				Schema::table( $table ),
				$column,
				$value
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		return null !== $found;
	}

	/**
	 * Where an account stands with the second factor, in a word.
	 *
	 * @param array{enabled: bool, pending: bool, confirmed: bool, backup_remaining: int} $enrollment
	 */
	private static function enrollment_label( array $enrollment ): string {
		if ( $enrollment['enabled'] ) {
			return __( 'On', 'bettershield' );
		}

		return $enrollment['pending'] ? __( 'Being set up', 'bettershield' ) : __( 'Off', 'bettershield' );
	}

	/**
	 * Which of this plugin's per-person records one account currently holds.
	 *
	 * Read by prefix rather than from a list, so a record added later is
	 * counted without anybody remembering to name it twice: the erasure either
	 * takes it, or the declaration at the top of this class has to say why it
	 * stayed, and a test holds that against the uninstall script's census.
	 *
	 * @return string[]
	 */
	private static function records_held( int $user_id ): array {
		$all = get_user_meta( $user_id );

		if ( ! is_array( $all ) ) {
			return array();
		}

		$held = array();

		foreach ( array_keys( $all ) as $key ) {
			if ( str_starts_with( (string) $key, self::GROUP . '_' ) ) {
				$held[] = (string) $key;
			}
		}

		return $held;
	}

	/**
	 * A stored prefix as the network it is.
	 *
	 * Never rendered as an address: what is kept is the first part of one, and
	 * printing it bare would have somebody read a truncated value as the place
	 * a person signed in from.
	 *
	 * `Support\Ip` owns the rendering, and this used to own a second copy of
	 * it that branched on a four-byte prefix. The column is varbinary(16) and
	 * every writer stores sixteen bytes with IPv4 in its v4-mapped form, so
	 * the branch never ran and every IPv4 network in an export was labeled
	 * `::ffff:203.0.113.0/64` — an IPv4 /24 announced as an IPv6 /64, in a
	 * record handed to the person who asked for it.
	 *
	 * @param mixed $prefix
	 */
	private static function network( $prefix ): string {
		return Ip::prefix_label( is_string( $prefix ) ? $prefix : null ) ?? '';
	}
	/** A stored sign-in epoch, with an explicit zone; absence is not 1970. */
	private static function sign_in_time( $stored ): string {
		$timestamp = filter_var( $stored, FILTER_VALIDATE_INT, array( 'options' => array( 'min_range' => 1 ) ) );
		return false === $timestamp ? '' : (string) Time::utc_iso( gmdate( 'Y-m-d H:i:s', $timestamp ) );
	}

}
