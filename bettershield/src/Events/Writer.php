<?php
/**
 * Buffered activity event writer.
 *
 * All activity logging goes through this service. Events buffer in
 * memory during the request and flush on shutdown as one multi-row
 * INSERT — never one query per event, and never blocking work in the
 * response path.
 *
 * Request policies applied at flush time:
 * - Front-end GET requests persist security-relevant events only, so
 *   routine page views never gain a write.
 * - WooCommerce checkout and cart requests likewise persist
 *   security-relevant events only; everything else is dropped rather
 *   than delaying the response.
 * - The buffer is bounded; when it overflows, the drop is recorded as a
 *   single synthetic event with the true count, never silently.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Events;

use BetterShield\Cron\Runner;
use BetterShield\Database\Schema;
use BetterShield\Support\Checkout;
use BetterShield\Support\Ip;
use BetterShield\Support\Text;
use BetterShield\Support\Time;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Writer {

	public const SEVERITY_INFO     = 0;
	public const SEVERITY_LOW      = 1;
	public const SEVERITY_MEDIUM   = 2;
	public const SEVERITY_HIGH     = 3;
	public const SEVERITY_CRITICAL = 4;

	/**
	 * Event types an investigation needs: exempt from the request drop policy
	 * below and from the hourly sampler, so a trail an investigation follows
	 * cannot thin under the load it is investigating. Read here, in `Sampling`
	 * and in the digest, so a type added once is exempt in all of them.
	 */
	public const SECURITY_TYPES = array(
		'maintenance_window_started',
		'maintenance_window_closed',
		// A window booked to open by itself later, changed or canceled: the
		// record of who set alerts to go quiet, and for when.
		'maintenance_window_booked',
		'maintenance_booking_canceled',
		'maintenance_booking_missed',
		// A consent answer about data leaving the site is history that must
		// not thin: it is the record of what the owner agreed to, and when.
		'usage_tracking_enabled',
		'usage_tracking_disabled',
		// The same for the Hub link: what the owner agreed to send, and when
		// it stopped.
		'hub_link_enabled',
		'hub_link_disabled',
		// A known vulnerability arriving is history that must not thin, and
		// so is the row that closes it — a finding with no ending reads as
		// still open to anybody reading the log later.
		'vulnerability_found',
		'vulnerability_resolved',
		'login_failed',
		// A sign-in from a network this account has never used: the row an
		// investigation starts from, so it never thins under load.
		'login_new_network',
		'email_change_held',
		'email_change_confirmed',
		'user_created',
		'user_deleted',
		// On a network, taking somebody off a site is what deleting an account
		// looks like from that site: every permission they had here is gone
		// and the account itself is untouched. The row above is written on a
		// network only when the account is removed from the whole of it.
		'user_removed_from_site',
		'user_role_changed',
		// A role added alongside the others, and a change to what a role may
		// do at all. The second escalates every account holding that role and
		// touches no user record, so it is the quietest privilege change there
		// is and the one least able to afford being dropped.
		'user_role_granted',
		'user_role_revoked',
		// A privileged window that was supposed to close and did not, because
		// closing it would have left the site with nobody who can manage it.
		// Kept for the same reason the two above are: it is a privilege the
		// site still carries, and the row saying so is the one an
		// investigation looks for.
		'temporary_access_end_refused',
		// An account kept from signing in and given back, and the handover
		// they were part of: access taken away and restored by name, which
		// is what an investigation of who could reach this site reads.
		'account_suspended',
		'account_suspension_lifted',
		'handover_completed',
		'role_capabilities_changed',
		// Changing the address on an account is how it is taken: the reset
		// that follows looks entirely legitimate on its own.
		'user_email_changed',
		// The name an account signs in with: a rename is a change of who
		// can be guessed at, recorded as the address one is.
		'username_changed',
		'password_changed',
		// Asking for a reset link, which anybody can do unauthenticated from
		// the sign-in page. One is routine; a burst against one administrator
		// is a campaign, and it was the only type here whose own listener
		// called it a signal while it sat outside this list — so above the
		// sampling threshold the surplus was dropped as noise during exactly
		// the flood that made it a signal, and the digest counted none of it.
		'password_reset_requested',
		// The automatic eviction after a credential change: the row that
		// says whether the canonical incident response actually bit.
		'sessions_reset',
		// The credential a connected tool signs in with. Creation and
		// revocation are access being granted and withdrawn; *use* is
		// deliberately absent, because that is traffic and it is already
		// throttled to one row an hour at the listener.
		'app_password_created',
		// A credential held to what it is for, that hold taken away, and a
		// request it refused: the record of which door a leaked key could
		// and could not open.
		'app_password_limited',
		'app_password_unlimited',
		'app_password_refused',
		// All three changes that take an account over, on one privileged
		// account within an hour. Never thinned: it is the one row that
		// says the other three belong together.
		'account_takeover_sequence',
		'app_password_revoked',
		/*
		 * The decoy, and the two things that can happen to it. It belongs to no
		 * tool, is written into no configuration and is used by no workflow, so
		 * the only way it authenticates is that somebody read it out of this
		 * site's database or its backups: there is no innocent reading of a trip,
		 * and a disarm means the trap is no longer set. Neither may thin under
		 * load — the request they arrive on is not the owner's to choose, and a
		 * credential can be tried against any address on the site.
		 */
		'canary_used',
		'canary_page_touched',
		'canary_page_changed',
		'incident_status_changed',
		'incident_opened',
		// Incident evidence and reviewed responses must survive load sampling.
		'incident_code_added',
		'incident_code_modified',
		'incident_cron_unanswered',
		'incident_response_applied',
		// The two response actions that write nothing anywhere else. They are
		// the record of a capability map emptied and a schedule changed during
		// an incident, and they are written as the batch runs rather than
		// after it, so an interrupted batch still leaves the trail.
		'incident_account_demoted',
		'incident_cron_unscheduled',
		// A password refused on an account's own sign-in until a new one is
		// set, and the moment that stopped: the record of who could not sign
		// in during an incident, and why.
		'incident_password_held',
		'password_hold_lifted',
		// What an update of a plugin nobody publishes brought: the one record
		// of code that arrived with no published copy to compare it to.
		'update_code_changed',
		// A script on a store that may be reading card details, a decision
		// to let one be, and the hosts store pages load scripts from: the
		// record of code nothing else on the site can see.
		'store_script_flagged',
		'store_script_accepted',
		'store_script_unaccepted',
		'store_script_host_added',
		'observed_change_response',
		'dormant_privileged_login',
		// A ruling that reaches every site of a network is history no site
		// may thin on its own behalf.
		'network_2fa_policy_changed',
		'network_passkey_policy_changed',
		'canary_disarmed',
		'plugin_activated',
		'plugin_deactivated',
		'plugin_installed',
		'plugin_deleted',
		'theme_installed',
		'theme_deleted',
		// Activating a theme runs its code exactly as activating a plugin
		// does, and an update replaces code that was already running. Core's
		// own update was here from the start; the other three are the same
		// fact about somebody else's code and were not.
		'theme_changed',
		// Code written from the dashboard by whoever was signed in: the row
		// that says who, beside the file check's row that says what changed.
		'theme_plugin_file_edited',
		'plugin_updated',
		// An update whose files did not match what the publisher published.
		// The whole value of saying it is that it is said before the files
		// become the site, so it must not thin under load either.
		'package_unverified',
		// Adopting a copy that differs from the published one quiets that
		// row for a version, and the undo brings it back: both are the
		// record of a defense being stood down or restored by name.
		'package_adopted',
		'package_adoption_undone',
		// A change to somebody else's code that nobody sat down and made, and
		// the reversal of one. The plugin change itself is already here; these
		// carry why it happened and that there is a way back, which is the
		// half an investigation a week later actually asks for. Kept for the
		// same reason every other line above is: the load a site is under when
		// this fires is not the owner's to choose.
		'response_taken',
		'response_undone',
		// And an update it made being put back on its own, because the front
		// page stopped answering after it: the version the site runs changed
		// twice while nobody was there, and this is the row that says why.
		'response_rolled_back',
		'theme_updated',
		'core_updated',
		// A file that no longer matches what its publisher shipped, and the
		// two things an owner may do about it. None of these may thin under
		// load: they are the record of an intrusion and its handling.
		'file_changed',
		'file_restored',
		'file_quarantined',
		// The same move for a tool left in the web root, which was never
		// shipped by anybody and so is not an altered file.
		'leftover_tool_quarantined',
		'exposed_file_quarantined',
		// And the three ways that record gets undone or taken away: a restore
		// reversed puts the altered file back, a suppressed change is that
		// file told to stop being reported, and a deleted quarantine copy is
		// the evidence itself destroyed. Each is louder than the row it
		// answers, and each was droppable while that row was not.
		'file_restore_undone',
		'file_change_suppressed',
		'file_change_unsuppressed',
		// The same decision for a plugin's changes at once, and its return;
		// one row stands for hundreds, so it is kept like them.
		'file_changes_expected',
		'file_changes_unexpected',
		// And a selection of them from anywhere on the site: the same decision
		// about many rows, kept like them.
		'file_selection_expected',
		// A host saying a file is its own: each stands where a change row
		// would have, so it is kept like one.
		'file_expected',
		'file_expected_undone',
		'quarantine_deleted',
		// The quarantine folder's seal written from its finding, and taken
		// back: whether displaced bytes can be fetched (#2207).
		'quarantine_sealed',
		'quarantine_seal_undone',
		// The site's own http:// links rewritten in published content from
		// its finding, and put back: what every page of it now loads (#1291).
		'content_links_rewritten',
		'content_links_restored',
		// A content folder's permissions narrowed from its finding, and put
		// back: who on the server may add code the site runs (#2211).
		'folder_mode_tightened',
		'folder_mode_restored',
		// The same for wp-config.php, and a plugin updated or a deactivated
		// plugin or theme moved into quarantine from its finding, each with
		// its way back: code and the file that holds the site's keys (#2430).
		'config_mode_tightened',
		'config_mode_restored',
		'plugin_update_applied',
		'plugin_update_undone',
		'extension_quarantined',
		'extension_put_back',
		// Scheduled events nothing answers, removed from their finding and
		// put back: what can run on this site's schedule (#1952).
		'cron_events_removed',
		'cron_events_restored',
		// A REST route the owner picked to close to strangers: what anybody
		// not signed in can read on this site (#1870).
		'rest_route_watched',
		'rest_route_closed',
		'rest_route_reopened',
		'quarantine_downloaded',
		'safe_mode_entered',
		'safe_mode_exited',
		// The same pair for a whole network, which stands every site of it
		// down at once — a wider act than the one above and no more droppable.
		'network_safe_mode_entered',
		'network_safe_mode_exited',
		// The log's own seals taken again, and a reseal nobody here asked for
		// refused: the record of the record being rewritten, which is exactly
		// what an investigation of an edited log reads first.
		'log_resealed',
		'log_reseal_refused',
		'recovery_link_generated',
		'recovery_link_failed',
		// A sign-in change made while the way back was unproved, by a person
		// who was told so and went ahead.
		'recovery_preflight_overridden',
		'hardening_applied',
		'hardening_reverted',
		/*
		 * The two halves of a change made by something that is not a person:
		 * the moment somebody allowed exactly one action, and the moment it
		 * was carried out. Neither may thin under load — an owner asking
		 * afterwards who permitted a change and what was done with it is
		 * asking these two rows, and the load a site is under when an agent
		 * is working is not the owner's to choose.
		 */
		'write_confirmation_minted',
		'agent_write_applied',
		'agent_check_requested',
		'agent_triage_requested',
		// And the same change with nobody in the loop, which is the one this
		// list exists for: a leaked credential looks exactly like it.
		'agent_write_applied_direct',
		/*
		 * A credential an assistant reaches this site with, minted or
		 * replaced, and an application allowed to hold one. These are access
		 * being granted, which is the direction that has to stay answerable:
		 * "who let this in, and when" is the first question asked of an
		 * assistant that did something unexpected.
		 */
		'mcp_connected',
		'mcp_rotated',
		'mcp_app_granted',
		/*
		 * And the door closing on a network that kept presenting credentials
		 * this site does not recognize. It is the same row as a sign-in
		 * lockout and belongs in the same place: already one per network per
		 * window, so it is not volume — and the load a site is under while
		 * somebody is hammering an endpoint is exactly the load that would
		 * thin the record of it.
		 */
		'mcp_locked_out',
		// A copy of an assistant's credential coming back, and its access
		// ended for it: the loudest thing this endpoint can say.
		'mcp_refresh_reused',
		// A finding arriving and a finding closing. The first is the loudest
		// thing an audit can say and the second is what makes the first
		// readable afterwards — a problem with no ending reads as still open
		// to anybody going through the log later.
		'finding_opened',
		'finding_resolved',
		// Setting a finding aside is a protection declined, told apart from
		// reverting one only by which screen it was done from.
		'finding_suppressed',
		'finding_unsuppressed',
		// Setting one aside for a while, and its return: the same decision
		// with an end date, so the same record.
		'finding_snoozed',
		'finding_woken',
		// A copy of the site told it is staging, which mutes its alerts and
		// refuses the hub; a move; and either taken back. What a later
		// reader needs to know about why a site went quiet.
		'site_marked_staging',
		'site_marked_moved',
		'site_identity_undone',
		// A site of a network coming into being: the one row that stands
		// for WordPress filling in its roles and first administrator.
		'site_created',
		// And the rest of its life: archived, deactivated or marked as spam,
		// and removed. A site taken off a network is history an
		// investigation of that network reads.
		'site_status_changed',
		'site_deleted',
		'hardening_failed',
		'hardening_revert_failed',
		// A protection applied to the network in front of this site, and the
		// same one taken back. Kept for the same reason as the four above:
		// somebody reading the log after an incident needs to know what was
		// standing between the site and the internet at the time.
		'cloudflare_action_taken',
		'cloudflare_action_undone',
		// A change the edge was asked for and did not get is the state the
		// tab must not read as "armed": kept for the same reason the change is.
		'cloudflare_block_refused',
		'cloudflare_block_failed',
		'keys_rotated',
		'password_policy_updated',
		// Removing the two-factor requirement for a role is a defense being
		// switched off, in the same sentence as the two policy changes either
		// side of it here.
		'two_factor_policy_changed',
		// login_blocked and honeypot_rejected are deliberately absent: both
		// fire per bot attempt, and a flood of refused bots must be droppable
		// under load rather than becoming its own denial of service.
		'login_protection_updated',
		'login_lockout_started',
		// A public form closing to a network is one decision about many
		// requests, not one per request — so unlike the per-attempt refusals
		// above it, it is worth keeping under load.
		'surface_closed',
		'login_lockout_cleared',
		'login_lockout_emailed',
		'login_unlock_requested',
		'sessions_ended',
		// One session ended deliberately, which is what somebody does when
		// they see a sign-in they do not recognize.
		'session_ended_by_owner',
		// One the owner said was not theirs: where an investigation starts.
		'session_reported_by_owner',
		// Produced only on a visitor's page view, which is precisely the
		// request this writer keeps security types on and drops everything
		// else from — so without being named here it could never reach the
		// log at all, and the one check that confirms a protection from
		// reality had no record of ever having run.
		'hardening_verified',
		// A wrong second factor means the PASSWORD was right: the single
		// loudest signal in this list. Backup-code use and either end of
		// enrollment are account-security history.
		'two_factor_enabled',
		'two_factor_disabled',
		'two_factor_failed',
		// Usually a visitor's page view, where a magic link or social sign-in lands.
		'two_factor_skipped',
		// Re-entering a password to reach something dangerous, refused. The
		// same signal as a wrong second factor: somebody is at the door of an
		// action this plugin guards.
		'sudo_refused',
		'two_factor_backup_used',
		// Issuing a new set mints ten credentials that open the account
		// without the phone; spending one was history and minting ten was not.
		'two_factor_backup_reissued',
		// Another plugin's enrollments brought over as it is switched off, an
		// account each, the ones that could not come, and the copy taken
		// back: which accounts sign in with what is account-security history.
		'two_factor_imported',
		'two_factor_import_failed',
		'two_factor_import_undone',
		'two_factor_moved',
		'two_factor_not_moved',
		// Enrolling a way in, losing one, and a refusal that can mean a
		// copied device. All account-security history.
		'passkey_registered',
		'passkey_removed',
		'passkey_refused',
		// Switching the password off for a role, or back on, is the largest
		// single change anyone can make to how this site is entered.
		'passkey_policy_changed',
		/*
		 * A content policy going from watching to enforcing changes what every
		 * visitor's browser will run, and the reverse takes that protection
		 * away. Both are the kind of change somebody has to be able to find
		 * afterwards when a page stops working.
		 */
		/*
		 * The switch a person throws when the site is under attack, and the
		 * one they throw to end it. If any row in this table survives a flood,
		 * it is the one saying the site was closed and by whom.
		 */
		'lockdown_entered',
		'lockdown_left',
		'csp_enforced',
		'csp_report_only_restored',
		// The policy widened for a source or narrowed again, and its list of
		// what it would block cleared or put back: each changes what a
		// visitor's browser may run, or the evidence the quiet week is
		// measured from.
		'csp_source_allowed',
		'csp_source_removed',
		'csp_reports_cleared',
		'csp_reports_restored',
		// A plugin's request refused on its way to the address a cloud server
		// keeps its credentials on, and one noted on its way into the server's
		// own network. Both arrive on visitors' requests as often as anywhere,
		// where everything else is dropped, and both are already written at
		// most once an hour or once a day for each destination.
		'outbound_refused',
		'outbound_internal',
		/*
		 * A correct password refused because the account signs in with a
		 * passkey. It is the same signal as a wrong second factor and louder:
		 * the password was right, and somebody or something used it. On the
		 * account holder's own machine it is a habit; anywhere else it is the
		 * credential having leaked, which is the case this feature exists for.
		 */
		'password_refused_passkey_only',
		'password_refused_repeated',
		// The self-audit promise: every agent query IS a log row. A trail
		// that thins under load is not a trail.
		'ability_used',
		/*
		 * An ability refused to whoever asked for it. The clearest signal
		 * this product has that something is trying what it may not do, and
		 * an agent in a loop is exactly the load under which a droppable row
		 * would disappear — the flood being the signal, again.
		 */
		'agent_permission_denied',
		/*
		 * And the pattern the individual refusals add up to, which is the one
		 * that interrupts somebody. It is rarer than the rows it summarizes
		 * and louder than any of them, so if anything here survives a flood it
		 * is this.
		 */
		'agent_refusals_repeated',
		// Someone removed the capture hook. The record saying the record
		// stopped cannot itself be droppable.
		'agent_capture_removed',
		// And the row that says the invocation record is short for this
		// request. An omission that is not stated is a log that lies by
		// looking complete.
		'agent_capture_truncated',
		/*
		 * The site's address, where the administrator's mail goes, whether
		 * strangers may register and as what: the settings a takeover changes
		 * first. Rating them high was not enough on its own — they shared the
		 * generic setting row, which may thin, so the request a front-end
		 * exploit arrives on is exactly the one they could be dropped from.
		 * These five must never thin.
		 */
		'site_setting_changed',
		// And a write to one of them refused because nobody allowed to make
		// it was making it: the attempt itself, kept whatever the load.
		'takeover_setting_refused',
		// A plugin update that made a new write ability reachable to agents,
		// or opened an existing one wider (#1878).
		'ability_added',
		'ability_widened',
		'agent_new_network',
		// And the owner taking those changes as expected.
		'ability_changes_accepted',
		'ability_changes_accept_undone',
		// An import can flip every control at once; the record of it must not
		// thin under the load it may itself cause. An export is the same
		// document leaving, which is worth the same row.
		'settings_imported',
		'settings_exported',
		// Muting alerts is a defense being switched off, and "who made this
		// site go quiet" has to stay answerable. The sending of an alert is
		// deliberately not in this list: that is volume, not history.
		'alerts_updated',
		// Choosing that deleting this plugin takes its records with it, and
		// taking that back: the step before a deletion empties this log, so
		// the summary counts it and a busy hour does not thin it.
		'uninstall_choice_changed',
	);

	public const ENTRY_WP_CLI = 'wp-cli';
	public const ENTRY_REST   = 'rest';
	public const ENTRY_PHP    = 'php';

	/**
	 * The assistant endpoint, which arrives as a REST request and is not one.
	 *
	 * A call from a connected assistant is a REST request in every mechanical
	 * sense, so without this it was recorded as the dashboard's own traffic —
	 * and the one question an owner asks of these rows is which of them a
	 * person made. Named by the endpoint when it has authenticated, and never
	 * before: a refused call reached no further than the door.
	 */
	public const ENTRY_MCP = 'mcp';

	/** Every door a row can name, for anything that filters by one. */
	public const ENTRIES = array( self::ENTRY_PHP, self::ENTRY_REST, self::ENTRY_WP_CLI, self::ENTRY_MCP );

	private const MAX_BUFFER        = 200;
	private const MAX_CONTEXT_BYTES = 4096;

	/**
	 * A listener on the flushed action may record an event of its own — the
	 * alert dispatcher records that it sent one — and those rows arrive after
	 * the buffer has already been drained. Draining is therefore a short loop
	 * rather than a single pass, bounded here because a listener that records
	 * on every flush would otherwise never let the request end.
	 */
	private const MAX_FLUSH_PASSES = 3;

	/** Where a buffered row keeps the table it belongs in; never a column. */
	private const TABLE_KEY = '_table';

	private static ?Writer $instance = null;

	/**
	 * Test seam: a process cannot become a WP-CLI process from inside a
	 * test, so the suite names the door instead. Null means detect.
	 */
	private static ?string $entry_path_override = null;

	/**
	 * Whether this request came through the assistant endpoint. See
	 * `enter_assistant()`.
	 */
	private static bool $through_assistant = false;

	/**
	 * The resolved network for this request, keyed on what it was derived
	 * from. See client_network().
	 *
	 * @var array<string, ?string>
	 */
	private static array $network = array();

	/** @var array<int, array<string, mixed>> */
	private array $buffer = array();

	private int $dropped = 0;

	/**
	 * How many rows in the buffer may be given up to make room.
	 *
	 * Carried rather than counted on demand: once a buffer holds nothing but
	 * types that may not thin, every further event would otherwise walk the
	 * whole buffer to learn that again — during exactly the flood that filled
	 * it.
	 */
	private int $droppable = 0;

	public static function instance(): Writer {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {}

	public function register(): void {
		// Late priority: flush after other shutdown work has produced
		// whatever events it produces.
		add_action( 'shutdown', array( $this, 'flush' ), 100 );
	}

	/**
	 * Stop flushing for the rest of this request.
	 *
	 * Deletion happens inside a live request: the plugin boots, registers
	 * this flush, then its own files are removed — and shutdown fires
	 * afterwards, against classes the autoloader can no longer find. The
	 * buffer is dropped with the hook, which is correct: there is nowhere
	 * left to write it, and a log line is not worth a fatal on the way out.
	 */
	public function stand_down(): void {
		remove_action( 'shutdown', array( $this, 'flush' ), 100 );
		$this->buffer    = array();
		$this->droppable = 0;
	}

	/**
	 * Queue an event.
	 *
	 * The one way into the activity log, for this plugin and for any other
	 * that records its own activity here. What a caller can rely on, and what
	 * it owes:
	 *
	 * - `$event_type` is a slug this plugin names, or one registered on
	 *   `bettershield_event_types` (see `Types::registered()`). It is stored
	 *   cut to 32 characters. A type nobody registered is still written, and
	 *   shows as its own slug in no area.
	 * - `$severity` is one of the `SEVERITY_*` constants. High and critical
	 *   are sent at once, by email and to the alert channels, so they are for
	 *   what somebody should hear about now; everything else waits for the
	 *   digest.
	 * - `$args` takes `object_type` (a short slug, cut to 32), `object_id`
	 *   (cut to 191), `context` (an array, JSON-encoded and bounded where it is
	 *   stored), and `actor_type`, `actor_id` and `actor_label` where the
	 *   signed-in account is not the one acting. Any other key is ignored.
	 * - Never put a password, token, key, nonce, full IP address, file
	 *   contents or whole user record in `context`. The log is read by people
	 *   and can be sent to destinations the owner set up.
	 * - Nothing is written during the request. Rows are held in memory and
	 *   written as one statement at shutdown. On a visitor's GET and on the
	 *   store's cart and checkout, only `SECURITY_TYPES` are kept, so record
	 *   what somebody did in the dashboard, not what visitors do.
	 * - The buffer is bounded. Past it, one row records how many were dropped.
	 */
	public function record( string $event_type, int $severity = self::SEVERITY_INFO, array $args = array() ): void {
		if ( count( $this->buffer ) >= self::MAX_BUFFER && ! $this->make_room( $event_type ) ) {
			++$this->dropped;
			return;
		}

		if ( ! Sampling::never_sampled( $event_type ) ) {
			++$this->droppable;
		}

		$this->buffer[] = $this->build_row( $event_type, $severity, $args );
	}

	/**
	 * Whether the buffer has no room for another row.
	 *
	 * For a job that records one row per item it walks: past a full buffer a
	 * row that may not thin is dropped and only counted, so such a job asks
	 * this and flushes first.
	 */
	public function full(): bool {
		return count( $this->buffer ) >= self::MAX_BUFFER;
	}

	/**
	 * Give up the oldest row that may thin, so one that may not can be kept.
	 *
	 * Nothing flushes between the chunks of a long-running job, so a file scan
	 * across a site that has been altered wholesale arrives at this buffer as
	 * one unbroken run. Refusing on a full buffer alone meant the two hundred
	 * rows that happened to arrive first decided what the log held, and a
	 * settings change could keep out the record of an intrusion.
	 *
	 * The eviction is counted as a drop like any other, so the overflow row
	 * still states the true number: room is made, never taken quietly.
	 */
	private function make_room( string $event_type ): bool {
		if ( 0 === $this->droppable || ! Sampling::never_sampled( $event_type ) ) {
			return false;
		}

		foreach ( $this->buffer as $index => $event ) {
			if ( Sampling::never_sampled( (string) $event['event_type'] ) ) {
				continue;
			}

			array_splice( $this->buffer, $index, 1 );
			--$this->droppable;
			++$this->dropped;

			return true;
		}

		return false;
	}

	/**
	 * Persist the buffer as a batched INSERT and clear it.
	 */
	public function flush(): void {
		/**
		 * Drain bounded add-on aggregates through this writer at shutdown.
		 * Listeners may buffer completed summaries, but must not call flush().
		 */
		do_action( 'bettershield_events_before_flush' );
		for ( $pass = 0; $pass < self::MAX_FLUSH_PASSES; $pass++ ) {
			if ( ! $this->drain() ) {
				return;
			}
		}
	}

	/**
	 * One pass: everything buffered right now, as a single INSERT.
	 *
	 * @return bool Whether anything was persisted, which is what tells flush()
	 *              there may be more to do.
	 */
	private function drain(): bool {
		$events          = $this->buffer;
		$dropped         = $this->dropped;
		$this->buffer    = array();
		$this->dropped   = 0;
		$this->droppable = 0;

		/*
		 * Worked out only where it is needed, and never before.
		 *
		 * This runs at shutdown on every request, a quiet front-end page view
		 * included, and answering it reaches the store's cart and checkout
		 * conditionals. A request that buffered nothing has nothing to apply the
		 * answer to, so it must not pay for one.
		 */
		$context = null;

		if ( array() !== $events ) {
			$context = self::request_context();
			$events  = $this->filter_for_request( $events, $context );
		}

		/*
		 * Appended after the request drop policy, for the same reason the
		 * sampler's own row is: `buffer_overflow` is not a security type, so
		 * running it through the filter dropped it on exactly the front-end
		 * and checkout requests where a full buffer is most likely — and the
		 * log then reported itself complete on the one request where it was
		 * not. A row that explains an omission must never itself be omitted.
		 */
		if ( $dropped > 0 ) {
			$events[] = $this->build_row(
				'buffer_overflow',
				self::SEVERITY_LOW,
				array(
					'actor_type' => 'system',
					'context'    => array( 'dropped' => $dropped ),
				)
			);
		}

		/*
		 * The log's account of itself, merged after the request drop policy
		 * rather than before it, and computed even when this request had
		 * nothing else to write.
		 *
		 * Both parts matter. A row that explains an omission must never itself
		 * be omitted, so it does not travel through the policy that omits
		 * things. And an hour that ended while the site was quiet still has to
		 * be closed out, or the flood's final numbers would depend on the site
		 * staying busy enough to state them.
		 */
		$events = array_merge( Sampling::close_expired_hour(), $events );

		// Then the per-type hourly cap on this batch. What it drops is counted,
		// never lost: the count lands in the log as its own row.
		$sampled = Sampling::apply( $events );
		$events  = $sampled['keep'];

		if ( array() === $events ) {
			return false;
		}

		if ( null === $context ) {
			$context = self::request_context();
		}

		// One INSERT per table: nearly always one, and more only where this
		// request recorded rows inside a switch to another site.
		$tables = array();

		foreach ( $events as $event ) {
			$table = (string) ( $event[ self::TABLE_KEY ] ?? '' );
			unset( $event[ self::TABLE_KEY ] );

			$tables[ '' !== $table ? $table : Schema::table( 'events' ) ][] = $event;
		}

		$events = array();

		foreach ( $tables as $table => $rows ) {
			if ( $this->insert( $rows, (string) $table ) ) {
				$events = array_merge( $events, $rows );
				continue;
			}

			/*
			 * The batch did not reach the table. Announcing it would tell the
			 * alert dispatcher about rows the Activity screen will never show,
			 * so nothing is announced — and the loss is carried into the next
			 * flush's drop count, where it lands as the row that says the log
			 * is short. Not retried: whatever refused the statement is still
			 * refusing it, and a second attempt inside the same request only
			 * delays the response.
			 */
			$this->dropped += count( $rows );
		}

		if ( array() === $events ) {
			return false;
		}

		/**
		 * Fires after a batch of activity events has been written.
		 *
		 * Carries what was actually persisted — the request drop policy has
		 * already been applied — and the kind of request it happened on, so a
		 * listener can tell a visitor's page view from an admin action without
		 * working it out a second time. Alerting is the reason this exists: it
		 * must know what was recorded, and it must never do slow work on a
		 * request a visitor is waiting on.
		 *
		 * @param array<int, array<string, mixed>>           $events  Rows as written.
		 * @param array{front_end_get: bool, checkout: bool} $context The request this happened on.
		 */
		do_action( 'bettershield_events_flushed', $events, $context );

		return true;
	}

	/**
	 * A row built the way a recorded event is built, for the mechanisms that
	 * synthesize one rather than observing it — the sampler's own notices.
	 *
	 * Public so those rows travel through the same INSERT, with the same
	 * columns and the same truncation, as everything else in the batch.
	 *
	 * @param array<string, mixed> $args
	 * @return array<string, mixed>
	 */
	public function build_synthetic( string $event_type, int $severity, array $args ): array {
		return $this->build_row( $event_type, $severity, $args );
	}

	/** Account for volume an add-on's bounded buffer could not retain. */
	public function report_dropped( int $count ): void {
		$this->dropped += max( 0, $count );
	}

	/**
	 * Clear the in-memory buffer without persisting. Test seam.
	 */
	public function reset(): void {
		$this->buffer    = array();
		$this->dropped   = 0;
		$this->droppable = 0;

		// What waits to be recorded at the next drain is buffered too.
		Listeners::instance()->forget_pending();
	}

	/**
	 * Which door the current request came through: the dashboard's REST
	 * calls, WP-CLI, or plain PHP — cron, hooks, activation.
	 */
	public static function entry_path(): string {
		if ( null !== self::$entry_path_override ) {
			return self::$entry_path_override;
		}

		if ( self::$through_assistant ) {
			return self::ENTRY_MCP;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return self::ENTRY_WP_CLI;
		}

		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return self::ENTRY_REST;
		}

		return self::ENTRY_PHP;
	}

	/**
	 * Test seam for entry_path(). Pass null to return to detection.
	 */
	public static function override_entry_path( ?string $path ): void {
		self::$entry_path_override = $path;
	}

	/**
	 * Say that the rest of this request came through the assistant endpoint.
	 *
	 * Set once, by the endpoint, after the credential has been accepted.
	 * There is no way back: a request cannot stop having arrived that way,
	 * and an endpoint that could un-say it would let an ability hide which
	 * door it was reached through.
	 */
	public static function enter_assistant(): void {
		self::$through_assistant = true;
	}

	/**
	 * Forget it again. Production never needs this — the flag lives and dies
	 * with the request — but a test process is many requests in one lifetime.
	 */
	public static function leave_assistant(): void {
		self::$through_assistant = false;
	}

	/**
	 * Request-scoped drop policy. Pure so it is directly testable.
	 *
	 * @param array<int, array<string, mixed>>          $events
	 * @param array{front_end_get: bool, checkout: bool} $context
	 * @return array<int, array<string, mixed>>
	 */
	public function filter_for_request( array $events, array $context ): array {
		if ( ! $context['front_end_get'] && ! $context['checkout'] ) {
			return $events;
		}

		/*
		 * Checkout keeps security events and nothing else — the same rule as a
		 * visitor's page view, and for a better reason than it first appears.
		 *
		 * Writing nothing at all was tried, to match a readme sentence, and it
		 * was the wrong trade: WooCommerce creates an account during a guest
		 * checkout, and on a store that is exactly the account worth having a
		 * record of. Dropping it bought nothing, because this writer flushes at
		 * shutdown — after the response has already gone to the buyer — so
		 * those few rows were never on the checkout's critical path. The
		 * sentence was guarding against a cost the architecture had already
		 * removed, and the readme now says what actually happens.
		 */
		// Bounded volume summaries survive visitor filtering but remain subject to hourly sampling.
		$volume = (array) apply_filters( 'bettershield_request_volume_types', array() );

		// A magic link or a social sign-in lands on a front-end GET, a customer
		// signs in on the checkout, and that one request is the only record of
		// it. Still droppable under load, so it stays out of the security list.
		$volume[] = 'login';

		return array_values(
			array_filter(
				$events,
				static function ( array $event ) use ( $volume ): bool {
					return in_array( $event['event_type'], self::SECURITY_TYPES, true ) || in_array( $event['event_type'], $volume, true );
				}
			)
		);
	}

	/**
	 * @return array{front_end_get: bool, checkout: bool}
	 */
	private static function request_context(): array {
		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? strtoupper( sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) )
			: '';

		// The sign-out is a GET, on no screen this plugin owns, and it is the
		// only request it can ever happen on — so the visitor's-page-view rule
		// dropped every one of them and the log had no record anybody ever
		// left. The login screen is not a visitor's page view, and neither is
		// any request that signed somebody out: a store signs its customers
		// out from a front-end page of its own, without the login screen.
		$front_end_get = 'GET' === $method
			&& ! did_action( 'login_init' )
			&& ! did_action( 'wp_logout' )
			&& ! is_admin()
			&& ! wp_doing_cron()
			&& ! ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			&& ! ( defined( 'WP_CLI' ) && WP_CLI );

		return array(
			'front_end_get' => $front_end_get,
			/*
			 * False when a conditional tag cannot answer, which is the opposite
			 * of what the mechanisms that stand down on the checkout choose.
			 * Both are the safe answer for their own caller: they are deciding
			 * whether to act, and this is deciding what to keep — answering
			 * "checkout" on a request nobody could classify would silently drop
			 * every non-security row it recorded.
			 */
			'checkout'      => Checkout::is_store_path( false ),
		);
	}

	/**
	 * Whether the site itself is doing the work, rather than somebody visiting.
	 *
	 * Scheduled work carries no user on any of its paths — wp-cron, the
	 * loopback that stands in for a dead scheduler, the terminal — so the
	 * absence of one was read as a signed-out visitor, and the screens then
	 * credited every file-change row the scanner wrote to a stranger at the
	 * sign-in form. Anonymous is what is left once these are excluded: a
	 * request somebody outside the site actually made.
	 */
	private static function site_is_acting(): bool {
		return wp_doing_cron()
			|| Runner::in_task()
			|| ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * @return array<string, mixed>
	 */
	private function build_row( string $event_type, int $severity, array $args ): array {
		$actor_type = isset( $args['actor_type'] ) ? (string) $args['actor_type'] : null;
		// Named explicitly by callers that know the actor better than the
		// current-user global does — a login event fires before the session
		// is established, and a logout fires as it is being torn down.
		$actor_id    = isset( $args['actor_id'] ) ? (int) $args['actor_id'] : null;
		$actor_label = isset( $args['actor_label'] ) ? (string) $args['actor_label'] : null;

		if ( null === $actor_type ) {
			$user = wp_get_current_user();

			// Scheduled work is the site's own whoever's page load happened
			// to run it: the inline fallback executes an overdue task on an
			// administrator's request, and a row crediting that person with
			// a file the scanner found changed would name the wrong actor.
			if ( Runner::in_task() ) {
				$actor_type = 'system';
			} elseif ( $user instanceof \WP_User && $user->exists() ) {
				$actor_type = 'user';
				if ( null === $actor_id ) {
					$actor_id = (int) $user->ID;
				}
				// Denormalized at write time so the record survives the
				// account being deleted later.
				if ( null === $actor_label ) {
					$actor_label = '' !== $user->display_name ? $user->display_name : $user->user_login;
				}
			} elseif ( self::site_is_acting() ) {
				$actor_type = 'system';
			} else {
				$actor_type = 'anonymous';
			}
		}

		/*
		 * An account named by the caller is named in the row as one found
		 * here would be. Only the account read off the request was given its
		 * name, so "Site locked down", which names its actor because the
		 * lockdown ends that actor's session, read "user" (#1798).
		 */
		if ( 'user' === $actor_type && null === $actor_label && null !== $actor_id && $actor_id > 0 ) {
			$named = get_userdata( (int) $actor_id );

			if ( $named instanceof \WP_User ) {
				$actor_label = '' !== $named->display_name ? $named->display_name : $named->user_login;
			}
		}

		/*
		 * An agent's write, plan or check names the connection it came in on,
		 * as the transport's own row does, so a change that looks wrong can
		 * be tied to the assistant to disconnect (#2213).
		 */
		if ( str_starts_with( $event_type, 'agent_' ) && null !== \BetterShield\Mcp\Audit::connection() ) {
			$args['context'] = ( isset( $args['context'] ) && is_array( $args['context'] ) ? $args['context'] : array() )
				+ array( 'connection' => \BetterShield\Mcp\Audit::connection() );
		}

		$context = null;
		if ( isset( $args['context'] ) && array() !== $args['context'] ) {
			$encoded = wp_json_encode( $args['context'] );

			if ( is_string( $encoded ) ) {
				if ( strlen( $encoded ) > self::MAX_CONTEXT_BYTES ) {
					// A truncated record beats a rejected one: a write that
					// fails because its payload was large is a gap in the log.
					$encoded = wp_json_encode(
						array(
							'_truncated'      => true,
							'_original_bytes' => strlen( $encoded ),
						)
					);
				}
				$context = $encoded;
			}
		}

		return array(
			// Stamped where the row is made rather than where the buffer is
			// drained: a request that switches sites mid-flight records each
			// row against the site it was acting on — and into that site's
			// table. The table was picked at the drain, so a row recorded
			// inside a switch to a site whose log had not moved yet went into
			// the main site's, with no site on it. Not a column: insert()
			// writes from its own list and drain() takes it off again.
			self::TABLE_KEY => Schema::table( 'events' ),
			'site_id'     => Schema::site_id( 'events' ),
			'occurred_at' => Time::stamp(),
			'event_type'  => substr( $event_type, 0, 32 ),
			'severity'    => max( self::SEVERITY_INFO, min( self::SEVERITY_CRITICAL, $severity ) ),
			'actor_type'  => substr( $actor_type, 0, 16 ),
			'actor_id'    => $actor_id,
			'actor_label' => null !== $actor_label ? Text::clip( $actor_label, 191 ) : null,
			// A closed set of internal slugs, so bytes and characters agree.
			'object_type' => isset( $args['object_type'] ) ? substr( (string) $args['object_type'], 0, 32 ) : null,
			'object_id'   => isset( $args['object_id'] ) ? Text::clip( (string) $args['object_id'], 191 ) : null,
			'ip_prefix'   => self::client_network(),
			'context'     => $context,
			'entry_path'  => self::entry_path(),
		);
	}

	/**
	 * The network this request came from, truncated, resolved once.
	 *
	 * The client as the login tables see it — through Cloudflare or a named
	 * proxy when there is one — so an event and the attempt it describes name
	 * the same network. Confidence is irrelevant here: nothing is enforced on
	 * this value, only displayed, truncated.
	 *
	 * Held for the request because the connection cannot change inside one,
	 * while resolving it re-reads the login settings and re-cleans the
	 * allowlist, the blocklist and the proxy list every time — which a scan
	 * paid two hundred times over for one batch. Keyed on the headers the
	 * answer is derived from, and holding one entry, so a process that serves
	 * more than one request cannot carry an answer across.
	 */
	private static function client_network(): ?string {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- read only to key the memo; the address itself is validated and truncated by the two calls below.
		$key = implode(
			"\n",
			array(
				isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '',
				isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? (string) $_SERVER['HTTP_CF_CONNECTING_IP'] : '',
				isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? (string) $_SERVER['HTTP_X_FORWARDED_FOR'] : '',
			)
		);
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput

		if ( ! array_key_exists( $key, self::$network ) ) {
			// One settings read for both answers: a batch of rows resolves
			// the network once, and so does the pair of values it needs.
			$settings = \BetterShield\Login\Protection::instance()->settings();

			self::$network = array(
				$key => Ip::truncated_binary(
					\BetterShield\Support\ClientIp::resolve( $settings['trusted_proxies'], (bool) $settings['cloudflare'] )['ip']
				),
			);
		}

		return self::$network[ $key ];
	}

	/**
	 * One multi-row INSERT for the whole batch.
	 *
	 * Errors are suppressed for the duration, because every reason this
	 * statement fails is a reason the site's visitors must not be shown one:
	 * a deadlock, a lock-wait timeout, a batch larger than the server accepts,
	 * a full disk, or a table a migration never managed to create. With
	 * `WP_DEBUG_DISPLAY` on, an unsuppressed failure prints the statement and
	 * the table name to whoever is looking at the page.
	 *
	 * @param array<int, array<string, mixed>> $events
	 * @param string                           $table  The table they belong in.
	 * @return bool Whether the rows are on disk.
	 */
	private function insert( array $events, string $table ): bool {
		global $wpdb;

		$columns = array( 'site_id', 'occurred_at', 'event_type', 'severity', 'actor_type', 'actor_id', 'actor_label', 'object_type', 'object_id', 'ip_prefix', 'context' );

		// The door column arrived with schema 3. Until the upgrade has been
		// verified and stamped, the INSERT leaves it out rather than fail.
		if ( Schema::ready( 'entry_path' ) ) {
			$columns[] = 'entry_path';
		}

		$integers = array( 'site_id', 'severity', 'actor_id' );

		$rows_sql = array();
		$params   = array();

		foreach ( $events as $event ) {
			$placeholders = array();

			foreach ( $columns as $column ) {
				$value = $event[ $column ];

				if ( null === $value ) {
					$placeholders[] = 'NULL';
				} elseif ( in_array( $column, $integers, true ) ) {
					$placeholders[] = '%d';
					$params[]       = $value;
				} else {
					$placeholders[] = '%s';
					$params[]       = $value;
				}
			}

			$rows_sql[] = '(' . implode( ',', $placeholders ) . ')';
		}

		$sql = 'INSERT INTO %i (' . implode( ',', $columns ) . ') VALUES ' . implode( ',', $rows_sql );

		/*
		 * $sql is assembled, not interpolated: the column list is the literal
		 * whitelist above, the VALUES list holds only generated placeholders
		 * ('%d', '%s' or the NULL keyword), and the table name is bound with
		 * %i. Every event value travels in $params through prepare(). Static
		 * analysis cannot see that, and per-row inserts would defeat the
		 * one-query-per-flush design this whole class exists for.
		 */
		$was_suppressed = $wpdb->suppress_errors( true );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->query( $wpdb->prepare( $sql, array_merge( array( $table ), $params ) ) );

		$wpdb->suppress_errors( $was_suppressed );

		return false !== $result;
	}
}
