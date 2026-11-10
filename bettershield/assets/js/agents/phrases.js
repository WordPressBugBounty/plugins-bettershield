/**
 * The sentences the Agents screens say, in one place.
 *
 * Three tabs read the same facts back to the reader — how long a request has
 * left, what a credential may do, where a round trip stopped — and a second
 * spelling of any of them would drift from the first. What is here is wording
 * and arithmetic only: nothing fetches, and nothing decides.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
import { whenPhrase } from '../ui/when';

/**
 * Whole minutes from now until then, negative once it has passed.
 *
 * @param {?string} iso An ISO 8601 timestamp.
 * @param {number}  now Milliseconds since the epoch.
 * @return {?number} The gap in minutes, or null if there is no readable time.
 */
export function minutesUntil( iso, now ) {
	if ( ! iso ) {
		return null;
	}

	const at = new Date( iso ).getTime();

	return Number.isNaN( at ) ? null : Math.round( ( at - now ) / 60000 );
}

/*
 * Every other timestamp in this app is printed absolutely, on purpose. These
 * two are the exception, and the exception is the fifteen-minute window: a
 * clock time cannot answer "is there still time to allow this?" without the
 * reader doing the subtraction, and by the time they have, the answer may
 * have changed. Anything older than an hour and a half goes back to the
 * absolute phrase, where a date reads better than a large number of minutes.
 */
export function madePhrase( iso, now ) {
	const since = minutesUntil( iso, now );

	if ( null === since ) {
		return __( 'made at an unknown time', 'bettershield' );
	}

	const minutes = Math.max( 0, -since );

	if ( minutes < 1 ) {
		return __( 'made just now', 'bettershield' );
	}

	if ( minutes > 90 ) {
		return sprintf(
			/* translators: %s: when it was made, e.g. "today, 5:14 PM". */
			__( 'made %s', 'bettershield' ),
			whenPhrase( iso, new Date( now ) )
		);
	}

	return sprintf(
		/* translators: %d: a number of minutes. */
		_n( 'made %d minute ago', 'made %d minutes ago', minutes, 'bettershield' ),
		minutes
	);
}

export function expiryPhrase( iso, now ) {
	const left = minutesUntil( iso, now );

	if ( null === left ) {
		return '';
	}

	if ( left < 1 ) {
		return __( 'expired', 'bettershield' );
	}

	return sprintf(
		/* translators: %d: a number of minutes. */
		_n( 'expires in %d minute', 'expires in %d minutes', left, 'bettershield' ),
		left
	);
}

/*
 * The five states a proposal can be in, in the owner's words. "Spent" is the
 * word the contract uses for a confirmation that has been handed back and
 * used; on screen it says what happened rather than what the record calls it.
 */
export const STATUSES = {
	proposed: { kind: 'neutral', label: () => __( 'Waiting', 'bettershield' ) },
	allowed: { kind: 'good', label: () => __( 'Approved', 'bettershield' ) },
	spent: { kind: 'applied', label: () => __( 'Applied', 'bettershield' ) },
	withdrawn: { kind: 'muted', label: () => __( 'Approval canceled', 'bettershield' ) },
	declined: { kind: 'muted', label: () => __( 'Declined', 'bettershield' ) },
	expired: { kind: 'muted', label: () => __( 'Expired', 'bettershield' ) },
};

/**
 * What the row says its state is.
 *
 * A proposal that has run out of time is expired whatever the record still
 * says: the deadline passed on the reader's clock, and offering Allow on a
 * row the site will refuse is a control that lies.
 */
export function currentStatus( proposal, now ) {
	const open = 'proposed' === proposal.status || 'allowed' === proposal.status;
	const left = minutesUntil( proposal.expires_at, now );

	return open && null !== left && left < 1 ? 'expired' : proposal.status;
}

/** What a credential may do, as the contract spells it. */
export const READ_ONLY = 'read';
export const READ_WRITE = 'read write';

/** What a credential may do, as a person would say it. */
export function scopePhrase( scope ) {
	if ( ! scope ) {
		return '';
	}

	return READ_ONLY === scope
		? __( 'can read this site', 'bettershield' )
		: __( 'can read and change this site', 'bettershield' );
}

/** The same fact about an app that has signed in, said about the app. */
export function appScopePhrase( scope ) {
	if ( ! scope ) {
		return '';
	}

	return READ_ONLY === scope
		? __( 'reads', 'bettershield' )
		: __( 'reads and changes', 'bettershield' );
}

/*
 * A clock time on its own. The registration window is a quarter of an hour
 * wide, so the date beside it would be the same date every time — noise in
 * the one line a reader is checking against their own clock.
 */
export function clockTime( iso ) {
	const at = new Date( iso );

	return Number.isNaN( at.getTime() )
		? ''
		: new Intl.DateTimeFormat( undefined, { hour: 'numeric', minute: '2-digit' } ).format( at );
}

/**
 * Each step the round trip can stop at, said as what to do about it.
 *
 * A step name is the site's word for where it got to; on screen it has to be
 * the reader's. "tls" tells somebody nothing, and a test that reports a
 * failure nobody can act on is a test that trains its reader to stop pressing
 * the button.
 */
const STEPS = {
	disabled: () =>
		__( 'The connection is off, so nothing answered. Turn it on above, then test again.', 'bettershield' ),
	not_connected: () =>
		__( 'Nothing is connected yet. Add BetterShield to your assistant above, then test again.', 'bettershield' ),
	unreachable: () =>
		__(
			'The test couldn’t run from your server (some hosts block this). Your assistant may still connect; try it.',
			'bettershield'
		),
	tls: () =>
		__(
			'The https certificate failed verification. Local and staging sites often do; on a live site, check it.',
			'bettershield'
		),
	redirect: () =>
		__(
			'The address redirected. Check that the site and WordPress addresses match and both use https.',
			'bettershield'
		),
	not_routed: () =>
		__(
			'The address did not reach this plugin. Save Settings → Permalinks once, then test again.',
			'bettershield'
		),
	auth: () =>
		__( 'The key was turned away. Replace it above, then update your assistant.', 'bettershield' ),
	no_tools: () =>
		__(
			'The connection works, but nothing is offered. Turn on “Let AI assistants see security info”.',
			'bettershield'
		),
};

/** What the test says it found, in one sentence. */
export function testSentence( result ) {
	if ( ! result ) {
		return '';
	}

	if ( 'ok' === result.step ) {
		const tools = Number( result.tools || 0 );

		return sprintf(
			/* translators: %d: how many actions answered the test. */
			_n(
				'It works. %d action is available to your assistant.',
				'It works. %d actions are available to your assistant.',
				tools,
				'bettershield'
			),
			tools
		);
	}

	const said = STEPS[ result.step ];

	if ( said ) {
		return said();
	}

	return (
		result.message ||
		__( 'The test stopped without saying where.', 'bettershield' )
	);
}

/**
 * A three-state fact, said in the reader's words.
 *
 * A key the payload left out is not a pass. Every live controller sends this
 * one, so `unknown` is what a payload from something else — an older site, a
 * filtered reply — is reported as, rather than being rounded up to a tick.
 *
 * @param {*} value What the payload said, if it said anything.
 * @return {string} The chip's caption.
 */
export function prettyRoutedState( value ) {
	if ( undefined === value || null === value ) {
		return __( 'Unknown', 'bettershield' );
	}

	return value ? __( 'Yes', 'bettershield' ) : __( 'No', 'bettershield' );
}

/**
 * Why one of this plugin's abilities turned a call away, in words.
 *
 * The log keeps only the error code, which is right for privacy, and these
 * codes are the plugin's own: a fixed set, each with a meaning an owner can
 * act on. A code this map does not know, such as another plugin's, is left
 * for the screen to show as it is.
 *
 * @param {string} code An error code the call ended with.
 * @return {string} The reason, or an empty string for a code not ours.
 */
export function refusalPhrase( code ) {
	const reasons = {
		bettershield_rate_limited: __( 'The hourly limit for this change was reached', 'bettershield' ),
		bettershield_signin_change_refused: __( 'Sign-in changes need a person to agree', 'bettershield' ),
		bettershield_confirmation_required: __( 'Turning a protection off needs your approval first', 'bettershield' ),
		bettershield_proposal_required: __( 'This change needs your approval first', 'bettershield' ),
		bettershield_confirmation_unknown: __( 'The confirmation it gave is not one this site issued', 'bettershield' ),
		bettershield_confirmation_expired: __( 'The confirmation it gave had expired', 'bettershield' ),
		bettershield_confirmation_spent: __( 'The confirmation it gave had already been used', 'bettershield' ),
		bettershield_confirmation_withdrawn: __( 'The confirmation it gave was withdrawn', 'bettershield' ),
		bettershield_human_only: __( 'Only a person can make this change', 'bettershield' ),
		bettershield_irreversible_refused: __( 'This cannot be undone, so it waits for a person', 'bettershield' ),
		bettershield_recovery_unverified: __( 'Your recovery options haven’t been checked in the last 24 hours', 'bettershield' ),
		bettershield_state_moved: __( 'The site changed after the fix was suggested', 'bettershield' ),
		bettershield_state_busy: __( 'Another change was in progress', 'bettershield' ),
		bettershield_revert_busy: __( 'Another undo was in progress', 'bettershield' ),
		bettershield_open_proposals: __( 'Too many suggested fixes are already waiting', 'bettershield' ),
		bettershield_write_denied: __( 'Changes by assistants are switched off', 'bettershield' ),
		bettershield_read_abilities_off: __( 'Agent read access is switched off', 'bettershield' ),
		bettershield_network_only: __( 'Only the network can change this', 'bettershield' ),
		bettershield_unknown_item: __( 'No protection by that name', 'bettershield' ),
		bettershield_item_missing: __( 'Name the protection to apply', 'bettershield' ),
		bettershield_bad_options: __( 'The settings it asked for are not allowed', 'bettershield' ),
		// Said as it stood then: the cause is on the item's own card now (#2235).
		bettershield_unavailable: __( 'That protection could not be applied on this site at the time', 'bettershield' ),
		bettershield_already_active: __( 'It was already on', 'bettershield' ),
		bettershield_not_active: __( 'It was already off', 'bettershield' ),
		bettershield_not_applied: __( 'It was already off', 'bettershield' ),
		bettershield_unknown_undo: __( 'No such change to undo', 'bettershield' ),
		bettershield_already_reverted: __( 'That change was already undone', 'bettershield' ),
		bettershield_ledger_failed: __( 'The undo record could not be saved, so nothing changed', 'bettershield' ),
		bettershield_undo_unavailable: __( 'The undo record could not be saved, so nothing changed', 'bettershield' ),
		bettershield_not_restorable: __( 'This file cannot be put back from an official copy', 'bettershield' ),
		bettershield_unknown_plugin: __( 'No plugin by that name', 'bettershield' ),
		bettershield_plugin_not_active: __( 'That plugin was not active', 'bettershield' ),
		// Putting a file back, keeping the old one and taking it back (#2214).
		bettershield_file_changed: __( 'The file changed after review, so nothing was replaced', 'bettershield' ),
		bettershield_file_changed_since: __( 'The file changed after it was put back, so nothing was written', 'bettershield' ),
		bettershield_file_gone_since: __( 'The file was removed after it was put back, so nothing was written', 'bettershield' ),
		bettershield_file_busy: __( 'Another request was changing this file', 'bettershield' ),
		bettershield_restore_busy: __( 'Another request was putting this file back', 'bettershield' ),
		bettershield_file_missing: __( 'The file is missing', 'bettershield' ),
		bettershield_file_exists: __( 'A file this plugin did not create is already there', 'bettershield' ),
		bettershield_file_unreadable: __( 'The file could not be read', 'bettershield' ),
		bettershield_file_unwritable: __( 'The host does not let this plugin write the file', 'bettershield' ),
		bettershield_file_too_large: __( 'The file is over the size limit', 'bettershield' ),
		bettershield_file_ambiguous: __( 'The block appears more than once in the file', 'bettershield' ),
		bettershield_file_no_anchor: __( 'The file has an unfamiliar layout', 'bettershield' ),
		bettershield_block_changed: __( 'The block was edited, so undo left it alone', 'bettershield' ),
		bettershield_bad_path: __( 'The record names a file outside this WordPress installation', 'bettershield' ),
		bettershield_unknown_change: __( 'No such file change on record', 'bettershield' ),
		bettershield_change_not_open: __( 'That file change was already dealt with', 'bettershield' ),
		bettershield_change_already_suppressed: __( 'That file change was already accepted', 'bettershield' ),
		bettershield_change_not_suppressed: __( 'That file change is not accepted', 'bettershield' ),
		bettershield_not_published: __( 'The file is not in that version’s published list', 'bettershield' ),
		bettershield_not_in_package: __( 'The file is not among the plugin’s recorded differences', 'bettershield' ),
		bettershield_official_unreachable: __( 'The official copy could not be fetched', 'bettershield' ),
		bettershield_official_mismatch: __( 'The downloaded copy did not match the published checksum', 'bettershield' ),
		bettershield_official_unusable: __( 'The official copy came back empty or too large', 'bettershield' ),
		bettershield_restore_batch_size: __( 'Too many changes were asked for at once', 'bettershield' ),
		bettershield_no_quarantine: __( 'There is nowhere to keep the old file', 'bettershield' ),
		bettershield_seal_not_read: __( 'This server does not read the folder’s own rule', 'bettershield' ),
		bettershield_seal_custom: __( 'The folder has rules of its own', 'bettershield' ),
		bettershield_mode_changed: __( 'The folder’s permissions changed since', 'bettershield' ),
		bettershield_domain_check_soon: __( 'The records were asked for a moment ago', 'bettershield' ),
		bettershield_login_address_same: __( 'That address is already in use', 'bettershield' ),
		bettershield_mode_unchanged: __( 'The folder’s permissions could not be changed', 'bettershield' ),
		bettershield_mode_refused: __( 'That folder is left alone here', 'bettershield' ),
		bettershield_quarantine_missing: __( 'The kept copy is gone', 'bettershield' ),
		bettershield_quarantine_unreadable: __( 'The kept copy could not be read', 'bettershield' ),
		bettershield_quarantine_altered: __( 'The kept copy no longer matches what was stored', 'bettershield' ),
		bettershield_quarantine_unknown: __( 'No kept copy by that name', 'bettershield' ),
		bettershield_quarantine_not_removed: __( 'The kept copy could not be removed', 'bettershield' ),
		bettershield_quarantine_batch_size: __( 'Too many kept copies were asked for at once', 'bettershield' ),
		bettershield_quarantine_empty: __( 'There is nothing in quarantine', 'bettershield' ),
		bettershield_quarantine_no_uploads: __( 'The site has no uploads folder for the archive', 'bettershield' ),
		bettershield_quarantine_not_packaged: __( 'The archive could not be written', 'bettershield' ),
		bettershield_corrupt_record: __( 'The undo record is incomplete', 'bettershield' ),
		bettershield_unknown_token: __( 'No undo record exists for that change', 'bettershield' ),
		bettershield_unknown_mode: __( 'That undo record is not a file change', 'bettershield' ),
	};

	return reasons[ code ] || '';
}

/**
 * What no connection and no switch ever lets an agent do, as the chips on
 * Connect and on Permissions say it: one list, one wording (#2828).
 *
 * @return {string[]} The chips, in order.
 */
export function neverDone() {
	return [
		__( 'Making an account or a credential', 'bettershield' ),
		__( 'Changing the recovery link or recovery codes', 'bettershield' ),
		__( 'Turning off two-factor or email alerts', 'bettershield' ),
		__( 'Lifting a lockout', 'bettershield' ),
		__( 'Removing rows from the log', 'bettershield' ),
		__( 'Editing core server files (wp-config.php, .htaccess)', 'bettershield' ),
	];
}
