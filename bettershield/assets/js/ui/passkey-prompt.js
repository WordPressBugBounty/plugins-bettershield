/**
 * The browser's passkey prompt, for the two screens that open one to add a
 * passkey: Protect › Two-factor and the profile.
 *
 * Where the browser hands the prompt to the operating system, that prompt is
 * a window of its own. It can open behind another app, and the request's
 * `timeout` does not close it, so the page can wait with nothing on screen and
 * nothing that would ever end the wait. An abort does close it, wherever it is.
 */

import { __ } from '@wordpress/i18n';

/** How long to wait before saying that the prompt may not be in view. */
export const PROMPT_HINT_AFTER_MS = 15000;

/** How long the prompt may stay open: what the request asks as its `timeout`. */
export const PROMPT_TIMEOUT_MS = 120000;

/**
 * A wait on the prompt: `signal` goes with the request, `stop` closes the
 * prompt, `stopped` says whether a person did, and `done` ends the deadline
 * once the request has settled.
 *
 * @return {{signal: AbortSignal, stop: Function, stopped: Function, done: Function}} The wait.
 */
export function promptWait() {
	const controller = new AbortController();
	let stopped = false;
	const deadline = window.setTimeout( () => controller.abort(), PROMPT_TIMEOUT_MS );

	return {
		signal: controller.signal,
		stop: () => {
			stopped = true;
			controller.abort();
		},
		stopped: () => stopped,
		done: () => window.clearTimeout( deadline ),
	};
}

/**
 * What to say when a person pressed Stop Waiting: they chose it, so it isn't a
 * warning.
 *
 * @return {string} The message.
 */
export function promptStoppedWords() {
	return __( 'Stopped. Nothing was changed. Try again when your device is ready.', 'bettershield' );
}

/**
 * Firefox on a Mac has no passkey store of its own: it saves through the
 * operating system, which asks for iCloud Keychain. A page cannot read whether
 * that is on, so this says "if", and it only chooses words.
 *
 * @return {boolean} Whether this browser saves passkeys through iCloud Keychain alone.
 */
function savesThroughICloud() {
	const agent = window.navigator.userAgent;

	return agent.includes( 'Macintosh' ) && agent.includes( 'Firefox/' );
}

/**
 * The sentence shown while the prompt has been open for a while.
 *
 * @return {string} The hint.
 */
export function promptHint() {
	return __( 'Finish the prompt from your browser or password manager. It can open behind another window, so check there first. If nothing appears, stop and try another browser.', 'bettershield' );
}

/**
 * What to say when the prompt closed or could not save, with the way forward
 * where this browser has one to name.
 *
 * @param {string} said What happened.
 * @return {string} The message.
 */
export function withPromptHelp( said ) {
	if ( ! savesThroughICloud() ) {
		return said;
	}

	return (
		said +
		' ' +
		__( 'On a Mac, Firefox saves passkeys in iCloud Keychain. Turn it on in System Settings, use a phone or security key from More Options, or try another browser.', 'bettershield' )
	);
}

/**
 * What to say when the prompt ended without a key, or null for a refusal that
 * each screen words itself.
 *
 * @param {string} name The name of the browser's error.
 * @return {string|null} The message.
 */
export function promptClosedWords( name ) {
	switch ( name ) {
		case 'NotAllowedError':
		case 'AbortError':
			return withPromptHelp( __( 'The passkey prompt was dismissed or timed out. Nothing was changed.', 'bettershield' ) );
		// The device would not store the key. The browser's own message for this
		// reads as a database error.
		// On Firefox for a Mac the iCloud Keychain help names the ways forward,
		// so the general advice is left off rather than said twice.
		case 'ConstraintError':
			return savesThroughICloud()
				? withPromptHelp( __( 'This device couldn’t save the passkey. Nothing was changed.', 'bettershield' ) )
				: __( 'This device couldn’t save the passkey. Nothing was changed. Try another device or a password manager.', 'bettershield' );
		default:
			return null;
	}
}
