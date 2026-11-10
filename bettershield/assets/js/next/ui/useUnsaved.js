/**
 * Edits not yet saved, asked about before they are left behind.
 *
 * A screen that collects edits behind a save bar says so here while the bar
 * is up. A move to another screen or tab then asks first, and so does a
 * document load: the browser's own prompt, since a page cannot word that
 * one. Without it, a click in the sidebar dropped the edits without a word
 * (#1915).
 *
 * The holds live on the window, not in this module, because the add-on
 * bundles its own copy of this file: its screens hold the same set the
 * free plugin's moves ask about, and one listener serves both copies.
 */

import { useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

/**
 * The holds and the one listener, shared by every copy of this file.
 *
 * @return {{holders: Set, onBeforeUnload: Function}} The shared state.
 */
function shared() {
	if ( ! window.bettershieldUnsaved ) {
		window.bettershieldUnsaved = {
			// One entry per screen holding unsaved edits.
			holders: new Set(),
			onBeforeUnload( event ) {
				event.preventDefault();
				// Older browsers ask only when this is set.
				event.returnValue = '';
			},
		};
	}

	return window.bettershieldUnsaved;
}

/**
 * Whether a move may go ahead: yes when nothing is unsaved, otherwise
 * whatever the reader answers.
 *
 * @return {boolean} Whether to leave.
 */
export function confirmLeave() {
	if ( 0 === shared().holders.size ) {
		return true;
	}

	// eslint-disable-next-line no-alert -- a move has to wait for the answer.
	return window.confirm( __( 'You have unsaved changes. Leave without saving them?', 'bettershield' ) );
}

/**
 * Lets go of every hold, for a move already confirmed in the app: ending
 * your own session sends you to sign in, and the browser asked again on
 * the way out, over a session that was already gone.
 */
export function releaseUnsaved() {
	const { holders, onBeforeUnload } = shared();

	holders.clear();
	window.removeEventListener( 'beforeunload', onBeforeUnload );
}

/**
 * Holds the screen while `dirty` is true.
 *
 * @param {boolean} dirty Whether the screen has edits not yet saved.
 */
export default function useUnsaved( dirty ) {
	useEffect( () => {
		if ( ! dirty ) {
			return undefined;
		}

		const { holders, onBeforeUnload } = shared();
		const holder = {};

		holders.add( holder );
		window.addEventListener( 'beforeunload', onBeforeUnload );

		return () => {
			holders.delete( holder );

			if ( 0 === holders.size ) {
				window.removeEventListener( 'beforeunload', onBeforeUnload );
			}
		};
	}, [ dirty ] );
}
