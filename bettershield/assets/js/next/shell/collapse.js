/**
 * Whether the sidebar is folded to its marks, and where that choice is kept.
 *
 * A browser preference, for the reason the color scheme is one: one value
 * per person per browser, never worth a round trip, and a screen that waited
 * on a REST write to fold its own sidebar would feel slower than the audit.
 * Storage that refuses to answer (a locked-down browser, private browsing)
 * is an open sidebar that still folds for the visit.
 */

import { useCallback, useEffect, useState } from '@wordpress/element';

export const STORAGE_KEY = 'bettershield-sidebar';

const FOLDED = 'collapsed';
const OPEN = 'expanded';

/**
 * @return {boolean} Whether the reader last left the sidebar folded.
 */
export function readCollapsed() {
	try {
		return FOLDED === window.localStorage.getItem( STORAGE_KEY );
	} catch ( error ) {
		return false;
	}
}

function writeCollapsed( collapsed ) {
	try {
		window.localStorage.setItem( STORAGE_KEY, collapsed ? FOLDED : OPEN );
	} catch ( error ) {
		// Kept for this visit only. Nothing to report and nothing to retry.
	}
}

/**
 * @return {[boolean, Function]} Whether it is folded, and the press that turns it over.
 */
export function useCollapsed() {
	const [ collapsed, setCollapsed ] = useState( readCollapsed );
	const toggle = useCallback( () => setCollapsed( ( was ) => ! was ), [] );

	useEffect( () => {
		writeCollapsed( collapsed );
	}, [ collapsed ] );

	return [ collapsed, toggle ];
}
