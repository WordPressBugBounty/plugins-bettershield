/**
 * How a finding says that its list was cut short.
 *
 * Kept apart from the screen for the reason the cost wording is: the rule is
 * the part worth testing. Several findings cap their named lists — dormant privileged accounts,
 * mixed-content posts, and broken log seals — while a site can have many more. With no total on the screen, the number of
 * names *was* the number, so ten of ten and ten of forty were the same
 * finding, on checks whose whole point is the count.
 *
 * The other half of the rule: a total that was itself capped is stated as a
 * floor. Saying "of 200" when the pass stopped at two hundred would replace
 * one silent cap with a confident wrong number.
 *
 * And a third shape: a check that asks about a few plugins per run has, for
 * its first days, looked at a fraction of the site. Everything it found is on
 * the screen and the list is still short of the truth, so it says how far it
 * has got rather than nothing.
 */

import { __, sprintf } from '@wordpress/i18n';

/**
 * The sentence a finding's evidence owes about its own completeness, or null
 * when the list on screen is the whole of it.
 *
 * @param {Object} evidence The finding's evidence.
 * @return {?string} The note, or null.
 */
/**
 * The keys a check writes its list under. A closed set, because the note is a
 * claim about that list's length.
 */
const LIST_KEYS = [ 'accounts', 'plugins', 'files', 'events', 'posts', 'days' ];

export function truncationNote( evidence ) {
	if ( ! evidence || typeof evidence !== 'object' ) {
		return null;
	}

	const total = Number( evidence.total );

	if ( ! Number.isFinite( total ) || total <= 0 ) {
		return null;
	}

	/*
	 * By name rather than "whichever array comes first". Insertion order is
	 * not a contract, and an evidence payload that grows a second list would
	 * silently change which one this note is counting.
	 */
	const named = LIST_KEYS.map( ( key ) => evidence[ key ] ).find( Array.isArray );
	const shown = Array.isArray( named ) ? named.length : 0;

	if ( ! shown ) {
		return null;
	}

	if ( shown >= total ) {
		return sweepNote( evidence );
	}

	if ( evidence.complete === false ) {
		return sprintf(
			/* translators: 1: how many items are listed, 2: the smallest number there could be. */
			__( 'Showing %1$d of at least %2$d. One pass does not reach everything, so there may be more.', 'bettershield' ),
			shown,
			total
		);
	}

	return sprintf(
		/* translators: 1: how many items are listed, 2: how many there are. */
		__( 'Showing %1$d of %2$d.', 'bettershield' ),
		shown,
		total
	);
}

/**
 * The note a finding owes when everything it found is on the screen and it
 * has not yet looked everywhere: how many plugins the sweep has asked about,
 * out of how many there are to ask about. Null unless the evidence carries
 * both counts and says the pass is not complete.
 *
 * @param {Object} evidence The finding's evidence.
 * @return {?string} The note, or null.
 */
function sweepNote( evidence ) {
	if ( evidence.complete !== false ) {
		return null;
	}

	const checked = Number( evidence.checked );
	const unchecked = Number( evidence.unchecked );

	if ( ! Number.isFinite( checked ) || ! Number.isFinite( unchecked ) || unchecked <= 0 ) {
		return null;
	}

	return sprintf(
		/* translators: 1: how many plugins have been asked about, 2: how many there are to ask about. */
		__( 'Checked %1$d of %2$d plugins so far. The rest follow over the coming days.', 'bettershield' ),
		checked,
		checked + unchecked
	);
}
