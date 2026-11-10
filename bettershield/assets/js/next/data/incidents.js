/**
 * The rules behind the incident screens: what a correlation claims, in
 * words; how a long timeline folds; the days an incident covers, in the
 * reader's calendar; and what a response's second look and its left-over
 * candidates are called.
 *
 * Read by the redrawn Incidents tab, by the Overview's Activity card, and by
 * the classic screens the network admin still draws, so the words are kept
 * in one place.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

/** How many evidence records a timeline lists before the rest wait behind "Show all". */
export const TIMELINE_SHOWN = 20;

/**
 * What a correlation claims, as an incident's title.
 *
 * @param {string} confidence The incident's confidence key.
 * @return {string} The claim.
 */
export function confidenceLabel( confidence ) {
	return ( { review: __( 'Related changes worth a look', 'bettershield' ), pattern: __( 'Changes to sign-ins and files happened close together', 'bettershield' ), linked_access: __( 'One account made several sign-in or role changes', 'bettershield' ), decoy_used: __( 'Someone tried to sign in with the decoy credential', 'bettershield' ) } )[ confidence ] || __( 'Related changes worth a look', 'bettershield' );
}

/**
 * Which folded row a file record belongs to: the plugin or theme folder (the
 * two segments after wp-content, or the top folder otherwise), its kind, and
 * the hour. Anything that is not a file has none, and keeps its own card.
 *
 * @param {Object} e An evidence record.
 * @return {?{key: string, name: string}} The fold, or null.
 */
function fileFold( e ) {
	if ( 'file' !== e.snapshot?.object_type || ! e.snapshot?.object_id ) {
		return null;
	}

	const parts = String( e.snapshot.object_id ).split( '/' );
	const inside = 'wp-content' === parts[ 0 ] ? parts.slice( 1, 3 ) : parts.slice( 0, 1 );

	// By the plugin's or theme's own name where the server knows it, as the
	// rest of the plugin says it, not by its folder (#2484).
	return { key: `${ inside.join( '/' ) }|${ e.type }|${ String( e.occurred_at ).slice( 0, 13 ) }`, name: e.package_name || inside[ inside.length - 1 ] };
}

/**
 * Consecutive file records that share a folder, a kind and an hour, as one
 * row. A plugin update was one card per file: hundreds of rows saying the
 * same thing, with the account and setting changes far below them.
 *
 * @param {Object[]} sorted The records, oldest first.
 * @return {Array<{fold: ?Object, records: Object[]}>} The rows.
 */
export function foldTimeline( sorted ) {
	const rows = [];

	sorted.forEach( ( e ) => {
		const fold = fileFold( e );
		const last = rows[ rows.length - 1 ];

		if ( fold && last && last.fold && last.fold.key === fold.key ) {
			last.records.push( e );
			return;
		}

		rows.push( { fold, records: [ e ] } );
	} );

	return rows;
}

/**
 * A recorded day as a short date, read at noon so no time zone moves it.
 *
 * @param {string} day YYYY-MM-DD.
 * @return {string} The date, or the day as given when it cannot be read.
 */
export function dayText( day ) {
	const date = new Date( `${ day }T12:00:00` );

	return Number.isNaN( date.getTime() ) ? day : date.toLocaleDateString( undefined, { month: 'short', day: 'numeric' } );
}

/**
 * A moment as the day it falls on in the reader's calendar, or '' for none.
 *
 * @param {?string} iso An ISO 8601 moment.
 * @return {string} YYYY-MM-DD.
 */
export function readerDay( iso ) {
	const date = iso ? new Date( iso ) : null;

	if ( ! date || Number.isNaN( date.getTime() ) ) {
		return '';
	}

	return [ date.getFullYear(), String( date.getMonth() + 1 ).padStart( 2, '0' ), String( date.getDate() ).padStart( 2, '0' ) ].join( '-' );
}

/**
 * What each state of a re-checked line is called.
 *
 * @param {string} status The line's state.
 * @return {string} Its name.
 */
export function recheckStatus( status ) {
	return ( {
		open: __( 'Still open', 'bettershield' ),
		closed: __( 'Fixed', 'bettershield' ),
		not_done: __( 'Not done', 'bettershield' ),
		manual: __( 'Do this yourself', 'bettershield' ),
		not_checked: __( 'Not checked', 'bettershield' ),
		checking: __( 'Still checking', 'bettershield' ),
	} )[ status ] || status;
}

/**
 * How many of one kind of action a plan left for manual review, as a phrase:
 * one plural per kind, so "1 role change" reads right and a translator can
 * decline and reorder each. A kind this screen has no words for is shown by
 * its key.
 *
 * @param {string} kind  The kind of action.
 * @param {number} count How many were left.
 * @return {string} The phrase.
 */
export function omittedCount( kind, count ) {
	const phrases = {
		/* translators: %d: how many role changes. */
		demote: () => _n( '%d role change', '%d role changes', count, 'bettershield' ),
		/* translators: %d: how many session revocations. */
		sessions: () => _n( '%d session revocation', '%d session revocations', count, 'bettershield' ),
		/* translators: %d: how many app passwords will be removed. */
		passwords: () => _n( '%d app password to remove', '%d app passwords to remove', count, 'bettershield' ),
		/* translators: %d: how many password resets. */
		reset: () => _n( '%d password reset', '%d password resets', count, 'bettershield' ),
		/* translators: %d: how many scheduled tasks. */
		cron: () => _n( '%d scheduled task', '%d scheduled tasks', count, 'bettershield' ),
		/* translators: %d: how many file restorations. */
		restore: () => _n( '%d file restoration', '%d file restorations', count, 'bettershield' ),
		/* translators: %d: how many file quarantines. */
		quarantine: () => _n( '%d file quarantine', '%d file quarantines', count, 'bettershield' ),
	};

	return phrases[ kind ] ? sprintf( phrases[ kind ](), count ) : `${ count } ${ kind }`;
}
