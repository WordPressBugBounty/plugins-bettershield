/**
 * The Findings report's rules: where each finding is listed, what a search
 * keeps, how rows group, and what the groups and the score add up to.
 */

import { _n, sprintf } from '@wordpress/i18n';
import { SEVERITIES, pointsOff } from './overview';

/** The report's tabs, in the design's order. */
export const STATUSES = [ 'open', 'snoozed', 'fixed', 'suppressed', 'all' ];

/** How many of the impact meter's four segments each severity lights. */
export const METER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Where a finding is listed: a snoozed one is still open, but listed apart. */
export const viewOf = ( finding ) => ( finding.snoozed_until && 'open' === finding.status ? 'snoozed' : finding.status );

/**
 * @param {Array<Object>} all Every finding.
 * @return {Object<string, number>} How many each tab lists.
 */
export function statusCounts( all ) {
	const counts = { open: 0, snoozed: 0, fixed: 0, suppressed: 0, all: all.length };

	all.forEach( ( finding ) => {
		const view = viewOf( finding );

		if ( undefined !== counts[ view ] ) {
			counts[ view ] += 1;
		}
	} );

	return counts;
}

export const listed = ( all, status ) => ( 'all' === status ? all : all.filter( ( finding ) => viewOf( finding ) === status ) );

/**
 * Whether a finding answers a search: by its title or its area's name, the
 * two things a row is remembered by.
 */
export function answers( finding, query, areaLabel ) {
	const needle = String( query || '' ).trim().toLowerCase();

	if ( ! needle ) {
		return true;
	}

	return [ finding.title, areaLabel ].some( ( text ) => String( text || '' ).toLowerCase().includes( needle ) );
}

/**
 * Rows grouped by severity, worst first, or by area, the area with the
 * worst finding first. Rows keep the server's order inside a group.
 *
 * @param {Array<Object>} rows The rows on show.
 * @param {string}        by   severity or category.
 * @return {Array<{key: string, rows: Array<Object>, points: number}>} The groups.
 */
export function groupRows( rows, by ) {
	const groups = new Map();
	const keyOf = ( finding ) => ( 'category' === by ? finding.group || '' : finding.severity );

	rows.forEach( ( finding ) => {
		const key = keyOf( finding );

		if ( ! groups.has( key ) ) {
			groups.set( key, [] );
		}

		groups.get( key ).push( finding );
	} );

	// A severity this screen does not know ranks after the ones it does, and
	// its group is listed last rather than left out with its findings.
	const rank = ( severity ) => ( SEVERITIES.includes( severity ) ? SEVERITIES.indexOf( severity ) : SEVERITIES.length );
	const worst = ( list ) => Math.min( ...list.map( ( finding ) => rank( finding.severity ) ) );
	const order =
		'category' === by
			? [ ...groups.keys() ].sort( ( a, b ) => worst( groups.get( a ) ) - worst( groups.get( b ) ) )
			: [ ...SEVERITIES.filter( ( severity ) => groups.has( severity ) ), ...[ ...groups.keys() ].filter( ( key ) => ! SEVERITIES.includes( key ) ) ];

	return order.map( ( key ) => ( { key, rows: groups.get( key ), points: openPointsOff( groups.get( key ) ) } ) );
}

/**
 * Whether a finding costs points now: an open one, unless a Fix on this
 * screen has just closed it and the report has not been read since.
 *
 * @param {Object} finding The finding.
 * @return {boolean} Whether it counts.
 */
export const costs = ( finding ) => 'open' === finding.status && ! finding.fixed_now;

/**
 * Points off the score from the rows that cost any: the open ones. A fixed
 * or not-applicable finding keeps its deduction on record and costs nothing.
 *
 * @param {Array<Object>} rows   The rows on show.
 * @param {number}        health What site health is worth, where it is known.
 * @return {number} The points.
 */
export const openPointsOff = ( rows, health = Infinity ) => pointsOff( rows.filter( costs ), health );

/**
 * The hero's history clause: how the score moved across the recorded days,
 * or nothing before there are two of them. It is one item of the hero's
 * "·"-separated stats line, so like the others it has no full stop.
 *
 * @param {Array<{at: string, score: number}>} points Usable samples, oldest first.
 * @return {string} The clause, or an empty string.
 */
export function historyClause( points ) {
	if ( points.length < 2 ) {
		return '';
	}

	const first = Number( points[ 0 ].score );
	const last = Number( points[ points.length - 1 ].score );

	return first === last
		? sprintf(
				/* translators: 1: number of recorded days, 2: the score. */
				_n( 'Across %1$d recorded day the score has held at %2$d', 'Across %1$d recorded days the score has held at %2$d', points.length, 'bettershield' ),
				points.length,
				last
		  )
		: sprintf(
				/* translators: 1: number of recorded days, 2: the earlier score, 3: the score now. */
				_n(
					'Across %1$d recorded day the score moved from %2$d to %3$d',
					'Across %1$d recorded days the score moved from %2$d to %3$d',
					points.length,
					'bettershield'
				),
				points.length,
				first,
				last
		  );
}
