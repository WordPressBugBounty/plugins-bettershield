/**
 * The Overview's numbers, worked out from the audit the store holds. Pure
 * functions, so each rule the design draws is one place to read and test.
 */

import { __, sprintf } from '@wordpress/i18n';

export const SEVERITIES = [ 'critical', 'high', 'medium', 'low', 'info' ];

/** The ticks the severity bar is drawn with, at any count of findings. */
export const BAR_TICKS = 90;

/** The design's tile icon for each area a finding belongs to. */
export const AREA_ICONS = {
	extensions: 'package',
	access: 'lock',
	server: 'server',
	exposure: 'globe',
	configuration: 'settings-2',
	plugin: 'shield',
};

export const areaIcon = ( group ) => AREA_ICONS[ group ] || 'shield';

/**
 * Open findings by severity.
 *
 * @param {Array<Object>} findings The open findings.
 * @return {Object<string, number>} A count for each of the five severities.
 */
export function severityCounts( findings ) {
	const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

	findings.forEach( ( finding ) => {
		if ( undefined !== counts[ finding.severity ] ) {
			counts[ finding.severity ] += 1;
		}
	} );

	return counts;
}

/**
 * How the score was reached: its setup and site-health parts, and the cap a
 * critical finding holds it at. Empty where the payload has no parts.
 *
 * @param {Object} overview The overview payload.
 * @return {string} One line, e.g. "Setup 54/60 · Site health 31/40".
 */
export function scoreSplit( overview ) {
	const buckets = overview && overview.buckets;

	if ( ! buckets || ! buckets.setup || ! buckets.health ) {
		return '';
	}

	const line = sprintf(
		/* translators: 1: setup points earned, 2: setup points possible, 3: site health points earned, 4: site health points possible. */
		__( 'Setup %1$d/%2$d · Site health %3$d/%4$d', 'bettershield' ),
		Number( buckets.setup.earned ) || 0,
		Number( buckets.setup.of ) || 0,
		Number( buckets.health.earned ) || 0,
		Number( buckets.health.of ) || 0
	);

	return buckets.capped
		? line +
				' · ' +
				sprintf(
					/* translators: %d: the highest score allowed while a critical finding is open. */
					__( 'Held at %d while a critical finding is open', 'bettershield' ),
					Number( buckets.cap ) || 0
				)
		: line;
}

/**
 * The points a set of findings takes off the score, counted the way the
 * score counts them: a setup item two findings share costs its points once,
 * and site health stops at its floor. Added up plainly, the Open findings
 * badge said more points than the header above it (#2512).
 *
 * @param {Array}  findings The findings.
 * @param {number} healthOf What site health is worth, where it is known.
 * @return {number} Points off the score.
 */
export function pointsOff( findings, healthOf = Infinity ) {
	const items = new Map();
	let health = 0;

	findings.forEach( ( finding ) => {
		const points = Number( finding.deduction ) || 0;

		if ( finding.score_item ) {
			items.set( finding.score_item, points );
		} else {
			health += points;
		}
	} );

	return [ ...items.values() ].reduce( ( sum, points ) => sum + points, 0 ) + Math.min( health, healthOf );
}

/**
 * What site health is worth, from the overview, for pointsOff().
 *
 * @param {Object} overview The overview, or null before it is read.
 * @return {number} Its points, or Infinity where they are not known.
 */
export function healthOf( overview ) {
	return Number( overview && overview.buckets && overview.buckets.health && overview.buckets.health.of ) || Infinity;
}

/**
 * The severity bar: its ticks shared out by how many findings each severity
 * holds, so the bar always has the same length. Remainders go to the largest
 * fractions, so the shares always add up to the whole bar.
 *
 * @param {Object<string, number>} counts From severityCounts().
 * @param {number}                 total  The ticks to share.
 * @return {Array<number>} Ticks per severity, in SEVERITIES order.
 */
export function severityTicks( counts, total = BAR_TICKS ) {
	const sum = SEVERITIES.reduce( ( all, key ) => all + counts[ key ], 0 );

	if ( ! sum ) {
		return SEVERITIES.map( () => 0 );
	}

	const exact = SEVERITIES.map( ( key ) => ( counts[ key ] / sum ) * total );
	const ticks = exact.map( Math.floor );
	let left = total - ticks.reduce( ( all, n ) => all + n, 0 );

	exact
		.map( ( value, index ) => ( { index, rest: value - Math.floor( value ) } ) )
		.sort( ( a, b ) => b.rest - a.rest || a.index - b.index )
		.forEach( ( { index } ) => {
			if ( left > 0 ) {
				ticks[ index ] += 1;
				left -= 1;
			}
		} );

	return ticks;
}

/**
 * Whether a finding is snoozed. A snoozed finding is still open and still
 * counted in the score; it is only left out of what the Overview asks for
 * next, as the sidebar's count leaves it out.
 */
export const isSnoozed = ( finding ) => Boolean( finding.snoozed_until );

/** The open findings that are not snoozed. */
export const awake = ( findings ) => findings.filter( ( finding ) => ! isSnoozed( finding ) );

/**
 * When the first snoozed finding comes back, or null when none is snoozed.
 * Stamped by one clock in one format, so the earliest sorts first.
 */
export const firstBack = ( findings ) =>
	findings
		.map( ( finding ) => finding.snoozed_until )
		.filter( Boolean )
		.sort()[ 0 ] || null;

/** Whether a finding can be fixed in one click now. */
export const isOneClick = ( finding ) => Boolean( finding.remediable && finding.hardening_item && ! finding.hardening_active );

/**
 * Findings fixed by one press of an action that already has a route: a new
 * recovery link, a check run again, storage repaired, the contact renewed
 * (#1944). They rank with the one-click fixes in what to do first, and stay
 * out of what applying fixes would add to the score, since a check can come
 * back with more findings.
 */
export const ONE_PRESS = [ 'recovery_link_lapsing', 'vulnerability_data_stale', 'files_never_checked', 'schema_storage_unavailable', 'claims_unreadable', 'disclosure_contact_lapsing' ];

/** Whether a finding is fixed by one press: a one-click fix, or one of those. */
const onePress = ( finding ) => isOneClick( finding ) || ONE_PRESS.includes( finding.id );

/**
 * The hero's goal: what fixing the high-severity findings (critical and high)
 * would make the score. A snoozed one is not asked for, but its points still
 * come off the score it would reach.
 *
 * The score it would reach is the server's own, worked out with the same
 * calculation as the score: the setup and health parts each stop at their
 * floor and a critical finding holds the total down, so adding points up
 * here would promise a number the fixes cannot reach.
 *
 * @param {Array<Object>} findings The open findings.
 * @param {number}        score    The score now.
 * @param {number}        reached  `serious_fixed_score` from the overview.
 * @return {{count: number, target: number, gain: number, oneClick: number}} How many, the score after, the points gained, and how many of them are one-click.
 */
export function goal( findings, score, reached ) {
	const serious = awake( findings ).filter( ( finding ) => 'critical' === finding.severity || 'high' === finding.severity );
	const target = Number.isFinite( Number( reached ) ) && null !== reached && undefined !== reached ? Number( reached ) : Number( score ) || 0;

	return {
		count: serious.length,
		target,
		gain: Math.max( 0, target - ( Number( score ) || 0 ) ),
		oneClick: serious.filter( isOneClick ).length,
	};
}

/**
 * The findings worth doing first: one-press fixes first, then the rest, each
 * by the points it is worth, at most three. One already partly handled, such
 * as XML-RPC with its pingbacks blocked, stays in the full list only.
 *
 * @param {Array<Object>} findings The open findings, in the server's order.
 * @param {number}        limit    How many.
 * @return {Array<Object>} The findings to show.
 */
export function doFirst( findings, limit = 3 ) {
	return findings
		.filter( ( finding ) => ! finding.partly_handled )
		.map( ( finding, index ) => ( { finding, index } ) )
		.sort(
			( a, b ) =>
				Number( onePress( b.finding ) ) - Number( onePress( a.finding ) ) ||
				( Number( b.finding.deduction ) || 0 ) - ( Number( a.finding.deduction ) || 0 ) ||
				a.index - b.index
		)
		.slice( 0, limit )
		.map( ( { finding } ) => finding );
}

/**
 * The first sentence of a passage, for a one-line summary.
 *
 * @param {string} text The passage.
 * @return {string} Up to and including its first full stop.
 */
export function firstSentence( text ) {
	const value = String( text || '' ).trim();
	const match = value.match( /^.*?[.!?](?=\s|$)/ );

	return match ? match[ 0 ] : value;
}

/**
 * How many checks the last audit actually got an answer from.
 *
 * A check whose evidence could not be gathered keeps whatever it reported
 * last rather than being overwritten with a false negative, which leaves the
 * run partial. Reporting the total as though every check had answered turns
 * an older result into a current one on the line the score is read for.
 *
 * @param {Object} data The overview payload.
 * @return {{ran: number, total: number, missed: number}} What answered, out of what.
 */
export function coverage( data ) {
	const total = Math.max( 0, Number( data.checks_count ) || 0 );
	// Absent on a payload built before the run counted them, which is not the
	// same as a run in which checks failed.
	const ran = undefined === data.checks_ran ? total : Math.max( 0, Math.min( total, Number( data.checks_ran ) || 0 ) );

	return { ran, total, missed: total - ran };
}
