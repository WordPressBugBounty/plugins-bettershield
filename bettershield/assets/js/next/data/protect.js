/**
 * The numbers Protect's strips are drawn from, worked out from what the store
 * holds. Pure functions, so each rule the strip states is one place to read
 * and test.
 */

import { readableHistory } from '../../ui/scoreHistory';

/**
 * A grade is overall posture, not a severity: the good grades in brand, the
 * middling ones in yellow and the poor ones in orange. Red stays reserved for
 * critical findings.
 */
const GRADE_TONES = { A: 'brand', B: 'brand', C: 'yellow', D: 'yellow', E: 'orange', F: 'orange' };

/**
 * @param {string} grade A letter grade, A through F.
 * @return {string} The Badge tone it is drawn in.
 */
export function gradeTone( grade ) {
	return GRADE_TONES[ grade ] || 'neutral';
}

/**
 * What the one-click fixes on offer are worth: every open, not snoozed,
 * one-click fix whose hardening is not already on. A snoozed finding still
 * counts in the score; the fixes leave it out, as the lists offering them do.
 *
 * The score they would reach is the server's `projected_score`, worked out
 * with the same calculation as the score on exactly these findings removed.
 * Adding their points to the score instead would promise a number the fixes
 * cannot reach: each part of the score stops at its floor, and a critical
 * finding holds the total down.
 *
 * @param {Object} data The overview payload.
 * @return {{fixes: number, worth: number, reachable: number}} How many fixes, the points they would gain, and the score they would reach (0 where none can be promised).
 */
export function fixesWorth( data ) {
	const open = ( data.findings || [] ).filter( ( finding ) => ! finding.snoozed_until );
	const applicable = open.filter( ( finding ) => finding.remediable && ! finding.hardening_active );
	const audited = Boolean( data.generated_at );
	const score = audited ? Number( data.score ) || 0 : 0;
	const reachable = audited && Number.isFinite( Number( data.projected_score ) ) ? Number( data.projected_score ) : 0;

	return {
		fixes: applicable.length,
		worth: audited ? Math.max( 0, reachable - score ) : 0,
		reachable,
	};
}

/**
 * Of the checks that could not be evaluated, the ones that have never
 * answered at all, which have no earlier result to stand from (on a new site,
 * every one of them), and the ones keeping the result they last had. A
 * payload that does not name them counts every one as kept.
 *
 * @param {Object} data   The overview payload.
 * @param {number} missed How many checks could not be evaluated.
 * @return {{never: number, kept: number}} The two counts.
 */
export function unanswered( data, missed ) {
	const unknown = Array.isArray( data.checks_unknown ) ? data.checks_unknown : [];
	const never = Math.min( missed, unknown.filter( ( check ) => ! check.last_answered_at ).length );

	return { never, kept: missed - never };
}

/** At most this many recorded days are read for the score's movement. */
export const RECENT_DAYS = 30;

/**
 * The recorded days the score's movement is said over: the most recent
 * thirty, oldest first. One day is not a movement, so fewer than two give
 * nothing to say.
 *
 * @param {Array<{at: string, score: number}>|undefined} history The overview's history.
 * @return {Array<{at: string, score: number}>} The days, or none.
 */
export function recentScores( history ) {
	const all = readableHistory( history );

	return all.length < 2 ? [] : all.slice( -RECENT_DAYS );
}
