/**
 * The rules behind what Protection › Recovery says about the way back in: where
 * the recovery link stands, and how each readiness check came out.
 *
 * Read by the tab's strip and by its readiness card, so the two cannot
 * disagree about a link or a count.
 */

import { __ } from '@wordpress/i18n';

/**
 * No printed codes, in words: none issued yet, or a set whose every code has
 * been used. "None issued" of a set used up was untrue, as "0 left" was of
 * one never issued (#1931).
 *
 * @param {boolean} issued Whether a set was ever issued here.
 * @return {string} The words.
 */
export function noCodesWord( issued ) {
	return issued ? __( 'All used', 'bettershield' ) : __( 'None issued', 'bettershield' );
}

/**
 * Where the link stands, as one word for the strip. The readiness report is
 * the fuller answer (it knows about expiry and a refused email), so it is read
 * first, and the overview's two flags only when there is no report.
 *
 * @param {Object} data The overview payload.
 * @return {string} available, missing, expired or refused.
 */
export function linkState( data ) {
	const report = data.recovery_readiness;

	if ( report && report.link ) {
		return report.link;
	}

	if ( ! data.recovery_link_exists ) {
		return 'missing';
	}

	return false === data.recovery_link_mailed ? 'refused' : 'available';
}

/*
 * What each check's answer means for the one question the card exists for:
 * would the way back in work today. "good" is evidence it would; "attention"
 * is something to do; "idle" is a check that has not been asked to run, which
 * is neither a pass nor a fault.
 */

/**
 * @param {Object} report The readiness report.
 * @return {string} good or attention.
 */
export function linkTone( report ) {
	return 'available' === report.link ? 'good' : 'attention';
}

/**
 * @param {Object} report The readiness report.
 * @return {string} good, idle or attention.
 */
export function mailTone( report ) {
	if ( 'accepted' === report.mail ) {
		return 'good';
	}

	return 'off' === report.mail || 'untested' === report.mail ? 'idle' : 'attention';
}

/**
 * How many of the checks answered well, for the strip.
 *
 * Out of the four the card lists, always: leaving the weekly email check out
 * while it is off read "2 of 3" above a card of four (#2574). Off counts as
 * not checked, as untested does.
 *
 * @param {?Object} report The readiness report.
 * @return {{ good: number, total: number }} The count.
 */
export function readinessCount( report ) {
	if ( ! report ) {
		return { good: 0, total: 4 };
	}

	const tones = [
		linkTone( report ),
		report.offline_codes > 0 ? 'good' : 'attention',
		report.administrators_with_email > 0 ? 'good' : 'attention',
		mailTone( report ),
	];

	return { good: tones.filter( ( tone ) => 'good' === tone ).length, total: tones.length };
}
