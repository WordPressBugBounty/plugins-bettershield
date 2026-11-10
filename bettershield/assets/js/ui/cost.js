/**
 * How the measured front-end cost is worded.
 *
 * Kept apart from the panel that shows it because the wording is the part with
 * a rule in it, and a rule worth testing: a measurement is allowed to round for
 * reading, and is never allowed to round down into a claim it does not support.
 * Below the threshold the answer is "under", not "none" — "0 ms" reads as a
 * promise, and this feature exists because promises in this category are worth
 * less than numbers.
 */

import { __, sprintf } from '@wordpress/i18n';

/** Under this many queries per page, the average is stated as none. */
const NO_QUERIES_BELOW = 0.005;

/** Under this many milliseconds, the figure is smaller than it is worth printing. */
const NO_TIME_BELOW = 0.01;

export function queryPhrase( queries ) {
	if ( queries < NO_QUERIES_BELOW ) {
		return __( 'no database queries', 'bettershield' );
	}

	return sprintf(
		/* translators: %s: an average number of database queries, e.g. 0.05. */
		__( '%s database queries', 'bettershield' ),
		queries
	);
}

export function timePhrase( ms ) {
	if ( ms < NO_TIME_BELOW ) {
		return __( 'under a hundredth of a millisecond', 'bettershield' );
	}

	return sprintf(
		/* translators: %s: a duration in milliseconds, e.g. 0.42. */
		__( '%s ms', 'bettershield' ),
		ms
	);
}

/**
 * The sentence itself, or null when there is nothing honest to say yet.
 */
export function costHeadline( cost ) {
	if ( ! cost ) {
		return null;
	}

	return sprintf(
		/* translators: 1: number of page views, 2: a number of database queries, 3: a duration. */
		__( 'Over the last %1$s page views, BetterShield added %2$s and %3$s.', 'bettershield' ),
		new Intl.NumberFormat().format( cost.pages ),
		queryPhrase( cost.queries ),
		timePhrase( cost.ms )
	);
}
