/**
 * What the vulnerability check says when its source could not be reached
 * and no earlier result exists, written once for every screen that says it.
 *
 * Settings put "No check has run yet." above the failure, and the Findings
 * footer said the checks "have not run yet" and then that "the update
 * failed": a check had run, and both screens told it two ways (#2484).
 */

import { __, sprintf } from '@wordpress/i18n';

/**
 * Whether the last check failed to reach its source with nothing to show.
 *
 * @param {Object} feed The vulnerability feed's status.
 * @return {boolean} Whether there is no result because the source was out of reach.
 */
export function unreachedWithoutResults( feed ) {
	return Boolean(
		feed && feed.error && ! feed.has_data && 'inventory' !== feed.error_kind
	);
}

/**
 * The sentence for that state.
 *
 * @param {Object} feed The vulnerability feed's status.
 * @return {string} The sentence.
 */
export function unreachedText( feed ) {
	return sprintf(
		/* translators: %s: where the list of known vulnerabilities comes from, e.g. "BetterShield Hub". */
		__(
			'The last vulnerability check couldn’t reach %s, so there are no results yet. Try again later.',
			'bettershield'
		),
		feed.feed_label || __( 'the vulnerability list', 'bettershield' )
	);
}
