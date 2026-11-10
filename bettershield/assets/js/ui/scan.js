/**
 * How far along a file check is, in words.
 *
 * Kept apart from the screen because the rule is the part worth testing, and
 * the rule is the same one the front-end cost wording follows: a measurement
 * may be rounded for reading and may never be rounded into a claim it does not
 * support. A check that has finished no targets yet has not "finished 0 of 14"
 * in any sense the reader cares about — it has started.
 *
 * The sentence is also the accessible name of the bar beside it, so it has to
 * stand on its own without the bar.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * @param {?Object} progress What the report says about the run in flight.
 * @return {string} One sentence.
 */
export function scanProgress( progress ) {
	const waiting = __( 'A check is running. On large sites it runs in steps and can take a few minutes.', 'bettershield' );

	if ( ! progress || ! progress.targets ) {
		return waiting;
	}

	const done = Math.min( Number( progress.target ) || 0, Number( progress.targets ) );
	const checked = Number( progress.checked ) || 0;

	// What is being looked at now beats how many are left, when there is a
	// name for it: "checking akismet" is a thing that is happening, and "3 of
	// 14" is a fraction somebody has to interpret. Both, where both are known.
	const where = progress.label
		? sprintf(
				/* translators: 1: what is being checked, 2: how many are done, 3: how many there are. */
				__( 'Checking %1$s — %2$d of %3$d', 'bettershield' ),
				progress.label,
				done,
				progress.targets
		  )
		: sprintf(
				/* translators: 1: how many are done, 2: how many there are. */
				__( 'Checked %1$d of %2$d', 'bettershield' ),
				done,
				progress.targets
		  );

	if ( ! checked ) {
		return where + '.';
	}

	return (
		where +
		' · ' +
		sprintf(
			/* translators: %s: a number of files. */
			_n( '%s file so far.', '%s files so far.', checked, 'bettershield' ),
			checked.toLocaleString()
		)
	);
}
