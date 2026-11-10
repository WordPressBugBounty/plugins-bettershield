/**
 * The score's recorded history, read the same way wherever it is drawn.
 *
 * Which samples count, and what they say in a sentence, are decisions about
 * the data rather than about a picture, so they live here rather than in the
 * posture band that draws them.
 */

import { _n, sprintf } from '@wordpress/i18n';

/**
 * The samples that can be drawn at all, oldest first.
 *
 * One filter, so there is one answer to how many recorded days there are.
 *
 * @param {Array<{at: string, score: number}>|undefined} history Any order.
 * @return {Array<{at: string, score: number}>} Usable samples, oldest first.
 */
export function readableHistory( history ) {
	return ( history || [] )
		.filter(
			( point ) => point && Number.isFinite( Number( point.score ) ) && Number.isFinite( Date.parse( point.at ) )
		)
		.sort( ( a, b ) => Date.parse( a.at ) - Date.parse( b.at ) );
}

/**
 * What the history says, in a sentence.
 *
 * The sentence is the chart, for anybody not reading the picture — and a
 * shape with no numbers beside it is a direction rather than a fact even for
 * those who are.
 *
 * @param {Array<{at: string, score: number}>} points Usable samples, oldest first.
 * @return {string} The sentence.
 */
export function postureSentence( points ) {
	const scores = points.map( ( point ) => Number( point.score ) );
	const first = scores[ 0 ];
	const last = scores[ scores.length - 1 ];

	return last === first
		? sprintf(
				/* translators: 1: number of recorded days, 2: the score. */
				_n(
					'Across %1$d recorded day the score has held at %2$d.',
					'Across %1$d recorded days the score has held at %2$d.',
					scores.length,
					'bettershield'
				),
				scores.length,
				last
		  )
		: sprintf(
				/* translators: 1: number of recorded days, 2: the earlier score, 3: the score now. */
				_n(
					'Over %1$d recorded day, the score went from %2$d to %3$d.',
					'Over %1$d recorded days, the score went from %2$d to %3$d.',
					scores.length,
					'bettershield'
				),
				scores.length,
				first,
				last
		  );
}
