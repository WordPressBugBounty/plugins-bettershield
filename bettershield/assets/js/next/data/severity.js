/**
 * The severity vocabulary in words: critical, high, medium, low, info.
 *
 * Written down once, in both of the cases it is rendered in: a badge carries
 * the word on its own and takes a capital, while a sentence carries it
 * mid-line. Two entries rather than one plus `toLowerCase()`, because case is
 * not a mechanical transform in every language (German capitalizes the noun
 * in both positions), and the contexts tell a translator which is which.
 */

import { _x } from '@wordpress/i18n';

const SEVERITY_WORDS = {
	critical: {
		alone: () => _x( 'Critical', 'severity, on its own', 'bettershield' ),
		inline: () => _x( 'critical', 'severity, inside a sentence', 'bettershield' ),
	},
	high: {
		alone: () => _x( 'High', 'severity, on its own', 'bettershield' ),
		inline: () => _x( 'high', 'severity, inside a sentence', 'bettershield' ),
	},
	medium: {
		alone: () => _x( 'Medium', 'severity, on its own', 'bettershield' ),
		inline: () => _x( 'medium', 'severity, inside a sentence', 'bettershield' ),
	},
	low: {
		alone: () => _x( 'Low', 'severity, on its own', 'bettershield' ),
		inline: () => _x( 'low', 'severity, inside a sentence', 'bettershield' ),
	},
	info: {
		alone: () => _x( 'Info', 'severity, on its own', 'bettershield' ),
		inline: () => _x( 'info', 'severity, inside a sentence', 'bettershield' ),
	},
};

/**
 * One severity as a word inside a sentence.
 *
 * @param {string} severity One of the five.
 * @return {string} The word, lower case.
 */
export function severityLabel( severity ) {
	return ( SEVERITY_WORDS[ severity ] || SEVERITY_WORDS.info ).inline();
}

/**
 * One severity as a word on its own, for the badge that carries it.
 *
 * @param {string} severity One of the five.
 * @return {string} The word, capitalized.
 */
export function severityName( severity ) {
	return ( SEVERITY_WORDS[ severity ] || SEVERITY_WORDS.info ).alone();
}
