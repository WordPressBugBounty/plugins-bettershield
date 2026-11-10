/**
 * A set of codes shown once: two-factor backup codes, or printed recovery
 * codes.
 *
 * Each code is a numbered tile of its own rather than a line in one block of
 * text, so the set reads as separate things to keep, and the number is the
 * one somebody ticks off on paper. In the design's type, with figures of one
 * width, rather than monospace.
 */

import './Codes.css';

/**
 * @param {Object}   props
 * @param {string[]} props.codes The codes, in the order they were issued.
 */
export default function Codes( { codes } ) {
	return (
		<ol className="bs-ds-codes">
			{ codes.map( ( code ) => (
				<li key={ code }>
					<code className="bs-ds-codes__code">{ code }</code>
				</li>
			) ) }
		</ol>
	);
}
