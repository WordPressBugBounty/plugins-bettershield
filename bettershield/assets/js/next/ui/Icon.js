/**
 * One icon, drawn the way the design draws it.
 *
 * The design's frames export each icon at the size it is drawn; those are
 * used as they are. A name or size no frame draws falls back to the Lucide
 * outline the design's icon set is built from, at the frames' stroke weight.
 */

import { createElement } from '@wordpress/element';
import { DRAWN, LUCIDE } from './icon-data';

/** The icon a static note draws. */
export const NOTE_ICON = 'info';

/** The frames draw every icon with this stroke, in pixels, at every size. */
const STROKE = 1.45833;

/**
 * @param {Object} props
 * @param {string} props.name      The icon's Lucide name, e.g. "list-checks".
 * @param {number} props.size      12, 14, 16 or 18.
 * @param {string} props.tone      One of the design's icon colors: brand, 1, 2, 3, ok, warning, error, info, onbrand.
 * @param {string} props.className Extra classes.
 */
export default function Icon( { name, size = 16, tone = '', className = '' } ) {
	const drawn = DRAWN[ `${ name }@${ size }` ];
	const box = drawn ? size : 24;
	const children = drawn
		? drawn.map( ( d, index ) => <path key={ index } d={ d } /> )
		: ( LUCIDE[ name ] || [] ).map( ( [ tag, attrs ], index ) => createElement( tag, { key: index, ...attrs } ) );
	const classes = [ 'bs-ds-icon', tone ? `bs-ds-ic-${ tone }` : '', className ].filter( Boolean ).join( ' ' );

	return (
		<svg
			className={ classes }
			width={ size }
			height={ size }
			viewBox={ `0 0 ${ box } ${ box }` }
			fill="none"
			stroke="currentColor"
			strokeWidth={ ( STROKE * box ) / size }
			strokeLinecap="round"
			strokeLinejoin="round"
			aria-hidden="true"
			focusable="false"
		>
			{ children }
		</svg>
	);
}
