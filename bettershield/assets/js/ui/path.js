/**
 * Where a file path is allowed to break across lines.
 *
 * The Files screen exists to say which file changed, and a path held to one
 * unwrappable line was clipped with no ellipsis and no tooltip — twenty of
 * twenty-one rows on an ordinary desktop, worst at exactly the deep
 * `vendor/composer/…` paths whose distinguishing part is the tail. The owner
 * was being asked to decide about a file whose name they could only see the
 * start of.
 *
 * Wrapping alone is not enough on its own: a path has no spaces, so a browser
 * either breaks at the first hyphen it finds — leaving `wp-` alone on a line
 * and the rest still too long — or breaks mid-segment. Splitting on the
 * separator gives every `/` a break opportunity, so lines fill and breaks land
 * where a reader expects them.
 *
 * Split rather than a zero-width space in the string: a break opportunity that
 * is a real character travels with a copy-paste, and the whole point of a path
 * on this screen is that somebody can paste it into a terminal.
 */

import { Fragment } from '@wordpress/element';

/**
 * A path as the pieces it may break between, each keeping its own separator.
 *
 * @param {string} path A relative file path.
 * @return {string[]} The segments, in order, joining back to the original.
 */
export function pathSegments( path ) {
	const text = String( path ?? '' );

	if ( '' === text ) {
		return [];
	}

	return text.split( '/' ).map( ( part, index, all ) => ( index < all.length - 1 ? part + '/' : part ) );
}

/**
 * A path, or a line of text that ends in one, set to break only at its
 * separators. Each `/` is followed by a break opportunity rather than a
 * character, so a copy-paste keeps the path whole.
 *
 * @param {Object} props
 * @param {string} props.path The path, or text naming one.
 * @return {import('react').ReactNode} The pieces, each with its break opportunity.
 */
export function BreakablePath( { path } ) {
	return pathSegments( path ).map( ( part, index ) => (
		<Fragment key={ index }>
			{ part }
			<wbr />
		</Fragment>
	) );
}
