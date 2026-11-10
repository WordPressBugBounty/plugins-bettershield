/**
 * Small formatting rules the steps share.
 */

import { _x } from '@wordpress/i18n';

/**
 * Names as one phrase: "A", "A and B", "A, B and C", in the page's language
 * where the browser knows how.
 *
 * @param {string[]} names The names.
 * @return {string} The phrase.
 */
export function listOf( names ) {
	const list = ( Array.isArray( names ) ? names : [] ).filter( Boolean );

	if ( list.length < 2 ) {
		return list[ 0 ] || '';
	}

	try {
		const locale = document.documentElement.lang || undefined;

		return new window.Intl.ListFormat( locale, { style: 'long', type: 'conjunction' } ).format( list );
	} catch ( error ) {
		return list.slice( 0, -1 ).join( ', ' ) + ' ' + _x( 'and', 'joins the last two names in a list', 'bettershield' ) + ' ' + list[ list.length - 1 ];
	}
}

/**
 * A sentence whose hyphenated words stay whole: the hyphen between two
 * letters becomes a non-breaking one (U+2011), so "sign-in" never ends one
 * line as "sign-" and starts the next as "in" (#2304). Done when drawn, so
 * the translated string keeps its plain hyphen.
 *
 * @param {string} text A translated sentence.
 * @return {string} The same sentence, its word hyphens unbreakable.
 */
export function keepHyphenated( text ) {
	return String( text || '' ).replace( /(\p{L})-(?=\p{L})/gu, '$1\u2011' );
}

/**
 * The first letters of a name, for a tile that stands in for its logo.
 *
 * @param {string} name A product name.
 * @return {string} One or two capitals.
 */
export function initials( name ) {
	const words = String( name || '' )
		.replace( /[^\p{L}\p{N}\s.]/gu, ' ' )
		.split( /[\s.]+/ )
		.filter( Boolean );

	if ( ! words.length ) {
		return '';
	}

	if ( 1 === words.length ) {
		// One word written in camel case still has two parts: BetterDocs.
		const capitals = words[ 0 ].match( /\p{Lu}/gu ) || [];

		return ( capitals.length > 1 ? capitals.slice( 0, 2 ).join( '' ) : words[ 0 ].slice( 0, 2 ) ).toUpperCase();
	}

	return ( words[ 0 ][ 0 ] + words[ 1 ][ 0 ] ).toUpperCase();
}
