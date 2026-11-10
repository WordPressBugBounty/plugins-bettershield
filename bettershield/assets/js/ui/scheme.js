/**
 * Which color scheme this app is drawn in, and where that choice is kept.
 *
 * Two values and no third. There was a `system` option that handed
 * ThemeProvider no background seed, leaving the generated ramp to follow
 * wp-admin — but the app paints its own page color now, so `system` drew a
 * light canvas under a ramp that was free to be dark. It was the one state in
 * which the two halves of the scheme could disagree, and collapsing it away
 * is what makes them always agree: both values below pin a background seed,
 * and the canvas is read from the same attribute.
 *
 * The seeds are the page background, not the card: ThemeProvider reads
 * `color.background` to decide which way the ramp runs, and generates the
 * raised surface from it. They agree with the literal fallbacks in
 * tokens.css, which is what makes WordPress 6.7 through 7.0 — where there is
 * no ramp to generate — land on the same two schemes rather than on a paler
 * approximation of them.
 *
 * The preference is a browser preference. It is one value per person per
 * browser, it never leaves the machine, and it does not need a round trip to
 * change the screen — a scheme that flickered through a REST write on every
 * press would be the one interaction on this screen that felt slower than the
 * audit. Storage that refuses to answer (a locked-down browser, private
 * browsing) is a light scheme that cannot be changed rather than an error:
 * the screen still renders, the control still works for the session.
 */

import { createContext, useCallback, useContext, useEffect, useState } from '@wordpress/element';

/** The two, and the order the control moves through them. */
export const SCHEMES = [ 'light', 'dark' ];

/** What a reader who has never chosen gets, and what an unreadable store falls back to. */
export const DEFAULT_SCHEME = 'light';

const STORAGE_KEY = 'bettershield-scheme';

/** The page background each scheme seeds the ramp with. */
const BACKGROUND_SEEDS = {
	light: '#ffffff',
	dark: '#141a21',
};

function readStored() {
	try {
		const stored = window.localStorage.getItem( STORAGE_KEY );

		// Anything else is a value this version does not have — including
		// `system`, which earlier versions wrote. It reads as light, which is
		// what that setting rendered as on every core admin scheme anyway.
		return SCHEMES.includes( stored ) ? stored : DEFAULT_SCHEME;
	} catch ( error ) {
		return DEFAULT_SCHEME;
	}
}

function writeStored( scheme ) {
	try {
		window.localStorage.setItem( STORAGE_KEY, scheme );
	} catch ( error ) {
		// A browser that will not keep the preference still honors it for
		// this visit. There is nothing to report and nothing to retry.
	}
}

/**
 * The seed ThemeProvider is given for a scheme.
 *
 * @param {string} scheme One of SCHEMES.
 * @return {string} A background seed.
 */
export function backgroundSeed( scheme ) {
	return BACKGROUND_SEEDS[ scheme ] || BACKGROUND_SEEDS[ DEFAULT_SCHEME ];
}

/**
 * The value written to `data-bs-scheme`.
 *
 * It selects the dark token block, and it is also what tells the stylesheet
 * that this page belongs to us — which is what lets the admin canvas behind
 * the app be painted at all. Written only on our own screens, because the app
 * that writes it is only mounted there.
 *
 * @param {string} scheme One of SCHEMES.
 * @return {string} The attribute value.
 */
export function schemeAttribute( scheme ) {
	return SCHEMES.includes( scheme ) ? scheme : DEFAULT_SCHEME;
}

/**
 * The scheme that is not the one given, which is the whole of the control.
 *
 * @param {string} scheme One of SCHEMES.
 * @return {string} The other one.
 */
export function otherScheme( scheme ) {
	return 'dark' === scheme ? 'light' : 'dark';
}

/**
 * The preference, and a setter that persists it.
 *
 * Read once on mount rather than during render: the first paint is the
 * server's HTML either way, and reading storage in a render body is a read
 * that can throw in the one place React cannot recover from.
 *
 * @return {[string, Function]} The current scheme and a setter.
 */
export function useSchemePreference() {
	const [ scheme, set ] = useState( DEFAULT_SCHEME );

	useEffect( () => {
		set( readStored() );
	}, [] );

	const choose = useCallback( ( next ) => {
		if ( ! SCHEMES.includes( next ) ) {
			return;
		}

		set( next );
		writeStored( next );
	}, [] );

	/*
	 * A popover that finds no slot renders at the end of the document, where
	 * the override block scoped to `.bs-app` cannot reach it. The attribute
	 * goes on the body as well so that one selector can, and so that the rule
	 * that paints the admin canvas has something to hang on.
	 */
	useEffect( () => {
		document.body.setAttribute( 'data-bs-scheme', schemeAttribute( scheme ) );

		return () => document.body.removeAttribute( 'data-bs-scheme' );
	}, [ scheme ] );

	return [ scheme, choose ];
}

/**
 * The chosen scheme, for anything below the root that needs to read or change it.
 *
 * The root owns the state because the root is what hands ThemeProvider its
 * seed, and the control that changes it is in the masthead — two places far
 * enough apart that passing it down by hand would thread it through every
 * component in between.
 */
export const SchemeContext = createContext( { scheme: DEFAULT_SCHEME, setScheme: () => {} } );

export function useScheme() {
	return useContext( SchemeContext );
}
