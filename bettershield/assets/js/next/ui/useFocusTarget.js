/**
 * A link straight to one setting: `?focus=<name>` on a screen's address.
 *
 * A finding's link opened a long screen at its top, with nothing marked,
 * so the reader scrolled and guessed which setting answered it. The setting
 * a link names carries `data-bs-focus="<name>"`; once it is drawn it is
 * brought into view, takes focus and is marked for a moment, as a linked
 * finding is on the report. A name the screen does not have is ignored and
 * the screen opens as it always did.
 */

import './useFocusTarget.css';

import { useEffect } from '@wordpress/element';

/** How long the mark stays, in milliseconds. */
const MARKED_FOR = 2400;

/** How long a screen still loading its settings is waited for. */
const WAITED_FOR = 15000;

/**
 * How long the setting has to stay put before it is left where it is, and
 * how often it is looked at until then, in milliseconds. Login & Access drew
 * the setting, then its sign-in hardening rows arrived above it a moment
 * later and pushed it some 1300 px down, out of view (#2584).
 */
export const SETTLES_FOR = 1500;
const LOOKED_AT_EVERY = 100;

/** Never followed for longer than this, however long the screen keeps moving. */
const FOLLOWED_FOR = 8000;

/** What the reader does to move the page themselves: it is not fought. */
const OWN_MOVES = [ 'wheel', 'touchstart', 'keydown', 'mousedown', 'pointerdown' ];

/** The class that marks the setting. */
export const MARK = 'bs-ds-focus-target';

/**
 * The event a setting on a hidden part of a screen sends up to ask for that
 * part to be shown: the group of a tabbed screen that holds it. Whatever
 * draws the hidden part answers it.
 */
export const REVEAL = 'bs-ds-focus-reveal';

/** The setting the address names, if it names one this could have drawn. */
export function linkedSetting() {
	let name = '';

	try {
		name = new URL( window.location.href ).searchParams.get( 'focus' ) || '';
	} catch ( error ) {
		return '';
	}

	return /^[a-z0-9_-]{1,64}$/.test( name ) ? name : '';
}

/**
 * Where focus goes inside the setting: its own control, not the ⓘ beside
 * its title, and the setting itself when it has no control.
 *
 * @param {HTMLElement} node The setting.
 * @return {HTMLElement} What takes focus.
 */
export function controlOf( node ) {
	const fields = node.querySelector( 'input:not([type="hidden"]):not(:disabled), select:not(:disabled), textarea:not(:disabled)' );

	if ( fields ) {
		return fields;
	}

	const pressable = Array.from( node.querySelectorAll( 'button:not(:disabled), a[href]' ) ).find( ( candidate ) => ! candidate.closest( '.bs-ds-setting__titlerow' ) );

	if ( pressable ) {
		return pressable;
	}

	if ( ! node.hasAttribute( 'tabindex' ) ) {
		node.setAttribute( 'tabindex', '-1' );
	}

	return node;
}

/**
 * Bring the setting into view, focus it and mark it.
 *
 * @param {HTMLElement} node The setting.
 */
export function land( node ) {
	if ( ! node.isConnected ) {
		return;
	}

	if ( node.scrollIntoView ) {
		node.scrollIntoView( { block: 'center' } );
	}

	controlOf( node ).focus( { preventScroll: true } );
	node.classList.add( MARK );
	window.setTimeout( () => node.classList.remove( MARK ), MARKED_FOR );
}

/**
 * Keep the setting in view while the screen settles around it.
 *
 * It is landed on as soon as it is drawn, and a screen often draws more
 * above it afterwards: the rows a second read brings, a notice. Each time
 * it has moved it is brought back to the middle, until it has stayed put
 * for SETTLES_FOR. A reader who scrolls, clicks or presses a key has taken
 * over, and is left where they went.
 *
 * @param {HTMLElement} node The setting, already landed on.
 * @return {Function} Stops following it.
 */
export function follow( node ) {
	const where = () => node.getBoundingClientRect().top;
	const started = Date.now();
	let last = where();
	let still = started;
	let timer = 0;

	const stop = () => {
		window.clearInterval( timer );
		OWN_MOVES.forEach( ( type ) => window.removeEventListener( type, stop, true ) );
	};

	timer = window.setInterval( () => {
		const now = Date.now();

		if ( ! node.isConnected ) {
			stop();
			return;
		}

		if ( Math.abs( where() - last ) > 1 ) {
			if ( node.scrollIntoView ) {
				node.scrollIntoView( { block: 'center' } );
			}

			last = where();
			still = now;
		}

		if ( now - still >= SETTLES_FOR || now - started >= FOLLOWED_FOR ) {
			stop();
		}
	}, LOOKED_AT_EVERY );
	OWN_MOVES.forEach( ( type ) => window.addEventListener( type, stop, { capture: true, passive: true } ) );

	return stop;
}

/**
 * Answer `?focus=` on the screen the route draws.
 *
 * @param {{section: string, tab: string}} route The route drawn.
 */
export default function useFocusTarget( route ) {
	useEffect( () => {
		const name = linkedSetting();

		if ( ! name || 'function' !== typeof window.MutationObserver ) {
			return undefined;
		}

		const find = () => document.querySelector( `[data-bs-focus="${ name }"]` );
		let observer = null;
		let timer = 0;
		let following = null;
		let asked = null;
		let gone = false;

		const stop = () => {
			if ( observer ) {
				observer.disconnect();
			}

			window.clearTimeout( timer );
		};
		const stopAll = () => {
			gone = true;
			stop();

			if ( following ) {
				following();
			}
		};

		/*
		 * On the next frame, not now: the route's own effect focuses the
		 * screen's heading and the shell scrolls to the top, over the
		 * setting, as it did over a linked finding. Then followed, so what
		 * the screen draws above it afterwards does not carry it away.
		 */
		const arrive = ( node ) => {
			stop();
			window.requestAnimationFrame( () => {
				if ( gone ) {
					return;
				}

				land( node );

				if ( node.isConnected ) {
					following = follow( node );
				}
			} );
		};

		/*
		 * A setting on a group of the screen not shown (Settings › General
		 * keeps every group drawn, the others hidden) cannot be scrolled to
		 * or focused: its group is asked to open, once, and it is landed on
		 * when it shows.
		 */
		const reach = () => {
			const node = find();

			if ( ! node ) {
				return false;
			}

			if ( node.closest( '[hidden]' ) ) {
				if ( asked !== node ) {
					asked = node;
					node.dispatchEvent( new window.CustomEvent( REVEAL, { bubbles: true } ) );
				}

				// Shown by that answer at once, or later by a render.
				if ( node.closest( '[hidden]' ) ) {
					return false;
				}
			}

			arrive( node );

			return true;
		};

		if ( reach() ) {
			return stopAll;
		}

		// Most screens read their settings first; the setting comes later.
		observer = new window.MutationObserver( reach );
		observer.observe( document.body, { childList: true, subtree: true, attributes: true, attributeFilter: [ 'hidden' ] } );
		timer = window.setTimeout( stop, WAITED_FOR );

		return stopAll;
	}, [ route.section, route.tab ] );
}
