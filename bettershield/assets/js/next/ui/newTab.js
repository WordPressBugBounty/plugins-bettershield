/**
 * Going to the hub in a tab of its own, and noticing the owner come back.
 *
 * Connect used to send the admin tab itself to the hub, so the owner left
 * the screen they were on (#2621). The hub opens beside it now, as every
 * other way to the hub already did, and the screen reads again when the
 * owner returns, so it says the site is connected without a reload.
 */

import { useEffect, useRef } from '@wordpress/element';

/**
 * Open an address in a new tab that has no handle on this one.
 *
 * The tab opens blank and loses its `opener` before it is pointed anywhere,
 * so the page it loads cannot reach back into the admin. A browser that
 * blocks the tab gets the same-tab navigation Connect always did, so the
 * press never does nothing.
 *
 * @param {string} url Where to go.
 * @return {boolean} Whether a new tab opened.
 */
export function openInNewTab( url ) {
	const tab = window.open( '', '_blank' );

	if ( ! tab ) {
		window.location.assign( url );

		return false;
	}

	tab.opener = null;
	tab.location.href = url;

	return true;
}

/**
 * Read again each time the owner comes back to this tab while `waiting`.
 *
 * Focus and visibilitychange both fire on one return, so a return counts
 * only after the tab was left: one read each time. A return that arrives
 * while a read is still out asks for one more once it lands, since that
 * read may have started before the hub finished.
 *
 * @param {boolean}  waiting Whether a return should read.
 * @param {Function} then    The read; may return a promise.
 */
export function useOnReturn( waiting, then ) {
	const read = useRef( then );
	const away = useRef( false );
	const out = useRef( false );
	const again = useRef( false );

	read.current = then;

	useEffect( () => {
		if ( ! waiting ) {
			return undefined;
		}

		let live = true;

		// Waiting starts as the hub's tab opens, so the owner is already away.
		away.current = true;

		const run = () => {
			out.current = true;
			again.current = false;

			Promise.resolve()
				.then( () => read.current() )
				.catch( () => null )
				.then( () => {
					out.current = false;

					if ( live && again.current ) {
						run();
					}
				} );
		};

		const leave = () => {
			away.current = true;
		};

		const back = () => {
			if ( ! away.current ) {
				return;
			}

			away.current = false;

			if ( out.current ) {
				again.current = true;
			} else {
				run();
			}
		};

		const seen = () => ( 'hidden' === document.visibilityState ? leave() : back() );

		window.addEventListener( 'blur', leave );
		window.addEventListener( 'focus', back );
		document.addEventListener( 'visibilitychange', seen );

		return () => {
			live = false;
			window.removeEventListener( 'blur', leave );
			window.removeEventListener( 'focus', back );
			document.removeEventListener( 'visibilitychange', seen );
		};
	}, [ waiting ] );
}
