/**
 * A clock that moves, for the few places a deadline is counted down.
 *
 * Almost everything in this app prints an absolute time, which never needs
 * re-reading. A countdown does: "expires in 2 minutes" printed once is a
 * sentence that becomes false while the reader is looking at it, and the
 * control beside it goes on offering something the site will refuse.
 *
 * It ticks only while the caller says a deadline is still ahead, because a
 * timer left running behind a screen nobody is reading is a re-render every
 * fifteen seconds for the life of the tab.
 */

import { useEffect, useState } from '@wordpress/element';

/** Fifteen seconds: a quarter of the smallest unit any of this copy prints. */
const EVERY = 15000;

/**
 * @param {boolean} live    Whether anything on screen is still counting down.
 * @param {number}  everyMs How often to re-read the clock while it is.
 * @return {number} The moment to read the deadlines against.
 */
export default function useNow( live, everyMs = EVERY ) {
	const [ now, setNow ] = useState( () => Date.now() );

	useEffect( () => {
		if ( ! live ) {
			return undefined;
		}

		const tick = () => setNow( Date.now() );
		const id = setInterval( tick, everyMs );

		/*
		 * The listener matters more than the interval. "Leave the screen open"
		 * usually means "leave the tab behind another one", and a backgrounded
		 * tab has its intervals throttled to a minute or more — which is
		 * exactly the case this exists for. Correct the moment it is looked at.
		 */
		document.addEventListener( 'visibilitychange', tick );

		return () => {
			clearInterval( id );
			document.removeEventListener( 'visibilitychange', tick );
		};
	}, [ live, everyMs ] );

	return now;
}
