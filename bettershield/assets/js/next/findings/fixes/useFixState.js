/**
 * What the account findings' panels share (#2430): reading the panel's own
 * list once, and saying what happened where the keyboard is.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { useStore } from '../../../store';
import { announce } from '../../../ui/announce';

/**
 * The panel's state, read from its route when it opens.
 *
 * @param {string} path The route.
 * @return {{state: Object|null, setState: Function, unread: boolean}} What was read, and whether it could not be.
 */
export default function useFixState( path ) {
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );

	useEffect( () => {
		let alive = true;

		apiFetch( { path } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [ path ] );

	return { state, setState, unread };
}

/**
 * A sentence said out loud and shown, with focus moved to it: the control
 * pressed has usually gone by then, replaced by what it did.
 *
 * @return {{said: string, say: Function, status: Object}} The sentence, the way to say one, and a ref for the line that shows it.
 */
export function useSaid() {
	const [ said, setSaid ] = useState( { words: '', at: 0 } );
	const status = useRef( null );

	useEffect( () => {
		if ( said.words && status.current ) {
			status.current.focus();
		}
	}, [ said ] );

	const say = ( words ) => {
		setSaid( { words, at: Date.now() } );
		announce( words );
	};

	return { said: said.words, say, status };
}

/**
 * Run the audit once, by itself, when a panel finds that what its finding
 * names is already gone — changed somewhere the audit has not looked since.
 * The finding then closes without anybody pressing anything.
 *
 * @param {boolean} gone Whether the panel found nothing left to act on.
 */
export function useAuditWhenGone( gone ) {
	const { runAudit } = useStore();
	const asked = useRef( false );

	useEffect( () => {
		if ( gone && ! asked.current ) {
			asked.current = true;
			runAudit();
		}
	}, [ gone, runAudit ] );
}
