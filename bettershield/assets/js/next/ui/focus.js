/**
 * Moving focus after an action, without taking it from a reader who has
 * moved on.
 */

import { useEffect, useRef } from '@wordpress/element';

/**
 * Focus `node` when the keyboard has nowhere to be: on the page body, or on
 * a control that is gone or disabled. A reader who went on to type or press
 * something else while the action ran keeps their place.
 *
 * @param {HTMLElement|null} node Where focus should go.
 */
export function focusIfLost( node ) {
	if ( ! node || ! node.isConnected ) {
		return;
	}

	const active = node.ownerDocument.activeElement;

	// A control held while it works keeps focus but takes no press, so it is
	// no place a reader chose to be.
	if ( active && active !== node.ownerDocument.body && active.isConnected && ! active.disabled && 'true' !== active.getAttribute( 'aria-disabled' ) ) {
		return;
	}

	node.focus();
}

/**
 * Focus `target` once `working` ends, when the keyboard has nowhere to be.
 *
 * For a control an action replaces with another (Lock the site down with
 * Lift the lockdown): the one pressed is gone, so the store has nothing to
 * give focus back to, and the browser left it on the page (#1926).
 *
 * @param {boolean} working  Whether the action is running.
 * @param {Object}  target   A ref to where focus should go after it.
 * @param {Object}  fallback A ref to where it goes when `target` is gone.
 */
export function useFocusAfter( working, target, fallback = null ) {
	const was = useRef( working );

	useEffect( () => {
		if ( was.current && ! working ) {
			focusIfLost( target.current && target.current.isConnected ? target.current : fallback && fallback.current );
		}

		was.current = working;
	}, [ working, target, fallback ] );
}
