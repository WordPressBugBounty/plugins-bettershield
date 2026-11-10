/**
 * The slot an add-on's section draws into.
 */

import { useEffect, useRef } from '@wordpress/element';

/**
 * A section this app does not draw itself — one an add-on registered — gets
 * the chrome and an element to mount into. The add-on's own script mounts
 * there; a DOM event tells it when the slot exists, and again on every route
 * change so it can follow the tab.
 *
 * The slot is inside this app's frame, and says so (`data-framed`, and
 * `framed` on the event): the sidebar and the bar are already drawn around
 * it, so an add-on draws its screen and nothing else. One that does not know
 * the attribute draws what it always drew.
 *
 * A tab the add-on said it draws with the redesign's components sits in the
 * redesign's content box, and the slot says that too (`data-drawn`, and
 * `drawn` on the event).
 */
export default function AddOnSlot( { route, drawn = false } ) {
	const ref = useRef( null );

	useEffect( () => {
		const slot = ref.current;
		return () => document.dispatchEvent( new window.CustomEvent( 'bettershield:slot-removed', { detail: { slot } } ) );
	}, [] );

	useEffect( () => {
		if ( ref.current ) {
			ref.current.dispatchEvent(
				new window.CustomEvent( 'bettershield:slot', { bubbles: true, detail: { section: route.section, tab: route.tab, framed: true, drawn } } )
			);
		}
	}, [ route, drawn ] );

	return <div id="bettershield-slot" ref={ ref } data-section={ route.section } data-tab={ route.tab } data-framed="" data-drawn={ drawn ? '' : undefined } />;
}
