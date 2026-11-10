/**
 * The route the app is on, and moving between routes without a document
 * load.
 *
 * Each section is a real admin page; moving between two is a state change
 * here. Because the document stops changing, focus and the screen-reader
 * announcement become this app's job: focus moves to the screen's heading
 * after a move, never on first paint.
 */

import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import { initialRoute, NAVIGATED } from '../../nav';
import { interceptLinks, routeFromUrl, syncAdminMenu, syncTitle } from '../../router';
import { confirmLeave } from '../ui/useUnsaved';

/**
 * @return {{route: {section: string, tab: string}, headingRef: Object, go: Function}} The route, the heading to focus, and a move.
 */
export default function useRoute() {
	const [ route, setRoute ] = useState( initialRoute );
	const headingRef = useRef( null );
	const settled = useRef( false );
	// The address shown, so a Back the reader takes back can be undone.
	const shown = useRef( window.location.href );

	const go = useCallback( ( href ) => {
		// A link to the address already shown is not a move. Pushed, every
		// click on the current screen's own link added an identical entry,
		// so leaving took one Back per click, and focus jumped from the link
		// to the heading of a screen that had not changed.
		if ( new URL( href, window.location.href ).href === window.location.href ) {
			return;
		}

		// Edits behind a save bar are asked about first (#1915).
		if ( ! confirmLeave() ) {
			return;
		}

		window.history.pushState( {}, '', href );
		shown.current = window.location.href;
		setRoute( routeFromUrl( href ) );
		// A push fires no popstate: said so the screen on the address reads
		// it again, as it does after Back.
		window.dispatchEvent( new window.Event( NAVIGATED ) );
	}, [] );

	useEffect( () => {
		const onPopState = () => {
			// Back has already moved the address and cannot be stopped, so a
			// reader who stays is put back where they were.
			if ( ! confirmLeave() ) {
				window.history.pushState( {}, '', shown.current );
				return;
			}

			shown.current = window.location.href;
			setRoute( routeFromUrl( window.location.href ) );
		};

		window.addEventListener( 'popstate', onPopState );
		const release = interceptLinks( go );

		return () => {
			window.removeEventListener( 'popstate', onPopState );
			release();
		};
	}, [ go ] );

	useEffect( () => {
		syncAdminMenu( route.section );
		syncTitle( route.section, initialRoute.section, route.tab );

		if ( ! settled.current ) {
			settled.current = true;
			return;
		}

		if ( headingRef.current ) {
			headingRef.current.focus();
		}
	}, [ route ] );

	return { route, headingRef, go };
}
