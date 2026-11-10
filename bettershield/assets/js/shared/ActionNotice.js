/**
 * The one place an action's failure is reported.
 *
 * Shared by both dashboard bundles, so a change to it lands once.
 */

import { useEffect, useRef } from '@wordpress/element';
import { useStore } from '../store';
import Alert from '../next/ui/Alert';

/**
 * Action failures surface once, above the screen, rather than inside whichever
 * control happened to be pressed.
 *
 * @param {Object} props
 * @param {Object} props.route    The screen it belongs to.
 * @param {Object} props.fallback Where Dismiss puts focus when the refused control is gone.
 */
export default function ActionNotice( { route, fallback = null } ) {
	const { notice, setNotice } = useStore();
	const box = useRef( null );
	// The control the reader last had, and the one Dismiss gives focus back
	// to: by the time a refusal arrives, the control it refused has usually
	// lost focus to the page body.
	const lastFocused = useRef( null );
	const returnTo = useRef( null );

	useEffect( () => {
		const remember = ( event ) => {
			if ( ! box.current || ! box.current.contains( event.target ) ) {
				lastFocused.current = event.target;
			}
		};

		document.addEventListener( 'focusin', remember );

		return () => document.removeEventListener( 'focusin', remember );
	}, [] );

	// A failure belongs to the screen it happened on. Navigation is a
	// pushState, so without this the banner followed the reader to the next
	// screen and stood over controls that had refused nothing.
	useEffect( () => {
		setNotice( null );
	}, [ route.section, route.tab, setNotice ] );

	/*
	 * The banner sits at the top of the screen, and on a long one that was
	 * thousands of pixels above the Save, the switch or the code form that
	 * was refused, which showed nothing of its own. So a new reason comes to
	 * the reader: into view, clear of the admin bar, and with focus — unless
	 * they are typing somewhere, which is theirs to finish.
	 */
	useEffect( () => {
		if ( ! notice || ! box.current ) {
			return;
		}

		const active = document.activeElement;
		const typing =
			active &&
			! active.disabled &&
			( active.isContentEditable ||
				active.matches( 'textarea, select, input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"])' ) );

		if ( typing ) {
			return;
		}

		returnTo.current = active && active !== document.body ? active : lastFocused.current;
		box.current.focus( { preventScroll: true } );
		box.current.scrollIntoView?.( { block: 'center' } );
	}, [ notice ] );

	const dismiss = () => {
		const to = returnTo.current;

		returnTo.current = null;
		setNotice( null );

		if ( to && to.isConnected && ! to.disabled ) {
			to.focus();
		} else {
			fallback?.current?.focus();
		}
	};

	if ( ! notice ) {
		return null;
	}

	// The redesign's error alert: the old dashboard's classes read tokens
	// that are not declared on its screens, so it drew as bare text (#2477).
	return <Alert tone="error" layout="default" desc={ notice } onDismiss={ dismiss } alertRef={ box } live="alert" />;
}
