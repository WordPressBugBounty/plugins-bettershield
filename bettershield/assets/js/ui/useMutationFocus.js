import { useContext, useEffect, useRef, useState } from '@wordpress/element';
import { StoreContext } from '../store';

/**
 * Keep keyboard position when a successful action takes its own control away.
 *
 * Away means removed, or disabled: a browser moves focus off a control that
 * becomes disabled, so a Save that has nothing left to save, or a button held
 * disabled while its request runs, leaves the reader on the page body just as
 * a removed row does. Focus goes back to the control where it can still take
 * it, and to the fallback where it cannot.
 */
export default function useMutationFocus( fallback ) {
	const [ completed, setCompleted ] = useState( null );
	const settled = useRef( null );
	const mounted = useRef( true );
	const store = useContext( StoreContext );

	// The store holds a control disabled until its request has finished,
	// which is after the success callback ran. Read the control only once it
	// lets go, or a button about to come back reads as one that is gone.
	const holding = Boolean( store && store.busy );

	useEffect( () => {
		mounted.current = true;
		return () => { mounted.current = false; };
	}, [] );

	useEffect( () => {
		if ( ! completed || holding || settled.current === completed ) {
			return;
		}

		settled.current = completed;

		const { origin } = completed;
		const active = document.activeElement;

		// Focus the reader moved on to is theirs, and stays where they put it.
		if ( active !== document.body && active !== origin ) {
			return;
		}

		if ( origin?.isConnected && ! origin.disabled ) {
			if ( active === document.body ) {
				origin.focus();
			}
			return;
		}

		fallback.current?.focus();
	}, [ completed, holding, fallback ] );

	// Pass this callback into the store action so a password-confirmation
	// retry retains it. A `.then()` on the initial, refused request does not.
	return ( onSuccess ) => {
		const origin = document.activeElement;
		return async ( result ) => {
			if ( ! result || ! mounted.current ) {
				return;
			}
			await onSuccess( result );
			if ( mounted.current ) {
				setCompleted( { origin } );
			}
		};
	};
}
