/**
 * The Quick Setup: its own page and its own bundle.
 *
 * It is drawn with the redesigned dashboard's tokens and components, and the
 * reader's choice of light or dark, so it reads as the same product; it shares
 * nothing else, because it has a start and an end and the app's navigation
 * would be seven ways out of it.
 */

// The token layers, then the redesign's base: the font, the app's root and
// the text and icon styles the components share.
import '../css/tokens.css';
import '../css/tokens-ds.css';
import './next/base.css';

import { Popover, SlotFillProvider } from '@wordpress/components';
import { createRoot } from '@wordpress/element';
import Wizard from './next/setup/Wizard';
import { BRAND_SEEDS } from './shared/seeds';
import { backgroundSeed, SchemeContext, schemeAttribute, useSchemePreference } from './ui/scheme';

function Root() {
	const ThemeProvider = window.wp?.theme?.ThemeProvider;
	const [ scheme, setScheme ] = useSchemePreference();
	const background = backgroundSeed( scheme );
	const seeds = background ? { ...BRAND_SEEDS, background } : BRAND_SEEDS;

	// The app's root class, for the components' rules and the design's type,
	// and its own beside it, which sets the dashboard's frame aside.
	const app = (
		<SlotFillProvider>
			<div className="bs-ds-app bs-ds-setup" data-bs-scheme={ schemeAttribute( scheme ) }>
				<Wizard />
				<Popover.Slot />
			</div>
		</SlotFillProvider>
	);

	return (
		<SchemeContext.Provider value={ { scheme, setScheme } }>
			{ ThemeProvider ? (
				<ThemeProvider color={ seeds } cornerRadius="subtle">
					{ app }
				</ThemeProvider>
			) : (
				app
			) }
		</SchemeContext.Provider>
	);
}

const mount = document.getElementById( 'bettershield-setup' );

if ( mount ) {
	// The design's tokens are declared on the body (see tokens-ds.css), so the
	// class is on before anything draws, as the dashboard does.
	document.body.classList.add( 'bs-ds-body' );
	createRoot( mount ).render( <Root /> );

	/*
	 * Back from the dashboard can bring this page out of the browser's memory
	 * without asking the site for it, so a finished setup would be drawn again
	 * without the site having the chance to send the owner on. Ask again.
	 */
	window.addEventListener( 'pageshow', ( event ) => {
		if ( event.persisted ) {
			window.location.reload();
		}
	} );
}
