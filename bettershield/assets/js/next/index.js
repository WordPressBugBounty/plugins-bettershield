/**
 * The dashboard, on every screen: a site's and the network's.
 *
 * It reads the same store, routes and strings as the screens before it and
 * draws its own frame. A section it does not redraw yet renders its current
 * screen inside that frame, so every address keeps working while screens
 * move over.
 */

// The current token roles and shared primitives come first: the screens not
// redrawn yet still read them. The redesign's own tokens and layers follow.
import '../../css/tokens.css';
import '../../css/base.css';
import '../shell.css';
import '../../css/tokens-ds.css';
import './base.css';
// The classic sheet and stand-in rules, which no screen of this plugin draws
// any more: an add-on's tab that is not drawn with the redesign's components
// still renders in the classic wrapper and reads them.
import '../ui/Sheet.css';
import '../ui/Skeleton.css';

import { Popover, SlotFillProvider } from '@wordpress/components';
import { createRoot } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { StoreProvider } from '../store';
import { isNetwork, restRoot } from '../nav';
import { rootURLMiddleware } from '../rest';
import { backgroundSeed, SchemeContext, schemeAttribute, useSchemePreference } from '../ui/scheme';
import { BRAND_SEEDS } from '../shared/seeds';
import Shell from './shell/Shell';

if ( isNetwork && restRoot ) {
	apiFetch.use( rootURLMiddleware( restRoot ) );
}

export function Root() {
	const ThemeProvider = window.wp?.theme?.ThemeProvider;
	const [ scheme, setScheme ] = useSchemePreference();
	const background = backgroundSeed( scheme );
	const seeds = background ? { ...BRAND_SEEDS, background } : BRAND_SEEDS;

	const app = (
		<SlotFillProvider>
			<div className="bs-ds-app" data-bs-scheme={ schemeAttribute( scheme ) }>
				<StoreProvider>
					<Shell />
				</StoreProvider>
				<Popover.Slot />
			</div>
		</SlotFillProvider>
	);

	const themed = ThemeProvider ? (
		<ThemeProvider color={ seeds } cornerRadius="subtle">
			{ app }
		</ThemeProvider>
	) : (
		app
	);

	return <SchemeContext.Provider value={ { scheme, setScheme } }>{ themed }</SchemeContext.Provider>;
}

const el = document.getElementById( 'bettershield-root' );

if ( el ) {
	// The redesign's tokens are declared on the body (see tokens-ds.css), so the
	// class is on before anything draws.
	document.body.classList.add( 'bs-ds-body' );
	createRoot( el ).render( <Root /> );
}
