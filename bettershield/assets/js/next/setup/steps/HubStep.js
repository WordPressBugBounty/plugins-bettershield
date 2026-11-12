/**
 * BetterShield Hub: the setup's last step, on every site (#2297). Where the
 * site cannot connect yet (an older WordPress, plain permalinks, a lockdown,
 * a staging copy), its Connect opens the Hub screen, which says what to
 * change, instead of starting a connection that would be refused.
 *
 * Optional, and said so: what the hub does, the same choice of what it may
 * do that the Hub screen offers, Connect, and "I'll connect later", which
 * goes to the Dashboard. Connect opens the hub in a new tab and leaves this
 * one where it is (#2621); coming back to it reads the setup again, and the
 * step then says the site is connected, with the way to the hub and to the
 * Dashboard. The press that connected it is met once, in one tab, with a
 * dialog saying the setup is done; closing it opens the Dashboard.
 */

import { createInterpolateElement, useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import Button from '../../ui/Button';
import { openInNewTab, useOnReturn } from '../../ui/newTab';
import { SettingsCard } from '../../ui/Setting';
import Frame, { Footer } from '../Frame';
import { HubLink, SetupDoneDialog } from '../HubConnected';
import { useSetup } from '../context';
import leave from '../leave';
import brand from '../brand';

/** The Hub screen's own route: the step connects through it, as that screen does. */
const CONNECT = '/bettershield/v1/hub/connect';

/** Marks the dialog as shown here, so a reload or the hub's own tab does not repeat it. */
const SHOWN = 'bettershield-hub-connected-shown';

/**
 * Whether this browser has shown the dialog, marking that it has: connecting
 * leaves two tabs on this step. Where the browser refuses the storage the dialog
 * simply may show again.
 *
 * @return {boolean} Whether it had been shown.
 */
function shownBefore() {
	try {
		const shown = null !== window.localStorage.getItem( SHOWN );

		window.localStorage.setItem( SHOWN, '1' );

		return shown;
	} catch ( error ) {
		return false;
	}
}

export default function HubStep() {
	const { state, run, busy, links, refresh, headingRef, keepFocus } = useSetup();
	const hub = state.hub || { connected: false, url: '' };
	const connecting = 'hub-connect' === busy;
	// The hub's tab is open, so a return to this one may find the site connected.
	const [ opened, setOpened ] = useState( false );
	const wasConnected = useRef( hub.connected );
	const [ celebrating, setCelebrating ] = useState( false );
	// Where a way out of the step goes once its dialog, saying the setup is done, is closed.
	const [ leavingTo, setLeavingTo ] = useState( null );

	/*
	 * The dialog goes before the page does. The frame fades as it closes, and
	 * still drawn after that it came back until the next page had loaded.
	 */
	const leaveDialog = leavingTo ? (
		<SetupDoneDialog
			connected={ false }
			onClose={ () => {
				setLeavingTo( null );
				leave( leavingTo );
			} }
		/>
	) : null;

	const connect = () =>
		run( 'hub-connect', CONNECT, { access: 'write', from: 'setup' } ).then( ( answer ) => {
			if ( answer && answer.redirect && openInNewTab( answer.redirect ) ) {
				setOpened( true );
			}
		} );

	useOnReturn( opened && ! hub.connected, refresh );

	// The heading changes under the owner, so the keyboard goes to it.
	useEffect( () => {
		if ( opened && hub.connected ) {
			headingRef.current?.focus( { preventScroll: true } );
		}
	}, [ opened, hub.connected ] ); // eslint-disable-line react-hooks/exhaustive-deps

	// Connected just now: read here, or arrived at from the hub's own tab.
	useEffect( () => {
		if ( hub.connected && ( ! wasConnected.current || hub.returning ) && ! shownBefore() ) {
			setCelebrating( true );
		}

		// A later connection is news again.
		if ( ! hub.connected ) {
			try {
				window.localStorage.removeItem( SHOWN );
			} catch ( error ) {
				// Nothing was stored, then.
			}
		}

		wasConnected.current = hub.connected;
	}, [ hub.connected, hub.returning ] );

	// The card both versions of the step show; `why` is the reason the site can't connect yet.
	const whatConnectingDoes = ( why = '' ) => (
		<SettingsCard icon="network" title={ __( 'What connecting does', 'bettershield' ) }>
			<div className="bs-ds-setup-card__body">
				<p className="bs-ds-setup__note">
					{ createInterpolateElement(
						__( 'Connecting turns on “Let AI assistants see security info” and “Let AI assistants fix things”. Change them under <a>Agents<new /></a>.', 'bettershield' ),
						{
							// In a new tab, as the other in-step links: this step has
							// no Back, and the same tab left the setup (#2632).
							a: links.agents ? <a href={ links.agents } target="_blank" rel="noopener noreferrer" /> : <span />,
							new: links.agents ? <span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span> : <span />,
						}
					) }
				</p>
				{ why ? <p className="bs-ds-setup__note">{ why }</p> : <p className="bs-ds-setup__note">{ __( 'You sign in to the hub, approve the connection, and come back here.', 'bettershield' ) }</p> }
			</div>
		</SettingsCard>
	);

	if ( hub.connected ) {
		return (
			<Frame
				variant="hero"
				badge={ <HubLink /> }
				title={ sprintf( /* translators: %s: the plugin's name. */ __( 'Connected to %s Hub', 'bettershield' ), brand() ) }
				subtitle={ __( 'This site now appears in the hub with your other sites.', 'bettershield' ) }
				footer={
					<Footer noSkip primary={ { label: __( 'Open the Dashboard', 'bettershield' ), onClick: () => leave( links.dashboard ) } }>
						<Button type="secondary" size="md" icon="arrow-out" iconTone="2" href={ hub.url } target="_blank" rel="noopener noreferrer">
							{ sprintf( /* translators: %s: the plugin's name. */ __( 'Open %s Hub', 'bettershield' ), brand() ) }
						</Button>
					</Footer>
				}
			>
				{ /* Closing it is the end of the setup, as "I’ll Connect Later"
				     is: the Dashboard opens, the dialog gone first. Only the tab
				     that shows it leaves; the other one stays on this step. */ }
				{ celebrating ? (
					<SetupDoneDialog
						already={ Boolean( hub.again ) }
						onClose={ () => {
							setCelebrating( false );

							if ( links.dashboard ) {
								leave( links.dashboard );
							} else {
								keepFocus();
							}
						} }
					/>
				) : null }
			</Frame>
		);
	}

	/*
	 * Where the site cannot connect yet, the step keeps its usual look: the
	 * same card, the reason under it, and Connect opening the Hub screen,
	 * which says what to change.
	 */
	if ( hub.blocked ) {
		return (
			<Frame
				variant="wide"
				title={ sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ) }
				subtitle={ __( 'Manage all your sites in one place, with downtime emails and one AI assistant.', 'bettershield' ) }
				footer={
					<Footer noSkip primary={ { label: sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ), onClick: () => setLeavingTo( links.hub ) } }>
						<Button type="secondary" size="md" onClick={ () => setLeavingTo( links.dashboard ) }>
							{ __( 'I’ll Connect Later', 'bettershield' ) }
						</Button>
					</Footer>
				}
			>
				{ whatConnectingDoes( hub.blocked ) }
				{ leaveDialog }
			</Frame>
		);
	}

	return (
		<Frame
			variant="wide"
			title={ sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ) }
			subtitle={ __( 'Manage all your sites in one place, with downtime emails and one AI assistant.', 'bettershield' ) }
			footer={
				<Footer noSkip primary={ { label: sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ), onClick: connect, busy: connecting } }>
					{ /* Filled, so the way out of the step reads as a button (#2531). */ }
					<Button type="secondary" size="md" disabled={ connecting } onClick={ () => setLeavingTo( links.dashboard ) }>
						{ __( 'I’ll Connect Later', 'bettershield' ) }
					</Button>
				</Footer>
			}
		>
			{ whatConnectingDoes() }
			{ leaveDialog }
		</Frame>
	);
}
