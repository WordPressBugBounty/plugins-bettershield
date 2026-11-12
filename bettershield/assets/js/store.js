/**
 * Data layer for the admin app.
 *
 * Three resources, each loaded the first time a screen asks for it rather
 * than all at once, so Overview is interactive without waiting for the other
 * screens' data. Every mutation returns the surfaces it moved, and those are
 * written straight back — a score that lags the change that caused it is the
 * kind of small dishonesty this product exists not to commit.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import { whenPhrase } from './ui/when';
import { atLeast, SCAN_HOLD, SEND_HOLD } from './ui/hold';
import { releaseUnsaved } from './next/ui/useUnsaved';

/*
 * Exported so the hooks below can be driven directly. They are the rules this
 * layer keeps rather than presentation, and testing a rule should not mean
 * mounting a screen.
 */
export const StoreContext = createContext( null );

const IDLE = { status: 'idle', data: null };

const ENDPOINTS = {
	overview: '/bettershield/v1/overview',
	findings: '/bettershield/v1/findings',
	hardening: '/bettershield/v1/hardening',
	passwordPolicy: '/bettershield/v1/settings/password-policy',
	uninstall: '/bettershield/v1/settings/uninstall',
	sudo: '/bettershield/v1/settings/sudo',
	lockdown: '/bettershield/v1/lockdown',
	securityTxt: '/bettershield/v1/settings/security-txt',
	loginProtection: '/bettershield/v1/login-protection',
	sessions: '/bettershield/v1/login-protection/sessions',
	twoFactor: '/bettershield/v1/two-factor/status',
	twoFactorPolicy: '/bettershield/v1/two-factor/policy',
	passkeyPolicy: '/bettershield/v1/passkeys/policy',
	abilities: '/bettershield/v1/settings/abilities',
	alerts: '/bettershield/v1/settings/alerts',
	aiStatus: '/bettershield/v1/ai/status',
	vulnerabilities: '/bettershield/v1/vulnerabilities',
	agentSurface: '/bettershield/v1/agent-surface',
	diagnostics: '/bettershield/v1/diagnostics',
	settingsUndo: '/bettershield/v1/settings/undo',
	usage: '/bettershield/v1/settings/usage',
};

/** How many of each settings area's changes the undo route lists by default, and how many more each widening reads. */
const UNDO_WINDOW = 20;

/** The widest window the undo route reads (SettingsLedger::MOST_LISTED); past it every read of the list was refused. */
const UNDO_MOST = 500;

export function StoreProvider( { children } ) {
	const [ resources, setResources ] = useState( {
		overview: IDLE,
		findings: IDLE,
		hardening: IDLE,
		passwordPolicy: IDLE,
		uninstall: IDLE,
		sudo: IDLE,
		lockdown: IDLE,
		securityTxt: IDLE,
		loginProtection: IDLE,
		sessions: IDLE,
		twoFactor: IDLE,
		twoFactorPolicy: IDLE,
		passkeyPolicy: IDLE,
		abilities: IDLE,
		alerts: IDLE,
		aiStatus: IDLE,
		vulnerabilities: IDLE,
		agentSurface: IDLE,
		diagnostics: IDLE,
		settingsUndo: IDLE,
		usage: IDLE,
	} );

	// Transient UI state: a failed action explains itself here rather than
	// throwing the screen away.
	const [ notice, setNotice ] = useState( null );
	/*
	 * What completed most recently, so a control that saves the moment it is
	 * flipped can say so. A toggle that writes silently reads as a dead
	 * control, and to somebody using a screen reader it is not merely quiet —
	 * there is no evidence the action happened at all.
	 */
	const [ saved, setSaved ] = useState( null );
	const [ busy, setBusy ] = useState( null );

	// Guards a resource against being fetched twice when two panels mount in
	// the same tick.
	const inflight = useRef( {} );

	// How many of each settings area's changes the undo list reads, once
	// "Load Older Changes" has widened it; 0 while it is the route's own.
	// Every later read of the list, a put-back's included, keeps the width.
	const undoWindow = useRef( 0 );
	const undoPath = ( path ) => ( undoWindow.current ? `${ path }?limit=${ undoWindow.current }` : path );

	// The action in flight, if any.
	const inflightAction = useRef( null );

	// Which call to act() was sent last, so a held working state is ended
	// only by the call that set it.
	const latestAction = useRef( 0 );

	// An action the password-confirmation gate held back, kept so the
	// confirmation dialog can re-run exactly what was asked. A ref rather
	// than state so the retry closure never reads a stale value; the boolean
	// is what the dialog renders on.
	const heldAction = useRef( null );
	const [ confirming, setConfirming ] = useState( false );

	/*
	 * Where the keyboard goes once the dialog has closed. The control that
	 * asked is held disabled while its request runs, so focus is already on
	 * the page body when the dialog opens, and that is where the dialog hands
	 * it back. The control is remembered from the moment it was pressed, and
	 * given focus again once the dialog has closed and nothing is in flight.
	 */
	const [ refocus, setRefocus ] = useState( null );

	// The same for a change to how people sign in that the recovery
	// pre-flight held back: the refused action, and what the check said.
	const heldPreflight = useRef( null );
	const [ preflight, setPreflight ] = useState( null );

	const put = useCallback( ( name, next ) => {
		setResources( ( current ) => ( { ...current, [ name ]: next } ) );
	}, [] );

	const load = useCallback(
		( name, { force = false } = {} ) => {
			if ( inflight.current[ name ] && ! force ) {
				return;
			}

			inflight.current[ name ] = true;
			// A refresh keeps what it already has on screen while the fresh
			// copy arrives: blanking a list to a skeleton after every toggle
			// unmounts the screen, drops focus and throws away any draft the
			// reader had open beside it.
			setResources( ( current ) => ( {
				...current,
				[ name ]: { status: 'loading', data: current[ name ] ? current[ name ].data : null },
			} ) );

			return apiFetch( { path: 'settingsUndo' === name ? undoPath( ENDPOINTS[ name ] ) : ENDPOINTS[ name ] } )
				.then( ( data ) => put( name, { status: 'ready', data } ) )
				.catch( () => put( name, { status: 'error', data: null } ) )
				.finally( () => {
					inflight.current[ name ] = false;
				} );
		},
		[ put ]
	);

	/**
	 * Lay an action's answer over the cached overview rather than replacing
	 * it. The answer is the screen payload less the unread-changes block,
	 * which only a visit may consume: written over the cached copy, it took
	 * "Since you last looked" off the screen until a reload.
	 */
	const putOverview = useCallback( ( data ) => {
		setResources( ( current ) => ( {
			...current,
			overview: {
				status: 'ready',
				data: current.overview && current.overview.data ? { ...current.overview.data, ...data } : data,
			},
		} ) );
	}, [] );

	/**
	 * Write back whatever surfaces a mutation returned. Anything it did not
	 * return is left alone rather than blanked, and that holds inside the
	 * overview as well.
	 */
	const absorb = useCallback(
		( payload ) => {
			if ( ! payload ) {
				return;
			}

			[ 'overview', 'findings', 'hardening', 'alerts' ].forEach( ( name ) => {
				if ( payload[ name ] !== undefined ) {
					if ( 'overview' === name ) {
						putOverview( payload.overview );
					} else {
						put( name, { status: 'ready', data: payload[ name ] } );
					}
				}
			} );

			/*
			 * A Fix answers with the score it produced and leaves the report
			 * out, so its row and the Undo beside it stay. The findings the
			 * fresh overview no longer counts as open are marked fixed on
			 * screen, beside the report, until the report is next read: any
			 * read replaces the resource, and the mark goes with it.
			 */
			if ( payload.overview !== undefined && payload.findings === undefined && Array.isArray( payload.overview?.findings ) ) {
				const stillOpen = new Set( payload.overview.findings.map( ( finding ) => finding.id ) );

				setResources( ( current ) => {
					const report = current.findings;

					if ( ! report || ! Array.isArray( report.data ) ) {
						return current;
					}

					const fixedNow = report.data.filter( ( finding ) => 'open' === finding.status && ! stillOpen.has( finding.id ) ).map( ( finding ) => finding.id );

					return { ...current, findings: { ...report, fixedNow } };
				} );
			}
		},
		[ put, putOverview ]
	);

	/**
	 * After a change to a hardening item: fetch the item list and the
	 * findings only where the answer did not already carry them.
	 */
	const refreshMissing = useCallback(
		( payload ) => {
			[ 'hardening', 'findings' ].forEach( ( name ) => {
				if ( ! payload || payload[ name ] === undefined ) {
					load( name, { force: true } );
				}
			} );
		},
		[ load ]
	);

	/*
	 * `then` runs on success and `refused` when the action did not happen: a
	 * refusal, or a password confirmation that was canceled. Both travel with
	 * a held action, so both survive the retry. The returned promise does
	 * not: behind the gate it has already resolved null, and a screen that
	 * chained its own follow-up onto it never ran it after the confirmation.
	 */
	const act = useCallback(
		( { path, key, then, refused, data, method = 'POST', hold = 0, origin = document.activeElement, refuseWhenBusy = false } ) => {
			// One action at a time. The screen disables the control it is
			// working on; this is the guard for the ones it does not, so a
			// second click while the first is in flight is not a second request.
			if ( null !== inflightAction.current ) {
				// Nothing was sent. A caller that waits on one of its two
				// answers before sending the next (the bulk runner) asks to
				// hear it was refused rather than wait forever; the others keep
				// the silent no-op they were written for.
				if ( refused && refuseWhenBusy ) {
					refused( { code: 'bettershield_busy', message: __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) } );
				}

				return Promise.resolve( null );
			}
			inflightAction.current = key;

			const call = ++latestAction.current;

			setNotice( null );
			setSaved( null );
			setBusy( key );

			/*
			 * `hold` keeps the control's working state up for one full pass of
			 * its animation — see ui/hold.js — and nothing else. The lock and
			 * the answer follow the request: held with the animation, every
			 * other control on the screen silently did nothing for three
			 * seconds after Run audit, and the new result reached the screen
			 * three seconds after the server had given it.
			 */
			const floor = atLeast( Promise.resolve(), hold );

			return apiFetch( { path, method, ...( data ? { data } : {} ) } )
				.then( ( result ) => {
					absorb( result );

					// A fresh object every time, so flipping the same control
					// twice announces twice rather than once.
					setSaved( { key, at: Date.now() } );

					if ( then ) {
						then( result );
					}

					return result;
				} )
				.catch( ( error ) => {
					// The gate the owner switched on: hold the action, ask for
					// the password, and the dialog re-runs it on success.
					if ( error && 'bettershield_confirm_password' === error.code ) {
						heldAction.current = { path, key, then, refused, data, method, hold, origin, refuseWhenBusy };
						setConfirming( true );

						return null;
					}

					// The way back in is not proved: hold the action, say why,
					// and let the person check now or go ahead a second time.
					if ( error && 'bettershield_recovery_preflight' === error.code ) {
						heldPreflight.current = { path, key, then, refused, data, method, hold, refuseWhenBusy };
						setPreflight( error.data?.preflight || { message: error.message, can_check_now: false, url: '' } );

						return null;
					}

					// A screen that says the refusal where it was made answers
					// true, and the banner at the top of the screen is not
					// raised as well, out of view and taking focus from it.
					const said = refused ? true === refused( error ) : false;

					if ( ! said ) {
						setNotice(
							error && error.message
								? error.message
								: __( 'That did not complete. Nothing was changed; try again.', 'bettershield' )
						);
					}

					return null;
				} )
				.finally( () => {
					inflightAction.current = null;
				} )
				// Only a success is held; a refusal says so at once.
				.then( ( result ) => ( null === result ? result : floor.then( () => result ) ) )
				.finally( () => {
					// Another action may have started in the meantime, and the
					// working state is now its own: the same control's too,
					// pressed again once something else had freed it, whose
					// request is still on its way when this hold ends.
					if ( call === latestAction.current ) {
						setBusy( ( current ) => ( current === key ? null : current ) );
					}

					/*
					 * The pressed control is held disabled while it works, and
					 * a browser drops focus off a disabled control to the page,
					 * so the next Tab started again at the top (#1926). Given
					 * back once nothing is in flight, where the control is
					 * still there and focus has gone nowhere else.
					 */
					setRefocus( ( current ) => current || { to: origin } );
				} );
		},
		[ absorb ]
	);

	const value = useMemo( () => {
		/*
		 * What follows a change to what agents may do, or to who is connected.
		 * The agent surface is one document, read by four tabs and the
		 * Overview's card, and a change made from one of them left the others
		 * drawing the old copy until a reload: Connect went on saying agents
		 * may apply a change, and offering a credential that could. Read again
		 * only where it has been read at all, then the caller's own follow-up.
		 */
		const surfaceMoved = ( onSuccess ) => ( data ) => {
			if ( resources.agentSurface.status !== 'idle' ) {
				load( 'agentSurface', { force: true } );
			}

			if ( onSuccess ) {
				onSuccess( data );
			}
		};

		/*
		 * An apply or undo refused because the item is already the way it was
		 * asked to be: another tab, an assistant or the monitor got there
		 * first. Nothing on this screen knew, so the row kept offering the
		 * press, and every press answered the same 409 until a reload. Read
		 * again what has been read at all, so the row catches up.
		 */
		const caughtUp = ( error ) => {
			if ( ! error || ! [ 'bettershield_already_active', 'bettershield_not_active' ].includes( error.code ) ) {
				return;
			}

			[ 'hardening', 'findings', 'overview' ].forEach( ( name ) => {
				if ( resources[ name ] && resources[ name ].status !== 'idle' ) {
					load( name, { force: true } );
				}
			} );
		};

		/*
		 * What follows a save the settings undo list records. The list sits on
		 * the Settings screen beside several of these settings, and it was
		 * read once: a save made there added a row nobody saw until a reload.
		 * Read again only where it has been read at all, then the caller's
		 * own follow-up.
		 */
		const settingsMoved = ( onSuccess ) => ( data ) => {
			if ( resources.settingsUndo.status !== 'idle' ) {
				load( 'settingsUndo', { force: true } );
			}

			if ( onSuccess ) {
				onSuccess( data );
			}
		};

		/*
		 * After a save the server audited for: the screens already holding the
		 * overview or the findings read them again, unless the answer carried
		 * them (the login settings answer does, and `act` has taken it in).
		 * A surface never opened is left for its own first read.
		 */
		const postureMoved = ( payload ) => {
			[ 'overview', 'findings' ].forEach( ( name ) => {
				if ( ( ! payload || payload[ name ] === undefined ) && resources[ name ].status !== 'idle' ) {
					load( name, { force: true } );
				}
			} );
		};

		return {
			resources,
			load,
			notice,
			setNotice,
			saved,
			busy,

			runAudit: () =>
				act( {
					path: '/bettershield/v1/audit',
					key: 'audit',
					hold: SCAN_HOLD,
					// Written as soon as it is answered, not after the button's
					// sweep: the audit endpoint answers with the overview
					// directly, and leaves the unread changes unread.
					then: ( data ) => {
						if ( data ) {
							putOverview( data );
							load( 'findings', { force: true } );
						}
					},
				} ).then(
					// Handed back once the sweep has played, so the screen can
					// say it happened: on a site where nothing changed, the only
					// visible difference is a timestamp moving by a second.
					( data ) => data
				),

			// The card offering the Quick Setup closes the moment it is
			// dismissed rather than waiting for the round trip: the owner asked
			// for it gone, and a card that lingers while a request is in flight
			// reads as ignoring them. The reload is what makes it stay gone.
			// A finished setup is closed to its URL until the owner asks to
			// run it again; the answer is where to go. Through `then`, so a
			// password asked for first still ends on the setup.
			// A screen pointing at one choice passes the step it is made on.
			reopenSetup: ( step ) =>
				act( {
					path: '/bettershield/v1/quick-setup/reopen',
					key: 'setup-reopen',
					data: 'string' === typeof step ? { step } : {},
					then: ( data ) => {
						if ( data?.url ) {
							window.location.assign( data.url );
						}
					},
				} ),

			// Behind the password gate: marking a copy staging makes it quieter.
			answerSiteIdentity: ( answer, then ) =>
				act( {
					path: '/bettershield/v1/site-identity/answer',
					key: 'site-identity',
					data: { answer },
					then: ( data ) => {
						load( 'overview', { force: true } );
						then?.( data );
					},
				} ),
			undoSiteIdentity: ( token, then ) =>
				act( {
					path: '/bettershield/v1/site-identity/undo',
					key: 'site-identity',
					data: { token },
					then: ( data ) => {
						load( 'overview', { force: true } );
						then?.( data );
					},
				} ),

			// Done with the card left after a move. Hides the card only; the
			// undo stays open on the server.
			doneSiteIdentity: ( token, then ) =>
				act( {
					path: '/bettershield/v1/site-identity/done',
					key: 'site-identity',
					data: { token },
					then: ( data ) => {
						load( 'overview', { force: true } );
						then?.( data );
					},
				} ),

			dismissSetupOffer: () =>
				act( { path: '/bettershield/v1/quick-setup/offer/dismiss', key: 'setup-offer' } ).then( ( data ) => {
					if ( data ) {
						load( 'overview', { force: true } );
					}
					return data;
				} ),

			/*
			 * The usage-data answer, from Settings or from the one reminder a
			 * skipped question earns. Either way the reminder is then done
			 * with, so the overview is read again as well as the switch.
			 */
			answerUsage: ( allowed ) =>
				act( {
					path: '/bettershield/v1/settings/usage',
					key: 'usage',
					data: { allowed },
					then: ( data ) => {
						put( 'usage', { status: 'ready', data } );
						load( 'overview', { force: true } );
					},
				} ),

			dismissUsageReminder: () =>
				act( {
					path: '/bettershield/v1/usage/reminder/dismiss',
					key: 'usage-reminder',
					then: ( data ) => {
						put( 'usage', { status: 'ready', data } );
						load( 'overview', { force: true } );
					},
				} ),

			// Same shape as the setup card above, and for the same reason: the
			// reader asked for it gone.
			dismissRelease: ( version ) =>
				act( { path: '/bettershield/v1/release/seen', key: 'release', data: { version } } ).then( ( data ) => {
					if ( data ) {
						load( 'overview', { force: true } );
					}
					return data;
				} ),

			// An application password held to routes and a network, that
			// hold taken away, and a change undone. The last two widen what a
			// credential reaches and may ask for the password first, so the
			// screen's callback rides along rather than chaining.
			// Each follow-up runs once the surface has been read again: the
			// row's controls and its line change only then.
			// `onRefused` lets the form say a refusal beside itself, not in
			// the page banner 2,500 px above it: true when it did (#2664).
			limitAppPassword: ( user, uuid, limit, then, onRefused ) =>
				act( {
					then: ( data ) =>
						Promise.resolve( load( 'agentSurface', { force: true } ) ).then( () => then?.( data ) ),
					path: `/bettershield/v1/agent-surface/app-passwords/${ user }/${ uuid }/limit`,
					key: `limit-${ uuid }`,
					data: limit,
					refused: ( error ) => onRefused?.( error ),
				} ),
			unlimitAppPassword: ( user, uuid, then ) =>
				act( {
					then: ( data ) =>
						Promise.resolve( load( 'agentSurface', { force: true } ) ).then( () => then?.( data ) ),
					path: `/bettershield/v1/agent-surface/app-passwords/${ user }/${ uuid }/limit`,
					key: `limit-${ uuid }`,
					method: 'DELETE',
				} ),
			undoAppPasswordLimit: ( token, then ) =>
				act( {
					then: ( data ) =>
						Promise.resolve( load( 'agentSurface', { force: true } ) ).then( () => then?.( data ) ),
					path: '/bettershield/v1/agent-surface/app-passwords/limit-undo',
					key: `limit-undo-${ token }`,
					data: { token },
				} ),

			saveAppPasswordExpiry: ( expiry, onSaved, onRefused ) =>
				act( {
					path: '/bettershield/v1/agent-surface/expiry',
					key: 'app-password-expiry',
					data: expiry,
					refused: ( error ) => onRefused?.( error ),
					then: settingsMoved( ( data ) => {
						load( 'agentSurface', { force: true } );
						onSaved?.( data );
					} ),
				} ),

			explainIncident: ( id, client, evidenceHash, then ) => act( { path: `/bettershield/v1/ai/incidents/${ id }`, data: { client, evidence_hash: evidenceHash }, then, key: 'incident-explanation' } ),
			prepareIncidentResponse: ( id, then ) => act( { path: `/bettershield/v1/incidents/${ id }/response`, then, key: 'incident-response' } ),
			applyIncidentResponse: ( token, selected, then ) => act( { path: `/bettershield/v1/incident-response/${ token }`, data: { selected }, then, key: 'incident-response' } ),
			undoIncidentResponse: ( token, item, then ) => act( { path: `/bettershield/v1/incident-response/${ token }/undo`, data: { item }, then, key: 'incident-response' } ),
			changeIncidentStatus: ( id, status, then ) => act( { path: `/bettershield/v1/incidents/${ id }/status`, key: `incident-${ id }`, data: { status }, then } ),
			refreshIncidents: () => act( { path: '/bettershield/v1/incidents/refresh', key: 'incidents-refresh' } ),

			// Behind the password gate, so what the card does with each answer
			// rides along in `then` rather than awaiting a first answer that
			// may be null and is never resolved again.
			saveDecoyPage: ( enabled, slug, onSaved, onRefused ) =>
				act( {
					path: '/bettershield/v1/agent-surface/decoy-page',
					key: 'decoy-page',
					data: { enabled, slug },
					refused: ( error ) => onRefused?.( error ),
					then: ( data ) => {
						load( 'agentSurface', { force: true } );
						onSaved?.( data );
					},
				} ),
			testDecoyPage: ( then ) => act( { path: '/bettershield/v1/agent-surface/decoy-page/test', key: 'decoy-page', then } ),

			setCanary: ( plant, onRefused ) =>
				act( {
					path: '/bettershield/v1/agent-surface/canary',
					key: 'canary',
					data: { plant },
					refused: ( error ) => onRefused?.( error ),
					then: () => load( 'agentSurface', { force: true } ),
				} ),

			setObservedCapture: ( enabled, then, refused ) => act( { path: '/bettershield/v1/observed-changes', data: { enabled }, then, refused, key: 'observed-capture' } ),
			restoreObservedChange: ( token, action, revision, then ) => act( { path: `/bettershield/v1/observed-changes/${ token }`, data: { action, revision }, then, key: 'observed-changes' } ),
			monitorItem: ( item, data, onSuccess ) => act( { path: `/bettershield/v1/hardening/${ item }/monitor`, data, key: `monitor-${ item }`, then: async ( result ) => { await Promise.all( [ load( 'hardening', { force: true } ), load( 'findings', { force: true } ) ] ); onSuccess?.( result ); } } ),
			/*
			 * The refresh and whatever the screen wants afterwards both run
			 * from the callback, not from a chained then: behind the password
			 * gate the first request is refused and resolves null, so a
			 * chained handler never sees the confirmed request's answer and
			 * the screen goes on showing the state the server no longer has.
			 *
			 * The answer carries the item list and the findings, and `act`
			 * has already put them in place, so the switch moves on the first
			 * answer. Anything an answer leaves out is fetched, as before.
			 */
			applyItem: ( item, options, onDone, onRefused, { refuseWhenBusy = false } = {} ) =>
				act( {
					path: `/bettershield/v1/hardening/${ item }/apply`,
					key: item,
					refuseWhenBusy,
					data: options ? { options } : undefined,
					then: ( data ) => {
						refreshMissing( data );
						onDone?.( data );
					},
					refused: ( error ) => {
						caughtUp( error );

						// The screen's answer passed on: true when it says the
						// refusal itself, and the top banner is not raised too.
						return onRefused?.( error );
					},
				} ),

			itemAction: ( item, action, args ) =>
				act( {
					path: `/bettershield/v1/hardening/${ item }/action/${ action }`,
					key: item,
					...( args ? { data: args } : {} ),
					then: () => load( 'hardening', { force: true } ),
				} ),

			// `refuseWhenBusy` for a caller that waits on one of the two answers
			// (the Findings undo): a press while another action ran was dropped
			// without either, and it waited for good.
			revertItem: ( item, onDone, onRefused, { refuseWhenBusy = false } = {} ) =>
				act( {
					path: `/bettershield/v1/hardening/${ item }/revert`,
					key: item,
					refuseWhenBusy,
					then: ( data ) => {
						refreshMissing( data );
						onDone?.( data );
					},
					refused: ( error ) => {
						caughtUp( error );

						// The screen's answer passed on: true when it says the
						// refusal itself, and the top banner is not raised too.
						return onRefused?.( error );
					},
				} ),

			// The owner's own answer travels with the request: a preview that
			// never reads the field cannot refuse anything, which makes it
			// read as approval.
			dryRun: ( item, options ) =>
				apiFetch( {
					path: `/bettershield/v1/hardening/${ item }/dry-run`,
					method: 'POST',
					...( options ? { data: { options } } : {} ),
				} ).catch( () => {
					setNotice( __( 'The preview could not be loaded. Nothing was changed.', 'bettershield' ) );
					return null;
				} ),

			setVulnerabilityChecks: ( enabled ) =>
				act( {
					path: '/bettershield/v1/vulnerabilities/consent',
					key: 'vulnerabilities',
					data: { enabled },
					// The server audits again with the answer, so the score
					// moves as well as the list.
					then: ( data ) => {
						put( 'vulnerabilities', { status: 'ready', data } );
						load( 'overview', { force: true } );
						load( 'findings', { force: true } );
					},
				} ),
			// Written as soon as it is answered; the returned promise waits
			// for the button's sweep.
			checkVulnerabilities: () =>
				act( {
					path: '/bettershield/v1/vulnerabilities/check',
					key: 'vulnerabilities',
					hold: SCAN_HOLD,
					then: ( data ) => {
						if ( data ) {
							put( 'vulnerabilities', { status: 'ready', data } );
							load( 'overview', { force: true } );
							load( 'findings', { force: true } );
						}
					},
				} ),
			// The answer carries the report and the score, which `act` takes in.
			quarantineTool: ( path ) =>
				act( {
					path: '/bettershield/v1/findings/leftover_tools_reachable/quarantine',
					key: `tool-${ path }`,
					data: { path },
				} ),
			// The same move for a downloadable backup, dump or log.
			quarantineArtifact: ( path, then ) =>
				act( {
					path: '/bettershield/v1/findings/artifacts_downloadable/quarantine',
					key: `artifact-${ path }`,
					data: { path },
					then,
				} ),
			// Behind the password gate, so the screen's callback rides along
			// rather than chaining onto a first answer that may be null.
			// Putting a finding back is not gated, and takes its callback the
			// same way so the two buttons on a row are written alike.
			// `refused` hears that one did not happen: a refusal, or a
			// password confirmation canceled. A screen acting on several
			// findings in turn waits on one or the other before the next.
			suppress: ( key, then, refused ) => act( { path: `/bettershield/v1/findings/${ key }/suppress`, key, then, refused, refuseWhenBusy: true } ),
			snooze: ( key, days, then, refused ) => act( { path: `/bettershield/v1/findings/${ key }/snooze`, key, data: { days }, then, refused, refuseWhenBusy: true } ),
			wake: ( key, then, refused ) => act( { path: `/bettershield/v1/findings/${ key }/wake`, key, then, refused, refuseWhenBusy: true } ),
			unsuppress: ( key, then, refused ) => act( { path: `/bettershield/v1/findings/${ key }/unsuppress`, key, then, refused, refuseWhenBusy: true } ),
			/*
			 * One step of a Fix panel's default, applied or undone from the
			 * finding's row (#2618): the route the panel itself calls, under
			 * the panel's own working key. A row runs several in turn and
			 * waits on one answer or the other, so a step started while
			 * another runs is refused rather than dropped.
			 */
			runFix: ( path, key, data, then, refused ) => act( { path, key, data, then, refused, refuseWhenBusy: true } ),
			// The quarantine folder's Fix (#2207): its seal written, taken
			// back (which asks for the session), and the server asked again
			// in the background. Each answers with what the panel draws.
			sealQuarantine: ( then ) => act( { path: '/bettershield/v1/findings/quarantine_unsealed/seal', key: 'quarantine-seal', then } ),
			unsealQuarantine: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/quarantine_unsealed/seal/undo', key: 'quarantine-seal', data: { undo }, then, refused } ),
			checkQuarantineAgain: ( then ) => act( { path: '/bettershield/v1/findings/quarantine_unsealed/check', key: 'quarantine-check', then } ),
			// Two-factor brought over from another plugin, taken back (#2762).
			undoTwoFactorImport: ( undo, then, refused ) => act( { path: '/bettershield/v1/two-factor/import/undo', key: 'two-factor-import', data: { undo }, then, refused } ),
			// The domain records' Check again (#2203): queues the lookup only.
			checkDomainRecordsAgain: ( then ) => act( { path: '/bettershield/v1/findings/domain_mail_records/check', key: 'domain-check', then } ),
			// How to fix a finding outside this plugin (#2430): its check asked
			// again. The answer carries the report and the score.
			checkFindingAgain: ( key, then ) => act( { path: `/bettershield/v1/findings/${ key }/guidance`, key: `guidance-${ key }`, hold: SCAN_HOLD, then } ),
			// The hidden content's Fix (#2210): the sign-in address moved again,
			// after the session, the password and the recovery pre-flight.
			// The stalled schedule's Try now (#2209): spawns the site's own run.
			trySchedule: ( then ) => act( { path: '/bettershield/v1/findings/cron_schedule_stalled/schedule', key: 'schedule-run', then } ),
			changeLoginAddress: ( slug, then ) => act( { path: '/bettershield/v1/findings/login_url_shadows_content/address', key: 'login-address', data: { slug }, then } ),
			// The plain-HTTP content's Fix (#1291): one batch of the rewrite,
			// or of its undo, per call.
			rewriteContentLinks: ( then ) => act( { path: '/bettershield/v1/findings/mixed_content_published/links/rewrite', key: 'content-links', then } ),
			undoContentLinks: ( then, refused ) => act( { path: '/bettershield/v1/findings/mixed_content_published/links/undo', key: 'content-links', then, refused } ),
			// The plain-HTTP address's Fix (#1289): the switch after the
			// recovery pre-flight, Keep HTTPS, and the way back. Each asks
			// for the session, so each rides the shared layer.
			switchToHttps: ( then ) => act( { path: '/bettershield/v1/findings/site_not_https/address', key: 'https-address', then } ),
			keepHttps: ( then ) => act( { path: '/bettershield/v1/findings/site_not_https/address/keep', key: 'https-address', then } ),
			undoHttps: ( then ) => act( { path: '/bettershield/v1/findings/site_not_https/address/undo', key: 'https-address', then } ),
			// The world-writable folders' Fix (#2211): the chosen folders
			// narrowed, and one put back (which asks for the session).
			tightenFolders: ( folders, then ) => act( { path: '/bettershield/v1/findings/content_dirs_world_writable/folders', key: 'content-folders', data: { folders }, then } ),
			restoreFolder: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/content_dirs_world_writable/folders/undo', key: 'content-folders', data: { undo }, then, refused } ),
			// The account findings' Fixes (#2430): each change, and each way
			// back, touches an account, so each may ask for the password first.
			renameAdmin: ( username, then, refused ) =>
				act( { path: '/bettershield/v1/findings/admin_username_exists/rename', key: 'admin-rename', data: { username }, then, refused } ),
			undoAdminRename: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/admin_username_exists/rename/undo', key: 'admin-rename', data: { undo }, then, refused } ),
			revokeStalePasswords: ( passwords, then ) => act( { path: '/bettershield/v1/findings/application_passwords_stale/revoke', key: 'stale-passwords', data: { passwords }, then } ),
			// Accepting a flagged store script, and taking that back (#2844).
			acceptStoreScript: ( script, then ) => act( { path: '/bettershield/v1/findings/store_script_reads_cards/accept', key: 'store-scripts', data: { script }, then } ),
			unacceptStoreScript: ( script, then ) => act( { path: '/bettershield/v1/findings/store_script_reads_cards/accept', key: 'store-scripts', data: { script }, method: 'DELETE', then } ),
			suspendDormant: ( accounts, then ) => act( { path: '/bettershield/v1/findings/privileged_account_dormant/suspend', key: 'dormant-accounts', data: { accounts }, then } ),
			// Also from the list of suspensions, which names the route.
			letBackIn: ( undo, then, path = '/bettershield/v1/findings/privileged_account_dormant/suspend/undo' ) =>
				act( { path: path.startsWith( '/bettershield/v1/' ) ? path : '/bettershield/v1/findings/privileged_account_dormant/suspend/undo', key: 'dormant-accounts', data: { undo }, then } ),
			askNewPasswords: ( accounts, then ) => act( { path: '/bettershield/v1/findings/passwords_below_policy/hold', key: 'weak-passwords', data: { accounts }, then } ),
			undoNewPassword: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/passwords_below_policy/hold/undo', key: 'weak-passwords', data: { undo }, then, refused } ),
			// The extension and site fixes (#2430): each press, and each way
			// back, which may ask for the password. Every path is written out,
			// so each can be found where it is called.
			updatePlugin: ( finding, plugin, then, refused ) =>
				act( {
					path: 'vulnerabilities_known' === finding ? '/bettershield/v1/findings/vulnerabilities_known/updates' : '/bettershield/v1/findings/plugin_updates_available/updates',
					key: 'plugin-update',
					data: { plugin },
					then,
					refused,
				} ),
			undoPluginUpdate: ( finding, undo, then, refused ) =>
				act( {
					path: 'vulnerabilities_known' === finding ? '/bettershield/v1/findings/vulnerabilities_known/updates/undo' : '/bettershield/v1/findings/plugin_updates_available/updates/undo',
					key: 'plugin-update',
					data: { undo },
					then,
					refused,
				} ),
			quarantineExtension: ( kind, id, then, refused ) => act( { path: '/bettershield/v1/findings/inactive_extensions/extensions', key: 'extensions', data: { kind, id }, then, refused } ),
			putBackExtension: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/inactive_extensions/extensions/undo', key: 'extensions', data: { undo }, then, refused } ),
			keepSignInUncached: ( then, refused ) => act( { path: '/bettershield/v1/findings/sign_in_page_cached/no-cache', key: 'sign-in-cache', then, refused } ),
			checkSignInCache: ( then, refused ) => act( { path: '/bettershield/v1/findings/sign_in_page_cached/no-cache/check', key: 'sign-in-cache', then, refused } ),
			tightenConfig: ( then, refused ) => act( { path: '/bettershield/v1/findings/config_world_writable/mode', key: 'config-mode', then, refused } ),
			restoreConfig: ( undo, then, refused ) => act( { path: '/bettershield/v1/findings/config_world_writable/mode/undo', key: 'config-mode', data: { undo }, then, refused } ),
			// Three findings answered by a setting of this plugin's own (#2564).
			// Each answer carries the score and the settings record, or the
			// item, its Undo puts back.
			blockCommonNames: ( then, refused ) => act( { path: '/bettershield/v1/findings/common_usernames_allowed/names', key: 'sign-in-extras', then, refused } ),
			turnOnProofOfWork: ( then, refused ) => act( { path: '/bettershield/v1/findings/proof_of_work_off/proof', key: 'sign-in-extras', then, refused } ),
			blockPingbacks: ( then, refused ) => act( { path: '/bettershield/v1/findings/pingbacks_open/block', key: 'sign-in-extras', then, refused } ),
			reapplyProtection: ( item, then, refused ) => act( { path: '/bettershield/v1/findings/hardening_not_working/protections', key: 'reapply-protection', data: { item }, then, refused } ),

			/*
			 * The file screen's reversing actions, and the two that quiet a
			 * package difference. They live here rather than beside the screen
			 * because each of them takes a protection away, and the site may
			 * be asking for the password again before it will do that — a
			 * challenge only this layer knows how to answer. A screen fetching
			 * for itself prints the sentence and offers nothing to type into.
			 */
			markChangeExpected: ( id, then ) =>
				act( { then, path: `/bettershield/v1/integrity/changes/${ id }/suppress`, key: `change-${ id }` } ),
			stopExpectingChange: ( id, then ) =>
				act( { then, path: `/bettershield/v1/integrity/changes/${ id }/suppress`, key: `change-${ id }`, method: 'DELETE' } ),
			adoptPackage: ( slug, version, then ) =>
				act( {
					then,
					path: `/bettershield/v1/integrity/packages/${ slug }/adopt`,
					key: `package-${ slug }`,
					data: { version },
				} ),
			// A plugin's changes at one version marked expected together, and
			// that marking taken back: the same guard as one row's.
			markPackageExpected: ( slug, context, version, count, digest, then ) =>
				act( {
					then,
					path: `/bettershield/v1/integrity/packages/${ slug }/expect`,
					key: `package-${ slug }`,
					data: { context, version, count, digest },
				} ),
			unmarkPackageExpected: ( slug, token, then ) =>
				act( {
					then,
					path: `/bettershield/v1/integrity/packages/${ slug }/expect`,
					key: `batch-${ token }`,
					method: 'DELETE',
					data: { token },
				} ),
			// A selection of changes marked expected as one decision, and that
			// marking taken back: the same guard as one row's.
			markChangesExpected: ( ids, then, refused ) =>
				act( { then, refused, path: '/bettershield/v1/integrity/changes/expect', key: 'changes-batch', data: { ids } } ),
			unmarkChangesExpected: ( token, then ) =>
				act( { then, path: '/bettershield/v1/integrity/changes/expect', key: `batch-${ token }`, method: 'DELETE', data: { token } } ),
			// Every change a filter matches marked expected the same way, held
			// to the count and the newest row the owner was shown; the
			// selection's own DELETE takes it back.
			markMatchingExpected: ( match, then, refused ) =>
				act( { then, refused, path: '/bettershield/v1/integrity/changes/matching/expect', key: 'changes-batch', data: match } ),
			undoPackageAdoption: ( slug, token, then ) =>
				act( {
					then,
					path: `/bettershield/v1/integrity/packages/${ slug }/adopt`,
					key: `package-${ slug }`,
					method: 'DELETE',
					data: { token },
				} ),
			putQuarantinedBack: ( token, then ) =>
				act( { then, path: `/bettershield/v1/quarantine/${ token }/restore`, key: token } ),
			forgetQuarantined: ( token, then ) =>
				act( { then, path: `/bettershield/v1/quarantine/${ token }`, key: token, method: 'DELETE' } ),
			// Several kept copies at once, put back or removed for good, after
			// one question; the screen sends them a batch at a time.
			quarantineBatch: ( action, tokens, then, refused ) =>
				act( { then, refused, path: '/bettershield/v1/quarantine/batch', key: 'quarantine-batch', data: { action, tokens }, refuseWhenBusy: true } ),

			// `onEnded` rides in `then`, so a pause ended after the password
			// gate asked first is still said where it was ended.
			endSafeMode: ( onEnded ) =>
				act( {
					path: '/bettershield/v1/safe-mode/end',
					key: 'safe-mode',
					then: ( result ) => {
						load( 'overview', { force: true } );

						if ( onEnded ) {
							onEnded( result );
						}
					},
				} ),

			// The new URL is handed to `then` rather than read off the returned
			// promise: when the password gate asks first, that promise answers
			// null and only `then` is carried into the confirmed retry — which
			// would leave the old link retired and the new one never shown.
			generateRecovery: ( onIssued ) => act( { path: '/bettershield/v1/recovery/regenerate', key: 'recovery', then: onIssued } ),
			// The answer carries the overview, which `act` takes in; the audit
			// it ran moved the findings too, read again where they are read.
			checkRecoveryReadiness: () =>
				act( {
					path: '/bettershield/v1/recovery/readiness/check',
					key: 'recovery-readiness',
					hold: SCAN_HOLD,
					then: () => {
						if ( 'idle' !== resources.findings.status ) {
							load( 'findings', { force: true } );
						}
					},
				} ),
			setRecoveryEmailTests: ( enabled ) => act( { path: '/bettershield/v1/recovery/readiness', key: 'recovery-email-tests', data: { email_tests: enabled } } ),
			// The owner's word that the recovery email arrived: the one thing
			// that confirms the emailed link as a way back in. The answer is
			// the setup's state, so the overview and findings are read again.
			confirmRecoveryReceived: ( then ) =>
				act( {
					path: '/bettershield/v1/quick-setup/recovery/received',
					key: 'recovery-received',
					data: { received: true },
					then: ( result ) => {
						load( 'overview', { force: true } );

						if ( 'idle' !== resources.findings.status ) {
							load( 'findings', { force: true } );
						}

						if ( then ) {
							then( result );
						}
					},
				} ),

			/*
			 * The codes are shown once and kept nowhere else, so what the
			 * screen does with them is passed in as a callback rather than
			 * chained on: behind the password gate the first request is
			 * refused and resolves null, and only the callback survives the
			 * retry. Chained, the set was issued, hashed and never shown —
			 * and issuing a set replaces the printed one the owner already
			 * had.
			 */
			issueRecoveryCodes: ( onIssued ) =>
				act( {
					path: '/bettershield/v1/recovery/codes',
					key: 'recovery-codes',
					then: ( data ) => {
						load( 'overview', { force: true } );
						onIssued?.( data );
					},
				} ),

			/*
			 * The read opt-in, saved from two screens and stored once.
			 *
			 * What follows a save is passed in rather than chained on, for the
			 * reason the write opt-in below states: a site with the password
			 * gate on answers the first request with a refusal, and only the
			 * callback survives the retry.
			 */
			saveAbilities: ( enabled, onSuccess, refused ) =>
				act( {
					path: '/bettershield/v1/settings/abilities',
					key: 'abilities',
					data: { enabled },
					refused,
					then: ( data ) => {
						put( 'abilities', { status: 'ready', data } );

						// The registered-abilities list changes with the toggle.
						if ( resources.agentSurface.status !== 'idle' ) {
							load( 'agentSurface', { force: true } );
						}

						// And the switch records a way back on the undo list.
						if ( resources.settingsUndo.status !== 'idle' ) {
							load( 'settingsUndo', { force: true } );
						}

						if ( onSuccess ) {
							onSuccess( data );
						}
					},
				} ),

			/*
			 * Letting an agent act, and the three moves that follow from it.
			 *
			 * They run through this layer rather than the screen's own
			 * fetcher because allowing one change is a protected action: the
			 * site can answer it by asking for the password again, and this
			 * is the only place that recognizes that refusal and can put a
			 * field on screen to answer it. What the screen wants to do
			 * afterwards is therefore passed in as a callback rather than
			 * chained onto the promise — the held request resolves null, and
			 * only the callback survives the retry.
			 */
			saveWriteAccess: ( enabled, onSuccess ) =>
				act( {
					path: '/bettershield/v1/agents/write-access',
					key: 'agents-write-access',
					data: { enabled },
					then: surfaceMoved( onSuccess ),
				} ),

			allowProposal: ( id, onSuccess ) =>
				act( {
					path: `/bettershield/v1/agents/proposals/${ encodeURIComponent( id ) }/allow`,
					key: `proposal-${ id }`,
					then: surfaceMoved( onSuccess ),
				} ),

			withdrawProposal: ( id, onSuccess ) =>
				act( {
					path: `/bettershield/v1/agents/proposals/${ encodeURIComponent( id ) }/withdraw`,
					key: `proposal-${ id }`,
					then: surfaceMoved( onSuccess ),
				} ),

			/*
			 * Pairing an assistant with this site, and the moves that follow.
			 *
			 * They belong here for the same reason allowing a change does:
			 * each is a protected action the site may answer by asking for
			 * the password again, and this is the only layer that recognizes
			 * that refusal and can put a field on screen to answer it. What
			 * the screen wants to do with the reply is passed in as a
			 * callback rather than chained onto the promise — the held
			 * request resolves null, and only the callback survives the retry.
			 *
			 * Connect and rotate hand back a credential in plaintext exactly
			 * once. It is never written into a resource, so nothing here
			 * absorbs the reply; the screen shows it and lets it go. Each
			 * carries the scope the credential is minted for, so the reader's
			 * choice reaches the mint rather than being applied afterwards.
			 */
			setMcpEnabled: ( enabled, onSuccess, refused ) =>
				act( { path: '/bettershield/v1/mcp/enable', key: 'mcp-enable', data: { enabled }, then: surfaceMoved( onSuccess ), refused } ),

			connectMcp: ( scope, onSuccess ) =>
				act( { path: '/bettershield/v1/mcp/connect', key: 'mcp-connect', data: { scope }, then: surfaceMoved( onSuccess ) } ),

			rotateMcp: ( scope, onSuccess ) =>
				act( { path: '/bettershield/v1/mcp/rotate', key: 'mcp-rotate', data: { scope }, then: surfaceMoved( onSuccess ) } ),

			disconnectMcp: ( onSuccess ) =>
				act( { path: '/bettershield/v1/mcp/disconnect', key: 'mcp-disconnect', then: surfaceMoved( onSuccess ) } ),

			revokeMcpApp: ( id, onSuccess ) =>
				act( {
					path: `/bettershield/v1/mcp/apps/${ encodeURIComponent( id ) }`,
					method: 'DELETE',
					key: `mcp-app-${ id }`,
					then: surfaceMoved( onSuccess ),
				} ),

			// The tools one app may use (#1879): unticked ones are hidden
			// from it and refused. Allowing one back asks for the password.
			setMcpAppTools: ( id, toolsDenied, onSuccess ) =>
				act( {
					path: `/bettershield/v1/mcp/apps/${ encodeURIComponent( id ) }/tools`,
					key: `mcp-app-tools-${ id }`,
					data: { tools_denied: toolsDenied },
					then: onSuccess,
				} ),

			testMcpConnection: ( onSuccess ) =>
				act( { path: '/bettershield/v1/mcp/self-test', key: 'mcp-self-test', hold: SEND_HOLD, then: onSuccess } ),

			/*
			 * The optional hub. Connecting turns on the switches it needs and
			 * answers with the address the browser goes to next; the screen
			 * follows it. Starting and ending the connection
			 * are protected like every other move on this tab.
			 */
			connectHub: ( access, onSuccess ) =>
				act( { path: '/bettershield/v1/hub/connect', key: 'hub-connect', data: { access }, then: onSuccess } ),

			disconnectHub: ( onSuccess ) =>
				act( { path: '/bettershield/v1/hub/disconnect', key: 'hub-disconnect', then: onSuccess } ),

			// The Hub link: on with the classes it sends, or off. Answers with
			// the hub's state, as the calls above do.
			setHubLink: ( data, onSuccess ) =>
				act( { path: '/bettershield/v1/hub/link', key: 'hub-link', data, then: onSuccess } ),

			/*
			 * Recording agent activity, which is a different decision from
			 * letting agents read this site. The reply carries only the
			 * capture flag, so it is merged into the abilities resource
			 * rather than replacing it — writing the whole value back would
			 * blank the read opt-in beside it on screen.
			 */
			setAgentCapture: ( enabled ) =>
				act( {
					path: '/bettershield/v1/agent-activity/capture',
					key: 'agentCapture',
					data: { enabled },
					then: settingsMoved( ( data ) => {
						if ( resources.abilities.status === 'ready' ) {
							put( 'abilities', {
								status: 'ready',
								data: { ...resources.abilities.data, capture_enabled: data.capture_enabled },
							} );
						}
					} ),
				} ),

			/*
			 * Naming a role here decides whether a password opens those
			 * accounts. The reply is re-read rather than assumed, because the
			 * coverage counts beside the control change with it — how many of
			 * the named accounts actually hold a passkey is the only thing
			 * that says whether the policy is doing anything yet.
			 */
			savePasskeyPolicy: ( policy, onSaved ) =>
				act( {
					path: '/bettershield/v1/passkeys/policy',
					key: 'passkey-policy',
					data: policy,
					then: settingsMoved( ( data ) => {
						load( 'passkeyPolicy', { force: true } );
						onSaved?.( data );
					} ),
				} ),

			/*
			 * The emergency switch. Both directions reload the whole overview
			 * as well, because a lockdown changes what most other panels are
			 * telling the reader — and a screen still describing the site as
			 * open while it is closed is worse than a slow one.
			 */
			setLockdown: ( active ) =>
				act( {
					path: '/bettershield/v1/lockdown',
					key: 'lockdown',
					data: { active },
					then: settingsMoved( ( data ) => {
						put( 'lockdown', { status: 'ready', data } );
						load( 'overview', { force: true } );
					} ),
				} ),

			startTwoFactor: () => act( { path: '/bettershield/v1/two-factor/start', key: 'two-factor' } ),

			confirmTwoFactor: ( code ) =>
				act( { path: '/bettershield/v1/two-factor/confirm', key: 'two-factor', data: { code } } ),

			acknowledgeTwoFactor: () =>
				act( {
					path: '/bettershield/v1/two-factor/acknowledge',
					key: 'two-factor',
					then: () => load( 'twoFactor', { force: true } ),
				} ),

			discardTwoFactor: () =>
				// The status carries a pending flag; drop the stale copy
				// whether or not the request landed, since the screen returns
				// to the beginning either way. Behind the password gate the
				// first attempt is refused, so the refresh below reads the
				// state the discard has not happened to yet — hence the one
				// in `then`, which runs on the confirmed retry.
				act( {
					path: '/bettershield/v1/two-factor/discard',
					key: 'two-factor',
					then: () => load( 'twoFactor', { force: true } ),
				} ).then( ( data ) => {
					load( 'twoFactor', { force: true } );
					return data;
				} ),

			// A code, as everywhere; in safe mode, the account's own password
			// instead, which the server accepts only then.
			disableTwoFactor: ( code, password ) =>
				act( {
					path: '/bettershield/v1/two-factor/disable',
					key: 'two-factor',
					data: password ? { password } : { code },
					then: () => load( 'twoFactor', { force: true } ),
				} ),

			// A fresh set for an account already enrolled. The codes come back
			// once, in the response, and are never stored anywhere — so the
			// caller shows them and the reader keeps them, or they are gone.
			reissueBackupCodes: ( code, onIssued ) =>
				act( {
					path: '/bettershield/v1/two-factor/backup-codes',
					key: 'backup-codes',
					data: { code },
					then: ( data ) => {
						load( 'twoFactor', { force: true } );
						onIssued?.( data );
					},
				} ),

			// Sign-in limits left to another plugin, as the Quick Setup's step
			// leaves them: behind the password gate, so the follow-up rides along.
			leaveLimitsToOther: ( then ) =>
				act( {
					path: '/bettershield/v1/findings/login_limits_overlap/leave',
					key: 'login-limits-leave',
					then: ( data ) => {
						load( 'loginProtection', { force: true } );
						then?.( data );
					},
				} ),

			// Scheduled events nothing answers, removed from their finding, and
			// put back: the undo is behind the password gate, so its follow-up
			// rides along. The answers carry the report, which `act` takes in.
			removeCronEvents: ( hooks, then ) =>
				act( {
					path: '/bettershield/v1/findings/cron_events_unanswered/remove',
					key: 'cron-remove',
					data: { hooks },
					then,
				} ),
			undoCronRemoval: ( undo, then, refused ) =>
				act( {
					path: '/bettershield/v1/findings/cron_events_unanswered/remove/undo',
					key: 'cron-undo',
					data: { undo },
					then,
					refused,
				} ),

			// REST routes the owner picked to close to strangers (#1870): watching
			// and closing take nothing away; opening one again asks for the
			// session, so its follow-up rides along. Each answer is the panel's list.
			watchRestRoute: ( route, then ) =>
				act( {
					path: '/bettershield/v1/findings/rest_surface_unreviewed/routes/watch',
					key: 'rest-route',
					data: { route },
					then,
				} ),
			closeRestRoute: ( route, then ) =>
				act( {
					path: '/bettershield/v1/findings/rest_surface_unreviewed/routes/close',
					key: 'rest-route',
					data: { route },
					then,
				} ),
			reopenRestRoute: ( undo, then, refused ) =>
				act( {
					path: '/bettershield/v1/findings/rest_surface_unreviewed/routes/undo',
					key: 'rest-route-undo',
					data: { undo },
					then,
					refused,
				} ),

			// An update's ability changes taken as expected: behind the password
			// gate, so the follow-up rides along.
			acceptAbilityChanges: ( then ) => act( { path: '/bettershield/v1/agent-surface/abilities/accept', key: 'ability-accept', then } ),
			// And brought back to wait again: it only adds warnings, so it is open.
			undoAbilityAccept: ( undo, then ) => act( { path: '/bettershield/v1/agent-surface/abilities/accept/undo', key: 'ability-accept-undo', data: { undo }, then } ),

			saveLoginProtection: ( settings, onSaved ) =>
				act( {
					path: '/bettershield/v1/login-protection',
					key: 'login-protection',
					data: settings,
					then: settingsMoved( ( data ) => {
						load( 'loginProtection', { force: true } );
						// The Protections tile counts these settings too.
						load( 'hardening', { force: true } );
						// The save answers with the audit it ran, so a finding
						// it closed is gone without a Run audit.
						postureMoved( data );
						onSaved?.( data );
					} ),
				} ),

			// The follow-up runs once the list has been read again: the row's
			// button is replaced by its chip only then.
			releaseLockout: ( id, onDone, onRefused ) =>
				act( {
					path: `/bettershield/v1/login-protection/lockouts/${ id }/release`,
					key: `lockout-${ id }`,
					then: ( data ) =>
						Promise.resolve( load( 'loginProtection', { force: true } ) ).then( () => onDone?.( data ) ),
					// Already over (its emailed link, another administrator): the
					// list is read again so the row says what is true now, and
					// the screen is told why beside it.
					refused: ( error ) => {
						if ( error && 'bettershield_no_lockout' === error.code ) {
							Promise.resolve( load( 'loginProtection', { force: true } ) ).then( () => onRefused?.( error ) );

							// Said beside the list by the screen that asked.
							return Boolean( onRefused );
						}

						onRefused?.( error );

						// Said beside the list too, by the screen that asked: a
						// banner as well would say it twice, and take the
						// keyboard from the list to the top of the page.
						return Boolean( onRefused );
					},
				} ),

			undoSettingsChange: ( token, accept ) =>
				act( { path: undoPath( `/bettershield/v1/settings/undo/${ token }` ), key: token, then: ( data ) => {
					if ( data ) {
						put( 'settingsUndo', { status: 'ready', data } );
						// The surfaces this may have rewritten are re-read
						// rather than patched: what came back is whatever the
						// validator accepted, which is not always what was
						// asked for.
						[ 'loginProtection', 'passwordPolicy', 'alerts', 'securityTxt', 'twoFactorPolicy', 'sudo', 'uninstall', 'abilities' ].forEach(
							( key ) => load( key, { force: true } )
						);
						postureMoved();
					}
					accept?.( data );
				} } ),

			// Twenty more of each settings area's changes, read in place of
			// the list on screen: the window widens rather than paging, so a
			// quiet area's change is never skipped between two pages.
			loadOlderSettingsChanges: () => {
				undoWindow.current = Math.min( ( undoWindow.current || UNDO_WINDOW ) + UNDO_WINDOW, UNDO_MOST );
				return load( 'settingsUndo', { force: true } );
			},

			// Keyed per control rather than per screen. One key for every
			// sign-out meant confirming it for one person spun and disabled
			// every other person's button and the site-wide one at the same
			// time, which reads as a site-wide sign-out already underway — on
			// the most consequential control here.
			endSessions: ( payload, onDone ) =>
				act( {
					path: '/bettershield/v1/login-protection/sessions/end',
					key: payload && payload.user_id ? `sessions-${ payload.user_id }` : 'sessions-site',
					data: payload,
					then: ( data ) => {
						if ( data ) {
							put( 'sessions', {
								status: 'ready',
								data: {
									sessions: data.sessions,
									total: data.total,
									reach: data.reach,
									cap_supported: data.cap_supported,
								},
							} );
						}

						/*
						 * The sweep is bounded and says what it did not reach.
						 * The confirmation promises every session on the site,
						 * so a sweep that stopped short has to say so here —
						 * silence reads as "done", which is the one thing this
						 * button must not say when it is not true.
						 */
						if ( data && ( data.surplus > 0 || data.skipped > 0 ) ) {
							setNotice(
								sprintf(
									/* translators: %d: how many accounts the sweep did not reach. */
									_n(
										'Sessions ended, but %d account was not reached. Run it again to finish.',
										'Sessions ended, but %d accounts were not reached. Run it again to finish.',
										( data.surplus || 0 ) + ( data.skipped || 0 ),
										'bettershield'
									),
									( data.surplus || 0 ) + ( data.skipped || 0 )
								)
							);
						}
						// The confirmation promised the sign-in page; keep the promise
						// in the same click rather than on whatever the reader does
						// next with a session that no longer exists.
						if ( data && data.ended_own && data.login_url ) {
							// Confirmed already, and the session is gone: no
							// second "leave this page?" on the way out.
							releaseUnsaved();
							window.location.assign( data.login_url );

							return;
						}

						onDone?.( data );
					},
				} ),

			// One of keep, remove, or package-then-remove. Sent by name rather
			// than as a flag, because a third answer has no boolean to be.
			saveUninstallChoice: ( choice ) =>
				act( {
					path: '/bettershield/v1/settings/uninstall',
					key: 'uninstall',
					data: { choice },
					then: ( data ) => {
						put( 'uninstall', { status: 'ready', data } );

						// Each answer records a way back on the undo list.
						if ( resources.settingsUndo.status !== 'idle' ) {
							load( 'settingsUndo', { force: true } );
						}
					},
				} ),

			saveSecurityTxt: ( next, onSaved, onRefused ) =>
				act( {
					path: '/bettershield/v1/settings/security-txt',
					key: 'securityTxt',
					data: next,
					then: settingsMoved( ( data ) => {
						put( 'securityTxt', { status: 'ready', data } );
						postureMoved();
						onSaved?.( data );
					} ),
					refused: onRefused,
				} ),

			/**
			 * The settings document, fetched fresh each time: it is what the
			 * site is set to now, not what it was when the screen opened.
			 */
			exportSettings: () => {
				setNotice( null );
				return apiFetch( { path: '/bettershield/v1/settings/export' } ).catch( ( error ) => {
					setNotice( error && error.message ? error.message : __( 'The export did not complete.', 'bettershield' ) );
					return null;
				} );
			},

			/**
			 * Plan an import (apply = false: nothing changes) or carry it out.
			 * Applying moves the score, the hardening list and every setting
			 * the document carries, and records a way back for each, so all of
			 * them are reloaded rather than trusted to be current. A surface
			 * left off this list goes on showing its old state on the very
			 * screen the import was made from.
			 */
			importSettings: ( document, apply, onDone, onRefused ) =>
				act( {
					path: '/bettershield/v1/settings/import',
					key: apply ? 'settings-import-apply' : 'settings-import-plan',
					data: { document, apply: !! apply },
					then: ( data ) => {
						if ( apply ) {
							[
								'overview',
								'findings',
								'hardening',
								'passwordPolicy',
								'loginProtection',
								'twoFactorPolicy',
								'passkeyPolicy',
								'securityTxt',
								'sudo',
								'abilities',
								'alerts',
								'uninstall',
								'agentSurface',
								'settingsUndo',
							].forEach(
								( name ) => load( name, { force: true } )
							);
						}

						onDone?.( data );
					},
					refused: onRefused,
				} ),

			/**
			 * Every alert control saves on the spot rather than behind a Save
			 * button: each is one switch whose effect is stated beside it, and a
			 * mute that needed a second click to take is a mute that failed.
			 * Muting also moves the Overview banner, so posture is refreshed.
			 */
			startMaintenance: ( minutes ) => act( { path: '/bettershield/v1/alerts/maintenance', key: 'maintenance', data: { minutes } } ),
			endMaintenance: () => act( { path: '/bettershield/v1/alerts/maintenance/end', key: 'maintenance' } ),
			// A window booked to open by itself later, and taken back (#107).
			bookMaintenance: ( starts, minutes ) => act( { path: '/bettershield/v1/alerts/maintenance/booking', key: 'maintenance', data: { starts, minutes } } ),
			cancelMaintenanceBooking: () => act( { path: '/bettershield/v1/alerts/maintenance/booking', key: 'maintenance', method: 'DELETE' } ),

			// The key names the control that saved, so "Saved." is said beside
			// that one and not beside every control on the screen.
			saveAlerts: ( changes, onSaved, onRefused, key = 'alerts' ) =>
				act( {
					path: '/bettershield/v1/settings/alerts',
					key,
					data: changes,
					then: settingsMoved( ( data ) => {
						put( 'alerts', { status: 'ready', data } );
						postureMoved();
						onSaved?.( data );
					} ),
					refused: onRefused,
				} ),

			// The screen says what became of the press beside the button, from
			// the outcome the route gives back.
			sendDigest: () =>
				act( {
					path: '/bettershield/v1/alerts/digest',
					key: 'digest',
					hold: SEND_HOLD,
					then: ( data ) => {
						if ( data && data.alerts ) {
							put( 'alerts', { status: 'ready', data: data.alerts } );
						}
					},
				} ),

			// One real message through the exact path live alerts take; the
			// screen reports the three-way answer the route gives back.
			sendAlertTest: () => act( { path: '/bettershield/v1/alerts/test', key: 'alert-test', hold: SEND_HOLD } ),

			saveTwoFactorPolicy: ( next, onSaved ) =>
				act( {
					path: '/bettershield/v1/two-factor/policy',
					key: 'two-factor-policy',
					data: next,
					then: settingsMoved( ( data ) => {
						load( 'twoFactorPolicy', { force: true } );
						onSaved?.( data );
					} ),
				} ),

			saveStoreTab: ( on ) =>
				act( {
					path: '/bettershield/v1/two-factor/policy',
					key: 'two-factor-store-tab',
					data: { store_tab: on },
					then: settingsMoved( () => load( 'twoFactorPolicy', { force: true } ) ),
				} ),

			// Where the sign-in page offers a passkey, not who must use one:
			// saved the moment it is pressed, as a switch is.
			savePasskeyAutofill: ( on ) =>
				act( {
					path: '/bettershield/v1/passkeys/policy',
					key: 'passkey-autofill',
					data: { autofill: on },
					then: settingsMoved( () => load( 'passkeyPolicy', { force: true } ) ),
				} ),

			saveAccountPage: ( page ) =>
				act( {
					path: '/bettershield/v1/two-factor/policy',
					key: 'two-factor-account-page',
					data: { account_page: page },
					then: settingsMoved( () => load( 'twoFactorPolicy', { force: true } ) ),
				} ),

			saveSudo: ( enabled ) =>
				act( {
					path: '/bettershield/v1/settings/sudo',
					key: 'sudo',
					data: { enabled },
					then: ( data ) => {
						if ( data ) {
							put( 'sudo', { status: 'ready', data } );
						}

						// The switch records a way back on the undo list.
						if ( resources.settingsUndo.status !== 'idle' ) {
							load( 'settingsUndo', { force: true } );
						}
					},
				} ),

			confirming,

			// The dialog's submit: prove the password, then re-run what the
			// gate held back. Rejections carry the route's own message —
			// wrong password, or the guessing cap — for the dialog to show.
			submitConfirmPassword: ( password ) =>
				apiFetch( { path: '/bettershield/v1/confirm-password', method: 'POST', data: { password } } ).then( () => {
					const held = heldAction.current;

					heldAction.current = null;
					setConfirming( false );

					if ( held ) {
						setRefocus( { to: held.origin } );
					}

					return held ? act( held ) : null;
				} ),

			cancelConfirmPassword: () => {
				const held = heldAction.current;

				heldAction.current = null;
				setConfirming( false );

				if ( held ) {
					setRefocus( { to: held.origin } );
				}

				// Nothing was changed, so the screen stops showing it as if it were.
				if ( held && held.refused ) {
					held.refused( null );
				}
			},

			preflight,

			// Run the recovery check, then the held change again. If the way
			// back is still not proved, the route refuses again and the dialog
			// comes back with the new reason.
			checkRecoveryAndRetry: () =>
				apiFetch( { path: '/bettershield/v1/recovery/readiness/check', method: 'POST' } ).then( () => {
					const held = heldPreflight.current;

					heldPreflight.current = null;
					setPreflight( null );

					return held ? act( held ) : null;
				} ),

			// The second confirmation: the same change, saying so.
			overridePreflight: () => {
				const held = heldPreflight.current;

				heldPreflight.current = null;
				setPreflight( null );

				return held ? act( { ...held, data: { ...( held.data || {} ), override_preflight: true } } ) : null;
			},

			cancelPreflight: () => {
				const held = heldPreflight.current;

				heldPreflight.current = null;
				setPreflight( null );

				// Nothing was changed, as when a password confirmation is canceled.
				if ( held && held.refused ) {
					held.refused( null );
				}
			},

			/**
			 * The open findings explained together; one ask, or a kept answer.
			 * The answer is handed to `then`, which the password gate re-runs
			 * with the action when it had to ask first.
			 */
			explainAudit: ( then ) => act( { path: '/bettershield/v1/ai/summary', key: 'explain-audit', then } ),

			/**
			 * Ask the model the owner connected to WordPress to explain one
			 * finding. Nothing is generated until they ask, and the answer may
			 * be one already written: the route keeps an explanation until that
			 * finding's evidence changes, and says which it handed back.
			 */
			explainFinding: ( finding, onExplained ) =>
				act( { path: `/bettershield/v1/ai/explain/${ finding }`, key: `explain-${ finding }`, then: onExplained } ),

			/**
			 * The precision signal. Bound to one delivered email, so reloading
			 * or following a second finding in that email cannot count it twice.
			 */
			markAlertUnhelpful: ( delivery ) =>
				act( { path: '/bettershield/v1/alerts/feedback', key: 'alert-feedback', data: { delivery } } ),

			savePasswordPolicy: ( policy, onSaved ) =>
				act( {
					path: '/bettershield/v1/settings/password-policy',
					key: 'password-policy',
					data: policy,
					then: settingsMoved( ( data ) => {
						// The defaults are kept from the read where an answer
						// does not carry them, so the hints beside the fields
						// do not go with a save.
						setResources( ( current ) => ( {
							...current,
							passwordPolicy: { status: 'ready', data: { defaults: current.passwordPolicy?.data?.defaults, ...data } },
						} ) );
						postureMoved();
						onSaved?.( data );
					} ),
				} ),

			/*
			 * The network screens' four writes.
			 *
			 * They live here rather than beside the screen for the same reason
			 * the file screen's do: each can be answered with "confirm your
			 * password", and only this layer knows how to turn that into a
			 * field somebody can type into. A screen fetching for itself
			 * prints the sentence as a failure and offers nothing to answer it
			 * with — and on a network these are the writes that most want the
			 * gate, because each of them decides something for every site.
			 *
			 * The read that follows each one is the caller's: the network
			 * cards hold their own data, so there is no shared resource here
			 * to write back into.
			 */
			refreshNetworkSites: ( then ) =>
				act( { then, path: '/bettershield/v1/network/sites/refresh', key: 'network-sites' } ),

			saveNetworkPolicy: ( section, policy, then ) =>
				act( {
					then,
					path: '/bettershield/v1/network/policies',
					key: `network-policies-${ section }`,
					// One section per save, so naming one leaves the other
					// exactly as it was rather than writing back a copy the
					// screen happened to be holding.
					data: { [ section ]: policy },
				} ),

			generateNetworkRecovery: ( then ) =>
				act( { then, path: '/bettershield/v1/network/recovery/link', key: 'network-recovery' } ),

			rotateNetworkKeys: ( then ) =>
				act( { then, path: '/bettershield/v1/network/recovery/rotate-keys', key: 'network-keys' } ),

			// The pause the network's link raised, ended on every site. A
			// site's own end does not reach it.
			endNetworkSafeMode: ( then ) =>
				act( { then, path: '/bettershield/v1/network/safe-mode/end', key: 'network-safe-mode' } ),

			revertNetworkChange: ( token, then ) =>
				act( { then, path: '/bettershield/v1/network/undo/revert', key: `network-undo-${ token }`, data: { token } } ),
		};
	}, [ resources, load, notice, saved, busy, act, put, putOverview, confirming, preflight, refreshMissing ] );

	/*
	 * After the screens' own effects, which run first: a screen that moved
	 * the keyboard somewhere after the change keeps it there, and so does a
	 * reader who has moved on.
	 */
	useEffect( () => {
		if ( ! refocus || confirming || null !== busy ) {
			return;
		}

		setRefocus( null );

		const { to } = refocus;
		const active = document.activeElement;

		if ( active && active !== document.body ) {
			return;
		}

		if ( to && to.isConnected && ! to.disabled ) {
			to.focus();
		}
	}, [ refocus, confirming, busy ] );

	return <StoreContext.Provider value={ value }>{ children }</StoreContext.Provider>;
}

export function useStore() {
	return useContext( StoreContext );
}

/**
 * Subscribe to one resource, fetching it on first use.
 */
export function useResource( name, { skip = false } = {} ) {
	const store = useStore();
	const resource = store.resources[ name ];

	// `skip` for a reader the route will refuse: asked anyway, the read
	// answered 403 on every visit and the screen could only call it a fault.
	useEffect( () => {
		if ( ! skip && resource.status === 'idle' ) {
			store.load( name );
		}
	}, [ name, resource.status, store, skip ] );

	return {
		resource,
		reload: () => store.load( name, { force: true } ),
	};
}

/**
 * Whether a control belongs to the action currently in flight.
 *
 * A named function rather than a comparison written out at each call site,
 * because the obvious spelling is wrong in a way that looks right: `busy` is
 * null while nothing is happening, and several of the keys passed here — a
 * finding's hardening item, for one — are null on most rows. `busy === key`
 * then matches null against null and reports every one of those rows as busy
 * forever. Excluding the idle case first is the whole job.
 */
export function isWorking( busy, ...keys ) {
	if ( null === busy || undefined === busy ) {
		return false;
	}

	return keys.some( ( key ) => key === busy );
}

/**
 * Absolute time, as a person would say it: "today, 4:43 PM", "Sep 30, 4:43 PM".
 * Relative times are avoided on purpose: "2 days ago" reads as reassurance
 * when it should read as staleness. It printed `toLocaleString()`, the
 * "9/30/2026, 4:43:13 PM" that ui/when.js exists to replace, on every screen
 * that still asked here.
 */
export function formatTime( iso ) {
	return whenPhrase( iso );
}

/**
 * A scheduled time that has already passed means the schedule was missed, not
 * that something is about to happen. Saying "next audit runs" over a past
 * timestamp is the kind of quietly wrong dashboard this product exists to not
 * be, so callers branch on this.
 */
export function isPast( iso ) {
	if ( ! iso ) {
		return false;
	}

	const then = new Date( iso ).getTime();

	return ! Number.isNaN( then ) && then < Date.now();
}

export function hoursSince( iso ) {
	if ( ! iso ) {
		return null;
	}

	const then = new Date( iso ).getTime();

	return Number.isNaN( then ) ? null : ( Date.now() - then ) / 36e5;
}

/**
 * Whether the action under this key finished a moment ago.
 *
 * For the controls that save on the flip rather than behind a Save button.
 * Those wrote silently: nothing visible confirmed it stuck, and the app's only
 * banner is for errors, so a screen reader was told nothing either way. The
 * confirmation clears itself, because a "Saved" that stays on screen stops
 * meaning "just now".
 *
 * @param {string} key     The action key passed to the store.
 * @param {number} seconds How long the confirmation stands.
 * @return {boolean} True while it should be shown.
 */
export function useSaved( key, seconds = 5 ) {
	const { saved } = useStore();
	const [ showing, setShowing ] = useState( false );

	useEffect( () => {
		if ( ! saved || saved.key !== key ) {
			/*
			 * Cleared rather than merely left alone. Every action mints a
			 * fresh `saved`, so this effect re-runs for every confirmation on
			 * the screen — and React runs the previous cleanup first, which
			 * cancels the reset this one was relying on. Returning here
			 * without clearing left "Saved." standing beside a control that
			 * had saved minutes earlier, which is the one thing it must not
			 * say.
			 */
			setShowing( false );

			return undefined;
		}

		setShowing( true );

		const timer = setTimeout( () => setShowing( false ), seconds * 1000 );

		return () => clearTimeout( timer );
	}, [ saved, key, seconds ] );

	return showing;
}
