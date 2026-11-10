/**
 * Passkeys, on the Two-factor tab beside the other way of proving it is you.
 *
 * A passkey is a key pair the device keeps. There is no shared secret on the
 * server to steal, nothing to type, and the browser will only sign for the
 * domain the key was made for, which is what makes it the one credential that
 * cannot be phished.
 *
 * The site explains the account’s actual policy: adding a passkey can arm
 * passkey-only sign-in for a required role. The same explanation appears on
 * the profile screen, where other roles manage their own passkeys.
 *
 * One card: its state in the header, one sentence, the questions it raises,
 * the passkeys as rows of a table, and naming a new device with the card's
 * one primary action.
 */

import './Passkeys.css';

import apiFetch from '@wordpress/api-fetch';
import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useStore } from '../../store';
import { PROMPT_HINT_AFTER_MS, PROMPT_TIMEOUT_MS, promptClosedWords, promptHint, promptStoppedWords, promptWait } from '../../ui/passkey-prompt';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Field, { FieldRow } from '../ui/Field';
import { focusIfLost, useFocusAfter } from '../ui/focus';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import Table, { Cell, Row, TitleMeta } from '../ui/Table';
import Topics from '../ui/Topics';

/** Base64url is what WebAuthn speaks; ArrayBuffers are what it hands back. */
function fromBase64Url( value ) {
	const raw = window.atob( value.replace( /-/g, '+' ).replace( /_/g, '/' ) );
	const bytes = new Uint8Array( raw.length );

	for ( let i = 0; i < raw.length; i++ ) {
		bytes[ i ] = raw.charCodeAt( i );
	}

	return bytes;
}

/**
 * What the browser's refusal means in words. WebAuthn errors carry a name
 * and a message written for developers; the name is the reliable part.
 */
function describe( error ) {
	if ( ! error ) {
		return __( 'Your device did not complete the setup. Nothing was changed.', 'bettershield' );
	}

	const closed = promptClosedWords( error.name );

	if ( closed ) {
		return closed;
	}

	switch ( error.name ) {
		case 'InvalidStateError':
			return __( 'This device already holds a passkey for this account.', 'bettershield' );
		case 'SecurityError':
			return __( 'Your browser blocked this. Passkeys need a secure https:// address with a valid certificate. Nothing was changed.', 'bettershield' );
		case 'NotSupportedError':
			return __( 'This device can’t create this type of passkey. Try another device or a password manager.', 'bettershield' );
		default:
			return error.message || __( 'Your device did not complete the setup. Nothing was changed.', 'bettershield' );
	}
}

/**
 * Whether the browser says the new key can sign in without a username, from
 * the `credProps` extension: '1' or '0', or undefined where it said nothing
 * (older browsers), which the server records as unknown. The sign-in form has
 * no username step, so the server refuses a key reported as '0' (#2469).
 */
function discoverableOf( credential ) {
	const results = credential && 'function' === typeof credential.getClientExtensionResults ? credential.getClientExtensionResults() : null;
	const rk = results && results.credProps ? results.credProps.rk : undefined;

	if ( 'boolean' !== typeof rk ) {
		return undefined;
	}

	return rk ? '1' : '0';
}

function toBase64Url( buffer ) {
	const bytes = new Uint8Array( buffer );
	let binary = '';

	for ( let i = 0; i < bytes.length; i++ ) {
		binary += String.fromCharCode( bytes[ i ] );
	}

	return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
}

/**
 * Prove, with one of this account's own passkeys, that the person at this
 * session holds it: what an account gives before its passkeys change when it
 * has no password the site accepts and no second factor.
 */
function confirmWithPasskey() {
	return apiFetch( { path: '/bettershield/v1/passkeys/confirm-options', method: 'POST' } ).then( ( options ) =>
		navigator.credentials
			.get( {
				publicKey: {
					challenge: fromBase64Url( options.challenge ),
					rpId: options.rpId,
					// This account's own and no other: the proof is that its
					// holder is here, not that somebody with a passkey is.
					allowCredentials: ( options.allow || [] ).map( ( id ) => ( { type: 'public-key', id: fromBase64Url( id ) } ) ),
					// It stands in for a password, so the person is asked for
					// and not only a touch.
					userVerification: 'required',
					timeout: 120000,
				},
			} )
			.then( ( credential ) =>
				apiFetch( {
					path: '/bettershield/v1/passkeys/confirm',
					method: 'POST',
					data: {
						handle: options.handle,
						id: credential.id,
						clientDataJSON: toBase64Url( credential.response.clientDataJSON ),
						authenticatorData: toBase64Url( credential.response.authenticatorData ),
						signature: toBase64Url( credential.response.signature ),
					},
				} )
			)
	);
}

/**
 * What to say when a proof was not accepted. The server's refusals carry a
 * sentence for the person; a device that did not answer carries a message
 * written for developers, so it is said in words instead.
 *
 * @param {Object} error The refusal.
 * @param {Object} held  The proof that was asked for.
 * @return {string} What to say.
 */
function refusalOf( error, held ) {
	if ( error && typeof error.code === 'string' && error.message ) {
		return error.message;
	}

	if ( 'passkey' === held.kind ) {
		return __( 'Your device did not confirm it is you. Nothing was changed.', 'bettershield' );
	}

	return error && error.message ? error.message : held.message;
}

/**
 * The card before its list has landed. It sits beside the two-factor card, so
 * it holds a card's height from the start: arriving a beat later as a whole
 * card, it made the pair jump.
 */
function PasskeysBone() {
	return (
		<Skeleton label={ __( 'Loading your passkeys…', 'bettershield' ) }>
			<CardBone rows={ [ '90%', '55%' ] } />
		</Skeleton>
	);
}

/**
 * @param {Object}   props
 * @param {Function} props.onChanged Called once a passkey has been added or
 *                                   removed, for whatever describes the same
 *                                   accounts elsewhere on the screen.
 * @param {string}   props.policy    The saved passkey-only roles; the card is
 *                                   read again when they change.
 */
/**
 * For whoever manages the site: another plugin also handles two-factor, and
 * how many accounts it covers, which a passkey cannot sign in because that
 * plugin asks for its own code after it (#2465). The way out is one plugin
 * for two-factor, chosen in the Quick Setup's Coexistence step.
 *
 * @param {Object} props
 * @param {Object} props.shared The other plugin's name and how many accounts it covers.
 */
function SharedTwoFactor( { shared } ) {
	const { reopenSetup, busy } = useStore();

	return (
		<Alert
			layout="default"
			tone="warning"
			desc={ sprintf(
				/* translators: 1: another security plugin's name, 2: how many accounts it has two-factor set up for. */
				_n(
					'Two plugins handle two-factor here: BetterShield and %1$s. %2$d account has two-factor set up there, so a passkey cannot sign it in and is not offered to it.',
					'Two plugins handle two-factor here: BetterShield and %1$s. %2$d accounts have two-factor set up there, so a passkey cannot sign them in and is not offered to them.',
					shared.count,
					'bettershield'
				),
				shared.name,
				shared.count
			) }
			actions={
				<Button type="secondary" size="sm" isBusy={ isWorking( busy, 'setup-reopen' ) } onClick={ () => reopenSetup( 'coexistence' ) }>
					{ __( 'Choose in Quick Setup', 'bettershield' ) }
				</Button>
			}
		/>
	);
}

export default function Passkeys( { onChanged, policy = '' } ) {
	const [ state, setState ] = useState( null );
	const [ status, setStatus ] = useState( 'loading' );
	const [ busy, setBusy ] = useState( null );
	const [ notice, setNotice ] = useState( null );
	// Stop Waiting pressed: said on its own, because it isn't a problem.
	const [ stopped, setStopped ] = useState( false );
	const [ label, setLabel ] = useState( '' );
	// The name as the field holds it now. A retry after the password or code
	// is the closure from the press that asked for it, and read from its
	// render it sent the name as it was then: one typed while the question
	// was open was dropped, and then cleared.
	const labelNow = useRef( '' );
	labelNow.current = label;
	const [ hint, setHint ] = useState( false );
	// The prompt this screen has open: what Stop Waiting and leaving close.
	const wait = useRef( null );
	const [ proof, setProof ] = useState( null );
	const [ proofValue, setProofValue ] = useState( '' );
	const mounted = useRef( true );

	/*
	 * Add a passkey is held while the device is asked and while a proof is
	 * asked for, and a browser drops focus off a held control to the page
	 * (#1926). The proof's first control takes it when the proof opens, and
	 * Add a passkey once it lets go.
	 */
	const proofBox = useRef( null );
	const add = useRef( null );
	const proving = Boolean( proof );

	useFocusAfter( 'enroll' === busy || proving, add );

	// Stop Waiting goes away with the wait it ends, so focus would fall to the
	// page; Add a passkey takes it back once it can be pressed again.
	const [ refocusAdd, setRefocusAdd ] = useState( false );

	useEffect( () => {
		if ( refocusAdd && null === busy && add.current ) {
			add.current.focus();
			setRefocusAdd( false );
		}
	}, [ refocusAdd, busy ] );

	useEffect( () => {
		if ( proving && proofBox.current ) {
			focusIfLost( proofBox.current.querySelector( 'input, button' ) );
		}
	}, [ proving ] );

	/*
	 * Adding or removing a passkey asks the holder to prove it is them: a
	 * current code where two-factor is on, the password again where the site
	 * accepts one, and one of the account's own passkeys otherwise.
	 * The request is held here and sent again, with the proof, once it is
	 * given.
	 */
	const askedForProof = ( error, retry ) => {
		const code = error && error.code;

		if ( 'bettershield_current_code_required' === code || 'bettershield_wrong_code' === code ) {
			setProof( { kind: 'code', message: error.message, retry } );
		} else if ( 'bettershield_confirm_password' === code ) {
			setProof( { kind: 'password', message: error.message, retry } );
		} else if ( 'bettershield_confirm_passkey' === code ) {
			setProof( { kind: 'passkey', message: error.message, retry } );
		} else {
			return false;
		}

		setProofValue( '' );

		return true;
	};

	/*
	 * Where focus goes once the control that had it is gone. Removing a
	 * passkey takes its row out of the list, and adding one clears the name
	 * field and so disables the button beside it; either way the browser
	 * drops focus to the top of the document, and a screen reader hears
	 * nothing about what just happened. The next row, or the row that just
	 * appeared, is the evidence; the name field and then the card itself are
	 * the fallbacks when there is none.
	 *
	 * Wanted rather than done at once, because the node to move to does not
	 * exist until the card has drawn the new list.
	 */
	const rowRefs = useRef( new Map() );
	const addRef = useRef( null );
	const cardRef = useRef( null );
	const [ focusWanted, setFocusWanted ] = useState( null );

	const keepRow = ( id ) => ( node ) => {
		if ( node ) {
			rowRefs.current.set( id, node );
		} else {
			rowRefs.current.delete( id );
		}
	};

	useEffect( () => {
		if ( ! focusWanted || ! state ) {
			return;
		}

		const ids = state.passkeys.map( ( passkey ) => passkey.id );
		let node = null;

		if ( focusWanted.gone ) {
			node = ids.includes( focusWanted.gone ) ? rowRefs.current.get( focusWanted.gone ) : rowRefs.current.get( focusWanted.neighbor );
		} else {
			const fresh = ids.find( ( id ) => ! focusWanted.before.includes( id ) );

			node = fresh ? rowRefs.current.get( fresh ) : null;
		}

		node = node || ( addRef.current && addRef.current.querySelector( 'input' ) ) || cardRef.current;

		if ( node ) {
			node.focus();
		}

		setFocusWanted( null );
	}, [ focusWanted, state ] );

	const changed = () => {
		if ( onChanged ) {
			onChanged();
		}
	};

	useEffect( () => {
		mounted.current = true;

		return () => {
			mounted.current = false;

			// A prompt left open behind another window would outlast the screen.
			if ( wait.current ) {
				wait.current.stop();
			}
		};
	}, [] );

	const load = useCallback( () => {
		apiFetch( { path: '/bettershield/v1/passkeys' } )
			.then( ( data ) => {
				if ( mounted.current ) {
					setState( data );
					setStatus( 'ready' );
				}
			} )
			.catch( () => mounted.current && setStatus( 'error' ) );
	}, [] );

	useEffect( load, [ load ] );

	// The passkey-only roles were saved elsewhere on the screen: the hint
	// above the button depends on them, so it is read again (#2485).
	const policyRead = useRef( policy );

	useEffect( () => {
		if ( policyRead.current !== policy ) {
			policyRead.current = policy;
			load();
		}
	}, [ policy, load ] );

	/*
	 * The passkey policy's notice links here as #bettershield-passkeys, the
	 * profile panel's anchor, which this screen did not have: the link
	 * landed at the top with focus on the page (#2125). Once the card is
	 * drawn, arriving with it brings the card into view and focus to it.
	 */
	const arrived = useRef( false );

	useEffect( () => {
		if ( 'ready' !== status || arrived.current || '#bettershield-passkeys' !== window.location.hash || ! cardRef.current ) {
			return;
		}

		arrived.current = true;

		if ( 'function' === typeof cardRef.current.scrollIntoView ) {
			cardRef.current.scrollIntoView( { block: 'start' } );
		}

		cardRef.current.focus( { preventScroll: true } );
	}, [ status ] );

	// A prompt that never appears looks exactly like one that is taking a
	// while. After a bit, say so: the browser may still answer, but the
	// person should know what they are waiting for.
	useEffect( () => {
		if ( busy !== 'enroll' ) {
			setHint( false );
			return undefined;
		}

		const timer = window.setTimeout( () => mounted.current && setHint( true ), PROMPT_HINT_AFTER_MS );

		return () => window.clearTimeout( timer );
	}, [ busy ] );

	const enroll = ( proved = {} ) => {
		const before = state.passkeys.map( ( passkey ) => passkey.id );
		// The name this enrollment sends, set when the request is built.
		let sent = '';
		const asked = promptWait();

		wait.current = asked;

		setBusy( 'enroll' );
		setNotice( null );
		setStopped( false );

		apiFetch( { path: '/bettershield/v1/passkeys/register-options', method: 'POST', data: proved } )
			.then( ( options ) =>
				navigator.credentials
					.create( {
						publicKey: {
							challenge: fromBase64Url( options.challenge ),
							rp: { id: options.rp.id, name: options.rp.name },
							user: {
								id: fromBase64Url( options.user.id ),
								name: options.user.name,
								displayName: options.user.displayName,
							},
							pubKeyCredParams: options.algorithms.map( ( alg ) => ( { type: 'public-key', alg } ) ),
							// The server decides how hard to ask. Preferred almost
							// always: a touch-only key is a fine second factor
							// for an account that also has a code. Required only
							// where this key would become the sole way in for an
							// account whose password is refused, because there a
							// key that cannot verify its holder is a lockout
							// waiting for the next sign-in.
							// The resident key is always required: the sign-in form asks
							// for any key this site holds, with no username first, so a key
							// that keeps nothing on the device is never offered (#2469).
							authenticatorSelection: {
								residentKey: 'required',
								requireResidentKey: true,
								userVerification: options.verification || 'preferred',
							},
							// So a device already enrolled on this account
							// declines quietly rather than failing at the server.
							excludeCredentials: ( options.registered || [] ).map( ( id ) => ( {
								type: 'public-key',
								id: fromBase64Url( id ),
							} ) ),
							timeout: PROMPT_TIMEOUT_MS,
							attestation: 'none',
							// Asks the browser to say whether it stored the key, so one
							// that cannot sign in is refused rather than saved.
							extensions: { credProps: true },
						},
						signal: asked.signal,
					} )
					.then( ( credential ) => {
						sent = labelNow.current;

						return apiFetch( {
							path: '/bettershield/v1/passkeys/register',
							method: 'POST',
							data: {
								handle: options.handle,
								clientDataJSON: toBase64Url( credential.response.clientDataJSON ),
								attestationObject: toBase64Url( credential.response.attestationObject ),
								transports: ( credential.response.getTransports ? credential.response.getTransports() : [] ).join( ',' ),
								label: sent.trim(),
								discoverable: discoverableOf( credential ),
							},
						} );
					} )
			)
			.then( ( data ) => {
				if ( mounted.current ) {
					setState( data );
					// Cleared for the next one, unless it was changed again
					// after it was sent.
					setLabel( ( now ) => ( now === sent ? '' : now ) );
					setFocusWanted( { before } );
					changed();
				}
			} )
			.catch( ( error ) => {
				if ( mounted.current && asked.stopped() ) {
					setStopped( true );
				} else if ( mounted.current && ! askedForProof( error, enroll ) ) {
					// The server's refusals arrive with a string code and a
					// sentence written for the person; the browser's are
					// DOMExceptions, whose legacy numeric code says nothing.
					setNotice( error && typeof error.code === 'string' && error.message ? error.message : describe( error ) );
				}
			} )
			.finally( () => {
				asked.done();
				wait.current = null;

				if ( mounted.current ) {
					setBusy( null );
				}
			} );
	};

	const remove = ( id, proved = {} ) => {
		// The row after this one, or before it when it is last: decided now,
		// while the list still says where this one stands.
		const ids = state.passkeys.map( ( passkey ) => passkey.id );
		const at = ids.indexOf( id );
		const neighbor = ids[ at + 1 ] || ids[ at - 1 ] || null;

		setBusy( `remove-${ id }` );
		setNotice( null );

		apiFetch( { path: `/bettershield/v1/passkeys/${ id }`, method: 'DELETE', data: proved } )
			.then( ( data ) => {
				if ( mounted.current ) {
					setState( data );
					setFocusWanted( { gone: id, neighbor } );
					changed();
				}
			} )
			.catch( ( error ) => {
				if ( mounted.current && ! askedForProof( error, ( more ) => remove( id, more ) ) ) {
					setNotice( error && typeof error.code === 'string' && error.message ? error.message : __( 'That passkey could not be removed.', 'bettershield' ) );
				}
			} )
			.finally( () => mounted.current && setBusy( null ) );
	};

	/*
	 * With two-factor on, every change asks for a current code. Asked with
	 * the press, so the first request carries it: asked after a refusal, a
	 * removal took Remove, Yes, an error, then the code (#2147).
	 */
	const withCode = ( retry, ask ) => {
		if ( ! state.needs_code ) {
			retry( {} );

			return;
		}

		setNotice( null );
		setProofValue( '' );
		setProof( { kind: 'code', message: ask, retry } );
	};

	const submitProof = () => {
		const held = proof;
		const value = proofValue.trim();

		if ( ! held || ( 'passkey' !== held.kind && '' === value ) ) {
			return;
		}

		setProof( null );
		setProofValue( '' );

		if ( 'code' === held.kind ) {
			held.retry( { code: value } );

			return;
		}

		setBusy( 'proof' );

		const asked =
			'passkey' === held.kind
				? confirmWithPasskey()
				: apiFetch( { path: '/bettershield/v1/confirm-password', method: 'POST', data: { password: value } } );

		asked
			.then( () => {
				if ( mounted.current ) {
					setBusy( null );
					held.retry( {} );
				}
			} )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setBusy( null );
					setProof( { ...held, message: refusalOf( error, held ) } );
				}
			} );
	};

	/*
	 * A load that failed is said out loud. Drawing nothing would read, on this
	 * card, the same as "this site does not offer passkeys": the reader would
	 * be told a feature is absent when in fact one request did not answer.
	 */
	if ( status === 'error' ) {
		return <ErrorState onRetry={ load } />;
	}

	if ( status === 'loading' || ! state ) {
		return <PasskeysBone />;
	}

	const secure = window.isSecureContext !== false;
	const supported = secure && typeof window.PublicKeyCredential !== 'undefined' && !! navigator.credentials?.create;
	// Whether this account can sign in with one, which is the card's state:
	// a passkey held on a site where passkeys are off signs nobody in.
	const held = state.available && state.passkeys.some( ( passkey ) => passkey.usable !== false );

	return (
		<Card className="bs-ds-2fa__method bs-ds-passkeys" aria-labelledby="bs-ds-passkeys-title">
			<CardHead
				icon="fingerprint"
				id="bs-ds-passkeys-title"
				title={
					<span ref={ cardRef } id="bettershield-passkeys" tabIndex={ -1 } className="bs-ds-passkeys__title">
						{ __( 'Passkeys', 'bettershield' ) }
					</span>
				}
			>
				<Badge tone={ held ? 'brand' : 'neutral' }>{ held ? __( 'Ready', 'bettershield' ) : ! state.available ? state.label || __( 'Unavailable', 'bettershield' ) : __( 'Not set up', 'bettershield' ) }</Badge>
			</CardHead>

			<div className="bs-ds-2fa__body">
				{ /* Explain this account's policy before enrollment can change
				     which sign-in methods the site accepts. */ }
				<p className="bs-ds-2fa__lead">
					{ state.intro || __( 'Sign in with a passkey: your fingerprint, face or device PIN.', 'bettershield' ) }
				</p>

				<Topics
					items={ [
						{
							key: 'what',
							label: __( 'What a passkey is', 'bettershield' ),
							lead: __( 'A sign-in you unlock with your fingerprint, face or device PIN, instead of a password.', 'bettershield' ),
							points: [
								__( 'Your phone, computer or password manager keeps the passkey.', 'bettershield' ),
								__( 'This site only keeps a matching record that can’t be used to sign in.', 'bettershield' ),
								__( 'There is nothing to type.', 'bettershield' ),
							],
						},
						{
							key: 'phishing',
							label: __( 'Protection from fake sites', 'bettershield' ),
							lead: __( 'Your browser offers a passkey only to this exact address.', 'bettershield' ),
							text: __( 'A fake copy of this site cannot get it from you, unlike a password.', 'bettershield' ),
						},
					] }
				/>

				{ ! state.available ? <Alert layout="default" tone="info" desc={ state.reason } /> : null }

				{ state.shared ? <SharedTwoFactor shared={ state.shared } /> : null }

				{ state.available && ! supported ? (
					<Alert
						layout="default"
						tone="info"
						desc={ ! secure ? __( 'Open this page at its https:// address to add a passkey.', 'bettershield' ) : __( 'This browser does not support passkeys. Try a current Chrome, Safari, Edge or Firefox.', 'bettershield' ) }
					/>
				) : null }

				{ /* These two flows do not go through the shared data layer, so
				     nothing announces them above the screen: this is the only
				     place a dismissed prompt or a refused removal is ever said. */ }
				{ notice ? (
					<div role="alert">
						<Alert layout="default" tone="warning" desc={ notice } />
					</div>
				) : null }

				{ stopped ? (
					<div role="status">
						<Alert layout="default" tone="info" desc={ promptStoppedWords() } />
					</div>
				) : null }

				{ proof ? (
					<div className="bs-ds-passkeys__proof" ref={ proofBox }>
						<p className="bs-ds-2fa__note" role="alert">
							{ proof.message }
						</p>
						{ 'passkey' === proof.kind ? (
							<span className="bs-ds-2fa__actions">
								{ /* The device is asked on a press of this button rather
								     than at once: a browser asks for a passkey only in
								     answer to something the person did. */ }
								<Button type="primary" size="sm" isBusy={ busy === 'proof' } disabled={ busy === 'proof' } onClick={ submitProof }>
									{ __( 'Use a Passkey', 'bettershield' ) }
								</Button>
								<Button type="ghost" size="sm" onClick={ () => setProof( null ) }>
									{ __( 'Cancel', 'bettershield' ) }
								</Button>
							</span>
						) : (
							<FieldRow>
								<Field
									width="md"
									label={ 'code' === proof.kind ? __( 'Authenticator app code or backup code', 'bettershield' ) : __( 'Your password', 'bettershield' ) }
									type={ 'code' === proof.kind ? 'text' : 'password' }
									autoComplete={ 'code' === proof.kind ? 'one-time-code' : 'current-password' }
									value={ proofValue }
									onChange={ setProofValue }
									onKeyDown={ ( event ) => {
										if ( 'Enter' === event.key ) {
											event.preventDefault();
											submitProof();
										}
									} }
								/>
								<span className="bs-ds-2fa__actions">
									<Button type="primary" size="sm" isBusy={ busy === 'proof' } disabled={ busy === 'proof' || '' === proofValue.trim() } onClick={ submitProof }>
										{ __( 'Confirm', 'bettershield' ) }
									</Button>
									<Button type="ghost" size="sm" onClick={ () => setProof( null ) }>
										{ __( 'Cancel', 'bettershield' ) }
									</Button>
								</span>
							</FieldRow>
						) }
					</div>
				) : null }
			</div>

			{ state.passkeys.length ? (
				<Table
					className="bs-ds-passkeys__list"
					label={ __( 'Passkeys', 'bettershield' ) }
					head={ false }
					columns={ [
						{ key: 'passkey', label: __( 'Passkey', 'bettershield' ) },
						// Capped, so the confirmation that opens here wraps
						// rather than squeezing the name to a few letters.
						{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'fit-content(50%)', align: 'end' },
					] }
				>
					{ state.passkeys.map( ( passkey ) => (
						<Row key={ passkey.id } className="bs-ds-passkeys__row">
							<Cell>
								<TitleMeta
									title={
										<span className="bs-ds-passkeys__name" ref={ keepRow( passkey.id ) } tabIndex={ -1 }>
											{ passkey.label }
										</span>
									}
									meta={
										passkey.last_used_at
											? sprintf(
													/* translators: %s: date and time. */
													__( 'last used %s', 'bettershield' ),
													formatTime( passkey.last_used_at )
											  )
											: __( 'never used', 'bettershield' )
									}
								/>
							</Cell>
							<Cell align="end">
								{ /* Armed, like every other control here that takes a
								     way in away. One click removed a credential
								     somebody may be relying on to sign in, with
								     nothing said in between. */ }
								<Armed
									type="ghost"
									label={ __( 'Remove', 'bettershield' ) }
									// Named by its row: with several passkeys every
									// button read "Remove" (#2148).
									aria-label={ sprintf(
										/* translators: %s: a passkey's name. */
										__( 'Remove %s', 'bettershield' ),
										passkey.label
									) }
									consequence={ __(
										'This passkey stops working and your other devices are signed out. If your site requires passkeys for your role, keep at least one.',
										'bettershield'
									) }
									busy={ busy === `remove-${ passkey.id }` }
									disabled={ null !== proof || busy === 'proof' }
									onConfirm={ () => withCode( ( proved ) => remove( passkey.id, proved ), __( 'To remove a passkey, confirm it’s you.', 'bettershield' ) ) }
								/>
							</Cell>
						</Row>
					) ) }
				</Table>
			) : null }

			{ /* Not offered to an account another plugin covers: its own code
			     would still be asked after the passkey (#2465). The lead
			     above says why. */ }
			{ state.available && supported && ! state.elsewhere && state.passkeys.length < state.max ? (
				<div className="bs-ds-passkeys__add" ref={ addRef }>
					<p className="bs-ds-2fa__note">{ __( 'Next, your browser asks where to save the passkey: this device, your phone or a password manager.', 'bettershield' ) }</p>
					<FieldRow>
						<Field
							width="md"
							label={ __( 'Passkey name (optional)', 'bettershield' ) }
							placeholder={ __( 'Work laptop', 'bettershield' ) }
							// What the server keeps; a longer name was cut there
							// without a word.
							maxLength={ 191 }
							value={ label }
							onChange={ setLabel }
						/>
						{ /* The card's one primary action, handed to Confirm while
						     a proof is asked for. */ }
						<Button
							ref={ add }
							type={ proof ? 'secondary' : 'primary' }
							// The field's height beside it (#2574).
							size="md"
							isBusy={ busy === 'enroll' }
							// Held while a proof is asked for and while it is
							// checked: a second press beside the retry started
							// a second enrollment.
							disabled={ busy === 'enroll' || busy === 'proof' || null !== proof }
							onClick={ () => withCode( enroll, __( 'To add a passkey, confirm it’s you.', 'bettershield' ) ) }
						>
							{ busy === 'enroll' ? __( 'Waiting for Your Device…', 'bettershield' ) : __( 'Add a Passkey', 'bettershield' ) }
						</Button>
						{ hint ? (
							<Button type="secondary" size="md" onClick={ () => {
								if ( wait.current ) {
									setRefocusAdd( true );
									wait.current.stop();
								}
							} }>
								{ __( 'Stop Waiting', 'bettershield' ) }
							</Button>
						) : null }
					</FieldRow>
					{ hint ? (
						<p className="bs-ds-2fa__note" role="status">
							{ promptHint() }
						</p>
					) : null }
				</div>
			) : null }
		</Card>
	);
}
