/**
 * Fix for three findings that answer to one of BetterShield's own settings
 * (#2564): common usernames not refused, no proof of work at sign-in, and
 * pingbacks still open.
 *
 * Each press makes the change its screen would, through that screen's own
 * save, after saying what it changes:
 *
 * - Common usernames: refuses the names no account here uses, and says how
 *   many and how long one try of them pauses the connection. Undo puts the
 *   blocklist back through the settings record the save wrote.
 * - Proof of work: switched on while sign-in protection is on, saying that
 *   sign-in then needs JavaScript after wrong passwords. Undo turns it off.
 * - Pingbacks: the XML-RPC protection with pingbacks only, so the rest of
 *   XML-RPC keeps answering. Undo turns the protection off.
 *
 * The row stays, marked fixed, with its Undo, until the report is read
 * again. The Undo is kept here by finding, so closing and opening the row
 * keeps it; it also stays where the setting changes are undone.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../../nav';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';

/** The findings this panel answers. */
export const SIGN_IN_EXTRAS = [ 'common_usernames_allowed', 'proof_of_work_off', 'pingbacks_open' ];

/** Each fix's way back, by finding, while this page is open. */
const UNDOS = new Map();

/** Where each finding's setting is, for anybody who wants to look first. */
const PLACES = {
	common_usernames_allowed: { slug: 'bettershield-protect', tab: 'login', focus: 'blocklist', label: () => __( 'Open Login & Access', 'bettershield' ) },
	proof_of_work_off: { slug: 'bettershield-protect', tab: 'login', focus: 'proof_of_work', label: () => __( 'Open Login & Access', 'bettershield' ) },
	pingbacks_open: { slug: 'bettershield-protect', tab: 'hardening', focus: 'xmlrpc', label: () => __( 'Open Hardening', 'bettershield' ) },
};

/** The state each panel reads first, where it needs one. */
const STATES = {
	common_usernames_allowed: '/bettershield/v1/findings/common_usernames_allowed/names',
	proof_of_work_off: '/bettershield/v1/findings/proof_of_work_off/proof',
};

/**
 * @param {string} id The finding.
 * @return {string} The address of its setting, or ''.
 */
function placeUrl( id ) {
	const place = PLACES[ id ];
	const base = place ? tabUrl( place.slug, place.tab ) : '';

	return base ? `${ base }&focus=${ encodeURIComponent( place.focus ) }` : '';
}

export default function SignInExtras( { finding } ) {
	const store = useStore();
	const { blockCommonNames, turnOnProofOfWork, blockPingbacks, undoSettingsChange, revertItem, confirmRecoveryReceived, busy } = store;
	const id = finding.id;
	const [ state, setState ] = useState( STATES[ id ] ? null : {} );
	const [ unread, setUnread ] = useState( false );
	const [ undo, setUndo ] = useState( () => UNDOS.get( id ) || null );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const working = isWorking( busy, 'sign-in-extras' ) || isWorking( busy, 'xmlrpc' ) || Boolean( undo && undo.token && isWorking( busy, undo.token ) );

	useEffect( () => {
		if ( ! STATES[ id ] ) {
			return undefined;
		}

		let alive = true;

		apiFetch( { path: STATES[ id ] } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [ id ] );

	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const refused = ( error ) => {
		say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	const keep = ( way ) => {
		UNDOS.set( id, way );
		setUndo( way );
	};

	const forget = () => {
		UNDOS.delete( id );
		setUndo( null );
	};

	const place = placeUrl( id );
	// Before recovery is confirmed, the names fix waits on Recovery, so its
	// button opens Recovery rather than the blocklist (#2613).
	const waitsOnRecovery = 'common_usernames_allowed' === id && state && ! state.recovery_ready;
	const open = waitsOnRecovery ? (
		<Button type="secondary" size="sm" trailing="arrow-right" href={ tabUrl( 'bettershield-protect', 'recovery' ) }>
			{ __( 'Open Recovery', 'bettershield' ) }
		</Button>
	) : place ? (
		<Button type="secondary" size="sm" trailing="arrow-right" href={ place }>
			{ PLACES[ id ].label() }
		</Button>
	) : null;

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The setting could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the setting…', 'bettershield' ) }</p>;
	}

	const names = Array.isArray( state.names ) ? state.names : [];
	let text = '';
	let label = '';
	let consequence = '';
	let blocked = '';
	let apply = null;

	if ( 'common_usernames_allowed' === id ) {
		text = __( 'Sign-in tries with names nobody here uses are refused before any password is checked.', 'bettershield' );
		label = __( 'Refuse These Names', 'bettershield' );
		consequence = sprintf(
			/* translators: 1: how many usernames; 2: the usernames, e.g. "admin, root"; 3: minutes. */
			_n(
				'This name will be refused at sign-in: %2$s. No account here uses it. One try with it will pause that connection for %3$d minutes.',
				'These %1$d names will be refused at sign-in: %2$s. No account here uses them. One try with any of them will pause that connection for %3$d minutes.',
				names.length,
				'bettershield'
			),
			names.length,
			names.join( ', ' ),
			state.minutes
		);

		if ( ! names.length ) {
			blocked = __( 'Every common name is refused already, or an account here uses it.', 'bettershield' );
		} else if ( ! state.recovery_ready ) {
			blocked = __( 'Confirm your recovery options first: check that the recovery email arrived, or download the recovery codes. Typing one of these names by mistake locks you out briefly.', 'bettershield' );
		}

		apply = () =>
			blockCommonNames( ( answer ) => {
				if ( answer ) {
					keep( { token: answer.undo || '' } );
					say( 'success', sprintf(
						/* translators: %s: the usernames, e.g. "admin, root". */
						__( 'Refused at sign-in: %s.', 'bettershield' ),
						( answer.names || names ).join( ', ' )
					) );
				}
			}, refused );
	} else if ( 'proof_of_work_off' === id ) {
		text = __( 'After a few wrong passwords from one connection, the browser solves a small puzzle before the next try.', 'bettershield' );
		label = __( 'Turn On Sign-in Puzzle', 'bettershield' );
		consequence = finding.break_note || __( 'After a few wrong passwords, the next try needs JavaScript. A failed puzzle never locks anyone out.', 'bettershield' );

		if ( ! state.protection_on ) {
			blocked = __( 'Sign-in protection is off, and the sign-in puzzle needs it. Turn it on in Login & Access first.', 'bettershield' );
		}

		apply = () =>
			turnOnProofOfWork( ( answer ) => {
				if ( answer ) {
					keep( { token: answer.undo || '' } );
					say( 'success', __( 'Proof of work is on. Sign-in needs JavaScript after a few wrong passwords.', 'bettershield' ) );
				}
			}, refused );
	} else {
		text = __( 'Block only the pingbacks XML-RPC accepts. Apps and services that publish through XML-RPC keep working.', 'bettershield' );
		label = __( 'Block Pingbacks Only', 'bettershield' );
		consequence = finding.break_note || __( 'Other sites can no longer notify yours when they link to it. Everything else that uses XML-RPC keeps working.', 'bettershield' );

		apply = () =>
			blockPingbacks( ( answer ) => {
				if ( answer ) {
					keep( { item: answer.item || 'xmlrpc' } );
					say( 'success', __( 'Pingbacks are blocked. The rest of XML-RPC still answers.', 'bettershield' ) );
				}
			}, refused );
	}

	const back = () => {
		setSaid( null );

		if ( undo.item ) {
			revertItem(
				undo.item,
				( answer ) => {
					if ( answer ) {
						forget();
						say( 'success', __( 'Undone. Pingbacks are accepted again.', 'bettershield' ) );
					}
				},
				refused
			);

			return;
		}

		undoSettingsChange( undo.token, ( answer ) => {
			if ( answer ) {
				forget();
				say( 'success', __( 'Undone. The setting is back as it was.', 'bettershield' ) );
			}
		} );
	};

	const fixed = Boolean( undo );

	return (
		<>
			{ ! fixed ? (
				<>
					<p className="bs-ds-fix__text">{ text }</p>
					{ blocked ? <p className="bs-ds-fix__note">{ blocked }</p> : null }
					<div className="bs-ds-fix__actions">
						{ blocked ? null : (
							<Armed type="primary" label={ label } consequence={ consequence } confirm={ __( 'Yes, Apply It', 'bettershield' ) } busy={ working } disabled={ working } onConfirm={ apply } />
						) }
						{ /* Waiting only on the owner's word that the recovery
						     email arrived: said here too, so the fix can go
						     ahead without leaving the panel (#2629). */ }
						{ waitsOnRecovery && 'pending' === state.recovery_receipt ? (
							<Button
								type="primary"
								size="sm"
								isBusy={ isWorking( busy, 'recovery-received' ) }
								disabled={ isWorking( busy, 'recovery-received' ) }
								onClick={ () =>
									confirmRecoveryReceived( () =>
										apiFetch( { path: STATES[ id ] } ).then(
											( answer ) => setState( answer ),
											() => setUnread( true )
										)
									)
								}
							>
								{ __( 'Confirm the Email Arrived', 'bettershield' ) }
							</Button>
						) : null }
						{ open }
					</div>
				</>
			) : null }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
			{ /* A save with nothing to record has no way back here; the
			     setting's own screen still changes it. */ }
			{ fixed && ( undo.item || undo.token ) ? (
				<div className="bs-ds-fix__actions">
					<Armed
						label={ __( 'Undo', 'bettershield' ) }
						consequence={ __( 'The setting goes back to how it was before, and the finding opens again.', 'bettershield' ) }
						confirm={ __( 'Yes, Put It Back', 'bettershield' ) }
						busy={ working }
						disabled={ working }
						onConfirm={ back }
					/>
				</div>
			) : null }
		</>
	);
}

SignInExtras.kind = 'acts';
