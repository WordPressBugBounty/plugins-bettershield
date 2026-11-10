/**
 * Fix for "An admin-level account has gone unused for a long time" (#2430).
 *
 * Each account the finding names, ticked, and Suspend: the account keeps its
 * role, content and passwords and cannot sign in until it is let back in.
 * Each suspended account has its own Let back in here, and on the list of
 * suspensions under Activity once the finding has closed. An account that
 * must stay able to sign in says why instead of offering a box.
 */

import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';
import Field from '../../ui/Field';
import useFixState, { useSaid } from './useFixState';

/**
 * One account's line.
 *
 * @param {Object} row The account.
 * @return {string} The line.
 */
function named( row ) {
	return sprintf(
		/* translators: 1: a username; 2: a number of days. */
		_n( '%1$s, unused for %2$d day', '%1$s, unused for %2$d days', row.days, 'bettershield' ),
		row.login,
		row.days
	);
}

export default function DormantSuspend() {
	const { suspendDormant, letBackIn, busy } = useStore();
	const { state, setState, unread } = useFixState( '/bettershield/v1/findings/privileged_account_dormant/accounts' );
	const [ picked, setPicked ] = useState( null );
	// What was suspended from here, each with its way back, and what was refused.
	const [ suspended, setSuspended ] = useState( [] );
	const [ refused, setRefused ] = useState( [] );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'dormant-accounts' );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The accounts could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the accounts…', 'bettershield' ) }</p>;
	}

	const open = state.accounts.filter( ( row ) => '' === row.refused );
	const chosen = picked || open.map( ( row ) => row.id );
	const toggle = ( id, on ) => setPicked( on ? [ ...chosen, id ] : chosen.filter( ( other ) => other !== id ) );

	const suspend = () => {
		announce( __( 'Suspending the chosen accounts…', 'bettershield' ) );
		suspendDormant( chosen, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setSuspended( ( was ) => [ ...was, ...answer.suspended ] );
			setRefused( answer.refused );
			setPicked( null );
			setState( answer.state );
			say(
				sprintf(
					/* translators: %d: how many accounts were suspended. */
					_n( '%d account is suspended. It cannot sign in until you let it back in.', '%d accounts are suspended. They cannot sign in until you let them back in.', answer.suspended.length, 'bettershield' ),
					answer.suspended.length
				)
			);
		} );
	};

	const lift = ( row ) => {
		announce(
			sprintf(
				/* translators: %s: a username. */
				__( 'Letting %s back in…', 'bettershield' ),
				row.login
			)
		);
		letBackIn( row.undo, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setSuspended( ( was ) => was.filter( ( other ) => other.undo !== row.undo ) );
			say(
				sprintf(
					/* translators: %s: a username. */
					__( '%s can sign in again.', 'bettershield' ),
					row.login
				)
			);
		} );
	};

	return (
		<>
			{ state.accounts.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Untick anyone who is only away. A suspended account keeps its role, content and passwords, and cannot sign in until you let it back in.', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.accounts.map( ( row ) => (
							<li key={ row.id }>
								{ '' === row.refused ? (
									<Field kind="check" label={ named( row ) } checked={ chosen.includes( row.id ) } disabled={ working } onChange={ ( on ) => toggle( row.id, on ) } />
								) : (
									<p className="bs-ds-fix__note">
										{ sprintf(
											/* translators: 1: an account; 2: why it is left alone. */
											__( '%1$s. %2$s', 'bettershield' ),
											named( row ),
											row.refused
										) }
									</p>
								) }
							</li>
						) ) }
					</ul>
					{ open.length ? (
						<div className="bs-ds-fix__actions">
							<Armed
								type="primary"
								label={ sprintf(
									/* translators: %d: how many accounts are ticked. */
									_n( 'Suspend %d Account', 'Suspend %d Accounts', chosen.length, 'bettershield' ),
									chosen.length
								) }
								consequence={ __( 'They cannot sign in, by password, passkey or application password, until you let them back in. Nothing is deleted.', 'bettershield' ) }
								confirm={ __( 'Yes, Suspend', 'bettershield' ) }
								busy={ working }
								disabled={ ! chosen.length }
								onConfirm={ suspend }
							/>
						</div>
					) : null }
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No admin-level account is unused now.', 'bettershield' ) }</p>
			) }
			{ suspended.length ? (
				<ul className="bs-ds-fix__list" aria-label={ __( 'Suspended', 'bettershield' ) }>
					{ suspended.map( ( row ) => (
						<li key={ row.undo } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ sprintf(
									/* translators: %s: a username. */
									__( '%s is suspended', 'bettershield' ),
									row.login
								) }
							</span>
							<Button
								type="secondary"
								size="sm"
								disabled={ working }
								aria-label={ sprintf(
									/* translators: %s: a username. */
									__( 'Let %s back in', 'bettershield' ),
									row.login
								) }
								onClick={ () => lift( row ) }
							>
								{ __( 'Let Back In', 'bettershield' ) }
							</Button>
						</li>
					) ) }
				</ul>
			) : null }
			{ refused.length ? (
				<ul className="bs-ds-fix__list">
					{ refused.map( ( row ) => (
						<li key={ row.id } className="bs-ds-fix__note">
							{ sprintf(
								/* translators: 1: a username; 2: why it was not suspended. */
								__( '%1$s was not suspended. %2$s', 'bettershield' ),
								row.login,
								row.reason
							) }
						</li>
					) ) }
				</ul>
			) : null }
			{ said ? (
				<>
					<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
						{ said }
					</p>
					<p className="bs-ds-fix__note">{ __( 'Once this finding closes, let an account back in from Activity, under Undo important setting changes.', 'bettershield' ) }</p>
				</>
			) : null }
		</>
	);
}

DormantSuspend.kind = 'acts';
