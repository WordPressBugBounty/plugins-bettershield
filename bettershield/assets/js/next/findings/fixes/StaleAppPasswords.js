/**
 * Fix for "Application passwords that nothing has used for months" (#2430).
 *
 * Each unused application password by its account and name, all ticked, so
 * one the owner still needs can be left out. Revoke cannot be undone, since
 * a revoked password cannot be restored, and the confirmation says so before
 * the press; the activity log records each one.
 */

import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Armed from '../../ui/Armed';
import Field from '../../ui/Field';
import useFixState, { useSaid } from './useFixState';

/**
 * One password's line: whose, what it is called, and how long it has sat.
 *
 * @param {Object} row The password.
 * @return {string} The line.
 */
function named( row ) {
	return row.used
		? sprintf(
				/* translators: 1: a username; 2: an application password's name; 3: a number of days. */
				_n( '%1$s: %2$s, unused for %3$d day', '%1$s: %2$s, unused for %3$d days', row.days, 'bettershield' ),
				row.login,
				row.name,
				row.days
		  )
		: sprintf(
				/* translators: 1: a username; 2: an application password's name; 3: a number of days. */
				_n( '%1$s: %2$s, never used in %3$d day', '%1$s: %2$s, never used in %3$d days', row.days, 'bettershield' ),
				row.login,
				row.name,
				row.days
		  );
}

export default function StaleAppPasswords() {
	const { revokeStalePasswords, busy } = useStore();
	const { state, setState, unread } = useFixState( '/bettershield/v1/findings/application_passwords_stale/passwords' );
	const [ picked, setPicked ] = useState( null );
	const [ refused, setRefused ] = useState( [] );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'stale-passwords' );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The application passwords could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the application passwords…', 'bettershield' ) }</p>;
	}

	const open = state.passwords.filter( ( row ) => '' === row.refused );
	// Every one that can be revoked starts ticked: each is one the finding counts.
	const chosen = picked || open.map( ( row ) => row.key );
	const toggle = ( key, on ) => setPicked( on ? [ ...chosen, key ] : chosen.filter( ( other ) => other !== key ) );

	const revoke = () => {
		announce( __( 'Revoking the chosen application passwords…', 'bettershield' ) );
		revokeStalePasswords( chosen, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setState( answer.state );
			setRefused( answer.refused );
			setPicked( null );
			say(
				sprintf(
					/* translators: %d: how many application passwords were revoked. */
					_n(
						'%d application password was revoked. It stops working now, and the activity log records it.',
						'%d application passwords were revoked. They stop working now, and the activity log records each.',
						answer.revoked.length,
						'bettershield'
					),
					answer.revoked.length
				)
			);
		} );
	};

	return (
		<>
			{ state.passwords.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Untick any a tool still needs. A revoked password cannot be restored; the tool would need a new one.', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.passwords.map( ( row ) => (
							<li key={ row.key }>
								{ '' === row.refused ? (
									<Field kind="check" label={ named( row ) } checked={ chosen.includes( row.key ) } disabled={ working } onChange={ ( on ) => toggle( row.key, on ) } />
								) : (
									<p className="bs-ds-fix__note">
										{ sprintf(
											/* translators: 1: an application password; 2: why it is left alone. */
											__( '%1$s. %2$s', 'bettershield' ),
											named( row ),
											row.refused
										) }
									</p>
								) }
							</li>
						) ) }
					</ul>
					{ state.total > state.passwords.length ? (
						<p className="bs-ds-fix__note">
							{ sprintf(
								/* translators: %d: how many more are not listed. */
								_n( '%d more is not listed. Revoke these and it is listed next.', '%d more are not listed. Revoke these and they are listed next.', state.total - state.passwords.length, 'bettershield' ),
								state.total - state.passwords.length
							) }
						</p>
					) : null }
					{ open.length ? (
						<div className="bs-ds-fix__actions">
							<Armed
								type="primary"
								label={ sprintf(
									/* translators: %d: how many application passwords are ticked. */
									_n( 'Revoke %d Password', 'Revoke %d Passwords', chosen.length, 'bettershield' ),
									chosen.length
								) }
								consequence={ __( 'Any tool using these stops working until it gets a new one. This cannot be undone: a revoked password cannot be restored.', 'bettershield' ) }
								confirm={ __( 'Yes, Revoke Them', 'bettershield' ) }
								busy={ working }
								disabled={ ! chosen.length }
								onConfirm={ revoke }
							/>
						</div>
					) : null }
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No application password has gone unused that long now.', 'bettershield' ) }</p>
			) }
			{ refused.length ? (
				<ul className="bs-ds-fix__list">
					{ refused.map( ( row ) => (
						<li key={ row.key } className="bs-ds-fix__note">
							{ sprintf(
								/* translators: 1: a username; 2: an application password's name; 3: why it was not revoked. */
								__( '%1$s: %2$s was not revoked. %3$s', 'bettershield' ),
								row.login,
								row.name,
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
				</>
			) : null }
		</>
	);
}

StaleAppPasswords.kind = 'acts';
