/**
 * Fix for "Some accounts signed in with passwords below the policy" (#2430).
 *
 * Each account the policy flagged, ticked, and Ask for a new password: its
 * current password stops signing it in until it sets one, and WordPress
 * emails it the link to. The password is never changed here, so each has an
 * Undo that lets the old one sign in again.
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
	return row.privileged
		? sprintf(
				/* translators: %s: a username. */
				__( '%s, can change the site', 'bettershield' ),
				row.login
		  )
		: row.login;
}

export default function WeakPasswordReset() {
	const { askNewPasswords, undoNewPassword, checkFindingAgain, busy } = useStore();
	const { state, setState, unread } = useFixState( '/bettershield/v1/findings/passwords_below_policy/accounts' );
	const [ picked, setPicked ] = useState( null );
	const [ held, setHeld ] = useState( [] );
	const [ refused, setRefused ] = useState( [] );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'weak-passwords' );
	const checking = isWorking( busy, 'guidance-passwords_below_policy' );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The accounts could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the accounts…', 'bettershield' ) }</p>;
	}

	// Your own row is changed on your profile, never asked from here.
	const open = state.accounts.filter( ( row ) => '' === row.refused && ! row.self );
	const others = state.accounts.filter( ( row ) => ! row.self );

	// The reader's own password is theirs to change on their profile; the
	// finding closes once the check sees it changed.
	const checkOwn = () => {
		announce( __( 'Checking again…', 'bettershield' ) );
		checkFindingAgain( 'passwords_below_policy', ( answer ) => {
			if ( answer && answer.open ) {
				say( __( 'Your password is still weaker than your password rules. Change it on your profile, then press Check Again.', 'bettershield' ) );
			}
		} );
	};
	const chosen = picked || open.map( ( row ) => row.id );
	const toggle = ( id, on ) => setPicked( on ? [ ...chosen, id ] : chosen.filter( ( other ) => other !== id ) );

	const ask = () => {
		announce( __( 'Asking the chosen accounts for a new password…', 'bettershield' ) );
		askNewPasswords( chosen, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setHeld( ( was ) => [ ...was, ...answer.held ] );
			setRefused( answer.refused );
			setPicked( null );
			setState( answer.state );
			say(
				sprintf(
					/* translators: %d: how many accounts were asked. */
					_n(
						'%d account must set a new password at its next sign-in. A reset link is on its way to it.',
						'%d accounts must set a new password at their next sign-in. A reset link is on its way to each.',
						answer.held.length,
						'bettershield'
					),
					answer.held.length
				)
			);
		} );
	};

	const undo = ( row ) => {
		announce(
			sprintf(
				/* translators: %s: a username. */
				__( 'Letting %s sign in with the old password again…', 'bettershield' ),
				row.login
			)
		);
		undoNewPassword( row.undo, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setHeld( ( was ) => was.filter( ( other ) => other.undo !== row.undo ) );
			say(
				sprintf(
					/* translators: %s: a username. */
					__( '%s signs in with its current password again.', 'bettershield' ),
					row.login
				)
			);
		} );
	};

	return (
		<>
			{ state.accounts.length ? (
				<>
					{ state.accounts
						.filter( ( row ) => row.self )
						.map( ( row ) => (
							<div key={ row.id }>
								<p className="bs-ds-fix__text">{ __( 'Your password is weaker than your password rules. Change it on your profile, then press Check Again.', 'bettershield' ) }</p>
								<div className="bs-ds-fix__actions">
									{ row.profile ? (
										<Button type="secondary" size="sm" trailing="arrow-right" href={ row.profile }>
											{ __( 'Change Your Password', 'bettershield' ) }
										</Button>
									) : null }
									{ /* With other accounts below, their Ask is the panel's main action. */ }
									<Button type={ others.length ? 'secondary' : 'primary' } size="sm" isBusy={ checking } disabled={ checking || working } onClick={ checkOwn }>
										{ __( 'Check Again', 'bettershield' ) }
									</Button>
								</div>
							</div>
						) ) }
					{ others.length ? (
						<p className="bs-ds-fix__text">
							{ __( 'Each chosen account sets a new password before its current one signs it in again. Passkeys keep working.', 'bettershield' ) }
						</p>
					) : null }
					{ others.length ? (
						<ul className="bs-ds-fix__list">
						{ others.map( ( row ) => (
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
					) : null }
					{ state.total > state.accounts.length ? (
						<p className="bs-ds-fix__note">
							{ sprintf(
								/* translators: %d: how many more are not listed. */
								_n( '%d more is not listed. Ask these and it is listed next.', '%d more are not listed. Ask these and they are listed next.', state.total - state.accounts.length, 'bettershield' ),
								state.total - state.accounts.length
							) }
						</p>
					) : null }
					{ open.length ? (
						<div className="bs-ds-fix__actions">
							<Armed
								type="primary"
								label={ sprintf(
									/* translators: %d: how many accounts are ticked. */
									_n( 'Ask %d Account for a New Password', 'Ask %d Accounts for a New Password', chosen.length, 'bettershield' ),
									chosen.length
								) }
								consequence={ __( 'Their current password stops signing them in, and WordPress emails each a link to set a new one. Undo lets the old one work again.', 'bettershield' ) }
								confirm={ __( 'Yes, Ask Them', 'bettershield' ) }
								busy={ working }
								disabled={ ! chosen.length }
								onConfirm={ ask }
							/>
						</div>
					) : null }
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No account is waiting to be asked now.', 'bettershield' ) }</p>
			) }
			{ held.length ? (
				<ul className="bs-ds-fix__list" aria-label={ __( 'Asked for a new password', 'bettershield' ) }>
					{ held.map( ( row ) => (
						<li key={ row.undo } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ sprintf(
									/* translators: %s: a username. */
									__( '%s must set a new password', 'bettershield' ),
									row.login
								) }
							</span>
							<Button
								type="secondary"
								size="sm"
								disabled={ working }
								aria-label={ sprintf(
									/* translators: %s: a username. */
									__( 'Undo for %s', 'bettershield' ),
									row.login
								) }
								onClick={ () => undo( row ) }
							>
								{ __( 'Undo', 'bettershield' ) }
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
								/* translators: 1: a username; 2: why it was not asked. */
								__( '%1$s was not asked. %2$s', 'bettershield' ),
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
				</>
			) : null }
		</>
	);
}

WeakPasswordReset.kind = 'acts';
