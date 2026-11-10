/**
 * Fix for "A user is named "admin"" (#2430).
 *
 * The owner types the new username and confirms it; the account keeps its
 * ID, posts, role and password. Renaming the account that is signed in keeps
 * its session and says to sign in with the new name next time. Undo puts the
 * old name back while no other account has taken it.
 */

import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';
import Field from '../../ui/Field';
import useFixState, { useAuditWhenGone, useSaid } from './useFixState';

export default function AdminRename() {
	const { renameAdmin, undoAdminRename, busy } = useStore();
	const { state, unread } = useFixState( '/bettershield/v1/findings/admin_username_exists/account' );
	const [ name, setName ] = useState( '' );
	const [ error, setError ] = useState( '' );
	const [ renamed, setRenamed ] = useState( null );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'admin-rename' );
	const typed = name.trim();
	// The same name in any case is refused when saved; said here, before the
	// confirmation offers it (#2617).
	const sameName = 'admin' === typed.toLowerCase();

	// Renamed or removed somewhere else since the last audit: the audit runs
	// by itself and the finding closes.
	useAuditWhenGone( Boolean( state ) && ! state.account && ! renamed );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The account could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the account…', 'bettershield' ) }</p>;
	}

	const rename = () => {
		setError( '' );
		announce( __( 'Renaming the account…', 'bettershield' ) );
		renameAdmin(
			typed,
			( answer ) => {
				if ( ! answer || ! answer.undo ) {
					return;
				}

				setRenamed( answer );
				say(
					answer.you
						? sprintf(
								/* translators: %1$s: the new username. */
								__( 'Renamed to %1$s. You stay signed in; next time, sign in with %1$s.', 'bettershield' ),
								answer.to
						  )
						: sprintf(
								/* translators: %s: the new username. */
								__( 'The account admin is now %s. Its posts and password are unchanged.', 'bettershield' ),
								answer.to
						  )
				);
			},
			// Core's rules, said beside the field rather than at the top.
			( refusal ) => {
				if ( refusal && 'bettershield_confirm_password' !== refusal.code && refusal.message ) {
					setError( refusal.message );
					announce( refusal.message );

					return true;
				}

				return false;
			}
		);
	};

	const undo = () => {
		announce( __( 'Putting the name admin back…', 'bettershield' ) );
		undoAdminRename( renamed.undo, ( answer ) => {
			if ( answer ) {
				setRenamed( null );
				setName( '' );
				say(
					answer.you
						? __( 'The account is named admin again. You stay signed in; sign in as admin next time.', 'bettershield' )
						: __( 'The account is named admin again.', 'bettershield' )
				);
			}
		} );
	};

	const line = said ? (
		<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
			{ said }
		</p>
	) : null;

	if ( renamed ) {
		return (
			<>
				{ line }
				<div className="bs-ds-fix__actions">
					<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ undo }>
						{ __( 'Undo', 'bettershield' ) }
					</Button>
				</div>
			</>
		);
	}

	if ( ! state.account ) {
		return line || <p className="bs-ds-fix__text">{ __( 'No account is named admin now. Updating this finding…', 'bettershield' ) }</p>;
	}

	if ( state.refused ) {
		return <p className="bs-ds-fix__text">{ state.refused }</p>;
	}

	return (
		<>
			<p className="bs-ds-fix__text">{ __( 'Give the account called admin a new username. Its ID, posts, role and password stay exactly as they are.', 'bettershield' ) }</p>
			{ state.account.you ? (
				<p className="bs-ds-fix__note">{ __( 'This is your account. You stay signed in, and sign in with the new name next time.', 'bettershield' ) }</p>
			) : null }
			<Field
				label={ __( 'New username', 'bettershield' ) }
				help={
					state.network
						? __( 'At least 4 lowercase letters or numbers.', 'bettershield' )
						: __( 'Letters, numbers, spaces and . - _ @, as WordPress allows.', 'bettershield' )
				}
				error={ error || ( sameName ? __( 'Choose a name other than admin.', 'bettershield' ) : '' ) }
				width="md"
				value={ name }
				disabled={ working }
				autoComplete="off"
				spellCheck={ false }
				maxLength={ 60 }
				onChange={ ( value ) => {
					setName( value );
					setError( '' );
				} }
			/>
			<div className="bs-ds-fix__actions">
				<Armed
					type="primary"
					label={ __( 'Rename Admin', 'bettershield' ) }
					consequence={ sprintf(
						/* translators: %s: the new username. */
						__( 'The username admin becomes %s. Undo puts it back while no other account takes the name. You may be asked for your password first.', 'bettershield' ),
						typed
					) }
					confirm={ __( 'Yes, Rename It', 'bettershield' ) }
					busy={ working }
					disabled={ ! typed || sameName }
					onConfirm={ rename }
				/>
			</div>
			{ line }
		</>
	);
}

AdminRename.kind = 'acts';
