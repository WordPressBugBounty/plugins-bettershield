/**
 * Fix for "wp-config.php can be written by other accounts on the server"
 * (#1868, #2430).
 *
 * The file's permissions now and what they would be: only the write access
 * the group and other accounts have is taken, so the owner can still edit it
 * and WordPress still reads it. Undo puts back the exact mode it had. A file
 * another account owns, or a Windows server, says why it is left alone.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';

export default function ConfigMode() {
	const { tightenConfig, restoreConfig, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const working = isWorking( busy, 'config-mode' );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/findings/config_world_writable/mode' } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The file’s permissions could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the file’s permissions…', 'bettershield' ) }</p>;
	}

	if ( state.windows ) {
		return <p className="bs-ds-fix__text">{ __( 'On a Windows server, permissions are not set this way. Ask your host to stop other accounts writing to wp-config.php.', 'bettershield' ) }</p>;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const refused = ( error ) => {
		say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	const apply = () => {
		setSaid( null );
		announce( __( 'Changing the permissions…', 'bettershield' ) );
		tightenConfig( ( answer ) => {
			if ( answer ) {
				setState( answer.state );
				say(
					'success',
					sprintf(
						/* translators: 1: permissions before, e.g. "0666"; 2: permissions now. */
						__( 'wp-config.php is now %2$s, changed from %1$s. Its Undo stays under Activity, Undo important setting changes.', 'bettershield' ),
						answer.from,
						answer.to
					)
				);
			}
		}, refused );
	};

	const undo = () => {
		setSaid( null );
		restoreConfig(
			state.undo,
			( answer ) => {
				if ( answer ) {
					setState( answer.state );
					say(
						'success',
						sprintf(
							/* translators: %s: permissions, e.g. "0666". */
							__( 'wp-config.php is back to %s.', 'bettershield' ),
							answer.state.mode
						)
					);
				}
			},
			refused
		);
	};

	return (
		<>
			{ state.writable && '' === state.refused ? (
				<>
					<p className="bs-ds-fix__text">
						{ sprintf(
							/* translators: 1: permissions now, e.g. "0666"; 2: the permissions it would get. */
							__( 'wp-config.php: %1$s to %2$s', 'bettershield' ),
							state.mode,
							state.proposed
						) }
					</p>
					<p className="bs-ds-fix__note">{ __( 'Takes away only the write access other accounts have. The owner keeps theirs, and WordPress still reads the file.', 'bettershield' ) }</p>
					<div className="bs-ds-fix__actions">
						<Armed
							type="primary"
							label={ sprintf( /* translators: %s: the permissions it would get, e.g. "0644". */ __( 'Set to %s', 'bettershield' ), state.proposed ) }
							consequence={ sprintf(
								/* translators: 1: permissions now; 2: the permissions it would get. */
								__( 'wp-config.php goes from %1$s to %2$s. Nothing inside it changes, and Undo puts %1$s back.', 'bettershield' ),
								state.mode,
								state.proposed
							) }
							confirm={ __( 'Yes, Change It', 'bettershield' ) }
							busy={ working }
							disabled={ working }
							onConfirm={ apply }
						/>
					</div>
				</>
			) : null }
			{ state.writable && '' !== state.refused ? <p className="bs-ds-fix__text">{ state.refused }</p> : null }
			{ ! state.writable && ! state.undo ? <p className="bs-ds-fix__text">{ __( 'Only its owner can write to wp-config.php now.', 'bettershield' ) }</p> : null }
			{ /* Opened again after the change: what it did, above its Undo. */ }
			{ ! state.writable && state.undo && ! said ? (
				<p className="bs-ds-fix__text">
					{ sprintf(
						/* translators: 1: permissions now, e.g. "0644"; 2: permissions before, e.g. "0664". */
						__( 'wp-config.php is now %1$s, changed from %2$s.', 'bettershield' ),
						state.mode,
						state.from
					) }
				</p>
			) : null }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
			{ state.undo ? (
				<div className="bs-ds-fix__actions">
					<Armed
						label={ __( 'Undo', 'bettershield' ) }
						consequence={ sprintf(
							/* translators: %s: permissions, e.g. "0666". */
							__( 'wp-config.php goes back to %s, so other accounts can write to it again.', 'bettershield' ),
							state.from
						) }
						confirm={ __( 'Yes, Put It Back', 'bettershield' ) }
						busy={ working }
						disabled={ working }
						onConfirm={ undo }
					/>
				</div>
			) : null }
		</>
	);
}

ConfigMode.kind = 'acts';
