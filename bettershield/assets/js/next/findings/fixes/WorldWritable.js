/**
 * Fix for "Folders under wp-content can be written by every account on the
 * server" (#2211).
 *
 * Each folder the finding names, with its mode now and the mode it would
 * get: only the write access every account has is taken, so the owner's
 * and the group's stay as they are. A folder that cannot be changed here
 * says why. Each change has its own Undo, which puts back the exact mode.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Button from '../../ui/Button';
import Field from '../../ui/Field';

export default function WorldWritable() {
	const { tightenFolders, restoreFolder, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ picked, setPicked ] = useState( null );
	// What was changed from here, each with its undo handle, and what was refused.
	const [ changed, setChanged ] = useState( [] );
	const [ refused, setRefused ] = useState( [] );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/findings/content_dirs_world_writable/folders' } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The folders’ permissions could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the folders…', 'bettershield' ) }</p>;
	}

	if ( state.windows ) {
		return <p className="bs-ds-fix__text">{ __( 'On Windows servers, BetterShield can’t change this. Ask your host to stop other users from changing these folders.', 'bettershield' ) }</p>;
	}

	const working = isWorking( busy, 'content-folders' );
	const open = state.folders.filter( ( folder ) => '' === folder.refused );
	// Every folder that can be changed starts chosen: each is one the
	// finding named, and each change has its own Undo.
	const chosen = picked || open.map( ( folder ) => folder.name );
	const toggle = ( name, on ) => setPicked( on ? [ ...chosen, name ] : chosen.filter( ( other ) => other !== name ) );

	const apply = () =>
		tightenFolders( chosen, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setChanged( ( was ) => [ ...was, ...answer.changed ] );
			setRefused( answer.refused );
			setPicked( null );
			setState( answer.state );
			announce(
				sprintf(
					/* translators: %d: how many folders were changed. */
					_n( '%d folder is now protected.', '%d folders are now protected.', answer.changed.length, 'bettershield' ),
					answer.changed.length
				)
			);
		} );

	const undo = ( row ) =>
		restoreFolder( row.undo, ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setChanged( ( was ) => was.filter( ( other ) => other.undo !== row.undo ) );
			setState( answer.state );
			announce(
				sprintf(
					/* translators: 1: a folder; 2: its permissions, e.g. "0777". */
					__( '%1$s is back to %2$s.', 'bettershield' ),
					row.name,
					row.from
				)
			);
		} );

	return (
		<>
			{ state.folders.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Stops other users on the server from changing these folders. Your site keeps working.', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.folders.map( ( folder ) => (
							<li key={ folder.name }>
								{ '' === folder.refused ? (
									<Field
										kind="check"
										label={ sprintf(
											/* translators: 1: a folder; 2: its permissions now; 3: the permissions it would get. */
											__( '%1$s: permissions changed from %2$s to %3$s', 'bettershield' ),
											folder.name,
											folder.mode,
											folder.proposed
										) }
										checked={ chosen.includes( folder.name ) }
										disabled={ working }
										onChange={ ( on ) => toggle( folder.name, on ) }
									/>
								) : (
									<p className="bs-ds-fix__note">
										{ sprintf(
											/* translators: 1: a folder; 2: why it is left alone. */
											__( '%1$s: %2$s', 'bettershield' ),
											folder.name,
											folder.refused
										) }
									</p>
								) }
							</li>
						) ) }
					</ul>
					{ open.length ? (
						<div className="bs-ds-fix__actions">
							<Button type="primary" size="sm" isBusy={ working } disabled={ working || ! chosen.length } onClick={ apply }>
								{ sprintf(
									/* translators: %d: how many folders are chosen. */
									_n( 'Fix Permissions on %d Folder', 'Fix Permissions on %d Folders', chosen.length, 'bettershield' ),
									chosen.length
								) }
							</Button>
						</div>
					) : null }
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No folder the finding named is writable by every account now.', 'bettershield' ) }</p>
			) }
			{ changed.length ? (
				<ul className="bs-ds-fix__list" aria-label={ __( 'Changed', 'bettershield' ) }>
					{ changed.map( ( row ) => (
						<li key={ row.undo } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ sprintf(
									/* translators: 1: a folder; 2: its permissions before; 3: its permissions now. */
									__( '%1$s: permissions changed from %2$s to %3$s', 'bettershield' ),
									row.name,
									row.from,
									row.to
								) }
							</span>
							<Button
								type="secondary"
								size="sm"
								disabled={ working }
								aria-label={ sprintf(
									/* translators: %s: a folder. */
									__( 'Undo %s', 'bettershield' ),
									row.name
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
						<li key={ row.name } className="bs-ds-fix__note">
							{ sprintf(
								/* translators: 1: a folder; 2: why it was not changed. */
								__( '%1$s was not changed: %2$s', 'bettershield' ),
								row.name,
								row.reason
							) }
						</li>
					) ) }
				</ul>
			) : null }
		</>
	);
}

WorldWritable.kind = 'acts';
