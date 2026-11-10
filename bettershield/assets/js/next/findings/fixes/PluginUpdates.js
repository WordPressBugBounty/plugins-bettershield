/**
 * Fix for "Plugins have updates available" and "Installed components have
 * published advisories" (#2430).
 *
 * Each plugin with its version now and the one offered, and Update now, one
 * at a time, through WordPress's own installer. Before the press it says an
 * update cannot be fully undone, and recommends a backup where none is seen.
 * Undo installs the version that was there again. A plugin that updates from
 * its own publisher, or has no fixed version yet, says why and points to the
 * screen that handles it.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';

/**
 * @param {Object} props
 * @param {Object} props.finding The finding.
 */
export default function PluginUpdates( { finding } ) {
	const { updatePlugin, undoPluginUpdate, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const working = isWorking( busy, 'plugin-update' );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: `/bettershield/v1/findings/${ finding.id }/updates` } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [ finding.id ] );

	// The result takes focus, so it is read where the press was.
	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The plugins could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the plugins…', 'bettershield' ) }</p>;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const refused = ( error ) => {
		say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	const update = ( row ) => {
		setSaid( null );
		announce( sprintf( /* translators: %s: a plugin's name. */ __( 'Updating %s…', 'bettershield' ), row.name ) );
		updatePlugin(
			finding.id,
			row.file,
			( answer ) => {
				if ( ! answer ) {
					return;
				}

				setState( answer.state );
				say(
					'success',
					sprintf(
						/* translators: 1: a plugin's name; 2: its version before; 3: its version now. */
						__( '%1$s is updated from %2$s to %3$s. Its Undo stays under Activity, Undo important setting changes.', 'bettershield' ),
						answer.name,
						answer.from,
						answer.to
					)
				);
			},
			refused
		);
	};

	const undo = ( row ) => {
		setSaid( null );
		announce( sprintf( /* translators: %s: a plugin's name. */ __( 'Putting %s back…', 'bettershield' ), row.name ) );
		undoPluginUpdate(
			finding.id,
			row.undo,
			( answer ) => {
				if ( ! answer ) {
					return;
				}

				setState( answer.state );
				say(
					'success',
					sprintf(
						/* translators: 1: a plugin's name; 2: a version number. */
						__( '%1$s is back to version %2$s. Anything the update changed in the database stays.', 'bettershield' ),
						answer.name,
						answer.version
					)
				);
			},
			refused
		);
	};

	const open = state.rows.filter( ( row ) => '' === row.refused );

	return (
		<>
			{ open.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Each update runs through WordPress’s own installer, as Update now under Plugins does.', 'bettershield' ) }</p>
					<p className="bs-ds-fix__note">{ __( 'An update can’t be fully undone. Undo puts the earlier code back, but not the changes the update made to the database.', 'bettershield' ) }</p>
					{ state.backup_seen ? null : (
						<Alert layout="default" tone="warning" desc={ __( 'No backup plugin is active. Make a backup first, or check that your host keeps one.', 'bettershield' ) } />
					) }
				</>
			) : null }
			{ state.rows.length ? (
				<ul className="bs-ds-fix__list">
					{ state.rows.map( ( row ) => (
						<li key={ row.file || row.name } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ row.offer
									? sprintf(
											/* translators: 1: a plugin's name; 2: its version now; 3: the version offered. */
											__( '%1$s: %2$s to %3$s', 'bettershield' ),
											row.name,
											row.version,
											row.offer
									  )
									: sprintf(
											/* translators: 1: a plugin's name; 2: its version now. */
											__( '%1$s: %2$s', 'bettershield' ),
											row.name,
											row.version
									  ) }
							</span>
							{ '' === row.refused ? (
								<Armed
									type="primary"
									label={ __( 'Update Now', 'bettershield' ) }
									aria-label={ sprintf( /* translators: %s: a plugin's name. */ __( 'Update %s Now', 'bettershield' ), row.name ) }
									consequence={ sprintf(
										/* translators: 1: a plugin's name; 2: the version offered. */
										__( 'Installs %1$s %2$s. Undo can put the code back, not its database changes.', 'bettershield' ),
										row.name,
										row.offer
									) }
									confirm={ __( 'Yes, Update', 'bettershield' ) }
									busy={ working }
									disabled={ working }
									onConfirm={ () => update( row ) }
								/>
							) : (
								<span className="bs-ds-fix__note">{ row.refused }</span>
							) }
						</li>
					) ) }
				</ul>
			) : said || state.updated.length ? null : (
				// The empty state would sit right above the result of an update, so it waits until no result is showing.
				<p className="bs-ds-fix__text">{ __( 'Nothing here can be updated now. WordPress may not have checked for updates yet.', 'bettershield' ) }</p>
			) }
			{ open.length < state.rows.length ? (
				<div className="bs-ds-fix__actions">
					<Button type="secondary" size="sm" icon="external-link" iconTone="2" href={ state.updates_url }>
						{ __( 'Open Updates', 'bettershield' ) }
					</Button>
				</div>
			) : null }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
			{ state.updated.length ? (
				<ul className="bs-ds-fix__list" aria-label={ __( 'Updated', 'bettershield' ) }>
					{ state.updated.map( ( row ) => (
						<li key={ row.undo } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ sprintf(
									/* translators: 1: a plugin's name; 2: its version before; 3: its version now. */
									__( '%1$s updated: %2$s to %3$s', 'bettershield' ),
									row.name,
									row.from,
									row.to
								) }
							</span>
							<Armed
								label={ __( 'Undo', 'bettershield' ) }
								aria-label={ sprintf( /* translators: %s: a plugin's name. */ __( 'Undo the Update of %s', 'bettershield' ), row.name ) }
								consequence={ sprintf(
									/* translators: 1: a plugin's name; 2: a version number. */
									__( 'Installs %1$s %2$s again. Any advisory it carried applies again.', 'bettershield' ),
									row.name,
									row.from
								) }
								confirm={ __( 'Yes, Put It Back', 'bettershield' ) }
								busy={ working }
								disabled={ working }
								onConfirm={ () => undo( row ) }
							/>
						</li>
					) ) }
				</ul>
			) : null }
		</>
	);
}

PluginUpdates.kind = 'acts';
