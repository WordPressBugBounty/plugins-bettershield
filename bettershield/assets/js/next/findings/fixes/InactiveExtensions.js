/**
 * Fix for "Deactivated plugins or themes are still installed" (#2430).
 *
 * Each deactivated plugin and unused theme, with Move to quarantine: the
 * folder is kept as a copy no one can run, never deleted, and its settings
 * stay in the database. Each move has its own Put back, which puts the
 * folder where it was. One that cannot be moved here says why.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';

const PATH = '/bettershield/v1/findings/inactive_extensions/extensions';

export default function InactiveExtensions() {
	const { quarantineExtension, putBackExtension, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const working = isWorking( busy, 'extensions' );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: PATH } ).then(
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
		return <p className="bs-ds-fix__text">{ __( 'The plugins and themes could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the plugins and themes…', 'bettershield' ) }</p>;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const refused = ( error ) => {
		say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	const move = ( row ) => {
		setSaid( null );
		announce( sprintf( /* translators: %s: a plugin's or theme's name. */ __( 'Moving %s to quarantine…', 'bettershield' ), row.name ) );
		quarantineExtension(
			row.kind,
			row.id,
			( answer ) => {
				if ( answer ) {
					setState( answer.state );
					say( 'success', sprintf( /* translators: %s: a plugin's or theme's name. */ __( '%s is in quarantine. Put back returns it, settings and all, here or under Activity, Undo important setting changes.', 'bettershield' ), answer.name ) );
				}
			},
			refused
		);
	};

	const putBack = ( row ) => {
		setSaid( null );
		announce( sprintf( /* translators: %s: a plugin's or theme's name. */ __( 'Putting %s back…', 'bettershield' ), row.name ) );
		putBackExtension(
			row.undo,
			( answer ) => {
				if ( answer ) {
					setState( answer.state );
					say( 'success', sprintf( /* translators: %s: a plugin's or theme's name. */ __( '%s is back where it was, still deactivated.', 'bettershield' ), answer.name ) );
				}
			},
			refused
		);
	};

	const kindOf = ( row ) => ( 'theme' === row.kind ? __( 'Theme', 'bettershield' ) : __( 'Plugin', 'bettershield' ) );

	return (
		<>
			{ state.rows.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Move to quarantine keeps a copy no one can run and takes the folder away. Nothing is deleted, and settings stay.', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.rows.map( ( row ) => (
							<li key={ `${ row.kind }:${ row.id }` } className="bs-ds-fix__done">
								<span className="bs-ds-fix__text">
									{ sprintf(
										/* translators: 1: "Plugin" or "Theme"; 2: its name. */
										__( '%1$s: %2$s', 'bettershield' ),
										kindOf( row ),
										row.name
									) }
								</span>
								{ '' === row.refused ? (
									<Armed
										label={ __( 'Move to Quarantine', 'bettershield' ) }
										aria-label={ sprintf( /* translators: %s: a plugin's or theme's name. */ __( 'Move %s to Quarantine', 'bettershield' ), row.name ) }
										consequence={ sprintf(
											/* translators: %s: a plugin's or theme's name. */
											__( '%s leaves the site’s folders and is kept in quarantine. Its uninstall step does not run, so its settings stay.', 'bettershield' ),
											row.name
										) }
										confirm={ __( 'Yes, Move It', 'bettershield' ) }
										busy={ working }
										disabled={ working }
										onConfirm={ () => move( row ) }
									/>
								) : (
									<span className="bs-ds-fix__note">{ row.refused }</span>
								) }
							</li>
						) ) }
					</ul>
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No deactivated plugin or unused theme is left to move.', 'bettershield' ) }</p>
			) }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
			{ state.moved.length ? (
				<ul className="bs-ds-fix__list" aria-label={ __( 'In quarantine', 'bettershield' ) }>
					{ state.moved.map( ( row ) => (
						<li key={ row.undo } className="bs-ds-fix__done">
							<span className="bs-ds-fix__text">
								{ sprintf(
									/* translators: 1: "Plugin" or "Theme"; 2: its name. */
									__( '%1$s in quarantine: %2$s', 'bettershield' ),
									kindOf( row ),
									row.name
								) }
							</span>
							{ '' === row.blocked ? (
								<Armed
									label={ __( 'Put Back', 'bettershield' ) }
									aria-label={ sprintf( /* translators: %s: a plugin's or theme's name. */ __( 'Put %s Back', 'bettershield' ), row.name ) }
									consequence={ sprintf(
										/* translators: %s: a plugin's or theme's name. */
										__( '%s returns to its folder, still deactivated. Visitors can reach its files again.', 'bettershield' ),
										row.name
									) }
									confirm={ __( 'Yes, Put It Back', 'bettershield' ) }
									busy={ working }
									disabled={ working }
									onConfirm={ () => putBack( row ) }
								/>
							) : (
								<span className="bs-ds-fix__note">{ row.blocked }</span>
							) }
						</li>
					) ) }
				</ul>
			) : null }
		</>
	);
}

InactiveExtensions.kind = 'acts';
