/**
 * What the setup's hub step shows once the site is connected: this site and
 * the hub joined by a tick, and the dialog that says the setup is done, under
 * the design's shield picture.
 *
 * The pictures are decorative: the words beside them say everything they
 * show. Closing the dialog, or its one button, opens the dashboard.
 */

import './HubConnected.css';

import { Modal } from '@wordpress/components';
import { useId, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import brand from './brand';
import { pageModel } from './api';
import leave from './leave';
import viaCore from './core';
import { announce } from '../../ui/announce';
import { listOf } from '../../setup/format';

export function HubLink() {
	return (
		<div className="bs-ds-setup-link" aria-hidden="true">
			<span className="bs-ds-setup-link__glow" />
			<span className="bs-ds-setup-link__tile">
				<Icon name="globe" size={ 24 } tone="1" />
			</span>
			<span className="bs-ds-setup-link__line" />
			<span className="bs-ds-setup-link__seal">
				<Icon name="check" size={ 20 } />
			</span>
			<span className="bs-ds-setup-link__line" />
			<span className="bs-ds-setup-link__tile">
				<Icon name="network" size={ 24 } tone="1" />
			</span>
		</div>
	);
}

/**
 * What the setup changed, as the dialog's rows: the protections that are on,
 * the safe fixes Setup applied, and the first scan. A row is left out where
 * the page was not given what it says (a reload on the hub step).
 *
 * @param {?Object} summary The setup's summary, as Ready reads it.
 * @return {Array<{icon: string, title: string, about: string}>} The rows.
 */
function changedRows( summary ) {
	if ( ! summary ) {
		return [];
	}

	const rows = [];
	const fixes = summary.fixes || {};
	const on = ( fixes.items || [] ).filter( ( fix ) => fix.on );
	const applied = ( fixes.applied || [] ).length;

	if ( on.length ) {
		const names = on.slice( 0, 2 ).map( ( fix ) => fix.title );

		rows.push( {
			icon: 'shield-check',
			// Counts every protection that is on, some on before the setup
			// ran, so it says "on" rather than "switched on" (#2996).
			title: sprintf(
				/* translators: %d: how many protections are on. */
				_n( '%d protection on', '%d protections on', on.length, 'bettershield' ),
				on.length
			),
			about:
				on.length > 2
					? sprintf(
							/* translators: 1: two protections' names, 2: how many more there are. */
							_n( '%1$s and %2$d more', '%1$s and %2$d more', on.length - 2, 'bettershield' ),
							names.join( ', ' ),
							on.length - 2
					  )
					: listOf( names ),
		} );
	}

	if ( applied ) {
		rows.push( {
			icon: 'undo-2',
			title: sprintf(
				/* translators: %d: how many safe fixes Setup applied. */
				_n( '%d safe fix applied', '%d safe fixes applied', applied, 'bettershield' ),
				applied
			),
			about: _n( 'It can be undone from Protection', 'Each one can be undone from Protection', applied, 'bettershield' ),
		} );
	}

	// The plugins the Ecosystem step installed, and the ones Coexistence
	// switched off with the way back on, as the Ecosystem step lists them.
	const installed = ( summary.installed || [] ).filter( Boolean );

	if ( installed.length ) {
		rows.push( {
			icon: 'package',
			title: _n( 'Plugin installed and activated', 'Plugins installed and activated', installed.length, 'bettershield' ),
			about: listOf( installed ),
		} );
	}

	const deactivated = ( summary.deactivated || [] ).filter( Boolean );

	if ( deactivated.length ) {
		rows.push( {
			icon: 'power',
			title: _n( 'Plugin deactivated', 'Plugins deactivated', deactivated.length, 'bettershield' ),
			about: listOf( deactivated ),
			reactivate: ( summary.reactivate || [] ).filter( ( entry ) => entry && entry.activate_url ),
		} );
	}

	if ( summary.first_scan ) {
		const running = Boolean( summary.first_scan.running );

		rows.push( {
			icon: 'list-checks',
			title: running ? __( 'First scan running', 'bettershield' ) : __( 'First scan finished', 'bettershield' ),
			about: running
				? __( 'Your score appears when it finishes.', 'bettershield' )
				: sprintf(
						/* translators: 1: a score out of 100, 2: a letter grade. */
						__( 'Score %1$d, grade %2$s', 'bettershield' ),
						summary.score,
						summary.grade
				  ),
		} );
	}

	return rows;
}

/**
 * @param {Object}   props
 * @param {Function} props.onClose   Closes it, and goes where the setup goes next.
 * @param {string}   props.doneLabel The button that does the same, named for where it goes.
 * @param {string}   props.findings  The Findings screen, for Review Findings; none to leave it out.
 * @param {?Object}  props.summary   What the setup changed, for the rows.
 * @param {boolean}  props.connected Whether the site has just connected to the hub.
 * @param {boolean}  props.already   Whether it was connected before Connect was pressed.
 */
export function SetupDoneDialog( { onClose, doneLabel = '', findings = '', summary = null, connected = true, already = false } ) {
	let text = __( 'Quick Setup is done. You can connect this site to the hub at any time.', 'bettershield' );

	if ( already ) {
		/* translators: %s: the plugin's name. */
		text = sprintf( __( 'This site is already connected to %s Hub.', 'bettershield' ), brand() );
	} else if ( connected ) {
		/* translators: %s: the plugin's name. */
		text = sprintf( __( 'Quick Setup is done, and this site is connected to %s Hub.', 'bettershield' ), brand() );
	}

	const titleId = useId();
	// The plugins turned back on from here, and the one turning on now.
	const [ backOn, setBackOn ] = useState( [] );
	const [ turning, setTurning ] = useState( '' );

	const [ failed, setFailed ] = useState( [] );

	const turnBackOn = ( entry ) => {
		setTurning( entry.file );
		/* translators: %s: a plugin's name. */
		announce( sprintf( __( 'Turning %s back on…', 'bettershield' ), entry.name ) );
		viaCore( entry.activate_url )
			.then( () => {
				setBackOn( ( list ) => [ ...list, entry.file ] );
				/* translators: %s: a plugin's name. */
				announce( sprintf( __( '%s is on again.', 'bettershield' ), entry.name ) );
			} )
			.catch( () => {
				setFailed( ( list ) => [ ...list, entry.file ] );
				/* translators: %s: a plugin's name. */
				announce( sprintf( __( '%s could not be turned back on here. Activate it from the Plugins screen.', 'bettershield' ), entry.name ), 'assertive' );
			} )
			.finally( () => setTurning( '' ) );
	};
	const assets = window.bettershield?.assetsUrl || '';
	const rows = changedRows( summary );
	const host = pageModel().host || window.location.host;

	return (
		<Modal className="bs-ds-setup-done" aria={ { labelledby: titleId } } onRequestClose={ onClose } size="medium">
			<div
				className="bs-ds-setup-done__hero"
				style={ assets ? { backgroundImage: `url("${ assets }setup/hero.webp")` } : undefined }
				aria-hidden="true"
			/>
			<div className="bs-ds-setup-done__body">
				<div className="bs-ds-setup-done__heading">
					<h2 id={ titleId } className="bs-ds-setup-done__title">
						{ __( 'Quick Setup Complete', 'bettershield' ) }
					</h2>
					{ rows.length ? (
						<p className="bs-ds-setup-done__text">
							{ sprintf(
								/* translators: %s: the site's address. */
								__( 'Here’s what Quick Setup changed on %s.', 'bettershield' ),
								host
							) }
						</p>
					) : null }
					{ /* The hub's part, where the rows do not already say the setup is done. */ }
					{ ! rows.length || connected || already ? <p className="bs-ds-setup-done__text">{ text }</p> : null }
				</div>

				{ rows.length ? (
					<ul className="bs-ds-setup-done__changes">
						{ rows.map( ( row ) => (
							<li key={ row.icon }>
								<Icon name={ row.icon } size={ 16 } tone="brand" />
								<span className="bs-ds-setup-done__change">
									<span className="bs-ds-setup-done__change-title">{ row.title }</span>
									{ row.about ? <span className="bs-ds-setup-done__change-about">{ row.about }</span> : null }
									{ ( row.reactivate || [] ).map( ( entry ) =>
										backOn.includes( entry.file ) ? (
											<span key={ entry.file } className="bs-ds-setup-done__change-about" role="status">
												{ sprintf( /* translators: %s: a plugin's name. */ __( '%s is on again.', 'bettershield' ), entry.name ) }
											</span>
										) : failed.includes( entry.file ) ? (
											<span key={ entry.file } className="bs-ds-setup-done__change-about" role="status">
												{ sprintf( /* translators: %s: a plugin's name. */ __( '%s could not be turned back on here. Activate it from the Plugins screen.', 'bettershield' ), entry.name ) }
											</span>
										) : (
											<Button
												key={ entry.file }
												type="secondary"
												size="sm"
												className="bs-ds-setup-done__back"
												isBusy={ turning === entry.file }
												disabled={ '' !== turning }
												/* translators: %s: a plugin's name. */
												aria-label={ sprintf( __( 'Turn %s Back On', 'bettershield' ), entry.name ) }
												onClick={ () => turnBackOn( entry ) }
											>
												{ row.reactivate.length > 1
													? /* translators: %s: a plugin's name. */
													  sprintf( __( 'Turn %s Back On', 'bettershield' ), entry.name )
													: __( 'Turn It Back On', 'bettershield' ) }
											</Button>
										)
									) }
								</span>
							</li>
						) ) }
					</ul>
				) : null }
			</div>
			<div className="bs-ds-app bs-ds-setup-done__actions">
				{ findings ? (
					<Button type="secondary" size="md" className="bs-ds-setup-done__review" onClick={ () => leave( findings ) }>
						{ __( 'Review Findings', 'bettershield' ) }
					</Button>
				) : null }
				<Button type="primary" size="md" className="bs-ds-setup-done__go" onClick={ onClose }>
					{ doneLabel || __( 'Go to Dashboard', 'bettershield' ) }
				</Button>
			</div>
		</Modal>
	);
}
