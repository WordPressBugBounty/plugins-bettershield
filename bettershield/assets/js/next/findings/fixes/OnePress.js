/**
 * Fix for six findings whose step is one press of an action that already
 * has a route (#1944): a new recovery link, checking advisories, checking
 * files, repairing storage (two findings) and renewing the security
 * contact.
 *
 * Each says what the press does, runs it, and has the report read again so
 * the finding follows. A new recovery link is shown here once, the way the
 * Recovery screen shows it, because the saved one stops working. A file
 * check that runs on in the background says so rather than waiting.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { ONE_PRESS } from '../../data/overview';
import { announce } from '../../../ui/announce';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

/** The storage repair, shared by the two findings it answers. */
const repair = {
	text: () => __( 'Repair adds back BetterShield’s missing database parts. It never deletes your data.', 'bettershield' ),
	label: () => __( 'Repair Storage', 'bettershield' ),
	key: 'fix-repair',
	run: () =>
		apiFetch( { path: '/bettershield/v1/schema/repair', method: 'POST' } ).then( ( result ) =>
			result && result.repaired ? __( 'Storage was repaired.', 'bettershield' ) : ( result && result.reason ) || __( 'The repair did not complete. The database’s answer is on the Overview.', 'bettershield' )
		),
};

/** Each finding's press, by its key. */
const ACTIONS = {
	vulnerability_data_stale: {
		text: () => __( 'Check your plugins and themes for known security issues now.', 'bettershield' ),
		label: () => __( 'Check Now', 'bettershield' ),
		key: 'vulnerabilities',
		store: true,
		// Its own route runs the audit, and the store reads the report again.
		run: ( store, then ) => Promise.resolve( store.checkVulnerabilities() ).then( ( data ) => data && then( __( 'Security check finished.', 'bettershield' ), false ) ),
	},
	files_never_checked: {
		text: () => __( 'Compare WordPress and its plugins with the copies WordPress.org publishes. On a large site it carries on in the background.', 'bettershield' ),
		label: () => __( 'Check Files Now', 'bettershield' ),
		key: 'fix-files',
		run: () =>
			apiFetch( { path: '/bettershield/v1/integrity/scan', method: 'POST' } ).then( ( report ) =>
				report && report.running ? __( 'Checking… it carries on in the background, and the finding updates when it finishes.', 'bettershield' ) : __( 'The files were checked.', 'bettershield' )
			),
	},
	schema_storage_unavailable: repair,
	claims_unreadable: repair,
	disclosure_contact_lapsing: {
		text: () => __( 'Renew your security.txt contact file for another year.', 'bettershield' ),
		label: () => __( 'Renew for a Year', 'bettershield' ),
		key: 'securityTxt',
		store: true,
		run: ( store, then ) => store.saveSecurityTxt( { renew: true }, () => then( __( 'The contact now expires a year from today.', 'bettershield' ) ) ),
	},
};

/**
 * A new recovery link, shown once.
 */
function RecoveryRenew() {
	const { generateRecovery, runAudit, busy } = useStore();
	const [ url, setUrl ] = useState( null );
	const copy = useRef( null );
	const working = isWorking( busy, 'recovery' );

	useEffect( () => {
		if ( url && copy.current ) {
			copy.current.focus();
		}
	}, [ url ] );

	const make = () =>
		generateRecovery( ( result ) => {
			if ( result && result.url ) {
				setUrl( result.url );
				announce( __( 'A new recovery link is ready. It is shown only here.', 'bettershield' ) );
			}
		} );

	if ( url ) {
		return (
			<>
				<p className="bs-ds-fix__text">{ __( 'Store this link somewhere you can reach when locked out. It is shown only now, and lasts 90 days.', 'bettershield' ) }</p>
				<div ref={ copy } tabIndex={ -1 }>
					<CopyField label={ __( 'Recovery link', 'bettershield' ) } value={ url } copyLabel={ __( 'Copy Link', 'bettershield' ) } />
				</div>
				{ /* The audit closes the finding, and with it this row and the
				     link, so it waits until the link is saved. */ }
				<div className="bs-ds-fix__actions">
					<Button type="secondary" size="sm" isBusy={ isWorking( busy, 'audit' ) } disabled={ isWorking( busy, 'audit' ) } onClick={ runAudit }>
						{ __( 'I Have Saved It', 'bettershield' ) }
					</Button>
				</div>
			</>
		);
	}

	return (
		<>
			<p className="bs-ds-fix__text">{ __( 'A new link lasts another 90 days. The link you have saved stops working as soon as it is made.', 'bettershield' ) }</p>
			<div className="bs-ds-fix__actions">
				<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ make }>
					{ __( 'Get a New Recovery Link', 'bettershield' ) }
				</Button>
			</div>
		</>
	);
}

/**
 * The press for one of the other five findings.
 *
 * @param {Object} props
 * @param {Object} props.finding The finding.
 */
function Press( { finding } ) {
	const store = useStore();
	const { runAudit, load, busy } = store;
	const action = ACTIONS[ finding.id ];
	const [ running, setRunning ] = useState( false );
	const [ said, setSaid ] = useState( '' );
	const working = running || isWorking( busy, action.key );

	const say = ( words ) => {
		setSaid( words );
		announce( words );
	};

	const press = () => {
		setSaid( '' );

		// A store action reads the report again itself, or hands its words
		// back; a route called here is followed by the audit.
		if ( action.store ) {
			action.run( store, ( words, audit = true ) => {
				say( words );

				if ( audit ) {
					window.setTimeout( runAudit, 0 );
				}
			} );

			return;
		}

		setRunning( true );
		action
			.run()
			.then(
				( words ) => {
					say( words );
					load( 'overview', { force: true } );
					runAudit();
				},
				( error ) => say( ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) )
			)
			.finally( () => setRunning( false ) );
	};

	return (
		<>
			<p className="bs-ds-fix__text">{ action.text() }</p>
			<div className="bs-ds-fix__actions">
				<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ press }>
					{ action.label() }
				</Button>
			</div>
			{ said ? (
				<p className="bs-ds-fix__note" role="status">
					{ said }
				</p>
			) : null }
		</>
	);
}


export { ONE_PRESS };

export default function OnePress( { finding } ) {
	return 'recovery_link_lapsing' === finding.id ? <RecoveryRenew /> : <Press finding={ finding } />;
}

OnePress.kind = 'acts';
