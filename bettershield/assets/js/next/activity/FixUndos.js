/**
 * The ways back from fixes made on the Findings report (#2430), kept after
 * their finding closes: a plugin update, an unused plugin or theme moved into
 * quarantine, wp-config.php's permissions, the account renamed from "admin",
 * scheduled events removed (#2471), folders' permissions narrowed,
 * accounts asked for a new password, REST addresses watched or closed
 * to visitors (#1870), this site's own links rewritten to https:// and the
 * quarantine folder sealed (#2658). Each asks first, and goes
 * through the same route as the finding's own Undo, so the password is asked
 * for where the owner turned that on.
 */

import brand from '../setup/brand';
import './FixUndos.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../store';
import { announce } from '../../ui/announce';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Table, { Cell, Row } from '../ui/Table';

/** Each kind's line, control and what pressing it does. */
const KINDS = {
	admin_rename: {
		line: ( row ) =>
			/* translators: 1: the old username, "admin"; 2: the username it has now. */
			sprintf( __( 'Username %1$s renamed to %2$s', 'bettershield' ), row.from, row.to ),
		label: () => __( 'Undo', 'bettershield' ),
		consequence: ( row ) =>
			/* translators: 1: the username it has now; 2: the old username, "admin". */
			sprintf( __( 'The account signs in as %2$s again instead of %1$s, while no other account takes that name.', 'bettershield' ), row.to, row.from ),
		/* translators: %s: the old username, "admin". */
		done: ( row ) => sprintf( __( 'The account is named %s again.', 'bettershield' ), row.from ),
		busy: 'admin-rename',
	},
	plugin_update: {
		line: ( row ) =>
			/* translators: 1: a plugin's name; 2: its version before; 3: its version now. */
			sprintf( __( '%1$s updated from %2$s to %3$s', 'bettershield' ), row.name, row.from, row.to ),
		label: () => __( 'Undo Update', 'bettershield' ),
		consequence: ( row ) =>
			/* translators: 1: a plugin's name; 2: a version number. */
			sprintf( __( 'Installs %1$s %2$s again. Database changes the update made stay, and any advisory it carried applies again.', 'bettershield' ), row.name, row.from ),
		done: ( row ) =>
			/* translators: 1: a plugin's name; 2: a version number. */
			sprintf( __( '%1$s is back to version %2$s.', 'bettershield' ), row.name, row.from ),
		busy: 'plugin-update',
	},
	plugin_quarantined: {
		/* translators: %s: a plugin's name. */
		line: ( row ) => sprintf( __( 'Plugin in quarantine: %s', 'bettershield' ), row.name ),
		label: () => __( 'Put Back', 'bettershield' ),
		/* translators: %s: a plugin's name. */
		consequence: ( row ) => sprintf( __( '%s returns to its folder, still deactivated. Visitors can reach its files again.', 'bettershield' ), row.name ),
		/* translators: %s: a plugin's or theme's name. */
		done: ( row ) => sprintf( __( '%s is back where it was, still deactivated.', 'bettershield' ), row.name ),
		busy: 'extensions',
	},
	theme_quarantined: {
		/* translators: %s: a theme's name. */
		line: ( row ) => sprintf( __( 'Theme in quarantine: %s', 'bettershield' ), row.name ),
		label: () => __( 'Put Back', 'bettershield' ),
		/* translators: %s: a theme's name. */
		consequence: ( row ) => sprintf( __( '%s returns to the themes folder. Visitors can reach its files again.', 'bettershield' ), row.name ),
		/* translators: %s: a plugin's or theme's name. */
		done: ( row ) => sprintf( __( '%s is back where it was, still deactivated.', 'bettershield' ), row.name ),
		busy: 'extensions',
	},
	config_mode: {
		/* translators: 1: permissions before, e.g. "0666"; 2: permissions now. */
		line: ( row ) => sprintf( __( 'wp-config.php permissions changed from %1$s to %2$s', 'bettershield' ), row.from, row.to ),
		label: () => __( 'Undo', 'bettershield' ),
		/* translators: %s: permissions, e.g. "0666". */
		consequence: ( row ) => sprintf( __( 'wp-config.php goes back to %s, so other accounts can write to it again.', 'bettershield' ), row.from ),
		/* translators: %s: permissions, e.g. "0666". */
		done: ( row ) => sprintf( __( 'wp-config.php is back to %s.', 'bettershield' ), row.from ),
		busy: 'config-mode',
	},
	scheduled_events: {
		/* translators: %s: the names of scheduled events, separated by commas. */
		line: ( row ) => sprintf( __( 'Scheduled events removed: %s', 'bettershield' ), row.name ),
		label: () => __( 'Undo', 'bettershield' ),
		consequence: () => __( 'Each event is scheduled again as it was, with its arguments. Nothing answers them yet, so they may still do nothing.', 'bettershield' ),
		done: () => __( 'The scheduled events are back on the schedule.', 'bettershield' ),
		busy: 'cron-undo',
	},
	folder_mode: {
		/* translators: 1: a folder, e.g. "wp-content/uploads"; 2: permissions before, e.g. "0777"; 3: permissions now. */
		line: ( row ) => sprintf( __( '%1$s permissions changed from %2$s to %3$s', 'bettershield' ), row.name, row.from, row.to ),
		label: () => __( 'Undo', 'bettershield' ),
		/* translators: 1: a folder, e.g. "wp-content/uploads"; 2: permissions, e.g. "0777". */
		consequence: ( row ) => sprintf( __( '%1$s goes back to %2$s, so every account on the server can write to it again.', 'bettershield' ), row.name, row.from ),
		/* translators: 1: a folder, e.g. "wp-content/uploads"; 2: permissions, e.g. "0777". */
		done: ( row ) => sprintf( __( '%1$s is back to %2$s.', 'bettershield' ), row.name, row.from ),
		busy: 'content-folders',
	},
	rest_route: {
		line: ( row ) =>
			'closed' === row.to
				? /* translators: %s: a REST address. */
				  sprintf( __( 'Closed to visitors not signed in: %s', 'bettershield' ), row.name )
				: /* translators: %s: a REST address. */
				  sprintf( __( 'Watched before closing: %s', 'bettershield' ), row.name ),
		label: () => __( 'Open Again', 'bettershield' ),
		/* translators: %s: a REST address. */
		consequence: ( row ) => sprintf( __( 'Anyone can read %s again.', 'bettershield' ), row.name ),
		/* translators: %s: a REST address. */
		done: ( row ) => sprintf( __( 'Anyone can read %s again.', 'bettershield' ), row.name ),
		busy: 'rest-route-undo',
	},
	content_links: {
		line: ( row ) =>
			sprintf(
				/* translators: %d: how many published posts. */
				_n( 'Links in %d post changed to https://', 'Links in %d posts changed to https://', Number( row.to ), 'bettershield' ),
				Number( row.to )
			),
		label: () => __( 'Undo', 'bettershield' ),
		consequence: () => __( 'Each post goes back to its http:// links, as it was. A post edited since is left as it is.', 'bettershield' ),
		done: ( row, answer ) => {
			const skipped = ( answer && answer.run && answer.run.skipped ) || [];

			return skipped.length
				? sprintf(
						/* translators: %d: how many posts were left as they are. */
						_n(
							'The rewritten posts are back as they were, except %d edited since, left as it is.',
							'The rewritten posts are back as they were, except %d edited since, left as they are.',
							skipped.length,
							'bettershield'
						),
						skipped.length
				  )
				: __( 'The rewritten posts are back as they were.', 'bettershield' );
		},
		busy: 'content-links',
	},
	two_factor_import: {
		line: ( row ) =>
			sprintf(
				/* translators: 1: how many accounts, 2: a plugin's name. */
				_n( 'Two-factor brought over for %1$s account from %2$s', 'Two-factor brought over for %1$s accounts from %2$s', Number( row.to ), 'bettershield' ),
				Number( row.to ),
				row.name
			),
		label: () => __( 'Undo', 'bettershield' ),
		/* translators: 1: the plugin's own name, e.g. BetterShield, 2: another plugin's name. */
		consequence: ( row ) => sprintf( __( 'Those accounts stop asking for a %1$s code and sign in with only their password, unless %2$s is turned back on. An account set up again since keeps its own.', 'bettershield' ), brand(), row.name ),
		done: () => __( 'The two-factor brought over is taken back.', 'bettershield' ),
		busy: 'two-factor-import',
	},
	quarantine_seal: {
		line: () => __( 'Quarantine folder sealed from visitors', 'bettershield' ),
		label: () => __( 'Undo', 'bettershield' ),
		consequence: () => __( 'The seal comes off, so visitors may be able to open files in the quarantine folder again.', 'bettershield' ),
		done: () => __( 'The quarantine folder’s seal is off.', 'bettershield' ),
		busy: 'quarantine-seal',
	},
	password_hold: {
		/* translators: %s: a username. */
		line: ( row ) => sprintf( __( 'New password asked of %s', 'bettershield' ), row.name ),
		label: () => __( 'Undo', 'bettershield' ),
		/* translators: %s: a username. */
		consequence: ( row ) => sprintf( __( '%s signs in with the current password again. The reset email already sent still works.', 'bettershield' ), row.name ),
		/* translators: %s: a username. */
		done: ( row ) => sprintf( __( '%s signs in with the current password again.', 'bettershield' ), row.name ),
		busy: 'weak-passwords',
	},
};

/**
 * @param {Object}   props
 * @param {Array}    props.rows    The ways back still open, from the listing.
 * @param {Function} props.onDone  Reads the listing again after one is used.
 */
export default function FixUndos( { rows, onDone } ) {
	const { undoPluginUpdate, putBackExtension, restoreConfig, undoAdminRename, undoCronRemoval, restoreFolder, undoNewPassword, reopenRestRoute, undoContentLinks, unsealQuarantine, undoTwoFactorImport, busy } =
		useStore();
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const known = ( rows || [] ).filter( ( row ) => KINDS[ row.kind ] );

	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	if ( ! known.length && ! said ) {
		return null;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const press = ( row ) => {
		const kind = KINDS[ row.kind ];
		const then = ( answer ) => {
			if ( answer ) {
				say( 'success', kind.done( row, answer ) );
				onDone();
			}
		};
		const refused = ( error ) => {
			say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

			return true;
		};

		setSaid( null );

		if ( 'plugin_update' === row.kind ) {
			undoPluginUpdate( 'plugin_updates_available', row.token, then, refused );
		} else if ( 'config_mode' === row.kind ) {
			restoreConfig( row.token, then, refused );
		} else if ( 'admin_rename' === row.kind ) {
			undoAdminRename( row.token, then, refused );
		} else if ( 'scheduled_events' === row.kind ) {
			undoCronRemoval( row.token, then, refused );
		} else if ( 'folder_mode' === row.kind ) {
			restoreFolder( row.token, then, refused );
		} else if ( 'password_hold' === row.kind ) {
			undoNewPassword( row.token, then, refused );
		} else if ( 'rest_route' === row.kind ) {
			reopenRestRoute( row.token, then, refused );
		} else if ( 'content_links' === row.kind ) {
			// One batch per call, as the finding's own Undo runs: the next
			// until the run says every post is back.
			const batch = () =>
				undoContentLinks( ( answer ) => {
					if ( answer && answer.run && ! answer.run.undone ) {
						// The shared layer lets go of one action after its
						// callbacks run, so the next batch waits for that.
						window.setTimeout( batch, 0 );

						return;
					}

					then( answer );
				}, refused );

			batch();
		} else if ( 'quarantine_seal' === row.kind ) {
			unsealQuarantine( row.token, then, refused );
		} else if ( 'two_factor_import' === row.kind ) {
			undoTwoFactorImport( row.token, then, refused );
		} else {
			putBackExtension( row.token, then, refused );
		}
	};

	const name = __( 'Fixes and Setup Changes', 'bettershield' );

	return (
		<>
			<h3 className="bs-ds-observed__head">{ name }</h3>
			<p className="bs-ds-fixundos__about">{ __( 'Changes made from a finding’s Fix or in Quick Setup, kept here after the finding closes.', 'bettershield' ) }</p>
			{ known.length ? (
				<Table label={ name } head={ false } columns={ [ { key: 'change', label: name } ] }>
					{ known.map( ( row ) => {
						const kind = KINDS[ row.kind ];

						return (
							<Row key={ row.token }>
								<Cell>
									<span>{ kind.line( row ) }</span>
									{ row.blocked ? (
										<span className="bs-ds-observed__note">{ row.blocked }</span>
									) : (
										<Armed
											label={ kind.label() }
											aria-label={ `${ kind.label() }: ${ kind.line( row ) }` }
											consequence={ kind.consequence( row ) }
											confirm={ __( 'Yes, Put It Back', 'bettershield' ) }
											busy={ isWorking( busy, kind.busy ) }
											disabled={ Boolean( busy ) }
											onConfirm={ () => press( row ) }
										/>
									) }
								</Cell>
							</Row>
						);
					} ) }
				</Table>
			) : null }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
		</>
	);
}
