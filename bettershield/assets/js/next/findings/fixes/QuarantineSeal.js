/**
 * Fix for "Quarantined files are not blocked from the web" (#2207).
 *
 * Where this server reads the folder's own rule, the seal is written for the
 * owner, read back, and can be undone. Where it does not, the exact rule for
 * this server and this folder is handed over to paste into its
 * configuration. Either way Check again asks the server in the background,
 * and the finding closes only when the audit after it sees the folder
 * refused: a pasted rule is never taken on trust.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

export default function QuarantineSeal() {
	const { sealQuarantine, unsealQuarantine, checkQuarantineAgain, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	// The undo handle of a seal written from here, while it stands.
	const [ sealed, setSealed ] = useState( null );
	const [ undone, setUndone ] = useState( false );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/findings/quarantine_unsealed/seal' } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'This server’s details could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading this server…', 'bettershield' ) }</p>;
	}

	const sealing = isWorking( busy, 'quarantine-seal' );
	const checking = isWorking( busy, 'quarantine-check' ) || state.checking;

	let body;

	if ( sealed ) {
		body = (
			<Alert
				layout="default"
				tone="success"
				live
				desc={ __( 'Done. The quarantine folder is now blocked from the web.', 'bettershield' ) }
				actions={
					<Button type="secondary" size="sm" isBusy={ sealing } disabled={ sealing } onClick={ () =>
							unsealQuarantine( sealed, () => {
								setSealed( null );
								setUndone( true );
								announce( __( 'Undone. The quarantine folder is no longer blocked.', 'bettershield' ) );
							} )
						}>
						{ __( 'Undo', 'bettershield' ) }
					</Button>
				}
			/>
		);
	} else if ( state.repair ) {
		body = (
			<>
				<p className="bs-ds-fix__text">{ __( 'BetterShield can block this folder from the web for you, and you can undo it.', 'bettershield' ) }</p>
				<div className="bs-ds-fix__actions">
					<Button type="primary" size="sm" isBusy={ sealing } disabled={ sealing } onClick={ () =>
							sealQuarantine( ( answer ) => {
								if ( answer && answer.undo ) {
									setSealed( answer.undo );
									setUndone( false );
									announce( __( 'The quarantine folder is blocked from the web.', 'bettershield' ) );
								}
							} )
						}>
						{ __( 'Block the Folder', 'bettershield' ) }
					</Button>
				</div>
			</>
		);
	} else if ( state.custom ) {
		body = <p className="bs-ds-fix__text">{ __( 'The folder has rules of its own, so BetterShield leaves them alone. Make sure they refuse every file in it.', 'bettershield' ) }</p>;
	} else if ( state.rule ) {
		body = (
			<>
				<p className="bs-ds-fix__text">
					{ sprintf(
						/* translators: 1: a web server's name, e.g. "nginx"; 2: where the rule goes. */
						__( 'Your %1$s server needs a setting added by your host. Send them this rule: %2$s', 'bettershield' ),
						state.rule.server,
						state.rule.where
					) }
				</p>
				<CopyField multiline label={ __( 'Rule for your host', 'bettershield' ) } value={ state.rule.rule } copyLabel={ __( 'Copy Rule', 'bettershield' ) } />
				<p className="bs-ds-fix__note">{ __( 'It only blocks the quarantine folder.', 'bettershield' ) }</p>
			</>
		);
	} else {
		body = <p className="bs-ds-fix__text">{ __( 'We couldn’t tell which server your site runs on. Ask your host to block web access to this folder.', 'bettershield' ) }</p>;
	}

	return (
		<>
			<p className="bs-ds-fix__text">
				{ sprintf(
					/* translators: 1: the folder, from the site's root; 2: the web server's name. */
					__( 'Folder: %1$s · Server: %2$s', 'bettershield' ),
					state.folder,
					state.server
				) }
			</p>
			{ undone ? <Alert layout="default" tone="info" live desc={ __( 'Undone. The quarantine folder is no longer blocked.', 'bettershield' ) } /> : null }
			{ body }
			<div className="bs-ds-fix__actions">
				<Button type="secondary" size="sm" isBusy={ isWorking( busy, 'quarantine-check' ) } disabled={ checking } onClick={ () =>
						checkQuarantineAgain( ( answer ) => {
							if ( answer && answer.state ) {
								setState( answer.state );
								announce( __( 'The server will be asked again in the background.', 'bettershield' ) );
							}
						} )
					}>
					{ __( 'Check Again', 'bettershield' ) }
				</Button>
			</div>
			{ checking ? (
				<p className="bs-ds-fix__note" role="status">
					{ __( 'Asking the server in the background. The finding closes once the audit after it sees the folder refused.', 'bettershield' ) }
				</p>
			) : null }
		</>
	);
}

QuarantineSeal.kind = 'acts';
