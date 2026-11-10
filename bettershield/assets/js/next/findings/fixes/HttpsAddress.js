/**
 * Fix for "The site address is not HTTPS" (#1289).
 *
 * Check HTTPS asks the site for its own front page over HTTPS, checking the
 * certificate, the way Site Health does. Switch to HTTPS changes both
 * addresses after the recovery pre-flight the store already asks for, and
 * the switch then waits: unless Keep HTTPS is pressed on this screen opened
 * over HTTPS within five minutes, both addresses go back to http on their
 * own. Keep HTTPS is offered only over HTTPS, because that page loading is
 * the proof.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';

const PATH = '/bettershield/v1/findings/site_not_https/address';

/**
 * This screen's own address over HTTPS, where Keep HTTPS can be pressed.
 *
 * @return {string} The address.
 */
function overHttps() {
	return window.location.href.replace( /^http:/, 'https:' );
}

export default function HttpsAddress() {
	const { switchToHttps, keepHttps, undoHttps, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ check, setCheck ] = useState( null );
	const [ checking, setChecking ] = useState( false );

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

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The site address could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the site address…', 'bettershield' ) }</p>;
	}

	const working = isWorking( busy, 'https-address' );
	const pending = state.switched && state.pending_until;

	const runCheck = () => {
		setChecking( true );
		apiFetch( { path: '/bettershield/v1/findings/site_not_https/address/check', method: 'POST' } )
			.then(
				( answer ) => {
					setCheck( answer );
					announce( answer.ready ? __( 'The site answers over HTTPS with a trusted certificate.', 'bettershield' ) : __( 'The HTTPS check did not pass.', 'bettershield' ) );
				},
				( error ) => setCheck( { ready: false, problems: [ error.message || __( 'The check could not run. Try again.', 'bettershield' ) ] } )
			)
			.finally( () => setChecking( false ) );
	};

	const switchNow = () =>
		switchToHttps( ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setState( answer.state );
			announce( __( 'The site address is HTTPS for now. Open this screen over HTTPS and press Keep HTTPS within 5 minutes.', 'bettershield' ) );
		} );

	const keep = () =>
		keepHttps( ( answer ) => {
			if ( answer ) {
				setState( answer.state );
				announce( __( 'HTTPS is kept.', 'bettershield' ) );
			}
		} );

	const undo = () =>
		undoHttps( ( answer ) => {
			if ( answer ) {
				setState( answer.state );
				setCheck( null );
				announce( __( 'Your site is back on http.', 'bettershield' ) );
			}
		} );

	// Switched and waiting: Keep HTTPS over HTTPS, or the way there.
	if ( pending ) {
		return (
			<>
				<Alert
					layout="default"
					tone="warning"
					live
					desc={ sprintf(
						/* translators: %s: a date and time. */
						__( 'Your site is on https for now. Press Keep HTTPS before %s, or it switches back to http.', 'bettershield' ),
						formatTime( state.pending_until )
					) }
				/>
				{ state.over_https ? (
					<p className="bs-ds-fix__text">{ __( 'This screen loaded over HTTPS, so the new address works in your browser.', 'bettershield' ) }</p>
				) : (
					<p className="bs-ds-fix__text">{ __( 'You’re still viewing this page over http. Open it with https:// and press Keep HTTPS there. You may need to sign in again.', 'bettershield' ) }</p>
				) }
				<div className="bs-ds-fix__actions">
					{ state.over_https ? (
						<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ keep }>
							{ __( 'Keep HTTPS', 'bettershield' ) }
						</Button>
					) : (
						<Button type="primary" size="sm" href={ overHttps() }>
							{ __( 'Open This Screen Over HTTPS', 'bettershield' ) }
						</Button>
					) }
					<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ undo }>
						{ __( 'Go Back to HTTP Now', 'bettershield' ) }
					</Button>
				</div>
			</>
		);
	}

	// Switched and kept: the way back, asked first.
	if ( state.switched ) {
		return (
			<>
				<p className="bs-ds-fix__text">{ __( 'Your site now uses HTTPS.', 'bettershield' ) }</p>
				<div className="bs-ds-fix__actions">
					<Armed
						type="secondary"
						label={ __( 'Undo the Switch', 'bettershield' ) }
						consequence={ __( 'Your site goes back to http, and passwords are sent unencrypted again.', 'bettershield' ) }
						confirm={ __( 'Yes, Go Back to HTTP', 'bettershield' ) }
						busy={ working }
						onConfirm={ undo }
					/>
				</div>
			</>
		);
	}

	if ( ! state.available ) {
		return <p className="bs-ds-fix__text">{ state.note }</p>;
	}

	return (
		<>
			<p className="bs-ds-fix__text">
				{ sprintf(
					/* translators: %s: the site address. */
					__( 'Your site address is %s. First check that your site works with https, then switch.', 'bettershield' ),
					state.address
				) }
			</p>
			{ check && check.ready ? <Alert layout="default" tone="success" desc={ __( 'The site answers over HTTPS with a trusted certificate.', 'bettershield' ) } /> : null }
			{ check && ! check.ready ? (
				<Alert layout="default" tone="error" desc={ check.problems.join( ' ' ) } />
			) : null }
			<p className="bs-ds-fix__note">{ __( 'After switching, open this page with https:// and press Keep HTTPS within 5 minutes. If you don’t, your site switches back to http automatically, so you can’t get locked out.', 'bettershield' ) }</p>
			<div className="bs-ds-fix__actions">
				<Button type={ check && check.ready ? 'secondary' : 'primary' } size="sm" isBusy={ checking } disabled={ checking || working } onClick={ runCheck }>
					{ check ? __( 'Check Again', 'bettershield' ) : __( 'Check HTTPS', 'bettershield' ) }
				</Button>
				{ check && check.ready ? (
					<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ switchNow }>
						{ __( 'Switch to HTTPS', 'bettershield' ) }
					</Button>
				) : null }
			</div>
		</>
	);
}

HttpsAddress.kind = 'acts';
