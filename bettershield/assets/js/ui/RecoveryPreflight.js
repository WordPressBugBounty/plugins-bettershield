/**
 * The recovery pre-flight's answer to a change to how people sign in.
 *
 * The change was held because the way back in is not proved: there is no
 * working recovery link or printed code, or nobody checked within the day.
 * Checking now clears the second and re-runs the change; going ahead anyway is
 * the second confirmation the route asks for, and it is recorded.
 */

import { Button, Modal } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useStore } from '../store';

export default function RecoveryPreflight() {
	const { preflight, checkRecoveryAndRetry, overridePreflight, cancelPreflight } = useStore();
	/*
	 * The check running and the error shown, each held with the pre-flight it
	 * belongs to. This stays mounted between pre-flights, so plain state
	 * carried a failed check's error into the next one, which opened
	 * announcing a failure nothing had checked; and a check answering after
	 * Cancel set its error, or held the buttons, on the next.
	 */
	const [ checkingFor, setCheckingFor ] = useState( null );
	const [ failed, setFailed ] = useState( null );

	if ( ! preflight ) {
		return null;
	}

	const checking = checkingFor === preflight;
	const error = failed && failed.preflight === preflight ? failed.message : null;

	const check = () => {
		const asked = preflight;

		setCheckingFor( asked );
		setFailed( null );

		checkRecoveryAndRetry()
			.catch( ( failure ) => {
				setFailed( {
					preflight: asked,
					message: failure && failure.message ? failure.message : __( 'The check did not complete. Try again in a minute.', 'bettershield' ),
				} );
			} )
			.finally( () => setCheckingFor( ( current ) => ( current === asked ? null : current ) ) );
	};

	const close = () => {
		setFailed( null );
		cancelPreflight();
	};

	return (
		<Modal className="bs-popover" title={ __( 'Check the way back in first', 'bettershield' ) } onRequestClose={ close } size="small">
			<p>{ preflight.message }</p>
			<p>
				{ __(
					'You can go ahead anyway. The activity log records it with the failed check.',
					'bettershield'
				) }
			</p>
			{ /* An alert, so a refusal is heard as it appears: a plain
			     paragraph told a screen-reader user nothing, the guessing
			     cap's message included. */ }
			{ error ? (
				<p className="bs-confirm__error" role="alert">
					{ error }
				</p>
			) : null }
			<div className="bs-confirm__actions">
				{ preflight.can_check_now ? (
					<Button variant="primary" isBusy={ checking } disabled={ checking } onClick={ check }>
						{ __( 'Check Now', 'bettershield' ) }
					</Button>
				) : null }
				{ ! preflight.can_check_now && preflight.url ? (
					<Button variant="primary" href={ preflight.url }>
						{ __( 'Open Recovery', 'bettershield' ) }
					</Button>
				) : null }
				<Button variant="secondary" disabled={ checking } onClick={ overridePreflight }>
					{ __( 'Go Ahead Anyway', 'bettershield' ) }
				</Button>
				<Button variant="tertiary" onClick={ close }>
					{ __( 'Cancel', 'bettershield' ) }
				</Button>
			</div>
		</Modal>
	);
}
