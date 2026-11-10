/**
 * The password-confirmation dialog.
 *
 * Shared by both dashboard bundles, so a change to it lands once.
 */

import { Button, Modal, TextControl } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useStore } from '../store';

/**
 * The password-confirmation dialog: the client half of the gate on actions
 * that remove protection. The store holds the action the gate refused;
 * proving the password here re-runs it, and canceling drops it. Errors the
 * route answers — a wrong password, the guessing cap — surface inside the
 * dialog, where the person who can act on them is looking.
 *
 * It opens on the field rather than on its own frame, which left the field
 * two Tabs away, behind the close button.
 */
export default function ConfirmPassword() {
	const { confirming, submitConfirmPassword, cancelConfirmPassword } = useStore();
	const [ password, setPassword ] = useState( '' );
	const [ error, setError ] = useState( null );
	const [ checking, setChecking ] = useState( false );

	if ( ! confirming ) {
		return null;
	}

	const submit = () => {
		if ( checking || ! password ) {
			return;
		}

		setChecking( true );
		setError( null );

		submitConfirmPassword( password )
			.then( () => setPassword( '' ) )
			.catch( ( failure ) => {
				setError( failure && failure.message ? failure.message : __( 'That did not work. Please try again.', 'bettershield' ) );
			} )
			.finally( () => setChecking( false ) );
	};

	const cancel = () => {
		setPassword( '' );
		setError( null );
		cancelConfirmPassword();
	};

	return (
		<Modal
			className="bs-popover"
			title={ __( 'Confirm your password', 'bettershield' ) }
			onRequestClose={ cancel }
			size="small"
			focusOnMount="firstContentElement"
		>
			<p>
				{ __(
					'This removes a protection, so enter your password. You will not be asked again for a while.',
					'bettershield'
				) }
			</p>
			<TextControl
				__nextHasNoMarginBottom
				__next40pxDefaultSize
				type="password"
				autoComplete="current-password"
				label={ __( 'Your password', 'bettershield' ) }
				value={ password }
				onChange={ setPassword }
				onKeyDown={ ( event ) => {
					if ( 'Enter' === event.key ) {
						event.preventDefault();
						submit();
					}
				} }
			/>
			{ /* An alert, so a refusal is heard as it appears: a plain
			     paragraph told a screen-reader user nothing, the guessing
			     cap's message included. */ }
			{ error ? (
				<p className="bs-confirm__error" role="alert">
					{ error }
				</p>
			) : null }
			<div className="bs-confirm__actions">
				{ /* Held, not disabled: a disabled button drops the keyboard
				     to the page body, out of reach of Escape, while the
				     password is checked. */ }
				<Button
					variant="primary"
					isBusy={ checking }
					disabled={ checking || ! password }
					accessibleWhenDisabled
					onClick={ submit }
				>
					{ __( 'Confirm and Continue', 'bettershield' ) }
				</Button>
				<Button variant="tertiary" onClick={ cancel }>
					{ __( 'Cancel', 'bettershield' ) }
				</Button>
			</div>
		</Modal>
	);
}
