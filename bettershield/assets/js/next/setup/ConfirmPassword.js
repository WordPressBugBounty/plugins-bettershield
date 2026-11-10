/**
 * The password, asked again before something is taken away.
 *
 * Only on a site whose owner switched that on, and only for the answers in
 * this setup that weaken something — trusting a proxy, handing sign-in limits
 * to another plugin, undoing a fix. The held write runs again the moment the
 * password is confirmed, and the prompt closes so the step's own control shows
 * it working; canceling drops it and changes nothing, even while the password
 * is still being checked.
 *
 * The dialog renders at the end of the document, outside the setup's root, so
 * its content carries the app's class itself: the design's field and buttons
 * are drawn under it.
 */

import './ConfirmPassword.css';

import { Modal } from '@wordpress/components';
import { useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import apiFetch from '@wordpress/api-fetch';
import Button from '../ui/Button';
import Field from '../ui/Field';
import { ROUTES } from './api';

/**
 * @param {Object}   props
 * @param {?Object}  props.held      The write waiting, with its `attempt`.
 * @param {Function} props.onDone    Called with the write's answer (or a promise of it), or null.
 * @param {Function} props.onFailure Called when the retried write fails.
 */
export default function ConfirmPassword( { held, onDone, onFailure } ) {
	const [ password, setPassword ] = useState( '' );
	const [ problem, setProblem ] = useState( '' );
	const [ checking, setChecking ] = useState( false );
	// The write the password is being checked for. Canceling clears it, and
	// an answer that arrives after that runs nothing.
	const pending = useRef( null );
	// Which check is the latest. A canceled one can answer after the next
	// has been sent, and only the latest may say the checking is over:
	// otherwise the button came back while a check was still out, and a
	// press sent the password again.
	const latest = useRef( 0 );

	if ( ! held ) {
		return null;
	}

	const cancel = () => {
		pending.current = null;
		latest.current += 1;
		setPassword( '' );
		setProblem( '' );
		setChecking( false );
		onDone( null );
	};

	const submit = () => {
		if ( checking || ! password ) {
			return;
		}

		const asked = held;
		latest.current += 1;
		const ticket = latest.current;

		pending.current = asked;
		setChecking( true );
		setProblem( '' );

		apiFetch( { path: ROUTES.confirmPassword, method: 'POST', data: { password } } )
			.then(
				() => {
					if ( pending.current !== asked ) {
						return;
					}

					pending.current = null;
					setPassword( '' );
					onDone(
						asked.attempt().catch( ( failure ) => {
							onFailure( failure );

							return null;
						} )
					);
				},
				( failure ) => {
					if ( pending.current === asked ) {
						setProblem( failure && failure.message ? failure.message : __( 'That did not work. Please try again.', 'bettershield' ) );
					}
				}
			)
			.finally( () => {
				if ( latest.current === ticket ) {
					setChecking( false );
				}
			} );
	};

	// Opened on the field rather than on the dialog's own frame, which left
	// the field two Tabs away, behind the close button.
	return (
		<Modal
			className="bs-ds-setup-dialog"
			title={ __( 'Confirm your password', 'bettershield' ) }
			onRequestClose={ cancel }
			size="small"
			focusOnMount="firstContentElement"
		>
			<div className="bs-ds-app bs-ds-setup-dialog__body">
				<p className="bs-ds-setup-dialog__text">
					{ __(
						'Changing a protection needs your password. You will not be asked again for a while.',
						'bettershield'
					) }
				</p>
				<Field
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
				{ problem ? (
					<p className="bs-ds-setup__problem" role="alert">
						{ problem }
					</p>
				) : null }
				<div className="bs-ds-setup-dialog__actions">
					{ /* Held, not disabled: a disabled button drops the keyboard
					     to the page body, out of reach of Escape, while the
					     password is checked. */ }
					<Button
						type="primary"
						size="md"
						isBusy={ checking }
						disabled={ checking || ! password }
						accessibleWhenDisabled
						onClick={ submit }
					>
						{ __( 'Confirm and Continue', 'bettershield' ) }
					</Button>
					<Button type="ghost" size="md" onClick={ cancel }>
						{ __( 'Cancel', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</Modal>
	);
}
