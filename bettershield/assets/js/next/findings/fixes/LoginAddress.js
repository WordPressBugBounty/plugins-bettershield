/**
 * Fix for "Something published at the moved sign-in address is hidden by
 * the sign-in form" (#2210).
 *
 * The address now and what it hides, a new address checked by the item's
 * own rule, and Custom sign-in address, which moves it after the
 * session, the password and the recovery pre-flight the store already asks
 * for. The new address is shown once it is in place, to be kept off the
 * site. The content itself is never renamed or unpublished from here.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';
import Field from '../../ui/Field';

const PATH = '/bettershield/v1/findings/login_url_shadows_content/address';

/**
 * What the item's rule says about a typed address, or nothing where it fits.
 *
 * @param {string} value The address typed.
 * @param {Object} field The item's field.
 * @return {string} The problem, or an empty string.
 */
function problemWith( value, field ) {
	if ( '' === value || ! field.pattern ) {
		return '';
	}

	return new RegExp( field.pattern ).test( value.toLowerCase() ) ? '' : field.pattern_note;
}

export default function LoginAddress() {
	const { changeLoginAddress, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ slug, setSlug ] = useState( '' );
	const [ moved, setMoved ] = useState( '' );

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
		return <p className="bs-ds-fix__text">{ __( 'The sign-in address could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the sign-in address…', 'bettershield' ) }</p>;
	}

	const working = isWorking( busy, 'login-address' );
	const problem = problemWith( slug, state.field );
	const hidden = state.shadowed;

	const change = () =>
		changeLoginAddress( slug.toLowerCase(), ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setMoved( answer.address );
			setState( answer.state );
			setSlug( '' );
			announce( __( 'The sign-in address was changed. Keep the new one somewhere safe.', 'bettershield' ) );
		} );

	return (
		<>
			{ moved ? (
				<>
					<Alert layout="default" tone="success" live desc={ __( 'The sign-in address was changed, and the old one no longer answers. Keep the new one somewhere safe, off this site.', 'bettershield' ) } />
					<CopyField label={ __( 'New sign-in address', 'bettershield' ) } value={ moved } copyLabel={ __( 'Copy Address', 'bettershield' ) } />
					{ hidden ? <p className="bs-ds-fix__note">{ __( 'That address is already in use. Choose another.', 'bettershield' ) }</p> : null }
				</>
			) : null }
			{ ! moved && hidden ? (
				<p className="bs-ds-fix__text">
					{ hidden.content
						? sprintf(
								/* translators: 1: the sign-in address; 2: a title; 3: a content type, e.g. page. */
								__( 'The sign-in form at %1$s hides “%2$s” (%3$s).', 'bettershield' ),
								state.address,
								hidden.content,
								hidden.type
						  )
						: sprintf(
								/* translators: %s: the sign-in address. */
								__( 'Your sign-in page at %s is blocking one of your site’s pages.', 'bettershield' ),
								state.address
						  ) }
				</p>
			) : null }
			{ state.active && ( ! moved || hidden ) ? (
				<>
					<Field
						label={ state.field.label }
						help={ state.field.description }
						error={ problem }
						placeholder={ state.field.placeholder }
						value={ slug }
						onChange={ setSlug }
						disabled={ working }
					/>
					<p className="bs-ds-fix__note">{ __( 'Your current sign-in address stops working once you change it. The page keeps its address.', 'bettershield' ) }</p>
					<div className="bs-ds-fix__actions">
						<Button type="primary" size="sm" isBusy={ working } disabled={ working || '' === slug || Boolean( problem ) } onClick={ change }>
							{ __( 'Change the Sign-In Address', 'bettershield' ) }
						</Button>
						{ state.edit_url ? (
							<Button type="secondary" size="sm" href={ state.edit_url }>
								{ __( 'Edit the Hidden Content', 'bettershield' ) }
							</Button>
						) : null }
					</div>
				</>
			) : null }
		</>
	);
}

LoginAddress.kind = 'acts';
