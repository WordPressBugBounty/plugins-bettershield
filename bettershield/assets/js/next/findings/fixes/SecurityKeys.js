/**
 * Fix for "The secret keys in wp-config.php are missing or unchanged"
 * (#2208).
 *
 * Eight new key and salt lines, made in this browser and shown only here,
 * to paste over the eight in wp-config.php. They become the site's
 * credentials once installed, so they never leave the page: no request
 * carries them, nothing stores them, and they go when the panel closes.
 * Nothing here edits the file, so there is nothing to undo; Check again
 * audits afresh once the owner has replaced the lines.
 */

import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

/** The eight constants, in wp-config-sample.php's order. */
export const KEYS = [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ];

/*
 * Printable characters less the quote, the backslash and the space, so a
 * value cannot end the single-quoted PHP string it is pasted into.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~';

const LENGTH = 64;

/**
 * One value from the browser's own generator. Bytes past the last whole
 * multiple of the alphabet are drawn again, so no character is likelier.
 *
 * @return {string} A value.
 */
export function generateValue() {
	const limit = 256 - ( 256 % ALPHABET.length );
	let value = '';

	while ( value.length < LENGTH ) {
		const bytes = new Uint8Array( LENGTH );

		window.crypto.getRandomValues( bytes );

		for ( const byte of bytes ) {
			if ( byte < limit && value.length < LENGTH ) {
				value += ALPHABET[ byte % ALPHABET.length ];
			}
		}
	}

	return value;
}

/**
 * The eight define() lines, aligned as wp-config-sample.php writes them.
 *
 * @return {string} The lines.
 */
export function generateLines() {
	return KEYS.map( ( name ) => `define( '${ name }',${ ' '.repeat( 17 - name.length ) }'${ generateValue() }' );` ).join( '\n' );
}

export default function SecurityKeys( { finding } ) {
	const { runAudit, busy } = useStore();
	// Held here alone: closing the panel or leaving the screen unmounts it,
	// and the lines go with it.
	const [ lines, setLines ] = useState( '' );
	const [ still, setStill ] = useState( null );
	const shared = false !== ( window.bettershield?.can || {} ).shared_config;
	const supported = Boolean( window.crypto && window.crypto.getRandomValues );
	const checking = isWorking( busy, 'audit' );

	if ( ! shared ) {
		return <p className="bs-ds-fix__text">{ __( 'On a network, every site shares wp-config.php. A network administrator replaces these lines.', 'bettershield' ) }</p>;
	}

	const generate = () => {
		setLines( generateLines() );
		setStill( null );
		announce( __( 'Your new security keys are ready to copy. They’re made in this browser, sent nowhere and shown only once.', 'bettershield' ) );
	};

	const checkAgain = () =>
		Promise.resolve( runAudit() ).then( ( data ) => {
			if ( ! data ) {
				return;
			}

			const open = ( data.findings || [] ).some( ( row ) => finding.id === row.id );

			setStill( open );
			announce( open ? __( 'The keys still read as missing or unchanged.', 'bettershield' ) : __( 'The keys now read as strong.', 'bettershield' ) );
		} );

	return (
		<>
			<Alert layout="default" tone="warning" desc={ __( 'Replacing these lines signs everyone out, you included. Each person signs in again once.', 'bettershield' ) } />
			{ lines ? (
				<>
					<p className="bs-ds-fix__text">
						{ __( 'In wp-config.php, replace the eight lines that start with AUTH_KEY through NONCE_SALT with these. Your host’s file manager can open the file.', 'bettershield' ) }
					</p>
					<CopyField multiline label={ __( 'New security keys', 'bettershield' ) } value={ lines } copyLabel={ __( 'Copy Lines', 'bettershield' ) } />
				</>
			) : null }
			{ ! supported ? <p className="bs-ds-fix__text">{ __( 'This browser can’t create the keys. Try another browser, or use WordPress.org’s key generator.', 'bettershield' ) }</p> : null }
			{ false === still ? <p className="bs-ds-fix__text">{ __( 'The keys now read as strong.', 'bettershield' ) }</p> : null }
			{ true === still ? <p className="bs-ds-fix__note">{ __( 'The keys still look weak. Check that you saved the right wp-config.php file.', 'bettershield' ) }</p> : null }
			<div className="bs-ds-fix__actions">
				{ supported ? (
					<Button type={ lines ? 'secondary' : 'primary' } size="sm" onClick={ generate }>
						{ lines ? __( 'Generate Again', 'bettershield' ) : __( 'Create New Keys', 'bettershield' ) }
					</Button>
				) : null }
				<Button type="secondary" size="sm" isBusy={ checking } disabled={ checking } onClick={ checkAgain }>
					{ __( 'Check Again', 'bettershield' ) }
				</Button>
			</div>
		</>
	);
}

// The lines are replaced by hand: nothing here changes the site.
SecurityKeys.kind = 'guidance';
