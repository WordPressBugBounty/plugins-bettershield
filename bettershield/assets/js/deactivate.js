/**
 * Why BetterShield is being switched off, asked on the Plugins screen.
 *
 * Deliberately not the admin app: this runs on core's Plugins screen, and it
 * is enqueued only where the deactivation report the owner agreed to share
 * will carry the answer. Plain DOM over a native dialog, which gives Escape,
 * a modal backdrop and a focus that stays inside without any of it being
 * rebuilt here.
 *
 * Send saves the answer, then follows the Deactivate link. Skip follows it
 * without saving. Close and Escape leave the plugin active and put focus back
 * on the link. A save that fails still deactivates: the person asked to
 * switch the plugin off, and a reason that could not be kept is not a reason
 * to refuse that.
 */

import apiFetch from '@wordpress/api-fetch';
import { __, sprintf } from '@wordpress/i18n';

import '../css/tokens.css';
import './deactivate.css';

const config = window.bettershieldDeactivate || {};

// The reasons, in the order the old form gave them. The keys are what the
// site stores; the report carries the site's own English wording for each.
const REASONS = [
	{ key: 'no_longer_needed', label: __( 'I no longer need the plugin', 'bettershield' ) },
	{ key: 'found_better', label: __( 'I found a better plugin', 'bettershield' ), details: __( 'Which plugin?', 'bettershield' ) },
	{ key: 'not_working', label: __( 'I couldn’t get the plugin to work', 'bettershield' ) },
	{ key: 'temporary', label: __( 'It’s a temporary deactivation', 'bettershield' ) },
	{ key: 'other', label: __( 'Other', 'bettershield' ), details: __( 'What happened?', 'bettershield' ), long: true },
];

// The most the site keeps of the few words, in characters.
const DETAILS_MAX = 200;

const el = ( tag, attributes = {}, children = [] ) => {
	const node = document.createElement( tag );

	Object.entries( attributes ).forEach( ( [ name, value ] ) => {
		if ( 'text' === name ) {
			node.textContent = value;
		} else if ( false !== value && null !== value && undefined !== value ) {
			node.setAttribute( name, true === value ? '' : value );
		}
	} );

	children.filter( Boolean ).forEach( ( child ) => node.appendChild( child ) );

	return node;
};

/**
 * The Deactivate link on this plugin's own row, on a site's Plugins screen
 * or the network's.
 *
 * @return {?HTMLAnchorElement} The link, or null where the row has none.
 */
function deactivateLink() {
	if ( ! config.plugin ) {
		return null;
	}

	const row = Array.from( document.querySelectorAll( 'tr[data-plugin]' ) ).find( ( node ) => node.getAttribute( 'data-plugin' ) === config.plugin );

	return row ? row.querySelector( '.row-actions .deactivate a' ) : null;
}

/**
 * The dialog, built once.
 *
 * @param {HTMLAnchorElement} link The Deactivate link it stands in front of.
 * @return {HTMLDialogElement} The dialog.
 */
function build( link ) {
	const name = config.name || 'BetterShield';
	const fields = {};

	const options = REASONS.map( ( reason ) => {
		const id = `bettershield-deactivate-${ reason.key }`;
		const radio = el( 'input', { type: 'radio', name: 'bettershield-deactivate-reason', id, value: reason.key } );
		let extra = null;

		if ( reason.details ) {
			const fieldId = `${ id }-details`;

			extra = el( reason.long ? 'textarea' : 'input', {
				id: fieldId,
				class: 'bs-deactivate__details',
				maxlength: String( DETAILS_MAX ),
				rows: reason.long ? '2' : null,
				type: reason.long ? null : 'text',
				'aria-label': reason.details,
				placeholder: reason.details,
				hidden: true,
			} );
			fields[ reason.key ] = extra;
		}

		return el( 'li', {}, [ el( 'label', { for: id }, [ radio, el( 'span', { text: reason.label } ) ] ), extra ] );
	} );

	const heading = el( 'h2', {
		id: 'bettershield-deactivate-title',
		class: 'bs-deactivate__title',
		/* translators: %s: the plugin's name. */
		text: sprintf( __( 'Why are you deactivating %s?', 'bettershield' ), name ),
	} );
	const lead = el( 'p', {
		id: 'bettershield-deactivate-lead',
		class: 'bs-deactivate__lead',
		text: __( 'Your answer is sent once, with the usage data you already agreed to share. Choose Skip to send no reason.', 'bettershield' ),
	} );
	const list = el( 'fieldset', { class: 'bs-deactivate__reasons' }, [
		el( 'legend', { class: 'screen-reader-text', text: __( 'Reason', 'bettershield' ) } ),
		el( 'ul', {}, options ),
	] );
	const status = el( 'p', { class: 'bs-deactivate__status', role: 'status' } );
	const send = el( 'button', { type: 'button', class: 'button button-primary', text: __( 'Send and Deactivate', 'bettershield' ), disabled: true } );
	const skip = el( 'button', { type: 'button', class: 'button', text: __( 'Skip and Deactivate', 'bettershield' ) } );
	const close = el( 'button', {
		type: 'button',
		class: 'bs-deactivate__close',
		'aria-label': __( 'Close, keep the plugin active', 'bettershield' ),
	} );

	close.appendChild( el( 'span', { 'aria-hidden': 'true', text: '×' } ) );

	const dialog = el(
		'dialog',
		{ class: 'bs-deactivate', 'aria-labelledby': heading.id, 'aria-describedby': lead.id },
		[ close, heading, lead, list, status, el( 'div', { class: 'bs-deactivate__actions' }, [ send, skip ] ) ]
	);

	const chosen = () => {
		const radio = dialog.querySelector( 'input[name="bettershield-deactivate-reason"]:checked' );

		return radio ? radio.value : '';
	};

	// The few-words field shows under the reason that takes it, and only
	// there; Send waits until a reason is picked.
	list.addEventListener( 'change', () => {
		const key = chosen();

		Object.entries( fields ).forEach( ( [ reason, field ] ) => {
			field.hidden = reason !== key;
		} );

		send.disabled = '' === key;
	} );

	const leave = () => {
		window.location.href = link.href;
	};

	skip.addEventListener( 'click', leave );
	close.addEventListener( 'click', () => dialog.close() );

	send.addEventListener( 'click', () => {
		const key = chosen();

		if ( '' === key ) {
			return;
		}

		send.disabled = true;
		skip.disabled = true;
		status.textContent = __( 'Sending…', 'bettershield' );

		apiFetch( {
			path: '/bettershield/v1/usage/deactivation-reason',
			method: 'POST',
			data: { reason: key, details: fields[ key ] ? fields[ key ].value.slice( 0, DETAILS_MAX ) : '' },
		} )
			.catch( () => null )
			.then( leave );
	} );

	// Closed by the button or by Escape: nothing changes, and focus goes back
	// to the link that opened it.
	dialog.addEventListener( 'close', () => link.focus() );

	document.body.appendChild( dialog );

	return dialog;
}

const link = deactivateLink();

if ( link && 'function' === typeof window.HTMLDialogElement ) {
	let dialog = null;

	link.addEventListener( 'click', ( event ) => {
		event.preventDefault();

		dialog = dialog || build( link );
		dialog.showModal();
		dialog.querySelector( 'input[type="radio"]' ).focus();
	} );
}
