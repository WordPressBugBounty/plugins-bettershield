/**
 * Two-factor enrollment and passkeys on the profile screen.
 *
 * Deliberately not the admin app: this runs on core's profile.php for
 * whoever the two-factor and passkey-only policies target — roles that cannot
 * open any screen the app is enqueued on. Plain DOM against the /two-factor
 * and /passkeys REST routes, which any signed-in session satisfies. No <form>
 * elements: this whole panel renders inside core's profile form, where a
 * nested form tag is dropped by the parser and its buttons submit the wrong
 * form.
 */

import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';

import { whenPhrase } from './ui/when';
import { copyToClipboard } from './ui/copy';
import { download } from './ui/download';
import { PROMPT_HINT_AFTER_MS, PROMPT_TIMEOUT_MS, promptClosedWords, promptHint, promptStoppedWords, promptWait } from './ui/passkey-prompt';
import '../css/tokens.css';
import './profile.css';

const holder = document.getElementById( 'bettershield-2fa-enroll' );
const resetHolder = document.getElementById( 'bettershield-2fa-admin-reset' );
const codesHolder = document.getElementById( 'bettershield-2fa-backup-codes' );
const passkeyHolder = document.getElementById( 'bettershield-passkeys-panel' );
const passkeyRemoveHolder = document.getElementById( 'bettershield-passkeys-admin-remove' );

/*
 * Turning two-factor on reloads the page, and focus started again at the top
 * of it (#1926). The reload is marked, and the section's heading takes focus.
 */
const ARMED_MARK = 'bettershield-2fa-armed';

try {
	if ( window.sessionStorage.getItem( ARMED_MARK ) ) {
		window.sessionStorage.removeItem( ARMED_MARK );

		const section = document.getElementById( 'bettershield-two-factor' );

		if ( section ) {
			section.tabIndex = -1;
			section.focus();
		}
	}
} catch ( e ) {}

/*
 * When each session was last active, said in the reader's time as the app's
 * screens say it: the server prints the site's own format, which read hours
 * apart from the same sign-in on Activity (#1934).
 */
document.querySelectorAll( 'time[data-bs-local][datetime]' ).forEach( ( node ) => {
	node.textContent = whenPhrase( node.getAttribute( 'datetime' ) );
} );

// The count at which the page warns that backup codes are nearly out.
const LOW_WATER = 3;

const el = ( tag, className, text ) => {
	const node = document.createElement( tag );
	if ( className ) {
		node.className = className;
	}
	if ( text ) {
		node.textContent = text;
	}
	return node;
};

/*
 * On a store's My Account tab the page belongs to the theme, which styles its
 * buttons through this class rather than core's admin `button`.
 */
const inStore = Boolean( document.querySelector( '.bs-store-account' ) );

const button = ( label, primary ) => {
	const node = el( 'button', ( primary ? 'button button-primary' : 'button' ) + ( inStore ? ' wp-element-button' : '' ), label );
	// Inside core's profile form a bare <button> submits the profile.
	node.type = 'button';
	return node;
};

/*
 * Fetched when a code is actually drawn. This script is enqueued on every
 * profile screen on the site, and the encoder is the bulk of it — for a step
 * most of those visits never reach. The manual entry key is printed beside the
 * code from the same secret, so a browser that cannot fetch the encoder can
 * still finish the enrollment.
 */
const qrSvg = ( uri ) =>
	import( /* webpackChunkName: "qrcode" */ 'qrcode-generator' ).then( ( module ) => {
		const qrcode = module.default || module;
		const qr = qrcode( 0, 'M' );

		qr.addData( uri );
		qr.make();

		return qr.createSvgTag( { cellSize: 4, margin: 0, scalable: true } );
	} );

/**
 * Adding or removing a passkey asks the holder to prove it is them: a current
 * code where two-factor is on, the password again where the site accepts one,
 * and one of the account's own passkeys otherwise. Draws what answers the
 * refusal and sends the request again with it.
 *
 * @return {boolean} Whether the refusal was a request for proof.
 */
function askForProof( error, into, retry ) {
	const code = error && error.code;

	if ( 'bettershield_confirm_password' === code ) {
		fail( error, into );
		askForPassword( into, () => retry( {} ) );

		return true;
	}

	if ( 'bettershield_confirm_passkey' === code ) {
		fail( error, into );
		askForPasskey( into, () => retry( {} ) );

		return true;
	}

	if ( 'bettershield_current_code_required' !== code && 'bettershield_wrong_code' !== code ) {
		return false;
	}

	fail( error, into );
	askForCode( into, retry );

	return true;
}

/**
 * The current-code field a passkey change needs where two-factor is on,
 * asked with the press when the account is known to need one (#2218), or
 * after a refusal that asks for it.
 *
 * @param {HTMLElement} into  Where it is drawn.
 * @param {Function}    retry Sends the change again, with the code.
 * @param {string}      ask   What to say first, when not after a refusal.
 */
function askForCode( into, retry, ask = '' ) {
	// One field at a time: a second refusal replaces the first one's.
	const previous = into.querySelector( '#bettershield-passkey-proof' );
	if ( previous && previous.parentNode ) {
		previous.parentNode.remove();
	}

	const row = el( 'p', 'bs-profile-2fa__row' );

	if ( ask ) {
		const said = el( 'span', 'description bs-profile-2fa__ask', ask );
		said.id = 'bettershield-passkey-proof-ask';
		row.append( said );
	}

	const label = el( 'label', '', __( 'Authenticator app code or backup code', 'bettershield' ) );
	label.setAttribute( 'for', 'bettershield-passkey-proof' );

	const field = el( 'input' );
	field.type = 'text';
	field.id = 'bettershield-passkey-proof';
	field.className = 'regular-text';
	field.autocomplete = 'one-time-code';

	const go = button( __( 'Confirm', 'bettershield' ), true );
	const cancel = button( __( 'Cancel', 'bettershield' ) );

	const submit = () => {
		if ( '' === field.value.trim() ) {
			field.focus();
			return;
		}

		row.remove();
		retry( { code: field.value.trim() } );
	};

	go.addEventListener( 'click', submit );
	cancel.addEventListener( 'click', () => row.remove() );
	field.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	if ( ask ) {
		field.setAttribute( 'aria-describedby', 'bettershield-passkey-proof-ask' );
	}

	row.append( label, field, go, cancel );
	into.append( row );
	field.focus();
}

/**
 * Starts a passkey change with the proof it needs: the code field first
 * where the account has two-factor on, so the first request carries it and
 * is not refused (#2218), and straight away otherwise.
 *
 * The line above the field says what the code is for, by the button
 * pressed: it repeated the field's label, and said "change" for an add.
 *
 * @param {Object}   state  The passkeys, as the server answers.
 * @param {Function} change Sends the change, with what proves it.
 * @param {string}   ask    What the code is asked for.
 */
function withCode( state, change, ask ) {
	if ( ! state.needs_code ) {
		change();

		return;
	}

	askForCode( passkeyHolder, change, ask );
}

/** Counts the error notes made, so each has an id of its own to point at. */
let notes = 0;

/*
 * A refusal is announced, and the fields beside it are described by it: it
 * was written into a bare paragraph, and focus going back to the field read
 * out the field's label and nothing about why.
 */
function fail( error, into = holder ) {
	let note = into.querySelector( '.bs-profile-2fa__error' );

	if ( ! note ) {
		note = into.insertBefore( el( 'p', 'bs-profile-2fa__error' ), into.firstChild );
		note.setAttribute( 'role', 'alert' );
		note.id = `bettershield-profile-error-${ ++notes }`;
	}

	note.textContent = error && error.message ? error.message : __( 'That did not work. Please try again.', 'bettershield' );
	into.querySelectorAll( 'input' ).forEach( ( input ) => input.setAttribute( 'aria-describedby', note.id ) );
}

/*
 * A panel redrawn in place takes the control that had focus with it, and
 * focus fell to the page. It goes to the line that says what happened.
 */
function announce( into, text ) {
	const line = el( 'p', 'bs-profile-2fa__said', text );

	line.setAttribute( 'role', 'status' );
	line.tabIndex = -1;
	into.insertBefore( line, into.firstChild );
	line.focus();
}

function clear( into = holder ) {
	into.textContent = '';
}

/**
 * The password gate, in plain DOM.
 *
 * Where the owner switched it on, an action that takes a protection away
 * answers with a code rather than doing the work — and that answer is a
 * request for a field, not a failure. Printed as an error it leaves the
 * sentence "confirm your password" on a screen with nowhere to type one, and
 * the button never works again. The admin app has a dialog for this; this
 * panel runs on core's profile screen and has to carry its own.
 *
 * @param {HTMLElement} into  Where to put the field.
 * @param {Function}    retry What to run once the password is accepted.
 */
function askForPassword( into, retry ) {
	// One row a panel: a second refusal replaces the first one's, as the code
	// field does, and the row's Confirm runs what was asked last. A row in
	// another panel on the same screen keeps its own, under an id of its own,
	// so every field is named by its label (#2032).
	const previous = into.querySelector( '.bs-profile-2fa__row--password' );
	if ( previous ) {
		previous.remove();
	}

	let id = 'bettershield-confirm-password';
	for ( let n = 2; document.getElementById( id ); n++ ) {
		id = `bettershield-confirm-password-${ n }`;
	}

	const row = el( 'p', 'bs-profile-2fa__row bs-profile-2fa__row--password' );

	const label = el( 'label', '', __( 'Confirm your password', 'bettershield' ) );
	label.setAttribute( 'for', id );

	const field = el( 'input' );
	field.type = 'password';
	field.id = id;
	field.className = 'regular-text';
	field.autocomplete = 'current-password';

	const go = button( __( 'Confirm', 'bettershield' ), true );
	const cancel = button( __( 'Cancel', 'bettershield' ) );

	const submit = () => {
		// Enter reaches here past a disabled button, so it asks the button.
		if ( go.disabled ) {
			return;
		}

		go.disabled = true;

		apiFetch( { path: '/bettershield/v1/confirm-password', method: 'POST', data: { password: field.value } } )
			.then( () => {
				row.remove();
				retry();
			} )
			.catch( ( error ) => {
				go.disabled = false;
				fail( error, into );
				field.focus();
			} );
	};

	go.addEventListener( 'click', submit );
	cancel.addEventListener( 'click', () => row.remove() );
	field.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	row.append( label, field, go, cancel );
	into.append( row );
	field.focus();
}

/**
 * The passkey gate, in plain DOM. An account with no password the site
 * accepts and no second factor proves it holds the account with one of its
 * own passkeys. The device is asked on a press of the button rather than at
 * once, because a browser asks for a passkey only in answer to something the
 * person did.
 *
 * @param {HTMLElement} into  Where to put the button.
 * @param {Function}    retry What to run once the passkey is accepted.
 */
function askForPasskey( into, retry ) {
	const row = el( 'p', 'bs-profile-2fa__row' );
	const go = button( __( 'Use a Passkey', 'bettershield' ), true );
	const cancel = button( __( 'Cancel', 'bettershield' ) );

	go.addEventListener( 'click', () => {
		if ( go.disabled ) {
			return;
		}

		go.disabled = true;

		confirmWithPasskey()
			.then( () => {
				row.remove();
				retry();
			} )
			.catch( ( error ) => {
				go.disabled = false;
				fail(
					error && typeof error.code === 'string' && error.message
						? error
						: { message: __( 'Your device did not confirm it is you. Nothing was changed.', 'bettershield' ) },
					into
				);
			} );
	} );
	cancel.addEventListener( 'click', () => row.remove() );

	row.append( go, cancel );
	into.append( row );
	go.focus();
}

/*
 * A copy button that says whether it copied, as the admin screens' do: a key
 * or a set of codes the person believes they copied and did not is a way in
 * they lack (#2067).
 */
function copyButton( label, text ) {
	const copy = button( label );

	copy.addEventListener( 'click', () =>
		copyToClipboard( text ).then(
			() => {
				copy.textContent = __( 'Copied', 'bettershield' );
			},
			() => {
				copy.textContent = __( 'Copying failed. Select it and copy it yourself.', 'bettershield' );
			}
		)
	);

	return copy;
}

/*
 * Ways to keep backup codes that are on screen once, as Protect > Two-factor
 * offers them: copied, or saved as the same file (#2067).
 */
function keepButtons( codes ) {
	const save = button( __( 'Download Codes', 'bettershield' ) );

	save.addEventListener( 'click', () =>
		download(
			'backup-codes.txt',
			sprintf(
				/* translators: %s: the site's host name. */
				__( 'Two-factor backup codes for %s', 'bettershield' ),
				window.location.hostname
			) +
				'\n' +
				__( 'Use each code once, in place of the code from your authenticator app.', 'bettershield' ) +
				'\n\n' +
				codes.join( '\n' ) +
				'\n'
		)
	);

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( copyButton( __( 'Copy Codes', 'bettershield' ), codes.join( '\n' ) ), save );

	return row;
}

/* ---- step 1: the offer ---------------------------------------------------- */

function offer() {
	clear();

	const start = button( __( 'Set Up Two-Factor', 'bettershield' ), true );
	start.addEventListener( 'click', () => {
		start.disabled = true;
		apiFetch( { path: '/bettershield/v1/two-factor/start', method: 'POST', data: {} } )
			.then( scan )
			.catch( ( error ) => {
				start.disabled = false;
				fail( error );
			} );
	} );

	holder.append( start );

	return start;
}

/* ---- step 2: scan and confirm --------------------------------------------- */

/*
 * The key in groups of four, as the printed backup codes are grouped. A short
 * remainder joins the group before it, so the key never ends on a lone
 * character (#2172).
 */
function keyGroups( secret ) {
	const groups = String( secret ).match( /.{1,4}/g ) || [];

	if ( groups.length > 1 && groups[ groups.length - 1 ].length < 4 ) {
		groups[ groups.length - 2 ] += groups.pop();
	}

	return groups;
}

function scan( { secret, uri } ) {
	clear();

	holder.append( el( 'p', '', __( 'In your authenticator app, scan this code or type the key, then enter the six-digit code it shows.', 'bettershield' ) ) );

	const qr = el( 'div', 'bs-profile-2fa__qr' );
	holder.append( qr );
	qrSvg( uri ).then( ( svg ) => {
		qr.innerHTML = svg;
	} ).catch( () => {} );

	/*
	 * At phone width the key shared a line with Copy key and broke wherever it
	 * ran out of room, leaving its last character alone beside the button,
	 * easy to miss when typing it in. It is drawn on its own line in groups of
	 * four that never break inside, and Copy key comes after it. The groups are
	 * spaced by the stylesheet, not by spaces, so the key selected by hand and
	 * the one Copy key copies are both the bare key (#2172).
	 */
	const key = el( 'p', 'bs-profile-2fa__key', __( 'Can’t scan the code? Type this key into your app instead:', 'bettershield' ) );
	const code = el( 'code' );
	keyGroups( secret ).forEach( ( group ) => code.append( el( 'span', '', group ) ) );
	key.append( code );
	holder.append( key );

	const copyRow = el( 'p', 'bs-profile-2fa__row' );
	copyRow.append( copyButton( __( 'Copy Key', 'bettershield' ), secret ) );
	holder.append( copyRow );

	const label = el( 'label', '', __( 'Code from the app', 'bettershield' ) );
	label.setAttribute( 'for', 'bettershield-2fa-code' );

	const input = el( 'input' );
	input.type = 'text';
	input.id = 'bettershield-2fa-code';
	input.className = 'regular-text';
	input.autocomplete = 'one-time-code';
	input.inputMode = 'numeric';
	input.spellcheck = false;

	const confirm = button( __( 'Confirm Code', 'bettershield' ), true );
	const submit = () => {
		// A second Enter while this runs would stage a second set of codes.
		if ( confirm.disabled ) {
			return;
		}

		confirm.disabled = true;
		apiFetch( { path: '/bettershield/v1/two-factor/confirm', method: 'POST', data: { code: input.value.trim() } } )
			.then( ( { backup_codes: codes } ) => keep( codes ) )
			.catch( ( error ) => {
				confirm.disabled = false;
				fail( error );
				input.focus();
			} );
	};

	confirm.addEventListener( 'click', submit );
	input.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	/*
	 * Back to the offer, and the half-made secret with it, as Protect >
	 * Two-factor's Cancel does. Not waited on: starting again replaces the
	 * pending secret anyway (#2067). Clearing the panel took the focused
	 * Cancel with it and focus fell to <body>, so it goes back to the button
	 * that opened the panel, as the other inline prompts hand it back (#2171).
	 */
	const cancel = button( __( 'Cancel', 'bettershield' ) );
	cancel.addEventListener( 'click', () => {
		apiFetch( { path: '/bettershield/v1/two-factor/discard', method: 'POST', data: {} } ).catch( () => {} );
		offer().focus();
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( label, input, confirm, cancel );
	holder.append( row );
	holder.append( el( 'p', 'description', __( 'Two-factor is not on yet. If you leave this page now, nothing changes.', 'bettershield' ) ) );
	input.focus();
}

/* ---- step 3: the backup codes --------------------------------------------- */

function keep( codes ) {
	clear();

	const intro = el( 'p', '', __( 'Your app is connected. Save these backup codes: each one signs you in once if you lose your phone. They are shown only now.', 'bettershield' ) );

	// The button that led here is gone with the panel it sat in.
	intro.tabIndex = -1;
	holder.append( intro );
	intro.focus();

	const list = el( 'p', 'bs-profile-2fa__codes' );
	codes.forEach( ( code ) => list.append( el( 'span', '', code ) ) );
	holder.append( list );
	holder.append( keepButtons( codes ) );

	const done = button( __( 'Turn On Two-Factor', 'bettershield' ), true );
	done.addEventListener( 'click', () => {
		// Held, not disabled: a disabled button drops focus to the page while
		// the request runs (#1926).
		if ( 'true' === done.getAttribute( 'aria-disabled' ) ) {
			return;
		}

		done.setAttribute( 'aria-disabled', 'true' );
		apiFetch( { path: '/bettershield/v1/two-factor/acknowledge', method: 'POST', data: {} } )
			.then( () => {
				// The server-rendered panel now shows the armed state, and an
				// account the policy was holding gets its dashboard back. The
				// reloaded page puts focus back on this section.
				try {
					window.sessionStorage.setItem( ARMED_MARK, '1' );
				} catch ( e ) {}

				window.location.reload();
			} )
			.catch( ( error ) => {
				done.removeAttribute( 'aria-disabled' );
				fail( error );
			} );
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( done );
	holder.append( row );
}

/**
 * An administrator turning two-factor off for somebody else.
 *
 * The support path for an account whose phone and codes are both gone. The
 * route has always existed and been gated on `edit_user`; until now there was
 * nowhere to press, so the only way to do the thing the readme describes was
 * to hand-write a request.
 *
 * Armed with a confirmation because it takes a protection away from an account
 * that is not the one pressing.
 */
function adminReset() {
	const id = resetHolder.dataset.user;

	const go = button( __( 'Turn Off Two-Factor for This User', 'bettershield' ) );
	const note = el( 'span', 'bs-profile-2fa__note' );

	const send = () => {
		go.disabled = true;
		note.textContent = '';

		apiFetch( { path: `/bettershield/v1/two-factor/users/${ id }/disable`, method: 'POST', data: {} } )
			.then( () => {
				window.location.reload();
			} )
			.catch( ( error ) => {
				go.disabled = false;

				if ( error && 'bettershield_confirm_password' === error.code ) {
					note.textContent = error.message;
					askForPassword( resetHolder, send );
					return;
				}

				note.textContent =
					error && error.message
						? error.message
						: __( 'Two-factor could not be turned off. Reload the page and try again.', 'bettershield' );
			} );
	};

	go.addEventListener( 'click', () => {
		if (
			// eslint-disable-next-line no-alert
			! window.confirm(
				__(
					'Turn off two-factor for this account? They will use only a password until they set it up again.',
					'bettershield'
				)
			)
		) {
			return;
		}

		send();
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( go, note );
	resetHolder.append( row );
}

/**
 * An administrator removing somebody else's passkeys.
 *
 * The support path for a holder who has lost the device: under passkey-only
 * their password is refused while they hold one, and the recovery link and
 * printed codes are the owner's, not theirs. Armed with a confirmation, as
 * turning their two-factor off is, because it takes a way in away from an
 * account that is not the one pressing.
 */
function adminRemovePasskeys() {
	const id = passkeyRemoveHolder.dataset.user;

	const go = button( __( 'Remove This Account’s Passkeys', 'bettershield' ) );
	const note = el( 'span', 'bs-profile-2fa__note' );

	const send = () => {
		go.disabled = true;
		note.textContent = '';

		apiFetch( { path: `/bettershield/v1/passkeys/users/${ id }/remove`, method: 'POST', data: {} } )
			.then( () => {
				window.location.reload();
			} )
			.catch( ( error ) => {
				go.disabled = false;

				if ( error && 'bettershield_confirm_password' === error.code ) {
					note.textContent = error.message;
					askForPassword( passkeyRemoveHolder, send );
					return;
				}

				note.textContent = error && error.message ? error.message : __( 'That could not be done.', 'bettershield' );
			} );
	};

	go.addEventListener( 'click', () => {
		if (
			// eslint-disable-next-line no-alert
			! window.confirm(
				__(
					'Remove all passkeys on this account? Every device is signed out, and they use their password until they add one.',
					'bettershield'
				)
			)
		) {
			return;
		}

		send();
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( go, note );
	passkeyRemoveHolder.append( row );
}

/* ---- issuing a fresh set, for an account already using two-factor --------- */

/**
 * Backup codes used to be minted once, at enrollment, and from then on only
 * ever decreased. An editor who spent theirs and then lost their phone had no
 * way in at all — the app is gone, the codes are gone, and the recovery link is
 * the site owner's credential rather than theirs. The panel had been counting
 * down toward exactly that, on a screen they visit, offering nothing.
 *
 * A current code is required before anything is issued, and that is the point
 * rather than a formality: ten long-lived credentials handed to whoever holds
 * the session would leave a hijacked session better off than it started.
 */
function reissue() {
	clear( codesHolder );

	const go = button( __( 'Create New Backup Codes', 'bettershield' ) );
	const off = button( __( 'Turn Off Two-Factor or Switch Phones', 'bettershield' ) );

	go.addEventListener( 'click', () => ask() );
	off.addEventListener( 'click', () => askOff() );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( go, off );
	codesHolder.append( row );
}

/**
 * Turning two-factor off for oneself, behind a current code, which is how
 * moving it to a new phone starts: without this, anybody but an
 * administrator had to ask one to strip the factor. The same proof the
 * dashboard's own turn-off asks for, through the same route, so a role the
 * site requires it for is refused there with the reason.
 */
function askOff() {
	clear( codesHolder );

	codesHolder.append(
		el(
			'p',
			'',
			__(
				'Enter a code from your app, or a backup code, to turn off two-factor. Your backup codes stop working. Switching phones? Set it up again afterward.',
				'bettershield'
			)
		)
	);

	const label = el( 'label', '', __( 'Authenticator app code or backup code', 'bettershield' ) );
	label.setAttribute( 'for', 'bettershield-2fa-off-code' );

	const field = el( 'input' );
	field.type = 'text';
	field.id = 'bettershield-2fa-off-code';
	field.className = 'regular-text';
	field.autocomplete = 'one-time-code';
	field.inputMode = 'numeric';
	field.spellcheck = false;

	const go = button( __( 'Turn Off Two-Factor', 'bettershield' ), true );
	const cancel = button( __( 'Cancel', 'bettershield' ) );

	const submit = () => {
		// A second Enter while this runs would offer a spent code.
		if ( go.disabled ) {
			return;
		}

		go.disabled = true;

		apiFetch( {
			path: '/bettershield/v1/two-factor/disable',
			method: 'POST',
			data: { code: field.value.trim() },
		} )
			.then( () => turnedOff() )
			.catch( ( error ) => {
				go.disabled = false;
				fail( error, codesHolder );
				field.focus();
			} );
	};

	go.addEventListener( 'click', submit );
	field.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	cancel.addEventListener( 'click', () => reissue() );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( label, field, go, cancel );
	codesHolder.append( row );
	field.focus();
}

/**
 * Said where it was done, with the way on to the new phone: setting it up
 * again is the panel this page draws once two-factor is off.
 */
function turnedOff() {
	clear( codesHolder );

	// The lines the page printed said two-factor was on and counted codes
	// that no longer work; left, the section said on and off at once (#2222).
	document.getElementById( 'bettershield-2fa-backup-count' )?.remove();
	document.getElementById( 'bettershield-2fa-backup-low' )?.remove();

	const done = el( 'p', '', __( 'Two-factor is off for your account.', 'bettershield' ) );

	done.setAttribute( 'role', 'status' );

	const again = button( __( 'Set It Up on a New Phone', 'bettershield' ), true );

	again.addEventListener( 'click', () => {
		window.location.hash = 'bettershield-two-factor';
		window.location.reload();
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( again );
	codesHolder.append( done, row );
	again.focus();
}

function ask() {
	clear( codesHolder );

	codesHolder.append(
		el(
			'p',
			'',
			__(
				'To confirm, enter a code from your authenticator app or a backup code. Your current backup codes will stop working.',
				'bettershield'
			)
		)
	);

	const label = el( 'label', '', __( 'Authenticator app code or backup code', 'bettershield' ) );
	label.setAttribute( 'for', 'bettershield-2fa-reissue-code' );

	const field = el( 'input' );
	field.type = 'text';
	field.id = 'bettershield-2fa-reissue-code';
	field.className = 'regular-text';
	field.autocomplete = 'one-time-code';
	field.inputMode = 'numeric';
	field.spellcheck = false;

	const go = button( __( 'Create New Backup Codes', 'bettershield' ), true );
	const cancel = button( __( 'Cancel', 'bettershield' ) );

	const submit = () => {
		// A second Enter while this runs would offer the same code again, and
		// a spent code is counted as a wrong one.
		if ( go.disabled ) {
			return;
		}

		go.disabled = true;

		apiFetch( {
			path: '/bettershield/v1/two-factor/backup-codes',
			method: 'POST',
			data: { code: field.value.trim() },
		} )
			.then( ( { codes, remaining } ) => show( codes, remaining ) )
			.catch( ( error ) => {
				go.disabled = false;
				fail( error, codesHolder );
				field.focus();
			} );
	};

	go.addEventListener( 'click', submit );
	field.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	cancel.addEventListener( 'click', () => reissue() );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( label, field, go, cancel );
	codesHolder.append( row );
	field.focus();
}

/**
 * The count of unused backup codes above the panel, and the warning under it
 * when the account is nearly out, redrawn in the words the page prints them
 * with. Both were printed with the page, so anything on this screen that
 * changes the count has to say so here.
 *
 * @param {number} held How many unused codes the account now has.
 */
function drawCount( held ) {
	const count = document.getElementById( 'bettershield-2fa-backup-count' );

	if ( ! count ) {
		return;
	}

	count.textContent = sprintf(
		/* translators: %d: number of unused backup codes. */
		_n(
			'Two-factor is on. You have %d backup code left.',
			'Two-factor is on. You have %d backup codes left.',
			held,
			'bettershield'
		),
		held
	);

	const low = document.getElementById( 'bettershield-2fa-backup-low' );

	if ( held > LOW_WATER ) {
		low?.remove();
		return;
	}

	const warning = low || el( 'p', 'description' );
	warning.id = 'bettershield-2fa-backup-low';
	warning.textContent =
		0 === held
			? __( 'Backup codes sign you in if you lose your phone. You have none left. Create new codes now.', 'bettershield' )
			: __( 'Backup codes sign you in if you lose your phone. You are almost out. Create new codes now.', 'bettershield' );

	if ( ! low ) {
		count.after( warning );
	}
}

/**
 * Reads the count again after a passkey change: a backup code given as the
 * proof is spent, and the line above would otherwise still offer it.
 */
function recount() {
	if ( ! document.getElementById( 'bettershield-2fa-backup-count' ) ) {
		return;
	}

	apiFetch( { path: '/bettershield/v1/two-factor/status' } )
		.then( ( status ) => {
			if ( status && status.enabled && Number.isInteger( status.backup_remaining ) ) {
				drawCount( status.backup_remaining );
			}
		} )
		// The change itself went through; a count that could not be read is
		// left as it was rather than reported over the passkey list.
		.catch( () => {} );
}

function show( codes, remaining ) {
	clear( codesHolder );

	// The set these codes replaced is gone, and with it any warning that the
	// account was nearly out of it.
	drawCount( Number.isInteger( remaining ) ? remaining : codes.length );

	const intro = el(
		'p',
		'',
		__(
			'Your old codes no longer work. Each new code works once and is shown only now. Save them in a password manager or print them.',
			'bettershield'
		)
	);

	codesHolder.append( intro );

	const list = el( 'p', 'bs-profile-2fa__codes' );
	codes.forEach( ( code ) => list.append( el( 'span', '', code ) ) );
	codesHolder.append( list );
	codesHolder.append( keepButtons( codes ) );

	// The button that led here is gone with the panel it sat in.
	intro.tabIndex = -1;
	intro.focus();
}

/* ---- passkeys ------------------------------------------------------------- */

/**
 * The passkey list, and the two things that can be done to it.
 *
 * The admin app has a passkey screen already, but it needs a capability only
 * an administrator holds — and the passkey-only policy can name any role on
 * the site. Without this panel, a named editor was told their password was
 * about to stop working and had nowhere at all to enroll the credential that
 * replaces it.
 */

/** Base64url is what WebAuthn speaks; ArrayBuffers are what it hands back. */
function fromBase64Url( value ) {
	const raw = window.atob( value.replace( /-/g, '+' ).replace( /_/g, '/' ) );
	const bytes = new Uint8Array( raw.length );

	for ( let i = 0; i < raw.length; i++ ) {
		bytes[ i ] = raw.charCodeAt( i );
	}

	return bytes;
}

function toBase64Url( buffer ) {
	const bytes = new Uint8Array( buffer );
	let binary = '';

	for ( let i = 0; i < bytes.length; i++ ) {
		binary += String.fromCharCode( bytes[ i ] );
	}

	return window.btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
}

/**
 * What the browser's refusal means in words. WebAuthn errors carry a name and
 * a message written for developers; the name is the reliable part.
 */
function describePasskeyError( error ) {
	if ( ! error ) {
		return __( 'Your device did not complete the setup. Nothing was changed.', 'bettershield' );
	}

	// The server's refusals arrive with a string code and a sentence written
	// for the person; the browser's are DOMExceptions, whose legacy numeric
	// code says nothing.
	if ( typeof error.code === 'string' && error.message ) {
		return error.message;
	}

	const closed = promptClosedWords( error.name );

	if ( closed ) {
		return closed;
	}

	switch ( error.name ) {
		case 'InvalidStateError':
			return __( 'This device already holds a passkey for this account.', 'bettershield' );
		case 'SecurityError':
			return __( 'Your browser blocked this. Passkeys need a secure https:// address with a valid certificate. Nothing was changed.', 'bettershield' );
		case 'NotSupportedError':
			return __( 'This device can’t create this type of passkey. Try another device or a password manager.', 'bettershield' );
		default:
			return error.message || __( 'Your device did not complete the setup. Nothing was changed.', 'bettershield' );
	}
}

function passkeys() {
	apiFetch( { path: '/bettershield/v1/passkeys' } )
		.then( drawPasskeys )
		.catch( ( error ) => fail( error, passkeyHolder ) );
}

/**
 * @param {Object} state The passkeys, as the server answers.
 * @param {string} said  What just happened to them, if anything.
 */
function drawPasskeys( state, said = '' ) {
	fillPasskeys( state );

	if ( said ) {
		announce( passkeyHolder, said );
	}
}

/**
 * A passkey list that came back from a change, drawn, and the count above
 * read again in case a backup code paid for the change.
 *
 * @param {Object} state The passkey list the route answered with.
 * @param {string} said  What just happened to them.
 */
function drawChangedPasskeys( state, said ) {
	drawPasskeys( state, said );
	recount();
}

/** @param {Object} state The passkeys, as the server answers. */
function fillPasskeys( state ) {
	clear( passkeyHolder );

	if ( ! state.available ) {
		passkeyHolder.append( el( 'p', 'description', state.reason ) );
		return;
	}

	if ( state.passkeys.length ) {
		const list = el( 'ul', 'bs-profile-passkeys' );

		state.passkeys.forEach( ( passkey ) => {
			const item = el( 'li' );
			item.append( el( 'span', 'bs-profile-passkeys__label', passkey.label ) );

			/* A credential is bound to the domain it was made for and cannot
			   be moved to another, so one from before this host shared its
			   passkeys is listed for removal rather than for signing in. */
			if ( passkey.usable === false ) {
				item.append(
					el(
						'span',
						'description',
						__(
							'Works only on the site where you created it. Add a new passkey to sign in on every site in this network.',
							'bettershield'
						)
					)
				);
			}

			const drop = button( __( 'Remove', 'bettershield' ) );
			drop.addEventListener( 'click', () => {
				if (
					// eslint-disable-next-line no-alert
					! window.confirm(
						__(
							'Remove this passkey? Your other devices are signed out; this one stays signed in.',
							'bettershield'
						)
					)
				) {
					return;
				}

				const dropIt = ( proved = {} ) =>
					apiFetch( { path: `/bettershield/v1/passkeys/${ passkey.id }`, method: 'DELETE', data: proved } )
						.then( ( next ) => drawChangedPasskeys( next, __( 'Passkey removed.', 'bettershield' ) ) )
						.catch( ( error ) => {
							drop.disabled = false;
							if ( ! askForProof( error, passkeyHolder, dropIt ) ) {
								fail( error, passkeyHolder );
							}
						} );

				withCode(
					state,
					( proved ) => {
						drop.disabled = true;

						return dropIt( proved );
					},
					__( 'To remove a passkey, confirm it’s you.', 'bettershield' )
				);
			} );

			item.append( drop );
			list.append( item );
		} );

		passkeyHolder.append( list );
	}

	if ( window.isSecureContext === false || typeof window.PublicKeyCredential === 'undefined' || ! navigator.credentials?.create ) {
		passkeyHolder.append(
			el(
				'p',
				'description',
				window.isSecureContext === false ? __( 'Open this page at its https:// address to add a passkey.', 'bettershield' ) : __( 'This browser does not support passkeys. Try a current Chrome, Safari, Edge or Firefox.', 'bettershield' )
			)
		);
		return;
	}

	/* Not offered to an account another security plugin covers: its own code
	   would still be asked after the passkey, and the panel's description
	   already says so (#2465). */
	if ( state.elsewhere ) {
		return;
	}

	if ( state.passkeys.length >= state.max ) {
		passkeyHolder.append(
			el(
				'p',
				'description',
				sprintf(
					/* translators: %d: the maximum number of passkeys per account. */
					__( '%d passkeys is the limit. Remove one to add another.', 'bettershield' ),
					state.max
				)
			)
		);
		return;
	}

	passkeyHolder.append( el( 'p', 'description', __( 'Next, your browser asks where to save the passkey: this device, your phone or a password manager.', 'bettershield' ) ) );
	const label = el( 'label', '', __( 'Passkey name (optional)', 'bettershield' ) );
	label.setAttribute( 'for', 'bettershield-passkey-label' );

	const field = el( 'input' );
	field.type = 'text';
	field.id = 'bettershield-passkey-label';
	field.className = 'regular-text';
	field.placeholder = __( 'Work laptop', 'bettershield' );
	// What the server keeps; a longer name was cut there without a word.
	field.maxLength = 191;

	const add = button( __( 'Add a Passkey', 'bettershield' ), true );
	const submit = () => {
		// A second Enter while the device is asking would start a second prompt.
		if ( add.disabled ) {
			return;
		}

		const start = ( proved = {} ) => {
			add.disabled = true;
			add.textContent = __( 'Waiting for Your Device…', 'bettershield' );
			passkeyHolder.querySelector( '.bs-profile-2fa__stopped' )?.remove();

			// The prompt can be out of sight, with this page holding its one
			// control, so a person who sees nothing is told and given a way out.
			const asked = promptWait();
			const stop = button( __( 'Stop Waiting', 'bettershield' ) );
			const note = el( 'p', 'description', promptHint() );
			note.setAttribute( 'role', 'status' );
			stop.addEventListener( 'click', asked.stop );
			const hint = window.setTimeout( () => {
				row.append( stop );
				row.after( note );
			}, PROMPT_HINT_AFTER_MS );
			const settled = () => {
				const refocus = stop === document.activeElement;

				asked.done();
				window.clearTimeout( hint );
				stop.remove();
				note.remove();

				return refocus;
			};

			return enrollPasskey( field.value.trim(), proved, asked.signal )
				.then( ( next ) => {
					settled();

					return drawChangedPasskeys( next, __( 'Passkey added.', 'bettershield' ) );
				} )
				.catch( ( error ) => {
					const refocus = settled();

					add.disabled = false;
					add.textContent = __( 'Add a Passkey', 'bettershield' );

					if ( refocus ) {
						add.focus();
					}

					if ( asked.stopped() ) {
						const said = el( 'p', 'description bs-profile-2fa__stopped', promptStoppedWords() );

						said.setAttribute( 'role', 'status' );
						passkeyHolder.insertBefore( said, passkeyHolder.firstChild );
					} else if ( ! askForProof( error, passkeyHolder, start ) ) {
						fail( error, passkeyHolder );
					}
				} );
		};

		withCode( state, start, __( 'To add a passkey, confirm it’s you.', 'bettershield' ) );
	};

	add.addEventListener( 'click', submit );
	field.addEventListener( 'keydown', ( event ) => {
		if ( 'Enter' === event.key ) {
			// Never let Enter fall through to the profile form around us.
			event.preventDefault();
			submit();
		}
	} );

	const row = el( 'p', 'bs-profile-2fa__row' );
	row.append( label, field, add );
	passkeyHolder.append( row );
}

/**
 * Prove, with one of this account's own passkeys, that the person at this
 * session holds it: what an account gives before its passkeys change when it
 * has no password the site accepts and no second factor.
 */
function confirmWithPasskey() {
	return apiFetch( { path: '/bettershield/v1/passkeys/confirm-options', method: 'POST' } ).then( ( options ) =>
		navigator.credentials
			.get( {
				publicKey: {
					challenge: fromBase64Url( options.challenge ),
					rpId: options.rpId,
					// This account's own and no other: the proof is that its
					// holder is here, not that somebody with a passkey is.
					allowCredentials: ( options.allow || [] ).map( ( id ) => ( { type: 'public-key', id: fromBase64Url( id ) } ) ),
					// It stands in for a password, so the person is asked for
					// and not only a touch.
					userVerification: 'required',
					timeout: 120000,
				},
			} )
			.then( ( credential ) =>
				apiFetch( {
					path: '/bettershield/v1/passkeys/confirm',
					method: 'POST',
					data: {
						handle: options.handle,
						id: credential.id,
						clientDataJSON: toBase64Url( credential.response.clientDataJSON ),
						authenticatorData: toBase64Url( credential.response.authenticatorData ),
						signature: toBase64Url( credential.response.signature ),
					},
				} )
			)
	);
}

/**
 * Whether the browser says the new key can sign in without a username, from
 * the `credProps` extension: '1' or '0', or undefined where it said nothing
 * (older browsers), which the server records as unknown. The sign-in form has
 * no username step, so the server refuses a key reported as '0' (#2469).
 */
function discoverableOf( credential ) {
	const results = credential && 'function' === typeof credential.getClientExtensionResults ? credential.getClientExtensionResults() : null;
	const rk = results && results.credProps ? results.credProps.rk : undefined;

	if ( 'boolean' !== typeof rk ) {
		return undefined;
	}

	return rk ? '1' : '0';
}

function enrollPasskey( label, proved = {}, signal = undefined ) {
	return apiFetch( { path: '/bettershield/v1/passkeys/register-options', method: 'POST', data: proved } )
		.then( ( options ) =>
			navigator.credentials
				.create( {
					publicKey: {
						challenge: fromBase64Url( options.challenge ),
						rp: { id: options.rp.id, name: options.rp.name },
						user: {
							id: fromBase64Url( options.user.id ),
							name: options.user.name,
							displayName: options.user.displayName,
						},
						pubKeyCredParams: options.algorithms.map( ( alg ) => ( { type: 'public-key', alg } ) ),
						// The server decides how hard to ask: required only
						// where this key would become the sole way in for an
						// account whose password is refused.
						// The resident key is always required: the sign-in form asks
						// for any key this site holds, with no username first, so a key
						// that keeps nothing on the device is never offered (#2469).
						authenticatorSelection: {
							residentKey: 'required',
							requireResidentKey: true,
							userVerification: options.verification || 'preferred',
						},
						// So a device already enrolled on this account declines
						// quietly rather than failing at the server.
						excludeCredentials: ( options.registered || [] ).map( ( id ) => ( {
							type: 'public-key',
							id: fromBase64Url( id ),
						} ) ),
						timeout: PROMPT_TIMEOUT_MS,
						attestation: 'none',
						// Asks the browser to say whether it stored the key, so one
						// that cannot sign in is refused rather than saved.
						extensions: { credProps: true },
					},
					signal,
				} )
				.then( ( credential ) =>
					apiFetch( {
						path: '/bettershield/v1/passkeys/register',
						method: 'POST',
						data: {
							handle: options.handle,
							clientDataJSON: toBase64Url( credential.response.clientDataJSON ),
							attestationObject: toBase64Url( credential.response.attestationObject ),
							transports: ( credential.response.getTransports
								? credential.response.getTransports()
								: [] ).join( ',' ),
							label,
							discoverable: discoverableOf( credential ),
						},
					} )
				)
				.catch( ( error ) => {
					throw new Error( describePasskeyError( error ) );
				} )
		);
}

if ( holder ) {
	offer();
}

if ( codesHolder ) {
	reissue();
}

if ( resetHolder ) {
	adminReset();
}

if ( passkeyHolder ) {
	passkeys();
}

if ( passkeyRemoveHolder ) {
	adminRemovePasskeys();
}
