/**
 * Copy text to the clipboard, wherever the page is served from.
 *
 * Shared by every screen that offers a copy button — the recovery link, the
 * two-factor secret, the diagnostic report — so the fallback lives once.
 */

/**
 * Copy through a temporary selection.
 *
 * The deprecated path, kept because it is the only one that works where this
 * link matters most: the asynchronous clipboard API is a secure-context
 * feature, so on a site served over plain HTTP it is not merely restricted but
 * absent — and a site without HTTPS is exactly the site this plugin reports on.
 */
function copyBySelection( text ) {
	return new Promise( ( resolve, reject ) => {
		const field = document.createElement( 'textarea' );

		field.value = text;
		field.setAttribute( 'readonly', '' );
		// Fixed rather than scrolled off the page: an off-screen absolute
		// element moves the viewport when it takes selection.
		field.style.position = 'fixed';
		field.style.top = '0';
		field.style.opacity = '0';
		field.style.pointerEvents = 'none';

		document.body.appendChild( field );
		field.select();
		field.setSelectionRange( 0, text.length );

		let copied = false;

		try {
			copied = document.execCommand( 'copy' );
		} catch ( error ) {
			copied = false;
		}

		field.remove();

		if ( copied ) {
			resolve();
		} else {
			reject( new Error( 'copy-refused' ) );
		}
	} );
}

export function copyToClipboard( text ) {
	const viaClipboardApi =
		window.isSecureContext && window.navigator.clipboard
			? window.navigator.clipboard.writeText( text )
			: Promise.reject( new Error( 'clipboard-api-unavailable' ) );

	// The API rejects on a denied permission or an unfocused document just as
	// readily as it is missing over plain HTTP, and the selection copy answers
	// all three, so the fallback hangs off the rejection rather than off a
	// feature test alone.
	return viaClipboardApi.catch( () => copyBySelection( text ) );
}
