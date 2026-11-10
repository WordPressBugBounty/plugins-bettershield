/**
 * Hand the person a file built in the page.
 *
 * Shared by every screen that offers a download — the activity export, the
 * settings document, the two-factor backup codes — so the one way of doing it
 * lives once. Nothing is fetched and nothing leaves the browser: the bytes are
 * already on screen; this only lets them be kept.
 */

/**
 * @param {string} filename What the saved file is called.
 * @param {string} text     Its contents.
 * @param {string} type     Its MIME type.
 */
export function download( filename, text, type = 'text/plain;charset=utf-8' ) {
	const blob = new window.Blob( [ text ], { type } );
	const url = window.URL.createObjectURL( blob );
	const link = document.createElement( 'a' );

	link.href = url;
	link.download = filename;
	document.body.appendChild( link );
	link.click();
	document.body.removeChild( link );
	window.URL.revokeObjectURL( url );
}

/**
 * The same, for bytes that arrived base64-encoded.
 *
 * Decoded to a byte array rather than handed over as text: a quarantined file
 * is arbitrary bytes, and putting the decoded string through a text blob would
 * re-encode every byte above 127 into something else. The type stays plain
 * text on purpose — this is evidence being carried off the site, and nothing
 * about it should let a browser treat it as anything executable.
 *
 * @param {string} filename What the saved file is called.
 * @param {string} base64   Its contents, base64-encoded.
 * @param {string} type     Its MIME type.
 */
export function downloadBytes( filename, base64, type = 'text/plain' ) {
	const binary = window.atob( base64 );
	const bytes = new Uint8Array( binary.length );

	for ( let i = 0; i < binary.length; i++ ) {
		bytes[ i ] = binary.charCodeAt( i );
	}

	download( filename, bytes, type );
}
