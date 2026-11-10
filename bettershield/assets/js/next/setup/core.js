/**
 * Follow one of WordPress's own plugin links (Deactivate, Activate) in place,
 * as the owner's press: core checks the nonce and the capability and does the
 * rest, as it does from the Plugins screen. Its redirect afterwards is not
 * followed; the step reads the setup again to see what changed. One place,
 * so a test can stand in for the request.
 *
 * @param {string} url Core's link.
 * @return {Promise<boolean>} Whether core answered the request.
 */
export default function viaCore( url ) {
	return window
		.fetch( url, { credentials: 'same-origin', redirect: 'manual' } )
		.then( ( response ) => 'opaqueredirect' === response.type || response.ok )
		.catch( () => false );
}

/**
 * Core's Deactivate, marked as the setup's, so the setup can name the plugin
 * as switched off at the end.
 *
 * @param {string} url Core's Deactivate for the plugin.
 * @return {string} The same link with the setup's marker.
 */
export function marked( url ) {
	const link = new URL( url, window.location.href );

	link.searchParams.set( 'bettershield_setup', '1' );

	return link.toString();
}
