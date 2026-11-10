/**
 * Leave the setup for another admin screen in the same tab: WordPress's own
 * Deactivate for another plugin, which comes back to the setup once done.
 * One place, so a test can stand in for the browser's navigation.
 *
 * @param {string} url Where to go.
 */
export default function leave( url ) {
	window.location.assign( url );
}
