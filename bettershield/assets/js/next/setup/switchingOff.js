/**
 * Which other plugins the Coexistence step switches off, under the answers
 * on screen. The step's main button and the picture beside it both read this,
 * so the picture never says "Turns off" for a plugin the button leaves on.
 */

/**
 * The jobs a plugin is kept for by a choice on screen. A job with no choice,
 * such as a firewall, is left out: nothing on this step can hand it over,
 * so it never stands between the owner and the Plugins screen (#2232).
 *
 * @param {Object} plugin  The plugin, with its jobs.
 * @param {Object} choices Job => choice, as on screen.
 * @return {string[]} The jobs a choice still keeps it for.
 */
export function chosenFor( plugin, choices ) {
	return ( plugin.jobs || [] ).filter( ( job ) => Object.prototype.hasOwnProperty.call( choices, job ) && 'bettershield' !== choices[ job ] );
}

/**
 * The plugins this step could switch off: each whose every job with a choice
 * is BetterShield's on screen, once. A plugin whose sign-in address comes
 * over once the way back in is set up waits, and stays on until then so that
 * address keeps working.
 *
 * @param {Object[]} rows    The step's rows.
 * @param {Object}   choices Job => choice, as on screen.
 * @return {Object[]} The plugins, each once.
 */
export function listedOff( rows, choices ) {
	const listed = [];

	rows.forEach( ( row ) =>
		( row.deactivate || [] ).forEach( ( plugin ) => {
			if ( listed.some( ( other ) => other.file === plugin.file ) ) {
				return;
			}

			const waits = plugin.waits && 'bettershield' === choices.login_url;

			if ( ! waits && ! chosenFor( plugin, choices ).length && ( plugin.jobs || [] ).some( ( job ) => 'bettershield' === choices[ job ] ) ) {
				listed.push( plugin );
			}
		} )
	);

	return listed;
}

/**
 * Of those, the ones the main button switches off: where nothing stands in
 * the way and WordPress gives a link this account may use. Where the site has
 * turned the setup's deactivation off (`off`), the button switches nothing
 * off and the step points to the Plugins screen instead (#2993).
 *
 * @param {Object[]} listed What `listedOff()` answered.
 * @return {Object[]} The plugins the main button switches off.
 */
export function switchingOff( listed ) {
	return listed.filter( ( plugin ) => '' === plugin.why && ( plugin.link || plugin.deactivate_url ) );
}
