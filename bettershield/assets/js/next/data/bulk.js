/**
 * One action per finding, in turn: each starts once the one before it has
 * answered, because the store runs a single action at a time and ignores a
 * second one started while the first is in flight.
 *
 * `perform( key, done, refused )` starts the action for one finding and calls
 * `done` when it happened or `refused` when it did not, with the error, or
 * with nothing when a password confirmation was canceled. A cancel stops the
 * run: the reader said no to all of it, not to one. A refusal is the
 * caller's to say, so `refused` answers true to the store for it.
 *
 * @param {Array<string>} keys    The findings, in the order to act on them.
 * @param {Function}      perform Starts one.
 * @return {Promise<{done: Array<string>, failed: Array<string>, stopped: Array<string>, reason: string}>} What happened to each, and why the first that failed did.
 */
export async function runEach( keys, perform ) {
	const done = [];
	const failed = [];
	let reason = '';

	for ( let index = 0; index < keys.length; index++ ) {
		const key = keys[ index ];

		// eslint-disable-next-line no-await-in-loop
		const outcome = await new Promise( ( resolve ) => {
			perform(
				key,
				() => resolve( 'done' ),
				( error ) => {
					if ( error && ! reason ) {
						reason = error.message || '';
					}

					resolve( error ? 'failed' : 'canceled' );

					/*
					 * Said where it was asked: every caller reports what
					 * could not be done, and why, in the alert beside the
					 * list. Answered true so the store does not raise the
					 * top banner as well, out of view and taking focus from
					 * that alert.
					 */
					return Boolean( error );
				}
			);
		} );

		if ( 'canceled' === outcome ) {
			return { done, failed, stopped: keys.slice( index ), reason };
		}

		( 'done' === outcome ? done : failed ).push( key );

		// The store lets go of the finished action only after its callbacks
		// have run; the next one waits for that.
		// eslint-disable-next-line no-await-in-loop
		await new Promise( ( resolve ) => setTimeout( resolve, 0 ) );
	}

	return { done, failed, stopped: [], reason };
}

/**
 * What "I manage this myself" marks: the finding, and with XML-RPC its
 * pingback half while that is open, since one block answers both rows.
 *
 * @param {Object}   finding The finding chosen.
 * @param {Object[]} all     Every finding the screen holds.
 * @return {string[]} Their keys, the chosen one first.
 */
export function managedKeys( finding, all ) {
	const covers = 'xmlrpc_enabled' === finding.id && all.some( ( other ) => 'pingbacks_open' === other.id && 'open' === other.status );

	return covers ? [ finding.id, 'pingbacks_open' ] : [ finding.id ];
}
