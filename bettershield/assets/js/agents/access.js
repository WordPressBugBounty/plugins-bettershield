/**
 * The two facts every Agents screen has to agree on: what the opt-ins say, and
 * whose clock the deadlines were minted against.
 *
 * Four screens read the same site through four routes, and each reply carries
 * its own copy of the answer. Reading them the same way in one place is what
 * keeps a switch on one tab from disagreeing with the sentence about it on the
 * next.
 */

/** Only what the reply actually carried; a key it left out is left alone. */
export function accessFrom( payload ) {
	const out = {};

	[ 'read_enabled', 'write_enabled', 'capability_granted', 'sudo_required' ].forEach( ( key ) => {
		if ( payload[ key ] !== undefined ) {
			out[ key ] = !! payload[ key ];
		}
	} );

	// Why a sign-in change cannot be allowed from this account, as the site
	// words it, or null while the password is asked for.
	if ( payload.password_reason !== undefined ) {
		out.password_reason = payload.password_reason ? String( payload.password_reason ) : null;
	}

	return out;
}

/**
 * How far this browser's clock stands from the site's, in milliseconds.
 *
 * Every deadline on these screens is minted by the site and read here. A
 * browser twenty minutes fast reads a live proposal as expired, offers
 * nothing, and says nothing anybody can act on — so where a payload states the
 * moment the site wrote it, the deadlines in that payload are read against
 * that instead. A payload that states nothing is read against the browser, as
 * before.
 *
 * @param {?Object} payload A document that may carry the site's own `now`.
 * @return {number} Milliseconds to add to this clock to reach the site's.
 */
export function siteSkew( payload ) {
	const stated = payload && payload.now ? Date.parse( payload.now ) : NaN;

	return Number.isNaN( stated ) ? 0 : stated - Date.now();
}
