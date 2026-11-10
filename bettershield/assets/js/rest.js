/**
 * Where a request goes, and what it carries.
 *
 * Two rules that belong to requests rather than to any screen, and that a
 * screen therefore cannot be the place to test: which REST root a path
 * resolves against, and how the log's filters are written onto a query string.
 *
 * ## The root
 *
 * WordPress installs its own middleware that turns a path into a URL against
 * the REST root of whichever site served the page. On a network screen that is
 * the main site, which is also where the routes carrying network state are
 * registered — so it is right today by coincidence rather than by anything
 * said out loud. This says it out loud.
 *
 * Ordering matters and is the reason the path is removed rather than merely
 * resolved. Middleware registered later runs first, so ours would set a URL
 * and core's would then recompute one from the path it left behind. Handing
 * the rest of the chain a request that has a URL and no path is what makes the
 * decision stick.
 */

/**
 * @param {string} root Absolute REST root, ending in a slash or a query.
 * @return {Function} An apiFetch middleware.
 */
export function rootURLMiddleware( root ) {
	return ( options, next ) => {
		if ( 'string' !== typeof options.path || options.url ) {
			return next( options );
		}

		let path = options.path.replace( /^\//, '' );

		/*
		 * A site with plain permalinks has its REST root in a query string
		 * (`…/?rest_route=/`), so the path's own `?` has to become an `&` or
		 * the route arrives with its filters attached to nothing.
		 */
		if ( -1 !== root.indexOf( '?' ) ) {
			path = path.replace( '?', '&' );
		}

		const resolved = { ...options, url: root + path };

		// Removed, not merely overridden: core's own root middleware runs
		// after this one and would rebuild the URL from whatever path it
		// still found on the request.
		delete resolved.path;

		return next( resolved );
	};
}

/**
 * The activity filters as the routes take them. The unfiltered value of each
 * is absent, so an untouched screen asks for a bare listing.
 *
 * Shared by the listing, the export and the network's union log, because all
 * three narrow the same record and a second spelling would let two of them
 * disagree about what a filter means.
 *
 * @param {Object}  filters The filter state, including `site` on a network.
 * @param {?number} cursor  Where the next page starts.
 * @return {string} A leading-`?` query string, or an empty string.
 */
/**
 * A day from the date inputs, as the instant it starts or ends at in the
 * reader's own timezone.
 *
 * The log files each row under the reader's calendar day, and a day sent as a
 * day is read in the site's timezone instead. Where the two differ, filtering
 * to a day on screen asked for other hours than the ones filed under it.
 */
function dayEdge( day, end ) {
	const date = new Date( `${ day }T${ end ? '23:59:59.999' : '00:00:00.000' }` );

	if ( Number.isNaN( date.getTime() ) ) {
		return day;
	}

	// A day the calendar does not have, February 30, rolls into the next
	// month. Sent as it is instead, so the site refuses it and the screen
	// says so, rather than filtering from a day nobody asked for.
	const same = [ date.getFullYear(), String( date.getMonth() + 1 ).padStart( 2, '0' ), String( date.getDate() ).padStart( 2, '0' ) ].join( '-' );

	return same === day ? date.toISOString() : day;
}

export function logQuery( filters, cursor ) {
	const params = new window.URLSearchParams();

	if ( cursor ) {
		params.set( 'cursor', String( cursor ) );
	}

	if ( 'all' !== filters.area ) {
		params.set( 'area', filters.area );
	}

	[ 'search', 'actor' ].forEach( ( name ) => {
		if ( filters[ name ] ) {
			params.set( name, filters[ name ] );
		}
	} );

	if ( filters.from ) {
		params.set( 'from', dayEdge( filters.from, false ) );
	}

	if ( filters.to ) {
		params.set( 'to', dayEdge( filters.to, true ) );
	}

	// One network, by the label a row shows. Sent as `prefix`: on the route,
	// `network` already means reading every site of one.
	if ( filters.network ) {
		params.set( 'prefix', filters.network );
	}

	// A list on the wire, because the route takes one. The control picks a
	// single site today; naming it this way means widening that to two is a
	// change to the control alone.
	if ( filters.site ) {
		params.set( 'sites[]', String( filters.site ) );
	}

	const query = params.toString();

	return query ? '?' + query : '';
}
