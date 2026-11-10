/**
 * Client-side navigation over the real admin URLs.
 *
 * Every section is a genuine WordPress page and every link points at its
 * genuine address. This layer only removes the document load between two of
 * them: the URL pushed is the same URL the link carried, so a refresh, a
 * bookmark, a shared link or a browser with JavaScript disabled all still land
 * on the server route with its capability check intact.
 *
 * Nothing here is load-bearing. If any of it fails the links still work as
 * links, which is the whole reason they stayed links.
 */

import { OWNED, findSection, navItemFor, routeFromUrl } from './nav';

/**
 * Every query parameter this app resolves for itself.
 *
 * A link on one of our screens can carry more than a destination. WordPress
 * builds an action link by adding parameters to the address you are already
 * on, so any notice rendered above this app produces a link whose `page` is
 * ours and whose real payload is a nonce and an action for a handler on the
 * server. Claiming it on the strength
 * of `page` alone swallowed the click: the router pushed the same URL, React
 * re-rendered the same screen, and `admin_init` never ran. The buttons did
 * nothing, silently.
 *
 * So the test is not "is this page ours" but "do we understand all of it".
 * Anything else belongs to the server and stays a real navigation.
 */
const CLIENT_PARAMS = [ 'page', 'tab', 'finding', 'from', 'actor', 'network', 'since', 'until', 'account', 'status', 'area', 'focus', 'group' ];

/**
 * A click the browser should be allowed to handle its own way: a modified
 * click opening a tab or window, a middle click, or one already handled.
 */
function isPlainClick( event ) {
	return (
		! event.defaultPrevented &&
		0 === event.button &&
		! event.metaKey &&
		! event.ctrlKey &&
		! event.shiftKey &&
		! event.altKey
	);
}

/**
 * Where the link a click landed on points, if it points within this site.
 */
function clickedUrl( event ) {
	const target = event.target;

	if ( ! target || 'function' !== typeof target.closest ) {
		return null;
	}

	const link = target.closest( 'a[href]' );

	if ( ! link || '_blank' === link.target || link.hasAttribute( 'download' ) ) {
		return null;
	}

	let url;

	try {
		url = new URL( link.href, window.location.origin );
	} catch ( error ) {
		return null;
	}

	return url.origin === window.location.origin ? url : null;
}

/**
 * Whether a link points within the screen already open.
 *
 * A citation in an AI explanation links to the numbered finding further down
 * the same screen. It differs from the address only by its fragment, so it
 * passed as a route: the address was pushed again, the screen re-rendered,
 * and focus went to the screen's heading instead of the item it cites.
 */
function withinScreen( url ) {
	return '' !== url.hash && url.pathname === window.location.pathname && url.search === window.location.search;
}

/** The element a link within the screen points at, if it is on the page. */
function inPageTarget( url ) {
	try {
		return document.getElementById( decodeURIComponent( url.hash.slice( 1 ) ) );
	} catch ( error ) {
		return null;
	}
}

/**
 * Whether a link within this site is one this app owns.
 */
function ownedLink( url ) {
	if ( ! OWNED.includes( url.searchParams.get( 'page' ) ) ) {
		return null;
	}

	for ( const name of url.searchParams.keys() ) {
		if ( ! CLIENT_PARAMS.includes( name ) ) {
			return null;
		}
	}

	return url;
}

/**
 * One listener on the document rather than a handler per link.
 *
 * It covers the section tabs, the tab row inside a section, links between
 * screens, and the plugin's own items in the admin sidebar — which matters,
 * because the sidebar is offered as a convenience and would be the slow path
 * if it alone still reloaded.
 *
 * @return {Function} Removes the listener.
 */
export function interceptLinks( go ) {
	const handler = ( event ) => {
		if ( ! isPlainClick( event ) ) {
			return;
		}

		const url = clickedUrl( event );

		if ( ! url ) {
			return;
		}

		// A jump within the screen is not a move: no address is pushed, and
		// focus goes where the link points, which also brings it into view.
		// One that points at nothing on the page is the browser's.
		if ( withinScreen( url ) ) {
			const target = inPageTarget( url );

			if ( target ) {
				event.preventDefault();
				target.focus();

				/*
				 * A target that cannot take focus — core's "Skip to main
				 * content" points at #wpbody-content, which has no tabindex —
				 * left focus on the link, with the default jump canceled,
				 * and the next Tab went through the whole admin menu (#2122).
				 * It takes focus by script only, as a heading does.
				 */
				if ( document.activeElement !== target && ! target.hasAttribute( 'tabindex' ) ) {
					target.setAttribute( 'tabindex', '-1' );
					target.focus();
				}

				if ( document.activeElement !== target && 'function' === typeof target.scrollIntoView ) {
					target.scrollIntoView();
				}
			}

			return;
		}

		if ( ! ownedLink( url ) ) {
			return;
		}

		event.preventDefault();
		go( url.href );
	};

	document.addEventListener( 'click', handler );

	return () => document.removeEventListener( 'click', handler );
}

/**
 * Keep the admin sidebar telling the truth.
 *
 * WordPress marks the current submenu item from the `page` parameter it was
 * served with, and a client-side move never tells it. Matching is on the exact
 * parameter, never a substring: `bettershield` is a prefix of every other slug
 * we own.
 *
 * Purely cosmetic. If the markup this reads ever changes, the highlight goes
 * stale and nothing else does.
 */
export function syncAdminMenu( section ) {
	const menu = document.getElementById( 'adminmenu' );

	if ( ! menu ) {
		return;
	}

	menu.querySelectorAll( '.wp-submenu li' ).forEach( ( item ) => {
		const link = item.querySelector( 'a[href]' );

		if ( ! link ) {
			return;
		}

		let page;

		try {
			page = new URL( link.href, window.location.origin ).searchParams.get( 'page' );
		} catch ( error ) {
			return;
		}

		if ( ! OWNED.includes( page ) ) {
			return;
		}

		item.classList.toggle( 'current', page === section );
		link.classList.toggle( 'current', page === section );
	} );
}

/*
 * The document title is rewritten by swapping the section name inside whatever
 * WordPress already assembled, rather than by rebuilding it. The rest of that
 * string is the site name and the suffix, both translated and neither ours to
 * reconstruct.
 */
const initialTitle = 'undefined' !== typeof document ? document.title : '';

export function syncTitle( section, initialSection, tab = '' ) {
	const from = findSection( initialSection );
	const to = findSection( section );

	if ( ! from || ! to || ! initialTitle.includes( from.label ) ) {
		return;
	}

	/*
	 * The screen as the sidebar names it, before its section: every tab of
	 * Protect read "Protect ‹ Site", and every Ultra screen "Ultra ‹ Site",
	 * in the browser tab, its history menu and to a screen reader (#2123).
	 */
	const found = tab ? navItemFor( { section, tab } ) : null;
	const name = found && found.item.label && found.item.label !== to.label ? `${ found.item.label } ‹ ${ to.label }` : to.label;

	document.title = initialTitle.replace( from.label, name );
}

export { routeFromUrl };
