/**
 * The navigation model, handed over by PHP, and the rules for reading a route
 * out of a URL.
 *
 * Sections are real WordPress admin pages: the server decides which one is
 * open, refuses anyone without the capability for it, and builds every URL.
 * What lives here is the client half — turning one of those URLs back into a
 * route so a click need not reload the document to act on it.
 *
 * Resolution mirrors the server exactly. An unknown section falls back to the
 * first one; an unknown tab falls back to its own section's first tab and never
 * to Overview, because a renamed tab must not throw the reader out of the area
 * they were in.
 */

const model = window.bettershield || {};

export const sections = Array.isArray( model.sections ) ? model.sections : [];
export const brand = model.brand || 'BetterShield';

/*
 * An owner's label on the chrome, where an add-on gives one: the image the
 * sidebar draws in place of the mark, whether a label is in force, and
 * whether the links to this plugin's support are offered. The server
 * decides each; nothing here reads the label on its own.
 */
export const brandLogo = 'string' === typeof model.brandLogo ? model.brandLogo : '';
export const branded = true === model.branded;
export const helpLinks = false !== model.helpLinks;

/*
 * The hub connection, for the top bar's way to it: whether the site holds
 * one, and the hub's address where it may be opened ('' where the address
 * moved or the pinned one is invalid). The server decides both.
 */
const hubModel = model.hub || {};
export const hubConnected = true === hubModel.connected;
export const hubUrl = 'string' === typeof hubModel.url ? hubModel.url : '';

/**
 * Whether this is the network's screen rather than one site's.
 *
 * The same bundle draws both, and the difference is not cosmetic: the network
 * screens read rows belonging to every site and the site screens read one
 * site's. Deciding it from the server's own model rather than from the address
 * keeps the two sets of screens from ever being drawn under the wrong one.
 */
export const isNetwork = true === model.network;

/**
 * Where the routes carrying network state answer.
 *
 * Network admin is served by the main site, so the root a browser would work
 * out for itself is already the right one — but "already" is not "stated", and
 * the routes are registered on the main site whichever site serves the
 * request. Named by the server so the bundle assumes nothing.
 */
export const restRoot = 'string' === typeof model.restRoot ? model.restRoot : '';

/** How many days the activity log keeps, which bounds any report on it. */
export const retentionDays = Number( ( model.limits || {} ).retention_days ) || 30;

/** How many sites the roll-up walks before it says it stopped. */
export const maxSites = Number( ( model.limits || {} ).max_sites ) || 0;

/**
 * Areas per surface, in chip order and translated server-side. Each list holds
 * only the areas that surface can actually produce, so no screen ever draws a
 * chip that is permanently zero.
 */
const areaModel = model.areas || {};

export const findingAreas = Array.isArray( areaModel.findings ) ? areaModel.findings : [];
export const activityAreas = Array.isArray( areaModel.activity ) ? areaModel.activity : [];

/**
 * A finding's area by the name its heading carries, in the reader's language.
 * The slug is a stored key, English in every locale; it is shown only where
 * the server named no such area.
 *
 * @param {string} slug The area as a finding records it.
 * @return {string} Its name.
 */
export function findingAreaLabel( slug ) {
	const area = findingAreas.find( ( candidate ) => candidate.slug === slug );

	return area ? area.label : slug || '';
}

/**
 * Whether this reader may manage the plugin: what running the audit and the
 * reads behind the agent card and the explanations answer to. The sections
 * are filtered the same way on the server; this says it for the controls
 * that are not a section. Read when asked, and yes where the model is silent,
 * which is every screen drawn for somebody who may.
 *
 * @return {boolean} Whether the reader may manage the plugin.
 */
export function mayManage() {
	const can = ( window.bettershield || {} ).can;

	return can ? !! can.manage : true;
}

/**
 * Whether this reader may change the files every site shares: restore,
 * accept or quarantine them. On a network, a network administrator only;
 * yes where the model is silent.
 *
 * @return {boolean} Whether the file actions are this reader's.
 */
export function mayChangeSharedCode() {
	const can = ( window.bettershield || {} ).can;

	return mayManage() && ( ! can || false !== can.shared_code );
}

/**
 * Whether this reader may read the posture: the score and findings the
 * Overview is built from. Read when asked, and yes where the model is silent,
 * as `mayManage()` is.
 *
 * @return {boolean} Whether the reader may read the posture.
 */
export function mayReadPosture() {
	const can = ( window.bettershield || {} ).can;

	return can && 'read_posture' in can ? !! can.read_posture : true;
}

/** Page slugs this app owns, which is what a link is tested against. */
export const OWNED = sections.map( ( section ) => section.slug );

/** Whether a paid add-on has this site on its tier; the sidebar names it. */
export const tier = 'ultra' === model.tier ? 'ultra' : 'free';

/**
 * A sidebar built from the sections alone: one zone, one group, one entry per
 * screen. What a model without a sidebar gets — a test, or a server older
 * than the bundle — so every screen is still reachable, just not grouped.
 */
function sidebarFromSections() {
	const items = [];

	sections.forEach( ( section ) => {
		const tabs = Array.isArray( section.tabs ) ? section.tabs : [];
		const screens = tabs.length ? tabs : [ { slug: '', label: section.label, url: section.url } ];

		screens.forEach( ( screen ) => {
			items.push( {
				key: screen.slug ? `${ section.slug }/${ screen.slug }` : section.slug,
				section: section.slug,
				tab: screen.slug,
				label: screen.label,
				url: screen.url,
				icon: '',
				count: 0,
			} );
		} );
	} );

	return items.length ? [ { key: 'core', label: '', groups: [ { key: 'home', label: '', items } ] } ] : [];
}

/**
 * The sidebar, as the server built it (Admin\Navigation): this plugin's own
 * screens in the first zone, grouped the way its sections are, then a zone
 * per add-on under that add-on's name. Every screen is listed once.
 */
export const navZones = Array.isArray( model.nav ) && model.nav.length ? model.nav : sidebarFromSections();

/**
 * The sidebar entry a route is on, with its group and zone.
 *
 * A section with tabs matches on the tab as well; the route has already been
 * resolved, so an address with no tab is on its section's first. An entry no
 * section serves — a page of its own — is never the current one.
 *
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {?{zone: Object, group: Object, item: Object}} The entry, or null.
 */
export function navItemFor( route ) {
	for ( const zone of navZones ) {
		for ( const group of zone.groups || [] ) {
			for ( const item of group.items || [] ) {
				if ( item.section && item.section === route.section && ( ! item.tab || item.tab === route.tab ) ) {
					return { zone, group, item };
				}
			}
		}
	}

	return null;
}

/** The first entry of the sidebar: where the wordmark leads. */
export function homeUrl() {
	const first = navZones[ 0 ] && navZones[ 0 ].groups[ 0 ] && navZones[ 0 ].groups[ 0 ].items[ 0 ];

	return first ? first.url : '';
}

export function findSection( slug ) {
	return sections.find( ( section ) => section.slug === slug );
}

/**
 * Whether an add-on draws this tab with the redesign's components, as it
 * said in its section (`drawn`). Such a tab's slot sits in the redesign's
 * content box; any other add-on tab keeps the wrapper that carries the
 * classic look, so an add-on that says nothing draws what it always drew.
 *
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {boolean} Whether the add-on draws it in the new design.
 */
export function isDrawnAddOn( route ) {
	const section = findSection( route.section );
	const drawn = section && Array.isArray( section.drawn ) ? section.drawn : [];

	return drawn.includes( route.tab || '' );
}

export function sectionUrl( slug ) {
	const found = findSection( slug );

	return found ? found.url : '';
}

/**
 * A link straight to one tab of a section.
 *
 * The section URL still comes from the server, so the capability check and the
 * page slug stay its business; only the tab is appended here, which is the one
 * part of the route the client already owns.
 */
export function tabUrl( slug, tab ) {
	const base = sectionUrl( slug );

	if ( ! base || ! tab ) {
		return base;
	}

	return `${ base }${ base.includes( '?' ) ? '&' : '?' }tab=${ encodeURIComponent( tab ) }`;
}

/**
 * A link straight to one finding on the report.
 *
 * The scroll-to-and-focus that answers `?finding=` was built for alert links
 * and used by nothing else, so the Overview's own "Details" — which points at
 * one specific finding — landed the reader at the top of a list to find it
 * again. Same address, same behavior, from inside the app.
 */
export function findingUrl( id ) {
	const base = sectionUrl( 'bettershield-findings' );

	if ( ! base || ! id ) {
		return base;
	}

	return `${ base }${ base.includes( '?' ) ? '&' : '?' }finding=${ encodeURIComponent( id ) }`;
}

/**
 * The event the app fires after it moves to an address itself. Pushing an
 * address fires no popstate, so a screen that reads its narrowing from the
 * address listens for this as well as for Back and Forward.
 */
export const NAVIGATED = 'bettershield:navigated';

/**
 * A link to the Findings report opened on one status, such as the snoozed
 * list, which its default Open view leaves out.
 */
export function findingsUrl( status ) {
	const base = sectionUrl( 'bettershield-findings' );

	if ( ! base || ! status ) {
		return base;
	}

	return `${ base }${ base.includes( '?' ) ? '&' : '?' }status=${ encodeURIComponent( status ) }`;
}

export function resolve( section, tab ) {
	const found = findSection( section ) || sections[ 0 ];

	if ( ! found ) {
		return { section: '', tab: '' };
	}

	const tabs = found.tabs || [];

	if ( ! tabs.length ) {
		return { section: found.slug, tab: '' };
	}

	const known = tabs.some( ( candidate ) => candidate.slug === tab );

	return { section: found.slug, tab: known ? tab : tabs[ 0 ].slug };
}

export function routeFromUrl( href ) {
	let url;

	try {
		url = new URL( href, window.location.origin );
	} catch ( error ) {
		return resolve( '', '' );
	}

	return resolve( url.searchParams.get( 'page' ) || '', url.searchParams.get( 'tab' ) || '' );
}

/** What the server rendered, which is the route before anything is clicked. */
export const initialRoute = resolve( model.section || '', model.tab || '' );

/*
 * What an alert email asked for, read from the address as it is now.
 *
 * The intent has always been that clicking around afterwards must not
 * re-trigger the arrival. Reading once, at the moment the bundle loaded, did
 * the opposite: navigation is a `pushState` and never re-runs this module, so
 * the values outlived the address that carried them. Every later return to
 * Findings scrolled to the row again, took focus again, and offered the
 * feedback button again — unanswered-looking — to a reader who had already
 * answered it. Reading live, the answer becomes empty the moment the address
 * moves on, which is the behavior the paragraph above always described.
 */
function opened() {
	try {
		return new URL( window.location.href ).searchParams;
	} catch ( error ) {
		return new URLSearchParams();
	}
}

/** The finding an alert linked to, if the current address came from one. */
export function linkedFinding() {
	return opened().get( 'finding' ) || '';
}

/** The Findings status a link named, if the current address came from one. */
export function linkedStatus() {
	return opened().get( 'status' ) || '';
}

/** The Settings › General group the address names (?group=leaves), if any. */
export function linkedGroup() {
	return opened().get( 'group' ) || '';
}

/** Whether the reader arrived from an alert, which is what may be asked about. */
export function cameFromAlert() {
	return 'alert' === opened().get( 'from' );
}

/** A calendar day as the log's date filters take it. */
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * An address for the Site log narrowed to one account, one network and a
 * range of days — what another screen links to when it means "everything this
 * person, or this network, did".
 *
 * The days travel as `since` and `until` rather than `from` and `to`: `from`
 * already means where the reader came from (`from=alert`). The network is the
 * label a row shows, never an address.
 *
 * @param {Object} narrowing
 * @param {string} narrowing.actor   An actor token, `user:<id>`.
 * @param {string} narrowing.network A stored network label.
 * @param {string} narrowing.since   YYYY-MM-DD.
 * @param {string} narrowing.until   YYYY-MM-DD.
 * @param {string} narrowing.search  Words the log opens searched for, such as a name tried at sign-in.
 * @return {string} The address, or '' when the log is not reachable here.
 */
export function activityUrl( { actor = '', network = '', since = '', until = '', search = '' } = {} ) {
	const base = tabUrl( 'bettershield-activity', 'site' );

	if ( ! base ) {
		return '';
	}

	const params = new window.URLSearchParams();

	Object.entries( { actor, network, since, until, search } ).forEach( ( [ key, value ] ) => {
		if ( value ) {
			params.set( key, value );
		}
	} );

	const query = params.toString();

	return query ? `${ base }${ base.includes( '?' ) ? '&' : '?' }${ query }` : base;
}

/**
 * What a link into the Site log asked for, read from the address as it is
 * now, with anything of the wrong shape dropped rather than sent on.
 *
 * A value of the right shape can still be one the site refuses: a day the
 * calendar does not have, a range that ends before it starts, a network
 * with host bits set. Those are sent once, and the Site log keeps its rows,
 * says why beside the filters and drops the value from the address.
 *
 * @return {{actor: string, network: string, from: string, to: string}} The narrowing.
 */
export function linkedLogFilters() {
	const params = opened();
	const actor = params.get( 'actor' ) || '';
	const network = params.get( 'network' ) || '';
	const since = params.get( 'since' ) || '';
	const until = params.get( 'until' ) || '';
	// The area tab, kept in the address like the rest (#2124); one the log
	// does not draw is All.
	const area = params.get( 'area' ) || '';

	return {
		area: activityAreas.some( ( entry ) => entry && entry.slug === area ) ? area : 'all',
		actor: /^(?:user:\d+|type:[a-z_]{1,16})$/.test( actor ) ? actor : '',
		network: /^[0-9a-fA-F.:]+\/(?:24|64)$/.test( network ) ? network : '',
		from: DAY.test( since ) ? since : '',
		to: DAY.test( until ) ? until : '',
	};
}

/**
 * What a link asked the Site log to search for, read once as it opens. Kept
 * apart from the narrowing above, which Back and Forward read again: a search
 * is typed, and the box would disagree with the rows.
 *
 * @return {string} The words, or ''.
 */
export function linkedSearch() {
	return ( opened().get( 'search' ) || '' ).trim().slice( 0, 100 );
}

/**
 * Write the narrowing on screen into the address.
 *
 * The log read its narrowing from the address once, as it opened, and never
 * wrote it back: after the reader cleared it, a reload, a copied link or Back
 * brought back what they had removed. A narrowing the reader chose from a row
 * or a tab is pushed, so Back undoes it (#2183); a change made with the
 * filters, or one the screen makes itself, replaces. The
 * alert arrival flag goes either way, so an arrival is not replayed.
 *
 * @param {Object<string, *>} narrowing Address parameters, and their values or empty.
 * @param {boolean}           push      Add a step to the history rather than replace this one.
 */
export function writeNarrowing( narrowing, push = false ) {
	let url;

	try {
		url = new URL( window.location.href );
	} catch ( error ) {
		return;
	}

	Object.entries( narrowing ).forEach( ( [ key, value ] ) => {
		if ( value ) {
			url.searchParams.set( key, String( value ) );
		} else {
			url.searchParams.delete( key );
		}
	} );

	url.searchParams.delete( 'from' );

	const href = url.toString();

	if ( href !== window.location.href ) {
		window.history[ push ? 'pushState' : 'replaceState' ]( window.history.state, '', href );
	}
}

/**
 * An address for Agent activity narrowed to the calls one account made.
 *
 * @param {number} account The account's id.
 * @return {string} The address.
 */
export function agentActivityUrl( account ) {
	const base = tabUrl( 'bettershield-activity', 'agents' );

	return base && account > 0 ? `${ base }${ base.includes( '?' ) ? '&' : '?' }account=${ account }` : base;
}

/** The account a link into Agent activity asked for, or 0. */
export function linkedAccount() {
	const account = parseInt( opened().get( 'account' ) || '', 10 );

	return account > 0 ? account : 0;
}

/**
 * The assistant connection a link into Agent activity asked for, or an empty
 * string: an alert about one links to its calls (#1880).
 */
export function linkedConnection() {
	const connection = opened().get( 'connection' ) || '';

	return /^(app|pairing):[\w.:-]{1,191}$/.test( connection ) ? connection : '';
}

/**
 * A link straight to one incident's timeline, from a row of the log about it.
 *
 * @param {number|string} id The incident's own number.
 * @return {string} The address, or the Incidents tab's when the id is not one.
 */
export function incidentUrl( id ) {
	const base = tabUrl( 'bettershield-activity', 'incidents' );
	const number = parseInt( id, 10 );

	return base && number > 0 ? `${ base }${ base.includes( '?' ) ? '&' : '?' }incident=${ number }` : base;
}

/** The incident a link into Incidents asked for, or 0. */
export function linkedIncident() {
	const incident = parseInt( opened().get( 'incident' ) || '', 10 );

	return incident > 0 ? incident : 0;
}
