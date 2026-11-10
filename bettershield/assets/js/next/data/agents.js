/**
 * Where this site stands on agent access, on every tab that is not Connect:
 * the strip's facts, worked out once for every screen that draws them.
 *
 * Four tabs read one payload and each used to open straight into its own
 * subject: the requests queue, the opt-ins, the inventory. None of them said
 * the thing a reader needs before any of it means anything — whether an agent
 * can reach this site at all, and whether one has. Somebody reading the
 * inventory of forty abilities has no way to tell, from that screen, that
 * nothing is connected and none of them is reachable.
 *
 * Connect does not draw this. Its step strip is the same facts with the
 * switches that change them, and a summary above a control that states the
 * same thing is the screen saying it twice.
 *
 * Read-only, deliberately. Every fact here is changed somewhere on this
 * section, and a strip that both reported and changed state would be a second
 * place to do what one tab is already for.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * The names of the three facts every one of these tabs opens with, shared with
 * the tabs' stand-ins. The tiles after them depend on the read.
 */
export function stateLabels() {
	return {
		reading: __( 'Viewing', 'bettershield' ),
		changes: __( 'Fixes', 'bettershield' ),
		assistant: __( 'Connection', 'bettershield' ),
	};
}

/**
 * The strip's cells, from the agent-surface payload.
 *
 * @param {Object} surface The agent-surface payload.
 * @return {Array} [{ key, icon, label, value, detail, tone }]
 */
export function agentTiles( surface ) {
	const labels = stateLabels();
	const mcp = surface.mcp || {};
	const on = !! surface.abilities_enabled;
	const writes = !! surface.write_enabled;
	const waiting = Math.max( 0, Number( surface.open_requests ) || 0 );
	const tools = Number( mcp.tools ) || 0;
	const signedIn = Math.max( 0, Number( mcp.apps ) || 0 );

	/*
	 * What an assistant's side of this looks like, in the order the answer
	 * stops being "nothing can reach this site": the server has to be on
	 * before a pairing means anything, and paired before a tool count does.
	 * An app that signed in through the browser holds access with no pairing
	 * at all — the hub never mints one — so it is counted rather than read as
	 * nothing being there.
	 */
	// A credential issued and not yet used is not a connection (#2062).
	const waitingCredential = Boolean( mcp.connected ) && false === mcp.used;

	const assistant = ! mcp.enabled
		? { value: __( 'Off', 'bettershield' ), badge: 'neutral', detail: __( 'No assistant can connect', 'bettershield' ) }
		: mcp.connected && ! waitingCredential
		? { value: __( 'Connected', 'bettershield' ), badge: 'brand', detail: __( 'Connected to this site', 'bettershield' ) }
		: signedIn <= 0 && waitingCredential
		? {
				value: __( 'Waiting', 'bettershield' ),
				badge: 'neutral',
				detail: __( 'Key created; no assistant has used it yet', 'bettershield' ),
		  }
		: signedIn > 0
		? {
				value: __( 'Signed in', 'bettershield' ),
				badge: 'brand',
				detail: sprintf(
					/* translators: %d: how many apps hold access to this site. */
					_n( '%d app holds access', '%d apps hold access', signedIn, 'bettershield' ),
					signedIn
				),
		  }
		: { value: __( 'None', 'bettershield' ), badge: 'neutral', detail: __( 'On, nothing connected yet', 'bettershield' ) };

	/*
	 * Reading first, because nothing an agent does here is possible without
	 * it and every other fact is conditional on it. A state is a word, not a
	 * figure, so it is drawn as a badge rather than in the figure's type
	 * (#2310): on in brand, off in neutral, since off is a choice this
	 * product supports rather than a fault to flag. Only a request waiting is
	 * toned, because it is the one fact here that asks for something.
	 */
	const tiles = [
		{
			key: 'reading',
			icon: 'eye',
			label: labels.reading,
			value: on ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ),
			badge: on ? 'brand' : 'neutral',
			detail: on
				? __( 'AI assistants can see this site', 'bettershield' )
				: __( 'Assistants can’t see anything', 'bettershield' ),
		},
		{
			key: 'changes',
			icon: 'pencil',
			label: labels.changes,
			value: writes ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ),
			badge: writes ? 'brand' : 'neutral',
			detail: writes
				? __( 'Undoable fixes apply; others ask you first', 'bettershield' )
				: __( 'Assistants can’t fix anything', 'bettershield' ),
		},
		{
			key: 'assistant',
			icon: 'bot',
			label: labels.assistant,
			...assistant,
		},
	];

	// A tool count only means something once something could call one. With
	// the server off it would be a number describing nothing.
	if ( mcp.enabled ) {
		tiles.push( {
			key: 'tools',
			icon: 'wrench',
			label: __( 'Tools', 'bettershield' ),
			value: String( tools ),
			detail: _n( 'Tool offered', 'Tools offered', tools, 'bettershield' ),
		} );
	}

	// Shown only when there is something to ask: "0 waiting" is the ordinary
	// state, and a tile for it would give that a place on every tab.
	if ( waiting > 0 ) {
		tiles.push( {
			key: 'waiting',
			icon: 'inbox',
			label: __( 'Requests', 'bettershield' ),
			value: String( waiting ),
			detail: _n( 'Request waiting for you', 'Requests waiting for you', waiting, 'bettershield' ),
			tone: 'caution',
		} );
	}

	return tiles;
}
