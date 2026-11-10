/**
 * The Activity card's rows, from each of the four places the Activity screens
 * read, shaped alike: an icon, a label and when.
 */

/** Icons for the event types the design draws, then by area. */
const TYPE_ICONS = [
	[ /^alert/, 'bell' ],
	[ /^unpublished_/, 'code' ],
	[ /^file_|^integrity_/, 'file' ],
	[ /^login|^logout/, 'log-in' ],
	[ /^user_|^role_/, 'users' ],
	[ /password/, 'key' ],
	[ /^incident_/, 'triangle-alert' ],
	[ /^agent_|ability/, 'bot' ],
	[ /^scan_|^audit/, 'refresh-cw' ],
	[ /^hardening_/, 'shield' ],
	[ /^plugin_|^theme_|update/, 'package' ],
];

const AREA_ICONS = { access: 'lock', exposure: 'globe', configuration: 'settings-2', extensions: 'package', plugin: 'shield' };

export function eventIcon( event ) {
	const type = String( event.type || '' );
	const found = TYPE_ICONS.find( ( [ pattern ] ) => pattern.test( type ) );

	return found ? found[ 1 ] : AREA_ICONS[ event.area ] || 'activity';
}

export const fromEvents = ( events ) =>
	( events || [] ).map( ( event ) => ( { key: `e${ event.id }`, icon: eventIcon( event ), label: event.label, at: event.occurred_at } ) );

export const fromFiles = ( files ) =>
	( ( files && files.samples ) || [] ).map( ( sample ) => ( { key: `f${ sample.id }`, icon: 'file', label: sample.path, at: files.last_run_at } ) );

export const fromIncidents = ( incidents, label ) =>
	( incidents || [] ).map( ( incident ) => ( { key: `i${ incident.id }`, icon: 'triangle-alert', label: label( incident.confidence ), at: incident.updated_at || incident.opened_at } ) );

export const fromAgents = ( invocations ) =>
	( invocations || [] ).map( ( call ) => ( { key: `a${ call.id }`, icon: 'bot', label: call.ability, at: call.invoked_at } ) );

/**
 * The newest rows across every source.
 *
 * @param {Array<Array<Object>>} sources Rows from each source.
 * @param {number}               limit   How many.
 * @return {Array<Object>} The newest first.
 */
export function newest( sources, limit = 4 ) {
	return sources
		.flat()
		.filter( ( row ) => row.at )
		.sort( ( a, b ) => String( b.at ).localeCompare( String( a.at ) ) )
		.slice( 0, limit );
}
