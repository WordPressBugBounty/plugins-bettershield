/**
 * The site log's rules: what the line under an entry says, who it names,
 * which day an entry is filed under and what that day's seal says, when a
 * refusal is about the narrowing rather than the log, and the four facts the
 * log opens with.
 *
 * Shared by the log the dashboard draws and the network's log, which still
 * draws the earlier screen, so the two read the same rows the same way.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
import { activityAreas } from '../../nav';
import { scopePhrase } from '../../agents/phrases';
import { siteDay, timeOfDay, whenPhrase } from '../../ui/when';

/** A count, grouped the reader's way. */
const count = ( value ) => Number( value ).toLocaleString();

/** A stored role list ("author,editor") as a reader would list it. */
const roleList = ( value ) => ( value ? String( value ).split( ',' ).join( ', ' ) : __( 'no role', 'bettershield' ) );

/** The versions a plugin moved between, where both were recorded. */
export const versionPhrase = ( context ) =>
	context.from && context.to
		? sprintf(
				/* translators: 1: the version a plugin was updated from, 2: the version it is at now. */
				__( 'version %1$s to %2$s', 'bettershield' ),
				context.from,
				context.to
		  )
		: null;

/** The name an application password was given, where it was given one. */
const passwordName = ( context ) => [
	context.name
		? sprintf(
				/* translators: %s: the name given to an application password. */
				__( 'named %s', 'bettershield' ),
				context.name
		  )
		: null,
];

/*
 * What some events record, said in words. Keyed by event type rather than by
 * context key, because the same key can count different things on different
 * events. Any other event keeps its raw `key: value` pairs, and only where it
 * has no object to name.
 */
/**
 * A two-factor or passkey requirement's stored pairs in words: who it is
 * required of, the grace period, and what the change gave up.
 *
 * @param {Object} context The row's context.
 * @return {Array<?string>} The phrases.
 */
function requirementPhrases( context ) {
	const roles = Array.isArray( context.roles ) ? context.roles.map( String ) : null;
	const weakened = Array.isArray( context.weakened ) ? context.weakened.map( String ) : [];

	return [
		roles
			? roles.length
				? sprintf(
						/* translators: %s: the roles, comma-separated. */
						__( 'required of %s', 'bettershield' ),
						roles.join( ', ' )
				  )
				: __( 'required of no role', 'bettershield' )
			: null,
		'grace_days' in context
			? sprintf(
					/* translators: %s: number of days. */
					_n( '%s day to set it up', '%s days to set it up', Number( context.grace_days ), 'bettershield' ),
					count( context.grace_days )
			  )
			: null,
		weakened.length
			? sprintf(
					/* translators: %s: what the change gave up, comma-separated. */
					__( 'weakened: %s', 'bettershield' ),
					weakened.join( ', ' )
			  )
			: null,
	];
}

const CONTEXT_PHRASES = {
	user_role_changed: ( context ) => [
		'from' in context || 'to' in context
			? sprintf(
					/* translators: 1: the roles an account had, e.g. "editor". 2: the roles it has now. */
					__( '%1$s to %2$s', 'bettershield' ),
					roleList( context.from ),
					roleList( context.to )
			  )
			: null,
	],
	// The document's format version is the file's business, not the
	// reader's (#2060): the row says what happened and who did it.
	settings_exported: () => [],
	// What an import changed, in words rather than its stored counts.
	settings_imported: ( context ) => [
		Number( context.applied ) > 0
			? sprintf(
					/* translators: %s: number of protections an import applied. */
					_n( '%s protection applied', '%s protections applied', Number( context.applied ), 'bettershield' ),
					count( context.applied )
			  )
			: null,
		Number( context.reverted ) > 0
			? sprintf(
					/* translators: %s: number of protections an import undid. */
					_n( '%s protection undone', '%s protections undone', Number( context.reverted ), 'bettershield' ),
					count( context.reverted )
			  )
			: null,
		Number( context.settings ) > 0
			? sprintf(
					/* translators: %s: number of settings sections an import changed. */
					_n( '%s setting changed', '%s settings changed', Number( context.settings ), 'bettershield' ),
					count( context.settings )
			  )
			: null,
		Number( context.failed ) > 0
			? sprintf(
					/* translators: %s: number of changes an import could not make. */
					_n( '%s change failed', '%s changes failed', Number( context.failed ), 'bettershield' ),
					count( context.failed )
			  )
			: null,
	],
	// What a request did to the roles, in words: the roles it added or
	// removed, the capabilities it moved (named while there are few), and the
	// plugin whose activation did it (#2080).
	// What an undo left in place and why, as the CLI says it: a guard file
	// someone else changed, a change with no undo record left (#2110).
	hardening_reverted: ( context ) => [ Array.isArray( context.notes ) && context.notes.length ? context.notes.map( String ).join( ' ' ) : null ],
	role_capabilities_changed: ( context ) => {
		const list = ( value ) => ( Array.isArray( value ) ? value.map( String ) : [] );
		/*
		 * This plugin's own permission, said as Agents › Permissions says it,
		 * never as its role:capability code (#2826). The row's subject
		 * already names the role.
		 */
		const own = {
			bettershield_write_posture: {
				/* translators: Said after the role it applies to, e.g. "Administrator | can now approve AI fixes". */
				granted: __( 'can now approve AI fixes', 'bettershield' ),
				/* translators: Said after the role it applies to, e.g. "Administrator | can no longer approve AI fixes". */
				revoked: __( 'can no longer approve AI fixes', 'bettershield' ),
			},
		};
		const capOf = ( entry ) => entry.slice( entry.indexOf( ':' ) + 1 );
		const ours = ( entries, way ) => [ ...new Set( entries.filter( ( entry ) => own[ capOf( entry ) ] ).map( ( entry ) => own[ capOf( entry ) ][ way ] ) ) ];
		const others = ( entries ) => entries.filter( ( entry ) => ! own[ capOf( entry ) ] );
		// A total counts every capability moved, this plugin's among them.
		const rest = ( entries, total ) => ( Number( total ) ? Math.max( 0, Number( total ) - ( entries.length - others( entries ).length ) ) : 0 );
		const moved = ( entries, total, few, many ) => {
			const number = Number( total ) || entries.length;

			if ( ! number ) {
				return null;
			}

			return ! Number( total ) && entries.length <= 5
				? sprintf( few, entries.join( ', ' ) )
				: sprintf( many( number ), count( number ) );
		};

		return [
			list( context.roles_added ).length
				? sprintf(
						/* translators: %s: comma-separated role names. */
						__( 'new role %s', 'bettershield' ),
						list( context.roles_added ).join( ', ' )
				  )
				: null,
			list( context.roles_removed ).length
				? sprintf(
						/* translators: %s: comma-separated role names. */
						__( 'role %s removed', 'bettershield' ),
						list( context.roles_removed ).join( ', ' )
				  )
				: null,
			list( context.renamed ).length
				? sprintf(
						/* translators: %s: comma-separated role names. */
						__( 'role %s renamed', 'bettershield' ),
						list( context.renamed ).join( ', ' )
				  )
				: null,
			...ours( list( context.granted ), 'granted' ),
			moved(
				others( list( context.granted ) ),
				rest( list( context.granted ), context.granted_total ),
				/* translators: %s: comma-separated role:capability pairs. */
				__( 'granted %s', 'bettershield' ),
				/* translators: %s: number of capabilities granted. */
				( number ) => _n( '%s capability granted', '%s capabilities granted', number, 'bettershield' )
			),
			...ours( list( context.revoked ), 'revoked' ),
			moved(
				others( list( context.revoked ) ),
				rest( list( context.revoked ), context.revoked_total ),
				/* translators: %s: comma-separated role:capability pairs. */
				__( 'took away %s', 'bettershield' ),
				/* translators: %s: number of capabilities taken away. */
				( number ) => _n( '%s capability taken away', '%s capabilities taken away', number, 'bettershield' )
			),
			list( context.activated ).length
				? sprintf(
						/* translators: %s: comma-separated plugin files. */
						__( 'when %s was activated', 'bettershield' ),
						list( context.activated ).join( ', ' )
				  )
				: null,
		];
	},
	user_role_granted: ( context ) => [ context.role ? String( context.role ) : null ],
	user_role_revoked: ( context ) => [ context.role ? String( context.role ) : null ],
	// A coalesced row stands for a burst, and says how big it was.
	login_failed: ( context ) => [
		Number( context.unlogged_attempts ) > 0
			? sprintf(
					/* translators: %s: number of further failed sign-ins this entry stands for. */
					_n( 'and %s more attempt', 'and %s more attempts', Number( context.unlogged_attempts ), 'bettershield' ),
					count( context.unlogged_attempts )
			  )
			: null,
		// The names those attempts tried, so a burst is read as what it was.
		Array.isArray( context.unlogged_names ) && context.unlogged_names.length
			? sprintf(
					/* translators: %s: comma-separated names the further failed sign-ins tried. */
					__( 'as %s', 'bettershield' ),
					context.unlogged_names.map( String ).join( ', ' )
			  )
			: null,
	],
	password_reset_requested: ( context ) => [
		Number( context.unlogged_attempts ) > 0
			? sprintf(
					/* translators: %s: number of further reset requests this entry stands for. */
					_n( 'and %s more request', 'and %s more requests', Number( context.unlogged_attempts ), 'bettershield' ),
					count( context.unlogged_attempts )
			  )
			: null,
	],
	app_password_created: passwordName,
	app_password_revoked: passwordName,
	// A requirement said in words, not as its stored pairs (#1793).
	two_factor_policy_changed: requirementPhrases,
	passkey_policy_changed: requirementPhrases,
	network_2fa_policy_changed: requirementPhrases,
	network_passkey_policy_changed: requirementPhrases,
	recovery_link_generated: ( context ) => [ true === context.replaced_previous ? __( 'the previous link stopped working', 'bettershield' ) : null ],
	alert_sent: ( context ) => [
		Number( context.events ) > 1
			? sprintf(
					/* translators: %s: how many events the alert named. */
					_n( 'about %s event', 'about %s events', Number( context.events ), 'bettershield' ),
					count( context.events )
			  )
			: null,
	],
	// An assistant let in says what it may do: read, or change the site too.
	mcp_app_granted: ( context ) => [ scopePhrase( context.scope ) || null ],
	// A call that did not complete says why: in words where the reason is one
	// the connection gives, and as its code where it is the ability's own.
	ability_used: ( context ) => {
		if ( 'failed' !== context.outcome ) {
			return [];
		}

		const reasons = {
			bettershield_mcp_unknown_tool: __( 'no such tool', 'bettershield' ),
			no_tool_named: __( 'no tool was named', 'bettershield' ),
			ability_invalid_input: __( 'its input was refused', 'bettershield' ),
			ability_invalid_permissions: __( 'not allowed for this account', 'bettershield' ),
			bettershield_mcp_reads_off: __( 'agent access is off', 'bettershield' ),
			bettershield_mcp_writes_off: __( 'agent changes are off', 'bettershield' ),
			bettershield_mcp_out_of_scope: __( 'outside what the connection may do', 'bettershield' ),
			bettershield_mcp_account_cannot_write: __( 'the account may not make agent changes', 'bettershield' ),
			result_not_encodable: __( 'the answer could not be sent', 'bettershield' ),
		};

		const code = context.error ? String( context.error ) : '';

		return [ code ? ( Object.prototype.hasOwnProperty.call( reasons, code ) ? reasons[ code ] : code ) : null ];
	},
	// The versions a plugin moved between, where the update row kept them (#2344).
	plugin_updated: ( context ) => [ versionPhrase( context ) ],
	update_code_changed: ( context ) => [
		versionPhrase( context ),
		Number( context.added ) > 0
			? sprintf(
					/* translators: %s: number of code files an update added. */
					_n( '%s added', '%s added', Number( context.added ), 'bettershield' ),
					count( context.added )
			  )
			: null,
		Number( context.changed ) > 0
			? sprintf(
					/* translators: %s: number of code files an update changed. */
					_n( '%s changed', '%s changed', Number( context.changed ), 'bettershield' ),
					count( context.changed )
			  )
			: null,
		Array.isArray( context.hidden ) && context.hidden.length
			? sprintf(
					/* translators: %s: number of files whose name starts with a dot. */
					_n( '%s whose name starts with a dot', '%s whose names start with a dot', context.hidden.length, 'bettershield' ),
					count( context.hidden.length )
			  )
			: null,
	],
	buffer_overflow: ( context ) => [
		'dropped' in context
			? sprintf(
					/* translators: %s: number of events that were not recorded. */
					_n( '%s not recorded', '%s not recorded', Number( context.dropped ), 'bettershield' ),
					count( context.dropped )
			  )
			: null,
	],
	scan_completed: ( context ) => [
		'open_findings' in context
			? sprintf(
					/* translators: %s: number of open findings. */
					_n( '%s open finding', '%s open findings', Number( context.open_findings ), 'bettershield' ),
					count( context.open_findings )
			  )
			: null,
		'suppressed_findings' in context
			? sprintf(
					/* translators: %s: number of findings marked not applicable. */
					_n( '%s marked not applicable', '%s marked not applicable', Number( context.suppressed_findings ), 'bettershield' ),
					count( context.suppressed_findings )
			  )
			: null,
	],
	integrity_scan_completed: ( context ) => [
		'checked' in context
			? sprintf(
					/* translators: %s: number of files checked. */
					_n( '%s file checked', '%s files checked', Number( context.checked ), 'bettershield' ),
					count( context.checked )
			  )
			: null,
		'changed' in context
			? sprintf(
					/* translators: %s: number of files that differ from the published copy. */
					_n( '%s changed', '%s changed', Number( context.changed ), 'bettershield' ),
					count( context.changed )
			  )
			: null,
		context.unverifiable
			? sprintf(
					/* translators: %s: number of plugins, themes or core that could not be compared. */
					_n( '%s could not be compared', '%s could not be compared', Number( context.unverifiable ), 'bettershield' ),
					count( context.unverifiable )
			  )
			: null,
	],
	// The hourly look at code nobody publishes: how much it read, and what
	// it found, said once rather than as five raw pairs.
	unpublished_watch_ran: ( context ) => [
		'files' in context && 'targets' in context
			? sprintf(
					/* translators: 1: number of files, 2: number of places they were read in. */
					_n( '%1$s file in %2$s checked', '%1$s files in %2$s checked', Number( context.files ), 'bettershield' ),
					count( context.files ),
					sprintf(
						/* translators: %s: number of places files were read in. */
						_n( '%s location', '%s locations', Number( context.targets ), 'bettershield' ),
						count( context.targets )
					)
			  )
			: null,
		'changed' in context
			? Number( context.changed ) > 0
				? sprintf(
						/* translators: %s: number of files that changed. */
						_n( '%s changed', '%s changed', Number( context.changed ), 'bettershield' ),
						count( context.changed )
				  )
				: __( 'nothing changed', 'bettershield' )
			: null,
		context.partial ? __( 'stopped before the end', 'bettershield' ) : null,
	],
};

/*
 * The files some events name, set after the phrase. The ones whose name
 * starts with a dot go first, because they are the reason to read the list,
 * and any the record counted without naming are said as a number.
 */
const CONTEXT_FILES = {
	update_code_changed: ( context ) => {
		const hidden = Array.isArray( context.hidden ) ? context.hidden.map( String ) : [];
		const files = Array.isArray( context.files ) ? context.files.map( String ) : [];
		const names = [ ...hidden, ...files.filter( ( file ) => ! hidden.includes( file ) ) ];

		return { names, more: Math.max( 0, Number( context.added || 0 ) + Number( context.changed || 0 ) - names.length ) };
	},
};

/** The parts naming the files an event recorded, if it records any. */
function filesOf( type, context ) {
	const listed = context && CONTEXT_FILES[ type ] ? CONTEXT_FILES[ type ]( context ) : null;

	if ( ! listed ) {
		return [];
	}

	return [
		listed.names.length ? { text: listed.names.join( ', ' ), words: false } : null,
		listed.more > 0
			? {
					text: sprintf(
						/* translators: %s: number of further files the record counted without naming. */
						_n( 'and %s more', 'and %s more', listed.more, 'bettershield' ),
						count( listed.more )
					),
					words: true,
			  }
			: null,
	].filter( Boolean );
}

/**
 * The line under an event, assembled from the parts the server chose to
 * record: what it was about, then what it recorded about it and any files it
 * names. Every branch degrades to something readable: an event with no
 * object still says what happened and who did it. An object is named by its
 * label where the server has one (a check's or a hardening item's title, an
 * account's login), and by its id where it does not. `words` says which: an
 * id or a raw pair is an identifier, a title or a phrase is text.
 *
 * @param {Object} event One row of the log.
 * @return {Array<{text: string, words: boolean}>} The parts, possibly none.
 */
export function summarize( event ) {
	const context = event.context && typeof event.context === 'object' ? event.context : null;
	const phrased = context && CONTEXT_PHRASES[ event.type ] ? CONTEXT_PHRASES[ event.type ]( context ).filter( Boolean ) : [];
	const recorded = [ phrased.length ? { text: phrased.join( ', ' ), words: true } : null, ...filesOf( event.type, context ) ].filter( Boolean );

	// An option's name says nothing the label did not, and is an internal
	// identifier on a reader's screen (#1793): left out where nothing names it.
	const optionName = Boolean( event.object_id ) && ! event.object_label && String( event.object_id ).startsWith( 'bettershield_' );

	if ( event.object_id && ! optionName ) {
		const object = event.object_label ? { text: event.object_label, words: true } : { text: event.object_id, words: false };

		return [ object, ...recorded ];
	}

	// A setting's row: what it recorded in words, or the label alone. Its
	// stored pairs are no more a reader's words than its option name is.
	if ( optionName ) {
		return recorded;
	}

	if ( recorded.length ) {
		return recorded;
	}

	// Stored pairs are never a reader's words: "server: nginx" under a row
	// told the owner nothing (#2363). A type with no phrases above shows its
	// name and object alone.

	return [];
}

/**
 * @param {Object} event One row of the log.
 * @return {string} Who did it, as the row names them.
 */
export function actorOf( event ) {
	if ( event.actor_label ) {
		return event.actor_label;
	}

	if ( event.actor_type === 'system' ) {
		return __( 'WordPress or the server', 'bettershield' );
	}

	if ( event.actor_type === 'agent' ) {
		return __( 'Agent', 'bettershield' );
	}

	return __( 'Signed-out visitor', 'bettershield' );
}

/**
 * A stored network as the emails write it, with its hidden part as "x":
 * "203.0.113.0/24" is "203.0.113.x", "2001:db8::/64" is
 * "2001:db8:0:0:x:x:x:x" (#2826). Anything else is said as it came.
 *
 * @param {string} label The network as stored, in range notation.
 * @return {string} The network in the emails' words.
 */
export function networkWords( label ) {
	const text = String( label || '' );
	const v4 = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/24$/.exec( text );

	if ( v4 ) {
		return `${ v4[ 1 ] }.x`;
	}

	const v6 = /^([0-9a-f:]+)\/64$/i.exec( text );

	if ( ! v6 ) {
		return text;
	}

	const [ head, tail = null ] = v6[ 1 ].split( '::' );
	const left = head ? head.split( ':' ) : [];
	const right = null !== tail && tail ? tail.split( ':' ) : [];
	const groups = null === tail ? left : [ ...left, ...Array( Math.max( 0, 8 - left.length - right.length ) ).fill( '0' ), ...right ];

	if ( groups.length !== 8 || groups.some( ( group ) => ! /^[0-9a-f]{1,4}$/i.test( group ) ) ) {
		return text;
	}

	return [ ...groups.slice( 0, 4 ).map( ( group ) => parseInt( group, 16 ).toString( 16 ) ), 'x', 'x', 'x', 'x' ].join( ':' );
}

/** The clock alone. The date is on the day's row above it. */
export function clockTime( iso ) {
	const date = new Date( iso );

	return Number.isNaN( date.getTime() )
		? __( 'unknown', 'bettershield' )
		: timeOfDay( date );
}

/** The area a row belongs to, named the way the filter above it names areas. */
export function areaLabel( event ) {
	const found = activityAreas.find( ( area ) => area.slug === event.area );

	return found ? found.label : '';
}

/**
 * The day a row is filed under, on the same clock as the time beside it.
 *
 * Not UTC, because a row stamped 11:40 PM filed under tomorrow's date is a log
 * that disagrees with itself on screen.
 *
 * @param {string} iso A timestamp.
 * @return {string} YYYY-MM-DD, or '' for a timestamp that is not one.
 */
export function localDay( iso ) {
	const date = new Date( iso );

	if ( Number.isNaN( date.getTime() ) ) {
		return '';
	}

	return siteDay( date );
}

/** The UTC day a row falls in, which is the day a seal is taken over. */
function utcDay( iso ) {
	const date = new Date( iso );

	return Number.isNaN( date.getTime() ) ? '' : date.toISOString().slice( 0, 10 );
}

/**
 * The rows, split into the days they happened on.
 *
 * The log arrives in the order the server keeps it — by id, which is the
 * order rows were written — and stays that way. This only marks where one day
 * ends and the next begins, so the reader is never counting backwards from a
 * timestamp to work out whether two rows are from the same afternoon.
 *
 * Split where the day changes rather than gathered by day, and the difference
 * matters: the writer is buffered, so a request that ran long flushes its
 * rows after ones that happened later, and `occurred_at` is not guaranteed to
 * descend with the id. Gathering would reorder the log to hide that;
 * splitting shows it, and a day appearing twice is the log saying it is not
 * in time order. Sorting here would also break the cursor, which is an id.
 *
 * The group is keyed on its first row rather than on its day, because a day
 * that appears twice would otherwise be two blocks with one key.
 *
 * @param {Array} events Rows, in the order the server returned them.
 * @return {Array<{key: string, day: string, events: Array}>} Runs of one day.
 */
export function byDay( events ) {
	const days = [];

	events.forEach( ( event ) => {
		const day = localDay( event.occurred_at );
		const last = days[ days.length - 1 ];

		if ( last && last.day === day ) {
			last.events.push( event );
			return;
		}

		days.push( { key: String( event.id ), day, events: [ event ] } );
	} );

	return days;
}

/**
 * What the seal chain says about one day on screen.
 *
 * A seal covers a UTC day and the reader's day is their own, so on most of
 * the world one of these spans two sealed days. Rather than assume an offset,
 * each row is asked which UTC day it fell in and the answer is the aggregate:
 * broken if any of them failed the last check, open if any is not sealed yet
 * (still under way, or ended and waiting for the next daily check), and
 * sealed only when every one of them is.
 *
 * `null` where the daily check has never run. An empty list of broken days is
 * not a statement that the chain is intact — it is also what a site that has
 * never checked reports, and the difference is the whole value of saying so.
 *
 * @param {Object} group One day's rows.
 * @param {Object} seals What the payload said about the chain.
 * @param {string} today The reader's own today, YYYY-MM-DD.
 * @return {?{tone: string, text: string}} What to print beside the date.
 */
export function sealState( group, seals, today = localDay( new Date().toISOString() ) ) {
	if ( ! seals || ! seals.checked_at ) {
		return null;
	}

	const sealed = seals.sealed || [];
	const broken = seals.broken || [];
	const days = [ ...new Set( group.events.map( ( event ) => utcDay( event.occurred_at ) ) ) ];

	if ( days.some( ( day ) => broken.includes( day ) ) ) {
		return { tone: 'broken', text: __( 'Changed after the day ended. Entries may have been edited or removed.', 'bettershield' ) };
	}

	const unsealed = days.filter( ( day ) => ! sealed.includes( day ) );

	if ( unsealed.length ) {
		// Said of the day on the separator, which is the reader's: only the
		// reader's today is still under way. An earlier day waits for the
		// daily check, which seals each day once it has ended in UTC, even
		// where that day's last rows fall in a UTC day still under way.
		return group.day === today
			? { tone: 'open', text: __( 'Still being recorded', 'bettershield' ), today: true }
			: { tone: 'open', text: __( 'Not checked yet. The next daily check covers it.', 'bettershield' ) };
	}

	return { tone: 'intact', text: __( 'Checked, unchanged since the day ended', 'bettershield' ) };
}

/**
 * @param {string} day YYYY-MM-DD.
 * @return {string} The date, the way a person says one, with today and yesterday named.
 */
export function dayLabel( day ) {
	const today = localDay( new Date().toISOString() );

	if ( day === today ) {
		return __( 'Today', 'bettershield' );
	}

	const yesterday = new Date();
	yesterday.setDate( yesterday.getDate() - 1 );

	if ( day === localDay( yesterday.toISOString() ) ) {
		return __( 'Yesterday', 'bettershield' );
	}

	const date = new Date( `${ day }T12:00:00` );

	return Number.isNaN( date.getTime() )
		? day
		: date.toLocaleDateString( undefined, { month: 'short', day: 'numeric', year: 'numeric' } );
}

/**
 * The site's refusal of the narrowing itself, or null for any other failure.
 *
 * A parameter whose own check fails comes back as WordPress's
 * rest_invalid_param, with this plugin's code only in its details, so the
 * code on the error itself is never the one to look for.
 *
 * @param {?Object} error What the request rejected with.
 * @return {?string} The reason to say, or null.
 */
export function narrowingRefused( error ) {
	if ( ! error ) {
		return null;
	}

	// The network has a refusal of its own, which says what a network looks
	// like; read as any other failure, it replaced the whole log.
	const codes = [ 'bettershield_invalid_activity_filter', 'bettershield_invalid_activity_network' ];

	if ( codes.includes( error.code ) ) {
		return error.message || '';
	}

	const details = 'rest_invalid_param' === error.code && error.data && error.data.details ? Object.values( error.data.details ) : [];
	const refused = details.find( ( detail ) => detail && codes.includes( detail.code ) );

	return refused ? refused.message || '' : null;
}

/** No filter applied. Also the shape every filter value is read out of. */
export const NO_FILTERS = { area: 'all', search: '', actor: '', from: '', to: '', site: '', network: '' };

/**
 * One cache entry per distinct view. Every filter decides which rows belong on
 * screen, so every filter belongs in the key — a view keyed on less than it is
 * filtered by would serve one query's rows under another's.
 *
 * @param {Object} filters The narrowing.
 * @return {string} The view's key.
 */
export function viewKey( filters ) {
	return [ filters.area, filters.search, filters.actor, filters.from, filters.to, filters.site, filters.network ].join( '\u0000' );
}

/**
 * Whether a date input's value is a whole day worth asking the log for.
 *
 * A date input reports a value as soon as the first digit of the year is
 * typed — "0002-09-29" on the way to 2026 — and asking for that sent a range
 * ending in the year 2, which the site refuses. A day is taken once its year
 * has four digits and is one the log could hold.
 *
 * @param {string} value What the input reports.
 * @return {boolean} Whether it is a day to ask for.
 */
export function wholeDay( value ) {
	const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec( value || '' );

	return !! match && Number( match[ 1 ] ) >= 1970;
}

/** Today, as the date inputs express it, so a range cannot be set in the future. */
export function today() {
	const now = new Date();
	const pad = ( n ) => String( n ).padStart( 2, '0' );

	return `${ now.getFullYear() }-${ pad( now.getMonth() + 1 ) }-${ pad( now.getDate() ) }`;
}

/** The facts' names, shared by the strip and the log's stand-in. */
export function glanceLabels() {
	return {
		entries: __( 'Entries', 'bettershield' ),
		who: __( 'People and tasks', 'bettershield' ),
		seal: __( 'Log check', 'bettershield' ),
		kept: __( 'Kept for', 'bettershield' ),
	};
}

/**
 * The log in four facts: how much is recorded, who appears in it, whether the
 * sealed days still match, and how long rows are kept. Read from the page the
 * screen already fetched, so it cannot disagree with the rows under it. The
 * network log has no seal, so it has no seal tile.
 *
 * @param {Object}   props
 * @param {Object}   props.counts    Entries per area, and `all`.
 * @param {string}   props.area      The category chosen, or `all`.
 * @param {Object[]} props.actors    Who appears in the log, as the filter lists them.
 * @param {?number}  props.actorsTotal How many appear, which the list stops short of.
 * @param {?Object}  props.seals     The seal chain's last check, or undefined on the network log.
 * @param {?number}  props.retention Days of history kept.
 * @param {boolean}  props.narrowed  Whether filters narrow the view.
 * @return {Array<Object>} The tiles: { key, label, value, detail, tone }; tone is 'good' or 'caution'.
 */
export function logTiles( { counts, area = 'all', actors, actorsTotal = null, seals, retention, narrowed } ) {
	const labels = glanceLabels();
	// `all` leaves the category out, so the menu can show every category's
	// count; under a chosen category, its own count is the one that matches.
	const total = Number( ( 'all' === area ? counts.all : counts[ area ] ) || 0 );
	const tiles = [
		{
			key: 'entries',
			label: labels.entries,
			value: total.toLocaleString(),
			detail: narrowed
				? __( 'Matching these filters', 'bettershield' )
				: __( 'In the history kept here', 'bettershield' ),
		},
		{
			key: 'who',
			label: labels.who,
			// The filter's list stops at forty; the count does not.
			value: String( Number.isInteger( actorsTotal ) ? actorsTotal : actors.length ),
			detail: __( 'Everyone and everything that made an entry', 'bettershield' ),
		},
	];

	if ( undefined !== seals ) {
		const broken = ( seals && seals.broken ) || [];
		let value = __( 'Not checked yet', 'bettershield' );
		let tone;
		let detail = __( 'The daily check has not run', 'bettershield' );

		if ( seals && seals.checked_at && ! broken.length && ! ( seals.sealed || [] ).length ) {
			/*
			 * A check over no sealed day found nothing broken, which is not
			 * the chain found intact: on a new site's first day the tile said
			 * Intact above a day still open.
			 */
			value = __( 'None yet', 'bettershield' );
			detail = __( 'The first check runs after today ends', 'bettershield' );
		} else if ( seals && seals.checked_at ) {
			value = broken.length ? __( 'Changed', 'bettershield' ) : __( 'Intact', 'bettershield' );
			tone = broken.length ? 'caution' : 'good';
			detail = broken.length
				? sprintf(
						/* translators: %d: number of sealed days whose rows changed. */
						_n( '%d sealed day no longer matches', '%d sealed days no longer match', broken.length, 'bettershield' ),
						broken.length
				  )
				: sprintf(
						/* translators: %s: when the chain was last checked, e.g. "today, 3:04 AM". */
						__( 'Checked %s', 'bettershield' ),
						whenPhrase( seals.checked_at )
				  );
		}

		tiles.push( { key: 'seal', label: labels.seal, value, tone, detail } );
	}

	tiles.push( {
		key: 'kept',
		label: labels.kept,
		value: retention
			? sprintf(
					/* translators: %d: number of days. */
					_n( '%d day', '%d days', retention, 'bettershield' ),
					retention
			  )
			: '—',
		detail: __( 'Older entries are deleted after this', 'bettershield' ),
	} );

	return tiles;
}
