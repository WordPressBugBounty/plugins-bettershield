/**
 * The rules behind Activity › File changes: what kind of difference a row
 * is, how loud it is, which question was asked of it, and how the report
 * groups its rows by what can be done about them.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
import { formatCount } from '../../ui/count';
import { mayChangeSharedCode } from '../../nav';

/** How many files a group lists before the rest wait behind "Show all". */
export const GROUP_SHOWN = 10;

/**
 * What kind of difference this is, in words rather than a code.
 *
 * @param {string} type The change type the report sends.
 * @return {string} The word.
 */
export function changeLabel( type ) {
	switch ( type ) {
		case 'modified':
			return __( 'Changed', 'bettershield' );
		case 'added':
			return __( 'Added', 'bettershield' );
		case 'removed':
			return __( 'Missing', 'bettershield' );
		case 'unreadable':
			return __( 'Could not be read', 'bettershield' );
		default:
			return type;
	}
}

/**
 * How loud a difference is. An altered or unexpected file is the loudest thing
 * this plugin reports; a missing one is routinely a locale build or a host
 * tidying up, and is rated to match. A file that is present but unreadable
 * says something about the server's permissions, not about the site's code.
 *
 * @param {string} type   The change type the report sends.
 * @param {string} graded The grade the report sends with it, where it does.
 * @return {string} One of the five severities.
 */
export function changeSeverity( type, graded = '' ) {
	// The server's grade, by the rule the activity log and the alerts grade
	// the same file by; the type alone graded every unpublished file critical
	// while those said medium (#1831).
	if ( [ 'critical', 'high', 'medium', 'low', 'info' ].includes( graded ) ) {
		return graded;
	}

	if ( 'unreadable' === type ) {
		return 'low';
	}

	return 'removed' === type ? 'medium' : 'critical';
}

/**
 * Which question was asked of this file.
 *
 * Core and directory plugins are compared against what their publisher
 * shipped. Drop-ins, must-use plugins, the theme, a commercial plugin the
 * directory has no answer for, and the configuration files at the root of
 * the site all have no publisher answer to compare against — so they are
 * compared against what they were last time. A weaker claim, and the screen
 * says so rather than implying an authority that does not exist.
 *
 * @param {string} context Where the file lives, as the report names it.
 * @return {?string} The weaker claim, or null for a published copy.
 */
export function claimFor( context ) {
	switch ( context ) {
		case 'dropin':
		case 'muplugin':
		case 'theme':
		case 'unlisted':
		case 'config':
			return __( 'compared with this file’s earlier version on your site', 'bettershield' );
		default:
			return null;
	}
}

/**
 * A group's changes by kind, in the words each row is labeled with
 * (changeLabel), which is how every surface counts them: the same three
 * numbers worded four ways read as four different facts.
 *
 * @param {Object} item A group or its preview, with `modified`, `added` and `removed`.
 * @return {string} The phrase.
 */
export function packageCounts( item ) {
	// Only the kinds there are: "0 added, 0 missing" said nothing (#2367).
	const parts = [
		/* translators: %s: files that differ from the official copy. */
		item.modified ? sprintf( _n( '%s changed', '%s changed', item.modified, 'bettershield' ), formatCount( item.modified ) ) : '',
		/* translators: %s: files that are not in the official release. */
		item.added ? sprintf( _n( '%s added', '%s added', item.added, 'bettershield' ), formatCount( item.added ) ) : '',
		/* translators: %s: official files that are missing. */
		item.removed ? sprintf( _n( '%s missing', '%s missing', item.removed, 'bettershield' ), formatCount( item.removed ) ) : '',
	].filter( Boolean );

	return parts.length ? parts.join( ', ' ) : __( 'No changes', 'bettershield' );
}

/**
 * What a group that cannot be put back holds, named by why.
 *
 * Each of these groups is keyed by its reason, and every one was headed "No
 * official copy to put back", so files nobody published, files that are
 * missing and a changed wp-config.php sat under the same heading two or three
 * times, told apart only by the note under each.
 *
 * @param {Object} change The first change in the group.
 * @return {string} The group's heading.
 */
export function groupLabel( change ) {
	switch ( change.change_type ) {
		case 'added':
			return __( 'Added files that are not in the official release', 'bettershield' );
		case 'removed':
			return __( 'Missing files', 'bettershield' );
		case 'unreadable':
			return __( 'Files that could not be read', 'bettershield' );
	}

	if ( claimFor( change.context ) ) {
		return __( 'Changed files with no official copy to compare (your theme, plugins from outside WordPress.org, settings files)', 'bettershield' );
	}

	if ( ! change.version ) {
		return __( 'Changed files from an unknown version', 'bettershield' );
	}

	return sprintf(
		/* translators: %s: the version a file was compared against. */
		__( 'Compared with version %s, but a different version is installed now. Check again.', 'bettershield' ),
		change.version
	);
}

/**
 * The changes, in groups by what can be done about them: files that can be
 * put back first, then whole packages, then files with no official copy.
 *
 * On a site with a few hundred changes the list was one run of identical
 * rows, and every file nothing had published repeated the same sentence
 * underneath it — the report ran to tens of thousands of pixels saying one
 * thing two hundred times. A group whose files share a reason says it once,
 * in its heading. Within a group the order is the report's own, newest first.
 *
 * @param {Object[]} changes The changes, newest first.
 * @return {Object[]} `{ key, label, note, changes }` per group, in reading order.
 */
export function groupChanges( changes ) {
	const groups = [];

	changes.forEach( ( change ) => {
		let key = 'why:' + ( change.why_not || '' );
		let label = groupLabel( change );
		let note = change.why_not || null;

		if ( 'core' === change.context && ! change.restorable && 'package_mismatch' !== change.change_type ) {
			// WordPress core's own files, above every plugin's: the classic
			// sign of a compromised site sat after one plugin's rows (#2118).
			// Core files that can be put back lead that group instead.
			key = 'core:' + ( change.why_not || '' );
			label = sprintf(
				/* translators: %s: what a group of changed files holds, e.g. "Files nobody published". */
				__( 'WordPress core: %s', 'bettershield' ),
				label
			);
		} else if ( 'package_mismatch' === change.change_type ) {
			key = 'package';
			label = __( 'Plugins that don’t match the official download', 'bettershield' );
			note = null;
		} else if ( change.restorable ) {
			key = 'restorable';
			label = __( 'Can be restored', 'bettershield' );
			note = mayChangeSharedCode()
				? __( 'Press Show the Difference, then restore the official file or accept your change.', 'bettershield' )
				: __( 'Press Show the Difference to see what changed.', 'bettershield' );
		}

		let group = groups.find( ( candidate ) => candidate.key === key );

		if ( ! group ) {
			group = { key, label, note, changes: [] };
			groups.push( group );
		}

		group.changes.push( change );
	} );

	const rank = ( key ) => {
		if ( 'restorable' === key ) {
			return 0;
		}

		// After what can be put back, whose core files lead it, and before
		// any plugin's (#2118).
		if ( key.startsWith( 'core:' ) ) {
			return 0.5;
		}

		return 'package' === key ? 1 : 2;
	};

	return groups.sort( ( a, b ) => rank( a.key ) - rank( b.key ) );
}

/**
 * The order the rows stand in on screen, which is the order of the groups.
 *
 * @param {Object[]} changes The changes, newest first.
 * @return {number[]} Their ids, top to bottom.
 */
export function screenOrder( changes ) {
	return groupChanges( changes ).flatMap( ( group ) => group.changes.map( ( row ) => row.id ) );
}

/** The most changes one marking takes: the server's own bound. */
export const MARK_AT_ONCE = 500;
/** The most files one question puts back from their official copies. */
export const RESTORE_AT_ONCE = 100;
/** How many go in one request: each is a request to WordPress.org. */
export const RESTORE_CHUNK = 25;
/** How many added code files a question names before it counts the rest. */
export const NAMED_CODE = 20;

/**
 * Whether a change can be one of a selection: every file change, never a
 * whole package's difference, which is answered by adopting it.
 *
 * @param {Object} change A row of the report.
 * @return {boolean} Whether it can be picked.
 */
export function selectableChange( change ) {
	return 'package_mismatch' !== change.change_type;
}

/**
 * What a selection holds, by kind in the words each row is labeled with,
 * how many can be put back, and every added file that can run as code, by
 * path: the ones a decision about many rows could hide.
 *
 * @param {Object[]} rows The selected changes.
 * @return {{modified: number, added: number, removed: number, unreadable: number, restorable: number, code: string[]}} The counts.
 */
export function selectionCounts( rows ) {
	const counts = { modified: 0, added: 0, removed: 0, unreadable: 0, restorable: 0, code: [] };

	rows.forEach( ( row ) => {
		if ( [ 'modified', 'added', 'removed', 'unreadable' ].includes( row.change_type ) ) {
			counts[ row.change_type ]++;
		}

		if ( row.restorable ) {
			counts.restorable++;
		}

		// The report's own answer (`can_run`, from the server's single list of
		// what a web server runs as code), so the question names exactly the
		// files the rows badge and the log counts.
		if ( 'added' === row.change_type && row.can_run && ! counts.code.includes( row.path ) ) {
			counts.code.push( row.path );
		}
	} );

	return counts;
}

/**
 * A selection's kinds in one phrase, the unreadable ones said only when there are some.
 *
 * @param {Object} counts From selectionCounts().
 * @return {string} The phrase.
 */
export function selectionPhrase( counts ) {
	const phrase = packageCounts( counts );

	return counts.unreadable
		? sprintf(
				/* translators: 1: the changes by kind, e.g. "8 altered, 3 not published, 1 missing"; 2: how many could not be read. */
				__( '%1$s, %2$d could not be read', 'bettershield' ),
				phrase,
				counts.unreadable
		  )
		: phrase;
}

/** How many kept copies go in one request, put back or removed. */
export const KEPT_AT_ONCE = 50;
/** The most kept copies one question removes for good. */
export const REMOVE_AT_ONCE = 50;

/**
 * A set with these keys added, or taken out, leaving the one given as it was.
 *
 * @param {Set}     set  The keys now.
 * @param {Array}   keys The keys to change.
 * @param {boolean} on   Add them, or take them out.
 * @return {Set} The new set.
 */
export function toggled( set, keys, on ) {
	const next = new Set( set );

	keys.forEach( ( key ) => ( on ? next.add( key ) : next.delete( key ) ) );

	return next;
}

/**
 * A list in pieces no larger than asked.
 *
 * @param {Array}  list The list.
 * @param {number} size The largest piece.
 * @return {Array[]} The pieces, in order.
 */
export function chunk( list, size ) {
	const parts = [];

	for ( let at = 0; at < list.length; at += size ) {
		parts.push( list.slice( at, at + size ) );
	}

	return parts;
}

/** The most changes one marking of every match takes: the server's own bound. */
export const MATCHING_AT_ONCE = 5000;

/** No filter: every open change. */
export const NO_FILTER = Object.freeze( { place: '', change_type: '', severity: '', search: '' } );

/**
 * The contexts each place covers, as the server's filter counts them
 * (Report::PLACES): a plugin nothing publishes is a plugin.
 */
const PLACES = {
	core: [ 'core' ],
	plugin: [ 'plugin', 'unlisted' ],
	theme: [ 'theme' ],
	other: [ 'extra', 'dropin', 'muplugin', 'config' ],
};

/**
 * Whether a filter narrows anything.
 *
 * @param {Object} filter { place, change_type, severity, search }.
 * @return {boolean} Whether any part of it is set.
 */
export function isFiltered( filter ) {
	return Boolean( filter && ( filter.place || filter.change_type || filter.severity || ( filter.search || '' ).trim() ) );
}

/**
 * The filter's parts that are set, in a fixed order, for a request.
 *
 * @param {Object} filter { place, change_type, severity, search }.
 * @return {Object} Only the parts that narrow.
 */
export function filterParams( filter ) {
	const out = {};

	[ 'place', 'change_type', 'severity', 'search' ].forEach( ( key ) => {
		const value = 'search' === key ? ( filter?.[ key ] || '' ).trim() : filter?.[ key ] || '';

		if ( value ) {
			out[ key ] = value;
		}
	} );

	return out;
}

/**
 * The filter as a query string, led by `?`, or nothing at all when it
 * narrows nothing, so an unfiltered read is the route as it always was.
 *
 * @param {Object} filter { place, change_type, severity, search }.
 * @param {Object} extra  More parameters, such as a cursor.
 * @return {string} The query.
 */
export function filterQuery( filter, extra = {} ) {
	const parts = Object.entries( { ...filterParams( filter ), ...extra } )
		.filter( ( [ , value ] ) => '' !== value && null !== value && undefined !== value )
		.map( ( [ key, value ] ) => `${ key }=${ encodeURIComponent( value ) }` );

	return parts.length ? `?${ parts.join( '&' ) }` : '';
}

/**
 * Whether a row is one the filter keeps, by the rule the server applies:
 * the row's own grade, its place, its kind, and the search anywhere in its
 * path or folder name, ignoring case.
 *
 * @param {Object} row    A row of the report.
 * @param {Object} filter { place, change_type, severity, search }.
 * @return {boolean} Whether it matches.
 */
export function matchesFilter( row, filter ) {
	const search = ( filter.search || '' ).trim().toLowerCase();

	if ( filter.place && ! ( PLACES[ filter.place ] || [] ).includes( row.context ) ) {
		return false;
	}

	if ( filter.change_type && filter.change_type !== row.change_type ) {
		return false;
	}

	if ( filter.severity && filter.severity !== changeSeverity( row.change_type, row.severity ) ) {
		return false;
	}

	return ! search || `${ row.path || '' }`.toLowerCase().includes( search ) || `${ row.slug || '' }`.toLowerCase().includes( search );
}

/**
 * An answer to an action, which is the whole open list, as the narrowed
 * screen shows it. Where the answer holds every open change, the rows the
 * filter keeps are exactly the list; where it is one page of many, the rows
 * on screen stay, less any the answer shows resolved, until the narrowed
 * list is read again.
 *
 * @param {?Object} current The report on screen.
 * @param {Object}  data    The answer.
 * @param {Object}  filter  The filter on screen.
 * @return {{report: Object, stale: boolean}} What to show, and whether to read the narrowed list again.
 */
export function filteredAnswer( current, data, filter ) {
	if ( ! data || ! isFiltered( filter ) || ! Array.isArray( data.changes ) ) {
		return { report: data, stale: false };
	}

	if ( ! data.next_cursor ) {
		const changes = data.changes.filter( ( row ) => matchesFilter( row, filter ) );

		return { report: { ...data, changes, next_cursor: null, matching: changes.length }, stale: false };
	}

	return {
		report: { ...data, changes: current?.changes || [], next_cursor: current?.next_cursor || null, matching: current?.matching ?? null },
		stale: true,
	};
}

/**
 * The choices of each filter, the first of each narrowing nothing.
 *
 * @return {{place: Array, change_type: Array, severity: Array}} [{ value, label }] for each.
 */
export function filterOptions() {
	return {
		place: [
			{ value: '', label: __( 'Everywhere', 'bettershield' ) },
			{ value: 'core', label: __( 'WordPress core', 'bettershield' ) },
			{ value: 'plugin', label: __( 'Plugins', 'bettershield' ) },
			{ value: 'theme', label: __( 'Themes', 'bettershield' ) },
			{ value: 'other', label: __( 'Other files (wp-config.php, must-use plugins)', 'bettershield' ) },
		],
		change_type: [
			{ value: '', label: __( 'Any change', 'bettershield' ) },
			...[ 'modified', 'added', 'removed', 'unreadable' ].map( ( type ) => ( { value: type, label: changeLabel( type ) } ) ),
		],
		severity: [
			{ value: '', label: __( 'Any severity', 'bettershield' ) },
			{ value: 'critical', label: __( 'Critical', 'bettershield' ) },
			{ value: 'high', label: __( 'High', 'bettershield' ) },
			{ value: 'medium', label: __( 'Medium', 'bettershield' ) },
			{ value: 'low', label: __( 'Low', 'bettershield' ) },
		],
	};
}
