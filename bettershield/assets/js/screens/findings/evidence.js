/**
 * A finding's evidence in words, for the checks with no renderer of their own.
 *
 * The fallback printed each key as it was stored and each value as JSON:
 * "REASON enforcement_not_attached", "EVENTS [{…}]", "COMPLETE true". Keys
 * this knows are named, codes this knows are said, lists are drawn as lists
 * and times as times. A key or code it does not know yet is still shown,
 * made readable rather than hidden, so nothing a check reports goes missing.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime } from '../../store';
import { brand } from '../../nav';

/** Keys another part of the screen already says, so they are not repeated. */
export const HIDDEN_KEYS = [ 'complete' ];

/*
 * A key named for the one check that stores it, where the shared name says
 * too little there (#2819): "Count" of what, and a second "Checked" time in
 * a panel that already says when the finding was last checked.
 */
const CHECK_LABELS = {
	plugin_updates_available: { count: () => __( 'Plugins with updates', 'bettershield' ) },
	artifacts_downloadable: { checked_at: () => __( 'Files tested', 'bettershield' ) },
};

/**
 * What an evidence key is called.
 *
 * @param {string} key   The key as the check stores it.
 * @param {string} check The finding's check, for a name only it uses.
 * @return {string} Its name.
 */
export function evidenceLabel( key, check = '' ) {
	if ( CHECK_LABELS[ check ] && CHECK_LABELS[ check ][ key ] ) {
		return CHECK_LABELS[ check ][ key ]();
	}

	const labels = {
		added: __( 'Added', 'bettershield' ),
		altered: __( 'Changed', 'bettershield' ),
		missing: __( 'Missing', 'bettershield' ),
		clutter: __( 'Of them, at the site root', 'bettershield' ),
		packages: __( 'Plugins that differ from the WordPress.org version', 'bettershield' ),
		unreadable: __( 'Could not be read', 'bettershield' ),
		files: __( 'Files', 'bettershield' ),
		total: __( 'In all', 'bettershield' ),
		count: __( 'Count', 'bettershield' ),
		unsalted: __( 'Of them, saved the old, weak way', 'bettershield' ),
		checked_at: __( 'Checked', 'bettershield' ),
		data_as_of: __( 'Data as of', 'bettershield' ),
		reason: __( 'Why', 'bettershield' ),
		detail: __( 'Detail', 'bettershield' ),
		restore_test: __( 'Restore test', 'bettershield' ),
		host_backups: __( 'Host backups', 'bettershield' ),
		last_backup: __( 'Last backup', 'bettershield' ),
		active_plugins: __( 'Active backup plugins', 'bettershield' ),
		inactive_plugins: __( 'Inactive backup plugins', 'bettershield' ),
		available: __( 'Available version', 'bettershield' ),
		new_version: __( 'New version', 'bettershield' ),
		installed_version: __( 'Installed version', 'bettershield' ),
		namespaces: __( 'Plugins', 'bettershield' ),
		namespace: __( 'Plugin', 'bettershield' ),
		routes: __( 'Addresses', 'bettershield' ),
		events: __( 'Scheduled events', 'bettershield' ),
		hook: __( 'Job name', 'bettershield' ),
		next_run: __( 'Next run', 'bettershield' ),
		default_role: __( 'Role new accounts get', 'bettershield' ),
		role: __( 'Role', 'bettershield' ),
		scheme: __( 'Address scheme', 'bettershield' ),
		own_links_covered: __( 'Links WordPress already fixes when showing the page', 'bettershield' ),
		goes_back_at: __( 'Goes back to http at', 'bettershield' ),
		address: __( 'Address', 'bettershield' ),
		set_by: __( 'Shown because of', 'bettershield' ),
		user_id: __( 'User ID', 'bettershield' ),
		plugin: __( 'Plugin', 'bettershield' ),
		plugins: __( 'Plugins', 'bettershield' ),
		themes: __( 'Themes', 'bettershield' ),
		scripts: __( 'Scripts', 'bettershield' ),
		// The directory does not say when a theme left it, only that it did.
		gone_since: __( 'Noticed missing on', 'bettershield' ),
		days: __( 'Days', 'bettershield' ),
		days_left: __( 'Days left', 'bettershield' ),
		age_days: __( 'Age in days', 'bettershield' ),
		email_check: __( 'Weekly email test', 'bettershield' ),
		link: __( 'Recovery link', 'bettershield' ),
		offline_codes: __( 'Recovery codes', 'bettershield' ),
		administrators_with_email: __( 'Administrators with an email address', 'bettershield' ),
		check_overdue: __( 'Recovery check overdue', 'bettershield' ),
		accounts: __( 'Accounts', 'bettershield' ),
		administrators: __( 'Administrators with a password only', 'bettershield' ),
		other_accounts: __( 'Other privileged accounts with a password only', 'bettershield' ),
		names: __( 'Names not refused yet', 'bettershield' ),
		path: __( 'Path', 'bettershield' ),
		folder: __( 'Folder', 'bettershield' ),
		slug: __( 'Slug', 'bettershield' ),
		name: __( 'Name', 'bettershield' ),
		open: __( 'Open', 'bettershield' ),
		headers: __( 'Headers', 'bettershield' ),
		last_run: __( 'Last run', 'bettershield' ),
		last_error: __( 'Last error', 'bettershield' ),
		behind: __( 'Overdue background jobs', 'bettershield' ),
		eol_since: __( 'Support ended', 'bettershield' ),
		branch: __( 'Branch', 'bettershield' ),
		server: __( 'Server', 'bettershield' ),
		type: __( 'Type', 'bettershield' ),
		address: __( 'Address', 'bettershield' ),
		unchecked: __( 'Not checked', 'bettershield' ),
		unfiltered_html: __( 'Roles that may publish unfiltered code', 'bettershield' ),
		unfiltered_upload: __( 'Roles that may upload any file type', 'bettershield' ),
		// The scheduled-hook check's own count: what it looked at, not every
		// hook the site has scheduled, which read as a wrong count.
		scheduled: __( 'Background jobs checked (beyond WordPress and BetterShield)', 'bettershield' ),
	};

	if ( labels[ key ] ) {
		return labels[ key ];
	}

	const words = String( key ).replace( /[_-]+/g, ' ' ).trim();

	return words.charAt( 0 ).toUpperCase() + words.slice( 1 );
}

/**
 * Whether a list entry is a path on the server and what kind of thing is
 * there, which is shown as the path with a short note rather than as
 * "Path: … · Kind: folder · Php files: 2".
 *
 * @param {*} item One entry of an evidence list.
 * @return {boolean} Whether it is one.
 */
export function isPathEntry( item ) {
	return !! item && 'object' === typeof item && 'string' === typeof item.path && ( 'string' === typeof item.kind || 'string' === typeof item.means );
}

/**
 * Whether a list entry is a scheduled hook, which is said as the hook, how
 * often and when it runs next rather than as "Hook: … · Scheduled: 1".
 *
 * @param {*} item One entry of an evidence list.
 * @return {boolean} Whether it is one.
 */
export function isHookEntry( item ) {
	return !! item && 'object' === typeof item && 'string' === typeof item.hook && 'number' === typeof item.scheduled;
}

/**
 * What is at a path, beside it: a folder and how many PHP files it holds.
 * A count that stopped short of the whole folder says so.
 *
 * @param {Object} item A path entry.
 * @return {string} The note, or nothing for a plain file.
 */
export function pathEntryNote( item ) {
	if ( 'folder' !== item.kind ) {
		return '';
	}

	if ( 'number' !== typeof item.php_files ) {
		return __( 'folder', 'bettershield' );
	}

	return false === item.counted_all
		? sprintf(
				/* translators: %d: number of PHP files counted before the count stopped. */
				_n( 'folder, %d or more PHP file', 'folder, %d or more PHP files', item.php_files, 'bettershield' ),
				item.php_files
		  )
		: sprintf(
				/* translators: %d: number of PHP files in the folder. */
				_n( 'folder, %d PHP file', 'folder, %d PHP files', item.php_files, 'bettershield' ),
				item.php_files
		  );
}

/**
 * Whether a list entry is a REST namespace with routes open to visitors.
 *
 * @param {*} item One entry of an evidence list.
 * @return {boolean} Whether it is one.
 */
export function isNamespaceEntry( item ) {
	return !! item && 'object' === typeof item && 'string' === typeof item.namespace && 'number' === typeof item.open;
}

/**
 * One entry of an evidence list in words: a path as itself, with what is at it.
 *
 * @param {*} item An entry.
 * @return {string} The entry, in words.
 */
export function entryText( item ) {
	if ( isHookEntry( item ) ) {
		const said = sprintf(
			/* translators: 1: a hook name, 2: how often it runs, e.g. "hourly" or "once", 3: when it runs next. */
			__( '%1$s — %2$s, next run %3$s', 'bettershield' ),
			item.hook,
			item.schedule || __( 'once', 'bettershield' ),
			evidenceText( item.next_run, 'next_run' )
		);

		return item.scheduled > 1
			? sprintf(
					/* translators: 1: a hook, how often and when, 2: how many events it has. */
					_n( '%1$s, %2$d event', '%1$s, %2$d events', item.scheduled, 'bettershield' ),
					said,
					item.scheduled
			  )
			: said;
	}

	// A namespace by how many of its routes answer a visitor; the routes
	// themselves are listed under it (#1970).
	if ( isNamespaceEntry( item ) ) {
		return sprintf(
			/* translators: 1: a REST API namespace, 2: how many of its routes are open to visitors. */
			_n( '%1$s — %2$d open route', '%1$s — %2$d open routes', item.open, 'bettershield' ),
			item.namespace,
			item.open
		);
	}

	if ( ! isPathEntry( item ) ) {
		return evidenceText( item );
	}

	// What a path means, where the check said: "The debug log, …".
	if ( 'string' === typeof item.means && item.means ) {
		return `${ item.path } — ${ item.means }`;
	}

	return pathEntryNote( item ) ? `${ item.path } — ${ pathEntryNote( item ) }` : item.path;
}

/** Whether a key is a path on the server, which is shown as it is. */
export function isPathKey( key ) {
	return /[/.]/.test( String( key ) );
}

/*
 * A value said for the one check that stores it (#2819): the protection by
 * the name Hardening gives it, and this plugin by its name, not its file.
 */
const CHECK_VALUES = {
	file_editor_enabled: { reason: { enforcement_not_attached: () => __( 'File editor lock is off', 'bettershield' ) } },
	user_listing_public: { reason: { enforcement_not_attached: () => __( 'Username privacy is off', 'bettershield' ) } },
	own_auto_updates_off: { plugin: () => brand },
};

/**
 * One value in words.
 *
 * @param {*}      value The value as stored.
 * @param {string} key   The key it was stored under.
 * @param {string} check The finding's check, for a value only it says its own way.
 * @return {string} What it reads as.
 */
export function evidenceText( value, key = '', check = '' ) {
	const own = CHECK_VALUES[ check ] && CHECK_VALUES[ check ][ key ];

	if ( 'function' === typeof own ) {
		return own();
	}

	if ( own && 'string' === typeof value && own[ value ] ) {
		return own[ value ]();
	}

	const codes = {
		enforcement_not_attached: __( 'Switched off on Hardening', 'bettershield' ),
		// A protection switched on whose hooks something has since removed.
		hooks_detached: __( 'Switched on, but not working', 'bettershield' ),
		// Applied, and paused with every other protection while safe mode is on.
		paused_by_safe_mode: __( 'Switched on, but paused while safe mode is on', 'bettershield' ),
		not_observed: __( 'Switched on, but not detected on your site', 'bettershield' ),
		switched_off: __( 'Switched off', 'bettershield' ),
		contents_changed: __( 'The contents changed', 'bettershield' ),
		chain_broken: __( 'Earlier log entries were changed', 'bettershield' ),
		rows_removed: __( 'All log entries for that day were deleted', 'bettershield' ),
		address_unreadable: __( 'The address could not be read', 'bettershield' ),
		not_checked: __( 'Not checked', 'bettershield' ),
		// Why sign-in lockouts are not running: which proxy setting is missing.
		proxy_names_no_visitor: __( 'Your CDN or proxy doesn’t send the visitor’s address', 'bettershield' ),
		unnamed_proxy: __( 'A CDN or proxy you haven’t added is in front of your site', 'bettershield' ),
		proxy_sends_no_header: __( 'The trusted proxy does not send the visitor’s address', 'bettershield' ),
		private_address: __( 'Visitors appear to come from a private address', 'bettershield' ),
		unknown: __( 'Unknown', 'bettershield' ),
		refused: __( 'Refused', 'bettershield' ),
		off: __( 'Off', 'bettershield' ),
		on: __( 'On', 'bettershield' ),
		site_address: __( 'Site Address (URL)', 'bettershield' ),
		wordpress_address: __( 'WordPress Address (URL), where sign-ins go', 'bettershield' ),
		wp_debug: __( 'WordPress debug mode', 'bettershield' ),
		php_settings: __( 'Your server’s PHP settings', 'bettershield' ),
		rules_missing: __( 'Its settings were removed from your server file', 'bettershield' ),
		rules_altered: __( 'Its settings in your server file were changed', 'bettershield' ),
		guards_missing: __( 'A protected folder lost its protection file', 'bettershield' ),
	};

	if ( true === value ) {
		return __( 'Yes', 'bettershield' );
	}

	if ( false === value ) {
		return __( 'No', 'bettershield' );
	}

	if ( null === value || undefined === value || '' === value ) {
		return __( 'None', 'bettershield' );
	}

	// A scheduled time is kept as seconds since the epoch.
	if ( 'number' === typeof value && /^(next_run|last_run|timestamp)$/.test( key ) && value > 1e9 ) {
		return formatTime( new Date( value * 1000 ).toISOString() );
	}

	if ( 'number' === typeof value ) {
		return value.toLocaleString();
	}

	if ( Array.isArray( value ) ) {
		return value.length ? value.map( ( item ) => evidenceText( item ) ).join( ', ' ) : __( 'None', 'bettershield' );
	}

	if ( 'object' === typeof value ) {
		return Object.entries( value )
			.map( ( [ name, item ] ) =>
				sprintf(
					/* translators: 1: what a value is, 2: the value. */
					__( '%1$s: %2$s', 'bettershield' ),
					evidenceLabel( name ),
					evidenceText( item, name )
				)
			)
			.join( ' · ' );
	}

	const text = String( value );

	if ( codes[ text ] ) {
		return codes[ text ];
	}

	// A time the check recorded, in the reader's own clock.
	if ( ( /_at$|_as_of$|^next_run$|^last_run$/.test( key ) || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test( text ) ) && ! Number.isNaN( Date.parse( text ) ) ) {
		return formatTime( text );
	}

	// A reason code nothing names yet, said as words rather than as the
	// identifier, which also lets it wrap between words. Only a reason: a
	// hook, slug or option name is shown as it is, since that is what to
	// search for.
	if ( 'reason' === key && /^[a-z][a-z0-9]*(_[a-z0-9]+)+$/.test( text ) ) {
		const words = text.replace( /_/g, ' ' );

		return words.charAt( 0 ).toUpperCase() + words.slice( 1 );
	}

	return text;
}

/**
 * A finding's evidence in one line, as its row's Evidence column says it:
 * each entry's name and value, "Name: value; Name: value".
 *
 * @param {Object} evidence The evidence as stored.
 * @return {string} The line, or nothing when there is no evidence to say.
 */
export function evidenceSummary( evidence ) {
	if ( ! evidence || 'object' !== typeof evidence || Array.isArray( evidence ) ) {
		return '';
	}

	return Object.entries( evidence )
		.filter( ( [ key ] ) => ! HIDDEN_KEYS.includes( key ) )
		.map( ( [ key, value ] ) => {
			const said = Array.isArray( value ) && value.length ? value.map( ( entry ) => ( isNamespaceEntry( entry ) ? evidenceText( entry ) : entryText( entry ) ) ).join( ', ' ) : evidenceText( value, key );

			return `${ isPathKey( key ) ? key : evidenceLabel( key ) }: ${ said }`;
		} )
		.join( '; ' );
}
