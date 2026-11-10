/**
 * The Fix panels whose usual choice is safe to make in one press, applied
 * from the finding's row and from the bulk bar.
 *
 * Each reads what its panel reads, takes the choice the panel starts with
 * (every folder, plugin, theme or account it lists that can be changed
 * here, or the mode it proposes), and sends it through the route the panel
 * itself calls. What comes back holds the undo handle of every change made,
 * so one Undo puts back all of them. Anything the panel would refuse, or
 * nothing left to change, is not guessed at: the press says so, and the
 * panel stays one press away for any other choice.
 */

import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';

const BASE = '/bettershield/v1/findings/';

/** What can be changed here: the rows the panel offers a control for. */
const offered = ( rows ) => ( Array.isArray( rows ) ? rows.filter( ( row ) => '' === row.refused ) : [] );

/** One update route for both findings that list plugins to update. */
const updates = ( id ) => ( {
	// Both list the same plugins: one press updates them for both.
	share: 'plugin-updates',
	shared: true,
	key: 'plugin-update',
	// An update cannot be fully undone, so it is asked about first.
	confirm: true,
	caution: () => __( 'A plugin update can’t be fully undone. Undo puts the earlier code back, not its database changes.', 'bettershield' ),
	name: () => __( 'Update the listed plugins', 'bettershield' ),
	read: `${ BASE }${ id }/updates`,
	steps: ( state ) => offered( state.rows ).map( ( row ) => ( { path: `${ BASE }${ id }/updates`, data: { plugin: row.file }, items: [ row.name || row.file ] } ) ),
	tokens: ( answer ) => [ answer.undo ],
	undo: `${ BASE }${ id }/updates/undo`,
} );

/**
 * Each finding with a safe default, by its key.
 *
 * `read` is the panel's own read, `steps( state )` what pressing sends,
 * each with the `items` it changes, named, so the question and the alert
 * can say which (#2638), and
 * `tokens( answer )` the undo handles in each answer, sent back to `undo`.
 * `key` is the panel's working key, `share` names findings one press
 * answers together, and `confirm` asks once before the press, saying
 * `caution` as it does. `shared` marks a route that changes what every
 * site on a network shares, which only a network administrator may.
 */
export const DEFAULTS = {
	config_world_writable: {
		key: 'config-mode',
		shared: true,
		name: () => __( 'Stop other accounts writing to wp-config.php', 'bettershield' ),
		read: `${ BASE }config_world_writable/mode`,
		steps: ( state ) => ( ! state.windows && state.writable && '' === state.refused ? [ { path: `${ BASE }config_world_writable/mode` } ] : [] ),
		tokens: ( answer ) => [ answer.undo ],
		undo: `${ BASE }config_world_writable/mode/undo`,
	},
	content_dirs_world_writable: {
		key: 'content-folders',
		shared: true,
		name: () => __( 'Stop other accounts changing the listed folders', 'bettershield' ),
		read: `${ BASE }content_dirs_world_writable/folders`,
		steps: ( state ) => {
			const folders = state.windows ? [] : offered( state.folders ).map( ( folder ) => folder.name );

			return folders.length ? [ { path: `${ BASE }content_dirs_world_writable/folders`, data: { folders }, items: folders } ] : [];
		},
		tokens: ( answer ) => ( answer.changed || [] ).map( ( row ) => row.undo ),
		undo: `${ BASE }content_dirs_world_writable/folders/undo`,
	},
	plugin_updates_available: updates( 'plugin_updates_available' ),
	vulnerabilities_known: updates( 'vulnerabilities_known' ),
	inactive_extensions: {
		key: 'extensions',
		shared: true,
		name: () => __( 'Move the listed plugins and themes to quarantine', 'bettershield' ),
		read: `${ BASE }inactive_extensions/extensions`,
		steps: ( state ) => offered( state.rows ).map( ( row ) => ( { path: `${ BASE }inactive_extensions/extensions`, data: { kind: row.kind, id: row.id }, items: [ row.name || row.id ] } ) ),
		tokens: ( answer ) => [ answer.undo ],
		undo: `${ BASE }inactive_extensions/extensions/undo`,
	},
	privileged_account_dormant: {
		key: 'dormant-accounts',
		// It stops people signing in, so it is asked about first.
		confirm: true,
		caution: () => __( 'A suspended account can’t sign in until you let it back in. Nothing is deleted.', 'bettershield' ),
		name: () => __( 'Suspend the listed accounts', 'bettershield' ),
		read: `${ BASE }privileged_account_dormant/accounts`,
		steps: ( state ) => {
			const rows = offered( state.accounts );
			const accounts = rows.map( ( row ) => row.id );

			return accounts.length ? [ { path: `${ BASE }privileged_account_dormant/suspend`, data: { accounts }, items: rows.map( ( row ) => row.login || String( row.id ) ) } ] : [];
		},
		tokens: ( answer ) => ( answer.suspended || [] ).map( ( row ) => row.undo ),
		undo: `${ BASE }privileged_account_dormant/suspend/undo`,
	},
};

/**
 * The finding's safe default, or null where it has none.
 *
 * @param {Object} finding The finding.
 * @return {?Object} Its entry in DEFAULTS.
 */
export const defaultOf = ( finding ) => {
	const entry = ( finding && DEFAULTS[ finding.id ] ) || null;

	return entry && entry.shared && sharedCodeHeld() ? null : entry;
};

/**
 * Whether the reader is a site administrator on a network, for whom the
 * code and files every site shares are the network administrator's: the
 * routes refuse them, so nothing offers it (#2639).
 *
 * @return {boolean} True where the shared-code routes would refuse.
 */
export const sharedCodeHeld = () => false === ( ( window.bettershield || {} ).can || {} ).shared_code;

/** The findings whose only fix changes the server's shared files. */
export const SHARED_FILES = [ 'config_world_writable', 'content_dirs_world_writable' ];

/** What a press that could not choose for the owner answers. */
export const NEEDS_CHOICE = 'bettershield_needs_choice';

/**
 * One store action as a promise, and a turn of the event loop after it:
 * the store lets go of an action only after its callbacks have run.
 *
 * @param {Function} run  The store's runFix.
 * @param {string}   key  The working key.
 * @param {Object}   step `{ path, data }`.
 * @return {Promise<Object>} The answer; rejected with the error, or null when a password prompt was canceled.
 */
const send = ( run, key, step ) =>
	new Promise( ( resolve, reject ) => {
		run(
			step.path,
			key,
			step.data,
			( answer ) => resolve( answer || {} ),
			( error ) => {
				reject( error || null );

				// Said by whoever pressed, beside what was pressed.
				return true;
			}
		);
	} ).then( ( answer ) => new Promise( ( resolve ) => setTimeout( () => resolve( answer ), 0 ) ) );

/**
 * Apply a finding's default.
 *
 * @param {Object}   finding The finding.
 * @param {Function} run     The store's runFix.
 * @return {Promise<{id: string, key: string, undo: string, tokens: Array<string>, name: string}>} What Undo needs. Rejected with the error, with null when a password prompt was canceled, or with `NEEDS_CHOICE` when nothing could be chosen here.
 */
export async function applyDefault( finding, run ) {
	const entry = defaultOf( finding );
	const state = await apiFetch( { path: entry.read } );
	const steps = entry.steps( state || {} );

	if ( ! steps.length ) {
		const error = new Error( __( 'This one needs a choice first. Other Options shows why.', 'bettershield' ) );

		error.code = NEEDS_CHOICE;
		throw error;
	}

	const tokens = [];
	// Each step is its own change with its own Undo: one refused leaves the
	// rest to be tried, and is said with its reason (#2637).
	const failed = [];
	let done = 0;
	// What was changed, by name, for the alert that says so (#2638).
	const changed = [];

	for ( const step of steps ) {
		try {
			// eslint-disable-next-line no-await-in-loop
			const answer = await send( run, entry.key, step );

			tokens.push( ...entry.tokens( answer ).filter( Boolean ) );
			done++;
			changed.push( ...( step.items || [] ) );
		} catch ( error ) {
			// A canceled password prompt stops the press: nothing more is sent.
			if ( ! error ) {
				if ( tokens.length ) {
					break;
				}

				throw error;
			}

			failed.push( { label: ( step.items || [] )[ 0 ] || '', message: error.message || '' } );
		}
	}

	if ( ! tokens.length ) {
		// Every step refused: the server's own reason, which may say what it
		// left behind. A refused move can still have kept a copy in quarantine.
		const refused = failed.find( ( item ) => item.message );

		throw new Error( refused ? refused.message : __( 'That did not complete. Try again.', 'bettershield' ) );
	}

	return { id: finding.id, key: entry.key, undo: entry.undo, tokens, name: entry.name(), changed, done, total: steps.length, failed };
}

/**
 * What a default that changed only part of its list says: how many of how
 * many, and the first that was not changed with the server's reason.
 *
 * @param {Object} record What applyDefault answered.
 * @return {string} The sentence, or '' when every step was applied.
 */
export function partialWords( record ) {
	if ( ! record || ! record.failed || ! record.failed.length ) {
		return '';
	}

	const first = record.failed[ 0 ];
	const why = first.label && first.message ? sprintf( /* translators: 1: a plugin, theme or folder, 2: why it was not changed. */ __( '%1$s: %2$s', 'bettershield' ), first.label, first.message ) : first.message || first.label;

	return sprintf(
		/* translators: 1: how many were changed, 2: how many were tried, 3: the first that was not, with why. */
		_n( '%1$d of %2$d changed. Not changed: %3$s', '%1$d of %2$d changed. Not changed: %3$s', record.total, 'bettershield' ),
		record.done,
		record.total,
		why
	);
}

/**
 * What a default would change, by name, read as its panel reads it.
 *
 * @param {Object} finding The finding.
 * @return {Promise<Array<string>>} The folders, plugins, themes or accounts; empty where nothing could be chosen.
 */
export async function previewDefault( finding ) {
	const entry = defaultOf( finding );
	const state = await apiFetch( { path: entry.read } );

	return entry.steps( state || {} ).reduce( ( names, step ) => names.concat( step.items || [] ), [] );
}

/**
 * A fix's name with what it changes, the first few and how many more:
 * "Move the listed plugins and themes to quarantine: acme-gallery, …".
 *
 * @param {string}        name  The fix's name.
 * @param {Array<string>} items What it changes, by name.
 * @return {string} The name alone where the list is empty.
 */
export function namedWith( name, items ) {
	const list = items || [];

	if ( ! list.length ) {
		return name;
	}

	const shown =
		list.length <= 4
			? list.join( ', ' )
			: sprintf(
					/* translators: 1: the first few names, comma separated, 2: how many more there are. */
					__( '%1$s and %2$d more', 'bettershield' ),
					list.slice( 0, 4 ).join( ', ' ),
					list.length - 4
			  );

	/* translators: 1: a fix's name, 2: what it changes, by name. */
	return sprintf( __( '%1$s: %2$s', 'bettershield' ), name, shown );
}

/**
 * Put back everything a default changed, the last change first.
 *
 * @param {Object}   record What applyDefault answered.
 * @param {Function} run    The store's runFix.
 * A change put back leaves the record, so pressing Undo again after one
 * failed sends only what is still changed.
 *
 * @return {Promise<void>} Rejected with the first error, or null when a password prompt was canceled.
 */
export async function undoDefault( record, run ) {
	for ( const token of [ ...record.tokens ].reverse() ) {
		// eslint-disable-next-line no-await-in-loop
		await send( run, record.key, { path: record.undo, data: { undo: token } } );
		record.tokens = record.tokens.filter( ( other ) => other !== token );
	}
}
