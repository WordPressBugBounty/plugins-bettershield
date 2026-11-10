/**
 * A settings change in words: one line per setting that differs, read from
 * the `{ from, to }` and `{ added, removed }` pairs the server sends for a
 * section, with the directions that leave the site less protected marked.
 *
 * Shared by the import plan, which says what a file would change before it
 * is applied, and the undo list, which says what each recorded change did.
 * A key this map does not know yet is still said, under its own name, so a
 * setting added to a section later is never shown as nothing.
 *
 * A map of named values arrives one line per name, under a dotted key such
 * as `surfaces.reset.enabled`. Each part is named in words, the way its
 * screen names it, rather than shown as the path.
 */

import { __, _n, _x, sprintf } from '@wordpress/i18n';
import { listOf } from '../../setup/format';
import { formatTime } from '../../store';
import { dayOptions } from './Alerts';

const off = ( change ) => true === change.from && false === change.to;
const on = ( change ) => false === change.from && true === change.to;
const lower = ( change ) => Number( change.to ) < Number( change.from );
const higher = ( change ) => Number( change.to ) > Number( change.from );
const removed = ( change ) => change.removed > 0;
const added = ( change ) => change.added > 0;

/**
 * What each section's settings are called, and which direction of a change
 * weakens the site. Called on each render, so the words follow the locale.
 *
 * @return {Object<string, Object<string, {label: string, weakens: ?Function, value: ?Function}>>} By section, then key.
 */
function settingNames() {
	const day = ( value ) => ( dayOptions().find( ( option ) => option.value === String( value ) ) || {} ).label;
	const deletion = ( value ) =>
		( {
			keep: __( 'keep everything', 'bettershield' ),
			remove: __( 'remove this plugin’s records', 'bettershield' ),
			package: __( 'keep a copy of the quarantined files, then remove everything', 'bettershield' ),
		} )[ value ];
	// A number of minutes with its unit, for a value whose label leaves the
	// unit out. Anything that is not a number is said as any value is.
	const minutes = ( value ) =>
		null === value || '' === value || ! Number.isFinite( Number( value ) )
			? undefined
			: /* translators: %d: a number of minutes. */
			  sprintf( _n( '%d minute', '%d minutes', Number( value ), 'bettershield' ), Number( value ) );

	return {
		password_policy: {
			enabled: { label: __( 'Require a minimum length for new passwords', 'bettershield' ), weakens: off },
			min_length: { label: __( 'Minimum length', 'bettershield' ), weakens: lower },
			min_length_privileged: { label: __( 'Minimum length for admins and editors', 'bettershield' ), weakens: lower },
			min_length_single_factor: { label: __( 'Minimum length with a password alone', 'bettershield' ), weakens: lower },
			single_factor_everyone: { label: __( 'Password-alone minimum for every account', 'bettershield' ), weakens: off },
		},
		login_protection: {
			enabled: { label: __( 'Sign-in protection', 'bettershield' ), weakens: off },
			attempt_limit: { label: __( 'Sign-in attempt limits', 'bettershield' ), weakens: off },
			threshold: { label: __( 'Failures allowed', 'bettershield' ), weakens: higher },
			window_minutes: { label: __( 'Counted within (minutes)', 'bettershield' ), weakens: lower },
			lockout_minutes: { label: __( 'Lockout lasts (minutes)', 'bettershield' ), weakens: lower },
			allowlist: { label: __( 'Always allowed', 'bettershield' ), weakens: added },
			blocklist: { label: __( 'Never allowed to sign in', 'bettershield' ), weakens: removed },
			trusted_proxies: { label: __( 'Addresses of your CDN or proxy', 'bettershield' ) },
			cloudflare: { label: __( 'Behind Cloudflare', 'bettershield' ) },
			honeypot: { label: __( 'Refuse obviously automated submissions', 'bettershield' ), weakens: off },
			idle_minutes: { label: __( 'Sign out after idle (minutes)', 'bettershield' ) },
			session_cap: { label: __( 'Devices signed in at once, per account', 'bettershield' ) },
			new_location_notice: { label: __( 'Tell account holders about sign-ins from a new network', 'bettershield' ), weakens: off },
			proof_of_work: { label: __( 'Slow down repeated failed sign-ins', 'bettershield' ), weakens: off },
			host_ban_line: { label: __( 'Send lockouts to the server’s firewall', 'bettershield' ), weakens: off },
			surfaces: {
				label: __( 'Limits on other forms', 'bettershield' ),
				// Each form's limit, named as Login & access names it. Its
				// switch is said under the form's own name, and each number
				// after it, so the line reads "Slow repeated sign-ups, counted
				// within: …". The unit goes with the values, since a label that
				// carried "(minutes)" stacked two parentheses.
				items: {
					comment: __( 'Send floods of comments to moderation', 'bettershield' ),
					reset: __( 'Slow repeated password reset requests', 'bettershield' ),
					register: __( 'Slow repeated sign-ups', 'bettershield' ),
				},
				fields: {
					enabled: { own: true, weakens: off },
					threshold: { label: __( 'limit per visitor', 'bettershield' ), weakens: higher },
					window_minutes: { label: __( 'counted within', 'bettershield' ), weakens: lower, value: minutes },
					lockout_minutes: { label: __( 'block lasts', 'bettershield' ), weakens: lower, value: minutes },
				},
			},
		},
		two_factor_policy: {
			roles: { label: __( 'Roles that need a second factor', 'bettershield' ), weakens: removed },
			grace_days: { label: __( 'Grace period, in days', 'bettershield' ), weakens: higher },
			store_tab: { label: __( 'Show Sign-in security on WooCommerce My Account', 'bettershield' ) },
		},
		passkey_policy: {
			roles: { label: __( 'Roles that sign in with a passkey only', 'bettershield' ), weakens: removed },
		},
		network_two_factor_policy: {
			roles: { label: __( 'Roles that need a second factor', 'bettershield' ), weakens: removed },
			grace_days: { label: __( 'Grace period, in days', 'bettershield' ), weakens: higher },
			set: { label: __( 'Network-wide requirement', 'bettershield' ) },
		},
		network_passkey_policy: {
			roles: { label: __( 'Roles that sign in with a passkey only', 'bettershield' ), weakens: removed },
			set: { label: __( 'Network-wide requirement', 'bettershield' ) },
		},
		lockdown: {
			active: { label: __( 'Site lockdown', 'bettershield' ) },
		},
		security_txt: {
			enabled: { label: __( 'Publish a security contact', 'bettershield' ) },
			contact: { label: __( 'Contact', 'bettershield' ) },
			policy: { label: __( 'Policy address', 'bettershield' ) },
			// A date as the screens say one, not its stored ISO form, and
			// left out where it only moved with the change beside it: it is
			// worked out when the file is published, not imported (#1933).
			expires: { label: __( 'Expires', 'bettershield' ), value: ( value ) => ( value ? formatTime( value ) : undefined ), computed: true },
		},
		agent_capture: {
			recording: { label: __( 'Record what agents do on this site', 'bettershield' ), weakens: off },
		},
		app_password_expiry: {
			enabled: { label: __( 'Delete unused application passwords', 'bettershield' ) },
			days: { label: __( 'Unused for (days)', 'bettershield' ) },
		},
		abilities: {
			enabled: { label: __( 'Let AI assistants see security info', 'bettershield' ) },
		},
		// The other agent switches, the decoy and the Hub link (#1824).
		agent_writes: {
			enabled: { label: __( 'Let AI assistants fix things', 'bettershield' ) },
		},
		mcp: {
			enabled: { label: __( 'Allow AI assistant connections', 'bettershield' ) },
		},
		// Counted per app, never listed: the tool names are the app's own business (#1879).
		mcp_app_tools: {
			tools_denied: { label: __( 'Tools connected apps may not use', 'bettershield' ), weakens: removed },
		},
		decoy_page: {
			enabled: { label: __( 'Decoy page', 'bettershield' ), weakens: off },
			slug: { label: __( 'Decoy address', 'bettershield' ) },
		},
		hub_link: {
			on: { label: __( 'Send this site’s security events to the hub', 'bettershield' ), weakens: off },
			posture: { label: __( 'Also send medium events and completed checks', 'bettershield' ) },
			full_log: { label: __( 'Also send the rest of the activity log', 'bettershield' ) },
		},
		uninstall: {
			// Follows the choice below, so said once, by the choice (#2617).
			remove_data: { label: __( 'When BetterShield is deleted', 'bettershield' ), weakens: on, computed: true },
			choice: { label: __( 'When BetterShield is deleted', 'bettershield' ), weakens: ( change ) => 'keep' === change.from, value: deletion },
		},
		sudo: {
			enabled: { label: __( 'Password confirmation', 'bettershield' ), weakens: off },
		},
		alerts: {
			muted: { label: __( 'Mute all alerts', 'bettershield' ), weakens: on },
			host_managed: { label: __( 'Routine alerts go to your host', 'bettershield' ), weakens: on },
			digest: { label: __( 'Weekly summary', 'bettershield' ), weakens: off },
			digest_day: { label: __( 'Summary day', 'bettershield' ), value: day },
			instant_critical: { label: __( 'Instant alerts for high and critical events', 'bettershield' ), weakens: off },
			account_notices_privileged: { label: __( 'Tell holders of accounts that can manage the site', 'bettershield' ), weakens: off },
			account_notices_others: { label: __( 'Tell holders of every other account', 'bettershield' ), weakens: off },
			// Event types moved from the instant email to the weekly summary (#1973).
			instant_off: { label: __( 'Event types sent in the weekly summary instead', 'bettershield' ), weakens: added },
			// Counted, never named: the addresses stay off the screen.
			recipients: { label: __( 'Where alerts go', 'bettershield' ) },
			// Counted too: each entry is an address and what it gets.
			preferences: { label: __( 'What each address gets', 'bettershield' ) },
		},
	};
}

/** A part of a dotted key in words, for a part no map names. */
const readable = ( part ) => part.replace( /_/g, ' ' );

/**
 * How a setting is named and judged, for a plain key or a dotted one.
 *
 * @param {Object} names The section's settings by key.
 * @param {string} key   e.g. `threshold`, or `surfaces.reset.threshold` for one value of a map.
 * @return {{label: string, weakens: ?Function, value: ?Function}} Its name and rules.
 */
function nameOf( names, key ) {
	if ( names[ key ] ) {
		return names[ key ];
	}

	const parts = key.split( '.' );

	if ( parts.length < 2 ) {
		return { label: readable( key ) };
	}

	const group = names[ parts[ 0 ] ] || {};
	const field = parts[ parts.length - 1 ];
	const rule = ( group.fields || {} )[ field ] || {};
	const middle = parts.slice( 1, -1 ).join( '.' );
	// What the value belongs to: a form by its own name, else the setting's.
	const owner = ( middle && ( group.items || {} )[ middle ] ) || ( middle ? readable( middle ) : group.label || readable( parts[ 0 ] ) );

	if ( rule.own ) {
		return { ...rule, label: owner };
	}

	return {
		...rule,
		label: sprintf(
			/* translators: 1: what a value belongs to, e.g. "Slow repeated sign-ups"; 2: the value, e.g. "limit per visitor". */
			_x( '%1$s, %2$s', 'a form, then one of its limits', 'bettershield' ),
			owner,
			rule.label || readable( field )
		),
	};
}

/**
 * One value in words.
 *
 * @param {*}         value  What the setting holds.
 * @param {?Function} spoken The setting's own words for its values, if it has any.
 * @return {string} The value as read.
 */
function said( value, spoken ) {
	const own = spoken ? spoken( value ) : undefined;

	if ( undefined !== own ) {
		return own;
	}

	if ( true === value ) {
		return __( 'on', 'bettershield' );
	}

	if ( false === value ) {
		return __( 'off', 'bettershield' );
	}

	if ( null === value || undefined === value || '' === value ) {
		return __( 'none', 'bettershield' );
	}

	return String( value );
}

/**
 * The lines that describe one section's changes.
 *
 * @param {string} section The section's key, e.g. `alerts`.
 * @param {Object} changes Its changes by key: `{ from, to }` for a value, `{ added, removed }` for a list.
 * @return {{key: string, text: string, weakens: boolean}[]} One line per setting that differs.
 */
export function changeLines( section, changes ) {
	const names = settingNames()[ section ] || {};
	const entries = Object.entries( changes || {} );
	// A value worked out from the others is said only when nothing else moved.
	const chosen = entries.filter( ( [ key ] ) => ! nameOf( names, key ).computed );
	const shown = chosen.length ? chosen : entries;

	return shown.map( ( [ key, change ] ) => {
		const name = nameOf( names, key );
		const label = name.label;
		const weakens = Boolean( name.weakens && name.weakens( change ) );

		if ( 'added' in change || 'removed' in change ) {
			return {
				key,
				weakens,
				text: sprintf(
					/* translators: 1: a setting that holds a list; 2: how many entries come and go, e.g. "1 added and 2 removed". */
					__( '%1$s: %2$s', 'bettershield' ),
					label,
					listOf( [
						change.added
							? sprintf( /* translators: %d: how many entries are added to a list. */ _n( '%d added', '%d added', change.added, 'bettershield' ), change.added )
							: '',
						change.removed
							? sprintf( /* translators: %d: how many entries are removed from a list. */ _n( '%d removed', '%d removed', change.removed, 'bettershield' ), change.removed )
							: '',
					] )
				),
			};
		}

		return {
			key,
			weakens,
			text: sprintf(
				/* translators: 1: a setting; 2: its value now; 3: its value after the change. */
				__( '%1$s: %2$s to %3$s', 'bettershield' ),
				label,
				said( change.from, name.value ),
				said( change.to, name.value )
			),
		};
	} );
}

/**
 * The lines that say what putting a change back does: the same settings,
 * each moving the other way.
 *
 * @param {string} section The section's key.
 * @param {Object} changes The changes the record made.
 * @return {{key: string, text: string, weakens: boolean}[]} One line per setting it moves back.
 */
export function putBackLines( section, changes ) {
	const back = {};

	Object.entries( changes || {} ).forEach( ( [ key, change ] ) => {
		back[ key ] = 'added' in change || 'removed' in change
			? { added: change.removed || 0, removed: change.added || 0 }
			: { from: change.to, to: change.from };
	} );

	return changeLines( section, back );
}
