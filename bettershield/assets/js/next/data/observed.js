/**
 * What a recorded change says about itself: whether a log entry has one to
 * review, its name, its values as text, where its response stands, and the
 * step to take by hand where the response is not applied here. Shared by the
 * log's rows and the previous-values card (next/activity/ObservedChanges.js).
 */

import { __, sprintf } from '@wordpress/i18n';
import { formatTime } from '../../store';

const supported = [ 'site_setting_changed', 'role_capabilities_changed', 'user_created', 'plugin_activated' ];

/**
 * What a log entry's review opens: the recorded change it carries, '' for an
 * entry of a supported kind captured before capture was on, or null for an
 * entry with nothing to review.
 *
 * @param {Object} event A row of the activity log.
 * @return {?string} The change's token, '' or null.
 */
export function reviewToken( event ) {
	// A network setting is recorded without a capture, ever: offering a
	// review would say capture was off when it never applies there.
	if ( 'network_setting' === event.object_type ) {
		return null;
	}

	if ( ! supported.includes( event.type ) && ! event.context?.change_token ) {
		return null;
	}

	return /^[a-f0-9]{32}$/.test( event.context?.change_token || '' ) ? event.context.change_token : '';
}

/**
 * The by-hand step for a setting a network keeps off Settings, General.
 *
 * On a network that screen has no default role and no registration switch on
 * any site, so the step names the network's own screen, and says so plainly
 * to a site administrator who cannot open it.
 *
 * @param {Object} view The recorded change, as the review read it.
 * @return {?import('react').ReactNode} The guidance, or null where the general one holds.
 */
function networkGuidance( view ) {
	const manages = Boolean( view.network.manages_sites );

	if ( 'default_role' === view.target ) {
		return <>
			{ manages
				? __( 'In Network Admin › Sites › Edit › Settings, set Default Role back to the old value shown above.', 'bettershield' )
				: __( 'Only a network administrator can change this. Ask one to set Default Role for this site back to the old value shown above. They can also run:', 'bettershield' ) }
			{ manages ? null : <> { ' ' }<code>{ `wp option update default_role ${ view.before } --url=${ view.network.url }` }</code></> }
		</>;
	}

	if ( 'siteurl' === view.target ) {
		return <>
			{ manages
				? __( 'In Network Admin › Sites › Edit › Settings, set Site URL back to the old value shown above.', 'bettershield' )
				: __( 'Only a network administrator can change this. Ask one to set Site URL for this site back to the old value shown above. They can also run:', 'bettershield' ) }
			{ manages ? null : <> { ' ' }<code>{ `wp option update siteurl ${ view.before } --url=${ view.network.url }` }</code></> }
		</>;
	}

	if ( 'users_can_register' === view.target ) {
		return manages
			? __( 'On a network, this site’s value is not used. Registration is set under Network Admin, Settings, Allow new registrations.', 'bettershield' )
			: __( 'On a network, this site’s value is not used. A network administrator sets registration under Network Admin, Settings, Allow new registrations.', 'bettershield' );
	}

	return null;
}

/**
 * What an owner does by hand where this screen does not apply the response:
 * the screen that holds the value, and the step to take there.
 *
 * @param {Object} view The recorded change, as the review read it.
 * @return {import('react').ReactNode} One paragraph of guidance.
 */
export function manualGuidance( view ) {
	// A constant in wp-config.php holds the address, and no screen can move it.
	if ( 'option' === view.kind && 'siteurl' === view.target && view.set_in_config ) {
		return __( 'Your site address is fixed in wp-config.php. Ask your host or developer to change it back to the old value.', 'bettershield' );
	}

	const network = view.network && 'option' === view.kind ? networkGuidance( view ) : null;

	if ( network ) {
		return network;
	}

	return ( {
		option: __( 'In Settings › General, set it back to the old value shown above.', 'bettershield' ),
		role: roleGuidance( view ),
		plugin: __( 'Deactivate the plugin on the Plugins screen.', 'bettershield' ),
		account: __( 'Under Users, give this account a role without admin access, then use Log Out Everywhere.', 'bettershield' ),
	} )[ view.kind ] || __( 'Review the current value on its own settings screen before changing anything.', 'bettershield' );
}
/**
 * The by-hand step for a role, in the direction the role moved: what it
 * gained comes off, and what it lost goes back. It said remove whichever
 * way the role had changed.
 *
 * @param {Object} view The recorded change, as the review read it.
 * @return {string} The guidance.
 */
function roleGuidance( view ) {
	const { added, removed } = capabilityDiff( view.before, view.after );

	if ( removed.length && added.length ) {
		return __( 'Use a role editor plugin to give this role back the permissions it had before (shown above).', 'bettershield' );
	}

	if ( removed.length ) {
		return __( 'Use a role editor plugin to give this role back the permissions it lost (shown above).', 'bettershield' );
	}

	return __( 'Use a role editor plugin to remove the permissions this role gained (shown above).', 'bettershield' );
}

/** A setting's name, for the few the capture covers. */
function optionName( target ) {
	return ( {
		default_role: __( 'Default role for new accounts', 'bettershield' ),
		users_can_register: __( 'Public registration', 'bettershield' ),
		admin_email: __( 'Administration email address', 'bettershield' ),
		siteurl: __( 'WordPress address', 'bettershield' ),
	} )[ target ] || target;
}

/**
 * One captured change as a line in the list: what changed, when, and where
 * its response stands, rather than the bare name of what it was made to.
 *
 * @param {Object} entry A row of the list, with `kind`, `target`, `phase` and `created_at`.
 * @return {string} The line.
 */
export function entryLine( entry ) {
	const what = ( {
		/* translators: %s: a role's name, e.g. "Editor". */
		role: () => sprintf( __( 'The %s role’s permissions changed', 'bettershield' ), entry.name || entry.target ),
		/* translators: %s: the name of a setting. */
		option: () => sprintf( __( '%s changed', 'bettershield' ), optionName( entry.target ) ),
		/* translators: %d: an account's ID. */
		account: () => sprintf( __( 'Account #%d made an administrator', 'bettershield' ), entry.target ),
		/* translators: %s: a plugin's name, or its file where it has none. */
		plugin: () => sprintf( __( '%s plugin turned on', 'bettershield' ), entry.name || entry.target ),
	} )[ entry.kind ];
	const phase = ( {
		ready: __( 'ready to review', 'bettershield' ),
		started: __( 'didn’t finish — check it', 'bettershield' ),
		applied: __( 'restored', 'bettershield' ),
		undone: __( 'undone', 'bettershield' ),
	} )[ entry.phase ];

	return [ what ? what() : String( entry.target ), entry.created_at ? formatTime( entry.created_at ) : null, phase || null ].filter( Boolean ).join( ' · ' );
}

/**
 * The capabilities a role gained and lost between two maps, which is the
 * difference a reader is looking for in three long lists.
 *
 * @param {Object} before The role's capabilities before.
 * @param {Object} after  Its capabilities after.
 * @return {{added: string[], removed: string[]}} What changed.
 */
export function capabilityDiff( before, after ) {
	const held = ( map ) => Object.keys( map && 'object' === typeof map ? map : {} ).filter( ( cap ) => map[ cap ] );
	const was = held( before );
	const now = held( after );

	return {
		added: now.filter( ( cap ) => ! was.includes( cap ) ),
		removed: was.filter( ( cap ) => ! now.includes( cap ) ),
	};
}

/**
 * What a review is about: a setting by its name, an account by its number,
 * anything else by what it was recorded against.
 *
 * @param {Object} view The recorded change, as the review read it.
 * @return {string} The name.
 */
export function reviewLabel( view ) {
	return view.kind === 'option' ? optionName( view.target ) : view.kind === 'account' ? sprintf( __( 'Account #%d', 'bettershield' ), view.target ) : view.target;
}

/**
 * One recorded value as text: a map as indented JSON, a switch as Yes or No.
 *
 * @param {*}      value  Before, after or the current value.
 * @param {string} target The option it belongs to, where it is one.
 * @return {string} The value to print.
 */
export function describeValue( value, target = '' ) {
	// Public registration is stored as 0 or 1; the review said so (#2611).
	if ( 'users_can_register' === target && ( '0' === String( value ) || '1' === String( value ) ) ) {
		return '1' === String( value ) ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' );
	}

	return typeof value === 'object' ? JSON.stringify( value, null, 2 ) : typeof value === 'boolean' ? ( value ? __( 'Yes', 'bettershield' ) : __( 'No', 'bettershield' ) ) : String( value );
}

/**
 * Where a response stands once it has started, said under the review.
 *
 * @param {string} phase started, applied or undone.
 * @return {string|undefined} The sentence, or nothing for a change still waiting.
 */
export function phaseNote( phase ) {
	return ( { started: __( 'This didn’t finish. Check the setting before trying again.', 'bettershield' ), applied: __( 'The old value was restored. Undo works while it stays unchanged.', 'bettershield' ), undone: __( 'Undo completed.', 'bettershield' ) } )[ phase ];
}
