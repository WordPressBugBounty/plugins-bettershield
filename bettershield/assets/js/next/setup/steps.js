/**
 * The order of the Quick Setup, and the rules for moving through it.
 *
 * Five steps at most, in the order that keeps an owner safe: consent first,
 * then what is already installed, then one Protect screen with the site's
 * answers and the fixes, saved in that order, then the summary with what is
 * still to do by hand (recovery, two-factor, usernames) and the recommended
 * plugins (Ecosystem), and the hub last, on
 * every site. One is conditional, and the server decides: the coexistence
 * check appears only when another security plugin is active (#2297).
 *
 * Kept free of React so the rules can be tested without mounting anything.
 */

import { __, sprintf } from '@wordpress/i18n';
import { emailProblem } from '../../ui/validate';
import brand from './brand';

/**
 * Every step the setup can have, in order.
 *
 * `short` is what the stepper prints; the step's own heading is longer and
 * lives with the step.
 *
 * @return {Array<{slug: string, short: string, optional: boolean}>} The steps.
 */
export function allSteps() {
	return [
		{ slug: 'welcome', short: __( 'Getting Started', 'bettershield' ), optional: false },
		{ slug: 'coexistence', short: __( 'Coexistence', 'bettershield' ), optional: true },
		{ slug: 'protect', short: __( 'Protect', 'bettershield' ), optional: false },
		// The summary, and the recommended plugins with it.
		{ slug: 'ready', short: __( 'Ecosystem', 'bettershield' ), optional: false },
		// On every site, saying why where the site cannot connect yet.
		{ slug: 'hub', short: sprintf( /* translators: %s: the plugin's name, or the label the site owner gave it. */ __( '%s Hub', 'bettershield' ), brand() ), optional: false },
	];
}

/** The slugs alone, in order. */
export const ORDER = [ 'welcome', 'coexistence', 'protect', 'ready', 'hub' ];

/** The steps Protect took over, which a setup saved before may name. */
const MERGED = [ 'site', 'recovery', 'fixes', 'ecosystem' ];

/**
 * The steps this site gets.
 *
 * A step the server did not name is left out, except that the required ones
 * are always kept: a payload that forgot one must not produce a setup with no
 * way back in or no end.
 *
 * @param {string[]} available Slugs the server says apply.
 * @return {Array<{slug: string, short: string, optional: boolean}>} Visible steps, in order.
 */
export function visibleSteps( available ) {
	const named = Array.isArray( available ) ? available : [];

	return allSteps().filter( ( step ) => ! step.optional || named.includes( step.slug ) );
}

/**
 * Where a visit opens.
 *
 * The saved step when it is still one this site has. When it is not — the
 * other security plugin was deactivated since, say — the next step after it
 * that is, so nobody is sent backwards past work they already did.
 *
 * @param {string}   saved   The step saved last time, if any.
 * @param {string[]} visible Visible slugs, in order.
 * @return {string} A visible slug.
 */
export function resumeAt( saved, visible ) {
	if ( ! visible.length ) {
		return 'welcome';
	}

	// A step Protect took over resumes on Protect, the old way back in among
	// them: its parts now live on their own screens, pointed to from Ecosystem.
	const step = MERGED.includes( saved ) ? 'protect' : saved;

	if ( visible.includes( step ) ) {
		return step;
	}

	const from = ORDER.indexOf( step );

	if ( from < 0 ) {
		return visible[ 0 ];
	}

	const later = visible.find( ( slug ) => ORDER.indexOf( slug ) > from );

	return later || visible[ visible.length - 1 ];
}

/**
 * The step after this one, or null at the end.
 *
 * @param {string}   current Current slug.
 * @param {string[]} visible Visible slugs, in order.
 * @return {?string} The next slug.
 */
export function nextStep( current, visible ) {
	const at = visible.indexOf( current );

	return at >= 0 && at < visible.length - 1 ? visible[ at + 1 ] : null;
}

/**
 * The step before this one, or null at the start.
 *
 * @param {string}   current Current slug.
 * @param {string[]} visible Visible slugs, in order.
 * @return {?string} The previous slug.
 */
export function previousStep( current, visible ) {
	const at = visible.indexOf( current );

	return at > 0 ? visible[ at - 1 ] : null;
}

/**
 * Whether a step in the stepper can be chosen directly.
 *
 * Only steps already passed, and never from Ready or the hub after it: the
 * summary there reads what happened, and walking back into a step from it
 * would let the page claim a setup is finished while a step stands open.
 *
 * @param {string}   slug    The step asked for.
 * @param {string}   current Current slug.
 * @param {string[]} visible Visible slugs, in order.
 * @return {boolean} Whether it may be opened.
 */
export function canVisit( slug, current, visible ) {
	if ( 'ready' === current || 'hub' === current ) {
		return false;
	}

	const target = visible.indexOf( slug );

	return target >= 0 && target < visible.indexOf( current );
}

/**
 * The most extra email addresses an owner may add beside the admin address.
 */
export const EXTRA_RECIPIENTS = 4;

/**
 * Whether a string is plausibly an email address.
 *
 * The server validates for real with `is_email()`; this only stops the field
 * from offering to save something obviously incomplete.
 *
 * @param {string} value What was typed.
 * @return {boolean} Whether it looks like an address.
 */
export function looksLikeEmail( value ) {
	const text = String( value || '' ).trim();

	// The same rule the Email alerts screen uses, so an address the site
	// would clean into a different one is caught here too.
	return '' !== text && null === emailProblem( text );
}

/**
 * Tidy the extra recipients before they are sent: trimmed, lowercased for
 * comparison, no blanks, no duplicates, never the admin address twice, and
 * no more than the limit.
 *
 * @param {string[]} list  What the fields hold.
 * @param {string}   admin The admin address, always a recipient already.
 * @return {string[]} The addresses to save.
 */
export function cleanRecipients( list, admin ) {
	const seen = new Set( [ String( admin || '' ).trim().toLowerCase() ] );
	const out = [];

	( Array.isArray( list ) ? list : [] ).forEach( ( raw ) => {
		const value = String( raw || '' ).trim();
		const key = value.toLowerCase();

		if ( ! value || seen.has( key ) ) {
			return;
		}

		seen.add( key );
		out.push( value );
	} );

	return out.slice( 0, EXTRA_RECIPIENTS );
}
