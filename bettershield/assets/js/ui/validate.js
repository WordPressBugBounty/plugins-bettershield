/**
 * What a field can be told is wrong before it is sent.
 *
 * Every rule here has an authority on the server, and none of these replaces
 * it. What they do is name a problem the moment it is visible, instead of
 * letting a malformed value sit in a list until a save fails — which on a
 * security list is worse than a save failing, because an unparseable range
 * never matches anything and looks exactly like one that does.
 *
 * The shape of each function follows from that: they return the *problem*, or
 * null. None of them returns "valid". A client cannot know whether a sign-in
 * address is already taken by a page, or whether a mail server will accept an
 * address; saying "looks fine" would be a claim, and saying nothing is the
 * honest absence of one.
 */

import { __, sprintf } from '@wordpress/i18n';

/** How many bits a prefix may name, by family. */
const MAX_BITS = { v4: 32, v6: 128 };

/**
 * The shortest prefix the sign-in lists accept, by family. Anything wider
 * covers too much of the internet to name one network, and the server
 * refuses it for all three lists.
 */
const MIN_LIST_BITS = { v4: 8, v6: 32 };

function looksLikeIpv4( value ) {
	const parts = value.split( '.' );

	return (
		4 === parts.length &&
		parts.every( ( part ) => /^\d{1,3}$/.test( part ) && Number( part ) <= 255 )
	);
}

/**
 * Rough by design: anything with a colon and only hex, colons and a possible
 * embedded v4 tail. The server parses it properly with `inet_pton`, and a
 * client-side IPv6 parser that disagreed with that in either direction would
 * be worse than no message at all.
 */
function looksLikeIpv6( value ) {
	return value.includes( ':' ) && /^[0-9a-f:.]+$/i.test( value ) && ! value.includes( ':::' );
}

/**
 * What is wrong with an IP address or CIDR range, or null.
 *
 * @param {string}  value           As typed.
 * @param {Object}  options
 * @param {boolean} options.widest  Hold the range to the widest the sign-in lists accept, /8 or /32.
 * @return {?string} The problem, in words.
 */
export function rangeProblem( value, { widest = false } = {} ) {
	const text = String( value ?? '' ).trim();

	if ( '' === text ) {
		return null;
	}

	const [ base, bits, ...rest ] = text.split( '/' );

	if ( rest.length ) {
		return __( 'Use one slash: an address, then the number of bits to match.', 'bettershield' );
	}

	const family = looksLikeIpv4( base ) ? 'v4' : looksLikeIpv6( base ) ? 'v6' : null;

	if ( ! family ) {
		return __( 'That is not an IP address. Try 203.0.113.4 or 203.0.113.0/24.', 'bettershield' );
	}

	if ( undefined === bits ) {
		return null;
	}

	if ( ! /^\d+$/.test( bits ) || Number( bits ) > MAX_BITS[ family ] ) {
		return 'v4' === family
			? __( 'After the slash, a whole number from 0 to 32.', 'bettershield' )
			: __( 'After the slash, a whole number from 0 to 128.', 'bettershield' );
	}

	if ( widest && Number( bits ) < MIN_LIST_BITS[ family ] ) {
		return sprintf(
			/* translators: %d: the shortest prefix length allowed, 8 or 32. */
			__( 'That range is too wide. The widest allowed is /%d.', 'bettershield' ),
			MIN_LIST_BITS[ family ]
		);
	}

	return null;
}

/**
 * What is wrong with an email address, or null.
 *
 * Deliberately loose — one @, something either side, a dot in the domain. A
 * stricter client-side test rejects addresses that are perfectly deliverable,
 * and refusing somebody's real address is a worse failure than accepting one
 * the server will refuse a moment later.
 *
 * @param {string} value As typed.
 * @return {?string} The problem, in words.
 */
export function emailProblem( value ) {
	const text = String( value ?? '' ).trim();

	if ( '' === text ) {
		return null;
	}

	if ( ! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( text ) ) {
		return __( 'That does not look like an email address.', 'bettershield' );
	}

	/*
	 * The characters the site keeps when it cleans an address. Anything else
	 * is taken out, which leaves a different address — alerts@acme_corp.com
	 * became alerts@acmecorp.com, somebody else's domain — so it is named
	 * here rather than sent.
	 */
	const [ local, domain ] = text.split( '@' );
	const labels = domain.split( '.' );

	if (
		! /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test( local ) ||
		labels.some( ( label ) => ! /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test( label ) )
	) {
		return __( 'That email address has an invalid character. Check for a stray character or space.', 'bettershield' );
	}

	return null;
}

/**
 * What is wrong with a value against a rule the server declared, or null.
 *
 * The pattern travels with the field from the item that owns it, so the rule
 * is written once and the screen never carries a second copy of it to drift
 * from. It is a plain character-class pattern for exactly that reason: it has
 * to mean the same thing to PHP and to a browser.
 *
 * A field the server stores lowercased says so, and is checked lowercased:
 * "MyLogin" was refused here as a broken rule, though the server takes it.
 *
 * @param {string}  value     As typed.
 * @param {?string} pattern   An anchored pattern, or nothing.
 * @param {?string} note      What the rule is, in words, for when it is broken.
 * @param {boolean} lowercase Whether the server lowercases the value first.
 * @return {?string} The problem, in words.
 */
export function patternProblem( value, pattern, note, lowercase = false ) {
	const typed = String( value ?? '' ).trim();
	const text = lowercase ? typed.toLowerCase() : typed;

	if ( '' === text || ! pattern ) {
		return null;
	}

	let rule;

	try {
		rule = new RegExp( pattern );
	} catch ( error ) {
		// A pattern this browser cannot read is not the reader's problem;
		// the server still holds the rule.
		return null;
	}

	return rule.test( text ) ? null : note || __( 'That is not an accepted value.', 'bettershield' );
}

/**
 * What is wrong with a published security contact, or null.
 *
 * The three shapes RFC 9116 documents, which is what the server accepts: a
 * bare address, a `mailto:`, a `tel:`, or an https address a finder can reach.
 * Plain http is refused here as it is there — a security contact reached over
 * a connection anybody can read is not one.
 *
 * @param {string} value As typed.
 * @return {?string} The problem, in words.
 */
export function contactProblem( value ) {
	const text = String( value ?? '' ).trim();

	if ( '' === text ) {
		return null;
	}

	if ( /^mailto:/i.test( text ) ) {
		return emailProblem( text.slice( 7 ) );
	}

	if ( /^tel:/i.test( text ) ) {
		return /^tel:\+?[0-9.\-() ]{3,30}$/i.test( text )
			? null
			: __( 'A telephone contact looks like tel:+15551234567.', 'bettershield' );
	}

	if ( /^https:\/\//i.test( text ) ) {
		return /^https:\/\/[^\s/]+\.[^\s/]+/i.test( text )
			? null
			: __( 'That is not a complete address.', 'bettershield' );
	}

	if ( /^http:\/\//i.test( text ) ) {
		return __( 'A security contact needs https, or anyone on the network can read the report.', 'bettershield' );
	}

	return emailProblem( text )
		? __( 'Enter an email address, or an https address where reporters can reach you.', 'bettershield' )
		: null;
}

/**
 * What is wrong with an https address, or null.
 *
 * The policy address on the disclosure file, and anywhere else the server
 * asks for a page rather than an address. Plain http is named for what it is
 * rather than left to the save: a page describing what a site promises a
 * finder, served over a connection anybody can alter, is not that page.
 *
 * @param {string} value As typed.
 * @return {?string} The problem, in words.
 */
export function urlProblem( value ) {
	const text = String( value ?? '' ).trim();

	if ( '' === text ) {
		return null;
	}

	if ( /^http:\/\//i.test( text ) ) {
		return __( 'That needs to be https, not plain http.', 'bettershield' );
	}

	if ( ! /^https:\/\/[^\s/]+\.[^\s/]+/i.test( text ) ) {
		return __( 'That is not a complete https address.', 'bettershield' );
	}

	return null;
}

/**
 * What is wrong with a grace period in days, or null.
 *
 * Unlike the fields above, an empty one is a problem: the period is always
 * sent. It is read as text, never through Number(), because Number( '' ) is
 * 0, and a grace of zero sends every covered account without two-factor to
 * enrollment on its next admin page.
 *
 * @param {string|number} value As typed, or as last saved.
 * @return {?string} The problem, in words.
 */
export function graceDaysProblem( value ) {
	const text = String( value ?? '' ).trim();

	return /^\d+$/.test( text ) && Number( text ) <= 90
		? null
		: __( 'Enter a number of days from 0 to 90.', 'bettershield' );
}
