/**
 * Whether a hardening preview still describes the form it was computed from.
 *
 * Kept out of the card because the rule is the part worth testing. Opening a
 * preview and then editing the field left the earlier projection on screen —
 * "move sign-in to /secret1" above a field now reading /secret2 — with the
 * button still offering to hide it. That is worse than no preview, because a
 * cautious owner opened the card precisely to read it before applying.
 *
 * Expressed as a match rather than as "clear it on every keystroke" so that
 * typing a value, changing your mind, and typing the first one back shows the
 * preview that does describe it, instead of demanding it be fetched twice.
 */

/**
 * Whether two sets of field values are the same answer.
 *
 * @param {?Object} a One set of values, or null.
 * @param {?Object} b The other.
 * @return {boolean} True when both hold the same keys with the same values.
 */
export function sameFieldValues( a, b ) {
	if ( ! a || ! b ) {
		return false;
	}

	const keys = Object.keys( a );

	if ( keys.length !== Object.keys( b ).length ) {
		return false;
	}

	// A field that takes several choices holds a list, which is the same
	// answer when it holds the same choices, whichever object carries them.
	return keys.every( ( key ) =>
		Array.isArray( a[ key ] ) && Array.isArray( b[ key ] )
			? a[ key ].length === b[ key ].length && a[ key ].every( ( value, index ) => value === b[ key ][ index ] )
			: a[ key ] === b[ key ]
	);
}
