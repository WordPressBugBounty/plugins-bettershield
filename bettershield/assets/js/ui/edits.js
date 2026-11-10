/**
 * Whether a card holding text fields has anything to save.
 *
 * Kept apart from the screen for the reason the validation rules are: the rule
 * is the part worth testing. A card that saves what a field holds when focus
 * leaves it cannot tell an edit from a visit — focus leaves a field somebody
 * tabbed through exactly as it leaves one they changed. Without this, opening
 * such a card and looking at it costs a request, an undo record and a line in
 * the activity log per field, and the record of what an owner changed fills
 * with changes nobody made.
 *
 * Trimmed, because that is what the server stores: it trims what it is given,
 * so a value differing only by the space on the end of it is not a change to
 * anything. Text only — a toggle is a change by construction, and the control
 * that carries one sends it directly.
 */

/**
 * The fields whose values differ from what is already saved.
 *
 * @param {Object}   saved The values as the server last returned them.
 * @param {Object}   next  The values the card is holding now.
 * @param {string[]} keys  The fields to compare.
 * @return {string[]} Those that changed, in the order given.
 */
export function editedFields( saved, next, keys ) {
	const text = ( value ) => String( value ?? '' ).trim();
	const before = saved && 'object' === typeof saved ? saved : {};
	const after = next && 'object' === typeof next ? next : {};

	return ( keys || [] ).filter( ( key ) => text( before[ key ] ) !== text( after[ key ] ) );
}
