/**
 * Enter, in a field that has a button beside it.
 *
 * Every list on these screens committed an entry only when its Add button was
 * clicked, so adding six addresses meant six trips to the mouse — on the most
 * common interaction the Login & Access and Alerts screens have, and against
 * the muscle memory every other tag and recipient field on the web has built.
 *
 * `preventDefault` because these fields sit inside forms whose default
 * submission is not what the reader means, and focus is deliberately left
 * where it is: the next thing somebody does after adding one address is type
 * the next one.
 *
 * @param {Function} act What Enter should do.
 * @return {Function} A keydown handler.
 */
export function onEnter( act ) {
	return ( event ) => {
		if ( ! event || 'Enter' !== event.key || event.shiftKey ) {
			return;
		}

		event.preventDefault();
		act();
	};
}

/**
 * Escape, on a disclosure or anywhere in what it opened.
 *
 * Escape puts away what is open on these screens and puts the reader back on
 * the control that opened it. Only while something is open, so the key still
 * reaches anything further out — a dialog, or the browser — the rest of the
 * time.
 *
 * @param {boolean}  open  Whether there is anything to close.
 * @param {Function} close Close it, and put focus back on its control.
 * @return {Function} A keydown handler.
 */
export function onEscape( open, close ) {
	return ( event ) => {
		if ( ! open || ! event || 'Escape' !== event.key ) {
			return;
		}

		event.stopPropagation();
		close();
	};
}
