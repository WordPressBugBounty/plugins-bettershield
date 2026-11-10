/**
 * Saying a change of state out loud, for a reader who cannot see it.
 *
 * A busy button says it is working by sweeping an icon and graying out, and
 * says it is done by changing its words and its icon back. A screen reader
 * hears none of that: the press goes quiet, and a reader who pressed "Run
 * audit" has no way to know the audit started, or that it ended, short of
 * hunting for a timestamp. The control has usually lost focus by then, being
 * disabled while it works, so even a label change is not read.
 *
 * WordPress already keeps two live regions on every admin page for this
 * (`wp.a11y.speak()`), so this hands the sentence to them rather than drawing
 * a region of its own beside each control. A failure needs nothing from here:
 * the notice that reports it takes focus, and is read when it does.
 */

import { speak } from '@wordpress/a11y';

/**
 * Says `message` once through WordPress's live regions.
 *
 * Polite waits for the reader's current sentence to end, which is what a
 * progress or completion message wants. Assertive interrupts, and is kept
 * for something the reader must hear before anything else.
 *
 * @param {string} message      The sentence, already translated.
 * @param {string} [politeness] 'polite' (the default) or 'assertive'.
 */
export function announce( message, politeness = 'polite' ) {
	if ( ! message ) {
		return;
	}

	speak( message, 'assertive' === politeness ? 'assertive' : 'polite' );
}
