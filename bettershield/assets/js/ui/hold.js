/**
 * How long a button's working state is held, at the least.
 *
 * An audit on a quiet site answers in a few hundred milliseconds, so the
 * control flicked from "Run Audit" to "Auditing…" and back before the eye had
 * found it, and the sweep drawn to say "this is a scan" was cut off a fifth of
 * the way across. The hold is one full pass of the button's own animation, so
 * whatever it draws is seen to finish.
 *
 * Only a success is held. A failure arrives when it arrives: dressing a
 * refusal up as more work would be the button saying something untrue.
 *
 * Nothing is held for a reader who asked for stillness — the hold exists only
 * so that motion can be seen, and without the motion it would be a delay and
 * nothing else. The same applies where the preference cannot be read at all.
 */

/** One sweep out and back: `bs-scan-sweep`, 1500ms each way, in base.css. */
export const SCAN_HOLD = 3000;

/** One fill of `bs-send-fill` in base.css. */
export const SEND_HOLD = 1200;

/**
 * The pause between one slice of a file check and the next, while the screen
 * that asked for it carries it on. Each slice is a few seconds of the
 * server's time, and on shared hosting the request after it should not be
 * queued straight behind it.
 */
export const SLICE_GAP = 1500;

/** Whether the reader's browser has not asked for stillness. */
export function motionAllowed() {
	return (
		typeof window !== 'undefined' &&
		!! window.matchMedia &&
		! window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches
	);
}

/**
 * Resolve with the request's answer, but not before `ms` have passed since it
 * was sent.
 *
 * @param {Promise} request The request in flight.
 * @param {number}  ms      The least time to hold, in milliseconds.
 * @return {Promise} The same answer, or the same refusal.
 */
export function atLeast( request, ms ) {
	if ( ! ms || ! motionAllowed() ) {
		return request;
	}

	const floor = new Promise( ( resolve ) => setTimeout( resolve, ms ) );

	return request.then( ( answer ) => floor.then( () => answer ) );
}
