/**
 * The Overview's data, read ahead on every screen.
 *
 * Shared by both dashboard bundles, so a change to it lands once.
 */

import { useResource } from '../store';
import { mayReadPosture } from '../nav';

/**
 * Overview's data backs the header on every screen, so it is requested once
 * here rather than by each screen that reads from it. With navigation no longer
 * reloading the page, that request now happens once per visit instead of once
 * per section.
 */
export default function OverviewPrefetch() {
	// Only for a reader the Overview answers: one who may read the activity
	// log and not the posture got a 403 for it on every screen.
	return mayReadPosture() ? <ReadOverviewAhead /> : null;
}

/** The read itself, apart so the hook is never called conditionally. */
function ReadOverviewAhead() {
	useResource( 'overview' );

	return null;
}
