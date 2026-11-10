/**
 * The network's log: the same screen the per-site record is, reading the union.
 *
 * A second implementation of a paged, filtered log would be the same lines
 * with one predicate changed, and the two would drift — the terminal already
 * had that problem with the query itself. So the screen takes the network as
 * a mode: one more filter, the site on each row, and a different route behind
 * both.
 */

import SiteActivity from '../activity/SiteActivity';

export default function NetworkActivity() {
	return <SiteActivity network />;
}
