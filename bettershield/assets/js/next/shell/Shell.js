/**
 * The redesigned frame around every screen (design frames 27:53063 and
 * 23:32941): the sidebar, and a sheet holding the top bar and the screen.
 *
 * Every screen of this plugin, a site's and the network's, is drawn with the
 * redesign's components in its content box. An add-on's tab that does not
 * say it draws with them renders inside the sheet in a wrapper carrying the
 * classic token roles it reads.
 */

import './Shell.css';

import { findSection, isDrawnAddOn, isNetwork } from '../../nav';
import AddOnSlot from '../../shared/AddOnSlot';
import ActionNotice from '../../shared/ActionNotice';
import ConfirmPassword from '../../shared/ConfirmPassword';
import OverviewPrefetch from '../../shared/OverviewPrefetch';
import UsageReminder from './UsageReminder';
import RecoveryPreflight from '../../ui/RecoveryPreflight';
import { schemeAttribute, useScheme } from '../../ui/scheme';
import { useCollapsed } from './collapse';
import { screenName } from './screenName';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import useRoute from './useRoute';
import useFocusTarget from '../ui/useFocusTarget';
import Overview from '../overview/Overview';
import Findings from '../findings/Findings';
import Connect from '../agents/Connect';
import Requests from '../agents/Requests';
import Permissions from '../agents/Permissions';
import Surface from '../agents/Surface';
import Hub from '../hub/Hub';
import SiteActivity from '../activity/SiteActivity';
import AgentActivity from '../activity/AgentActivity';
import Hardening from '../protect/Hardening';
import LoginAccess from '../protect/LoginAccess';
import TwoFactor from '../protect/TwoFactor';
import Recovery from '../protect/Recovery';
import Files from '../activity/Files';
import Incidents from '../activity/Incidents';
import General from '../settings/General';
import Alerts from '../settings/Alerts';
import NetworkOverview from '../network/NetworkOverview';
import NetworkActivity from '../network/NetworkActivity';
import NetworkIncidents from '../network/NetworkIncidents';

/**
 * A site's screens, by section: one function for a section drawn whole, or
 * its tabs by slug. A section or tab missing here is an add-on's, drawn in
 * its slot.
 */
export const REDRAWN = {
	bettershield: () => <Overview />,
	'bettershield-findings': () => <Findings />,
	'bettershield-protect': {
		hardening: () => <Hardening />,
		login: () => <LoginAccess />,
		'two-factor': () => <TwoFactor />,
		recovery: () => <Recovery />,
	},
	/*
	 * Connecting an assistant is the job, so it is the tab this section opens
	 * on; the inventory of what is registered is the fact sheet, so it is last.
	 * The old address under Protect answers with a server-side redirect to
	 * Connect, which is why nothing here has to recognize it.
	 */
	'bettershield-agents': ( route ) => {
		if ( 'requests' === route.tab ) {
			return <Requests />;
		}

		if ( 'permissions' === route.tab ) {
			return <Permissions />;
		}

		if ( 'surface' === route.tab ) {
			return <Surface />;
		}

		return <Connect />;
	},
	'bettershield-hub': () => <Hub />,
	'bettershield-activity': {
		site: () => <SiteActivity />,
		agents: () => <AgentActivity />,
		files: () => <Files />,
		incidents: () => <Incidents />,
	},
	'bettershield-settings': ( route ) => ( 'alerts' === route.tab ? <Alerts /> : <General /> ),
};

/**
 * The network's screens, drawn in network admin, kept in their own map rather
 * than added to the site's.
 *
 * The two sets are never both reachable: a section slug that is not in the map
 * for the surface being drawn falls back to that surface's own first screen,
 * so a network address can never render a screen about one site, and a site
 * address can never render one about the network.
 */
export const NETWORK_SCREENS = {
	'bettershield-network': () => <NetworkOverview />,
	'bettershield-network-activity': ( route ) => ( 'incidents' === route.tab ? <NetworkIncidents /> : <NetworkActivity /> ),
};

/**
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {?Function} What draws the route, if it is redrawn.
 */
export function redrawnFor( route ) {
	const entry = REDRAWN[ route.section ];

	if ( 'function' === typeof entry ) {
		return entry;
	}

	return entry && 'function' === typeof entry[ route.tab ] ? entry[ route.tab ] : null;
}

/**
 * An add-on's section: its slot, in the redesign's content box when the
 * add-on said it draws that tab with the redesign's components.
 *
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {{render: Function, redrawn: boolean, byAddOn: boolean}} What draws it.
 */
function addOnFor( route ) {
	const drawn = isDrawnAddOn( route );

	return { render: () => <AddOnSlot route={ route } drawn={ drawn } />, redrawn: drawn, byAddOn: true };
}

/**
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {{render: Function, redrawn: boolean, byAddOn: boolean}} What draws the screen, whether it is a redrawn one, and whether an add-on draws it.
 */
export function screenFor( route ) {
	// Network admin draws the network's own screens, redrawn, and never a
	// screen about one site: a section it does not know falls back to the
	// network's first.
	if ( isNetwork ) {
		if ( NETWORK_SCREENS[ route.section ] ) {
			return { render: NETWORK_SCREENS[ route.section ], redrawn: true, byAddOn: false };
		}

		return findSection( route.section ) ? addOnFor( route ) : { render: NETWORK_SCREENS[ 'bettershield-network' ], redrawn: true, byAddOn: false };
	}

	const redrawn = redrawnFor( route );

	if ( redrawn ) {
		return { render: redrawn, redrawn: true, byAddOn: false };
	}

	if ( findSection( route.section ) ) {
		return addOnFor( route );
	}

	return { render: REDRAWN.bettershield, redrawn: true, byAddOn: false };
}

export default function Shell() {
	const { route, headingRef } = useRoute();
	useFocusTarget( route );
	const [ collapsed, toggle ] = useCollapsed();
	const { scheme } = useScheme();
	const section = findSection( route.section );
	// An add-on's section is keyed by the section alone, so its slot, and the
	// add-on's screen in it, outlive a change of tab.
	const { render, redrawn, byAddOn } = screenFor( route );
	const { title } = screenName( route );

	return (
		<>
			<div className="screen-reader-text" aria-live="polite" role="status">
				{ section ? title : '' }
			</div>
			{ /* A site's posture, read ahead for the sidebar's count; the
			     network's screens have no such count to show. */ }
			{ isNetwork ? null : <OverviewPrefetch /> }
			{ /* Folded, the sidebar is a rail of its icons rather than gone: every
			     screen stays one press away. */ }
			<Sidebar route={ route } collapsed={ collapsed } />
			<div className="bs-ds-sheet">
				{ /* A division, not a second main: WordPress's #wpbody is the
				     page's main landmark already, and this sits inside it. */ }
				<div className="bs-ds-main">
					{ /* The way to the hub has the audit's gate, and is not offered on
					     the Hub screen itself. */ }
					<TopBar title={ title } headingRef={ headingRef } collapsed={ collapsed } toggle={ toggle } audit={ ! isNetwork } hub={ ! isNetwork && 'bettershield-hub' !== route.section } />
					<ConfirmPassword />
					<RecoveryPreflight />
					{ redrawn ? (
						<div className="bs-ds-content" key={ byAddOn ? route.section : `${ route.section }/${ route.tab }` }>
							<ActionNotice route={ route } fallback={ headingRef } />
							<UsageReminder />
							{ render( route ) }
						</div>
					) : (
						<div className="bs-app bs-ds-current" data-bs-scheme={ schemeAttribute( scheme ) } key={ byAddOn ? route.section : `${ route.section }/${ route.tab }` }>
							<ActionNotice route={ route } fallback={ headingRef } />
							<UsageReminder />
							{ render( route ) }
						</div>
					) }
				</div>
			</div>
		</>
	);
}
