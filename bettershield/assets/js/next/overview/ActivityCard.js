/**
 * The Overview's Activity card (design frame 27:53302): the four Activity
 * screens as tabs with their counts, and the latest four rows of the one
 * chosen. Filters and search are the full log's, one press away.
 */

import './ActivityCard.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { whenPhrase } from '../../ui/when';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Icon from '../ui/Icon';
import Table, { Cell, Row, WholeRow } from '../ui/Table';
import { panelProps } from '../ui/tabKeys';
import FitTabs from '../activity/FitTabs';
import { fromAgents, fromEvents, fromFiles, fromIncidents, newest } from '../data/activity';
import { confidenceLabel } from '../data/incidents';

const LIMIT = 4;

/** Rows read on demand, once per visit. */
function useLater( path, wanted ) {
	const [ rows, setRows ] = useState( null );

	useEffect( () => {
		if ( ! wanted || null !== rows ) {
			return;
		}

		apiFetch( { path } )
			.then( ( data ) => setRows( data ) )
			.catch( () => setRows( false ) );
	}, [ path, wanted, rows ] );

	return rows;
}

export default function ActivityCard( { overview } ) {
	const [ tab, setTab ] = useState( 'site' );
	const panel = overview.panels || {};
	const files = panel.files || null;
	const counts = ( panel.activity && panel.activity.counts ) || {};
	const incidents = useLater( '/bettershield/v1/incidents?status=open', 'incidents' === tab || 'all' === tab );
	const agents = useLater( '/bettershield/v1/agent-activity', 'agents' === tab || 'all' === tab );

	const site = fromEvents( panel.activity ? panel.activity.events : [] );
	const changed = fromFiles( files );
	const incidentRows = incidents ? fromIncidents( incidents.incidents, confidenceLabel ) : [];
	const agentRows = agents ? fromAgents( agents.invocations ) : [];

	const number = ( value ) => ( null === value || undefined === value ? null : Number( value ) || 0 );
	// Null for a reader who may not see the file report: its tab is not offered.
	const fileTab = Boolean( files );
	const tabCounts = {
		site: number( overview.receipts ? overview.receipts.events_week : null ),
		files: number( files ? files.open : null ),
		incidents: number( counts.incidents_open ),
		agents: number( counts.agent_requests ),
	};
	// Each count is of its own tab's list: this week's events, the open file
	// changes, the open incidents, the agent requests on record. Added
	// together they are not a count of anything, so All carries none.
	tabCounts.all = null;

	const rows = {
		all: newest( [ site, changed, incidentRows, agentRows ], LIMIT ),
		site: site.slice( 0, LIMIT ),
		files: changed.slice( 0, LIMIT ),
		incidents: incidentRows.slice( 0, LIMIT ),
		agents: agentRows.slice( 0, LIMIT ),
	}[ tab ];

	/*
	 * The log on the tab this card shows, and its search and filters, which
	 * are Site activity's: all three opened the log's default tab with
	 * nothing open, wherever the card was (#1917). Shown only where they
	 * are the log's, so they never send the reader off this card's tab.
	 */
	const log = tabUrl( 'bettershield-activity', 'all' === tab ? 'site' : tab );
	const narrowable = 'all' === tab || 'site' === tab;
	const siteLog = tabUrl( 'bettershield-activity', 'site' );

	// What the table says when it has no rows: that a read is on its way, that
	// it failed, or that there is nothing. The file report's count is null
	// when the report could not be read.
	const waitingOn = { incidents: [ incidents ], agents: [ agents ], all: [ incidents, agents ] }[ tab ] || [];
	const loading = waitingOn.includes( null );
	const unread = ( 'files' === tab && files && null === files.open ) || ( 'all' !== tab && waitingOn.includes( false ) );
	let empty = 'site' === tab ? __( 'Nothing was recorded this week.', 'bettershield' ) : __( 'Nothing has been recorded yet.', 'bettershield' );

	if ( loading ) {
		empty = { incidents: __( 'Loading incidents…', 'bettershield' ), agents: __( 'Loading agent activity…', 'bettershield' ) }[ tab ] || __( 'Loading the activity log…', 'bettershield' );
	} else if ( unread ) {
		empty = __( 'Couldn’t load this. Try again in a moment.', 'bettershield' );
	}

	// The newest rows across sources wait for every source, so a row read
	// late is not left out of them; a source that could not be read is named
	// under the rows the others gave.
	const shown = 'all' === tab && loading ? [] : rows;
	const missing =
		'all' === tab && ! loading
			? [
					files && null === files.open ? __( 'File changes could not be read just now, so they are not listed here.', 'bettershield' ) : null,
					false === incidents ? __( 'Incidents could not be read just now, so they are not listed here.', 'bettershield' ) : null,
					false === agents ? __( 'Agent activity could not be read just now, so it is not listed here.', 'bettershield' ) : null,
			  ].filter( Boolean )
			: [];

	return (
		<Card aria-labelledby="bs-ds-activity-title">
			<CardHead icon="activity" title={ __( 'Activity', 'bettershield' ) } id="bs-ds-activity-title" line auto>
				<Button type="secondary" size="sm" href={ log }>
					{ __( 'Open the Log', 'bettershield' ) }
				</Button>
			</CardHead>
			<div className="bs-ds-act__body">
				{ /* As many tabs as fit beside the controls, the rest in a select:
				     Agent activity was cut off behind them (#1917). */ }
				<FitTabs
					id="bs-ds-activity-tabs"
					label={ __( 'Activity', 'bettershield' ) }
					moreLabel={ __( 'More activity', 'bettershield' ) }
					optionLabel={ ( shownTab ) =>
						null === shownTab.count || undefined === shownTab.count
							? shownTab.label
							: sprintf(
									/* translators: 1: an activity tab, 2: how many entries it holds. */
									__( '%1$s (%2$s)', 'bettershield' ),
									shownTab.label,
									shownTab.count
							  )
					}
					selected={ tab }
					onSelect={ setTab }
					tabs={ [
						{ key: 'all', label: __( 'All', 'bettershield' ), count: tabCounts.all },
						{ key: 'site', label: __( 'Site activity', 'bettershield' ), count: tabCounts.site },
						fileTab ? { key: 'files', label: __( 'File changes', 'bettershield' ), count: tabCounts.files } : null,
						{ key: 'incidents', label: __( 'Incidents', 'bettershield' ), count: tabCounts.incidents },
						{ key: 'agents', label: __( 'Agent activity', 'bettershield' ), count: tabCounts.agents },
					].filter( Boolean ) }
					actions={
						narrowable ? (
							<>
								<Button type="toolbar" size="sm" icon="list-filter" iconTone="2" href={ `${ siteLog }#filters` }>
									{ __( 'Filters', 'bettershield' ) }
								</Button>
								<Button type="toolbar" size="sm" iconOnly href={ `${ siteLog }#search` } label={ __( 'Search', 'bettershield' ) }>
									<Icon name="search" size={ 16 } tone="2" />
								</Button>
							</>
						) : null
					}
				/>
				<div { ...panelProps( 'bs-ds-activity-tabs', tab ) }>
					<Table
						label={ __( 'Activity', 'bettershield' ) }
						columns={ [
							{ key: 'event', label: __( 'Event', 'bettershield' ) },
							{ key: 'when', label: __( 'When', 'bettershield' ), width: '140px' },
						] }
					>
						{ shown.map( ( row ) => (
							<Row key={ row.key }>
								<Cell>
									<span className="bs-ds-act__event">
										<Icon name={ row.icon } size={ 16 } tone="2" />
										<span className="bs-ds-t14 bs-ds-r bs-ds-c1 bs-ds-nowrap bs-ds-act__label">{ row.label }</span>
									</span>
								</Cell>
								<Cell>
									<span className="bs-ds-t12 bs-ds-r bs-ds-c2">{ whenPhrase( row.at ) }</span>
								</Cell>
							</Row>
						) ) }
						{ shown.length || missing.length ? null : <WholeRow kind="empty">{ empty }</WholeRow> }
						{ missing.map( ( note ) => (
							<WholeRow key={ note }>{ note }</WholeRow>
						) ) }
					</Table>
				</div>
			</div>
		</Card>
	);
}
