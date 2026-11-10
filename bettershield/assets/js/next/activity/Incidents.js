/**
 * Activity › Incidents: recorded access and executable-file changes, joined
 * where they line up.
 *
 * An incident is a correlation, not a verdict, and the screen is built to say
 * so: what the correlation claims is the title, the evidence is a timeline of
 * what was recorded and by whom, and every response is a plan somebody reads
 * and chooses from rather than something that happens.
 *
 * The status strip, then one card: Open and Handled as tabs, each incident a
 * row, and the incident a reader opens laid out under its row as cards: its
 * evidence, the activity around it, the explanation and the response.
 */

import './Incidents.css';

import apiFetch from '@wordpress/api-fetch';
import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { activityUrl, linkedIncident } from '../../nav';
import { formatTime, isWorking, useStore } from '../../store';
import { BreakablePath } from '../../ui/path';
import { whenPhrase } from '../../ui/when';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { useFocusAfter } from '../ui/focus';
import Skeleton, { Bone, CardBone } from '../ui/Skeleton';
import { EmptyState, ErrorState } from '../ui/States';
import Stats from '../ui/Stats';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Tabs from '../ui/Tabs';
import { panelProps } from '../ui/tabKeys';
import { confidenceLabel, dayText, foldTimeline, readerDay, TIMELINE_SHOWN } from '../data/incidents';
import { versionPhrase } from '../data/log';
import { formatCount } from '../../ui/count';
import IncidentExplanation from './IncidentExplanation';
import IncidentResponse from './IncidentResponse';
import Part from './Part';

const TABS_ID = 'bs-ds-incidents';

/** Widths for stand-in incidents, so no two neighbors match. */
const INCIDENT_WIDTHS = [ '13em', '17em', '11em' ];

/**
 * Incidents standing in for themselves: what the correlation claims and the
 * reference and counts under it, with the controls held at the end.
 *
 * @param {Object} props
 * @param {number} props.rows How many.
 */
function IncidentRowsBone( { rows = 3 } ) {
	return INCIDENT_WIDTHS.slice( 0, rows ).map( ( width ) => (
		<div key={ width } className="bs-ds-bonerow">
			<span className="bs-ds-bonerow__text">
				<Bone kind="title" w={ width } />
				<Bone w="9em" />
			</span>
			<Bone kind="control" w="128px" />
		</div>
	) );
}

/**
 * An incident's evidence before it has been read: the card it arrives in,
 * with a row where each record will be.
 */
function TimelineBone() {
	return (
		<Skeleton label={ __( 'Loading the timeline…', 'bettershield' ) }>
			<CardBone rows={ [ '46%', '38%', '52%' ] } />
		</Skeleton>
	);
}

/** Who did it, and how the record is tied to the incident. */
function TimelineWho( { e } ) {
	const relation = {
		within_24h: __( 'Happened within a day of the main event', 'bettershield' ),
		same_actor: __( 'Done by the same account', 'bettershield' ),
		same_subject: __( 'Affects the same account, file or setting', 'bettershield' ),
	}[ e.relation ];

	return (
		<span className="bs-ds-timeline__line">
			{ [
				e.actor_id
					? sprintf(
							/* translators: %d: an account's ID. */
							__( 'Done by account #%d', 'bettershield' ),
							e.actor_id
					  )
					: __( 'Not linked to a signed-in account', 'bettershield' ),
				relation,
			]
				.filter( Boolean )
				.join( ' · ' ) }
			{ e.actor_id ? (
				<>
					{ ' · ' }
					<a href={ activityUrl( { actor: `user:${ e.actor_id }` } ) }>{ __( 'Everything this account did', 'bettershield' ) }</a>
				</>
			) : null }
		</span>
	);
}

/**
 * What a file record was compared against. Under a folded row it speaks
 * for every file the row holds, so it says files (#2826).
 */
function TimelineComparison( { e, many = false } ) {
	return e.snapshot?.details?.comparison ? (
		<span className="bs-ds-timeline__line">
			{ e.snapshot.details.comparison === 'put_back'
				? many
					? __( 'Changed files were restored from quarantine, BetterShield’s safe storage', 'bettershield' )
					: __( 'A changed file was restored from quarantine, BetterShield’s safe storage', 'bettershield' )
				: e.type === 'incident_code_modified'
				? many
					? __( 'These files’ code changed since the last check', 'bettershield' )
					: __( 'The file’s code changed since the last check', 'bettershield' )
				: e.snapshot.details.comparison === 'saved_baseline'
				? __( 'New since BetterShield first scanned your files', 'bettershield' )
				: __( 'Not part of the official plugin or theme download', 'bettershield' ) }
		</span>
	) : null;
}

/**
 * When a record happened, and its own number, for the first cell of its row.
 * A folded row says the numbers it holds, or the count read as a gap in the
 * numbering beside it: "Record #6" and then "Record #11" (#2484).
 *
 * @param {Object}   props
 * @param {Object}   props.e   The record.
 * @param {number[]} props.ids The numbers of a folded row's records.
 */
function TimelineWhen( { e, ids = null } ) {
	const low = ids ? Math.min( ...ids ) : e.id;
	const high = ids ? Math.max( ...ids ) : e.id;

	return (
		<span className="bs-ds-timeline__when">
			<time dateTime={ e.occurred_at }>{ formatTime( e.occurred_at ) }</time>
			<span>
				{ low === high
					? sprintf( /* translators: %d: the evidence record ID. */ __( 'Record #%d', 'bettershield' ), low )
					: sprintf( /* translators: 1: the first evidence record ID, 2: the last. */ __( 'Records #%1$d–#%2$d', 'bettershield' ), low, high ) }
			</span>
		</span>
	);
}

/** One record's row: when, what, who, and the file or setting it was about. */
function TimelineCard( { e } ) {
	// A plugin's update by the versions it moved between, as Activity says it.
	const versions = 'plugin' === e.snapshot?.object_type ? versionPhrase( e.snapshot?.details || {} ) : null;

	return (
		<Row id={ `bs-incident-evidence-${ e.id }` } tabIndex={ -1 } className="bs-ds-timeline__record">
			<Cell>
				<TimelineWhen e={ e } />
			</Cell>
			<Cell>
				<TitleMeta
					title={ <strong className="bs-ds-timeline__label">{ e.label }</strong> }
					meta={
						<>
							{ /* Asked, never asserted: a person setting up a colleague's
							     account makes the same three changes. */ }
							{ 'account_takeover_sequence' === e.type ? (
								<span className="bs-ds-timeline__question">
									{ __( 'This account’s email, password and an application password changed within an hour. Was this expected?', 'bettershield' ) }
								</span>
							) : null }
							<TimelineWho e={ e } />
							{ /* The network, for a row a person or a visitor caused, read
							     from its log row as this is shown. Absent on file rows,
							     which have no request behind them at all. */ }
							{ undefined !== e.network ? (
								<span className="bs-ds-timeline__line bs-ds-timeline__network">
									{ e.network
										? sprintf(
												/* translators: %s: a network, e.g. 203.0.113.0/24. */
												__( 'From IP range %s', 'bettershield' ),
												e.network
										  )
										: __( 'No IP range recorded', 'bettershield' ) }
								</span>
							) : null }
							{ /* Named where the server names it; an option's name
							     or a bare account id is left out (#1793, #2489). */ }
							{ e.object_label ? (
								<span className="bs-ds-timeline__line">{ [ e.object_label, versions ].filter( Boolean ).join( ', ' ) }</span>
							) : e.snapshot?.object_id && ! String( e.snapshot.object_id ).startsWith( 'bettershield_' ) && ! [ 'user', 'setting', 'network_setting' ].includes( e.snapshot?.object_type ) ? (
								<>
									<span className="bs-ds-timeline__line bs-ds-timeline__path">
										<BreakablePath path={ e.snapshot.object_id } />
									</span>
									{ versions ? <span className="bs-ds-timeline__line">{ versions }</span> : null }
								</>
							) : null }
							<TimelineComparison e={ e } />
							{ e.snapshot?.details?.hooks?.length > 0 ? <span className="bs-ds-timeline__line">{ e.snapshot.details.hooks.join( ', ' ) }</span> : null }
							{ /* The code files a plugin's update brought, as Activity lists them. */ }
							{ 'update_code_changed' === e.type && e.snapshot?.details?.files?.length > 0 ? (
								<span className="bs-ds-timeline__line">
									{ [
										e.snapshot.details.files.join( ', ' ),
										Number( e.snapshot.details.more ) > 0
											? sprintf(
													/* translators: %s: number of further files the record counted without naming. */
													_n( 'and %s more', 'and %s more', Number( e.snapshot.details.more ), 'bettershield' ),
													Number( e.snapshot.details.more ).toLocaleString()
											  )
											: null,
									]
										.filter( Boolean )
										.join( ', ' ) }
								</span>
							) : null }
						</>
					}
				/>
			</Cell>
		</Row>
	);
}

/**
 * A folded row: the folder, how many files and when, said once, with the
 * paths behind a disclosure. A record the explanation links to opens it.
 */
function TimelineFold( { fold, records } ) {
	const [ open, setOpen ] = useState( false );
	const [ wanted, setWanted ] = useState( null );
	const first = records[ 0 ];
	const listId = `bs-incident-fold-${ first.id }`;
	// Files, not records: one file changed twice is one file, listed once
	// with each record beside it (#1834).
	const files = records.reduce( ( byPath, e ) => {
		const path = e.snapshot.object_id;

		byPath.set( path, [ ...( byPath.get( path ) || [] ), e ] );

		return byPath;
	}, new Map() );
	const count = files.size;

	useEffect( () => {
		if ( open && wanted ) {
			document.getElementById( `bs-incident-evidence-${ wanted }` )?.focus();
			setWanted( null );
		}
	}, [ open, wanted ] );

	const summary =
		'incident_code_added' === first.type
			? sprintf(
					/* translators: 1: a plugin or theme name, 2: number of files. */
					_n( '%1$s · %2$s new code file', '%1$s · %2$s new code files', count, 'bettershield' ),
					fold.name,
					formatCount( count )
			  )
			: sprintf(
					/* translators: 1: a plugin or theme name, 2: number of files. */
					_n( '%1$s · %2$s code file changed', '%1$s · %2$s code files changed', count, 'bettershield' ),
					fold.name,
					formatCount( count )
			  );

	return (
		<Row open={ open } className="bs-ds-timeline__record bs-ds-timeline__fold">
			<Cell>
				<TimelineWhen e={ first } ids={ records.map( ( e ) => e.id ) } />
			</Cell>
			<Cell>
				<TitleMeta
					title={ <strong className="bs-ds-timeline__label">{ summary }</strong> }
					meta={
						<>
							<TimelineWho e={ first } />
							<TimelineComparison e={ first } many={ count > 1 } />
							<span className="bs-ds-timeline__line">
								<Button
									type="ghost"
									size="sm"
									trailing={ open ? 'chevron-up' : 'chevron-down' }
									trailingTone="3"
									aria-expanded={ open }
									aria-controls={ open ? listId : undefined }
									onClick={ () => setOpen( ( was ) => ! was ) }
								>
									{ open
										? __( 'Hide the Files', 'bettershield' )
										: sprintf(
												/* translators: %s: number of files. */
												_n( 'Show the %s File', 'Show the %s Files', count, 'bettershield' ),
												formatCount( count )
										  ) }
								</Button>
							</span>
							{ open ? (
								<ul id={ listId } className="bs-ds-timeline__files">
									{ [ ...files ].map( ( [ path, held ] ) => (
										<li key={ held[ 0 ].id }>
											<span className="bs-ds-timeline__path">
												<BreakablePath path={ path } />
											</span>
											{ held.map( ( e ) => (
												<span key={ e.id } id={ `bs-incident-evidence-${ e.id }` } tabIndex={ -1 }>
													{ ' ' }
													{ /* A citation lands here: it says which file, as the
													     row did when it held one record. */ }
													<span className="screen-reader-text">{ path } </span>
													{ sprintf( /* translators: %d: the evidence record ID. */ __( 'Record #%d', 'bettershield' ), e.id ) }
												</span>
											) ) }
										</li>
									) ) }
								</ul>
							) : (
								// Where the explanation's links land while the list is
								// shut: reaching one opens the row and moves on to its record.
								records.map( ( e ) => (
									<span
										key={ e.id }
										id={ `bs-incident-evidence-${ e.id }` }
										tabIndex={ -1 }
										className="screen-reader-text"
										onFocus={ () => {
											setWanted( e.id );
											setOpen( true );
										} }
									/>
								) )
							) }
						</>
					}
				/>
			</Cell>
		</Row>
	);
}

export function IncidentTimeline( { incident, onMore, busy } ) {
	/*
	 * The first few, and the rest on request. An incident joining hundreds of
	 * records opened a timeline tens of thousands of pixels long, with the
	 * response and explanation panels somewhere past the end of it.
	 */
	const [ all, setAll ] = useState( false );
	const [ wanted, setWanted ] = useState( null );
	// Load more evidence goes once the last page is in, and the keyboard
	// went to the page with it: it goes to the fold's toggle instead (#1926).
	const loadMore = useRef( null );
	const fold = useRef( null );

	useFocusAfter( 'evidence' === busy, loadMore, fold );
	const sorted = [ ...( incident.evidence || [] ) ].sort( ( a, b ) => a.occurred_at.localeCompare( b.occurred_at ) || a.id - b.id );
	const folded = foldTimeline( sorted );
	const rows = all ? folded : folded.slice( 0, TIMELINE_SHOWN );

	/*
	 * The explanation cites records by id, and not every one it cites is
	 * among the first twenty: a link to one of the rest went nowhere. Each of
	 * the rest has a place for the link to land while they are folded away,
	 * which shows them all and moves on to the record, as a closed folder
	 * row does for its files.
	 */
	const behind = all ? [] : folded.slice( TIMELINE_SHOWN ).flatMap( ( row ) => row.records );

	useEffect( () => {
		if ( all && wanted ) {
			document.getElementById( `bs-incident-evidence-${ wanted }` )?.focus();
			setWanted( null );
		}
	}, [ all, wanted ] );
	// The incident's own count, not the page loaded so far.
	const total = Math.max( Number( incident.evidence_count ) || 0, sorted.length );
	const more = ( all || folded.length <= TIMELINE_SHOWN ) && incident.next_cursor > 0;

	return (
		<Part icon="history" title={ __( 'Evidence', 'bettershield' ) } className="bs-ds-timeline">
			{ incident.history ? (
				<p className="bs-ds-part__text">
					{ sprintf(
						/* translators: 1: date and time counting starts, e.g. "today, 6:08 AM UTC", 2: number of incidents. */
						_n( '%2$s incident recorded since %1$s.', '%2$s incidents recorded since %1$s.', incident.history.recorded_incidents, 'bettershield' ),
						formatTime( incident.history.since ),
						formatCount( incident.history.recorded_incidents )
					) }{ ' ' }
					{ /* Only where a signed-in account is part of it: an incident
					     no account is linked to has none to share (#2617). A count
					     above zero means one is, though its record may not be on
					     the page of evidence loaded so far. */ }
					{ Number( incident.history.other_incidents_sharing_actor ) > 0 || sorted.some( ( e ) => Number( e.actor_id ) > 0 ) ? (
						<>
							{ sprintf(
								/* translators: %s: number of other incidents. */
								_n(
									'%s other incident involves the same account.',
									'%s other incidents involve the same account.',
									incident.history.other_incidents_sharing_actor,
									'bettershield'
								),
								formatCount( incident.history.other_incidents_sharing_actor )
							) }{ ' ' }
						</>
					) : null }
					{ __( 'This only counts activity BetterShield still has on record.', 'bettershield' ) }
				</p>
			) : null }
			<p className="bs-ds-part__text">
				{ __(
					'Changes that happen close together may be unrelated. A changed file isn’t always harmful; compare it with the official version.',
					'bettershield'
				) }
			</p>
			{ rows.length || folded.length > TIMELINE_SHOWN || more ? (
				<Table
					label={ __( 'Evidence', 'bettershield' ) }
					className="bs-ds-timeline__table"
					columns={ [
						{ key: 'when', label: __( 'When', 'bettershield' ), width: '148px' },
						{ key: 'record', label: __( 'Record', 'bettershield' ) },
					] }
				>
					{ rows.map( ( row ) =>
						row.fold && row.records.length > 1 ? (
							<TimelineFold key={ `fold-${ row.records[ 0 ].id }` } fold={ row.fold } records={ row.records } />
						) : (
							<TimelineCard key={ row.records[ 0 ].id } e={ row.records[ 0 ] } />
						)
					) }
					{ folded.length > TIMELINE_SHOWN ? (
						<WholeRow kind="foot">
							<Button ref={ fold } type="ghost" size="sm" trailing={ all ? 'chevron-up' : 'chevron-down' } trailingTone="3" aria-expanded={ all } onClick={ () => setAll( ( open ) => ! open ) }>
								{ all
									? __( 'Show Fewer', 'bettershield' )
									: sorted.length < total
									? sprintf(
											/* translators: 1: evidence records loaded so far, 2: all the incident has. */
											__( 'Show the %1$s Loaded of %2$s Records', 'bettershield' ),
											formatCount( sorted.length ),
											formatCount( total )
									  )
									: sprintf(
											/* translators: %s: number of evidence records. */
											_n( 'Show the %s Record', 'Show All %s Records', total, 'bettershield' ),
											formatCount( total )
									  ) }
							</Button>
							{ behind.map( ( e ) => (
								<span
									key={ e.id }
									id={ `bs-incident-evidence-${ e.id }` }
									tabIndex={ -1 }
									className="screen-reader-text"
									onFocus={ () => {
										setWanted( e.id );
										setAll( true );
									} }
								/>
							) ) }
						</WholeRow>
					) : null }
					{ more ? (
						<WholeRow kind="foot">
							<Button ref={ loadMore } type="secondary" size="sm" isBusy={ 'evidence' === busy } disabled={ Boolean( busy ) } onClick={ onMore }>
								{ __( 'Load More Evidence', 'bettershield' ) }
							</Button>
						</WholeRow>
					) : null }
				</Table>
			) : null }
		</Part>
	);
}

/**
 * The activity log around this incident: everything in the days it covers,
 * and the same days narrowed to each account and each network its evidence
 * names. A set of links rather than a copy of the log, so what opens is the
 * log itself, with its own filters and export.
 *
 * @param {Object} props
 * @param {Object} props.incident The incident as its detail read answered.
 */
export function RelatedActivity( { incident } ) {
	const window_ = incident.window || {};
	// The log reads its days in the reader's calendar, so the incident's span
	// is read into the reader's days from the moments it covers. The site's
	// days are the fallback where the moments did not arrive.
	const days = {
		since: readerDay( window_.start ) || window_.since || '',
		until: readerDay( window_.end ) || window_.until || '',
	};
	const everything = activityUrl( days );

	if ( ! everything || ! days.since ) {
		return null;
	}

	const evidence = incident.evidence || [];
	// A few of each: past that, the log's own filters are the better tool.
	const accounts = [ ...new Set( evidence.map( ( e ) => e.actor_id ).filter( ( id ) => id > 0 ) ) ].slice( 0, 5 );
	const networks = [ ...new Set( evidence.map( ( e ) => e.network ).filter( Boolean ) ) ].slice( 0, 5 );

	return (
		<Part icon="activity" title={ __( 'Related activity', 'bettershield' ) } className="bs-ds-related">
			<p className="bs-ds-part__text">
				{ days.since === days.until
					? sprintf(
							/* translators: %s: a date. */
							__( 'The activity log on %s, the day this incident covers.', 'bettershield' ),
							dayText( days.since )
					  )
					: sprintf(
							/* translators: 1: a date, 2: a later date. */
							__( 'The activity log from %1$s to %2$s, the days this incident covers.', 'bettershield' ),
							dayText( days.since ),
							dayText( days.until )
					  ) }
			</p>
			<ul className="bs-ds-related__links">
				<li>
					<Button type="link" size="sm" trailing="arrow-right" href={ everything }>
						{ __( 'Everything in These Days', 'bettershield' ) }
					</Button>
				</li>
				{ accounts.map( ( id ) => (
					<li key={ `account-${ id }` }>
						<Button type="link" size="sm" trailing="arrow-right" href={ activityUrl( { ...days, actor: `user:${ id }` } ) }>
							{ sprintf(
								/* translators: %d: an account's number. */
								__( 'Account #%d in These Days', 'bettershield' ),
								id
							) }
						</Button>
					</li>
				) ) }
				{ networks.map( ( label ) => (
					<li key={ label }>
						<Button type="link" size="sm" trailing="arrow-right" href={ activityUrl( { ...days, network: label } ) }>
							{ sprintf(
								/* translators: %s: a network, e.g. 203.0.113.0/24. */
								__( 'Network %s in These Days', 'bettershield' ),
								label
							) }
						</Button>
					</li>
				) ) }
			</ul>
		</Part>
	);
}

/**
 * The record in four facts, from the page already fetched: how many incidents
 * this view holds, the evidence behind them, when correlation last ran, and
 * whether saved records are still waiting. The list endpoint pages, so the
 * first is what is loaded, with a plus where there is more.
 *
 * @param {Object}  props
 * @param {?Object} props.list    The incidents page, or null while loading.
 * @param {string}  props.status  Which view is shown: open or resolved.
 * @param {boolean} props.pending Whether the first page is still on its way.
 */
function IncidentsGlance( { list, status, pending = false } ) {
	const incidents = ( list && list.incidents ) || [];
	const more = list && list.next_cursor > 0;
	const engine = ( list && list.engine ) || {};
	const counts = ( list && list.counts ) || {};
	/*
	 * The open incidents and their evidence, whichever tab is on screen: on
	 * Handled the cards counted the handled page, read "Linked events to
	 * review" over it, and "Evidence 0" while an open incident had two
	 * (#2243). The site's own totals; the page on screen only where the site
	 * gave none and the page is the open one.
	 */
	const fromPage = 'open' === status;
	let open = null;
	let evidence = null;

	if ( Number.isFinite( counts.open ) ) {
		open = String( counts.open );
	} else if ( list && fromPage ) {
		open = `${ incidents.length }${ more ? '+' : '' }`;
	}

	if ( Number.isFinite( counts.open_evidence ) ) {
		evidence = counts.open_evidence;
	} else if ( list && fromPage ) {
		evidence = incidents.reduce( ( sum, item ) => sum + Number( item.evidence_count || 0 ), 0 );
	}

	const openCount = Number.isFinite( counts.open ) ? counts.open : incidents.length;

	let waiting = __( 'Up to date', 'bettershield' );
	let waitingTone;
	let waitingDetail = __( 'All recent activity is checked', 'bettershield' );

	if ( engine.failed ) {
		waiting = __( 'Retrying', 'bettershield' );
		waitingTone = 'caution';
		waitingDetail = __( 'The last check didn’t finish', 'bettershield' );
	} else if ( engine.pending ) {
		waiting = __( 'Some activity', 'bettershield' );
		waitingTone = 'caution';
		waitingDetail = __( 'Recent activity not checked yet', 'bettershield' );
	}

	const tiles = [
		{
			key: 'count',
			icon: 'layers',
			label: __( 'Open', 'bettershield' ),
			value: null !== open ? open : '—',
			tone: null !== open && '0' !== open ? 'caution' : undefined,
			detail: __( 'Incidents waiting for your review', 'bettershield' ),
		},
		{
			key: 'evidence',
			icon: 'file-text',
			label: __( 'Evidence', 'bettershield' ),
			value: null !== evidence ? evidence.toLocaleString() : '—',
			detail: sprintf(
				/* translators: %s: number of open incidents the evidence belongs to. */
				_n( 'Related records for %s open incident', 'Related records for %s open incidents', openCount, 'bettershield' ),
				formatCount( openCount )
			),
		},
		{
			key: 'correlated',
			icon: 'clock',
			label: __( 'Last checked', 'bettershield' ),
			value: engine.last_checked_at ? whenPhrase( engine.last_checked_at ) : __( 'Not yet', 'bettershield' ),
			text: true,
			detail: __( 'Sign-in and file changes compared', 'bettershield' ),
		},
		{ key: 'waiting', icon: 'hourglass', label: __( 'Still to check', 'bettershield' ), value: waiting, tone: waitingTone, detail: waitingDetail },
	];

	/*
	 * Before the first page has landed every tile is a guess: the counts are
	 * of nothing yet, and "Nothing waiting" would be said about records nobody
	 * has read. Each holds its place instead.
	 */
	return <Stats label={ __( 'Incidents at a glance', 'bettershield' ) } tiles={ pending ? tiles.map( ( tile ) => ( { ...tile, pending: true } ) ) : tiles } />;
}

export default function Incidents() {
	const [ status, setStatus ] = useState( 'open' );
	const [ list, setList ] = useState( null );
	const [ detail, setDetail ] = useState( null );
	const [ error, setError ] = useState( null );
	// The read that failed, so "Try Again" repeats it: the first page, a
	// further page, or one incident's timeline.
	const retry = useRef( null );
	/*
	 * What is being read, rather than only whether something is: the first
	 * page, a further page, or one incident's timeline — `list`, `more`,
	 * `detail-<id>` or `evidence`. Each has its own place on screen to wait
	 * in, and a single flag drew every one of them as the same block above
	 * the list, pushing the list down while one timeline was fetched.
	 */
	const [ fetching, setFetching ] = useState( null );
	const generation = useRef( 0 );
	const root = useRef( null );
	const focusAfterChange = useRef( false );
	// Load more incidents goes once the last page is in: focus comes back to
	// it, or to the records it extended (#2028).
	const moreIncidents = useRef( null );

	useFocusAfter( 'more' === fetching, moreIncidents, root );
	const { changeIncidentStatus, refreshIncidents, busy, saved } = useStore();
	const load = useCallback(
		async ( cursor = 0 ) => {
			const request = ++generation.current;
			setFetching( cursor ? 'more' : 'list' );
			setError( null );
			try {
				const data = await apiFetch( { path: `/bettershield/v1/incidents?status=${ status }&cursor=${ cursor }` } );
				if ( request === generation.current ) {
					setList( ( old ) => ( { ...data, read: status, incidents: cursor ? [ ...( old?.incidents || [] ), ...data.incidents ] : data.incidents } ) );
				}
			} catch ( e ) {
				if ( request === generation.current ) {
					retry.current = () => load( cursor );
					setError( e );
				}
			} finally {
				if ( request === generation.current ) {
					setFetching( null );
				}
			}
		},
		[ status ]
	);
	useEffect( () => {
		setList( null );
		setDetail( null );
		load();
		return () => {
			++generation.current;
		};
	}, [ load ] );
	useEffect( () => {
		if ( saved?.key === 'incidents-refresh' || /^incident-\d+$/.test( saved?.key || '' ) ) {
			setDetail( null );
			load();
		}
	}, [ saved, load ] );
	useEffect( () => {
		if ( list && focusAfterChange.current ) {
			root.current?.focus();
			focusAfterChange.current = false;
		}
	}, [ list ] );
	const changeStatus = ( id, next ) => {
		focusAfterChange.current = true;
		// A reopened incident is open again, so the Open tab is where it is
		// shown: the page stayed on the emptied Handled list (#2243).
		return changeIncidentStatus( id, next, 'resolved' === status && 'resolved' !== next ? () => setStatus( 'open' ) : undefined );
	};
	const open = async ( id, cursor = 0 ) => {
		const request = ++generation.current;
		setFetching( cursor ? 'evidence' : `detail-${ id }` );
		setError( null );
		try {
			const data = await apiFetch( { path: `/bettershield/v1/incidents/${ id }?cursor=${ cursor }` } );
			if ( request === generation.current ) {
				setDetail( ( old ) => ( { ...data, evidence: cursor && old?.id === id ? [ ...old.evidence, ...data.evidence ] : data.evidence } ) );
			}
		} catch ( e ) {
			if ( request === generation.current ) {
				retry.current = () => open( id, cursor );
				setError( e );
			}
		} finally {
			if ( request === generation.current ) {
				setFetching( null );
			}
		}
	};
	/*
	 * The incident a link from the log asked for, opened once its list is
	 * in (#2242). One already handled is on the other tab, which is read
	 * for it once; one on neither first page is left for the reader to find.
	 */
	const linked = useRef( { id: linkedIncident(), other: false } );
	useEffect( () => {
		const { id, other } = linked.current;

		// Only a list read for the tab on screen: a tab just switched still
		// holds the other tab's list until its own read lands.
		if ( ! id || ! list || list.read !== status || fetching ) {
			return;
		}

		if ( list.incidents.some( ( item ) => Number( item.id ) === id ) ) {
			linked.current = { id: 0, other };
			open( id );
		} else if ( 'open' === status && ! other ) {
			linked.current = { id, other: true };
			setStatus( 'resolved' );
		} else {
			linked.current = { id: 0, other };
		}
	} );
	// The first page of a view is on its way: nothing is on screen for it yet.
	const firstPage = 'list' === fetching && ! list;
	// A view already on screen is being read again, after an action on it.
	const refreshing = 'list' === fetching && Boolean( list );
	const incidents = ( list && list.incidents ) || [];
	// What the view on screen holds, on its own tab: the other view has not
	// been read, so its tab says nothing rather than a number nobody counted.
	const shownCount = list ? `${ incidents.length }${ list.next_cursor > 0 ? '+' : '' }` : null;
	// Each list's own total where the site says it, so an incident moved by
	// Mark handled or Reopen is counted on the other tab at once (#1921).
	const tabCount = ( key ) => {
		if ( list && list.counts && Number.isFinite( list.counts[ key ] ) ) {
			return String( list.counts[ key ] );
		}

		return key === status ? shownCount : null;
	};

	return (
		<div ref={ root } tabIndex={ -1 } aria-label={ __( 'Incident records', 'bettershield' ) } className="bs-ds-incidents">
			<IncidentsGlance list={ list } status={ status } pending={ ! list && ! error } />

			<Card className="bs-ds-incidents__card" aria-labelledby="bs-ds-incidents-title">
				<CardHead icon="link-2" title={ __( 'Incidents', 'bettershield' ) } id="bs-ds-incidents-title">
					{ /* Held through the refresh and the list read after it, and
					     focusable all the while (#1926). */ }
					{ list?.can_manage ? (
						<Button
							type="secondary"
							size="sm"
							icon="refresh-cw"
							iconTone="2"
							isBusy={ isWorking( busy, 'incidents-refresh' ) }
							disabled={ Boolean( fetching ) || isWorking( busy, 'incidents-refresh' ) }
							accessibleWhenDisabled
							onClick={ refreshIncidents }
						>
							{ __( 'Check for New Incidents', 'bettershield' ) }
						</Button>
					) : null }
				</CardHead>
				<p className="bs-ds-incidents__intro">
					{ __( 'Groups sign-in, account and file changes that happened close together, so you can review them as one. It doesn’t scan for malware.', 'bettershield' ) }
				</p>

				<Tabs
					id={ TABS_ID }
					label={ __( 'Filter incidents by status', 'bettershield' ) }
					selected={ status }
					onSelect={ setStatus }
					tabs={ [
						{ key: 'open', label: __( 'Open', 'bettershield' ), count: tabCount( 'open' ) },
						{ key: 'resolved', label: __( 'Handled', 'bettershield' ), count: tabCount( 'resolved' ) },
					] }
				/>

				<div { ...panelProps( TABS_ID, status ) }>
					{ error ? (
						<div className="bs-ds-incidents__notes">
							<ErrorState onRetry={ () => ( retry.current ? retry.current() : load() ) }>{ error.message }</ErrorState>
						</div>
					) : null }
					{ list && ! list.incidents.length && ! fetching ? (
						<EmptyState>{ __( 'No incidents here. That does not mean the site is clean; check Files and Findings too.', 'bettershield' ) }</EmptyState>
					) : null }

					{ /* The first page stands in as rows where its rows will be. */ }
					{ firstPage ? (
						<Skeleton label={ __( 'Loading incidents…', 'bettershield' ) }>
							<div className="bs-ds-incidents__bones">
								<IncidentRowsBone rows={ 3 } />
							</div>
						</Skeleton>
					) : null }

					{ /*
					   A view read again after an action keeps its rows, dimmed
					   while the fresh copy arrives, and a further page arrives as
					   rows at the foot of the ones already there.
					*/ }
					{ incidents.length ? (
						<div className={ `bs-ds-incidents__list${ refreshing ? ' is-settling' : '' }` } aria-busy={ refreshing || 'more' === fetching }>
							<Table
								label={ __( 'Incident records', 'bettershield' ) }
								columns={ [
									{ key: 'incident', label: __( 'Incident', 'bettershield' ) },
									{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
								] }
							>
								{ incidents.map( ( item ) => {
									const opened = detail?.id === item.id;
									const working = isWorking( busy, `incident-${ item.id }` ) || Boolean( fetching );

									return (
										<div key={ item.id } role="rowgroup" className="bs-ds-incident">
											<Row open={ opened }>
												<Cell>
													<TitleMeta
														title={
															<span className="bs-ds-incident__titlerow">
																<h3 className="bs-ds-incident__title">{ confidenceLabel( item.confidence ) }</h3>
																{ 'acknowledged' === item.status ? <Badge>{ __( 'Acknowledged', 'bettershield' ) }</Badge> : null }
															</span>
														}
														meta={
															<span className="bs-ds-incident__facts">
																<span className="bs-ds-incident__ref">
																	{ sprintf(
																		/* translators: %d: the incident's own number. */
																		__( 'Incident #%d', 'bettershield' ),
																		item.id
																	) }
																</span>
																{ /* A plural for each count: one string for both read
																     "1 anchors", with nothing for a translator to decline. */ }
																<span className="bs-ds-incident__count">
																	{ sprintf(
																		/* translators: %s: how many anchors the incident has. */
																		_n( '%s main event', '%s main events', item.anchor_count, 'bettershield' ),
																		formatCount( item.anchor_count )
																	) }
																	{ ' · ' }
																	{ sprintf(
																		/* translators: %s: how many evidence records the incident has. */
																		_n( '%s related record', '%s related records', item.evidence_count, 'bettershield' ),
																		formatCount( item.evidence_count )
																	) }
																</span>
															</span>
														}
													/>
												</Cell>
												<Cell align="end">
													{ list.can_manage && item.status !== 'resolved' ? (
														<>
															{ item.status === 'new' ? (
																<Button
																	type="ghost"
																	size="sm"
																	disabled={ working }
																	aria-label={ sprintf(
																		/* translators: %d: the incident's own number. */
																		__( 'Acknowledge, incident #%d', 'bettershield' ),
																		item.id
																	) }
																	onClick={ () => changeStatus( item.id, 'acknowledged' ) }
																>
																	{ __( 'Acknowledge', 'bettershield' ) }
																</Button>
															) : null }
															{ /* Named with its incident, as each of these is:
															     picked by ear every row's button was the same.
															     The name starts with the words on the button, so
															     saying what it reads reaches it (#1929). */ }
															<Button
																type="ghost"
																size="sm"
																disabled={ working }
																aria-label={ sprintf(
																	/* translators: %d: the incident's own number. */
																	__( 'Mark Handled, incident #%d', 'bettershield' ),
																	item.id
																) }
																onClick={ () => changeStatus( item.id, 'resolved' ) }
															>
																{ __( 'Mark Handled', 'bettershield' ) }
															</Button>
														</>
													) : null }
													{ /* Handled is not final: a click on the wrong row stopped an
													     incident collecting evidence, and its plan said to reopen
													     it with nothing that could. */ }
													{ list.can_manage && item.status === 'resolved' ? (
														<Button
															type="ghost"
															size="sm"
															disabled={ working }
															aria-label={ sprintf(
																/* translators: %d: the incident's own number. */
																__( 'Reopen, incident #%d', 'bettershield' ),
																item.id
															) }
															onClick={ () => changeStatus( item.id, 'acknowledged' ) }
														>
															{ __( 'Reopen', 'bettershield' ) }
														</Button>
													) : null }
													<Button
														type="secondary"
														size="sm"
														trailing={ opened ? 'chevron-up' : 'chevron-down' }
														trailingTone="3"
														isBusy={ `detail-${ item.id }` === fetching }
														disabled={ Boolean( fetching ) }
														aria-expanded={ opened }
														aria-label={ sprintf(
															opened
																? /* translators: %d: the incident's own number. */
																  __( 'Hide Timeline, incident #%d', 'bettershield' )
																: /* translators: %d: the incident's own number. */
																  __( 'Review Timeline, incident #%d', 'bettershield' ),
															item.id
														) }
														onClick={ () => ( opened ? setDetail( null ) : open( item.id ) ) }
													>
														{ opened ? __( 'Hide Timeline', 'bettershield' ) : __( 'Review Timeline', 'bettershield' ) }
													</Button>
												</Cell>
											</Row>

											{ /* The timeline asked for, standing in where it opens. */ }
											{ `detail-${ item.id }` === fetching && ! opened ? (
												<div className="bs-ds-incident__under bs-ds-incident__under--open" role="row">
													<div role="cell" className="bs-ds-incident__body">
														<TimelineBone />
													</div>
												</div>
											) : null }

											{ opened ? (
												<div className="bs-ds-incident__under bs-ds-incident__under--open" role="row">
													<div role="cell" className="bs-ds-incident__body">
														<IncidentTimeline incident={ detail } busy={ fetching } onMore={ () => open( item.id, detail.next_cursor ) } />
														<RelatedActivity incident={ detail } />
														{ list.can_manage ? <IncidentExplanation key={ `${ item.id }-${ detail.evidence_count }` } incident={ item.id } /> : null }
														{ list.can_manage ? <IncidentResponse incident={ item.id } resolved={ item.status === 'resolved' } /> : null }
													</div>
												</div>
											) : null }
										</div>
									);
								} ) }
								{ 'more' === fetching ? (
									<div className="bs-ds-incidents__bones" aria-hidden="true">
										<IncidentRowsBone rows={ 2 } />
									</div>
								) : null }
								{ list.next_cursor > 0 ? (
									<WholeRow kind="foot">
										<Button ref={ moreIncidents } type="secondary" size="sm" isBusy={ 'more' === fetching } disabled={ Boolean( fetching ) } onClick={ () => load( list.next_cursor ) }>
											{ __( 'Load More Incidents', 'bettershield' ) }
										</Button>
									</WholeRow>
								) : null }
							</Table>
						</div>
					) : null }

					{ /* When the correlation last ran, and what it is still waiting
					     on. A list with nothing in it means something different
					     depending on this line, so it is said at the foot of the
					     list rather than above it — and nothing is said until the
					     list has been read, because "has not completed yet" is what
					     an unread list would claim. */ }
					<p className="bs-ds-incidents__note" role="status">
						{ ! list && ! error ? (
							<Bone w="24em" />
						) : (
							<>
								{ list?.engine?.last_checked_at
									? sprintf(
											/* translators: %s: a date and time. */
											__( 'Last checked: %s', 'bettershield' ),
											formatTime( list.engine.last_checked_at )
									  )
									: __( 'Not checked yet. It runs in the background, or press Check for New Incidents.', 'bettershield' ) }
								{ list?.engine?.pending ? __( ' Some recent activity is still being checked.', 'bettershield' ) : '' }
								{ list?.engine?.failed ? __( ' The last check didn’t finish. It will try again automatically.', 'bettershield' ) : '' }
							</>
						) }
					</p>
				</div>
			</Card>
		</div>
	);
}
