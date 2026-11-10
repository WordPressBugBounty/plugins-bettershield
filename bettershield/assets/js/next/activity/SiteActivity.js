/**
 * Activity › Site activity: the record of what happened here, in the order
 * it happened.
 *
 * This screen owns its own fetching rather than going through the shared
 * resource store. The store models a screen's data as one value that a
 * mutation can write back wholesale; a paged log is the opposite shape,
 * appended to and never replaced, and forcing it through that door would
 * either discard pages on every refresh or teach the store a special case it
 * has no other use for.
 *
 * The retention boundary is stated as a plain fact at the end of the list. It
 * is never an upgrade prompt, and it is never dressed up as an error.
 *
 * The four facts, the previous values card for whoever manages the site, then
 * the log in one card: the categories as tabs with the search and the rest of
 * the filters at the row's end, a group row per day, a row per entry, and the
 * older entries with the seal note at its foot.
 *
 * The network's log is the same screen in a mode of its own: the union of
 * every site's rows, read from the network's route. A second implementation
 * of a paged, filtered log would be the same lines with one predicate changed,
 * and the two would drift. The mode adds the site filter and each row's site,
 * and leaves out what belongs to one site: the seal, the export, the previous
 * values and the address that follows the filters.
 */

import './SiteActivity.css';

import { Dropdown } from '@wordpress/components';
import { useCallback, useEffect, useMemo, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import { activityAreas, cameFromAlert, incidentUrl, linkedLogFilters, linkedSearch, NAVIGATED, writeNarrowing } from '../../nav';
import { logQuery } from '../../rest';
import { download } from '../../ui/download';
import { revealWhenPlaced } from '../../ui/revealWhenPlaced';
import { reviewToken } from '../data/observed';
import { eventIcon } from '../data/activity';
import {
	actorOf,
	areaLabel,
	byDay,
	clockTime,
	dayLabel,
	glanceLabels,
	logTiles,
	narrowingRefused,
	networkWords,
	NO_FILTERS,
	sealState,
	summarize,
	today,
	viewKey,
	wholeDay,
} from '../data/log';
import { AlertFeedback } from '../findings/Extras';
import { SEVERITY } from '../findings/Rows';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import InfoTip from '../ui/InfoTip';
import Field from '../ui/Field';
import { useFocusAfter } from '../ui/focus';
import Icon from '../ui/Icon';
import Skeleton, { Bone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { ErrorState } from '../ui/States';
import Table, { Cell, Row, WholeRow } from '../ui/Table';
import { panelProps } from '../ui/tabKeys';
import FitTabs from './FitTabs';
import ObservedChanges, { ChangeReview, ObservedChangesBone } from './ObservedChanges';

/**
 * The two records this screen can be pointed at.
 *
 * The network's is the union of every site's rows and carries the site each
 * one came from; the site's is what it always was. Only the routes differ —
 * the paging, the filters, the counts and the retention line are the same
 * questions asked of a wider set of rows.
 */
const ROUTES = {
	site: { list: '/bettershield/v1/activity', csv: '/bettershield/v1/activity/export' },
	network: { list: '/bettershield/v1/network/activity', csv: null },
};

const TABS_ID = 'bs-ds-log-tabs';

/** Each fact's 14 icon in the strip. */
const STAT_ICONS = { entries: 'list', who: 'users', seal: 'shield-check', kept: 'clock' };

/** The log's columns: the entry, its category, and the time it happened. */
const COLUMNS = () => [
	{ key: 'event', label: __( 'Event', 'bettershield' ) },
	{ key: 'area', label: __( 'Category', 'bettershield' ), width: '168px' },
	{ key: 'when', label: __( 'When', 'bettershield' ), width: '88px', align: 'end' },
];

/**
 * One entry: what happened and how much it matters, who did it and what to,
 * what can be done from it, which part of the site it belongs to, and when.
 *
 * Who did it sits under what happened rather than in a column of its own. It
 * is the same sentence either way, and as a column it forced every row to the
 * height of the longest actor on screen — on a log where most rows are the
 * plugin's own and say "BetterShield".
 *
 * @param {Object}   props
 * @param {Object}   props.event      The entry.
 * @param {boolean}  props.canManage  Whether this reader manages the site, and may review a recorded change.
 * @param {Function} props.onNarrow   Narrows the log to this row's person or network.
 * @param {Object}   props.narrowedTo What the log is narrowed to already.
 * @param {boolean}  props.reviewing  This row's review is open under it.
 * @param {Function} props.onReview   Opens this row's review, or closes it with null.
 * @param {boolean}  props.network    The row is on the network's log, which names its site.
 */
function Event( { event, canManage, onNarrow, narrowedTo = {}, reviewing = false, onReview, network = false } ) {
	const toggle = useRef( null );
	const details = summarize( event );
	const who = actorOf( event );
	// A pivot to what the log is already narrowed to would do nothing.
	const person = event.actor_id > 0 && narrowedTo.actor !== `user:${ event.actor_id }`;
	/*
	 * A network says where a person or a visitor came from. A row the site
	 * wrote itself — WP-CLI, a scheduled task — carries the server's own
	 * address, and "Everything From This Network" there pivoted to the
	 * server. The incident line keeps it to these two for the same reason.
	 */
	const from = [ 'user', 'anonymous' ].includes( event.actor_type ) ? event.network : null;
	const place = from && narrowedTo.network !== from;
	// What a manager can review from the row: a recorded change, or the
	// guidance for one recorded before capture was on.
	const token = canManage && ! network ? reviewToken( event ) : null;
	const open = null !== token && reviewing;
	const severity = 'info' === event.severity ? null : SEVERITY[ event.severity ] || null;
	const area = areaLabel( event );
	const panel = `bs-ds-review-${ event.id }`;
	// A row about an incident leads to its timeline: its subject was a bare
	// number with nothing to follow (#2242). The network's log names a row
	// of another site, whose incidents are on that site's own screen.
	const incident = ! network && 'incident' === event.object_type && /^[1-9][0-9]*$/.test( String( event.object_id || '' ) ) ? Number( event.object_id ) : 0;
	const actions = ( onNarrow && ( person || place ) ) || incident > 0 || null !== token;

	return (
		<>
			<Row className="bs-ds-event" open={ open } hover>
				<Cell className="bs-ds-event__cell">
					<span className="bs-ds-event__what">
						<Icon name={ eventIcon( event ) } size={ 16 } tone="2" />
						<span className="bs-ds-event__text">
							<span className="bs-ds-event__label">
								{ event.label }
								{ severity ? (
									<Badge tone={ severity.tone } icon={ severity.icon }>
										{ severity.label() }
									</Badge>
								) : null }
							</span>

							<span className="bs-ds-event__meta">
								{ /* Which site the entry came from, on the network's log
								     only. On one site's own log every row would carry the
								     same name. */ }
								{ network ? <span className="bs-ds-event__site">{ event.site_label }</span> : null }
								<span>{ who }</span>
								{ details.map( ( detail, index ) => (
									<span key={ index } className={ `bs-ds-event__detail${ detail.words ? ' is-words' : '' }` }>
										{ detail.text }
									</span>
								) ) }
								{ /* The door is worth naming only when it is not the usual
								     one: the dashboard's own calls are the default and say
								     nothing. */ }
								{ event.entry_path === 'wp-cli' ? <span className="bs-ds-event__via">{ __( 'via WP-CLI', 'bettershield' ) }</span> : null }
								{ /* The network, never the address: stored truncated, and
								     the only honest answer to "where did this come from".
								     Absent on rows recorded without a request behind them.
								     Why it is a network is one press away, never on hover
								     alone (#1940). */ }
								{ from ? (
									<span className="bs-ds-event__from">
										{ networkWords( from ) }
										<InfoTip label={ __( 'About the source network', 'bettershield' ) }>
											{ __( 'The visitor’s network (the IP address with the last part removed). Full IP addresses are never stored.', 'bettershield' ) }
										</InfoTip>
									</span>
								) : null }
							</span>

							{ /* What can be done from the row, on a line of its own under
							     the facts: the pivots that narrow the log first, together,
							     and Review change, which opens something rather than
							     narrowing, set apart at the line's end. */ }
							{ actions ? (
								<span className="bs-ds-event__actions">
									{ /* Everything from the person or the network on this row:
									     the same log, narrowed to it, without retyping either.
									     Named with whose and which, or every row's pivot is the
									     same control to a list of buttons read out. */ }
									{ onNarrow && person ? (
										<Button
											type="linksub"
											size="sm"
											className="bs-ds-event__pivot"
											/* translators: %s: a person, or the site itself. */
											aria-label={ sprintf( __( 'Everything From This Person, %s', 'bettershield' ), who ) }
											onClick={ () => onNarrow( { actor: `user:${ event.actor_id }` } ) }
										>
											{ __( 'Everything From This Person', 'bettershield' ) }
										</Button>
									) : null }
									{ onNarrow && place ? (
										<Button
											type="linksub"
											size="sm"
											className="bs-ds-event__pivot"
											/* translators: %s: a network, e.g. 203.0.113.x. */
											aria-label={ sprintf( __( 'Everything From This Network, %s', 'bettershield' ), networkWords( from ) ) }
											onClick={ () => onNarrow( { network: from } ) }
										>
											{ __( 'Everything From This Network', 'bettershield' ) }
										</Button>
									) : null }
									{ incident > 0 ? (
										<Button
											type="linksub"
											size="sm"
											className="bs-ds-event__pivot"
											href={ incidentUrl( incident ) }
											/* translators: %d: the number of an incident. */
											aria-label={ sprintf( __( 'Open incident #%d', 'bettershield' ), incident ) }
										>
											{ __( 'Open Incident', 'bettershield' ) }
										</Button>
									) : null }
									{ null !== token ? (
										<Button
											ref={ toggle }
											type="ghost"
											size="sm"
											className="bs-ds-event__review"
											trailing={ open ? 'chevron-up' : 'chevron-down' }
											trailingTone="3"
											aria-expanded={ open }
											aria-controls={ open ? panel : undefined }
											onClick={ () => onReview( open ? null : event.id ) }
										>
											{ __( 'Review Change', 'bettershield' ) }
										</Button>
									) : null }
								</span>
							) : null }
						</span>
					</span>
				</Cell>

				<Cell className="bs-ds-event__area">{ area ? <Badge>{ area }</Badge> : null }</Cell>

				<Cell align="end" className="bs-ds-event__when">
					{ clockTime( event.occurred_at ) }
				</Cell>
			</Row>
			{ open ? (
				<div className="bs-ds-event__under" role="row">
					<div role="cell">
						<ChangeReview
							id={ panel }
							token={ token }
							level={ 3 }
							onClose={ () => {
								onReview( null );
								// Escape closes it from inside; the keyboard goes back to
								// the control that opened it.
								if ( toggle.current ) {
									toggle.current.focus();
								}
							} }
						/>
					</div>
				</div>
			) : null }
		</>
	);
}

/**
 * One day: its row, saying the date and what the seal chain says about it,
 * and its entries. A box per day, so the day's row is held at the top only
 * while that day's own entries scroll past.
 *
 * @param {Object} props
 * @param {Object} props.group    The day's entries.
 * @param {Object} props.seals    What the last daily check said about the chain.
 * @param {*}      props.children The entries' rows.
 */
function Day( { group, seals, children } ) {
	const seal = sealState( group, seals );

	return (
		<div className="bs-ds-log__day" role="rowgroup">
			<WholeRow kind="group">
				<span className="bs-ds-log__date">{ dayLabel( group.day ) }</span>
				{ /*
				   Today's day still open is the usual state, said on every
				   visit, so it is a clock whose words are one press away
				   (#1325). The other states stay in words.
				*/ }
				{ seal && seal.today ? (
					<span className={ `bs-ds-log__seal bs-ds-log__seal--mark is-${ seal.tone }` }>
						<InfoTip icon="clock" label={ seal.text }>
							{ seal.text }
						</InfoTip>
					</span>
				) : null }
				{ seal && ! seal.today ? <span className={ `bs-ds-log__seal is-${ seal.tone }` }>{ seal.text }</span> : null }
			</WholeRow>
			{ children }
		</div>
	);
}

/** Widths for a run of stand-in entries, so no two neighbors match. */
const ROW_WIDTHS = [
	[ '14em', '9em' ],
	[ '19em', '12em' ],
	[ '11em', '8em' ],
	[ '16em', '14em' ],
	[ '13em', '7em' ],
	[ '21em', '10em' ],
];

/**
 * Entries standing in for themselves: what happened with who did it under
 * it, the category, and the time at the end, in the log's own columns.
 *
 * @param {Object} props
 * @param {number} props.rows How many.
 */
function PageBone( { rows = 3 } ) {
	return (
		<div className="bs-ds-log__bones" aria-hidden="true">
			{ ROW_WIDTHS.slice( 0, rows ).map( ( [ w, who ] ) => (
				<div key={ w } className="bs-ds-log__bonerow">
					<span className="bs-ds-log__bonetext">
						<Bone kind="title" w={ w } />
						<Bone w={ who } />
					</span>
					<Bone w="5em" />
					<Bone w="4.5em" />
				</div>
			) ) }
		</div>
	);
}

/**
 * The log before its first page has landed: the four facts, the previous
 * values card closed, then the log's card — its head and export, its intro,
 * the tab row, two days of entries and the foot.
 *
 * @param {Object}  props
 * @param {boolean} props.network The network's log, which has no seal, no export and no previous values.
 */
export function SiteActivityBone( { network = false } ) {
	const { entries, who, seal, kept } = glanceLabels();

	return (
		<Skeleton label={ __( 'Loading the activity log…', 'bettershield' ) }>
			<StatsBone labels={ network ? [ entries, who, kept ] : [ entries, who, seal, kept ] } />

			{ /* The site's log opens the previous-values card under its facts
			     for whoever manages the site, which is nearly everyone who can
			     read it. Closed, it is one header, and it is kept a place. */ }
			{ network ? null : <ObservedChangesBone /> }

			<div className="bs-ds-card">
				<div className="bs-ds-card__head">
					<span className="bs-ds-bone bs-ds-bone--tile" />
					<Bone kind="title" w="4.5em" />
					<span className="bs-ds-spacer" />
					{ network ? null : <Bone kind="control" w="108px" /> }
				</div>
				<div className="bs-ds-log__boneintro">
					<Bone w="30em" />
				</div>
				<div className="bs-ds-log__bonetabs">
					<Bone kind="title" w="4em" />
					<Bone kind="title" w="5em" />
					<Bone kind="title" w="6em" />
					<span className="bs-ds-spacer" />
					<Bone kind="control" w="200px" />
					<Bone kind="control" w="88px" />
				</div>
				<div className="bs-ds-log__bonegroup">
					<Bone w="3.5em" />
				</div>
				<PageBone rows={ 6 } />
				<div className="bs-ds-log__bonegroup">
					<Bone w="5em" />
				</div>
				<PageBone rows={ 3 } />
				<div className="bs-ds-log__bonefoot">
					<Bone kind="control" w="140px" />
					<Bone w="30em" />
				</div>
			</div>
		</Skeleton>
	);
}

/**
 * Said above the list rather than below it: a reader shown a capped list and
 * told about it afterwards has already drawn a conclusion from it.
 *
 * @param {Object}  props
 * @param {?Object} props.sampling What the page said about counting instead of listing.
 */
function SamplingNotice( { sampling } ) {
	if ( ! sampling || ! sampling.engaged || ! sampling.engaged.length ) {
		return null;
	}

	return (
		<Alert layout="default" tone="warning" live>
			<p>
				{ __(
					'Some events are happening too often to list one by one, so this hour they are only counted. Important events are always listed.',
					'bettershield'
				) }
			</p>
			<ul className="bs-ds-log__sampled">
				{ sampling.engaged.map( ( item ) => (
					<li key={ item.type }>
						{ sprintf(
							/* translators: 1: what happened, 2: how many are listed, 3: how many happened in total this hour. */
							__( '%1$s — %2$d listed, of %3$d so far this hour', 'bettershield' ),
							item.label,
							item.recorded,
							item.recorded + item.dropped
						) }
					</li>
				) ) }
			</ul>
		</Alert>
	);
}

/**
 * @param {Object}  props
 * @param {boolean} props.network Read every site of the network rather than this one.
 */

/**
 * What an arrival asks this tab to open, from the address's fragment.
 *
 * @param {string} hash The address's fragment, with its #.
 * @return {?string} 'filters', 'search' or null.
 */
function arrivedFor( hash ) {
	return { '#filters': 'filters', '#search': 'search' }[ hash ] || null;
}

export default function SiteActivity( { network = false } ) {
	const routes = network ? ROUTES.network : ROUTES.site;
	/*
	 * On the network log, whether some sites' activity has not been copied
	 * in yet, so the note saying they are not listed shows only then (#2617).
	 */
	const [ sitesPending, setSitesPending ] = useState( false );

	useEffect( () => {
		if ( ! network ) {
			return undefined;
		}

		let live = true;

		apiFetch( { path: '/bettershield/v1/network/migration' } ).then(
			( data ) => live && setSitesPending( Boolean( data ) && ! data.complete ),
			() => {}
		);

		return () => {
			live = false;
		};
	}, [ network ] );
	/*
	 * Pages already fetched, keyed by view: { [view]: { events, cursor } }.
	 *
	 * The log cannot be filtered in the browser — it is paged, so only one page
	 * is ever held, and filtering that would hide rows the next page would bring
	 * straight back. What can be avoided is asking twice. A view opened once
	 * stays open instantly, and moving back and forth between filters stops
	 * touching the network at all.
	 */
	const [ cache, setCache ] = useState( {} );

	/*
	 * Where the log opens: as a link from another screen asked — one account,
	 * one network, a range of days — or unfiltered. Read once, as the screen
	 * mounts; the network log spans sites and opens unfiltered.
	 *
	 * What is selected, and what the rows on screen belong to. They differ only
	 * while an uncached view is being fetched.
	 */
	const [ opening ] = useState( () => ( network ? NO_FILTERS : { ...NO_FILTERS, ...linkedLogFilters(), search: linkedSearch() } ) );
	const [ filters, setFilters ] = useState( opening );
	const [ shown, setShown ] = useState( () => viewKey( opening ) );

	/*
	 * What is typed, and what has been asked for. They differ while the typing
	 * settles: a query per keystroke would be a query per keystroke against a
	 * table with no index for LIKE, on somebody else's server.
	 */
	const [ typed, setTyped ] = useState( opening.search );

	// A search a link opened with is the box's from then on, and is taken off
	// the address so a reload does not bring back what was cleared.
	useEffect( () => {
		if ( opening.search ) {
			writeNarrowing( { search: '' } );
		}
	}, [ opening.search ] );

	/*
	 * Arrived from the Overview's Filters or Search, as #filters or #search:
	 * both opened this tab with nothing open (#1917). Done once the controls
	 * are drawn, and after the move has focused the heading, and the mark is
	 * taken off the address so Back or a reload does not do it again.
	 */
	const searchField = useRef( null );
	const filtersToggle = useRef( null );
	const [ arrival, setArrival ] = useState( () => arrivedFor( window.location.hash ) );

	useEffect( () => {
		const arrive = () => setArrival( arrivedFor( window.location.hash ) );

		window.addEventListener( NAVIGATED, arrive );

		return () => window.removeEventListener( NAVIGATED, arrive );
	}, [] );

	useEffect( () => {
		const node = 'search' === arrival ? searchField.current : filtersToggle.current;

		if ( ! arrival || ! node ) {
			return;
		}

		setArrival( null );
		window.history.replaceState( window.history.state, '', window.location.href.replace( /#.*$/, '' ) );

		// Not cleared with the render that follows: it is what that render
		// is for.
		window.setTimeout( () => {
			if ( ! node.isConnected ) {
				return;
			}

			if ( 'search' === arrival ) {
				node.focus();
			} else if ( 'true' !== node.getAttribute( 'aria-expanded' ) ) {
				node.click();
			}
		}, 0 );
	} );

	const [ retention, setRetention ] = useState( null );
	const [ actors, setActors ] = useState( [] );
	const [ actorsTotal, setActorsTotal ] = useState( null );
	const [ sites, setSites ] = useState( [] );
	// How many sites the network has, when the site filter lists fewer.
	const [ sitesTotal, setSitesTotal ] = useState( 0 );
	const [ sampling, setSampling ] = useState( null );
	const [ canManage, setCanManage ] = useState( false );
	// What the last daily check said about the seal chain, for the day rows.
	// Absent on the network log, which spans sites.
	const [ seals, setSeals ] = useState( null );
	const [ status, setStatus ] = useState( 'loading' );
	const [ appending, setAppending ] = useState( false );
	const [ appendFailed, setAppendFailed ] = useState( false );
	const [ exporting, setExporting ] = useState( false );
	const [ exportNote, setExportNote ] = useState( null );
	// The entry whose recorded change is open under it: one at a time, so the
	// card holds one review, and one action, at once.
	const [ reviewing, setReviewing ] = useState( null );

	/*
	 * The dates as typed, which the filters take only once both ends are
	 * whole days in order. Held apart because a date input reports every
	 * keystroke of the year, and the filters were asking the log for each.
	 */
	const [ days, setDays ] = useState( () => ( { from: opening.from, to: opening.to } ) );
	const [ daysBackwards, setDaysBackwards ] = useState( false );
	// Why the site refused the last narrowing, said beside the filters.
	const [ refusal, setRefusal ] = useState( '' );
	// The narrowing the rows on screen were read with, to go back to when the
	// site refuses a new one.
	const loaded = useRef( null );
	// The results line, where the keyboard goes when the control it was on
	// cleared a narrowing and went with it.
	const results = useRef( null );
	const [ refocus, setRefocus ] = useState( 0 );
	// Show older entries is held while its page loads, and goes once the
	// last page is in: focus comes back to it, or to the results line
	// (#1926).
	const more = useRef( null );

	useFocusAfter( appending, more, results );
	// Whether the next narrowing came from a row or an area tab, and so is a
	// step Back undoes (#2183).
	const pushNext = useRef( false );
	const opened = useRef( false );

	/*
	 * Requests already in flight, by identity rather than as a single flag.
	 *
	 * A flag cannot tell "this exact request is already running" from "some
	 * request is running", and both mistakes hurt: refusing a second view
	 * strands the screen dimmed against a control nothing is fetching for, while
	 * allowing a duplicate of the same one wastes a round trip and can append a
	 * page twice.
	 */
	const pending = useRef( new Set() );
	const mounted = useRef( true );

	// The view currently selected, readable from inside a response handler that
	// closed over an older one.
	const wanted = useRef( viewKey( opening ) );

	useEffect( () => {
		mounted.current = true;

		return () => {
			mounted.current = false;
		};
	}, [] );

	useEffect( () => {
		const timer = window.setTimeout( () => setFilters( ( current ) => ( { ...current, search: typed.trim() } ) ), 300 );

		return () => window.clearTimeout( timer );
	}, [ typed ] );

	const load = useCallback( ( within, cursor = null ) => {
		const view = viewKey( within );
		const key = cursor ? view + '#' + cursor : view;

		if ( pending.current.has( key ) ) {
			return;
		}

		pending.current.add( key );
		setAppending( Boolean( cursor ) );
		setAppendFailed( false );

		apiFetch( { path: routes.list + logQuery( within, cursor ) } )
			.then( ( data ) => {
				if ( ! mounted.current ) {
					return;
				}

				setCache( ( current ) => {
					const existing = cursor && current[ view ] ? current[ view ].events : [];

					return {
						...current,
						[ view ]: {
							events: [ ...existing, ...data.events ],
							cursor: data.next_cursor,
							// Kept with the view, so going back to it draws its
							// own counts rather than the last view's.
							counts: cursor && current[ view ] ? current[ view ].counts : data.counts || {},
						},
					};
				} );

				/*
				 * Several requests can be outstanding at once and can answer out
				 * of order. Each is cached either way — it is correct for the view
				 * that asked — but only the view still on the controls may take
				 * the screen, or a slow earlier response would yank the reader
				 * back to a query they have already moved on from.
				 */
				if ( view === wanted.current ) {
					setShown( view );
					loaded.current = within;
				}

				setRetention( data.retention_days );
				setActors( data.actors || [] );
				setActorsTotal( Number.isInteger( data.actors_total ) ? data.actors_total : null );
				// Only the first page of a view carries the site list: it is the
				// same on every page and costs an option read per site to build,
				// so a later page leaves the filter holding what it already has.
				if ( data.sites ) {
					setSites( data.sites );
					setSitesTotal( Number( data.sites_total ) || 0 );
				}
				setSampling( data.sampling || null );
				setCanManage( !! data.can_manage );
				setSeals( data.seals || null );
				setStatus( 'ready' );
			} )
			.catch( ( error ) => {
				if ( ! mounted.current ) {
					return;
				}
				if ( cursor ) {
					// An older page that did not arrive says so beside the button
					// rather than throwing away the pages already on screen.
					setAppendFailed( true );
				} else if ( null !== narrowingRefused( error ) ) {
					/*
					 * The site answered and refused the narrowing itself. That
					 * is not the log failing to load: the rows on screen stay,
					 * the reason is said beside the filters, and the filters go
					 * back to the ones those rows were read with — so nothing,
					 * Try again included, asks for the same refusal again. A
					 * refusal before any rows came, from a link, drops all it
					 * named — dates, area, account and network — since keeping
					 * whichever one was refused asks for the same view again.
					 * Should the fallback still be that view, the log says it
					 * failed rather than ask again.
					 */
					const back = loaded.current || { ...within, from: '', to: '', area: 'all', actor: '', network: '' };

					setRefusal( narrowingRefused( error ) );
					if ( viewKey( back ) === view ) {
						setStatus( 'error' );
					} else {
						setFilters( back );
					}
				} else {
					setStatus( 'error' );
				}
			} )
			.finally( () => {
				pending.current.delete( key );

				if ( mounted.current ) {
					setAppending( false );
				}
			} );
	}, [ routes.list ] );

	const view = viewKey( filters );

	useEffect( () => {
		wanted.current = view;

		// Already fetched: show it without a request, and without the screen
		// changing shape on the way.
		if ( cache[ view ] ) {
			setShown( view );
			return;
		}

		load( filters, null );
	}, [ load, filters, view, cache ] );

	const set = ( changes ) => {
		setRefusal( '' );
		setFilters( ( current ) => ( { ...current, ...changes } ) );
	};

	/*
	 * The address follows what a link can narrow the log to — who, which
	 * network, and the days — so a reload, a copied link or Back shows what is
	 * on screen. Not on the first paint, which is the address itself, and not
	 * on the network's log, which opens unfiltered.
	 */
	useEffect( () => {
		if ( network ) {
			return;
		}

		if ( ! opened.current ) {
			opened.current = true;
			return;
		}

		writeNarrowing( { area: 'all' === filters.area ? '' : filters.area, actor: filters.actor, network: filters.network, since: filters.from, until: filters.to }, pushNext.current );
		pushNext.current = false;
	}, [ network, filters.area, filters.actor, filters.network, filters.from, filters.to ] );

	// Back and Forward move the address without telling the screen: read the
	// narrowing it now carries.
	useEffect( () => {
		if ( network ) {
			return undefined;
		}

		const onPopState = () => {
			const linked = linkedLogFilters();

			setRefusal( '' );
			setFilters( ( current ) => ( { ...current, ...linked } ) );
		};

		// The app's own navigation, a tab or the menu, pushes the address
		// without a popstate and says so instead.
		window.addEventListener( 'popstate', onPopState );
		window.addEventListener( NAVIGATED, onPopState );

		return () => {
			window.removeEventListener( 'popstate', onPopState );
			window.removeEventListener( NAVIGATED, onPopState );
		};
	}, [ network ] );

	useEffect( () => {
		if ( refocus && results.current ) {
			results.current.focus();
		}
	}, [ refocus ] );

	// The inputs follow the dates whenever those move without them: Clear
	// filters, Clear all, or a refusal put back.
	useEffect( () => {
		setDays( { from: filters.from, to: filters.to } );
		setDaysBackwards( false );
	}, [ filters.from, filters.to ] );

	/*
	 * One end of the range, as typed. The filters take the pair only once
	 * both ends are whole days or empty, and in order: a half-typed year asks
	 * for nothing, and a start after the end is said here rather than sent to
	 * a site that would refuse it.
	 */
	const pickDay = ( end, value ) => {
		const next = { ...days, [ end ]: value };
		const ready = ( day ) => '' === day || wholeDay( day );

		setDays( next );

		if ( ! ready( next.from ) || ! ready( next.to ) ) {
			setDaysBackwards( false );
			return;
		}

		if ( next.from && next.to && next.from > next.to ) {
			setDaysBackwards( true );
			return;
		}

		setDaysBackwards( false );
		set( { from: next.from, to: next.to } );
	};

	/*
	 * Hand the browser a file it did not fetch as one.
	 *
	 * The log arrives as data because the REST server encodes whatever a route
	 * returns; the file is assembled here, which is also where the reader is.
	 */
	const runExport = () => {
		setExporting( true );
		setExportNote( null );

		apiFetch( { path: routes.csv + logQuery( filters, null ) } )
			.then( ( data ) => {
				if ( ! mounted.current ) {
					return;
				}

				// With a byte-order mark, so a spreadsheet reads it as UTF-8 and
				// non-ASCII names don't come out garbled (#2611).
				download( data.filename, `\uFEFF${ String( data.csv ).replace( /^\uFEFF/, '' ) }`, 'text/csv;charset=utf-8' );

				setExportNote(
					data.complete
						? sprintf(
								/* translators: %d: number of entries in the exported file. */
								_n( '%d entry exported.', '%d entries exported.', data.rows, 'bettershield' ),
								data.rows
						  )
						: sprintf(
								/* translators: %d: number of entries in the exported file. */
								__(
									'%d entries exported (the limit for one file). Choose a shorter date range to export the rest.',
									'bettershield'
								),
								data.rows
						  )
				);
			} )
			.catch( () => {
				if ( mounted.current ) {
					setExportNote( __( 'The export did not complete. Nothing on your site changed.', 'bettershield' ) );
				}
			} )
			.finally( () => {
				if ( mounted.current ) {
					setExporting( false );
				}
			} );
	};

	const entry = cache[ shown ];
	const events = entry ? entry.events : [];
	const cursor = entry ? entry.cursor : null;
	const counts = ( entry && entry.counts ) || {};

	/*
	 * True only while an uncached view is on its way. The rows on screen belong
	 * to the previous one for those few hundred milliseconds, so they are dimmed
	 * and marked busy rather than swapped for stand-ins: replacing the whole
	 * list reads as a page load, which is the thing this avoids.
	 */
	const settling = shown !== view;

	// The unfiltered option leads here, unlike the report: a log is opened to
	// see what happened, not to see one corner of it.
	// After All, the busiest categories first, so the ones with entries take
	// the tabs that fit and empty ones fall into More (#2071). The model's
	// order breaks a tie.
	const areaOptions = [
		{ slug: 'all', label: __( 'All', 'bettershield' ) },
		...activityAreas
			.map( ( area, index ) => ( { area, index, count: Number( counts[ area.slug ] || 0 ) } ) )
			.sort( ( a, b ) => b.count - a.count || a.index - b.index )
			.map( ( entry ) => entry.area ),
	];

	const actorOptions = useMemo( () => {
		const options = [
			{ value: '', label: __( 'Anyone', 'bettershield' ) },
			...actors.map( ( actor ) => ( {
				value: actor.token,
				label: sprintf(
					/* translators: 1: a person or the site itself, 2: how many entries they account for. */
					__( '%1$s (%2$d)', 'bettershield' ),
					actor.label,
					actor.count
				),
			} ) ),
		];

		// The list names the busiest accounts only. One arrived at from a row
		// or a link may be outside it, and the control still has to say who.
		if ( filters.actor && ! actors.some( ( actor ) => actor.token === filters.actor ) ) {
			const account = /^user:(\d+)$/.exec( filters.actor );

			options.push( {
				value: filters.actor,
				/* translators: %d: an account's number. */
				label: account ? sprintf( __( 'Account #%d', 'bettershield' ), Number( account[ 1 ] ) ) : filters.actor,
			} );
		}

		return options;
	}, [ actors, filters.actor ] );

	const siteOptions = useMemo(
		() => [ { value: '', label: __( 'Every site', 'bettershield' ) }, ...sites.map( ( site ) => ( { value: String( site.id ), label: site.label } ) ) ],
		[ sites ]
	);

	const narrowed = filters.area !== 'all' || filters.search || filters.actor || filters.from || filters.to || filters.site || filters.network;
	// How many of the panel's own filters are set, for the count on its button.
	const narrowedPanel = [ filters.actor, filters.from, filters.to, filters.site ].filter( Boolean ).length;

	if ( status === 'loading' ) {
		return <SiteActivityBone network={ network } />;
	}

	if ( status === 'error' ) {
		return <ErrorState onRetry={ () => load( filters, null ) } />;
	}

	const tiles = logTiles( { counts, area: filters.area, actors, actorsTotal, seals: network ? undefined : seals, retention, narrowed: Boolean( narrowed ) } ).map( ( tile ) => ( {
		...tile,
		icon: STAT_ICONS[ tile.key ],
	} ) );
	const matching = Number( counts[ filters.area ] || 0 );
	const notes = exportNote || refusal || filters.network || ( sampling && sampling.engaged && sampling.engaged.length );

	return (
		<>
			<Stats label={ __( 'Activity at a glance', 'bettershield' ) } tiles={ tiles } />

			{ canManage && ! network ? <ObservedChanges /> : null }

			<Card className="bs-ds-log" aria-labelledby="bs-ds-log-title">
				{ /* The export is the one control about the whole log rather than
				     about narrowing it, so it is the card's own. */ }
				<CardHead icon="activity" title={ __( 'Activity', 'bettershield' ) } id="bs-ds-log-title">
					{ routes.csv ? (
						<Button type="secondary" size="sm" icon="download" iconTone="2" isBusy={ exporting } disabled={ exporting } onClick={ runExport }>
							{ exporting ? __( 'Preparing…', 'bettershield' ) : __( 'Export CSV', 'bettershield' ) }
						</Button>
					) : null }
				</CardHead>
				<p className="bs-ds-log__intro">
					{ network && sitesPending
						? __(
								'Who did what, and when, across the network. Sites that have not been updated yet are not listed.',
								'bettershield'
						  )
						: network
						? __( 'Who did what, and when, across the network.', 'bettershield' )
						: __( 'Who did what, and when.', 'bettershield' ) }
				</p>

				{ /* Every instant alert links here, and the precision figure
				     counts it: this is where it can be said not worth sending.
				     Asked only on arriving from one, and of a reader who
				     manages the site, as the route requires. */ }
				{ canManage && ! network && cameFromAlert() ? (
					<div className="bs-ds-log__alert">
						<AlertFeedback recordedText={ __( 'Saved: this email was not worth sending. The log is unchanged.', 'bettershield' ) } />
					</div>
				) : null }

				{ /*
				   One row: the categories as tabs with their counts, and at its
				   end the search and the rest of the filters behind one button.
				   The narrower filters — who, and when — are reached for during
				   an investigation rather than on every visit, so they wait in a
				   panel instead of standing as a second row of chrome.
				*/ }
				<FitTabs
					id={ TABS_ID }
					label={ __( 'Category', 'bettershield' ) }
					moreLabel={ __( 'Category', 'bettershield' ) }
					tabs={ areaOptions.map( ( option ) => ( {
						key: option.slug,
						label: option.label,
						count: Number( counts[ option.slug ] || 0 ).toLocaleString(),
					} ) ) }
					optionLabel={ ( tab ) =>
						sprintf(
							/* translators: 1: an activity category, 2: how many entries it holds. */
							__( '%1$s (%2$s)', 'bettershield' ),
							'all' === tab.key ? __( 'All activity', 'bettershield' ) : tab.label,
							tab.count
						)
					}
					selected={ filters.area }
					onSelect={ ( area ) => {
						// A tab chosen is a step Back undoes, as on every
						// other tab strip; the filters still replace (#2183).
						// The tab already shown is no step at all.
						if ( area !== filters.area ) {
							pushNext.current = true;
						}

						set( { area } );
					} }
					actions={
						<>
							<label className="bs-ds-log__search">
								<Icon name="search" size={ 16 } tone="3" />
								<input
									ref={ searchField }
									type="search"
									value={ typed }
									placeholder={ __( 'Search by name or subject', 'bettershield' ) }
									aria-label={ __( 'Search activity', 'bettershield' ) }
									onChange={ ( event ) => setTyped( event.target.value ) }
								/>
							</label>

							<Dropdown
								className="bs-ds-log__filtersmenu"
								/*
								   Under the button, always: no flip to above it when
								   the room below is short, and no resize that would
								   squeeze the panel into a scrolling sliver. No shift
								   either — the library's shifts on both axes, and
								   kept the panel on screen by sliding it up over the
								   button it belongs to. Aligned to the button's right
								   edge, it already fits a narrow screen.
								*/
								popoverProps={ { placement: 'bottom-end', offset: 8, flip: false, resize: false, className: 'bs-ds-logpop' } }
								renderToggle={ ( { isOpen, onToggle } ) => (
									<Button
										ref={ filtersToggle }
										type="toolbar"
										size="sm"
										icon="list-filter"
										iconTone="2"
										trailing={ isOpen ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										className="bs-ds-log__filterstoggle"
										aria-expanded={ isOpen }
										onClick={ onToggle }
									>
										{ __( 'Filters', 'bettershield' ) }
										{ narrowedPanel ? <span className="bs-ds-tab__count bs-ds-log__filtercount">{ narrowedPanel }</span> : null }
									</Button>
								) }
								renderContent={ ( { onClose } ) => (
									<div className="bs-ds-logfilters" ref={ revealWhenPlaced }>
										<div className="bs-ds-logfilters__head">
											<h3 className="bs-ds-logfilters__title">{ __( 'Filter activity', 'bettershield' ) }</h3>
											<Button type="ghost" size="sm" iconOnly label={ __( 'Close', 'bettershield' ) } onClick={ onClose }>
												<Icon name="x" size={ 14 } tone="2" />
											</Button>
										</div>

										{ network ? (
											<Field kind="select" label={ __( 'Site', 'bettershield' ) } value={ filters.site } options={ siteOptions } onChange={ ( site ) => set( { site } ) } />
										) : null }
										{ network && sitesTotal > sites.length ? (
											<p className="bs-ds-logfilters__note">
												{ sprintf(
													/* translators: 1: sites the filter lists, 2: sites on the network. */
													__( 'This filter shows the first %1$d of %2$d sites. The list below covers every site.', 'bettershield' ),
													sites.length,
													sitesTotal
												) }
											</p>
										) : null }

										<Field kind="select" label={ __( 'Who', 'bettershield' ) } value={ filters.actor } options={ actorOptions } onChange={ ( actor ) => set( { actor } ) } />

										<div className="bs-ds-logfilters__days">
											<Field
												type="date"
												label={ __( 'From', 'bettershield' ) }
												max={ filters.to || today() }
												value={ days.from }
												onChange={ ( value ) => pickDay( 'from', value ) }
											/>
											<Field
												type="date"
												label={ __( 'To', 'bettershield' ) }
												min={ filters.from }
												max={ today() }
												value={ days.to }
												onChange={ ( value ) => pickDay( 'to', value ) }
											/>
										</div>

										{ daysBackwards ? (
											<p className="bs-ds-logfilters__note" role="alert">
												{ __( 'The start date is after the end date, so these dates are not applied yet.', 'bettershield' ) }
											</p>
										) : null }

										<span>
											<Button
												type="link"
												size="sm"
												className="bs-ds-logfilters__clear"
												disabled={ ! narrowedPanel }
												onClick={ () => set( { actor: '', from: '', to: '', site: '' } ) }
											>
												{ __( 'Clear Filters', 'bettershield' ) }
											</Button>
										</span>
									</div>
								) }
							/>
						</>
					}
				/>

				<div { ...panelProps( TABS_ID, filters.area ) } className="bs-ds-log__panel">
					{ notes ? (
						<div className="bs-ds-log__notes">
							{ exportNote ? <p className="bs-ds-log__note">{ exportNote }</p> : null }
							{ refusal ? (
								<div role="alert">
									<Alert layout="banner" tone="warning" desc={ refusal } />
								</div>
							) : null }
							{ /* One network is not a control of its own: it is reached
							     from a row or a link, so it is said here with its way
							     out. */ }
							{ filters.network ? (
								<p className="bs-ds-log__narrowed">
									{ sprintf(
										/* translators: %s: a network, e.g. 203.0.113.x. */
										__( 'Only activity from the network %s.', 'bettershield' ),
										networkWords( filters.network )
									) }{ ' ' }
									<Button
										type="link"
										size="sm"
										onClick={ () => {
											set( { network: '' } );
											// This button goes with the line it sits in.
											setRefocus( ( n ) => n + 1 );
										} }
									>
										{ __( 'Show Every Network', 'bettershield' ) }
									</Button>
								</p>
							) : null }
							<SamplingNotice sampling={ sampling } />
						</div>
					) : null }

					{ /* What the list below is, and how much of it there is. */ }
					<div className="bs-ds-log__results">
						<span className="bs-ds-log__label">{ narrowed ? __( 'Matching activity', 'bettershield' ) : __( 'Recent activity', 'bettershield' ) }</span>
						<span className="bs-ds-spacer" />
						<span className="bs-ds-log__count" role="status" tabIndex={ -1 } ref={ results }>
							{ sprintf(
								/* translators: %s: number of entries, already formatted. */
								_n( '%s result', '%s results', matching, 'bettershield' ),
								matching.toLocaleString()
							) }
						</span>
						{ /* Everything back at once — the category, the search and
						     the panel's filters — beside the count it resets. */ }
						{ narrowed ? (
							<Button
								type="link"
								size="sm"
								className="bs-ds-log__clearall"
								onClick={ () => {
									setTyped( '' );
									setRefusal( '' );
									setFilters( NO_FILTERS );
								} }
							>
								{ __( 'Clear All', 'bettershield' ) }
							</Button>
						) : null }
					</div>

					<div className={ `bs-ds-log__list${ settling ? ' is-settling' : '' }` } aria-busy={ settling || appending }>
						<Table label={ __( 'Activity log', 'bettershield' ) } className="bs-ds-tbl--grouped" columns={ COLUMNS() }>
							{ ! events.length && ! settling ? (
								<WholeRow kind="empty">
									<span className="bs-ds-log__emptytitle">
										{ narrowed ? __( 'Nothing matches these filters.', 'bettershield' ) : __( 'Nothing has been recorded yet.', 'bettershield' ) }
									</span>{ ' ' }
									{ narrowed
										? __( 'Widen one filter and try again.', 'bettershield' )
										: __(
												'Sign-ins, user and role changes, plugin and theme changes, and BetterShield’s own actions appear here.',
												'bettershield'
										  ) }
								</WholeRow>
							) : (
								byDay( events ).map( ( group ) => (
									<Day key={ group.key } group={ group } seals={ seals }>
										{ group.events.map( ( event ) => (
											<Event
												key={ event.id }
												event={ event }
												canManage={ canManage }
												narrowedTo={ filters }
												network={ network }
												reviewing={ reviewing === event.id }
												onReview={ setReviewing }
												onNarrow={ ( changes ) => {
													pushNext.current = true;
													set( changes );
												} }
											/>
										) ) }
									</Day>
								) )
							) }
							{ /* An older page on its way, drawn where it will land. */ }
							{ appending && ! settling ? <PageBone rows={ 3 } /> : null }
							{ ( cursor && ! settling ) || retention ? (
								<WholeRow kind="foot">
									{ cursor && ! settling ? (
										<Button ref={ more } type="secondary" size="sm" isBusy={ appending } disabled={ appending } onClick={ () => load( filters, cursor ) }>
											{ appending
												? __( 'Loading…', 'bettershield' )
												: appendFailed
												? __( 'That Did Not Load — Try Again', 'bettershield' )
												: __( 'Show Older Entries', 'bettershield' ) }
										</Button>
									) : null }
									{ retention ? (
										<span className="bs-ds-log__footnote">
											{ sprintf(
												/* translators: %s: number of days of history kept, already formatted with its unit. */
												__( 'Entries are deleted after %s.', 'bettershield' ),
												sprintf(
													/* translators: %d: number of days. */
													_n( '%d day', '%d days', retention, 'bettershield' ),
													retention
												)
											) }{ ' ' }
											{ /* Said plainly, because a seal that is taken for more
											     than it is would be worse than no seal at all. It is
											     a digest this site computes over its own rows; anybody
											     who can rewrite the rows can rewrite it. */ }
											{ seals && seals.checked_at
												? __( 'Each finished day is checked daily. This shows if past entries were changed. It does not stop changes.', 'bettershield' )
												: __(
														'Each finished day is checked once a day. Results appear after the first check.',
														'bettershield'
												  ) }
										</span>
									) : null }
								</WholeRow>
							) : null }
						</Table>
					</div>
				</div>
			</Card>
		</>
	);
}
