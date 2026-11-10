/**
 * Activity › Agent activity: what agents DID here, as distinct from what they
 * can do.
 *
 * Owns its own fetching rather than going through the shared resource store,
 * for the reason the activity log does: the store models a screen's data as
 * one value a mutation writes back whole, and a paged record is the opposite
 * shape — appended to, never replaced.
 *
 * The screen's question is "was anything turned away", and the outcome tabs
 * answer it before anything is clicked. "Refused · 0" is the good news and is
 * worth stating; it is not an empty screen.
 *
 * Attribution is stated no more strongly than the platform supports. Nothing
 * maps an ability to the plugin that registered it, so the namespace filter
 * says it is a naming convention rather than calling it a plugin.
 *
 * The four facts, the notice when recording is off, then one card: the
 * outcomes as tabs with the namespace and the door at the row's end, a row per
 * call, and the retention note at its foot.
 */

import './AgentActivity.css';

import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime } from '../../store';
import { linkedAccount, linkedConnection, NAVIGATED, tabUrl, writeNarrowing } from '../../nav';
import { refusalPhrase } from '../../agents/phrases';
import brand from '../setup/brand';
import Alert from '../ui/Alert';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Field from '../ui/Field';
import { useFocusAfter } from '../ui/focus';
import Icon from '../ui/Icon';
import Skeleton, { Bone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { EmptyState, ErrorState } from '../ui/States';
import Table, { Cell, Row, WholeRow } from '../ui/Table';
import Topics from '../ui/Topics';
import { panelProps } from '../ui/tabKeys';
import FitTabs from './FitTabs';

/**
 * How each outcome reads, and how loudly.
 *
 * Only the refusal carries any weight. Everything else is traffic: an ability
 * that ran, or one that was handed input it could not use. Coloring those
 * would spend the reader's attention on the rows that never needed it, and
 * leave nothing left for the one that does.
 */
const OUTCOMES = {
	completed: { kind: 'good', label: () => __( 'Completed', 'bettershield' ) },
	permission_denied: { kind: 'medium', label: () => __( 'Refused', 'bettershield' ) },
	input_invalid: { kind: 'neutral', label: () => __( 'Request was invalid', 'bettershield' ) },
	input_not_normalizable: { kind: 'neutral', label: () => __( 'Request could not be read', 'bettershield' ) },
	output_invalid: { kind: 'neutral', label: () => __( 'Answer was invalid', 'bettershield' ) },
	short_circuited: { kind: 'neutral', label: () => __( 'Answered by other code before it ran', 'bettershield' ) },
	failed: { kind: 'neutral', label: () => __( 'Failed', 'bettershield' ) },
	// Never guessed into something friendlier. A lifecycle that did not finish
	// is a fact about the record, and a wrong label is worse than an honest gap.
	unknown: { kind: 'muted', label: () => __( 'Did not finish', 'bettershield' ) },
};

function outcomeLabel( outcome ) {
	const conf = OUTCOMES[ outcome ];

	return conf ? conf.label() : outcome;
}

/** The doors worth naming. The dashboard's own calls are the default. */
const PATHS = {
	// The built-in MCP server: how every connected assistant comes in.
	mcp: () => __( 'through an AI assistant connection', 'bettershield' ),
	rest: () => __( 'through the REST API', 'bettershield' ),
	'wp-cli': () => __( 'via WP-CLI', 'bettershield' ),
	php: () => __( 'by code on this site', 'bettershield' ),
	unknown: () => __( 'from an unknown source', 'bettershield' ),
};

/** The same, as one line above a list whose every row came one way. */
const ALL_PATHS = {
	mcp: () => __( 'All of these ran through an AI assistant connection.', 'bettershield' ),
	rest: () => __( 'All of these ran through the REST API.', 'bettershield' ),
	'wp-cli': () => __( 'All of these ran via WP-CLI.', 'bettershield' ),
	php: () => __( 'All of these ran by code on this site.', 'bettershield' ),
	unknown: () => __( 'All of these came from an unknown source.', 'bettershield' ),
};

const TABS_ID = 'bs-ds-agentlog-tabs';

/** Each fact's 14 icon in the strip. */
const STAT_ICONS = { recording: 'scroll-text', all: 'bot', refused: 'ban', completed: 'circle-check' };

/** The record's columns: the call, how it ended, and when. */
const COLUMNS = () => [
	{ key: 'call', label: __( 'Action', 'bettershield' ) },
	{ key: 'outcome', label: __( 'Outcome', 'bettershield' ), width: '200px' },
	{ key: 'when', label: __( 'When', 'bettershield' ), width: '136px', align: 'end' },
];

/**
 * One call: the ability, who it ran as and through which door, how it ended
 * and why, and when.
 *
 * @param {Object}    props
 * @param {Object}    props.invocation The call.
 * @param {?Function} props.onAccount  Narrows the record to the account this ran as.
 */
function Call( { invocation, onAccount, sharedPath = false } ) {
	const conf = OUTCOMES[ invocation.outcome ] || OUTCOMES.unknown;
	// Said once above the list when every row shares it (#2606).
	const path = sharedPath ? null : PATHS[ invocation.entry_path ];
	const pivot = onAccount && invocation.user_id > 0;

	return (
		<Row className="bs-ds-call" hover>
			<Cell className="bs-ds-call__cell">
				<span className="bs-ds-call__what">
					<Icon name="bot" size={ 16 } tone="2" />
					<span className="bs-ds-call__text">
						{ /* The ability's own label, its code name behind it (#2364). */ }
						<span className="bs-ds-call__ability" title={ invocation.ability_label ? invocation.ability : undefined }>
							{ invocation.ability_label || invocation.ability }
						</span>
						<span className="bs-ds-call__detail">
							<span>{ invocation.user_label }</span>
							{ path ? <span className="bs-ds-call__via">{ path() }</span> : null }
							{ /* Which connection made it, so two assistants on one
							     account read apart (#2213). */ }
							{ invocation.connection_label ? (
								<span className="bs-ds-call__connection" title={ invocation.connection }>
									{ invocation.connection_label }
								</span>
							) : null }
							{ /* Only when it took long enough that the number means
							     something. Sub-millisecond durations are noise. */ }
							{ invocation.duration_ms > 0 ? (
								<span className="bs-ds-call__took">
									{ sprintf(
										/* translators: %d: a duration in milliseconds. */
										__( 'took %d ms', 'bettershield' ),
										invocation.duration_ms
									) }
								</span>
							) : null }
						</span>
						{ /* Every call made as this account, whichever connection
						     it came in on. */ }
						{ pivot ? (
							<span className="bs-ds-call__actions">
								<Button type="linksub" size="sm" className="bs-ds-call__pivot" onClick={ () => onAccount( invocation ) }>
									{ __( 'Everything This Account Did', 'bettershield' ) }
								</Button>
							</span>
						) : null }
					</span>
				</span>
			</Cell>

			<Cell className="bs-ds-call__outcome">
				<Badge tone={ kindTone( conf.kind ) }>{ outcomeLabel( invocation.outcome ) }</Badge>
				{ /* Why, in words, where the code is one of this plugin's;
				     the code itself stays on the line's tooltip for support.
				     Anybody else's code is shown as it was recorded. */ }
				{ invocation.error_code && refusalPhrase( invocation.error_code ) ? (
					<span className="bs-ds-call__reason" title={ invocation.error_code }>
						{ refusalPhrase( invocation.error_code ) }
					</span>
				) : null }
				{ invocation.error_code && ! refusalPhrase( invocation.error_code ) ? <span className="bs-ds-call__code">{ invocation.error_code }</span> : null }
				{ /* Set apart from Failed, which did report (#2364). */ }
				{ 'unknown' === invocation.outcome && ! invocation.error_code ? (
					<span className="bs-ds-call__reason">{ __( 'The record ended before the action reported a result.', 'bettershield' ) }</span>
				) : null }
			</Cell>

			<Cell align="end" className="bs-ds-call__when">
				{ formatTime( invocation.invoked_at ) }
			</Cell>
		</Row>
	);
}

/** Widths for a run of stand-in calls, so no two neighbors match. */
const CALL_WIDTHS = [
	[ '17em', '11em' ],
	[ '13em', '9em' ],
	[ '20em', '12em' ],
	[ '15em', '8em' ],
	[ '18em', '10em' ],
	[ '12em', '11em' ],
];

/**
 * Calls standing in for themselves: the ability and who asked, the outcome's
 * badge, and when, in the record's own columns.
 *
 * @param {Object} props
 * @param {number} props.rows How many.
 */
function CallsBone( { rows } ) {
	return (
		<div className="bs-ds-agentlog__bones" aria-hidden="true">
			{ CALL_WIDTHS.slice( 0, rows ).map( ( [ ability, detail ] ) => (
				<div key={ ability } className="bs-ds-agentlog__bonerow">
					<span className="bs-ds-agentlog__bonetext">
						<Bone kind="title" w={ ability } />
						<Bone w={ detail } />
					</span>
					<Bone w="84px" />
					<Bone w="7em" />
				</div>
			) ) }
		</div>
	);
}

/** The four facts' names, shared by the strip and the record's stand-in. */
function glanceLabels() {
	return {
		recording: __( 'Recording', 'bettershield' ),
		all: __( 'Calls', 'bettershield' ),
		refused: __( 'Refused', 'bettershield' ),
		completed: __( 'Completed', 'bettershield' ),
	};
}

/**
 * The record before its first page has landed: the four facts, then the card
 * — its head and link, its intro, the tab row with the two pickers, the calls
 * and the foot.
 */
export function AgentActivityBone() {
	return (
		<Skeleton label={ __( 'Loading agent activity…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />

			<div className="bs-ds-card">
				<div className="bs-ds-card__head">
					<span className="bs-ds-bone bs-ds-bone--tile" />
					<Bone kind="title" w="7em" />
					<span className="bs-ds-spacer" />
					<Bone kind="control" w="104px" />
				</div>
				<div className="bs-ds-agentlog__boneintro">
					<Bone w="100%" />
					<Bone w="52%" />
				</div>
				<div className="bs-ds-agentlog__bonetabs">
					<Bone kind="title" w="3em" />
					<Bone kind="title" w="5em" />
					<Bone kind="title" w="6em" />
					<Bone kind="title" w="7em" />
					<span className="bs-ds-spacer" />
					<Bone kind="control" w="160px" />
					<Bone kind="control" w="128px" />
				</div>
				<CallsBone rows={ 6 } />
				<div className="bs-ds-agentlog__bonefoot">
					<Bone w="14em" />
				</div>
			</div>
		</Skeleton>
	);
}

/** No filter applied. Also the shape every filter value is read out of. */
const NO_FILTERS = { outcome: 'all', namespace: '', entry_path: '', connection: '', user: 0 };

function queryString( filters, cursor ) {
	const params = new window.URLSearchParams();

	if ( cursor ) {
		params.set( 'cursor', String( cursor ) );
	}
	if ( 'all' !== filters.outcome ) {
		params.set( 'outcome', filters.outcome );
	}
	[ 'namespace', 'entry_path', 'connection' ].forEach( ( name ) => {
		if ( filters[ name ] ) {
			params.set( name, filters[ name ] );
		}
	} );
	if ( filters.user > 0 ) {
		params.set( 'user', String( filters.user ) );
	}

	const query = params.toString();

	return query ? '?' + query : '';
}

function viewKey( filters ) {
	return [ filters.outcome, filters.namespace, filters.entry_path, filters.connection, filters.user ].join( '|' );
}

/**
 * The record in four facts: whether it is being kept, and how the calls in it
 * ended. Read from the page the screen already fetched, so it cannot disagree
 * with the rows under it.
 *
 * @param {?Object} platform Whether recording is available and on.
 * @param {Object}  counts   Invocations per outcome, and `all`.
 * @param {boolean} narrowed Whether filters narrow the view.
 * @param {string}  outcome  The outcome tab chosen, or `all`.
 * @return {Array<Object>} The strip's tiles.
 */
function glanceTiles( platform, counts, narrowed, outcome = 'all' ) {
	const labels = glanceLabels();
	let recording = '—';
	let tone;
	let detail = '';

	if ( platform ) {
		if ( ! platform.available ) {
			recording = __( 'Unavailable', 'bettershield' );
			detail = __( 'Needs a newer WordPress version', 'bettershield' );
		} else if ( platform.enabled ) {
			recording = __( 'On', 'bettershield' );
			tone = 'good';
			detail = __( 'Every AI assistant action is recorded', 'bettershield' );
		} else {
			recording = __( 'Off', 'bettershield' );
			tone = 'caution';
			detail = __( 'Turn it on in Settings', 'bettershield' );
		}
	}

	const number = ( key ) => Number( counts[ key ] || 0 ).toLocaleString();

	return [
		{ key: 'recording', label: labels.recording, value: recording, tone, detail },
		{
			key: 'all',
			label: labels.all,
			// The calls the chosen outcome tab shows: it said "Matching these
			// filters" over the total of every outcome (#1920).
			value: number( 'all' === outcome ? 'all' : outcome ),
			detail: narrowed ? __( 'Matching these filters', 'bettershield' ) : __( 'In the history kept here', 'bettershield' ),
		},
		{
			key: 'refused',
			label: labels.refused,
			value: number( 'permission_denied' ),
			tone: Number( counts.permission_denied || 0 ) > 0 ? 'caution' : undefined,
			detail: __( 'Asked for more than allowed', 'bettershield' ),
		},
		{
			key: 'completed',
			label: labels.completed,
			value: number( 'completed' ),
			detail: __( 'Ran and answered', 'bettershield' ),
		},
	].map( ( tile ) => ( { ...tile, icon: STAT_ICONS[ tile.key ] } ) );
}

export default function AgentActivity() {
	const [ cache, setCache ] = useState( {} );
	// One account, when a link from another screen asked for it.
	const [ opening ] = useState( () => ( { ...NO_FILTERS, user: linkedAccount(), connection: linkedConnection() } ) );
	const [ filters, setFilters ] = useState( opening );
	const [ shown, setShown ] = useState( () => viewKey( opening ) );
	// Whose calls the one-account view shows, as its rows name them.
	const [ accountLabel, setAccountLabel ] = useState( '' );

	const [ retention, setRetention ] = useState( null );
	const [ platform, setPlatform ] = useState( null );
	const [ status, setStatus ] = useState( 'loading' );
	const [ appending, setAppending ] = useState( false );
	const [ appendFailed, setAppendFailed ] = useState( false );

	const pending = useRef( new Set() );
	const mounted = useRef( true );
	const wanted = useRef( viewKey( opening ) );
	// The list, where the keyboard goes when the control it was on cleared the
	// account and went with it.
	const list = useRef( null );
	const [ refocus, setRefocus ] = useState( 0 );
	// And the log's heading, for Clear filters, which goes with the filters
	// it clears; the list may be the empty line by then.
	const heading = useRef( null );
	// Show older entries goes once the last page is in: focus comes back to
	// it, or to the list it extended (#2028).
	const older = useRef( null );

	useFocusAfter( appending, older, list );
	// Whether the next account came from a row, and so is a step Back undoes.
	const pushNext = useRef( false );
	const opened = useRef( false );

	// The address follows the account a link can narrow this to, so a reload,
	// a copied link or Back shows what is on screen. Not on the first paint,
	// which is the address itself.
	useEffect( () => {
		if ( ! opened.current ) {
			opened.current = true;
			return;
		}

		writeNarrowing( { account: filters.user > 0 ? filters.user : '' }, pushNext.current );
		pushNext.current = false;
	}, [ filters.user ] );

	// Back and Forward move the address without telling the screen.
	useEffect( () => {
		const onPopState = () => setFilters( ( current ) => ( { ...current, user: linkedAccount() } ) );

		window.addEventListener( 'popstate', onPopState );
		window.addEventListener( NAVIGATED, onPopState );

		return () => {
			window.removeEventListener( 'popstate', onPopState );
			window.removeEventListener( NAVIGATED, onPopState );
		};
	}, [] );

	useEffect( () => {
		if ( refocus && list.current ) {
			list.current.focus();
		}
	}, [ refocus ] );

	useEffect( () => {
		mounted.current = true;

		return () => {
			mounted.current = false;
		};
	}, [] );

	const load = useCallback( ( within, cursor = null ) => {
		const view = viewKey( within );
		const key = cursor ? view + '#' + cursor : view;

		if ( pending.current.has( key ) ) {
			return;
		}

		pending.current.add( key );
		setAppending( Boolean( cursor ) );
		setAppendFailed( false );

		apiFetch( { path: '/bettershield/v1/agent-activity' + queryString( within, cursor ) } )
			.then( ( data ) => {
				if ( ! mounted.current ) {
					return;
				}

				/*
				 * The totals belong to the view they were counted for, beside
				 * its rows. Held once for the screen, they were whatever the
				 * last answer said, so going back to a view already read
				 * showed its rows under another filter's numbers. A further
				 * page of a view keeps the totals its first page brought.
				 */
				setCache( ( current ) => {
					const earlier = cursor ? current[ view ] : null;

					return {
						...current,
						[ view ]: {
							invocations: [ ...( earlier ? earlier.invocations : [] ), ...data.invocations ],
							cursor: data.next_cursor,
							counts: earlier ? earlier.counts : data.counts || {},
							namespaces: earlier ? earlier.namespaces : data.namespaces || [],
							connections: earlier ? earlier.connections : data.connections || [],
						},
					};
				} );

				/*
				 * Several requests can be outstanding and can answer out of
				 * order. Each is cached either way — it is correct for the view
				 * that asked — but only the view still on the controls may take
				 * the screen, or a slow earlier response would pull the reader
				 * back to a filter they have moved on from.
				 */
				if ( view === wanted.current ) {
					setShown( view );
				}

				setRetention( data.retention_days );
				setPlatform( {
					available: data.capture_available,
					enabled: data.capture_enabled,
					requires: data.requires_wp,
				} );
				setStatus( 'ready' );
			} )
			.catch( () => {
				if ( ! mounted.current ) {
					return;
				}
				if ( cursor ) {
					setAppendFailed( true );
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
	}, [] );

	const view = viewKey( filters );

	useEffect( () => {
		wanted.current = view;

		if ( cache[ view ] ) {
			setShown( view );
			return;
		}

		load( filters, null );
	}, [ load, filters, view, cache ] );

	const set = ( changes ) => setFilters( ( current ) => ( { ...current, ...changes } ) );

	const entry = cache[ shown ];
	const invocations = entry ? entry.invocations : [];
	/*
	 * One source for every row shown: said once above the list instead of
	 * after each account name, 40 times on a page (#2606). Two or more, and
	 * each row keeps its own.
	 */
	const paths = [ ...new Set( invocations.map( ( invocation ) => invocation.entry_path ).filter( ( path ) => PATHS[ path ] ) ) ];
	const sharedPath = invocations.length > 1 && 1 === paths.length && invocations.every( ( invocation ) => invocation.entry_path === paths[ 0 ] ) ? paths[ 0 ] : '';
	const cursor = entry ? entry.cursor : null;
	const counts = ( entry && entry.counts ) || {};
	const namespaces = ( entry && entry.namespaces ) || [];
	const connections = ( entry && entry.connections ) || [];
	const settling = shown !== view;
	const narrowed = 'all' !== filters.outcome || filters.namespace || filters.entry_path || filters.connection || filters.user > 0;

	if ( 'loading' === status ) {
		return <AgentActivityBone />;
	}

	if ( 'error' === status ) {
		return <ErrorState onRetry={ () => load( filters, null ) } />;
	}

	/*
	 * A platform without the hooks says so once, plainly, and draws nothing
	 * else. A version notice above an empty list would read as "nothing has
	 * happened", which is a different and untrue statement.
	 */
	if ( platform && ! platform.available ) {
		return (
			<Card className="bs-ds-agentlog" aria-labelledby="bs-agentlog-title">
				<CardHead icon="bot" title={ __( 'Agent activity', 'bettershield' ) } id="bs-agentlog-title" />
				<EmptyState>
					<span className="bs-ds-agentlog__emptytitle">{ __( 'Agent activity is not recorded on this version.', 'bettershield' ) }</span>{ ' ' }
					{ sprintf(
						/* translators: %s: a WordPress version number. */
						__(
							'Recording agent activity needs WordPress %s or later. Nothing is missing.',
							'bettershield'
						),
						platform.requires
					) }
				</EmptyState>
			</Card>
		);
	}

	// The outcome tabs, in the order that puts the answer first. Refused
	// leads because it is what the screen is opened for.
	const outcomeOptions = [
		{ slug: 'all', label: __( 'All', 'bettershield' ) },
		{ slug: 'permission_denied', label: __( 'Refused', 'bettershield' ) },
		...Object.keys( OUTCOMES )
			.filter( ( key ) => 'permission_denied' !== key )
			.map( ( key ) => ( { slug: key, label: outcomeLabel( key ) } ) ),
	];

	const namespaceOptions = [
		{ value: '', label: __( 'Any plugin', 'bettershield' ) },
		...namespaces.map( ( item ) => ( {
			value: item.namespace,
			label: sprintf(
				/* translators: 1: a plugin's name, or its ability namespace, 2: how many invocations it accounts for. */
				__( '%1$s (%2$d)', 'bettershield' ),
				// This plugin's own namespace reads as its name, not its code.
				'bettershield' === item.namespace ? brand() : item.namespace,
				item.total
			),
		} ) ),
	];

	// What agents are able to do is a different question from what they have
	// done, and it has a screen of its own — one a reader who may not manage
	// the plugin cannot open, so they are not offered an address that is empty.
	const surface = tabUrl( 'bettershield-agents', 'surface' );

	return (
		<>
			<Stats label={ __( 'Agent activity at a glance', 'bettershield' ) } tiles={ glanceTiles( platform, counts, Boolean( narrowed ), filters.outcome ) } />

			{ /* A line rather than a card of its own: it qualifies the list
			     below, and as a second empty panel above an empty list the
			     screen said "nothing" twice. */ }
			{ platform && ! platform.enabled ? (
				<Alert
					tone="warning"
					live
					title={ __( 'Recording is switched off.', 'bettershield' ) }
					desc={ __( 'Entries below were recorded before then. Turn it back on in Settings.', 'bettershield' ) }
				/>
			) : null }

			<Card className="bs-ds-agentlog" aria-labelledby="bs-agentlog-title">
				<CardHead
					icon="bot"
					id="bs-agentlog-title"
					title={
						<span ref={ heading } tabIndex={ -1 } className="bs-ds-agentlog__title">
							{ __( 'Agent activity', 'bettershield' ) }
						</span>
					}
				>
					{ surface ? (
						<Button type="secondary" size="sm" href={ surface }>
							{ __( 'Agent Surface', 'bettershield' ) }
						</Button>
					) : null }
				</CardHead>
				<p className="bs-ds-agentlog__intro">
					{ __( 'Every action an AI assistant ran on this site. What it sent is stored only in coded form, never as readable text.', 'bettershield' ) }
				</p>

				<FitTabs
					id={ TABS_ID }
					label={ __( 'Filter agent activity by outcome', 'bettershield' ) }
					moreLabel={ __( 'Outcome', 'bettershield' ) }
					tabs={ outcomeOptions.map( ( option ) => ( {
						key: option.slug,
						label: option.label,
						count: Number( counts[ option.slug ] || 0 ).toLocaleString(),
					} ) ) }
					optionLabel={ ( tab ) =>
						sprintf(
							/* translators: 1: how a call ended, 2: how many calls ended that way. */
							__( '%1$s (%2$s)', 'bettershield' ),
							tab.label,
							tab.count
						)
					}
					selected={ filters.outcome }
					onSelect={ ( outcome ) => set( { outcome } ) }
					actions={
						<>
							<Field
								kind="select"
								className="bs-ds-agentlog__pick"
								label={ __( 'Plugin (from the action name)', 'bettershield' ) }
								hideLabelFromVision
								value={ filters.namespace }
								options={ namespaceOptions }
								onChange={ ( namespace ) => set( { namespace } ) }
							/>
							<Field
								kind="select"
								className="bs-ds-agentlog__pick"
								label={ __( 'Came through', 'bettershield' ) }
								hideLabelFromVision
								value={ filters.entry_path }
								options={ [
									{ value: '', label: __( 'Any source', 'bettershield' ) },
									{ value: 'mcp', label: __( 'AI assistant connection', 'bettershield' ) },
									{ value: 'rest', label: __( 'REST API', 'bettershield' ) },
									{ value: 'wp-cli', label: __( 'Command line (WP-CLI)', 'bettershield' ) },
									{ value: 'php', label: __( 'Code on this site', 'bettershield' ) },
								] }
								onChange={ ( entry_path ) => set( { entry_path } ) }
							/>
							{ connections.length > 0 || filters.connection ? (
								<Field
									kind="select"
									className="bs-ds-agentlog__pick"
									label={ __( 'Connection', 'bettershield' ) }
									hideLabelFromVision
									value={ filters.connection }
									options={ [
										{ value: '', label: __( 'Any connection', 'bettershield' ) },
										...connections.map( ( item ) => ( {
											value: item.connection,
											label: sprintf(
												/* translators: 1: an assistant application's name, or a manual credential, 2: how many calls it made. */
												__( '%1$s (%2$d)', 'bettershield' ),
												item.label,
												item.total
											),
										} ) ),
										// A connection a link asked for that has no calls listed
										// yet, named as the link named it rather than as "any".
										...( filters.connection && ! connections.some( ( item ) => item.connection === filters.connection )
											? [ { value: filters.connection, label: filters.connection } ]
											: [] ),
									] }
									onChange={ ( connection ) => set( { connection } ) }
								/>
							) : null }
							{ narrowed ? (
								<Button
									type="link"
									size="sm"
									className="bs-ds-agentlog__clear"
									onClick={ () => {
										heading.current?.focus();
										setFilters( NO_FILTERS );
									} }
								>
									{ __( 'Clear Filters', 'bettershield' ) }
								</Button>
							) : null }
						</>
					}
				/>

				<div { ...panelProps( TABS_ID, filters.outcome ) } className="bs-ds-agentlog__panel">
					<div className="bs-ds-agentlog__notes">
						{ sharedPath ? <p className="bs-ds-agentlog__narrowed">{ ALL_PATHS[ sharedPath ]() }</p> : null }
						{ filters.user > 0 ? (
							<p className="bs-ds-agentlog__narrowed">
								{ sprintf(
									/* translators: %s: an account's name, or its number. */
									__( 'Only calls made as %s.', 'bettershield' ),
									/* translators: %d: an account's number. */
									accountLabel || sprintf( __( 'account #%d', 'bettershield' ), filters.user )
								) }{ ' ' }
								<Button
									type="link"
									size="sm"
									onClick={ () => {
										set( { user: 0 } );
										// This button goes with the line it sits in.
										setRefocus( ( n ) => n + 1 );
									} }
								>
									{ __( 'Show Every Account', 'bettershield' ) }
								</Button>
							</p>
						) : null }

						{ /* The caveat the namespace filter needs: a statement about
						     what the platform records, not a hint about how to use
						     the control, so it waits behind its own question. */ }
						<Topics
							className="bs-ds-agentlog__topics"
							items={ [
								{
									key: 'namespace',
									// Said without the platform's term for it (#2569).
									label: __( 'How the plugin is known', 'bettershield' ),
									text: __(
										'Each action names the plugin it belongs to. That is usually the plugin that added it, but WordPress does not check.',
										'bettershield'
									),
								},
							] }
						/>
					</div>

					<div
						className={ `bs-ds-agentlog__list${ settling ? ' is-settling' : '' }` }
						aria-busy={ settling || appending }
						tabIndex={ -1 }
						ref={ list }
					>
						<Table label={ __( 'Agent calls', 'bettershield' ) } columns={ COLUMNS() }>
							{ ! invocations.length && ! settling ? (
								<WholeRow kind="empty">
									<span className="bs-ds-agentlog__emptytitle">
										{ narrowed ? __( 'Nothing matches these filters.', 'bettershield' ) : __( 'No agent has done anything here yet.', 'bettershield' ) }
									</span>{ ' ' }
									{ narrowed
										? __( 'Widen one filter and try again.', 'bettershield' )
										: __(
												'Every action an AI assistant runs here, including refused ones, will appear in this list.',
												'bettershield'
										  ) }
								</WholeRow>
							) : (
								invocations.map( ( invocation ) => (
									<Call
										key={ invocation.id }
										invocation={ invocation }
										sharedPath={ Boolean( sharedPath ) }
										onAccount={
											filters.user > 0
												? null
												: ( chosen ) => {
														setAccountLabel( chosen.user_label );
														pushNext.current = true;
														set( { user: chosen.user_id } );
												  }
										}
									/>
								) )
							) }
							{ /* An older page on its way, drawn where it will land. */ }
							{ appending && ! settling ? <CallsBone rows={ 3 } /> : null }
							{ ( cursor && ! settling ) || retention ? (
								<WholeRow kind="foot">
									{ cursor && ! settling ? (
										<Button ref={ older } type="secondary" size="sm" isBusy={ appending } disabled={ appending } onClick={ () => load( filters, cursor ) }>
											{ appending
												? __( 'Loading…', 'bettershield' )
												: appendFailed
												? __( 'That Did Not Load — Try Again', 'bettershield' )
												: __( 'Show Older Entries', 'bettershield' ) }
										</Button>
									) : null }
									{ retention ? (
										<span className="bs-ds-agentlog__footnote">
											{ sprintf(
												/* translators: %s: number of days of history kept, already formatted with its unit. */
												__( 'Entries are deleted after %s.', 'bettershield' ),
												sprintf(
													/* translators: %d: number of days. */
													_n( '%d day', '%d days', retention, 'bettershield' ),
													retention
												)
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
