/**
 * An open incident's prepared response: a plan of bounded actions prepared
 * on request, each chosen on its own, applied as one batch after the batch
 * says what it will do, each undone on its own where a way back was kept, and
 * a second look at what is still open once the batch has finished.
 */

import './IncidentResponse.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useId, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, useStore } from '../../store';
import { BreakablePath } from '../../ui/path';
import useMutationFocus from '../../ui/useMutationFocus';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { useFocusAfter } from '../ui/focus';
import Field from '../ui/Field';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import { omittedCount, recheckStatus } from '../data/incidents';
import Part from './Part';

/** The mark a re-checked line's state is drawn with: still open is a caution, not an alarm. */
const RECHECK_MARKS = {
	open: 'warning',
	closed: 'ok',
	not_done: 'off',
	manual: 'info',
	not_checked: 'off',
	checking: 'info',
};

/** What each outcome of an applied action is called, and the tone it is drawn in. */
function resultBadge( status ) {
	return (
		{
			applied: [ __( 'Applied', 'bettershield' ), 'brand' ],
			refused: [ __( 'Refused', 'bettershield' ), 'neutral' ],
			uncertain: [ __( 'Didn’t finish — check it', 'bettershield' ), 'yellow' ],
			undone: [ __( 'Undone', 'bettershield' ), 'neutral' ],
			met: [ __( 'Requirement met', 'bettershield' ), 'brand' ],
			lifted: [ __( 'Lifted', 'bettershield' ), 'neutral' ],
		}[ status ] || [ status, 'neutral' ]
	);
}

export default function IncidentResponse( { incident, resolved } ) {
	const { prepareIncidentResponse, applyIncidentResponse, undoIncidentResponse, busy } = useStore();
	const [ recheck, setRecheck ] = useState( null );
	const [ rechecking, setRechecking ] = useState( false );
	const [ recheckError, setRecheckError ] = useState( '' );
	const [ plan, setPlan ] = useState( null );
	const [ selected, setSelected ] = useState( [] );
	const [ readError, setReadError ] = useState( '' );
	const [ history, setHistory ] = useState( { plans: [], next_cursor: 0 } );
	const [ reading, setReading ] = useState( false );
	const generation = useRef( 0 );
	const readHistory = async ( cursor = 0 ) => {
		const request = generation.current;
		try {
			const data = await apiFetch( { path: `/bettershield/v1/incidents/${ incident }/response/history?cursor=${ cursor }` } );
			if ( request === generation.current ) {
				setHistory( ( old ) => ( { plans: cursor ? [ ...old.plans, ...data.plans ] : data.plans, next_cursor: data.next_cursor } ) );
			}
		} catch ( e ) {
			if ( request === generation.current ) {
				setReadError( e.message );
			}
		}
	};
	useEffect( () => {
		readHistory();
		return () => {
			generation.current++;
		};
	}, [ incident ] ); // eslint-disable-line react-hooks/exhaustive-deps
	useEffect( () => {
		let alive = true;
		apiFetch( { path: `/bettershield/v1/incidents/${ incident }/response` } ).then(
			( data ) => {
				if ( alive && data.token ) {
					setPlan( data );
					setSelected( data.receipt?.selected || [] );
				}
			},
			( e ) => {
				if ( alive ) {
					setReadError( e.message );
				}
			}
		);
		return () => {
			alive = false;
		};
	}, [ incident ] );
	const accept = ( data ) => {
		setPlan( data );
		readHistory();
	};
	/*
	 * A second look at what an applied plan acted on. Asked directly rather
	 * than as one of the store's actions: it changes nothing, and it follows
	 * an action the store is still finishing, which would turn it away.
	 */
	const runRecheck = ( token ) => {
		const request = generation.current;
		setRechecking( true );
		setRecheckError( '' );
		apiFetch( { path: `/bettershield/v1/incident-response/${ token }/recheck`, method: 'POST' } )
			.then(
				( data ) => {
					if ( request === generation.current ) {
						setRecheck( data );
					}
				},
				( e ) => {
					if ( request === generation.current ) {
						setRecheckError( e.message );
					}
				}
			)
			.finally( () => {
				if ( request === generation.current ) {
					setRechecking( false );
				}
			} );
	};
	// The second look runs on its own once a batch has finished, as a separate
	// request: it never holds the batch up, and a plan read back later is
	// checked only when asked.
	const applied = ( data ) => {
		accept( data );
		setRecheck( null );
		if ( data?.receipt?.complete ) {
			runRecheck( data.token );
		}
	};
	// Undo replaces the plan under the same token, so a verdict reached
	// before it would go on being drawn: it is cleared and asked again.
	const undone = ( data ) => {
		setRecheck( null );
		if ( data?.receipt?.complete ) {
			runRecheck( data.token );
		}
	};
	const loadPlan = async ( token ) => {
		const request = generation.current;
		setReading( true );
		setReadError( '' );
		try {
			const data = await apiFetch( { path: `/bettershield/v1/incident-response/${ token }` } );
			if ( request === generation.current ) {
				setPlan( data );
				setSelected( data.receipt?.selected || [] );
			}
		} catch ( e ) {
			if ( request === generation.current ) {
				setReadError( e.message );
			}
		} finally {
			if ( request === generation.current ) {
				setReading( false );
			}
		}
	};
	return (
		<IncidentResponsePanel
			{ ...{
				incident,
				resolved,
				plan,
				selected,
				setSelected,
				readError,
				busy: busy || reading,
				history,
				readHistory,
				loadPlan,
				prepareIncidentResponse,
				applyIncidentResponse: ( token, chosen, then ) =>
					applyIncidentResponse( token, chosen, ( data ) => {
						then( data );
						applied( data );
					} ),
				undoIncidentResponse: ( token, id, then ) =>
					undoIncidentResponse( token, id, ( data ) => {
						then( data );
						undone( data );
					} ),
				accept,
				recheck: recheck?.token === plan?.token ? recheck : null,
				onRecheck: () => runRecheck( plan.token ),
				rechecking,
				recheckError,
			} }
		/>
	);
}

/**
 * The second look, as contain, verify, recover and confirm.
 *
 * Every line is a thing this read, or a thing it could not, and the summary
 * never claims more than that: "nothing we re-checked is still open", with
 * when it ran.
 */
function RecheckChecklist( { recheck, onRecheck, busy, headRef = null } ) {
	return (
		<div className="bs-ds-recheck">
			<h4 ref={ headRef } tabIndex={ -1 } className="bs-ds-recheck__title">
				{ __( 'After the response', 'bettershield' ) }
			</h4>
			<p role="status" className="bs-ds-part__text">
				{ recheck.open > 0
					? sprintf(
							/* translators: 1: number of lines still open, 2: date and time. */
							_n( '%1$d item still needs attention (checked %2$s).', '%1$d items still need attention (checked %2$s).', recheck.open, 'bettershield' ),
							recheck.open,
							formatTime( recheck.checked_at )
					  )
					: sprintf(
							/* translators: %s: date and time. */
							__( 'Everything below looks fixed (checked %s). This covers only the items listed.', 'bettershield' ),
							formatTime( recheck.checked_at )
					  ) }
			</p>
			{ recheck.groups.map( ( group ) => (
				<section key={ group.key } className="bs-ds-recheck__group">
					<h5 className="bs-ds-recheck__head">{ group.title }</h5>
					<KeyValues className="bs-ds-part__facts">
						{ group.lines.map( ( line ) => (
							<KeyValue
								key={ line.key }
								label={ line.url ? <a href={ line.url }>{ line.label }</a> : line.label }
								value={ recheckStatus( line.status ) }
								status={ RECHECK_MARKS[ line.status ] || '' }
								note={ line.detail || null }
							/>
						) ) }
					</KeyValues>
				</section>
			) ) }
			<span>
				<Button type="secondary" size="sm" icon="refresh-cw" iconTone="2" isBusy={ busy } disabled={ busy } onClick={ onRecheck }>
					{ busy ? __( 'Checking…', 'bettershield' ) : __( 'Check Again', 'bettershield' ) }
				</Button>
			</span>
		</div>
	);
}

function IncidentResponsePanel( {
	incident,
	resolved,
	plan,
	selected,
	setSelected,
	readError,
	busy,
	prepareIncidentResponse,
	applyIncidentResponse,
	undoIncidentResponse,
	accept,
	history,
	readHistory,
	loadPlan,
	recheck = null,
	onRecheck = null,
	rechecking = false,
	recheckError = '',
} ) {
	const heading = useRef( null );
	const afterMutation = useMutationFocus( heading );
	// Earlier plans, folded away until asked for.
	const [ historyOpen, setHistoryOpen ] = useState( false );
	const historyId = `bs-ds-response-history-${ useId().replace( /[^\w-]/g, '' ) }`;
	const recheckFirst = useRef( null );
	const recheckHead = useRef( null );

	useFocusAfter( rechecking, recheckFirst, recheckHead );

	return (
		<Part
			icon="list-checks"
			title={ __( 'Suggested fixes', 'bettershield' ) }
			headingRef={ heading }
			className="bs-ds-response"
			trailing={
				<Button
					type="secondary"
					size="sm"
					disabled={ !! busy || resolved }
					onClick={ () =>
						prepareIncidentResponse( incident, ( data ) => {
							setSelected( [] );
							accept( data );
						} )
					}
				>
					{ plan ? __( 'Prepare a Fresh Plan', 'bettershield' ) : __( 'Prepare Response Plan', 'bettershield' ) }
				</Button>
			}
		>
			{ readError ? (
				<div role="alert">
					<Alert layout="default" tone="error" desc={ readError } />
				</div>
			) : null }
			<p className="bs-ds-part__text">
				{ __( 'Check each step first: an account or file listed here may be innocent. Applying steps doesn’t close the incident.', 'bettershield' ) }
			</p>
			{ resolved ? (
				<p className="bs-ds-part__text">
					{ __( 'This incident is handled. Receipts and undo still work; reopen it to prepare another response.', 'bettershield' ) }
				</p>
			) : null }
			{ history?.plans.length > 0 ? (
				<div className="bs-ds-part__disclosure">
					<Button
						type="ghost"
						size="sm"
						trailing={ historyOpen ? 'chevron-up' : 'chevron-down' }
						trailingTone="3"
						aria-expanded={ historyOpen }
						aria-controls={ historyOpen ? historyId : undefined }
						onClick={ () => setHistoryOpen( ! historyOpen ) }
					>
						{ __( 'Response Plan History', 'bettershield' ) }
					</Button>
					{ historyOpen ? (
						<div id={ historyId } className="bs-ds-response__history">
							<p className="bs-ds-part__text">{ __( 'Open an earlier plan to review its receipt or undo its actions.', 'bettershield' ) }</p>
							<ul className="bs-ds-response__plans">
								{ history.plans.map( ( entry ) => (
									<li key={ entry.token }>
										<Button
											type="linksub"
											size="sm"
											disabled={ !! busy }
											// Held while a plan is read, and still where the
											// keyboard is (#2028).
											accessibleWhenDisabled
											aria-current={ entry.token === plan?.token ? 'true' : undefined }
											onClick={ () => loadPlan( entry.token ) }
										>
											{ sprintf(
												/* translators: %s: the date and time the plan was prepared. */
												__( 'Plan Prepared %s', 'bettershield' ),
												formatTime( entry.created_at )
											) }
										</Button>
									</li>
								) ) }
							</ul>
						</div>
					) : null }
				</div>
			) : null }
			{ history?.next_cursor > 0 ? (
				<span>
					<Button type="secondary" size="sm" disabled={ !! busy } onClick={ () => readHistory( history.next_cursor ) }>
						{ __( 'Load Older Response Plans', 'bettershield' ) }
					</Button>
				</span>
			) : null }

			{ plan ? (
				<>
					<KeyValues className="bs-ds-part__facts">
						<KeyValue
							label={
								/* translators: label beside the date and time the prepared selections expire. */
								__( 'This plan expires at', 'bettershield' )
							}
							value={ formatTime( plan.expires ) }
						/>
					</KeyValues>
					{ plan.limited ? (
						<p role="status" className="bs-ds-part__text">
							{ __( 'This plan covers up to 100 records, 5 accounts and 20 steps. Review anything beyond that on your own.', 'bettershield' ) }
						</p>
					) : null }
					{ Object.values( plan.omitted || {} ).some( ( count ) => count > 0 ) ? (
						<p className="bs-ds-part__text">
							{ sprintf(
								/* translators: %s: comma-separated counts and names of omitted action types. */
								__( 'These weren’t added to the plan, so check them yourself: %s.', 'bettershield' ),
								Object.entries( plan.omitted )
									.filter( ( [ , count ] ) => count > 0 )
									.map( ( [ kind, count ] ) => omittedCount( kind, count ) )
									.join( ', ' )
							) }
						</p>
					) : null }
					{ /* A plan belongs to the sign-in session that prepared it, and to
					     ten minutes. One past either is a record: shown, and said so,
					     rather than offered with an Apply that can only be refused. */ }
					{ false === plan.actionable && ! plan.receipt?.selected ? (
						<p role="status" className="bs-ds-part__text">
							{ 'session' === plan.stale
								? __( 'This plan was made in another browser or sign-in, so it can only be viewed. Prepare a new plan to act.', 'bettershield' )
								: __( 'This plan has expired and is read-only. Prepare a fresh plan to act.', 'bettershield' ) }
						</p>
					) : null }
					{ ! plan.ready ? (
						<p role="status" className="bs-ds-part__text">
							{ __( 'To apply this plan, set up a recovery method and turn off safe mode under Protection › Recovery.', 'bettershield' ) }
						</p>
					) : null }
					{ plan.refusals.length ? (
						<ul className="bs-ds-response__refusals">
							{ plan.refusals.map( ( text ) => (
								<li key={ text }>{ text }</li>
							) ) }
						</ul>
					) : null }
					<div className="bs-ds-response__items">
						{ plan.items.map( ( item ) => {
							const result = plan.receipt?.results?.[ item.id ];
							const [ outcome, tone ] = result ? resultBadge( result.status ) : [ '', '' ];

							return (
								<section className="bs-ds-response__item" key={ item.id }>
									<Field
										kind="check"
										label={ <BreakablePath path={ item.label } /> }
										checked={ selected.includes( item.id ) }
										disabled={ !! busy || !! item.refusal || !! plan.receipt?.selected || false === plan.actionable }
										onChange={ ( on ) => setSelected( ( old ) => ( on ? [ ...old, item.id ] : old.filter( ( id ) => id !== item.id ) ) ) }
									/>
									{ item.detail ? <p className="bs-ds-part__text">{ item.detail }</p> : null }
									{ item.note ? <p className="bs-ds-part__text">{ item.note }</p> : null }
									{ item.refusal ? (
										<p className="bs-ds-part__text">
											{ sprintf(
												/* translators: %s: why this action was refused. */
												__( 'Refused: %s', 'bettershield' ),
												item.refusal
											) }
										</p>
									) : null }
									{ result ? (
										<div role="status" className="bs-ds-response__result">
											<Badge tone={ tone }>{ outcome }</Badge>
											{ result.message ? <p className="bs-ds-part__text">{ result.message }</p> : null }
											{ 'applied' === result.status && result.undo ? (
												<span>
													<Button
														type="secondary"
														size="sm"
														icon="undo-2"
														iconTone="2"
														disabled={ !! busy }
														onClick={ () => undoIncidentResponse( plan.token, item.id, afterMutation( accept ) ) }
													>
														{ __( 'Undo This Action', 'bettershield' ) }
													</Button>
												</span>
											) : null }
										</div>
									) : null }
								</section>
							);
						} ) }
					</div>
					{ /* The checkboxes above choose what is in the batch; this is the
					     step that says what pressing it does, at the moment it is about
					     to happen. One batch here can change a role, end every session
					     on an account, revoke credentials and move files. */ }
					{ ! plan.receipt?.selected ? (
						<span className="bs-ds-response__apply">
							<Armed
								type="primary"
								label={ __( 'Apply Selected Actions', 'bettershield' ) }
								consequence={ sprintf(
									/* translators: %d: how many actions are selected. */
									_n(
										'This applies %d selected action now. If a way back was kept, it can be undone.',
										'This applies %d selected actions now, as one batch. Each with a way back can be undone separately.',
										selected.length,
										'bettershield'
									),
									selected.length
								) }
								busy={ !! busy }
								disabled={ ! selected.length || ! plan.ready || false === plan.actionable }
								onConfirm={ () => applyIncidentResponse( plan.token, selected, afterMutation( accept ) ) }
							/>
						</span>
					) : null }
					{ plan.receipt?.selected && ! plan.receipt.complete ? (
						<div role="alert">
							<Alert
								layout="default"
								tone="warning"
								desc={ __( 'Some steps didn’t finish. Before trying again, check the account or file and the Activity log.', 'bettershield' ) }
							/>
						</div>
					) : null }
					{ plan.receipt?.complete && recheckError ? (
						<div role="alert">
							<Alert layout="default" tone="error" desc={ recheckError } />
						</div>
					) : null }
					{ plan.receipt?.complete && onRecheck ? (
						recheck ? (
							<RecheckChecklist recheck={ recheck } onRecheck={ onRecheck } busy={ rechecking } headRef={ recheckHead } />
						) : (
							<p className="bs-ds-part__text">
								{ /* Held where it was pressed while the check runs; the
								     checklist that replaces it takes focus at its
								     heading (#2028). */ }
								<Button ref={ recheckFirst } type="secondary" size="sm" isBusy={ rechecking } disabled={ rechecking } onClick={ onRecheck }>
									{ rechecking ? __( 'Checking What Is Still Open…', 'bettershield' ) : __( 'Check What Is Still Open', 'bettershield' ) }
								</Button>
							</p>
						)
					) : null }
				</>
			) : null }
		</Part>
	);
}
