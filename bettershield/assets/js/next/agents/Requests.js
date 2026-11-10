/**
 * Agents › Requests: the changes an agent has worked out, waiting on a person.
 *
 * Nothing in this list has happened. A proposal is a plan and a deadline, and
 * it becomes a change only when somebody reads it and allows that one change,
 * once, before it expires. Allowing is the only thing in the product that
 * hands out a secret, and the secret is shown once.
 *
 * The agent strip, then one card: Waiting and All as tabs, each request a row
 * of the table with its plan opening under it.
 */

import './Requests.css';

import apiFetch from '@wordpress/api-fetch';
import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { accessFrom, siteSkew } from '../../agents/access';
import { currentStatus, expiryPhrase, madePhrase, STATUSES } from '../../agents/phrases';
import { tabUrl } from '../../nav';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import useNow from '../../ui/useNow';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import CopyField from '../ui/CopyField';
import Skeleton, { Bone, CardBone } from '../ui/Skeleton';
import { EmptyState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Tabs from '../ui/Tabs';
import { panelProps } from '../ui/tabKeys';
import AgentStrip, { AgentStripBone } from './AgentStrip';

const PROPOSALS = '/bettershield/v1/agents/proposals';

/** What the list is showing: the ones still waiting, or every one on record. */
const WAITING = 'open';
const EVERY = 'all';

const TABS_ID = 'bs-ds-requests';

/** Access plans, whose own lines say they cannot be undone. */
const ACCESS_TARGETS = [ 'sessions', 'mcp_app', 'lockdown' ];

/*
 * Why a change to how people sign in cannot be allowed while nobody is asked
 * for a password: it applies only with one re-entered at the allow, and the
 * site refuses the allow without it. The site's own reason when it sent one:
 * only it can tell the switch being off from an account with no password to
 * re-enter, and telling the second to turn on a switch that is on leads
 * nowhere.
 */
const PASSWORD_NEEDED = ( reason ) =>
	reason ||
	__(
		'Approving sign-in changes asks for your password. Turn on password confirmation under Settings first.',
		'bettershield'
	);

/**
 * The plan, as the ability computed it. Read before anything is allowed.
 *
 * @param {Object}  props
 * @param {Object}  props.proposal       The request.
 * @param {boolean} props.sudoRequired   Whether the allow asks for a password.
 * @param {string}  props.passwordReason Why a sign-in change cannot be allowed here.
 * @param {string}  props.status         The request's status as the row shows it.
 */
/**
 * What an applied request's stored outcome means, in words, or '' where the
 * row's badge and its "applied …" line already say it. The outcome is stored
 * as a machine word, never shown as it is (#2643).
 *
 * @param {string} outcome The stored outcome: applied, reverted, restored, deactivated, unknown, or a refusal's code.
 * @return {string} A sentence, or ''.
 */
function outcomeWords( outcome ) {
	switch ( outcome ) {
		case 'reverted':
			return __( 'The protection was taken off.', 'bettershield' );
		case 'restored':
			return __( 'The file was put back.', 'bettershield' );
		case 'deactivated':
			return __( 'The plugin was deactivated.', 'bettershield' );
		case 'unknown':
			return __( 'Applied, but the site couldn’t confirm the result.', 'bettershield' );
		case 'applied':
		case '':
		case null:
		case undefined:
			return '';
		default:
			// A refusal after the confirmation was spent stores its error code.
			return __( 'The site refused this change after it was confirmed. Site Activity has the reason.', 'bettershield' );
	}
}

function Plan( { proposal, sudoRequired, passwordReason, status = 'proposed' } ) {
	const plan = proposal.plan || {};
	// Recovery verified is not enough on its own: the change applies only
	// with a password re-entered at the allow, which nobody is asked for here.
	const needsPassword = plan.changes_signing_in && 'revert' !== plan.action && ! sudoRequired;
	const effect = plan.effect || [];
	const preview = plan.preview || [];
	let gate = null;

	/*
	 * The gate, said as a condition rather than as a warning. An item that
	 * moves the way people sign in is allowed only while the way back in is
	 * known to work, and the reader is told which of those facts is true today.
	 */
	// What an allow needs, said only while one can be given: on a request
	// already allowed it read "allow the change again", and the change then
	// applied (#1919).
	if ( 'file_change' !== proposal.target_type && plan.changes_signing_in && 'proposed' === status ) {
		if ( ! plan.recovery_ready ) {
			gate = __(
				'This changes how people sign in, so first press Check Recovery Options under Protection › Recovery.',
				'bettershield'
			);
		} else if ( needsPassword ) {
			gate = PASSWORD_NEEDED( passwordReason );
		} else {
			gate = __( 'This changes how people sign in. Your recovery link was checked in the last 24 hours, so it can be approved.', 'bettershield' );
		}
	}

	return (
		<div className="bs-ds-plan" id={ `bs-plan-${ proposal.id }` }>
			{ 'file_change' === proposal.target_type ? (
				<>
					<p className="bs-ds-plan__what">{ plan.path }</p>
					<p>{ plan.summary }</p>
					<p className="bs-ds-plan__meta">
						{ sprintf(
							/* translators: %s: the checksum of the published file. */
							__( 'Matches the official copy (%s)', 'bettershield' ),
							plan.checksum || ''
						) }
					</p>
					{ plan.quarantine ? <p className="bs-ds-plan__meta">{ __( 'The current file is quarantined, not deleted.', 'bettershield' ) }</p> : null }
				</>
			) : (
				<>
					{ /* The item's own title, and only that: the group arrives as
					     the key the items are filed under, a word nobody translated.
					     Left out where the row above already says it (#2643). */ }
					{ plan.title && plan.title !== proposal.target_label ? <p className="bs-ds-plan__what">{ plan.title }</p> : null }
					{ effect.length ? (
						<ul className="bs-ds-plan__lines">
							{ effect.map( ( line, index ) => (
								<li key={ index }>{ line }</li>
							) ) }
						</ul>
					) : null }
					{ plan.conflict ? <Alert layout="default" tone="warning" desc={ plan.conflict } /> : null }
					{ gate ? <Alert layout="default" tone="info" desc={ gate } /> : null }
					{ preview.length ? (
						<ul className="bs-ds-plan__lines">
							{ preview.map( ( line, index ) => (
								<li key={ index }>{ line }</li>
							) ) }
						</ul>
					) : null }
				</>
			) }
			{ /* Once applied, the strip under the row says whether it can be
			     undone now; the plan's own sentence would say it twice (#2643). */ }
			{ /* An access plan (sessions, an app, lockdown) already says in its
			     own lines that it cannot be undone; saying it again repeats it. */ }
			{ 'spent' === status || ( ! plan.reversible && ACCESS_TARGETS.includes( proposal.target_type ) ) ? null : (
				<p className="bs-ds-plan__meta">
					{ plan.reversible ? __( 'This can be put back afterwards.', 'bettershield' ) : __( 'This cannot be put back afterwards.', 'bettershield' ) }
				</p>
			) }
		</div>
	);
}

/**
 * One request: its row, then whatever opens under it.
 *
 * Allowing is the only thing on this screen that hands out a secret, and the
 * secret is shown once: minted for this change and this state of the site,
 * never written to any log, and the site keeps only its fingerprint. The row
 * says so in the same breath as showing it.
 */
function Proposal( { proposal, now, capability, sudoRequired, passwordReason, onChanged } ) {
	const { allowProposal, withdrawProposal, busy } = useStore();
	const heading = useRef( null );
	const afterMutation = useMutationFocus( heading );
	const [ open, setOpen ] = useState( false );
	const [ minted, setMinted ] = useState( null );

	const working = isWorking( busy, `proposal-${ proposal.id }` );
	const status = currentStatus( proposal, now );
	const shown = STATUSES[ status ] || STATUSES.proposed;
	const plan = proposal.plan || {};
	// The site refuses these too; the row refuses first, beside the sentence
	// saying which condition is unmet. Taking a sign-in protection off opens
	// the way in, so a revert plan is not held behind the recovery check.
	const movesSignIn = plan.changes_signing_in && 'revert' !== plan.action;
	const blocked = ! capability || ( movesSignIn && ( ! plan.recovery_ready || ! sudoRequired ) );
	const reasonId = `bs-blocked-${ proposal.id }`;
	let blockedReason = __( 'Your account can’t approve AI fixes. Ask an administrator.', 'bettershield' );

	if ( capability && ! plan.recovery_ready ) {
		blockedReason = __(
			'This changes how people sign in, so first press Check Recovery Options under Protection › Recovery.',
			'bettershield'
		);
	} else if ( capability ) {
		blockedReason = PASSWORD_NEEDED( passwordReason );
	}

	const refused = 'proposed' === status && blocked;

	const allow = () =>
		allowProposal(
			proposal.id,
			afterMutation( ( result ) => {
				setMinted( { confirmation: result.confirmation, expires_at: result.expires_at } );
				onChanged( result.proposal, status );
			} )
		);

	const withdraw = () =>
		withdrawProposal(
			proposal.id,
			afterMutation( ( result ) => {
				// Whatever was minted no longer opens anything.
				setMinted( null );
				onChanged( result.proposal, status );
			} )
		);

	// The heading is the thing that would change, and the kind of change is
	// a fact in the line under it.
	const meta = [
		proposal.ability_label,
		madePhrase( proposal.proposed_at, now ),
		// A deadline is a fact about a row that is still waiting; beside
		// "Used" it reads as a contradiction.
		'spent' === status || 'withdrawn' === status || 'declined' === status ? null : expiryPhrase( proposal.expires_at, now ),
		'spent' === status && proposal.spent_at
			? sprintf(
					/* translators: %s: when the change was made, e.g. "today, 5:14 PM". */
					__( 'applied %s', 'bettershield' ),
					whenPhrase( proposal.spent_at, new Date( now ) )
			  )
			: null,
		proposal.minted_by
			? sprintf(
					/* translators: %s: the name of the person who allowed the change. */
					__( 'approved by %s', 'bettershield' ),
					proposal.minted_by.display_name
			  )
			: null,
	].filter( Boolean );

	return (
		<>
			<Row open={ open }>
				<Cell>
					<TitleMeta
						title={
							<h3 className="bs-ds-proposal__name" tabIndex={ -1 } ref={ heading }>
								{ proposal.target_label }
							</h3>
						}
						meta={
							<>
								<span className="bs-ds-proposal__meta">
									{ meta.map( ( part, index ) => (
										<span key={ index }>{ part }</span>
									) ) }
								</span>
								{ /* The reason sits on the row, not inside the plan: a
								     disabled button with nothing beside it gives no prompt. */ }
								{ refused ? (
									<span className="bs-ds-proposal__reason" id={ reasonId }>
										{ blockedReason }
									</span>
								) : null }
							</>
						}
					/>
				</Cell>
				<Cell>
					<Badge tone={ kindTone( shown.kind ) }>{ shown.label() }</Badge>
				</Cell>
				<Cell align="end">
					<Button
						type="ghost"
						size="sm"
						trailing={ open ? 'chevron-up' : 'chevron-down' }
						trailingTone="3"
						aria-expanded={ open }
						aria-controls={ open ? `bs-plan-${ proposal.id }` : undefined }
						onClick={ () => setOpen( ! open ) }
					>
						{ open ? __( 'Hide Details', 'bettershield' ) : __( 'Show Details', 'bettershield' ) }
					</Button>
					{ 'proposed' === status ? (
						<Button type="primary" size="sm" isBusy={ working } disabled={ working || blocked } aria-describedby={ refused ? reasonId : undefined } onClick={ allow }>
							{ __( 'Approve', 'bettershield' ) }
						</Button>
					) : null }
					{ /* A plan nobody wants is set aside now rather than left
					     holding the count until it lapses. */ }
					{ 'proposed' === status ? (
						<Armed
							type="ghost"
							label={ __( 'Decline', 'bettershield' ) }
							consequence={ __( 'Set aside; nothing was applied. The assistant can ask again.', 'bettershield' ) }
							busy={ working }
							onConfirm={ withdraw }
						/>
					) : null }
					{ /* Armed: the confirmation the assistant holds stops working
					     the moment this completes, and is never handed out twice. */ }
					{ 'allowed' === status ? (
						<Armed
							type="ghost"
							label={ __( 'Cancel Approval', 'bettershield' ) }
							consequence={ __(
								'The code you copied stops working. Nothing was changed.',
								'bettershield'
							) }
							busy={ working }
							onConfirm={ withdraw }
						/>
					) : null }
				</Cell>
			</Row>
			{ open ? (
				<div className="bs-ds-proposal__under bs-ds-proposal__under--open" role="row">
					<div role="cell">
						<Plan proposal={ proposal } sudoRequired={ sudoRequired } passwordReason={ passwordReason } status={ status } />
					</div>
				</div>
			) : null }
			{ minted ? (
				<div className="bs-ds-proposal__under" role="row">
					<div role="cell" className="bs-ds-proposal__minted">
						<p role="status" className="bs-ds-proposal__once">
							{ __( 'Paste this into your assistant.', 'bettershield' ) }
						</p>
						<CopyField
							label={ sprintf(
								/* translators: %s: the change the confirmation opens, e.g. "Turn on the login limiter". */
								__( 'Approval code for %s', 'bettershield' ),
								proposal.target_label || proposal.ability_label
							) }
							value={ minted.confirmation }
							copyLabel={ sprintf(
								/* translators: %s: the change the confirmation opens. */
								__( 'Copy the Approval Code for %s', 'bettershield' ),
								proposal.target_label || proposal.ability_label
							) }
						/>
						<p className="bs-ds-plan__meta">
							{ sprintf(
								/* translators: %s: a date and time. */
								__( 'It works once, until %s, and is shown only now.', 'bettershield' ),
								formatTime( minted.expires_at )
							) }
						</p>
					</div>
				</div>
			) : null }
			{ 'spent' === status ? (
				<div className="bs-ds-proposal__under" role="row">
					<div role="cell" className="bs-ds-plan__meta">
						{ outcomeWords( proposal.outcome ) ? <p>{ outcomeWords( proposal.outcome ) }</p> : null }
						<p>
							{ proposal.revertable ? __( 'This can be undone.', 'bettershield' ) : __( 'This can’t be undone.', 'bettershield' ) }
						</p>
					</div>
				</div>
			) : null }
		</>
	);
}

/** The rows standing in for themselves while the first page is read. */
function RowsBone() {
	return (
		<Skeleton label={ __( 'Loading the requests…', 'bettershield' ) }>
			<div className="bs-ds-proposal__bones">
				{ [ '40%', '55%', '35%' ].map( ( w ) => (
					<div key={ w } className="bs-ds-bonerow">
						<span className="bs-ds-bonerow__text">
							<Bone kind="title" w={ w } />
							<Bone w="25%" />
						</span>
						<Bone kind="control" w="88px" />
					</div>
				) ) }
			</div>
		</Skeleton>
	);
}

/**
 * The requests card, and the whole of the minting surface. Present whether or
 * not anything can act, because "nothing can act" is an answer owners come
 * here for as often as the list.
 */
function RequestsCard( { surface } ) {
	const [ access, setAccess ] = useState( () => ( {
		read_enabled: !! surface.abilities_enabled,
		write_enabled: !! surface.write_enabled,
		capability_granted: !! surface.capability_granted,
		sudo_required: !! surface.sudo_required,
		password_reason: surface.password_reason || null,
	} ) );
	// What the site said was waiting when this page was read. The heading
	// prefers the rows to it; see below.
	const [ counted, setCounted ] = useState( () => Math.max( 0, Number( surface.open_requests ) || 0 ) );
	const [ list, setList ] = useState( null );
	const [ scope, setScope ] = useState( WAITING );
	const [ state, setState ] = useState( 'loading' );
	const [ error, setError ] = useState( '' );
	const [ more, setMore ] = useState( false );
	// Recorded when a page arrives: the gap between the two clocks is fixed,
	// the moment it is measured is not.
	const [ skew, setSkew ] = useState( 0 );
	// Which read a reply belongs to. A page that arrives after the reader has
	// changed what they look at answers a different question.
	const generation = useRef( 0 );

	const read = useCallback( ( which, cursor ) => {
		const request = ++generation.current;
		const path = `${ PROPOSALS }?status=${ which }${ cursor ? `&after=${ encodeURIComponent( cursor ) }` : '' }`;

		if ( cursor ) {
			setMore( true );
		} else {
			setState( 'loading' );
		}

		return apiFetch( { path } ).then(
			( data ) => {
				if ( request !== generation.current ) {
					return;
				}

				setSkew( siteSkew( data ) );
				setAccess( ( old ) => ( { ...old, ...accessFrom( data ) } ) );

				if ( undefined !== data.open_requests ) {
					setCounted( Math.max( 0, Number( data.open_requests ) || 0 ) );
				}

				setList( ( old ) => ( cursor && old ? { ...data, proposals: [ ...old.proposals, ...( data.proposals || [] ) ] } : data ) );
				setState( 'ready' );
				setError( '' );
				setMore( false );
			},
			( failure ) => {
				if ( request !== generation.current ) {
					return;
				}

				setState( 'error' );
				setError( failure && failure.message ? failure.message : '' );
				setMore( false );
			}
		);
	}, [] );

	useEffect( () => {
		read( scope );
	}, [ read, scope ] );

	/*
	 * A row is updated in place rather than by reading the list again: the
	 * reader may be several pages in. A row that was waiting and is not any
	 * more is one fewer in the count, counted here rather than asked for.
	 */
	const onChanged = ( updated, was ) => {
		setList( ( old ) => ( old ? { ...old, proposals: old.proposals.map( ( row ) => ( row.id === updated.id ? updated : row ) ) } : old ) );

		if ( 'proposed' === was ) {
			setCounted( ( count ) => Math.max( 0, count - 1 ) );
		}
	};

	const rows = ( list && list.proposals ) || [];
	/*
	 * One clock for the whole list. `drawnAt` is what the rows were last drawn
	 * with, so the decision to keep ticking is made against what the reader
	 * sees rather than the machine clock.
	 */
	const drawnAt = useRef( -Infinity );
	const counting = rows.some(
		( row ) => ( 'proposed' === row.status || 'allowed' === row.status ) && !! row.expires_at && Date.parse( row.expires_at ) > drawnAt.current
	);
	const now = useNow( counting ) + skew;

	drawnAt.current = now;

	/*
	 * The count follows the rows wherever the page holds all of them, and the
	 * site's own number only while it does not: a deadline passes on this
	 * screen's clock without anything being read, and the row says so at once.
	 */
	const held = rows.filter( ( row ) => 'proposed' === currentStatus( row, now ) ).length;
	const waiting = list && ! list.next_cursor ? held : counted;
	// The count is the summary tile's, right above; the title says what the
	// rows are for rather than repeating it.
	const title =
		waiting > 0
			? __( 'Waiting for your approval', 'bettershield' )
			: // Nothing waiting is said once, by the Waiting tab's count and its
			  // empty line; the title said it a third time (#2605).
			  __( 'Requests', 'bettershield' );

	return (
		<Card aria-labelledby="bs-ds-requests-title">
			<CardHead icon="inbox" title={ title } id="bs-ds-requests-title" />
			{ access.write_enabled ? (
				<p className="bs-ds-requests__intro">
					{ __(
						'Nothing here has been applied. Approving one gives you a one-time code to paste back to your assistant.',
						'bettershield'
					) }
				</p>
			) : null }

			{ ! access.write_enabled ? (
				<div className="bs-ds-requests__notes">
					<Alert
						layout="default"
						tone="info"
						desc={ __( 'Assistants can’t make fixes until “Let AI assistants fix things” is on.', 'bettershield' ) }
						actions={
							<Button type="secondary" size="sm" href={ tabUrl( 'bettershield-agents', 'permissions' ) }>
								{ __( 'Open Permissions', 'bettershield' ) }
							</Button>
						}
					/>
				</div>
			) : (
				<>
					{ /* Which requests the list shows is the one choice that
					     applies to all of it, so it sits above the rows. */ }
					<Tabs
						id={ TABS_ID }
						label={ __( 'Requests', 'bettershield' ) }
						selected={ scope }
						onSelect={ setScope }
						tabs={ [
							{ key: WAITING, label: __( 'Waiting', 'bettershield' ), count: waiting },
							{ key: EVERY, label: __( 'All', 'bettershield' ) },
						] }
					/>
					<div { ...panelProps( TABS_ID, scope ) }>
						{ access.sudo_required || ! access.capability_granted || 'error' === state ? (
							<div className="bs-ds-requests__notes">
								{ access.sudo_required ? <Alert layout="banner" tone="neutral" icon="lock" desc={ __( 'Approving a change asks for your password.', 'bettershield' ) } /> : null }
								{ ! access.capability_granted ? (
									<Alert
										layout="banner"
										tone="warning"
										desc={ __(
											'You can see suggested fixes but not approve them. Ask an administrator.',
											'bettershield'
										) }
									/>
								) : null }
								{ 'error' === state ? <Alert layout="banner" tone="error" desc={ error || __( 'This list could not be read just now.', 'bettershield' ) } /> : null }
							</div>
						) : null }

						{ /* The first page, on its way: its rows held in place.
						     A later read keeps the rows it has on screen. */ }
						{ 'loading' === state && ! list ? <RowsBone /> : null }

						{ rows.length ? (
							<Table
								label={ __( 'Requests', 'bettershield' ) }
								columns={ [
									{ key: 'change', label: __( 'Change', 'bettershield' ) },
									{ key: 'status', label: __( 'Status', 'bettershield' ), width: '120px' },
									{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
								] }
							>
								{ rows.map( ( proposal ) => (
									<Proposal
										key={ proposal.id }
										proposal={ proposal }
										now={ now }
										capability={ access.capability_granted }
										sudoRequired={ access.sudo_required }
										passwordReason={ access.password_reason }
										onChanged={ onChanged }
									/>
								) ) }
								{ list && list.next_cursor ? (
									<WholeRow kind="foot">
										<Button type="secondary" size="sm" isBusy={ more } disabled={ more } onClick={ () => read( scope, list.next_cursor ) }>
											{ __( 'Load More', 'bettershield' ) }
										</Button>
									</WholeRow>
								) : null }
							</Table>
						) : null }

						{ 'ready' === state && list && ! rows.length ? (
							<EmptyState>
								{ WAITING === scope ? __( 'Nothing is waiting for your approval.', 'bettershield' ) : __( 'No assistant has suggested anything on this site.', 'bettershield' ) }
							</EmptyState>
						) : null }
					</div>
				</>
			) }
		</Card>
	);
}

/** The screen standing in for itself while the agent payload is read. */
function RequestsBone() {
	return (
		<Skeleton label={ __( 'Loading the requests…', 'bettershield' ) }>
			<AgentStripBone />
			<CardBone rows={ [ '40%', '55%' ] } />
		</Skeleton>
	);
}

export default function Requests() {
	const { resource, reload } = useResource( 'agentSurface' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <RequestsBone /> }>
			{ ( data ) => (
				<>
					<AgentStrip surface={ data } />
					<RequestsCard surface={ data } />
				</>
			) }
		</Resource>
	);
}
