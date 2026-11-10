/**
 * Previous values and reversible responses: the choice to keep what a
 * supported setting, role, plugin or new administrator was before it changed,
 * the changes captured since, and the review of each one.
 *
 * A card closed behind its header, as the disclosure it replaces was closed:
 * it is opened for an investigation rather than on every visit. A review
 * opens in place, under the row it belongs to, rather than over the page.
 */

import './ObservedChanges.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { useStore } from '../../store';
import { capabilityDiff, describeValue, entryLine, manualGuidance, phaseNote, reviewLabel } from '../data/observed';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Field from '../ui/Field';
import FixUndos from './FixUndos';
import { useFocusAfter } from '../ui/focus';
import Icon from '../ui/Icon';
import { Saved } from '../ui/Setting';
import Skeleton, { Bone } from '../ui/Skeleton';
import Table, { Cell, Row } from '../ui/Table';

const TITLE_ID = 'bs-ds-observed-title';
const BODY_ID = 'bs-ds-observed-body';

/**
 * The recorded change before it has been read: its name, and the three values
 * under their labels, each in the block it will be printed in.
 */
function ReviewBone() {
	return (
		<Skeleton label={ __( 'Loading the recorded change…', 'bettershield' ) }>
			<Bone kind="title" w="12em" />
			{ [ '12em', '11em', '7em' ].map( ( width ) => (
				<span key={ width } className="bs-ds-review__bonevalue">
					<Bone w={ width } />
					<span className="bs-ds-review__bonebox">
						<Bone w="60%" />
					</span>
				</span>
			) ) }
			<Bone w="100%" />
			<Bone kind="control" w="128px" />
		</Skeleton>
	);
}

/**
 * What the card holds before its read has landed: the choice, the line about
 * how much of it is used, and the save.
 */
function CaptureBone() {
	return (
		<Skeleton label={ __( 'Loading the capture setting…', 'bettershield' ) }>
			<Bone kind="title" w="16em" />
			<Bone w="100%" />
			<Bone w="38%" />
			<Bone kind="control" w="178px" />
		</Skeleton>
	);
}

/**
 * The review itself, once read: what changed, before and after and now, what
 * the response does where it can run here, and the one action it allows.
 *
 * @param {Object}   props
 * @param {Object}   props.view  The recorded change, as the review read it.
 * @param {*}        props.busy  The store's action in flight.
 * @param {Function} props.onAct Runs the response: 'apply' or 'undo'.
 * @param {number}   props.level The heading level of the change's name.
 */
function ReviewPanel( { view, busy, onAct, level } ) {
	const undo = view.phase === 'applied';
	const label = reviewLabel( view );
	const diff = 'role' === view.kind ? capabilityDiff( view.before, view.after ) : null;
	// What the response does, said only where it can run or has run and can
	// be undone. A refused one described an action that could not be taken,
	// right above the steps to take by hand.
	const responds = ! view.refusal || 'ready' !== view.phase;
	const Heading = `h${ Math.min( Math.max( level, 2 ), 6 ) }`;

	return (
		<div className="bs-ds-review__panel">
			<Heading className="bs-ds-review__name">{ String( label ) }</Heading>
			{ 'account' === view.kind ? (
				<p>
					{ responds
						? __(
								'Suspending blocks this admin from signing in or using app passwords. Nothing is deleted, and you can undo it. It pauses in safe mode or if no other admin remains.',
								'bettershield'
						  )
						: __( 'A new administrator was recorded.', 'bettershield' ) }
				</p>
			) : (
				<>
					{ /* A role's maps run to eighty lines each; what changed leads. */ }
					{ diff && ( diff.added.length || diff.removed.length ) ? (
						<ul className="bs-ds-review__diff">
							{ diff.added.map( ( cap ) => (
								<li key={ `+${ cap }` }>
									{ sprintf(
										/* translators: %s: a capability. */
										__( 'Can now: %s', 'bettershield' ),
										cap
									) }
								</li>
							) ) }
							{ diff.removed.map( ( cap ) => (
								<li key={ `-${ cap }` }>
									{ sprintf(
										/* translators: %s: a capability. */
										__( 'Can no longer: %s', 'bettershield' ),
										cap
									) }
								</li>
							) ) }
						</ul>
					) : null }
					<dl className="bs-ds-review__values">
						<div>
							<dt>{ __( 'Old value', 'bettershield' ) }</dt>
							<dd>
								<pre>{ describeValue( view.before, view.target ) }</pre>
							</dd>
						</div>
						<div>
							<dt>{ __( 'New value', 'bettershield' ) }</dt>
							<dd>
								<pre>{ describeValue( view.after, view.target ) }</pre>
							</dd>
						</div>
						<div>
							<dt>{ __( 'Current value', 'bettershield' ) }</dt>
							<dd>
								<pre>{ describeValue( view.current, view.target ) }</pre>
							</dd>
						</div>
					</dl>
					{ 'plugin' === view.kind && responds ? (
						<p>
							{ __(
								'Restoring turns the plugin off, but doesn’t undo what it already changed. Undo turns it back on.',
								'bettershield'
							) }
						</p>
					) : null }
				</>
			) }
			<p>
				{ __(
					'A change listed here isn’t necessarily harmful. Some changes, like later edits or protected accounts, can’t be restored here.',
					'bettershield'
				) }
			</p>
			{ 'ready' !== view.phase ? <p role="status">{ phaseNote( view.phase ) }</p> : null }
			{ view.refusal ? <p>{ view.refusal }</p> : null }
			{ view.refusal && 'ready' === view.phase ? <p>{ manualGuidance( view ) }</p> : null }
			{ undo || 'ready' === view.phase ? (
				<div className="bs-ds-review__actions">
					<Button
						type="primary"
						size="sm"
						disabled={ !! busy || !! view.refusal }
						onClick={ () => onAct( undo ? 'undo' : 'apply' ) }
					>
						{ undo
							? 'account' === view.kind
								? __( 'Lift Suspension', 'bettershield' )
								: __( 'Undo the Restore', 'bettershield' )
							: 'account' === view.kind
							? __( 'Suspend This Account', 'bettershield' )
							: __( 'Restore Old Value', 'bettershield' ) }
					</Button>
				</div>
			) : null }
		</div>
	);
}

/**
 * One recorded change, read and reviewed where it was asked for. An entry of
 * a supported kind recorded before capture was on has no token, and says what
 * to check by hand instead.
 *
 * @param {Object}   props
 * @param {string}   props.token   The change's token, or ''.
 * @param {Function} props.onClose Closes the review: Escape, from anywhere inside it.
 * @param {string}   props.id      The review's id, for the control that opened it.
 * @param {number}   props.level   The heading level of the change's name.
 */
export function ChangeReview( { token, onClose, id, level = 3 } ) {
	const { restoreObservedChange, busy } = useStore();
	const [ view, setView ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ attempt, retry ] = useState( 0 );

	useEffect( () => {
		let alive = true;

		if ( token ) {
			setView( null );
			setError( '' );
			apiFetch( { path: `/bettershield/v1/observed-changes/${ token }` } ).then(
				( result ) => {
					if ( alive ) {
						setView( result );
					}
				},
				( e ) => {
					if ( alive ) {
						setError( e.message );
					}
				}
			);
		}

		return () => {
			alive = false;
		};
	}, [ token, attempt ] );

	const onKeyDown = ( event ) => {
		if ( 'Escape' === event.key && onClose ) {
			event.stopPropagation();
			onClose();
		}
	};

	return (
		// The Escape handler catches keys from the buttons inside; the review
		// itself takes no focus of its own.
		// eslint-disable-next-line jsx-a11y/no-static-element-interactions
		<div className="bs-ds-review" id={ id } onKeyDown={ onKeyDown }>
			<p className="bs-ds-review__title">{ __( 'Review recorded change', 'bettershield' ) }</p>
			{ ! token ? (
				<p>
					{ __(
						'No old value was saved. Check the related WordPress screen and who made the change. Don’t delete an account just because it’s listed.',
						'bettershield'
					) }
				</p>
			) : null }
			{ token && ! view && ! error ? <ReviewBone /> : null }
			{ error ? (
				<div role="alert">
					<Alert
						layout="default"
						tone="error"
						desc={ error }
						actions={
							<Button type="secondary" size="sm" onClick={ () => retry( ( n ) => n + 1 ) }>
								{ __( 'Try Again', 'bettershield' ) }
							</Button>
						}
					/>
				</div>
			) : null }
			{ view ? (
				<ReviewPanel view={ view } busy={ busy } level={ level } onAct={ ( action ) => restoreObservedChange( token, action, view.revision, setView ) } />
			) : null }
		</div>
	);
}

/**
 * A list of changes to review: a row each, its review opening under it.
 *
 * @param {Object}   props
 * @param {string}   props.name     The list's name, for its heading and table.
 * @param {string}   props.list     Which list, so a change in both opens once.
 * @param {Array}    props.rows     [{ token, line, note, plain }], plain where there is nothing to review here.
 * @param {?Object}  props.review   The review open: { list, token }.
 * @param {Function} props.onReview Opens a row's review.
 * @param {Function} props.onClose  Closes the one open.
 * @param {Object}   props.lastRef  Takes the last row's control, where the keyboard goes when Load older changes goes.
 */
function Changes( { name, about = '', list, rows, review, onReview, onClose, lastRef = null } ) {
	// Each row's control, for the keyboard to go back to when its review closes.
	const controls = useRef( {} );

	return (
		<>
			<h3 className="bs-ds-observed__head">{ name }</h3>
			{ about ? <p>{ about }</p> : null }
			<Table label={ name } head={ false } columns={ [ { key: 'change', label: name } ] }>
				{ rows.map( ( row ) => {
					const open = Boolean( review ) && list === review.list && row.token === review.token;
					const panel = `bs-ds-review-${ list }-${ row.token }`;

					return [
						<Row key={ row.token } open={ open }>
							<Cell>
								{ row.plain ? (
									<span>{ row.line }</span>
								) : (
									<Button
										ref={ ( node ) => {
											controls.current[ row.token ] = node;
											if ( lastRef && row === rows[ rows.length - 1 ] ) {
												lastRef.current = node;
											}
										} }
										type="link"
										size="sm"
										className="bs-ds-observed__entry"
										aria-expanded={ open }
										aria-controls={ open ? panel : undefined }
										onClick={ () => ( open ? onClose() : onReview( list, row.token ) ) }
									>
										{ row.line }
									</Button>
								) }
								{ row.note ? <span className="bs-ds-observed__note">{ row.note }</span> : null }
								{ row.action || null }
							</Cell>
						</Row>,
						open ? (
							<div key={ `${ row.token }-review` } className="bs-ds-observed__under" role="row">
								<div role="cell">
									<ChangeReview
										id={ panel }
										token={ row.token }
										level={ 4 }
										onClose={ () => {
											onClose();
											// Escape closes it from inside; the keyboard goes back
											// to the line that opened it.
											if ( controls.current[ row.token ] ) {
												controls.current[ row.token ].focus();
											}
										} }
									/>
								</div>
							</div>
						) : null,
					];
				} ) }
			</Table>
		</>
	);
}

export default function ObservedChanges() {
	const { setObservedCapture, letBackIn, busy } = useStore();
	const [ data, setData ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ enabled, setEnabled ] = useState( false );
	// A refused save, said under its button rather than in the page's banner.
	const [ captureError, setCaptureError ] = useState( '' );
	// The review open, and the list it was opened from: a change can be in
	// both, and opens once.
	const [ review, setReview ] = useState( null );
	const [ moreBusy, setMoreBusy ] = useState( false );
	// Load older changes is held while its page loads and goes once the last
	// page is in: focus comes back to it, or to the last change listed
	// (#2028).
	const more = useRef( null );
	const lastChange = useRef( null );

	useFocusAfter( moreBusy, more, lastChange );
	// An older page that could not be read, said beside the button that asks
	// for it again. On the first read's line, its Try again re-read the first
	// page instead and dropped the pages already loaded.
	const [ moreError, setMoreError ] = useState( '' );
	const [ open, setOpen ] = useState( false );
	const loadMore = () => {
		setMoreBusy( true );
		setMoreError( '' );
		apiFetch( { path: `/bettershield/v1/observed-changes?cursor=${ data.next_cursor }` } )
			.then(
				( result ) => setData( ( old ) => ( { ...result, recent: [ ...old.recent, ...result.recent ] } ) ),
				( e ) => setMoreError( e && e.message ? e.message : __( 'The older entries could not be read. Try again.', 'bettershield' ) )
			)
			.finally( () => setMoreBusy( false ) );
	};
	const [ attempt, retry ] = useState( 0 );

	useEffect( () => {
		let alive = true;

		setError( '' );
		apiFetch( { path: '/bettershield/v1/observed-changes' } ).then(
			( result ) => {
				if ( alive ) {
					setMoreError( '' );
					setData( result );
					setEnabled( result.enabled );
				}
			},
			( e ) => {
				if ( alive ) {
					setError( e.message );
				}
			}
		);

		return () => {
			alive = false;
		};
	}, [ attempt ] );

	/*
	 * A review that closes reads the list again, because what it did moved
	 * the change's phase: as far as it was loaded, following the cursor, and
	 * in place. Re-reading the first page replaced the list, so the older
	 * pages already loaded were gone and an entry from one of them, with the
	 * keyboard on it, went too. Rows keep their keys across the read, so the
	 * entry the keyboard is on stays where it is.
	 */
	const close = () => {
		setReview( null );

		const loaded = data && Array.isArray( data.recent ) ? data.recent.length : 0;
		const read = ( path, gathered ) =>
			apiFetch( { path } ).then( ( result ) => {
				const recent = [ ...gathered, ...( result.recent || [] ) ];

				return recent.length < loaded && result.next_cursor
					? read( `/bettershield/v1/observed-changes?cursor=${ result.next_cursor }`, recent ).then( ( last ) => ( { ...result, recent: last.recent, next_cursor: last.next_cursor } ) )
					: { ...result, recent };
			} );

		read( '/bettershield/v1/observed-changes', [] ).then(
			( result ) => {
				setData( result );
				setEnabled( result.enabled );
			},
			// The list stays as it was; the next close or a reload reads it.
			() => null
		);
	};
	const reviewOf = ( list, token ) => setReview( { list, token } );
	const saveCapture = () => {
		setCaptureError( '' );
		setObservedCapture(
			enabled,
			() => {
				// Saved now, so there is nothing left to save while the card reads again.
				setData( ( current ) => ( { ...current, enabled } ) );
				retry( ( n ) => n + 1 );
			},
			( refusal ) => {
				// Canceled at the password prompt: nothing was asked of the server.
				if ( refusal ) {
					setCaptureError( refusal.message || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );
				}

				return true;
			}
		);
	};

	return (
		<Card className="bs-ds-observed" aria-labelledby={ TITLE_ID }>
			<CardHead icon="history" title={ __( 'Undo important setting changes', 'bettershield' ) } id={ TITLE_ID } auto>
				<Button
					type="ghost"
					size="sm"
					iconOnly
					// Its own name, the card's title as what it opens (#2471):
					// named by the title alone, it read as a second heading.
					aria-label={ __( 'Show details', 'bettershield' ) }
					aria-describedby={ TITLE_ID }
					aria-expanded={ open }
					aria-controls={ open ? BODY_ID : undefined }
					onClick={ () => setOpen( ( was ) => ! was ) }
				>
					<Icon name={ open ? 'chevron-up' : 'chevron-down' } size={ 14 } tone="3" />
				</Button>
			</CardHead>
			{ open ? (
				<div className="bs-ds-observed__body" id={ BODY_ID }>
					<p className="bs-ds-observed__intro">
						{ __( 'Saves the old value when key settings, roles, plugins or admin accounts change, so you can put them back. Nothing changes automatically.', 'bettershield' ) }{ ' ' }
						{ __( 'Saved values can include admin email addresses and are kept after the log entry ends.', 'bettershield' ) }
					</p>
					{ error ? (
						<div className="bs-ds-observed__part" role="alert">
							<Alert
								layout="default"
								tone="error"
								desc={ error }
								actions={
									<Button type="secondary" size="sm" onClick={ () => retry( ( n ) => n + 1 ) }>
										{ __( 'Try Again', 'bettershield' ) }
									</Button>
								}
							/>
						</div>
					) : null }
					{ ! data && ! error ? (
						<div className="bs-ds-observed__part">
							<CaptureBone />
						</div>
					) : null }
					{ data ? (
						<>
							<div className="bs-ds-observed__part bs-ds-observed__capture">
								<Field
									kind="check"
									label={ __( 'Save old values so I can undo changes', 'bettershield' ) }
									checked={ enabled }
									disabled={ !! busy || ! data.available || ( ! enabled && data.used >= 1000 ) }
									onChange={ setEnabled }
								/>
								{ ! data.available ? <p>{ __( 'Available once BetterShield finishes updating its database. Reload this page in a minute.', 'bettershield' ) }</p> : null }
								<p className="bs-ds-observed__meta">
									{ sprintf(
										/* translators: 1: how many capture slots are used, 2: how many capture slots there are. */
										__(
											'%1$s of %2$s saved changes used. Busy moments and checkout pages aren’t saved.',
											'bettershield'
										),
										Number( data.used || 0 ).toLocaleString(),
										( 1000 ).toLocaleString()
									) }
								</p>
								<div className="bs-ds-observed__save">
									<Button
										type="secondary"
										size="sm"
										disabled={ !! busy || ! data.available || enabled === data.enabled }
										onClick={ saveCapture }
									>
										{ __( 'Save', 'bettershield' ) }
									</Button>
									<Saved forKey="observed-capture" />
								</div>
								{ captureError ? <Alert layout="default" tone="error" live="alert" desc={ captureError } /> : null }
							</div>
							<FixUndos rows={ data.fixes } onDone={ () => retry( ( n ) => n + 1 ) } />
							{ data.suspensions?.length > 0 ? (
								<Changes
									name={ __( 'Account suspensions', 'bettershield' ) }
									about={ __( 'Suspended accounts can’t sign in until you let them back in.', 'bettershield' ) }
									list="suspensions"
									rows={ data.suspensions.map( ( r ) => ( {
										token: r.token,
										// One another feature made is lifted there, not reviewed
										// here, and the row says so in place of a review.
										line: r.elsewhere
											? r.name ||
											  sprintf(
													/* translators: %d: an account's ID. */
													__( 'Account #%d', 'bettershield' ),
													r.target
											  )
											: sprintf(
													/* translators: %s: an account's username, or "account #12" where it has none. */
													__( 'Review %s', 'bettershield' ),
													r.name ||
														sprintf(
															/* translators: %d: an account's ID. */
															__( 'account #%d', 'bettershield' ),
															r.target
														)
											  ),
										plain: Boolean( r.elsewhere ),
										// One another feature made, with its own way back named here.
										action: r.lift ? (
											<Button
												type="secondary"
												size="sm"
												disabled={ !! busy }
												aria-label={ sprintf(
													/* translators: %s: an account's username, or "account #12" where it has none. */
													__( 'Let %s back in', 'bettershield' ),
													r.name ||
														sprintf(
															/* translators: %d: an account's ID. */
															__( 'account #%d', 'bettershield' ),
															r.target
														)
												) }
												onClick={ () => letBackIn( r.token, ( answer ) => answer && retry( ( n ) => n + 1 ), r.lift ) }
											>
												{ __( 'Let Back In', 'bettershield' ) }
											</Button>
										) : null,
										note: [ r.paused ? __( 'Suspension is on hold while recovery mode or another sign-in protection is active.', 'bettershield' ) : '', r.elsewhere || '' ].filter( Boolean ).join( ' ' ),
									} ) ) }
									review={ review }
									onReview={ reviewOf }
									onClose={ close }
								/>
							) : null }
							{ data.recent?.length > 0 ? (
								<Changes
									name={ __( 'Saved changes', 'bettershield' ) }
									list="recent"
									rows={ data.recent.map( ( r ) => ( { token: r.token, line: entryLine( r ), note: '' } ) ) }
									review={ review }
									onReview={ reviewOf }
									onClose={ close }
									lastRef={ lastChange }
								/>
							) : null }
							{ data.next_cursor ? (
								<div className="bs-ds-observed__more">
									{ moreError ? (
										<p className="bs-ds-observed__more-error" role="alert">
											{ moreError }
										</p>
									) : null }
									<Button ref={ more } type="secondary" size="sm" disabled={ moreBusy } accessibleWhenDisabled onClick={ loadMore }>
										{ __( 'Load Older Changes', 'bettershield' ) }
									</Button>
								</div>
							) : null }
						</>
					) : null }
				</div>
			) : null }
		</Card>
	);
}

/** The card's shape while the log it sits over is read: closed, one header. */
export function ObservedChangesBone() {
	return (
		<div className="bs-ds-card">
			<div className="bs-ds-card__head">
				<span className="bs-ds-bone bs-ds-bone--tile" />
				<Bone kind="title" w="19em" />
			</div>
		</div>
	);
}
