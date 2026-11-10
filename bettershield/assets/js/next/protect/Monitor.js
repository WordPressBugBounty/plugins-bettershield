/**
 * What "Monitor first" opens on a hardening row: a window in which the rule is
 * watched against real requests without changing their outcome, what it
 * matched, and enforcing the settings that were watched.
 *
 * The row draws the control and the panel this sits in; this is the reading
 * inside it.
 */

import './Monitor.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import Button from '../ui/Button';
import Field, { FieldRow } from '../ui/Field';

/**
 * Whether a row offers to be watched before it is enforced.
 *
 * The row draws the control and this draws what it opens, so the two have to
 * agree on when there is anything to open.
 *
 * @param {Object} item A hardening item.
 * @return {boolean} Whether "Monitor first" is offered.
 */
export function hasMonitor( item ) {
	// Only where test mode can measure something, or a test is on record:
	// on every other row the button opened a note saying it could not (#2413).
	return Boolean( item.monitor ) && Boolean( item.monitor.supported || item.monitor.state ) && ! ( item.active && ! item.monitor.state );
}

/**
 * Each phase of a window, in words.
 *
 * @param {string}  phase   The window's phase.
 * @param {boolean} nothing Nothing came in while it ran: a finished test then
 *                          has nothing to review, and does not say to (#2822).
 */
function phaseWords( phase, nothing = false ) {
	if ( 'finished' === phase && nothing ) {
		return __( 'Test finished', 'bettershield' );
	}

	return {
		watching: __( 'Testing', 'bettershield' ),
		finished: __( 'Test finished — review, then turn it on', 'bettershield' ),
		applying: __( 'Apply was interrupted — inspect the current protection before retrying', 'bettershield' ),
		enforced: __( 'On', 'bettershield' ),
		undone: __( 'The enforced setting was undone', 'bettershield' ),
		review_ended: __( 'Automatic review window ended', 'bettershield' ),
		reverted: __( 'Turned off: it blocked signed-in people too often', 'bettershield' ),
		review_changed: __( 'Protection changed — automatic undo ended', 'bettershield' ),
		review_failed: __( 'Automatic undo was refused — review the current protection', 'bettershield' ),
	}[ phase ];
}

/** The window's saved settings, named as the item's own fields name them. */
function optionLabel( item, key ) {
	const field = ( item.fields || [] ).find( ( candidate ) => candidate.key === key );

	return (
		( field && field.label ) ||
		{ roles: __( 'Accounts', 'bettershield' ), mode: __( 'Scope', 'bettershield' ), slug: __( 'Sign-in address', 'bettershield' ) }[ key ] ||
		key
	);
}

function optionValues( item, key, value ) {
	const field = ( item.fields || [] ).find( ( candidate ) => candidate.key === key );
	const values = Array.isArray( value ) ? value : [ value ];

	return values
		.map( ( one ) => {
			const choice = field && field.choices ? field.choices.find( ( candidate ) => candidate.value === one ) : null;

			return choice ? choice.label : one;
		} )
		.join( ', ' );
}

/**
 * @param {Object}   props
 * @param {Object}   props.item        The hardening item.
 * @param {Object}   props.options     The values its fields hold now, which a new window watches.
 * @param {boolean}  props.invalid     A field the window needs is empty or wrong.
 * @param {Function} props.monitorItem The store's action.
 * @param {string}   props.busy        The store's busy key.
 */
export function MonitorPanel( { item, options, invalid, monitorItem, busy } ) {
	const [ seconds, setSeconds ] = useState( '86400' );
	const [ threshold, setThreshold ] = useState( '0' );
	const statusRef = useRef( null );
	const focusAfterChange = useMutationFocus( statusRef );
	// Starting a window keeps its button, so the hook gives focus back to it;
	// the status that start has just drawn is what has to be read.
	const [ statusWanted, setStatusWanted ] = useState( false );
	const change = ( data ) =>
		monitorItem(
			item.id,
			data,
			focusAfterChange( () => {
				if ( 'start' === data.action ) {
					setStatusWanted( true );
				}
			} )
		);
	const monitor = item.monitor;
	const state = monitor ? monitor.state : null;
	const working = isWorking( busy, `monitor-${ item.id }`, item.id );

	useEffect( () => {
		if ( ! statusWanted || working || ! statusRef.current ) {
			return;
		}

		statusRef.current.focus();
		setStatusWanted( false );
	}, [ statusWanted, working, state ] );

	if ( ! hasMonitor( item ) ) {
		return null;
	}

	const unknown = state && ( state.storage_failed || null === state.observed || null === state.matched );

	/*
	 * A test still running or waiting to be turned on. Once the rule is on,
	 * one that never moved past that is stale: the row said On while this
	 * still said "Testing from … Nothing has come in yet".
	 */
	const testPhase = state && ( 'watching' === state.phase || 'finished' === state.phase );
	const stale = testPhase && item.active;

	if ( ! monitor.supported ) {
		return (
			<div className="bs-ds-monitor">
				<p>
					{ 'csp_report_only' === item.id
						? __( 'Use this item’s report-only policy and browser reports before enforcing.', 'bettershield' )
						: // In the owner's words (#1795): there are no "staging checks"
						  // to use, and a "shadow" is the design's word, not theirs.
						  __( 'This one can’t be measured before it’s on. Preview the change first, and use Undo if anything breaks.', 'bettershield' ) }
				</p>
			</div>
		);
	}

	return (
		<div className="bs-ds-monitor">
			<p>
				{ __(
					'Test mode records what this would block without blocking anything. Bots are counted too. No matches is a good sign, not a guarantee.',
					'bettershield'
				) }
			</p>

			{ state && ! stale ? (
				<div className="bs-ds-monitor__status" role="status" ref={ statusRef } tabIndex={ -1 }>
					<p className="bs-ds-monitor__phase">{ phaseWords( state.phase, 0 === state.observed ) }</p>
					<p>
						{ 'watching' !== state.phase
							? sprintf(
									/* translators: 1: date and time the test started, 2: date and time it ended. */
									__( 'Tested from %1$s to %2$s', 'bettershield' ),
									formatTime( state.started ),
									formatTime( state.ends )
							  )
							: sprintf(
									/* translators: 1: date and time the observation window started, 2: date and time it ends. */
									__( 'Testing from %1$s to %2$s', 'bettershield' ),
									formatTime( state.started ),
									formatTime( state.ends )
							  ) }
					</p>
					{ unknown && ! testPhase ? null : unknown ? (
						<p>{ __( 'This test’s records are incomplete or expired. Start a new test before you turn it on.', 'bettershield' ) }</p>
					) : (
						<p>
							{ sprintf(
								/* translators: 1: how many requests the test saw, 2: how many of them this rule would have blocked. */
								_n( '%1$d request seen. %2$d would have been blocked.', '%1$d requests seen. %2$d would have been blocked.', state.observed, 'bettershield' ),
								state.observed,
								state.matched
							) }
						</p>
					) }
					{ /* A finished test that saw nothing showed nothing: the next
					     step is a longer test, not turning it on (#2822). */ }
					{ testPhase && 0 === state.observed ? (
						<p>
							{ 'finished' === state.phase
								? __( 'Nothing came in, so it showed nothing. Test longer before you turn it on.', 'bettershield' )
								: __( 'Nothing has come in yet, so there is nothing to go on.', 'bettershield' ) }
						</p>
					) : null }
					<ul className="bs-ds-monitor__options">
						{ Object.entries( state.options || {} ).map( ( [ key, value ] ) => (
							<li key={ key }>
								{ optionLabel( item, key ) }: { optionValues( item, key, value ) }
							</li>
						) ) }
					</ul>
					{ state.review_blocked ? (
						<p>
							{ __(
								'Automatic undo only runs while you still have a working recovery link and protection isn’t paused.',
								'bettershield'
							) }
						</p>
					) : null }
					{ state.threshold > 0 ? (
						<p>
							{ sprintf(
								/* translators: 1: how many signed-in dashboard denials undo the rule, 2: date and time automatic undo ends, 3: how many denials are recorded so far, or "unknown". */
								_n(
									'Turns this off by itself if it blocks a signed-in person %1$d time before %2$s. So far: %3$s.',
									'Turns this off by itself if it blocks a signed-in person %1$d times before %2$s. So far: %3$s.',
									state.threshold,
									'bettershield'
								),
								state.threshold,
								formatTime( state.review_until ),
								null === state.denied ? __( 'unknown', 'bettershield' ) : String( state.denied )
							) }
						</p>
					) : null }
				</div>
			) : null }

			{ ! item.active ? (
				<>
					{ state && 'watching' === state.phase ? (
						<div className="bs-ds-monitor__actions">
							<Button type="secondary" size="sm" disabled={ working } onClick={ () => change( { action: 'stop', id: state.id } ) }>
								{ __( 'End Test Now', 'bettershield' ) }
							</Button>
						</div>
					) : null }

					{ state && 'finished' === state.phase ? (
						<div className="bs-ds-monitor__enforce">
							<p>
								{ __(
									'Turning it on uses the settings you tested. You need a working recovery method, and safe mode must be off. You can undo it.',
									'bettershield'
								) }
							</p>
							{ monitor.auto_revert_supported ? (
								<Field
									kind="select"
									width="md"
									label={ __( 'Automatic undo for the first 24 hours', 'bettershield' ) }
									value={ threshold }
									options={ [
										{ value: '0', label: __( 'I’ll undo it myself', 'bettershield' ) },
										...[ 1, 5, 10 ].map( ( n ) => ( {
											value: String( n ),
											label: sprintf(
												/* translators: %d: how many signed-in denials undo the rule. */
												_n( 'Turn off after %d blocked sign-in', 'Turn off after %d blocked sign-ins', n, 'bettershield' ),
												n
											),
										} ) ),
									] }
									onChange={ setThreshold }
								/>
							) : null }
							{ '0' !== threshold ? (
								<p className="bs-ds-monitor__caution">
									{ __(
										'A signed-in account the rule blocks can turn it off by reaching this number. Signed-out visitors cannot. Choose this only while testing.',
										'bettershield'
									) }
								</p>
							) : null }
							<div className="bs-ds-monitor__actions">
								{ /* A test that saw nothing points at a longer test, so turning it on is not the main action. */ }
								<Button
									type={ 0 === state.observed ? 'secondary' : 'primary' }
									size="sm"
									disabled={ working || unknown }
									onClick={ () => change( { action: 'enforce', id: state.id, threshold: Number( threshold ) } ) }
								>
									{ __( 'Turn It On', 'bettershield' ) }
								</Button>
							</div>
						</div>
					) : null }

					<FieldRow>
						<Field
							kind="select"
							width="md"
							label={ __( 'Test for', 'bettershield' ) }
							value={ seconds }
							options={ [
								{ value: '3600', label: __( '1 hour', 'bettershield' ) },
								{ value: '86400', label: __( '24 hours', 'bettershield' ) },
								{ value: '604800', label: __( '7 days', 'bettershield' ) },
							] }
							onChange={ setSeconds }
						/>
						<Button type="secondary" size="sm" disabled={ working || invalid } onClick={ () => change( { action: 'start', seconds: Number( seconds ), options } ) }>
							{ state ? __( 'Start a New Test', 'bettershield' ) : __( 'Start Test', 'bettershield' ) }
						</Button>
					</FieldRow>
				</>
			) : null }
		</div>
	);
}

/**
 * @param {Object}  props
 * @param {Object}  props.item    The hardening item.
 * @param {Object}  props.options The values its fields hold now.
 * @param {boolean} props.invalid A field the window needs is empty or wrong.
 */
export default function HardeningMonitor( { item, options, invalid } ) {
	const { monitorItem, busy } = useStore();

	return <MonitorPanel { ...{ item, options, invalid, monitorItem, busy } } />;
}
