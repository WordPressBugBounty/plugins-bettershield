/**
 * Fix for "Something is scheduled that no code answers" (#1952).
 *
 * Each hook the finding names, ticked, so a hook the owner recognizes can be
 * left out; Remove takes every scheduled run of the ticked ones off the
 * schedule, kept first, and Undo puts them back on their old schedule. The
 * panel holds the Undo until the owner checks again, because the check that
 * closes the finding takes its row off the screen.
 */

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import { focusIfLost } from '../../ui/focus';
import Button from '../../ui/Button';
import Field from '../../ui/Field';
import { useAuditWhenGone } from './useFixState';

export default function UnansweredEvents( { finding } ) {
	const { removeCronEvents, undoCronRemoval, busy } = useStore();
	const events = ( finding.evidence && finding.evidence.events ) || [];
	const [ chosen, setChosen ] = useState( () => events.map( ( event ) => event.hook ) );
	const [ removed, setRemoved ] = useState( null );
	const [ said, setSaid ] = useState( '' );
	const working = isWorking( busy, 'cron-remove' ) || isWorking( busy, 'cron-undo' );
	// The control pressed goes away with each answer: Remove for Undo, and
	// Undo for the list. Focus follows to what took its place.
	const undoButton = useRef( null );
	const status = useRef( null );

	// Nothing left to remove: the jobs went some other way, and the audit
	// closes the finding on its own.
	useAuditWhenGone( ! events.length && ! removed );

	useEffect( () => {
		if ( ! working ) {
			focusIfLost( removed ? undoButton.current : status.current );
		}
	}, [ removed, said, working ] );

	const say = ( words ) => {
		setSaid( words );
		announce( words );
	};

	const toggle = ( hook, on ) => setChosen( ( was ) => ( on ? [ ...was, hook ] : was.filter( ( one ) => one !== hook ) ) );

	const remove = () =>
		removeCronEvents( chosen, ( answer ) => {
			if ( answer && answer.undo ) {
				setRemoved( answer );
				say(
					sprintf(
						/* translators: %s: the names of scheduled hooks. */
						__( 'Removed: %s. Undo puts them back on their old schedule.', 'bettershield' ),
						answer.removed.join( ', ' )
					)
				);
			}
		} );

	const undo = () =>
		undoCronRemoval( removed.undo, ( answer ) => {
			if ( answer ) {
				setRemoved( null );
				say( __( 'The events are scheduled again, as they were.', 'bettershield' ) );
			}
		} );

	if ( removed ) {
		return (
			<>
				{ said ? (
					<p className="bs-ds-fix__text" role="status">
						{ said }
					</p>
				) : null }
				<div className="bs-ds-fix__actions">
					<Button ref={ undoButton } type="secondary" size="sm" isBusy={ isWorking( busy, 'cron-undo' ) } disabled={ working } onClick={ undo }>
						{ __( 'Undo', 'bettershield' ) }
					</Button>
				</div>
			</>
		);
	}

	if ( ! events.length ) {
		return <p className="bs-ds-fix__text">{ __( 'There are no jobs to remove now. Updating this finding…', 'bettershield' ) }</p>;
	}

	return (
		<>
			<p className="bs-ds-fix__text">
				{ __( 'Untick any you recognize. Some working plugins show up here by mistake; Undo puts them back.', 'bettershield' ) }
			</p>
			<ul className="bs-ds-fix__list">
				{ events.map( ( event ) => (
					<li key={ event.hook }>
						<Field kind="check" label={ event.hook } checked={ chosen.includes( event.hook ) } disabled={ working } onChange={ ( on ) => toggle( event.hook, on ) } />
					</li>
				) ) }
			</ul>
			<div className="bs-ds-fix__actions">
				<Button type="primary" size="sm" isBusy={ isWorking( busy, 'cron-remove' ) } disabled={ working || ! chosen.length } onClick={ remove }>
					{ sprintf(
						/* translators: %d: how many scheduled hooks are ticked. */
						_n( 'Remove %d Background Job', 'Remove %d Background Jobs', chosen.length, 'bettershield' ),
						chosen.length
					) }
				</Button>
			</div>
			{ said ? (
				<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
					{ said }
				</p>
			) : null }
		</>
	);
}

UnansweredEvents.kind = 'acts';
