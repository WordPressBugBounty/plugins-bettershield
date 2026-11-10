/**
 * Fix for "Scheduled work has stopped running" (#2209).
 *
 * Try scheduled work now asks the site to run its own schedule, without
 * running anything in this request, and watches the stored schedule for a
 * minute to say whether it caught up. Where it stays stalled: whether
 * WordPress's own trigger is off, and the system cron line a host runs
 * every five minutes. Check again reads the schedule afresh.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

const PATH = '/bettershield/v1/findings/cron_schedule_stalled/schedule';

/** How often, and how many times, the schedule is read after Try now. */
const POLL_MS = 5000;
const POLLS = 12;

/** What Try now's answer means, in words. */
const RESULTS = {
	on_time: () => __( 'Nothing is overdue now.', 'bettershield' ),
	unsupported: () => __( 'Your host runs background jobs for this site, so they can’t be started from here.', 'bettershield' ),
	refused: () => __( 'WordPress didn’t start the jobs. They may already be running.', 'bettershield' ),
};

/**
 * How many tasks are overdue, in words.
 *
 * @param {number} count How many.
 * @return {string} The words.
 */
function overdueWords( count ) {
	return count
		? sprintf(
				/* translators: %d: how many background jobs are overdue. */
				_n( '%d background job is overdue.', '%d background jobs are overdue.', count, 'bettershield' ),
				count
		  )
		: __( 'No background job is overdue.', 'bettershield' );
}

export default function ScheduledWork() {
	const { trySchedule, load, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( '' );
	const [ watching, setWatching ] = useState( false );
	const [ checking, setChecking ] = useState( false );
	const timer = useRef( null );
	const alive = useRef( true );

	const read = () => apiFetch( { path: PATH } );

	useEffect( () => {
		read().then(
			( answer ) => alive.current && setState( answer ),
			() => alive.current && setUnread( true )
		);

		return () => {
			alive.current = false;
			window.clearTimeout( timer.current );
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The schedule could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the schedule…', 'bettershield' ) }</p>;
	}

	const say = ( words ) => {
		setSaid( words );
		announce( words );
	};

	// Read the stored schedule a few times while the spawned run works.
	const watch = ( before, left ) => {
		timer.current = window.setTimeout( () => {
			read().then(
				( answer ) => {
					if ( ! alive.current ) {
						return;
					}

					setState( answer );

					if ( answer.overdue < before || 0 === answer.overdue ) {
						setWatching( false );
						load( 'findings', { force: true } );
						say(
							sprintf(
								/* translators: 1: how many tasks were overdue; 2: how many are now. */
								__( 'Background jobs ran. Overdue: %1$d before, %2$d now.', 'bettershield' ),
								before,
								answer.overdue
							)
						);
					} else if ( left > 1 ) {
						watch( before, left - 1 );
					} else {
						setWatching( false );
						say( __( 'Still overdue after a minute. Ask your host to run the jobs on a timer, as shown below.', 'bettershield' ) );
					}
				},
				() => alive.current && setWatching( false )
			);
		}, POLL_MS );
	};

	const tryNow = () =>
		trySchedule( ( answer ) => {
			if ( ! answer ) {
				return;
			}

			setState( answer.state );

			// Asked just now, or by this dashboard within five minutes (its
			// requests ask too): either way there is a run to watch for.
			if ( 'asked' === answer.result || 'paced' === answer.result ) {
				setWatching( true );
				say(
					'asked' === answer.result
						? __( 'The site was asked to run its schedule. Watching for it to catch up…', 'bettershield' )
						: __( 'The site was asked to run its schedule in the last five minutes, so it is not asked again. Watching for it to catch up…', 'bettershield' )
				);
				watch( answer.state.overdue, POLLS );
			} else {
				say( ( RESULTS[ answer.result ] || RESULTS.refused )() );
			}
		} );

	const checkAgain = () => {
		setChecking( true );
		read()
			.then( ( answer ) => {
				if ( alive.current ) {
					setState( answer );
					load( 'findings', { force: true } );
					say( overdueWords( answer.overdue ) );
				}
			} )
			.finally( () => alive.current && setChecking( false ) );
	};

	const running = isWorking( busy, 'schedule-run' ) || watching;

	return (
		<>
			<p className="bs-ds-fix__text">{ overdueWords( state.overdue ) }</p>
			<div className="bs-ds-fix__actions">
				<Button type="primary" size="sm" isBusy={ running } disabled={ running } onClick={ tryNow }>
					{ __( 'Run Background Jobs Now', 'bettershield' ) }
				</Button>
				<Button type="secondary" size="sm" isBusy={ checking } disabled={ checking } onClick={ checkAgain }>
					{ __( 'Check Again', 'bettershield' ) }
				</Button>
			</div>
			{ said ? (
				<p className="bs-ds-fix__note" role="status">
					{ said }
				</p>
			) : null }
			<p className="bs-ds-fix__text">
				{ state.disabled
					? __( 'WordPress’s own trigger is off on this site (DISABLE_WP_CRON), so the host has to run the schedule. Ask them to run this every five minutes:', 'bettershield' )
					: __( 'WordPress only runs background jobs when someone visits, so quiet sites fall behind. Ask your host to run this every five minutes:', 'bettershield' ) }
			</p>
			<CopyField label={ __( 'Command for your host', 'bettershield' ) } value={ state.command } copyLabel={ __( 'Copy Line', 'bettershield' ) } />
			{ ! state.exact ? <p className="bs-ds-fix__note">{ __( 'Your host will replace /path/to/php with the right path.', 'bettershield' ) }</p> : null }
			<CopyField label={ __( 'Or this web address', 'bettershield' ) } value={ state.url_command } copyLabel={ __( 'Copy Line', 'bettershield' ) } />
			<p className="bs-ds-fix__note">{ __( 'Nothing here edits the server’s schedule. Running both is fine: WordPress runs each task once.', 'bettershield' ) }</p>
		</>
	);
}

ScheduledWork.kind = 'acts';
