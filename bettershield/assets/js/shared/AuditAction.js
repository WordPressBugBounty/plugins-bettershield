/**
 * What the bar's audit control knows and does: when the site was last read,
 * and the press that reads it again.
 */

import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useStore } from '../store';
import { announce } from '../ui/announce';

/**
 * What the audit control knows and does, for whichever bar draws it: the
 * Overview as last read, whether an audit is running, whether one just
 * finished, and the press that starts one.
 *
 * @return {{overview: Object, running: boolean, done: boolean, run: Function}} The control's state.
 */
export function useAuditRun() {
	const { resources, runAudit, busy } = useStore();
	const overview = resources.overview;
	const running = 'audit' === busy;

	/*
	 * A finished audit says so on the control that started it, for a moment,
	 * before the control goes back to offering another. On a site where
	 * nothing changed the only other sign is the timestamp beside it moving,
	 * which is easy to miss from the button the reader just watched sweep.
	 */
	const [ done, setDone ] = useState( false );

	useEffect( () => {
		if ( ! done ) {
			return undefined;
		}

		const settle = setTimeout( () => setDone( false ), 1800 );

		return () => clearTimeout( settle );
	}, [ done ] );

	/*
	 * Both ends of the run are said aloud as well as drawn: the sweep and the
	 * check mark are all the control shows, and it is disabled while it
	 * works, so a screen reader heard the press and then nothing. A failure
	 * is the notice's to say.
	 */
	const run = () => {
		// The store runs one action at a time and quietly refuses a second,
		// so with another still in flight no audit starts, and none is said.
		if ( busy ) {
			return Promise.resolve();
		}

		// No count: the last audit's was a ceiling, not this run's progress (#2294).
		announce( __( 'Auditing the site…', 'bettershield' ) );

		return runAudit().then( ( data ) => {
			if ( data ) {
				setDone( true );
				announce( __( 'Audit complete.', 'bettershield' ) );
			}
		} );
	};

	return { overview, running, done, run };
}
