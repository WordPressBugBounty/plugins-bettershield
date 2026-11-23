/**
 * Carrying the first file check and first probes on from a screen waiting for them.
 *
 * A check moves in slices, and between them it waits for the hourly task, so a
 * screen saying the score is on its way asks for the next slice when the last
 * one answers. It stops when they end or the screen closes. A slice that fails
 * is asked again a few times, further apart each time; when they keep failing
 * the progress says the check paused, and the hourly task finishes it.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';

const SLICE_GAP = 1500;

/** Waits before asking a failed slice again: about twenty seconds in all. */
const RETRY_GAPS = [ 3000, 6000, 12000 ];

/**
 * @param {?Object}  report     The payload's `first_scan`.
 * @param {Function} onFinished Called once the check has finished.
 * @return {?Object} The check's progress, once a slice has reported it.
 */
export function useFirstScan( report, onFinished ) {
	const [ progress, setProgress ] = useState( null );
	const finished = useRef( onFinished );
	const drive = Boolean( report && report.drive );

	finished.current = onFinished;

	useEffect( () => {
		if ( ! drive ) {
			return undefined;
		}

		let stopped = false;
		let timer = 0;
		let failed = 0;

		const slice = () => {
			apiFetch( { path: '/bettershield/v1/integrity/scan', method: 'POST' } )
				.then( ( answer ) => {
					if ( stopped ) {
						return;
					}

					failed = 0;

					if ( answer && ( answer.running || answer.first_scan_running ) ) {
						setProgress( answer.progress || null );
						timer = window.setTimeout( slice, SLICE_GAP );
					} else {
						finished.current();
					}
				} )
				.catch( () => {
					if ( stopped ) {
						return;
					}

					if ( failed < RETRY_GAPS.length ) {
						timer = window.setTimeout( slice, RETRY_GAPS[ failed ] );
						failed++;

						return;
					}

					setProgress( ( last ) => ( { ...( last || {} ), paused: true } ) );
				} );
		};

		slice();

		return () => {
			stopped = true;
			window.clearTimeout( timer );
		};
	}, [ drive ] );

	return progress;
}
