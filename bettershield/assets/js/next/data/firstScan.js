/**
 * Carrying the first file check and first probes on from a screen waiting for them.
 *
 * A check moves in slices, and between them it waits for the hourly task, so a
 * screen saying the score is on its way asks for the next slice when the last
 * one answers. It stops when they end, the screen closes or a slice fails; the
 * server's bounded wait covers that last case.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';

const SLICE_GAP = 1500;

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

		const slice = () => {
			apiFetch( { path: '/bettershield/v1/integrity/scan', method: 'POST' } )
				.then( ( answer ) => {
					if ( stopped ) {
						return;
					}

					if ( answer && ( answer.running || answer.first_scan_running ) ) {
						setProgress( answer.progress || null );
						timer = window.setTimeout( slice, SLICE_GAP );
					} else {
						finished.current();
					}
				} )
				.catch( () => {} );
		};

		slice();

		return () => {
			stopped = true;
			window.clearTimeout( timer );
		};
	}, [ drive ] );

	return progress;
}
