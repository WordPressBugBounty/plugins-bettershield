/**
 * The security report, on demand (#696): one page with the score, its trend,
 * the findings and what changed in a period, to keep, forward or print.
 *
 * Built on the server from the weekly summary's figures, with only the
 * sections this reader may read on screen, and handed over here: saved as a
 * file, or printed from a frame the page holds, so no window opens and
 * nothing is sent anywhere.
 */

import './ReportCard.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import { retentionDays } from '../../nav';
import { announce } from '../../ui/announce';
import { download } from '../../ui/download';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Field from '../ui/Field';

/** The periods offered, each only where the log keeps that many days. */
export function periods( kept ) {
	const days = [ 7, 30, 90 ].filter( ( day ) => day <= kept );

	return ( days.length ? days : [ kept ] ).map( ( day ) => ( {
		value: String( day ),
		label: sprintf(
			/* translators: %d: how many days back the report covers. */
			_n( 'Last %d day', 'Last %d days', day, 'bettershield' ),
			day
		),
	} ) );
}

export default function ReportCard() {
	const options = periods( retentionDays );
	const [ days, setDays ] = useState( options.some( ( option ) => '30' === option.value ) ? '30' : options[ options.length - 1 ].value );
	const [ working, setWorking ] = useState( '' );
	const [ said, setSaid ] = useState( '' );
	const [ failed, setFailed ] = useState( '' );
	const frame = useRef( null );
	const mounted = useRef( true );

	useEffect(
		() => () => {
			mounted.current = false;
		},
		[]
	);

	const fetchReport = async ( kind ) => {
		setWorking( kind );
		setSaid( '' );
		setFailed( '' );
		announce( __( 'Making the report…', 'bettershield' ) );

		try {
			return await apiFetch( { path: `/bettershield/v1/report?days=${ days }` } );
		} catch ( error ) {
			if ( mounted.current ) {
				setFailed( ( error && error.message ) || __( 'The report could not be made. Nothing was changed; try again.', 'bettershield' ) );
			}

			return null;
		} finally {
			if ( mounted.current ) {
				setWorking( '' );
			}
		}
	};

	const save = async () => {
		const report = await fetchReport( 'download' );

		if ( report && mounted.current ) {
			const done = __( 'Report downloaded. Open it in a browser to read or print it.', 'bettershield' );

			download( report.filename, report.html, 'text/html;charset=utf-8' );
			setSaid( done );
			announce( done );
		}
	};

	/*
	 * Printed from a frame on this page rather than a new window, which a
	 * browser may block: the frame takes the page, prints it, and the
	 * browser's own dialog offers "Save as PDF".
	 *
	 * The frame is sandboxed so nothing in the page can run (#2276). Two
	 * permissions stay, and both are needed for this page to print it:
	 * `allow-same-origin` keeps the frame on this page's origin, without
	 * which reaching its window to call print() is a cross-origin error, and
	 * `allow-modals` is what lets a sandboxed document open the print dialog
	 * at all. Without `allow-scripts` the pair cannot be used to lift the
	 * sandbox from inside.
	 */
	const print = async () => {
		const report = await fetchReport( 'print' );

		if ( ! report || ! mounted.current || ! frame.current ) {
			return;
		}

		const target = frame.current;

		target.onload = () => {
			target.onload = null;

			if ( target.contentWindow ) {
				target.contentWindow.focus();
				target.contentWindow.print();
			}
		};
		const done = __( 'The print dialog opens with the report. Choose “Save as PDF” there to keep a PDF.', 'bettershield' );

		target.srcdoc = report.html;
		setSaid( done );
		announce( done );
	};

	return (
		<Card className="bs-ds-report" aria-labelledby="bs-ds-report-title">
			<CardHead icon="file-text" title={ __( 'Security report', 'bettershield' ) } id="bs-ds-report-title" line />
			<div className="bs-ds-report__body">
				<p className="bs-ds-report__lede bs-ds-t13 bs-ds-r bs-ds-c2">
					{ __( 'One page with your score, findings and what changed, to keep or print. It lists no addresses, logins or emails.', 'bettershield' ) }
				</p>
				<Field kind="select" label={ __( 'Covers', 'bettershield' ) } width="md" value={ days } options={ options } onChange={ setDays } />
				{ failed ? <Alert tone="error" live title={ failed } /> : null }
				{ /* Said through announce() as it happens; shown here to stay. */ }
				<p className="bs-ds-report__said bs-ds-t12 bs-ds-r bs-ds-c2">
					{ said }
				</p>
			</div>
			<div className="bs-ds-report__actions">
				<Button type="secondary" size="sm" icon="download" iconTone="1" isBusy={ 'download' === working } disabled={ Boolean( working ) } accessibleWhenDisabled onClick={ save }>
					{ __( 'Download Report', 'bettershield' ) }
				</Button>
				<Button type="ghost" size="sm" icon="printer" iconTone="1" isBusy={ 'print' === working } disabled={ Boolean( working ) } accessibleWhenDisabled onClick={ print }>
					{ __( 'Print or Save As PDF', 'bettershield' ) }
				</Button>
			</div>
			<iframe ref={ frame } className="bs-ds-report__frame" sandbox="allow-same-origin allow-modals" title={ __( 'Security report for printing', 'bettershield' ) } aria-hidden="true" tabIndex={ -1 } />
		</Card>
	);
}
