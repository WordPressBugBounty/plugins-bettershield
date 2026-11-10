/**
 * The usage report this site would send, exactly, and what was last sent:
 * the proof behind the list of what is collected, for whoever wants it.
 *
 * Read from the server, which builds it the way sending builds it and sends
 * nothing to do so, and only when asked for: behind its own control, under
 * the question it is about and never in place of it.
 */

import './UsageReport.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useId, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { whenPhrase } from '../../ui/when';
import Alert from './Alert';
import Button from './Button';
import CopyField from './CopyField';

/** Where the report is read from. */
export const USAGE_PREVIEW = '/bettershield/v1/settings/usage/preview';

/**
 * The sentence before the report: that showing it sent nothing, and whether
 * anything goes at all.
 *
 * @param {Object} preview The server's answer.
 * @return {string} The sentence.
 */
export function previewLead( preview ) {
	if ( ! preview.configured ) {
		return __( 'Nothing has been sent. This build cannot send reports. This is what one would carry.', 'bettershield' );
	}

	if ( preview.staging ) {
		return __( 'Nothing has been sent. A staging copy never sends reports. This is what one would carry.', 'bettershield' );
	}

	if ( ! preview.allowed ) {
		return __( 'Nothing has been sent. If you allow it, this is sent at most once a day.', 'bettershield' );
	}

	return __( 'Nothing was sent to show this. The next report carries it.', 'bettershield' );
}

/**
 * The lines after it: what was last sent and under which reference, whether
 * the site has changed since, when the next goes, and the one a deactivation
 * sends.
 *
 * @param {Object} preview The server's answer.
 * @return {string[]} The lines; none where nothing has been sent.
 */
export function lastReportLines( preview ) {
	if ( ! preview.last_sent ) {
		return [];
	}

	const lines = [
		preview.reference
			? sprintf(
					/* translators: 1: when, e.g. "today, 5:14 PM"; 2: the reference the usage service files this site under. */
					__( 'The last report went %1$s, filed under reference %2$s.', 'bettershield' ),
					whenPhrase( preview.last_sent ),
					preview.reference
			  )
			: sprintf(
					/* translators: %s: when, e.g. "today, 5:14 PM". */
					__( 'The last report went %s.', 'bettershield' ),
					whenPhrase( preview.last_sent )
			  ),
	];

	if ( true === preview.unchanged ) {
		lines.push( __( 'It said the same as the report above.', 'bettershield' ) );
	} else if ( false === preview.unchanged && preview.sends ) {
		// Only where a next report goes at all: with sharing off, or on a
		// staging copy, nothing carries it.
		lines.push( __( 'Something has changed since, like a version or plugin. The next report carries it.', 'bettershield' ) );
	}

	if ( preview.sends && preview.next_after ) {
		lines.push(
			sprintf(
				/* translators: %s: when, e.g. "tomorrow, 5:14 PM". */
				__( 'The next one goes with the first daily run after %s.', 'bettershield' ),
				whenPhrase( preview.next_after )
			)
		);
	}

	// The same: a deactivation is reported only where reports go.
	if ( preview.sends && preview.reference ) {
		lines.push( __( 'If BetterShield is deactivated, one more report goes, marked Deactivated with the date.', 'bettershield' ) );
	}

	return lines;
}

/** The report itself, read when this is drawn. */
function Report() {
	const [ preview, setPreview ] = useState( null );
	const [ failed, setFailed ] = useState( '' );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: USAGE_PREVIEW } ).then(
			( data ) => alive && setPreview( data ),
			( error ) => alive && setFailed( error && error.message ? error.message : __( 'The report could not be built. Nothing was sent.', 'bettershield' ) )
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( failed ) {
		return (
			<p className="bs-ds-usagereport__line" role="alert">
				{ failed }
			</p>
		);
	}

	if ( ! preview ) {
		return (
			<p className="bs-ds-usagereport__line" role="status">
				{ __( 'Putting the report together…', 'bettershield' ) }
			</p>
		);
	}

	return (
		<div className="bs-ds-usagereport">
			<Alert layout="default" tone="info" desc={ previewLead( preview ) } />
			<CopyField label={ __( 'The report, field by field', 'bettershield' ) } value={ JSON.stringify( preview.report, null, 2 ) } multiline copyLabel={ __( 'Copy the Report', 'bettershield' ) } />
			<p className="bs-ds-usagereport__line">
				{ sprintf(
					/* translators: %s: the address the usage report is sent to. */
					__( 'Sent as form fields to %s, and nowhere else.', 'bettershield' ),
					preview.endpoint
				) }
			</p>
			{ preview.network ? (
				<p className="bs-ds-usagereport__line">
					{ __( 'On a network, the report covers the network: address, name, administrator, the main site’s theme and plugins, and network-active plugins.', 'bettershield' ) }
				</p>
			) : null }
			{ lastReportLines( preview ).map( ( line ) => (
				<p key={ line } className="bs-ds-usagereport__line">
					{ line }
				</p>
			) ) }
		</div>
	);
}

/** The control that opens the report, and the report under it. */
export default function UsageReport() {
	const [ open, setOpen ] = useState( false );
	const panel = `bs-ds-usage-report-${ useId().replace( /[^\w-]/g, '' ) }`;

	return (
		<div className="bs-ds-usagereport">
			<Button
				type="ghost"
				size="sm"
				className="bs-ds-topics__ask bs-ds-topics__lone"
				trailing={ open ? 'chevron-up' : 'chevron-down' }
				trailingTone="3"
				aria-expanded={ open }
				aria-controls={ open ? panel : undefined }
				onClick={ () => setOpen( ! open ) }
			>
				{ open ? __( 'Hide the report', 'bettershield' ) : __( 'Preview the report', 'bettershield' ) }
			</Button>
			{ open ? (
				<div id={ panel }>
					<Report />
				</div>
			) : null }
		</div>
	);
}
