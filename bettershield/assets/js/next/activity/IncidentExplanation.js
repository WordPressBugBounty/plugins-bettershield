/**
 * An open incident's explanation: what a draft would send, shown before
 * anything is sent, the request on its own press, and the draft with each
 * claim linked to the evidence it cites.
 */

import './IncidentExplanation.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { formatTime, useStore } from '../../store';
import { download } from '../../ui/download';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import Skeleton, { Bone } from '../ui/Skeleton';
import Part from './Part';

/**
 * The explanation's body before what it would send has been read: the
 * sentence about what leaves the site, the disclosure that shows it, and the
 * control that asks.
 */
function ExplanationBone() {
	return (
		<Skeleton label={ __( 'Loading what an explanation would send…', 'bettershield' ) }>
			<span className="bs-ds-part__bones">
				<Bone w="100%" />
				<Bone w="100%" />
				<Bone w="42%" />
			</span>
			<Bone kind="control" w="14em" />
			<Bone kind="control" w="108px" />
		</Skeleton>
	);
}

export default function IncidentExplanation( { incident } ) {
	const [ preview, setPreview ] = useState( null );
	const [ draft, setDraft ] = useState( null );
	const [ error, setError ] = useState( '' );
	// What would be sent, folded away until asked for: it is long, and it is
	// the part a reader checks rather than reads.
	const [ reviewing, setReviewing ] = useState( false );
	const { explainIncident, busy } = useStore();
	const evidenceId = `bs-ds-explain-evidence-${ incident }`;

	useEffect( () => {
		let alive = true;

		apiFetch( { path: `/bettershield/v1/ai/incidents/${ incident }` } ).then(
			( data ) => {
				if ( alive ) {
					setPreview( data );
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
	}, [ incident ] );

	return (
		<Part icon="sparkle" title={ __( 'Explain this incident', 'bettershield' ) } className="bs-ds-explain">
			{ error ? (
				<div role="alert">
					<Alert layout="default" tone="error" desc={ error } />
				</div>
			) : null }
			{ ! preview && ! error ? <ExplanationBone /> : null }
			{ preview ? (
				<>
					<p className="bs-ds-part__text">
						{ __(
							'This sends the records below to your AI provider, which may use credit. Account names and IDs, file locations, passwords and request contents are removed. The AI can’t change anything.',
							'bettershield'
						) }
					</p>
					{ preview.evidence.limited ? (
						<p className="bs-ds-part__text">{ __( 'Only the first 30 records are sent, so the summary won’t cover the rest.', 'bettershield' ) }</p>
					) : null }
					<div className="bs-ds-part__disclosure">
						<Button
							type="ghost"
							size="sm"
							trailing={ reviewing ? 'chevron-up' : 'chevron-down' }
							trailingTone="3"
							aria-expanded={ reviewing }
							aria-controls={ reviewing ? evidenceId : undefined }
							onClick={ () => setReviewing( ! reviewing ) }
						>
							{ __( 'Review Exactly What Will Be Sent', 'bettershield' ) }
						</Button>
						{ /* Scrolls on its own, so it is a stop in the keyboard's order. */ }
						{ reviewing ? (
							<pre id={ evidenceId } className="bs-ds-explain__evidence" tabIndex={ 0 }>
								{ JSON.stringify( preview.evidence, null, 2 ) }
							</pre>
						) : null }
					</div>
					{ ! preview.availability.available ? <Alert layout="default" tone="info" desc={ preview.availability.notice } /> : null }
					<div className="bs-ds-explain__actions">
						<Button
							type="secondary"
							size="sm"
							disabled={ !! busy || ! preview.availability.available }
							onClick={ () => explainIncident( incident, false, preview.evidence_hash, setDraft ) }
						>
							{ __( 'Explain This', 'bettershield' ) }
						</Button>
						<Button
							type="secondary"
							size="sm"
							disabled={ !! busy || ! preview.availability.available }
							onClick={ () => explainIncident( incident, true, preview.evidence_hash, setDraft ) }
						>
							{ __( 'Draft a Summary for My Client', 'bettershield' ) }
						</Button>
					</div>
				</>
			) : null }
			{ draft ? (
				<div role="status" className="bs-ds-explain__draft">
					<Alert layout="default" tone="warning" desc={ __( 'This is an AI draft. Check every claim against its cited evidence before you use or share it.', 'bettershield' ) } />
					<KeyValues className="bs-ds-part__facts">
						<KeyValue
							label={
								/* translators: label beside the date and time the draft was written. */
								__( 'Created', 'bettershield' )
							}
							value={ formatTime( draft.generated_at ) }
						/>
					</KeyValues>
					{ draft.paragraphs.map( ( paragraph, p ) => (
						<p key={ p } className="bs-ds-explain__paragraph">
							{ paragraph.map( ( sentence, s ) => (
								<span key={ s }>
									{ sentence.text }{ ' ' }
									{ sentence.evidence_ids.map( ( id ) => (
										<a key={ id } href={ `#bs-incident-evidence-${ id }` } onClick={ () => document.getElementById( `bs-incident-evidence-${ id }` )?.focus() }>
											{ `[${ id }] ` }
										</a>
									) ) }
								</span>
							) ) }
						</p>
					) ) }
					{ draft.client ? (
						<span>
							<Button
								type="secondary"
								size="sm"
								icon="download"
								iconTone="2"
								onClick={ () => {
									const text = [
										__( 'Draft for review. Based only on what BetterShield recorded; it doesn’t confirm the cause or that the site is clean.', 'bettershield' ),
										...draft.paragraphs.map( ( p ) => p.map( ( s ) => `${ s.text } [${ s.evidence_ids.join( ', ' ) }]` ).join( ' ' ) ),
										JSON.stringify( draft.evidence, null, 2 ),
									].join( '\n\n' );
									download( `incident-${ incident }-client-draft.txt`, text );
								} }
							>
								{ __( 'Download Draft With Evidence', 'bettershield' ) }
							</Button>
						</span>
					) : null }
				</div>
			) : null }
		</Part>
	);
}
