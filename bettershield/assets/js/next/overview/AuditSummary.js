/**
 * "Explain My Audit": the open findings, explained together in three short
 * paragraphs by the AI provider the owner connected.
 *
 * Absent where the feature is (no provider, no WordPress 7.0, switched off)
 * and where nothing is open. The answer is never shown without the findings
 * it was built from: each sentence carries the numbers of the findings it
 * rests on, and the numbered list sits under it, so what the reader is told
 * can be checked against what the audit recorded.
 */

import './AuditSummary.css';

import { useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import useMutationFocus from '../../ui/useMutationFocus';
import { findingUrl, mayManage } from '../../nav';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, IconTile } from '../ui/Card';
import { severityName } from '../data/severity';

/**
 * @param {Object} props
 * @param {number} props.open     How many findings are open.
 * @param {string} props.openKeys Which findings are open, as one string.
 */
export default function AuditSummary( { open, openKeys = '' } ) {
	const { explainAudit, busy } = useStore();
	// Whether a provider is connected is read only for somebody who may ask
	// one: the read answers nobody else, and a reader was shown its refusal.
	const manage = mayManage();
	const { resource } = useResource( 'aiStatus', { skip: ! manage } );
	const [ asked, setAsked ] = useState( null );
	const answerRef = useRef( null );
	const afterExplain = useMutationFocus( answerRef );
	const status = resource.data;

	// An answer stands for the findings it was asked about. Once they move (a
	// fix applied, an audit run) it is put away and the ask is offered
	// again, rather than left citing a finding that is no longer open.
	const result = asked && asked.openKeys === openKeys ? asked.data : null;
	const ask = () => explainAudit( afterExplain( ( data ) => data && setAsked( { data, openKeys } ) ) );

	if ( ! manage ) {
		return null;
	}

	// A status that could not be read is said as that, never drawn as the
	// same nothing as a site with no provider.
	if ( 'error' === resource.status && open ) {
		return (
			<Card className="bs-ds-audit bs-ds-audit--ask">
				<IconTile icon="file-text" />
				<p className="bs-ds-audit__said">
					{ __( 'Could not check for a connected AI provider, so Explain My Audit is not offered.', 'bettershield' ) }
				</p>
			</Card>
		);
	}

	if ( ! status || ! status.available || ! open ) {
		return null;
	}

	const working = isWorking( busy, 'explain-audit' );

	if ( ! result ) {
		return (
			<Card className="bs-ds-audit bs-ds-audit--ask">
				<IconTile icon="file-text" />
				{ /* What leaves the site, said before the button is pressed. */ }
				<p className="bs-ds-audit__said">
					{ __( 'Your AI provider explains your unfixed findings in three short paragraphs.', 'bettershield' ) }{ ' ' }
					{ __( 'Up to twelve open findings are sent to it: titles, severities and evidence, with web and email addresses removed.', 'bettershield' ) }
				</p>
				<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ ask }>
					{ working ? __( 'Asking…', 'bettershield' ) : __( 'Explain My Audit', 'bettershield' ) }
				</Button>
			</Card>
		);
	}

	return (
		<Card className="bs-ds-audit" aria-labelledby="bs-ds-audit-title" ref={ answerRef } tabIndex={ -1 }>
			<CardHead icon="file-text" title={ __( 'Your audit, explained', 'bettershield' ) } id="bs-ds-audit-title">
				{ /* Free while the findings have not moved: the same findings are
				     answered from what was kept. */ }
				<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ ask }>
					{ working ? __( 'Asking…', 'bettershield' ) : __( 'Ask Again', 'bettershield' ) }
				</Button>
			</CardHead>
			<div className="bs-ds-audit__body">
				{ result.paragraphs.map( ( paragraph, index ) => (
					<p key={ index } className="bs-ds-audit__para">
						{ paragraph.map( ( sentence, at ) => (
							<span key={ at }>
								{ sentence.text }{ ' ' }
								<span className="bs-ds-audit__cites">
									{ sentence.evidence_ids.map( ( id ) => (
										<a key={ id } href={ `#bs-audit-summary-finding-${ id }` }>
											{ sprintf(
												/* translators: %d: the number of a finding in the list below. */
												__( '[%d]', 'bettershield' ),
												id
											) }
										</a>
									) ) }
								</span>{ ' ' }
							</span>
						) ) }
					</p>
				) ) }

				<p className="bs-ds-audit__source">
					{ result.cached
						? sprintf(
								/* translators: %s: date and time the summary was written. */
								__( 'AI summary from %s, based only on the findings below.', 'bettershield' ),
								formatTime( result.generated_at )
						  )
						: __( 'Written by your connected AI provider, using only the findings below.', 'bettershield' ) }
					{ result.limited
						? ` ${ sprintf(
								/* translators: 1: findings sent, 2: findings open. */
								__( 'It saw the %1$d most serious of %2$d open findings.', 'bettershield' ),
								result.findings.length,
								result.open_total
						  ) }`
						: '' }
				</p>
			</div>

			<ol className="bs-ds-audit__findings">
				{ result.findings.map( ( finding ) => (
					<li key={ finding.id } id={ `bs-audit-summary-finding-${ finding.id }` } tabIndex={ -1 }>
						<Badge tone={ kindTone( finding.severity ) }>{ severityName( finding.severity ) }</Badge>
						<a href={ findingUrl( finding.key ) }>{ finding.title }</a>
					</li>
				) ) }
			</ol>
		</Card>
	);
}
