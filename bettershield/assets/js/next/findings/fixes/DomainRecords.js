/**
 * Fix for the domain's mail and certificate records (#2203).
 *
 * Each record family that has a problem, with the exact host, type and value
 * to publish, or why no value is offered; where the domain's DNS is managed;
 * and Check again, which asks the daily lookup to run in the background.
 * DNS is changed outside this site, so nothing here has an Undo, and the
 * finding closes only when a later lookup sees the records.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { mayManage } from '../../../nav';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

const PATH = '/bettershield/v1/findings/domain_mail_records/records';

/** Each family's name as the panel heads it. */
const FAMILIES = {
	spf: () => __( 'SPF: which services may send your email', 'bettershield' ),
	dmarc: () => __( 'DMARC: what happens to fake email', 'bettershield' ),
	caa: () => __( 'CAA: who may issue your SSL certificate', 'bettershield' ),
};

/**
 * One record to publish, or the reason none is offered.
 *
 * @param {Object} props
 * @param {Object} props.record The record.
 */
function Record( { record } ) {
	return (
		<li className="bs-ds-fix__record">
			<h4 className="bs-ds-fix__text bs-ds-m">{ ( FAMILIES[ record.family ] || ( () => record.family ) )() }</h4>
			<p className="bs-ds-fix__note">
				{ record.value
					? sprintf(
							/* translators: %s: a DNS record type, e.g. TXT. */
							__( 'Type: %s', 'bettershield' ),
							record.type
					  )
					: sprintf(
							/* translators: 1: a DNS name, e.g. _dmarc.example.com; 2: a record type, e.g. TXT. */
							__( 'Name: %1$s · Type: %2$s', 'bettershield' ),
							record.host,
							record.type
					  ) }
			</p>
			{ record.value ? (
				<>
					<CopyField label={ __( 'Name', 'bettershield' ) } value={ record.host } copyLabel={ __( 'Copy Name', 'bettershield' ) } />
					<CopyField multiline label={ __( 'Value', 'bettershield' ) } value={ record.value } copyLabel={ __( 'Copy Value', 'bettershield' ) } />
				</>
			) : (
				<p className="bs-ds-fix__text">{ record.refused }</p>
			) }
			{ record.replaces > 1 ? <p className="bs-ds-fix__note">{ __( 'Replace your existing SPF record with this one. A domain can only have one.', 'bettershield' ) }</p> : null }
			{ record.added && record.added.length ? (
				<p className="bs-ds-fix__note">
					{ sprintf(
						/* translators: %s: SPF terms added, e.g. include:_spf.google.com. */
						__( 'Adds %s for the mail service this site was found to use. Everything the record had stays.', 'bettershield' ),
						record.added.join( ', ' )
					) }
				</p>
			) : null }
			{ record.note ? <p className="bs-ds-fix__note">{ record.note }</p> : null }
		</li>
	);
}

export default function DomainRecords() {
	const { checkDomainRecordsAgain, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: PATH } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The records could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the domain’s records…', 'bettershield' ) }</p>;
	}

	const checking = state.checking;
	const working = isWorking( busy, 'domain-check' );

	return (
		<>
			{ state.reliable ? (
				<>
					<p className="bs-ds-fix__text">
						{ state.provider
							? sprintf(
									/* translators: %s: a DNS service, e.g. Cloudflare. */
									__( 'This domain’s DNS is managed at %s. Add or change these records there.', 'bettershield' ),
									state.provider.label
							  )
							: __( 'Add these where you manage your domain, usually where you bought it or at your CDN, such as Cloudflare.', 'bettershield' ) }
					</p>
					{ state.provider ? (
						<div className="bs-ds-fix__actions">
							<Button type="secondary" size="sm" trailing="external-link" href={ state.provider.url } target="_blank" rel="noopener noreferrer">
								{ sprintf(
									/* translators: %s: a DNS service, e.g. Cloudflare. */
									__( 'Open %s', 'bettershield' ),
									state.provider.label
								) }
							</Button>
						</div>
					) : null }
					<ul className="bs-ds-fix__list">
						{ state.records.map( ( record ) => (
							<Record key={ record.family } record={ record } />
						) ) }
					</ul>
					<p className="bs-ds-fix__note">{ __( 'You make these changes outside WordPress, so there is no Undo here. This finding clears once BetterShield sees the new records.', 'bettershield' ) }</p>
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'We couldn’t read your domain’s current settings, so we can’t suggest records yet.', 'bettershield' ) }</p>
			) }
			{ mayManage() ? (
				<div className="bs-ds-fix__actions">
					<Button
						type="secondary"
						size="sm"
						isBusy={ working }
						disabled={ checking || working }
						onClick={ () =>
							checkDomainRecordsAgain( ( answer ) => {
								if ( answer && answer.state ) {
									setState( answer.state );
									announce( __( 'The records will be looked up again in the background.', 'bettershield' ) );
								}
							} )
						}
					>
						{ __( 'Check Again', 'bettershield' ) }
					</Button>
				</div>
			) : null }
			{ checking ? (
				<p className="bs-ds-fix__note" role="status">
					{ __( 'Looking the records up again in the background. The finding updates when the answer is in.', 'bettershield' ) }
				</p>
			) : null }
		</>
	);
}

// Records are published where the domain is managed, not here.
DomainRecords.kind = 'guidance';
