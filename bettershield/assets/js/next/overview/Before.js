/**
 * What has to be read before the score is, because each part qualifies it:
 * the setup offered to a site it never opened for, the question a site in a
 * new place is asked, safe mode, the plugin's own record keeping, and a score
 * that may not be current.
 */

import { __, sprintf } from '@wordpress/i18n';
import { formatTime, hoursSince } from '../../store';
import Alert from '../ui/Alert';
import SafeMode from '../protect/SafeMode';
import SetupOffer from './SetupOffer';
import SiteCard from './SiteCard';
import Storage from './Storage';

/** How old a score is before the Overview says it may not describe the site now. */
const STALE_AFTER_HOURS = 48;

/**
 * Something is working, but not fully: said in place, as a status, rather
 * than by showing old data as though it were current.
 *
 * @param {Object} props
 * @param {*}      props.children What is not working.
 */
function Degraded( { children } ) {
	return <Alert layout="default" tone="info" live desc={ children } />;
}

/**
 * @param {Object}   props
 * @param {Object}   props.overview The overview payload.
 * @param {Function} props.onGone   Called when a card takes itself away, so focus has somewhere to go.
 * @param {Function} props.reload   Reads the overview again.
 * @param {string}   props.note     What a repair of the record keeping said.
 * @param {Function} props.setNote  Keeps it.
 */
export default function Before( { overview, onGone, reload, note, setNote } ) {
	const age = hoursSince( overview.generated_at );

	return (
		<>
			<SetupOffer offer={ overview.onboarding?.setup } onDismiss={ onGone } />
			<SiteCard identity={ overview.site_identity } onGone={ onGone } />
			<SafeMode safeMode={ overview.safe_mode || null } />
			<Storage
				rows={ overview.readiness }
				onRepaired={ ( said ) => {
					setNote( said || '' );

					if ( said ) {
						onGone();
					}

					reload();
				} }
			/>
			{ /* Always here, empty until there is something to say: the card
			     that would have said it is the one a successful repair removes. */ }
			<p className="bs-ds-storage__said" role="status">
				{ note }
			</p>

			{ overview.alerts_muted ? (
				<Degraded>
					{ __(
						'Alerts are muted, so no alert or weekly summary is emailed. The site is still watched.',
						'bettershield'
					) }
				</Degraded>
			) : null }

			{ ! overview.next_check_at ? (
				<Degraded>
					{ __(
						'No daily audit is scheduled, so this score only updates when you run one.',
						'bettershield'
					) }
				</Degraded>
			) : null }

			{ null !== age && age > STALE_AFTER_HOURS ? (
				<Degraded>
					{ sprintf(
						/* translators: %s: date and time. */
						__( 'This score is from %s and may be out of date.', 'bettershield' ),
						formatTime( overview.generated_at )
					) }
				</Degraded>
			) : null }
		</>
	);
}
