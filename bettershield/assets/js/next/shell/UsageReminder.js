/**
 * The one reminder a skipped usage question earns.
 *
 * A week after the owner pressed Skip on the Quick Setup's first step, and
 * only on this plugin's own screens, the question is asked once more, at the
 * top of the screen. Either answer ends it, and so does closing it: it is
 * never shown again. Saying no sends nothing, exactly as skipping did.
 */

import './UsageReminder.css';

import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useStore } from '../../store';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { usageSummary } from '../data/usage';

export default function UsageReminder() {
	const { resources, answerUsage, dismissUsageReminder, busy } = useStore();
	const [ gone, setGone ] = useState( false );
	const overview = resources.overview;

	if ( gone || ! overview || 'ready' !== overview.status || ! overview.data?.onboarding?.usage_reminder ) {
		return null;
	}

	const working = 'usage' === busy || 'usage-reminder' === busy;

	const close = () => {
		setGone( true );
		dismissUsageReminder();
	};

	return (
		<Card className="bs-ds-usagenote" aria-labelledby="bs-ds-usagenote-title">
			<CardHead icon="send" title={ __( 'Share usage data?', 'bettershield' ) } id="bs-ds-usagenote-title">
				<Button type="ghost" size="sm" icon="x" iconOnly aria-label={ __( 'Dismiss', 'bettershield' ) } disabled={ working } onClick={ close } />
			</CardHead>
			<div className="bs-ds-usagenote__body">
				<p className="bs-ds-usagenote__text">
					{ usageSummary() }
				</p>
				<p className="bs-ds-usagenote__text">{ __( 'You will not be asked again.', 'bettershield' ) }</p>
				<div className="bs-ds-usagenote__actions">
					<Button
						type="primary"
						size="sm"
						isBusy={ 'usage' === busy }
						disabled={ working }
						onClick={ () => {
							setGone( true );
							answerUsage( true );
						} }
					>
						{ __( 'Share Usage Data', 'bettershield' ) }
					</Button>
					<Button type="ghost" size="sm" disabled={ working } onClick={ close }>
						{ __( 'No Thanks', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</Card>
	);
}
