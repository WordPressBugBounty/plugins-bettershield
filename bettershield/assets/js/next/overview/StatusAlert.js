/**
 * The one compact alert under the hero (design frame 27:53126): whether any
 * finding deserves a look, dismissible until the next audit.
 */

import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import { whenPhrase } from '../../ui/when';
import { dismiss, isDismissed } from '../data/dismissed';
import { awake } from '../data/overview';

/**
 * @param {Object}   props
 * @param {Object}   props.overview The audit.
 * @param {Function} props.onClosed Called as it is dismissed, before it goes, to move focus on.
 */
export default function StatusAlert( { overview, onClosed } ) {
	const audit = overview.generated_at || '';
	// The audit it was closed on, so a newer audit brings it back while the
	// screen stays open.
	const [ closedOn, setClosedOn ] = useState( null );
	const hidden = closedOn === audit || isDismissed( 'status', audit );

	if ( hidden || ! audit ) {
		return null;
	}

	// A snoozed finding is not one this asks the owner to look at.
	const open = awake( overview.findings || [] ).length;
	const serious = awake( overview.findings || [] ).some( ( finding ) => 'critical' === finding.severity || 'high' === finding.severity );
	const close = () => {
		dismiss( 'status', audit );

		if ( onClosed ) {
			onClosed();
		}

		setClosedOn( audit );
	};

	// Toned as something to look at: green with a check said "all good"
	// beside a grade F with high findings open (#2055).
	if ( serious ) {
		return (
			<Alert
				tone="warning"
				title={ sprintf(
					/* translators: %d: how many findings are open. */
					_n( '%d finding needs your attention. Start with the ones under “Do first”.', '%d findings need your attention. Start with the ones under “Do first”.', open, 'bettershield' ),
					open
				) }
				onDismiss={ close }
			/>
		);
	}

	return (
		<Alert
			tone="success"
			title={ __( 'Nothing needs urgent attention.', 'bettershield' ) }
			desc={
				overview.next_check_at
					? sprintf(
							/* translators: %s: when the next scheduled audit runs. */
							__( 'The next scheduled audit runs %s.', 'bettershield' ),
							whenPhrase( overview.next_check_at )
					  )
					: __( 'Run an audit any time to update your score.', 'bettershield' )
			}
			onDismiss={ close }
		/>
	);
}
