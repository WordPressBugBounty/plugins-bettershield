/**
 * What this plugin costs the people who visit the site, measured here.
 *
 * A number about this site's own traffic, rather than an assurance. It is
 * only worth showing while it stays honest, which is what constrains the
 * card: it names what was counted and how large the sample was rather than
 * implying every page view was measured, and it says nothing at all until
 * enough have been seen for the figure to mean anything.
 */

import './FrontEndCost.css';

import { __, sprintf } from '@wordpress/i18n';
import { costHeadline } from '../../ui/cost';
import { formatTime } from '../../store';
import { Card, CardHead } from '../ui/Card';
import InfoTip from '../ui/InfoTip';

export default function FrontEndCost( { cost } ) {
	if ( ! cost ) {
		return null;
	}

	return (
		<Card className="bs-ds-cost" aria-labelledby="bs-ds-cost-title">
			<CardHead icon="gauge" title={ __( 'BetterShield’s effect on page speed', 'bettershield' ) } id="bs-ds-cost-title" />
			<div className="bs-ds-cost__body">
				{ /* The figure stands; how it was measured is behind an ⓘ on it. */ }
				<div className="bs-ds-cost__row">
					<p className="bs-ds-cost__line">{ costHeadline( cost ) }</p>
					<InfoTip label={ __( 'How this is measured', 'bettershield' ) }>
						{ sprintf(
							/* translators: 1: sample rate, e.g. 20. 2: a date and time. */
							__(
								'Measured on 1 in %1$d page views since %2$s. Dashboard, checkout and background requests aren’t counted.',
								'bettershield'
							),
							cost.one_in,
							formatTime( cost.since )
						) }
					</InfoTip>
				</div>
			</div>
		</Card>
	);
}
