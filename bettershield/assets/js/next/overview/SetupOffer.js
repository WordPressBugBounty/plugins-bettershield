/**
 * The card that offers the Quick Setup, for a site it did not open by itself.
 *
 * A site that had this plugin before the setup existed, one installed from
 * another plugin's own setup, or one activated in bulk or from the terminal is
 * never redirected; it is offered the setup here instead, once, and a setup
 * somebody left part way is offered the rest of it. Dismissing the card is a
 * complete answer: the setup stays in the menu for anybody who wants it.
 */

import './SetupOffer.css';

import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { isWorking, useStore } from '../../store';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * @param {Object}   props
 * @param {?Object}  props.offer     { url, resume } from the overview, or null.
 * @param {Function} props.onDismiss Called before the card goes, while the
 *                                   button that dismissed it still has focus.
 */
export default function SetupOffer( { offer, onDismiss } ) {
	const { dismissSetupOffer, busy } = useStore();
	const [ gone, setGone ] = useState( false );

	if ( gone || ! offer ) {
		return null;
	}

	return (
		<Card className="bs-ds-setup-offer" aria-labelledby="bs-ds-setup-offer-title">
			<CardHead
				icon="shield"
				// The feature's own name, as everywhere else: the heading said
				// "Run the Quick Setup" over a button saying "Run Quick
				// Setup" (#2190). The button carries the verb.
				title={ offer.resume ? __( 'Finish the Quick Setup', 'bettershield' ) : __( 'Quick Setup', 'bettershield' ) }
				id="bs-ds-setup-offer-title"
			>
				<Button
					type="ghost"
					size="sm"
					iconOnly
					label={ __( 'Dismiss the Quick Setup card', 'bettershield' ) }
					disabled={ isWorking( busy, 'setup-offer' ) }
					onClick={ () => {
						onDismiss?.();
						setGone( true );
						dismissSetupOffer();
					} }
				>
					<Icon name="x" size={ 14 } tone="2" />
				</Button>
			</CardHead>
			<div className="bs-ds-setup-offer__body">
				<p className="bs-ds-setup-offer__text">
					{ offer.resume
						? __( 'What you saved is kept, and setup opens where you left it.', 'bettershield' )
						: __( 'Set up the security basics in two minutes. Every change can be undone.', 'bettershield' ) }
				</p>
				<Button type="primary" size="sm" href={ offer.url } className="bs-ds-setup-offer__go">
					{ offer.resume ? __( 'Continue the Setup', 'bettershield' ) : __( 'Run Quick Setup', 'bettershield' ) }
					<Icon name="arrow-right" size={ 14 } tone="onbrand" className="bs-ds-setup-offer__arrow" />
				</Button>
			</div>
		</Card>
	);
}
