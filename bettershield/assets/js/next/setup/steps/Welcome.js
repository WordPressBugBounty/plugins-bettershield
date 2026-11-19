/**
 * Getting Started: the usage-data question, asked once and plainly.
 *
 * The question is answered by one of two buttons inside its card: Allow &
 * Continue, the step's one Primary, is the yes and moves on; Skip, a quieter
 * Ghost beside it, sends nothing and moves on, and a week later
 * one reminder is offered on this plugin's own screens, then never again.
 * There is no box to tick and no other way forward, so moving on never
 * doubles as agreeing (#1734). The sentence says exactly what is sent,
 * including the administrator's email address, which is why it never calls
 * the report anonymous.
 *
 * The step asks once. Opened again after an answer, it shows the welcome
 * and Get Started, which only moves on: after a yes, a Skip beside the
 * question would have left sharing on while looking like the way to decline
 * it, and the reminder promises not to ask again. The answer is changed in
 * Settings › General, so a reopened step never turns sharing on, or leaves
 * it on, with a click that looks like going on (#661).
 *
 * On a network the report describes the whole network, so only a super admin
 * is asked. A site administrator gets the welcome without the question, and
 * Get Started only moves on.
 *
 * Drawn as the design's first card: the heading, three lines on what the
 * setup does, then the question in a box of its own — the sentence, ending
 * in a "What We Collect" link that opens the full list of what is sent under
 * it. Allow & Continue is the step's one Primary at the column's foot, and
 * Skip, the no, sits at the end of the strip under the card, where every
 * step's Skip is. The picture is beside it.
 */

import './Welcome.css';

import { useId, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { Card } from '../../ui/Card';
import { Answer } from '../../ui/Topics';
import { usageSummary } from '../../data/usage';
import Frame, { Footer } from '../Frame';
import Benefits from '../Benefits';
import { useSetup } from '../context';
import { ROUTES } from '../api';
import brand from '../brand';

/** What the setup does, in three lines, as the design opens with. */
function WelcomeBenefits() {
	return (
		<Benefits
			items={ [
				[ 'shield-check', __( 'Turn on the protections most sites need', 'bettershield' ) ],
				[ 'list-checks', __( 'Get your first security score in minutes', 'bettershield' ) ],
				[ 'undo-2', __( 'Undo any change, any time', 'bettershield' ) ],
			] }
		/>
	);
}

export default function Welcome() {
	const { state, run, busy, advance, skip } = useSetup();
	const consent = state.consent || {};
	// Which answer is on its way, so only its button shows it.
	const [ answering, setAnswering ] = useState( '' );
	// The list of what is sent, opened from the link that ends the sentence.
	const [ listed, setListed ] = useState( false );
	const listId = useId();

	// Skip is an answer to the question, and leaves the step skipped.
	const answer = ( value ) => {
		setAnswering( value );

		return run( 'consent', ROUTES.consent, { answer: value } ).then( ( result ) => {
			if ( result ) {
				( 'skip' === value ? skip : advance )();
			}
		} );
	};

	// Not theirs to answer, or answered already: the welcome, and on.
	if ( false === consent.can_answer || consent.asked ) {
		return (
			<Frame
				variant="hero"
				title={ sprintf( /* translators: %s: the plugin's name. */ __( 'Welcome to %s', 'bettershield' ), brand() ) }
				subtitle={ __( 'Set up your site’s security basics in under 2 minutes.', 'bettershield' ) }
				footer={ <Footer noSkip primary={ { label: __( 'Get Started', 'bettershield' ), onClick: advance } } /> }
			>
				<WelcomeBenefits />
			</Frame>
		);
	}

	return (
		<Frame
			variant="hero"
			title={ sprintf( /* translators: %s: the plugin's name. */ __( 'Welcome to %s', 'bettershield' ), brand() ) }
			subtitle={ __( 'Set up your site’s security basics in under 2 minutes.', 'bettershield' ) }
			footer={
				/* The yes is the step's one Primary; Skip, the no, is quieter, at the strip's end. */
				<Footer
					primary={ { label: __( 'Allow & Continue', 'bettershield' ), onClick: () => answer( 'yes' ), busy: 'consent' === busy && 'yes' === answering } }
					skip={ { label: __( 'Skip', 'bettershield' ), onClick: () => answer( 'skip' ) } }
				/>
			}
		>
			<WelcomeBenefits />

			{ /* A short question rather than a settings card: no header, as in
			     the shared onboarding design. Still a named region. */ }
			<Card className="bs-ds-settings bs-ds-setup-consent" aria-label={ __( 'Usage data sharing', 'bettershield' ) }>
				<div className="bs-ds-setup-card__body">
					<p className="bs-ds-setup__text bs-ds-setup-consent__text">
						{ usageSummary() }{ ' ' }
						<button
							type="button"
							className="bs-ds-setup-consent__collect"
							aria-expanded={ listed }
							aria-controls={ listId }
							onClick={ () => setListed( ! listed ) }
						>
							{ __( 'What We Collect', 'bettershield' ) }
						</button>
					</p>

					{ listed ? (
						<div id={ listId } className="bs-ds-topics__body bs-ds-setup-consent__list">
							<Answer
								item={ {
									text: __( 'Only if you allow it, at most once a day:', 'bettershield' ),
									points: consent.fields || [],
									// The exact report lives under Settings › General › Share
									// usage data; here it pushed the question far down (#2132).
									body: (
										<p>
											{ sprintf( /* translators: %1$s: the plugin's name. */ __( 'Never sent: anything about visitors, other accounts, sign-ins, or what %1$s found or recorded. Turn this off anytime in %1$s Settings.', 'bettershield' ), brand() ) }
										</p>
									),
								} }
							/>
						</div>
					) : null }

				</div>
			</Card>
		</Frame>
	);
}
