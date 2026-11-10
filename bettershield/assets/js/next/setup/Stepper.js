/**
 * Where the setup is, as a row of numbered steps.
 *
 * Drawn as the design's tab row: each step its number in a pill and its name,
 * the open one in the primary ink with the 2px indicator under it, and one
 * rule under the row. It is not a tab list, though: steps already passed can
 * be opened again directly, except while a step is saving, when they wait
 * with the footer's buttons; the one open now is marked for assistive
 * technology as the current step, and the ones ahead are plain text, because
 * a step that cannot be opened is not a control. A step passed by Skip says
 * so, rather than reading as done.
 *
 * On a narrow panel seven names do not fit. The pills stay, and every one that
 * could be pressed can still be pressed; the names move out of sight but stay
 * in each control's name, and one line beneath says which step of how many
 * this is.
 */

import './Stepper.css';

import { __, sprintf } from '@wordpress/i18n';
import Icon from '../ui/Icon';

/**
 * @param {Object}   props
 * @param {Array}    props.steps    Visible steps, in order.
 * @param {string}   props.current  The step open now.
 * @param {Function} props.canVisit Whether a step may be opened directly.
 * @param {Function} props.onVisit  Open a step.
 * @param {boolean}  props.locked   Whether a step is saving.
 * @param {string[]} props.skipped  Steps passed by Skip rather than finished.
 */
export default function Stepper( { steps, current, canVisit, onVisit, locked = false, skipped = [] } ) {
	const at = steps.findIndex( ( step ) => step.slug === current );
	const total = steps.length;

	return (
		<div className="bs-ds-steps">
			<ol className="bs-ds-steps__list" aria-label={ __( 'Setup progress', 'bettershield' ) }>
				{ steps.map( ( step, index ) => {
					let state = index === at ? 'current' : 'ahead';

					if ( index < at ) {
						state = skipped.includes( step.slug ) ? 'skipped' : 'done';
					}

					const passed = 'done' === state || 'skipped' === state;
					const marker = (
						<span className="bs-ds-steps__marker" aria-hidden="true">
							{ 'done' === state ? <Icon name="check" size={ 12 } tone="ok" /> : index + 1 }
						</span>
					);

					return (
						<li key={ step.slug } className={ `bs-ds-steps__item is-${ state }` } aria-current={ 'current' === state ? 'step' : undefined }>
							{ passed && canVisit( step.slug ) ? (
								<button
									type="button"
									className="bs-ds-steps__link"
									disabled={ locked }
									onClick={ () => onVisit( step.slug ) }
									aria-label={ sprintf(
										'skipped' === state
											? /* translators: %s: step name. */
											  __( '%s, skipped. Open this step again', 'bettershield' )
											: /* translators: %s: step name. */
											  __( '%s, done. Open this step again', 'bettershield' ),
										step.short
									) }
								>
									{ marker }
									<span className="bs-ds-steps__label">{ step.short }</span>
								</button>
							) : (
								<span className="bs-ds-steps__link">
									{ marker }
									<span className="bs-ds-steps__label">{ step.short }</span>
									{ 'done' === state ? <span className="screen-reader-text">{ __( '(done)', 'bettershield' ) }</span> : null }
									{ 'skipped' === state ? <span className="screen-reader-text">{ __( '(skipped)', 'bettershield' ) }</span> : null }
								</span>
							) }
						</li>
					);
				} ) }
			</ol>

			<p className="bs-ds-steps__compact" aria-hidden="true">
				<span className="bs-ds-steps__count">
					{ sprintf(
						/* translators: 1: step number, 2: number of steps. */
						__( 'Step %1$d of %2$d', 'bettershield' ),
						at + 1,
						total
					) }
				</span>
				<span className="bs-ds-steps__name">{ steps[ at ]?.short }</span>
			</p>
		</div>
	);
}
