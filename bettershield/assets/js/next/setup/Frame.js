/**
 * One step's page: its heading, its body and its footer.
 *
 * The heading takes focus when the step opens, so it carries the id the panel
 * is labeled by. The footer is the same on every step that has one — Back on
 * the left, Skip and the step's own action on the right — so the way forward
 * is always in the same place and never needs finding. That action is the
 * step's one Primary button; everything inside the step is quieter.
 */

import './Frame.css';

import { __ } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import { useSetup } from './context';

/**
 * @param {Object}                    props
 * @param {string}                    props.title    The step's heading.
 * @param {string}                    props.subtitle One line under it.
 * @param {import('react').ReactNode} props.badge    Something before the heading.
 * @param {import('react').ReactNode} props.children The body.
 * @param {import('react').ReactNode} props.footer   The footer, usually a Footer.
 * @param {string}                    props.variant  'hero' for the centered first step.
 * @param {string[]}                  props.inline   Write keys whose failure the step shows beside its own control.
 * @param {import('react').ReactNode} props.aside    Something at the heading's other end, such as the score.
 */
export default function Frame( { title, subtitle, badge, children, footer, variant, inline = [], aside = null } ) {
	const { headingRef, error, notice } = useSetup();
	const shown = error && ! inline.includes( error.key ) ? error : null;

	return (
		<>
			<div className={ `bs-ds-setup__head${ variant ? ` bs-ds-setup__head--${ variant }` : '' }${ aside ? ' is-aside' : '' }` }>
				<div className="bs-ds-setup__head-text">
					{ badge }
					<h1 id="bs-setup-title" className="bs-ds-setup__title" ref={ headingRef } tabIndex={ -1 }>
						{ title }
					</h1>
					{ subtitle ? <p className="bs-ds-setup__subtitle">{ subtitle }</p> : null }
				</div>
				{ aside ? <div className="bs-ds-setup__head-aside">{ aside }</div> : null }
			</div>

			<div className={ `bs-ds-setup__body${ variant ? ` bs-ds-setup__body--${ variant }` : '' }` }>
				{ notice ? <Alert layout="default" tone="success" live desc={ notice } /> : null }

				{ children }

				{ shown ? (
					<div className="bs-ds-setup__error" role="alert">
						<Alert layout="default" tone="error" desc={ shown.message } />
					</div>
				) : null }
			</div>

			{ footer }
		</>
	);
}

/**
 * @param {Object}                    props
 * @param {Object}                    props.skip     { label, onClick } for a skip that is not simply "next".
 * @param {boolean}                   props.noSkip   Leave Skip out.
 * @param {Object}                    props.primary  { label, onClick, busy, disabled }.
 * @param {boolean}                   props.locked   Hold every control while the step works on its own.
 * @param {import('react').ReactNode} props.children Anything else, before the actions.
 */
export function Footer( { skip, noSkip = false, primary, locked = false, children } ) {
	const { canGoBack, back, skip: skipStep, busy } = useSetup();
	const working = null !== busy || locked;

	return (
		<div className="bs-ds-setup__foot">
			<div className="bs-ds-setup__foot-start">
				{ canGoBack ? (
					<Button type="ghost" size="md" className="bs-ds-setup__back" disabled={ working } onClick={ back }>
						{ /* Back points the way the page reads, so it turns over in a right-to-left one. */ }
						<Icon name="arrow-left" size={ 16 } tone="1" className="bs-ds-setup__flip" />
						{ __( 'Back', 'bettershield' ) }
					</Button>
				) : null }
			</div>

			<div className="bs-ds-setup__foot-end">
				{ children }
				{ noSkip ? null : (
					<Button type="ghost" size="md" className="bs-ds-setup__skip" disabled={ working } onClick={ skip?.onClick || skipStep }>
						{ skip?.label || __( 'Skip', 'bettershield' ) }
					</Button>
				) }
				{ primary ? (
					<Button
						type="primary"
						size="md"
						className="bs-ds-setup__primary"
						isBusy={ primary.busy }
						disabled={ working || primary.disabled }
						onClick={ primary.onClick }
					>
						{ primary.label }
					</Button>
				) : null }
			</div>
		</div>
	);
}
