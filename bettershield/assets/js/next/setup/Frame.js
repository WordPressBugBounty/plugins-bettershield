/**
 * One step's page: a card in two columns, with a strip along its foot.
 *
 * The left column holds the step: its number of how many, its heading (which
 * takes focus when the step opens, so it carries the id the panel is labeled
 * by), the line under it, the body, and the step's way on at the column's
 * foot — Back, then its one Primary button. The right column is a picture of
 * what the step is about, drawn from the site's own answers where it can be;
 * it repeats what the left column says, so it is hidden from assistive
 * technology. The strip under the card holds what is quieter than the way
 * on: a step's own line, Need help? and the step's Skip.
 */

import './Frame.css';

import { __, sprintf } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import brand, { helpLinks } from './brand';
import { useSetup } from './context';
import Visual from './Visual';

/**
 * The step's place in the setup, as the design writes it: "02 / 05".
 *
 * @param {number} at    The step's index.
 * @param {number} total How many steps this site has.
 * @return {string} The count.
 */
export function stepCount( at, total ) {
	const pad = ( number ) => String( number ).padStart( 2, '0' );

	return sprintf(
		/* translators: 1: this step's number, 2: the number of steps. Both are two digits. */
		__( '%1$s / %2$s', 'bettershield' ),
		pad( at + 1 ),
		pad( total )
	);
}

/**
 * The line in the strip under a step's card, for a step that does not give
 * its own: what the step will and will not do to the site.
 *
 * @param {string} step The step on screen.
 * @return {string} The line, or nothing.
 */
export function stripNote( step ) {
	switch ( step ) {
		case 'coexistence':
			return sprintf( /* translators: %s: the plugin's name. */ __( 'Your settings come over to %s before anything is switched off.', 'bettershield' ), brand() );
		case 'ready':
			return __( 'Nothing installs until you switch it on.', 'bettershield' );
		default:
			return '';
	}
}

/**
 * @param {Object}                    props
 * @param {string}                    props.title    The step's heading.
 * @param {string}                    props.subtitle One line under it.
 * @param {import('react').ReactNode} props.badge    Something before the heading.
 * @param {import('react').ReactNode} props.children The body.
 * @param {import('react').ReactNode} props.footer   The way on, usually a Footer.
 * @param {string}                    props.variant  'hero' for the first step, 'wide' for the hub.
 * @param {string[]}                  props.inline   Write keys whose failure the step shows beside its own control.
 * @param {import('react').ReactNode} props.aside    Something beside the heading, such as the score.
 * @param {boolean}                   props.quietAside Read the aside out only: the picture draws it.
 * @param {import('react').ReactNode} props.note     The strip's line, where the step's default (stripNote) is not it.
 */
/**
 * The strip's line on the steps that open the setup: the first scan as it
 * runs, then its score with a way to see what it found.
 *
 * @param {Object} props
 * @param {Object} props.state The setup's state.
 * @param {string} props.findings The Findings screen.
 * @return {?import('react').ReactNode} The line, or nothing before the first read.
 */
function ScanLine( { state, findings } ) {
	if ( ! state ) {
		return null;
	}

	if ( state.first_scan?.running ) {
		return (
			<>
				<span className="bs-ds-setup__scan-spin" aria-hidden="true" />
				<span>{ __( 'Your first scan is running. You can carry on while it works.', 'bettershield' ) }</span>
			</>
		);
	}

	const score = state.score || {};

	if ( undefined === score.score ) {
		return null;
	}

	return (
		<>
			<Icon name="list-checks" size={ 14 } tone="2" />
			<span>
				{ sprintf(
					/* translators: 1: the site's security score out of 100, 2: its letter grade. */
					__( 'First scan done: %1$d out of 100, grade %2$s.', 'bettershield' ),
					score.score,
					score.grade || '–'
				) }{ ' ' }
				{ findings ? (
					<a className="bs-ds-setup__strip-link" href={ findings } target="_blank" rel="noopener noreferrer">
						{ __( 'See what it found', 'bettershield' ) }
						<span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span>
					</a>
				) : null }
			</span>
		</>
	);
}

/**
 * What a refusal offers beside it: Check Now for the way back in, which runs
 * the check and sends the refused request again, or Recovery where the check
 * can't be run from here (#2992).
 *
 * @param {Object}      error The refusal on screen.
 * @param {string|null} busy  The write in progress.
 * @return {*} The button, or null.
 */
function errorAction( error, busy ) {
	if ( error.checkNow ) {
		return (
			<Button type="secondary" size="sm" disabled={ null !== busy } onClick={ error.checkNow }>
				{ __( 'Check Now', 'bettershield' ) }
			</Button>
		);
	}

	if ( error.url ) {
		return (
			<Button type="secondary" size="sm" href={ error.url }>
				{ __( 'Open Recovery', 'bettershield' ) }
			</Button>
		);
	}

	return null;
}

export default function Frame( { title, subtitle, badge, children, footer, variant, inline = [], aside = null, quietAside = false, note = null } ) {
	const { headingRef, error, notice, current, visible = [], state, links = {}, busy } = useSetup();
	const scan = ! note && [ 'welcome', 'protect' ].includes( current ) ? <ScanLine state={ state } findings={ links.findings } /> : null;
	const line = note || stripNote( current );
	const shown = error && ! inline.includes( error.key ) ? error : null;
	const at = visible.indexOf( current );

	// A Footer is drawn in two places: its buttons at the column's foot, and
	// its Skip and Need help? in the strip under the card.
	const split = footer && footer.type === Footer;

	return (
		<div className={ `bs-ds-setup__stage${ variant ? ` bs-ds-setup__stage--${ variant }` : '' }` }>
			<div className="bs-ds-setup__card">
				<div className="bs-ds-setup__content">
					<div className={ `bs-ds-setup__head${ variant ? ` bs-ds-setup__head--${ variant }` : '' }${ aside && ! quietAside ? ' is-aside' : '' }` }>
						<div className="bs-ds-setup__head-text">
							{ at >= 0 ? (
								<p className="bs-ds-setup__count" aria-hidden="true">
									{ stepCount( at, visible.length ) }
								</p>
							) : null }
							{ badge }
							<h1 id="bs-setup-title" className="bs-ds-setup__title" ref={ headingRef } tabIndex={ -1 }>
								{ title }
							</h1>
							{ subtitle ? <p className="bs-ds-setup__subtitle">{ subtitle }</p> : null }
						</div>
						{ aside ? <div className={ `bs-ds-setup__head-aside${ quietAside ? ' screen-reader-text' : '' }` }>{ aside }</div> : null }
					</div>

					<div className={ `bs-ds-setup__body${ variant ? ` bs-ds-setup__body--${ variant }` : '' }` }>
						{ notice ? <Alert layout="default" tone="success" live desc={ notice } /> : null }

						{ children }

						{ shown ? (
							<div className="bs-ds-setup__error" role="alert">
								<Alert layout="default" tone="error" desc={ shown.message } actions={ errorAction( shown, busy ) } />
							</div>
						) : null }
					</div>

					{ split ? <FooterActions { ...footer.props } /> : footer }
				</div>

				<Visual step={ current } />
			</div>

			<div className="bs-ds-setup__strip">
				{ scan ? (
					<p className="bs-ds-setup__strip-note" aria-live="polite">
						{ scan }
					</p>
				) : null }
				{ ! scan && line ? (
					<p className="bs-ds-setup__strip-note">
						<Icon name="shield-check" size={ 14 } tone="2" />
						<span>{ line }</span>
					</p>
				) : null }
				{ split ? <FooterStrip { ...footer.props } /> : null }
				{ ! split && helpLinks() ? (
					<div className="bs-ds-setup__foot-start bs-ds-setup__help-line">
						<HelpLink />
					</div>
				) : null }
			</div>
		</div>
	);
}

/** Where help is, on the page that sells nothing. */
export const SUPPORT_URL = 'https://bettershield.ai/support/';

/**
 * A way to reach us from every step: a plain link to the support page, in a
 * new tab so the setup stays where it was. No chat widget here: that would
 * load someone else's script on the owner's site.
 */
export function HelpLink() {
	// Left out where an owner's label asks for this plugin's links to go.
	if ( ! helpLinks() ) {
		return null;
	}

	return (
		<a className="bs-ds-setup__help" href={ SUPPORT_URL } target="_blank" rel="noopener noreferrer">
			{ __( 'Need help?', 'bettershield' ) }
			<span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span>
		</a>
	);
}

/**
 * The step's way on, at the foot of its column: Back, anything the step adds,
 * and its one Primary button, which takes the room that is left.
 *
 * @param {Object}                    props
 * @param {Object}                    props.primary  { label, onClick, busy, disabled, icon }; icon false for none.
 * @param {boolean}                   props.locked   Hold every control while the step works on its own.
 * @param {import('react').ReactNode} props.children Anything else, before the Primary.
 */
function FooterActions( { primary, locked = false, children } ) {
	const { canGoBack, back, busy } = useSetup();
	const working = null !== busy || locked;

	return (
		<div className="bs-ds-setup__foot">
			{ canGoBack ? (
				<Button type="secondary" size="md" className="bs-ds-setup__back" disabled={ working } onClick={ back }>
					{ __( 'Back', 'bettershield' ) }
				</Button>
			) : null }
			{ children }
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
					{ /* On points the way the page reads, so it turns over in a right-to-left one. A
					     Primary that leaves the page says so instead, and one that ends a choice has none. */ }
					{ false === primary.icon ? null : (
						<Icon name={ primary.icon || 'arrow-right' } size={ 16 } tone="onbrand" className={ primary.icon ? '' : 'bs-ds-setup__flip' } />
					) }
				</Button>
			) : null }
		</div>
	);
}

/**
 * What the strip holds of a Footer: Need help?, then the step's Skip at the
 * strip's far end.
 *
 * @param {Object}  props
 * @param {Object}  props.skip   { label, onClick } for a skip that is not simply "next".
 * @param {boolean} props.noSkip Leave Skip out.
 * @param {boolean} props.locked Hold every control while the step works on its own.
 */
function FooterStrip( { skip, noSkip = false, locked = false } ) {
	const { skip: skipStep, busy } = useSetup();
	const working = null !== busy || locked;

	return (
		<div className="bs-ds-setup__foot-start">
			<HelpLink />
			{ noSkip ? null : (
				<Button type="ghost" size="sm" className="bs-ds-setup__skip" disabled={ working } onClick={ skip?.onClick || skipStep }>
					{ skip?.label || __( 'Skip', 'bettershield' ) }
				</Button>
			) }
		</div>
	);
}

/**
 * A step's footer. Frame draws it in two parts (see FooterActions and
 * FooterStrip); drawn anywhere else, it is both, one after the other.
 *
 * @param {Object} props See FooterActions and FooterStrip.
 */
export function Footer( props ) {
	return (
		<>
			<FooterActions { ...props } />
			<FooterStrip { ...props } />
		</>
	);
}
