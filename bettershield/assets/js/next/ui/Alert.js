/**
 * The design's Alert (component 23:21210), in its three layouts:
 *
 * - Compact: one 36-tall line, the title then the description. Page level,
 *   directly under the hero or the status strip, at most one.
 * - Default: a box whose description wraps, with room for actions under it.
 *   Inside a card, when the message needs reading or acting on.
 * - Banner: a full-width tinted line with no border, between the groups of a
 *   table or under a card's header.
 *
 * The classic callout's tones are read too (safe, caution), so a message
 * moves over without being re-toned by hand.
 */

import './Alert.css';

import { __ } from '@wordpress/i18n';
import Icon, { NOTE_ICON } from './Icon';

const ICONS = {
	success: [ 'circle-check', 'ok' ],
	warning: [ 'triangle-alert', 'warning' ],
	info: [ NOTE_ICON, 'info' ],
	error: [ 'circle-x', 'error' ],
	neutral: [ 'bell', '2' ],
};

const ALIASES = { safe: 'success', good: 'success', caution: 'warning' };

/**
 * @param {Object}   props
 * @param {string}   props.tone      success, warning, info, error or neutral.
 * @param {string}   props.layout    compact, default or banner.
 * @param {string}   props.title     The title.
 * @param {*}        props.desc      The description.
 * @param {*}        props.children  The description, written between the tags instead (Default layout).
 * @param {Function} props.onDismiss Dismisses it; none, and there is no dismiss.
 * @param {*}        props.actions   Controls: after the text on one line, or under it in the Default layout.
 * @param {*}        props.live      Announce it: true for an action just taken, 'alert' for one that was refused.
 * @param {Object}   props.alertRef  Takes the alert's element, to move focus to it.
 * @param {string}   props.icon      An icon in place of the tone's own.
 */
export default function Alert( { tone = 'success', layout = 'compact', title, desc, children, onDismiss, actions, live = false, alertRef, icon: iconName = '' } ) {
	const known = ALIASES[ tone ] || ( ICONS[ tone ] ? tone : 'info' );
	const [ icon, iconTone ] = ICONS[ known ];
	const description = desc || children || null;
	const role = live ? ( 'alert' === live ? 'alert' : 'status' ) : undefined;
	const shape = [ 'default', 'banner' ].includes( layout ) ? layout : 'compact';
	const classes = `bs-ds-alert bs-ds-alert--${ known }${ 'compact' === shape ? '' : ` bs-ds-alert--${ shape }` }`;
	const dismiss = onDismiss ? (
		<button type="button" className="bs-ds-alert__dismiss" aria-label={ __( 'Dismiss', 'bettershield' ) } onClick={ onDismiss }>
			<Icon name="x" size={ 16 } tone="2" />
		</button>
	) : null;

	if ( 'default' === shape ) {
		return (
			<div ref={ alertRef } tabIndex={ alertRef ? -1 : undefined } className={ classes } role={ role }>
				<Icon name={ iconName || icon } size={ 16 } tone={ iconTone } className="bs-ds-alert__icon" />
				<div className="bs-ds-alert__body">
					{ title ? <p className="bs-ds-alert__title">{ title }</p> : null }
					{ description ? <div className="bs-ds-alert__desc">{ description }</div> : null }
					{ actions ? <div className="bs-ds-alert__actions">{ actions }</div> : null }
				</div>
				{ dismiss }
			</div>
		);
	}

	return (
		<div ref={ alertRef } tabIndex={ alertRef ? -1 : undefined } className={ classes } role={ role }>
			<Icon name={ iconName || icon } size={ 16 } tone={ iconTone } />
			<p className="bs-ds-alert__text">
				{ title ? <span className="bs-ds-alert__title">{ title }</span> : null }
				{ description ? <span className="bs-ds-alert__desc">{ description }</span> : null }
			</p>
			{ actions }
			{ dismiss }
		</div>
	);
}
