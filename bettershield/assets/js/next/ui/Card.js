/**
 * The design's Card pattern: a bordered panel with a 60-tall header (an icon
 * tile, the title, then one trailing badge or button), and the Tray that sits
 * a card on a recessed strip with a note and one action under it.
 */

import './Card.css';

import { forwardRef } from '@wordpress/element';
import Icon from './Icon';

export function IconTile( { icon, size = 'sm' } ) {
	return (
		<span className={ `bs-ds-tile bs-ds-tile--${ size }` } aria-hidden="true">
			<Icon name={ icon } size={ 'sm' === size ? 14 : 16 } tone="1" />
		</span>
	);
}

/**
 * @param {Object}  props
 * @param {string}  props.icon     The tile's icon.
 * @param {string}  props.title    The card's name.
 * @param {string}  props.id       The heading's id, for the card's label.
 * @param {boolean} props.line     A rule under the header.
 * @param {boolean} props.auto     Height from the content rather than 60.
 * @param {Object}  props.headingRef Takes the heading, which can then be focused: for a card that moves focus to its own title.
 * @param {*}       props.children The one trailing element.
 */
export function CardHead( { icon, title, id, line = false, auto = false, headingRef, children } ) {
	return (
		<div className={ `bs-ds-card__head${ line ? ' bs-ds-card__head--line' : '' }${ auto ? ' bs-ds-card__head--auto' : '' }` }>
			<IconTile icon={ icon } />
			<h2 className="bs-ds-card__title bs-ds-t14 bs-ds-m bs-ds-c1 bs-ds-nowrap" id={ id } ref={ headingRef } tabIndex={ headingRef ? -1 : undefined }>
				{ title }
			</h2>
			<span className="bs-ds-spacer" />
			{ children }
		</div>
	);
}

/**
 * Forwards its ref to the panel, so a screen can move focus to a card that
 * took the place of the control that asked for it.
 */
export const Card = forwardRef( function Card( { as: Tag = 'section', className = '', children, ...rest }, ref ) {
	return (
		<Tag ref={ ref } className={ `bs-ds-card${ className ? ` ${ className }` : '' }` } { ...rest }>
			{ children }
		</Tag>
	);
} );

/**
 * The design's Section header (26:38559): a label over a list inside a card,
 * with a badge at its far end where the list has a count.
 *
 * @param {Object} props
 * @param {*}      props.children The label.
 * @param {*}      props.aside    The badge or control at its far end.
 * @param {string} props.id       The label's id, for the list it names.
 * @param {string} props.as       The label's element: a heading where the label heads a card of its own.
 */
export function SectionHead( { children, aside = null, id, as: Label = 'span' } ) {
	return (
		<div className="bs-ds-section-head">
			<Label className="bs-ds-t14 bs-ds-m bs-ds-c2" id={ id }>
				{ children }
			</Label>
			{ aside }
		</div>
	);
}

/**
 * @param {Object} props
 * @param {*}      props.note   The strip's note.
 * @param {*}      props.action Its one action.
 */
export function Tray( { note, action, children } ) {
	return (
		<div className="bs-ds-tray">
			{ children }
			<div className="bs-ds-tray__foot">
				<span className="bs-ds-t12 bs-ds-r bs-ds-c2 bs-ds-nowrap">{ note }</span>
				<span className="bs-ds-spacer" />
				{ action }
			</div>
		</div>
	);
}
