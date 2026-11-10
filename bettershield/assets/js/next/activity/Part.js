/**
 * One part of an open incident (its evidence, the activity around it, the
 * explanation, the response), as a card under the incident's row: the
 * design's card header, its title a heading at the level the incident's own
 * parts take, and the part's body under it.
 */

import './Part.css';

import { useId } from '@wordpress/element';
import { Card, IconTile } from '../ui/Card';

/**
 * @param {Object} props
 * @param {string} props.icon       The header tile's icon.
 * @param {*}      props.title      The part's name.
 * @param {Object} props.headingRef Takes the heading, where focus is put back on it after an action.
 * @param {*}      props.trailing   The header's one button.
 * @param {string} props.className  Extra classes.
 * @param {*}      props.children   The part's body.
 */
export default function Part( { icon, title, headingRef = null, trailing = null, className = '', children } ) {
	const id = `bs-ds-part-${ useId().replace( /[^\w-]/g, '' ) }`;

	return (
		<Card className={ `bs-ds-part${ className ? ` ${ className }` : '' }` } aria-labelledby={ id }>
			<div className="bs-ds-card__head bs-ds-part__head">
				<IconTile icon={ icon } />
				<h3 className="bs-ds-card__title bs-ds-t14 bs-ds-m bs-ds-c1 bs-ds-part__title" id={ id } ref={ headingRef } tabIndex={ headingRef ? -1 : undefined }>
					{ title }
				</h3>
				<span className="bs-ds-spacer" />
				{ trailing }
			</div>
			<div className="bs-ds-part__body">{ children }</div>
		</Card>
	);
}
