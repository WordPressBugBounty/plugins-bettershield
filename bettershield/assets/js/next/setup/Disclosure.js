/**
 * A part of a step that is folded until it is asked for: one Ghost button
 * naming it, with a short summary of what it holds, and its content under it.
 *
 * The content stays drawn while folded, only hidden, so what a part holds
 * keeps the owner's answers and the save the step's Apply calls, whether or
 * not it was ever opened.
 */

import './Disclosure.css';

import { useId } from '@wordpress/element';
import Icon from '../ui/Icon';

/**
 * @param {Object}                    props
 * @param {string}                    props.label    What the part is.
 * @param {*}                         props.summary  A short line of what it holds, after the label.
 * @param {boolean}                   props.open     Whether it is open.
 * @param {Function}                  props.onToggle Called with the new state.
 * @param {string}                    props.className Extra classes.
 * @param {import('react').ReactNode} props.children What it holds.
 */
export default function Disclosure( { label, summary = null, open, onToggle, className = '', children } ) {
	const id = `bs-ds-setup-fold-${ useId().replace( /[^\w-]/g, '' ) }`;

	return (
		<div className={ `bs-ds-setup-fold${ open ? ' is-open' : '' }${ className ? ` ${ className }` : '' }` }>
			<button type="button" className="bs-ds-setup-fold__toggle" aria-expanded={ open } aria-controls={ id } onClick={ () => onToggle( ! open ) }>
				<span className="bs-ds-setup-fold__label">{ label }</span>
				{ summary ? <span className="bs-ds-setup-fold__summary">{ summary }</span> : null }
				<Icon name="chevron-down" size={ 16 } tone="3" className="bs-ds-setup-fold__chevron" />
			</button>
			<div id={ id } className="bs-ds-setup-fold__body" hidden={ ! open }>
				{ children }
			</div>
		</div>
	);
}
