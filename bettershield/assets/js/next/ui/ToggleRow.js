/**
 * The design's List item / Toggle (26:38447): a setting's name and its
 * switch, on the library's FormToggle so it is a real checkbox underneath.
 */

import './ToggleRow.css';

import { FormToggle } from '@wordpress/components';
import { useState } from '@wordpress/element';

let made = 0;

/**
 * @param {Object}   props
 * @param {string}   props.label    The setting's name.
 * @param {boolean}  props.checked  The position the switch is drawn in.
 * @param {boolean}  props.disabled Whether it can be pressed at all.
 * @param {boolean}  props.isBusy   Whether its change is on its way: drawn
 *                                  dimmed, and a second press is not taken.
 *                                  It stays enabled, so focus stays on it.
 * @param {Function} props.onChange Called on a press.
 */
export default function ToggleRow( { label, checked, disabled = false, isBusy = false, onChange } ) {
	const [ id ] = useState( () => `bs-ds-toggle-${ ++made }` );

	return (
		<div className={ isBusy ? 'bs-ds-li is-busy' : 'bs-ds-li' } aria-busy={ isBusy ? 'true' : undefined }>
			<label className="bs-ds-li__label bs-ds-t14 bs-ds-r bs-ds-c1" htmlFor={ id }>
				{ label }
			</label>
			<FormToggle id={ id } className="bs-ds-toggle" checked={ checked } disabled={ disabled } onChange={ isBusy ? () => {} : onChange } />
		</div>
	);
}
