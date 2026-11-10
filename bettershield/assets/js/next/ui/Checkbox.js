/**
 * The design's Table/Checkbox (23:20094): a 16 box in a 24 hit area, on the
 * library's CheckboxControl so checked, mixed and keyboard behave natively.
 */

import './Checkbox.css';

import { CheckboxControl } from '@wordpress/components';

/**
 * @param {Object}   props
 * @param {string}   props.label    The accessible name; the box shows no text.
 * @param {string}   props.state    true, false or mixed.
 * @param {Function} props.onChange Called with the new checked state.
 * @param {boolean}  props.disabled Whether it can be changed.
 * @param {string}   props.role     The table role of the cell it sits in, if any.
 */
export default function Checkbox( { label, state, onChange, disabled = false, role } ) {
	return (
		<span className="bs-ds-check" role={ role }>
			<CheckboxControl
				__nextHasNoMarginBottom
				aria-label={ label }
				checked={ true === state || 'true' === state }
				indeterminate={ 'mixed' === state }
				disabled={ disabled }
				onChange={ onChange }
			/>
		</span>
	);
}
