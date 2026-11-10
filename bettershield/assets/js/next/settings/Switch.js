/**
 * A switch with its own words beside it, at the end of a settings row.
 *
 * A row names the setting ("Mute everything"); the switch says what turning
 * it on does ("Mute all alerts"), and other lines on the screen point at the
 * switch by those words. The words are the switch's label and are clicked
 * with it, as the library's ToggleControl drew them; the switch itself is
 * the design's Toggle (the same FormToggle, the same rules as ToggleRow).
 */

import './Switch.css';
// The switch is drawn to the design's size by the rules ToggleRow carries.
import '../ui/ToggleRow.css';

import { FormToggle } from '@wordpress/components';
import { useId } from '@wordpress/element';

/**
 * @param {Object}   props
 * @param {*}        props.label       What the switch does.
 * @param {boolean}  props.checked     Whether it is on.
 * @param {boolean}  props.disabled    Whether it can be changed.
 * @param {Function} props.onChange    Called with true or false.
 * @param {string}   props.describedBy The id of a line that says more about it.
 */
export default function Switch( { label, checked, disabled = false, onChange, describedBy } ) {
	const id = `bs-ds-endswitch-${ useId().replace( /[^\w-]/g, '' ) }`;

	return (
		<label className="bs-ds-endswitch" htmlFor={ id }>
			<span className="bs-ds-endswitch__label">{ label }</span>
			<FormToggle
				id={ id }
				className="bs-ds-toggle"
				checked={ Boolean( checked ) }
				disabled={ disabled }
				// Called with on or off, as the library's ToggleControl was.
				onChange={ ( event ) => onChange( Boolean( event && event.target ? event.target.checked : event ) ) }
				aria-describedby={ describedBy }
			/>
		</label>
	);
}
