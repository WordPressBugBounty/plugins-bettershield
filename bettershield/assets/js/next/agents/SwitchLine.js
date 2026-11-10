/**
 * A switch with its own words beside it, under a row that has a title of
 * its own: a step on Connect, whose switch carries the step's own name
 * ("Let AI assistants see security info"), and a credential on Surface.
 *
 * The design's Toggle (6:10487) leads, as the library's ToggleControl drew
 * it, and the whole line is its label, so the words are both its name and
 * somewhere to press. A line about it, when the switch cannot be thrown yet,
 * sits under the words and describes it.
 */

import './SwitchLine.css';

import { useId } from '@wordpress/element';
import { Toggle } from '../ui/Setting';

/**
 * @param {Object}   props
 * @param {*}        props.label    The switch's words.
 * @param {boolean}  props.checked  Whether it is on.
 * @param {boolean}  props.disabled Whether it can be changed.
 * @param {*}        props.help     A line under it: why it cannot be changed yet.
 * @param {Function} props.onChange Called with true or false, as the library's ToggleControl was.
 * @param {*}        props.children What the switch said after a save ("Saved."), at the line's end.
 */
export default function SwitchLine( { label, checked, disabled = false, help = null, onChange, children = null } ) {
	const helpId = `bs-ds-switch-${ useId().replace( /[^\w-]/g, '' ) }-help`;

	return (
		<div className="bs-ds-switch">
			<div className="bs-ds-switch__row">
				<label className="bs-ds-switch__line">
					<Toggle
						checked={ checked }
						disabled={ disabled }
						describedBy={ help ? helpId : undefined }
						onChange={ ( event ) => onChange( Boolean( event && event.target ? event.target.checked : event ) ) }
					/>
					<span className="bs-ds-switch__label">{ label }</span>
				</label>
				{ children }
			</div>
			{ help ? (
				<p className="bs-ds-switch__help" id={ helpId }>
					{ help }
				</p>
			) : null }
		</div>
	);
}
