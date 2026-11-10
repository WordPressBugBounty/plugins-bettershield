/**
 * One question with a few answers.
 *
 * Real radio buttons, in a fieldset with a legend, so the keyboard moves
 * through them the way it moves through any radio group and a screen reader
 * hears the question before the answers. Drawn as the design's radios: a 16
 * circle, brand-filled when chosen, the answer beside it and its note under
 * the answer.
 */

import './Choice.css';

import { useState } from '@wordpress/element';

/** Names each group's radios apart, and ties its help line to it. */
let groups = 0;

/**
 * @param {Object}                    props
 * @param {string}                    props.legend   The question.
 * @param {import('react').ReactNode} props.help     A line under the question.
 * @param {string}                    props.value    The answer chosen.
 * @param {Array}                     props.options  { value, label, note? } each.
 * @param {Function}                  props.onChange Called with the new answer.
 * @param {boolean}                   props.disabled Whether it can be changed.
 * @param {boolean}                   props.quiet    Hide the legend visually.
 */
export default function Choice( { legend, help, value, options, onChange, disabled = false, quiet = false } ) {
	const [ id ] = useState( () => `bs-choice-${ ++groups }` );

	return (
		<fieldset className="bs-ds-choice" aria-describedby={ help ? `${ id }-help` : undefined }>
			<legend className={ quiet ? 'screen-reader-text' : 'bs-ds-choice__legend' }>{ legend }</legend>
			{ help ? (
				<p id={ `${ id }-help` } className="bs-ds-choice__help">
					{ help }
				</p>
			) : null }
			<div className="bs-ds-choice__options">
				{ options.map( ( option ) => {
					const checked = option.value === value;

					return (
						<label
							key={ option.value }
							className={ `bs-ds-choice__option${ checked ? ' is-checked' : '' }${ disabled ? ' is-disabled' : '' }` }
						>
							<input
								type="radio"
								className="bs-ds-choice__input"
								name={ id }
								value={ option.value }
								checked={ checked }
								disabled={ disabled }
								onChange={ () => onChange( option.value ) }
							/>
							<span className="bs-ds-choice__label">
								{ option.label }
								{ option.tip ? <span className="bs-ds-choice__tip">{ option.tip }</span> : null }
							</span>
							{ option.note ? <span className="bs-ds-choice__note">{ option.note }</span> : null }
						</label>
					);
				} ) }
			</div>
		</fieldset>
	);
}
