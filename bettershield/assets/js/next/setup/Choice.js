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
 * @param {boolean}                   props.inline   The answers on one line, as the design's coexistence card
 *                                                   draws them: each answer's short words (`short`) on screen
 *                                                   with its full words read out, and the chosen one's note
 *                                                   under the line.
 */
export default function Choice( { legend, help, value, options, onChange, disabled = false, quiet = false, inline = false } ) {
	const [ id ] = useState( () => `bs-choice-${ ++groups }` );

	return (
		<fieldset className={ `bs-ds-choice${ inline ? ' is-inline' : '' }` } aria-describedby={ help ? `${ id }-help` : undefined }>
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
								{ inline && option.short ? (
									<>
										<span aria-hidden="true">{ option.short }</span>
										<span className="screen-reader-text">{ option.label }</span>
									</>
								) : (
									option.label
								) }
								{ option.tip ? <span className="bs-ds-choice__tip">{ option.tip }</span> : null }
							</span>
							{ option.note ? <span className={ `bs-ds-choice__note${ inline ? ' screen-reader-text' : '' }` }>{ option.note }</span> : null }
						</label>
					);
				} ) }
			</div>
			{ inline ? <ChosenNote options={ options } value={ value } /> : null }
		</fieldset>
	);
}

/**
 * The chosen answer's note, under a line of answers. Each answer's note is
 * read out with the answer itself, so this one is for the eye.
 *
 * @param {Object} props
 * @param {Array}  props.options The answers.
 * @param {string} props.value   The answer chosen.
 */
function ChosenNote( { options, value } ) {
	const chosen = options.find( ( option ) => option.value === value );
	// The first answer's note sits under its words, past the radio, so
	// "Recommended" reads as that answer's.
	const first = chosen === options[ 0 ];

	return chosen && chosen.note ? (
		<p key={ value } className={ `bs-ds-choice__chosen${ first ? ' is-first' : '' }` } aria-hidden="true">
			{ chosen.note }
		</p>
	) : null;
}
