/**
 * A form field, drawn the design's way: the library's own control underneath
 * (so its label, id, help text and keyboard behavior stay what WordPress
 * gives), and the design's look on top, taken from Input/Search (2:4168):
 * 32 tall, radius 8, the control border and its shadow, a 2px brand ring on
 * focus, the label a 12 medium line over it and the help a 12 line under it.
 *
 * One component with a `kind` rather than one per control, so every field on
 * every screen comes from the same place.
 */

import './Field.css';

import { BaseControl, CheckboxControl, RadioControl, SelectControl, TextControl } from '@wordpress/components';
import { forwardRef, useId } from '@wordpress/element';

/**
 * @param {Object}   props
 * @param {string}   props.kind      text (the default), select, textarea, radio, check or checks.
 * @param {*}        props.label     The field's name.
 * @param {*}        props.help      A line under it.
 * @param {string}   props.error     What is wrong with what was typed, said under it.
 * @param {string}   props.width     sm (a number or a short code), md, or full (the default).
 * @param {*}        props.value     text, select, textarea: the value. radio: the chosen option. checks: the chosen options.
 * @param {boolean}  props.checked   check: whether it is ticked.
 * @param {Array}    props.options   select, radio, checks: [{ value, label }].
 * @param {Function} props.onChange  Called with the new value (checks: the new list; check: true or false).
 * @param {string}   props.className Extra classes.
 *
 * checks: with no label, pass `aria-labelledby` naming the title the group
 * sits under, or a screen reader hears its options under no name at all.
 */
function Field( { kind = 'text', label, help, error = '', width = 'full', value, checked, options = [], onChange, className = '', ...rest }, ref ) {
	const made = useId().replace( /[^\w-]/g, '' );
	const errorId = error ? `bs-ds-field-${ made }-error` : undefined;
	// The library names a control's help `<id>__help` and points the control
	// at it; naming the control here lets the error join that link rather
	// than replace it, and lets no error leave it alone.
	const id = rest.id || `bs-ds-field-${ made }`;
	const helpId = help ? `${ id }__help` : '';
	const described = [ rest[ 'aria-describedby' ], helpId, errorId ].filter( Boolean ).join( ' ' ) || undefined;
	const linked = { id, 'aria-describedby': described };
	const classes = [ 'bs-ds-field', `bs-ds-field--${ kind }`, `bs-ds-field--${ width }`, error ? 'is-invalid' : '', className ].filter( Boolean ).join( ' ' );
	const shared = { label, help };
	let control;

	if ( 'select' === kind ) {
		control = <SelectControl { ...shared } __nextHasNoMarginBottom __next40pxDefaultSize value={ value } options={ options } onChange={ onChange } { ...rest } { ...linked } />;
	} else if ( 'textarea' === kind ) {
		/*
		 * The library's TextareaControl reads no id of ours: it names its own
		 * for the label and the help and puts ours on the textarea, so the
		 * label named nothing and the help link pointed nowhere. Drawn as its
		 * BaseControl and textarea instead, under the one id.
		 */
		control = (
			<BaseControl __nextHasNoMarginBottom id={ id } label={ label } help={ help }>
				<textarea
					className="components-textarea-control__input"
					rows={ 4 }
					ref={ ref }
					value={ value ?? '' }
					onChange={ ( event ) => onChange && onChange( event.target.value ) }
					{ ...rest }
					{ ...linked }
				/>
			</BaseControl>
		);
	} else if ( 'radio' === kind ) {
		control = <RadioControl __nextHasNoMarginBottom label={ label } help={ help } selected={ value } options={ options } onChange={ onChange } { ...rest } />;
	} else if ( 'check' === kind ) {
		control = <CheckboxControl { ...shared } __nextHasNoMarginBottom checked={ Boolean( checked ) } onChange={ onChange } { ...rest } />;
	} else if ( 'checks' === kind ) {
		const chosen = Array.isArray( value ) ? value : [];

		control = (
			<fieldset className="bs-ds-field__set" aria-labelledby={ rest[ 'aria-labelledby' ] } aria-describedby={ described }>
				{ label ? <legend className="bs-ds-field__legend">{ label }</legend> : null }
				<div className="bs-ds-field__options">
					{ options.map( ( option ) => (
						<CheckboxControl
							key={ option.value }
							__nextHasNoMarginBottom
							label={ option.label }
							checked={ chosen.includes( option.value ) }
							disabled={ rest.disabled || option.disabled }
							onChange={ ( on ) => onChange( on ? [ ...chosen, option.value ] : chosen.filter( ( item ) => item !== option.value ) ) }
						/>
					) ) }
				</div>
				{ help ? (
					<p className="bs-ds-field__help" id={ helpId }>
						{ help }
					</p>
				) : null }
			</fieldset>
		);
	} else {
		control = (
			<TextControl
				{ ...shared }
				__nextHasNoMarginBottom
				ref={ ref }
				__next40pxDefaultSize
				value={ value ?? '' }
				onChange={ onChange }
				aria-invalid={ error ? 'true' : undefined }
				{ ...rest }
				{ ...linked }
			/>
		);
	}

	return (
		<div className={ classes }>
			{ control }
			{ /* An alert as well as a description: the description is read
			     only on the field, and an error found by Save appears while
			     focus is on the button. */ }
			{ error ? (
				<p className="bs-ds-field__error" id={ errorId } role="alert">
					{ error }
				</p>
			) : null }
		</div>
	);
}

// Forwarded to the input, so a screen can put focus in the field it opened.
export default forwardRef( Field );

/**
 * Fields side by side, wrapping under each other when there is no room: a
 * limit's three numbers, a name beside an address.
 *
 * @param {Object} props
 * @param {*}      props.children The fields, and the button that acts on them.
 * @param {string} props.align    end (the default) lines the fields and their button up along the bottom; start lines them up along the top, for fields that carry a line under them.
 */
export function FieldRow( { children, align = 'end' } ) {
	return <div className={ `bs-ds-fieldrow${ 'start' === align ? ' bs-ds-fieldrow--start' : '' }` }>{ children }</div>;
}
