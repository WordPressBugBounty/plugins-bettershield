/**
 * A value to copy (an address, a prompt, a confirmation shown once) beside
 * the button that copies it, and what pressing it did.
 *
 * In the design's type rather than monospace: the frames use one family
 * everywhere. A one-line value is a read-only field the reader can select
 * into; a block is a focusable region that keeps its line breaks.
 */

import './CopyField.css';

import { useId, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { copyToClipboard } from '../../ui/copy';
import Button from './Button';

/**
 * The copy button on its own, saying what happened beside it rather than on
 * it, so its accessible name stays its name.
 *
 * @param {Object}  props
 * @param {string}  props.text    What is copied.
 * @param {string}  props.label   The button's words.
 * @param {string}  props.type    The button's type; secondary by default.
 * @param {boolean} props.inPlace Show "Copied" on the button itself, at its own width; its name stays the label.
 */
export function CopyButton( { text, label, type = 'secondary', inPlace = false } ) {
	const [ state, setState ] = useState( 'idle' );

	const copy = () =>
		copyToClipboard( text ).then(
			() => {
				setState( 'copied' );
				// The words beside the button are what announced it; they
				// go back once it has been heard.
				window.setTimeout( () => setState( 'idle' ), 2000 );
			},
			// A failure stays: it is a thing to act on, not a flash.
			() => setState( 'failed' )
		);

	let outcome = null;

	if ( 'copied' === state ) {
		outcome = __( 'Copied', 'bettershield' );
	} else if ( 'failed' === state ) {
		outcome = __( 'Could not copy — select it by hand', 'bettershield' );
	}

	const copied = 'copied' === state;

	/*
	 * Beside a field the note took a place of its own and pushed the button
	 * under the field. There the button says it, and the other word sits
	 * unseen in the same cell, so the button keeps the longer one's width.
	 */
	const doneWord = __( 'Copied', 'bettershield' );
	const words = inPlace ? (
		<span className="bs-ds-copybutton__words" data-other={ copied ? label : doneWord }>
			<span>{ copied ? doneWord : label }</span>
		</span>
	) : (
		label
	);

	return (
		<span className="bs-ds-copybutton">
			{ /* On a primary button the icon takes the on-brand ink, as the
			     site's own Copy link does: gray read as switched off. */ }
			<Button
				type={ type }
				size="sm"
				icon={ inPlace && copied ? 'check' : 'copy' }
				iconTone={ 'primary' === type ? 'onbrand' : '2' }
				aria-label={ inPlace ? label : undefined }
				onClick={ copy }
			>
				{ words }
			</Button>
			<span className={ inPlace && 'failed' !== state ? 'bs-ds-copied screen-reader-text' : 'bs-ds-copied' } role="status">
				{ outcome }
			</span>
		</span>
	);
}

/**
 * @param {Object}  props
 * @param {string}  props.label     What the value is.
 * @param {string}  props.value     The value.
 * @param {boolean} props.multiline A block of lines rather than one line.
 * @param {string}  props.copyLabel The button's words; "Copy" by default.
 * @param {string}  props.dir       The value's direction: "ltr" for an address,
 *                                  a key or code; "auto" for words in the
 *                                  reader's language, such as a message.
 */
export default function CopyField( { label, value, multiline = false, copyLabel, dir = 'ltr' } ) {
	const text = value || '';
	const labelId = `bs-ds-copy-${ useId().replace( /[^\w-]/g, '' ) }`;

	return (
		<div className={ `bs-ds-copyfield${ multiline ? ' bs-ds-copyfield--block' : '' }` }>
			{ label ? (
				<span className="bs-ds-copyfield__label" id={ labelId }>
					{ label }
				</span>
			) : null }
			<div className="bs-ds-copyfield__row">
				{ /* An address, a key or a configuration reads left to right in
				     every language: in a right-to-left page the block's braces
				     were mirrored and the field cut off the address's start.
				     A translated message keeps its own direction. */ }
				{ multiline ? (
					<pre className="bs-ds-copyfield__block" dir={ dir } tabIndex={ 0 } role="group" aria-labelledby={ label ? labelId : undefined }>
						{ text }
					</pre>
				) : (
					<input className="bs-ds-copyfield__value" type="text" dir={ dir } readOnly value={ text } aria-label={ label } />
				) }
				<CopyButton text={ text } label={ copyLabel || __( 'Copy', 'bettershield' ) } inPlace />
			</div>
		</div>
	);
}
