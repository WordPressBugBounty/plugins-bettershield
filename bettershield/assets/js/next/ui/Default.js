/**
 * What a field holds when nobody has chosen anything, and the way back to it:
 * "Default: 5" and Use it, under the field it is about.
 *
 * A security tool's defaults are its recommendation. Shown only while the
 * field differs from it: under a field that already holds it, the line would
 * be noise, and Use it would do nothing.
 */

import './Default.css';

import { __, sprintf } from '@wordpress/i18n';
import Button from './Button';

/**
 * @param {Object}   props
 * @param {*}        props.value    What the field holds now.
 * @param {*}        props.fallback What it holds by default.
 * @param {Function} props.onReset  Puts the default back.
 * @param {Function} props.format   How the default is said, where not as itself.
 */
export default function Default( { value, fallback, onReset, format } ) {
	if ( undefined === fallback || null === fallback ) {
		return null;
	}

	// Compared as text: a number typed into a field is a string, and "12" and
	// 12 are the same answer.
	if ( String( value ?? '' ) === String( fallback ) ) {
		return null;
	}

	const shown = format ? format( fallback ) : String( fallback );

	return (
		<p className="bs-ds-default">
			<span>
				{ sprintf(
					/* translators: %s: the value this setting has when nobody has chosen one. */
					__( 'Default: %s', 'bettershield' ),
					shown
				) }
			</span>
			<Button type="link" size="sm" className="bs-ds-default__use" onClick={ onReset }>
				{ __( 'Use It', 'bettershield' ) }
			</Button>
		</p>
	);
}
