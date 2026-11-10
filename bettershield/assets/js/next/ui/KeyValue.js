/**
 * Facts as label and value (List item / Key-value, 26:38485), and a status
 * line ending in where to go about it (List item / Action, 26:38452).
 *
 * A value is text, a status (a check or a warning beside the words) or a
 * Badge, as the component's three variants draw it.
 */

import './KeyValue.css';

import Button from './Button';
import Icon, { NOTE_ICON } from './Icon';

const STATUS = {
	ok: [ 'check', 'ok' ],
	warning: [ 'triangle-alert', 'warning' ],
	error: [ 'circle-x', 'error' ],
	info: [ NOTE_ICON, 'info' ],
	off: [ 'circle-dashed', '3' ],
};

/**
 * @param {Object} props
 * @param {*}      props.label  What the fact is.
 * @param {*}      props.value  The fact.
 * @param {string} props.status ok, warning, error, info or off: a mark before the value.
 * @param {*}      props.note   A line under the row, where the value needs one.
 */
export function KeyValue( { label, value, status = '', note = null } ) {
	const mark = STATUS[ status ];

	return (
		<div className="bs-ds-kv">
			<div className="bs-ds-kv__row">
				<span className="bs-ds-kv__label">{ label }</span>
				<span className="bs-ds-kv__value">
					{ mark ? <Icon name={ mark[ 0 ] } size={ 12 } tone={ mark[ 1 ] } /> : null }
					{ value }
				</span>
			</div>
			{ note ? <p className="bs-ds-kv__note">{ note }</p> : null }
		</div>
	);
}

/**
 * @param {Object}  props
 * @param {*}       props.children  The facts.
 * @param {string}  props.className Where the list sits, for the screen that places it.
 * @param {boolean} props.ruled     A rule above each fact: for a list across a wide card, where a value sits far from its label.
 */
export function KeyValues( { children, className = '', ruled = false } ) {
	const classes = [ 'bs-ds-kvs', ruled ? 'bs-ds-kvs--ruled' : '', className ].filter( Boolean ).join( ' ' );

	return <div className={ classes }>{ children }</div>;
}

/**
 * @param {Object}   props
 * @param {*}        props.text    The status line.
 * @param {*}        props.link    The action's words.
 * @param {string}   props.href    Where it goes.
 * @param {Function} props.onClick What it does, when it does not go anywhere.
 */
export function ActionRow( { text, link, href, onClick } ) {
	return (
		<div className="bs-ds-act-row">
			<span className="bs-ds-t12 bs-ds-r bs-ds-c2 bs-ds-act-row__text">{ text }</span>
			<span className="bs-ds-spacer" />
			{ link ? (
				<Button type="linksub" size="sm" className="bs-ds-t12" href={ href } onClick={ onClick }>
					{ link }
					<Icon name="arrow-right" size={ 14 } tone="1" />
				</Button>
			) : null }
		</div>
	);
}
