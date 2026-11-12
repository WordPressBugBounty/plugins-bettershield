/**
 * What the setup's hub step shows once the site is connected: this site and
 * the hub joined by a tick, and the dialog that says the setup is done.
 *
 * Drawn from the token layer rather than shipped as images, so both turn over
 * with the scheme. The pictures are decorative: the words beside them say
 * everything they show.
 */

import './HubConnected.css';

import { Modal } from '@wordpress/components';
import { useId } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import Icon from '../ui/Icon';
import brand from './brand';

/** Each piece of confetti: x, y, its turn, and which token paints it. */
const CONFETTI = [
	[ 112, 8, 20, 'brand' ],
	[ 146, 2, -24, 'info' ],
	[ 176, 26, 38, 'warning' ],
	[ 190, 62, -16, 'brand' ],
	[ 174, 98, 28, 'info' ],
	[ 92, 28, -36, 'warning' ],
	[ 68, 14, 12, 'success' ],
	[ 158, 44, -40, 'success' ],
];

export function HubLink() {
	return (
		<div className="bs-ds-setup-link" aria-hidden="true">
			<span className="bs-ds-setup-link__glow" />
			<span className="bs-ds-setup-link__tile">
				<Icon name="globe" size={ 24 } tone="1" />
			</span>
			<span className="bs-ds-setup-link__line" />
			<span className="bs-ds-setup-link__seal">
				<Icon name="check" size={ 20 } />
			</span>
			<span className="bs-ds-setup-link__line" />
			<span className="bs-ds-setup-link__tile">
				<Icon name="network" size={ 24 } tone="1" />
			</span>
		</div>
	);
}

function Popper() {
	return (
		<svg className="bs-ds-setup-done__art" viewBox="0 0 210 170" width="210" height="170" aria-hidden="true" focusable="false">
			<circle className="bs-ds-setup-done__halo" cx="118" cy="80" r="66" />
			<path className="bs-ds-setup-done__cone" d="M28 156 90 56l58 56Z" />
			<path className="bs-ds-setup-done__stripe" d="m74 82 32 31-20 9-24-23Zm-24 39 22 21-17 7-15-14Z" />
			<ellipse className="bs-ds-setup-done__mouth" cx="119" cy="84" rx="40" ry="14" transform="rotate(44 119 84)" />
			{ CONFETTI.map( ( [ x, y, turn, tone ], index ) => (
				<rect
					key={ `${ x }-${ y }` }
					className={ `bs-ds-setup-done__bit bs-ds-setup-done__bit--${ tone }` }
					style={ { '--bs-ds-bit-order': index } }
					x={ x }
					y={ y }
					width="7"
					height="11"
					rx="1.5"
					transform={ `rotate(${ turn } ${ x + 3.5 } ${ y + 5.5 })` }
				/>
			) ) }
			<circle className="bs-ds-setup-done__seal" cx="119" cy="78" r="26" />
			<path className="bs-ds-setup-done__tick" d="m107 78 9 9 16-18" />
		</svg>
	);
}

/**
 * @param {Object}   props
 * @param {Function} props.onClose   Closes it.
 * @param {boolean}  props.connected Whether the site has just connected to the hub.
 * @param {boolean}  props.already   Whether it was connected before Connect was pressed.
 */
export function SetupDoneDialog( { onClose, connected = true, already = false } ) {
	let text = __( 'Quick Setup is done. You can connect this site to the hub at any time.', 'bettershield' );

	if ( already ) {
		/* translators: %s: the plugin's name. */
		text = sprintf( __( 'This site is already connected to %s Hub.', 'bettershield' ), brand() );
	} else if ( connected ) {
		/* translators: %s: the plugin's name. */
		text = sprintf( __( 'Quick Setup is done, and this site is connected to %s Hub.', 'bettershield' ), brand() );
	}

	const titleId = useId();

	return (
		<Modal className="bs-ds-setup-done" aria={ { labelledby: titleId } } onRequestClose={ onClose } size="medium">
			<div className="bs-ds-setup-done__body">
				<Popper />
				<h2 id={ titleId } className="bs-ds-setup-done__title">
					{ __( 'Congratulations', 'bettershield' ) }
				</h2>
				<p className="bs-ds-setup-done__text">{ text }</p>
			</div>
		</Modal>
	);
}
