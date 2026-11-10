/**
 * An ⓘ beside a label or a heading that opens a short explanation: the why
 * or the how of a setting, in a sentence or two (forty words at most).
 * Anything longer, or with steps, goes in "How this works" under the row.
 *
 * A real button: it opens on a click or a tap, never on hover alone, says
 * whether it is open, and the text it opens describes it. Escape, a click
 * outside or a second press closes it, and focus goes back to the button.
 * What a person must see to stay safe (a lock-out risk, a change that signs
 * others out, one that cannot be undone, data that leaves the site, a gap in
 * coverage) is never put behind one.
 *
 * Free of the dashboard's store, as the setting rows are.
 */

import './InfoTip.css';

import { Dropdown } from '@wordpress/components';
import { useEffect, useId, useRef } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import Icon from './Icon';

/**
 * Closes the open explanation on a press anywhere outside it and its button.
 * The dropdown closes only when focus leaves it, and the button keeps focus
 * (or, in Safari, never takes it), so a press on the page left it open.
 *
 * @param {Object}   props
 * @param {Object}   props.toggle The button's ref.
 * @param {Function} props.onClose Closes it.
 * @param {*}        props.children The explanation.
 */
function ClosesOutside( { toggle, onClose, children } ) {
	const own = useRef( null );

	useEffect( () => {
		const press = ( event ) => {
			const pop = own.current && own.current.closest( '.components-popover' );

			if ( ( own.current && own.current.contains( event.target ) ) || ( pop && pop.contains( event.target ) ) || ( toggle.current && toggle.current.contains( event.target ) ) ) {
				return;
			}

			onClose();
		};

		document.addEventListener( 'pointerdown', press, true );

		return () => document.removeEventListener( 'pointerdown', press, true );
	}, [ toggle, onClose ] );

	return <div ref={ own }>{ children }</div>;
}

/**
 * @param {Object} props
 * @param {string} props.label     What the button is about, for a reader who cannot see the ⓘ.
 * @param {*}      props.children  The explanation.
 * @param {string} props.placement Where it opens.
 * @param {string} props.icon      The mark it shows, where a state says more than ⓘ would (a clock for a day still open).
 */
export default function InfoTip( { label, children, placement = 'bottom-start', icon = 'info' } ) {
	const id = `bs-ds-infotip-${ useId().replace( /[^\w-]/g, '' ) }`;
	const toggle = useRef( null );

	return (
		<Dropdown
			className="bs-ds-infotip"
			popoverProps={ { placement, offset: 6, className: 'bs-ds-infotip__pop' } }
			renderToggle={ ( { isOpen, onToggle, onClose } ) => (
				<button
					ref={ toggle }
					type="button"
					className="bs-ds-infotip__button"
					aria-expanded={ isOpen }
					aria-label={ label || __( 'More about this', 'bettershield' ) }
					aria-describedby={ isOpen ? id : undefined }
					onClick={ onToggle }
					// The text holds nothing to focus, so focus stays here and
					// Escape is answered here too.
					onKeyDown={ ( event ) => {
						if ( isOpen && 'Escape' === event.key ) {
							event.preventDefault();
							event.stopPropagation();
							onClose();
						}
					} }
				>
					<Icon name={ icon } size={ 14 } tone="3" />
				</button>
			) }
			// Whatever draws the dropdown may call this with nothing; the
			// explanation still shows, and only the outside press is skipped.
			renderContent={ ( { onClose } = {} ) => (
				<ClosesOutside toggle={ toggle } onClose={ onClose || ( () => {} ) }>
					<p className="bs-ds-infotip__text" id={ id }>
						{ children }
					</p>
				</ClosesOutside>
			) }
		/>
	);
}
