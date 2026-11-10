/**
 * `inert`, set on the element rather than passed as a prop.
 *
 * React only learned the attribute in 19. The React WordPress ships is 18,
 * which treats `inert` as an unknown attribute: a boolean passed to it is
 * dropped with a console warning, so `inert={ true }` never reached the page
 * and a closing panel's links stayed in the tab order. A string would reach
 * the page in 18 and be read as false in 19. Writing the attribute directly
 * means the same thing under both.
 *
 * A layout effect, so the attribute is on the element before the frame that
 * shows the state it belongs to.
 */

import { useLayoutEffect } from '@wordpress/element';

/**
 * @param {{current: ?Element}} ref Which element.
 * @param {boolean}             on  Whether it is inert.
 */
export default function useInert( ref, on ) {
	useLayoutEffect( () => {
		if ( ref.current ) {
			ref.current.toggleAttribute( 'inert', !! on );
		}
	} );
}
