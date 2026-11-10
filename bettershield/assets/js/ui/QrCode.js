/**
 * An enrollment URI as a QR code, drawn in the page.
 *
 * Shared by the Two-Factor screen and the Quick Setup, which enroll the same
 * way. The encoder arrives when a code is actually drawn: it is the largest
 * single dependency either bundle has, and it is wanted on one step of one
 * enrollment. Encoded once per URI — type 0 auto-sizes, and medium error
 * correction is the register standard.
 */

import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

/**
 * @param {Object} props
 * @param {string} props.uri       The otpauth:// URI.
 * @param {string} props.className The element's class.
 * @param {number} props.margin    The light border drawn inside the code, in
 *                                 the encoder's units (a module is 4), for a
 *                                 code drawn on a dark surface: a scanner finds
 *                                 the corners by the light around them.
 */
export default function QrCode( { uri, className, margin = 0 } ) {
	const [ svg, setSvg ] = useState( null );

	useEffect( () => {
		let live = true;

		import( /* webpackChunkName: "qrcode" */ 'qrcode-generator' )
			.then( ( module ) => {
				if ( ! live ) {
					return;
				}

				const qrcode = module.default || module;
				const qr = qrcode( 0, 'M' );

				qr.addData( uri );
				qr.make();

				setSvg( qr.createSvgTag( { cellSize: 4, margin, scalable: true } ) );
			} )
			.catch( () => {} );

		return () => {
			live = false;
		};
	}, [ uri, margin ] );

	// Nothing to draw yet, or the encoder could not be fetched. The same
	// secret is printed as text beside this, which is what finishes the
	// enrollment either way.
	if ( ! svg ) {
		return null;
	}

	return (
		<div
			className={ className }
			role="img"
			aria-label={ __( 'QR code for your authenticator app. The same secret appears as text beside it.', 'bettershield' ) }
			// The SVG is generated locally from the enrollment URI by a bundled
			// encoder; nothing is fetched and nothing leaves the page.
			dangerouslySetInnerHTML={ { __html: svg } }
		/>
	);
}
