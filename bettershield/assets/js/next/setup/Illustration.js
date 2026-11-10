/**
 * The picture on the first step: the product's mark on a small posture card,
 * with the three things the setup is about to put in place around it.
 *
 * Drawn from the token layer rather than shipped as an image, so it turns over
 * with the scheme like everything else, and decorative throughout — the step's
 * own words say everything the picture shows.
 */

import './Illustration.css';

import { __ } from '@wordpress/i18n';
import Icon from '../ui/Icon';
import { useScheme } from '../../ui/scheme';

export default function Illustration() {
	const { scheme } = useScheme();
	const assets = window.bettershield?.assetsUrl;

	return (
		<div className="bs-ds-setup-art" aria-hidden="true">
			<span className="bs-ds-setup-art__glow" />

			<div className="bs-ds-setup-art__card">
				<div className="bs-ds-setup-art__top">
					{ assets ? (
						<img className="bs-ds-setup-art__mark" src={ `${ assets }mark-${ 'dark' === scheme ? 'dark' : 'light' }.svg` } width="56" height="56" alt="" />
					) : (
						<span className="bs-ds-setup-art__mark bs-ds-setup-art__mark--glyph">
							<Icon name="shield" size={ 18 } tone="1" />
						</span>
					) }
					<span className="bs-ds-setup-art__grade">A</span>
				</div>

				<ul className="bs-ds-setup-art__rows">
					{ [ 72, 58, 84 ].map( ( width, index ) => (
						<li key={ width } style={ { '--bs-ds-art-order': index } }>
							<span className="bs-ds-setup-art__tick">
								<Icon name="check" size={ 12 } />
							</span>
							<span className="bs-ds-setup-art__bar" style={ { '--bs-ds-art-width': `${ width }%` } } />
						</li>
					) ) }
				</ul>
			</div>

			<span className="bs-ds-setup-art__chip bs-ds-setup-art__chip--one">
				<Icon name="key" size={ 12 } tone="2" />
				{ __( 'Account recovery', 'bettershield' ) }
			</span>
			<span className="bs-ds-setup-art__chip bs-ds-setup-art__chip--two">
				<Icon name="lock" size={ 12 } tone="2" />
				{ __( 'Quick security fixes', 'bettershield' ) }
			</span>
		</div>
	);
}
