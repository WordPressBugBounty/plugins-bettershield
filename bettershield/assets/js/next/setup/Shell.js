/**
 * The setup page's corners: the logo at the top, and who is setting up which
 * site at the foot.
 *
 * The logo links to the plugin's dashboard.
 */

import './Shell.css';

import { __, sprintf } from '@wordpress/i18n';
import { useScheme } from '../../ui/scheme';
import { pageModel } from './api';
import brand from './brand';

/**
 * @param {Object} props
 * @param {string} props.href Where the logo goes: the plugin's dashboard.
 */
export function SetupLogo( { href } ) {
	const { scheme } = useScheme();
	const assets = window.bettershield?.assetsUrl || '';
	const logo = pageModel().logo;
	const tone = 'dark' === scheme ? 'dark' : 'light';
	const label = sprintf( /* translators: %s: the plugin's name. */ __( 'Go to %s', 'bettershield' ), brand() );

	// An owner's label shows its own logo beside its own name; this plugin's
	// own is its mark and its wordmark.
	const picture = logo ? (
		<>
			<img className="bs-ds-setup__logo-mark" src={ logo } alt="" height="28" />
			<span className="bs-ds-setup__logo-name">{ brand() }</span>
		</>
	) : (
		<>
			<img className="bs-ds-setup__logo-mark" src={ `${ assets }mark-${ tone }.svg` } alt="" width="28" height="28" />
			<img className="bs-ds-setup__logo-word" src={ `${ assets }wordmark-${ tone }.svg` } alt="" width="93" height="12" />
		</>
	);

	return href ? (
		<a className="bs-ds-setup__logo" href={ href } aria-label={ label }>
			{ picture }
		</a>
	) : (
		<span className="bs-ds-setup__logo">{ picture }</span>
	);
}

/** "Setting up", then the site's address and who is setting it up. */
export function Context() {
	const model = pageModel();
	const where = [ model.host, model.user ].filter( Boolean ).join( ' · ' );

	if ( ! where ) {
		return null;
	}

	return (
		<p className="bs-ds-setup__context">
			<span className="bs-ds-setup__context-label">{ __( 'Setting up', 'bettershield' ) }</span>
			<span className="bs-ds-setup__context-site">{ where }</span>
		</p>
	);
}
