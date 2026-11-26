/**
 * After the Quick Setup, for each plugin it handed jobs from that is still
 * active: its settings came over, and they take effect in BetterShield once
 * it is switched off. Shown on this plugin's own screens only, until it is
 * deactivated or the notice is closed. Where the site has the setup's
 * deactivation on, its button is WordPress's own Deactivate; otherwise it
 * says it opens the Plugins screen, where the owner switches it off.
 */

import './SwitchOffNotice.css';

import { __, sprintf } from '@wordpress/i18n';
import { listOf } from '../../setup/format';
import { useStore } from '../../store';
import Alert from '../ui/Alert';
import Button from '../ui/Button';

/**
 * What else switching the plugin off stops, in words, or [] when nothing
 * BetterShield does not take over.
 *
 * @param {string[]} jobs Job slugs the plugin keeps doing.
 * @return {string[]} Each in words.
 */
export function alsoStops( jobs ) {
	const named = {
		firewall: __( 'its firewall', 'bettershield' ),
		backups: __( 'its backups', 'bettershield' ),
		login_url: __( 'its custom sign-in address', 'bettershield' ),
		vulnerabilities: __( 'its blocking of known security holes', 'bettershield' ),
		https_redirect: __( 'its HTTPS redirect', 'bettershield' ),
	};

	return ( jobs || [] ).filter( ( job ) => named[ job ] ).map( ( job ) => named[ job ] );
}

/**
 * The description for one plugin.
 *
 * @param {Object} plugin One entry of onboarding.switch_off.
 * @return {string} The sentences.
 */
export function switchOffText( plugin ) {
	const parts = [
		sprintf(
			/* translators: %s: a plugin's name. */
			__( 'Deactivate %s to access and use these settings in BetterShield.', 'bettershield' ),
			plugin.name
		),
	];

	if ( plugin.two_factor ) {
		parts.push( __( 'Accounts with two-factor there move to BetterShield when it is deactivated, and keep their authenticator app.', 'bettershield' ) );
	}

	const also = alsoStops( plugin.also );

	if ( also.length ) {
		parts.push(
			sprintf(
				/* translators: 1: a plugin's name, 2: what else it does, e.g. "its firewall". */
				__( 'Deactivating %1$s also switches off %2$s.', 'bettershield' ),
				plugin.name,
				listOf( also )
			)
		);
	}

	return parts.join( ' ' );
}

export default function SwitchOffNotice() {
	const { resources, dismissSwitchOff, busy } = useStore();
	const overview = resources.overview;
	const plugins = overview && 'ready' === overview.status ? overview.data?.onboarding?.switch_off || [] : [];

	if ( ! plugins.length ) {
		return null;
	}

	return (
		<div className="bs-ds-switchoff">
			{ plugins.map( ( plugin ) => (
				<Alert
					key={ plugin.file }
					tone="info"
					layout="default"
					title={ sprintf(
						/* translators: %s: a plugin's name. */
						__( 'Settings have been migrated from %s to BetterShield', 'bettershield' ),
						plugin.name
					) }
					desc={ switchOffText( plugin ) }
					onDismiss={ 'switch-off' === busy ? undefined : () => dismissSwitchOff( plugin.file ) }
					actions={
						plugin.deactivate_url ? (
							<Button type="secondary" size="sm" href={ plugin.deactivate_url }>
								{ __( 'Deactivate', 'bettershield' ) }
							</Button>
						) : (
							<Button type="secondary" size="sm" href={ plugin.plugins_url }>
								{ __( 'Open Plugins', 'bettershield' ) }
							</Button>
						)
					}
				/>
			) ) }
		</div>
	);
}
