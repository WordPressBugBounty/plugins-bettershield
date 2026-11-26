/**
 * After the Quick Setup, for each security plugin still doing a job
 * BetterShield can take over — kept in the setup, or never asked because the
 * step was skipped: what BetterShield would take, and one press to move it.
 *
 * The press is the setup's own save for those choices, so the same guards
 * hold. It never switches the plugin off itself: where the person may, it
 * then follows WordPress's own Deactivate, which moves the two-factor
 * accounts as the plugin goes; elsewhere the deactivate notice that follows
 * names the Plugins screen. Closing the notice is keeping the plugin; the
 * Overview still offers the move.
 */

import './MigrateNotice.css';

import { __, _n, sprintf } from '@wordpress/i18n';
import { listOf } from '../../setup/format';
import { useStore } from '../../store';
import { announce } from '../../ui/announce';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { alsoStops } from './SwitchOffNotice';

/**
 * Each job in words.
 *
 * @param {string[]} jobs Job slugs.
 * @return {string} The jobs, joined.
 */
function jobsText( jobs ) {
	const named = {
		two_factor: __( 'two-factor', 'bettershield' ),
		login_limits: __( 'sign-in limits', 'bettershield' ),
		login_url: __( 'the custom sign-in address', 'bettershield' ),
	};
	return listOf( ( jobs || [] ).filter( ( job ) => named[ job ] ).map( ( job ) => named[ job ] ) );
}

/**
 * The description for one plugin.
 *
 * @param {Object} plugin One entry of onboarding.migrate.
 * @return {string} The sentences.
 */
export function migrateText( plugin ) {
	const parts = [
		sprintf(
			/* translators: 1: a plugin's name, 2: jobs, e.g. "two-factor and sign-in limits". */
			__( '%1$s still handles %2$s here. BetterShield can take this over and bring its settings with it.', 'bettershield' ),
			plugin.name,
			jobsText( plugin.jobs )
		),
	];

	if ( plugin.accounts > 0 ) {
		parts.push(
			sprintf(
				/* translators: %d: how many accounts. */
				_n(
					'%d account with two-factor there keeps its authenticator app.',
					'%d accounts with two-factor there keep their authenticator app.',
					plugin.accounts,
					'bettershield'
				),
				plugin.accounts
			)
		);
	}

	const also = alsoStops( plugin.also );

	parts.push(
		plugin.can_deactivate
			? sprintf(
					/* translators: %s: a plugin's name. */
					__( 'Migrate & Deactivate moves it, then switches %s off.', 'bettershield' ),
					plugin.name
			  )
			: sprintf(
					/* translators: %s: a plugin's name. */
					__( 'Migrate moves it. Then deactivate %s from the Plugins screen to finish.', 'bettershield' ),
					plugin.name
			  )
	);

	// Deactivating it ends more than the jobs moved: said before anyone presses.
	if ( also.length ) {
		parts.push(
			sprintf(
				/* translators: 1: a plugin's name, 2: what else it does, e.g. "its firewall, its backups". */
				__( 'Deactivating %1$s also switches off %2$s, which BetterShield doesn’t take over.', 'bettershield' ),
				plugin.name,
				listOf( also )
			)
		);
	}

	return parts.join( ' ' );
}

export default function MigrateNotice() {
	const { resources, migrateFrom, dismissMigrate, reopenSetup, busy } = useStore();
	const overview = resources.overview;
	const plugins = overview && 'ready' === overview.status ? overview.data?.onboarding?.migrate || [] : [];

	if ( ! plugins.length ) {
		return null;
	}

	const working = 'migrate' === busy || 'migrate-dismiss' === busy;

	return (
		<div className="bs-ds-migrate">
			{ plugins.map( ( plugin ) => (
				<Alert
					key={ plugin.file }
					tone="info"
					layout="default"
					title={ sprintf(
						/* translators: %s: a plugin's name. */
						__( 'Move %s’s jobs to BetterShield', 'bettershield' ),
						plugin.name
					) }
					desc={ migrateText( plugin ) }
					onDismiss={ working ? undefined : () => dismissMigrate( plugin.file ) }
					actions={
						<>
							<Button type="primary" size="sm" isBusy={ 'migrate' === busy } disabled={ working } onClick={ () => {
									announce(
										sprintf(
											/* translators: %s: a plugin's name. */
											__( 'Moving %s’s jobs to BetterShield…', 'bettershield' ),
											plugin.name
										)
									);
									migrateFrom( plugin.file );
								} }>
								{ plugin.can_deactivate ? __( 'Migrate & Deactivate', 'bettershield' ) : __( 'Migrate', 'bettershield' ) }
							</Button>
							<Button type="secondary" size="sm" disabled={ working } onClick={ () => reopenSetup( 'coexistence' ) }>
								{ __( 'Review in Quick Setup', 'bettershield' ) }
							</Button>
						</>
					}
				/>
			) ) }
		</div>
	);
}
