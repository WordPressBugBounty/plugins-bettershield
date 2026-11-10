/**
 * Two standing facts about a site, in the Overview's rail: activity far from
 * its own usual, and which security plugin does which job where it has
 * another. Cards like the rail's others: the header, the facts, and a status
 * line ending in where to go about them.
 */

import './Signals.css';

import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { useStore } from '../../store';
import { listOf } from '../../setup/format';
import brand from '../setup/brand';
import { whenPhrase } from '../../ui/when';
import { Card, CardHead } from '../ui/Card';
import { ActionRow } from '../ui/KeyValue';

/**
 * A length of time in the words a person uses for it.
 *
 * @param {number} seconds
 * @return {string} e.g. "5 hours", "40 minutes".
 */
function span( seconds ) {
	const minutes = Math.round( Number( seconds ) / 60 );

	if ( minutes >= 120 ) {
		const hours = Math.round( minutes / 60 );

		/* translators: %d: a number of hours. */
		return sprintf( _n( '%d hour', '%d hours', hours, 'bettershield' ), hours );
	}

	/* translators: %d: a number of minutes. */
	return sprintf( _n( '%d minute', '%d minutes', minutes, 'bettershield' ), minutes );
}

/**
 * What was out of line for this site in the last day, against its own last
 * thirty. Absent on most days, when nothing was. Not a warning: a launch or a
 * wave of bots trips it as readily as anything worse, so it says what was seen
 * and what is usual and leaves the reading to the owner.
 *
 * @param {Object}  props
 * @param {?Object} props.panel The server's notes, or null.
 */
export function Unusual( { panel } ) {
	if ( ! panel || ! ( panel.notes || [] ).length ) {
		return null;
	}

	// Empty for a reader the screen does not open for: no link to nowhere.
	const activity = tabUrl( 'bettershield-activity', 'site' );

	return (
		<Card className="bs-ds-unusual" aria-labelledby="bs-ds-unusual-title">
			<CardHead icon="activity" title={ __( 'Unusual activity this week', 'bettershield' ) } id="bs-ds-unusual-title" />
			<ul className="bs-ds-signals__list">
				{ panel.notes.map( ( note ) => (
					<li key={ `${ note.metric }-${ note.at }` } className="bs-ds-signals__note">
						{ 'signin_failures' === note.metric
							? sprintf(
									/* translators: 1: failed sign-ins in an hour, 2: the usual hourly count, 3: when. */
									__( '%1$d failed sign-ins in an hour (usually about %2$s) · %3$s', 'bettershield' ),
									note.observed,
									String( note.usual ),
									whenPhrase( note.at )
							  )
							: sprintf(
									/* translators: 1: a length of time, 2: another length of time, 3: when. */
									__( 'Scheduled site tasks didn’t run for %1$s (usually at most %2$s). This can mean visits are low or WordPress’s scheduler is stuck · %3$s', 'bettershield' ),
									span( note.observed ),
									span( note.usual ),
									whenPhrase( note.at )
							  ) }
					</li>
				) ) }
			</ul>
			<ActionRow
				text={ __( 'Compared with this site’s last 30 days. This is for your information; BetterShield took no action.', 'bettershield' ) }
				link={ activity ? __( 'Open Activity', 'bettershield' ) : null }
				href={ activity }
			/>
		</Card>
	);
}

/**
 * Which security plugin does which job, where the site has another one.
 *
 * Said here rather than only in the setup that asked, because two plugins on
 * one site is a standing fact about it: somebody reading the dashboard a
 * month later should not have to guess why the sign-in limits are off here.
 *
 * @param {Object} props
 * @param {Object} props.split The overview payload's `neighbors`.
 */
export function Neighbors( { split } ) {
	// Opens the Quick Setup on the step where the choice is made; Settings,
	// which it pointed to, has no way to change it (#2149).
	const { reopenSetup } = useStore();

	if ( ! split || ! ( split.others || [] ).length ) {
		return null;
	}

	return (
		<Card className="bs-ds-neighbors" aria-labelledby="bs-ds-neighbors-title">
			<CardHead icon="layers" title={ __( 'Who does which job', 'bettershield' ) } id="bs-ds-neighbors-title" />
			<dl className="bs-ds-signals__list">
				{ split.others.map( ( other ) => (
					<div key={ other.name } className="bs-ds-neighbors__row">
						<dt>{ other.name }</dt>
						<dd>{ listOf( other.jobs ) }</dd>
					</div>
				) ) }
				<div className="bs-ds-neighbors__row">
					<dt>{ brand() }</dt>
					<dd>{ listOf( split.ours || [] ) }</dd>
				</div>
			</dl>
			{ /*
			   * A plugin still keeping sign-in limits or two-factor gets the step's own migration (#2755).
			   * "Locked out twice" only where both limit sign-ins at once: kept by choice, this plugin's limit is off.
			   */ }
			{ ( split.migrate || [] ).length ? (
				<ActionRow
					text={
						( split.double || [] ).length
							? sprintf(
									/* translators: %s: one or more plugin names. */
									_n(
										'%s also limits sign-ins, so people can be locked out twice.',
										'%s also limit sign-ins, so people can be locked out twice.',
										split.double.length,
										'bettershield'
									),
									listOf( split.double )
							  )
							: sprintf(
									/* translators: 1: one or more plugin names, 2: this plugin's name. */
									_n( '%1$s still does these jobs. %2$s can take them over.', '%1$s still do these jobs. %2$s can take them over.', split.migrate.length, 'bettershield' ),
									listOf( split.migrate ),
									brand()
							  )
					}
					link={ __( 'Migrate', 'bettershield' ) }
					onClick={ () => reopenSetup( 'coexistence' ) }
				/>
			) : (
				<ActionRow
					text={ __( 'Change who keeps sign-in limits, two-factor and the sign-in address by running the Quick Setup again.', 'bettershield' ) }
					link={ __( 'Run Quick Setup', 'bettershield' ) }
					onClick={ () => reopenSetup( 'coexistence' ) }
				/>
			) }
		</Card>
	);
}
