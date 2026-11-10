/**
 * The parts of this plugin's own record keeping that are not working.
 *
 * Absent on every site where the migration did what it was asked, which is
 * almost all of them: this is the one place the product admits that one of
 * its own tables is not there, and it says which part of the product has
 * stopped rather than leaving the reader to notice an empty screen weeks
 * later. It reports; Repair runs the same migration the plugin runs on its
 * own, and says what the database answered when it still cannot.
 *
 * It sits above the score because the score is computed from records this
 * card says are not being kept: reading the number first and the caveat
 * second is the wrong order for the one screen that has to be trusted.
 */

import './Storage.css';

import apiFetch from '@wordpress/api-fetch';
import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';

/**
 * @param {Object}   props
 * @param {Array}    props.rows       The overview's `readiness`.
 * @param {Function} props.onRepaired Given what a repair said: a sentence when it worked, empty when not.
 */
export default function Storage( { rows, onRepaired } ) {
	const [ working, setWorking ] = useState( false );
	const [ outcome, setOutcome ] = useState( null );
	const degraded = ( rows || [] ).filter( ( row ) => ! row.ready );

	if ( ! degraded.length ) {
		return null;
	}

	const repairable = degraded.some( ( row ) => row.repairable );

	/*
	 * A repair that works takes this whole card away, and with it the button
	 * that was pressed and the only place on screen that could say what
	 * happened. So the sentence is handed upward, to a live region that
	 * outlives the card, and so is the fact that focus needs somewhere to go.
	 */
	const repair = () => {
		setWorking( true );
		setOutcome( null );

		return apiFetch( { path: '/bettershield/v1/schema/repair', method: 'POST' } )
			.then( ( result ) => {
				setOutcome( result.repaired ? null : result.reason || '' );
				onRepaired( result.repaired ? __( 'Storage was repaired. Everything is being recorded again.', 'bettershield' ) : '' );
			} )
			.catch( ( error ) => setOutcome( error.message || '' ) )
			.finally( () => setWorking( false ) );
	};

	return (
		<Card className="bs-ds-storage" aria-labelledby="bs-ds-storage-title">
			<CardHead icon="database" title={ __( 'Part of this plugin’s storage is unavailable', 'bettershield' ) } id="bs-ds-storage-title" />
			<div className="bs-ds-storage__body">
				<Alert
					layout="default"
					tone="warning"
					desc={ __(
						'Everything not listed below works as usual, and nothing already recorded is lost.',
						'bettershield'
					) }
				/>
			</div>

			<ul className="bs-ds-storage__list">
				{ degraded.map( ( row ) => (
					<li key={ row.capability } className="bs-ds-storage__row">
						<span className="bs-ds-storage__what">{ row.label }</span>
						<span className="bs-ds-storage__effect">{ row.consequence }</span>
						{ row.since ? (
							<span className="bs-ds-storage__since">
								{ sprintf(
									/* translators: %s: a date and time, e.g. "Sep 6, 12:52 PM". */
									__( 'Unavailable since %s', 'bettershield' ),
									whenPhrase( row.since )
								) }
							</span>
						) : null }
						{ /* What the database said, quoted rather than paraphrased:
						     the one line here a host's support desk can act on. */ }
						{ row.reason ? <q className="bs-ds-storage__reason">{ row.reason }</q> : null }
					</li>
				) ) }
			</ul>

			{ repairable || null !== outcome ? (
				<div className="bs-ds-storage__actions">
					{ repairable ? (
						<Button type="secondary" size="sm" icon="refresh-cw" iconTone="2" isBusy={ working } disabled={ working } onClick={ repair }>
							{ working ? __( 'Repairing…', 'bettershield' ) : __( 'Repair', 'bettershield' ) }
						</Button>
					) : null }
					{ null !== outcome ? (
						<span className="bs-ds-storage__note" role="status">
							{ '' === outcome
								? __( 'The repair ran again, but this part still isn’t working. Contact support.', 'bettershield' )
								: sprintf(
										/* translators: %s: what the database reported, in its own words. */
										__( 'The repair ran again but didn’t finish: %s', 'bettershield' ),
										outcome
								  ) }
						</span>
					) : null }
				</div>
			) : null }
		</Card>
	);
}
