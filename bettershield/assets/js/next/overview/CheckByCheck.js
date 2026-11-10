/**
 * What changed since an earlier day, check by check.
 *
 * The score's history says whether it moved; this says which checks moved
 * it. It compares the findings as they stand with how they stood at the end
 * of a recorded day, so "we were a B last week" can be answered with the
 * three checks that opened since rather than a guess.
 *
 * The day is chosen with a control of its own. Absent until a day has kept
 * its checks, which on a site updating to this release is the day after its
 * first audit.
 */

import './CheckByCheck.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { findingUrl } from '../../nav';
import Alert from '../ui/Alert';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, SectionHead } from '../ui/Card';
import Field from '../ui/Field';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import { severityLabel, severityName } from '../data/severity';

/**
 * A recorded UTC day as a short date, read at noon so no time zone moves it
 * onto the day before or after.
 *
 * @param {string} day YYYY-MM-DD.
 * @return {string} The day, formatted for the reader's locale.
 */
export function dayLabel( day ) {
	const date = new Date( `${ day }T12:00:00Z` );

	return Number.isNaN( date.getTime() ) ? day : date.toLocaleDateString( undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' } );
}

function Group( { title, rows, children } ) {
	if ( ! rows.length ) {
		return null;
	}

	return (
		<div className="bs-ds-posture__group">
			<SectionHead as="h3">{ title }</SectionHead>
			<ul className="bs-ds-posture__list">{ rows.map( children ) }</ul>
		</div>
	);
}

/** A finding's severity, with its word. */
function Severity( { severity } ) {
	return <Badge tone={ kindTone( severity ) }>{ severityName( severity ) }</Badge>;
}

/**
 * @param {Object} props
 * @param {string} props.generatedAt When the last audit ran; a new one is read again.
 */
export default function CheckByCheck( { generatedAt } ) {
	const [ state, setState ] = useState( null );
	const [ error, setError ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ open, setOpen ] = useState( false );
	const alive = useRef( true );
	// Which read an answer is for. The day can be changed again while one is
	// on its way, so only the latest counts (#2028).
	const asked = useRef( 0 );
	// The day chosen while its read is out. The select shows it rather than
	// the day the comparison on screen was read for, or every change of day
	// sprang back until its answer came, and the arrow keys could not move
	// past the next day.
	const [ chosen, setChosen ] = useState( null );

	const load = ( since ) => {
		const ticket = ++asked.current;
		const current = () => alive.current && ticket === asked.current;

		setBusy( true );
		setError( '' );
		setChosen( since || null );

		apiFetch( { path: since ? `/bettershield/v1/posture?since=${ encodeURIComponent( since ) }` : '/bettershield/v1/posture' } )
			.then(
				( result ) => current() && setState( result ),
				( e ) => current() && setError( e.message )
			)
			.finally( () => {
				if ( current() ) {
					// Answered: the comparison on screen is the chosen day's now,
					// or, when the read failed, the select goes back to the day
					// it is still about.
					setChosen( null );
					setBusy( false );
				}
			} );
	};

	useEffect( () => {
		alive.current = true;
		load( '' );

		return () => {
			alive.current = false;
		};
	}, [ generatedAt ] );

	// Before the first answer: a stand-in while it is on its way, and a
	// failure said rather than a card that never appears.
	if ( ! state ) {
		if ( error ) {
			return <ErrorState title={ __( 'What changed, check by check, could not be read.', 'bettershield' ) } onRetry={ () => load( '' ) } />;
		}

		return busy ? (
			<Skeleton label={ __( 'Reading what changed, check by check…', 'bettershield' ) }>
				<CardBone rows={ [ '62%', '48%' ] } />
			</Skeleton>
		) : null;
	}

	if ( ! state.days || ! state.days.length ) {
		return null;
	}

	const diff = state.diff;
	// A payload from before the put-back group existed has none.
	const putBack = ( diff && diff.put_back ) || [];
	const quiet = diff && ! diff.opened.length && ! diff.resolved.length && ! diff.set_aside.length && ! putBack.length && ! diff.changed.length;
	const linked = ( row ) => (
		<li key={ row.id } className="bs-ds-posture__row bs-ds-posture__row--chip">
			<Severity severity={ row.severity } />
			<a href={ findingUrl( row.id ) }>{ row.title }</a>
		</li>
	);
	const plain = ( row ) => (
		<li key={ row.id } className="bs-ds-posture__row bs-ds-posture__row--chip">
			<Severity severity={ row.severity } />
			<span>{ row.title }</span>
		</li>
	);

	return (
		<Card className="bs-ds-posture" aria-labelledby="bs-ds-posture-title" aria-busy={ busy }>
			{ /* Closed until asked for: a comparison to read on purpose,
			     not a second list of findings under the first. */ }
			<CardHead icon="list-checks" title={ __( 'What changed, check by check', 'bettershield' ) } id="bs-ds-posture-title">
				<Button type="ghost" size="sm" trailing={ open ? 'chevron-up' : 'chevron-down' } trailingTone="3" aria-expanded={ open } aria-controls={ open ? 'bs-ds-posture-panel' : undefined } onClick={ () => setOpen( ( was ) => ! was ) }>
					{ open ? __( 'Hide', 'bettershield' ) : __( 'Show', 'bettershield' ) }
				</Button>
			</CardHead>
			{ open ? (
				<div id="bs-ds-posture-panel">
					<div className="bs-ds-posture__head">
						<p className="bs-ds-posture__lede">{ __( 'See how each check changed since a day you pick.', 'bettershield' ) }</p>
						<Field
							kind="select"
							width="md"
							label={ __( 'Compared with', 'bettershield' ) }
							value={ chosen || ( diff ? diff.since.day : '' ) }
							// Not disabled while a day is read: a disabled select
							// drops the keyboard to the page on every change of day
							// (#2028). It says it is reading instead.
							aria-busy={ busy ? 'true' : undefined }
							options={ [ ...state.days ].reverse().map( ( day ) => ( {
								value: day.day,
								label: sprintf(
									/* translators: 1: a date, 2: the score on that date. */
									__( '%1$s, score %2$d', 'bettershield' ),
									dayLabel( day.day ),
									day.score
								),
							} ) ) }
							onChange={ load }
						/>
					</div>

					{ error ? (
						<div className="bs-ds-posture__body" role="alert">
							<Alert layout="default" tone="error" desc={ error } />
						</div>
					) : null }

					{ diff ? (
						<div className="bs-ds-posture__body" role="status">
							<p className="bs-ds-posture__score">
								{ sprintf(
									/* translators: 1: the score then, 2: a date, 3: the score now. */
									__( 'Score %1$d at the end of %2$s, %3$d now.', 'bettershield' ),
									diff.since.score,
									dayLabel( diff.since.day ),
									diff.now.score
								) }
							</p>

							{ quiet ? (
								<p className="bs-ds-posture__score">
									{ sprintf(
										/* translators: %s: a date. */
										__( 'No check has changed since %s.', 'bettershield' ),
										dayLabel( diff.since.day )
									) }
								</p>
							) : null }

							<Group title={ __( 'Opened since', 'bettershield' ) } rows={ diff.opened }>
								{ linked }
							</Group>
							<Group title={ __( 'Severity changed', 'bettershield' ) } rows={ diff.changed }>
								{ ( row ) => (
									<li key={ row.id } className="bs-ds-posture__row">
										<a href={ findingUrl( row.id ) }>{ row.title }</a>
										<span className="bs-ds-posture__moved">
											{ sprintf(
												/* translators: 1: severity before, 2: severity now. */
												__( '%1$s, now %2$s', 'bettershield' ),
												severityLabel( row.from ),
												severityLabel( row.to )
											) }
										</span>
									</li>
								) }
							</Group>
							<Group title={ __( 'Passed since', 'bettershield' ) } rows={ diff.resolved }>
								{ plain }
							</Group>
							<Group title={ __( 'Marked “doesn’t apply” since', 'bettershield' ) } rows={ diff.set_aside }>
								{ plain }
							</Group>
							<Group title={ __( 'No longer marked “doesn’t apply” since', 'bettershield' ) } rows={ putBack }>
								{ linked }
							</Group>
						</div>
					) : null }
				</div>
			) : null }
		</Card>
	);
}
