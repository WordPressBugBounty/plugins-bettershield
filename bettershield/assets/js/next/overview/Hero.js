/**
 * The Overview's hero (design frame 27:54728, option "Grade-led"): the score
 * gauge, the grade with how it was read behind an ⓘ, what fixing the
 * high-severity findings would make the score, and a footer saying how many
 * checks ran and how many could not.
 */

import './Hero.css';

import { createInterpolateElement } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import ScoreGauge, { gaugeState } from '../ui/ScoreGauge';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import HeroCard from '../ui/HeroCard';
import InfoTip from '../ui/InfoTip';
import { coverage, goal, scoreSplit } from '../data/overview';
import { findingsUrl } from '../../nav';
import { scanProgress } from '../../ui/scan';

function GoalLine( { reach } ) {
	return (
		<div className="bs-ds-hero__goalrow">
			<p className="bs-ds-hero__goal">
				{ createInterpolateElement(
					sprintf(
						/* translators: 1: how many critical or high findings are open, 2: the score fixing them would reach. */
						_n(
							'Fixing the <strong>%1$d critical or high finding</strong> takes you to <em>%2$d</em>',
							'Fixing the <strong>%1$d critical and high findings</strong> takes you to <em>%2$d</em>',
							reach.count,
							'bettershield'
						),
						reach.count,
						reach.target
					),
					{ strong: <strong />, em: <em /> }
				) }
			</p>
			<Badge tone="brand">
				{ sprintf(
					/* translators: %d: points the score would gain. */
					_n( '+%d point', '+%d points', reach.gain, 'bettershield' ),
					reach.gain
				) }
			</Badge>
		</div>
	);
}

/**
 * @param {Object}   props
 * @param {Object}   props.overview  The audit, as the store holds it; null before one ran.
 * @param {boolean}  props.running   Whether an audit is running.
 * @param {Function} props.onUnknown Shows the checks that could not run.
 * @param {Object}   props.heroRef   Takes the score card's element, for focus.
 * @param {?Object}  props.progress  How far the first file check has got.
 */
export default function Hero( { overview, running, onUnknown, heroRef, progress = null } ) {
	const audited = Boolean( overview && overview.generated_at );
	const marked = Number( overview && overview.marked_findings ) || 0;
	const findings = audited ? overview.findings || [] : [];
	const score = audited ? Number( overview.score ) || 0 : 0;
	const grade = audited ? overview.grade : '';
	// The first file check can move this score, so it waits for the check.
	const waiting = audited && Boolean( overview.first_scan && overview.first_scan.running );
	const state = gaugeState( { grade, audited, running: running || waiting } );
	// The grade keeps the last run's color while the next one reads: the
	// gauge's "scanning" state has no grade, and a failing F drew in the
	// green kept for good grades (#2572).
	const tone = gaugeState( { grade, audited, running: false } );
	const reach = goal( findings, score, audited ? overview.serious_fixed_score : undefined );
	const split = audited ? scoreSplit( overview ) : '';
	const { ran, missed } = audited ? coverage( overview ) : { ran: 0, missed: 0 };
	// A check that has never answered has no last result to show: on a new
	// site that is every one of them.
	const never = audited ? Math.min( missed, ( overview.checks_unknown || [] ).filter( ( check ) => ! check.last_answered_at ).length ) : 0;
	const kept = missed - never;

	return (
		<div className="bs-ds-hero">
			<HeroCard label={ __( 'Score', 'bettershield' ) } heroRef={ heroRef }>
				<div className="bs-ds-hero__row">
					<ScoreGauge state={ state } score={ score } grade={ grade } />
					<span className="screen-reader-text">
						{ waiting ? __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) : null }
						{ audited && ! waiting
							? sprintf(
									/* translators: 1: the score, 2: the letter grade. */
									__( 'Your site scores %1$d out of 100, grade %2$s.', 'bettershield' ),
									score,
									grade
							  )
							: null }
						{ audited ? null : __( 'This site has not been audited yet.', 'bettershield' ) }
					</span>
					{ waiting ? (
						<div className="bs-ds-hero__next">
							<p className="bs-ds-hero__goal">{ __( 'Your first scan is running.', 'bettershield' ) }</p>
							<p className="bs-ds-hero__para">{ __( 'Your score appears here when it finishes. What it has found so far is listed below.', 'bettershield' ) }</p>
							<p className="bs-ds-t12 bs-ds-r bs-ds-c2">{ scanProgress( progress ) }</p>
						</div>
					) : null }
					{ audited && ! waiting ? (
						<div className="bs-ds-hero__next">
							{ /*
							   How the score was read sits behind an ⓘ beside the
							   grade (#1326): that the audit only reads, and what a
							   check that could not run shows. How many could not
							   run stays in sight under the card.
							*/ }
							<div className="bs-ds-hero__gradeline">
								<p className={ `bs-ds-hero__grade bs-ds-hero__grade--${ tone }` }>
									{ createInterpolateElement(
										sprintf(
											/* translators: %s: the letter grade, e.g. "B". */
											__( 'Grade <b>%s</b>', 'bettershield' ),
											grade
										),
										{ b: <b /> }
									) }
								</p>
								<InfoTip label={ __( 'About this score', 'bettershield' ) }>
									{ __( 'The audit only reads, so nothing was changed to get this score.', 'bettershield' ) }
									{ kept > 0
										? ' ' +
										  sprintf(
												/* translators: %d: how many checks could not run this time. */
												_n(
													'%d check couldn’t run this time, so it shows its last result.',
													'%d checks couldn’t run this time, so they show their last results.',
													kept,
													'bettershield'
												),
												kept
										  )
										: null }
									{ never > 0
										? ' ' +
										  sprintf(
												/* translators: %d: how many checks could not run and never have. */
												_n( '%d check couldn’t run and has no result yet.', '%d checks couldn’t run and have no result yet.', never, 'bettershield' ),
												never
										  )
										: null }
								</InfoTip>
							</div>
							{ /* How the score was reached: its two parts, and the cap. */ }
							{ split ? <p className="bs-ds-t12 bs-ds-r bs-ds-c2">{ split }</p> : null }
							<div className="bs-ds-hero__stack">
								{ reach.count > 0 ? <GoalLine reach={ reach } /> : null }
								{ reach.count > 0 && 0 === reach.oneClick ? (
									<p className="bs-ds-hero__para">
										{ _n(
											'It needs a manual fix. It explains what could break before you change anything.',
											'These need a manual fix. Each one explains what could break before you change anything.',
											reach.count,
											'bettershield'
										) }
									</p>
								) : null }
							</div>
						</div>
					) : null }
				</div>
			</HeroCard>
			{ /* What ran, once there is a run: before the first audit the strip
			     stood empty under the card (#1326). */ }
			{ audited ? (
				<div className="bs-ds-hero__foot">
					<span className="bs-ds-hero__note">
						<Icon name="list-checks" size={ 14 } tone="3" />
						<span className="bs-ds-t12 bs-ds-r bs-ds-c2 bs-ds-nowrap">
							{ sprintf(
								/* translators: %d: how many checks ran. */
								_n( '%d check run.', '%d checks run.', ran, 'bettershield' ),
								ran
							) }
							{ missed > 0
								? ' ' +
								  sprintf(
										/* translators: %d: how many checks could not run. */
										_n( '%d couldn’t run this time.', '%d couldn’t run this time.', missed, 'bettershield' ),
										missed
								  )
								: null }
						</span>
						{ missed > 0 ? (
							<Button type="linksub" size="sm" onClick={ onUnknown }>
								{ _n( 'See Which One', 'See Which Ones', missed, 'bettershield' ) }
							</Button>
						) : null }
					</span>
					{ marked > 0 ? (
						<span className="bs-ds-hero__note">
							<Button type="linksub" size="sm" href={ findingsUrl( 'suppressed' ) }>
								{ sprintf(
									/* translators: %d: how many findings the owner took out of the score. */
									_n( 'Includes %d item you manage yourself', 'Includes %d items you manage yourself', marked, 'bettershield' ),
									marked
								) }
							</Button>
						</span>
					) : null }
				</div>
			) : null }
		</div>
	);
}
