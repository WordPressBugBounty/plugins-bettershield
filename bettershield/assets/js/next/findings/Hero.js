/**
 * The Findings report's score strip: one sentence of grade and points, the
 * how behind an ⓘ, and a line of what ran and how the score has moved.
 *
 * It carried the Overview's whole score panel, gauge and all, which the
 * Overview already shows (#1324). The gauge stays there; here the figures
 * are said once, in a strip the height of its two lines.
 */

import './Hero.css';

import { __, _n, sprintf } from '@wordpress/i18n';
import InfoTip from '../ui/InfoTip';
import { readableHistory } from '../../ui/scoreHistory';
import { historyClause } from '../data/findings';
import { scoreSplit } from '../data/overview';

export default function Hero( { overview, open, heroRef } ) {
	const audited = Boolean( overview && overview.generated_at );
	// The first file check can move the score, so the figures wait for it.
	const waiting = audited && Boolean( overview.first_scan && overview.first_scan.running );
	const score = audited ? Number( overview.score ) || 0 : 0;
	const grade = audited ? overview.grade : '';
	const ran = audited ? Number( overview.checks_ran ) || 0 : 0;
	const missed = audited ? Math.max( 0, ( Number( overview.checks_count ) || 0 ) - ran ) : 0;
	// What the open findings take off is what stands between the score and
	// 100: each part stops at its floor, so their deductions can add up to
	// more than the score actually lost.
	const points = audited ? Math.max( 0, 100 - score ) : 0;
	const split = audited && ! waiting ? scoreSplit( overview ) : '';
	// A snoozed finding is still open and still counted in the score, so it
	// is counted here; the Open tab lists it apart, so the sentence says how
	// many it holds, as the Overview's tile does (#1792).
	// Until the list is read, the audit's own counts stand in, so the
	// sentence never says no findings while they load or fail to.
	const listed = Array.isArray( open );
	const count = listed ? open.length : Number( audited && overview.open_findings ) || 0;
	const snoozed = listed ? open.filter( ( finding ) => finding.snoozed_until ).length : Number( audited && overview.snoozed_findings ) || 0;

	const stats = [
		sprintf(
			/* translators: %d: how many checks ran. */
			_n( '%d check run', '%d checks run', ran, 'bettershield' ),
			ran
		),
		missed > 0
			? sprintf(
					/* translators: %d: how many checks could not run. Short: the notice below says the rest. */
					_n( '%d couldn’t run', '%d couldn’t run', missed, 'bettershield' ),
					missed
			  )
			: '',
		audited && ! waiting ? historyClause( readableHistory( overview.history ) ) : '',
		split,
	].filter( Boolean );

	return (
		<section ref={ heroRef } tabIndex={ heroRef ? -1 : undefined } className="bs-ds-card bs-ds-fhero" aria-label={ __( 'Score', 'bettershield' ) }>
			<div className="bs-ds-fhero__text">
				{ /* The figure stands here, and the how behind an ⓘ beside it. */ }
				<div className="bs-ds-fhero__head">
					<h2 className="bs-ds-fhero__title">
						{ /* A snoozed finding still counts, but is not called open:
						     the Open tab leaves it out (#2483). */ }
						{ waiting ? __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) : null }
						{ audited && ! waiting
							? sprintf(
									snoozed > 0
										? /* translators: 1: letter grade, 2: score, 3: findings, some snoozed, 4: the points they take off, e.g. "111 points". */
										  _n(
												'Grade %1$s, %2$d/100. Your %3$d finding takes %4$s off the score.',
												'Grade %1$s, %2$d/100. Your %3$d findings take %4$s off the score.',
												count,
												'bettershield'
										  )
										: /* translators: 1: letter grade, 2: score, 3: open findings, 4: the points they take off, e.g. "111 points". */
										  _n(
												'Grade %1$s, %2$d/100. Your %3$d open finding takes %4$s off the score.',
												'Grade %1$s, %2$d/100. Your %3$d open findings take %4$s off the score.',
												count,
												'bettershield'
										  ),
									grade,
									score,
									count,
									sprintf(
										/* translators: %d: points off the score. */
										_n( '%d point', '%d points', points, 'bettershield' ),
										points
									)
							  )
							: null }
						{ audited ? null : __( 'No audit has run yet. Use Run Audit above.', 'bettershield' ) }
					</h2>
					<InfoTip label={ __( 'About this score', 'bettershield' ) }>
						{ __( 'The audit only reads, so nothing was changed to get this score. Most fixes can be undone.', 'bettershield' ) }
					</InfoTip>
				</div>
				{ /* Its own line: the title holds to one line by design. */ }
				{ audited && ! waiting && snoozed > 0 ? (
					<p className="bs-ds-fhero__para">
						{ sprintf(
							/* translators: %d: how many of the open findings are snoozed. */
							_n( '%d of them is snoozed but still lowers your score.', '%d of them are snoozed but still lower your score.', snoozed, 'bettershield' ),
							snoozed
						) }
					</p>
				) : null }
				{ audited ? (
					// A list, so each figure is read as its own item; the dots
					// between them are only drawn.
					<ul className="bs-ds-fhero__stats" role="list">
						{ stats.map( ( stat, index ) => (
							<li key={ stat } className="bs-ds-fhero__stat">
								{ index ? <span aria-hidden="true">{ '  ·  ' }</span> : null }
								{ stat }
							</li>
						) ) }
					</ul>
				) : null }
			</div>
		</section>
	);
}
