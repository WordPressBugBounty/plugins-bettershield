/**
 * Protection › Hardening: the items that are not about signing in.
 *
 * The score strip first, because every switch below moves the number on it,
 * and a list of switches with no score over it makes the reader hold that
 * number in their head while they work down the list. Then a card per group
 * of items; the groups say what each item protects. The sign-in group is read
 * on Login & access instead, beside the lockouts it belongs with.
 */

import './Hardening.css';

import { createInterpolateElement } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { useResource } from '../../store';
import { postureSentence } from '../../ui/scoreHistory';
import { coverage, scoreSplit } from '../data/overview';
import { fixesWorth, gradeTone, recentScores, unanswered } from '../data/protect';
import Badge from '../ui/Badge';
import Skeleton, { StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import Topics from '../ui/Topics';
import HardeningCards from './HardeningCards';
import SafeMode from './SafeMode';

/** The strip's names, shared by the strip and its stand-in. */
function stripLabels() {
	return {
		score: __( 'Score', 'bettershield' ),
		protections: __( 'Protections', 'bettershield' ),
		checks: __( 'Checks run', 'bettershield' ),
		findings: __( 'Open findings', 'bettershield' ),
	};
}

/**
 * Where the site stands and what the fixes on offer would make it, the
 * protections switched on below, what the audit managed, and what is open.
 *
 * @param {Object} props
 * @param {Object} props.data      The overview payload.
 * @param {Object} props.hardening The hardening resource, for the count of what is on.
 */
export function PostureStrip( { data, hardening } ) {
	const labels = stripLabels();
	const covered = coverage( data );
	const { fixes, worth, reachable } = fixesWorth( data );

	/*
	 * Nothing audited is not the same as nothing found. A site whose first
	 * audit has not run has no open findings because nobody has looked, and
	 * showing that as a perfect score is the one reading this must never give.
	 */
	const audited = !! data.generated_at;

	/*
	 * What the fixes on offer would gain: the score they would reach, from
	 * the server's own calculation, against the score now. Drawn only where
	 * they would move it.
	 */
	let worthLine = null;

	// The first file check can move the score, so the figures wait for it.
	const waiting = audited && Boolean( data.first_scan && data.first_scan.running );

	if ( worth > 0 && ! waiting ) {
		worthLine = sprintf(
			/* translators: 1: number of score points gained, 2: the score those points would reach, 3: how many protections are available. */
			_n( 'Turn on %3$d protection below to reach %2$d (+%1$d)', 'Turn on %3$d protections below to reach %2$d (+%1$d)', fixes, 'bettershield' ),
			worth,
			reachable,
			fixes
		);
	}

	// How the score was reached, as the Overview says it.
	const split = audited && ! waiting ? scoreSplit( data ) : '';

	// How many of this screen's switches are on, as the server counts them;
	// held in place while that is read.
	const counted = hardening.data?.count?.screens?.hardening || null;
	const failed = ! counted && 'error' === hardening.status;

	let protections = '—';

	if ( counted ) {
		protections = sprintf(
			/* translators: 1: how many protections are on, 2: how many there are. */
			__( '%1$d of %2$d', 'bettershield' ),
			counted.on,
			counted.total
		);
	}

	const tiles = [
		{
			key: 'score',
			icon: 'gauge',
			label: labels.score,
			value: (
				<span className="bs-ds-hstrip__score">
					{ /* The numeral and the grade are the statement, read as one
					     sentence rather than as "61 C". */ }
					<span className="screen-reader-text">
						{ waiting ? __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) : null }
						{ audited && ! waiting
							? sprintf(
									/* translators: 1: score out of 100, 2: letter grade. */
									__( 'Your site scores %1$d out of 100, grade %2$s.', 'bettershield' ),
									data.score,
									data.grade
							  )
							: null }
						{ audited ? null : __( 'This site has not been audited yet.', 'bettershield' ) }
					</span>
					<span aria-hidden="true">{ audited && ! waiting ? data.score : '—' }</span>
					<span aria-hidden="true" className="bs-ds-hstrip__grade">
						<Badge tone={ audited && ! waiting ? gradeTone( data.grade ) : 'neutral' }>
							{ waiting ? __( 'Scanning…', 'bettershield' ) : null }
							{ audited && ! waiting
								? sprintf(
										/* translators: %s: a letter grade, A through F. */
										__( 'Grade %s', 'bettershield' ),
										data.grade
								  )
								: null }
							{ audited ? null : __( 'Not audited', 'bettershield' ) }
						</Badge>
					</span>
				</span>
			),
			// One short line, as every tile has: how the 30 days moved is said
			// under "How this works", where the strip's longer sentences are.
			detail:
				split || worthLine ? (
					<>
						{ split ? <span className="bs-ds-hstrip__line">{ split }</span> : null }
						{ worthLine ? <span className="bs-ds-hstrip__line bs-ds-hstrip__worth">{ worthLine }</span> : null }
					</>
				) : null,
		},
		{
			key: 'protections',
			icon: 'shield-check',
			label: labels.protections,
			value: protections,
			detail: failed ? __( 'Could not be read', 'bettershield' ) : __( 'On', 'bettershield' ),
			pending: ! counted && ! failed,
		},
		{
			/*
			 * How many answered, not how many were attempted, and beside it how
			 * many did not: the two add up to the run, and a count of attempts
			 * would claim an answer from every check.
			 */
			key: 'checks',
			icon: 'list-checks',
			label: labels.checks,
			value: covered.ran,
			detail: sprintf(
				/* translators: %d: how many checks could not run. */
				_n( '%d couldn’t run this time', '%d couldn’t run this time', covered.missed, 'bettershield' ),
				covered.missed
			),
		},
		{
			/*
			 * A snoozed finding is still open and still counted in the score,
			 * so it is counted here too, and the line under it says how many
			 * of them are snoozed.
			 */
			key: 'findings',
			icon: 'flag',
			label: labels.findings,
			value: data.open_findings,
			detail:
				data.snoozed_findings > 0
					? sprintf(
							/* translators: %d: how many of the open findings are snoozed. */
							_n( 'open finding, %d snoozed', 'open findings, %d snoozed', data.open_findings, 'bettershield' ),
							data.snoozed_findings
					  )
					: null,
		},
	];

	return <Stats tiles={ tiles } />;
}

/**
 * The strip standing in for itself while the score is on its way, with the
 * names it arrives with.
 */
export function PostureStripBone() {
	return (
		<Skeleton label={ __( 'Loading the score…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( stripLabels() ) } />
		</Skeleton>
	);
}

/**
 * What the screen as a whole does, and what the score over it is and is not:
 * the sentences the classic posture band carried, behind one question.
 *
 * @param {Object} props
 * @param {Object} props.data The overview payload, once it has landed.
 */
export function HowThisWorks( { data } ) {
	let said = null;

	if ( data ) {
		const audited = !! data.generated_at;
		const days = recentScores( data.history );
		const { missed } = coverage( data );
		const { never, kept } = unanswered( data, missed );

		said = (
			<>
				<p>
					{ ! audited ? (
						__(
							'The first audit runs on its own shortly, or run one now. Until then, this screen cannot say whether anything needs fixing.',
							'bettershield'
						)
					) : (
						createInterpolateElement(
							// One sentence, so a translator can reorder it.
							__( '<strong>Nothing was changed to produce this score.</strong>', 'bettershield' ),
							{ strong: <strong /> }
						)
					) }
				</p>

				{ /* How the score moved over the recorded days, which the score's
				     tile above has no room for. */ }
				{ days.length ? <p className="bs-ds-hstrip__movement">{ postureSentence( days ) }</p> : null }

				{ /* A check that could not be evaluated keeps what it last said;
				     one that never answered has nothing to keep. */ }
				{ audited && kept > 0 ? (
					<p>
						{ sprintf(
							/* translators: %d: how many checks could not be evaluated. */
							_n(
								'%d check couldn’t run this time, so the score uses its last result.',
								'%d checks couldn’t run this time, so the score uses their last results.',
								kept,
								'bettershield'
							),
							kept
						) }
					</p>
				) : null }

				{ audited && never > 0 ? (
					<p>
						{ sprintf(
							/* translators: %d: how many checks could not be evaluated and never have been. */
							_n(
								'%d check couldn’t run and has no result yet.',
								'%d checks couldn’t run and have no result yet.',
								never,
								'bettershield'
							),
							never
						) }
					</p>
				) : null }
			</>
		);
	}

	return (
		<Topics
			items={ [
				{
					key: 'how',
					label: __( 'How this works', 'bettershield' ),
					lead: __(
						'Each protection turns on and off on its own. Previews change nothing.',
						'bettershield'
					),
					body: said,
				},
			] }
		/>
	);
}

export default function Hardening() {
	// The strip reads the overview payload. Held in place while it is on its
	// way, and kept through a refresh of a posture already on screen.
	const posture = useResource( 'overview' ).resource;
	const hardening = useResource( 'hardening' ).resource;

	return (
		<>
			{ /*
			   Safe mode takes off what runs inside WordPress. The three items
			   whose protection is a file (PHP in uploads, sensitive files,
			   uploads listings) leave it on disk, and the server keeps
			   applying it.
			*/ }
			<SafeMode note={ __( 'Three protections stored in server files stay on: blocking code in uploads, hiding private files and hiding upload folders.', 'bettershield' ) } />

			{ posture.data ? <PostureStrip data={ posture.data } hardening={ hardening } /> : null }
			{ ! posture.data && 'error' !== posture.status ? <PostureStripBone /> : null }

			<HowThisWorks data={ posture.data } />

			<HardeningCards
				screen="hardening"
				empty={ __( 'No hardening items are available.', 'bettershield' ) }
				loading={ [ 4, 3, 3 ] }
				// Not every protection here has a full way back: Strict HTTPS
				// stays in browsers that saw it (#2821).
				undoNote={ __( 'Every change is logged, and most can be undone.', 'bettershield' ) }
			/>
		</>
	);
}
