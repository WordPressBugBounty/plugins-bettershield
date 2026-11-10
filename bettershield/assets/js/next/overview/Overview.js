/**
 * The redrawn Overview (design frame 27:53063): the hero, the one status
 * alert, then two columns: this week, findings and activity on the left;
 * protection, agents and recovery on the right.
 */

import './Overview.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { useResource } from '../../store';
import { useAuditRun } from '../../shared/AuditAction';
import Hero from './Hero';
import StatusAlert from './StatusAlert';
import ThisWeek from './ThisWeek';
import FindingsCard from './FindingsCard';
import ActivityCard from './ActivityCard';
import { AgentsCard, FilesCard, ProtectionTray, RecoveryCard } from './Rail';
import Before from './Before';
import AuditSummary from './AuditSummary';
import SinceLastVisit from './SinceLastVisit';
import CheckByCheck from './CheckByCheck';
import ReleaseNote from './ReleaseNote';
import FrontEndCost from './FrontEndCost';
import ReportCard from './ReportCard';
import { Neighbors, Unusual } from './Signals';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { useKept } from '../ui/useKept';
import { focusIfLost } from '../ui/focus';
import { useFirstScan } from '../data/firstScan';

export default function Overview() {
	const { resource, reload } = useResource( 'overview' );
	const { running } = useAuditRun();
	const [ view, setView ] = useState( 'first' );
	const findings = useRef( null );
	const hero = useRef( null );
	// A refresh keeps the copy already on screen while the fresh one arrives,
	// and after it fails, so the cards and what the reader had open in them
	// stay put. Only a first read has nothing to draw.
	const overview = useKept( resource.data );
	const progress = useFirstScan( overview ? overview.first_scan : null, reload );
	const failedRef = useRef( null );
	const [ retrying, setRetrying ] = useState( false );
	// What a repair of the plugin's record keeping said, kept across the
	// reload that takes its card away.
	const [ storageNote, setStorageNote ] = useState( '' );
	const retry = () => {
		setRetrying( true );
		reload();
	};

	// Try again goes with its alert while the read is out. Once it answers,
	// focus goes back to the alert if it failed again, or to the score.
	useEffect( () => {
		if ( ! retrying || 'loading' === resource.status ) {
			return;
		}

		setRetrying( false );
		focusIfLost( 'error' === resource.status ? failedRef.current : hero.current );
	}, [ retrying, resource.status ] );

	const failed = (
		<Alert
			tone="error"
			live
			alertRef={ failedRef }
			title={ __( 'That could not be loaded.', 'bettershield' ) }
			desc={ __( 'This is a display problem, not a security problem. Your site is unchanged.', 'bettershield' ) }
			actions={
				<Button type="secondary" size="sm" onClick={ retry }>
					{ __( 'Try Again', 'bettershield' ) }
				</Button>
			}
		/>
	);

	// "See Which One" opens the findings card on what could not be checked.
	const showUnknown = () => {
		setView( 'unknown' );

		if ( findings.current && findings.current.scrollIntoView ) {
			findings.current.scrollIntoView( { block: 'start' } );
		}
	};

	if ( ! overview && 'error' === resource.status ) {
		return failed;
	}

	if ( ! overview ) {
		return <p className="bs-ds-t14 bs-ds-r bs-ds-c2">{ __( 'Loading…', 'bettershield' ) }</p>;
	}

	// Nothing audited is not nothing found: until an audit has run, the hero
	// says so and no list claims there is nothing to do. A refresh that failed
	// says so above the copy it could not replace.
	return (
		<>
			{ 'error' === resource.status ? failed : null }
			<Before
				overview={ overview }
				onGone={ () => hero.current && hero.current.focus() }
				reload={ reload }
				note={ storageNote }
				setNote={ setStorageNote }
			/>
			<Hero overview={ overview } running={ running } onUnknown={ showUnknown } heroRef={ hero } progress={ progress } />
			<StatusAlert overview={ overview } onClosed={ () => hero.current && hero.current.focus() } />
			<div className="bs-ds-ov-grid">
				<div className="bs-ds-ov-col">
					<ThisWeek receipts={ overview.receipts } protection={ overview.panels ? overview.panels.protection : null } />
					{ overview.generated_at ? (
						<div ref={ findings }>
							<FindingsCard overview={ overview } view={ view } setView={ setView } />
						</div>
					) : null }
					{ overview.panels && overview.panels.activity ? <ActivityCard overview={ overview } /> : null }
					{ /* The audit in other words, what happened since the last
					     visit, which checks moved the score, what an update
					     added, and what the plugin costs a visitor's page. */ }
					<AuditSummary open={ overview.open_findings } openKeys={ ( overview.findings || [] ).map( ( f ) => f.id ).join( ' ' ) } />
					<SinceLastVisit block={ overview.since_last_visit } />
					<CheckByCheck generatedAt={ overview.generated_at } />
					<ReleaseNote release={ overview.release } />
					<FrontEndCost cost={ overview.front_end_cost } />
				</div>
				<aside className="bs-ds-ov-col">
					<ProtectionTray protection={ overview.panels ? overview.panels.protection : null } />
					<AgentsCard />
					<RecoveryCard overview={ overview } />
					<ReportCard />
					<FilesCard panel={ overview.panels ? overview.panels.files : null } />
					<Neighbors split={ overview.neighbors } />
					<Unusual panel={ overview.panels ? overview.panels.unusual : null } />
				</aside>
			</div>
		</>
	);
}
