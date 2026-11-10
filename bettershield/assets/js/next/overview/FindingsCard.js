/**
 * The Overview's Findings card (design frame 27:53145): the open findings'
 * count and points, a severity bar and legend, and four views of them.
 */

import './FindingsCard.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { findingsUrl, mayManage, sectionUrl } from '../../nav';
import { isWorking, useStore } from '../../store';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Segmented from '../ui/Segmented';
import { panelProps } from '../ui/tabKeys';
import { focusIfLost } from '../ui/focus';
import { formatCount } from '../../ui/count';
import FindingCard from './FindingCard';
import { managedTitle, movedLine } from '../findings/Bulk';
import { pointsLostLabel } from '../findings/Rows';
import { managedKeys, runEach } from '../data/bulk';
import { SEVERITIES, awake, doFirst, firstBack, healthOf, isOneClick, pointsOff, severityCounts, severityTicks } from '../data/overview';

const LABELS = {
	critical: () => __( 'Critical', 'bettershield' ),
	high: () => __( 'High', 'bettershield' ),
	medium: () => __( 'Medium', 'bettershield' ),
	low: () => __( 'Low', 'bettershield' ),
	info: () => __( 'Info', 'bettershield' ),
};

/**
 * A finding's one-line summary, where it has one: the changed files say how
 * many and of what kind, from the file report. Every other finding's title
 * already says what is wrong. The first sentence of why it matters stood
 * under it, cut off with an ellipsis and no way to read the rest (#1326);
 * the whole of it is under How to fix, and on Findings.
 */
function metaFor( finding, files ) {
	if ( 'files_altered' === finding.id && files && files.kinds ) {
		const kinds = files.kinds;
		const total = ( Number( kinds.modified ) || 0 ) + ( Number( kinds.added ) || 0 ) + ( Number( kinds.removed ) || 0 );

		return sprintf(
			/* translators: 1: files that differ, 2: altered, 3: nothing published, 4: missing. In the words the Files screen labels its rows with. */
			_n( '%1$s file: %2$s changed, %3$s added, %4$s missing', '%1$s files: %2$s changed, %3$s added, %4$s missing', total, 'bettershield' ),
			formatCount( total ),
			formatCount( kinds.modified ),
			formatCount( kinds.added ),
			formatCount( kinds.removed )
		);
	}

	return '';
}

function SeverityBar( { counts } ) {
	const ticks = severityTicks( counts );
	const spans = [];

	SEVERITIES.forEach( ( severity, index ) => {
		for ( let n = 0; n < ticks[ index ]; n++ ) {
			spans.push( <span key={ `${ severity }-${ n }` } className={ `bs-ds-sevbar__tick bs-ds-sevbar__tick--${ severity }` } /> );
		}
	} );

	return (
		<div className="bs-ds-sevbar" aria-hidden="true">
			{ spans }
		</div>
	);
}

function Legend( { counts } ) {
	// The four the design always lists, and Critical whenever there is one.
	const shown = SEVERITIES.filter( ( severity ) => 'critical' !== severity || counts.critical > 0 );

	return (
		<div className="bs-ds-legend">
			{ shown.map( ( severity ) => (
				<span key={ severity } className="bs-ds-legend__item">
					<span className={ `bs-ds-legend__dot bs-ds-legend__dot--${ severity }` } />
					<span className="bs-ds-r bs-ds-c2">{ LABELS[ severity ]() }</span>
					<span className="bs-ds-m bs-ds-c1">{ counts[ severity ] }</span>
				</span>
			) ) }
		</div>
	);
}

const VIEWS = 'bs-ds-fviews';

export function Panel( { view, head, badge, lede = null, scroll = false, empty, headRef, children } ) {
	const items = ( Array.isArray( children ) ? children : [ children ] ).flat().filter( Boolean );

	return (
		<div className="bs-ds-fpanel" { ...panelProps( VIEWS, view ) }>
			{ /* Named for screen readers and focus only: the selected tab
			     above already says it on screen (#2517). */ }
			<span ref={ headRef } tabIndex={ -1 } id={ `${ VIEWS }-${ view }-title` } className="bs-ds-fpanel__title">
				{ head }
			</span>
			{ badge ? (
				<div className="bs-ds-fpanel__head">
					<Badge>{ badge }</Badge>
				</div>
			) : null }
			{ lede ? <p className="bs-ds-fpanel__lede bs-ds-t12 bs-ds-r bs-ds-c2">{ lede }</p> : null }
			{ items.length ? (
				// A list that scrolls inside the card is a stop for the keyboard,
				// named by its panel, or the rows below its fold could not be
				// reached without a mouse (#2186).
				<div
					className={ `bs-ds-fpanel__list${ scroll ? ' bs-ds-fpanel__list--scroll' : '' }` }
					// eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrolling region has to take focus to be scrolled from the keyboard.
					tabIndex={ scroll ? 0 : undefined }
					role={ scroll ? 'region' : undefined }
					aria-labelledby={ scroll ? `${ VIEWS }-${ view }-title` : undefined }
				>
					{ items }
				</div>
			) : (
				<p className="bs-ds-t12 bs-ds-r bs-ds-c2">{ empty }</p>
			) }
		</div>
	);
}

function RecentCard( { entry, onUndone } ) {
	const { busy, revertItem } = useStore();
	const working = isWorking( busy, entry.item );
	let action = null;

	if ( entry.reverted ) {
		action = <Badge>{ __( 'Undone', 'bettershield' ) }</Badge>;
	} else if ( entry.undoable ) {
		action = (
			<Button type="ghost" size="md" isBusy={ working } disabled={ working } onClick={ () => revertItem( entry.item, onUndone ) }>
				{ __( 'Undo', 'bettershield' ) }
			</Button>
		);
	} else {
		// Turned off somewhere else. Said rather than left blank: an empty
		// slot where the rows beside it have a button reads as a button
		// that failed to draw.
		action = <Badge>{ __( 'Already off', 'bettershield' ) }</Badge>;
	}

	// An undo that cannot take back everything says so, in the Hardening
	// screen's words, rather than under "Undo never expires".
	const note = ! entry.reverted && entry.undoable && false === entry.reversible ? __( 'Undo turns this off, but browsers that already visited keep using HTTPS until their saved setting expires.', 'bettershield' ) : null;

	return <FindingCard finding={ { id: entry.item, title: entry.label } } icon="shield" meta={ whenPhrase( entry.at ) } note={ note } action={ action } />;
}

/**
 * @param {Object}   props
 * @param {Object}   props.overview The audit.
 * @param {string}   props.view     The view on show: all, first, unknown or recent.
 * @param {Function} props.setView  Changes it.
 */
export default function FindingsCard( { overview, view, setView } ) {
	// A snoozed finding is still open and still counted in the score; it is
	// only left out of what this card asks for next, and said as left out.
	const all = overview.findings || [];
	const findings = awake( all );
	const snoozed = all.length - findings.length;
	// With every open finding snoozed, nothing is asked for until one is back.
	const quiet = snoozed
		? sprintf(
				/* translators: %s: when the first snoozed finding comes back, e.g. "Oct 7, 12:00 PM". */
				__( 'All open findings are snoozed. The first returns %s.', 'bettershield' ),
				whenPhrase( firstBack( all ) )
		  )
		: __( 'Nothing needs urgent attention.', 'bettershield' );
	const counts = severityCounts( findings );
	const points = pointsOff( findings, healthOf( overview ) );
	const files = overview.panels ? overview.panels.files : null;
	// Null for a reader who may not undo: the view is not offered to them.
	const recentPanel = overview.panels ? overview.panels.recent : null;
	const recent = recentPanel ? recentPanel.entries || [] : [];
	// The list keeps rows already undone and rows already off, so what it
	// says of them is read off the rows rather than said of all of them.
	const open = recent.filter( ( entry ) => entry.undoable && ! entry.reverted );
	const undoable = open.length;
	// "Undo never expires" over a row whose undo leaves the header in
	// browsers is the claim that row's own caveat takes back.
	const whole = open.every( ( entry ) => false !== entry.reversible );
	let recentLede = null;

	if ( undoable > 0 && undoable === recent.length ) {
		recentLede = __( 'You can undo any of these.', 'bettershield' );
	} else if ( undoable > 0 ) {
		recentLede = __( 'You can undo any of these.', 'bettershield' );
	}
	const unknown = overview.checks_unknown || [];
	// A stale finding's check is already listed among the ones that could not
	// run; it is shown once, as that check.
	const unknownKeys = new Set( unknown.map( ( check ) => check.key ) );
	const stale = all.filter( ( finding ) => finding.stale && ! unknownKeys.has( finding.id ) );
	const headRef = useRef( null );
	const { busy, revertItem, suppress, unsuppress } = useStore();
	/*
	 * A finding fixed in one click left the list with no word and no Undo,
	 * where a snooze on Findings says so and offers one (#1914). The fix is
	 * said above the views, named by the protection the answer lists, with
	 * an Undo that turns it off again. Focus goes to it, unless the reader
	 * moved on.
	 */
	const [ applied, setApplied ] = useState( null );
	const appliedRef = useRef( null );
	const undoing = Boolean( applied ) && isWorking( busy, applied.item );

	useEffect( () => {
		if ( applied ) {
			focusIfLost( appliedRef.current );
		}
	}, [ applied ] );

	const onApplied = ( finding, data ) => {
		const items = ( data && data.hardening && data.hardening.items ) || [];
		const item = items.find( ( candidate ) => candidate.id === finding.hardening_item );

		setApplied( { item: finding.hardening_item, name: ( item && item.title ) || finding.title } );
	};
	const undoApplied = () =>
		revertItem( applied.item, () => {
			setApplied( null );
			focusIfLost( headRef.current );
		} );

	/*
	 * "I manage this myself": held here, because the card it was chosen on
	 * leaves the list with the answer and the way back has to stay.
	 */
	const [ marking, setMarking ] = useState( '' );
	const [ marked, setMarked ] = useState( null );
	const markedRef = useRef( null );

	useEffect( () => {
		if ( marked ) {
			focusIfLost( markedRef.current );
		}
	}, [ marked ] );

	const markManaged = async ( id, keys ) => {
		setMarking( id );
		const outcome = await runEach( keys, ( key, ok, no ) => suppress( key, ok, no ) );
		setMarking( '' );

		if ( outcome.done.length || outcome.failed.length ) {
			setMarked( { keys: outcome.done, reason: outcome.failed.length ? outcome.reason || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) : '' } );
		}
	};
	const undoManaged = async () => {
		setMarking( 'undo' );
		const outcome = await runEach( [ ...marked.keys ].reverse(), ( key, ok, no ) => unsuppress( key, ok, no ) );
		setMarking( '' );

		if ( outcome.failed.length ) {
			setMarked( { keys: marked.keys.filter( ( key ) => ! outcome.done.includes( key ) ), reason: outcome.reason } );
		} else if ( outcome.done.length ) {
			setMarked( null );
			focusIfLost( headRef.current );
		}
	};
	const manageOf = ( finding ) => {
		if ( ! finding.self_managed || ! mayManage() ) {
			return null;
		}

		const keys = managedKeys( finding, all );
		const covered = all.filter( ( other ) => keys.includes( other.id ) );
		const also = covered.find( ( other ) => other.id !== finding.id );

		return {
			also: also ? also.title : '',
			points: pointsOff( covered, healthOf( overview ) ),
			working: marking === finding.id,
			onConfirm: () => markManaged( finding.id, keys ),
		};
	};
	const card = ( finding ) => (
		<FindingCard key={ `f-${ finding.id }` } finding={ finding } meta={ metaFor( finding, files ) } checked={ overview.generated_at } onApplied={ onApplied } safeMode={ overview.safe_mode } manage={ manageOf( finding ) } />
	);

	return (
		<Card aria-labelledby="bs-ds-findings-title">
			<CardHead icon="list-checks" title={ __( 'Findings', 'bettershield' ) } id="bs-ds-findings-title" line>
				<Button type="secondary" size="sm" href={ sectionUrl( 'bettershield-findings' ) }>
					{ __( 'View All', 'bettershield' ) }
				</Button>
			</CardHead>
			<div className="bs-ds-findings__body">
				<div className="bs-ds-findings__summary">
					<div className="bs-ds-findings__totals">
						<p className="bs-ds-findings__total">{ findings.length }</p>
						{ overview.first_scan && overview.first_scan.running ? null : <Badge tone="red">{ pointsLostLabel( points ) }</Badge> }
					</div>
					<div className="bs-ds-findings__severity">
						<SeverityBar counts={ counts } />
						<Legend counts={ counts } />
					</div>
				</div>
				{ snoozed ? (
					<p className="bs-ds-findings__snoozed bs-ds-t12 bs-ds-r bs-ds-c2">
						{ sprintf(
							/* translators: %d: number of snoozed findings. */
							_n(
								'%d snoozed finding is hidden until it returns, but still counts in the score.',
								'%d snoozed findings are hidden until they return, but still count in the score.',
								snoozed,
								'bettershield'
							),
							snoozed
						) }{ ' ' }
						<a href={ findingsUrl( 'snoozed' ) }>{ _n( 'See it under Findings', 'See them under Findings', snoozed, 'bettershield' ) }</a>
					</p>
				) : null }
				{ applied ? (
					<Alert
						live
						alertRef={ appliedRef }
						tone="success"
						title={ sprintf(
							/* translators: %s: the protection that was turned on. */
							__( 'Applied: %s', 'bettershield' ),
							applied.name
						) }
						actions={
							<Button type="ghost" size="sm" isBusy={ undoing } disabled={ undoing } onClick={ undoApplied }>
								{ __( 'Undo', 'bettershield' ) }
							</Button>
						}
						onDismiss={ () => {
							setApplied( null );
							focusIfLost( headRef.current );
						} }
					/>
				) : null }
				{ marked ? (
					<Alert
						live
						alertRef={ markedRef }
						tone={ marked.keys.length ? 'success' : 'error' }
						title={ marked.keys.length ? managedTitle( marked.keys.length ) : marked.reason }
						desc={ marked.keys.length ? [ movedLine( marked.keys.length ), marked.reason ].filter( Boolean ).join( ' ' ) : undefined }
						actions={
							marked.keys.length ? (
								<Button type="ghost" size="sm" isBusy={ 'undo' === marking } disabled={ 'undo' === marking } onClick={ undoManaged }>
									{ __( 'Undo', 'bettershield' ) }
								</Button>
							) : undefined
						}
						onDismiss={ () => {
							setMarked( null );
							focusIfLost( headRef.current );
						} }
					/>
				) : null }
				<div className="bs-ds-findings__views">
					<Segmented
						id={ VIEWS }
						label={ __( 'Findings', 'bettershield' ) }
						selected={ 'unknown' === view ? 'first' : view }
						onSelect={ setView }
						options={ [
							{ key: 'all', label: __( 'All', 'bettershield' ) },
							{ key: 'first', label: __( 'Do first', 'bettershield' ) },
							recentPanel ? { key: 'recent', label: __( 'Done recently', 'bettershield' ) } : null,
						].filter( Boolean ) }
					/>
					{ 'all' === view ? (
						<Panel
							view={ view }
							headRef={ headRef }
							head={ sprintf(
								/* translators: %d: how many findings are open. */
								_n( 'All %d open finding', 'All %d open findings', findings.length, 'bettershield' ),
								findings.length
							) }
							scroll
							empty={ quiet }
						>
							{ findings.map( card ) }
						</Panel>
					) : null }
					{ 'first' === view || 'unknown' === view ? (
						<Panel
							view={ view }
							headRef={ headRef }
							head={ __( 'Do first', 'bettershield' ) }
							badge={ sprintf(
								/* translators: 1: findings with a one-click fix, 2: open findings. */
								__( '%1$d of %2$d can be fixed in one click', 'bettershield' ),
								findings.filter( isOneClick ).length,
								findings.length
							) }
							empty={ quiet }
						>
							{ doFirst( findings ).map( card ) }
						</Panel>
					) : null }
					{ 'recent' === view && recentPanel ? (
						<Panel
							view={ view }
							headRef={ headRef }
							head={ __( 'Done recently', 'bettershield' ) }
							badge={ undoable > 0 && whole ? __( 'You can undo these at any time.', 'bettershield' ) : null }
							lede={ recentLede }
							scroll
							empty={ __( 'Nothing to undo', 'bettershield' ) }
						>
							{ recent.map( ( entry ) => (
								<RecentCard key={ `${ entry.item }-${ entry.at }` } entry={ entry } onUndone={ () => focusIfLost( headRef.current ) } />
							) ) }
						</Panel>
					) : null }
					{ /* Checks that could not run are not a thing to act on, so
					     they are a line under the list, not a tab (#2517). */ }
					{ unknown.length + stale.length > 0 ? (
						<div className="bs-ds-findings__unknown">
							<p className="bs-ds-t12 bs-ds-r bs-ds-c2">
								{ sprintf(
									/* translators: %d: how many checks could not run. The Overview's score card says the same (#2572). */
									_n( '%d couldn’t run this time.', '%d couldn’t run this time.', unknown.length + stale.length, 'bettershield' ),
									unknown.length + stale.length
								) }{ ' ' }
								<Button type="linksub" size="sm" aria-expanded={ 'unknown' === view } onClick={ () => setView( 'unknown' === view ? 'first' : 'unknown' ) }>
									{ 'unknown' === view ? _n( 'Hide It', 'Hide Them', unknown.length + stale.length, 'bettershield' ) : _n( 'See Which One', 'See Which Ones', unknown.length + stale.length, 'bettershield' ) }
								</Button>
							</p>
							{ 'unknown' === view ? (
								<div className="bs-ds-fpanel__list">
									{ unknown.map( ( check ) => (
										<FindingCard key={ `u-${ check.key }` } finding={ { id: check.key, title: check.title } } icon="circle-dashed" meta={ check.reason } action={ null } />
									) ) }
									{ stale.map( card ) }
								</div>
							) : null }
						</div>
					) : null }
				</div>
			</div>
		</Card>
	);
}
