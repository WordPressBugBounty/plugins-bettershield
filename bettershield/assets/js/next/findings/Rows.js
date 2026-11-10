/**
 * The report's table rows (Table kit 23:20078, as the bulk frames use it):
 * the header, a group row per severity or area, a row per finding with its
 * explanation underneath when open, and the summary.
 */

import './Rows.css';

import { createInterpolateElement, useState } from '@wordpress/element';
import { __, _n, _x, sprintf } from '@wordpress/i18n';
import { mayManage, sectionUrl, tabUrl } from '../../nav';
import { formatTime, isWorking, useStore } from '../../store';
import { announce } from '../../ui/announce';
import { whenPhrase } from '../../ui/when';
import { entryText, evidenceLabel, evidenceText, HIDDEN_KEYS, isNamespaceEntry, isPathKey } from '../../screens/findings/evidence';
import { truncationNote } from '../../ui/truncation';
import { AffectedTable, AlertFeedback, Explanation, ExposedFiles, LeftoverTools } from './Extras';
import { FixPanel, applyWord, fixLabel, fixWord, hasFix } from './Fix';
import { NEEDS_CHOICE, SHARED_FILES, applyDefault, defaultOf, sharedCodeHeld } from './defaults';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Checkbox from '../ui/Checkbox';
import Icon from '../ui/Icon';
import Menu from '../ui/Menu';
import { areaIcon, isOneClick } from '../data/overview';
import { METER, costs, viewOf } from '../data/findings';

export const SEVERITY = {
	critical: { tone: 'red', icon: 'circle-x', label: () => __( 'Critical', 'bettershield' ) },
	high: { tone: 'orange', icon: 'triangle-alert', label: () => __( 'High', 'bettershield' ) },
	medium: { tone: 'yellow', icon: 'scan', label: () => __( 'Medium', 'bettershield' ) },
	low: { tone: 'blue', icon: 'circle-dashed', label: () => __( 'Low', 'bettershield' ) },
	info: { tone: 'neutral', icon: 'clock', label: () => __( 'Info', 'bettershield' ) },
};

/**
 * A severity's badge. One this screen has no badge for is drawn in the info
 * badge's style under the name the finding carries, so it neither takes the
 * table down nor reads as a second Info group.
 *
 * @param {string} key The finding's severity.
 * @return {Object} The badge's tone, icon and label.
 */
export const severityOf = ( key ) => SEVERITY[ key ] || { ...SEVERITY.info, label: () => String( key ) };

/**
 * Points off the score, as the badges and totals say them.
 *
 * Isolated from the text around it, and set in the direction of what it
 * says, as a row's own figure is with `<bdi>`: in a right-to-left page the
 * minus trailed the number. Said with the first-strong isolate marks rather
 * than an element, because some callers put it inside a sentence.
 */
export const ptsLabel = ( n ) =>
	'\u2068' +
	sprintf(
		/* translators: %d: points off the score. */
		_n( '−%d pt', '−%d pts', n, 'bettershield' ),
		n
	) +
	'\u2069';

/**
 * The same figure said in full, for a badge that stands alone: "−85 pts"
 * beside the findings count said nothing about what it counted (#2408).
 *
 * @param {number} n Points off the score.
 * @return {string} The label, isolated from the page's direction.
 */
export const pointsLostLabel = ( n ) =>
	'\u2068' +
	sprintf(
		/* translators: %d: points the open findings take off the score. */
		_n( '%d point lost', '%d points lost', n, 'bettershield' ),
		n
	) +
	'\u2069';

/**
 * A row that is one block across the table: a message, an alert, the
 * explanation under a finding. Its one cell is laid out as its contents, so
 * the block draws exactly as it would outside a table.
 */
export function WholeRow( { className, children, ...rest } ) {
	return (
		<div className={ className } role="row" { ...rest }>
			<div className="bs-ds-fwhole" role="cell">
				{ children }
			</div>
		</div>
	);
}

export function HeadRow( { state, onAll, selectable } ) {
	return (
		<div className="bs-ds-frow bs-ds-frow--head" role="row">
			{ selectable ? <Checkbox role="columnheader" label={ __( 'Select all', 'bettershield' ) } state={ state } onChange={ onAll } /> : <span className="bs-ds-frow__gap" /> }
			<div className="bs-ds-fcol-find bs-ds-t12 bs-ds-m bs-ds-c2" role="columnheader">
				{ __( 'Finding', 'bettershield' ) }
			</div>
			<div className="bs-ds-fcol-cat bs-ds-t12 bs-ds-m bs-ds-c2" role="columnheader">
				{ __( 'Category', 'bettershield' ) }
			</div>
			<div className="bs-ds-fcol-imp bs-ds-t12 bs-ds-m bs-ds-c2" role="columnheader">
				{ __( 'Severity', 'bettershield' ) }
			</div>
			<div className="bs-ds-fcol-act" role="columnheader">
				<span className="bs-ds-t12 bs-ds-m bs-ds-c2 bs-ds-frow__acthead">{ __( 'Recommended action', 'bettershield' ) }</span>
				<span className="bs-ds-frow__moregap" />
			</div>
		</div>
	);
}

export function GroupRow( { group, by, areaLabel } ) {
	const severity = severityOf( group.key );
	const lead =
		'category' === by ? (
			<Badge icon={ areaIcon( group.key ) }>{ areaLabel( group.key ) }</Badge>
		) : (
			<Badge tone={ severity.tone } icon={ severity.icon }>
				{ severity.label() }
			</Badge>
		);

	return (
		<div className="bs-ds-frow bs-ds-frow--group" role="row">
			<div className="bs-ds-frow__lead" role="cell">
				{ lead }
				<span className="bs-ds-m bs-ds-c2">
					{ sprintf(
						/* translators: %d: how many findings the group holds. */
						_n( '%d finding', '%d findings', group.rows.length, 'bettershield' ),
						group.rows.length
					) }
				</span>
				{ 'severity' === by && 'critical' === group.key ? (
					<>
						<span className="bs-ds-r bs-ds-c3">·</span>
						<span className="bs-ds-m bs-ds-c1">{ __( 'Fix this first', 'bettershield' ) }</span>
					</>
				) : null }
			</div>
			<div className="bs-ds-fcol-imp" role="cell">
				<span className="bs-ds-t12 bs-ds-m bs-ds-c2 bs-ds-nowrap">{ group.points
						? ptsLabel( group.points )
						: sprintf(
								/* translators: %d: points off the score, here none. */
								_n( '%d pt', '%d pts', 0, 'bettershield' ),
								0
						  ) }</span>
			</div>
			<div className="bs-ds-fcol-act" />
		</div>
	);
}

/**
 * A row's control named by its finding: on a list, every one read "Apply
 * fix" or "Open Users" with nothing to tell them apart (#2187). The words
 * shown stay as they are; the name adds what they are about, as Explain's
 * does.
 *
 * @param {string} words   The control's words.
 * @param {Object} finding The finding.
 * @return {string} The name.
 */
export function aboutFinding( words, finding ) {
	return sprintf(
		/* translators: 1: a control's words, e.g. "Apply Fix"; 2: what it is about, e.g. "Old remote publishing (XML-RPC) is turned on". */
		_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
		words,
		finding.title
	);
}

/** The vulnerability check's list of things installed, drawn as its table rather than as words. */
function affected( evidence ) {
	return Array.isArray( evidence?.items ) && evidence.items.length && undefined !== evidence.items[ 0 ].installed_version;
}

/** The leftover-tools check's list, drawn with a way to move each tool out of reach. */
function tools( evidence ) {
	return Array.isArray( evidence?.tools ) && evidence.tools.length > 0;
}

/**
 * The downloadable files, drawn with a way to move each out of reach where
 * the check marked which can be: only where the rule that hides them
 * cannot apply on this server.
 */
function exposedFiles( evidence ) {
	return Array.isArray( evidence?.files ) && evidence.files.length > 0 && undefined !== evidence.files[ 0 ].quarantine;
}

/** How many entries of a list show before "Show all". */
const LIST_SHOWN = 5;

/**
 * A list of evidence as a list: one entry to a line, under its label. Joined
 * into one string beside the label, a list of namespaces or hooks broke into
 * a ragged column a word or two wide (#1970). Past five, the rest wait behind
 * "Show all", and so do the routes behind each namespace.
 *
 * @param {Object} props
 * @param {Array}  props.items The entries.
 */
function EvidenceList( { items } ) {
	const [ all, setAll ] = useState( false );
	const routed = items.some( ( item ) => isNamespaceEntry( item ) && Array.isArray( item.routes ) && item.routes.length );
	const shown = all ? items : items.slice( 0, LIST_SHOWN );
	const more = items.length > LIST_SHOWN;

	return (
		<>
			<ul className="bs-ds-fdetail__list">
				{ shown.map( ( item, index ) => (
					<li key={ index }>
						{ entryText( item ) }
						{ all && isNamespaceEntry( item ) && Array.isArray( item.routes ) && item.routes.length ? (
							<ul className="bs-ds-fdetail__sublist">
								{ item.routes.map( ( route ) => (
									<li key={ route }>{ route }</li>
								) ) }
							</ul>
						) : null }
					</li>
				) ) }
			</ul>
			{ more || routed ? (
				<button type="button" className="bs-ds-fdetail__more" aria-expanded={ all } onClick={ () => setAll( ( was ) => ! was ) }>
					{ all && __( 'Show Fewer', 'bettershield' ) }
					{ ! all && more
						? sprintf(
								/* translators: %d: how many entries the list holds. */
								__( 'Show All %d', 'bettershield' ),
								items.length
						  )
						: null }
					{ ! all && ! more ? __( 'Show the Addresses', 'bettershield' ) : null }
				</button>
			) : null }
		</>
	);
}

function Evidence( { finding } ) {
	const cut = truncationNote( finding.evidence || {} );
	const drawnApart = [ affected( finding.evidence ) ? 'items' : '', tools( finding.evidence ) ? 'tools' : '', exposedFiles( finding.evidence ) ? 'files' : '' ];
	const entries = Object.entries( finding.evidence || {} ).filter( ( [ key ] ) => ! HIDDEN_KEYS.includes( key ) && ! drawnApart.includes( key ) );

	return (
		<div className="bs-ds-fdetail__tray">
			<div className="bs-ds-fdetail__card bs-ds-fdetail__card--inner">
				<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">{ __( 'Evidence', 'bettershield' ) }</p>
				<div className="bs-ds-fdetail__body">
					{ entries.length ? (
						entries.map( ( [ key, value ] ) => {
							const list = Array.isArray( value ) && value.length > 0;

							return (
								<div key={ key } className={ `bs-ds-fdetail__item${ 1 === entries.length ? ' is-value' : '' }${ list ? ' is-list' : '' }` }>
									<span className="bs-ds-t12 bs-ds-r bs-ds-c2">{ isPathKey( key ) ? key : evidenceLabel( key, finding.id ) }</span>
									{ list ? (
										<div className="bs-ds-m bs-ds-c1 bs-ds-fdetail__value">
											<EvidenceList items={ value } />
										</div>
									) : (
										<span className="bs-ds-m bs-ds-c1 bs-ds-fdetail__value">{ evidenceText( value, key, finding.id ) }</span>
									) }
								</div>
							);
						} )
					) : (
						<p className="bs-ds-fdetail__text">{ __( 'No extra details for this finding.', 'bettershield' ) }</p>
					) }
					{ cut ? <p className="bs-ds-fdetail__text">{ cut }</p> : null }
					{ finding.stale && finding.stale_reason ? <p className="bs-ds-fdetail__text">{ finding.stale_reason }</p> : null }
					{ finding.fixed_now ? <p className="bs-ds-fdetail__text">{ __( 'This is what the audit saw before the fix. It updates the next time this page loads.', 'bettershield' ) }</p> : null }
				</div>
			</div>
			<div className="bs-ds-fdetail__foot bs-ds-t12 bs-ds-r bs-ds-c2">
				<span>{ __( 'Last checked:', 'bettershield' ) }</span>
				<span>{ formatTime( finding.last_seen_at ) }</span>
			</div>
		</div>
	);
}

function Fact( { title, children } ) {
	return (
		<div className="bs-ds-fdetail__card">
			<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">{ title }</p>
			<div className="bs-ds-fdetail__body">
				<p className="bs-ds-fdetail__text">{ children }</p>
			</div>
		</div>
	);
}

/**
 * The explanation under a row (Table/Row detail · Finding, 27:43366).
 *
 * Under the four facts, across the detail's width: the vulnerable versions,
 * the leftover tools and their quarantine, the plain-language explanation,
 * and the question asked of somebody who came from an alert.
 *
 * @param {Object}  props
 * @param {Object}  props.finding   The finding.
 * @param {string}  props.id        The detail's element id.
 * @param {boolean} props.fromAlert Whether the reader opened it from an alert.
 */
export function RowDetail( { finding, id, fromAlert = false } ) {
	return (
		<WholeRow className="bs-ds-fdetail" id={ id } aria-label={ finding.title }>
			<Fact title={ __( 'Why it matters', 'bettershield' ) }>{ finding.why }</Fact>
			<Fact title={ __( 'What to know first', 'bettershield' ) }>{ finding.break_note }</Fact>
			<Fact title={ __( 'Effect on the score', 'bettershield' ) }>
				{ costs( finding )
					? sprintf(
							/* translators: 1: severity label, 2: number of points. */
							_n(
								'This lowers your score by %2$d point until it’s fixed (%1$s severity).',
								'This lowers your score by %2$d points until it’s fixed (%1$s severity).',
								finding.deduction,
								'bettershield'
							),
							severityOf( finding.severity ).label().toLowerCase(),
							finding.deduction
					  )
					: __( 'Nothing. Only open findings affect the score.', 'bettershield' ) }
			</Fact>
			{ /* The exact next step, where the finding has one (#1954). */ }
			<FixPanel finding={ finding } id={ `${ id }-fix` } />
			<Evidence finding={ finding } />
			{ affected( finding.evidence ) ? <AffectedTable items={ finding.evidence.items } label={ finding.title } /> : null }
			{ tools( finding.evidence ) ? <LeftoverTools tools={ finding.evidence.tools } open={ 'open' === finding.status } label={ finding.title } /> : null }
			{ exposedFiles( finding.evidence ) ? <ExposedFiles files={ finding.evidence.files } open={ 'open' === finding.status } label={ finding.title } /> : null }
			<Explanation finding={ finding } />
			{ fromAlert ? <AlertFeedback /> : null }
		</WholeRow>
	);
}

/**
 * One finding's row.
 *
 * @param {Object}   props
 * @param {Object}   props.finding    The finding.
 * @param {string}   props.areaLabel  Its area's name.
 * @param {boolean}  props.selectable Whether rows can be selected here.
 * @param {boolean}  props.selected   Whether it is.
 * @param {Function} props.onSelect   Selects or clears it.
 * @param {boolean}  props.open       Whether its explanation is showing.
 * @param {Function} props.onExplain  Shows or hides it.
 * @param {Array}    props.menu       The ⋯ menu's choices; none, and there is no menu.
 * @param {boolean}  props.working    Whether a bulk action is running; the row's own actions wait.
 * @param {Function} props.onApplied  Told when its one-click fix applied.
 * @param {Function} props.onDefaulted Told what its panel's default changed, or why it could not.
 * @param {Function} props.onAsk      Asks once before a default that is asked about first.
 * @param {Function} props.rowRef     Keeps the row's element.
 * @param {Object}   props.safeMode   The overview's safe-mode state, when read.
 */
export function Row( { finding, areaLabel, selectable, selected, onSelect, open, onExplain, menu, working = false, onApplied, onDefaulted, onAsk, rowRef, fromAlert = false, safeMode = null } ) {
	const { busy, applyItem, runFix } = useStore();
	const [ defaulting, setDefaulting ] = useState( false );
	// A Fix panel whose usual choice is safe to make in one press (#2618).
	const fallback = 'open' === finding.status && ! finding.fixed_now && mayManage() && onDefaulted ? defaultOf( finding ) : null;
	const detailId = `bs-ds-fdetail-${ finding.id }`;
	const view = viewOf( finding );
	const applying = isWorking( busy, finding.hardening_item );
	let seen = sprintf(
		/* translators: %s: when the finding was first seen. */
		__( 'First seen %s', 'bettershield' ),
		whenPhrase( finding.first_seen_at )
	);

	if ( finding.fixed_now ) {
		seen = __( 'Fixed just now', 'bettershield' );
	} else if ( 'snoozed' === view ) {
		seen = sprintf(
			/* translators: %s: when the snooze ends. */
			__( 'Snoozed until %s. It comes back sooner if it becomes more serious.', 'bettershield' ),
			whenPhrase( finding.snoozed_until )
		);
	} else if ( 'fixed' === view && finding.resolved_at ) {
		seen = sprintf(
			/* translators: %s: when the finding was resolved. */
			__( 'Resolved %s', 'bettershield' ),
			whenPhrase( finding.resolved_at )
		);
	}

	let action = null;

	/*
	 * Set to applied and open anyway: applying again is the one thing the
	 * apply route refuses, so a sentence says why there is no button, and a
	 * link points at what to do. Safe mode is named only while it is on —
	 * otherwise the last check simply found the protection not working, and
	 * an Overview with nothing to end is no help.
	 *
	 * Partly handled is not paused: XML-RPC with pingbacks only is on as
	 * chosen, open because the rest still answers, and the server's control
	 * leads to the setting (#2665). Nor is a check that couldn't run: the row
	 * says what stopped it, and the protection may be fine (#2725).
	 */
	const paused = 'open' === finding.status && finding.remediable && finding.hardening_active && ! finding.partly_handled && ( ! finding.stale || Boolean( safeMode && safeMode.active ) );
	let pausedNote = null;

	if ( paused && safeMode && safeMode.active ) {
		pausedNote = safeMode.by_network
			? __( 'This is on, but network-wide safe mode is pausing every protection. The network administrator can end it.', 'bettershield' )
			: __( 'This is on, but safe mode is pausing every protection.', 'bettershield' );

		if ( ! safeMode.by_network && sectionUrl( 'bettershield' ) ) {
			action = (
				<Button type="secondary" size="sm" icon="external-link" iconTone="2" href={ sectionUrl( 'bettershield' ) }>
					{ __( 'End Safe Mode on the Overview', 'bettershield' ) }
				</Button>
			);
		}
	} else if ( paused ) {
		pausedNote = __( 'This protection is on but not working. Open Hardening to see why.', 'bettershield' );

		if ( tabUrl( 'bettershield-protect', 'hardening' ) ) {
			action = (
				<Button type="secondary" size="sm" icon="external-link" iconTone="2" href={ tabUrl( 'bettershield-protect', 'hardening' ) }>
					{ __( 'Open Hardening', 'bettershield' ) }
				</Button>
			);
		}
	}

	/*
	 * Each action is the design system's Button, as the Overview's card draws
	 * the same ones (#2293): a bare word at the end of the row did not read as
	 * something to press.
	 */
	// Offered only to somebody the apply route answers, as the current screen does.
	if ( 'open' === finding.status && isOneClick( finding ) && mayManage() ) {
		action = (
			<Button
				type="primary"
				size="sm"
				isBusy={ applying }
				disabled={ applying || working }
				aria-label={ aboutFinding( applying ? __( 'Applying…', 'bettershield' ) : applyWord( finding ), finding ) }
				onClick={ () => {
					// Said as it starts, since the button only shows it (#2293).
					announce( __( 'Applying…', 'bettershield' ) );
					applyItem( finding.hardening_item, undefined, onApplied );
				} }
			>
				{ applying ? __( 'Applying…', 'bettershield' ) : applyWord( finding ) }
			</Button>
		);
	} else if ( fallback ) {
		const pressing = defaulting || isWorking( busy, fallback.key );
		const press = () => {
			if ( fallback.confirm && onAsk ) {
				onAsk();
				return;
			}

			announce( __( 'Applying…', 'bettershield' ) );
			setDefaulting( true );
			applyDefault( finding, runFix ).then(
				( record ) => {
					setDefaulting( false );
					onDefaulted( record );
				},
				( error ) => {
					setDefaulting( false );

					// Nothing to choose here: the panel says why, and offers the rest.
					if ( error && NEEDS_CHOICE === error.code ) {
						announce( error.message );

						if ( ! open ) {
							onExplain();
						}

						return;
					}

					// A canceled password prompt changed nothing and says nothing.
					if ( error ) {
						onDefaulted( null, error );
					}
				}
			);
		};

		action = (
			<>
				<Button
					type="primary"
					size="sm"
					isBusy={ pressing }
					disabled={ pressing || working }
					aria-label={ aboutFinding( pressing ? __( 'Applying…', 'bettershield' ) : applyWord( finding ), finding ) }
					onClick={ press }
				>
					{ pressing ? __( 'Applying…', 'bettershield' ) : applyWord( finding ) }
				</Button>
				{ /* The panel, for any choice other than the usual one. */ }
				<Button
					type="ghost"
					size="sm"
					aria-expanded={ open }
					aria-controls={ open ? `${ detailId }-fix` : undefined }
					aria-label={ aboutFinding( __( 'Other Options', 'bettershield' ), finding ) }
					onClick={ onExplain }
				>
					{ __( 'Other Options', 'bettershield' ) }
				</Button>
			</>
		);
	} else if ( ! paused && hasFix( finding ) ) {
		// A panel in the row's detail with what this finding's fix needs,
		// called Fix only where pressing in it changes something (#2430).
		action = (
			<Button type="secondary" size="sm" trailing={ open ? 'chevron-up' : 'chevron-down' } aria-expanded={ open } aria-controls={ open ? `${ detailId }-fix` : undefined } aria-label={ finding.fixed_now ? fixLabel( finding, __( 'Fixed', 'bettershield' ) ) : fixLabel( finding ) } onClick={ onExplain }>
				{ finding.fixed_now ? __( 'Fixed', 'bettershield' ) : fixWord( finding ) }
			</Button>
		);
	} else if ( ! paused && 'open' === finding.status && finding.control && finding.control.url ) {
		// A fixed or not-applicable finding has nothing left to fix.
		action = (
			<Button type="secondary" size="sm" icon="external-link" iconTone="2" href={ finding.control.url } aria-label={ aboutFinding( finding.control.label, finding ) }>
				{ finding.control.label }
			</Button>
		);
	}

	// No fix this reader may make: a network administrator can (#2639).
	const networkNote = ! action && 'open' === finding.status && SHARED_FILES.includes( finding.id ) && sharedCodeHeld() ? __( 'Only a network administrator can change this.', 'bettershield' ) : null;

	return (
		<>
			<div ref={ rowRef } tabIndex={ -1 } className={ `bs-ds-frow bs-ds-frow--item${ selected ? ' is-selected' : '' }${ open ? ' is-open' : '' }${ finding.stale || pausedNote ? ' is-stale' : '' }` } role="row">
				{ selectable ? (
					<Checkbox
						role="cell"
						disabled={ working }
						label={ sprintf(
							/* translators: %s: the finding's title. */
							__( 'Select %s', 'bettershield' ),
							finding.title
						) }
						state={ selected }
						onChange={ onSelect }
					/>
				) : (
					<span className="bs-ds-frow__gap" />
				) }
				<div className="bs-ds-fcol-find" role="cell">
					<div className="bs-ds-frow__stack">
						<span className="bs-ds-frow__title">{ finding.title }</span>
						<span className="bs-ds-frow__meta">
							<span>{ seen }</span>
							<span aria-hidden="true">·</span>
							<button
								type="button"
								className="bs-ds-frow__explain"
								aria-expanded={ open }
								aria-controls={ open ? detailId : undefined }
								// Which finding, in the name: ten read "Explain" (#2057).
								aria-label={ sprintf(
									/* translators: 1: a control's words, e.g. "Explain"; 2: what it is about, e.g. "Old remote publishing (XML-RPC) is turned on". */
									_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
									__( 'Details', 'bettershield' ),
									finding.title
								) }
								onClick={ onExplain }
							>
								{ __( 'Details', 'bettershield' ) }
							</button>
						</span>
						{ /* The check failed to run this time, so the server kept
						     the result it recorded before: said, or the row reads
						     as though the latest audit had confirmed it. */ }
						{ finding.stale ? (
							<span className="bs-ds-frow__stale">
								{ finding.stale_reason
									? sprintf(
											/* translators: %s: why the check could not run, as a sentence. */
											__( '%s This shows its earlier result.', 'bettershield' ),
											finding.stale_reason
									  )
									: __( 'The latest audit could not run this check, so this shows its earlier result.', 'bettershield' ) }
							</span>
						) : null }
						{ pausedNote ? <span className="bs-ds-frow__stale">{ pausedNote }</span> : null }
					{ networkNote ? <span className="bs-ds-frow__stale">{ networkNote }</span> : null }
					</div>
				</div>
				<div className="bs-ds-fcol-cat" role="cell">
					<Badge icon={ areaIcon( finding.group ) }>{ areaLabel }</Badge>
				</div>
				<div className="bs-ds-fcol-imp" role="cell">
					<span className="bs-ds-meter" aria-hidden="true">
						{ [ 0, 1, 2, 3 ].map( ( segment ) => (
							<span key={ segment } className={ segment < ( METER[ finding.severity ] || 0 ) ? `is-${ finding.severity }` : '' } />
						) ) }
					</span>
					<span className="bs-ds-fvalue">
						{ /* Only an open finding costs points; any other shows
						     none, as an info one does. */ }
						{ 'info' === finding.severity || ! costs( finding ) ? (
							<span className="bs-ds-c3">—</span>
						) : (
							// Isolated, and set in the direction of what it says:
							// in a right-to-left page the minus trailed the number.
							<bdi>
								{ createInterpolateElement(
									sprintf(
										/* translators: %d: points the finding takes off the score. */
										_n( '<n>−%d</n> <u>pt</u>', '<n>−%d</n> <u>pts</u>', Number( finding.deduction ) || 0, 'bettershield' ),
										Number( finding.deduction ) || 0
									),
									{ n: <span className="bs-ds-c1" />, u: <span className="bs-ds-c3" /> }
								) }
							</bdi>
						) }
					</span>
				</div>
				<div className="bs-ds-fcol-act" role="cell">
					{ action }
					{ menu && menu.length ? (
						<Menu
							placement="bottom-end"
							items={ menu }
							renderToggle={ ( { isOpen, onToggle } ) => (
								<button
									type="button"
									className="bs-ds-fmore"
									disabled={ working }
									aria-expanded={ isOpen }
									aria-label={ sprintf(
										/* translators: %s: the finding's title. */
										__( 'More actions for %s', 'bettershield' ),
										finding.title
									) }
									onClick={ onToggle }
								>
									<Icon name="ellipsis" size={ 16 } tone="2" />
								</button>
							) }
						/>
					) : (
						<span className="bs-ds-frow__moregap" />
					) }
				</div>
			</div>
			{ open ? <RowDetail finding={ finding } id={ detailId } fromAlert={ fromAlert } /> : null }
		</>
	);
}

export function Summary( { count, categories, total } ) {
	const strong = { b: <b />, s: <span /> };

	return (
		<div className="bs-ds-frow bs-ds-frow--summary" role="row">
			<span className="bs-ds-frow__gap" />
			<div className="bs-ds-fcell bs-ds-fcol-find" role="cell">
				{ createInterpolateElement(
					sprintf(
						/* translators: %d: how many findings the table shows. */
						_n( '<b>%d</b> <s>finding in view</s>', '<b>%d</b> <s>findings in view</s>', count, 'bettershield' ),
						count
					),
					strong
				) }
			</div>
			<div className="bs-ds-fcell bs-ds-fcol-cat" role="cell">
				{ createInterpolateElement(
					sprintf(
						/* translators: %d: how many areas the shown findings belong to. */
						_n( '<b>%d</b> <s>category</s>', '<b>%d</b> <s>categories</s>', categories, 'bettershield' ),
						categories
					),
					strong
				) }
			</div>
			<div className="bs-ds-fcell bs-ds-fcol-imp" role="cell">
				{ createInterpolateElement(
					sprintf(
						/* translators: %s: points the shown findings take off the score, e.g. "−111 pts". */
						__( '<s>Total</s> <b>%s</b>', 'bettershield' ),
						total
							? ptsLabel( total )
							: sprintf(
									/* translators: %d: points off the score, here none. */
									_n( '%d pt', '%d pts', 0, 'bettershield' ),
									0
							  )
					),
					strong
				) }
			</div>
			<div className="bs-ds-fcol-act" />
		</div>
	);
}
