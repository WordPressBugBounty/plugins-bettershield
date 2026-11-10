/**
 * The redrawn Findings report (design section "Findings · Bulk actions",
 * 23:32940): the hero, an alert when a check could not run, and one table of
 * findings by status, grouped by severity or area, with the bulk flow.
 */

import './Findings.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { cameFromAlert, findingAreas, linkedFinding, linkedStatus, mayManage, NAVIGATED, writeNarrowing } from '../../nav';
import { useResource, useStore } from '../../store';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { IconTile } from '../ui/Card';
import Icon, { NOTE_ICON } from '../ui/Icon';
import Menu from '../ui/Menu';
import Tabs from '../ui/Tabs';
import { panelProps } from '../ui/tabKeys';
import { focusIfLost } from '../ui/focus';
import { useKept } from '../ui/useKept';
import Hero from './Hero';
import { GroupRow, HeadRow, Row, Summary, WholeRow, ptsLabel } from './Rows';
import { BulkBar, Confirm, Done, FixConfirm, REMIND_DAYS } from './Bulk';
import { hasFix } from './Fix';
import { applyDefault, defaultOf, namedWith, partialWords, previewDefault, undoDefault } from './defaults';
import { VulnerabilityNote } from './Extras';
import { managedKeys, runEach } from '../data/bulk';
import { healthOf, isOneClick, pointsOff } from '../data/overview';
import { STATUSES, answers, costs, groupRows, listed, openPointsOff, statusCounts, viewOf } from '../data/findings';
import { dismiss, isDismissed } from '../data/dismissed';
import { announce } from '../../ui/announce';

const areaLabel = ( slug ) => ( findingAreas.find( ( area ) => area.slug === slug ) || {} ).label || slug || '';

function CheckAlert( { overview, onClosed } ) {
	const audit = overview.generated_at || '';
	const missed = Math.max( 0, ( Number( overview.checks_count ) || 0 ) - ( Number( overview.checks_ran ) || 0 ) );
	// Kept results apart from none: on a new site nothing has a last result
	// to show, and the notice said each one did (#2189). Counted as the
	// Overview counts them.
	const never = Math.min( missed, ( overview.checks_unknown || [] ).filter( ( check ) => ! check.last_answered_at ).length );
	const kept = missed - never;
	// The audit it was closed on, so a newer audit brings it back while the
	// screen stays open.
	const [ closedOn, setClosedOn ] = useState( null );
	// Which checks could not run and why, as the Overview lists them (#2732).
	const [ open, setOpen ] = useState( false );
	const named = ( overview.checks_unknown || [] ).filter( ( check ) => check.title || check.key );
	const hidden = closedOn === audit || isDismissed( 'unchecked', audit );

	if ( hidden || ! missed ) {
		return null;
	}

	/*
	 * Said once (#2818): when every one of them shows its last result, or
	 * none has one, the title says so and the counts under it would repeat it.
	 */
	let title;

	if ( kept === missed ) {
		title = sprintf(
			/* translators: %d: how many checks could not run; each shows its last result. */
			_n( '%d check couldn’t run this time, so it shows its last result.', '%d checks couldn’t run this time, so they show their last results.', missed, 'bettershield' ),
			missed
		);
	} else if ( never === missed ) {
		title = sprintf(
			/* translators: %d: how many checks could not run and never have. */
			_n( '%d check couldn’t run and has no result yet.', '%d checks couldn’t run and have no result yet.', missed, 'bettershield' ),
			missed
		);
	} else {
		title = sprintf(
			/* translators: %d: how many checks could not run. */
			_n( '%d check couldn’t run this time.', '%d checks couldn’t run this time.', missed, 'bettershield' ),
			missed
		);
	}

	const mixed = kept > 0 && never > 0;
	const counts = [
		mixed && kept > 0
			? sprintf(
					/* translators: %d: how many of the checks that could not run show an earlier result. */
					_n( '%d shows its last result.', '%d show their last results.', kept, 'bettershield' ),
					kept
			  )
			: '',
		mixed && never > 0
			? sprintf(
					/* translators: %d: how many of the checks that could not run have never had a result. */
					_n( '%d has no result yet.', '%d have no result yet.', never, 'bettershield' ),
					never
			  )
			: '',
	]
		.filter( Boolean )
		.join( ' ' );

	return (
		<Alert
			tone="warning"
			layout={ open ? 'default' : 'compact' }
			actions={
				named.length ? (
					<Button type="linksub" size="sm" aria-expanded={ open } onClick={ () => setOpen( ! open ) }>
						{ open ? _n( 'Hide It', 'Hide Them', named.length, 'bettershield' ) : _n( 'See Which One', 'See Which Ones', named.length, 'bettershield' ) }
					</Button>
				) : null
			}
			title={ title }
			desc={
				open ? (
					<>
						{ counts }
						<ul className="bs-ds-fchecks">
							{ named.map( ( check ) => (
								<li key={ check.key || check.title }>
									{ check.reason
										? sprintf(
												/* translators: 1: a check's name, 2: why it could not run. */
												__( '%1$s: %2$s', 'bettershield' ),
												check.title || check.key,
												check.reason
										  )
										: check.title || check.key }
								</li>
							) ) }
						</ul>
					</>
				) : (
					counts
				)
			}
			onDismiss={ () => {
				dismiss( 'unchecked', audit );

				// Its dismiss button goes with it: focus goes to the score above.
				if ( onClosed ) {
					onClosed();
				}

				setClosedOn( audit );
			} }
		/>
	);
}

/**
 * How many findings a fix applied just now left open: its protection is on,
 * and the report still lists the finding. A panel's own change is left out,
 * since its alert never says the finding is fixed.
 *
 * @param {Object}   result What the last action did.
 * @param {Object[]} all    The findings as last read.
 * @return {number} How many are still open.
 */
function stillOpenAfterFix( result, all ) {
	return result.keys.filter( ( key ) => {
		if ( 'fix' !== result.kind || ( result.records && result.records[ key ] ) ) {
			return false;
		}

		return all.some( ( finding ) => finding.id === key && 'open' === finding.status && finding.hardening_active && ! finding.fixed_now );
	} ).length;
}

export default function Findings() {
	const store = useStore();
	const { resource, reload } = useResource( 'findings' );
	const { resource: overviewResource, reload: reloadOverview } = useResource( 'overview' );
	const { resource: advisories } = useResource( 'vulnerabilities' );
	// Whether a provider can explain a finding in plain language, asked for
	// somebody who may ask it.
	useResource( 'aiStatus', { skip: ! mayManage() } );
	const linked = linkedFinding();

	const [ status, setStatus ] = useState( () => ( STATUSES.includes( linkedStatus() ) ? linkedStatus() : 'open' ) );
	const [ query, setQuery ] = useState( '' );
	const [ by, setBy ] = useState( 'severity' );
	const [ selected, setSelected ] = useState( [] );
	// The findings the not-applicable confirmation is asking about, or null.
	const [ confirmKeys, setConfirmKeys ] = useState( null );
	// The findings the Apply Fix question is asking about, or null (#2565).
	const [ fixKeys, setFixKeys ] = useState( null );
	// The last bulk action's outcome, for its alert and Undo:
	// { kind, keys, failed, reason, undoing }.
	const [ result, setResult ] = useState( null );
	/*
	 * What reversing an action did, said the way the action itself was:
	 * Undo, "Put back in the report" and "Show it now" changed the list
	 * with nothing said or announced (#2139).
	 */
	const [ said, setSaid ] = useState( '' );
	const say = ( message ) => {
		setSaid( message );
		announce( message );
	};
	// Where focus goes once the next render has drawn: { get }.
	const [ focusNext, setFocusNext ] = useState( null );
	const alertRef = useRef( null );
	const titleRef = useRef( null );
	const heroRef = useRef( null );
	const tableRef = useRef( null );
	const confirmRef = useRef( null );
	// The control the not-applicable question was asked from, or a getter for it.
	const confirmFrom = useRef( null );
	const [ working, setWorking ] = useState( false );
	const [ open, setOpen ] = useState( () => ( linked ? { [ linked ]: true } : {} ) );
	const rowRefs = useRef( new Map() );
	const arrived = useRef( false );

	// A refresh keeps the copy already on screen while the fresh one arrives,
	// and after it fails, so the rows, the selection and focus stay put. Only
	// a first read has nothing to draw.
	const kept = useKept( resource.data );
	const read = Array.isArray( kept );
	// A Fix that worked keeps its row, for its Undo, until the report is
	// read again; the row says it is fixed and costs nothing meanwhile.
	const fixedNow = resource.fixedNow || [];
	const all = read ? kept.map( ( finding ) => ( fixedNow.includes( finding.id ) ? { ...finding, fixed_now: true } : finding ) ) : [];
	const overview = useKept( overviewResource.data );
	const findingsFailed = 'error' === resource.status;
	const overviewFailed = 'error' === overviewResource.status;
	const failedRef = useRef( null );
	const [ retrying, setRetrying ] = useState( false );
	const retry = () => {
		setRetrying( true );

		if ( findingsFailed ) {
			reload();
		}

		if ( overviewFailed ) {
			reloadOverview();
		}
	};

	// Try again goes with its alert, or its row, while the reads are out.
	// Once they answer, focus goes back to whichever still says it failed, or
	// to the card title.
	useEffect( () => {
		if ( ! retrying || 'loading' === resource.status || 'loading' === overviewResource.status ) {
			return;
		}

		setRetrying( false );
		focusIfLost( failedRef.current || ( tableRef.current && tableRef.current.querySelector( '.bs-ds-fempty--retry button' ) ) || titleRef.current );
	}, [ retrying, resource.status, overviewResource.status ] );

	const failedAlert = (
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
	// A row fixed a moment ago stays in Open, for its Undo, but no longer counts as open.
	const counts = statusCounts( all.map( ( finding ) => ( finding.fixed_now ? { ...finding, status: 'fixed' } : finding ) ) );
	const rows = listed( all, status ).filter( ( finding ) => answers( finding, query, areaLabel( finding.group ) ) );
	const groups = groupRows( rows, by );
	const openNow = listed( all, 'open' );
	const counted = all.filter( costs );
	const selectable = 'open' === status && mayManage();
	const chosen = rows.filter( ( finding ) => selected.includes( finding.id ) );
	const confirmed = confirmKeys ? all.filter( ( finding ) => confirmKeys.includes( finding.id ) ) : [];
	/*
	 * The selection's fixes the bulk bar applies: the ones whose row shows
	 * Apply Fix, a protection's or a Fix panel's usual choice (#2618). A
	 * panel with no safe default, a guided fix or an outside fix asks the
	 * owner something first, so it stays on its row.
	 */
	/*
	 * A row just fixed from its own Apply Fix stays in view, marked fixed
	 * now, until the list is read again (#2583); its finding still says
	 * open, and counting it would offer its fix a second time.
	 */
	const onePress = ( finding ) => 'open' === finding.status && ! finding.fixed_now && ( ( isOneClick( finding ) && ! hasFix( finding ) ) || Boolean( defaultOf( finding ) ) );
	// One per protection: two findings one protection, or one press, answers are one fix.
	const fixOf = ( finding ) => finding.hardening_item || ( defaultOf( finding ) || {} ).share || finding.id;
	const fixable = chosen.filter( onePress ).filter( ( finding, index, list ) => list.findIndex( ( other ) => fixOf( other ) === fixOf( finding ) ) === index );
	// Read by the keys asked about, so the question stays as asked while the rows it fixes leave.
	const fixing = fixKeys ? fixKeys.map( ( key ) => all.find( ( finding ) => finding.id === key ) ).filter( Boolean ) : [];
	/*
	 * What each fix turns on is a protection, named as Hardening names it.
	 * The question listed the findings' titles, the problems, under "These
	 * turn on:" whenever Hardening had not been opened first, so the list is
	 * read as soon as the selection holds a fix to apply. A list that could
	 * not be read falls back to the finding's title rather than holding the
	 * question shut.
	 */
	const { resource: hardeningRead } = useResource( 'hardening', { skip: ! ( fixable.length || fixKeys ) } );
	const hardeningItems = ( hardeningRead.data && hardeningRead.data.items ) || [];
	const protectionOf = ( finding ) => {
		if ( defaultOf( finding ) ) {
			return defaultOf( finding ).name();
		}

		const item = hardeningItems.find( ( candidate ) => candidate.id === finding.hardening_item );

		return ( item && item.title ) || finding.title;
	};
	const protectionsKnown = Boolean( hardeningRead.data ) || 'error' === hardeningRead.status || ( fixKeys || [] ).every( ( key ) => defaultOf( { id: key } ) );
	/*
	 * What each panel default in the question would change, by name, read
	 * as its panel reads it: "the listed plugins" listed none (#2638). Null
	 * while being read; a read that fails leaves the name alone.
	 */
	const [ previews, setPreviews ] = useState( null );

	useEffect( () => {
		const keys = ( fixKeys || [] ).filter( ( key ) => defaultOf( { id: key } ) );

		if ( ! keys.length ) {
			setPreviews( {} );
			return undefined;
		}

		let live = true;

		setPreviews( null );
		Promise.all( keys.map( ( key ) => previewDefault( { id: key } ).then( ( items ) => [ key, items ], () => [ key, [] ] ) ) ).then( ( pairs ) => {
			if ( live ) {
				setPreviews( Object.fromEntries( pairs ) );
			}
		} );

		return () => {
			live = false;
		};
	}, [ ( fixKeys || [] ).join( ',' ) ] ); // eslint-disable-line react-hooks/exhaustive-deps
	const questionOf = ( finding ) => ( defaultOf( finding ) && previews ? namedWith( protectionOf( finding ), previews[ finding.id ] ) : protectionOf( finding ) );

	// After an action, focus goes to the alert that reports it when the
	// control that started it has gone, unless the reader moved on.
	useEffect( () => {
		if ( result ) {
			focusIfLost( alertRef.current );
		}
	}, [ result ] );

	// Focus asked for before a render, resolved after it: the control that
	// replaced the one pressed, or the card's title when that one is gone.
	useEffect( () => {
		if ( focusNext ) {
			setFocusNext( null );
			focusIfLost( focusNext.get() );
		}
	}, [ focusNext ] );

	// The not-applicable question takes focus when it opens, so it is read
	// before it is answered.
	useEffect( () => {
		if ( ( confirmKeys || fixKeys ) && confirmRef.current ) {
			confirmRef.current.focus();
		}
	}, [ confirmKeys, fixKeys ] );

	// A linked finding: shown on its own tab, opened, and brought into view once.
	useEffect( () => {
		const finding = all.find( ( candidate ) => candidate.id === linked );

		if ( ! finding || arrived.current ) {
			return;
		}

		if ( viewOf( finding ) !== status && 'all' !== status ) {
			setStatus( viewOf( finding ) );
			return;
		}

		const row = rowRefs.current.get( linked );

		if ( ! row ) {
			return;
		}

		arrived.current = true;

		/*
		 * On the next frame, not now. With the list already loaded this runs
		 * in the same commit as the route change, and the shell's route
		 * effect runs after its children's: it focused the screen's heading
		 * and scrolled to the top, over the row (#2023).
		 */
		// Not canceled when this effect runs again: it has arrived by then,
		// and a canceled frame would leave the row never focused. A row gone
		// by the frame is left alone.
		window.requestAnimationFrame( () => {
			if ( ! row.isConnected ) {
				return;
			}

			if ( row.scrollIntoView ) {
				row.scrollIntoView( { block: 'center' } );
			}

			row.focus( { preventScroll: true } );
		} );
	}, [ all, linked, status ] );

	const choose = ( next ) => {
		// Choosing the tab already shown is not a step: no entry for Back.
		if ( next === status ) {
			return;
		}

		setStatus( next );
		// Kept in the address, so a reload, Back or a copied link reopens
		// this tab rather than Open (#2124). Pushed, as every other tab strip
		// is, so Back steps through the tabs chosen before leaving (#2183).
		writeNarrowing( { status: 'open' === next ? '' : next }, true );
		setSelected( [] );
		setConfirmKeys( null );
		setFixKeys( null );
	};

	// Back and Forward move the address without telling the screen: read the
	// status it now carries (#2183). The app's own navigation, a link to
	// Findings from Findings, pushes without a popstate and says so instead.
	useEffect( () => {
		const onPopState = () => {
			const next = linkedStatus();

			setStatus( STATUSES.includes( next ) ? next : 'open' );
			setSelected( [] );
			setConfirmKeys( null );
			setFixKeys( null );
		};

		window.addEventListener( 'popstate', onPopState );
		window.addEventListener( NAVIGATED, onPopState );

		return () => {
			window.removeEventListener( 'popstate', onPopState );
			window.removeEventListener( NAVIGATED, onPopState );
		};
	}, [] );

	// The not-applicable question names the findings selected when it was
	// asked, so any change to the selection, or to what is shown, closes it.
	const toggle = ( id ) => {
		setConfirmKeys( null );
		setFixKeys( null );
		setSelected( ( was ) => ( was.includes( id ) ? was.filter( ( key ) => key !== id ) : [ ...was, id ] ) );
	};
	const focusLater = ( get ) => setFocusNext( { get } );
	// The header row's checkbox: Select all, or the bulk bar's Clear selection.
	const headerBox = () => ( tableRef.current && tableRef.current.querySelector( '.bs-ds-frow--head input, .bs-ds-fbulk input' ) ) || titleRef.current;
	const back = ( from ) => {
		const node = 'function' === typeof from ? from() : from;

		return node && node.isConnected && ! node.disabled ? node : headerBox();
	};
	const moreFor = ( id ) => () => {
		const row = rowRefs.current.get( id );

		return row ? row.querySelector( '.bs-ds-fmore' ) : null;
	};

	const selectAll = () => {
		setConfirmKeys( null );
		setFixKeys( null );
		setSelected( rows.map( ( finding ) => finding.id ) );
		focusLater( headerBox );
	};
	const search = ( next ) => {
		setConfirmKeys( null );
		setFixKeys( null );
		setQuery( next );
	};
	const clear = () => {
		setSelected( [] );
		setConfirmKeys( null );
		setFixKeys( null );
		focusLater( headerBox );
	};

	// Whether the question came from one row's menu, which it then names
	// (#2072); a selection keeps the count.
	const [ confirmOne, setConfirmOne ] = useState( false );
	const [ confirmManaged, setConfirmManaged ] = useState( false );
	// One row's menu names its finding, and the one other that choice covers.
	const confirmLead = confirmOne ? confirmed.find( ( finding ) => finding.id === confirmKeys[ 0 ] ) : null;
	const confirmAlso = confirmLead ? confirmed.find( ( finding ) => finding !== confirmLead ) : null;
	const openConfirm = ( list, from, one = false, managed = false ) => {
		confirmFrom.current = from || null;
		setConfirmOne( one );
		setConfirmManaged( managed );
		setFixKeys( null );
		setConfirmKeys( list );
	};
	const closeConfirm = () => {
		setConfirmKeys( null );
		setFixKeys( null );
		focusLater( () => back( confirmFrom.current ) );
	};

	const keys = () => chosen.map( ( finding ) => finding.id );

	/*
	 * What an action leaves on screen: the alert for what changed, with how
	 * many could not be changed and why, or only that. A new action replaces
	 * the last one's alert, so Undo always reverses what it reports; one that
	 * changed nothing (the password prompt was canceled) leaves it, and focus
	 * goes back to where the action began. The findings it changed leave the
	 * selection; the rest of the selection stays.
	 */
	const report = ( kind, outcome, from ) => {
		setSelected( ( was ) => was.filter( ( key ) => ! outcome.done.includes( key ) ) );

		if ( outcome.done.length || outcome.failed.length ) {
			setSaid( '' );
			setResult( { kind, keys: outcome.done, failed: outcome.failed.length, reason: outcome.reason } );
			return;
		}

		focusLater( () => back( from ) );
	};

	const remind = async ( days, list = keys(), from = null ) => {
		setWorking( true );
		setConfirmKeys( null );
		setFixKeys( null );
		const outcome = await runEach( list, ( key, ok, no ) => store.snooze( key, days, ok, no ) );
		setWorking( false );
		report( 'snooze', outcome, from );
	};

	const markNotApplicable = async () => {
		const list = confirmKeys || [];

		setWorking( true );
		const outcome = await runEach( list, ( key, ok, no ) => store.suppress( key, ok, no ) );
		setWorking( false );
		setConfirmKeys( null );
		setFixKeys( null );
		report( confirmManaged ? 'managed' : 'na', outcome, confirmFrom.current );
	};

	/*
	 * The selection's one-press fixes, asked about once and applied one by
	 * one through the route the row's Apply Fix uses, so each has its own
	 * Undo. The answers carry the report, so it is not read again (#2565).
	 */
	const openFixConfirm = ( event ) => {
		confirmFrom.current = ( event && event.currentTarget ) || null;
		setConfirmKeys( null );
		setFixKeys( fixable.map( ( finding ) => finding.id ) );
	};
	const closeFixConfirm = () => {
		setFixKeys( null );
		focusLater( () => back( confirmFrom.current ) );
	};
	const applyFixes = async () => {
		const list = fixing;
		const items = {};
		const names = {};
		// What each panel default changed, for its Undo.
		const records = {};

		list.forEach( ( finding ) => {
			items[ finding.id ] = finding.hardening_item;
			names[ finding.id ] = protectionOf( finding );
		} );

		setWorking( true );
		announce( __( 'Applying…', 'bettershield' ) );
		const outcome = await runEach( list.map( ( finding ) => finding.id ), ( key, ok, no ) => {
			const finding = list.find( ( candidate ) => candidate.id === key );

			if ( ! defaultOf( finding ) ) {
				return store.applyItem( items[ key ], undefined, ok, no, { refuseWhenBusy: true } );
			}

			return applyDefault( finding, store.runFix ).then(
				( record ) => {
					records[ key ] = record;
					ok();
				},
				no
			);
		} );
		setWorking( false );
		setFixKeys( null );
		setSelected( ( was ) => was.filter( ( key ) => ! outcome.done.includes( key ) ) );

		if ( ! outcome.done.length && ! outcome.failed.length ) {
			focusLater( () => back( confirmFrom.current ) );
			return;
		}

		const first = list.find( ( finding ) => finding.id === outcome.done[ 0 ] );

		setSaid( '' );
		setResult( {
			kind: 'fix',
			keys: outcome.done,
			items,
			records,
			item: first ? first.hardening_item : null,
			name: first ? names[ first.id ] : '',
			title: first ? first.title : '',
			failed: outcome.failed.length,
			reason: outcome.reason,
			// A default that changed only part of its list says which (#2637).
			partial: Object.values( records ).map( partialWords ).filter( Boolean ).join( ' ' ),
			// What the panel defaults changed, by name (#2638).
			named: Object.values( records ).map( ( record ) => namedWith( record.name, record.changed ) ).join( '. ' ),
		} );
	};

	/*
	 * A fix applied from its row says so, with an Undo, as a snooze and "not
	 * applicable" do: the row went with no word, and the way back was the
	 * Hardening switch (#1914). Named by the protection the answer lists.
	 */
	const applied = ( finding ) => ( data ) => {
		const items = ( data && data.hardening && data.hardening.items ) || [];
		const item = items.find( ( candidate ) => candidate.id === finding.hardening_item );

		setSaid( '' );
		setResult( { kind: 'fix', keys: [ finding.id ], item: finding.hardening_item, name: ( item && item.title ) || finding.title, title: finding.title, failed: 0, reason: '' } );
	};

	/*
	 * A Fix panel's usual choice applied from its row (#2618): said the same
	 * way, with an Undo that puts back everything it changed. One that could
	 * not be applied says why in the same place.
	 */
	const defaulted = ( finding ) => ( record, error ) => {
		setSaid( '' );

		if ( ! record ) {
			setResult( { kind: 'fix', keys: [], failed: 1, reason: ( error && error.message ) || '' } );
			return;
		}

		setResult( { kind: 'fix', keys: [ finding.id ], records: { [ finding.id ]: record }, name: namedWith( record.name, record.changed ), title: finding.title, failed: 0, reason: '', partial: partialWords( record ) } );
	};

	// A default asked about first, asked as the bulk bar asks.
	const askFor = ( finding ) => () => {
		confirmFrom.current = () => {
			const row = rowRefs.current.get( finding.id );

			return row ? row.querySelector( '.bs-ds-fcol-act button' ) : null;
		};
		setConfirmKeys( null );
		setFixKeys( [ finding.id ] );
	};

	// Undo keeps its alert, and the findings it could not put back, until
	// every one of them is back.
	const undo = async () => {
		setWorking( true );
		/*
		 * The last change first: a later fix can rest on an earlier one, as
		 * moving a plugin to quarantine does on the update just made to it,
		 * and the earlier one cannot be put back while the later stands.
		 */
		const outcome = await runEach( [ ...result.keys ].reverse(), ( key, ok, no ) => {
			const record = 'fix' === result.kind && result.records && result.records[ key ];

			if ( record ) {
				return undoDefault( record, store.runFix ).then( ok, no );
			}

			if ( 'fix' === result.kind ) {
				return store.revertItem( ( result.items && result.items[ key ] ) || result.item, ok, no, { refuseWhenBusy: true } );
			}

			return 'snooze' === result.kind ? store.wake( key, ok, no ) : store.unsuppress( key, ok, no );
		} );
		setWorking( false );

		// Canceled at the password prompt before anything was sent: the alert
		// stays as it was, and focus goes back to its Undo.
		if ( ! outcome.done.length && ! outcome.failed.length ) {
			focusLater( () => back( () => alertRef.current && alertRef.current.querySelector( '.bs-ds-fundo' ) ) );
			return;
		}

		const left = result.keys.filter( ( key ) => ! outcome.done.includes( key ) );

		if ( left.length ) {
			setResult( { ...result, keys: left, failed: outcome.failed.length, reason: outcome.reason, undoing: true } );
			return;
		}

		const was = result;

		setResult( null );

		if ( 'fix' === was.kind && was.keys.length > 1 ) {
			say( sprintf(
				/* translators: %d: how many fixes were undone. */
				_n( 'Undone: %d finding is open again.', 'Undone: %d findings are open again.', was.keys.length, 'bettershield' ),
				was.keys.length
			) );
		} else if ( 'fix' === was.kind ) {
			// The finding by its title: the fix's name read "Turn off remote
			// publishing (XML-RPC) is off again" (#2483).
			/* translators: %s: a finding's title, e.g. "Old remote publishing (XML-RPC) is turned on". */
			say( sprintf( __( 'Undone: “%s” is open again.', 'bettershield' ), was.title || was.name ) );
		} else if ( 'snooze' === was.kind ) {
			say( _n( 'Undone: the finding is back in Open.', 'Undone: the findings are back in Open.', outcome.done.length, 'bettershield' ) );
		} else {
			say( _n( 'Undone: the finding is back in the report.', 'Undone: the findings are back in the report.', outcome.done.length, 'bettershield' ) );
		}

		// On the finding it put back where its row is on this tab.
		focusLater( () => rowRefs.current.get( was.keys[ 0 ] ) || titleRef.current );
	};

	const dismissResult = () => {
		setResult( null );
		focusLater( () => titleRef.current );
	};

	// A finding that leaves this tab takes its row, and the control pressed
	// in it, with it.
	const toTitle = () => focusLater( () => titleRef.current );

	// When the snooze just set ends, read back from the finding it was set on.
	const snoozedUntil = () => {
		const first = result && all.find( ( finding ) => finding.id === result.keys[ 0 ] );

		return first && first.snoozed_until ? whenPhrase( first.snoozed_until ) : '';
	};

	/*
	 * Bringing a finding back from its row ends what the message above says
	 * about it: left up, it said the finding was snoozed "until ." or not
	 * applicable after it was back, and its Undo asked the server to undo
	 * what was already undone (#1811).
	 */
	const bringBack = ( act, id, message ) => () => {
		setResult( ( current ) => ( current && ( current.keys || [] ).includes( id ) ? null : current ) );
		act( id, () => {
			say( message );
			toTitle();
		} );
	};

	const menuFor = ( finding ) => {
		if ( ! mayManage() ) {
			return [];
		}

		const view = viewOf( finding );

		if ( 'open' === view ) {
			return [
				{
					key: 'na',
					label: finding.self_managed ? __( 'I manage this myself', 'bettershield' ) : __( 'Not applicable', 'bettershield' ),
					onClick: () =>
						finding.self_managed
							? openConfirm( managedKeys( finding, all ), moreFor( finding.id ), true, true )
							: openConfirm( [ finding.id ], moreFor( finding.id ), true ),
				},
				{ key: 'remind', head: __( 'Snooze', 'bettershield' ) },
				...REMIND_DAYS.map( ( days ) => ( {
					key: `in-${ days }`,
					label: sprintf(
						/* translators: %d: number of days. */
						_n( 'In %d day', 'In %d days', days, 'bettershield' ),
						days
					),
					onClick: () => remind( days, [ finding.id ], moreFor( finding.id ) ),
				} ) ),
			];
		}

		if ( 'snoozed' === view ) {
			// The comment sits on the line before the string it describes, or
			// make-pot hands it to the label instead.
			const said = sprintf(
				/* translators: %s: a finding's title. */
				__( '%s is back in Open.', 'bettershield' ),
				finding.title
			);

			return [ { key: 'wake', label: __( 'Unsnooze', 'bettershield' ), onClick: bringBack( ( id, then ) => store.wake( id, then ), finding.id, said ) } ];
		}

		if ( 'suppressed' === view ) {
			const said = sprintf(
				/* translators: %s: a finding's title. */
				__( '%s is back in Open.', 'bettershield' ),
				finding.title
			);

			return [ { key: 'back', label: __( 'Move back to Open', 'bettershield' ), onClick: bringBack( ( id, then ) => store.unsuppress( id, then ), finding.id, said ) } ];
		}

		return [];
	};

	const keepRow = ( id ) => ( node ) => {
		if ( node ) {
			rowRefs.current.set( id, node );
		} else {
			rowRefs.current.delete( id );
		}
	};

	const advisory = Boolean( advisories.data ) && false === advisories.data.feed_bound;
	let body;

	if ( ! read && findingsFailed ) {
		body = (
			<WholeRow className="bs-ds-fempty bs-ds-fempty--retry">
				{ __( 'Couldn’t load this. Try again in a moment.', 'bettershield' ) }
				<Button type="secondary" size="sm" onClick={ retry }>
					{ __( 'Try Again', 'bettershield' ) }
				</Button>
			</WholeRow>
		);
	} else if ( ! read ) {
		body = <WholeRow className="bs-ds-fempty">{ __( 'Loading the findings…', 'bettershield' ) }</WholeRow>;
	} else if ( ! rows.length ) {
		body = (
			<WholeRow className="bs-ds-fempty">
				{ query ? __( 'Nothing under this status matches that search.', 'bettershield' ) : __( 'Nothing has this status. Try another one above.', 'bettershield' ) }
			</WholeRow>
		);
	} else {
		body = groups.map( ( group ) => [
			<GroupRow key={ `g-${ group.key }` } group={ group } by={ by } areaLabel={ areaLabel } />,
			...group.rows.map( ( finding ) => (
				<Row
					key={ finding.id }
					finding={ finding }
					areaLabel={ areaLabel( finding.group ) }
					selectable={ selectable }
					selected={ selected.includes( finding.id ) }
					onSelect={ () => toggle( finding.id ) }
					open={ Boolean( open[ finding.id ] ) }
					onExplain={ () => setOpen( ( was ) => ( { ...was, [ finding.id ]: ! was[ finding.id ] } ) ) }
					menu={ menuFor( finding ) }
					working={ working }
					onApplied={ applied( finding ) }
					onDefaulted={ defaulted( finding ) }
					onAsk={ askFor( finding ) }
					rowRef={ keepRow( finding.id ) }
					fromAlert={ finding.id === linked && cameFromAlert() }
					safeMode={ overview ? overview.safe_mode : null }
				/>
			) ),
		] );
	}

	return (
		<>
			{ /* One alert for whichever read failed; a first read of the findings that failed says so in the table instead. */ }
			{ ( findingsFailed && read ) || overviewFailed ? failedAlert : null }
			{ overview ? (
				<>
					<Hero overview={ overview } open={ read ? counted : null } heroRef={ heroRef } />
					<CheckAlert overview={ overview } onClosed={ () => heroRef.current && heroRef.current.focus() } />
				</>
			) : null }
			{ ! overview && ! overviewFailed ? <p className="bs-ds-t14 bs-ds-r bs-ds-c2">{ __( 'Loading…', 'bettershield' ) }</p> : null }
			<section className="bs-ds-card" aria-labelledby="bs-ds-fcard-title">
				<div className="bs-ds-fcard-head">
					<IconTile icon="list-checks" />
					<h2 ref={ titleRef } tabIndex={ -1 } className="bs-ds-card__title bs-ds-t14 bs-ds-m bs-ds-c1 bs-ds-nowrap" id="bs-ds-fcard-title">
						{ __( 'Open findings', 'bettershield' ) }
					</h2>
					{ /* Its figure waits for the list, as the tab counts do. */ }
					{ read ? <Badge tone="red">{ ptsLabel( pointsOff( openNow.filter( costs ), healthOf( overview ) ) ) }</Badge> : null }
					<span className="bs-ds-spacer" />
				</div>
				<div className="bs-ds-fcard-body">
					<Tabs
						id="bs-ds-ftabs"
						label={ __( 'Findings by status', 'bettershield' ) }
						selected={ status }
						onSelect={ choose }
						tabs={ [
							{ key: 'open', label: __( 'Open', 'bettershield' ), count: read ? counts.open : null },
							{ key: 'snoozed', label: __( 'Snoozed', 'bettershield' ), count: read ? counts.snoozed : null },
							{ key: 'fixed', label: __( 'Fixed', 'bettershield' ), count: read ? counts.fixed : null },
							{ key: 'suppressed', label: __( 'Not applicable', 'bettershield' ), count: read ? counts.suppressed : null },
							{ key: 'all', label: __( 'All', 'bettershield' ), count: read ? counts.all : null },
						] }
						actions={
							<>
								<Menu
									items={ [
										{ key: 'severity', label: __( 'Severity', 'bettershield' ), onClick: () => setBy( 'severity' ) },
										{ key: 'category', label: __( 'Category', 'bettershield' ), onClick: () => setBy( 'category' ) },
									] }
									renderToggle={ ( { isOpen, onToggle } ) => (
										<button type="button" className="bs-ds-fselect" aria-expanded={ isOpen } onClick={ onToggle }>
											<span className="bs-ds-r bs-ds-c2">{ __( 'Group By', 'bettershield' ) }</span>
											<span className="bs-ds-m bs-ds-c1">{ 'category' === by ? __( 'Category', 'bettershield' ) : __( 'Severity', 'bettershield' ) }</span>
											<Icon name="chevron-down" size={ 14 } tone="3" />
										</button>
									) }
								/>
								<label className="bs-ds-fsearch">
									<Icon name="search" size={ 16 } tone="3" />
									<input
										type="search"
										value={ query }
										placeholder={ __( 'Search findings', 'bettershield' ) }
										aria-label={ __( 'Search findings', 'bettershield' ) }
										onChange={ ( event ) => search( event.target.value ) }
									/>
								</label>
							</>
						}
					/>
					<div { ...panelProps( 'bs-ds-ftabs', status ) }>
					<div ref={ tableRef } className="bs-ds-ftable" role="table" aria-labelledby="bs-ds-fcard-title">
						{ said && ! result ? <Alert layout="default" tone="success" desc={ said } onDismiss={ () => setSaid( '' ) } /> : null }
						{ result ? (
							<Done
								alertRef={ alertRef }
								kind={ result.kind }
								count={ result.keys.length }
								failed={ result.failed }
								reason={ result.reason }
								partial={ result.partial || '' }
								named={ result.named || '' }
								undoing={ Boolean( result.undoing ) }
								until={ snoozedUntil() }
								name={ result.name || '' }
								changed={ Boolean( result.records && Object.keys( result.records ).length ) }
								stillOpen={ stillOpenAfterFix( result, all ) }
								working={ working }
								onUndo={ undo }
								onDismiss={ dismissResult }
							/>
						) : null }
						{ selectable && chosen.length ? (
							<BulkBar
								count={ chosen.length }
								total={ rows.length }
								all={ chosen.length === rows.length }
								points={ openPointsOff( chosen, healthOf( overview ) ) }
								working={ working }
								onClear={ clear }
								onRemind={ ( days ) => remind( days ) }
								onNotApplicable={ ( event ) => openConfirm( keys(), event && event.currentTarget ) }
								fixable={ fixable.length }
								onApplyFix={ openFixConfirm }
							/>
						) : (
							<HeadRow
								selectable={ selectable && rows.length > 0 }
								state={ false }
								onAll={ selectAll }
							/>
						) }
						{ confirmed.length ? (
							<Confirm
								dialogRef={ confirmRef }
								count={ confirmed.length }
								name={ confirmLead ? confirmLead.title : '' }
								managed={ confirmManaged }
								also={ confirmOne && confirmManaged && confirmAlso ? confirmAlso.title : '' }
								// Never more than the site can lose, as the header badge (#2611).
								points={ pointsOff( confirmed, healthOf( overview ) ) }
								working={ working }
								onConfirm={ markNotApplicable }
								onCancel={ closeConfirm }
							/>
						) : null }
						{ fixing.length ? (
							<FixConfirm
								dialogRef={ confirmRef }
								count={ fixing.length }
								names={ protectionsKnown && previews ? fixing.map( questionOf ) : null }
								cautions={ [ ...new Set( fixing.map( ( finding ) => ( defaultOf( finding ) || {} ).caution ).filter( Boolean ).map( ( caution ) => caution() ) ) ] }
								working={ working }
								onConfirm={ applyFixes }
								onCancel={ closeFixConfirm }
							/>
						) : null }
						{ body }
						{ advisory ? (
							<WholeRow className="bs-ds-fbanner">
								<Icon name={ NOTE_ICON } size={ 16 } tone="info" />
								<p className="bs-ds-alert__text">
									<span className="bs-ds-fbanner__title">{ __( 'No vulnerability database connected, so known vulnerabilities aren’t checked.', 'bettershield' ) }</span>
								</p>
							</WholeRow>
						) : null }
						{ advisories.data && advisories.data.feed_bound ? (
							<WholeRow className="bs-ds-fnote">
								<VulnerabilityNote feed={ advisories.data } />
							</WholeRow>
						) : null }
						{ rows.length ? <Summary count={ rows.length } categories={ new Set( rows.map( ( finding ) => finding.group ) ).size } total={ openPointsOff( rows, healthOf( overview ) ) } /> : null }
					</div>
					</div>
				</div>
			</section>
		</>
	);
}
