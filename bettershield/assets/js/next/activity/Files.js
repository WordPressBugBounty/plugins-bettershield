/**
 * Activity › File changes: what differs from the copies WordPress published.
 *
 * The screen's job is to let somebody tell a developer's deliberate edit from
 * code they did not put there, which is a judgment no plugin should make for
 * them. So it shows the difference rather than a verdict: the path, when it
 * was noticed, what kind of change it is, and — on request — the actual lines.
 *
 * Two things it must never do. It must never present a stale answer as a
 * current one: when the check last ran is the first line on the screen, and an
 * old one says so. And it must never imply that a target nothing published was
 * found clean; those are listed by name, because "two things could not be
 * checked" is not actionable and "your commercial plugin could not be checked"
 * is.
 *
 * The status strip, then the report as one card: the check's state under its
 * header, the notes, a group row per plugin and version, and the changed
 * files as a table grouped by what can be done about them, each opening its
 * difference under it. What was displaced is kept in a second card.
 */

import './Files.css';

import apiFetch from '@wordpress/api-fetch';
import { useCallback, useEffect, useMemo, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { mayChangeSharedCode, mayManage } from '../../nav';
import { formatTime, isPast, isWorking, useStore } from '../../store';
import { downloadBytes } from '../../ui/download';
import { atLeast, SCAN_HOLD, SLICE_GAP } from '../../ui/hold';
import { BreakablePath } from '../../ui/path';
import { scanProgress } from '../../ui/scan';
import { announce } from '../../ui/announce';
import useMutationFocus from '../../ui/useMutationFocus';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { focusIfLost, useFocusAfter } from '../ui/focus';
import InfoTip from '../ui/InfoTip';
import Skeleton, { CardBone, StatsBone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import Stats from '../ui/Stats';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import { SEVERITY } from '../findings/Rows';
import { changeLabel, changeSeverity, chunk, claimFor, filteredAnswer, filterOptions, filterParams, filterQuery, GROUP_SHOWN, groupChanges, isFiltered, KEPT_AT_ONCE, MARK_AT_ONCE, MATCHING_AT_ONCE, NAMED_CODE, NO_FILTER, packageCounts, REMOVE_AT_ONCE, RESTORE_AT_ONCE, RESTORE_CHUNK, screenOrder, selectableChange, selectionCounts, selectionPhrase, toggled } from '../data/files';
import Checkbox from '../ui/Checkbox';
import Field from '../ui/Field';
import Icon from '../ui/Icon';
import { formatCount } from '../../ui/count';
import { SelectionBar, SelectionDock, SelectionQuestion, SelectionReceipt } from './Selection';

/** A path as the design sets it: its own type, breaking only at its separators. */
function Path( { path } ) {
	return (
		<span className="bs-ds-files__path">
			<BreakablePath path={ path } />
		</span>
	);
}

/**
 * The severity a difference is drawn with: the word on the tone, never the
 * tone alone.
 *
 * @param {Object} props
 * @param {string} props.severity One of the five.
 */
function SeverityBadge( { severity } ) {
	const shown = SEVERITY[ severity ] || SEVERITY.info;

	return (
		<Badge tone={ shown.tone } icon={ shown.icon }>
			{ shown.label() }
		</Badge>
	);
}

/**
 * The line-by-line comparison, under the row it belongs to.
 *
 * The diff is markup WordPress generated from two strings it was given, which
 * is why it is injected rather than rendered: it is a table of escaped lines,
 * produced by core's own differ.
 *
 * Only the part that differs is drawn at first, with the lines around it;
 * the whole file is one press away.
 *
 * @param {Object}   props
 * @param {string}   props.html    The comparison core drew.
 * @param {boolean}  props.partial Whether only the part that differs is drawn.
 * @param {Function} props.onWhole Asks for the whole file.
 * @param {boolean}  props.working Whether it is on its way.
 */
function Difference( { html, partial = false, onWhole = null, working = false } ) {
	return (
		<>
			<div className="bs-ds-files__diff" dangerouslySetInnerHTML={ { __html: html } } />
			{ partial && onWhole ? (
				<p className="bs-ds-files__line">
					<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ onWhole }>
						{ __( 'Show the Whole File', 'bettershield' ) }
					</Button>
				</p>
			) : null }
		</>
	);
}

/**
 * The column a row's checkbox sits in: named for assistive technology, as
 * narrow as the box.
 *
 * @param {boolean} straight The rows sit straight in the table, on its
 *                           tracks, and their padding comes out of this one.
 * @return {Object} The column.
 */
function selectColumn( straight = false ) {
	return {
		key: 'select',
		label: <span className="screen-reader-text">{ __( 'Select', 'bettershield' ) }</span>,
		width: straight ? 'calc(var(--bs-ds-space-ml) + 24px)' : '24px',
	};
}

/**
 * The cell a row's checkbox sits in, where the table has the column: empty on
 * a row that cannot be picked, so every row keeps the table's columns.
 *
 * @param {Object}   props
 * @param {boolean}  props.column   Whether the table has the column.
 * @param {string}   props.label    Which row the checkbox picks.
 * @param {?boolean} props.state    Whether the row is picked; null for a row that cannot be.
 * @param {Function} props.onChange Picks the row, or lets it go.
 */
function SelectCell( { column, label = '', state = null, onChange } ) {
	if ( ! column ) {
		return null;
	}

	return <Cell>{ null === state ? null : <Checkbox label={ label } state={ state } onChange={ onChange } /> }</Cell>;
}

/**
 * What was displaced, and the three things an owner can do about it.
 *
 * The mechanism has always kept these files; there was simply no way to look.
 * Download is the forensics path and is logged, because handing somebody the
 * bytes of a file that was displaced for being altered is a security-relevant
 * act. Delete is the one irreversible thing on this screen, so it arms first
 * and says what it means before it does it.
 */
/**
 * A file's size as people read it: bytes, then KB, then MB.
 *
 * @param {number} bytes The size in bytes.
 * @return {string} The size, e.g. "12 KB".
 */
function fileSize( bytes ) {
	const size = Number( bytes ) || 0;

	if ( size < 1024 ) {
		/* translators: %d: a file size in bytes. */
		return sprintf( _n( '%d byte', '%d bytes', size, 'bettershield' ), size );
	}

	const kb = size / 1024;

	return kb < 1024
		? /* translators: %s: a file size in kilobytes, e.g. "12". */
		  sprintf( __( '%s KB', 'bettershield' ), Math.round( kb ).toLocaleString() )
		: /* translators: %s: a file size in megabytes, e.g. "1.4". */
		  sprintf( __( '%s MB', 'bettershield' ), ( Math.round( ( kb / 1024 ) * 10 ) / 10 ).toLocaleString() );
}

/**
 * What a kept copy of altered code is, said on its row: what it differs from,
 * and the incident whose response took it out.
 *
 * @param {{against: string, incident: number}} code What the copy differs from, and the incident that took it out.
 * @return {string} The line.
 */
function codeLine( code ) {
	const differs = code.against
		? /* translators: %s: the official copy, e.g. "WordPress 7.1.3". */
		  sprintf( __( 'Changed code that doesn’t match %s.', 'bettershield' ), code.against )
		: __( 'A file that isn’t part of any official release.', 'bettershield' );

	return code.incident > 0
		? /* translators: 1: what the copy is, said as a sentence, 2: an incident's own number. */
		  sprintf( __( '%1$s The response to incident #%2$d removed it.', 'bettershield' ), differs, code.incident )
		: differs;
}

function Quarantined( { items, note, hasMore, onMore, loadingMore, onDownload, onPutBack, onDelete, isBusy, column = false, picked = new Set(), onPick = () => {}, dock = null } ) {
	const [ puttingBack, setPuttingBack ] = useState( null );
	const deleteRefs = useRef( new Map() );
	// Show older quarantined files goes once the last page is in: focus
	// comes back to it, or to the card's heading (#2028).
	const older = useRef( null );
	const title = useRef( null );

	useFocusAfter( loadingMore, older, title );

	/* An entry put back loses the button that was pressed, so focus moves to
	   the next action on the same entry rather than dropping to the page —
	   once the entry's request has let go of it, since a control held while
	   it runs cannot take focus. */
	const settled = puttingBack ? ! isBusy( puttingBack ) : false;

	useEffect( () => {
		if ( puttingBack && settled && items.some( ( entry ) => entry.token === puttingBack && entry.restored ) ) {
			deleteRefs.current.get( puttingBack )?.focus();
			setPuttingBack( null );
		}
	}, [ items, puttingBack, settled ] );

	if ( ! items.length ) {
		return null;
	}

	// Only a copy still kept can be picked: one removed has nothing left to act on.
	const choosable = column ? items.filter( ( entry ) => entry.present ) : [];
	const on = choosable.filter( ( entry ) => picked.has( entry.token ) ).length;
	const allShown = sprintf(
		/* translators: %s: how many kept copies are shown. */
		_n( 'Select the %s copy shown', 'Select all %s copies shown', choosable.length, 'bettershield' ),
		formatCount( choosable.length )
	);

	return (
		<Card className="bs-ds-quarantine" aria-labelledby="bs-ds-quarantine-title">
			<CardHead
				icon="archive"
				title={
					<span ref={ title } tabIndex={ -1 }>
						{ __( 'Quarantine', 'bettershield' ) }
					</span>
				}
				id="bs-ds-quarantine-title"
			/>
			<p className="bs-ds-files__intro">
				{ __(
					'Files BetterShield moved or replaced are stored here, where visitors can’t open them. You can put each one back.',
					'bettershield'
				) }
			</p>

			{ /*
			   What the buttons below answered, said beside them. Everything
			   above this card is within a screen of the block that reports it;
			   this list sits after every recorded difference, which on a site
			   with a history is tens of thousands of pixels of scrolling away
			   from the top of the page.

			   Keyed on the tone so a refusal replaces an outcome with a new
			   element rather than changing the role of the one already there,
			   which is what makes it interrupt.
			*/ }
			{ note ? (
				<div key={ note.tone } className="bs-ds-quarantine__note" role={ 'alert' === note.tone ? 'alert' : 'status' }>
					<Alert layout="default" tone={ 'alert' === note.tone ? 'error' : 'success' } desc={ note.text } />
				</div>
			) : null }

			<Table
				label={ __( 'Quarantine', 'bettershield' ) }
				columns={ [
					...( column ? [ selectColumn( true ) ] : [] ),
					{ key: 'path', label: __( 'Path', 'bettershield' ) },
					{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
				] }
			>
				{ choosable.length ? (
					<WholeRow kind="note">
						<Checkbox
							label={ allShown }
							state={ on === choosable.length ? true : on > 0 && 'mixed' }
							onChange={ () => onPick( choosable.map( ( entry ) => entry.token ), on !== choosable.length ) }
						/>
						<span aria-hidden="true">{ allShown }</span>
					</WholeRow>
				) : null }

				{ items.map( ( item ) => (
					<Row key={ item.token } className="bs-ds-quarantine__item" selected={ picked.has( item.token ) }>
						<SelectCell
							column={ column }
							label={ sprintf(
								/* translators: %s: a file's path. */
								__( 'Select %s', 'bettershield' ),
								item.path
							) }
							state={ item.present ? picked.has( item.token ) : null }
							onChange={ () => onPick( [ item.token ], ! picked.has( item.token ) ) }
						/>
						<Cell>
							<TitleMeta
								title={ <Path path={ item.path } /> }
								meta={
									<span className="bs-ds-quarantine__meta">
										{ ! item.present && __( 'No longer on this site.', 'bettershield' ) }
										{ item.present && ! item.restored && sprintf(
											/* translators: 1: file size, e.g. "12 KB", 2: date and time. */
											__( '%1$s, moved %2$s', 'bettershield' ),
											fileSize( item.size ),
											formatTime( item.at )
										) }
										{ item.code ? <span className="bs-ds-quarantine__code">{ codeLine( item.code ) }</span> : null }
										{ item.present && item.restored && sprintf(
											/* translators: 1: file size, e.g. "12 KB", 2: date and time it was moved, 3: date and time it was put back. */
											__( '%1$s, moved %2$s. Put back %3$s. A copy is still stored here.', 'bettershield' ),
											fileSize( item.size ),
											formatTime( item.at ),
											formatTime( item.restored_at )
										) }
									</span>
								}
							/>
						</Cell>
						<Cell align="end">
							{ /* Each of these answers only an account that may manage
							     the plugin; a reader is shown what is kept, not offered
							     to move it. Each is named with its file: the same three
							     buttons sit on every entry, and by ear they were one. */ }
							{ item.present && mayChangeSharedCode() ? (
								<>
									<Button
										type="ghost"
										size="sm"
										icon="download"
										iconTone="1"
										disabled={ isBusy( item.token ) }
										aria-label={ sprintf(
											/* translators: %s: the file's path. */
											__( 'Download a copy of %s', 'bettershield' ),
											item.path
										) }
										onClick={ () => onDownload( item ) }
									>
										{ __( 'Download a Copy', 'bettershield' ) }
									</Button>

									{ /* The undo every restore promised: the file
									     that was here goes back, byte for byte,
									     through the writer that displaced it. Once
									     it has, the undo is spent and pressing it
									     again could only be refused. */ }
									{ /* Altered code a check or a response took out
									     is asked about first, by what it differs from
									     and which incident removed it: one press wrote
									     it back over the official file (#2244). */ }
									{ ! item.restored && item.code ? (
										<Armed
											type="secondary"
											label={ __( 'Put This File Back', 'bettershield' ) }
											aria-label={ sprintf(
												/* translators: %s: the path the file goes back to. */
												__( 'Put This File Back at %s', 'bettershield' ),
												item.path
											) }
											consequence={ __( 'This puts the changed code back in place of the current file, and that code will run on your site.', 'bettershield' ) }
											confirm={ __( 'Yes, Put the Code Back', 'bettershield' ) }
											busy={ isBusy( item.token ) }
											onConfirm={ () => {
												setPuttingBack( item.token );
												onPutBack( item );
											} }
										/>
									) : null }
									{ ! item.restored && ! item.code ? (
										<Button
											type="secondary"
											size="sm"
											isBusy={ isBusy( item.token ) }
											disabled={ isBusy( item.token ) }
											aria-label={ sprintf(
												/* translators: %s: the path the file goes back to. */
												__( 'Put This File Back at %s', 'bettershield' ),
												item.path
											) }
											onClick={ () => {
												setPuttingBack( item.token );
												onPutBack( item );
											} }
										>
											{ __( 'Put This File Back', 'bettershield' ) }
										</Button>
									) : null }

									{ /* Held through the request and after a refusal,
									     so a retry is the one press it was before. */ }
									<Armed
										ref={ ( node ) => {
											if ( node ) {
												deleteRefs.current.set( item.token, node );
											} else {
												deleteRefs.current.delete( item.token );
											}
										} }
										type="ghost"
										held
										label={ __( 'Delete', 'bettershield' ) }
										aria-label={ sprintf(
											/* translators: %s: the file's path. */
											__( 'Delete %s', 'bettershield' ),
											item.path
										) }
										consequence={ __( 'This permanently deletes the stored copy. Your live site isn’t affected.', 'bettershield' ) }
										confirm={ __( 'Yes, Delete Permanently', 'bettershield' ) }
										busy={ isBusy( item.token ) }
										onConfirm={ () => onDelete( item ) }
									/>
								</>
							) : null }
						</Cell>
					</Row>
				) ) }

				{ /*
				   The ledger is read a page at a time, and a page that filled up
				   is not the end of it. Without this the oldest entries were
				   unreachable from the one surface that is a person looking at
				   them, and nothing on the screen said they existed.
				 */ }
				{ hasMore ? (
					<WholeRow kind="foot">
						<Button ref={ older } type="secondary" size="sm" isBusy={ loadingMore } disabled={ loadingMore } onClick={ onMore }>
							{ __( 'Show Older Quarantined Files', 'bettershield' ) }
						</Button>
					</WholeRow>
				) : null }
			</Table>

			{ dock }
		</Card>
	);
}

/**
 * A whole package that did not match the copy its publisher published.
 *
 * Noticed while an update was being unpacked, one moment before it became the
 * site. It is a different shape from the rows above it: not one file with one
 * comparison, but a version with a list of files, each of which can be looked
 * at on its own.
 *
 * And it is the one row here with an answer that is not "put it back". A
 * plugin built from source, or patched for one site, differs at every update
 * for as long as it is installed — so the owner can say the copy is theirs,
 * which quiets exactly that version and nothing else.
 */
function PackageRow( { change, onAdopt, busy, column = false } ) {
	/*
	 * The paths live beside the row rather than on it, so a row can outlive
	 * them — a half-restored database, a hand edit. The finding is still true
	 * and still has to be shown; what is missing is the list, and the row says
	 * nothing about files rather than claiming there are none.
	 */
	const pkg = change.package || {
		slug: change.slug,
		version: change.version,
		files: [],
		total: 0,
		adopted_changed: false,
		changed: [],
	};
	const [ shown, setShown ] = useState( null );
	const [ diff, setDiff ] = useState( null );
	const [ partial, setPartial ] = useState( false );
	const [ loading, setLoading ] = useState( null );
	const [ diffError, setDiffError ] = useState( null );
	const diffId = `bs-ds-filediff-${ change.id }`;

	const showDiff = ( path ) => {
		if ( shown === path ) {
			setShown( null );
			setDiff( null );
			return;
		}

		setLoading( path );
		setDiffError( null );

		apiFetch( {
			path: `/bettershield/v1/integrity/changes/${ change.id }/preview`,
			method: 'POST',
			data: { path },
		} )
			.then( ( data ) => {
				setShown( path );
				setDiff( data.diff );
				setPartial( Boolean( data.partial ) );
			} )
			.catch( ( error ) =>
				setDiffError(
					error && error.message
						? error.message
						: __( 'The comparison could not be fetched.', 'bettershield' )
				)
			)
			.finally( () => setLoading( null ) );
	};

	// The whole of the file on show, where only the part that differs was drawn.
	const showWhole = () => {
		setLoading( shown );
		setDiffError( null );

		apiFetch( {
			path: `/bettershield/v1/integrity/changes/${ change.id }/preview`,
			method: 'POST',
			data: { path: shown, whole: true },
		} )
			.then( ( data ) => {
				setDiff( data.diff );
				setPartial( false );
			} )
			.catch( ( error ) => setDiffError( error && error.message ? error.message : __( 'The comparison could not be fetched.', 'bettershield' ) ) )
			.finally( () => setLoading( null ) );
	};

	return (
		<>
			<Row id={ `bs-ds-filerow-${ change.id }` } tabIndex={ -1 } open={ Boolean( diff ) } className="bs-ds-filerow">
				{ /* Answered by adopting it, never as one of a selection. */ }
				<SelectCell column={ column } />
				<Cell>
					<SeverityBadge severity="high" />
				</Cell>
				<Cell>
					<TitleMeta
						title={
							// A sentence rather than a path: what differs here is
							// a release, and the files it differs in are listed under it.
							<span className="bs-ds-files__pkgtitle">
								{ sprintf(
									/* translators: 1: a plugin name, 2: its version. */
									__( '%1$s %2$s doesn’t match the official download', 'bettershield' ),
									pkg.name || pkg.slug,
									pkg.version
								) }
							</span>
						}
						meta={
							<span className="bs-ds-files__meta">
								<span>{ __( 'Whole plugin', 'bettershield' ) }</span>
								<span>
									{ sprintf(
										/* translators: %s: date and time. */
										__( 'Found %s', 'bettershield' ),
										formatTime( change.detected_at )
									) }
									{ pkg.total ? ' · ' : null }
									{ pkg.total
										? sprintf(
												/* translators: %s: number of files. */
												_n(
													'%s file differs from the WordPress.org download.',
													'%s files differ from the WordPress.org download.',
													pkg.total,
													'bettershield'
												),
												formatCount( pkg.total )
										  )
										: null }
								</span>
							</span>
						}
					/>
				</Cell>
				<Cell align="end">
					{ mayChangeSharedCode() ? (
						<Button type="secondary" size="sm" isBusy={ busy } disabled={ busy } onClick={ () => onAdopt( change ) }>
							{ __( 'Trust This Version', 'bettershield' ) }
						</Button>
					) : null }
				</Cell>
			</Row>
			<div className={ `bs-ds-files__under${ diff ? ' bs-ds-files__under--open' : '' }` } role="row">
				<div role="cell" className="bs-ds-files__undercell" id={ diffId }>
					{ /* Not a verdict about what the change means — the paths, and a
					     way to read the lines of each one. */ }
					{ pkg.files.length ? (
						<ul className="bs-ds-files__pkgfiles">
							{ pkg.files.map( ( file ) => (
								<li key={ file.path } className="bs-ds-files__pkgfile">
									<Path path={ file.path } />
									{ mayManage() ? (
										<Button
											type="ghost"
											size="sm"
											trailing={ shown === file.path ? 'chevron-up' : 'chevron-down' }
											trailingTone="3"
											isBusy={ loading === file.path }
											disabled={ null !== loading }
											aria-expanded={ shown === file.path }
											aria-label={ sprintf(
												shown === file.path
													? /* translators: %s: the file's path. */
													  __( 'Hide the difference for %s', 'bettershield' )
													: /* translators: %s: the file's path. */
													  __( 'Show the difference for %s', 'bettershield' ),
												file.path
											) }
											onClick={ () => showDiff( file.path ) }
										>
											{ shown === file.path
												? __( 'Hide the Difference', 'bettershield' )
												: __( 'Show the Difference', 'bettershield' ) }
										</Button>
									) : null }
								</li>
							) ) }
						</ul>
					) : null }

					{ pkg.total > pkg.files.length ? (
						<p className="bs-ds-files__line">
							{ sprintf(
								/* translators: %s: number of files listed. */
								__( 'Showing the first %s files.', 'bettershield' ),
								formatCount( pkg.files.length )
							) }
						</p>
					) : null }

					{ /* The half a bare mismatch cannot say: this is not a copy nobody
					     looked at, it is the copy you looked at, changed since. */ }
					{ pkg.adopted_changed ? (
						<p className="bs-ds-files__line">
							{ __(
								'These files changed after you trusted this version:',
								'bettershield'
							) }
							{ ' ' }
							{ pkg.changed.join( ', ' ) }
						</p>
					) : null }

					<p className="bs-ds-files__line">
						{ __(
							'If you or your developer edited this plugin, trust this version to stop the alert. It comes back if one of its files changes.',
							'bettershield'
						) }
					</p>

					{ diffError ? <p className="bs-ds-files__line">{ diffError }</p> : null }

					{ diff ? <Difference html={ diff } partial={ partial } onWhole={ showWhole } working={ null !== loading } /> : null }
				</div>
			</div>
		</>
	);
}

/**
 * What marking one group expected would cover, asked before it is done: the
 * counts, and each added file that can run as code, named, because one
 * injected file among a release's changes is what a batch could hide.
 */
function PackagePreview( { id, preview, busy, onConfirm, onCancel } ) {
	const more = ( preview.added_code_total || 0 ) - ( preview.added_code || [] ).length;
	// Inside the folder the heading already names, so each line is the part
	// that differs.
	const folder = `wp-content/${ 'theme' === preview.context ? 'themes' : 'plugins' }/${ preview.slug }/`;
	const inside = ( path ) => ( path.startsWith( folder ) ? path.slice( folder.length ) : path );

	return (
		<div className="bs-ds-files__under bs-ds-files__under--open" role="row">
			<div role="cell" className="bs-ds-files__undercell bs-ds-files__preview" id={ id }>
				<p className="bs-ds-files__lead">
					{ sprintf(
						/* translators: 1: number of changes, 2: a plugin name, 3: its version, 4: the changes by kind. */
						_n(
							'This accepts %1$s change to %2$s %3$s (%4$s). You can undo it in one step. New changes are still shown.',
							'This accepts %1$s changes to %2$s %3$s (%4$s). You can undo it in one step. New changes are still shown.',
							preview.total,
							'bettershield'
						),
						formatCount( preview.total ),
						preview.name,
						preview.version,
						packageCounts( preview )
					) }
				</p>

				{ preview.added_code_total ? (
					<Alert
						layout="default"
						tone="warning"
						desc={
							<>
								<p>
									{ sprintf(
										/* translators: %s: number of added files that can run as code. */
										_n(
											'%s added file is a script that could run on your site. Look at it before you accept:',
											'%s added files are scripts that could run on your site. Look at them before you accept:',
											preview.added_code_total,
											'bettershield'
										),
										formatCount( preview.added_code_total )
									) }
								</p>
								<ul className="bs-ds-files__code">
									{ preview.added_code.map( ( path ) => (
										<li key={ path }>
											<Path path={ inside( path ) } />
										</li>
									) ) }
								</ul>
								{ more > 0 ? (
									<p>
										{ sprintf(
											/* translators: %s: number of added code files not listed. */
											_n( 'And %s more.', 'And %s more.', more, 'bettershield' ),
											formatCount( more )
										) }
									</p>
								) : null }
							</>
						}
					/>
				) : null }

				<div className="bs-ds-files__confirm">
					<Button type="primary" size="sm" isBusy={ busy } disabled={ busy } onClick={ onConfirm }>
						{ sprintf(
							/* translators: %s: number of changes. */
							_n( 'Accept This %s Change', 'Accept These %s Changes', preview.total, 'bettershield' ),
							formatCount( preview.total )
						) }
					</Button>
					<Button type="ghost" size="sm" onClick={ onCancel }>
						{ __( 'Cancel', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</div>
	);
}

/**
 * One plugin or theme at one recorded version, with what can be done to its
 * changes at once: a group row, and the preview of a marking under it.
 */
function PackageGroup( { pkg, preview, busy, onRecheck, onPreview, onConfirm, onCancel } ) {
	const panelId = `bs-ds-package-${ pkg.context }-${ pkg.slug }`;

	return (
		<div role="rowgroup" aria-label={ pkg.name } className="bs-ds-files__package">
			<WholeRow
				kind="group"
				aside={
					mayChangeSharedCode() ? (
						<>
							{ 'plugin' === pkg.context ? (
								<Button type="secondary" size="sm" icon="refresh-cw" iconTone="2" isBusy={ busy.recheck } disabled={ busy.recheck } onClick={ onRecheck }>
									{ busy.recheck ? __( 'Checking…', 'bettershield' ) : __( 'Check Again', 'bettershield' ) }
								</Button>
							) : null }
							<Button
								type="ghost"
								size="sm"
								trailing={ preview ? 'chevron-up' : 'chevron-down' }
								trailingTone="3"
								aria-expanded={ !! preview }
								aria-controls={ preview ? panelId : undefined }
								isBusy={ busy.preview }
								disabled={ busy.preview }
								onClick={ onPreview }
							>
								{ sprintf(
									/* translators: %s: number of changes. */
									_n( 'Review and Accept %s Change…', 'Review and Accept %s Changes…', pkg.total, 'bettershield' ),
									formatCount( pkg.total )
								) }
							</Button>
						</>
					) : null
				}
			>
				<span className="bs-ds-files__pkgname">
					<span className="bs-ds-files__pkgtitle">{ pkg.name }</span>
					<span className="bs-ds-files__pkgmeta">
						{ sprintf(
							/* translators: 1: a version number, 2: the changes by kind. */
							__( 'Version %1$s: %2$s', 'bettershield' ),
							pkg.version || __( 'unknown', 'bettershield' ),
							packageCounts( pkg )
						) }
					</span>
				</span>
			</WholeRow>
			{ preview ? <PackagePreview id={ panelId } preview={ preview } busy={ busy.expect } onConfirm={ onConfirm } onCancel={ onCancel } /> : null }
		</div>
	);
}

/**
 * One changed file: its severity, its path with what kind of change it is and
 * what it was compared against, and what can be done about it. The lines that
 * differ open under it.
 */
function FileRow( { change, onRestore, onSuppress, onQuarantine = null, busy, sharedWhy = false, column = false, picked = false, onPick = () => {} } ) {
	const [ diff, setDiff ] = useState( null );
	// Keep in quarantine asks once, under the row, before it moves anything.
	const [ keeping, setKeeping ] = useState( false );
	// Cancel takes the question away, and focus back to what asked it.
	const keepToggle = useRef( null );
	const keepId = `bs-ds-filekeep-${ change.id }`;
	const keepable = null !== onQuarantine && 'added' === change.change_type;
	const [ partial, setPartial ] = useState( false );
	const [ loadingDiff, setLoadingDiff ] = useState( false );
	const [ diffError, setDiffError ] = useState( null );
	const diffId = `bs-ds-filediff-${ change.id }`;

	const showDiff = () => {
		if ( diff ) {
			setDiff( null );
			return;
		}

		setLoadingDiff( true );
		setDiffError( null );

		apiFetch( { path: `/bettershield/v1/integrity/changes/${ change.id }/preview`, method: 'POST' } )
			.then( ( data ) => {
				setDiff( data.diff );
				setPartial( Boolean( data.partial ) );
			} )
			.catch( ( error ) =>
				setDiffError(
					error && error.message
						? error.message
						: __( 'The comparison could not be fetched.', 'bettershield' )
				)
			)
			.finally( () => setLoadingDiff( false ) );
	};

	// The whole file, where only the part that differs was drawn.
	const showWhole = () => {
		setLoadingDiff( true );
		setDiffError( null );

		apiFetch( { path: `/bettershield/v1/integrity/changes/${ change.id }/preview`, method: 'POST', data: { whole: true } } )
			.then( ( data ) => {
				setDiff( data.diff );
				setPartial( false );
			} )
			.catch( ( error ) => setDiffError( error && error.message ? error.message : __( 'The comparison could not be fetched.', 'bettershield' ) ) )
			.finally( () => setLoadingDiff( false ) );
	};

	return (
		<>
			<Row id={ `bs-ds-filerow-${ change.id }` } tabIndex={ -1 } open={ Boolean( diff ) } selected={ picked } className="bs-ds-filerow">
				<SelectCell
					column={ column }
					label={ sprintf(
						/* translators: %s: a file's path. */
						__( 'Select %s', 'bettershield' ),
						change.path
					) }
					state={ picked }
					onChange={ onPick }
				/>
				<Cell>
					<SeverityBadge severity={ changeSeverity( change.change_type, change.severity ) } />
				</Cell>
				<Cell>
					<TitleMeta
						title={ <Path path={ change.path } /> }
						meta={
							<>
								<span className="bs-ds-files__meta">
									<span>{ changeLabel( change.change_type ) }</span>
									{ /* Which rows the Overview's "added files can run as
									     code" counts: nothing here said (#1968). */ }
									{ change.can_run ? (
										<span>
											<Badge tone="orange">{ __( 'Can run as code', 'bettershield' ) }</Badge>
										</span>
									) : null }
									<span>
										{ /* One sentence per shape, so a translator can
										     reorder it and keeps the separator. */ }
										{ claimFor( change.context )
											? sprintf(
													/* translators: 1: date and time, 2: what the file was compared with, e.g. "compared with what it was here before". */
													__( 'Found %1$s · %2$s', 'bettershield' ),
													formatTime( change.detected_at ),
													claimFor( change.context )
											  )
											: change.version
											? sprintf(
													/* translators: 1: date and time, 2: a version number. */
													__( 'Found %1$s · compared with version %2$s', 'bettershield' ),
													formatTime( change.detected_at ),
													change.version
											  )
											: sprintf(
													/* translators: %s: date and time. */
													__( 'Found %s', 'bettershield' ),
													formatTime( change.detected_at )
											  ) }
									</span>
								</span>
								{ /* Said by the group heading instead when every file
								     under it shares the reason. */ }
								{ ! change.restorable && change.why_not && ! sharedWhy ? (
									<span className="bs-ds-files__why">{ change.why_not }</span>
								) : null }
							</>
						}
					/>
				</Cell>
				<Cell align="end">
					{ /* Every action here answers only an account that may manage
					     the plugin; a reader is shown the change and offered none.
					     Each is named with its file: the same buttons sit on every
					     row, and by ear "Expected" eleven times named nothing. */ }
					{ mayManage() ? (
						<>
							{ change.restorable ? (
								<>
									<Button
										type="ghost"
										size="sm"
										trailing={ diff ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										onClick={ showDiff }
										isBusy={ loadingDiff }
										disabled={ loadingDiff }
										aria-expanded={ Boolean( diff ) }
										aria-controls={ diff ? diffId : undefined }
										aria-label={ sprintf(
											diff
												? /* translators: %s: the file's path. */
												  __( 'Hide the difference for %s', 'bettershield' )
												: /* translators: %s: the file's path. */
												  __( 'Show the difference for %s', 'bettershield' ),
											change.path
										) }
									>
										{ diff ? __( 'Hide the Difference', 'bettershield' ) : __( 'Show the Difference', 'bettershield' ) }
									</Button>
									{ mayChangeSharedCode() ? (
									<Button
										type="secondary"
										size="sm"
										isBusy={ busy }
										disabled={ busy }
										aria-label={ sprintf(
											/* translators: %s: the file's path. */
											__( 'Restore the official file at %s', 'bettershield' ),
											change.path
										) }
										onClick={ () => onRestore( change ) }
									>
										{ __( 'Restore Official File', 'bettershield' ) }
									</Button>
									) : null }
								</>
							) : null }

							{ /* A file nobody published: its own way out of the site,
							     kept rather than deleted (#1971). */ }
							{ keepable && mayChangeSharedCode() ? (
								<Button
									ref={ keepToggle }
									type="secondary"
									size="sm"
									disabled={ busy }
									aria-expanded={ keeping }
									aria-controls={ keeping ? keepId : undefined }
									aria-label={ sprintf(
										/* translators: %s: the file's path. */
										__( 'Move %s to quarantine', 'bettershield' ),
										change.path
									) }
									onClick={ () => setKeeping( ( was ) => ! was ) }
								>
									{ __( 'Move to Quarantine', 'bettershield' ) }
								</Button>
							) : null }
							{ mayChangeSharedCode() ? (
								<Button
									type="ghost"
									size="sm"
									isBusy={ busy }
									disabled={ busy }
									aria-label={ sprintf(
										/* translators: %s: the file's path. */
										__( 'Accept the change to %s', 'bettershield' ),
										change.path
									) }
									title={ __( 'Stop listing it until the file changes again', 'bettershield' ) }
									onClick={ () => onSuppress( change ) }
								>
									{ __( 'Accept Change', 'bettershield' ) }
								</Button>
							) : null }
						</>
					) : null }
				</Cell>
			</Row>
			{ keepable && keeping ? (
				<div className="bs-ds-files__under bs-ds-files__under--open" role="row">
					<div role="cell" className="bs-ds-files__undercell" id={ keepId }>
						<p className="bs-ds-files__line">
							{ __( 'Moves this file to quarantine and leaves an empty placeholder. Anything that uses the file may stop working. You can put it back anytime.', 'bettershield' ) }
						</p>
						<div className="bs-ds-files__keep">
							<Button
								type="primary"
								size="sm"
								isBusy={ busy }
								disabled={ busy }
								onClick={ () => {
									setKeeping( false );
									onQuarantine( change );
								} }
							>
								{ __( 'Move to Quarantine', 'bettershield' ) }
							</Button>
							<Button
								type="ghost"
								size="sm"
								disabled={ busy }
								onClick={ () => {
									setKeeping( false );
									if ( keepToggle.current ) {
										keepToggle.current.focus();
									}
								} }
							>
								{ __( 'Cancel', 'bettershield' ) }
							</Button>
						</div>
					</div>
				</div>
			) : null }
			{ diffError || diff ? (
				<div className={ `bs-ds-files__under${ diff ? ' bs-ds-files__under--open' : '' }` } role="row">
					<div role="cell" className="bs-ds-files__undercell" id={ diffId }>
						{ diffError ? <p className="bs-ds-files__line">{ diffError }</p> : null }
						{ diff ? <Difference html={ diff } partial={ partial } onWhole={ showWhole } working={ loadingDiff } /> : null }
					</div>
				</div>
			) : null }
		</>
	);
}

/**
 * A group's own row: its name and how many it holds, as the heading the
 * rows under it are read beneath.
 *
 * @param {Object} props
 * @param {string} props.label The group's name.
 * @param {number} props.count How many it holds.
 */
/**
 * What a group's badge says.
 *
 * Every change loaded, the rows are the count. Otherwise the loaded rows are
 * part of the group, and counting them told a reader marking files expected
 * that nothing changed: the first page came back and the next change in line
 * slid into the same group. So the group's own total where the site counts
 * one — the files that can be put back, and the files nobody published when
 * they are one group — and otherwise a count that says it is of loaded rows.
 *
 * @param {Object}   group   One group from groupChanges().
 * @param {Object[]} changes Every change loaded.
 * @param {Object}   report  The report, with `next_cursor` and `open_changes`.
 * @return {number|string} The badge.
 */
function groupCount( group, changes, report ) {
	const loaded = group.changes.length;
	const totals = report.open_changes || {};

	if ( ! report.next_cursor ) {
		return loaded;
	}

	// The site's totals are of every open change, not of the ones a filter
	// keeps.
	if ( Number.isInteger( report.matching ) ) {
		return sprintf(
			/* translators: 1: rows of this group on screen, 2: rows loaded in all. */
			__( '%1$s of the %2$s loaded', 'bettershield' ),
			formatCount( loaded ),
			formatCount( changes.length )
		);
	}

	if ( 'restorable' === group.key && Number.isInteger( totals.restorable ) ) {
		return totals.restorable;
	}

	const added = changes.filter( ( change ) => 'added' === change.change_type ).length;

	if ( Number.isInteger( totals.added ) && added === loaded && group.changes.every( ( change ) => 'added' === change.change_type && ! change.restorable ) ) {
		return totals.added;
	}

	return sprintf(
		/* translators: 1: rows of this group on screen, 2: rows loaded in all. */
		__( '%1$s of the %2$s loaded', 'bettershield' ),
		formatCount( loaded ),
		formatCount( changes.length )
	);
}

/**
 * A group's heading, with how many it holds, and the checkbox that picks
 * every loaded row of it where any can be picked.
 *
 * @param {Object}  props
 * @param {string}  props.label The group's name.
 * @param {*}       props.count How many it holds.
 * @param {?Object} props.pick  { label, state, onChange }: the checkbox that picks every loaded row of it.
 */
function GroupHead( { label, count, pick = null } ) {
	return (
		<WholeRow kind="group">
			{ pick ? <Checkbox label={ pick.label } state={ pick.state } onChange={ pick.onChange } /> : null }
			<h3 className="bs-ds-files__group">
				{ label }
				<Badge>{ 'number' === typeof count ? formatCount( count ) : count }</Badge>
			</h3>
		</WholeRow>
	);
}

/** The four facts' names, shared by the strip and the tab's stand-in. */
function glanceLabels() {
	return {
		checked: __( 'Last check', 'bettershield' ),
		open: __( 'Changed files to review', 'bettershield' ),
		restorable: __( 'Can be restored', 'bettershield' ),
		quarantine: __( 'In quarantine', 'bettershield' ),
	};
}

/**
 * The file check in four facts: when it last looked, how much it found
 * unresolved, how much of that can be put back, and what is kept aside.
 * Read from the report the screen already holds, so it cannot disagree with
 * the list under it.
 *
 * @param {Object}   props
 * @param {Object}   props.report         The integrity report.
 * @param {Object[]} props.changes        The changes loaded so far.
 * @param {Object[]} props.quarantined    The quarantined files loaded so far.
 * @param {boolean}  props.quarantineMore Whether more are kept than are loaded.
 * @param {string}   props.quarantineRead Where the quarantine's own read stands: loading, ready or error.
 */
function FilesGlance( { report, changes, quarantined, quarantineMore, quarantineRead = 'ready' } ) {
	const labels = glanceLabels();
	const open = report.open_changes && report.open_changes.total ? report.open_changes.total : changes.length;
	/* Counted by the server across every page. The rows loaded so far are a
	   page or a few of them, and on a site with many newer unpublished files
	   they held none of these, so the tile led with 0. */
	const counted = Number.isInteger( report.open_changes?.restorable );
	const restorable = counted ? report.open_changes.restorable : changes.filter( ( change ) => change.restorable ).length;

	let next = __( 'No check is scheduled', 'bettershield' );

	if ( report.running ) {
		next = scanProgress( report.progress );
	} else if ( report.next_run_at && ! isPast( report.next_run_at ) ) {
		next = sprintf(
			/* translators: %s: when the next check runs, e.g. "today, 4:02 PM". */
			__( 'Next check %s', 'bettershield' ),
			whenPhrase( report.next_run_at )
		);
	}

	/*
	 * A first check still under way, or paused between steps: it has already
	 * compared files and listed changes, so the tiles say how far it got
	 * rather than "Never" and "Nothing compared yet" (#2633).
	 */
	const first = ! report.ever_run && report.progress && report.progress.targets ? report.progress : null;

	const tiles = [
		{
			key: 'checked',
			icon: 'clock',
			label: labels.checked,
			value: report.ever_run
				? whenPhrase( report.last_run_at )
				: first
				? sprintf(
						/* translators: 1: how many parts of the site are checked, 2: how many there are. */
						__( 'In progress, %1$s of %2$s', 'bettershield' ),
						formatCount( Math.min( Number( first.target ) || 0, Number( first.targets ) ) ),
						formatCount( first.targets )
				  )
				: __( 'Never', 'bettershield' ),
			text: true,
			tone: report.ever_run || first ? undefined : 'caution',
			detail: next,
		},
		{
			key: 'open',
			icon: 'file-diff',
			label: labels.open,
			value: formatCount( open ),
			tone: open ? 'caution' : 'good',
			detail:
				report.ever_run && report.stats
					? sprintf(
							/* translators: %s: number of files compared. */
							_n( 'Across %s file compared', 'Across %s files compared', report.stats.checked, 'bettershield' ),
							formatCount( report.stats.checked )
					  )
					: first && Number( first.checked ) > 0
					? sprintf(
							/* translators: %s: number of files compared so far. */
							_n( 'Across %s file so far', 'Across %s files so far', Number( first.checked ), 'bettershield' ),
							formatCount( Number( first.checked ) )
					  )
					: __( 'Nothing compared yet', 'bettershield' ),
		},
		{
			key: 'restorable',
			icon: 'undo-2',
			label: labels.restorable,
			value: formatCount( restorable ),
			detail: counted
				? sprintf(
						/* translators: %s: number of unresolved file changes. */
						_n( 'Of %s to review', 'Of %s to review', open, 'bettershield' ),
						formatCount( open )
				  )
				: sprintf(
						/* translators: %s: number of changes listed on screen. */
						_n( 'Of the %s shown below', 'Of the %s shown below', changes.length, 'bettershield' ),
						formatCount( changes.length )
				  ),
		},
		{
			key: 'quarantine',
			icon: 'archive',
			label: labels.quarantine,
			/*
			 * The quarantine is a read of its own. Before it lands, "0" would
			 * be a claim about files nobody has counted yet, so the tile holds
			 * its place; after a read that failed it has no number to give.
			 */
			value:
				'error' === quarantineRead
					? '—'
					: quarantineMore
					? `${ quarantined.length }+`
					: formatCount( quarantined.length ),
			detail: __( 'Moved out of use, not deleted unless you choose', 'bettershield' ),
			pending: 'loading' === quarantineRead,
		},
	];

	return <Stats label={ __( 'Files at a glance', 'bettershield' ) } tiles={ tiles } />;
}

/**
 * What a part-finished check is waiting for, when nothing on the screen is
 * carrying it on: the scheduled check, or a press of Continue check.
 *
 * @param {Object} report The integrity report.
 * @return {string} One sentence.
 */
function parkedNote( report ) {
	if ( report.next_run_at && ! isPast( report.next_run_at ) ) {
		return sprintf(
			/* translators: %s: when the next scheduled check runs, e.g. "today, 4:02 PM". */
			__( 'The check is paused partway. It resumes %s, or press Continue Check to resume now.', 'bettershield' ),
			whenPhrase( report.next_run_at )
		);
	}

	return __( 'The check is paused partway. Press Continue Check to finish it.', 'bettershield' );
}

/**
 * The file check before its report has landed: the four facts, with their
 * names already in place, then the report's card with rows where its rows
 * will be.
 */
export function FilesBone() {
	return (
		<Skeleton label={ __( 'Loading the file check…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />
			<CardBone rows={ [ '46%', '62%', '38%', '54%' ] } />
		</Skeleton>
	);
}

export default function Files() {
	const summaryHeading = useRef( null );
	const choosing = mayChangeSharedCode();
	// Why parts of the site were not compared, opened on request.
	const [ whyOpen, setWhyOpen ] = useState( false );
	// The groups opened past their first few files, by group key.
	const [ openGroups, setOpenGroups ] = useState( () => new Set() );
	const toggleGroup = ( key ) =>
		setOpenGroups( ( current ) => {
			const next = new Set( current );

			if ( next.has( key ) ) {
				next.delete( key );
			} else {
				next.add( key );
			}

			return next;
		} );

	/*
	 * Where focus goes when a row is resolved and the control that had it
	 * goes with it.
	 *
	 * The row next to it, and the heading only when none survives. Sent
	 * straight to the heading it jumped the reader to the top of a report
	 * they were some way down — which on a site with several hundred changed
	 * files means finding their place again after every single decision.
	 *
	 * The neighbor is chosen when the action is asked for, while the list
	 * still says where the row stands, and resolved when focus is actually
	 * moved, because the node does not exist until the report has come back.
	 * `useMutationFocus` reads `.current` at that moment, so this is a getter
	 * rather than a ref somebody has to remember to update in time.
	 */
	const wantedRow = useRef( null );
	const landing = useMemo(
		() => ( {
			get current() {
				const row = wantedRow.current
					? document.getElementById( `bs-ds-filerow-${ wantedRow.current }` )
					: null;

				return row || summaryHeading.current;
			},
		} ),
		[]
	);
	const afterMutation = useMutationFocus( landing );
	const [ report, setRawReport ] = useState( null );
	/*
	 * What the open list is narrowed by, on the server, so it covers every
	 * page and not only the rows loaded. The search is kept as typed and
	 * narrows after a pause. A mirror for answers that arrive later.
	 */
	const [ filter, setFilter ] = useState( NO_FILTER );
	const [ typed, setTyped ] = useState( '' );
	const filterNow = useRef( NO_FILTER );
	const searchField = useRef( null );
	// Every change the filter matches, picked across pages not loaded: what
	// the site counted of them, or null.
	const [ everything, setEverything ] = useState( null );
	// What the last pass could not compare, and of it the plugins nothing
	// publishes, whose files are watched against the copy first seen (#1969).
	const unverifiable = ( report && report.unverifiable ) || [];
	const watched = unverifiable.filter( ( item ) => 'plugin' === item.context && 'not_published' === item.reason );
	const notCompared = unverifiable.filter( ( item ) => ! watched.includes( item ) );
	const [ status, setStatus ] = useState( 'loading' );
	/*
	 * A set rather than one value. Every control on this screen used to read
	 * the same scalar, so starting a second action overwrote it and re-enabled
	 * the first — which then read "idle" while its request was still in
	 * flight, and a second click sent a duplicate. The shared store already
	 * guards this way; this screen had its own unguarded version.
	 */
	const [ busy, setBusy ] = useState( () => new Set() );
	/*
	 * Five of this screen's actions take a protection away, so they run
	 * through the shared data layer: it is the only fetcher that recognizes
	 * "confirm your password again" and can put a field on screen to answer
	 * it. Their busy state therefore lives in the store, and both sources
	 * answer the same question here.
	 */
	const {
		markChangeExpected,
		stopExpectingChange,
		putQuarantinedBack,
		forgetQuarantined,
		quarantineBatch,
		adoptPackage,
		undoPackageAdoption,
		markPackageExpected,
		unmarkPackageExpected,
		markChangesExpected,
		unmarkChangesExpected,
		markMatchingExpected,
		busy: shared,
		notice: sharedNotice,
		setNotice: setSharedNotice,
		load: loadShared,
		resources,
	} = useStore();
	const isBusy = ( key ) => busy.has( key ) || isWorking( shared, key );

	// The re-entry guards read this mirror, not the render-scope set: two
	// clicks landing before React re-renders both saw the stale set and both
	// fired, and the second delete 404ed with a spurious failure notice.
	const busyNow = useRef( new Set() );

	const claim = ( key ) => {
		if ( busyNow.current.has( key ) ) {
			return false;
		}
		busyNow.current.add( key );
		setBusy( ( current ) => new Set( current ).add( key ) );
		return true;
	};

	const release = ( key ) => {
		busyNow.current.delete( key );
		if ( mounted.current ) {
			setBusy( ( current ) => {
				const next = new Set( current );
				next.delete( key );
				return next;
			} );
		}
	};
	/*
	 * Two slots, because they are two different things. A failure interrupts
	 * and stands until it is dismissed; an outcome is announced politely and
	 * replaced by the next one. Written into one state and rendered in the
	 * error card, "the file that was there is back, byte for byte" arrived
	 * styled as a failure and read out as an emergency.
	 */
	const [ notice, setNotice ] = useState( null );
	const [ done, setDone ] = useState( null );
	/*
	 * A row's own outcome, said in the head of the group the row was in. The
	 * slot above is at the top of the card, out of view from a row further
	 * down, while the row after it slides into the same place: from the
	 * screen it looked as if Expected or Put back had done nothing.
	 */
	const [ rowNote, setRowNote ] = useState( null );

	// One outcome on screen at a time: a later one said above replaces it.
	useEffect( () => {
		if ( done || notice ) {
			setRowNote( null );
		}
	}, [ done, notice ] );
	// The changes marked expected, folded away until asked for: they are
	// the exception, and a long list of them would push the open ones down.
	const [ expectedOpen, setExpectedOpen ] = useState( false );
	// The one group whose marking is being previewed, and what it would cover.
	const [ packagePreview, setPackagePreview ] = useState( null );
	/*
	 * The quarantine list keeps its own slot for both. It is the last thing on
	 * a page whose length is the length of the site's history, so an outcome
	 * rendered with the two above — which belong to controls at the top of the
	 * screen — is out of sight from the button that produced it.
	 */
	const [ quarantineNote, setQuarantineNote ] = useState( null );
	/*
	 * The way back from the one action on this screen that quiets something.
	 * It is kept beside the outcome rather than on the row, because the row it
	 * belongs to is gone the moment the adoption lands.
	 */
	const [ adopted, setAdopted ] = useState( null );
	const [ quarantined, setQuarantined ] = useState( [] );
	// What to ask for to continue the ledger, and whether there is anything
	// left to ask for. Zero means this page was the last.
	const [ quarantineNext, setQuarantineNext ] = useState( 0 );
	const [ quarantineMore, setQuarantineMore ] = useState( false );
	// Whether the first read of the quarantine has answered. Later reads keep
	// the list they have on screen while they run.
	const [ quarantineRead, setQuarantineRead ] = useState( 'loading' );
	const [ loadingMore, setLoadingMore ] = useState( false );
	/*
	 * Many rows at once. The changes are picked by id and the kept copies by
	 * token, each list on its own: they take different actions. What is
	 * picked is read against the rows on screen, so a row resolved by
	 * anything else simply stops being counted.
	 */
	const [ picked, setPicked ] = useState( () => new Set() );
	const [ pickedKept, setPickedKept ] = useState( () => new Set() );
	// The question asked before a decision about many: { list, kind, rows }.
	const [ asking, setAsking ] = useState( null );
	// What the last one did, said where it was taken: { list, kind, … }.
	const [ receipt, setReceipt ] = useState( null );
	// Kept copies going a request at a time, between the shared layer's turns.
	const [ turning, setTurning ] = useState( false );
	const askRef = useRef( null );
	const receiptRef = useRef( null );
	const barRef = useRef( null );
	/*
	 * A mirror of the list as last shown. The router below reads how many are
	 * left and must not be rebuilt when the list changes, because it is a
	 * dependency of the effect that moves a refusal down into the card.
	 *
	 * Answers that arrive after a click build on it too, not on the list the
	 * click saw: an older page loaded while a put-back was out was dropped
	 * again when the put-back answered, until a reload.
	 */
	const shown = useRef( [] );

	const showQuarantined = useCallback( ( items ) => {
		shown.current = items;
		setQuarantined( items );
	}, [] );

	const mounted = useRef( true );

	useEffect( () => {
		mounted.current = true;

		return () => {
			mounted.current = false;
		};
	}, [] );

	const load = useCallback( () => {
		const asked = filterNow.current;

		apiFetch( { path: '/bettershield/v1/integrity' + filterQuery( asked ) } )
			.then( ( data ) => {
				if ( mounted.current && asked === filterNow.current ) {
					setRawReport( data );
					setStatus( 'ready' );
				}
			} )
			.catch( () => {
				if ( mounted.current ) {
					setStatus( 'error' );
				}
			} );
	}, [] );

	useEffect( load, [ load ] );

	/*
	 * An action answers with the whole open list. Narrowed, the screen shows
	 * the rows the filter keeps of it, and reads the narrowed list again when
	 * the answer was one page of many.
	 */
	const setReport = useCallback(
		( next ) => {
			if ( 'function' === typeof next || ! isFiltered( filterNow.current ) ) {
				setRawReport( next );

				return;
			}

			setRawReport( ( current ) => filteredAnswer( current, next, filterNow.current ).report );

			if ( next && next.next_cursor ) {
				load();
			}
		},
		[ load ]
	);

	/*
	 * A progress answer while a run goes on, taken as the run's own fields
	 * only. Every answer is the first page, and replacing the whole report
	 * with it dropped the older rows the reader had brought in, every few
	 * seconds, and put back rows just resolved when an answer overtook an
	 * action. Once the run has ended, the answer is what it found, whole.
	 */
	const takeRun = useCallback( ( data, narrowed = false ) => {
		if ( ! data || ! data.running ) {
			// The run's end, read through the filter or not.
			( narrowed ? setRawReport : setReport )( data );

			return;
		}

		setRawReport( ( current ) =>
			current
				? {
						...current,
						running: data.running,
						progress: data.progress,
						stats: data.stats,
						last_run_at: data.last_run_at,
						ever_run: data.ever_run,
						next_run_at: data.next_run_at,
				  }
				: data
		);
	}, [ setReport ] );

	/*
	 * A finished run re-runs the audit on the server, so the score and the
	 * findings other screens read have moved: read again whatever of them has
	 * been read. Kept from the first report seen, so opening the screen is not
	 * taken for a run that just finished.
	 */
	const lastRun = report ? report.last_run_at || '' : null;
	const seenRun = useRef( null );

	useEffect( () => {
		if ( null === lastRun ) {
			return;
		}

		if ( null !== seenRun.current && lastRun !== seenRun.current ) {
			[ 'overview', 'findings' ].forEach( ( name ) => {
				if ( resources[ name ] && 'idle' !== resources[ name ].status ) {
					loadShared( name, { force: true } );
				}
			} );
		}

		seenRun.current = lastRun;
		// eslint-disable-next-line react-hooks/exhaustive-deps -- a run finishing is the trigger, not the resources it reads again.
	}, [ lastRun ] );

	/*
	 * A run in flight is asked about again until it stops. The bar can only
	 * appear while one is running, and a run is running because a scheduled
	 * tick left it part-finished — nothing on this screen starts or ends it.
	 * Drawn once from the load that mounted the screen, the bar stood still
	 * for as long as anybody looked at it, which is exactly what the bar
	 * exists instead of. Reading the state is a read and costs a query.
	 */
	const running = !! ( report && report.running );

	// Whether this screen is carrying a check on: see the effect after this one.
	const [ driving, setDriving ] = useState( false );

	useEffect( () => {
		// While this screen drives the run, each slice answers with the report.
		if ( ! running || driving ) {
			return undefined;
		}

		const timer = window.setInterval( () => {
			const asked = filterNow.current;

			apiFetch( { path: '/bettershield/v1/integrity' + filterQuery( asked ) } )
				.then( ( data ) => {
					if ( mounted.current && asked === filterNow.current ) {
						takeRun( data, true );
					}
				} )
				.catch( () => {} );
		}, 4000 );

		return () => window.clearInterval( timer );
	}, [ running, driving, takeRun ] );

	/*
	 * Carrying a check on from this screen. A slice is a few seconds of
	 * work, and after the one Check now ran the run waited for the hourly
	 * task, with the bar and the line standing still for anyone watching.
	 * Once somebody asks for a check here, the next slice is asked for when
	 * the last one answers, until the run ends, the screen closes or a slice
	 * fails. A run nobody here asked for is not driven from a page view.
	 */
	const sliceOut = isBusy( 'scan' );

	useEffect( () => {
		if ( ! driving ) {
			return undefined;
		}

		if ( ! running ) {
			setDriving( false );

			return undefined;
		}

		if ( sliceOut ) {
			return undefined;
		}

		const timer = window.setTimeout( () => {
			if ( ! claim( 'scan' ) ) {
				return;
			}

			apiFetch( { path: '/bettershield/v1/integrity/scan', method: 'POST' } )
				.then( ( data ) => {
					if ( mounted.current ) {
						takeRun( data );
					}
				} )
				.catch( ( error ) => {
					if ( mounted.current ) {
						setDriving( false );
						setNotice(
							error && error.message
								? error.message
								: __( 'The check stopped partway. It resumes at the next scheduled check, or you can press Continue Check.', 'bettershield' )
						);
					}
				} )
				.finally( () => release( 'scan' ) );
		}, SLICE_GAP );

		return () => window.clearTimeout( timer );
	}, [ driving, running, sliceOut, report ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const loadQuarantine = useCallback( () => {
		apiFetch( { path: '/bettershield/v1/quarantine' } )
			.then( ( data ) => {
				if ( mounted.current ) {
					showQuarantined( data.items || [] );
					setQuarantineMore( !! data.has_more );
					setQuarantineNext( Number( data.next_before_id ) || 0 );
					setQuarantineRead( 'ready' );
				}
			} )
			.catch( () => {
				if ( mounted.current ) {
					// A read that failed after one that answered keeps the
					// answer it had.
					setQuarantineRead( ( read ) => ( 'ready' === read ? read : 'error' ) );
				}
			} );
	}, [ showQuarantined ] );

	useEffect( loadQuarantine, [ loadQuarantine ] );

	// The question takes focus when it opens, so it is read before it is answered.
	useEffect( () => {
		if ( asking && askRef.current ) {
			askRef.current.focus();
		}
	}, [ asking ] );

	// What happened takes the keyboard when the control that asked has gone.
	useEffect( () => {
		if ( receipt ) {
			focusIfLost( receiptRef.current );
		}
	}, [ receipt ] );

	/*
	 * Whether the refusal the shared layer is about to announce belongs to
	 * this card. Two of the three actions here run through that layer, which
	 * says why it refused above the whole screen — the right place for an
	 * action taken at the top of one, and out of sight for these, which are
	 * taken at the bottom.
	 *
	 * Every other action on this screen that goes through the same layer
	 * clears it, so a refusal belonging to a row at the top cannot be claimed
	 * down here after a held quarantine action was abandoned.
	 */
	const fromQuarantine = useRef( false );

	/*
	 * Beside the list while there is a list. Removing the last item takes the
	 * card away with it and sends focus back to the heading at the top of the
	 * screen, so on that one action the sentence has to go back up there too
	 * rather than leave with the card that was carrying it.
	 */
	const tellQuarantine = useCallback( ( text, tone = 'status' ) => {
		if ( shown.current.length ) {
			setQuarantineNote( { tone, text } );

			return;
		}

		setQuarantineNote( null );

		if ( 'alert' === tone ) {
			setNotice( text );
		} else {
			setDone( text );
		}
	}, [] );

	// The next page, appended: the list is newest first and stays that way,
	// so what arrives goes after what is already on screen.
	const loadMoreQuarantine = useCallback( () => {
		if ( ! quarantineNext ) {
			return;
		}

		setLoadingMore( true );

		apiFetch( { path: `/bettershield/v1/quarantine?before_id=${ quarantineNext }` } )
			.then( ( data ) => {
				if ( ! mounted.current ) {
					return;
				}

				showQuarantined( [ ...shown.current, ...( data.items || [] ) ] );
				setQuarantineMore( !! data.has_more );
				setQuarantineNext( Number( data.next_before_id ) || 0 );
			} )
			// Said beside the button: an empty catch here left the list as it
			// was, which reads as "there was nothing older".
			.catch( ( error ) => {
				if ( mounted.current ) {
					tellQuarantine( error && error.message ? error.message : __( 'The older entries could not be read. Try again.', 'bettershield' ), 'alert' );
				}
			} )
			.finally( () => {
				if ( mounted.current ) {
					setLoadingMore( false );
				}
			} );
	}, [ quarantineNext, showQuarantined, tellQuarantine ] );

	useEffect( () => {
		if ( ! fromQuarantine.current || ! sharedNotice ) {
			return;
		}

		fromQuarantine.current = false;
		setSharedNotice( null );
		tellQuarantine( sharedNotice, 'alert' );
	}, [ sharedNotice, setSharedNotice, tellQuarantine ] );

	const downloadQuarantined = ( item ) => {
		if ( ! claim( item.token ) ) {
			return;
		}

		setQuarantineNote( null );

		apiFetch( { path: `/bettershield/v1/quarantine/${ item.token }/download`, method: 'POST' } )
			.then( ( data ) => {
				/*
				 * Written out in the browser rather than linked to: the folder
				 * these live in answers 404 to the web by design, and a link
				 * would be the one way back in.
				 */
				downloadBytes( data.filename, data.base64 );

				if ( mounted.current ) {
					tellQuarantine( __( 'A copy was downloaded; the activity log records it.', 'bettershield' ) );
				}
			} )
			.catch( ( error ) => {
				if ( mounted.current ) {
					tellQuarantine( error && error.message ? error.message : __( 'That copy could not be read.', 'bettershield' ), 'alert' );
				}
			} )
			.finally( () => release( item.token ) );
	};

	/*
	 * After a put-back or a delete, the entry acted on is updated where it
	 * is, and every page loaded so far stays: the answer's own first page
	 * used to replace them, so the older entries could not be reached until a
	 * reload. An entry the screen does not hold takes the answer's page, and
	 * what it says about older ones.
	 */
	const afterQuarantineAction = ( data, token ) => {
		if ( data.item && shown.current.some( ( entry ) => entry.token === token ) ) {
			showQuarantined( shown.current.map( ( entry ) => ( entry.token === token ? { ...entry, ...data.item } : entry ) ) );
			return;
		}

		showQuarantined( data.items || [] );
		setQuarantineMore( !! data.has_more );
		setQuarantineNext( Number( data.next_before_id ) || 0 );
	};

	/* The quarantine card and the package actions are not row mutations, so
	   they clear the aim rather than inherit whichever row was resolved last. */
	const aimAtSummary = () => {
		wantedRow.current = null;
	};

	const putBackQuarantined = ( item ) => {
		aimAtSummary();
		setQuarantineNote( null );
		fromQuarantine.current = true;

		putQuarantinedBack( item.token, afterMutation( ( data ) => {
			// A refusal resolves null: the shared layer has already either
			// said why or asked for the password.
			if ( ! data || ! mounted.current ) {
				return;
			}

			fromQuarantine.current = false;
			afterQuarantineAction( data, item.token );

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			/* Only a change the file check had recorded is listed again at
			   once; anything else is found, if it still differs, by the next
			   check. */
			tellQuarantine(
				data.reported
					? __( 'The file is back as it was, and it is listed again under changed files.', 'bettershield' )
					: __( 'The file is back as it was. The next check compares it with the official copy.', 'bettershield' )
			);
		} ) );
	};

	const deleteQuarantined = ( item ) => {
		aimAtSummary();
		setQuarantineNote( null );
		fromQuarantine.current = true;

		forgetQuarantined( item.token, afterMutation( ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			fromQuarantine.current = false;
			afterQuarantineAction( data, item.token );
			tellQuarantine( __( 'That copy is gone. The activity log keeps a record of it.', 'bettershield' ) );
		} ) );
	};

	/* ---- many rows at once ------------------------------------------------ */

	// Any change to what is picked closes the question it raised: the
	// question named a count, and that count is no longer the one on screen.
	const pickChanges = ( ids, on ) => {
		setAsking( null );

		// Every match picked, a row let go: what stays picked is the rows
		// loaded, less that one.
		if ( everything ) {
			const loaded = ( report?.changes || [] ).filter( selectableChange ).map( ( change ) => change.id );

			setEverything( null );
			setPicked( toggled( new Set( loaded ), ids, on ) );

			return;
		}

		setPicked( ( was ) => toggled( was, ids, on ) );
	};

	/* ---- narrowing the list ------------------------------------------------ */

	/*
	 * A new filter is a new list: what was picked was picked from the old
	 * one, so it goes, with the question it raised. A decision's answer, and
	 * its Undo, stay.
	 */
	const narrow = ( change ) => {
		const next = { ...filterNow.current, ...change };

		if ( [ 'place', 'change_type', 'severity', 'search' ].every( ( key ) => next[ key ] === filterNow.current[ key ] ) ) {
			return;
		}

		filterNow.current = next;
		setFilter( next );
		setPicked( new Set() );
		setEverything( null );
		setAsking( null );
		setOpenGroups( new Set() );

		apiFetch( { path: '/bettershield/v1/integrity' + filterQuery( next ) } )
			.then( ( data ) => {
				if ( ! mounted.current || next !== filterNow.current ) {
					return;
				}

				setRawReport( data );

				const total = isFiltered( next ) ? Number( data.matching ) || 0 : Number( data.open_changes?.total ) || 0;

				announce(
					sprintf(
						/* translators: %s: how many open file changes the filter matches. */
						_n( '%s file change matches.', '%s file changes match.', total, 'bettershield' ),
						formatCount( total )
					)
				);
			} )
			.catch( ( error ) => {
				if ( mounted.current && next === filterNow.current ) {
					setNotice( error && error.message ? error.message : __( 'The file changes could not be loaded. Try again.', 'bettershield' ) );
				}
			} );
	};

	// The search narrows once typing pauses, not at every key.
	useEffect( () => {
		const timer = window.setTimeout( () => narrow( { search: typed.trim() } ), 300 );

		return () => window.clearTimeout( timer );
		// eslint-disable-next-line react-hooks/exhaustive-deps -- what was typed is the trigger.
	}, [ typed ] );

	// Every filter off at once; the keyboard goes to the search, since the
	// control that was pressed goes with the filters.
	const clearFilters = () => {
		setTyped( '' );
		narrow( NO_FILTER );
		window.requestAnimationFrame( () => focusIfLost( searchField.current ) );
	};

	/*
	 * Every change the filter matches, on pages not loaded too. The site
	 * counts them first, by kind, with the added code among them by name and
	 * the newest one, which every decision about them is held to.
	 */
	const selectEverything = () => {
		if ( ! claim( 'matching' ) ) {
			return;
		}

		const asked = filterNow.current;

		setAsking( null );
		announce( __( 'Counting every matching change…', 'bettershield' ) );

		apiFetch( { path: '/bettershield/v1/integrity/changes/matching' + filterQuery( asked ) } )
			.then( ( data ) => {
				if ( ! mounted.current || asked !== filterNow.current ) {
					return;
				}

				const total = Number( data.total ) || 0;

				if ( total ) {
					setEverything( { ...data, filter: asked } );
				}

				announce(
					total
						? sprintf(
								/* translators: %s: how many changes are selected. */
								_n( 'All %s matching change is selected.', 'All %s matching changes are selected.', total, 'bettershield' ),
								formatCount( total )
						  )
						: __( 'None of the matching changes can be selected.', 'bettershield' )
				);
				// The control that asked goes with the answer: the keyboard
				// goes to the bar that now holds every match.
				window.requestAnimationFrame( () => focusIfLost( barRef.current && barRef.current.querySelector( 'button' ) ) );
			} )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error && error.message ? error.message : __( 'The matching changes could not be counted. Nothing was selected.', 'bettershield' ) );
				}
			} )
			.finally( () => release( 'matching' ) );
	};

	/** The list as the site answered it, where the filter it was asked with is still the one on screen. */
	const takeNarrowed = ( data, asked ) => {
		if ( asked === filterNow.current ) {
			setRawReport( data );
		} else {
			load();
		}
	};

	// Every match marked expected as one decision, with one Undo.
	const markEverythingExpected = ( all ) => {
		aimAtSummary();
		fromQuarantine.current = false;

		markMatchingExpected(
			{ ...filterParams( all.filter ), seen: all.total, through: all.through },
			( data ) => {
				if ( ! data || ! mounted.current ) {
					return;
				}

				if ( data.integrity ) {
					takeNarrowed( data.integrity, all.filter );
				}

				setAsking( null );
				setEverything( null );
				setPicked( new Set() );
				setReceipt( { list: 'changes', kind: 'expected', count: data.expected.count, skipped: data.expected.skipped, undo: data.expected.undo } );
			},
			( error ) => {
				// A password prompt put away leaves the question as it was asked.
				if ( error && mounted.current ) {
					setAsking( null );
					setReceipt( { list: 'changes', kind: 'refused', text: error.message || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) } );
				}

				return true;
			}
		);
	};

	/*
	 * The official copies of every match that has one, as many as one
	 * question puts back, a request at a time from where the last stopped.
	 * A file left as it was is passed over and not counted, so a run of
	 * files that cannot be put back does not use up the question. Each file
	 * keeps its own undo, and one Undo puts every displaced file back, as a
	 * selection's does.
	 */
	const restoreEverything = async ( all, most ) => {
		if ( ! claim( 'restore-chosen' ) ) {
			return;
		}

		aimAtSummary();

		const restored = [];
		const skipped = {};
		const named = {};
		let after = 0;
		let last = null;
		let failure = '';
		let more = 0;

		try {
			while ( restored.length < most ) {
				// eslint-disable-next-line no-await-in-loop
				const data = await apiFetch( {
					path: '/bettershield/v1/integrity/changes/matching/restore',
					method: 'POST',
					data: { ...filterParams( all.filter ), through: all.through, after, limit: Math.min( RESTORE_CHUNK, most - restored.length ) },
				} );

				last = data.integrity || last;
				restored.push( ...( data.restored || [] ) );
				Object.assign( skipped, data.skipped || {} );
				Object.assign( named, data.named || {} );
				more = Number( data.remaining ) || 0;

				if ( ! more ) {
					break;
				}

				// Nothing reached at all would ask the same again for ever.
				if ( Number( data.after ) === after ) {
					failure = __( 'The rest could not be restored right now. Select them and try again.', 'bettershield' );
					break;
				}

				after = Number( data.after );
			}
		} catch ( error ) {
			failure = error && error.message ? error.message : __( 'That did not complete. Nothing more on your site was changed.', 'bettershield' );
		} finally {
			release( 'restore-chosen' );
		}

		if ( ! mounted.current ) {
			return;
		}

		if ( last ) {
			takeNarrowed( last, all.filter );
		}

		if ( restored.length ) {
			loadQuarantine();
		}

		setAsking( null );
		setEverything( null );
		setPicked( new Set() );
		setReceipt( {
			list: 'changes',
			kind: 'restored',
			count: restored.length,
			left: leftLines( skipped, ( id ) => named[ id ] || String( id ) ),
			failure,
			more: failure ? 0 : more,
			tokens: restored.map( ( entry ) => entry.undo ),
		} );
	};

	const pickKept = ( tokens, on ) => {
		setAsking( null );
		setPickedKept( ( was ) => toggled( was, tokens, on ) );
	};

	/** The path a kept copy came from. */
	const keptPath = ( token ) => ( shown.current.find( ( entry ) => entry.token === token ) || { path: token } ).path;

	/** What was left as it was, with why, as lines. */
	const leftLines = ( skipped, pathOf ) =>
		Object.entries( skipped || {} ).map( ( [ key, why ] ) => ( {
			key,
			text: sprintf(
				/* translators: 1: a file's path, 2: why it was left as it was. */
				__( '%1$s: %2$s', 'bettershield' ),
				pathOf( key ),
				why
			),
		} ) );

	/** Kept entries as they now stand, laid over the list without dropping its pages. */
	const patchKept = ( items ) => {
		const now = new Map( ( items || [] ).map( ( entry ) => [ entry.token, entry ] ) );

		showQuarantined( shown.current.map( ( entry ) => ( now.has( entry.token ) ? { ...entry, ...now.get( entry.token ) } : entry ) ) );
	};

	/**
	 * Kept copies put back or removed, a request at a time through the shared
	 * layer, which can ask for the password and does so once. Resolves with
	 * what the requests did together, or null when the password was not given
	 * and nothing was sent.
	 *
	 * @param {string}   action put_back or remove.
	 * @param {string[]} tokens The copies, in order.
	 * @return {Promise<?Object>} { done, skipped, reported, items, integrity, failure }.
	 */
	const keptInTurn = async ( action, tokens ) => {
		const outcome = { done: [], skipped: {}, reported: 0, items: [], integrity: null, failure: '' };
		const parts = chunk( tokens, KEPT_AT_ONCE );

		setTurning( true );

		try {
			for ( let index = 0; index < parts.length; index++ ) {
				// eslint-disable-next-line no-await-in-loop
				const data = await new Promise( ( resolve ) =>
					quarantineBatch( action, parts[ index ], resolve, ( error ) => {
						resolve( error ? { error } : null );

						return true;
					} )
				);

				if ( null === data ) {
					return outcome.done.length ? outcome : null;
				}

				if ( data.error ) {
					outcome.failure = data.error.message || __( 'That did not complete. Nothing more was changed.', 'bettershield' );

					return outcome;
				}

				outcome.done.push( ...( data.done || [] ) );
				Object.assign( outcome.skipped, data.skipped || {} );
				outcome.reported += data.reported || 0;
				outcome.items.push( ...( data.items || [] ) );
				outcome.integrity = data.integrity || outcome.integrity;

				// The shared layer lets go of one action after its callbacks run.
				// eslint-disable-next-line no-await-in-loop
				await new Promise( ( resolve ) => setTimeout( resolve, 0 ) );
			}

			return outcome;
		} finally {
			if ( mounted.current ) {
				setTurning( false );
			}
		}
	};

	const markChosenExpected = ( rows ) => {
		const ids = rows.map( ( row ) => row.id );

		aimAtSummary();
		fromQuarantine.current = false;

		markChangesExpected(
			ids,
			( data ) => {
				if ( ! data || ! mounted.current ) {
					return;
				}

				if ( data.integrity ) {
					setReport( data.integrity );
				}

				setAsking( null );
				setPicked( ( was ) => toggled( was, ids, false ) );
				setReceipt( { list: 'changes', kind: 'expected', count: data.expected.count, skipped: data.expected.skipped, undo: data.expected.undo } );
			},
			( error ) => {
				// A password prompt put away leaves the question as it was asked.
				if ( error && mounted.current ) {
					setAsking( null );
					setReceipt( { list: 'changes', kind: 'refused', text: error.message || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) } );
				}

				return true;
			}
		);
	};

	const undoExpected = ( outcome ) =>
		unmarkChangesExpected( outcome.undo, ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			setReceipt( { list: 'changes', kind: 'returned', count: data.returned || 0 } );
		} );

	/*
	 * The official copies of the picked files that have one, a request at a
	 * time: each is a request to WordPress.org, so the site puts back as many
	 * as it can in one request and hands the rest back. One question covered
	 * all of them.
	 */
	const restoreChosen = async ( rows ) => {
		if ( ! claim( 'restore-chosen' ) ) {
			return;
		}

		aimAtSummary();

		const pathOf = ( id ) => ( rows.find( ( row ) => String( row.id ) === String( id ) ) || { path: String( id ) } ).path;
		const restored = [];
		const skipped = {};
		let queue = rows.map( ( row ) => row.id );
		let last = null;
		let failure = '';

		try {
			while ( queue.length ) {
				const ask = queue.slice( 0, RESTORE_CHUNK );
				// eslint-disable-next-line no-await-in-loop
				const data = await apiFetch( { path: '/bettershield/v1/integrity/changes/restore', method: 'POST', data: { ids: ask } } );
				const behind = ( data.left || [] ).map( Number );

				last = data.integrity || last;
				restored.push( ...( data.restored || [] ) );
				Object.assign( skipped, data.skipped || {} );

				// Nothing reached at all would ask the same again for ever.
				if ( behind.length === ask.length ) {
					failure = __( 'The rest could not be restored right now. They are still selected, so you can try again.', 'bettershield' );
					break;
				}

				queue = [ ...behind, ...queue.slice( ask.length ) ];
			}
		} catch ( error ) {
			failure = error && error.message ? error.message : __( 'That did not complete. Nothing more on your site was changed.', 'bettershield' );
		} finally {
			release( 'restore-chosen' );
		}

		if ( ! mounted.current ) {
			return;
		}

		if ( last ) {
			setReport( last );
		}

		if ( restored.length ) {
			loadQuarantine();
		}

		setAsking( null );
		setPicked( ( was ) => toggled( was, restored.map( ( entry ) => entry.change_id ), false ) );
		setReceipt( { list: 'changes', kind: 'restored', count: restored.length, left: leftLines( skipped, pathOf ), failure, tokens: restored.map( ( entry ) => entry.undo ) } );
	};

	// The files that were there, back: each restore's own undo, through the
	// quarantine list's own route.
	const undoRestored = async ( outcome ) => {
		const back = await keptInTurn( 'put_back', outcome.tokens );

		if ( ! mounted.current || null === back ) {
			return;
		}

		patchKept( back.items );

		if ( back.integrity ) {
			setReport( back.integrity );
		}

		setReceipt( { list: 'changes', kind: 'restore_undone', count: back.done.length, left: leftLines( back.skipped, keptPath ), failure: back.failure } );
	};

	const keptAction = async ( kind, entries ) => {
		aimAtSummary();
		setQuarantineNote( null );
		fromQuarantine.current = false;

		const outcome = await keptInTurn( kind, entries.map( ( entry ) => entry.token ) );

		if ( ! mounted.current || null === outcome ) {
			return;
		}

		patchKept( outcome.items );

		if ( outcome.integrity ) {
			setReport( outcome.integrity );
		}

		setAsking( null );
		setPickedKept( ( was ) => toggled( was, outcome.done, false ) );
		setReceipt( { list: 'kept', kind, count: outcome.done.length, reported: outcome.reported, left: leftLines( outcome.skipped, keptPath ), failure: outcome.failure } );
	};

	const dismissReceipt = () => {
		setReceipt( null );
		window.requestAnimationFrame( () => focusIfLost( summaryHeading.current ) );
	};

	/*
	 * Adopting quiets a difference rather than putting anything back, so it
	 * goes through the shared layer for the same reason the others do: the
	 * site may ask for the password first, and a refusal resolves null with
	 * the field already on its way.
	 */
	const adoptThisCopy = ( item ) => {
		aimAtSummary();
		fromQuarantine.current = false;

		adoptPackage( item.slug, item.version, afterMutation( ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			const said = __( 'Trusted. You won’t be alerted about this version unless one of its files changes.', 'bettershield' );

			// With the sentence it is offered beside: see the banner.
			if ( data.adopted ) {
				setAdopted( { slug: data.adopted.slug, token: data.adopted.undo, said } );
			}

			setDone( said );
		} ) );
	};

	const withdrawAdoption = ( item ) => {
		aimAtSummary();
		fromQuarantine.current = false;

		undoPackageAdoption( item.slug, item.token, afterMutation( ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			setAdopted( null );
			setDone( __( 'Undone. This plugin is listed again.', 'bettershield' ) );
		} ) );
	};

	/**
	 * The row that should hold focus once this one is gone: the one after it,
	 * or the one before it when it is last. Decided now, while the list still
	 * says where this row stands.
	 *
	 * @param {number} id The row about to be resolved.
	 */
	const aimAfter = ( id ) => {
		const order = screenOrder( report?.changes || [] );
		const at = order.indexOf( id );

		wantedRow.current = order[ at + 1 ] || order[ at - 1 ] || null;
	};

	/**
	 * The group a row stands in now, read before it is resolved away.
	 *
	 * @param {number} id A row.
	 * @return {?string} The group's key.
	 */
	const groupOf = ( id ) => {
		const group = groupChanges( report?.changes || [] ).find( ( candidate ) => candidate.changes.some( ( change ) => change.id === id ) );

		return group ? group.key : null;
	};

	/**
	 * Say a row's outcome in its group while the group is still on screen,
	 * and in the slot at the top when it went with the row — which is where
	 * focus goes then.
	 *
	 * @param {?string} group   The row's group.
	 * @param {Object}  after   The report as it stands now.
	 * @param {string}  text    What happened.
	 * @param {string}  tone    status or alert.
	 */
	const sayForRow = ( group, after, text, tone = 'status' ) => {
		const stays = group && groupChanges( ( after && after.changes ) || [] ).some( ( candidate ) => candidate.key === group );

		if ( stays ) {
			setDone( null );
			setNotice( null );
			setRowNote( { group, tone, text } );

			return;
		}

		setRowNote( null );

		if ( 'alert' === tone ) {
			setNotice( text );
		} else {
			setDone( text );
		}
	};

	const suppressChange = ( item ) => {
		fromQuarantine.current = false;
		aimAfter( item.id );

		const group = groupOf( item.id );

		markChangeExpected( item.id, afterMutation( ( data ) => {
			if ( data.integrity ) {
				setReport( data.integrity );
			}
			sayForRow(
				group,
				data.integrity,
				group && groupChanges( ( data.integrity && data.integrity.changes ) || [] ).some( ( candidate ) => candidate.key === group )
					? sprintf(
							/* translators: %s: the file's path. */
							__( 'Accepted: %s. You’ll see it again only if the file changes again.', 'bettershield' ),
							item.path
					  )
					: __( 'Accepted. You’ll see it again only if the file changes again.', 'bettershield' )
			);
		} ) );
	};

	/*
	 * A file that can run as code is asked about first, as the same file in a
	 * selection is: one press on its row silenced a critical arrival with no
	 * word about what it was (#2247).
	 */
	const acceptChange = ( item ) => {
		if ( item.can_run ) {
			setAsking( { list: 'changes', kind: 'expected', rows: [ item ], single: true } );
			return;
		}

		suppressChange( item );
	};

	/*
	 * Marking a change expected hides it from the list above, so taking that
	 * back has to happen somewhere else: here, beside the list of what was
	 * marked. It goes back to being reported as it was before.
	 */
	const stopExpecting = ( item ) => {
		stopExpectingChange( item.id, afterMutation( ( data ) => {
			if ( data.integrity ) {
				setReport( data.integrity );
			}
			setDone( __( 'It’s back in the list of changes to review.', 'bettershield' ) );
		} ) );
	};

	/** One group's identity: a plugin or theme at one recorded version. */
	const packageKey = ( pkg ) => `${ pkg.context }:${ pkg.slug }:${ pkg.version }`;

	/*
	 * Asked before anything is marked, and the count and the digest of the
	 * rows it shows go back with the marking: a group that has grown, shrunk
	 * or swapped a row since is refused, so the one confirmation covers
	 * exactly what it was shown.
	 */
	const previewPackage = ( pkg ) => {
		const key = `preview-${ packageKey( pkg ) }`;

		if ( packagePreview?.key === packageKey( pkg ) ) {
			setPackagePreview( null );
			return;
		}

		if ( ! claim( key ) ) {
			return;
		}

		setNotice( null );

		apiFetch( {
			path: `/bettershield/v1/integrity/packages/${ pkg.slug }/preview`,
			method: 'POST',
			data: { context: pkg.context, version: pkg.version },
		} )
			.then( ( data ) => {
				if ( mounted.current ) {
					setPackagePreview( { key: packageKey( pkg ), data } );
				}
			} )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error && error.message ? error.message : __( 'The preview could not be loaded. Nothing was changed.', 'bettershield' ) );
				}
			} )
			.finally( () => release( key ) );
	};

	const expectPackage = ( pkg ) => {
		const preview = packagePreview?.data;

		if ( ! preview ) {
			return;
		}

		aimAtSummary();
		fromQuarantine.current = false;

		markPackageExpected( pkg.slug, pkg.context, pkg.version, preview.total, preview.digest, afterMutation( ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			setPackagePreview( null );
			setDone(
				sprintf(
					/* translators: %s: number of changes. */
					_n(
						'Accepted %s change. To undo, use “Accepted in bulk” below.',
						'Accepted %s changes. To undo, use “Accepted in bulk” below.',
						data.expected?.count || preview.total,
						'bettershield'
					),
					formatCount( data.expected?.count || preview.total )
				)
			);
		} ) );
	};

	/*
	 * Compared a request at a time until every open row of the plugin has
	 * been looked at: a large plugin does not fit in one, and each answer
	 * carries where the next begins.
	 */
	const recheckPackage = ( pkg ) => {
		const key = `recheck-${ packageKey( pkg ) }`;

		if ( ! claim( key ) ) {
			return;
		}

		aimAtSummary();
		setNotice( null );

		let checked = 0;
		let closed = 0;

		const step = ( after ) =>
			apiFetch( {
				path: `/bettershield/v1/integrity/packages/${ pkg.slug }/recheck`,
				method: 'POST',
				data: { after },
			} ).then( ( data ) => {
				checked += data.rechecked.checked;
				closed += data.rechecked.closed;

				if ( mounted.current && data.integrity ) {
					setReport( data.integrity );
				}

				return data.rechecked.left > 0 && data.rechecked.after > 0 && mounted.current ? step( data.rechecked.after ) : data;
			} );

		step( 0 )
			.then( afterMutation( ( data ) => {
				if ( ! mounted.current ) {
					return;
				}

				setDone(
					sprintf(
						/* translators: 1: what was compared, e.g. "Compared 3 changed files in Akismet with the official version 5.3."; 2: how many matched, e.g. "2 now match and were removed from the list." */
						__( '%1$s %2$s', 'bettershield' ),
						sprintf(
							/* translators: 1: open changes compared, 2: a plugin name, 3: the version compared against. */
							_n(
								'Compared %1$s changed file in %2$s with the official version %3$s.',
								'Compared %1$s changed files in %2$s with the official version %3$s.',
								checked,
								'bettershield'
							),
							formatCount( checked ),
							pkg.name,
							data.rechecked.version
						),
						// "0 matched and are closed" read as if something was closed, so
						// none matching is its own sentence: what was compared stays open.
						0 === closed
							? sprintf(
								/* translators: %s: how many changes were compared, none of which matched the published version. */
								_n( '%s still doesn’t match, so it stays in the list.', 'None of the %s match yet, so they stay in the list.', checked, 'bettershield' ),
								formatCount( checked )
							  )
							: sprintf(
								/* translators: %s: how many of the compared changes matched the published version. */
								_n( '%s now matches and was removed from the list.', '%s now match and were removed from the list.', closed, 'bettershield' ),
								formatCount( closed )
							  )
					)
				);
			} ) )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error && error.message ? error.message : __( 'That did not complete. Nothing on your site was changed.', 'bettershield' ) );
				}
			} )
			.finally( () => release( key ) );
	};

	const unmarkBatch = ( batch ) => {
		aimAtSummary();
		fromQuarantine.current = false;

		const after = afterMutation( ( data ) => {
			if ( ! data || ! mounted.current ) {
				return;
			}

			if ( data.integrity ) {
				setReport( data.integrity );
			}

			setDone(
				sprintf(
					/* translators: %s: number of changes. */
					_n( '%s change is back in the list.', '%s changes are back in the list.', data.returned || 0, 'bettershield' ),
					formatCount( data.returned || 0 )
				)
			);
		} );

		// A selection names no plugin, so it is taken back by its own route.
		if ( 'selection' === batch.context ) {
			unmarkChangesExpected( batch.undo, after );

			return;
		}

		unmarkPackageExpected( batch.slug, batch.undo, after );
	};

	const act = ( path, key, outcome, then, row = null ) => {
		// Through the same guard the other handlers use. Reading the
		// render-scope set instead saw a stale copy between two clicks landing
		// in one tick, which is the race the mirror above exists for.
		if ( ! claim( key ) ) {
			return;
		}

		setNotice( null );

		/*
		 * The check is a scan and its button sweeps like one, so the button
		 * is held for one full pass — see ui/hold.js — and nothing else is.
		 * Held with the request, the check's result reached the screen three
		 * seconds after the server gave it (#1781), as the store's own act()
		 * once did. The answer is shown when it arrives; only the button's
		 * working state waits for the sweep to finish.
		 */
		const floor = atLeast( Promise.resolve(), 'scan' === key ? SCAN_HOLD : 0 );
		let succeeded = false;

		apiFetch( { path, method: 'POST' } )
			.then( afterMutation( ( data ) => {
				succeeded = true;

				if ( ! mounted.current ) {
					return;
				}

				if ( data.integrity ) {
					setReport( data.integrity );
				} else {
					setReport( data );
				}

				if ( outcome && row ) {
					sayForRow( row.group, data.integrity || data, row.said );
				} else if ( outcome ) {
					setDone( outcome );
				}
				if ( then ) {
					then();
				}
			} ) )
			.catch( ( error ) => {
				if ( mounted.current && row ) {
					// Refused, the row is still there, and so is its group.
					sayForRow( row.group, report, error && error.message ? error.message : __( 'That did not complete. Nothing on your site was changed.', 'bettershield' ), 'alert' );
				} else if ( mounted.current ) {
					setNotice(
						error && error.message
							? error.message
							: __( 'That did not complete. Nothing on your site was changed.', 'bettershield' )
					);
				}
			} )
			.finally( () => {
				// Outside the mounted guard: release() handles an unmounted
				// screen itself, and leaving the key claimed would keep the
				// control disabled for the life of the page. A refusal is not
				// held: it arrives when it arrives.
				( succeeded ? floor : Promise.resolve() ).then( () => release( key ) );
			} );
	};

	const moreChanges = () => {
		if ( ! report?.next_cursor || ! claim( 'more-changes' ) ) {
			return;
		}
		const snapshot = report;
		setNotice( null );
		apiFetch( { path: '/bettershield/v1/integrity' + filterQuery( filterNow.current, { cursor: report.next_cursor } ) } )
			.then( afterMutation( ( next ) => {
				if ( ! mounted.current ) {
					return;
				}
				// A scan's end or a decision replaces the rows. Discard a late
				// page then, instead of reintroducing rows just resolved. A
				// progress answer leaves the rows as they were, and the page
				// is still the next one.
				setReport( ( current ) =>
					current.changes !== snapshot.changes
						? current
						: { ...next, changes: [ ...current.changes, ...next.changes ].filter( ( row, index, all ) => all.findIndex( ( other ) => other.id === row.id ) === index ) }
				);
			} ) )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error.message );
				}
			} )
			.finally( () => release( 'more-changes' ) );
	};

	/*
	 * The list marked expected, a page at a time, the same way: the count is
	 * of all of them, and each press brings the next page in behind the ones
	 * already shown.
	 */
	const moreExpected = () => {
		if ( ! report?.suppressed_next || ! claim( 'more-expected' ) ) {
			return;
		}
		const snapshot = report;
		setNotice( null );
		// Through afterMutation, as the changes' own pages are: the button goes
		// with the last page, and focus would go with it (#2028).
		apiFetch( { path: `/bettershield/v1/integrity/expected?cursor=${ encodeURIComponent( report.suppressed_next ) }` } )
			.then( afterMutation( ( next ) => {
				if ( ! mounted.current ) {
					return;
				}
				// The same: only the list this extends being replaced makes
				// the page stale.
				setReport( ( current ) =>
					current.suppressed !== snapshot.suppressed
						? current
						: {
								...current,
								suppressed: [ ...( current.suppressed || [] ), ...next.changes ].filter( ( row, index, all ) => all.findIndex( ( other ) => other.id === row.id ) === index ),
								suppressed_next: next.next_cursor,
								suppressed_total: next.total,
						  }
				);
			} ) )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error.message );
				}
			} )
			.finally( () => release( 'more-expected' ) );
	};

	// The markings made a group at a time, a page at a time the same way.
	const moreBatches = () => {
		if ( ! report?.batches_next || ! claim( 'more-batches' ) ) {
			return;
		}
		const snapshot = report;
		setNotice( null );
		apiFetch( { path: `/bettershield/v1/integrity/batches?cursor=${ encodeURIComponent( report.batches_next ) }` } )
			.then( afterMutation( ( next ) => {
				if ( ! mounted.current ) {
					return;
				}
				// The same: a running check's progress answer leaves the
				// groups as they were, and the page is still the next one.
				setReport( ( current ) =>
					current.batches !== snapshot.batches
						? current
						: {
								...current,
								batches: [ ...( current.batches || [] ), ...next.batches ].filter( ( row, index, all ) => all.findIndex( ( other ) => other.undo === row.undo ) === index ),
								batches_next: next.next_cursor,
								batches_total: next.total,
						  }
				);
			} ) )
			.catch( ( error ) => {
				if ( mounted.current ) {
					setNotice( error.message );
				}
			} )
			.finally( () => release( 'more-batches' ) );
	};

	if ( status === 'loading' ) {
		return <FilesBone />;
	}

	if ( status === 'error' || ! report ) {
		return <ErrorState onRetry={ load } />;
	}

	// All of them, not the page loaded so far; a report from before the total
	// was sent counts what it carries.
	const expectedTotal = Math.max( Number( report.suppressed_total ) || 0, ( report.suppressed || [] ).length );
	const batchesTotal = Math.max( Number( report.batches_total ) || 0, ( report.batches || [] ).length );

	// One state at a time. While a check runs it says so, with its bar and
	// count; the time of the last finished check comes back when it ends.
	// Both at once read as two states competing for the same line.
	let checkState = __( 'Never checked', 'bettershield' );

	if ( report.running ) {
		checkState = __( 'Checking files', 'bettershield' );
	} else if ( report.ever_run ) {
		checkState = sprintf(
			/* translators: %s: date and time. */
			__( 'Last checked %s', 'bettershield' ),
			formatTime( report.last_run_at )
		);
	}

	const changes = report.changes || [];
	const packages = report.packages || [];
	// WordPress core's own changed files, said first: under one plugin's
	// many rows a changed core file was row 256 with no summary (#2118).
	const core = report.core || null;
	const batches = report.batches || [];
	const suppressed = report.suppressed || [];
	const batchWorking = turning || isBusy( 'changes-batch' ) || isBusy( 'restore-chosen' ) || isBusy( 'quarantine-batch' ) || Boolean( receipt && receipt.undo && isBusy( `batch-${ receipt.undo }` ) );
	const chosen = choosing ? changes.filter( ( change ) => selectableChange( change ) && picked.has( change.id ) ) : [];
	const filtered = isFiltered( filter );
	// How many match, on every page: the filter's count, or every open
	// change but the packages' own differences, which cannot be picked.
	const matchingTotal = filtered ? Number( report.matching ) || 0 : Math.max( 0, ( Number( report.open_changes?.total ) || 0 ) - ( Number( report.open_changes?.packages ) || 0 ) );
	const keptChosen = choosing ? quarantined.filter( ( entry ) => entry.present && pickedKept.has( entry.token ) ) : [];

	/** The checkbox that picks every loaded row of a group, or null. */
	const groupPick = ( group ) => {
		const ids = choosing ? group.changes.filter( selectableChange ).map( ( change ) => change.id ) : [];

		if ( ! ids.length ) {
			return null;
		}

		const on = everything ? ids.length : ids.filter( ( id ) => picked.has( id ) ).length;
		// More of the group than is loaded: every loaded one picked is still
		// not the whole group, and the box said it was (#2058).
		const total = groupCount( group, changes, report );
		const partial = ! everything && Number.isInteger( total ) && total > ids.length;

		return {
			label: partial
				? sprintf(
						/* translators: 1: how many changes of the group are loaded, 2: the group's name. */
						_n( 'Select the %1$d loaded change in %2$s', 'Select the %1$d loaded changes in %2$s', ids.length, 'bettershield' ),
						ids.length,
						group.label
				  )
				: sprintf(
						/* translators: 1: how many changes the group holds on screen, 2: the group's name. */
						_n( 'Select the %1$d change in %2$s', 'Select all %1$d changes in %2$s', ids.length, 'bettershield' ),
						ids.length,
						group.label
				  ),
			state: on === ids.length ? ! partial || 'mixed' : on > 0 && 'mixed',
			onChange: () => pickChanges( ids, on !== ids.length ),
		};
	};

	const questionFor = ( ask ) => {
		const n = ask.rows.length;

		if ( 'expected_all' === ask.kind ) {
			const all = ask.all;

			return {
				/* translators: %s: how many file changes match. */
				title: sprintf( _n( 'Accept %s matching file change?', 'Accept all %s matching file changes?', all.total, 'bettershield' ), formatCount( all.total ) ),
				desc: sprintf(
					/* translators: %s: the changes by kind, e.g. "8 altered, 3 not published, 1 missing". */
					_n(
						'This matching change is hidden until the file changes again. You can undo it.',
						'%s, on every page. Each is hidden until its file changes again. One Undo brings them all back.',
						all.total,
						'bettershield'
					),
					selectionPhrase( all )
				),
				namesLead: sprintf(
					/* translators: %s: number of added files that can run as code. */
					_n( '%s added file is a script that could run on your site. Look at it before you accept:', '%s added files are scripts that could run on your site. Look at them before you accept:', all.added_code_total, 'bettershield' ),
					formatCount( all.added_code_total )
				),
				names: ( all.added_code || [] ).slice( 0, NAMED_CODE ),
				more:
					all.added_code_total > Math.min( NAMED_CODE, ( all.added_code || [] ).length )
						? sprintf(
								/* translators: %s: number of added code files not listed. */
								_n( 'And %s more.', 'And %s more.', all.added_code_total - Math.min( NAMED_CODE, ( all.added_code || [] ).length ), 'bettershield' ),
								formatCount( all.added_code_total - Math.min( NAMED_CODE, ( all.added_code || [] ).length ) )
						  )
						: '',
				/* translators: %s: how many file changes. */
				confirm: sprintf( _n( 'Accept %s', 'Accept %s', all.total, 'bettershield' ), formatCount( all.total ) ),
				onConfirm: () => markEverythingExpected( all ),
			};
		}

		if ( 'restore_all' === ask.kind ) {
			const left = ask.all.total - ask.all.restorable;

			return {
				/* translators: %s: how many files. */
				title: sprintf( _n( 'Put back the official copy of %s file?', 'Put back the official copies of %s files?', ask.most, 'bettershield' ), formatCount( ask.most ) ),
				desc: [
					__( 'Each is downloaded from WordPress.org and verified. The current file is quarantined first and can be put back.', 'bettershield' ),
					left
						? sprintf(
								/* translators: %s: how many selected files have no official copy. */
								_n( '%s selected file has no official copy and is left alone.', '%s selected files have no official copy and are left alone.', left, 'bettershield' ),
								formatCount( left )
						  )
						: '',
				]
					.filter( Boolean )
					.join( ' ' ),
				/* translators: %s: how many files. */
				confirm: sprintf( _n( 'Put Back %s', 'Put Back %s', ask.most, 'bettershield' ), formatCount( ask.most ) ),
				onConfirm: () => restoreEverything( ask.all, ask.most ),
			};
		}

		if ( 'expected' === ask.kind ) {
			const counts = selectionCounts( ask.rows );

			return {
				/* translators: %s: how many file changes. */
				title: sprintf( _n( 'Accept %s file change?', 'Accept %s file changes?', n, 'bettershield' ), formatCount( n ) ),
				desc: sprintf(
					/* translators: %s: the changes by kind, e.g. "8 altered, 3 not published, 1 missing". */
					_n(
						'This change is hidden until the file changes again. You can undo it.',
						'%s. Each is hidden until its file changes again. One Undo brings them all back.',
						n,
						'bettershield'
					),
					selectionPhrase( counts )
				),
				namesLead: sprintf(
					/* translators: %s: number of added files that can run as code. */
					_n( '%s added file is a script that could run on your site. Look at it before you accept:', '%s added files are scripts that could run on your site. Look at them before you accept:', counts.code.length, 'bettershield' ),
					formatCount( counts.code.length )
				),
				names: counts.code.slice( 0, NAMED_CODE ),
				more:
					counts.code.length > NAMED_CODE
						? sprintf(
								/* translators: %s: number of added code files not listed. */
								_n( 'And %s more.', 'And %s more.', counts.code.length - NAMED_CODE, 'bettershield' ),
								formatCount( counts.code.length - NAMED_CODE )
						  )
						: '',
				/* translators: %s: how many file changes. */
				confirm: sprintf( _n( 'Accept %s', 'Accept %s', n, 'bettershield' ), formatCount( n ) ),
				// One row's own Accept goes the way it always went, once asked (#2247).
				onConfirm: ask.single
					? () => {
							setAsking( null );
							suppressChange( ask.rows[ 0 ] );
					  }
					: () => markChosenExpected( ask.rows ),
			};
		}

		if ( 'restore' === ask.kind ) {
			return {
				/* translators: %s: how many files. */
				title: sprintf( _n( 'Put back the official copy of %s file?', 'Put back the official copies of %s files?', n, 'bettershield' ), formatCount( n ) ),
				desc: [
					__( 'Each is downloaded from WordPress.org and verified. The current file is quarantined first and can be put back.', 'bettershield' ),
					ask.skipped
						? sprintf(
								/* translators: %s: how many selected files have no official copy. */
								_n( '%s selected file has no official copy and is left alone.', '%s selected files have no official copy and are left alone.', ask.skipped, 'bettershield' ),
								formatCount( ask.skipped )
						  )
						: '',
				]
					.filter( Boolean )
					.join( ' ' ),
				/* translators: %s: how many files. */
				confirm: sprintf( _n( 'Put Back %s', 'Put Back %s', n, 'bettershield' ), formatCount( n ) ),
				onConfirm: () => restoreChosen( ask.rows ),
			};
		}

		if ( 'put_back' === ask.kind ) {
			const code = ask.rows.filter( ( row ) => row.code ).length;

			return {
				/* translators: %s: how many files. */
				title: sprintf( _n( 'Put %s file back?', 'Put %s files back?', n, 'bettershield' ), formatCount( n ) ),
				desc: [
					_n(
						'It goes back as it was, and a copy stays here. If it was changed or deleted since, it is skipped.',
						'Each file goes back as it was, and a copy stays here. Files that were changed or deleted since are skipped.',
						n,
						'bettershield'
					),
					// Said as the single row says it (#2244).
					code
						? sprintf(
								/* translators: %s: how many of the files hold changed code. */
								_n( '%s of them contains changed code that BetterShield removed. Putting it back lets that code run again.', '%s of them contain changed code that BetterShield removed. Putting them back lets that code run again.', code, 'bettershield' ),
								formatCount( code )
						  )
						: '',
				]
					.filter( Boolean )
					.join( ' ' ),
				/* translators: %s: how many files. */
				confirm: sprintf( _n( 'Put %s Back', 'Put %s Back', n, 'bettershield' ), formatCount( n ) ),
				onConfirm: () => keptAction( 'put_back', ask.rows ),
			};
		}

		return {
			/* translators: %s: how many kept copies. */
			title: sprintf( _n( 'Remove %s copy for good?', 'Remove %s copies for good?', n, 'bettershield' ), formatCount( n ) ),
			desc: _n(
				'It is deleted and cannot be brought back. The activity log keeps a record of it.',
				'They are deleted and cannot be brought back. The activity log keeps a record of each.',
				n,
				'bettershield'
			),
			/* translators: %s: how many kept copies. */
			confirm: sprintf( _n( 'Remove %s for Good', 'Remove %s for Good', n, 'bettershield' ), formatCount( n ) ),
			onConfirm: () => keptAction( 'remove', ask.rows ),
		};
	};

	const answerFor = ( outcome ) => {
		const tail = ( lines ) => lines.filter( Boolean ).join( ' ' );
		const warn = ( outcome.left && outcome.left.length ) || outcome.failure ? 'warning' : 'success';

		switch ( outcome.kind ) {
			case 'expected':
				return {
					/* translators: %s: how many file changes. */
					title: sprintf( _n( '%s file change accepted.', '%s file changes accepted.', outcome.count, 'bettershield' ), formatCount( outcome.count ) ),
					desc: tail( [
						__( 'They’re hidden until their files change. Undo brings them all back.', 'bettershield' ),
						outcome.skipped
							? sprintf(
									/* translators: %s: how many selected changes had been dealt with already. */
									_n( '%s selected change was already restored or accepted, so it was skipped.', '%s selected changes were already restored or accepted, so they were skipped.', outcome.skipped, 'bettershield' ),
									formatCount( outcome.skipped )
							  )
							: '',
					] ),
					undoLabel: __( 'Undo', 'bettershield' ),
					onUndo: () => undoExpected( outcome ),
				};
			case 'returned':
				/* translators: %s: number of changes. */
				return { title: sprintf( _n( '%s change is back in the list.', '%s changes are back in the list.', outcome.count, 'bettershield' ), formatCount( outcome.count ) ) };
			case 'restored':
				return {
					tone: warn,
					title: outcome.count
						? sprintf(
								/* translators: %s: how many files. */
								_n( 'Put back the official copy of %s file.', 'Put back the official copies of %s files.', outcome.count, 'bettershield' ),
								formatCount( outcome.count )
						  )
						: __( 'No file was put back.', 'bettershield' ),
					desc: tail( [
						outcome.count ? __( 'The files that were there are kept in quarantine, below.', 'bettershield' ) : '',
						outcome.more
							? sprintf(
									/* translators: %s: how many more matching files have an official copy. */
									_n( '%s more matching file has an official copy. Select all again to put it back.', '%s more matching files have official copies. Select all again to put them back.', outcome.more, 'bettershield' ),
									formatCount( outcome.more )
							  )
							: '',
						outcome.left.length ? __( 'Left as they were:', 'bettershield' ) : '',
						outcome.failure,
					] ),
					left: outcome.left,
					undoLabel: outcome.tokens.length ? __( 'Undo Restore', 'bettershield' ) : '',
					onUndo: () => undoRestored( outcome ),
				};
			case 'restore_undone':
				return {
					tone: warn,
					title: sprintf(
						/* translators: %s: how many files. */
						_n( 'Undone. Your previous %s file is back.', 'Undone. Your previous %s files are back.', outcome.count, 'bettershield' ),
						formatCount( outcome.count )
					),
					desc: tail( [ outcome.count ? __( 'They are listed again under changed files.', 'bettershield' ) : '', outcome.left.length ? __( 'Left as they were:', 'bettershield' ) : '', outcome.failure ] ),
					left: outcome.left,
				};
			case 'put_back':
				return {
					tone: warn,
					title: outcome.count
						? sprintf(
								/* translators: %s: how many files. */
								_n( '%s file is put back as it was.', '%s files are put back as they were.', outcome.count, 'bettershield' ),
								formatCount( outcome.count )
						  )
						: __( 'No file was put back.', 'bettershield' ),
					desc: tail( [
						outcome.reported
							? sprintf(
									/* translators: %s: how many files are listed again. */
									_n( '%s is listed again under changed files.', '%s are listed again under changed files.', outcome.reported, 'bettershield' ),
									formatCount( outcome.reported )
							  )
							: '',
						outcome.count ? __( 'Each copy is still kept here.', 'bettershield' ) : '',
						outcome.left.length ? __( 'Left as they were:', 'bettershield' ) : '',
						outcome.failure,
					] ),
					left: outcome.left,
				};
			case 'remove':
				return {
					tone: warn,
					title: outcome.count
						? sprintf(
								/* translators: %s: how many kept copies. */
								_n( '%s copy removed for good.', '%s copies removed for good.', outcome.count, 'bettershield' ),
								formatCount( outcome.count )
						  )
						: __( 'No copy was removed.', 'bettershield' ),
					desc: tail( [
						outcome.count ? _n( 'The record that it existed stays in the activity log.', 'The record that each existed stays in the activity log.', outcome.count, 'bettershield' ) : '',
						outcome.left.length ? __( 'Left as they were:', 'bettershield' ) : '',
						outcome.failure,
					] ),
					left: outcome.left,
				};
			default:
				return { tone: 'error', title: outcome.text };
		}
	};

	const changeBar = ( rows ) => {
		const restorable = rows.filter( ( change ) => change.restorable );

		return {
			/* translators: %s: how many changes are selected. */
			said: sprintf( _n( '%s change selected', '%s changes selected', rows.length, 'bettershield' ), formatCount( rows.length ) ),
			detail: selectionPhrase( selectionCounts( rows ) ),
			actions: [
				{
					key: 'expected',
					/* translators: %s: how many changes are selected. */
					label: sprintf( _n( 'Accept %s', 'Accept %s', rows.length, 'bettershield' ), formatCount( rows.length ) ),
					disabled: rows.length > MARK_AT_ONCE,
					/* translators: %s: the most changes marked at once. */
					why: sprintf( __( 'You can accept up to %s at a time.', 'bettershield' ), formatCount( MARK_AT_ONCE ) ),
					onClick: () => setAsking( { list: 'changes', kind: 'expected', rows } ),
				},
				/*
				 * Past the most one question puts back, the first of them go,
				 * and the rest stay selected for the next press: disabled, the
				 * obvious path (select the group, put back) went nowhere
				 * (#2058).
				 */
				restorable.length > RESTORE_AT_ONCE
					? {
							key: 'restore',
							label: sprintf(
								/* translators: 1: the most files put back at once, 2: how many selected files have an official copy. */
								__( 'Restore the First %1$s of %2$s Files', 'bettershield' ),
								formatCount( RESTORE_AT_ONCE ),
								formatCount( restorable.length )
							),
							onClick: () => setAsking( { list: 'changes', kind: 'restore', rows: restorable.slice( 0, RESTORE_AT_ONCE ), skipped: rows.length - restorable.length } ),
					  }
					: null,
				restorable.length && restorable.length <= RESTORE_AT_ONCE
					? {
							key: 'restore',
							/* translators: %s: how many selected files have an official copy. */
							label: sprintf( _n( 'Put Back %s Official Copy', 'Put Back %s Official Copies', restorable.length, 'bettershield' ), formatCount( restorable.length ) ),
							onClick: () => setAsking( { list: 'changes', kind: 'restore', rows: restorable, skipped: rows.length - restorable.length } ),
					  }
					: null,
				// More match than are loaded: every one of them, on every page.
				report.next_cursor
					? {
							key: 'everything',
							label: sprintf(
								/* translators: %s: how many open changes match. */
								__( 'Select All %s Matching Changes', 'bettershield' ),
								formatCount( matchingTotal )
							),
							disabled: isBusy( 'matching' ),
							onClick: selectEverything,
					  }
					: null,
			].filter( Boolean ),
			onClear: () => {
				setAsking( null );
				setPicked( new Set() );
			},
		};
	};

	// Every change the filter matches, counted by the site rather than read
	// off the rows loaded.
	const everythingBar = ( all ) => {
		const most = Math.min( all.restorable, RESTORE_AT_ONCE );

		return {
			/* translators: %s: how many changes are selected. */
			said: sprintf( _n( 'All %s matching change selected', 'All %s matching changes selected', all.total, 'bettershield' ), formatCount( all.total ) ),
			detail: selectionPhrase( all ),
			actions: [
				{
					key: 'expected',
					/* translators: %s: how many changes are selected. */
					label: sprintf( _n( 'Accept %s', 'Accept %s', all.total, 'bettershield' ), formatCount( all.total ) ),
					disabled: all.total > MATCHING_AT_ONCE,
					/* translators: %s: the most changes marked at once. */
					why: sprintf( __( 'You can accept up to %s at a time. Use the filters to select fewer.', 'bettershield' ), formatCount( MATCHING_AT_ONCE ) ),
					onClick: () => setAsking( { list: 'changes', kind: 'expected_all', rows: [], all } ),
				},
				all.restorable
					? {
							key: 'restore',
							label:
								all.restorable > RESTORE_AT_ONCE
									? sprintf(
											/* translators: 1: the most files put back at once, 2: how many selected files have an official copy. */
											__( 'Restore the First %1$s of %2$s Files', 'bettershield' ),
											formatCount( RESTORE_AT_ONCE ),
											formatCount( all.restorable )
									  )
									: sprintf(
											/* translators: %s: how many selected files have an official copy. */
											_n( 'Put Back %s Official Copy', 'Put Back %s Official Copies', all.restorable, 'bettershield' ),
											formatCount( all.restorable )
									  ),
							onClick: () => setAsking( { list: 'changes', kind: 'restore_all', rows: [], all, most } ),
					  }
					: null,
			].filter( Boolean ),
			onClear: () => {
				setAsking( null );
				setEverything( null );
				setPicked( new Set() );
			},
		};
	};

	const keptBar = ( entries ) => {
		const back = entries.filter( ( entry ) => ! entry.restored );

		return {
			/* translators: %s: how many kept copies are selected. */
			said: sprintf( _n( '%s copy selected', '%s copies selected', entries.length, 'bettershield' ), formatCount( entries.length ) ),
			actions: [
				back.length
					? {
							key: 'put_back',
							/* translators: %s: how many files. */
							label: sprintf( _n( 'Put %s File Back', 'Put %s Files Back', back.length, 'bettershield' ), formatCount( back.length ) ),
							onClick: () => setAsking( { list: 'kept', kind: 'put_back', rows: back } ),
					  }
					: null,
				{
					key: 'remove',
					/* translators: %s: how many kept copies. */
					label: sprintf( _n( 'Remove %s for Good', 'Remove %s for Good', entries.length, 'bettershield' ), formatCount( entries.length ) ),
					disabled: entries.length > REMOVE_AT_ONCE,
					/* translators: %s: the most kept copies removed at once. */
					why: sprintf( __( 'Remove at most %s at a time.', 'bettershield' ), formatCount( REMOVE_AT_ONCE ) ),
					onClick: () => setAsking( { list: 'kept', kind: 'remove', rows: entries } ),
				},
			].filter( Boolean ),
			onClear: () => {
				setAsking( null );
				setPickedKept( new Set() );
			},
		};
	};

	// No: the question goes, and the keyboard goes back to the bar that asked it.
	const cancelAsking = () => {
		// Asked from a row rather than the bar: back to that row (#2247).
		const from = asking && asking.single ? document.getElementById( `bs-ds-filerow-${ asking.rows[ 0 ].id }` ) : null;

		setAsking( null );
		window.requestAnimationFrame( () => focusIfLost( from || ( barRef.current && barRef.current.querySelector( 'button' ) ) ) );
	};

	const dockFor = ( list, bar, label ) => {
		const ask = asking && list === asking.list ? asking : null;
		const said = receipt && list === receipt.list ? receipt : null;

		if ( ! ask && ! said && ! bar ) {
			return null;
		}

		return (
			<SelectionDock label={ label }>
				{ said ? <SelectionReceipt { ...answerFor( said ) } working={ batchWorking } onDismiss={ dismissReceipt } alertRef={ receiptRef } /> : null }
				{ ask ? <SelectionQuestion { ...questionFor( ask ) } working={ batchWorking } dialogRef={ askRef } onCancel={ cancelAsking } /> : null }
				{ ! ask && bar ? <SelectionBar { ...bar } working={ batchWorking } barRef={ barRef } /> : null }
			</SelectionDock>
		);
	};
	// Busy between slices too: the check is still going while it waits.
	const scanning = isBusy( 'scan' ) || ( driving && !! report.running );
	// Part-finished, and nothing on this screen is carrying it on.
	const parked = !! report.running && ! scanning;
	// A change marked expected is not open, and the file may still differ
	// from its published copy, so with any marked this does not say
	// everything matches.
	let empty = null;

	if ( ! changes.length && ! report.changes_error ) {
		if ( filtered ) {
			empty = [ __( 'No open change matches.', 'bettershield' ), __( 'Change the filters or clear them to see every open change.', 'bettershield' ) ];
		} else if ( ! report.ever_run ) {
			empty = [
				__( 'Nothing has been compared yet.', 'bettershield' ),
				__( 'Run a check to compare this site with WordPress’s published copies. It only reads.', 'bettershield' ),
			];
		} else if ( expectedTotal > 0 ) {
			empty = [
				__( 'No changed files to review.', 'bettershield' ),
				sprintf(
					/* translators: %s: how many file changes are marked expected. */
					_n(
						'%s accepted change is listed below. Files with no official copy to compare are listed above.',
						'%s accepted changes are listed below. Files with no official copy to compare are listed above.',
						expectedTotal,
						'bettershield'
					),
					formatCount( expectedTotal )
				),
			];
		} else {
			empty = [
				__( 'Everything matches the published copies.', 'bettershield' ),
				__( 'Every file with an official copy matches it. Files with no official copy are listed above; they could not be checked.', 'bettershield' ),
			];
		}
	}

	const compared = report.ever_run && report.stats;
	const foot = report.next_cursor || compared;

	return (
		<>
			<FilesGlance
				report={ report }
				changes={ changes }
				quarantined={ quarantined }
				quarantineMore={ quarantineMore }
				quarantineRead={ quarantineRead }
			/>

			<Card className="bs-ds-files" aria-labelledby="bs-ds-files-title">
				<CardHead icon="file-diff" title={ __( 'File check', 'bettershield' ) } id="bs-ds-files-title">
					{ mayManage() && ! ( report && report.elsewhere ) ? (
						// A scan, so it says so the way the audit does.
						<Button
							type="secondary"
							size="sm"
							icon="refresh-cw"
							iconTone="2"
							isBusy={ scanning }
							disabled={ scanning }
							onClick={ () => act( '/bettershield/v1/integrity/scan', 'scan', undefined, () => setDriving( true ) ) }
						>
							{ scanning && __( 'Checking…', 'bettershield' ) }
							{ ! scanning && ( parked ? __( 'Continue Check', 'bettershield' ) : __( 'Check Now', 'bettershield' ) ) }
						</Button>
					) : null }
				</CardHead>
				<p className="bs-ds-files__intro">
					{ __( 'Compares your WordPress and plugin files with the official copies, so you can spot changes you did not make.', 'bettershield' ) }
				</p>
				{ report && report.elsewhere ? (
					<p className="bs-ds-files__intro">
						{ __( 'On this network, the main site checks the files every site shares. This is its latest check.', 'bettershield' ) }
					</p>
				) : null }
				{ /* On a network the files are every site's: a site administrator
				     reads the changes, and a network administrator acts (#2615). */ }
				{ mayManage() && ! mayChangeSharedCode() ? (
					<p className="bs-ds-files__intro">
						{ __( 'These files are shared by every site on the network, so only a network administrator can restore or accept a change. You can review them here.', 'bettershield' ) }
					</p>
				) : null }

				{ /* Freshness beside the control that refreshes it. A screen that
				     cannot say when it last looked cannot be trusted to say a site
				     is clean, so the date is at the top of the card rather than
				     somewhere down the page. */ }
				<div className="bs-ds-files__state">
					{ /*
					   A heading, not a line of text. This is where focus lands
					   when a row is resolved and the control that had it is gone,
					   and a screen reader arriving on a paragraph is told nothing
					   about where it now is.
					*/ }
					<h3 className="bs-ds-files__when" ref={ summaryHeading } tabIndex={ -1 }>
						{ checkState }
					</h3>

					{ /*
					   A bar rather than a spinner. This is the longest thing the
					   plugin does, and an indeterminate spinner on a multi-minute
					   job reads as hung — and what somebody does about a hung page
					   is reload it, which starts the run again. Coarse on purpose:
					   targets finished only ever goes up, where a percentage
					   derived from a position inside one target would stall for
					   whole minutes on a big plugin. Here beside the count it
					   measures, on a track that does not change length as the
					   count's wording does.
					*/ }
					{ report.running && report.progress && report.progress.targets ? (
						<div
							className="bs-ds-files__bar"
							role="progressbar"
							aria-valuemin={ 0 }
							aria-valuemax={ report.progress.targets }
							aria-valuenow={ report.progress.target }
							aria-valuetext={ scanProgress( report.progress ) }
						>
							<span
								className="bs-ds-files__bardone"
								style={ {
									width: `${ Math.round(
										( Math.min( report.progress.target, report.progress.targets ) / report.progress.targets ) * 100
									) }%`,
								} }
							/>
						</div>
					) : null }
					{ /* The next check's time is the Last check tile's, just above;
					     said here too it was the same time twice in one view
					     (#2820). A running check's progress stays beside its bar. */ }
					{ report.running ? (
						<p className="bs-ds-files__next">{ scanProgress( report.progress ) + ( parked ? ' ' + parkedNote( report ) : '' ) }</p>
					) : null }
				</div>

				{ /* Every note in the card, the core one too, inside the one padded
				   column, so none of them runs to the card's edges (#2467). */ }
				{ notice || done || ( report.unverifiable && report.unverifiable.length ) || report.changes_error || core ? (
					<div className="bs-ds-files__notes">
						{ notice ? (
							<div role="alert">
								<Alert layout="default" tone="error" desc={ notice } onDismiss={ () => setNotice( null ) } />
							</div>
						) : null }

						{ done ? (
							<div className="bs-ds-files__done" role="status">
								<Alert
									layout="default"
									tone="success"
									desc={ done }
									actions={
										// The adoption's undo, beside the adoption's own
										// sentence only. Any later outcome replaces the
										// sentence, and an Undo left beside it read as that
										// outcome's while it took back the earlier adoption.
										adopted && adopted.said === done ? (
											<Button
												type="secondary"
												size="sm"
												isBusy={ isBusy( `package-${ adopted.slug }` ) }
												disabled={ isBusy( `package-${ adopted.slug }` ) }
												onClick={ () => withdrawAdoption( adopted ) }
											>
												{ __( 'Undo', 'bettershield' ) }
											</Button>
										) : null
									}
								/>
							</div>
						) : null }

						{ /*
						   Never let silence read as approval. The lead line says only
						   that the comparison did not happen — the entries arrive for
						   more than one reason (nothing published these files to
						   compare them against, or the location holds more files than
						   one pass walks), and each carries the server's own sentence
						   saying which.
						*/ }
						{ unverifiable.length ? (
							<div role="status">
								<Alert
									layout="default"
									tone="info"
									desc={
										<>
											{ /* The gap is always said, its reasons one press away.
											     A plugin nothing publishes is watched against the copy
											     first seen, and its changes are listed below: it was
											     said to be "not compared" with them in view (#1969). */ }
											{ watched.length ? (
												<p>
													{ sprintf(
														/* translators: %s: how many plugins have no published copy. */
														_n(
															'%s plugin isn’t on WordPress.org, so its files are compared with how they were when BetterShield first checked them.',
															'%s plugins aren’t on WordPress.org, so their files are compared with how they were when BetterShield first checked them.',
															watched.length,
															'bettershield'
														),
														formatCount( watched.length )
													) }
												</p>
											) : null }
											<p>
												{ notCompared.length
													? sprintf(
															/* translators: %s: how many plugins or WordPress versions could not be compared. */
															_n( '%s plugin, theme or WordPress version could not be checked.', '%s plugins, themes or WordPress versions could not be checked.', notCompared.length, 'bettershield' ),
															formatCount( notCompared.length )
													  )
													: null }{ notCompared.length ? ' ' : null }
												<Button type="linksub" size="sm" className="bs-ds-btn--inline" aria-expanded={ whyOpen } aria-controls={ whyOpen ? 'bs-ds-files-why' : undefined } onClick={ () => setWhyOpen( ( was ) => ! was ) }>
													{ whyOpen ? __( 'Hide Why', 'bettershield' ) : __( 'Why?', 'bettershield' ) }
												</Button>
											</p>
											{ whyOpen ? (
											<ul className="bs-ds-files__unverifiable" id="bs-ds-files-why">
												{ report.unverifiable.map( ( item ) => (
													<li key={ `${ item.context }:${ item.slug }:${ item.version }:${ item.reason }` }>
														{ item.slug
															? sprintf(
																	/* translators: 1: a plugin name, 2: its version. */
																	__( '%1$s %2$s', 'bettershield' ),
																	item.name || item.slug,
																	item.version
															  )
															: sprintf(
																	/* translators: %s: a WordPress version. */
																	__( 'WordPress %s', 'bettershield' ),
																	item.version
															  ) }
														{ ' — ' }
														{ item.message }
													</li>
												) ) }
											</ul>
											) : null }
										</>
									}
								/>
							</div>
						) : null }

						{ report.changes_error ? (
							<div role="alert">
								<Alert layout="default" tone="error" desc={ report.changes_error } />
							</div>
						) : null }

						{ core ? (
							<div role="note">
								<Alert
									layout="default"
									tone="warning"
									desc={ sprintf(
										/* translators: 1: a WordPress version, 2: the changes by kind, e.g. "1 altered". */
										__( 'WordPress core %1$s: %2$s. Core files are listed first below.', 'bettershield' ),
										core.version || __( 'an unknown version', 'bettershield' ),
										packageCounts( core )
									) }
								/>
							</div>
						) : null }
					</div>
				) : null }

				{ packages.length ? (
					<section className="bs-ds-files__packages" aria-labelledby="bs-ds-files-packages">
						<div className="bs-ds-files__section">
							<h3 className="bs-ds-files__group">
								{ /* The section is named by these words alone, not
								     by the count and the ⓘ's own name beside them. */ }
								<span id="bs-ds-files-packages">{ __( 'Changes grouped by plugin', 'bettershield' ) }</span>
								<Badge>{ packages.length }</Badge>
								{ /* The why behind an ⓘ, the one thing to do in sight (#1325). */ }
								<InfoTip label={ __( 'About plugins by version', 'bettershield' ) }>
									{ __(
										'Files that match the official copy again drop off this list. For a plugin that was edited or isn’t on WordPress.org, accept each version once.',
										'bettershield'
									) }
								</InfoTip>
							</h3>
							{ mayChangeSharedCode() ? <p className="bs-ds-files__line">{ __( 'Just updated a plugin? Press Check Again so its files are compared with the new version.', 'bettershield' ) }</p> : null }
						</div>
						<Table label={ __( 'Changes grouped by plugin', 'bettershield' ) } head={ false } columns={ [ { key: 'package', label: __( 'Plugin', 'bettershield' ) } ] }>
							{ packages.map( ( pkg ) => (
								<PackageGroup
									key={ packageKey( pkg ) }
									pkg={ pkg }
									preview={ packagePreview?.key === packageKey( pkg ) ? packagePreview.data : null }
									busy={ {
										recheck: isBusy( `recheck-${ packageKey( pkg ) }` ),
										preview: isBusy( `preview-${ packageKey( pkg ) }` ),
										expect: isBusy( `package-${ pkg.slug }` ),
									} }
									onRecheck={ () => recheckPackage( pkg ) }
									onPreview={ () => previewPackage( pkg ) }
									onConfirm={ () => expectPackage( pkg ) }
									onCancel={ () => setPackagePreview( null ) }
								/>
							) ) }
						</Table>
					</section>
				) : null }

				{ /* Narrowed on the site, so every page is narrowed, not only
				     the rows loaded. Shown once there is something to narrow. */ }
				{ report.ever_run && ( filtered || report.open_changes?.total > 0 ) ? (
					<div className="bs-ds-files__filters" role="search" aria-label={ __( 'Filter file changes', 'bettershield' ) }>
						<label className="bs-ds-files__search">
							<Icon name="search" size={ 16 } tone="3" />
							<input
								ref={ searchField }
								type="search"
								value={ typed }
								maxLength={ 200 }
								placeholder={ __( 'Search by path', 'bettershield' ) }
								aria-label={ __( 'Search file changes by path', 'bettershield' ) }
								onChange={ ( event ) => setTyped( event.target.value ) }
							/>
						</label>
						<Field kind="select" width="sm" label={ __( 'Location', 'bettershield' ) } value={ filter.place } options={ filterOptions().place } onChange={ ( place ) => narrow( { place } ) } />
						<Field kind="select" width="sm" label={ __( 'Type of change', 'bettershield' ) } value={ filter.change_type } options={ filterOptions().change_type } onChange={ ( type ) => narrow( { change_type: type } ) } />
						<Field kind="select" width="sm" label={ __( 'Severity', 'bettershield' ) } value={ filter.severity } options={ filterOptions().severity } onChange={ ( severity ) => narrow( { severity } ) } />
						{ filtered || typed ? (
							<Button type="ghost" size="sm" icon="x" iconTone="2" onClick={ clearFilters }>
								{ __( 'Clear Filters', 'bettershield' ) }
							</Button>
						) : null }
					</div>
				) : null }

				{ filtered || report.open_changes?.total > changes.length || report.next_cursor ? (
					<div className="bs-ds-files__showing">
						{ /* Narrowed, the count is said as it arrives (announce()),
						     so the line is not a second live region saying it again. */ }
						<p role={ filtered ? undefined : 'status' }>
							{ filtered
								? sprintf(
										/* translators: 1: loaded rows, 2: open file changes the filter matches. */
										_n( 'Showing %1$s of %2$s matching file change.', 'Showing %1$s of %2$s matching file changes.', Number( report.matching ) || 0, 'bettershield' ),
										formatCount( changes.length ),
										formatCount( Number( report.matching ) || 0 )
								  )
								: sprintf(
										/* translators: 1: loaded rows, 2: total unresolved file changes at the last read. */
										__( 'Showing %1$s of %2$s changed files. Files that can be restored come first, then the newest.', 'bettershield' ),
										formatCount( changes.length ),
										formatCount( report.open_changes?.total || changes.length )
								  ) }
						</p>
						{ choosing && report.next_cursor && ! everything && matchingTotal > 0 ? (
							<Button type="linksub" size="sm" className="bs-ds-btn--inline" isBusy={ isBusy( 'matching' ) } disabled={ isBusy( 'matching' ) } onClick={ selectEverything }>
								{ sprintf(
									/* translators: %s: how many open changes match. */
									__( 'Select All %s Matching Changes', 'bettershield' ),
									formatCount( matchingTotal )
								) }
							</Button>
						) : null }
					</div>
				) : null }

				{ changes.length || empty || batches.length || suppressed.length || foot ? (
					<Table
						label={ __( 'File changes', 'bettershield' ) }
						className="bs-ds-files__table bs-ds-tbl--grouped"
						columns={ [
							...( choosing ? [ selectColumn() ] : [] ),
							{ key: 'severity', label: __( 'Severity', 'bettershield' ), width: '112px' },
							// The path keeps room to be read: once it is down to its floor,
							// a changed file's three buttons wrap in their cell rather than
							// take it (#2555). With room to spare they stay on one line.
							{ key: 'change', label: __( 'Change', 'bettershield' ), width: 'minmax(220px, 1fr)' },
							{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
						] }
					>
						{ groupChanges( changes ).map( ( group ) => (
							<div key={ group.key } role="rowgroup" aria-label={ group.label } className="bs-ds-files__rows">
								<GroupHead label={ group.label } count={ groupCount( group, changes, report ) } pick={ groupPick( group ) } />
								{ rowNote && rowNote.group === group.key ? (
									<WholeRow kind="note">
										<span key={ rowNote.text } className="bs-ds-files__rownote" role={ 'alert' === rowNote.tone ? 'alert' : 'status' }>
											<Alert layout="default" tone={ 'alert' === rowNote.tone ? 'error' : 'success' } desc={ rowNote.text } onDismiss={ () => setRowNote( null ) } />
										</span>
									</WholeRow>
								) : null }
								{ group.note ? <WholeRow kind="note">{ group.note }</WholeRow> : null }
								{ ( openGroups.has( group.key ) ? group.changes : group.changes.slice( 0, GROUP_SHOWN ) ).map( ( change ) =>
									'package_mismatch' === change.change_type ? (
										<PackageRow
											key={ change.id }
											change={ change }
											busy={ isBusy( `package-${ change.slug }` ) }
											onAdopt={ adoptThisCopy }
											column={ choosing }
										/>
									) : (
										<FileRow
											key={ change.id }
											change={ change }
											sharedWhy={ null !== group.note && group.note === change.why_not }
											busy={ isBusy( `change-${ change.id }` ) }
											column={ choosing }
											picked={ Boolean( everything ) || picked.has( change.id ) }
											onPick={ () => pickChanges( [ change.id ], ! everything && ! picked.has( change.id ) ) }
											onRestore={ ( item ) => {
												// Restoring resolves the row too, so focus has
												// the same place to go as marking one expected.
												aimAfter( item.id );

												return act(
													`/bettershield/v1/integrity/changes/${ item.id }/restore`,
													`change-${ item.id }`,
													__( 'The official file is restored. Your old version is in Quarantine below, where you can put it back.', 'bettershield' ),
													loadQuarantine,
													{
														group: groupOf( item.id ),
														said: sprintf(
															/* translators: %s: the file's path. */
															__( 'Restored: %s. Your old version is in Quarantine below, where you can put it back.', 'bettershield' ),
															item.path
														),
													}
												);
											} }
											onSuppress={ acceptChange }
											onQuarantine={ ( item ) => {
												aimAfter( item.id );

												return act(
													`/bettershield/v1/integrity/changes/${ item.id }/quarantine`,
													`change-${ item.id }`,
													__( 'File moved to quarantine. To undo, use Put This File Back in the Quarantine list below.', 'bettershield' ),
													loadQuarantine,
													{
														group: groupOf( item.id ),
														said: sprintf(
															/* translators: %s: the file's path. */
															__( 'Moved to quarantine: %s. You can put it back from the Quarantine list below.', 'bettershield' ),
															item.path
														),
													}
												);
											} }
										/>
									)
								) }
								{ /* The rest of a long group waits behind one control, so
								     the next group is a scroll away rather than a
								     hundred rows away. */ }
								{ group.changes.length > GROUP_SHOWN ? (
									<WholeRow kind="foot">
										<Button
											type="ghost"
											size="sm"
											trailing={ openGroups.has( group.key ) ? 'chevron-up' : 'chevron-down' }
											trailingTone="3"
											aria-expanded={ openGroups.has( group.key ) }
											onClick={ () => toggleGroup( group.key ) }
										>
											{ /* The group's own count can be more than is loaded;
											     the rest come with Load Older Changes, so the
											     button says how many it opens of how many. */ }
											{ openGroups.has( group.key )
												? __( 'Show Fewer', 'bettershield' )
												: Number.isInteger( groupCount( group, changes, report ) ) && groupCount( group, changes, report ) > group.changes.length
												? sprintf(
														/* translators: 1: number of files of the group loaded on screen, 2: number of files in the whole group. */
														__( 'Show %1$s of %2$s', 'bettershield' ),
														formatCount( group.changes.length ),
														formatCount( groupCount( group, changes, report ) )
												  )
												: sprintf(
														/* translators: %s: number of files in the group. */
														__( 'Show All %s', 'bettershield' ),
														formatCount( group.changes.length )
												  ) }
										</Button>
									</WholeRow>
								) : null }
							</div>
						) ) }

						{ empty ? (
							<WholeRow kind="empty">
								<span className="bs-ds-files__empty">
									<span className="bs-ds-files__emptytitle">{ empty[ 0 ] }</span> { empty[ 1 ] }
								</span>
							</WholeRow>
						) : null }

						{ batches.length ? (
							<div role="rowgroup" aria-label={ __( 'Accepted in bulk', 'bettershield' ) } className="bs-ds-files__rows">
								<GroupHead label={ __( 'Accepted in bulk', 'bettershield' ) } count={ batchesTotal } />
								<WholeRow kind="note">
									{ __( 'Show a group in the list again to bring back the changes it accepted.', 'bettershield' ) }
								</WholeRow>
								{ batches.map( ( batch ) => (
									<Row key={ batch.undo } className="bs-ds-files__batch">
										<SelectCell column={ choosing } />
										<Cell />
										<Cell>
											<TitleMeta
												title={
													// A selection names no version: its name says what it is.
													batch.version
														? sprintf(
																/* translators: 1: a plugin name, 2: its version. */
																__( '%1$s %2$s', 'bettershield' ),
																batch.name,
																batch.version
														  )
														: batch.name
												}
												meta={ sprintf(
													/* translators: 1: number of changes, 2: when, e.g. "today, 2:14 PM". */
													_n( '%1$s change, accepted %2$s', '%1$s changes, accepted %2$s', batch.count, 'bettershield' ),
													formatCount( batch.count ),
													whenPhrase( batch.at )
												) }
											/>
										</Cell>
										<Cell align="end">
											{ mayChangeSharedCode() ? (
												<Button
													type="secondary"
													size="sm"
													isBusy={ isBusy( `batch-${ batch.undo }` ) }
													disabled={ isBusy( `batch-${ batch.undo }` ) }
													onClick={ () => unmarkBatch( batch ) }
												>
													{ __( 'Show in List Again', 'bettershield' ) }
												</Button>
											) : null }
										</Cell>
									</Row>
								) ) }
								{ report.batches_next ? (
									<WholeRow
										kind="foot"
										aside={
											<Button
												type="secondary"
												size="sm"
												isBusy={ isBusy( 'more-batches' ) }
												disabled={ isBusy( 'more-batches' ) }
												onClick={ moreBatches }
											>
												{ __( 'Show More Groups', 'bettershield' ) }
											</Button>
										}
									>
										{ sprintf(
											/* translators: 1: groups listed so far, 2: groups marked expected in all. */
											__( 'Showing %1$s of %2$s.', 'bettershield' ),
											formatCount( batches.length ),
											formatCount( batchesTotal )
										) }
									</WholeRow>
								) : null }
							</div>
						) : null }

						{ suppressed.length ? (
							<div role="rowgroup" aria-label={ __( 'Accepted changes', 'bettershield' ) } className="bs-ds-files__rows">
								<GroupHead label={ __( 'Accepted changes', 'bettershield' ) } count={ expectedTotal } />
								<WholeRow kind="note">
									{ __( 'Changes you accepted. They come back only if the file changes again.', 'bettershield' ) }
								</WholeRow>

								{ expectedOpen
									? suppressed.map( ( change ) => (
											<Row key={ change.id } className="bs-ds-filerow">
												<SelectCell column={ choosing } />
												<Cell />
												<Cell>
													<TitleMeta title={ <Path path={ change.path } /> } meta={ changeLabel( change.change_type ) } />
												</Cell>
												<Cell align="end">
													{ mayChangeSharedCode() ? (
														<Button
															type="secondary"
															size="sm"
															isBusy={ isBusy( `change-${ change.id }` ) }
															disabled={ isBusy( `change-${ change.id }` ) }
															aria-label={ sprintf(
																/* translators: %s: a file path. */
																__( 'Show %s in the list again', 'bettershield' ),
																change.path
															) }
															onClick={ () => stopExpecting( change ) }
														>
															{ __( 'Show in List Again', 'bettershield' ) }
														</Button>
													) : null }
												</Cell>
											</Row>
									  ) )
									: null }

								{ expectedOpen && report.suppressed_next ? (
									<WholeRow
										kind="foot"
										aside={
											<Button
												type="secondary"
												size="sm"
												isBusy={ isBusy( 'more-expected' ) }
												disabled={ isBusy( 'more-expected' ) }
												onClick={ moreExpected }
											>
												{ __( 'Show More Files', 'bettershield' ) }
											</Button>
										}
									>
										{ sprintf(
											/* translators: 1: files listed so far, 2: files marked expected in all. */
											__( 'Showing %1$s of %2$s.', 'bettershield' ),
											formatCount( suppressed.length ),
											formatCount( expectedTotal )
										) }
									</WholeRow>
								) : null }

								<WholeRow kind="foot">
									<Button
										type="ghost"
										size="sm"
										trailing={ expectedOpen ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										aria-expanded={ expectedOpen }
										onClick={ () => setExpectedOpen( ! expectedOpen ) }
									>
										{ expectedOpen
											? __( 'Hide Them', 'bettershield' )
											: sprintf(
													/* translators: %s: number of files marked expected. */
													_n( 'Show the %s File', 'Show All %s Files', expectedTotal, 'bettershield' ),
													formatCount( expectedTotal )
											  ) }
									</Button>
								</WholeRow>
							</div>
						) : null }

						{ foot ? (
							<WholeRow
								kind="foot"
								aside={
									report.next_cursor ? (
										<Button
											type="secondary"
											size="sm"
											isBusy={ isBusy( 'more-changes' ) }
											disabled={ isBusy( 'more-changes' ) }
											onClick={ moreChanges }
										>
											{ __( 'Load Older Changes', 'bettershield' ) }
										</Button>
									) : null
								}
							>
								{ compared ? (
									<span className="bs-ds-files__compared">
										{ sprintf(
											/* translators: %s: number of files compared. */
											_n( '%s file compared.', '%s files compared.', report.stats.checked, 'bettershield' ),
											formatCount( report.stats.checked )
										) }{ ' ' }
										{ mayChangeSharedCode() ? __( 'When you restore a file, the old version is kept in quarantine below.', 'bettershield' ) : null }
									</span>
								) : null }
							</WholeRow>
						) : null }
					</Table>
				) : null }

				{ dockFor( 'changes', everything && choosing ? everythingBar( everything ) : chosen.length ? changeBar( chosen ) : null, __( 'Selected file changes', 'bettershield' ) ) }
			</Card>

			<Quarantined
				items={ quarantined }
				note={ quarantineNote }
				hasMore={ quarantineMore }
				onMore={ loadMoreQuarantine }
				loadingMore={ loadingMore }
				isBusy={ isBusy }
				onDownload={ downloadQuarantined }
				onPutBack={ putBackQuarantined }
				onDelete={ deleteQuarantined }
				column={ choosing }
				picked={ pickedKept }
				onPick={ pickKept }
				dock={ dockFor( 'kept', keptChosen.length ? keptBar( keptChosen ) : null, __( 'Selected copies', 'bettershield' ) ) }
			/>
		</>
	);
}
