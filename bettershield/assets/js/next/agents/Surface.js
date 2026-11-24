/**
 * Agents › Surface: what agents *can* do here, as distinct from what they did.
 *
 * A fact sheet, and the last tab for that reason: most owners read it once.
 * It states platform facts. "Three plugins expose write abilities over REST"
 * is information; a row becomes a warning only when it is a finding, and then
 * it carries the finding's severity, not the screen's tone.
 *
 * The strip, then two columns. On the left, what changed since the last
 * update and the inventory: one table, a group row per registering plugin,
 * with what is open to non-admins lifted into a group of its own at the top,
 * because that is the question the list exists to answer. On the right, a
 * card for each other way in: the application passwords, the traps, and
 * what other plugins open or keep.
 */

import './Surface.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { listOf } from '../../setup/format';
import { formatTime, useResource, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, Tray } from '../ui/Card';
import Field from '../ui/Field';
import { focusIfLost } from '../ui/focus';
import Icon from '../ui/Icon';
import SettingRow, { Saved, Toggle } from '../ui/Setting';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { EmptyState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Tabs from '../ui/Tabs';
import { panelProps } from '../ui/tabKeys';
import AgentStrip, { AgentStripBone } from './AgentStrip';

/** The one filter that crosses every group: everything, or what is open. */
const ALL = '__all';
const OPEN = '__open';

/** The group that lifts what is open to non-admins out of its plugin's. */
const LOOK = '__look';

/** Rows one page of a group carries. */
const PER_PAGE = 25;

/** A group this long or shorter opens by itself; a longer one waits to be asked. */
const SHORT = 5;

/** The namespace this plugin registers under, which is what makes a group ours. */
const OURS = 'bettershield/';

/** The namespace WordPress itself registers under. */
const CORE = 'core/';

/** The id the inventory's tabs and the table under them share. */
const TABS_ID = 'bs-ds-abilities';

/** Whether an ability lets accounts below administrator call it. */
const isOpen = ( ability ) => 'allowed' === ability.low_privilege_access;

/**
 * The inventory, folded into one group per registering plugin, with what is
 * open to non-admins in a group of its own ahead of them.
 *
 * Ours first, then by name. Sorting by the name a plugin gives itself rather
 * than by its directory is what makes the list read as a shelf of plugins
 * instead of a list of slugs.
 *
 * Under the Open to non-admins tab every row is open, so lifting them would
 * empty every plugin's group into one: there they stay with their plugin,
 * which is the one thing that tab has left to say about them.
 *
 * @param {Array<Object>} abilities The abilities to group.
 * @param {boolean}       lift      Whether to lift what is open into its own group.
 * @return {Array<Object>} One entry per group, each with its rows.
 */
function groupsOf( abilities, lift = true ) {
	const groups = new Map();
	const look = [];

	abilities.forEach( ( ability ) => {
		if ( lift && isOpen( ability ) ) {
			look.push( ability );

			return;
		}

		const key = ability.registering_source;

		if ( ! groups.has( key ) ) {
			groups.set( key, {
				source: key,
				label: ability.registering_source_label || key,
				ours: false,
				core: false,
				rows: [],
			} );
		}

		const group = groups.get( key );
		const name = String( ability.name || '' );

		group.rows.push( ability );

		// Read off the ability's own namespace rather than off a directory
		// name, which is whatever the site happened to install this under.
		group.ours = group.ours || name.startsWith( OURS );
		group.core = group.core || name.startsWith( CORE );
	} );

	const plugins = Array.from( groups.values() ).sort( ( a, b ) => {
		if ( a.ours !== b.ours ) {
			return a.ours ? -1 : 1;
		}

		return a.label.localeCompare( b.label );
	} );

	return look.length ? [ { source: LOOK, label: __( 'Needs a look', 'bettershield' ), look: true, rows: look }, ...plugins ] : plugins;
}

/**
 * The changes waiting in New since your last update, by ability name: what
 * each one was, so its row in the inventory can say so.
 *
 * @param {Array<Object>} changes The waiting changes.
 * @return {Object} kind by name.
 */
function pendingOf( changes ) {
	const pending = {};

	( changes || [] ).forEach( ( change ) => {
		if ( change && change.name ) {
			pending[ change.name ] = change.kind;
		}
	} );

	return pending;
}

/** An ability's name without its namespace: the group above already says whose it is. */
function shortName( name ) {
	const text = String( name || '' );
	const slash = text.indexOf( '/' );

	return slash > 0 ? text.slice( slash + 1 ) : text;
}

/**
 * What a group row says after its count.
 *
 * "Nothing to review" only when it is true: not while one of the group's
 * abilities waits in New since your last update, and not while the site
 * could not tell who may use one of them.
 *
 * @param {Object} group   The group.
 * @param {Object} pending The waiting changes, by ability name.
 * @return {{text: string, quiet: boolean}} The line, and whether it says only that all is well.
 */
function groupSays( group, pending ) {
	if ( group.look ) {
		return { text: __( 'Open to non-admins', 'bettershield' ), quiet: false };
	}

	const waiting = group.rows.filter( ( ability ) => pending[ ability.name ] ).length;

	if ( waiting ) {
		return {
			text: sprintf(
				/* translators: %d: how many of the group’s abilities are waiting to be reviewed. */
				_n( '%d to review', '%d to review', waiting, 'bettershield' ),
				waiting
			),
			quiet: false,
		};
	}

	if ( group.rows.some( ( ability ) => 'allowed' !== ability.low_privilege_access && 'denied' !== ability.low_privilege_access ) ) {
		return { text: __( 'Access not known for some', 'bettershield' ), quiet: false };
	}

	return { text: __( 'Nothing to review', 'bettershield' ), quiet: true };
}

/** The icon a group row leads with. */
function groupIcon( group ) {
	if ( group.look ) {
		return 'triangle-alert';
	}

	if ( group.ours ) {
		return 'shield';
	}

	return group.core ? 'layers' : 'plug';
}

/**
 * One group: its row, opening in place, then its rows a page at a time.
 *
 * The rows are a group of the one table under the tab row, so every group
 * shares the table's columns and its one header.
 */
function AbilityGroup( { group, open, onToggle, pending = {} } ) {
	const [ shown, setShown ] = useState( PER_PAGE );
	const rows = group.rows;
	const page = rows.slice( 0, shown );
	const says = groupSays( group, pending );

	return (
		<>
			<WholeRow kind="group">
				<button type="button" className={ `bs-ds-surface__grouphead${ group.look ? ' bs-ds-surface__grouphead--look' : '' }` } aria-expanded={ open } onClick={ onToggle }>
					<Icon name={ groupIcon( group ) } size={ 14 } tone="2" />
					<span className="bs-ds-surface__groupname">{ group.label }</span>
					<Badge className="bs-ds-surface__groupcount">{ rows.length }</Badge>
					<span className={ `bs-ds-surface__groupsays${ says.quiet ? ' bs-ds-surface__groupsays--quiet' : '' }` }>{ says.text }</span>
					<span className="bs-ds-spacer" />
					{ /* The one mark that says "this opens", turned when it has. */ }
					<Icon name="chevron-down" size={ 16 } tone="2" className="bs-ds-surface__chevron" />
				</button>
			</WholeRow>

			{ open ? (
				<div
					className="bs-ds-surface__rows"
					role="rowgroup"
					aria-label={
						group.look
							? __( 'Abilities open to non-admins', 'bettershield' )
							: sprintf(
									/* translators: %s: the name of the plugin that registered them. */
									__( 'Abilities registered by %s', 'bettershield' ),
									group.label
							  )
					}
				>
					{ page.map( ( ability ) => (
						<Row key={ ability.name } className={ `bs-ds-surface__row${ isOpen( ability ) ? ' bs-ds-surface__row--look' : '' }` }>
							<Cell>
								<span className="bs-ds-surface__ability">
									{ isOpen( ability ) ? <Icon name="triangle-alert" size={ 16 } tone="1" /> : null }
									<span className="bs-ds-surface__name" title={ ability.name }>
										<span aria-hidden="true">{ shortName( ability.name ) }</span>
										<span className="screen-reader-text">{ ability.name }</span>
									</span>
									{ /* Lifted out of its plugin's group, a row says whose it is itself. */ }
									{ group.look ? (
										<span className="bs-ds-surface__owner" aria-hidden="true">
											{ ability.registering_source_label || ability.registering_source }
										</span>
									) : null }
									{ /* What the tray promises: an update's addition, marked where it sits. */ }
									{ pending[ ability.name ] ? (
										<Badge tone={ kindTone( 'medium' ) }>{ 'added' === pending[ ability.name ] ? __( 'new', 'bettershield' ) : __( 'opened wider', 'bettershield' ) }</Badge>
									) : null }
								</span>
							</Cell>
							<Cell>
								<span className="bs-ds-surface__fact">{ ability.annotated_readonly ? __( 'Views only', 'bettershield' ) : __( 'Changes site', 'bettershield' ) }</span>
							</Cell>
							<Cell>
								<span className="bs-ds-surface__fact">{ ability.exposed_in_rest ? __( 'REST', 'bettershield' ) : __( 'Site only', 'bettershield' ) }</span>
							</Cell>
							<Cell>
								{ isOpen( ability ) ? (
									<Badge tone={ kindTone( 'medium' ) }>{ __( 'non-admins', 'bettershield' ) }</Badge>
								) : (
									<span className="bs-ds-surface__fact">{ 'denied' === ability.low_privilege_access ? __( 'Admins only', 'bettershield' ) : __( 'Unknown', 'bettershield' ) }</span>
								) }
							</Cell>
						</Row>
					) ) }

					{ rows.length > shown ? (
						<WholeRow
							kind="foot"
							aside={ sprintf(
								/* translators: 1: how many rows are shown, 2: how many there are. */
								__( 'Showing %1$d of %2$d', 'bettershield' ),
								page.length,
								rows.length
							) }
						>
							<Button type="secondary" size="sm" onClick={ () => setShown( shown + PER_PAGE ) }>
								{ __( 'Show More', 'bettershield' ) }
							</Button>
						</WholeRow>
					) : null }
				</div>
			) : null }
		</>
	);
}

/**
 * What an update or an activation added or opened wider since the abilities
 * were last accepted (#1878): a card of each with its plugin and what it now
 * does, and Mark As Reviewed, which takes the abilities as they are now as
 * the baseline. Once reviewed, a line in its place, with an Undo.
 *
 * @param {Object} props
 * @param {Array}  props.changes The changes waiting.
 */
function NewSinceUpdate( { changes } ) {
	const { acceptAbilityChanges, undoAbilityAccept, load, busy } = useStore();
	const [ said, setSaid ] = useState( null );
	// The accept's undo record, while its Undo is on offer.
	const [ undo, setUndo ] = useState( '' );
	// The card the pressed button sat in is gone once the review lands, so the
	// line that replaced it takes the keyboard, rather than the page's body.
	const line = useRef( null );
	const lineShown = Boolean( said ) && ! ( changes && changes.length );

	useEffect( () => {
		if ( lineShown ) {
			focusIfLost( line.current );
		}
	}, [ lineShown, said ] );

	const putBack = () =>
		undoAbilityAccept( undo, ( answer ) => {
			if ( answer ) {
				setUndo( '' );
				setSaid( { tone: 'info', title: '', desc: __( 'These changes are waiting for you again.', 'bettershield' ) } );
				load( 'agentSurface', { force: true } );
			}
		} );

	if ( ! changes || ! changes.length ) {
		return said ? (
			<Alert
				alertRef={ line }
				tone={ said.tone }
				title={ said.title }
				desc={ said.desc }
				live
				actions={
					undo ? (
						<Button type="secondary" size="sm" isBusy={ 'ability-accept-undo' === busy } disabled={ Boolean( busy ) } onClick={ putBack }>
							{ __( 'Undo', 'bettershield' ) }
						</Button>
					) : null
				}
			/>
		) : null;
	}

	const accept = () =>
		acceptAbilityChanges( ( answer ) => {
			setUndo( ( answer && answer.undo ) || '' );
			setSaid( {
				tone: 'success',
				title: __( 'Reviewed.', 'bettershield' ),
				desc: __( 'Only new changes will show here after the next update.', 'bettershield' ),
			} );
			load( 'agentSurface', { force: true } );
		} );

	return (
		<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-changes-title">
			<CardHead icon="bot" id="bs-ds-changes-title" title={ __( 'New since your last update', 'bettershield' ) } line>
				<Badge>{ changes.length }</Badge>
			</CardHead>
			<div className="bs-ds-surface__changes">
				<Alert
					tone="warning"
					title={ sprintf(
						/* translators: %d: how many AI actions changed. */
						_n( '%d action changed.', '%d actions changed.', changes.length, 'bettershield' ),
						changes.length
					) }
					desc={ __( 'These AI actions are new or open to more people since the last update. Nothing was blocked.', 'bettershield' ) }
				/>
				<div className="bs-ds-surface__boxed">
					<Table
						label={ __( 'New since your last update', 'bettershield' ) }
						columns={ [
							{ key: 'name', label: __( 'Ability', 'bettershield' ) },
							{ key: 'what', label: __( 'What changed', 'bettershield' ), width: '240px' },
						] }
					>
						{ changes.map( ( change ) => (
							<Row key={ change.name }>
								<Cell>
									<TitleMeta title={ change.name } meta={ change.owner_label } />
								</Cell>
								<Cell className="bs-ds-surface__chips">
									<Badge tone={ kindTone( 'medium' ) }>{ 'added' === change.kind ? __( 'new', 'bettershield' ) : __( 'opened wider', 'bettershield' ) }</Badge>
									{ change.readonly ? null : <Badge tone={ kindTone( 'medium' ) }>{ __( 'changes site', 'bettershield' ) }</Badge> }
									{ change.open ? <Badge tone={ kindTone( 'medium' ) }>{ __( 'non-admins', 'bettershield' ) }</Badge> : null }
								</Cell>
							</Row>
						) ) }
					</Table>
				</div>
				<div>
					<Button type="secondary" size="sm" isBusy={ 'ability-accept' === busy } disabled={ Boolean( busy ) } onClick={ accept }>
						{ __( 'Mark As Reviewed', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</Card>
	);
}

function Abilities( { available, abilities, pending = {} } ) {
	const [ filter, setFilter ] = useState( ALL );
	const [ search, setSearch ] = useState( '' );
	// Which groups the reader has opened or closed by hand. Anything absent
	// follows the default: short groups open, long ones shut.
	const [ opened, setOpened ] = useState( {} );

	const head = (
		<CardHead
			icon="bot"
			id="bs-ds-abilities-title"
			title={ __( 'Actions plugins offer to AI', 'bettershield' ) }
			tip={ __( 'Flagged actions can change your site, run from outside, and are open to non-admins.', 'bettershield' ) }
			line
		>
			{ available ? <Badge>{ abilities.length }</Badge> : null }
		</CardHead>
	);

	if ( ! available ) {
		return (
			<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-abilities-title">
				{ head }
				<div className="bs-ds-surface__notes">
					<Alert layout="default" tone="info" desc={ __( 'Abilities require WordPress 6.9.', 'bettershield' ) } />
				</div>
			</Card>
		);
	}

	const needle = search.trim().toLowerCase();
	const matches = ( ability ) => ( ALL === filter || isOpen( ability ) ) && ( '' === needle || String( ability.name || '' ).toLowerCase().includes( needle ) );

	// Whether the reader is looking at a subset rather than at everything.
	const narrowed = ALL !== filter || '' !== needle;
	const shown = groupsOf( abilities.filter( matches ), ALL === filter );
	// A group holding a change that waits for review opens, so its mark is seen.
	const openByDefault = ( group ) => group.look || narrowed || group.rows.length <= SHORT || group.rows.some( ( ability ) => pending[ ability.name ] );

	const counts = {
		[ ALL ]: abilities.length,
		[ OPEN ]: abilities.filter( isOpen ).length,
	};

	return (
		<Tray icon="info" wrap note={ __( 'New actions from plugin updates show here first, marked new.', 'bettershield' ) }>
			<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-abilities-title">
				{ head }

				{ abilities.length ? (
					<div className="bs-ds-surface__body">
						<div className="bs-ds-surface__tabs">
							<Tabs
								id={ TABS_ID }
								label={ __( 'Show abilities', 'bettershield' ) }
								selected={ filter }
								onSelect={ setFilter }
								tabs={ [
									{ key: ALL, label: __( 'All', 'bettershield' ), count: counts[ ALL ] },
									{ key: OPEN, label: __( 'Open to non-admins', 'bettershield' ), count: counts[ OPEN ] },
								] }
								actions={
									<label className="bs-ds-surface__search">
										<Icon name="search" size={ 16 } tone="3" />
										<input
											type="search"
											value={ search }
											placeholder={ __( 'Search ability names', 'bettershield' ) }
											aria-label={ __( 'Search ability names', 'bettershield' ) }
											onChange={ ( event ) => setSearch( event.target.value ) }
										/>
									</label>
								}
							/>
						</div>

						<div className="bs-ds-surface__panel" { ...panelProps( TABS_ID, filter ) }>
							{ OPEN === filter && ! counts[ OPEN ] ? (
								<EmptyState>
									{ sprintf(
										/* translators: %d: number of registered abilities. */
										_n(
											'None of the %d registered ability admits accounts below administrator.',
											'None of the %d registered abilities admits accounts below administrator.',
											abilities.length,
											'bettershield'
										),
										abilities.length
									) }
								</EmptyState>
							) : null }

							{ shown.length ? (
								<Table
									label={ __( 'Actions plugins offer to AI', 'bettershield' ) }
									className="bs-ds-tbl--grouped bs-ds-surface__inventory"
									columns={ [
										{ key: 'name', label: __( 'Ability', 'bettershield' ) },
										{ key: 'changes', label: __( 'Changes site', 'bettershield' ), width: '112px' },
										{ key: 'from', label: __( 'Used from', 'bettershield' ), width: '80px' },
										{ key: 'who', label: __( 'Who can use it', 'bettershield' ), width: '112px' },
									] }
								>
									{ shown.map( ( group ) => (
										<AbilityGroup
											key={ group.source }
											group={ group }
											pending={ pending }
											/*
											 * A list being narrowed hides nothing that
											 * survived the narrowing: a search or a
											 * filter whose matches stay inside a shut
											 * group is one that answers nothing. So
											 * everything left open is open — unless the
											 * reader has said otherwise about it.
											 */
											open={ undefined === opened[ group.source ] ? openByDefault( group ) : opened[ group.source ] }
											onToggle={ () =>
												setOpened( ( state ) => ( {
													...state,
													[ group.source ]: undefined === state[ group.source ] ? ! openByDefault( group ) : ! state[ group.source ],
												} ) )
											}
										/>
									) ) }
								</Table>
							) : null }

							{ ! shown.length && '' !== needle ? <EmptyState>{ __( 'No ability name matches that.', 'bettershield' ) }</EmptyState> : null }
						</div>
					</div>
				) : (
					<EmptyState>{ __( 'No plugin offers AI actions yet.', 'bettershield' ) }</EmptyState>
				) }
			</Card>
		</Tray>
	);
}

/**
 * One application password: what it is, what it reaches, and the form that
 * holds it to routes and a network, opening under it.
 *
 * A limit narrows what a leaked credential can do: the REST routes it is for,
 * the network it is used from, or both. A request outside either is refused
 * and recorded. Every change has an undo, offered right after it.
 *
 * The decoy takes no limit: any use of it is the alarm, from anywhere.
 */
function Password( { userId, password } ) {
	const { limitAppPassword, unlimitAppPassword, undoAppPasswordLimit, busy } = useStore();
	const [ editing, setEditing ] = useState( false );
	const [ routes, setRoutes ] = useState( '' );
	const [ range, setRange ] = useState( '' );
	const [ undo, setUndo ] = useState( null );
	const limit = password.limit;
	const working = busy === `limit-${ password.uuid }`;
	// Save limit leaves with the form, Remove limit with the limit and Undo
	// with itself, so the line saying what the password now reaches takes
	// the keyboard.
	const status = useRef( null );
	const afterChange = useMutationFocus( status );
	const limitable = !! password.uuid && ! password.decoy;
	/*
	 * Opening the form and Cancel each take the button that was pressed
	 * away, so the keyboard goes into the form, and back to Set Limits
	 * (#2662).
	 */
	const form = useRef( null );
	const actions = useRef( null );
	const [ returning, setReturning ] = useState( false );
	// A refused limit is said in the form, where it can be corrected, not in
	// the page banner far above it (#2664).
	const [ refusal, setRefusal ] = useState( '' );
	const sayRefusal = ( error ) => {
		setRefusal( error?.message || '' );

		return Boolean( error?.message );
	};

	useEffect( () => {
		if ( editing ) {
			form.current?.querySelector( 'input' )?.focus();
		} else if ( returning ) {
			actions.current?.querySelector( 'button' )?.focus();
			setReturning( false );
		}
	}, [ editing, returning ] );

	const open = () => {
		setRoutes( ( limit?.routes || [] ).join( ', ' ) );
		setRange( limit?.range || '' );
		setRefusal( '' );
		setEditing( true );
	};

	const cancel = () => {
		setRefusal( '' );
		setReturning( true );
		setEditing( false );
	};

	const save = () =>
		limitAppPassword(
			userId,
			password.uuid,
			{ routes, range },
			afterChange( ( data ) => {
				setRefusal( '' );
				setEditing( false );
				setUndo( data.undo || null );
			} ),
			sayRefusal
		);

	const remove = () =>
		unlimitAppPassword(
			userId,
			password.uuid,
			afterChange( ( data ) => setUndo( data.undo || null ) )
		);

	return (
		<>
			<Row className="bs-ds-surface__password" open={ editing }>
				<Cell>
					<TitleMeta
						title={ password.name }
						meta={
							password.last_used_at
								? sprintf(
										/* translators: 1: date created, 2: date last used. */
										__( 'created %1$s · last used %2$s', 'bettershield' ),
										formatTime( password.created_at ),
										formatTime( password.last_used_at )
								  )
								: sprintf(
										/* translators: %s: date created. */
										__( 'created %s · never used', 'bettershield' ),
										formatTime( password.created_at )
								  )
						}
					/>
					{ limitable ? (
						<div className="bs-ds-surface__limit">
							<span className="bs-ds-surface__reach" ref={ status } tabIndex={ -1 }>
								{ limit
									? [
											limit.routes?.length
												? sprintf(
														/* translators: %s: a list of REST route prefixes. */
														__( 'Limited to %s', 'bettershield' ),
														limit.routes.join( ', ' )
												  )
												: null,
											limit.range
												? sprintf(
														/* translators: %s: an address or range, e.g. 203.0.113.0/24. */
														__( 'only from %s', 'bettershield' ),
														limit.range
												  )
												: null,
									  ]
											.filter( Boolean )
											.join( ' · ' )
									: __( 'No limits: works for everything its user can do, from any address', 'bettershield' ) }
							</span>

							{ editing ? null : (
								<span className="bs-ds-surface__limitactions" ref={ actions }>
									<Button
										type="ghost"
										size="sm"
										disabled={ working }
										onClick={ open }
										aria-label={ sprintf(
											/* translators: %s: an application password’s name. */
											__( 'Set limits for %s', 'bettershield' ),
											password.name
										) }
									>
										{ __( 'Set Limits', 'bettershield' ) }
									</Button>
									{ limit ? (
										<Button
											type="ghost"
											size="sm"
											isBusy={ working }
											disabled={ working }
											onClick={ remove }
											aria-label={ sprintf(
												/* translators: %s: an application password’s name. */
												__( 'Remove the limit on %s', 'bettershield' ),
												password.name
											) }
										>
											{ __( 'Remove Limit', 'bettershield' ) }
										</Button>
									) : null }
									{ undo ? (
										<Button
											type="ghost"
											size="sm"
											aria-label={ sprintf(
												/* translators: %s: an application password’s name. */
												__( 'Undo the limit change on %s', 'bettershield' ),
												password.name
											) }
											disabled={ busy === `limit-undo-${ undo }` }
											onClick={ () => undoAppPasswordLimit( undo, afterChange( () => setUndo( null ) ) ) }
										>
											{ __( 'Undo', 'bettershield' ) }
										</Button>
									) : null }
								</span>
							) }
						</div>
					) : null }
				</Cell>
			</Row>

			{ limitable && editing ? (
				<div className="bs-ds-surface__under" role="row">
					<div className="bs-ds-surface__limitform" role="cell" ref={ form }>
						<Field
							label={ __( 'Parts of the site it can use', 'bettershield' ) }
							help={ __( 'Leave empty for all. Developers can name specific API paths here.', 'bettershield' ) }
							value={ routes }
							disabled={ working }
							onChange={ ( next ) => {
								setRoutes( next );
								setRefusal( '' );
							} }
						/>
						<Field
							label={ __( 'Only allow from this IP address', 'bettershield' ) }
							help={ __( 'Leave empty to allow any address.', 'bettershield' ) }
							value={ range }
							disabled={ working }
							onChange={ ( next ) => {
								setRange( next );
								setRefusal( '' );
							} }
						/>
						{ refusal ? <Alert layout="default" tone="error" live="alert" desc={ refusal } /> : null }
						<span className="bs-ds-surface__limitactions">
							<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ save }>
								{ __( 'Save Limit', 'bettershield' ) }
							</Button>
							<Button type="ghost" size="sm" disabled={ working } onClick={ cancel }>
								{ __( 'Cancel', 'bettershield' ) }
							</Button>
						</span>
					</div>
				</div>
			) : null }
		</>
	);
}

/** The application passwords every account holds: a group row per account. */
function PasswordList( { holders } ) {
	if ( ! holders.length ) {
		return null;
	}

	return (
		<div className="bs-ds-surface__holders">
			<Table label={ __( 'Application passwords', 'bettershield' ) } head={ false } columns={ [ { key: 'name', label: __( 'Name', 'bettershield' ) } ] }>
				{ holders.map( ( holder ) => [
					<WholeRow
						key={ `holder-${ holder.user_id }` }
						kind="group"
						aside={ holder.oldest_unused_days >= 90 ? <Badge tone={ kindTone( 'low' ) }>{ __( 'unused', 'bettershield' ) }</Badge> : null }
					>
						<span className="bs-ds-surface__holder">
							<span className="bs-ds-surface__login">{ holder.login }</span>
							<span>{ holder.role }</span>
							<span>
								{ sprintf(
									/* translators: %d: number of application passwords the account holds. */
									_n( '%d application password', '%d application passwords', holder.count, 'bettershield' ),
									holder.count
								) }
							</span>
						</span>
					</WholeRow>,
					...( holder.passwords || [] ).map( ( password, index ) => (
						<Password key={ `${ holder.user_id }-${ password.uuid || index }` } userId={ holder.user_id } password={ password } />
					) ),
				] ) }
			</Table>
			<p className="bs-ds-surface__help bs-ds-surface__holdershelp">
				{ __( '“Unused” means not used for 90 days; it still works. Each password’s owner can revoke it from their profile.', 'bettershield' ) }
			</p>
		</div>
	);
}

/** The ages the sweep offers, in days. */
const AGES = [ 30, 90, 180, 365 ];

/** An age said in words: a year where it is one. */
function ageLabel( days ) {
	return 365 === days
		? __( '1 year', 'bettershield' )
		: sprintf(
				/* translators: %d: a number of days. */
				_n( '%d day', '%d days', days, 'bettershield' ),
				days
		  );
}

/**
 * The design's Segmented control as a choice of one value: radios, so a
 * reader hears a setting rather than a set of tabs.
 */
function AgeChoice( { label, value, options, disabled, onChange } ) {
	const index = options.indexOf( value );
	/*
	 * While a choice saves the radios are marked unavailable rather than
	 * disabled: a disabled button drops the focus the arrow key just moved to
	 * it, and the reader is left on the page's body. A press or a key during
	 * the save does nothing, so the next step is taken from the saved value.
	 */
	const move = ( event ) => {
		const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[ event.key ];

		if ( ! step ) {
			return;
		}

		event.preventDefault();

		if ( disabled ) {
			return;
		}

		const next = options[ ( Math.max( index, 0 ) + step + options.length ) % options.length ];
		const group = event.currentTarget.closest( '[role="radiogroup"]' );

		group?.querySelector( `[data-days="${ next }"]` )?.focus();
		onChange( next );
	};

	return (
		<div className="bs-ds-seg" role="radiogroup" aria-label={ label }>
			{ options.map( ( days ) => (
				<button
					key={ days }
					type="button"
					role="radio"
					data-days={ days }
					className="bs-ds-seg__item"
					aria-checked={ value === days }
					tabIndex={ value === days || ( index < 0 && days === options[ 0 ] ) ? 0 : -1 }
					aria-disabled={ disabled || undefined }
					onClick={ () => ! disabled && value !== days && onChange( days ) }
					onKeyDown={ move }
				>
					{ ageLabel( days ) }
				</button>
			) ) }
		</div>
	);
}

/**
 * Retiring the credentials nobody uses.
 *
 * WordPress gives an application password no expiry at all, so on a site that
 * has been running a while they accumulate: a plugin somebody trialled, a
 * deploy script from an agency that no longer has the contract, an app that
 * was uninstalled. Each still opens the site.
 *
 * The copy carries the one thing that separates this from everything else this
 * plugin does — a deleted password cannot be put back, because the secret was
 * never stored. It is said on the row, not behind an ⓘ.
 */
function Retirement( { expiry, minDays } ) {
	const { saveAppPasswordExpiry, busy } = useStore();
	const saving = busy === 'app-password-expiry';
	const days = Number( expiry.days ) || 0;
	// A saved age the choices do not hold (set before they were offered) stays one of them.
	const options = Array.from( new Set( [ ...AGES.filter( ( age ) => age >= minDays ), days ].filter( Boolean ) ) ).sort( ( a, b ) => a - b );
	// A refused change is said under the choice, not in the page banner
	// far above it (#2664).
	const [ refusal, setRefusal ] = useState( '' );
	const sayRefusal = ( error ) => {
		setRefusal( error?.message || '' );

		return Boolean( error?.message );
	};

	return (
		<SettingRow
			title={ __( 'Delete unused passwords', 'bettershield' ) }
			about={ __( 'Checked daily. Deleted passwords can’t be restored, so tools need a new one.', 'bettershield' ) }
			control={ <Saved forKey="app-password-expiry" /> }
			toggle={ {
				checked: Boolean( expiry.enabled ),
				disabled: saving,
				onChange: ( enabled ) => saveAppPasswordExpiry( { ...expiry, enabled }, () => setRefusal( '' ), sayRefusal ),
			} }
		>
			{ expiry.enabled ? (
				<div className="bs-ds-surface__age">
					<span className="bs-ds-surface__agelabel" id="bs-ds-surface-age">
						{ __( 'Delete when unused for', 'bettershield' ) }
					</span>
					<AgeChoice
						label={ __( 'Delete when unused for', 'bettershield' ) }
						value={ days }
						options={ options }
						disabled={ saving }
						onChange={ ( next ) => saveAppPasswordExpiry( { ...expiry, days: next }, () => setRefusal( '' ), sayRefusal ) }
					/>
					<span className="bs-ds-surface__help">{ __( 'Counted from last use, or from creation if never used.', 'bettershield' ) }</span>
				</div>
			) : null }
			{ refusal ? <Alert layout="default" tone="error" live="alert" desc={ refusal } /> : null }
		</SettingRow>
	);
}

/** A trap's state beside its name: On in brand, Off in neutral. */
function OnOff( { on } ) {
	return on ? <Badge tone={ kindTone( 'on' ) }>{ __( 'On', 'bettershield' ) }</Badge> : <Badge>{ __( 'Off', 'bettershield' ) }</Badge>;
}

/**
 * A credential that exists only to be used by somebody who should not have it.
 *
 * Everything else this plugin reports is an inference with a reading where
 * nothing is wrong. This one has none: the decoy belongs to no tool and is
 * written into no configuration, so the only way it is ever used is that
 * somebody read it out of this site's database or its backups.
 *
 * The owner is told exactly what it is and where — the deception is of an
 * attacker, and a tripwire nobody knew about is one that fires at three in the
 * morning and nobody knows why.
 */
function Decoy( { canary, used } ) {
	const { setCanary, busy } = useStore();
	const working = busy === 'canary';
	// A refusal said under the switch, not in the page banner (#2664).
	const [ refusal, setRefusal ] = useState( '' );

	return (
		<SettingRow
			title={ __( 'Trap password', 'bettershield' ) }
			about={ __( 'A decoy password. If anyone tries it, you get an alert, since your data was likely copied.', 'bettershield' ) }
			badge={ <OnOff on={ !! canary } /> }
		>
			<div className="bs-ds-surface__switch">
				<div className="bs-ds-surface__switchtext">
					<span className="bs-ds-surface__switchlabel" id="bs-ds-surface-canary">
						{ __( 'Keep a trap password on my account', 'bettershield' ) }
					</span>
					<span className="bs-ds-surface__help" id="bs-ds-surface-canary-help">
						{ __( 'Listed on your profile, marked “do not use”.', 'bettershield' ) }
					</span>
				</div>
				<Saved forKey="canary" />
				<Toggle
					checked={ !! canary }
					disabled={ working }
					labelledBy="bs-ds-surface-canary"
					describedBy="bs-ds-surface-canary-help"
					onChange={ ( event ) => {
						const plant = Boolean( event && event.target ? event.target.checked : event );

						setRefusal( '' );
						setCanary( plant, ( error ) => {
							setRefusal( error?.message || '' );

							return Boolean( error?.message );
						} );
					} }
				/>
			</div>
			{ refusal ? <Alert layout="default" tone="error" live="alert" desc={ refusal } /> : null }

			{ /* Said from the log the alarm writes to: a card that went on
			     saying nothing had touched the decoy after it fired was
			     the one place on the screen that had it wrong. */ }
			{ canary && used ? (
				<div role="status">
					<Alert
						layout="default"
						tone="warning"
						desc={ sprintf(
							/* translators: 1: when it was planted, 2: when it was last used, 3: how many times it has been used. */
							_n(
								'Planted %1$s. Used %3$d time, last %2$s, and refused: someone has read the database or a backup.',
								'Planted %1$s. Used %3$d times, last %2$s, and refused each time: someone has read the database or a backup.',
								used.count,
								'bettershield'
							),
							formatTime( canary.planted_at ),
							formatTime( used.at ),
							used.count
						) }
					/>
				</div>
			) : null }
			{ canary && ! used ? (
				<p className="bs-ds-surface__line" role="status">
					<Icon name="circle-check" size={ 14 } tone="2" />
					{ sprintf(
						/* translators: %s: date and time. */
						__( 'Added %s. No one has tried it.', 'bettershield' ),
						formatTime( canary.planted_at )
					) }
				</p>
			) : null }
			{ canary ? (
				<div>
					<Button type="link" size="sm" href={ tabUrl( 'bettershield-activity', 'site' ) } trailing="arrow-right">
						{ __( 'See It in Activity', 'bettershield' ) }
					</Button>
				</div>
			) : null }
		</SettingRow>
	);
}

/**
 * An unused path that answers like any missing page, and raises an alert when
 * something asks for it.
 */
function DecoyUrl( { state = {} } ) {
	const { saveDecoyPage, testDecoyPage, busy } = useStore();
	const working = busy === 'decoy-page';
	const [ slug, setSlug ] = useState( state.slug || '' );
	const [ tested, setTested ] = useState( null );
	// A refused path is said under the field it is about, which stays in
	// view, not in the page banner far above it (#2664).
	const [ refusal, setRefusal ] = useState( '' );
	const collision = tested?.collision || state.collision || '';
	const status = useRef( null );
	const afterMutation = useMutationFocus( status );

	/*
	 * The swap lands with the surface read again after the save, once the
	 * press has let go, so the line above found the pressed control still
	 * there and left focus to it; then it went, and focus with it (#1926).
	 * The status line takes focus when the state a press asked for arrives.
	 */
	const pressed = useRef( false );
	const enabled = Boolean( state.enabled );

	useEffect( () => {
		if ( pressed.current ) {
			pressed.current = false;
			focusIfLost( status.current );
		}
	}, [ enabled ] );

	useEffect( () => {
		setSlug( state.slug || '' );
		setTested( null );
	}, [ state.slug ] );

	/*
	 * Turning the decoy on or off replaces this row's controls with the other
	 * state's, so the control that was pressed is gone by the time the reply
	 * lands. The line saying which state the site is in now is on both sides of
	 * that swap, which is what makes it somewhere to land.
	 *
	 * The follow-up is handed to the store rather than awaited: behind the
	 * password gate the first answer is null, and only what the call carries
	 * is run again once the password is confirmed.
	 */
	const save = ( on, path ) => {
		pressed.current = on !== enabled;
		setRefusal( '' );
		saveDecoyPage( on, path.trim(), afterMutation( () => {} ), ( error ) => {
			pressed.current = false;
			setRefusal( error?.message || '' );

			return Boolean( error?.message );
		} );
	};

	const check = () => testDecoyPage( ( result ) => setTested( { matched: Boolean( result?.matched ), collision: result?.collision || '' } ) );

	return (
		<SettingRow
			title={ __( 'Trap page', 'bettershield' ) }
			about={ __( 'A hidden page only intruders find. Visits alert you.', 'bettershield' ) }
			badge={ <OnOff on={ enabled && ! collision } /> }
		>
			{ state.enabled ? (
				<>
					<div className="bs-ds-surface__address">
						{ /* The address inside the status line, so focus landing here reads both. */ }
						<p className="bs-ds-surface__state" role="status" ref={ status } tabIndex={ -1 }>
							{ collision ? __( 'Saved, but not active:', 'bettershield' ) : __( 'Your trap page (visiting it yourself sends an alert too):', 'bettershield' ) }{ ' ' }
							<span className="bs-ds-surface__url" title={ state.url }>
								{ pathOf( state.url ) }
							</span>
						</p>
					</div>

					<span className="bs-ds-surface__actions">
						<Button type="secondary" size="sm" disabled={ working } onClick={ check }>
							{ __( 'Test It (No Alert Sent)', 'bettershield' ) }
						</Button>
						{ /* Armed, like the other controls that take a protection
						     away: the path is gone the moment this completes, and
						     the one that replaces it is a different path. */ }
						<Armed
							type="ghost"
							label={ __( 'Turn Off', 'bettershield' ) }
							consequence={ __( 'The path stops being watched and raises no alert. Setting up again gives a new path.', 'bettershield' ) }
							busy={ working }
							onConfirm={ () => save( false, '' ) }
						/>
					</span>

					{ /* Something published at the path since it was saved is
					     shown to visitors, so the path is no longer watched. Said
					     here rather than left to an alert per reader. */ }
					{ 'sign_in' === collision ? (
						<div role="status">
							<Alert
								layout="default"
								tone="warning"
								desc={ __( 'Your sign-in address uses this path, so the decoy is not watching it. Disable it and choose another.', 'bettershield' ) }
							/>
						</div>
					) : null }
					{ 'content' === collision ? (
						<div role="status">
							<Alert
								layout="default"
								tone="warning"
								desc={ __( 'Published content now uses this path, so the decoy is not watching it. Disable it and choose another.', 'bettershield' ) }
							/>
						</div>
					) : null }
					{ null !== tested && ! collision ? (
						<div role="status">
							<Alert
								layout="default"
								tone={ tested.matched ? 'success' : 'warning' }
								desc={
									tested.matched
										? __( 'The saved path is recognized. No public request or alert was sent.', 'bettershield' )
										: __( 'The saved path was not recognized. Reload and check it.', 'bettershield' )
								}
							/>
						</div>
					) : null }
				</>
			) : (
				<>
					<p className="screen-reader-text" role="status" ref={ status } tabIndex={ -1 }>
						{ __( 'No trap page is set.', 'bettershield' ) }
					</p>
					<Field
						label={ __( 'Trap page address', 'bettershield' ) }
						help={ __( 'a–z, 0–9 or hyphens, starting with a letter.', 'bettershield' ) }
						error={ refusal }
						value={ slug }
						placeholder="private-export-review"
						onChange={ ( next ) => {
							setSlug( next );
							setRefusal( '' );
						} }
						disabled={ working }
						maxLength={ 80 }
						autoCapitalize="off"
						spellCheck={ false }
					/>
					<div>
						<Button type="secondary" size="sm" disabled={ working || ! slug } isBusy={ working } onClick={ () => save( true, slug ) }>
							{ __( 'Turn On Trap Page', 'bettershield' ) }
						</Button>
					</div>
				</>
			) }
		</SettingRow>
	);
}

/** A trap page's address as its path, as the reader would type it after the site's own. */
function pathOf( url ) {
	try {
		return new URL( url ).pathname;
	} catch ( error ) {
		return String( url || '' );
	}
}

/** Where a credential is kept, said in words rather than in a storage term. */
const SOURCES = {
	database: () => __( 'in this site’s database', 'bettershield' ),
	env: () => __( 'in an environment variable', 'bettershield' ),
	constant: () => __( 'in a PHP constant', 'bettershield' ),
};

/**
 * Where the saved keys are kept, said once for all of them: one place when
 * they share it, the site when they do not.
 *
 * @param {Array<Object>} configured The connectors with a key saved.
 * @return {string} The place, as a phrase that follows "saved".
 */
function keptIn( configured ) {
	const places = Array.from( new Set( configured.map( ( connector ) => connector.storage_source ) ) );

	if ( 1 === places.length ) {
		if ( 'database' === places[ 0 ] ) {
			return __( 'in the database', 'bettershield' );
		}

		if ( SOURCES[ places[ 0 ] ] ) {
			return SOURCES[ places[ 0 ] ]();
		}
	}

	return __( 'on this site', 'bettershield' );
}

/**
 * One finding of the last card: its name and a state word, the sentence
 * under them, then a line per thing found.
 */
function Found( { title, badge, about = null, children = null } ) {
	return (
		<div className="bs-ds-surface__found">
			<div className="bs-ds-surface__foundhead">
				<h3 className="bs-ds-surface__foundtitle">{ title }</h3>
				{ badge }
			</div>
			{ about ? <p className="bs-ds-surface__line">{ about }</p> : null }
			{ children }
		</div>
	);
}

/**
 * Other plugins' MCP servers on this site, read from the REST routes (#1877):
 * the route, the plugin it belongs to, whether it answers without signing
 * in, and whether that plugin has a published advisory. Nothing is called,
 * and nothing here changes another plugin.
 */
function McpServers( { endpoints } ) {
	const list = endpoints || [];
	const open = list.filter( ( endpoint ) => endpoint.open ).length;

	let badge = <Badge tone={ kindTone( 'good' ) }>{ __( 'None found', 'bettershield' ) }</Badge>;
	let about = null;

	if ( list.length ) {
		badge = open ? (
			<Badge tone={ kindTone( 'high' ) }>
				{ sprintf(
					/* translators: %d: how many endpoints accept calls without signing in. */
					__( '%d open', 'bettershield' ),
					open
				) }
			</Badge>
		) : (
			<Badge>
				{ sprintf(
					/* translators: %d: how many endpoints other plugins run. */
					__( '%d found', 'bettershield' ),
					list.length
				) }
			</Badge>
		);
		about = open
			? sprintf(
					/* translators: 1: how many endpoints accept calls without signing in, 2: how many there are. */
					_n( '%1$d of %2$d accepts calls without signing in.', '%1$d of %2$d accept calls without signing in.', open, 'bettershield' ),
					open,
					list.length
			  )
			: sprintf(
					/* translators: %d: how many endpoints other plugins run. */
					_n( '%d endpoint from another plugin. It asks callers to sign in.', '%d endpoints from other plugins. Each asks callers to sign in.', list.length, 'bettershield' ),
					list.length
			  );
	}

	return (
		<Found title={ __( 'Other plugins’ AI connections', 'bettershield' ) } badge={ badge } about={ about }>
			{ list.length ? (
				<ul className="bs-ds-surface__items" aria-label={ __( 'Other plugins’ AI connections', 'bettershield' ) }>
					{ list.map( ( endpoint ) => (
						<li key={ endpoint.route } className="bs-ds-surface__item">
							<span className="bs-ds-surface__itemtext">
								<span className="bs-ds-surface__route">{ endpoint.route }</span>
								<span className="bs-ds-surface__where">
									<span>{ endpoint.owner_label }</span>
									{ endpoint.advisory ? <span>{ __( 'has a published advisory', 'bettershield' ) }</span> : null }
								</span>
							</span>
							{ endpoint.open ? (
								<Badge tone={ kindTone( 'high' ) }>{ __( 'anyone, no sign-in', 'bettershield' ) }</Badge>
							) : endpoint.sign_in ? (
								// OAuth discovery and sign-in steps have to answer a caller with no token (#2939).
								<Badge>{ __( 'sign-in route', 'bettershield' ) }</Badge>
							) : endpoint.not_mcp ? (
								// Let a stranger through but gave no AI-connection answer, so it asks for no sign-in either.
								<Badge>{ __( 'not an AI connection', 'bettershield' ) }</Badge>
							) : (
								<Badge>{ __( 'signed-in users only', 'bettershield' ) }</Badge>
							) }
						</li>
					) ) }
				</ul>
			) : null }
		</Found>
	);
}

/**
 * Connector credentials, and who can read them.
 *
 * Every sentence here is a statement of how WordPress works — not an
 * accusation about a connector, and not a warning. Core masks these values in
 * its own REST responses, so "readable over the API" would be false. What is
 * true is that the credential is an option, a variable or a constant, and
 * every plugin running here can read all three directly — no route involved.
 */
function Connectors( { report } ) {
	// Absent below the version that has connectors at all, rather than a
	// placeholder promising a feature that is gated on the platform.
	if ( ! report || ! report.available ) {
		return null;
	}

	const configured = report.connectors.filter( ( c ) => c.configured );
	/*
	 * The list holds every connector that takes a key, a log service or a
	 * spam filter as much as an AI service, so the row names the services
	 * whose keys are saved rather than calling them all AI keys. Each
	 * plural follows its own number (#2663).
	 */
	const plugins = Number( report.readable_by_plugin_count ) || 0;
	const readers =
		1 === configured.length
			? sprintf(
					/* translators: %d: how many plugins are active. */
					_n( 'The %d active plugin can read it.', 'All %d active plugins can read it.', plugins, 'bettershield' ),
					plugins
			  )
			: sprintf(
					/* translators: %d: how many plugins are active. */
					_n( 'The %d active plugin can read them.', 'All %d active plugins can read them.', plugins, 'bettershield' ),
					plugins
			  );

	return (
		<Found
			title={ __( 'Stored service keys', 'bettershield' ) }
			badge={
				configured.length ? (
					<Badge tone={ kindTone( 'medium' ) }>
						{ sprintf(
							/* translators: %d: how many service keys are saved. */
							_n( '%d key saved', '%d keys saved', configured.length, 'bettershield' ),
							configured.length
						) }
					</Badge>
				) : (
					<Badge tone={ kindTone( 'good' ) }>{ __( 'None saved', 'bettershield' ) }</Badge>
				)
			}
			about={
				configured.length
					? sprintf(
							/* translators: 1: the services whose keys are saved, e.g. "OpenAI and Elastic", 2: where they are kept, e.g. "in the database", 3: who can read them. */
							_n( 'A key for %1$s is saved %2$s. %3$s', 'Keys for %1$s are saved %2$s. %3$s', configured.length, 'bettershield' ),
							listOf( configured.map( ( connector ) => connector.label ) ),
							keptIn( configured ),
							readers
					  )
					: null
			}
		>
			{ /* The saved keys only: the ones not set are said by the badge,
			     not as rows of "Not Set" (#2569, #2663). */ }
			{ configured.length ? (
				<ul className="bs-ds-surface__items" aria-label={ __( 'Connector credentials', 'bettershield' ) }>
					{ configured.map( ( connector ) => (
						<li key={ connector.id } className="bs-ds-surface__item bs-ds-surface__connector">
							<span className="bs-ds-surface__itemtext">
								<span className="bs-ds-surface__route">{ connector.label }</span>
								<span className="bs-ds-surface__where">
									{ SOURCES[ connector.storage_source ] ? <span>{ SOURCES[ connector.storage_source ]() }</span> : null }
									{ /* Four characters, so one key can be told from
									     another. Never more, whoever is asking. */ }
									{ connector.key_hint ? <span>{ '…' + connector.key_hint }</span> : null }
								</span>
							</span>
							<Badge>{ 'database' === connector.storage_source ? __( 'Unencrypted', 'bettershield' ) : __( 'Saved', 'bettershield' ) }</Badge>
						</li>
					) ) }
				</ul>
			) : null }
		</Found>
	);
}

/** How many application passwords the site holds, said as the card's badge. */
function passwordCount( holders ) {
	const count = holders.reduce( ( sum, holder ) => sum + ( Number( holder.count ) || 0 ), 0 );

	return count ? <Badge>{ count }</Badge> : <Badge>{ __( 'None', 'bettershield' ) }</Badge>;
}

/**
 * The Surface tab before the surface document has landed: the strip, then
 * the inventory beside the cards of everything else that can reach the site.
 */
function SurfaceBone() {
	return (
		<Skeleton label={ __( 'Loading the agent surface…', 'bettershield' ) }>
			<AgentStripBone />
			<div className="bs-ds-surface__grid">
				<div className="bs-ds-surface__main">
					<CardBone rows={ [ '40%', '55%', '35%', '50%', '30%' ] } />
				</div>
				<div className="bs-ds-surface__side">
					<CardBone rows={ [ '60%', '45%' ] } toggle />
					<CardBone rows={ [ '50%', '35%', '45%' ] } toggle />
					<CardBone rows={ [ '55%', '40%' ] } />
				</div>
			</div>
		</Skeleton>
	);
}

export default function Surface() {
	const { resource, reload } = useResource( 'agentSurface' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <SurfaceBone /> }>
			{ ( data ) => {
				const holders = data.application_passwords || [];
				const traps = ( data.canary ? 1 : 0 ) + ( data.decoy_page?.enabled && ! data.decoy_page?.collision ? 1 : 0 );

				return (
					<>
						<AgentStrip surface={ data } />
						<div className="bs-ds-surface__grid">
							<div className="bs-ds-surface__main">
								<NewSinceUpdate changes={ data.ability_changes } />
								<Abilities available={ data.abilities_api_available } abilities={ data.abilities || [] } pending={ pendingOf( data.ability_changes ) } />
							</div>

							{ /*
							   Then what else can reach this site, in the order a
							   reader meets it: the credentials that exist and the
							   sweep that retires the forgotten ones, the two traps
							   that exist to be found, and what other plugins open
							   or keep.
							*/ }
							<div className="bs-ds-surface__side">
								<Tray icon="info" wrap note={ __( 'Each removal is logged by name.', 'bettershield' ) }>
									<Card className="bs-ds-surface__card bs-ds-settings" aria-labelledby="bs-ds-passwords-title">
										<CardHead icon="key-round" id="bs-ds-passwords-title" title={ __( 'Application passwords', 'bettershield' ) }>
											{ passwordCount( holders ) }
										</CardHead>
										<Retirement expiry={ data.expiry } minDays={ Number( data.expiry_min_days ) || 30 } />
										<PasswordList holders={ holders } />
									</Card>
								</Tray>

								<Tray icon="info" wrap note={ __( 'If anyone touches a trap, you get an alert.', 'bettershield' ) }>
									<Card className="bs-ds-surface__card bs-ds-settings" aria-labelledby="bs-ds-traps-title">
										<CardHead icon="globe" id="bs-ds-traps-title" title={ __( 'Traps', 'bettershield' ) }>
											<Badge tone={ traps ? kindTone( 'on' ) : 'neutral' }>
												{ sprintf(
													/* translators: %d: how many of the two traps are on. */
													__( '%d of 2 on', 'bettershield' ),
													traps
												) }
											</Badge>
										</CardHead>
										<Decoy canary={ data.canary } used={ data.canary_use || null } />
										<DecoyUrl state={ data.decoy_page } />
									</Card>
								</Tray>

								<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-ways-title">
									<CardHead icon="shield-check" id="bs-ds-ways-title" title={ __( 'Other ways in, checked', 'bettershield' ) } />
									{ /* The other doors an agent can use: other plugins'
									     own MCP servers (#1877), and the keys their
									     connectors hold. */ }
									<McpServers endpoints={ data.mcp_endpoints } />
									<Connectors report={ data.connectors } />
								</Card>
							</div>
						</div>
					</>
				);
			} }
		</Resource>
	);
}
