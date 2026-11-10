/**
 * Agents › Surface: what agents *can* do here, as distinct from what they did.
 *
 * A fact sheet, and the last tab for that reason: most owners read it once.
 * It states platform facts. "Three plugins expose write abilities over REST"
 * is information; a row becomes a warning only when it is a finding, and then
 * it carries the finding's severity, not the screen's tone.
 *
 * The inventory is grouped by the plugin that registered each ability, because
 * with several plugins installed the flat list ran to ninety rows and the
 * question it exists to answer — is anything open to lower roles — was
 * somewhere inside them. This plugin's own group is open; every other is a row
 * with a name and a count until somebody asks.
 *
 * The agent strip, then two cards: the inventory as one table (All and Open to
 * lower roles as tabs, the search at the tab row's end, a group row per
 * registering plugin), and a card of rows for everything else that can reach
 * this site.
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
import { Card, CardHead } from '../ui/Card';
import Field, { FieldRow } from '../ui/Field';
import { focusIfLost } from '../ui/focus';
import Icon from '../ui/Icon';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { EmptyState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Tabs from '../ui/Tabs';
import { panelProps } from '../ui/tabKeys';
import Topics from '../ui/Topics';
import AgentStrip, { AgentStripBone } from './AgentStrip';
import SwitchLine from './SwitchLine';

/** The one filter that crosses every group: everything, or what is open. */
const ALL = '__all';
const OPEN = '__open';

/** Rows one page of a group carries. */
const PER_PAGE = 25;

/** The namespace this plugin registers under, which is what makes a group ours. */
const OURS = 'bettershield/';

/** The id the inventory's tabs and the table under them share. */
const TABS_ID = 'bs-ds-abilities';

/**
 * The inventory, folded into one group per registering plugin.
 *
 * Ours first and open, the rest by name and collapsed. Sorting by the name a
 * plugin gives itself rather than by its directory is what makes the list read
 * as a shelf of plugins instead of a list of slugs.
 *
 * @param {Array<Object>} abilities Every ability the registry holds.
 * @return {Array<Object>} One entry per registering plugin.
 */
function groupsOf( abilities ) {
	const groups = new Map();

	abilities.forEach( ( ability ) => {
		const key = ability.registering_source;

		if ( ! groups.has( key ) ) {
			groups.set( key, {
				source: key,
				label: ability.registering_source_label || key,
				ours: false,
				abilities: [],
			} );
		}

		const group = groups.get( key );

		group.abilities.push( ability );

		// Read off the ability's own namespace rather than off a directory
		// name, which is whatever the site happened to install this under.
		if ( String( ability.name || '' ).startsWith( OURS ) ) {
			group.ours = true;
		}
	} );

	return Array.from( groups.values() ).sort( ( a, b ) => {
		if ( a.ours !== b.ours ) {
			return a.ours ? -1 : 1;
		}

		return a.label.localeCompare( b.label );
	} );
}

/**
 * Who can call an ability: the column this whole inventory exists for.
 *
 * @param {Object} props
 * @param {string} props.access allowed, denied, or anything else for not known.
 */
function AccessBadge( { access } ) {
	if ( 'allowed' === access ) {
		return <Badge tone={ kindTone( 'medium' ) }>{ __( 'non-admins', 'bettershield' ) }</Badge>;
	}

	if ( 'denied' === access ) {
		return <Badge tone={ kindTone( 'neutral' ) }>{ __( 'admins only', 'bettershield' ) }</Badge>;
	}

	return <Badge tone={ kindTone( 'muted' ) }>{ __( 'unknown', 'bettershield' ) }</Badge>;
}

/**
 * What an ability declares it would do.
 *
 * @param {Object}  props
 * @param {boolean} props.readonly Whether it declares itself read-only.
 */
function DeclaresBadge( { readonly } ) {
	return readonly ? (
		<Badge tone={ kindTone( 'good' ) }>{ __( 'views only', 'bettershield' ) }</Badge>
	) : (
		<Badge tone={ kindTone( 'high' ) }>{ __( 'changes site', 'bettershield' ) }</Badge>
	);
}

/**
 * One plugin's abilities: its group row, opening in place, then its rows a
 * page at a time.
 *
 * The rows are a group of the one table under the tab row, named for the
 * plugin, so every group shares the table's columns and its one header.
 */
function AbilityGroup( { group, rows, open, onToggle } ) {
	const [ shown, setShown ] = useState( PER_PAGE );
	const page = rows.slice( 0, shown );

	return (
		<>
			<WholeRow kind="group">
				<button type="button" className="bs-ds-surface__grouphead" aria-expanded={ open } onClick={ onToggle }>
					<Icon name="plug" size={ 14 } tone="2" />
					<span className="bs-ds-surface__groupname">{ group.label }</span>
					<Badge className="bs-ds-surface__groupcount">{ rows.length }</Badge>
					<span className="bs-ds-spacer" />
					{ /* The one mark that says "this opens", turned when it has. */ }
					<Icon name="chevron-down" size={ 14 } tone="3" className="bs-ds-surface__chevron" />
				</button>
			</WholeRow>

			{ open ? (
				<div
					className="bs-ds-surface__rows"
					role="rowgroup"
					aria-label={ sprintf(
						/* translators: %s: the name of the plugin that registered them. */
						__( 'Abilities registered by %s', 'bettershield' ),
						group.label
					) }
				>
					{ page.map( ( ability ) => (
						<Row key={ ability.name } className="bs-ds-surface__row">
							<Cell>
								<span className="bs-ds-surface__name">{ ability.name }</span>
							</Cell>
							<Cell>
								<span className="bs-ds-surface__by">{ ability.registering_source_label || ability.registering_source }</span>
							</Cell>
							<Cell className="bs-ds-surface__chips">
								<DeclaresBadge readonly={ ability.annotated_readonly } />
								{ ability.exposed_in_rest ? <Badge tone={ kindTone( 'neutral' ) }>{ __( 'REST', 'bettershield' ) }</Badge> : null }
								<AccessBadge access={ ability.low_privilege_access } />
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
 * were last accepted (#1878): each with its plugin and what it now does, and
 * Accept, which takes the abilities as they are now as the baseline.
 *
 * @param {Object} props
 * @param {Array}  props.changes The changes waiting.
 */
function NewSinceUpdate( { changes } ) {
	const { acceptAbilityChanges, undoAbilityAccept, load, busy } = useStore();
	const [ said, setSaid ] = useState( '' );
	// The accept's undo record, while its Undo is on offer.
	const [ undo, setUndo ] = useState( '' );

	const putBack = () =>
		undoAbilityAccept( undo, ( answer ) => {
			if ( answer ) {
				setUndo( '' );
				setSaid( __( 'These changes are waiting for you again.', 'bettershield' ) );
				load( 'agentSurface', { force: true } );
			}
		} );

	if ( ! changes || ! changes.length ) {
		return said ? (
			<div className="bs-ds-surface__notes">
				<p className="bs-ds-surface__intro" role="status">
					{ said }
				</p>
				{ undo ? (
					<div>
						<Button type="secondary" size="sm" isBusy={ 'ability-accept-undo' === busy } disabled={ Boolean( busy ) } onClick={ putBack }>
							{ __( 'Undo', 'bettershield' ) }
						</Button>
					</div>
				) : null }
			</div>
		) : null;
	}

	const accept = () =>
		acceptAbilityChanges( ( answer ) => {
			setUndo( ( answer && answer.undo ) || '' );
			setSaid( __( 'Reviewed. Only new changes will show here after the next update.', 'bettershield' ) );
			load( 'agentSurface', { force: true } );
		} );

	return (
		<div className="bs-ds-surface__notes">
			<Alert
				layout="default"
				tone="warning"
				title={ __( 'New since your last update', 'bettershield' ) }
				desc={ __( 'A plugin update or a new plugin added these AI actions or opened them to more people. Nothing was blocked.', 'bettershield' ) }
			/>
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
							{ change.readonly ? null : <Badge tone={ kindTone( 'high' ) }>{ __( 'changes site', 'bettershield' ) }</Badge> }
							{ change.open ? <Badge tone={ kindTone( 'medium' ) }>{ __( 'non-admins', 'bettershield' ) }</Badge> : null }
						</Cell>
					</Row>
				) ) }
			</Table>
			<div>
				<Button type="secondary" size="sm" isBusy={ 'ability-accept' === busy } disabled={ Boolean( busy ) } onClick={ accept }>
					{ __( 'Mark As Reviewed', 'bettershield' ) }
				</Button>
			</div>
		</div>
	);
}

function Abilities( { available, abilities, changes = [] } ) {
	const [ filter, setFilter ] = useState( ALL );
	const [ search, setSearch ] = useState( '' );
	// Which groups the reader has opened or closed by hand. Anything absent
	// follows the default: ours open, everybody else's shut.
	const [ opened, setOpened ] = useState( {} );

	if ( ! available ) {
		return (
			<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-abilities-title">
				<CardHead icon="bot" id="bs-ds-abilities-title" title={ __( 'Actions plugins offer to AI', 'bettershield' ) } />
				<div className="bs-ds-surface__notes">
					<Alert layout="default" tone="info" desc={ __( 'Abilities require WordPress 6.9.', 'bettershield' ) } />
				</div>
			</Card>
		);
	}

	const isOpenToLowerRoles = ( ability ) => 'allowed' === ability.low_privilege_access;
	const needle = search.trim().toLowerCase();
	const matches = ( ability ) =>
		( ALL === filter || isOpenToLowerRoles( ability ) ) &&
		( '' === needle || String( ability.name || '' ).toLowerCase().includes( needle ) );

	// Whether the reader is looking at a subset rather than at everything.
	const narrowed = ALL !== filter || '' !== needle;
	const groups = groupsOf( abilities );
	const shown = groups
		.map( ( group ) => ( { group, rows: group.abilities.filter( matches ) } ) )
		.filter( ( entry ) => entry.rows.length > 0 );

	const counts = {
		[ ALL ]: abilities.length,
		[ OPEN ]: abilities.filter( isOpenToLowerRoles ).length,
	};

	return (
		<Card className="bs-ds-surface__card" aria-labelledby="bs-ds-abilities-title">
			<CardHead icon="bot" id="bs-ds-abilities-title" title={ __( 'Actions plugins offer to AI', 'bettershield' ) } />
			<NewSinceUpdate changes={ changes } />
			<p className="bs-ds-surface__intro">
				{ __(
					'Every action your plugins let AI assistants use.',
					'bettershield'
				) }
			</p>
			<div className="bs-ds-surface__notes">
				<Topics
					items={ [
						{
							key: 'who',
							label: __( 'What to look for', 'bettershield' ),
							lead: __( 'Who can use it.', 'bettershield' ),
							text: __(
								'It is flagged when it can change your site, can be used from outside, and is open to non-admins.',
								'bettershield'
							),
						},
					] }
				/>
			</div>

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
								className="bs-ds-tbl--grouped"
								columns={ [
									{ key: 'name', label: __( 'Ability', 'bettershield' ) },
									{ key: 'by', label: __( 'Registered by', 'bettershield' ), width: '160px' },
									{ key: 'what', label: __( 'Can change site · Used from · Who can use it', 'bettershield' ), width: '240px' },
								] }
							>
								{ shown.map( ( entry ) => (
									<AbilityGroup
										key={ entry.group.source }
										group={ entry.group }
										rows={ entry.rows }
										/*
										 * A list being narrowed hides nothing that
										 * survived the narrowing: a search or a
										 * filter whose matches stay inside a shut
										 * group is one that answers nothing. So
										 * everything left open is open — unless the
										 * reader has said otherwise about it.
										 */
										open={
											undefined === opened[ entry.group.source ]
												? entry.group.ours || narrowed
												: opened[ entry.group.source ]
										}
										onToggle={ () =>
											setOpened( ( state ) => ( {
												...state,
												[ entry.group.source ]:
													undefined === state[ entry.group.source ]
														? ! ( entry.group.ours || narrowed )
														: ! state[ entry.group.source ],
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
				<EmptyState>
					{ __(
						'No plugin offers AI actions yet.',
						'bettershield'
					) }
				</EmptyState>
			) }
		</Card>
	);
}

/**
 * One application password: its row, and the form that holds it to routes and
 * a network, opening under the row.
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
				</Cell>
				<Cell>
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
									<Button type="ghost" size="sm" disabled={ working } onClick={ open }>
										{ __( 'Set Limits', 'bettershield' ) }
									</Button>
									{ limit ? (
										<Button type="ghost" size="sm" isBusy={ working } disabled={ working } onClick={ remove }>
											{ __( 'Remove Limit', 'bettershield' ) }
										</Button>
									) : null }
									{ undo ? (
										<Button
											type="ghost"
											size="sm"
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
						<FieldRow>
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
						</FieldRow>
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

/**
 * The application passwords every account holds: a row saying what they are,
 * then a table of them, a group row per account.
 */
function ApplicationPasswords( { holders } ) {
	return (
		<>
			<SettingRow
				title={ __( 'Application passwords', 'bettershield' ) }
				about={ __( 'Every application password on the site, for every user.', 'bettershield' ) }
				topics={ [
					{
						key: 'stale',
						label: __( 'Unused', 'bettershield' ),
						lead: __( 'Not used for 90 days, but still works.', 'bettershield' ),
						note: {
							tone: 'info',
							text: __( 'Its owner can revoke it from their profile.', 'bettershield' ),
						},
					},
				] }
			/>

			{ holders.length ? (
				<Table
					label={ __( 'Application passwords', 'bettershield' ) }
					columns={ [
						{ key: 'name', label: __( 'Name', 'bettershield' ) },
						{ key: 'access', label: __( 'Access', 'bettershield' ) },
					] }
				>
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
			) : (
				<EmptyState>
					{ __( 'No application passwords are in use. Assistants connected here are listed on Connect.', 'bettershield' ) }
				</EmptyState>
			) }
		</>
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
 * plugin does — a revoked password cannot be put back, because the secret was
 * never stored. Saying so is not a disclaimer; it is the difference between an
 * owner switching this on knowingly and finding out at three in the morning.
 */
function Retirement( { expiry, minDays } ) {
	const { saveAppPasswordExpiry, busy } = useStore();
	const saving = busy === 'app-password-expiry';
	const [ draft, setDraft ] = useState( null );
	const value = draft || expiry;
	// A refused day count is said under the field, not in the page banner
	// far above it (#2664).
	const [ refusal, setRefusal ] = useState( '' );
	const sayRefusal = ( error ) => {
		setRefusal( error?.message || '' );

		return Boolean( error?.message );
	};

	return (
		<SettingRow
			title={ __( 'Delete unused app passwords', 'bettershield' ) }
			about={ __(
				'Checked once a day; unused ones are deleted.',
				'bettershield'
			) }
		>
			<Alert
				layout="default"
				tone="warning"
				desc={ __( 'Can’t be undone: the tool using it will need a new password. Each removal is logged by name.', 'bettershield' ) }
			/>

			<SwitchLine
				label={ sprintf(
					/* translators: %d: the saved number of days a password may go unused. */
					_n( 'Delete application passwords unused for %d day', 'Delete application passwords unused for %d days', Number( expiry.days ) || 0, 'bettershield' ),
					Number( expiry.days ) || 0
				) }
				checked={ value.enabled }
				disabled={ saving }
				/*
				 * The saved value, not the draft. A half-typed day count in
				 * the field below is refused by the server, so somebody who
				 * had started editing it could not turn the switch off at all
				 * until they corrected a number they were no longer using.
				 */
				onChange={ ( enabled ) => saveAppPasswordExpiry( { ...expiry, enabled }, () => setRefusal( '' ), sayRefusal ) }
			>
				<Saved forKey="app-password-expiry" />
			</SwitchLine>

			{ value.enabled ? (
				// Along the top: the field carries a help line, and lined up
				// along the bottom Save sat beside that line, not the input.
				<FieldRow align="start">
					<Field
						type="number"
						width="md"
						min={ minDays }
						max={ 3650 }
						label={ __( 'Unused for (days)', 'bettershield' ) }
						help={ __( 'Counted from last use, or from creation if never used.', 'bettershield' ) }
						error={ refusal }
						value={ String( value.days ) }
						disabled={ saving }
						onChange={ ( days ) => {
							setDraft( { ...value, days } );
							setRefusal( '' );
						} }
					/>
					<Button
						type="secondary"
						size="sm"
						isBusy={ saving }
						disabled={ saving || ! draft }
						onClick={ () =>
							// Cleared only once saved, and passed in so it
							// still runs after a password confirmation. A
							// refusal raises the banner; clearing the draft
							// then would snap the field back and lose what
							// was typed.
							saveAppPasswordExpiry(
								{ ...value, days: Number( value.days ) },
								() => {
									setDraft( null );
									setRefusal( '' );
								},
								sayRefusal
							)
						}
					>
						{ __( 'Save', 'bettershield' ) }
					</Button>
				</FieldRow>
			) : null }
		</SettingRow>
	);
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
function Decoy( { canary, name, used } ) {
	const { setCanary, busy } = useStore();
	const working = busy === 'canary';
	// A refusal said under the switch, not in the page banner (#2664).
	const [ refusal, setRefusal ] = useState( '' );

	return (
		<SettingRow
			title={ __( 'Trap password', 'bettershield' ) }
			about={ __( 'A fake app password that no one should use. If anyone tries it, you get an alert, as it means your database or a backup was copied.', 'bettershield' ) }
			meta={ sprintf(
				/* translators: %s: the name the decoy appears under. */
				__( 'It shows on your profile as “%s”. Using it yourself also sends an alert.', 'bettershield' ),
				name
			) }
		>
			<SwitchLine
				label={ __( 'Keep a trap password on my account', 'bettershield' ) }
				checked={ !! canary }
				disabled={ working }
				onChange={ ( plant ) => {
					setRefusal( '' );
					setCanary( plant, ( error ) => {
						setRefusal( error?.message || '' );

						return Boolean( error?.message );
					} );
				} }
			>
				<Saved forKey="canary" />
			</SwitchLine>
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
						actions={
							<Button type="secondary" size="sm" href={ tabUrl( 'bettershield-activity', 'site' ) }>
								{ __( 'See It in Activity', 'bettershield' ) }
							</Button>
						}
					/>
				</div>
			) : null }
			{ canary && ! used ? (
				<p className="bs-ds-surface__line" role="status">
					{ sprintf(
						/* translators: %s: date and time. */
						__( 'Added %s. No one has tried it.', 'bettershield' ),
						formatTime( canary.planted_at )
					) }
				</p>
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

	const check = () =>
		testDecoyPage( ( result ) => setTested( { matched: Boolean( result?.matched ), collision: result?.collision || '' } ) );

	return (
		<SettingRow
			title={ __( 'Trap page', 'bettershield' ) }
			about={ __( 'A hidden address no real visitor would open. If someone does, you get an alert.', 'bettershield' ) }
			topics={ [
				{
					key: 'path',
					label: __( 'How this works', 'bettershield' ),
					text: __(
						'It shows your normal 404 page. A visit can be a scanner or an accident, not proof of compromise.',
						'bettershield'
					),
					points: [
						__( 'Choose a path nothing uses.', 'bettershield' ),
						__( 'Only requests that reach WordPress are seen; server rules and edge caches can bypass it.', 'bettershield' ),
						__( 'Repeat visits alert at most once a minute.', 'bettershield' ),
					],
				},
			] }
		>
			<p className="bs-ds-surface__state" role="status" ref={ status } tabIndex={ -1 }>
				{ state.enabled ? (
					<>
						{ collision
							? __( 'Saved, but not active:', 'bettershield' )
							: __( 'Your trap page (visiting it yourself sends an alert too):', 'bettershield' ) }{ ' ' }
						<span className="bs-ds-surface__url">{ state.url }</span>
					</>
				) : (
					__( 'No trap page is set.', 'bettershield' )
				) }
			</p>

			{ state.enabled ? (
				<>
					<span className="bs-ds-surface__actions">
						<Button type="secondary" size="sm" disabled={ working } onClick={ check }>
							{ __( 'Test It (No Alert Sent)', 'bettershield' ) }
						</Button>
						{ /* Armed, like the other controls that take a protection
						     away: the path is gone the moment this completes, and
						     the one that replaces it is a different path. */ }
						<Armed
							type="ghost"
							label={ __( 'Turn Off Trap Page', 'bettershield' ) }
							consequence={ __(
								'The path stops being watched and raises no alert. Setting up again gives a new path.',
								'bettershield'
							) }
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
								desc={ __(
									'Your sign-in address uses this path, so the decoy is not watching it. Disable it and choose another.',
									'bettershield'
								) }
							/>
						</div>
					) : null }
					{ 'content' === collision ? (
						<div role="status">
							<Alert
								layout="default"
								tone="warning"
								desc={ __(
									'Published content now uses this path, so the decoy is not watching it. Disable it and choose another.',
									'bettershield'
								) }
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
										? __(
												'The saved path is recognized. No public request or alert was sent.',
												'bettershield'
										  )
										: __( 'The saved path was not recognized. Reload and check it.', 'bettershield' )
								}
							/>
						</div>
					) : null }
				</>
			) : (
				<FieldRow align="start">
					<Field
						label={ __( 'Trap page address', 'bettershield' ) }
						help={ __( '8–80 lowercase letters, digits or hyphens, starting with a letter. Example: private-export-review', 'bettershield' ) }
						error={ refusal }
						value={ slug }
						onChange={ ( next ) => {
							setSlug( next );
							setRefusal( '' );
						} }
						disabled={ working }
						maxLength={ 80 }
						autoCapitalize="off"
						spellCheck={ false }
					/>
					<Button type="secondary" size="sm" disabled={ working || ! slug } isBusy={ working } onClick={ () => save( true, slug ) }>
						{ __( 'Turn On Trap Page', 'bettershield' ) }
					</Button>
				</FieldRow>
			) }
		</SettingRow>
	);
}

/** Where a credential is kept, said in words rather than in a storage term. */
const SOURCES = {
	database: () => __( 'in this site’s database', 'bettershield' ),
	env: () => __( 'in an environment variable', 'bettershield' ),
	constant: () => __( 'in a PHP constant', 'bettershield' ),
};

/**
 * Other plugins' MCP servers on this site, read from the REST routes (#1877):
 * the route, the plugin it belongs to, whether it answers without signing
 * in, and whether that plugin has a published advisory. Nothing is called,
 * and nothing here changes another plugin.
 */
function McpServers( { endpoints } ) {
	const list = endpoints || [];
	const open = list.filter( ( endpoint ) => endpoint.open ).length;

	let about = __( 'No other plugin lets AI assistants connect here.', 'bettershield' );

	if ( list.length ) {
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
		<>
			<SettingRow
				title={ __( 'Other plugins’ AI connections', 'bettershield' ) }
				about={ about }
				topics={ [
					{
						key: 'how',
						label: __( 'How this works', 'bettershield' ),
						text: __( 'Other plugins that let AI assistants connect. Any that don’t ask for a sign-in are flagged.', 'bettershield' ),
					},
				] }
			/>

			{ list.length ? (
				<Table
					label={ __( 'Other plugins’ AI connections', 'bettershield' ) }
					columns={ [
						{ key: 'route', label: __( 'Route', 'bettershield' ) },
						{ key: 'who', label: __( 'Who can call it', 'bettershield' ), width: '200px' },
					] }
				>
					{ list.map( ( endpoint ) => (
						<Row key={ endpoint.route } className="bs-ds-surface__connector">
							<Cell>
								<TitleMeta
									title={ endpoint.route }
									meta={
										<span className="bs-ds-surface__where">
											<span>{ endpoint.owner_label }</span>
											{ endpoint.advisory ? <span>{ __( 'has a published advisory', 'bettershield' ) }</span> : null }
										</span>
									}
								/>
							</Cell>
							<Cell>
								{ endpoint.open ? (
									<Badge tone={ kindTone( 'high' ) }>{ __( 'anyone, no sign-in', 'bettershield' ) }</Badge>
								) : (
									<Badge tone={ kindTone( 'neutral' ) }>{ __( 'signed-in users only', 'bettershield' ) }</Badge>
								) }
							</Cell>
						</Row>
					) ) }
				</Table>
			) : null }
		</>
	);
}

/**
 * Connector credentials, and who can read them.
 *
 * This row is the one that proves the positioning, and it only works if the
 * tone is right. Every sentence here is a statement of how WordPress works —
 * not an accusation about a connector, and not a warning. An owner who reads
 * it and feels informed will act; one who feels alarmed will dismiss it.
 *
 * The claim is also deliberately narrow. Core masks these values in its own
 * REST responses, so "readable over the API" would be false. What is true is
 * that the credential is an option, a variable or a constant, and every plugin
 * running here can read all three directly — no route involved.
 */
function Connectors( { report, referenceUrl } ) {
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
		<>
			<SettingRow
				title={ __( 'Stored service keys', 'bettershield' ) }
				about={
					configured.length
						? sprintf(
								/* translators: 1: the services whose keys are saved, e.g. "OpenAI and Elastic", 2: who can read them. */
								_n( 'A key for %1$s is saved on this site. %2$s', 'Keys for %1$s are saved on this site. %2$s', configured.length, 'bettershield' ),
								listOf( configured.map( ( connector ) => connector.label ) ),
								readers
						  )
						: __( 'No service key is saved on this site.', 'bettershield' )
				}
				topics={ [
					{
						key: 'how',
						label: __( 'How this works', 'bettershield' ),
						text: report.advisory,
						body: (
							<p>
								<Button type="link" size="sm" href={ referenceUrl } target="_blank" rel="noopener noreferrer" trailing="external-link">
									{ __( 'WordPress Plans to Encrypt These Keys', 'bettershield' ) }
								</Button>
							</p>
						),
					},
				] }
			/>

			{ /* With none saved the row's one line says so: eleven rows of
			     "not set" under it said it again (#2569). */ }
			{ configured.length ? (
				<Table
					label={ __( 'Connector credentials', 'bettershield' ) }
					columns={ [
						{ key: 'name', label: __( 'Name', 'bettershield' ) },
						{ key: 'state', label: __( 'State', 'bettershield' ), width: '200px' },
					] }
				>
					{ /* The saved keys only: the ones not set are said by the
					     row's sentence, not as rows of "Not Set" (#2663). */ }
					{ configured.map( ( connector ) => (
						<Row key={ connector.id } className="bs-ds-surface__connector">
							<Cell>
								<TitleMeta
									title={ connector.label }
									meta={
										<span className="bs-ds-surface__where">
											{ connector.configured && SOURCES[ connector.storage_source ] ? <span>{ SOURCES[ connector.storage_source ]() }</span> : null }
											{ /* Four characters, so one key can be told from
											     another. Never more, whoever is asking. */ }
											{ connector.key_hint ? <span>{ '…' + connector.key_hint }</span> : null }
										</span>
									}
								/>
							</Cell>
							<Cell>
								{ /* One state word; where it is kept is said under the name. */ }
								{ connector.configured ? (
									<Badge tone={ kindTone( 'database' === connector.storage_source ? 'neutral' : 'muted' ) }>
										{ 'database' === connector.storage_source ? __( 'Unencrypted', 'bettershield' ) : __( 'Saved', 'bettershield' ) }
									</Badge>
								) : (
									<Badge tone={ kindTone( 'muted' ) }>{ __( 'Not Set', 'bettershield' ) }</Badge>
								) }
							</Cell>
						</Row>
					) ) }
				</Table>
			) : null }
		</>
	);
}

/**
 * The Surface tab before the surface document has landed: the strip, the
 * inventory, and the card of everything else that can reach the site.
 */
function SurfaceBone() {
	return (
		<Skeleton label={ __( 'Loading the agent surface…', 'bettershield' ) }>
			<AgentStripBone />
			<CardBone rows={ [ '40%', '55%', '35%' ] } />
			<CardBone rows={ [ '30%', '50%', '35%', '25%' ] } toggle />
		</Skeleton>
	);
}

export default function Surface() {
	const { resource, reload } = useResource( 'agentSurface' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <SurfaceBone /> }>
			{ ( data ) => (
				<>
					<AgentStrip surface={ data } />
					<Abilities available={ data.abilities_api_available } abilities={ data.abilities } changes={ data.ability_changes } />

					{ /*
					   Then what else can reach this site, in the order a reader
					   meets it: the credentials that exist, the sweep that
					   retires the forgotten ones, the one that exists to be
					   stolen, the path that exists to be asked for, the other
					   MCP servers on the site, and the keys another plugin's
					   connector holds.

					   One card rather than five. They are five answers to a
					   single question, and five cards made them read as five
					   unrelated settings that happened to be on the same tab —
					   which is also how somebody comes to configure the decoy
					   without ever having scrolled past it to the connector
					   keys. Inside, a row each, under the row's rule.
					*/ }
					<SettingsCard
						className="bs-ds-surface__card"
						icon="key"
						title={ __( 'Other ways in to check', 'bettershield' ) }
					>
						<ApplicationPasswords holders={ data.application_passwords } />
						<Retirement expiry={ data.expiry } minDays={ data.expiry_min_days } />
						<Decoy canary={ data.canary } name={ data.canary_name } used={ data.canary_use || null } />
						<DecoyUrl state={ data.decoy_page } />
						{ /* The other doors an agent can use: other plugins' own
						     MCP servers (#1877). */ }
						<McpServers endpoints={ data.mcp_endpoints } />
						<Connectors report={ data.connectors } referenceUrl={ data.connectors_reference } />
					</SettingsCard>
				</>
			) }
		</Resource>
	);
}
