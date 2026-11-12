/**
 * Agents › Connect: where an assistant is let in, and everything that follows.
 *
 * Top to bottom, as the other connect screens in this family read:
 *
 * - The header: the screen's state in a word, what used the connection last,
 *   and the one switch on the tab, which turns on what a connection needs.
 * - What a connected assistant can do, closed until opened: where the two
 *   opt-ins (seeing, and fixing) stand, and what no connection may ever do.
 * - Four figures: requests waiting, tools offered, connected apps, last use.
 * - Add BetterShield to your assistant: Claude and ChatGPT sign in through
 *   the browser from one address; editors and command-line tools take a
 *   configuration and a connection key, which lives at the card's foot.
 * - The apps that hold access, each with its tools and its own disconnect.
 * - Connection diagnostics, with a test that makes one real call.
 *
 * The server is part of this plugin: the assistant reaches this site's own
 * address, and the site reaches nothing new for it.
 *
 * Everything that mutates goes through the shared data layer rather than a
 * fetch of its own, so a site with the password gate on gets the same
 * challenge here that every other protected action gets, and the reply still
 * arrives on the other side of it.
 */

import './Connect.css';

import apiFetch from '@wordpress/api-fetch';
import { Fragment, useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { READ_ONLY, READ_WRITE, appScopePhrase, neverDone, prettyRoutedState, scopePhrase, testSentence } from '../../agents/phrases';
import { tabUrl } from '../../nav';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import { motionAllowed } from '../../ui/hold';
import useMutationFocus from '../../ui/useMutationFocus';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, IconTile } from '../ui/Card';
import ClientLogo from './ClientLogos';
import CopyField, { CopyButton } from '../ui/CopyField';
import Field from '../ui/Field';
import Icon from '../ui/Icon';
import InfoTip from '../ui/InfoTip';
import Segmented from '../ui/Segmented';
import Skeleton, { Bone, CardBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { EmptyState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta } from '../ui/Table';
import { onTabKey, panelId, panelProps, tabId } from '../ui/tabKeys';
import Recipe from './Recipe';
import SwitchLine from './SwitchLine';

const MCP_CONNECTION = '/bettershield/v1/mcp/connection';
const MCP_APPS = '/bettershield/v1/mcp/apps';

/** The id the two ways to connect, and the panel under them, share. */
const MODES_ID = 'bs-ds-connect-modes';

/** The id the editor tiles, and the setup under them, share. */
const CLIENTS_ID = 'bs-ds-clients';

/**
 * The assistants this screen carries a setup for, in the order they are met.
 *
 * The key is the one the reply files that client's configuration under, and
 * nothing here decides what a configuration says — a client the site has no
 * recipe for is offered the plain address rather than an empty block.
 */
const CLIENTS = [
	{ key: 'claude_remote', logo: 'claude', label: () => __( 'Claude', 'bettershield' ), note: () => __( 'Web, desktop and mobile.', 'bettershield' ) },
	{ key: 'chatgpt', logo: 'chatgpt', label: () => __( 'ChatGPT', 'bettershield' ), note: () => __( 'Copy the address, add it in ChatGPT, then approve it here.', 'bettershield' ) },
	{ key: 'claude_desktop', logo: 'claude', label: () => __( 'Claude Desktop', 'bettershield' ), note: () => __( 'Config file', 'bettershield' ) },
	{ key: 'cursor', logo: 'cursor', label: () => __( 'Cursor', 'bettershield' ), note: () => __( 'Editor', 'bettershield' ) },
	{ key: 'vscode', logo: 'vscode', label: () => __( 'VS Code', 'bettershield' ), note: () => __( 'Editor', 'bettershield' ) },
	{ key: 'codex', logo: 'codex', label: () => __( 'Codex', 'bettershield' ), note: () => __( 'Command line', 'bettershield' ) },
];

/**
 * The clients that register themselves through the browser sign-in flow.
 *
 * The rest are handed a credential and a configuration file, so what this
 * list decides is which tab a client is on: an address and an approval, or a
 * block to copy. The sign-in path also needs the pretty addresses routed,
 * which is a fact only these two have to hear.
 */
const OAUTH_CLIENTS = [ 'claude_remote', 'chatgpt' ];

const KEY_CLIENTS = CLIENTS.filter( ( entry ) => ! OAUTH_CLIENTS.includes( entry.key ) );


/**
 * How long a new connection key stays on the screen, in milliseconds. After
 * that it is dropped from memory, so a tab left open does not keep a working
 * secret one click away; replacing the key is the way back to one.
 */
export const KEY_SHOWN_FOR = 5 * 60 * 1000;

/**
 * VS Code's own form: a `servers` entry in its mcp.json. The key is not
 * written into the file: VS Code asks for it the first time the server
 * starts and keeps it in its own secret storage.
 *
 * @param {string} url The address a client with a headers field takes.
 * @return {string} The configuration, ready to paste.
 */
export function vscodeConfig( url ) {
	return JSON.stringify(
		{
			servers: {
				bettershield: {
					type: 'http',
					url,
					headers: { Authorization: 'Bearer ${input:bettershield-key}' },
				},
			},
			inputs: [
				{
					type: 'promptString',
					id: 'bettershield-key',
					description: __( 'BetterShield connection key', 'bettershield' ),
					password: true,
				},
			],
		},
		null,
		2
	);
}

/**
 * What each client does with what this card hands it, in its own order: three
 * short steps, the same three places every time (get it, paste it, finish).
 *
 * @param {string} client One of CLIENTS' keys.
 * @return {string[]} The steps, in order.
 */
export function clientSteps( client ) {
	switch ( client ) {
		case 'chatgpt':
			return [
				__( 'Copy the address above.', 'bettershield' ),
				__( 'In ChatGPT’s settings, add a custom connector, paste it and choose OAuth.', 'bettershield' ),
				__( 'Approve the connection on this site when asked.', 'bettershield' ),
			];
		case 'claude_desktop':
			return [
				__( 'Create a connection key below.', 'bettershield' ),
				__( 'In Claude Desktop, open Settings → Developer → Edit Config and add the configuration.', 'bettershield' ),
				__( 'Put your key in place of PASTE_YOUR_TOKEN_HERE, then restart Claude Desktop.', 'bettershield' ),
			];
		case 'cursor':
			return [
				__( 'Create a connection key below.', 'bettershield' ),
				__( 'In Cursor, open Settings → MCP → Add new server and paste the configuration.', 'bettershield' ),
				__( 'Put your key in place of PASTE_YOUR_TOKEN_HERE, then save.', 'bettershield' ),
			];
		case 'vscode':
			return [
				__( 'Create a connection key below.', 'bettershield' ),
				__( 'In VS Code, run “MCP: Open User Configuration” and paste the configuration.', 'bettershield' ),
				__( 'Start the server and paste your key when VS Code asks for it.', 'bettershield' ),
			];
		case 'codex':
			return [
				__( 'Create a connection key below.', 'bettershield' ),
				__( 'Add the configuration to Codex’s config.toml.', 'bettershield' ),
				__( 'Set the environment variable to your key, then restart Codex.', 'bettershield' ),
			];
		default:
			return [
				__( 'Copy the address above.', 'bettershield' ),
				__( 'In Claude, open Settings → Connectors → Add custom connector, paste it, then press Add and Connect.', 'bettershield' ),
				__( 'Approve the connection on this site when asked.', 'bettershield' ),
			];
	}
}

/**
 * A client's steps as a numbered list: a number each and one line, never a
 * tick, because nothing on this site can see how far a person got inside
 * their own assistant.
 *
 * @param {Object}   props
 * @param {string[]} props.steps The steps, in order.
 */
function Steps( { steps } ) {
	return (
		<ol className="bs-ds-connect__steps">
			{ steps.map( ( text, index ) => (
				<li key={ text }>
					<span className="bs-ds-connect__num" aria-hidden="true">
						{ index + 1 }
					</span>
					<span>{ text }</span>
				</li>
			) ) }
		</ol>
	);
}

/**
 * A client's own logo, in its colors, on a neutral tile so nothing tints it.
 *
 * @param {Object} props
 * @param {string} props.logo The logo's name.
 */
function ClientMark( { logo } ) {
	return (
		<span className="bs-ds-connect__mark" aria-hidden="true">
			<ClientLogo name={ logo } />
		</span>
	);
}

/**
 * A new connection key: masked until asked, copied whole, and gone from the
 * screen after KEY_SHOWN_FOR. Only the last four characters are ever drawn
 * while it is hidden, the same four the site keeps as its hint.
 *
 * @param {Object} props
 * @param {string} props.token The key, as the site handed it back.
 */
export function KeyField( { token } ) {
	const [ shown, setShown ] = useState( false );
	const masked = '•'.repeat( 24 ) + token.slice( -4 );

	return (
		<div className="bs-ds-copyfield bs-ds-connect__keyfield">
			<span className="bs-ds-copyfield__label">{ __( 'Connection key', 'bettershield' ) }</span>
			<div className="bs-ds-copyfield__row">
				<input
					className="bs-ds-copyfield__value"
					type="text"
					readOnly
					spellCheck={ false }
					autoComplete="off"
					value={ shown ? token : masked }
					aria-label={ __( 'Connection key', 'bettershield' ) }
				/>
				<Button
					type="ghost"
					size="sm"
					icon={ shown ? 'eye-off' : 'eye' }
					aria-pressed={ shown }
					onClick={ () => setShown( ! shown ) }
				>
					{ shown ? __( 'Hide', 'bettershield' ) : __( 'Show', 'bettershield' ) }
				</Button>
				{ /* "Copied" on the button, as beside every other field: a note
				     beside it moved the row for two seconds (#2635). */ }
				<CopyButton text={ token } label={ __( 'Copy the Key', 'bettershield' ) } inPlace />
			</div>
		</div>
	);
}

/**
 * The newest moment anything used the connection, and what it was.
 *
 * @param {Object}      connection The connection document.
 * @param {Object[]|null} apps     The signed-in apps, when read.
 * @return {Object|null} `{ name, at }`, or null when nothing has used it.
 */
export function lastUse( connection, apps ) {
	let latest = null;

	if ( connection && connection.connected && connection.last_used ) {
		latest = { name: __( 'Connection key', 'bettershield' ), at: connection.last_used };
	}

	( apps || [] ).forEach( ( app ) => {
		if ( app.last_used_at && ( ! latest || Date.parse( app.last_used_at ) > Date.parse( latest.at ) ) ) {
			latest = { name: app.name, at: app.last_used_at };
		}
	} );

	return latest;
}

/**
 * The screen's header: what this is, where the connection stands in a word
 * and a line, and the switch that lets assistants connect.
 *
 * @param {Object}  props
 * @param {string}  props.status     One of none, off, closed, attention, connected, ready.
 * @param {Object}  props.connection The connection document.
 * @param {Array}   props.apps       The signed-in apps, when read.
 * @param {number}  props.signedIn   How many apps hold a grant.
 * @param {Object}  props.headingRef Takes the title, for focus to land on.
 * @param {*}       props.control    The connections switch, or what stands in for it.
 * @param {*}       props.children   What the switch came to, under the header's first row.
 */
export function StatusHero( { status, connection, apps, signedIn, headingRef = null, control = null, children = null } ) {
	const used = lastUse( connection, apps );
	let line;
	let badge;

	switch ( status ) {
		case 'connected':
			line = used
				? sprintf(
						/* translators: 1: an app's name, or "Connection key", 2: when it last used the connection. */
						__( 'Last used by %1$s, %2$s.', 'bettershield' ),
						used.name,
						formatTime( used.at )
				  )
				: __( 'Ready and waiting. Nothing has used the connection yet.', 'bettershield' );
			badge = <Badge tone="brand" icon="circle-check">{ __( 'Connected', 'bettershield' ) }</Badge>;
			break;
		case 'attention':
			line = __( 'The account behind the connection key lost access. Replace the key from an account that manages BetterShield.', 'bettershield' );
			badge = <Badge tone="yellow">{ __( 'Action needed', 'bettershield' ) }</Badge>;
			break;
		case 'closed':
			line =
				signedIn > 0 || ( connection && connection.connected )
					? __( 'Connected apps keep their access, but nothing reaches the site until you turn connections back on.', 'bettershield' )
					: __( 'Turn on “Allow AI assistant connections” to connect an assistant.', 'bettershield' );
			badge = <Badge>{ __( 'Off', 'bettershield' ) }</Badge>;
			break;
		case 'ready':
			line = __( 'Pick your assistant below and follow its three steps.', 'bettershield' );
			badge = <Badge>{ __( 'Not connected', 'bettershield' ) }</Badge>;
			break;
		default:
			line = __( 'Reading security info is off, so assistants see nothing. Turn it on in Permissions.', 'bettershield' );
			badge = <Badge>{ __( 'Off', 'bettershield' ) }</Badge>;
	}

	return (
		<Card className="bs-ds-connect__hero" aria-label={ __( 'Connection status', 'bettershield' ) } data-status={ status }>
			<div className="bs-ds-connect__herohead">
				<IconTile icon="bot" size="md" />
				<div className="bs-ds-connect__herotext">
					<div className="bs-ds-connect__herotitlerow">
						<h2 className="bs-ds-connect__herotitle bs-ds-t14 bs-ds-m bs-ds-c1" ref={ headingRef } tabIndex={ headingRef ? -1 : undefined }>
							{ __( 'Agent access', 'bettershield' ) }
						</h2>
						{ badge }
					</div>
					<p className="bs-ds-connect__heroline">{ line }</p>
				</div>
				{ control ? <div className="bs-ds-connect__herocontrol">{ control }</div> : null }
			</div>
			{ children }
		</Card>
	);
}

/**
 * One of the two opt-ins, as a column of the access card: its name, where it
 * stands and a link to where it is changed. It carries no switch: the
 * header's is the one control on this tab, and the opt-ins are set on
 * Permissions.
 *
 * @param {Object}  props
 * @param {string}  props.title What the opt-in is.
 * @param {boolean} props.done  Whether it is on.
 * @param {*}       props.line  The one line about what it allows.
 * @param {*}       props.link  Where it is changed.
 */
function Allow( { title, done, line = null, link = null } ) {
	return (
		<div className={ `bs-ds-step${ done ? ' is-done' : '' }` }>
			<div className="bs-ds-step__head">
				<span className="bs-ds-step__mark" aria-hidden="true">
					<Icon name={ done ? 'circle-check' : 'circle-dashed' } size={ 16 } tone={ done ? 'ok' : '3' } />
				</span>
				<h3 className="bs-ds-step__title">{ title }</h3>
				<Badge tone={ done ? 'brand' : 'neutral' }>{ done ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }</Badge>
			</div>
			{ line ? <p className="bs-ds-step__line">{ line }</p> : null }
			{ link }
		</div>
	);
}

/**
 * One fact of what an assistant would meet: what it is, what the state costs
 * when it costs something, and the state as a badge at the row's end.
 *
 * @param {Object}  props
 * @param {string}  props.label  What the fact is.
 * @param {boolean} props.ok     Whether it is in the state an assistant needs.
 * @param {string}  props.state  The state, in words.
 * @param {*}       props.detail What the state costs, under the label.
 * @param {*}       props.more   What opens under the row on request.
 * @param {boolean} props.attention Whether a state that isn't ok is a failed check, drawn for attention.
 */
function HealthRow( { label, ok, state, detail = null, more = null, attention = false } ) {
	return (
		<div className="bs-ds-connect__health">
			<div className="bs-ds-connect__healthtext">
				<span className="bs-ds-connect__healthlabel">{ label }</span>
				{ detail ? <span className="bs-ds-connect__healthnote">{ detail }</span> : null }
				{ more }
			</div>
			{ /* A failed check is drawn in the attention tone; an option that is
			     simply off stays neutral (#2604). */ }
			<Badge tone={ ok ? 'brand' : attention ? 'yellow' : 'neutral' }>{ state }</Badge>
		</div>
	);
}

/**
 * The apps that have signed in, before that list has been read: two rows in
 * the table's own shape.
 */
function AppsBone() {
	return (
		<Skeleton label={ __( 'Loading the connected apps…', 'bettershield' ) }>
			<div className="bs-ds-connect__bones">
				{ [ '30%', '22%' ].map( ( width ) => (
					<div key={ width } className="bs-ds-bonerow">
						<span className="bs-ds-bonerow__text">
							<Bone kind="title" w={ width } />
							<Bone w="45%" />
						</span>
						<Bone kind="control" w="64px" />
					</div>
				) ) }
			</div>
		</Skeleton>
	);
}

/**
 * The connection's own cards before the connection has been read: the card
 * that connects an assistant and the health of the connection.
 */
function ConnectionBone() {
	return (
		<Skeleton label={ __( 'Loading the connection…', 'bettershield' ) }>
			<CardBone rows={ [ '90%', '55%' ] } />
			<CardBone rows={ [ '30%', '50%', '25%', '40%' ] } />
		</Skeleton>
	);
}

/**
 * The Connect tab before the surface document has landed.
 */
function ConnectBone() {
	return (
		<Skeleton label={ __( 'Loading the agent connection…', 'bettershield' ) }>
			<CardBone rows={ [ '35%', '40%' ] } toggle />
			<CardBone rows={ [ '90%', '55%' ] } />
			<CardBone rows={ [ '30%', '50%', '25%', '40%' ] } />
		</Skeleton>
	);
}

/**
 * A card's head as this screen draws it: the title (a heading focus can land
 * on), an ⓘ beside it where one helps, and what ends the row.
 *
 * @param {Object} props
 * @param {string} props.id         The heading's id, for the card's label.
 * @param {string} props.icon       The card's icon tile.
 * @param {*}      props.title      The title.
 * @param {Object} props.headingRef Takes the heading.
 * @param {*}      props.tip        The ⓘ's text.
 * @param {*}      props.children   What ends the row.
 */
function Head( { id, icon, title, headingRef = null, tip = null, children = null } ) {
	return (
		<CardHead
			icon={ icon }
			id={ id }
			title={
				<span className="bs-ds-connect__title">
					<span ref={ headingRef } tabIndex={ headingRef ? -1 : undefined } className="bs-ds-connect__focus">
						{ title }
					</span>
					{ tip ? (
						<InfoTip
							label={ sprintf(
								/* translators: %s: a card's title. */
								__( 'About %s', 'bettershield' ),
								title
							) }
						>
							{ tip }
						</InfoTip>
					) : null }
				</span>
			}
		>
			{ children ? <div className="bs-ds-connect__headend">{ children }</div> : null }
		</CardHead>
	);
}

/**
 * What the hub loses from the tools unticked for it. Two separate warnings,
 * because they cost different things, and neither stops the save.
 *
 * @param {Object}   app      The connected app.
 * @param {string[]} unticked The tools unticked for it right now.
 * @return {string[]} The sentences to show.
 */
export function hubToolWarnings( app, unticked ) {
	if ( ! app.is_hub ) {
		return [];
	}

	const warnings = [];

	if ( unticked.includes( 'get-hub-link' ) ) {
		warnings.push(
			app.hub_link_on
				? __( 'BetterShield Hub will keep getting this site’s events until the Hub link is turned off and on.', 'bettershield' )
				: __( 'If the Hub link is turned on later, BetterShield Hub won’t take this site’s events.', 'bettershield' )
		);
	}

	if ( unticked.includes( 'get-security-overview' ) && unticked.includes( 'get-security-posture' ) ) {
		warnings.push( __( 'BetterShield Hub will stop getting this site’s score and findings.', 'bettershield' ) );
	}

	return warnings;
}

/**
 * The tools one app may use (#1879): every tool its access allows, ticked
 * unless the owner unticked it. Unticked tools are left out of the app's list
 * and refused when it calls them. A tool unticked earlier that its access no
 * longer offers stays unticked.
 *
 * @param {Object}   props
 * @param {Object}   props.app      The app, with `tools` and `tools_denied`.
 * @param {boolean}  props.saving   Whether a save is in flight.
 * @param {Function} props.onSave   Called with the tool names to untick.
 * @param {Function} props.onCancel Closes the panel without saving.
 */
export function AppToolsPanel( { app, saving, onSave, onCancel } ) {
	const tools = app.tools || [];
	const denied = app.tools_denied || [];
	const [ chosen, setChosen ] = useState( () => tools.map( ( tool ) => tool.name ).filter( ( name ) => ! denied.includes( name ) ) );
	const offered = tools.map( ( tool ) => tool.name );
	const unticked = [ ...offered.filter( ( name ) => ! chosen.includes( name ) ), ...denied.filter( ( name ) => ! offered.includes( name ) ) ];

	if ( ! tools.length ) {
		return <p className="bs-ds-connect__toolsnone">{ __( 'This app has nothing it can do right now. Turn on “Let AI assistants see security info” above.', 'bettershield' ) }</p>;
	}

	return (
		<div className="bs-ds-connect__tools">
			<Field
				kind="checks"
				label={ __( 'What this app can do', 'bettershield' ) }
				help={ __( 'Untick anything you don’t want this app to use. New ones are allowed until you untick them.', 'bettershield' ) }
				value={ chosen }
				disabled={ saving }
				options={ tools.map( ( tool ) => ( {
					value: tool.name,
					label: tool.writes
						? sprintf(
								/* translators: %s: a tool's name. */
								__( '%s (changes the site)', 'bettershield' ),
								tool.title
						  )
						: tool.title,
				} ) ) }
				onChange={ setChosen }
			/>
			{ hubToolWarnings( app, unticked ).map( ( warning ) => (
				<Alert key={ warning } layout="default" tone="warning" live desc={ warning } />
			) ) }
			<div className="bs-ds-connect__toolsacts">
				<Button type="primary" size="sm" isBusy={ saving } disabled={ saving } onClick={ () => onSave( unticked ) }>
					{ __( 'Save Tools', 'bettershield' ) }
				</Button>
				<Button type="ghost" size="sm" disabled={ saving } onClick={ onCancel }>
					{ __( 'Cancel', 'bettershield' ) }
				</Button>
			</div>
		</div>
	);
}

/**
 * How many of an app's tools it may use, when the owner narrowed them.
 *
 * @param {Object} app The app, with `tools` and `tools_denied`.
 * @return {string} e.g. "12 of 26 tools", or '' when nothing is unticked.
 */
export function toolsPhrase( app ) {
	const tools = ( app.tools || [] ).map( ( tool ) => tool.name );
	const denied = ( app.tools_denied || [] ).filter( ( name ) => tools.includes( name ) );

	if ( ! denied.length ) {
		return '';
	}

	return sprintf(
		/* translators: 1: how many tools the app may use, 2: how many its access allows. */
		_n( '%1$d of %2$d tool', '%1$d of %2$d tools', tools.length, 'bettershield' ),
		tools.length - denied.length,
		tools.length
	);
}

/**
 * The three opt-ins as the agent surface states them.
 *
 * @param {Object} surface The agent surface document.
 * @return {Object} What the screen holds of them.
 */
function seedAccess( surface ) {
	return {
		read_enabled: !! surface.abilities_enabled,
		read_available: !! surface.abilities_api_available,
		write_enabled: !! surface.write_enabled,
		capability_granted: !! surface.capability_granted,
		sudo_required: !! surface.sudo_required,
	};
}

/**
 * Connecting an assistant, and everything that follows from having done it.
 *
 * One component rather than several, because the three switches, the
 * connection document and the credential are one piece of state: the health
 * card has to agree with the switch above it, and two components holding two
 * copies of that answer is how they stop agreeing.
 */
function ConnectScreen( { surface } ) {
	const {
		saveAbilities,
		setMcpEnabled,
		connectMcp,
		rotateMcp,
		disconnectMcp,
		revokeMcpApp,
		setMcpAppTools,
		testMcpConnection,
		busy,
	} = useStore();

	const pairing = useRef( null );
	const afterPairing = useMutationFocus( pairing );
	const appsHeading = useRef( null );
	const afterRevoke = useMutationFocus( appsHeading );
	const healthHeading = useRef( null );
	const afterTest = useMutationFocus( healthHeading );

	/*
	 * The three opt-ins, seeded from the document this screen was drawn with
	 * and then kept by whatever each route answered. A save is a later read of
	 * the same site than the document was, so it wins.
	 */
	const [ access, setAccess ] = useState( () => seedAccess( surface ) );

	const [ connection, setConnection ] = useState( null );
	const [ state, setState ] = useState( 'loading' );
	// Held in the screen and nowhere else. It is handed back once, it is never
	// written into a resource, and reloading the screen does not bring it back.
	const [ token, setToken ] = useState( null );
	// Set once a key that was on the screen has been taken off it by time.
	const [ keyExpired, setKeyExpired ] = useState( false );

	useEffect( () => {
		if ( ! token ) {
			return undefined;
		}

		setKeyExpired( false );

		const timer = window.setTimeout( () => {
			setToken( null );
			setKeyExpired( true );
		}, KEY_SHOWN_FOR );

		return () => window.clearTimeout( timer );
	}, [ token ] );
	const [ announced, setAnnounced ] = useState( '' );
	/*
	 * What the step's own switch, and the last app's revoke, came to. Said on
	 * the step, which is drawn whatever assistant is chosen: the manual card
	 * that holds `announced` is a closed panel for a browser-signed-in one,
	 * and a status in a closed panel is neither shown nor heard (#2027).
	 */
	const [ stepSaid, setStepSaid ] = useState( '' );
	// Whether what the step said is an outcome or a refusal.
	const [ stepTone, setStepTone ] = useState( 'success' );
	// One outcome on the screen at a time, wherever it is said.
	const say = ( text ) => {
		setStepSaid( '' );
		setAnnounced( text );
	};
	const sayOnStep = ( text, tone = 'success' ) => {
		setAnnounced( '' );
		setStepTone( tone );
		setStepSaid( text );
	};
	/*
	 * What the next credential is minted for. It travels with the request
	 * rather than being applied to a credential afterwards, so a credential
	 * never widens without a new one being issued — and it starts at what the
	 * site will actually grant, because a credential minted with more than the
	 * site allows is one that quietly gains it the day the opt-in goes on.
	 */
	const [ mayWrite, setMayWrite ] = useState( () => !! surface.write_enabled );

	/*
	 * And seeded again whenever the document is read again. A change made on
	 * another tab reads it again, and it is then the latest word on the site;
	 * a screen that kept its first copy went on saying agents may apply a
	 * change after they no longer could. The next credential follows the
	 * write opt-in only when that moved, so a box the reader unticked stays so.
	 */
	const drawnWith = useRef( surface );

	useEffect( () => {
		const before = drawnWith.current;

		if ( before === surface ) {
			return;
		}

		drawnWith.current = surface;
		setAccess( seedAccess( surface ) );

		if ( !! before.write_enabled !== !! surface.write_enabled ) {
			setMayWrite( !! surface.write_enabled );
		}
		if ( !! before.write_enabled !== !! surface.write_enabled || !! before.abilities_enabled !== !! surface.abilities_enabled ) {
			setConnectionRead( ( count ) => count + 1 );
			setAppsRead( ( count ) => count + 1 );
		}
	}, [ surface ] );
	const [ client, setClient ] = useState( KEY_CLIENTS[ 0 ].key );
	const [ apps, setApps ] = useState( null );
	const [ appsNote, setAppsNote ] = useState( '' );
	// Kept apart from an empty list: a read that failed says nothing about
	// whether any app still has access, and must never read as "none".
	const [ appsFailed, setAppsFailed ] = useState( false );
	const [ appsRead, setAppsRead ] = useState( 0 );
	// While a read of the grants is on its way, so Refresh shows it working.
	const [ appsReading, setAppsReading ] = useState( false );
	const [ test, setTest ] = useState( null );
	/*
	 * Bumped after reading or changes is switched, because the tool count is
	 * the connection's answer and moves with both. A read again that fails
	 * keeps the copy on screen rather than taking the cards away.
	 */
	const [ connectionRead, setConnectionRead ] = useState( 0 );

	useEffect( () => {
		let live = true;

		apiFetch( { path: MCP_CONNECTION } ).then(
			( data ) => {
				if ( live ) {
					setConnection( data );
					setState( 'ready' );
				}
			},
			() => {
				if ( live ) {
					setState( ( old ) => ( 'ready' === old ? old : 'error' ) );
				}
			}
		);

		return () => {
			live = false;
		};
	}, [ connectionRead ] );

	/*
	 * Re-check reads the connection again on its own, so the button can say
	 * it is working and then that it is done: the read is often quicker than
	 * an eye, and a row that comes back unchanged looked like nothing ran.
	 */
	const [ recheck, setRecheck ] = useState( 'idle' );
	const recheckWords = {
		idle: __( 'Re-check', 'bettershield' ),
		busy: __( 'Checking…', 'bettershield' ),
		done: __( 'Checked', 'bettershield' ),
	};
	const recheckLongest = Object.values( recheckWords ).reduce( ( a, b ) => ( b.length > a.length ? b : a ) );
	const recheckNow = () => {
		if ( 'busy' === recheck ) {
			return;
		}

		setRecheck( 'busy' );

		const seen = new Promise( ( resolve ) => window.setTimeout( resolve, 600 ) );

		Promise.all( [ apiFetch( { path: MCP_CONNECTION } ), seen ] ).then(
			( [ data ] ) => {
				setConnection( data );
				setState( 'ready' );
				setRecheck( 'done' );
				window.setTimeout( () => setRecheck( ( old ) => ( 'done' === old ? 'idle' : old ) ), 2500 );
			},
			() => seen.then( () => setRecheck( 'failed' ) )
		);
	};

	const connected = !! ( connection && connection.connected );

	/*
	 * Access is held by a credential minted here or by an app that signed in
	 * through the consent page, and the second needs no credential at all —
	 * the hub never mints one. Either is something this screen has to list
	 * and be able to end.
	 */
	const signedIn = Math.max( 0, Number( connection && connection.apps ) || 0 );
	const held = connected || signedIn > 0;

	// The grants are worth reading only once something holds access, and
	// worth reading again the moment that changes.
	useEffect( () => {
		setAppsFailed( false );

		if ( ! held ) {
			setApps( null );
			setAppsReading( false );

			return undefined;
		}

		let live = true;

		setAppsReading( true );
		apiFetch( { path: MCP_APPS } )
			.then(
				( data ) => {
					if ( live ) {
						setApps( data && data.apps ? data.apps : [] );
					}
				},
				() => {
					if ( live ) {
						setApps( null );
						setAppsFailed( true );
					}
				}
			)
			.finally( () => {
				if ( live ) {
					setAppsReading( false );
				}
			} );

		return () => {
			live = false;
		};
	}, [ held, appsRead ] );

	// The button goes with the alert it sits in, so focus goes to the card's
	// heading rather than to the top of the page.
	const readAppsAgain = () => {
		setAppsNote( '' );
		setAppsRead( ( count ) => count + 1 );
		appsHeading.current?.focus();
	};

	/*
	 * A refusal said on the step, under the switch that was pressed, rather
	 * than in the banner at the top of the screen. A password prompt that was
	 * canceled arrives with no error at all.
	 */
	const refusedOnStep = ( fallback ) => ( error ) => {
		sayOnStep( error && error.message ? error.message : fallback, 'error' );

		return true;
	};

	const notChanged = __( 'The password wasn’t confirmed, so nothing was changed.', 'bettershield' );

	const openOrClose = ( next ) =>
		setMcpEnabled(
			next,
			afterPairing( ( data ) => {
				setConnection( ( old ) => ( { ...old, enabled: !! data.enabled } ) );
				// Read again after the switch moved, so an earlier read still
				// on its way never puts the old answer back.
				setConnectionRead( ( count ) => count + 1 );
				setToken( null );
				setTest( null );
				sayOnStep(
					data.enabled
						? __( 'Saved. You can now connect an AI assistant.', 'bettershield' )
						: __( 'Saved. AI assistants can’t connect.', 'bettershield' )
				);
			} ),
			refusedOnStep( notChanged )
		);

	/*
	 * The header's switch, the one control on this tab. Turning it on turns
	 * on what a connection needs: reading first, when it is off, and then
	 * connections, each through its own route so each meets the same checks
	 * and the same password prompt. Reading refused stops there, with
	 * connections left off. Turning it off closes connections only: reading
	 * serves more than this tab, and it stays as Permissions has it.
	 */
	const enable = ( next ) => {
		if ( ! next || access.read_enabled ) {
			return openOrClose( next );
		}

		return saveAbilities(
			true,
			( data ) => {
				setAccess( ( old ) => ( { ...old, read_enabled: !! data.enabled } ) );

				if ( ! data.enabled ) {
					sayOnStep( __( 'Reading security info could not be turned on, so connections stay off.', 'bettershield' ), 'error' );

					return;
				}

				// After the first request has let go of the one-at-a-time
				// lock, which it holds until this callback has returned.
				window.setTimeout( () => openOrClose( true ), 0 );
			},
			refusedOnStep( __( 'Reading security info could not be turned on, so connections stay off.', 'bettershield' ) )
		);
	};

	// Read from the live opt-in rather than from the box alone: with changes
	// off there is no wider scope to ask for, and the site mints the narrow one
	// whatever this sends.
	// And from what this account holds: the site mints the narrow scope for an
	// account that may not make agent changes, whatever this sends.
	const scope = mayWrite && access.write_enabled && access.capability_granted ? READ_WRITE : READ_ONLY;

	const connect = () =>
		connectMcp(
			scope,
			afterPairing( ( data ) => {
				setConnection( data.connection );
				setToken( data.token );
				// A round trip describes the credential it used. This is a
				// different credential, so what that one found no longer
				// describes anything on the screen.
				setTest( null );
				say( __( 'Key created. Paste it into your assistant. This box shows when it is first used.', 'bettershield' ) );
			} )
		);

	const rotate = () =>
		rotateMcp(
			scope,
			afterPairing( ( data ) => {
				setConnection( data.connection );
				setToken( data.token );
				setTest( null );
				say(
					__( 'A new key was created. The old one no longer works.', 'bettershield' )
				);
			} )
		);

	/*
	 * Disconnect ends the credential and every app's grant, the hub's
	 * included, so the confirmation names them and the line after says how
	 * many went.
	 */
	const ending = apps ? apps.map( ( app ) => app.name ) : [];
	const disconnectConsequence = ( () => {
		if ( connected && ending.length ) {
			return sprintf(
				/* translators: %s: the names of the apps that lose their access, separated by commas. */
				__( 'The key stops working, and these apps lose access: %s.', 'bettershield' ),
				ending.join( ', ' )
			);
		}

		if ( ending.length ) {
			return sprintf(
				/* translators: %s: the names of the apps that lose their access, separated by commas. */
				__( 'These apps lose their access: %s.', 'bettershield' ),
				ending.join( ', ' )
			);
		}

		// The apps have not been read, and no credential was issued: what ends
		// is every app's access, whichever they are.
		if ( ! connected ) {
			return __( 'Every app that signed in loses its access.', 'bettershield' );
		}

		return __( 'The key stops working, and any assistant using it is turned away.', 'bettershield' );
	} )();

	const disconnect = () => {
		const ended = ending.length;

		return disconnectMcp(
			afterPairing( ( data ) => {
				setConnection( data.connection );
				setToken( null );
				setTest( null );
				say(
					connected && ended
						? sprintf(
								/* translators: %d: how many apps lost their access. */
								_n(
									'Disconnected. The old key and %d signed-in app no longer reach this site.',
									'Disconnected. The old key and %d signed-in apps no longer reach this site.',
									ended,
									'bettershield'
								),
								ended
						  )
						: connected
						? __( 'Disconnected. Nothing reaches this site with the old key.', 'bettershield' )
						: __( 'Disconnected. No signed-in app can reach this site now.', 'bettershield' )
				);
			} )
		);
	};

	/*
	 * The last grant on a site with no credential takes the apps card with it,
	 * so the outcome is said, and keyboard position kept, on the connection
	 * step above rather than on a card that is no longer there.
	 */
	const revoke = ( id ) => {
		const last = ! connected && !! apps && apps.length <= 1;
		const removed = __( 'That app was removed. It must sign in again to return.', 'bettershield' );

		return revokeMcpApp(
			id,
			( last ? afterPairing : afterRevoke )( ( data ) => {
				const left = data && data.apps ? data.apps : [];

				setApps( left );
				setAppsFailed( false );
				setConnection( ( old ) => ( { ...old, apps: left.length } ) );

				if ( last ) {
					sayOnStep( removed );
				} else {
					setAppsNote( removed );
				}
			} )
		);
	};

	// The app whose tools are open, one at a time.
	const [ toolsOpen, setToolsOpen ] = useState( '' );

	const saveTools = ( id, unticked ) =>
		setMcpAppTools(
			id,
			unticked,
			afterRevoke( ( data ) => {
				setApps( data && data.apps ? data.apps : [] );
				setToolsOpen( '' );
				setAppsNote( __( 'Saved. The app sees the change the next time it reads its tool list.', 'bettershield' ) );
			} )
		);

	/*
	 * The test answers quickly and its result sits under the rows, so the
	 * button says it is testing and then shows a tick, the old result goes
	 * while it runs, and the new one is scrolled into view.
	 */
	const [ tested, setTested ] = useState( false );
	const testResult = useRef( null );
	const testWords = {
		idle: __( 'Test Connection', 'bettershield' ),
		busy: __( 'Testing…', 'bettershield' ),
	};
	const testLongest = Object.values( testWords ).reduce( ( a, b ) => ( b.length > a.length ? b : a ) );
	const runTest = () => {
		setTest( null );
		setTested( false );
		testMcpConnection(
			afterTest( ( result ) => {
				setTest( result );
				setTested( true );
				window.setTimeout( () => setTested( false ), 2500 );
			} )
		);
	};

	useEffect( () => {
		if ( test && testResult.current && testResult.current.scrollIntoView ) {
			testResult.current.scrollIntoView( { block: 'nearest', behavior: motionAllowed() ? 'smooth' : 'auto' } );
		}
	}, [ test ] );

	const reads = !! access.read_enabled;
	const writes = !! access.write_enabled;
	const capability = !! access.capability_granted;
	const permissions = tabUrl( 'bettershield-agents', 'permissions' );
	const working = isWorking( busy, 'abilities', 'mcp-enable', 'mcp-connect', 'mcp-rotate', 'mcp-disconnect' );

	/*
	 * The one control that decides what the next credential may do. It sits
	 * beside whichever button mints one, because a scope chosen anywhere else
	 * would be a setting the reader has to remember having set.
	 *
	 * With changes off it is off and cannot be set: the credential is issued
	 * for what the site grants today, and widening it is a new credential
	 * chosen after the opt-in, not a box ticked before it. So it is for an
	 * account that does not hold the permission for agent changes: the
	 * credential runs as that account, and the site issues it read only.
	 */
	let scopeHelp;

	if ( ! writes ) {
		scopeHelp = __(
			'It can only look until you turn on “Let AI assistants fix things”.',
			'bettershield'
		);
	} else if ( ! capability ) {
		scopeHelp = __(
			'Your account can’t allow AI fixes, so this assistant can only look. Ask an administrator.',
			'bettershield'
		);
	}

	/*
	 * Under a connected credential the box is about the one Rotate issues:
	 * the one in use keeps the scope it was issued with. "Allow this
	 * credential" there read as a switch on it, and unticking it changed
	 * nothing anybody could see (#1925).
	 */
	if ( connected && ! scopeHelp ) {
		scopeHelp = __( 'Takes effect when you replace the key.', 'bettershield' );
	}

	const scopeChoice = (
		<Field
			kind="check"
			className="bs-ds-connect__scope"
			label={ connected ? __( 'Let a new key make fixes', 'bettershield' ) : __( 'Allow this key to make fixes', 'bettershield' ) }
			checked={ mayWrite && writes && capability }
			disabled={ working || ! writes || ! capability }
			help={ scopeHelp }
			onChange={ setMayWrite }
		/>
	);

	// A credential the site is answering, which is what the recipes are for.
	const paired = !! ( connection && connection.enabled && connected );
	// Anything the site is answering: a credential, or an app that signed in.
	const answering = !! ( connection && connection.enabled && held );
	// A credential whose account can no longer hold it: the door refuses it,
	// so the step is not done however connected the card looks.
	const stranded = !! ( connection && false === connection.holder_can_act );

	// Which way to connect is open: the browser sign-in or editors and CLI.
	const [ mode, setMode ] = useState( 'oauth' );
	// The backup address and the first prompt, under the setups.
	const [ moreOpen, setMoreOpen ] = useState( false );
	// "What a connected assistant can do" is closed until the reader opens it:
	// it says where things stand and holds nothing to set.
	const [ canDoOpen, setCanDoOpen ] = useState( false );

	const onPermissions = (
		<Button type="linksub" size="sm" className="bs-ds-step__link" href={ permissions } trailing="arrow-right">
			{ __( 'Change on Permissions', 'bettershield' ) }
		</Button>
	);

	/*
	 * The header's switch: the one control on the tab. Off, with reading off
	 * too, it says that turning it on turns reading on as well.
	 */
	let control;

	if ( connection ) {
		let help = null;

		if ( ! access.read_available ) {
			help = __( 'Requires WordPress 6.9.', 'bettershield' );
		} else if ( ! reads && ! connection.enabled ) {
			help = __( 'Also turns on “Let AI assistants see security info”.', 'bettershield' );
		}

		control = (
			<SwitchLine
				label={ __( 'Allow AI assistant connections', 'bettershield' ) }
				checked={ !! connection.enabled }
				disabled={ working || ( ! access.read_available && ! connection.enabled ) }
				help={ help }
				onChange={ enable }
			/>
		);
	} else if ( 'error' === state ) {
		control = <Alert layout="default" tone="error" desc={ __( 'The connection could not be read. Reload to try again.', 'bettershield' ) } />;
	} else {
		// The switch the header will carry, held in its place while the
		// connection is read.
		control = (
			<span className="bs-ds-connect__switchbone" aria-hidden="true">
				<span className="bs-ds-bone bs-ds-bone--toggle" />
				<Bone w="12em" />
			</span>
		);
	}

	let status = 'none';

	if ( connection ) {
		if ( ! connection.enabled ) {
			status = 'closed';
		} else if ( ! reads ) {
			status = 'none';
		} else if ( paired && stranded ) {
			status = 'attention';
		} else if ( answering ) {
			status = 'connected';
		} else {
			status = 'ready';
		}
	}

	const hero = (
		<StatusHero status={ status } connection={ connection } apps={ apps } signedIn={ signedIn } headingRef={ pairing } control={ control }>
			{ /* On the page before anything is said in it: a status region
			     added together with its words is one a screen reader often
			     never announces. */ }
			<div role="status" className="bs-ds-connect__stepsaid">
				{ stepSaid ? <Alert layout="default" tone={ stepTone } desc={ stepSaid } /> : null }
			</div>
		</StatusHero>
	);

	const accessCard = (
		<Card className="bs-ds-connect__can" aria-labelledby="bs-ds-connect-can">
			<div className="bs-ds-connect__canhead">
				{ /* A card title like every other on the tab, which also opens
				     what it names. */ }
				<h2 className="bs-ds-connect__cantitle bs-ds-t14 bs-ds-m bs-ds-c1">
					<button
						type="button"
						className="bs-ds-connect__cantoggle"
						id="bs-ds-connect-can"
						aria-expanded={ canDoOpen }
						aria-controls="bs-ds-connect-cando"
						onClick={ () => setCanDoOpen( ! canDoOpen ) }
					>
						<span>{ __( 'What a connected assistant can do', 'bettershield' ) }</span>
						<Icon name={ canDoOpen ? 'chevron-up' : 'chevron-down' } size={ 14 } tone="2" />
					</button>
				</h2>
				<p className="bs-ds-connect__intro">
					{ __( 'Ask Claude, ChatGPT or another assistant about this site’s security and get answers from the site itself.', 'bettershield' ) }{ ' ' }
					{ __( 'Each assistant acts as the account that let it in, and every call is recorded.', 'bettershield' ) }
				</p>
			</div>
			<div className="bs-ds-connect__cando" id="bs-ds-connect-cando" hidden={ ! canDoOpen }>
				<Allow
					title={ __( 'Let AI assistants see security info', 'bettershield' ) }
					done={ reads }
					line={
						access.read_available
							? __( 'They see what these BetterShield screens show. Seeing never changes anything.', 'bettershield' )
							: __( 'Requires WordPress 6.9.', 'bettershield' )
					}
					link={ access.read_available ? onPermissions : null }
				/>

				<Allow
					title={ __( 'Allow fixes (optional)', 'bettershield' ) }
					done={ writes }
					line={
						writes
							? __( 'Fixes that can be undone apply right away. Sign-in changes and anything else risky wait for your OK.', 'bettershield' )
							: __( 'When off, assistants can only look.', 'bettershield' )
					}
					link={ onPermissions }
				/>

				<div className="bs-ds-connect__never">
					<h3 className="bs-ds-connect__label">{ __( 'Never, through any connection', 'bettershield' ) }</h3>
					<ul className="bs-ds-connect__chips">
						{ /* What no connection may ever do, whatever is switched
						     on: the site refuses these at the door. The same
						     chips as Permissions, from one list. */ }
						{ neverDone().map( ( phrase ) => (
							<li key={ phrase }>
								<Badge>{ phrase }</Badge>
							</li>
						) ) }
					</ul>
				</div>
			</div>
		</Card>
	);

	if ( ! connection ) {
		return (
			<>
				{ hero }
				{ accessCard }
				{ 'error' === state ? null : <ConnectionBone /> }
			</>
		);
	}

	const health = connection.health || {};
	const snippets = connection.snippets || {};
	const tools = Number( health.tools || 0 );
	const testing = isWorking( busy, 'mcp-self-test' );
	const used = lastUse( connection, apps );
	const openRequests = Math.max( 0, Number( surface.open_requests ) || 0 );

	const figures = (
		<Stats
			label={ __( 'Agent access at a glance', 'bettershield' ) }
			tiles={ [
				{
					key: 'requests',
					icon: 'inbox',
					label: __( 'Requests waiting', 'bettershield' ),
					value: String( openRequests ),
					tone: openRequests ? 'warning' : '',
					detail: (
						<Button type="linksub" size="sm" href={ tabUrl( 'bettershield-agents', 'requests' ) } trailing="arrow-right">
							{ __( 'Review', 'bettershield' ) }
						</Button>
					),
				},
				{
					key: 'tools',
					icon: 'code',
					label: __( 'Tools offered', 'bettershield' ),
					value: String( tools ),
					detail: writes ? __( 'read and undoable fixes', 'bettershield' ) : __( 'read-only', 'bettershield' ),
				},
				{
					key: 'apps',
					icon: 'layout-grid',
					label: __( 'Connected apps', 'bettershield' ),
					value: String( signedIn ),
					detail: connected ? __( 'and a connection key', 'bettershield' ) : null,
				},
				{
					key: 'last',
					icon: 'clock',
					label: __( 'Last activity', 'bettershield' ),
					value: used ? formatTime( used.at ) : __( 'None yet', 'bettershield' ),
					text: true,
					detail: (
						<Button type="linksub" size="sm" href={ tabUrl( 'bettershield-activity', 'agents' ) } trailing="arrow-right">
							{ __( 'See Agent Activity', 'bettershield' ) }
						</Button>
					),
				},
			] }
		/>
	);

	/*
	 * The apps that signed in: a row each, the line saying none has, the read
	 * that failed with a way to read again, or their stand-in while they are
	 * read. A list that could not be read must never look like an empty one.
	 */
	let appsBody;

	if ( apps && apps.length ) {
		appsBody = (
			<div className="bs-ds-connect__tablewrap">
			<Table
				label={ __( 'Connected apps', 'bettershield' ) }
				className="bs-ds-connect__table"
				columns={ [
					{ key: 'app', label: __( 'Name', 'bettershield' ), width: 'minmax(160px, 1fr)' },
					{ key: 'access', label: __( 'Access', 'bettershield' ), width: '170px' },
					{ key: 'granted', label: __( 'Connected', 'bettershield' ), width: '170px' },
					{ key: 'used', label: __( 'Last used', 'bettershield' ), width: '150px' },
					{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
				] }
			>
				{ apps.map( ( app ) => (
					<Fragment key={ app.id }>
						<Row className="bs-ds-connect__app">
							<Cell>
								<TitleMeta
									title={ <span className="bs-ds-connect__appname">{ app.name }</span> }
									meta={
										false === app.holder_can_act ? (
											<span className="bs-ds-connect__refused">
												{ __( 'Blocked: the person who connected it no longer has permission', 'bettershield' ) }
											</span>
										) : null
									}
								/>
							</Cell>
							<Cell>
								<span className="bs-ds-connect__access">
									{ app.scope ? <Badge tone={ 'read' === app.scope ? 'brand' : 'blue' }>{ appScopePhrase( app.scope ) }</Badge> : null }
									{ toolsPhrase( app ) ? <Badge tone="yellow">{ toolsPhrase( app ) }</Badge> : null }
								</span>
							</Cell>
							<Cell>
								<span className="bs-ds-connect__appmeta">
									{ sprintf(
										/* translators: 1: who allowed it, 2: when they did. */
										__( 'allowed by %1$s, %2$s', 'bettershield' ),
										app.granted_by ? app.granted_by.display_name : __( 'an account that is gone', 'bettershield' ),
										formatTime( app.granted_at )
									) }
								</span>
							</Cell>
							<Cell>
								<span className="bs-ds-connect__appmeta">
									{ app.last_used_at
										? sprintf(
												/* translators: %s: when the app last used the connection. */
												__( 'last used %s', 'bettershield' ),
												formatTime( app.last_used_at )
										  )
										: __( 'never used', 'bettershield' ) }
								</span>
							</Cell>
							<Cell align="end">
								<span className="bs-ds-connect__rowacts">
									<Button
										type="ghost"
										size="sm"
										trailing={ toolsOpen === app.id ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										aria-expanded={ toolsOpen === app.id }
										aria-controls={ toolsOpen === app.id ? `bs-app-tools-${ app.id }` : undefined }
										onClick={ () => setToolsOpen( toolsOpen === app.id ? '' : app.id ) }
									>
										{ __( 'Tools', 'bettershield' ) }
									</Button>
									{ /* Armed: an app that is let go has to sign in again,
									     with an administrator approving it, to return. */ }
									<Armed
										type="ghost"
										label={ __( 'Disconnect', 'bettershield' ) }
										aria-label={ sprintf(
											/* translators: %s: a connected app's name. */
											__( 'Disconnect %s', 'bettershield' ),
											app.name
										) }
										consequence={ sprintf(
											/* translators: %s: a connected app's name. */
											__( '%s loses access and must sign in again to return.', 'bettershield' ),
											app.name
										) }
										busy={ isWorking( busy, `mcp-app-${ app.id }` ) }
										onConfirm={ () => revoke( app.id ) }
									/>
								</span>
							</Cell>
						</Row>
						{ toolsOpen === app.id ? (
							<div className="bs-ds-connect__under" role="row" id={ `bs-app-tools-${ app.id }` }>
								<div role="cell">
									<AppToolsPanel
										app={ app }
										saving={ isWorking( busy, `mcp-app-tools-${ app.id }` ) }
										onSave={ ( unticked ) => saveTools( app.id, unticked ) }
										onCancel={ () => setToolsOpen( '' ) }
									/>
								</div>
							</div>
						) : null }
					</Fragment>
				) ) }
			</Table>
			</div>
		);
	} else if ( apps ) {
		appsBody = <EmptyState>{ __( 'No app has signed in to this site yet.', 'bettershield' ) }</EmptyState>;
	} else if ( appsFailed ) {
		appsBody = (
			<div className="bs-ds-connect__notes">
				<div role="alert">
					<Alert
						layout="default"
						tone="error"
						desc={ __( 'Could not load the signed-in apps. Their access has not changed.', 'bettershield' ) }
						actions={
							<Button type="secondary" size="sm" onClick={ readAppsAgain }>
								{ __( 'Try Again', 'bettershield' ) }
							</Button>
						}
					/>
				</div>
			</div>
		);
	} else {
		appsBody = <AppsBone />;
	}

	/*
	 * The connection key, in the Editors & CLI tab under the chosen tool's
	 * setup: who made it, what it may do, what the next one may do, and the
	 * way to replace it. Claude and ChatGPT sign in without one, so their
	 * cards never show or mention it.
	 */
	const keyRow = (
		<div className="bs-ds-connect__credential">
			<div className="bs-ds-connect__who">
				<p className="bs-ds-connect__keytitle">
					<span>{ __( 'Connection key', 'bettershield' ) }</span>
					<Badge>{ __( 'Editors & CLI', 'bettershield' ) }</Badge>
					{ paired ? (
						<Badge tone="brand">{ __( 'Key ready', 'bettershield' ) }</Badge>
					) : connected ? (
						<Badge tone="yellow">{ __( 'Not working: run the test below', 'bettershield' ) }</Badge>
					) : null }
				</p>
				{ connected ? (
					<p className="bs-ds-connect__by">
						<span>
							{ null === connection.last_used
								? sprintf(
										/* translators: 1: who issued the credential, 2: when they did. */
										__( 'Key created by %1$s, %2$s, not used yet', 'bettershield' ),
										connection.connected_by ? connection.connected_by.display_name : __( 'someone', 'bettershield' ),
										formatTime( connection.connected_at )
								  )
								: connection.connected_by
								? sprintf(
										/* translators: 1: who connected it, 2: when they did. */
										__( 'Connected by %1$s, %2$s', 'bettershield' ),
										connection.connected_by.display_name,
										formatTime( connection.connected_at )
								  )
								: sprintf(
										/* translators: %s: when it was connected. */
										__( 'Connected %s', 'bettershield' ),
										formatTime( connection.connected_at )
								  ) }
						</span>
						{ /* Four characters, so one credential can be told from
						     another. Never more, whoever is asking. */ }
						{ connection.token_hint ? (
							<span className="bs-ds-connect__hint">
								{ sprintf(
									/* translators: %s: the last few characters of the credential. */
									__( 'ending %s', 'bettershield' ),
									connection.token_hint
								) }
							</span>
						) : null }
						{ connection.scope ? <Badge>{ scopePhrase( connection.scope ) }</Badge> : null }
					</p>
				) : (
					<p className="bs-ds-connect__by">{ __( 'Editors and command-line tools use a connection key.', 'bettershield' ) }</p>
				) }

				{ /* The credential runs as that account, and the door refuses
				     it once the account cannot hold it. */ }
				{ connected && false === connection.holder_can_act ? (
					<div role="alert">
						<Alert
							layout="default"
							tone="warning"
							desc={ __( 'The account behind this key lost access, so it is turned away. Reconnect from an account that manages BetterShield.', 'bettershield' ) }
						/>
					</div>
				) : null }

				{ scopeChoice }
			</div>

			<div className="bs-ds-connect__actions">
				{ /* Armed: the credential in use stops opening anything the
				     moment a new one is issued. */ }
				{ connected ? (
					<Armed
						label={ __( 'Replace Key', 'bettershield' ) }
						consequence={ __( 'The old key stops working. Paste the new one into your assistant.', 'bettershield' ) }
						busy={ working }
						onConfirm={ rotate }
					/>
				) : (
					<Button type="secondary" size="sm" icon="key-round" isBusy={ working } disabled={ working } onClick={ connect }>
						{ __( 'Create Key', 'bettershield' ) }
					</Button>
				) }
			</div>
		</div>
	);

	/*
	 * The one place on this screen that hands out a credential. It is minted
	 * for this site, the site keeps only its fingerprint, and no read ever
	 * returns it — so the row says so in the same breath as showing it.
	 */
	const tokenRow = token ? (
		<div className="bs-ds-connect__token">
			<p className="bs-ds-connect__keytitle">
				<span>{ __( 'New connection key', 'bettershield' ) }</span>
				<Badge tone="yellow">{ __( 'Shown once', 'bettershield' ) }</Badge>
			</p>
			<p role="status" className="bs-ds-connect__once">
				{ __( 'Copy this now. It is shown only once.', 'bettershield' ) }
			</p>
			<KeyField token={ token } />
			<p className="bs-ds-connect__hint">{ __( 'Hidden until you press Show, and removed from this screen after 5 minutes.', 'bettershield' ) }</p>
		</div>
	) : keyExpired ? (
		<div className="bs-ds-connect__token">
			<p className="bs-ds-connect__once">{ __( 'The key is no longer shown. If you didn’t copy it, replace it.', 'bettershield' ) }</p>
		</div>
	) : null;

	const endpoint = connection.endpoint;
	const pickedClient = KEY_CLIENTS.find( ( entry ) => entry.key === client ) || KEY_CLIENTS[ 0 ];

	// Claude and ChatGPT, side by side: an address, three steps, an approval.
	const oauthPanel = (
		<>
			<div className="bs-ds-connect__clients">
				{ CLIENTS.filter( ( entry ) => OAUTH_CLIENTS.includes( entry.key ) ).map( ( entry ) => {
					const snippet = snippets[ entry.key ] || {};
					const name = entry.label();

					return (
						<article key={ entry.key } className="bs-ds-connect__client" aria-label={ name }>
							<div className="bs-ds-connect__clienthead">
								<ClientMark logo={ entry.logo } />
								<div className="bs-ds-connect__clienttext">
									<p className="bs-ds-connect__clientname">
										<span>{ name }</span>
										<Badge tone="brand">{ __( 'Browser sign-in', 'bettershield' ) }</Badge>
									</p>
									<p className="bs-ds-connect__clientnote">{ entry.note() }</p>
								</div>
							</div>
							{ false === health.pretty_routed ? (
								<Alert
									layout="default"
									tone="warning"
									desc={ sprintf(
										/* translators: %s: the assistant being set up, e.g. "Claude". */
										__( 'With plain permalinks, %s cannot sign in through the browser. Pick another structure under Settings → Permalinks.', 'bettershield' ),
										name
									) }
								/>
							) : (
								<>
									<CopyField label={ __( 'Connector address', 'bettershield' ) } value={ snippet.url || endpoint } copyLabel={ __( 'Copy the Address', 'bettershield' ) } />
									<Steps steps={ clientSteps( entry.key ) } />
								</>
							) }
							{ /* Said beside the address: an assistant that adds a site
							     by its address alone needs https (#2074). */ }
							{ false === health.https ? (
								<Alert
									layout="default"
									tone="warning"
									desc={ sprintf(
										/* translators: %s: the assistant being set up, e.g. "Claude". */
										__( 'This site is not on https, so %s can’t add it by address. Switch the site to https first.', 'bettershield' ),
										name
									) }
								/>
							) : null }
						</article>
					);
				} ) }
			</div>

			{ /* What the other tab holds, said once. */ }
			<div className="bs-ds-connect__others">
				<span className="bs-ds-connect__label">{ __( 'Editors & CLI', 'bettershield' ) }</span>
				{ KEY_CLIENTS.map( ( entry ) => (
					<Badge key={ entry.key }>
						<ClientLogo name={ entry.logo } size={ 12 } />
						{ entry.label() }
					</Badge>
				) ) }
				<span className="bs-ds-connect__otherstext">
					{ __( 'Each gets a ready-to-paste configuration.', 'bettershield' ) }
				</span>
				<Button type="secondary" size="sm" onClick={ () => setMode( 'key' ) }>
					{ __( 'Set Up an Editor', 'bettershield' ) }
				</Button>
			</div>
		</>
	);

	// Editors and command-line tools: a tile each, then the chosen one's setup.
	const keyPanel = (
		<>
			<div className="bs-ds-connect__tiles" role="tablist" aria-label={ __( 'Choose an editor or tool', 'bettershield' ) }>
				{ KEY_CLIENTS.map( ( entry ) => (
					<button
						key={ entry.key }
						type="button"
						role="tab"
						id={ tabId( CLIENTS_ID, entry.key ) }
						className="bs-ds-connect__tile"
						aria-selected={ client === entry.key }
						aria-controls={ panelId( CLIENTS_ID ) }
						tabIndex={ client === entry.key ? 0 : -1 }
						onClick={ () => setClient( entry.key ) }
						onKeyDown={ ( event ) =>
							onTabKey(
								event,
								KEY_CLIENTS.map( ( one ) => one.key ),
								client,
								setClient,
								CLIENTS_ID
							)
						}
					>
						<ClientMark logo={ entry.logo } />
						<span className="bs-ds-connect__tilename">{ entry.label() }</span>
						<span className="bs-ds-connect__tilenote">{ entry.note() }</span>
					</button>
				) ) }
			</div>

			<div className="bs-ds-connect__recipe" { ...panelProps( CLIENTS_ID, pickedClient.key ) }>
				<Steps steps={ clientSteps( pickedClient.key ) } />
				{ paired ? (
					<Recipe
						snippet={ 'vscode' === pickedClient.key ? { json: vscodeConfig( connection.fallback_endpoint || endpoint ) } : snippets[ pickedClient.key ] }
						endpoint={ endpoint }
					/>
				) : (
					<p className="bs-ds-connect__needkey">{ __( 'This assistant needs a connection key. Create one below, then copy the setup.', 'bettershield' ) }</p>
				) }
			</div>

			{ keyRow }
			{ tokenRow }
		</>
	);

	/*
	 * A setup into a connection that has to be answering. A site with the
	 * switch off answers no assistant, whatever credential it still holds, so
	 * a recipe here would be an instruction that cannot work.
	 */
	const open = connection.enabled && reads;
	const backup = !! connection.fallback_endpoint && connection.fallback_endpoint !== endpoint;
	const hasMore = backup || !! connection.prompt;

	const addCard = (
		<Card className="bs-ds-connect__card bs-ds-connect__add" aria-labelledby="bs-ds-connect-add">
			<Head
				id="bs-ds-connect-add"
				icon="plug"
				title={ __( 'Add BetterShield to your assistant', 'bettershield' ) }
				tip={ __( 'Claude and ChatGPT sign in through your browser, with nothing to paste. Editors and command-line tools use a connection key you create here.', 'bettershield' ) }
			>
				{ open ? (
					<Segmented
						id={ MODES_ID }
						label={ __( 'How the assistant connects', 'bettershield' ) }
						options={ [
							{ key: 'oauth', label: __( 'Browser sign-in', 'bettershield' ) },
							{ key: 'key', label: __( 'Editors & CLI', 'bettershield' ) },
						] }
						selected={ mode }
						onSelect={ setMode }
					/>
				) : null }
			</Head>

			{ open ? (
				<div className="bs-ds-connect__panel" { ...panelProps( MODES_ID, mode ) }>
					{ 'key' === mode ? keyPanel : oauthPanel }
				</div>
			) : (
				<p className="bs-ds-connect__closed">
					{ connection.enabled
						? __( 'Reading security info is off on Permissions, so an assistant would see nothing. Turn it on there to see the setup.', 'bettershield' )
						: __( 'Turn on “Allow AI assistant connections” at the top to see the setup for each assistant.', 'bettershield' ) }
				</p>
			) }

			{ announced ? (
				<div className="bs-ds-connect__notes" role="status">
					<Alert layout="default" tone="success" desc={ announced } />
				</div>
			) : null }

			{ /* Shared by both ways to connect, and closed until asked for, so
			     nothing stands above the address to copy. */ }
			{ open && hasMore ? (
				<div className="bs-ds-connect__more">
					<Button
						type="link"
						size="sm"
						trailing={ moreOpen ? 'chevron-up' : 'chevron-down' }
						aria-expanded={ moreOpen }
						aria-controls="bs-ds-connect-moreopts"
						onClick={ () => setMoreOpen( ! moreOpen ) }
					>
						{ __( 'More options', 'bettershield' ) }
					</Button>
					<div className="bs-ds-connect__extras" id="bs-ds-connect-moreopts" hidden={ ! moreOpen }>
						{ /* The plain-permalinks address. It always answers, so it
						     is the one to try when the pretty one does not — and on a
						     site where it already is the address, saying it twice
						     helps nobody. */ }
						{ backup ? (
							<CopyField
								label={ __( 'Backup address (if the first doesn’t work)', 'bettershield' ) }
								value={ connection.fallback_endpoint }
								copyLabel={ __( 'Copy the Backup Address', 'bettershield' ) }
							/>
						) : null }
						{ connection.prompt ? (
							<CopyField label={ __( 'A first question to ask your assistant', 'bettershield' ) } value={ connection.prompt } copyLabel={ __( 'Copy the Prompt', 'bettershield' ) } dir="auto" />
						) : null }
					</div>
				</div>
			) : null }

			{ false === connection.available ? (
				<div className="bs-ds-connect__notes">
					<Alert layout="default" tone="warning" desc={ __( 'Part of BetterShield didn’t load. Reinstall it from WordPress.org.', 'bettershield' ) } />
				</div>
			) : null }
		</Card>
	);

	/*
	 * Disconnect All ends the credential and every app's grant, the hub's
	 * included, so the confirmation names them and the line after says how
	 * many went.
	 */
	const appsCard = held ? (
		<Card className="bs-ds-connect__card" aria-labelledby="bs-ds-connect-apps">
			<Head
				id="bs-ds-connect-apps"
				icon="users"
				title={ __( 'Connected apps', 'bettershield' ) }
				headingRef={ appsHeading }
				tip={ __( 'Every app with access, who let it in, and when it was last used.', 'bettershield' ) }
			>
				<Button type="secondary" size="sm" icon="refresh-cw" isBusy={ appsReading } disabled={ appsReading } onClick={ readAppsAgain }>
					{ __( 'Refresh', 'bettershield' ) }
				</Button>
				<Armed type="secondary" label={ __( 'Disconnect All', 'bettershield' ) } consequence={ disconnectConsequence } busy={ working } onConfirm={ disconnect } />
			</Head>

			{ appsNote ? (
				<div className="bs-ds-connect__notes">
					<div role="status">
						<Alert layout="default" tone="success" desc={ appsNote } />
					</div>
				</div>
			) : null }

			{ appsBody }
		</Card>
	) : null;

	// Where the two opt-ins in the diagnostics are changed.
	const changeOnPermissions = (
		<Button type="linksub" size="sm" className="bs-ds-connect__healthlink" href={ permissions } trailing="arrow-right">
			{ __( 'Change on Permissions', 'bettershield' ) }
		</Button>
	);

	const diagnosticsCard = (
		<Card className="bs-ds-connect__card" aria-labelledby="bs-ds-connect-health">
			<Head
				id="bs-ds-connect-health"
				icon="gauge"
				title={ __( 'Connection diagnostics', 'bettershield' ) }
				headingRef={ healthHeading }
				tip={ __( 'Verified directly on the live site. The test makes a real call and shows exactly how far the request gets.', 'bettershield' ) }
			>
				<Button
					type="secondary"
					size="sm"
					className="bs-ds-connect__recheck"
					icon={ 'done' === recheck ? 'check' : 'refresh-cw' }
					isBusy={ 'busy' === recheck }
					disabled={ 'busy' === recheck }
					onClick={ recheckNow }
				>
					{ /* The longest word holds the width, so the button beside it stays put. */ }
					<span className="bs-ds-connect__recheckwords" data-longest={ recheckLongest }>
						<span>{ recheckWords[ recheck ] || recheckWords.idle }</span>
					</span>
				</Button>
				<Button type="primary" size="sm" icon={ tested && ! testing ? 'check' : 'play' } iconTone="onbrand" isBusy={ testing } disabled={ testing } onClick={ runTest }>
					<span className="bs-ds-connect__recheckwords" data-longest={ testLongest }>
						<span>{ testWords[ testing ? 'busy' : 'idle' ] }</span>
					</span>
				</Button>
			</Head>

			<p className={ 'failed' === recheck ? 'bs-ds-connect__recheckfail' : 'screen-reader-text' } role="status">
				{ 'done' === recheck ? __( 'Checked again just now.', 'bettershield' ) : null }
				{ 'failed' === recheck ? __( 'Could not check again. Try Re-check in a moment.', 'bettershield' ) : null }
			</p>

			<div className={ 'busy' === recheck ? 'bs-ds-connect__healths is-checking' : 'bs-ds-connect__healths' } aria-busy={ 'busy' === recheck }>
				<HealthRow
					label={ __( 'Served over https', 'bettershield' ) }
					ok={ !! health.https }
					attention
					state={ health.https ? __( 'Yes', 'bettershield' ) : __( 'No', 'bettershield' ) }
					detail={ health.https ? null : __( 'Claude and ChatGPT need https to connect.', 'bettershield' ) }
				/>
				<HealthRow
					label={ __( 'Site addresses match', 'bettershield' ) }
					ok={ !! health.scheme_agreement }
					attention
					state={ health.scheme_agreement ? __( 'Yes', 'bettershield' ) : __( 'No', 'bettershield' ) }
					detail={ health.scheme_agreement ? null : __( 'Your Site Address and WordPress Address differ, so assistants get redirected. Fix them in Settings › General.', 'bettershield' ) }
				/>
				{ /*
				   Three states, not two. A fact the payload did not state is not
				   a fact this card can report as a pass: a tick beside something
				   nobody said is a claim the screen invented.
				*/ }
				<HealthRow
					label={ __( 'Permalinks set up', 'bettershield' ) }
					ok={ true === health.pretty_routed }
					attention={ false === health.pretty_routed }
					state={ prettyRoutedState( health.pretty_routed ) }
					detail={
						false === health.pretty_routed
							? __( 'With plain permalinks, Claude and ChatGPT cannot sign in through the browser. Other clients still work.', 'bettershield' )
							: null
					}
				/>
				{ /* The count is the fact this row is for. The names, opened
				     here, were one paragraph of every tool broken at its
				     hyphens (#2557); Agent surface lists them grouped, with a
				     search, so the row leads there instead. */ }
				<HealthRow
					label={ __( 'Tools offered', 'bettershield' ) }
					ok={ tools > 0 }
					state={ String( tools ) }
					more={
						tools > 0 && tabUrl( 'bettershield-agents', 'surface' ) ? (
							<Button type="linksub" size="sm" className="bs-ds-connect__healthlink" href={ tabUrl( 'bettershield-agents', 'surface' ) } trailing="arrow-right">
								{ __( 'See Every Tool in Agent Surface', 'bettershield' ) }
							</Button>
						) : null
					}
				/>
				{ /*
				   The three opt-ins, from the live facts this screen already
				   holds rather than from the copy the connection carried when it
				   was read.
				*/ }
				<HealthRow
					label={ __( 'Let AI assistants see security info', 'bettershield' ) }
					ok={ reads }
					state={ reads ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }
					more={ changeOnPermissions }
				/>
				<HealthRow
					label={ __( 'Let AI assistants fix things', 'bettershield' ) }
					ok={ writes }
					state={ writes ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }
					detail={ writes ? null : __( 'While this is off, no account can approve AI fixes.', 'bettershield' ) }
					more={ changeOnPermissions }
				/>
				{ /* The approval comes with fixes and the account's role, so it
				     is only a question while fixes are on. */ }
				{ writes ? (
					<HealthRow
						label={ __( 'Your account can approve AI fixes', 'bettershield' ) }
						ok={ capability }
						state={ capability ? __( 'Yes', 'bettershield' ) : __( 'No', 'bettershield' ) }
						detail={ capability ? null : __( 'Your role doesn’t hold this permission. An administrator grants it.', 'bettershield' ) }
					/>
				) : null }
			</div>

			{ /* What the site itself said, under the sentence that translated
			     it — a certificate's own complaint is the thing a host asks for. */ }
			{ test ? (
				<div className="bs-ds-connect__test" ref={ testResult }>
					<Alert
						layout="default"
						tone={ 'ok' === test.step ? 'success' : 'warning' }
						desc={
							<>
								<p role="status">{ testSentence( test ) }</p>
								{ test.message ? <p className="bs-ds-connect__said">{ test.message }</p> : null }
							</>
						}
					/>
				</div>
			) : null }
		</Card>
	);

	return (
		<>
			{ hero }
			{ figures }
			{ accessCard }
			{ addCard }
			{ appsCard }
			{ diagnosticsCard }
		</>
	);
}

export default function Connect() {
	const { resource, reload } = useResource( 'agentSurface' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <ConnectBone /> }>
			{ ( data ) => <ConnectScreen surface={ data } /> }
		</Resource>
	);
}
