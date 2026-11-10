/**
 * The Overview's right rail (design frame 27:53347): Protection's six
 * switches on a tray, the agent connection, and the way back in.
 */

import './Rail.css';

import { createInterpolateElement, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { mayManage, sectionUrl, tabUrl } from '../../nav';
import { listOf } from '../../setup/format';
import { useResource, useStore } from '../../store';
import { announce } from '../../ui/announce';
import { whenPhrase } from '../../ui/when';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, Tray } from '../ui/Card';
import { ActionRow, KeyValue, KeyValues } from '../ui/KeyValue';
import ToggleRow from '../ui/ToggleRow';
import { formatCount } from '../../ui/count';
import { noCodesWord } from '../data/recovery';

/** The six protections the Overview offers as switches, in the design's order. */
export const RAIL_ITEMS = [ 'xmlrpc', 'file_editor', 'user_enumeration', 'security_headers', 'directory_browsing', 'version_disclosure' ];

/**
 * The tray's note: the protections not drawn as switches, off and on.
 *
 * @param {number} off Protections off that the card doesn't show.
 * @param {number} on  Protections on that the card doesn't show.
 * @return {string} The note, or nothing when the card shows every one.
 */
export function restNote( off, on ) {
	if ( off > 0 && on > 0 ) {
		return sprintf(
			/* translators: 1: protections not shown here that are off, 2: protections not shown here that are on. */
			_n( 'Not shown here: %1$d off, %2$d on.', 'Not shown here: %1$d off, %2$d on.', off, 'bettershield' ),
			off,
			on
		);
	}

	if ( off > 0 ) {
		return sprintf(
			/* translators: %d: how many protections are switched off. */
			_n( '%d more is off. Turn it on when you’re ready.', '%d more are off. Turn them on when you’re ready.', off, 'bettershield' ),
			off
		);
	}

	if ( on > 0 ) {
		return sprintf(
			/* translators: %d: protections not shown here that are on. */
			_n( '%d more is on.', '%d more are on.', on, 'bettershield' ),
			on
		);
	}

	return '';
}

export function ProtectionTray( { protection } ) {
	const { busy, applyItem, revertItem } = useStore();
	// The position each pressed switch was asked to take, by item, until the
	// server answers. A switch drawn only from the server's value sat still
	// for the whole request and then snapped across (#2308).
	const [ pending, setPending ] = useState( {} );

	if ( ! protection ) {
		return null;
	}

	const items = RAIL_ITEMS.map( ( key ) => ( protection.items || [] ).find( ( item ) => item.key === key ) ).filter( Boolean );
	// A protection the server or another plugin already provides is on, and
	// isn't this switch's to change (#2716).
	const shown = ( item ) => Boolean( item.in_force_elsewhere ) || ( item.key in pending ? pending[ item.key ] : Boolean( item.active ) );
	// The server's count, moved by the switches still on their way, so it
	// moves with the one pressed.
	const moved = ( protection.items || [] ).reduce(
		( sum, item ) => sum + ( item.key in pending && pending[ item.key ] !== Boolean( item.active ) ? ( pending[ item.key ] ? 1 : -1 ) : 0 ),
		0
	);
	const count = protection.count || {};
	const total = Number( count.total ) || 0;
	const active = Math.min( total, Math.max( 0, ( Number( count.on ) || 0 ) + moved ) );
	// The note counts only the protections the card doesn't draw, so the
	// switches and the note add up to the badge (#2731).
	const drawnOn = items.filter( shown ).length;
	const restOff = Math.max( 0, total - active - ( items.length - drawnOn ) );
	const restOn = Math.max( 0, active - drawnOn );
	// The count is of every protection, and Protect keeps them on two tabs, so
	// the two numbers here add up to the one on the badge.
	const onTab = ( tab ) => Number( count.screens?.[ tab ]?.total ) || 0;

	const settle = ( key ) =>
		setPending( ( current ) => {
			const next = { ...current };

			delete next[ key ];

			return next;
		} );

	/*
	 * The switch moves at once and stays put until the answer, which brings
	 * the server's own value in with it. A refusal, or a password prompt
	 * canceled, puts it back: the store's notice says why. Pressed while any
	 * action is in flight, the store would drop the request without either
	 * answer, so the press is not taken and the switch does not move.
	 */
	const flip = ( item, name ) => {
		if ( null !== busy && undefined !== busy ) {
			return;
		}

		if ( item.key in pending ) {
			return;
		}

		const on = ! item.active;

		setPending( ( current ) => ( { ...current, [ item.key ]: on } ) );
		announce(
			on
				? sprintf(
						/* translators: %s: a protection's name. */
						__( 'Switching on %s…', 'bettershield' ),
						name
				  )
				: sprintf(
						/* translators: %s: a protection's name. */
						__( 'Switching off %s…', 'bettershield' ),
						name
				  )
		);

		const done = () => {
			settle( item.key );
			announce(
				on
					? sprintf(
							/* translators: %s: a protection's name. */
							__( '%s is on.', 'bettershield' ),
							name
					  )
					: sprintf(
							/* translators: %s: a protection's name. */
							__( '%s is off.', 'bettershield' ),
							name
					  )
			);
		};
		const refused = () => {
			settle( item.key );
		};

		if ( on ) {
			applyItem( item.key, undefined, done, refused );
		} else {
			revertItem( item.key, done, refused );
		}
	};

	return (
		<Tray
			note={ restNote( restOff, restOn ) }
		>
			<Card aria-labelledby="bs-ds-protection-title">
				<CardHead icon="shield" title={ __( 'Protection', 'bettershield' ) } id="bs-ds-protection-title">
					<Badge>
						{ sprintf(
							/* translators: 1: protections switched on, 2: protections there are. */
							__( '%1$d of %2$d on', 'bettershield' ),
							active,
							total
						) }
					</Badge>
				</CardHead>
				{ items.map( ( item ) => {
					// Applied with a narrower choice than the title says
					// (XML-RPC with pingbacks only), the switch names it
					// rather than reading as all of it.
					const label = item.scope
						? sprintf(
								/* translators: 1: a protection's name, 2: the narrower choice it was applied with, such as "pingbacks only". */
								__( '%1$s — %2$s', 'bettershield' ),
								item.label,
								item.scope
						  )
						: item.label;

					return (
						<ToggleRow
							key={ item.key }
							label={ label }
							checked={ shown( item ) }
							// Kept enabled while it works, so focus stays on it;
							// the row ignores a second press until the answer.
							isBusy={ item.key in pending }
							disabled={ ! mayManage() || Boolean( item.in_force_elsewhere ) }
							onChange={ () => flip( item, item.label ) }
						/>
					);
				} ) }
				<p className="bs-ds-protection__where bs-ds-t12 bs-ds-r bs-ds-c2">
					{ createInterpolateElement(
						sprintf(
							/* translators: 1: protections on the Hardening tab, 2: protections on the Login & access tab. */
							_n(
								'See all protections on <hardening>Hardening</hardening> (%1$d) and <login>Login & Access</login> (%2$d).',
								'See all protections on <hardening>Hardening</hardening> (%1$d) and <login>Login & Access</login> (%2$d).',
								onTab( 'login' ),
								'bettershield'
							),
							onTab( 'hardening' ),
							onTab( 'login' )
						),
						{
							hardening: <a href={ tabUrl( 'bettershield-protect', 'hardening' ) } />,
							login: <a href={ tabUrl( 'bettershield-protect', 'login' ) } />,
						}
					) }
				</p>
			</Card>
		</Tray>
	);
}

function AgentsCardBody() {
	const { resource } = useResource( 'agentSurface' );

	// A failed read says so, rather than drawing the same nothing as a card
	// that has not loaded yet.
	if ( 'error' === resource.status ) {
		return (
			<Card aria-labelledby="bs-ds-agents-title">
				<CardHead icon="bot" title={ __( 'Agents', 'bettershield' ) } id="bs-ds-agents-title" />
				<ActionRow text={ __( 'Couldn’t load this. Try again in a moment.', 'bettershield' ) } link={ __( 'Open Agents', 'bettershield' ) } href={ sectionUrl( 'bettershield-agents' ) } />
			</Card>
		);
	}

	if ( 'ready' !== resource.status || ! resource.data ) {
		return null;
	}

	const surface = resource.data;
	const mcp = surface.mcp || {};
	// A credential issued and not yet used is ready, not connected (#2062).
	const issued = Boolean( mcp.enabled && mcp.connected && false === mcp.used );
	const connected = Boolean( mcp.enabled && ( ( mcp.connected && ! issued ) || Number( mcp.apps ) > 0 ) );
	const tools = Number( mcp.tools ) || 0;
	const waiting = Number( surface.open_requests ) || 0;

	return (
		<Card aria-labelledby="bs-ds-agents-title">
			<CardHead icon="bot" title={ __( 'Agents', 'bettershield' ) } id="bs-ds-agents-title">
				<Badge tone={ connected ? 'brand' : 'neutral' }>{ connected ? __( 'Connected', 'bettershield' ) : issued ? __( 'Ready', 'bettershield' ) : __( 'None', 'bettershield' ) }</Badge>
			</CardHead>
			<ActionRow
				text={
					connected
						? __( 'An assistant is connected.', 'bettershield' )
						: issued
						? __( 'A connection key is ready, but no AI assistant has used it yet.', 'bettershield' )
						: __( 'No AI assistant is connected.', 'bettershield' )
				}
				link={ connected || issued ? __( 'Open Connect', 'bettershield' ) : __( 'Connect One', 'bettershield' ) }
				href={ tabUrl( 'bettershield-agents', 'connect' ) }
			/>
			<ActionRow
				text={ sprintf(
					/* translators: %d: how many actions this site offers a connected assistant. */
					_n( 'AI assistants could use %d action on this site.', 'AI assistants could use %d actions on this site.', tools, 'bettershield' ),
					tools
				) }
				link={ __( 'Open Agent Surface', 'bettershield' ) }
				href={ tabUrl( 'bettershield-agents', 'surface' ) }
			/>
			<ActionRow
				text={
					waiting > 0
						? sprintf(
								/* translators: %d: how many requests are waiting for an answer. */
								_n( '%d request is waiting for you.', '%d requests are waiting for you.', waiting, 'bettershield' ),
								waiting
						  )
						: __( 'No AI request is waiting for your approval.', 'bettershield' )
				}
				link={ __( 'Open Requests', 'bettershield' ) }
				href={ tabUrl( 'bettershield-agents', 'requests' ) }
			/>
		</Card>
	);
}

/** The agent connection is read with the manage capability, like its route. */
export function AgentsCard() {
	return mayManage() ? <AgentsCardBody /> : null;
}

export function RecoveryCard( { overview } ) {
	const readiness = overview.recovery_readiness;

	if ( ! readiness ) {
		return null;
	}

	const codes = Number( overview.recovery_codes_left ) || 0;
	const linked = 'available' === readiness.link;
	// An emailed link the owner hasn't said arrived is not yet a way back in:
	// the "No way back in has been confirmed yet" finding stays open for it,
	// so the card does not call recovery ready beside it (#2629).
	const unconfirmed = false === overview.recovery_confirmed;
	const awaiting = linked && 'pending' === overview.recovery_receipt;
	const recovery = tabUrl( 'bettershield-protect', 'recovery' );

	return (
		<Card className="bs-ds-recovery" aria-labelledby="bs-ds-recovery-title">
			<div className="bs-ds-recovery__top">
				<CardHead
					icon="key"
					// Never "ready" over a link row that says it needs attention: printed
					// codes keep a site out of needs_attention, and a link can still be
					// missing, expired or refused beside them.
					title={ readiness.needs_attention || ! linked || unconfirmed ? __( 'Recovery isn’t confirmed yet', 'bettershield' ) : __( 'You can get back in if locked out', 'bettershield' ) }
					id="bs-ds-recovery-title"
					line
				/>
				<KeyValues>
					<KeyValue
						label={ __( 'Recovery email link', 'bettershield' ) }
						status={ linked && ! awaiting ? 'ok' : '' }
						value={ linked ? ( awaiting ? __( 'Sent, not confirmed yet', 'bettershield' ) : __( 'Ready', 'bettershield' ) ) : __( 'Needs attention', 'bettershield' ) }
					/>
					<KeyValue
						label={ __( 'Recovery codes', 'bettershield' ) }
						value={
							<Badge tone={ codes > 0 ? 'neutral' : 'yellow' }>
								{ codes > 0
									? sprintf(
											/* translators: %d: how many unused recovery codes remain. */
											_n( '%d left', '%d left', codes, 'bettershield' ),
											codes
									  )
									: noCodesWord( overview.recovery_codes_issued ) }
							</Badge>
						}
					/>
					<KeyValue
						label={ __( 'Recovery last checked', 'bettershield' ) }
						value={ readiness.checked_at ? whenPhrase( readiness.checked_at ) : __( 'Never checked', 'bettershield' ) }
					/>
				</KeyValues>
			</div>
			{ /* Only to somebody the Recovery tab opens for. */ }
			{ recovery ? (
				<div className="bs-ds-recovery__actions">
					<Button type="secondary" size="sm" href={ recovery }>
						{ __( 'Review Recovery', 'bettershield' ) }
					</Button>
					{ /* Only a hash of each code is kept, so codes on record
					     cannot be shown or printed again: the tab offers a new
					     set, which is what this says, and only once none are
					     left. With codes left, reviewing recovery is the action. */ }
					{ 0 === codes ? (
						<Button type="ghost" size="sm" icon="printer" iconTone="1" href={ recovery }>
							{ __( 'Get Recovery Codes', 'bettershield' ) }
						</Button>
					) : null }
				</div>
			) : null }
		</Card>
	);
}

/**
 * What the Files card says when no change is open.
 *
 * Nothing open is a clean site only when a check ran lately and compared
 * everything. It is also what no check at all leaves, a check that could not
 * compare part of the site, and one too old to speak for today, and the card
 * says which, as the Files screen does, rather than calling all four clean.
 * A change marked expected is not open either, and the file may still differ
 * from the published copy, so with any marked the line says how many.
 *
 * @param {Object} panel The files panel.
 * @return {{badge: string, tone: string, line: string}} The badge and the line.
 */
function nothingOpen( panel ) {
	const expected = Number( panel.expected ) || 0;

	if ( ! panel.ever_run ) {
		return { badge: __( 'Never checked', 'bettershield' ), tone: 'neutral', line: __( 'Your WordPress files haven’t been checked against the official versions yet.', 'bettershield' ) };
	}

	// A plugin nothing publishes is watched against the copy first seen, so
	// it is not among what was not compared (#1969).
	const notCompared = Math.max( 0, ( Number( panel.unverifiable ) || 0 ) - ( Number( panel.watched ) || 0 ) );

	if ( notCompared > 0 ) {
		return {
			badge: sprintf(
				/* translators: %d: how many plugins, themes or core could not be compared. */
				_n( '%d not compared', '%d not compared', notCompared, 'bettershield' ),
				notCompared
			),
			tone: 'yellow',
			line:
				expected > 0
					? sprintf(
							/* translators: %d: how many file changes are marked expected. */
							_n(
								'No unexpected file changes. You approved %d change. Some files couldn’t be checked.',
								'No unexpected file changes. You approved %d changes. Some files couldn’t be checked.',
								expected,
								'bettershield'
							),
							expected
					  )
					: __( 'Nothing differs in the files compared. Part of the site was not compared.', 'bettershield' ),
		};
	}

	if ( panel.stale ) {
		return {
			badge: __( 'Out of date', 'bettershield' ),
			tone: 'neutral',
			line:
				expected > 0
					? sprintf(
							/* translators: 1: when the files were last checked, e.g. "today, 5:14 PM"; 2: how many file changes are marked expected. */
							_n(
								'Last checked %1$s. Nothing was open then, and %2$d change is accepted.',
								'Last checked %1$s. Nothing was open then, and %2$d changes are accepted.',
								expected,
								'bettershield'
							),
							whenPhrase( panel.last_run_at ),
							expected
					  )
					: sprintf(
							/* translators: %s: when the files were last checked, e.g. "today, 5:14 PM". */
							__( 'Last checked %s. Nothing differed then.', 'bettershield' ),
							whenPhrase( panel.last_run_at )
					  ),
		};
	}

	return {
		badge: __( 'All accepted', 'bettershield' ),
		tone: 'green',
		line:
			expected > 0
				? sprintf(
						/* translators: %d: how many file changes are marked expected. */
						_n( 'Nothing is open. %d change is accepted.', 'Nothing is open. %d changes are accepted.', expected, 'bettershield' ),
						expected
				  )
				: __( 'Every file matches the copy WordPress.org shipped.', 'bettershield' ),
	};
}

/**
 * Open changes by kind, in the words the Files screen labels its rows with.
 *
 * @param {Object} item Counts with `modified`, `added`, `removed` and `unreadable`.
 * @return {string} The kinds there are any of.
 */
function kindPhrases( item ) {
	return listOf(
		[
			item.modified
				? sprintf(
						/* translators: %d: how many files differ from the official copy. */
						_n( '%d changed', '%d changed', item.modified, 'bettershield' ),
						item.modified
				  )
				: '',
			item.added
				? sprintf(
						/* translators: %d: how many files are not in the official release. */
						_n( '%d added', '%d added', item.added, 'bettershield' ),
						item.added
				  )
				: '',
			item.removed
				? sprintf(
						/* translators: %d: how many published files are missing. */
						_n( '%d missing', '%d missing', item.removed, 'bettershield' ),
						item.removed
				  )
				: '',
			item.unreadable
				? sprintf(
						/* translators: %d: how many files could not be read to compare. */
						_n( '%d could not be read', '%d could not be read', item.unreadable, 'bettershield' ),
						item.unreadable
				  )
				: '',
		].filter( Boolean )
	);
}

/**
 * The files, as the classic Overview kept them: whether they were ever
 * checked and when, what could not be compared, what is marked expected,
 * what is open and where it comes from — a plugin that is no longer
 * installed above all — and an added file that can run as code, which a
 * large count hides.
 *
 * @param {Object} props
 * @param {Object} props.panel The overview's files panel.
 */
export function FilesCard( { panel } ) {
	if ( ! panel ) {
		return null;
	}

	const files = tabUrl( 'bettershield-activity', 'files' );

	// A change table that could not be read is not a clean site.
	if ( null === panel.open || undefined === panel.open ) {
		return (
			<Card className="bs-ds-filescard" aria-labelledby="bs-ds-filescard-title">
				<CardHead icon="file-diff" title={ __( 'File Changes', 'bettershield' ) } id="bs-ds-filescard-title" />
				<ActionRow text={ __( 'Couldn’t load this. Try again in a moment.', 'bettershield' ) } link={ files ? __( 'Open File Changes', 'bettershield' ) : null } href={ files } />
			</Card>
		);
	}

	const open = Number( panel.open ) || 0;
	const kinds = panel.kinds || {};
	const quiet = open > 0 ? null : nothingOpen( panel );
	const sources = ( panel.sources || [] ).slice( 0, 3 );

	return (
		<Card className="bs-ds-filescard" aria-labelledby="bs-ds-filescard-title">
			<CardHead icon="file-diff" title={ __( 'File Changes', 'bettershield' ) } id="bs-ds-filescard-title">
				{ open > 0 ? (
					<Badge tone="yellow">
						{ sprintf(
							/* translators: %s: how many changed files are waiting to be reviewed. */
							_n( '%s to review', '%s to review', open, 'bettershield' ),
							formatCount( open )
						) }
					</Badge>
				) : (
					<Badge tone={ quiet.tone }>{ quiet.badge }</Badge>
				) }
			</CardHead>
			<ActionRow text={ open > 0 ? kindPhrases( kinds ) : quiet.line } link={ files ? __( 'Open File Changes', 'bettershield' ) : null } href={ files } />
			{ open > 0 && kinds.added_code > 0 ? (
				<ActionRow
					text={ sprintf(
						/* translators: %d: how many added files can run as code. */
						_n( '%d new file could run on your site. Check it on File Changes.', '%d new files could run on your site. Check them on File Changes.', kinds.added_code, 'bettershield' ),
						kinds.added_code
					) }
				/>
			) : null }
			{ open > 0 && sources.length ? (
				<KeyValues className="bs-ds-filescard__sources">
					{ sources.map( ( source ) => (
						<KeyValue
							key={ `${ source.name }|${ source.version }` }
							label={
								source.installed
									? `${ source.name } ${ source.version }`.trim()
									: sprintf(
											/* translators: %s: a plugin or theme name, with its version. */
											__( '%s (not installed)', 'bettershield' ),
											`${ source.name } ${ source.version }`.trim()
									  )
							}
							// A core file changed is the change that matters most (#2118).
							status={ source.installed && ! source.core ? '' : 'warning' }
							value={ kindPhrases( source ) }
						/>
					) ) }
				</KeyValues>
			) : null }
		</Card>
	);
}
