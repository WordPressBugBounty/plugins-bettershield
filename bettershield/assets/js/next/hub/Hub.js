/**
 * BetterShield Hub: connecting this site to the hub, which is optional.
 *
 * One card. Not connected: what the hub is for, how far it may reach, and the
 * button that starts it. Connected: what the hub can do right now (the site's
 * own switches decide that, not the grant), when it last read the site, and
 * Disconnect. The hub's address is not a setting: it is hub.bettershield.ai
 * unless wp-config.php pins another.
 *
 * Connecting is an ordinary grant through this site's own consent page, so it
 * is listed with the other applications and ends the same way. Nothing in the
 * plugin waits on the hub.
 */

import './Hub.css';

import apiFetch from '@wordpress/api-fetch';
import { createInterpolateElement, useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { formatTime, isWorking, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { openInNewTab, useOnReturn } from '../ui/newTab';
import SettingRow from '../ui/SettingRow';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import brand from '../setup/brand';
import ToggleRow from '../ui/ToggleRow';

const HUB = '/bettershield/v1/hub';

/** Why a link that is on sends nothing right now, by the reason the site gives. */
function linkStanding( link ) {
	return {
		staging: __( 'This site is marked as a test (staging) copy, so nothing is sent. Change that on the Overview.', 'bettershield' ),
		moved: __( 'This site was copied from another, so nothing is sent. Turn this off and on again to fix it.', 'bettershield' ),
		other_hub: __( 'Instant alerts only work with hub.bettershield.ai, and this site is connected to a different hub.', 'bettershield' ),
		not_connected: __( 'This site is no longer connected to hub.bettershield.ai, so instant alerts stop at the next run.', 'bettershield' ),
		unavailable: __( 'Your server can’t secure the data sent, so nothing is sent. Ask your host to update PHP.', 'bettershield' ),
	}[ link.standing ];
}

/** Why the link cannot be turned on here, by the reason the site gives. */
function linkRefusal( link ) {
	return {
		staging: __( 'This site is marked as a test (staging) copy, so nothing is sent. Change that on the Overview.', 'bettershield' ),
		other_hub: __( 'Instant alerts only work with hub.bettershield.ai, and this site is connected to a different hub.', 'bettershield' ),
		not_connected: __( 'Instant alerts need this site connected to hub.bettershield.ai.', 'bettershield' ),
		unavailable: __( 'Your server can’t secure the data sent, so this is off. Ask your host to update PHP.', 'bettershield' ),
	}[ link.refusal ];
}

/** How sending has gone, in a line: what the hub last said, and when. */
function linkProgress( link ) {
	if ( link.retry_at && 401 === link.last_answer ) {
		return __( 'Setting up can take up to six hours. Events are saved and sent once it’s ready.', 'bettershield' );
	}

	if ( link.retry_at ) {
		return sprintf(
			/* translators: %s: when the link tries again, e.g. "today, 5:14 PM". */
			__( 'The last send didn’t go through. It will try again %s.', 'bettershield' ),
			whenPhrase( link.retry_at )
		);
	}

	if ( link.last_sent_at ) {
		return sprintf(
			/* translators: 1: when events were last sent, 2: when the last heartbeat went, e.g. "today, 5:14 PM". */
			__( 'Last sent %1$s. Last online signal %2$s.', 'bettershield' ),
			whenPhrase( link.last_sent_at ),
			whenPhrase( link.heartbeat_at )
		);
	}

	if ( link.heartbeat_at ) {
		return sprintf(
			/* translators: %s: when the last heartbeat went, e.g. "today, 5:14 PM". */
			__( 'No events to send yet. Last online signal %s.', 'bettershield' ),
			whenPhrase( link.heartbeat_at )
		);
	}

	return __( 'Turned on. The first online signal goes within a few minutes.', 'bettershield' );
}

/**
 * The Hub link: whether this site sends its security events to the hub as they
 * happen. Off until the owner turns it on; turning it off deletes the key it
 * signs with, and turning it on again makes a new one.
 */
function LinkRow( { link, busy, onSet } ) {
	const blocked = ! link.on && !! link.refusal;
	const standing = link.on && link.standing ? linkStanding( link ) : '';

	return (
		<SettingRow
			className="bs-ds-hub__link"
			title={ __( 'Send alerts to the hub instantly', 'bettershield' ) }
			about={ __(
				'Sends security events to hub.bettershield.ai as they happen, plus a regular “still online” signal.',
				'bettershield'
			) }
			tip={ __( 'Without this, the hub only sees changes when it next checks your site. Sends are secured with a key that is deleted when you turn this off.', 'bettershield' ) }
			meta={ ( () => {
				if ( blocked ) {
					return linkRefusal( link );
				}

				return link.on && ! standing ? linkProgress( link ) : null;
			} )() }
			toggle={ {
				checked: link.on,
				disabled: busy || blocked,
				onChange: ( on ) => onSet( { on } ),
			} }
		>
			{ standing ? <Alert layout="default" tone="info" desc={ standing } /> : null }
			{ link.on ? (
				<>
					<p className="bs-ds-hub__meta">
						{ __(
							'Always sent: high and critical events, vulnerabilities, protections turned on or off, plugin, theme and role changes, and what other AI assistants did.',
							'bettershield'
						) }
					</p>
					<p className="bs-ds-hub__meta">
						{ __( 'Usernames are scrambled and IP addresses shortened. Never sent: file contents, passwords, keys or personal details.', 'bettershield' ) }
					</p>
					<ToggleRow
						label={ __( 'Also send medium events and completed checks', 'bettershield' ) }
						checked={ link.posture }
						disabled={ busy }
						onChange={ () => onSet( { on: true, posture: ! link.posture, full_log: link.full_log } ) }
					/>
					<ToggleRow
						label={ __( 'Also send all other activity (logins, edits and more)', 'bettershield' ) }
						checked={ link.full_log }
						disabled={ busy }
						onChange={ () => onSet( { on: true, posture: link.posture, full_log: ! link.full_log } ) }
					/>
				</>
			) : null }
		</SettingRow>
	);
}

export default function Hub() {
	const { connectHub, disconnectHub, setHubLink, busy } = useStore();
	const [ hub, setHub ] = useState( null );
	const [ failed, setFailed ] = useState( false );
	// Bumped by Try again, so the read below runs once more.
	const [ attempt, setAttempt ] = useState( 0 );

	/*
	 * Disconnect draws the card again without itself, so the keyboard goes to
	 * the card's heading once the hub has gone.
	 */
	const heading = useRef( null );
	const afterEnd = useMutationFocus( heading );
	const [ ended, setEnded ] = useState( '' );

	useEffect( () => {
		let live = true;

		setFailed( false );

		apiFetch( { path: HUB } ).then(
			( data ) => {
				if ( live ) {
					setHub( data );
				}
			},
			() => {
				if ( live ) {
					setFailed( true );
				}
			}
		);

		return () => {
			live = false;
		};
	}, [ attempt ] );

	/*
	 * Connect opens the hub in a new tab (#2621), so the card reads the hub
	 * again when the owner comes back to this one. A read that fails then
	 * keeps the card as it was rather than putting the error in its place.
	 */
	const [ opened, setOpened ] = useState( false );
	const joined = !! hub && hub.connected;

	useOnReturn( opened && ! joined, () => apiFetch( { path: HUB } ).then( setHub, () => null ) );

	// The card changes under the owner, so the keyboard goes to its heading.
	useEffect( () => {
		if ( opened && joined ) {
			heading.current?.focus( { preventScroll: true } );
		}
	}, [ opened, joined ] );

	/*
	 * A read that failed says so. Drawing nothing took the only Disconnect off
	 * the screen while a hub may well still hold access.
	 */
	if ( failed ) {
		return (
			<ErrorState title={ sprintf( /* translators: %s: the plugin's name, or the label the site owner gave it. */ __( '%s Hub', 'bettershield' ), brand() ) } onRetry={ () => setAttempt( ( n ) => n + 1 ) }>
				{ __( 'Couldn’t load the hub status. Reload the page; nothing was changed.', 'bettershield' ) }
			</ErrorState>
		);
	}

	if ( ! hub ) {
		return (
			<Skeleton label={ __( 'Loading the hub connection…', 'bettershield' ) }>
				<CardBone rows={ [ '90%', '60%', '40%' ] } />
			</Skeleton>
		);
	}

	const connecting = isWorking( busy, 'hub-connect' );
	const ending = isWorking( busy, 'hub-disconnect' );
	const linking = isWorking( busy, 'hub-link' );
	// The grant that reaches furthest, newest first among equals: an older
	// write grant from before a reconnect still works.
	const apps = hub.apps || [];
	const app = apps.find( ( grant ) => 'read write' === grant.scope ) || apps[ 0 ] || null;
	// When the hub last read the site: the newest use of any of its grants.
	const lastRead =
		apps
			.map( ( grant ) => grant.last_used )
			.filter( Boolean )
			.sort()
			.pop() || null;
	const quietForADay = !! lastRead && Date.now() - new Date( lastRead ).getTime() > 24 * 60 * 60 * 1000;
	// The hub this grant was approved for; the address can move since, in
	// wp-config.php or from a setting older versions kept, and the grant is
	// still that hub's until it is disconnected.
	const connectedHost = app && app.host ? app.host : hub.host;
	const moved = !! app && ! hub.pin_invalid && connectedHost !== hub.host;
	// Plain permalinks route none of the addresses the hub signs in through.
	const plain = false === hub.pretty_routed;

	const start = () =>
		connectHub( 'write', ( result ) => {
			if ( result && result.redirect && openInNewTab( result.redirect ) ) {
				setOpened( true );
			}
		} );

	/*
	 * A grant is not access: the site's own switches decide what a hub call
	 * meets, and the card says that rather than what the grant was approved
	 * for. Every refusal is named: with two of them, undoing one does not let
	 * the hub in, so only a lone refusal promises that it does.
	 */
	const refused = hub.connected && false === hub.reachable;
	const readsOnly = ! refused && !! app && 'read write' === app.scope && false === hub.writes;
	const refusals = Array.isArray( hub.refused_by ) ? hub.refused_by : [];
	const alone = {
		staging: __( 'This site is marked as a test (staging) copy, so the hub can’t connect. Change that on the Overview.', 'bettershield' ),
		connection: __( 'The hub can’t connect because AI assistant connections are off. Turn them on under Agents › Connect.', 'bettershield' ),
		lockdown: __( 'Hub access is paused while the site is locked down, and resumes when the lockdown ends.', 'bettershield' ),
		reading: __( 'The hub can’t connect because AI assistants can’t see this site. Turn that on under Agents › Connect.', 'bettershield' ),
	};
	const among = {
		staging: __( 'This site is marked as a test (staging) copy.', 'bettershield' ),
		connection: __( 'AI assistant connections are off.', 'bettershield' ),
		lockdown: __( 'The site is locked down, which pauses hub access.', 'bettershield' ),
		reading: __( 'AI assistants can’t see this site.', 'bettershield' ),
	};
	const refusal =
		refusals.length > 1
			? [
					__( 'Several settings are blocking the hub. Fix each one below to reconnect.', 'bettershield' ),
					...refusals.map( ( key ) => among[ key ] ).filter( Boolean ),
			  ].join( ' ' )
			: alone[ refusals[ 0 ] ];
	// Where each refusal is undone, once each: the switches share a screen.
	const fixes = [
		refusals.includes( 'staging' ) && { href: hub.overview_url, label: __( 'Open the Overview', 'bettershield' ) },
		refusals.includes( 'lockdown' ) && hub.recovery_url && { href: hub.recovery_url, label: __( 'Open Recovery', 'bettershield' ) },
		( readsOnly || refusals.some( ( key ) => 'connection' === key || 'reading' === key ) ) && {
			href: hub.agents_url,
			label: __( 'Open Agents › Connect', 'bettershield' ),
		},
	].filter( Boolean );
	// Not connected yet: the start is refused while a lockdown is on, or on
	// a copy marked as staging, which refuses the hub (#2151).
	const lockedDown = refusals.includes( 'lockdown' );
	const staging = refusals.includes( 'staging' );

	const end = () =>
		disconnectHub(
			afterEnd( ( result ) => {
				setHub( result );
				setEnded( __( 'Disconnected from the hub.', 'bettershield' ) );
			} )
		);

	const connected = hub.connected && app;
	let standing = '';

	if ( connected && ! refused ) {
		if ( readsOnly ) {
			standing = __( 'The hub can view this site but not fix anything, because fixes are turned off under Agents.', 'bettershield' );
		} else {
			standing =
				'read write' === app.scope
					? __( 'The hub can view this site and make fixes that can be undone.', 'bettershield' )
					: __( 'The hub can view this site but not change anything.', 'bettershield' );
		}
	}

	return (
		<Card className="bs-ds-hub" aria-labelledby="bs-ds-hub-title">
			<CardHead
				icon="link"
				id="bs-ds-hub-title"
				title={
					<span ref={ heading } tabIndex={ -1 } className="bs-ds-hub__title">
						{ sprintf( /* translators: %s: the plugin's name, or the label the site owner gave it. */ __( '%s Hub', 'bettershield' ), brand() ) }
					</span>
				}
			>
				{ connected ? <Badge tone={ refused ? 'yellow' : 'brand' }>{ __( 'Connected', 'bettershield' ) }</Badge> : null }
			</CardHead>

			<div className="bs-ds-hub__body">
				{ /* Pinned to an address the site cannot use: the card says so
				     rather than connecting to the default instead. */ }
				{ hub.pin_invalid ? (
					<div role="alert">
						<Alert
							layout="default"
							tone="error"
							desc={ __( 'The hub address set in your wp-config.php file isn’t a valid https address, so this site can’t connect. Ask your developer.', 'bettershield' ) }
						/>
					</div>
				) : null }
				{ /* Said, because the card that follows reads the same as one
				     that was never connected. */ }
				{ ended && ! hub.connected ? (
					<div role="status">
						<Alert layout="default" tone="success" desc={ ended } />
					</div>
				) : null }

				{ connected ? (
					<>
						{ refused && refusal ? (
							<Alert
								layout="default"
								tone="warning"
								desc={ refusal }
								actions={
									fixes.length
										? fixes.map( ( fix ) => (
												<Button key={ fix.href } type="secondary" size="sm" href={ fix.href }>
													{ fix.label }
												</Button>
										  ) )
										: null
								}
							/>
						) : (
							<p className="bs-ds-hub__lead">{ standing }</p>
						) }
						<p className="bs-ds-hub__meta">
							{ sprintf(
								/* translators: 1: the hub's host name, 2: when the connection was approved. */
								__( 'Connected to %1$s since %2$s.', 'bettershield' ),
								connectedHost,
								app.granted_at ? formatTime( app.granted_at ) : __( 'recently', 'bettershield' )
							) }{ ' ' }
							{ /* Whether the hub is still checking in, which the
							     connection date alone could not say. */ }
							{ lastRead
								? sprintf(
										/* translators: %s: when the hub last read this site, e.g. "today, 5:14 PM". */
										__( 'Last checked by the hub %s.', 'bettershield' ),
										whenPhrase( lastRead )
								  )
								: __( 'The hub hasn’t checked this site yet.', 'bettershield' ) }
							{ quietForADay ? ' ' + __( 'The hub hasn’t checked this site for over a day.', 'bettershield' ) : null }
						</p>
						{ moved ? (
							<Alert
								layout="default"
								tone="info"
								desc={ sprintf(
									/* translators: %s: the host name the hub address names now. */
									__( 'The hub address is now %s. Disconnect and reconnect to move this site there.', 'bettershield' ),
									hub.host
								) }
							/>
						) : null }
						<div className="bs-ds-hub__actions">
							{ /* The configured address is not where this grant was
							     approved, so it is not offered as the way to it. */ }
							{ moved || hub.pin_invalid ? null : (
								<Button type="secondary" size="sm" icon="arrow-out" iconTone="2" href={ hub.url } target="_blank" rel="noopener noreferrer">
									{ __( 'Open the Hub', 'bettershield' ) }
								</Button>
							) }
							{ readsOnly
								? fixes.map( ( fix ) => (
										<Button key={ fix.href } type="secondary" size="sm" href={ fix.href }>
											{ fix.label }
										</Button>
								  ) )
								: null }
							{ /* Armed: getting back needs a hub sign-in and two
							     approvals, so the first press says what stops. */ }
							<Armed
								type="ghost"
								label={ __( 'Disconnect', 'bettershield' ) }
								consequence={ __( 'The hub can no longer view or fix this site. Reconnecting needs a hub sign-in and your approval.', 'bettershield' ) }
								busy={ ending }
								onConfirm={ end }
							/>
						</div>
					</>
				) : (
					<>
						<p className="bs-ds-hub__lead">
							{ __(
								'Manage all your sites in one place, with downtime emails and one AI assistant.',
								'bettershield'
							) }
						</p>
						<p className="bs-ds-hub__meta">
							{ /* The one screen that says connecting allows AI access
							     leads to where it is changed (#2569). */ }
							{ createInterpolateElement(
								__( 'Connecting turns on “Let AI assistants see security info” and “Let AI assistants fix things”. Change them under <a>Agents</a>.', 'bettershield' ),
								{ a: tabUrl( 'bettershield-agents', 'permissions' ) ? <a href={ tabUrl( 'bettershield-agents', 'permissions' ) } /> : <span /> }
							) }
						</p>
						<div className="bs-ds-hub__actions">
							<Button
								type="primary"
								size="sm"
								onClick={ start }
								isBusy={ connecting }
								disabled={ connecting || ! hub.available || hub.pin_invalid || plain || lockedDown || staging }
							>
								{ sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ) }
							</Button>
						</div>
						{ ! hub.available ? <Alert layout="default" tone="info" desc={ __( 'Connecting needs WordPress 6.9 or later.', 'bettershield' ) } /> : null }
						{ /* Said before the press: the hub signs in through the
						     pretty addresses, and would refuse the site after
						     the switches were on. */ }
						{ hub.available && staging ? (
							<Alert
								layout="default"
								tone="info"
								desc={ __( 'This site is marked as a test (staging) copy, so it can’t connect. Change that on the Overview.', 'bettershield' ) }
								actions={
									<Button type="secondary" size="sm" href={ hub.overview_url }>
										{ __( 'Open the Overview', 'bettershield' ) }
									</Button>
								}
							/>
						) : null }
						{ hub.available && lockedDown ? (
							<Alert
								layout="default"
								tone="info"
								desc={ __( 'This site is locked down, which pauses connected apps. Connect once the lockdown ends.', 'bettershield' ) }
								actions={
									hub.recovery_url ? (
										<Button type="secondary" size="sm" href={ hub.recovery_url }>
											{ __( 'Open Recovery', 'bettershield' ) }
										</Button>
									) : null
								}
							/>
						) : null }
						{ hub.available && plain ? (
							<Alert
								layout="default"
								tone="warning"
								desc={ __(
									'Connecting needs readable page addresses. Under Settings › Permalinks, choose any option except Plain.',
									'bettershield'
								) }
							/>
						) : null }
					</>
				) }
			</div>

			{ connected && hub.link ? <LinkRow link={ hub.link } busy={ linking } onSet={ ( data ) => setHubLink( data, setHub ) } /> : null }

		</Card>
	);
}
