/**
 * BetterShield Hub: connecting this site to the hub, which is optional.
 *
 * Not connected: one card that says what the hub is for, the button that
 * starts it, and how connecting goes, step by step, on request. Connected:
 * a strip of four facts, the instant-alerts card, and the Connection card in
 * the rail, with what the hub can do right now (the site's own switches decide
 * that, not the grant), when it last read the site, and Disconnect. The hub's
 * address is not a setting: it is hub.bettershield.ai unless wp-config.php
 * pins another.
 *
 * Connecting is an ordinary grant through this site's own consent page, so it
 * is listed with the other applications and ends the same way. Nothing in the
 * plugin waits on the hub.
 */

import './Hub.css';

import apiFetch from '@wordpress/api-fetch';
import { createInterpolateElement, useEffect, useId, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { formatTime, isWorking, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead, IconTile, Tray } from '../ui/Card';
import Icon from '../ui/Icon';
import InfoTip from '../ui/InfoTip';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import { openInNewTab, useOnReturn } from '../ui/newTab';
import { Toggle } from '../ui/SettingRow';
import Skeleton, { CardBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { ErrorState } from '../ui/States';
import brand from '../setup/brand';

const HUB = '/bettershield/v1/hub';

const assets = () => ( window.bettershield && window.bettershield.assetsUrl ) || '';

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
 * The drawing beside the pitch: three sites stacked, the middle one named.
 * It says nothing a reader needs, so it is hidden from them.
 */
function Faint() {
	return (
		<span className="bs-ds-hub-stack__row bs-ds-hub-stack__row--faint">
			<IconTile icon="globe" />
			<span className="bs-ds-hub-stack__text">
				<span className="bs-ds-hub-stack__line bs-ds-hub-stack__line--long" />
				<span className="bs-ds-hub-stack__line bs-ds-hub-stack__line--thin" />
			</span>
			<span className="bs-ds-hub-stack__line bs-ds-hub-stack__line--end" />
		</span>
	);
}

function Stack( { host } ) {
	return (
		<div className="bs-ds-hub-stack" aria-hidden="true">
			<img className="bs-ds-hub-stack__glow" src={ `${ assets() }next/hub-glow.svg` } alt="" />
			<Faint />
			<span className="bs-ds-hub-stack__row bs-ds-hub-stack__row--front">
				<IconTile icon="globe" />
				<span className="bs-ds-hub-stack__text">
					<span className="bs-ds-t14 bs-ds-m bs-ds-c1 bs-ds-nowrap">{ host }</span>
					<span className="bs-ds-hub-stack__line bs-ds-hub-stack__line--wide" />
				</span>
				<Badge>{ __( 'Grade A', 'bettershield' ) }</Badge>
			</span>
			<Faint />
		</div>
	);
}

/** How connecting goes, in three steps, opened from the pitch. */
function Steps( { host, id } ) {
	const steps = [
		[
			'log-in',
			sprintf(
				/* translators: %s: the hub's host name. */
				__( '1. Sign in to %s in the new tab', 'bettershield' ),
				host
			),
		],
		[ 'circle-check', __( '2. Approve this site on its consent page', 'bettershield' ) ],
		[ 'refresh-cw', __( '3. Come back here. The connection shows on its own.', 'bettershield' ) ],
	];

	return (
		<Tray icon="info" wrap note={ __( 'You can disconnect any time from this page.', 'bettershield' ) }>
			<Card aria-labelledby={ `${ id }-title` } id={ id }>
				<CardHead icon="list-checks" title={ __( 'How connecting works', 'bettershield' ) } id={ `${ id }-title` } line />
				<ol className="bs-ds-hub-steps">
					{ steps.map( ( [ icon, text ] ) => (
						<li key={ icon } className="bs-ds-hub-steps__step">
							<span className="bs-ds-hub-steps__marker" aria-hidden="true">
								<span className="bs-ds-hub-steps__circle">
									<Icon name={ icon } size={ 16 } tone="1" />
								</span>
								<span className="bs-ds-hub-steps__connector" />
							</span>
							<span className="bs-ds-hub-steps__text bs-ds-t14 bs-ds-m bs-ds-c1">{ text }</span>
						</li>
					) ) }
				</ol>
			</Card>
		</Tray>
	);
}

/** One row of what is sent: its words, a line about it, and what decides it. */
function SentRow( { id, label, about = null, children } ) {
	return (
		<div className="bs-ds-hub-sent__row">
			<span className="bs-ds-hub-sent__text">
				<span className="bs-ds-t14 bs-ds-r bs-ds-c1" id={ id }>
					{ label }
				</span>
				{ about ? <span className="bs-ds-hub-sent__about">{ about }</span> : null }
			</span>
			{ children }
		</div>
	);
}

/**
 * The Hub link: whether this site sends its security events to the hub as they
 * happen. Off until the owner turns it on; turning it off deletes the key it
 * signs with, and turning it on again makes a new one.
 */
function LinkCard( { link, busy, onSet } ) {
	const made = useId().replace( /[^\w-]/g, '' );
	const titleId = `bs-ds-hub-link-${ made }`;
	const aboutId = `${ titleId }-about`;
	const blocked = ! link.on && !! link.refusal;
	const standing = link.on && link.standing ? linkStanding( link ) : '';
	const title = __( 'Send alerts to the hub instantly', 'bettershield' );
	let note = null;

	if ( blocked ) {
		note = linkRefusal( link );
	} else if ( link.on && ! standing ) {
		note = linkProgress( link );
	} else if ( ! link.on ) {
		note = __( 'Off. The hub sees changes when it next checks this site.', 'bettershield' );
	}

	return (
		<Tray icon="clock" wrap note={ note }>
			<Card className="bs-ds-hub__link" aria-labelledby={ titleId }>
				<div className="bs-ds-card__head bs-ds-card__head--line">
					<IconTile icon="bell" />
					<h2 className="bs-ds-card__title bs-ds-hub__link-title bs-ds-t14 bs-ds-m bs-ds-c1" id={ titleId }>
						{ title }
					</h2>
					<InfoTip
						label={ sprintf(
							/* translators: %s: a setting's name. */
							__( 'About %s', 'bettershield' ),
							title
						) }
					>
						{ __( 'Without this, the hub only sees changes when it next checks your site. Sends are secured with a key that is deleted when you turn this off.', 'bettershield' ) }
					</InfoTip>
					<span className="bs-ds-spacer" />
					<Toggle
						checked={ link.on }
						disabled={ busy || blocked }
						labelledBy={ titleId }
						describedBy={ aboutId }
						onChange={ ( event ) => onSet( { on: Boolean( event && event.target ? event.target.checked : event ) } ) }
					/>
				</div>
				<div className="bs-ds-hub__body">
					<p className="bs-ds-hub__lead bs-ds-hub__lead--quiet" id={ aboutId }>
						{ __( 'Sends security events to hub.bettershield.ai as they happen, plus a regular “still online” signal.', 'bettershield' ) }
					</p>
					{ standing ? <Alert layout="default" tone="info" desc={ standing } /> : null }
					{ link.on ? (
						<div className="bs-ds-hub-sent">
							<span className="bs-ds-t12 bs-ds-m bs-ds-c2">{ __( 'What’s sent', 'bettershield' ) }</span>
							<div className="bs-ds-hub-sent__list">
								<SentRow
									id={ `${ titleId }-always` }
									label={ __( 'High and critical events', 'bettershield' ) }
									about={ __( 'Vulnerabilities, protections turned on or off, plugin, theme and role changes, and what other AI assistants did.', 'bettershield' ) }
								>
									<Badge>{ __( 'Always', 'bettershield' ) }</Badge>
								</SentRow>
								<SentRow id={ `${ titleId }-posture` } label={ __( 'Medium events and completed checks', 'bettershield' ) }>
									<Toggle
										checked={ link.posture }
										disabled={ busy }
										labelledBy={ `${ titleId }-posture` }
										onChange={ () => onSet( { on: true, posture: ! link.posture, full_log: link.full_log } ) }
									/>
								</SentRow>
								<SentRow id={ `${ titleId }-full` } label={ __( 'All other activity', 'bettershield' ) } about={ __( 'Sign-ins, edits and more.', 'bettershield' ) }>
									<Toggle
										checked={ link.full_log }
										disabled={ busy }
										labelledBy={ `${ titleId }-full` }
										onChange={ () => onSet( { on: true, posture: link.posture, full_log: ! link.full_log } ) }
									/>
								</SentRow>
							</div>
						</div>
					) : null }
					<p className="bs-ds-hub-privacy">
						<Icon name="info" size={ 16 } tone="2" />
						<span>
							{ __( 'Usernames are scrambled and IP addresses shortened. File contents, passwords, keys and personal details are never sent.', 'bettershield' ) }
						</span>
					</p>
				</div>
			</Card>
		</Tray>
	);
}

export default function Hub() {
	const { connectHub, disconnectHub, setHubLink, busy } = useStore();
	const [ hub, setHub ] = useState( null );
	const [ failed, setFailed ] = useState( false );
	// Bumped by Try again, so the read below runs once more.
	const [ attempt, setAttempt ] = useState( 0 );
	// "How it works" opens the steps under the pitch.
	const [ explained, setExplained ] = useState( false );
	const stepsId = `bs-ds-hub-steps-${ useId().replace( /[^\w-]/g, '' ) }`;

	/*
	 * Disconnect draws the screen again without the connection, so the
	 * keyboard goes to the screen's heading once the hub has gone.
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
	 * Connect opens the hub in a new tab (#2621), so the screen reads the hub
	 * again when the owner comes back to this one. A read that fails then
	 * keeps the screen as it was rather than putting the error in its place.
	 */
	const [ opened, setOpened ] = useState( false );
	const joined = !! hub && hub.connected;

	useOnReturn( opened && ! joined, () => apiFetch( { path: HUB } ).then( setHub, () => null ) );

	// The screen changes under the owner, so the keyboard goes to its heading.
	useEffect( () => {
		if ( opened && joined ) {
			heading.current?.focus( { preventScroll: true } );
		}
	}, [ opened, joined ] );

	const name = sprintf( /* translators: %s: the plugin's name, or the label the site owner gave it. */ __( '%s Hub', 'bettershield' ), brand() );

	/*
	 * A read that failed says so. Drawing nothing took the only Disconnect off
	 * the screen while a hub may well still hold access.
	 */
	if ( failed ) {
		return (
			<ErrorState title={ name } onRetry={ () => setAttempt( ( n ) => n + 1 ) }>
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
	 * meets, and the screen says that rather than what the grant was approved
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
	const permissionsUrl = tabUrl( 'bettershield-agents', 'permissions' );

	const end = () =>
		disconnectHub(
			afterEnd( ( result ) => {
				setHub( result );
				setEnded( __( 'Disconnected from the hub.', 'bettershield' ) );
			} )
		);

	const connected = hub.connected && app;
	const fixesOn = !! app && 'read write' === app.scope && ! readsOnly;
	let standing = '';

	if ( connected && ! refused ) {
		if ( readsOnly ) {
			standing = __( 'The hub can view this site but not fix anything, because fixes are turned off under Agents.', 'bettershield' );
		} else {
			standing = fixesOn
				? __( 'The hub can view this site and make fixes that can be undone.', 'bettershield' )
				: __( 'The hub can view this site but not change anything.', 'bettershield' );
		}
	}

	// The AI permissions connecting turned on, as the site holds them now.
	const seeing = ! refusals.includes( 'reading' ) && ! refusals.includes( 'connection' );
	const permissionsOn = ( seeing ? 1 : 0 ) + ( seeing && false !== hub.writes ? 1 : 0 );

	/* Said above everything else: the pinned address, and a disconnect just made. */
	const notices = (
		<>
			{ /* Pinned to an address the site cannot use: the screen says so
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
			{ /* Said, because the screen that follows reads the same as one
			     that was never connected. */ }
			{ ended && ! hub.connected ? (
				<div role="status">
					<Alert layout="default" tone="success" desc={ ended } />
				</div>
			) : null }
		</>
	);

	if ( ! connected ) {
		return (
			<div className="bs-ds-hub">
				<h2 ref={ heading } tabIndex={ -1 } className="bs-ds-hub__title screen-reader-text">
					{ name }
				</h2>
				{ notices }
				<Tray
					icon="info"
					wrap
					note={ sprintf(
						/* translators: %s: the hub's host name. */
						__( 'Connecting opens %s in a new tab. You approve it there, then come back here.', 'bettershield' ),
						hub.host
					) }
				>
					<Card className="bs-ds-hub-hero" aria-labelledby="bs-ds-hub-pitch">
						<div className="bs-ds-hub-hero__pitch">
							<span className="bs-ds-hub-hero__tile" aria-hidden="true">
								<Icon name="globe" size={ 16 } tone="1" />
							</span>
							<div className="bs-ds-hub-hero__text">
								<h3 className="bs-ds-hub-hero__heading" id="bs-ds-hub-pitch">
									{ __( 'All your sites in one place', 'bettershield' ) }
								</h3>
								<p className="bs-ds-hub__lead bs-ds-hub__lead--quiet">
									{ __( 'Downtime emails and one AI assistant for every site you run.', 'bettershield' ) }
								</p>
								<p className="bs-ds-hub__meta">
									{ /* The one screen that says connecting allows AI access
									     leads to where it is changed (#2569). */ }
									{ createInterpolateElement(
										__( 'Connecting turns on “Let AI assistants see security info” and “Let AI assistants fix things.” Change them under <a>Agents</a>.', 'bettershield' ),
										{ a: permissionsUrl ? <a href={ permissionsUrl } /> : <span /> }
									) }
								</p>
							</div>
							<div className="bs-ds-hub__actions">
								<Button
									type="primary"
									size="md"
									icon="arrow-out"
									onClick={ start }
									isBusy={ connecting }
									disabled={ connecting || ! hub.available || hub.pin_invalid || plain || lockedDown || staging }
								>
									{ sprintf( /* translators: %s: the plugin's name. */ __( 'Connect to %s Hub', 'bettershield' ), brand() ) }
								</Button>
								<Button type="ghost" size="md" aria-expanded={ explained } aria-controls={ stepsId } onClick={ () => setExplained( ( open ) => ! open ) }>
									{ __( 'How it works', 'bettershield' ) }
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
						</div>
						<Stack host={ hub.host } />
					</Card>
				</Tray>
				{ explained ? <Steps host={ hub.host } id={ stepsId } /> : null }
			</div>
		);
	}

	const link = hub.link || null;
	let access = __( 'View + fix', 'bettershield' );
	let accessDetail = __( 'Fixes that can be undone', 'bettershield' );
	let accessLong = __( 'View and undoable fixes', 'bettershield' );

	if ( refused ) {
		access = __( 'Paused', 'bettershield' );
		accessDetail = __( 'Blocked by this site’s settings', 'bettershield' );
		accessLong = __( 'Paused by this site’s settings', 'bettershield' );
	} else if ( ! fixesOn ) {
		access = __( 'View only', 'bettershield' );
		accessDetail = __( 'No changes', 'bettershield' );
		accessLong = __( 'View only', 'bettershield' );
	}

	let alertsDetail = __( 'Off until you turn it on', 'bettershield' );

	if ( link && link.on ) {
		alertsDetail = link.last_sent_at
			? sprintf(
					/* translators: %s: when events were last sent, e.g. "today, 5:14 PM". */
					__( 'Last sent %s', 'bettershield' ),
					whenPhrase( link.last_sent_at )
			  )
			: __( 'Nothing sent yet', 'bettershield' );
	}

	const tiles = [
		{
			key: 'status',
			icon: 'globe',
			label: __( 'Status', 'bettershield' ),
			value: refused ? __( 'Paused', 'bettershield' ) : __( 'Connected', 'bettershield' ),
			tone: refused ? 'warning' : 'success',
			detail: sprintf(
				/* translators: %s: when the connection was approved. */
				__( 'Since %s', 'bettershield' ),
				app.granted_at ? formatTime( app.granted_at ) : __( 'recently', 'bettershield' )
			),
		},
		{
			key: 'checked',
			icon: 'clock',
			label: __( 'Last checked', 'bettershield' ),
			value: lastRead ? whenPhrase( lastRead ) : __( 'Not yet', 'bettershield' ),
			text: true,
			tone: quietForADay ? 'warning' : '',
			detail: quietForADay ? __( 'Over a day ago', 'bettershield' ) : __( 'By the hub', 'bettershield' ),
		},
		{ key: 'access', icon: 'shield-check', label: __( 'Access', 'bettershield' ), value: access, detail: accessDetail },
		{
			key: 'alerts',
			icon: 'bell',
			label: __( 'Instant alerts', 'bettershield' ),
			value: link && link.on ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ),
			tone: link && link.on ? 'success' : '',
			detail: alertsDetail,
		},
	];

	return (
		<div className="bs-ds-hub">
			<h2 ref={ heading } tabIndex={ -1 } className="bs-ds-hub__title screen-reader-text">
				{ name }
			</h2>
			{ notices }
			<Stats label={ name } tiles={ tiles } />
			<div className="bs-ds-hub-grid">
				<div className="bs-ds-hub-grid__col">
					{ link ? <LinkCard link={ link } busy={ linking } onSet={ ( data ) => setHubLink( data, setHub ) } /> : null }
				</div>
				<div className="bs-ds-hub-grid__col">
					<Tray
						icon="info"
						wrap
						note={
							permissionsOn
								? sprintf(
										/* translators: %d: how many AI permissions are on. */
										_n( '%d AI permission on.', '%d AI permissions on.', permissionsOn, 'bettershield' ),
										permissionsOn
								  )
								: __( 'AI permissions are off.', 'bettershield' )
						}
						action={
							permissionsUrl ? (
								<Button type="linksub" size="sm" className="bs-ds-t12" href={ permissionsUrl }>
									{ __( 'Agents', 'bettershield' ) }
									<Icon name="arrow-right" size={ 14 } tone="1" />
								</Button>
							) : null
						}
					>
						<Card className="bs-ds-hub-connection" aria-labelledby="bs-ds-hub-connection-title">
							<CardHead icon="globe" title={ __( 'Connection', 'bettershield' ) } id="bs-ds-hub-connection-title" line>
								<Badge tone={ refused ? 'yellow' : 'brand' }>{ refused ? __( 'Paused', 'bettershield' ) : __( 'Connected', 'bettershield' ) }</Badge>
							</CardHead>
							<div className="bs-ds-hub__body">
								{ refused && refusal ? (
									<Alert
										layout="default"
										tone="warning"
										desc={ refusal }
										actions={
											fixes.length
												? fixes.map( ( fix ) => (
														<Button key={ fix.label } type="secondary" size="sm" href={ fix.href }>
															{ fix.label }
														</Button>
												  ) )
												: null
										}
									/>
								) : (
									<p className="bs-ds-hub__lead">{ standing }</p>
								) }
								<KeyValues className="bs-ds-hub__facts">
									{ /* "Hub", not "Hub address": the address is a fact
									     here, never a setting to change. */ }
									<KeyValue label={ __( 'Hub', 'bettershield' ) } value={ connectedHost } />
									<KeyValue
										label={ __( 'Connected since', 'bettershield' ) }
										value={ app.granted_at ? formatTime( app.granted_at ) : __( 'recently', 'bettershield' ) }
									/>
									{ /* Whether the hub is still checking in, which the
									     connection date alone could not say. */ }
									<KeyValue
										label={ __( 'Last checked', 'bettershield' ) }
										value={ lastRead ? whenPhrase( lastRead ) : __( 'Not yet', 'bettershield' ) }
										status={ quietForADay ? 'warning' : '' }
										note={
											( ! lastRead && __( 'The hub hasn’t checked this site yet.', 'bettershield' ) ) ||
											( quietForADay && __( 'The hub hasn’t checked this site for over a day.', 'bettershield' ) ) ||
											null
										}
									/>
									<KeyValue label={ __( 'Access', 'bettershield' ) } value={ accessLong } />
								</KeyValues>
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
								{ /* The configured address is not where this grant was
								     approved, so it is not offered as the way to it. */ }
								{ ( ! moved && ! hub.pin_invalid ) || readsOnly ? (
									<div className="bs-ds-hub__actions">
										{ moved || hub.pin_invalid ? null : (
											<Button type="secondary" size="sm" icon="arrow-out" iconTone="2" href={ hub.url } target="_blank" rel="noopener noreferrer">
												{ __( 'Open the Hub', 'bettershield' ) }
											</Button>
										) }
										{ readsOnly
											? fixes.map( ( fix ) => (
													<Button key={ fix.label } type="secondary" size="sm" href={ fix.href }>
														{ fix.label }
													</Button>
											  ) )
											: null }
									</div>
								) : null }
							</div>
							<div className="bs-ds-hub__end">
								<span className="bs-ds-hub__end-note">{ __( 'Hub access ends until you reconnect.', 'bettershield' ) }</span>
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
						</Card>
					</Tray>
				</div>
			</div>
		</div>
	);
}
