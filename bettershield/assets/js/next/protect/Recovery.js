/**
 * Protection › Recovery: whether the way back works today, in four facts; the
 * two ways back themselves; the evidence that they would work; and, last, the
 * one control here that closes something.
 *
 * The recovery link is the single most important control in the plugin: it
 * is what stops this becoming the security plugin that locked someone out. It
 * lives one tab away from the controls that can refuse a sign-in.
 *
 * The strip, then three cards: the way back in, with the link and the printed
 * codes as its rows; the readiness checks; and the lockdown. The longer
 * explanations open under what they explain.
 */

import './Recovery.css';

import { createPortal, useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import { copyToClipboard } from '../../ui/copy';
import { download } from '../../ui/download';
import { whenPhrase } from '../../ui/when';
import { linkState, noCodesWord, readinessCount } from '../data/recovery';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { focusIfLost, useFocusAfter } from '../ui/focus';
import Icon from '../ui/Icon';
import SettingRow, { SettingsCard } from '../ui/Setting';
import Skeleton, { CardBone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { Resource } from '../ui/States';
import Topics from '../ui/Topics';
import Codes from './Codes';
import Readiness from './Readiness';
import SafeMode from './SafeMode';

/** The four facts' names, shared by the strip and the tab's stand-in. */
function glanceLabels() {
	return {
		link: __( 'Recovery link', 'bettershield' ),
		codes: __( 'Recovery codes', 'bettershield' ),
		readiness: __( 'Recovery check', 'bettershield' ),
		lockdown: __( 'Lockdown', 'bettershield' ),
	};
}

function RecoverySummary( { data } ) {
	const labels = glanceLabels();
	const { resource } = useResource( 'lockdown' );
	const lockdown = resource && resource.data ? resource.data.lockdown : null;
	const link = linkState( data );
	const codes = Math.max( 0, Number( data.recovery_codes_left ) || 0 );
	const report = data.recovery_readiness;
	const { good, total } = readinessCount( report );

	const linkWord = {
		available: __( 'Ready', 'bettershield' ),
		missing: __( 'Missing', 'bettershield' ),
		expired: __( 'Expired', 'bettershield' ),
		refused: __( 'Not delivered', 'bettershield' ),
	};

	let checked = __( 'Not checked yet', 'bettershield' );

	if ( report && report.overdue ) {
		checked = __( 'The daily check is overdue', 'bettershield' );
	} else if ( report && report.checked_at ) {
		checked = sprintf(
			/* translators: %s: when, e.g. "today, 3:07 PM". */
			__( 'Checked %s', 'bettershield' ),
			whenPhrase( report.checked_at )
		);
	}

	const tiles = [
		{
			key: 'link',
			icon: 'link',
			label: labels.link,
			value: linkWord[ link ] || linkWord.available,
			detail: 'available' === link ? __( 'Good for one use', 'bettershield' ) : __( 'Generate a new one below', 'bettershield' ),
			tone: 'available' === link ? 'good' : 'caution',
		},
		{
			key: 'codes',
			icon: 'printer',
			label: labels.codes,
			value: String( codes ),
			detail: codes ? _n( 'Unused code', 'Unused codes', codes, 'bettershield' ) : noCodesWord( data.recovery_codes_issued ),
			tone: codes ? 'good' : 'caution',
		},
		{
			key: 'readiness',
			icon: 'list-checks',
			label: labels.readiness,
			value: sprintf(
				/* translators: 1: checks that passed, 2: how many checks there are. */
				__( '%1$d of %2$d', 'bettershield' ),
				good,
				total
			),
			detail: checked,
			tone: report && report.overdue ? 'caution' : null,
		},
		{
			key: 'lockdown',
			icon: 'lock',
			label: labels.lockdown,
			value: lockdown && lockdown.active ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ),
			detail:
				lockdown && lockdown.active
					? sprintf(
							/* translators: %s: date and time. */
							__( 'Since %s', 'bettershield' ),
							formatTime( new Date( lockdown.since * 1000 ).toISOString() )
					  )
					: __( 'No lockdown', 'bettershield' ),
			tone: lockdown && lockdown.active ? 'caution' : null,
			// A read of its own. "Off" before it has answered would be a
			// guess, and on the one switch here that closes the site.
			pending: ! resource.data && 'error' !== resource.status,
		},
	];

	return <Stats label={ __( 'Recovery at a glance', 'bettershield' ) } tiles={ tiles } />;
}

export function RecoveryLink( { exists, mailed, receipt = '' } ) {
	const { generateRecovery, confirmRecoveryReceived, busy } = useStore();
	const confirming = isWorking( busy, 'recovery-received' );
	const [ url, setUrl ] = useState( null );
	const [ copyState, setCopyState ] = useState( 'idle' );
	const generating = isWorking( busy, 'recovery' );
	const copyRef = useRef( null );

	// The button that made the link is replaced by it, so focus dropped to
	// the page body on a link shown once (#2056). Copying it takes focus, as
	// a new set of codes does below.
	useEffect( () => {
		if ( url ) {
			focusIfLost( copyRef.current );
		}
	}, [ url ] );

	const generate = () =>
		generateRecovery( ( result ) => {
			if ( result && result.url ) {
				setUrl( result.url );
				setCopyState( 'idle' );
			}
		} );

	// A copy button that quietly fails is worse than no copy button: the owner
	// walks away believing they have the one credential that gets them back in.
	// Both outcomes are therefore stated.
	const copy = () =>
		copyToClipboard( url ).then(
			() => setCopyState( 'copied' ),
			() => setCopyState( 'failed' )
		);

	// Whether the line saying where the link stands is one to act on.
	const needsAction = ! exists || false === mailed;

	/*
	 * Worded by what is on record about the link, not by how the plugin was
	 * set up: no link is emailed at activation. `mailed` is the result of the
	 * last send for this link: true accepted, false refused, null never
	 * attempted because the link was handed over when it was made.
	 */
	let standing = __( 'A link exists. It was shown once and not emailed. Generating a new one cancels it.', 'bettershield' );

	if ( ! exists ) {
		standing = __( 'No link exists yet.', 'bettershield' );
	} else if ( false === mailed ) {
		standing = __(
			'The link’s email could not be sent. Generate a new one and store it now. This cancels the old one.',
			'bettershield'
		);
	} else if ( true === mailed ) {
		standing = __( 'A link exists and was emailed to the administration address. Generating a new one cancels it.', 'bettershield' );
	}

	return (
		<SettingRow
			title={ __( 'Recovery link', 'bettershield' ) }
			about={ __(
				'If you’re locked out, open this link and press the button. BetterShield’s protections pause for one hour so you can sign in. No settings change.',
				'bettershield'
			) }
			control={
				! url ? (
					<Button type="primary" size="sm" isBusy={ generating } disabled={ generating } onClick={ generate }>
						{ exists ? __( 'Generate a New Link', 'bettershield' ) : __( 'Generate Recovery Link', 'bettershield' ) }
					</Button>
				) : null
			}
			topics={ [
				{
					key: 'how',
					label: __( 'How this works', 'bettershield' ),
					lead: __( 'Each link works once. Using it gives you a new one.', 'bettershield' ),
					steps: [
						__( 'This site doesn’t keep a readable copy, so the link is shown only once.', 'bettershield' ),
						__( 'Opening the link only shows a page. Pressing the button there uses it up.', 'bettershield' ),
						__( 'The next link is shown right away and emailed to the administration address.', 'bettershield' ),
					],
					note: {
						tone: 'safe',
						text: __( 'A used link found in an old inbox or server log is worth nothing.', 'bettershield' ),
					},
				},
				{
					key: 'pauses',
					label: __( 'What it pauses', 'bettershield' ),
					lead: __( 'Everything on Login & Access that can stop someone signing in.', 'bettershield' ),
					tags: [
						__( 'Lockouts', 'bettershield' ),
						__( 'The blocklist', 'bettershield' ),
						__( 'A moved sign-in address', 'bettershield' ),
						__( 'Session limits', 'bettershield' ),
					],
					body: <p>{ __( 'A sign-in lockout also ends on its own, and its email has an unlock link for just that lockout.', 'bettershield' ) }</p>,
					note: {
						tone: 'safe',
						text: __( 'While paused, no settings change, so nothing here can lock you out for good.', 'bettershield' ),
					},
				},
			] }
		>
			{ /* The two rules for keeping it, as two short facts rather than two
			     more sentences in the line above. */ }
			<ul className="bs-ds-wayback__facts">
				<li>
					<Icon name="check" size={ 12 } tone="2" />
					{ __( 'Store it off this site, in a password manager for example.', 'bettershield' ) }
				</li>
				<li>
					<Icon name="check" size={ 12 } tone="2" />
					{ __( 'A link is good for one use.', 'bettershield' ) }
				</li>
			</ul>

			{ /* Where the link stands, said as something to do when it asks for
			     something, so the one case that needs a new link now is not
			     read as the same quiet line as the case that does not. */ }
			{ ! url && needsAction ? (
				<div className="bs-ds-wayback__state is-attention">
					<Alert layout="default" tone="warning" desc={ standing } />
				</div>
			) : null }
			{ ! url && ! needsAction ? <p className="bs-ds-wayback__state">{ standing }</p> : null }

			{ /* The emailed link counts as a way back in only once the owner
			     says the email arrived; nothing else on any screen asked
			     (#2629). */ }
			{ ! url && 'pending' === receipt && false !== mailed ? (
				<div className="bs-ds-wayback__state">
					<Alert
						layout="default"
						tone="info"
						desc={ __( 'Did the recovery email arrive? Confirm it here, so the link counts as your way back in.', 'bettershield' ) }
						actions={
							<Button type="secondary" size="sm" isBusy={ confirming } disabled={ confirming } accessibleWhenDisabled={ confirming } onClick={ () => confirmRecoveryReceived() }>
								{ __( 'It Arrived', 'bettershield' ) }
							</Button>
						}
					/>
				</div>
			) : null }
			{ ! url && 'confirmed' === receipt ? <p className="bs-ds-wayback__state">{ __( 'You confirmed the recovery email arrived.', 'bettershield' ) }</p> : null }

			{ /* The link itself, once, in a panel of its own: the one moment on
			     this tab that cannot be repeated is set apart from the rest. */ }
			{ url ? (
				<div className="bs-ds-wayback__reveal">
					<p className="bs-ds-wayback__secret">{ url }</p>
					<div className="bs-ds-wayback__actions">
						{ /* The card's one primary action while the link is on
						     screen, in the place Generate stood. */ }
						<Button ref={ copyRef } type="primary" size="sm" icon="copy" iconTone="onbrand" onClick={ copy }>
							{ copyState === 'copied' ? __( 'Copied', 'bettershield' ) : __( 'Copy Link', 'bettershield' ) }
						</Button>
						<span className="bs-ds-wayback__said" role="status">
							{ copyState === 'failed'
								? __( 'Copying failed. Select the link above and copy it yourself. This is the only place it is shown.', 'bettershield' )
								: __( 'Shown once. Leaving this screen clears it from view.', 'bettershield' ) }
						</span>
					</div>
				</div>
			) : null }
		</SettingRow>
	);
}

/**
 * The host a code address names, for the printout's title. The page's own
 * host stands in when the address is missing or unreadable.
 *
 * @param {string} address
 * @return {string} e.g. "example.org".
 */
function hostOf( address ) {
	try {
		return new URL( address ).host;
	} catch ( error ) {
		return window.location.host;
	}
}

/**
 * The codes as they go to paper.
 *
 * A copy of its own, drawn as a direct child of the page and shown only in
 * print. Printing the card where it sits put two of eight codes on paper: it
 * lives inside a panel that clips what overflows it, below everything the tab
 * drew first. The copy also says what the codes are for and where to use one,
 * because the paper is kept somewhere this site is not.
 *
 * @param {Object}   props
 * @param {string[]} props.codes
 * @param {string}   props.address Where a code is used, the code added to the end.
 */
function PrintedCodes( { codes, address } ) {
	return createPortal(
		<div className="bs-ds-recovery-print">
			<h1 className="bs-ds-recovery-print__title">
				{ sprintf(
					/* translators: %s: the site's host name. */
					__( 'BetterShield recovery codes for %s', 'bettershield' ),
					hostOf( address )
				) }
			</h1>
			{ address ? (
				<p>
					{ sprintf(
						/* translators: %s: the address a code is added to. */
						__( 'If you are locked out, open %s followed by one of these codes. Each works once and pauses BetterShield’s protections for an hour. Keep this off this site.', 'bettershield' ),
						address
					) }
				</p>
			) : null }
			<ol className="bs-ds-recovery-print__codes">
				{ codes.map( ( code ) => (
					<li key={ code }>
						<code>{ code }</code>
					</li>
				) ) }
			</ol>
		</div>,
		document.body
	);
}

/**
 * The printed codes as a file, in the words Quick Setup's download uses.
 *
 * @param {string[]} codes   The codes.
 * @param {string}   address Where a code is added to.
 */
function keepSheet( codes, address ) {
	download(
		'bettershield-recovery-codes.txt',
		sprintf(
			/* translators: %s: the site's host name. */
			__( 'BetterShield recovery codes for %s', 'bettershield' ),
			window.location.hostname
		) +
			'\n' +
			sprintf(
				/* translators: %s: the address a code is added to. */
				__( 'If you are locked out, open %s followed by one of these codes. Each works once and pauses BetterShield’s protections for an hour. Keep this off this site.', 'bettershield' ),
				address
			) +
			'\n\n' +
			codes.join( '\n' ) +
			'\n'
	);
}

/**
 * The way back that does not depend on email arriving.
 *
 * The recovery link is the guaranteed way in, and it has one dependency the
 * promise it serves does not: it arrives by email and is replaced by email. An
 * owner whose mail is broken, whose address has changed, or whose inbox was
 * the thing that was breached has a link they cannot receive, on exactly the
 * day it was supposed to work.
 *
 * These are printed and kept off the site. Each opens safe mode once, at the
 * same address the link uses, and is then spent.
 */
export function RecoveryCodes( { remaining, issued = false } ) {
	const { issueRecoveryCodes, busy } = useStore();
	const [ codes, setCodes ] = useState( null );
	const [ address, setAddress ] = useState( '' );
	const [ copyState, setCopyState ] = useState( 'idle' );
	const working = isWorking( busy, 'recovery-codes' );
	const shownRef = useRef( null );

	// The button that issued them is drawn only until they arrive, so it left
	// with the press and focus dropped to the page body. The codes just shown
	// take it instead.
	useEffect( () => {
		if ( codes ) {
			focusIfLost( shownRef.current );
		}
	}, [ codes ] );

	const issue = () =>
		issueRecoveryCodes( ( result ) => {
			if ( result ) {
				setCodes( result.codes );
				setAddress( result.code_address || '' );
				setCopyState( 'idle' );
			}
		} );

	// Said either way, for the reason the link's copy button says it: a set
	// the owner believes they copied and did not is a way back they lack.
	const copyAll = () =>
		copyToClipboard( codes.join( '\n' ) ).then(
			() => setCopyState( 'copied' ),
			() => setCopyState( 'failed' )
		);

	return (
		<SettingRow
			title={ __( 'Recovery codes', 'bettershield' ) }
			about={ __(
				'Store them somewhere outside this site. Each code pauses sign-in protection once, like the recovery link.',
				'bettershield'
			) }
			control={
				// Replacing a set retires every code kept offline at once, so it
				// is asked first; the first set is not (#2064).
				! codes && remaining ? (
					<Armed
						label={ __( 'Issue a New Set', 'bettershield' ) }
						consequence={ sprintf(
							/* translators: %d: how many printed codes are still unused. */
							_n(
								'Replace your %d unused recovery code? The code you saved before stops working at once.',
								'Replace your %d unused recovery codes? The codes you saved before stop working at once.',
								remaining,
								'bettershield'
							),
							remaining
						) }
						confirm={ __( 'Replace Them', 'bettershield' ) }
						busy={ working }
						onConfirm={ issue }
					/>
				) : ! codes ? (
					<Button type="secondary" size="sm" isBusy={ working } disabled={ working } onClick={ issue }>
						{ __( 'Issue Recovery Codes', 'bettershield' ) }
					</Button>
				) : null
			}
		>
			{ codes ? <PrintedCodes codes={ codes } address={ address } /> : null }

			{ codes ? (
				<div className="bs-ds-wayback__reveal bs-ds-wayback__codes" ref={ shownRef } tabIndex={ -1 }>
					<p className="bs-ds-wayback__said">
						{ __(
							'This is the only time these are shown. Print this page now.',
							'bettershield'
						) }
					</p>
					<Codes codes={ codes } />
					<div className="bs-ds-wayback__actions">
						<Button type="secondary" size="sm" icon="printer" iconTone="2" onClick={ () => window.print() }>
							{ __( 'Print', 'bettershield' ) }
						</Button>
						<Button type="secondary" size="sm" icon="copy" iconTone="2" onClick={ copyAll }>
							{ copyState === 'copied' ? __( 'Copied', 'bettershield' ) : __( 'Copy All', 'bettershield' ) }
						</Button>
						{ /* For an owner without a printer, as Quick Setup and the
						     two-factor backup codes offer (#2066). */ }
						<Button type="secondary" size="sm" icon="download" iconTone="2" onClick={ () => keepSheet( codes, address ) }>
							{ __( 'Download Codes', 'bettershield' ) }
						</Button>
						<span className="bs-ds-wayback__said" role="status">
							{ copyState === 'failed' ? __( 'Copying failed. Select the codes above and copy them yourself.', 'bettershield' ) : '' }
						</span>
					</div>
				</div>
			) : null }

			{ ! codes && ! remaining ? (
				<div className="bs-ds-wayback__state is-attention">
					<Alert
						layout="default"
						tone="warning"
						desc={ issued ? __( 'The last set is all used. Issue a new set.', 'bettershield' ) : __( 'None issued yet.', 'bettershield' ) }
					/>
				</div>
			) : null }

			{ ! codes && remaining ? (
				<p className="bs-ds-wayback__state">
					{ sprintf(
						/* translators: %d: how many unused codes remain. */
						_n( '%d unused code. Issuing a new set replaces it.', '%d unused codes. Issuing a new set replaces them.', remaining, 'bettershield' ),
						remaining
					) }
				</p>
			) : null }
		</SettingRow>
	);
}

/**
 * The two ways back in, as the rows of one card, with how many printed codes
 * are left in its header.
 *
 * @param {Object} props
 * @param {Object} props.data The overview payload.
 */
function WayBackIn( { data } ) {
	const codes = Math.max( 0, Number( data.recovery_codes_left ) || 0 );
	const link = linkState( data );

	/*
	 * Both ways back, since the card holds both: the header spoke only of the
	 * codes, and an amber "None issued" read as no way back in above a link
	 * that was ready (#2065). Amber only when neither would get anyone in.
	 */
	const linkWords = {
		available: __( 'Link ready', 'bettershield' ),
		refused: __( 'Link not delivered', 'bettershield' ),
		expired: __( 'Link expired', 'bettershield' ),
		missing: __( 'No link', 'bettershield' ),
	};
	let codeWords = data.recovery_codes_issued ? __( 'all codes used', 'bettershield' ) : __( 'no recovery codes', 'bettershield' );

	if ( codes > 0 ) {
		codeWords = sprintf(
			/* translators: %d: unused printed recovery codes. */
			_n( '%d code left', '%d codes left', codes, 'bettershield' ),
			codes
		);
	}

	return (
		<SettingsCard
			icon="life-buoy"
			title={ __( 'Your recovery options', 'bettershield' ) }
			trailing={
				<Badge tone={ 'available' === link || codes > 0 ? 'neutral' : 'yellow' }>
					{ sprintf(
						/* translators: 1: where the recovery link stands, 2: how many printed codes are left. */
						__( '%1$s · %2$s', 'bettershield' ),
						linkWords[ link ] || linkWords.missing,
						codeWords
					) }
				</Badge>
			}
		>
			<RecoveryLink exists={ data.recovery_link_exists } mailed={ data.recovery_link_mailed } receipt={ data.recovery_receipt || '' } />
			<RecoveryCodes remaining={ data.recovery_codes_left } issued={ Boolean( data.recovery_codes_issued ) } />
		</SettingsCard>
	);
}

/**
 * The lockdown card standing in for itself, while its own read is out in a
 * tab that is otherwise drawn.
 *
 * @param {Object} props
 * @param {string} props.label What is on its way.
 */
function LockdownBone( { label } ) {
	return (
		<Skeleton label={ label }>
			<CardBone rows={ [ '45%' ] } />
		</Skeleton>
	);
}

/**
 * The tab before the posture it reads has landed: the four facts, then the
 * three cards (the two ways back in, the readiness checks, and the lockdown).
 */
export function RecoveryBone() {
	return (
		<Skeleton label={ __( 'Loading recovery…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />
			<CardBone rows={ [ '70%', '85%' ] } />
			<CardBone rows={ [ '40%', '45%', '55%', '40%' ] } />
			<CardBone rows={ [ '45%' ] } />
		</Skeleton>
	);
}

/**
 * The switch a person throws when the site is under attack.
 *
 * Last on this tab and deliberately so: everything above it is a way back in,
 * and this is the only control here that closes something. Somebody reaching
 * for it in an emergency should have passed their own way back in on the
 * way, because throwing this without a working recovery link is the one
 * sequence that could strand them.
 *
 * The copy states the cost rather than softening it. On a shop or a membership
 * site most accounts stop being able to sign in, and finding that out
 * afterwards, mid-incident, is worse than reading it here.
 */
function LockdownSwitch() {
	const { resource, reload } = useResource( 'lockdown' );
	const { setLockdown, busy } = useStore();
	const working = isWorking( busy, 'lockdown' );
	// Locking swaps the control for Lift the lockdown, and lifting swaps it
	// back: focus goes to the one now there.
	const control = useRef( null );

	useFocusAfter( working, control );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <LockdownBone label={ __( 'Loading the lockdown switch…', 'bettershield' ) } /> }>
			{ ( data ) => {
				const on = data.lockdown && data.lockdown.active;

				return (
					<Card className="bs-ds-lockdown" aria-labelledby="bs-ds-lockdown-title">
						<CardHead icon="lock" id="bs-ds-lockdown-title" title={ __( 'Emergency lockdown', 'bettershield' ) }>
							<Badge tone={ on ? 'yellow' : 'neutral' }>{ on ? __( 'Locked down', 'bettershield' ) : __( 'Off', 'bettershield' ) }</Badge>
						</CardHead>

						<div className="bs-ds-lockdown__body">
							{ on ? (
								<Alert
									layout="default"
									tone="warning"
									live
									desc={ sprintf(
										/* translators: %s: date and time. */
										__( 'This site has been locked down since %s. It stays locked down until you lift it.', 'bettershield' ),
										formatTime( new Date( data.lockdown.since * 1000 ).toISOString() )
									) }
									actions={
										<Armed
											ref={ control }
											label={ __( 'Lift the Lockdown', 'bettershield' ) }
											consequence={ __( 'Every account can sign in again, and everything the lockdown paused resumes.', 'bettershield' ) }
											busy={ working }
											onConfirm={ () => setLockdown( false ) }
										/>
									}
								/>
							) : (
								<>
									{ /* The card's one action first, so "The button above" under
									     Getting back out is true. Its confirmation still says the
									     cost before anything happens (#2311). */ }
									<div className="bs-ds-lockdown__arm">
										<Armed
											ref={ control }
											label={ __( 'Lock the Site Down', 'bettershield' ) }
											consequence={
												data.lockdown && data.lockdown.site_accounts_only
													? __(
															'Signs out this site’s own accounts and stops plugin and theme changes until you lift it. Network administrators and people on other sites stay signed in. Visitors see no change.',
															'bettershield'
													  )
													: __(
															'Signs everyone else out of the dashboard and stops installing or updating plugins and themes from it until you lift it. Visitors see no change.',
															'bettershield'
													  )
											}
											confirm={ __( 'Yes: Lock This Site Down', 'bettershield' ) }
											busy={ working }
											onConfirm={ () => setLockdown( true ) }
										/>
									</div>
									<Topics
										items={ [
											{
												/*
												 * What it does, line by line. Joined by commas in
												 * one sentence, the one a reader most needs before
												 * pressing (that it signs out their own other
												 * devices too) was the second clause of a sentence
												 * nobody finished.
												 */
												key: 'does',
												label: __( 'What it does', 'bettershield' ),
												lead: __( 'While it is on, it:', 'bettershield' ),
												points: [
													__( 'Signs out every other dashboard session, including yours on other devices.', 'bettershield' ),
													__( 'Refuses sign-ins from every account that cannot manage this site.', 'bettershield' ),
													__( 'Turns off remote publishing (XML-RPC) and passwords used by apps.', 'bettershield' ),
													__( 'Disconnects AI assistants, connected apps and BetterShield Hub until you lift it.', 'bettershield' ),
													__( 'Stops new registrations.', 'bettershield' ),
													__( 'Stops installing or updating from the dashboard. Automatic updates still run.', 'bettershield' ),
													__( 'Still lets you deactivate or delete plugins, and switch or delete themes.', 'bettershield' ),
												],
											},
											{
												key: 'visitors',
												label: __( 'What visitors see', 'bettershield' ),
												lead: __( 'The site, exactly as before.', 'bettershield' ),
												points: [
													__( 'Nothing here touches the front end.', 'bettershield' ),
													__( 'WooCommerce checkout and carts keep working for guests and customers already signed in.', 'bettershield' ),
												],
											},
											{
												key: 'cost',
												label: __( 'Who can’t sign in', 'bettershield' ),
												lead: __( 'Everyone except administrators.', 'bettershield' ),
												points: [ __( 'Their sign-in attempts don’t count toward lockouts, so they can sign in normally once you lift it.', 'bettershield' ) ],
												note: { tone: 'caution', text: __( 'On a shop or membership site, that is most accounts.', 'bettershield' ) },
											},
											{
												key: 'back',
												label: __( 'How to end the lockdown', 'bettershield' ),
												lead: __( 'Either of two ways.', 'bettershield' ),
												points: [
													__( 'The button above.', 'bettershield' ),
													__( 'Or use your recovery link: it pauses the lockdown for an hour. Lift it here during that hour, or it starts again.', 'bettershield' ),
												],
											},
										] }
									/>
								</>
							) }
						</div>
					</Card>
				);
			} }
		</Resource>
	);
}

export default function Recovery() {
	const { resource, reload } = useResource( 'overview' );

	return (
		<>
			<SafeMode />
			<Resource resource={ resource } onRetry={ reload } loading={ <RecoveryBone /> }>
				{ ( data ) => (
					<>
						<RecoverySummary data={ data } />
						<WayBackIn data={ data } />
						{ data.recovery_readiness ? <Readiness report={ data.recovery_readiness } /> : null }
						{ /* Last: everything above is a way back in, and somebody
						     reaching for this in an emergency should have passed
						     their own way back in on the way to it. */ }
						<LockdownSwitch />
					</>
				) }
			</Resource>
		</>
	);
}
