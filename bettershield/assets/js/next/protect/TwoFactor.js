/**
 * Protection › Two-factor: this account's ways of proving it is you, then what
 * the site asks of every account.
 *
 * Self-service enrollment runs in the order that makes lockout impossible:
 * prove the device, hold the backup codes, only then arm. The screen mirrors
 * the server's lifecycle exactly. Abandoning at any step changes nothing about
 * signing in, and the screen says so at each step rather than hoping nobody
 * wonders.
 *
 * The strip, then the two methods side by side as two cards of one kind (one
 * column on a narrow screen; setting two-factor up, or holding fresh codes,
 * takes the full width), then one card with a row per requirement. The longer
 * explanations open under what they explain.
 */

import './TwoFactor.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useResource, useStore } from '../../store';
import { download } from '../../ui/download';
import QrCode from '../../ui/QrCode';
import { offer } from '../../ui/TierOffer';
import { graceDaysProblem } from '../../ui/validate';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import { focusIfLost } from '../ui/focus';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import CopyField, { CopyButton } from '../ui/CopyField';
import Field, { FieldRow } from '../ui/Field';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { Bone, CardBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { Resource } from '../ui/States';
import Topics from '../ui/Topics';
import Codes from './Codes';
import Passkeys from './Passkeys';
import SafeMode from './SafeMode';

/**
 * The backup codes as a file the person can keep, built from the codes
 * already on screen.
 *
 * @param {string[]} codes The ten codes.
 */
function keepCodes( codes ) {
	download(
		'backup-codes.txt',
		sprintf(
			/* translators: %s: the site's host name. */
			__( 'Two-factor backup codes for %s', 'bettershield' ),
			window.location.hostname
		) +
			'\n' +
			__( 'Use each code once, in place of the code from your authenticator app.', 'bettershield' ) +
			'\n\n' +
			codes.join( '\n' ) +
			'\n'
	);
}

/**
 * Ways to keep a set of codes that is on screen once: copied, or saved as a
 * file.
 *
 * @param {Object}   props
 * @param {string[]} props.codes The codes.
 */
function KeepCodes( { codes } ) {
	return (
		<div className="bs-ds-2fa__actions">
			<CopyButton text={ codes.join( '\n' ) } label={ __( 'Copy Codes', 'bettershield' ) } />
			<Button type="secondary" size="sm" icon="download" iconTone="2" onClick={ () => keepCodes( codes ) }>
				{ __( 'Download Codes', 'bettershield' ) }
			</Button>
		</div>
	);
}

function Enrollment( { onDone } ) {
	const { startTwoFactor, confirmTwoFactor, acknowledgeTwoFactor, discardTwoFactor, busy } = useStore();
	const [ step, setStep ] = useState( 'intro' );
	const [ enrollment, setEnrollment ] = useState( null );
	const [ code, setCode ] = useState( '' );
	const [ codes, setCodes ] = useState( null );
	const working = isWorking( busy, 'two-factor' );

	/*
	 * Each step replaces the one before, and the button pressed goes with it:
	 * focus dropped to the page body, and a keyboard user started again from
	 * the top. The step that replaced it takes focus, never on first paint.
	 */
	const bodyRef = useRef( null );
	const firstStep = useRef( step );

	useEffect( () => {
		if ( step !== firstStep.current ) {
			firstStep.current = null;
			focusIfLost( bodyRef.current );
		}
	}, [ step ] );

	if ( 'intro' === step ) {
		return (
			<div className="bs-ds-2fa__body" key="intro" ref={ bodyRef } tabIndex={ -1 }>
				<p className="bs-ds-2fa__lead">
					{ __(
						'Asks for a 6-digit code from your phone after your password. Nothing changes until you finish setup.',
						'bettershield'
					) }
				</p>
				<div className="bs-ds-2fa__actions">
					<Button
						type="primary"
						size="sm"
						isBusy={ working }
						disabled={ working }
						onClick={ () =>
							startTwoFactor().then( ( result ) => {
								if ( result ) {
									setEnrollment( result );
									setStep( 'scan' );
								}
							} )
						}
					>
						{ __( 'Set Up Two-Factor', 'bettershield' ) }
					</Button>
				</div>
			</div>
		);
	}

	if ( 'scan' === step ) {
		return (
			<div className="bs-ds-2fa__body" key="scan" ref={ bodyRef } tabIndex={ -1 }>
				{ /* Three numbered steps: open the app, scan or type, enter the
				     code. The numbers are the guidance, so the copy inside each
				     step can stay short. */ }
				<ol className="bs-ds-2fa__steps">
					<li>
						<p className="bs-ds-2fa__step">{ __( 'Open an authenticator app on your phone', 'bettershield' ) }</p>
						<p className="bs-ds-2fa__note">
							{ __( 'Any app that makes six-digit codes works, like Google Authenticator.', 'bettershield' ) }
						</p>
					</li>
					<li>
						<p className="bs-ds-2fa__step">{ __( 'Scan this code with the app, or type the key in', 'bettershield' ) }</p>
						<div className="bs-ds-2fa__enroll">
							{ /* Its own light border, two modules wide: on the dark
							     scheme's card a scanner finds the corners by it. */ }
							<QrCode uri={ enrollment.uri } className="bs-ds-2fa__qr" margin={ 8 } />
							<div className="bs-ds-2fa__manual">
								{ /* A block, which wraps, rather than a one-line field
								     narrower than the key: whoever cannot scan the code
								     types this, and the field cut its tail off. */ }
								<CopyField label={ __( 'Manual entry key', 'bettershield' ) } value={ enrollment.secret } copyLabel={ __( 'Copy Key', 'bettershield' ) } multiline />
							</div>
						</div>
					</li>
					<li>
						<p className="bs-ds-2fa__step">{ __( 'Enter the six-digit code the app now shows', 'bettershield' ) }</p>
						<p className="bs-ds-2fa__note">{ __( 'This checks the app works before anything changes.', 'bettershield' ) }</p>
						<FieldRow>
							<Field
								width="sm"
								label={ __( 'Code from the app', 'bettershield' ) }
								hideLabelFromVision
								value={ code }
								onChange={ setCode }
								placeholder="123456"
								inputMode="numeric"
								autoComplete="one-time-code"
							/>
							<span className="bs-ds-2fa__actions">
								<Button
									type="primary"
									size="sm"
									isBusy={ working }
									disabled={ working || code.replace( /\D/g, '' ).length !== 6 }
									onClick={ () =>
										confirmTwoFactor( code ).then( ( result ) => {
											if ( result ) {
												setCodes( result.backup_codes );
												setCode( '' );
												setStep( 'codes' );
											}
										} )
									}
								>
									{ __( 'Confirm Code', 'bettershield' ) }
								</Button>
								<Button
									type="ghost"
									size="sm"
									disabled={ working }
									onClick={ () => {
										// Back to the beginning, and the half-made
										// secret goes with it. The screen does not
										// wait on that request: starting again
										// replaces the pending secret anyway, so a
										// discard that fails must not strand anyone
										// here.
										setStep( 'intro' );
										setEnrollment( null );
										setCode( '' );
										discardTwoFactor();
									} }
								>
									{ __( 'Cancel', 'bettershield' ) }
								</Button>
							</span>
						</FieldRow>
					</li>
				</ol>
				<p className="bs-ds-2fa__note">{ __( 'Two-factor is not on yet. If you leave this page now, nothing changes.', 'bettershield' ) }</p>
			</div>
		);
	}

	// codes
	return (
		<div className="bs-ds-2fa__body" key="codes" ref={ bodyRef } tabIndex={ -1 }>
			<p className="bs-ds-2fa__lead">
				{ __(
					'Use these backup codes to sign in without your phone. Each works once and is shown only now. Store them with your passwords.',
					'bettershield'
				) }
			</p>

			<Codes codes={ codes } />
			<KeepCodes codes={ codes } />

			<div className="bs-ds-2fa__actions">
				<Button
					className="bs-ds-2fa__arm"
					type="primary"
					size="sm"
					isBusy={ working }
					disabled={ working }
					onClick={ () =>
						acknowledgeTwoFactor().then( ( result ) => {
							if ( result ) {
								onDone();
							}
						} )
					}
				>
					{ __( 'Turn On Two-Factor', 'bettershield' ) }
				</Button>
			</div>
			<p className="bs-ds-2fa__note">
				{ __( 'Two-factor turns on only when you press that button.', 'bettershield' ) }
			</p>
		</div>
	);
}

function Enabled( { status, onDone } ) {
	const { disableTwoFactor, reissueBackupCodes, busy } = useStore();
	const [ code, setCode ] = useState( '' );
	const [ password, setPassword ] = useState( '' );
	const [ fresh, setFresh ] = useState( '' );
	const [ issued, setIssued ] = useState( null );
	const working = isWorking( busy, 'two-factor' );
	const issuing = isWorking( busy, 'backup-codes' );
	// Safe mode is on, so this account's password turns its own factor off:
	// the way back when the phone and the codes are both gone. The server
	// says when; the screen follows.
	const byPassword = true === status.password_turn_off;

	return (
		<>
			<div className="bs-ds-2fa__body">
				<p className="bs-ds-2fa__lead">
					{ sprintf(
						/* translators: %d: number of unused backup codes. */
						_n( '%d backup code unused.', '%d backup codes unused.', status.backup_remaining, 'bettershield' ),
						status.backup_remaining
					) }
					{ status.backup_remaining <= 3 ? ' ' + __( 'Running low, so issue a fresh set below.', 'bettershield' ) : '' }
				</p>

				{ /* What two-factor is needs no explaining. What is worth saying
				     is the thing someone would not guess: that the tools already
				     connected to this site carry on working. */ }
				{ /* Only while they do: refused by "Refuse application passwords"
				     or a lockdown, the sentence was untrue (#1847). */ }
				{ false !== status.app_passwords_work ? (
					<p className="bs-ds-2fa__note">{ __( 'Passwords made for apps and tools keep working and don’t ask for a code. You can turn them off under Login & Access.', 'bettershield' ) }</p>
				) : null }

				<Topics
					items={ [
						{
							key: 'signing-in',
							label: __( 'What changes at sign-in', 'bettershield' ),
							steps: [ __( 'Your password, as now.', 'bettershield' ), __( 'Then a code from the app, or a backup code.', 'bettershield' ) ],
							note: {
								tone: 'info',
								// The same sentence as the card's, and only while it is so (#1847, #2411).
								text:
									false !== status.app_passwords_work
										? __( 'Passwords made for apps and tools keep working and don’t ask for a code. You can turn them off under Login & Access.', 'bettershield' )
										: __( 'Passwords made for apps and tools are turned off right now, so they can’t be used to sign in.', 'bettershield' ),
							},
						},
						{
							key: 'lost',
							label: __( 'Lost your device', 'bettershield' ),
							lead: __( 'You still have two ways back in.', 'bettershield' ),
							points: [
								__( 'An administrator can turn two-factor off for you.', 'bettershield' ),
								__( 'Use your recovery link. It lets you sign in with just your password and turn two-factor off here.', 'bettershield' ),
							],
						},
					] }
				/>
			</div>

			{ /* Backup codes used to be minted once, at enrollment, and only ever
			     decrease. Somebody who spent theirs and then lost their phone had
			     nothing left, and the only way to get more was to turn the factor
			     off and set it up again, which needs the phone: it worked exactly
			     while it was not needed. */ }
			<SettingRow
				title={ __( 'New backup codes', 'bettershield' ) }
				about={
					issued
						? __(
								'Your old codes no longer work. Each new one works once and is shown only now.',
								'bettershield'
						  )
						: __(
								'A new set replaces all your backup codes.',
								'bettershield'
						  )
				}
			>
				{ issued ? (
					<>
						<Codes codes={ issued } />
						<KeepCodes codes={ issued } />
					</>
				) : (
					<FieldRow>
						<Field width="md" label={ __( 'App code or backup code', 'bettershield' ) } value={ fresh } onChange={ setFresh } inputMode="numeric" />
						{ /* The card's one primary action while two-factor is on. */ }
						<Button
							type="primary"
							size="sm"
							isBusy={ issuing }
							disabled={ issuing || ! fresh.trim() }
							onClick={ () =>
								reissueBackupCodes( fresh, ( result ) => {
									if ( result ) {
										setFresh( '' );
										setIssued( result.codes );
									}
								} )
							}
						>
							{ __( 'Create New Backup Codes', 'bettershield' ) }
						</Button>
					</FieldRow>
				) }
			</SettingRow>

			{ byPassword ? (
				<SettingRow
					title={ __( 'Turn off', 'bettershield' ) }
					about={ __( 'Your recovery link is in use, so your password alone can turn two-factor off. An alert email is sent.', 'bettershield' ) }
				>
					<FieldRow>
						<Field width="md" label={ __( 'Your password', 'bettershield' ) } type="password" autoComplete="current-password" value={ password } onChange={ setPassword } />
						<Button
							type="secondary"
							size="sm"
							isBusy={ working }
							disabled={ working || ! password }
							onClick={ () =>
								disableTwoFactor( '', password ).then( ( result ) => {
									// Never kept past the request, whatever it answered.
									setPassword( '' );

									if ( result ) {
										onDone();
									}
								} )
							}
						>
							{ __( 'Turn Two-Factor Off', 'bettershield' ) }
						</Button>
					</FieldRow>
				</SettingRow>
			) : (
				<SettingRow title={ __( 'Turn off', 'bettershield' ) }>
					<FieldRow>
						<Field width="md" label={ __( 'App code or backup code', 'bettershield' ) } value={ code } onChange={ setCode } inputMode="numeric" />
						<Button
							type="secondary"
							size="sm"
							isBusy={ working }
							disabled={ working || ! code.trim() }
							onClick={ () =>
								disableTwoFactor( code ).then( ( result ) => {
									if ( result ) {
										setCode( '' );
										onDone();
									}
								} )
							}
						>
							{ __( 'Turn Two-Factor Off', 'bettershield' ) }
						</Button>
					</FieldRow>
				</SettingRow>
			) }
		</>
	);
}

/**
 * The one quiet place this tab may say a paid tier exists: at the foot of the
 * two-factor card, and only when the server names an offer.
 */
function Offer() {
	if ( ! offer ) {
		return null;
	}

	return (
		<p className="bs-ds-2fa__offer">
			<span>
				{ __(
					'BetterShield Ultra adds trusted devices and a per-role two-factor report.',
					'bettershield'
				) }
			</span>
			<Button type="link" size="sm" href={ offer.url } target="_blank" rel="noopener noreferrer" trailing="external-link" trailingTone="2">
				{ sprintf(
					/* translators: %s: the name BetterShield Ultra. */
					__( 'About %s', 'bettershield' ),
					offer.name
				) }
			</Button>
		</p>
	);
}

/**
 * This account's second factor: its state in the header, then enrollment or
 * what an armed factor offers.
 *
 * @param {Object}   props
 * @param {Object}   props.status The account's two-factor status.
 * @param {Function} props.onDone Reads the status again once it has changed.
 */
function TwoFactorCard( { status, onDone } ) {
	/*
	 * Turning it on or off swaps the whole card body, the button pressed with
	 * it, and focus fell to the page (#1926). The card takes it, read with
	 * its title and new state; never on first paint.
	 */
	const card = useRef( null );
	const was = useRef( status.enabled );

	useEffect( () => {
		if ( was.current !== status.enabled ) {
			was.current = status.enabled;
			focusIfLost( card.current );
		}
	}, [ status.enabled ] );

	return (
		<Card ref={ card } tabIndex={ -1 } className="bs-ds-2fa__method" aria-labelledby="bs-ds-2fa-title">
			<CardHead icon="smartphone" id="bs-ds-2fa-title" title={ __( 'Two-factor authentication', 'bettershield' ) }>
				{ status.enabled ? <Badge tone="brand">{ __( 'On', 'bettershield' ) }</Badge> : <Badge>{ __( 'Off', 'bettershield' ) }</Badge> }
			</CardHead>
			{ status.enabled ? <Enabled status={ status } onDone={ onDone } /> : <Enrollment onDone={ onDone } /> }
			<Offer />
		</Card>
	);
}

/**
 * This account's two-factor card before its status has landed.
 */
function MethodBone() {
	return (
		<Skeleton label={ __( 'Loading your two-factor settings…', 'bettershield' ) }>
			<CardBone rows={ [ '90%' ] } />
		</Skeleton>
	);
}

/**
 * A requirement's row before its read has landed.
 *
 * @param {Object} props
 * @param {string} props.label What is on its way.
 */
function RequirementBone( { label } ) {
	return (
		<Skeleton label={ label }>
			<div className="bs-ds-bonerow">
				<span className="bs-ds-bonerow__text">
					<Bone kind="title" w="30%" />
					<Bone w="90%" />
					<Bone w="70%" />
				</span>
			</div>
		</Skeleton>
	);
}

/**
 * Which of the picked roles a store sends to My Account instead of the
 * dashboard, said under the picker. The requirement is asked for in the
 * dashboard, so for those accounts it is asked nowhere; they can still set up
 * their own sign-in from the store's account page.
 *
 * @param {Object}   props
 * @param {string[]} props.picked The roles ticked now.
 * @param {Object[]} props.roles  The roles on offer, each with `store_only`.
 * @param {string}   props.kind   `two-factor` or `passkey`.
 */
export function StoreRoleNote( { picked, roles, kind } ) {
	const names = ( roles || [] ).filter( ( role ) => role.store_only && picked.includes( role.slug ) ).map( ( role ) => role.label );

	if ( ! names.length ) {
		return null;
	}

	const list = names.join( ', ' );

	return (
		<div role="status">
			<Alert
				layout="default"
				tone="info"
				desc={
					'passkey' === kind
						? sprintf(
								/* translators: %s: comma-separated role names. */
								__( 'In WooCommerce, %s accounts add a passkey under My Account › Sign-in security, then sign in with it on the main sign-in page, not the store form.', 'bettershield' ),
								list
						  )
						: sprintf(
								/* translators: %s: comma-separated role names. */
								__( 'WooCommerce sends %s to My Account, so this requirement never reaches them. They can still set it up under Sign-in security.', 'bettershield' ),
								list
						  )
				}
			/>
		</div>
	);
}

/**
 * Whether two role lists name the same roles. A role unticked and ticked
 * again goes to the end of the list, so comparing the lists in order read
 * the same choice as a change and offered Save for it.
 *
 * @param {string[]} a One list of role slugs.
 * @param {string[]} b The other.
 * @return {boolean} Whether they hold the same roles.
 */
function sameRoles( a, b ) {
	return [ ...a ].sort().join( ',' ) === [ ...b ].sort().join( ',' );
}

/**
 * The roles a network requires of every site, from a policy read; none off a
 * network or where it requires nothing.
 *
 * @param {?Object} data A policy read carrying `network`.
 * @return {string[]} Role slugs.
 */
function networkRoles( data ) {
	return ( data && data.network && Array.isArray( data.network.roles ) && data.network.roles ) || [];
}

/**
 * Two role lists as one, each role once.
 *
 * @param {string[]} a One list of role slugs.
 * @param {string[]} b The other.
 * @return {string[]} Both.
 */
function bothRoles( a, b ) {
	return [ ...a, ...b.filter( ( slug ) => ! a.includes( slug ) ) ];
}

/**
 * The line under a role picker that names the roles the network requires,
 * which are drawn ticked and cannot be unticked here.
 *
 * @param {Object}   props
 * @param {string[]} props.required The network's role slugs.
 * @param {Object[]} props.roles    The site's roles, with labels.
 */
function NetworkRolesNote( { required, roles } ) {
	if ( ! required.length ) {
		return null;
	}

	const labels = {};

	( roles || [] ).forEach( ( role ) => {
		labels[ role.slug ] = role.label;
	} );

	return (
		<p className="bs-ds-2fa__note">
			{ sprintf(
				/* translators: %s: role names, e.g. "Editor, Author". */
				__( 'Required network-wide: %s. Only a network administrator can remove these.', 'bettershield' ),
				required.map( ( slug ) => labels[ slug ] || slug ).join( ', ' )
			) }
		</p>
	);
}

/**
 * A quiet line beside a Save button whose form has changed, so a change made
 * and not saved does not look like one that was. Announced politely, once.
 *
 * @param {Object}  props
 * @param {boolean} props.dirty Whether the form differs from what is saved.
 */
function Unsaved( { dirty } ) {
	return (
		<span className="bs-ds-2fa__unsaved" role="status">
			{ dirty ? __( 'Unsaved changes', 'bettershield' ) : '' }
		</span>
	);
}

/**
 * Requiring the factor of a role.
 *
 * Enforced in the dashboard rather than at the sign-in, so a mistake here is a
 * form somebody can fill in rather than a door that refuses them, and the row
 * says exactly that, because an owner about to require something of their
 * whole team deserves to know what the failure mode is.
 */
function RolePolicy() {
	const { resource, reload } = useResource( 'twoFactorPolicy' );
	const { saveTwoFactorPolicy, busy } = useStore();
	const [ draft, setDraft ] = useState( null );
	const saving = isWorking( busy, 'two-factor-policy' );

	return (
		<div className="bs-ds-2fa__requirement">
			<Resource resource={ resource } onRetry={ reload } loading={ <RequirementBone label={ __( 'Loading the two-factor requirement…', 'bettershield' ) } /> }>
				{ ( saved ) => {
					const policy = draft || saved;
					const roles = policy.roles || [];
					// Required of every site by the network, whatever this one names.
					const network = networkRoles( saved );

					/*
					 * Read as the field's text, not as a number: Number( '' ) is
					 * 0, so a cleared field saved a grace of zero, which sends
					 * every covered account without two-factor to enrollment on
					 * its next admin page. A field that is not a whole number of
					 * days in range is said to be wrong and is never sent.
					 */
					const grace = String( policy.grace_days ).trim();
					const graceProblem = graceDaysProblem( grace );
					const dirty = draft && ( ! sameRoles( draft.roles, saved.roles ) || Boolean( graceProblem ) || Number( grace ) !== saved.grace_days );
					// Another plugin kept for two-factor: a role added here is
					// asked for this plugin's code on top of that one's.
					const adding = Boolean( saved.handled_by ) && roles.some( ( role ) => ! ( saved.roles || [] ).includes( role ) );
					const save = () => saveTwoFactorPolicy( { roles, grace_days: Number( grace ) }, () => setDraft( null ) );

					return (
						<SettingRow
							// Named so the role picker under it can say which
							// policy its roles are for (#2030).
							id="bs-ds-2fa-roles-title"
							title={ __( 'Require two-factor for these roles', 'bettershield' ) }
							about={ __( 'Chosen roles must set up two-factor after a grace period.', 'bettershield' ) }
							topics={ [
								{
									key: 'grace',
									label: __( 'During the grace period', 'bettershield' ),
									text: __(
										// The reminder goes only where the grace period is longer
										// than its three days (#1848).
										'They keep working, with a countdown. Periods over three days add an email three days before the end. Then the dashboard sends them to setup.',
										'bettershield'
									),
								},
								{
									key: 'where',
									label: __( 'Where they set it up', 'bettershield' ),
									lead: __( 'On their own profile screen, which every account can open.', 'bettershield' ),
								},
								{
									key: 'locked-out',
									label: __( 'Lockout risk', 'bettershield' ),
									lead: __( 'None. People without two-factor can still sign in; the dashboard then asks them to set it up.', 'bettershield' ),
									points: [
										__( 'Your recovery link turns it off for an hour.', 'bettershield' ),
										__( 'Your recovery link always works, whatever you choose here.', 'bettershield' ),
									],
								},
							] }
						>
							<Field
								kind="checks"
								className="bs-ds-2fa__roles"
								aria-labelledby="bs-ds-2fa-roles-title"
								value={ bothRoles( roles, network ) }
								disabled={ saving }
								options={ ( saved.available_roles || [] ).map( ( role ) => ( { value: role.slug, label: role.label, disabled: network.includes( role.slug ) } ) ) }
								// The network's roles are drawn ticked, not saved as the site's own.
								onChange={ ( next ) => setDraft( { ...policy, roles: next.filter( ( slug ) => ! network.includes( slug ) || roles.includes( slug ) ) } ) }
							/>
							<NetworkRolesNote required={ network } roles={ saved.available_roles } />
							<StoreRoleNote picked={ roles } roles={ saved.available_roles } kind="two-factor" />

							<Field
								className="bs-ds-2fa__grace"
								width="sm"
								type="number"
								min={ 0 }
								max={ 90 }
								label={ __( 'Grace period, in days', 'bettershield' ) }
								help={ graceProblem || __( 'Days each person has to set it up, from when this first applies to them. 0 means right away.', 'bettershield' ) }
								value={ String( policy.grace_days ) }
								disabled={ saving }
								onChange={ ( value ) => setDraft( { ...policy, grace_days: value } ) }
							/>

							<div className="bs-ds-2fa__save">
								{ adding ? (
									<Armed
										type="primary"
										label={ __( 'Save Requirement', 'bettershield' ) }
										consequence={ sprintf(
											/* translators: %s: the name of the other plugin that handles two-factor. */
											__( '%s already handles two-factor. The added roles will also be asked to set up BetterShield’s, so people using both enter two codes.', 'bettershield' ),
											saved.handled_by
										) }
										confirm={ __( 'Save Anyway', 'bettershield' ) }
										busy={ saving }
										disabled={ saving || ! dirty || Boolean( graceProblem ) }
										onConfirm={ save }
									/>
								) : (
									<Button
										// The card's one Primary is the Save of the row with changes.
										type={ dirty ? 'primary' : 'secondary' }
										size="sm"
										isBusy={ saving }
										disabled={ saving || ! dirty || Boolean( graceProblem ) }
										onClick={ save }
									>
										{ __( 'Save Requirement', 'bettershield' ) }
									</Button>
								) }
								<Saved forKey="two-factor-policy" />
								<Unsaved dirty={ dirty } />
							</div>
						</SettingRow>
					);
				} }
			</Resource>
		</div>
	);
}

/**
 * Whether a store's My Account page offers the Sign-in security tab. Only
 * where there is a store, and saved the moment it is pressed, as a switch is.
 */
export function StoreTab() {
	const { resource } = useResource( 'twoFactorPolicy' );
	const { saveStoreTab, busy } = useStore();
	const saving = isWorking( busy, 'two-factor-store-tab' );

	// On the data alone: a refresh after the save keeps it, and a row that
	// left while one was on its way would take the keyboard's place with it.
	if ( ! resource.data || ! resource.data.store_active ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Show Sign-in security on WooCommerce My Account', 'bettershield' ) }
			about={ __( 'Lets customers set up two-factor and passkeys and see their signed-in devices.', 'bettershield' ) }
			control={ <Saved forKey="two-factor-store-tab" /> }
			toggle={ {
				checked: Boolean( resource.data.store_tab ),
				onChange: ( on ) => {
					if ( ! saving ) {
						saveStoreTab( on );
					}
				},
			} }
			topics={ [
				{
					key: 'still-shown',
					label: __( 'When it’s off', 'bettershield' ),
					lead: __( 'The tab still shows to anyone a rule above requires, or who already has two-factor or a passkey, so they can manage it.', 'bettershield' ),
				},
			] }
		/>
	);
}

/**
 * The page members kept out of the dashboard set this up on, saved the moment
 * it is picked.
 */
export function AccountPagePicker() {
	const { resource } = useResource( 'twoFactorPolicy' );
	const { saveAccountPage, busy } = useStore();
	const saving = isWorking( busy, 'two-factor-account-page' );

	if ( ! resource.data ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Sign-in Security Page', 'bettershield' ) }
			about={ __( 'For people who can’t open the dashboard. Reminders and notices link them here.', 'bettershield' ) }
			control={ <Saved forKey="two-factor-account-page" /> }
			topics={ [
				{
					key: 'how',
					label: __( 'Setting it up', 'bettershield' ),
					lead: __( 'Add the Sign-in Security block or the [bettershield_account] shortcode to a published page, then choose it here.', 'bettershield' ),
				},
			] }
		>
			<Field
				kind="select"
				width="md"
				label={ __( 'Page', 'bettershield' ) }
				value={ String( resource.data.account_page || 0 ) }
				disabled={ saving }
				options={ [
					{ value: '0', label: __( 'None', 'bettershield' ) },
					...( resource.data.account_pages || [] ).map( ( page ) => ( { value: String( page.id ), label: page.title } ) ),
				] }
				onChange={ ( value ) => saveAccountPage( Number( value ) ) }
			/>
		</SettingRow>
	);
}

/**
 * Passkey-only sign-in.
 *
 * The row has one job beyond the control itself, which is to say plainly what
 * naming a role does and does not do. The feature's whole safety rests on a
 * rule that is not obvious from a checkbox (nobody is refused until they hold
 * a passkey), and an owner who does not know that will either be afraid to
 * switch it on or switch it on expecting something it will not do yet.
 *
 * The coverage lines are the honest form of the same thing. "Editors are
 * passwordless" describes a setting; "four editors, one of whom has a passkey"
 * describes the site, and only the second tells anybody whether the policy is
 * doing anything.
 */
function PasskeyPolicy() {
	const { resource, reload } = useResource( 'passkeyPolicy' );
	const { savePasskeyPolicy, busy } = useStore();
	const [ draft, setDraft ] = useState( null );
	const saving = isWorking( busy, 'passkey-policy' );

	return (
		<div className="bs-ds-2fa__requirement">
			<Resource resource={ resource } onRetry={ reload } loading={ <RequirementBone label={ __( 'Loading the passkey requirement…', 'bettershield' ) } /> }>
				{ ( data ) => {
					const saved = data.policy.roles || [];
					const roles = draft ? draft.roles : saved;
					const dirty = draft && ! sameRoles( draft.roles, saved );
					// Required of every site by the network, whatever this one names.
					const network = networkRoles( data );

					/*
					 * Where passkeys are off the gate stands aside, so nothing
					 * here is in effect. A role can still be taken out, which is
					 * the way back for a policy saved before the site moved off
					 * HTTPS; adding one is refused, so its box is not offered.
					 */
					const off = false === data.available;

					/*
					 * Every named role, not only the ones still short. A role
					 * where everybody has enrolled is the good news this row
					 * exists to deliver: hiding it left an owner who had finished
					 * the job with no confirmation that they had, and no way to
					 * tell "fully applied" from "not applied at all".
					 */
					const labels = {};

					( data.roles || [] ).forEach( ( role ) => {
						labels[ role.slug ] = role.label;
					} );

					const coverage = data.coverage || [];

					return (
						<SettingRow
							id="bs-ds-passkey-roles-title"
							title={ __( 'Sign in with a passkey only', 'bettershield' ) }
							about={ __(
								'Once they add a passkey, accounts in these roles can’t sign in with a password.',
								'bettershield'
							) }
							topics={ [
								{
									key: 'why',
									label: __( 'Why passkeys only', 'bettershield' ),
									lead: __( 'A password that can’t sign anyone in can’t be phished, guessed or reused from another site’s breach.', 'bettershield' ),
								},
								{
									key: 'when',
									label: __( 'When it starts applying', 'bettershield' ),
									lead: __( 'Only once an account has added a passkey.', 'bettershield' ),
									points: [
										__( 'Nothing changes for people in the role without a passkey.', 'bettershield' ),
										__( 'Their password still works; their dashboard asks them to add one.', 'bettershield' ),
									],
									note: { tone: 'safe', text: __( 'Nobody is ever refused without another way in.', 'bettershield' ) },
								},
								{
									key: 'locked-out',
									label: __( 'A lost passkey', 'bettershield' ),
									lead: __( 'Password sign-in comes back if you use your recovery link or a recovery code, or remove the person’s last passkey.', 'bettershield' ),
									points: [ __( 'For someone else, remove it on their Edit user screen.', 'bettershield' ) ],
									note: { tone: 'safe', text: __( 'The same ways back work for every other protection here.', 'bettershield' ) },
								},
							] }
						>
							<Field
								kind="checks"
								className="bs-ds-2fa__roles"
								aria-labelledby="bs-ds-passkey-roles-title"
								value={ bothRoles( roles, network ) }
								disabled={ saving }
								options={ ( data.roles || [] ).map( ( role ) => ( {
									value: role.slug,
									label: role.label,
									disabled: ( off && ! saved.includes( role.slug ) ) || network.includes( role.slug ),
								} ) ) }
								// The network's roles are drawn ticked, not saved as the site's own.
								onChange={ ( next ) => setDraft( { roles: next.filter( ( slug ) => ! network.includes( slug ) || roles.includes( slug ) ) } ) }
							/>
							<NetworkRolesNote required={ network } roles={ data.roles } />

							{ off ? (
								<div role="status">
									<Alert
										layout="default"
										tone={ saved.length ? 'warning' : 'info' }
										desc={
											saved.length
												? __( 'Not in effect: passkeys are off, so these roles still sign in with passwords.', 'bettershield' )
												: __( 'Passkeys are off, so no role can be asked to sign in with one.', 'bettershield' )
										}
									/>
								</div>
							) : (
								<StoreRoleNote picked={ roles } roles={ data.roles } kind="passkey" />
							) }

							{ ! off && coverage.length ? (
								<ul className="bs-ds-coverage" role="status">
									{ coverage.map( ( row ) => (
										<li key={ row.role }>
											{ /* How far the role has got, drawn as well as said.
											     Decorative: the sentence under it is the fact. */ }
											<span className="bs-ds-coverage__bar" aria-hidden="true">
												<span style={ { '--bs-ds-coverage': row.accounts ? Math.min( 1, row.enrolled / row.accounts ) : 0 } } />
											</span>
											<span>
												{ /*
												   The empty case first: zero enrolled of
												   zero accounts satisfies "all covered",
												   and English picks the plural at zero, so
												   a role nobody holds read as a role whose
												   passwords no longer sign anybody in.
												*/ }
												{ 0 === row.accounts
													? sprintf(
															/* translators: %s: a role name. */
															__( '%s: no account has this role.', 'bettershield' ),
															labels[ row.role ] || row.role
													  )
													: row.enrolled >= row.accounts
													? sprintf(
															/* translators: 1: a role name, 2: how many accounts hold it. */
															_n(
																'%1$s: %2$d account now signs in with a passkey only.',
																'%1$s: all %2$d accounts now sign in with a passkey only.',
																row.accounts,
																'bettershield'
															),
															labels[ row.role ] || row.role,
															row.accounts
													  )
													: sprintf(
															/* translators: 1: a role name, 2: how many of the accounts have a passkey, 3: how many accounts hold the role. */
															__( '%1$s: %2$d of %3$d have a passkey. The rest still sign in with a password.', 'bettershield' ),
															labels[ row.role ] || row.role,
															row.enrolled,
															row.accounts
													  ) }
												{ row.capped ? ' ' + __( '(counted up to the first 200.)', 'bettershield' ) : '' }
											</span>
										</li>
									) ) }
								</ul>
							) : null }

							<div className="bs-ds-2fa__save">
								<Button
									// The card's one Primary is the Save of the row with changes.
									type={ dirty ? 'primary' : 'secondary' }
									size="sm"
									isBusy={ saving }
									disabled={ saving || ! dirty }
									onClick={ () => savePasskeyPolicy( { roles }, () => setDraft( null ) ) }
								>
									{ __( 'Save Requirement', 'bettershield' ) }
								</Button>
								<Saved forKey="passkey-policy" />
								<Unsaved dirty={ dirty } />
							</div>
						</SettingRow>
					);
				} }
			</Resource>
		</div>
	);
}

/**
 * Whether the sign-in page offers a saved passkey in the username field's own
 * list, beside saved passwords. Saved the moment it is pressed, as a switch
 * is. The button below Log In stays either way.
 */
export function PasskeyAutofill() {
	const { resource } = useResource( 'passkeyPolicy' );
	const { savePasskeyAutofill, busy } = useStore();
	const saving = isWorking( busy, 'passkey-autofill' );

	if ( ! resource.data ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Offer passkeys in the username field', 'bettershield' ) }
			about={ __( 'On the sign-in page, a saved passkey shows in the username field’s list, beside saved passwords.', 'bettershield' ) }
			control={ <Saved forKey="passkey-autofill" /> }
			toggle={ {
				checked: false !== resource.data.policy.autofill,
				onChange: ( on ) => {
					if ( ! saving ) {
						savePasskeyAutofill( on );
					}
				},
			} }
			topics={ [
				{
					key: 'how',
					label: __( 'How it works', 'bettershield' ),
					lead: __( 'Picking a passkey from the list signs in, the same as Log In With a Passkey.', 'bettershield' ),
					points: [
						__( 'Only in browsers that support it. The button below Log In stays for the rest.', 'bettershield' ),
						__( 'The password field works as before.', 'bettershield' ),
					],
				},
			] }
		/>
	);
}

/**
 * The tab at a glance: this account's own second factor, then what the site
 * asks of every account. Three answers a person opening this tab usually came
 * for, readable before any card below is.
 *
 * Read from the same resources the cards below use, so the strip and the
 * cards cannot disagree; a value not yet loaded holds its place rather than
 * guessing.
 */
function AtAGlance() {
	const own = useResource( 'twoFactor' ).resource;
	const required = useResource( 'twoFactorPolicy' ).resource;
	const passkeys = useResource( 'passkeyPolicy' ).resource;

	const named = ( slugs, roles ) => {
		const labels = {};

		( roles || [] ).forEach( ( role ) => {
			labels[ role.slug ] = role.label;
		} );

		return slugs.map( ( slug ) => labels[ slug ] || slug ).join( ', ' );
	};

	const roleCount = ( count ) =>
		count
			? sprintf(
					/* translators: %d: number of roles. */
					_n( '%d role', '%d roles', count, 'bettershield' ),
					count
			  )
			: __( 'No roles', 'bettershield' );

	const ownReady = Boolean( own.data );
	const on = ownReady && own.data.enabled;
	// The roles enforced here: the site's own and the network's, and those an
	// add-on asks under its own rules, so nobody asked is left uncounted.
	const elsewhereRoles = ( required.data && required.data.elsewhere && Array.isArray( required.data.elsewhere.roles ) && required.data.elsewhere.roles ) || [];
	const requiredRoles = bothRoles( bothRoles( ( required.data && required.data.roles ) || [], networkRoles( required.data ) ), elsewhereRoles );
	const passkeyRoles = bothRoles( ( passkeys.data && passkeys.data.policy && passkeys.data.policy.roles ) || [], networkRoles( passkeys.data ) );

	// Named roles on a site where passkeys are off are stored, not enforced.
	const passkeysOff = Boolean( passkeys.data ) && false === passkeys.data.available;

	// A tile whose read is still out holds its place rather than guessing.
	const waiting = ( resource ) => ! resource.data && 'error' !== resource.status;

	const tiles = [
		{
			key: 'own',
			icon: 'smartphone',
			label: __( 'Your two-factor', 'bettershield' ),
			value: ownReady ? ( on ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) ) : '—',
			tone: on ? 'good' : undefined,
			detail: on
				? sprintf(
						/* translators: %d: number of unused backup codes. */
						_n( '%d backup code unused', '%d backup codes unused', own.data.backup_remaining, 'bettershield' ),
						own.data.backup_remaining
				  )
				: __( 'Not set up on this account yet', 'bettershield' ),
			pending: waiting( own ),
		},
		{
			key: 'required',
			icon: 'users',
			label: __( 'Two-factor required for', 'bettershield' ),
			value: required.data ? roleCount( requiredRoles.length ) : '—',
			tone: requiredRoles.length > 0 ? 'good' : undefined,
			detail: requiredRoles.length ? named( requiredRoles, required.data.available_roles ) : __( 'Nobody is asked to set it up yet', 'bettershield' ),
			pending: waiting( required ),
		},
		{
			key: 'passkey',
			icon: 'fingerprint',
			label: __( 'Passkey-only sign-in for', 'bettershield' ),
			value: passkeys.data ? roleCount( passkeyRoles.length ) : '—',
			tone: passkeyRoles.length > 0 ? ( passkeysOff ? 'caution' : 'good' ) : undefined,
			detail: passkeyRoles.length
				? passkeysOff
					? __( 'Not in effect: passkeys are off on this site', 'bettershield' )
					: named( passkeyRoles, passkeys.data.roles )
				: __( 'Every role can still use a password', 'bettershield' ),
			pending: waiting( passkeys ),
		},
	];

	return <Stats label={ __( 'Two-factor at a glance', 'bettershield' ) } tiles={ tiles } />;
}

/**
 * Another plugin kept for two-factor in Quick Setup. Keeping it changed only
 * the setup, and this screen went on offering enrollment and the role
 * requirement with nothing said: whoever took them was asked for two codes.
 */
function HandledElsewhere() {
	const policy = useResource( 'twoFactorPolicy' ).resource;
	const name = 'ready' === policy.status && policy.data ? policy.data.handled_by : '';

	return name ? (
		<Alert
			layout="default"
			tone="info"
			desc={ sprintf(
				/* translators: %s: the name of the other plugin, or several separated by commas. */
				__( 'Two-factor is handled by %s on this site.', 'bettershield' ),
				name
			) }
		/>
	) : null;
}

export default function TwoFactor() {
	const { resource, reload } = useResource( 'twoFactor' );
	const { load } = useStore();
	// The saved passkey-only roles, so the card's own hint is read again when
	// they change: unticked, it still said the password no longer worked (#2485).
	const passkeyPolicy = useResource( 'passkeyPolicy' ).resource;
	const passkeyOnly = ( passkeyPolicy?.data?.policy?.roles || [] ).join( ',' );

	return (
		<>
			<SafeMode />
			<HandledElsewhere />
			<AtAGlance />

			{ /*
			   The ways this account signs in, then what the site asks of every
			   account: a requirement reads best once the method it requires has
			   been read. The two methods side by side, as two cards of one kind:
			   they answer the same question.
			*/ }
			<section className="bs-ds-2fa__methods" aria-label={ __( 'Your sign-in', 'bettershield' ) }>
				<Resource resource={ resource } onRetry={ reload } loading={ <MethodBone /> }>
					{ ( status ) => <TwoFactorCard status={ status } onDone={ reload } /> }
				</Resource>

				{ /* A passkey added or removed moves the coverage lines on the
				     requirement below (how many of the named accounts hold one),
				     so the policy is read again rather than left describing the
				     site as it was. This account's own status is read again
				     too: a backup code given as the proof is spent, and the
				     count beside it would otherwise still offer it. */ }
				<Passkeys
					policy={ passkeyOnly }
					onChanged={ () => {
						load( 'passkeyPolicy', { force: true } );
						load( 'twoFactor', { force: true } );
					} }
				/>
			</section>

			{ /* The passkey requirement last, because it is the only control on
			     this screen that takes something away rather than adding it,
			     and it only makes sense to somebody who has read the
			     requirement above it and the passkeys card before that. */ }
			<SettingsCard icon="users" title={ __( 'What the site requires', 'bettershield' ) }>
				<RolePolicy />
				<PasskeyPolicy />
				<PasskeyAutofill />
				<StoreTab />
				<AccountPagePicker />
			</SettingsCard>
		</>
	);
}
