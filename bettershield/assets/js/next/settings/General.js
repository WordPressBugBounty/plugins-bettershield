/**
 * Settings › General: the plugin's own configuration — password policy,
 * audit scheduling, what leaves the site, what this copy records and asks
 * before it acts, and what it leaves behind if it goes. What arrives by
 * email is the Alerts tab beside this one.
 *
 * The four facts first, then the four groups as tabs. Each group is a card
 * of setting rows — the setting's name and one line, its control at the
 * end, the longer explanations under "How it works" — with the cards that
 * stand on their own beside it: BetterShield Hub with what leaves the site,
 * the settings history with this installation. The recovery link lives under
 * Protect, beside the things it undoes.
 */

import './General.css';

import { FormFileUpload } from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';
import { createInterpolateElement, useEffect, useId, useLayoutEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { helpLinks, linkedGroup, sectionUrl, tabUrl, writeNarrowing } from '../../nav';
import { listOf } from '../../setup/format';
import { formatTime, isPast, isWorking, useResource, useStore } from '../../store';
import { copyToClipboard } from '../../ui/copy';
import { download } from '../../ui/download';
import { editedFields } from '../../ui/edits';
import { limits, offer } from '../../ui/TierOffer';
import { providerCredit, unreachedText, unreachedWithoutResults } from '../data/vulnerabilities';
import useMutationFocus from '../../ui/useMutationFocus';
import useUnsaved from '../ui/useUnsaved';
import { contactProblem, urlProblem } from '../../ui/validate';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Field from '../ui/Field';
import Icon from '../ui/Icon';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { Bone, CardBone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { EmptyState, ErrorState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Topics from '../ui/Topics';
import FitTabs from '../activity/FitTabs';
import { REVEAL } from '../ui/useFocusTarget';
import UsageReport from '../ui/UsageReport';
import { panelProps } from '../ui/tabKeys';
import { changeLines, putBackLines } from './changes';
import Switch from './Switch';
import SwitchLine from '../agents/SwitchLine';

/** The tabs' id base, which ties each tab to the panel it shows. */
const TABS_ID = 'bs-ds-settings';

/** A React id, as an attribute other markup can point at. */
function useDomId() {
	return useId().replace( /[^\w-]/g, '' );
}

/**
 * One setting standing in for itself, as a row of its card, while its own
 * read is out.
 *
 * @param {Object}  props
 * @param {string}  props.label  What is loading.
 * @param {boolean} props.toggle The row ends in a switch.
 */
function RowBone( { label, toggle = false } ) {
	return (
		<Skeleton label={ label }>
			<div className="bs-ds-bonerow">
				<span className="bs-ds-bonerow__text">
					<Bone kind="title" w="30%" />
					<Bone w="70%" />
				</span>
				{ toggle ? <span className="bs-ds-bone bs-ds-bone--toggle" /> : <Bone kind="control" w="96px" /> }
			</div>
		</Skeleton>
	);
}

/**
 * A setting's own read: its stand-in, or the row, or a failure said inside
 * the row's own padding rather than across the card's edge.
 *
 * @param {Object}   props
 * @param {Object}   props.resource The store's resource.
 * @param {Function} props.onRetry  Reads again.
 * @param {*}        props.loading  The stand-in.
 * @param {Function} props.children Given the data.
 */
function RowResource( { resource, onRetry, loading, children } ) {
	if ( resource && 'error' === resource.status ) {
		return (
			<div className="bs-ds-setting">
				<ErrorState onRetry={ onRetry } />
			</div>
		);
	}

	return (
		<Resource resource={ resource } onRetry={ onRetry } loading={ loading }>
			{ children }
		</Resource>
	);
}

/**
 * What a field holds when nobody has chosen, and a way back to it.
 *
 * A security tool's defaults are its recommendation, and they were visible
 * only as whatever a fresh install happened to show. Shown only while the
 * field differs from it: on a site that never touched the number, repeating
 * it is noise, and a reset to what is already there does nothing.
 *
 * @param {Object}   props
 * @param {*}        props.value    What the field holds now.
 * @param {*}        props.fallback What it would hold by default.
 * @param {Function} props.onReset  Puts it back.
 */
function DefaultHint( { value, fallback, onReset } ) {
	if ( undefined === fallback || null === fallback ) {
		return null;
	}

	// Compared as text: a number that arrived from a field is a string, and
	// "12" and 12 are the same answer.
	if ( String( value ?? '' ) === String( fallback ) ) {
		return null;
	}

	return (
		<p className="bs-ds-gen__default">
			{ sprintf(
				/* translators: %s: the value this setting has when nobody has chosen one. */
				__( 'Default: %s', 'bettershield' ),
				String( fallback )
			) }
			<Button type="linksub" size="sm" onClick={ onReset }>
				{ __( 'Use Default', 'bettershield' ) }
			</Button>
		</p>
	);
}

/* ---------- what this site checks ---------- */

/**
 * Whether the policy as edited differs from the one saved.
 *
 * @param {?Object} draft The edits, or null.
 * @param {?Object} saved The saved policy, or null while it loads.
 * @return {boolean} Whether there is something to save.
 */
function policyEdited( draft, saved ) {
	return Boolean(
		draft &&
			saved &&
			( draft.enabled !== saved.enabled ||
				Number( draft.min_length ) !== saved.min_length ||
				Number( draft.min_length_privileged ) !== saved.min_length_privileged ||
				Number( draft.min_length_single_factor ) !== saved.min_length_single_factor ||
				Boolean( draft.single_factor_everyone ) !== Boolean( saved.single_factor_everyone ) )
	);
}

/**
 * What is wrong with the lengths as typed, by field, in the server's own
 * words: each a whole number from 6 to 64, and the one for admins and
 * editors no lower than everyone else's. Said under the field as it is typed,
 * rather than after a refused save at the top of the screen (#2499).
 *
 * @param {Object} policy The policy as edited.
 * @return {Object<string, string>} Field => problem; empty when all is well.
 */
export function policyProblems( policy ) {
	const problems = {};
	const range = __( 'Minimum lengths need to be between 6 and 64 characters.', 'bettershield' );

	[ 'min_length', 'min_length_privileged', 'min_length_single_factor' ].forEach( ( key ) => {
		const text = String( policy[ key ] ?? '' ).trim();
		const value = Number( text );

		if ( '' === text || ! Number.isInteger( value ) || value < 6 || value > 64 ) {
			problems[ key ] = range;
		}
	} );

	if ( ! problems.min_length && ! problems.min_length_privileged && Number( policy.min_length_privileged ) < Number( policy.min_length ) ) {
		problems.min_length_privileged = __( 'The minimum for admins and editors cannot be lower than for everyone else.', 'bettershield' );
	}

	return problems;
}

export function PasswordPolicy() {
	const { resource, reload } = useResource( 'passwordPolicy' );
	const { savePasswordPolicy, busy } = useStore();
	const [ draft, setDraft ] = useState( null );
	const saving = busy === 'password-policy';

	// Leaving with edits not saved asks first, as Login & access does: a
	// click in the sidebar threw them away without a word (#2053).
	const { status: readStatus, data: savedPolicy } = resource;
	useUnsaved( policyEdited( draft, 'ready' === readStatus ? savedPolicy : null ) );

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the password policy…', 'bettershield' ) } toggle /> }>
			{ ( saved ) => {
				const policy = draft || saved;
				const defaults = saved.defaults || {};
				const dirty = policyEdited( draft, saved );
				// Only the numbers on screen: off, they are not shown or edited.
				const problems = policy.enabled ? policyProblems( policy ) : {};

				return (
					<SettingRow
						focusKey="password_policy"
						title={ __( 'Password policy', 'bettershield' ) }
						about={ __( 'Minimum length for new passwords.', 'bettershield' ) }
						control={
							<Switch
								label={ __( 'Require a minimum length for new passwords', 'bettershield' ) }
								checked={ policy.enabled }
								disabled={ saving }
								onChange={ ( enabled ) => setDraft( { ...policy, enabled } ) }
							/>
						}
						topics={ [
							{
								key: 'existing',
								label: __( 'Passwords already in use', 'bettershield' ),
								lead: __( 'Nothing changes. Existing passwords keep working; the rule applies only when a password is set or changed.', 'bettershield' ),
								points: [
									__( 'A password from before the policy keeps working.', 'bettershield' ),
									__( 'The account holder sees a note on their profile suggesting a longer password.', 'bettershield' ),
								],
							},
							{
								key: 'skipped',
								label: __( 'Which passwords are not checked', 'bettershield' ),
								lead: __( 'These three are skipped:', 'bettershield' ),
								points: [
									__(
										'Application passwords, since WordPress generates them.',
										'bettershield'
									),
									__(
										'Accounts created by other plugins, imports or command-line tools.',
										'bettershield'
									),
									__(
										'Store checkout passwords, checked at first sign-in instead.',
										'bettershield'
									),
								],
							},
						] }
					>
						{ policy.enabled ? (
							<div className="bs-ds-policy">
								<div className="bs-ds-policy__fields">
									{ /* Each field and its default in one column, so the
									     hint sits under the field it is about rather than
									     between the two. The columns share their rows
									     (label, box, help, default), so a label that wraps
									     drops every box beside it, not only its own. */ }
									<div className="bs-ds-policy__field">
										<Field
											type="number"
											min={ 6 }
											max={ 64 }
											label={ __( 'Minimum length', 'bettershield' ) }
											help={ problems.min_length ? undefined : __( 'For most accounts.', 'bettershield' ) }
											error={ problems.min_length || '' }
											value={ String( policy.min_length ) }
											disabled={ saving }
											onChange={ ( value ) => setDraft( { ...policy, min_length: value } ) }
										/>
										<DefaultHint
											value={ policy.min_length }
											fallback={ defaults.min_length }
											onReset={ () => setDraft( { ...policy, min_length: defaults.min_length } ) }
										/>
									</div>
									<div className="bs-ds-policy__field">
										<Field
											type="number"
											min={ 6 }
											max={ 64 }
											label={ __( 'For admins and editors', 'bettershield' ) }
											help={ problems.min_length_privileged ? undefined : __( 'Accounts that can change the site.', 'bettershield' ) }
											error={ problems.min_length_privileged || '' }
											value={ String( policy.min_length_privileged ) }
											disabled={ saving }
											onChange={ ( value ) => setDraft( { ...policy, min_length_privileged: value } ) }
										/>
										<DefaultHint
											value={ policy.min_length_privileged }
											fallback={ defaults.min_length_privileged }
											onReset={ () => setDraft( { ...policy, min_length_privileged: defaults.min_length_privileged } ) }
										/>
									</div>
									<div className="bs-ds-policy__field">
										<Field
											type="number"
											min={ 6 }
											max={ 64 }
											label={ __( 'Admins and editors without two-factor', 'bettershield' ) }
											help={ problems.min_length_single_factor ? undefined : __( 'Minimum length for admins and editors who don’t use two-factor or a passkey.', 'bettershield' ) }
											error={ problems.min_length_single_factor || '' }
											value={ String( policy.min_length_single_factor ) }
											disabled={ saving }
											onChange={ ( value ) => setDraft( { ...policy, min_length_single_factor: value } ) }
										/>
										<DefaultHint
											value={ policy.min_length_single_factor }
											fallback={ defaults.min_length_single_factor }
											onReset={ () => setDraft( { ...policy, min_length_single_factor: defaults.min_length_single_factor } ) }
										/>
									</div>
								</div>
								{ /* The third number's reach, on a line of its own
								     under the three: lined up with the first box,
								     the switch leading and its words beside it. */ }
								<SwitchLine
									label={ __( 'Use this longer minimum for every account without two-factor, including store customers', 'bettershield' ) }
									checked={ Boolean( policy.single_factor_everyone ) }
									disabled={ saving }
									onChange={ ( everyone ) => setDraft( { ...policy, single_factor_everyone: everyone } ) }
								/>
							</div>
						) : null }

						<div className="bs-ds-gen__actions">
							{ /* The card's one primary: the switch and the two numbers
							     are a draft until this sends them. */ }
							<Button
								type="primary"
								size="sm"
								isBusy={ saving }
								// Held while a length is out of range, as the contact
								// fields hold theirs: the press would only be refused.
								disabled={ saving || ! dirty || Object.keys( problems ).length > 0 }
								onClick={ () =>
									savePasswordPolicy(
										{
											enabled: policy.enabled,
											min_length: Number( policy.min_length ),
											min_length_privileged: Number( policy.min_length_privileged ),
											min_length_single_factor: Number( policy.min_length_single_factor ),
											single_factor_everyone: Boolean( policy.single_factor_everyone ),
										},
										() => setDraft( null )
									)
								}
							>
								{ __( 'Save Policy', 'bettershield' ) }
							</Button>
						</div>
					</SettingRow>
				);
			} }
		</RowResource>
	);
}

function ScheduledAudits( { data } ) {
	const { runAudit, busy } = useStore();
	const auditing = busy === 'audit';

	/*
	 * An audit reads the site and stores no setting, so the shared "Saved."
	 * would announce a configuration change that had not happened. What is
	 * true is that it ran — which on a site where nothing changed is otherwise
	 * only visible as a timestamp moving by a second.
	 */
	const [ audited, setAudited ] = useState( false );

	useEffect( () => {
		if ( ! audited ) {
			return undefined;
		}

		const timer = window.setTimeout( () => setAudited( false ), 6000 );

		return () => window.clearTimeout( timer );
	}, [ audited ] );

	return (
		<SettingRow
			title={ __( 'Scheduled audits', 'bettershield' ) }
			about={
				! data.next_check_at
					? sprintf(
							/* translators: %s: date and time of the last audit. */
							__( 'No audit is scheduled. The last one ran %s.', 'bettershield' ),
							formatTime( data.generated_at )
					  )
					: isPast( data.next_check_at )
					? sprintf(
							/* translators: 1: date and time the audit was due, 2: date and time of the last audit. */
							__( 'The audit due %1$s has not run. The last one ran %2$s.', 'bettershield' ),
							formatTime( data.next_check_at ),
							formatTime( data.generated_at )
					  )
					: sprintf(
							/* translators: 1: date and time of the next audit, 2: date and time of the last audit. */
							__( 'The next audit runs %1$s. The last one ran %2$s.', 'bettershield' ),
							formatTime( data.next_check_at ),
							formatTime( data.generated_at )
					  )
			}
			control={
				<>
					{ /* The button spun and stopped and said nothing, on a screen
					     that shows none of what the audit produced. Whether it
					     found anything is a press away, so the way there is
					     offered beside it rather than described. */ }
					{ audited ? (
						<span className="bs-ds-gen__done" role="status">
							<Icon name="check" size={ 12 } tone="ok" />
							{ __( 'Audited just now.', 'bettershield' ) }
						</span>
					) : null }
					<Button
						type="secondary"
						size="sm"
						icon="refresh-cw"
						iconTone="2"
						isBusy={ auditing }
						disabled={ auditing }
						onClick={ () =>
							runAudit().then( ( result ) => {
								if ( result ) {
									setAudited( true );
								}
							} )
						}
					>
						{ auditing ? __( 'Auditing…', 'bettershield' ) : __( 'Run Audit', 'bettershield' ) }
					</Button>
					<Button type="linksub" size="sm" trailing="arrow-right" href={ sectionUrl( 'bettershield-findings' ) }>
						{ __( 'See the Full Report', 'bettershield' ) }
					</Button>
				</>
			}
			topics={ [
				{
					key: 'audit-does',
					label: __( 'What an audit does', 'bettershield' ),
					lead: __( 'It reads the site and records findings.', 'bettershield' ),
					note: { tone: 'safe', text: __( 'It changes nothing, so running one is never a risk.', 'bettershield' ) },
				},
				{
					key: 'late',
					label: __( 'Why one can be late', 'bettershield' ),
					lead: __( 'Scheduled tasks run on visits, so quiet sites can miss them.', 'bettershield' ),
					note: { tone: 'safe', text: __( 'A badly overdue audit runs when you next open the dashboard.', 'bettershield' ) },
				},
			] }
		/>
	);
}

/**
 * The vulnerability check's consent: the one outside call this feature
 * makes, stated in full beside the switch that allows it. Drawn only when a
 * data source is bound to this site — with none, there is nothing to consent
 * to and the Findings screen already says so.
 */
function VulnerabilityChecks() {
	const { resource, reload } = useResource( 'vulnerabilities' );
	const { setVulnerabilityChecks, checkVulnerabilities, busy } = useStore();
	const feed = resource.data;

	// Asked before the hide below, because the hide means "no data source is
	// bound to this site" and a failed request means nothing of the kind. Both
	// drew the same blank space, so a row that could not load read as a row
	// that does not apply here.
	if ( 'error' === resource.status ) {
		return (
			<div className="bs-ds-setting">
				<ErrorState onRetry={ reload } />
			</div>
		);
	}

	if ( ! feed || ! feed.feed_bound ) {
		return null;
	}

	const working = busy === 'vulnerabilities';

	return (
		<SettingRow
			focusKey="vulnerability_checks"
			title={ __( 'Vulnerability checks', 'bettershield' ) }
			about={ sprintf(
				/* translators: %s: feed name. */
				__( 'Sends %s the names and versions of your plugins (including must-use plugins), themes and WordPress. Nothing else.', 'bettershield' ),
				feed.feed_label
			) }
			tip={ __( 'Checks run daily and after updates or removals. No site address, email, username or key is sent.', 'bettershield' ) }
			control={
				<>
					<Saved forKey="vulnerabilities" />
					<Switch
						label={ __( 'Check plugins, themes and WordPress for known security issues', 'bettershield' ) }
						checked={ feed.enabled }
						disabled={ working }
						onChange={ ( on ) => setVulnerabilityChecks( on ) }
					/>
				</>
			}
		>
			{ feed.enabled ? (
				<div className="bs-ds-gen__actions">
					<Button type="secondary" size="sm" icon="scan-search" iconTone="2" isBusy={ working } disabled={ working } onClick={ () => checkVulnerabilities() }>
						{ __( 'Check Now', 'bettershield' ) }
					</Button>
					<span className="bs-ds-gen__note">
						{ feed.has_data
							? sprintf(
									/* translators: 1: date, 2: how many items were checked, e.g. "12 items checked"; 3: how many need a review, e.g. "2 items for review". */
									__( 'Last checked %1$s: %2$s, %3$s.', 'bettershield' ),
									formatTime( feed.published_at || feed.fetched_at ),
									sprintf(
										/* translators: %d: how many installed items the feed was checked against. */
										_n( '%d item checked', '%d items checked', feed.checked, 'bettershield' ),
										feed.checked
									),
									sprintf(
										/* translators: %d: how many of the checked items a published advisory may affect, for the owner to review. */
										_n( '%d item for review', '%d items for review', feed.affected, 'bettershield' ),
										feed.affected
									)
							  )
							: // A check that ran and failed is said once, below.
							  unreachedWithoutResults( feed ) ? null : __( 'No check has run yet.', 'bettershield' ) }
						{ providerCredit( feed ) ? ' ' + providerCredit( feed ) : null }
					</span>
				</div>
			) : null }
			{ feed.error ? (
				<Alert
					layout="default"
					tone="warning"
					desc={
						// A result to keep only once a check has succeeded (#2136).
						feed.has_data
							? sprintf(
									/* translators: %s: error text. */
									__( 'The latest check failed (%s). The results shown are from the last successful check.', 'bettershield' ),
									feed.error
							  )
							: 'inventory' === feed.error_kind
							? feed.error
							: unreachedText( feed )
					}
				/>
			) : null }
		</SettingRow>
	);
}

/* ---------- what leaves this site ---------- */

export function SecurityContact() {
	const { resource, reload } = useResource( 'securityTxt' );
	const { saveSecurityTxt, busy } = useStore();
	const saving = busy === 'securityTxt';
	const [ draft, setDraft ] = useState( null );
	const [ error, setError ] = useState( null );
	// Pressed on the switch: the text field's blur-save is left to the
	// switch, which sends the edits with its own change (#2488).
	const toSwitch = useRef( false );

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the security contact…', 'bettershield' ) } toggle /> }>
			{ ( data ) => {
				const value = draft || data;

				const save = ( next ) => {
					setError( null );
					setDraft( { ...value, ...next } );

					// The store's act() never rejects — a refusal resolves
					// null and raises the global notice — so a .catch() here
					// was dead code, and the optimistic draft outlived the
					// refusal: the row said "Published" about a change the
					// server had refused. Whatever came back, the server's
					// answer is the truth to show.
					// Both outcomes passed in rather than chained on: behind
					// the password gate the returned promise resolves before
					// anybody has answered, and a canceled confirmation is a
					// change that was not made.
					// Without the stored date: sent back, a date that had passed
					// refused every save it rode along with. The server keeps it,
					// or renews it when the file is published again or renewed.
					const sent = { ...value, ...next };
					delete sent.expires;

					saveSecurityTxt(
						sent,
						() => setDraft( null ),
						( refusal ) => {
							// The server says why, as plainly as anything here
							// could: "Add a contact: …" (#2488).
							setError( refusal?.message || __( 'That change was not saved. The card shows what is published.', 'bettershield' ) );
							setDraft( null );

							return true;
						}
					);
				};

				/*
				 * What the text fields do when focus leaves them. A blur is
				 * not an edit — focus leaves a field somebody tabbed through
				 * exactly as it leaves one they changed — and a save that
				 * changes nothing still costs a request, an undo record and a
				 * line in the activity log. So the row sends only what
				 * actually differs from what is published, and otherwise drops
				 * the draft and goes back to showing that.
				 */
				const saveEdits = () => {
					/*
					 * Focus left for the switch: its press saves these edits
					 * with it. Saved here, the save disabled the switch before
					 * the press landed, and the press was lost (#2488).
					 */
					if ( toSwitch.current ) {
						toSwitch.current = false;

						return;
					}

					if ( editedFields( data, value, [ 'contact', 'policy' ] ).length ) {
						save( {} );

						return;
					}

					setDraft( null );
				};

				// Said while it is being typed rather than on the blur that
				// saves it. This file is published for finders, and a contact
				// nobody can reach is worse than none.
				const contactIssue = contactProblem( value.contact || '' );
				const policyIssue = urlProblem( value.policy || '' );
				const lapsing = value.enabled && value.expires;
				const left = lapsing ? new Date( value.expires ).getTime() - Date.now() : 0;
				// A date saved before the year's limit (#2250): RFC 9116 asks
				// for less than a year, so it is said, and Renew brings it in.
				const distant = left > 366 * 864e5;

				return (
					<SettingRow
						focusKey="security_contact"
						title={ __( 'Security contact (security.txt)', 'bettershield' ) }
						about={ __( 'Publishes a small public file that tells anyone who finds a security problem on your site how to contact you.', 'bettershield' ) }
						control={
							<span
								className="bs-ds-contact__switch"
								onPointerDownCapture={ () => {
									toSwitch.current = true;
								} }
								onMouseDownCapture={ () => {
									toSwitch.current = true;
								} }
							>
								<Switch
									label={ __( 'Publish a security contact', 'bettershield' ) }
									checked={ value.enabled }
									disabled={ saving }
									onChange={ ( enabled ) => {
										toSwitch.current = false;
										save( { enabled } );
									} }
								/>
							</span>
						}
						topics={ [
							{
								key: 'served',
								label: __( 'How this works', 'bettershield' ),
								lead: __( 'BetterShield creates the file when someone asks for it. Nothing is saved to your server.', 'bettershield' ),
								points: [
									__( 'Turning it off removes it completely.', 'bettershield' ),
									__( 'It works on any hosting.', 'bettershield' ),
									__( 'It always shows what you set here.', 'bettershield' ),
								],
							},
							{
								key: 'expires',
								label: __( 'Why it expires', 'bettershield' ),
								lead: __( 'The standard requires one, so people know the contact is current.', 'bettershield' ),
								text: __(
									'An outdated contact leaves reporters with no way to reach you.',
									'bettershield'
								),
								note: { tone: 'info', text: __( 'You’ll get a reminder in Findings a month before it expires.', 'bettershield' ) },
							},
						] }
					>
						<div className="bs-ds-contact__fields">
							<Field
								label={ __( 'Contact', 'bettershield' ) }
								help={ contactIssue ? undefined : __( 'An email address, or an https page with a form.', 'bettershield' ) }
								error={ contactIssue || '' }
								value={ value.contact || '' }
								disabled={ saving }
								onChange={ ( contact ) => setDraft( { ...value, contact } ) }
								onBlur={ () => ( contactProblem( value.contact || '' ) ? null : saveEdits() ) }
							/>
							<Field
								label={ __( 'Disclosure policy page (optional)', 'bettershield' ) }
								help={ policyIssue ? undefined : __( 'An https page saying how you handle reports.', 'bettershield' ) }
								error={ policyIssue || '' }
								value={ value.policy || '' }
								disabled={ saving }
								onChange={ ( policy ) => setDraft( { ...value, policy } ) }
								onBlur={ () => ( urlProblem( value.policy || '' ) ? null : saveEdits() ) }
							/>
						</div>

						{ error ? <Alert layout="default" tone="error" desc={ error } /> : null }

						{ lapsing ? (
							<p className="bs-ds-gen__note">
								{ sprintf(
									left <= 0
										? /* translators: %s: a date. */
										  __( 'Published, but its expiry date, %s, has passed.', 'bettershield' )
										: distant
										? /* translators: %s: a date. */
										  __( 'Published until %s, more than a year away. The standard asks that this contact be checked at least yearly.', 'bettershield' )
										: /* translators: %s: a date. */
										  __( 'Published. Expires %s.', 'bettershield' ),
									formatTime( value.expires )
								) }{ ' ' }
								{ /* The way to move the date on, offered when the
								     audit starts asking for it: within a month of
								     the date, or past it. And to bring in one
								     more than a year out. */ }
								{ left <= 30 * 864e5 || distant ? (
									<Button type="linksub" size="sm" disabled={ saving } onClick={ () => save( { renew: true } ) }>
										{ __( 'Renew for a Year', 'bettershield' ) }
									</Button>
								) : null }
							</p>
						) : null }

						{ /*
						   Whether the address the standard reserves can be
						   answered here at all. The server derives it from where
						   WordPress lives, so it is a fact about the install
						   rather than anything set on this row — and it is shown
						   whichever way the switch is set, because it is part of
						   deciding.
						*/ }
						{ value.root_note ? <p className="bs-ds-gen__note">{ value.root_note }</p> : null }
					</SettingRow>
				);
			} }
		</RowResource>
	);
}

/**
 * Where the agent read opt-in now lives.
 *
 * The switch itself moved to Agents, as step one of Connect and again on
 * Permissions, with one option behind both. What stays here is the sentence
 * somebody looking for it on this screen needs — its neighbors are the other
 * things that leave this site, and a reader scanning them should not
 * conclude the setting was removed.
 *
 * Exported so it can be mounted on its own.
 */
export function AgentAbilities() {
	return (
		<SettingRow
			title={ __( 'AI assistant access', 'bettershield' ) }
			about={ __(
				'Let AI assistants (such as Claude or ChatGPT) read this site’s security status and, if you allow it, apply fixes you can undo.',
				'bettershield'
			) }
			tip={ __( 'An assistant sees only what the WordPress account it uses can see.', 'bettershield' ) }
			control={
				<Button type="secondary" size="sm" trailing="arrow-right" href={ tabUrl( 'bettershield-agents', 'connect' ) }>
					{ __( 'Open Agents', 'bettershield' ) }
				</Button>
			}
		/>
	);
}

/**
 * What asking for a plain-language explanation has cost this month.
 *
 * The asking happens on the report; the running total belongs here, because
 * the activity log keeps each ask for days rather than months and cannot
 * answer "what has this cost me". Two numbers rather than one: the second is
 * the answer to the first — an explanation is kept until that finding's
 * evidence changes, so most readings spend nothing.
 *
 * Exported so it can be mounted on its own.
 */
export function Explanations() {
	const { resource, reload } = useResource( 'aiStatus' );

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the explanations’ figures…', 'bettershield' ) } /> }>
			{ ( data ) => {
				const usage = data.usage || { calls: 0, cached: 0 };
				// What one account may ask for in an hour: a number, or null
				// where nothing caps it.
				const budget = data.budget;
				let cap = null;

				if ( budget ) {
					cap = budget.per_hour
						? sprintf(
								/* translators: %d: how many explanations one account may ask for in an hour. */
								__( 'Up to %d an hour for each account.', 'bettershield' ),
								budget.per_hour
						  )
						: __( 'No hourly limit on this site.', 'bettershield' );
				}

				return (
					<SettingRow
						title={ __( 'Plain-language explanations', 'bettershield' ) }
						about={
							data.available
								? __( 'Get plain-language explanations of findings and incidents from the AI service connected to WordPress. Only the details of the one being explained are sent.', 'bettershield' )
								: data.notice
						}
						// The screen the notice names, for somebody who may open it.
						control={
							! data.available && data.connectors_url ? (
								<Button type="secondary" size="sm" trailing="arrow-right" href={ data.connectors_url }>
									{ __( 'Open Connectors', 'bettershield' ) }
								</Button>
							) : null
						}
						meta={
							data.available ? (
								<>
									{ sprintf(
										/* translators: 1: how many explanations were asked of the provider, 2: how many were answered from an earlier ask. */
										__( 'Explanations this month: %1$d new, %2$d reused from earlier answers (no cost).', 'bettershield' ),
										usage.calls,
										usage.cached
									) }
									{ cap ? ` ${ cap }` : null }
								</>
							) : null
						}
						topics={ [
							{
								key: 'how',
								label: __( 'How this works', 'bettershield' ),
								text: __(
									'Each question goes to the AI provider connected to WordPress, with only its recorded evidence.',
									'bettershield'
								),
								points: [
									__( 'One finding.', 'bettershield' ),
									__( 'Up to twelve findings (Explain My Audit).', 'bettershield' ),
									__( 'An incident, with account names and file paths hidden.', 'bettershield' ),
									__( 'Answers are saved and reused until the finding changes.', 'bettershield' ),
									__( 'No key is stored or asked for.', 'bettershield' ),
								],
							},
						] }
					/>
				);
			} }
		</RowResource>
	);
}

/**
 * Whether the last usage report landed. A report that did not says why, so a
 * site that has said yes is never left believing it is sharing when it is not.
 */
function UsageLastReport( { data } ) {
	if ( data.failure ) {
		return (
			<p className="bs-ds-gen__note" role="status">
				{ data.failure } { __( 'BetterShield tries again on its daily run.', 'bettershield' ) }
			</p>
		);
	}

	return (
		<p className="bs-ds-gen__note" role="status">
			{ data.last_sent
				? sprintf(
						/* translators: %s: when, e.g. "today, 5:14 PM". */
						__( 'Last report sent %s.', 'bettershield' ),
						whenPhrase( data.last_sent )
				  )
				: __( 'The first report is on its way.', 'bettershield' ) }
		</p>
	);
}

/**
 * Usage data — the lasting home of the answer the Quick Setup asks once.
 *
 * Off unless the owner said yes, and switching it off stops the report at
 * once. The list of what is sent is read from the server, which builds the
 * report from the same list, so what the owner is shown cannot drift from
 * what leaves the site.
 */
function UsageSharing() {
	const { resource, reload } = useResource( 'usage' );
	const { answerUsage, busy } = useStore();
	const saving = busy === 'usage';

	/*
	 * On a network the report describes the whole network, so the answer is
	 * the network's and a super admin's to give. A site administrator sees
	 * it, and the switch is held.
	 */
	const held = ( data ) => false === data.can_answer;

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the usage data switch…', 'bettershield' ) } toggle /> }>
			{ ( data ) => (
				<SettingRow
					title={ __( 'Share usage data', 'bettershield' ) }
					about={ __(
						'Sends WPDeveloper a short report, at most once a day, with your site address and admin email. No visitor data or security events.',
						'bettershield'
					) }
					tip={ __( 'It shows which plugins and versions to test BetterShield with.', 'bettershield' ) }
					control={ <Saved forKey="usage" /> }
					toggle={ {
						checked: !! data.allowed,
						disabled: saving || held( data ),
						onChange: ( allowed ) => answerUsage( allowed ),
					} }
					topics={ [
						{
							key: 'collected',
							label: __( 'What we collect', 'bettershield' ),
							points: data.fields || [],
						},
					] }
				>
					{ ! data.configured ? (
						<p className="bs-ds-gen__note">
							{ __( 'This copy of BetterShield can’t send usage reports, so this switch has no effect.', 'bettershield' ) }
						</p>
					) : null }
					{ held( data ) ? (
						<p className="bs-ds-gen__note">
							{ __( 'On a network, a network administrator decides this for every site and reads the report.', 'bettershield' ) }
						</p>
					) : null }
					{ data.configured && data.allowed ? <UsageLastReport data={ data } /> : null }
					{ /* The report itself, for whoever may answer for it. */ }
					{ held( data ) ? null : <UsageReport /> }
				</SettingRow>
			) }
		</RowResource>
	);
}

export function ReportProblem() {
	const { resources, load } = useStore();
	const resource = resources.diagnostics;
	const [ copied, setCopied ] = useState( false );
	const [ copyFailed, setCopyFailed ] = useState( false );
	const ready = resource.status === 'ready' && resource.data;

	const copy = () => {
		if ( ! resource.data ) {
			return;
		}
		setCopyFailed( false );
		copyToClipboard( resource.data.text ).then(
			() => {
				setCopied( true );
				window.setTimeout( () => setCopied( false ), 2000 );
			},
			// The report is for the broken and the insecure site — the one
			// where the clipboard may refuse. It stays selectable by hand.
			() => setCopyFailed( true )
		);
	};

	return (
		<SettingRow
			title={ __( 'Report a problem', 'bettershield' ) }
			about={ __(
				'Copy this setup report into a support request. Nothing is sent.',
				'bettershield'
			) }
			tip={ __( 'It lists versions, active fixes, safe-mode state and recent plugin errors.', 'bettershield' ) }
			control={
				ready ? (
					<>
						<Button type="secondary" size="sm" icon="copy" iconTone="2" onClick={ copy }>
							{ copied ? __( 'Copied', 'bettershield' ) : __( 'Copy the Report', 'bettershield' ) }
						</Button>
						<Button type="ghost" size="sm" onClick={ () => load( 'diagnostics', { force: true } ) }>
							{ __( 'Refresh', 'bettershield' ) }
						</Button>
					</>
				) : (
					<Button
						type="secondary"
						size="sm"
						isBusy={ resource.status === 'loading' }
						disabled={ resource.status === 'loading' }
						onClick={ () => load( 'diagnostics', { force: true } ) }
					>
						{ resource.status === 'error' ? __( 'Try Again', 'bettershield' ) : __( 'Prepare the Report', 'bettershield' ) }
					</Button>
				)
			}
			topics={ [
				{
					key: 'left-out',
					label: __( 'What is left out', 'bettershield' ),
					lead: __( 'Anything that identifies your site or anyone on it.', 'bettershield' ),
					tags: [
						__( 'No address', 'bettershield' ),
						__( 'No email', 'bettershield' ),
						__( 'No usernames', 'bettershield' ),
						__( 'No IP addresses', 'bettershield' ),
						__( 'No keys', 'bettershield' ),
					],
					steps: [
						__( 'Read it.', 'bettershield' ),
						__( 'Copy it.', 'bettershield' ),
						__( 'Paste it into a support thread.', 'bettershield' ),
					],
				},
			] }
			output={
				ready ? (
					<div className="bs-ds-report__out">
						{ copyFailed ? (
							<p className="bs-ds-gen__note">
								{ __( 'Copying failed. Select the report below and copy it by hand.', 'bettershield' ) }
							</p>
						) : null }
						<textarea className="bs-ds-report__text" readOnly rows={ 12 } value={ resource.data.text } aria-label={ __( 'Diagnostic report', 'bettershield' ) } />
					</div>
				) : null
			}
		>
			{ /* Left out where the owner labeled the chrome and asked for this
			     plugin's links to go; the report is still theirs to send. */ }
			{ helpLinks ? (
				<p className="bs-ds-gen__note">
					<Button
						type="ghost"
						size="sm"
						className="bs-ds-topics__ask bs-ds-topics__lone"
						trailing="arrow-out"
						trailingTone="3"
						href={ resource.data ? resource.data.support_url : 'https://wordpress.org/support/plugin/bettershield/' }
						target="_blank"
						rel="noopener noreferrer"
					>
						{ __( 'Support forum', 'bettershield' ) }
					</Button>
				</p>
			) : null }
		</SettingRow>
	);
}

/* ---------- this installation ---------- */

/**
 * Recording what agents do — the other half of the agent question, and a
 * separate decision from whether an agent may read this site at all. A site
 * that refuses every agent still wants the record of what tried.
 *
 * On by default, and the row says why rather than leaving somebody to guess:
 * a record nobody switched on is the only kind that is missing on the day it
 * matters.
 */
function AgentRecording() {
	const { resource, reload } = useResource( 'abilities' );

	/*
	 * Said and switched in one place, Agents › Permissions, beside the rest
	 * of what agents may do; this row says where it stands and goes there.
	 * The same paragraph stood on both screens.
	 */
	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the recording switch…', 'bettershield' ) } /> }>
			{ ( data ) => (
				<SettingRow
					title={ __( 'Recording agent activity', 'bettershield' ) }
					badge={ data.capture_available ? <Badge tone={ data.capture_enabled ? 'brand' : 'neutral' }>{ data.capture_enabled ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }</Badge> : null }
					about={
						data.capture_available
							? // The screen is Agent activity; "Activity › Agents" named one that
							  // is not there (#2191). A link where the reader can open it.
							  createInterpolateElement( __( 'Logs everything AI assistants do on this site, in <a>Activity › Agent activity</a>.', 'bettershield' ), {
									a: tabUrl( 'bettershield-activity', 'agents' ) ? <a href={ tabUrl( 'bettershield-activity', 'agents' ) } /> : <span />,
							  } )
							: sprintf(
									/* translators: %s: a WordPress version number. */
									__( 'Requires WordPress %s.', 'bettershield' ),
									data.capture_requires
							  )
					}
					control={
						data.capture_available ? (
							<Button type="secondary" size="sm" trailing="arrow-right" href={ tabUrl( 'bettershield-agents', 'permissions' ) }>
								{ __( 'Change This in Agents', 'bettershield' ) }
							</Button>
						) : null
					}
				/>
			) }
		</RowResource>
	);
}

/**
 * BetterShield Hub, as a row: whether this site is connected, and the way to
 * the Hub screen, which says what connecting sends and turns on before
 * anything is. The whole Hub card stood here as well, word for word.
 */
function HubRow() {
	// null while it is being read, `false` when the read failed, else the answer.
	const [ hub, setHub ] = useState( null );
	const [ attempt, setAttempt ] = useState( 0 );

	useEffect( () => {
		let live = true;

		setHub( null );

		/*
		 * A failed read is said as one. Stored as an empty answer it read as
		 * "not connected", and the row said nothing is sent to the hub on a
		 * site that may be sending; this plugin does not guess at what leaves
		 * the site.
		 */
		apiFetch( { path: '/bettershield/v1/hub' } ).then(
			( data ) => live && setHub( data || {} ),
			() => live && setHub( false )
		);

		return () => {
			live = false;
		};
	}, [ attempt ] );

	if ( false === hub ) {
		return (
			<SettingsCard icon="link" title={ __( 'BetterShield Hub', 'bettershield' ) }>
				<div className="bs-ds-setting">
					<ErrorState title={ __( 'Whether this site is connected could not be read.', 'bettershield' ) } onRetry={ () => setAttempt( ( n ) => n + 1 ) } />
				</div>
			</SettingsCard>
		);
	}

	const connected = Boolean( hub && hub.connected );

	return (
		<SettingsCard icon="link" title={ __( 'BetterShield Hub', 'bettershield' ) }>
			<SettingRow
				title={ __( 'Connection', 'bettershield' ) }
				badge={ hub ? <Badge tone={ connected ? 'brand' : 'neutral' }>{ connected ? __( 'Connected', 'bettershield' ) : __( 'Not connected', 'bettershield' ) }</Badge> : null }
				about={
					// Nothing is said about what is sent until the answer is in.
					null === hub
						? null
						: connected
						? __( 'This site shares its security score and findings with BetterShield Hub.', 'bettershield' )
						: __( 'Nothing is sent to the hub until you connect.', 'bettershield' )
				}
				control={
					<Button type="secondary" size="sm" trailing="arrow-right" href={ tabUrl( 'bettershield-hub' ) }>
						{ connected || null === hub ? __( 'Open Hub', 'bettershield' ) : __( 'Connect', 'bettershield' ) }
					</Button>
				}
			/>
		</SettingsCard>
	);
}

/**
 * The Quick Setup, once it is finished. It leaves the menu then and its URL
 * sends the owner to the dashboard, so this is the way back to it: a re-run
 * opens on the site as it is and changes only what the owner changes. It
 * never asks the usage question again, so the row does not offer it.
 */
function RunSetupAgain( { url } ) {
	const { reopenSetup, busy } = useStore();

	if ( ! url ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Quick Setup', 'bettershield' ) }
			about={ __(
				'Go through setup again: the account recovery link, two-factor sign-in and recommended fixes.',
				'bettershield'
			) }
			tip={ __( 'It opens with your current settings and changes only what you change. Usage sharing is set under Privacy & sharing.', 'bettershield' ) }
			control={
				<Button type="secondary" size="sm" isBusy={ 'setup-reopen' === busy } disabled={ null !== busy } onClick={ reopenSetup }>
					{ __( 'Run Quick Setup Again', 'bettershield' ) }
				</Button>
			}
		/>
	);
}

/**
 * Whether this plugin is in the reader's language. On a site in another
 * language WordPress's own menus arrive translated while every string of this
 * plugin stays English until a translation for it exists, and a half-English
 * screen reads as a gap about to be filled rather than the state it is.
 *
 * Said only to a reader who works in a language other than English; the
 * screens and what the server sends (email, notices) are translated by
 * separate catalogs, so either can be there without the other.
 *
 * @param {Object}  props
 * @param {?Object} props.language The overview's language report, or null.
 */
export function LanguageRow( { language } ) {
	if ( ! language ) {
		return null;
	}

	const { screens, catalog, core } = language;
	// Named in the language itself only where the screens can show it so.
	const name = screens ? language.native || language.name : language.name;
	let badge = __( 'In English', 'bettershield' );
	let tone = 'neutral';
	let about;

	if ( screens && catalog ) {
		badge = __( 'Translated', 'bettershield' );
		tone = 'brand';
		about = sprintf(
			/* translators: %s: the reader's WordPress language, e.g. "Deutsch". */
			__( 'Screens and emails are in %s.', 'bettershield' ),
			name
		);
	} else if ( screens ) {
		badge = __( 'Partly translated', 'bettershield' );
		about = sprintf(
			/* translators: %s: the reader's WordPress language, e.g. "Deutsch". */
			__( 'Screens are in %s. Emails and server messages are still in English.', 'bettershield' ),
			name
		);
	} else if ( catalog ) {
		badge = __( 'Partly translated', 'bettershield' );
		about = sprintf(
			/* translators: %s: the reader's WordPress language, e.g. "German". */
			__( 'Emails and server messages are in %s. Screens are still in English.', 'bettershield' ),
			name
		);
	} else if ( core ) {
		about = sprintf(
			/* translators: %s: the reader's WordPress language, e.g. "German". */
			__( 'WordPress is in %s. BetterShield is still in English.', 'bettershield' ),
			name
		);
	} else {
		about = sprintf(
			/* translators: %s: the reader's WordPress language, e.g. "German". */
			__( 'Neither WordPress nor BetterShield is in %s yet.', 'bettershield' ),
			name
		);
	}

	return <SettingRow title={ __( 'Language', 'bettershield' ) } badge={ <Badge tone={ tone }>{ badge }</Badge> } about={ about } />;
}

/**
 * The gate on actions that remove protection.
 *
 * Off by default and stated as friction rather than sold as a feature: it is
 * a real cost on a real workflow, and an owner who has not asked for it
 * should not meet it after an update.
 */
export function ConfirmBeforeRemoving() {
	const { resource, reload } = useResource( 'sudo' );
	const { saveSudo, busy } = useStore();
	const saving = busy === 'sudo';

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the password confirmation setting…', 'bettershield' ) } toggle /> }>
			{ ( data ) => (
				<SettingRow
					title={ __( 'Password confirmation', 'bettershield' ) }
					about={ __(
						'Confirm your password before removing a protection. Once confirmed, you are not asked again for fifteen minutes.',
						'bettershield'
					) }
					control={
						<>
							<Saved forKey="sudo" />
							<Switch
								label={ __( 'Ask for my password before removing a protection', 'bettershield' ) }
								checked={ data.enabled }
								disabled={ saving }
								onChange={ ( enabled ) => saveSudo( enabled ) }
							/>
						</>
					}
					topics={ [
						{
							key: 'what',
							label: __( 'What it asks about', 'bettershield' ),
							lead: __( 'The actions that take a protection away.', 'bettershield' ),
							tags: [
								__( 'Undoing a security fix', 'bettershield' ),
								__( 'Importing a settings file', 'bettershield' ),
								__( 'Changing how signing in works', 'bettershield' ),
								__( 'Ending sessions', 'bettershield' ),
								__( 'Turning a protection off', 'bettershield' ),
							],
							note: { tone: 'info', text: __( 'You’re never asked when adding protection or just viewing.', 'bettershield' ) },
						},
						{
							key: 'locked-out',
							label: __( 'Lockout risk', 'bettershield' ),
							lead: __( 'None.', 'bettershield' ),
							points: [
								__( 'Safe mode turns it off, along with every other protection.', 'bettershield' ),
								__( 'Passkey-only accounts are never asked for a password.', 'bettershield' ),
							],
						},
					] }
				/>
			) }
		</RowResource>
	);
}

/**
 * A hardening row of an import plan, in words rather than codes: what it is,
 * what would happen, and why not where nothing would.
 *
 * @param {string} action The plan's action for the row.
 * @return {string} The action in words.
 */
function planWord( action ) {
	switch ( action ) {
		case 'apply':
			return __( 'will be applied', 'bettershield' );
		case 'revert':
			return __( 'will be undone', 'bettershield' );
		case 'reconfigure':
			return __( 'will change its settings', 'bettershield' );
		case 'keep':
			return __( 'already matches', 'bettershield' );
		case 'change':
			return __( 'will change', 'bettershield' );
		case 'unavailable':
			return __( 'is not available here', 'bettershield' );
		case 'invalid':
			// Read, but refused by a rule the note under it names (#2617).
			return __( 'can’t be used', 'bettershield' );
		case 'unknown':
			return __( 'isn’t in this version of BetterShield', 'bettershield' );
		default:
			return action;
	}
}

/**
 * @param {string} result What applying did to the row.
 * @return {string} The result in words.
 */
function resultWord( result ) {
	switch ( result ) {
		case 'applied':
			return __( 'applied', 'bettershield' );
		case 'reverted':
			return __( 'undone', 'bettershield' );
		case 'changed':
			return __( 'changed', 'bettershield' );
		case 'failed':
			return __( 'failed', 'bettershield' );
		case 'skipped':
			return __( 'left as it was', 'bettershield' );
		default:
			return result;
	}
}

function ImportPlan( { plan } ) {
	const rows = [
		...plan.hardening.map( ( row ) => ( {
			key: 'h:' + row.item,
			title: row.title,
			action: row.action,
			result: row.result,
			// The item's own reason it cannot apply (needs HTTPS, the main
			// site, the server's configuration), where it named one (#2235).
			label: 'unavailable' === row.action && ! row.result ? row.label || '' : '',
			// What happens to the item and what it warns of once on are two
			// facts, and a row can carry both. A change that failed made
			// nothing to warn about, so its refusal stands alone.
			note: [ row.note, 'failed' === row.result ? null : row.conflict_warning ].filter( Boolean ).join( ' ' ) || null,
			quiet: row.action === 'keep',
		} ) ),
		...plan.settings.map( ( row ) => ( {
			key: 's:' + row.section,
			title: row.title,
			action: row.action,
			result: row.result,
			note: row.note || null,
			quiet: row.action === 'keep',
			// What would change, setting by setting: "will change" alone had
			// lockouts turned off and alerts muted approved unread.
			lines: 'change' === row.action ? changeLines( row.section, row.changes ) : [],
		} ) ),
	];

	return (
		<ul className="bs-ds-import">
			{ rows.map( ( row ) => (
				<li key={ row.key } className={ 'bs-ds-import__row' + ( row.quiet ? ' is-quiet' : '' ) }>
					<span className="bs-ds-import__title">{ row.title }</span>
					<span className="bs-ds-import__action">{ row.result ? resultWord( row.result ) : row.label || planWord( row.action ) }</span>
					{ row.lines && row.lines.length ? (
						<ul className="bs-ds-import__changes">
							{ row.lines.map( ( line ) => (
								<li key={ line.key } className={ line.weakens ? 'is-weaker' : undefined }>
									{ line.weakens ? (
										<>
											<Icon name="triangle-alert" size={ 12 } tone="warning" />
											<span className="screen-reader-text">{ __( 'Less protection:', 'bettershield' ) } </span>
										</>
									) : null }
									{ line.text }
								</li>
							) ) }
						</ul>
					) : null }
					{ row.note ? <span className="bs-ds-import__note">{ row.note }</span> : null }
				</li>
			) ) }
		</ul>
	);
}

/**
 * Whether nothing in a plan could be read: every row refused as unreadable or
 * unknown here. "Nothing to Change" then read as a file already applied (#2249).
 *
 * @param {Object} plan The import plan.
 * @return {boolean} Whether no row was read.
 */
function nothingRead( plan ) {
	return [ ...plan.hardening, ...plan.settings ].every( ( row ) => 'invalid' === row.action || 'unknown' === row.action );
}

/**
 * Settings another security plugin left on this site, offered for import.
 *
 * Each is read on the server into an ordinary settings document, so what
 * happens next is the file import's own preview and apply, with every change
 * shown first and undoable one at a time. What could not be carried is said
 * under the preview, with the reason for each. Absent when none are found.
 */
function OtherPlugins( { onPreview, disabled } ) {
	const [ sources, setSources ] = useState( [] );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/settings/import/sources' } ).then(
			( data ) => alive && setSources( Array.isArray( data.sources ) ? data.sources : [] ),
			() => {}
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( ! sources.length ) {
		return null;
	}

	return (
		<div className="bs-ds-sources">
			<p className="bs-ds-gen__note">
				{ __( 'We found settings from another security plugin on this site. Preview them before importing; that plugin isn’t changed.', 'bettershield' ) }
			</p>
			<ul className="bs-ds-sources__list">
				{ sources.map( ( source ) => (
					<li key={ source.key }>
						<span className="bs-ds-sources__name">
							{ source.name }
							<span className="bs-ds-sources__state">
								{ ' ' }
								{ source.active ? __( '(active)', 'bettershield' ) : __( '(not active)', 'bettershield' ) }
							</span>
						</span>
						<Button
							type="secondary"
							size="sm"
							disabled={ disabled || ! source.mapped }
							onClick={ ( event ) => onPreview( source, event.currentTarget ) }
							aria-label={
								source.mapped
									? sprintf(
											/* translators: %s: a plugin's name. */
											__( 'Preview Import from %s', 'bettershield' ),
											source.name
									  )
									: undefined
							}
						>
							{ source.mapped ? __( 'Preview Import', 'bettershield' ) : __( 'No Settings to Import', 'bettershield' ) }
						</Button>
					</li>
				) ) }
			</ul>
		</div>
	);
}

/** What a source had that was left out, and why each. */
function NotCarried( { source } ) {
	if ( ! source || ! source.unmapped.length ) {
		return null;
	}

	return (
		<div className="bs-ds-sources__left">
			<p className="bs-ds-gen__note">
				{ sprintf(
					/* translators: %s: a plugin's name. */
					__( 'Not imported from %s:', 'bettershield' ),
					source.name
				) }
			</p>
			<ul>
				{ source.unmapped.map( ( row ) => (
					<li key={ row.setting }>
						{ /* The setting, then why, apart: run together they read as one sentence (#2500). */ }
						<strong>
							{ sprintf(
								/* translators: %s: the name of a setting another plugin had. */
								__( '%s:', 'bettershield' ),
								row.setting
							) }
						</strong>{ ' ' }
						{ row.reason }
					</li>
				) ) }
			</ul>
		</div>
	);
}

export function SettingsTransfer() {
	const { exportSettings, importSettings, busy } = useStore();
	const [ document_, setDocument ] = useState( null );
	const [ plan, setPlan ] = useState( null );
	const [ fileError, setFileError ] = useState( null );
	// Whether that message is the only word on it. A file that fails in the
	// browser never reaches the store, so no page notice says so and the
	// message is announced here; the server's refusal is said by that notice,
	// and announcing it here too would say it twice (#2031).
	const [ fileErrorSaid, setFileErrorSaid ] = useState( false );
	// The other plugin a preview came from, when it did.
	const [ source, setSource ] = useState( null );
	// "Make these changes" is replaced by the receipt, which takes the
	// keyboard and is announced.
	const receipt = useRef( null );
	const afterApply = useMutationFocus( receipt );
	// Where the keyboard goes back to when a preview is put away: the button
	// that opened it. Another plugin's preview went back to "Import a
	// settings file…", a different control higher up (#2202).
	const importButton = useRef( null );
	const opener = useRef( null );

	// A preview could only be left by applying it or reloading (#1924).
	const cancelPlan = () => {
		setPlan( null );
		setDocument( null );
		setSource( null );
		( opener.current && opener.current.isConnected ? opener.current : importButton.current )?.focus();
		opener.current = null;
	};

	const previewSource = ( chosen, from = null ) => {
		opener.current = from;
		setFileError( null );
		setPlan( null );
		setSource( chosen );
		setDocument( chosen.document );
		importSettings( chosen.document, false, ( result ) => result && setPlan( result ) );
	};
	const planning = busy === 'settings-import-plan';
	const applying = busy === 'settings-import-apply';

	const onFile = ( event ) => {
		const input = event.target;
		const file = input.files && input.files[ 0 ];
		if ( ! file ) {
			return;
		}
		setFileError( null );
		setFileErrorSaid( false );
		setPlan( null );
		setSource( null );
		file.text()
			.then( ( text ) => {
				let parsed;
				try {
					parsed = JSON.parse( text );
				} catch ( e ) {
					setFileError( __( 'That isn’t a BetterShield settings file. Choose the .json file you exported.', 'bettershield' ) );
					setFileErrorSaid( true );
					return;
				}
				setDocument( parsed );
				importSettings(
					parsed,
					false,
					( result ) => setPlan( result ),
					// Refused by the server. Without this the only sign was
					// the page-top banner, a scroll away from the button that
					// caused it, on a screen where nothing else had changed —
					// so choosing a file appeared to do nothing at all.
					() =>
						setFileError(
							__(
								'That file was refused: it may be from a newer version, or not a settings file.',
								'bettershield'
							)
						)
				);
			} )
			.catch( () => {
				setFileError( __( 'That file could not be read.', 'bettershield' ) );
				setFileErrorSaid( true );
			} )
			.finally( () => {
				// Cleared so choosing the same file again — after fixing what
				// the plan refused, say — fires again; a file input stays silent
				// when its value does not change.
				input.value = '';
			} );
	};

	return (
		<SettingRow
			title={ __( 'Move settings between sites', 'bettershield' ) }
			about={ __(
				'Export to a file, then import it on another site. Nothing changes until you confirm.',
				'bettershield'
			) }
			control={
				<>
					<Button
						type="secondary"
						size="sm"
						icon="download"
						iconTone="2"
						onClick={ () =>
							exportSettings().then( ( doc ) => {
								if ( doc ) {
									download( 'bettershield-settings.json', JSON.stringify( doc, null, 2 ) + '\n', 'application/json' );
								}
							} )
						}
					>
						{ __( 'Export Settings', 'bettershield' ) }
					</Button>
					<FormFileUpload
						accept="application/json,.json"
						onChange={ onFile }
						render={ ( { openFileDialog } ) => (
							<Button ref={ importButton } type="secondary" size="sm" icon="upload" iconTone="2" onClick={ openFileDialog } isBusy={ planning } disabled={ planning || applying }>
								{ __( 'Import a Settings File…', 'bettershield' ) }
							</Button>
						) }
					/>
				</>
			}
			topics={ [
				{
					key: 'stays',
					label: __( 'What stays behind', 'bettershield' ),
					lead: __( 'These stay here and are not exported:', 'bettershield' ),
					tags: [
						__( 'Two-factor enrollments', 'bettershield' ),
						__( 'Sessions', 'bettershield' ),
						__( 'Who added each allowed or blocked address', 'bettershield' ),
						__( 'The recovery link', 'bettershield' ),
						__( 'Alert recipients', 'bettershield' ),
					],
					note: { tone: 'info', text: __( 'On the site you import into, the activity log shows you as the person who made the changes.', 'bettershield' ) },
				},
			] }
			output={
				<>
					<OtherPlugins onPreview={ previewSource } disabled={ planning || applying } />

					{ fileError && fileErrorSaid ? (
						<div role="alert">
							<Alert layout="default" tone="error" desc={ fileError } />
						</div>
					) : null }
					{ fileError && ! fileErrorSaid ? <Alert layout="default" tone="error" desc={ fileError } /> : null }

					{ plan ? (
						<div className="bs-ds-import__plan">
							<ImportPlan plan={ plan } />
							<NotCarried source={ source } />
							{ plan.applied ? (
								<Alert
									layout="default"
									tone="success"
									live
									alertRef={ receipt }
									desc={ sprintf(
										/* translators: 1: fixes applied, 2: fixes undone, 3: settings changed, 4: failures. Each is a bare count, so no plural is needed. */
										__( 'Import finished. Fixes turned on: %1$d. Fixes turned off: %2$d. Settings changed: %3$d. Failed: %4$d.', 'bettershield' ),
										plan.counts.applied,
										plan.counts.reverted,
										plan.counts.settings,
										plan.counts.failed
									) }
								/>
							) : (
								<div className="bs-ds-gen__actions">
									<Button
										type="primary"
										size="sm"
										isBusy={ applying }
										disabled={ applying || plan.changes === 0 }
										onClick={ () =>
											// The result is the only receipt of what was
											// changed, so it is passed in and still shown
											// after a password confirmation.
											importSettings( document_, true, afterApply( ( result ) => setPlan( result ) ) )
										}
									>
										{ plan.changes === 0 && nothingRead( plan )
											? __( 'Nothing in This File Could Be Read', 'bettershield' )
											: plan.changes === 0
											? __( 'Nothing to Change', 'bettershield' )
											: sprintf(
													/* translators: %d: number of changes. */
													_n( 'Make This Change', 'Make These %d Changes', plan.changes, 'bettershield' ),
													plan.changes
											  ) }
									</Button>
									<Button type="ghost" size="sm" disabled={ applying } onClick={ cancelPlan }>
										{ __( 'Cancel', 'bettershield' ) }
									</Button>
									<span className="bs-ds-gen__note">
										{ __( 'Nothing has changed yet. Each change can be undone later.', 'bettershield' ) }
									</span>
								</div>
							) }
						</div>
					) : null }
				</>
			}
		/>
	);
}

export function UninstallChoice() {
	const { resource, reload } = useResource( 'uninstall' );
	const { saveUninstallChoice, busy } = useStore();
	const saving = busy === 'uninstall';

	return (
		<RowResource resource={ resource } onRetry={ reload } loading={ <RowBone label={ __( 'Loading the uninstall choice…', 'bettershield' ) } /> }>
			{ ( data ) => {
				const choice = data.choice || 'keep';

				return (
					<SettingRow
						title={ __( 'When BetterShield is deleted', 'bettershield' ) }
						about={ __(
							'By default, deleting the plugin keeps its records for any reinstall.',
							'bettershield'
						) }
						control={ <Saved forKey="uninstall" /> }
						topics={ [
							{
								key: 'kept',
								label: __( 'Why they are kept', 'bettershield' ),
								lead: __( 'They are a record of what happened to your site.', 'bettershield' ),
								text: __( 'A deletion during a migration or troubleshooting should not erase it.', 'bettershield' ),
								points: [
									__( 'The activity log, findings and undo history are kept.', 'bettershield' ),
									__(
										'Quarantined files are never just deleted: “Keep a copy of the quarantined files” saves them first.',
										'bettershield'
									),
								],
							},
							{
								key: 'asked',
								label: __( 'Why you are asked now', 'bettershield' ),
								lead: __( 'By the time it is deleted, the plugin cannot ask.', 'bettershield' ),
								note: { tone: 'info', text: __( 'Whatever is set here is what deletion does.', 'bettershield' ) },
							},
						] }
					>
						{ /*
						   All three stay on screen rather than folding into a
						   dropdown: one of them destroys records and one of them
						   writes a file, and neither is a detail to hide behind a
						   single line of text.
						*/ }
						<Field
							kind="radio"
							label={ __( 'When BetterShield is deleted', 'bettershield' ) }
							// The row's title already says it on screen; the
							// group keeps its name for a screen reader.
							hideLabelFromVision
							value={ choice }
							disabled={ saving }
							options={ [
								{ label: __( 'Keep everything', 'bettershield' ), value: 'keep' },
								{ label: __( 'Remove all BetterShield data (activity log, findings, settings)', 'bettershield' ), value: 'remove' },
								{ label: __( 'Keep a copy of the quarantined files, then remove everything', 'bettershield' ), value: 'package' },
							] }
							onChange={ ( next ) => saveUninstallChoice( next ) }
						/>

						{ /*
						   Which of the two is true depends on the answer above:
						   keeping everything leaves the rules written into files
						   in place, and both answers that remove the records take
						   every applied item off first. Only a file outlives the
						   plugin: everything its code enforces stops when the code
						   is gone.
						*/ }
						{ 'keep' === choice ? (
							<Alert
								layout="default"
								tone="warning"
								title={ __( 'Fixes that write to your server files stay in place.', 'bettershield' ) }
								desc={ __(
									'Some fixes write rules to your server files, and those stay after deletion. Everything else stops, including two-factor. Undo any fixes you don’t want before deleting.',
									'bettershield'
								) }
							/>
						) : (
							<Alert
								layout="default"
								tone="warning"
								title={ __( 'Security fixes you applied are removed first.', 'bettershield' ) }
								desc={ __(
									'This also removes the rules BetterShield wrote to your server files. To keep them, choose Keep everything.',
									'bettershield'
								) }
							/>
						) }

						<ul className="bs-ds-gen__points">
							<li>
								{ __(
									'With the copy option, BetterShield saves one zip file in its sealed quarantine folder under uploads. Collect it from the server yourself, with your host’s file manager.',
									'bettershield'
								) }
							</li>
							<li>{ __( 'The zip file stays on your server and isn’t emailed or sent anywhere.', 'bettershield' ) }</li>
							<li>{ __( 'It contains your files that BetterShield replaced when restoring originals.', 'bettershield' ) }</li>
						</ul>

						<p className="bs-ds-gen__note">
							{ data.quarantined > 0
								? sprintf(
										/* translators: %d: how many files are currently in quarantine. */
										_n( '%d file is in quarantine now.', '%d files are in quarantine now.', data.quarantined, 'bettershield' ),
										data.quarantined
								  )
								: __( 'Nothing is in quarantine right now.', 'bettershield' ) }
						</p>
					</SettingRow>
				);
			} }
		</RowResource>
	);
}

/*
 * Settings changes that can still be put back.
 *
 * Every save on these screens records what was there before it, the same way
 * applying a hardening item does — so "every change is reversible" means
 * every change rather than most of them. Putting one back is an ordinary save
 * of the previous values: it passes the same validation, and a bound that has
 * since tightened refuses it rather than forcing a state the screen could not
 * produce.
 */

/** How many settings changes the history lists before folding the rest. */
const UNDO_SHOWN = 5;

/** The id of the older changes, while they are open. */
const UNDO_OLDER = 'bs-ds-undo-older';

/**
 * The history before it has been read: the latest few saves, each as its row
 * of what changed, who and when, and the way back.
 */
function UndoListBone() {
	return (
		<Skeleton label={ __( 'Loading the settings history…', 'bettershield' ) }>
			<div className="bs-ds-undo__bones">
				{ [ '9em', '7em', '10.5em', '8em', '6.5em' ].map( ( width ) => (
					<div key={ width } className="bs-ds-bonerow">
						<span className="bs-ds-bonerow__text">
							<Bone kind="title" w={ width } />
							<Bone w="14em" />
						</span>
						<Bone kind="control" w="88px" />
					</div>
				) ) }
			</div>
		</Skeleton>
	);
}

/**
 * What putting one change back did, said once it has: the area, and each
 * setting it moved back.
 *
 * @param {Object} change A row of the undo list.
 * @return {string} The confirmation.
 */
function putBackMessage( change ) {
	const back = putBackLines( change.surface, change.summary ).map( ( line ) => line.text );

	return back.length
		? sprintf(
				/* translators: 1: a settings area, e.g. "Alerts"; 2: what moved back, e.g. "Summary day: Tuesday to Monday". */
				__( 'Undid the %1$s change (%2$s).', 'bettershield' ),
				change.label,
				listOf( back )
		  )
		: sprintf(
				/* translators: %s: a settings area, e.g. "Alerts". */
				__( 'Undid the %s change.', 'bettershield' ),
				change.label
		  );
}

export function SettingsUndo() {
	const heading = useRef( null );
	const afterMutation = useMutationFocus( heading );
	const [ message, setMessage ] = useState( '' );
	const [ showOlder, setShowOlder ] = useState( false );
	const { resource, reload } = useResource( 'settingsUndo' );
	const { undoSettingsChange, loadOlderSettingsChanges, busy } = useStore();
	const titleId = `bs-ds-undo-${ useDomId() }`;

	const row = ( change ) => {
		const lines = changeLines( change.surface, change.summary );
		const working = isWorking( busy, change.token );

		return (
			<Row key={ change.token } className="bs-ds-undo__row">
				<Cell>
					<TitleMeta
						title={ change.label }
						meta={
							<>
								{ /* What this save changed, so six alerts saves are not
								     six rows that differ only by the second. */ }
								{ lines.length ? <span className="bs-ds-undo__change">{ listOf( lines.map( ( line ) => line.text ) ) }</span> : null }
								<span className="bs-ds-undo__when">
									{ change.by
										? sprintf(
												/* translators: 1: username, 2: date and time. */
												__( 'changed by %1$s, %2$s', 'bettershield' ),
												change.by,
												formatTime( change.at )
										  )
										: formatTime( change.at ) }
								</span>
							</>
						}
					/>
				</Cell>
				<Cell align="end">
					<Button
						type="secondary"
						size="sm"
						isBusy={ working }
						disabled={ working }
						// Which change, in the name: a column of them read
						// "Put it back" alike (#1928).
						aria-label={ sprintf(
							/* translators: 1: a settings area, e.g. "Alerts"; 2: what the change did, or when it was made. */
							__( 'Undo: %1$s, %2$s', 'bettershield' ),
							change.label,
							lines.length ? listOf( lines.map( ( line ) => line.text ) ) : formatTime( change.at )
						) }
						onClick={ () => {
							setMessage( '' );
							undoSettingsChange(
								change.token,
								afterMutation( () => setMessage( putBackMessage( change ) ) )
							);
						} }
					>
						{ __( 'Undo', 'bettershield' ) }
					</Button>
				</Cell>
			</Row>
		);
	};

	return (
		<Card className="bs-ds-undo" aria-labelledby={ titleId }>
			<CardHead
				icon="rotate-ccw"
				id={ titleId }
				title={
					<span ref={ heading } tabIndex={ -1 } className="bs-ds-undo__title">
						{ __( 'Settings history', 'bettershield' ) }
					</span>
				}
			/>
			<p className="bs-ds-undo__message" role="status">
				{ message }
			</p>
			<RowResource resource={ resource } onRetry={ reload } loading={ <UndoListBone /> }>
				{ ( data ) => {
					const changes = ( data && data.changes ) || [];

					if ( ! changes.length ) {
						return (
							<EmptyState>
								{ __(
									'No settings changes yet. Each time you save a setting, it’s listed here so you can undo it.',
									'bettershield'
								) }
							</EmptyState>
						);
					}

					/*
					 * The latest few, and the rest folded. The whole history on
					 * one card ran to twenty rows on an ordinary site, and the
					 * change somebody wants to put back is nearly always one of
					 * the last.
					 */
					const recent = changes.slice( 0, UNDO_SHOWN );
					const older = changes.slice( UNDO_SHOWN );
					/*
					 * The route reads a window of each area's latest changes and
					 * says how many there are in all, so the fold counts every
					 * older one, and the ones past the window are read on asking
					 * rather than left where nothing can put them back.
					 */
					const total = Number.isInteger( data.total ) ? Math.max( data.total, changes.length ) : changes.length;
					const olderCount = total - recent.length;
					const unread = total - changes.length;
					const reading = 'loading' === resource.status;

					return (
						<Table
							label={ __( 'Settings history', 'bettershield' ) }
							head={ false }
							columns={ [
								{ key: 'change', label: __( 'Change', 'bettershield' ) },
								{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
							] }
						>
							{ recent.map( row ) }
							{ olderCount && showOlder ? (
								<div role="rowgroup" id={ UNDO_OLDER } className="bs-ds-tbl__rows">
									{ older.map( row ) }
									{ /* One press reads twenty more of each area, so it names no count; at the widest window there is nothing more to read. */ }
									{ unread > 0 && ! data.widest ? (
										<WholeRow kind="foot">
											<Button type="secondary" size="sm" isBusy={ reading } disabled={ reading } onClick={ loadOlderSettingsChanges }>
												{ __( 'Load Older Changes', 'bettershield' ) }
											</Button>
										</WholeRow>
									) : null }
								</div>
							) : null }
							{ olderCount ? (
								<WholeRow kind="foot">
									<Button
										type="ghost"
										size="sm"
										trailing={ showOlder ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										aria-expanded={ showOlder }
										aria-controls={ showOlder ? UNDO_OLDER : undefined }
										onClick={ () => setShowOlder( ( open ) => ! open ) }
									>
										{ showOlder
											? __( 'Show Fewer', 'bettershield' )
											: sprintf(
													/* translators: %d: number of older settings changes. */
													_n( 'Show %d Older Change', 'Show %d Older Changes', olderCount, 'bettershield' ),
													olderCount
											  ) }
									</Button>
								</WholeRow>
							) : null }
						</Table>
					);
				} }
			</RowResource>
		</Card>
	);
}

/* ---------- records and connections ---------- */

/**
 * Facts rather than settings: nothing here is a control, and a reader
 * scanning the switches should be able to see where the switches stop. Two
 * answers to one question, on one card.
 *
 * @param {Object}  props
 * @param {boolean} props.ai Whether an AI provider is connected: the list of what leaves the site names it only then.
 */
function Records( { ai } ) {
	const facts = [
		__(
			'By default, only WordPress.org is contacted, to check official files.',
			'bettershield'
		),
		__( 'Those requests carry only installed versions, never your address, email, usernames or keys. No account is needed.', 'bettershield' ),
		__(
			'With “Leaked password check” on, a password being chosen is checked with Pwned Passwords.',
			'bettershield'
		),
		__( 'The password itself is never sent, only the first five characters of a scrambled copy of it.', 'bettershield' ),
		ai
			? __(
					'With an AI provider connected, each explanation you ask for (of a finding, Explain My Audit or an incident) sends it the recorded evidence.',
					'bettershield'
			  )
			: null,
		ai ? __( 'Web and email addresses are removed first.', 'bettershield' ) : null,
		__(
			'Fixes that edit server files change only the lines BetterShield added.',
			'bettershield'
		),
		__( 'Undo puts those lines back exactly as they were.', 'bettershield' ),
		__( 'IP addresses are shortened before storage, never kept in full.', 'bettershield' ),
		__( 'Passwords, tokens and file contents are never stored.', 'bettershield' ),
	].filter( Boolean );

	return (
		<SettingsCard
			icon="scroll-text"
			title={ __( 'What BetterShield records and contacts', 'bettershield' ) }
		>
			<SettingRow
				title={ __( 'What this version records', 'bettershield' ) }
				about={ __( 'Recording happens after each page is sent, so it doesn’t slow your pages down.', 'bettershield' ) }
				meta={ sprintf(
					/* translators: %d: number of days of history kept. */
					_n(
						'Records are kept for %d day. See them under Activity.',
						'Records are kept for %d days. See them under Activity.',
						limits.retentionDays,
						'bettershield'
					),
					limits.retentionDays
				) }
				topics={ [
					{
						key: 'how',
						label: __( 'What is recorded', 'bettershield' ),
						lead: __( 'Each record says who did it, what changed and when.', 'bettershield' ),
						points: [
							__( 'Sign-ins and failed sign-ins.', 'bettershield' ),
							__( 'User and role changes.', 'bettershield' ),
							__( 'Plugin and theme changes.', 'bettershield' ),
							__( 'Changes to key WordPress settings, like the site address or who can register.', 'bettershield' ),
							__( 'Every change this plugin makes itself.', 'bettershield' ),
						],
						note: {
							tone: 'info',
							text: __( 'On WooCommerce checkout, only security records are kept, like account creation.', 'bettershield' ),
						},
					},
				] }
			/>
			{ /* One line in sight; each fact opens on request. */ }
			<SettingRow
				title={ __( 'Data and connections', 'bettershield' ) }
				about={ __( 'Contacts only WordPress.org, unless you turn on a setting that sends more.', 'bettershield' ) }
				topics={ [
					{
						key: 'contacts',
						label: __( 'What this plugin contacts', 'bettershield' ),
						points: facts,
					},
				] }
			/>
		</SettingsCard>
	);
}

/**
 * The one quiet place this screen says a paid tier exists: at the foot of the
 * last tab, after the facts, and only when the server named an offer. The
 * words are the server's, so this bundle carries no promise of its own; what
 * it adds opens on request, so the card itself reads in a line.
 */
function Offer() {
	if ( ! offer ) {
		return null;
	}

	return (
		<SettingsCard
			icon="package"
			title={ offer.name }
			intro={ offer.summary || null }
			trailing={
				<Button type="secondary" size="sm" icon="arrow-out" iconTone="2" href={ offer.url } target="_blank" rel="noopener noreferrer">
					{ sprintf(
						/* translators: %s: the name BetterShield Ultra. */
						__( 'About %s', 'bettershield' ),
						offer.name
					) }
				</Button>
			}
		>
			{ offer.adds && offer.adds.length ? (
				<div className="bs-ds-setting">
					<Topics
						about={ offer.name }
						items={ [ { key: 'adds', label: __( 'What it adds', 'bettershield' ), points: offer.adds } ] }
					/>
				</div>
			) : null }
		</SettingsCard>
	);
}

/* ---------- the tab ---------- */

/** The four facts' names, shared by the strip and the tab's stand-in. */
function glanceLabels() {
	return {
		audit: __( 'Next audit', 'bettershield' ),
		password: __( 'Password policy', 'bettershield' ),
		contact: __( 'Security contact (security.txt)', 'bettershield' ),
		sudo: __( 'Password confirmation', 'bettershield' ),
	};
}

/** The groups of this tab, in the order they are drawn. */
function shelves() {
	return [
		{ key: 'checks', label: __( 'Checks & passwords', 'bettershield' ) },
		{ key: 'leaves', label: __( 'Privacy & sharing', 'bettershield' ) },
		{ key: 'install', label: __( 'Plugin data & tools', 'bettershield' ) },
		{ key: 'record', label: __( 'What BetterShield records', 'bettershield' ) },
	];
}

/**
 * The tab before the posture it reads has landed: the four facts, the row of
 * tabs, and the first group's card with its rows.
 */
export function SettingsBone() {
	return (
		<Skeleton label={ __( 'Loading the settings…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />
			<div className="bs-ds-gen__tabsbone">
				{ [ '9em', '9.5em', '7em', '10em' ].map( ( width ) => (
					<Bone key={ width } kind="title" w={ width } />
				) ) }
			</div>
			<CardBone rows={ [ '35%', '30%', '40%' ] } toggle />
		</Skeleton>
	);
}

/**
 * What the password tile says under its On or Off: the policy's length, and
 * whether leaked passwords are refused, which the breach check does on its
 * own whatever the policy says.
 *
 * @param {?Object} password The password policy, or null while it is read.
 * @param {boolean} breached Whether the leaked-password check is on.
 * @return {string} The line.
 */
function passwordDetail( password, breached ) {
	const privileged = password ? Number( password.min_length_privileged ) || 0 : 0;
	const single = password ? Number( password.min_length_single_factor ) || 0 : 0;

	/*
	 * And the longer bar for an account a password alone opens, which the
	 * tile left out (#2574): admins and editors only, unless the owner
	 * widened it to everyone.
	 */
	if ( password && password.enabled && privileged > password.min_length && single > privileged ) {
		if ( password.single_factor_everyone ) {
			return breached
				? sprintf(
						/* translators: 1: minimum characters for most accounts, 2: for admins and editors, 3: for any account without two-factor. */
						__( 'At least %1$d characters, %2$d for admins and editors, %3$d for anyone without two-factor, and leaked ones are refused', 'bettershield' ),
						password.min_length,
						privileged,
						single
				  )
				: sprintf(
						/* translators: 1: minimum characters for most accounts, 2: for admins and editors, 3: for any account without two-factor. */
						__( 'At least %1$d characters, %2$d for admins and editors, %3$d for anyone without two-factor', 'bettershield' ),
						password.min_length,
						privileged,
						single
				  );
		}

		return breached
			? sprintf(
					/* translators: 1: minimum characters for most accounts, 2: for admins and editors, 3: for admins and editors who skip two-factor. */
					__( 'At least %1$d characters, %2$d for admins and editors, %3$d if they skip two-factor, and leaked ones are refused', 'bettershield' ),
					password.min_length,
					privileged,
					single
			  )
			: sprintf(
					/* translators: 1: minimum characters for most accounts, 2: for admins and editors, 3: for admins and editors who skip two-factor. */
					__( 'At least %1$d characters, %2$d for admins and editors, %3$d if they skip two-factor', 'bettershield' ),
					password.min_length,
					privileged,
					single
			  );
	}

	/*
	 * The same bar for every role, and the longer one where a password
	 * alone opens the account: without this the tile said only the lower
	 * number whenever the owner set both role minimums alike.
	 */
	if ( password && password.enabled && privileged <= password.min_length && single > password.min_length ) {
		if ( password.single_factor_everyone ) {
			return breached
				? sprintf(
						/* translators: 1: minimum characters for any account, 2: for any account without two-factor. */
						__( 'At least %1$d characters, %2$d for anyone without two-factor, and leaked ones are refused', 'bettershield' ),
						password.min_length,
						single
				  )
				: sprintf(
						/* translators: 1: minimum characters for any account, 2: for any account without two-factor. */
						__( 'At least %1$d characters, %2$d for anyone without two-factor', 'bettershield' ),
						password.min_length,
						single
				  );
		}

		return breached
			? sprintf(
					/* translators: 1: minimum characters for any account, 2: for admins and editors without two-factor. */
					__( 'At least %1$d characters, %2$d for admins and editors without two-factor, and leaked ones are refused', 'bettershield' ),
					password.min_length,
					single
			  )
			: sprintf(
					/* translators: 1: minimum characters for any account, 2: for admins and editors without two-factor. */
					__( 'At least %1$d characters, %2$d for admins and editors without two-factor', 'bettershield' ),
					password.min_length,
					single
			  );
	}

	/*
	 * Both minimums where they differ: the lower one alone understated what
	 * the site asks of the accounts that can change it (#2198).
	 */
	if ( password && password.enabled && privileged > password.min_length ) {
		return breached
			? sprintf(
					/* translators: 1: minimum characters for most accounts, 2: minimum characters for admins and editors. */
					__( 'At least %1$d characters, %2$d for admins and editors, and leaked ones are refused', 'bettershield' ),
					password.min_length,
					privileged
			  )
			: sprintf(
					/* translators: 1: minimum characters for most accounts, 2: minimum characters for admins and editors. */
					__( 'At least %1$d characters, %2$d for admins and editors', 'bettershield' ),
					password.min_length,
					privileged
			  );
	}

	if ( password && password.enabled ) {
		return breached
			? sprintf(
					/* translators: %d: minimum number of characters. */
					_n(
						'At least %d character, and leaked ones are refused',
						'At least %d characters, and leaked ones are refused',
						password.min_length,
						'bettershield'
					),
					password.min_length
			  )
			: sprintf(
					/* translators: %d: minimum number of characters. */
					_n( 'At least %d character', 'At least %d characters', password.min_length, 'bettershield' ),
					password.min_length
			  );
	}

	return breached ? __( 'Leaked passwords are refused', 'bettershield' ) : __( 'Any password is accepted', 'bettershield' );
}

/**
 * The tab in four facts: when the site is next read, and the three settings
 * whose state is worth knowing without opening them. Read from the resources
 * the rows use, so the strip cannot disagree with them; a value not yet
 * loaded holds its place until it is.
 *
 * @param {Object} props
 * @param {Object} props.data The overview document.
 */
function AtAGlance( { data } ) {
	const labels = glanceLabels();
	const passwordRead = useResource( 'passwordPolicy' ).resource;
	const contactRead = useResource( 'securityTxt' ).resource;
	const sudoRead = useResource( 'sudo' ).resource;
	// The leaked-password check is a hardening item rather than part of the
	// policy, and refuses passwords whether the policy is on or not.
	const hardeningRead = useResource( 'hardening' ).resource;
	const breached = Boolean( ( hardeningRead.data?.items || [] ).find( ( item ) => 'breached_passwords' === item.id && item.active ) );
	const password = passwordRead.data;
	const contact = contactRead.data;
	const sudo = sudoRead.data;
	// A tile whose read is still out holds its place rather than a dash.
	const waiting = ( read ) => ! read.data && 'error' !== read.status;
	const onOff = ( known, on ) => {
		if ( ! known ) {
			return '—';
		}

		return on ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' );
	};

	let audit = __( 'Not scheduled', 'bettershield' );
	let auditTone = 'caution';

	if ( data.next_check_at ) {
		audit = whenPhrase( data.next_check_at );
		auditTone = isPast( data.next_check_at ) ? 'caution' : 'good';
	}

	const tiles = [
		{
			key: 'audit',
			icon: 'calendar-clock',
			label: labels.audit,
			value: audit,
			text: true,
			tone: auditTone,
			detail: __( 'Runs daily; changes nothing', 'bettershield' ),
		},
		{
			key: 'password',
			icon: 'key-round',
			label: labels.password,
			value: onOff( password, password && password.enabled ),
			tone: password && password.enabled ? 'good' : undefined,
			detail: passwordDetail( password, breached ),
			pending: waiting( passwordRead ),
		},
		{
			key: 'contact',
			icon: 'mail',
			label: labels.contact,
			value: contact ? ( contact.enabled ? __( 'Published', 'bettershield' ) : __( 'Off', 'bettershield' ) ) : '—',
			tone: contact && contact.enabled ? 'good' : undefined,
			detail: __( 'Where people report security problems', 'bettershield' ),
			pending: waiting( contactRead ),
		},
		{
			key: 'sudo',
			icon: 'lock',
			label: labels.sudo,
			value: onOff( sudo, sudo && sudo.enabled ),
			tone: sudo && sudo.enabled ? 'good' : undefined,
			// Said for the state it is in: off, nobody is asked at all.
			detail: sudo && sudo.enabled ? __( 'Asked again after 15 minutes', 'bettershield' ) : __( 'Not asked', 'bettershield' ),
			pending: waiting( sudoRead ),
		},
	];

	return <Stats label={ __( 'Settings at a glance', 'bettershield' ) } tiles={ tiles } />;
}

/**
 * Opens the group that holds a setting a link names (`?focus=`): the
 * Security contact sits on Privacy & sharing, and its finding's link opened
 * the tab on Checks & passwords with the setting hidden and nothing focused.
 * Listened for from the commit that draws the groups, before the link's
 * search for the setting can ask.
 *
 * @param {Object}   props
 * @param {Function} props.onShelf Opens a group, by its key.
 */
function OpenOnLink( { onShelf } ) {
	useLayoutEffect( () => {
		const open = ( event ) => {
			const panel = event.target && event.target.closest ? event.target.closest( '[data-bs-shelf]' ) : null;
			const key = panel ? panel.getAttribute( 'data-bs-shelf' ) : '';

			if ( shelves().some( ( shelf ) => shelf.key === key ) ) {
				onShelf( key );
			}
		};

		document.addEventListener( REVEAL, open );

		return () => document.removeEventListener( REVEAL, open );
	}, [ onShelf ] );

	return null;
}

export default function General() {
	const { resource, reload } = useResource( 'overview' );
	// Whether an AI provider is connected: the list of what leaves the site
	// names it only then. The explanations row reads the same resource.
	const { resource: ai } = useResource( 'aiStatus' );
	// Which group is open, kept in the address (none for the first), so a
	// reload, Back or a copied link reopens it rather than the first group.
	const [ shelf, setShelf ] = useState( () => {
		const linked = linkedGroup();
		return shelves().some( ( { key } ) => key === linked ) ? linked : 'checks';
	} );
	const chooseShelf = ( next ) => {
		setShelf( next );
		writeNarrowing( { group: 'checks' === next ? '' : next } );
	};

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <SettingsBone /> }>
			{ ( data ) => {
				/*
				 * Grouped rather than a run of a dozen settings: what the site
				 * checks, what leaves it, what belongs to this copy of the
				 * plugin, and what it records are four different questions,
				 * and a reader looking for one of them should not have to
				 * read the other three to find out. Every group stays
				 * mounted, as it did on one long page, so a draft in one is
				 * still there after a look at another.
				 */
				const panels = {
					checks: (
						<SettingsCard
							icon="list-checks"
							title={ __( 'Checks & passwords', 'bettershield' ) }
							intro={ __( 'Password rules and the automatic checks BetterShield runs.', 'bettershield' ) }
						>
							<PasswordPolicy />
							<ScheduledAudits data={ data } />
							<VulnerabilityChecks />
						</SettingsCard>
					),
					leaves: (
						<>
							<SettingsCard
								icon="send"
								title={ __( 'Privacy & sharing', 'bettershield' ) }
								intro={ __( 'Nothing here is sent until you turn it on.', 'bettershield' ) }
							>
								<SecurityContact />
								<AgentAbilities />
								<Explanations />
								<UsageSharing />
								<ReportProblem />
							</SettingsCard>
							<HubRow />
						</>
					),
					install: (
						<>
							<SettingsCard
								icon="hard-drive"
								title={ __( 'Plugin data & tools', 'bettershield' ) }
								intro={ __(
									'Import and export settings, password confirmation, settings history and what happens if you delete the plugin.',
									'bettershield'
								) }
							>
								{ /* A record kept here and sent nowhere, on until it is
								     turned off: not one of the things that leave. */ }
								<AgentRecording />
								<RunSetupAgain url={ data.onboarding?.rerun } />
								<LanguageRow language={ data.language } />
								<ConfirmBeforeRemoving />
								<SettingsTransfer />
								<UninstallChoice />
							</SettingsCard>
							<SettingsUndo />
						</>
					),
					record: (
						<>
							<Records ai={ Boolean( ai.data?.available ) } />
							<Offer />
						</>
					),
				};

				return (
					<>
						<OpenOnLink onShelf={ setShelf } />
						<AtAGlance data={ data } />
						{ /* As many tabs as fit, the rest in a select, as Activity's
						     row does: on a phone the row was cut mid-word with
						     its last tab off-screen and no cue (#1935). */ }
						<FitTabs
							id={ TABS_ID }
							label={ __( 'Settings sections', 'bettershield' ) }
							moreLabel={ __( 'Settings sections', 'bettershield' ) }
							optionLabel={ ( tab ) => tab.label }
							tabs={ shelves() }
							selected={ shelf }
							onSelect={ chooseShelf }
						/>
						{ shelves().map( ( { key } ) => (
							<div
								key={ key }
								className="bs-ds-gen__panel"
								data-bs-shelf={ key }
								hidden={ key !== shelf }
								{ ...( key === shelf ? panelProps( TABS_ID, shelf ) : {} ) }
							>
								{ panels[ key ] }
							</div>
						) ) }
					</>
				);
			} }
		</Resource>
	);
}
