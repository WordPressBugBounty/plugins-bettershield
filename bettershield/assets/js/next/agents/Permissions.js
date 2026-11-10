/**
 * Agents › Permissions: the switches, and the facts, stated once.
 *
 * For the person who sets this up and leaves. Every switch here is the same
 * control as its step on Connect and the same option behind it; what is extra
 * on this tab is what nobody sets and everybody eventually asks about: what
 * an agent can never reach, and how often it may act.
 *
 * The agent strip, then three cards of rows. The longer explanations open
 * under the row they explain.
 */

import './Permissions.css';

import { useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { neverDone } from '../../agents/phrases';
import { tabUrl } from '../../nav';
import { isWorking, useResource, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import { SectionHead } from '../ui/Card';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { CardBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { Resource } from '../ui/States';
import Topics from '../ui/Topics';
import AgentStrip, { AgentStripBone } from './AgentStrip';

/**
 * The two opt-ins, and the capability that carries the second.
 *
 * One card because they are read as a pair: the write switch depends on the
 * read switch, and a reader should not answer the second without the first.
 */
function Opting( { surface } ) {
	const { resource, reload } = useResource( 'abilities' );
	const { saveAbilities, saveWriteAccess, busy } = useStore();
	const heading = useRef( null );
	const afterSave = useMutationFocus( heading );
	const [ write, setWrite ] = useState( () => ( {
		enabled: !! surface.write_enabled,
		capability_granted: !! surface.capability_granted,
	} ) );
	const [ announced, setAnnounced ] = useState( null );
	const savingRead = isWorking( busy, 'abilities' );
	const savingWrite = isWorking( busy, 'agents-write-access' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={
				<Skeleton label={ __( 'Loading what agents may do…', 'bettershield' ) }>
					<CardBone rows={ [ '50%', '65%', '45%' ] } toggle />
				</Skeleton>
			}>
			{ ( data ) => {
				const reads = !! data.enabled;

				return (
					<SettingsCard
						icon="bot"
						title={
							<span ref={ heading } tabIndex={ -1 } className="bs-ds-perms__title">
								{ __( 'What agents may do here', 'bettershield' ) }
							</span>
						}
						intro={ __(
							'Allow viewing first, then fixes. Both are off by default.',
							'bettershield'
						) }
					>
						{ data.available ? (
							<>
								<SettingRow
									title={ __( 'Let AI assistants see security info', 'bettershield' ) }
									about={ __(
										'When off, AI assistants can’t see any BetterShield information. Other plugins’ settings are separate.',
										'bettershield'
									) }
									control={ <Saved forKey="abilities" /> }
									toggle={ {
										checked: reads,
										disabled: savingRead,
										onChange: ( enabled ) =>
											saveAbilities( enabled, ( answer ) => {
												// Reading off takes changes, and the permission that
												// carries them, with it in the same act. Passed in
												// rather than chained on, so a confirmed password
												// retry still runs it.
												if ( answer && ! answer.enabled ) {
													setWrite( { enabled: false, capability_granted: false } );
												}
											} ),
									} }
								/>
								<SettingRow
									title={ __( 'Let AI assistants fix things', 'bettershield' ) }
									about={
										/* What is true now, not what the switch would do (#2611). */
										! reads
											? __( 'Turn on “Let AI assistants see security info” first.', 'bettershield' )
											: write.enabled
											? __( 'Assistants can make fixes. Turning this off stops them; to allow fixes again later, turn it on and reconnect the assistant.', 'bettershield' )
											: __( 'Assistants can’t make fixes. They can still read security info. To allow fixes, turn this on and reconnect the assistant.', 'bettershield' )
									}
									tip={ __( 'Fixes that can be undone apply right away. Sign-in changes and anything else risky wait for your OK.', 'bettershield' ) }
									toggle={ {
										checked: !! write.enabled,
										disabled: savingWrite || ! reads,
										onChange: ( enabled ) =>
											saveWriteAccess(
												enabled,
												afterSave( ( answer ) => {
													setWrite( { enabled: !! answer.enabled, capability_granted: !! answer.capability_granted } );
													setAnnounced( !! answer.enabled );
												} )
											),
									} }
								>
									{ null === announced ? null : (
										<div role="status">
											<Alert
												layout="default"
												tone="success"
												desc={
													announced
														? __(
																'Saved. Assistants ask in the conversation before each bigger change. Other plans wait in Requests.',
																'bettershield'
														  )
														: __( 'Saved. Assistants are now read-only. Reconnect one to allow changes.', 'bettershield' )
												}
											/>
										</div>
									) }
								</SettingRow>
								<SettingRow
									className="bs-ds-perms__capability"
									title={ __( 'You can approve AI fixes', 'bettershield' ) }
									about={ capabilityNote( write ) }
									// Off is the default, not a warning: said in words, in a
									// neutral pill (#2569).
									control={ <Badge tone={ write.capability_granted ? 'brand' : undefined }>{ write.capability_granted ? __( 'Yes', 'bettershield' ) : __( 'Not yet', 'bettershield' ) }</Badge> }
								/>
							</>
						) : (
							<div className="bs-ds-perms__note">
								<Alert layout="default" tone="info" desc={ __( 'Requires WordPress 6.9.', 'bettershield' ) } />
							</div>
						) }
					</SettingsCard>
				);
			} }
		</Resource>
	);
}

/**
 * Recording what agents do: a separate decision from the two above. The
 * same control and option Settings carries; a site that refuses every agent
 * still wants the record of what tried.
 */
function Recording() {
	const { resource, reload } = useResource( 'abilities' );
	const { setAgentCapture, busy } = useStore();
	const saving = isWorking( busy, 'agentCapture' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={
				<Skeleton label={ __( 'Loading the recording switch…', 'bettershield' ) }>
					<CardBone rows={ [ '55%' ] } toggle />
				</Skeleton>
			}>
			{ ( data ) => (
				<SettingsCard
					icon="scroll-text"
					title={ __( 'Recording agent activity', 'bettershield' ) }
					trailing={
						<Button type="secondary" size="sm" href={ tabUrl( 'bettershield-activity', 'agents' ) }>
							{ __( 'See Agent Activity', 'bettershield' ) }
						</Button>
					}
					intro={ __(
						'Everything an assistant asks for, even what was refused, is logged in Activity › Agent activity.',
						'bettershield'
					) }
				>
					{ data.capture_available ? (
						<SettingRow
							title={ __( 'Record what agents do on this site', 'bettershield' ) }
							about={ __( 'Keep this on: it is your record if something goes wrong.', 'bettershield' ) }
							control={ <Saved forKey="agentCapture" /> }
							toggle={ { checked: data.capture_enabled, disabled: saving, onChange: ( enabled ) => setAgentCapture( enabled ) } }
							topics={ [
								{
									key: 'kept',
									label: __( 'What is kept', 'bettershield' ),
									text: __(
										'What was asked, when, by whom, how it connected, and the result.',
										'bettershield'
									),
									note: {
										tone: 'info',
										text: __( 'What the assistant typed isn’t stored, only a scrambled code, in case it contained a password.', 'bettershield' ),
									},
								},
							] }
						/>
					) : (
						<div className="bs-ds-perms__note">
							<Alert
								layout="default"
								tone="info"
								desc={ sprintf(
									/* translators: %s: a WordPress version number. */
									__( 'Requires WordPress %s.', 'bettershield' ),
									data.capture_requires
								) }
							/>
						</div>
					) }
				</SettingsCard>
			) }
		</Resource>
	);
}

/**
 * What no level of this reaches, and how often it may act. Neither is a
 * control; both are questions an owner asks once and wants answered where the
 * switches are. The limits are the site's own numbers, so a site that raised
 * one is told the number it has.
 */
function Boundaries( { surface } ) {
	const limits = surface.limits || {};
	const writes = Math.max( 1, Number( limits.writes_per_hour ) || 0 );
	const plans = Math.max( 1, Number( limits.plans_per_hour ) || 0 );
	const factor = Math.max( 1, Number( limits.site_factor ) || 1 );

	return (
		<SettingsCard
			icon="lock"
			title={ __( 'What stays yours', 'bettershield' ) }
			intro={ __( 'Sign-in changes, file restores and plugin deactivation always need your approval.', 'bettershield' ) }
		>
			{ /* What no switch hands an agent, as chips rather than a sentence. */ }
			<div className="bs-ds-perms__yours">
				<SectionHead>{ __( 'Never done by an agent', 'bettershield' ) }</SectionHead>
				<ul className="bs-ds-perms__chips">
					{ neverDone().map( ( chip ) => (
						<li key={ chip }>
							<Badge>{ chip }</Badge>
						</li>
					) ) }
				</ul>
			</div>
			<div className="bs-ds-perms__limits">
				<SectionHead>{ __( 'How often an agent may act', 'bettershield' ) }</SectionHead>
				{ /* The three ceilings as numbers first: the figure is what
				     somebody comes to this card to check. */ }
				<Stats
					tiles={ [
						{
							key: 'writes',
							icon: 'pencil',
							label: _n( 'Fix of each type per hour, per assistant', 'Fixes of each type per hour, per assistant', writes, 'bettershield' ),
							value: writes,
						},
						// The site-wide ceiling the note below states, as a
						// figure beside the other two (#2569).
						{
							key: 'site',
							icon: 'globe',
							label: _n( 'Fix of each type per hour, whole site', 'Fixes of each type per hour, whole site', writes * factor, 'bettershield' ),
							value: writes * factor,
						},
						{
							key: 'plans',
							icon: 'clipboard-list',
							label: _n( 'Suggested fix per hour', 'Suggested fixes per hour', plans, 'bettershield' ),
							value: plans,
						},
					] }
				/>
				<Topics
					items={ [
						{
							key: 'how',
							label: __( 'How this works', 'bettershield' ),
							body: (
								<>
									<p>
										{ __(
											'Assistants that can fix things ask you in the chat. Others can’t suggest fixes. Fixes suggested from WP-CLI wait in Requests.',
											'bettershield'
										) }
									</p>
									<p>{ __( 'Changes to sign-in also need your recovery link checked in the last 24 hours (Protection › Recovery).', 'bettershield' ) }</p>
									<p>
										{ sprintf(
											/* translators: 1: how many fixes of one type each assistant may make in an hour; 2: how many the whole site allows. */
											_n(
												'Each assistant can make %1$d fix of each type per hour, and the whole site %2$d.',
												'Each assistant can make %1$d fixes of each type per hour, and the whole site %2$d.',
												writes,
												'bettershield'
											),
											writes,
											writes * factor
										) }{ ' ' }
										{ sprintf(
											/* translators: %d: how many fixes may be suggested in an hour. */
											_n(
												'Suggesting fixes has a higher limit, %d an hour, since a suggestion changes nothing.',
												'Suggesting fixes has a higher limit, %d an hour, since a suggestion changes nothing.',
												plans,
												'bettershield'
											),
											plans
										) }
									</p>
									<p>{ __( 'Anything over the limit is refused; the assistant can try again later.', 'bettershield' ) }</p>
								</>
							),
						},
					] }
				/>
			</div>
		</SettingsCard>
	);
}

/** The screen standing in for itself while the agent payload is read. */
function PermissionsBone() {
	return (
		<Skeleton label={ __( 'Loading the permissions…', 'bettershield' ) }>
			<AgentStripBone />
			<CardBone rows={ [ '50%', '65%', '45%' ] } toggle />
			<CardBone rows={ [ '55%' ] } toggle />
		</Skeleton>
	);
}

/**
 * What the permission row says under its answer. While changes are off the
 * switch is what grants it, so telling the site's only administrator that an
 * administrator grants it pointed at nobody (#2001).
 *
 * @param {{enabled: boolean, capability_granted: boolean}} write The changes switch and the permission.
 * @return {string|null} The note, or none where the account holds it.
 */
function capabilityNote( write ) {
	if ( write.capability_granted ) {
		return null;
	}

	if ( ! write.enabled ) {
		return __( 'Administrators get this when you allow AI fixes.', 'bettershield' );
	}

	return __( 'You can see suggested fixes but not approve them. Ask an administrator.', 'bettershield' );
}

export default function Permissions() {
	const { resource, reload } = useResource( 'agentSurface' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <PermissionsBone /> }>
			{ ( data ) => (
				<>
					{ /* Where the site stands before the switches that move it. */ }
					<AgentStrip surface={ data } />
					<Opting surface={ data } />
					<Recording />
					<Boundaries surface={ data } />
				</>
			) }
		</Resource>
	);
}
