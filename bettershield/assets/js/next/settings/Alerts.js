/**
 * Settings › Email alerts: what arrives by email, and how to stop it.
 *
 * The mute is the first row, because it is the control someone opens this
 * tab looking for. Everything under it is shown as switched off while the
 * mute is on rather than hidden, so the state of the site is legible at a
 * glance: a person coming back in three months should be able to see both
 * that alerting is silenced and what it would do if it were not.
 *
 * The precision figures are here rather than in a report kept to ourselves.
 * A rate that only its authors read is not a check on anything.
 *
 * The four facts first, then two cards of rows: when alerts are sent and to
 * whom, and what is worth sending. What an alert never carries closes the
 * tab, as a list rather than a setting.
 */

import './Alerts.css';

import { useEffect, useId, useMemo, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useResource, useStore } from '../../store';
import { onEnter } from '../../ui/keys';
import { emailProblem } from '../../ui/validate';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import useUnsaved from '../ui/useUnsaved';
import Field, { FieldRow } from '../ui/Field';
import { focusIfLost } from '../ui/focus';
import Icon from '../ui/Icon';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { CardBone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { Resource } from '../ui/States';
import Switch from './Switch';

/** A React id, as an attribute other markup can point at. */
/*
 * Each control saves under a key of its own, so "Saved." is said beside the
 * control that saved; any of them saving holds every control on the screen.
 */
const SAVES = [ 'alerts', 'alerts-digest', 'alerts-instant', 'alerts-types', 'alerts-recipients', 'alerts-account' ];

function useDomId() {
	return useId().replace( /[^\w-]/g, '' );
}

/**
 * The tab before its settings have landed: the four facts, then the two
 * cards with their rows.
 */
export function AlertsBone() {
	return (
		<Skeleton label={ __( 'Loading the alert settings…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />
			<CardBone rows={ [ '45%', '60%', '50%' ] } toggle />
			<CardBone rows={ [ '40%', '35%', '55%' ] } toggle />
		</Skeleton>
	);
}

/** Sunday first, matching how WordPress numbers the days it hands back. */
export function dayOptions() {
	return [
		{ value: '0', label: __( 'Sunday', 'bettershield' ) },
		{ value: '1', label: __( 'Monday', 'bettershield' ) },
		{ value: '2', label: __( 'Tuesday', 'bettershield' ) },
		{ value: '3', label: __( 'Wednesday', 'bettershield' ) },
		{ value: '4', label: __( 'Thursday', 'bettershield' ) },
		{ value: '5', label: __( 'Friday', 'bettershield' ) },
		{ value: '6', label: __( 'Saturday', 'bettershield' ) },
	];
}

/**
 * Said beside a switch the mute is holding off.
 *
 * Disabled with nothing beside it, a switch reads as broken: the reason was
 * one row up, and a reader trying to turn the weekly summary on had no way
 * to know that the mute was what stood in the way, or that what they chose
 * before is kept.
 */
function heldByMute() {
	return __(
		'Paused while alerts are muted. Your setting is kept.',
		'bettershield'
	);
}

/**
 * Turned on by the host from the command line, and off by the owner here, so
 * it is shown only while it is on.
 *
 * @param {Object} props
 * @param {Object} props.data The alert settings.
 */
export function HostManaged( { data } ) {
	const { saveAlerts, busy } = useStore();

	if ( ! data.host_managed ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Routine alerts go to your host', 'bettershield' ) }
			about={ __( 'Routine alerts wait for the weekly summary. Signs of an attack still email you at once.', 'bettershield' ) }
			control={
				<Switch
					label={ __( 'Routine alerts go to your host', 'bettershield' ) }
					checked={ data.host_managed }
					disabled={ isWorking( busy, ...SAVES ) }
					onChange={ ( host_managed ) => saveAlerts( { host_managed } ) }
				/>
			}
		/>
	);
}

function Mute( { data } ) {
	const { saveAlerts, busy } = useStore();
	const saving = isWorking( busy, ...SAVES );

	return (
		<SettingRow
			title={ __( 'Mute everything', 'bettershield' ) }
			about={ __( 'Stops all alert emails. Account-recovery emails still go out.', 'bettershield' ) }
			// The switch shows whether alerts are muted here. A mute set by
			// marking this site a staging copy stops applying once the copy
			// runs at another address, and is said so rather than shown on.
			meta={
				data.staging_mute_lapsed
					? __( 'This site was muted as a staging copy, but it now runs at a different address, so alerts are sent.', 'bettershield' )
					: null
			}
			control={
				<Switch
					label={ __( 'Mute all alerts', 'bettershield' ) }
					checked={ data.muted }
					disabled={ saving }
					onChange={ ( muted ) => saveAlerts( { muted } ) }
				/>
			}
			topics={ [
				{
					key: 'still-runs',
					label: __( 'What keeps running', 'bettershield' ),
					lead: __( 'Everything else, exactly as before.', 'bettershield' ),
					points: [
						__( 'The site is still watched.', 'bettershield' ),
						__( 'Findings still open and close.', 'bettershield' ),
						__( 'The activity record still fills up.', 'bettershield' ),
					],
				},
				{
					key: 'still-sent',
					label: __( 'What still goes out', 'bettershield' ),
					lead: __( 'Mail about a person’s own account, sent to that person.', 'bettershield' ),
					points: [
						__( 'The link that clears a sign-in lockout, after wrong passwords.', 'bettershield' ),
						__( 'Sign-ins from a new network, where that notice is on.', 'bettershield' ),
						__( 'The recovery link, when re-requested or replaced after use.', 'bettershield' ),
						__( 'A confirmation link for a privileged account’s new address, where that fix is on.', 'bettershield' ),
						__( 'A change to the ways into a person’s own account, where that email is on.', 'bettershield' ),
						__( 'A two-factor reminder, three days before the deadline.', 'bettershield' ),
					],
				},
				{
					key: 'visible',
					label: __( 'Where muting shows', 'bettershield' ),
					lead: __( 'Muting shows on the Overview and the dashboard widget, and is logged in Activity.', 'bettershield' ),
				},
			] }
		/>
	);
}

/**
 * Planned maintenance: routine alerts held for a window the owner opens now
 * or books ahead to open by itself (#107), which closes on its own. While one is open, or its closing summary is
 * still owed, the row says so and offers the way to end it.
 *
 * Exported so it can be mounted on its own with the window's state.
 *
 * @param {Object}  props
 * @param {Object}  props.state The maintenance window as the alerts document carries it.
 * @param {boolean} props.muted Whether every alert is muted.
 * @param {boolean} props.off   Whether email alerts are off.
 */
export function Maintenance( { state = {}, muted = false, off = false } ) {
	const { startMaintenance, endMaintenance, bookMaintenance, cancelMaintenanceBooking, busy } = useStore();
	const working = busy === 'maintenance';
	// The document can carry no window at all.
	const current = state || {};
	const booked = current.booked || null;
	const [ minutes, setMinutes ] = useState( booked ? String( booked.minutes ) : '120' );
	// Now, or booked for later (#107).
	const [ when, setWhen ] = useState( booked ? 'later' : 'now' );
	const [ starts, setStarts ] = useState( booked ? booked.local : '' );
	const [ now, setNow ] = useState( Date.now() );

	useEffect( () => {
		const timer = setInterval( () => setNow( Date.now() ), 15000 );

		return () => clearInterval( timer );
	}, [] );

	// A booking made or changed elsewhere fills the form again.
	useEffect( () => {
		if ( booked ) {
			setWhen( 'later' );
			setStarts( booked.local );
			setMinutes( String( booked.minutes ) );
		}
	}, [ booked && booked.local, booked && booked.minutes ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const active = current.active && Date.parse( current.until ) > now;
	const pending = ! active && current.summary_pending;
	// Muted or switched off, nothing is being sent, so a window has nothing
	// to hold. One already open keeps its status and its end.
	const held = ( muted || off ) && ! active && ! pending && ! booked;
	let status = __( 'Ordinary alerts are active.', 'bettershield' );

	if ( active ) {
		status = sprintf(
			/* translators: %s: the date and time the maintenance window ends. */
			__( 'Active until %s', 'bettershield' ),
			whenPhrase( current.until )
		);
	} else if ( pending ) {
		status = __( 'Ordinary alerts have resumed. The closing summary is pending.', 'bettershield' );
	} else if ( booked ) {
		status = booked.by
			? sprintf(
					/* translators: 1: when the window starts, 2: when it ends, 3: who booked it. */
					__( 'Booked from %1$s to %2$s by %3$s. It starts by itself.', 'bettershield' ),
					whenPhrase( booked.at ),
					whenPhrase( booked.until ),
					booked.by
			  )
			: sprintf(
					/* translators: 1: when the window starts, 2: when it ends. */
					__( 'Booked from %1$s to %2$s. It starts by itself.', 'bettershield' ),
					whenPhrase( booked.at ),
					whenPhrase( booked.until )
			  );
	} else if ( held ) {
		status = muted
			? __( 'Alerts are muted, so maintenance mode isn’t needed.', 'bettershield' )
			: __( 'Email alerts are off, so maintenance mode isn’t needed.', 'bettershield' );
	}

	let action = __( 'Start Maintenance', 'bettershield' );

	if ( active ) {
		action = __( 'End Maintenance', 'bettershield' );
	} else if ( pending ) {
		action = __( 'Send the Closing Summary', 'bettershield' );
	} else if ( booked ) {
		action = __( 'Change Booking', 'bettershield' );
	} else if ( 'later' === when ) {
		action = __( 'Book Maintenance', 'bettershield' );
	}

	const press = () => {
		if ( active || pending ) {
			endMaintenance();
		} else if ( 'later' === when ) {
			bookMaintenance( starts, Number( minutes ) );
		} else {
			startMaintenance( Number( minutes ) );
		}
	};

	return (
		<SettingRow
			title={ __( 'Planned maintenance', 'bettershield' ) }
			about={ __( 'Pause routine alerts while you work. Critical alerts still send.', 'bettershield' ) }
			topics={ [
				{
					key: 'how',
					label: __( 'How this works', 'bettershield' ),
					text: __(
						'Routine alerts (admin, plugin, theme, WordPress update and file changes) wait for the weekly summary instead of being emailed.',
						'bettershield'
					),
					points: [
						__( 'Still sent right away: critical events, visits to the decoy page, lockdowns, passkey-only sign-in being turned on, and protections being changed.', 'bettershield' ),
						__( 'Protections stay on.', 'bettershield' ),
						__( 'The window ends on its own, even if tasks run late.', 'bettershield' ),
					],
				},
				{
					key: 'book',
					label: __( 'Booking ahead', 'bettershield' ),
					text: __( 'A booked window starts by itself at the time you set, on the site’s clock, and ends when booked even if it starts late.', 'bettershield' ),
					points: [
						__( 'Booking emails your alert recipients at once, naming who booked it and when it runs.', 'bettershield' ),
						__( 'One window at a time, booked or open.', 'bettershield' ),
					],
				},
				{
					key: 'after',
					label: __( 'When it ends', 'bettershield' ),
					text: __( 'A closing summary goes out through your alert channels, following your settings, mute included.', 'bettershield' ),
				},
			] }
		>
			<div className="bs-ds-maint">
				<p className="bs-ds-maint__status" role="status">
					{ status }
				</p>
				{ active || pending ? (
					<p className="bs-ds-alerts__note">
						{ sprintf(
							/* translators: 1: how many events were recorded, e.g. "4 events", 2: how many alerts were held, e.g. "1 routine alert". */
							__( 'So far: %1$s logged, %2$s waiting for the summary.', 'bettershield' ),
							/* translators: %d: how many events were recorded during maintenance. */
							sprintf( _n( '%d event', '%d events', current.total || 0, 'bettershield' ), current.total || 0 ),
							/* translators: %d: how many routine alerts were held during maintenance. */
							sprintf( _n( '%d routine alert', '%d routine alerts', current.held || 0, 'bettershield' ), current.held || 0 )
						) }
					</p>
				) : null }
				<FieldRow>
					{ ! active && ! pending && ! booked ? (
						<div className="bs-ds-maint__duration">
							<Field
								kind="select"
								label={ __( 'Start', 'bettershield' ) }
								value={ when }
								onChange={ setWhen }
								disabled={ working || held }
								options={ [
									{ value: 'now', label: __( 'Now', 'bettershield' ) },
									{ value: 'later', label: __( 'Later, at a time I book', 'bettershield' ) },
								] }
							/>
						</div>
					) : null }
					{ ! active && ! pending && 'later' === when ? (
						<div className="bs-ds-maint__duration">
							<Field
								type="datetime-local"
								label={ __( 'Starts at (site time)', 'bettershield' ) }
								value={ starts }
								onChange={ setStarts }
								disabled={ working || held }
							/>
						</div>
					) : null }
					{ ! active && ! pending ? (
						<div className="bs-ds-maint__duration">
							<Field
								kind="select"
								label={ __( 'Duration', 'bettershield' ) }
								value={ minutes }
								onChange={ setMinutes }
								disabled={ working || held }
								options={ [
									{ value: '30', label: __( '30 minutes', 'bettershield' ) },
									{ value: '60', label: __( '1 hour', 'bettershield' ) },
									{ value: '120', label: __( '2 hours', 'bettershield' ) },
									{ value: '240', label: __( '4 hours', 'bettershield' ) },
								] }
							/>
						</div>
					) : null }
					{ /* The card's one primary: opening or booking a window.
					     Ending one, finishing its summary or canceling a
					     booking puts things back as they were. As tall as the
					     selects beside it. */ }
					<Button
						type={ active || pending || booked ? 'secondary' : 'primary' }
						size="md"
						disabled={ working || held || ( 'later' === when && ! active && ! pending && ! starts ) }
						isBusy={ working }
						onClick={ press }
					>
						{ action }
					</Button>
					{ booked && ! active && ! pending ? (
						<Button type="secondary" size="md" disabled={ working } onClick={ () => cancelMaintenanceBooking() }>
							{ __( 'Cancel Booking', 'bettershield' ) }
						</Button>
					) : null }
				</FieldRow>
			</div>
		</SettingRow>
	);
}

/** What an address can ask instant alerts to interrupt it for. */
export function instantOptions() {
	return [
		{ value: 'high', label: __( 'High and critical', 'bettershield' ) },
		{ value: 'critical', label: __( 'Critical only', 'bettershield' ) },
		{ value: 'off', label: __( 'None', 'bettershield' ) },
	];
}

/**
 * What one address chose. An address that has chosen nothing is stored
 * without an entry and hears everything.
 *
 * @param {Array}  preferences The saved choices, `{ address, instant, digest }`.
 * @param {string} address     The address.
 * @return {{instant: string, digest: boolean}} Its choice.
 */
export function choiceOf( preferences, address ) {
	const found = ( preferences || [] ).find( ( entry ) => entry.address.toLowerCase() === address.toLowerCase() );

	return { instant: found ? found.instant : 'high', digest: found ? found.digest : true };
}

function Recipients( { data } ) {
	const { saveAlerts, sendAlertTest, busy } = useStore();
	const [ draft, setDraft ] = useState( '' );
	const [ refusal, setRefusal ] = useState( null );
	const [ choiceRefusal, setChoiceRefusal ] = useState( null );
	const [ tested, setTested ] = useState( null );
	// Which language each address was sent the test in.
	const [ languages, setLanguages ] = useState( [] );
	const rowId = `bs-ds-recipients-${ useDomId() }-row`;

	// An address typed and not yet added is an edit leaving would lose
	// (#2053).
	useUnsaved( '' !== draft.trim() );
	const problemId = `bs-ds-recipients-${ useDomId() }-problem`;
	const saving = isWorking( busy, ...SAVES );
	const testing = busy === 'alert-test';
	// One list per set of addresses, so the effect below that watches it
	// runs when the addresses change and not on every render.
	const named = useMemo( () => data.recipients || [], [ data.recipients ] );
	const max = Number( data.max ) || 5;
	const full = named.length >= max;

	/*
	 * Where focus goes once an address has been removed. Its row went with
	 * it, and the button that had focus, so the browser dropped focus to the
	 * document: a keyboard user started again from the top of the page, and
	 * a screen-reader user heard nothing about what had happened. The next
	 * address is where the eye would go; when there is none, the field for
	 * adding one, which is the only thing left in the row.
	 *
	 * Wanted rather than done at once, because the node to move to does not
	 * exist until the row has re-rendered with the new list.
	 */
	const rowRefs = useRef( new Map() );
	const addRef = useRef( null );
	const [ focusWanted, setFocusWanted ] = useState( null );

	const keepRow = ( address ) => ( node ) => {
		if ( node ) {
			rowRefs.current.set( address, node );
		} else {
			rowRefs.current.delete( address );
		}
	};

	const remove = ( address ) => {
		// The row after this one, or before it when it is last: decided now,
		// while the list still says where this one stands.
		const at = named.indexOf( address );
		const neighbor = named[ at + 1 ] || named[ at - 1 ] || null;

		setChoiceRefusal( null );
		saveAlerts(
			{ recipients: named.filter( ( keep ) => keep !== address ) },
			( result ) => {
				// Only on success: a refusal leaves the row and its button where
				// they were.
				if ( result ) {
					setFocusWanted( { address, neighbor } );
				}
			},
			// Taking off the last address on high and critical is refused,
			// and said here rather than only in the banner at the top.
			( error ) => setChoiceRefusal( error && error.message ? error.message : null ),
			'alerts-recipients'
		);
	};

	// One address's choice, saved on its own. A refusal — nobody left on
	// high and critical — is said under the list.
	const choose = ( address, change ) => {
		setChoiceRefusal( null );
		saveAlerts(
			{ preferences: [ { address, ...change } ] },
			undefined,
			( error ) => setChoiceRefusal( error && error.message ? error.message : null ),
			'alerts-recipients'
		);
	};

	useEffect( () => {
		if ( ! focusWanted ) {
			return;
		}

		const { address, neighbor, added } = focusWanted;
		const field = addRef.current && addRef.current.querySelector( 'input' );

		if ( added ) {
			// The field is held while the save runs.
			if ( saving ) {
				return;
			}

			setFocusWanted( null );
			focusIfLost( field );

			return;
		}

		const node = named.includes( address )
			? rowRefs.current.get( address )
			: rowRefs.current.get( neighbor ) || field;

		if ( node ) {
			node.focus();
		}

		setFocusWanted( null );
	}, [ focusWanted, named, saving ] );

	const test = () => {
		setTested( null );
		setLanguages( [] );
		sendAlertTest().then( ( result ) => {
			if ( ! result ) {
				return;
			}

			const outcomes = {
				/* translators: shown after a test alert went out. */
				sent: __( 'Sent. If it arrives, alerts will reach you too.', 'bettershield' ),
				refused: __( 'The mail server refused it, so real alerts would be lost too. Check the server’s mail setup.', 'bettershield' ),
				muted: __( 'Alerts are muted, so nothing was sent. Unmute to test.', 'bettershield' ),
				no_recipient: __( 'Nothing was sent: no address is set and the site has no admin email.', 'bettershield' ),
				// Nothing was sent and nothing was wrong: the second test
				// inside the window is declined so the button cannot be used
				// to mail an address repeatedly.
				too_soon: __( 'A test just went out. Try again in a few minutes.', 'bettershield' ),
			};

			setTested( outcomes[ result.outcome ] || outcomes.refused );
			setLanguages( 'sent' === result.outcome && Array.isArray( result.languages ) ? result.languages : [] );
		} );
	};

	// Named while it is being typed. The save says the same thing a moment
	// later, but by then the address has left the field. Compared without
	// case, as the site compares them: a variant reaches the same inbox.
	const typed = draft.trim().toLowerCase();
	const problem =
		emailProblem( draft ) ||
		( typed && named.some( ( address ) => address.toLowerCase() === typed )
			? __( 'This address is already in the list.', 'bettershield' )
			: null );
	const said = problem || refusal;

	const edit = ( value ) => {
		setRefusal( null );
		setDraft( value );
	};

	const add = () => {
		const address = draft.trim();

		if ( problem || full ) {
			return;
		}

		if ( ! address ) {
			setDraft( '' );
			return;
		}

		saveAlerts(
			{ recipients: [ ...named, address ] },
			( result ) => {
				if ( result ) {
					setDraft( '' );
					// Add is held until there is a next address to add, so the
					// keyboard went to the page: it goes to the field (#1926).
					setFocusWanted( { added: true } );
				}
			},
			// Kept on a refusal so the address can be corrected rather than
			// retyped, and the reason said under it rather than only in the
			// banner at the top of the page.
			( error ) => setRefusal( error && error.message ? error.message : null ),
			'alerts-recipients'
		);
	};

	return (
		<SettingRow
			title={ __( 'Where alerts go', 'bettershield' ) }
			about={
				named.length
					? __(
							'Alerts and summaries go to these addresses. Choose what each one gets. They don’t need a WordPress account.',
							'bettershield'
					  )
					: ( data.effective_recipients || [] )[ 0 ]
					? sprintf(
							/* translators: %s: an email address. */
							__(
								'Until you add an address, alerts go to the admin email, %s.',
								'bettershield'
							),
							data.effective_recipients[ 0 ]
					  )
					: // A sentence of its own: "the admin email, nowhere." read as one (#2391).
					  __( 'Add an address: this site has no admin email to send alerts to.', 'bettershield' )
			}
		>
			{ ( data.effective_recipients || [] ).length ? null : (
				<Alert
					layout="default"
					tone="warning"
					desc={ __(
						'Alerts cannot be sent: there is no usable address. Add one here, or set the WordPress admin email.',
						'bettershield'
					) }
				/>
			) }

			{ named.length ? (
				<ul className="bs-ds-recipients">
					{ named.map( ( address, index ) => (
						<li key={ address } ref={ keepRow( address ) } tabIndex={ -1 }>
							<span className="bs-ds-recipients__address" id={ `${ rowId }-${ index }` }>
								{ address }
							</span>
							<Button
								type="ghost"
								size="sm"
								disabled={ saving }
								aria-label={ sprintf(
									/* translators: %s: an email address. */
									__( 'Remove %s', 'bettershield' ),
									address
								) }
								onClick={ () => remove( address ) }
							>
								{ __( 'Remove', 'bettershield' ) }
							</Button>
							{ /* What this address gets, each control named by the
							     address it belongs to. */ }
							<div className="bs-ds-recipients__choices">
								<Field
									kind="select"
									width="md"
									label={ __( 'Instant alerts', 'bettershield' ) }
									// The select control drops a description it
									// is handed, so the address goes in its name.
									aria-label={ sprintf(
										/* translators: %s: an email address. */
										__( 'Instant alerts for %s', 'bettershield' ),
										address
									) }
									value={ choiceOf( data.preferences, address ).instant }
									options={ instantOptions() }
									disabled={ saving }
									aria-describedby={ `${ rowId }-${ index }` }
									onChange={ ( instant ) => choose( address, { instant } ) }
								/>
								<Field
									kind="check"
									label={ __( 'Weekly summary', 'bettershield' ) }
									checked={ choiceOf( data.preferences, address ).digest }
									disabled={ saving }
									aria-describedby={ `${ rowId }-${ index }` }
									onChange={ ( digest ) => choose( address, { digest } ) }
								/>
							</div>
						</li>
					) ) }
				</ul>
			) : null }

			{ choiceRefusal ? (
				<p className="bs-ds-recipients__problem" role="alert">
					{ choiceRefusal }
				</p>
			) : null }

			<Saved forKey="alerts-recipients" />

			<div className="bs-ds-recipients__add" ref={ addRef }>
				<FieldRow>
					<Field
						type="email"
						label={ __( 'Add an address', 'bettershield' ) }
						placeholder="you@example.com"
						value={ draft }
						disabled={ saving || full }
						onChange={ edit }
						onKeyDown={ onEnter( add ) }
						aria-invalid={ said ? 'true' : undefined }
						aria-describedby={ said ? problemId : undefined }
					/>
					<Button type="secondary" size="md" isBusy={ saving } disabled={ saving || full || ! draft.trim() || !! problem } onClick={ add }>
						{ __( 'Add', 'bettershield' ) }
					</Button>
				</FieldRow>
			</div>

			{ said ? (
				<p className="bs-ds-recipients__problem" id={ problemId }>
					{ said }
				</p>
			) : null }

			{ full ? (
				<p className="bs-ds-recipients__limit">
					{ sprintf(
						/* translators: %d: the most addresses alerts can go to. */
						__( 'Up to %d addresses. Remove one to add another.', 'bettershield' ),
						max
					) }
				</p>
			) : null }

			<div className="bs-ds-alerts__actions bs-ds-recipients__test">
				<Button type="secondary" size="sm" icon="send" iconTone="2" isBusy={ testing } disabled={ testing } onClick={ test }>
					{ __( 'Send a Test Alert', 'bettershield' ) }
				</Button>
				<p className="bs-ds-alerts__note" role="status">
					{ tested ||
						__( 'Sends a real alert email to catch mail problems early.', 'bettershield' ) }
				</p>
			</div>
			{ /* Alerts are written in each reader's language: an account's
			     own, or the site's for an address that is nobody's account. */ }
			{ languages.length ? (
				<div className="bs-ds-recipients__languages">
					<p className="bs-ds-alerts__note">{ __( 'Each address gets alerts in:', 'bettershield' ) }</p>
					<ul>
						{ languages.map( ( entry ) => (
							<li key={ entry.address }>
								{ sprintf(
									/* translators: 1: an email address, 2: a language, e.g. "German". */
									__( '%1$s: %2$s', 'bettershield' ),
									entry.address,
									entry.language
								) }
							</li>
						) ) }
					</ul>
				</div>
			) : null }
		</SettingRow>
	);
}

function Digest( { data } ) {
	const { saveAlerts, sendDigest, busy } = useStore();
	const [ outcome, setOutcome ] = useState( null );
	const heldId = `bs-ds-digest-${ useDomId() }-held`;
	const saving = isWorking( busy, ...SAVES );
	const sending = busy === 'digest';

	// Said beside the button, as the test alert's answer is: a press that
	// went out said nothing, and one declined because a summary had just gone
	// out was reported, far above, as the mail server refusing it.
	const send = () => {
		setOutcome( null );
		sendDigest().then( ( result ) => {
			if ( ! result ) {
				return;
			}

			const outcomes = {
				sent: __( 'Sent. Check the inbox.', 'bettershield' ),
				refused: __(
					'WordPress could not send the summary. Check the server’s mail setup.',
					'bettershield'
				),
				too_soon: __( 'A summary just went out, so this one was not sent. Try again later.', 'bettershield' ),
				just_tried: __( 'A summary was just tried, so this one was not sent. Try again shortly.', 'bettershield' ),
				muted: __( 'Alerts are muted, so nothing was sent.', 'bettershield' ),
				no_recipient: __( 'Nothing was sent: no address is set and the site has no admin email.', 'bettershield' ),
				no_digest_recipient: __( 'Nothing was sent: every address has the weekly summary turned off.', 'bettershield' ),
			};

			setOutcome( outcomes[ result.outcome ] || ( result.sent ? outcomes.sent : outcomes.refused ) );
		} );
	};

	return (
		<SettingRow
			title={ __( 'Weekly summary', 'bettershield' ) }
			about={ __(
				'Findings opened and resolved, notable sign-in and account activity, and the score.',
				'bettershield'
			) }
			meta={ data.muted ? <span id={ heldId }>{ heldByMute() }</span> : null }
			control={
				<Switch
					label={ __( 'Send a weekly summary', 'bettershield' ) }
					/*
					 * Drawn off while alerting is muted, without changing
					 * what is stored. Disabling a switch at its stored value
					 * leaves it reading ON beside a note saying nothing is
					 * being emailed — and a returning administrator glancing
					 * at an ON switch can reasonably conclude summaries are
					 * still going out. Unmuting puts it back where they left it.
					 */
					checked={ data.muted ? false : data.digest }
					disabled={ saving || data.muted }
					describedBy={ data.muted ? heldId : undefined }
					onChange={ ( digest ) => saveAlerts( { digest }, undefined, undefined, 'alerts-digest' ) }
				/>
			}
			topics={ [
				{
					key: 'window',
					label: __( 'What week it covers', 'bettershield' ),
					lead: __( 'Everything since the last summary, not a fixed seven days.', 'bettershield' ),
					text: __( 'A missed week is reported, not skipped.', 'bettershield' ),
				},
				{
					key: 'quiet',
					label: __( 'After a quiet week', 'bettershield' ),
					lead: __( 'It arrives anyway, saying so.', 'bettershield' ),
					text: __(
						'A summary alone does not mean something is wrong.',
						'bettershield'
					),
				},
			] }
		>
			{ data.digest ? (
				<div className="bs-ds-alerts__day">
					<Field
						kind="select"
						label={ __( 'Day', 'bettershield' ) }
						value={ String( data.digest_day ) }
						options={ dayOptions() }
						disabled={ saving || data.muted }
						onChange={ ( day ) => saveAlerts( { digest_day: Number( day ) }, undefined, undefined, 'alerts-digest' ) }
					/>
				</div>
			) : null }

			<Saved forKey="alerts-digest" />

			<div className="bs-ds-alerts__actions">
				<Button type="secondary" size="sm" icon="send" iconTone="2" isBusy={ sending } disabled={ sending || data.muted } onClick={ send }>
					{ __( 'Send One Now', 'bettershield' ) }
				</Button>
				<span className="bs-ds-alerts__note" role="status">
					{ outcome || __( 'Sends this week’s summary now. The next one covers from today.', 'bettershield' ) }
				</span>
			</div>
		</SettingRow>
	);
}

/**
 * The email to an account holder when a way of signing in to their own
 * account is added or removed (#1855). It goes to that person, not to the
 * alert recipients, so muting alerts does not hold it.
 *
 * @param {Object} props
 * @param {Object} props.data The alert settings.
 */
function AccountNotices( { data } ) {
	const { saveAlerts, busy } = useStore();
	const saving = isWorking( busy, ...SAVES );

	return (
		<SettingRow
			title={ __( 'Account change emails', 'bettershield' ) }
			about={ __( 'Emails people when a way into their own account is added or removed.', 'bettershield' ) }
			control={
				<span className="bs-ds-alerts__accounts">
					<Saved forKey="alerts-account" />
					<Switch
						label={ __( 'Email people who manage this site', 'bettershield' ) }
						checked={ !! data.account_notices_privileged }
						disabled={ saving }
						onChange={ ( on ) => saveAlerts( { account_notices_privileged: on }, undefined, undefined, 'alerts-account' ) }
					/>
					<Switch
						label={ __( 'Email everyone else', 'bettershield' ) }
						checked={ !! data.account_notices_others }
						disabled={ saving }
						onChange={ ( on ) => saveAlerts( { account_notices_others: on }, undefined, undefined, 'alerts-account' ) }
					/>
				</span>
			}
			topics={ [
				{
					key: 'account-what',
					label: __( 'What they are told about', 'bettershield' ),
					lead: __( 'Changes to how their own account can be signed in to.', 'bettershield' ),
					points: [
						__( 'Two-factor turned on or off, and new backup codes.', 'bettershield' ),
						__( 'A passkey added or removed, named by its label.', 'bettershield' ),
						__( 'An application password created or revoked.', 'bettershield' ),
					],
				},
				{
					key: 'account-how',
					label: __( 'What the email says', 'bettershield' ),
					lead: __( 'When, the network and the browser, and a link to their profile.', 'bettershield' ),
					points: [
						__( 'Changes within ten minutes come in one email.', 'bettershield' ),
						__( 'The email shows only part of the IP address, never the full address.', 'bettershield' ),
					],
				},
			] }
		/>
	);
}

function Instant( { data } ) {
	const { saveAlerts, busy } = useStore();
	const heldId = `bs-ds-instant-${ useDomId() }-held`;
	const saving = isWorking( busy, ...SAVES );

	return (
		<SettingRow
			title={ __( 'Instant alerts', 'bettershield' ) }
			about={ __( 'Emails high and critical events at once.', 'bettershield' ) }
			meta={ data.muted ? <span id={ heldId }>{ heldByMute() }</span> : null }
			control={
				<>
					{ /* Beside the switch, as the other switch rows have it: below the row it always drew an empty block. */ }
					<Saved forKey="alerts-instant" />
					<Switch
						label={ __( 'Email me about high and critical events as they happen', 'bettershield' ) }
						checked={ data.muted ? false : data.instant_critical }
						disabled={ saving || data.muted }
						describedBy={ data.muted ? heldId : undefined }
						onChange={ ( instant ) => saveAlerts( { instant_critical: instant }, undefined, undefined, 'alerts-instant' ) }
					/>
				</>
			}
			topics={ [
				{
					key: 'instant',
					label: __( 'What is sent instantly', 'bettershield' ),
					lead: __( 'Events rated High or Critical.', 'bettershield' ),
					points: [
						__( 'Critical, the highest.', 'bettershield' ),
						__(
							'High: likely signs of a compromise, like a new administrator.',
							'bettershield'
						),
						__( 'A few events, like use of the trap password, still email with this off. Only muting alerts stops them.', 'bettershield' ),
					],
				},
				{
					key: 'timing',
					label: __( 'When one arrives', 'bettershield' ),
					lead: __( 'Several at once are sent as one message. Sending never slows your pages.', 'bettershield' ),
				},
			] }
		/>
	);
}

/**
 * The event types that have sent an instant email here, each with a switch:
 * off, it waits for the weekly summary instead (#1973). Grouped by area as
 * Site Activity groups them. A type that has been critical is locked on,
 * because critical goes out at once. That holds only while instant alerts are
 * on and not muted, so neither the rule nor its badge is shown otherwise.
 *
 * @param {Object} props
 * @param {Object} props.data The alert settings.
 */
export function InstantTypes( { data } ) {
	const { saveAlerts, busy } = useStore();
	const made = useDomId();
	const heldId = `bs-ds-types-${ made }-held`;
	const lockedId = `bs-ds-types-${ made }-locked`;
	const saving = isWorking( busy, ...SAVES );
	const types = data.instant_types || [];
	const off = data.instant_off || [];
	const held = data.muted || ! data.instant_critical;

	const groups = [];

	types.forEach( ( type ) => {
		let group = groups.find( ( one ) => one.area === type.area );

		if ( ! group ) {
			group = { area: type.area, label: type.area_label, types: [] };
			groups.push( group );
		}

		group.types.push( type );
	} );

	const set = ( type, instant ) =>
		saveAlerts(
			{ instant_off: instant ? off.filter( ( one ) => one !== type ) : [ ...off, type ] },
			undefined,
			undefined,
			'alerts-types'
		);

	return (
		<SettingRow
			title={ __( 'Instant alerts by type', 'bettershield' ) }
			about={ ( () => {
				// Held, the line below says the one thing that matters.
				if ( held ) {
					return null;
				}

				/* With the summary off, a type turned off here is not emailed at all (#2616). */
				return data.digest
					? __( 'Turn a type off to get it in the weekly summary instead.', 'bettershield' )
					: __( 'The weekly summary is off, so a type turned off here isn’t emailed at all.', 'bettershield' );
			} )() }
			meta={
				held ? (
					<span id={ heldId }>
						{ data.muted
							? heldByMute()
							: data.digest
							? __( 'Instant alerts are off, so every type waits for the summary. Only a few events still email at once, like use of the trap password.', 'bettershield' )
							: __( 'Instant alerts and the weekly summary are both off. Only a few events still email, like use of the trap password.', 'bettershield' ) }
					</span>
				) : null
			}
			control={ <Saved forKey="alerts-types" /> }
			output={
				0 === types.length ? (
					<p className="bs-ds-alerts__note">
						{ __( 'Event types show here once one has sent an instant alert.', 'bettershield' ) }
					</p>
				) : (
					<div className="bs-ds-alerts__types">
						{ /* The rule set apart from the helper line above it, as the
						     screen's other notices are, and only where a switch is
						     held by it; each held switch also says so itself (#2671). */ }
						{ ! held && types.some( ( type ) => type.critical && ! off.includes( type.type ) ) ? (
							<Alert layout="default" tone="info" desc={ <span id={ lockedId }>{ __( 'Critical alerts are always sent at once.', 'bettershield' ) }</span> } />
						) : null }
						{ groups.map( ( group ) => (
							<section key={ group.area } className="bs-ds-alerts__type-group" aria-label={ group.label }>
								<h4 className="bs-ds-alerts__type-area">{ group.label }</h4>
								{ group.types.map( ( type ) => {
									// A type held before it was ever critical can still
									// be turned back on; it is only never turned off.
									const isOff = off.includes( type.type );
									const locked = type.critical && ! isOff;

									return (
										<Switch
											key={ type.type }
											label={
												locked && ! held ? (
													<>
														{ type.label }
														<Badge className="bs-ds-alerts__always">{ __( 'Always sent', 'bettershield' ) }</Badge>
													</>
												) : (
													type.label
												)
											}
											checked={ ! isOff }
											disabled={ saving || held || locked }
											describedBy={ ( held && heldId ) || ( locked && lockedId ) || undefined }
											onChange={ ( instant ) => set( type.type, instant ) }
										/>
									);
								} ) }
							</section>
						) ) }
					</div>
				)
			}
		/>
	);
}

/** A run of days as a phrase, pluralized on the number of days itself. */
function windowPhrase( days ) {
	return sprintf(
		/* translators: %d: a number of days. */
		_n( '%d day', '%d days', days, 'bettershield' ),
		days
	);
}

function Precision( { precision } ) {
	if ( precision?.available === false ) {
		return (
			<SettingRow
				title={ __( 'Alert usefulness', 'bettershield' ) }
				about={ <span role="status">{ __( 'Alert feedback figures could not be read. Reload to retry.', 'bettershield' ) }</span> }
			/>
		);
	}

	if ( ! precision ) {
		return null;
	}

	return (
		<SettingRow
			title={ __( 'Alert usefulness', 'bettershield' ) }
			about={
				/* The window carries its own plural. Nested inside a sentence
				   chosen by the alert count, it took whichever form that count
				   asked for — which in a language whose rules differ between
				   the two numbers is the wrong one. */
				precision.sent
					? sprintf(
							/* translators: 1: number of alerts sent, 2: a period of days, already carrying its own unit, 3: number marked unhelpful. */
							_n(
								'%1$d alert sent in the last %2$s; %3$d marked unhelpful.',
								'%1$d alerts sent in the last %2$s; %3$d marked unhelpful.',
								precision.sent,
								'bettershield'
							),
							precision.sent,
							windowPhrase( precision.window_days ),
							precision.unhelpful
					  )
					: sprintf(
							/* translators: %s: a period of days, already carrying its own unit. */
							__( 'No alert has been sent in the last %s.', 'bettershield' ),
							windowPhrase( precision.window_days )
					  )
			}
			topics={ [
				{
					key: 'counted',
					label: __( 'Where the count comes from', 'bettershield' ),
					steps: [
						__( 'Every alert links to the thing it is about.', 'bettershield' ),
						__( 'There you can mark the alert as not worth sending.', 'bettershield' ),
						__( 'The count shows here, where you can turn alerts off.', 'bettershield' ),
					],
				},
			] }
		/>
	);
}

/**
 * Reference, not a setting: nothing here is a control, so it is not a row of
 * either card above. One line for what an alert carries and one for
 * where it goes, each with its own mark, under the same head as every card.
 */
function Never() {
	return (
		<SettingsCard className="bs-ds-never" icon="mail" title={ __( 'What alerts include and where they go', 'bettershield' ) }>
			<ul className="bs-ds-never__list">
				{ [
					{ icon: 'list-checks', text: __( 'Each alert says what happened and what to do next.', 'bettershield' ) },
					{ icon: 'send', text: __( 'Only the message leaves, through WordPress mail to your addresses.', 'bettershield' ) },
				].map( ( line ) => (
					<li key={ line.icon }>
						<Icon name={ line.icon } size={ 14 } tone="3" />
						<span>{ line.text }</span>
					</li>
				) ) }
			</ul>
		</SettingsCard>
	);
}

/** The four facts' names, shared by the strip and the tab's stand-in. */
function glanceLabels() {
	return {
		sending: __( 'Alerts', 'bettershield' ),
		to: __( 'Sent to', 'bettershield' ),
		digest: __( 'Weekly summary', 'bettershield' ),
		instant: __( 'Instant alerts', 'bettershield' ),
	};
}

/**
 * The tab in four facts: whether anything is sent at all, where it goes, and
 * the two kinds of message. Read from the same document the rows below use,
 * so the strip cannot disagree with them.
 *
 * @param {Object} props
 * @param {Object} props.data The alerts document.
 */
function AtAGlance( { data } ) {
	const labels = glanceLabels();
	const named = data.recipients || [];
	const reaching = data.effective_recipients || [];
	const day = dayOptions().find( ( option ) => option.value === String( data.digest_day ) );
	const now = Date.now();
	const quiet = data.maintenance && data.maintenance.active && Date.parse( data.maintenance.until ) > now;

	let sending = __( 'On', 'bettershield' );
	let sendingTone = 'good';
	let sendingDetail = __( 'Sent through WordPress', 'bettershield' );

	if ( data.muted ) {
		sending = __( 'Muted', 'bettershield' );
		sendingTone = 'caution';
		sendingDetail = __( 'No alert or weekly summary is emailed', 'bettershield' );
	} else if ( ! data.digest && ! data.instant_critical ) {
		sending = __( 'Off', 'bettershield' );
		sendingTone = 'caution';
		sendingDetail = __( 'Only a few events still email, like use of the trap password', 'bettershield' );
	} else if ( quiet ) {
		sending = __( 'Maintenance', 'bettershield' );
		sendingTone = 'caution';
		sendingDetail = __( 'Routine alerts are held for now', 'bettershield' );
	}

	// What a message kind's tile says: paused under the mute, else its state.
	const kind = ( on, onWord ) => {
		if ( data.muted ) {
			return __( 'Paused', 'bettershield' );
		}

		return on ? onWord : __( 'Off', 'bettershield' );
	};

	const tiles = [
		{ key: 'sending', icon: 'bell', label: labels.sending, value: sending, tone: sendingTone, detail: sendingDetail },
		{
			key: 'to',
			icon: 'mail',
			label: labels.to,
			value: reaching.length
				? sprintf(
						/* translators: %d: number of email addresses. */
						_n( '%d address', '%d addresses', reaching.length, 'bettershield' ),
						reaching.length
				  )
				: __( 'Nobody', 'bettershield' ),
			tone: reaching.length ? undefined : 'caution',
			detail: named.length ? reaching[ 0 ] : __( 'The admin email', 'bettershield' ),
		},
		/*
		 * Muted, both of these read as off on their rows — the switches are
		 * held down while the mute is on, and put back where they were when
		 * it comes off. The strip says the same, rather than reporting a
		 * setting that is not currently sending anything.
		 */
		{
			key: 'digest',
			icon: 'calendar',
			label: labels.digest,
			value: kind( data.digest, day ? day.label : __( 'On', 'bettershield' ) ),
			tone: ! data.muted && data.digest ? 'good' : undefined,
			detail: data.muted ? __( 'Held while alerts are muted', 'bettershield' ) : data.digest ? __( 'Once a week', 'bettershield' ) : __( 'Not emailed', 'bettershield' ),
		},
		{
			key: 'instant',
			icon: 'zap',
			label: labels.instant,
			value: kind( data.instant_critical, __( 'On', 'bettershield' ) ),
			tone: ! data.muted && data.instant_critical ? 'good' : undefined,
			detail: data.muted ? __( 'Held while alerts are muted', 'bettershield' ) : data.instant_critical ? __( 'High and critical events', 'bettershield' ) : __( 'Not emailed', 'bettershield' ),
		},
	];

	return <Stats label={ __( 'Alerts at a glance', 'bettershield' ) } tiles={ tiles } />;
}

export default function Alerts() {
	const { resource, reload } = useResource( 'alerts' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <AlertsBone /> }>
			{ ( data ) => (
				<>
					<AtAGlance data={ data } />

					{ /*
					   Two cards for two questions. Whether anything is sent at
					   all, and when, is a decision somebody makes once; which
					   things are worth an email is one they come back to.
					*/ }
					<SettingsCard icon="bell" title={ __( 'When alerts are sent, and to whom', 'bettershield' ) }>
						{ data.muted ? (
							<div className="bs-ds-alerts__muted">
								<Alert
									layout="default"
									tone="warning"
									live
									desc={ __(
										'Alerts are muted: no alert or summary is emailed. Account-recovery mail still goes out, and protections keep working.',
										'bettershield'
									) }
								/>
							</div>
						) : null }
						<HostManaged data={ data } />
						<Mute data={ data } />
						<Maintenance state={ data.maintenance } muted={ data.muted } off={ ! data.digest && ! data.instant_critical } />
						<Recipients data={ data } />
					</SettingsCard>

					<SettingsCard icon="mail-check" title={ __( 'What gets emailed', 'bettershield' ) }>
						<Digest data={ data } />
						<Instant data={ data } />
						<InstantTypes data={ data } />
						<AccountNotices data={ data } />
						<Precision precision={ data.precision } />
					</SettingsCard>

					<Never />
				</>
			) }
		</Resource>
	);
}
