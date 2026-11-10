/**
 * Protection › Login & access: the tab in four facts, then who is at the door,
 * sign-in protection, the sign-in switches from the hardening registry, the
 * public forms, the two lists and trusted proxies, and sessions.
 *
 * Two rules govern this screen. Every control that can refuse a sign-in says
 * plainly what it refuses and what stays open, and the way back in (Recovery,
 * one tab over) is referenced where the refusing happens. And nothing here
 * ends the acting administrator's own session without a confirmation that
 * says so by name.
 *
 * The settings below the door are one draft, kept by one Save: a switch or a
 * number changed here is not in force until it is saved.
 */

import './LoginAccess.css';

import { ExternalLink } from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';
import { useEffect, useId, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { listOf } from '../../setup/format';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import { offer } from '../../ui/TierOffer';
import useMutationFocus from '../../ui/useMutationFocus';
import useUnsaved from '../ui/useUnsaved';
import { rangeProblem } from '../../ui/validate';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Default from '../ui/Default';
import Field, { FieldRow } from '../ui/Field';
import InfoTip from '../ui/InfoTip';
import SettingRow, { Saved, SettingsCard, Toggle } from '../ui/Setting';
import Skeleton, { CardBone, StatsBone } from '../ui/Skeleton';
import Stats from '../ui/Stats';
import { Resource } from '../ui/States';
import ListEditor from './AccessLists';
import Attempts from './Attempts';
import Door, { CONNECTION_CARD, runningCount } from './Door';
import HardeningCards from './HardeningCards';
import SafeMode from './SafeMode';
import ActiveSessions from './Sessions';

/*
 * The public forms, and what passing a threshold on each one does.
 *
 * Comments say "held" rather than "refused" because that is what happens, and
 * because the difference is the whole reason this was allowed on a form the
 * site's own readers use: a comment that waits for a person can still be
 * published, and one that was thrown away cannot.
 */
const PUBLIC_FORMS = [
	{
		key: 'comment',
		focus: 'comment_form',
		label: __( 'Send floods of comments to moderation', 'bettershield' ),
		help: __( 'Extra comments go to moderation. Nothing is deleted.', 'bettershield' ),
		tip: __( 'Counted per visitor address. Once one address reaches the number below, its comments wait for your approval. Moderators are never affected.', 'bettershield' ),
		/* translators: %s: a length of time, e.g. "10 minutes". */
		countHelp: __( 'Comments from one connection within %s.', 'bettershield' ),
		hold: true,
	},
	{
		key: 'reset',
		focus: 'reset_form',
		label: __( 'Slow repeated password reset requests', 'bettershield' ),
		help: __( 'Extra requests get the normal reply. Accounts are never affected.', 'bettershield' ),
		tip: __( 'Counted per visitor address. Once one address reaches the number below, it gets the normal reply, so the form never says whether an account exists.', 'bettershield' ),
		/* translators: %s: a length of time, e.g. "15 minutes". */
		countHelp: __( 'Requests from one connection within %s.', 'bettershield' ),
		hold: false,
	},
	{
		key: 'register',
		focus: 'register_form',
		label: __( 'Slow repeated sign-ups', 'bettershield' ),
		help: __( 'Extra sign-ups are told to try again later. Only with open registration.', 'bettershield' ),
		tip: __( 'Counted per visitor address. Once one address reaches the number below, its sign-ups are blocked.', 'bettershield' ),
		/* translators: %s: a length of time, e.g. "1 hour". */
		countHelp: __( 'Sign-ups from one connection within %s.', 'bettershield' ),
		hold: false,
	},
	/*
	 * Not a form, and off until the owner turns it on: every 404 the site
	 * answers runs through it. Closed, it changes only pages that were missing
	 * anyway (#690).
	 */
	{
		key: 'probe',
		label: __( 'Block visitors scanning for hidden files', 'bettershield' ),
		help: __( 'Stops bots that request many missing pages. Real pages keep working; only missing ones get a plain “not found”.', 'bettershield' ),
		tip: __(
			'Counted per visitor address. Once one address reaches the number below, missing pages get a plain “not found”. A private settings file counts straight away.',
			'bettershield'
		),
		/* translators: %s: a length of time, e.g. "10 minutes". */
		countHelp: __( 'Different missing pages one connection asked for within %s.', 'bettershield' ),
		hold: false,
		bare: true,
		off: true,
	},
];

/**
 * Whether a public form's limit is on: as saved, or, where nothing was saved
 * for it, as it ships. Every form ships on except the probe surface.
 *
 * @param {Object} form   One of PUBLIC_FORMS.
 * @param {Object} policy Its policy as saved or drafted.
 * @return {boolean} On.
 */
function formOn( form, policy ) {
	return undefined === ( policy || {} ).enabled ? ! form.off : policy.enabled !== false;
}

/**
 * A counting window in words: whole hours as hours, anything else in minutes.
 *
 * @param {number|string} minutes The window.
 * @return {string} e.g. "10 minutes", "1 hour".
 */
export function windowPhrase( minutes ) {
	const value = Math.max( 1, Number( minutes ) || 1 );

	if ( value >= 60 && 0 === value % 60 ) {
		/* translators: %d: a number of hours. */
		return sprintf( _n( '%d hour', '%d hours', value / 60, 'bettershield' ), value / 60 );
	}

	/* translators: %d: a number of minutes. */
	return sprintf( _n( '%d minute', '%d minutes', value, 'bettershield' ), value );
}

/** The three numbers a form's policy is made of, as the save would take them. */
const FORM_NUMBERS = [ 'threshold', 'window_minutes', 'lockout_minutes' ];

/**
 * What a form's edited numbers would have done over the attempts still
 * recorded, beside what the saved numbers did, read before Save.
 *
 * Absent while the numbers are the saved ones. The table keeps two days and
 * does not record whether a source could be verified, so the sentence says
 * what it was replayed against and that this is the most the numbers could
 * have done.
 *
 * @param {Object} props
 * @param {Object} props.form   The public form.
 * @param {Object} props.policy Its numbers as edited.
 * @param {Object} props.saved  Its numbers as saved.
 */
function FormReplay( { form, policy, saved } ) {
	const numbers = FORM_NUMBERS.map( ( key ) => Number( policy[ key ] ) );
	const changed = FORM_NUMBERS.some( ( key, index ) => numbers[ index ] !== Number( saved[ key ] ) );
	const valid = numbers[ 0 ] >= 3 && numbers[ 0 ] <= 100 && numbers[ 1 ] >= 1 && numbers[ 1 ] <= 1440 && numbers[ 2 ] >= 1 && numbers[ 2 ] <= 1440;
	const [ answer, setAnswer ] = useState( null );
	const [ failed, setFailed ] = useState( '' );

	useEffect( () => {
		setAnswer( null );
		setFailed( '' );

		if ( ! changed || ! valid ) {
			return undefined;
		}

		let alive = true;
		const timer = setTimeout( () => {
			apiFetch( {
				path: `/bettershield/v1/login-protection/replay?surface=${ form.key }&threshold=${ numbers[ 0 ] }&window_minutes=${ numbers[ 1 ] }&lockout_minutes=${ numbers[ 2 ] }`,
			} ).then(
				( result ) => alive && setAnswer( result ),
				( error ) => alive && setFailed( error.message || __( 'The recorded attempts could not be read.', 'bettershield' ) )
			);
		}, 400 );

		return () => {
			alive = false;
			clearTimeout( timer );
		};
	}, [ changed, valid, form.key, ...numbers ] ); // eslint-disable-line react-hooks/exhaustive-deps

	if ( ! changed || ! valid ) {
		return null;
	}

	if ( failed ) {
		return <p className="bs-ds-formgate__replay">{ failed }</p>;
	}

	if ( ! answer ) {
		return null;
	}

	if ( ! answer.attempts ) {
		return (
			<p className="bs-ds-formgate__replay" role="status">
				{ __( 'Nothing was recorded on this form in the last two days, so there is nothing to replay.', 'bettershield' ) }
			</p>
		);
	}

	/*
	 * In pieces, each counted on its own: one string carrying "%d attempts"
	 * and "%d connections" read "from 1 connections", and could not be put
	 * into a language with more than two plural forms.
	 */
	const said = [
		sprintf(
			/* translators: 1: attempts recorded, 2: date and time. */
			_n( 'Against the %1$d attempt recorded since %2$s,', 'Against the %1$d attempts recorded since %2$s,', answer.attempts, 'bettershield' ),
			answer.attempts,
			formatTime( answer.from )
		),
		form.hold
			? sprintf(
					/* translators: 1: attempts the new limits would have sent to moderation, 2: addresses they came from. */
					_n( 'these limits would have sent %1$d to moderation, from %2$d address.', 'these limits would have sent %1$d to moderation, from %2$d addresses.', answer.proposed.closed, 'bettershield' ),
					answer.proposed.caught,
					answer.proposed.closed
			  )
			: form.bare
			? sprintf(
					/* translators: 1: missing pages the new limits would have blocked, 2: addresses they came from. */
					_n( 'these limits would have blocked %1$d, from %2$d address.', 'these limits would have blocked %1$d, from %2$d addresses.', answer.proposed.closed, 'bettershield' ),
					answer.proposed.caught,
					answer.proposed.closed
			  )
			: sprintf(
					/* translators: 1: attempts the new numbers would have refused, 2: addresses they came from. */
					_n( 'these limits would have blocked %1$d, from %2$d address.', 'these limits would have blocked %1$d, from %2$d addresses.', answer.proposed.closed, 'bettershield' ),
					answer.proposed.caught,
					answer.proposed.closed
			  ),
		form.hold
			? sprintf(
					/* translators: 1: attempts the saved numbers held, 2: addresses they came from. */
					_n( 'The saved limits sent %1$d to moderation, from %2$d address.', 'The saved limits sent %1$d to moderation, from %2$d addresses.', answer.saved.closed, 'bettershield' ),
					answer.saved.caught,
					answer.saved.closed
			  )
			: form.bare
			? sprintf(
					/* translators: 1: missing pages the saved numbers answered plainly, 2: addresses they came from. */
					_n( 'The saved limits blocked %1$d, from %2$d address.', 'The saved limits blocked %1$d, from %2$d addresses.', answer.saved.closed, 'bettershield' ),
					answer.saved.caught,
					answer.saved.closed
			  )
			: sprintf(
					/* translators: 1: attempts the saved numbers refused, 2: addresses they came from. */
					_n( 'The saved limits blocked %1$d, from %2$d address.', 'The saved limits blocked %1$d, from %2$d addresses.', answer.saved.closed, 'bettershield' ),
					answer.saved.caught,
					answer.saved.closed
			  ),
	].join( ' ' );

	return (
		<p className="bs-ds-formgate__replay" role="status">
			{ said }{ ' ' }
			{ __( 'This counts every address, so the real number may be lower.', 'bettershield' ) }
			{ /* The comment form holds a comment while it is closed without
			     recording it, so those were never there to replay. */ }
			{ form.hold ? ` ${ __( 'Comments held while the form was closed are not counted.', 'bettershield' ) }` : '' }
			{ answer.truncated ? ` ${ __( 'Only the most recent attempts were read.', 'bettershield' ) }` : '' }
		</p>
	);
}

/**
 * A number with a meaning, and the value it ships with under it.
 *
 * @param {Object}   props
 * @param {string}   props.label     What the number decides.
 * @param {*}        props.help      A line under it.
 * @param {number}   props.min       The smallest it may be.
 * @param {number}   props.max       The largest it may be.
 * @param {*}        props.value     What it holds.
 * @param {boolean}  props.disabled  Whether it can be changed.
 * @param {Function} props.onChange  Called with what was typed.
 * @param {*}        props.fallback  The value it ships with.
 * @param {Function} props.onReset   Puts that back.
 * @param {Function} props.format    How the default is said, where not as itself.
 * @param {boolean}  props.hideLabel The label is the row's title, already on screen.
 * @param {string}   props.className Where the number sits.
 */
function NumberField( { label, help, min, max, value, disabled, onChange, fallback, onReset, format, hideLabel = false, className = '' } ) {
	return (
		<div className={ `bs-ds-number${ className ? ` ${ className }` : '' }` }>
			<Field
				type="number"
				min={ min }
				max={ max }
				label={ label }
				hideLabelFromVision={ hideLabel }
				help={ help }
				value={ String( value ?? '' ) }
				disabled={ disabled }
				onChange={ onChange }
			/>
			<Default value={ value } fallback={ fallback } onReset={ onReset } format={ format } />
		</div>
	);
}

/**
 * One switch, drawn the way a hardening item is: the switch leads, the title
 * and what it does follow, and where it stands is said beside the title.
 *
 * What the switch needs once it is on (the numbers a limit counts with) is
 * under the words and opens with it, so a row that is off is a single line of
 * intent and a row that is on shows what it is set to.
 *
 * @param {Object}   props
 * @param {string}   props.title     What the switch turns on. Also its accessible name.
 * @param {*}        props.help      What that means for a request.
 * @param {boolean}  props.checked   Whether it is on.
 * @param {boolean}  props.disabled  Whether it can be changed.
 * @param {Function} props.onChange  Called with on or off.
 * @param {string}   props.status    Where it stands, when there is more to say than On.
 * @param {*}        props.tip       The why or the how, behind an ⓘ beside the title.
 * @param {Array}    props.topics    "How this works", under the row.
 * @param {string}   props.className Where the row sits.
 * @param {?boolean} props.saved     How it stands as saved, where the switch waits for Save.
 * @param {*}        props.idle      Why a switch that is on does nothing yet, said under it.
 * @param {string}   props.focusKey  The name a link's `?focus=` gives the rule.
 * @param {*}        props.children  What opens when the switch is on.
 */
function Rule( { title, help, tip = null, checked, disabled, onChange, status, topics = null, className = '', saved = null, idle = null, focusKey = undefined, children } ) {
	const id = `bs-ds-rule-${ useId().replace( /[^\w-]/g, '' ) }`;

	/*
	 * A switch that takes effect on Save says so until it is saved: it read
	 * "On" while nothing had been turned on, and leaving the screen then
	 * kept it off (#2075).
	 */
	let badge = <Badge tone={ checked ? 'brand' : 'neutral' }>{ checked ? status || __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }</Badge>;

	if ( null !== saved && Boolean( saved ) !== Boolean( checked ) ) {
		badge = <Badge tone="yellow">{ checked ? __( 'On after Save', 'bettershield' ) : __( 'Off after Save', 'bettershield' ) }</Badge>;
	} else if ( checked && idle ) {
		// On, and nothing it acts on can be read: a green chip beside
		// "Lockouts are off" read as two answers (#2576).
		badge = <Badge tone="yellow">{ __( 'On, not running', 'bettershield' ) }</Badge>;
	}

	return (
		<SettingRow
			id={ id }
			className={ `bs-ds-rule${ className ? ` ${ className }` : '' }` }
			focusKey={ focusKey }
			title={ title }
			about={ help }
			tip={ tip }
			badge={ badge }
			lead={
				<Toggle
					checked={ checked }
					disabled={ disabled }
					onChange={ ( event ) => onChange( Boolean( event && event.target ? event.target.checked : event ) ) }
					labelledBy={ id }
					describedBy={ help ? `${ id }-about` : undefined }
				/>
			}
			topics={ topics }
		>
			{ checked && idle ? <p className="bs-ds-access__note">{ idle }</p> : null }
			{ checked && children ? children : null }
		</SettingRow>
	);
}

/** The four facts' names, shared by the strip and the page's stand-in. */
function glanceLabels() {
	return {
		connection: __( 'Visitor addresses', 'bettershield' ),
		lockouts: __( 'Lockouts', 'bettershield' ),
		rules: __( 'Protections', 'bettershield' ),
		people: __( 'Signed in', 'bettershield' ),
	};
}

/**
 * The page in four facts, before any of the controls that change them.
 *
 * @param {Object} props
 * @param {Object} props.data The login-protection payload.
 */
function AccessSummary( { data } ) {
	const labels = glanceLabels();
	const { resource } = useResource( 'sessions' );
	const resolution = data.resolution || {};
	const active = runningCount( data );
	// The server's count, a read of its own as on Hardening's strip: the tile
	// holds its place until it lands, and says so if it fails.
	const { resource: hardening } = useResource( 'hardening' );
	const signIn = hardening?.data?.count?.screens?.login || null;
	const signInFailed = ! signIn && hardening && 'error' === hardening.status;
	// Counted by the server: the list it sends is one page of it.
	const people = resource && resource.data ? resource.data.total ?? ( resource.data.sessions || [] ).length : null;

	// What it means and where the reason is: "Can't be read" beside plain
	// numbers read as an error, with the cause further down the page (#2522).
	let connected = (
		<>
			{ resolution.ignored_headers ? __( 'Behind a proxy. Lockouts are off.', 'bettershield' ) : __( 'Lockouts are off.', 'bettershield' ) }{ ' ' }
			<a href={ `#${ CONNECTION_CARD }` }>{ __( 'See why', 'bettershield' ) }</a>
		</>
	);

	if ( resolution.confident ) {
		connected = 'direct' === resolution.method ? __( 'Lockouts work', 'bettershield' ) : __( 'Lockouts work (via your proxy)', 'bettershield' );
	}

	const tiles = [
		{
			key: 'connection',
			icon: 'network',
			label: labels.connection,
			value: resolution.confident ? __( 'Readable', 'bettershield' ) : __( 'Not visible', 'bettershield' ),
			detail: connected,
			tone: resolution.confident ? 'good' : 'caution',
		},
		{
			key: 'lockouts',
			icon: 'lock',
			label: labels.lockouts,
			value: String( active ),
			detail: active ? __( 'Active now', 'bettershield' ) : __( 'None active', 'bettershield' ),
			tone: active ? 'caution' : '',
		},
		{
			key: 'rules',
			icon: 'shield-check',
			label: labels.rules,
			value: signIn
				? sprintf(
						/* translators: 1: how many protections are on, 2: how many there are. */
						__( '%1$d of %2$d', 'bettershield' ),
						signIn.on,
						signIn.total
				  )
				: '—',
			detail: signInFailed ? __( 'Could not be read', 'bettershield' ) : __( 'Switched on', 'bettershield' ),
			pending: ! signIn && ! signInFailed,
		},
		{
			key: 'people',
			icon: 'users',
			label: labels.people,
			value: null === people ? '—' : String( people ),
			detail: null === people ? __( 'Could not be read', 'bettershield' ) : _n( 'Account right now', 'Accounts right now', people, 'bettershield' ),
			// The sessions are a read of their own. Until it lands the tile
			// holds its place; a failed read says it has no answer.
			pending: null === people && 'error' !== resource.status,
		},
	];

	return <Stats label={ __( 'Login & Access at a glance', 'bettershield' ) } tiles={ tiles } />;
}

/** "2 of 4 on", for a card's header. */
function onOf( list ) {
	return sprintf(
		/* translators: 1: how many are on, 2: how many there are. */
		__( '%1$d of %2$d on', 'bettershield' ),
		list.filter( Boolean ).length,
		list.length
	);
}

/**
 * Whether two settings say the same thing. A field holds what was typed, so
 * "5" is the saved 5, and a list or a form's own settings are read by what
 * they hold. An edit put back to the saved value is no change: the save bar
 * stayed up for one, and Save sent a no-op.
 *
 * @param {*} a One value.
 * @param {*} b The other.
 * @return {boolean} Whether they are the same answer.
 */
function alike( a, b ) {
	if ( Array.isArray( a ) || Array.isArray( b ) ) {
		return Array.isArray( a ) && Array.isArray( b ) && a.length === b.length && a.every( ( item, index ) => alike( item, b[ index ] ) );
	}

	if ( a && b && 'object' === typeof a && 'object' === typeof b ) {
		return [ ...new Set( [ ...Object.keys( a ), ...Object.keys( b ) ] ) ].every( ( key ) => alike( a[ key ], b[ key ] ) );
	}

	return String( a ?? '' ) === String( b ?? '' );
}

/**
 * Everything on the tab that is saved by its Save: four cards of settings,
 * with the sign-in switches from the hardening registry between the first two
 * (they apply on the switch, as they do on Hardening), and the save bar.
 *
 * @param {Object}  props
 * @param {Object}  props.saved                The settings as saved.
 * @param {Object}  props.defaults             What each ships with.
 * @param {string}  props.scopeNote            What the attempt count covers, where that is less than the account.
 * @param {string}  props.publicScopeNote      The same, for the public forms.
 * @param {boolean} props.proofOfWorkAvailable Whether this connection can do the browser calculation.
 * @param {Array}   props.alsoLimiting         Other plugins limiting sign-in attempts.
 * @param {string}  props.coexistenceUrl       Where the choice between them is made.
 * @param {Object}  props.hostBanLine          Whether this server can write the auth-log line, and whether its host decided it.
 * @param {boolean} props.lockoutsRun          Whether this site can read visitor addresses, so lockouts can run.
 */
function ProtectionSettings( { saved, defaults, scopeNote, publicScopeNote, proofOfWorkAvailable, alsoLimiting = [], coexistenceUrl = '', hostBanLine = {}, lockoutsRun = true } ) {
	const { saveLoginProtection, reopenSetup, busy } = useStore();
	const [ draft, setDraft ] = useState( null );
	// The settings this bar's own cards have edited since the last save.
	const [ edited, setEdited ] = useState( [] );
	const [ proxiesText, setProxiesText ] = useState( ( saved.trusted_proxies || [] ).join( ', ' ) );
	const saving = isWorking( busy, 'login-protection' );
	const value = draft || saved;
	const fallback = defaults || {};
	// Only what these cards edited: a setting another control on the tab saved
	// since the first edit is not an unsaved change of theirs.
	const dirty = null !== draft && edited.some( ( key ) => ! alike( draft[ key ], saved[ key ] ) );
	// Leaving with the bar up asks first, rather than dropping the edits.
	useUnsaved( dirty );
	// The save bar leaves with the draft it saved, so the Sessions card's
	// heading, the last thing above it, takes the keyboard.
	const sessionsBar = useRef( null );
	const afterSave = useMutationFocus( sessionsBar );

	// Whether a session limit can be kept on this site. Read from the sessions
	// resource, which is the one that knows; undefined until it has loaded,
	// and only an outright false changes what the field says.
	const { resource: sessionsResource } = useResource( 'sessions' );
	const capSupported = sessionsResource && sessionsResource.data ? sessionsResource.data.cap_supported : undefined;

	const set = ( patch ) => {
		setDraft( { ...value, ...patch } );
		setEdited( ( keys ) => [ ...new Set( [ ...keys, ...Object.keys( patch ) ] ) ] );
	};

	// A blank number is not a number: sending Number('') would save 0 —
	// "never" for a timeout, "no cap" for a limit — as if the reader had
	// chosen it. The public forms' numbers too, which the server refuses
	// blank; a form's number not yet touched is not in the draft at all.
	const numbers = [ 'threshold', 'window_minutes', 'lockout_minutes', 'idle_minutes', 'session_cap' ];
	const surfaces = value.surfaces || {};
	const incomplete =
		numbers.some( ( key ) => String( value[ key ] ).trim() === '' ) ||
		Object.values( surfaces ).some( ( policy ) =>
			[ 'threshold', 'window_minutes', 'lockout_minutes' ].some( ( key ) => undefined !== ( policy || {} )[ key ] && String( policy[ key ] ).trim() === '' )
		);

	// Each proxy checked as the lists are, the first problem named with the
	// entry it is about: this field had no check and only Save refused it.
	const proxiesProblem = proxiesText
		.split( ',' )
		.map( ( entry ) => entry.trim() )
		.filter( Boolean )
		.map( ( entry ) => {
			const wrong = rangeProblem( entry, { widest: true } );

			return wrong
				? sprintf(
						/* translators: 1: the entry as typed, 2: what is wrong with it. */
						__( '%1$s: %2$s', 'bettershield' ),
						entry,
						wrong
				  )
				: null;
		} )
		.find( Boolean );


	const discard = () => {
		setDraft( null );
		setEdited( [] );
		setProxiesText( ( saved.trusted_proxies || [] ).join( ', ' ) );
	};

	/*
	 * Only what this bar's own cards changed. The draft is a copy of every
	 * saved setting, taken at the first edit, and sending all of it put back
	 * whatever another control on the tab saved meanwhile: answering the
	 * Cloudflare question above the cards and then pressing Save reversed the
	 * answer, with nothing to say so. So the keys sent are the ones these
	 * cards edited, and of those only the ones that differ from what is saved
	 * now. The server keeps every setting left out.
	 */
	const changes = () =>
		Object.fromEntries(
			edited
				.filter( ( key ) => ! alike( value[ key ], saved[ key ] ) )
				.map( ( key ) => [ key, numbers.includes( key ) ? Number( value[ key ] ) : value[ key ] ] )
		);

	const save = () =>
		saveLoginProtection(
			changes(),
			afterSave( ( result ) => {
				// Passed in rather than chained on, so it still runs when a
				// password confirmation let the save through.
				setDraft( null );
				setEdited( [] );
				// The route answers with the settings as saved, under
				// `settings`; an empty box here would read as an empty list,
				// and the next address typed would replace it.
				setProxiesText( ( ( ( result && result.settings ) || value ).trusted_proxies || [] ).join( ', ' ) );
			} )
		);

	return (
		<>
			<SettingsCard
				icon="key-round"
				title={ __( 'Sign-in protection', 'bettershield' ) }
				// Counted as saved, as the tile above counts: an unsaved switch
				// says so on its own row.
				trailing={ <Badge>{ onOf( [ saved.attempt_limit && lockoutsRun, saved.honeypot, saved.proof_of_work, saved.new_location_notice ] ) }</Badge> }
			>
				<Rule
					className="bs-ds-attempts"
					focusKey="attempt_limit"
					title={ __( 'Sign-in attempt limits', 'bettershield' ) }
					help={ __( 'After too many wrong passwords from one address, that address can’t sign in for a while.', 'bettershield' ) }
					checked={ value.attempt_limit }
					saved={ Boolean( saved.attempt_limit ) }
					disabled={ saving }
					onChange={ ( on ) => set( { attempt_limit: on } ) }
					idle={
						lockoutsRun ? null : (
							<>
								{ __( 'Not running until this site can see visitor addresses.', 'bettershield' ) }{ ' ' }
								<a href={ `#${ CONNECTION_CARD }` }>{ __( 'See why', 'bettershield' ) }</a>
							</>
						)
					}
					status={ sprintf(
						/* translators: 1: failures allowed, 2: minutes they are counted within. */
						__( '%1$s tries in %2$s min', 'bettershield' ),
						value.threshold,
						value.window_minutes
					) }
					topics={ [
						{
							key: 'how',
							label: __( 'How this works', 'bettershield' ),
							lead: __( 'Only addresses this site can read reliably are locked out.', 'bettershield' ),
							text: __( 'If the site can’t read an address reliably, it doesn’t lock it out, so you never lock out a whole office or yourself.', 'bettershield' ),
							body: (
								<p>
									{ __(
										'Each repeat lockout in the same day lasts twice as long, up to a day. Unlocking it here, or from the emailed link, starts the count again.',
										'bettershield'
									) }
								</p>
							),
							note: {
								tone: 'info',
								text: __( 'If your site sits behind a proxy you haven’t listed under Addresses of your CDN or proxy, lockouts stay off so visitors aren’t locked out together.', 'bettershield' ),
							},
						},
					] }
				>
					{ /*
					   What the count covers, where that is less than the account it
					   protects. An account is the same account on every site of a
					   network while these counters are this site's own, so the
					   number below is a number of tries for this site.
					*/ }
					{ scopeNote ? <p className="bs-ds-access__note">{ scopeNote }</p> : null }

					{ /* Another plugin counting the same failures, said beside the
					     switch it overlaps, with where the choice is made. A
					     finished setup is closed to its own address, so this
					     opens it again first, as Settings does. */ }
					{ value.attempt_limit && alsoLimiting.length ? (
						<Alert
							layout="default"
							tone="info"
							desc={ sprintf(
								/* translators: %s: the name of another plugin, or the names of several, e.g. "Limit Login Attempts Reloaded and Loginizer". */
								_n(
									'%s also limits sign-in attempts, so the lower limit applies. Only BetterShield’s own lockouts are listed and lifted here.',
									'%s also limit sign-in attempts, so the lower limit applies. Only BetterShield’s own lockouts are listed and lifted here.',
									alsoLimiting.length,
									'bettershield'
								),
								listOf( alsoLimiting )
							) }
							actions={
								coexistenceUrl ? (
									<Button type="secondary" size="sm" isBusy={ isWorking( busy, 'setup-reopen' ) } onClick={ () => reopenSetup( 'coexistence' ) }>
										{ __( 'Choose a Plugin in Quick Setup', 'bettershield' ) }
									</Button>
								) : null
							}
						/>
					) : null }

					<FieldRow align="start">
						<NumberField
							label={ __( 'Failures allowed', 'bettershield' ) }
							min={ 3 }
							max={ 100 }
							value={ value.threshold }
							disabled={ saving }
							onChange={ ( threshold ) => set( { threshold } ) }
							fallback={ fallback.threshold }
							onReset={ () => set( { threshold: fallback.threshold } ) }
						/>
						<NumberField
							label={ __( 'Counted within (minutes)', 'bettershield' ) }
							min={ 1 }
							max={ 1440 }
							value={ value.window_minutes }
							disabled={ saving }
							onChange={ ( windowMinutes ) => set( { window_minutes: windowMinutes } ) }
							fallback={ fallback.window_minutes }
							onReset={ () => set( { window_minutes: fallback.window_minutes } ) }
						/>
						<NumberField
							label={ __( 'Lockout lasts (minutes)', 'bettershield' ) }
							min={ 1 }
							max={ 1440 }
							value={ value.lockout_minutes }
							disabled={ saving }
							onChange={ ( lockoutMinutes ) => set( { lockout_minutes: lockoutMinutes } ) }
							fallback={ fallback.lockout_minutes }
							onReset={ () => set( { lockout_minutes: fallback.lockout_minutes } ) }
						/>
					</FieldRow>
				</Rule>

				<Rule
					focusKey="honeypot"
					title={ __( 'Block simple bots on forms', 'bettershield' ) }
					help={ __( 'Stops many bots on sign-in, sign-up and comment forms, with no puzzle for people.', 'bettershield' ) }
					checked={ value.honeypot }
					saved={ Boolean( saved.honeypot ) }
					disabled={ saving }
					onChange={ ( honeypot ) => set( { honeypot } ) }
					topics={ [
						{
							key: 'how',
							label: __( 'How this works', 'bettershield' ),
							lead: __( 'A hidden field and a timer on sign-in, registration and comment forms.', 'bettershield' ),
							points: [
								__( 'A script that fills every field is refused.', 'bettershield' ),
								__( 'So is one that submits faster than any person could.', 'bettershield' ),
							],
						},
					] }
				/>

				<Rule
					focusKey="proof_of_work"
					// Named as the finding names it, with what it does under it.
					title={ __( 'Ask for a sign-in puzzle after wrong passwords', 'bettershield' ) }
					help={
						false === proofOfWorkAvailable
							? __( 'Needs HTTPS. Your site isn’t using HTTPS yet, so this is off.', 'bettershield' )
							: __( 'Adds a check after wrong passwords: the browser solves a short task before the next try. People don’t notice it.', 'bettershield' )
					}
					tip={
						false === proofOfWorkAvailable
							? null
							: __( 'After a few wrong passwords from one connection, the next try needs a small browser task. Without JavaScript, a visitor is told so and never locked out for it.', 'bettershield' )
					}
					checked={ value.proof_of_work }
					saved={ Boolean( saved.proof_of_work ) }
					disabled={ saving }
					onChange={ ( proofOfWork ) => set( { proof_of_work: proofOfWork } ) }
				/>

				{ /*
				  * Last in this card because it is the one thing here that writes
				  * to somebody other than the site's administrator, and that is
				  * worth reading before it is switched on.
				  */ }
				<Rule
					title={ __( 'Tell account holders about sign-ins from a new network', 'bettershield' ) }
					help={ __( 'Emails the person when their account signs in from somewhere new. At most once a day.', 'bettershield' ) }
					tip={ __( 'It goes to the account’s owner, not the alert list, and blocks nothing.', 'bettershield' ) }
					checked={ value.new_location_notice }
					saved={ Boolean( saved.new_location_notice ) }
					disabled={ saving }
					onChange={ ( notice ) => set( { new_location_notice: notice } ) }
				/>
			</SettingsCard>

			{ /*
			   The hardening items about the sign-in door, read here rather than
			   in the hardening list: someone looking for the address of their own
			   login page comes to this tab. Beside the other sign-in switches.
			*/ }
			<HardeningCards screen="login" />

			<SettingsCard
				icon="hourglass"
				title={ __( 'Request protection', 'bettershield' ) }
				trailing={
					<>
						<InfoTip label={ __( 'Why some addresses aren’t limited', 'bettershield' ) } placement="bottom-end">
							{ __( 'When the site can’t read a visitor’s address reliably, it records the attempt but never locks it out.', 'bettershield' ) }
						</InfoTip>
						<Badge>{ onOf( PUBLIC_FORMS.map( ( form ) => formOn( form, ( saved.surfaces || {} )[ form.key ] ) ) ) }</Badge>
					</>
				}
				intro={
					<>
						{ /*
						   Unconditional, the promise was untrue while the server
						   firewall line is on: a form that turns a connection away
						   writes the line too, and the firewall then bans that
						   network for every page, the dashboard included (#1846).
						*/ }
						{ /*
						   Shorter, with the unverifiable connection behind the ⓘ
						   in the header (#1323). The firewall's reach is a
						   lock-out risk, so it stays in sight.
						*/ }
						{ hostBanOn( value, hostBanLine )
							? __(
								'These limits also go to your server firewall, which can block a whole network from your site and dashboard. The recovery link can’t undo that.',
								'bettershield'
							)
							: __( 'These limits are separate from sign-in lockouts, so they never lock you out of your site.', 'bettershield' ) }
						{ /*
						   These forms count on the same per-site tables the sign-in
						   gate does, so they owe the reader the same sentence about
						   what the number covers on a network.
						*/ }
						{ publicScopeNote ? <span className="bs-ds-access__scope">{ publicScopeNote }</span> : null }
					</>
				}
			>
				{ PUBLIC_FORMS.map( ( form ) => {
					const policy = surfaces[ form.key ] || {};
					const formDefault = ( fallback.surfaces || {} )[ form.key ] || {};
					const savedPolicy = ( saved.surfaces || {} )[ form.key ] || {};
					const update = ( patch ) =>
						set( {
							surfaces: {
								...surfaces,
								[ form.key ]: { ...policy, ...patch },
							},
						} );

					return (
						<Rule
							key={ form.key }
							className="bs-ds-formgate"
							focusKey={ form.focus }
							title={ form.label }
							help={ form.help }
							tip={ form.tip || null }
							checked={ formOn( form, policy ) }
							saved={ formOn( form, savedPolicy ) }
							disabled={ saving }
							onChange={ ( enabled ) => update( { enabled } ) }
							status={ sprintf(
								/* translators: %s: the submission that closes the form, e.g. 10. */
								__( 'Limit: %s', 'bettershield' ),
								policy.threshold ?? formDefault.threshold ?? ''
							) }
						>
							<FieldRow align="start">
								<NumberField
									label={ __( 'Limit per visitor', 'bettershield' ) }
									min={ 3 }
									max={ 100 }
									value={ policy.threshold }
									disabled={ saving }
									onChange={ ( threshold ) => update( { threshold } ) }
									fallback={ formDefault.threshold }
									onReset={ () => update( { threshold: formDefault.threshold } ) }
								/>
								<NumberField
									label={ __( 'Counted within (minutes)', 'bettershield' ) }
									min={ 1 }
									max={ 1440 }
									value={ policy.window_minutes }
									disabled={ saving }
									onChange={ ( windowMinutes ) => update( { window_minutes: windowMinutes } ) }
									fallback={ formDefault.window_minutes }
									onReset={ () => update( { window_minutes: formDefault.window_minutes } ) }
								/>
								<NumberField
									label={ __( 'Block lasts (minutes)', 'bettershield' ) }
									min={ 1 }
									max={ 1440 }
									value={ policy.lockout_minutes }
									disabled={ saving }
									onChange={ ( lockoutMinutes ) => update( { lockout_minutes: lockoutMinutes } ) }
									fallback={ formDefault.lockout_minutes }
									onReset={ () => update( { lockout_minutes: formDefault.lockout_minutes } ) }
								/>
							</FieldRow>
							{ /* Under the row, so the three fields keep one width, as in
							     Sign-in protection (#2576). */ }
							<p className="bs-ds-access__note">{ sprintf( form.countHelp, windowPhrase( policy.window_minutes ?? formDefault.window_minutes ) ) }</p>
							<FormReplay form={ form } policy={ { ...formDefault, ...policy } } saved={ { ...formDefault, ...savedPolicy } } />
						</Rule>
					);
				} ) }
			</SettingsCard>

			<SettingsCard
				icon="list-filter"
				title={ __( 'Allow and block lists', 'bettershield' ) }
				trailing={
					<Badge>
						{ sprintf(
							/* translators: 1: entries on the allow list, 2: entries on the block list. */
							__( '%1$d allowed · %2$d blocked', 'bettershield' ),
							( value.allowlist || [] ).length,
							( value.blocklist || [] ).length
						) }
					</Badge>
				}
			>
				<ListEditor
					title={ __( 'Always allowed', 'bettershield' ) }
					intro={ __( 'Addresses that are never locked out.', 'bettershield' ) }
					explain={ {
						lead: __( 'An agency working from fixed addresses puts them here.', 'bettershield' ),
						note: {
							tone: 'info',
							text: __( 'Only IP addresses can go here, because a browser name is easy to fake.', 'bettershield' ),
						},
					} }
					entries={ value.allowlist || [] }
					onChange={ ( allowlist ) => set( { allowlist } ) }
					withUa={ false }
					withUsername={ false }
				/>

				<ListEditor
					focusKey="blocklist"
					title={ __( 'Never allowed to sign in', 'bettershield' ) }
					intro={ __( 'Blocked from signing in. They can still view the site.', 'bettershield' ) }
					note={ __( 'A username on its own is blocked from every address. Add an address too, and it is only blocked from there.', 'bettershield' ) }
					explain={ {
						lead: __( 'Each kind of entry is matched in its own way.', 'bettershield' ),
						points: [
							__( 'Addresses only work when this site can read visitors’ real addresses (see the top of this page).', 'bettershield' ),
							__( 'A browser or bot name is blocked wherever it comes from.', 'bettershield' ),
							__( 'A listed name always gets the wrong-password reply.', 'bettershield' ),
							__(
								'Anyone who tries a blocked username is locked out at once, even if no such account exists.',
								'bettershield'
							),
							__( 'Only verified connections are locked out, never Always allowed addresses.', 'bettershield' ),
						],
						note: {
							tone: 'success',
							text: __( 'The account you are signed in with cannot be added.', 'bettershield' ),
						},
					} }
					entries={ value.blocklist || [] }
					onChange={ ( blocklist ) => set( { blocklist } ) }
					withUa={ true }
					withUsername={ true }
				/>

				<SettingRow
					className="bs-ds-proxies"
					focusKey="trusted_proxies"
					title={ __( 'Addresses of your CDN or proxy', 'bettershield' ) }
					about={ __( 'If your host or a firewall service sits in front of your site, add its address so lockouts see real visitors. Ask your host if unsure.', 'bettershield' ) }
					topics={ [
						{
							key: 'how',
							label: __( 'How this works', 'bettershield' ),
							lead: __( 'Until it is listed here, visitors coming through it are never locked out, because the site can’t see who they are.', 'bettershield' ),
							note: {
								tone: 'info',
								text: __( 'Cloudflare needs no entry; its published ranges are recognized.', 'bettershield' ),
							},
						},
					] }
				>
					<Field
						width="md"
						label={ __( 'Your proxy’s IP addresses, separated by commas', 'bettershield' ) }
						placeholder="192.0.2.10, 192.0.2.0/24"
						value={ proxiesText }
						disabled={ saving }
						error={ proxiesProblem || '' }
						onChange={ ( raw ) => {
							// The text is kept as typed, a trailing comma included,
							// and parsed into the list; rendering the parse back
							// would eat the comma as it was typed and make a second
							// entry impossible to type.
							setProxiesText( raw );
							set( {
								trusted_proxies: raw
									.split( ',' )
									.map( ( s ) => s.trim() )
									.filter( Boolean ),
							} );
						} }
					/>
				</SettingRow>
			</SettingsCard>

			<HostFirewall value={ value } saved={ saved } status={ hostBanLine } disabled={ saving } onChange={ ( on ) => set( { host_ban_line: on } ) } />

			<SettingsCard
				icon="users-round"
				title={
					<span className="bs-ds-access__focus" ref={ sessionsBar } tabIndex={ -1 }>
						{ __( 'Signed-in devices', 'bettershield' ) }
					</span>
				}
			>
				<SettingRow
					title={ __( 'Sign out after idle (minutes)', 'bettershield' ) }
					about={ __( 'Sign people out after this many idle minutes (5 to 1,440, that is 24 hours). 0 turns it off. This includes you.', 'bettershield' ) }
					control={
						<NumberField
							className="bs-ds-number--end"
							hideLabel
							label={ __( 'Sign out after idle (minutes)', 'bettershield' ) }
							min={ 0 }
							// What the server accepts. The 1 to 4 gap below it
							// cannot be a minimum while 0 is allowed, so the
							// text of the row says it.
							max={ 1440 }
							value={ value.idle_minutes }
							disabled={ saving }
							onChange={ ( idle ) => set( { idle_minutes: idle } ) }
							fallback={ fallback.idle_minutes }
							onReset={ () => set( { idle_minutes: fallback.idle_minutes } ) }
							// Zero is a meaning, not a number, and "Default: 0" would
							// leave the reader to work out which meaning.
							format={ () => __( 'no timeout', 'bettershield' ) }
						/>
					}
				/>

				<SettingRow
					title={ __( 'Devices signed in at once, per account', 'bettershield' ) }
					about={
						// A site that swapped WordPress's session storage has no
						// entries to remove, so the limit cannot be kept there: a
						// setting that reports itself applied while allowing every
						// extra session is worse than one honestly unavailable.
						false === capSupported
							? __(
									'Not available on this site: another plugin manages sign-ins. Signing people out still works.',
									'bettershield'
							  )
							: __( '0 means no limit. When someone goes over, their oldest sign-in is signed out.', 'bettershield' )
					}
					control={
						<NumberField
							className="bs-ds-number--end"
							hideLabel
							label={ __( 'Devices signed in at once, per account', 'bettershield' ) }
							min={ 0 }
							max={ 100 }
							value={ value.session_cap }
							disabled={ saving || false === capSupported }
							onChange={ ( cap ) => set( { session_cap: cap } ) }
							fallback={ fallback.session_cap }
							onReset={ () => set( { session_cap: fallback.session_cap } ) }
							format={ () => __( 'no limit', 'bettershield' ) }
						/>
					}
				/>

				{ /*
				  * Under the two limits: this is the part of the card that
				  * reports rather than configures, read after a change to see who
				  * the change applies to.
				  */ }
				<ActiveSessions />
			</SettingsCard>

			{ dirty ? (
				<div className="bs-ds-savebar" role="status">
					<span className="bs-ds-savebar__label">
						{ incomplete ? __( 'Fill in every number to save.', 'bettershield' ) : __( 'Unsaved changes.', 'bettershield' ) }
					</span>
					<span className="bs-ds-savebar__actions">
						<Button type="ghost" size="sm" disabled={ saving } onClick={ discard }>
							{ __( 'Discard', 'bettershield' ) }
						</Button>
						<Button type="primary" size="sm" isBusy={ saving } disabled={ saving || incomplete } onClick={ save }>
							{ __( 'Save', 'bettershield' ) }
						</Button>
					</span>
				</div>
			) : (
				<Saved forKey="login-protection" />
			) }
		</>
	);
}

/**
 * Whether the auth-log line is written here: unavailable is off, a host's
 * decision stands, and on a network's subsite the main site's answer does,
 * because the firewall bans for every site on the server.
 *
 * @param {Object} value  The settings being edited.
 * @param {Object} status `available`, `forced`, `network` and `on`, from the server.
 * @return {boolean} Whether a pause writes the line.
 */
function hostBanOn( value, status = {} ) {
	const forced = 'boolean' === typeof status.forced ? status.forced : null;

	if ( false === status.available ) {
		return false;
	}

	if ( null !== forced ) {
		return forced;
	}

	return true === status.network ? Boolean( status.on ) : Boolean( value.host_ban_line );
}

/**
 * The line a firewall jail on this server reads when a connection is paused.
 * Its own card, and outside the counts on this tab and the Overview: it does
 * nothing for a site whose server runs no such jail, so an "off" here is not
 * a protection missing.
 *
 * Shown as enforced. A host can decide it for every site it runs, and a
 * server without PHP's system log has nothing to write it with; either way
 * the switch is held, and the help says why.
 *
 * @param {Object}   props
 * @param {Object}   props.value    The settings being edited.
 * @param {Object}   props.saved    The settings as saved.
 * @param {Object}   props.status   `available` and `forced`, from the server.
 * @param {boolean}  props.disabled Whether a save is running.
 * @param {Function} props.onChange Called with the new state.
 */
function HostFirewall( { value, saved = value, status, disabled, onChange } ) {
	const available = false !== status.available;
	const forced = 'boolean' === typeof status.forced ? status.forced : null;
	const network = true === status.network;
	const checked = hostBanOn( value, status );
	const savedOn = hostBanOn( saved, status );

	/*
	 * One line, with what the firewall then does in sight: it blocks the
	 * whole network on every page, the dashboard included, which is a way
	 * to be locked out and so never only behind an ⓘ (#1323).
	 */
	let help = __( 'For hosts that run a server firewall. Locked-out networks are then blocked from the whole site, your dashboard included. Ask your host before turning this on.', 'bettershield' );
	let tip = null;

	if ( ! available ) {
		help = __( 'Not available: your host doesn’t allow this.', 'bettershield' );
	} else if ( true === forced ) {
		help = __( 'Your host turned this on for all its sites.', 'bettershield' );
	} else if ( false === forced ) {
		help = __( 'Your host turned this off for all its sites.', 'bettershield' );
	} else if ( network ) {
		help = __( 'Set from the main site, because a firewall ban covers every site on this server.', 'bettershield' );
		tip = __( 'Lines from this site also respect the main site’s allowed list.', 'bettershield' );
	}

	return (
		<SettingsCard
			icon="server"
			title={ __( 'Server firewall', 'bettershield' ) }
			trailing={ <Badge>{ savedOn ? __( 'On', 'bettershield' ) : __( 'Off', 'bettershield' ) }</Badge> }
		>
			<Rule
				className="bs-ds-hostban"
				title={ __( 'Send lockouts to the server’s firewall', 'bettershield' ) }
				help={ help }
				tip={ tip }
				checked={ checked }
				saved={ savedOn }
				disabled={ disabled || ! available || null !== forced || network }
				onChange={ onChange }
				status={ null !== forced ? __( 'Set by your host', 'bettershield' ) : network ? __( 'Set from the main site', 'bettershield' ) : '' }
				topics={ [
					{
						key: 'how',
						label: __( 'How this works', 'bettershield' ),
						lead: __( 'The firewall is told a network, never a full address or username.', 'bettershield' ),
						points: [
							__( 'A network here means a block of neighboring addresses, not one visitor.', 'bettershield' ),
							__( 'Comment floods sent to moderation are never passed to the firewall.', 'bettershield' ),
							__( 'Networks on your Always allowed list are never sent. The recovery link can’t undo a firewall block.', 'bettershield' ),
						],
						note: {
							tone: 'info',
							text: __(
								'A firewall block covers a whole network, more than a lockout here does. Your host has to set it up.',
								'bettershield'
							),
						},
					},
					// The setup files and the line a jail reads are for whoever
					// runs the server, not for the owner reading "How this
					// works" (#2576).
					{
						key: 'host',
						label: __( 'For your host', 'bettershield' ),
						lead: __( 'Setup files for fail2ban are in the plugin’s fail2ban folder. Each lockout writes a line like this one:', 'bettershield' ),
						body: <code className="bs-ds-hostban__sample">bettershield: lockout surface=signin network=203.0.113.0/24 minutes=15 site=example.com</code>,
					},
				] }
			/>
		</SettingsCard>
	);
}

/**
 * The one quiet place this tab may say a paid tier adds to it: at its foot,
 * nowhere near a lockout or a warning, and only where the server named an
 * offer. The words for the link come from the server too.
 *
 * @param {Object} props
 * @param {string} props.summary What the tier adds here, in one sentence.
 */
function TierNote( { summary } ) {
	if ( ! offer ) {
		return null;
	}

	return (
		<p className="bs-ds-access__tier">
			<span>{ summary || offer.summary || '' }</span>
			<ExternalLink href={ offer.url } className="bs-ds-access__tierlink">
				{ sprintf(
					/* translators: %s: the name BetterShield Ultra. */
					__( 'About %s', 'bettershield' ),
					offer.name
				) }
			</ExternalLink>
		</p>
	);
}

/**
 * The tab before its settings have landed: the four facts, then the first
 * cards in their order.
 */
export function LoginAccessBone() {
	return (
		<Skeleton label={ __( 'Loading Login & Access…', 'bettershield' ) }>
			<StatsBone labels={ Object.values( glanceLabels() ) } />
			<CardBone rows={ [ '40%', '30%' ] } />
			<CardBone rows={ [ '55%', '48%', '40%', '62%' ] } toggle />
			<CardBone rows={ [ '45%', '50%', '38%' ] } toggle />
		</Skeleton>
	);
}

/*
 * The screen, in the order the questions come: what is happening at the door
 * right now, then what decides who gets through, then the forms anybody can
 * reach, then the lists that override all of it for particular people, then
 * how long anybody stays in. The strip above answers each of those in a word
 * first, for the reader who only came to check.
 */
export default function LoginAccess() {
	const { resource, reload } = useResource( 'loginProtection' );

	return (
		<>
			<SafeMode />
			<Resource resource={ resource } onRetry={ reload } loading={ <LoginAccessBone /> }>
				{ ( data ) => (
					<>
						<AccessSummary data={ data } />

						<Door data={ data } onRecheck={ reload } />

						<Attempts blocklist={ ( data.settings || {} ).blocklist || [] } />

						<ProtectionSettings
							saved={ data.settings }
							defaults={ data.defaults }
							scopeNote={ data.scope_note }
							alsoLimiting={ data.also_limiting || [] }
							coexistenceUrl={ data.coexistence_url || '' }
							publicScopeNote={ data.scope_note_public }
							proofOfWorkAvailable={ data.proof_of_work_available }
							hostBanLine={ data.host_ban_line || {} }
							lockoutsRun={ Boolean( ( data.resolution || {} ).confident ) }
						/>

						<TierNote
							summary={ __(
								'BetterShield Ultra adds a sign-in setup step for required roles, trusted devices and a per-role two-factor report.',
								'bettershield'
							) }
						/>
					</>
				) }
			</Resource>
		</>
	);
}
