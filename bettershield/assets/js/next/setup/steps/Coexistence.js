/**
 * Coexistence Check: one row per job two security plugins would both do.
 *
 * Every row starts on BetterShield, unless a choice was already saved: the
 * step never recommends keeping another plugin. Nothing changes until
 * Save & Continue, and Skip changes nothing at all.
 *
 * Every Use BetterShield answer has an ⓘ: the settings that come over from the
 * plugins its card names, or what BetterShield does there when nothing does.
 * Saving brings them over, and Skip does not (#1964).
 *
 * The step's one main button switches off each plugin whose every job with a
 * choice is BetterShield's, through WordPress's own Deactivate. Once every job
 * is BetterShield's it reads Migrate & Deactivate, with how many plugins it
 * takes where that is more than one, and Save & Continue otherwise. A plugin
 * that only moves the sign-in address is never counted: it goes on its own
 * press. The ⓘ beside it says which plugins go and what else
 * stops with them (#2113, #2232). WordPress
 * switches a plugin off on the owner's press; BetterShield never does by
 * itself. An account WordPress gives no such link is pointed to the Plugins
 * screen instead (#2232).
 *
 * One card per job: its name and the choice under it. A job with no choice
 * says what the other plugin does there.
 */

import './Coexistence.css';

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../../ui/Alert';
import Button from '../../ui/Button';
import InfoTip from '../../ui/InfoTip';
import { SettingsCard } from '../../ui/Setting';
import Choice from '../Choice';
import Frame, { Footer } from '../Frame';
import { useSetup } from '../context';
import { ROUTES } from '../api';
import viaCore, { marked } from '../core';
import { listOf } from '../../../setup/format';
import { formatCount } from '../../../ui/count';
import { announce } from '../../../ui/announce';
import brand from '../brand';

/** Each job's tile in its card's header. */
const ICONS = {
	login_limits: 'lock',
	two_factor: 'fingerprint',
	login_url: 'log-in',
	firewall: 'shield',
	vulnerabilities: 'shield-alert',
	https_redirect: 'globe',
};

/**
 * What the owner reads for one job.
 *
 * @param {Object}  row                 The row from the server.
 * @param {boolean} vulnerabilityChecks Whether BetterShield's own vulnerability check is on.
 * @param {string}  home                WordPress's own sign-in address, e.g. /wp-login.php.
 * @return {{title: string, statement: string, options: Array, note: string}} The words.
 */
function words( row, vulnerabilityChecks = false, home = '/wp-login.php' ) {
	const names = listOf( row.plugins );
	const count = row.plugins.length;

	switch ( row.job ) {
		case 'login_limits':
			return {
				title: __( 'Sign-in attempt limits', 'bettershield' ),
				/* translators: %s: one or more plugin names. */
				statement: sprintf( _n( '%s already limits sign-in attempts.', '%s already limit sign-in attempts.', count, 'bettershield' ), names ),
				options: [
					{ value: 'bettershield', label: sprintf( /* translators: %s: the plugin's name. */ __( 'Use %s', 'bettershield' ), brand() ), note: __( 'Recommended', 'bettershield' ) },
					/* translators: %s: one or more plugin names. */
					{ value: 'keep', label: sprintf( __( 'Keep %s', 'bettershield' ), names ), note: sprintf( /* translators: %s: the plugin's name. */ __( '%s’s sign-in limit is turned off', 'bettershield' ), brand() ) },
				],
			};
		case 'two_factor':
			return {
				title: __( 'Two-factor', 'bettershield' ),
				/* translators: %s: one or more plugin names. */
				statement: sprintf( _n( '%s already handles two-factor.', '%s already handle two-factor.', count, 'bettershield' ), names ),
				options: [
					{ value: 'bettershield', label: sprintf( /* translators: %s: the plugin's name. */ __( 'Use %s', 'bettershield' ), brand() ), note: __( 'Recommended', 'bettershield' ) },
					/* translators: %s: one or more plugin names. */
					{ value: 'keep', label: sprintf( __( 'Keep %s', 'bettershield' ), names ), note: sprintf( /* translators: %s: the plugin's name. */ __( '%s won’t set up its own two-factor', 'bettershield' ), brand() ) },
				],
			};
		case 'login_url': {
			// On here too: at the very address that plugin answers at, both work; at another, only one can.
			let note = '';

			if ( row.ours_on ) {
				note = row.ours_shared
					? /* translators: 1: this plugin's name, 2: one or more plugin names. */
					  sprintf( __( '%1$s answers at the same sign-in address as %2$s, so the two don’t clash.', 'bettershield' ), brand(), names )
					: /* translators: 1: this plugin's name, 2: one or more plugin names. */
					  sprintf( __( '%1$s’s sign-in address is on too, and only one address can work. Turn off %1$s’s under Login & Access, or deactivate %2$s.', 'bettershield' ), brand(), names );
			}

			return {
				title: __( 'Sign-in address', 'bettershield' ),
				/* translators: %s: one or more plugin names. */
				statement: sprintf( _n( '%s handles your sign-in address.', '%s handle your sign-in address.', count, 'bettershield' ), names ),
				note,
				options: [
					{
						value: 'bettershield',
						label: sprintf( /* translators: %s: the plugin's name. */ __( 'Use %s', 'bettershield' ), brand() ),
						// Recommended only where the address people use comes over with it.
						note: row.address_carried
							? __( 'Recommended', 'bettershield' )
							: /* translators: %s: WordPress's own sign-in address, e.g. /wp-login.php. */
							  sprintf( __( 'Your sign-in page goes back to %s', 'bettershield' ), home ),
					},
					/* translators: %s: one or more plugin names. */
					{ value: 'keep', label: sprintf( __( 'Keep %s', 'bettershield' ), names ), note: sprintf( /* translators: %s: the plugin's name. */ __( '%s won’t change your sign-in address', 'bettershield' ), brand() ) },
				],
			};
		}
		case 'vulnerabilities':
			return {
				title: __( 'Known vulnerabilities', 'bettershield' ),
				/* translators: %s: one or more plugin names. */
				statement: sprintf( _n( '%s checks your plugins for known security holes and blocks attempts to use them.', '%s check your plugins for known security holes and block attempts to use them.', count, 'bettershield' ), names ),
				// Said as it is here: BetterShield's own check may be on,
				// and patching at a firewall is the other plugin's (#2233).
				note: vulnerabilityChecks
					? sprintf( /* translators: %s: the plugin's name. */ __( '%s also checks your plugins for known security holes and tells you. That plugin keeps blocking attempts to use them.', 'bettershield' ), brand() )
					: sprintf( /* translators: %s: the plugin's name. */ __( '%s can also check your plugins for known security holes once you switch its check on. That plugin keeps blocking attempts to use them.', 'bettershield' ), brand() ),
				options: [],
			};
		case 'https_redirect':
			return {
				title: __( 'HTTPS redirect', 'bettershield' ),
				/* translators: %s: one or more plugin names. */
				statement: sprintf( _n( '%s redirects plain HTTP to HTTPS.', '%s redirect plain HTTP to HTTPS.', count, 'bettershield' ), names ),
				note: row.ours_on
					? /* translators: 1: this plugin's name, 2: one or more plugin names. */
					  sprintf( __( '%1$s’s redirect is on too. Turn off %1$s’s under Hardening, or deactivate %2$s.', 'bettershield' ), brand(), names )
					: /* translators: %s: the plugin's name. */
					  sprintf( __( '%s’s own redirect stays off.', 'bettershield' ), brand() ),
				options: [],
			};
		default:
			// No card for a job the server does not state, a firewall among
			// them: this step does not tell an owner to keep another plugin
			// (#2298).
			return null;
	}
}

/**
 * Each job as a sentence names it.
 *
 * @return {Object<string, string>} Job => words.
 */
function jobWords() {
	return {
		login_limits: __( 'sign-in attempt limits', 'bettershield' ),
		two_factor: __( 'two-factor', 'bettershield' ),
		login_url: __( 'the sign-in address', 'bettershield' ),
		vulnerabilities: __( 'blocking known security holes', 'bettershield' ),
		https_redirect: __( 'the HTTPS redirect', 'bettershield' ),
	};
}

/**
 * The jobs a plugin does here that the choices on screen do not hand to
 * BetterShield. Switching the plugin off stops every one of them, so any
 * left means it stays on (#2113). A job with no choice, such as a firewall,
 * is never handed over.
 *
 * @param {Object} plugin  The plugin, with its jobs.
 * @param {Object} choices Job => choice, as on screen.
 * @return {string[]} The jobs it is still kept for.
 */
function keptFor( plugin, choices ) {
	return ( plugin.jobs || [] ).filter( ( job ) => 'bettershield' !== choices[ job ] );
}

/**
 * The jobs a plugin is kept for by a choice on screen. A job with no choice,
 * such as a firewall, is left out: nothing on this step can hand it over,
 * so it never stands between the owner and the Plugins screen (#2232).
 *
 * @param {Object} plugin  The plugin, with its jobs.
 * @param {Object} choices Job => choice, as on screen.
 * @return {string[]} The jobs a choice still keeps it for.
 */
function chosenFor( plugin, choices ) {
	return ( plugin.jobs || [] ).filter( ( job ) => Object.prototype.hasOwnProperty.call( choices, job ) && 'bettershield' !== choices[ job ] );
}

/**
 * The plugin's other jobs that stop with it: those no choice here hands over.
 *
 * @param {Object} plugin  The plugin, with its jobs.
 * @param {Object} choices Job => choice, as on screen.
 * @return {string[]} Each in words, e.g. "its firewall".
 */
function otherJobs( plugin, choices ) {
	const named = {
		firewall: __( 'its firewall', 'bettershield' ),
		backups: __( 'its backups', 'bettershield' ),
		login_url: __( 'its custom sign-in address', 'bettershield' ),
		vulnerabilities: __( 'its blocking of known security holes', 'bettershield' ),
		https_redirect: __( 'its HTTPS redirect', 'bettershield' ),
	};

	return keptFor( plugin, choices )
		.filter( ( job ) => named[ job ] )
		.map( ( job ) => named[ job ] );
}

/**
 * What becomes of the backup codes of the accounts that move, led by a space
 * to follow a sentence, or '' when no account moves.
 *
 * @param {Object} move What one plugin brings over, from the server.
 * @return {string} The sentence, or ''.
 */
export function backupCodesLine( move ) {
	const moving = move?.moving || 0;
	const codes = move?.codes_moving || 0;

	if ( moving < 1 ) {
		return '';
	}

	if ( codes < 1 ) {
		return ` ${ __( 'Backup codes don’t move. Each person makes new ones on their profile.', 'bettershield' ) }`;
	}

	return codes < moving
		? ` ${ __( 'Unused backup codes move too. Anyone with none left makes new ones on their profile.', 'bettershield' ) }`
		: ` ${ __( 'Unused backup codes move too.', 'bettershield' ) }`;
}

/**
 * What switching a two-factor plugin off does to the accounts set up with
 * it: the ones whose authenticator app comes over as it is, and the ones
 * that cannot, by name. A plugin whose secrets cannot come over moves
 * nobody, so every account it set up is named. Only where its accounts
 * cannot be read at all, the general sentence.
 *
 * Short, for the main button's ⓘ, where what becomes of the backup codes is
 * said too. Where the line before already counts the accounts that move,
 * `counted` leaves them out (#2832).
 *
 * @param {Object}  plugin          The plugin, with its file and jobs.
 * @param {Array}   moves           What each two-factor plugin brings over, from the server.
 * @param {Object}  options
 * @param {boolean} options.counted Whether to count the accounts that keep their app.
 * @return {string} The sentences, or ''.
 */
export function twoFactorMove( plugin, moves, { counted = true } = {} ) {
	if ( ! ( plugin.jobs || [] ).includes( 'two_factor' ) ) {
		return '';
	}

	const move = ( moves || [] ).find( ( entry ) => entry.file === plugin.file );

	if ( ! move ) {
		return sprintf( /* translators: %s: the plugin's name. */ __( 'Anyone enrolled in its two-factor signs in with only their password until they set up %s’s.', 'bettershield' ), brand() );
	}

	const parts = [];

	if ( counted && move.moving > 0 ) {
		/* translators: %s: how many accounts. */
		parts.push( sprintf( _n( '%s account keeps its authenticator app.', '%s accounts keep their authenticator app.', move.moving, 'bettershield' ), formatCount( move.moving ) ) );
	}

	if ( move.staying > 0 ) {
		const more = move.staying - ( move.named || [] ).length;
		const names = more > 0 ? [ ...move.named, sprintf( /* translators: %s: how many more accounts. */ _n( '%s more', '%s more', more, 'bettershield' ), formatCount( more ) ) ] : move.named || [];

		parts.push(
			sprintf(
				/* translators: %s: the names of the accounts. */
				_n(
					'%s must set up two-factor again, and signs in with only a password until then.',
					'%s must set up two-factor again, and sign in with only a password until then.',
					move.staying,
					'bettershield'
				),
				listOf( names )
			)
		);
	}

	return parts.join( ' ' );
}

// The one plugin here whose switching off also undoes more than the address (#2748).
const WP_HIDE = 'wp-hide-security-enhancer/wp-hide.php';

/**
 * What else stops when the owner deactivates a plugin on the Plugins
 * screen: its jobs that no choice here hands to BetterShield, and the
 * two-factor its enrolled users lose. Said beside the pointer, so leaving
 * to deactivate it never loses a protection unsaid (#2113, #2232).
 *
 * @param {Object} plugin  The plugin, with its name and jobs.
 * @param {Object} choices Job => choice, as on screen.
 * @param {Array}  moves   What each two-factor plugin brings over.
 * @param {Object} opts    `twoFactor: false` leaves out the two-factor
 *                         line, for a card that already says it.
 * @return {string} The sentences, or ''.
 */
function alsoStops( plugin, choices, moves, { twoFactor = true } = {} ) {
	const left = otherJobs( plugin, choices );
	const parts = left.length
		? [
				sprintf(
					/* translators: 1: a plugin's name, 2: what else it does here, e.g. "its firewall". */
					__( 'Deactivating %1$s also switches off %2$s.', 'bettershield' ),
					plugin.name,
					listOf( left )
				),
		  ]
		: [];

	if ( twoFactor ) {
		parts.push( twoFactorMove( plugin, moves ) );
	}

	// Its path rewrites, headers, captcha and two-factor stop with it (#2748).
	if ( WP_HIDE === plugin.file ) {
		/* translators: %s: a plugin's name. */
		parts.push( sprintf( __( '%s also stops renaming your site’s folders and drops its other changes.', 'bettershield' ), plugin.name ) );
	}

	return parts.filter( Boolean ).join( ' ' );
}

/**
 * Why a plugin cannot be switched off from here, when it cannot.
 *
 * @param {string} why  `network` or `capability`.
 * @param {string} name The plugin's name.
 * @return {string} The sentence.
 */
function heldBack( why, name, networkPlugins = '' ) {
	if ( 'network' !== why ) {
		/* translators: %s: a plugin's name. */
		return sprintf( __( 'Your account cannot deactivate %s on this site. Ask an administrator who can.', 'bettershield' ), name );
	}

	if ( ! networkPlugins ) {
		/* translators: %s: a plugin's name. */
		return sprintf( __( '%s is active across the whole network, so a network administrator has to deactivate it in Network Admin › Plugins.', 'bettershield' ), name );
	}

	return (
		<>
			{ sprintf(
				/* translators: %s: a plugin's name. */
				__( '%s is active across the whole network, so it is deactivated in Network Admin › Plugins.', 'bettershield' ),
				name
			) }{ ' ' }
			<a href={ networkPlugins } target="_blank" rel="noopener noreferrer">
				{ __( 'Open Network Admin › Plugins', 'bettershield' ) }
			</a>
		</>
	);
}

export default function Coexistence() {
	const { state, run, hold, busy, advance, setNotice, links, keepFocus, stayOnStep, refresh } = useSetup();
	/*
	 * Plugins switched off from this step, for their Turn It Back On: once
	 * off, a plugin is no longer among the rows. And those core left on, by
	 * file, to say so where each was pressed. A press can reach several.
	 */
	const [ switchedOff, setSwitchedOff ] = useState( [] );
	const [ stillOn, setStillOn ] = useState( [] );
	const rows = state.coexistence?.rows || [];
	// What switching each two-factor plugin off brings over (#2762).
	const moves = state.coexistence?.two_factor_move || [];
	// Another plugin's settings the step can bring over.
	const offered = state.coexistence?.imports || [];
	// WordPress's own sign-in page, under any folder it is installed in.
	const signInHome = state.coexistence?.sign_in_default || '/wp-login.php';

	const [ choices, setChoices ] = useState( () => {
		const initial = {};

		rows.forEach( ( row ) => {
			if ( 'choice' === row.kind ) {
				initial[ row.job ] = row.choice;
			}
		} );

		return initial;
	} );

	/*
	 * A plugin doing several jobs is offered once, under the last of its
	 * cards, so one confirmation covers everything it stops.
	 */
	const lastCardOf = ( plugin ) =>
		rows
			.filter( ( row ) => 'choice' === row.kind && ( row.deactivate || [] ).some( ( other ) => other.file === plugin.file ) )
			.map( ( row ) => row.job )
			.pop();

	/*
	 * Pointed to the Plugins screen: where switching it off here is off
	 * (#2107), or where it is on but the plugin still does a job no choice
	 * here hands over, such as a firewall (#2232). Either way only once
	 * every job with a choice is BetterShield's, under the last of its cards.
	 */
	const pointed = ( plugin, job ) =>
		! chosenFor( plugin, choices ).length && ( 'off' === plugin.why || ( '' === plugin.why && keptFor( plugin, choices ).length > 0 ) ) && lastCardOf( plugin ) === job;

	// Reachable by WordPress's own link, so the main button can take it.
	const onePress = ( plugin ) => Boolean( plugin.link ) && ! keptFor( plugin, choices ).length;

	// The choices, and the settings to bring over where there are any.
	/*
	 * What each source carries under the choices on screen: a row that
	 * waits on a job (the sign-in numbers, while another plugin limits
	 * sign-ins) is shown and counted only while that job is BetterShield's,
	 * as Save applies the choice before it imports (#2498).
	 */
	const carrying = offered
		.map( ( source ) => ( { ...source, carried: source.carried.filter( ( title ) => ! ( source.waits || {} )[ title ] || 'bettershield' === choices[ source.waits[ title ] ] ) } ) )
		.filter( ( source ) => source.carried.length > 0 );

	/*
	 * The plugins this step could switch off: each whose every job with a
	 * choice is BetterShield's on screen, once, where WordPress gives a link
	 * this account may use. The cards already say what else stops with each.
	 */
	const listed = [];

	rows.forEach( ( row ) =>
		( row.deactivate || [] ).forEach( ( plugin ) => {
			if ( listed.some( ( other ) => other.file === plugin.file ) ) {
				return;
			}

			const jobs = plugin.jobs || [];

			if ( ! chosenFor( plugin, choices ).length && jobs.some( ( job ) => 'bettershield' === choices[ job ] ) ) {
				listed.push( plugin );
			}
		} )
	);

	// How many other plugins the step names, for its heading.
	const others = new Set( rows.flatMap( ( row ) => row.plugins || [] ) ).size;

	const movable = listed.filter( ( plugin ) => ( 'off' === plugin.why || '' === plugin.why ) && ( plugin.link || plugin.deactivate_url ) );

	// The plugins the main button switches off.
	const switchingOff = movable;

	/*
	 * BetterShield keeps one set of attempt-limit numbers. Of the plugins the
	 * main button brings over, the one whose numbers rank strictest keeps
	 * them, as the import does; the others bring only the rest, and say so
	 * under what doesn't come over.
	 */
	const bringsLimits = ( source ) => Boolean( source.limits ) && ( ! source.limits.waits || 'bettershield' === choices[ source.limits.waits ] );
	const limitsFrom = carrying
		.filter( bringsLimits )
		.sort( ( a, b ) => a.limits.rank - b.limits.rank );
	const limitsKept = limitsFrom[ 0 ];
	const limitsLost = ( source ) => Boolean( limitsKept ) && limitsFrom.includes( source ) && source !== limitsKept;

	const imports = carrying
		.map( ( source ) => ( limitsLost( source ) ? { ...source, carried: source.carried.filter( ( title ) => ! source.limits.drops.includes( title ) ) } : source ) )
		.filter( ( source ) => source.carried.length > 0 );

	const body = () => ( imports.length ? { choices, import: imports.map( ( source ) => source.key ) } : { choices } );

	/*
	 * The main button switches a plugin off. It read Save & Continue while
	 * any job was kept with another plugin, and still switched off the ones
	 * whose jobs were handed over (#2871).
	 */
	const migrating = switchingOff.length > 0;

	/*
	 * The step's main button, for what a press does. It counts the plugins it
	 * takes: "All" read as every plugin listed (#2754).
	 */
	const primaryLabel = () => {
		if ( ! migrating ) {
			return __( 'Save & Continue', 'bettershield' );
		}

		return 1 === switchingOff.length ? __( 'Migrate & Deactivate Plugin', 'bettershield' ) : __( 'Migrate & Deactivate Plugins', 'bettershield' );
	};

	// WordPress's own Deactivate for each, one after another.
	const throughCore = ( plugins ) => plugins.reduce( ( done, plugin ) => done.then( () => viaCore( plugin.link || marked( plugin.deactivate_url ) ) ), Promise.resolve() );

	/*
	 * Read after a press that reached these plugins: those off get their way
	 * back, and each core left on is named, where one name hid the rest.
	 * Answers with the ones left on.
	 */
	const settle = ( plugins, answer ) => {
		const left = plugins.filter( ( plugin ) => isActive( answer, plugin.file ) );
		const off = plugins.filter( ( plugin ) => ! left.includes( plugin ) );

		setSwitchedOff( ( list ) => [
			...list.filter( ( entry ) => ! off.some( ( plugin ) => plugin.file === entry.file ) ),
			...off.map( ( plugin ) => ( { file: plugin.file, name: plugin.name, activate_url: plugin.activate_url || '' } ) ),
		] );
		setStillOn( left.map( ( plugin ) => plugin.file ) );

		if ( left.length ) {
			/* translators: %s: one or more plugin names. */
			announce( sprintf( _n( '%s is still on.', '%s are still on.', left.length, 'bettershield' ), listOf( left.map( ( plugin ) => plugin.name ) ) ) );
		}

		return left;
	};

	/*
	 * Save the choices, then switch those plugins off through WordPress's own
	 * Deactivate, one after another, and move on. Choosing BetterShield and
	 * pressing Save left the other plugin running beside it. A plugin core
	 * left on keeps the step on screen, saying so under its card or its tick.
	 */
	const save = () =>
		run( 'coexistence', ROUTES.coexistence, body() ).then( ( result ) => {
			if ( ! result ) {
				return undefined;
			}

			if ( ! switchingOff.length ) {
				advance();

				return undefined;
			}

			stayOnStep( 'coexistence' );
			setStillOn( [] );
			/* translators: %s: one or more plugin names. */
			announce( sprintf( __( 'Deactivating %s…', 'bettershield' ), listOf( switchingOff.map( ( plugin ) => plugin.name ) ) ) );

			return hold( 'coexistence', () =>
				throughCore( switchingOff )
					.then( () => refresh() )
					.then( ( answer ) => {
						if ( ! settle( switchingOff, answer ).length ) {
							advance();
						}
					} )
			);
		} );

	// Whether the setup, as read, still has the plugin doing a job here.
	const isActive = ( answer, file ) =>
		! answer || ( answer.state?.coexistence?.rows || [] ).some( ( row ) => ( row.deactivate || [] ).some( ( plugin ) => plugin.file === file ) );

	// Turn a plugin switched off here back on, through core's own Activate.
	const turnBackOn = ( entry ) =>
		hold( `activate:${ entry.file }`, () =>
			viaCore( entry.activate_url )
				.then( () => refresh() )
				.then( ( answer ) => {
					if ( answer && isActive( answer, entry.file ) ) {
						setSwitchedOff( ( list ) => list.filter( ( other ) => other.file !== entry.file ) );
						/* translators: %s: a plugin's name. */
						announce( sprintf( __( '%s is on again.', 'bettershield' ), entry.name ) );
						keepFocus();

						return;
					}

					/* translators: %s: a plugin's name. */
					setNotice( sprintf( __( '%s could not be turned back on here. Activate it from the Plugins screen.', 'bettershield' ), entry.name ) );
				} )
		);

	// What was switched off here, each with its way back.
	const offCards = switchedOff.map( ( entry ) => {
		const working = `activate:${ entry.file }` === busy;

		return (
			<Alert
				key={ `off:${ entry.file }` }
				layout="default"
				tone="success"
				/* translators: %s: a plugin's name. */
				desc={ sprintf( __( '%s is off. Its settings are kept, so turning it back on picks up where it was.', 'bettershield' ), entry.name ) }
				actions={
					entry.activate_url ? (
						<Button
							type="secondary"
							size="sm"
							className="bs-ds-setup__wrap"
							isBusy={ working }
							disabled={ null !== busy }
							accessibleWhenDisabled={ working }
							onClick={ () => turnBackOn( entry ) }
							/* translators: %s: a plugin's name. */
							aria-label={ sprintf( __( 'Turn %s Back On', 'bettershield' ), entry.name ) }
						>
							{ __( 'Turn It Back On', 'bettershield' ) }
						</Button>
					) : (
						<Button type="secondary" size="sm" className="bs-ds-setup__wrap" trailing="external-link" trailingTone="2" href={ links.plugins } target="_blank" rel="noopener noreferrer">
							{ __( 'Open the Plugins Screen', 'bettershield' ) }
						</Button>
					)
				}
			/>
		);
	} );

	/*
	 * What a save here brought over from a plugin no longer offered for
	 * import, where its card was: a Deactivate takes the card away (#2607).
	 */
	const broughtOver = ( state.coexistence?.imported || [] )
		.filter( ( row ) => row.count > 0 && ! imports.some( ( source ) => source.name === row.name ) )
		.map( ( row ) => (
			<Alert
				key={ `imported:${ row.name }` }
				layout="default"
				tone="success"
				/* translators: 1: how many settings, 2: a plugin's name. */
				desc={ sprintf( _n( 'Brought over %1$s setting from %2$s.', 'Brought over %1$s settings from %2$s.', row.count, 'bettershield' ), formatCount( row.count ), row.name ) }
			/>
		) );

	const stillOnNote = ( plugin ) =>
		stillOn.includes( plugin.file ) ? (
			<Alert
				layout="default"
				tone="warning"
				/* translators: %s: a plugin's name. */
				desc={ sprintf( __( '%s is still on. Something on this site kept it on. Deactivate it from the Plugins screen.', 'bettershield' ), plugin.name ) }
				actions={
					<Button type="secondary" size="sm" className="bs-ds-setup__wrap" trailing="external-link" trailingTone="2" href={ links.plugins } target="_blank" rel="noopener noreferrer">
						{ __( 'Open the Plugins Screen', 'bettershield' ) }
					</Button>
				}
			/>
		) : null;

	/*
	 * Every Use BetterShield answer has an ⓘ. It lists the settings that come
	 * over from the plugins its card names; a plugin named by no card with a
	 * choice is listed on the first card that has one. A card with nothing to
	 * bring over says what BetterShield does there instead.
	 */
	const choiceRows = rows.filter( ( row ) => 'choice' === row.kind && words( row ) );
	const tipFor = {};

	imports.forEach( ( source ) => {
		const named = choiceRows.filter( ( one ) => ( one.plugins || [] ).includes( source.name ) );

		( named.length ? named : choiceRows.slice( 0, 1 ) ).forEach( ( row ) => {
			tipFor[ row.job ] = [ ...( tipFor[ row.job ] || [] ), source ];
		} );
	} );

	// What BetterShield does on a card with nothing to bring over.
	const doesHere = ( row ) => {
		const names = listOf( row.plugins || [] );

		switch ( row.job ) {
			case 'login_limits':
				/* translators: 1: this plugin's name, 2: one or more plugin names. */
				return sprintf( __( '%1$s limits failed sign-ins with its own numbers. Nothing comes over from %2$s for this.', 'bettershield' ), brand(), names );
			case 'two_factor':
				/* translators: %s: this plugin's name. */
				return sprintf( __( '%s asks for a code from an authenticator app when people sign in.', 'bettershield' ), brand() );
			case 'login_url':
				return row.address_carried
					? /* translators: 1: this plugin's name, 2: one or more plugin names. */
					  sprintf( __( '%1$s answers at the sign-in address %2$s uses now.', 'bettershield' ), brand(), names )
					: /* translators: 1: one or more plugin names, 2: WordPress's own sign-in address, e.g. /wp-login.php. */
					  sprintf( __( '%1$s’s address doesn’t come over. Your sign-in page goes back to %2$s until you choose a new one under Login & Access.', 'bettershield' ), names, signInHome );
			default:
				/* translators: %s: this plugin's name. */
				return sprintf( __( '%s takes over this job.', 'bettershield' ), brand() );
		}
	};

	// On the two-factor card, which accounts keep their authenticator app.
	const accountLines = ( row ) =>
		'two_factor' === row.job
			? ( row.deactivate || [] )
					.map( ( plugin ) => ( { plugin, line: `${ twoFactorMove( plugin, moves ) }${ backupCodesLine( moves.find( ( entry ) => entry.file === plugin.file ) ) }`.trim() } ) )
					.filter( ( { line } ) => line )
					.map( ( { plugin, line } ) => (
						<span key={ `accounts:${ plugin.file }` }>
							<strong>{ plugin.name }:</strong> { line }
						</span>
					) )
			: [];

	/*
	 * What else stops with each plugin the main button switches off, said
	 * once, on the first card that names it. The two-factor card's account
	 * lines already say what its accounts get.
	 */
	const stopsFor = {};

	switchingOff.forEach( ( plugin ) => {
		const row = choiceRows.find( ( one ) => ( one.deactivate || [] ).some( ( entry ) => entry.file === plugin.file ) ) || choiceRows[ 0 ];

		if ( row ) {
			stopsFor[ row.job ] = [ ...( stopsFor[ row.job ] || [] ), plugin ];
		}
	} );

	const stopLines = ( row ) =>
		( stopsFor[ row.job ] || [] )
			.map( ( plugin ) => {
				const twoFactor = 'two_factor' !== row.job;
				const codes = twoFactor ? backupCodesLine( moves.find( ( entry ) => entry.file === plugin.file ) ) : '';

				return { plugin, line: `${ alsoStops( plugin, choices, moves, { twoFactor } ) }${ codes }`.trim() };
			} )
			.filter( ( { line } ) => line )
			.map( ( { plugin, line } ) => (
				<span key={ `stops:${ plugin.file }` }>
					<strong>{ plugin.name }:</strong> { line }
				</span>
			) );

	const useTip = ( row ) => {
		const sources = tipFor[ row.job ] || [];

		if ( ! sources.length ) {
			return (
				<InfoTip label={ sprintf( /* translators: %s: this plugin's name. */ __( 'About using %s here', 'bettershield' ), brand() ) }>
					<span className="bs-ds-setup-coex__tip">
						<span>{ doesHere( row ) }</span>
						{ accountLines( row ) }
						{ stopLines( row ) }
					</span>
				</InfoTip>
			);
		}

		return (
			<InfoTip label={ __( 'Settings that come over', 'bettershield' ) }>
				<span className="bs-ds-setup-coex__tip">
					{ sources.map( ( source ) => (
						<span key={ source.key }>
							<strong>
								{ sprintf(
									/* translators: %s: a plugin's name. */
									__( 'From %s:', 'bettershield' ),
									source.name
								) }
							</strong>{ ' ' }
							{ listOf( source.carried ) }
						</span>
					) ) }
					{ accountLines( row ) }
					<span>
						{ sprintf(
							/* translators: %s: the plugin's name. */
							__( '%s copies these when you continue. The other plugin’s own settings stay as they are.', 'bettershield' ),
							brand()
						) }
					</span>
					{ stopLines( row ) }
				</span>
			</InfoTip>
		);
	};

	// Nothing left to choose: every plugin that shared a job is switched off.
	if ( ! rows.length ) {
		return (
			<Frame
				title={ __( 'Each job has one plugin now', 'bettershield' ) }
				subtitle={ sprintf( /* translators: %s: the plugin's name. */ __( 'No other active security plugin shares a job with %s, so there is nothing left to choose here.', 'bettershield' ), brand() ) }
				footer={ <Footer noSkip primary={ { label: __( 'Continue', 'bettershield' ), onClick: () => advance() } } /> }
			>
				{ offCards }
				{ broughtOver }
			</Frame>
		);
	}

	return (
		<Frame
			title={
				others > 1
					? /* translators: %s: how many other security plugins. */
					  sprintf( _n( '%s other security plugin is active', '%s other security plugins are active', others, 'bettershield' ), formatCount( others ) )
					: __( 'Another security plugin is active', 'bettershield' )
			}
			subtitle={ sprintf( /* translators: %s: the plugin's name. */ __( 'Switch to %s for a seamless security experience.', 'bettershield' ), brand() ) }
			footer={
				<Footer
					primary={ {
						label: primaryLabel(),
						onClick: save,
						busy: 'coexistence' === busy,
					} }
				/>
			}
		>
			{ offCards }
			{ rows.map( ( row ) => {
				const text = words( row, Boolean( state.coexistence?.vulnerability_checks ), signInHome );
				const chosen = choices[ row.job ];

				if ( ! text ) {
					return null;
				}

				return (
					<SettingsCard key={ row.job } icon={ ICONS[ row.job ] || 'shield' } title={ text.title } intro={ 'choice' === row.kind ? undefined : text.statement }>
						{ 'choice' === row.kind ? (
							<div className="bs-ds-setup-card__body">
								<Choice
									legend={ text.title }
									quiet
									value={ chosen }
									options={ text.options.map( ( option ) => ( 'bettershield' === option.value ? { ...option, tip: useTip( row ) } : option ) ) }
									onChange={ ( value ) => setChoices( { ...choices, [ row.job ]: value } ) }
								/>
								{ text.note ? <p className="bs-ds-setup__note">{ text.note }</p> : null }
								{ 'bettershield' === chosen && ( row.deactivate || [] ).some( ( plugin ) => ! onePress( plugin ) && ! plugin.deactivate_url && pointed( plugin, row.job ) ) ? (
									<Alert
										layout="default"
										tone="info"
										desc={ [
											sprintf(
												/* translators: 1: one or more plugin names, 2: this plugin's name. */
												__( 'Deactivate %1$s on the Plugins screen when ready. %2$s never switches it off.', 'bettershield' ),
												listOf( row.deactivate.filter( ( plugin ) => ! onePress( plugin ) && ! plugin.deactivate_url && pointed( plugin, row.job ) ).map( ( plugin ) => plugin.name ) ),
												brand()
											),
											...row.deactivate.filter( ( plugin ) => ! onePress( plugin ) && ! plugin.deactivate_url && pointed( plugin, row.job ) ).map( ( plugin ) => alsoStops( plugin, choices, moves ) ),
										]
											.filter( Boolean )
											.join( ' ' ) }
										actions={
											<Button type="secondary" size="sm" className="bs-ds-setup__wrap" trailing="external-link" trailingTone="2" href={ links.plugins } target="_blank" rel="noopener noreferrer">
												{ __( 'Open the Plugins Screen', 'bettershield' ) }
											</Button>
										}
									/>
								) : null }
							</div>
						) : null }
						{ 'choice' !== row.kind && text.note ? (
							<div className="bs-ds-setup-card__body">
								<p className="bs-ds-setup__note">{ text.note }</p>
							</div>
						) : null }
					</SettingsCard>
				);
			} ) }

			{ broughtOver }

			{ movable
				.filter( ( plugin ) => stillOn.includes( plugin.file ) )
				.map( ( plugin ) => (
					<div key={ `still:${ plugin.file }` } className="bs-ds-setup-coex__stack">
						{ stillOnNote( plugin ) }
					</div>
				) ) }
			{ listed
				.filter( ( plugin ) => ! movable.includes( plugin ) && '' !== plugin.why && 'off' !== plugin.why )
				.map( ( plugin ) => (
					<p key={ `held:${ plugin.file }` } className="bs-ds-setup__note">
						{ heldBack( plugin.why, plugin.name, links.networkPlugins ) }
					</p>
				) ) }
		</Frame>
	);
}
