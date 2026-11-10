/**
 * Your Site: the two facts that decide whether protection could lock people
 * out, and where alerts go.
 *
 * Who signs in decides whether the next step offers to require two-factor of
 * administrators. Whether a proxy sits in front decides which address is the
 * visitor's — the commonest way a sign-in limit locks everybody out at once is
 * treating a proxy's one address as every visitor's. It is detected where it
 * can be and pre-selected, and the owner's answer is the one that counts.
 *
 * The alert settings are today's defaults, shown so the owner knows where
 * alerts go; nothing changes unless something here is changed.
 *
 * Three cards: the two questions with their answers, and what an answer
 * means in an alert under them; then the alerts: the addresses, and the two
 * kinds of email as switch rows.
 *
 * None of them moves the score, so Protect folds them under More settings,
 * with sensible answers already given: who signs in as "Just me", where
 * alerts go as one line with Change opening the addresses. The proxy question
 * is asked up front instead while BetterShield cannot tell how visits arrive,
 * because it decides whether sign-in lockouts can work. The parts are handed
 * to Protect to place, with whether the fold must open: muted alerts, an
 * address to fix, or an answer refused.
 */

import './YourSite.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../../ui/Alert';
import Badge from '../../ui/Badge';
import Button from '../../ui/Button';
import Field from '../../ui/Field';
import Icon from '../../ui/Icon';
import InfoTip from '../../ui/InfoTip';
import SettingRow, { SettingsCard } from '../../ui/Setting';
import Choice from '../Choice';
import { useSetup } from '../context';
import { ROUTES } from '../api';
import { looksLikeEmail } from '../steps';
import brand from '../brand';

/**
 * The rows the recipient list starts with. The administration address is
 * always a recipient already and is not the owner's to remove here.
 *
 * @param {Object} alerts The alert settings from the server.
 * @return {Array<{email: string, locked: boolean, key: number}>} The rows.
 */
function startingRows( alerts ) {
	const admin = String( alerts.admin_email || '' ).toLowerCase();
	const list = Array.isArray( alerts.recipients ) && alerts.recipients.length ? alerts.recipients : [ alerts.admin_email ];

	return list.map( ( email, index ) => ( {
		email,
		locked: String( email ).toLowerCase() === admin,
		key: index,
	} ) );
}

/**
 * What is wrong with each row, if anything: not an address, or one already
 * in the list above it. A blank row is simply left out when saving.
 *
 * @param {Array} rows The rows.
 * @return {Object} Row key => problem.
 */
function problemsIn( rows ) {
	const seen = new Set();
	const problems = {};

	rows.forEach( ( row ) => {
		const value = String( row.email || '' ).trim().toLowerCase();

		if ( ! value ) {
			return;
		}

		if ( ! looksLikeEmail( value ) ) {
			/*
			 * A whole address that fails holds a character the site would
			 * refuse, and saying "enter a whole address" would not tell the
			 * reader which part is wrong.
			 */
			problems[ row.key ] = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test( value )
				? __( 'This address has a character email addresses cannot have. Check for a stray character or space.', 'bettershield' )
				: __( 'Enter a whole email address, like name@example.com.', 'bettershield' );
		} else if ( seen.has( value ) ) {
			problems[ row.key ] = __( 'This address is already in the list.', 'bettershield' );
		}

		seen.add( value );
	} );

	return problems;
}

/**
 * A refused save, said beside the address it is about, or null when it names
 * none of the addresses that were sent.
 *
 * The schema's own refusal says only "Invalid parameter(s): recipients", and
 * names the row in its details, `recipients[1]`; the alert settings name the
 * address in their sentence. Either way the answer reached the reader as a
 * banner under the form, naming neither the address nor what was wrong.
 *
 * @param {?Object} error The step's last failure.
 * @param {Array}   sent  What the save sent: { key, email } in order.
 * @return {?Object} { key, email, message }.
 */
function refusalFor( error, sent ) {
	if ( ! error || 'site' !== error.key ) {
		return null;
	}

	const said = error.params && 'string' === typeof error.params.recipients ? error.params.recipients : '';
	const at = /recipients\[(\d+)\]/.exec( said );
	let row = at ? sent[ Number( at[ 1 ] ) ] : null;

	if ( ! row && 'string' === typeof error.message ) {
		row = sent.find( ( item ) => item.email && error.message.includes( item.email ) ) || null;
	}

	// WordPress's own refusal names no row. Where only one address could be
	// meant, the one the owner typed rather than the locked admin address,
	// it is that one.
	if ( ! row && said ) {
		const typed = sent.filter( ( item ) => ! item.locked );

		row = 1 === typed.length ? typed[ 0 ] : null;
	}

	if ( ! row ) {
		return null;
	}

	return {
		key: row.key,
		email: row.email,
		message:
			'rest_invalid_param' === error.code
				? __( 'This address has a character email addresses cannot have, or a missing part. Check it and save again.', 'bettershield' )
				: error.message,
	};
}

// The answer each detection stands for.
const DETECTED_CHOICE = { cloudflare: 'cloudflare', proxy: 'other', private: 'other' };

/**
 * What BetterShield found about how visits reach the site, said first so the
 * question reads as a confirmation (#1962).
 *
 * @param {string} detected 'cloudflare', 'proxy', 'private' or ''.
 * @return {string} The sentence.
 */
function foundLine( detected ) {
	if ( 'cloudflare' === detected ) {
		return sprintf( /* translators: %s: the plugin's name. */ __( '%s checked: this site is behind Cloudflare.', 'bettershield' ), brand() );
	}

	if ( 'proxy' === detected ) {
		return sprintf( /* translators: %s: the plugin's name. */ __( '%s checked: visits reach this site through a service in front of it.', 'bettershield' ), brand() );
	}

	// The finding's own test, said here first (#2199).
	if ( 'private' === detected ) {
		return sprintf( /* translators: %s: the plugin's name. */ __( '%s found that visits reach your site through another service, likely your host’s. Add its address so each visitor is counted separately.', 'bettershield' ), brand() );
	}

	return sprintf( /* translators: %s: the plugin's name. */ __( '%s checked: visits reach this site directly.', 'bettershield' ), brand() );
}

/**
 * The trusted proxies as typed: one per line, or separated by commas or
 * spaces, blanks dropped. Login & Access checks each one.
 *
 * @param {string} text What the field holds.
 * @return {string[]} The addresses and ranges.
 */
function proxyList( text ) {
	return String( text || '' )
		.split( /[\s,]+/ )
		.map( ( entry ) => entry.trim() )
		.filter( Boolean );
}

/**
 * Whether BetterShield cannot tell how visits arrive, or the answer stands
 * in the way of lockouts: then the question is asked up front.
 *
 * @param {Object} state The setup's state.
 * @return {boolean} Whether to ask it up front.
 */
export function proxyUnsure( state ) {
	return 'private' === state.site.proxy.detected || Boolean( state.score && state.score.lockouts );
}

/**
 * The site's answers, held until Apply, and the parts that ask them.
 *
 * @param {Object}   props
 * @param {Function} props.register Given the save Protect's Apply calls, which resolves whether it went through.
 * @param {Function} props.onTeam   Told who signs in as the answer changes, for the way back in beside it.
 * @return {Object} { who, proxy, alerts, refusal, attention, summary, team }.
 */
export function useYourSite( { register, onTeam } ) {
	const { state, run, busy, error, setNotice, keepFocus } = useSetup();
	const site = state.site;
	const alerts = site.alerts;
	const max = Number( alerts.max ) || 5;

	const [ team, setTeam ] = useState( site.team || 'solo' );
	const [ proxy, setProxy ] = useState( () => {
		// A first run takes what could be detected; a re-run, or an answer
		// already given, shows what is set.
		if ( ! state.rerun && ! site.proxy.answered && 'direct' === site.proxy.choice && DETECTED_CHOICE[ site.proxy.detected ] ) {
			return DETECTED_CHOICE[ site.proxy.detected ];
		}

		return site.proxy.choice || 'direct';
	} );
	// The proxy's addresses, named here rather than on Login & Access.
	const [ proxies, setProxies ] = useState( () => ( site.proxy.list || [] ).join( '\n' ) );
	const [ clearTrusted, setClearTrusted ] = useState( false );
	const [ rows, setRows ] = useState( () => startingRows( alerts ) );
	const [ nextKey, setNextKey ] = useState( rows.length );
	const [ digest, setDigest ] = useState( Boolean( alerts.digest ) );
	const [ instant, setInstant ] = useState( Boolean( alerts.instant ) );
	const [ tried, setTried ] = useState( false );
	const [ attempt, setAttempt ] = useState( 0 );
	// Whether the alert addresses are open under their line: from the start
	// while alerts are muted, which the owner has to act on.
	const [ open, setOpen ] = useState( () => Boolean( alerts.muted ) );
	const sent = useRef( [] );
	const list = useRef( null );

	const problems = problemsIn( rows );
	const filled = rows.filter( ( row ) => String( row.email || '' ).trim() );
	const refused = refusalFor( error, sent.current );

	// Said under the address while it still reads as it did when refused.
	if ( refused && ! problems[ refused.key ] && rows.some( ( row ) => row.key === refused.key && String( row.email || '' ).trim() === refused.email ) ) {
		problems[ refused.key ] = refused.message;
	}

	// Nothing to send alerts to is a reason too, and was held back unsaid.
	if ( 0 === filled.length ) {
		const first = rows.find( ( row ) => ! row.locked );

		if ( first ) {
			problems[ first.key ] = __( 'Enter an email address for alerts.', 'bettershield' );
		}
	}

	const invalid = Object.keys( problems ).length > 0 || 0 === filled.length;

	/*
	 * Held back, or refused: the reader is taken to the address, which on a
	 * short screen can be well above the button they pressed.
	 */
	useEffect( () => {
		if ( ! attempt || ! list.current ) {
			return;
		}

		const field = list.current.querySelector( '.is-problem input' );

		if ( field ) {
			field.focus();
		}
	}, [ attempt, refused && refused.key ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const update = ( key, email ) => setRows( rows.map( ( row ) => ( row.key === key ? { ...row, email } : row ) ) );
	const remove = ( key ) => setRows( rows.filter( ( row ) => row.key !== key ) );
	const add = () => {
		setRows( [ ...rows, { email: '', locked: false, key: nextKey } ] );
		setNextKey( nextKey + 1 );
	};

	// Who signs in, as the way back in beside it on Protect reads it.
	useEffect( () => {
		onTeam?.( team );
	}, [ team ] ); // eslint-disable-line react-hooks/exhaustive-deps

	// Opened where a refusal is about one of the answers it holds.
	useEffect( () => {
		if ( error && 'site' === error.key ) {
			setOpen( true );
		}
	}, [ error ] );

	/*
	 * The answers sent, resolving whether they went through. Held back while
	 * an address needs work: the questions open, and the reader is taken to it.
	 */
	const submit = () => {
		setTried( true );
		setAttempt( ( count ) => count + 1 );

		if ( invalid ) {
			setOpen( true );

			return Promise.resolve( false );
		}

		sent.current = filled.map( ( row ) => ( { key: row.key, email: String( row.email ).trim(), locked: Boolean( row.locked ) } ) );

		return run( 'site', ROUTES.site, {
			team,
			proxy,
			recipients: filled.map( ( row ) => String( row.email ).trim() ),
			digest,
			instant,
			// Left out, Login & Access's list stays exactly as it is.
			...( 'other' === proxy ? { trusted_proxies: proxyList( proxies ) } : {} ),
			...( 'direct' === proxy && clearTrusted ? { trusted_proxies: [] } : {} ),
		} ).then( ( result ) => Boolean( result ) );
	};

	register?.( submit );

	const detected = site.proxy.detected;

	const who = (
				<SettingsCard icon="users" title={ __( 'Who signs in to this site?', 'bettershield' ) }>
					<div className="bs-ds-setup-card__body">
						<Choice
							legend={ __( 'Who signs in to this site?', 'bettershield' ) }
							quiet
							help={ __( 'With a team, you can require two-factor for administrators under Protection › Two-Factor.', 'bettershield' ) }
							value={ team }
							onChange={ setTeam }
							options={ [
								{ value: 'solo', label: __( 'Just me', 'bettershield' ) },
								{ value: 'team', label: __( 'Me and a team', 'bettershield' ) },
							] }
						/>
					</div>
				</SettingsCard>
	);

	/*
	 * "Keep what BetterShield found" only while the answer is what was found:
	 * beside a saved answer that differs, it told the owner to keep something
	 * the save would not. With the address box open and empty, no address was
	 * found to keep, and one line says what to do with the box: three notes
	 * there contradicted each other (#2487).
	 */
	let proxyNote = sprintf( /* translators: %s: the plugin's name. */ __( 'Your answer replaces what %s found. Change it anytime in Login & Access.', 'bettershield' ), brand() );

	if ( 'other' === proxy && '' === proxies.trim() ) {
		proxyNote = __( 'Not sure? Leave this empty and change it later in Login & Access.', 'bettershield' );
	} else if ( proxy === ( DETECTED_CHOICE[ detected ] || 'direct' ) ) {
		proxyNote = __( 'Not sure? Keep what was found. Change it later in Login & Access.', 'bettershield' );
	}

	const proxyCard = (
				<SettingsCard
					icon="cloud"
					title={ __( 'Does your site use Cloudflare or a similar service in front of it?', 'bettershield' ) }
					// How to answer, one press away; the lockout risk stays in
					// view under the question (#2840).
					trailing={
						<InfoTip label={ __( 'How to answer', 'bettershield' ) } placement="bottom-end">
							{ __( 'Pick Cloudflare if its orange cloud is on for your domain. Pick “another service” for a host firewall or any other service in front of your site.', 'bettershield' ) }{ ' ' }
							{ __( 'Enter its addresses one per line. Your host can tell you what they are.', 'bettershield' ) }
						</InfoTip>
					}
				>
					<div className="bs-ds-setup-card__body">
						<p className="bs-ds-setup__text">{ foundLine( detected ) }</p>

						<Choice
							legend={ __( 'Does your site use Cloudflare or a similar service in front of it?', 'bettershield' ) }
							quiet
							help={ __(
								'With such a service, all visitors can look like one visitor, so one lockout could block everyone.',
								'bettershield'
							) }
							value={ proxy }
							onChange={ setProxy }
							options={ [
								{ value: 'direct', label: __( 'No', 'bettershield' ) },
								{ value: 'cloudflare', label: __( 'Yes, Cloudflare', 'bettershield' ) },
								{ value: 'other', label: __( 'Yes, another service', 'bettershield' ) },
							] }
						/>

						{ 'other' === proxy ? (
							<Field
								kind="textarea"
								label={ __( 'Addresses of the service in front of your site', 'bettershield' ) }
								value={ proxies }
								onChange={ setProxies }
								rows={ 3 }
								spellCheck={ false }
							/>
						) : null }

						{ 'direct' === proxy && site.proxy.trusted > 0 ? (
							<Alert
								layout="default"
								tone="info"
								desc={ sprintf(
									/* translators: %d: how many trusted proxies are named. */
									_n(
										'Login & Access still lists %d trusted proxy. It stays unless you remove it here.',
										'Login & Access still lists %d trusted proxies. They stay unless you remove them here.',
										site.proxy.trusted,
										'bettershield'
									),
									site.proxy.trusted
								) }
								actions={
									<Field
										kind="check"
										label={ _n( 'Remove it when I save', 'Remove them when I save', site.proxy.trusted, 'bettershield' ) }
										checked={ clearTrusted }
										onChange={ setClearTrusted }
									/>
								}
							/>
						) : null }

						<p className="bs-ds-setup__note">{ proxyNote }</p>
					</div>
				</SettingsCard>
	);

	const alertsCard = (
			<SettingsCard
				icon="mail"
				title={ __( 'Email Alerts', 'bettershield' ) }
				intro={ __( 'Who gets the weekly summary and urgent alerts. Changes here also update Settings › Email Alerts.', 'bettershield' ) }
			>
				<div className="bs-ds-setup-card__body">
					<ul ref={ list } className="bs-ds-setup-recipients" aria-label={ __( 'Alert recipients', 'bettershield' ) }>
						{ rows.map( ( row, index ) =>
							row.locked ? (
								<li key={ row.key } className="bs-ds-setup-recipients__row is-locked">
									<span className="bs-ds-setup-recipients__fixed">
										<Icon name="lock" size={ 14 } tone="3" />
										<span className="bs-ds-setup-recipients__email">{ row.email }</span>
									</span>
									<Badge>{ __( 'Site admin', 'bettershield' ) }</Badge>
								</li>
							) : (
								<li key={ row.key } className={ `bs-ds-setup-recipients__row${ tried && problems[ row.key ] ? ' is-problem' : '' }` }>
									<Field
										type="email"
										autoComplete="email"
										label={ sprintf(
											/* translators: %d: position in the list of recipients. */
											__( 'Recipient %d', 'bettershield' ),
											index + 1
										) }
										hideLabelFromVision
										placeholder={ __( 'name@example.com', 'bettershield' ) }
										value={ row.email }
										onChange={ ( value ) => update( row.key, value ) }
										onBlur={ ( event ) => {
											// Left for the step's own buttons, the press says it. Said
											// here, the message pushed the button down between the
											// press and the release, and the press was lost.
											const next = event && event.relatedTarget;

											if ( ! ( next && next.closest && next.closest( '.bs-ds-setup__foot' ) ) ) {
												setTried( true );
											}
										} }
										error={ tried && problems[ row.key ] ? problems[ row.key ] : '' }
									/>
									{ rows.length > 1 ? (
										<Button
											type="ghost"
											size="sm"
											iconOnly
											icon="x"
											iconTone="2"
											className="bs-ds-setup-recipients__remove"
											label={ sprintf(
												/* translators: %s: an email address, or "this row" when blank. */
												__( 'Remove %s', 'bettershield' ),
												row.email || __( 'this row', 'bettershield' )
											) }
											onClick={ () => remove( row.key ) }
										/>
									) : null }
								</li>
							)
						) }
					</ul>

					{ rows.length < max ? (
						<div className="bs-ds-setup__actions">
							<Button type="secondary" size="sm" icon="plus" iconTone="2" onClick={ add }>
								{ __( 'Add Another Email', 'bettershield' ) }
							</Button>
						</div>
					) : (
						<p className="bs-ds-setup__note">
							{ sprintf(
								/* translators: %d: most recipients allowed. */
								__( 'Up to %d addresses in total.', 'bettershield' ),
								max
							) }
						</p>
					) }
				</div>

				<SettingRow
					title={ sprintf(
						/* translators: %s: a weekday, e.g. Monday. */
						__( 'Weekly summary, every %s', 'bettershield' ),
						alerts.digest_day
					) }
					about={ __( 'Changes, findings and actions, in one email.', 'bettershield' ) }
					toggle={ { checked: digest, onChange: setDigest } }
				/>
				<SettingRow
					title={ __( 'Instant alerts for serious problems', 'bettershield' ) }
					about={
						instant
							? __( 'Emailed right away, so you don’t wait for the weekly summary.', 'bettershield' )
							: __( 'While this is off, nobody is emailed about most attacks. Only a few events still email, like use of the trap password.', 'bettershield' )
					}
					toggle={ { checked: instant, onChange: setInstant } }
				/>

				{ alerts.muted ? (
					<div className="bs-ds-setup-card__row">
						<Alert
							layout="default"
							tone="warning"
							desc={ __( 'Alerts are muted, so no alert or weekly summary is emailed.', 'bettershield' ) }
							actions={
								<Button
									type="secondary"
									size="sm"
									className="bs-ds-setup__wrap"
									disabled={ null !== busy }
									accessibleWhenDisabled={ 'unmute' === busy }
									onClick={ () =>
										run( 'unmute', ROUTES.unmute ).then( ( answer ) => {
											if ( answer ) {
												setNotice( __( 'Alerts are on again.', 'bettershield' ) );
												keepFocus();
											}
										} )
									}
								>
									{ __( 'Unmute Alerts', 'bettershield' ) }
								</Button>
							}
						/>
					</div>
				) : null }
			</SettingsCard>
	);

	const recipients = filled.map( ( row ) => String( row.email ).trim() );
	const others = recipients.length - 1;
	const to =
		others > 0
			? sprintf(
					/* translators: 1: an email address, 2: how many more addresses. */
					_n( '%1$s and %2$d other', '%1$s and %2$d others', others, 'bettershield' ),
					recipients[ 0 ],
					others
			  )
			: recipients[ 0 ];

	let line;

	if ( alerts.muted ) {
		line = __( 'Alerts are muted', 'bettershield' );
	} else if ( ! digest && ! instant ) {
		// A few events still email with both off, so "off" alone would not be true.
		line = __( 'Most email alerts are off', 'bettershield' );
	} else if ( ! recipients.length ) {
		line = __( 'Alerts go nowhere yet', 'bettershield' );
	} else {
		line = sprintf(
			/* translators: %s: who alerts go to, e.g. "admin@example.com and 2 others". */
			__( 'Alerts go to %s', 'bettershield' ),
			to
		);
	}

	const alertsPart = (
		<>
			<div className="bs-ds-setup-alerts">
				<Icon name="mail" size={ 14 } tone="2" />
				<span className="bs-ds-setup-alerts__line">{ line }</span>
				<Button type="secondary" size="sm" aria-expanded={ open } onClick={ () => setOpen( ! open ) }>
					{ open ? __( 'Done', 'bettershield' ) : __( 'Change', 'bettershield' ) }
				</Button>
			</div>
			{ open ? alertsCard : null }
		</>
	);

	return {
		who,
		proxy: proxyCard,
		alerts: alertsPart,
		// A refusal no address on screen is the cause of.
		refusal: error && 'site' === error.key && ! refused ? <Alert layout="default" tone="error" desc={ error.message } /> : null,
		// Whether the fold these sit in has to open for the owner to act.
		attention: Boolean( alerts.muted ) || ( error && 'site' === error.key ) || ( tried && invalid ),
		summary: line,
		team,
	};
}
