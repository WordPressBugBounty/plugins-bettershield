/**
 * Login & access › Your connection and lockouts: how this site sees the person reading
 * it, and the lockouts that fall out of that, in one card.
 *
 * First on the tab, because it is the fact every control below depends on:
 * which address this site believes it is talking to.
 */

import './Door.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import { focusIfLost } from '../ui/focus';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import InfoTip from '../ui/InfoTip';
import SettingRow, { SettingsCard } from '../ui/Setting';
import { EmptyState } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';
import Topics from '../ui/Topics';

/*
 * How many lockouts are listed before the rest fold away. The list keeps
 * expired entries for a while, and seventeen rows of "Expired" pushed every
 * setting on this screen a screen further down to say that nothing is wrong.
 */
const LOCKOUTS_SHOWN = 5;

/** The card's heading, which the stats strip's "See why" leads to (#2522). */
export const CONNECTION_CARD = 'bs-access-connection';

/**
 * How many lockouts are in force. The server counts them; the list it sends
 * can be cut, so counting its rows can come up short.
 *
 * @param {Object} data The login-protection payload.
 * @return {number} Lockouts in force.
 */
export function runningCount( data ) {
	return Number.isInteger( data.lockouts_active ) ? data.lockouts_active : ( data.lockouts || [] ).filter( ( lockout ) => lockout.active ).length;
}

/**
 * Whether anything is locked out at this moment, for the card's header.
 *
 * @param {Object} data The login-protection payload.
 * @return {string} The phrase.
 */
function lockoutNote( data ) {
	const active = runningCount( data );

	return active
		? sprintf(
				/* translators: %d: how many lockouts are in force. */
				_n( '%d lockout active', '%d lockouts active', active, 'bettershield' ),
				active
		  )
		: __( 'No lockouts active', 'bettershield' );
}

/**
 * The detection method as a phrase in a sentence. The stored slugs are for
 * the log; a reader should not have to learn them.
 *
 * @param {string} method The method.
 * @return {string} The phrase.
 */
function methodPhrase( method ) {
	switch ( method ) {
		case 'cloudflare':
			return __( 'through Cloudflare, from its published ranges', 'bettershield' );
		case 'cloudflare-unconfirmed':
			return __( 'through Cloudflare, counted with the connecting address too', 'bettershield' );
		case 'trusted-proxy':
			return __( 'through the proxy you named under Addresses of your CDN or proxy', 'bettershield' );
		case 'direct':
			return __( 'directly', 'bettershield' );
		default:
			return method;
	}
}

/**
 * The connection, in one line: where it came from, and what the edge or the
 * proxy in front of it said about it.
 *
 * @param {Object} resolution The request's resolution.
 * @return {string} The line.
 */
function connectionLine( resolution ) {
	if ( resolution.connecting && resolution.claimed ) {
		return sprintf(
			/* translators: 1: the address the connection came from, 2: the address the Cloudflare header names. */
			__( 'Connecting from %1$s. Cloudflare says %2$s.', 'bettershield' ),
			resolution.connecting,
			resolution.claimed
		);
	}

	if ( resolution.connecting && 'trusted-proxy' === resolution.method && resolution.seen_as && resolution.seen_as !== resolution.connecting ) {
		return sprintf(
			/* translators: 1: the proxy's address, 2: the visitor's address the proxy passed on. */
			__( 'Through your proxy at %1$s. You appear as %2$s.', 'bettershield' ),
			resolution.connecting,
			resolution.seen_as
		);
	}

	/*
	 * Direct and still not believed, with no proxy named: a private or
	 * loopback address. "Directly" above "can't see visitors' real
	 * addresses" read as two answers (#2576).
	 */
	if ( resolution.connecting && 'direct' === resolution.method && ! resolution.confident && ! resolution.named_proxy && ! resolution.ignored_headers ) {
		return sprintf(
			/* translators: %s: the address the connection came from. */
			__( 'Connecting from %s, a private address.', 'bettershield' ),
			resolution.connecting
		);
	}

	if ( resolution.connecting && 'direct' === resolution.method ) {
		return sprintf(
			/* translators: %s: the address the connection came from. */
			__( 'Connecting from %s, directly.', 'bettershield' ),
			resolution.connecting
		);
	}

	if ( resolution.connecting ) {
		return sprintf(
			/* translators: %s: the address the connection came from. */
			__( 'Connecting from %s.', 'bettershield' ),
			resolution.connecting
		);
	}

	return __( 'This request arrived with no address.', 'bettershield' );
}

/**
 * Whether lockouts can run on what was read, and if not, what to do about it.
 *
 * @param {Object} resolution The request's resolution.
 * @return {string} The sentence.
 */
function confidenceLine( resolution ) {
	if ( resolution.confident ) {
		return sprintf(
			/* translators: %s: how visitors' addresses are read, e.g. "directly", "through Cloudflare". */
			__( 'Lockouts are on. This site sees each visitor’s real address, %s.', 'bettershield' ),
			methodPhrase( resolution.method )
		);
	}

	/*
	 * A proxy the owner named, whose header arrived and names no visitor:
	 * ignored too, so asked before the headers nothing vouches for. Naming it
	 * again changes nothing.
	 */
	if ( resolution.named_proxy_no_visitor ) {
		return __(
			'Lockouts are off because your proxy doesn’t pass on visitors’ real addresses. Ask your host to send them in the X-Forwarded-For header.',
			'bettershield'
		);
	}

	if ( resolution.ignored_headers ) {
		return __(
			'Lockouts are off: this connection came through a proxy you have not listed. Add it under Addresses of your CDN or proxy below.',
			'bettershield'
		);
	}

	/*
	 * Not confident and no header ignored: a proxy that is named and sends no
	 * header, a private address nothing names, or (only with no address at
	 * all) unreadable. Each asks for something different.
	 */
	if ( resolution.connecting && resolution.named_proxy ) {
		return __(
			'Lockouts are off because your proxy doesn’t pass on visitors’ real addresses. Ask your host to turn that on.',
			'bettershield'
		);
	}

	if ( resolution.connecting ) {
		return __( 'Lockouts are off until this site can see real visitor addresses. Ask your host which proxy it uses, then add it under Addresses of your CDN or proxy.', 'bettershield' );
	}

	return __( 'With no address, nothing is counted for this connection.', 'bettershield' );
}

/**
 * Why the line above says what it does, where the line alone is short.
 *
 * @param {Object} resolution The request's resolution.
 * @return {?string} The reasoning, behind an ⓘ, or null.
 */
function confidenceTip( resolution ) {
	if ( resolution.confident || resolution.named_proxy_no_visitor ) {
		return null;
	}

	if ( resolution.ignored_headers ) {
		return __(
			'Until you name it, this site can’t tell visitors apart, so it doesn’t lock anyone out rather than lock everyone out.',
			'bettershield'
		);
	}

	if ( resolution.named_proxy || ! resolution.connecting ) {
		return null;
	}

	return __( 'A private address means WordPress is not reached directly. Counting it would put every visitor behind it under one lockout, you included.', 'bettershield' );
}

/**
 * How this site sees the person reading the screen.
 *
 * Their own request is the probe, and it is the only honest one: a connection
 * out of Cloudflare's ranges looks like an edge without being proof of one,
 * because anything hosted there reaches a site that is not behind Cloudflare
 * too. So this reports the two addresses and asks, rather than deciding on the
 * site's behalf. Neither address is stored anywhere.
 *
 * @param {Object}   props
 * @param {Object}   props.resolution The request's resolution.
 * @param {Object}   props.settings   The saved settings.
 * @param {Function} props.onRecheck  Reads the screen again.
 */
function SeenAs( { resolution, settings, onRecheck } ) {
	const { saveLoginProtection, busy } = useStore();
	const saving = isWorking( busy, 'login-protection' );
	const unconfirmed = 'cloudflare-unconfirmed' === resolution.method;

	// A confirmation that was true once and quietly is not: the site still
	// believes an edge it is no longer reached through. Worth a sentence,
	// because nothing else on the screen would show it.
	const stale = settings.cloudflare && 'cloudflare' !== resolution.method && ! unconfirmed;

	/*
	 * Check Again read the screen again and said nothing, so nobody could
	 * tell it had run (#2576). What the card said before is kept, so the
	 * answer can say whether anything moved.
	 */
	const [ check, setCheck ] = useState( null );
	const said = connectionLine( resolution ) + ' ' + confidenceLine( resolution );
	const recheck = () => {
		const before = said;

		setCheck( { busy: true, before } );
		Promise.resolve( onRecheck() ).finally( () => setCheck( { busy: false, before } ) );
	};
	let checkNote = '';

	if ( check && ! check.busy ) {
		checkNote =
			check.before === said
				? __( 'Checked just now. No change.', 'bettershield' )
				: sprintf(
						/* translators: %s: how the site sees the visit now, e.g. "Connecting from 203.0.113.7, directly." */
						__( 'Checked just now. %s', 'bettershield' ),
						connectionLine( resolution )
				  );
	}

	return (
		<SettingRow
			className="bs-ds-seenas"
			title={ __( 'How this site sees you', 'bettershield' ) }
			about={ connectionLine( resolution ) }
			tip={ __( 'This shows how the site sees your own visit. Nothing is saved.', 'bettershield' ) }
			control={
				// The answer is about the request being made, so asking again
				// is a new request.
				<Button type="ghost" size="sm" icon="refresh-cw" iconTone="1" isBusy={ Boolean( check && check.busy ) } disabled={ Boolean( check && check.busy ) } onClick={ recheck }>
					{ check && check.busy ? __( 'Checking…', 'bettershield' ) : __( 'Check Again', 'bettershield' ) }
				</Button>
			}
		>
			{ resolution.confident ? (
				<p className="bs-ds-seenas__said">{ confidenceLine( resolution ) }</p>
			) : (
				<Alert
					layout="default"
					tone="warning"
					desc={
						<>
							{ confidenceLine( resolution ) }
							{ confidenceTip( resolution ) ? (
								<>
									{ ' ' }
									<InfoTip label={ __( 'Why lockouts are off', 'bettershield' ) }>{ confidenceTip( resolution ) }</InfoTip>
								</>
							) : null }
						</>
					}
				/>
			) }

			{ checkNote ? (
				<p className="bs-ds-seenas__said" role="status">
					{ checkNote }
				</p>
			) : null }

			{ unconfirmed ? (
				<Alert
					layout="default"
					tone="info"
					desc={
						<>
							{ __(
								'This visit came through Cloudflare. If your site uses Cloudflare, confirm it so lockouts apply to the real visitor.',
								'bettershield'
							) }
							{ ' ' }
							<InfoTip label={ __( 'Why both addresses count', 'bettershield' ) }>
								{ __( 'Until you confirm, a lockout covers both Cloudflare’s address and the visitor’s, so nobody can dodge it.', 'bettershield' ) }
							</InfoTip>
						</>
					}
					actions={
						<Button type="primary" size="sm" isBusy={ saving } disabled={ saving } onClick={ () => saveLoginProtection( { cloudflare: true } ) }>
							{ __( 'Yes, This Site Is Behind Cloudflare', 'bettershield' ) }
						</Button>
					}
				/>
			) : null }

			{ stale ? (
				<Alert
					layout="default"
					tone="warning"
					desc={ __(
						'This site trusts Cloudflare, but this request bypassed it: you used another route, or the site has left Cloudflare.',
						'bettershield'
					) }
					actions={
						<Button type="secondary" size="sm" isBusy={ saving } disabled={ saving } onClick={ () => saveLoginProtection( { cloudflare: false } ) }>
							{ __( 'Turn That Off', 'bettershield' ) }
						</Button>
					}
				/>
			) : null }
		</SettingRow>
	);
}

/**
 * How long one lockout was set to last, and why when a return made it longer
 * than configured: its source had been locked out earlier the same day.
 *
 * @param {Object} lockout One row of the list, with `repeat` from its record.
 * @return {string} The phrase, or nothing for a row that does not say.
 */
function lockoutLength( lockout ) {
	// Released early, it did not last its length (#2485).
	if ( ! lockout.minutes || lockout.released ) {
		return '';
	}

	const length =
		lockout.minutes >= 120 && 0 === lockout.minutes % 60
			? sprintf(
					/* translators: %d: number of hours. */
					_n( '%d-hour lockout', '%d-hour lockout', lockout.minutes / 60, 'bettershield' ),
					lockout.minutes / 60
			  )
			: sprintf(
					/* translators: %d: number of minutes. */
					_n( '%d-minute lockout', '%d-minute lockout', lockout.minutes, 'bettershield' ),
					lockout.minutes
			  );

	// From the lockout's own record, not from today's setting: a pause made
	// while the setting was longer is not one a return made longer.
	if ( 'signin' === lockout.surface && lockout.repeat > 0 ) {
		return sprintf(
			/* translators: %s: how long, e.g. "2-hour lockout". */
			__( '%s, longer because it came back within a day', 'bettershield' ),
			length
		);
	}

	return length;
}

/**
 * What was tried from the network: how many attempts, and the last name used.
 *
 * @param {Object} lockout One row of the list.
 * @return {string} The phrase.
 */
function attemptsPhrase( lockout ) {
	return lockout.last_username
		? sprintf(
				/* translators: 1: attempt count, 2: username. */
				_n( '%1$d failed attempt, last as “%2$s”', '%1$d failed attempts, last as “%2$s”', lockout.attempts, 'bettershield' ),
				lockout.attempts,
				lockout.last_username
		  )
		: sprintf(
				/* translators: %d: attempt count. */
				_n( '%d attempt', '%d attempts', lockout.attempts, 'bettershield' ),
				lockout.attempts
		  );
}

/**
 * @param {Object} props
 * @param {Array}  props.lockouts The lockouts the server sent.
 * @param {number} props.total    How many are on record.
 * @param {number} props.running  How many are in force.
 */
function Lockouts( { lockouts, total, running } ) {
	const { releaseLockout, busy } = useStore();
	const [ all, setAll ] = useState( false );
	// Release now becomes the row's "Released" badge once the list is read
	// again, so the list's heading takes the keyboard.
	const heading = useRef( null );
	const afterRelease = useMutationFocus( heading );

	/*
	 * Why a release was refused, said beside the list rather than only at the
	 * top of the screen, out of view from the row that was pressed. Its
	 * button has usually gone with the row by then, so the list's heading
	 * takes the keyboard.
	 */
	const [ refusal, setRefusal ] = useState( '' );

	useEffect( () => {
		if ( refusal ) {
			focusIfLost( heading.current );
		}
	}, [ refusal ] );

	const release = ( lockout ) => {
		setRefusal( '' );
		releaseLockout(
			lockout.id,
			afterRelease( () => {} ),
			( error ) => {
				// Canceled at the password prompt: nothing was asked of the
				// server, so there is nothing to say beside the list.
				if ( error ) {
					setRefusal( error.message || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );
				}
			}
		);
	};

	/*
	 * The active ones first, whatever their age: they are the only rows here
	 * anybody can act on. The rest keep the order the server gave them.
	 */
	const ordered = [ ...lockouts.filter( ( lockout ) => lockout.active ), ...lockouts.filter( ( lockout ) => ! lockout.active ) ];
	const first = ordered.slice( 0, LOCKOUTS_SHOWN );
	const rest = ordered.slice( LOCKOUTS_SHOWN );
	const unlisted = Math.max( 0, running - lockouts.filter( ( lockout ) => lockout.active ).length );

	const row = ( lockout ) => {
		const working = isWorking( busy, `lockout-${ lockout.id }` );
		let status = __( 'Expired', 'bettershield' );

		if ( lockout.active ) {
			status = __( 'Active', 'bettershield' );
		} else if ( lockout.released ) {
			status = __( 'Released', 'bettershield' );
		}

		return (
			<Row key={ lockout.id } className="bs-ds-lockout">
				<Cell>
					<TitleMeta title={ lockout.network } meta={ lockout.surface_label || null } />
				</Cell>
				<Cell>{ attemptsPhrase( lockout ) }</Cell>
				<Cell>
					<TitleMeta title={ whenPhrase( lockout.started_at ) } meta={ lockoutLength( lockout ) || null } />
				</Cell>
				<Cell>
					<Badge tone={ lockout.active ? 'yellow' : 'neutral' }>{ status }</Badge>
				</Cell>
				<Cell align="end">
					{ lockout.active ? (
						<Button
							type="ghost"
							size="sm"
							isBusy={ working }
							disabled={ working }
							aria-label={ sprintf(
								/* translators: 1: the form that was closed, e.g. sign-in. 2: the network that is locked out, e.g. 203.0.113.0/24. The name starts with the button's own words (#2485). */
								__( 'Release Now: %1$s lockout for %2$s', 'bettershield' ),
								// The row's label starts a line; here it reads mid-sentence.
								( lockout.surface_label || __( 'sign-in', 'bettershield' ) ).toLocaleLowerCase(),
								lockout.network
							) }
							onClick={ () => release( lockout ) }
						>
							{ __( 'Release Now', 'bettershield' ) }
						</Button>
					) : null }
				</Cell>
			</Row>
		);
	};

	let note = null;

	if ( unlisted ) {
		note = sprintf(
			/* translators: %d: how many running lockouts the list leaves out. */
			_n(
				'%d more running lockout is not listed. It ends on its own.',
				'%d more running lockouts are not listed. They end on their own.',
				unlisted,
				'bettershield'
			),
			unlisted
		);
	} else if ( total > lockouts.length ) {
		note = sprintf(
			/* translators: 1: how many lockouts are listed, 2: how many there are in all. */
			__( 'Showing the %1$d most recent of %2$d. Running lockouts come first.', 'bettershield' ),
			lockouts.length,
			total
		);
	}

	let more = null;

	if ( rest.length ) {
		if ( all ) {
			more = __( 'Show Fewer', 'bettershield' );
		} else if ( total > ordered.length ) {
			// "All" only when the list is whole: beside "the 50 most recent of
			// 58" it promised 58 and showed 50.
			more = sprintf(
				/* translators: %d: how many of the most recent lockouts the list holds. */
				__( 'Show the %d Most Recent', 'bettershield' ),
				ordered.length
			);
		} else {
			more = sprintf(
				/* translators: %d: how many lockouts are on record. */
				__( 'Show All %d', 'bettershield' ),
				ordered.length
			);
		}
	}

	return (
		<div className="bs-ds-lockouts">
			<div className="bs-ds-lockouts__head">
				<h3 className="bs-ds-lockouts__title" ref={ heading } tabIndex={ -1 }>
					{ __( 'Lockouts', 'bettershield' ) }
				</h3>
				<Topics
					items={ [
						{
							key: 'how',
							label: __( 'How this works', 'bettershield' ),
							lead: __( 'Every lockout ends on its own.', 'bettershield' ),
							points: [
								__( 'If a real account was targeted, its owner was emailed an unlock link.', 'bettershield' ),
								__( 'The recovery link, on the Recovery tab, pauses everything here at once.', 'bettershield' ),
								// The row names the /24 or /64, and the pause is keyed on
								// the one IPv4 address or the IPv6 /64.
								__( 'A lockout covers one visitor’s address, not their whole network.', 'bettershield' ),
							],
						},
					] }
				/>
			</div>

			{ refusal ? (
				<div role="status">
					<Alert layout="default" tone="info" desc={ refusal } onDismiss={ () => setRefusal( '' ) } />
				</div>
			) : null }

			{ lockouts.length ? (
				<Table
					label={ __( 'Lockouts', 'bettershield' ) }
					columns={ [
						{ key: 'network', label: __( 'Address', 'bettershield' ) },
						{ key: 'tried', label: __( 'Attempts', 'bettershield' ) },
						{ key: 'when', label: __( 'When', 'bettershield' ) },
						{ key: 'status', label: __( 'Status', 'bettershield' ), width: '88px' },
						{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
					] }
				>
					{ first.map( row ) }
					{ rest.length && all ? (
						<div role="rowgroup" id="bs-lockouts-more" className="bs-ds-tbl__rows">
							{ rest.map( row ) }
						</div>
					) : null }
					{ note || more ? (
						<WholeRow
							kind="foot"
							aside={
								more ? (
									<Button
										type="ghost"
										size="sm"
										trailing="chevron-down"
										trailingTone="3"
										className="bs-ds-lockouts__more"
										aria-expanded={ all }
										aria-controls={ all ? 'bs-lockouts-more' : undefined }
										onClick={ () => setAll( ( open ) => ! open ) }
									>
										{ more }
									</Button>
								) : null
							}
						>
							{ note }
						</WholeRow>
					) : null }
				</Table>
			) : (
				<EmptyState>{ __( 'No one is locked out right now. That is normal.', 'bettershield' ) }</EmptyState>
			) }
		</div>
	);
}

/**
 * @param {Object}   props
 * @param {Object}   props.data     The login-protection payload.
 * @param {Function} props.onRecheck Reads the screen again.
 */
export default function Door( { data, onRecheck } ) {
	const running = runningCount( data );

	return (
		<SettingsCard icon="door-open" id={ CONNECTION_CARD } title={ __( 'Your connection and lockouts', 'bettershield' ) } trailing={ <Badge tone={ running ? 'yellow' : 'neutral' }>{ lockoutNote( data ) }</Badge> }>
			<SeenAs resolution={ data.resolution || {} } settings={ data.settings || {} } onRecheck={ onRecheck } />
			<Lockouts lockouts={ data.lockouts || [] } total={ data.lockouts_total || 0 } running={ running } />
		</SettingsCard>
	);
}
