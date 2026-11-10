/**
 * Fix for "Sign-in lockouts are not running" (#2205).
 *
 * What the last real request showed, in the words of its case, and the
 * setting that case asks about: the trusted proxies, typed by the owner
 * from their provider's documentation, or Cloudflare where a connection
 * from Cloudflare's own ranges was seen. Nothing here is filled in from a
 * forwarded header or a connecting address. The save is login protection's
 * own, which asks for the password where it gives something away, and
 * Check again says fixed only once a request made since resolved a visitor.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Button from '../../ui/Button';
import Field from '../../ui/Field';

const PATH = '/bettershield/v1/findings/lockouts_not_running/proxy';

/** What each case means, and what it asks for. */
const CASES = {
	unnamed_proxy: () =>
		__( 'A service in front of your site, like a CDN, passes on visitor addresses, but BetterShield doesn’t trust it yet. Add the address ranges your host or CDN lists.', 'bettershield' ),
	proxy_names_no_visitor: () =>
		__( 'The service you added isn’t passing on visitors’ real addresses. Check its settings, or add any other service in front of it.', 'bettershield' ),
	proxy_sends_no_header: () =>
		__( 'The service you added doesn’t pass on visitors’ addresses. Turn that option on in its settings, or ask your host.', 'bettershield' ),
	private_address: () => __( 'Every visitor seems to come from the same internal address, so BetterShield can’t tell them apart.', 'bettershield' ),
};

/** One IPv4 or IPv6 address, or a CIDR range of one, roughly; the server checks it exactly. */
const RANGE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)(?:\/\d{1,3})?$/i;

/**
 * The typed list, one entry a line.
 *
 * @param {string} text What was typed.
 * @return {string[]} The entries.
 */
function entries( text ) {
	return text
		.split( /[\s,]+/ )
		.map( ( line ) => line.trim() )
		.filter( Boolean );
}

export default function ProxySetup() {
	const { saveLoginProtection, runAudit, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ behind, setBehind ] = useState( null );
	const [ text, setText ] = useState( null );
	const [ said, setSaid ] = useState( '' );
	const [ checking, setChecking ] = useState( false );

	const read = () => apiFetch( { path: PATH } );

	useEffect( () => {
		let alive = true;

		read().then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The proxy settings could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading what the last request showed…', 'bettershield' ) }</p>;
	}

	const say = ( words ) => {
		setSaid( words );
		announce( words );
	};

	const saving = isWorking( busy, 'login-protection' );
	const typed = null === text ? state.trusted_proxies.join( '\n' ) : text;
	const list = entries( typed );
	const wrong = list.find( ( entry ) => ! RANGE.test( entry ) ) || '';
	const asks = 'private_address' !== state.reason || true === behind;

	const saved = () => {
		setText( null );
		read().then( setState );
		say( __( 'Saved. Open any other dashboard page, wait a minute, then come back and press Check Again.', 'bettershield' ) );
	};

	const checkAgain = () => {
		setChecking( true );
		read()
			.then( ( answer ) => {
				setState( answer );

				if ( ! answer.current ) {
					say( __( 'Not tested yet. Open another dashboard page, wait a minute, then press Check Again.', 'bettershield' ) );
				} else if ( answer.resolved ) {
					say( __( 'Fixed. BetterShield can now block repeated wrong passwords.', 'bettershield' ) );
					runAudit();
				} else {
					say( __( 'Visitors’ addresses still cannot be read.', 'bettershield' ) );
				}
			} )
			.finally( () => setChecking( false ) );
	};

	return (
		<>
			{ state.reason ? <p className="bs-ds-fix__text">{ CASES[ state.reason ]() }</p> : null }
			{ 'private_address' === state.reason ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Does your site use a service like Cloudflare, or does your host put one in front of it? (Ask your host if unsure.)', 'bettershield' ) }</p>
					<div className="bs-ds-fix__actions">
						<Button type={ true === behind ? 'primary' : 'secondary' } size="sm" aria-pressed={ true === behind } onClick={ () => setBehind( true ) }>
							{ __( 'Yes', 'bettershield' ) }
						</Button>
						<Button type={ false === behind ? 'primary' : 'secondary' } size="sm" aria-pressed={ false === behind } onClick={ () => setBehind( false ) }>
							{ __( 'No', 'bettershield' ) }
						</Button>
					</div>
					{ false === behind ? (
						<p className="bs-ds-fix__note">
							{ __( 'Ask your host why every visitor looks the same to your site. Until that is fixed, one person’s lockout can block everyone.', 'bettershield' ) }
						</p>
					) : null }
				</>
			) : null }
			{ asks && state.cloudflare_seen && ! state.cloudflare ? (
				<div className="bs-ds-fix__record">
					<p className="bs-ds-fix__text">{ __( 'Requests came from Cloudflare’s own address ranges. If this site is behind Cloudflare, trust the visitor address it sends.', 'bettershield' ) }</p>
					<div className="bs-ds-fix__actions">
						<Button type="primary" size="sm" isBusy={ saving } disabled={ saving } onClick={ () => saveLoginProtection( { cloudflare: true }, saved ) }>
							{ __( 'This Site Is Behind Cloudflare', 'bettershield' ) }
						</Button>
					</div>
				</div>
			) : null }
			{ asks ? (
				<div className="bs-ds-fix__record">
					<Field
						kind="textarea"
						label={ __( 'Addresses of your CDN or proxy', 'bettershield' ) }
						help={ __( 'One address or range per line, copied from your host’s or CDN’s documentation.', 'bettershield' ) }
						error={
							wrong
								? __( 'Each line needs to be an IP address or range, such as 10.0.0.0/8.', 'bettershield' )
								: ''
						}
						value={ typed }
						onChange={ setText }
						disabled={ saving }
					/>
					<div className="bs-ds-fix__actions">
						<Button
							type="primary"
							size="sm"
							isBusy={ saving }
							disabled={ saving || Boolean( wrong ) || null === text }
							onClick={ () => saveLoginProtection( { trusted_proxies: list }, saved ) }
						>
							{ __( 'Save Trusted Proxies', 'bettershield' ) }
						</Button>
					</div>
				</div>
			) : null }
			<div className="bs-ds-fix__actions">
				<Button type="secondary" size="sm" isBusy={ checking } disabled={ checking } onClick={ checkAgain }>
					{ __( 'Check Again', 'bettershield' ) }
				</Button>
			</div>
			{ said ? (
				<p className="bs-ds-fix__note" role="status">
					{ said }
				</p>
			) : null }
		</>
	);
}

ProxySetup.kind = 'acts';
