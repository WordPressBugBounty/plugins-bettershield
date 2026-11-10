/**
 * Fix for "The sign-in page is served from a page cache" (#2430).
 *
 * One press tells caching plugins, server caches and CDNs not to keep the
 * sign-in page, then asks the page again. A cache that still answers with a
 * stored copy is named, with what it needs. Undo is the protection's own,
 * the same one Protection shows.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';

const ITEM = 'sign_in_no_cache';

export default function SignInPage() {
	const { keepSignInUncached, checkSignInCache, revertItem, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const alive = useRef( true );
	const working = isWorking( busy, 'sign-in-cache' ) || isWorking( busy, ITEM );

	const read = () =>
		apiFetch( { path: '/bettershield/v1/findings/sign_in_page_cached/no-cache' } ).then(
			( answer ) => alive.current && setState( answer ),
			() => alive.current && setUnread( true )
		);

	useEffect( () => {
		read();

		return () => {
			alive.current = false;
		};
	}, [] );

	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The sign-in page’s last check could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the last check…', 'bettershield' ) }</p>;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	// What the check found, said as an outcome.
	const outcome = ( answer ) => {
		setState( answer );

		if ( ! answer.cached ) {
			say( 'success', __( 'The sign-in page was asked for again and came from WordPress, not a cache.', 'bettershield' ) );
			return;
		}

		say(
			'warning',
			answer.caches.length
				? sprintf(
						/* translators: %s: names of caching plugins or services. */
						__( 'A cache still serves a stored copy. Clear it, or exclude the sign-in address, in: %s.', 'bettershield' ),
						answer.caches.join( ', ' )
				  )
				: __( 'A cache still serves a stored copy. Clear it, or exclude the sign-in address in your host’s or CDN’s cache.', 'bettershield' )
		);
	};

	const refused = ( error ) => {
		say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	const apply = () => {
		setSaid( null );
		announce( __( 'Applying, then asking the sign-in page again…', 'bettershield' ) );
		keepSignInUncached( ( answer ) => answer && outcome( answer ), refused );
	};

	const check = () => {
		setSaid( null );
		announce( __( 'Asking the sign-in page again…', 'bettershield' ) );
		checkSignInCache( ( answer ) => answer && outcome( answer ), refused );
	};

	const undo = () => {
		setSaid( null );
		revertItem(
			ITEM,
			() =>
				read().then( () => {
					if ( alive.current ) {
						say( 'success', __( 'The sign-in page is sent as before, with WordPress’s own caching headers only.', 'bettershield' ) );
					}
				} ),
			refused
		);
	};

	return (
		<>
			{ state.address ? (
				<p className="bs-ds-fix__text">
					{ sprintf(
						/* translators: %s: the sign-in address, e.g. "/wp-login.php". */
						__( 'Last checked: %s', 'bettershield' ),
						state.address
					) }
					{ state.headers.length ? ` (${ state.headers.join( ', ' ) })` : '' }
				</p>
			) : null }
			{ state.active ? (
				<p className="bs-ds-fix__text">{ __( 'Caches are told not to keep the sign-in page. A copy one kept before stays until it is cleared.', 'bettershield' ) }</p>
			) : (
				<p className="bs-ds-fix__text">{ __( 'Tells caching plugins, server caches and CDNs not to keep the sign-in page, wherever it has been moved to. No files change.', 'bettershield' ) }</p>
			) }
			{ state.caches.length ? (
				<p className="bs-ds-fix__note">
					{ sprintf(
						/* translators: %s: names of caching plugins or services. */
						__( 'If it stays cached, exclude the sign-in address in: %s.', 'bettershield' ),
						state.caches.join( ', ' )
					) }
				</p>
			) : null }
			<div className="bs-ds-fix__actions">
				{ state.active ? (
					<>
						<Button type="primary" size="sm" isBusy={ isWorking( busy, 'sign-in-cache' ) } disabled={ working } onClick={ check }>
							{ __( 'Check Again', 'bettershield' ) }
						</Button>
						<Armed
							label={ __( 'Undo', 'bettershield' ) }
							consequence={ __( 'The sign-in page is sent with WordPress’s own caching headers only, so a cache may keep it again.', 'bettershield' ) }
							confirm={ __( 'Yes, Undo', 'bettershield' ) }
							busy={ isWorking( busy, ITEM ) }
							disabled={ working }
							onConfirm={ undo }
						/>
					</>
				) : (
					<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ apply }>
						{ __( 'Stop Caching the Sign-In Page', 'bettershield' ) }
					</Button>
				) }
			</div>
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
		</>
	);
}

SignInPage.kind = 'acts';
