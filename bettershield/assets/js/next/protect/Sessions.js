/**
 * Login & access › Sessions › Who is signed in: one row per account, its
 * sessions in it, and signing an account (or everyone this reader can) out.
 *
 * Nothing here ends the acting administrator's own session without a
 * confirmation that says so by name.
 */

import './Sessions.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import useMutationFocus from '../../ui/useMutationFocus';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Skeleton, { Bone } from '../ui/Skeleton';
import { EmptyState, Resource } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';

/**
 * Who is signed in, before that read has landed: two accounts in the list's
 * own rows, and the site-wide control under them.
 */
function SessionsBone() {
	return (
		<Skeleton label={ __( 'Loading who is signed in…', 'bettershield' ) }>
			<div className="bs-ds-sessions__bones">
				{ [ '30%', '40%' ].map( ( width ) => (
					<div key={ width } className="bs-ds-bonerow">
						<span className="bs-ds-bonerow__text">
							<Bone kind="title" w={ width } />
							<Bone w="55%" />
						</span>
						<Bone kind="control" w="180px" />
					</div>
				) ) }
			</div>
		</Skeleton>
	);
}

export default function ActiveSessions() {
	const { resource, reload } = useResource( 'sessions' );
	const { endSessions, busy } = useStore();
	// Signing out another account takes its row, and the control with it.
	const heading = useRef( null );
	const afterEnd = useMutationFocus( heading );

	/*
	 * One page of the accounts at a time, the reader and the accounts that can
	 * change the site first. Every signed-in account was drawn at once, and a
	 * store's customers made a page three hundred thousand pixels tall. Pages
	 * read after the first are kept here until the list is read again.
	 */
	const [ more, setMore ] = useState( [] );
	const [ loadingMore, setLoadingMore ] = useState( false );
	const firstPage = resource && resource.data ? resource.data.sessions : null;

	useEffect( () => setMore( [] ), [ firstPage ] );

	return (
		<div className="bs-ds-sessions">
			<div className="bs-ds-sessions__head">
				<h3 className="bs-ds-sessions__title" ref={ heading } tabIndex={ -1 }>
					{ __( 'Who is signed in', 'bettershield' ) }
				</h3>
			</div>
			<Resource resource={ resource } onRetry={ reload } loading={ <SessionsBone /> }>
				{ ( data ) => {
					const users = [ ...( data.sessions || [] ), ...more ];
					const total = data.total ?? users.length;
					const reach = data.reach || { reaches: 0, leaves: 0 };
					const showMore = () => {
						setLoadingMore( true );
						apiFetch( { path: `/bettershield/v1/login-protection/sessions?offset=${ users.length }` } )
							.then( ( next ) => setMore( ( shown ) => [ ...shown, ...( ( next && next.sessions ) || [] ) ] ) )
							.catch( () => {} )
							.finally( () => setLoadingMore( false ) );
					};
					const me = ( users.find( ( u ) => u.is_me ) || {} ).login || __( 'you', 'bettershield' );

					return (
						<>
							{ users.length ? (
								<Table
									label={ __( 'Who is signed in', 'bettershield' ) }
									columns={ [
										{ key: 'who', label: __( 'Who', 'bettershield' ), width: 'minmax(0, 1fr)' },
										{ key: 'sessions', label: __( 'Sessions', 'bettershield' ), width: 'minmax(0, 1.6fr)' },
										{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
									] }
								>
									{ users.map( ( user ) => (
										<Row key={ user.user_id } className="bs-ds-session">
											<Cell>
												<TitleMeta
													title={
														<span className="bs-ds-session__who">
															<span>{ user.login }</span>
															{ user.is_me ? <Badge tone="brand">{ __( 'you', 'bettershield' ) }</Badge> : null }
														</span>
													}
													meta={ ( user.roles || [] ).join( ', ' ) }
												/>
											</Cell>
											<Cell>
												<ul className="bs-ds-session__list">
													{ ( user.sessions || [] ).map( ( session, index ) => (
														<li key={ index }>
															<span>
																{ /* Activity is stamped only while idle
																     sign-out is on; without it the sign-in
																     time stood in for "last seen" (#2068),
																     and the note why is said once, under the
																     table (#2576). */ }
																{ session.last_seen_at
																	? sprintf(
																			/* translators: 1: sign-in time, 2: last activity time. */
																			__( 'Signed in %1$s · last seen %2$s', 'bettershield' ),
																			formatTime( session.signed_in_at ),
																			formatTime( session.last_seen_at )
																	  )
																	: sprintf(
																			/* translators: %s: sign-in time. */
																			__( 'Signed in %s', 'bettershield' ),
																			formatTime( session.signed_in_at )
																	  ) }
															</span>
															{ session.ip ? <span className="bs-ds-session__ip">{ session.ip }</span> : null }
														</li>
													) ) }
												</ul>
											</Cell>
											<Cell align="end">
												<Armed
													label={ __( 'Sign Out All Their Sessions', 'bettershield' ) }
													// Whose, in the name: every row's read the same (#1928).
													aria-label={ sprintf(
														/* translators: %s: the username whose sessions end. */
														__( 'Sign Out All Their Sessions: %s', 'bettershield' ),
														user.login
													) }
													consequence={
														user.is_me
															? sprintf(
																	/* translators: %s: the acting administrator's own username. */
																	__( 'These are your own sessions, %s, including this one. You will be signed out.', 'bettershield' ),
																	user.login
															  )
															: sprintf(
																	/* translators: %s: username. */
																	__( '%s is signed out on every device. Their account and password are untouched.', 'bettershield' ),
																	user.login
															  )
													}
													busy={ isWorking( busy, `sessions-${ user.user_id }` ) }
													onConfirm={ () => endSessions( { user_id: user.user_id }, afterEnd( () => {} ) ) }
												/>
											</Cell>
										</Row>
									) ) }
									{ total > users.length ? (
										<WholeRow
											kind="foot"
											aside={
												<Button type="ghost" size="sm" isBusy={ loadingMore } disabled={ loadingMore } onClick={ showMore }>
													{ __( 'Show More', 'bettershield' ) }
												</Button>
											}
										>
											{ sprintf(
												/* translators: 1: how many signed-in accounts are listed, 2: how many there are. */
												__( 'Showing %1$d of %2$d signed-in accounts.', 'bettershield' ),
												users.length,
												total
											) }
										</WholeRow>
									) : null }
								</Table>
							) : (
								<EmptyState>{ __( 'Nobody is signed in right now.', 'bettershield' ) }</EmptyState>
							) }

							<div className="bs-ds-sessions__all">
								{ users.some( ( user ) => ( user.sessions || [] ).some( ( session ) => ! session.last_seen_at ) ) ? (
									<p className="bs-ds-sessions__note">{ __( 'Last activity shows once idle sign-out is on.', 'bettershield' ) }</p>
								) : null }
								<Armed
									label={ __( 'Sign Out Everyone', 'bettershield' ) }
									consequence={
										reach.leaves > 0
											? sprintf(
													/* translators: 1: sessions this will end, 2: sessions it will leave, 3: the acting user's own username. */
													__(
														'This signs out %1$d devices, including yours (%3$s). %2$d belong to accounts you can’t manage and stay signed in. Passwords don’t change.',
														'bettershield'
													),
													reach.reaches,
													reach.leaves,
													me
											  )
											: sprintf(
													/* translators: %s: the acting administrator's own username. */
													__(
														'Every session ends, yours (%s) included. You are signed out at once; your password still works.',
														'bettershield'
													),
													me
											  )
									}
									busy={ isWorking( busy, 'sessions-site' ) }
									onConfirm={ () => endSessions( { scope: 'site' } ) }
								/>
							</div>
						</>
					);
				} }
			</Resource>
		</div>
	);
}
