/**
 * Login & access › Recent sign-in attempts: the networks failed sign-ins came
 * from and the names they tried, over the last week or month (#1979).
 *
 * Each line opens the Site log narrowed to it. Which names are real accounts,
 * and the offer to block one that is not, come only to someone who may list
 * the site's users: the server leaves both out for anyone else.
 */

import './Attempts.css';

import apiFetch from '@wordpress/api-fetch';
import { useCallback, useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { activityUrl } from '../../nav';
import { isWorking, useStore } from '../../store';
import { announce } from '../../ui/announce';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Segmented from '../ui/Segmented';
import { SettingsCard } from '../ui/Setting';
import { Loading, ErrorState } from '../ui/States';
import { panelProps } from '../ui/tabKeys';

const SPANS = 'bs-ds-tried-span';

/**
 * The calendar day a span starts on, as the log's date filter takes it.
 *
 * @param {number} days How far back.
 * @return {string} YYYY-MM-DD.
 */
export function spanStart( days ) {
	const day = new Date( Date.now() - days * 86400000 );
	const pad = ( number ) => String( number ).padStart( 2, '0' );

	return `${ day.getFullYear() }-${ pad( day.getMonth() + 1 ) }-${ pad( day.getDate() ) }`;
}

/**
 * One line: what it is, opening the log narrowed to it, and how many tries.
 *
 * @param {Object} props
 * @param {string} props.href     Where it opens.
 * @param {string} props.label    What it is.
 * @param {number} props.count    Attempts.
 * @param {*}      props.children Marks and the offer, after the count.
 */
function Line( { href, label, count, children = null } ) {
	return (
		<li className="bs-ds-tried__line">
			{ href ? (
				<a className="bs-ds-tried__name" href={ href }>
					{ label }
				</a>
			) : (
				<span className="bs-ds-tried__name">{ label }</span>
			) }
			<span className="bs-ds-tried__count">
				{ sprintf(
					/* translators: %s: a number of failed sign-ins. */
					_n( '%s try', '%s tries', count, 'bettershield' ),
					count.toLocaleString()
				) }
			</span>
			{ children }
		</li>
	);
}

/**
 * @param {Object} props
 * @param {Array}  props.blocklist The block list as saved, which a blocked name joins.
 */
export default function Attempts( { blocklist = [] } ) {
	const { saveLoginProtection, busy } = useStore();
	const [ days, setDays ] = useState( 7 );
	const [ read, setRead ] = useState( { status: 'loading', data: null } );
	const saving = isWorking( busy, 'login-protection' );

	const load = useCallback( () => {
		setRead( ( current ) => ( { ...current, status: 'loading' } ) );

		return apiFetch( { path: `/bettershield/v1/login-protection/attempts?days=${ days }` } ).then(
			( data ) => setRead( { status: 'ready', data } ),
			() => setRead( { status: 'error', data: null } )
		);
	}, [ days ] );

	useEffect( () => {
		load();
	}, [ load ] );

	const since = spanStart( days );
	const data = read.data;

	// Added from every network, as a name typed into the list is; read again
	// once it is saved, so the line says Blocked.
	const block = ( name ) => {
		/* translators: %s: a username someone tried at sign-in. */
		announce( sprintf( __( 'Blocking %s…', 'bettershield' ), name ) );
		saveLoginProtection( { blocklist: [ ...blocklist, { username: name } ] }, () => {
			/* translators: %s: a username someone tried at sign-in. */
			announce( sprintf( __( '%s is blocked from signing in.', 'bettershield' ), name ) );
			load();
		} );
	};

	let body;

	if ( 'error' === read.status ) {
		body = <ErrorState onRetry={ load } />;
	} else if ( ! data ) {
		body = <Loading label={ __( 'Loading sign-in attempts…', 'bettershield' ) } />;
	} else if ( ! data.total ) {
		body = (
			<p className="bs-ds-tried__none">
				{ sprintf(
					/* translators: %d: number of days. */
					_n( 'No failed sign-ins in the last %d day.', 'No failed sign-ins in the last %d days.', data.days, 'bettershield' ),
					data.days
				) }
			</p>
		);
	} else {
		body = (
			<>
				<p className="bs-ds-tried__total">
					{ sprintf(
						/* translators: 1: number of failed sign-ins, 2: number of days. */
						_n( '%1$s failed sign-in in the last %2$d days.', '%1$s failed sign-ins in the last %2$d days.', data.total, 'bettershield' ),
						data.total.toLocaleString(),
						data.days
					) }
				</p>
				<div className="bs-ds-tried__lists">
					<section className="bs-ds-tried__list" aria-labelledby="bs-ds-tried-networks">
						<h4 id="bs-ds-tried-networks" className="bs-ds-tried__head">
							{ __( 'Top networks', 'bettershield' ) }
						</h4>
						{ data.networks.length ? (
							<ul>
								{ data.networks.map( ( entry ) => (
									<Line key={ entry.network } href={ activityUrl( { network: entry.network, since } ) } label={ entry.network } count={ entry.count } />
								) ) }
							</ul>
						) : (
							<p className="bs-ds-tried__none">{ __( 'No network could be read.', 'bettershield' ) }</p>
						) }
					</section>
					<section className="bs-ds-tried__list" aria-labelledby="bs-ds-tried-names">
						<h4 id="bs-ds-tried-names" className="bs-ds-tried__head">
							{ __( 'Names tried', 'bettershield' ) }
						</h4>
						<ul>
							{ data.names.map( ( entry ) => (
								<Line key={ entry.name } href={ activityUrl( { search: entry.name, since } ) } label={ entry.name } count={ entry.count }>
									{ entry.account ? <Badge tone="blue">{ __( 'Account', 'bettershield' ) }</Badge> : null }
									{ entry.blocked ? <Badge>{ __( 'Blocked', 'bettershield' ) }</Badge> : null }
									{ entry.blockable ? (
										<Button
											type="secondary"
											size="sm"
											isBusy={ saving }
											disabled={ saving }
											aria-label={ sprintf(
												/* translators: %s: a username someone tried at sign-in. */
												__( 'Block %s from signing in', 'bettershield' ),
												entry.name
											) }
											onClick={ () => block( entry.name ) }
										>
											{ __( 'Block', 'bettershield' ) }
										</Button>
									) : null }
								</Line>
							) ) }
						</ul>
					</section>
				</div>
				{ data.marked ? (
					<p className="bs-ds-tried__note">
						{ __( 'Account marks a name that belongs to someone on this site. A blocked name is refused from every network.', 'bettershield' ) }
					</p>
				) : null }
			</>
		);
	}

	return (
		<SettingsCard
			icon="user-x"
			title={ __( 'Recent sign-in attempts', 'bettershield' ) }
			trailing={
				<Segmented
					id={ SPANS }
					label={ __( 'Period', 'bettershield' ) }
					selected={ String( days ) }
					onSelect={ ( key ) => setDays( Number( key ) ) }
					options={ [
						{ key: '7', label: __( '7 days', 'bettershield' ) },
						{ key: '30', label: __( '30 days', 'bettershield' ) },
					] }
				/>
			}
		>
			<div className="bs-ds-tried" { ...panelProps( SPANS, String( days ) ) }>
				{ body }
			</div>
		</SettingsCard>
	);
}
