/**
 * Network › Incidents: every site's open incidents, ten sites at a time.
 *
 * One card: what the roll-up is, then a table with a group row per site (its
 * name, linking to the site's own screen) and a row per open incident under
 * it, with what the site could not say written in the group as a note. Each
 * site keeps its own evidence, correlation progress and response controls, so
 * nothing here acts on an incident.
 */

import './NetworkIncidents.css';

import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, sprintf } from '@wordpress/i18n';
import { confidenceLabel } from '../data/incidents';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Skeleton, { Bone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';

/** Widths for stand-in sites, so no two neighbors match. */
const SITE_WIDTHS = [ '9em', '12em', '8em' ];

/**
 * Sites standing in for themselves while a page of the roll-up is read: each
 * site's group row, and the rows its incidents will take.
 *
 * @param {Object} props
 * @param {number} props.sites How many.
 */
function SitesBone( { sites } ) {
	return (
		<Skeleton label={ __( 'Loading incidents across the network…', 'bettershield' ) }>
			<div className="bs-ds-netinc__bones">
				{ SITE_WIDTHS.slice( 0, sites ).map( ( width ) => (
					<div key={ width } className="bs-ds-netinc__bonesite">
						<div className="bs-ds-netinc__bonegroup">
							<Bone kind="title" w={ width } />
						</div>
						<div className="bs-ds-bonerow">
							<span className="bs-ds-bonerow__text">
								<Bone kind="title" w="16em" />
								<Bone w="6em" />
							</span>
						</div>
						<div className="bs-ds-bonerow">
							<span className="bs-ds-bonerow__text">
								<Bone kind="title" w="13em" />
								<Bone w="6em" />
							</span>
						</div>
					</div>
				) ) }
			</div>
		</Skeleton>
	);
}

/**
 * One site: its group row, its open incidents, and what it could not say.
 *
 * @param {Object} props
 * @param {Object} props.site The site's part of the roll-up.
 */
function SiteIncidents( { site } ) {
	const incomplete = ! site.unavailable && ( ! site.engine.last_checked_at || site.engine.pending || site.engine.failed );

	return (
		<div role="rowgroup" className="bs-ds-netinc__site">
			<WholeRow kind="group">
				<h3 className="bs-ds-netinc__name">
					<a href={ site.url }>{ site.label || sprintf( /* translators: %d: the site ID in the network. */ __( 'Site #%d', 'bettershield' ), site.site_id ) }</a>
				</h3>
			</WholeRow>
			{ site.unavailable ? (
				<WholeRow kind="note">
					{ 'storage' === site.unavailable_reason ? (
						<>
							{ __( 'Incident history could not be read: this site’s storage needs repair.', 'bettershield' ) }{ ' ' }
							<a href={ site.repair_url }>{ __( 'Repair it from the site’s Overview', 'bettershield' ) }</a>
						</>
					) : (
						__( 'Incident history could not be read. Reload to try again.', 'bettershield' )
					) }
				</WholeRow>
			) : (
				<>
					{ ! site.incidents.length ? <WholeRow kind="note">{ __( 'No open incidents recorded.', 'bettershield' ) }</WholeRow> : null }
					{ site.incidents.map( ( item ) => (
						<Row key={ item.id }>
							<Cell>
								<TitleMeta
									title={ confidenceLabel( item.confidence ) }
									meta={ sprintf(
										/* translators: %d: the incident's own number. */
										__( 'Incident #%d', 'bettershield' ),
										item.id
									) }
								/>
							</Cell>
						</Row>
					) ) }
					{ site.more_incidents ? <WholeRow kind="note">{ __( 'More incidents are available on the site’s screen.', 'bettershield' ) }</WholeRow> : null }
					{ incomplete ? <WholeRow kind="note">{ __( 'Correlation is incomplete or needs a retry. Open the site to review progress.', 'bettershield' ) }</WholeRow> : null }
				</>
			) }
		</div>
	);
}

export default function NetworkIncidents() {
	const [ data, setData ] = useState( null );
	const [ error, setError ] = useState( null );
	const [ busy, setBusy ] = useState( false );
	const generation = useRef( 0 );
	const load = useCallback( async ( cursor = 0 ) => {
		const request = ++generation.current;
		setBusy( true );
		setError( null );
		try {
			const next = await apiFetch( { path: `/bettershield/v1/network/incidents?cursor=${ cursor }` } );
			if ( next.failed ) {
				throw new Error( __( 'The site inventory could not be read.', 'bettershield' ) );
			}
			if ( request === generation.current ) {
				setData( ( previous ) => ( { ...next, sites: cursor ? [ ...previous.sites, ...next.sites ] : next.sites } ) );
			}
		} catch ( e ) {
			if ( request === generation.current ) {
				setError( e );
			}
		} finally {
			if ( request === generation.current ) {
				setBusy( false );
			}
		}
	}, [] );
	useEffect( () => {
		load();
		return () => {
			++generation.current;
		};
	}, [ load ] );

	const sites = data ? data.sites : [];

	/*
	 * The first page stands in as sites where its sites will be; a further
	 * page, asked for at the foot, arrives as sites under the ones already
	 * there — never as a block above them, which pushed every site read so far
	 * down the page while the next ten were fetched.
	 */
	return (
		<Card className="bs-ds-netinc" aria-labelledby="bs-ds-netinc-title">
			<CardHead icon="link-2" title={ __( 'Incidents', 'bettershield' ) } id="bs-ds-netinc-title" />
			<p className="bs-ds-netinc__intro">
				{ __( 'Open incidents, ten sites at a time. Respond from each site.', 'bettershield' ) }
			</p>

			{ error ? (
				<div className="bs-ds-netinc__notes">
					<ErrorState onRetry={ () => load() }>{ error.message }</ErrorState>
				</div>
			) : null }

			{ sites.length ? (
				<Table label={ __( 'Incident records', 'bettershield' ) } columns={ [ { key: 'incident', label: __( 'Incident', 'bettershield' ) } ] }>
					{ sites.map( ( site ) => (
						<SiteIncidents key={ site.site_id } site={ site } />
					) ) }
				</Table>
			) : null }

			{ busy && ! error ? <SitesBone sites={ data ? 2 : 3 } /> : null }

			{ data?.next_cursor > 0 ? (
				<div className="bs-ds-netinc__foot">
					<Button type="secondary" size="sm" isBusy={ busy } disabled={ busy } onClick={ () => load( data.next_cursor ) }>
						{ __( 'Load More Sites', 'bettershield' ) }
					</Button>
				</div>
			) : null }
		</Card>
	);
}
