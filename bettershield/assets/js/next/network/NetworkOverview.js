/**
 * The network's home: every site's posture, and the four things that are set
 * once for all of them.
 *
 * The sites table is the reason this screen exists — without it a network
 * administrator opens each dashboard one at a time to learn anything at all.
 * Under it sit the cards for the state that belongs to the network rather
 * than to any site: the two policies set above every site, where the move to
 * the shared tables stands, the one link that opens all of them, the sign-in
 * keys, and the network's rulings that can be put back.
 *
 * Each card fetches for itself. They answer at different speeds and two of
 * them may not answer at all on an install where their half is not present, so
 * a single load that fails takes down one card rather than the screen.
 */

import './NetworkOverview.css';
import NetworkHubConnect from './NetworkHubConnect';

import { useCallback, useEffect, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { __, _n, sprintf } from '@wordpress/i18n';
import useMutationFocus from '../../ui/useMutationFocus';
import { formatTime, isWorking, useStore } from '../../store';
import { graceDaysProblem } from '../../ui/validate';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { CopyButton } from '../ui/CopyField';
import Field from '../ui/Field';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import SettingRow, { Saved, SettingsCard } from '../ui/Setting';
import Skeleton, { Bone, CardBone } from '../ui/Skeleton';
import { ErrorState } from '../ui/States';
import Table, { Cell, Row, TitleMeta } from '../ui/Table';
import Topics from '../ui/Topics';

/**
 * One read, with the four answers a network card can have.
 *
 * `absent` is the fourth and the reason this is not the shared resource store:
 * a route that is not registered is not a failure, it is a half of the product
 * this install does not have, and saying "that could not be loaded" about it
 * would be untrue.
 *
 * @param {string} path The route.
 * @return {{status: string, data: ?Object, reload: Function}} The read.
 */
function useNetworkRead( path ) {
	const [ state, setState ] = useState( { status: 'loading', data: null } );
	const generation = useRef( 0 );

	const load = useCallback( () => {
		const request = ++generation.current;

		setState( ( current ) => ( { status: 'loading', data: current.data } ) );

		return apiFetch( { path } )
			.then( ( data ) => {
				if ( request === generation.current ) {
					setState( { status: 'ready', data } );
				}
			} )
			.catch( ( failure ) => {
				if ( request !== generation.current ) {
					return;
				}

				setState( {
					status: failure && 'rest_no_route' === failure.code ? 'absent' : 'error',
					data: null,
				} );
			} );
	}, [ path ] );

	useEffect( () => {
		load();
		return () => {
			++generation.current;
		};
	}, [ load ] );

	return { ...state, reload: load };
}

/**
 * A part the install does not have the other half of yet, said in the card it
 * would have filled.
 *
 * @param {Object} props
 * @param {*}      props.children What is not here.
 */
function NotHereYet( { children } ) {
	return (
		<div className="bs-ds-network__notes">
			<Alert layout="default" tone="info" live desc={ children } />
		</div>
	);
}

/**
 * A card's title that takes focus, for the action that disables its own
 * control: the keyboard lands on the card rather than on the page.
 *
 * @param {Object} props
 * @param {Object} props.headingRef Takes the title.
 * @param {*}      props.children   The title.
 */
function FocusTitle( { headingRef, children } ) {
	return (
		<span ref={ headingRef } tabIndex={ -1 } className="bs-ds-network__title">
			{ children }
		</span>
	);
}

/* ---- the sites table ------------------------------------------------------- */

/** The table's columns, with the narrow layout's own names for two of them. */
const SITE_COLUMNS = () => [
	{ key: 'site', label: __( 'Site', 'bettershield' ) },
	{ key: 'score', label: __( 'Score', 'bettershield' ), width: '96px' },
	{ key: 'open', label: __( 'Open findings', 'bettershield' ), width: '112px' },
	{ key: 'audited', label: __( 'Last audit', 'bettershield' ), width: '176px' },
	{ key: 'state', label: __( 'State', 'bettershield' ), width: 'minmax(0, 224px)' },
];

/**
 * A cell's name, drawn only where the cells stack and the header strip is not
 * drawn; assistive technology reads the header instead.
 *
 * @param {Object} props
 * @param {*}      props.children The name.
 */
function NarrowLabel( { children } ) {
	return (
		<span className="bs-ds-netsites__label" aria-hidden="true">
			{ children }
		</span>
	);
}

/**
 * @param {Object} props
 * @param {Object} props.site One site's row of the roll-up.
 */
function SiteRow( { site } ) {
	const who = (
		<Cell className="bs-ds-netsites__who">
			<TitleMeta
				title={
					<a className="bs-ds-netsites__name" href={ site.admin }>
						{ site.name }
					</a>
				}
				meta={ site.url }
			/>
		</Cell>
	);

	if ( ! site.installed ) {
		return (
			<Row className="bs-ds-netsites__row">
				{ who }
				<Cell className="bs-ds-netsites__quiet bs-ds-netsites__rest">
					{ __( 'Not set up here yet. Opening this site’s dashboard sets it up.', 'bettershield' ) }
				</Cell>
			</Row>
		);
	}

	return (
		<Row className="bs-ds-netsites__row">
			{ who }

			<Cell className="bs-ds-netsites__score">
				{ null === site.score ? (
					<span className="bs-ds-netsites__quiet">{ __( 'Not audited yet', 'bettershield' ) }</span>
				) : (
					<>
						<span className="bs-ds-netsites__figure">{ site.score }</span>
						<span className="bs-ds-netsites__grade">{ site.grade }</span>
					</>
				) }
			</Cell>

			<Cell className="bs-ds-netsites__open">
				<NarrowLabel>{ __( 'Open findings', 'bettershield' ) }</NarrowLabel>
				{ null === site.open_findings || undefined === site.open_findings ? (
					<span className="bs-ds-netsites__quiet">{ __( 'Not audited yet', 'bettershield' ) }</span>
				) : (
					site.open_findings
				) }
			</Cell>

			<Cell className="bs-ds-netsites__audited">
				<NarrowLabel>{ __( 'Last audit', 'bettershield' ) }</NarrowLabel>
				{ site.audited_at ? formatTime( site.audited_at ) : __( 'Never', 'bettershield' ) }
			</Cell>

			<Cell className="bs-ds-netsites__state">
				{ site.migrated ? (
					<Badge tone={ kindTone( 'good' ) }>{ __( 'Carried over', 'bettershield' ) }</Badge>
				) : (
					<Badge tone={ kindTone( 'neutral' ) }>{ __( 'Not yet carried over', 'bettershield' ) }</Badge>
				) }
				{ site.recovery_link ? null : <Badge tone={ kindTone( 'medium' ) }>{ __( 'No way back in', 'bettershield' ) }</Badge> }
			</Cell>
		</Row>
	);
}

/** Widths for stand-in sites, so no two neighbors match. */
const SITE_WIDTHS = [ '9em', '12em', '7em', '10em' ];

/**
 * The sites card before the roll-up has been read: its head and control, its
 * sentence, the header strip and rows in the table's five columns.
 */
function SitesBone() {
	return (
		<Skeleton label={ __( 'Loading the sites on this network…', 'bettershield' ) }>
			<div className="bs-ds-card">
				<div className="bs-ds-card__head">
					<span className="bs-ds-bone bs-ds-bone--tile" />
					<Bone kind="title" w="12em" />
					<span className="bs-ds-spacer" />
					<Bone kind="control" w="160px" />
				</div>
				<div className="bs-ds-network__boneintro">
					<Bone w="30em" />
				</div>
				<div className="bs-ds-netsites__bonehead">
					<Bone w="3em" />
					<Bone w="3.5em" />
					<Bone w="4em" />
					<Bone w="5em" />
					<Bone w="3em" />
				</div>
				{ SITE_WIDTHS.map( ( width ) => (
					<div key={ width } className="bs-ds-netsites__bonerow">
						<span className="bs-ds-bonerow__text">
							<Bone kind="title" w={ width } />
							<Bone w="13em" />
						</span>
						<Bone w="3em" />
						<Bone w="1.5em" />
						<Bone w="9em" />
						<Bone kind="control" w="96px" />
					</div>
				) ) }
				<div className="bs-ds-network__bonefoot">
					<Bone w="12em" />
				</div>
			</div>
		</Skeleton>
	);
}

function SitesTable() {
	const { status, data, reload } = useNetworkRead( '/bettershield/v1/network/sites' );
	const { refreshNetworkSites, busy } = useStore();
	const working = isWorking( busy, 'network-sites' );

	/*
	 * Later pages, appended below the first as they are asked for. Kept apart
	 * from the first page so a refresh, which re-reads the first page, starts
	 * the list over rather than leaving an older page appended to a newer one.
	 */
	const [ more, setMore ] = useState( { sites: [], next: null } );
	const [ appending, setAppending ] = useState( false );
	const [ appendError, setAppendError ] = useState( '' );

	useEffect( () => {
		setMore( { sites: [], next: null } );
		setAppendError( '' );
	}, [ data ] );

	if ( 'loading' === status && ! data ) {
		return <SitesBone />;
	}

	if ( 'error' === status || 'absent' === status ) {
		return <ErrorState onRetry={ reload } />;
	}

	const sites = [ ...( data.sites || [] ), ...more.sites ];
	const short = sites.filter( ( site ) => site.installed && ! site.recovery_link ).length;
	const total = Math.max( Number( data.total ) || 0, sites.length );
	const next = null === more.next ? Number( data.next_cursor ) || 0 : more.next;
	const partial = total > sites.length;

	const showMore = () => {
		setAppending( true );
		setAppendError( '' );

		apiFetch( { path: `/bettershield/v1/network/sites?cursor=${ next }` } )
			.then(
				( page ) => setMore( ( old ) => ( { sites: [ ...old.sites, ...( page.sites || [] ) ], next: Number( page.next_cursor ) || 0 } ) ),
				( error ) => setAppendError( error.message || __( 'The next sites could not be read. Try again.', 'bettershield' ) )
			)
			.finally( () => setAppending( false ) );
	};

	return (
		<Card className="bs-ds-netsites" aria-labelledby="bs-ds-netsites-title">
			<CardHead icon="gauge" title={ __( 'Every site on this network', 'bettershield' ) } id="bs-ds-netsites-title">
				<Button type="secondary" size="sm" icon="refresh-cw" iconTone="2" isBusy={ working } disabled={ working } onClick={ () => refreshNetworkSites( reload ) }>
					{ working ? __( 'Reading…', 'bettershield' ) : __( 'Read Them Again Now', 'bettershield' ) }
				</Button>
			</CardHead>

			{ /* What the whole screen is, said once, on the card it is mostly about. */ }
			<p className="bs-ds-network__intro">
				{ __( 'Each site handles its own security; the network sets a few things for all.', 'bettershield' ) }
			</p>

			{ partial || short ? (
				<div className="bs-ds-network__notes">
					{ partial ? (
						<p className="bs-ds-netsites__count" role="status">
							{ sprintf(
								/* translators: 1: sites shown, 2: sites on the network. */
								__( 'Showing %1$d of %2$d sites.', 'bettershield' ),
								sites.length,
								total
							) }
						</p>
					) : null }

					{ short ? (
						<Alert
							layout="default"
							tone="warning"
							live
							desc={
								partial
									? sprintf(
											/* translators: 1: how many of the sites shown have no way back in, 2: how many sites are shown. */
											_n(
												'%1$d of the %2$d sites shown has no working recovery link or recovery codes. Passkey-only roles cannot be widened until every site, shown or not, has one.',
												'%1$d of the %2$d sites shown have no working recovery link or recovery codes. Passkey-only roles cannot be widened until every site, shown or not, has one.',
												short,
												'bettershield'
											),
											short,
											sites.length
									  )
									: sprintf(
											/* translators: %d: how many sites have no way back in. */
											_n(
												'%d site has no working recovery link or recovery codes. Passkey-only roles cannot be widened until every site has one.',
												'%d sites have no working recovery link or recovery codes. Passkey-only roles cannot be widened until every site has one.',
												short,
												'bettershield'
											),
											short
									  )
							}
						/>
					) : null }
				</div>
			) : null }

			<Table className="bs-ds-netsites__table" label={ __( 'Sites on this network', 'bettershield' ) } columns={ SITE_COLUMNS() }>
				{ sites.map( ( site ) => (
					<SiteRow key={ site.id } site={ site } />
				) ) }
			</Table>

			{ appendError ? (
				<p className="bs-ds-netsites__error" role="alert">
					{ appendError }
				</p>
			) : null }

			<div className="bs-ds-network__foot">
				{ next > 0 ? (
					<Button type="secondary" size="sm" isBusy={ appending } disabled={ appending } onClick={ showMore }>
						{ appending ? __( 'Reading…', 'bettershield' ) : __( 'Show More Sites', 'bettershield' ) }
					</Button>
				) : null }
				<span className="bs-ds-network__footnote">
					{ sprintf(
						/* translators: %s: an absolute date and time. */
						__( 'Read %s.', 'bettershield' ),
						formatTime( new Date( data.built_at * 1000 ).toISOString() )
					) }
				</span>
				<Saved forKey="network-sites" />
			</div>

			<NetworkHubConnect sites={ sites } />

			<Topics
				className="bs-ds-network__topics"
				items={ [
					{
						key: 'figures',
						label: __( 'How this works', 'bettershield' ),
						text: __(
							'These come from each site’s last audit and are saved for a while.',
							'bettershield'
						),
					},
				] }
			/>
		</Card>
	);
}

/* ---- the two policies ------------------------------------------------------ */

/**
 * The policies card's rows before their read has landed: each row's title and
 * badge, its sentence, its roles, and its save.
 */
function PoliciesBone() {
	return (
		<Skeleton label={ __( 'Loading the network policies…', 'bettershield' ) }>
			{ [ [ '15em', true ], [ '14em', false ] ].map( ( [ width, grace ] ) => (
				<div key={ width } className="bs-ds-netpolicy__bone">
					<span className="bs-ds-bonerow__text">
						<Bone kind="title" w={ width } />
						<Bone w="85%" />
					</span>
					<span className="bs-ds-netpolicy__boneroles">
						{ [ '6em', '4.5em', '5em', '6.5em', '5.5em' ].map( ( role ) => (
							<Bone key={ role } w={ role } />
						) ) }
					</span>
					{ grace ? <Bone kind="control" w="120px" /> : null }
					<Bone kind="control" w="64px" />
				</div>
			) ) }
		</Skeleton>
	);
}

/**
 * @param {Object}   props
 * @param {number}   props.revision   Moves when a ruling is put back from the
 *                                    undo card, which changes what this card read.
 * @param {Function} props.onSaved    Called once a save lands, which adds a
 *                                    ruling the undo card lists.
 * @param {Object}   props.headingRef Takes the card's title, where the undo card
 *                                    puts focus when its own row has gone.
 */
function PoliciesCard( { revision, onSaved, headingRef } ) {
	const { status, data, reload } = useNetworkRead( '/bettershield/v1/network/policies' );
	const { saveNetworkPolicy, busy } = useStore();
	const [ draft, setDraft ] = useState( null );
	const seen = useRef( revision );
	const headings = { two_factor: useRef( null ), passkey: useRef( null ) };
	const afterSave = {
		two_factor: useMutationFocus( headings.two_factor ),
		passkey: useMutationFocus( headings.passkey ),
	};

	/*
	 * A put-back changes the policy under this card. Read again, and drop
	 * any draft: one built on the old roles would post them back with the
	 * next Save and require them on every site again.
	 */
	useEffect( () => {
		if ( seen.current === revision ) {
			return;
		}

		seen.current = revision;
		setDraft( null );
		reload();
	}, [ revision, reload ] );

	const saving = isWorking( busy, 'network-policies-two_factor', 'network-policies-passkey' );

	const card = ( children ) => (
		<SettingsCard icon="users" title={ <FocusTitle headingRef={ headingRef }>{ __( 'Set once, for every site', 'bettershield' ) }</FocusTitle> }>
			{ children }
		</SettingsCard>
	);

	if ( 'loading' === status && ! data ) {
		return card( <PoliciesBone /> );
	}

	if ( 'error' === status ) {
		return card(
			<div className="bs-ds-network__notes">
				<ErrorState onRetry={ reload } />
			</div>
		);
	}

	if ( 'absent' === status ) {
		return card( <NotHereYet>{ __( 'This site did not answer the request for network policies. Check that BetterShield is installed in full and network-activated, at the same version on every site.', 'bettershield' ) }</NotHereYet> );
	}

	const roles = data.roles || [];
	const current = draft || { two_factor: data.two_factor, passkey: data.passkey };

	/*
	 * The grace field is read as its text, as the site's own screen reads it.
	 * Number( '' ) is 0, so a cleared field saved a zero-day floor, and every
	 * site runs the shorter of its own grace and this one.
	 */
	const grace = String( current.two_factor.grace_days ?? '' ).trim();
	const graceProblem = graceDaysProblem( grace );

	const change = ( section, changes ) => setDraft( { ...current, [ section ]: { ...current[ section ], ...changes } } );

	/*
	 * Only the fields the route takes. The read carries `set` beside them —
	 * whether the network has chosen anything at all — and sending that back
	 * would be the screen posting a fact the server derives.
	 */
	const payload = ( section ) =>
		'two_factor' === section ? { roles: current.two_factor.roles || [], grace_days: Number( grace ) } : { roles: current.passkey.roles || [] };

	// A landed save leaves nothing to save, so its button is disabled under
	// the reader; focus goes to the row's title rather than the page.
	const save = ( section ) =>
		saveNetworkPolicy(
			section,
			payload( section ),
			afterSave[ section ]( () => {
				setDraft( null );
				onSaved();
				return reload();
			} )
		);

	const dirty = ( section ) => {
		if ( ! draft ) {
			return false;
		}

		// Compared as the number it will be sent as, so typing the saved
		// value back leaves nothing to save.
		const mine = 'two_factor' === section && ! graceProblem ? { ...draft.two_factor, grace_days: Number( grace ) } : draft[ section ];

		return JSON.stringify( mine ) !== JSON.stringify( data[ section ] );
	};

	const options = roles.map( ( role ) => ( { value: role.slug, label: role.label } ) );

	/*
	 * Saved with no role ticked is still a decision (nothing is required),
	 * but "Set" over an empty list read as a requirement in force (#1922).
	 */
	const standing = ( policy ) => {
		if ( ! policy.set ) {
			return <Badge tone={ kindTone( 'muted' ) }>{ __( 'Not set', 'bettershield' ) }</Badge>;
		}

		return ( policy.roles || [] ).length ? (
			<Badge tone={ kindTone( 'good' ) }>{ __( 'Set', 'bettershield' ) }</Badge>
		) : (
			<Badge tone={ kindTone( 'muted' ) }>{ __( 'None required', 'bettershield' ) }</Badge>
		);
	};

	return card(
		<>
			<SettingRow
				className="bs-ds-netpolicy"
				// Named so the role picker under it can say which policy its
				// roles are for (#2030).
				id="bs-ds-netpolicy-two-factor-title"
				title={ <FocusTitle headingRef={ headings.two_factor }>{ __( 'Require two-factor across the network', 'bettershield' ) }</FocusTitle> }
				name={ __( 'Require two-factor across the network', 'bettershield' ) }
				badge={ standing( data.two_factor ) }
				about={ __(
					'Sites can require more than this, but not less.',
					'bettershield'
				) }
				tip={ __(
					'Each site keeps its own choice and adds this to it. Each site’s grace period counts from when that site first saw the account.',
					'bettershield'
				) }
			>
				<Field
					kind="checks"
					className="bs-ds-netpolicy__roles"
					aria-labelledby="bs-ds-netpolicy-two-factor-title"
					value={ current.two_factor.roles || [] }
					disabled={ saving }
					options={ options }
					onChange={ ( next ) => change( 'two_factor', { roles: next } ) }
				/>

				<Field
					className="bs-ds-netpolicy__grace"
					width="sm"
					type="number"
					min={ 0 }
					max={ 90 }
					label={ __( 'Grace period, in days', 'bettershield' ) }
					help={ graceProblem || __( 'If a site sets one too, the shorter applies. Zero asks at once.', 'bettershield' ) }
					disabled={ saving }
					value={ String( current.two_factor.grace_days ) }
					onChange={ ( value ) => change( 'two_factor', { grace_days: value } ) }
				/>

				<div className="bs-ds-netpolicy__save">
					<Button
						// The card's one Primary is the Save of the row with changes.
						type={ dirty( 'two_factor' ) ? 'primary' : 'secondary' }
						size="sm"
						isBusy={ isWorking( busy, 'network-policies-two_factor' ) }
						disabled={ saving || ! dirty( 'two_factor' ) || Boolean( graceProblem ) }
						onClick={ () => save( 'two_factor' ) }
					>
						{ __( 'Save', 'bettershield' ) }
					</Button>
					<Saved forKey="network-policies-two_factor" />
				</div>
			</SettingRow>

			<SettingRow
				className="bs-ds-netpolicy"
				id="bs-ds-netpolicy-passkey-title"
				title={ <FocusTitle headingRef={ headings.passkey }>{ __( 'Passkey-only roles across the network', 'bettershield' ) }</FocusTitle> }
				badge={ standing( data.passkey ) }
				about={ __(
					'Widening this needs a working recovery link or recovery codes on every site.',
					'bettershield'
				) }
			>
				<Field
					kind="checks"
					className="bs-ds-netpolicy__roles"
					aria-labelledby="bs-ds-netpolicy-passkey-title"
					value={ current.passkey.roles || [] }
					disabled={ saving }
					options={ options }
					onChange={ ( next ) => change( 'passkey', { roles: next } ) }
				/>

				<div className="bs-ds-netpolicy__save">
					<Button
						// The card's one Primary is the Save of the row with changes.
						type={ dirty( 'passkey' ) ? 'primary' : 'secondary' }
						size="sm"
						isBusy={ isWorking( busy, 'network-policies-passkey' ) }
						disabled={ saving || ! dirty( 'passkey' ) }
						onClick={ () => save( 'passkey' ) }
					>
						{ __( 'Save', 'bettershield' ) }
					</Button>
					<Saved forKey="network-policies-passkey" />
				</div>
			</SettingRow>
		</>
	);
}

/* ---- the migration --------------------------------------------------------- */

function MigrationCard() {
	const { status, data, reload } = useNetworkRead( '/bettershield/v1/network/migration' );

	if ( 'loading' === status && ! data ) {
		return (
			<Skeleton label={ __( 'Loading the migration’s progress…', 'bettershield' ) }>
				<CardBone rows={ [ '9em', '6em' ] } />
			</Skeleton>
		);
	}

	if ( 'error' === status ) {
		return <ErrorState onRetry={ reload } />;
	}

	if ( 'absent' === status ) {
		return null;
	}

	const done = data.complete;

	/*
	 * Three states, not two. A network where the copy has not begun is not "in
	 * progress" — saying so about a network that has never been touched is the
	 * kind of quietly wrong dashboard this product exists not to be.
	 */
	const standing = done
		? { kind: 'good', label: __( 'Finished', 'bettershield' ) }
		: data.retrying
		? { kind: 'medium', label: __( 'Waiting to retry', 'bettershield' ) }
		: 'running' === data.status
		? { kind: 'neutral', label: __( 'In progress', 'bettershield' ) }
		: // Reopened for a site added since it finished: it has started, and
		// "Not started" beside the date it started read as a contradiction.
		data.started_at
		? { kind: 'neutral', label: __( 'Catching up a new site', 'bettershield' ) }
		: { kind: 'muted', label: __( 'Not started', 'bettershield' ) };

	return (
		<Card className="bs-ds-netmove" aria-labelledby="bs-ds-netmove-title">
			<CardHead icon="database" title={ __( 'Moving the log to the shared tables', 'bettershield' ) } id="bs-ds-netmove-title">
				<Badge tone={ kindTone( standing.kind ) }>{ standing.label }</Badge>
			</CardHead>

			<p className="bs-ds-network__intro">
				{ data.retrying
					? __( 'A batch failed; the next run retries from where it stopped. Original records are untouched.', 'bettershield' )
					: done
					? __( 'Every site’s rows are in the shared tables. The originals are untouched.', 'bettershield' )
					: __( 'It runs in small scheduled batches and never slows a page. Nothing is removed.', 'bettershield' ) }
			</p>

			<KeyValues className="bs-ds-netmove__figures">
				<KeyValue
					label={ __( 'Sites carried over', 'bettershield' ) }
					value={ sprintf(
						/* translators: 1: sites finished, 2: sites in total. */
						__( '%1$d of %2$d', 'bettershield' ),
						data.sites_done,
						data.sites_total
					) }
				/>

				{ data.current.site_id ? <KeyValue label={ __( 'Working on', 'bettershield' ) } value={ data.current.site_label } /> : null }

				{ data.resealed_days ? <KeyValue label={ __( 'Days re-sealed', 'bettershield' ) } value={ data.resealed_days } /> : null }

				{ data.ignored_rows ? <KeyValue label={ __( 'Rows already present', 'bettershield' ) } value={ data.ignored_rows } /> : null }
			</KeyValues>

			<Topics
				className="bs-ds-network__topics"
				items={ [
					{
						key: 'how',
						label: __( 'How this works', 'bettershield' ),
						text: __(
							'The log, findings, agent record and passkeys are stored once for the network, so this page can read across sites.',
							'bettershield'
						),
					},
				] }
			/>
		</Card>
	);
}

/* ---- the way back in ------------------------------------------------------- */

/** The way back in and the key rotation before their read has landed. */
function RecoveryCardsBone() {
	return (
		<Skeleton label={ __( 'Loading the network’s way back in…', 'bettershield' ) }>
			<CardBone rows={ [ '100%', '30%' ] } />
			<CardBone rows={ [ '100%', '62%' ] } />
		</Skeleton>
	);
}

function RecoveryCard() {
	const { status, data, reload } = useNetworkRead( '/bettershield/v1/network/recovery/link' );
	const { generateNetworkRecovery, rotateNetworkKeys, endNetworkSafeMode, busy } = useStore();
	const [ url, setUrl ] = useState( null );
	// Moves once the keys are rotated, which puts the confirmation away: it is
	// held while the request runs and after a refusal, so a retry is one press.
	const [ rotations, setRotations ] = useState( 0 );
	const heading = useRef( null );
	const afterMutation = useMutationFocus( heading );
	const keysHeading = useRef( null );
	const afterRotate = useMutationFocus( keysHeading );

	const making = isWorking( busy, 'network-recovery' );
	const rotating = isWorking( busy, 'network-keys' );
	const ending = isWorking( busy, 'network-safe-mode' );

	if ( 'loading' === status && ! data ) {
		return <RecoveryCardsBone />;
	}

	if ( 'error' === status ) {
		return <ErrorState onRetry={ reload } />;
	}

	const title = <FocusTitle headingRef={ heading }>{ __( 'Recovery link for the network', 'bettershield' ) }</FocusTitle>;

	if ( 'absent' === status ) {
		return (
			<Card className="bs-ds-netrecovery" aria-labelledby="bs-ds-netrecovery-title">
				<CardHead icon="door-open" title={ title } id="bs-ds-netrecovery-title" />
				<NotHereYet>{ __( 'This site did not answer the request for a network recovery link. Check that BetterShield is installed in full and network-activated, at the same version on every site.', 'bettershield' ) }</NotHereYet>
			</Card>
		);
	}

	const link = data.link || {};
	const paused = Boolean( data.safe_mode && data.safe_mode.active );

	return (
		<>
			<Card className="bs-ds-netrecovery" aria-labelledby="bs-ds-netrecovery-title">
				<CardHead icon="door-open" title={ title } id="bs-ds-netrecovery-title">
					<Button
						type="primary"
						size="sm"
						isBusy={ making }
						disabled={ making }
						onClick={ () =>
							generateNetworkRecovery(
								afterMutation( ( made ) => {
									setUrl( made.url || null );
									return reload();
								} )
							)
						}
					>
						{ link.exists ? __( 'Generate a New Link', 'bettershield' ) : __( 'Generate Recovery Link', 'bettershield' ) }
					</Button>
				</CardHead>

				<p className="bs-ds-network__intro">
					{ __(
						'Opening the link and pressing the button there pauses enforcement on every site for an hour, without a password or second factor. A site’s own link pauses only that site.',
						'bettershield'
					) }
				</p>

				<Saved forKey="network-recovery" />

				{ paused ? (
					<div className="bs-ds-network__notes">
						<Alert
							layout="default"
							tone="warning"
							live
							desc={ __( 'Enforcement is paused on every site. It resumes on its own, with nothing turned off or lost.', 'bettershield' ) }
							actions={
								<>
									{ /* Ended here or nowhere: a site's own "End safe mode
									     now" does not reach the network's pause. */ }
									<Button type="secondary" size="sm" isBusy={ ending } disabled={ ending } onClick={ () => endNetworkSafeMode( afterMutation( reload ) ) }>
										{ __( 'End the Pause Now', 'bettershield' ) }
									</Button>
									<Saved forKey="network-safe-mode" />
								</>
							}
						/>
					</div>
				) : null }

				{ /*
				   The URL is shown once and kept nowhere, so an admin who is
				   not told it appeared can navigate away from a value nobody
				   can produce again. "Saved." does not say a secret is on the
				   screen; this does.
				*/ }
				{ url ? (
					<div className="bs-ds-netrecovery__reveal" role="status">
						<p className="bs-ds-netrecovery__secret">{ url }</p>
						{ /* Copied in one press, as a site's own link is: shown once,
						     it was left to be selected by hand (#1937). */ }
						<CopyButton text={ url } label={ __( 'Copy Link', 'bettershield' ) } type="primary" />
						<p className="bs-ds-netrecovery__said">
							{ __( 'Shown once. Store it somewhere you can reach without signing in; only its fingerprint is kept here.', 'bettershield' ) }
						</p>
					</div>
				) : null }
			</Card>

			<Card className="bs-ds-netkeys" aria-labelledby="bs-ds-netkeys-title">
				<CardHead icon="key-round" title={ <FocusTitle headingRef={ keysHeading }>{ __( 'Rotate the sign-in keys', 'bettershield' ) }</FocusTitle> } id="bs-ds-netkeys-title" />

				<p className="bs-ds-network__intro">
					{ __(
						'Every other session on every site ends; people sign in again with their current password. You stay signed in.',
						'bettershield'
					) }
				</p>

				<div className="bs-ds-network__notes">
					<Alert
						layout="default"
						tone="warning"
						desc={ __( 'This cannot be undone: the old keys are gone once replaced.', 'bettershield' ) }
					/>
				</div>

				<div className="bs-ds-netkeys__act">
					{ /* What the classic box made the reader tick is what the
					     confirmation says, and its button keeps the action's name. */ }
					<Armed
						key={ rotations }
						held
						label={ __( 'Rotate the Sign-In Keys', 'bettershield' ) }
						consequence={ __( 'I understand every other session on every site will end', 'bettershield' ) }
						confirm={ __( 'Rotate the Sign-In Keys', 'bettershield' ) }
						busy={ rotating }
						onConfirm={ () =>
							rotateNetworkKeys(
								afterRotate( () => {
									setRotations( ( count ) => count + 1 );
									return reload();
								} )
							)
						}
					/>
					<Saved forKey="network-keys" />
				</div>
			</Card>
		</>
	);
}

/* ---- the rulings that can be put back -------------------------------------- */

/**
 * The network's own rulings that can be put back. The main site's history
 * lives in the same table and is not the network's to show, so the route
 * answers only the network surfaces.
 *
 * @param {Object}   props
 * @param {Object}   props.fallback   Where focus goes when the row it was on has gone.
 * @param {number}   props.revision   Moves when a policy is saved, which adds a ruling here.
 * @param {Function} props.onReverted Called once a ruling is put back.
 */
function UndoCard( { fallback, revision, onReverted } ) {
	const { status, data, reload } = useNetworkRead( '/bettershield/v1/network/undo' );
	const { revertNetworkChange, busy, saved } = useStore();
	const afterMutation = useMutationFocus( fallback );
	const seen = useRef( revision );

	// A policy saved above is a new ruling here; list it without a reload.
	useEffect( () => {
		if ( seen.current === revision ) {
			return;
		}

		seen.current = revision;
		reload();
	}, [ revision, reload ] );
	const confirmation = <Saved forKey={ saved?.key.startsWith( 'network-undo-' ) ? saved.key : null } />;

	if ( 'loading' === status && ! data ) {
		return null;
	}

	if ( 'error' === status ) {
		return <ErrorState onRetry={ reload } />;
	}

	if ( 'absent' === status ) {
		return null;
	}

	const entries = data.entries || [];

	if ( ! entries.length ) {
		return confirmation;
	}

	const putBack = ( token ) =>
		revertNetworkChange(
			token,
			afterMutation( () => {
				onReverted();
				return reload();
			} )
		);

	return (
		<Card className="bs-ds-netundo" aria-labelledby="bs-ds-netundo-title">
			<CardHead icon="rotate-ccw" title={ __( 'Recent changes to the network', 'bettershield' ) } id="bs-ds-netundo-title" />
			<p className="bs-ds-network__intro">{ __( 'Putting one back changes every site it applied to.', 'bettershield' ) }</p>
			<Table
				label={ __( 'Recent changes to the network', 'bettershield' ) }
				head={ false }
				columns={ [
					{ key: 'change', label: __( 'Change', 'bettershield' ) },
					{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
				] }
			>
				{ entries.map( ( entry ) => (
					<Row key={ entry.token } className="bs-ds-netundo__row">
						<Cell>
							<TitleMeta
								title={ entry.label }
								meta={
									entry.by
										? sprintf(
												/* translators: 1: a date and time, 2: an account name. */
												__( '%1$s by %2$s', 'bettershield' ),
												formatTime( entry.at ),
												entry.by
										  )
										: formatTime( entry.at )
								}
							/>
						</Cell>
						<Cell align="end">
							<Button
								type="secondary"
								size="sm"
								isBusy={ isWorking( busy, `network-undo-${ entry.token }` ) }
								aria-busy={ isWorking( busy, `network-undo-${ entry.token }` ) }
								disabled={ !! busy }
								onClick={ () => putBack( entry.token ) }
							>
								{ __( 'Put Back', 'bettershield' ) }
							</Button>
						</Cell>
					</Row>
				) ) }
			</Table>
			<div className="bs-ds-netundo__said">{ confirmation }</div>
		</Card>
	);
}

export default function NetworkOverview() {
	const settingsHeading = useRef( null );
	// How many rulings were put back, and how many were saved: each card
	// reads again when the other one changed what it shows.
	const [ putBacks, setPutBacks ] = useState( 0 );
	const [ saves, setSaves ] = useState( 0 );

	return (
		<div className="bs-ds-network">
			<SitesTable />
			<PoliciesCard revision={ putBacks } onSaved={ () => setSaves( ( count ) => count + 1 ) } headingRef={ settingsHeading } />
			<MigrationCard />
			<RecoveryCard />
			<UndoCard fallback={ settingsHeading } revision={ saves } onReverted={ () => setPutBacks( ( count ) => count + 1 ) } />
		</div>
	);
}
