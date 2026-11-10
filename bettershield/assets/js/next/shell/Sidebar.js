/**
 * The sidebar: the product's name and plan, the reader, every screen, and the
 * way to the documentation.
 *
 * Every entry comes from the navigation model the server builds; nothing here
 * decides what a reader may open. Overview and Findings stand alone; each
 * group (Protect, Agents, Activity, Settings, and an add-on's groups) is one
 * entry that opens onto its screens, one open at a time, starting with the one
 * that holds the screen on show. An add-on's zone sits under its name, and
 * there a group is a menu only where the server gave it a mark: one it sent
 * without (a group of one screen, which a menu would make a click for
 * nothing) is its name over its screens.
 *
 * Three shapes, from one list. Open, each entry is its icon and its name.
 * Folded (the reader's choice, kept in the browser), it is a rail of the
 * icons: a name shows beside its icon under the pointer or the keyboard and
 * stays the control's name either way, and a group's screens open beside the
 * rail. On a narrow screen it is a strip whose list opens under a Menu
 * button, because a column there leaves the screen a sliver.
 */

import './Sidebar.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { brand, brandLogo, branded, helpLinks, navItemFor, navZones, tier } from '../../nav';
import { useStore } from '../../store';
import Icon from '../ui/Icon';
import Badge from '../ui/Badge';
import { useKept } from '../ui/useKept';
import matchAdminMenu from './adminMenu';

/** Where "Docs & support" leads. */
export const DOCS_URL = 'https://bettershield.ai/docs/';

/** The design's icon for each entry and group, by the server's name for it. */
const ICONS = {
	overview: 'layout-grid',
	findings: 'list-checks',
	protect: 'shield',
	agents: 'bot',
	activity: 'activity',
	settings: 'settings-2',
	features: 'sparkle',
	signin: 'log-in',
	reports: 'chart-column',
	response: 'zap',
	account: 'key',
	// An add-on's one account screen, drawn as a plain entry rather than
	// under a menu, keeps the account's mark.
	license: 'key',
	// The network admin's entries. Incidents fell back to the grid Network
	// draws, and the two read as one (#1936); it takes its card's mark.
	network: 'layout-grid',
	incidents: 'link-2',
};

const iconFor = ( name ) => ICONS[ name ] || 'layout-grid';

/** The screen whose entry carries the number of requests waiting. */
const REQUESTS = 'bettershield-agents/requests';

/**
 * The numbers the sidebar carries, as the store last read them: open findings
 * that are not snoozed, and requests waiting for an answer. Null until read.
 *
 * @return {{findings: ?number, waiting: ?number}} The counts.
 */
export function useCounts() {
	const { resources } = useStore();
	// The last copies read, kept through a refresh that failed.
	const overview = useKept( resources.overview && resources.overview.data );
	const surface = useKept( resources.agentSurface && resources.agentSurface.data );

	return {
		findings: overview ? Math.max( 0, ( Number( overview.open_findings ) || 0 ) - ( Number( overview.snoozed_findings ) || 0 ) ) : null,
		waiting: surface && null !== surface.open_requests && undefined !== surface.open_requests ? Math.max( 0, Number( surface.open_requests ) || 0 ) : null,
	};
}

function countOf( item, counts ) {
	if ( 'bettershield-findings' === item.section && null !== counts.findings ) {
		return counts.findings;
	}

	if ( REQUESTS === `${ item.section }/${ item.tab }` && null !== counts.waiting ) {
		return counts.waiting;
	}

	return Number( item.count ) || 0;
}

/*
 * The number is drawn for the eye only. The control it sits on is named
 * whole, label and count in one string, because the label and the count are
 * separate boxes and a name put together from them read "Findings , 12
 * open", with a space before the comma (#2188).
 */
function Count( { value } ) {
	return (
		<span className="bs-ds-nav__count">
			<span className="bs-ds-t10 bs-ds-r bs-ds-nowrap" aria-hidden="true">
				{ value }
			</span>
		</span>
	);
}

function Entry( { item, active, child = false, counts } ) {
	const count = countOf( item, counts );
	const said =
		'bettershield-findings' === item.section
			? /* translators: 1: a screen's name, e.g. "Findings", 2: how many findings are open. */ _n( '%1$s, %2$d open', '%1$s, %2$d open', count, 'bettershield' )
			: /* translators: 1: a screen's name, 2: how many requests are waiting for an answer. */ _n( '%1$s, %2$d waiting', '%1$s, %2$d waiting', count, 'bettershield' );

	return (
		<a
			href={ item.url }
			className={ `bs-ds-nav__item${ child ? ' bs-ds-nav__item--child' : '' }${ active ? ' is-active' : '' }` }
			aria-current={ active ? 'page' : undefined }
			aria-label={ count > 0 ? sprintf( said, item.label, count ) : undefined }
		>
			{ child ? null : <Icon name={ iconFor( item.icon ) } size={ 16 } tone={ active ? 'brand' : '2' } /> }
			<span className="bs-ds-nav__label bs-ds-t14 bs-ds-lead bs-ds-m">{ item.label }</span>
			{ count > 0 ? <Count value={ count } /> : null }
		</a>
	);
}

/**
 * A group's name where it says more than its label, read as one sentence so
 * a translator can reorder it: that it holds the open screen, and how many
 * requests wait under it while it is shut.
 *
 * @param {string}  label   The group's name, e.g. "Protect".
 * @param {boolean} holds   Whether the open screen is in it.
 * @param {number}  waiting Requests waiting under it, while shown.
 * @return {string|undefined} The name, or undefined where the label says it all.
 */
function groupName( label, holds, waiting ) {
	if ( holds && waiting > 0 ) {
		/* translators: 1: a section of the plugin's screens, e.g. "Agents", 2: how many requests are waiting for an answer. */
		return sprintf( _n( '%1$s, current section, %2$d waiting', '%1$s, current section, %2$d waiting', waiting, 'bettershield' ), label, waiting );
	}

	if ( holds ) {
		/* translators: %s: a section of the plugin's screens, e.g. "Protect". */
		return sprintf( __( '%s, current section', 'bettershield' ), label );
	}

	if ( waiting > 0 ) {
		/* translators: 1: a section of the plugin's screens, e.g. "Agents", 2: how many requests are waiting for an answer. */
		return sprintf( _n( '%1$s, %2$d waiting', '%1$s, %2$d waiting', waiting, 'bettershield' ), label, waiting );
	}

	return undefined;
}

function Group( { group, id, open, current, toggle, counts, folded = false, close } ) {
	const holds = Boolean( current && group.items.some( ( item ) => item.key === current.item.key ) );
	const waiting = group.items.reduce( ( sum, item ) => sum + ( 'bettershield-findings' === item.section ? 0 : countOf( item, counts ) ), 0 );
	const button = useRef( null );
	const item = useRef( null );

	/*
	 * Folded, the screens open beside the rail rather than under it, and
	 * shut the way a menu does: Escape hands focus back to the group, and a
	 * press anywhere else closes them. Escape closes them from anywhere, so
	 * a flyout the keyboard has left is not stuck over the page.
	 */
	useEffect( () => {
		if ( ! folded || ! open ) {
			return undefined;
		}

		const outside = ( event ) => {
			if ( item.current && ! item.current.contains( event.target ) ) {
				close();
			}
		};
		const escape = ( event ) => {
			if ( 'Escape' === event.key && item.current && ! item.current.contains( event.target ) ) {
				close();
			}
		};

		document.addEventListener( 'mousedown', outside );
		document.addEventListener( 'keydown', escape );

		return () => {
			document.removeEventListener( 'mousedown', outside );
			document.removeEventListener( 'keydown', escape );
		};
	}, [ folded, open, close ] );

	// Tabbing past the last screen leaves the group, and the flyout goes
	// with it rather than staying open over the content. Focus that goes
	// nowhere is a press on a spot that takes none, which may be inside the
	// flyout; a press outside it is the mousedown handler's.
	const onBlur = ( event ) => {
		if ( folded && open && item.current && event.relatedTarget && ! item.current.contains( event.relatedTarget ) ) {
			close();
		}
	};

	const onKeyDown = ( event ) => {
		if ( folded && open && 'Escape' === event.key ) {
			event.preventDefault();
			close();

			if ( button.current ) {
				button.current.focus();
			}
		}
	};

	// The current screen's own entry is no move, so nothing else shut the
	// flyout on it, and it stayed open over the page. It shuts on that click,
	// and focus goes back to the group, as on Escape.
	const onClick = ( event ) => {
		if ( folded && open && event.target instanceof window.Element && event.target.closest( 'a[aria-current="page"]' ) ) {
			close();

			if ( button.current ) {
				button.current.focus();
			}
		}
	};

	return (
		// eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape and a click on the current screen are handled for the links inside, not the item.
		<li ref={ item } onKeyDown={ onKeyDown } onBlur={ onBlur } onClick={ onClick } className={ folded ? 'bs-ds-nav__group' : undefined }>
			{ /* Folded, the current screen is behind its group's icon, so the icon is what is marked. */ }
			<button
				ref={ button }
				type="button"
				className={ `bs-ds-nav__item${ folded && holds ? ' is-active' : '' }` }
				aria-expanded={ open }
				aria-controls={ id }
				aria-label={ groupName( group.label, holds, waiting > 0 && ! open ? waiting : 0 ) }
				onClick={ toggle }
			>
				<Icon name={ iconFor( group.key ) } size={ 16 } tone="2" />
				<span className="bs-ds-nav__label bs-ds-t14 bs-ds-lead bs-ds-m">{ group.label }</span>
				{ waiting > 0 && ! open ? <Count value={ waiting } /> : null }
				<Icon name={ open ? 'chevron-up' : 'chevron-down' } size={ 16 } tone="3" className="bs-ds-nav__chevron" />
			</button>
			<ul id={ id } className={ `bs-ds-nav__sub${ folded ? ' bs-ds-nav__sub--flyout' : '' }` } hidden={ ! open } aria-label={ folded ? group.label : undefined }>
				{ group.items.map( ( item ) => (
					<li key={ item.key }>
						<Entry item={ item } child counts={ counts } active={ Boolean( current && current.item.key === item.key ) } />
					</li>
				) ) }
			</ul>
		</li>
	);
}

/** The list the Menu button opens on a narrow screen. */
export const LIST_ID = 'bs-ds-nav-list';

/**
 * @param {Object}  props
 * @param {Object}  props.route     The screen on show.
 * @param {boolean} props.collapsed Whether the reader folded the sidebar to its icons.
 */
export default function Sidebar( { route, collapsed = false } ) {
	const current = navItemFor( route );
	const counts = useCounts();
	const model = window.bettershield || {};
	const holding = current && current.group.label ? `${ current.zone.key }/${ current.group.key }` : '';
	// Folded, nothing opens on its own: a flyout on every arrival would sit
	// over the screen the reader came to see.
	const [ expanded, setExpanded ] = useState( collapsed ? '' : holding );
	const [ menuOpen, setMenuOpen ] = useState( false );

	// A move opens the group the new screen belongs to, or, folded, shuts
	// whatever flyout led there.
	useEffect( () => {
		setExpanded( collapsed ? '' : holding );
		setMenuOpen( false );
	}, [ holding, collapsed, route.section, route.tab ] );

	// The admin menu's bubble follows the live count, as this sidebar's does.
	useEffect( () => {
		if ( null !== counts.waiting ) {
			matchAdminMenu( counts.waiting );
		}
	}, [ counts.waiting ] );

	const close = () => setExpanded( '' );

	/*
	 * Folded, an entry's name shows beside its icon on hover and focus.
	 * Escape hides it, as a tooltip should be dismissible, until the pointer
	 * leaves that entry or focus moves on.
	 */
	useEffect( () => {
		if ( ! collapsed ) {
			return undefined;
		}

		const hide = ( event ) => {
			if ( 'Escape' !== event.key ) {
				return;
			}

			document.querySelectorAll( '.bs-ds-side.is-collapsed .bs-ds-nav__item:hover, .bs-ds-side.is-collapsed .bs-ds-nav__item:focus' ).forEach( ( entry ) => {
				const show = () => {
					entry.removeAttribute( 'data-hide-tip' );
					entry.removeEventListener( 'mouseleave', show );
					entry.removeEventListener( 'blur', show );
				};

				entry.setAttribute( 'data-hide-tip', '' );
				entry.addEventListener( 'mouseleave', show );
				entry.addEventListener( 'blur', show );
			} );
		};

		document.addEventListener( 'keydown', hide );

		return () => document.removeEventListener( 'keydown', hide );
	}, [ collapsed ] );
	const classes = [ 'bs-ds-side', collapsed ? 'is-collapsed' : '', menuOpen ? 'is-menu-open' : '' ].filter( Boolean ).join( ' ' );

	return (
		<nav className={ classes } aria-label={ brand }>
			<div className="bs-ds-brand">
				<span className={ `bs-ds-brand__mark${ brandLogo ? ' bs-ds-brand__mark--owner' : '' }` } aria-hidden="true">
					<img src={ brandLogo || `${ model.assetsUrl || '' }next/logo-mark.svg` } alt="" />
				</span>
				<span className="bs-ds-brand__name">
					<span className="bs-ds-brand__row">
						<span className="bs-ds-t14 bs-ds-m bs-ds-c1 bs-ds-nowrap">{ brand }</span>
						{ /* The tier is this product's word, and a labeled chrome is the owner's. */ }
						{ 'ultra' === tier && ! branded ? <Badge tone="brand">{ __( 'Ultra', 'bettershield' ) }</Badge> : null }
					</span>
					{ model.userName ? <span className="bs-ds-t12 bs-ds-r bs-ds-c3 bs-ds-nowrap">{ model.userName }</span> : null }
				</span>
				{ /* Shown only on a narrow screen, where the list is a strip's. */ }
				<button type="button" className="bs-ds-side__menu" aria-expanded={ menuOpen } aria-controls={ LIST_ID } onClick={ () => setMenuOpen( ( was ) => ! was ) }>
					<Icon name={ menuOpen ? 'x' : 'panel-left' } size={ 16 } tone="2" />
					<span className="bs-ds-t14 bs-ds-m">{ __( 'Menu', 'bettershield' ) }</span>
				</button>
			</div>

			<div className="bs-ds-nav" id={ LIST_ID }>
				{ navZones.map( ( zone ) => (
					<div key={ zone.key } className="bs-ds-nav__zone" role={ zone.label ? 'group' : undefined } aria-labelledby={ zone.label ? `bs-ds-zone-${ zone.key }` : undefined }>
						{ zone.label ? (
							<p className={ `bs-ds-nav__overline bs-ds-t12 bs-ds-m bs-ds-c3 bs-ds-nowrap${ collapsed ? ' screen-reader-text' : '' }` } id={ `bs-ds-zone-${ zone.key }` }>
								{ zone.label }
							</p>
						) : null }
						<ul className="bs-ds-nav__list">
							{ ( zone.groups || [] ).map( ( group ) => {
								if ( ! group.label ) {
									return ( group.items || [] ).map( ( item ) => (
										<li key={ item.key }>
											<Entry item={ item } counts={ counts } active={ Boolean( current && current.item.key === item.key ) } />
										</li>
									) );
								}

								const key = `${ zone.key }/${ group.key }`;

								// This plugin's own groups are menus in this frame; an
								// add-on's are where it marked them, as it asked.
								if ( 'core' !== zone.key && ! group.icon ) {
									return (
										<li key={ key } className="bs-ds-nav__set">
											<p className={ `bs-ds-nav__heading bs-ds-t12 bs-ds-m bs-ds-c3 bs-ds-nowrap${ collapsed ? ' screen-reader-text' : '' }` } id={ `bs-ds-set-${ zone.key }-${ group.key }` }>
												{ group.label }
											</p>
											<ul className="bs-ds-nav__list" aria-labelledby={ `bs-ds-set-${ zone.key }-${ group.key }` }>
												{ ( group.items || [] ).map( ( item ) => (
													<li key={ item.key }>
														<Entry item={ item } counts={ counts } active={ Boolean( current && current.item.key === item.key ) } />
													</li>
												) ) }
											</ul>
										</li>
									);
								}

								return (
									<Group
										key={ key }
										group={ group }
										id={ `bs-ds-sub-${ zone.key }-${ group.key }` }
										open={ expanded === key }
										current={ current }
										counts={ counts }
										toggle={ () => setExpanded( ( was ) => ( was === key ? '' : key ) ) }
										folded={ collapsed }
										close={ close }
									/>
								);
							} ) }
						</ul>
					</div>
				) ) }
			</div>

			{ /* Left out where the owner labeled the chrome and asked for this
			     plugin's links to go. */ }
			{ helpLinks ? (
				<div className="bs-ds-side__foot">
					<a className="bs-ds-nav__item" href={ DOCS_URL } target="_blank" rel="noopener noreferrer">
						<Icon name="book-open" size={ 16 } tone="2" />
						<span className="bs-ds-nav__label bs-ds-t14 bs-ds-lead bs-ds-m">{ __( 'Docs & support', 'bettershield' ) }</span>
						<span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span>
					</a>
				</div>
			) : null }
		</nav>
	);
}
