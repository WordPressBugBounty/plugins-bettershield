/**
 * The design's Table/Tab row (23:25804): tabs with a count pill, a 2px
 * indicator under the selected one, one divider under the row, and room for
 * controls at its end.
 *
 * Where the tabs outgrow the row they scroll. The row then fades out at the
 * side that has more, so a cut-off label reads as "there is more this way",
 * and the selected tab is always scrolled into view.
 */

import './Tabs.css';

import { useEffect, useLayoutEffect, useRef, useState } from '@wordpress/element';
import { onTabKey, panelId, tabId } from './tabKeys';
import { formatCount } from '../../ui/count';

/**
 * Which ends of a scrolled row hold more than shows.
 *
 * @param {?HTMLElement} list The tab list.
 * @return {string} The classes for the clipped ends, or ''.
 */
function clippedEnds( list ) {
	if ( ! list || list.scrollWidth <= list.clientWidth + 1 ) {
		return '';
	}

	// In a right-to-left page the start is on the right and scrollLeft runs negative.
	const from = Math.abs( list.scrollLeft );
	const room = list.scrollWidth - list.clientWidth;

	return [ from > 1 ? 'is-clipped-start' : '', from < room - 1 ? 'is-clipped-end' : '' ].filter( Boolean ).join( ' ' );
}

/**
 * @param {Object}   props
 * @param {string}   props.id       The id base tying each tab to the panel.
 * @param {string}   props.label    What the tabs choose between.
 * @param {Array}    props.tabs     [{key, label, count}]
 * @param {string}   props.selected The selected tab's key.
 * @param {Function} props.onSelect Called with a tab's key.
 * @param {*}        props.actions  Controls at the row's end.
 */
export default function Tabs( { id, label, tabs, selected, onSelect, actions } ) {
	const keys = tabs.map( ( tab ) => tab.key );
	const list = useRef( null );
	const [ clipped, setClipped ] = useState( '' );

	// The selected tab in view, without moving the page around it.
	useLayoutEffect( () => {
		const row = list.current;
		const tab = row ? row.querySelector( '[aria-selected="true"]' ) : null;

		if ( ! tab || row.scrollWidth <= row.clientWidth ) {
			return;
		}

		const start = tab.offsetLeft - row.offsetLeft;
		const end = start + tab.offsetWidth;

		if ( start < row.scrollLeft || end > row.scrollLeft + row.clientWidth ) {
			row.scrollLeft = Math.max( 0, start - ( row.clientWidth - tab.offsetWidth ) / 2 );
		}
	}, [ selected ] );

	useEffect( () => {
		const row = list.current;

		if ( ! row ) {
			return undefined;
		}

		const update = () => setClipped( clippedEnds( row ) );
		const watcher = 'undefined' !== typeof window.ResizeObserver ? new window.ResizeObserver( update ) : null;

		update();
		row.addEventListener( 'scroll', update, { passive: true } );

		if ( watcher ) {
			watcher.observe( row );
		}

		return () => {
			row.removeEventListener( 'scroll', update );

			if ( watcher ) {
				watcher.disconnect();
			}
		};
	}, [ tabs.length ] );

	return (
		<div className="bs-ds-tabs">
			<div ref={ list } className={ `bs-ds-tabs__list${ clipped ? ` ${ clipped }` : '' }` } role="tablist" aria-label={ label }>
				{ tabs.map( ( tab ) => (
					<button
						key={ tab.key }
						type="button"
						role="tab"
						id={ tabId( id, tab.key ) }
						className="bs-ds-tab"
						aria-selected={ selected === tab.key }
						aria-controls={ panelId( id ) }
						tabIndex={ selected === tab.key ? 0 : -1 }
						onClick={ () => onSelect( tab.key ) }
						onKeyDown={ ( event ) => onTabKey( event, keys, selected, onSelect, id ) }
					>
						{ tab.label }
						{ null === tab.count || undefined === tab.count ? null : <span className="bs-ds-tab__count">{ 'number' === typeof tab.count ? formatCount( tab.count ) : tab.count }</span> }
					</button>
				) ) }
			</div>
			<span className="bs-ds-spacer" />
			{ actions ? <span className="bs-ds-tabs__actions">{ actions }</span> : null }
		</div>
	);
}
