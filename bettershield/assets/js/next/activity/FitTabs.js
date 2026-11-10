/**
 * A list's tab row when its tabs can outnumber the room: as many tabs as fit
 * beside the row's controls, and the rest in a select at the row's end, so
 * no tab is ever out of sight behind a scroll.
 *
 * What fits is measured from a copy of every tab that is laid out and never
 * shown, the way the classic filter chips measured theirs: measuring the
 * visible row would only ever report the tabs that survived the last
 * measurement, so the row could shrink and never grow back. A row with no
 * width yet (nothing laid out) shows every tab.
 *
 * The chosen tab trades places with the last tab that fits, so what is
 * chosen is always the tab drawn as chosen. A tab chosen from the select
 * stays listed there too, as the select's value, so the select says what was
 * chosen from it rather than More (#1718). Where the
 * card is narrow the controls take a line of their own under the tabs, and
 * the tabs have the row's whole width.
 */

import './FitTabs.css';

import { useCallback, useLayoutEffect, useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { itemsThatFit } from '../../ui/fit';
import Field from '../ui/Field';
import Tabs from '../ui/Tabs';

/**
 * @param {Object}   props
 * @param {string}   props.id          The id base tying each tab to the panel.
 * @param {string}   props.label       What the tabs choose between.
 * @param {Array}    props.tabs        [{key, label, count}]
 * @param {string}   props.selected    The selected tab's key.
 * @param {Function} props.onSelect    Called with a tab's key.
 * @param {*}        props.actions     Controls at the row's end.
 * @param {string}   props.moreLabel   The select's accessible name.
 * @param {Function} props.optionLabel A tab as the select lists it, given the tab.
 */
export default function FitTabs( { id, label, tabs, selected, onSelect, actions = null, moreLabel, optionLabel } ) {
	const root = useRef( null );
	const copies = useRef( null );
	const [ fits, setFits ] = useState( tabs.length );
	const total = tabs.length;
	const index = tabs.findIndex( ( tab ) => tab.key === selected );
	// What the copies measure: a new count changes a tab's width.
	const drawn = tabs.map( ( tab ) => `${ tab.key }:${ tab.label }:${ tab.count }` ).join( '|' );

	const measure = useCallback( () => {
		const box = root.current;
		const bench = copies.current;
		const row = box && box.querySelector( '.bs-ds-tabs' );
		const list = box && box.querySelector( '.bs-ds-tabs__list' );

		if ( ! row || ! list || ! bench || ! row.clientWidth ) {
			setFits( total );
			return;
		}

		const ends = box.querySelector( '.bs-ds-tabs__actions' );
		const end = box.querySelector( '.bs-ds-fittabs__end' );
		const style = window.getComputedStyle( row );
		const gap = ends ? parseFloat( window.getComputedStyle( ends ).columnGap ) || 0 : 0;
		// The controls on a line of their own, on a narrow card: the tabs have
		// the row, less the spacer that holds the controls apart from them.
		const stacked = Boolean( ends ) && ends.getBoundingClientRect().top >= list.getBoundingClientRect().bottom - 1;
		const room = row.clientWidth - ( parseFloat( style.paddingLeft ) || 0 ) - ( parseFloat( style.paddingRight ) || 0 ) - 1;
		const beside = end && ! stacked ? end.offsetWidth : 0;
		const more = bench.querySelector( '.bs-ds-fittabs__more' );
		const reserve = stacked || ! more ? 0 : more.offsetWidth + gap;
		const widths = Array.from( bench.querySelectorAll( '.bs-ds-tab' ) ).map( ( node ) => node.offsetWidth );

		setFits( itemsThatFit( room - beside, widths, reserve, 0, index ) );
	}, [ total, index ] );

	useLayoutEffect( () => {
		measure();

		if ( 'undefined' === typeof window.ResizeObserver ) {
			return undefined;
		}

		const observer = new window.ResizeObserver( () => measure() );
		const box = root.current;

		[ '.bs-ds-tabs', '.bs-ds-fittabs__end' ].forEach( ( selector ) => {
			const node = box && box.querySelector( selector );

			if ( node ) {
				observer.observe( node );
			}
		} );

		return () => observer.disconnect();
	}, [ measure, drawn ] );

	let visible = tabs.slice( 0, fits );
	let overflow = tabs.slice( fits );
	const fromSelect = overflow.some( ( tab ) => tab.key === selected );

	// The chosen tab trades places with the last one that fits, and stays
	// in the select as its value.
	if ( fromSelect ) {
		const chosen = tabs.find( ( tab ) => tab.key === selected );

		visible = [ ...visible.slice( 0, -1 ), chosen ];
		overflow = tabs.filter( ( tab ) => tab === chosen || ! visible.includes( tab ) );
	}

	const more = overflow.length ? (
		<Field
			kind="select"
			width="sm"
			className="bs-ds-fittabs__more"
			label={ moreLabel }
			hideLabelFromVision
			value={ fromSelect ? selected : '' }
			options={ [
				{ value: '', label: __( 'More', 'bettershield' ) },
				...overflow.map( ( tab ) => ( { value: tab.key, label: optionLabel ? optionLabel( tab ) : tab.label } ) ),
			] }
			onChange={ ( key ) => {
				if ( key ) {
					onSelect( key );
				}
			} }
		/>
	) : null;

	return (
		<div className="bs-ds-fittabs" ref={ root }>
			<Tabs
				id={ id }
				label={ label }
				tabs={ visible }
				selected={ selected }
				onSelect={ onSelect }
				actions={
					more || actions ? (
						<>
							{ more }
							{ actions ? <span className="bs-ds-fittabs__end">{ actions }</span> : null }
						</>
					) : null
				}
			/>
			<div className="bs-ds-fittabs__bench" aria-hidden="true">
				<div className="bs-ds-fittabs__copies" ref={ copies }>
					{ tabs.map( ( tab ) => (
						<span key={ tab.key } className="bs-ds-tab">
							{ tab.label }
							{ null === tab.count || undefined === tab.count ? null : <span className="bs-ds-tab__count">{ tab.count }</span> }
						</span>
					) ) }
					<span className="bs-ds-field bs-ds-field--sm bs-ds-fittabs__more" />
				</div>
			</div>
		</div>
	);
}
