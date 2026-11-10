/**
 * The design's Stat group (26:38522): equal cells in one bordered strip, each
 * a label row (a 14 icon and the label) over a 24 value.
 *
 * A screen's status strip is drawn with it. A cell may carry the line under
 * the value that says what the value means ("Generate a new one below"), so
 * nothing the strip says is lost when it moves into the design.
 */

import './Stats.css';

import { __ } from '@wordpress/i18n';
import Badge from './Badge';
import Icon from './Icon';
import { Bone } from './Skeleton';

/**
 * The value's color, by the tone a status asks for. The classic strip named
 * two of them `good` and `caution`; both spellings are read.
 */
const TONES = {
	good: 'success',
	success: 'success',
	caution: 'warning',
	warning: 'warning',
	error: 'error',
	info: 'info',
};

/**
 * @param {Object}  props
 * @param {string}  props.icon    The label's 14 icon, a Lucide name.
 * @param {string}  props.label   What the value is.
 * @param {*}       props.value   The value.
 * @param {*}       props.detail  A line under the value, where one helps.
 * @param {string}  props.tone    success, warning, error or info; none for an ordinary value.
 * @param {boolean} props.pending The value is still being read.
 * @param {boolean} props.text    The value is a phrase (a date, a time) rather than a figure: drawn a step
 *                                smaller, so it keeps one line and the strip the height of its figures.
 * @param {string}  props.badge   The value is a state ("On", "Off") rather than a figure: drawn as a
 *                                Badge in this tone (neutral, brand, …), at a label's size. A word in
 *                                the figure's 24 type outweighed everything else on the screen (#2310).
 */
export function StatCell( { icon = '', label, value, detail = null, tone = '', pending = false, text = false, badge = '' } ) {
	const toned =
		( TONES[ tone ] ? ` bs-ds-stat__value--${ TONES[ tone ] }` : '' ) +
		( text ? ' bs-ds-stat__value--text' : '' ) +
		( badge ? ' bs-ds-stat__value--badge' : '' );

	return (
		<div className="bs-ds-stat" aria-busy={ pending ? 'true' : undefined }>
			<span className="bs-ds-stat__label">
				{ icon ? <Icon name={ icon } size={ 14 } tone="2" /> : null }
				<span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2">{ label }</span>
			</span>
			{ pending ? (
				<span className="bs-ds-stat__value">
					<Bone kind="value" w="3em" />
					<span className="screen-reader-text">{ __( 'Loading…', 'bettershield' ) }</span>
				</span>
			) : (
				<span className={ `bs-ds-stat__value${ toned }` }>{ badge ? <Badge tone={ badge }>{ value }</Badge> : value }</span>
			) }
			{ ! pending && null !== detail && undefined !== detail && '' !== detail ? <span className="bs-ds-stat__detail">{ detail }</span> : null }
		</div>
	);
}

/**
 * @param {Object} props
 * @param {string} props.label The strip's accessible name; without one it is not a region of its own.
 * @param {Array}  props.tiles [{ key, icon, label, value, detail, tone, pending, text, badge }]
 */
export default function Stats( { label = '', tiles } ) {
	const cells = ( tiles || [] ).map( ( { key, ...tile } ) => <StatCell key={ key } { ...tile } /> );

	return label ? (
		<section className="bs-ds-stats" aria-label={ label }>
			{ cells }
		</section>
	) : (
		<div className="bs-ds-stats">{ cells }</div>
	);
}
