/**
 * Stand-ins drawn in the shape of what is loading: a bar where a word goes, a
 * card of rows where a card goes. The page keeps its layout while the read
 * is out, so what arrives lands where its stand-in was rather than pushing
 * everything below it down.
 *
 * A stand-in says once, and only, what is on its way: the Skeleton root holds
 * the one status line and is busy; every shape inside it is hidden from
 * assistive technology and out of the keyboard's reach.
 */

import './Skeleton.css';

import { __ } from '@wordpress/i18n';

/**
 * @param {Object}        props
 * @param {string|number} props.w    Width, a CSS length or a number of pixels.
 * @param {string}        props.kind text (a 12 bar), title (a 14 bar), value (a 24 bar), control (a 28 block) or dot.
 */
export function Bone( { w = '8em', kind = 'text' } ) {
	return <span className={ `bs-ds-bone bs-ds-bone--${ kind }` } style={ { width: 'number' === typeof w ? `${ w }px` : w } } aria-hidden="true" />;
}

/**
 * The root of a stand-in: busy, and saying once what is loading.
 *
 * @param {Object} props
 * @param {string} props.label    What is loading.
 * @param {*}      props.children The shapes.
 */
export default function Skeleton( { label, children } ) {
	return (
		<div className="bs-ds-skel" aria-busy="true">
			<span className="screen-reader-text" role="status">
				{ label || __( 'Loading…', 'bettershield' ) }
			</span>
			<div className="bs-ds-skel__shapes" aria-hidden="true">
				{ children }
			</div>
		</div>
	);
}

/**
 * A card's shape: the header's tile and title, then rows.
 *
 * @param {Object}  props
 * @param {Array}   props.rows   Each row's text width, top to bottom.
 * @param {boolean} props.toggle Each row ends in a switch.
 */
export function CardBone( { rows = [ '60%', '45%', '70%' ], toggle = false } ) {
	return (
		<div className="bs-ds-card">
			<div className="bs-ds-card__head">
				<span className="bs-ds-bone bs-ds-bone--tile" />
				<Bone kind="title" w="9em" />
			</div>
			{ rows.map( ( w, index ) => (
				<div key={ index } className="bs-ds-bonerow">
					<span className="bs-ds-bonerow__text">
						<Bone kind="title" w={ w } />
						<Bone w="85%" />
					</span>
					{ toggle ? <span className="bs-ds-bone bs-ds-bone--toggle" /> : null }
				</div>
			) ) }
		</div>
	);
}

/**
 * The status strip's shape, its labels already in place where they do not
 * wait on the read, so the strip reads right before its values arrive.
 *
 * @param {Object} props
 * @param {Array}  props.labels The cells' labels; a missing one is drawn as a bar.
 */
export function StatsBone( { labels = [] } ) {
	return (
		<div className="bs-ds-stats">
			{ labels.map( ( label, index ) => (
				<div key={ index } className="bs-ds-stat">
					<span className="bs-ds-stat__label">{ label ? <span className="bs-ds-t12 bs-ds-r bs-ds-c2">{ label }</span> : <Bone w="6em" /> }</span>
					<span className="bs-ds-stat__value">
						<Bone kind="value" w="3em" />
					</span>
				</div>
			) ) }
		</div>
	);
}
