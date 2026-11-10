/**
 * The design's Score gauge (component 23:26391): 41 ticks on a half circle,
 * lit up to the score in the state's color, over a glow, a rim and a fade
 * into the card, with the score, a caption and the scale's two ends.
 *
 * Every layer is one half-disc shape drawn here and colored by the design's
 * tokens, so each state reads correctly in both color schemes.
 */

import './ScoreGauge.css';

import { useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';

const TICKS = 41;

/** The half-disc every layer is drawn from, on a 150 by 75 box. */
const DISC =
	'M0 75C0 65.15 1.94 55.4 5.71 46.3C9.48 37.2 15 28.93 21.97 21.97C28.93 15 37.2 9.48 46.3 5.71C55.4 1.94 65.15 0 75 0C84.85 0 94.6 1.94 103.7 5.71C112.8 9.48 121.07 15 128.03 21.97C135 28.93 140.52 37.2 144.29 46.3C148.06 55.4 150 65.15 150 75L75 75L0 75Z';

/** The scanning sweep: ticks 15 to 23, brightening toward the last. */
const SWEEP_FROM = 14;
const SWEEP = [ 0.15, 0.26, 0.36, 0.47, 0.57, 0.68, 0.79, 0.89, 1 ];

let instances = 0;

/**
 * The gauge's state for an audit.
 *
 * @param {Object}  audit
 * @param {string}  audit.grade   The letter grade.
 * @param {boolean} audit.audited Whether the site has been audited.
 * @param {boolean} audit.running Whether an audit is running now.
 * @return {string} good, fair, poor, scanning or nodata.
 */
export function gaugeState( { grade, audited, running } ) {
	if ( running ) {
		return 'scanning';
	}

	if ( ! audited ) {
		return 'nodata';
	}

	if ( 'A' === grade || 'B' === grade ) {
		return 'good';
	}

	return 'C' === grade || 'D' === grade ? 'fair' : 'poor';
}

/**
 * How many ticks a score lights: its share of the 41, and never none, so a
 * score of zero still shows where the scale starts.
 *
 * @param {number} score 0 to 100.
 * @return {number} 1 to 41.
 */
export function litTicks( score ) {
	return Math.max( 1, Math.min( TICKS, Math.round( ( ( Number( score ) || 0 ) / 100 ) * TICKS ) ) );
}

/*
 * The scale's ends, inline like each tick's place: a stylesheet left would be
 * flipped to right for a right-to-left admin while the ticks, inline, are not,
 * and 28 then read like 72 (#2640).
 */
const SCALE_MIN = { left: '5px' };
const SCALE_MAX = { left: '195px' };

function Tick( { index, on, opacity } ) {
	const degrees = 180 - 4.5 * index;
	const radians = ( degrees * Math.PI ) / 180;
	const style = {
		left: `${ 106 + 97.5 * Math.cos( radians ) - 8.5 }px`,
		top: `${ 114 - 97.5 * Math.sin( radians ) - 1.5 }px`,
		transform: `rotate(${ -degrees }deg)`,
	};

	if ( undefined !== opacity ) {
		style.opacity = opacity;
	}

	return <span className={ `bs-ds-gauge__tick${ on ? ' is-on' : '' }` } style={ style } />;
}

/**
 * @param {Object} props
 * @param {string} props.state good, fair, poor, scanning or nodata.
 * @param {number} props.score 0 to 100.
 * @param {string} props.grade The letter grade.
 */
export default function ScoreGauge( { state, score, grade } ) {
	const [ id ] = useState( () => `bs-ds-gauge-${ ++instances }` );
	const lit = 'good' === state || 'fair' === state || 'poor' === state ? litTicks( score ) : 0;
	const ticks = [];

	for ( let index = 0; index < TICKS; index++ ) {
		const sweep = 'scanning' === state ? SWEEP[ index - SWEEP_FROM ] : undefined;

		ticks.push( <Tick key={ index } index={ index } on={ index < lit || undefined !== sweep } opacity={ sweep } /> );
	}

	let numeral = String( score );
	let caption = sprintf(
		/* translators: %s: the letter grade, e.g. "B". */
		__( 'Grade %s', 'bettershield' ),
		grade
	);

	if ( 'scanning' === state ) {
		numeral = '—';
		caption = __( 'Scanning…', 'bettershield' );
	} else if ( 'nodata' === state ) {
		numeral = '--';
		caption = __( 'No scan yet', 'bettershield' );
	}

	return (
		<div className={ `bs-ds-gauge bs-ds-gauge--${ state }` } aria-hidden="true">
			<svg className="bs-ds-gauge__disc" width="150" height="150" viewBox="0 0 150 150" fill="none">
				<defs>
					<linearGradient id={ `${ id }-fade` } x1="75" y1="0" x2="75" y2="150" gradientUnits="userSpaceOnUse">
						<stop offset="0.05" stopOpacity="0" />
						<stop offset="0.5" />
					</linearGradient>
					<mask id={ `${ id }-fademask` } maskUnits="userSpaceOnUse" x="0" y="0" width="150" height="75" style={ { maskType: 'alpha' } }>
						<path d={ DISC } fill={ `url(#${ id }-fade)` } />
					</mask>
					<mask id={ `${ id }-inside` } fill="white">
						<path d={ DISC } />
					</mask>
				</defs>
				<path className="bs-ds-gauge__glow" d={ DISC } />
				{ 'nodata' === state ? null : <path className="bs-ds-gauge__rim" d={ DISC } strokeWidth="2" mask={ `url(#${ id }-inside)` } /> }
				<g mask={ `url(#${ id }-fademask)` }>
					<path className="bs-ds-gauge__fade" d={ DISC } />
				</g>
			</svg>
			<div className="bs-ds-gauge__ticks">{ ticks }</div>
			<p className="bs-ds-gauge__score">{ numeral }</p>
			<p className="bs-ds-gauge__caption">{ caption }</p>
			<p className="bs-ds-gauge__scale bs-ds-gauge__scale--min" style={ SCALE_MIN }>
				0
			</p>
			<p className="bs-ds-gauge__scale bs-ds-gauge__scale--max" style={ SCALE_MAX }>
				100
			</p>
		</div>
	);
}
