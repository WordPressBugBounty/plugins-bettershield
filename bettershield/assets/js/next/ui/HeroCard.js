/**
 * The hero's card: a bordered surface with the design's glow and dotted mark
 * drawn behind what it holds, 200 tall, on the Overview.
 */

import './HeroCard.css';

const assets = () => ( window.bettershield && window.bettershield.assetsUrl ) || '';

/**
 * @param {Object}  props
 * @param {string}  props.label   The card's name.
 * @param {Object}  props.heroRef Takes the card's element, so focus can be moved to it.
 * @param {*}       props.children What it holds.
 */
export default function HeroCard( { label, heroRef, children } ) {
	return (
		<section ref={ heroRef } tabIndex={ heroRef ? -1 : undefined } className="bs-ds-herocard" aria-label={ label }>
			<div className="bs-ds-herocard__glow" aria-hidden="true">
				<div>
					<span>
						<img src={ `${ assets() }next/hero-glow.svg` } alt="" />
					</span>
				</div>
			</div>
			<img className="bs-ds-herocard__dots" src={ `${ assets() }next/hero-dots.svg` } alt="" aria-hidden="true" />
			{ children }
		</section>
	);
}
