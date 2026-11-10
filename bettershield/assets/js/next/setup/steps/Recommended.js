/**
 * Recommended: the Protect step's choices that move the score, one compact
 * row each, every row with the points it is worth, read from the site's own
 * scoring.
 *
 * A row is one line: its name over a short gray line, its points as a chip,
 * and its switch at the end. A small link under the gray line may open what
 * the choice holds (the fixes one by one) under the row; nothing else is
 * nested in a row. An item already earned says so in place of its points.
 */

import './Recommended.css';

import { useId } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import Icon from '../../ui/Icon';

/**
 * The points an item is worth, as a chip, or that it is earned already.
 *
 * @param {Object}  props
 * @param {number}  props.points What the item is worth.
 * @param {boolean} props.open   Whether it is still to earn.
 * @param {boolean} props.later  Still to earn, but not by this step: only once visits can be told apart.
 */
export function Points( { points, open, later = false } ) {
	if ( ! points ) {
		return null;
	}

	if ( open && later ) {
		return (
			<span className="bs-ds-setup-chip is-later">
				{ sprintf(
					/* translators: %d: points the score gains later, once the owner answers the Cloudflare question linked beside it. */
					__( '+%d later', 'bettershield' ),
					points
				) }
			</span>
		);
	}

	return open ? (
		<span className="bs-ds-setup-chip">
			<span aria-hidden="true">{ `+${ points }` }</span>
			<span className="screen-reader-text">
				{ sprintf(
					/* translators: %d: points the score gains. */
					__( '+%d points', 'bettershield' ),
					points
				) }
			</span>
		</span>
	) : (
		<span className="bs-ds-setup-chip is-earned">
			<Icon name="check" size={ 12 } tone="3" />
			<span>
				{ sprintf(
					/* translators: %d: points the score already has from this. */
					__( '%d earned', 'bettershield' ),
					points
				) }
			</span>
		</span>
	);
}

/**
 * @param {Object}                    props
 * @param {string}                    props.title    Its name.
 * @param {*}                         props.about    The short gray line under it.
 * @param {*}                         props.extra    A small link under that line.
 * @param {?Object}                   props.points   { points, open } from the site's scoring, or nothing.
 * @param {Function}                  props.control  Given the title's id, draws the row's switch.
 * @param {string}                    props.id       The title's id, for something that points at it.
 * @param {import('react').ReactNode} props.children What the link opens, under the row.
 */
export function ScoreRow( { title, about = null, extra = null, points = null, control = null, id, children = null } ) {
	const made = `bs-ds-setup-rec-${ useId().replace( /[^\w-]/g, '' ) }`;
	const titleId = id || made;

	return (
		<li className="bs-ds-setup-rec__row" aria-labelledby={ titleId }>
			<div className={ points && points.later && points.open ? 'bs-ds-setup-rec__line is-later' : 'bs-ds-setup-rec__line' }>
				<div className="bs-ds-setup-rec__text">
					<h3 className="bs-ds-setup-rec__title" id={ titleId }>
						{ title }
					</h3>
					{ about ? <p className="bs-ds-setup-rec__about">{ about }</p> : null }
					{ extra ? <div className="bs-ds-setup-rec__extra">{ extra }</div> : null }
				</div>
				<span className="bs-ds-setup-rec__end">
					{ points ? <Points points={ points.points } open={ points.open } later={ Boolean( points.later ) } /> : null }
					{ control ? control( titleId ) : null }
				</span>
			</div>
			{ children ? <div className="bs-ds-setup-rec__body">{ children }</div> : null }
		</li>
	);
}

/**
 * The block the rows sit in, headed by what they are worth together.
 *
 * @param {Object}                    props
 * @param {number}                    props.total    Points still to earn here.
 * @param {import('react').ReactNode} props.children The rows.
 */
export default function Recommended( { total, children } ) {
	return (
		<section className="bs-ds-setup-rec" aria-labelledby="bs-ds-setup-rec-title">
			<div className="bs-ds-setup-rec__head">
				<h2 className="bs-ds-setup-rec__heading" id="bs-ds-setup-rec-title">
					{ __( 'Recommended', 'bettershield' ) }
				</h2>
				{ total > 0 ? (
					<span className="bs-ds-setup-chip bs-ds-setup-rec__total">
						{ sprintf(
							/* translators: %d: points the choices below can add to the score. */
							__( '+%d points', 'bettershield' ),
							total
						) }
					</span>
				) : null }
			</div>
			<ul className="bs-ds-setup-rec__rows">{ children }</ul>
		</section>
	);
}
