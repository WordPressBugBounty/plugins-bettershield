/**
 * The grade and score, and where they go: the letter in a ring in the ink
 * the dashboard's hero gives a grade, its score beside it, and, when there
 * is somewhere to go, an arrow to the next pair. Protect shows where Apply
 * takes it; Ready shows where the setup took it. The numbers are always the
 * site's, never worked out here.
 */

import './ScoreMove.css';

import { __, sprintf } from '@wordpress/i18n';
import Icon from '../ui/Icon';

/**
 * The grade's ink, as the dashboard's hero gives it: brand for A and B, the
 * warning ink for C and D, the error ink below. The words carry the grade too.
 *
 * @param {string} grade A letter grade.
 * @return {string} good, fair or poor.
 */
export function gradeState( grade ) {
	if ( 'A' === grade || 'B' === grade ) {
		return 'good';
	}

	return 'C' === grade || 'D' === grade ? 'fair' : 'poor';
}

function Mark( { grade, score } ) {
	return (
		<span className="bs-ds-setup-score__mark">
			<span className={ `bs-ds-setup-score__letter is-${ gradeState( grade ) }` }>{ grade }</span>
			<span className="bs-ds-setup-score__number">{ score }</span>
		</span>
	);
}

/**
 * @param {Object}  props
 * @param {Object}  props.from  { score, grade } as it is, or as it was.
 * @param {?Object} props.to    { score, grade } where it goes; nothing to show none.
 * @param {string}  props.label The move in words, for assistive technology.
 */
export default function ScoreMove( { from, to = null, label } ) {
	const moves = Boolean( to ) && to.score !== from.score;
	const words =
		label ||
		( moves
			? sprintf(
					/* translators: 1: a letter grade, 2: a score out of 100, 3: a letter grade, 4: a score out of 100. */
					__( 'Grade %1$s, %2$d, to grade %3$s, %4$d', 'bettershield' ),
					from.grade,
					from.score,
					to.grade,
					to.score
			  )
			: sprintf(
					/* translators: 1: a letter grade, 2: a score out of 100. */
					__( 'Grade %1$s, %2$d', 'bettershield' ),
					from.grade,
					from.score
			  ) );

	return (
		<span className="bs-ds-setup-score" role="img" aria-label={ words }>
			<Mark grade={ from.grade } score={ from.score } />
			{ moves ? (
				<>
					<Icon name="arrow-right" size={ 16 } tone="3" className="bs-ds-setup__flip" />
					<Mark grade={ to.grade } score={ to.score } />
				</>
			) : null }
		</span>
	);
}
