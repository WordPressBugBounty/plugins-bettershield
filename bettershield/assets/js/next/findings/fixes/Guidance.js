/**
 * How to fix: the panel for a finding whose cause is outside this plugin
 * (#2430). Nothing in it changes the site, so it is never called Fix.
 *
 * It says what is wrong in plain words, where the fix is made and who
 * usually makes it, the exact steps, a short message the owner can send to
 * whoever does it, and Check again, which asks the finding's check once
 * more and says what it found.
 */

import './Guidance.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { evidenceSummary } from '../../../screens/findings/evidence';
import { announce } from '../../../ui/announce';
import Badge from '../../ui/Badge';
import { focusIfLost } from '../../ui/focus';
import Button from '../../ui/Button';
import CopyField from '../../ui/CopyField';

/**
 * What Check again found, in words.
 *
 * @param {Object} answer The route's answer.
 * @return {string} The words.
 */
export function checkedWords( answer ) {
	if ( answer.queued ) {
		return __( 'Looking again in the background. The finding updates when that finishes.', 'bettershield' );
	}

	const test = {
		refused: () => __( 'The mail server refused the test alert too, so this is still open.', 'bettershield' ),
		muted: () => __( 'Alerts are muted, so no test was sent. Unmute them in Settings › Alerts first.', 'bettershield' ),
		no_recipient: () => __( 'Alerts have no recipient, so no test was sent. Add one in Settings › Alerts first.', 'bettershield' ),
		too_soon: () => __( 'A test alert went out in the last five minutes. Try again shortly.', 'bettershield' ),
	}[ answer.test ];

	if ( test && answer.open ) {
		return test();
	}

	const seen = answer.open ? evidenceSummary( answer.evidence ) : '';

	if ( seen ) {
		return sprintf(
			/* translators: %s: what the check saw, as the finding's Evidence shows it, e.g. "Count: 2". */
			__( 'Still open. The check still sees: %s.', 'bettershield' ),
			seen.replace( /[.\s]+$/, '' )
		);
	}

	return answer.open
		? __( 'Checked again. It is still open: the check found the same thing.', 'bettershield' )
		: __( 'Checked again. It is fixed, and the finding is closed.', 'bettershield' );
}

/**
 * @param {Object}   props
 * @param {string}   props.findingId  The finding the check belongs to.
 * @param {string}   props.what       What is wrong, in plain words.
 * @param {boolean}  props.outside    Whether the fix is made outside WordPress.
 * @param {string}   props.where      Where the fix is made, and who usually makes it.
 * @param {string[]} props.steps      The steps, in order.
 * @param {string}   props.message    A message for whoever makes the fix, or none.
 * @param {Array}    props.links      Screens that help, each { label, href }.
 * @param {string}   props.checkLabel Check again's words, where it does more than check.
 * @param {boolean}  props.checking   Whether a look asked for earlier is still running.
 */
export default function Guidance( { findingId, what, outside = true, where, steps = [], message = '', links = [], checkLabel = '', checking = false } ) {
	const { checkFindingAgain, busy } = useStore();
	const [ said, setSaid ] = useState( checking ? checkedWords( { queued: true } ) : '' );
	const note = useRef( null );
	const working = isWorking( busy, `guidance-${ findingId }` );

	// The answer takes focus, so it is read where the press was made.
	useEffect( () => {
		if ( said && note.current ) {
			note.current.focus();
		}
	}, [ said ] );

	const check = () => {
		setSaid( '' );
		announce( __( 'Checking again…', 'bettershield' ) );
		checkFindingAgain( findingId, ( answer ) => {
			if ( answer ) {
				const words = checkedWords( answer );

				setSaid( words );
				announce( words );

				// Closed, the finding's row goes and this panel with it: the
				// list's title keeps the reader's place.
				if ( ! answer.open && ! answer.queued ) {
					window.setTimeout( () => focusIfLost( document.getElementById( 'bs-ds-fcard-title' ) ), 0 );
				}
			}
		} );
	};

	return (
		<>
			<p className="bs-ds-fix__text">{ what }</p>
			<div className="bs-ds-fix__where">
				<Badge className="bs-ds-fix__mark" icon={ outside ? 'server' : 'panel-left' }>{ outside ? __( 'Outside WordPress', 'bettershield' ) : __( 'In WordPress', 'bettershield' ) }</Badge>
				<p className="bs-ds-fix__note">{ where }</p>
			</div>
			{ steps.length ? (
				<ol className="bs-ds-fix__steps">
					{ steps.map( ( step ) => (
						<li key={ step } className="bs-ds-fix__text">
							{ step }
						</li>
					) ) }
				</ol>
			) : null }
			{ message ? <CopyField multiline label={ __( 'A message you can send', 'bettershield' ) } value={ message } copyLabel={ __( 'Copy Message', 'bettershield' ) } dir="auto" /> : null }
			<div className="bs-ds-fix__actions">
				{ links.map( ( link ) => (
					<Button key={ link.href } type="secondary" size="sm" trailing="arrow-right" href={ link.href }>
						{ link.label }
					</Button>
				) ) }
				<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ check }>
					{ checkLabel || __( 'Check Again', 'bettershield' ) }
				</Button>
			</div>
			{ said ? (
				<p ref={ note } tabIndex={ -1 } className="bs-ds-fix__note" role="status">
					{ said }
				</p>
			) : null }
		</>
	);
}

Guidance.kind = 'guidance';
