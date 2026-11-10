/**
 * The design's Finding card (component 29:57360): the area tile, the title, a
 * one-line summary, and the one action the finding's data calls for. "How to
 * fix" opens the explanation in place.
 */

import './FindingCard.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { ConfirmBox } from '../findings/Bulk';
import { FixPanel, applyWord, fixLabel, fixWord, hasFix } from '../findings/Fix';
import { aboutFinding } from '../findings/Rows';
import { findingUrl, mayManage } from '../../nav';
import { isWorking, useStore } from '../../store';
import { whenPhrase } from '../../ui/when';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import { IconTile } from '../ui/Card';
import { focusIfLost } from '../ui/focus';
import { areaIcon, isOneClick } from '../data/overview';

/**
 * Why an item set to applied still has its finding open. Safe mode is named
 * only while it is on: otherwise the last check found the protection not
 * working, and "nothing is enforcing it" sent a reader looking for a safe
 * mode to end.
 *
 * @param {?Object} safeMode The overview's safe-mode state.
 * @return {string} The line.
 */
function appliedButOpen( safeMode ) {
	return safeMode && safeMode.active
		? __( 'Set to applied, and safe mode is pausing it.', 'bettershield' )
		: __( 'Set to applied, but the last check found it not working.', 'bettershield' );
}

/**
 * @param {Object} props
 * @param {Object} props.finding  The finding.
 * @param {string} props.meta     Its one-line summary.
 * @param {string} props.checked  When the audit last ran, ISO.
 * @param {string} props.icon     The tile's icon, when not the area's.
 * @param {*}        props.action    An action in place of the finding's own.
 * @param {Function} props.onApplied Told when its fix applied, with the finding and the answer.
 * @param {Object}   props.safeMode  The overview's safe-mode state, when read.
 * @param {string}   props.note      A caveat under the summary, wrapped rather than cut short.
 * @param {?Object}  props.manage    "I manage this myself", where it is offered: `points`, `also`, `working` and `onConfirm`, which answers once it is done.
 */
export default function FindingCard( { finding, meta, checked, icon, action, onApplied, safeMode = null, note = null, manage = null } ) {
	const { busy, applyItem } = useStore();
	const [ open, setOpen ] = useState( false );
	const [ fixing, setFixing ] = useState( false );
	const [ confirming, setConfirming ] = useState( false );
	const confirmRef = useRef( null );
	const manageRef = useRef( null );
	const asked = useRef( false );
	const fixId = `bs-ds-fcard-fix-${ finding.id }`;

	// To the question when it opens; back to the button once it has gone
	// and taken the control that was pressed with it.
	useEffect( () => {
		if ( confirming ) {
			asked.current = true;

			if ( confirmRef.current ) {
				confirmRef.current.focus();
			}
		} else if ( asked.current ) {
			asked.current = false;
			focusIfLost( manageRef.current );
		}
	}, [ confirming ] );

	const stopAsking = () => setConfirming( false );
	const applying = isWorking( busy, finding.hardening_item );
	const enforcing = finding.remediable && finding.hardening_active;
	// On and open by choice (XML-RPC with pingbacks only): it is enforcing.
	const leadsToSetting = Boolean( enforcing && finding.control && finding.control.url );
	const deducts = Number( finding.deduction ) || 0;
	let control = action;

	if ( undefined === control ) {
		// Offered only to somebody the apply route answers, as the current screen does.
		if ( isOneClick( finding ) && mayManage() ) {
			control = (
				<Button
					type="primary"
					size="md"
					isBusy={ applying }
					disabled={ applying }
					aria-label={ aboutFinding( applying ? __( 'Applying…', 'bettershield' ) : applyWord( finding ), finding ) }
					onClick={ () => applyItem( finding.hardening_item, undefined, ( data ) => onApplied && onApplied( finding, data ) ) }
				>
					{ applying ? __( 'Applying…', 'bettershield' ) : applyWord( finding ) }
				</Button>
			);
		} else if ( hasFix( finding ) ) {
			// The finding's own panel, under the card, with the values and
			// controls its fix needs (#1954), named as the Findings report
			// names it: Fix where it acts, How to fix where it guides (#2430).
			control = (
				<Button
					type="secondary"
					size="md"
					trailing={ fixing ? 'chevron-up' : 'chevron-down' }
					aria-expanded={ fixing }
					aria-controls={ fixing ? fixId : undefined }
					aria-label={ fixLabel( finding ) }
					onClick={ () => setFixing( ( was ) => ! was ) }
				>
					{ fixWord( finding ) }
				</Button>
			);
		} else if ( finding.control && finding.control.url ) {
			// Ahead of the applied case: an item that is on and leaves its
			// finding open (XML-RPC with pingbacks only) leads to its setting.
			control = (
				<Button type="secondary" size="md" href={ finding.control.url } aria-label={ aboutFinding( finding.control.label, finding ) }>
					{ finding.control.label }
				</Button>
			);
		} else if ( enforcing ) {
			control = null;
		} else {
			control = (
				<Button
					type="ghost"
					size="md"
					trailing={ open ? 'chevron-up' : 'chevron-down' }
					aria-expanded={ open }
					aria-label={ aboutFinding( __( 'How to Fix', 'bettershield' ), finding ) }
					onClick={ () => setOpen( ( was ) => ! was ) }
				>
					{ __( 'How to Fix', 'bettershield' ) }
				</Button>
			);
		}
	}

	return (
		<article className="bs-ds-fcard">
			<div className="bs-ds-fcard__row">
				<IconTile icon={ icon || areaIcon( finding.group ) } size="md" />
				<div className="bs-ds-fcard__text">
					<span className="bs-ds-t14 bs-ds-lead bs-ds-m bs-ds-c1">{ finding.title }</span>
					{ enforcing && ! leadsToSetting ? (
						<span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2 bs-ds-fcard__meta">{ appliedButOpen( safeMode ) }</span>
					) : null }
					{ ! ( enforcing && ! leadsToSetting ) && meta ? <span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2 bs-ds-fcard__meta">{ meta }</span> : null }
					{ note ? <span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2">{ note }</span> : null }
					{ manage ? (
						<span className="bs-ds-fcard__manage">
							<Button ref={ manageRef } type="linksub" size="sm" aria-label={ aboutFinding( __( 'I Manage This Myself', 'bettershield' ), finding ) } onClick={ () => setConfirming( true ) }>
								{ __( 'I Manage This Myself', 'bettershield' ) }
							</Button>
						</span>
					) : null }
				</div>
				{ control }
			</div>
			{ confirming && manage ? (
				<div className="bs-ds-fcard__confirm">
					<ConfirmBox
						dialogRef={ confirmRef }
						id={ `bs-ds-fcard-confirm-${ finding.id }` }
						count={ 1 }
						name={ finding.title }
						managed
						also={ manage.also }
						points={ manage.points }
						working={ manage.working }
						onConfirm={ () => manage.onConfirm().then( stopAsking ) }
						onCancel={ stopAsking }
					/>
				</div>
			) : null }
			{ fixing ? (
				<div className="bs-ds-fcard__fix">
					<FixPanel finding={ finding } id={ fixId } />
				</div>
			) : null }
			{ open ? (
				<div className="bs-ds-fcard__explain">
					<div className="bs-ds-fcard__columns">
						<div className="bs-ds-fcard__column">
							<p className="bs-ds-t12 bs-ds-m bs-ds-c2 bs-ds-nowrap">{ __( 'Why it matters', 'bettershield' ) }</p>
							<p className="bs-ds-fcard__body">{ finding.why }</p>
						</div>
						<div className="bs-ds-fcard__column">
							<p className="bs-ds-t12 bs-ds-m bs-ds-c2 bs-ds-nowrap">{ __( 'What to know first', 'bettershield' ) }</p>
							<p className="bs-ds-fcard__body">{ finding.break_note }</p>
						</div>
					</div>
					<div className="bs-ds-fcard__foot">
						<p className="bs-ds-t12 bs-ds-r bs-ds-c2 bs-ds-fcard__note">
							{ deducts > 0
								? sprintf(
										/* translators: 1: points the finding takes off the score, 2: when the audit last ran. */
										_n(
											'Costs %1$d point until fixed · Last checked %2$s',
											'Costs %1$d points until fixed · Last checked %2$s',
											deducts,
											'bettershield'
										),
										deducts,
										whenPhrase( checked )
								  )
								: sprintf(
										/* translators: %s: when the audit last ran. */
										__( 'Last checked %s', 'bettershield' ),
										whenPhrase( checked )
								  ) }
						</p>
						<Button type="link" size="sm" href={ findingUrl( finding.id ) }>
							{ __( 'Open This Finding', 'bettershield' ) }
							<Icon name="arrow-right" size={ 14 } tone="1" />
						</Button>
					</div>
				</div>
			) : null }
		</article>
	);
}
