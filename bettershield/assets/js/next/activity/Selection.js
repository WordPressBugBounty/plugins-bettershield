/**
 * Acting on many rows at once, on the file report and the quarantine list:
 * the bar a selection brings up, the question asked before anything
 * changes, and what happened after, with its Undo where there is one.
 *
 * All three sit in one dock held at the foot of the window, so the question
 * and its answer are where the reader is: both lists run to thousands of
 * pixels on a site with a history.
 */

import './Selection.css';

import { useEffect, useId } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { announce } from '../../ui/announce';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import Icon from '../ui/Icon';

/** How many lines of what was left as it was show before the list scrolls. */
const LEFT_SHOWN = 6;

/**
 * @param {Object} props
 * @param {string} props.label    What the region is, for assistive technology.
 * @param {*}      props.children The bar, the question and what happened.
 */
export function SelectionDock( { label, children } ) {
	return (
		<div className="bs-ds-seldock" role="region" aria-label={ label }>
			{ children }
		</div>
	);
}

/**
 * How many are picked, what they are, and what can be done to all of them.
 *
 * @param {Object}   props
 * @param {string}   props.said    How many are selected, in words.
 * @param {string}   props.detail  What they are, by kind.
 * @param {Array}    props.actions [{ key, label, onClick, disabled, why }]: why is said while it is held.
 * @param {Function} props.onClear Empties the selection.
 * @param {boolean}  props.working A decision is being carried out.
 * @param {Object}   props.barRef  Takes the bar, for focus to come back to.
 */
export function SelectionBar( { said, detail = '', actions, onClear, working, barRef } ) {
	return (
		<div ref={ barRef } className="bs-ds-selbar">
			<p className="bs-ds-selbar__said">
				<span className="bs-ds-selbar__count">{ said }</span>
				{ detail ? <span className="bs-ds-selbar__detail">{ detail }</span> : null }
			</p>
			<div className="bs-ds-selbar__actions">
				{ actions.map( ( action ) => (
					<Button key={ action.key } type="secondary" size="sm" disabled={ working || action.disabled } onClick={ action.onClick }>
						{ action.label }
					</Button>
				) ) }
				<Button type="ghost" size="sm" icon="x" iconTone="2" disabled={ working } onClick={ onClear }>
					{ __( 'Clear Selection', 'bettershield' ) }
				</Button>
			</div>
			{ actions
				.filter( ( action ) => action.disabled && action.why )
				.map( ( action ) => (
					<p key={ action.key } className="bs-ds-selbar__why">
						{ action.why }
					</p>
				) ) }
		</div>
	);
}

/**
 * The question asked before anything changes: how many, what they are and
 * what doing it means, with the control that does it and the way out. It
 * takes focus when it opens, so it is read before it is answered; Escape
 * answers no.
 *
 * @param {Object}   props
 * @param {string}   props.title     The question, with its count.
 * @param {string}   props.desc      What doing it means.
 * @param {string}   props.namesLead The line before the names, where there are any.
 * @param {string[]} props.names     Paths worth reading before saying yes.
 * @param {string}   props.more      How many more there are than are named, in words.
 * @param {string}   props.confirm   The control's words, with the count.
 * @param {boolean}  props.working   The decision is being carried out.
 * @param {Function} props.onConfirm Does it.
 * @param {Function} props.onCancel  Does not.
 * @param {Object}   props.dialogRef Takes the question, for focus.
 */
export function SelectionQuestion( { title, desc, namesLead = '', names = [], more = '', confirm, working, onConfirm, onCancel, dialogRef } ) {
	const id = useId().replace( /[^\w-]/g, '' );

	// Its control goes quiet while it works; the reader is told it started,
	// and the answer that replaces it is announced as it arrives.
	useEffect( () => {
		if ( working ) {
			announce( __( 'Working…', 'bettershield' ) );
		}
	}, [ working ] );

	const onKeyDown = ( event ) => {
		if ( 'Escape' === event.key && ! working ) {
			event.stopPropagation();
			onCancel();
		}
	};

	return (
		<div
			ref={ dialogRef }
			tabIndex={ -1 }
			className="bs-ds-selask"
			role="alertdialog"
			aria-labelledby={ `bs-ds-selask-${ id }-title` }
			aria-describedby={ `bs-ds-selask-${ id }-desc` }
			onKeyDown={ onKeyDown }
		>
			<span className="bs-ds-selask__lead">
				<Icon name="triangle-alert" size={ 16 } tone="warning" />
			</span>
			<div className="bs-ds-selask__content">
				<p className="bs-ds-selask__title" id={ `bs-ds-selask-${ id }-title` }>
					{ title }
				</p>
				<div className="bs-ds-selask__desc" id={ `bs-ds-selask-${ id }-desc` }>
					<p>{ desc }</p>
					{ names.length ? (
						<>
							<p>{ namesLead }</p>
							<ul className="bs-ds-selask__names">
								{ names.map( ( name ) => (
									<li key={ name }>{ name }</li>
								) ) }
							</ul>
							{ more ? <p>{ more }</p> : null }
						</>
					) : null }
				</div>
				<div className="bs-ds-selask__actions">
					<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ onConfirm }>
						{ confirm }
					</Button>
					<Button type="ghost" size="sm" disabled={ working } onClick={ onCancel }>
						{ __( 'Cancel', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</div>
	);
}

/**
 * What a decision about many did: how many, which were left as they were and
 * why, and its Undo where there is one. Announced as it arrives, and put
 * away by the reader.
 *
 * @param {Object}   props
 * @param {string}   props.tone      success, warning or error.
 * @param {string}   props.title     What happened, with its count.
 * @param {string}   props.desc      What it means now.
 * @param {Array}    props.left      [{ key, text }]: what was left as it was, and why.
 * @param {string}   props.undoLabel Undo's words, where there is one.
 * @param {Function} props.onUndo    Takes it back.
 * @param {boolean}  props.working   A decision is being carried out.
 * @param {Function} props.onDismiss Puts it away.
 * @param {Object}   props.alertRef  Takes the answer, for focus.
 */
export function SelectionReceipt( { tone = 'success', title, desc = '', left = [], undoLabel = '', onUndo, working, onDismiss, alertRef } ) {
	// A long list scrolls inside the answer rather than covering the rows,
	// and can be reached by keyboard to be scrolled.
	const long = left.length > LEFT_SHOWN;

	return (
		// The alert's tint is see-through, and the answer sits over the rows.
		<div className="bs-ds-selsaid">
			<Alert
				live
				layout="default"
				alertRef={ alertRef }
				tone={ tone }
				title={ title }
				desc={
					desc || left.length ? (
						<>
							{ desc ? <p>{ desc }</p> : null }
							{ left.length ? (
								<ul className={ long ? 'bs-ds-selleft bs-ds-selleft--long' : 'bs-ds-selleft' } tabIndex={ long ? 0 : undefined } aria-label={ long ? __( 'Left as they were', 'bettershield' ) : undefined }>
									{ left.map( ( item ) => (
										<li key={ item.key }>{ item.text }</li>
									) ) }
								</ul>
							) : null }
						</>
					) : undefined
				}
				actions={
					undoLabel && onUndo ? (
						<Button type="ghost" size="sm" isBusy={ working } disabled={ working } onClick={ onUndo }>
							{ undoLabel }
						</Button>
					) : null
				}
				onDismiss={ working ? undefined : onDismiss }
			/>
		</div>
	);
}
