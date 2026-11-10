/**
 * The bulk flow (design frames 23:32941, 23:34367, 23:34787, 23:36680): the
 * bar a selection brings up, the remind menu, the inline confirmation before
 * findings are marked not applicable, and the alert after, with Undo.
 */

import './Bulk.css';

import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Checkbox from '../ui/Checkbox';
import Icon from '../ui/Icon';
import Menu from '../ui/Menu';
import { WholeRow, ptsLabel } from './Rows';

/** The lengths a finding can be snoozed for: the ones the plugin offers. */
export const REMIND_DAYS = [ 7, 30 ];

/**
 * @param {Object}   props
 * @param {number}   props.count           How many findings are selected.
 * @param {number}   props.total           How many rows are listed.
 * @param {boolean}  props.all             Whether every listed row is selected.
 * @param {number}   props.points          Points the selection takes off the score.
 * @param {number}   props.fixable         How many of them have a one-press fix.
 * @param {boolean}  props.working         Whether an action is running.
 * @param {Function} props.onClear         Clears the selection.
 * @param {Function} props.onRemind        Snoozes the selection for a number of days.
 * @param {Function} props.onNotApplicable Asks about marking the selection not applicable.
 * @param {Function} props.onApplyFix      Asks about applying the one-press fixes.
 */
export function BulkBar( { count, total, all, points: off, fixable = 0, working, onClear, onRemind, onNotApplicable, onApplyFix } ) {
	return (
		<div className="bs-ds-fbulk" role="row">
			<div className="bs-ds-fbulk__cell" role="cell">
				<Checkbox label={ __( 'Clear selection', 'bettershield' ) } state={ count === total && all ? true : 'mixed' } onChange={ onClear } disabled={ working } />
				<span className="bs-ds-fbulk__label">
					{ sprintf(
						/* translators: %d: how many findings are selected. */
						_n( '%d selected', '%d selected', count, 'bettershield' ),
						count
					) }
				</span>
				<Badge>{ ptsLabel( off ) }</Badge>
				<span className="bs-ds-spacer" />
				{ /* Only the fixes a row applies in one press: a Fix panel, guided
				     or outside fix asks the owner something first. */ }
				{ fixable > 0 && onApplyFix ? (
					<Button type="toolbar" size="sm" icon="wrench" iconTone="2" disabled={ working } onClick={ onApplyFix }>
						{ sprintf(
							/* translators: %d: how many of the selected findings have a one-press fix. */
							__( 'Apply Fix (%d)', 'bettershield' ),
							fixable
						) }
					</Button>
				) : null }
				<Menu
					head={ sprintf(
						/* translators: %d: how many findings the reminder is for. */
						_n( 'Snooze %d finding', 'Snooze %d findings', count, 'bettershield' ),
						count
					) }
					items={ REMIND_DAYS.map( ( days ) => ( {
						key: `in-${ days }`,
						label: sprintf(
							/* translators: %d: number of days. */
							_n( 'In %d day', 'In %d days', days, 'bettershield' ),
							days
						),
						onClick: () => onRemind( days ),
					} ) ) }
					renderToggle={ ( { isOpen, onToggle } ) => (
						<Button type="toolbar" size="sm" icon="clock" iconTone="2" trailing="chevron-down" trailingTone="3" aria-expanded={ isOpen } disabled={ working } onClick={ onToggle }>
							{ __( 'Snooze', 'bettershield' ) }
						</Button>
					) }
				/>
				<Button type="toolbar" size="sm" icon="ban" iconTone="2" disabled={ working } onClick={ onNotApplicable }>
					{ __( 'Mark Not Applicable', 'bettershield' ) }
				</Button>
				<Button type="ghost" size="sm" icon="x" iconTone="2" disabled={ working } onClick={ onClear }>
					{ __( 'Clear', 'bettershield' ) }
				</Button>
			</div>
		</div>
	);
}

/**
 * The question itself, outside the report's table, for a screen that asks it
 * elsewhere.
 *
 * @param {Object}   props
 * @param {number}   props.count     How many findings it asks about.
 * @param {string}   props.name      The finding it names, when it came from one finding.
 * @param {number}   props.points    What they take off the score.
 * @param {boolean}  props.managed   Whether it asks in the words of "I manage this myself".
 * @param {string}   props.also      The title of a second finding that choice covers.
 * @param {string}   props.id        Prefix for the ids that label the dialog.
 * @param {boolean}  props.working   Whether it is being carried out.
 * @param {Function} props.onConfirm Marks them.
 * @param {Function} props.onCancel  Asks nothing more.
 * @param {Object}   props.dialogRef Takes the question's element, for focus.
 */
export function ConfirmBox( { count, name = '', points: off, managed = false, also = '', id = 'bs-ds-fconfirm', working, onConfirm, onCancel, dialogRef } ) {
	// One named finding is spoken of as one, whatever else it covers.
	const said = name ? 1 : count;

	// Escape answers no, as it does in any dialog.
	const onKeyDown = ( event ) => {
		if ( 'Escape' === event.key && ! working ) {
			event.stopPropagation();
			onCancel();
		}
	};

	let title = sprintf(
		/* translators: %d: how many findings. */
		_n( 'Mark %d finding as not applicable?', 'Mark %d findings as not applicable?', count, 'bettershield' ),
		count
	);
	let press = sprintf(
		/* translators: %d: how many findings. */
		_n( 'Mark %d Not Applicable', 'Mark %d Not Applicable', count, 'bettershield' ),
		count
	);

	if ( name && managed ) {
		title = sprintf(
			/* translators: %s: a finding's title. */
			__( 'Mark “%s” as managed by you?', 'bettershield' ),
			name
		);
		press = __( 'I Manage This Myself', 'bettershield' );
	} else if ( name ) {
		title = sprintf(
			/* translators: %s: a finding's title. */
			__( 'Mark “%s” as not applicable?', 'bettershield' ),
			name
		);
		press = __( 'Mark Not Applicable', 'bettershield' );
	}

	return (
		<div
			ref={ dialogRef }
			tabIndex={ -1 }
			className="bs-ds-fconfirm"
			role="alertdialog"
			aria-labelledby={ `${ id }-title` }
			aria-describedby={ `${ id }-desc` }
			onKeyDown={ onKeyDown }
		>
			<span className="bs-ds-fconfirm__lead">
				<Icon name="triangle-alert" size={ 16 } tone="warning" />
			</span>
			<div className="bs-ds-fconfirm__content">
				<div className="bs-ds-fconfirm__text">
					<p className="bs-ds-fconfirm__title" id={ `${ id }-title` }>
						{ title }
					</p>
					<p className="bs-ds-fconfirm__desc" id={ `${ id }-desc` }>
						{ sprintf(
							/* translators: %s: points off the score, e.g. "−9 pts". */
							_n(
								'It stops counting against your score (%s). Nothing on your site changes, and you can restore it.',
								'They stop counting against your score (%s). Nothing on your site changes, and you can restore them.',
								said,
								'bettershield'
							),
							ptsLabel( off )
						) }
						{ also
							? ' ' +
							  sprintf(
									/* translators: %s: the title of a second finding the same choice covers. */
									__( 'It also covers “%s”.', 'bettershield' ),
									also
							  )
							: null }
					</p>
				</div>
				<div className="bs-ds-fconfirm__actions">
					<Button type="toolbar" size="sm" isBusy={ working } disabled={ working } onClick={ onConfirm }>
						{ press }
					</Button>
					<Button type="ghost" size="sm" disabled={ working } onClick={ onCancel }>
						{ __( 'Cancel', 'bettershield' ) }
					</Button>
				</div>
			</div>
		</div>
	);
}

export function Confirm( props ) {
	return (
		<WholeRow className="bs-ds-fblock">
			<ConfirmBox { ...props } />
		</WholeRow>
	);
}

/**
 * The alert's headline after "I manage this myself".
 *
 * @param {number} count How many findings it marked.
 * @return {string} The line.
 */
export function managedTitle( count ) {
	return sprintf(
		/* translators: %d: how many findings. */
		_n( '%d finding marked as managed by you.', '%d findings marked as managed by you.', count, 'bettershield' ),
		count
	);
}

/**
 * Where those findings went, said in the same alert.
 *
 * @param {number} count How many findings it marked.
 * @return {string} The line.
 */
export function movedLine( count ) {
	return _n(
		'It moved to the Not applicable tab and no longer counts against the score.',
		'They moved to the Not applicable tab and no longer count against the score.',
		count,
		'bettershield'
	);
}

/**
 * The one question before the selection's one-press fixes are applied:
 * what each turns on, and that each can be undone.
 *
 * @param {Object}    props
 * @param {number}    props.count     How many fixes it asks about.
 * @param {?string[]} props.names     The protection each fix turns on, by Hardening's name; null while that list is still being read.
 * @param {string[]}  props.cautions  What any of them can't take back, said before the press.
 * @param {boolean}   props.working   Whether the fixes are being applied.
 * @param {Function}  props.onConfirm Applies them.
 * @param {Function}  props.onCancel  Asks nothing more.
 * @param {Object}    props.dialogRef Takes the question's element, for focus.
 */
export function FixConfirm( { count, names, cautions = [], working, onConfirm, onCancel, dialogRef } ) {
	// Asked before the names are known only for the moment the list takes
	// to read: Apply waits for them, so nothing is applied unnamed.
	const reading = ! names;
	const onKeyDown = ( event ) => {
		if ( 'Escape' === event.key && ! working ) {
			event.stopPropagation();
			onCancel();
		}
	};

	return (
		<WholeRow className="bs-ds-fblock">
			<div
				ref={ dialogRef }
				tabIndex={ -1 }
				className="bs-ds-fconfirm"
				role="alertdialog"
				aria-labelledby="bs-ds-fconfirm-title"
				aria-describedby="bs-ds-fconfirm-desc"
				onKeyDown={ onKeyDown }
			>
				<span className="bs-ds-fconfirm__lead">
					<Icon name="triangle-alert" size={ 16 } tone="warning" />
				</span>
				<div className="bs-ds-fconfirm__content">
					<div className="bs-ds-fconfirm__text">
						<p className="bs-ds-fconfirm__title" id="bs-ds-fconfirm-title">
							{ sprintf(
								/* translators: %d: how many fixes. */
								_n( 'Apply %d fix?', 'Apply %d fixes?', count, 'bettershield' ),
								count
							) }
						</p>
						<div className="bs-ds-fconfirm__desc" id="bs-ds-fconfirm-desc">
							<p className="bs-ds-fconfirm__desc">{ _n( 'This fix is applied:', 'These fixes are applied:', count, 'bettershield' ) }</p>
							{ reading ? (
								<p className="bs-ds-fconfirm__desc">{ __( 'Reading the protections…', 'bettershield' ) }</p>
							) : (
								<ul className="bs-ds-fconfirm__list">
									{ names.map( ( name, index ) => (
										<li key={ `${ index }-${ name }` }>{ name }</li>
									) ) }
								</ul>
							) }
							{ cautions.map( ( caution ) => (
								<p key={ caution } className="bs-ds-fconfirm__desc">
									{ caution }
								</p>
							) ) }
							<p className="bs-ds-fconfirm__desc">
								{ 1 === count
									? __( 'It’s applied just as its own Apply Fix would. You can undo it afterwards.', 'bettershield' )
									: __( 'Each is applied just as its own Apply Fix would. You can undo them all at once afterwards.', 'bettershield' ) }
							</p>
						</div>
					</div>
					<div className="bs-ds-fconfirm__actions">
						<Button type="toolbar" size="sm" isBusy={ working } disabled={ working || reading } onClick={ onConfirm }>
							{ sprintf(
								/* translators: %d: how many fixes. */
								_n( 'Apply %d Fix', 'Apply %d Fixes', count, 'bettershield' ),
								count
							) }
						</Button>
						<Button type="ghost" size="sm" disabled={ working } onClick={ onCancel }>
							{ __( 'Cancel', 'bettershield' ) }
						</Button>
					</div>
				</div>
			</div>
		</WholeRow>
	);
}

/**
 * What a bulk action did, with Undo, and what it could not do, with why:
 * findings marked not applicable, or snoozed until a time.
 *
 * @param {Object}   props
 * @param {string}   props.kind      na, managed, snooze or fix (one, or several from the bulk bar).
 * @param {number}   props.count     How many findings it changed.
 * @param {number}   props.failed    How many it could not change.
 * @param {string}   props.reason    Why the first of those could not be changed.
 * @param {boolean}  props.undoing   Whether those are ones Undo could not put back.
 * @param {string}   props.until     When the snooze ends, as words; snooze only.
 * @param {string}   props.name      The protection turned on; fix only.
 * @param {boolean}  props.changed   Whether a fix made a change of its own rather than turning on a protection; fix only.
 * @param {number}   props.stillOpen How many fixed findings the audit still finds open; fix only.
 * @param {boolean}  props.working   Whether Undo is running.
 * @param {Function} props.onUndo    Reverses it.
 * @param {Function} props.onDismiss Hides the alerts.
 * @param {Object}   props.alertRef  Takes the first alert's element, for focus.
 */
export function Done( { kind = 'na', count, failed = 0, reason = '', partial = '', named = '', undoing = false, until = '', name = '', changed = false, stillOpen = 0, working, onUndo, onDismiss, alertRef } ) {
	const snoozed = 'snooze' === kind;
	// A fix applied from its row, which was taken away with no word and no
	// way back but the Hardening switch (#1914).
	const fixed = 'fix' === kind;
	let title =
		'managed' === kind
			? managedTitle( count )
			: sprintf(
					/* translators: %d: how many findings. */
					_n( '%d finding marked not applicable.', '%d findings marked not applicable.', count, 'bettershield' ),
					count
			  );
	let desc = movedLine( count );

	if ( snoozed ) {
		title = sprintf(
			/* translators: 1: how many findings, 2: when the snooze ends. */
			_n( '%1$d finding snoozed until %2$s.', '%1$d findings snoozed until %2$s.', count, 'bettershield' ),
			count,
			until
		);
		desc = _n(
			'It’s in the Snoozed tab and still lowers your score. It comes back sooner if it becomes more serious.',
			'They moved to Snoozed and still count in the score. Each returns early if it gets worse.',
			count,
			'bettershield'
		);
	} else if ( fixed && ( count > 1 || failed > 0 ) ) {
		// From the bulk bar: how many, and plainly which could not be (#2565).
		title =
			failed > 0
				? sprintf(
						/* translators: 1: how many fixes were applied, 2: how many could not be, 3: why the first of those could not be. */
						_n( '%1$d fix applied. %2$d couldn’t be: %3$s', '%1$d fixes applied. %2$d couldn’t be: %3$s', count, 'bettershield' ),
						count,
						failed,
						reason || __( 'it was refused.', 'bettershield' )
				  )
				: sprintf(
						/* translators: %d: how many fixes were applied. */
						_n( '%d fix applied.', '%d fixes applied.', count, 'bettershield' ),
						count
				  );
		desc = changed
			? _n( 'Undo puts back what it changed.', 'Undo puts back what each one changed.', count, 'bettershield' )
			: _n( 'Undo turns the protection off again.', 'Undo turns those protections off again.', count, 'bettershield' );

		// What the panel defaults changed, by name, before the way back (#2638).
		if ( named ) {
			desc = `${ named }. ${ desc }`;
		}
	} else if ( fixed ) {
		title = sprintf(
			/* translators: %s: the protection that was turned on. */
			__( 'Applied: %s', 'bettershield' ),
			name
		);
		// A panel's usual choice, made from the row (#2618): what it changed
		// is the panel's own, and its Undo puts that back.
		desc = changed
			? _n( 'Undo puts back what it changed.', 'Undo puts back what each one changed.', 1, 'bettershield' )
			: __( 'The finding is fixed. Undo turns the protection off again.', 'bettershield' );
	}

	/*
	 * The protection is on and the audit still finds the problem (#2701):
	 * never "fixed", and never green. The row below says the same.
	 */
	const unresolved = fixed && ! undoing && stillOpen > 0;

	if ( unresolved && 1 === count && ! failed ) {
		title = sprintf(
			/* translators: %s: the protection that was turned on. */
			__( '%s is on, but the finding is still open.', 'bettershield' ),
			name
		);
		desc = __( 'Open Hardening to see why. Undo turns the protection off again.', 'bettershield' );
	} else if ( unresolved ) {
		const left = sprintf(
			/* translators: %d: how many findings stayed open after their fix. */
			_n( '%d finding is still open. Open Hardening to see why.', '%d findings are still open. Open Hardening to see why.', stillOpen, 'bettershield' ),
			stillOpen
		);

		desc = `${ left } ${ desc }`;
	}

	/*
	 * A default that changed only part of its list (#2637): never the green
	 * "Applied". A single one leads with how many and what was not changed;
	 * from the bulk bar it is said under the count.
	 */
	const short = fixed && ! undoing && '' !== partial;

	if ( short && 1 === count && ! failed ) {
		title = partial;
	} else if ( short ) {
		desc = `${ partial } ${ desc }`;
	}

	// Said in the one alert, so the warning below would repeat it.
	const failedApart = ! ( fixed && count > 0 && failed > 0 && ! undoing );

	return (
		<WholeRow className="bs-ds-fblock bs-ds-fblock--stack">
			{ count > 0 ? (
				<Alert
					live
					alertRef={ alertRef }
					tone={ failedApart && ! short && ! unresolved ? 'success' : 'warning' }
					title={ title }
					desc={ desc }
					actions={
						<Button type="ghost" size="sm" className="bs-ds-fundo" isBusy={ working } disabled={ working } onClick={ onUndo }>
							{ __( 'Undo', 'bettershield' ) }
						</Button>
					}
					onDismiss={ onDismiss }
				/>
			) : null }
			{ failed > 0 && failedApart ? (
				<Alert
					live
					alertRef={ count > 0 ? undefined : alertRef }
					tone="warning"
					title={
						undoing
							? sprintf(
									/* translators: %d: how many findings Undo could not put back. */
									_n( '%d finding could not be put back.', '%d findings could not be put back.', failed, 'bettershield' ),
									failed
							  )
							: sprintf(
									/* translators: %d: how many findings were left as they were. */
									_n( '%d finding could not be changed.', '%d findings could not be changed.', failed, 'bettershield' ),
									failed
							  )
					}
					desc={ reason }
					onDismiss={ count > 0 ? undefined : onDismiss }
				/>
			) : null }
		</WholeRow>
	);
}
