/**
 * A control that asks once before it acts: pressed, it is replaced by what
 * will happen, "Yes, Do It" and "Cancel". Focus moves to "Yes, Do It" so the
 * consequence is read with it, and back to the control if the reader cancels.
 *
 * The classic confirmation with the design's buttons: the resting control in
 * the type the screen asks for, the confirmation as the region's one Primary,
 * the way out as a Ghost.
 */

import './Armed.css';

import { forwardRef, useEffect, useId, useRef, useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import Button from './Button';

/**
 * @param {Object}   props
 * @param {*}        props.label       The control's words.
 * @param {*}        props.consequence What pressing "Yes, Do It" will do.
 * @param {boolean}  props.busy        The action is running.
 * @param {boolean}  props.disabled    The control cannot be pressed.
 * @param {Function} props.onConfirm   The action.
 * @param {string}   props.type        The resting control's type: secondary (the default), ghost, primary.
 * @param {string}   props.size        sm (the default) or md.
 * @param {string}   props.icon        The resting control's leading icon.
 * @param {string}   props.confirm     The confirmation's words, where "Yes, Do It" is not the right ones.
 * @param {boolean}  props.held        The confirmation stays up while the action runs and after it fails, so a
 *                                     retry is one press; it goes with what it acted on.
 * @param {string}   props.aria-label  The resting control's accessible name, where its words are the same on every row.
 * @param {string}   props.aria-describedby The id of a line that says why the resting control cannot be pressed now.
 * @param {Object}   ref               Takes the resting control, so a screen can put focus back on it.
 */
function Armed(
	{
		label,
		consequence,
		busy = false,
		disabled = false,
		onConfirm,
		type = 'secondary',
		size = 'sm',
		icon = '',
		confirm: confirmLabel = '',
		held = false,
		'aria-label': name,
		'aria-describedby': describedBy,
	},
	ref
) {
	const [ armed, setArmed ] = useState( false );
	const noteId = useId().replace( /[^\w-]/g, '' ) + '-consequence';
	const confirm = useRef( null );
	const resting = useRef( null );
	const wasArmed = useRef( false );

	useEffect( () => {
		if ( armed ) {
			wasArmed.current = true;

			if ( confirm.current ) {
				confirm.current.focus();
			}
		} else if ( wasArmed.current && resting.current ) {
			resting.current.focus();
		}
	}, [ armed ] );

	const stopped = Boolean( busy ) || Boolean( disabled );

	if ( ! armed ) {
		return (
			<Button
				ref={ ( node ) => {
					resting.current = node;

					if ( 'function' === typeof ref ) {
						ref( node );
					} else if ( ref ) {
						ref.current = node;
					}
				} }
				type={ type }
				size={ size }
				icon={ icon }
				iconTone="1"
				disabled={ stopped }
				// Still focusable while its action runs, so focus is not
				// dropped from the control that was just used.
				accessibleWhenDisabled={ Boolean( busy ) }
				aria-label={ name }
				aria-describedby={ describedBy }
				onClick={ () => setArmed( true ) }
			>
				{ label }
			</Button>
		);
	}

	// Escape answers no, as Cancel does and as it does in any dialog: the
	// confirmation stayed up (#1927). Not while a held request is out,
	// which Cancel cannot take back either.
	const onKeyDown = ( event ) => {
		if ( 'Escape' === event.key && ! ( held && busy ) ) {
			event.stopPropagation();
			setArmed( false );
		}
	};

	return (
		// eslint-disable-next-line jsx-a11y/no-static-element-interactions -- Escape for the buttons inside it, as Cancel.
		<span className="bs-ds-armed" onKeyDown={ onKeyDown }>
			<span id={ noteId } className="bs-ds-armed__note">
				{ consequence }
			</span>
			<span className="bs-ds-armed__actions">
				<Button
					ref={ confirm }
					type="primary"
					size={ size }
					aria-describedby={ noteId }
					isBusy={ busy }
					disabled={ stopped }
					onClick={ () => {
						if ( ! held ) {
							setArmed( false );
						}

						onConfirm();
					} }
				>
					{ confirmLabel || __( 'Yes, Do It', 'bettershield' ) }
				</Button>
				{ /* Held, the request cannot be taken back once it is out. */ }
				<Button type="ghost" size={ size } disabled={ held && Boolean( busy ) } onClick={ () => setArmed( false ) }>
					{ __( 'Cancel', 'bettershield' ) }
				</Button>
			</span>
		</span>
	);
}

// Forwarded to the resting control, so a screen can put focus back on it.
export default forwardRef( Armed );
