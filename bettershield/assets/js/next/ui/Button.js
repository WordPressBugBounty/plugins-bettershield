/**
 * The design's Button (Primary, Secondary, Toolbar, Ghost, Subtle, Link,
 * Link-subtle; sm 28, md 32, lg 36), on the library's Button so focus,
 * busy and disabled behave the way every other WordPress control does.
 *
 * The library's own look is replaced, not mixed in: no `variant` is passed,
 * so none of its variant classes are on the element.
 */

import './Button.css';

import { Button as CoreButton } from '@wordpress/components';
import { forwardRef } from '@wordpress/element';
import Icon from './Icon';

/** Leading icons that read as "working" when they turn. */
const SPINNING = [ 'refresh-cw' ];

/**
 * @param {Object}  props
 * @param {string}  props.type     primary, secondary, toolbar, ghost, subtle, link or linksub.
 * @param {string}  props.size     sm, md or lg.
 * @param {string}  props.icon     Leading icon name.
 * @param {string}  props.iconTone The leading icon's color.
 * @param {string}  props.trailing Trailing icon name.
 * @param {string}  props.trailingTone The trailing icon's color.
 * @param {boolean} props.iconOnly A square button with only its icon; `label` names it.
 * @param {string}  props.className Extra classes.
 */
function Button(
	{
		type = 'secondary',
		size = 'sm',
		icon = '',
		iconTone = '',
		trailing = '',
		trailingTone = '1',
		iconOnly = false,
		className = '',
		children,
		...rest
	},
	ref
) {
	/*
	 * A control held while its own request runs stays focusable, as the
	 * library allows: disabled outright, the browser dropped focus to the
	 * page, and the next Tab started again at the top (#1926). It still
	 * takes no press, and says it is unavailable.
	 */
	const focusable = undefined !== rest.accessibleWhenDisabled ? rest.accessibleWhenDisabled : Boolean( rest.isBusy );

	const iconSize = 'sm' === size ? 14 : 16;
	// A refresh icon turns while its button's request runs, on every button,
	// so the press shows until the work it started is done.
	const turning = Boolean( rest.isBusy ) && SPINNING.includes( icon );
	const classes = [
		'bs-ds-btn',
		`bs-ds-btn--${ type }`,
		`bs-ds-btn--${ size }`,
		iconOnly ? 'bs-ds-btn--icon' : '',
		turning ? 'bs-ds-btn--turning' : '',
		className,
	]
		.filter( Boolean )
		.join( ' ' );

	return (
		<CoreButton ref={ ref } className={ classes } { ...rest } accessibleWhenDisabled={ focusable }>
			{ icon ? <Icon name={ icon } size={ iconSize } tone={ iconTone } /> : null }
			{ children }
			{ trailing ? <Icon name={ trailing } size={ 14 } tone={ trailingTone } /> : null }
		</CoreButton>
	);
}

// Forwarded, so a screen can put focus back on the control that opened something.
export default forwardRef( Button );
