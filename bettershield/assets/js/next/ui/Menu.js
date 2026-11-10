/**
 * A menu under a control: the library's Dropdown, its panel drawn as the
 * design's menu (as in the remind menu of frame 23:34367), with an optional
 * heading and a list of choices.
 */

import './Menu.css';

import { Dropdown } from '@wordpress/components';

/**
 * @param {Object}   props
 * @param {Function} props.renderToggle The control, given { isOpen, onToggle }.
 * @param {string}   props.head         A heading over the choices.
 * @param {Array}    props.items        [{ key, label, onClick, head }]: a `head` entry is a heading between choices.
 * @param {string}   props.placement    Where the panel opens.
 */
export default function Menu( { renderToggle, head, items, placement = 'bottom-start' } ) {
	return (
		<Dropdown
			className="bs-ds-menuwrap"
			popoverProps={ { placement, offset: 6, className: 'bs-ds-popover' } }
			renderToggle={ renderToggle }
			renderContent={ ( { onClose } ) => (
				<div className="bs-ds-menu" role="menu">
					{ head ? <div className="bs-ds-menu__head">{ head }</div> : null }
					{ items.map( ( item ) =>
						item.head ? (
							<div key={ item.key } className="bs-ds-menu__head">
								{ item.head }
							</div>
						) : (
							<button
								key={ item.key }
								type="button"
								role="menuitem"
								className="bs-ds-menu__item"
								onClick={ () => {
									onClose();
									item.onClick();
								} }
							>
								{ item.label }
							</button>
						)
					) }
				</div>
			) }
		/>
	);
}
