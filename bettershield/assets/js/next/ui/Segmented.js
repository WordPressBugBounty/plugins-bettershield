/**
 * The design's Segmented control (10:17620): two to four views of one card.
 */

import './Segmented.css';

import { onTabKey, panelId, tabId } from './tabKeys';

export default function Segmented( { id, label, options, selected, onSelect } ) {
	const keys = options.map( ( option ) => option.key );

	return (
		<div className="bs-ds-seg" role="tablist" aria-label={ label }>
			{ options.map( ( option ) => (
				<button
					key={ option.key }
					type="button"
					role="tab"
					id={ tabId( id, option.key ) }
					className="bs-ds-seg__item"
					aria-selected={ selected === option.key }
					aria-controls={ panelId( id ) }
					tabIndex={ selected === option.key ? 0 : -1 }
					onClick={ () => onSelect( option.key ) }
					onKeyDown={ ( event ) => onTabKey( event, keys, selected, onSelect, id ) }
				>
					{ option.label }
				</button>
			) ) }
		</div>
	);
}
