/**
 * What tabs share: the ids that tie a tab to its panel, and the keys that
 * move between tabs (arrows, Home, End), with focus following the choice.
 * Only the selected tab is in the page's tab order.
 */

export const tabId = ( base, key ) => `${ base }-tab-${ key }`;
export const panelId = ( base ) => `${ base }-panel`;

/** The attributes a tab's panel takes. */
export const panelProps = ( base, selected ) => ( { role: 'tabpanel', id: panelId( base ), 'aria-labelledby': tabId( base, selected ) } );

/**
 * Whether a tab sits in a right-to-left row: its computed direction, or the
 * nearest `dir` where nothing computes one.
 *
 * @param {?Element} node The tab.
 * @return {boolean} Whether its row runs right to left.
 */
function isRtl( node ) {
	if ( ! node || ! node.closest ) {
		return false;
	}

	const computed = window.getComputedStyle ? window.getComputedStyle( node ).direction : '';

	if ( computed ) {
		return 'rtl' === computed;
	}

	const marked = node.closest( '[dir]' );

	return Boolean( marked ) && 'rtl' === marked.getAttribute( 'dir' );
}

/**
 * @param {KeyboardEvent} event    The key.
 * @param {Array<string>} keys     The tabs' keys, in order.
 * @param {string}        selected The selected tab's key.
 * @param {Function}      onSelect Selects a tab by key.
 * @param {string}        base     The tabs' id base.
 */
export function onTabKey( event, keys, selected, onSelect, base ) {
	const index = keys.indexOf( selected );
	// In a right-to-left row the tabs run right to left, so the arrows swap:
	// Right moved focus to the tab drawn on its left.
	const step = isRtl( event.currentTarget ) ? -1 : 1;
	const moves = {
		ArrowRight: index + step,
		ArrowDown: index + 1,
		ArrowLeft: index - step,
		ArrowUp: index - 1,
		Home: 0,
		End: keys.length - 1,
	};

	if ( ! ( event.key in moves ) ) {
		return;
	}

	event.preventDefault();

	const next = keys[ ( moves[ event.key ] + keys.length ) % keys.length ];

	onSelect( next );

	const tab = document.getElementById( tabId( base, next ) );

	if ( tab ) {
		tab.focus();
	}
}
