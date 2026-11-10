/**
 * How many items of a row fit before the rest have to move into a menu.
 *
 * Its own module, importing nothing, so the rule can be tested without pulling
 * the component library in behind it — the same reason the data helpers live
 * apart from the screens that render them.
 */

/**
 * @param {number}   available Width the row has to work with.
 * @param {number[]} widths    Natural width of each item, in order.
 * @param {number}   reserve   Width the menu button needs, including its gap.
 * @param {number}   gap       Space between two items.
 * @param {number}   selectedIndex Selected item that replaces the last visible item when overflowing.
 * @return {number} How many items to show, always at least one.
 */
export function itemsThatFit( available, widths, reserve, gap, selectedIndex = -1 ) {
	let used = 0;
	let count = 0;

	for ( let index = 0; index < widths.length; index++ ) {
		const width = widths[ index ] + ( index ? gap : 0 );

		/*
		 * Room for the menu button is only kept while something would still be
		 * left over. Reserving it against the final item would push that item
		 * into a menu opened to reveal one entry — which costs more space than
		 * it saves and reads as a bug.
		 */
		const trailing = index < widths.length - 1 ? reserve : 0;

		if ( used + width + trailing > available ) {
			break;
		}

		used += width;
		count++;
	}

	// A selected overflow item replaces the last visible chip. Its actual width
	// must fit too, or that replacement can push the menu out of the clipped row.
	if ( selectedIndex >= count && selectedIndex < widths.length ) {
		while ( count > 1 ) {
			const prefix = widths.slice( 0, count - 1 ).reduce( ( sum, width ) => sum + width, 0 );
			if ( prefix + widths[ selectedIndex ] + ( count - 1 ) * gap + reserve <= available ) {
				break;
			}
			count--;
		}
	}

	// Never nothing. A row of only a menu button hides the filter it is for,
	// and at that width the layout has already stacked anyway.
	return Math.max( 1, count );
}
