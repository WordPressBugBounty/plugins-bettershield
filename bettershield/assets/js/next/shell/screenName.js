/**
 * What the top bar calls the screen.
 */

import { brand, findSection, navItemFor } from '../../nav';

/**
 * The sidebar's name for the screen where it has one, and the section's
 * otherwise, so a screen missing from the sidebar still has a heading.
 *
 * @param {{section: string, tab: string}} route A resolved route.
 * @return {{title: string, group: string, zone: string}} The heading, and the add-on and group above it.
 */
export function screenName( route ) {
	const found = navItemFor( route );

	if ( found ) {
		return { title: found.item.label, group: found.group.label || '', zone: found.zone.label || '' };
	}

	const section = findSection( route.section );

	return { title: section ? section.label : brand, group: '', zone: '' };
}
