/**
 * The last copy of a resource a screen drew, kept through a failed refresh.
 *
 * The store keeps a resource's data while a refresh reads the fresh copy, and
 * drops it when that read fails. A screen drawn from it would blank, and take
 * the reader's place with it, over a read that only failed to update what
 * they were looking at. The screen says the refresh failed instead.
 */

import { useEffect, useRef } from '@wordpress/element';

/**
 * @param {*} data The resource's data as the store holds it now.
 * @return {*} That, or the last copy there was, or null before any.
 */
export function useKept( data ) {
	const kept = useRef( null );
	const present = null !== data && undefined !== data;

	useEffect( () => {
		if ( present ) {
			kept.current = data;
		}
	}, [ data, present ] );

	return present ? data : kept.current;
}
