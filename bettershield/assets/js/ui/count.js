/**
 * A count as a reader reads it: grouped the browser's way ("2,485"), as the
 * stats strips have always written theirs.
 *
 * A sentence that counts passes the number to a `%d`, which never groups, so
 * the same screen read "2,969" in its strip and "2262 related records" in a
 * row (#2552). Where a count meets text it goes through here, as a `%s`; the
 * plural choice in `_n()` still takes the raw number.
 *
 * @param {number|string} value The count.
 * @return {string} It, grouped.
 */
export function formatCount( value ) {
	return ( Number( value ) || 0 ).toLocaleString();
}
