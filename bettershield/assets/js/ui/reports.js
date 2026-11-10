/**
 * What a watching item has actually seen, turned into rows a card can draw.
 *
 * Kept apart from the screen for the reason the cost wording and the
 * truncation note are: the rule is the part worth testing. An item that
 * collects and refuses to move on until the collection is empty has to say
 * what is in it — a count on its own asks the owner to fix something the
 * screen will not name.
 *
 * The rows arrive from an endpoint browsers post to without a session, so
 * nothing here treats them as trustworthy text: they are read as data, the
 * list is bounded before it is drawn, and a row with no directive is not a
 * kind of anything.
 */

import { __, _n, sprintf } from '@wordpress/i18n';

/**
 * How many kinds a card shows. The server keeps more than a person reads at a
 * glance, and a list long enough to scroll past the card is not a summary.
 */
const SHOWN = 12;

/** The stored rows that name a kind: one with no directive is not a kind of anything. */
function kinds( reports ) {
	return Array.isArray( reports ) ? reports.filter( ( row ) => row && typeof row === 'object' && !! row.directive ) : [];
}

/**
 * How many kinds the card does not list. The reason beside the switch counts
 * every stored kind, and a list of twelve under "30 kinds would still be
 * blocked" has to say the rest exist.
 *
 * @param {Array} reports What the item collected, as the endpoint stored it.
 * @return {number} The kinds past the rows drawn.
 */
export function reportsBeyond( reports ) {
	return Math.max( 0, kinds( reports ).length - SHOWN );
}

/**
 * The rows to draw for one item's collection.
 *
 * @param {Array} reports What the item collected, as the endpoint stored it.
 * @return {Array} Rows carrying a directive, an origin, a count and a label.
 */
export function reportRows( reports ) {
	return kinds( reports )
		.slice( 0, SHOWN )
		.map( ( row ) => {
			const directive = String( row.directive );
			const count = Number( row.count );
			// Every count through its plural forms: "%d times" alone could not
			// be translated for languages with more than two (#1838).
			const times =
				count > 1
					? sprintf(
							/* translators: %d: how many times something was blocked, always more than one. */
							_n( '%d time', '%d times', count, 'bettershield' ),
							count
					  )
					: __( 'once', 'bettershield' );

			// A browser sends no address for an inline script or a violation
			// it will not name the source of. A blank cell reads as a bug;
			// saying what happened reads as the truth.
			const blocked = row.blocked
				? String( row.blocked )
				: __( 'somewhere this site could not read', 'bettershield' );

			// What the server says this row can be let into the policy as, or
			// null where it cannot. The server asks again when it is pressed.
			const allowable = row.allow && 'object' === typeof row.allow && row.allow.directive && ! row.allow.refused && row.blocked;

			return {
				key: directive + ' ' + blocked,
				directive,
				blocked,
				times,
				label: sprintf(
					/* translators: 1: the policy directive, 2: where the blocked resource came from. */
					__( '%1$s from %2$s', 'bettershield' ),
					directive,
					blocked
				),
				allow: allowable
					? {
							directive,
							source: String( row.blocked ),
							as: String( row.allow.directive ),
							warning: row.allow.warning ? String( row.allow.warning ) : '',
					  }
					: null,
			};
		} );
}
