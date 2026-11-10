/**
 * The admin menu's bubble for the Agents screen, kept to the live count.
 *
 * WordPress drew the bubble when the page loaded, with the number of requests
 * waiting then. It sits outside this app, so nothing else moves it when one
 * is allowed or withdrawn here: brought to the same number, or taken away at
 * none.
 */

/**
 * @param {number} waiting The live count.
 */
export default function matchAdminMenu( waiting ) {
	const menu = document.getElementById( 'adminmenu' );

	if ( ! menu ) {
		return;
	}

	Array.from( menu.querySelectorAll( 'a[href*="page=bettershield-agents"]' ) ).forEach( ( anchor ) => {
		let page = '';

		try {
			page = new URL( anchor.getAttribute( 'href' ), window.location.href ).searchParams.get( 'page' );
		} catch {
			return;
		}

		if ( 'bettershield-agents' !== page ) {
			return;
		}

		const bubble = anchor.querySelector( '.update-plugins' );

		if ( waiting < 1 ) {
			if ( bubble ) {
				bubble.remove();
			}

			return;
		}

		const shown = waiting.toLocaleString();

		if ( bubble ) {
			bubble.className = `update-plugins count-${ waiting }`;

			const number = bubble.querySelector( '.plugin-count' );

			if ( number ) {
				number.textContent = shown;
			}

			return;
		}

		const added = document.createElement( 'span' );
		const number = document.createElement( 'span' );

		added.className = `update-plugins count-${ waiting }`;
		number.className = 'plugin-count';
		number.textContent = shown;
		added.appendChild( number );
		( anchor.querySelector( '.wp-menu-name' ) || anchor ).append( ' ', added );
	} );
}
