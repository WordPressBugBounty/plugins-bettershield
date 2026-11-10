/**
 * Brings the whole filter panel into view once the popover has placed it.
 *
 * The panel always opens under its button. Left to choose, the popover opened
 * it above the button whenever the room below was short — over the summary
 * and the tabs — and then moved it back under the button as soon as a scroll
 * made room, so it was found in a different place each time and jumped while
 * the page moved. Opening in one place means the page sometimes has to move
 * instead, and this is that: a scroll only as far as the panel's last row.
 *
 * It waits for the popover to be placed, because before then the panel sits
 * at the top of the document and scrolling to it there would throw the
 * reader to the top of the page.
 *
 * Shared by the site log the dashboard draws and the network's log.
 *
 * @param {?HTMLElement} node The panel, as React attaches it.
 */
export function revealWhenPlaced( node ) {
	if ( ! node || ! node.scrollIntoView ) {
		return;
	}

	let frames = 0;

	const step = () => {
		const popover = node.closest( '.components-popover' );

		if ( popover && popover.classList.contains( 'is-positioned' ) ) {
			const reduced = window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;

			node.scrollIntoView( { block: 'nearest', behavior: reduced ? 'auto' : 'smooth' } );

			return;
		}

		frames += 1;

		if ( frames < 30 ) {
			window.requestAnimationFrame( step );
		}
	};

	window.requestAnimationFrame( step );
}
