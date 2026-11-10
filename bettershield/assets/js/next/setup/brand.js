/**
 * The plugin's name as the admin area shows it: the owner's label where an
 * add-on sets one, otherwise BetterShield. The server hands it over with the
 * page; read when asked, so every string built from it agrees with the menu.
 *
 * @return {string} The name.
 */
export default function brand() {
	const model = ( 'undefined' !== typeof window && window.bettershield ) || {};

	return 'string' === typeof model.brand && '' !== model.brand.trim() ? model.brand : 'BetterShield';
}
