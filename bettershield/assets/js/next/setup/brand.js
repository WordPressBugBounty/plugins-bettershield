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

/**
 * Whether the links to this plugin's support are offered: not where an owner
 * labeled the chrome and asked for them to go, as the dashboard's sidebar
 * leaves out Docs & support. The server decides; read when asked.
 *
 * @return {boolean} Whether to show them.
 */
export function helpLinks() {
	const model = ( 'undefined' !== typeof window && window.bettershield ) || {};

	return false !== model.helpLinks;
}
