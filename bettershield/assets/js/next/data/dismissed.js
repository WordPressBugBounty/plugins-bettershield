/**
 * Alerts a reader dismissed, kept in this browser until the next audit: the
 * dismissal is remembered with the audit it was made on, and a newer audit
 * brings the alert back.
 */

const KEY = 'bettershield-ds-dismissed';

function read() {
	try {
		const stored = JSON.parse( window.localStorage.getItem( KEY ) || '{}' );

		return stored && 'object' === typeof stored ? stored : {};
	} catch ( error ) {
		return {};
	}
}

export function isDismissed( id, audit ) {
	return Boolean( audit ) && read()[ id ] === audit;
}

export function dismiss( id, audit ) {
	const stored = read();

	stored[ id ] = audit;

	try {
		window.localStorage.setItem( KEY, JSON.stringify( stored ) );
	} catch ( error ) {
		// Kept for this visit only.
	}
}
