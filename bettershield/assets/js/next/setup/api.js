/**
 * The Quick Setup's requests.
 *
 * Every write answers with the whole setup state, read back from the site
 * after the write rather than echoed from what was sent. The screen then draws
 * what is true, which is the only thing Ready is allowed to summarize.
 */

import apiFetch from '@wordpress/api-fetch';
import { __ } from '@wordpress/i18n';

const ROOT = '/bettershield/v1/quick-setup';

/**
 * Every route the setup writes to, written out in full so each can be found
 * by name. The two-factor ones are the Two-Factor screen's own: the setup
 * enrolls through them rather than through a copy.
 */
export const ROUTES = {
	step: '/bettershield/v1/quick-setup/step',
	consent: '/bettershield/v1/quick-setup/consent',
	coexistence: '/bettershield/v1/quick-setup/coexistence',
	coexistenceDeactivate: '/bettershield/v1/quick-setup/coexistence/deactivate',
	site: '/bettershield/v1/quick-setup/site',
	recoveryReceived: '/bettershield/v1/quick-setup/recovery/received',
	recoveryResend: '/bettershield/v1/quick-setup/recovery/resend',
	recoveryCodes: '/bettershield/v1/quick-setup/recovery/codes',
	requireTwoFactor: '/bettershield/v1/quick-setup/two-factor/require',
	commonNames: '/bettershield/v1/quick-setup/common-names',
	unblockName: '/bettershield/v1/quick-setup/common-names/unblock',
	unblockAllNames: '/bettershield/v1/quick-setup/common-names/unblock-all',
	unmute: '/bettershield/v1/quick-setup/alerts/unmute',
	fixes: '/bettershield/v1/quick-setup/fixes',
	undoFix: ( item ) => `/bettershield/v1/quick-setup/fixes/${ item }/undo`,
	previewFixes: '/bettershield/v1/quick-setup/fixes/preview',
	undoSet: '/bettershield/v1/quick-setup/fixes/undo-set',
	install: '/bettershield/v1/quick-setup/ecosystem/install',
	complete: '/bettershield/v1/quick-setup/complete',
	twoFactorStart: '/bettershield/v1/two-factor/start',
	twoFactorConfirm: '/bettershield/v1/two-factor/confirm',
	twoFactorAcknowledge: '/bettershield/v1/two-factor/acknowledge',
	twoFactorDiscard: '/bettershield/v1/two-factor/discard',
	confirmPassword: '/bettershield/v1/confirm-password',
};

/**
 * Whether a refusal is the site asking for the password again, which the
 * setup answers with a field to type it into rather than a failure notice.
 *
 * @param {*} failure What apiFetch rejected with.
 * @return {boolean} Whether to ask.
 */
export function needsPassword( failure ) {
	return Boolean( failure ) && 'bettershield_confirm_password' === failure.code;
}

/**
 * What the page was handed by PHP: the setup's state as the page was drawn,
 * and the addresses of the screens it points at. Read when asked rather than
 * when this module loads, so the page's own script has always run first.
 *
 * @return {Object} The model.
 */
export function pageModel() {
	return window.bettershieldSetup || {};
}

/**
 * A request to one of the setup's routes, or to another of this plugin's
 * when the path is given in full — the setup enrolls two-factor through the
 * same routes the Two-Factor screen uses rather than a copy of them.
 *
 * @param {string} path   Below the setup root with a leading slash, '' for
 *                        the root, or a full `/bettershield/v1/…` path.
 * @param {Object} data   The body, for a write.
 * @param {string} method GET or POST.
 * @return {Promise<Object>} The answer.
 */
export function request( path = '', data = undefined, method = data ? 'POST' : 'GET' ) {
	return apiFetch( {
		path: 0 === path.indexOf( '/bettershield/' ) ? path : ROOT + path,
		method,
		...( data ? { data } : {} ),
	} );
}

/**
 * A request's failure in words a person can act on.
 *
 * @param {*} error What apiFetch rejected with.
 * @return {string} A sentence.
 */
export function failureMessage( error ) {
	if ( error && 'string' === typeof error.message && error.message ) {
		return error.message;
	}

	return __( 'That did not complete. Nothing was changed; try again.', 'bettershield' );
}
