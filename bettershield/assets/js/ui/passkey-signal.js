/**
 * Tell the browser's passkey store which of this account's passkeys the site
 * still accepts.
 *
 * A passkey removed here stays in the person's password manager, keeps being
 * offered at sign-in, and then fails. Browsers that support the WebAuthn
 * Signal API take this list and stop offering the rest. Elsewhere nothing
 * happens, and nothing about the screen depends on it.
 *
 * Sent each time the account's own passkey list is read: after a passkey is
 * removed the list is read again, so the removed one is no longer in it.
 *
 * @param {?{rpId: string, userId: string, accepted: string[]}} signal The server's list, or null where passkeys are off.
 * @return {boolean} Whether the browser was told.
 */
export function signalAccepted( signal ) {
	const credential = typeof window !== 'undefined' ? window.PublicKeyCredential : undefined;

	if ( ! signal || ! credential || 'function' !== typeof credential.signalAllAcceptedCredentials ) {
		return false;
	}

	// A promise the screen never waits on: a browser that declines, or a
	// store that has no passkey for this account, is not an error to show.
	Promise.resolve()
		.then( () =>
			credential.signalAllAcceptedCredentials( {
				rpId: signal.rpId,
				userId: signal.userId,
				allAcceptedCredentialIds: Array.isArray( signal.accepted ) ? signal.accepted : [],
			} )
		)
		.catch( () => {} );

	return true;
}
