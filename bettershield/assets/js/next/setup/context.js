/**
 * What every step reads: the setup's state, where it is, and the one way to
 * write to the site.
 */

import { createContext, useContext } from '@wordpress/element';

export const SetupContext = createContext( null );

/**
 * @return {Object} The setup's state and actions.
 */
export function useSetup() {
	return useContext( SetupContext );
}
