/**
 * Fix for the two sign-in limit findings (#1945).
 *
 * "Nothing is limiting sign-in attempts": Turn on pausing switches on
 * "Sign-in attempt limits" through login protection's own
 * save, so the settings ledger can undo it like any other save.
 *
 * "Two plugins limit sign-in attempts": Leave it to the other plugin saves
 * the same choice as the Quick Setup's security-plugins step, which turns
 * BetterShield's limit off and so asks for the password first.
 *
 * Login & Access stays a quieter second way, for anybody who wants to look
 * at the settings first.
 */

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../../nav';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import { focusIfLost } from '../../ui/focus';
import Button from '../../ui/Button';

/**
 * The other plugins' names, as one phrase.
 *
 * @param {Object} finding The finding.
 * @return {string} The names.
 */
function others( finding ) {
	const plugins = finding.evidence && finding.evidence.plugins;

	return Array.isArray( plugins ) ? plugins.join( ', ' ) : String( plugins || '' );
}

export default function LoginLimits( { finding } ) {
	const { saveLoginProtection, leaveLimitsToOther, runAudit, load, busy } = useStore();
	const [ said, setSaid ] = useState( '' );
	const overlap = 'login_limits_overlap' === finding.id;
	const working = isWorking( busy, overlap ? 'login-limits-leave' : 'login-protection' );
	const settings = tabUrl( 'bettershield-protect', 'login' );
	// The button held while it works lets focus go; the answer takes it.
	const status = useRef( null );

	useEffect( () => {
		if ( said ) {
			focusIfLost( status.current );
		}
	}, [ said, working ] );

	const done = ( words ) => {
		setSaid( words );
		announce( words );
		load( 'findings', { force: true } );
		load( 'overview', { force: true } );
	};

	const act = () =>
		overlap
			? leaveLimitsToOther( () => done( __( 'The other plugin now handles wrong-password limits. BetterShield’s limit is off.', 'bettershield' ) ) )
			: saveLoginProtection( { enabled: true, attempt_limit: true }, () => {
					done( __( 'Wrong-password limits are on. You can turn them off in Login & Access.', 'bettershield' ) );
					// The save does not run the checks; the audit closes the finding,
					// once the save's own action has let go.
					window.setTimeout( runAudit, 0 );
			  } );

	const name = others( finding );

	return (
		<>
			<p className="bs-ds-fix__text">
				{ overlap
					? sprintf(
							/* translators: %s: the names of other plugins that limit sign-in attempts. */
							__( 'BetterShield and %s both block people after wrong passwords. Keep just one, so you only have one place to unblock someone.', 'bettershield' ),
							name
					  )
					: __( 'After several wrong passwords, that visitor has to wait before trying again. People who type the right password are not affected.', 'bettershield' ) }
			</p>
			<div className="bs-ds-fix__actions">
				<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ act }>
					{ overlap
						? sprintf(
								/* translators: %s: the names of other plugins that limit sign-in attempts. */
								__( 'Leave It to %s', 'bettershield' ),
								name
						  )
						: __( 'Turn On Wrong-Password Limits', 'bettershield' ) }
				</Button>
				{ settings ? (
					<Button type="secondary" size="sm" trailing="arrow-right" href={ settings }>
						{ __( 'Open Login & Access', 'bettershield' ) }
					</Button>
				) : null }
			</div>
			{ overlap ? <p className="bs-ds-fix__note">{ __( 'This switches BetterShield’s own pause off, so it may ask for your password first.', 'bettershield' ) }</p> : null }
			{ said ? (
				<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
					{ said }
				</p>
			) : null }
		</>
	);
}

LoginLimits.kind = 'acts';
