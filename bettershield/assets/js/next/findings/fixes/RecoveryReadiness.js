/**
 * Fix for "Some recovery options need attention" (#2204).
 *
 * Only the checks that failed, each with the step that fixes it: a new
 * recovery link or a set of printed codes (the same rows Protection › Recovery
 * draws, which say first that the old one stops working and show the new
 * one once), the Users screen where an administrator's address is added,
 * the alert setting that has to change, or the test email sent now. Somebody
 * who may only read the findings sees the checks and none of the steps.
 *
 * What BetterShield does in one press is set apart from what the owner does
 * elsewhere, which is marked as theirs (#2430).
 */

import { useRef } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { mayManage, sectionUrl, tabUrl } from '../../../nav';
import { formatTime, isWorking, useResource, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import { RecoveryCodes, RecoveryLink } from '../../protect/Recovery';
import Badge from '../../ui/Badge';
import { focusIfLost } from '../../ui/focus';
import Button from '../../ui/Button';

/** What each failed check is, in words. */
const SAID = {
	link: {
		missing: () => __( 'There is no recovery link.', 'bettershield' ),
		expired: () => __( 'The recovery link has expired.', 'bettershield' ),
		refused: () => __( 'The recovery link’s email could not be delivered.', 'bettershield' ),
	},
	mail: {
		refused: () => __( 'The weekly email check was refused by the mail server.', 'bettershield' ),
		stale: () => __( 'The weekly email check has not passed in over a week.', 'bettershield' ),
		untested: () => __( 'The weekly email check has not run yet.', 'bettershield' ),
		muted: () => __( 'Email alerts are muted, so the recovery email would not be sent.', 'bettershield' ),
		no_recipient: () => __( 'Email alerts have no recipient, so the recovery email has nowhere to go.', 'bettershield' ),
	},
};

/**
 * The Users screen, filtered to administrators, in this site's admin: the
 * plugin's own screens' address with its page swapped for the users list.
 *
 * @return {string} The address.
 */
function usersUrl() {
	return sectionUrl( 'bettershield' ).replace( /admin\.php.*$/, '' ) + 'users.php?role=administrator';
}

/** The mark on a step the owner takes outside this panel. */
const yours = () => <Badge className="bs-ds-fix__mark" icon="user">{ __( 'You do this', 'bettershield' ) }</Badge>;

export default function RecoveryReadiness() {
	const { checkRecoveryReadiness, busy } = useStore();
	const overview = useResource( 'overview' ).resource;
	const data = overview.data || {};
	const report = data.recovery_readiness;
	const manage = mayManage();
	const checking = isWorking( busy, 'recovery-readiness' );
	/*
	 * A step once shown stays while the panel is open. A new link or set of
	 * codes is shown once, by the row that asked for it, and the answer that
	 * carries it also says the check now passes: dropping the row then would
	 * retire the old link and never show the new one.
	 */
	const shown = useRef( new Set() );
	// Check recovery options, where focus goes once the test email's step,
	// and the button pressed in it, has gone.
	const again = useRef( null );

	/*
	 * The overview is in but carries no recovery checks: a client view sends
	 * none, so the panel says who sees them rather than reading forever.
	 */
	if ( ! report && overview.data ) {
		return <p className="bs-ds-fix__note">{ __( 'Ask a site administrator to complete these steps.', 'bettershield' ) }</p>;
	}

	if ( ! report ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the recovery checks…', 'bettershield' ) }</p>;
	}

	const linkWorks = 'available' === report.link;
	const codes = Math.max( 0, Number( report.offline_codes ) || 0 );
	const mailFix = [ 'muted', 'no_recipient' ].includes( report.mail );
	const mailCheck = [ 'refused', 'stale', 'untested' ].includes( report.mail );
	const steps = [];

	// Whether a step is drawn: failing now, or failing when it was first drawn.
	const draws = ( key, failing ) => {
		if ( failing ) {
			shown.current.add( key );
		}

		return failing || shown.current.has( key );
	};

	if ( draws( 'link', ! linkWorks ) ) {
		steps.push(
			<li key="link" className="bs-ds-fix__record">
				{ ! linkWorks ? <p className="bs-ds-fix__text">{ ( SAID.link[ report.link ] || SAID.link.missing )() }</p> : null }
				{ manage ? <RecoveryLink exists={ 'missing' !== report.link } mailed={ 'refused' === report.link ? false : null } /> : null }
			</li>
		);
	}

	// Printed codes are a second way back, asked for only where the link
	// does not work either: that is when the site has none at all.
	if ( draws( 'codes', ! linkWorks && 0 === codes ) ) {
		steps.push(
			<li key="codes" className="bs-ds-fix__record">
				{ ! linkWorks && 0 === codes ? <p className="bs-ds-fix__text">{ __( 'You also have no unused backup codes, so you have no way back in if you get locked out.', 'bettershield' ) }</p> : null }
				{ manage ? <RecoveryCodes remaining={ 0 } issued={ Boolean( report.offline_codes_issued ) } /> : null }
			</li>
		);
	}

	if ( 0 === Number( report.administrators_with_email ) ) {
		steps.push(
			<li key="admins" className="bs-ds-fix__record">
				{ yours() }
				<p className="bs-ds-fix__text">{ __( 'No administrator has an email address to be reached at. Add one to an administrator’s profile; BetterShield does not choose or change accounts.', 'bettershield' ) }</p>
				{ manage ? (
					<div className="bs-ds-fix__actions">
						<Button type="secondary" size="sm" trailing="arrow-right" href={ usersUrl() }>
							{ __( 'Open the Administrators', 'bettershield' ) }
						</Button>
					</div>
				) : null }
			</li>
		);
	}

	if ( mailFix ) {
		steps.push(
			<li key="mail" className="bs-ds-fix__record">
				{ yours() }
				<p className="bs-ds-fix__text">{ SAID.mail[ report.mail ]() }</p>
				{ manage ? (
					<div className="bs-ds-fix__actions">
						<Button type="secondary" size="sm" trailing="arrow-right" href={ tabUrl( 'bettershield-settings', 'alerts' ) }>
							{ 'muted' === report.mail ? __( 'Unmute Email Alerts', 'bettershield' ) : __( 'Add an Alert Recipient', 'bettershield' ) }
						</Button>
					</div>
				) : null }
			</li>
		);
	}

	const check = () => {
		announce( __( 'Checking the way back in. The finding updates when it is done.', 'bettershield' ) );
		Promise.resolve( checkRecoveryReadiness() ).then( () => focusIfLost( again.current ) );
	};

	if ( mailCheck || report.overdue ) {
		steps.push(
			<li key="check" className="bs-ds-fix__record">
				<p className="bs-ds-fix__text">
					{ mailCheck ? SAID.mail[ report.mail ]() : null }
					{ mailCheck && report.overdue ? ' ' : null }
					{ report.overdue ? __( 'Your recovery options haven’t been checked recently.', 'bettershield' ) : null }
				</p>
				{ /* The readiness check sends the test email itself whenever
				     one is due, which every one of these states is. */ }
				{ manage && mailCheck ? (
					<>
						<p className="bs-ds-fix__note">{ __( 'Sends one test email to the alert addresses, then checks every recovery option again.', 'bettershield' ) }</p>
						<div className="bs-ds-fix__actions">
							<Button type="primary" size="sm" isBusy={ checking } disabled={ checking } onClick={ check }>
								{ __( 'Send a Test Email', 'bettershield' ) }
							</Button>
						</div>
					</>
				) : null }
			</li>
		);
	}

	return (
		<>
			{ steps.length ? (
				<ul className="bs-ds-fix__list">{ steps }</ul>
			) : (
				<p className="bs-ds-fix__text">{ __( 'Every check passed when this was last read. Check again to close the finding.', 'bettershield' ) }</p>
			) }
			{ manage && ! mailCheck ? (
				<div className="bs-ds-fix__actions">
					<Button ref={ again } type={ report.overdue ? 'primary' : 'secondary' } size="sm" isBusy={ checking } disabled={ checking } onClick={ check }>
						{ __( 'Check Recovery Options', 'bettershield' ) }
					</Button>
				</div>
			) : null }
			{ report.checked_at ? (
				<p className="bs-ds-fix__note">
					{ sprintf(
						/* translators: %s: a date and time. */
						__( 'Last checked %s.', 'bettershield' ),
						formatTime( report.checked_at )
					) }
				</p>
			) : null }
		</>
	);
}

RecoveryReadiness.kind = 'acts';
