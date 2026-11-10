/**
 * Recovery readiness: the evidence that the way back in would work today,
 * with the limits of each check stated beside it.
 *
 * One card: "Check Recovery Options" in its header, each check a key-value row
 * whose mark says how it came out and whose note says why, when the checks
 * last ran, and the weekly email check as a switch.
 */

import './Readiness.css';

import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useStore } from '../../store';
import { linkTone, mailTone } from '../data/recovery';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import SettingRow, { Saved, Toggle } from '../ui/Setting';

/** The mark a check's answer is drawn with: a pass, something to do, or a check not asked to run. */
const MARKS = { good: 'ok', attention: 'warning', idle: 'info' };

/**
 * @param {Object} props
 * @param {Object} props.report The readiness report.
 */
export default function Readiness( { report } ) {
	const { checkRecoveryReadiness, setRecoveryEmailTests, busy, saved } = useStore();

	return (
		<ReadinessCard
			report={ report }
			onCheck={ checkRecoveryReadiness }
			onEmailChange={ setRecoveryEmailTests }
			working={ isWorking( busy, 'recovery-readiness', 'recovery-email-tests' ) }
			checking={ isWorking( busy, 'recovery-readiness' ) }
			savedKey={ saved?.key }
		/>
	);
}

function ReadinessCard( { report, onCheck, onEmailChange, working = false, checking = false, savedKey } ) {
	if ( ! report ) {
		return null;
	}

	const link = {
		available: __( 'You have a working recovery link. Keep your copy somewhere outside this site.', 'bettershield' ),
		missing: __( 'No recovery link yet. Generate one above.', 'bettershield' ),
		expired: __( 'The saved link has expired. Generate a replacement above.', 'bettershield' ),
		refused: __( 'The link email could not be sent. Generate a new link above and save the one shown.', 'bettershield' ),
	};
	const mail = {
		off: __( 'Weekly email checks are off, so mail delivery is not tested here.', 'bettershield' ),
		untested: __( 'No test yet for the current recipients. One runs with the next weekly send.', 'bettershield' ),
		accepted: __( 'The last test email was sent. Check your inbox to be sure it arrived.', 'bettershield' ),
		refused: __( 'The last test email couldn’t be sent. Your site may need an email (SMTP) plugin; ask your host.', 'bettershield' ),
		muted: __( 'Alerts are muted, so no test is sent. Resume them under Alerts.', 'bettershield' ),
		no_recipient: __( 'There is no valid alert recipient. Add one under Alerts.', 'bettershield' ),
		stale: __( 'The weekly test email didn’t go out on time. Your site’s background tasks may not be running; ask your host.', 'bettershield' ),
	};

	/*
	 * One row per check: what was checked, a mark saying how it came out, and
	 * the answer with its limit under it. The mark is never the only carrier
	 * of the result (every answer says it in words), so it is hidden from
	 * assistive technology.
	 */
	const checks = [
		{
			key: 'link',
			name: __( 'Recovery link', 'bettershield' ),
			tone: linkTone( report ),
			answer: link[ report.link ],
		},
		{
			key: 'codes',
			name: __( 'Recovery codes', 'bettershield' ),
			tone: report.offline_codes > 0 ? 'good' : 'attention',
			answer:
				report.offline_codes > 0
					? sprintf(
							/* translators: %d: unused printed recovery codes. */
							_n(
								'%d unused code remains. Check you still have the printed copy.',
								'%d unused codes remain. Check you still have the printed copy.',
								report.offline_codes,
								'bettershield'
							),
							report.offline_codes
					  )
					: report.offline_codes_issued
					? __( 'All used. Issue a new set above.', 'bettershield' )
					: __( 'None issued. Issue a set above.', 'bettershield' ),
		},
		{
			key: 'admin',
			name: __( 'Admin email address', 'bettershield' ),
			tone: report.administrators_with_email > 0 ? 'good' : 'attention',
			answer:
				( report.administrators_with_email > 0
					? __( 'At least one administrator has a valid email address.', 'bettershield' )
					: __( 'No administrator has a valid address. Check Users and the administration email.', 'bettershield' ) ) +
				( report.admin_scan_limited
					? ` ${ sprintf(
							/* translators: %d: how many administrator accounts were checked before the check stopped. */
							_n( 'Only the first %d administrator account was checked.', 'Only the first %d administrator accounts were checked.', report.admin_scan_limit, 'bettershield' ),
							report.admin_scan_limit
					  ) }`
					: '' ),
		},
		{
			key: 'mail',
			name: __( 'Alert emails arrive', 'bettershield' ),
			tone: mailTone( report ),
			// The test date is a sentence of its own, and none is given while
			// the check is off: a date under "off" read as a test just run.
			answer:
				mail[ report.mail ] +
				( report.mail_checked_at && 'off' !== report.mail
					? ` ${ sprintf(
							/* translators: %s: date and time of the last email test. */
							__( 'Last tested: %s.', 'bettershield' ),
							formatTime( report.mail_checked_at )
					  ) }`
					: '' ),
		},
	];

	return (
		<Card className="bs-ds-readiness" aria-labelledby="bs-ds-readiness-title">
			<CardHead icon="clipboard-check" id="bs-ds-readiness-title" title={ __( 'Recovery check', 'bettershield' ) }>
				<Button type="secondary" size="sm" disabled={ working } isBusy={ checking } onClick={ onCheck }>
					{ __( 'Check Recovery Options', 'bettershield' ) }
				</Button>
			</CardHead>

			<div className="bs-ds-readiness__body">
				{ /* The weekly email is promised only while it is on: the row
				     below said off under a line that said it goes out (#2574). */ }
				<p className="bs-ds-readiness__intro">
					{ report.email_tests
						? __( 'Checked every day, without using up your link or codes. A test email goes to your alert recipients once a week.', 'bettershield' )
						: __( 'Checked every day, without using up your link or codes.', 'bettershield' ) }
				</p>

				<KeyValues className="bs-ds-readiness__checks">
					{ checks.map( ( check ) => (
						<KeyValue key={ check.key } label={ check.name } status={ MARKS[ check.tone ] } value="" note={ check.answer } />
					) ) }
				</KeyValues>

				{ /* What a check just did, and when the checks last ran. "Saved."
				     for the switch is said beside the switch. */ }
				<p className="bs-ds-readiness__when" role="status">
					{ 'recovery-readiness' === savedKey ? __( 'Readiness checked.', 'bettershield' ) : '' }{ ' ' }
					{ report.checked_at
						? sprintf( /* translators: %s: the date and time of the last check. */ __( 'Last checked %s.', 'bettershield' ), formatTime( report.checked_at ) )
						: __( 'Not checked yet. Press Check Recovery Options.', 'bettershield' ) }
					{ /* Overdue only once there was a first check: on day one it read as a fault (#2412). */ }
					{ report.overdue && report.checked_at ? ` ${ __( 'The daily check is overdue.', 'bettershield' ) }` : '' }
				</p>
			</div>

			{ /* Switch first, as every other Protection row has it (#2574). */ }
			<SettingRow
				id="bs-ds-readiness-email"
				title={ __( 'Send a weekly recovery email check', 'bettershield' ) }
				about={ __( 'Checks that alert emails reach your recipients.', 'bettershield' ) }
				control={ <Saved forKey="recovery-email-tests" /> }
				lead={
					<Toggle
						checked={ report.email_tests }
						disabled={ working }
						onChange={ ( event ) => onEmailChange( Boolean( event && event.target ? event.target.checked : event ) ) }
						labelledBy="bs-ds-readiness-email"
						describedBy="bs-ds-readiness-email-about"
					/>
				}
			/>
		</Card>
	);
}
