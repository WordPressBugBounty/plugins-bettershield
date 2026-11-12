/**
 * Fix: an in-place panel on a finding, with the exact values and controls
 * its next step needs (#1954).
 *
 * "Apply Fix" is for a protection that turns on in one press. Most findings
 * need more than that: what is affected, a choice, a rule to paste. Each of
 * those registers a panel here by its finding's key, and the Findings report
 * and the Overview offer it on the finding while it is open, to somebody
 * who may manage the site. The panel is the same on both.
 *
 * Each panel declares what pressing it does, as its `kind` (#2430): `acts`
 * where a control in it changes the site, and only those are called Fix;
 * `guidance` where it only shows the way, called How to fix, or the panel's
 * own `word` where one names it better.
 */

import './Fix.css';

import { __, _x, sprintf } from '@wordpress/i18n';
import { mayManage, mayReadPosture } from '../../nav';
import { SHARED_FILES, sharedCodeHeld } from './defaults';
import AdminRename from './fixes/AdminRename';
import ConfigMode from './fixes/ConfigMode';
import ContentLinks from './fixes/ContentLinks';
import DomainRecords from './fixes/DomainRecords';
import DormantSuspend from './fixes/DormantSuspend';
import FilesAltered from './fixes/FilesAltered';
import HttpsAddress from './fixes/HttpsAddress';
import InactiveExtensions from './fixes/InactiveExtensions';
import LoginAddress from './fixes/LoginAddress';
import LoginLimits from './fixes/LoginLimits';
import OnePress, { ONE_PRESS } from './fixes/OnePress';
import PluginUpdates from './fixes/PluginUpdates';
import ProtectionRepair from './fixes/ProtectionRepair';
import ProxySetup from './fixes/ProxySetup';
import QuarantineSeal from './fixes/QuarantineSeal';
import RecoveryReadiness from './fixes/RecoveryReadiness';
import RestRoutes from './fixes/RestRoutes';
import ScheduledWork from './fixes/ScheduledWork';
import SecurityKeys from './fixes/SecurityKeys';
import ServerGuidance, { SERVER_GUIDANCE } from './fixes/ServerGuidance';
import SignInExtras, { SIGN_IN_EXTRAS } from './fixes/SignInExtras';
import SignInPage from './fixes/SignInPage';
import StaleAppPasswords from './fixes/StaleAppPasswords';
import StoreScripts from './fixes/StoreScripts';
import UnansweredEvents from './fixes/UnansweredEvents';
import WeakPasswordReset from './fixes/WeakPasswordReset';
import WorldWritable from './fixes/WorldWritable';

/** Each finding with a panel, by its key. */
export const PANELS = {
	files_altered: FilesAltered,
	quarantine_unsealed: QuarantineSeal,
	content_dirs_world_writable: WorldWritable,
	security_keys_weak: SecurityKeys,
	domain_mail_records: DomainRecords,
	login_url_shadows_content: LoginAddress,
	cron_schedule_stalled: ScheduledWork,
	recovery_readiness_incomplete: RecoveryReadiness,
	lockouts_not_running: ProxySetup,
	mixed_content_published: ContentLinks,
	site_not_https: HttpsAddress,
	login_attempts_unlimited: LoginLimits,
	login_limits_overlap: LoginLimits,
	cron_events_unanswered: UnansweredEvents,
	rest_surface_unreviewed: RestRoutes,
	admin_username_exists: AdminRename,
	application_passwords_stale: StaleAppPasswords,
	store_script_reads_cards: StoreScripts,
	privileged_account_dormant: DormantSuspend,
	passwords_below_policy: WeakPasswordReset,
	plugin_updates_available: PluginUpdates,
	vulnerabilities_known: PluginUpdates,
	inactive_extensions: InactiveExtensions,
	sign_in_page_cached: SignInPage,
	config_world_writable: ConfigMode,
	hardening_not_working: ProtectionRepair,
	// One press of an action that already has a route (#1944).
	...Object.fromEntries( ONE_PRESS.map( ( key ) => [ key, OnePress ] ) ),
	// One of BetterShield's own settings, changed as its screen would (#2564).
	...Object.fromEntries( SIGN_IN_EXTRAS.map( ( key ) => [ key, SignInExtras ] ) ),
	// How to fix, where the cause is on the server or with the host (#2430).
	...Object.fromEntries( SERVER_GUIDANCE.map( ( key ) => [ key, ServerGuidance ] ) ),
};

/*
 * Panels that also show what to do, or what is wrong, to somebody who may
 * only read the findings: the records to publish change nothing here. Their
 * actions stay with somebody who may manage the site.
 */
const FOR_READERS = [ 'domain_mail_records', 'recovery_readiness_incomplete' ];

/**
 * Whether this finding offers Fix to this reader now.
 *
 * @param {Object} finding The finding.
 * @return {boolean} Whether it does.
 */
export function hasFix( finding ) {
	// wp-config.php and the shared folders are a network administrator's on a network (#2639).
	if ( finding && SHARED_FILES.includes( finding.id ) && sharedCodeHeld() ) {
		return false;
	}

	return Boolean( finding && 'open' === finding.status && PANELS[ finding.id ] && ( mayManage() || ( FOR_READERS.includes( finding.id ) && mayReadPosture() ) ) );
}

/**
 * What the finding's panel declares pressing it does: `acts` or `guidance`.
 *
 * @param {Object} finding The finding.
 * @return {string} The kind.
 */
export function fixKind( finding ) {
	const Panel = finding && PANELS[ finding.id ];

	return Panel && 'guidance' === Panel.kind ? 'guidance' : 'acts';
}

/**
 * The words on the control that opens the panel: Fix only where it acts.
 *
 * @param {Object} finding The finding.
 * @return {string} The words.
 */
export function fixWord( finding ) {
	const Panel = PANELS[ finding.id ];

	if ( Panel && Panel.word ) {
		return Panel.word();
	}

	return 'guidance' === fixKind( finding ) ? __( 'How to Fix', 'bettershield' ) : __( 'Fix', 'bettershield' );
}

/**
 * The one-press fix's words: Apply Fix, or what pressing it does where the
 * generic words hide it. "Apply Fix" on a setting the owner may just prefer
 * read as repairing a fault (#2568).
 */
const APPLY_WORDS = {
	own_auto_updates_off: () => __( 'Turn On Auto-Updates', 'bettershield' ),
};

/**
 * @param {Object} finding The finding.
 * @return {string} The words on its one-press fix.
 */
export function applyWord( finding ) {
	const word = finding && APPLY_WORDS[ finding.id ];

	return word ? word() : __( 'Apply Fix', 'bettershield' );
}

/**
 * The control's name, which says which finding it is for: on a list every
 * one would read "Fix" otherwise.
 *
 * @param {Object} finding The finding.
 * @param {string} word    The control's words, when not the panel's own.
 * @return {string} The name.
 */
export function fixLabel( finding, word = fixWord( finding ) ) {
	return sprintf(
		/* translators: 1: a control's words, e.g. "Fix"; 2: what it is about, e.g. "Files no longer match the official copies". */
		_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
		word,
		finding.title
	);
}

/**
 * The finding's panel, or nothing where it has none.
 *
 * @param {Object} props
 * @param {Object} props.finding The finding.
 * @param {string} props.id      The panel's id, for the control that opens it.
 */
export function FixPanel( { finding, id } ) {
	if ( ! hasFix( finding ) ) {
		return null;
	}

	const Panel = PANELS[ finding.id ];

	return (
		<section className="bs-ds-fdetail__card bs-ds-fx-wide bs-ds-fix" id={ id } aria-label={ fixLabel( finding ) }>
			<p className="bs-ds-fdetail__head bs-ds-t12 bs-ds-m bs-ds-c2">{ fixWord( finding ) }</p>
			<div className="bs-ds-fdetail__body bs-ds-fix__body">
				<Panel finding={ finding } />
			</div>
		</section>
	);
}
