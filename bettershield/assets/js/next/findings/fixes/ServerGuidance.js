/**
 * How to fix, for each finding whose cause is on the server, with the host
 * or in a choice only a person makes (#2430): the words the Guidance panel
 * draws, from the finding's own evidence.
 *
 * The site's address, for the message to the host, is read from the route
 * that also says whether a look asked for earlier is still running.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../../nav';
import { formatTime } from '../../../store';
import Guidance from './Guidance';

/** The findings answered here. */
export const SERVER_GUIDANCE = [
	'certificate_expiring',
	'disk_space_low',
	'php_end_of_life',
	'default_table_prefix',
	'admin_user_id_one',
	'backup_plugin_not_visible',
	'plugins_directory_unclaimed',
	'alerts_undeliverable',
	'network_passkey_no_way_back',
];

/** The same last step, worded once. */
const thenCheck = () => __( 'When that is done, press Check Again.', 'bettershield' );

/**
 * A day, said in the reader's language.
 *
 * @param {string} day A date, YYYY-MM-DD.
 * @return {string} The date.
 */
function dayText( day ) {
	const date = new Date( `${ day }T00:00:00Z` );

	return Number.isNaN( date.getTime() ) ? String( day ) : date.toLocaleDateString( undefined, { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' } );
}

/** Each finding's words, from its evidence and the site's address. */
export const GUIDES = {
	certificate_expiring: ( evidence, address ) => {
		const days = Number( evidence.days_left );
		const expired = Number.isFinite( days ) && days < 0;
		const left = Math.max( 0, Number.isFinite( days ) ? days : 0 );

		return {
			what: expired
				? __( 'The site’s security certificate has expired, so browsers warn visitors away from every page.', 'bettershield' )
				: sprintf(
						/* translators: %d: days until the certificate expires. */
						_n( 'The site’s security certificate expires in %d day. After that, browsers warn visitors away from every page.', 'The site’s security certificate expires in %d days. After that, browsers warn visitors away from every page.', left, 'bettershield' ),
						left
				  ),
			where: __( 'This is fixed outside WordPress, on the server. Your hosting provider, or whoever issued the certificate, renews it.', 'bettershield' ),
			steps: [
				__( 'In your hosting panel, open the SSL or certificates section. Many hosts renew free certificates on their own; check that automatic renewal is on.', 'bettershield' ),
				__( 'If you bought the certificate from another company, renew it there, then install the new one on the server.', 'bettershield' ),
				__( 'Not sure who handles it? Send your hosting provider the message below.', 'bettershield' ),
				__( 'When it is renewed, press Check Again. The certificate is read again in the background.', 'bettershield' ),
			],
			message: expired
				? sprintf(
						/* translators: %s: the site's address, e.g. shop.example.com. */
						__( 'Hello. The security certificate for %s has expired. Could you renew it, and make sure it renews automatically from now on? Thank you.', 'bettershield' ),
						address
				  )
				: sprintf(
						/* translators: 1: the site's address, e.g. shop.example.com; 2: days until the certificate expires. */
						_n(
							'Hello. The security certificate for %1$s expires in %2$d day. Could you renew it, and make sure it renews automatically from now on? Thank you.',
							'Hello. The security certificate for %1$s expires in %2$d days. Could you renew it, and make sure it renews automatically from now on? Thank you.',
							left,
							'bettershield'
						),
						address,
						left
				  ),
		};
	},

	disk_space_low: ( evidence, address ) => ( {
		what: __( 'The disk this site saves to is almost full. When it fills, uploads, updates and the activity log stop working.', 'bettershield' ),
		where: __( 'Disk space comes with your hosting plan, outside WordPress. You can free some yourself, and your hosting provider can add more.', 'bettershield' ),
		steps: [
			__( 'Remove backup files you have already copied somewhere else. Backup plugins often keep old copies in wp-content.', 'bettershield' ),
			__( 'Delete media, plugins and themes you no longer use, and empty any cache.', 'bettershield' ),
			__( 'Ask your hosting provider how much space your plan has, and whether it can have more.', 'bettershield' ),
			thenCheck(),
		],
		message: sprintf(
			/* translators: %s: the site's address, e.g. shop.example.com. */
			__( 'Hello. My site %s is almost out of disk space. Could you tell me what is using the space, and whether my plan can have more? Thank you.', 'bettershield' ),
			address
		),
	} ),

	php_end_of_life: ( evidence, address ) => ( {
		what: sprintf(
			/* translators: 1: a PHP version, e.g. 8.0; 2: a date. */
			__( 'This site runs PHP %1$s, which stopped receiving security fixes on %2$s.', 'bettershield' ),
			evidence.branch,
			dayText( evidence.eol_since )
		),
		where: __( 'PHP is the software on the server that runs WordPress. You change it in your hosting panel, or your hosting provider does.', 'bettershield' ),
		steps: [
			__( 'Make a backup of the site first.', 'bettershield' ),
			__( 'In your hosting panel, find the PHP version setting, and choose the newest version your plugins and theme support.', 'bettershield' ),
			__( 'Open a few pages and sign in to check everything works. If something breaks, switch back and contact that plugin’s author.', 'bettershield' ),
			thenCheck(),
		],
		message: sprintf(
			/* translators: 1: the site's address, e.g. shop.example.com; 2: a PHP version, e.g. 8.0. */
			__( 'Hello. My site %1$s runs PHP %2$s, which no longer receives security fixes. Could you move it to a supported version, or tell me how? Thank you.', 'bettershield' ),
			address,
			evidence.branch
		),
	} ),

	default_table_prefix: ( evidence, address ) => ( {
		// That it is no risk alone is said once, in Why it matters, and the
		// row already says low severity (#2819).
		what: __( 'The database tables use wp_, the name every WordPress site starts with.', 'bettershield' ),
		where: __( 'Renaming database tables is done outside WordPress, and a mistake can take the site offline. A developer or your hosting provider usually does it.', 'bettershield' ),
		steps: [
			__( 'Plan it for when the site is next moved or rebuilt, with a full backup first.', 'bettershield' ),
			__( 'Whoever does it changes the prefix in wp-config.php and renames every table, plus the settings that carry the old name.', 'bettershield' ),
			thenCheck(),
		],
		message: sprintf(
			/* translators: %s: the site's address, e.g. shop.example.com. */
			__( 'Hello. My site %s uses the default wp_ database table prefix. When the site is next moved or rebuilt, could you change it, with a backup first? Thank you.', 'bettershield' ),
			address
		),
	} ),

	admin_user_id_one: ( evidence, address, finding ) => ( {
		what: __( 'User ID 1, the first account made on this site, is still an administrator. Automated tools try that account first.', 'bettershield' ),
		outside: false,
		where: __( 'You fix this in WordPress, on the Users screen. BetterShield does not create or delete accounts for you.', 'bettershield' ),
		steps: [
			__( 'Create a new administrator with its own email address, then sign in as that account.', 'bettershield' ),
			__( 'Delete user ID 1. When WordPress asks, give its content to the new account.', 'bettershield' ),
			__( 'If user ID 1 is still needed, change its role to one below administrator instead.', 'bettershield' ),
			thenCheck(),
		],
		links: finding.control && finding.control.url ? [ { label: finding.control.label, href: finding.control.url } ] : [],
	} ),

	backup_plugin_not_visible: ( evidence, address ) => ( {
		what: __( 'BetterShield found no active backup plugin it recognizes. Your host may still back up the site, but this check cannot see that.', 'bettershield' ),
		where: __( 'Backups often come from your hosting provider, outside WordPress. Ask them first; a backup plugin is the other way.', 'bettershield' ),
		steps: [
			__( 'Ask your hosting provider whether they back up this site, how often, where the copies are kept, and how to restore one.', 'bettershield' ),
			__( 'If their backups suit you, choose “I manage this myself” from its menu.', 'bettershield' ),
			__( 'If not, install a backup plugin that keeps copies off this server, and try restoring one.', 'bettershield' ),
			thenCheck(),
		],
		message: sprintf(
			/* translators: %s: the site's address, e.g. shop.example.com. */
			__( 'Hello. Do you back up my site %s? How often, how long are copies kept, and how do I restore one? Thank you.', 'bettershield' ),
			address
		),
	} ),

	plugins_directory_unclaimed: ( evidence, address ) => {
		const files = Array.isArray( evidence.files ) ? evidence.files : [];
		const total = Number( evidence.total ) || files.length;
		const named = files
			.slice( 0, 5 )
			.map( ( item ) => ( item && item.path ) || String( item ) )
			.join( ', ' );

		return {
			what: sprintf(
				/* translators: %d: how many items no plugin claims. */
				_n(
					'The plugins folder holds %d item that no installed plugin claims. WordPress does not show it, update it or remove it.',
					'The plugins folder holds %d items that no installed plugin claims. WordPress does not show them, update them or remove them.',
					total,
					'bettershield'
				),
				total
			),
			where: __( 'These are reached outside WordPress, with your host’s file manager or SFTP. Your hosting provider or developer can say whether they put them there.', 'bettershield' ),
			steps: [
				__( 'Look at each item listed under Evidence.', 'bettershield' ),
				__( 'Ask your hosting provider or developer whether any of them are theirs.', 'bettershield' ),
				__( 'Download a copy of each one nobody claims, then remove it with your host’s file manager or SFTP.', 'bettershield' ),
				thenCheck(),
			],
			message: named
				? sprintf(
						/* translators: 1: the site's address, e.g. shop.example.com; 2: file and folder names. */
						__( 'Hello. The plugins folder on my site %1$s holds items no installed plugin claims: %2$s. Did you or your systems put any of them there? Thank you.', 'bettershield' ),
						address,
						named
				  )
				: '',
		};
	},

	alerts_undeliverable: ( evidence, address ) => ( {
		what: evidence.refused_at
			? sprintf(
					/* translators: %s: a date and time. */
					__( 'The mail server refused BetterShield’s last alert, sent %s. Until mail is delivered again, security alerts do not reach you.', 'bettershield' ),
					formatTime( evidence.refused_at )
			  )
			: __( 'The mail server refused BetterShield’s last alert. Until mail is delivered again, security alerts do not reach you.', 'bettershield' ),
		where: __( 'Whether this server may send mail is set up by your hosting provider, outside WordPress. Many sites send through an SMTP plugin and a mail service instead.', 'bettershield' ),
		steps: [
			__( 'In Settings › Alerts, check that the alert addresses are right.', 'bettershield' ),
			__( 'Ask your hosting provider whether this server may send mail, or set up an SMTP plugin with a mail service.', 'bettershield' ),
			__( 'Then press Send a Test Alert. The finding closes once a message is accepted.', 'bettershield' ),
		],
		message: sprintf(
			/* translators: %s: the site's address, e.g. shop.example.com. */
			__( 'Hello. My site %s cannot send email: the mail server refuses its messages. Can this server send mail, or should I use an outside mail service? Thank you.', 'bettershield' ),
			address
		),
		links: tabUrl( 'bettershield-settings', 'alerts' ) ? [ { label: __( 'Open Alert Settings', 'bettershield' ), href: tabUrl( 'bettershield-settings', 'alerts' ) } ] : [],
		checkLabel: __( 'Send a Test Alert', 'bettershield' ),
	} ),

	network_passkey_no_way_back: ( evidence ) => {
		const count = Number( evidence.count ) || 0;

		return {
			what: sprintf(
				/* translators: %d: how many sites have no way back. */
				_n(
					'%d site under the network’s passkey-only policy has no recovery link or recovery codes. Anyone there who loses a passkey needs you to get back in.',
					'%d sites under the network’s passkey-only policy have no recovery link or recovery codes. Anyone there who loses a passkey needs you to get back in.',
					count,
					'bettershield'
				),
				count
			),
			outside: false,
			where: __( 'You fix this in WordPress, on each site listed. That site’s administrator or a network administrator can do it.', 'bettershield' ),
			steps: [
				__( 'On each site listed under Evidence, open BetterShield › Protection › Recovery.', 'bettershield' ),
				__( 'Make a recovery link or print backup codes, and keep them somewhere safe away from the site.', 'bettershield' ),
				__( 'Then press Check Again here, on the main site.', 'bettershield' ),
			],
		};
	},
};

/**
 * @param {Object} props
 * @param {Object} props.finding The finding.
 */
export default function ServerGuidance( { finding } ) {
	const [ state, setState ] = useState( null );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: `/bettershield/v1/findings/${ finding.id }/guidance` } ).then(
			( answer ) => alive && setState( answer ),
			// Unread, the message names the address this screen was opened on.
			() => alive && setState( { address: window.location.hostname, checking: false } )
		);

		return () => {
			alive = false;
		};
	}, [ finding.id ] );

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading what the check found…', 'bettershield' ) }</p>;
	}

	const guide = GUIDES[ finding.id ]( finding.evidence || {}, state.address || window.location.hostname, finding );

	return <Guidance findingId={ finding.id } checking={ Boolean( state.checking ) } { ...guide } />;
}

ServerGuidance.kind = 'guidance';
