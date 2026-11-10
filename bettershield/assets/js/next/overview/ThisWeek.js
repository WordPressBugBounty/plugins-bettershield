/**
 * "This week" (design frame 27:53129): three equal cells, a label row and a
 * value each, drawn by the shared Stat group.
 */

import { __ } from '@wordpress/i18n';
import Stats from '../ui/Stats';

const count = ( value ) => ( Number( value ) || 0 ).toLocaleString();

export default function ThisWeek( { receipts, protection } ) {
	const week = receipts || {};
	// The count every screen says. The panel is only read by someone who can
	// manage protections; anyone else gets the count the receipts carry.
	const on = protection && protection.count ? protection.count.on : week.hardening_active;

	return (
		<Stats
			tiles={ [
				{ key: 'audits', icon: 'refresh-cw', label: __( 'Audits run this week', 'bettershield' ), value: count( week.audits_week ) },
				{ key: 'hardening', icon: 'shield', label: __( 'Protections on', 'bettershield' ), value: count( on ) },
				{ key: 'events', icon: 'activity', label: __( 'Activity recorded this week', 'bettershield' ), value: count( week.events_week ) },
			] }
		/>
	);
}
