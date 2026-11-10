/**
 * Every hardening item one screen draws, a card per group: the group's name
 * with its icon tile and how many of its items are on, then a row per item.
 *
 * The groups arrive in the order they are meant to be read, which is the order
 * the registry declares them in, and say which screen draws them: a taxonomy
 * the server owns, so the two ends cannot disagree about what a group is
 * called or where it is read.
 */

import { __, sprintf } from '@wordpress/i18n';
import { brand } from '../../nav';
import { useResource } from '../../store';
import Alert from '../ui/Alert';
import Badge from '../ui/Badge';
import { SettingsCard } from '../ui/Setting';
import Skeleton, { CardBone } from '../ui/Skeleton';
import { EmptyState, Resource } from '../ui/States';
import HardeningRow from './HardeningRow';

/** Each group's tile, by its key in the registry. */
const GROUP_ICONS = {
	sign_in: 'log-in',
	accounts: 'users',
	exposure: 'eye',
	execution: 'terminal',
	browser: 'globe',
};

/**
 * "2 of 4 on": how many of a list of items are on.
 *
 * @param {Array} list The items.
 * @return {string} The count.
 */
export function itemsOn( list ) {
	return sprintf(
		/* translators: 1: how many items in this group are applied, 2: how many there are. */
		__( '%1$d of %2$d on', 'bettershield' ),
		list.filter( ( entry ) => entry.active || entry.in_force_elsewhere ).length,
		list.length
	);
}

/**
 * The items a screen draws, by group, in the registry's order.
 *
 * @param {Object} data   The hardening payload.
 * @param {string} screen The screen whose groups are wanted.
 * @return {Array<[string, Object, Array]>} Each group's key, the group, and its items; empty groups left out.
 */
export function groupsFor( data, screen ) {
	const items = ( data && data.items ) || [];

	return Object.entries( ( data && data.groups ) || {} )
		.filter( ( [ , group ] ) => group.screen === screen )
		.map( ( [ key, group ] ) => [ key, group, items.filter( ( item ) => item.group === key ) ] )
		.filter( ( [ , , list ] ) => list.length );
}

/**
 * A note two or more of a screen's items carry word for word, about an item
 * that is still offered (a server that could not say whether it reads
 * .htaccess): said once above the cards, with a chip on each row it is about.
 *
 * @param {Array} items The screen's items.
 * @return {string} The note, or an empty string.
 */
export function sharedNote( items ) {
	const counts = {};

	items
		.filter( ( item ) => false !== item.available && item.availability_note )
		.forEach( ( item ) => {
			counts[ item.availability_note ] = ( counts[ item.availability_note ] || 0 ) + 1;
		} );

	return Object.keys( counts ).find( ( note ) => counts[ note ] > 1 ) || '';
}

/**
 * The cards standing in for themselves while the registry is read.
 *
 * @param {Object} props
 * @param {Array}  props.cards How many rows each card holds.
 */
export function HardeningCardsBone( { cards = [ 3 ] } ) {
	const widths = [ '45%', '60%', '38%', '52%' ];

	return (
		<Skeleton label={ __( 'Loading the protections…', 'bettershield' ) }>
			{ cards.map( ( rows, card ) => (
				<CardBone key={ card } rows={ Array.from( { length: rows }, ( ignored, row ) => widths[ ( card + row ) % widths.length ] ) } toggle />
			) ) }
		</Skeleton>
	);
}

/**
 * @param {Object} props
 * @param {string} props.screen  Which screen's groups to draw.
 * @param {string} props.empty   What to say when the screen has no items; nothing is drawn without it.
 * @param {Array}  props.loading How many rows each card's stand-in holds.
 * @param {string} props.undoNote What is said once above the cards about undo, while something is on.
 */
export default function HardeningCards( { screen, empty = '', loading = [ 3 ], undoNote = '' } ) {
	const { resource, reload } = useResource( 'hardening' );

	return (
		<Resource resource={ resource } onRetry={ reload } loading={ <HardeningCardsBone cards={ loading } /> }>
			{ ( data ) => {
				const shown = groupsFor( data, screen );

				if ( ! shown.length ) {
					return empty ? (
						<SettingsCard icon="shield" title={ __( 'Protect', 'bettershield' ) }>
							<EmptyState>{ empty }</EmptyState>
						</SettingsCard>
					) : null;
				}

				const note = sharedNote( shown.flatMap( ( [ , , list ] ) => list ) );
				// Said once for the screen rather than after each item that is
				// on (#2606); an item undo can't fully reach still says so.
				const undoable = shown.some( ( [ , , list ] ) => list.some( ( item ) => item.active && false !== item.reversible ) );

				return (
					<>
						{ undoable ? <p className="bs-ds-hcards__note">{ undoNote || __( 'Every protection here can be undone.', 'bettershield' ) }</p> : null }
						{ /* Said for the rows the chip marks, rather than in the words
						     each row would use on its own (#2821). */ }
						{ note ? (
							<Alert
								layout="default"
								tone="warning"
								title={ __( 'Some protections may not work on this server', 'bettershield' ) }
								desc={ sprintf(
									/* translators: %s: the plugin's name. */
									__( 'Your server may ignore the file %s writes. The protections marked “May not work on this server” depend on it.', 'bettershield' ),
									brand
								) }
							/>
						) : null }
						{ shown.map( ( [ key, group, list ] ) => (
							<SettingsCard key={ key } icon={ GROUP_ICONS[ key ] || 'shield' } title={ group.title } trailing={ <Badge>{ itemsOn( list ) }</Badge> }>
								{ list.map( ( item ) => (
									<HardeningRow key={ item.id } item={ item } sharedNote={ note } />
								) ) }
							</SettingsCard>
						) ) }
					</>
				);
			} }
		</Resource>
	);
}
