/**
 * What changed while the reader was away.
 *
 * Under the findings and the activity, and only when there is something in
 * it. The score is what the screen exists to answer and the fixes are what to
 * do about it; this is the answer to "what happened", which is read after
 * both. On most visits it is absent entirely.
 *
 * Deliberately not a warning. Everything in it is something somebody did on
 * purpose; the point is that the reader may not have been the somebody, and a
 * red panel would say the site is under attack when what happened is usually
 * a colleague activating a plugin.
 */

import './SinceLastVisit.css';

import { useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { sectionUrl, tabUrl } from '../../nav';
import { whenPhrase } from '../../ui/when';
import { scopePhrase } from '../../agents/phrases';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Table, { Cell, Row, TitleMeta, WholeRow } from '../ui/Table';

/** How many changes are listed before the rest wait behind "Show More". */
export const FIRST = 5;

const MORE_ID = 'bs-ds-since-more';

/**
 * Files that stopped matching their official copies, as one row where there
 * is more than one: eight rows that said the same thing pushed everything
 * else under Show more, and File changes lists each one anyway.
 *
 * @param {Array} changes The block's changes, newest first.
 * @return {Array} The same, with the file rows as one, where the first of them stood.
 */
export function grouped( changes ) {
	const files = changes.filter( ( change ) => 'file_changed' === change.type );

	if ( files.length < 2 ) {
		return changes;
	}

	const actors = new Set( files.map( ( change ) => change.actor ) );

	return changes.reduce( ( out, change ) => {
		if ( 'file_changed' !== change.type ) {
			out.push( change );
		} else if ( change === files[ 0 ] ) {
			out.push( { id: `files-${ change.id }`, files: files.length, actor: 1 === actors.size ? change.actor : '', occurred_at: change.occurred_at } );
		}

		return out;
	}, [] );
}

function ChangeRow( { change } ) {
	if ( change.files ) {
		return (
			<Row>
				<Cell>
					<TitleMeta
						title={ sprintf(
							/* translators: %d: how many files no longer match their official copies. */
							_n( '%d file changed', '%d files changed', change.files, 'bettershield' ),
							change.files
						) }
						meta={
							<a href={ tabUrl( 'bettershield-activity', 'files' ) }>{ __( 'View in File Changes', 'bettershield' ) }</a>
						}
					/>
				</Cell>
				<Cell>
					<span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2 bs-ds-since__who">{ change.actor }</span>
				</Cell>
				<Cell>
					<span className="bs-ds-t12 bs-ds-r bs-ds-c2">{ whenPhrase( change.occurred_at ) }</span>
				</Cell>
			</Row>
		);
	}

	// A title or a login reads as words; a file path or a version breaks
	// anywhere rather than widening the card.
	const meta =
		change.subject || change.scope ? (
			<>
				{ change.subject ? <span className={ `bs-ds-since__subject${ change.subject_is_name ? ' is-words' : '' }` }>{ change.subject }</span> : null }
				{ /* What an assistant that was let in may do. */ }
				{ change.scope ? <span className="bs-ds-since__subject is-words">{ scopePhrase( change.scope ) }</span> : null }
			</>
		) : null;

	return (
		<Row>
			<Cell>
				<TitleMeta title={ change.label } meta={ meta } />
			</Cell>
			<Cell>
				<span className="bs-ds-t12 bs-ds-lead bs-ds-r bs-ds-c2 bs-ds-since__who">{ change.actor }</span>
			</Cell>
			<Cell>
				<span className="bs-ds-t12 bs-ds-r bs-ds-c2">{ whenPhrase( change.occurred_at ) }</span>
			</Cell>
		</Row>
	);
}

/**
 * @param {Object} props
 * @param {Object} props.block The overview's `since_last_visit`.
 */
export default function SinceLastVisit( { block } ) {
	const [ all, setAll ] = useState( false );

	if ( ! block || ! block.changes || ! block.changes.length ) {
		return null;
	}

	// Empty for a reader who may not open the log.
	const logUrl = sectionUrl( 'bettershield-activity' );
	const changes = grouped( block.changes );
	const first = changes.slice( 0, FIRST );
	const rest = changes.slice( FIRST );
	const more = rest.length
		? all
			? __( 'Show Fewer', 'bettershield' )
			: sprintf(
					/* translators: %d: how many more changes the list holds. */
					_n( 'Show %d More', 'Show %d More', rest.length, 'bettershield' ),
					rest.length
			  )
		: '';
	const heading = sprintf(
		/* translators: %s: when the reader last looked, e.g. "today, 12:52 PM" or "Sep 6, 12:52 PM". */
		__( 'What changed since your last visit (%s)', 'bettershield' ),
		whenPhrase( block.since )
	);

	return (
		<Card className="bs-ds-since" aria-labelledby="bs-ds-since-title">
			<CardHead icon="history" title={ heading } id="bs-ds-since-title" />
			<Table
				label={ heading }
				columns={ [
					{ key: 'change', label: __( 'Change', 'bettershield' ) },
					{ key: 'who', label: __( 'Who', 'bettershield' ), width: 'minmax(0, 112px)' },
					{ key: 'when', label: __( 'When', 'bettershield' ), width: '112px' },
				] }
			>
				{ first.map( ( change ) => (
					<ChangeRow key={ change.id } change={ change } />
				) ) }
				{ rest.length && all ? (
					<div role="rowgroup" id={ MORE_ID } className="bs-ds-tbl__rows">
						{ rest.map( ( change ) => (
							<ChangeRow key={ change.id } change={ change } />
						) ) }
					</div>
				) : null }

				{ /* The link only for a reader who can open the log: the address
				     is empty for one who cannot, and an empty link went nowhere. */ }
				{ block.more || more ? (
					<WholeRow
						kind="foot"
						aside={
							<>
								{ more ? (
									<Button
										type="ghost"
										size="sm"
										trailing={ all ? 'chevron-up' : 'chevron-down' }
										trailingTone="3"
										aria-expanded={ all }
										aria-controls={ all ? MORE_ID : undefined }
										onClick={ () => setAll( ( open ) => ! open ) }
									>
										{ more }
									</Button>
								) : null }
								{ block.more && logUrl ? (
									<Button type="secondary" size="sm" href={ logUrl }>
										{ __( 'Open the Log', 'bettershield' ) }
									</Button>
								) : null }
							</>
						}
					>
						{ block.more ? __( 'More changes are in the activity log.', 'bettershield' ) : null }
					</WholeRow>
				) : null }

				{ /* Said only when it is true: a window reaching further back than
				     the log keeps is a period this plugin cannot answer for, and
				     "since you last looked" would otherwise overclaim. */ }
				{ block.clamped ? (
					<WholeRow kind="note">
						{ __( 'Your last visit was before the oldest saved activity, so earlier changes aren’t shown.', 'bettershield' ) }
					</WholeRow>
				) : null }
			</Table>
		</Card>
	);
}
