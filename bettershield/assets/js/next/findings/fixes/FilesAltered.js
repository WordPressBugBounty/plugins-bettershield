/**
 * Fix for "Files no longer match the official copies" (#2206).
 *
 * What differs, by kind, and how many of the changed files have a verified
 * official copy to put back; then the Files tab, whose list opens on exactly
 * these changes with their comparison, selection and restore. Nothing is put
 * back, deleted or accepted from here: an altered file may be a developer's
 * deliberate edit, and only the comparison says which.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../../nav';
import Badge from '../../ui/Badge';
import Button from '../../ui/Button';
import { formatCount } from '../../../ui/count';

/**
 * @param {Object} props
 * @param {Object} props.finding The finding, with its counts as evidence.
 */
export default function FilesAltered( { finding } ) {
	/*
	 * The counts as the Files tab has them now, which the Overview's copy of
	 * the finding does not carry; the finding's own evidence stands in until
	 * they are read. How many can be put back is said only once read.
	 */
	const [ open, setOpen ] = useState( null );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/integrity' } ).then(
			( report ) => {
				if ( alive && report && report.open_changes && Number.isInteger( report.open_changes.total ) ) {
					setOpen( report.open_changes );
				}
			},
			() => {}
		);

		return () => {
			alive = false;
		};
	}, [] );

	const evidence = finding.evidence || {};
	const counts = open
		? { files: open.total, altered: open.modified, added: open.added, missing: open.removed }
		: { files: evidence.files, altered: evidence.altered, added: evidence.added, missing: evidence.missing };
	const files = Number( counts.files ) || 0;
	const restorable = open && Number.isInteger( open.restorable ) ? open.restorable : null;

	const kinds = [
		[ Number( counts.altered ) || 0, ( n ) => sprintf( /* translators: %s: how many files differ from their official copy. */ _n( '%s changed', '%s changed', n, 'bettershield' ), formatCount( n ) ) ],
		[ Number( counts.added ) || 0, ( n ) => sprintf( /* translators: %s: how many files are not in the official copy. */ _n( '%s added', '%s added', n, 'bettershield' ), formatCount( n ) ) ],
		[ Number( counts.missing ) || 0, ( n ) => sprintf( /* translators: %s: how many official files are missing. */ _n( '%s missing', '%s missing', n, 'bettershield' ), formatCount( n ) ) ],
	].filter( ( [ n ] ) => n > 0 );
	const filesUrl = tabUrl( 'bettershield-activity', 'files' );

	return (
		<>
			<p className="bs-ds-fix__text">
				{ sprintf(
					/* translators: %s: how many files differ from the official copies. */
					_n( '%s file differs from the official copies.', '%s files differ from the official copies.', files, 'bettershield' ),
					formatCount( files )
				) }
			</p>
			{ kinds.length ? (
				<ul className="bs-ds-fix__counts">
					{ kinds.map( ( [ n, label ] ) => (
						<li key={ label( n ) }>
							<Badge>{ label( n ) }</Badge>
						</li>
					) ) }
				</ul>
			) : null }
			{ null !== restorable ? (
				<p className="bs-ds-fix__text">
					{ restorable > 0
						? sprintf(
								/* translators: %s: how many changed files can be restored to the official version. */
								_n(
									'%s can be restored to the official version. The changed copy is kept in quarantine, and this can be undone.',
									'%s can be restored to the official version. The changed copies are kept in quarantine, and each can be undone.',
									restorable,
									'bettershield'
								),
								formatCount( restorable )
						  )
						: __( 'None of these can be restored automatically. Review each, and accept the changes you made on purpose.', 'bettershield' ) }
				</p>
			) : null }
			{ filesUrl ? (
				<div className="bs-ds-fix__actions">
					<Button type="primary" size="sm" href={ filesUrl } trailing="arrow-right">
						{ __( 'Review Affected Files', 'bettershield' ) }
					</Button>
				</div>
			) : null }
			<p className="bs-ds-fix__note">
				{ __( 'Compare each file before acting. Nothing is restored, deleted or accepted from here.', 'bettershield' ) }
			</p>
		</>
	);
}

// It leads to the review; nothing is put back from here.
FilesAltered.kind = 'guidance';
FilesAltered.word = () => __( 'Review Files', 'bettershield' );
