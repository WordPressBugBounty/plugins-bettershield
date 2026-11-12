/**
 * Fix for "A script on your store may be reading card details" (#2844).
 *
 * Each flagged script by where it is and what it was seen doing, never its
 * text. Removing one is the owner's job, in the place named; what this panel
 * does is accept one the owner or their developer added, so it stays quiet
 * until it changes, and take that back.
 */

import { __ } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';
import useFixState, { useSaid } from './useFixState';

export default function StoreScripts() {
	const { acceptStoreScript, unacceptStoreScript, busy } = useStore();
	const { state, setState, unread } = useFixState( '/bettershield/v1/findings/store_script_reads_cards/scripts' );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'store-scripts' );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The flagged scripts could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the flagged scripts…', 'bettershield' ) }</p>;
	}

	const accept = ( row ) => {
		announce( __( 'Accepting the script…', 'bettershield' ) );
		acceptStoreScript( row.key, ( answer ) => {
			if ( answer ) {
				setState( answer );
				say( __( 'Accepted. It stays quiet until it changes, and the activity log records it.', 'bettershield' ) );
			}
		} );
	};

	const putBack = ( row ) => {
		unacceptStoreScript( row.key, ( answer ) => {
			if ( answer ) {
				setState( answer );
				say( __( 'It’s flagged again.', 'bettershield' ) );
			}
		} );
	};

	return (
		<>
			{ state.scripts.length ? (
				<>
					<p className="bs-ds-fix__text">
						{ __( 'Look at each script where it is named. If nobody you know added it, remove it there and change every administrator’s password. If you did, accept it.', 'bettershield' ) }
					</p>
					<ul className="bs-ds-fix__list">
						{ state.scripts.map( ( row ) => (
							<li key={ row.key }>
								<p className="bs-ds-fix__text">{ row.words }</p>
								<div className="bs-ds-fix__actions">
									<Armed
										label={ __( 'Accept This Script', 'bettershield' ) }
										consequence={ __( 'It won’t be flagged again unless it changes. Accept it only if you know who added it.', 'bettershield' ) }
										confirm={ __( 'Yes, Accept It', 'bettershield' ) }
										busy={ working }
										onConfirm={ () => accept( row ) }
									/>
								</div>
							</li>
						) ) }
					</ul>
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'No flagged script is waiting now.', 'bettershield' ) }</p>
			) }
			{ state.accepted.length ? (
				<>
					<p className="bs-ds-fix__note">{ __( 'Accepted', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.accepted.map( ( row ) => (
							<li key={ row.key } className="bs-ds-fix__note">
								{ row.words }{ ' ' }
								<Button type="secondary" size="sm" disabled={ working } onClick={ () => putBack( row ) }>
									{ __( 'Flag It Again', 'bettershield' ) }
								</Button>
							</li>
						) ) }
					</ul>
				</>
			) : null }
			{ said ? (
				<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
					{ said }
				</p>
			) : null }
		</>
	);
}

StoreScripts.kind = 'acts';
