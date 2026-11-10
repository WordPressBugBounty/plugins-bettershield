/**
 * Fix for "Some protections that are switched on are not working" (#2430).
 *
 * Each protection the finding names, with what was seen, and Apply again:
 * it is undone and applied once more with the settings it has, so its rules
 * and hooks are put back. One that changes how people sign in checks the
 * way back in first. If it fails again, something else is undoing it, and
 * the panel says so.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';

/** What was seen, in words, by the reason the check gives. */
const SEEN = {
	rules_missing: () => __( 'Its rules are gone from the server file.', 'bettershield' ),
	rules_altered: () => __( 'Its rules in the server file were changed.', 'bettershield' ),
	guards_missing: () => __( 'Some of the guard files it placed are gone.', 'bettershield' ),
	hooks_detached: () => __( 'Switched on, but not running on this site.', 'bettershield' ),
	not_observed: () => __( 'Switched on, but not seen on a visitor’s page.', 'bettershield' ),
};

export default function ProtectionRepair() {
	const { reapplyProtection, load, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ said, setSaid ] = useState( null );
	const result = useRef( null );
	const working = isWorking( busy, 'reapply-protection' );

	useEffect( () => {
		let alive = true;

		apiFetch( { path: '/bettershield/v1/findings/hardening_not_working/protections' } ).then(
			( answer ) => alive && setState( answer ),
			() => alive && setUnread( true )
		);

		return () => {
			alive = false;
		};
	}, [] );

	useEffect( () => {
		if ( said && result.current ) {
			result.current.focus();
		}
	}, [ said ] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The protections could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the protections…', 'bettershield' ) }</p>;
	}

	const say = ( tone, words ) => {
		setSaid( { tone, words } );
		announce( words );
	};

	const reapply = ( row ) => {
		setSaid( null );
		announce( sprintf( /* translators: %s: a protection's name. */ __( 'Applying %s again…', 'bettershield' ), row.title ) );
		reapplyProtection(
			row.id,
			( answer ) => {
				if ( ! answer ) {
					return;
				}

				setState( answer.state );
				say(
					answer.working ? 'success' : 'warning',
					answer.working
						? sprintf( /* translators: %s: a protection's name. */ __( '%s is applied again and working.', 'bettershield' ), row.title )
						: sprintf( /* translators: %s: a protection's name. */ __( '%s was applied again, but still is not working. Something else on the site is undoing it.', 'bettershield' ), row.title )
				);

				// The report and the score, as they now stand.
				load( 'hardening', { force: true } );
			},
			( error ) => {
				say( 'error', ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

				return true;
			}
		);
	};

	return (
		<>
			{ state.items.length ? (
				<>
					<p className="bs-ds-fix__text">{ __( 'Apply again undoes the protection and applies it once more with the settings it has, putting back its rules and hooks.', 'bettershield' ) }</p>
					<ul className="bs-ds-fix__list">
						{ state.items.map( ( row ) => (
							<li key={ row.id } className="bs-ds-fix__done">
								<span className="bs-ds-fix__text">
									{ sprintf(
										/* translators: 1: a protection's name; 2: what was seen. */
										__( '%1$s: %2$s', 'bettershield' ),
										row.title,
										SEEN[ row.reason ] ? SEEN[ row.reason ]() : row.reason
									) }
								</span>
								<Armed
									label={ __( 'Apply Again', 'bettershield' ) }
									aria-label={ sprintf( /* translators: %s: a protection's name. */ __( 'Apply %s Again', 'bettershield' ), row.title ) }
									consequence={
										row.signs_in
											? __( 'It is undone and applied again with the same settings, after checking your way back in. The sign-in address stays the same.', 'bettershield' )
											: __( 'It is undone and applied again at once, with the same settings.', 'bettershield' )
									}
									confirm={ __( 'Yes, Apply Again', 'bettershield' ) }
									busy={ working }
									disabled={ working }
									onConfirm={ () => reapply( row ) }
								/>
							</li>
						) ) }
					</ul>
				</>
			) : (
				<p className="bs-ds-fix__text">{ __( 'Every protection that is switched on is working now.', 'bettershield' ) }</p>
			) }
			{ said ? (
				<div ref={ result } tabIndex={ -1 }>
					<Alert layout="default" tone={ said.tone } desc={ said.words } />
				</div>
			) : null }
		</>
	);
}

ProtectionRepair.kind = 'acts';
