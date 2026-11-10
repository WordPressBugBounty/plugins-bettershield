/**
 * Safe mode is on: every protection is paused until it ends.
 *
 * The notice at the top of the Overview and of each Protect tab, so they
 * cannot disagree about when the pause ends or how to end it: the same
 * words, read from the same overview payload, with the end time and the way
 * to end it. An owner just back through the recovery link is most likely
 * reading one of the Protect tabs, which would otherwise say nothing.
 */

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useResource, useStore } from '../../store';
import Alert from '../ui/Alert';
import Button from '../ui/Button';

/**
 * The Overview hands it the payload it already holds, kept across a refresh,
 * so the notice does not blink out while the screen reads itself again.
 *
 * @param {Object} props
 * @param {*}      props.note     A line about the tab it sits on, if any.
 * @param {Object} props.safeMode The overview's `safe_mode`, where the screen holds it already.
 */
export default function SafeMode( { note = null, safeMode: given } ) {
	const overview = useResource( 'overview' ).resource;
	const { endSafeMode, busy } = useStore();
	const read = overview.data ? overview.data.safe_mode : null;
	const safeMode = undefined === given ? read : given;
	/*
	 * Ended from here, the banner and its button went and the keyboard fell
	 * to the page with nothing said (#2220). Where it was, a confirmation
	 * takes the focus and is announced.
	 */
	const [ ended, setEnded ] = useState( false );
	const said = useRef( null );
	const active = Boolean( safeMode && safeMode.active );

	useEffect( () => {
		if ( ended && ! active ) {
			said.current?.focus();
		}
	}, [ ended, active ] );

	if ( ! active ) {
		return ended ? (
			<div ref={ said } tabIndex={ -1 } className="bs-ds-safemode-ended">
				<Alert layout="default" tone="success" live desc={ __( 'Safe mode ended. Protection is back on.', 'bettershield' ) } />
			</div>
		) : null;
	}

	const ending = isWorking( busy, 'safe-mode' );

	return (
		<Alert
			layout="default"
			tone="warning"
			live
			title={ __( 'Protection is paused.', 'bettershield' ) }
			desc={
				<>
					{ safeMode.until
						? sprintf(
								/* translators: %s: date and time. */
								__( 'BetterShield’s protections are paused until %s so you can get back in. No settings were changed.', 'bettershield' ),
								formatTime( safeMode.until )
						  )
						: __( 'BetterShield’s protections are paused so you can get back in. No settings were changed.', 'bettershield' ) }
					{ note ? <> { note }</> : null }
					{ safeMode.by_network
						? ' ' + __( 'This pause is network-wide. Only a network administrator can end it, from Network Admin › BetterShield.', 'bettershield' )
						: null }
				</>
			}
			actions={
				// Only the site's own pause is this site's to end; the button
				// did nothing to the network's.
				safeMode.by_network ? null : (
					<Button type="secondary" size="sm" isBusy={ ending } disabled={ ending } onClick={ () => endSafeMode( () => setEnded( true ) ) }>
						{ __( 'End Safe Mode Now', 'bettershield' ) }
					</Button>
				)
			}
		/>
	);
}
