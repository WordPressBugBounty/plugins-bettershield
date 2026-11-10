/**
 * Fix for "Some plugin data can be read by anyone without signing in"
 * (#1870): require sign-in for an address the owner picks.
 *
 * Nothing is closed by default. Each address the finding names offers
 * Require Sign-in, which only watches it for a week: how many requests reach
 * it from visitors who are not signed in, and from which sites. Then the
 * owner closes it, and visitors who are not signed in are refused on that
 * address only, or opens it again. Every one says what closing can break,
 * because most of these are open on purpose.
 */

import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isPast, isWorking, useStore } from '../../../store';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';
import useFixState, { useSaid } from './useFixState';

const PATH = '/bettershield/v1/findings/rest_surface_unreviewed/routes';

/**
 * What was seen on a watched address, in one line.
 *
 * @param {Object} row The address.
 * @return {string} The line.
 */
function seen( row ) {
	const sites = Object.entries( row.origins || {} )
		.map( ( [ site, count ] ) => `${ site } (${ count })` )
		.join( ', ' );
	const requests = sprintf(
		/* translators: %d: how many requests reached the address from visitors not signed in. */
		_n( '%d request from visitors not signed in so far.', '%d requests from visitors not signed in so far.', row.requests, 'bettershield' ),
		row.requests
	);

	/* translators: 1: how many requests, as a sentence; 2: the sites they came from, with counts. */
	return sites ? sprintf( __( '%1$s From: %2$s.', 'bettershield' ), requests, sites ) : requests;
}

export default function RestRoutes() {
	const { watchRestRoute, closeRestRoute, reopenRestRoute, busy } = useStore();
	const { state, setState, unread } = useFixState( PATH );
	const { said, say, status } = useSaid();
	const working = isWorking( busy, 'rest-route' ) || isWorking( busy, 'rest-route-undo' );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The addresses could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the addresses…', 'bettershield' ) }</p>;
	}

	const answered = ( words ) => ( answer ) => {
		if ( answer && answer.routes ) {
			setState( { routes: answer.routes } );
			say( words );
		}
	};

	const refused = ( error ) => {
		say( ( error && error.message ) || __( 'That did not complete. Nothing was changed; try again.', 'bettershield' ) );

		return true;
	};

	return (
		<>
			<p className="bs-ds-fix__text">
				{ __( 'Pick an address to require sign-in for. BetterShield watches who reads it for a week first; then you close it or open it again.', 'bettershield' ) }
			</p>
			<p className="bs-ds-fix__note">{ __( 'A separate app or front end that reads a closed address stops working, so check each one first.', 'bettershield' ) }</p>
			<ul className="bs-ds-fix__list">
				{ state.routes.map( ( row ) => (
					<li key={ row.route } className="bs-ds-fix__done">
						<code>{ row.route }</code>
						{ 'open' === row.state && ! row.offered ? <span className="bs-ds-fix__note">{ __( 'BetterShield leaves this one open.', 'bettershield' ) }</span> : null }
						{ 'open' === row.state && row.offered ? (
							<Button
								type="secondary"
								size="sm"
								disabled={ working }
								aria-label={ sprintf(
									/* translators: %s: a REST address. */
									__( 'Require sign-in for %s', 'bettershield' ),
									row.route
								) }
								onClick={ () => watchRestRoute( row.route, answered( __( 'Watching it for a week. Come back to close it.', 'bettershield' ) ) ) }
							>
								{ __( 'Require Sign-in', 'bettershield' ) }
							</Button>
						) : null }
						{ 'watching' === row.state ? (
							<>
								<span className="bs-ds-fix__note">{ seen( row ) }</span>
								{ isPast( row.closable_at ) ? (
									<Button
										type="primary"
										size="sm"
										disabled={ working }
										onClick={ () => closeRestRoute( row.route, answered( __( 'Closed. Visitors who are not signed in are refused there now.', 'bettershield' ) ) ) }
									>
										{ __( 'Close to Visitors', 'bettershield' ) }
									</Button>
								) : (
									<span className="bs-ds-fix__note">
										{ sprintf(
											/* translators: %s: a date and time. */
											__( 'You can close it from %s.', 'bettershield' ),
											formatTime( row.closable_at )
										) }
									</span>
								) }
							</>
						) : null }
						{ 'closed' === row.state ? <span className="bs-ds-fix__note">{ __( 'Closed to visitors who are not signed in.', 'bettershield' ) }</span> : null }
						{ /* A watched address was never closed, so stopping the watch
						     opens nothing: it only clears what was seen (#2512). */ }
						{ 'open' !== row.state ? (
							<Armed
								label={ 'closed' === row.state ? __( 'Open Again', 'bettershield' ) : __( 'Stop Watching', 'bettershield' ) }
								consequence={
									'closed' === row.state
										? __( 'Anyone can read this address again, and what was seen on it is cleared.', 'bettershield' )
										: __( 'What was seen on it is cleared.', 'bettershield' )
								}
								busy={ isWorking( busy, 'rest-route-undo' ) }
								disabled={ working }
								onConfirm={ () => reopenRestRoute( row.undo, answered( 'closed' === row.state ? __( 'Anyone can read it again.', 'bettershield' ) : __( 'Stopped watching it.', 'bettershield' ) ), refused ) }
							/>
						) : null }
					</li>
				) ) }
			</ul>
			{ said ? (
				<p className="bs-ds-fix__note" role="status" ref={ status } tabIndex={ -1 }>
					{ said }
				</p>
			) : null }
		</>
	);
}

RestRoutes.kind = 'acts';
