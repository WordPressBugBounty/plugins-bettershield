/**
 * Fix for "Published content still points at plain HTTP" (#1291).
 *
 * How many published posts carry this site's own http:// address, then
 * Rewrite to https://, a batch at a time with the count so far, and Undo,
 * which puts each post back byte for byte and names any edited since. Links
 * to other hosts are never touched. Offered while the address is HTTPS.
 */

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { isWorking, useStore } from '../../../store';
import { announce } from '../../../ui/announce';
import Alert from '../../ui/Alert';
import Armed from '../../ui/Armed';
import Button from '../../ui/Button';

const PATH = '/bettershield/v1/findings/mixed_content_published/links';

export default function ContentLinks() {
	const { rewriteContentLinks, undoContentLinks, busy } = useStore();
	const [ state, setState ] = useState( null );
	const [ unread, setUnread ] = useState( false );
	const [ going, setGoing ] = useState( '' );
	const alive = useRef( true );

	useEffect( () => {
		apiFetch( { path: PATH } ).then(
			( answer ) => alive.current && setState( answer ),
			() => alive.current && setUnread( true )
		);

		return () => {
			alive.current = false;
		};
	}, [] );

	if ( unread ) {
		return <p className="bs-ds-fix__text">{ __( 'The published content could not be read. Open the finding again to retry.', 'bettershield' ) }</p>;
	}

	if ( ! state ) {
		return <p className="bs-ds-fix__note">{ __( 'Reading the published content…', 'bettershield' ) }</p>;
	}

	const working = Boolean( going ) || isWorking( busy, 'content-links' );
	const run = state.run;
	// Every run not yet undone, which Undo puts back together (#2283).
	const kept = run ? run.kept || run.changed : 0;

	// One batch, then the next, until the run says it is done.
	const step = ( kind ) => {
		setGoing( kind );
		const send = 'rewrite' === kind ? rewriteContentLinks : undoContentLinks;
		const next = ( answer ) => {
			if ( ! alive.current ) {
				return;
			}

			if ( ! answer ) {
				setGoing( '' );
				return;
			}

			setState( answer );

			const finished = 'rewrite' === kind ? answer.run && answer.run.done : answer.run && answer.run.undone;

			if ( finished ) {
				setGoing( '' );
				announce(
					'rewrite' === kind
						? sprintf(
								/* translators: %d: how many posts were changed. */
								_n( '%d post now links to the HTTPS address.', '%d posts now link to the HTTPS address.', answer.run.changed, 'bettershield' ),
								answer.run.changed
						  )
						: __( 'The rewritten posts are back as they were.', 'bettershield' )
				);
				return;
			}

			// The shared layer lets go of one action after its callbacks
			// run, so the next batch is sent once this one has returned.
			window.setTimeout( () => send( next ), 0 );
		};

		send( next );
	};

	if ( ! state.https ) {
		return <p className="bs-ds-fix__text">{ __( 'The site address is not HTTPS, so its own links are left as they are. Switch the address first.', 'bettershield' ) }</p>;
	}

	return (
		<>
			{ state.core_covers ? (
				<p className="bs-ds-fix__note">{ __( 'WordPress already fixes these links when it shows a page. Updating them here fixes them in the posts themselves.', 'bettershield' ) }</p>
			) : null }
			<p className="bs-ds-fix__text">
				{ state.remaining
					? sprintf(
							/* translators: 1: how many published posts, 2: the site's own address over plain HTTP. */
							_n( '%1$d published post links to %2$s.', '%1$d published posts link to %2$s.', state.remaining, 'bettershield' ),
							state.remaining,
							state.origin
					  )
					: sprintf(
							/* translators: %s: the site's own address over plain HTTP. */
							__( 'No published post links to %s. Links to other sites are left as they are.', 'bettershield' ),
							state.origin
					  ) }
			</p>
			{ going ? (
				<p className="bs-ds-fix__note" role="status">
					{ 'rewrite' === going
						? sprintf(
								/* translators: %d: how many posts so far. */
								_n( 'Rewriting… %d post so far.', 'Rewriting… %d posts so far.', run ? run.changed : 0, 'bettershield' ),
								run ? run.changed : 0
						  )
						: __( 'Putting the posts back…', 'bettershield' ) }
				</p>
			) : null }
			{ run && run.done && ! run.undone && ! going ? (
				<Alert
					layout="default"
					tone="success"
					desc={ sprintf(
						/* translators: %d: how many posts were changed. */
						_n( '%d post was rewritten. Undo puts it back exactly as it was.', '%d posts were rewritten. Undo puts each back exactly as it was.', kept, 'bettershield' ),
						kept
					) }
				/>
			) : null }
			{ run && run.capped && ! going ? <p className="bs-ds-fix__note">{ sprintf( /* translators: %d: the most posts one run changes. */ __( 'Up to %d posts are updated at a time. Press the button again for the rest.', 'bettershield' ), state.run_max ) }</p> : null }
			{ run && run.undone && run.skipped.length ? (
				<Alert
					layout="default"
					tone="warning"
					desc={ sprintf(
						/* translators: %s: post titles, comma-separated. */
						__( 'These posts were edited afterward, so they weren’t changed back: %s', 'bettershield' ),
						run.skipped.map( ( post ) => post.title || `#${ post.id }` ).join( ', ' )
					) }
				/>
			) : null }
			<p className="bs-ds-fix__note">{ __( 'Only links to your own site change. You can undo this.', 'bettershield' ) }</p>
			<div className="bs-ds-fix__actions">
				{ state.remaining ? (
					<Button type="primary" size="sm" isBusy={ 'rewrite' === going } disabled={ working } onClick={ () => step( 'rewrite' ) }>
						{ sprintf(
							/* translators: %d: how many posts. */
							_n( 'Update Links in %d Post', 'Update Links in %d Posts', Math.min( state.remaining, state.run_max ), 'bettershield' ),
							Math.min( state.remaining, state.run_max )
						) }
					</Button>
				) : null }
				{ run && run.done && ! run.undone ? (
					<Armed
						type="secondary"
						label={ __( 'Undo', 'bettershield' ) }
						consequence={ __( 'The rewritten posts go back to their http:// links. Posts edited since are left alone.', 'bettershield' ) }
						confirm={ __( 'Yes, Put Them Back', 'bettershield' ) }
						busy={ 'undo' === going }
						onConfirm={ () => step( 'undo' ) }
					/>
				) : null }
			</div>
		</>
	);
}

ContentLinks.kind = 'acts';
