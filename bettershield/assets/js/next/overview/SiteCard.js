/**
 * The card that asks, once a site is somewhere new, whether it is a staging
 * copy or a move, and says so afterwards on a copy marked staging.
 *
 * Nothing is decided for the owner. Each answer lists what it will do before
 * it does it, and the one undo puts back everything that answer changed.
 */

import './SiteCard.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { tabUrl } from '../../nav';
import { isWorking, useStore } from '../../store';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import Icon from '../ui/Icon';

/**
 * What the card asks, for what is known to have changed.
 *
 * @param {Object} change      The overview's `site_identity.change`.
 * @param {string} change.from The address the site had.
 * @param {string} change.to   The address it has now.
 * @param {string} change.kind `address`, `server` or `original`.
 * @return {{title: string, desc: string}} The card's heading and question.
 */
function question( { from, to, kind } ) {
	// Only the folder is known to have changed: on the same server or
	// another one, which nothing here can tell apart.
	if ( 'server' === kind ) {
		return {
			title: __( 'This site is running from a new location', 'bettershield' ),
			desc: sprintf(
				/* translators: %s: the site's address. */
				__( 'Is this a test copy (staging) of %s, or has the site moved here?', 'bettershield' ),
				to
			),
		};
	}

	// Marked a staging copy and now at the address of the live site it was
	// marked a copy of, with nothing else changed: "It was live.example.org
	// and is now live.example.org" would say nothing.
	if ( 'original' === kind ) {
		return {
			title: __( 'This site is at the live site’s address', 'bettershield' ),
			desc: sprintf(
				/* translators: %s: the live site's address. */
				__( 'Is this still a staging copy of %s, or has the site moved here?', 'bettershield' ),
				to
			),
		};
	}

	return {
		title: __( 'This site’s address changed', 'bettershield' ),
		desc: sprintf(
			/* translators: 1: the address the site had, 2: the address it has now. */
			__( 'Is %2$s a staging copy of %1$s, or has the site moved here?', 'bettershield' ),
			from,
			to
		),
	};
}

/**
 * @param {Object}    props
 * @param {?Object}   props.identity The overview's `site_identity`.
 * @param {?Function} props.onGone   Called when Done takes the card away, so
 *                                   focus can go somewhere that stays.
 */
export default function SiteCard( { identity, onGone } ) {
	const { answerSiteIdentity, undoSiteIdentity, doneSiteIdentity, busy, resources } = useStore();
	const [ choice, setChoice ] = useState( null );
	const [ moved, setMoved ] = useState( null );
	const [ undone, setUndone ] = useState( false );

	/*
	 * Every answer replaces the button that was pressed, so focus is taken
	 * somewhere on purpose: to the plan an answer brings up, to the card an
	 * answer leaves behind, and to the first answer after Back or Undo.
	 *
	 * Wanted rather than done at once: the node does not exist until the card
	 * has redrawn, and after Go ahead or Undo not until the overview it is
	 * drawn from has reloaded. One that never arrives is let go of then.
	 */
	const titleRef = useRef( null );
	const planRef = useRef( null );
	const firstRef = useRef( null );
	const [ focusWanted, setFocusWanted ] = useState( null );
	const status = resources.overview?.status;

	useEffect( () => {
		if ( ! focusWanted || ( focusWanted.reload && 'ready' !== status ) ) {
			return;
		}

		const node = { title: titleRef, plan: planRef, first: firstRef }[ focusWanted.to ].current;

		if ( node ) {
			node.focus();
		}
		setFocusWanted( null );
	}, [ focusWanted, status ] );

	if ( ! identity ) {
		return null;
	}

	const working = isWorking( busy, 'site-identity' );

	const choose = ( answer ) => {
		setUndone( false );
		setChoice( answer );
		setFocusWanted( { to: answer ? 'plan' : 'first' } );
	};

	const undo = ( token ) =>
		undoSiteIdentity( token, () => {
			setMoved( null );
			setUndone( true );
			setFocusWanted( { to: 'first', reload: true } );
		} );

	// Answered "moved", just now or on an earlier visit: the two steps that
	// are the owner's own, where they are done, and the way back. Drawn from
	// the overview as well as from this card's memory, which a reload, or
	// following the first step, took away.
	const movedUndo = moved || ( ! identity.change && ! identity.staging && 'moved' === identity.answer && ! identity.done && identity.undo ? identity.undo : null );

	// Done with the card: it goes, and the answer's undo stays open.
	const done = ( token ) =>
		doneSiteIdentity( token, ( data ) => {
			if ( data ) {
				setMoved( null );
				onGone?.();
			}
		} );

	if ( movedUndo ) {
		return (
			<Card className="bs-ds-site" aria-labelledby="bs-ds-site-title">
				<CardHead icon="globe" title={ __( 'This is now the site’s address', 'bettershield' ) } id="bs-ds-site-title" headingRef={ titleRef } />
				<div className="bs-ds-site__body">
					<p className="bs-ds-site__text">{ __( 'Two steps are yours, on the screens that do them:', 'bettershield' ) }</p>
					<ul className="bs-ds-site__steps bs-ds-site__steps--links">
						<li>
							<Button type="link" size="sm" href={ tabUrl( 'bettershield-protect', 'recovery' ) }>
								{ __( 'Issue a Recovery Link for This Address', 'bettershield' ) }
								<Icon name="arrow-right" size={ 14 } tone="1" className="bs-ds-site__arrow" />
							</Button>
						</li>
						<li>
							<Button type="link" size="sm" href={ tabUrl( 'bettershield-activity', 'files' ) }>
								{ __( 'Check the Files on This Server', 'bettershield' ) }
								<Icon name="arrow-right" size={ 14 } tone="1" className="bs-ds-site__arrow" />
							</Button>
						</li>
					</ul>
					<div className="bs-ds-site__actions">
						<Button type="secondary" size="sm" disabled={ working } onClick={ () => done( movedUndo ) }>
							{ __( 'Done', 'bettershield' ) }
						</Button>
						<Button type="ghost" size="sm" icon="undo-2" iconTone="1" disabled={ working } onClick={ () => undo( movedUndo ) }>
							{ __( 'Undo', 'bettershield' ) }
						</Button>
					</div>
				</div>
			</Card>
		);
	}

	// A copy already marked staging, and nothing new since.
	if ( ! identity.change && identity.staging ) {
		return (
			<Card className="bs-ds-site bs-ds-site--staging" aria-labelledby="bs-ds-site-title">
				<CardHead icon="globe" title={ __( 'This is a staging copy', 'bettershield' ) } id="bs-ds-site-title" headingRef={ titleRef }>
					{ identity.undo ? (
						<Button type="ghost" size="sm" icon="undo-2" iconTone="1" disabled={ working } onClick={ () => undo( identity.undo ) }>
							{ __( 'Undo', 'bettershield' ) }
						</Button>
					) : null }
				</CardHead>
				<div className="bs-ds-site__body">
					<p className="bs-ds-site__text">
						{ identity.original
							? sprintf(
									/* translators: %s: the live site's address. */
									__( 'A copy of %s. Alerts are muted, BetterShield Hub can’t connect, and no usage data is sent.', 'bettershield' ),
									identity.original
							  )
							: __( 'Alerts are muted, BetterShield Hub can’t connect, and no usage data is sent.', 'bettershield' ) }
					</p>
				</div>
			</Card>
		);
	}

	if ( ! identity.change ) {
		return null;
	}

	const { title, desc } = question( identity.change );
	const confirm = () =>
		answerSiteIdentity( choice, ( data ) => {
			if ( data && 'moved' === choice ) {
				setMoved( data.undo );
			}
			setChoice( null );
			setFocusWanted( { to: 'title', reload: true } );
		} );

	return (
		<Card className="bs-ds-site" aria-labelledby="bs-ds-site-title">
			<CardHead icon="globe" title={ title } id="bs-ds-site-title" />
			<div className="bs-ds-site__body">
				<Alert
					layout="default"
					tone="warning"
					icon="globe"
					desc={ desc }
					actions={
						choice ? null : (
							<>
								<Button type="secondary" size="sm" ref={ firstRef } onClick={ () => choose( 'staging' ) }>
									{ __( 'A Staging Copy', 'bettershield' ) }
								</Button>
								<Button type="secondary" size="sm" onClick={ () => choose( 'moved' ) }>
									{ __( 'The Site Moved Here', 'bettershield' ) }
								</Button>
							</>
						)
					}
				/>

				{ /* Said as well as shown: the card redrew under the reader, and
				     focus alone does not say why. */ }
				{ undone ? (
					<p className="screen-reader-text" role="status">
						{ __( 'Your answer was undone.', 'bettershield' ) }
					</p>
				) : null }

				{ choice ? (
					<div className="bs-ds-site__plan">
						<p className="bs-ds-site__lead" ref={ planRef } tabIndex={ -1 }>
							{ 'staging' === choice ? __( 'Marking this a staging copy will:', 'bettershield' ) : __( 'Saying the site moved here will:', 'bettershield' ) }
						</p>
						<ul className="bs-ds-site__steps">
							{ ( identity.plan?.[ choice ] || [] ).map( ( step ) => (
								<li key={ step }>{ step }</li>
							) ) }
						</ul>
						<p className="bs-ds-site__note">{ __( 'One undo puts back everything this changes.', 'bettershield' ) }</p>
						<div className="bs-ds-site__actions">
							<Button type="primary" size="sm" isBusy={ working } disabled={ working } onClick={ confirm }>
								{ __( 'Go Ahead', 'bettershield' ) }
							</Button>
							<Button type="ghost" size="sm" onClick={ () => choose( null ) }>
								{ __( 'Back', 'bettershield' ) }
							</Button>
						</div>
					</div>
				) : null }
			</div>
		</Card>
	);
}
