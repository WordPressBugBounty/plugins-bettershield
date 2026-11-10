/**
 * What the last update added, and that none of it is switched on.
 *
 * Almost everything this plugin ships arrives off, and several of the features
 * write to people who are not the site's administrator or add a requirement
 * nobody asked for, so an update must never switch one on. A release note
 * alone does not carry that: it reaches only the people who go and read one,
 * while a site on auto-update takes the new capabilities and is told nothing.
 * This card is the half of the notice that reaches the rest.
 *
 * The headline is the whole value, so the card only appears while it is true.
 * A feature that ever ships on by default is stated first and plainly, and the
 * server refuses to build a card whose headline it cannot stand behind.
 *
 * Once per version, per person, dismissible, selling nothing. If it ever stops
 * being those four things it should be removed rather than softened.
 */

import './ReleaseNote.css';

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { useStore } from '../../store';
import Button from '../ui/Button';
import { Card, CardHead } from '../ui/Card';
import { focusIfLost } from '../ui/focus';

export default function ReleaseNote( { release } ) {
	const { dismissRelease } = useStore();
	const [ gone, setGone ] = useState( false );

	// Dismiss takes the card, and itself, away, and the browser dropped focus
	// to the page body. It goes to the page's heading instead.
	useEffect( () => {
		if ( gone ) {
			focusIfLost( document.querySelector( '.bs-ds-top__title' ) );
		}
	}, [ gone ] );

	if ( gone || ! release || ! release.features || ! release.features.length ) {
		return null;
	}

	// What is on here, now, not what the release shipped switched on. The two
	// are different the moment somebody changes a setting, and this sentence
	// is a claim about their site rather than about the release.
	const on = release.features.filter( ( feature ) => feature.is_on );
	const headline = `${ sprintf(
		/* translators: %d: how many features arrived. */
		_n( 'This update added %d thing.', 'This update added %d things.', release.features.length, 'bettershield' ),
		release.features.length
	) } ${
		on.length
			? sprintf(
					/* translators: %d: how many are already active. */
					_n( '%d of them is already switched on.', '%d of them are already switched on.', on.length, 'bettershield' ),
					on.length
			  )
			: __( 'None of them is switched on.', 'bettershield' )
	}`;

	return (
		<Card className="bs-ds-release" aria-labelledby="bs-ds-release-title">
			<CardHead
				icon="package"
				title={ sprintf(
					/* translators: %s: the version this site is on now. */
					__( 'New in BetterShield %s', 'bettershield' ),
					release.to
				) }
				id="bs-ds-release-title"
				line
				auto
			>
				<Button
					type="ghost"
					size="sm"
					onClick={ () => {
						setGone( true );
						dismissRelease( release.to );
					} }
				>
					{ __( 'Dismiss', 'bettershield' ) }
				</Button>
			</CardHead>

			<p className="bs-ds-release__lede">{ headline }</p>

			<ul className="bs-ds-release__list">
				{ release.features.map( ( feature ) => (
					<li key={ feature.id } className="bs-ds-release__item">
						{ feature.title ? <p className="bs-ds-release__title">{ feature.title }</p> : null }
						<p className="bs-ds-release__what">{ feature.what }</p>
						<p className="bs-ds-release__changes">{ feature.changes }</p>
					</li>
				) ) }
			</ul>

			<p className="bs-ds-release__note">
				{ /* "Nothing here changed your site" is only true while none of
				     them is on: one on by default after the update has changed
				     it, and the line under it said otherwise. */ }
				{ on.length
					? sprintf(
							/* translators: 1: the version this site was on, 2: the version it is on now. */
							__( 'From %1$s to %2$s.', 'bettershield' ),
							release.from,
							release.to
					  )
					: sprintf(
							/* translators: 1: the version this site was on, 2: the version it is on now. */
							__( 'From %1$s to %2$s. Nothing here changed your site; each one waits for you.', 'bettershield' ),
							release.from,
							release.to
					  ) }
			</p>
		</Card>
	);
}
