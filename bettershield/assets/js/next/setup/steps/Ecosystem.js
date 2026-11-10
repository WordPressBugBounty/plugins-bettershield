/**
 * Recommended plugins: other plugins from the same team, on the Ecosystem
 * step (the setup's summary), each with its own switch as before (#2297).
 *
 * Every switch starts off. The owner turns on the ones they want, and the
 * step's Continue installs and activates exactly those, one after another,
 * each through WordPress's own installer and each its own request, so one
 * that fails never takes the others with it. A failure stays on its row
 * with the WordPress.org link and its switch goes back off, and the step
 * stays open so it can be read; Continue then goes on without it, and
 * switching it on again tries again. Go to Overview installs nothing.
 *
 * Two lists, the ones suggested for this site first, each plugin a compact
 * tile in a three-column grid with a hairline between rows: its name, one
 * short line (why it is suggested here, in the accent ink, or what it does),
 * and its switch, which gives way to what installing it came to. The full
 * description is the tile's tooltip and is read to screen readers.
 */

import './Ecosystem.css';

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../../ui/Alert';
import Badge from '../../ui/Badge';
import { Toggle } from '../../ui/Setting';
import { useSetup } from '../context';
import { failureMessage, request, ROUTES } from '../api';
import { initials } from '../../../setup/format';

/**
 * One plugin: its name and its switch, and one line about it.
 *
 * @param {Object}   props
 * @param {Object}   props.plugin   The plugin from the server.
 * @param {boolean}  props.chosen   Whether its switch is on.
 * @param {?Object}  props.result   What installing it came to, if it was tried.
 * @param {boolean}  props.working  Whether it is being installed now.
 * @param {boolean}  props.locked   Whether the switches are held.
 * @param {Function} props.onToggle Called with the switch's new state.
 */
function PluginRow( { plugin, chosen, result, working, locked, onToggle } ) {
	const done = Boolean( result ) && 'error' !== result.status;
	const failed = Boolean( result ) && 'error' === result.status;
	const heading = `bs-eco-${ plugin.slug }`;

	let control;

	if ( done ) {
		control = (
			<span role="status">
				<Badge tone="brand" icon="check">
					{ 'active' === result.status ? __( 'Active', 'bettershield' ) : __( 'Installed', 'bettershield' ) }
				</Badge>
			</span>
		);
	} else if ( working ) {
		control = (
			<span className="bs-ds-setup-eco__working" role="status">
				<span className="bs-ds-setup-eco__spinner" aria-hidden="true" />
				{ __( 'Installing…', 'bettershield' ) }
			</span>
		);
	} else {
		control = (
			<Toggle
				checked={ chosen }
				disabled={ locked }
				onChange={ ( event ) => onToggle( Boolean( event && event.target ? event.target.checked : event ) ) }
				label={ sprintf(
					/* translators: %s: plugin name. */
					__( 'Install %s', 'bettershield' ),
					plugin.name
				) }
			/>
		);
	}

	// The short line the compact list shows; the full description stays for
	// the tooltip and for screen readers.
	const line = plugin.why || plugin.short || plugin.description;
	const full = plugin.description && plugin.description !== line ? plugin.description : '';

	return (
		<li className={ `bs-ds-setup-eco__item${ plugin.why ? ' is-recommended' : '' }` } title={ plugin.description || undefined }>
			<div className="bs-ds-setup-eco__top">
				{ /* The plugin's own logo, shipped with this plugin; its initials where none is. */ }
				<span className={ `bs-ds-setup-eco__icon${ plugin.icon ? '' : ' is-initials' }` } aria-hidden="true">
					{ plugin.icon ? <img src={ plugin.icon } alt="" width="20" height="20" loading="lazy" /> : initials( plugin.name ) }
				</span>
				<div className="bs-ds-setup-eco__text">
					<h3 className="bs-ds-setup-eco__name" id={ heading }>
						{ plugin.name }
					</h3>
					{ /* Why it is suggested here, where it is; what it does otherwise. */ }
					<p className="bs-ds-setup-eco__about">{ line }</p>
					{ full ? <span className="screen-reader-text">{ full }</span> : null }
				</div>
				<span className="bs-ds-setup-eco__control">{ control }</span>
			</div>

			{ failed ? (
				<div className="bs-ds-setup-eco__problem" role="alert">
					<Alert
						layout="default"
						tone="error"
						desc={
							<>
								{ result.message }{ ' ' }
								<a href={ plugin.url } target="_blank" rel="noopener noreferrer">
									{ __( 'Get it from WordPress.org', 'bettershield' ) }
								</a>
							</>
						}
					/>
				</div>
			) : null }
		</li>
	);
}

/**
 * One list of plugins: a plain head with its name and a quiet note at the
 * other end, then the tiles in a grid with a hairline between rows.
 *
 * @param {Object}                    props
 * @param {string}                    props.id       The heading's id.
 * @param {string}                    props.title    The list's name.
 * @param {string}                    props.note     The quiet note at the head's end.
 * @param {import('react').ReactNode} props.children The tiles.
 */
function PluginList( { id, title, note, children } ) {
	return (
		<section className="bs-ds-setup-eco" aria-labelledby={ id }>
			<div className="bs-ds-setup-eco__head">
				<h2 className="bs-ds-setup-eco__heading" id={ id }>
					{ title }
				</h2>
				{ note ? <span className="bs-ds-setup-eco__note">{ note }</span> : null }
			</div>
			<ul className="bs-ds-setup-eco__list">{ children }</ul>
		</section>
	);
}

/**
 * @param {Object}   props
 * @param {Function} props.register Given the install the step's Continue runs, which resolves whether every chosen plugin is in.
 * @param {Function} props.onChosen Told how many switches are on, for the Continue's label.
 */
export default function RecommendedPlugins( { register, onChosen } ) {
	const { state, busy, hold, setError } = useSetup();
	const lists = state.ecosystem || { recommended: [], more: [] };
	const [ chosen, setChosen ] = useState( [] );
	const [ results, setResults ] = useState( {} );
	const [ working, setWorking ] = useState( null );
	const [ said, setSaid ] = useState( '' );

	const waiting = chosen.filter( ( slug ) => ! results[ slug ] || 'error' === results[ slug ].status );
	const installing = null !== working;

	useEffect( () => {
		onChosen?.( waiting.length );
	}, [ waiting.length ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const toggle = ( slug, on ) => setChosen( on ? [ ...chosen, slug ] : chosen.filter( ( item ) => item !== slug ) );

	/*
	 * One plugin at a time, in the order they appear. Each answer is kept
	 * against its row as it comes, so the screen shows the progress rather
	 * than a spinner that ends in a verdict. Resolves whether all went in.
	 */
	const installChosen = async () => {
		if ( ! waiting.length ) {
			return true;
		}

		const order = [ ...lists.recommended, ...lists.more ].map( ( plugin ) => plugin.slug ).filter( ( slug ) => waiting.includes( slug ) );
		const next = { ...results };
		let failures = 0;

		setError( null );

		await hold( 'ecosystem', async () => {
			for ( const slug of order ) {
				setWorking( slug );

				try {
					const answer = await request( ROUTES.install, { slug } );

					next[ slug ] = { status: answer?.status || 'installed' };
				} catch ( failure ) {
					next[ slug ] = { status: 'error', message: failureMessage( failure ) };
					failures++;
				}

				setResults( { ...next } );
			}
		} );

		setWorking( null );

		if ( failures ) {
			// Switched back off, so Continue goes on without them as the
			// message says; switching one on again tries it again.
			setChosen( ( list ) => list.filter( ( slug ) => 'error' !== next[ slug ]?.status ) );
			setSaid( '' );
			setError( {
				key: 'ecosystem',
				message: sprintf(
					/* translators: %d: number of plugins that could not be installed. */
					_n(
						'%d plugin could not be installed. The others are active, and you can continue.',
						'%d plugins could not be installed. The others are active, and you can continue.',
						failures,
						'bettershield'
					),
					failures
				),
			} );

			return false;
		}

		setSaid( __( 'Every plugin you chose is installed and active.', 'bettershield' ) );

		return true;
	};

	register?.( installChosen );

	if ( ! lists.recommended.length && ! lists.more.length ) {
		return null;
	}

	const rows = ( list ) =>
		list.map( ( plugin ) => (
			<PluginRow
				key={ plugin.slug }
				plugin={ plugin }
				chosen={ chosen.includes( plugin.slug ) }
				result={ results[ plugin.slug ] }
				working={ working === plugin.slug }
				locked={ installing || null !== busy }
				onToggle={ ( on ) => toggle( plugin.slug, on ) }
			/>
		) );

	const offNote = __( 'Off until you switch one on', 'bettershield' );
	const count = sprintf(
		/* translators: %d: number of plugins in the list. */
		_n( '%d plugin', '%d plugins', lists.more.length, 'bettershield' ),
		lists.more.length
	);

	return (
		<>
			{ lists.recommended.length ? (
				<PluginList id="bs-setup-eco-recommended" title={ __( 'Recommended for your site', 'bettershield' ) } note={ offNote }>
					{ rows( lists.recommended ) }
				</PluginList>
			) : null }

			{ lists.more.length ? (
				<PluginList id="bs-setup-eco-more" title={ __( 'More from WPDeveloper', 'bettershield' ) } note={ lists.recommended.length ? count : `${ offNote } · ${ count }` }>
					{ rows( lists.more ) }
				</PluginList>
			) : null }

			<div className="screen-reader-text" role="status" aria-live="polite">
				{ said }
			</div>
		</>
	);
}
