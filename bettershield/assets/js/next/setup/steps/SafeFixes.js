/**
 * Safe Fixes: five that cannot lock anybody out or break a page, first on
 * the Protect step (#2297).
 *
 * Each is ticked unless it is already on, and Protect's one Apply applies the
 * ticked ones, after the site's answers and the way back in. A fix already in
 * force — applied earlier, by another plugin, or in wp-config.php — says so
 * and is not applied again. Skip applies nothing.
 *
 * Before anything is applied, each fix that is not on says what it would do,
 * read from the same dry run the Hardening tab previews with. One that warns
 * of a conflict, or that this server cannot honor, starts unticked: a set
 * that breaks one site in a hundred is worse than applying them one by one.
 *
 * Nothing that touches signing in is here: those stay off until they are
 * chosen on the Hardening tab, where each has room to say what it could break.
 *
 * One card, a setting row per fix: its name, what it does, and its switch,
 * which is the tick the step's sentences speak of. A fix already in force says
 * where from under its line and carries a badge in place of the switch.
 */

import './SafeFixes.css';

import { useEffect, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Alert from '../../ui/Alert';
import Badge from '../../ui/Badge';
import { Card } from '../../ui/Card';
import SettingRow from '../../ui/Setting';
import { useSetup } from '../context';
import { request, ROUTES } from '../api';
import { keepHyphenated } from '../../../setup/format';
import brand from '../brand';

function sourceLine( fix ) {
	if ( 'wp-config' === fix.source ) {
		return __( 'Set in wp-config.php.', 'bettershield' );
	}

	if ( 'plugin' === fix.source && fix.source_name ) {
		/* translators: 1: the name of another security plugin, 2: this plugin's name. */
		return sprintf( __( 'Done by %1$s, so %2$s leaves it alone.', 'bettershield' ), fix.source_name, brand() );
	}

	// The "Already on" badge says it, and nothing more is known (#2840).
	if ( 'elsewhere' === fix.source ) {
		return null;
	}

	return sprintf( /* translators: %s: the plugin's name. */ __( 'Applied by %s. Undo it from Hardening at any time.', 'bettershield' ), brand() );
}

/**
 * Why one fix starts off, under its switch, if it does. What it would do (the
 * dry run's effect lines) is behind the row's "What it does".
 */
function Preview( { row } ) {
	return (
		<>
			{ ! row.available ? (
				<Alert layout="default" tone="warning" desc={ row.availability_note || __( 'This server cannot support this fix, so it stays off.', 'bettershield' ) } />
			) : null }
			{ row.available && row.conflict_warning ? (
				<Alert
					layout="default"
					tone="warning"
					desc={
						<>
							{ row.conflict_warning } { __( 'Left unticked so you can decide.', 'bettershield' ) }
						</>
					}
				/>
			) : null }
		</>
	);
}

/**
 * Whether the dry run has anything to say under a fix.
 *
 * @param {?Object} row The fix's preview, if it has one.
 * @return {boolean} Whether to draw it.
 */
function previews( row ) {
	return Boolean( row ) && ( ! row.available || Boolean( row.conflict_warning ) );
}

/**
 * What a fix would do here, as the row's one question.
 *
 * @param {?Object} row The fix's preview, if it has one.
 * @return {?Array} The row's topics, or nothing to ask.
 */
function whatItDoes( row ) {
	return row && row.effect.length ? [ { key: 'does', label: __( 'What it does', 'bettershield' ), points: row.effect } ] : null;
}

/**
 * Whether a fix in force was put there by this plugin, the usual case,
 * which the card says once rather than on every row.
 *
 * @param {Object} fix A fix.
 * @return {boolean} Whether BetterShield applied it.
 */
function ours( fix ) {
	return ! [ 'wp-config', 'plugin', 'elsewhere' ].includes( fix.source ) || ( 'plugin' === fix.source && ! fix.source_name );
}

/**
 * The line over the fixes an Apply did not apply. A fix held for its warning
 * was left off rather than failed, and "the rest are on" only when some were
 * applied.
 *
 * @param {Object}   problems Why each fix was not applied, by id.
 * @param {string[]} held     The fixes held for their warning.
 * @param {string[]} applied  The fixes that were applied.
 * @return {string} The line.
 */
function problemsLine( problems, held, applied ) {
	const ids = Object.keys( problems );
	const some = Array.isArray( applied ) && applied.length > 0;

	if ( ids.every( ( id ) => held.includes( id ) ) ) {
		return some
			? sprintf(
					/* translators: %d: number of fixes left off because of their warnings. */
					_n(
						'%d fix was left off because of its warning; the rest are on. Tick it to apply anyway.',
						'%d fixes were left off because of their warnings; the rest are on. Tick them to apply anyway.',
						ids.length,
						'bettershield'
					),
					ids.length
			  )
			: sprintf(
					/* translators: %d: number of fixes left off because of their warnings. */
					_n(
						'%d fix was left off because of its warning. Tick it to apply anyway.',
						'%d fixes were left off because of their warnings. Tick them to apply anyway.',
						ids.length,
						'bettershield'
					),
					ids.length
			  );
	}

	return some
		? __( 'Some fixes could not be applied; the rest are on. Try those again or skip them.', 'bettershield' )
		: sprintf(
				/* translators: %d: number of fixes that could not be applied. */
				_n( '%d fix could not be applied. Try it again, or skip it.', '%d fixes could not be applied. Try them again, or skip them.', ids.length, 'bettershield' ),
				ids.length
		  );
}

/**
 * @param {Object}   props
 * @param {Function} props.register  Given the apply Protect calls, which resolves whether it went through.
 * @param {Function} props.onSettled Told when the preview has answered, before which nothing is applied.
 * @param {Function} props.onChosen  Told which fixes are ticked, for the score Apply would reach.
 * @param {Function} props.onAttention Told whether a fix has something to say beside it: a warning, or a failure.
 * @param {Function} props.onControl   Given the switch for the whole set: on ticks every fix the preview vouched for, off none.
 */
export default function SafeFixes( { register, onSettled, onChosen, onAttention, onControl } ) {
	const { state, run, busy, setError } = useSetup();
	const fixes = state.fixes || [];
	const [ ticked, setTicked ] = useState( () => fixes.filter( ( fix ) => ! fix.on ).map( ( fix ) => fix.id ) );
	const [ failed, setFailed ] = useState( {} );
	const [ preview, setPreview ] = useState( {} );
	// Whether the preview has answered, either way. Until it has, nothing can
	// be ticked or applied: the ticks it holds back are the step's promise,
	// and an Apply pressed before them sent the fixes it promised to leave off.
	const [ settled, setSettled ] = useState( false );
	// The fixes whose conflict warning has been shown, from the preview or
	// from an Apply that held them. Ticked, they are sent as confirmed.
	const [ warned, setWarned ] = useState( [] );

	// What each fix would do, read once on arrival. A fix the preview holds
	// back is unticked then, and the owner may tick it again.
	useEffect( () => {
		let alive = true;

		request( ROUTES.previewFixes ).then(
			( answer ) => {
				if ( ! alive ) {
					return;
				}

				const byId = {};

				( answer && Array.isArray( answer.preview ) ? answer.preview : [] ).forEach( ( row ) => {
					byId[ row.id ] = row;
				} );

				setPreview( byId );
				setWarned( Object.keys( byId ).filter( ( id ) => byId[ id ].conflict_warning ) );
				setTicked( ( current ) => current.filter( ( id ) => ! byId[ id ] || byId[ id ].recommended ) );
				setSettled( true );
			},
			() => {
				if ( ! alive ) {
					return;
				}

				// Nothing vouched for any of them, so none stays ticked.
				setTicked( [] );
				setSettled( true );
				setError( {
					key: 'fixes',
					message: __( 'Fix details could not be loaded, so none is ticked. Tick the ones you want or skip.', 'bettershield' ),
				} );
			}
		);

		return () => {
			alive = false;
		};
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [] );

	useEffect( () => {
		onSettled?.( settled );
	}, [ settled ] ); // eslint-disable-line react-hooks/exhaustive-deps

	const pending = fixes.filter( ( fix ) => ! fix.on );
	const chosen = ticked.filter( ( id ) => pending.some( ( fix ) => fix.id === id ) );

	useEffect( () => {
		onChosen?.( chosen );
	}, [ chosen.join( ' ' ) ] ); // eslint-disable-line react-hooks/exhaustive-deps

	// A warning or a failure is said beside its fix, which has to be in view.
	const attention = Object.keys( failed ).length > 0 || pending.some( ( fix ) => previews( preview[ fix.id ] ) );

	useEffect( () => {
		onAttention?.( attention );
	}, [ attention ] ); // eslint-disable-line react-hooks/exhaustive-deps

	// The set's one switch, on Protect's row: every fix the preview vouched
	// for, or none. A fix held for its warning is ticked one by one.
	onControl?.( ( on ) => setTicked( on ? pending.filter( ( fix ) => ! preview[ fix.id ] || preview[ fix.id ].recommended ).map( ( fix ) => fix.id ) : [] ) );

	const toggle = ( id, on ) => setTicked( on ? [ ...ticked, id ] : ticked.filter( ( item ) => item !== id ) );

	// The ticked fixes, resolving whether every one went through.
	const apply = () => {
		if ( ! chosen.length ) {
			return Promise.resolve( true );
		}

		return run( 'fixes', ROUTES.fixes, { items: chosen, confirm: chosen.filter( ( id ) => warned.includes( id ) ) } ).then( ( answer ) => {
			if ( ! answer ) {
				return false;
			}

			const held = Array.isArray( answer.held ) ? answer.held : [];

			// Held because of a warning the screen had not shown yet: shown
			// now, beside the fix, and unticked, so it stays off unless it is
			// ticked again, which confirms it.
			if ( held.length ) {
				setWarned( ( current ) => [ ...new Set( [ ...current, ...held ] ) ] );
				setTicked( ( current ) => current.filter( ( id ) => ! held.includes( id ) ) );
			}

			const problems = answer.failed || {};

			setFailed( problems );

			if ( Object.keys( problems ).length ) {
				setError( { key: 'fixes', message: problemsLine( problems, held, answer.applied ) } );

				return false;
			}

			return true;
		} );
	};

	register?.( apply );

	return (
		<>
			<Card as="ul" className="bs-ds-setup-fixes">
				{ fixes.map( ( fix ) => (
					<li key={ fix.id } className={ `bs-ds-setup-fixes__item${ fix.on ? ' is-on' : '' }${ failed[ fix.id ] ? ' is-problem' : '' }` }>
						{ fix.on ? (
							<SettingRow
								title={ fix.title }
								about={ fix.description }
								tip={ fix.detail || null }
								meta={ ours( fix ) ? null : sourceLine( fix ) }
								control={
									<Badge tone="brand" icon="check">
										{ __( 'Already on', 'bettershield' ) }
									</Badge>
								}
							/>
						) : (
							<SettingRow
								title={ fix.title }
								about={ fix.description }
								tip={ fix.detail || null }
								topics={ whatItDoes( preview[ fix.id ] ) }
								toggle={ {
									checked: ticked.includes( fix.id ),
									disabled: null !== busy || ! settled || false === preview[ fix.id ]?.available,
									onChange: ( on ) => toggle( fix.id, on ),
								} }
							>
								{ previews( preview[ fix.id ] ) || failed[ fix.id ] ? (
									<>
										{ previews( preview[ fix.id ] ) ? <Preview row={ preview[ fix.id ] } /> : null }
										{ failed[ fix.id ] ? (
											<p className="bs-ds-setup__problem" role="status">
												{ failed[ fix.id ] }
											</p>
										) : null }
									</>
								) : null }
							</SettingRow>
						) }
					</li>
				) ) }
			</Card>

			{ fixes.some( ( fix ) => fix.on && ours( fix ) ) ? <p className="bs-ds-setup__note">{ sprintf( /* translators: %s: the plugin's name. */ __( '%s applied the fixes already on. Undo any of them in Hardening.', 'bettershield' ), brand() ) }</p> : null }

			{ /*
			   The sign-in address is drawn on Login & Access, not Hardening.
			   Said, not linked: a link here invited leaving the setup half done.
			   As wide as the card above it, and "sign-in" kept on one line (#2304).
			   The two options first, then the lock-out risk, which stays visible;
			   short, as Ready says it again a screen later (#2840).
			*/ }
			<p className="bs-ds-setup__note bs-ds-setup__note--wide">
				{ keepHyphenated( __( 'Left off for now: a custom sign-in address and Strict HTTPS (HSTS). A mistake with either can lock people out.', 'bettershield' ) ) }
			</p>
		</>
	);
}
