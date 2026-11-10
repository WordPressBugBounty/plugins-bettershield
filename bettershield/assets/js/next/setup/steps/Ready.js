/**
 * Ready, the Ecosystem step: what is in place on this site now, kept short,
 * then the plugins.
 *
 * Every line is read from the site after the setup finished, never from what
 * the setup remembers doing, and a line appears only when it applies here. The
 * grade is the audit's, as it stands, with where this run of the setup found
 * it and the points the setup earned; there is no meter and no distance to a
 * perfect score.
 *
 * The grade's move at the heading's other end; then everything the setup
 * changed in one folded list, every undo inside it: the
 * fixes as switches with the set's own undo, who handles sign-in and
 * two-factor, what was brought over or switched off, the names refused, and
 * the options it left off. What was chosen a step earlier and changed nothing
 * (usage data, where alerts go) is not said again. Then the plugins, each with
 * its own switch. The ways on are the footer's, as every step's way on is: no
 * offer, no upgrade, no sharing (#2297).
 */

import './Ready.css';

import { createInterpolateElement, useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import Badge from '../../ui/Badge';
import Button from '../../ui/Button';
import { Card } from '../../ui/Card';
import { useFocusAfter } from '../../ui/focus';
import Icon, { NOTE_ICON } from '../../ui/Icon';
import { Toggle } from '../../ui/Setting';
import Skeleton, { CardBone } from '../../ui/Skeleton';
import Disclosure from '../Disclosure';
import Frame, { Footer } from '../Frame';
import ScoreMove from '../ScoreMove';
import { useSetup } from '../context';
import { ROUTES } from '../api';
import viaCore from '../core';
import RecommendedPlugins from './Ecosystem';
import { keepHyphenated, listOf } from '../../../setup/format';
import brand from '../brand';

function Line( { on = true, children, extra, headRef } ) {
	return (
		<li className={ `bs-ds-setup-ready__line${ on ? '' : ' is-off' }` }>
			<Icon name={ on ? 'circle-check' : 'circle-dashed' } size={ 16 } tone={ on ? 'ok' : '3' } className="bs-ds-setup-ready__mark" />
			<div className="bs-ds-setup-ready__text">
				{ headRef ? (
					<span ref={ headRef } tabIndex={ -1 } className="bs-ds-setup-ready__head">
						{ children }
					</span>
				) : (
					children
				) }
				{ extra }
			</div>
		</li>
	);
}

/**
 * How many safe fixes setup turned on.
 *
 * Counted from what setup applied: a fix already on was counted as applied,
 * "5 of 5" under "what setup turned on" while the set's own undo named four
 * (#2059). Not from the set alone, which undoing the set clears: a fix
 * switched back on here after that was counted as already on (#2248). An
 * answer with neither counts what is on.
 *
 * @param {Object} fixes The summary's fixes: on, total, the set and what setup applied.
 * @return {{applied: number, already: number}} Turned on by setup, and on before it.
 */
function fixCounts( fixes ) {
	let record = null;

	if ( Array.isArray( fixes.applied ) ) {
		record = fixes.applied;
	} else if ( Array.isArray( fixes.set ) ) {
		record = fixes.set;
	}

	const applied = record ? record.length : fixes.on;

	return { applied, already: record ? Math.max( 0, fixes.on - applied ) : 0 };
}

/**
 * How many safe fixes setup turned on, and how many were on before it.
 *
 * @param {Object} fixes The summary's fixes.
 * @return {string} The line.
 */
function appliedLine( fixes ) {
	const { applied, already } = fixCounts( fixes );

	// None applied is said plainly: "0 of 5" read as a failed score (#2841).
	if ( ! applied ) {
		return already > 0
			? sprintf(
					/* translators: %d: safe fixes that were on before setup. */
					_n( 'No safe fixes applied. %d was already on.', 'No safe fixes applied. %d were already on.', already, 'bettershield' ),
					already
			  )
			: __( 'No safe fixes applied.', 'bettershield' );
	}

	if ( already > 0 ) {
		return sprintf(
			/* translators: 1: fixes setup turned on, 2: fixes offered, 3: fixes that were on before setup. */
			_n( 'Safe fixes applied: %1$d of %2$d, and %3$d was already on', 'Safe fixes applied: %1$d of %2$d, and %3$d were already on', already, 'bettershield' ),
			applied,
			fixes.total,
			already
		);
	}

	return sprintf(
		/* translators: 1: fixes on, 2: fixes offered. */
		__( 'Safe fixes applied: %1$d of %2$d', 'bettershield' ),
		applied,
		fixes.total
	);
}

/**
 * One fix BetterShield applied, as a switch named by the fix: its state, and
 * the way to turn it off and back on, in one control.
 *
 * @param {Object}   props
 * @param {Object}   props.fix      The fix from the summary.
 * @param {boolean}  props.disabled Whether the switch is held.
 * @param {Function} props.onChange Called with the switch's new state.
 */
function FixSwitch( { fix, disabled, onChange } ) {
	const id = `bs-ds-setup-fix-${ fix.id }`;

	return (
		<>
			<span id={ id } className="bs-ds-setup-ready__fix">
				{ fix.title }
			</span>
			<Toggle checked={ !! fix.on } disabled={ disabled } labelledBy={ id } onChange={ ( event ) => onChange( Boolean( event && event.target ? event.target.checked : event ) ) } />
		</>
	);
}

function coexistenceWords( row ) {
	const names = listOf( row.plugins );
	const ours = 'bettershield' === row.choice;

	switch ( row.job ) {
		case 'login_limits':
			return ours
				? sprintf( /* translators: %s: the plugin's name. */ __( '%s limits sign-in attempts', 'bettershield' ), brand() )
				: sprintf(
						/* translators: %s: one or more plugin names. */
						_n( '%s limits sign-in attempts', '%s limit sign-in attempts', row.plugins.length, 'bettershield' ),
						names
				  );
		case 'two_factor':
			return ours
				? sprintf( /* translators: %s: the plugin's name. */ __( '%s handles two-factor', 'bettershield' ), brand() )
				: sprintf(
						/* translators: %s: one or more plugin names. */
						_n( '%s handles two-factor', '%s handle two-factor', row.plugins.length, 'bettershield' ),
						names
				  );
		default:
			return '';
	}
}

export default function Ready() {
	const { state, run, hold, busy, links, refresh, visible, next } = useSetup();
	const toHub = visible.includes( 'hub' );
	// The recommended plugins switched on, installed by Continue before it
	// moves on; how many, for its label.
	const install = useRef( null );
	const [ chosen, setChosen ] = useState( 0 );
	const summary = state.summary;
	const fixesRef = useRef( null );
	const [ said, setSaid ] = useState( '' );
	// Fixes switched off here stay on the list, so they can be switched back.
	const [ offHere, setOffHere ] = useState( [] );
	const [ applying, setApplying ] = useState( null );
	const [ changesOpen, setChangesOpen ] = useState( false );
	// The switch is held while it works, which takes the keyboard to the
	// page; once it lets go, the keyboard comes back to the line, as an undo
	// does. Read after that render, not in the request's finally, where the
	// line may be one that has since been drawn again (#2028).
	useFocusAfter( null !== applying, fixesRef );

	/*
	 * An Undo takes its own button away with the line it was on, so focus
	 * would fall to the page. It goes to the line that counts the fixes
	 * instead, and the change is said out loud.
	 */
	const undo = ( fix ) =>
		run( `undo-${ fix.id }`, ROUTES.undoFix( fix.id ) ).then( ( answer ) => {
			if ( answer ) {
				setOffHere( ( ids ) => ( ids.includes( fix.id ) ? ids : [ ...ids, fix.id ] ) );
				setSaid(
					sprintf(
						/* translators: %s: the fix's name. */
						__( 'Turned off: %s', 'bettershield' ),
						fix.title
					)
				);
				fixesRef.current?.focus();
			}
		} );

	/*
	 * A fix switched off here, switched back on through the same route the
	 * Safe Fixes step applies with, which answers this switch with the summary
	 * the step draws. A fix whose warning has to be read first is held by the
	 * server and stays off, and the line says where to turn it on instead.
	 *
	 * Through run(), so a refusal is said in the frame's alert as every other
	 * write's is: sent directly, a failure was swallowed and the switch only
	 * sprang back.
	 */
	const reapply = ( fix ) => {
		setApplying( fix.id );

		return run( `reapply-${ fix.id }`, ROUTES.fixes, { items: [ fix.id ], confirm: [], rejoin: true } )
			.then( ( answer ) => {
				if ( ! answer ) {
					return;
				}

				const now = ( answer?.state?.summary?.fixes?.items || [] ).find( ( item ) => item.id === fix.id );

				setSaid(
					now && now.on
						? sprintf(
								/* translators: %s: the fix's name. */
								__( 'Turned back on: %s', 'bettershield' ),
								fix.title
						  )
						: sprintf(
								/* translators: %s: the fix's name. */
								__( '%s couldn’t be turned on here. Turn it on in Hardening, which shows what it changes before you confirm.', 'bettershield' ),
								fix.title
						  )
				);
			} )
			.finally( () => setApplying( null ) );
	};

	/*
	 * The whole set back at once, newest first, by the token each fix was
	 * applied under. A fix left as it is is named with the server's own
	 * reason: changed since, already undone, or held by another change for a
	 * moment. One sentence for all three told an owner whose fixes were only
	 * waiting that they had changed.
	 */
	const undoSet = () =>
		run( 'undo-set', ROUTES.undoSet, {} ).then( ( answer ) => {
			if ( ! answer ) {
				return;
			}

			const title = ( id ) => ( summary.fixes.items.find( ( fix ) => fix.id === id ) || { title: id } ).title;

			// They stay on the list, switched off, as a fix undone with its
			// own switch does: they went from it and could not be put back
			// here (#1923).
			setOffHere( ( ids ) => [ ...ids, ...( answer.reverted || [] ).filter( ( id ) => ! ids.includes( id ) ) ] );
			const left = Object.entries( answer.skipped || {} ).map( ( [ id, why ] ) =>
				sprintf(
					/* translators: 1: a fix, 2: why it was left as it is. */
					__( '%1$s: %2$s', 'bettershield' ),
					title( id ),
					why
				)
			);
			const done = sprintf(
				/* translators: %d: number of fixes undone. */
				_n( 'Turned off %d fix.', 'Turned off %d fixes.', ( answer.reverted || [] ).length, 'bettershield' ),
				( answer.reverted || [] ).length
			);

			setSaid( left.length ? `${ done } ${ __( 'Not changed:', 'bettershield' ) } ${ left.join( ' ' ) }` : done );
			fixesRef.current?.focus();
		} );

	// Opened straight onto Ready — a reload — the summary is read on arrival.
	useEffect( () => {
		if ( ! summary ) {
			refresh();
		}
	}, [] ); // eslint-disable-line react-hooks/exhaustive-deps

	if ( ! summary ) {
		return (
			// Nothing is known yet about what setup turned on, so the heading
			// claims nothing either way.
			<Frame title={ __( 'Ecosystem', 'bettershield' ) } subtitle={ __( 'Reading what is in place on this site…', 'bettershield' ) }>
				<Skeleton label={ __( 'Reading what is in place on this site…', 'bettershield' ) }>
					<CardBone rows={ [ '40%', '65%', '55%', '70%' ] } />
				</Skeleton>
			</Frame>
		);
	}

	const fixes = summary.fixes;
	const choices = ( summary.coexistence || [] ).filter( ( row ) => 'choice' === row.kind );

	/*
	 * Every step skipped, or left as it was: no fix on, no way back in
	 * confirmed, no two-factor of the owner's own. The heading called the
	 * site protected and the line under it pointed at what setup turned on,
	 * above "Safe fixes applied: 0 of 5".
	 */
	const refused = summary.common_names || [];
	// A choice that hands a job to BetterShield, and a plugin the Ecosystem
	// step installed, are things the setup did too (#2117).
	const installed = summary.installed || [];
	// What Coexistence brought over from another plugin, and the plugins
	// switched off from its Deactivate that are still off (#1964).
	const imported = summary.imported || [];
	const deactivated = summary.deactivated || [];
	const reactivate = summary.reactivate || [];
	const handedOver = choices.some( ( row ) => 'bettershield' === row.choice );
	// The other plugins two-factor is left with, as the summary lists them.
	const elsewhere = String( ( summary.two_factor || {} ).handled_by || '' )
		.split( ', ' )
		.filter( Boolean );
	// A fix that was on before setup ran is not one setup turned on: the
	// heading claimed it, and "0 of 5" carried a check (#2248).
	const { applied } = fixCounts( fixes );
	const nothing = ! applied && ! summary.recovery && ! ( summary.two_factor || {} ).enrolled && ! refused.length && ! handedOver && ! installed.length && ! imported.length && ! deactivated.length;

	// The first file check can still move the score, so the figure waits.
	const scanning = Boolean( summary.first_scan && summary.first_scan.running );
	// The points this run of the setup added, where it read the score first.
	const earned = summary.before ? summary.score - summary.before.score : 0;
	const gradeWords =
		earned > 0
			? sprintf(
					/* translators: 1: a letter grade, A to F, 2: points the setup added to the score. */
					__( 'Security grade: %1$s, %2$d points from Setup', 'bettershield' ),
					summary.grade,
					earned
			  )
			: sprintf(
					/* translators: %s: a letter grade, A to F. */
					__( 'Security grade: %s', 'bettershield' ),
					summary.grade
			  );

	// A plugin switched off took its protections with it, which the score the
	// setup counts from already reflects: said, so it matches what came before.
	let subtitle = nothing ? __( 'Nothing was turned on. See the Overview for your score and next steps.', 'bettershield' ) : null;

	// What happened, why, then the next action, with the plugins named as
	// the Deactivated line below names them (#2841).
	if ( null !== ( summary.found ?? null ) && summary.before && ! scanning && deactivated.length ) {
		subtitle = sprintf(
			/* translators: 1: the score before, 2: the score after, 3: the plugins switched off, e.g. "Plugin One and Plugin Two". */
			_n(
				'Your score went from %1$d to %2$d because %3$s is off. See the Overview for what to do next.',
				'Your score went from %1$d to %2$d because %3$s are off. See the Overview for what to do next.',
				deactivated.length,
				'bettershield'
			),
			summary.found,
			summary.before.score,
			listOf( deactivated )
		);
	}

	// Everything the setup changed, each with its undo where it has one.
	const changes = [
		...choices.map( ( row ) => <Line key={ `choice:${ row.job }` }>{ coexistenceWords( row ) }</Line> ),
		...imported.map( ( row ) => (
			<Line key={ `imported:${ row.name }` }>
				{ sprintf(
					/* translators: 1: how many settings, 2: a plugin's name. */
					_n( 'Brought over %1$d setting from %2$s', 'Brought over %1$d settings from %2$s', row.count, 'bettershield' ),
					row.count,
					row.name
				) }
			</Line>
		) ),
		deactivated.length ? (
			<Line
				key="deactivated"
				extra={
					reactivate.some( ( entry ) => entry.activate_url ) ? (
						<div className="bs-ds-setup-ready__back">
							{ /* The way back the Coexistence card promised: WordPress's
							     own Activate, as its in-place Deactivate offers (#2610). */ }
							{ reactivate
								.filter( ( entry ) => entry.activate_url )
								.map( ( entry ) => (
									<Button
										key={ entry.file }
										type="secondary"
										size="sm"
										isBusy={ `activate:${ entry.file }` === busy }
										disabled={ null !== busy }
										accessibleWhenDisabled={ `activate:${ entry.file }` === busy }
										onClick={ () => hold( `activate:${ entry.file }`, () => viaCore( entry.activate_url ).then( () => refresh() ) ) }
										/* translators: %s: a plugin's name. */
										aria-label={ sprintf( __( 'Turn %s Back On', 'bettershield' ), entry.name ) }
									>
										{ reactivate.filter( ( other ) => other.activate_url ).length > 1
											? /* translators: %s: the plugin name. */
											  sprintf( __( 'Turn %s Back On', 'bettershield' ), entry.name )
											: __( 'Turn It Back On', 'bettershield' ) }
									</Button>
								) ) }
						</div>
					) : null
				}
			>
				{ sprintf(
					/* translators: %s: one or more plugin names. */
					__( 'Deactivated: %s', 'bettershield' ),
					listOf( deactivated )
				) }
			</Line>
		) : null,
		installed.length ? (
			<Line key="installed">
				{ sprintf(
					/* translators: %s: one or more plugin names. */
					__( 'Installed and activated: %s', 'bettershield' ),
					listOf( installed )
				) }
			</Line>
		) : null,
		summary.recovery ? <Line key="recovery">{ __( 'Account recovery is set up', 'bettershield' ) }</Line> : null,
		refused.length ? (
			<Line key="names">
				{ sprintf(
					/* translators: %s: usernames, e.g. "administrator, root, test". */
					__( 'Usernames blocked at sign-in: %s', 'bettershield' ),
					refused.join( ', ' )
				) }
			</Line>
		) : null,
		/*
		 * Another plugin's two-factor is the site as it was, not a change, and
		 * a Coexistence choice to keep it has its own line above: listed alone
		 * under "Each can be undone" it read as something Setup did (#2841).
		 * Beside the owner's own enrollment it is said on that one line, so the
		 * two do not read as disagreeing about who asks for codes.
		 */
		summary.two_factor.enrolled ? (
			<Line key="enrolled">
				{ elsewhere.length
					? sprintf(
							/* translators: %s: one or more plugin names, e.g. "Two Factor" or "Two Factor and WP 2FA". */
							_n(
								'Two-factor set up for your account. %s also asks for codes on this site.',
								'Two-factor set up for your account. %s also ask for codes on this site.',
								elsewhere.length,
								'bettershield'
							),
							listOf( elsewhere )
					  )
					: __( 'Two-factor set up for your account', 'bettershield' ) }
			</Line>
		) : null,
		summary.two_factor.required ? (
			<Line key="required">
				{ sprintf(
					/* translators: %d: number of days. */
					_n(
						'Two-factor required for administrators within %d day',
						'Two-factor required for administrators within %d days',
						summary.two_factor.grace_days,
						'bettershield'
					),
					summary.two_factor.grace_days
				) }
			</Line>
		) : null,
		<Line
			key="fixes"
			on={ applied > 0 }
			headRef={ fixesRef }
			extra={
				fixes.on || offHere.length ? (
					<ul className="bs-ds-setup-ready__fixes">
						{ /* Each fix as a switch that shows its state and
						     turns it off and back on in place. */ }
						{ fixes.items
							.filter( ( fix ) => fix.on || offHere.includes( fix.id ) )
							.map( ( fix ) => (
								<li key={ fix.id }>
									{ fix.ours || offHere.includes( fix.id ) ? (
										<FixSwitch fix={ fix } disabled={ null !== busy || null !== applying } onChange={ ( on ) => ( on ? reapply( fix ) : undo( fix ) ) } />
									) : (
										<>
											<span className="bs-ds-setup-ready__fix">{ fix.title }</span>
											<Badge>{ __( 'Already on', 'bettershield' ) }</Badge>
										</>
									) }
								</li>
							) ) }
						{ ( fixes.set || [] ).length > 1 ? (
							<li className="bs-ds-setup-ready__set">
								<Button type="secondary" size="sm" isBusy={ 'undo-set' === busy } disabled={ null !== busy } onClick={ undoSet }>
									{ /*
									   Says what pressing it does, and how many (#1923). The names
									   are the switches just above, so the label does not repeat
									   them; "Quick Setup applied" keeps the fixes that were on
									   before it out of the count (#2306).
									*/ }
									{ sprintf(
										/* translators: %d: how many safe fixes Quick Setup turned on, always two or more. */
										_n( 'Turn Off the %d Fix Quick Setup Applied', 'Turn Off All %d Fixes Quick Setup Applied', fixes.set.length, 'bettershield' ),
										fixes.set.length
									) }
								</Button>
							</li>
						) : null }
					</ul>
				) : null
			}
		>
			{ appliedLine( fixes ) }
		</Line>,
	].filter( Boolean );

	/*
	 * How many settings the setup changed, for the fold's count: the fixes
	 * line stands for each fix it turned on, every other line for one. It
	 * counted lines, so four fixes read as "(1)" (#2631).
	 */
	const changedCount = changes.reduce( ( sum, line ) => sum + ( 'fixes' === line.key ? applied : 1 ), 0 );

	// "Nothing was turned on" only over an empty list: above "What Setup
	// changed (1)" it contradicted the count (#2841).
	if ( nothing && changedCount > 0 && subtitle ) {
		subtitle = __( 'See the Overview for your score and next steps.', 'bettershield' );
	}

	return (
		<Frame
			title={ __( 'Ecosystem', 'bettershield' ) }
			subtitle={ subtitle }
			aside={
				<span className="bs-ds-setup-ready__grade">
					{ scanning ? (
						<span role="status">{ __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) }</span>
					) : (
						<ScoreMove from={ summary.before || { score: summary.score, grade: summary.grade } } to={ { score: summary.score, grade: summary.grade } } label={ gradeWords } />
					) }
					{ earned > 0 ? (
						<span className="bs-ds-setup__head-note" aria-hidden="true">
							{ sprintf(
								/* translators: %d: points the setup added to the score. */
								__( '+%d from Setup', 'bettershield' ),
								earned
							) }
						</span>
					) : null }
				</span>
			}
			footer={
				<Footer
					noSkip
					primary={
						toHub
							? {
									label: chosen ? __( 'Install & Continue', 'bettershield' ) : __( 'Continue', 'bettershield' ),
									onClick: () => ( install.current ? install.current() : Promise.resolve( true ) ).then( ( done ) => done && next() ),
									busy: 'ecosystem' === busy,
							  }
							: null
					}
				>
					{ toHub ? null : (
						<Button type="primary" size="md" href={ links.dashboard }>
							{ __( 'Go to Overview', 'bettershield' ) }
						</Button>
					) }
				</Footer>
			}
		>
			<Card as="div" className="bs-ds-setup-ready__block">
				<Disclosure
					className="bs-ds-setup-ready__changes"
					label={ sprintf(
						/* translators: %d: how many things the setup changed. */
						__( 'What Setup changed (%d)', 'bettershield' ),
						changedCount
					) }
					summary={ changedCount > 0 ? __( 'Each can be undone', 'bettershield' ) : undefined }
					open={ changesOpen }
					onToggle={ setChangesOpen }
				>
					<ul className="bs-ds-setup-ready__lines bs-ds-setup-ready__lines--plain">{ changes }</ul>

					<p className="bs-ds-setup-ready__off">
						<Icon name={ NOTE_ICON } size={ 14 } tone="3" />
						{ /*
						   What Setup left alone, where each is, and why (#2291); "sign-in"
						   kept on one line (#2304). Short, since Protect said it a screen
						   earlier (#2841).
						*/ }
						<span>
							{ createInterpolateElement(
								keepHyphenated(
									/* translators: <login> and <hardening> wrap links to those screens; <new /> is "(opens in a new tab)" for screen readers. */
									__( 'Left off: a custom sign-in address on <login>Login & Access<new /></login>, and Strict HTTPS (HSTS) on <hardening>Hardening<new /></hardening>. A mistake with either can lock people out.', 'bettershield' )
								),
								{
									// In a new tab, as the other in-step links: the
									// same tab left the setup before the Hub step (#2656).
									login: <a href={ links.login } target="_blank" rel="noopener noreferrer" />,
									hardening: <a href={ links.hardening } target="_blank" rel="noopener noreferrer" />,
									new: <span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span>,
								}
							) }
						</span>
					</p>
				</Disclosure>
			</Card>

			<p className="screen-reader-text" role="status">
				{ said }
			</p>

			<RecommendedPlugins
				register={ ( installChosen ) => {
					install.current = installChosen;
				} }
				onChosen={ setChosen }
			/>
		</Frame>
	);
}
