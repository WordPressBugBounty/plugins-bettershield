/**
 * The setup's frame: where it is and how to move. There is no way out of the
 * whole setup at once: every step has its own Skip, and the admin menu beside
 * the page is always there.
 *
 * Moving between steps never reloads the page, so two things the browser
 * would have done are done here: focus goes to the new step's heading, and a
 * screen reader is told which step of how many it is on. The first paint does
 * neither — taking focus from somebody who has just opened a page is its own
 * failure.
 *
 * Every write goes through `run`, which puts the site's answer back on screen
 * and, where the owner has asked for their password before anything is taken
 * away, asks for it and tries once more. While one is working the stepper is
 * held with the footer, and a step the owner has left can neither move them
 * on nor show its error on the step they are on now.
 *
 * Drawn as the design's main panel on the page's own background: the steps
 * along its top as a tab row, the open step under them, and its way on in a
 * bar along the foot.
 */

import './Wizard.css';

import { useCallback, useEffect, useMemo, useRef, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import Button from '../ui/Button';
import ConfirmPassword from './ConfirmPassword';
import { focusIfLost } from '../ui/focus';
import { useFirstScan } from '../data/firstScan';
import Stepper from './Stepper';
import { SetupContext } from './context';
import { failureMessage, needsPassword, pageModel, request, ROUTES } from './api';
import { canVisit, nextStep, previousStep, resumeAt, visibleSteps } from './steps';
import Welcome from './steps/Welcome';
import Coexistence from './steps/Coexistence';
import Protect from './steps/Protect';
import Ready from './steps/Ready';
import HubStep from './steps/HubStep';
import brand from './brand';

const VIEWS = {
	welcome: Welcome,
	coexistence: Coexistence,
	protect: Protect,
	ready: Ready,
	hub: HubStep,
};

export default function Wizard() {
	const [ model ] = useState( pageModel );
	const links = model.links || {};
	const [ state, setState ] = useState( model.state || null );
	// Whether this visit opened a setup that was already finished. Read once:
	// finishing it again must not start calling the visit a re-run.
	const [ rerun ] = useState( Boolean( model.state?.rerun ) );
	/*
	 * A step whose own action took it out of the setup (the last other
	 * security plugin switched off on Coexistence) stays on screen, done,
	 * until the owner moves on: the wizard never jumps away under them
	 * (#2133). Moving anywhere lets it go.
	 */
	const [ stay, setStay ] = useState( null );
	const steps = useMemo( () => {
		const named = state?.steps || [];

		return visibleSteps( stay && ! named.includes( stay ) ? [ ...named, stay ] : named );
	}, [ state?.steps, stay ] );
	const visible = useMemo( () => steps.map( ( step ) => step.slug ), [ steps ] );
	const [ current, setCurrent ] = useState( () => resumeAt( state?.step, visible ) );
	// The steps passed by Skip rather than finished: the stepper draws them
	// apart, and the site keeps them with where the owner is.
	const [ skippedSteps, setSkippedSteps ] = useState( () => model.state?.skipped_steps || [] );
	const [ busy, setBusy ] = useState( null );
	const [ error, setError ] = useState( null );
	const [ held, setHeld ] = useState( null );
	const [ announcement, setAnnouncement ] = useState( '' );
	const headingRef = useRef( null );
	// What the last action did, said at the top of the step on screen: a
	// step that went away because of it (the last other security plugin
	// switched off) hands the sentence to the one that opens next.
	const [ notice, setNotice ] = useState( null );
	// An action done on the step can take away the control that was pressed
	// (Unmute alerts, Unblock, Deactivate), which drops focus on the page.
	// Once the step has redrawn, its heading takes it (#2108).
	const [ redrawn, setRedrawn ] = useState( 0 );
	const keepFocus = useCallback( () => setRedrawn( ( count ) => count + 1 ), [] );
	useEffect( () => {
		if ( redrawn ) {
			focusIfLost( headingRef.current );
		}
	}, [ redrawn ] );
	const settled = useRef( false );
	// The step on screen, for answers that arrive after the owner moved.
	const shown = useRef( current );

	/*
	 * One write at a time, keyed so the control that asked can show it is
	 * working. Resolves with the route's answer, or null when it did not
	 * complete — the step decides what to do with either.
	 */
	const run = useCallback( ( key, path, data ) => {
		const from = shown.current;

		setBusy( key );
		setError( null );

		const attempt = () =>
			request( path, data || {} ).then( ( answer ) => {
				if ( answer && answer.state ) {
					setState( answer.state );
				}

				return answer;
			} );

		return attempt()
			.catch(
				( failure ) =>
					new Promise( ( resolve ) => {
						if ( shown.current !== from ) {
							resolve( null );

							return;
						}

						if ( needsPassword( failure ) ) {
							setHeld( { key, attempt, resolve } );

							return;
						}

						// The code and the fields it names as well, so a step
						// can say a refusal beside the field it is about.
						setError( {
							key,
							message: failureMessage( failure ),
							code: failure && failure.code ? String( failure.code ) : '',
							params: failure && failure.data && failure.data.params ? failure.data.params : null,
						} );
						resolve( null );
					} )
			)
			.finally( () => setBusy( null ) );
	}, [] );

	/*
	 * Work a step runs itself rather than through `run` holds the same lock,
	 * so the stepper and the footer wait for it too.
	 */
	const hold = useCallback( ( key, work ) => {
		setBusy( key );

		return Promise.resolve()
			.then( work )
			.finally( () => setBusy( null ) );
	}, [] );

	/*
	 * Read the whole setup again, for the writes that go to another screen's
	 * routes and so do not answer with it.
	 */
	const refresh = useCallback(
		() =>
			request()
				.then( ( answer ) => {
					if ( answer && answer.state ) {
						setState( answer.state );
					}

					return answer;
				} )
				.catch( () => null ),
		[]
	);

	// The first file check runs while any step is open, so no step shows a score it could still move.
	useFirstScan( state ? state.first_scan : null, refresh );

	/*
	 * `passed` is the step left behind on the way forward, and whether it was
	 * left by Skip; moving back, or opening a step from the stepper, passes
	 * nothing.
	 */
	const go = useCallback( ( slug, passed = null ) => {
		if ( ! slug ) {
			return;
		}

		setError( null );
		setNotice( null );
		setStay( null );
		setCurrent( slug );

		if ( passed ) {
			setSkippedSteps( ( list ) => [ ...list.filter( ( step ) => step !== passed.step ), ...( passed.skipped ? [ passed.step ] : [] ) ] );
		}

		// Where to resume if the owner leaves now. Nothing waits on it: a
		// step that fails to save is only a step the next visit repeats.
		request( ROUTES.step, { step: slug, ...( passed ? { passed: passed.step, skipped: passed.skipped } : {} ) } ).catch( () => {} );
	}, [] );

	// Strictly true: these are handed to buttons as click handlers, and an
	// event is truthy.
	const next = useCallback(
		( skipped = false ) => go( nextStep( current, visible ), { step: current, skipped: true === skipped } ),
		[ go, current, visible ]
	);
	const back = useCallback( () => go( previousStep( current, visible ) ), [ go, current, visible ] );

	/*
	 * The last step before Ready finishes the setup, and Ready reads the site
	 * as it is afterwards. Finishing first means the summary can never claim a
	 * setup is done that the site does not have on record as done.
	 */
	const finish = useCallback( ( skipped = false ) => {
		const from = shown.current;

		run( 'complete', ROUTES.complete, { skipped: false } ).then( ( answer ) => {
			if ( answer && shown.current === from ) {
				go( 'ready', { step: from, skipped: true === skipped } );
			}
		} );
	}, [ run, go ] );

	// Only from the step that is open: a step's answer that arrives after
	// the owner went back somewhere else moves nobody.
	const advance = useCallback( ( skipped = false ) => {
		if ( shown.current !== current ) {
			return;
		}

		if ( 'ready' === nextStep( current, visible ) ) {
			finish( true === skipped );
		} else {
			next( true === skipped );
		}
	}, [ current, visible, finish, next ] );

	// The same move, as a Skip: the step is passed without being finished.
	const skip = useCallback( () => advance( true ), [ advance ] );

	useEffect( () => {
		const index = visible.indexOf( current );
		const step = steps[ index ];

		shown.current = current;

		if ( ! settled.current ) {
			settled.current = true;

			return;
		}

		setAnnouncement(
			step
				? sprintf(
						/* translators: 1: step number, 2: number of steps, 3: step name. */
						__( 'Step %1$d of %2$d: %3$s', 'bettershield' ),
						index + 1,
						visible.length,
						step.short
				  )
				: ''
		);

		window.scrollTo( { top: 0 } );
		headingRef.current?.focus( { preventScroll: true } );
	}, [ current ] ); // eslint-disable-line react-hooks/exhaustive-deps

	// The current step went away under the owner — the other security
	// plugin was deactivated in another tab — so move on to the next one.
	// One its own action removed is kept by `stay` instead.
	useEffect( () => {
		if ( ! visible.includes( current ) ) {
			setCurrent( resumeAt( current, visible ) );
		}
	}, [ visible, current ] );

	if ( ! state ) {
		return (
			<div className="bs-ds-setup__frame">
				<div className="bs-ds-setup__panel bs-ds-setup__panel--error" role="alert">
					<Alert
						layout="default"
						tone="error"
						desc={ sprintf( /* translators: %s: the plugin's name. */ __( 'The Quick Setup could not load. All of it is also on the %s screens.', 'bettershield' ), brand() ) }
						actions={
							<Button type="secondary" size="sm" href={ links.dashboard }>
								{ sprintf( /* translators: %s: the plugin's name. */ __( 'Go to %s', 'bettershield' ), brand() ) }
							</Button>
						}
					/>
				</div>
			</div>
		);
	}

	const View = VIEWS[ current ] || Welcome;

	const context = {
		state,
		setState,
		rerun,
		current,
		visible,
		steps,
		busy,
		error,
		setError,
		notice,
		setNotice,
		keepFocus,
		stayOnStep: setStay,
		run,
		hold,
		refresh,
		go,
		next,
		back,
		advance,
		skip,
		finish,
		links,
		headingRef,
		// Ecosystem goes back to Protect; the hub step, which leaves the site, does not.
		canGoBack: null !== previousStep( current, visible ) && 'hub' !== current,
		isLast: 'ready' === nextStep( current, visible ),
	};

	return (
		<SetupContext.Provider value={ context }>
			<div className="bs-ds-setup__frame">
				{ /* A named region inside WordPress's own main landmark, not a second one. */ }
				<section className="bs-ds-setup__panel" aria-labelledby="bs-setup-title">
					<Stepper
						steps={ steps }
						current={ current }
						skipped={ skippedSteps }
						canVisit={ ( slug ) => canVisit( slug, current, visible ) }
						onVisit={ go }
						locked={ null !== busy }
					/>
					<View key={ current } />
				</section>

				<div className="screen-reader-text" role="status" aria-live="polite">
					{ announcement }
				</div>

				<ConfirmPassword
					held={ held }
					onDone={ ( answer ) => {
						const resolve = held?.resolve;

						setHeld( null );
						resolve?.( answer );
					} }
					onFailure={ ( failure ) => setError( { key: held?.key, message: failureMessage( failure ) } ) }
				/>
			</div>
		</SetupContext.Provider>
	);
}
