/**
 * Protect: the choices that raise the score first, each with its points, and
 * the settings that do not change it folded under them with their answers
 * already given, with one Apply (#2297).
 *
 * At the top, the grade and score now and where Apply takes them with what is
 * chosen, read from the site's own projection: this screen does no arithmetic
 * on the score, at the heading's other end. Then Recommended: sign-in limits
 * and the safe fixes as one row, each a compact line with the points its
 * setup item is worth and a switch. Then More settings, closed: who signs in,
 * how visits arrive, where alerts go, and the vulnerability checks, which
 * stay an opt-in switch because they contact BetterShield Hub. While
 * BetterShield cannot tell how visits arrive, which decides whether lockouts
 * can work, the sign-in row says so in one line that opens the question.
 *
 * What needs the owner's own hands — account recovery, two-factor and the
 * usernames to block — is not here, nor on Ecosystem: Findings lists each,
 * with its points, while it is still to do (#2608).
 *
 * Apply saves in the order the old steps did, and stops at the first
 * refusal, said beside what it is about: the site's answers, then the
 * vulnerability checks, then the fixes.
 */

import './Protect.css';

import { useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { listOf } from '../../../setup/format';
import Badge from '../../ui/Badge';
import SettingRow, { SettingsCard, Toggle } from '../../ui/Setting';
import Disclosure from '../Disclosure';
import Frame, { Footer } from '../Frame';
import ScoreMove from '../ScoreMove';
import { useSetup } from '../context';
import Recommended, { ScoreRow } from './Recommended';
import SafeFixes from './SafeFixes';
import { proxyUnsure, useYourSite } from './YourSite';

/** The vulnerability checks' own consent route, as Settings › General uses it. */
const CONSENT = '/bettershield/v1/vulnerabilities/consent';

/** The setup items the safe fixes earn, as the site's scoring names them. */
const FIX_ITEMS = [ 'file_editor', 'version_hidden', 'directory_browsing', 'username_discovery', 'security_headers' ];

/**
 * The vulnerability checks, offered in the words Settings › General says
 * them in. Off by default, and saved only by Apply.
 *
 * @param {Object}   props
 * @param {Object}   props.checks   The checks as the server states them.
 * @param {boolean}  props.on       Whether the switch is on.
 * @param {Function} props.onChange Called with the switch's new state.
 */
function VulnerabilityChecks( { checks, on, onChange } ) {
	const { busy } = useSetup();

	return (
		<SettingsCard icon="shield-alert" title={ __( 'Vulnerability checks', 'bettershield' ) }>
			<SettingRow
				title={ __( 'Check plugins, themes and WordPress for known security issues', 'bettershield' ) }
				about={ sprintf(
					/* translators: %s: feed name. */
					__( 'Sends %s the names and versions of your plugins (including must-use plugins), themes and WordPress. Nothing else.', 'bettershield' ),
					checks.label
				) }
				tip={ __( 'Checks run daily and after updates or removals. No site address, email, username or key is sent.', 'bettershield' ) }
				toggle={ { checked: on, disabled: null !== busy, onChange } }
			/>
		</SettingsCard>
	);
}

/**
 * Where Apply takes the score with what is chosen, from the site's own
 * projection for that set of choices.
 *
 * @param {Object}   score  The site's score and projections.
 * @param {Function} chosen Whether a choice is chosen.
 * @return {{score: number, grade: string}} The score after Apply.
 */
function projectedScore( score, chosen ) {
	const choices = Array.isArray( score.choices ) ? score.choices : [];
	// Each chosen choice is one bit of the set, in the order the site sent them.
	const set = choices.reduce( ( bits, choice, bit ) => ( chosen( choice ) ? bits + 2 ** bit : bits ), 0 );

	return ( score.projected || [] )[ set ] || { score: score.score, grade: score.grade };
}

/**
 * The score now and after Apply, at the heading's other end. Where the
 * proxy answer can still let lockouts run, which only a request after Apply
 * shows, the score after is said as an estimate.
 *
 * @param {Object} props
 * @param {Object} props.score The site's score and projections.
 * @param {Object} props.after The score after Apply.
 */
function ScorePreview( { score, after } ) {
	const moves = after.score !== score.score;
	let note = '';

	if ( moves ) {
		note = score.uncertain ? __( 'after Apply (estimate)', 'bettershield' ) : __( 'after Apply', 'bettershield' );
	}

	return (
		<span className="bs-ds-setup-protect__score">
			<ScoreMove from={ { score: score.score, grade: score.grade } } to={ after } />
			{ note ? <span className="bs-ds-setup__head-note bs-ds-setup-protect__score-note">{ note }</span> : null }
		</span>
	);
}

export default function Protect() {
	const { state, run, busy, advance, links } = useSetup();
	const checks = state.vulnerabilities || { available: false, on: false, label: '' };
	// The first file check can still move the score, so the figure waits.
	const scanning = Boolean( state.first_scan && state.first_scan.running );
	const score = scanning ? null : state.score || null;
	const [ checking, setChecking ] = useState( Boolean( checks.on ) );
	const [ settled, setSettled ] = useState( false );
	// Who signs in as answered under More settings, before it is saved.
	const [ team, setTeam ] = useState( state.site.team || 'solo' );
	const [ fixes, setFixes ] = useState( [] );
	const [ fixesOpen, setFixesOpen ] = useState( false );
	const [ fixesSay, setFixesSay ] = useState( false );
	const [ moreOpen, setMoreOpen ] = useState( false );
	// The fixes' one switch, handed over by the set as it draws.
	const setAllFixes = useRef( null );
	const proxyRef = useRef( null );
	// Each part's own save, handed over as it draws.
	const saves = useRef( {} );
	const register = ( key ) => ( save ) => {
		saves.current[ key ] = save;
	};

	const site = useYourSite( { register: register( 'site' ), onTeam: setTeam } );

	const consent = () => ( checking === Boolean( checks.on ) ? Promise.resolve( true ) : run( 'vulnerabilities', CONSENT, { enabled: checking } ).then( Boolean ) );

	const apply = () => {
		const order = [ saves.current.site, consent, saves.current.fixes ].filter( Boolean );

		// One after another, and on only while each went through.
		order
			.reduce( ( chain, save ) => chain.then( ( done ) => ( done ? save() : false ) ), Promise.resolve( true ) )
			.then( ( done ) => {
				if ( done ) {
					// Every save went through, so the step is done and ticked.
					// The way back in is no longer Protect's to finish: Ecosystem
					// points to Recovery while it is not set up (#2196).
					advance( false );
				}
			} );
	};

	const working = [ 'site', 'vulnerabilities', 'fixes' ].includes( busy );

	// What each item is worth and whether it is still to earn, from the site.
	const item = ( name ) => ( score && score.points && score.points[ name ] ? { points: score.points[ name ], open: Boolean( score.open && score.open[ name ] ) } : null );

	// Only the safe fixes are choices the preview can count now.
	const chosen = ( choice ) => fixes.includes( choice );
	const after = score ? projectedScore( score, chosen ) : null;
	const unsure = proxyUnsure( state );
	// While visits cannot be told apart, lockouts cannot run, so Apply cannot
	// earn the sign-in points: the row says when its points come (#2573).
	const limitsItem = item( 'sign_in_limits' );
	const limitsLater = unsure && Boolean( limitsItem ) && limitsItem.open;
	// The header's points are the preview's own move, from the site's real
	// score: adding each item's points drew "+17 points" beside 29 → 44,
	// since a grade's cap and what Apply cannot earn yet sit between them.
	const total = score && after ? Math.max( 0, after.score - score.score ) : 0;

	const limits = ( state.coexistence?.rows || [] ).find( ( row ) => 'login_limits' === row.job && 'choice' === row.kind );
	const limitsElsewhere = Boolean( limits ) && state.coexistence.saved && 'bettershield' !== limits.choice;
	const fixList = state.fixes || [];
	const fixesPending = fixList.filter( ( fix ) => ! fix.on ).length;
	/*
	 * The safe fixes' points on the header's scale: the score's move with
	 * every fix not already on, from the site's own projection. Adding each
	 * fix's weight drew "+17" beside "+7 points", and counted one the server
	 * already did (#2631).
	 */
	const pendingIds = fixList.filter( ( fix ) => ! fix.on ).map( ( fix ) => fix.id );
	const allFixes = score ? projectedScore( score, ( choice ) => pendingIds.includes( choice ) ) : null;
	const fixesWorth = score && allFixes ? Math.max( 0, allFixes.score - score.score ) : 0;
	// With nothing left to turn on, the row says what the fixes earned, as the sign-in row beside it does.
	const fixesEarned = score && score.points ? FIX_ITEMS.reduce( ( sum, name ) => sum + ( score.points[ name ] || 0 ), 0 ) : 0;

	const limitsOn = ! limitsElsewhere;
	const tries = state.site?.limits?.tries || 5;
	const minutes = state.site?.limits?.minutes || 15;
	const limitsAbout = limitsElsewhere
		? sprintf(
				/* translators: %s: one or more plugin names. */
				__( 'Kept with %s, as you chose.', 'bettershield' ),
				listOf( limits.plugins || [] )
		  )
		: sprintf(
				/* translators: 1: failed sign-ins allowed, 2: minutes they are counted over. */
				__( '%1$d tries in %2$d minutes', 'bettershield' ),
				tries,
				minutes
		  );

	// The proxy question lives under More settings; while BetterShield cannot
	// tell how visits arrive, the sign-in row points to it in one line.
	const showProxy = () => {
		setMoreOpen( true );
		window.requestAnimationFrame?.( () => {
			proxyRef.current?.scrollIntoView?.( { block: 'center' } );
			proxyRef.current?.focus?.();
		} );
	};

	const more = [
		site.summary,
		'team' === team ? __( 'Me and a team', 'bettershield' ) : __( 'Just me', 'bettershield' ),
		checks.available ? ( checking ? __( 'Vulnerability checks on', 'bettershield' ) : __( 'Vulnerability checks off', 'bettershield' ) ) : '',
	]
		.filter( Boolean )
		.join( ' · ' );

	const fixesShown = fixesOpen || fixesSay;

	return (
		<Frame
			inline={ [ 'site' ] }
			title={ __( 'Protect your site', 'bettershield' ) }
			aside={
				scanning ? (
					<span className="bs-ds-setup-protect__score" role="status">
						{ __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) }
					</span>
				) : score ? (
					<ScorePreview score={ score } after={ after } />
				) : null
			}
			footer={ <Footer primary={ { label: __( 'Apply & Continue', 'bettershield' ), onClick: apply, busy: working, disabled: ! settled } } /> }
		>
			<Recommended total={ total }>
				{ /*
				   BetterShield's own, on unless the job was kept with another
				   plugin, and changed only on Login & Access, which asks for the
				   password as any weakening does: a status and a link there, not
				   a switch that never moved (#2573). While visits cannot be told
				   apart, lockouts do not run yet, so it says Not running yet rather
				   than On.
				*/ }
				<ScoreRow
					title={ __( 'Sign-in attempt limits', 'bettershield' ) }
					about={ limitsAbout }
					points={ limitsItem ? { ...limitsItem, later: limitsLater } : null }
					extra={
						<span className="bs-ds-setup-rec__links">
							{ unsure && ! limitsElsewhere ? (
								<button type="button" className="bs-ds-setup-rec__link" aria-controls="bs-ds-setup-protect-proxy" onClick={ showProxy }>
									{ __( 'Answer the Cloudflare question', 'bettershield' ) }
								</button>
							) : null }
							{ links && links.login ? (
								// In a new tab: nothing in the middle of the setup sends the
								// owner off it (#2091).
								<a className="bs-ds-setup-rec__link" href={ links.login } target="_blank" rel="noopener noreferrer">
									{ __( 'Change in Login & Access', 'bettershield' ) }
									<span className="screen-reader-text">{ __( '(opens in a new tab)', 'bettershield' ) }</span>
								</a>
							) : null }
						</span>
					}
					control={ ( () => {
						if ( ! limitsOn ) {
							return null;
						}

						return unsure ? () => <Badge tone="neutral">{ __( 'Not running yet', 'bettershield' ) }</Badge> : () => <Badge tone="brand">{ __( 'On', 'bettershield' ) }</Badge>;
					} )() }
				/>

				<ScoreRow
					title={ sprintf(
						/* translators: %d: how many safe fixes there are. */
						_n( '%d safe fix', '%d safe fixes', fixList.length, 'bettershield' ),
						fixList.length
					) }
					about={ fixesPending ? __( 'File editor, usernames, headers, folders, version', 'bettershield' ) : __( 'Every safe fix is on already.', 'bettershield' ) }
					points={ score ? { points: fixesPending ? fixesWorth : fixesEarned, open: fixesPending > 0 && fixesWorth > 0 } : null }
					extra={
						fixesPending ? (
							<button type="button" className="bs-ds-setup-rec__link" aria-expanded={ fixesShown } aria-controls="bs-ds-setup-protect-fixes" onClick={ () => setFixesOpen( ! fixesShown ) }>
								{ fixesShown ? __( 'Done', 'bettershield' ) : __( 'Choose Fixes', 'bettershield' ) }
							</button>
						) : null
					}
					control={ ( id ) => (
						<Toggle
							checked={ fixes.length > 0 || ! fixesPending }
							disabled={ ! settled || ! fixesPending || null !== busy }
							labelledBy={ id }
							onChange={ ( event ) => setAllFixes.current?.( Boolean( event && event.target ? event.target.checked : event ) ) }
						/>
					) }
				>
					<div id="bs-ds-setup-protect-fixes" className="bs-ds-setup-protect__part" hidden={ ! fixesShown }>
						<SafeFixes
							register={ register( 'fixes' ) }
							onSettled={ setSettled }
							onChosen={ setFixes }
							onAttention={ setFixesSay }
							onControl={ ( setAll ) => {
								setAllFixes.current = setAll;
							} }
						/>
					</div>
				</ScoreRow>
			</Recommended>

			<Disclosure
				label={ __( 'More settings', 'bettershield' ) }
				summary={ more ? `${ __( 'No effect on your score', 'bettershield' ) } · ${ more }` : __( 'No effect on your score', 'bettershield' ) }
				open={ moreOpen || site.attention }
				onToggle={ setMoreOpen }
			>
				<div className="bs-ds-setup-pair">
					{ site.who }
					<div id="bs-ds-setup-protect-proxy" ref={ proxyRef } tabIndex={ -1 } className="bs-ds-setup-protect__proxy">
						{ site.proxy }
					</div>
				</div>
				{ site.alerts }
				{ checks.available ? <VulnerabilityChecks checks={ checks } on={ checking } onChange={ setChecking } /> : null }
			</Disclosure>
			{ site.refusal }

			<p className="screen-reader-text" role="status">
				{ after && after.score !== score.score
					? sprintf(
							/* translators: 1: a letter grade, 2: a score out of 100. */
							__( 'After Apply: grade %1$s, score %2$d.', 'bettershield' ),
							after.grade,
							after.score
					  )
					: '' }
			</p>
		</Frame>
	);
}
