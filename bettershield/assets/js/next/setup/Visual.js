/**
 * The picture beside each step: what the step is about, drawn on the design's
 * soft background for it, from this site's own answers where it has them —
 * its address, its score, the other security plugins it found, the fixes and
 * the plugins it recommends.
 *
 * It repeats what the step's column says and offers nothing to press, so it
 * is hidden from assistive technology, and on a narrow window it is not drawn
 * at all (Frame.css).
 */

import './Visual.css';

import { __, sprintf } from '@wordpress/i18n';
import Icon from '../ui/Icon';
import ScoreGauge, { gaugeState } from '../ui/ScoreGauge';
import { pageModel } from './api';
import brand from './brand';
import { useSetup } from './context';
import { listedOff, switchingOff } from './switchingOff';

/** The step a background belongs to: Ready is drawn as the plugins it recommends. */
const BACKGROUNDS = {
	welcome: 'welcome',
	coexistence: 'coexistence',
	protect: 'protect',
	ready: 'ecosystem',
	hub: 'hub',
};

/** What each job another plugin does is called on the card of plugins found. */
function jobName( job ) {
	return (
		{
			login_limits: __( 'Sign-in limits', 'bettershield' ),
			two_factor: __( 'Two-factor', 'bettershield' ),
			login_url: __( 'Sign-in address', 'bettershield' ),
			firewall: __( 'Firewall', 'bettershield' ),
			vulnerabilities: __( 'Vulnerability checks', 'bettershield' ),
			file_integrity: __( 'File checks', 'bettershield' ),
		}[ job ] || ''
	);
}

/** The site's address, as the page was given it. */
function host() {
	return pageModel().host || window.location.host;
}

/**
 * What the site is called on the score cards: its title where it has one,
 * which reads whole where a long address was cut short, else its address.
 */
function siteName() {
	const name = String( pageModel().site || '' ).trim();

	return '' !== name ? name : host();
}

/** A longer address is set smaller, so it fits the card beside the gauge. */
function addressSize( address ) {
	// The whole name is shown, wrapping as it needs: a very long one steps
	// down once more so the card stays a card.
	if ( address.length > 28 ) {
		return ' is-longest';
	}

	if ( address.length > 13 ) {
		return ' is-longer';
	}

	return address.length > 9 ? ' is-long' : '';
}

/** The plugin's mark: the owner's label's logo where it has one. */
function Mark() {
	const logo = pageModel().logo;
	const assets = window.bettershield?.assetsUrl || '';

	return <img className="bs-ds-setup-visual__mark" src={ logo || `${ assets }next/logo-mark.svg` } alt="" width="16" height="20" />;
}

/** A floating label with an icon tile, as the design scatters over its pictures. */
function Chip( { icon, children, className = '' } ) {
	return (
		<span className={ `bs-ds-setup-visual__chip ${ className }` }>
			<span className="bs-ds-setup-visual__tile">
				<Icon name={ icon } size={ 14 } tone="brand" />
			</span>
			{ children }
		</span>
	);
}

/** A window of the plugin's own screens, cut off by the picture's edge. */
function AppWindow( { place, example = false, children } ) {
	return (
		<div className="bs-ds-setup-visual__window">
			<div className="bs-ds-setup-visual__bar">
				<Mark />
				<span className="bs-ds-setup-visual__crumb">{ place[ 0 ] }</span>
				<span className="bs-ds-setup-visual__slash">/</span>
				<span className="bs-ds-setup-visual__place">{ place[ 1 ] }</span>
				{ /* Sample numbers, not this owner's: said so, so nobody reads them as their own. */ }
				{ example ? <span className="bs-ds-setup-visual__tag bs-ds-setup-visual__example">{ __( 'Example', 'bettershield' ) }</span> : null }
			</div>
			{ children }
		</div>
	);
}

/** A switch as a picture: on or off, never pressed. */
function Switch( { on } ) {
	return <span className={ `bs-ds-setup-visual__switch${ on ? ' is-on' : '' }` } />;
}

/**
 * The site's score as the design's gauge, or the score a step expects once
 * it is applied.
 *
 * @param {Object}  state The setup.
 * @param {?Object} after { score, grade } after the step's changes, if it gives one.
 */
function gauge( state, after = null ) {
	const score = after || state.score || {};
	const running = Boolean( state.first_scan?.running );

	return (
		<ScoreGauge
			state={ gaugeState( { grade: score.grade, audited: undefined !== score.score, running } ) }
			score={ score.score || 0 }
			grade={ score.grade || '' }
		/>
	);
}

/**
 * The site's badge on the Welcome picture, read from the first scan.
 *
 * @param {Object} state The setup's state.
 * @return {string} The words.
 */
function scanBadge( state ) {
	if ( state.first_scan?.running ) {
		return __( 'Scanning…', 'bettershield' );
	}

	return undefined !== ( state.score || {} ).score ? __( 'Scanned', 'bettershield' ) : __( 'Ready for first scan', 'bettershield' );
}

function Welcome( { state } ) {
	return (
		<>
			<Chip icon="key" className="is-one">
				{ __( 'Account recovery', 'bettershield' ) }
			</Chip>
			<Chip icon="lock" className="is-two is-small">
				{ __( 'Sign-in protection', 'bettershield' ) }
			</Chip>
			<Chip icon="zap" className="is-three">
				{ __( 'Quick security fixes', 'bettershield' ) }
			</Chip>

			<div className="bs-ds-setup-visual__bezel">
				<div className="bs-ds-setup-visual__site">
					{ gauge( state ) }
					<div className="bs-ds-setup-visual__site-text">
						<span className={ `bs-ds-setup-visual__host${ addressSize( siteName() ) }` } title={ host() }>
							{ siteName() }
						</span>
						{ /* Follows the first scan: Ready before it, Scanning while it
						     runs, Scanned once the gauge shows its score (#2996). */ }
						<span className="bs-ds-setup-visual__ready">
							<Icon name="scan" size={ 12 } tone="brand" />
							{ scanBadge( state ) }
						</span>
					</div>
				</div>
			</div>
		</>
	);
}

function Coexistence( { state, draft } ) {
	const rows = state.coexistence?.rows || [];
	const plugins = new Map();
	// The answer on screen, saved or not: the picture follows the radios.
	const choices = {};

	rows.forEach( ( row ) => {
		if ( 'choice' === row.kind ) {
			choices[ row.job ] = draft?.coexistence?.[ row.job ] || row.choice;
		}
	} );

	// "Turns off" only for what the step's button really switches off: not a
	// plugin whose sign-in address waits for the end of the setup, one kept
	// for another job, or one this account can't switch off.
	const off = new Set( switchingOff( listedOff( rows, choices ) ).map( ( plugin ) => plugin.file ) );

	rows.forEach( ( row ) => {
		( row.deactivate || [] ).forEach( ( plugin ) => {
			const seen = plugins.get( plugin.file ) || { name: plugin.name, jobs: new Set(), off: false };

			( plugin.jobs || [] ).forEach( ( job ) => seen.jobs.add( job ) );
			seen.off = off.has( plugin.file );
			plugins.set( plugin.file, seen );
		} );

		// A plugin named on a row it does not deactivate on still does the job.
		( row.plugins || [] ).forEach( ( name ) => {
			if ( ! Array.from( plugins.values() ).some( ( plugin ) => plugin.name === name ) ) {
				plugins.set( name, { name, jobs: new Set( [ row.job ] ), off: false } );
			}
		} );
	} );

	return (
		<>
			<span className="bs-ds-setup-visual__badge is-top">
				<Icon name="arrow-right" size={ 16 } tone="brand" />
				{ __( 'Settings come over', 'bettershield' ) }
			</span>

			<div className="bs-ds-setup-visual__found">
				<div className="bs-ds-setup-visual__found-head">
					<span className="bs-ds-setup-visual__square">
						<Icon name="package" size={ 14 } tone="1" />
					</span>
					<span className="bs-ds-setup-visual__lines">
						<span className="bs-ds-setup-visual__name">
							{ sprintf( /* translators: %s: the site's address. */ __( 'Found on %s', 'bettershield' ), host() ) }
						</span>
						<span className="bs-ds-setup-visual__detail">{ __( 'What happens when you continue', 'bettershield' ) }</span>
					</span>
				</div>
				{ Array.from( plugins.values() ).slice( 0, 4 ).map( ( plugin ) => (
					<div key={ plugin.name } className="bs-ds-setup-visual__found-row">
						<span className="bs-ds-setup-visual__square">
							<Icon name="shield" size={ 14 } tone="1" />
						</span>
						<span className="bs-ds-setup-visual__lines">
							<span className="bs-ds-setup-visual__name">{ plugin.name }</span>
							<span className="bs-ds-setup-visual__detail">
								{ Array.from( plugin.jobs ).map( jobName ).filter( Boolean ).join( ', ' ) }
							</span>
						</span>
						<span key={ plugin.off ? 'off' : 'on' } className={ `bs-ds-setup-visual__tag is-changing${ plugin.off ? '' : ' is-green' }` }>
							{ plugin.off ? __( 'Turns off', 'bettershield' ) : __( 'Stays on', 'bettershield' ) }
						</span>
					</div>
				) ) }
			</div>

			<span className="bs-ds-setup-visual__badge is-bottom">
				<Icon name="undo-2" size={ 16 } tone="brand" />
				{ __( 'Turn back on any time', 'bettershield' ) }
			</span>
		</>
	);
}

function Protect( { state, draft } ) {
	const fixes = state.fixes || [];
	const rows = [
		{ id: 'sign_in_limits', title: __( 'Limit sign-in attempts', 'bettershield' ), on: Boolean( state.score?.lockouts ) },
		...fixes.map( ( fix ) => ( { id: fix.id, title: fix.title, on: Boolean( fix.on ) } ) ),
	];

	return (
		<AppWindow place={ [ brand(), __( 'Protection', 'bettershield' ) ] }>
			<div className="bs-ds-setup-visual__scan">
				{ gauge( state, draft?.protect?.after ) }
				<div className="bs-ds-setup-visual__scan-text">
					<span className="bs-ds-setup-visual__scan-title" title={ host() }>
						{ siteName() }
					</span>
					<span className="bs-ds-setup-visual__scan-sub">
						{ state.first_scan?.running ? __( 'Your first scan is running. Your score appears when it finishes.', 'bettershield' ) : __( 'after Apply (estimate)', 'bettershield' ) }
					</span>
				</div>
			</div>

			<div className="bs-ds-setup-visual__list">
				<div className="bs-ds-setup-visual__list-card">
					<div className="bs-ds-setup-visual__list-head">
						<Icon name="shield" size={ 16 } tone="1" />
						<span className="bs-ds-setup-visual__name">{ __( 'Protection', 'bettershield' ) }</span>
						<span className="bs-ds-setup-visual__tag">
							{ sprintf(
								/* translators: 1: how many protections are on, 2: how many there are. */
								__( '%1$d of %2$d on', 'bettershield' ),
								rows.filter( ( row ) => row.on ).length,
								rows.length
							) }
						</span>
					</div>
					{ rows.slice( 0, 3 ).map( ( row ) => (
						<div key={ row.id } className="bs-ds-setup-visual__list-row">
							<span>{ row.title }</span>
							<Switch on />
						</div>
					) ) }
				</div>
				<span className="bs-ds-setup-visual__list-foot">{ __( 'Switches on when you apply', 'bettershield' ) }</span>
			</div>
		</AppWindow>
	);
}

function Plugin( { plugin, big = false } ) {
	return (
		<div className={ `bs-ds-setup-visual__plugin${ big ? ' is-big' : '' }` }>
			<div className="bs-ds-setup-visual__plugin-head">
				<span className="bs-ds-setup-visual__plugin-icon">{ plugin.icon ? <img src={ plugin.icon } alt="" width="20" height="20" /> : null }</span>
				{ big ? (
					<>
						<span className="bs-ds-setup-visual__lines">
							<span className="bs-ds-setup-visual__name">{ plugin.name }</span>
							<span className="bs-ds-setup-visual__detail">{ plugin.short || plugin.description }</span>
						</span>
						{ plugin.why ? <span className="bs-ds-setup-visual__tag is-yellow">{ plugin.why }</span> : null }
					</>
				) : null }
			</div>
			{ big ? null : (
				<>
					<span className="bs-ds-setup-visual__name">{ plugin.name }</span>
					<span className="bs-ds-setup-visual__detail">{ plugin.short || plugin.description }</span>
				</>
			) }
		</div>
	);
}

function Ready( { state } ) {
	const plugins = [ ...( state.ecosystem?.recommended || [] ), ...( state.ecosystem?.more || [] ) ];

	return (
		<AppWindow place={ [ brand(), __( 'Plugins', 'bettershield' ) ] }>
			<div className="bs-ds-setup-visual__plugins">
				<span className="bs-ds-setup-visual__eyebrow">{ __( 'Recommended for your site', 'bettershield' ) }</span>
				{ plugins[ 0 ] ? <Plugin plugin={ plugins[ 0 ] } big /> : null }
				<div className="bs-ds-setup-visual__pair">
					{ plugins.slice( 1, 3 ).map( ( plugin ) => (
						<Plugin key={ plugin.slug } plugin={ plugin } />
					) ) }
				</div>
			</div>
		</AppWindow>
	);
}

function Hub( { state } ) {
	const connected = Boolean( state.hub?.connected );
	// The others are a picture of what the hub lists, not this owner's sites.
	const others = [
		{ name: __( 'shop.your.site', 'bettershield' ), kind: __( 'Store', 'bettershield' ), score: 92, grade: 'A', tone: 'is-green' },
		{ name: __( 'docs.your.site', 'bettershield' ), kind: __( 'Documentation', 'bettershield' ), score: 61, grade: 'C', tone: 'is-yellow' },
		{ name: __( 'blog.your.site', 'bettershield' ), kind: __( 'Blog', 'bettershield' ), score: 78, grade: 'B', tone: 'is-green' },
	];

	return (
		<AppWindow example place={ [ sprintf( /* translators: %s: the plugin's name. */ __( '%s Hub', 'bettershield' ), brand() ), __( 'Sites', 'bettershield' ) ] }>
			<div className="bs-ds-setup-visual__stats">
				{ [
					[ __( 'Sites', 'bettershield' ), 4 ],
					[ __( 'Open findings', 'bettershield' ), 31 ],
					[ __( 'Down now', 'bettershield' ), 0 ],
				].map( ( [ label, value ] ) => (
					<span key={ label } className="bs-ds-setup-visual__stat">
						<span className="bs-ds-setup-visual__detail">{ label }</span>
						<span className="bs-ds-setup-visual__stat-value">{ value }</span>
					</span>
				) ) }
			</div>

			<div className="bs-ds-setup-visual__sites">
				<div className="bs-ds-setup-visual__site-row">
					<span className="bs-ds-setup-visual__square is-round">
						<Icon name="globe" size={ 14 } tone="1" />
					</span>
					<span className="bs-ds-setup-visual__lines">
						<span className="bs-ds-setup-visual__name">{ host() }</span>
						<span className="bs-ds-setup-visual__detail">{ __( 'This site', 'bettershield' ) }</span>
					</span>
					<span className="bs-ds-setup-visual__tag is-brand">{ connected ? __( 'Connected', 'bettershield' ) : __( 'Connecting', 'bettershield' ) }</span>
				</div>
				{ others.map( ( site ) => (
					<div key={ site.name } className="bs-ds-setup-visual__site-row">
						<span className="bs-ds-setup-visual__square is-round">
							<Icon name="globe" size={ 14 } tone="1" />
						</span>
						<span className="bs-ds-setup-visual__lines">
							<span className="bs-ds-setup-visual__name">{ site.name }</span>
							<span className="bs-ds-setup-visual__detail">{ site.kind }</span>
						</span>
						<span className="bs-ds-setup-visual__score">{ site.score }</span>
						<span className={ `bs-ds-setup-visual__tag ${ site.tone }` }>
							{ sprintf( /* translators: %s: a letter grade. */ __( 'Grade %s', 'bettershield' ), site.grade ) }
						</span>
					</div>
				) ) }
			</div>
		</AppWindow>
	);
}

const PICTURES = { welcome: Welcome, coexistence: Coexistence, protect: Protect, ready: Ready, hub: Hub };

/**
 * @param {Object} props
 * @param {string} props.step The step on screen.
 */
export default function Visual( { step } ) {
	const { state, draft } = useSetup();
	const Picture = PICTURES[ step ];
	const assets = window.bettershield?.assetsUrl || '';

	if ( ! Picture ) {
		return null;
	}

	return (
		<div
			className={ `bs-ds-setup-visual bs-ds-setup-visual--${ BACKGROUNDS[ step ] }` }
			style={ assets ? { backgroundImage: `url("${ assets }setup/${ BACKGROUNDS[ step ] }.webp")` } : undefined }
			aria-hidden="true"
		>
			<div className="bs-ds-setup-visual__frame">
				<Picture state={ state } draft={ draft } />
			</div>
		</div>
	);
}
