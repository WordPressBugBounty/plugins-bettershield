/**
 * The bar along the top of the sheet (design frame 27:53100): the sidebar
 * toggle, a rule, the screen's name, when the site was last audited, the
 * control that audits it again, the way to the hub, and the color scheme.
 *
 * The name is the page's heading and where focus goes after a move.
 */

import './TopBar.css';

import { __, sprintf } from '@wordpress/i18n';
import { hubConnected, hubUrl, mayManage, navItemFor } from '../../nav';
import { whenPhrase } from '../../ui/when';
import { otherScheme, useScheme } from '../../ui/scheme';
import { useAuditRun } from '../../shared/AuditAction';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import { useKept } from '../ui/useKept';

/** The Hub screen's section. */
const HUB = 'bettershield-hub';

function AuditRun() {
	const { overview, running, done, run } = useAuditRun();
	// Kept while a refresh reads the fresh copy, and after one fails.
	const last = useKept( overview.data );

	return (
		<>
			{ last && last.generated_at ? (
				<span className="bs-ds-top__audit">
					<Icon name="clock" size={ 14 } tone="3" />
					<span className="bs-ds-t12 bs-ds-r bs-ds-c3 bs-ds-nowrap">
						{ sprintf(
							/* translators: %s: when the last audit ran, e.g. "today, 5:14 PM". */
							__( 'Last audit %s', 'bettershield' ),
							whenPhrase( last.generated_at )
						) }
					</span>
				</span>
			) : null }
			{ mayManage() ? (
				<Button
					type="primary"
					size="lg"
					icon={ done && ! running ? 'check' : 'refresh-cw' }
					iconTone="onbrand"
					className="bs-ds-top__run"
					isBusy={ running }
					disabled={ running }
					// Still focusable while the audit runs, so focus is not
					// dropped from the control that was just pressed.
					accessibleWhenDisabled
					onClick={ run }
				>
					{ /* Just "Auditing…": the last audit's count was a ceiling, not
					     progress for this run (#2294). */ }
					{ running && __( 'Auditing…', 'bettershield' ) }
					{ ! running && done && __( 'Audit Complete', 'bettershield' ) }
					{ ! running && ! done && __( 'Run Audit', 'bettershield' ) }
				</Button>
			) : null }
		</>
	);
}

/*
 * The way to the hub, offered only where the sidebar lists its entry: the
 * entry is left out for a reader who may not open it, and, under an owner's
 * label, while the site holds no connection. Connected, it opens the hub in
 * a new tab, as the Hub screen's "Open the Hub" does and only where that is
 * offered; otherwise it opens the Hub screen, where Connect is. Secondary,
 * so Run Audit stays the bar's one primary control.
 */
function HubLink() {
	const entry = navItemFor( { section: HUB, tab: '' } );

	if ( ! entry ) {
		return null;
	}

	const away = hubConnected && '' !== hubUrl;
	const label = entry.item.label;

	return (
		<Button
			type="secondary"
			size="lg"
			icon={ away ? 'arrow-out' : 'network' }
			iconTone="2"
			className="bs-ds-top__hub"
			href={ away ? hubUrl : entry.item.url }
			{ ...( away ? { target: '_blank', rel: 'noopener noreferrer' } : {} ) }
			aria-label={ label }
		>
			<span className="bs-ds-top__hub-label">{ label }</span>
		</Button>
	);
}

function SchemeSwitch() {
	const { scheme, setScheme } = useScheme();
	const next = otherScheme( scheme );
	const label = 'dark' === next ? __( 'Switch to dark', 'bettershield' ) : __( 'Switch to light', 'bettershield' );

	return (
		<Button
			type="toolbar"
			size="md"
			className="bs-ds-top__scheme"
			label={ label }
			aria-label={ label }
			onClick={ () => setScheme( next ) }
		>
			<Icon name={ 'dark' === next ? 'moon' : 'sun' } size={ 16 } tone="2" />
		</Button>
	);
}

/*
 * The bar is drawn inside WordPress's own main region (#wpbody), so a
 * <header> here was a second banner landmark nested in main, next to the
 * admin bar. It is a plain box; the screen's <h1> still names the page (#2185).
 */
export default function TopBar( { title, headingRef, collapsed, toggle, audit = true, hub = false } ) {
	const label = collapsed ? __( 'Expand the sidebar', 'bettershield' ) : __( 'Collapse the sidebar', 'bettershield' );

	return (
		<div className="bs-ds-top">
			<button type="button" className="bs-ds-top__toggle" aria-label={ label } aria-expanded={ ! collapsed } onClick={ toggle }>
				<Icon name="panel-left" size={ 18 } tone="3" />
			</button>
			<span className="bs-ds-top__rule" aria-hidden="true" />
			<h1 ref={ headingRef } tabIndex={ -1 } className="bs-ds-top__title">
				{ title }
			</h1>
			<span className="bs-ds-spacer" />
			{ audit ? <AuditRun /> : null }
			{ hub ? <HubLink /> : null }
			<SchemeSwitch />
		</div>
	);
}
