/**
 * Activity › File changes, the parts the screen is drawn from (design
 * section "File Changes · Flow"): the check's progress and its four places,
 * the plugins table, the accept dialog, the filter chips, a group's band, the
 * severity meter and the four cards a changed file opens into.
 *
 * None of these hold state or call the site: the screen passes what they
 * show and what their controls do.
 */

import './FileCheck.css';

import { Modal } from '@wordpress/components';
import { useId } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime, isPast } from '../../store';
import { formatCount } from '../../ui/count';
import { whenPhrase } from '../../ui/when';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Icon from '../ui/Icon';
import brand from '../setup/brand';
import { METER } from '../data/findings';
import { SEVERITY } from '../findings/Rows';

/** The four parts of the site a check walks, in the order it walks them. */
export const PLACES = [ 'core', 'plugin', 'theme', 'other' ];

/** Each place's name. */
export function placeLabel( place ) {
	return {
		core: __( 'WordPress core', 'bettershield' ),
		plugin: __( 'Plugins', 'bettershield' ),
		theme: __( 'Themes', 'bettershield' ),
		other: __( 'Other files', 'bettershield' ),
	}[ place ];
}

/**
 * How long the last check took, as the design says it: "Finished in 6
 * minutes." Said plainly when the start isn't known or the time is odd.
 *
 * @param {?string} started  When it began (ISO).
 * @param {?string} finished When it finished (ISO).
 * @return {string} The sentence.
 */
export function tookPhrase( started, finished ) {
	const span = Date.parse( finished ) - Date.parse( started );

	if ( ! Number.isFinite( span ) || span < 0 ) {
		return __( 'Finished.', 'bettershield' );
	}

	const minutes = Math.round( span / 60000 );

	if ( minutes < 1 ) {
		return __( 'Finished in under a minute.', 'bettershield' );
	}

	return sprintf(
		/* translators: %s: how many minutes the check took. */
		_n( 'Finished in %s minute.', 'Finished in %s minutes.', minutes, 'bettershield' ),
		formatCount( minutes )
	);
}

/**
 * The heading over a file's severity reason, one whole sentence per grade:
 * a lower-cased translated grade read wrong in languages that capitalize it.
 *
 * @param {string} severity critical, high, medium, low or info.
 * @return {string} The heading.
 */
export function whyTitle( severity ) {
	switch ( severity ) {
		case 'critical':
			return __( 'Why it is critical', 'bettershield' );
		case 'high':
			return __( 'Why it is high', 'bettershield' );
		case 'medium':
			return __( 'Why it is medium', 'bettershield' );
		case 'low':
			return __( 'Why it is low', 'bettershield' );
		default:
			return __( 'Why it matters this much', 'bettershield' );
	}
}

/**
 * The running check's title, one whole sentence per place: lower-casing a
 * translated place name ("Checking wordpress core") broke the proper noun in
 * English and the grammar of languages that capitalize nouns.
 *
 * @param {?string} place What is under way: core, plugin, theme or other.
 * @param {string}  at    The server's name for it, for a place this doesn't know.
 * @return {string} The title.
 */
export function checkingTitle( place, at ) {
	switch ( place ) {
		case 'core':
			return __( 'Checking WordPress core', 'bettershield' );
		case 'plugin':
			return __( 'Checking plugins', 'bettershield' );
		case 'theme':
			return __( 'Checking themes', 'bettershield' );
		case 'other':
			return __( 'Checking other files', 'bettershield' );
		default:
			return sprintf(
				/* translators: %s: what the check is looking at, e.g. "WordPress itself" or a plugin’s name. */
				__( 'Checking %s', 'bettershield' ),
				at
			);
	}
}

/**
 * A place's state: its icon, its words and, where changes were found, how
 * many.
 *
 * @param {Object}  report The integrity report.
 * @param {string}  place  core, plugin, theme or other.
 * @param {boolean} parked The run is paused partway.
 * @return {{icon: string, label: string, count: number}} The state.
 */
export function placeState( report, place, parked ) {
	const count = Number( ( report.places || {} )[ place ] ) || 0;
	const found = { icon: 'file-diff', label: __( 'Changes found', 'bettershield' ), count };
	const clean = { icon: 'circle-check', label: __( 'No changes', 'bettershield' ), count: 0 };

	if ( report.running && report.progress ) {
		const where = ( report.progress.places || {} )[ place ];

		if ( 'current' === where ) {
			return parked
				? { icon: 'clock', label: __( 'Paused', 'bettershield' ), count: 0 }
				: { icon: 'refresh-cw', label: __( 'Checking', 'bettershield' ), count: 0 };
		}

		if ( 'waiting' === where ) {
			return { icon: 'circle-dashed', label: __( 'Waiting', 'bettershield' ), count: 0 };
		}

		return count ? found : clean;
	}

	if ( ! report.ever_run ) {
		return { icon: 'circle-dashed', label: __( 'Not checked yet', 'bettershield' ), count: 0 };
	}

	return count ? found : clean;
}

/**
 * The check's line, its bar and what happens next (Progress, 1:1673), then
 * the four places (Locations, 1:1683).
 *
 * @param {Object}  props
 * @param {Object}  props.report       The integrity report.
 * @param {boolean} props.parked       The run is paused partway.
 * @param {Object}  props.headingRef   Takes the line, where focus lands once a row is resolved.
 */
export function CheckProgress( { report, parked, headingRef } ) {
	const progress = report.running && report.progress ? report.progress : null;
	const checked = progress ? Number( progress.checked ) || 0 : Number( report.stats?.checked ) || 0;
	let title = __( 'Not checked yet', 'bettershield' );
	let meta = '';
	let note = __( 'Run a check to compare this site with WordPress’s published copies. It only reads.', 'bettershield' );
	let share = 0;

	if ( progress ) {
		const current = PLACES.find( ( place ) => 'current' === ( progress.places || {} )[ place ] );
		const at = progress.label || placeLabel( current || 'plugin' );

		title = parked
			? sprintf(
					/* translators: %s: what the check was looking at, e.g. "WordPress itself" or a plugin's folder. */
					__( 'Paused at %s', 'bettershield' ),
					at
			  )
			: checkingTitle( current, at );
		meta = sprintf(
			/* translators: 1: folders checked, 2: folders in all, 3: files compared so far. */
			_n( '%1$s of %2$s folders · %3$s file so far', '%1$s of %2$s folders · %3$s files so far', checked, 'bettershield' ),
			formatCount( Math.min( Number( progress.target ) || 0, Number( progress.targets ) || 0 ) ),
			formatCount( Number( progress.targets ) || 0 ),
			formatCount( checked )
		);
		share = progress.targets ? Math.min( progress.target, progress.targets ) / progress.targets : 0;

		if ( parked ) {
			note =
				report.next_run_at && ! isPast( report.next_run_at )
					? sprintf(
							/* translators: %s: when the next scheduled check runs, e.g. "today, 4:02 PM". */
							__( 'Paused partway through. It picks up again %s, or press Continue Check to resume now.', 'bettershield' ),
							whenPhrase( report.next_run_at )
					  )
					: __( 'Paused partway through. Press Continue Check to finish it.', 'bettershield' );
		} else {
			note = __( 'You can leave this page. The check keeps going and the list updates when it finishes.', 'bettershield' );
		}
	} else if ( report.ever_run ) {
		title = sprintf(
			/* translators: %s: date and time. */
			__( 'Checked %s', 'bettershield' ),
			formatTime( report.last_run_at )
		);
		meta = sprintf(
			/* translators: %s: number of files compared. */
			_n( '%s file compared', '%s files compared', checked, 'bettershield' ),
			formatCount( checked )
		);
		share = 1;
		const took = tookPhrase( report.last_started_at, report.last_run_at );
		const next =
			report.next_run_at && ! isPast( report.next_run_at )
				? sprintf(
						/* translators: %s: when the next check runs, e.g. "today, 4:02 PM". */
						__( 'Next check %s.', 'bettershield' ),
						whenPhrase( report.next_run_at )
				  )
				: __( 'No check is scheduled.', 'bettershield' );

		note = `${ took } ${ next }`;
	}

	return (
		<>
			<div className="bs-ds-fcheck__progress">
				<div className="bs-ds-fcheck__row">
					{ /* A heading: focus lands here once a resolved row's control is gone. */ }
					<h3 className="bs-ds-fcheck__title" ref={ headingRef } tabIndex={ -1 }>
						{ title }
					</h3>
					<span className="bs-ds-spacer" />
					{ meta ? <span className="bs-ds-fcheck__meta">{ meta }</span> : null }
				</div>
				{ /* A bar rather than a spinner: this is the longest thing the
				     plugin does, and a spinner on a job of minutes reads as hung. */ }
				<div
					className="bs-ds-fcheck__track"
					role="progressbar"
					aria-valuemin={ 0 }
					aria-valuemax={ progress ? progress.targets : 1 }
					aria-valuenow={ progress ? Math.min( progress.target, progress.targets ) : Math.round( share ) }
					aria-valuetext={ meta || title }
				>
					<span className="bs-ds-fcheck__fill" style={ { width: `${ Math.round( share * 100 ) }%` } } />
				</div>
				<p className="bs-ds-fcheck__note">
					<Icon name="clock" size={ 14 } tone="2" />
					<span>{ note }</span>
				</p>
			</div>
			<ul className="bs-ds-fcheck__places" aria-label={ __( 'Where the check stands', 'bettershield' ) }>
				{ PLACES.map( ( place ) => {
					const state = placeState( report, place, parked );

					return (
						<li key={ place } className="bs-ds-fcheck__place">
							<span className="bs-ds-fcheck__placename">{ placeLabel( place ) }</span>
							<span className="bs-ds-fcheck__placestate">
								<Icon name={ state.icon } size={ 14 } tone="1" />
								<span>{ state.label }</span>
								{ state.count ? <Badge tone="yellow">{ formatCount( state.count ) }</Badge> : null }
							</span>
						</li>
					);
				} ) }
			</ul>
		</>
	);
}

/**
 * The line under a row's name. A theme says it is one, since the table is
 * headed by plugins and lists a changed theme too.
 *
 * @param {Object}  pkg   The row.
 * @param {boolean} older Compared with a version no longer installed.
 * @return {string} A format taking the version.
 */
function subLine( pkg, older ) {
	if ( 'theme' === pkg.context ) {
		return older
			? /* translators: %s: the version the theme’s files were compared with. */
			  __( 'Theme · compared with %s', 'bettershield' )
			: /* translators: %s: a theme’s version number. */
			  __( 'Theme · version %s', 'bettershield' );
	}

	return older
		? /* translators: %s: the version the files were compared with. */
		  __( 'Compared with %s', 'bettershield' )
		: /* translators: %s: a version number. */
		  __( 'Version %s', 'bettershield' );
}

/**
 * Changes by plugin (1:1767): a row per plugin and version with its counts,
 * whether it was compared with the version installed now, and what to do.
 *
 * @param {Object}   props
 * @param {Object[]} props.packages The report's groups.
 * @param {?Object}  props.core     WordPress core's own changed files.
 * @param {boolean}  props.canAct   The reader may change shared code.
 * @param {Function} props.busy     Whether a key's request is out.
 * @param {Function} props.keyOf    A group's identity.
 * @param {Function} props.onRecheck   Checks a group's files again.
 * @param {Function} props.onReview    Opens the accept dialog for a group.
 */
export function PluginTable( { packages, core = null, canAct, busy, keyOf, onRecheck, onReview } ) {
	const dash = <span className="bs-ds-fplug__none">—</span>;
	const number = ( n ) => ( Number( n ) > 0 ? formatCount( n ) : dash );
	const rows = [
		...( core && core.total
			? [ { ...core, name: __( 'WordPress core', 'bettershield' ), context: 'core', installed: core.version, isCore: true } ]
			: [] ),
		...packages,
	];

	return (
		<div className="bs-ds-fplug" role="table" aria-label={ __( 'Changes by plugin', 'bettershield' ) }>
			<div className="bs-ds-fplug__row bs-ds-fplug__row--head" role="row">
				<span role="columnheader">{ __( 'Plugin', 'bettershield' ) }</span>
				<span role="columnheader">{ __( 'Changed', 'bettershield' ) }</span>
				<span role="columnheader">{ __( 'Added', 'bettershield' ) }</span>
				<span role="columnheader">{ __( 'Missing', 'bettershield' ) }</span>
				<span role="columnheader">{ __( 'Status', 'bettershield' ) }</span>
				<span role="columnheader">{ __( 'Action', 'bettershield' ) }</span>
			</div>
			{ rows.map( ( pkg ) => {
				const key = pkg.isCore ? 'core' : keyOf( pkg );
				const older = ! pkg.isCore && !! pkg.installed && !! pkg.version && pkg.installed !== pkg.version;

				return (
					<div key={ key } className="bs-ds-fplug__row" role="row">
						<span className="bs-ds-fplug__name" role="cell">
							<span className="bs-ds-fplug__title">{ pkg.name }</span>
							<span className="bs-ds-fplug__sub">
								{ sprintf( subLine( pkg, older ), pkg.version || __( 'unknown', 'bettershield' ) ) }
							</span>
						</span>
						<span role="cell" data-label={ __( 'Changed', 'bettershield' ) }>
							{ number( pkg.modified ) }
						</span>
						<span role="cell" data-label={ __( 'Added', 'bettershield' ) }>
							{ number( pkg.added ) }
						</span>
						<span role="cell" data-label={ __( 'Missing', 'bettershield' ) }>
							{ number( pkg.removed ) }
						</span>
						<span role="cell" className="bs-ds-fplug__status">
							{ older ? (
								<Badge tone="yellow">
									{ sprintf(
										/* translators: %s: the version installed now. */
										__( '%s installed', 'bettershield' ),
										pkg.installed
									) }
								</Badge>
							) : (
								<span className="bs-ds-fplug__ready">
									{ pkg.installed || pkg.isCore ? __( 'Ready to review', 'bettershield' ) : __( 'Not installed now', 'bettershield' ) }
								</span>
							) }
						</span>
						<span role="cell" className="bs-ds-fplug__action">
							{ canAct && ! pkg.isCore && older && 'theme' !== pkg.context ? (
								<Button
									type="secondary"
									size="sm"
									icon="refresh-cw"
									iconTone="1"
									isBusy={ busy( `recheck-${ key }` ) }
									disabled={ busy( `recheck-${ key }` ) }
									aria-label={ sprintf(
										/* translators: %s: a plugin's name. */
										__( 'Check %s again', 'bettershield' ),
										pkg.name
									) }
									onClick={ () => onRecheck( pkg ) }
								>
									{ busy( `recheck-${ key }` ) ? __( 'Checking…', 'bettershield' ) : __( 'Check Again', 'bettershield' ) }
								</Button>
							) : null }
							{ ! pkg.isCore && older && 'theme' === pkg.context ? (
								// Themes have no check-again of their own: say when it happens
								// rather than leave the cell empty.
								<span className="bs-ds-fplug__ready">{ __( 'Compared again at the next check', 'bettershield' ) }</span>
							) : null }
							{ canAct && ! pkg.isCore && ! older ? (
								<Button
									type="secondary"
									size="sm"
									isBusy={ busy( `preview-${ key }` ) }
									disabled={ busy( `preview-${ key }` ) }
									aria-label={ sprintf(
										/* translators: 1: number of changes, 2: a plugin's name. */
										_n( 'Review and accept %1$s change to %2$s', 'Review and accept %1$s changes to %2$s', pkg.total, 'bettershield' ),
										formatCount( pkg.total ),
										pkg.name
									) }
									onClick={ () => onReview( pkg ) }
								>
									{ sprintf(
										/* translators: %s: number of changes. */
										__( 'Review and Accept %s', 'bettershield' ),
										formatCount( pkg.total )
									) }
								</Button>
							) : null }
						</span>
					</div>
				);
			} ) }
		</div>
	);
}

/** A path's last part: the file's own name. */
export function fileName( path ) {
	const parts = String( path || '' ).split( '/' );

	return parts[ parts.length - 1 ] || String( path || '' );
}

/**
 * Where a file sits inside its plugin, theme or the site: the folders
 * between the root and the file.
 *
 * @param {Object} change The change.
 * @return {string} e.g. "includes/Traits", "plugin root" or "Site root".
 */
export function folderOf( change ) {
	const path = String( change.path || '' );
	let rest = path;

	if ( change.slug && ( 'plugin' === change.context || 'unlisted' === change.context ) ) {
		rest = path.replace( new RegExp( `^wp-content/plugins/${ escapeRegExp( change.slug ) }/` ), '' );
	} else if ( change.slug && 'theme' === change.context ) {
		rest = path.replace( new RegExp( `^wp-content/themes/${ escapeRegExp( change.slug ) }/` ), '' );
	}

	const at = rest.lastIndexOf( '/' );

	if ( at > 0 ) {
		return rest.slice( 0, at );
	}

	if ( rest !== path ) {
		return 'theme' === change.context ? __( 'theme root', 'bettershield' ) : __( 'plugin root', 'bettershield' );
	}

	return __( 'Site root', 'bettershield' );
}

function escapeRegExp( text ) {
	return String( text ).replace( /[.*+?^${}()|[\]\\]/g, '\\$&' );
}

/**
 * Accept N changes (1:2253): what marking one plugin's changes accepted
 * covers, asked before it is done, with each added script named.
 *
 * @param {Object}   props
 * @param {Object}   props.pkg       The group.
 * @param {Object}   props.preview   What the site says the marking covers.
 * @param {boolean}  props.busy      The marking is on its way.
 * @param {Function} props.onConfirm Marks them.
 * @param {Function} props.onCancel  Closes the dialog.
 */
export function AcceptDialog( { pkg, preview, busy, onConfirm, onCancel } ) {
	const titleId = `bs-ds-faccept-${ useId().replace( /[^\w-]/g, '' ) }`;
	const name = preview.name || pkg.name;
	const added = preview.added_code || [];
	const more = ( preview.added_code_total || 0 ) - added.length;
	// Inside the folder the dialog already names, so each line is what differs.
	const folder = `wp-content/${ 'theme' === preview.context ? 'themes' : 'plugins' }/${ preview.slug || pkg.slug }/`;
	const inside = ( path ) => ( path.startsWith( folder ) ? path.slice( folder.length ) : path );
	const counts = [
		{ key: 'modified', label: __( 'Changed', 'bettershield' ), value: preview.modified ?? pkg.modified },
		{ key: 'added', label: __( 'Added', 'bettershield' ), value: preview.added ?? pkg.added },
		...( Number( preview.removed ?? pkg.removed ) > 0 ? [ { key: 'removed', label: __( 'Missing', 'bettershield' ), value: preview.removed ?? pkg.removed } ] : [] ),
		{ key: 'code', label: __( 'Can run as code', 'bettershield' ), value: preview.added_code_total || 0, warn: true },
	];

	return (
		<Modal className="bs-ds-faccept" aria={ { labelledby: titleId } } onRequestClose={ onCancel } size="medium">
			<div className="bs-ds-faccept__head">
				<h2 className="bs-ds-faccept__title" id={ titleId }>
					{ sprintf(
						/* translators: 1: number of changes, 2: a plugin's name. */
						_n( 'Accept %1$s change to %2$s?', 'Accept %1$s changes to %2$s?', preview.total, 'bettershield' ),
						formatCount( preview.total ),
						name
					) }
				</h2>
				<p className="bs-ds-faccept__lead">
					{ sprintf(
						/* translators: 1: a plugin's name, 2: its version. */
						__( '%1$s %2$s. Each change is hidden until its file changes again.', 'bettershield' ),
						name,
						preview.version || pkg.version
					) }
				</p>
			</div>

			<div className="bs-ds-faccept__body">
				<dl className="bs-ds-faccept__counts">
					{ counts.map( ( count ) => (
						<div key={ count.key } className="bs-ds-faccept__count">
							<dt>{ count.label }</dt>
							<dd className={ count.warn && Number( count.value ) > 0 ? 'bs-ds-faccept__warn' : undefined }>
								{ /* None reads as the table reads it, a dash rather than "0". */ }
								{ Number( count.value ) > 0 ? formatCount( Number( count.value ) ) : <span className="bs-ds-fplug__none">—</span> }
							</dd>
						</div>
					) ) }
				</dl>

				{ preview.added_code_total ? (
					<div className="bs-ds-faccept__scripts">
						<p className="bs-ds-faccept__text">
							{ sprintf(
								/* translators: %s: number of added files that can run as code. */
								_n(
									'%s added file is a script that could run on your site. Look at it before you accept.',
									'%s added files are scripts that could run on your site. Look at them before you accept.',
									preview.added_code_total,
									'bettershield'
								),
								formatCount( preview.added_code_total )
							) }
						</p>
						<ul className="bs-ds-faccept__list">
							{ added.map( ( path ) => {
								const within = inside( path );
								const at = within.lastIndexOf( '/' );

								return (
									<li key={ path } className="bs-ds-faccept__item">
										<Icon name="code" size={ 16 } tone="2" />
										<span className="bs-ds-faccept__file">
											<span className="bs-ds-faccept__name">{ fileName( within ) }</span>
											<span className="bs-ds-faccept__meta">
												{ [ at > 0 ? within.slice( 0, at ) : '', __( 'Added', 'bettershield' ), __( 'Can run as code', 'bettershield' ) ].filter( Boolean ).join( ' · ' ) }
											</span>
										</span>
									</li>
								);
							} ) }
						</ul>
						{ more > 0 ? (
							<p className="bs-ds-faccept__text">
								{ sprintf(
									/* translators: %s: number of added code files not listed. */
									_n( 'And %s more.', 'And %s more.', more, 'bettershield' ),
									formatCount( more )
								) }
							</p>
						) : null }
					</div>
				) : null }

				<ul className="bs-ds-faccept__notes">
					<li>
						<Icon name="check" size={ 16 } tone="2" />
						<span>{ __( 'You can undo it in one step, from the Accepted tab.', 'bettershield' ) }</span>
					</li>
					<li>
						<Icon name="check" size={ 16 } tone="2" />
						<span>{ __( 'New changes to these files are still shown.', 'bettershield' ) }</span>
					</li>
				</ul>
			</div>

			<div className="bs-ds-app bs-ds-faccept__actions">
				<Button type="ghost" size="md" onClick={ onCancel }>
					{ __( 'Cancel', 'bettershield' ) }
				</Button>
				<Button type="primary" size="md" isBusy={ busy } disabled={ busy } onClick={ onConfirm }>
					{ sprintf(
						/* translators: %s: number of changes. */
						_n( 'Accept %s Change', 'Accept %s Changes', preview.total, 'bettershield' ),
						formatCount( preview.total )
					) }
				</Button>
			</div>
		</Modal>
	);
}

/**
 * A filter as the design draws it (Type, Location, Severity, 1:1786): its
 * name, then the choice, on one control.
 *
 * @param {Object}   props
 * @param {string}   props.label    The filter's name.
 * @param {string}   props.value    The choice.
 * @param {Array}    props.options  [{ value, label }].
 * @param {Function} props.onChange Called with the new choice.
 */
export function FilterChip( { label, value, options, onChange } ) {
	return (
		<label className="bs-ds-fchip">
			<span className="bs-ds-fchip__label">{ label }</span>
			<select className="bs-ds-fchip__select" value={ value } onChange={ ( event ) => onChange( event.target.value ) }>
				{ options.map( ( option ) => (
					<option key={ option.value } value={ option.value }>
						{ option.label }
					</option>
				) ) }
			</select>
			<Icon name="chevron-down" size={ 14 } tone="2" />
		</label>
	);
}

/**
 * A severity as four marks and its word (Impact, 27:43485).
 *
 * @param {Object} props
 * @param {string} props.severity One of the five.
 */
export function SeverityMeter( { severity } ) {
	const shown = SEVERITY[ severity ] || SEVERITY.info;

	return (
		<span className="bs-ds-fcsev">
			<span className="bs-ds-meter" aria-hidden="true">
				{ [ 0, 1, 2, 3 ].map( ( segment ) => (
					<span key={ segment } className={ segment < ( METER[ severity ] || 0 ) ? `is-${ severity }` : '' } />
				) ) }
			</span>
			<span className="bs-ds-fcsev__word">{ shown.label() }</span>
		</span>
	);
}

/**
 * A group's band (Group, 27:38734): its icon, its name in capitals and how
 * many it holds.
 *
 * @param {Object} props
 * @param {string} props.icon  The band's icon.
 * @param {string} props.label The group's name.
 * @param {*}      props.count How many it holds.
 * @param {*}      props.pick  The checkbox that picks the group, in selection mode.
 */
export function GroupBand( { icon, label, count, pick = null } ) {
	return (
		<div className="bs-ds-fcgroup" role="row">
			<div className="bs-ds-fcgroup__cell" role="cell">
				{ pick }
				<Icon name={ icon } size={ 14 } tone="2" />
				<h3 className="bs-ds-fcgroup__label">{ label }</h3>
				<Badge>{ 'number' === typeof count ? formatCount( count ) : count }</Badge>
			</div>
		</div>
	);
}

/**
 * Why a file's severity is what it is, by what kind of file it is.
 *
 * @param {Object} change The change.
 * @return {string} One sentence.
 */
function severityReason( change ) {
	const name = fileName( change.path ).toLowerCase();
	const ext = name.includes( '.' ) ? name.split( '.' ).pop() : '';

	if ( 'removed' === change.change_type ) {
		return __( 'A missing file can stop part of the site from working as it should.', 'bettershield' );
	}

	if ( [ 'php', 'phtml', 'php5', 'php7', 'phar', 'inc' ].includes( ext ) ) {
		if ( 'core' === change.context ) {
			return __( 'It’s a PHP file, so it runs every time WordPress loads.', 'bettershield' );
		}

		return 'theme' === change.context
			? __( 'It’s a PHP file, so it runs every time the theme loads.', 'bettershield' )
			: __( 'It’s a PHP file, so it runs every time the plugin loads.', 'bettershield' );
	}

	if ( [ 'js', 'mjs' ].includes( ext ) ) {
		return __( 'It’s a script, so it runs in your visitors’ browsers.', 'bettershield' );
	}

	if ( 'css' === ext ) {
		return __( 'It’s a stylesheet. It can change how pages look, but it doesn’t run code.', 'bettershield' );
	}

	return __( 'Files like this don’t run on their own, but other code can read them.', 'bettershield' );
}

/**
 * The four cards a changed file opens into (Row detail, 27:43521): why it
 * matters, what could break, why its severity, and the evidence.
 *
 * @param {Object}  props
 * @param {Object}  props.change   The change.
 * @param {string}  props.name     The plugin, theme or WordPress it belongs to.
 * @param {string}  props.severity Its severity.
 * @param {?string} props.checked  When the site was last checked.
 * @param {string}  props.id       The detail's id.
 */
export function FileDetail( { change, name, severity, checked, id } ) {
	const whose = change.version
		? sprintf(
				/* translators: 1: a plugin, theme or "WordPress"; 2: its version. */
				__( '%1$s %2$s', 'bettershield' ),
				name,
				change.version
		  )
		: name;
	let matters = change.why_not || __( 'This file differs from the copy it was compared with.', 'bettershield' );
	let breaks = __( 'Accepting the change stops listing it until the file changes again. Nothing on your site changes.', 'bettershield' );

	if ( 'modified' === change.change_type && change.restorable ) {
		matters = sprintf(
			/* translators: %s: a plugin, theme or WordPress, with its version. */
			__( 'This file differs from the copy %s ships. Sometimes that is a developer’s deliberate edit. Sometimes it is code somebody else put on your site.', 'bettershield' ),
			whose
		);
		breaks = __( 'Restoring puts the official copy back. Your version is kept in quarantine, so nothing is lost. If you edited this file on purpose, accept the change instead.', 'bettershield' );
	} else if ( 'added' === change.change_type ) {
		matters = sprintf(
			/* translators: %s: a plugin, theme or WordPress, with its version. */
			__( 'This file isn’t part of %s. Sometimes a developer added it on purpose. Sometimes it is code somebody else put on your site.', 'bettershield' ),
			whose
		);
		breaks = __( 'Moving it to quarantine leaves an empty placeholder, so anything that uses the file may stop working. You can put it back anytime.', 'bettershield' );
	} else if ( 'removed' === change.change_type ) {
		matters = sprintf(
			/* translators: %s: a plugin, theme or WordPress, with its version. */
			__( 'This file is part of %s, but it isn’t on your site.', 'bettershield' ),
			whose
		);
		breaks = sprintf(
			/* translators: %s: the plugin’s name, or the label the site owner gave it. */
			__( '%s can’t recreate missing files. Reinstall the plugin, theme or WordPress version it came from, then check again.', 'bettershield' ),
			brand()
		);
	}

	return (
		<div className="bs-ds-fcdetail" id={ id } role="row">
			<div className="bs-ds-fcdetail__cards" role="cell">
				<div className="bs-ds-fdetail__card">
					<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">{ __( 'Why it matters', 'bettershield' ) }</p>
					<div className="bs-ds-fdetail__body">
						<p className="bs-ds-fcdetail__text">{ matters }</p>
					</div>
				</div>
				<div className="bs-ds-fdetail__card">
					<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">{ __( 'What could break', 'bettershield' ) }</p>
					<div className="bs-ds-fdetail__body">
						<p className="bs-ds-fcdetail__text">{ breaks }</p>
					</div>
				</div>
				<div className="bs-ds-fdetail__card">
					<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">
						{ whyTitle( severity ) }
					</p>
					<div className="bs-ds-fdetail__body">
						<p className="bs-ds-fcdetail__text">{ severityReason( change ) }</p>
					</div>
				</div>
				<div className="bs-ds-fcdetail__evidence">
					<div className="bs-ds-fcdetail__evcard">
						<p className="bs-ds-fdetail__head bs-ds-t14 bs-ds-m bs-ds-c1">{ __( 'Evidence', 'bettershield' ) }</p>
						<div className="bs-ds-fcdetail__evbody">
							<span className="bs-ds-fcdetail__evlabel">{ __( 'Compared with', 'bettershield' ) }</span>
							<span className="bs-ds-fcdetail__evvalue">{ change.version || __( 'Its earlier copy', 'bettershield' ) }</span>
						</div>
					</div>
					<p className="bs-ds-fcdetail__evfoot">
						<span>{ __( 'Last checked:', 'bettershield' ) }</span>
						<span>{ checked ? formatTime( checked ) : __( 'Not yet', 'bettershield' ) }</span>
					</p>
				</div>
			</div>
		</div>
	);
}
