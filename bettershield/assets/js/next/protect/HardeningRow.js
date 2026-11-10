/**
 * One hardening item as a row of a card: the switch leading, the item's name
 * and one line about it, its state, and the rest under the row. Drawn on
 * Hardening and, for the items about signing in, on Login & access; where it
 * is drawn changes nothing about the item: the same apply, the same undo
 * through the ledger, the same preview and the same conflict probe.
 *
 * Two rules shape the row. A conflict or a blocker is said inside the row of
 * the switch that would meet it, never after the failure. And the preview is
 * a real preview: it asks the server what applying would do and changes
 * nothing, so a cautious owner can read the exact effect first.
 */

import './HardeningRow.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, _x, sprintf } from '@wordpress/i18n';
import { formatTime, isWorking, useStore } from '../../store';
import { onEscape } from '../../ui/keys';
import { sameFieldValues } from '../../ui/preview';
import { reportRows, reportsBeyond } from '../../ui/reports';
import { patternProblem } from '../../ui/validate';
import { whenPhrase } from '../../ui/when';
import Alert from '../ui/Alert';
import Armed from '../ui/Armed';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import CopyField, { CopyButton } from '../ui/CopyField';
import Default from '../ui/Default';
import Field from '../ui/Field';
import Icon from '../ui/Icon';
import SettingRow, { Toggle } from '../ui/Setting';
import Topics from '../ui/Topics';
import HardeningMonitor, { hasMonitor } from './Monitor';

/**
 * What a field that takes several choices holds now: what was picked, or the
 * default until something is.
 *
 * @param {Object} field  The field.
 * @param {Object} values What has been chosen so far, by key.
 * @return {string[]} The picked values.
 */
function picked( field, values ) {
	const value = values[ field.key ];

	if ( Array.isArray( value ) ) {
		return value;
	}

	return [ value || field.default ].filter( Boolean );
}

/**
 * The owner's input an item takes before it is applied, each field with the
 * value it ships with under it.
 *
 * @param {Object}   props
 * @param {Array}    props.fields   The item's fields.
 * @param {Object}   props.values   What has been chosen so far, by key.
 * @param {Function} props.onChange Called with a field's key and its new value.
 */
function Fields( { fields, values, onChange } ) {
	const box = useRef( null );

	/*
	 * Back to the default, and focus with it: the line that held the button
	 * goes once the default is chosen, and a removed control drops focus to
	 * the page. A choice lands on its chosen option, a text field on itself.
	 */
	const reset = ( field ) => {
		onChange( field.key, field.multiple ? [ field.default ] : field.default );

		window.requestAnimationFrame( () => {
			let selector = field.choices ? `input[type="radio"][value="${ field.default }"]` : 'input';

			if ( field.multiple ) {
				selector = 'input[type="checkbox"]:checked';
			}

			const own = box.current && box.current.querySelector( `[data-field="${ field.key }"]` );
			const control = own && own.querySelector( selector );

			if ( control ) {
				control.focus();
			}
		} );
	};

	return (
		<div className="bs-ds-hrow__fields" ref={ box }>
			{ fields.map( ( field ) => {
				let control;

				if ( field.choices && field.multiple ) {
					/*
					 * A field that takes several choices, as the roles to keep
					 * out of the dashboard do: drawn as radios, a store could
					 * keep its subscribers or its customers out, never both.
					 */
					control = (
						<Field
							kind="checks"
							label={ field.label }
							help={ field.description }
							options={ field.choices }
							value={ picked( field, values ) }
							onChange={ ( chosen ) => onChange( field.key, chosen ) }
						/>
					);
				} else if ( field.choices ) {
					/*
					 * Both options stay on screen rather than folding into a
					 * dropdown: the choice decides who this stops working for,
					 * and that is not a detail to hide behind one line of text.
					 */
					control = (
						<Field
							kind="radio"
							label={ field.label }
							help={ field.description }
							value={ values[ field.key ] || field.default || '' }
							options={ field.choices }
							onChange={ ( value ) => onChange( field.key, value ) }
						/>
					);
				} else {
					control = (
						<Field
							width="md"
							label={ field.label }
							/*
							 * The rule while it is being broken, and what the
							 * field is for the rest of the time. The pattern
							 * travels from the item that owns it, so the screen
							 * never carries a second copy of a rule to drift
							 * from the one that refuses.
							 */
							help={
								patternProblem( values[ field.key ] || '', field.pattern, field.pattern_note, true === field.lowercase ) ||
								field.description
							}
							placeholder={ field.placeholder }
							/*
							 * None of these are credentials, but a field on a
							 * security screen labeled "sign-in address" reads
							 * like one to a password manager, which offers to
							 * fill it and leaves its badge in the input.
							 */
							autoComplete="off"
							value={ values[ field.key ] || '' }
							onChange={ ( value ) => onChange( field.key, value ) }
						/>
					);
				}

				return (
					<div key={ field.key } className="bs-ds-hrow__field" data-field={ field.key }>
						{ control }
						{ /*
						   The value the item ships with, for anybody who has
						   typed over it and wants back. A choice is compared as
						   it is drawn (the default until another option is
						   picked) and named by the option's words rather than
						   its stored value.
						*/ }
						{ field.default ? (
							<Default
								value={
									field.multiple ? picked( field, values ).join( ',' ) : field.choices ? values[ field.key ] || field.default : values[ field.key ] || ''
								}
								fallback={ field.default }
								format={
									field.choices
										? ( value ) => ( field.choices.find( ( choice ) => choice.value === value ) || {} ).label || value
										: undefined
								}
								onReset={ () => reset( field ) }
							/>
						) : null }
					</div>
				);
			} ) }
		</div>
	);
}

/**
 * The preview's lines, less the one "How this works" already says word for
 * word: the two disclosures read the same on most rows (#2575). Kept whole
 * where that line is all there is.
 *
 * @param {string[]} lines The preview's lines.
 * @param {string}   how   What "How this works" says.
 * @return {string[]} The lines to list.
 */
export function previewLines( lines = [], how = '' ) {
	const rest = how ? lines.filter( ( line ) => line !== how ) : lines;

	return rest.length ? rest : lines;
}

/**
 * What a real page a visitor received actually carried.
 *
 * Every other line on the row comes from what the plugin stored when the item
 * was applied. This one comes from the site, so it is a line of its own, and
 * an item nothing can observe says so outright: a blank there reads as "fine",
 * and that is not a claim this can make.
 *
 * @param {Object} props
 * @param {Object} props.item The hardening item.
 */
function Verified( { item } ) {
	if ( ! item.active ) {
		return null;
	}

	// Said by the ⓘ beside the row's own "On": a second "On" chip under it
	// read as the same answer twice (#2575).
	if ( ! item.observable ) {
		return null;
	}

	const record = item.verification;

	if ( ! record ) {
		return null;
	}

	let kind = 'waiting';
	let mark = [ 'clock', '3' ];

	if ( 'present' === record.status ) {
		kind = 'good';
		mark = [ 'circle-check', 'ok' ];
	} else if ( 'absent' === record.status ) {
		kind = 'bad';
		mark = [ 'triangle-alert', 'warning' ];
	}

	return (
		<p className={ `bs-ds-hrow__verify bs-ds-hrow__verify--${ kind }` }>
			<Icon name={ mark[ 0 ] } size={ 12 } tone={ mark[ 1 ] } />
			<span>
				{ 'present' === record.status
					? sprintf(
							/* translators: %s: date and time. */
							__( 'Confirmed on a page a visitor received, %s.', 'bettershield' ),
							formatTime( new Date( record.at * 1000 ).toISOString() )
					  )
					: record.detail }
			</span>
		</p>
	);
}

/**
 * An extra operation on an applied item. Consequential (rotating keys signs
 * every other account out), so it asks once before it acts and says what it
 * will do; one the site has not earned yet is stated rather than offered.
 *
 * @param {Object}   props
 * @param {Object}   props.action  The action.
 * @param {Function} props.onRun   Runs it.
 * @param {boolean}  props.working The item's request is running.
 */
function Action( { action, onRun, working } ) {
	/*
	 * A button that exists only to be refused teaches somebody to press it and
	 * read an error, when the reason is a fact about their own site and is
	 * more useful said plainly. The server refuses it anyway, so this is the
	 * presentation of that rule and not the rule itself.
	 */
	if ( false === action.available ) {
		return (
			<p className="bs-ds-hrow__unavailable">
				<strong>{ action.label }</strong> — { action.description }
			</p>
		);
	}

	return (
		<Armed
			label={ action.label }
			consequence={ action.description }
			busy={ working }
			disabled={ working }
			confirm={ sprintf(
				/* translators: %s: action name. */
				__( 'Yes: %s', 'bettershield' ),
				action.label
			) }
			onConfirm={ () => onRun( action.key ) }
		/>
	);
}

/**
 * What the policy has watched happen, as visitors' browsers reported it, with
 * the way to let a source in where the server says one can be.
 *
 * @param {Object}   props
 * @param {Array}    props.rows    The loudest kinds.
 * @param {number}   props.left    How many more kinds there are than the list shows.
 * @param {boolean}  props.working The item's request is running.
 * @param {Function} props.onAllow Lets one row's source into the policy.
 */
function Reports( { rows, left, working = false, onAllow = null } ) {
	return (
		<div className="bs-ds-hrow__reports">
			<ul>
				{ rows.map( ( row ) => (
					<li key={ row.key }>
						<span className="bs-ds-hrow__directive">{ row.directive }</span>
						<span className="bs-ds-hrow__origin">{ row.blocked }</span>
						<span className="bs-ds-hrow__times">{ row.times }</span>
						{ row.allow && onAllow ? (
							<Armed
								type="ghost"
								label={ __( 'Allow', 'bettershield' ) }
								aria-label={ sprintf(
									/* translators: 1: where the blocked resource came from, 2: a content policy directive. */
									__( 'Allow %1$s for %2$s', 'bettershield' ),
									row.allow.source,
									row.allow.as
								) }
								consequence={ [
									sprintf(
										/* translators: 1: where the blocked resource came from, 2: a content policy directive. */
										__( 'Adds %1$s to %2$s. Anyone can send reports, so allow only a source you recognize. The 7-day quiet period starts over.', 'bettershield' ),
										row.allow.source,
										row.allow.as
									),
									row.allow.warning,
								]
									.filter( Boolean )
									.join( ' ' ) }
								confirm={ __( 'Yes: Allow It', 'bettershield' ) }
								busy={ working }
								disabled={ working }
								onConfirm={ () => onAllow( row.allow ) }
							/>
						) : null }
					</li>
				) ) }
			</ul>
			{ /* The list is the loudest kinds; the count beside the switch is all of them. */ }
			{ left > 0 ? (
				<p>
					{ sprintf(
						/* translators: %d: how many more kinds were reported than the list shows. */
						_n( 'And %d more kind, reported less often.', 'And %d more kinds, reported less often.', left, 'bettershield' ),
						left
					) }
				</p>
			) : null }
			<p>
				{ __( 'Visitors’ browsers report these. Allow or fix each one before you turn the policy on.', 'bettershield' ) }{ ' ' }
				{ __( 'Code written straight into a page can’t be allowed; a developer has to move it into a file.', 'bettershield' ) }
			</p>
		</div>
	);
}

/**
 * The sources the owner let into the policy, each with the way back.
 *
 * @param {Object}   props
 * @param {Array}    props.sources  [{ directive, source }].
 * @param {boolean}  props.working  The item's request is running.
 * @param {Function} props.onRemove Takes one back off.
 */
function Allowed( { sources, working, onRemove } ) {
	return (
		<div className="bs-ds-hrow__reports">
			<ul>
				{ sources.map( ( entry ) => (
					<li key={ entry.directive + ' ' + entry.source }>
						<span className="bs-ds-hrow__directive">{ entry.directive }</span>
						<span className="bs-ds-hrow__origin">{ entry.source }</span>
						<Armed
							type="ghost"
							label={ __( 'Remove', 'bettershield' ) }
							aria-label={ sprintf(
								/* translators: 1: an allowed source, 2: a content policy directive. */
								__( 'Stop Allowing %1$s for %2$s', 'bettershield' ),
								entry.source,
								entry.directive
							) }
							consequence={ sprintf(
								/* translators: 1: an allowed source, 2: a content policy directive. */
								__( 'Removes %1$s from %2$s. Anything from there is reported again, and blocked while the policy is enforced. The 7-day quiet period starts over.', 'bettershield' ),
								entry.source,
								entry.directive
							) }
							confirm={ __( 'Yes: Remove It', 'bettershield' ) }
							busy={ working }
							disabled={ working }
							onConfirm={ () => onRemove( entry ) }
						/>
					</li>
				) ) }
			</ul>
		</div>
	);
}

/**
 * @param {Object} props
 * @param {Object} props.item       The hardening item.
 * @param {string} props.sharedNote A note the screen already says once above its rows; this row shows a chip for it instead.
 */
export default function HardeningRow( { item, sharedNote = '' } ) {
	const { applyItem, revertItem, itemAction, dryRun, busy, confirming, preflight } = useStore();
	const [ preview, setPreview ] = useState( null );
	// The values the preview above was computed for.
	const [ previewFor, setPreviewFor ] = useState( null );
	const [ previewing, setPreviewing ] = useState( false );
	const [ fieldValues, setFieldValues ] = useState( {} );
	const [ monitorOpen, setMonitorOpen ] = useState( false );
	// What the last undo from this row left in place, and why: a guard file
	// someone else changed is left alone, and the screen said only "Off"
	// while the CLI named it (#2110).
	const [ undoNotes, setUndoNotes ] = useState( [] );
	const titleId = `bs-ds-hitem-${ item.id }`;
	// Said once above the rows that share it, and marked on each.
	const shared = Boolean( sharedNote ) && sharedNote === item.availability_note;

	/*
	 * From the values as they stand rather than the ones this render closed
	 * over. An item can carry several fields, and two changes landing in one
	 * tick would otherwise write the second on top of a copy taken before the
	 * first, dropping it with nothing on screen to say so.
	 */
	const setField = ( key, value ) => setFieldValues( ( current ) => ( { ...current, [ key ]: value } ) );

	/*
	 * The switch is the control in both directions, so it is where focus goes
	 * back to after an apply or an undo, and its accessible name is the item's,
	 * so what is announced on arrival says which row this is. Wanted rather
	 * than done here: the request has to finish first.
	 *
	 * A refusal wants it back too: a browser moves focus off a control that
	 * becomes disabled. An action held for the password gate is neither; the
	 * dialog gives focus back itself once it closes.
	 */
	const controlRef = useRef( null );
	const [ focusWanted, setFocusWanted ] = useState( null );
	const working = isWorking( busy, item.id );

	/*
	 * Where the reader moved the switch, shown at once. It waited, grayed
	 * out, for the server's answer and then jumped (#1942). It gives way to
	 * the answer once nothing is in flight or held for a password or a
	 * sign-in check, so a refusal or a cancel slides it back.
	 */
	const [ moved, setMoved ] = useState( null );
	const held = confirming || Boolean( preflight );
	// Provided by the server or another plugin, it's on and not this switch's to change (#2716).
	const on = item.in_force_elsewhere || ( null === moved ? item.active : moved );

	useEffect( () => {
		if ( null !== moved && ! working && ! held ) {
			setMoved( null );
		}
	}, [ moved, working, held ] );

	useEffect( () => {
		if ( ! focusWanted || working ) {
			return;
		}

		const node = controlRef.current && controlRef.current.querySelector( 'input[type="checkbox"]' );

		if ( ! node ) {
			return;
		}

		const active = document.activeElement;

		// Still held for some other reason (a field the change needs is now
		// empty), or the reader has moved on: nothing to give focus to.
		if ( ! node.disabled && ( ! active || active === document.body || active === node ) ) {
			node.focus();
		}

		setFocusWanted( null );
	}, [ focusWanted, item.active, working ] );

	const toggleAgain = ( error ) => {
		if ( error ) {
			setFocusWanted( 'toggle' );
		}
	};

	const fields = item.fields || [];
	const actions = item.actions || [];
	const notes = item.notes || [];
	const reports = reportRows( item.reports );
	const reportsLeft = reportsBeyond( item.reports );
	const allowedSources = Array.isArray( item.allowed_sources ) ? item.allowed_sources.filter( ( entry ) => entry && entry.directive && entry.source ) : [];

	// A field that ships with a default is already answered, so it must not
	// hold the switch while the owner looks at a control that reads filled in.
	const missingInput =
		! item.active &&
		fields.some(
			( field ) =>
				field.required &&
				( field.multiple ? 0 === picked( field, fieldValues ).length : ! ( fieldValues[ field.key ] || field.default || '' ).trim() )
		);

	// And a field whose value breaks a rule the item itself declared: the
	// server would refuse it a moment later.
	const brokenInput =
		! item.active &&
		fields.some( ( field ) => Boolean( patternProblem( fieldValues[ field.key ] || '', field.pattern, field.pattern_note, true === field.lowercase ) ) );

	/*
	 * What goes to the server: what the owner typed or chose, and the declared
	 * default for anything left alone. A field with neither is omitted rather
	 * than sent empty, so an untouched optional field previews as it always has.
	 */
	const chosenValues = fields.reduce( ( carried, field ) => {
		const value = fieldValues[ field.key ] || field.default || '';

		return value ? { ...carried, [ field.key ]: value } : carried;
	}, {} );

	const apply = () => {
		setMoved( true );
		setUndoNotes( [] );
		applyItem(
			item.id,
			fields.length ? chosenValues : undefined,
			( result ) => {
				if ( result ) {
					setFocusWanted( 'toggle' );
				}
			},
			toggleAgain
		);
	};

	const revert = () => {
		setMoved( false );
		setUndoNotes( [] );
		revertItem(
			item.id,
			( result ) => {
				if ( result ) {
					setUndoNotes( Array.isArray( result.notes ) ? result.notes.map( String ).filter( Boolean ) : [] );
					setFocusWanted( 'toggle' );
				}
			},
			toggleAgain
		);
	};

	/*
	 * A preview is about the values it was computed from, so it is shown only
	 * while it still describes them: editing a field after opening one would
	 * otherwise leave the earlier projection under a field that now differs.
	 */
	const previewPanelId = `bs-preview-${ item.id }`;
	const monitorPanelId = `bs-monitor-${ item.id }`;
	const showing = preview && sameFieldValues( previewFor, chosenValues ) ? preview : null;
	const monitored = hasMonitor( item );
	const previewToggle = useRef( null );

	const closePreview = () => {
		setPreview( null );

		if ( previewToggle.current ) {
			previewToggle.current.focus();
		}
	};

	const togglePreview = () => {
		if ( previewing ) {
			return;
		}

		if ( showing ) {
			setPreview( null );

			return;
		}

		setPreviewing( true );
		setPreviewFor( chosenValues );
		dryRun( item.id, fields.length ? chosenValues : undefined )
			.then( ( result ) => setPreview( result ) )
			.finally( () => setPreviewing( false ) );
	};

	/*
	 * Off, and this site cannot have it yet (the server's own configuration,
	 * HTTPS, the main site): the switch is drawn disabled, and the note that
	 * says why is what it is described by. It looked pressable and did
	 * nothing when pressed (#2324).
	 */
	const unreachable = ! item.active && false === item.available && Boolean( item.availability_note ) && ! shared;
	// Nothing on this site needs it: not a fault, and nothing to preview.
	const notNeeded = ! item.active && false === item.available && 'not_needed' === item.availability_reason;

	let state = __( 'Off', 'bettershield' );

	if ( null !== moved ) {
		// Said where the state is, so nothing else on the row moves.
		state = __( 'Saving…', 'bettershield' );
	} else if ( item.in_force_elsewhere ) {
		// Off here, but the server or another plugin already does it, so it
		// reads as on and says who, ahead of a server's own check passing.
		if ( 'host' === item.in_force_by ) {
			state = __( 'Set by your host', 'bettershield' );
		} else if ( item.in_force_by ) {
			/* translators: %s: another plugin's name. */
			state = sprintf( __( 'Set by %s', 'bettershield' ), item.in_force_by );
		} else {
			state = __( 'Already in force on this site', 'bettershield' );
		}
	} else if ( false === item.available ) {
		// Why, in the server's words for it: needs HTTPS, the server's own
		// configuration, the main site or the network (#2235).
		state = item.availability_label || __( 'Not available here', 'bettershield' );
	} else if ( item.active ) {
		state = __( 'On', 'bettershield' );
	}

	/*
	 * What the switch cannot say: when this was applied, and that turning it
	 * back off is always available.
	 */
	const meta = item.active ? (
		<span className="bs-ds-hrow__meta">
			{ item.applied_at ? (
				<span>
					{ sprintf(
						/* translators: %s: when, e.g. "Tue" or "yesterday". */
						__( 'On since %s', 'bettershield' ),
						whenPhrase( item.applied_at )
					) }
				</span>
			) : null }
			{ /* Undo cannot reach a browser that already kept what it was sent.
			     That every other one can be undone is said once above the
			     cards, not on each row (#2606). */ }
			{ false === item.reversible ? <span>{ __( 'Undo stops it, but browsers that already saw it remember it for a while.', 'bettershield' ) }</span> : null }
		</span>
	) : item.in_force_elsewhere ? (
		<span className="bs-ds-hrow__meta">
			<span>{ __( 'Changing it here won’t turn it off.', 'bettershield' ) }</span>
		</span>
	) : null;

	/*
	 * The technical line (the registry's own first word on what applying
	 * does, which is a declaration rather than a measurement) and what
	 * applying actually did, then what the policy watched happen. The whole
	 * set of effects is under Preview the change, which asks the server.
	 */
	// Before it is applied, an item whose choice changes what it does says
	// how the picked choice works.
	const chosenHow = item.active
		? ''
		: fields.reduce( ( found, field ) => found || ( ( field.choices || [] ).find( ( choice ) => choice.value === ( fieldValues[ field.key ] || field.default ) ) || {} ).how || '', '' );
	const effect = chosenHow || ( item.effect || [] )[ 0 ] || '';
	const topics = [
		effect || ( item.active && notes.length )
			? {
					key: 'how',
					label: __( 'How this works', 'bettershield' ),
					text: effect,
					points: item.active ? notes : [],
			  }
			: null,
		item.active && reports.length
			? {
					key: 'reports',
					label: __( 'What it would have blocked', 'bettershield' ),
					body: (
						<Reports
							rows={ reports }
							left={ reportsLeft }
							working={ working }
							onAllow={ ( allow ) => itemAction( item.id, 'allow_source', { directive: allow.directive, source: allow.source } ) }
						/>
					),
			  }
			: null,
		item.active && allowedSources.length
			? {
					key: 'allowed',
					label: __( 'Sources you allowed', 'bettershield' ),
					body: (
						<Allowed
							sources={ allowedSources }
							working={ working }
							onRemove={ ( entry ) => itemAction( item.id, 'remove_source', { directive: entry.directive, source: entry.source } ) }
						/>
					),
			  }
			: null,
		/*
		 * Where this cannot apply on this server, the same rule in the
		 * server's own syntax, for the owner or the host to add by hand.
		 */
		false === item.available && item.server_rule
			? {
					key: 'server',
					label: __( 'Rules for your host', 'bettershield' ),
					lead: item.server_rule.where,
					body: <CopyField label={ item.server_rule.label } value={ item.server_rule.text } multiline copyLabel={ __( 'Copy the Rules', 'bettershield' ) } />,
					note: {
						tone: 'info',
						text: __( 'Your server ignores the rules BetterShield writes. Send these lines to your host; once added, the protection works.', 'bettershield' ),
					},
			  }
			: null,
	].filter( Boolean );

	return (
		<SettingRow
			id={ titleId }
			focusKey={ item.id }
			className={ `bs-ds-hrow${ on ? ' is-on' : '' }` }
			title={ item.title }
			about={ item.description }
			// Where "On" comes from, for a row nothing outside can check, in the
			// row's own ⓘ rather than a second "On" chip (#2575).
			tip={
				item.active && ! item.observable
					? [ item.detail, __( 'This can’t be checked from outside, so “On” comes from your settings.', 'bettershield' ) ].filter( Boolean ).join( ' ' )
					: item.detail || null
			}
			badge={
				<>
					<Badge tone={ null === moved && ( ( item.active && false !== item.available ) || 'server_enforced' === item.availability_reason || item.in_force_elsewhere ) ? 'brand' : 'neutral' }>{ state }</Badge>
					{ shared ? <Badge>{ __( 'May not work on this server', 'bettershield' ) }</Badge> : null }
				</>
			}
			meta={ meta }
			lead={
				<span className="bs-ds-hrow__switch" ref={ controlRef }>
					{ /*
					   An item this site cannot have stays off, but one that
					   became unavailable after it was applied (a move to
					   nginx, an address that lost HTTPS) still has to be
					   switchable off: this switch is the way to undo it.
					*/ }
					<Toggle
						checked={ on }
						// Not disabled while it saves: a disabled control loses
						// focus and grays out. A second press waits instead, and
						// so does a press while another row saves: the store
						// would drop it, and the switch moved and snapped back.
						disabled={ Boolean( item.in_force_elsewhere ) || ( ! item.active && false === item.available ) || missingInput || brokenInput }
						onChange={ () => {
							if ( working || null !== moved || busy ) {
								return;
							}

							if ( item.active ) {
								revert();
							} else {
								apply();
							}
						} }
						labelledBy={ titleId }
						describedBy={ [ item.description ? `${ titleId }-about` : '', unreachable ? `${ titleId }-why` : '' ].filter( Boolean ).join( ' ' ) || undefined }
					/>
				</span>
			}
			control={
				/*
				 * Beside the switch's own answer rather than under the prose:
				 * watching a rule before enforcing it is a choice about how the
				 * switch is thrown. What it opens is drawn under the row.
				 */
				monitored && ( item.active || false !== item.available ) ? (
					<Button
						type="toolbar"
						size="sm"
						trailing="chevron-down"
						trailingTone="3"
						className="bs-ds-hrow__monitor"
						aria-expanded={ monitorOpen }
						aria-controls={ monitorOpen ? monitorPanelId : undefined }
						// Which row, in the name: a column of them read alike (#2057).
						aria-label={ sprintf(
							/* translators: 1: a control's words, e.g. "Try It in Test Mode"; 2: what it is about, e.g. "Disable XML-RPC". */
							_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
							__( 'Try It in Test Mode', 'bettershield' ),
							item.title
						) }
						onClick={ () => setMonitorOpen( ( open ) => ! open ) }
					>
						{ __( 'Try It in Test Mode', 'bettershield' ) }
					</Button>
				) : null
			}
		>
			{ item.conflict_warning ? <Alert layout="default" tone={ item.conflict_tone || 'warning' } desc={ item.conflict_warning } /> : null }

			{ /* Good news, said plainly under the description rather than in a
			     warning box beside a switch that looks blocked (#2523). */ }
			{ notNeeded && ! shared ? (
				<p className="bs-ds-hrow__note" id={ `${ titleId }-why` }>
					{ item.availability_note }
				</p>
			) : null }

			{ item.availability_note && ! shared && ! notNeeded ? (
				<Alert
					layout="default"
					tone={ item.availability_tone || 'warning' }
					desc={ <span id={ `${ titleId }-why` }>{ item.availability_note }</span> }
					actions={
						item.availability_url ? (
							<Button type="secondary" size="sm" trailing="arrow-right" href={ item.availability_url }>
								{ __( 'Open Network Admin', 'bettershield' ) }
							</Button>
						) : null
					}
				/>
			) : null }

			{ undoNotes.length && ! item.active ? <Alert layout="default" tone="info" live title={ __( 'Undone. Please read:', 'bettershield' ) } desc={ undoNotes.join( ' ' ) } /> : null }

			{ item.revert_failed ? (
				<Alert
					layout="default"
					tone="warning"
					desc={ sprintf(
						/* translators: %s: the reason the last undo did not complete. */
						__( 'The last undo did not complete: %s Try Undo again.', 'bettershield' ),
						item.revert_failed
					) }
				/>
			) : null }

			{ /*
			   Where an applied item left the site, beside the one action that
			   follows from it: store this somewhere off this site.
			*/ }
			{ /*
			   Copy only beside an address, the one value here anybody keeps
			   or shares: beside "Subscriber" or a sentence it read as one
			   more thing to store somewhere (#2225).
			*/ }
			{ item.active && item.summary ? (
				<div className="bs-ds-hrow__summary">
					<span className="bs-ds-hrow__summarytext">{ item.summary }</span>
					{ /^https?:\/\//i.test( String( item.summary ).trim() ) ? <CopyButton text={ item.summary } label={ __( 'Copy', 'bettershield' ) } /> : null }
				</div>
			) : null }

			<Verified item={ item } />

			{ /*
			   The switch is held until the item has what it needs; a control
			   that will not move and gives no reason reads as broken rather
			   than as waiting. Said with the field it is about.
			*/ }
			{ ( missingInput || brokenInput ) && ( item.active || false !== item.available ) ? (
				<p className="bs-ds-hrow__waiting">
					{ missingInput ? __( 'Fill in the field below first.', 'bettershield' ) : __( 'Correct the field below first.', 'bettershield' ) }
				</p>
			) : null }

			{ ! item.active && false !== item.available && fields.length ? <Fields fields={ fields } values={ fieldValues } onChange={ setField } /> : null }

			{ item.active && actions.length ? (
				<div className="bs-ds-hrow__actions">
					{ actions.map( ( action ) => (
						<Action key={ action.key } action={ action } working={ working } onRun={ ( key ) => itemAction( item.id, key ) } />
					) ) }
				</div>
			) : null }

			<Topics
				items={ topics }
				about={ item.title }
				// One open at a time in the row: an answer closes the
				// preview, and the preview closes the answer (#2523).
				shut={ !! showing }
				onOpen={ () => showing && setPreview( null ) }
				extra={
					// Nothing to preview where the site does not need it.
					notNeeded ? null : 
					// Held rather than disabled while the preview loads: a
					// disabled button drops the keyboard to the page body.
					<Button
						ref={ previewToggle }
						type="ghost"
						size="sm"
						trailing="chevron-down"
						trailingTone="3"
						className="bs-ds-hrow__preview-toggle"
						aria-expanded={ !! showing }
						aria-controls={ showing ? previewPanelId : undefined }
						isBusy={ previewing }
						disabled={ previewing }
						accessibleWhenDisabled
						onClick={ togglePreview }
						onKeyDown={ onEscape( !! showing, closePreview ) }
						// Which row, in the name (#2057).
						aria-label={ sprintf(
							/* translators: 1: a control's words, e.g. "Preview the Change"; 2: what it is about, e.g. "Disable XML-RPC". */
							_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
							showing ? __( 'Hide Preview', 'bettershield' ) : __( 'Preview the Change', 'bettershield' ),
							item.title
						) }
					>
						{ showing ? __( 'Hide Preview', 'bettershield' ) : __( 'Preview the Change', 'bettershield' ) }
					</Button>
				}
			/>

			{ showing ? (
				// Escape anywhere in the preview puts it away and the keyboard
				// back on its button, as it does on the button itself.
				// eslint-disable-next-line jsx-a11y/no-static-element-interactions
				<div className="bs-ds-hrow__panel bs-ds-hrow__preview" id={ previewPanelId } onKeyDown={ onEscape( !! showing, closePreview ) }>
					{ showing.refusal ? (
						<>
							<h4>{ __( 'This can’t be turned on yet:', 'bettershield' ) }</h4>
							<Alert layout="default" tone="warning" desc={ showing.refusal } />
							<p className="bs-ds-hrow__note">{ __( 'Nothing was changed. Correct it above and preview again.', 'bettershield' ) }</p>
						</>
					) : (
						<>
							{ /* Said for the state the item is in: one already applied
							     does this now, and one this site cannot have is not
							     something applying would do. */ }
							{ ( showing.already_active || item.in_force_elsewhere ) ? <h4>{ __( 'This is already on. It:', 'bettershield' ) }</h4> : null }
							{ ! ( showing.already_active || item.in_force_elsewhere ) && false === showing.available ? <h4>{ __( 'This cannot be applied on this site:', 'bettershield' ) }</h4> : null }
							{ /* A lead-in the items' own lines agree with: they say
							     "Blocks…", "Removes…", as "It:" above does (#2575). */ }
							{ ! ( showing.already_active || item.in_force_elsewhere ) && false !== showing.available ? <h4>{ __( 'Once applied, this:', 'bettershield' ) }</h4> : null }
							{ false === showing.available && showing.availability_note ? <p className="bs-ds-hrow__note">{ showing.availability_note }</p> : null }
							{ /* Its own lead-in, so what it would do does not read as
							     more of why it cannot be done. */ }
							{ ! ( showing.already_active || item.in_force_elsewhere ) && false === showing.available ? <h4>{ __( 'Where it can be applied, it:', 'bettershield' ) }</h4> : null }
							<ul className="bs-ds-hrow__effects">
								{ previewLines( showing.effect, effect ).map( ( line ) => (
									<li key={ line }>{ line }</li>
								) ) }
							</ul>
							{ /* The way back, where the eye lands after the list, and a
							     file only where one is written (#2575). Said only where
							     turning it on is the next step and undo reaches it all:
							     that previews change nothing is said once, above the
							     cards (#2822). */ }
							{ ! ( showing.already_active || item.in_force_elsewhere ) && false !== showing.available && false !== item.reversible ? (
								<Alert
									layout="default"
									tone="success"
									desc={
										item.writes_files
											? __( 'The current state and the file it changes are saved first, so Undo can restore them.', 'bettershield' )
											: __( 'The current state is saved first, so Undo can put it back.', 'bettershield' )
									}
								/>
							) : null }
						</>
					) }
				</div>
			) : null }

			{ monitored && monitorOpen ? (
				<div className="bs-ds-hrow__panel" id={ monitorPanelId }>
					<h4>{ __( 'Test mode', 'bettershield' ) }</h4>
					<HardeningMonitor item={ item } options={ chosenValues } invalid={ missingInput || brokenInput } />
				</div>
			) : null }
		</SettingRow>
	);
}
