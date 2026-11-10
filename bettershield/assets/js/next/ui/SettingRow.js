/**
 * A card of settings, and the rows in it: the design's Card (26:38220) with
 * List item rows under its header, each a title, one line about it, and the
 * control at the row's end.
 *
 * A row reads in a line or two. What the classic setting cards printed in
 * full (how it works, what it pauses, what still goes out) is passed as
 * `topics` and opens under the row on request; what the control produces (a
 * list, a plan, a field) goes in the row's body, under its text.
 *
 * Free of the dashboard's store, so an add-on drawing its own screens in the
 * frame can use the rows without bundling the store. The dashboard's screens
 * import them, and `Saved`, from ./Setting.
 */

import './Setting.css';
// The switch is drawn to the design's size by the same rules as ToggleRow's.
import './ToggleRow.css';

import { FormToggle } from '@wordpress/components';
import { useId } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { Card, CardHead } from './Card';
import InfoTip from './InfoTip';
import Topics from './Topics';

/**
 * A card of settings: its header (an icon tile, the title, one trailing badge
 * or button), an optional line under it, then its rows.
 *
 * @param {Object} props
 * @param {string} props.icon      The header tile's icon.
 * @param {string} props.title     The card's name.
 * @param {string} props.id        The heading's id, when something else points at it.
 * @param {*}      props.trailing  The header's one badge or button.
 * @param {*}      props.intro     One line under the header.
 * @param {string} props.className Extra classes.
 * @param {*}      props.children  The rows.
 */
export function SettingsCard( { icon, title, id, trailing = null, intro = null, className = '', children } ) {
	const made = useId().replace( /[^\w-]/g, '' );
	const headingId = id || `bs-ds-card-${ made }`;

	return (
		<Card className={ `bs-ds-settings${ className ? ` ${ className }` : '' }` } aria-labelledby={ headingId }>
			<CardHead icon={ icon } title={ title } id={ headingId }>
				{ trailing }
			</CardHead>
			{ intro ? <p className="bs-ds-settings__intro">{ intro }</p> : null }
			{ children }
		</Card>
	);
}

/**
 * The design's Toggle (6:10487) on its own: a switch named by something else
 * on the row, the library's FormToggle underneath so it stays a checkbox.
 *
 * @param {Object}   props
 * @param {boolean}  props.checked     Whether it is on.
 * @param {Function} props.onChange    Called with the change event, as the library does.
 * @param {boolean}  props.disabled    Whether it can be changed.
 * @param {string}   props.labelledBy  The id of what names it.
 * @param {string}   props.describedBy The id of what describes it.
 * @param {string}   props.label       Its name, where nothing on screen gives one.
 */
export function Toggle( { checked, onChange, disabled = false, labelledBy, describedBy, label } ) {
	return (
		<FormToggle
			className="bs-ds-toggle"
			checked={ Boolean( checked ) }
			disabled={ disabled }
			onChange={ onChange }
			aria-labelledby={ labelledBy }
			aria-describedby={ describedBy }
			aria-label={ labelledBy ? undefined : label }
		/>
	);
}

/**
 * One setting.
 *
 * @param {Object}   props
 * @param {*}        props.title    Its name.
 * @param {string}   props.name     Its name as plain text, where the title is an element: it names the ⓘ.
 * @param {*}        props.about    One line about it.
 * @param {*}        props.meta     A quieter line under that: since when, until when.
 * @param {*}        props.badge    Its state, beside the title.
 * @param {*}        props.tip      The why or the how, behind an ⓘ beside the title: forty words at most.
 * @param {*}        props.lead     A control before the text, as a switch leads a protection.
 * @param {*}        props.control  The control at the row's end; before the switch when there is one.
 * @param {Object}   props.toggle   A switch for the control: { checked, onChange( on ), disabled }, named by the title.
 * @param {Array}    props.topics   "How it works" questions, opened under the row.
 * @param {*}        props.children What the setting holds under its text: fields, a list.
 * @param {*}        props.output   What the control produced, at the row's full width.
 * @param {number}   props.level    The title's heading level; 3 under a card's own heading.
 * @param {string}   props.id       The title's id, when something else points at it.
 * @param {string}   props.focusKey The name a link's `?focus=` gives this setting.
 * @param {string}   props.className Extra classes.
 */
export default function SettingRow( {
	title,
	name = null,
	about = null,
	meta = null,
	badge = null,
	tip = null,
	lead = null,
	control = null,
	toggle = null,
	topics = null,
	children = null,
	output = null,
	level = 3,
	id,
	focusKey = undefined,
	className = '',
} ) {
	const made = useId().replace( /[^\w-]/g, '' );
	const titleId = id || `bs-ds-setting-${ made }`;
	const aboutId = `${ titleId }-about`;
	const Heading = `h${ Math.min( Math.max( level, 2 ), 6 ) }`;
	const switched = toggle ? (
		<Toggle
			checked={ toggle.checked }
			// Called with on or off, as the library's ToggleControl was.
			onChange={ ( event ) => toggle.onChange( Boolean( event && event.target ? event.target.checked : event ) ) }
			disabled={ toggle.disabled }
			labelledBy={ titleId }
			describedBy={ about ? aboutId : undefined }
		/>
	) : null;
	// What the control said ("Saved.") sits before the switch, the switch at the far end.
	const end = control || switched ? (
		<>
			{ control }
			{ switched }
		</>
	) : null;
	const indented = lead ? ' bs-ds-setting__under--lead' : '';

	return (
		<div className={ `bs-ds-setting${ className ? ` ${ className }` : '' }` } data-bs-focus={ focusKey }>
			<div className="bs-ds-setting__main">
				{ lead ? <div className="bs-ds-setting__lead">{ lead }</div> : null }
				<div className="bs-ds-setting__text">
					<div className="bs-ds-setting__titlerow">
						<Heading className="bs-ds-setting__title" id={ titleId }>
							{ title }
						</Heading>
						{ tip ? (
							<InfoTip
								label={
									'string' === typeof title || name
										? sprintf(
												/* translators: %s: a setting's name. */
												__( 'About %s', 'bettershield' ),
												'string' === typeof title ? title : name
										  )
										: undefined
								}
							>
								{ tip }
							</InfoTip>
						) : null }
						{ badge }
					</div>
					{ about ? (
						<div className="bs-ds-setting__about" id={ aboutId }>
							{ about }
						</div>
					) : null }
					{ meta ? <div className="bs-ds-setting__meta">{ meta }</div> : null }
				</div>
				{ end ? <div className="bs-ds-setting__control">{ end }</div> : null }
			</div>
			{ children ? <div className={ `bs-ds-setting__under${ indented }` }>{ children }</div> : null }
			{ topics && topics.length ? <Topics items={ topics } about={ 'string' === typeof title ? title : '' } className={ `bs-ds-setting__under${ indented }` } /> : null }
			{ output ? <div className="bs-ds-setting__output">{ output }</div> : null }
		</div>
	);
}
