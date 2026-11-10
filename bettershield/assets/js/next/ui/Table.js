/**
 * The design's table kit (23:20078) for lists of things: a header strip on
 * the tertiary surface, rows 12 by 20 under a rule, group rows that name a
 * run of rows, and a footer row. The columns are a grid the table sets once,
 * so every row lines up with the header without measuring anything.
 *
 * Marked up as an ARIA table, as the Findings report's is, so a screen reader
 * reads rows and columns; on a narrow screen the cells stack and the header
 * is kept for assistive technology only.
 */

import './Table.css';

/**
 * The grid every row of a table shares.
 *
 * @param {Array} columns [{ width }]: a CSS track per column; none fills.
 * @return {string} The grid-template-columns value.
 */
export function tracks( columns ) {
	return columns.map( ( column ) => column.width || 'minmax(0, 1fr)' ).join( ' ' );
}

/**
 * @param {Object} props
 * @param {string} props.label     The table's accessible name.
 * @param {Array}  props.columns   [{ key, label, width, align }]: align end puts a column's cells at the far edge.
 * @param {boolean} props.head     Whether the header strip is drawn (it is always there for assistive technology).
 * @param {string} props.className Extra classes.
 * @param {*}      props.children  The rows.
 */
export default function Table( { label, columns, head = true, className = '', children } ) {
	return (
		<div
			className={ `bs-ds-tbl${ className ? ` ${ className }` : '' }` }
			role="table"
			aria-label={ label }
			style={ { '--bs-ds-tbl-cols': tracks( columns ) } }
		>
			<div className={ `bs-ds-tbl__head${ head ? '' : ' bs-ds-tbl__head--quiet' }` } role="row">
				{ columns.map( ( column ) => (
					<span key={ column.key } role="columnheader" className={ `bs-ds-tbl__th${ 'end' === column.align ? ' bs-ds-tbl__cell--end' : '' }` }>
						{ column.label }
					</span>
				) ) }
			</div>
			{ children }
		</div>
	);
}

/**
 * @param {Object}  props
 * @param {boolean} props.open      The row's detail is open under it.
 * @param {boolean} props.selected  The row is picked.
 * @param {boolean} props.hover     The row lightens under the pointer, for a row that does something.
 * @param {string}  props.className Extra classes.
 * @param {*}       props.children  Its cells.
 */
export function Row( { open = false, selected = false, hover = false, className = '', children, ...rest } ) {
	const classes = [ 'bs-ds-tbl__row', hover ? 'bs-ds-tbl__row--hover' : '', open ? 'is-open' : '', selected ? 'is-selected' : '', className ].filter( Boolean ).join( ' ' );

	return (
		<div className={ classes } role="row" { ...rest }>
			{ children }
		</div>
	);
}

/**
 * @param {Object} props
 * @param {string} props.align     end: at the row's far edge.
 * @param {string} props.className Extra classes.
 * @param {*}      props.children  What the cell holds.
 */
export function Cell( { align = '', className = '', children } ) {
	return (
		<div className={ `bs-ds-tbl__cell${ 'end' === align ? ' bs-ds-tbl__cell--end' : '' }${ className ? ` ${ className }` : '' }` } role="cell">
			{ children }
		</div>
	);
}

/**
 * A cell's usual content: a 14 title over a 12 line about it.
 *
 * @param {Object} props
 * @param {*}      props.title The name.
 * @param {*}      props.meta  The line under it.
 * @param {string} props.icon  A 16 icon before both.
 */
export function TitleMeta( { title, meta = null, icon = null } ) {
	return (
		<span className="bs-ds-tbl__tm">
			{ icon }
			<span className="bs-ds-tbl__tm-text">
				<span className="bs-ds-tbl__title">{ title }</span>
				{ meta ? <span className="bs-ds-tbl__meta">{ meta }</span> : null }
			</span>
		</span>
	);
}

/**
 * A row across the whole table: a group's name, a note, the empty line.
 *
 * @param {Object} props
 * @param {string} props.kind      group (the tertiary strip), note, empty or foot.
 * @param {*}      props.children  What it says.
 * @param {*}      props.aside     Held at the row's far end.
 */
export function WholeRow( { kind = 'note', children, aside = null } ) {
	return (
		<div className={ `bs-ds-tbl__whole bs-ds-tbl__whole--${ kind }` } role="row">
			<div className="bs-ds-tbl__wholecell" role="cell">
				<span className="bs-ds-tbl__wholetext">{ children }</span>
				{ aside ? <span className="bs-ds-tbl__aside">{ aside }</span> : null }
			</div>
		</div>
	);
}
