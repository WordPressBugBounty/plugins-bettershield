/**
 * Login & access › Allowed and refused: a list of entries that override
 * everything else on the tab for particular people, as a row of its card with
 * the entries in a table and the form that adds one under it.
 *
 * Entries are part of the tab's draft: added and removed here, and kept by
 * the tab's Save.
 */

import './AccessLists.css';

import { useId, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { formatTime } from '../../store';
import { onEnter } from '../../ui/keys';
import { rangeProblem } from '../../ui/validate';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Field, { FieldRow } from '../ui/Field';
import SettingRow from '../ui/Setting';
import Table, { Cell, Row, TitleMeta } from '../ui/Table';

/*
 * What an entry is called on the screen. A blocklist entry may name an
 * address, a browser string or an account, and an entry whose only field is
 * the account rendered as an empty row with an unlabeled Remove button beside
 * it: two of those and an administrator cannot tell which name they are
 * about to unblock.
 */
function entryLabel( entry ) {
	return entry.range || entry.username || entry.ua || '';
}

/** One entry's identity, for the row key and for refusing a duplicate. */
function entryKey( entry ) {
	return `${ entry.range || '' }|${ entry.ua || '' }|${ entry.username || '' }`;
}

/**
 * @param {Object}   props
 * @param {string}   props.title        The list's name.
 * @param {string}   props.intro        What being on it means, in a line.
 * @param {Object}   props.explain      How it works: { lead, text, points, note }.
 * @param {string}   props.note         A line under the form, about what it takes.
 * @param {Array}    props.entries      The entries, as the draft holds them.
 * @param {Function} props.onChange     Called with the new list.
 * @param {boolean}  props.withUa       Takes a user-agent fragment.
 * @param {boolean}  props.withUsername Takes a username.
 * @param {string}   props.className    Where the list sits, for the screen that places it.
 * @param {string}   props.focusKey     The name a link's `?focus=` gives the list.
 */
export default function ListEditor( { title, intro, explain, note, entries, onChange, withUa, withUsername, className = '', focusKey = undefined } ) {
	const [ range, setRange ] = useState( '' );
	const [ ua, setUa ] = useState( '' );
	const [ username, setUsername ] = useState( '' );
	const [ entryNote, setEntryNote ] = useState( '' );

	/*
	 * Named while it is being typed rather than when the save fails. A range
	 * with a prefix length of 33 was accepted into the list, saved, and then
	 * matched nothing forever, which on a list that decides who may sign in
	 * looks exactly like an entry that works.
	 *
	 * And a duplicate is said, not cleared as though it had been added: the
	 * same combination twice is one entry, and the second would render under
	 * the first's key and remove the wrong row later.
	 */
	const typed = {
		range: range.trim(),
		ua: withUa ? ua.trim() : '',
		username: withUsername ? username.trim() : '',
	};
	const listed = Boolean( typed.range || typed.ua || typed.username ) && entries.some( ( existing ) => entryKey( existing ) === entryKey( typed ) );
	const badRange = rangeProblem( range, { widest: true } );
	const problem = badRange || ( listed ? __( 'Already on the list.', 'bettershield' ) : null );

	/*
	 * The refusal is said once, under all the fields, and tied to the ones it
	 * is about: the range for a range it cannot take, every field filled in
	 * for a duplicate, which is the combination. Add stays in the Tab order
	 * and points at it, and it is announced when an entry is asked for with
	 * it standing — Enter in a field — rather than as it is typed: every
	 * address starts as something that is not one yet (#2029).
	 */
	const problemId = `bs-ds-listedit-${ useId().replace( /[^\w-]/g, '' ) }-problem`;
	// Which refusal was asked about, and how many times, so each Enter says
	// it again on a node of its own.
	const [ asked, setAsked ] = useState( { problem: '', times: 0 } );
	const said = Boolean( problem ) && problem === asked.problem;
	const marks = ( filled ) =>
		problem && ( badRange ? filled === range : '' !== filled.trim() ) ? { 'aria-invalid': 'true', 'aria-describedby': problemId } : {};

	const clear = () => {
		setRange( '' );
		setUa( '' );
		setUsername( '' );
		setEntryNote( '' );
	};

	const add = () => {
		if ( problem ) {
			setAsked( ( was ) => ( { problem, times: was.times + 1 } ) );
			return;
		}

		const entry = {
			range: range.trim(),
			ua: withUa ? ua.trim() : '',
			username: withUsername ? username.trim() : '',
			note: entryNote.trim(),
		};

		if ( ! entry.range && ! entry.ua && ! entry.username ) {
			return;
		}

		onChange( [ ...entries, entry ] );
		clear();
	};

	return (
		<SettingRow
			className={ `bs-ds-listedit${ className ? ` ${ className }` : '' }` }
			focusKey={ focusKey }
			title={ title }
			about={ intro }
			badge={
				<Badge>
					{ entries.length
						? sprintf(
								/* translators: %d: how many entries the list holds. */
								_n( '%d entry', '%d entries', entries.length, 'bettershield' ),
								entries.length
						  )
						: __( 'Empty', 'bettershield' ) }
				</Badge>
			}
			topics={ explain ? [ { key: 'how', label: __( 'How this works', 'bettershield' ), ...explain } ] : null }
		>
			{ entries.length ? (
				<Table
					className="bs-ds-listedit__table"
					label={ title }
					columns={ [
						{ key: 'entry', label: __( 'Entry', 'bettershield' ) },
						{ key: 'added', label: __( 'Added', 'bettershield' ) },
						{ key: 'actions', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
					] }
				>
					{ entries.map( ( entry, index ) => (
						<Row key={ entryKey( entry ) } className="bs-ds-listedit__row">
							<Cell>
								<TitleMeta
									title={
										<span className="bs-ds-listedit__what">
											<span>{ entryLabel( entry ) }</span>
											{ entry.range && entry.username ? <span>{ entry.username }</span> : null }
											{ ( entry.range || entry.username ) && entry.ua ? <span>{ entry.ua }</span> : null }
										</span>
									}
									meta={ entry.note || null }
								/>
							</Cell>
							<Cell>
								<span className="bs-ds-listedit__added">
									{ entry.author
										? sprintf(
												/* translators: 1: username, 2: date. */
												__( 'added by %1$s, %2$s', 'bettershield' ),
												entry.author,
												entry.added_at ? formatTime( entry.added_at ) : ''
										  )
										: __( 'new — saves with the form', 'bettershield' ) }
								</span>
							</Cell>
							<Cell align="end">
								<Button
									type="ghost"
									size="sm"
									aria-label={ sprintf(
										/* translators: %s: the list entry being removed. */
										__( 'Remove %s', 'bettershield' ),
										entryLabel( entry )
									) }
									onClick={ () => onChange( entries.filter( ( keep, i ) => i !== index ) ) }
								>
									{ __( 'Remove', 'bettershield' ) }
								</Button>
							</Cell>
						</Row>
					) ) }
				</Table>
			) : null }

			{ /*
			   The fields for a new entry side by side, on one baseline, with the
			   button at the end; what they share is said once, under all of them.
			*/ }
			<div className="bs-ds-listedit__form">
				<FieldRow>
					<Field
						label={ __( 'IP address, or a range like 203.0.113.0/24', 'bettershield' ) }
						placeholder="203.0.113.0/24"
						value={ range }
						onChange={ setRange }
						onKeyDown={ onEnter( add ) }
						{ ...marks( range ) }
					/>
					{ withUsername ? (
						<Field
							label={ __( 'Or a username', 'bettershield' ) }
							placeholder="olduser"
							value={ username }
							onChange={ setUsername }
							onKeyDown={ onEnter( add ) }
							{ ...( badRange ? {} : marks( username ) ) }
						/>
					) : null }
					{ withUa ? (
						<Field
							label={ __( 'Or part of a browser or bot name', 'bettershield' ) }
							placeholder="BadScanner"
							value={ ua }
							onChange={ setUa }
							onKeyDown={ onEnter( add ) }
							{ ...( badRange ? {} : marks( ua ) ) }
						/>
					) : null }
					<Field
						label={ __( 'Note', 'bettershield' ) }
						placeholder={ __( 'Why you added it', 'bettershield' ) }
						value={ entryNote }
						onChange={ setEntryNote }
						onKeyDown={ onEnter( add ) }
					/>
					<Button type="secondary" size="sm" disabled={ !! problem } accessibleWhenDisabled aria-describedby={ problem ? problemId : undefined } onClick={ add }>
						{ __( 'Add', 'bettershield' ) }
					</Button>
				</FieldRow>

				{ problem ? (
					<p key={ said ? `said-${ asked.times }` : 'shown' } className="bs-ds-listedit__problem" id={ problemId } role={ said ? 'alert' : undefined }>
						{ problem }
					</p>
				) : null }
				{ note ? <p className="bs-ds-listedit__hint">{ note }</p> : null }
			</div>
		</SettingRow>
	);
}
