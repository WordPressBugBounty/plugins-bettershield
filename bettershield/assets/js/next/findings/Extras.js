/**
 * What a finding says beyond its four facts, drawn in the row's detail beside
 * them: the vulnerable versions, the leftover tools and their quarantine, the
 * plain-language explanation, and the question asked of somebody who came
 * from an alert. And the note under the report on where advisories come from.
 */

import './Extras.css';

import { useEffect, useRef, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import { announce } from '../../ui/announce';
import useMutationFocus from '../../ui/useMutationFocus';
import { formatTime, isWorking, useStore } from '../../store';
import { entryText, evidenceLabel, evidenceText, isNamespaceEntry, isPathKey } from '../../screens/findings/evidence';
import Badge, { kindTone } from '../ui/Badge';
import Button from '../ui/Button';
import { focusIfLost } from '../ui/focus';
import Icon, { NOTE_ICON } from '../ui/Icon';
import { KeyValue, KeyValues } from '../ui/KeyValue';
import Table, { Cell, Row, TitleMeta } from '../ui/Table';
import { severityName } from '../data/severity';
import { unreachedText, unreachedWithoutResults } from '../data/vulnerabilities';

/** A finding's severity, with its word. */
function Severity( { severity } ) {
	return <Badge tone={ kindTone( severity ) }>{ severityName( severity ) }</Badge>;
}

/**
 * Was this alert worth sending?
 *
 * Offered only where an alert actually linked to, and only to someone who
 * arrived from one: asked of a reader browsing the report, it is a question
 * about nothing. The answer is the whole of the precision metric, and it is
 * recorded here rather than through a link in the email itself, which would
 * have to be a state-changing address that works without signing in.
 *
 * @param {Object} props
 * @param {string} props.recordedText What is said once the answer is recorded.
 */
export function AlertFeedback( { recordedText = '' } ) {
	const { markAlertUnhelpful, busy } = useStore();
	const [ recorded, setRecorded ] = useState( false );
	const recordedLine = useRef( null );
	const delivery = new URLSearchParams( window.location.search ).get( 'delivery' ) || '';

	// The button pressed is gone once the answer is recorded, and focus fell
	// to the page with it: the line that takes its place takes the focus.
	useEffect( () => {
		if ( recorded ) {
			focusIfLost( recordedLine.current );
		}
	}, [ recorded ] );

	if ( ! /^[0-9a-f]{32}$/.test( delivery ) ) {
		return null;
	}

	if ( recorded ) {
		return (
			<p className="bs-ds-ffeedback" role="status" ref={ recordedLine } tabIndex={ -1 }>
				{ recordedText || __( 'Thanks, noted. The finding stays open. You can change which alerts you get in Settings › Email Alerts.', 'bettershield' ) }
			</p>
		);
	}

	return (
		<div className="bs-ds-ffeedback">
			<span>{ __( 'Did this email alert tell you something you didn’t need?', 'bettershield' ) }</span>
			<Button
				type="ghost"
				size="sm"
				isBusy={ isWorking( busy, 'alert-feedback' ) }
				disabled={ isWorking( busy, 'alert-feedback' ) }
				onClick={ () =>
					markAlertUnhelpful( delivery ).then( ( result ) => {
						if ( result ) {
							setRecorded( true );
						}
					} )
				}
			>
				{ __( 'Tell Us It Wasn’t Useful', 'bettershield' ) }
			</Button>
		</div>
	);
}

/**
 * An explanation, and the facts it was built from, together.
 *
 * They are never shown apart. The whole claim this feature makes is that a
 * reader can check what they were told against what the scanner actually
 * recorded: an explanation presented on its own would be asking for trust
 * instead, which is what "no receipts, no claim" rules out.
 *
 * @param {Object} props
 * @param {Object} props.finding The finding.
 */
export function Explanation( { finding } ) {
	const { resources, explainFinding, busy } = useStore();
	const [ result, setResult ] = useState( null );
	/*
	 * The answer replaces the button that asked for it, so the browser drops
	 * focus to the document: a screen-reader user is told nothing arrived and
	 * a keyboard user starts again from the top of the page. Focus goes into
	 * the answer instead, which is also where the reading starts.
	 */
	const answerRef = useRef( null );
	const afterExplain = useMutationFocus( answerRef );
	const status = resources.aiStatus.data;

	// Absent, not broken: no WordPress 7.0, no provider, AI switched off. The
	// finding reads exactly as it did before.
	if ( ! status || ! status.available ) {
		return null;
	}

	const working = isWorking( busy, `explain-${ finding.id }` );

	if ( result ) {
		const evidence = Object.entries( result.evidence || {} );

		return (
			<div className="bs-ds-fdetail__card bs-ds-fx-wide bs-ds-fexplain" role="status" ref={ answerRef } tabIndex={ -1 }>
				<div className="bs-ds-fdetail__body">
					{ result.explanation.split( /\n{2,}/ ).map( ( paragraph, index ) => (
						<p key={ index } className="bs-ds-fexplain__para">
							{ paragraph }
						</p>
					) ) }

					{ /*
					  * Which ask this is. An answer is kept until the finding's
					  * evidence moves, so most readings show one written earlier,
					  * and a paragraph presented as though the model had just
					  * looked at the site, when it had not, is the small
					  * dishonesty the receipts beside it exist to rule out.
					  */ }
					<p className="bs-ds-fexplain__source">
						{ result.cached
							? sprintf(
									/* translators: %s: date and time the explanation was written. */
									__( 'AI explanation from %s, based only on the details below.', 'bettershield' ),
									formatTime( result.generated_at )
							  )
							: __( 'Written by your connected AI provider, using only the evidence below.', 'bettershield' ) }
					</p>

					{ evidence.length ? (
						<KeyValues className="bs-ds-fexplain__evidence">
							{ evidence.map( ( [ key, value ] ) => (
								<KeyValue
									key={ key }
									label={ isPathKey( key ) ? key : evidenceLabel( key, finding.id ) }
									// A namespace with its routes: the answer was built from
									// them, and the card says it was built from what it shows.
									value={ Array.isArray( value ) && value.length ? value.map( ( entry ) => ( isNamespaceEntry( entry ) ? evidenceText( entry ) : entryText( entry ) ) ).join( ', ' ) : evidenceText( value, key, finding.id ) }
								/>
							) ) }
						</KeyValues>
					) : (
						<p className="bs-ds-fexplain__source">{ __( 'It only had the finding’s title and description to go on.', 'bettershield' ) }</p>
					) }
				</div>
			</div>
		);
	}

	return (
		<div className="bs-ds-fexplain__ask">
			<Button
				type="ghost"
				size="sm"
				icon="message-square"
				iconTone="1"
				isBusy={ working }
				disabled={ working }
				onClick={ () => explainFinding( finding.id, afterExplain( setResult ) ) }
			>
				{ working ? __( 'Asking…', 'bettershield' ) : __( 'Explain This in Plain Language', 'bettershield' ) }
			</Button>
			<span>{ __( 'Uses the AI provider you connected to WordPress.', 'bettershield' ) }</span>
		</div>
	);
}

/**
 * The vulnerability finding's evidence is a list of things installed, each
 * with the version held, the version that fixes it, and its identifiers: a
 * table, not a JSON blob.
 *
 * @param {Object} props
 * @param {Array}  props.items What is installed.
 * @param {string} props.label The table's name: the finding's title.
 */
export function AffectedTable( { items, label } ) {
	return (
		<div className="bs-ds-fdetail__card bs-ds-fx-wide bs-ds-fx-table">
			<Table
				label={ label }
				columns={ [
					{ key: 'installed', label: __( 'Installed', 'bettershield' ) },
					{ key: 'version', label: __( 'Version', 'bettershield' ), width: 'minmax(0, 96px)' },
					{ key: 'fixed', label: __( 'Fixed in version', 'bettershield' ), width: 'minmax(0, 96px)' },
					{ key: 'severity', label: __( 'Severity', 'bettershield' ), width: '88px' },
					{ key: 'ids', label: __( 'Reference ID (CVE)', 'bettershield' ), width: 'minmax(0, 1fr)' },
				] }
			>
				{ items.map( ( item ) => (
					<Row key={ `${ item.type }:${ item.slug }` }>
						<Cell>
							<TitleMeta title={ item.name } meta={ item.active ? null : __( '(inactive)', 'bettershield' ) } />
						</Cell>
						<Cell>{ item.installed_version }</Cell>
						<Cell>{ item.fixed_in ? item.fixed_in : __( 'no fix yet', 'bettershield' ) }</Cell>
						<Cell>
							{ 'unknown' === item.match_status ? <Badge>{ __( 'Couldn’t compare your version', 'bettershield' ) }</Badge> : false === item.severity_known ? <Badge>{ __( 'Unknown', 'bettershield' ) }</Badge> : <Severity severity={ item.severity } /> }
						</Cell>
						<Cell>
							<span className="bs-ds-fx-ids">{ ( item.cve_ids || [] ).join( ', ' ) || '—' }</span>
						</Cell>
					</Row>
				) ) }
			</Table>
		</div>
	);
}

/**
 * The leftover tools the probe reached, each with what it is and a way to
 * move it out of reach. Full width under the facts: a path, a sentence and a
 * button do not fit a quarter of the row.
 *
 * @param {Object}  props
 * @param {Array}   props.tools What answered.
 * @param {boolean} props.open  Whether the finding is open, and a tool can still be moved.
 * @param {string}  props.label The table's name: the finding's title.
 */
export function LeftoverTools( { tools, open, label } ) {
	const { quarantineTool, busy } = useStore();

	return (
		<div className="bs-ds-fdetail__card bs-ds-fx-wide bs-ds-fx-table bs-ds-ftools">
			<Table
				label={ label }
				head={ false }
				columns={ [
					{ key: 'tool', label: __( 'Path', 'bettershield' ) },
					{ key: 'severity', label: __( 'Severity', 'bettershield' ), width: '88px' },
					{ key: 'action', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
				] }
			>
				{ tools.map( ( tool ) => (
					<Row key={ tool.path }>
						<Cell>
							<TitleMeta
								title={ `/${ tool.path }` }
								meta={
									<>
										{ tool.means }
										{ /* The move keeps a copy, and a copy this large is
										     always refused: say so rather than offer it. */ }
										{ open && tool.too_large ? (
											<span className="bs-ds-ftools__large" id={ `bs-tool-large-${ tool.path }` }>
												{ __( 'This file is too big to quarantine. Move it out of your site’s public folder with your host’s file manager.', 'bettershield' ) }
											</span>
										) : null }
									</>
								}
							/>
						</Cell>
						<Cell>
							<Severity severity={ tool.severity } />
						</Cell>
						<Cell align="end">
							{ open ? (
								<Button
									type="secondary"
									size="sm"
									isBusy={ isWorking( busy, `tool-${ tool.path }` ) }
									disabled={ Boolean( busy ) || Boolean( tool.too_large ) }
									aria-describedby={ tool.too_large ? `bs-tool-large-${ tool.path }` : undefined }
									aria-label={ sprintf(
										/* translators: %s: a file path. */
										__( 'Quarantine %s', 'bettershield' ),
										`/${ tool.path }`
									) }
									onClick={ () => quarantineTool( tool.path ) }
								>
									{ __( 'Quarantine', 'bettershield' ) }
								</Button>
							) : null }
						</Cell>
					</Row>
				) ) }
			</Table>
		</div>
	);
}

/**
 * The downloadable files the probe found, where the rule that hides them
 * cannot apply on this server: each backup, dump or log with a way to move
 * it out of reach, and `.git` or `.env` with why not.
 *
 * @param {Object}  props
 * @param {Array}   props.files What answered.
 * @param {boolean} props.open  Whether the finding is open, and a file can still be moved.
 * @param {string}  props.label The table's name: the finding's title.
 */
export function ExposedFiles( { files, open, label } ) {
	const { quarantineArtifact, busy } = useStore();
	const [ said, setSaid ] = useState( '' );
	// The row pressed is gone once its file is: the answer takes focus.
	const status = useRef( null );

	useEffect( () => {
		if ( said && ! busy ) {
			focusIfLost( status.current );
		}
	}, [ said, busy ] );

	const quarantine = ( path ) =>
		quarantineArtifact( path, ( answer ) => {
			if ( answer ) {
				const words = __( 'Moved to quarantine. To restore it, use the Quarantine list in File Changes.', 'bettershield' );

				setSaid( words );
				announce( words );
			}
		} );

	return (
		<div className="bs-ds-fdetail__card bs-ds-fx-wide bs-ds-fx-table bs-ds-ftools">
			<Table
				label={ label }
				head={ false }
				columns={ [
					{ key: 'file', label: __( 'Path', 'bettershield' ) },
					{ key: 'action', label: __( 'Actions', 'bettershield' ), width: 'auto', align: 'end' },
				] }
			>
				{ files.map( ( file ) => {
					const note = `bs-artifact-note-${ file.path }`;
					let why = null;

					if ( open && ! file.quarantine ) {
						why = __( 'Moving it could break a tool that uses it. Move it out of your site’s public folder with your host’s file manager.', 'bettershield' );
					} else if ( open && file.too_large ) {
						why = __( 'This file is too big to quarantine. Move it out of your site’s public folder with your host’s file manager.', 'bettershield' );
					}

					return (
						<Row key={ file.path }>
							<Cell>
								<TitleMeta
									title={ `/${ file.path }` }
									meta={
										<>
											{ file.means }
											{ why ? (
												<span className="bs-ds-ftools__large" id={ note }>
													{ why }
												</span>
											) : null }
										</>
									}
								/>
							</Cell>
							<Cell align="end">
								{ open && file.quarantine ? (
									<Button
										type="secondary"
										size="sm"
										isBusy={ isWorking( busy, `artifact-${ file.path }` ) }
										disabled={ Boolean( busy ) || Boolean( file.too_large ) }
										aria-describedby={ file.too_large ? note : undefined }
										aria-label={ sprintf(
											/* translators: %s: a file path. */
											__( 'Quarantine %s', 'bettershield' ),
											`/${ file.path }`
										) }
										onClick={ () => quarantine( file.path ) }
									>
										{ __( 'Quarantine', 'bettershield' ) }
									</Button>
								) : null }
							</Cell>
						</Row>
					);
				} ) }
			</Table>
			{ said ? (
				<p className="bs-ds-ffeedback" role="status" ref={ status } tabIndex={ -1 }>
					{ said }
				</p>
			) : null }
		</div>
	);
}

/**
 * One honest line about published advisories: whether anything checks them
 * at all, and how old the answer is. "Nothing was checked" and "nothing is
 * vulnerable" are different sentences, and this is where the difference is
 * said.
 *
 * Read as a footnote under the rows it is about. Above the whole report it
 * was the screen's first sentence, which put a paragraph about a source that
 * is not connected in front of a reader who had come to see what is wrong
 * with their site.
 *
 * @param {Object} props
 * @param {Object} props.feed The vulnerability feed's status.
 */
export function VulnerabilityNote( { feed } ) {
	if ( ! feed ) {
		return null;
	}

	let text;
	if ( ! feed.feed_bound ) {
		text = __( 'This version of BetterShield doesn’t check plugins against a list of known security issues. It only tells you about available updates.', 'bettershield' );
	} else if ( ! feed.enabled ) {
		text = __( 'Vulnerability checks are off, so nothing was checked for known vulnerabilities. Turn them on in Settings.', 'bettershield' );
	} else if ( unreachedWithoutResults( feed ) ) {
		text = unreachedText( feed );
	} else if ( ! feed.has_data ) {
		text = __( 'Vulnerability checks are on but have not run yet.', 'bettershield' );
	} else {
		text = sprintf(
			/* translators: 1: feed name, 2: date, 3: an age, already carrying its own unit. */
			__( 'Checked against %1$s. List last updated %2$s (%3$s).', 'bettershield' ),
			feed.feed_label,
			formatTime( feed.published_at || feed.fetched_at ),
			// Its own count, or the sentence picks the plural chosen for
			// something else, and "1 days old" is what a feed fetched
			// yesterday renders.
			sprintf(
				/* translators: %d: a number of days. */
				_n( '%d day old', '%d days old', feed.age_days || 0, 'bettershield' ),
				feed.age_days || 0
			)
		);
		if ( feed.stale ) {
			text += ' ' + __( 'That is old enough that newer security issues may be listed.', 'bettershield' );
		}
	}

	if ( feed.error && ! unreachedWithoutResults( feed ) ) { text += ' ' + ( feed.has_data ? __( 'The last update failed, so you’re seeing the previous results.', 'bettershield' ) : __( 'The update failed, and there are no results yet.', 'bettershield' ) ); }
	if ( feed.unknown ) { text += ' ' + __( 'We couldn’t check some versions. Check those plugins’ pages for security notes.', 'bettershield' ); }

	return (
		<>
			<Icon name={ NOTE_ICON } size={ 16 } tone="3" />
			<div className="bs-ds-ffeed"><p>{ text }</p>
				{ ( feed.attribution || [] ).map( ( attribution, index ) => <details key={ index }><summary>{ __( 'Source', 'bettershield' ) }</summary>
					{ attribution.message ? <p>{ attribution.message }</p> : null }
					{ ( attribution.notices || [] ).map( ( notice, n ) => <p key={ n }>{ notice.source }: { notice.notice } { notice.license } { notice.license_url ? <a href={ notice.license_url } target="_blank" rel="noopener noreferrer">{ __( 'License', 'bettershield' ) }</a> : null }</p> ) }
				</details> ) }
			</div>
		</>
	);
}
