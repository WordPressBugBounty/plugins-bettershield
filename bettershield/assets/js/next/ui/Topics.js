/**
 * "How it works": the questions a setting raises, each a Ghost sm button with
 * a chevron that opens its answer in place, under the row (the design's
 * disclosure: a trailing chevron means it opens where it is).
 *
 * The answers are the screens' existing explanations, moved here so the row
 * itself reads in one line. One is open at a time; opening another swaps it,
 * Escape closes it and puts focus back on its question. Items take the shape
 * the classic disclosure took ({ key, label, lead, text, tags, points, steps,
 * body, note }), so a screen moves its explanations over as they are.
 *
 * The answer's height is animated both ways: the panel is measured, keeps its
 * content through the closing transition, and is inert while it closes.
 */

import './Topics.css';

import { useEffect, useId, useLayoutEffect, useRef, useState } from '@wordpress/element';
import { _x, sprintf } from '@wordpress/i18n';
import useInert from '../../ui/inert';
import Alert from './Alert';
import Badge from './Badge';
import Button from './Button';

function reducedMotion() {
	return !! window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;
}

/** A close that never reports its end still lets go of the answer. */
const SETTLE_MS = 500;

/**
 * One answer, in the order a reader takes it in: the sentence to take away,
 * the explanation, then any list, then the caveat.
 *
 * @param {Object} props
 * @param {Object} props.item The topic.
 */
export function Answer( { item } ) {
	const note = 'string' === typeof item.note ? { text: item.note } : item.note;

	return (
		<>
			{ item.lead ? <p className="bs-ds-topics__lead">{ item.lead }</p> : null }

			{ item.text ? <p>{ item.text }</p> : null }

			{ item.tags && item.tags.length ? (
				<ul className="bs-ds-topics__tags">
					{ item.tags.map( ( tag ) => (
						<li key={ tag }>
							<Badge>{ tag }</Badge>
						</li>
					) ) }
				</ul>
			) : null }

			{ item.points && item.points.length ? (
				<ul className="bs-ds-topics__points">
					{ item.points.map( ( point ) => (
						<li key={ point }>{ point }</li>
					) ) }
				</ul>
			) : null }

			{ item.steps && item.steps.length ? (
				<ol className="bs-ds-topics__steps">
					{ item.steps.map( ( step ) => (
						<li key={ step }>{ step }</li>
					) ) }
				</ol>
			) : null }

			{ item.body || null }

			{ note && note.text ? <Alert layout="default" tone={ note.tone || 'info' } desc={ note.text } /> : null }
		</>
	);
}

/**
 * @param {Object} props
 * @param {Array}  props.items     [{ key, label, lead, text, tags, points, steps, body, note }]
 * @param {string} props.className Where the row sits, for the screen that places it.
 * @param {*}      props.extra     Controls at the end of the row of questions: a disclosure the screen opens itself.
 * @param {string} props.about     What the questions are about, said in each one's name: a dozen rows each
 *                                 asked "How this works", and a screen reader's list could not tell them apart (#1928).
 * @param {boolean}  props.shut      The screen opened its own disclosure in `extra`: any open answer closes, so
 *                                   the two never stack open under the row (#2523).
 * @param {Function} props.onOpen    Told when an answer opens, so the screen can close its own.
 */
export default function Topics( { items, className = '', extra = null, about = '', shut = false, onOpen } ) {
	// `open` is the topic asked for; `shown` is the one whose answer is drawn,
	// which outlives `open` by the length of the closing transition.
	const [ open, setOpen ] = useState( null );
	const [ shown, setShown ] = useState( null );
	const [ height, setHeight ] = useState( 0 );
	const panel = useRef( null );
	const inner = useRef( null );
	const asks = useRef( {} );
	const mine = useId().replace( /[^\w-]/g, '' );
	const panelId = ( key ) => `bs-ds-topic-${ mine }-${ key }`;

	useLayoutEffect( () => {
		setHeight( open && inner.current ? inner.current.offsetHeight : 0 );
	}, [ open, shown ] );

	// An answer can change height while open (a list loads, the window
	// narrows); the panel follows it.
	useEffect( () => {
		if ( ! open || ! inner.current || 'undefined' === typeof window.ResizeObserver ) {
			return undefined;
		}

		const observer = new window.ResizeObserver( () => {
			if ( inner.current ) {
				setHeight( inner.current.offsetHeight );
			}
		} );

		observer.observe( inner.current );

		return () => observer.disconnect();
	}, [ open ] );

	useEffect( () => {
		if ( open || null === shown ) {
			return undefined;
		}

		const timer = window.setTimeout( () => setShown( null ), SETTLE_MS );

		return () => window.clearTimeout( timer );
	}, [ open, shown ] );

	useEffect( () => {
		if ( shut ) {
			setOpen( null );
		}
	}, [ shut ] );

	const closing = ! open && null !== shown;

	useInert( panel, closing );

	const list = ( items || [] ).filter( Boolean );

	if ( ! list.length && ! extra ) {
		return null;
	}

	const choose = ( key ) => {
		const next = open === key ? null : key;

		setOpen( next );

		if ( next ) {
			setShown( next );
			onOpen?.( next );
		} else if ( reducedMotion() ) {
			setShown( null );
		}
	};

	const onKeyDown = ( event ) => {
		if ( 'Escape' !== event.key || ! open ) {
			return;
		}

		event.stopPropagation();

		const ask = asks.current[ open ];

		choose( open );

		if ( ask ) {
			ask.focus();
		}
	};

	return (
		// The Escape handler catches keys from the buttons and links inside;
		// the group itself takes no focus of its own.
		// eslint-disable-next-line jsx-a11y/no-static-element-interactions
		<div className={ `bs-ds-topics${ open ? ' is-open' : '' }${ className ? ` ${ className }` : '' }` } onKeyDown={ onKeyDown }>
			<div className="bs-ds-topics__row">
				{ list.map( ( item ) => (
					<Button
						key={ item.key }
						ref={ ( node ) => {
							asks.current[ item.key ] = node;
						} }
						type="ghost"
						size="sm"
						trailing="chevron-down"
						trailingTone="3"
						className="bs-ds-topics__ask"
						aria-expanded={ open === item.key }
						aria-controls={ panelId( item.key ) }
						aria-label={
							about && 'string' === typeof item.label
								? sprintf(
										/* translators: 1: a question, e.g. "How this works"; 2: what it is about, e.g. "Disable XML-RPC". */
										_x( '%1$s: %2$s', 'a question, then what it is about', 'bettershield' ),
										item.label,
										about
								  )
								: undefined
						}
						onClick={ () => choose( item.key ) }
					>
						{ item.label }
					</Button>
				) ) }
				{ extra }
			</div>

			<div
				ref={ panel }
				className="bs-ds-topics__panel"
				style={ { height } }
				aria-hidden={ closing ? 'true' : undefined }
				onTransitionEnd={ ( event ) => {
					if ( event.target === panel.current && 'height' === event.propertyName && ! open ) {
						setShown( null );
					}
				} }
			>
				<div ref={ inner } className="bs-ds-topics__answers">
					{ list.map( ( item ) => (
						<div key={ item.key } className="bs-ds-topics__body" id={ panelId( item.key ) } hidden={ shown !== item.key }>
							<Answer item={ item } />
						</div>
					) ) }
				</div>
			</div>
		</div>
	);
}
