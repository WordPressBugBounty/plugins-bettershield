/**
 * Naming accounts in a two-factor list: a search that finds this site's
 * accounts by name, username or email, then the accounts named so far, each
 * with a way to take it off. The search comes first so two lists side by side
 * keep their search boxes level, however many people each names.
 *
 * A search box over a list of buttons rather than a token field: each result
 * says whose account it is (name, username, roles) before it is picked, which
 * is the one thing that matters when the list decides who is asked for a code.
 */

import './PeoplePicker.css';

import apiFetch from '@wordpress/api-fetch';
import { useEffect, useState } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import Button from '../ui/Button';
import Field from '../ui/Field';

const SEARCH = '/bettershield/v1/two-factor/policy/accounts';

/**
 * @param {Object}   props
 * @param {string}   props.label    What the list is for.
 * @param {string}   props.help     A line under the search.
 * @param {Object[]} props.people   The accounts named, each { id, name, login }.
 * @param {number[]} props.taken    Ids named in the other list, offered as unavailable.
 * @param {string}   props.takenWhy Why a taken account can't be picked here.
 * @param {boolean}  props.disabled While saving.
 * @param {boolean}  props.canAdd   Whether accounts can be added now; taking one off always can.
 * @param {Function} props.onChange Called with the new list of accounts.
 */
export default function PeoplePicker( { label, help, people, taken = [], takenWhy = '', disabled = false, canAdd = true, onChange } ) {
	const [ search, setSearch ] = useState( '' );
	const [ found, setFound ] = useState( [] );
	const [ failed, setFailed ] = useState( false );
	// The search the results are the answer to, so "no matches" waits for one.
	const [ answered, setAnswered ] = useState( '' );
	const term = search.trim();

	useEffect( () => {
		if ( ! term ) {
			setFound( [] );
			setFailed( false );
			return undefined;
		}

		let live = true;
		// A short pause, so typing a name is one request rather than one a letter.
		const wait = setTimeout( () => {
			apiFetch( { path: `${ SEARCH }?search=${ encodeURIComponent( term ) }` } )
				.then( ( rows ) => {
					if ( live ) {
						setFound( Array.isArray( rows ) ? rows : [] );
						setFailed( false );
						setAnswered( term );
					}
				} )
				.catch( () => {
					if ( live ) {
						setFound( [] );
						setFailed( true );
					}
				} );
		}, 300 );

		return () => {
			live = false;
			clearTimeout( wait );
		};
	}, [ term ] );

	const named = people.map( ( person ) => person.id );
	const add = ( person ) => {
		onChange( [ ...people, { id: person.id, name: person.name, login: person.login } ] );
		setSearch( '' );
	};

	return (
		<div className="bs-ds-people">
			<p className="bs-ds-people__label">{ label }</p>
			{ canAdd ? (
			<Field
				className="bs-ds-people__search"
				width="md"
				type="search"
				label={ sprintf(
					/* translators: %s: what the list is for, e.g. "Also require two-factor for these people". */
					__( 'Find an account to add: %s', 'bettershield' ),
					label
				) }
				hideLabelFromVision
				placeholder={ __( 'Search by name, username or email', 'bettershield' ) }
				help={ failed ? __( 'The search didn’t work. Try again.', 'bettershield' ) : help }
				value={ search }
				disabled={ disabled }
				onChange={ setSearch }
			/>
			) : null }
			{ term && answered === term && found.length ? (
				<ul className="bs-ds-people__found" aria-label={ __( 'Matching accounts', 'bettershield' ) }>
					{ found.map( ( person ) => {
						const already = named.includes( person.id );
						const other = taken.includes( person.id );

						return (
							<li key={ person.id } className="bs-ds-people__result">
								<span className="bs-ds-people__name">
									{ person.name || person.login }
									<span className="bs-ds-people__login">
										{ [ person.login, ( person.roles || [] ).join( ', ' ) ].filter( Boolean ).join( ' · ' ) }
									</span>
									{ other ? <span className="bs-ds-people__why">{ takenWhy }</span> : null }
								</span>
								<Button type="secondary" size="sm" disabled={ disabled || already || other } onClick={ () => add( person ) }>
									{ already ? __( 'Added', 'bettershield' ) : __( 'Add', 'bettershield' ) }
								</Button>
							</li>
						);
					} ) }
				</ul>
			) : null }
			{ term && answered === term && ! found.length && ! failed ? (
				<p className="bs-ds-people__none" role="status">
					{ __( 'No matching accounts on this site.', 'bettershield' ) }
				</p>
			) : null }
			{ people.length ? (
				<ul className="bs-ds-people__chosen">
					{ people.map( ( person ) => (
						<li key={ person.id } className="bs-ds-people__person">
							<span className="bs-ds-people__name">
								{ person.name || person.login }
								{ person.name && person.name !== person.login ? <span className="bs-ds-people__login">{ person.login }</span> : null }
							</span>
							<Button
								type="ghost"
								size="sm"
								disabled={ disabled }
								onClick={ () => onChange( people.filter( ( other ) => other.id !== person.id ) ) }
								aria-label={ sprintf(
									/* translators: %s: a person's name. */
									__( 'Remove %s', 'bettershield' ),
									person.name || person.login
								) }
							>
								{ __( 'Remove', 'bettershield' ) }
							</Button>
						</li>
					) ) }
				</ul>
			) : (
				<p className="bs-ds-people__none">{ __( 'Nobody yet.', 'bettershield' ) }</p>
			) }
		</div>
	);
}
