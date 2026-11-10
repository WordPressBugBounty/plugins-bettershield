/** Each selected subsite keeps its own ordinary Hub consent. */
import { useEffect, useRef, useState } from '@wordpress/element';
import apiFetch from '@wordpress/api-fetch';
import { announce } from '../../ui/announce';
import { __, sprintf } from '@wordpress/i18n';
import Armed from '../ui/Armed';
import Button from '../ui/Button';
import Field from '../ui/Field';
import './NetworkHubConnect.css';

export default function NetworkHubConnect( { sites } ) {
	const [ selected, setSelected ] = useState( [] );
	const [ queue, setQueue ] = useState( [] );
	const [ index, setIndex ] = useState( 0 );
	const [ completed, setCompleted ] = useState( [] );
	const [ link, setLink ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ message, setMessage ] = useState( '' );
	useEffect( () => announce( busy ? __( 'Working…', 'bettershield' ) : message ), [ busy, message ] );
	const current = queue[ index ];
	const heading = useRef( null );
	useEffect( () => { if ( queue.length ) heading.current?.focus(); }, [ index, queue.length, link ] );
	const advance = ( connected ) => {
		if ( connected ) setCompleted( ( old ) => [ ...old, current.id ] );
		setIndex( ( old ) => old + 1 ); setLink( '' );
	};
	const check = async () => {
		setBusy( true ); setMessage( '' );
		try {
			const result = await apiFetch( { path: `/bettershield/v1/network/hub/status?sites[]=${ current.id }` } );
			const state = result.sites.find( ( s ) => s.id === current.id );
			if ( state?.connected ) { advance( true ); setMessage( __( 'Connection confirmed. Continue with the next site.', 'bettershield' ) ); }
			else setMessage( state?.error || __( 'No connection is approved yet. Finish both approvals, then check again, or skip this site.', 'bettershield' ) );
		} catch ( error ) { setMessage( error.message ); } finally { setBusy( false ); }
	};
	const prepare = async () => {
		setBusy( true ); setMessage( '' ); setLink( '' );
		try {
			const result = await apiFetch( { path: '/bettershield/v1/network/hub/connect', method: 'POST', data: { site_id: current.id, access: 'write', confirmed: true } } );
			if ( result.connected ) { advance( true ); setMessage( __( 'This site is already connected. Its current access is unchanged.', 'bettershield' ) ); }
			else { setLink( result.redirect ); setMessage( __( 'Finish both approvals, then come back and press Check Connection.', 'bettershield' ) ); }
		} catch ( error ) { setMessage( error.message ); } finally { setBusy( false ); }
	};
	const stop = () => { setQueue( [] ); setSelected( [] ); setLink( '' ); setMessage( __( 'The queue is closed. Completed connections remain connected.', 'bettershield' ) ); };
	return <section className="bs-ds-network-hub" aria-labelledby="network-hub-title">
		<h3 id="network-hub-title" ref={ heading } tabIndex={ -1 }>{ __( 'Connect selected sites to Hub', 'bettershield' ) }</h3>
		<p>{ __( 'Choose up to ten sites. Each is approved in its own tab.', 'bettershield' ) }</p>
		{ ! queue.length ? <>
			<Field kind="checks" label={ __( 'Sites to connect', 'bettershield' ) } value={ selected } onChange={ ( values ) => setSelected( values.slice( 0, 10 ) ) } options={ sites.filter( ( s ) => s.installed ).map( ( s ) => ( { value: s.id, label: s.name || s.url, disabled: selected.length >= 10 && ! selected.includes( s.id ) } ) ) } />
			<Button disabled={ ! selected.length } onClick={ () => { setQueue( sites.filter( ( s ) => selected.includes( s.id ) ) ); setIndex( 0 ); setCompleted( [] ); setMessage( '' ); } }>{ __( 'Review Selected Sites', 'bettershield' ) }</Button>
		</> : current ? <>
			<h4>{ sprintf( /* translators: 1: current position, 2: selected sites, 3: site name. */ __( '%1$d of %2$d: %3$s', 'bettershield' ), index + 1, queue.length, current.name || current.url ) }</h4>
			<p>{ current.url }</p>
			{ ! link && <><Armed key={ current.id } label={ __( 'Prepare This Connection', 'bettershield' ) } consequence={ __( 'This turns on the site’s agent reads, changes and assistant connection, which its Settings history can undo.', 'bettershield' ) } busy={ busy } onConfirm={ prepare } /></> }
			{ link && <div className="bs-ds-network-hub__actions"><Button href={ link } target="_blank" rel="noopener noreferrer">{ __( 'Approve This Site', 'bettershield' ) }</Button><Button disabled={ busy } isBusy={ busy } onClick={ check }>{ __( 'Check Connection', 'bettershield' ) }</Button><Button disabled={ busy } onClick={ () => setLink( '' ) }>{ __( 'Start This Site Again', 'bettershield' ) }</Button></div> }
			<div className="bs-ds-network-hub__actions"><Button disabled={ busy } onClick={ () => { advance( false ); setMessage( __( 'Site skipped. Any connection already approved remains connected.', 'bettershield' ) ); } }>{ __( 'Skip This Site', 'bettershield' ) }</Button><Button disabled={ busy } onClick={ stop }>{ __( 'Stop Here', 'bettershield' ) }</Button></div>
		</> : <><p>{ sprintf( /* translators: 1: confirmed connected sites, 2: selected sites. */ __( '%1$d of %2$d sites confirmed connected. Skipped sites can be selected again.', 'bettershield' ), completed.length, queue.length ) }</p><Button onClick={ stop }>{ __( 'Close Queue', 'bettershield' ) }</Button></> }
		{ message && <p>{ message }</p> }
	</section>;
}
