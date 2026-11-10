/**
 * What a screen draws while its read is out, when there is nothing to list,
 * and when the read failed: the same three answers the classic screens gave
 * (and the same words), drawn with the design's parts.
 *
 * A failed read always says so. Drawing nothing would look the same as a
 * feature that does not apply to this site, and the reader would be told the
 * wrong thing.
 */

import './States.css';

import { __ } from '@wordpress/i18n';
import Alert from './Alert';
import Button from './Button';
import Skeleton, { CardBone } from './Skeleton';

/**
 * @param {Object} props
 * @param {string} props.label What is loading.
 * @param {Array}  props.rows  The stand-in's rows, by text width.
 */
export function Loading( { label, rows } ) {
	return (
		<Skeleton label={ label || __( 'Loading…', 'bettershield' ) }>
			<CardBone rows={ rows } />
		</Skeleton>
	);
}

/**
 * The design's empty state: the card stays, its list is gone, and one 12
 * line says why.
 *
 * @param {Object} props
 * @param {*}      props.children The line.
 */
export function EmptyState( { children } ) {
	return <p className="bs-ds-empty">{ children }</p>;
}

/**
 * @param {Object}   props
 * @param {string}   props.title    The title; "That could not be loaded." by default.
 * @param {*}        props.children The explanation; the display-problem sentence by default.
 * @param {Function} props.onRetry  Reads again.
 * @param {Object}   props.alertRef Takes the alert, to move focus to it.
 */
export function ErrorState( { title, children, onRetry, alertRef } ) {
	return (
		<div role="alert">
			<Alert
				tone="error"
				layout="default"
				alertRef={ alertRef }
				title={ title || __( 'That could not be loaded.', 'bettershield' ) }
				desc={
					children ||
					__( 'This is a display problem, not a security problem. Your site is unchanged.', 'bettershield' )
				}
				actions={
					onRetry ? (
						<Button type="secondary" size="sm" onClick={ onRetry }>
							{ __( 'Try Again', 'bettershield' ) }
						</Button>
					) : null
				}
			/>
		</div>
	);
}

/**
 * A resource's three states in one place: loading, failed, or its data.
 *
 * @param {Object}   props
 * @param {Object}   props.resource The store's resource.
 * @param {Function} props.onRetry  Reads again.
 * @param {*}        props.loading  What to draw while the first read is out.
 * @param {Function} props.children Given the data, once there is some.
 */
export function Resource( { resource, onRetry, loading, children } ) {
	if ( ! resource || 'idle' === resource.status || ( 'loading' === resource.status && ! resource.data ) ) {
		return loading || <Loading />;
	}

	if ( 'error' === resource.status ) {
		return <ErrorState onRetry={ onRetry } />;
	}

	return children( resource.data );
}
