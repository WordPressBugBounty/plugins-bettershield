/**
 * A timestamp as a person would say it.
 *
 * The screens an owner reads first are read at a glance: the last audit, when
 * a finding was first seen, when somebody changed something while nobody was
 * watching. `toLocaleString()` answers all of those with "9/7/2026, 5:14:47 PM"
 * — a machine format that spends its most legible characters on a second
 * nothing here is accurate to, and dates the two days a reader can name.
 *
 * Four shapes, and no fifth: today and yesterday are named, an older date
 * inside the same year drops the year, and one outside it keeps it. Absolute
 * still, never "2 days ago" — a relative phrase reads as reassurance where a
 * date reads as staleness, which is the distinction this product is built on.
 *
 * The locale is the browser's own, which is what every screen here has always
 * formatted with: nothing in the model the server inlines carries a locale, so
 * naming one would be inventing a fact rather than honoring one.
 *
 * The clock is the site's, as in every email this plugin sends, read from what
 * WordPress itself hands its date script. A reader in another zone gets the
 * site's zone named after the time, so the same moment never reads as two. A
 * reader in the site's own zone sees the time alone. On a page without that
 * script it stays the browser's clock.
 */

import { __, sprintf } from '@wordpress/i18n';

/**
 * The site's zone as WordPress states it, or null where the page has no date
 * script. A site can name a zone or give a bare offset, and an offset has no
 * name to hand to the formatter.
 */
function siteZone() {
	const zone = window.wp?.date?.getSettings?.()?.timezone;

	return zone ? { name: String( zone.string || '' ), hours: Number( zone.offset ) || 0 } : null;
}

/** Whether this browser can format in a zone by that name. */
function knowsZone( name ) {
	try {
		new Intl.DateTimeFormat( 'en', { timeZone: name } );

		return '' !== name;
	} catch ( error ) {
		return false;
	}
}

/**
 * Format a moment on the site's clock.
 *
 * @param {Date}    date    The moment.
 * @param {Object}  options Intl options.
 * @param {string=} locale  The browser's own by default.
 * @return {Intl.DateTimeFormat} and the date to give it, as a pair.
 */
function onSiteClock( date, options, locale ) {
	const zone = siteZone();

	if ( ! zone ) {
		return [ new Intl.DateTimeFormat( locale, options ), date ];
	}

	if ( knowsZone( zone.name ) ) {
		return [ new Intl.DateTimeFormat( locale, { ...options, timeZone: zone.name } ), date ];
	}

	// An offset: move the moment by it and read that as UTC.
	return [ new Intl.DateTimeFormat( locale, { ...options, timeZone: 'UTC' } ), new Date( date.getTime() + zone.hours * 36e5 ) ];
}

function formatted( date, options ) {
	const [ format, moment ] = onSiteClock( date, options );

	return format.format( moment );
}

/** The site's calendar and clock at a moment, as numbers. */
function wallClock( date ) {
	const [ format, moment ] = onSiteClock(
		date,
		{ year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', hourCycle: 'h23' },
		'en-US'
	);
	const parts = {};

	format.formatToParts( moment ).forEach( ( part ) => {
		parts[ part.type ] = Number( part.value );
	} );

	return parts;
}

/** That calendar day as a number, so two can be subtracted. */
function dayNumber( date ) {
	const { year, month, day } = wallClock( date );

	return Date.UTC( year, month - 1, day ) / 864e5;
}

/**
 * The site's zone, named as every email names it (Time::zone()), or '' for a
 * reader whose own clock already says the same.
 */
function zoneLabel( date ) {
	const zone = siteZone();

	if ( ! zone ) {
		return '';
	}

	const { year, month, day, hour, minute } = wallClock( date );
	const offset = Math.round( ( Date.UTC( year, month - 1, day, hour, minute ) - Math.floor( date.getTime() / 6e4 ) * 6e4 ) / 6e4 );

	if ( offset === -date.getTimezoneOffset() ) {
		return '';
	}

	if ( knowsZone( zone.name ) ) {
		const named = new Intl.DateTimeFormat( 'en-US', { timeZone: zone.name, timeZoneName: 'short' } )
			.formatToParts( date )
			.find( ( part ) => 'timeZoneName' === part.type );

		if ( named && /^[A-Z]{2,5}$/.test( named.value ) && 'GMT' !== named.value ) {
			return named.value;
		}
	}

	if ( 0 === offset ) {
		return 'UTC';
	}

	const minutes = Math.abs( offset );
	const label = `UTC${ offset < 0 ? '-' : '+' }${ Math.floor( minutes / 60 ) }`;

	return 0 === minutes % 60 ? label : `${ label }:${ String( minutes % 60 ).padStart( 2, '0' ) }`;
}

/**
 * The time of day on the site's clock, with the zone where the reader needs it.
 *
 * @param {Date} date The moment.
 * @return {string} e.g. "5:14 PM", or "5:14 PM UTC+6".
 */
export function timeOfDay( date ) {
	const time = formatted( date, { hour: 'numeric', minute: '2-digit' } );
	const label = zoneLabel( date );

	return label ? `${ time } ${ label }` : time;
}

/**
 * The calendar day a moment falls on, on the site's clock.
 *
 * @param {Date} date The moment.
 * @return {string} YYYY-MM-DD.
 */
export function siteDay( date ) {
	const { year, month, day } = wallClock( date );

	return [ year, String( month ).padStart( 2, '0' ), String( day ).padStart( 2, '0' ) ].join( '-' );
}

/**
 * @param {?string} iso An ISO 8601 timestamp, or nothing.
 * @param {Date}    now The moment to read it against; the clock by default.
 * @return {string} The phrase to print.
 */
export function whenPhrase( iso, now = new Date() ) {
	if ( ! iso ) {
		return __( 'never', 'bettershield' );
	}

	const date = new Date( iso );

	if ( Number.isNaN( date.getTime() ) ) {
		return __( 'unknown', 'bettershield' );
	}

	const time = timeOfDay( date );
	const days = Math.round( dayNumber( now ) - dayNumber( date ) );

	if ( 0 === days ) {
		return sprintf(
			/* translators: %s: a time of day, e.g. 5:14 PM. */
			__( 'today, %s', 'bettershield' ),
			time
		);
	}

	if ( 1 === days ) {
		return sprintf(
			/* translators: %s: a time of day, e.g. 12:52 PM. */
			__( 'yesterday, %s', 'bettershield' ),
			time
		);
	}

	// The year only where it is news. A date inside the year being read
	// carries it in every reader's head already.
	const day = formatted(
		date,
		wallClock( date ).year === wallClock( now ).year
			? { month: 'short', day: 'numeric' }
			: { month: 'short', day: 'numeric', year: 'numeric' }
	);

	return sprintf(
		/* translators: 1: a date, e.g. Sep 6. 2: a time of day, e.g. 12:52 PM. */
		__( '%1$s, %2$s', 'bettershield' ),
		day,
		time
	);
}
