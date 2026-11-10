/**
 * The design's Badge, size sm: a label on a tone's fill, no border.
 */

import './Badge.css';

import Icon from './Icon';

/**
 * The tone a classic status chip's kind is drawn in, so a status moves over
 * in the color it had: good news in brand, severity in its own tone, and
 * everything that is only a fact in neutral.
 */
const KIND_TONES = {
	good: 'brand',
	safe: 'brand',
	on: 'brand',
	critical: 'red',
	high: 'orange',
	medium: 'yellow',
	caution: 'yellow',
	warning: 'yellow',
	low: 'blue',
	info: 'neutral',
	neutral: 'neutral',
	muted: 'neutral',
	applied: 'neutral',
};

/**
 * @param {string} kind A classic chip's kind.
 * @return {string} The Badge tone it is drawn in.
 */
export function kindTone( kind ) {
	return KIND_TONES[ kind ] || 'neutral';
}

/**
 * @param {Object} props
 * @param {string} props.tone      neutral, brand, red, orange, yellow or blue.
 * @param {string} props.icon      Optional leading icon, 12px.
 * @param {string} props.className Extra classes.
 */
export default function Badge( { tone = 'neutral', icon = '', className = '', children } ) {
	return (
		<span className={ `bs-ds-badge bs-ds-badge--${ tone }${ className ? ` ${ className }` : '' }` }>
			{ icon ? <Icon name={ icon } size={ 12 } /> : null }
			{ children }
		</span>
	);
}
