/**
 * Where this site stands on agent access, at the top of every Agents tab but
 * Connect: the design's Stat group over the facts in next/data/agents.js.
 */

import { __ } from '@wordpress/i18n';
import { agentTiles, stateLabels } from '../data/agents';
import Stats from '../ui/Stats';
import { StatsBone } from '../ui/Skeleton';

/**
 * @param {Object} props
 * @param {Object} props.surface The agent-surface payload.
 */
export default function AgentStrip( { surface } ) {
	return <Stats label={ __( 'AI assistant access', 'bettershield' ) } tiles={ agentTiles( surface ) } />;
}

/** The strip's shape, for a screen's stand-in while the payload is read. */
export function AgentStripBone() {
	return <StatsBone labels={ Object.values( stateLabels() ) } />;
}
