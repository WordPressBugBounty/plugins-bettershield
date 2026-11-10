/**
 * What sharing usage data sends, in one sentence.
 *
 * Quick Setup's question and the Overview's reminder ask the same thing, so
 * they say it with the same words (#2407): the full list stays behind
 * "What We Collect" and under Settings › General. It names how often and
 * every kind of field `Usage::payload()` sends, the inactive plugins among
 * them, so the short form never says less than the report holds.
 */

import { __ } from '@wordpress/i18n';

/**
 * The summary both screens show beside the question.
 *
 * @return {string} The sentence.
 */
export function usageSummary() {
	return `${ __(
		'Sharing sends WPDeveloper a short report, at most once a day: your site’s address, title and admin email, language and versions, which plugins are installed and active, and the theme.',
		'bettershield'
	) } ${ __( 'Nothing about visitors, users or security events is sent.', 'bettershield' ) }`;
}
