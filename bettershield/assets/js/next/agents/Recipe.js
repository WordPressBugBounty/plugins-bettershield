/**
 * The configuration for whichever assistant is picked, on Agents › Connect.
 *
 * A client the site has no ready-made block for is offered the plain address
 * rather than an empty block: nothing here decides what a configuration says,
 * and a card that showed an empty one would be describing a failure as a step.
 *
 * Drawn with the design's copy field (a recessed block in Geist, its own
 * Copy button beside it) and a 12 line under it for how the client signs in.
 */

import './Recipe.css';

import { __, sprintf } from '@wordpress/i18n';
import Alert from '../ui/Alert';
import CopyField from '../ui/CopyField';

/**
 * How a client signs in, in words: the browser flow is what an owner sees,
 * and its protocol name is not.
 *
 * @param {string} auth The snippet's sign-in method.
 * @return {string} The sentence.
 */
function signsIn( auth ) {
	if ( 'oauth' === auth ) {
		return __( 'Signs in through the browser.', 'bettershield' );
	}

	return sprintf(
		/* translators: %s: how that client signs in. */
		__( 'Signs in with: %s', 'bettershield' ),
		auth
	);
}

/**
 * @param {Object} props
 * @param {Object} props.snippet  What the picked client is handed.
 * @param {string} props.endpoint The address the card shows for every client.
 */
export default function Recipe( { snippet, endpoint } ) {
	/*
	 * Codex reads its servers from config.toml, where the JSON block the
	 * other clients take is a parse error that stops it starting. Its table
	 * names an environment variable for the token rather than holding it.
	 */
	if ( snippet && snippet.toml ) {
		return (
			<>
				<CopyField
					label={ __( 'Add to Codex’s config.toml', 'bettershield' ) }
					value={ snippet.toml }
					multiline
					copyLabel={ __( 'Copy the Configuration', 'bettershield' ) }
				/>
				<p className="bs-ds-recipe__meta">
					{ sprintf(
						/* translators: %s: the name of an environment variable. */
						__( 'Set %s to your connection key where Codex runs.', 'bettershield' ),
						snippet.token_env
					) }
				</p>
			</>
		);
	}

	if ( snippet && snippet.json ) {
		return (
			<CopyField
				label={ __( 'Configuration', 'bettershield' ) }
				value={ snippet.json }
				multiline
				copyLabel={ __( 'Copy the Configuration', 'bettershield' ) }
			/>
		);
	}

	if ( snippet && snippet.url ) {
		return (
			<>
				{ /* The card shows the address below for every client; the
				     same string again, with a second copy button, helped
				     nobody. */ }
				{ snippet.url !== endpoint ? (
					<CopyField
						label={ __( 'Address to paste', 'bettershield' ) }
						value={ snippet.url }
						copyLabel={ __( 'Copy the Address to Paste', 'bettershield' ) }
					/>
				) : null }
				{ snippet.auth ? <p className="bs-ds-recipe__meta">{ signsIn( snippet.auth ) }</p> : null }
			</>
		);
	}

	return (
		<Alert
			layout="default"
			tone="info"
			desc={ __(
				'No step-by-step guide for this one. Paste the address below into your assistant’s connector settings.',
				'bettershield'
			) }
		/>
	);
}
