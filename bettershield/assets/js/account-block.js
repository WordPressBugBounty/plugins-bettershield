/**
 * The Sign-in Security block, in the editor. It draws for the person viewing
 * the page, so the editor shows what it is rather than the editor's own panels.
 */

import { registerBlockType } from '@wordpress/blocks';
import { useBlockProps } from '@wordpress/block-editor';
import { Placeholder } from '@wordpress/components';
import { __ } from '@wordpress/i18n';

const Edit = () => (
	<div { ...useBlockProps() }>
		<Placeholder
			icon="shield"
			label={ __( 'Sign-in Security', 'bettershield' ) }
			instructions={ __( 'Two-factor, passkeys and signed-in devices appear here for people who are signed in.', 'bettershield' ) }
		/>
	</div>
);

registerBlockType( 'bettershield/account', {
	apiVersion: 3,
	title: __( 'Sign-in Security', 'bettershield' ),
	category: 'widgets',
	icon: 'shield',
	supports: { html: false },
	edit: Edit,
	save: () => null,
} );
