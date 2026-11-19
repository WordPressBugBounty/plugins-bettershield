/**
 * A short list of what a step does, each line with its icon, as the design
 * opens the Welcome and hub steps with.
 */

import './Benefits.css';

import Icon from '../ui/Icon';

/**
 * @param {Object}                  props
 * @param {Array<[string, string]>} props.items Each line's icon name and words.
 */
export default function Benefits( { items } ) {
	return (
		<ul className="bs-ds-setup-benefits">
			{ items.map( ( [ icon, text ] ) => (
				<li key={ text }>
					<Icon name={ icon } size={ 16 } tone="brand" />
					{ text }
				</li>
			) ) }
		</ul>
	);
}
