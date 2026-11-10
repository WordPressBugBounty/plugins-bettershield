/**
 * The settings rows (./SettingRow), and "Saved." beside a control, which
 * reads the dashboard's store.
 */

import './Setting.css';

import { __ } from '@wordpress/i18n';
import { useSaved } from '../../store';
import Icon from './Icon';

export { default, SettingsCard, Toggle } from './SettingRow';

/**
 * "Saved.", beside the control that just saved, announced as it appears.
 *
 * @param {Object} props
 * @param {string} props.forKey The store action key the control saves under.
 */
export function Saved( { forKey } ) {
	const showing = useSaved( forKey );

	if ( ! showing ) {
		return null;
	}

	return (
		<p className="bs-ds-saved" role="status">
			<Icon name="check" size={ 12 } tone="ok" />
			{ __( 'Saved.', 'bettershield' ) }
		</p>
	);
}
