<?php
/**
 * Fix for "Two plugins limit sign-in attempts" (#1945): leave the job to the
 * other plugin.
 *
 * The same choice the Quick Setup's security-plugins step saves, which is
 * what clears the finding: BetterShield's attempt limit goes off, through
 * the settings ledger, and the plugins limiting sign-ins now are kept with
 * the choice. Only the sign-in limit's answer changes; every other job keeps
 * the choice already saved for it, where saving the step's whole form from
 * here would have reset them.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Onboarding\QuickSetup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginLimits {

	/**
	 * @return true|\WP_Error
	 */
	public static function leave_to_other() {
		$saved = (array) ( QuickSetup::state()['coexistence'] ?? array() );

		return QuickSetup::save_coexistence( array_merge( $saved, array( 'login_limits' => 'keep' ) ) );
	}
}
