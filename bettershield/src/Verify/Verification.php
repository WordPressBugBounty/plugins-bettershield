<?php
/**
 * What the audit is allowed to conclude from a page view.
 *
 * A thin reader rather than a second source of truth: the checks ask this one
 * question — did a real visitor's page contradict what this item claims? —
 * and everything else about verification stays in `State` and `Checks`.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Verify;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Verification {

	/**
	 * The sentence describing what was missing, if the last page view found
	 * this item absent. Null when it was present, when nothing has been
	 * observed yet, or when the item is not observable at all.
	 *
	 * Null on "not yet observed" is deliberate: an item nobody has been able
	 * to confirm is not the same as one that has been contradicted, and only
	 * the second is a finding. Saying otherwise would make every freshly
	 * applied item raise an alarm until the next visitor arrives.
	 */
	public static function last_absence( string $item ): ?string {
		$record = State::for_item( $item );

		if ( null === $record || Checks::ABSENT !== ( $record['status'] ?? '' ) ) {
			return null;
		}

		$detail = trim( (string) ( $record['detail'] ?? '' ) );

		return '' === $detail ? __( 'It was not there on the last page a visitor received.', 'bettershield' ) : $detail;
	}
}
