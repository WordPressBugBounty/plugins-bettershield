<?php
/**
 * What stopped a check that reads this site by asking it.
 *
 * A check that can't reach its own site keeps its earlier result, and the row
 * says so. "It didn't work" gives the owner nothing to act on, and the request
 * already said what went wrong: a status from a firewall or a password prompt,
 * a certificate it couldn't verify, or no answer in time.
 *
 * Certificate and timeout errors are matched on their message, since the HTTP
 * API gives them all one code. A transport that words them differently gets
 * the general sentence.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Audit;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SelfRequest {

	public const REFUSED     = 'refused';
	public const SSL         = 'ssl';
	public const TIMEOUT     = 'timeout';
	public const UNREACHABLE = 'unreachable';

	/**
	 * What went wrong with a request that didn't give an answer.
	 *
	 * @param array<string, mixed>|\WP_Error $response What the HTTP API returned.
	 * @return array{kind: string, code: int}
	 */
	public static function failure( $response ): array {
		if ( is_wp_error( $response ) ) {
			$message = strtolower( (string) $response->get_error_message() );

			if ( str_contains( $message, 'ssl' ) || str_contains( $message, 'certificate' ) ) {
				return array( 'kind' => self::SSL, 'code' => 0 );
			}

			return array( 'kind' => str_contains( $message, 'timed out' ) ? self::TIMEOUT : self::UNREACHABLE, 'code' => 0 );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		return array( 'kind' => in_array( $code, array( 401, 403 ), true ) ? self::REFUSED : self::UNREACHABLE, 'code' => $code );
	}

	/**
	 * The sentence for a failure, or the check's own when none was recorded.
	 *
	 * @param array<string, mixed>|null $failure   What failure() returned.
	 * @param string                    $otherwise The check's general sentence.
	 */
	public static function reason( ?array $failure, string $otherwise ): string {
		switch ( $failure['kind'] ?? '' ) {
			case self::REFUSED:
				return sprintf(
					/* translators: %d: the HTTP status the server answered with, such as 403. */
					__( 'Your server refused its own request (HTTP %d), so this check couldn’t run. A firewall or password protection may be blocking it.', 'bettershield' ),
					(int) $failure['code']
				);

			case self::SSL:
				return __( 'Your server couldn’t verify its own SSL certificate, so this check couldn’t run.', 'bettershield' );

			case self::TIMEOUT:
				return __( 'Your server took more than 5 seconds to answer itself, so this check couldn’t run.', 'bettershield' );

			case self::UNREACHABLE:
				return __( 'Your server couldn’t reach itself, so this check couldn’t run.', 'bettershield' );
		}

		return $otherwise;
	}
}
