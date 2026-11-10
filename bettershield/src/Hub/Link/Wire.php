<?php
/**
 * One message from the Hub link to the hub: signed over its exact bytes,
 * sent, and its answer read.
 *
 * The contract (v1) is the hub's and this plugin's together. Each request
 * carries the id the site signs as and an Ed25519 signature over the body;
 * the body names the version, the site and the moment it was signed, and the
 * hub refuses one signed more than ten minutes ago. Every answer the contract
 * gives is read as an answer rather than turned into a failure: what each one
 * means for what is sent next is the sender's to decide.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Hub\Link;

use BetterShield\Support\Http;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Wire {

	/** Where a batch of events goes. */
	public const EVENTS = '/v1/link/events';

	/** Where a heartbeat goes. */
	public const HEARTBEAT = '/v1/link/heartbeat';

	/** The contract's version, which the body names. */
	public const VERSION = 1;

	/**
	 * The answers the contract gives: accepted; malformed; not signed by a
	 * key the hub read; a batch it has already; no longer read; too large;
	 * and wait.
	 */
	private const ANSWERS = array( 202, 400, 401, 409, 410, 413, 429, 503 );

	/**
	 * Sign one message and send it.
	 *
	 * `status` is 0 when nothing answered — no key to sign with, a refused or
	 * failed connection — and otherwise the status the hub answered with.
	 * `retry_after` is how many seconds it asked for, or 0.
	 *
	 * @param array<string, mixed> $fields The message's own fields.
	 * @return array{status: int, retry_after: int}
	 */
	public static function send( string $path, array $fields ): array {
		$site = Link::record()['site'];
		$body = self::body( $site, $fields );

		$signature = '' === $body ? '' : Link::sign( $body );

		if ( '' === $site || '' === $signature ) {
			return array(
				'status'      => 0,
				'retry_after' => 0,
			);
		}

		$response = Http::post(
			'https://' . Link::HOST . $path,
			array(
				'body'                => $body,
				'headers'             => array(
					'Content-Type'             => 'application/json',
					'X-BetterShield-Site'      => $site,
					'X-BetterShield-Signature' => $signature,
				),
				'timeout'             => 10,
				// The hub answers where it was asked. A redirect is somebody
				// else answering, and a signed body is not handed on.
				'redirection'         => 0,
				// An answer is a status and a sentence; nothing longer is read.
				'limit_response_size' => 8192,
			),
			self::ANSWERS
		);

		if ( is_wp_error( $response ) ) {
			$data = $response->get_error_data();

			return array(
				'status'      => is_array( $data ) ? (int) ( $data['status'] ?? 0 ) : 0,
				'retry_after' => 0,
			);
		}

		return array(
			'status'      => (int) wp_remote_retrieve_response_code( $response ),
			'retry_after' => self::retry_after( (string) wp_remote_retrieve_header( $response, 'retry-after' ) ),
		);
	}

	/**
	 * The exact bytes that are signed and sent: the version, the site and the
	 * moment of signing, then the message's own fields. '' when the fields
	 * cannot be written as JSON.
	 *
	 * @param array<string, mixed> $fields
	 */
	public static function body( string $site, array $fields ): string {
		$body = wp_json_encode(
			array(
				'v'         => self::VERSION,
				'site'      => $site,
				'signed_at' => gmdate( 'Y-m-d\TH:i:s.v\Z' ),
			) + $fields,
			JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
		);

		return is_string( $body ) ? $body : '';
	}

	/**
	 * A Retry-After header as seconds: a number of them, or a date to wait
	 * until. 0 when there is none, or it says nothing this can read.
	 */
	public static function retry_after( string $value ): int {
		$value = trim( $value );

		if ( '' === $value ) {
			return 0;
		}

		if ( ctype_digit( $value ) ) {
			return (int) $value;
		}

		$until = strtotime( $value );

		return false === $until ? 0 : max( 0, $until - time() );
	}
}
