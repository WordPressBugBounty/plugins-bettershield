<?php
/**
 * An answer that goes out as an event stream rather than as one JSON body.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Mcp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The REST server encodes whatever a response holds as JSON. A stream is text
 * this endpoint has already encoded, message by message, so it travels as a
 * value of its own kind and the controller writes it out as it is.
 */
final class EventStream {

	public string $body;

	public function __construct( string $body ) {
		$this->body = $body;
	}
}
