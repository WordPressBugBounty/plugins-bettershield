<?php
/**
 * Fix for "Sign-in lockouts are not running" (#2205).
 *
 * Which of the four cases this site is in, read from what a real request
 * saw, and the settings that case asks about: the trusted proxies the owner
 * names, or Cloudflare where a connection from Cloudflare's own ranges was
 * seen. Nothing is inferred from a header or a private address, nothing is
 * filled in from one, and the save is login protection's own, with its
 * validation, record and password. Fixed is said only once a request made
 * under the new settings resolved a visitor.
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Fixes;

use BetterShield\Login\Protection;
use BetterShield\Support\Observed;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ProxySetup {

	/**
	 * Which case an unresolved request was: a named proxy whose header names
	 * no usable visitor, headers no named proxy vouches for, a named proxy
	 * that sends none, or a private address nothing names. The first is
	 * asked before the second because its header is ignored too.
	 *
	 * @param array<string, bool> $observed What Observed::client_resolution() said.
	 */
	public static function reason( array $observed ): string {
		if ( ! empty( $observed['named_proxy_no_visitor'] ) ) {
			return 'proxy_names_no_visitor';
		}

		if ( ! empty( $observed['ignored_headers'] ) ) {
			return 'unnamed_proxy';
		}

		if ( ! empty( $observed['named_proxy'] ) ) {
			return 'proxy_sends_no_header';
		}

		return 'private_address';
	}

	/**
	 * What the panel shows. Never an address a request carried.
	 *
	 * @return array{observed: bool, current: bool, resolved: bool, reason: string, cloudflare_seen: bool, cloudflare: bool, trusted_proxies: string[]}
	 */
	public static function state(): array {
		$observed = Observed::client_resolution();
		$settings = Protection::instance()->settings();

		return array(
			'observed'        => null !== $observed,
			// Made under the settings in force now, so its answer is about them.
			'current'         => null !== $observed && $observed['current'],
			'resolved'        => null !== $observed && $observed['resolved'],
			'reason'          => null === $observed || $observed['resolved'] ? '' : self::reason( $observed ),
			'cloudflare_seen' => null !== $observed && $observed['cloudflare_seen'],
			'cloudflare'      => (bool) $settings['cloudflare'],
			'trusted_proxies' => array_values( (array) $settings['trusted_proxies'] ),
		);
	}
}
