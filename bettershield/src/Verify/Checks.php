<?php
/**
 * What can be confirmed from a real visitor's request, and how.
 *
 * The audit already probes whether enforcement is attached, and that catches
 * a great deal. What it cannot catch is the case where enforcement is
 * attached *for the request the audit runs in* and absent for everybody else:
 * the audit runs in wp-admin, and every protection here exists for the front
 * end. A filter hooked only on an admin condition, a header another plugin
 * strips after ours sets it —
 * all of those look correct from the dashboard and are wrong for visitors.
 *
 * So this asks the one question the dashboard cannot: on the page a visitor
 * just received, was the protection actually there?
 *
 * Three answers, and the third is the important one. `present` means it was
 * observed. `absent` means it was looked for on a page where it should have
 * been and was not. `unknown` means this request could not tell — and a
 * verifier that cannot see says exactly that, never "not protected".
 *
 * @package BetterShield
 */

declare( strict_types=1 );

namespace BetterShield\Verify;

use BetterShield\Hardening\Item\VersionDisclosure;
use BetterShield\Hardening\Items;
use BetterShield\Hardening\Manager;
use BetterShield\Support\Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Checks {

	public const PRESENT = 'present';
	public const ABSENT  = 'absent';
	public const UNKNOWN = 'unknown';

	/**
	 * Items that can be confirmed from a front-end response, and the observer
	 * that does it. An item absent from this list is not unverifiable in
	 * principle — it is one whose effect a page view cannot see, and the
	 * screen says so rather than leaving a blank.
	 *
	 * @return array<string, callable(): array{status: string, detail: string}>
	 */
	public static function observers(): array {
		return array(
			'security_headers'   => static function (): array {
				return self::observe_headers();
			},
			'version_disclosure' => static function (): array {
				return self::observe_generator();
			},
			'user_enumeration'   => static function (): array {
				return self::observe_enumeration();
			},
			// Both send a header a page view can see, exactly like the four
			// above; leaving them unobservable made the two items whose whole
			// effect is a header the two the sampler could not confirm.
			'hsts'               => static function (): array {
				// A header the daily check saw the web server sending is one
				// the item leaves to it on purpose, so PHP never queues one:
				// present, as the security headers count one the server
				// sends. Looked for here instead, it was "missing" on every
				// page view of exactly the sites that send it themselves.
				if ( ! empty( \BetterShield\Hardening\Manager::instance()->item_state( 'hsts' )['server_sends'] ) ) {
					return array(
						'status' => self::PRESENT,
						'detail' => __( 'Your web server sends this header itself, so this plugin does not send a second one.', 'bettershield' ),
					);
				}

				// The header goes out only on requests WordPress sees as
				// encrypted. On one it did not — which behind a proxy that
				// handles the encryption is every request — the header could
				// not have been on the page whatever this plugin did, and
				// looking for it anyway reports a proxied site as broken on
				// every page view.
				if ( ! Server::connection_is_https() ) {
					return array(
						'status' => self::UNKNOWN,
						'detail' => __( 'WordPress saw the last page as plain HTTP, and sends this header only over HTTPS. If a proxy handles HTTPS, wp-config.php must say so.', 'bettershield' ),
					);
				}

				return self::observe_one_header( 'Strict-Transport-Security' );
			},
			/*
			 * Whichever header the item's current mode actually sends. Pinned
			 * to the report-only name, this reported the strongest state of
			 * the feature as broken: a promoted policy sends the enforcing
			 * header, the sampler looked for the other one, found nothing, and
			 * answered ABSENT — a real negative on an item working harder than
			 * it ever had. This verifier exists so an item a visitor did not
			 * get stops reading as fine; inverted, it does the opposite.
			 */
			'csp_report_only'    => static function (): array {
				$mode = \BetterShield\Hardening\Item\ContentSecurityPolicy::mode(
					\BetterShield\Hardening\Manager::instance()->item_state( 'csp_report_only' )
				);

				return self::observe_one_header(
					\BetterShield\Hardening\Item\ContentSecurityPolicy::MODE_ENFORCING === $mode
						? 'Content-Security-Policy'
						: 'Content-Security-Policy-Report-Only'
				);
			},
		);
	}

	/**
	 * Whether one named header left PHP on this page view.
	 *
	 * @return array{status: string, detail: string}
	 */
	private static function observe_one_header( string $name ): array {
		foreach ( headers_list() as $header ) {
			if ( strtolower( $name ) === strtolower( trim( (string) strtok( $header, ':' ) ) ) ) {
				return array(
					'status' => self::PRESENT,
					'detail' => sprintf(
						/* translators: %s: an HTTP header name. */
						__( '%s was on the page a visitor just received.', 'bettershield' ),
						$name
					),
				);
			}
		}

		return array(
			'status' => self::ABSENT,
			'detail' => sprintf(
				/* translators: %s: an HTTP header name. */
				__( 'This plugin did not send %s on the last page. Your web server may still add it.', 'bettershield' ),
				$name
			),
		);
	}

	/**
	 * Whether an item can be confirmed this way at all.
	 */
	public static function is_observable( string $item ): bool {
		return isset( self::observers()[ $item ] );
	}

	/**
	 * Run one item's observer.
	 *
	 * @return array{status: string, detail: string}
	 */
	public static function observe( string $item ): array {
		$observers = self::observers();

		if ( ! isset( $observers[ $item ] ) ) {
			return array(
				'status' => self::UNKNOWN,
				'detail' => __( 'This protection has no effect a page view can see.', 'bettershield' ),
			);
		}

		return ( $observers[ $item ] )();
	}

	/**
	 * The four headers, as they actually left PHP.
	 *
	 * `headers_list()` reports what this process set, which is the only part
	 * this plugin is responsible for. A header the web server adds after PHP
	 * has finished is invisible here — so an absence is reported as "we did
	 * not send this", which is true, rather than as "the visitor did not get
	 * it", which this cannot know. The detail line says which.
	 *
	 * @return array{status: string, detail: string}
	 */
	private static function observe_headers(): array {
		return self::headers_observed( headers_list() );
	}

	/**
	 * The comparison itself, given the header lines PHP queued: separate so
	 * it can be asked under a runner that cannot set response headers.
	 *
	 * A header the daily check saw the web server sending is one the item
	 * leaves to it on purpose, so PHP never queues it. It counts as present:
	 * expected here, it was "missing" from every page a visitor received.
	 *
	 * @param string[] $queued Header lines, as headers_list() gives them.
	 * @return array{status: string, detail: string}
	 */
	public static function headers_observed( array $queued ): array {
		$sent = array();

		$left = array_map( 'strtolower', (array) ( Manager::instance()->item_state( 'security_headers' )['server_sends'] ?? array() ) );

		foreach ( $queued as $header ) {
			$name = strtolower( trim( (string) strtok( $header, ':' ) ) );

			if ( '' !== $name ) {
				$sent[ $name ] = true;
			}
		}

		$missing = array();
		$server  = array();

		foreach ( array_keys( Items::headers() ) as $header ) {
			if ( in_array( strtolower( $header ), $left, true ) ) {
				$server[] = $header;
			} elseif ( ! isset( $sent[ strtolower( $header ) ] ) ) {
				$missing[] = $header;
			}
		}

		if ( array() === $missing && array() !== $server ) {
			return array(
				'status' => self::PRESENT,
				'detail' => sprintf(
					/* translators: %s: comma-separated list of header names. */
					__( 'This plugin’s headers were on the last page, and the web server sends %s itself.', 'bettershield' ),
					implode( ', ', $server )
				),
			);
		}

		if ( array() === $missing ) {
			return array(
				'status' => self::PRESENT,
				'detail' => __( 'All four headers were on the page a visitor just received.', 'bettershield' ),
			);
		}

		return array(
			'status' => self::ABSENT,
			'detail' => sprintf(
				/* translators: %s: comma-separated list of header names. */
				__( 'This plugin did not send %s on the last page. Your web server may still add it.', 'bettershield' ),
				implode( ', ', $missing )
			),
		);
	}

	/**
	 * Whether the version is still being published.
	 *
	 * This can inspect only the core API; theme-authored markup is not observed.
	 *
	 * @return array{status: string, detail: string}
	 */
	private static function observe_generator(): array {
		// Another plugin's own generator tag can still come back from the
		// API beside an empty core one; only the WordPress version counts.
		if ( ! VersionDisclosure::names_core_version( (string) get_the_generator( 'xhtml' ) ) ) {
			return array(
				'status' => self::UNKNOWN,
				'detail' => __( 'WordPress’s generator returned no version. Pages are not scanned for generator tags a theme or plugin adds.', 'bettershield' ),
			);
		}

		return array(
			'status' => self::ABSENT,
			'detail' => __( 'The core generator API still returns the WordPress version. Page markup was not inspected.', 'bettershield' ),
		);
	}

	/**
	 * Whether the author-enumeration guard is attached on this request.
	 *
	 * The audit asks the same question; the difference is where. This runs on
	 * a visitor's page load, which is the request the guard exists for and the
	 * only one that proves it is hooked there.
	 *
	 * @return array{status: string, detail: string}
	 */
	private static function observe_enumeration(): array {
		// Every route the item closes, from the one list the item hooks from:
		// two of eight attached is not the item attached.
		if ( Manager::instance()->enforcement_attached( 'user_enumeration' ) ) {
			return array(
				'status' => self::UNKNOWN,
				'detail' => __( 'All guards were in place on the last page view, which cannot check REST, sitemaps, embeds, sign-in or password reset.', 'bettershield' ),
			);
		}

		return array(
			'status' => self::ABSENT,
			'detail' => __( 'Some guards were missing on the last page view, so the user list may be reachable again.', 'bettershield' ),
		);
	}
}
